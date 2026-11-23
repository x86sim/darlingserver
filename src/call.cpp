/**
 * This file is part of Darling.
 *
 * Copyright (C) 2021 Darling developers
 *
 * Darling is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Darling is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Darling.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE 1
#include <darlingserver/call.hpp>
#include <darlingserver/server.hpp>
#include <sys/uio.h>

#include <darlingserver/logging.hpp>
#include <darlingserver/duct-tape.h>
#include <darlingserver/config.hpp>
#include <sys/fcntl.h>
#include <sys/syscall.h>
#include <darlingserver/kqchan.hpp>
#include <utility> // x86Sim
#include <darlingserver/system-config.hpp>
#include <darlingserver/platform-identity.hpp>
#include <darlingserver/iosurface.hpp>
#include <darlingserver/code-signing.hpp>
#include <darlingserver/trust-store.hpp>
#include <darling-config.h>
#include <kern/cs_blobs.h>
#include <limits.h>
#include <list>
#include <map>
#include <mutex>

static DarlingServer::Log callLog("calls");

DarlingServer::Log DarlingServer::Call::rpcReplyLog("replies");


// x86Sim (Speed 36): opt-in RPC counters for the mach_msg fast-path study. On while the file
// $X86SIM_SCRATCH/ds-rpcstats.on exists (checked once a second); every second with traffic, one line of
// per-call-number counts and mach_msg shapes is appended to $X86SIM_SCRATCH/ds-rpcstats.log. Slots 400-449 count
// memory-entry work (duct-tape memory.c, X86SIM_MSTAT), 450-459 S2C calls (thread.cpp).
#include <atomic>
#include <ctime>
#include <unistd.h>
#include <cstdio>
extern "C" int x86sim_rpcstats_on;
int x86sim_rpcstats_on = 0;
static std::atomic<uint64_t> x86sim_calls[512];
// shapes: 0 simple no-local, 1 simple + local send-once (request), 2 simple + other local, 3 complex, 4 voucher; +5 when combined with a receive
static std::atomic<uint64_t> x86sim_shapes[10];
extern "C" void x86sim_rpcstat_msg(unsigned int bits, int rcv) {
	int k = (bits & 0x80000000u) ? 3 : ((bits >> 16) & 0x1f) ? 4 : ((bits >> 8) & 0x1f) == 0 ? 0 :
		((bits >> 8) & 0x1f) == 21 /* MAKE_SEND_ONCE */ ? 1 : 2;
	x86sim_shapes[k + (rcv ? 5 : 0)]++;
}
extern "C" void x86sim_rpcstat_slot(unsigned slot) {
	if (x86sim_rpcstats_on && slot < 512) x86sim_calls[slot]++;
}
extern "C" void x86sim_rpcstat_add(unsigned slot, unsigned long n) {
	if (x86sim_rpcstats_on && slot < 512) x86sim_calls[slot] += n;
}
static void x86sim_rpcstats_tick(unsigned number) {
	static std::atomic<int64_t> last{0};
	timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
	int64_t sec = ts.tv_sec, l = last.load();
	if (sec != l && last.compare_exchange_strong(l, sec)) {
		bool was = x86sim_rpcstats_on;
		// x86Sim: under $X86SIM_SCRATCH (was a fixed /home/bobby path)
		static std::string onPath, logPath;
		if (onPath.empty()) {
			const char* d = getenv("X86SIM_SCRATCH");
			std::string dir = d && *d ? d : "/tmp";
			onPath = dir + "/ds-rpcstats.on";
			logPath = dir + "/ds-rpcstats.log";
		}
		x86sim_rpcstats_on = access(onPath.c_str(), F_OK) == 0;
		if (was) {
			FILE* f = fopen(logPath.c_str(), "a");
			if (f) {
				fprintf(f, "t=%lld calls", (long long)sec);
				for (int i = 0; i < 512; i++) { uint64_t c = x86sim_calls[i].exchange(0); if (c) fprintf(f, " %d:%llu", i, (unsigned long long)c); }
				fprintf(f, " | shapes");
				for (int i = 0; i < 10; i++) fprintf(f, " %llu", (unsigned long long)x86sim_shapes[i].exchange(0));
				fprintf(f, "\n");
				fclose(f);
			}
		}
	}
	if (x86sim_rpcstats_on && number < 512) x86sim_calls[number]++;
}
std::shared_ptr<DarlingServer::Call> DarlingServer::Call::callFromMessage(Message&& requestMessage) {
	if (requestMessage.data().size() < sizeof(dserver_rpc_callhdr_t)) {
		throw std::invalid_argument("Message buffer was too small for call header");
	}

	dserver_rpc_callhdr_t* header = reinterpret_cast<dserver_rpc_callhdr_t*>(requestMessage.data().data());
	std::shared_ptr<Call> result = nullptr;
	x86sim_rpcstats_tick(header->number);
	std::shared_ptr<Process> process = nullptr;
	std::shared_ptr<Thread> thread = nullptr;

	// first, make sure we know this call number
	switch (header->number) {
		case dserver_callnum_s2c:
		case dserver_callnum_push_reply:
		DSERVER_VALID_CALLNUM_CASES
			break;

		default:
			throw std::invalid_argument("Invalid call number");
	}

	static const uid_t serverUid = getuid();

	if (requestMessage.uid() != serverUid) {
		throw std::runtime_error("System-reported message UID != darlingserver UID");
	}

	if ((header->number & DSERVER_CALL_UNMANAGED_FLAG) == 0) {
		// now let's lookup (and possibly create) the process and thread making this call
		process = processRegistry().registerIfAbsent(header->pid, [&]() {
			std::shared_ptr<Process> tmp = nullptr;

			int lifetimePipe = -1;

			if (header->number == dserver_callnum_checkin) {
				auto checkinCall = reinterpret_cast<dserver_rpc_call_checkin_t*>(header);
				if (checkinCall->body.lifetime_listener_pipe != -1) {
					lifetimePipe = requestMessage.extractDescriptorAtIndex(checkinCall->body.lifetime_listener_pipe);
					checkinCall->body.lifetime_listener_pipe = -1;
				}
			}

			try {
				tmp = std::make_shared<Process>(requestMessage.pid(), header->pid, static_cast<Process::Architecture>(header->architecture), lifetimePipe);
			} catch (std::system_error e) {
				return tmp;
			}

			Server::sharedInstance().monitorProcess(tmp);
			return tmp;
		});

		if (!process) {
			callLog.error() << "Received call #" << header->number << " (" << dserver_callnum_to_string(header->number) << ") from non-existent process? PID " << header->pid << " (" << requestMessage.pid() << "), TID " << header->tid << "; dropped, the caller gets no reply" << callLog.endLog;

			// ignore this call
			// TODO: instead of ignoring it, we should return a generic reply indicating `-ESRCH` or something like that.
			return nullptr;
		}

		// Ported from VibeDarling/darlingserver@37cb5e2 (Cristian Magherusan-Stanciu): checked before the thread is
		// looked up or registered, so a rejected message cannot change a thread's reply address (it was checked after
		// thread->setAddress()).
		if (process->id() != requestMessage.pid()) {
			throw std::runtime_error("System-reported message PID != darlingserver-recorded PID");
		}

		thread = threadRegistry().registerIfAbsent(header->tid, [&]() {
			std::shared_ptr<Thread> tmp = nullptr;

			void* stackHint = nullptr;

			if (header->number == dserver_callnum_checkin) {
				auto checkinCall = reinterpret_cast<dserver_rpc_call_checkin_t*>(header);
				stackHint = reinterpret_cast<void*>(checkinCall->body.stack_hint);
			}

			try {
				tmp = std::make_shared<Thread>(process, header->tid, stackHint);
			} catch (std::system_error e) {
				return tmp;
			}

			tmp->setAddress(requestMessage.address());
			tmp->registerWithProcess();
			return tmp;
		});

		if (!thread) {
			callLog.error() << "Received call #" << header->number << " (" << dserver_callnum_to_string(header->number) << ") from non-existent thread? PID " << header->pid << " (" << requestMessage.pid() << "), TID " << header->tid << "; dropped, the caller gets no reply" << callLog.endLog;

			// ignore this call
			// TODO: instead of ignoring it, we should return a generic reply indicating `-ESRCH` or something like that.
			return nullptr;
		}

		// Ported from VibeDarling/darlingserver@feef733 (Cristian Magherusan-Stanciu): the thread a call names must
		// belong to the calling process; otherwise one process could run a call on another's thread and replace its
		// reply address. (A thread detached at exec is unregistered by notifyDead().)
		if (thread->process() != process) {
			throw std::runtime_error("Message TID belongs to a different process");
		}

		thread->setAddress(requestMessage.address());
	}

	if (callLog.enabled(Log::Type::Debug)) {
		auto pidString = (process) ? (std::to_string(process->id()) + " (" + std::to_string(process->nsid()) + ")") : (std::to_string(header->pid) + " (-1)");
		auto tidString = (thread) ? (std::to_string(thread->id()) + " (" + std::to_string(thread->nsid()) + ")") : (std::to_string(header->tid) + " (-1)");
		callLog.debug() << "Received call #" << header->number << " (" << dserver_callnum_to_string(header->number) << ") from PID " << pidString << ", TID " << tidString << callLog.endLog;
	}

	if (header->number == dserver_callnum_s2c) {
		// this is an S2C reply

		bool stale = false;
		bool staleUsedInterrupt = false;
		size_t staleMappingLength = 0;
		bool staleMappingReusable = false;
		bool accepted = false;

		{
			std::unique_lock lock(thread->_rwlock);

			if (thread->_s2cStaleReplyPending) {
				// no new call is sent while an abandoned one is unanswered, so this is the reply to the call
				// whose wait was interrupted; nobody is waiting for it any more
				stale = true;
				staleUsedInterrupt = thread->_s2cStaleReplyUsedInterrupt;
				staleMappingLength = thread->_s2cStaleMappingLength;
				staleMappingReusable = thread->_s2cStaleMappingReusable;
				thread->_s2cStaleReplyPending = false;
				thread->_s2cStaleReplyUsedInterrupt = false;
				thread->_s2cStaleMappingLength = 0;
				thread->_s2cStaleMappingReusable = false;
			} else if (thread->_s2cCallInFlight && !thread->_s2cReply) {
				thread->_s2cReply = std::move(requestMessage);
				accepted = true;
			}
		}

		if (accepted) {
			dtape_semaphore_up(thread->_s2cReplySempahore);
		} else if (stale) {
			callLog.debug() << "Discarding reply to an abandoned S2C call" << callLog.endLog;
			if (staleMappingLength > 0) {
				// nobody will use the memory the abandoned mmap call mapped; it is unmapped before the next S2C call
				thread->_s2cNoteStaleMapping(requestMessage, staleMappingLength, staleMappingReusable);
			}
			if (staleUsedInterrupt) {
				// the client's S2C interrupt handler is waiting for us to let it go
				dtape_semaphore_up(thread->_s2cInterruptExitSemaphore);
			}
		} else {
			// a misbehaving client can send a reply nobody asked for; dropping it is the only safe thing to do
			callLog.error() << "Received unexpected S2C reply; ignoring it" << callLog.endLog;
		}

		return nullptr;
	} else if (header->number == dserver_callnum_push_reply) {
		// this is a reply push
		// (used to send interrupted replies back to the server)

		auto pushReplyCall = reinterpret_cast<const dserver_rpc_call_push_reply_t*>(requestMessage.data().data());
		Message replyToSave(pushReplyCall->reply_size, 0);

		// extract the reply-push synchronization pipe
		// owned here so it is closed on every exit; the client is blocked on the read end and EOF releases it
		FD pipeDesc(requestMessage.extractDescriptorAtIndex(requestMessage.descriptors().size() - 1));
		char tmp = 1;

		if (!pipeDesc) {
			throw std::runtime_error("Failed to extract reply-push synchronization pipe");
		}

		if (!process->readMemory(pushReplyCall->reply, replyToSave.data().data(), pushReplyCall->reply_size)) {
			throw std::runtime_error("Failed to read client-pushed reply body");
		}

		replyToSave.replaceDescriptors(requestMessage.descriptors());
		requestMessage.replaceDescriptors({});

		replyToSave.setAddress(requestMessage.address());

		bool pending = false;
		{
			std::unique_lock lock(thread->_rwlock);
			// the client can push more than one reply: e.g. when a signal arrives while it waits for the reply to
			// interrupt_exit, the new interrupt_enter sees both that reply and the reply to the call the first signal
			// interrupted (sent after interrupt_exit). all of them are kept, in order.
			// the client pushes replies only while it waits for the reply to its latest interrupt_enter, so they belong to
			// that interrupt. if we haven't started handling it yet, keep them for it.
			if ((thread->_pendingCall && thread->_pendingCall->number() == Call::Number::InterruptEnter) || !thread->_pendingInterrupts.empty()) {
				// this means the client got interrupted after we had already sent a reply for the interrupted call,
				// the client saw this unexpected reply while waiting for interrupt_enter to respond and sent it back to us,
				// and we received both calls (interrupt_enter and push_reply) at the same time.
				// the interrupt_enter can also still be queued behind the call that sent the reply (see `Thread::setPendingCall`):
				// the call has replied, but the interrupt is only scheduled once the call's microthread returns. the reply must
				// not go to an interrupt that is already being handled: with none, it would be dropped (and the client would
				// wait for it forever); for a nested interrupt, it would only be sent once the outer interrupt exits.
				thread->_pendingSavedReplies.push_back(std::move(replyToSave));
				pending = true;
			} else {
				if (thread->_interrupts.empty()) {
					throw std::runtime_error("Client tried to push reply outside of interrupt");
				}
				thread->_interrupts.top().savedReplies.push_back(std::move(replyToSave));
			}
		}

		callLog.debug() << *thread << ": Saved client-pushed reply (" << (pending ? "pending" : "normal") << ")" << callLog.endLog;

		// write a byte to the pipe so the caller can continue
		write(pipeDesc.fd(), &tmp, sizeof(tmp));

		return nullptr;
	}

	// finally, let's construct the call class

	#define CALL_CASE(_callName, _className) \
		case dserver_callnum_ ## _callName: { \
			if (requestMessage.data().size() < sizeof(dserver_rpc_call_ ## _callName ## _t)) { \
				throw std::invalid_argument("Message buffer was too small for dserver_call_" #_callName "_t"); \
			} \
			result = std::make_shared<_className>(thread, reinterpret_cast<dserver_rpc_call_ ## _callName ## _t*>(header), std::move(requestMessage)); \
		} break;

	switch (header->number) {
		DSERVER_CONSTRUCT_CASES

		default:
			throw std::invalid_argument("Invalid call number");
	}

	#undef CALL_CASE

	// x86Sim (willi/darlingserver#14): Thread::_s2cPerform() gives mldr's checkin and thread-exit checkout the S2C
	// signal (mldr's RPC hooks abort on an S2C call); libsystem's (fork child's checkin, exec's checkout) serve it inline.
	if (auto checkin = std::dynamic_pointer_cast<Checkin>(result)) {
		result->_madeByMldr = !checkin->_body.is_fork;
	} else if (auto checkout = std::dynamic_pointer_cast<Checkout>(result)) {
		result->_madeByMldr = checkout->_body.exec_listener_pipe < 0;
	}

	if (thread) {
		// x86Sim (willi/darlingserver#13): a call queued behind the pending one is scheduled when that one is done
		if (!thread->setPendingCall(result)) {
			callLog.debug() << *thread << ": Call queued behind the pending call" << callLog.endLog;
			return nullptr;
		}
		return result;
	} else {
		Thread::kernelAsync([result]() {
			result->processCall();
		});
		return nullptr;
	}
};

DarlingServer::Call::Call(std::shared_ptr<Thread> thread, Address replyAddress, dserver_rpc_callhdr_t* callHeader):
	_thread(thread),
	_replyAddress(replyAddress),
	_header(*callHeader)
	{};

DarlingServer::Call::~Call() {};

std::shared_ptr<DarlingServer::Thread> DarlingServer::Call::thread() const {
	return _thread.lock();
};

void DarlingServer::Call::sendBasicReply(int resultCode) {
	throw std::runtime_error("This call cannot send a basic reply");
};

void DarlingServer::Call::sendBSDReply(int resultCode, uint32_t returnValue) {
	throw std::runtime_error("This call cannot send a BSD reply");
};

bool DarlingServer::Call::isXNUTrap() const {
	return false;
};

bool DarlingServer::Call::isBSDTrap() const {
	return false;
};

void DarlingServer::Call::sendReply(Message&& reply) {
	Server::sharedInstance().sendMessage(std::move(reply));
};

//
// call processing
//

/*
 *
 * A note about RPC wrappers:
 *
 * The auto-generated RPC wrappers provide both client-side wrappers as well as server-side wrappers.
 * The server-side wrappers automatically handle a few things like replies and descriptors.
 *
 * Replies:
 * The RPC wrappers provide a custom `_sendReply` method specific to each call class.
 * This method takes the result/status code as its first parameter followed by the return parameters
 * specified in the call interface. When a call is done processing, it simply calls `_sendReply` with the necessary
 * parameters and the RPC wrappers will take care of setting up the message and loading it onto the reply queue
 * for the server to send it out.
 *
 * Descriptors:
 * The RPC wrappers automatically handle ownership of descriptors, both incoming and outgoing.
 *
 * Incoming descriptors are extracted from the message and ownership is moved into the call instance.
 * The call processing code can use the descriptor however it likes while the call instance is still alive.
 * If it would like to move ownership out of the call instance, it can set the descriptor in the `_body` to `-1`.
 * Descriptors still left in the `_body` when the call instance is destroyed are automatically closed.
 *
 * Ownership of outgoing descriptors is passed into the reply message. In other words, when a descriptor
 * is given to `_sendReply`, the call instance loses ownership of that descriptor. If the call instance
 * would like to retain ownership, it should `dup()` the descriptor and pass the `dup()`ed descriptor to `_sendReply` instead.
 *
 */

void DarlingServer::Call::Checkin::processCall() {
	// the Call instance creation already took care of registering the process and thread.

	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			// the process needs to know when the checkin occurs, in case it has a pending replacement
			// and also to notify its parent about when the fork is complete
			process->notifyCheckin(static_cast<Process::Architecture>(_header.architecture), _body.is_fork, thread->nsid() == process->nsid());
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::Checkout::processCall() {
	int code = 0;
	bool threadDied = false;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (_body.exec_listener_pipe >= 0) {
				// this is actually an execve;
				// let's monitor the FD we got

				// make it non-blocking
				int flags = fcntl(_body.exec_listener_pipe, F_GETFL);
				if (flags < 0) {
					code = -errno;
				} else {
					flags |= O_NONBLOCK;
					if (fcntl(_body.exec_listener_pipe, F_SETFL, flags) < 0) {
						code = -errno;
					} else {
						// now monitor it
						auto fd = std::make_shared<FD>(_body.exec_listener_pipe);
						_body.exec_listener_pipe = -1; // the FD instance now owns the descriptor

						auto replacingWithDarlingProcess = _body.executing_macho;

						// x86Sim: recorded now, before the reply lets the client exec: the new image's main-thread check-in
						// then always finds it, however late the pipe's hangup is handled (Process::notifyCheckin)
						if (replacingWithDarlingProcess) {
							process->noteExecCheckout();
						}

						std::weak_ptr<Process> weakProcess = process;
						Server::sharedInstance().addMonitor(std::make_shared<Monitor>(fd, Monitor::Event::HangUp, false, true, [fd, weakProcess, replacingWithDarlingProcess](std::shared_ptr<Monitor> monitor, Monitor::Event events) {
							Server::sharedInstance().removeMonitor(monitor);

							auto process = weakProcess.lock();

							if (!process) {
								// the process died...
								return;
							}

							char tmp;
							int result = read(fd->fd(), &tmp, sizeof(tmp));

							if (result < 0) {
								// we shouldn't even get EAGAIN
								throw std::system_error(errno, std::generic_category(), "Failed to read from exec listener pipe");
							}

							if (result == 0) {
								// the execve succeeded
								if (!replacingWithDarlingProcess) {
									// the Darling process was replaced with a non-Darling process
									// treat it like death
									process->notifyDead();
								}
								// x86Sim: a Darling image's exec was recorded at the checkout; its main-thread check-in
								// completes it (it may have done so already)
							} else {
								// the execve failed (the old image goes on)
								if (replacingWithDarlingProcess) {
									process->noteExecFailed();
								}
							}
						}));
					}
				}
			} else {
				thread->notifyDead();
				threadDied = true;

				// if this was the last thread in the process, it'll be automatically unregistered
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	// x86Sim (willi/darlingserver#10): the call is over. A dead thread with no active call is released when it returns
	// to the top of its microthread (doneWorking); with `_thread` reset below, the reply no longer deactivated it, and a
	// checked-out thread stayed for ever (its duct-taped thread still in task_threads(), its stack). Not the main thread:
	// mldr parks its Linux thread and the process lives on; it is released with the process (notifyProcessDead()).
	// `self` keeps the call (the thread's active call held the only reference) until the reply is sent.
	std::shared_ptr<Call> self;
	if (auto thread = _thread.lock(); thread && (self = thread->activeCall()).get() == this && thread->process() && thread->id() != thread->process()->id()) {
		thread->deactivateCall(self);
	}

	// clear the thread pointer so that the reply will be sent directly through the server
	// (otherwise, we would attempt to send it through the thread, which is now dead)
	_thread.reset();

	_sendReply(code);
};

void DarlingServer::Call::VchrootPath::processCall() {
	int code = 0;
	size_t fullLength = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (_body.buffer_size > 0) {
				auto tmpstr = process->vchrootPath().substr(0, _body.buffer_size - 1);
				auto len = std::min(tmpstr.length() + 1, _body.buffer_size);

				fullLength = process->vchrootPath().length();

				if (!process->writeMemory(_body.buffer, tmpstr.c_str(), len, &code)) {
					// writeMemory returns a positive error code, but we want a negative one
					code = -code;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, fullLength);
};

void DarlingServer::Call::TaskSelfTrap::processCall() {
	const auto taskSelfPort = dtape_task_self_trap();
	_sendReply(0, taskSelfPort);
};

// x86Sim: see dtape_memfd_for_region
void DarlingServer::Call::X86SimMemfdForRegion::processCall() {
	int fd = -1;
	uint64_t offset = 0;
	uint32_t shared = 0;
	if (_body.address == 0 && _body.size == 0) {
		// x86Sim: capability probe (an older darlingserver fails it with -EFAULT): `offset` = the calls this one has
		// past x86sim_memfd_for_region, bit 0 = x86sim_entry_copy_fd. A client must never send a call number its
		// server doesn't know: the server drops it and the caller waits for its reply forever.
		_sendReply(0, -1, 1, 0);
		return;
	}
	int code = dtape_memfd_for_region(_body.address, _body.size, &fd, &offset, &shared);
	_sendReply(code, fd, offset, shared); // the reply message closes our copy once sent
};

// x86Sim: see dtape_entry_copy_fd
void DarlingServer::Call::X86SimEntryCopyFd::processCall() {
	int fd = -1;
	uint64_t fileOffset = 0, mapSize = 0, dataAdjust = 0;
	int code = dtape_entry_copy_fd(_body.entry, _body.offset, _body.size, _body.flags, &fd, &fileOffset, &mapSize, &dataAdjust);
	_sendReply(code, fd, fileOffset, mapSize, dataAdjust); // the reply message closes our copy once sent
};

void DarlingServer::Call::HostSelfTrap::processCall() {
	const auto hostSelfPort = dtape_host_self_trap();
	_sendReply(0, hostSelfPort);
};

void DarlingServer::Call::ThreadSelfTrap::processCall() {
	const auto threadSelfPort = dtape_thread_self_trap();
	_sendReply(0, threadSelfPort);
};

void DarlingServer::Call::MachReplyPort::processCall() {
	const auto machReplyPort = dtape_mach_reply_port();
	_sendReply(0, machReplyPort);
};

void DarlingServer::Call::Kprintf::processCall() {
	static auto kprintfLog = Log("kprintf");
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			char* tmp = (char*)malloc(_body.string_length + 1);

			if (tmp) {
				if (process->readMemory(_body.string, tmp, _body.string_length, &code)) {
					size_t len = _body.string_length;

					// strip trailing whitespace
					while (len > 0 && isspace(tmp[len - 1])) {
						--len;
					}
					tmp[len] = '\0';

					kprintfLog.info() << tmp << kprintfLog.endLog;
				} else {
					// readMemory returns a positive error code, but we want a negative one
					code = -code;
				}

				free(tmp);
			} else {
				code = -ENOMEM;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::StartedSuspended::processCall() {
	int code = 0;
	bool suspended = false;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			suspended = process->startSuspended();
			process->setStartSuspended(false);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, suspended);
};

void DarlingServer::Call::GetTracer::processCall() {
	int code = 0;
	int32_t tracer = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (auto tracerProcess = process->tracerProcess()) {
				tracer = tracerProcess->nsid();
			} else {
				// leave `tracer` as 0
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, tracer);
};

void DarlingServer::Call::Uidgid::processCall() {
	int code = 0;
	int uid = -1;
	int gid = -1;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			// HACK
			// we shouldn't need to access _dtapeTask; Process should provide a method for this (but it doesn't yet because i'm not sure how to make that API feel at-home in C++)
			dtape_task_uidgid(process->_dtapeTask, _body.new_uid, _body.new_gid, &uid, &gid);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, uid, gid);
};

void DarlingServer::Call::SetThreadHandles::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		thread->setThreadHandles(_body.pthread_handle, _body.dispatch_qaddr, _body.cancel_marked_addr);
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::Vchroot::processCall() {
	int code = 0;

	// TODO: wrap all `processCall` calls in try-catch like this
	try {
		if (auto thread = _thread.lock()) {
			if (auto process = thread->process()) {
				process->setVchrootDirectory(std::make_shared<FD>(_body.directory_fd));
				_body.directory_fd = -1;
			} else {
				code = -ESRCH;
			}
		} else {
			code = -ESRCH;
		}
	} catch (std::system_error err) {
		code = -err.code().value();
	} catch (...) {
		code = std::numeric_limits<int>::min();
	}

	_sendReply(code);
};

void DarlingServer::Call::MldrPath::processCall() {
	int code = 0;
	uint64_t fullLength = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			auto mldrPath = Config::defaultMldrPath();
			auto tmpstr = mldrPath.substr(0, _body.buffer_size - 1);
			auto len = std::min(tmpstr.length() + 1, _body.buffer_size);

			fullLength = mldrPath.length();

			if (!process->writeMemory(_body.buffer, tmpstr.c_str(), len, &code)) {
				// writeMemory returns a positive error code, but we want a negative one
				code = -code;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, fullLength);
};

void DarlingServer::Call::ThreadGetSpecialReplyPort::processCall() {
	_sendReply(0, dtape_thread_get_special_reply_port());
};

void DarlingServer::Call::MkTimerCreate::processCall() {
	_sendReply(0, dtape_mk_timer_create());
};

void DarlingServer::Call::PthreadKill::processCall() {
	int code = 0;

	if (auto targetThread = Thread::threadForPort(_body.thread_port)) {
		try {
			targetThread->sendSignal(_body.signal);
		} catch (std::system_error e) {
			code = -e.code().value();
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::PthreadCanceled::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		code = thread->pthreadCanceled(_body.action);
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::PthreadTestcancel::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (!thread->pthreadTestcancel()) {
			code = -EINVAL;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::PthreadMarkcancel::processCall() {
	int code = 0;

	auto thread = _thread.lock();
	auto targetThread = Thread::threadForPort(_body.thread_port);

	// like xnu, only accept threads of the caller's own task
	if (thread && targetThread && targetThread->process() && targetThread->process() == thread->process()) {
		// a thread that cancels itself is not waiting anywhere
		targetThread->pthreadMarkcancel(targetThread != thread);
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::KqchanMachPortOpen::processCall() {
	int code = 0;
	int socket = -1;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			auto kqchan = std::make_shared<Kqchan::MachPort>(process, _body.port_name, _body.receive_buffer, _body.receive_buffer_size, _body.saved_filter_flags);

			try {
				socket = kqchan->setup();
			} catch (std::system_error e) {
				code = -e.code().value();
			} catch (...) {
				// just report that we couldn't find the port
				code = -ESRCH;
			}

			process->registerKqchan(kqchan);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, socket);
};

void DarlingServer::Call::KqchanProcOpen::processCall() {
	int code = 0;
	int socket = -1;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			auto kqchan = std::make_shared<Kqchan::Process>(process, _body.pid, _body.flags);

			try {
				socket = kqchan->setup();
			} catch (std::system_error e) {
				code = -e.code().value();
			} catch (...) {
				// just report that we couldn't find the process
				code = -ESRCH;
			}

			process->registerKqchan(kqchan);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, socket);
};

void DarlingServer::Call::FileportMakeport::processCall() {
	int code = 0;
	uint32_t portName = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (_body.fd < 0) {
				code = -EBADF;
			} else {
				// the fileport takes ownership of the descriptor
				int fd = _body.fd;
				_body.fd = -1;

				switch (dtape_fileport_makeport(process->_dtapeTask, fd, &portName)) {
					case dtape_fileport_result_ok:
						break;
					case dtape_fileport_result_no_resources:
						code = -EAGAIN;
						break;
					case dtape_fileport_result_invalid_port:
						code = -EINVAL;
						break;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, portName);
};

void DarlingServer::Call::FileportMakefd::processCall() {
	int code = 0;
	int fd = -1;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			switch (dtape_fileport_makefd(process->_dtapeTask, _body.port_name, &fd)) {
				case dtape_fileport_result_ok:
					break;
				case dtape_fileport_result_no_resources:
					code = -EMFILE;
					break;
				case dtape_fileport_result_invalid_port:
					// not a send right to a fileport
					code = -EINVAL;
					break;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	// the reply takes ownership of the new descriptor
	_sendReply(code, fd);
};

static DarlingServer::Log systemConfigLog("sysconfig");

// raised once by the first accepted push. every waiter passes the count on when it wakes up,
// so the latch stays raised for later waiters too.
static dtape_semaphore_t* systemConfigLatch(dtape_task_t* kernelTask) {
	static std::once_flag once;
	static dtape_semaphore_t* latch = nullptr;
	std::call_once(once, [kernelTask]() {
		latch = dtape_semaphore_create(kernelTask, 0);
	});
	return latch;
};

void DarlingServer::Call::SetSystemConfig::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			int uid = -1;
			dtape_task_uidgid(process->_dtapeTask, -1, -1, &uid, nullptr);

			// the configuration comes from the root-owned `/Library/Preferences`, so only root may push it.
			// this is checked before the caller's memory is looked at.
			if (uid != 0) {
				code = -EPERM;
			} else if (_body.config_size != sizeof(dserver_system_config_t)) {
				code = -EINVAL;
			} else if (auto latch = systemConfigLatch(Process::kernelProcess()->_dtapeTask); !latch) {
				code = -ENOMEM;
			} else {
				dserver_system_config_t config;
				bool isFirst = false;

				if (!process->readMemory(_body.config, &config, sizeof(config), &code)) {
					// readMemory returns a positive error code, but we want a negative one
					code = -code;
				} else {
					code = SystemConfig::sharedInstance().apply(config, isFirst);
				}

				if (code == 0) {
					systemConfigLog.info() << "Process " << process->id() << " (" << process->nsid() << ") set the system configuration" << systemConfigLog.endLog;
					if (isFirst) {
						dtape_semaphore_up(latch);
					}
				} else {
					systemConfigLog.warning() << "Rejected the system configuration from process " << process->id() << " (" << process->nsid() << "): " << code << systemConfigLog.endLog;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::GetSystemConfig::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (_body.config_size != sizeof(dserver_system_config_t)) {
				code = -EINVAL;
			} else {
				auto config = SystemConfig::sharedInstance().current();
				if (!process->writeMemory(_body.config, &config, sizeof(config), &code)) {
					// writeMemory returns a positive error code, but we want a negative one
					code = -code;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::WaitSystemConfig::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (thread->process()) {
			if (SystemConfig::sharedInstance().current().generation == 0) {
				if (auto latch = systemConfigLatch(Process::kernelProcess()->_dtapeTask); !latch) {
					code = -ENOMEM;
				} else if (dtape_semaphore_down_simple(latch)) {
					// wake up the next waiter (or leave the latch raised for later ones)
					dtape_semaphore_up(latch);
				} else {
					code = -EINTR;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::SetPlatformIdentity::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			int uid = -1;
			dtape_task_uidgid(process->_dtapeTask, -1, -1, &uid, nullptr);

			// the identity comes from the root-owned `/Library/Preferences`, so only root may push it.
			// this is checked before the caller's memory is looked at.
			if (uid != 0) {
				code = -EPERM;
			} else if (_body.identity_size != sizeof(dserver_platform_identity_t)) {
				code = -EINVAL;
			} else {
				dserver_platform_identity_t identity;

				if (!process->readMemory(_body.identity, &identity, sizeof(identity), &code)) {
					// readMemory returns a positive error code, but we want a negative one
					code = -code;
				} else {
					code = PlatformIdentity::sharedInstance().apply(identity, [](const dserver_platform_identity_t& applied) {
						// `host_info()` reports the configured memory size, as `hw.memsize` does
						dtape_host_set_memory_size(applied.memory_size);
					});
				}

				if (code == 0) {
					systemConfigLog.info() << "Process " << process->id() << " (" << process->nsid() << ") set the platform identity" << systemConfigLog.endLog;
				} else {
					systemConfigLog.warning() << "Rejected the platform identity from process " << process->id() << " (" << process->nsid() << "): " << code << systemConfigLog.endLog;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::GetPlatformIdentity::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (_body.identity_size != sizeof(dserver_platform_identity_t)) {
				code = -EINVAL;
			} else {
				auto identity = PlatformIdentity::sharedInstance().current();
				if (!process->writeMemory(_body.identity, &identity, sizeof(identity), &code)) {
					// writeMemory returns a positive error code, but we want a negative one
					code = -code;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::ForkWaitForChild::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			// the child inherits our task's special ports (e.g. the bootstrap port) when it
			// checks in, so the parent must not return from fork() before that. if a signal
			// interrupted the wait, have the caller wait again; the child's check-in will
			// still raise the semaphore.
			if (!process->waitForChildAfterFork()) {
				code = -EINTR;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::Sigprocess::processCall() {
	int code = 0;
	int newBSDSignal = 0;

	if (auto thread = _thread.lock()) {
		try {
			thread->processSignal(_body.bsd_signal_number, _body.linux_signal_number, _body.code, _body.signal_address, _body.thread_state, _body.float_state);
			newBSDSignal = thread->pendingSignal();
		} catch (std::system_error e) {
			code = -e.code().value();
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, newBSDSignal);
};

void DarlingServer::Call::TaskIs64Bit::processCall() {
	int code = 0;
	bool is64Bit = false;

	if (auto maybeTargetProcess = processRegistry().lookupEntryByNSID(_body.id)) {
		auto targetProcess = *maybeTargetProcess;
		is64Bit = targetProcess->is64Bit();
	} else {
		code = -ESRCH;
	}

	_sendReply(code, is64Bit);
};

void DarlingServer::Call::InterruptEnter::processCall() {
	Thread::_handleInterruptEnterForCurrentThread();

	_sendReply(0);
};

void DarlingServer::Call::InterruptExit::processCall() {
	auto thread = _thread.lock();

	dtape_thread_sigexc_exit(thread->_dtapeThread);

	_sendReply(0);

	{
		std::unique_lock lock(thread->_rwlock);

		auto tmp = std::move(thread->_interrupts.top());

		thread->_interrupts.pop();

		for (auto& savedReply: tmp.savedReplies) {
			callLog.debug() << *thread << ": Going to send saved reply" << callLog.endLog;
			Server::sharedInstance().sendMessage(std::move(savedReply));
		}
	}
};

void DarlingServer::Call::ConsoleOpen::processCall() {
	static Log consoleLog("console");

	int code = 0;
	int sockets[2] = { -1, -1 };

	// we don't really need bidirectional communication, so a pipe would suffice,
	// except that when you set O_NONBLOCK on one side of a pipe, it is set for both.

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) < 0) {
		int err = errno;
		callLog.warning() << __PRETTY_FUNCTION__ << ": socketpair failed with " << err << callLog.endLog;

		// just report EMFILE for the peer
		code = EMFILE;
	} else {
		// make our side non-blocking
		int flags = fcntl(sockets[0], F_GETFL);
		if (flags < 0) {
			code = -errno;
		} else {
			flags |= O_NONBLOCK;
			if (fcntl(sockets[0], F_SETFL, flags) < 0) {
				code = -errno;
			} else {
				// now monitor it
				auto fd = std::make_shared<FD>(sockets[0]);
				std::weak_ptr<Process> weakProcess;

				if (auto thread = _thread.lock()) {
					if (auto process = thread->process()) {
						weakProcess = process;
					}
				}

				Server::sharedInstance().addMonitor(std::make_shared<Monitor>(fd, Monitor::Event::Readable | Monitor::Event::HangUp, false, false, [fd, weakProcess](std::shared_ptr<Monitor> monitor, Monitor::Event events) {
					auto proc = weakProcess.lock();

					if (!proc || static_cast<uint64_t>(events & Monitor::Event::HangUp) != 0) {
						Server::sharedInstance().removeMonitor(monitor);
						return;
					}

					if (static_cast<uint64_t>(events & Monitor::Event::Readable) != 0) {
						std::stringstream data;
						while (true) {
							char buf[128];
							auto count = read(fd->fd(), buf, sizeof(buf) - 1);
							if (count <= 0) {
								break;
							}
							buf[count] = '\0';
							data << buf;
						}
						consoleLog.info() << *proc << ": " << data.rdbuf();
					}
				}));
			}
		}
	}

	if (code != 0) {
		if (sockets[0] >= 0) {
			close(sockets[0]);
			sockets[0] = -1;
		}
		if (sockets[1] >= 0) {
			close(sockets[1]);
			sockets[1] = -1;
		}
	}
	_sendReply(code, sockets[1]);
};

void DarlingServer::Call::SetDyldInfo::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			dtape_task_set_dyld_info(process->_dtapeTask, _body.address, _body.length);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::StopAfterExec::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			process->setStartSuspended(true);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

// x86Sim: see Process::setSpawnExec
void DarlingServer::Call::SpawnExec::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			process->setSpawnExec(true);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::SetTracer::processCall() {
	int code = 0;
	std::shared_ptr<Process> targetProcess = nullptr;
	std::shared_ptr<Process> tracerProcess = nullptr;

	if (_body.target == 0) {
		if (auto thread = _thread.lock()) {
			targetProcess = thread->process();
		}
	} else {
		if (auto maybeTargetProcess = processRegistry().lookupEntryByNSID(_body.target)) {
			targetProcess = *maybeTargetProcess;
		}
	}

	if (targetProcess) {
		if (_body.tracer == 0) {
			// detach: the calling process stops being the tracer. Only the tracer itself may do this.
			if (_body.target == 0) {
				code = EPERM;
			} else if (auto thread = _thread.lock()) {
				if (!targetProcess->clearTracerProcess(thread->process())) {
					code = EPERM;
				}
			} else {
				code = -ESRCH;
			}
			_sendReply(code);
			return;
		} else {
			if (auto maybeTracerProcess = processRegistry().lookupEntryByNSID(_body.tracer)) {
				tracerProcess = *maybeTracerProcess;
			} else {
				// intentionally not negated because this is not an internal error;
				// this is a perfectly valid case
				code = ESRCH;
			}
		}

		if (code == 0 && tracerProcess) {
			code = _mediateAttach(targetProcess, tracerProcess);
		}

		if (code == 0) {
			if (!targetProcess->setTracerProcess(tracerProcess)) {
				// again, not negated because this isn't an internal error;
				// simply indicates there was already a tracer set for the target
				code = EPERM;
			}
		}
	} else {
		// ditto from before
		code = ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::TidForThread::processCall() {
	int code = 0;
	int32_t tid = 0;

	if (auto thread = Thread::threadForPort(_body.thread)) {
		tid = thread->nsid();
	} else {
		// might be user error (e.g. invalid port number or dead thread), so don't negate it
		code = ESRCH;
	}

	_sendReply(code, tid);
};

void DarlingServer::Call::PtraceSigexc::processCall() {
	int code = 0;

	if (auto maybeProcess = processRegistry().lookupEntryByNSID(_body.target)) {
		auto process = *maybeProcess;

		code = _mediateTracing(process);
		if (code == 0) {
			dtape_task_set_sigexc_enabled(process->_dtapeTask, _body.enabled);
			dtape_task_try_resume(process->_dtapeTask);
		}
	} else {
		// not negated because this isn't an internal error
		code = ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::PtraceThupdate::processCall() {
	int code = 0;

	if (auto maybeThread = threadRegistry().lookupEntryByNSID(_body.target)) {
		auto thread = *maybeThread;
		auto process = thread->process();

		code = process ? _mediateTracing(process) : 0;
		if (code == 0) {
			thread->setPendingSignal(_body.signum);
		}
	} else {
		// not negated because this isn't an internal error
		code = ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::ThreadSuspended::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		thread->waitWhileUserSuspended(_body.thread_state, _body.float_state);
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::S2CPerform::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		bool abandoned = false;

		{
			std::unique_lock lock(thread->_rwlock);
			if (thread->_s2cInterruptAbandoned > 0) {
				// the server stopped waiting for this interrupt; there is nothing to perform, so don't wait for anyone
				--thread->_s2cInterruptAbandoned;
				abandoned = true;
			} else {
				// from here on, a caller that stops waiting for the green light knows we're about to give it and will let us go
				thread->_s2cInterruptEntered = true;
			}
		}

		if (!abandoned) {
			dtape_semaphore_up(thread->_s2cInterruptEnterSemaphore);
			dtape_semaphore_down_simple(thread->_s2cInterruptExitSemaphore);
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::SetExecutablePath::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			std::string tmpstr;
			tmpstr.resize(_body.buffer_size);
			if (!process->readMemory((uintptr_t)_body.buffer, tmpstr.data(), _body.buffer_size, &code)) {
				code = -code;
			} else {
				process->setExecutablePath(tmpstr.c_str());
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
}

namespace {

	// The last known path of each file that has been given a file reference. References are shared
	// between processes, so this can't live in any one of them. The server only remembers these paths:
	// it never accesses them, and the process asking for a path checks that it still leads to the file.
	class FileRefPaths {
	public:
		void remember(uint64_t device, uint64_t inode, std::string path) {
			std::unique_lock lock(_mutex);
			const Key key(device, inode);
			auto found = _entries.find(key);

			if (found != _entries.end()) {
				_order.erase(found->second);
				_entries.erase(found);
			}

			_order.emplace_front(key, std::move(path));
			_entries.emplace(key, _order.begin());

			if (_entries.size() > maximumEntries) {
				_entries.erase(_order.back().first);
				_order.pop_back();
			}
		};

		bool lookup(uint64_t device, uint64_t inode, std::string& path) {
			std::unique_lock lock(_mutex);
			auto found = _entries.find(Key(device, inode));

			if (found == _entries.end()) {
				return false;
			}

			_order.splice(_order.begin(), _order, found->second);
			path = found->second->second;
			return true;
		};

	private:
		using Key = std::pair<uint64_t, uint64_t>;
		using Entry = std::pair<Key, std::string>;

		static constexpr size_t maximumEntries = 65536;

		std::mutex _mutex;
		std::list<Entry> _order; // most recently used first
		std::map<Key, std::list<Entry>::iterator> _entries;
	};

	FileRefPaths fileRefPaths;

};

void DarlingServer::Call::FileRefRegister::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (_body.path_length == 0) {
				code = -EINVAL;
			} else if (_body.path_length >= PATH_MAX) {
				code = -ENAMETOOLONG;
			} else {
				std::string path;
				path.resize(_body.path_length);

				if (!process->readMemory((uintptr_t)_body.path, path.data(), _body.path_length, &code)) {
					code = -code;
				} else {
					fileRefPaths.remember(_body.device, _body.inode, std::move(path));
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::FileRefPath::processCall() {
	int code = 0;
	uint64_t fullLength = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			std::string path;

			if (!fileRefPaths.lookup(_body.device, _body.inode, path)) {
				code = -ENOENT;
			} else {
				fullLength = path.length();

				if (path.length() >= _body.buffer_size) {
					code = -ENAMETOOLONG;
				} else if (!process->writeMemory((uintptr_t)_body.buffer, path.c_str(), path.length() + 1, &code)) {
					code = -code;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, fullLength);
};

void DarlingServer::Call::SetExecutableUuid::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			std::array<uint8_t, 16> uuid;
			if (!process->readMemory((uintptr_t)_body.uuid, uuid.data(), uuid.size(), &code)) {
				// readMemory returns a positive error code, but we want a negative one
				code = -code;
			} else {
				process->setExecutableUuid(uuid);
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::GetExecutableUuid::processCall() {
	int code = 0;

	if (auto callingThread = _thread.lock()) {
		if (auto callingProcess = callingThread->process()) {
			if (auto maybeTargetProcess = processRegistry().lookupEntryByNSID(_body.pid)) {
				auto uuid = (*maybeTargetProcess)->executableUuid();
				if (!callingProcess->writeMemory((uintptr_t)_body.uuid, uuid.data(), uuid.size(), &code)) {
					code = -code;
				}
			} else {
				// not negated because this is an acceptable case (see GetExecutablePath).
				code = ESRCH;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::GetExecutablePath::processCall() {
	int code = 0;
	uint64_t fullLength;

	if (auto callingThread = _thread.lock()) {
		if (auto callingProcess = callingThread->process()) {
			if (auto maybeTargetProcess = processRegistry().lookupEntryByNSID(_body.pid)) {
				auto targetProcess = *maybeTargetProcess;
				auto path = targetProcess->executablePath();
				auto len = std::min(path.length() + 1, _body.buffer_size);
				if (!callingProcess->writeMemory((uintptr_t)_body.buffer, path.c_str(), len, &code)) {
					code = -code;
				}
				fullLength = path.length();
			} else {
				// not negated because this is an acceptable case.
				// e.g. the target process may have died before the call was processed.
				code = ESRCH;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, fullLength);
}

void DarlingServer::Call::Groups::processCall() {
	int code = 0;
	std::vector<uint32_t> oldGroups;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			oldGroups = process->groups();

			if (_body.new_groups != 0 && _body.new_group_count > 0) {
				std::vector<uint32_t> newGroups;
				newGroups.resize(_body.new_group_count);

				if (!process->readMemory((uintptr_t)_body.new_groups, newGroups.data(), newGroups.size() * sizeof(uint32_t), &code)) {
					code = -code;
				} else {
					process->setGroups(newGroups);
				}
			}

			if (code == 0 && _body.old_groups != 0 && _body.old_group_space > 0) {
				auto len = std::min(oldGroups.size(), _body.old_group_space) * sizeof(uint32_t);
				if (!process->writeMemory((uintptr_t)_body.old_groups, oldGroups.data(), len, &code)) {
					code = -code;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, oldGroups.size());
};

void DarlingServer::Call::DebugListProcesses::processCall() {
	int code = 0;
	auto processes = processRegistry().copyEntries();
	int pipes[2] = {-1, -1};

	code = pipe(pipes);
	if (code == 0) {
		for (const auto& process: processes) {
			dserver_debug_process_t debugProcess;
			debugProcess.pid = process->nsid();
			debugProcess.port_count = dtape_debug_task_port_count(process->_dtapeTask);
			write(pipes[1], &debugProcess, sizeof(debugProcess));
		}

		close(pipes[1]);
	}

	_sendReply(code, processes.size(), pipes[0]);
};

void DarlingServer::Call::DebugListPorts::processCall() {
	int code = 0;
	uint64_t portCount = 0;
	int pipes[2] = {-1, -1};

	if (auto maybeProcess = processRegistry().lookupEntryByNSID(_body.process)) {
		auto process = *maybeProcess;

		code = pipe(pipes);
		if (code == 0) {
			portCount = dtape_debug_task_list_ports(process->_dtapeTask, [](void* context, const dtape_debug_port_t* port) {
				int& writeFD = *(int*)context;
				dserver_debug_port_t debugPort;

				debugPort.port_name = port->name;
				debugPort.rights = port->rights;
				debugPort.refs = port->refs;
				debugPort.messages = port->messages;

				write(writeFD, &debugPort, sizeof(debugPort));

				return true;
			}, &pipes[1]);
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, portCount, pipes[0]);
};

void DarlingServer::Call::DebugListMembers::processCall() {
	int code = 0;
	uint64_t portCount = 0;
	int pipes[2] = {-1, -1};

	if (auto maybeProcess = processRegistry().lookupEntryByNSID(_body.process)) {
		auto process = *maybeProcess;

		code = pipe(pipes);
		if (code == 0) {
			portCount = dtape_debug_portset_list_members(process->_dtapeTask, _body.portset, [](void* context, const dtape_debug_port_t* port) {
				int& writeFD = *(int*)context;
				dserver_debug_port_t debugPort;

				debugPort.port_name = port->name;
				debugPort.rights = port->rights;
				debugPort.refs = port->refs;
				debugPort.messages = port->messages;

				write(writeFD, &debugPort, sizeof(debugPort));

				return true;
			}, &pipes[1]);
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, portCount, pipes[0]);
};

void DarlingServer::Call::DebugListMessages::processCall() {
	int code = 0;
	uint64_t portCount = 0;
	int pipes[2] = {-1, -1};

	if (auto maybeProcess = processRegistry().lookupEntryByNSID(_body.process)) {
		auto process = *maybeProcess;

		code = pipe(pipes);
		if (code == 0) {
			portCount = dtape_debug_port_list_messages(process->_dtapeTask, _body.port, [](void* context, const dtape_debug_message_t* port) {
				int& writeFD = *(int*)context;
				dserver_debug_message_t debugMessage;

				debugMessage.sender = port->sender;
				debugMessage.size = port->size;

				write(writeFD, &debugMessage, sizeof(debugMessage));

				return true;
			}, &pipes[1]);
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, portCount, pipes[0]);
};

void DarlingServer::Call::HostPid::processCall() {
	int code = 0;
	int32_t hostPID = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			hostPID = process->id();
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, hostPID);
};

void DarlingServer::Call::PidForHostPid::processCall() {
	int code = 0;
	int32_t pid = 0;

	if (_body.host_pid <= 0) {
		code = -ESRCH;
	} else if (auto maybeProcess = processRegistry().lookupEntryByID(_body.host_pid)) {
		pid = (*maybeProcess)->nsid();
	} else {
		code = -ESRCH;
	}

	_sendReply(code, pid);
};

DSERVER_CLASS_SOURCE_DEFS;

//
// code signing
//

static DarlingServer::Log codeSigningLog("codesign");

// where the trust store is in the prefix when `TrustStorePath` is not set
static constexpr const char* defaultTrustStorePath = "/private/var/db/darling/trustcache";

// the key that signs the trust store, in the Darling installation (outside the prefix's writable layer)
static std::string trustStorePublicKeyPath() {
	return DarlingServer::Config::libexecPath() + "/private/var/db/darling/trustcache.pub";
}

static bool trustStoreContains(const uint8_t* cdhash) {
	auto config = DarlingServer::SystemConfig::sharedInstance().current();
	std::string path = defaultTrustStorePath;
	std::string error;

	if (config.trust_store_path[0] != '\0') {
		path.assign(config.trust_store_path, strnlen(config.trust_store_path, sizeof(config.trust_store_path)));
	}

	bool found = DarlingServer::TrustStore::sharedInstance().contains(DarlingServer::Server::sharedInstance().prefix(), path, trustStorePublicKeyPath(), cdhash, error);

	if (!error.empty()) {
		codeSigningLog.warning() << "Cannot use the trust store " << path << ": " << error << codeSigningLog.endLog;
	}

	return found;
};

// looks up the process `pid` (0 for the caller); anyone may read the state of any process,
// only root may change that of another process
static int lookUpCodeSigningTarget(const std::shared_ptr<DarlingServer::Process>& caller, int32_t pid, bool modify, std::shared_ptr<DarlingServer::Process>& target) {
	if (pid == 0 || pid == caller->nsid()) {
		target = caller;
		return 0;
	}

	auto maybeTarget = DarlingServer::processRegistry().lookupEntryByNSID(pid);
	if (!maybeTarget) {
		return -ESRCH;
	}
	target = *maybeTarget;

	return (!modify || caller->guestUID() == 0) ? 0 : -EPERM;
};

int DarlingServer::Call::_mediateAttach(std::shared_ptr<Process> target, std::shared_ptr<Process> tracer) {
	using namespace CodeSigning;

	auto state = target->codeSigningState();
	if (state.code_signing_policy == dserver_code_signing_policy_off) {
		return 0;
	}

	bool isSelf = (tracer == target);
	std::shared_ptr<Process> caller;
	if (auto thread = _thread.lock()) {
		caller = thread->process();
	}

	// only the tracer itself (attaching) or the target (asking to be traced) may set a tracer
	bool fromParty = caller && (caller == tracer || caller == target);

	auto csr = SystemConfig::sharedInstance().current().csr_active_config;
	bool allowed = fromParty && attachRule(isSelf, tracer->guestUID(), target->guestUID(), state, csr);
	auto verdict = applyPolicy(state.code_signing_policy, allowed);

	if (verdict == Verdict::Denied) {
		codeSigningLog.warning() << "Attaching " << *tracer << " to " << *target << " denied" << codeSigningLog.endLog;
		// not negated, like the other errors of this call; ptrace() reports EBUSY for a process that denied attachment
		return (state.darling_flags & DSERVER_CS_DENY_ATTACH) ? EBUSY : EPERM;
	} else if (verdict == Verdict::WouldDeny) {
		codeSigningLog.info() << "Attaching " << *tracer << " to " << *target << " would be denied under enforcement" << codeSigningLog.endLog;
	}

	return 0;
};

int DarlingServer::Call::_mediateTracing(std::shared_ptr<Process> target) {
	using namespace CodeSigning;

	auto state = target->codeSigningState();
	if (state.code_signing_policy == dserver_code_signing_policy_off) {
		return 0;
	}

	std::shared_ptr<Process> caller;
	if (auto thread = _thread.lock()) {
		caller = thread->process();
	}

	// only the process's tracer, or the process itself, may change how it is traced
	bool allowed = caller && (caller == target || caller == target->tracerProcess());
	auto verdict = applyPolicy(state.code_signing_policy, allowed);

	if (verdict == Verdict::Denied) {
		codeSigningLog.warning() << "Tracing request for " << *target << " from a process that is not its tracer denied" << codeSigningLog.endLog;
		// not negated, like the other errors of these calls
		return EPERM;
	} else if (verdict == Verdict::WouldDeny) {
		codeSigningLog.info() << "Tracing request for " << *target << " from a process that is not its tracer would be denied under enforcement" << codeSigningLog.endLog;
	}

	return 0;
};

void DarlingServer::Call::CsRegisterImage::processCall() {
	int code = 0;
	uint32_t flags = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			// read before anything is recorded; the descriptor stays ours (and is closed with the call).
			// pages and the CMS signature are only checked when the process's policy asks for it.
			auto policy = process->codeSigningState().code_signing_policy;
			auto image = std::make_shared<CodeSigning::Image>(CodeSigning::verifyImage(_body.image, _body.image_offset, CodeSigning::checksForPolicy(policy), trustStoreContains));

			if (!process->registerCodeSigningImage(image)) {
				code = -EPERM;
			} else {
				flags = image->state.flags;
				if (image->state.status == dserver_cs_status_invalid && !image->error.empty()) {
					codeSigningLog.info() << *process << ": the image's signature is not valid: " << image->error << codeSigningLog.endLog;
				} else if (policy == dserver_code_signing_policy_warn && !image->error.empty()) {
					codeSigningLog.warning() << *process << ": the image's signature would not be valid under enforcement: " << image->error << codeSigningLog.endLog;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, flags);
};

void DarlingServer::Call::CsGetState::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			std::shared_ptr<Process> target;

			if (_body.state_size != sizeof(dserver_cs_state_t)) {
				code = -EINVAL;
			} else if ((code = lookUpCodeSigningTarget(process, _body.pid, false, target)) == 0) {
				auto state = target->codeSigningState();
				if (!process->writeMemory(_body.state, &state, sizeof(state), &code)) {
					code = -code;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::CsCopyEntitlements::processCall() {
	int code = 0;
	uint64_t length = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			std::shared_ptr<Process> target;

			if ((code = lookUpCodeSigningTarget(process, _body.pid, false, target)) == 0) {
				if (auto image = target->codeSigningImage()) {
					const auto& blob = _body.der ? image->derEntitlements : image->entitlements;
					length = blob.size();

					if (length > _body.buffer_size) {
						code = -ERANGE;
					} else if (length > 0 && !process->writeMemory(_body.buffer, blob.data(), blob.size(), &code)) {
						code = -code;
					}
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, length);
};

void DarlingServer::Call::CsUpdateFlags::processCall() {
	int code = 0;
	uint32_t flags = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			std::shared_ptr<Process> target;

			if ((_body.set_flags & ~CodeSigning::settableFlags()) != 0 || (_body.clear_flags & ~CodeSigning::clearableFlags()) != 0) {
				code = -EINVAL;
			} else if ((code = lookUpCodeSigningTarget(process, _body.pid, true, target)) == 0) {
				if ((_body.clear_flags & CodeSigning::libraryValidationFlags()) != 0) {
					// a process can only turn its own library validation off
					auto image = target->codeSigningImage();
					if (target != process || !CodeSigning::clearLibraryValidationRule(target->codeSigningState().code_signing_policy, image ? *image : CodeSigning::Image())) {
						code = -EPERM;
					}
				}
				if (code == 0) {
					flags = target->updateCodeSigningFlags(_body.set_flags, _body.clear_flags);
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, flags);
};

void DarlingServer::Call::CsDenyAttach::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			process->denyAttach();
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::CsMarkSandboxed::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			process->markSandboxed();
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::CsVerifyImage::processCall() {
	int code = 0;
	uint32_t status = dserver_cs_status_invalid;
	uint32_t flags = 0;
	uint64_t codeLimit = 0;
	uint32_t pageSizeLog2 = 0;
	bool libraryValidationOk = false;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			auto state = process->codeSigningState();
			bool enforced = state.code_signing_policy == dserver_code_signing_policy_enforce;
			auto library = CodeSigning::verifyImage(_body.image, _body.image_offset, CodeSigning::checksForPolicy(state.code_signing_policy), trustStoreContains);
			auto mainImage = process->codeSigningImage();
			std::string error;

			status = library.state.status;
			flags = library.state.flags;
			codeLimit = library.state.code_limit;
			pageSizeLog2 = library.pageSizeLog2;
			// library validation only refuses anything under enforcement
			libraryValidationOk = !enforced || CodeSigning::libraryValidationAllows(state, mainImage ? *mainImage : CodeSigning::Image(), library, error);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, status, flags, codeLimit, pageSizeLog2, libraryValidationOk);
};

//
// IOSurface service (see "IOSurface service" in rpc-supplement.h)
//

void DarlingServer::Call::IosurfaceRetain::processCall() {
	int code = 0;
	uint32_t surfaceID = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			code = IOSurfaceRegistry::sharedInstance().retain(process->id(), _body.memory, _body.id_hint, _body.flags, _body.counter_offset, &surfaceID);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, surfaceID);
};

void DarlingServer::Call::IosurfaceRelease::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			code = IOSurfaceRegistry::sharedInstance().release(process->id(), _body.surface_id);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::IosurfaceLookup::processCall() {
	int code = 0;
	int memory = -1;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			code = IOSurfaceRegistry::sharedInstance().lookup(process->id(), _body.surface_id, &memory);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	// the reply takes ownership of the new descriptor
	_sendReply(code, memory);
};

void DarlingServer::Call::IosurfacePublishGpuBuffer::processCall() {
	int code = 0;
	int published = -1;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			dserver_iosurface_gpu_buffer_t info;
			if (_body.info_size != sizeof(info)) {
				code = -EINVAL;
			} else if (!process->readMemory(_body.info, &info, sizeof(info), &code)) {
				code = -code;
			} else {
				dserver_iosurface_gpu_buffer_t publishedInfo;
				code = IOSurfaceRegistry::sharedInstance().publishGPUBuffer(process->id(), _body.surface_id, _body.buffer, info, &published, &publishedInfo);
				if (code == 0 && !process->writeMemory(_body.info, &publishedInfo, sizeof(publishedInfo), &code)) {
					code = -code;
					close(published);
					published = -1;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, published);
};

void DarlingServer::Call::IosurfaceCopyGpuBuffer::processCall() {
	int code = 0;
	int buffer = -1;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			dserver_iosurface_gpu_buffer_t info;
			if (_body.info_size != sizeof(info)) {
				code = -EINVAL;
			} else {
				code = IOSurfaceRegistry::sharedInstance().copyGPUBuffer(process->id(), _body.surface_id, &buffer, &info);
				if (code == 0 && !process->writeMemory(_body.info, &info, sizeof(info), &code)) {
					code = -code;
					close(buffer);
					buffer = -1;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, buffer);
};

void DarlingServer::Call::IosurfaceSetUsage::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			code = IOSurfaceRegistry::sharedInstance().setUsage(process->id(), _body.surface_id, _body.usage);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::IosurfaceGetState::processCall() {
	int code = 0;
	IOSurfaceRegistry::State state {};

	if (auto thread = _thread.lock()) {
		if (thread->process()) {
			code = IOSurfaceRegistry::sharedInstance().getState(_body.surface_id, &state);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, state.holders, state.memoryUsers, state.flags);
};
