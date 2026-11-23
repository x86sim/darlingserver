#ifndef _DARLINGSERVER_DUCT_TAPE_MEMORY_H_
#define _DARLINGSERVER_DUCT_TAPE_MEMORY_H_

#include <stdint.h>
#include <mach/vm_types.h>
#include <os/refcnt.h>
#include <sys/tree.h>

#include <darlingserver/duct-tape/locks.h>

struct dtape_task;
struct dtape_thread;

typedef struct dtape_map_shared_descriptor {
	os_refcnt_t refcount;
	int memfd;
	uint64_t size;
	// x86Sim: the memfd's inode, and a link in the list of all descriptors (to find the descriptor of a
	// process's existing MAP_SHARED mapping by the inode in /proc/<pid>/maps)
	uint64_t inode;
	// (x86Sim: one list per hash bucket of the inode; the list of all descriptors was walked for every share)
	struct dtape_map_shared_descriptor* all_next;
	struct dtape_map_shared_descriptor** all_prev;
} dtape_map_shared_descriptor_t;

typedef struct dtape_map_shared_entry {
	RB_ENTRY(dtape_map_shared_entry) link;
	uint64_t address;
	uint64_t size;
	uint64_t page_offset;
	dtape_map_shared_descriptor_t* descriptor;
} dtape_map_shared_entry_t;

typedef RB_HEAD(dtape_map_shared_entry_head, dtape_map_shared_entry) dtape_map_shared_entry_head_t;

struct _vm_map {
	uint32_t dtape_page_shift;
	uint64_t max_offset;
	os_refcnt_t map_refcnt;
	struct dtape_task* dtape_task;
	dtape_map_shared_entry_head_t shared_entries;
	dtape_mutex_t shared_entry_lock;
	// x86Sim: the largest size of any entry ever inserted: entries overlapping [a, b) start in [a - max, b),
	// so a lookup walks only those instead of the whole tree (entries outlive munmap, the tree only grows)
	uint64_t max_entry_size;
	// x86Sim: when the entries were last checked against the process's mappings (dtape_map_prune_shared_entries)
	uint64_t last_prune_ns;
	// x86Sim: a link in the list of all maps (dtape_memory_sweep_tick checks every map's entries in turn)
	struct _vm_map* all_next;
	struct _vm_map** all_prev;
};

typedef struct _vm_map dtape_map_t;

// releases the object kept by mach_make_memory_entry_internal() for the given thread (if any)
void dtape_thread_release_kept_descriptor(struct dtape_thread* thread);

// maps `size` bytes in `map` for the given out-of-line copy or port array (`key`) of the message the current thread
// is receiving, unless already done; the message's copyout takes the region with dtape_thread_take_reserved_region()
kern_return_t dtape_thread_reserve_region(vm_map_t map, const void* key, vm_size_t size);
// returns the region reserved for `key` by the current thread and forgets it, or 0 if there is none
uintptr_t dtape_thread_take_reserved_region(const void* key);
// unmaps (when `map` is given) and forgets the regions the thread reserved but didn't use
void dtape_thread_release_reserved_regions(struct dtape_thread* thread, vm_map_t map);

#define VM_MAP_PAGE_SHIFT(map) ((map) ? (map)->dtape_page_shift : PAGE_SHIFT)

struct vm_map_header {

};

struct vm_map_copy {
	int type;
	uint64_t offset;
	uint64_t size;
	union {
		struct vm_map_header hdr;
		vm_object_t object;
		void* kdata;
	} c_u;
	// x86Sim: >= 0 when the data is in a frozen memfd instead of dtape_copy_data (large copies, memory.c)
	int dtape_frozen_fd;
	char dtape_copy_data[];
};

#define cpy_hdr c_u.hdr

#define cpy_object c_u.object
#define cpy_kdata c_u.kdata

#define VM_MAP_COPY_ENTRY_LIST 1
#define VM_MAP_COPY_OBJECT 2
#define VM_MAP_COPY_KERNEL_BUFFER 3

void dtape_memory_init(void);
vm_map_t dtape_vm_map_create(struct dtape_task* task);
void dtape_vm_map_destroy(vm_map_t map);

#endif // _DARLINGSERVER_DUCT_TAPE_MEMORY_H_
