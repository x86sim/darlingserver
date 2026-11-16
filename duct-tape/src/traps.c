#include <darlingserver/duct-tape.h>

#include <mach/mach_traps.h>

uint32_t dtape_task_self_trap(void) {
	return task_self_trap(NULL);
};

uint32_t dtape_host_self_trap(void) {
	return host_self_trap(NULL);
};

uint32_t dtape_thread_self_trap(void) {
	return thread_self_trap(NULL);
};

uint32_t dtape_mach_reply_port(void) {
	return mach_reply_port(NULL);
};

uint32_t dtape_thread_get_special_reply_port(void) {
	return thread_get_special_reply_port(NULL);
};

uint32_t dtape_mk_timer_create(void) {
	return mk_timer_create_trap(NULL);
};

// x86Sim: see host_darling_set_io_master_port()
struct set_io_master_port_args {
	uint32_t name;
};
extern kern_return_t host_darling_set_io_master_port(mach_port_name_t name);

static kern_return_t set_io_master_port(struct set_io_master_port_args* args) {
	return host_darling_set_io_master_port(args->name);
};

// x86Sim: see task_spawn_set_special_port()
struct spawn_set_special_port_args {
	int32_t which;
	uint32_t name;
};
extern kern_return_t task_spawn_set_special_port(int which, mach_port_name_t name);

static kern_return_t spawn_set_special_port(struct spawn_set_special_port_args* args) {
	return task_spawn_set_special_port(args->which, args->name);
};

DSERVER_DTAPE_DEFS;

