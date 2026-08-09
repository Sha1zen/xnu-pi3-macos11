/*
 * bsd_pthread_stub.c - minimal pthread-kext function-table stand-in for
 * xnu-on-rpi3.
 *
 * bsd/pthread/pthread_shims.c's pthread_init()/pth_proc_hashinit()/etc. are
 * thin shims onto a `pthread_functions` vtable that real macOS populates via
 * pthread_kext_register(), called by the real pthread.kext at kext-load
 * time. That kext's actual implementation (bsdthread_create, psynch_*,
 * workq_* - the real userspace-pthread scheduling primitives) is Apple-
 * internal and was never part of any apple-oss-distributions release, same
 * situation as launchd/opendirectoryd (see project memory) - there is
 * nothing to vendor here.
 *
 * This project has no kext-loading infrastructure at all, so nothing would
 * ever call pthread_kext_register() otherwise - bsd_init()'s own
 * unconditional `pthread_init()` call panics outright ("pthread kernel
 * extension not loaded (function table is NULL)"), a real, unavoidable
 * architectural gap, not a bug in anything we wrote.
 *
 * Minimal, honest stand-in: register a function table of safe no-ops/error
 * returns, just enough that bsd_init()'s own pthread_init() call and normal
 * BSD proc lifecycle (pth_proc_hashinit/pth_proc_hashdelete, called
 * unconditionally from fork/exit) don't crash. The actual pthread syscalls
 * (bsdthread_create, psynch_*, workq_*) return an error rather than doing
 * anything real - our minimal static init binary (tools/init_binary) does
 * not use pthreads and was built specifically to avoid needing them; if a
 * future userland component needs real pthread_create()/pthread_mutex_*
 * support, this is where that real implementation would need to go.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/pthread_shims.h>

static void
stub_pthread_init(void)
{
}

static void
stub_pth_proc_hashinit(proc_t p)
{
	(void)p;
}

static void
stub_pth_proc_hashdelete(proc_t p)
{
	(void)p;
}

static int
stub_bsdthread_create(struct proc *p, user_addr_t user_func, user_addr_t user_funcarg,
    user_addr_t user_stack, user_addr_t user_pthread, uint32_t flags, user_addr_t *retval)
{
	(void)p; (void)user_func; (void)user_funcarg; (void)user_stack; (void)user_pthread; (void)flags;
	if (retval) {
		*retval = 0;
	}
	return ENOTSUP;
}

static int
stub_bsdthread_register(struct proc *p, user_addr_t threadstart, user_addr_t wqthread,
    int pthsize, user_addr_t dummy_value, user_addr_t targetconc_ptr,
    uint64_t dispatchqueue_offset, int32_t *retval)
{
	(void)p; (void)threadstart; (void)wqthread; (void)pthsize; (void)dummy_value;
	(void)targetconc_ptr; (void)dispatchqueue_offset;
	if (retval) {
		*retval = 0;
	}
	return ENOTSUP;
}

static int
stub_bsdthread_register2(struct proc *p, user_addr_t threadstart, user_addr_t wqthread,
    uint32_t flags, user_addr_t stack_addr_hint, user_addr_t targetconc_ptr,
    uint32_t dispatchqueue_offset, uint32_t tsd_offset, int32_t *retval)
{
	(void)p; (void)threadstart; (void)wqthread; (void)flags; (void)stack_addr_hint;
	(void)targetconc_ptr; (void)dispatchqueue_offset; (void)tsd_offset;
	if (retval) {
		*retval = 0;
	}
	return ENOTSUP;
}

static int
stub_bsdthread_terminate(struct proc *p, user_addr_t stackaddr, size_t size,
    uint32_t kthport, uint32_t sem, int32_t *retval)
{
	(void)p; (void)stackaddr; (void)size; (void)kthport; (void)sem;
	if (retval) {
		*retval = 0;
	}
	return ENOTSUP;
}

static int
stub_thread_selfid(struct proc *p, uint64_t *retval)
{
	(void)p;
	if (retval) {
		*retval = 0;
	}
	return ENOTSUP;
}

static int
stub_psynch_error(void)
{
	return ENOTSUP;
}

static void
stub_pthread_find_owner(thread_t thread, struct stackshot_thread_waitinfo *waitinfo)
{
	(void)thread;
	(void)waitinfo;
}

static void *
stub_pthread_get_thread_kwq(thread_t thread)
{
	(void)thread;
	return NULL;
}

static int
stub_workq_handle_stack_events(proc_t p, thread_t th, vm_map_t map,
    user_addr_t stackaddr, mach_port_name_t kport,
    user_addr_t events, int nevents, int upcall_flags)
{
	(void)p; (void)th; (void)map; (void)stackaddr; (void)kport;
	(void)events; (void)nevents; (void)upcall_flags;
	return ENOTSUP;
}

static int
stub_workq_create_threadstack(proc_t p, vm_map_t vmap, mach_vm_offset_t *out_addr)
{
	(void)p; (void)vmap;
	if (out_addr) {
		*out_addr = 0;
	}
	return ENOTSUP;
}

static int
stub_workq_destroy_threadstack(proc_t p, vm_map_t vmap, mach_vm_offset_t stackaddr)
{
	(void)p; (void)vmap; (void)stackaddr;
	return ENOTSUP;
}

static void
stub_workq_setup_thread(proc_t p, thread_t th, vm_map_t map, user_addr_t stackaddr,
    mach_port_name_t kport, int th_qos, int setup_flags, int upcall_flags)
{
	(void)p; (void)th; (void)map; (void)stackaddr; (void)kport;
	(void)th_qos; (void)setup_flags; (void)upcall_flags;
}

static void
stub_workq_markfree_threadstack(proc_t p, thread_t th, vm_map_t map, user_addr_t stackaddr)
{
	(void)p; (void)th; (void)map; (void)stackaddr;
}

static const struct pthread_functions_s bsd_pthread_stub_functions = {
	.version = PTHREAD_FUNCTIONS_TABLE_VERSION,
	.pthread_init = stub_pthread_init,
	.pth_proc_hashinit = stub_pth_proc_hashinit,
	.pth_proc_hashdelete = stub_pth_proc_hashdelete,
	.bsdthread_create = stub_bsdthread_create,
	.bsdthread_register = stub_bsdthread_register,
	.bsdthread_terminate = stub_bsdthread_terminate,
	.thread_selfid = stub_thread_selfid,
	.psynch_mutexwait = (typeof(((pthread_functions_t)0)->psynch_mutexwait))stub_psynch_error,
	.psynch_mutexdrop = (typeof(((pthread_functions_t)0)->psynch_mutexdrop))stub_psynch_error,
	.psynch_cvbroad = (typeof(((pthread_functions_t)0)->psynch_cvbroad))stub_psynch_error,
	.psynch_cvsignal = (typeof(((pthread_functions_t)0)->psynch_cvsignal))stub_psynch_error,
	.psynch_cvwait = (typeof(((pthread_functions_t)0)->psynch_cvwait))stub_psynch_error,
	.psynch_cvclrprepost = (typeof(((pthread_functions_t)0)->psynch_cvclrprepost))stub_psynch_error,
	.psynch_rw_longrdlock = (typeof(((pthread_functions_t)0)->psynch_rw_longrdlock))stub_psynch_error,
	.psynch_rw_rdlock = (typeof(((pthread_functions_t)0)->psynch_rw_rdlock))stub_psynch_error,
	.psynch_rw_unlock = (typeof(((pthread_functions_t)0)->psynch_rw_unlock))stub_psynch_error,
	.psynch_rw_wrlock = (typeof(((pthread_functions_t)0)->psynch_rw_wrlock))stub_psynch_error,
	.psynch_rw_yieldwrlock = (typeof(((pthread_functions_t)0)->psynch_rw_yieldwrlock))stub_psynch_error,
	.bsdthread_register2 = stub_bsdthread_register2,
	.pthread_find_owner = stub_pthread_find_owner,
	.pthread_get_thread_kwq = stub_pthread_get_thread_kwq,
	.workq_handle_stack_events = stub_workq_handle_stack_events,
	.workq_create_threadstack = stub_workq_create_threadstack,
	.workq_destroy_threadstack = stub_workq_destroy_threadstack,
	.workq_setup_thread = stub_workq_setup_thread,
	.workq_markfree_threadstack = stub_workq_markfree_threadstack,
};

void
bsd_pthread_stub_register(void)
{
	pthread_callbacks_t discard_callbacks;
	pthread_kext_register((pthread_functions_t)&bsd_pthread_stub_functions, &discard_callbacks);
}
