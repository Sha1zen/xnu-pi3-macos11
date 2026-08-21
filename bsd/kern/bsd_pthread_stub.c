/*
 * bsd_pthread_stub.c - minimal pthread-kext function-table stand-in for
 * xnu-on-rpi3.
 *
 * bsd/pthread/pthread_shims.c's pthread_init()/pth_proc_hashinit()/etc. are
 * thin shims onto a `pthread_functions` vtable that real macOS populates via
 * pthread_kext_register(), called by the real pthread.kext at kext-load
 * time. CORRECTED (see bsd_pthread_workq.c's header comment for the full
 * evidence trail): only bsdthread_create's real scheduling-policy pieces
 * and psynch_*'s userspace-mutex/cv slow path are genuinely Apple-internal
 * and unavailable, same situation as launchd/opendirectoryd (see project
 * memory). bsdthread_register and all five workq_* thread-stack hooks
 * DO have real, open-source implementations - they're pthread.kext's own
 * real kernel-support code, shipped as third_party/libpthread's own
 * kern/ subdirectory (Apple builds that as a real kext; this project has
 * no kext-loading boundary, so it's linked directly into the kernel
 * instead, same as everything else here) - now ported for real in
 * bsd/kern/bsd_pthread_workq.c, not stubbed.
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
 * unconditionally from fork/exit) don't crash. psynch_* and
 * bsdthread_terminate/thread_selfid still return an error rather than
 * doing anything real (psynch_* is real, substantial design+
 * implementation work of its own, deliberately out of scope here - see
 * docs/roadmap.md Phase 7.5). bsdthread_register and the five workq_*
 * thread-stack hooks are real as of this pass (bsd_pthread_workq.c).
 *
 * bsdthread_create() below IS now real: it creates a genuine second Mach
 * thread in the calling task using exactly the primitives Apple's real
 * pthread_shims.c hands the (closed-source) pthread.kext for this purpose
 * via the `pthread_kern` callback table (pthread_kern->thread_create /
 * ->thread_set_wq_state64 / ->thread_resume - see pthread_shims.c's
 * `pthread_callbacks` initializer, which wires these directly to the real,
 * open-source osfmk/kern/thread.c and osfmk/arm64/status.c implementations
 * already used elsewhere in this exact kernel - e.g.
 * bsd/dev/arm/unix_signal.c's sendsig_set_thread_state64() already sets up
 * an arm_thread_state64_t for a thread returning to userspace via the same
 * real signal-delivery path, and osfmk/arm64/locore.s's
 * thread_bootstrap_return -> arm64_thread_exception_return is the exact
 * same real, already-proven-safe return-to-EL0 path every exec() in this
 * project already goes through). No new machine-dependent code was written
 * for this - it is a direct, minimal use of existing real primitives.
 *
 * This does NOT implement the real pthread ABI (no libpthread trampoline,
 * no TSD/dispatch-queue wiring, no thread port returned for
 * bsdthread_terminate/pthread_kill to target) - it hands the new thread's
 * PC/SP/x0 directly from bsdthread_create()'s own raw arguments, which is
 * enough for a real second thread to run real code, but is NOT
 * pthread_create()-compatible. bsdthread_terminate and psynch_* remain
 * stubbed; see the real test program at tools/pthread_kthread_test/ for
 * the smallest real, verified exercise of this specific path (workqueue
 * thread creation has its own separate real test, see
 * bsd_pthread_workq.c and docs/roadmap.md Phase 7.5).
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/pthread_shims.h>
#include <sys/proc_internal.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <mach/arm/thread_status.h>
#include <mach/kern_return.h>
#include <mach/thread_act.h>

/*
 * Real implementations, ported from third_party/libpthread (real,
 * open-source pthread.kext kernel-support code - see
 * bsd/kern/bsd_pthread_workq.c's own header comment for the full
 * evidence trail and why this corrects the assumption in this file's
 * own header comment above that none of this was ever open-sourced).
 */
extern int real_bsdthread_register(struct proc *p, user_addr_t threadstart,
    user_addr_t wqthread, int pthsize, user_addr_t pthread_init_data,
    user_addr_t pthread_init_data_size, uint64_t dispatchqueue_offset,
    int32_t *retval);
extern int workq_create_threadstack(proc_t p, vm_map_t vmap, mach_vm_offset_t *out_addr);
extern int workq_destroy_threadstack(proc_t p, vm_map_t vmap, mach_vm_offset_t stackaddr);
extern void workq_setup_thread(proc_t p, thread_t th, vm_map_t map, user_addr_t stackaddr,
    mach_port_name_t kport, int th_qos, int setup_flags, int upcall_flags);
extern void workq_markfree_threadstack(proc_t p, thread_t th, vm_map_t map, user_addr_t stackaddr);
extern int workq_handle_stack_events(proc_t p, thread_t th, vm_map_t map,
    user_addr_t stackaddr, mach_port_name_t kport, user_addr_t events,
    int nevents, int upcall_flags);

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

/*
 * real_bsdthread_create() - minimal real second-Mach-thread creation.
 *
 * Sequence (deliberately mirrors bsd/kern/kern_fork.c's fork()/fork1() and
 * bsd/kern/kern_exec.c's new-thread setup, both of which already do
 * "create -> set initial register state -> resume -> drop our creation
 * reference" for a thread that's about to run real userspace code on this
 * exact kernel):
 *
 *   1. pthread_kern->thread_create(current_task(), &th) - real
 *      osfmk/kern/thread.c thread_create(). Returns a thread that is
 *      already suspended (thread_create() always leaves a fresh thread
 *      with user_stop_count=1 - see osfmk/kern/thread.c) so its register
 *      state can be set safely before anything can run.
 *   2. pthread_kern->thread_set_wq_state64(th, &state) - real
 *      osfmk/arm64/status.c thread_set_wq_state64(), the same primitive
 *      pthread.kext itself would have used for this. Sets pc/sp/x0 only;
 *      no pthread-ABI trampoline args (kport/self/flags in x1-x3) because
 *      this does not implement the real libpthread contract, only real
 *      thread creation.
 *   3. pthread_kern->thread_resume(th) - undoes the create-time suspend;
 *      the thread now runs for real, entering userspace at user_func via
 *      thread_bootstrap_return -> arm64_thread_exception_return (real,
 *      already-exercised-by-every-exec() path).
 *   4. thread_deallocate(th) - drop our local creation reference, exactly
 *      like fork()'s "drop the extra references we got during the
 *      creation" (kern_fork.c) does for the child thread it just started.
 *      The thread continues to exist/run via the task's own internal
 *      thread-list reference, not this one.
 *
 * No thread port is created/returned (real bsdthread_create returns a
 * mach port name in *retval for later pthread_kill/bsdthread_terminate
 * use) - out of scope for this minimal step, so *retval is left 0 and
 * there is currently no way for userspace to terminate/signal the new
 * thread individually. It exits only when the whole task exits (real,
 * pre-existing task_terminate_internal() teardown, exercised here for the
 * first time with >1 live thread in a task - this is exactly the case
 * tools/pthread_kthread_test/ is designed to exercise and QEMU-verify).
 */
static int
real_bsdthread_create(struct proc *p, user_addr_t user_func, user_addr_t user_funcarg,
    user_addr_t user_stack, user_addr_t user_pthread, uint32_t flags, user_addr_t *retval)
{
	thread_t th = THREAD_NULL;
	kern_return_t kr;
	arm_thread_state64_t state;

	(void)p; (void)user_pthread; (void)flags;

	if (retval) {
		*retval = 0;
	}

	kr = pthread_kern->thread_create(current_task(), &th);
	if (kr != KERN_SUCCESS || th == THREAD_NULL) {
		return EAGAIN;
	}

	bzero(&state, sizeof(state));
	state.pc = user_func;
	state.sp = user_stack;
	state.x[0] = user_funcarg;

	kr = pthread_kern->thread_set_wq_state64(th, (thread_state_t)&state);
	if (kr != KERN_SUCCESS) {
		thread_terminate(th);
		thread_deallocate(th);
		return EINVAL;
	}

	kr = pthread_kern->thread_resume(th);
	if (kr != KERN_SUCCESS) {
		thread_terminate(th);
		thread_deallocate(th);
		return EINVAL;
	}

	thread_deallocate(th);
	return 0;
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

static const struct pthread_functions_s bsd_pthread_stub_functions = {
	/*
	 * version = 0, NOT PTHREAD_FUNCTIONS_TABLE_VERSION (1) - deliberate,
	 * evidence-backed (see bsd_pthread_workq.c's header comment): real
	 * third_party/libpthread/kern/kern_init.c's own
	 * `pthread_internal_functions` initializer leaves `.version` unset
	 * (defaults to 0), which is what makes bsd/pthread/pthread_shims.c's
	 * real bsdthread_register() syscall wrapper dispatch through the
	 * OLDER `.bsdthread_register` slot below (populated with
	 * real_bsdthread_register) instead of `.bsdthread_register2`
	 * (left as an unreachable-by-design ENOTSUP stub - the newer
	 * TSD-offset-aware SPI, no real consumer in this project's pinned
	 * libpthread vintage).
	 */
	.version = 0,
	.pthread_init = stub_pthread_init,
	.pth_proc_hashinit = stub_pth_proc_hashinit,
	.pth_proc_hashdelete = stub_pth_proc_hashdelete,
	.bsdthread_create = real_bsdthread_create,
	.bsdthread_register = real_bsdthread_register,
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
	.workq_handle_stack_events = workq_handle_stack_events,
	.workq_create_threadstack = workq_create_threadstack,
	.workq_destroy_threadstack = workq_destroy_threadstack,
	.workq_setup_thread = workq_setup_thread,
	.workq_markfree_threadstack = workq_markfree_threadstack,
};

void
bsd_pthread_stub_register(void)
{
	pthread_callbacks_t discard_callbacks;
	pthread_kext_register((pthread_functions_t)&bsd_pthread_stub_functions, &discard_callbacks);
}
