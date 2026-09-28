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
 * This file registers the function table (it started as safe no-ops/error
 * returns). Every entry is now real: bsdthread_register/create/terminate,
 * thread_selfid, the workq_* thread-stack hooks and pthread_init come from
 * kern_support.c (bsd_pthread_workq.c); the psynch_* syscalls, the
 * per-process psynch hash and the stackshot owner lookups are kern_synch.c
 * (bsd_pthread_synch.c, DAR-416). Only bsdthread_register2 stays ENOTSUP.
 *
 * bsdthread_create()/bsdthread_terminate() are now real, full
 * implementations of the real pthread ABI (verbatim ports of
 * third_party/libpthread/kern/kern_support.c's real
 * _bsdthread_create/_bsdthread_terminate, see bsd_pthread_workq.c) - a
 * real Mach thread port is allocated and returned in x1 (matching
 * _pthread_start(self, kport, fun, arg, stacksize, pflags)'s real
 * parameter order), and bsdthread_terminate() really deallocates the
 * caller's stack and self-terminates via thread_terminate(current_thread())
 * before returning to userspace via pthread_kern->thread_exception_return().
 * This supersedes an earlier, deliberately minimal version documented
 * here (no thread port, PC/SP/x0 set directly from raw arguments, not
 * pthread_create()-compatible) - see git history for that version if
 * needed. See docs/daemon-roadmap.md's Phase 6.6 entry for the real
 * userland gap this closes (pthread_join()/_pthread_terminate() call
 * bsdthread_terminate() unconditionally at thread exit).
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

/*
 * DAR-416: pthread init, the per-process psynch hash, the psynch_* syscalls
 * and the stackshot owner lookups are real now. bsd_pthread_synch.c is
 * third_party/libpthread/kern/kern_synch.c, and real_pthread_init() is
 * kern_support.c's _pthread_init (bsd_pthread_workq.c). They were no-op /
 * ENOTSUP stubs here. That was invisible under this port's hand-written
 * userland pthread, but Apple's libpthread takes psynch for every
 * RECURSIVE/ERRORCHECK mutex and every rwlock (pthread_mutex.c:1765-1779
 * restricts ulock to NORMAL firstfit), so a contended one spun at 100% CPU
 * (configd's CFFDManager lock). Each slot is declared with its own
 * pthread_functions_s type, so the table matches kern_init.c:19-39.
 */
#define PTHREAD_REAL_FN(slot, fn) \
	extern __typeof__(*((pthread_functions_t)0)->slot) fn
extern void real_pthread_init(void);
PTHREAD_REAL_FN(pth_proc_hashinit, _pth_proc_hashinit);
PTHREAD_REAL_FN(pth_proc_hashdelete, _pth_proc_hashdelete);
PTHREAD_REAL_FN(psynch_mutexwait, _psynch_mutexwait);
PTHREAD_REAL_FN(psynch_mutexdrop, _psynch_mutexdrop);
PTHREAD_REAL_FN(psynch_cvbroad, _psynch_cvbroad);
PTHREAD_REAL_FN(psynch_cvsignal, _psynch_cvsignal);
PTHREAD_REAL_FN(psynch_cvwait, _psynch_cvwait);
PTHREAD_REAL_FN(psynch_cvclrprepost, _psynch_cvclrprepost);
PTHREAD_REAL_FN(psynch_rw_longrdlock, _psynch_rw_longrdlock);
PTHREAD_REAL_FN(psynch_rw_rdlock, _psynch_rw_rdlock);
PTHREAD_REAL_FN(psynch_rw_unlock, _psynch_rw_unlock);
PTHREAD_REAL_FN(psynch_rw_wrlock, _psynch_rw_wrlock);
PTHREAD_REAL_FN(psynch_rw_yieldwrlock, _psynch_rw_yieldwrlock);
PTHREAD_REAL_FN(pthread_find_owner, _pthread_find_owner);
PTHREAD_REAL_FN(pthread_get_thread_kwq, _pthread_get_thread_kwq);

/*
 * real_bsdthread_create()/real_bsdthread_terminate(): now real, verbatim
 * ports from third_party/libpthread/kern/kern_support.c's
 * _bsdthread_create/_bsdthread_terminate (same real infrastructure
 * real_bsdthread_register above already uses) -- see
 * bsd/kern/bsd_pthread_workq.c's own header comment for the full
 * evidence trail. This supersedes an earlier, deliberately minimal
 * version that lived here (no real thread port allocated/returned, no
 * pthread-ABI register convention, `bsdthread_terminate` an
 * unconditional ENOTSUP stub) -- real userland `pthread_join()`/
 * `_pthread_terminate()` call `bsdthread_terminate()` unconditionally
 * at thread exit, which made every userland thread whose start routine
 * returned hit `PTHREAD_INTERNAL_CRASH`. Both functions now live in
 * bsd_pthread_workq.c, declared extern below (same pattern as
 * real_bsdthread_register).
 */
extern int real_bsdthread_create(struct proc *p, user_addr_t user_func,
    user_addr_t user_funcarg, user_addr_t user_stack, user_addr_t user_pthread,
    uint32_t flags, user_addr_t *retval);
extern int real_bsdthread_terminate(struct proc *p, user_addr_t stackaddr,
    size_t size, uint32_t kthport, uint32_t sem, int32_t *retval);
extern int real_thread_selfid(struct proc *p, uint64_t *retval);

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
	.pthread_init = real_pthread_init,
	.pth_proc_hashinit = _pth_proc_hashinit,
	.pth_proc_hashdelete = _pth_proc_hashdelete,
	.bsdthread_create = real_bsdthread_create,
	.bsdthread_register = real_bsdthread_register,
	.bsdthread_terminate = real_bsdthread_terminate,
	.thread_selfid = real_thread_selfid,
	.psynch_mutexwait = _psynch_mutexwait,
	.psynch_mutexdrop = _psynch_mutexdrop,
	.psynch_cvbroad = _psynch_cvbroad,
	.psynch_cvsignal = _psynch_cvsignal,
	.psynch_cvwait = _psynch_cvwait,
	.psynch_cvclrprepost = _psynch_cvclrprepost,
	.psynch_rw_longrdlock = _psynch_rw_longrdlock,
	.psynch_rw_rdlock = _psynch_rw_rdlock,
	.psynch_rw_unlock = _psynch_rw_unlock,
	.psynch_rw_wrlock = _psynch_rw_wrlock,
	.psynch_rw_yieldwrlock = _psynch_rw_yieldwrlock,
	.bsdthread_register2 = stub_bsdthread_register2,
	.pthread_find_owner = _pthread_find_owner,
	.pthread_get_thread_kwq = _pthread_get_thread_kwq,
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
