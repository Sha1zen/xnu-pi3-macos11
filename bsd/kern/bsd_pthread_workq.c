/*
 * bsd_pthread_workq.c - real workqueue thread-stack/setup hooks for the
 * `pthread_functions` vtable, ported from Apple's real, open-source
 * pthread.kext kernel-support code.
 *
 * CORRECTION to bsd_pthread_stub.c's own header comment (which claims the
 * pthread.kext implementation - bsdthread_create / psynch_* / workq_* - "was
 * never part of any apple-oss-distributions release"): that is true for
 * bsdthread_create's *scheduling policy* and psynch_*'s userspace-mutex
 * primitives, but false for the five workq_* thread-stack hooks and for
 * bsdthread_register - real, unmodified Apple source for all six already
 * sits in this project's own third_party/libpthread checkout (pinned
 * `libpthread-454.80.2`, confirmed against distribution-macOS's
 * `macos-112` manifest by setup_third_party.sh, same tag-verification
 * method this project always uses - see that script's own header
 * comment). third_party/libpthread/kern/kern_support.c +
 * kern/kern_init.c are literally pthread.kext's real kernel-side
 * implementation (Apple ships pthread.kext as *this* apple-oss-
 * distributions repo's kern/ subdirectory, built as a real kext on real
 * macOS/iOS - this project has no kext-loading boundary, so it's linked
 * directly into the kernel image instead, exactly like every other
 * "kext" in this project's iokit/ tree). This was missed by the
 * previous (bsdthread_create) session; found here by actually reading
 * third_party/libpthread/kern/ instead of trusting the older header
 * comment - see docs/roadmap.md Phase 7.5 for the full writeup.
 *
 * What's ported below (real Apple algorithms, not reinvented):
 *   - workq_create_threadstack/workq_destroy_threadstack: real
 *     mach_vm_map/mach_vm_allocate + mach_vm_protect guard-page setup,
 *     from kern_support.c's real workq_create_threadstack (added a guard
 *     page below a real stack region in the target process's own vm_map).
 *   - workq_markfree_threadstack: real mach_vm_behavior_set(...,
 *     VM_BEHAVIOR_REUSABLE) hint for an idle worker thread's stack.
 *   - workq_setup_thread: real thread-register-state setup (arm64:
 *     x0=self, x1=kport, x2=stack_bottom, x3=kevent_list,
 *     x4=upcall_flags, x5=kevent_count, pc=the real wqthread entry point
 *     registered via bsdthread_register, sp=stack top) followed by a
 *     real, noreturn jump back to userspace via
 *     pthread_kern->thread_bootstrap_return()/unix_syscall_return() -
 *     the exact real mechanism, not a stand-in. NOTE (load-bearing):
 *     this function panics ("workqueue thread start function pointer is
 *     NULL") if proc_get_wqthread(p) was never set - i.e. it is only
 *     safe to reach after a real bsdthread_register call has run for
 *     the calling process. That's why real_bsdthread_register below is
 *     part of this same port, not a separate/future step.
 *   - workq_handle_stack_events: real kevent-list marshalling via the
 *     already-real pthread_kern->kevent_workq_internal callback (real
 *     bsd/kern/kern_event.c kqueue plumbing, already built into this
 *     kernel - see bsd/sys/event.h's real kevent_workq_internal()).
 *   - real_bsdthread_register (ported from kern_support.c's
 *     `_bsdthread_register`, renamed to match this project's
 *     `real_bsdthread_create` naming convention): real per-process
 *     pthread registration (records threadstart/wqthread/pthsize/
 *     tsd offsets via the already-real pthread_kern proc_set_* callback
 *     family). Wired to the OLDER (`.bsdthread_register`, not
 *     `.bsdthread_register2`) vtable slot deliberately - confirmed by
 *     reading third_party/libpthread/kern/kern_init.c's own
 *     `pthread_internal_functions` initializer, which leaves `.version`
 *     unset (defaults to 0, since kern_init.c never sets it and C static
 *     init zero-fills). bsd/pthread/pthread_shims.c's real
 *     bsdthread_register() syscall wrapper branches on
 *     `pthread_functions->version >= 1` to decide which slot to call -
 *     version 0 means the OLD slot, whose real signature (verified by
 *     reading both sides: bsd/sys/pthread_shims.h's
 *     `(p, threadstart, wqthread, int pthsize, user_addr_t dummy_value,
 *     user_addr_t targetconc_ptr, uint64_t dispatchqueue_offset,
 *     int32_t *retval)` vs. kern_support.c's real
 *     `_bsdthread_register(p, threadstart, wqthread, int pthsize,
 *     user_addr_t pthread_init_data, user_addr_t pthread_init_data_size,
 *     uint64_t dispatchqueue_offset, int32_t *retval)`) match exactly
 *     type-for-type - the "dummy_value"/"targetconc_ptr" xnu-side names
 *     are just stale pre-blob-era names for the same two slots
 *     kern_support.c calls pthread_init_data/pthread_init_data_size.
 *     This is real, evidence-backed (not guessed) - see the exact grep
 *     trail in docs/roadmap.md's Phase 7.5 entry. Consequence:
 *     bsd_pthread_stub.c's `.version` field must be 0, not
 *     PTHREAD_FUNCTIONS_TABLE_VERSION (1), to match this real pairing -
 *     changed there, not here.
 *
 * NOT ported (out of scope, real and substantial subsystems of their
 * own, still ENOTSUP stubs in bsd_pthread_stub.c): bsdthread_register2
 * (the newer TSD-offset-aware SPI - unreachable now that `.version` is
 * correctly 0, see above), psynch_* (userspace mutex/cv/rwlock kernel
 * slow path), bsdthread_terminate, thread_selfid, bsdthread_ctl (QoS
 * override machinery - a separate real subsystem pthread_workqueue.c
 * also implements policy for for but wasn't in this task's scope).
 *
 * Trimmed from a full drop-in of kern_support.c (which also has
 * bsdthread_create / psynch_* / ctl_* bodies this project's
 * bsd_pthread_stub.c already handles separately, and would collide with
 * on symbol names if compiled together): only the six functions above,
 * their small static helpers, and the few struct/macro definitions
 * kern/kern_internal.h would otherwise supply (copied verbatim below,
 * cited by source line) are included here.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/pthread_shims.h>
#include <sys/proc_internal.h>
#include <sys/event.h>
#include <pthread/workqueue_syscalls.h>
#include <pthread/priority_private.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <mach/arm/thread_status.h>
#include <mach/kern_return.h>
#include <mach/thread_act.h>
#include <mach/shared_region.h>
#include <mach/vm_behavior.h>
#include <mach/vm_statistics.h>
#include <vm/vm_map.h>
#include <vm/vm_fault.h>

/*
 * mach_vm_map_external/mach_vm_allocate_external/mach_vm_deallocate/
 * mach_vm_protect/mach_vm_behavior_set: real kernel-internal VM entry
 * points (osfmk/vm/vm_user.c) - none of them are declared in any header
 * on bsd/kern/'s own include path (confirmed by grepping the whole tree -
 * every other real kernel caller either lives inside osfmk/ itself, where
 * these happen to already be in scope some other way, or - like
 * osfmk/ipc/mach_kernelrpc.c - includes the MIG-generated
 * <mach/mach_vm_server.h>, which isn't reachable from a bsd/ translation
 * unit either). Real signatures copied verbatim from their real
 * definitions (osfmk/vm/vm_user.c) rather than pulling in the generated
 * MIG header.
 */
extern kern_return_t mach_vm_map_external(vm_map_t target_map,
    mach_vm_offset_t *address, mach_vm_size_t initial_size, mach_vm_offset_t mask,
    int flags, ipc_port_t port, vm_object_offset_t offset, boolean_t copy,
    vm_prot_t cur_protection, vm_prot_t max_protection, vm_inherit_t inheritance);
extern kern_return_t mach_vm_allocate_external(vm_map_t map,
    mach_vm_offset_t *addr, mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(vm_map_t map, mach_vm_offset_t start,
    mach_vm_size_t size);
extern kern_return_t mach_vm_protect(vm_map_t map, mach_vm_offset_t start,
    mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
extern kern_return_t mach_vm_behavior_set(vm_map_t map, mach_vm_offset_t start,
    mach_vm_size_t size, vm_behavior_t new_behavior);

/* real macro from kern_support.c's own header chain (libpthread-454.80.2) */
#define PTH_DEFAULT_STACKSIZE 512*1024

/* magical `nkevents` value for _pthread_wqthread - real value from
 * third_party/libpthread/kern/kern_internal.h line 208. */
#define WORKQ_EXIT_THREAD_NKEVENT   (-1)

/* mach/vm_statistics.h guards VM_MAKE_TAG behind `#if !XNU_KERNEL_PRIVATE`
 * (this bsd/kern/ translation unit IS built with XNU_KERNEL_PRIVATE set,
 * unlike third_party/libpthread's own kext-shaped build) - same real
 * value, just re-declared for this build configuration. */
#ifndef VM_MAKE_TAG
#define VM_MAKE_TAG(tag) ((tag) << 24)
#endif

/*
 * Real struct definitions from third_party/libpthread/kern/kern_internal.h
 * (lines 66-92 as of libpthread-454.80.2) - copied verbatim, this project
 * has no kext-loading boundary so there's no shared private header both
 * sides would normally include from the same SDK snapshot.
 */
struct _pthread_registration_data {
	uint64_t version;
	uint64_t dispatch_queue_offset;
	uint64_t /* pthread_priority_t */ main_qos;
	uint32_t tsd_offset;
	uint32_t return_to_kernel_offset;
	uint32_t mach_thread_self_offset;
	mach_vm_address_t stack_addr_hint;
#define _PTHREAD_REG_DEFAULT_POLICY_MASK 0xff
#define _PTHREAD_REG_DEFAULT_USE_ULOCK 0x100
#define _PTHREAD_REG_DEFAULT_USE_ADAPTIVE_SPIN 0x200
	uint32_t mutex_default_policy;
	uint32_t joinable_offset_bits;
};

/* real macros from kern_support.c (libpthread-454.80.2) lines 120-133 */
#define C_WORKQ_STK_ALIGN       16
#if defined(__arm64__)
#define PTHREAD_T_OFFSET (12*1024)
#else
#define PTHREAD_T_OFFSET 0
#endif

#define MAX_PTHREAD_SIZE 64*1024

/* PTHREAD_FEATURE_* / PTHREAD_FEATURE_SUPPORTED: real values copied
 * verbatim from third_party/libpthread/kern/kern_internal.h lines 55-108
 * (libpthread-454.80.2) - this project has no shared private header both
 * sides would normally include from the same SDK snapshot. */
#define PTHREAD_FEATURE_DISPATCHFUNC   0x01
#define PTHREAD_FEATURE_FINEPRIO       0x02
#define PTHREAD_FEATURE_BSDTHREADCTL   0x04
#define PTHREAD_FEATURE_SETSELF        0x08
#define PTHREAD_FEATURE_QOS_MAINTENANCE 0x10
#define PTHREAD_FEATURE_KEVENT         0x40
#define PTHREAD_FEATURE_WORKLOOP       0x80
#define PTHREAD_FEATURE_QOS_DEFAULT    0x40000000
#define PTHREAD_FEATURE_SUPPORTED \
	(PTHREAD_FEATURE_DISPATCHFUNC | PTHREAD_FEATURE_FINEPRIO | \
	 PTHREAD_FEATURE_BSDTHREADCTL | PTHREAD_FEATURE_SETSELF | \
	 PTHREAD_FEATURE_QOS_MAINTENANCE | PTHREAD_FEATURE_QOS_DEFAULT | \
	 PTHREAD_FEATURE_KEVENT | PTHREAD_FEATURE_WORKLOOP)

#pragma mark - Workqueue Thread Support (verbatim from kern_support.c)

static mach_vm_offset_t
stack_addr_hint(proc_t p, vm_map_t vmap)
{
	mach_vm_offset_t stackaddr;
	mach_vm_offset_t aslr_offset;
	bool proc64bit = proc_is64bit(p);
	bool proc64bit_data = proc_is64bit_data(p);

	_Static_assert(powerof2(PTH_DEFAULT_STACKSIZE), "PTH_DEFAULT_STACKSIZE is a power-of-two");

	(void)proc64bit_data;
	user_addr_t main_thread_stack_top = 0;
	if (pthread_kern->proc_get_user_stack) {
		main_thread_stack_top = pthread_kern->proc_get_user_stack(p);
	}
	if (proc64bit && main_thread_stack_top) {
		stackaddr = vm_map_trunc_page_mask((vm_map_offset_t)main_thread_stack_top,
				vm_map_page_mask(vmap));
	} else {
		aslr_offset = random() % ((proc64bit ? 4 : 2) * PTH_DEFAULT_STACKSIZE);
		aslr_offset = vm_map_trunc_page_mask((vm_map_offset_t)aslr_offset,
				vm_map_page_mask(vmap));
		if (proc64bit) {
			stackaddr = SHARED_REGION_BASE_ARM64 - 64 * PTH_DEFAULT_STACKSIZE - aslr_offset;
		} else {
			if (proc64bit_data) {
				stackaddr = SHARED_REGION_BASE_ARM64_32;
			} else {
				stackaddr = SHARED_REGION_BASE_ARM;
			}
			stackaddr -= 32 * PTH_DEFAULT_STACKSIZE + aslr_offset;
		}
	}
	return stackaddr;
}

static mach_vm_size_t
workq_thread_allocsize(proc_t p, vm_map_t wq_map,
		mach_vm_size_t *guardsize_out)
{
	mach_vm_size_t guardsize = vm_map_page_size(wq_map);
	mach_vm_size_t pthread_size = vm_map_round_page_mask(
			pthread_kern->proc_get_pthsize(p) + PTHREAD_T_OFFSET,
			vm_map_page_mask(wq_map));
	if (guardsize_out) *guardsize_out = guardsize;
	return guardsize + PTH_DEFAULT_STACKSIZE + pthread_size;
}

int
workq_create_threadstack(proc_t p, vm_map_t vmap, mach_vm_offset_t *out_addr)
{
	mach_vm_offset_t stackaddr = pthread_kern->proc_get_stack_addr_hint(p);
	mach_vm_size_t guardsize, th_allocsize;
	kern_return_t kret;

	th_allocsize = workq_thread_allocsize(p, vmap, &guardsize);
	kret = mach_vm_map_external(vmap, &stackaddr, th_allocsize, page_size - 1,
			VM_MAKE_TAG(VM_MEMORY_STACK) | VM_FLAGS_ANYWHERE, NULL, 0, FALSE,
			VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);

	if (kret != KERN_SUCCESS) {
		kret = mach_vm_allocate_external(vmap, &stackaddr, th_allocsize,
				VM_MAKE_TAG(VM_MEMORY_STACK) | VM_FLAGS_ANYWHERE);
	}

	if (kret != KERN_SUCCESS) {
		goto fail;
	}

	/*
	 * The guard page is at the lowest address
	 * The stack base is the highest address
	 */
	kret = mach_vm_protect(vmap, stackaddr, guardsize, FALSE, VM_PROT_NONE);
	if (kret != KERN_SUCCESS) {
		goto fail_vm_deallocate;
	}

	if (out_addr) {
		*out_addr = stackaddr;
	}
	return 0;

fail_vm_deallocate:
	(void)mach_vm_deallocate(vmap, stackaddr, th_allocsize);
fail:
	return kret;
}

int
workq_destroy_threadstack(proc_t p, vm_map_t vmap, mach_vm_offset_t stackaddr)
{
	return mach_vm_deallocate(vmap, stackaddr,
			workq_thread_allocsize(p, vmap, NULL));
}

void
workq_markfree_threadstack(proc_t OS_UNUSED p, thread_t OS_UNUSED th,
		vm_map_t vmap, user_addr_t stackaddr)
{
	/* Keep this in sync with workq_setup_thread() */
	const vm_size_t       guardsize = vm_map_page_size(vmap);
	const user_addr_t     freeaddr = (user_addr_t)stackaddr + guardsize;
	const vm_map_offset_t freesize = vm_map_trunc_page_mask(
			(PTH_DEFAULT_STACKSIZE + guardsize + PTHREAD_T_OFFSET) - 1,
			vm_map_page_mask(vmap)) - guardsize;

	__assert_only kern_return_t kr = mach_vm_behavior_set(vmap, freeaddr,
			freesize, VM_BEHAVIOR_REUSABLE);
#if MACH_ASSERT
	if (kr != KERN_SUCCESS && kr != KERN_INVALID_ADDRESS) {
		printf("bsd_pthread_workq: unable to make thread stack reusable (kr: %d)\n", kr);
	}
#endif
}

struct workq_thread_addrs {
	user_addr_t self;
	user_addr_t stack_bottom;
	user_addr_t stack_top;
};

static inline void
workq_thread_set_top_addr(struct workq_thread_addrs *th_addrs, user_addr_t addr)
{
	th_addrs->stack_top = (addr & -C_WORKQ_STK_ALIGN);
}

static void
workq_thread_get_addrs(vm_map_t map, user_addr_t stackaddr,
					   struct workq_thread_addrs *th_addrs)
{
	const vm_size_t guardsize = vm_map_page_size(map);

	th_addrs->self = (user_addr_t)(stackaddr + PTH_DEFAULT_STACKSIZE +
			guardsize + PTHREAD_T_OFFSET);
	workq_thread_set_top_addr(th_addrs, th_addrs->self);
	th_addrs->stack_bottom = (user_addr_t)(stackaddr + guardsize);
}

static inline void
workq_set_register_state(proc_t p, thread_t th,
		struct workq_thread_addrs *addrs, mach_port_name_t kport,
		user_addr_t kevent_list, uint32_t upcall_flags, int kevent_count)
{
	user_addr_t wqstart_fnptr = pthread_kern->proc_get_wqthread(p);
	if (!wqstart_fnptr) {
		panic("workqueue thread start function pointer is NULL");
	}

	arm_thread_state64_t state = {
		.pc = (uint64_t)wqstart_fnptr,
		.x[0] = (uint64_t)addrs->self,
		.x[1] = (uint64_t)kport,
		.x[2] = (uint64_t)addrs->stack_bottom,
		.x[3] = (uint64_t)kevent_list,
		.x[4] = (uint64_t)upcall_flags,
		.x[5] = (uint64_t)kevent_count,

		.sp = (uint64_t)((vm_offset_t)addrs->stack_top),
	};

	int error = pthread_kern->thread_set_wq_state64(th, (thread_state_t)&state);
	if (error != KERN_SUCCESS) {
		panic("workq_set_register_state: thread_set_wq_state failed: %d", error);
	}
}

static inline int
workq_kevent(proc_t p, struct workq_thread_addrs *th_addrs,
		user_addr_t eventlist, int nevents, int kevent_flags,
		user_addr_t *kevent_list_out, int *kevent_count_out)
{
	int ret;

	user_addr_t kevent_list = th_addrs->self -
			WQ_KEVENT_LIST_LEN * sizeof(struct kevent_qos_s);
	user_addr_t data_buf = kevent_list - WQ_KEVENT_DATA_SIZE;
	user_size_t data_available = WQ_KEVENT_DATA_SIZE;

	ret = pthread_kern->kevent_workq_internal(p, eventlist, nevents,
			kevent_list, WQ_KEVENT_LIST_LEN,
			data_buf, &data_available,
			kevent_flags, kevent_count_out);

	if (ret != 0 || *kevent_count_out == -1) {
		*kevent_list_out = 0;
		*kevent_count_out = 0;
		return ret;
	}

	workq_thread_set_top_addr(th_addrs, data_buf + data_available);
	*kevent_list_out = kevent_list;
	return ret;
}

__attribute__((noreturn,noinline))
void
workq_setup_thread(proc_t p, thread_t th, vm_map_t map, user_addr_t stackaddr,
		mach_port_name_t kport, int th_qos __unused, int setup_flags, int upcall_flags)
{
	struct workq_thread_addrs th_addrs;
	bool first_use = (setup_flags & WQ_SETUP_FIRST_USE);
	user_addr_t kevent_list = 0;
	int kevent_count = 0;

	workq_thread_get_addrs(map, stackaddr, &th_addrs);

	if (first_use) {
		uint32_t tsd_offset = pthread_kern->proc_get_pthread_tsd_offset(p);
		if (tsd_offset) {
			mach_vm_offset_t th_tsd_base = th_addrs.self + tsd_offset;
			kern_return_t kret = pthread_kern->thread_set_tsd_base(th,
					th_tsd_base);
			if (kret == KERN_SUCCESS) {
				upcall_flags |= WQ_FLAG_THREAD_TSD_BASE_SET;
			}
		}

		/*
		 * Pre-fault the first page of the new thread's stack and the page
		 * that will contain the pthread_t structure.
		 */
		vm_map_offset_t mask = vm_map_page_mask(map);
		vm_map_offset_t th_page = vm_map_trunc_page_mask(th_addrs.self, mask);
		vm_map_offset_t stk_page = vm_map_trunc_page_mask(th_addrs.stack_top - 1, mask);
		/*
		 * vm_fault()'s real signature grows a `vm_tag_t wire_tag` 5th
		 * argument when XNU_KERNEL_PRIVATE is set (see osfmk/vm/vm_fault.h)
		 * - true for this bsd/kern/ translation unit, unlike
		 * third_party/libpthread's own kext-shaped build (which sees the
		 * 7-arg non-private overload) - VM_KERN_MEMORY_NONE is the same
		 * "no specific tag" sentinel this project's own kern_exec.c
		 * already uses for an analogous real vm_fault-adjacent call.
		 */
		if (th_page != stk_page) {
			vm_fault(map, stk_page, VM_PROT_READ | VM_PROT_WRITE, FALSE, VM_KERN_MEMORY_NONE, THREAD_UNINT, NULL, 0);
		}
		vm_fault(map, th_page, VM_PROT_READ | VM_PROT_WRITE, FALSE, VM_KERN_MEMORY_NONE, THREAD_UNINT, NULL, 0);
	}

	if (setup_flags & WQ_SETUP_EXIT_THREAD) {
		kevent_count = WORKQ_EXIT_THREAD_NKEVENT;
	} else if (upcall_flags & WQ_FLAG_THREAD_KEVENT) {
		unsigned int flags = KEVENT_FLAG_STACK_DATA | KEVENT_FLAG_IMMEDIATE;
		workq_kevent(p, &th_addrs, 0, 0, flags, &kevent_list, &kevent_count);
	}

	workq_set_register_state(p, th, &th_addrs, kport,
			kevent_list, upcall_flags, kevent_count);

	if (first_use) {
		pthread_kern->thread_bootstrap_return();
	} else {
		pthread_kern->unix_syscall_return(EJUSTRETURN);
	}
	__builtin_unreachable();
}

int
workq_handle_stack_events(proc_t p, thread_t th, vm_map_t map,
		user_addr_t stackaddr, mach_port_name_t kport,
		user_addr_t events, int nevents, int upcall_flags)
{
	struct workq_thread_addrs th_addrs;
	user_addr_t kevent_list = 0;
	int kevent_count = 0, error;
	__assert_only kern_return_t kr;

	workq_thread_get_addrs(map, stackaddr, &th_addrs);

	unsigned int flags = KEVENT_FLAG_STACK_DATA | KEVENT_FLAG_IMMEDIATE |
			KEVENT_FLAG_PARKING;
	error = workq_kevent(p, &th_addrs, events, nevents, flags,
			&kevent_list, &kevent_count);

	if (error || kevent_count == 0) {
		return error;
	}

	kr = pthread_kern->thread_set_voucher_name(MACH_PORT_NULL);
	assert(kr == KERN_SUCCESS);

	workq_set_register_state(p, th, &th_addrs, kport,
			kevent_list, upcall_flags, kevent_count);

	pthread_kern->unix_syscall_return(EJUSTRETURN);
	__builtin_unreachable();
}

#pragma mark - bsdthread_register (verbatim algorithm from kern_support.c's _bsdthread_register)

/*
 * real_bsdthread_register() - wired to the OLDER `.bsdthread_register`
 * vtable slot (not `.bsdthread_register2`) - see this file's header
 * comment for why that's the real, correct pairing for this project's
 * exact xnu-7195 + libpthread-454.80.2 combination.
 */
int
real_bsdthread_register(struct proc *p,
		    user_addr_t threadstart,
		    user_addr_t wqthread,
		    int pthsize,
		    user_addr_t pthread_init_data,
		    user_addr_t pthread_init_data_size,
		    uint64_t dispatchqueue_offset,
		    int32_t *retval)
{
	struct _pthread_registration_data data = {};
	uint32_t max_tsd_offset;
	kern_return_t kr;
	size_t pthread_init_sz = 0;

	/* syscall randomizer test can pass bogus values */
	if (pthsize < 0 || pthsize > MAX_PTHREAD_SIZE) {
		return(EINVAL);
	}
	/*
	 * if we have pthread_init_data, then we use that and target_concptr
	 * (which is an offset) get data.
	 */
	if (pthread_init_data != 0) {
		if (pthread_init_data_size < sizeof(data.version)) {
			return EINVAL;
		}
		pthread_init_sz = MIN(sizeof(data), (size_t)pthread_init_data_size);
		int ret = copyin(pthread_init_data, &data, pthread_init_sz);
		if (ret) {
			return ret;
		}
		if (data.version != (size_t)pthread_init_data_size) {
			return EINVAL;
		}
	} else {
		data.dispatch_queue_offset = dispatchqueue_offset;
	}

	/* We have to do this before proc_get_register so that it resets after fork */
	mach_vm_offset_t stackaddr = stack_addr_hint(p, pthread_kern->current_map());
	pthread_kern->proc_set_stack_addr_hint(p, (user_addr_t)stackaddr);

	/* prevent multiple registrations */
	if (pthread_kern->proc_get_register(p) != 0) {
		return(EINVAL);
	}

	pthread_kern->proc_set_threadstart(p, threadstart);
	pthread_kern->proc_set_wqthread(p, wqthread);
	pthread_kern->proc_set_pthsize(p, pthsize);
	pthread_kern->proc_set_register(p);

	uint32_t tsd_slot_sz = proc_is64bit(p) ? sizeof(uint64_t) : sizeof(uint32_t);
	if ((uint32_t)pthsize >= tsd_slot_sz &&
			data.tsd_offset <= (uint32_t)(pthsize - tsd_slot_sz)) {
		max_tsd_offset = ((uint32_t)pthsize - data.tsd_offset - tsd_slot_sz);
	} else {
		data.tsd_offset = 0;
		max_tsd_offset = 0;
	}
	pthread_kern->proc_set_pthread_tsd_offset(p, data.tsd_offset);

	if (data.dispatch_queue_offset > max_tsd_offset) {
		data.dispatch_queue_offset = 0;
	}
	pthread_kern->proc_set_dispatchqueue_offset(p, data.dispatch_queue_offset);

	if (pthread_kern->proc_set_return_to_kernel_offset) {
		if (data.return_to_kernel_offset > max_tsd_offset) {
			data.return_to_kernel_offset = 0;
		}
		pthread_kern->proc_set_return_to_kernel_offset(p,
				data.return_to_kernel_offset);
	}

	if (pthread_kern->proc_set_mach_thread_self_tsd_offset) {
		if (data.mach_thread_self_offset > max_tsd_offset) {
			data.mach_thread_self_offset = 0;
		}
		pthread_kern->proc_set_mach_thread_self_tsd_offset(p,
				data.mach_thread_self_offset);
	}

	if (pthread_init_data != 0) {
		/* Outgoing data that userspace expects as a reply */
		data.version = sizeof(struct _pthread_registration_data);
		data.main_qos = _pthread_unspecified_priority();

		if (pthread_kern->qos_main_thread_active()) {
			mach_msg_type_number_t nqos = THREAD_QOS_POLICY_COUNT;
			thread_qos_policy_data_t qos;
			boolean_t gd = FALSE;

			kr = pthread_kern->thread_policy_get(current_thread(),
					THREAD_QOS_POLICY, (thread_policy_t)&qos, &nqos, &gd);
			if (kr != KERN_SUCCESS || qos.qos_tier == THREAD_QOS_UNSPECIFIED) {
				/*
				 * Unspecified threads means the kernel wants us
				 * to impose legacy upon the thread.
				 */
				qos.qos_tier = THREAD_QOS_LEGACY;
				qos.tier_importance = 0;

				kr = pthread_kern->thread_policy_set_internal(current_thread(),
						THREAD_QOS_POLICY, (thread_policy_t)&qos,
						THREAD_QOS_POLICY_COUNT);
			}

			if (kr == KERN_SUCCESS) {
				data.main_qos = _pthread_priority_make_from_thread_qos(
						qos.qos_tier, 0, 0);
			}
		}

		data.stack_addr_hint = stackaddr;
		data.mutex_default_policy = 0;

		kr = copyout(&data, pthread_init_data, pthread_init_sz);
		if (kr != KERN_SUCCESS) {
			return EINVAL;
		}
	}

	/* return the supported feature set as the return value. */
	*retval = PTHREAD_FEATURE_SUPPORTED;

	return(0);
}
