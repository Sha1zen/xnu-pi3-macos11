/*
 * Copyright (c) 2000-2020 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/message.h>
#include <mach/port.h>
#include <mach/mig_errors.h>
#include <mach/task.h>
#include <mach/thread_status.h>
#include <mach/exception_types.h>
#include <mach/exc.h>
#include <mach/mach_exc.h>

#include <ipc/port.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_machdep.h>

#include <kern/counters.h>
#include <kern/ipc_tt.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/host.h>
#include <kern/misc_protos.h>
#include <kern/ux_handler.h>

#include <vm/vm_map.h>

#include <security/mac_mach_internal.h>
#include <string.h>

#include <pexpert/pexpert.h>

bool panic_on_exception_triage = false;

/*
 * -user_fault_debug: print a one-shot report (exception type/codes, PC,
 * LR, SP, FAR, ESR, the vm_map regions containing PC and FAR, the
 * argument registers, and an fp-chain backtrace) for each of the first
 * 64 userland exceptions in the boot. Off by default. See the comment
 * at the use site in exception_triage() for why this exists.
 */
bool user_fault_debug = false;

unsigned long c_thr_exc_raise = 0;
unsigned long c_thr_exc_raise_state = 0;
unsigned long c_thr_exc_raise_state_id = 0;
unsigned long c_tsk_exc_raise = 0;
unsigned long c_tsk_exc_raise_state = 0;
unsigned long c_tsk_exc_raise_state_id = 0;

/* forward declarations */
kern_return_t exception_deliver(
	thread_t                thread,
	exception_type_t        exception,
	mach_exception_data_t   code,
	mach_msg_type_number_t  codeCnt,
	struct exception_action *excp,
	lck_mtx_t                       *mutex);

static kern_return_t
check_exc_receiver_dependency(
	exception_type_t exception,
	struct exception_action *excp,
	lck_mtx_t *mutex);

#ifdef MACH_BSD
kern_return_t bsd_exception(
	exception_type_t        exception,
	mach_exception_data_t   code,
	mach_msg_type_number_t  codeCnt);
#endif /* MACH_BSD */

#if __has_feature(ptrauth_calls)
extern int exit_with_pac_exception(
	void *proc,
	exception_type_t         exception,
	mach_exception_code_t    code,
	mach_exception_subcode_t subcode);

extern bool proc_is_traced(void *p);
#endif /* __has_feature(ptrauth_calls) */

/*
 * Routine: exception_init
 * Purpose:
 *   Global initialization of state for exceptions.
 * Conditions:
 *   None.
 */
void
exception_init(void)
{
	int tmp = 0;

	if (PE_parse_boot_argn("-panic_on_exception_triage", &tmp, sizeof(tmp))) {
		panic_on_exception_triage = true;
	}

	if (PE_parse_boot_argn("-user_fault_debug", &tmp, sizeof(tmp))) {
		user_fault_debug = true;
		/*
		 * Announce it. Without this the facility is unfalsifiable from a
		 * boot log: a run that reports nothing looks identical whether
		 * the flag never reached the kernel or no userland exception
		 * happened to occur -- exactly the "absence of output proves
		 * nothing" trap this project has been burned by before.
		 */
		printf("user_fault_debug: enabled, will report the first 64 "
		    "userland exceptions\n");
	}
}

/*
 *	Routine:	exception_deliver
 *	Purpose:
 *		Make an upcall to the exception server provided.
 *	Conditions:
 *		Nothing locked and no resources held.
 *		Called from an exception context, so
 *		thread_exception_return and thread_kdb_return
 *		are possible.
 *	Returns:
 *		KERN_SUCCESS if the exception was handled
 */
kern_return_t
exception_deliver(
	thread_t                thread,
	exception_type_t        exception,
	mach_exception_data_t   code,
	mach_msg_type_number_t  codeCnt,
	struct exception_action *excp,
	lck_mtx_t                       *mutex)
{
	ipc_port_t              exc_port = IPC_PORT_NULL;
	exception_data_type_t   small_code[EXCEPTION_CODE_MAX];
	int                     code64;
	int                     behavior;
	int                     flavor;
	kern_return_t           kr;
	task_t task;
	ipc_port_t thread_port = IPC_PORT_NULL, task_port = IPC_PORT_NULL;

	/*
	 *  Save work if we are terminating.
	 *  Just go back to our AST handler.
	 */
	if (!thread->active && !thread->inspection) {
		return KERN_SUCCESS;
	}

	/*
	 * If there are no exception actions defined for this entity,
	 * we can't deliver here.
	 */
	if (excp == NULL) {
		return KERN_FAILURE;
	}

	assert(exception < EXC_TYPES_COUNT);
	if (exception >= EXC_TYPES_COUNT) {
		return KERN_FAILURE;
	}

	excp = &excp[exception];

	/*
	 * Snapshot the exception action data under lock for consistency.
	 * Hold a reference to the port over the exception_raise_* calls
	 * so it can't be destroyed.  This seems like overkill, but keeps
	 * the port from disappearing between now and when
	 * ipc_object_copyin_from_kernel is finally called.
	 */
	lck_mtx_lock(mutex);
	exc_port = excp->port;
	if (!IP_VALID(exc_port)) {
		lck_mtx_unlock(mutex);
		return KERN_FAILURE;
	}
	ip_lock(exc_port);
	if (!ip_active(exc_port)) {
		ip_unlock(exc_port);
		lck_mtx_unlock(mutex);
		return KERN_FAILURE;
	}
	ip_reference(exc_port);
	exc_port->ip_srights++;
	ip_unlock(exc_port);

	flavor = excp->flavor;
	behavior = excp->behavior;
	lck_mtx_unlock(mutex);

	code64 = (behavior & MACH_EXCEPTION_CODES);
	behavior &= ~MACH_EXCEPTION_MASK;

	if (!code64) {
		small_code[0] = CAST_DOWN_EXPLICIT(exception_data_type_t, code[0]);
		small_code[1] = CAST_DOWN_EXPLICIT(exception_data_type_t, code[1]);
	}

	task = thread->task;

#if CONFIG_MACF
	/* Now is a reasonably good time to check if the exception action is
	 * permitted for this process, because after this point we will send
	 * the message out almost certainly.
	 * As with other failures, exception_triage_thread will go on
	 * to the next level.
	 */

	/* The global exception-to-signal translation port is safe to be an exception handler. */
	if (is_ux_handler_port(exc_port) == FALSE &&
	    mac_exc_action_check_exception_send(task, excp) != 0) {
		kr = KERN_FAILURE;
		goto out_release_right;
	}
#endif

	if (behavior != EXCEPTION_STATE) {
		task_reference(task);
		task_port = convert_task_to_port(task);
		/* task ref consumed */
		thread_reference(thread);
		thread_port = convert_thread_to_port(thread);
		/* thread ref consumed */
	}

	switch (behavior) {
	case EXCEPTION_STATE: {
		mach_msg_type_number_t state_cnt;
		thread_state_data_t state;

		c_thr_exc_raise_state++;
		state_cnt = _MachineStateCount[flavor];
		kr = thread_getstatus_to_user(thread, flavor,
		    (thread_state_t)state,
		    &state_cnt);
		if (kr == KERN_SUCCESS) {
			if (code64) {
				kr = mach_exception_raise_state(exc_port,
				    exception,
				    code,
				    codeCnt,
				    &flavor,
				    state, state_cnt,
				    state, &state_cnt);
			} else {
				kr = exception_raise_state(exc_port, exception,
				    small_code,
				    codeCnt,
				    &flavor,
				    state, state_cnt,
				    state, &state_cnt);
			}
			if (kr == KERN_SUCCESS) {
				if (exception != EXC_CORPSE_NOTIFY) {
					kr = thread_setstatus_from_user(thread, flavor,
					    (thread_state_t)state,
					    state_cnt);
				}
				goto out_release_right;
			}
		}

		goto out_release_right;
	}

	case EXCEPTION_DEFAULT:
		c_thr_exc_raise++;
		if (code64) {
			kr = mach_exception_raise(exc_port,
			    thread_port,
			    task_port,
			    exception,
			    code,
			    codeCnt);
		} else {
			kr = exception_raise(exc_port,
			    thread_port,
			    task_port,
			    exception,
			    small_code,
			    codeCnt);
		}

		goto out_release_right;

	case EXCEPTION_STATE_IDENTITY: {
		mach_msg_type_number_t state_cnt;
		thread_state_data_t state;

		c_thr_exc_raise_state_id++;
		state_cnt = _MachineStateCount[flavor];
		kr = thread_getstatus_to_user(thread, flavor,
		    (thread_state_t)state,
		    &state_cnt);
		if (kr == KERN_SUCCESS) {
			if (code64) {
				kr = mach_exception_raise_state_identity(
					exc_port,
					thread_port,
					task_port,
					exception,
					code,
					codeCnt,
					&flavor,
					state, state_cnt,
					state, &state_cnt);
			} else {
				kr = exception_raise_state_identity(exc_port,
				    thread_port,
				    task_port,
				    exception,
				    small_code,
				    codeCnt,
				    &flavor,
				    state, state_cnt,
				    state, &state_cnt);
			}

			if (kr == KERN_SUCCESS) {
				if (exception != EXC_CORPSE_NOTIFY) {
					kr = thread_setstatus_from_user(thread, flavor,
					    (thread_state_t)state,
					    state_cnt);
				}
				goto out_release_right;
			}
		}

		goto out_release_right;
	}

	default:
		panic("bad exception behavior!");
		return KERN_FAILURE;
	}/* switch */

out_release_right:

	if (task_port) {
		ipc_port_release_send(task_port);
	}

	if (thread_port) {
		ipc_port_release_send(thread_port);
	}

	if (exc_port) {
		ipc_port_release_send(exc_port);
	}

	return kr;
}

/*
 * Routine: check_exc_receiver_dependency
 * Purpose:
 *      Verify that the port destined for receiving this exception is not
 *      on the current task. This would cause hang in kernel for
 *      EXC_CRASH primarily. Note: If port is transferred
 *      between check and delivery then deadlock may happen.
 *
 * Conditions:
 *		Nothing locked and no resources held.
 *		Called from an exception context.
 * Returns:
 *      KERN_SUCCESS if its ok to send exception message.
 */
kern_return_t
check_exc_receiver_dependency(
	exception_type_t exception,
	struct exception_action *excp,
	lck_mtx_t *mutex)
{
	kern_return_t retval = KERN_SUCCESS;

	if (excp == NULL || exception != EXC_CRASH) {
		return retval;
	}

	task_t task = current_task();
	lck_mtx_lock(mutex);
	ipc_port_t xport = excp[exception].port;
	if (IP_VALID(xport)
	    && ip_active(xport)
	    && task->itk_space == xport->ip_receiver) {
		retval = KERN_FAILURE;
	}
	lck_mtx_unlock(mutex);
	return retval;
}


/*
 *	Routine:	exception_triage_thread
 *	Purpose:
 *		The thread caught an exception.
 *		We make an up-call to the thread's exception server.
 *	Conditions:
 *		Nothing locked and no resources held.
 *		Called from an exception context, so
 *		thread_exception_return and thread_kdb_return
 *		are possible.
 *	Returns:
 *		KERN_SUCCESS if exception is handled by any of the handlers.
 */
kern_return_t
exception_triage_thread(
	exception_type_t        exception,
	mach_exception_data_t   code,
	mach_msg_type_number_t  codeCnt,
	thread_t                thread)
{
	task_t                  task;
	host_priv_t             host_priv;
	lck_mtx_t               *mutex;
	kern_return_t   kr = KERN_FAILURE;


	assert(exception != EXC_RPC_ALERT);

	/*
	 * If this behavior has been requested by the the kernel
	 * (due to the boot environment), we should panic if we
	 * enter this function.  This is intended as a debugging
	 * aid; it should allow us to debug why we caught an
	 * exception in environments where debugging is especially
	 * difficult.
	 */
	if (panic_on_exception_triage) {
		panic("called exception_triage when it was forbidden by the boot environment");
	}

	/*
	 * Try to raise the exception at the activation level.
	 */
	mutex = &thread->mutex;
	if (KERN_SUCCESS == check_exc_receiver_dependency(exception, thread->exc_actions, mutex)) {
		kr = exception_deliver(thread, exception, code, codeCnt, thread->exc_actions, mutex);
		if (kr == KERN_SUCCESS || kr == MACH_RCV_PORT_DIED) {
			goto out;
		}
	}

	/*
	 * Maybe the task level will handle it.
	 */
	task = thread->task;
	mutex = &task->itk_lock_data;
	if (KERN_SUCCESS == check_exc_receiver_dependency(exception, task->exc_actions, mutex)) {
		kr = exception_deliver(thread, exception, code, codeCnt, task->exc_actions, mutex);
		if (kr == KERN_SUCCESS || kr == MACH_RCV_PORT_DIED) {
			goto out;
		}
	}

	/*
	 * How about at the host level?
	 */
	host_priv = host_priv_self();
	mutex = &host_priv->lock;

	if (KERN_SUCCESS == check_exc_receiver_dependency(exception, host_priv->exc_actions, mutex)) {
		kr = exception_deliver(thread, exception, code, codeCnt, host_priv->exc_actions, mutex);
		if (kr == KERN_SUCCESS || kr == MACH_RCV_PORT_DIED) {
			goto out;
		}
	}

out:
	if ((exception != EXC_CRASH) && (exception != EXC_RESOURCE) &&
	    (exception != EXC_GUARD) && (exception != EXC_CORPSE_NOTIFY)) {
		thread_exception_return();
	}
	return kr;
}

/*
 *	Routine:	exception_triage
 *	Purpose:
 *		The current thread caught an exception.
 *		We make an up-call to the thread's exception server.
 *	Conditions:
 *		Nothing locked and no resources held.
 *		Called from an exception context, so
 *		thread_exception_return and thread_kdb_return
 *		are possible.
 *	Returns:
 *		KERN_SUCCESS if exception is handled by any of the handlers.
 */
int debug4k_panic_on_exception = 0;

#if defined(__arm64__) || defined(__arm__)
/*
 * -user_fault_debug helper: describe the vm_map entry containing a user
 * address. See the use site in exception_triage() below.
 *
 * A raw PC is close to useless in a dynamically linked process -- it has
 * to be resolved against whichever image dyld happened to map it into.
 * The vm_map entry containing the PC starts at that image's own mach
 * header (a Mach-O __TEXT segment is mapped from file offset 0), so
 * vme_start is the image base and `addr - vme_start` is a static file
 * offset that nm/otool can resolve on the host. The same lookup on the
 * fault address says what the process thought it was touching and, on a
 * miss, which mapped region it ran off the end of.
 *
 * Everything is copied out under the map lock and printed by the caller
 * afterwards, never from in here: printf() on this platform goes to a
 * 115200-baud serial console, and holding a task's vm_map lock across
 * that transmission would stall every concurrent mmap/munmap in the
 * faulting process.
 */
struct ufd_region {
	bool     found;         /* addr lies inside a mapped entry */
	bool     have_prev;     /* !found, and there is a real preceding entry */
	uint64_t start;
	uint64_t end;
	uint64_t offset;
	uint64_t next_start;    /* 0 if there is no following entry */
	int      prot;
	int      max_prot;
};

static void
ufd_lookup_region(vm_map_t map, vm_map_offset_t addr, struct ufd_region *r)
{
	vm_map_entry_t e;

	bzero(r, sizeof(*r));
	if (map == VM_MAP_NULL) {
		return;
	}

	vm_map_lock_read(map);
	if (vm_map_lookup_entry(map, addr, &e)) {
		r->found = true;
	} else if (e != vm_map_to_entry(map)) {
		/*
		 * On a miss vm_map_lookup_entry hands back the PRECEDING
		 * entry, which is the useful thing to report (it is the
		 * region the access ran off the end of). It can also hand
		 * back the map header itself when the address is below
		 * everything -- that is not a vm_map_entry and its
		 * protection fields do not exist, so it is skipped rather
		 * than printed as garbage.
		 */
		r->have_prev = true;
	}
	if (r->found || r->have_prev) {
		r->start = (uint64_t)e->vme_start;
		r->end = (uint64_t)e->vme_end;
		r->offset = (uint64_t)VME_OFFSET(e);
		r->prot = e->protection;
		r->max_prot = e->max_protection;
		if (e->vme_next != vm_map_to_entry(map)) {
			r->next_start = (uint64_t)e->vme_next->vme_start;
		}
	}
	vm_map_unlock_read(map);
}
#endif /* __arm64__ || __arm__ */

kern_return_t
exception_triage(
	exception_type_t        exception,
	mach_exception_data_t   code,
	mach_msg_type_number_t  codeCnt)
{
	thread_t thread = current_thread();

	/*
	 * user_fault_debug: opt-in console report of every userland
	 * exception, enabled with the `-user_fault_debug` boot-arg. Off by
	 * default; when off this costs one global load per exception.
	 *
	 * This project has no crash reporter, no ReportCrash, and no
	 * debugger. The only thing a userland crash surfaces on the console
	 * otherwise is task.c's "Failed to send exception
	 * EXC_CORPSE_NOTIFY" line, which by then has already thrown the
	 * original exception away (it re-triages a synthesized EXC_CRASH
	 * with no PC, no fault address and no image name). That bare line
	 * has now cost this project two separate multi-session
	 * investigations -- DAR-217, where the real message only appeared
	 * after running the daemon by hand from the root shell, and DAR-222,
	 * where the crashing thread was not even the thread whose output
	 * the printf-bisection was following. Hence keeping this rather
	 * than deleting it after DAR-222.
	 *
	 * exception_triage() is the single choke point every arm64 user
	 * exception really passes through (14 call sites across
	 * osfmk/arm64/sleh.c and osfmk/arm/trap.c), and it runs before the
	 * corpse path discards the original, so this is the earliest place
	 * that can see the real type/codes/PC/FAR/ESR.
	 *
	 * Deliberately printed from the kernel rather than from userland:
	 * the bug being chased is usually userland state corruption, so any
	 * userland diagnostic channel shares the failure mode it is trying
	 * to observe. Everything here comes from the kernel's own copy of
	 * the user register file, saved by the exception vector before any
	 * suspect userland state is touched. Output is capped so a
	 * crash-looping launchd job cannot bury the console.
	 */
	if (user_fault_debug && thread != THREAD_NULL &&
	    thread->task != kernel_task) {
		static volatile uint32_t ufd_reports = 0;

		if (ufd_reports < 64) {
			ufd_reports++;
#if defined(__arm64__) || defined(__arm__)
			arm_saved_state_t *ufd_ss = find_user_regs(thread);

			if (ufd_ss != NULL) {
				printf("user_fault_debug: pid %d exc %d codes 0x%llx 0x%llx "
				    "pc 0x%llx lr 0x%llx sp 0x%llx far 0x%llx esr 0x%x "
				    "mh 0x%llx\n",
				    task_pid(thread->task), exception,
				    (uint64_t)(codeCnt > 0 ? code[0] : 0),
				    (uint64_t)(codeCnt > 1 ? code[1] : 0),
				    (uint64_t)get_saved_state_pc(ufd_ss),
				    (uint64_t)get_saved_state_lr(ufd_ss),
				    (uint64_t)get_saved_state_sp(ufd_ss),
				    (uint64_t)get_saved_state_far(ufd_ss),
				    get_saved_state_esr(ufd_ss),
				    (uint64_t)thread->task->mach_header_vm_address);

				vm_map_t ufd_map = thread->task->map;
				vm_map_offset_t ufd_pc =
				    (vm_map_offset_t)get_saved_state_pc(ufd_ss);
				vm_map_offset_t ufd_far =
				    (vm_map_offset_t)get_saved_state_far(ufd_ss);
				struct ufd_region ufd_r;

				ufd_lookup_region(ufd_map, ufd_pc, &ufd_r);
				if (ufd_r.found) {
					printf("user_fault_debug:   pc region [0x%llx,0x%llx) "
					    "prot %d/%d off 0x%llx -> pc+0x%llx\n",
					    ufd_r.start, ufd_r.end, ufd_r.prot,
					    ufd_r.max_prot, ufd_r.offset,
					    (uint64_t)ufd_pc - ufd_r.start);
				} else {
					printf("user_fault_debug:   pc 0x%llx unmapped\n",
					    (uint64_t)ufd_pc);
				}

				ufd_lookup_region(ufd_map, ufd_far, &ufd_r);
				if (ufd_r.found) {
					printf("user_fault_debug:   far region [0x%llx,0x%llx) "
					    "prot %d/%d off 0x%llx -> far+0x%llx\n",
					    ufd_r.start, ufd_r.end, ufd_r.prot,
					    ufd_r.max_prot, ufd_r.offset,
					    (uint64_t)ufd_far - ufd_r.start);
				} else if (ufd_r.have_prev) {
					printf("user_fault_debug:   far 0x%llx unmapped; "
					    "prev region [0x%llx,0x%llx) prot %d/%d, "
					    "next starts 0x%llx\n",
					    (uint64_t)ufd_far, ufd_r.start, ufd_r.end,
					    ufd_r.prot, ufd_r.max_prot, ufd_r.next_start);
				} else {
					printf("user_fault_debug:   far 0x%llx unmapped, "
					    "below every mapping\n", (uint64_t)ufd_far);
				}

				/*
				 * Argument registers: for a memcpy/memset-shaped
				 * fault x0/x1/x2 are dst/val/len, which says how
				 * far past the end of the destination the write
				 * was going and where it started.
				 */
				printf("user_fault_debug:   x0 0x%llx x1 0x%llx x2 0x%llx "
				    "x3 0x%llx x4 0x%llx x5 0x%llx fp 0x%llx\n",
				    (uint64_t)get_saved_state_reg(ufd_ss, 0),
				    (uint64_t)get_saved_state_reg(ufd_ss, 1),
				    (uint64_t)get_saved_state_reg(ufd_ss, 2),
				    (uint64_t)get_saved_state_reg(ufd_ss, 3),
				    (uint64_t)get_saved_state_reg(ufd_ss, 4),
				    (uint64_t)get_saved_state_reg(ufd_ss, 5),
				    (uint64_t)get_saved_state_fp(ufd_ss));

				/*
				 * Frame-pointer backtrace. The user register file
				 * only carries one return address (LR); everything
				 * above that lives in the user stack, so it has to
				 * be copied in. Frames are collected first and
				 * resolved to image bases afterwards, so the map
				 * lock is never held across a copyin (which can
				 * itself fault and block).
				 */
				uint64_t ufd_lrs[8];
				unsigned ufd_nlr = 0;
				uint64_t ufd_fp = (uint64_t)get_saved_state_fp(ufd_ss);

				while (ufd_nlr < 8 && ufd_fp != 0 &&
				    (ufd_fp & 0x7) == 0) {
					uint64_t next_fp = 0, frame_lr = 0;

					if (copyin_atomic64((user_addr_t)ufd_fp, &next_fp) != 0) {
						break;
					}
					if (copyin_atomic64((user_addr_t)(ufd_fp + 8), &frame_lr) != 0) {
						break;
					}
					ufd_lrs[ufd_nlr++] = frame_lr;
					if (next_fp <= ufd_fp) {
						break;
					}
					ufd_fp = next_fp;
				}

				for (unsigned i = 0; i < ufd_nlr; i++) {
					ufd_lookup_region(ufd_map,
					    (vm_map_offset_t)ufd_lrs[i], &ufd_r);
					if (ufd_r.found && (ufd_r.prot & VM_PROT_EXECUTE)) {
						printf("user_fault_debug:   bt[%u] 0x%llx = "
						    "image 0x%llx + 0x%llx\n", i, ufd_lrs[i],
						    ufd_r.start, ufd_lrs[i] - ufd_r.start);
					} else {
						printf("user_fault_debug:   bt[%u] 0x%llx = ?\n",
						    i, ufd_lrs[i]);
					}
				}
			} else
#endif /* __arm64__ || __arm__ */
			{
				printf("user_fault_debug: pid %d exc %d codes 0x%llx 0x%llx "
				    "(no user saved state)\n",
				    task_pid(thread->task), exception,
				    (uint64_t)(codeCnt > 0 ? code[0] : 0),
				    (uint64_t)(codeCnt > 1 ? code[1] : 0));
			}
		}
	}
	/* end user_fault_debug */

	if (VM_MAP_PAGE_SIZE(thread->task->map) < PAGE_SIZE) {
		DEBUG4K_EXC("thread %p task %p map %p exception %d codes 0x%llx 0x%llx \n", thread, thread->task, thread->task->map, exception, code[0], code[1]);
		if (debug4k_panic_on_exception) {
			panic("DEBUG4K %s:%d thread %p task %p map %p exception %d codes 0x%llx 0x%llx \n", __FUNCTION__, __LINE__, thread, thread->task, thread->task->map, exception, code[0], code[1]);
		}
	}
#if __has_feature(ptrauth_calls)
	/*
	 * If it is a ptrauth violation, then check if the task has the TF_PAC_EXC_FATAL
	 * flag set and isn't being ptraced. If so, terminate the task via exit_with_reason
	 */
	if (exception & EXC_PTRAUTH_BIT) {
		exception &= ~EXC_PTRAUTH_BIT;

		boolean_t traced_flag = FALSE;
		task_t task = thread->task;
		void *proc = task->bsd_info;

		if (task->bsd_info) {
			traced_flag = proc_is_traced(proc);
		}

		if (task_is_pac_exception_fatal(current_task()) && !traced_flag) {
			exit_with_pac_exception(proc, exception, code[0], code[1]);
			thread_exception_return();
			/* NOT_REACHABLE */
		}
	}
#endif /* __has_feature(ptrauth_calls) */
	return exception_triage_thread(exception, code, codeCnt, thread);
}

kern_return_t
bsd_exception(
	exception_type_t        exception,
	mach_exception_data_t   code,
	mach_msg_type_number_t  codeCnt)
{
	task_t                  task;
	lck_mtx_t               *mutex;
	thread_t                self = current_thread();
	kern_return_t           kr;

	/*
	 * Maybe the task level will handle it.
	 */
	task = current_task();
	mutex = &task->itk_lock_data;

	kr = exception_deliver(self, exception, code, codeCnt, task->exc_actions, mutex);

	if (kr == KERN_SUCCESS || kr == MACH_RCV_PORT_DIED) {
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}


/*
 * Raise an exception on a task.
 * This should tell launchd to launch Crash Reporter for this task.
 */
kern_return_t
task_exception_notify(exception_type_t exception,
    mach_exception_data_type_t exccode, mach_exception_data_type_t excsubcode)
{
	mach_exception_data_type_t      code[EXCEPTION_CODE_MAX];
	wait_interrupt_t                wsave;
	kern_return_t kr = KERN_SUCCESS;

	code[0] = exccode;
	code[1] = excsubcode;

	wsave = thread_interrupt_level(THREAD_UNINT);
	kr = exception_triage(exception, code, EXCEPTION_CODE_MAX);
	(void) thread_interrupt_level(wsave);
	return kr;
}


/*
 *	Handle interface for special performance monitoring
 *	This is a special case of the host exception handler
 */
kern_return_t
sys_perf_notify(thread_t thread, int pid)
{
	host_priv_t             hostp;
	ipc_port_t              xport;
	wait_interrupt_t        wsave;
	kern_return_t           ret;

	hostp = host_priv_self();       /* Get the host privileged ports */
	mach_exception_data_type_t      code[EXCEPTION_CODE_MAX];
	code[0] = 0xFF000001;           /* Set terminate code */
	code[1] = pid;          /* Pass out the pid */

	struct task *task = thread->task;
	xport = hostp->exc_actions[EXC_RPC_ALERT].port;

	/* Make sure we're not catching our own exception */
	if (!IP_VALID(xport) ||
	    !ip_active(xport) ||
	    task->itk_space == xport->data.receiver) {
		return KERN_FAILURE;
	}

	wsave = thread_interrupt_level(THREAD_UNINT);
	ret = exception_deliver(
		thread,
		EXC_RPC_ALERT,
		code,
		2,
		hostp->exc_actions,
		&hostp->lock);
	(void)thread_interrupt_level(wsave);

	return ret;
}
