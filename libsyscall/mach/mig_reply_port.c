/*
 * Copyright (c) 2010 Apple Inc. All rights reserved.
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

#include <mach/mach.h>
#include <mach/mach_init.h>
#include <sys/cdefs.h>
#include "tsd.h"

__XNU_PRIVATE_EXTERN mach_port_t _task_reply_port = MACH_PORT_NULL;

static inline mach_port_t
_mig_get_reply_port()
{
	return (mach_port_t)(uintptr_t)_os_tsd_get_direct(__TSD_MIG_REPLY);
}

static inline void
_mig_set_reply_port(mach_port_t port)
{
	_os_tsd_set_direct(__TSD_MIG_REPLY, (void *)(uintptr_t)port);
}

/*
 * Called by mig interface code whenever a reply port is needed.
 * Tracing is masked during this call; otherwise, a call to printf()
 * can result in a call to malloc() which eventually reenters
 * mig_get_reply_port() and deadlocks.
 */
static long iokit_diag13_syscall3(long num, long a0, long a1, long a2) {
	register long x0 asm("x0") = a0;
	register long x1 asm("x1") = a1;
	register long x2 asm("x2") = a2;
	register long x16 asm("x16") = num;
	asm volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x16) : "memory", "cc");
	return x0;
}
static void iokit_diag13(const char *msg) {
	long len = 0;
	while (msg[len] != '\0') { len++; }
	long fd = iokit_diag13_syscall3(5, (long)"/dev/console", 0x0001 | 0x20000, 0);
	if (fd < 0) { return; }
	iokit_diag13_syscall3(4, fd, (long)msg, len);
	iokit_diag13_syscall3(6, fd, 0, 0);
}

/* TEMP DIAGNOSTIC 2026-08-29, resuming bug #6: print the raw TPIDRRO_EL0-
 * derived TSD base pointer as hex, bracketing each real memory access this
 * function makes, so a bisection of exactly which line SIGSEGVs doesn't
 * require re-adding instrumentation and re-booting again. Deliberately
 * duplicates iokit_diag13's own raw-syscall console helper rather than
 * sharing it -- this needs to print a pointer value, not just a fixed
 * string, and this file must stay self-contained (see this file's own
 * surrounding convention: every iokit_diagN helper in this investigation
 * is self-contained per translation unit). */
static void iokit_diag13_hex(const char *label, unsigned long val) {
	char buf[32];
	long len = 0;
	while (label[len] != '\0') { len++; }
	char hex[19];
	hex[0] = '0'; hex[1] = 'x';
	for (int i = 0; i < 16; i++) {
		int nibble = (val >> ((15 - i) * 4)) & 0xf;
		hex[2 + i] = nibble < 10 ? ('0' + nibble) : ('a' + nibble - 10);
	}
	hex[18] = '\n';
	long total = 0;
	for (long i = 0; i < len && total < (long)sizeof(buf); i++) { buf[total++] = label[i]; }
	for (long i = 0; i < 19 && total < (long)sizeof(buf); i++) { buf[total++] = hex[i]; }
	long fd = iokit_diag13_syscall3(5, (long)"/dev/console", 0x0001 | 0x20000, 0);
	if (fd < 0) { return; }
	iokit_diag13_syscall3(4, fd, (long)buf, total);
	iokit_diag13_syscall3(6, fd, 0, 0);
}

__attribute__((always_inline)) static inline void **
iokit_diag13_tsd_base(void) {
	uint64_t tsd;
	__asm__("mrs %0, TPIDRRO_EL0\n\t"
	        "bic %0, %0, #0x7\n" : "=r" (tsd));
	return (void **)(uintptr_t)tsd;
}

mach_port_t
mig_get_reply_port(void)
{
	iokit_diag13("IOKITDIAG13: mig_get_reply_port (libsystem_kernel.dylib copy) entry\n");
	iokit_diag13_hex("IOKITDIAG13: raw TSD base=", (unsigned long)(uintptr_t)iokit_diag13_tsd_base());
	mach_port_t port = _mig_get_reply_port();
	iokit_diag13_hex("IOKITDIAG13: past _mig_get_reply_port, port=", (unsigned long)port);
	if (port == MACH_PORT_NULL) {
		port = mach_reply_port();
		iokit_diag13_hex("IOKITDIAG13: past mach_reply_port, port=", (unsigned long)port);
		_mig_set_reply_port(port);
		iokit_diag13("IOKITDIAG13: past _mig_set_reply_port\n");
	}
	iokit_diag13("IOKITDIAG13: mig_get_reply_port exit\n");
	return port;
}

/*
 * Called by mig interface code after a timeout on the reply port.
 * May also be called by user. The new mig calls with port passed in.
 */
void
mig_dealloc_reply_port(mach_port_t migport)
{
	mach_port_t port = _mig_get_reply_port();
	if (port != MACH_PORT_NULL && port != _task_reply_port) {
		_mig_set_reply_port(_task_reply_port);
		(void) mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
		if (migport != port) {
			(void) mach_port_deallocate(mach_task_self(), migport);
		}
		_mig_set_reply_port(MACH_PORT_NULL);
	}
}

/*************************************************************
 *  Called by mig interfaces after each RPC.
 *  Could be called by user.
 ***********************************************************/

void
mig_put_reply_port(mach_port_t reply_port __unused)
{
}
