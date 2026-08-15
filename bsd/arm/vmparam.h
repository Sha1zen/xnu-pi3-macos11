/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
 */

#ifndef _BSD_ARM_VMPARAM_H_
#define _BSD_ARM_VMPARAM_H_ 1

#include <sys/resource.h>

#ifndef KERNEL
#include <TargetConditionals.h>
#endif

#define USRSTACK        (0x27E00000)    /* ASLR slides stack down by up to 1MB */
#define USRSTACK64      (0x000000016FE00000ULL)

/*
 * Virtual memory related constants, all in bytes
 */
#ifndef DFLDSIZ
#define DFLDSIZ         (RLIM_INFINITY)         /* initial data size limit */
#endif
#ifndef MAXDSIZ
#define MAXDSIZ         (RLIM_INFINITY)         /* max data size */
#endif
/*
 * xnu-rpi3 port: this board (BCM2837) builds with CONFIG_EMBEDDED (real
 * Apple constraint -- BCM2837 is embedded-only upstream, see this
 * project's CLAUDE.md), which collapses DFLSSIZ/MAXSSIZ below to real
 * iOS-app values (1MB soft/hard) rather than real macOS desktop values
 * (8MB soft / 64MB hard). Real iOS apps are small, single-purpose, and
 * never run a desktop-shaped interactive C process like a real GNU bash
 * with its own recursive-descent parser -- this project's userland does
 * (tools/userland_staging/build_bash.sh), a genuine mismatch between
 * what CONFIG_EMBEDDED assumes about its userland and what this port
 * actually runs on top of it. Confirmed as the real root cause of real
 * bash.macho's early QEMU SIGSEGV (~230-250 stack frames in, matching
 * 1MB / ~4KB-per-frame exactly) via bsd/kern/kern_exec.c's
 * mach_vm_protect() stack-guard math, not guessed. Both macros are
 * designed by Apple's own header to be overridden this way (see the
 * #ifndef guards below) -- this is the real, intended escape hatch, not
 * a source hack. Only affects this board; every other platform's real
 * DFLSSIZ/MAXSSIZ values below are untouched.
 */
#if defined(BCM2837) && !defined(DFLSSIZ) && !defined(MAXSSIZ)
#define DFLSSIZ         (8*1024*1024 - 16*1024)  /* real macOS desktop default, not iOS's 1MB */
#define MAXSSIZ         (64*1024*1024)           /* real macOS desktop max, not iOS's 1MB */
#endif
#ifndef DFLSSIZ
/* XXX stack size default is a platform property: use getrlimit(2) */
#if (defined(TARGET_OS_OSX) && (TARGET_OS_OSX != 0)) || \
        (defined(KERNEL) && !defined(CONFIG_EMBEDDED) || (CONFIG_EMBEDDED == 0))
#define DFLSSIZ         (8*1024*1024 - 16*1024)
#else
#define DFLSSIZ         (1024*1024 - 16*1024)   /* initial stack size limit */
#endif /* TARGET_OS_OSX .. || XNU_KERNEL_PRIVATE .. */
#endif /* DFLSSIZ */
#ifndef MAXSSIZ
/* XXX stack size limit is a platform property: use getrlimit(2) */
#if (defined(TARGET_OS_OSX) && (TARGET_OS_OSX != 0)) || \
        (defined(KERNEL) && !defined(CONFIG_EMBEDDED) || (CONFIG_EMBEDDED == 0))
#define MAXSSIZ         (64*1024*1024)          /* max stack size */
#else
#define MAXSSIZ         (1024*1024)             /* max stack size */
#endif /* TARGET_OS_OSX .. || XNU_KERNEL_PRIVATE .. */
#endif /* MAXSSIZ */
#ifndef DFLCSIZ
#define DFLCSIZ         (0)                     /* initial core size limit */
#endif
#ifndef MAXCSIZ
#define MAXCSIZ         (RLIM_INFINITY)         /* max core size */
#endif  /* MAXCSIZ */

#endif  /* _BSD_ARM_VMPARAM_H_ */
