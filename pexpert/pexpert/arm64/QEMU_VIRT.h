#ifndef _PEXPERT_ARM_QEMU_VIRT_H
#define _PEXPERT_ARM_QEMU_VIRT_H

/*
 * QEMU 'virt' machine (arm64) board configuration for the iOS-On-Nothing
 * project. Modeled after the BCM2837 bring-up header: the kernel core is
 * runtime-adaptive via the Apple-format Device Tree; this header only pins
 * build-time feature switches that pexpert and bsd expect to see.
 */

/* Generic switches mirroring the BCM2837 bring-up pattern. */
#define NO_MONITOR 1
#define NO_ECORE 1

#define QEMU_VIRT
#define QEMU_VIRT_BRINGUP
#define ARM_ARCH_TIMER

#define __ARM_ARCH__              8
#define __ARM_VMSA__              8
#define __ARM_VFP__               4
#define __ARM_COHERENT_CACHE__    1
#define __ARM_DEBUG__             7
#define __ARM64_PMAP_SUBPAGE_L1__ 1

/* Early console: PL011 at QEMU virt address 0x09000000 (matched from the
 * 'uart0' DT node; register mapping resolved from the tree at boot). */
#define QEMU_PL011_UART

#define ARM_BREAK                asm volatile("brk #0");

/* QEMU virt GIC location (GIC-600-style downstream of the GICv3 model) for
 * IOKit's interrupt controller driver to consume. */
#define QEMU_VIRT_GICD_BASE 0x08010000
#define QEMU_VIRT_GICR_BASE 0x08014000

#endif /* _PEXPERT_ARM_QEMU_VIRT_H */
