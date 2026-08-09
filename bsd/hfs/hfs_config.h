/*
 * hfs_config.h - built-in-filesystem compat shim for xnu-on-rpi3.
 *
 * Real apple-oss-distributions/hfs is built as a standalone kext
 * (hfs.kext) via its own Xcode project. That project force-includes
 * core/kext-config.h as a GCC prefix header (see hfs.xcconfig's
 * GCC_PREFIX_HEADER=core/kext-config.h) to set the feature macros
 * every .c file in the project assumes are already defined before
 * any other header is processed. xnu's built-in-filesystem convention
 * (mockfs, msdosfs) has no per-optional-group prefix-header
 * mechanism, so this header is `#include`d explicitly as the very
 * first line of every vendored bsd/hfs/*.c file instead (see
 * docs/hfs-integration-notes.md for why, and for the one-line
 * addition to each file).
 *
 * kext-config.h itself branches on `#if (TARGET_OS_IPHONE &&
 * !TARGET_OS_SIMULATOR)` after `#include <TargetConditionals.h>`.
 * That header does not exist anywhere in this kernel's own (-nostdinc)
 * include paths - real xnu source (e.g. bsd/sys/cdefs.h, and this
 * vendored hfs_vfsops.c itself, which has several `#if TARGET_OS_OSX`
 * blocks) already references TARGET_OS_OSX/TARGET_OS_IPHONE WITHOUT
 * ever including TargetConditionals.h anywhere in-tree, relying on
 * plain C's "undefined macro in #if evaluates to 0" rule (a
 * -Wundef-only warning, and this build already runs with
 * BUILD_WERROR=0) to make them implicitly false. That is exactly the
 * right behavior for this project's real target anyway (an embedded,
 * non-macOS, non-simulator board - this project's real kernel build,
 * tools/build_xnu_7195.sh, itself uses SDKROOT=iphoneos/
 * PLATFORM=iPhoneOS, i.e. is already conceptually the
 * TARGET_OS_IPHONE-true / TARGET_OS_OSX-false side of that split),
 * so this file deliberately does NOT try to define or fake
 * TargetConditionals.h - it just lets TARGET_OS_OSX/TARGET_OS_IPHONE
 * fall through as undefined/false everywhere they're used, in both
 * this file and the vendored .c files, the same way the rest of this
 * kernel already does.
 *
 * Concretely, that means kext-config.h's "OS X" branch (CONFIG_HFS_DIRLINK,
 * CONFIG_SEARCHFS) is correctly NOT selected here, and the one place
 * upstream hfs_vfsops.c calls into hfs_getencodingbias()/
 * hfs_setencodingbias() is gated `#if TARGET_OS_OSX` and so is
 * correctly compiled out - which matters, because apple-oss-
 * distributions/hfs declares (in hfs_encodings/hfs_encodings.h) but,
 * as far as `gh search code` across the entire apple-oss-distributions
 * org could find, never actually PUBLISHES a definition anywhere for
 * mac_roman_to_unicode()/unicode_to_mac_roman()/mac_roman_to_utf8()/
 * utf8_to_mac_roman() - see docs/hfs-integration-notes.md's Blockers
 * section. Every other call site for those four functions is gated
 * `#if CONFIG_HFS_STD` (confirmed by walking the #if/#endif nesting
 * for each call site), and CONFIG_HFS_STD is also correctly left
 * unset here (legacy pre-1998 HFS Standard support is out of scope
 * for this project - a fresh SD card only ever gets a modern HFS+
 * volume). So with TARGET_OS_OSX and CONFIG_HFS_STD both naturally
 * false, this genuinely-missing-upstream code never needs to link.
 *
 * QUOTA and NAMEDSTREAMS are also deliberately NOT set here even
 * though kext-config.h sets them (QUOTA 0 on the iOS branch,
 * NAMEDSTREAMS 1 on the OS X branch): both are already real
 * MASTER-config-driven macros this kernel generates itself (the
 * `quota` opt tag in config/MASTER - confirmed off for this platform
 * via a standalone compile test producing a QUOTA-redefined warning
 * against the real generated bsd/DEVELOPMENT/quota.h; and the
 * `namedstreams` token already present in config/MASTER.arm64.bcm2837's
 * FILESYS_BASE bracket - confirmed via the real, already-captured
 * build .CFLAGS from a prior build). Redefining them here would
 * either just warn (same value) or, worse, silently diverge from
 * whatever the rest of this kernel is actually configured with if
 * that bracket ever changes.
 */

#ifndef _hfs_config_
#define _hfs_config_

#define HFS_COMPRESSION 1
#define FIFO 1

#endif /* _hfs_config_ */
