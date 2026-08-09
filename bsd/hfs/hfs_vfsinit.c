/*
 * hfs_vfsinit.c - built-in-filesystem registration shim for xnu-on-rpi3.
 *
 * Real apple-oss-distributions/hfs registers itself with VFS from
 * core/hfs_iokit.cpp's `com_apple_filesystems_hfs::start()`, an
 * IOService subclass whose start() is invoked by IOKit when the
 * hfs.kext bundle is matched and loaded. This project has no kext
 * loading/matching infrastructure (no kernel cache builder, no code
 * signing, no IOKit kext personality matching against a bundled
 * hfs.kext) and does not need one: the actual VFS registration work
 * hfs_iokit.cpp's start() does is exactly one call to the real,
 * unconditionally-present xnu KPI `vfs_fsadd()` (bsd/vfs/kpi_vfs.c) -
 * the same dynamic-registration KPI any kext-shaped filesystem uses.
 * That call has no IOKit-specific prerequisites of its own.
 *
 * So instead of a kext, this file is a plain C replacement for
 * hfs_iokit.cpp: it does the same vfs_fsadd() call, but from a normal
 * kernel-internal init function (hfs_vfsinit(), analogous in spirit
 * to mockfs's vfsconf-table registration, just via the dynamic KPI
 * instead of the static bsd/vfs/vfs_conf.c table) instead of from an
 * IOService::start(). See docs/hfs-integration-notes.md for the
 * one-line call-site addition (bsd/kern/bsd_init.c, right after
 * vfsinit()) needed to actually invoke hfs_vfsinit() at boot - not
 * applied here since bsd_init.c is shared with concurrent work.
 *
 * This file also provides trivial stand-ins for the three IOKit
 * helper functions hfs_vfsops.c / hfs_vfsutils.c call unconditionally
 * (hfs_is_ejectable, hfs_iterate_media_with_content,
 * hfs_get_platform_serial_number - see hfs_iokit.h). All three are
 * soft-fail/no-op safe by design in upstream hfs already (their
 * results only affect eject-permission checks, Fusion-drive/external-
 * journal device enumeration, and FileVault journal-info-block serial
 * number stamping, none of which apply to a single emulated-SD-card
 * HFS+ volume with no IOMedia/AppleKeyStore stack backing it).
 */

#include "hfs_config.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/errno.h>
#include <mach/kern_return.h>

#include "hfs.h"
#include "hfs_iokit.h"

extern struct vnodeopv_desc hfs_vnodeop_opv_desc;
#if CONFIG_HFS_STD
extern struct vnodeopv_desc hfs_std_vnodeop_opv_desc;
#endif
extern struct vnodeopv_desc hfs_specop_opv_desc;
extern struct vnodeopv_desc hfs_fifoop_opv_desc;
extern struct vfsops hfs_vfsops;

static vfstable_t hfs_vfs_handle;

#define lengthof(x) (sizeof(x)/sizeof(*x))

#ifndef VFS_TBLVNOP_SECLUDE_RENAME
#define VFS_TBLVNOP_SECLUDE_RENAME 0
#endif

int
hfs_vfsinit(void)
{
	struct vnodeopv_desc *op_descs[] = {
		&hfs_vnodeop_opv_desc,
#if CONFIG_HFS_STD
		&hfs_std_vnodeop_opv_desc,
#endif
		&hfs_specop_opv_desc,
#if FIFO
		&hfs_fifoop_opv_desc,
#endif
	};

	struct vfs_fsentry vfe = {
		.vfe_vfsops = &hfs_vfsops,
		.vfe_vopcnt = lengthof(op_descs),
		.vfe_opvdescs = op_descs,
		.vfe_fsname = "hfs",
		.vfe_flags = (VFS_TBLNOTYPENUM | VFS_TBLLOCALVOL | VFS_TBLREADDIR_EXTENDED
					  | VFS_TBL64BITREADY | VFS_TBLVNOP_PAGEOUTV2 | VFS_TBLVNOP_PAGEINV2
					  | VFS_TBLTHREADSAFE | VFS_TBLCANMOUNTROOT | VFS_TBLVNOP_SECLUDE_RENAME
					  | VFS_TBLNATIVEXATTR)
	};

	int ret = vfs_fsadd(&vfe, &hfs_vfs_handle);

	if (ret) {
		printf("hfs: vfs_fsadd failed: %d!\n", ret);
		hfs_vfs_handle = NULL;
		return ret;
	}

	hfs_init_zones();
	hfs_sysctl_register();

	return 0;
}

/*
 * Real implementation asks IOKit ("IOMedia"/"Ejectable" property,
 * matched by BSD name) whether the device hfs is mounted on is
 * user-ejectable. There is no IOMedia stack backing this driver's
 * emulated SD block device the way a real optical/USB drive would
 * have one, and the SD card isn't ejectable in that sense anyway, so
 * "not ejectable" (0) is both the safe and the correct answer here.
 */
int
hfs_is_ejectable(__unused const char *cdev_name)
{
	return 0;
}

/*
 * Real implementation iterates IOMedia objects matching a given
 * "Content" UUID (used to find sibling members of a Fusion Drive /
 * external-journal pair). This platform has exactly one HFS+ device
 * and no such pairing, so there is nothing to iterate - never calling
 * `func` is the correct behavior, matching what upstream does when
 * IOKit finds no matching services.
 */
void
hfs_iterate_media_with_content(__unused const char *content_uuid_cstring,
	__unused int (*func)(const char *bsd_name, const char *uuid_str, void *arg),
	__unused void *arg)
{
}

/*
 * Real implementation reads the platform serial number via
 * IOPlatformExpertDevice, and is used only to stamp an (informational,
 * best-effort) machine serial number into the journal info block.
 * KERN_NOT_SUPPORTED is exactly what upstream itself returns when
 * IOKit can't find "IOPlatformExpertDevice" or the property is
 * absent, so callers already treat this as a normal, handled case.
 */
kern_return_t
hfs_get_platform_serial_number(char *serial_number_str, uint32_t len)
{
	if (len < 1) {
		return KERN_NOT_SUPPORTED;
	}
	serial_number_str[0] = '\0';
	return KERN_NOT_SUPPORTED;
}

/*
 * No AppleKeyStore/Secure-Enclave-equivalent key service exists on
 * this platform. Real hfs_iokit.cpp looks one up dynamically via
 * IOService::callPlatformFunction(kAKSFileSystemKeyServices, ...)
 * and falls back to ENXIO if that fails; here it always fails, so
 * always return ENXIO directly - hfs_cprotect.c's callers already
 * treat that as a normal "content protection unavailable" result
 * (e.g. class-protected file creation/unwrap fails cleanly; class
 * "none"/unprotected files are unaffected).
 */
int
hfs_unwrap_key(__unused cp_cred_t access,
	__unused const cp_wrapped_key_t wrapped_key_in,
	__unused cp_raw_key_t key_out)
{
	return ENXIO;
}

int
hfs_rewrap_key(__unused cp_cred_t access, __unused cp_key_class_t dp_class,
	__unused const cp_wrapped_key_t wrapped_key_in,
	__unused cp_wrapped_key_t wrapped_key_out)
{
	return ENXIO;
}

int
hfs_new_key(__unused cp_cred_t access, __unused cp_key_class_t dp_class,
	__unused cp_raw_key_t key_out, __unused cp_wrapped_key_t wrapped_key_out)
{
	return ENXIO;
}

int
hfs_backup_key(__unused cp_cred_t access,
	__unused const cp_wrapped_key_t wrapped_key_in,
	__unused cp_wrapped_key_t wrapped_key_out)
{
	return ENXIO;
}
