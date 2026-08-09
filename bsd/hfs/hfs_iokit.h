/*
 * hfs_iokit.h - trimmed compat shim for xnu-on-rpi3.
 *
 * The real apple-oss-distributions/hfs hfs_iokit.h additionally
 * declares four AppleKeyStore-backed key-wrapping functions
 * (hfs_unwrap_key/hfs_rewrap_key/hfs_new_key/hfs_backup_key) behind
 * `#include <AppleKeyStore/AppleKeyStoreFSServices.h>`, using
 * AppleKeyStore's own aks_cred_t/aks_wrapped_key_t/aks_raw_key_t
 * types. AppleKeyStore is a separate, closed-source framework this
 * project does not have. It also turns out not to matter: this
 * exact xnu-7195 tree's own bsd/sys/cprotect.h (already vendored,
 * not part of this vendoring pass) independently defines a generic,
 * kernel-internal equivalent of the very same interface -
 * cp_cred_t/cp_wrapped_key_t/cp_raw_key_t/cp_key_class_t, with
 * identical field layouts (key/key_len/dp_class etc) and identical
 * unwrapper_t/rewrapper_t/new_key_t/backup_key_t function-pointer
 * shapes - just generalized away from the AppleKeyStore-specific
 * naming. hfs_cprotect.c has been mechanically adapted (in this
 * vendoring pass) to use the cp_* names instead of aks_* throughout;
 * this header declares hfs_unwrap_key etc. to match. See
 * docs/hfs-integration-notes.md for the full explanation.
 *
 * Note CONFIG_PROTECT is NOT actually optional on this kernel: this
 * project's DEVELOPMENT_ARM64_BCM2837 build config already defines
 * -DCONFIG_PROTECT unconditionally (confirmed via the real, already-
 * generated BUILD/obj/.../bsd/DEVELOPMENT/.CFLAGS from a prior
 * build), so hfs_config.h cannot turn it off - hfs_cprotect.c's full
 * body compiles for real, hence needing this adaptation rather than
 * being able to just rely on it being preprocessed away.
 */

#ifndef hfs_iokit_h
#define hfs_iokit_h

#include <sys/cdefs.h>
#include <sys/cprotect.h>

__BEGIN_DECLS

int hfs_is_ejectable(const char *cdev_name);
void hfs_iterate_media_with_content(const char *content_uuid_cstring,
									int (*func)(const char *bsd_name,
												const char *uuid_str,
												void *arg),
									void *arg);
kern_return_t hfs_get_platform_serial_number(char *serial_number_str,
											 uint32_t len);

/*
 * Real signatures (matching AppleKeyStore's own) take aks_cred_t /
 * aks_wrapped_key_t / aks_raw_key_t; here they take this tree's own
 * generic cp_cred_t / cp_wrapped_key_t / cp_raw_key_t instead - see
 * comment above. There is no real key-service backing on this
 * platform (no Secure Enclave / AppleKeyStore equivalent), so all
 * four unconditionally return ENXIO - the same error upstream's own
 * key_services() helper returns when the platform doesn't implement
 * kAKSFileSystemKeyServices, which callers already treat as a normal,
 * handled "content protection unavailable" case.
 */
int hfs_unwrap_key(cp_cred_t access, const cp_wrapped_key_t wrapped_key_in,
				   cp_raw_key_t key_out);
int hfs_rewrap_key(cp_cred_t access, cp_key_class_t dp_class,
				   const cp_wrapped_key_t wrapped_key_in,
				   cp_wrapped_key_t wrapped_key_out);
int hfs_new_key(cp_cred_t access, cp_key_class_t dp_class,
				cp_raw_key_t key_out, cp_wrapped_key_t wrapped_key_out);
int hfs_backup_key(cp_cred_t access, const cp_wrapped_key_t wrapped_key_in,
				   cp_wrapped_key_t wrapped_key_out);

__END_DECLS

#endif /* hfs_iokit_h */
