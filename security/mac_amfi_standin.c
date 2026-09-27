/*
 * mac_amfi_standin: a permissive stand-in for AMFI's code-signing policy
 * (iokit port, DAR-391; real enforcement is DAR-414).
 *
 * Why it exists. The kernel honours a process's entitlements only when the
 * process is CS_SIGNED: cs_entitlements_blob_get() returns nothing otherwise
 * (bsd/kern/kern_cs.c:1463-1469), and IOUserClient::copyClientEntitlement()
 * reads them through it (iokit/Kernel/IOUserClient.cpp:1475-1484). Nothing
 * in open xnu sets CS_SIGNED for a normally loaded binary (the one other
 * setter, the detached-signature path at bsd/kern/kern_exec.c:6939, refuses
 * any binary with entitlements): load_code_signature()
 * copies only the blob's own flags plus CS_VALID (bsd/kern/mach_loader.c:3211,
 * bsd/kern/ubc_subr.c:3350), and ubc_cs_blob_add() leaves the rest to the
 * MACF policies' vnode_check_signature hooks (ubc_subr.c:3511-3512,
 * security/mac_vfs.c:1341). On Apple platforms that policy is AMFI, which is
 * closed source; this port has none, so no process could hold an
 * entitlement, and every IOHIDFamily user client (entitlement-checked:
 * iokit/HID/IOHIDFamily/IOHIDEventServiceUserClient.cpp:242-253,
 * iokit/HID/IOHIDSystem/IOHIDUserClient.cpp:72) was unreachable.
 *
 * What it does. One MACF policy with a single hook, vnode_check_signature,
 * which ubc_cs_blob_add() calls for a signature blob whose structure the
 * kernel has already checked (cs_blob_create_validated(), ubc_subr.c:3494;
 * ubc_cs_blob_revalidate() calls it again at ubc_subr.c:4219). Page hashes
 * are still checked at fault time, and the entitlements blob's own hash when
 * it is read (ubc_subr.c:764). The hook adds CS_SIGNED to the blob's flags
 * and accepts it, so the binary's own entitlements (ad-hoc signatures
 * included) are honoured. The intent is to approximate a Mac booted with
 * AMFI relaxed (amfi_get_out_of_my_way=1); AMFI itself is closed source, so
 * that is an approximation, not a copy. It trusts self-asserted entitlements
 * and enforces nothing; DAR-414 tracks real enforcement. If root turns off
 * security.mac.vnode_enforce, MACF skips the hook (security/mac_vfs.c:
 * 1333-1337) and later execs lose their entitlements.
 *
 * When it registers. On non-macOS targets mac_policy_list is
 * SECURITY_READ_ONLY_LATE (mac_base.c:252-257), so policies must register
 * in mac_policy_initmach() (mac_base.c:383-404), before lockdown
 * (osfmk/kern/startup.c:731, before STARTUP_SUB_LOCKDOWN and machine_lockdown()), which is where Apple's own security
 * extensions (AMFI, Sandbox) register through
 * load_security_extensions_function (libsa/bootstrap.cpp:161, 530: kexts
 * marked AppleSecurityExtension). Registering later
 * (from IOKit matching) faults writing the list. mac_amfi_standin_register()
 * is called from there. Boot-arg amfi_standin=0 skips it.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel_types.h>
#include <sys/codesign.h>
#include <pexpert/pexpert.h>
#include <security/mac_policy.h>

static int
amfi_standin_vnode_check_signature(struct vnode *vp __unused, struct label *label __unused,
    cpu_type_t cpu_type __unused, struct cs_blob *cs_blob __unused,
    unsigned int *cs_flags, unsigned int *signer_type __unused, int flags __unused,
    unsigned int platform __unused, char **fatal_failure_desc __unused,
    size_t *fatal_failure_desc_len __unused)
{
	*cs_flags |= CS_SIGNED;
	return 0;
}

static const struct mac_policy_ops amfi_standin_ops = {
	.mpo_vnode_check_signature = amfi_standin_vnode_check_signature,
};

static struct mac_policy_conf amfi_standin_conf = {
	.mpc_name            = "amfi_standin",
	.mpc_fullname        = "Permissive code-signing policy (AMFI stand-in, DAR-391)",
	.mpc_labelnames      = NULL,
	.mpc_labelname_count = 0,
	.mpc_ops             = &amfi_standin_ops,
	.mpc_loadtime_flags  = 0,
	.mpc_field_off       = NULL,
	.mpc_runtime_flags   = 0,
	.mpc_list            = NULL,
	.mpc_data            = NULL,
};

static mac_policy_handle_t amfi_standin_handle;

void mac_amfi_standin_register(void);

void
mac_amfi_standin_register(void)
{
	unsigned int enabled = 1;

	PE_parse_boot_argn("amfi_standin", &enabled, sizeof(enabled));
	if (!enabled) {
		printf("amfi_standin: disabled by boot-arg amfi_standin=0\n");
		return;
	}
	int err = mac_policy_register(&amfi_standin_conf, &amfi_standin_handle, NULL);
	if (err != 0) {
		printf("amfi_standin: mac_policy_register failed (%d)\n", err);
		return;
	}
	printf("amfi_standin: registered; signed binaries are CS_SIGNED and their "
	    "entitlements honoured (permissive, DAR-414)\n");
}
