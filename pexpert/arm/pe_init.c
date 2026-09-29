/*
 * Copyright (c) 2000-2017 Apple Inc. All rights reserved.
 *
 *    arm platform expert initialization.
 */
#include <sys/types.h>
#include <sys/kdebug.h>
#include <mach/vm_param.h>
#include <pexpert/protos.h>
#include <pexpert/pexpert.h>
#include <pexpert/boot.h>
#include <pexpert/device_tree.h>
#include <pexpert/pe_images.h>
#include <kern/sched_prim.h>
#include <machine/machine_routines.h>
#include <arm/caches_internal.h>
#include <kern/debug.h>
#include <libkern/section_keywords.h>

#if defined __arm__
#include <pexpert/arm/board_config.h>
#elif defined __arm64__
#include <pexpert/arm64/board_config.h>
#endif


/* extern references */
extern void     pe_identify_machine(boot_args *bootArgs);

/* static references */
static void     pe_prepare_images(void);

/* private globals */
SECURITY_READ_ONLY_LATE(PE_state_t) PE_state;
#define FW_VERS_LEN 128
char            firmware_version[FW_VERS_LEN];

/*
 * This variable is only modified once, when the BSP starts executing. We put it in __TEXT
 * as page protections on kernel text early in startup are read-write. The kernel is
 * locked down later in start-up, said mappings become RO and thus this
 * variable becomes immutable.
 *
 * See osfmk/arm/arm_vm_init.c for more information.
 */
SECURITY_READ_ONLY_SPECIAL_SECTION(volatile uint32_t, "__TEXT,__const") debug_enabled = FALSE;

uint8_t         gPlatformECID[8];
uint32_t        gPlatformMemoryID;
static boolean_t vc_progress_initialized = FALSE;
uint64_t    last_hwaccess_thread = 0;
char     gTargetTypeBuffer[16];
char     gModelTypeBuffer[32];

/* Clock Frequency Info */
clock_frequency_info_t gPEClockFrequencyInfo;

vm_offset_t gPanicBase = 0;
unsigned int gPanicSize;
struct embedded_panic_header *panic_info = NULL;

#if (DEVELOPMENT || DEBUG) && defined(XNU_TARGET_OS_BRIDGE)
/*
 * On DEVELOPMENT bridgeOS, we map the x86 panic region
 * so we can include this data in bridgeOS corefiles
 */
uint64_t macos_panic_base = 0;
unsigned int macos_panic_size = 0;

struct macos_panic_header *mac_panic_header = NULL;
#endif

/* Maximum size of panic log excluding headers, in bytes */
static unsigned int panic_text_len;

/* Whether a console is standing by for panic logging */
static boolean_t panic_console_available = FALSE;

extern uint32_t crc32(uint32_t crc, const void *buf, size_t size);

void PE_slide_devicetree(vm_offset_t);

static void
check_for_panic_log(void)
{
#ifdef PLATFORM_PANIC_LOG_PADDR
	gPanicBase = ml_io_map_wcomb(PLATFORM_PANIC_LOG_PADDR, PLATFORM_PANIC_LOG_SIZE);
	panic_text_len = PLATFORM_PANIC_LOG_SIZE - sizeof(struct embedded_panic_header);
	gPanicSize = PLATFORM_PANIC_LOG_SIZE;
#else
	DTEntry entry, chosen;
	unsigned int size;
	uintptr_t const *reg_prop;
	uint32_t const *panic_region_length;

	/*
	 * DT properties for the panic region are populated by UpdateDeviceTree() in iBoot:
	 *
	 * chosen {
	 *   embedded-panic-log-size = <0x00080000>;
	 *   [a bunch of other stuff]
	 * };
	 *
	 * pram {
	 *   reg = <0x00000008_fbc48000 0x00000000_000b4000>;
	 * };
	 *
	 * reg[0] is the physical address
	 * reg[1] is the size of iBoot's kMemoryRegion_Panic (not used)
	 * embedded-panic-log-size is the maximum amount of data to store in the buffer
	 */
	if (kSuccess != SecureDTLookupEntry(0, "pram", &entry)) {
		return;
	}

	if (kSuccess != SecureDTGetProperty(entry, "reg", (void const **)&reg_prop, &size)) {
		return;
	}

	if (kSuccess != SecureDTLookupEntry(0, "/chosen", &chosen)) {
		return;
	}

	if (kSuccess != SecureDTGetProperty(chosen, "embedded-panic-log-size", (void const **) &panic_region_length, &size)) {
		return;
	}

	gPanicBase = ml_io_map_wcomb(reg_prop[0], panic_region_length[0]);

	/* Deduct the size of the panic header from the panic region size */
	panic_text_len = panic_region_length[0] - sizeof(struct embedded_panic_header);
	gPanicSize = panic_region_length[0];

#if DEVELOPMENT && defined(XNU_TARGET_OS_BRIDGE)
	if (PE_consistent_debug_enabled()) {
		uint64_t macos_panic_physbase = 0;
		uint64_t macos_panic_physlen = 0;
		/* Populate the macOS panic region data if it's present in consistent debug */
		if (PE_consistent_debug_lookup_entry(kDbgIdMacOSPanicRegion, &macos_panic_physbase, &macos_panic_physlen)) {
			macos_panic_base = ml_io_map_with_prot(macos_panic_physbase, macos_panic_physlen, VM_PROT_READ);
			mac_panic_header = (struct macos_panic_header *) ((void *) macos_panic_base);
			macos_panic_size = macos_panic_physlen;
		}
	}
#endif /* DEVELOPMENT && defined(XNU_TARGET_OS_BRIDGE) */

#endif
	panic_info = (struct embedded_panic_header *)gPanicBase;

	/* Check if a shared memory console is running in the panic buffer */
	if (panic_info->eph_magic == 'SHMC') {
		panic_console_available = TRUE;
		return;
	}

	/* Check if there's a boot profile in the panic buffer */
	if (panic_info->eph_magic == 'BTRC') {
		return;
	}

	/*
	 * Check to see if a panic (FUNK) is in VRAM from the last time
	 */
	if (panic_info->eph_magic == EMBEDDED_PANIC_MAGIC) {
		printf("iBoot didn't extract panic log from previous session crash, this is bad\n");
	}

	/* Clear panic region */
	bzero((void *)gPanicBase, gPanicSize);
}

int
PE_initialize_console(PE_Video * info, int op)
{
	static int last_console = -1;

	if (info && (info != &PE_state.video)) {
		info->v_scale = PE_state.video.v_scale;
	}

	switch (op) {
	case kPEDisableScreen:
		initialize_screen(info, op);
		last_console = switch_to_serial_console();
		kprintf("kPEDisableScreen %d\n", last_console);
		break;

	case kPEEnableScreen:
		initialize_screen(info, op);
		if (info) {
			PE_state.video = *info;
		}
		kprintf("kPEEnableScreen %d\n", last_console);
		if (last_console != -1) {
			switch_to_old_console(last_console);
		}
		break;

	case kPEReleaseScreen:
		/*
		 * we don't show the progress indicator on boot, but want to
		 * show it afterwards.
		 */
		if (!vc_progress_initialized) {
			default_progress.dx = 0;
			default_progress.dy = 0;
			vc_progress_initialize(&default_progress,
			    default_progress_data1x,
			    default_progress_data2x,
			    default_progress_data3x,
			    (unsigned char *) appleClut8);
			vc_progress_initialized = TRUE;
		}
		initialize_screen(info, op);
		break;

	default:
		initialize_screen(info, op);
		break;
	}

	return 0;
}

void
PE_init_iokit(void)
{
	DTEntry         entry;
	unsigned int    size, scale;
	unsigned long   display_size;
	void const * const *map;
	unsigned int    show_progress;
	int             *delta, image_size, flip;
	uint32_t        start_time_value = 0;
	uint32_t        debug_wait_start_value = 0;
	uint32_t        load_kernel_start_value = 0;
	uint32_t        populate_registry_time_value = 0;

	PE_init_printf(TRUE);

	printf("iBoot version: %s\n", firmware_version);

	if (kSuccess == SecureDTLookupEntry(0, "/chosen/memory-map", &entry)) {
		boot_progress_element const *bootPict;

		if (kSuccess == SecureDTGetProperty(entry, "BootCLUT", (void const **) &map, &size)) {
			bcopy(map[0], appleClut8, sizeof(appleClut8));
		}

		if (kSuccess == SecureDTGetProperty(entry, "Pict-FailedBoot", (void const **) &map, &size)) {
			bootPict = (boot_progress_element const *) map[0];
			default_noroot.width = bootPict->width;
			default_noroot.height = bootPict->height;
			default_noroot.dx = 0;
			default_noroot.dy = bootPict->yOffset;
			default_noroot_data = &bootPict->data[0];
		}
	}

	pe_prepare_images();

	scale = PE_state.video.v_scale;
	flip = 1;

#if defined(XNU_TARGET_OS_OSX)
	int notused;
	show_progress = TRUE;
	if (PE_parse_boot_argn("-restore", &notused, sizeof(notused))) {
		show_progress = FALSE;
	}
	if (PE_parse_boot_argn("-noprogress", &notused, sizeof(notused))) {
		show_progress = FALSE;
	}
#else
	show_progress = FALSE;
	PE_parse_boot_argn("-progress", &show_progress, sizeof(show_progress));
#endif /* XNU_TARGET_OS_OSX */
	if (show_progress) {
		/* Rotation: 0:normal, 1:right 90, 2:left 180, 3:left 90 */
		switch (PE_state.video.v_rotate) {
		case 2:
			flip = -1;
			OS_FALLTHROUGH;
		case 0:
			display_size = PE_state.video.v_height;
			image_size = default_progress.height;
			delta = &default_progress.dy;
			break;
		case 1:
			flip = -1;
			OS_FALLTHROUGH;
		case 3:
		default:
			display_size = PE_state.video.v_width;
			image_size = default_progress.width;
			delta = &default_progress.dx;
		}
		assert(*delta >= 0);
		while (((unsigned)(*delta + image_size)) >= (display_size / 2)) {
			*delta -= 50 * scale;
			assert(*delta >= 0);
		}
		*delta *= flip;

		/* Check for DT-defined progress y delta */
		PE_get_default("progress-dy", &default_progress.dy, sizeof(default_progress.dy));

		vc_progress_initialize(&default_progress,
		    default_progress_data1x,
		    default_progress_data2x,
		    default_progress_data3x,
		    (unsigned char *) appleClut8);
		vc_progress_initialized = TRUE;
	}

	if (kdebug_enable && kdebug_debugid_enabled(IOKDBG_CODE(DBG_BOOTER, 0))) {
		/* Trace iBoot-provided timing information. */
		if (kSuccess == SecureDTLookupEntry(0, "/chosen/iBoot", &entry)) {
			uint32_t const * value_ptr;

			if (kSuccess == SecureDTGetProperty(entry, "start-time", (void const **)&value_ptr, &size)) {
				if (size == sizeof(start_time_value)) {
					start_time_value = *value_ptr;
				}
			}

			if (kSuccess == SecureDTGetProperty(entry, "debug-wait-start", (void const **)&value_ptr, &size)) {
				if (size == sizeof(debug_wait_start_value)) {
					debug_wait_start_value = *value_ptr;
				}
			}

			if (kSuccess == SecureDTGetProperty(entry, "load-kernel-start", (void const **)&value_ptr, &size)) {
				if (size == sizeof(load_kernel_start_value)) {
					load_kernel_start_value = *value_ptr;
				}
			}

			if (kSuccess == SecureDTGetProperty(entry, "populate-registry-time", (void const **)&value_ptr, &size)) {
				if (size == sizeof(populate_registry_time_value)) {
					populate_registry_time_value = *value_ptr;
				}
			}
		}

		KDBG_RELEASE(IOKDBG_CODE(DBG_BOOTER, 0), start_time_value, debug_wait_start_value, load_kernel_start_value, populate_registry_time_value);
	}

	InitIOKit(PE_state.deviceTreeHead);
	ConfigureIOKit();
}

void
PE_lockdown_iokit(void)
{
	/*
	 * On arm/arm64 platforms, and especially those that employ KTRR/CTRR,
	 * machine_lockdown() is treated as a hard security checkpoint, such that
	 * code which executes prior to lockdown must be minimized and limited only to
	 * trusted parts of the kernel and specially-entitled kexts.  We therefore
	 * cannot start the general-purpose IOKit matching process until after lockdown,
	 * as it may involve execution of untrusted/non-entitled kext code.
	 * Furthermore, such kext code may process attacker controlled data (e.g.
	 * network packets), which dramatically increases the potential attack surface
	 * against a kernel which has not yet enabled the full set of available
	 * hardware protections.
	 */
	StartIOKitMatching();
}

void
PE_slide_devicetree(vm_offset_t slide)
{
	assert(PE_state.initialized);
	/* TEMP DIAGNOSTIC / COMPAT FIX: this used to be plain pointer
	 * arithmetic (`PE_state.deviceTreeHead += slide;`). Our modern
	 * Xcode 26.6 clang - much newer than whatever built this xnu-7195
	 * vintage originally - instruments `void* + integer` with a
	 * pointer-arithmetic-overflow hardening check that doesn't
	 * understand phystokv()-style "physical address plus a huge kernel
	 * slide, deliberately flipping the top bits into canonical kernel
	 * space" as legitimate: it detects the top-bit change and POISONS
	 * the result with a fixed movk #0xc8a2 marker instead of trapping
	 * (confirmed via lldb disassembly of the compiled function).
	 * phystokv() elsewhere in the tree never hits this because it does
	 * the identical slide as plain vm_offset_t integer arithmetic, only
	 * casting to a pointer at the point of use - do the same here to
	 * sidestep the check entirely, since the actual math is correct.
	 * See project memory (Bug #4 investigation). */
	PE_state.deviceTreeHead = (void *)((vm_offset_t)PE_state.deviceTreeHead + slide);
	SecureDTInit(PE_state.deviceTreeHead, PE_state.deviceTreeSize);
}

/*
 * BCM2837 VideoCore mailbox property-tag protocol - requests an HDMI
 * framebuffer from the GPU firmware so PE_state.video can be populated
 * before PE_create_console() runs (see its call site in PE_init_platform
 * below), giving video_console.c a real scrollback console on HDMI instead
 * of nothing.
 *
 * Ported from the project's old xnu-6153 tree (third_party/xnu,
 * pexpert/arm/pe_init.c), where it was originally written and validated
 * against project memory's register/tag-ID cross-checks (Linux's
 * drivers/mailbox/bcm2835-mailbox.c and drivers/firmware/raspberrypi.c;
 * tag IDs also cross-checked against third_party/qemu-zhuowei's own
 * hw/misc/bcm2835_property.c). Adapted for this tree's vintage: uses
 * SecureDTFindEntry/SecureDTGetProperty (this tree has no plain
 * DTFindEntry/DTGetProperty), and ml_vtophys instead of kvtophys (the
 * choice the old tree's own follow-up fix settled on as the actually
 * working API for that vintage - kept here for consistency, and it's
 * already reachable via this file's existing <machine/machine_routines.h>
 * include, so no new #include is needed).
 *
 * Neither loader this project boots through populates boot_args->Video at
 * all (confirmed: neither third_party/qemu-zhuowei's arm_load_macho() nor
 * FlorentRevest/u-boot's cmd/bootxnu.c touch it, both leave it zeroed), so
 * this always runs. On any failure it just returns FALSE and leaves
 * PE_state.video zeroed exactly as before - falls back to the existing
 * kPETextMode path, no regression versus not having this at all.
 */
enum {
	kBcm2837MboxRegRead        = 0x00 / sizeof(uint32_t), // MAIL0_RD  (VC -> ARM)
	kBcm2837MboxRegStatus      = 0x18 / sizeof(uint32_t), // MAIL0_STA
	kBcm2837MboxRegWrite       = 0x20 / sizeof(uint32_t), // MAIL1_WRT (ARM -> VC)
	kBcm2837MboxRegWriteStatus = 0x38 / sizeof(uint32_t), // MAIL1_STA (ARM_0_MAIL1 + 0x18)

	kBcm2837MboxFull  = 1U << 31,
	kBcm2837MboxEmpty = 1U << 30,

	kBcm2837MboxChannelProperty = 8,
};

enum {
	kBcm2837TagSetPhysicalWH  = 0x00048003,
	kBcm2837TagSetVirtualWH   = 0x00048004,
	kBcm2837TagSetDepth       = 0x00048005,
	kBcm2837TagSetPixelOrder  = 0x00048006,
	kBcm2837TagAllocateBuffer = 0x00040001,
	kBcm2837TagGetPitch       = 0x00040008,
	kBcm2837TagEnd            = 0,

	/*
	 * osfmk/console/video_console.c's 32bpp renderer hardcodes
	 * little-endian 0x00RRGGBB words regardless of v_pixelFormat
	 * (confirmed on the old tree: that field is written here and in the
	 * i386 pe_init.c, but never read anywhere in that source tree -
	 * purely decorative; this tree's PE_init_platform similarly just
	 * strlcpy()s a fixed "BBBBBBBBGGGGGGGGRRRRRRRR" string into it from
	 * boot_args, never derived from real pixel order). 0x00RRGGBB stored
	 * little-endian is BB,GG,RR,00 in memory - i.e. the framebuffer needs
	 * BGR byte order, not RGB, to render real colors instead of
	 * red/blue swapped.
	 */
	kBcm2837PixelOrderBGR = 0,
};

/*
 * Fixed layout for exactly the 5 tags bcm2837_video_init() sends, laid out
 * as a flat uint32_t array (not a C struct) so the on-the-wire word offsets
 * are unambiguous and match the real property-list framing byte-for-byte:
 * buf[0]=total size, buf[1]=request/response code, then each tag is
 * {tag_id, value_buf_size, req_resp_size, ...value words...}, terminated
 * by a lone 0 end tag.
 */
enum {
	kMsgIdxSize = 0,
	kMsgIdxCode = 1,

	kMsgIdxPhysWHTag = 2, kMsgIdxPhysWHBufSize = 3, kMsgIdxPhysWHReqSize = 4,
	kMsgIdxPhysW = 5, kMsgIdxPhysH = 6,

	kMsgIdxVirtWHTag = 7, kMsgIdxVirtWHBufSize = 8, kMsgIdxVirtWHReqSize = 9,
	kMsgIdxVirtW = 10, kMsgIdxVirtH = 11,

	kMsgIdxDepthTag = 12, kMsgIdxDepthBufSize = 13, kMsgIdxDepthReqSize = 14,
	kMsgIdxDepthVal = 15,

	kMsgIdxOrderTag = 16, kMsgIdxOrderBufSize = 17, kMsgIdxOrderReqSize = 18,
	kMsgIdxOrderVal = 19,

	kMsgIdxAllocTag = 20, kMsgIdxAllocBufSize = 21, kMsgIdxAllocReqSize = 22,
	kMsgIdxAllocBase = 23, kMsgIdxAllocRespSize = 24,

	kMsgIdxPitchTag = 25, kMsgIdxPitchBufSize = 26, kMsgIdxPitchReqSize = 27,
	kMsgIdxPitchVal = 28,

	kMsgIdxEnd = 29,

	kBcm2837MsgWords = 30,
};

#define BCM2837_FB_WIDTH  640
#define BCM2837_FB_HEIGHT 480
#define BCM2837_FB_DEPTH  32

/* Bounds for the "fb_width"/"fb_height" boot-args: the framebuffer is
 * gpu_mem-backed (config.txt gpu_mem=64) and 1920x1200x4 is ~9.2 MB, so
 * anything in this range fits; values outside it are ignored. */
#define BCM2837_FB_MIN_W 320
#define BCM2837_FB_MAX_W 1920
#define BCM2837_FB_MIN_H 200
#define BCM2837_FB_MAX_H 1200

/*
 * Submits msg (msg[kMsgIdxSize] must already be set to the total buffer
 * size in bytes) over the property-tag channel and blocks until the GPU
 * replies into the same buffer. msg must be 16-byte aligned - the low 4
 * bits of the physical address double as the mailbox channel number in the
 * wire protocol.
 *
 * The explicit cache maintenance here isn't optional: msg lives in normal
 * cached kernel memory, but the GPU firmware reads/writes it over the bus
 * with no CPU cache involved at all, so a write the CPU thinks already
 * happened may still only be sitting in a cache line until CleanPoC_
 * DcacheRegion() pushes it out, and a read after the GPU's reply may
 * return a stale cached copy until FlushPoC_DcacheRegion() invalidates it.
 */
static boolean_t
bcm2837_mbox_call(volatile uint32_t *mbox, uint32_t *msg)
{
	addr64_t msgPhys = ml_vtophys((vm_offset_t) msg);
	if ((msgPhys & 0xF) != 0) {
		return FALSE;
	}

	CleanPoC_DcacheRegion((vm_offset_t) msg, msg[kMsgIdxSize]);

	unsigned waited = 0;
	while (mbox[kBcm2837MboxRegWriteStatus] & kBcm2837MboxFull) {
		if (waited++ > 100000) {
			return FALSE;
		}
	}
	mbox[kBcm2837MboxRegWrite] = (uint32_t)(msgPhys & ~0xFULL) | kBcm2837MboxChannelProperty;

	waited = 0;
	for (;;) {
		while (mbox[kBcm2837MboxRegStatus] & kBcm2837MboxEmpty) {
			if (waited++ > 1000000) {
				return FALSE;
			}
		}
		uint32_t reply = mbox[kBcm2837MboxRegRead];
		if ((reply & 0xF) == kBcm2837MboxChannelProperty) {
			break;
		}
		/* Not our channel (shouldn't happen - we never registered any
		 * other channel's IRQ/consumer) - keep draining. */
	}

	FlushPoC_DcacheRegion((vm_offset_t) msg, msg[kMsgIdxSize]);
	return msg[kMsgIdxCode] == 0x80000000; /* RPI_FIRMWARE_STATUS_SUCCESS */
}

/*
 * Looks up the "mbox" DT node (devicetrees/rpi3.dts / rpi3-realhw.dts),
 * requests a BCM2837_FB_WIDTH x BCM2837_FB_HEIGHT x BCM2837_FB_DEPTH HDMI
 * framebuffer from the GPU firmware, and fills in *video on success.
 * Returns FALSE (leaving *video untouched) on any failure - missing DT
 * node, mailbox timeout, or a GPU-reported error.
 *
 * NOT static, NOT called from PE_init_platform above (unlike the old
 * xnu-6153 tree this was ported from) - confirmed via a live QEMU crash
 * (fault in io_map_with_prot, called from ml_io_map below, called from
 * PE_init_platform's first (!vm_initialized) pass) that ml_io_map() isn't
 * safe that early on this tree: VM/pmap isn't bootstrapped until
 * arm_vm_init() (osfmk/arm/arm_init.c), which runs strictly after
 * PE_init_platform(FALSE, ...). Called instead directly from arm_init()
 * between arm_vm_init() and PE_create_console() - see the extern
 * declaration and call site there for why that's the correct window.
 */
boolean_t
bcm2837_video_init(PE_Video *video)
{
	DTEntry entry;
	uintptr_t const *reg_prop;
	unsigned int prop_size;
	vm_offset_t soc_base = pe_arm_get_soc_base_phys();

	if (soc_base == 0) {
		return FALSE;
	}
	if (SecureDTFindEntry("name", "mbox", &entry) != kSuccess) {
		return FALSE;
	}
	if (SecureDTGetProperty(entry, "reg", (void const **)&reg_prop, &prop_size) != kSuccess) {
		return FALSE;
	}

	volatile uint32_t *mboxBase = (volatile uint32_t *) ml_io_map(soc_base + reg_prop[0], (vm_size_t)reg_prop[1]);
	if (mboxBase == NULL) {
		return FALSE;
	}

	static uint32_t sMboxMsg[kBcm2837MsgWords] __attribute__((aligned(16)));
	uint32_t *b = sMboxMsg;

	/* Requested size: BCM2837_FB_WIDTH x BCM2837_FB_HEIGHT unless BOTH
	 * "fb_width" and "fb_height" boot-args are given and in range (set
	 * them on real hardware with uEnv.txt's extra_bootargs). */
	uint32_t reqW = BCM2837_FB_WIDTH, reqH = BCM2837_FB_HEIGHT;
	uint32_t argW = 0, argH = 0;
	if (PE_parse_boot_argn("fb_width", &argW, sizeof(argW)) &&
	    PE_parse_boot_argn("fb_height", &argH, sizeof(argH)) &&
	    argW >= BCM2837_FB_MIN_W && argW <= BCM2837_FB_MAX_W &&
	    argH >= BCM2837_FB_MIN_H && argH <= BCM2837_FB_MAX_H) {
		reqW = argW;
		reqH = argH;
	}

	b[kMsgIdxCode] = 0; /* RPI_FIRMWARE_STATUS_REQUEST */

	b[kMsgIdxPhysWHTag] = kBcm2837TagSetPhysicalWH;
	b[kMsgIdxPhysWHBufSize] = 8;
	b[kMsgIdxPhysWHReqSize] = 0;
	b[kMsgIdxPhysW] = reqW;
	b[kMsgIdxPhysH] = reqH;

	b[kMsgIdxVirtWHTag] = kBcm2837TagSetVirtualWH;
	b[kMsgIdxVirtWHBufSize] = 8;
	b[kMsgIdxVirtWHReqSize] = 0;
	b[kMsgIdxVirtW] = reqW;
	b[kMsgIdxVirtH] = reqH;

	b[kMsgIdxDepthTag] = kBcm2837TagSetDepth;
	b[kMsgIdxDepthBufSize] = 4;
	b[kMsgIdxDepthReqSize] = 0;
	b[kMsgIdxDepthVal] = BCM2837_FB_DEPTH;

	b[kMsgIdxOrderTag] = kBcm2837TagSetPixelOrder;
	b[kMsgIdxOrderBufSize] = 4;
	b[kMsgIdxOrderReqSize] = 0;
	b[kMsgIdxOrderVal] = kBcm2837PixelOrderBGR;

	b[kMsgIdxAllocTag] = kBcm2837TagAllocateBuffer;
	b[kMsgIdxAllocBufSize] = 8;
	b[kMsgIdxAllocReqSize] = 0;
	b[kMsgIdxAllocBase] = 16; /* requested alignment, in bytes */
	b[kMsgIdxAllocRespSize] = 0;

	b[kMsgIdxPitchTag] = kBcm2837TagGetPitch;
	b[kMsgIdxPitchBufSize] = 4;
	b[kMsgIdxPitchReqSize] = 0;
	b[kMsgIdxPitchVal] = 0;

	b[kMsgIdxEnd] = kBcm2837TagEnd;
	b[kMsgIdxSize] = kBcm2837MsgWords * sizeof(uint32_t);

	if (!bcm2837_mbox_call(mboxBase, b)) {
		return FALSE;
	}

	/* The returned bus address has one of the VC alias bits (0x40000000/
	 * 0x80000000/0xC0000000, selecting cache behavior on the VC's own
	 * bus) set in the top byte - mask them off to get the real physical
	 * address, a standard, widely-documented gotcha of this interface. */
	uint32_t fbPhysAddr = b[kMsgIdxAllocBase] & 0x3FFFFFFF;
	uint32_t fbSize = b[kMsgIdxAllocRespSize];
	uint32_t fbPitch = b[kMsgIdxPitchVal];
	if (fbPhysAddr == 0 || fbSize == 0 || fbPitch == 0) {
		return FALSE;
	}

	/* PHYSICAL address, not a mapping (DAR-331). This used to hand over
	 * an ml_io_map_wcomb() VIRTUAL address, but every consumer of
	 * v_baseAddr on this path treats it as physical:
	 *  - initialize_screen() (osfmk/console/video_console.c:2902-2906)
	 *    maps it itself with io_map_spec() whenever kernel_map is still
	 *    NULL -- which it is when arm_init() calls PE_create_console() --
	 *    so it was io-mapping a kernel VA as if it were a PA (visible in
	 *    the boot log as "initialize_screen: b=FFFFFFF0...") and drawing
	 *    into the wrong memory. Likely the real cause of the "shows
	 *    blank" note at arm_init.c's hdmi_console gate.
	 *  - IOBootFramebuffer::getApertureRange() builds an IODeviceMemory
	 *    from it (IOGraphics IOBootFramebuffer.cpp:236).
	 * That is also what a real boot loader passes in boot_args->Video,
	 * which PE_init_platform() copies verbatim (this file, :676). */
	video->v_baseAddr = fbPhysAddr;
	video->v_length = fbSize;
	video->v_rowBytes = fbPitch;
	/* The property-tag interface overwrites each tag's value words with
	 * what the firmware actually set, so a size it adjusted is reported
	 * here; fall back to the request if a word came back zero. */
	uint32_t gotW = b[kMsgIdxPhysW];
	uint32_t gotH = b[kMsgIdxPhysH];
	if (gotW == 0 || gotH == 0) {
		gotW = reqW;
		gotH = reqH;
	}
	kprintf("bcm2837_video_init: %ux%u requested, %ux%u granted, pitch %u\n",
	    reqW, reqH, gotW, gotH, fbPitch);
	video->v_width = gotW;
	video->v_height = gotH;
	video->v_depth = BCM2837_FB_DEPTH;
	/* 0 -> PE_create_console() picks kPETextMode, so kPEAcquireScreen
	 * (kern/startup.c:721) runs gc_enable(TRUE) and the framebuffer
	 * becomes a text console (video_console.c:2989-3024). It used to be
	 * 1 (kPEGraphicsMode), which only ever arms the boot progress
	 * spinner -- and runvm.sh passes -noprogress -- so nothing was ever
	 * drawn. */
	video->v_display = 0;
	return TRUE;
}

void
PE_init_platform(boolean_t vm_initialized, void *args)
{
	DTEntry         entry;
	unsigned int    size;
	void * const    *prop;
	boot_args      *boot_args_ptr = (boot_args *) args;

	if (PE_state.initialized == FALSE) {
		PE_state.initialized = TRUE;
		PE_state.bootArgs = boot_args_ptr;
		PE_state.deviceTreeHead = boot_args_ptr->deviceTreeP;
		PE_state.deviceTreeSize = boot_args_ptr->deviceTreeLength;
		PE_state.video.v_baseAddr = boot_args_ptr->Video.v_baseAddr;
		PE_state.video.v_rowBytes = boot_args_ptr->Video.v_rowBytes;
		PE_state.video.v_width = boot_args_ptr->Video.v_width;
		PE_state.video.v_height = boot_args_ptr->Video.v_height;
		PE_state.video.v_depth = (boot_args_ptr->Video.v_depth >> kBootVideoDepthDepthShift) & kBootVideoDepthMask;
		PE_state.video.v_rotate = (boot_args_ptr->Video.v_depth >> kBootVideoDepthRotateShift) & kBootVideoDepthMask;
		PE_state.video.v_scale = ((boot_args_ptr->Video.v_depth >> kBootVideoDepthScaleShift) & kBootVideoDepthMask) + 1;
		PE_state.video.v_display = boot_args_ptr->Video.v_display;
		strlcpy(PE_state.video.v_pixelFormat, "BBBBBBBBGGGGGGGGRRRRRRRR", sizeof(PE_state.video.v_pixelFormat));
	}
	if (!vm_initialized) {
		/*
		 * Setup the Device Tree routines
		 * so the console can be found and the right I/O space
		 * can be used..
		 */
		SecureDTInit(PE_state.deviceTreeHead, PE_state.deviceTreeSize);
		pe_identify_machine(boot_args_ptr);
	} else {
		pe_arm_init_interrupts(args);
		pe_arm_init_debug(args);
	}

	if (!vm_initialized) {
		if (kSuccess == (SecureDTFindEntry("name", "device-tree", &entry))) {
			if (kSuccess == SecureDTGetProperty(entry, "target-type",
			    (void const **)&prop, &size)) {
				if (size > sizeof(gTargetTypeBuffer)) {
					size = sizeof(gTargetTypeBuffer);
				}
				bcopy(prop, gTargetTypeBuffer, size);
				gTargetTypeBuffer[size - 1] = '\0';
			}
		}
		if (kSuccess == (SecureDTFindEntry("name", "device-tree", &entry))) {
			if (kSuccess == SecureDTGetProperty(entry, "model",
			    (void const **)&prop, &size)) {
				if (size > sizeof(gModelTypeBuffer)) {
					size = sizeof(gModelTypeBuffer);
				}
				bcopy(prop, gModelTypeBuffer, size);
				gModelTypeBuffer[size - 1] = '\0';
			}
		}
		if (kSuccess == SecureDTLookupEntry(NULL, "/chosen", &entry)) {
			if (kSuccess == SecureDTGetProperty(entry, "debug-enabled",
			    (void const **) &prop, &size)) {
				/*
				 * We purposefully modify a constified variable as
				 * it will get locked down by a trusted monitor or
				 * via page table mappings. We don't want people easily
				 * modifying this variable...
				 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
				boolean_t *modify_debug_enabled = (boolean_t *) &debug_enabled;
				if (size > sizeof(uint32_t)) {
					size = sizeof(uint32_t);
				}
				bcopy(prop, modify_debug_enabled, size);
#pragma clang diagnostic pop
			}
			if (kSuccess == SecureDTGetProperty(entry, "firmware-version",
			    (void const **) &prop, &size)) {
				if (size > sizeof(firmware_version)) {
					size = sizeof(firmware_version);
				}
				bcopy(prop, firmware_version, size);
				firmware_version[size - 1] = '\0';
			}
			if (kSuccess == SecureDTGetProperty(entry, "unique-chip-id",
			    (void const **) &prop, &size)) {
				if (size > sizeof(gPlatformECID)) {
					size = sizeof(gPlatformECID);
				}
				bcopy(prop, gPlatformECID, size);
			}
			if (kSuccess == SecureDTGetProperty(entry, "dram-vendor-id",
			    (void const **) &prop, &size)) {
				if (size > sizeof(gPlatformMemoryID)) {
					size = sizeof(gPlatformMemoryID);
				}
				bcopy(prop, &gPlatformMemoryID, size);
			}
		}
		pe_init_debug();
	}
}

void
PE_create_console(void)
{
	/*
	 * Check the head of VRAM for a panic log saved on last panic.
	 * Do this before the VRAM is trashed.
	 */
	check_for_panic_log();

	if (PE_state.video.v_display) {
		PE_initialize_console(&PE_state.video, kPEGraphicsMode);
	} else {
		PE_initialize_console(&PE_state.video, kPETextMode);
	}
}

int
PE_current_console(PE_Video * info)
{
	*info = PE_state.video;
	return 0;
}

void
PE_display_icon(__unused unsigned int flags, __unused const char *name)
{
	if (default_noroot_data) {
		vc_display_icon(&default_noroot, default_noroot_data);
	}
}

extern          boolean_t
PE_get_hotkey(__unused unsigned char key)
{
	return FALSE;
}

static timebase_callback_func gTimebaseCallback;

void
PE_register_timebase_callback(timebase_callback_func callback)
{
	gTimebaseCallback = callback;

	PE_call_timebase_callback();
}

void
PE_call_timebase_callback(void)
{
	struct timebase_freq_t timebase_freq;

	timebase_freq.timebase_num = gPEClockFrequencyInfo.timebase_frequency_hz;
	timebase_freq.timebase_den = 1;

	if (gTimebaseCallback) {
		gTimebaseCallback(&timebase_freq);
	}
}

/*
 * The default PE_poll_input handler.
 */
int
PE_stub_poll_input(__unused unsigned int options, char *c)
{
	*c = (char)uart_getc();
	return 0;               /* 0 for success, 1 for unsupported */
}

/*
 * This routine will return 1 if you are running on a device with a variant
 * of iBoot that allows debugging. This is typically not the case on production
 * fused parts (even when running development variants of iBoot).
 *
 * The routine takes an optional argument of the flags passed to debug="" so
 * kexts don't have to parse the boot arg themselves.
 */
uint32_t
PE_i_can_has_debugger(uint32_t *debug_flags)
{
	if (debug_flags) {
#if DEVELOPMENT || DEBUG
		assert(startup_phase >= STARTUP_SUB_TUNABLES);
#endif
		if (debug_enabled) {
			*debug_flags = debug_boot_arg;
		} else {
			*debug_flags = 0;
		}
	}
	return debug_enabled;
}

/*
 * This routine returns TRUE if the device is configured
 * with panic debugging enabled.
 */
boolean_t
PE_panic_debugging_enabled()
{
	return panicDebugging;
}

void
PE_save_buffer_to_vram(unsigned char *buf, unsigned int *size)
{
	if (!panic_info || !size) {
		return;
	}

	if (!buf) {
		*size = panic_text_len;
		return;
	}

	if (*size == 0) {
		return;
	}

	*size = *size > panic_text_len ? panic_text_len : *size;
	if (panic_info->eph_magic != EMBEDDED_PANIC_MAGIC) {
		printf("Error!! Current Magic 0x%X, expected value 0x%x", panic_info->eph_magic, EMBEDDED_PANIC_MAGIC);
	}

	/* CRC everything after the CRC itself - starting with the panic header version */
	panic_info->eph_crc = crc32(0L, &panic_info->eph_version, (panic_text_len +
	    sizeof(struct embedded_panic_header) - offsetof(struct embedded_panic_header, eph_version)));
}

uint32_t
PE_get_offset_into_panic_region(char *location)
{
	assert(gPanicBase != 0);
	assert(location >= (char *) gPanicBase);
	assert((unsigned int)(location - gPanicBase) < gPanicSize);

	return (uint32_t)(uintptr_t)(location - gPanicBase);
}

void
PE_init_panicheader()
{
	if (!panic_info) {
		return;
	}

	bzero(panic_info, sizeof(struct embedded_panic_header));

	/*
	 * The panic log begins immediately after the panic header -- debugger synchronization and other functions
	 * may log into this region before we've become the exclusive panicking CPU and initialize the header here.
	 */
	panic_info->eph_panic_log_offset = debug_buf_base ? PE_get_offset_into_panic_region(debug_buf_base) : 0;

	panic_info->eph_magic = EMBEDDED_PANIC_MAGIC;
	panic_info->eph_version = EMBEDDED_PANIC_HEADER_CURRENT_VERSION;

	return;
}

/*
 * Tries to update the panic header to keep it consistent on nested panics.
 *
 * NOTE: The purpose of this function is NOT to detect/correct corruption in the panic region,
 *       it is to update the panic header to make it consistent when we nest panics.
 */
void
PE_update_panicheader_nestedpanic()
{
	if (!panic_info) {
		return;
	}

	/*
	 * If the panic log offset is not set, re-init the panic header
	 */
	if (panic_info->eph_panic_log_offset == 0) {
		PE_init_panicheader();
		panic_info->eph_panic_flags |= EMBEDDED_PANIC_HEADER_FLAG_NESTED_PANIC;
		return;
	}

	panic_info->eph_panic_flags |= EMBEDDED_PANIC_HEADER_FLAG_NESTED_PANIC;

	/*
	 * If the panic log length is not set, set the end to
	 * the current location of the debug_buf_ptr to close it.
	 */
	if (panic_info->eph_panic_log_len == 0) {
		panic_info->eph_panic_log_len = PE_get_offset_into_panic_region(debug_buf_ptr);

		/* If this assert fires, it's indicative of corruption in the panic region */
		assert(panic_info->eph_other_log_offset == panic_info->eph_other_log_len == 0);
	}

	/* If this assert fires, it's likely indicative of corruption in the panic region */
	assert(((panic_info->eph_stackshot_offset == 0) && (panic_info->eph_stackshot_len == 0)) ||
	    ((panic_info->eph_stackshot_offset != 0) && (panic_info->eph_stackshot_len != 0)));

	/*
	 * If we haven't set up the other log yet, set the beginning of the other log
	 * to the current location of the debug_buf_ptr
	 */
	if (panic_info->eph_other_log_offset == 0) {
		panic_info->eph_other_log_offset = PE_get_offset_into_panic_region(debug_buf_ptr);

		/* If this assert fires, it's indicative of corruption in the panic region */
		assert(panic_info->eph_other_log_len == 0);
	}

	return;
}

boolean_t
PE_reboot_on_panic(void)
{
	uint32_t debug_flags;

	if (PE_i_can_has_debugger(&debug_flags)
	    && (debug_flags & DB_NMI)) {
		/* kernel debugging is active */
		return FALSE;
	} else {
		return TRUE;
	}
}

void
PE_sync_panic_buffers(void)
{
	/*
	 * rdar://problem/26453070:
	 * The iBoot panic region is write-combined on arm64.  We must flush dirty lines
	 * from L1/L2 as late as possible before reset, with no further reads of the panic
	 * region between the flush and the reset.  Some targets have an additional memcache (L3),
	 * and a read may bring dirty lines out of L3 and back into L1/L2, causing the lines to
	 * be discarded on reset.  If we can make sure the lines are flushed to L3/DRAM,
	 * the platform reset handler will flush any L3.
	 */
	if (gPanicBase) {
		CleanPoC_DcacheRegion_Force(gPanicBase, gPanicSize);
	}
}

static void
pe_prepare_images(void)
{
	if ((1 & PE_state.video.v_rotate) != 0) {
		// Only square square images with radial symmetry are supported
		// No need to actually rotate the data

		// Swap the dx and dy offsets
		uint32_t tmp = default_progress.dx;
		default_progress.dx = default_progress.dy;
		default_progress.dy = tmp;
	}
#if 0
	uint32_t cnt, cnt2, cnt3, cnt4;
	uint32_t tmp, width, height;
	uint8_t  data, *new_data;
	const uint8_t *old_data;

	width  = default_progress.width;
	height = default_progress.height * default_progress.count;

	// Scale images if the UI is being scaled
	if (PE_state.video.v_scale > 1) {
		new_data = kalloc(width * height * scale * scale);
		if (new_data != 0) {
			old_data = default_progress_data;
			default_progress_data = new_data;
			for (cnt = 0; cnt < height; cnt++) {
				for (cnt2 = 0; cnt2 < width; cnt2++) {
					data = *(old_data++);
					for (cnt3 = 0; cnt3 < scale; cnt3++) {
						for (cnt4 = 0; cnt4 < scale; cnt4++) {
							new_data[width * scale * cnt3 + cnt4] = data;
						}
					}
					new_data += scale;
				}
				new_data += width * scale * (scale - 1);
			}
			default_progress.width  *= scale;
			default_progress.height *= scale;
			default_progress.dx     *= scale;
			default_progress.dy     *= scale;
		}
	}
#endif
}

void
PE_mark_hwaccess(uint64_t thread)
{
	last_hwaccess_thread = thread;
	asm volatile ("dmb ish");
}
