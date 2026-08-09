/*
 * TEMP DIAGNOSTIC / COMPAT: genuinely missing from this xnu-7195.81.3
 * opensource release (confirmed: not anywhere in this tree, unlike the
 * newer xnu-latest tree which has a real 254-line version - but that
 * version's macro names have already drifted, e.g. no longer defines
 * IF_PAC_FAST_A_KEY_SWITCHING/HAS_PAC_SLOW_A_KEY_SWITCHING that this
 * vintage's osfmk/arm64/exception_asm.h references, so copying it
 * wholesale wouldn't help). Only consumer in this whole tree is
 * exception_asm.h's single unconditional #include - everything it
 * actually uses from this header (IF_PAC_FAST_A_KEY_SWITCHING) is itself
 * gated behind #if HAS_PAC_SLOW_A_KEY_SWITCHING, which is never defined
 * for BCM2837 (no PAC hardware - see pexpert/pexpert/arm64/BCM2837.h),
 * so an empty stub is sufficient. See project memory for the full
 * porting rationale.
 */
#ifndef _ARM64_PAC_ASM_H_
#define _ARM64_PAC_ASM_H_

#ifndef __ASSEMBLER__
#error "This header should only be used in .s files"
#endif

#endif /* _ARM64_PAC_ASM_H_ */
