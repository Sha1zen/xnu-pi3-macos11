/*
 * corecrypto_aes_register.c - real AES core for xnu-on-rpi3, closing
 * docs/backlog.md item 0a ("No AES implementation exists anywhere in
 * this kernel").
 *
 * g_crypto_funcs (libkern/crypto/register_crypto.c) is a table of
 * function pointers that real macOS's closed-source corecrypto kext
 * fills in via register_crypto_functions(). This kernel loads no kexts
 * at all, so the table stayed permanently NULL and every AES consumer
 * (tcp_tfo_init, bsd/nfs/gss/ccrypto.c) faulted or degraded. corecrypto
 * itself is confirmed absent from apple-oss-distributions (searched,
 * zero repos) - this project's documented fallback is FreeBSD, whose
 * sys/crypto/rijndael/ is self-contained and cleanly licensed (public
 * domain - Rijmen/Bosselaers/Barreto, the AES designers themselves,
 * cleaner than the PureDarwin/corecrypto AES core scoped-but-unused
 * 2026-08-27, which had three conflicting license attributions).
 *
 * This file is the corecrypto-shaped adapter: struct ccmode_ecb/cbc/ctr
 * instances (EXTERNAL_HEADERS/corecrypto/ccmode_impl.h) wired to the
 * vendored freebsd/rijndael-alg-fst.c block cipher core, plus the
 * boot-time register_crypto_functions() call. Only the AES fields are
 * filled in; every other g_crypto_funcs slot (digests, DES, RSA, GCM,
 * ChaCha20-Poly1305, rng) stays NULL exactly as before - existing
 * callers already null-check before use (see corecrypto_aes.c's
 * aes_encrypt_key(), the original guard added 2026-08-21), and real
 * consumers of those other slots either have their own from-scratch
 * replacement already (SHA-256/MD5) or don't exist in this tree yet.
 *
 * Context sizing: libkern/libkern/crypto/aes.h's AES_CBC_CTX_MAX_SIZE
 * (~280 bytes, rounded to 288 by cccbc_ctx's 16-byte alignment) is a
 * hardcoded budget baked into the aes_encrypt_ctx/aes_decrypt_ctx
 * typedefs used throughout the kernel - our struct aes_block_ctx (one
 * key-schedule direction: an int plus 4*(Nr+1) 32-bit words, <= 244
 * bytes for AES-256) fits with room to spare. ECB and CTR aren't
 * constrained by that legacy budget (nothing in this tree embeds their
 * context types inline), so their .size fields are exactly
 * sizeof(struct aes_block_ctx) / sizeof(struct aes_ctr_ctx).
 */

#include <libkern/crypto/crypto_internal.h>
#include <libkern/crypto/register_crypto.h>
#include <libkern/libkern.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccaes.h>
#include <kern/debug.h>
#include <string.h>

#include "freebsd/rijndael.h"
#include "freebsd/rijndael_local.h"

/* ================= shared AES-ECB block-cipher context ================= */

struct aes_block_ctx {
	int      Nr;
	uint32_t rk[4 * (RIJNDAEL_MAXNR + 1)];
} __attribute__((aligned(16)));

static int
aes_key_bits(size_t key_nbytes, int *bits_out)
{
	switch (key_nbytes) {
	case 16: *bits_out = 128; return 0;
	case 24: *bits_out = 192; return 0;
	case 32: *bits_out = 256; return 0;
	default: return -1;
	}
}

static int
aes_block_init_enc(const struct ccmode_ecb *ecb __unused, ccecb_ctx *ctx,
    size_t key_nbytes, const void *key)
{
	struct aes_block_ctx *bc = (struct aes_block_ctx *)(void *)ctx;
	int bits;
	if (aes_key_bits(key_nbytes, &bits)) {
		return -1;
	}
	bc->Nr = rijndaelKeySetupEnc(bc->rk, key, bits);
	return 0;
}

static int
aes_block_init_dec(const struct ccmode_ecb *ecb __unused, ccecb_ctx *ctx,
    size_t key_nbytes, const void *key)
{
	struct aes_block_ctx *bc = (struct aes_block_ctx *)(void *)ctx;
	int bits;
	if (aes_key_bits(key_nbytes, &bits)) {
		return -1;
	}
	bc->Nr = rijndaelKeySetupDec(bc->rk, key, bits);
	return 0;
}

static int
aes_ecb_crypt_enc(const ccecb_ctx *ctx, size_t nblocks, const void *in, void *out)
{
	const struct aes_block_ctx *bc = (const struct aes_block_ctx *)(const void *)ctx;
	const uint8_t *src = in;
	uint8_t *dst = out;
	for (size_t i = 0; i < nblocks; i++) {
		rijndaelEncrypt(bc->rk, bc->Nr, src, dst);
		src += 16;
		dst += 16;
	}
	return 0;
}

static int
aes_ecb_crypt_dec(const ccecb_ctx *ctx, size_t nblocks, const void *in, void *out)
{
	const struct aes_block_ctx *bc = (const struct aes_block_ctx *)(const void *)ctx;
	const uint8_t *src = in;
	uint8_t *dst = out;
	for (size_t i = 0; i < nblocks; i++) {
		rijndaelDecrypt(bc->rk, bc->Nr, src, dst);
		src += 16;
		dst += 16;
	}
	return 0;
}

static const struct ccmode_ecb aes_ecb_encrypt_mode = {
	.size = sizeof(struct aes_block_ctx),
	.block_size = 16,
	.init = aes_block_init_enc,
	.ecb = aes_ecb_crypt_enc,
};

static const struct ccmode_ecb aes_ecb_decrypt_mode = {
	.size = sizeof(struct aes_block_ctx),
	.block_size = 16,
	.init = aes_block_init_dec,
	.ecb = aes_ecb_crypt_dec,
};

/* ================= AES-CBC ================= */

static int
aes_cbc_init_enc(const struct ccmode_cbc *cbc __unused, cccbc_ctx *ctx,
    size_t key_len, const void *key)
{
	struct aes_block_ctx *bc = (struct aes_block_ctx *)(void *)ctx;
	int bits;
	if (aes_key_bits(key_len, &bits)) {
		return -1;
	}
	bc->Nr = rijndaelKeySetupEnc(bc->rk, key, bits);
	return 0;
}

static int
aes_cbc_init_dec(const struct ccmode_cbc *cbc __unused, cccbc_ctx *ctx,
    size_t key_len, const void *key)
{
	struct aes_block_ctx *bc = (struct aes_block_ctx *)(void *)ctx;
	int bits;
	if (aes_key_bits(key_len, &bits)) {
		return -1;
	}
	bc->Nr = rijndaelKeySetupDec(bc->rk, key, bits);
	return 0;
}

static int
aes_cbc_crypt_enc(const cccbc_ctx *ctx, cccbc_iv *iv, size_t nblocks, const void *in, void *out)
{
	const struct aes_block_ctx *bc = (const struct aes_block_ctx *)(const void *)ctx;
	uint8_t *ivb = (uint8_t *)(void *)iv;
	const uint8_t *src = in;
	uint8_t *dst = out;
	uint8_t block[16];

	for (size_t i = 0; i < nblocks; i++) {
		for (int j = 0; j < 16; j++) {
			block[j] = src[j] ^ ivb[j];
		}
		rijndaelEncrypt(bc->rk, bc->Nr, block, dst);
		memcpy(ivb, dst, 16);
		src += 16;
		dst += 16;
	}
	return 0;
}

static int
aes_cbc_crypt_dec(const cccbc_ctx *ctx, cccbc_iv *iv, size_t nblocks, const void *in, void *out)
{
	const struct aes_block_ctx *bc = (const struct aes_block_ctx *)(const void *)ctx;
	uint8_t *ivb = (uint8_t *)(void *)iv;
	const uint8_t *src = in;
	uint8_t *dst = out;
	uint8_t plain[16];
	uint8_t prev_ct[16];

	for (size_t i = 0; i < nblocks; i++) {
		memcpy(prev_ct, src, 16); /* save before a possible in-place out==in overwrite */
		rijndaelDecrypt(bc->rk, bc->Nr, src, plain);
		for (int j = 0; j < 16; j++) {
			dst[j] = plain[j] ^ ivb[j];
		}
		memcpy(ivb, prev_ct, 16);
		src += 16;
		dst += 16;
	}
	return 0;
}

static const struct ccmode_cbc aes_cbc_encrypt_mode = {
	.size = sizeof(struct aes_block_ctx),
	.block_size = 16,
	.init = aes_cbc_init_enc,
	.cbc = aes_cbc_crypt_enc,
	.custom = NULL,
};

static const struct ccmode_cbc aes_cbc_decrypt_mode = {
	.size = sizeof(struct aes_block_ctx),
	.block_size = 16,
	.init = aes_cbc_init_dec,
	.cbc = aes_cbc_crypt_dec,
	.custom = NULL,
};

/* ================= AES-CTR =================
 *
 * CTR mode only ever runs the forward cipher (the counter block is
 * encrypted and XORed with plain/ciphertext either direction), so
 * there is exactly one context type for both ccaes_ctr_crypt directions
 * - matching corecrypto's own ccmode_ctr shape, which likewise has no
 * decrypt/encrypt split (see EXTERNAL_HEADERS/corecrypto/ccmode_impl.h).
 * Big-endian 128-bit counter increment (the standard AES-CTR/RFC 3686
 * convention OpenSSH's aes128-ctr/aes256-ctr also use) - no in-kernel
 * consumer exists yet (grep confirms zero ccaes_ctr_crypt references in
 * this tree), this is registered for interface completeness per
 * docs/backlog.md item 0a's scoped plan, not exercised today.
 */

struct aes_ctr_ctx {
	int      Nr;
	uint32_t rk[4 * (RIJNDAEL_MAXNR + 1)];
	uint8_t  counter[16];
	uint8_t  keystream[16];
	size_t   keystream_used; /* 0..16; 16 means "keystream exhausted" */
} __attribute__((aligned(16)));

static void
aes_ctr_increment(uint8_t counter[16])
{
	for (int i = 15; i >= 0; i--) {
		if (++counter[i] != 0) {
			break;
		}
	}
}

static int
aes_ctr_init(const struct ccmode_ctr *mode __unused, ccctr_ctx *ctx,
    size_t key_len, const void *key, const void *iv)
{
	struct aes_ctr_ctx *cc = (struct aes_ctr_ctx *)(void *)ctx;
	int bits;
	if (aes_key_bits(key_len, &bits)) {
		return -1;
	}
	cc->Nr = rijndaelKeySetupEnc(cc->rk, key, bits);
	if (iv) {
		memcpy(cc->counter, iv, 16);
	} else {
		memset(cc->counter, 0, 16);
	}
	cc->keystream_used = 16;
	return 0;
}

static int
aes_ctr_setctr(const struct ccmode_ctr *mode __unused, ccctr_ctx *ctx, const void *ctr)
{
	struct aes_ctr_ctx *cc = (struct aes_ctr_ctx *)(void *)ctx;
	memcpy(cc->counter, ctr, 16);
	cc->keystream_used = 16;
	return 0;
}

static int
aes_ctr_crypt(ccctr_ctx *ctx, size_t nbytes, const void *in, void *out)
{
	struct aes_ctr_ctx *cc = (struct aes_ctr_ctx *)(void *)ctx;
	const uint8_t *src = in;
	uint8_t *dst = out;

	for (size_t i = 0; i < nbytes; i++) {
		if (cc->keystream_used == 16) {
			rijndaelEncrypt(cc->rk, cc->Nr, cc->counter, cc->keystream);
			aes_ctr_increment(cc->counter);
			cc->keystream_used = 0;
		}
		dst[i] = src[i] ^ cc->keystream[cc->keystream_used];
		cc->keystream_used++;
	}
	return 0;
}

static const struct ccmode_ctr aes_ctr_mode = {
	.size = sizeof(struct aes_ctr_ctx),
	.block_size = 1, /* corecrypto convention for CTR: stream, not block-restricted */
	.ecb_block_size = 16,
	.init = aes_ctr_init,
	.setctr = aes_ctr_setctr,
	.ctr = aes_ctr_crypt,
	.custom = NULL,
};

/* ================= FIPS-197 / SP 800-38A known-answer self-test =================
 *
 * Runs through the real ccmode_ecb/ccmode_cbc/ccmode_ctr interfaces
 * (not the raw rijndaelEncrypt/Decrypt core directly) so a bug in this
 * file's adapter glue - not just a bug in the vendored core - fails
 * loudly at boot rather than producing silently-wrong ciphertext
 * (docs/backlog.md item 0a's explicit risk callout: "a subtly wrong AES
 * silently produces valid-looking wrong ciphertext -- worse than
 * none"). Vectors are the standard, widely-published NIST test vectors:
 * FIPS-197 Appendix C.1-C.3 (AES-128/192/256 ECB single block) and
 * SP 800-38A Appendix F.2.1/F.5.1 (AES-128 CBC/CTR single block).
 */

static int
aes_kat_ecb(const struct ccmode_ecb *enc, const struct ccmode_ecb *dec,
    const uint8_t *key, size_t key_len, const uint8_t *pt, const uint8_t *ct)
{
	uint8_t buf[16];
	struct aes_block_ctx ctx;

	if (enc->init(enc, (ccecb_ctx *)&ctx, key_len, key) != 0) {
		return -1;
	}
	if (enc->ecb((ccecb_ctx *)&ctx, 1, pt, buf) != 0) {
		return -1;
	}
	if (memcmp(buf, ct, 16) != 0) {
		return -1;
	}

	if (dec->init(dec, (ccecb_ctx *)&ctx, key_len, key) != 0) {
		return -1;
	}
	if (dec->ecb((ccecb_ctx *)&ctx, 1, ct, buf) != 0) {
		return -1;
	}
	if (memcmp(buf, pt, 16) != 0) {
		return -1;
	}
	return 0;
}

static int
aes_kat_cbc128(void)
{
	static const uint8_t key[16] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	};
	static const uint8_t iv[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	};
	static const uint8_t pt[16] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	};
	static const uint8_t ct[16] = {
		0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
		0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
	};
	struct aes_block_ctx ctx;
	uint8_t iv_buf[16], out[16];

	if (aes_cbc_encrypt_mode.init(&aes_cbc_encrypt_mode, (cccbc_ctx *)&ctx, 16, key) != 0) {
		return -1;
	}
	memcpy(iv_buf, iv, 16);
	if (aes_cbc_encrypt_mode.cbc((cccbc_ctx *)&ctx, (cccbc_iv *)iv_buf, 1, pt, out) != 0) {
		return -1;
	}
	if (memcmp(out, ct, 16) != 0) {
		return -1;
	}

	if (aes_cbc_decrypt_mode.init(&aes_cbc_decrypt_mode, (cccbc_ctx *)&ctx, 16, key) != 0) {
		return -1;
	}
	memcpy(iv_buf, iv, 16);
	if (aes_cbc_decrypt_mode.cbc((cccbc_ctx *)&ctx, (cccbc_iv *)iv_buf, 1, ct, out) != 0) {
		return -1;
	}
	if (memcmp(out, pt, 16) != 0) {
		return -1;
	}
	return 0;
}

static int
aes_kat_ctr128(void)
{
	static const uint8_t key[16] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	};
	static const uint8_t counter[16] = {
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
	};
	static const uint8_t pt[16] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	};
	static const uint8_t ct[16] = {
		0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
		0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
	};
	struct aes_ctr_ctx ctx;
	uint8_t out[16];

	if (aes_ctr_mode.init(&aes_ctr_mode, (ccctr_ctx *)&ctx, 16, key, counter) != 0) {
		return -1;
	}
	if (aes_ctr_mode.ctr((ccctr_ctx *)&ctx, 16, pt, out) != 0) {
		return -1;
	}
	if (memcmp(out, ct, 16) != 0) {
		return -1;
	}
	return 0;
}

static int
aes_freebsd_core_self_test(void)
{
	static const uint8_t key128[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	};
	static const uint8_t key192[24] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	};
	static const uint8_t key256[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	};
	static const uint8_t pt[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	};
	static const uint8_t ct128[16] = {
		0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
		0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
	};
	static const uint8_t ct192[16] = {
		0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
		0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
	};
	static const uint8_t ct256[16] = {
		0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
		0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
	};

	if (aes_kat_ecb(&aes_ecb_encrypt_mode, &aes_ecb_decrypt_mode, key128, 16, pt, ct128) != 0) {
		return -1;
	}
	if (aes_kat_ecb(&aes_ecb_encrypt_mode, &aes_ecb_decrypt_mode, key192, 24, pt, ct192) != 0) {
		return -1;
	}
	if (aes_kat_ecb(&aes_ecb_encrypt_mode, &aes_ecb_decrypt_mode, key256, 32, pt, ct256) != 0) {
		return -1;
	}
	if (aes_kat_cbc128() != 0) {
		return -1;
	}
	if (aes_kat_ctr128() != 0) {
		return -1;
	}
	return 0;
}

/* ================= boot-time registration ================= */

static struct crypto_functions aes_only_crypto_funcs = {
	.ccaes_ecb_encrypt = &aes_ecb_encrypt_mode,
	.ccaes_ecb_decrypt = &aes_ecb_decrypt_mode,
	.ccaes_cbc_encrypt = &aes_cbc_encrypt_mode,
	.ccaes_cbc_decrypt = &aes_cbc_decrypt_mode,
	.ccaes_ctr_crypt = &aes_ctr_mode,
	/* every other slot intentionally left NULL - see file header comment */
};

void xnu_rpi3_register_freebsd_aes(void);

void
xnu_rpi3_register_freebsd_aes(void)
{
	if (aes_freebsd_core_self_test() != 0) {
		panic("freebsd AES core failed its FIPS-197 known-answer self-test");
	}
	if (register_crypto_functions(&aes_only_crypto_funcs) != 0) {
		panic("register_crypto_functions() called twice - g_crypto_funcs already set");
	}
}
