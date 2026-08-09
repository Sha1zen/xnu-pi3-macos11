/*
 * corecrypto_sha1.c - standalone SHA-1, replacing this file's original
 * corecrypto-dispatch implementation for xnu-on-rpi3.
 *
 * Same situation as corecrypto_sha2.c/corecrypto_md5.c in this directory
 * (see corecrypto_sha2.c's header comment for the full explanation) -
 * g_crypto_funcs is never populated in this from-scratch kernel (no
 * kext-loading infrastructure, and real macOS's corecrypto kext was
 * never open-sourced). Fixed proactively alongside MD5 (found via
 * msdosfs_generate_volume_uuid()) since SHA-1 is a similarly common
 * dependency likely to be hit by the next thing exercised for the
 * first time.
 *
 * SHA1_CTX (libkern/libkern/crypto/sha1.h) has real, named union fields
 * (h/c/m), not an opaque corecrypto-sized buffer, so this is a direct
 * standard RFC 3174 implementation against that exact struct. Note the
 * bit count (c.b64[0]) is msb-first per this header's own comment,
 * unlike MD5's lsb-first count - handled directly as a plain uint64_t
 * here since native byte order doesn't matter for a same-process
 * counter, only the final big-endian serialization into the padding
 * block does.
 */

#include <sys/types.h>
#include <libkern/crypto/sha1.h>
#include <libkern/libkern.h>
#include <string.h>

static inline uint32_t
rotl32(uint32_t x, int n)
{
	return (x << n) | (x >> (32 - n));
}

static void
sha1_compress(SHA1_CTX *ctx, const uint8_t block[64])
{
	uint32_t w[80];
	for (int i = 0; i < 16; i++) {
		w[i] = ((uint32_t)block[i * 4] << 24) |
		    ((uint32_t)block[i * 4 + 1] << 16) |
		    ((uint32_t)block[i * 4 + 2] << 8) |
		    (uint32_t)block[i * 4 + 3];
	}
	for (int i = 16; i < 80; i++) {
		w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
	}

	uint32_t a = ctx->h.b32[0], b = ctx->h.b32[1], c = ctx->h.b32[2];
	uint32_t d = ctx->h.b32[3], e = ctx->h.b32[4];

	for (int i = 0; i < 80; i++) {
		uint32_t f, k;
		if (i < 20) {
			f = (b & c) | (~b & d);
			k = 0x5A827999;
		} else if (i < 40) {
			f = b ^ c ^ d;
			k = 0x6ED9EBA1;
		} else if (i < 60) {
			f = (b & c) | (b & d) | (c & d);
			k = 0x8F1BBCDC;
		} else {
			f = b ^ c ^ d;
			k = 0xCA62C1D6;
		}
		uint32_t temp = rotl32(a, 5) + f + e + k + w[i];
		e = d; d = c; c = rotl32(b, 30); b = a; a = temp;
	}

	ctx->h.b32[0] += a;
	ctx->h.b32[1] += b;
	ctx->h.b32[2] += c;
	ctx->h.b32[3] += d;
	ctx->h.b32[4] += e;
}

void
SHA1Init(SHA1_CTX *ctx)
{
	ctx->h.b32[0] = 0x67452301;
	ctx->h.b32[1] = 0xEFCDAB89;
	ctx->h.b32[2] = 0x98BADCFE;
	ctx->h.b32[3] = 0x10325476;
	ctx->h.b32[4] = 0xC3D2E1F0;
	ctx->c.b64[0] = 0; /* total bits processed so far */
}

void
SHA1Update(SHA1_CTX *ctx, const void *data, size_t len)
{
	const uint8_t *p = (const uint8_t *)data;
	uint64_t bits_so_far = ctx->c.b64[0];
	unsigned int have = (unsigned int)((bits_so_far >> 3) & 0x3F);

	ctx->c.b64[0] = bits_so_far + ((uint64_t)len << 3);

	unsigned int off = 0;
	if (have) {
		unsigned int need = 64 - have;
		unsigned int take = (len < need) ? (unsigned int)len : need;
		memcpy(ctx->m.b8 + have, p, take);
		off += take;
		if (have + take == 64) {
			sha1_compress(ctx, ctx->m.b8);
			have = 0;
		} else {
			return;
		}
	}

	while (off + 64 <= len) {
		sha1_compress(ctx, p + off);
		off += 64;
	}

	if (off < len) {
		memcpy(ctx->m.b8, p + off, len - off);
	}
}

void
SHA1Final(void *digest, SHA1_CTX *ctx)
{
	uint64_t bits = ctx->c.b64[0];
	unsigned int have = (unsigned int)((bits >> 3) & 0x3F);

	uint8_t pad = 0x80;
	SHA1Update(ctx, &pad, 1);

	uint8_t zero = 0;
	have = (unsigned int)((ctx->c.b64[0] >> 3) & 0x3F);
	while (have != 56) {
		SHA1Update(ctx, &zero, 1);
		have = (unsigned int)((ctx->c.b64[0] >> 3) & 0x3F);
	}

	uint8_t lenbuf[8];
	for (int i = 0; i < 8; i++) {
		lenbuf[i] = (uint8_t)(bits >> (56 - i * 8));
	}
	/* append directly - bypass Update's bit-count math for the length block itself */
	memcpy(ctx->m.b8 + 56, lenbuf, 8);
	sha1_compress(ctx, ctx->m.b8);

	uint8_t *out = (uint8_t *)digest;
	for (int i = 0; i < 5; i++) {
		out[i * 4] = (uint8_t)(ctx->h.b32[i] >> 24);
		out[i * 4 + 1] = (uint8_t)(ctx->h.b32[i] >> 16);
		out[i * 4 + 2] = (uint8_t)(ctx->h.b32[i] >> 8);
		out[i * 4 + 3] = (uint8_t)ctx->h.b32[i];
	}
}

#ifdef XNU_KERNEL_PRIVATE
void
SHA1UpdateUsePhysicalAddress(SHA1_CTX *ctx, const void *data, size_t len)
{
	SHA1Update(ctx, data, len);
}
#endif

/* This is not publicised in header, but exported in libkern.exports */
void SHA1Final_r(SHA1_CTX *context, void *digest);
void
SHA1Final_r(SHA1_CTX *context, void *digest)
{
	SHA1Final(digest, context);
}

/*
 * This function is called by the SHA1 hardware kext during its init.
 * This will register the function to call to perform SHA1 using hardware.
 * No such kext exists in this project - left as a real, harmless stub
 * matching the original file (nothing calls sha1_hardware_hook here).
 */
#include <sys/types.h>
#include <libkern/OSAtomic.h>
#include <sys/systm.h>

typedef kern_return_t (*InKernelPerformSHA1Func)(void *ref, const void *data, size_t dataLen, u_int32_t *inHash, u_int32_t options, u_int32_t *outHash, Boolean usePhysicalAddress);
void sha1_hardware_hook(Boolean option, InKernelPerformSHA1Func func, void *ref);
static void *SHA1Ref;
static InKernelPerformSHA1Func performSHA1WithinKernelOnly;

void
sha1_hardware_hook(Boolean option, InKernelPerformSHA1Func func, void *ref)
{
	if (option) {
		OSCompareAndSwapPtr((void*)NULL, (void*)ref, (void * volatile*)&SHA1Ref);

		if (!OSCompareAndSwapPtr((void *)NULL, (void *)func, (void * volatile *)&performSHA1WithinKernelOnly)) {
			panic("sha1_hardware_hook: Called twice.. Should never happen\n");
		}
	} else {
		performSHA1WithinKernelOnly = NULL;
		SHA1Ref = NULL;
	}
}
