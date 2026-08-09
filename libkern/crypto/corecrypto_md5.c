/*
 * corecrypto_md5.c - standalone MD5, replacing this file's original
 * corecrypto-dispatch implementation for xnu-on-rpi3.
 *
 * Same situation as libkern/crypto/corecrypto_sha2.c (see that file's
 * header comment for the full explanation): every function here
 * originally indirected through g_crypto_funcs (libkern/crypto/
 * register_crypto.c), a function table only ever populated by real
 * macOS's corecrypto kext - never open-sourced, and never registered in
 * this from-scratch kernel (no kext-loading infrastructure at all).
 * First real caller found: msdosfs_generate_volume_uuid()
 * (bsd/msdosfs/msdosfs_vfsops.c), used while mounting root - null
 * pointer dereference via g_crypto_funcs->ccmd5_di.
 *
 * MD5_CTX (libkern/libkern/crypto/md5.h) has real, named fields (the
 * classic RSA reference implementation layout: state[4]/count[2]/
 * buffer[64]) rather than an opaque corecrypto-sized buffer like
 * SHA256_CTX, so this is a direct, standard RFC 1321 implementation
 * against that exact struct.
 */

#include <libkern/crypto/md5.h>
#include <libkern/libkern.h>
#include <string.h>

static const uint8_t PADDING[64] = { 0x80, /* rest is zero */ };

static inline uint32_t
rotl32(uint32_t x, int n)
{
	return (x << n) | (x >> (32 - n));
}

#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))

#define STEP(f, a, b, c, d, x, t, s) \
	(a) = rotl32((a) + f((b), (c), (d)) + (x) + (t), (s)) + (b)

static const uint32_t K[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static const int Sshift[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

static void
md5_compress(MD5_CTX *ctx, const uint8_t block[64])
{
	uint32_t x[16];
	for (int i = 0; i < 16; i++) {
		x[i] = (uint32_t)block[i * 4] |
		    ((uint32_t)block[i * 4 + 1] << 8) |
		    ((uint32_t)block[i * 4 + 2] << 16) |
		    ((uint32_t)block[i * 4 + 3] << 24);
	}

	uint32_t a = ctx->state[0], b = ctx->state[1];
	uint32_t c = ctx->state[2], d = ctx->state[3];

	for (int i = 0; i < 64; i++) {
		uint32_t f;
		int g;
		if (i < 16) {
			f = F(b, c, d);
			g = i;
		} else if (i < 32) {
			f = G(b, c, d);
			g = (5 * i + 1) % 16;
		} else if (i < 48) {
			f = H(b, c, d);
			g = (3 * i + 5) % 16;
		} else {
			f = I(b, c, d);
			g = (7 * i) % 16;
		}
		uint32_t temp = d;
		d = c;
		c = b;
		b = rotl32(a + f + K[i] + x[g], Sshift[i]) + b;
		a = temp;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
}

void
MD5Init(MD5_CTX *ctx)
{
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
	ctx->count[0] = 0;
	ctx->count[1] = 0;
}

void
MD5Update(MD5_CTX *ctx, const void *data, unsigned int len)
{
	const uint8_t *p = (const uint8_t *)data;

	/* bytes already buffered, derived from bit count so far */
	unsigned int have = (unsigned int)((ctx->count[0] >> 3) & 0x3F);
	unsigned int need = 64 - have;

	uint32_t addbits = (uint32_t)len << 3;
	ctx->count[0] += addbits;
	if (ctx->count[0] < addbits) {
		ctx->count[1]++; /* carry */
	}
	ctx->count[1] += (uint32_t)((uint64_t)len >> 29);

	unsigned int off = 0;
	if (len >= need) {
		if (have) {
			memcpy(ctx->buffer + have, p, need);
			md5_compress(ctx, ctx->buffer);
			off = need;
			have = 0;
		}
		while (off + 64 <= len) {
			md5_compress(ctx, p + off);
			off += 64;
		}
	}
	if (off < len) {
		memcpy(ctx->buffer + have, p + off, len - off);
	}
}

void
MD5Final(unsigned char digest[MD5_DIGEST_LENGTH], MD5_CTX *ctx)
{
	uint32_t bits0 = ctx->count[0];
	uint32_t bits1 = ctx->count[1];

	unsigned int have = (unsigned int)((ctx->count[0] >> 3) & 0x3F);
	unsigned int padlen = (have < 56) ? (56 - have) : (120 - have);

	MD5Update(ctx, PADDING, padlen);

	uint8_t lenbuf[8];
	lenbuf[0] = (uint8_t)bits0; lenbuf[1] = (uint8_t)(bits0 >> 8);
	lenbuf[2] = (uint8_t)(bits0 >> 16); lenbuf[3] = (uint8_t)(bits0 >> 24);
	lenbuf[4] = (uint8_t)bits1; lenbuf[5] = (uint8_t)(bits1 >> 8);
	lenbuf[6] = (uint8_t)(bits1 >> 16); lenbuf[7] = (uint8_t)(bits1 >> 24);
	MD5Update(ctx, lenbuf, 8);

	for (int i = 0; i < 4; i++) {
		digest[i * 4] = (uint8_t)ctx->state[i];
		digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 8);
		digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 16);
		digest[i * 4 + 3] = (uint8_t)(ctx->state[i] >> 24);
	}
}
