/*
 * corecrypto_sha2.c - standalone SHA-256/384/512, replacing this file's
 * original corecrypto-dispatch implementation for xnu-on-rpi3.
 *
 * The original implementation of every function in this file was a thin
 * wrapper indirecting through a global function-table pointer
 * (g_crypto_funcs, libkern/crypto/register_crypto.c) that real macOS's
 * corecrypto kext populates via register_crypto_functions() at boot. That
 * kext's real implementation was never part of any apple-oss-distributions
 * release (same situation as launchd/pthread.kext - see project memory) and
 * nothing in this from-scratch kernel ever calls register_crypto_functions()
 * - g_crypto_funcs stays NULL forever, so every one of these functions
 * dereferenced a null pointer + a small struct-member offset the first time
 * any caller ever exercised them (confirmed via a real fault, FAR=0x30,
 * ESR=0x96000005 - translation fault - inside SHA256_Init, called from
 * vm_kernel_addrhash() by devfs_mount(), the very first real caller in this
 * project's boot history).
 *
 * Rather than stub these out, this is a real, standard, from-scratch
 * SHA-256/384/512 implementation (FIPS 180-4) - these functions are
 * genuinely used for real purposes elsewhere in this kernel (address
 * obfuscation via vm_kernel_addrhash, and likely code-signing-hash-adjacent
 * paths in bsd/kern/ubc_subr.c), not just placeholders.
 *
 * SHA256_CTX/SHA384_CTX/SHA512_CTX (libkern/libkern/crypto/sha2.h) are
 * opaque corecrypto-sized byte buffers (ccdigest_ctx_decl(...)), sized
 * generously enough for real corecrypto internal state - comfortably large
 * enough for the plain state structs below (checked via _Static_assert).
 * Nothing outside this kernel ever consumes these contexts directly, so
 * there's no ABI compatibility requirement with corecrypto's actual layout.
 */

#include <libkern/crypto/sha2.h>
#include <libkern/libkern.h>
#include <string.h>

/* ---- shared big-endian helpers ---- */

static inline uint32_t
load_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void
store_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static inline uint64_t
load_be64(const uint8_t *p)
{
	return ((uint64_t)load_be32(p) << 32) | (uint64_t)load_be32(p + 4);
}

static inline void
store_be64(uint8_t *p, uint64_t v)
{
	store_be32(p, (uint32_t)(v >> 32));
	store_be32(p + 4, (uint32_t)v);
}

/* ================= SHA-256 ================= */

struct sha256_state {
	uint32_t h[8];
	uint64_t total_len; /* bytes processed so far */
	uint8_t  buf[64];
	uint32_t buf_len;
};
_Static_assert(sizeof(struct sha256_state) <= sizeof(SHA256_CTX),
    "sha256_state must fit in SHA256_CTX's opaque buffer");

static const uint32_t sha256_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline uint32_t
rotr32(uint32_t x, int n)
{
	return (x >> n) | (x << (32 - n));
}

static void
sha256_compress(struct sha256_state *st, const uint8_t block[64])
{
	uint32_t w[64];
	for (int i = 0; i < 16; i++) {
		w[i] = load_be32(block + i * 4);
	}
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	uint32_t a = st->h[0], b = st->h[1], c = st->h[2], d = st->h[3];
	uint32_t e = st->h[4], f = st->h[5], g = st->h[6], h = st->h[7];

	for (int i = 0; i < 64; i++) {
		uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
		uint32_t ch = (e & f) ^ (~e & g);
		uint32_t temp1 = h + S1 + ch + sha256_k[i] + w[i];
		uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t temp2 = S0 + maj;

		h = g; g = f; f = e; e = d + temp1;
		d = c; c = b; b = a; a = temp1 + temp2;
	}

	st->h[0] += a; st->h[1] += b; st->h[2] += c; st->h[3] += d;
	st->h[4] += e; st->h[5] += f; st->h[6] += g; st->h[7] += h;
}

void
SHA256_Init(SHA256_CTX *ctx)
{
	struct sha256_state *st = (struct sha256_state *)(void *)ctx;
	st->h[0] = 0x6a09e667; st->h[1] = 0xbb67ae85;
	st->h[2] = 0x3c6ef372; st->h[3] = 0xa54ff53a;
	st->h[4] = 0x510e527f; st->h[5] = 0x9b05688c;
	st->h[6] = 0x1f83d9ab; st->h[7] = 0x5be0cd19;
	st->total_len = 0;
	st->buf_len = 0;
}

void
SHA256_Update(SHA256_CTX *ctx, const void *data, size_t len)
{
	struct sha256_state *st = (struct sha256_state *)(void *)ctx;
	const uint8_t *p = (const uint8_t *)data;

	st->total_len += len;

	if (st->buf_len > 0) {
		size_t take = 64 - st->buf_len;
		if (take > len) {
			take = len;
		}
		memcpy(st->buf + st->buf_len, p, take);
		st->buf_len += (uint32_t)take;
		p += take;
		len -= take;
		if (st->buf_len == 64) {
			sha256_compress(st, st->buf);
			st->buf_len = 0;
		}
	}

	while (len >= 64) {
		sha256_compress(st, p);
		p += 64;
		len -= 64;
	}

	if (len > 0) {
		memcpy(st->buf, p, len);
		st->buf_len = (uint32_t)len;
	}
}

void
SHA256_Final(void *digest, SHA256_CTX *ctx)
{
	struct sha256_state *st = (struct sha256_state *)(void *)ctx;
	uint64_t bit_len = st->total_len * 8;

	uint8_t pad = 0x80;
	SHA256_Update(ctx, &pad, 1);

	uint8_t zero = 0;
	while (st->buf_len != 56) {
		SHA256_Update(ctx, &zero, 1);
	}

	uint8_t lenbuf[8];
	store_be64(lenbuf, bit_len);
	/* append directly - avoid recursing through Update's total_len math */
	memcpy(st->buf + 56, lenbuf, 8);
	sha256_compress(st, st->buf);

	uint8_t *out = (uint8_t *)digest;
	for (int i = 0; i < 8; i++) {
		store_be32(out + i * 4, st->h[i]);
	}
}

/* ================= SHA-512 / SHA-384 ================= */

struct sha512_state {
	uint64_t h[8];
	uint64_t total_len; /* bytes processed so far (< 2^64 bytes, plenty) */
	uint8_t  buf[128];
	uint32_t buf_len;
};
_Static_assert(sizeof(struct sha512_state) <= sizeof(SHA512_CTX),
    "sha512_state must fit in SHA512_CTX's opaque buffer");

static const uint64_t sha512_k[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

static inline uint64_t
rotr64(uint64_t x, int n)
{
	return (x >> n) | (x << (64 - n));
}

static void
sha512_compress(struct sha512_state *st, const uint8_t block[128])
{
	uint64_t w[80];
	for (int i = 0; i < 16; i++) {
		w[i] = load_be64(block + i * 8);
	}
	for (int i = 16; i < 80; i++) {
		uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
		uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	uint64_t a = st->h[0], b = st->h[1], c = st->h[2], d = st->h[3];
	uint64_t e = st->h[4], f = st->h[5], g = st->h[6], h = st->h[7];

	for (int i = 0; i < 80; i++) {
		uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
		uint64_t ch = (e & f) ^ (~e & g);
		uint64_t temp1 = h + S1 + ch + sha512_k[i] + w[i];
		uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
		uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint64_t temp2 = S0 + maj;

		h = g; g = f; f = e; e = d + temp1;
		d = c; c = b; b = a; a = temp1 + temp2;
	}

	st->h[0] += a; st->h[1] += b; st->h[2] += c; st->h[3] += d;
	st->h[4] += e; st->h[5] += f; st->h[6] += g; st->h[7] += h;
}

static void
sha512_update(struct sha512_state *st, const void *data, size_t len)
{
	const uint8_t *p = (const uint8_t *)data;

	st->total_len += len;

	if (st->buf_len > 0) {
		size_t take = 128 - st->buf_len;
		if (take > len) {
			take = len;
		}
		memcpy(st->buf + st->buf_len, p, take);
		st->buf_len += (uint32_t)take;
		p += take;
		len -= take;
		if (st->buf_len == 128) {
			sha512_compress(st, st->buf);
			st->buf_len = 0;
		}
	}

	while (len >= 128) {
		sha512_compress(st, p);
		p += 128;
		len -= 128;
	}

	if (len > 0) {
		memcpy(st->buf, p, len);
		st->buf_len = (uint32_t)len;
	}
}

static void
sha512_final(struct sha512_state *st, void *digest, int digest_words)
{
	uint64_t bit_len_lo = st->total_len * 8;

	uint8_t pad = 0x80;
	sha512_update(st, &pad, 1);

	uint8_t zero = 0;
	while (st->buf_len != 112) {
		sha512_update(st, &zero, 1);
	}

	uint8_t lenbuf[16];
	memset(lenbuf, 0, 8); /* high 64 bits of a 128-bit length: always 0 here */
	store_be64(lenbuf + 8, bit_len_lo);
	memcpy(st->buf + 112, lenbuf, 16);
	sha512_compress(st, st->buf);

	uint8_t *out = (uint8_t *)digest;
	for (int i = 0; i < digest_words; i++) {
		store_be64(out + i * 8, st->h[i]);
	}
}

void
SHA512_Init(SHA512_CTX *ctx)
{
	struct sha512_state *st = (struct sha512_state *)(void *)ctx;
	st->h[0] = 0x6a09e667f3bcc908ULL; st->h[1] = 0xbb67ae8584caa73bULL;
	st->h[2] = 0x3c6ef372fe94f82bULL; st->h[3] = 0xa54ff53a5f1d36f1ULL;
	st->h[4] = 0x510e527fade682d1ULL; st->h[5] = 0x9b05688c2b3e6c1fULL;
	st->h[6] = 0x1f83d9abfb41bd6bULL; st->h[7] = 0x5be0cd19137e2179ULL;
	st->total_len = 0;
	st->buf_len = 0;
}

void
SHA512_Update(SHA512_CTX *ctx, const void *data, size_t len)
{
	sha512_update((struct sha512_state *)(void *)ctx, data, len);
}

void
SHA512_Final(void *digest, SHA512_CTX *ctx)
{
	sha512_final((struct sha512_state *)(void *)ctx, digest, 8);
}

void
SHA384_Init(SHA384_CTX *ctx)
{
	struct sha512_state *st = (struct sha512_state *)(void *)ctx;
	st->h[0] = 0xcbbb9d5dc1059ed8ULL; st->h[1] = 0x629a292a367cd507ULL;
	st->h[2] = 0x9159015a3070dd17ULL; st->h[3] = 0x152fecd8f70e5939ULL;
	st->h[4] = 0x67332667ffc00b31ULL; st->h[5] = 0x8eb44a8768581511ULL;
	st->h[6] = 0xdb0c2e0d64f98fa7ULL; st->h[7] = 0x47b5481dbefa4fa4ULL;
	st->total_len = 0;
	st->buf_len = 0;
}

void
SHA384_Update(SHA384_CTX *ctx, const void *data, size_t len)
{
	sha512_update((struct sha512_state *)(void *)ctx, data, len);
}

void
SHA384_Final(void *digest, SHA384_CTX *ctx)
{
	uint64_t full[8];
	sha512_final((struct sha512_state *)(void *)ctx, full, 8);
	memcpy(digest, full, 48); /* SHA-384 = first 384 bits of the SHA-512 state */
}
