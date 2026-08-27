/*
 * corecrypto_sha2.c - SHA-256/384/512 for xnu-on-rpi3.
 *
 * None of these functions ever went through g_crypto_funcs
 * (libkern/crypto/register_crypto.c) - real macOS's closed-source
 * corecrypto kext populates that table via register_crypto_functions(),
 * but SHA256_Init/_Update/_Final etc are plain global functions with no
 * table indirection anywhere in their call chain (cs_hash_sha256,
 * cdhash/boot-session-UUID hashing in kern_exec.c, chunklist.c all call
 * them directly). The original bug was a NULL+offset fault reached a
 * different way: an earlier revision of this file *was* a thin
 * g_crypto_funcs wrapper (nothing ever calls register_crypto_functions()
 * in this from-scratch kernel, so the table stays NULL forever), fixed by
 * replacing it with a from-scratch FIPS 180-4 implementation for all three
 * digests.
 *
 * SHA-256 has since been upgraded off that from-scratch path (2026-08-27,
 * docs/backlog.md P2 item 0b): SHA256_Init/_Update/_Final now call the
 * real, unmodified, audited Apple corecrypto core directly
 * (ccsha256_di()/ccdigest_init/_update/_final -
 * osfmk/corecrypto/ccsha256_di.c, ccsha256_ltc_di.c, ccdigest_*.c),
 * already compiled into this exact kernel and already proven working by
 * osfmk/prng/prng_random.c's bootseed_init(), which calls the same
 * ccdigest_init()/&ccsha256_ltc_di pair. SHA-384/512 stay on the
 * from-scratch path below - real corecrypto bodies for those two don't
 * exist anywhere in this checkout (only headers), confirmed absent from
 * both third_party/xnu-7195 and third_party/xnu-latest's SHA-512 case.
 *
 * SHA256_CTX/SHA384_CTX/SHA512_CTX (libkern/libkern/crypto/sha2.h) are
 * real corecrypto-shaped opaque contexts (ccdigest_ctx_decl(...)) - for
 * SHA-256 that's now load-bearing (it's exactly what real ccdigest_init/
 * _update/_final expect); for SHA-384/512 it's still just generously
 * sized scratch space for the plain state structs below (checked via
 * _Static_assert), with no ABI requirement against corecrypto's actual
 * layout since nothing outside this kernel consumes those two directly.
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

/*
 * ================= SHA-256 =================
 *
 * Wired to the real, audited corecrypto core rather than a from-scratch
 * compress loop (docs/backlog.md P2 item 0b, acted on 2026-08-27).
 * ccsha256_di()/ccdigest_init/ccdigest_update/ccdigest_final are real,
 * unmodified Apple corecrypto (osfmk/corecrypto/ccsha256_di.c,
 * ccsha256_ltc_di.c, ccdigest_*.c), already marked `standard` in
 * osfmk/conf/files and already proven working in this exact kernel build
 * by osfmk/prng/prng_random.c's bootseed_init(), which calls this same
 * ccdigest_init/&ccsha256_ltc_di pair directly. SHA256_CTX's `ctx` field
 * is itself a real ccdigest_ctx_decl array (libkern/libkern/crypto/sha2.h)
 * sized for corecrypto's own state layout, so no adapter is needed beyond
 * routing these three entry points to the real calls. SHA-384/512 stay on
 * the from-scratch path below (real corecrypto bodies for those are
 * absent from this checkout, see backlog) and so still need the shared
 * big-endian helpers above.
 */
void
SHA256_Init(SHA256_CTX *ctx)
{
	ccdigest_init(ccsha256_di(), ctx->ctx);
}

void
SHA256_Update(SHA256_CTX *ctx, const void *data, size_t len)
{
	ccdigest_update(ccsha256_di(), ctx->ctx, len, data);
}

void
SHA256_Final(void *digest, SHA256_CTX *ctx)
{
	ccdigest_final(ccsha256_di(), ctx->ctx, (unsigned char *)digest);
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
