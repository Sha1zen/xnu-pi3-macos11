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
 * ccdigest_init()/&ccsha256_ltc_di pair. SHA-384/512 have no real
 * corecrypto body anywhere in this checkout (only headers, confirmed
 * absent from both third_party/xnu-7195 and third_party/xnu-latest's
 * SHA-512 case) - per this project's Apple-then-FreeBSD-then-custom
 * source priority, their compress core is now FreeBSD's real, 2-clause
 * BSD sha512c.c (2026-08-28, docs/backlog.md item 0a's sibling gap;
 * see libkern/crypto/freebsd/sha512_transform.c), not hand-written. The
 * buffering/padding wrapper below (sha512_update/sha512_final and the
 * Init/Update/Final entry points) stays this project's own, since it
 * has to match this file's own SHA512_CTX/SHA384_CTX layout rather than
 * FreeBSD's differently-shaped SHA512Context.
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

/* ---- shared big-endian helpers (SHA-384/512 Final() output only -
 * the compress core's own big-endian block load lives in
 * freebsd/sha512_transform.c now) ---- */

static inline void
store_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
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

/*
 * Real compress core, vendored from freebsd-src release/13.2.0
 * (sys/crypto/sha2/sha512c.c) - see libkern/crypto/freebsd/
 * sha512_transform.c for the K[80] table and round function, in place
 * of this file's former hand-written K table and compress loop.
 */
extern void SHA512_Transform(uint64_t *state, const unsigned char block[128]);

static void
sha512_compress(struct sha512_state *st, const uint8_t block[128])
{
	SHA512_Transform(st->h, block);
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
