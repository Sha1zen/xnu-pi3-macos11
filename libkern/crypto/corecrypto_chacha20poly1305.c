/*
 * Copyright (c) 2017 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <corecrypto/ccchacha20poly1305.h>
#include <libkern/crypto/crypto_internal.h>
#include <libkern/crypto/chacha20poly1305.h>

static ccchacha20poly1305_fns_t
fns(void)
{
	/* DAR-108: same real, never-registered-kext condition
	 * corecrypto_aes.c's aes_encrypt_key() already guards against - see
	 * that function's own header comment for the full citation. Every
	 * one of the 9 public entry points below funnels through this one
	 * function (and info(), which itself calls fns()), so a NULL check
	 * here plus one at each public entry point (fns() alone dereffing
	 * safely does not stop `fns()->init(...)` etc from still
	 * dereferencing a NULL fns() result at the call site) covers all of
	 * them. */
	if (g_crypto_funcs == NULL) {
		return NULL;
	}
	return g_crypto_funcs->ccchacha20poly1305_fns;
}

static const struct ccchacha20poly1305_info *
info(void)
{
	ccchacha20poly1305_fns_t f = fns();
	if (f == NULL) {
		return NULL;
	}
	return f->info();
}

int
chacha20poly1305_init(chacha20poly1305_ctx *ctx, const uint8_t *key)
{
	ccchacha20poly1305_fns_t f = fns();
	if (f == NULL) {
		return -1;
	}
	return f->init(info(), ctx, key);
}

int
chacha20poly1305_reset(chacha20poly1305_ctx *ctx)
{
	ccchacha20poly1305_fns_t f = fns();
	if (f == NULL) {
		return -1;
	}
	return f->reset(info(), ctx);
}

int
chacha20poly1305_setnonce(chacha20poly1305_ctx *ctx, const uint8_t *nonce)
{
	ccchacha20poly1305_fns_t f = fns();
	if (f == NULL) {
		return -1;
	}
	return f->setnonce(info(), ctx, nonce);
}

int
chacha20poly1305_incnonce(chacha20poly1305_ctx *ctx, uint8_t *nonce)
{
	ccchacha20poly1305_fns_t f = fns();
	if (f == NULL) {
		return -1;
	}
	return f->incnonce(info(), ctx, nonce);
}

int
chacha20poly1305_aad(chacha20poly1305_ctx *ctx, size_t nbytes, const void *aad)
{
	ccchacha20poly1305_fns_t f = fns();
	if (f == NULL) {
		return -1;
	}
	return f->aad(info(), ctx, nbytes, aad);
}

int
chacha20poly1305_encrypt(chacha20poly1305_ctx *ctx, size_t nbytes, const void *ptext, void *ctext)
{
	ccchacha20poly1305_fns_t f = fns();
	if (f == NULL) {
		return -1;
	}
	return f->encrypt(info(), ctx, nbytes, ptext, ctext);
}

int
chacha20poly1305_finalize(chacha20poly1305_ctx *ctx, uint8_t *tag)
{
	ccchacha20poly1305_fns_t f = fns();
	if (f == NULL) {
		return -1;
	}
	return f->finalize(info(), ctx, tag);
}

int
chacha20poly1305_decrypt(chacha20poly1305_ctx *ctx, size_t nbytes, const void *ctext, void *ptext)
{
	ccchacha20poly1305_fns_t f = fns();
	if (f == NULL) {
		return -1;
	}
	return f->decrypt(info(), ctx, nbytes, ctext, ptext);
}

int
chacha20poly1305_verify(chacha20poly1305_ctx *ctx, const uint8_t *tag)
{
	ccchacha20poly1305_fns_t f = fns();
	if (f == NULL) {
		return -1;
	}
	return f->verify(info(), ctx, tag);
}
