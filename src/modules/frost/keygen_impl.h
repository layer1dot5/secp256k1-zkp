/**********************************************************************
 * Copyright (c) 2021, 2022 Jesse Posner                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_FROST_KEYGEN_IMPL_H
#define SECP256K1_MODULE_FROST_KEYGEN_IMPL_H

#include <string.h>

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_extrakeys.h"
#include "../../../include/secp256k1_frost.h"

#include "keygen.h"
#include "../../ecmult.h"
#include "../../field.h"
#include "../../group.h"
#include "../../hash.h"
#include "../../scalar.h"

/* Computes indexhash = tagged_hash(pk || idx) */
static int secp256k1_frost_compute_indexhash(const secp256k1_context *ctx, secp256k1_scalar *indexhash, const secp256k1_xonly_pubkey *pk) {
    secp256k1_sha256 sha;
    unsigned char buf[32];
    const unsigned char zerobyte[1] = { 0 };

    if (!secp256k1_xonly_pubkey_serialize(ctx, buf, pk)) {
        return 0;
    }
    secp256k1_sha256_initialize_tagged(&sha, (unsigned char*)"FROST/index", sizeof("FROST/index") - 1);
    secp256k1_sha256_write(&sha, buf, sizeof(buf));
    /* TODO: add sub_indices for weights > 1 */
    secp256k1_sha256_write(&sha, zerobyte, 1);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(indexhash, buf, NULL);
    /* The x-coordinate must not be zero (see
     * draft-irtf-cfrg-frost-08#section-4.2.2) */
    if (secp256k1_scalar_is_zero(indexhash)) {
        return 0;
    }

    return 1;
}

static const unsigned char secp256k1_frost_share_magic[4] = { 0xa1, 0x6a, 0x42, 0x03 };

static void secp256k1_frost_share_save(secp256k1_frost_share* share, secp256k1_scalar *s) {
    memcpy(&share->data[0], secp256k1_frost_share_magic, 4);
    secp256k1_scalar_get_b32(&share->data[4], s);
}

static int secp256k1_frost_share_load(const secp256k1_context* ctx, secp256k1_scalar *s, const secp256k1_frost_share* share) {
    int overflow;

    ARG_CHECK(secp256k1_memcmp_var(&share->data[0], secp256k1_frost_share_magic, 4) == 0);
    secp256k1_scalar_set_b32(s, &share->data[4], &overflow);
    /* Parsed shares cannot overflow */
    VERIFY_CHECK(!overflow);
    return 1;
}

int secp256k1_frost_share_serialize(const secp256k1_context* ctx, unsigned char *out32, const secp256k1_frost_share* share) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out32 != NULL);
    ARG_CHECK(share != NULL);
    memcpy(out32, &share->data[4], 32);
    return 1;
}

int secp256k1_frost_share_parse(const secp256k1_context* ctx, secp256k1_frost_share* share, const unsigned char *in32) {
    secp256k1_scalar tmp;
    int overflow;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(share != NULL);
    ARG_CHECK(in32 != NULL);

    secp256k1_scalar_set_b32(&tmp, in32, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_frost_share_save(share, &tmp);
    return 1;
}

int secp256k1_frost_share_gen(const secp256k1_context *ctx, secp256k1_pubkey *vss_commitment, secp256k1_frost_share *share, const unsigned char *session_id, const secp256k1_keypair *keypair, const secp256k1_xonly_pubkey *pk, size_t threshold) {
    secp256k1_sha256 sha;
    secp256k1_scalar idx;
    secp256k1_scalar sk;
    secp256k1_scalar share_i;
    secp256k1_ge ge_tmp;
    unsigned char buf[32];
    unsigned char rngseed[32];
    secp256k1_scalar rand[2];
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(share != NULL);
    memset(share, 0, sizeof(*share));
    ARG_CHECK(session_id != NULL);
    ARG_CHECK(keypair != NULL);
    ARG_CHECK(pk != NULL);
    ARG_CHECK(threshold > 1);

    if (!secp256k1_keypair_load(ctx, &sk, &ge_tmp, keypair)) {
        return 0;
    }
    /* The first coefficient is the secret key, and thus the first commitment
     * is the public key. */
    if (vss_commitment != NULL) {
        secp256k1_pubkey_save(&vss_commitment[0], &ge_tmp);
    }
    /* Compute seed which commits to threshold and session ID */
    secp256k1_scalar_get_b32(buf, &sk);
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, session_id, 32);
    secp256k1_sha256_write(&sha, buf, 32);
    for (i = 0; i < 8; i++) {
        rngseed[i + 0] = threshold / (1ull << (i * 8));
    }
    secp256k1_sha256_write(&sha, rngseed, 8);
    secp256k1_sha256_finalize(&sha, rngseed);
    /* Derive coefficients commitments from the seed */
    if (vss_commitment != NULL) {
        for (i = 0; i < threshold - 1; i++) {
            secp256k1_gej rj;
            secp256k1_ge rp;

            if (i % 2 == 0) {
                secp256k1_scalar_chacha20(&rand[0], &rand[1], rngseed, i);
            }
            /* Compute commitment to each coefficient */
            secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &rand[i % 2]);
            secp256k1_ge_set_gej(&rp, &rj);
            secp256k1_pubkey_save(&vss_commitment[threshold - i - 1], &rp);
        }
    }

    /* Derive share */
    /* See draft-irtf-cfrg-frost-08#appendix-C.1 */
    secp256k1_scalar_clear(&share_i);
    if (!secp256k1_frost_compute_indexhash(ctx, &idx, pk)) {
        return 0;
    }
    for (i = 0; i < threshold - 1; i++) {
        if (i % 2 == 0) {
            secp256k1_scalar_chacha20(&rand[0], &rand[1], rngseed, i);
        }
        /* Horner's method to evaluate polynomial to derive shares */
        secp256k1_scalar_add(&share_i, &share_i, &rand[i % 2]);
        secp256k1_scalar_mul(&share_i, &share_i, &idx);
    }
    secp256k1_scalar_add(&share_i, &share_i, &sk);
    secp256k1_frost_share_save(share, &share_i);

    return 1;
}

#endif
