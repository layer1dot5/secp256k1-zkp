/**********************************************************************
 * Copyright (c) 2021, 2022 Jesse Posner                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_FROST_SESSION_IMPL_H
#define SECP256K1_MODULE_FROST_SESSION_IMPL_H

#include "session.h"

static const unsigned char secp256k1_frost_secnonce_magic[4] = { 0x84, 0x7d, 0x46, 0x25 };

static void secp256k1_frost_secnonce_save(secp256k1_frost_secnonce *secnonce, secp256k1_scalar *k) {
    memcpy(&secnonce->data[0], secp256k1_frost_secnonce_magic, 4);
    secp256k1_scalar_get_b32(&secnonce->data[4], &k[0]);
    secp256k1_scalar_get_b32(&secnonce->data[36], &k[1]);
}

static int secp256k1_frost_secnonce_load(const secp256k1_context* ctx, secp256k1_scalar *k, secp256k1_frost_secnonce *secnonce) {
    int is_zero;
    ARG_CHECK(secp256k1_memcmp_var(&secnonce->data[0], secp256k1_frost_secnonce_magic, 4) == 0);
    secp256k1_scalar_set_b32(&k[0], &secnonce->data[4], NULL);
    secp256k1_scalar_set_b32(&k[1], &secnonce->data[36], NULL);
    /* We make very sure that the nonce isn't invalidated by checking the values
     * in addition to the magic. */
    is_zero = secp256k1_scalar_is_zero(&k[0]) & secp256k1_scalar_is_zero(&k[1]);
    secp256k1_declassify(ctx, &is_zero, sizeof(is_zero));
    ARG_CHECK(!is_zero);
    return 1;
}

/* If flag is true, invalidate the secnonce; otherwise leave it. Constant-time. */
static void secp256k1_frost_secnonce_invalidate(const secp256k1_context* ctx, secp256k1_frost_secnonce *secnonce, int flag) {
    secp256k1_memczero(secnonce->data, sizeof(secnonce->data), flag);
    /* The flag argument is usually classified. So, above code makes the magic
     * classified. However, we need the magic to be declassified to be able to
     * compare it during secnonce_load. */
    secp256k1_declassify(ctx, secnonce->data, sizeof(secp256k1_frost_secnonce_magic));
}

static const unsigned char secp256k1_frost_pubnonce_magic[4] = { 0x8b, 0xcf, 0xe2, 0xc2 };

/* Requires that none of the provided group elements is infinity. Works for both
 * frost_pubnonce and frost_aggnonce. */
static void secp256k1_frost_pubnonce_save(secp256k1_frost_pubnonce* nonce, secp256k1_ge* ge, uint16_t idx) {
    int i;
    memcpy(&nonce->data[0], secp256k1_frost_pubnonce_magic, 4);
    nonce->data[4] = (idx + 1) >> 8;
    nonce->data[5] = (idx + 1) & 0xFF;
    for (i = 0; i < 2; i++) {
        secp256k1_point_save(nonce->data + 6+64*i, &ge[i]);
    }
}

static void secp256k1_frost_pubnonce_load_idx(uint16_t* idx, const secp256k1_frost_pubnonce* nonce) {
    *idx = (nonce->data[4] << 8) + nonce->data[5] - 1;
}

/* Returns 1 unless the nonce wasn't properly initialized */
static int secp256k1_frost_pubnonce_load(const secp256k1_context* ctx, secp256k1_ge* ge, uint16_t* idx, const secp256k1_frost_pubnonce* nonce) {
    int i;

    ARG_CHECK(secp256k1_memcmp_var(&nonce->data[0], secp256k1_frost_pubnonce_magic, 4) == 0);
    secp256k1_frost_pubnonce_load_idx(idx, nonce);
    for (i = 0; i < 2; i++) {
        secp256k1_point_load(&ge[i], nonce->data + 6+64*i);
    }
    return 1;
}

int secp256k1_frost_pubnonce_serialize(const secp256k1_context* ctx, unsigned char *out68, const secp256k1_frost_pubnonce* nonce) {
    secp256k1_ge ge[2];
    int i;
    uint16_t idx;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out68 != NULL);
    memset(out68, 0, 68);
    ARG_CHECK(nonce != NULL);

    if (!secp256k1_frost_pubnonce_load(ctx, ge, &idx, nonce)) {
        return 0;
    }
    /* TODO: create helper function */
    out68[0] = (idx + 1) >> 8;
    VERIFY_CHECK(out68[0] == nonce->data[4]);
    out68[1] = (idx + 1) & 0xFF;
    VERIFY_CHECK(out68[1] == nonce->data[5]);
    for (i = 0; i < 2; i++) {
        int ret;
        size_t size = 33;
        ret = secp256k1_eckey_pubkey_serialize(&ge[i], &out68[2+33*i], &size, 1);
        /* serialize must succeed because the point was just loaded */
        VERIFY_CHECK(ret && size == 33);
    }
    return 1;
}


static const unsigned char secp256k1_frost_aggnonce_magic[4] = { 0x37, 0x21, 0x75, 0xe3 };

static void secp256k1_frost_aggnonce_save(secp256k1_frost_aggnonce* nonce, secp256k1_ge* ge) {
    int i;
    memcpy(&nonce->data[0], secp256k1_frost_aggnonce_magic, 4);
    for (i = 0; i < 2; i++) {
        secp256k1_point_save(nonce->data + 4+64*i, &ge[i]);
    }
}

/* Returns 1 unless the nonce wasn't properly initialized */
static int secp256k1_frost_aggnonce_load(const secp256k1_context* ctx, secp256k1_ge* ge, const secp256k1_frost_aggnonce* nonce) {
    int i;

    ARG_CHECK(secp256k1_memcmp_var(&nonce->data[0], secp256k1_frost_aggnonce_magic, 4) == 0);
    for (i = 0; i < 2; i++) {
        secp256k1_point_load(&ge[i], nonce->data + 4+64*i);
    }
    return 1;
}

int secp256k1_frost_aggnonce_serialize(const secp256k1_context* ctx, unsigned char *out66, const secp256k1_frost_aggnonce* nonce) {
    secp256k1_ge ge[2];
    int i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out66 != NULL);
    memset(out66, 0, 66);
    ARG_CHECK(nonce != NULL);

    if (!secp256k1_frost_aggnonce_load(ctx, ge, nonce)) {
        return 0;
    }
    for (i = 0; i < 2; i++) {
        int ret;
        size_t size = 33;
        ret = secp256k1_eckey_pubkey_serialize(&ge[i], &out66[33*i], &size, 1);
        /* serialize must succeed because the point was just loaded */
        VERIFY_CHECK(ret && size == 33);
    }
    return 1;
}

static const unsigned char secp256k1_frost_session_cache_magic[4] = { 0x9d, 0xed, 0xe9, 0x17 };

/* A session consists of
 * - 4 byte session cache magic
 * - 1 byte the parity of the final nonce
 * - 32 byte serialized x-only final nonce
 * - 32 byte nonce coefficient b
 * - 32 byte signature challenge hash e
 * - 32 byte scalar s that is added to the partial signatures of the signers
 */
static void secp256k1_frost_session_save(secp256k1_frost_session *session, const secp256k1_frost_session_internal *session_i) {
    unsigned char *ptr = session->data;

    memcpy(ptr, secp256k1_frost_session_cache_magic, 4);
    ptr += 4;
    *ptr = session_i->fin_nonce_parity;
    ptr += 1;
    memcpy(ptr, session_i->fin_nonce, 32);
    ptr += 32;
    secp256k1_scalar_get_b32(ptr, &session_i->noncecoef);
    ptr += 32;
    secp256k1_scalar_get_b32(ptr, &session_i->challenge);
    ptr += 32;
    secp256k1_scalar_get_b32(ptr, &session_i->s_part);
}

static int secp256k1_frost_session_load(const secp256k1_context* ctx, secp256k1_frost_session_internal *session_i, const secp256k1_frost_session *session) {
    const unsigned char *ptr = session->data;

    ARG_CHECK(secp256k1_memcmp_var(ptr, secp256k1_frost_session_cache_magic, 4) == 0);
    ptr += 4;
    session_i->fin_nonce_parity = *ptr;
    ptr += 1;
    memcpy(session_i->fin_nonce, ptr, 32);
    ptr += 32;
    secp256k1_scalar_set_b32(&session_i->noncecoef, ptr, NULL);
    ptr += 32;
    secp256k1_scalar_set_b32(&session_i->challenge, ptr, NULL);
    ptr += 32;
    secp256k1_scalar_set_b32(&session_i->s_part, ptr, NULL);
    return 1;
}

static const unsigned char secp256k1_frost_partial_sig_magic[4] = { 0xeb, 0xfb, 0x1a, 0x32 };

static void secp256k1_frost_partial_sig_save(secp256k1_frost_partial_sig* sig, secp256k1_scalar *s) {
    memcpy(&sig->data[0], secp256k1_frost_partial_sig_magic, 4);
    secp256k1_scalar_get_b32(&sig->data[4], s);
}

static int secp256k1_frost_partial_sig_load(const secp256k1_context* ctx, secp256k1_scalar *s, const secp256k1_frost_partial_sig* sig) {
    int overflow;

    ARG_CHECK(secp256k1_memcmp_var(&sig->data[0], secp256k1_frost_partial_sig_magic, 4) == 0);
    secp256k1_scalar_set_b32(s, &sig->data[4], &overflow);
    /* Parsed signatures can not overflow */
    VERIFY_CHECK(!overflow);
    return 1;
}

static void secp256k1_nonce_function_frost(secp256k1_scalar *k, const unsigned char *session_id, const unsigned char *msg32, const unsigned char *key32, const unsigned char *agg_pk32, const unsigned char *extra_input32) {
    secp256k1_sha256 sha;
    unsigned char seed[32];
    unsigned char i;
    enum { n_extra_in = 4 };
    const unsigned char *extra_in[n_extra_in];

    /* TODO: this doesn't have the same sidechannel resistance as the BIP340
     * nonce function because the seckey feeds directly into SHA. */

    /* Subtract one from `sizeof` to avoid hashing the implicit null byte */
    secp256k1_sha256_initialize_tagged(&sha, (unsigned char*)"FROST/nonce", sizeof("FROST/nonce") - 1);
    secp256k1_sha256_write(&sha, session_id, 32);
    extra_in[0] = msg32;
    extra_in[1] = key32;
    extra_in[2] = agg_pk32;
    extra_in[3] = extra_input32;
    for (i = 0; i < n_extra_in; i++) {
        unsigned char len;
        if (extra_in[i] != NULL) {
            len = 32;
            secp256k1_sha256_write(&sha, &len, 1);
            secp256k1_sha256_write(&sha, extra_in[i], 32);
        } else {
            len = 0;
            secp256k1_sha256_write(&sha, &len, 1);
        }
    }
    secp256k1_sha256_finalize(&sha, seed);

    for (i = 0; i < 2; i++) {
        unsigned char buf[32];
        secp256k1_sha256_initialize(&sha);
        secp256k1_sha256_write(&sha, seed, 32);
        secp256k1_sha256_write(&sha, &i, sizeof(i));
        secp256k1_sha256_finalize(&sha, buf);
        secp256k1_scalar_set_b32(&k[i], buf, NULL);
    }
}

int secp256k1_frost_nonce_gen(const secp256k1_context* ctx, secp256k1_frost_secnonce *secnonce, secp256k1_frost_pubnonce *pubnonce, const unsigned char *session_id32, uint16_t my_index, const secp256k1_frost_share *agg_share, const unsigned char *msg32, const secp256k1_xonly_pubkey *agg_pk, const unsigned char *extra_input32) {
    secp256k1_scalar k[2];
    secp256k1_ge nonce_pt[2];
    int i;
    unsigned char pk_ser[32];
    unsigned char *pk_ser_ptr = NULL;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secnonce != NULL);
    memset(secnonce, 0, sizeof(*secnonce));
    ARG_CHECK(pubnonce != NULL);
    memset(pubnonce, 0, sizeof(*pubnonce));
    ARG_CHECK(session_id32 != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    if (agg_share == NULL) {
        /* Check in constant time that the session_id is not 0 as a
         * defense-in-depth measure that may protect against a faulty RNG. */
        unsigned char acc = 0;
        for (i = 0; i < 32; i++) {
            acc |= session_id32[i];
        }
        ret &= !!acc;
        memset(&acc, 0, sizeof(acc));
    }

    /* Check that the agg_share is valid to be able to sign for it later. */
    if (agg_share != NULL) {
        secp256k1_scalar sk;
        ret &= secp256k1_scalar_set_b32_seckey(&sk, agg_share->data);
        secp256k1_scalar_clear(&sk);
    }

    if (agg_pk != NULL) {
        int ret_tmp;

        ret_tmp = secp256k1_xonly_pubkey_serialize(ctx, pk_ser, agg_pk);
        /* Serialization can not fail because the loaded point can not be infinity. */
        VERIFY_CHECK(ret_tmp);
        pk_ser_ptr = pk_ser;
    }
    secp256k1_nonce_function_frost(k, session_id32, msg32, agg_share->data, pk_ser_ptr, extra_input32);
    VERIFY_CHECK(!secp256k1_scalar_is_zero(&k[0]));
    VERIFY_CHECK(!secp256k1_scalar_is_zero(&k[1]));
    VERIFY_CHECK(!secp256k1_scalar_eq(&k[0], &k[1]));
    secp256k1_frost_secnonce_save(secnonce, k);
    secp256k1_frost_secnonce_invalidate(ctx, secnonce, !ret);

    for (i = 0; i < 2; i++) {
        secp256k1_gej nonce_ptj;
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &nonce_ptj, &k[i]);
        secp256k1_ge_set_gej(&nonce_pt[i], &nonce_ptj);
        secp256k1_declassify(ctx, &nonce_pt[i], sizeof(nonce_pt));
        secp256k1_scalar_clear(&k[i]);
    }
    /* nonce_pt won't be infinity because k != 0 with overwhelming probability */
    secp256k1_frost_pubnonce_save(pubnonce, nonce_pt, my_index);
    return ret;
}

static int secp256k1_frost_sum_nonces(const secp256k1_context* ctx, secp256k1_gej *summed_nonces, const secp256k1_frost_pubnonce * const* pubnonces, uint16_t n_pubnonces) {
    uint16_t idx;
    uint16_t i;
    int j;

    secp256k1_gej_set_infinity(&summed_nonces[0]);
    secp256k1_gej_set_infinity(&summed_nonces[1]);

    for (i = 0; i < n_pubnonces; i++) {
        secp256k1_ge nonce_pt[2];
        if (!secp256k1_frost_pubnonce_load(ctx, nonce_pt, &idx, pubnonces[i])) {
            return 0;
        }
        for (j = 0; j < 2; j++) {
            secp256k1_gej_add_ge_var(&summed_nonces[j], &summed_nonces[j], &nonce_pt[j], NULL);
        }
    }
    return 1;
}

int secp256k1_frost_nonce_agg(const secp256k1_context* ctx, secp256k1_frost_aggnonce  *aggnonce, const secp256k1_frost_pubnonce * const* pubnonces, uint16_t n_pubnonces) {
    secp256k1_gej aggnonce_ptj[2];
    secp256k1_ge aggnonce_pt[2];
    int i;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(aggnonce != NULL);
    ARG_CHECK(pubnonces != NULL);
    ARG_CHECK(n_pubnonces > 0);

    if (!secp256k1_frost_sum_nonces(ctx, aggnonce_ptj, pubnonces, n_pubnonces)) {
        return 0;
    }
    for (i = 0; i < 2; i++) {
        if (secp256k1_gej_is_infinity(&aggnonce_ptj[i])) {
            /* There must be at least one dishonest signer. If we would return 0
               here, we will never be able to determine who it is. Therefore, we
               should continue such that the culprit is revealed when collecting
               and verifying partial signatures.

               However, dealing with the point at infinity (loading,
               de-/serializing) would require a lot of extra code complexity.
               Instead, we set the aggregate nonce to some arbitrary point (the
               generator). This is secure, because it only restricts the
               abilities of the attacker: an attacker that forces the sum of
               nonces to be infinity by sending some maliciously generated nonce
               pairs can be turned into an attacker that forces the sum to be
               the generator (by simply adding the generator to one of the
               malicious nonces), and this does not change the winning condition
               of the EUF-CMA game. */
            aggnonce_pt[i] = secp256k1_ge_const_g;
        } else {
            secp256k1_ge_set_gej(&aggnonce_pt[i], &aggnonce_ptj[i]);
        }
    }
    secp256k1_frost_aggnonce_save(aggnonce, aggnonce_pt);
    return 1;
}

/* Implements binding factor from draft-irtf-cfrg-frost-04, section 4.4. */
static int secp256k1_frost_compute_noncehash(const secp256k1_context* ctx, unsigned char *noncehash, const unsigned char *msg, const secp256k1_frost_pubnonce * const* pubnonces, uint16_t n_pubnonces) {
    unsigned char buf[68];
    secp256k1_sha256 sha;
    uint16_t i;

    secp256k1_sha256_initialize_tagged(&sha, (unsigned char*)"FROST/noncecoef", sizeof("FROST/noncecoef") - 1);
    /* TODO: sort by index */
    for (i = 0; i < n_pubnonces; i++) {
        if (!secp256k1_frost_pubnonce_serialize(ctx, buf, pubnonces[i])) {
            return 0;
        }
        secp256k1_sha256_write(&sha, buf, sizeof(buf));
    }
    secp256k1_sha256_write(&sha, msg, 32);
    secp256k1_sha256_finalize(&sha, noncehash);
    return 1;
}

static int secp256k1_frost_nonce_process_internal(const secp256k1_context* ctx, int *fin_nonce_parity, unsigned char *fin_nonce, secp256k1_scalar *b, secp256k1_gej *aggnoncej, const unsigned char *msg, const secp256k1_frost_pubnonce * const* pubnonces, uint16_t n_pubnonces) {
    unsigned char noncehash[32];
    secp256k1_ge fin_nonce_pt;
    secp256k1_gej fin_nonce_ptj;
    secp256k1_ge aggnonce[2];

    secp256k1_ge_set_gej(&aggnonce[0], &aggnoncej[0]);
    secp256k1_ge_set_gej(&aggnonce[1], &aggnoncej[1]);
    if (!secp256k1_frost_compute_noncehash(ctx, noncehash, msg, pubnonces, n_pubnonces)) {
        return 0;
    }
    /* fin_nonce = aggnonce[0] + b*aggnonce[1] */
    secp256k1_scalar_set_b32(b, noncehash, NULL);
    secp256k1_ecmult(&fin_nonce_ptj, &aggnoncej[1], b, NULL);
    secp256k1_gej_add_ge(&fin_nonce_ptj, &fin_nonce_ptj, &aggnonce[0]);
    secp256k1_ge_set_gej(&fin_nonce_pt, &fin_nonce_ptj);

    if (secp256k1_ge_is_infinity(&fin_nonce_pt)) {
        /* unreachable with overwhelming probability */
        return 0;
    }
    secp256k1_fe_normalize_var(&fin_nonce_pt.x);
    secp256k1_fe_get_b32(fin_nonce, &fin_nonce_pt.x);

    secp256k1_fe_normalize_var(&fin_nonce_pt.y);
    *fin_nonce_parity = secp256k1_fe_is_odd(&fin_nonce_pt.y);
    return 1;
}

static void secp256k1_frost_lagrange_coefficient(secp256k1_scalar *r, const secp256k1_frost_pubnonce * const* pubnonces, uint16_t n_participants, uint16_t idx) {
    uint16_t i;
    secp256k1_scalar num;
    secp256k1_scalar den;
    secp256k1_scalar party_idx;

    secp256k1_scalar_set_int(&num, 1);
    secp256k1_scalar_set_int(&den, 1);
    secp256k1_scalar_set_int(&party_idx, idx);
    for (i = 0; i < n_participants; i++) {
        uint16_t counterparty_idx;
        secp256k1_scalar mul;

        secp256k1_frost_pubnonce_load_idx(&counterparty_idx, pubnonces[i]);
        if (counterparty_idx == idx) {
            continue;
        }

        secp256k1_scalar_set_int(&mul, counterparty_idx);
        secp256k1_scalar_negate(&mul, &mul);
        secp256k1_scalar_mul(&num, &num, &mul);

        secp256k1_scalar_add(&mul, &mul, &party_idx);
        secp256k1_scalar_mul(&den, &den, &mul);
    }

    secp256k1_scalar_inverse_var(&den, &den);
    secp256k1_scalar_mul(r, &num, &den);
}

int secp256k1_frost_nonce_process(const secp256k1_context* ctx, secp256k1_frost_session *session, const secp256k1_frost_aggnonce *aggnonce, const secp256k1_frost_pubnonce * const* pubnonces, uint16_t n_pubnonces, const unsigned char *msg32, const secp256k1_xonly_pubkey *agg_pk, uint16_t idx) {
    secp256k1_ge aggnonce_pt[2];
    secp256k1_gej aggnonce_ptj[2];
    unsigned char fin_nonce[32];
    secp256k1_frost_session_internal session_i;
    unsigned char agg_pk32[32];
    secp256k1_scalar l;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(aggnonce != NULL);
    ARG_CHECK(msg32 != NULL);

    if (!secp256k1_xonly_pubkey_serialize(ctx, agg_pk32, agg_pk)) {
        return 0;
    }

    if (!secp256k1_frost_aggnonce_load(ctx, aggnonce_pt, aggnonce)) {
        return 0;
    }
    secp256k1_gej_set_ge(&aggnonce_ptj[0], &aggnonce_pt[0]);
    secp256k1_gej_set_ge(&aggnonce_ptj[1], &aggnonce_pt[1]);
    if (!secp256k1_frost_nonce_process_internal(ctx, &session_i.fin_nonce_parity, fin_nonce, &session_i.noncecoef, aggnonce_ptj, msg32, pubnonces, n_pubnonces)) {
        return 0;
    }

    secp256k1_schnorrsig_challenge(&session_i.challenge, fin_nonce, msg32, 32, agg_pk32);
    secp256k1_frost_lagrange_coefficient(&l, pubnonces, n_pubnonces, idx);
    secp256k1_scalar_mul(&session_i.challenge, &session_i.challenge, &l);
    secp256k1_scalar_set_int(&session_i.s_part, 0);
    memcpy(session_i.fin_nonce, fin_nonce, sizeof(session_i.fin_nonce));
    secp256k1_frost_session_save(session, &session_i);
    return 1;
}

void secp256k1_frost_partial_sign_clear(secp256k1_scalar *sk, secp256k1_scalar *k) {
    secp256k1_scalar_clear(sk);
    secp256k1_scalar_clear(&k[0]);
    secp256k1_scalar_clear(&k[1]);
}

/* TODO: partial sig verification function */
int secp256k1_frost_partial_sign(const secp256k1_context* ctx, secp256k1_frost_partial_sig *partial_sig, secp256k1_frost_secnonce *secnonce, const secp256k1_frost_share *agg_share, const secp256k1_frost_session *session) {
    secp256k1_scalar sk;
    secp256k1_scalar k[2];
    secp256k1_scalar s;
    secp256k1_frost_session_internal session_i;
    int ret;
    int overflow;

    VERIFY_CHECK(ctx != NULL);

    ARG_CHECK(secnonce != NULL);
    /* Fails if the magic doesn't match */
    ret = secp256k1_frost_secnonce_load(ctx, k, secnonce);
    /* Set nonce to zero to avoid nonce reuse. This will cause subsequent calls
     * of this function to fail */
    memset(secnonce, 0, sizeof(*secnonce));
    if (!ret) {
        secp256k1_frost_partial_sign_clear(&sk, k);
        return 0;
    }

    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(agg_share != NULL);
    ARG_CHECK(session != NULL);

    secp256k1_scalar_set_b32(&sk, agg_share->data, &overflow);
    if (overflow) {
        return 0;
    }
    if (!secp256k1_frost_session_load(ctx, &session_i, session)) {
        secp256k1_frost_partial_sign_clear(&sk, k);
        return 0;
    }
    if (session_i.fin_nonce_parity) {
        secp256k1_scalar_negate(&k[0], &k[0]);
        secp256k1_scalar_negate(&k[1], &k[1]);
    }

    /* Sign */
    secp256k1_scalar_mul(&s, &session_i.challenge, &sk);
    secp256k1_scalar_mul(&k[1], &session_i.noncecoef, &k[1]);
    secp256k1_scalar_add(&k[0], &k[0], &k[1]);
    secp256k1_scalar_add(&s, &s, &k[0]);
    secp256k1_frost_partial_sig_save(partial_sig, &s);
    secp256k1_frost_partial_sign_clear(&sk, k);
    return 1;
}

int secp256k1_frost_partial_sig_agg(const secp256k1_context* ctx, unsigned char *sig64, const secp256k1_frost_session *session, const secp256k1_frost_partial_sig * const* partial_sigs, uint16_t n_sigs) {
    uint16_t i;
    secp256k1_frost_session_internal session_i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(partial_sigs != NULL);
    ARG_CHECK(n_sigs > 0);

    if (!secp256k1_frost_session_load(ctx, &session_i, session)) {
        return 0;
    }
    for (i = 0; i < n_sigs; i++) {
        secp256k1_scalar term;
        if (!secp256k1_frost_partial_sig_load(ctx, &term, partial_sigs[i])) {
            return 0;
        }
        secp256k1_scalar_add(&session_i.s_part, &session_i.s_part, &term);
    }
    secp256k1_scalar_get_b32(&sig64[32], &session_i.s_part);
    memcpy(&sig64[0], session_i.fin_nonce, 32);
    return 1;
}

#endif
