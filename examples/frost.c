/***********************************************************************
 * Copyright (c) 2021, 2022 Jesse Posner                               *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

/**
 * This file demonstrates how to use the FROST module to create a threshold
 * signature. Additionally, see the documentation in include/secp256k1_frost.h.
 */

#include <stdio.h>
#include <assert.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_frost.h>

#include "random.h"

 /* Number of public keys involved in creating the aggregate signature */
#define N_SIGNERS 5

 /* Threshold required in creating the aggregate signature */
#define THRESHOLD 3

struct signer_secrets {
    secp256k1_keypair keypair;
    secp256k1_frost_share agg_share;
    secp256k1_frost_secnonce secnonce;
};

struct signer {
    secp256k1_xonly_pubkey pubkey;
    secp256k1_pubkey share_pk;
    secp256k1_frost_pubnonce pubnonce;
    secp256k1_frost_session session;
    secp256k1_frost_partial_sig partial_sig;
    secp256k1_pubkey vss_commitment[THRESHOLD];
    unsigned char vss_hash[32];
};

 /* Create a key pair and store it in seckey and pubkey */
int create_keypair(const secp256k1_context* ctx, struct signer_secrets *signer_secrets, struct signer *signer) {
    unsigned char seckey[32];
    FILE *frand = fopen("/dev/urandom", "r");
    if (frand == NULL) {
        return 0;
    }
    do {
        if(!fread(seckey, sizeof(seckey), 1, frand)) {
             fclose(frand);
             return 0;
         }
    /* The probability that this not a valid secret key is approximately 2^-128 */
    } while (!secp256k1_ec_seckey_verify(ctx, seckey));
    fclose(frand);
    if (!secp256k1_keypair_create(ctx, &signer_secrets->keypair, seckey)) {
        return 0;
    }
    if (!secp256k1_keypair_xonly_pub(ctx, &signer->pubkey, NULL, &signer_secrets->keypair)) {
        return 0;
    }
    return 1;
}

 /* Create shares and coefficient commitments */
int create_shares(const secp256k1_context* ctx, struct signer_secrets *signer_secrets, struct signer *signer, secp256k1_xonly_pubkey *agg_pk) {
    int i, j;
    secp256k1_frost_share shares[N_SIGNERS][N_SIGNERS];
    const secp256k1_pubkey *vss_commitments[N_SIGNERS];

    for (i = 0; i < N_SIGNERS; i++) {
        FILE *frand;
        unsigned char session_id[32];
        /* Create random session ID. It is absolutely necessary that the session ID
         * is unique for every call of secp256k1_frost_share_gen for a given pubkey. */
        frand = fopen("/dev/urandom", "r");
        if(frand == NULL) {
            return 0;
        }
        if (!fread(session_id, 32, 1, frand)) {
            fclose(frand);
            return 0;
        }
        fclose(frand);
        /* Generate a polynomial share for the first participant and save the
         * vss commitment */
        if (!secp256k1_frost_share_gen(ctx, signer[i].vss_commitment, &shares[i][0], session_id, &signer_secrets[i].keypair, &signer[0].pubkey, THRESHOLD)) {
            return 0;
        }
        vss_commitments[i] = signer[i].vss_commitment;
        for (j = 1; j < N_SIGNERS; j++) {
            /* Generate a polynomial share for the remaining participants */
            if (!secp256k1_frost_share_gen(ctx, NULL, &shares[i][j], session_id, &signer_secrets[i].keypair, &signer[j].pubkey, THRESHOLD)) {
                return 0;
            }
        }
    }

    /* KeyGen communication round 1: exchange shares, nonce commitments, and
     * coefficient commitments */
    for (i = 0; i < N_SIGNERS; i++) {
        const secp256k1_frost_share *assigned_shares[N_SIGNERS];

        /* Each participant receives a share from each participant (including
         * themselves) corresponding to their index. */
        for (j = 0; j < N_SIGNERS; j++) {
            assigned_shares[j] = &shares[j][i];
        }
        /* Each participant aggregates the shares they received. */
        if (!secp256k1_frost_share_agg(ctx, &signer_secrets[i].agg_share, &signer[i].share_pk, agg_pk, signer[i].vss_hash, assigned_shares, vss_commitments, N_SIGNERS, THRESHOLD, &signer[i].pubkey)) {
            return 0;
        }
    }

    return 1;
}

/* Sign the VSS commitments */
int sign_vss(const secp256k1_context* ctx, struct signer_secrets *signer_secrets, struct signer *signer, unsigned char sigs[N_SIGNERS][64]) {
    int i;

    for (i = 0; i < N_SIGNERS; i++) {
        FILE *frand;
        unsigned char aux_rand[32];

        frand = fopen("/dev/urandom", "r");
        if(frand == NULL) {
            return 0;
        }
        if (!fread(aux_rand, 32, 1, frand)) {
            fclose(frand);
            return 0;
        }
        fclose(frand);

        if (!secp256k1_schnorrsig_sign32(ctx, sigs[i], signer[i].vss_hash, &signer_secrets[i].keypair, aux_rand)) {
            return 0;
        }
    }

    return 1;
}

/* Sign a message hash with the given threshold and aggregate shares and store
 * the result in sig */
int sign(const secp256k1_context* ctx, struct signer_secrets *signer_secrets, struct signer *signer, const unsigned char* msg32, secp256k1_xonly_pubkey *agg_pk, unsigned char *sig64) {
    int i;
    int idx = 0;
    int signers = 0;
    const secp256k1_frost_pubnonce *pubnonces[THRESHOLD];
    const secp256k1_xonly_pubkey *pubkeys[THRESHOLD];
    const secp256k1_frost_partial_sig *partial_sigs[THRESHOLD];
    unsigned char seed[THRESHOLD];

    for (i = 0; i < N_SIGNERS; i++) {
        FILE *frand;
        unsigned char seckey[32];
        unsigned char session_id[32];
        /* Create random session ID. It is absolutely necessary that the session ID
         * is unique for every call of secp256k1_frost_nonce_gen. Otherwise
         * it's trivial for an attacker to extract the secret key! */
        frand = fopen("/dev/urandom", "r");
        if(frand == NULL) {
            return 0;
        }
        if (!fread(session_id, 32, 1, frand)) {
            fclose(frand);
            return 0;
        }
        fclose(frand);
        if (!secp256k1_keypair_sec(ctx, seckey, &signer_secrets[i].keypair)) {
            return 0;
        }
        /* Initialize session and create secret nonce for signing and public
         * nonce to send to the other signers. */
        if (!secp256k1_frost_nonce_gen(ctx, &signer_secrets[i].secnonce, &signer[i].pubnonce, session_id, &signer_secrets[i].agg_share, msg32, agg_pk, NULL)) {
            return 0;
        }
    }

    for (i =0; i < THRESHOLD; i++) {
        while (1) {
            if (!fill_random(&seed[i], 1)) {
                return 0;
            }
            idx = seed[i] % N_SIGNERS;
            if (!(signers & (1 << idx))) {
                break;
            }
        }
        signers = signers ^ (1 << idx);
        pubnonces[i] = &signer[idx].pubnonce;
        pubkeys[i] = &signer[idx].pubkey;
    }
    /* Signing communication round 1: Exchange nonces */
    for (i = 0; i < THRESHOLD; i++) {
        idx = seed[i] % N_SIGNERS;
        if (!secp256k1_frost_nonce_process(ctx, &signer[idx].session, pubnonces, THRESHOLD, msg32, agg_pk, &signer[idx].pubkey, pubkeys)) {
            return 0;
        }
        /* partial_sign will clear the secnonce by setting it to 0. That's because
         * you must _never_ reuse the secnonce (or use the same session_id to
         * create a secnonce). If you do, you effectively reuse the nonce and
         * leak the secret key. */
        if (!secp256k1_frost_partial_sign(ctx, &signer[idx].partial_sig, &signer_secrets[idx].secnonce, &signer_secrets[idx].agg_share, &signer[idx].session)) {
            return 0;
        }
        partial_sigs[i] = &signer[idx].partial_sig;
    }
    /* Communication round 2: A production system would exchange
     * partial signatures here before moving on. */
    for (i = 0; i < THRESHOLD; i++) {
        idx = seed[i] % N_SIGNERS;
        /* To check whether signing was successful, it suffices to either verify
         * the aggregate signature with the aggregate public key using
         * secp256k1_schnorrsig_verify, or verify all partial signatures of all
         * signers individually. Verifying the aggregate signature is cheaper but
         * verifying the individual partial signatures has the advantage that it
         * can be used to determine which of the partial signatures are invalid
         * (if any), i.e., which of the partial signatures cause the aggregate
         * signature to be invalid and thus the protocol run to fail. It's also
         * fine to first verify the aggregate sig, and only verify the individual
         * sigs if it does not work.
         */
        if (!secp256k1_frost_partial_sig_verify(ctx, &signer[idx].partial_sig, &signer[idx].pubnonce, &signer[idx].share_pk, &signer[idx].session)) {
            return 0;
        }
    }
    return secp256k1_frost_partial_sig_agg(ctx, sig64, &signer[idx].session, partial_sigs, THRESHOLD);
}

int main(void) {
    secp256k1_context* ctx;
    int i;
    struct signer_secrets signer_secrets[N_SIGNERS];
    struct signer signers[N_SIGNERS];
    unsigned char sigs[N_SIGNERS][64];
    secp256k1_xonly_pubkey agg_pk;
    unsigned char msg[32] = "this_could_be_the_hash_of_a_msg!";
    unsigned char sig[64];

    /* Create a context for signing and verification */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    printf("Creating key pairs......");
    for (i = 0; i < N_SIGNERS; i++) {
        if (!create_keypair(ctx, &signer_secrets[i], &signers[i])) {
            printf("FAILED\n");
            return 1;
        }
    }
    printf("ok\n");
    printf("Creating shares......");
    if (!create_shares(ctx, signer_secrets, signers, &agg_pk)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    printf("Signing VSS proofs......");
    if (!sign_vss(ctx, signer_secrets, signers, sigs)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    printf("Verifying VSS proof signatures.....");
    for (i = 0; i < N_SIGNERS; i++) {
        if (!secp256k1_schnorrsig_verify(ctx, sigs[i], signers[0].vss_hash, 32, &signers[i].pubkey)) {
            printf("FAILED\n");
            return 1;
        }
    }
    printf("ok\n");
    printf("Signing message with FROST.........");
    if (!sign(ctx, signer_secrets, signers, msg, &agg_pk, sig)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    printf("Verifying signature.....");
    if (!secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &agg_pk)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    secp256k1_context_destroy(ctx);
    return 0;
}
