#ifndef SECP256K1_FROST_H
#define SECP256K1_FROST_H

#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** This code is currently a work in progress. It's not secure nor stable.  IT
 * IS EXTREMELY DANGEROUS AND RECKLESS TO USE THIS MODULE IN PRODUCTION!

 * This module implements a variant of Flexible Round-Optimized Schnorr
 * Threshold Signatures (FROST) by Chelsea Komlo and Ian Goldberg
 * (https://crysp.uwaterloo.ca/software/frost/). Signatures are compatible with
 * BIP-340 ("Schnorr").

/** Opaque data structures
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. If you
 *  need to convert to a format suitable for storage, transmission, or
 *  comparison, use the corresponding serialization and parsing functions.
 */

/** Opaque data structure that holds a signer's _secret_ share.
 *
 *  Guaranteed to be 36 bytes in size. Serialized and parsed with
 *  `frost_share_serialize` and `frost_share_parse`.
 */
typedef struct {
    unsigned char data[36];
} secp256k1_frost_share;

/** Serialize a FROST share
 *
 *  Returns: 1 when the share could be serialized, 0 otherwise
 *  Args:    ctx: a secp256k1 context object
 *  Out:   out32: pointer to a 32-byte array to store the serialized share
 *  In:    share: pointer to the share
 */
SECP256K1_API int secp256k1_frost_share_serialize(
    const secp256k1_context* ctx,
    unsigned char *out32,
    const secp256k1_frost_share* share
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse a FROST share.
 *
 *  Returns: 1 when the share could be parsed, 0 otherwise.
 *  Args:    ctx: a secp256k1 context object
 *  Out:   share: pointer to a share object
 *  In:     in32: pointer to the 32-byte share to be parsed
 */
SECP256K1_API int secp256k1_frost_share_parse(
    const secp256k1_context* ctx,
    secp256k1_frost_share* share,
    const unsigned char *in32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Creates a key generation share and verifiable secret sharing ("VSS")
 *  commitments.
 *
 *  To generate a key, each participant generates a share for each other
 *  participant. For example, in the case of 2 particpants, Alice and Bob, they
 *  each generate 2 shares, distribute 1 share to each other using a secure
 *  channel, and keep 1 for themselves.
 *
 *  Each participant _must_ have a secure channel with each other participant
 *  with which they can transmit shares to each other.
 *
 *  A new session_id32 _must_ be used for each key generation session. For
 *  example, in the case of 2 participants, Alice and Bob, Alice will generate
 *  a session_id32 and use it for each of the 2 calls to
 *  secp256k1_frost_share_gen and Bob will generate a session_id32 and use it
 *  for each of the 2 calls to secp256k1_frost_share_gen. Both Alice and Bob
 *  must NOT REUSE there respective session_id32 again for subsequent key
 *  generation sessions. If Alice and Bob fail to complete this session or
 *  start a new session to generate a new key, they must NOT REUSE their
 *  respective session_id32 again, but instead generate a new one. It is
 *  recommended to always choose session_id32 uniformly at random to avoid
 *  their reuse.
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:            ctx: pointer to a context object initialized for
 *                        verification
 *  Out:  vss_commitment: the coefficient commitments. The length of this array
 *                        must be equal to the threshold (can be NULL).
 *                 share: pointer to the key generation share
 *   In:    session_id32: a 32-byte session_id32 as explained above
 *               keypair: pointer to a keypair that contains the secret that is
 *                        shared
 *                    pk: pointer to the public key of the share recipient
 *             threshold: the minimum number of signers required to produce a
 *                        signature
 */
SECP256K1_API int secp256k1_frost_share_gen(
    const secp256k1_context *ctx,
    secp256k1_pubkey *vss_commitment,
    secp256k1_frost_share *share,
    const unsigned char *session_id32,
    const secp256k1_keypair *keypair,
    const secp256k1_xonly_pubkey *pk,
    size_t threshold
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);
 */

#ifdef __cplusplus
}
#endif

#endif
