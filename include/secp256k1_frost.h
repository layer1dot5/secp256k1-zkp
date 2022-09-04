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
 *
 * Following the convention used in the MuSig module, the API uses the singular
 * term "nonce" to refer to the two "nonces" used by the FROST scheme.
 */

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

/** Opaque data structure that holds a signer's _secret_ nonce.
 *
 *  Guaranteed to be 68 bytes in size.
 *
 *  WARNING: This structure MUST NOT be copied or read or written to directly.
 *  A signer who is online throughout the whole process and can keep this
 *  structure in memory can use the provided API functions for a safe standard
 *  workflow. See
 *  https://blockstream.com/2019/02/18/musig-a-new-multisignature-standard/ for
 *  more details about the risks associated with serializing or deserializing
 *  this structure.
 *
 *  We repeat, copying this data structure can result in nonce reuse which will
 *  leak the secret signing key.
 */
typedef struct {
    unsigned char data[68];
} secp256k1_frost_secnonce;

/** Opaque data structure that holds a signer's public nonce.
*
*  Guaranteed to be 132 bytes in size. It can be safely copied/moved.
*  Serialized and parsed with `frost_pubnonce_serialize` and
*  `frost_pubnonce_parse`.
*/
typedef struct {
    unsigned char data[132];
} secp256k1_frost_pubnonce;

/** Parse a signer's public nonce.
 *
 *  Returns: 1 when the nonce could be parsed, 0 otherwise.
 *  Args:    ctx: a secp256k1 context object
 *  Out:   nonce: pointer to a nonce object
 *  In:     in66: pointer to the 66-byte nonce to be parsed
 */
SECP256K1_API int secp256k1_frost_pubnonce_parse(
    const secp256k1_context* ctx,
    secp256k1_frost_pubnonce* nonce,
    const unsigned char *in66
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize a signer's public nonce
 *
 *  Returns: 1 when the nonce could be serialized, 0 otherwise
 *  Args:    ctx: a secp256k1 context object
 *  Out:   out66: pointer to a 66-byte array to store the serialized nonce
 *  In:    nonce: pointer to the nonce
 */
SECP256K1_API int secp256k1_frost_pubnonce_serialize(
    const secp256k1_context* ctx,
    unsigned char *out66,
    const secp256k1_frost_pubnonce* nonce
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

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

/** Aggregates shares
 *
 *  As part of the key generation protocol, each participant receives a share
 *  from each participant, including a share they "receive" from themselves.
 *  This function verifies those shares against their VSS commitments,
 *  aggregates the shares, and then aggregates the commitments to each
 *  participant's first polynomial coefficient to derive the aggregate public
 *  key.
 *
 *  This function outputs a vss_hash, which is a sha256 image of the VSS of all
 *  participants. The vss_hash _must_ be signed and distributed to each other
 *  participant, and upon receiving a signed vss_hash from each other
 *  participant, the signature must be verified against the vss_hash generated
 *  by the receiving participant, otherwise the key generation session must be
 *  aborted. This vss_commitments _must_ be sorted by the x-only pubkeys of the
 *  participants, otherwise the vss_hash generated will be invalid.
 *
 *  If this function returns an error, `secp256k1_frost_share_verify` can be
 *  called on each share to determine which participants submitted faulty
 *  shares.
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise (which does NOT mean
 *           the resulting signature verifies).
 *  Args:         ctx: pointer to a context object
 *  Out:    agg_share: the aggregated share
 *             agg_pk: the aggregated x-only public key
 *           vss_hash: sha256 image of the coefficient commitments
 *  In:        shares: all key generation shares for the partcipant's index
 *    vss_commitments: coefficient commitments of all participants ordered by
 *                     the x-only pubkeys of the participants
 *           n_shares: the total number of shares
 *          threshold: the minimum number of shares required to produce a
 *                     signature
 *                 pk: the public key of the participant whose shares are being
 *                     aggregated
 */
SECP256K1_API int secp256k1_frost_share_agg(
    const secp256k1_context* ctx,
    secp256k1_frost_share *agg_share,
    secp256k1_xonly_pubkey *agg_pk,
    unsigned char *vss_hash,
    const secp256k1_frost_share * const* shares,
    const secp256k1_pubkey * const* vss_commitments,
    size_t n_shares,
    size_t threshold,
    const secp256k1_xonly_pubkey *pk
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(9);

/** Verifies a share received during a key generation session
 *
 *  The signature is verified against the VSS commitment received with the
 *  share.
 *
 *  Returns: 0 if the arguments are invalid or the share does not verify, 1
 *           otherwise
 *  Args         ctx: pointer to a context object, initialized for verification
 *  In:    threshold: the minimum number of signers required to produce a
 *                    signature
 *                pk: pointer to the public key of the share recipient
 *             share: pointer to a key generation share
 *    vss_commitment: the commitments to the coeffcieints used to generate the
 *                    share
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_share_verify(
    const secp256k1_context* ctx,
    size_t threshold,
    const secp256k1_xonly_pubkey *pk,
    const secp256k1_frost_share *share,
    const secp256k1_pubkey * const* vss_commitment
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

SECP256K1_API int secp256k1_frost_compute_pubshare(
    const secp256k1_context* ctx,
    secp256k1_pubkey *pubshare,
    size_t threshold,
    const secp256k1_xonly_pubkey *pk,
    const secp256k1_pubkey * const* vss_commitments,
    size_t n_participants
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Starts a signing session by generating a nonce
 *
 *  This function outputs a secret nonce that will be required for signing and a
 *  corresponding public nonce that is intended to be sent to other signers.
 *
 *  FROST, like MuSig, differs from regular Schnorr signing in that
 *  implementers _must_ take special care to not reuse a nonce. This can be
 *  ensured by following these rules:
 *
 *  1. Each call to this function must have a UNIQUE session_id32 that must NOT BE
 *     REUSED in subsequent calls to this function.
 *     If you do not provide a seckey, session_id32 _must_ be UNIFORMLY RANDOM
 *     AND KEPT SECRET (even from other signers). If you do provide a seckey,
 *     session_id32 can instead be a counter (that must never repeat!). However,
 *     it is recommended to always choose session_id32 uniformly at random.
 *  2. If you already know the seckey, message or aggregate public key, they
 *     can be optionally provided to derive the nonce and increase
 *     misuse-resistance. The extra_input32 argument can be used to provide
 *     additional data that does not repeat in normal scenarios, such as the
 *     current time.
 *  3. Avoid copying (or serializing) the secnonce. This reduces the possibility
 *     that it is used more than once for signing.
 *
 *  Remember that nonce reuse will leak the secret key!
 *  Note that using the same agg_share for multiple FROST sessions is fine.
 *
 *  Returns: 0 if the arguments are invalid and 1 otherwise
 *  Args:         ctx: pointer to a context object, initialized for signing
 *  Out:     secnonce: pointer to a structure to store the secret nonce
 *           pubnonce: pointer to a structure to store the public nonce
 *  In:  session_id32: a 32-byte session_id32 as explained above. Must be
 *                     unique to this call to secp256k1_frost_nonce_gen and
 *                     must be uniformly random unless you really know what you
 *                     are doing.
 *          agg_share: the aggregated share that will later be used for
 *                     signing, if already known (can be NULL)
 *              msg32: the 32-byte message that will later be signed, if
 *                     already known (can be NULL)
 *             agg_pk: the FROST-aggregated public key (can be NULL)
 *      extra_input32: an optional 32-byte array that is input to the nonce
 *                     derivation function (can be NULL)
 */
SECP256K1_API int secp256k1_frost_nonce_gen(
    const secp256k1_context* ctx,
    secp256k1_frost_secnonce *secnonce,
    secp256k1_frost_pubnonce *pubnonce,
    const unsigned char *session_id32,
    const secp256k1_frost_share *agg_share,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *agg_pk,
    const unsigned char *extra_input32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

 */

#ifdef __cplusplus
}
#endif

#endif
