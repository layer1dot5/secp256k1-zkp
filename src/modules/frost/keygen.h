/**********************************************************************
 * Copyright (c) 2021, 2022 Jesse Posner                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_FROST_KEYGEN_H
#define SECP256K1_MODULE_FROST_KEYGEN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_frost.h"

#include "../../group.h"
#include "../../scalar.h"

typedef struct {
    secp256k1_ge pk;
    secp256k1_scalar tweak;
    int parity_acc;
} secp256k1_tweak_cache_internal;

static int secp256k1_tweak_cache_load(const secp256k1_context* ctx, secp256k1_tweak_cache_internal *cache_i, const secp256k1_frost_tweak_cache *cache);

static int secp256k1_frost_compute_indexhash(const secp256k1_context *ctx, secp256k1_scalar *indexhash, const secp256k1_xonly_pubkey *pk);

#endif
