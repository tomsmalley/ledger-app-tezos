/*******************************************************************************
*   Ledger Blue
*   (c) 2016 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "keys.h"

#include "apdu.h"
#include "blake2.h"
#include "globals.h"
#include "protocol.h"
#include "types.h"

#include <stdbool.h>
#include <string.h>

struct bip32_path_wire {
    uint8_t length;
    uint32_t components[0];
} __attribute((packed))__;

void read_bip32_path(/*in*/ size_t buf_size, /*in*/ uint8_t const *buf, /*out*/ bip32_path_t *const out) {
    struct bip32_path_wire const *const buf_as_bip32 = (struct bip32_path_wire const *)buf;

    out->length = READ_UNALIGNED_BIG_ENDIAN(uint8_t, &buf_as_bip32->length);

    // TODO: Why the +1 below?
    if (buf_size < out->length * sizeof(*out->components) + 1) THROW(EXC_WRONG_LENGTH_FOR_INS);
    if (out->length == 0 || out->length > MAX_BIP32_PATH) THROW(EXC_WRONG_VALUES);

    for (size_t i = 0; i < out->length; i++) {
        out->components[i] = READ_UNALIGNED_BIG_ENDIAN(uint32_t, &buf_as_bip32->components[i]);
    }
}

struct key_pair *generate_key_pair(cx_curve_t const curve, bip32_path_t const *const bip32_path) {
    struct priv_generate_key_pair *const priv = &global.priv.generate_key_pair;

#if CX_APILEVEL > 8
    if (curve == CX_CURVE_Ed25519) {
        os_perso_derive_node_bip32_seed_key(
            HDW_ED25519_SLIP10, curve, bip32_path->components, bip32_path->length,
            priv->privateKeyData, NULL, NULL, 0);
    } else {
#endif
        os_perso_derive_node_bip32(curve, bip32_path->components, bip32_path->length, priv->privateKeyData, NULL);
#if CX_APILEVEL > 8
    }
#endif
    cx_ecfp_init_private_key(curve, priv->privateKeyData, sizeof(priv->privateKeyData), &priv->res.private_key);
    cx_ecfp_generate_pair(curve, &priv->res.public_key, &priv->res.private_key, 1);

    if (curve == CX_CURVE_Ed25519) {
        cx_edward_compress_point(
            curve,
            priv->res.public_key.W,
            priv->res.public_key.W_len);
        priv->res.public_key.W_len = 33;
    }
    memset(priv->privateKeyData, 0, sizeof(priv->privateKeyData));
    return &priv->res;
}

cx_ecfp_public_key_t *public_key_hash(uint8_t output[HASH_SIZE], cx_curve_t curve,
                                      const cx_ecfp_public_key_t *restrict public_key) {
    cx_ecfp_public_key_t *const compressed = &global.priv.public_key_hash.compressed;
    switch (curve) {
        case CX_CURVE_Ed25519:
            {
                compressed->W_len = public_key->W_len - 1;
                memcpy(compressed->W, public_key->W + 1, compressed->W_len);
                break;
            }
        case CX_CURVE_SECP256K1:
        case CX_CURVE_SECP256R1:
            {
                memcpy(compressed->W, public_key->W, public_key->W_len);
                compressed->W[0] = 0x02 + (public_key->W[64] & 0x01);
                compressed->W_len = 33;
                break;
            }
        default:
            THROW(EXC_WRONG_PARAM);
    }
    b2b_init(&global.blake2b.hash_state, HASH_SIZE);
    b2b_update(&global.blake2b.hash_state, compressed->W, compressed->W_len);
    b2b_final(&global.blake2b.hash_state, output, HASH_SIZE);
    return compressed;
}
