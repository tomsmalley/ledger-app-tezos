#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "exception.h"
#include "os_cx.h"
#include "types.h"

// throws
void read_bip32_path(/*in*/ size_t buf_size, /*in*/ uint8_t const *buf, /*out*/ bip32_path_t *const out);

struct key_pair *generate_key_pair(cx_curve_t const curve, bip32_path_t const *const bip32_path);

cx_ecfp_public_key_t *public_key_hash(uint8_t output[HASH_SIZE], cx_curve_t curve,
                                      const cx_ecfp_public_key_t *restrict public_key);

enum curve_code {
    TEZOS_ED,
    TEZOS_SECP256K1,
    TEZOS_SECP256R1,
    TEZOS_NO_CURVE = 255,
};

static inline uint8_t curve_to_curve_code(cx_curve_t curve) {
    switch(curve) {
        case CX_CURVE_Ed25519:
            return TEZOS_ED;
        case CX_CURVE_SECP256K1:
            return TEZOS_SECP256K1;
        case CX_CURVE_SECP256R1:
            return TEZOS_SECP256R1;
        default:
            THROW(EXC_MEMORY_ERROR);
    }
}

static inline cx_curve_t curve_code_to_curve(uint8_t curve_code) {
    static const cx_curve_t curves[] = { CX_CURVE_Ed25519, CX_CURVE_SECP256K1, CX_CURVE_SECP256R1 };
    if (curve_code > sizeof(curves) / sizeof(*curves)) {
        THROW(EXC_WRONG_PARAM);
    }
    return curves[curve_code];
}
