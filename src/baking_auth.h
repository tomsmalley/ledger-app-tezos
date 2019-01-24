#pragma once

#include "apdu.h"
#include "operations.h"
#include "protocol.h"

#include <stdbool.h>
#include <stdint.h>

void authorize_baking(cx_curve_t curve, bip32_path_t const *const bip32_path);
void guard_baking_authorized(cx_curve_t curve, void *data, int datalen, bip32_path_t const *const bip32_path);
bool is_path_authorized(cx_curve_t curve, bip32_path_t const *const bip32_path);
void update_high_water_mark(void *data, int datalen);
void write_highest_level(level_t level, bool is_endorsement);
bool is_level_authorized(level_t level, bool is_endorsement);
bool is_valid_level(level_t level);
void update_auth_text(void);

void prompt_contract_for_baking(struct parsed_contract *contract, ui_callback_t ok_cb, ui_callback_t cxl_cb);
void prompt_address(bool bake, cx_curve_t curve,
                    const cx_ecfp_public_key_t *key,
                    ui_callback_t ok_cb, ui_callback_t cxl_cb) __attribute__((noreturn));

struct parsed_baking_data {
    bool is_endorsement;
    level_t level;
};
// Return false if it is invalid
bool parse_baking_data(const void *data, size_t length, struct parsed_baking_data *out);
