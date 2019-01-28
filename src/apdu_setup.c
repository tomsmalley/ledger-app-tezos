#include "apdu_setup.h"

#include "apdu.h"
#include "cx.h"
#include "globals.h"
#include "keys.h"
#include "to_string.h"
#include "ui_prompt.h"
#include "ui.h"

#include <string.h>

#define G global.u.setup

struct setup_wire {
    uint32_t main_chain_id;
    struct {
        uint32_t main;
        uint32_t test;
    } hwm;
    struct bip32_path_wire bip32_path;
} __attribute__((packed));

static bool ok(void) {
    UPDATE_NVRAM(ram, {
        ram->curve = G.curve;
        copy_bip32_path(&ram->bip32_path, &G.bip32_path);
        ram->main_chain_id = G.main_chain_id;
        ram->hwm.main.highest_level = G.hwm.main;
        ram->hwm.main.had_endorsement = false;
        ram->hwm.test.highest_level = G.hwm.test;
        ram->hwm.test.had_endorsement = false;
    });
    delayed_send(provide_pubkey(G_io_apdu_buffer, &G.public_key));
    return true;
}

#define SET_STATIC_UI_VALUE(index, str) register_ui_callback(index, copy_string, STATIC_UI_VALUE(str))

__attribute__((noreturn)) static void prompt_setup(
    cx_curve_t const curve,
    cx_ecfp_public_key_t const *const key,
    ui_callback_t const ok_cb,
    ui_callback_t const cxl_cb)
{
    static const size_t TYPE_INDEX = 0;
    static const size_t ADDRESS_INDEX = 1;
    static const size_t CHAIN_INDEX = 2;
    static const size_t MAIN_HWM_INDEX = 3;
    static const size_t TEST_HWM_INDEX = 4;

    static const char *const prompts[] = {
        PROMPT("Authorize"),
        PROMPT("Address"),
        PROMPT("Chain"),
        PROMPT("Main Chain HWM"),
        PROMPT("Test Chain HWM"),
        NULL,
    };

    pubkey_to_pkh_string(G.ui.pkh, sizeof(G.ui.pkh), curve, key);

    SET_STATIC_UI_VALUE(TYPE_INDEX, "Baking?");
    register_ui_callback(ADDRESS_INDEX, copy_string, &G.ui.pkh);
    register_ui_callback(CHAIN_INDEX, chain_id_to_string, &G.main_chain_id);
    register_ui_callback(MAIN_HWM_INDEX, number_to_string_indirect32, &G.hwm.main);
    register_ui_callback(TEST_HWM_INDEX, number_to_string_indirect32, &G.hwm.test);

    ui_prompt(prompts, NULL, ok_cb, cxl_cb);
}

unsigned int handle_apdu_setup(__attribute__((unused)) uint8_t instruction) {
    if (READ_UNALIGNED_BIG_ENDIAN(uint8_t, &G_io_apdu_buffer[OFFSET_P1]) != 0) THROW(EXC_WRONG_PARAM);

    struct setup_wire const *const buf_as_setup = (struct setup_wire const *)&G_io_apdu_buffer[OFFSET_CDATA];
    uint32_t const dataLength = READ_UNALIGNED_BIG_ENDIAN(uint8_t, &G_io_apdu_buffer[OFFSET_LC]);
    if (dataLength < sizeof(struct setup_wire)) THROW(EXC_WRONG_LENGTH_FOR_INS);

    uint8_t const curve_code = READ_UNALIGNED_BIG_ENDIAN(uint8_t, &G_io_apdu_buffer[OFFSET_CURVE]);
    G.curve = curve_code_to_curve(curve_code);

    size_t consumed = 0;
    G.main_chain_id.v = CONSUME_UNALIGNED_BIG_ENDIAN(consumed, uint32_t, (uint8_t const *)&buf_as_setup->main_chain_id);
    G.hwm.main = CONSUME_UNALIGNED_BIG_ENDIAN(consumed, uint32_t, (uint8_t const *)&buf_as_setup->hwm.main);
    G.hwm.test = CONSUME_UNALIGNED_BIG_ENDIAN(consumed, uint32_t, (uint8_t const *)&buf_as_setup->hwm.test);
    read_bip32_path(&G.bip32_path, (uint8_t const *)&buf_as_setup->bip32_path, dataLength - consumed);

    struct key_pair *const pair = generate_key_pair(G.curve, &G.bip32_path);
    memset(&pair->private_key, 0, sizeof(pair->private_key));
    memcpy(&G.public_key, &pair->public_key, sizeof(G.public_key));

    prompt_setup(global.u.pubkey.curve, &global.u.pubkey.public_key, ok, delay_reject);
}
