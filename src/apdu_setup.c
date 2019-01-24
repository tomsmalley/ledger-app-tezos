#include "apdu_setup.h"

#include "globals.h"
#include "keys.h"
#include "os_cx.h"

static struct apdu_setup_globals const *const glob = global.u.setup;

struct setup_wire {
  uint32_t main_chain_id;
  struct {
    uint32_t main;
    uint32_t test;
  } hwm;
  struct bip32_path_wire bip32_path;
} __attribute__((packed));

static size_t provide_pubkey(uint8_t *const io_buffer, cx_ecfp_public_key_t const *const pubkey) {
    size_t tx = 0;
    io_buffer[tx++] = pubkey->W_len;
    memmove(io_buffer + tx, pubkey->W, pubkey->W_len);
    tx += pubkey->W_len;
    io_buffer[tx++] = 0x90;
    io_buffer[tx++] = 0x00;
    return tx;
}

static bool ok(void) {
    authorize_baking(glob->curve, &glob->bip32_path);
    delayed_send(provide_pubkey(G_io_apdu_buffer, &global.u.setup.public_key););
    return true;
}

#define CONSUME(counter, type, addr) ({ counter += sizeof(type); READ_UNALIGNED_BIG_ENDIAN(type, addr); })

unsigned int handle_apdu_setup(__attribute__((unused)) uint8_t instruction) {
    if (READ_UNALIGNED_BIG_ENDIAN(uint8_t, G_io_apdu_buffer[OFFSET_P1]) != 0) THROW(EXC_WRONG_PARAM);

    uint8_t *const dataBuffer = &G_io_apdu_buffer[OFFSET_CDATA];
    struct setup_wire const *const buf_as_setup = dataBuffer;
    uint32_t const dataLength = READ_UNALIGNED_BIG_ENDIAN(uint8_t, G_io_apdu_buffer[OFFSET_LC]);
    if (dataLength < sizeof(setup_wire)) THROW(EXC_WRONG_LENGTH_FOR_INS);

    uint8_t const curve_code = READ_UNALIGNED_BIG_ENDIAN(uint8_t, G_io_apdu_buffer[OFFSET_CURVE]);
    glob->curve = curve_code_to_curve(curve_code);

    size_t consumed = 0;
    glob->main_chain_id.v = CONSUME(consumed, uint32_t, &buf_as_setup->main_chain_id);
    glob->hwm.main = CONSUME(consumed, uint32_t, &buf_as_setup->hwm.main);
    glob->hwm.test = CONSUME(consumed, uint32_t, &buf_as_setup->hwm.test);
    read_bip32_path(dataLength - consumed, &buf_as_setup->bip32_path, &glob->bip32_path);

    struct key_pair *const pair = generate_key_pair(glob->curve, &glob->bip32_path);
    memset(&pair->private_key, 0, sizeof(pair->private_key));
    memcpy(&glob->public_key, &pair->public_key, sizeof(glob->public_key));

    prompt_address(bake, global.u.pubkey.curve, &global.u.pubkey.public_key, ok, delay_reject);
}

