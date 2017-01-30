/*******************************************************************************
*   OtherDime : Attestation demonstration
*   (c) 2017 Ledger
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
#include "os.h"
#include "cx.h"
#include <stdbool.h>

#include "os_io_seproxyhal.h"
#include "string.h"

#include "glyphs.h"

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

void ui_idle(void);

#define CLA 0xE0

#define INS_GET_PUBLIC_KEY 0x00
#define INS_SIGN 0x02
#define INS_GET_ATTESTATION_DATA 0x04
#define INS_EXPORT 0x06
#define INS_IMPORT 0x08
#define INS_CREATE_KEY 0x0A
#define INS_STATUS 0x0C

#define ROLE_ENDORSEMENT_SIGNER 0xFE
#define ROLE_EXPORT 0x01
#define ROLE_IMPORT 0x02

#define SW_OK 0x9000
#define SW_CONDITIONS_NOT_SATISFIED 0x6985
#define SW_INVALID_DATA 0x6A80
#define SW_INCORRECT_P1_P2 0x6B00
#define SW_INTERNAL 0x6F00

#define SEALED 0xAD
#define UNSEALED 0x53

bagl_element_t tmp_element;

ux_state_t ux;
// display stepped screens
unsigned int ux_step;
unsigned int ux_step_count;

typedef enum {
    STEP_NONE = 0,
    STEP_EXPORT_1,
    STEP_EXPORT_2,
    STEP_IMPORT_1,
    STEP_IMPORT_2,
    STEP_IMPORT_3
} exchange_step_t;

cx_ecfp_private_key_t exchangePrivate;
cx_ecfp_public_key_t exchangePublic;
cx_aes_key_t aesKey;
uint8_t remotePublic[65];
uint8_t remoteAttestationPublic[65];
uint8_t step;
uint8_t status[10];
uint8_t refreshUi;
uint8_t replySize;

static const uint8_t STATUS_UNAVAILABLE[] = "Unavailable";
static const uint8_t STATUS_SEALED[] = "Sealed";
static const uint8_t STATUS_UNSEALED[] = "Unsealed";

static const uint8_t OWNER_PUBLIC_KEY[] = {
    0x04,

    0x7f, 0xb9, 0x56, 0x46, 0x9c, 0x5c, 0x9b, 0x89, 0x84, 0x0d, 0x55,
    0xb4, 0x35, 0x37, 0xe6, 0x6a, 0x98, 0xdd, 0x48, 0x11, 0xea, 0x0a,
    0x27, 0x22, 0x42, 0x72, 0xc2, 0xe5, 0x62, 0x29, 0x11, 0xe8,

    0x53, 0x7a, 0x2f, 0x8e, 0x86, 0xa4, 0x6b, 0xae, 0xc8, 0x28, 0x64,
    0xe9, 0x8d, 0xd0, 0x1e, 0x9c, 0xcc, 0x2f, 0x8b, 0xc5, 0xdf, 0xc9,
    0xcb, 0xe5, 0xa9, 0x1a, 0x29, 0x04, 0x98, 0xdd, 0x96, 0xe4};

typedef struct internalStorage_t {
#define STORAGE_MAGIC 0xDEAD1337
    uint32_t magic;
    cx_ecfp_private_key_t privateKey;
    uint8_t sealed;
    uint8_t available;

} internalStorage_t;

WIDE internalStorage_t N_storage_real;
#define N_storage (*(WIDE internalStorage_t *)PIC(&N_storage_real))

uint8_t import_export_step_1(uint8_t role);

#if TARGET_ID == 0x31100002
const bagl_element_t ui_idle_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x01, 11, 8, 16, 16, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_LOGO_LEDGER_MINI},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 33, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "OtherDime",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 34, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     status,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x01, 118, 14, 7, 4, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_DOWN},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x02, 29, 9, 14, 14, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_DASHBOARD_BADGE},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 50, 19, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "Quit app",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x02, 3, 14, 7, 4, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_UP},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

unsigned int ui_idle_nanos_button(unsigned int button_mask,
                                  unsigned int button_mask_counter);

unsigned int ui_idle_nanos_state;
unsigned int ui_idle_nanos_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        return (ui_idle_nanos_state == element->component.userid - 1);
    }
    return 1;
}

unsigned int ui_idle_nanos_button(unsigned int button_mask,
                                  unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // UP
        if (ui_idle_nanos_state != 0) {
            ui_idle_nanos_state--;
            UX_DISPLAY(ui_idle_nanos, ui_idle_nanos_prepro);
        }
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: // DOWN
        if (ui_idle_nanos_state != 1) {
            ui_idle_nanos_state++;
            UX_DISPLAY(ui_idle_nanos, ui_idle_nanos_prepro);
        }
        break;

    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: // Settings, EXIT
        if (ui_idle_nanos_state == 1) {
            os_sched_exit(NULL);
        }
        break;
    }
    return 0;
}

const bagl_element_t ui_confirm_exchange_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x01, 33, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 34, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "Exchange",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

};

unsigned int ui_confirm_exchange_nanos_button(unsigned int button_mask,
                                              unsigned int button_mask_counter);

unsigned int ui_confirm_exchange_nanos_state;
unsigned int ui_confirm_exchange_nanos_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        return (ui_confirm_exchange_nanos_state ==
                element->component.userid - 1);
    }
    return 1;
}

unsigned int
ui_confirm_exchange_nanos_button(unsigned int button_mask,
                                 unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        // confirm
        replySize = import_export_step_1(ROLE_EXPORT);
        step = STEP_EXPORT_1;
        G_io_apdu_buffer[replySize] = SW_OK >> 8;
        G_io_apdu_buffer[replySize + 1] = SW_OK & 0xff;
        // io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, replySize + 2);
        replySize += 2;
        refreshUi = 1;
        ui_idle();
        break;

    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        // deny
        G_io_apdu_buffer[0] = SW_CONDITIONS_NOT_SATISFIED >> 8;
        G_io_apdu_buffer[1] = SW_CONDITIONS_NOT_SATISFIED & 0xff;
        // io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
        replySize = 2;
        refreshUi = 1;
        ui_idle();
        break;

    default:
        break;
    }
}

const bagl_element_t ui_confirm_unseal_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x01, 33, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 34, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "Unseal",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

};

unsigned int ui_confirm_unseal_nanos_button(unsigned int button_mask,
                                            unsigned int button_mask_counter);

unsigned int ui_confirm_unseal_nanos_state;
unsigned int ui_confirm_unseal_nanos_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        return (ui_confirm_unseal_nanos_state == element->component.userid - 1);
    }
    return 1;
}

unsigned int ui_confirm_unseal_nanos_button(unsigned int button_mask,
                                            unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: {
        // confirm
        uint8_t sealed = UNSEALED;
        nvm_write(&N_storage.sealed, (void *)&sealed, 1);
        cx_ecdsa_sign(&N_storage.privateKey, CX_LAST | CX_RND_RFC6979,
                      CX_SHA256, G_io_apdu_buffer + 5, 32, G_io_apdu_buffer);
        G_io_apdu_buffer[0] = 0x30;
        replySize = G_io_apdu_buffer[1] + 2;
        G_io_apdu_buffer[replySize] = SW_OK >> 8;
        G_io_apdu_buffer[replySize + 1] = SW_OK & 0xff;
        replySize += 2;
        refreshUi = 1;
        ui_idle();
    } break;

    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        // deny
        G_io_apdu_buffer[0] = SW_CONDITIONS_NOT_SATISFIED >> 8;
        G_io_apdu_buffer[1] = SW_CONDITIONS_NOT_SATISFIED & 0xff;
        replySize = 2;
        refreshUi = 1;
        ui_idle();
        break;

    default:
        break;
    }
}

#endif // #if TARGET_ID == 0x31100002

void ui_idle(void) {
    if (!N_storage.available) {
        os_memmove(status, STATUS_UNAVAILABLE, sizeof(STATUS_UNAVAILABLE));
    } else {
        if (N_storage.sealed == SEALED) {
            os_memmove(status, STATUS_SEALED, sizeof(STATUS_SEALED));
        } else {
            os_memmove(status, STATUS_UNSEALED, sizeof(STATUS_UNSEALED));
        }
    }
    ui_idle_nanos_state = 0; // start by displaying the idle first screen
    UX_DISPLAY(ui_idle_nanos, ui_idle_nanos_prepro);
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        if (tx_len) {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

            if (channel & IO_RESET_AFTER_REPLIED) {
                reset();
            }
            return 0; // nothing received from the master so far (it's a tx
                      // transaction)
        } else {
            return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                          sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}

uint8_t import_export_step_1(uint8_t role) {
    // First stage of the exchange : generate an ephemeral keypair, commit it to
    // the current code hash
    // using attestation key 1
    cx_ecfp_generate_pair(CX_CURVE_256K1, &exchangePublic, &exchangePrivate, 0);
    os_memmove(G_io_apdu_buffer, exchangePublic.W, 65);
    G_io_apdu_buffer[100] = role;
    os_memmove(G_io_apdu_buffer + 101, exchangePublic.W, 65);
    os_endorsement_key1_sign_data(G_io_apdu_buffer + 100, 66,
                                  G_io_apdu_buffer + 65);
    return 65 + G_io_apdu_buffer[66] + 2;
}

void import_export_step_2() {
    // Second stage of the exchange : verify the attestation of the other party
    // against the common owner
    cx_ecfp_public_key_t tmpPublic;
    cx_sha256_t sha;
    uint8_t hash[32];
    uint8_t role = ROLE_ENDORSEMENT_SIGNER;
    uint8_t certificateLength;
    certificateLength = G_io_apdu_buffer[66 + 5] + 2;
    if ((certificateLength + 65) != G_io_apdu_buffer[4]) {
        THROW(SW_INVALID_DATA);
    }
    cx_ecfp_init_public_key(CX_CURVE_256K1, OWNER_PUBLIC_KEY,
                            sizeof(OWNER_PUBLIC_KEY), &tmpPublic);
    cx_sha256_init(&sha);
    cx_hash(&sha.header, 0, &role, 1, NULL);
    cx_hash(&sha.header, CX_LAST, G_io_apdu_buffer + 5, 65, hash);
    if (!cx_ecdsa_verify(&tmpPublic, CX_LAST, CX_SHA256, hash, 32,
                         G_io_apdu_buffer + 5 + 65, certificateLength)) {
        THROW(SW_INVALID_DATA);
    }
    os_memmove(remoteAttestationPublic, G_io_apdu_buffer + 5, 65);
}

void import_export_step_3(uint8_t role) {
    // Third stage of the exchange : verify the ephemeral key of the other party
    // against the common owner and common running code
    cx_ecfp_public_key_t tmpPublic;
    cx_sha256_t sha;
    uint8_t hash[32];
    uint8_t codeHash[32];
    uint8_t certificateLength;
    uint8_t secretPoint[65];
    os_endorsement_get_code_hash(codeHash);
    certificateLength = G_io_apdu_buffer[66 + 5] + 2;
    if ((certificateLength + 65) != G_io_apdu_buffer[4]) {
        THROW(SW_INVALID_DATA);
    }
    cx_ecfp_init_public_key(CX_CURVE_256K1, remoteAttestationPublic,
                            sizeof(remoteAttestationPublic), &tmpPublic);
    cx_sha256_init(&sha);
    cx_hash(&sha.header, 0, &role, 1, NULL);
    cx_hash(&sha.header, 0, G_io_apdu_buffer + 5, 65, NULL);
    cx_hash(&sha.header, CX_LAST, codeHash, sizeof(codeHash), hash);
    if (!cx_ecdsa_verify(&tmpPublic, CX_LAST, CX_SHA256, hash, 32,
                         G_io_apdu_buffer + 5 + 65, certificateLength)) {
        THROW(SW_INVALID_DATA);
    }
    // All go, prepare export
    if (cx_ecdh(&exchangePrivate, CX_ECDH_POINT, G_io_apdu_buffer + 5,
                secretPoint) != 65) {
        THROW(SW_INVALID_DATA);
    }
    secretPoint[0] = (secretPoint[64] & 1 ? 0x03 : 0x02);
    cx_hash_sha256(secretPoint, 33, secretPoint);
    cx_aes_init_key(secretPoint, 16, &aesKey);
}

void cleanup() {
    os_memset(&exchangePrivate, 0, sizeof(cx_ecfp_private_key_t));
    os_memset(&aesKey, 0, sizeof(cx_aes_key_t));
    step = STEP_NONE;
}

void sample_main(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        volatile unsigned short sw = 0;
        uint8_t available = N_storage.available;
        uint8_t sealed = N_storage.sealed;

        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                // no apdu received, well, reset the session, and reset the
                // bootloader configuration
                if (rx == 0) {
                    THROW(0x6982);
                }

                if (G_io_apdu_buffer[0] != CLA) {
                    THROW(0x6E00);
                }

                switch (G_io_apdu_buffer[1]) {
                case INS_EXPORT:

                    if (!N_storage.available) {
                        THROW(SW_CONDITIONS_NOT_SATISFIED);
                    }
                    if (N_storage.sealed != SEALED) {
                        THROW(SW_CONDITIONS_NOT_SATISFIED);
                    }
                    switch (G_io_apdu_buffer[2]) {
                    case 0x01:
                        flags |= IO_ASYNCH_REPLY;
                        ui_confirm_exchange_nanos_state = 0;
                        UX_DISPLAY(ui_confirm_exchange_nanos,
                                   ui_confirm_exchange_nanos_prepro);
                        break;
                    case 0x02: {
                        if (step != STEP_EXPORT_1) {
                            THROW(SW_CONDITIONS_NOT_SATISFIED);
                        }
                        import_export_step_2();
                        step = STEP_EXPORT_2;
                    } break;
                    case 0x03: {
                        // Exchange successful, export the key and delete it
                        uint8_t available;
                        if (step != STEP_EXPORT_2) {
                            THROW(SW_CONDITIONS_NOT_SATISFIED);
                        }
                        import_export_step_3(ROLE_IMPORT);
                        cx_rng(G_io_apdu_buffer, 16);
                        if (cx_aes_iv(&aesKey, CX_LAST | CX_ENCRYPT |
                                                   CX_PAD_NONE | CX_CHAIN_CBC,
                                      G_io_apdu_buffer, N_storage.privateKey.d,
                                      32, G_io_apdu_buffer + 16) != 32) {
                            THROW(SW_INTERNAL);
                        }
                        os_memset(&exchangePrivate, 0,
                                  sizeof(cx_ecfp_private_key_t));
                        nvm_write(&N_storage.privateKey,
                                  (void *)&exchangePrivate,
                                  sizeof(cx_ecfp_private_key_t));
                        available = 0;
                        nvm_write(&N_storage.available, (void *)&available, 1);
                        tx = 16 + 32;
                        cleanup();
                    } break;

                    default:
                        THROW(SW_INCORRECT_P1_P2);
                    }
                    break;

                case INS_IMPORT:
                    if (N_storage.available) {
                        THROW(SW_CONDITIONS_NOT_SATISFIED);
                    }
                    switch (G_io_apdu_buffer[2]) {
                    case 0x01:
                        tx = import_export_step_1(ROLE_IMPORT);
                        step = STEP_IMPORT_1;
                        break;
                    case 0x02: {
                        if (step != STEP_IMPORT_1) {
                            THROW(SW_CONDITIONS_NOT_SATISFIED);
                        }
                        import_export_step_2();
                        step = STEP_IMPORT_2;
                    } break;
                    case 0x03: {
                        if (step != STEP_IMPORT_2) {
                            THROW(SW_CONDITIONS_NOT_SATISFIED);
                        }
                        import_export_step_3(ROLE_EXPORT);
                        step = STEP_IMPORT_3;
                    } break;
                    case 0x04: {
                        // Exchange successful, import the encrypted key blob
                        uint8_t privateKey[32];
                        uint8_t available = 1;
                        uint8_t sealed = SEALED;
                        cx_ecfp_private_key_t tmpPrivate;
                        if (step != STEP_IMPORT_3) {
                            THROW(SW_CONDITIONS_NOT_SATISFIED);
                        }
                        if (cx_aes_iv(&aesKey, CX_LAST | CX_DECRYPT |
                                                   CX_PAD_NONE | CX_CHAIN_CBC,
                                      G_io_apdu_buffer + 5,
                                      G_io_apdu_buffer + 5 + 16, 32,
                                      privateKey) != 32) {
                            THROW(SW_INTERNAL);
                        }
                        cx_ecfp_init_private_key(CX_CURVE_256K1, privateKey,
                                                 sizeof(privateKey),
                                                 &tmpPrivate);
                        nvm_write(&N_storage.privateKey, (void *)&tmpPrivate,
                                  sizeof(cx_ecfp_private_key_t));
                        nvm_write(&N_storage.sealed, (void *)&sealed, 1);
                        nvm_write(&N_storage.available, (void *)&available, 1);
                        os_memset(&tmpPrivate, 0,
                                  sizeof(cx_ecfp_private_key_t));
                        os_memset(privateKey, 0, sizeof(privateKey));
                        cleanup();
                    } break;

                    default:
                        THROW(SW_INCORRECT_P1_P2);
                    }
                    break;

                case INS_GET_PUBLIC_KEY: {
                    cx_ecfp_private_key_t tmpPrivate;
                    cx_ecfp_public_key_t tmpPublic;
                    if (!N_storage.available) {
                        THROW(SW_CONDITIONS_NOT_SATISFIED);
                    }
                    os_memmove(&tmpPrivate, &N_storage.privateKey,
                               sizeof(cx_ecfp_private_key_t));
                    cx_ecfp_generate_pair(CX_CURVE_256K1, &tmpPublic,
                                          &tmpPrivate, 1);
                    os_memset(&tmpPrivate, 0, sizeof(cx_ecfp_private_key_t));
                    os_memmove(G_io_apdu_buffer, tmpPublic.W, 65);
                    tx = 65;
                } break;

                case INS_GET_ATTESTATION_DATA:
                    os_endorsement_get_public_key(1, G_io_apdu_buffer);
                    os_endorsement_get_public_key_certificate(
                        1, G_io_apdu_buffer + 65);
                    tx = 65 + G_io_apdu_buffer[66] + 2;
                    break;

                case INS_CREATE_KEY: {
                    uint8_t available = 1;
                    uint8_t sealed = SEALED;
                    cx_ecfp_private_key_t tmpPrivate;
                    cx_ecfp_public_key_t tmpPublic;
                    if (N_storage.available) {
                        THROW(SW_CONDITIONS_NOT_SATISFIED);
                    }
                    cx_ecfp_generate_pair(CX_CURVE_256K1, &tmpPublic,
                                          &tmpPrivate, 0);
                    nvm_write(&N_storage.privateKey, (void *)&tmpPrivate,
                              sizeof(cx_ecfp_private_key_t));
                    nvm_write(&N_storage.sealed, (void *)&sealed, 1);
                    nvm_write(&N_storage.available, (void *)&available, 1);
                    os_memset(&tmpPrivate, 0, sizeof(cx_ecfp_private_key_t));
                } break;

                case INS_SIGN: {
                    if (!N_storage.available) {
                        THROW(SW_CONDITIONS_NOT_SATISFIED);
                    }
                    if (N_storage.sealed == SEALED) {
                        flags |= IO_ASYNCH_REPLY;
                        ui_confirm_unseal_nanos_state = 0;
                        UX_DISPLAY(ui_confirm_unseal_nanos,
                                   ui_confirm_unseal_nanos_prepro);
                        break;
                    } else if (N_storage.sealed != UNSEALED) {
                        THROW(SW_CONDITIONS_NOT_SATISFIED);
                    }
                    cx_ecdsa_sign(&N_storage.privateKey,
                                  CX_LAST | CX_RND_RFC6979, CX_SHA256,
                                  G_io_apdu_buffer + 5, 32, G_io_apdu_buffer);
                    G_io_apdu_buffer[0] = 0x30;
                    tx = G_io_apdu_buffer[1] + 2;
                } break;

                case INS_STATUS:
                    G_io_apdu_buffer[0] = (N_storage.available != 0);
                    G_io_apdu_buffer[1] = (N_storage.available != 0) &&
                                          (N_storage.sealed == SEALED);
                    tx = 2;
                    break;
                }
                // default no error
                THROW(SW_OK);
            }
            CATCH_OTHER(e) {
                switch (e & 0xFFFFF000) {
                case 0x6000:
                    sw = e;
                    break;
                case SW_OK:
                    // ok
                    sw = e;
                    break;
                default:
                    // Internal error
                    sw = 0x6800 | (e & 0x7FF);
                    break;
                }
                if (sw != SW_OK) {
                    // Security cleanup
                    cleanup();
                }
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;

                refreshUi = ((available != N_storage.available) ||
                             (sealed != N_storage.sealed));
                if (refreshUi) {
                    flags |= IO_ASYNCH_REPLY;
                    replySize = tx;
                    ui_idle();
                }
            }
            FINALLY {
            }
        }
        END_TRY;
    }

    // return_to_dashboard:
    return;
}

// override point, but nothing more to do
void io_seproxyhal_display(const bagl_element_t *element) {
    // common icon element display,
    if ((element->component.type & (~BAGL_FLAG_TOUCHABLE)) == BAGL_ICON
        // this is a streamed icon from the app content
        && element->component.icon_id == 0 && element->text != NULL) {
        bagl_icon_details_t *icon = (bagl_icon_details_t *)PIC(element->text);
        // here could avoid the loop and do a pure aysnch stuff, but it's way
        // too sluggish
        io_seproxyhal_display_icon(element, icon);
        return;
    }
    io_seproxyhal_display_default((bagl_element_t *)element);
}

void display_done() {
    if (refreshUi) {
        refreshUi = 0;
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, replySize);
    }
}

unsigned char io_event(unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_FINGER_EVENT:
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_STATUS_EVENT:
        if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&
            !(U4BE(G_io_seproxyhal_spi_buffer, 3) &
              SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
            THROW(EXCEPTION_IO_RESET);
        }
    // no break is intentional
    default:
        UX_DEFAULT_EVENT();
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        UX_DISPLAYED_EVENT(display_done(););
        break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
        UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
            if (ux_step_count) {
                // prepare next screen
                ux_step = (ux_step + 1) % ux_step_count;
                // redisplay screen
                UX_REDISPLAY();
            }
        });
        break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

void app_exit(void) {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

__attribute__((section(".boot"))) int main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    UX_INIT();

    // ensure exception will work as planned
    os_boot();

    BEGIN_TRY {
        TRY {
            io_seproxyhal_init();

            if (N_storage.magic != STORAGE_MAGIC) {
                uint32_t magic = STORAGE_MAGIC;
                uint8_t available = 0x00;
                nvm_write(&N_storage.magic, (void *)&magic, sizeof(uint32_t));
                nvm_write(&N_storage.available, (void *)&available, 1);
            }

            step = STEP_NONE;
            refreshUi = 0;

            USB_power(1);

            ui_idle();

            sample_main();
        }
        CATCH_OTHER(e) {
        }
        FINALLY {
        }
    }
    END_TRY;

    app_exit();

    return 0;
}
