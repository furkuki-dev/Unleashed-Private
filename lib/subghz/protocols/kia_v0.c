#include "kia_v0.h"

#include "../blocks/const.h"
#include "../blocks/decoder.h"
#include "../blocks/encoder.h"
#include "../blocks/generic.h"
#include "../blocks/math.h"
#include "../blocks/custom_btn_i.h"

#include <string.h>

#define TAG "SubGhzProtocolKiaV0"

static const SubGhzBlockConst subghz_protocol_kia_const = {
    .te_short = 250,
    .te_long = 500,
    .te_delta = 100,
    .min_count_bit_for_found = 61,
};

#define KIA_V0_TYPE_KIA    KIA_V0_SUBTYPE_KIA
#define KIA_V0_TYPE_SUZUKI KIA_V0_SUBTYPE_SUZUKI
#define KIA_V0_TYPE_HONDA  KIA_V0_SUBTYPE_HONDA

#define KIA_V0_BIT_COUNT_KIA    61U
#define KIA_V0_BIT_COUNT_SUZUKI 64U
#define KIA_V0_BIT_COUNT_HONDA  72U

#define KIA_V0_KIA_GAP      1000U
#define KIA_V0_KIA_GAP_BASE 700U
#define KIA_V0_KIA_GAP_SPAN 1000U

#define KIA_V0_SUZUKI_GAP      2000U
#define KIA_V0_SUZUKI_GAP_SPAN 500U

#define KIA_V0_TYPE1_SYNC           750U
#define KIA_V0_TYPE1_PREAMBLE_PAIRS 0x13FU
#define KIA_V0_TYPE2_PREAMBLE_PAIRS 0x140U
#define KIA_V0_TAIL_PREAMBLE_PAIRS  0x0FU

#define KIA_V0_UPLOAD_CAPACITY                                                  \
    ((KIA_V0_TYPE2_PREAMBLE_PAIRS * 2U) + (KIA_V0_BIT_COUNT_SUZUKI * 2U) + 3U + \
     (KIA_V0_TAIL_PREAMBLE_PAIRS * 2U) + (KIA_V0_BIT_COUNT_SUZUKI * 2U))
#define KIA_V0_ENCODER_DEFAULT_REPEAT 10U

typedef enum {
    KiaV0DecoderStepReset = 0,
    KiaV0DecoderStepPreamble = 1,
    KiaV0DecoderStepSaveDuration = 2,
    KiaV0DecoderStepCheckDuration = 3,
} KiaV0DecoderStep;

typedef struct {
    uint32_t serial;
    uint16_t counter;
    uint8_t button;
    uint8_t crc;
    uint8_t type;
    bool crc_valid;
} KiaV0Fields;

struct SubGhzProtocolDecoderKIA {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;
    uint16_t packet_bit_count;
    uint16_t preamble_pairs;
    uint8_t type;
};

struct SubGhzProtocolEncoderKIA {
    SubGhzProtocolEncoderBase base;
    SubGhzProtocolBlockEncoder encoder;
    SubGhzBlockGeneric generic;
    uint8_t type;
    KiaV0Fields fields;
};

static const uint8_t kia_v0_honda_crc_table[16] = {
    0x4A, 0x25, 0x96, 0x4B, 0xA1, 0xD4, 0x6A, 0x35,
    0x9E, 0x4F, 0xA3, 0xD5, 0xEE, 0x77, 0xBF, 0xDB,
};

static const char* const kia_v0_honda_button_names[7] = {
    "Unlock", "Trunk", "Lock2", "Unlock2", "Trunk2", "Unlock3", "Trunk3",
};

static inline uint8_t kia_v0_reverse_bits8(uint8_t value) {
    value = (uint8_t)(((value >> 4U) | (value << 4U)) & 0xFFU);
    value = (uint8_t)(((value & 0x33U) << 2U) | ((value >> 2U) & 0x33U));
    value = (uint8_t)(((value & 0x55U) << 1U) | ((value >> 1U) & 0x55U));
    return value;
}

static inline void kia_v0_u64_to_bytes_be(uint64_t data, uint8_t bytes[8]) {
    for(size_t i = 0; i < 8; i++) {
        bytes[i] = (uint8_t)((data >> ((7U - i) * 8U)) & 0xFFU);
    }
}

static inline uint64_t kia_v0_bytes_to_u64_be(const uint8_t bytes[8]) {
    uint64_t data = 0;
    for(size_t i = 0; i < 8; i++) {
        data = (data << 8U) | bytes[i];
    }
    return data;
}

static inline bool kia_v0_is_short(uint32_t duration) {
    return DURATION_DIFF(duration, subghz_protocol_kia_const.te_short) <
           subghz_protocol_kia_const.te_delta;
}

static inline bool kia_v0_is_long(uint32_t duration) {
    return DURATION_DIFF(duration, subghz_protocol_kia_const.te_long) <
           subghz_protocol_kia_const.te_delta;
}

static bool kia_v0_read_hex_u64(FlipperFormat* ff, const char* key, uint64_t* out_key) {
    uint8_t buf[8] = {0};
    if(!flipper_format_rewind(ff)) return false;
    if(!flipper_format_read_hex(ff, key, buf, sizeof(buf))) return false;
    *out_key = kia_v0_bytes_to_u64_be(buf);
    return true;
}

#define kia_v0_crc8_poly(data, len) subghz_protocol_blocks_crc8((data), (len), 0x7F, 0x00)

static bool kia_v0_suzuki_verify_shifted_crc_words(uint32_t lo, uint32_t hi) {
    uint32_t r3 = ((lo >> 16) | (hi << 16)) & (uint32_t)~0xF0000000u;
    uint32_t r2 = (lo >> 12) & 0x0FU;
    uint32_t r1 = (hi >> 12) & 0xFFFFU;
    const uint8_t r4 = (uint8_t)((lo >> 4) & 0xFFU);

    r1 = ((r1 & 0xFFU) << 8) | ((r1 >> 8) & 0xFFU);

    uint8_t buf[6];
    buf[0] = (uint8_t)(r1 & 0xFFu);
    buf[1] = (uint8_t)((r1 >> 8) & 0xFFu);
    buf[2] = (uint8_t)((r3 >> 20) & 0xFFu);

    const uint8_t mid = (uint8_t)((r3 >> 12) & 0xFFu);
    buf[3] = mid;
    buf[4] = (uint8_t)((r3 >> 4) & 0xFFu);
    buf[5] = (uint8_t)(((r3 << 4) | (r2 & 0x0FU)) & 0xFFU);

    return (kia_v0_crc8_poly(buf, 6) == r4);
}

static bool kia_v0_suzuki_shifted_crc_valid(uint64_t shifted_key) {
    const uint32_t lo = (uint32_t)(shifted_key & 0xFFFFFFFFULL);
    const uint32_t hi = (uint32_t)((shifted_key >> 32) & 0xFFFFFFFFULL);
    return kia_v0_suzuki_verify_shifted_crc_words(lo, hi);
}

static uint8_t kia_v0_suzuki_crc8_from_fields(uint32_t serial, uint8_t button, uint32_t counter) {
    uint8_t buf[6];
    const uint16_t cnt_u16 = (uint16_t)(counter & 0xFFFFU);
    const uint16_t c_sw = (uint16_t)((cnt_u16 << 8) | (cnt_u16 >> 8));
    buf[0] = (uint8_t)(c_sw & 0xFFU);
    buf[1] = (uint8_t)((c_sw >> 8) & 0xFFU);
    buf[2] = (uint8_t)((serial >> 20) & 0xFFU);
    buf[3] = (uint8_t)((serial >> 12) & 0xFFU);
    buf[4] = (uint8_t)((serial >> 4) & 0xFFU);
    buf[5] = (uint8_t)((button & 0xFFU) | ((uint8_t)((uint32_t)serial << 4)));
    return kia_v0_crc8_poly(buf, 6);
}

static uint64_t kia_v0_suzuki_shifted_key_from_fields(
    uint32_t serial,
    uint8_t button,
    uint32_t counter,
    uint8_t crc_byte) {
    const uint32_t r8 = ((uint32_t)serial << 16) | ((uint32_t)crc_byte << 4) |
                        (((uint32_t)button & 0x0FU) << 12);
    const uint32_t r5 =
        (uint32_t)(((serial >> 16) & 0xFFFU) | (((uint32_t)(counter & 0xFFFFU)) << 12)) |
        0xF0000000U;
    return ((uint64_t)r5 << 32) | (uint64_t)r8;
}

static bool kia_v0_suzuki_resolve_shifted(uint64_t decode_data, uint64_t* out_shifted) {
    if(kia_v0_suzuki_shifted_crc_valid(decode_data)) {
        *out_shifted = decode_data;
        return true;
    }
    const uint64_t from_wire = decode_data << 1U;
    if(kia_v0_suzuki_shifted_crc_valid(from_wire)) {
        *out_shifted = from_wire;
        return true;
    }
    return false;
}

static uint8_t kia_v0_calculate_crc_poly(uint64_t data) {
    uint8_t crc_data[6];
    crc_data[0] = (data >> 48) & 0xFF;
    crc_data[1] = (data >> 40) & 0xFF;
    crc_data[2] = (data >> 32) & 0xFF;
    crc_data[3] = (data >> 24) & 0xFF;
    crc_data[4] = (data >> 16) & 0xFF;
    crc_data[5] = (data >> 8) & 0xFF;
    return kia_v0_crc8_poly(crc_data, 6);
}

static bool kia_v0_verify_crc_poly(uint64_t data) {
    uint8_t received_crc = data & 0xFF;
    return (kia_v0_calculate_crc_poly(data) == received_crc);
}

static uint64_t kia_v0_honda_transform(uint64_t data) {
    uint8_t bytes[8];
    kia_v0_u64_to_bytes_be(data, bytes);
    for(size_t index = 0; index < 8; index++) {
        bytes[index] = kia_v0_reverse_bits8(bytes[index]);
    }
    return kia_v0_bytes_to_u64_be(bytes);
}

static uint8_t kia_v0_family_crc(uint16_t counter, uint32_t serial, uint8_t button) {
    const uint8_t bytes[6] = {
        (uint8_t)(counter >> 8U),
        (uint8_t)counter,
        (uint8_t)(serial >> 20U),
        (uint8_t)(serial >> 12U),
        (uint8_t)(serial >> 4U),
        (uint8_t)(((serial & 0x0FU) << 4U) | (button & 0x0FU)),
    };
    uint8_t crc = 0;
    for(size_t index = 0; index < sizeof(bytes); index++) {
        crc ^= bytes[index];
    }
    return crc;
}

static uint8_t kia_v0_honda_fold_counter(uint16_t counter) {
    uint8_t value = 0;
    for(size_t index = 0; index < sizeof(kia_v0_honda_crc_table); index++) {
        if((counter >> index) & 1U) {
            value ^= kia_v0_honda_crc_table[index];
        }
    }
    return value;
}

static uint8_t kia_v0_honda_crc(uint8_t header, uint16_t counter) {
    uint8_t value = kia_v0_honda_fold_counter(counter);
    switch(header) {
    case 0xAA: value ^= 0xA5; break;
    case 0x2A: value ^= 0x21; break;
    case 0x6A: value ^= 0x15; break;
    case 0xFA: value ^= 0x73; break;
    default:   value ^= 0xC6; break;
    }
    return value;
}

static uint8_t kia_v0_honda_header(uint8_t button) {
    const uint8_t button_3bit = button & 0x07U;
    const uint8_t base = (button_3bit == 0x07U) ? 0x1AU : 0x0AU;
    return (uint8_t)(((button_3bit << 5U) & 0xE0U) | base);
}

static uint64_t kia_v0_build_kia_raw(uint32_t serial, uint8_t button, uint16_t counter, uint8_t crc) {
    const uint32_t high = 0x0F000000UL | (((uint32_t)counter & 0xFFFFUL) << 8U) |
                          ((serial >> 20U) & 0xFFUL);
    const uint32_t low = (((uint32_t)serial & 0x000FFFFFUL) << 12U) |
                         (((uint32_t)button & 0x0FUL) << 8U) | crc;
    return ((uint64_t)high << 32U) | low;
}

static uint64_t kia_v0_build_honda_key(uint32_t serial, uint8_t button, uint16_t counter) {
    const uint8_t header = kia_v0_honda_header(button);
    const uint8_t crc = kia_v0_honda_crc(header, counter);
    const uint8_t bytes[8] = {
        0xF0,
        kia_v0_reverse_bits8((uint8_t)(counter >> 8U)),
        kia_v0_reverse_bits8((uint8_t)counter),
        (uint8_t)(serial >> 16U),
        (uint8_t)(serial >> 8U),
        (uint8_t)serial,
        header,
        crc,
    };
    return kia_v0_bytes_to_u64_be(bytes);
}

static bool kia_v0_honda_key_valid(uint64_t key) {
    return ((key >> 60U) == 0x0FULL) && (((key >> 56U) & 0x0FULL) == 0x00ULL) &&
           (((key >> 8U) & 0x0FULL) == 0x0AULL);
}

static void kia_v0_parse_family_raw(uint64_t raw, uint8_t type, KiaV0Fields* fields) {
    fields->type = type;
    fields->serial = (type == KIA_V0_TYPE_SUZUKI) ? (uint32_t)((raw >> 16U) & 0x0FFFFFFFULL) :
                                                    (uint32_t)((raw >> 12U) & 0x0FFFFFFFULL);
    fields->button = (type == KIA_V0_TYPE_SUZUKI) ? (uint8_t)((raw >> 12U) & 0x0FU) :
                                                    (uint8_t)((raw >> 8U) & 0x0FU);
    fields->counter = (type == KIA_V0_TYPE_SUZUKI) ? (uint16_t)((raw >> 44U) & 0xFFFFU) :
                                                     (uint16_t)((raw >> 40U) & 0xFFFFU);
    fields->crc = (type == KIA_V0_TYPE_SUZUKI) ? (uint8_t)((raw >> 4U) & 0xFFU) :
                                                 (uint8_t)(raw & 0xFFU);
    if(type == KIA_V0_TYPE_SUZUKI) {
        fields->crc_valid = kia_v0_suzuki_shifted_crc_valid(raw);
    } else {
        fields->crc_valid =
            (kia_v0_family_crc(fields->counter, fields->serial, fields->button) == fields->crc);
    }
}

static void kia_v0_parse_honda_key(uint64_t key, KiaV0Fields* fields) {
    uint8_t bytes[8];
    kia_v0_u64_to_bytes_be(key, bytes);
    fields->type = KIA_V0_TYPE_HONDA;
    fields->serial = ((uint32_t)bytes[3] << 16U) | ((uint32_t)bytes[4] << 8U) | (uint32_t)bytes[5];
    fields->counter = ((uint16_t)kia_v0_reverse_bits8(bytes[1]) << 8U) |
                      (uint16_t)kia_v0_reverse_bits8(bytes[2]);
    fields->button = bytes[6] >> 5U;
    fields->crc = bytes[7];
    fields->crc_valid = (kia_v0_honda_crc(bytes[6], fields->counter) == fields->crc);
}

static const char* kia_v0_protocol_subtype_name(uint8_t type) {
    switch(type) {
    case KIA_V0_TYPE_SUZUKI: return "Suzuki V0";
    case KIA_V0_TYPE_HONDA:  return "Honda V0";
    default:                 return SUBGHZ_PROTOCOL_KIA_V0_NAME;
    }
}

static const char* kia_v0_button_name(uint8_t button, uint8_t type) {
    if(type == KIA_V0_TYPE_HONDA) {
        if((button >= 1U) && (button <= (uint8_t)(sizeof(kia_v0_honda_button_names) /
                                                  sizeof(kia_v0_honda_button_names[0])))) {
            return kia_v0_honda_button_names[button - 1U];
        }
        return "??";
    }
    if(type == KIA_V0_TYPE_SUZUKI) {
        switch(button) {
        case 0x03: return "Lock";
        case 0x04: return "Unlock";
        case 0x02: return "Trunk";
        default:   return "??";
        }
    }
    switch(button) {
    case 0x01: return "Lock";
    case 0x02: return "Unlock";
    case 0x03: return "Trunk";
    default:   return "??";
    }
}

static uint8_t kia_v0_custom_to_btn(uint8_t custom_btn_id, uint8_t type, uint8_t original_btn) {
    if(type == KIA_V0_TYPE_SUZUKI) {
        switch(custom_btn_id) {
        case SUBGHZ_CUSTOM_BTN_UP:   return 0x03U;
        case SUBGHZ_CUSTOM_BTN_DOWN: return 0x04U;
        case SUBGHZ_CUSTOM_BTN_LEFT: return 0x02U;
        default:                     return original_btn;
        }
    }
    if(type == KIA_V0_TYPE_HONDA) {
        switch(custom_btn_id) {
        case SUBGHZ_CUSTOM_BTN_UP:    return 0x01U;
        case SUBGHZ_CUSTOM_BTN_DOWN:  return 0x03U;
        case SUBGHZ_CUSTOM_BTN_LEFT:  return 0x02U;
        case SUBGHZ_CUSTOM_BTN_RIGHT: return 0x04U;
        case 5U:                      return 0x05U;
        case 6U:                      return 0x06U;
        case 7U:                      return 0x07U;
        default:                      return original_btn;
        }
    }
    switch(custom_btn_id) {
    case SUBGHZ_CUSTOM_BTN_UP:   return 0x01U;
    case SUBGHZ_CUSTOM_BTN_DOWN: return 0x02U;
    case SUBGHZ_CUSTOM_BTN_LEFT: return 0x03U;
    default:                     return original_btn;
    }
}

static void kia_v0_parse_data(
    SubGhzBlockGeneric* generic,
    uint8_t type,
    KiaV0Fields* fields,
    uint16_t* packet_bit_count) {
    memset(fields, 0, sizeof(*fields));

    if(type == KIA_V0_TYPE_HONDA) {
        kia_v0_parse_honda_key(generic->data, fields);
        generic->data_count_bit = KIA_V0_BIT_COUNT_HONDA;
    } else {
        kia_v0_parse_family_raw(generic->data, type, fields);
        generic->data_count_bit = (type == KIA_V0_TYPE_SUZUKI) ? KIA_V0_BIT_COUNT_SUZUKI :
                                                                 KIA_V0_BIT_COUNT_KIA;
        if(type == KIA_V0_TYPE_KIA) {
            fields->crc_valid = kia_v0_verify_crc_poly(generic->data);
        }
    }

    generic->serial = fields->serial;
    generic->cnt = fields->counter;
    generic->btn = fields->button;
    if(packet_bit_count) {
        *packet_bit_count = generic->data_count_bit;
    }
}

static uint8_t kia_v0_infer_type_from_bits(uint32_t bits) {
    if(bits == KIA_V0_BIT_COUNT_KIA) return KIA_V0_TYPE_KIA;
    if(bits == KIA_V0_BIT_COUNT_SUZUKI) return KIA_V0_TYPE_SUZUKI;
    if(bits == KIA_V0_BIT_COUNT_HONDA) return KIA_V0_TYPE_HONDA;
    return KIA_V0_TYPE_KIA;
}

const SubGhzProtocolDecoder subghz_protocol_kia_decoder = {
    .alloc = subghz_protocol_decoder_kia_alloc,
    .free = subghz_protocol_decoder_kia_free,
    .feed = subghz_protocol_decoder_kia_feed,
    .reset = subghz_protocol_decoder_kia_reset,
    .get_hash_data = subghz_protocol_decoder_kia_get_hash_data,
    .serialize = subghz_protocol_decoder_kia_serialize,
    .deserialize = subghz_protocol_decoder_kia_deserialize,
    .get_string = subghz_protocol_decoder_kia_get_string,
};

const SubGhzProtocolEncoder subghz_protocol_kia_encoder = {
    .alloc = subghz_protocol_encoder_kia_alloc,
    .free = subghz_protocol_encoder_kia_free,
    .deserialize = subghz_protocol_encoder_kia_deserialize,
    .stop = subghz_protocol_encoder_kia_stop,
    .yield = subghz_protocol_encoder_kia_yield,
};

const SubGhzProtocol subghz_protocol_kia_v0 = {
    .name = SUBGHZ_PROTOCOL_KIA_V0_NAME,
    .type = SubGhzProtocolTypeDynamic,
    .flag = SubGhzProtocolFlag_315 | SubGhzProtocolFlag_433 | SubGhzProtocolFlag_AM |
            SubGhzProtocolFlag_FM | SubGhzProtocolFlag_Decodable | SubGhzProtocolFlag_Load |
            SubGhzProtocolFlag_Save | SubGhzProtocolFlag_Send,
    .decoder = &subghz_protocol_kia_decoder,
    .encoder = &subghz_protocol_kia_encoder,
};

static size_t kia_v0_append_short_pairs(LevelDuration* upload, size_t index, size_t count) {
    for(size_t p = 0; p < count; p++) {
        upload[index++] = level_duration_make(true, (uint32_t)subghz_protocol_kia_const.te_short);
        upload[index++] = level_duration_make(false, (uint32_t)subghz_protocol_kia_const.te_short);
    }
    return index;
}

static size_t kia_v0_append_data_pairs(
    LevelDuration* upload,
    size_t index,
    uint64_t data,
    uint8_t bit_count) {
    for(int bit = bit_count - 1; bit >= 0; bit--) {
        const uint32_t duration = ((data >> bit) & 1ULL) ?
                                      (uint32_t)subghz_protocol_kia_const.te_long :
                                      (uint32_t)subghz_protocol_kia_const.te_short;
        upload[index++] = level_duration_make(true, duration);
        upload[index++] = level_duration_make(false, duration);
    }
    return index;
}

static void kia_v0_build_honda_upload(SubGhzProtocolEncoderKIA* instance, uint64_t key) {
    size_t index = 0;
    const uint64_t raw_onair = kia_v0_honda_transform(key);

    instance->encoder.upload[index++] = level_duration_make(true, KIA_V0_TYPE1_SYNC);
    instance->encoder.upload[index++] = level_duration_make(false, KIA_V0_TYPE1_SYNC);
    index = kia_v0_append_short_pairs(instance->encoder.upload, index, KIA_V0_TYPE1_PREAMBLE_PAIRS);
    index = kia_v0_append_data_pairs(instance->encoder.upload, index, raw_onair, KIA_V0_BIT_COUNT_KIA);
    instance->encoder.upload[index++] = level_duration_make(true, 1500);
    instance->encoder.upload[index++] = level_duration_make(false, 1500);
    index = kia_v0_append_short_pairs(instance->encoder.upload, index, KIA_V0_TAIL_PREAMBLE_PAIRS);
    index = kia_v0_append_data_pairs(instance->encoder.upload, index, raw_onair, KIA_V0_BIT_COUNT_KIA);
    instance->encoder.upload[index++] = level_duration_make(true, KIA_V0_KIA_GAP);

    instance->encoder.front = 0;
    instance->encoder.size_upload = index;
}

static void kia_v0_build_kia_upload(SubGhzProtocolEncoderKIA* instance, uint64_t raw) {
    size_t index = 0;

    instance->encoder.upload[index++] = level_duration_make(true, KIA_V0_TYPE1_SYNC);
    instance->encoder.upload[index++] = level_duration_make(false, KIA_V0_TYPE1_SYNC);
    index = kia_v0_append_short_pairs(instance->encoder.upload, index, KIA_V0_TYPE1_PREAMBLE_PAIRS);
    index = kia_v0_append_data_pairs(instance->encoder.upload, index, raw, KIA_V0_BIT_COUNT_KIA);
    instance->encoder.upload[index++] = level_duration_make(true, 1500);
    instance->encoder.upload[index++] = level_duration_make(false, 1500);
    index = kia_v0_append_short_pairs(instance->encoder.upload, index, KIA_V0_TAIL_PREAMBLE_PAIRS);
    index = kia_v0_append_data_pairs(instance->encoder.upload, index, raw, KIA_V0_BIT_COUNT_KIA);
    instance->encoder.upload[index++] = level_duration_make(true, KIA_V0_KIA_GAP);

    instance->encoder.front = 0;
    instance->encoder.size_upload = index;
}

static void kia_v0_build_suzuki_upload(SubGhzProtocolEncoderKIA* instance, uint64_t shifted) {
    size_t index = 0;

    index = kia_v0_append_short_pairs(instance->encoder.upload, index, KIA_V0_TYPE2_PREAMBLE_PAIRS);
    index = kia_v0_append_data_pairs(instance->encoder.upload, index, shifted, KIA_V0_BIT_COUNT_SUZUKI);
    instance->encoder.upload[index++] = level_duration_make(false, KIA_V0_SUZUKI_GAP);
    instance->encoder.upload[index++] = level_duration_make(true, KIA_V0_SUZUKI_GAP);
    instance->encoder.upload[index++] =
        level_duration_make(false, (uint32_t)subghz_protocol_kia_const.te_short);
    index = kia_v0_append_short_pairs(instance->encoder.upload, index, KIA_V0_TAIL_PREAMBLE_PAIRS);
    index = kia_v0_append_data_pairs(instance->encoder.upload, index, shifted, KIA_V0_BIT_COUNT_SUZUKI);

    instance->encoder.front = 0;
    instance->encoder.size_upload = index;
}

static void kia_v0_encoder_apply_fields(SubGhzProtocolEncoderKIA* instance) {
    instance->generic.serial = instance->fields.serial;
    instance->generic.cnt = instance->fields.counter;
    if(instance->type == KIA_V0_TYPE_HONDA) {
        instance->generic.btn = instance->fields.button & 0x07U;
    } else {
        instance->generic.btn = instance->fields.button & 0x0FU;
    }

    if(instance->type == KIA_V0_TYPE_HONDA) {
        instance->generic.data = kia_v0_build_honda_key(
            instance->fields.serial, instance->fields.button & 0x07U, instance->fields.counter);
        instance->generic.data_count_bit = KIA_V0_BIT_COUNT_HONDA;
        kia_v0_parse_data(&instance->generic, instance->type, &instance->fields, NULL);
        kia_v0_build_honda_upload(instance, instance->generic.data);
    } else if(instance->type == KIA_V0_TYPE_SUZUKI) {
        instance->fields.crc = kia_v0_suzuki_crc8_from_fields(
            instance->fields.serial,
            instance->fields.button & 0x0FU,
            (uint32_t)instance->fields.counter);
        instance->fields.crc_valid = true;
        const uint64_t shifted = kia_v0_suzuki_shifted_key_from_fields(
            instance->fields.serial,
            instance->fields.button & 0x0FU,
            (uint32_t)instance->fields.counter,
            instance->fields.crc);
        instance->generic.data = shifted;
        instance->generic.data_count_bit = KIA_V0_BIT_COUNT_SUZUKI;
        kia_v0_parse_data(&instance->generic, instance->type, &instance->fields, NULL);
        kia_v0_build_suzuki_upload(instance, shifted);
    } else {
        uint64_t partial = kia_v0_build_kia_raw(
            instance->fields.serial,
            instance->fields.button & 0x0FU,
            instance->fields.counter,
            0);
        instance->fields.crc = kia_v0_calculate_crc_poly(partial);
        instance->fields.crc_valid = true;
        instance->generic.data = kia_v0_build_kia_raw(
            instance->fields.serial,
            instance->fields.button & 0x0FU,
            instance->fields.counter,
            instance->fields.crc);
        instance->generic.data_count_bit = KIA_V0_BIT_COUNT_KIA;
        kia_v0_parse_data(&instance->generic, instance->type, &instance->fields, NULL);
        kia_v0_build_kia_upload(instance, instance->generic.data);
    }
}

void* subghz_protocol_encoder_kia_alloc(SubGhzEnvironment* environment) {
    UNUSED(environment);
    SubGhzProtocolEncoderKIA* instance = malloc(sizeof(SubGhzProtocolEncoderKIA));
    furi_check(instance);
    memset(instance, 0, sizeof(*instance));

    instance->base.protocol = &subghz_protocol_kia_v0;
    instance->generic.protocol_name = instance->base.protocol->name;
    instance->encoder.size_upload = KIA_V0_UPLOAD_CAPACITY;
    instance->encoder.upload = malloc(instance->encoder.size_upload * sizeof(LevelDuration));
    furi_check(instance->encoder.upload);
    instance->encoder.repeat = KIA_V0_ENCODER_DEFAULT_REPEAT;
    instance->encoder.is_running = false;

    return instance;
}

void subghz_protocol_encoder_kia_free(void* context) {
    furi_assert(context);
    SubGhzProtocolEncoderKIA* instance = context;
    if(instance->encoder.upload) {
        free(instance->encoder.upload);
    }
    free(instance);
}

void subghz_protocol_encoder_kia_stop(void* context) {
    furi_assert(context);
    SubGhzProtocolEncoderKIA* instance = context;
    instance->encoder.is_running = false;
    instance->encoder.front = 0;
}

LevelDuration subghz_protocol_encoder_kia_yield(void* context) {
    SubGhzProtocolEncoderKIA* instance = context;

    if(instance->encoder.repeat == 0 || !instance->encoder.is_running ||
       instance->encoder.size_upload == 0) {
        instance->encoder.is_running = false;
        return level_duration_reset();
    }

    LevelDuration ret = instance->encoder.upload[instance->encoder.front];
    if(++instance->encoder.front == instance->encoder.size_upload) {
        if(!subghz_block_generic_global.endless_tx) instance->encoder.repeat--;
        instance->encoder.front = 0;
    }

    return ret;
}

static SubGhzProtocolStatus kia_v0_verify_protocol_name(FlipperFormat* ff, const char* expected) {
    FuriString* tmp = furi_string_alloc();
    if(!tmp) return SubGhzProtocolStatusError;
    SubGhzProtocolStatus result = SubGhzProtocolStatusErrorParserOthers;
    flipper_format_rewind(ff);
    if(flipper_format_read_string(ff, "Protocol", tmp)) {
        if(furi_string_equal(tmp, expected)) {
            result = SubGhzProtocolStatusOk;
        } else {
            result = SubGhzProtocolStatusErrorParserProtocolName;
        }
    }
    furi_string_free(tmp);
    return result;
}

static void kia_v0_encoder_apply_flipper_fields(
    SubGhzProtocolEncoderKIA* instance,
    bool got_serial,
    uint32_t ser_u32,
    bool got_btn,
    uint32_t btn_u32,
    bool got_cnt,
    uint32_t cnt_u32) {
    if(got_serial) instance->generic.serial = ser_u32;
    if(got_btn) instance->generic.btn = (uint8_t)btn_u32;
    if(got_cnt) instance->generic.cnt = cnt_u32;

    if(instance->type == KIA_V0_TYPE_HONDA) {
        instance->generic.data = kia_v0_build_honda_key(
            instance->generic.serial,
            instance->generic.btn & 0x07U,
            (uint16_t)(instance->generic.cnt & 0xFFFFU));
        instance->generic.data_count_bit = KIA_V0_BIT_COUNT_HONDA;
    } else if(instance->type == KIA_V0_TYPE_SUZUKI) {
        const uint8_t crc = kia_v0_suzuki_crc8_from_fields(
            instance->generic.serial, instance->generic.btn & 0x0FU, instance->generic.cnt);
        instance->generic.data = kia_v0_suzuki_shifted_key_from_fields(
            instance->generic.serial, instance->generic.btn & 0x0FU, instance->generic.cnt, crc);
        instance->generic.data_count_bit = KIA_V0_BIT_COUNT_SUZUKI;
    } else {
        uint64_t partial = kia_v0_build_kia_raw(
            instance->generic.serial,
            instance->generic.btn & 0x0FU,
            (uint16_t)(instance->generic.cnt & 0xFFFFU),
            0);
        uint8_t crc = kia_v0_calculate_crc_poly(partial);
        instance->generic.data = kia_v0_build_kia_raw(
            instance->generic.serial,
            instance->generic.btn & 0x0FU,
            (uint16_t)(instance->generic.cnt & 0xFFFFU),
            crc);
        instance->generic.data_count_bit = KIA_V0_BIT_COUNT_KIA;
    }
}

SubGhzProtocolStatus
    subghz_protocol_encoder_kia_deserialize(void* context, FlipperFormat* flipper_format) {
    furi_assert(context);
    SubGhzProtocolEncoderKIA* instance = context;

    instance->encoder.is_running = false;
    instance->encoder.front = 0U;

    SubGhzProtocolStatus ret =
        kia_v0_verify_protocol_name(flipper_format, instance->base.protocol->name);
    if(ret != SubGhzProtocolStatusOk) {
        return ret;
    }

    flipper_format_rewind(flipper_format);
    uint32_t bits = 0;
    if(!flipper_format_read_uint32(flipper_format, "Bit", &bits, 1)) {
        return SubGhzProtocolStatusErrorValueBitCount;
    }
    if((bits != KIA_V0_BIT_COUNT_KIA) && (bits != KIA_V0_BIT_COUNT_SUZUKI) &&
       (bits != KIA_V0_BIT_COUNT_HONDA)) {
        return SubGhzProtocolStatusErrorValueBitCount;
    }

    uint32_t type_u32 = kia_v0_infer_type_from_bits(bits);
    flipper_format_rewind(flipper_format);
    {
        uint32_t tmp = 0;
        if(flipper_format_read_uint32(flipper_format, "Type", &tmp, 1)) {
            type_u32 = tmp;
        }
    }
    if(type_u32 < KIA_V0_TYPE_KIA || type_u32 > KIA_V0_TYPE_HONDA) {
        return SubGhzProtocolStatusErrorValueBitCount;
    }
    instance->type = (uint8_t)type_u32;

    uint64_t key_from_hex = 0;
    bool have_key = kia_v0_read_hex_u64(flipper_format, "Key", &key_from_hex);

    uint32_t ser_u32 = 0;
    uint32_t btn_u32 = 0;
    uint32_t cnt_u32 = 0;

    flipper_format_rewind(flipper_format);
    const bool got_serial = flipper_format_read_uint32(flipper_format, "Serial", &ser_u32, 1);
    flipper_format_rewind(flipper_format);
    const bool got_btn = flipper_format_read_uint32(flipper_format, "Btn", &btn_u32, 1);
    flipper_format_rewind(flipper_format);
    const bool got_cnt = flipper_format_read_uint32(flipper_format, "Cnt", &cnt_u32, 1);

    if(got_serial || got_btn || got_cnt) {
        kia_v0_encoder_apply_flipper_fields(
            instance, got_serial, ser_u32, got_btn, btn_u32, got_cnt, cnt_u32);
    } else if(have_key) {
        instance->generic.data = key_from_hex;
        instance->generic.data_count_bit = bits;
        kia_v0_parse_data(&instance->generic, instance->type, &instance->fields, NULL);
    } else {
        return SubGhzProtocolStatusErrorParserOthers;
    }

    uint32_t repeat = KIA_V0_ENCODER_DEFAULT_REPEAT;
    flipper_format_rewind(flipper_format);
    {
        uint32_t tmp = 0;
        if(flipper_format_read_uint32(flipper_format, "Repeat", &tmp, 1) && tmp > 0U) {
            repeat = (tmp > 50U) ? 50U : tmp;
        }
    }
    instance->encoder.repeat = repeat;

    {
        const uint8_t original_btn =
            (uint8_t)(instance->generic.btn &
                      ((instance->type == KIA_V0_TYPE_HONDA) ? 0x07U : 0x0FU));
        if(subghz_custom_btn_get_original() == 0) {
            subghz_custom_btn_set_original(original_btn);
        }
        subghz_custom_btn_set_max((instance->type == KIA_V0_TYPE_HONDA) ? 7 : 4);
        uint8_t custom_btn_id = subghz_custom_btn_get();
        instance->generic.btn =
            kia_v0_custom_to_btn(custom_btn_id, instance->type, original_btn);
    }

    {
        uint32_t mult = furi_hal_subghz_get_rolling_counter_mult();
        if(mult == 0U) mult = 1U;
        instance->generic.cnt = (instance->generic.cnt + mult) & 0xFFFFU;
    }

    kia_v0_encoder_apply_fields(instance);

    {
        flipper_format_rewind(flipper_format);
        uint32_t cnt_store = instance->generic.cnt;
        flipper_format_insert_or_update_uint32(flipper_format, "Cnt", &cnt_store, 1);
    }

    instance->encoder.front = 0;
    instance->encoder.is_running = true;

    return SubGhzProtocolStatusOk;
}

void* subghz_protocol_decoder_kia_alloc(SubGhzEnvironment* environment) {
    UNUSED(environment);
    SubGhzProtocolDecoderKIA* instance = malloc(sizeof(SubGhzProtocolDecoderKIA));
    furi_check(instance);
    memset(instance, 0, sizeof(*instance));

    instance->base.protocol = &subghz_protocol_kia_v0;
    instance->generic.protocol_name = instance->base.protocol->name;
    return instance;
}

void subghz_protocol_decoder_kia_free(void* context) {
    furi_assert(context);
    SubGhzProtocolDecoderKIA* instance = context;
    free(instance);
}

static void kia_v0_decoder_state_clear(SubGhzProtocolDecoderKIA* instance) {
    instance->decoder.parser_step = KiaV0DecoderStepReset;
    instance->decoder.te_last = 0;
    instance->decoder.decode_data = 0;
    instance->decoder.decode_count_bit = 0;
    instance->preamble_pairs = 0;
}

void subghz_protocol_decoder_kia_reset(void* context) {
    furi_assert(context);
    SubGhzProtocolDecoderKIA* instance = context;
    kia_v0_decoder_state_clear(instance);
    instance->type = 0;
}

static bool kia_v0_is_kia_gap(uint32_t duration) {
    return (duration >= KIA_V0_KIA_GAP_BASE) &&
           ((duration - KIA_V0_KIA_GAP_BASE) <= KIA_V0_KIA_GAP_SPAN);
}

static bool kia_v0_is_suzuki_gap_strict(uint32_t duration) {
    if(duration < KIA_V0_SUZUKI_GAP) {
        return false;
    }
    return (duration - KIA_V0_SUZUKI_GAP) <= KIA_V0_SUZUKI_GAP_SPAN;
}

static void kia_v0_decoder_commit(
    SubGhzProtocolDecoderKIA* instance,
    uint64_t data,
    uint8_t type,
    uint16_t bit_count) {
    instance->type = type;
    instance->packet_bit_count = bit_count;
    instance->generic.data = data;
    instance->generic.data_count_bit = bit_count;

    KiaV0Fields scratch;
    kia_v0_parse_data(&instance->generic, type, &scratch, &instance->packet_bit_count);

    if(subghz_custom_btn_get_original() == 0) {
        subghz_custom_btn_set_original(instance->generic.btn);
    }
    subghz_custom_btn_set_max((type == KIA_V0_TYPE_HONDA) ? 7 : 4);

    if(instance->base.callback) {
        instance->base.callback(&instance->base, instance->base.context);
    }

    kia_v0_decoder_state_clear(instance);
}

static void kia_v0_decoder_finish_kia_or_honda_at_gap(SubGhzProtocolDecoderKIA* instance) {
    if(instance->decoder.decode_count_bit != KIA_V0_BIT_COUNT_KIA) {
        kia_v0_decoder_state_clear(instance);
        return;
    }

    const uint64_t data = instance->decoder.decode_data;
    if(kia_v0_verify_crc_poly(data)) {
        kia_v0_decoder_commit(instance, data, KIA_V0_TYPE_KIA, KIA_V0_BIT_COUNT_KIA);
        return;
    }

    const uint64_t raw = data & 0x0FFFFFFFFFFFFFFFULL;
    const uint64_t key = kia_v0_honda_transform(raw);
    if(kia_v0_honda_key_valid(key)) {
        kia_v0_decoder_commit(instance, key, KIA_V0_TYPE_HONDA, KIA_V0_BIT_COUNT_HONDA);
        return;
    }

    kia_v0_decoder_state_clear(instance);
}

static bool kia_v0_decoder_try_honda(SubGhzProtocolDecoderKIA* instance) {
    if(instance->decoder.decode_count_bit != KIA_V0_BIT_COUNT_KIA) {
        return false;
    }
    if(kia_v0_verify_crc_poly(instance->decoder.decode_data)) {
        return false;
    }

    const uint64_t raw = instance->decoder.decode_data & 0x0FFFFFFFFFFFFFFFULL;
    const uint64_t key = kia_v0_honda_transform(raw);
    if(!kia_v0_honda_key_valid(key)) {
        return false;
    }

    kia_v0_decoder_commit(instance, key, KIA_V0_TYPE_HONDA, KIA_V0_BIT_COUNT_HONDA);
    return true;
}

void subghz_protocol_decoder_kia_feed(void* context, bool level, uint32_t duration) {
    furi_assert(context);
    SubGhzProtocolDecoderKIA* instance = context;

    switch(instance->decoder.parser_step) {
    case KiaV0DecoderStepReset:
        kia_v0_decoder_state_clear(instance);
        if(!level || !kia_v0_is_short(duration)) {
            break;
        }
        instance->decoder.parser_step = KiaV0DecoderStepPreamble;
        instance->decoder.te_last = duration;
        instance->preamble_pairs = 0;
        break;

    case KiaV0DecoderStepPreamble:
        if(level) {
            if(kia_v0_is_short(duration) || kia_v0_is_long(duration)) {
                instance->decoder.te_last = duration;
            } else {
                kia_v0_decoder_state_clear(instance);
            }
        } else if(kia_v0_is_short(duration) && kia_v0_is_short(instance->decoder.te_last)) {
            instance->preamble_pairs++;
        } else if(kia_v0_is_long(duration) && kia_v0_is_long(instance->decoder.te_last)) {
            if(instance->preamble_pairs > 14U) {
                instance->decoder.decode_data = 0;
                instance->decoder.decode_count_bit = 0;
                subghz_protocol_blocks_add_bit(&instance->decoder, 1U);
                subghz_protocol_blocks_add_bit(&instance->decoder, 1U);
                instance->decoder.parser_step = KiaV0DecoderStepSaveDuration;
            } else {
                kia_v0_decoder_state_clear(instance);
            }
        } else {
            kia_v0_decoder_state_clear(instance);
        }
        break;

    case KiaV0DecoderStepSaveDuration:
        if(!level) {
            kia_v0_decoder_state_clear(instance);
            break;
        }

        if(kia_v0_is_kia_gap(duration)) {
            kia_v0_decoder_finish_kia_or_honda_at_gap(instance);
            break;
        }

        if(kia_v0_is_suzuki_gap_strict(duration) &&
           kia_v0_is_suzuki_gap_strict(instance->decoder.te_last)) {
            if(instance->decoder.decode_count_bit == KIA_V0_BIT_COUNT_SUZUKI) {
                uint64_t shifted = 0;
                if(kia_v0_suzuki_resolve_shifted(instance->decoder.decode_data, &shifted)) {
                    kia_v0_decoder_commit(
                        instance, shifted, KIA_V0_TYPE_SUZUKI, KIA_V0_BIT_COUNT_SUZUKI);
                } else {
                    kia_v0_decoder_state_clear(instance);
                }
            } else {
                kia_v0_decoder_state_clear(instance);
            }
            break;
        }

        if(kia_v0_is_short(duration) || kia_v0_is_long(duration)) {
            instance->decoder.te_last = duration;
            instance->decoder.parser_step = KiaV0DecoderStepCheckDuration;
        } else {
            kia_v0_decoder_state_clear(instance);
        }
        break;

    case KiaV0DecoderStepCheckDuration:
        if(level) {
            kia_v0_decoder_state_clear(instance);
            break;
        }

        if(kia_v0_is_short(instance->decoder.te_last) && kia_v0_is_short(duration)) {
            subghz_protocol_blocks_add_bit(&instance->decoder, 0U);
            if(!kia_v0_decoder_try_honda(instance)) {
                instance->decoder.parser_step = KiaV0DecoderStepSaveDuration;
            }
            break;
        }

        if(kia_v0_is_long(instance->decoder.te_last) && kia_v0_is_long(duration)) {
            subghz_protocol_blocks_add_bit(&instance->decoder, 1U);
            if(!kia_v0_decoder_try_honda(instance)) {
                instance->decoder.parser_step = KiaV0DecoderStepSaveDuration;
            }
            break;
        }

        if(kia_v0_is_suzuki_gap_strict(duration)) {
            instance->decoder.te_last = duration;
            instance->decoder.parser_step = KiaV0DecoderStepSaveDuration;
            break;
        }

        if(!kia_v0_decoder_try_honda(instance)) {
            kia_v0_decoder_state_clear(instance);
        }
        break;

    default:
        kia_v0_decoder_state_clear(instance);
        break;
    }
}

uint8_t subghz_protocol_decoder_kia_get_hash_data(void* context) {
    furi_assert(context);
    SubGhzProtocolDecoderKIA* instance = context;
    return subghz_protocol_blocks_get_hash_data(
        &instance->decoder, (instance->decoder.decode_count_bit / 8) + 1);
}

SubGhzProtocolStatus subghz_protocol_decoder_kia_serialize(
    void* context,
    FlipperFormat* flipper_format,
    SubGhzRadioPreset* preset) {
    furi_assert(context);
    SubGhzProtocolDecoderKIA* instance = context;

    KiaV0Fields scratch;
    kia_v0_parse_data(&instance->generic, instance->type, &scratch, &instance->packet_bit_count);

    SubGhzProtocolStatus status =
        subghz_block_generic_serialize(&instance->generic, flipper_format, preset);
    if(status != SubGhzProtocolStatusOk) {
        return status;
    }

    uint32_t v_serial = instance->generic.serial;
    uint32_t v_btn = instance->generic.btn;
    uint32_t v_cnt = instance->generic.cnt;
    uint32_t v_type = instance->type;
    if(!flipper_format_write_uint32(flipper_format, "Serial", &v_serial, 1) ||
       !flipper_format_write_uint32(flipper_format, "Btn", &v_btn, 1) ||
       !flipper_format_write_uint32(flipper_format, "Cnt", &v_cnt, 1) ||
       !flipper_format_write_uint32(flipper_format, "Type", &v_type, 1)) {
        return SubGhzProtocolStatusErrorParserOthers;
    }
    return SubGhzProtocolStatusOk;
}

SubGhzProtocolStatus
    subghz_protocol_decoder_kia_deserialize(void* context, FlipperFormat* flipper_format) {
    furi_assert(context);
    SubGhzProtocolDecoderKIA* instance = context;

    SubGhzProtocolStatus status =
        subghz_block_generic_deserialize(&instance->generic, flipper_format);
    if(status != SubGhzProtocolStatusOk) {
        return status;
    }

    uint32_t bits = instance->generic.data_count_bit;
    if((bits != KIA_V0_BIT_COUNT_KIA) && (bits != KIA_V0_BIT_COUNT_SUZUKI) &&
       (bits != KIA_V0_BIT_COUNT_HONDA)) {
        return SubGhzProtocolStatusErrorValueBitCount;
    }

    uint32_t type_u32 = kia_v0_infer_type_from_bits(bits);
    flipper_format_rewind(flipper_format);
    {
        uint32_t tmp = 0;
        if(flipper_format_read_uint32(flipper_format, "Type", &tmp, 1)) {
            type_u32 = tmp;
        }
    }
    instance->type = (uint8_t)type_u32;

    KiaV0Fields scratch;
    kia_v0_parse_data(&instance->generic, instance->type, &scratch, &instance->packet_bit_count);

    uint32_t ser_u32 = 0;
    uint32_t btn_u32 = 0;
    uint32_t cnt_u32 = 0;
    bool got_serial = false;
    bool got_btn = false;
    bool got_cnt = false;

    flipper_format_rewind(flipper_format);
    got_serial = flipper_format_read_uint32(flipper_format, "Serial", &ser_u32, 1);
    flipper_format_rewind(flipper_format);
    got_btn = flipper_format_read_uint32(flipper_format, "Btn", &btn_u32, 1);
    flipper_format_rewind(flipper_format);
    got_cnt = flipper_format_read_uint32(flipper_format, "Cnt", &cnt_u32, 1);

    if(got_serial || got_btn || got_cnt) {
        if(got_serial) instance->generic.serial = ser_u32;
        if(got_btn) instance->generic.btn = (uint8_t)btn_u32;
        if(got_cnt) instance->generic.cnt = (uint16_t)cnt_u32;

        if(instance->type == KIA_V0_TYPE_HONDA) {
            instance->generic.data = kia_v0_build_honda_key(
                instance->generic.serial,
                instance->generic.btn & 0x07U,
                (uint16_t)(instance->generic.cnt & 0xFFFFU));
        } else if(instance->type == KIA_V0_TYPE_SUZUKI) {
            const uint8_t crc = kia_v0_suzuki_crc8_from_fields(
                instance->generic.serial, instance->generic.btn & 0x0FU, instance->generic.cnt);
            instance->generic.data = kia_v0_suzuki_shifted_key_from_fields(
                instance->generic.serial,
                instance->generic.btn & 0x0FU,
                instance->generic.cnt,
                crc);
        } else {
            uint64_t partial = kia_v0_build_kia_raw(
                instance->generic.serial,
                instance->generic.btn & 0x0FU,
                (uint16_t)(instance->generic.cnt & 0xFFFFU),
                0);
            uint8_t crc = kia_v0_calculate_crc_poly(partial);
            instance->generic.data = kia_v0_build_kia_raw(
                instance->generic.serial,
                instance->generic.btn & 0x0FU,
                (uint16_t)(instance->generic.cnt & 0xFFFFU),
                crc);
        }
        instance->generic.data_count_bit =
            (instance->type == KIA_V0_TYPE_SUZUKI) ? KIA_V0_BIT_COUNT_SUZUKI :
            (instance->type == KIA_V0_TYPE_HONDA)  ? KIA_V0_BIT_COUNT_HONDA :
                                                     KIA_V0_BIT_COUNT_KIA;
        kia_v0_parse_data(
            &instance->generic, instance->type, &scratch, &instance->packet_bit_count);
    }

    return SubGhzProtocolStatusOk;
}

void subghz_protocol_decoder_kia_get_string(void* context, FuriString* output) {
    furi_assert(context);

    SubGhzProtocolDecoderKIA* instance = context;
    KiaV0Fields fields;
    kia_v0_parse_data(&instance->generic, instance->type, &fields, &instance->packet_bit_count);

    subghz_custom_btn_set_max((instance->type == KIA_V0_TYPE_HONDA) ? 7 : 4);
    uint8_t display_btn = fields.button;
    uint8_t custom_btn_id = subghz_custom_btn_get();
    if(custom_btn_id != SUBGHZ_CUSTOM_BTN_OK) {
        display_btn = kia_v0_custom_to_btn(custom_btn_id, instance->type, fields.button);
    }

    const char* sn_fmt =
        (instance->type == KIA_V0_TYPE_HONDA) ?
            "%s %dbit\r\nKey:0x%llX\r\nSN:0x%06lX Btn:[%s]\r\nCRC:%02X [%s] Cnt:%04X\r\n" :
            "%s %dbit\r\nKey:0x%llX\r\nSN:0x%07lX Btn:[%s]\r\nCRC:%02X [%s] Cnt:%04X\r\n";
    furi_string_cat_printf(
        output,
        sn_fmt,
        kia_v0_protocol_subtype_name(instance->type),
        instance->packet_bit_count,
        (unsigned long long)instance->generic.data,
        (unsigned long)fields.serial,
        kia_v0_button_name(display_btn, instance->type),
        fields.crc,
        fields.crc_valid ? "OK" : "ERR",
        fields.counter);
}
