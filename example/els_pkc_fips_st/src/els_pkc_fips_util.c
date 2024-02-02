/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "els_pkc_fips_util.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define PLOG_DEBUG_BUFFER(...) printf_buffer(__VA_ARGS__)

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/

// clang-format off
static const mcuxClEls_KeyProp_t keypair_prop = {
    .bits = 
    {
        .upprot_priv    = MCUXCLELS_KEYPROPERTY_PRIVILEGED_TRUE,
        .upprot_sec     = MCUXCLELS_KEYPROPERTY_SECURE_TRUE,
        .ksize          = MCUXCLELS_KEYPROPERTY_KEY_SIZE_256,
    }
};

static const mcuxClEls_KeyProp_t shared_secret_prop = {
    .bits =
        {
            .upprot_priv = MCUXCLELS_KEYPROPERTY_PRIVILEGED_TRUE,
            .upprot_sec  = MCUXCLELS_KEYPROPERTY_SECURE_TRUE,
            .uckdf       = MCUXCLELS_KEYPROPERTY_CKDF_TRUE,
            .ksize       = MCUXCLELS_KEYPROPERTY_KEY_SIZE_128,
        },
};

static const mcuxClEls_KeyProp_t wrap_in_key_prop = {
    .bits =
        {
            .upprot_priv = MCUXCLELS_KEYPROPERTY_PRIVILEGED_TRUE,
            .upprot_sec  = MCUXCLELS_KEYPROPERTY_SECURE_TRUE,
            .ukuok       = MCUXCLELS_KEYPROPERTY_KUOK_TRUE,
            .ksize       = MCUXCLELS_KEYPROPERTY_KEY_SIZE_128,
            .kactv       = MCUXCLELS_KEYPROPERTY_ACTIVE_TRUE,
        },
};

static const mcuxClEls_KeyProp_t wrap_out_key_prop = {
    .bits =
        {
            .upprot_priv = MCUXCLELS_KEYPROPERTY_PRIVILEGED_TRUE,
            .upprot_sec  = MCUXCLELS_KEYPROPERTY_SECURE_TRUE,
            .ukwk        = MCUXCLELS_KEYPROPERTY_KWK_TRUE,
            .ksize       = MCUXCLELS_KEYPROPERTY_KEY_SIZE_256,
            .kactv       = MCUXCLELS_KEYPROPERTY_ACTIVE_TRUE,
        },
};

static const uint8_t ckdf_derivation_data_wrap_in[12U] = {
        0xC8U, 0xACU, 0x48U, 0x88U, 0xA6U, 0x1BU, 0x3DU, 0x9BU, 0x56U, 0xA9U, 0x75U, 0xE7U,
    };

static const uint8_t ckdf_derivation_data_wrap_out[12] = {
    0x4e, 0x5f, 0x0a, 0x1c, 0x43, 0x37, 0x2c, 0xd0, 0x54, 0x8e, 0x46, 0xc9,
};

static const mcuxClEls_KeyProp_t mac_key_prop = {
    .bits =
        {
            .upprot_priv = MCUXCLELS_KEYPROPERTY_PRIVILEGED_TRUE,
            .upprot_sec  = MCUXCLELS_KEYPROPERTY_SECURE_TRUE,
            .ucmac       = MCUXCLELS_KEYPROPERTY_CMAC_TRUE,
            .ksize       = MCUXCLELS_KEYPROPERTY_KEY_SIZE_256,
            .kactv       = MCUXCLELS_KEYPROPERTY_ACTIVE_TRUE,
        },
};

static const uint8_t ckdf_derivation_data_mac[12] = {
    0xea, 0x93, 0x05, 0x7a, 0x50, 0xb6, 0x4d, 0x58, 0x0a, 0xe6, 0x6b, 0x57,
};


static const uint8_t import_die_int_ecdh_sk[32] = {
    0x82, 0x9b, 0xb4, 0x4a, 0x3b, 0x6d, 0x73, 0x35, 0x09, 0x5e, 0xd9, 0x8d, 0xf6, 0x09, 0x89, 0x98,
    0xac, 0x63, 0xab, 0x4e, 0x4e, 0x78, 0xf6, 0x0a, 0x70, 0xea, 0x64, 0x92, 0xd4, 0xfc, 0xe4, 0x92,
};

static const uint8_t import_die_int_ecdh_pk[64] = {
    0x8c, 0xe2, 0x3a, 0x89, 0xe7, 0xc5, 0xe9, 0xb1, 0x3e, 0x89, 0xed, 0xdb, 0x69, 0xb9, 0x22, 0xf8,
    0xc2, 0x8f, 0x5d, 0xcc, 0x59, 0x3e, 0x5f, 0x7b, 0x6e, 0x5a, 0x6c, 0xb3, 0x62, 0xc0, 0x17, 0x8a,
    0x2f, 0xda, 0xe8, 0x72, 0x67, 0x7b, 0xdf, 0xfe, 0xdb, 0x4a, 0x6e, 0x39, 0x2a, 0x1b, 0xae, 0xf8,
    0x88, 0x8f, 0xc5, 0x11, 0xc3, 0x67, 0x85, 0x5a, 0xc5, 0x54, 0xbb, 0xeb, 0x19, 0xf6, 0x52, 0x66,
};

// clang-format on

// common flags
#define PSA_KEY_LOCATION_NXP_FLAG   0x400000U
#define PSA_KEY_LOCATION_EL2GO_FLAG 0x200000U
#define PSA_KEY_LOCATION_S50_FLAG   0x000001U
#define PSA_KEY_LOCATION_COMMON_FLAG \
    (PSA_KEY_LOCATION_VENDOR_FLAG | PSA_KEY_LOCATION_NXP_FLAG | PSA_KEY_LOCATION_EL2GO_FLAG | PSA_KEY_LOCATION_S50_FLAG)

// key/data
#define PSA_KEY_LOCATION_KEY_FLAG  0x000000
#define PSA_KEY_LOCATION_DATA_FLAG 0x008000

// blob/encrypted
#define PSA_KEY_LOCATION_BLOB_STORAGE_FLAG    0x000000
#define PSA_KEY_LOCATION_ENC_STORAGE_FLAG     0x000100
#define PSA_KEY_LOCATION_TEMP_STORAGE_FLAG    0x000200
#define PSA_KEY_LOCATION_KEY_GEN_STORAGE_FLAG 0x000300

#define PSA_KEY_LOCATION_S50_BLOB_STORAGE \
    ((PSA_KEY_LOCATION_COMMON_FLAG | PSA_KEY_LOCATION_BLOB_STORAGE_FLAG | PSA_KEY_LOCATION_KEY_FLAG))
#define MCUXCLPSADRIVER_IS_S50_BLOB_STORAGE(location)                         ((location) == PSA_KEY_LOCATION_S50_BLOB_STORAGE)
#define PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(persistence, location) ((location) << 8 | (persistence))

#define NXP_DIE_INT_IMPORT_KEK_SK  0x7FFF817CU
#define NXP_DIE_INT_IMPORT_AUTH_SK 0x7FFF817EU

const uint8_t key_blob_magic[7] = {'k', 'e', 'y', 'b', 'l', 'o', 'b'};

const size_t s50_blob_size = 100;

static inline void write_uint32_msb_first(uint8_t *pos, uint32_t data)
{
    pos[0] = ((data) >> 24) & 0xFF;
    pos[1] = ((data) >> 16) & 0xFF;
    pos[2] = ((data) >> 8) & 0xFF;
    pos[3] = ((data) >> 0) & 0xFF;
}

static const char nibble_to_char[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
};

static inline void printf_buffer(const char *name, const unsigned char *buffer, size_t size)
{
#define PP_BYTES_PER_LINE (32)
    char line_buffer[PP_BYTES_PER_LINE * 2 + 2];
    const unsigned char *pos = buffer;
    size_t remaining         = size;
    while (remaining > 0)
    {
        size_t block_size = remaining > PP_BYTES_PER_LINE ? PP_BYTES_PER_LINE : remaining;
        uint32_t len      = 0;
        for (size_t i = 0; i < block_size; i++)
        {
            line_buffer[len++] = nibble_to_char[((*pos) & 0xf0) >> 4];
            line_buffer[len++] = nibble_to_char[(*pos++) & 0x0f];
        }
        line_buffer[len++] = '\n';
        line_buffer[len++] = '\0';
        PRINTF("%s (0x%p): %s", name, pos, line_buffer);
        remaining -= block_size;
    }
}

static inline uint32_t get_required_keyslots(mcuxClEls_KeyProp_t prop)
{
    return prop.bits.ksize == MCUXCLELS_KEYPROPERTY_KEY_SIZE_128 ? 1U : 2U;
}

static inline bool els_is_active_keyslot(mcuxClEls_KeyIndex_t keyIdx)
{
    mcuxClEls_KeyProp_t key_properties;
    key_properties.word.value = ((const volatile uint32_t *)(&ELS->ELS_KS0))[keyIdx];
    return key_properties.bits.kactv;
}

static inline uint32_t els_get_key_size(mcuxClEls_KeyIndex_t keyIdx)
{
    mcuxClEls_KeyProp_t key_properties;
    key_properties.word.value = ((const volatile uint32_t *)(&ELS->ELS_KS0))[keyIdx];
    return (key_properties.bits.ksize == MCUXCLELS_KEYPROPERTY_KEY_SIZE_256) ? (256U / 8U) : (128U / 8U);
}

static inline status_t els_get_key_properties(mcuxClEls_KeyIndex_t key_index, mcuxClEls_KeyProp_t *key_properties)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_GetKeyProperties(key_index, key_properties));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_GetKeyProperties) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PLOG_ERROR("mcuxClEls_GetKeyProperties failed: 0x%08lx", result);
        return STATUS_ERROR_GENERIC;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();
    return STATUS_SUCCESS;
}

mcuxClEls_KeyIndex_t els_get_free_keyslot(uint32_t required_keyslots)
{
    for (mcuxClEls_KeyIndex_t keyIdx = 0U; keyIdx <= (MCUXCLELS_KEY_SLOTS - required_keyslots); keyIdx++)
    {
        bool is_valid_keyslot = true;
        for (uint32_t i = 0U; i < required_keyslots; i++)
        {
            if (els_is_active_keyslot(keyIdx + i))
            {
                is_valid_keyslot = false;
                break;
            }
        }

        if (is_valid_keyslot)
        {
            return keyIdx;
        }
    }
    return MCUXCLELS_KEY_SLOTS;
}

static status_t els_generate_keypair(mcuxClEls_KeyIndex_t *dst_key_index, uint8_t *public_key, size_t *public_key_size)
{
    if (*public_key_size < 64)
    {
        PLOG_ERROR("insufficient space for public key");
        return STATUS_ERROR_GENERIC;
    }

    mcuxClEls_EccKeyGenOption_t options = {0};
    options.bits.kgsrc                  = MCUXCLELS_ECC_OUTPUTKEY_RANDOM;
    options.bits.kgtypedh               = MCUXCLELS_ECC_OUTPUTKEY_KEYEXCHANGE;

    uint32_t keypair_required_keyslots = get_required_keyslots(keypair_prop);
    *dst_key_index                     = (mcuxClEls_KeyIndex_t)els_get_free_keyslot(keypair_required_keyslots);

    if (!(*dst_key_index < MCUXCLELS_KEY_SLOTS))
    {
        PLOG_ERROR("no free keyslot found");
        return STATUS_ERROR_GENERIC;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        result, token,
        mcuxClEls_EccKeyGen_Async(options, (mcuxClEls_KeyIndex_t)0U, *dst_key_index, keypair_prop, NULL, public_key));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_EccKeyGen_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PLOG_ERROR("mcuxClEls_EccKeyGen_Async failed: 0x%08x", result);
        return STATUS_ERROR_GENERIC;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PLOG_ERROR("mcuxClEls_WaitForOperation failed: 0x%08x", result);
        return STATUS_ERROR_GENERIC;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    *public_key_size = 64;
    return STATUS_SUCCESS;
}

static status_t els_perform_key_agreement(mcuxClEls_KeyIndex_t keypair_index,
                                          mcuxClEls_KeyProp_t shared_secret_prop,
                                          mcuxClEls_KeyIndex_t *dst_key_index,
                                          const uint8_t *public_key,
                                          size_t public_key_size)
{
    uint32_t shared_secret_required_keyslots = get_required_keyslots(shared_secret_prop);
    *dst_key_index                           = els_get_free_keyslot(shared_secret_required_keyslots);

    if (!(*dst_key_index < MCUXCLELS_KEY_SLOTS))
    {
        PLOG_ERROR("no free keyslot found");
        return STATUS_ERROR_GENERIC;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        result, token, mcuxClEls_EccKeyExchange_Async(keypair_index, public_key, *dst_key_index, shared_secret_prop));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_EccKeyExchange_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PLOG_ERROR("mcuxClEls_EccKeyExchange_Async failed: 0x%08x", result);
        return STATUS_ERROR_GENERIC;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PLOG_ERROR("mcuxClEls_WaitForOperation failed: 0x%08x", result);
        return STATUS_ERROR_GENERIC;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return STATUS_SUCCESS;
}

status_t els_delete_key(mcuxClEls_KeyIndex_t key_index)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_KeyDelete_Async(key_index));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_KeyDelete_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PLOG_ERROR("mcuxClEls_KeyDelete_Async failed: 0x%08x", result);
        return STATUS_ERROR_GENERIC;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PLOG_ERROR("mcuxClEls_WaitForOperation failed: 0x%08x", result);
        return STATUS_ERROR_GENERIC;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    return STATUS_SUCCESS;
}

static status_t els_derive_key(mcuxClEls_KeyIndex_t src_key_index,
                               mcuxClEls_KeyProp_t key_prop,
                               const uint8_t *dd,
                               mcuxClEls_KeyIndex_t *dst_key_index)
{
    uint32_t required_keyslots = get_required_keyslots(key_prop);

    *dst_key_index = els_get_free_keyslot(required_keyslots);

    if (!(*dst_key_index < MCUXCLELS_KEY_SLOTS))
    {
        PLOG_ERROR("no free keyslot found");
        return STATUS_ERROR_GENERIC;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token,
                                     mcuxClEls_Ckdf_Sp800108_Async(src_key_index, *dst_key_index, key_prop, dd));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Ckdf_Sp800108_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PLOG_ERROR("mcuxClEls_Ckdf_Sp800108_Async failed: 0x%08x", result);
        return STATUS_ERROR_GENERIC;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PLOG_ERROR("mcuxClEls_WaitForOperation failed: 0x%08x", result);
        return STATUS_ERROR_GENERIC;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    return STATUS_SUCCESS;
}

static status_t els_import_key(const uint8_t *wrapped_key,
                               size_t wrapped_key_size,
                               mcuxClEls_KeyProp_t key_prop,
                               mcuxClEls_KeyIndex_t unwrap_key_index,
                               mcuxClEls_KeyIndex_t *dst_key_index)
{
    uint32_t required_keyslots = get_required_keyslots(key_prop);
    *dst_key_index             = els_get_free_keyslot(required_keyslots);

    if (!(*dst_key_index < MCUXCLELS_KEY_SLOTS))
    {
        PLOG_ERROR("no free keyslot found");
        return STATUS_ERROR_GENERIC;
    }

    mcuxClEls_KeyImportOption_t options;
    options.bits.kfmt = MCUXCLELS_KEYIMPORT_KFMT_RFC3394;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        result, token,
        mcuxClEls_KeyImport_Async(options, wrapped_key, wrapped_key_size, unwrap_key_index, *dst_key_index));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_KeyImport_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PLOG_ERROR("mcuxClEls_KeyImport_Async failed: 0x%08lx", result);
        return STATUS_ERROR_GENERIC;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PLOG_ERROR("mcuxClEls_WaitForOperation failed: 0x%08lx", result);
        return STATUS_ERROR_GENERIC;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    return STATUS_SUCCESS;
}

static status_t els_get_random(unsigned char *out, size_t out_size)
{
    /* Get random IV for sector metadata encryption. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_Rng_DrbgRequest_Async(out, out_size));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Rng_DrbgRequest_Async) != token) ||
        (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PRINTF("mcuxClCss_Rng_DrbgRequest_Async failed: 0x%08lx\r\n", result);
        return STATUS_ERROR_GENERIC;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PRINTF("Css_EccKeyGen_Async WaitForOperation failed: 0x%08lx\r\n", result);
        return STATUS_ERROR_GENERIC;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    return STATUS_SUCCESS;
}

status_t host_derive_key_hkdf(const uint8_t *input_key,
                              size_t input_key_size,
                              const uint8_t *derivation_data,
                              size_t derivation_data_size,
                              uint32_t key_properties,
                              uint8_t *output,
                              size_t *output_size)
{
    status_t status = STATUS_SUCCESS;

    int ret          = 0;
    uint32_t counter = 1;
    mbedtls_cipher_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    bool ctx_valid = false;

    assert(input_key != NULL);
    assert(input_key_size == 32);
    assert(derivation_data != NULL);
    assert(derivation_data_size == 12);
    assert(output != NULL);
    assert(*output_size == 32);

    uint32_t lsbit         = key_properties & 0x01;
    uint32_t length_blocks = 1 + lsbit;
    uint32_t length_bytes  = length_blocks * AES_BLOCK_SIZE;
    assert(*output_size >= length_bytes);
    *output_size = length_bytes;

    // KDF in counter mode implementation as described in Section 5.1
    // of NIST SP 800-108, Recommendation for Key Derivation Using Pseudorandom Functions
    //  Derivation data[191:0](sic!) = software_derivation_data[95:0] || 64'h0 || requested_
    //  properties[31:0 || length[31:0] || counter[31:0]

    uint8_t dd[32] = {0};
    memcpy(&dd[0], derivation_data, derivation_data_size);
    memset(&dd[12], 0, 8);
    write_uint32_msb_first(&dd[20], key_properties);
    write_uint32_msb_first(&dd[24], length_bytes * 8); // expected in bits!
    write_uint32_msb_first(&dd[28], counter);

    mbedtls_cipher_type_t mbedtls_cipher_type = MBEDTLS_CIPHER_AES_256_ECB;
    const mbedtls_cipher_info_t *cipher_info  = mbedtls_cipher_info_from_type(mbedtls_cipher_type);

    PLOG_DEBUG_BUFFER("input_key", input_key, input_key_size);
    PLOG_DEBUG_BUFFER("dd", dd, sizeof(dd));

    uint8_t *pos = output;
    do
    {
        mbedtls_cipher_init(&ctx);
        ctx_valid = true;

        ret = mbedtls_cipher_setup(&ctx, cipher_info);
        RET_MBEDTLS_SUCCESS_OR_EXIT_MSG("mbedtls_cipher_setup failed: 0x%08x", ret);

        ret = mbedtls_cipher_cmac_starts(&ctx, input_key, input_key_size * 8);
        RET_MBEDTLS_SUCCESS_OR_EXIT_MSG("mbedtls_cipher_cmac_starts failed: 0x%08x", ret);

        ret = mbedtls_cipher_cmac_update(&ctx, dd, sizeof(dd));
        RET_MBEDTLS_SUCCESS_OR_EXIT_MSG("mbedtls_cipher_cmac_update failed: 0x%08x", ret);

        ret = mbedtls_cipher_cmac_finish(&ctx, pos);
        RET_MBEDTLS_SUCCESS_OR_EXIT_MSG("mbedtls_cipher_cmac_finish failed: 0x%08x", ret);

        mbedtls_cipher_free(&ctx);
        ctx_valid = false;

        write_uint32_msb_first(&dd[28], ++counter);
        pos += AES_BLOCK_SIZE;
    } while (counter * AES_BLOCK_SIZE <= length_bytes);

    PLOG_DEBUG_BUFFER("output", output, length_bytes);

exit:
    if (ctx_valid)
    {
        mbedtls_cipher_free(&ctx);
        ctx_valid = false;
    }

    return status;
}

status_t host_derive_key(const uint8_t *input_key,
                         size_t input_key_size,
                         const uint8_t *derivation_data,
                         size_t derivation_data_size,
                         uint32_t key_properties,
                         uint8_t *output,
                         size_t *output_size)
{
    status_t status = STATUS_SUCCESS;

    int ret          = 0;
    uint32_t counter = 1;
    mbedtls_cipher_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    bool ctx_valid = false;

    assert(input_key != NULL);
    assert(input_key_size == 32);
    assert(derivation_data != NULL);
    assert(derivation_data_size == 12);
    assert(output != NULL);
    assert(*output_size == 32);

    uint32_t lsbit         = key_properties & 0x01;
    uint32_t length_blocks = 1 + lsbit;
    uint32_t length_bytes  = length_blocks * AES_BLOCK_SIZE;
    assert(*output_size >= length_bytes);
    *output_size = length_bytes;

    // KDF in counter mode implementation as described in Section 5.1
    // of NIST SP 800-108, Recommendation for Key Derivation Using Pseudorandom Functions
    //  Derivation data[191:0](sic!) = software_derivation_data[95:0] || 64'h0 || requested_
    //  properties[31:0 || length[31:0] || counter[31:0]

    uint8_t dd[32] = {0};
    memcpy(&dd[0], derivation_data, derivation_data_size);
    memset(&dd[12], 0, 8);
    write_uint32_msb_first(&dd[20], key_properties);
    write_uint32_msb_first(&dd[24], length_bytes * 8); // expected in bits!
    write_uint32_msb_first(&dd[28], counter);

    mbedtls_cipher_type_t mbedtls_cipher_type = MBEDTLS_CIPHER_AES_256_ECB;
    const mbedtls_cipher_info_t *cipher_info  = mbedtls_cipher_info_from_type(mbedtls_cipher_type);

    PLOG_DEBUG_BUFFER("input_key", input_key, input_key_size);
    PLOG_DEBUG_BUFFER("dd", dd, sizeof(dd));

    uint8_t *pos = output;
    do
    {
        mbedtls_cipher_init(&ctx);
        ctx_valid = true;

        ret = mbedtls_cipher_setup(&ctx, cipher_info);
        RET_MBEDTLS_SUCCESS_OR_EXIT_MSG("mbedtls_cipher_setup failed: 0x%08x", ret);

        ret = mbedtls_cipher_cmac_starts(&ctx, input_key, input_key_size * 8);
        RET_MBEDTLS_SUCCESS_OR_EXIT_MSG("mbedtls_cipher_cmac_starts failed: 0x%08x", ret);

        ret = mbedtls_cipher_cmac_update(&ctx, dd, sizeof(dd));
        RET_MBEDTLS_SUCCESS_OR_EXIT_MSG("mbedtls_cipher_cmac_update failed: 0x%08x", ret);

        ret = mbedtls_cipher_cmac_finish(&ctx, pos);
        RET_MBEDTLS_SUCCESS_OR_EXIT_MSG("mbedtls_cipher_cmac_finish failed: 0x%08x", ret);

        mbedtls_cipher_free(&ctx);
        ctx_valid = false;

        write_uint32_msb_first(&dd[28], ++counter);
        pos += AES_BLOCK_SIZE;
    } while (counter * AES_BLOCK_SIZE <= length_bytes);

    PLOG_DEBUG_BUFFER("output", output, length_bytes);

exit:
    if (ctx_valid)
    {
        mbedtls_cipher_free(&ctx);
        ctx_valid = false;
    }

    return status;
}

static int get_random_mbedtls_callback(void *ctx, unsigned char *out, size_t out_size)
{
    status_t status = els_get_random(out, out_size);
    if (status != STATUS_SUCCESS)
    {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    return 0;
}

static status_t host_perform_key_agreement(const uint8_t *public_key,
                                           size_t public_key_size,
                                           uint8_t *shared_secret,
                                           size_t *shared_secret_size)
{
    assert(public_key != NULL);
    assert(public_key_size == 64);
    assert(shared_secret != NULL);
    assert(*shared_secret_size >= 32);

    status_t status                   = STATUS_SUCCESS;
    uint8_t public_key_compressed[65] = {0};
    unsigned char strbuf[128]         = {0};
    size_t strlen                     = sizeof(strbuf);

    int ret = 0;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point qB;
    mbedtls_mpi dA, zA;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&qB);
    mbedtls_mpi_init(&dA);
    mbedtls_mpi_init(&zA);

    *shared_secret_size = 32;
    ret                 = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    RET_MBEDTLS_SUCCESS_OR_EXIT_MSG("mbedtls_ecp_group_load failed: 0x%08x", ret);

    ret = mbedtls_mpi_read_binary(&dA, import_die_int_ecdh_sk, sizeof(import_die_int_ecdh_sk));
    RET_MBEDTLS_SUCCESS_OR_EXIT_MSG("mbedtls_mpi_read_binary failed: 0x%08x", ret);

    public_key_compressed[0] = 0x04;
    memcpy(&public_key_compressed[1], public_key, public_key_size);

    ret = mbedtls_ecp_point_read_binary(&grp, &qB, public_key_compressed, sizeof(public_key_compressed));
    RET_MBEDTLS_SUCCESS_OR_EXIT_MSG("mbedtls_ecp_point_read_binary failed: 0x%08x", ret);

    ret = mbedtls_ecdh_compute_shared(&grp, &zA, &qB, &dA, &get_random_mbedtls_callback, NULL);
    RET_MBEDTLS_SUCCESS_OR_EXIT_MSG("mbedtls_ecdh_compute_shared failed: 0x%08x", ret);

    mbedtls_ecp_point_write_binary(&grp, &qB, MBEDTLS_ECP_PF_UNCOMPRESSED, &strlen, &strbuf[0], sizeof(strbuf));
    printf_buffer("public_key", strbuf, strlen);

    mbedtls_mpi_write_binary(&zA, shared_secret, *shared_secret_size);
    PLOG_DEBUG_BUFFER("shared_secret", shared_secret, *shared_secret_size);
exit:
    return status;
}

static status_t host_wrap_key(
    const uint8_t *data, size_t data_size, const uint8_t *key, size_t key_size, uint8_t *output, size_t *output_size)
{
    status_t status = STATUS_SUCCESS;
    int ret         = 0;
    mbedtls_nist_kw_context ctx;
    mbedtls_nist_kw_init(&ctx);
    ret = mbedtls_nist_kw_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, key_size * 8, true);
    RET_MBEDTLS_SUCCESS_OR_EXIT_MSG("mbedtls_nist_kw_setkey failed: 0x%08x", ret);
    ret = mbedtls_nist_kw_wrap(&ctx, MBEDTLS_KW_MODE_KW, data, data_size, output, output_size, *output_size);
    RET_MBEDTLS_SUCCESS_OR_EXIT_MSG("mbedtls_nist_kw_wrap failed: 0x%08x", ret);
    PLOG_DEBUG_BUFFER("wrapped buffer", output, *output_size);
exit:
    mbedtls_nist_kw_free(&ctx);
    return status;
}

static status_t create_els_import_keyblob(const uint8_t *plain_key,
                                          size_t plain_key_size,
                                          mcuxClEls_KeyProp_t plain_key_prop,
                                          const uint8_t *key_wrap_in,
                                          size_t key_wrap_in_size,
                                          uint8_t *blob,
                                          size_t *blob_size)
{
    assert(plain_key_size == 16 || plain_key_size == 32);
    assert(key_wrap_in_size == 16);

    uint8_t buffer[ELS_BLOB_METADATA_SIZE + MAX_ELS_KEY_SIZE] = {0};
    size_t buffer_size                                        = ELS_BLOB_METADATA_SIZE + plain_key_size;

    // Enforce the wrpok bit - the key needs to be re-wrappable!
    plain_key_prop.bits.wrpok = MCUXCLELS_KEYPROPERTY_WRAP_TRUE;

    // This is what ELS documentation says. It does not work though??
    // memset(&buffer[0], 0xA6, 8);
    // write_uint32_msb_first(&buffer[8], plain_key_prop.word.value);
    // memset(&buffer[12], 0, 4);
    // memcpy(&buffer[16], plain_key, plain_key_size);

    write_uint32_msb_first(&buffer[0], plain_key_prop.word.value);
    memset(&buffer[4], 0, 4);
    memcpy(&buffer[8], plain_key, plain_key_size);
    PLOG_DEBUG_BUFFER("plain buffer before wrapping for import", buffer, buffer_size);

    status_t status = host_wrap_key(buffer, buffer_size, key_wrap_in, key_wrap_in_size, blob, blob_size);
    return status;
}

status_t import_plain_key_into_els(const uint8_t *plain_key,
                                   size_t plain_key_size,
                                   mcuxClEls_KeyProp_t key_properties,
                                   mcuxClEls_KeyIndex_t *index_output)
{
    status_t status           = STATUS_SUCCESS;
    uint8_t shared_secret[32] = {0};
    uint8_t key_wrap_in[32];
    uint8_t els_key_in_blob[ELS_BLOB_METADATA_SIZE + MAX_ELS_KEY_SIZE + ELS_WRAP_OVERHEAD];

    size_t shared_secret_len    = sizeof(shared_secret);
    size_t key_wrap_in_size     = sizeof(key_wrap_in);
    size_t els_key_in_blob_size = sizeof(els_key_in_blob);

    mcuxClEls_KeyIndex_t index_plain                     = MCUXCLELS_KEY_SLOTS;
    mcuxClEls_KeyIndex_t index_shared_secret             = MCUXCLELS_KEY_SLOTS;
    mcuxClEls_KeyIndex_t index_unwrap                    = MCUXCLELS_KEY_SLOTS;
    mcuxClEls_KeyIndex_t *potentially_used_key_indices[] = {&index_plain, &index_shared_secret, &index_unwrap};

    PLOG_INFO("Generating random ECC keypair...");
    uint8_t public_key[64] = {0u};
    size_t public_key_size = sizeof(public_key);
    status                 = els_generate_keypair(&index_plain, &public_key[0], &public_key_size);
    STATUS_SUCCESS_OR_EXIT_MSG("generate_keypair failed: 0x%08x", status);

    PLOG_INFO("Calculating shared secret on host...");
    status = host_perform_key_agreement(public_key, public_key_size, &shared_secret[0], &shared_secret_len);
    STATUS_SUCCESS_OR_EXIT_MSG("perform_key_agreement_host failed: 0x%08x", status);

    PLOG_INFO("Deriving wrapping key for import on host...");
    status = host_derive_key(shared_secret, shared_secret_len, ckdf_derivation_data_wrap_in,
                             sizeof(ckdf_derivation_data_wrap_in), wrap_in_key_prop.word.value, &key_wrap_in[0],
                             &key_wrap_in_size);
    STATUS_SUCCESS_OR_EXIT_MSG("ckdf_host failed: 0x%08x", status);

    PLOG_INFO("Creating ELS keyblob for import...");
    status = create_els_import_keyblob(plain_key, plain_key_size, key_properties, key_wrap_in, key_wrap_in_size,
                                       &els_key_in_blob[0], &els_key_in_blob_size);
    STATUS_SUCCESS_OR_EXIT_MSG("create_els_import_keyblob failed: 0x%08x", status);

    PLOG_INFO("Calculating shared secret on ELS...");
    status = els_perform_key_agreement(index_plain, shared_secret_prop, &index_shared_secret, import_die_int_ecdh_pk,
                                       sizeof(import_die_int_ecdh_pk));
    STATUS_SUCCESS_OR_EXIT_MSG("perform_key_agreement failed: 0x%08x", status);

    status = els_delete_key(index_plain);
    STATUS_SUCCESS_OR_EXIT_MSG("delete_key failed: 0x%08x", status);
    index_plain = MCUXCLELS_KEY_SLOTS;

    PLOG_INFO("Deriving wrapping key for import on ELS...");
    status = els_derive_key(index_shared_secret, wrap_in_key_prop, ckdf_derivation_data_wrap_in, &index_unwrap);
    STATUS_SUCCESS_OR_EXIT_MSG("derive_key failed: 0x%08x", status);

    status = els_delete_key(index_shared_secret);
    STATUS_SUCCESS_OR_EXIT_MSG("delete_key failed: 0x%08x", status);
    index_shared_secret = MCUXCLELS_KEY_SLOTS;

    PLOG_INFO("Importing wrapped key...");
    status = els_import_key(els_key_in_blob, els_key_in_blob_size, key_properties, index_unwrap, index_output);
    STATUS_SUCCESS_OR_EXIT_MSG("import_wrapped_key failed: 0x%08x", status);

    status = els_delete_key(index_unwrap);
    STATUS_SUCCESS_OR_EXIT_MSG("delete_key failed: 0x%08x", status);
    index_unwrap = MCUXCLELS_KEY_SLOTS;

exit:
    for (size_t i = 0; i < ARRAY_SIZE(potentially_used_key_indices); i++)
    {
        mcuxClEls_KeyIndex_t key_index = *(potentially_used_key_indices[i]);
        if (key_index < MCUXCLELS_KEY_SLOTS)
        {
            (void)els_delete_key(key_index);
        }
    }
    return status;
}
