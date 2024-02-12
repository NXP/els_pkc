/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "els_pkc_fips_kdf.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
 * @brief Execute Ckdf SP800-108.
 */
static bool ckdf_sp800108()
{
    uint8_t plain_key[32U] = {0x9CU, 0xF4U, 0x83U, 0x16U, 0xE4U, 0xEEU, 0x94U, 0x0FU, 0x75U, 0xA0U, 0x8BU,
                              0xA6U, 0xE2U, 0xEFU, 0x58U, 0xA6U, 0x4AU, 0x6FU, 0xD9U, 0xD9U, 0x15U, 0x2AU,
                              0x77U, 0x04U, 0xCCU, 0x73U, 0x43U, 0x68U, 0x07U, 0x03U, 0x1DU, 0x65U};

    uint8_t ckdf_derivation_data[12U] = {
        0xC8U, 0xACU, 0x48U, 0x88U, 0xA6U, 0x1BU, 0x3DU, 0x9BU, 0x56U, 0xA9U, 0x75U, 0xE7U,
    };

    mcuxClEls_KeyProp_t plain_key_properties = {
        .word = {.value = MCUXCLELS_KEYPROPERTY_VALUE_SECURE | MCUXCLELS_KEYPROPERTY_VALUE_PRIVILEGED |
                          MCUXCLELS_KEYPROPERTY_VALUE_KEY_SIZE_256 | MCUXCLELS_KEYPROPERTY_VALUE_CKDF}};

    mcuxClEls_KeyProp_t derived_key_properties = {
        .word = {.value = MCUXCLELS_KEYPROPERTY_VALUE_SECURE | MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE |
                          MCUXCLELS_KEYPROPERTY_VALUE_PRIVILEGED | MCUXCLELS_KEYPROPERTY_VALUE_KEY_SIZE_256 |
                          MCUXCLELS_KEYPROPERTY_VALUE_AES}};
    mcuxClEls_KeyIndex_t key_index = MCUXCLELS_KEY_SLOTS;

    uint8_t derived_key[32U] = {0U};
    size_t derived_key_size  = sizeof(derived_key);
    host_derive_key(plain_key, sizeof(plain_key), ckdf_derivation_data, sizeof(ckdf_derivation_data),
                    derived_key_properties.word.value, &derived_key[0U], &derived_key_size);

    uint8_t aes256_kat_output[16U] = {0U};
    uint8_t aes256_input[16U]      = {0x35U, 0xE6U, 0x2CU, 0x18U, 0x02U, 0xCAU, 0x06U, 0x5BU,
                                      0xCDU, 0x56U, 0x1EU, 0xBFU, 0x9BU, 0xF0U, 0x2DU, 0x00U};

    mcuxClEls_CipherOption_t cipher_options = {0U};
    cipher_options.bits.cphmde              = MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_ECB;
    cipher_options.bits.dcrpt               = MCUXCLELS_CIPHER_ENCRYPT;
    cipher_options.bits.extkey              = MCUXCLELS_CIPHER_EXTERNAL_KEY;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        result, token,
        mcuxClEls_Cipher_Async(cipher_options, (mcuxClEls_KeyIndex_t)0U, derived_key, MCUXCLELS_CIPHER_KEY_SIZE_AES_256,
                               aes256_input, sizeof(aes256_input), NULL, aes256_kat_output));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cipher_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    import_plain_key_into_els(plain_key, sizeof(plain_key), plain_key_properties, &key_index);

    uint32_t key_index_derived = els_get_free_keyslot(2U);
    els_delete_key(key_index_derived);

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        resultCkdf, tokenAsync,
        mcuxClEls_Ckdf_Sp800108_Async(key_index, key_index_derived, derived_key_properties, ckdf_derivation_data));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Ckdf_Sp800108_Async) != tokenAsync) ||
        (MCUXCLELS_STATUS_OK_WAIT != resultCkdf))
    {
        els_delete_key(key_index_derived);
        els_delete_key(key_index);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultWait, tokenWait, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != tokenWait)
    {
        els_delete_key(key_index_derived);
        els_delete_key(key_index);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    if (MCUXCLELS_STATUS_OK != resultWait)
    {
        els_delete_key(key_index_derived);
        els_delete_key(key_index);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    uint8_t aes256_output[16U] = {0U};

    mcuxClEls_CipherOption_t cipher_options_els = {0U};
    cipher_options_els.bits.cphmde              = MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_ECB;
    cipher_options_els.bits.dcrpt               = MCUXCLELS_CIPHER_ENCRYPT;
    cipher_options_els.bits.extkey              = MCUXCLELS_CIPHER_INTERNAL_KEY;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token,
                                     mcuxClEls_Cipher_Async(cipher_options_els, (mcuxClEls_KeyIndex_t)key_index_derived,
                                                            NULL, MCUXCLELS_CIPHER_KEY_SIZE_AES_256, aes256_input,
                                                            sizeof(aes256_input), NULL, aes256_output));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cipher_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        els_delete_key(key_index_derived);
        els_delete_key(key_index);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        els_delete_key(key_index_derived);
        els_delete_key(key_index);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (!mcuxClCore_assertEqual(aes256_kat_output, aes256_output, 16U))
    {
        els_delete_key(key_index_derived);
        els_delete_key(key_index);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    els_delete_key(key_index_derived);
    els_delete_key(key_index);
    return MCUXCLEXAMPLE_STATUS_OK;
}

/*!
 * @brief Execute Hkdf rfc5869.
 */
static bool hkdf_rfc5869()
{
    const uint8_t plain_key[32U] = {0x4AU, 0xDFU, 0x2DU, 0xD0U, 0x0CU, 0x88U, 0xC7U, 0x27U, 0x89U, 0x00U, 0x80U,
                                    0xC8U, 0x65U, 0x8AU, 0x26U, 0x54U, 0xEEU, 0x72U, 0x57U, 0x7BU, 0x51U, 0x42U,
                                    0xCEU, 0xE7U, 0x54U, 0x9AU, 0x67U, 0xB2U, 0x96U, 0x63U, 0x4CU, 0x68U};

    const uint8_t aes256_kat_output[16U] = {0x94U, 0x21U, 0x64U, 0x1CU, 0xA4U, 0x9DU, 0xEBU, 0x10U,
                                            0xFBU, 0xDAU, 0x1AU, 0x15U, 0x64U, 0xABU, 0xA4U, 0x61U};

    const uint8_t aes256_input[16U] = {0x6BU, 0xC1U, 0xBEU, 0xE2U, 0x2EU, 0x40U, 0x9FU, 0x96U,
                                       0xE9U, 0x3DU, 0x7EU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2AU};

    const uint8_t hkdf_derivation_data[32U] = {0U};

    mcuxClEls_KeyProp_t plain_key_properties = {
        .word = {.value = MCUXCLELS_KEYPROPERTY_VALUE_SECURE | MCUXCLELS_KEYPROPERTY_VALUE_PRIVILEGED |
                          MCUXCLELS_KEYPROPERTY_VALUE_KEY_SIZE_256 | MCUXCLELS_KEYPROPERTY_VALUE_HKDF}};

    mcuxClEls_KeyProp_t derived_key_properties = {
        .word = {.value = MCUXCLELS_KEYPROPERTY_VALUE_SECURE | MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE |
                          MCUXCLELS_KEYPROPERTY_VALUE_PRIVILEGED | MCUXCLELS_KEYPROPERTY_VALUE_KEY_SIZE_256 |
                          MCUXCLELS_KEYPROPERTY_VALUE_AES}};
    mcuxClEls_KeyIndex_t key_index = MCUXCLELS_KEY_SLOTS;

    import_plain_key_into_els(plain_key, sizeof(plain_key), plain_key_properties, &key_index);

    uint32_t key_index_derived = els_get_free_keyslot(2U);
    els_delete_key(key_index_derived);

    mcuxClEls_HkdfOption_t options;
    options.bits.rtfdrvdat = 0U;
    options.bits.hkdf_algo = (uint32_t)MCUXCLELS_HKDF_ALGO_RFC5869;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultCkdf, tokenAsync,
                                     mcuxClEls_Hkdf_Rfc5869_Async(options, key_index, key_index_derived,
                                                                  derived_key_properties, hkdf_derivation_data));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Hkdf_Rfc5869_Async) != tokenAsync) ||
        (MCUXCLELS_STATUS_OK_WAIT != resultCkdf))
    {
        els_delete_key(key_index);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultWait, tokenWait, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != tokenWait)
    {
        els_delete_key(key_index);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    if (MCUXCLELS_STATUS_OK != resultWait)
    {
        els_delete_key(key_index);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    uint8_t aes256_output[16U] = {0U};

    mcuxClEls_CipherOption_t cipher_options_els = {0U};
    cipher_options_els.bits.cphmde              = MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_ECB;
    cipher_options_els.bits.dcrpt               = MCUXCLELS_CIPHER_ENCRYPT;
    cipher_options_els.bits.extkey              = MCUXCLELS_CIPHER_INTERNAL_KEY;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token,
                                     mcuxClEls_Cipher_Async(cipher_options_els, (mcuxClEls_KeyIndex_t)key_index_derived,
                                                            NULL, MCUXCLELS_CIPHER_KEY_SIZE_AES_256, aes256_input,
                                                            sizeof(aes256_input), NULL, aes256_output));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cipher_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        els_delete_key(key_index_derived);
        els_delete_key(key_index);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        els_delete_key(key_index_derived);
        els_delete_key(key_index);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (!mcuxClCore_assertEqual(aes256_kat_output, aes256_output, 16U))
    {
        els_delete_key(key_index_derived);
        els_delete_key(key_index);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    els_delete_key(key_index_derived);
    els_delete_key(key_index);
    return MCUXCLEXAMPLE_STATUS_OK;
}

/*!
 * @brief Execute Hkdf SP800-56C.
 */
static bool hkdf_sp80056c()
{
    const uint8_t plain_key[32U] = {0x95U, 0x37U, 0xA2U, 0xE8U, 0xA3U, 0x38U, 0x27U, 0xC2U, 0xDEU, 0xF4U, 0xEAU,
                                    0x61U, 0x67U, 0xABU, 0x36U, 0xD4U, 0x68U, 0x3DU, 0x04U, 0x8BU, 0xD3U, 0x44U,
                                    0x7EU, 0x52U, 0x70U, 0x60U, 0x2BU, 0x4AU, 0x52U, 0xC8U, 0xBFU, 0x0EU};

    const uint8_t hkdf_derivation_data[32U] = {
        0x00U, 0x00U, 0x00U, 0x01U, 0x66U, 0x2AU, 0xF2U, 0x03U, 0x79U, 0xB2U, 0x9DU, 0x5EU, 0xF8U, 0x13U, 0xE6U, 0x55U,
        0x80U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U, 0x80U};

    const uint8_t derived_key_kat[32U] = {0xF1U, 0x97U, 0xF8U, 0xD2U, 0xB5U, 0xF2U, 0x8AU, 0x87U, 0xF1U, 0x4CU, 0xEEU,
                                          0x67U, 0x00U, 0xAEU, 0xB6U, 0x1EU, 0x49U, 0x4FU, 0xD0U, 0x9EU, 0xCDU, 0x21U,
                                          0x0EU, 0xB3U, 0xE6U, 0xD0U, 0xC8U, 0xD0U, 0x89U, 0x65U, 0xCDU, 0x86U};

    mcuxClEls_KeyProp_t plain_key_properties = {
        .word = {.value = MCUXCLELS_KEYPROPERTY_VALUE_SECURE | MCUXCLELS_KEYPROPERTY_VALUE_PRIVILEGED |
                          MCUXCLELS_KEYPROPERTY_VALUE_KEY_SIZE_256 | MCUXCLELS_KEYPROPERTY_VALUE_HKDF}};

    mcuxClEls_KeyIndex_t key_index = MCUXCLELS_KEY_SLOTS;

    uint8_t derived_key[32U] = {0U};

    import_plain_key_into_els(plain_key, sizeof(plain_key), plain_key_properties, &key_index);

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        resultCkdf, tokenAsync,
        mcuxClEls_Hkdf_Sp80056c_Async(key_index, derived_key, hkdf_derivation_data, sizeof(hkdf_derivation_data)));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Hkdf_Sp80056c_Async) != tokenAsync) ||
        (MCUXCLELS_STATUS_OK_WAIT != resultCkdf))
    {
        els_delete_key(key_index);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultWait, tokenWait, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != tokenWait)
    {
        els_delete_key(key_index);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    if (MCUXCLELS_STATUS_OK != resultWait)
    {
        els_delete_key(key_index);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (!mcuxClCore_assertEqual(derived_key_kat, derived_key, 32U))
    {
        els_delete_key(key_index);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    els_delete_key(key_index);
    return MCUXCLEXAMPLE_STATUS_OK;
}

void execute_kdf_kat(uint64_t options, char name[])
{
    if ((options & FIPS_CKDF_SP800108) || (options & FIPS_ALL_TESTS))
    {
        if (!ckdf_sp800108())
        {
            PRINTF("[ERROR] %s KAT FAILED\r\n", name);
        }
    }
    if ((options & FIPS_HKDF_RFC5869) || (options & FIPS_ALL_TESTS))
    {
        if (!hkdf_rfc5869())
        {
            PRINTF("[ERROR] %s KAT FAILED\r\n", name);
        }
    }
    if ((options & FIPS_HKDF_SP80056C) || (options & FIPS_ALL_TESTS))
    {
        if (!hkdf_sp80056c())
        {
            PRINTF("[ERROR] %s KAT FAILED\r\n", name);
        }
    }
}
