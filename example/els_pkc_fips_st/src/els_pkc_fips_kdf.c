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
 * @brief Execute Ckdf 800108.
 */
static bool ckdf_800108()
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

    uint32_t key_index_derived = els_get_free_keyslot(1U);
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
    uint8_t plain_key[32U] = {0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU,
                              0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU,
                              0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU, 0xAAU};

    uint8_t hkdf_derivation_data[MCUXCLELS_HKDF_RFC5869_DERIVATIONDATA_SIZE] = {
        0xC8U, 0xACU, 0x48U, 0x88U, 0xA6U, 0x1BU, 0x3DU, 0x9BU, 0x56U, 0xA9U, 0x75U, 0xE7U, 0xC8U, 0xACU, 0x48U, 0x88U,
        0xA6U, 0x1BU, 0x3DU, 0x9BU, 0x56U, 0xA9U, 0x75U, 0xE7U, 0xA6U, 0x1BU, 0x3DU, 0x9BU, 0x56U, 0xA9U, 0x75U, 0xE7U};

    mcuxClEls_KeyProp_t plain_key_properties = {
        .word = {.value = MCUXCLELS_KEYPROPERTY_VALUE_SECURE | MCUXCLELS_KEYPROPERTY_VALUE_PRIVILEGED |
                          MCUXCLELS_KEYPROPERTY_VALUE_KEY_SIZE_256 | MCUXCLELS_KEYPROPERTY_VALUE_HKDF}};

    mcuxClEls_KeyProp_t derived_key_properties = {
        .word = {.value = MCUXCLELS_KEYPROPERTY_VALUE_SECURE | MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE |
                          MCUXCLELS_KEYPROPERTY_VALUE_PRIVILEGED | MCUXCLELS_KEYPROPERTY_VALUE_KEY_SIZE_256 |
                          MCUXCLELS_KEYPROPERTY_VALUE_AES}};
    mcuxClEls_KeyIndex_t key_index = MCUXCLELS_KEY_SLOTS;

    uint8_t derived_key[32U] = {0U};
    size_t derived_key_size  = sizeof(derived_key);

    mbedtls_md_info_t md_info;
    md_info.type       = MBEDTLS_MD_SHA256;
    md_info.size       = 32U;
    md_info.block_size = 64U;

    mbedtls_hkdf(&md_info, NULL, 0U, plain_key, sizeof(plain_key), hkdf_derivation_data, sizeof(hkdf_derivation_data),
                 derived_key, sizeof(derived_key));
    // mbedtls_hkdf_expand(&md_info, plain_key, sizeof(plain_key), hkdf_derivation_data, sizeof(hkdf_derivation_data),
    //                    derived_key, sizeof(derived_key));

    // mbedtls_hkdf_extract(&md_info, hkdf_derivation_data, sizeof(hkdf_derivation_data), plain_key, sizeof(plain_key),
    //                      derived_key);

    PRINTF("\r\nDerived key with mbedtls: \r\n");
    PRINT_ARRAY(derived_key, sizeof(derived_key));

    /*int mbedtls_hkdf_extract(const mbedtls_md_info_t *md,
                         const unsigned char *salt, size_t salt_len,
                         const unsigned char *ikm, size_t ikm_len,
                         unsigned char *prk)*/
    /*mbedtls_hkdf(const mbedtls_md_info_t *md, const unsigned char *salt,
                         size_t salt_len, const unsigned char *ikm, size_t ikm_len,
                         const unsigned char *info, size_t info_len,
                         unsigned char *okm, size_t okm_len)*/
    /*int mbedtls_hkdf_expand(const mbedtls_md_info_t *md, const unsigned char *prk,
                        size_t prk_len, const unsigned char *info,
                        size_t info_len, unsigned char *okm, size_t okm_len);*/

    // TODO REPLACE WITH HKDF KNOWN ANSWER
    // host_derive_key(plain_key, sizeof(plain_key), hkdf_derivation_data, sizeof(hkdf_derivation_data),
    //                         derived_key_properties.word.value, &derived_key[0U], &derived_key_size);

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

    PRINTF("\r\nKAT AES256 output: \r\n");
    PRINT_ARRAY(aes256_kat_output, 16U);

    import_plain_key_into_els(plain_key, sizeof(plain_key), plain_key_properties, &key_index);

    uint32_t key_index_derived = els_get_free_keyslot(1U);
    els_delete_key(key_index_derived);

    mcuxClEls_HkdfOption_t options;
    options.bits.rtfdrvdat = 0U;
    options.bits.hkdf_algo = MCUXCLELS_HKDF_ALGO_RFC5869;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultCkdf, tokenAsync,
                                     mcuxClEls_Hkdf_Rfc5869_Async(options, key_index, key_index_derived,
                                                                  derived_key_properties, hkdf_derivation_data));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Hkdf_Rfc5869_Async) != tokenAsync) ||
        (MCUXCLELS_STATUS_OK_WAIT != resultCkdf))
    {
        PRINTF("[Error] hkdf-rfc5869 failed\r\n");
        els_delete_key(key_index);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultWait, tokenWait, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != tokenWait)
    {
        PRINTF("[Error] hkdf-rfc5869 wait token mismatch\r\n");
        els_delete_key(key_index);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    if (MCUXCLELS_STATUS_OK != resultWait)
    {
        PRINTF("[Error] hkdf-rfc5869 wait failed\r\n");
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

    PRINTF("\r\nOUR AES256 OUTPUT\r\n");
    PRINT_ARRAY(aes256_output, 16U);

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

void execute_kdf_kat(uint64_t options, char name[])
{
    if ((options & FIPS_CKDF) || (options & FIPS_ALL_TESTS))
    {
        if (!ckdf_800108())
        {
            PRINTF("[ERROR] %s KAT FAILED\r\n", name);
        }
    }
    if ((options & FIPS_HKDF) || (options & FIPS_ALL_TESTS))
    {
        if (!hkdf_rfc5869())
        {
            PRINTF("[ERROR] %s KAT FAILED\r\n", name);
        }
    }
}
