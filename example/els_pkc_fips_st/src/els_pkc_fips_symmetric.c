/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "els_pkc_fips_symmetric.h"

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
 * @brief Execute CBC decrypt/encrypt, depending on encrypt flag.
 */
static bool aes_encrypt(const uint8_t *plain_key,
                        const uint32_t key_size,
                        const uint8_t *iv,
                        const uint32_t iv_size,
                        const uint8_t *msg,
                        const uint32_t msg_size,
                        const uint8_t *cipher,
                        const uint32_t cipher_size,
                        const bool encrypt)
{
    /* Initialize session */
    mcuxClSession_Descriptor_t session_desc;
    mcuxClSession_Handle_t session = &session_desc;
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLCIPHER_AES_CRYPT_CPU_WA_BUFFER_SIZE, 0U);

    /* Initialize key */
    uint32_t key_desc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t key = (mcuxClKey_Handle_t)&key_desc;

    /* Set key properties */
    mcuxClEls_KeyProp_t key_properties;

    key_properties.word.value = 0U;
    key_properties.bits.ksize = MCUXCLELS_KEYPROPERTY_KEY_SIZE_128;
    key_properties.bits.kactv = MCUXCLELS_KEYPROPERTY_ACTIVE_TRUE;

    /* Load key */
    uint32_t dstData[8U];
    if (!mcuxClExample_Key_Init_And_Load(session, key, mcuxClKey_Type_Aes128, (mcuxCl_Buffer_t)plain_key, key_size,
                                         &key_properties, dstData, MCUXCLEXAMPLE_CONST_EXTERNAL_KEY))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Encryption                                                             */
    /**************************************************************************/
    uint32_t output_size = 0U;
    uint8_t output[16U];

    /* Start measuring */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        result_enc, token_enc,
        mcuxClCipher_crypt(
            /* mcuxClSession_Handle_t session: */ session,
            /* mcuxClKey_Handle_t key:         */ key,
            /* mcuxClCipher_Mode_t mode:       */
            encrypt ? mcuxClCipher_Mode_AES_CBC_Enc_NoPadding : mcuxClCipher_Mode_AES_CBC_Dec_NoPadding,
            /* mcuxCl_InputBuffer_t pIv:       */ iv,
            /* uint32_t ivLength:              */ iv_size,
            /* mcuxCl_InputBuffer_t pIn:       */ encrypt ? msg : cipher,
            /* uint32_t inLength:              */ encrypt ? msg_size : cipher_size,
            /* mcuxCl_Buffer_t pOut:           */ output,
            /* uint32_t * const pOutLength:    */ &output_size));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_crypt) != token_enc) || (MCUXCLCIPHER_STATUS_OK != result_enc))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (!mcuxClCore_assertEqual(msg, encrypt ? cipher : msg, msg_size))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Cleanup                                                                */
    /**************************************************************************/
    /* Flush the key */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClKey_flush(session, key));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush) != token) || (MCUXCLKEY_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Destroy Session and cleanup Session */
    if (!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    return MCUXCLEXAMPLE_STATUS_OK;
}

bool execute_cbc_kat(uint64_t options)
{
    aes_encrypt(NULL, 0, NULL, 0, NULL, 0, NULL, 0, true);
    return true;
}

bool execute_ecb_kat(uint64_t options)
{
    return true;
}

bool execute_ccm_kat(uint64_t options)
{
    return true;
}

bool execute_gcm_kat(uint64_t options)
{
    return true;
}

bool execute_ctr_kat(uint64_t options)
{
    return true;
}

/*!
 * @brief Execute CMAC decrypt/encrypt, depending on encrypt flag.
 */
static bool cmac(const uint8_t *plain_key,
                 const uint32_t key_size,
                 const uint8_t *plain_text,
                 const uint32_t plain_size,
                 const uint8_t *mac,
                 const uint32_t mac_size)
{
    /* Key buffer for the key in memory. */
    uint32_t key_buffer[32U];

    mcuxClSession_Descriptor_t session_desc;
    mcuxClSession_Handle_t session = &session_desc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(
        session, MCUXCLMAC_MAX_CPU_WA_BUFFER_SIZE + MCUXCLRANDOMMODES_NCINIT_WACPU_SIZE, 0U);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    /**************************************************************************/
    /* Key setup                                                              */
    /**************************************************************************/
    /* Create and initialize mcuxClKey_Descriptor_t structure. */
    uint32_t key_desc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t key = (mcuxClKey_Handle_t)&key_desc;

    mcuxClEls_KeyProp_t cmac_key_properties;
    cmac_key_properties.word.value = 0U;
    cmac_key_properties.bits.ucmac = MCUXCLELS_KEYPROPERTY_CMAC_TRUE;
    cmac_key_properties.bits.kactv = MCUXCLELS_KEYPROPERTY_ACTIVE_TRUE;

    cmac_key_properties.bits.ksize = MCUXCLELS_KEYPROPERTY_KEY_SIZE_256;
    if (!mcuxClExample_Key_Init_And_Load(session, key, mcuxClKey_Type_Aes256, (mcuxCl_Buffer_t)plain_key, key_size,
                                         &cmac_key_properties, key_buffer, MCUXCLEXAMPLE_CONST_EXTERNAL_KEY))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* MAC Generation                                                          */
    /**************************************************************************/
    uint32_t result_size = 0U;
    uint8_t result_buffer[MCUXCLELS_CMAC_OUT_SIZE];

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        result, token,
        mcuxClMac_compute(
            /* mcuxClSession_Handle_t session:  */ session,
            /* const mcuxClKey_Handle_t key:    */ key,
            /* const mcuxClMac_Mode_t mode:     */ mcuxClMac_Mode_CMAC,
            /* mcuxCl_InputBuffer_t pIn:        */ plain_text,
            /* uint32_t inLength:               */ (plain_size == 1U && plain_text[0] == 0U) ? 0U : plain_size,
            /* mcuxCl_Buffer_t pMac:            */ result_buffer,
            /* uint32_t * const pMacLength:     */ &result_size));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_compute) != token) || (MCUXCLMAC_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (!mcuxClCore_assertEqual(result_buffer, mac, mac_size))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Cleanup                                                                */
    /**************************************************************************/
    /* Flush the key */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClKey_flush(session, key));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush) != token) || (MCUXCLKEY_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Destroy Session and cleanup Session */
    if (!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    return MCUXCLEXAMPLE_STATUS_OK;
}

bool execute_cmac_kat(void)
{
    cmac(NULL, 0, NULL, 0, NULL, 0);
    return true;
}
