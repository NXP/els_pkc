/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "hmac_test.h"

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
 * @brief Execute HMAC.
 */
static bool hmac(const uint8_t *plain_key,
                 const uint32_t key_size,
                 const uint8_t *plain_text,
                 const uint32_t plain_size,
                 const uint8_t *mac,
                 const uint32_t mac_size,
                 const mcuxClHash_Algo_t hash_algorithm)
{
    /* Key buffer for the key in memory. */
    uint32_t key_buffer[142U];

    /* Allocate and initialize session / workarea */
    mcuxClSession_Descriptor_t session_desc;
    mcuxClSession_Handle_t session = &session_desc;

    /* Allocate and initialize session / workarea */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(
        session, MCUXCLHMAC_MAX_CPU_WA_BUFFER_SIZE + MCUXCLRANDOMMODES_NCINIT_WACPU_SIZE, 0U);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    /**************************************************************************/
    /* Key setup                                                              */
    /**************************************************************************/
    /* Create and initialize mcuxClKey_Descriptor_t structure. */
    uint32_t key_desc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t key = (mcuxClKey_Handle_t)&key_desc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        keyInit_result, keyInit_token,
        mcuxClKey_init(
            /* mcuxClSession_Handle_t pSession:                */ session,
            /* mcuxClKey_Handle_t key:                         */ key,
            /* const mcuxClKey_Type* type:                     */ mcuxClKey_Type_Hmac_variableLength,
            /* mcuxCl_Buffer_t pKeyData:                       */ (uint8_t *)plain_key,
            /* uint32_t keyDataLength:                         */ key_size));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != keyInit_token) || (MCUXCLKEY_STATUS_OK != keyInit_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Load key to memory. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(keyLoad_result, keyLoad_token, mcuxClKey_loadMemory(session, key, key_buffer));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_loadMemory) != keyLoad_token) ||
        (MCUXCLKEY_STATUS_OK != keyLoad_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Generate an HMAC mode containing the hash algorithm                    */
    /**************************************************************************/
    uint8_t hmac_mode_desc_buffer[MCUXCLHMAC_HMAC_MODE_DESCRIPTOR_SIZE];
    mcuxClMac_CustomMode_t mode = (mcuxClMac_CustomMode_t)hmac_mode_desc_buffer;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(hashCreateMode_result, hashCreateMode_token,
                                     mcuxClHmac_createHmacMode(
                                         /* mcuxClMac_CustomMode_t mode:       */ mode,
                                         /* mcuxClHash_Algo_t hashAlgorithm:   */ hash_algorithm));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHmac_createHmacMode) != hashCreateMode_token) ||
        (MCUXCLMAC_STATUS_OK != hashCreateMode_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* HMAC computation                                                       */
    /**************************************************************************/
    uint8_t result_buffer[128U];

    /* Call the mcuxClMac_compute function to compute a HMAC in one shot. */
    uint32_t result_size = 0U;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(macCompute_result, macCompute_token,
                                     mcuxClMac_compute(
                                         /* mcuxClSession_Handle_t session:  */ session,
                                         /* const mcuxClKey_Handle_t key:    */ key,
                                         /* const mcuxClMac_Mode_t mode:     */ mode,
                                         /* mcuxCl_InputBuffer_t pIn:        */ plain_text,
                                         /* uint32_t inLength:               */ plain_size,
                                         /* mcuxCl_Buffer_t pMac:            */ result_buffer,
                                         /* uint32_t * const pMacLength:     */ &result_size));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_compute) != macCompute_token) ||
        (MCUXCLMAC_STATUS_OK != macCompute_result))
    {
        PRINTF("[Error] HMAC failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (!mcuxClCore_assertEqual(result_buffer, mac, mac_size))
    {
        PRINTF("OUR MAC == with result size == %d\r\n", result_size);
        PRINT_ARRAY(result_buffer, mac_size);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Cleanup                                                                */
    /**************************************************************************/
    /* Flush the key. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(keyFlush_result, keyFlush_token, mcuxClKey_flush(session, key));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush) != keyFlush_token) || (MCUXCLKEY_STATUS_OK != keyFlush_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Clean-up and destroy the session. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(sessionCleanup_result, sessionCleanup_token, mcuxClSession_cleanup(session));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != sessionCleanup_token ||
        MCUXCLSESSION_STATUS_OK != sessionCleanup_result)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(sessionDestroy_result, sessionDestroy_token, mcuxClSession_destroy(session));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != sessionDestroy_token ||
        MCUXCLSESSION_STATUS_OK != sessionDestroy_result)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return true;
}

bool execute_hmac_kat(void)
{
    uint32_t test_amount  = sizeof(s_HmacMsgArraySize) / sizeof(s_HmacMsgArraySize[0U]);
    uint16_t tests_passed = 0U;
    for (uint32_t i = 0; i < test_amount; ++i)
    {
        const uint8_t *cur_key   = s_HmacKeyPtr[i];
        const uint8_t *cur_plain = s_HmacMsgPtr[i];
        const uint8_t *cur_mac   = s_HmacMacPtr[i];

        if (64U == s_HmacMacArraySize[i])
        {
            if (MCUXCLEXAMPLE_STATUS_OK == hmac(cur_key, s_HmacKeyArraySize[i], cur_plain, s_HmacMsgArraySize[i],
                                                cur_mac, s_HmacMacArraySize[i], mcuxClHash_Algorithm_Sha512))
            {
                ++tests_passed;
                PRINTF("HMAC PASSED with key length %d, tests passed == %d of total %d tests\r\n",
                       s_HmacKeyArraySize[i], tests_passed, test_amount);
            }
            else
            {
                PRINTF("------------------------\r\n");
                PRINTF("KAT MAC == \r\n");
                PRINT_ARRAY(cur_mac, s_HmacMacArraySize[i]);
                PRINTF("KEY == \r\n");
                PRINT_ARRAY(cur_key, s_HmacKeyArraySize[i]);
                PRINTF("MSG == with size == %d\r\n", s_HmacMsgArraySize[i]);
                PRINT_ARRAY(cur_plain, s_HmacMsgArraySize[i]);
                PRINTF("------------------------\r\n\n\n");
                PRINTF("HMAC 512 FAILED\r\n");
            }
        }
    }
    PRINTF("\r\n");
    return true;
}
