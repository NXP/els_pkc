/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "els_pkc_fips_hash.h"

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
 * @brief Execute SHA hash algorithm.
 */
static bool sha2(const uint8_t *msg,
                 const uint32_t msg_size,
                 const uint8_t *input_md,
                 const uint32_t md_size,
                 const mcuxClHash_Algo_t sha_algorithm)
{
    /* Initialize session */
    mcuxClSession_Descriptor_t session_desc;
    mcuxClSession_Handle_t session = &session_desc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(
        session, MCUXCLHASH_MAX_CPU_WA_BUFFER_SIZE + MCUXCLRANDOMMODES_NCINIT_WACPU_SIZE, 0U);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    /**************************************************************************/
    /* Hash computation                                                       */
    /**************************************************************************/
    uint32_t hash_output_size = 0U;
    uint8_t output_md[64U];
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token2,
                                     mcuxClHash_compute(
                                         /* mcuxClSession_Handle_t session: */ session,
                                         /* mcuxClHash_Algo_t algorithm:    */ sha_algorithm,
                                         /* mcuxCl_InputBuffer_t pIn:       */ msg,
                                         /* uint32_t inSize:                */ msg_size,
                                         /* mcuxCl_Buffer_t pOut            */ output_md,
                                         /* uint32_t *const pOutSize,       */ &hash_output_size));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute) != token2) || (MCUXCLHASH_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (!mcuxClCore_assertEqual(input_md, output_md, md_size))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Session clean-up                                                       */
    /**************************************************************************/
    /** Destroy Session and cleanup Session **/
    if (!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    return MCUXCLEXAMPLE_STATUS_OK;
}

void execute_sha_kat(uint64_t options, char name[])
{
    if ((options & FIPS_SHA224) || (options & FIPS_ALL_TESTS))
    {
        const uint8_t msg[11U]     = {0x6FU, 0x29U, 0xCAU, 0x27U, 0x41U, 0x90U, 0x40U, 0x07U, 0x20U, 0xBBU, 0xA2U};
        const uint8_t mac_kat[28U] = {0xACU, 0x53U, 0x15U, 0x79U, 0x47U, 0xAAU, 0x4BU, 0x2AU, 0x19U, 0x08U,
                                      0x91U, 0x82U, 0x38U, 0x2AU, 0x43U, 0x63U, 0xD1U, 0x82U, 0xDDU, 0x8EU,
                                      0x4CU, 0xA7U, 0x9CU, 0xD8U, 0x57U, 0x13U, 0x90U, 0xBEU};
        if (!sha2(msg, sizeof(msg), mac_kat, sizeof(mac_kat), mcuxClHash_Algorithm_Sha224))
        {
            PRINTF("[ERROR] %s KAT FAILED\r\n", name);
        }
    }
    if ((options & FIPS_SHA256) || (options & FIPS_ALL_TESTS))
    {
        const uint8_t msg[11U]     = {0x76U, 0xEDU, 0x24U, 0xA0U, 0xF4U, 0x0AU, 0x41U, 0x22U, 0x1EU, 0xBFU, 0xCFU};
        const uint8_t mac_kat[32U] = {0x04U, 0x4CU, 0xEFU, 0x80U, 0x29U, 0x01U, 0x93U, 0x2EU, 0x46U, 0xDCU, 0x46U,
                                      0xB2U, 0x54U, 0x5EU, 0x6CU, 0x99U, 0xC0U, 0xFCU, 0x32U, 0x3AU, 0x0EU, 0xD9U,
                                      0x9BU, 0x08U, 0x1BU, 0xDAU, 0x42U, 0x16U, 0x85U, 0x7FU, 0x38U, 0xACU};
        if (!sha2(msg, sizeof(msg), mac_kat, sizeof(mac_kat), mcuxClHash_Algorithm_Sha256))
        {
            PRINTF("[ERROR] %s KAT FAILED\r\n", name);
        }
    }
    if ((options & FIPS_SHA384) || (options & FIPS_ALL_TESTS))
    {
        const uint8_t msg[11U]     = {0x96U, 0x7FU, 0xA3U, 0x4CU, 0x07U, 0xE4U, 0x94U, 0x5AU, 0x77U, 0x05U, 0x1AU};
        const uint8_t mac_kat[48U] = {0xF8U, 0xF2U, 0x4DU, 0x81U, 0xC4U, 0xF8U, 0xF2U, 0x3EU, 0xCBU, 0x42U,
                                      0xD7U, 0x6EU, 0xD5U, 0xD2U, 0xB3U, 0x4CU, 0x9CU, 0xBCU, 0x1FU, 0x0AU,
                                      0x97U, 0x23U, 0x4DU, 0x11U, 0x14U, 0x80U, 0x4BU, 0x59U, 0x99U, 0x75U,
                                      0x9FU, 0x31U, 0x31U, 0xC7U, 0x41U, 0xD5U, 0x76U, 0x8CU, 0xC9U, 0x28U,
                                      0x16U, 0x35U, 0x03U, 0xC5U, 0xF5U, 0x5FU, 0x59U, 0x4BU};
        if (!sha2(msg, sizeof(msg), mac_kat, sizeof(mac_kat), mcuxClHash_Algorithm_Sha384))
        {
            PRINTF("[ERROR] %s KAT FAILED\r\n", name);
        }
    }
    if ((options & FIPS_SHA512) || (options & FIPS_ALL_TESTS))
    {
        const uint8_t msg[11U]     = {0x62U, 0x13U, 0xE1U, 0x0AU, 0x44U, 0x20U, 0xE0U, 0xD9U, 0xB7U, 0x70U, 0x37U};
        const uint8_t mac_kat[64U] = {0x99U, 0x82U, 0xDCU, 0x2AU, 0x04U, 0xDFU, 0xF1U, 0x65U, 0x56U, 0x7FU, 0x27U,
                                      0x6FU, 0xD4U, 0x63U, 0xEFU, 0xEFU, 0x2BU, 0x36U, 0x9FU, 0xA2U, 0xFBU, 0xCAU,
                                      0x8CU, 0xEEU, 0x31U, 0xCEU, 0x0DU, 0xE8U, 0xA7U, 0x9AU, 0x2EU, 0xB0U, 0xB5U,
                                      0x3EU, 0x43U, 0x7FU, 0x7DU, 0x9DU, 0x1FU, 0x41U, 0xC7U, 0x1DU, 0x72U, 0x5CU,
                                      0xABU, 0xB9U, 0x49U, 0xB5U, 0x13U, 0x07U, 0x5BU, 0xADU, 0x17U, 0x40U, 0xC9U,
                                      0xEEU, 0xFBU, 0xF6U, 0xA5U, 0xC6U, 0x63U, 0x34U, 0x00U, 0xC7U};
        if (!sha2(msg, sizeof(msg), mac_kat, sizeof(mac_kat), mcuxClHash_Algorithm_Sha512))
        {
            PRINTF("[ERROR] %s KAT FAILED\r\n", name);
        }
    }
}
