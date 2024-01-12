/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "hash_algorithm_tests.h"

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
static bool sha(const uint8_t *msg,
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
    uint8_t output_md[32U];
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        result, token2,
        mcuxClHash_compute(
            /* mcuxClSession_Handle_t session: */ session,
            /* mcuxClHash_Algo_t algorithm:    */ sha_algorithm,
            /* mcuxCl_InputBuffer_t pIn:       */ msg,
            /* uint32_t inSize:                */ (msg_size == 1U && msg[0] == 0U) ? 0U : msg_size,
            /* mcuxCl_Buffer_t pOut            */ output_md,
            /* uint32_t *const pOutSize,       */ &hash_output_size));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute) != token2) || (MCUXCLHASH_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (!mcuxClCore_assertEqual(input_md, output_md, hash_output_size))
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

bool execute_sha_kat(void)
{
    uint32_t test_amount  = sizeof(s_Sha256MdArraySize) / sizeof(s_Sha256MdArraySize[0U]);
    uint16_t tests_passed = 0U;
    for (uint32_t i = 0U; i < test_amount; ++i)
    {
        const uint8_t *cur_msg = s_Sha256MsgPtr[i];
        const uint8_t *cur_md  = s_Sha256MdPtr[i];

        if (MCUXCLEXAMPLE_STATUS_OK !=
            sha(cur_msg, s_Sha256MsgArraySize[i], cur_md, s_Sha256MdArraySize[i], mcuxClHash_Algorithm_Sha256))
            return false;
    }

    test_amount = sizeof(s_Sha384MdArraySize) / sizeof(s_Sha384MdArraySize[0]);
    for (uint32_t i = 0U; i < test_amount; ++i)
    {
        const uint8_t *cur_msg = s_Sha384MsgPtr[i];
        const uint8_t *cur_md  = s_Sha384MdPtr[i];

        if (MCUXCLEXAMPLE_STATUS_OK !=
            sha(cur_msg, s_Sha384MsgArraySize[i], cur_md, s_Sha384MdArraySize[i], mcuxClHash_Algorithm_Sha384))
            return false;
    }

    test_amount = sizeof(s_Sha512MdArraySize) / sizeof(s_Sha512MdArraySize[0]);
    for (uint32_t i = 0U; i < test_amount; ++i)
    {
        const uint8_t *cur_msg = s_Sha512MsgPtr[i];
        const uint8_t *cur_md  = s_Sha512MdPtr[i];

        if (MCUXCLEXAMPLE_STATUS_OK !=
            sha(cur_msg, s_Sha512MsgArraySize[i], cur_md, s_Sha512MdArraySize[i], mcuxClHash_Algorithm_Sha512))
            return false;
    }
    return true;
}
