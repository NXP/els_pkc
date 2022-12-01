/*--------------------------------------------------------------------------*/
/* Copyright 2021-2022 NXP                                                  */
/*                                                                          */
/* NXP Confidential. This software is owned or controlled by NXP and may    */
/* only be used strictly in accordance with the applicable license terms.   */
/* By expressly accepting such terms or by downloading, installing,         */
/* activating and/or otherwise using the software, you are agreeing that    */
/* you have read, and that you agree to comply with and are bound by, such  */
/* license terms. If you do not agree to be bound by the applicable license */
/* terms, then you may not retain, install, activate or otherwise use the   */
/* software.                                                                */
/*--------------------------------------------------------------------------*/

/** @file  mcuxClRandom_CssMode.c
 *  @brief Implementation of the Random component which provides APIs for
 *  handling of random number generators. This file implements the functions
 *  declared in mcuxClRandom.h. */


#include <mcuxClSession.h>
#include <mcuxClCss.h>
#include <mcuxClRandom.h>
#include <internal/mcuxClRandom_Private_Types.h>

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandom_CssMode_init)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_CssMode_init(
    mcuxClSession_Handle_t pSession
);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandom_CssMode_reseed)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_CssMode_reseed(
    mcuxClSession_Handle_t pSession
);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandom_CssMode_selftest)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_CssMode_selftest(
    mcuxClSession_Handle_t pSession,
    mcuxClRandom_Mode_t mode
);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandom_CssMode_generate)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_CssMode_generate(
    mcuxClSession_Handle_t pSession,
    uint8_t *             pOut,
    uint32_t              outLength
);

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_CssMode_init)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_CssMode_init(
    mcuxClSession_Handle_t pSession
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_CssMode_init);

    (void) pSession; // Parameter not needed in this mode.
	MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClRandom_CssMode_init, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_CssMode_reseed)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_CssMode_reseed(
    mcuxClSession_Handle_t pSession
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_CssMode_reseed);

    (void) pSession; // Parameter not needed in this mode.
	MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClRandom_CssMode_reseed, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_CssMode_selftest)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_CssMode_selftest(
    mcuxClSession_Handle_t pSession,
	mcuxClRandom_Mode_t mode
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_CssMode_selftest);

    (void) pSession; // Parameter not needed in this mode.
	MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClRandom_CssMode_selftest, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_CssMode_generate)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_CssMode_generate(
    mcuxClSession_Handle_t pSession,
    uint8_t *             pOut,
    uint32_t              outLength
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_CssMode_generate);

    (void) pSession; // Parameter not needed in this mode.

    /**
     * CSS DRBG output size must be a multiple of 4.
     * We first request as much as possible directly, and then use a small buffer
     * to copy up to 3 remaining bytes.
     */

    /**
     * Note: writing to pOut could be unaligned.
     * This could be improved by: - requesting a single word
     *                            - copying as many bytes as needed to achieve alignment
     *                            - requesting the following words to aligned addresses
     *                            - possibly requesting another single word to fill the remaining bytes
     */

    uint32_t requestSizeMin = MCUXCLCSS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MIN_SIZE;
    uint32_t requestSizeRemainingBytes = outLength % requestSizeMin;
    uint32_t requestSizeFullWordsBytes = outLength - requestSizeRemainingBytes;

    /* Request as many random bytes as possible with full word size. */
    if (requestSizeFullWordsBytes > 0u)
    {
        MCUX_CSSL_FP_FUNCTION_CALL(ret_DRBG_GetRandom1, mcuxClCss_Rng_DrbgRequest_Async(pOut, requestSizeFullWordsBytes));
        if (MCUXCLCSS_STATUS_OK_WAIT != ret_DRBG_GetRandom1)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CssMode_generate, MCUXCLRANDOM_STATUS_ERROR,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Rng_DrbgRequest_Async));
        }

        MCUX_CSSL_FP_FUNCTION_CALL(ret_DRBG_Wait1, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
        if (MCUXCLCSS_STATUS_OK != ret_DRBG_Wait1)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CssMode_generate, MCUXCLRANDOM_STATUS_ERROR,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Rng_DrbgRequest_Async),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));
        }
    }

    /* If requested size is not a multiple of 4, request one (additional) word and use it only partially. */
    if (requestSizeRemainingBytes > 0u)
    {
        uint8_t requestRemainingBuffer[MCUXCLCSS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MIN_SIZE] = {0u};

        MCUX_CSSL_FP_FUNCTION_CALL(ret_DRBG_GetRandom2, mcuxClCss_Rng_DrbgRequest_Async(requestRemainingBuffer,
                                                                                     requestSizeMin));
        if (MCUXCLCSS_STATUS_OK_WAIT != ret_DRBG_GetRandom2)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CssMode_generate, MCUXCLRANDOM_STATUS_ERROR,
                2u * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Rng_DrbgRequest_Async),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));
        }

        MCUX_CSSL_FP_FUNCTION_CALL(ret_DRBG_Wait2, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
        if (MCUXCLCSS_STATUS_OK != ret_DRBG_Wait2)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CssMode_generate, MCUXCLRANDOM_STATUS_ERROR,
                2u * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Rng_DrbgRequest_Async),
                2u * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));
        }

        /* Copy the remaining bytes from the buffer to output. */
        for(uint32_t i = 0; i < requestSizeRemainingBytes; i++)
        {
            pOut[requestSizeFullWordsBytes + i] = requestRemainingBuffer[i];
        }

    }

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClRandom_CssMode_generate, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK,
            MCUX_CSSL_FP_CONDITIONAL((requestSizeFullWordsBytes > 0u),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Rng_DrbgRequest_Async),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation)),
            MCUX_CSSL_FP_CONDITIONAL((requestSizeRemainingBytes > 0u),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Rng_DrbgRequest_Async),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation)));
}


const mcuxClRandom_OperationModeDescriptor_t mcuxClRandom_OperationModeDescriptor_CSS_Drbg = {
    .initFunction                    = mcuxClRandom_CssMode_init,
    .reseedFunction                  = mcuxClRandom_CssMode_reseed,
    .generateFunction                = mcuxClRandom_CssMode_generate,
    .selftestFunction                = mcuxClRandom_CssMode_selftest,
    .protectionTokenInitFunction     = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_CssMode_init),
    .protectionTokenReseedFunction   = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_CssMode_reseed),
    .protectionTokenGenerateFunction = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_CssMode_generate),
    .protectionTokenSelftestFunction = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_CssMode_selftest),
    .operationMode                   = MCUXCLRANDOM_CSSMODE
};


const mcuxClRandom_ModeDescriptor_t mcuxClRandom_mdCSS_Drbg = {
    .pOperationMode   = &mcuxClRandom_OperationModeDescriptor_CSS_Drbg,
    .pDrbgMode        = NULL,
    .contextSize      = 0u,
    .auxParam         = 0u,
    .securityStrength = 128u
};

