/*--------------------------------------------------------------------------*/
/* Copyright 2022 NXP                                                       */
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

/** @file  mcuxClTrng_CSS.c
 *  @brief Implementation of the Trng component which provides APIs for
 *  handling of Trng random number. This file implements the functions
 *  declared in mcuxClTrng_Internal_Functions.h. */


#include <mcuxClSession.h>
#include <mcuxClCss.h>
#include <mcuxCsslMemory.h>
#include <internal/mcuxClTrng_internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClTrng_Init)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClTrng_Status_t) mcuxClTrng_Init(void)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClTrng_Init);

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClTrng_Init, MCUXCLTRNG_STATUS_OK, MCUXCLTRNG_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClTrng_getEntropyInput)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClTrng_Status_t) mcuxClTrng_getEntropyInput(
    mcuxClSession_Handle_t pSession,
    uint32_t *pEntropyInput,
    uint32_t entropyInputLength
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClTrng_getEntropyInput);

    (void) pSession; // Parameter not needed in this mode.

    /**
     * CSS DTRNG output size must be 32 bytes.
     * We first request as much as possible directly, and then use a small buffer
     * to copy up to 32 remaining bytes.
     */

    /**
     * Note: writing to pEntropyInput could be unaligned.
     * This could be improved by: - requesting a 32 bytes
     *                            - copying as many bytes as needed to achieve alignment
     *                            - requesting the following 32 bytes to aligned addresses
     *                            - possibly requesting another 32 bytes to fill the remaining bytes
     */

    uint32_t requestSizeMin = MCUXCLTRNG_CSS_TRNG_OUTPUT_SIZE;
    uint32_t requestSizeRemainingBytes = entropyInputLength % requestSizeMin;
    uint32_t requestSizeFullWordsBytes = entropyInputLength - requestSizeRemainingBytes;
    uint32_t requestSizeLoop = requestSizeFullWordsBytes/requestSizeMin;

    /* Request as many random bytes as possible with full 32 bytes size. */
    if (requestSizeFullWordsBytes > 0u)
    {
        for(uint32_t i = 0; i < requestSizeLoop; i++)
        {
            MCUX_CSSL_FP_FUNCTION_CALL(ret_DTRNG_GetTrng1, mcuxClCss_Rng_DrbgRequestRaw_Async((uint8_t *)&pEntropyInput[i*MCUXCLTRNG_CSS_TRNG_OUTPUT_SIZE]));
            if (MCUXCLCSS_STATUS_OK_WAIT != ret_DTRNG_GetTrng1)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClTrng_getEntropyInput, MCUXCLTRNG_STATUS_ERROR,
                    (i+1) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Rng_DrbgRequestRaw_Async),
                    i * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Rng_DrbgRequestRaw_Async));
            }

            MCUX_CSSL_FP_FUNCTION_CALL(ret_DRBG_Wait1, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
            if (MCUXCLCSS_STATUS_OK != ret_DRBG_Wait1)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClTrng_getEntropyInput, MCUXCLTRNG_STATUS_ERROR,
                    (i+1) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Rng_DrbgRequestRaw_Async),
                    (i+1) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));
            }
        }
    }

    /* If requested size is not a multiple of 32, request one (additional) 32 bytes and use it only partially. */
    if (requestSizeRemainingBytes > 0u)
    {
        uint32_t requestRemainingBuffer[MCUXCLTRNG_CSS_TRNG_OUTPUT_SIZE] = {0u};

        MCUX_CSSL_FP_FUNCTION_CALL(ret_DTRNG_GetTrng2, mcuxClCss_Rng_DrbgRequestRaw_Async((uint8_t *)requestRemainingBuffer));
        if (MCUXCLCSS_STATUS_OK_WAIT != ret_DTRNG_GetTrng2)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClTrng_getEntropyInput, MCUXCLTRNG_STATUS_ERROR,
                (requestSizeLoop + 1) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Rng_DrbgRequestRaw_Async),
                requestSizeLoop * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));
        }

        MCUX_CSSL_FP_FUNCTION_CALL(ret_DRBG_Wait2, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
        if (MCUXCLCSS_STATUS_OK != ret_DRBG_Wait2)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClTrng_getEntropyInput, MCUXCLTRNG_STATUS_ERROR,
                (requestSizeLoop + 1) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Rng_DrbgRequestRaw_Async),
                (requestSizeLoop + 1) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));
        }

        /* Copy the remaining bytes from the buffer to output. */
        MCUX_CSSL_FP_FUNCTION_CALL(copy_result, mcuxCsslMemory_Copy(
           mcuxCsslParamIntegrity_Protect(4u, requestRemainingBuffer, &pEntropyInput[requestSizeFullWordsBytes], requestSizeRemainingBytes, requestSizeRemainingBytes),
               requestRemainingBuffer,
               &pEntropyInput[requestSizeFullWordsBytes],
               requestSizeRemainingBytes,
               requestSizeRemainingBytes)
        );
        if(MCUXCSSLMEMORY_STATUS_OK != copy_result)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClTrng_getEntropyInput, MCUXCLTRNG_STATUS_ERROR);
        }

    }

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClTrng_getEntropyInput, MCUXCLTRNG_STATUS_OK, MCUXCLTRNG_STATUS_FAULT_ATTACK,
            MCUX_CSSL_FP_CONDITIONAL((requestSizeFullWordsBytes > 0u),
               (entropyInputLength/MCUXCLTRNG_CSS_TRNG_OUTPUT_SIZE) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Rng_DrbgRequestRaw_Async),
               (entropyInputLength/MCUXCLTRNG_CSS_TRNG_OUTPUT_SIZE) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation)),
            MCUX_CSSL_FP_CONDITIONAL((requestSizeRemainingBytes > 0u),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Rng_DrbgRequestRaw_Async),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Copy)));
}
