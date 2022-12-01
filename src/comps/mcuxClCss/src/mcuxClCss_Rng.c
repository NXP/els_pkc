/*--------------------------------------------------------------------------*/
/* Copyright 2020-2022 NXP                                                  */
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

/**
 * @file mcuxClCss_Rng.c
 * @brief CSSv2 implementation for  random number generation.
 * This file implements the functions declared in mcuxClCss_Rng.h.
 */

#include <platform_specific_headers.h>
#include <stdbool.h>
#include <mcuxClCss_Rng.h>              // Implement mcuxClCss interface "Rng"
#include <mcuxClMemory.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <toolchain.h>
#include <mcuxClCss.h>
#include <internal/mcuxClCss_Internal.h>
#include <internal/mcuxClMemory_Copy_Internal.h>

#define RANDOM_BIT_ARRAY_SIZE 4U

// Command name change -- should move to top level platform header
#ifndef ID_CFG_CSS_CMD_RND_REQ
#define ID_CFG_CSS_CMD_RND_REQ ID_CFG_CSS_CMD_DRBG_REQ
#endif

// Utility code of mcuxClCss implementation for PRNG access

/**
 * Gets a pseudo-random 32-bit integer from the CSS PRNG.
 */
static inline uint32_t css_getPRNGWord(
    void)
{
    return MCUXCLCSS_SFR_READ(CSS_PRNG_DATOUT);
}

// Implementation of mcuxClCss interface "Rng"

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Rng_DrbgRequest_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Rng_DrbgRequest_Async(
    uint8_t * pOutput,
    size_t outputLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Rng_DrbgRequest_Async);

    MCUXCLCSS_INPUT_PARAM_CHECK_PROTECTED(mcuxClCss_Rng_DrbgRequest_Async, (MCUXCLCSS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MIN_SIZE > outputLength) || 
                                                                         (MCUXCLCSS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MAX_SIZE < outputLength) ||
                                                                         (0U != outputLength % 4U));

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Rng_DrbgRequest_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClCss_setOutput(pOutput, outputLength);

    mcuxClCss_startCommand(ID_CFG_CSS_CMD_RND_REQ, 0U, CSS_CMD_LITTLE_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Rng_DrbgRequest_Async, MCUXCLCSS_STATUS_OK_WAIT);
}

#ifdef MCUXCL_FEATURE_CSS_RND_RAW
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Rng_DrbgRequestRaw_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Rng_DrbgRequestRaw_Async(
    uint8_t * pOutput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Rng_DrbgRequestRaw_Async);

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Rng_DrbgRequestRaw_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClCss_setOutput_fixedSize(pOutput);

    mcuxClCss_startCommand(ID_CFG_CSS_CMD_RND_REQ, MCUXCLCSS_RNG_RND_REQ_RND_RAW, CSS_CMD_LITTLE_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Rng_DrbgRequestRaw_Async, MCUXCLCSS_STATUS_OK_WAIT);
}
#endif /* MCUXCL_FEATURE_CSS_RND_RAW */

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Rng_DrbgTestInstantiate_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Rng_DrbgTestInstantiate_Async(
    uint8_t const * pEntropy)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Rng_DrbgTestInstantiate_Async);

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Rng_DrbgTestInstantiate_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClCss_setInput0_fixedSize(pEntropy);

    mcuxClCss_startCommand(ID_CFG_CSS_CMD_DRBG_TEST, MCUXCLCSS_RNG_DRBG_TEST_MODE_INSTANTIATE, CSS_CMD_LITTLE_ENDIAN);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Rng_DrbgTestInstantiate_Async, MCUXCLCSS_STATUS_OK_WAIT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Rng_DrbgTestExtract_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Rng_DrbgTestExtract_Async(
    uint8_t * pOutput,
    size_t outputLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Rng_DrbgTestExtract_Async);

    MCUXCLCSS_INPUT_PARAM_CHECK_PROTECTED(mcuxClCss_Rng_DrbgTestExtract_Async, (MCUXCLCSS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MIN_SIZE > outputLength) || 
                                                                             (MCUXCLCSS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MAX_SIZE < outputLength) ||
                                                                             (0U != outputLength % 4U));

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Rng_DrbgTestExtract_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClCss_setOutput(pOutput, outputLength);

    mcuxClCss_startCommand(ID_CFG_CSS_CMD_DRBG_TEST, MCUXCLCSS_RNG_DRBG_TEST_MODE_EXTRACT, CSS_CMD_LITTLE_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Rng_DrbgTestExtract_Async, MCUXCLCSS_STATUS_OK_WAIT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Rng_DrbgTestAesEcb_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Rng_DrbgTestAesEcb_Async(
    uint8_t const * pDataKey,
    uint8_t * pOutput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Rng_DrbgTestAesEcb_Async);

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Rng_DrbgTestAesEcb_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClCss_setInput1_fixedSize(pDataKey);
    mcuxClCss_setOutput_fixedSize(pOutput);

    mcuxClCss_startCommand(ID_CFG_CSS_CMD_DRBG_TEST, MCUXCLCSS_RNG_DRBG_TEST_MODE_AES_ECB, CSS_CMD_LITTLE_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Rng_DrbgTestAesEcb_Async, MCUXCLCSS_STATUS_OK_WAIT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Rng_DrbgTestAesCtr_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Rng_DrbgTestAesCtr_Async(
    uint8_t const * pData,
    size_t dataLength,
    uint8_t const * pIvKey,
    uint8_t * pOutput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Rng_DrbgTestAesCtr_Async);

    MCUXCLCSS_INPUT_PARAM_CHECK_PROTECTED(mcuxClCss_Rng_DrbgTestAesCtr_Async, (0U != (dataLength % 16U)) || (0U == dataLength));

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Rng_DrbgTestAesCtr_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClCss_setInput0(pData, dataLength);
    mcuxClCss_setInput1_fixedSize(pIvKey);
    mcuxClCss_setOutput_fixedSize(pOutput);

    mcuxClCss_startCommand(ID_CFG_CSS_CMD_DRBG_TEST, MCUXCLCSS_RNG_DRBG_TEST_MODE_AES_CTR, CSS_CMD_LITTLE_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Rng_DrbgTestAesCtr_Async, MCUXCLCSS_STATUS_OK_WAIT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Rng_Dtrng_ConfigLoad_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Rng_Dtrng_ConfigLoad_Async(
    uint8_t const * pInput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Rng_Dtrng_ConfigLoad_Async);

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Rng_Dtrng_ConfigLoad_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClCss_setInput0_fixedSize(pInput);
    mcuxClCss_startCommand(ID_CFG_CSS_CMD_DTRNG_CFG_LOAD, 0U, CSS_CMD_LITTLE_ENDIAN);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Rng_Dtrng_ConfigLoad_Async, MCUXCLCSS_STATUS_OK_WAIT);
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Rng_Dtrng_ConfigEvaluate_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Rng_Dtrng_ConfigEvaluate_Async(
    uint8_t const * pInput,
    uint8_t * pOutput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Rng_Dtrng_ConfigEvaluate_Async);

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Rng_Dtrng_ConfigEvaluate_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClCss_setInput0_fixedSize(pInput);
    mcuxClCss_setOutput_fixedSize(pOutput);
    mcuxClCss_startCommand(ID_CFG_CSS_CMD_DTRNG_EVAL, 0U, CSS_CMD_LITTLE_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Rng_Dtrng_ConfigEvaluate_Async, MCUXCLCSS_STATUS_OK_WAIT);
}

#ifdef MCUXCL_FEATURE_CSS_PRND_INIT
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Prng_Init_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Prng_Init_Async(
    void)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Prng_Init_Async);

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Prng_Init_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClCss_startCommand(ID_CFG_CSS_CMD_RND_REQ, MCUXCLCSS_RNG_RND_REQ_PRND_INIT, CSS_CMD_LITTLE_ENDIAN);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Prng_Init_Async, MCUXCLCSS_STATUS_OK_WAIT);
}
#endif /* MCUXCL_FEATURE_CSS_PRND_INIT */

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Prng_GetRandomWord)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Prng_GetRandomWord(
    uint32_t * pWord)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Prng_GetRandomWord);

    *pWord = css_getPRNGWord();

    /* check if enough entropy is available */
    if (MCUXCLCSS_IS_ERROR_BIT_SET(MCUXCLCSS_SFR_CSS_ERR_STATUS_PRNG_ERR))
    {
        /* clear CSS error flags */
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCss_ResetErrorFlags());  /* always returns MCUXCLCSS_STATUS_OK. */

        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Prng_GetRandomWord, MCUXCLCSS_STATUS_HW_PRNG,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_ResetErrorFlags));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Prng_GetRandomWord, MCUXCLCSS_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Prng_GetRandom)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Prng_GetRandom(
    uint8_t * pOutput,
    size_t outputLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Prng_GetRandom);

    uint8_t * bytePtr = pOutput;
    uint8_t * const pOutputEnd = pOutput + outputLength;

    /* Fetch one word of PRNG and fill the leading "not word aligned" bytes */
    if (0u != ((uint32_t) bytePtr & 0x03u))
    {
        uint32_t randomWord = css_getPRNGWord();
        do
        {
            *bytePtr = (uint8_t) (randomWord & 0xFFu);
            bytePtr += 1u;
            randomWord >>= 8u;
        } while ((0u != ((uint32_t) bytePtr & 0x03u)) && (pOutputEnd > bytePtr));
    }

    /* Fill the specified buffer wordwise */
    uint8_t * const pOutputWordEnd = (uint8_t*) ((uint32_t) pOutputEnd & 0xFFFFFFFCu);
    while (pOutputWordEnd > bytePtr)
    {
        mcuxClMemory_StoreLittleEndian32(bytePtr, css_getPRNGWord());
        bytePtr += 4;
    }

    /* Fetch one word of PRNG and fill the remaining "less than one word" bytes */
    if (pOutputEnd > bytePtr)
    {
        uint32_t randomWord = css_getPRNGWord();
        do
        {
            *bytePtr = (uint8_t) (randomWord & 0xFFu);
            bytePtr += 1u;
            randomWord >>= 8u;
        } while (pOutputEnd > bytePtr);
    }

    /* check if enough entropy is available */
    if (MCUXCLCSS_IS_ERROR_BIT_SET(MCUXCLCSS_SFR_CSS_ERR_STATUS_PRNG_ERR))
    {
        /* clear CSS error flags */
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCss_ResetErrorFlags());  /* always returns MCUXCLCSS_STATUS_OK. */

        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Prng_GetRandom, MCUXCLCSS_STATUS_HW_PRNG,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_ResetErrorFlags));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Prng_GetRandom, MCUXCLCSS_STATUS_OK);
}
