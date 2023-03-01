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
 * @file mcuxClEls_Rng.c
 * @brief ELS implementation for  random number generation.
 * This file implements the functions declared in mcuxClEls_Rng.h.
 */

#include <platform_specific_headers.h>
#include <stdbool.h>
#include <mcuxClEls_Rng.h>              // Implement mcuxClEls interface "Rng"
#include <mcuxClMemory.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <toolchain.h>
#include <mcuxClEls.h>
#include <internal/mcuxClEls_Internal.h>
#include <internal/mcuxClMemory_Copy_Internal.h>

#define RANDOM_BIT_ARRAY_SIZE 4U

// Command name change -- should move to top level platform header
#ifndef ID_CFG_ELS_CMD_RND_REQ
#define ID_CFG_ELS_CMD_RND_REQ ID_CFG_ELS_CMD_DRBG_REQ
#endif

// Utility code of mcuxClEls implementation for PRNG access

/**
 * Gets a pseudo-random 32-bit integer from the ELS PRNG.
 */
static inline uint32_t els_getPRNGWord(
    void)
{
    return MCUXCLELS_SFR_READ(ELS_PRNG_DATOUT);
}

// Implementation of mcuxClEls interface "Rng"

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Rng_DrbgRequest_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Rng_DrbgRequest_Async(
    uint8_t * pOutput,
    size_t outputLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Rng_DrbgRequest_Async);

    MCUXCLELS_INPUT_PARAM_CHECK_PROTECTED(mcuxClEls_Rng_DrbgRequest_Async, (MCUXCLELS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MIN_SIZE > outputLength) || 
                                                                         (MCUXCLELS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MAX_SIZE < outputLength) ||
                                                                         (0U != outputLength % 4U));

    /* ELS SFRs are not cached => Tell SW to wait for ELS to come back from BUSY state before modifying the SFRs */
    if (mcuxClEls_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Rng_DrbgRequest_Async, MCUXCLELS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClEls_setOutput(pOutput, outputLength);

    mcuxClEls_startCommand(ID_CFG_ELS_CMD_RND_REQ, 0U, ELS_CMD_LITTLE_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Rng_DrbgRequest_Async, MCUXCLELS_STATUS_OK_WAIT);
}

#ifdef MCUXCL_FEATURE_ELS_RND_RAW
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Rng_DrbgRequestRaw_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Rng_DrbgRequestRaw_Async(
    uint8_t * pOutput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Rng_DrbgRequestRaw_Async);

    /* ELS SFRs are not cached => Tell SW to wait for ELS to come back from BUSY state before modifying the SFRs */
    if (mcuxClEls_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Rng_DrbgRequestRaw_Async, MCUXCLELS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClEls_setOutput_fixedSize(pOutput);

    mcuxClEls_startCommand(ID_CFG_ELS_CMD_RND_REQ, MCUXCLELS_RNG_RND_REQ_RND_RAW, ELS_CMD_LITTLE_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Rng_DrbgRequestRaw_Async, MCUXCLELS_STATUS_OK_WAIT);
}
#endif /* MCUXCL_FEATURE_ELS_RND_RAW */

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Rng_DrbgTestInstantiate_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Rng_DrbgTestInstantiate_Async(
    uint8_t const * pEntropy)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Rng_DrbgTestInstantiate_Async);

    /* ELS SFRs are not cached => Tell SW to wait for ELS to come back from BUSY state before modifying the SFRs */
    if (mcuxClEls_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Rng_DrbgTestInstantiate_Async, MCUXCLELS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClEls_setInput0_fixedSize(pEntropy);

    mcuxClEls_startCommand(ID_CFG_ELS_CMD_DRBG_TEST, MCUXCLELS_RNG_DRBG_TEST_MODE_INSTANTIATE, ELS_CMD_LITTLE_ENDIAN);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Rng_DrbgTestInstantiate_Async, MCUXCLELS_STATUS_OK_WAIT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Rng_DrbgTestExtract_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Rng_DrbgTestExtract_Async(
    uint8_t * pOutput,
    size_t outputLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Rng_DrbgTestExtract_Async);

    MCUXCLELS_INPUT_PARAM_CHECK_PROTECTED(mcuxClEls_Rng_DrbgTestExtract_Async, (MCUXCLELS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MIN_SIZE > outputLength) || 
                                                                             (MCUXCLELS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MAX_SIZE < outputLength) ||
                                                                             (0U != outputLength % 4U));

    /* ELS SFRs are not cached => Tell SW to wait for ELS to come back from BUSY state before modifying the SFRs */
    if (mcuxClEls_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Rng_DrbgTestExtract_Async, MCUXCLELS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClEls_setOutput(pOutput, outputLength);

    mcuxClEls_startCommand(ID_CFG_ELS_CMD_DRBG_TEST, MCUXCLELS_RNG_DRBG_TEST_MODE_EXTRACT, ELS_CMD_LITTLE_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Rng_DrbgTestExtract_Async, MCUXCLELS_STATUS_OK_WAIT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Rng_DrbgTestAesEcb_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Rng_DrbgTestAesEcb_Async(
    uint8_t const * pDataKey,
    uint8_t * pOutput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Rng_DrbgTestAesEcb_Async);

    /* ELS SFRs are not cached => Tell SW to wait for ELS to come back from BUSY state before modifying the SFRs */
    if (mcuxClEls_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Rng_DrbgTestAesEcb_Async, MCUXCLELS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClEls_setInput1_fixedSize(pDataKey);
    mcuxClEls_setOutput_fixedSize(pOutput);

    mcuxClEls_startCommand(ID_CFG_ELS_CMD_DRBG_TEST, MCUXCLELS_RNG_DRBG_TEST_MODE_AES_ECB, ELS_CMD_LITTLE_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Rng_DrbgTestAesEcb_Async, MCUXCLELS_STATUS_OK_WAIT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Rng_DrbgTestAesCtr_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Rng_DrbgTestAesCtr_Async(
    uint8_t const * pData,
    size_t dataLength,
    uint8_t const * pIvKey,
    uint8_t * pOutput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Rng_DrbgTestAesCtr_Async);

    MCUXCLELS_INPUT_PARAM_CHECK_PROTECTED(mcuxClEls_Rng_DrbgTestAesCtr_Async, (0U != (dataLength % 16U)) || (0U == dataLength));

    /* ELS SFRs are not cached => Tell SW to wait for ELS to come back from BUSY state before modifying the SFRs */
    if (mcuxClEls_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Rng_DrbgTestAesCtr_Async, MCUXCLELS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClEls_setInput0(pData, dataLength);
    mcuxClEls_setInput1_fixedSize(pIvKey);
    mcuxClEls_setOutput_fixedSize(pOutput);

    mcuxClEls_startCommand(ID_CFG_ELS_CMD_DRBG_TEST, MCUXCLELS_RNG_DRBG_TEST_MODE_AES_CTR, ELS_CMD_LITTLE_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Rng_DrbgTestAesCtr_Async, MCUXCLELS_STATUS_OK_WAIT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Rng_Dtrng_ConfigLoad_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Rng_Dtrng_ConfigLoad_Async(
    uint8_t const * pInput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Rng_Dtrng_ConfigLoad_Async);

    /* ELS SFRs are not cached => Tell SW to wait for ELS to come back from BUSY state before modifying the SFRs */
    if (mcuxClEls_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Rng_Dtrng_ConfigLoad_Async, MCUXCLELS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClEls_setInput0_fixedSize(pInput);
    mcuxClEls_startCommand(ID_CFG_ELS_CMD_DTRNG_CFG_LOAD, 0U, ELS_CMD_LITTLE_ENDIAN);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Rng_Dtrng_ConfigLoad_Async, MCUXCLELS_STATUS_OK_WAIT);
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Rng_Dtrng_ConfigEvaluate_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Rng_Dtrng_ConfigEvaluate_Async(
    uint8_t const * pInput,
    uint8_t * pOutput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Rng_Dtrng_ConfigEvaluate_Async);

    /* ELS SFRs are not cached => Tell SW to wait for ELS to come back from BUSY state before modifying the SFRs */
    if (mcuxClEls_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Rng_Dtrng_ConfigEvaluate_Async, MCUXCLELS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClEls_setInput0_fixedSize(pInput);
    mcuxClEls_setOutput_fixedSize(pOutput);
    mcuxClEls_startCommand(ID_CFG_ELS_CMD_DTRNG_EVAL, 0U, ELS_CMD_LITTLE_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Rng_Dtrng_ConfigEvaluate_Async, MCUXCLELS_STATUS_OK_WAIT);
}

#ifdef MCUXCL_FEATURE_ELS_PRND_INIT
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Prng_Init_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Prng_Init_Async(
    void)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Prng_Init_Async);

    /* ELS SFRs are not cached => Tell SW to wait for ELS to come back from BUSY state before modifying the SFRs */
    if (mcuxClEls_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Prng_Init_Async, MCUXCLELS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClEls_startCommand(ID_CFG_ELS_CMD_RND_REQ, MCUXCLELS_RNG_RND_REQ_PRND_INIT, ELS_CMD_LITTLE_ENDIAN);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Prng_Init_Async, MCUXCLELS_STATUS_OK_WAIT);
}
#endif /* MCUXCL_FEATURE_ELS_PRND_INIT */

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Prng_GetRandomWord)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Prng_GetRandomWord(
    uint32_t * pWord)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Prng_GetRandomWord);

    *pWord = els_getPRNGWord();

    /* check if enough entropy is available */
    if (MCUXCLELS_IS_ERROR_BIT_SET(MCUXCLELS_SFR_ERR_STATUS_PRNG_ERR))
    {
        /* clear ELS error flags */
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEls_ResetErrorFlags());  /* always returns MCUXCLELS_STATUS_OK. */

        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Prng_GetRandomWord, MCUXCLELS_STATUS_HW_PRNG,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_ResetErrorFlags));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Prng_GetRandomWord, MCUXCLELS_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Prng_GetRandom)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Prng_GetRandom(
    uint8_t * pOutput,
    size_t outputLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Prng_GetRandom);

    uint8_t * bytePtr = pOutput;
    uint8_t * const pOutputEnd = pOutput + outputLength;

    /* Fetch one word of PRNG and fill the leading "not word aligned" bytes */
    if (0u != ((uint32_t) bytePtr & 0x03u))
    {
        uint32_t randomWord = els_getPRNGWord();
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
        mcuxClMemory_StoreLittleEndian32(bytePtr, els_getPRNGWord());
        bytePtr += 4;
    }

    /* Fetch one word of PRNG and fill the remaining "less than one word" bytes */
    if (pOutputEnd > bytePtr)
    {
        uint32_t randomWord = els_getPRNGWord();
        do
        {
            *bytePtr = (uint8_t) (randomWord & 0xFFu);
            bytePtr += 1u;
            randomWord >>= 8u;
        } while (pOutputEnd > bytePtr);
    }

    /* check if enough entropy is available */
    if (MCUXCLELS_IS_ERROR_BIT_SET(MCUXCLELS_SFR_ERR_STATUS_PRNG_ERR))
    {
        /* clear ELS error flags */
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEls_ResetErrorFlags());  /* always returns MCUXCLELS_STATUS_OK. */

        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Prng_GetRandom, MCUXCLELS_STATUS_HW_PRNG,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_ResetErrorFlags));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_Prng_GetRandom, MCUXCLELS_STATUS_OK);
}
