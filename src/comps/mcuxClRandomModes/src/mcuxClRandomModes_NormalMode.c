/*--------------------------------------------------------------------------*/
/* Copyright 2021-2023 NXP                                                  */
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
/* Security Classification:  Company Confidential                           */
/*--------------------------------------------------------------------------*/

#include <nxpClToolchain.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxClSession.h>

#include <mcuxClRandomModes_MemoryConsumption.h>
#include <mcuxClRandomModes_Functions_TestMode.h>

#include <internal/mcuxClRandom_Internal_Types.h>
#include <internal/mcuxClRandomModes_Private_Drbg.h>
#include <internal/mcuxClRandomModes_Private_CtrDrbg.h>
#include <internal/mcuxClRandomModes_Private_NormalMode.h>
#include <internal/mcuxClTrng_Internal.h>

/* MISRA Ex. 20 - Rule 5.1 */
const mcuxClRandom_OperationModeDescriptor_t mcuxClRandomModes_OperationModeDescriptor_NormalMode_PrDisabled = {
    .initFunction                    = mcuxClRandomModes_NormalMode_initFunction,
    .reseedFunction                  = mcuxClRandomModes_NormalMode_reseedFunction,
    .generateFunction                = mcuxClRandomModes_NormalMode_generateFunction_PrDisabled,
    .selftestFunction                = mcuxClRandomModes_NormalMode_selftestFunction_PrDisabled,
    .protectionTokenInitFunction     = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_NormalMode_initFunction,
    .protectionTokenReseedFunction   = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_NormalMode_reseedFunction,
    .protectionTokenGenerateFunction = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_NormalMode_generateFunction_PrDisabled,
    .protectionTokenSelftestFunction = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_NormalMode_selftestFunction_PrDisabled,
    .operationMode                   = MCUXCLRANDOMMODES_NORMALMODE,
};



/**
 * \brief This function instantiates a DRBG in NORMAL_MODE following the lines of the function Instantiate_function specified in NIST SP800-90A
 *
 * This function instantiates a DRBG in NORMAL_MODE following the lines of the function Instantiate_function specified in NIST SP800-90A.
 * The function obtains entropy input for the DRBG seed from the TRNG.
 *
 * \param  pSession[in]          Handle for the current CL session
 *
 * \return
 *   - MCUXCLRANDOM_STATUS_OK              if the DRBG instantiation finished successfully
 *   - MCUXCLRANDOM_STATUS_FAULT_ATTACK    if the DRBG instantiation failed due to other unexpected reasons
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_NormalMode_initFunction)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandomModes_NormalMode_initFunction(mcuxClSession_Handle_t pSession)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_NormalMode_initFunction);

    mcuxClRandom_Mode_t sessionMode = pSession->randomCfg.mode;
    mcuxClRandomModes_DrbgModeDescriptor_t *pDrbgMode = (mcuxClRandomModes_DrbgModeDescriptor_t *) sessionMode->pDrbgMode;
    mcuxClRandomModes_Context_Generic_t *pRngCtxGeneric = (mcuxClRandomModes_Context_Generic_t *) pSession->randomCfg.ctx;

    /* Initialize buffer in CPU workarea for the entropy input to derive the DRBG seed */
    uint32_t *pEntropyInput = (uint32_t *)&pSession->cpuWa.buffer[pSession->cpuWa.used];
    pSession->cpuWa.used += MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(pDrbgMode->pDrbgVariant->initSeedSize);

    /* Call TRNG initialization function to ensure it's properly configured for upcoming TRNG accesses */
    MCUX_CSSL_FP_FUNCTION_CALL(result_trngInit, mcuxClTrng_Init());
    if (MCUXCLTRNG_STATUS_OK != result_trngInit)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_NormalMode_initFunction, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Generate entropy input using the TRNG */
    MCUX_CSSL_FP_FUNCTION_CALL(result_trng,
      mcuxClTrng_getEntropyInput(pSession, pEntropyInput, MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(pDrbgMode->pDrbgVariant->initSeedSize)*sizeof(uint32_t))
      );
    if (MCUXCLTRNG_STATUS_OK != result_trng)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_NormalMode_initFunction, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Derive the initial DRBG state from the generated entropy input  */
    MCUX_CSSL_FP_FUNCTION_CALL(result_instantiate, pDrbgMode->pDrbgAlgorithms->instantiateAlgorithm(pSession, pEntropyInput));
    if (MCUXCLRANDOM_STATUS_OK != result_instantiate)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_NormalMode_initFunction, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Initialize the reseed counter. This is done here and not in the generateAlgorithm as specified in NIST SP800-90A,
     * because this makes it easier to handle PTG.3. Functionally there is no difference. */
    pRngCtxGeneric->reseedCounter = 0u;

    pSession->cpuWa.used -= MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(pDrbgMode->pDrbgVariant->initSeedSize);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_NormalMode_initFunction, MCUXCLRANDOM_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClTrng_Init),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClTrng_getEntropyInput),
        pDrbgMode->pDrbgAlgorithms->protectionTokenInstantiateAlgorithm);
}


/**
 * \brief This function reseeds a DRBG in NORMAL_MODE following the lines of the function Reseed_function specified in NIST SP800-90A
 *
 * This function reseed a DRBG in NORMAL_MODE following the lines of the function Reseed_function specified in NIST SP800-90A.
 * The function obtains entropy input for the DRBG seed from the TRNG.
 *
 * \param  pSession[in]          Handle for the current CL session
 *
 * \return
 *   - MCUXCLRANDOM_STATUS_OK              if the DRBG reseeding finished successfully
 *   - MCUXCLRANDOM_STATUS_FAULT_ATTACK    if the DRBG reseeding failed due to other unexpected reasons
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_NormalMode_reseedFunction)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandomModes_NormalMode_reseedFunction(mcuxClSession_Handle_t pSession)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_NormalMode_reseedFunction);

    mcuxClRandom_Mode_t sessionMode = pSession->randomCfg.mode;
    mcuxClRandomModes_DrbgModeDescriptor_t *pDrbgMode = (mcuxClRandomModes_DrbgModeDescriptor_t *) sessionMode->pDrbgMode;
    mcuxClRandomModes_Context_Generic_t *pRngCtxGeneric = (mcuxClRandomModes_Context_Generic_t *) pSession->randomCfg.ctx;

    /* Initialize buffer in CPU workarea for the entropy input to derive the DRBG seed */
    uint32_t *pEntropyInput = (uint32_t *)&pSession->cpuWa.buffer[pSession->cpuWa.used];
    pSession->cpuWa.used += MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(pDrbgMode->pDrbgVariant->reseedSeedSize);

    /* Generate entropy input using the TRNG */
    MCUX_CSSL_FP_FUNCTION_CALL(result_trng,
        mcuxClTrng_getEntropyInput(pSession, pEntropyInput, MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(pDrbgMode->pDrbgVariant->reseedSeedSize)*sizeof(uint32_t))
        );
    if (MCUXCLTRNG_STATUS_OK != result_trng)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_NormalMode_reseedFunction, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Derive the initial DRBG state from the generated entropy input  */
    MCUX_CSSL_FP_FUNCTION_CALL(result_reseed, pDrbgMode->pDrbgAlgorithms->reseedAlgorithm(pSession, pEntropyInput));
    if (MCUXCLRANDOM_STATUS_OK != result_reseed)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_NormalMode_reseedFunction, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Reset the reseed counter. This is done here and not in the generateAlgorithm as specified in NIST SP800-90A,
     * because this makes it easier to handle PTG.3. Functionally there is no difference. */
    pRngCtxGeneric->reseedCounter = 0u;

    pSession->cpuWa.used -= MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(pDrbgMode->pDrbgVariant->reseedSeedSize);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_NormalMode_reseedFunction, MCUXCLRANDOM_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClTrng_getEntropyInput),
        pDrbgMode->pDrbgAlgorithms->protectionTokenReseedAlgorithm);
}


/**
 * \brief This function generates random numbers from a DRBG in NORMAL_MODE following the lines of the function Generate_function specified in NIST SP800-90A
 * and reseeds according to the DRG.3 security level.
 *
 * This function generates random numbers from a DRBG in NORMAL_MODE following the lines of the function Generate_function specified in NIST SP800-90A.
 * If reseedCounter overflowed, the DRBG will be reseeded before the randomness generation.
 * If so, the function obtains entropy input for the DRBG seed from the TRNG.
 *
 * \param  pSession[in]         Handle for the current CL session
 * \param  pOut[out]            Output buffer to which the generated randomness will be written
 * \param  outLength            Number of requested random bytes
 *
 * \return
 *   - MCUXCLRANDOM_STATUS_OK              if the random number generation finished successfully
 *   - MCUXCLRANDOM_STATUS_FAULT_ATTACK    if the random number generation failed due to other unexpected reasons
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_NormalMode_generateFunction_PrDisabled)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandomModes_NormalMode_generateFunction_PrDisabled(mcuxClSession_Handle_t pSession, uint8_t *pOut, uint32_t outLength)
{
    mcuxClRandom_Mode_t pMode = (mcuxClRandom_Mode_t) pSession->randomCfg.mode;
    mcuxClRandomModes_Context_Generic_t *pRngCtxGeneric = (mcuxClRandomModes_Context_Generic_t *) pSession->randomCfg.ctx;
    mcuxClRandomModes_DrbgModeDescriptor_t *pDrbgMode = (mcuxClRandomModes_DrbgModeDescriptor_t *) pMode->pDrbgMode;

    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_NormalMode_generateFunction_PrDisabled,
          MCUX_CSSL_FP_CONDITIONAL((pRngCtxGeneric->reseedCounter >= pDrbgMode->pDrbgVariant->reseedInterval),
                 pMode->pOperationMode->protectionTokenReseedFunction));



    /* Reseed the DRBG state if the reseed counter overflowed */
    if (pRngCtxGeneric->reseedCounter >= pDrbgMode->pDrbgVariant->reseedInterval)

    {
        MCUX_CSSL_FP_FUNCTION_CALL(result_reseed, pMode->pOperationMode->reseedFunction(pSession));
        if (MCUXCLRANDOM_STATUS_OK != result_reseed)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_NormalMode_generateFunction_PrDisabled, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
        }
    }

    /* Generate random bytes */
    MCUX_CSSL_FP_FUNCTION_CALL(result_generate, pDrbgMode->pDrbgAlgorithms->generateAlgorithm(pSession, pOut, outLength));
    if (MCUXCLRANDOM_STATUS_OK != result_generate)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_NormalMode_generateFunction_PrDisabled, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Increment the reseed counter. This is done here and not in the generateAlgorithm as specified in NIST SP800-90A,
     * because this makes it easier to handle PTG.3. Functionally there is no difference. */
    pRngCtxGeneric->reseedCounter += 1u;

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_NormalMode_generateFunction_PrDisabled, MCUXCLRANDOM_STATUS_OK,
        pDrbgMode->pDrbgAlgorithms->protectionTokenGenerateAlgorithm);
}



/**
 * \brief This function performs a selftest of a DRBG in NORMAL_MODE with DRG.3 security level
 *
 * This function performs a selftest of a DRBG in NORMAL_MODE. More precisely, it implements a CAVP like known answer test as specified in
 *
 *   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/DRBGVS.pdf
 *
 * ...
 *
 * @param  pSession[in]    Handle for the current CL session
 * @param  mode[in]        Mode of operation for random data generator.
 *
 * \return
 *   - MCUXCLRANDOM_STATUS_OK              if the selftest executed finished successfully
 *   - MCUXCLRANDOM_STATUS_FAULT_ATTACK    if the selftest failed
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_NormalMode_selftestFunction_PrDisabled)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandomModes_NormalMode_selftestFunction_PrDisabled(mcuxClSession_Handle_t pSession UNUSED_PARAM, mcuxClRandom_Mode_t mode UNUSED_PARAM)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_NormalMode_selftestFunction_PrDisabled);
    //TODO: This is outdated
#if 0
    /* Back up Random configuration of current session */
    mcuxClRandom_ModeDescriptor_t *modeBackup = (mcuxClRandom_ModeDescriptor_t *)pSession->randomCfg.mode;
    mcuxClRandom_Context_t ctxBackup = pSession->randomCfg.ctx;

    /* Allocate space for new testMode and testCtx in CPU workarea */
    mcuxClRandom_ModeDescriptor_t testMode;
    uint8_t ctxBuffer[MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE];
    mcuxClRandom_Context_t testCtx = (mcuxClRandom_Context_t)ctxBuffer;

    /* Derive testMode from passed mode */
    MCUX_CSSL_FP_FUNCTION_CALL(result_create, mcuxClRandomModes_createTestFromNormalMode(&testMode, mode, NULL));
    if (MCUXCLRANDOM_STATUS_OK != result_create)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_NormalMode_selftestFunction_PrDisabled, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Call function executing the selftest depending on whether prediction resistance is enabled or disabled */
    mcuxClRandomModes_DrbgModeDescriptor_t *pDrbgMode = (mcuxClRandomModes_DrbgModeDescriptor_t *) testMode.pDrbgMode;
    MCUX_CSSL_FP_FUNCTION_CALL(result_selftest, pDrbgMode->pDrbgPrMode->selftestPrHandler(pSession, testCtx, &testMode));
    if(MCUXCLRANDOM_STATUS_OK != result_selftest)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_NormalMode_selftestFunction_PrDisabled, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Restore Random configuration of session */
    pSession->randomCfg.mode = modeBackup;
    pSession->randomCfg.ctx = ctxBackup;

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_NormalMode_selftestFunction_PrDisabled, MCUXCLRANDOM_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_createTestFromNormalMode),
        pDrbgMode->pDrbgPrMode->protectionTokenSelftestPrHandler);
#endif
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_NormalMode_selftestFunction_PrDisabled, MCUXCLRANDOM_STATUS_OK);
}



/**
 * \brief TODO
 */
mcuxClRandom_Status_t mcuxClRandomModes_selftest_VerifyArrays(uint32_t length, uint32_t *expected, uint32_t *actual)
{
    // TODO: Code below to be adapted to CLNS framework. This includes adding flow protection
    for(uint32_t i = 0u; i < length; i++)
    {
        if(expected[i] != actual[i])
        {
            return MCUXCLRANDOM_STATUS_FAULT_ATTACK;
        }
    }
    return MCUXCLRANDOM_STATUS_OK;
}

/**
 * \brief TODO
 */
mcuxClRandom_Status_t mcuxClRandomModes_selftest_CheckContext(mcuxClRandomModes_Context_Generic_t *pCtx UNUSED_PARAM, uint32_t *pExpectedKey UNUSED_PARAM, uint32_t *pExpectedCounterV UNUSED_PARAM)
{
    // TODO
    return MCUXCLRANDOM_STATUS_OK;
}
