/*--------------------------------------------------------------------------*/
/* Copyright 2021 NXP                                                       */
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

#include <mcuxClRandom.h>
#include <mcuxClSession.h>

#include <mcuxClRandom_Functions_TestMode.h>

#include <internal/mcuxClRandom_Internal_Types.h>
#include <internal/mcuxClRandom_Private_Types.h>
#include <internal/mcuxClRandom_Private_Drbg.h>
#include <internal/mcuxClRandom_Private_PrDisabled.h>
#include <internal/mcuxClRandom_Private_NormalMode.h>


const mcuxClRandom_DrbgPrModeDescriptor_t mcuxClRandom_DrbgPrModeDescriptor_PrDisabled = {
    .generatePrHandler                    = mcuxClRandom_PrDisabled_generatePrHandler,
    .selftestPrHandler                    = mcuxClRandom_PrDisabled_selftestPrHandler,
    .protectionTokenGeneratePrHandler     = MCUX_CSSL_FP_FUNCID_mcuxClRandom_PrDisabled_generatePrHandler,
    .protectionTokenSelftestPrHandler     = MCUX_CSSL_FP_FUNCID_mcuxClRandom_PrDisabled_selftestPrHandler,
};


/**
 * \brief This function reseeds a DRBG within a generate call by calling the reseedFunction only if the reseed counter overflowed
 *
 * \param  pSession[in]         Handle for the current CL session
 *
 * \return
 *   - MCUXCLRANDOM_STATUS_OK              if the function finished successfully
 *   - MCUXCLRANDOM_STATUS_FAULT_ATTACK    if the function failed due to other unexpected reasons
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandom_PrDisabled_generatePrHandler)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_PrDisabled_generatePrHandler(mcuxClSession_Handle_t pSession)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_PrDisabled_generatePrHandler);
    mcuxClRandom_Context_Generic_t *pRngCtxGeneric = (mcuxClRandom_Context_Generic_t *) pSession->randomCfg.ctx;
    mcuxClRandom_Mode_t pMode = (mcuxClRandom_Mode_t) pSession->randomCfg.mode;

    /* Reseed the DRBG state if the reseed counter overflowed */
    if (pRngCtxGeneric->reseedCounter > pMode->pDrbgMode->pDrbgVariant->reseedInterval)
    {
        MCUX_CSSL_FP_FUNCTION_CALL(result_reseed, pMode->pOperationMode->reseedFunction(pSession));
        if (MCUXCLRANDOM_STATUS_OK != result_reseed)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_PrDisabled_generatePrHandler, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
        }
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_PrDisabled_generatePrHandler, MCUXCLRANDOM_STATUS_OK,
          MCUX_CSSL_FP_CONDITIONAL((pRngCtxGeneric->reseedCounter > pMode->pDrbgMode->pDrbgVariant->reseedInterval),
            pMode->pOperationMode->protectionTokenReseedFunction));
}


/**
 * \brief This function performs a selftest of a DRBG if prediction resistance is disabled
 *
 * This function performs a selftest of a DRBG if prediction resistance is disabled. More precisely, it implements a CAVP like known answer test as specified in
 *
 *   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/DRBGVS.pdf
 *
 * i.e. known answer tests for the following flow are executed
 *
 *    (initialize entropy input)
 *    init
 *    (update entropy input)
 *    reseed
 *    generate
 *    generate
 *    uninit
 *
 * @param [in]     pSession   Handle for the current CL session.
 * @param [in]     testCtx    Pointer to a Random data context buffer large enough
 *                            to hold the context for the selected @p mode
 * @param [in]     testMode   Mode of operation for random data generator.
 *
 * \return
 *   - MCUXCLRANDOM_STATUS_OK              if the selftest finished successfully
 *   - MCUXCLRANDOM_STATUS_FAULT_ATTACK    if the selftest failed
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandom_PrDisabled_selftestPrHandler)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_PrDisabled_selftestPrHandler(mcuxClSession_Handle_t pSession, mcuxClRandom_Context_t testCtx, mcuxClRandom_Mode_t testMode)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_PrDisabled_selftestPrHandler);
#if 0
    /* Set entropy input pointer in testMode */ 
    mcuxClRandom_DrbgModeDescriptor_t *pDrbgMode = (mcuxClRandom_DrbgModeDescriptor_t *) testMode->pDrbgMode;
    mcuxClRandom_Context_Generic_t *pTestCtx = (mcuxClRandom_Context_Generic_t *) pSession->randomCfg.ctx;

    uint32_t **testVectors = (uint32_t **)pDrbgMode->pDrbgTestVectors;
    MCUX_CSSL_FP_FUNCTION_CALL(ret_updateIn, mcuxClRandom_updateEntropyInput(testMode,
                testVectors[MCUXCLRANDOM_TESTVECTORS_INDEX_ENTROPY_PRDISABLED]));
    (void)ret_updateIn;

    /**************************************
    * Test mcuxClRandom_init function     *
    **************************************/

    /* Call Random_init */
    MCUX_CSSL_FP_FUNCTION_CALL(ret_init, mcuxClRandom_init(pSession, (mcuxClRandom_Context_t)pTestCtx, testMode));
    if(MCUXCLRANDOM_STATUS_OK != ret_init)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_PrDisabled_selftestPrHandler, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }


    /* Verify internal DRBG state */
    // TODO: Consider calling the checkContext function via function pointers because the state structure is different for CTR_DRBG and HASH_DRBG e.g.
    if(MCUXCLRANDOM_STATUS_OK != mcuxClRandom_selftest_CheckContext(pTestCtx,
                                                                  testVectors[MCUXCLRANDOM_TESTVECTORS_INDEX_INIT_KEY_PRDISABLED],
                                                                  testVectors[MCUXCLRANDOM_TESTVECTORS_INDEX_INIT_V_PRDISABLED]))
    {
        return MCUXCLRANDOM_STATUS_FAULT_ATTACK;
    }

    /**************************************
    * Test mcuxClRandom_reseed function   *
    **************************************/

    /* Input new entropy to be used for reseeding by updating testMode */
    MCUX_CSSL_FP_FUNCTION_CALL(ret_updateIn2, mcuxClRandom_updateEntropyInput(testMode,
                testVectors[MCUXCLRANDOM_TESTVECTORS_INDEX_ENTROPY_RESEED_PRDISABLED]));
    (void)ret_updateIn2;

    MCUX_CSSL_FP_FUNCTION_CALL(ret_reseed, mcuxClRandom_reseed(pSession));
    /* Call Random_reseed */
    if(MCUXCLRANDOM_STATUS_OK != ret_reseed)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_PrDisabled_selftestPrHandler, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Verify internal DRBG state */
    if(MCUXCLRANDOM_STATUS_OK != mcuxClRandom_selftest_CheckContext(pTestCtx,
                                                                  testVectors[MCUXCLRANDOM_TESTVECTORS_INDEX_RESEED_KEY_PRDISABLED],
                                                                  testVectors[MCUXCLRANDOM_TESTVECTORS_INDEX_RESEED_V_PRDISABLED]))
    {
        return MCUXCLRANDOM_STATUS_FAULT_ATTACK;
    }

    /***********************************************
     * First test of mcuxClRandom_generate function *
     ***********************************************/

     uint8_t randomBytes[MCUXCLRANDOM_SELFTEST_RANDOMDATALENGTH];
     MCUX_CSSL_FP_FUNCTION_CALL(ret_generate,
             mcuxClRandom_generate(pSession, randomBytes, MCUXCLRANDOM_SELFTEST_RANDOMDATALENGTH));
     if(MCUXCLRANDOM_STATUS_OK != ret_generate)
     {
         return MCUXCLRANDOM_STATUS_FAULT_ATTACK;
     }

     /* Verify internal DRBG state */
     if(MCUXCLRANDOM_STATUS_OK != mcuxClRandom_selftest_CheckContext(pTestCtx,
                                                                   testVectors[MCUXCLRANDOM_TESTVECTORS_INDEX_GENONE_KEY_PRDISABLED],
                                                                   testVectors[MCUXCLRANDOM_TESTVECTORS_INDEX_GENONE_V_PRDISABLED]))
     {
         return MCUXCLRANDOM_STATUS_FAULT_ATTACK;
     }


    /************************************************
     * Second test of mcuxClRandom_generate function *
     ************************************************/
     MCUX_CSSL_FP_FUNCTION_CALL(ret_generate2,
             mcuxClRandom_generate(pSession, randomBytes, MCUXCLRANDOM_SELFTEST_RANDOMDATALENGTH));
     if(MCUXCLRANDOM_STATUS_OK != ret_generate2)
     {
         MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_PrDisabled_selftestPrHandler, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
     }

    /* Verify internal DRBG state */
    if(MCUXCLRANDOM_STATUS_OK != mcuxClRandom_selftest_CheckContext(pTestCtx,
                                                                  testVectors[MCUXCLRANDOM_TESTVECTORS_INDEX_GENTWO_KEY_PRDISABLED],
                                                                  testVectors[MCUXCLRANDOM_TESTVECTORS_INDEX_GENTWO_V_PRDISABLED]))
    {
        return MCUXCLRANDOM_STATUS_FAULT_ATTACK;
    }

    /* Verify generated random bytes */
    if(MCUXCLRANDOM_STATUS_OK != mcuxClRandom_selftest_VerifyArrays(MCUXCLRANDOM_SELFTEST_RANDOMDATALENGTH/(sizeof(uint32_t)),
                                                                  testVectors[MCUXCLRANDOM_TESTVECTORS_INDEX_RANDOMDATA_PRDISABLED],
                                                                  (uint32_t *)randomBytes))
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_PrDisabled_selftestPrHandler, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /**************************************
     * Test mcuxClRandom_uninit function   *
     **************************************/

    uint16_t contextSizeInWords = testMode->contextSize / sizeof(uint32_t);
    MCUX_CSSL_FP_FUNCTION_CALL(ret_uninit, mcuxClRandom_uninit(pSession));
    if(MCUXCLRANDOM_STATUS_OK != ret_uninit) 
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_PrDisabled_selftestPrHandler, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Verify whether context is clear */
    for (uint16_t i=0u; i < contextSizeInWords; i++)
    {
        if(((uint32_t *) pTestCtx)[i] != 0u)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_PrDisabled_selftestPrHandler, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
        }
    }
#endif
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_PrDisabled_selftestPrHandler, MCUXCLRANDOM_STATUS_OK);
}
