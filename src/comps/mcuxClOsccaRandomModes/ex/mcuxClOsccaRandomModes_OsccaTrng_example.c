/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023 NXP                                                  */
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
 * @file  mcuxClOsccaRandomModes_OsccaTrng_example.c
 * @brief Example for the mcuxClOsccaRandomModes component
 *
 * @example mcuxClOsccaRandomModes_OsccaTrng_example.c
 * @brief   Example for the mcuxClOsccaRandomModes component
 */

#include <stdbool.h>  // bool type for the example's return code
#include <stddef.h>
#include <mcuxClRandom.h>
#include <mcuxClOsccaRandomModes.h>
#include <mcuxClSession.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_ELS_Helper.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClOscca_FunctionIdentifiers.h>
#include <mcuxClCore_Examples.h>

/** Performs an example usage of the mcuxClOsccaRandomModes component with OSCCA mode.
 * @retval true  The example code completed successfully
 * @retval false The example code failed */
bool mcuxClOsccaRandomModes_OsccaTrng_example(void)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /* Initialize ELS, Enable the ELS */
    if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Buffers to store the generated random values in. */
    uint8_t rng_buffer[41u];
    uint8_t rng_buffer1[3u];
    uint8_t rng_buffer2[4u];
    uint8_t rng_buffer3[5u];

    mcuxClSession_Descriptor_t session;
    //Allocate and initialize session
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(&session, MCUXCLOSCCARANDOMMODES_OSCCARNG_SELFTEST_CPU_SIZE, 0u);

    /* Initialize the PRNG */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(prngInitRet, prngInitToken, mcuxClRandom_ncInit(&session));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != prngInitToken) || (MCUXCLRANDOM_STATUS_OK != prngInitRet))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* selftest                                                               */
    /**************************************************************************/
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomSelfRet, randomSelfToken, mcuxClRandom_selftest(
                                                   &session,
                                                   mcuxClOsccaRandomModes_Mode_TRNG));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_selftest) != randomSelfToken) || (MCUXCLRANDOM_STATUS_OK != randomSelfRet))
    {
        return false;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Random init                                                            */
    /**************************************************************************/
    /* We need a context for OSCCA Rng. */
    uint32_t ctx[MCUXCLOSCCARANDOMMODES_OSCCARNG_CONTEXT_SIZE_IN_WORDS];
    mcuxClRandom_Context_t pCtx = (mcuxClRandom_Context_t)ctx;
    /* Initialize the Random session with OSCCA TRNG mode. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomInitRet, InitToken, mcuxClRandom_init(
                                                  &session,
                                                  pCtx,
                                                  mcuxClOsccaRandomModes_Mode_TRNG));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init) != InitToken) || (MCUXCLRANDOM_STATUS_OK != randomInitRet))
    {
        return false;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Generate random values.                                                */
    /**************************************************************************/

    /* Generate random values of smaller amount than one word size. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomGenRet, randomGenToken, mcuxClRandom_generate(
                                                  &session,
                                                  rng_buffer1,
                                                  3u));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate) != randomGenToken) || (MCUXCLRANDOM_STATUS_OK != randomGenRet))
    {
        return false;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Generate random values of multiple of word size. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomGenRet2, randomGenToken2, mcuxClRandom_generate(
                                                  &session,
                                                  rng_buffer2,
                                                  4u));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate) != randomGenToken2) || (MCUXCLRANDOM_STATUS_OK != randomGenRet2))
    {
        return false;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Generate random values of larger amount than but not multiple of one word size. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomGenRet3, randomGenToken3, mcuxClRandom_generate(
                                                  &session,
                                                  rng_buffer3,
                                                  5u));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate) != randomGenToken3) || (MCUXCLRANDOM_STATUS_OK != randomGenRet3))
    {
        return false;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Generate random values of larger amount than but not multiple of one word size. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomGenRet4, randomGenToken4, mcuxClRandom_generate(
                                                  &session,
                                                  rng_buffer,
                                                  41u));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate) != randomGenToken4) || (MCUXCLRANDOM_STATUS_OK != randomGenRet4))
    {
        return false;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Random uninit. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomUninitresult, token6, mcuxClRandom_uninit(&session));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_uninit) != token6) || (MCUXCLRANDOM_STATUS_OK != randomUninitresult))
    {
        return false;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Cleanup                                                                */
    /**************************************************************************/
    /** Destroy Session and cleanup Session **/
    if(!mcuxClExample_Session_Clean(&session))
    {
        return false;
    }

    /* Disable the ELS */
    if(!mcuxClExample_Els_Disable())
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return true;
}
