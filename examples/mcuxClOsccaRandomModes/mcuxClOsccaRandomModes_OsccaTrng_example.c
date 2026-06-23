/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
/*                                                                          */
/* SPDX-License-Identifier: BSD-3-Clause                                    */
/*                                                                          */
/* Redistribution and use in source and binary forms, with or without       */
/* modification, are permitted provided that the following conditions are   */
/* met:                                                                     */
/*                                                                          */
/* 1. Redistributions of source code must retain the above copyright        */
/*    notice, this list of conditions and the following disclaimer.         */
/*                                                                          */
/* 2. Redistributions in binary form must reproduce the above copyright     */
/*    notice, this list of conditions and the following disclaimer in the   */
/*    documentation and/or other materials provided with the distribution.  */
/*                                                                          */
/* 3. Neither the name of the copyright holder nor the names of its         */
/*    contributors may be used to endorse or promote products derived from  */
/*    this software without specific prior written permission.              */
/*                                                                          */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS  */
/* IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED    */
/* TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A          */
/* PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT       */
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,   */
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED */
/* TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR   */
/* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF   */
/* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS       */
/* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.             */
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
#include <mcuxClRandomModes.h>
#include <mcuxClOsccaRandomModes.h>
#include <mcuxClSession.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClOscca_FunctionIdentifiers.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_ELS_Helper.h>

/** Performs an example usage of the mcuxClOsccaRandomModes component with OSCCA mode.
 * @retval true  The example code completed successfully
 * @retval false The example code failed */
MCUXCLEXAMPLE_FUNCTION(mcuxClOsccaRandomModes_OsccaTrng_example)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /** Initialize ELS, Enable the ELS **/
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
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(&session, MCUXCLEXAMPLE_MAX_WA(MCUXCLOSCCARANDOMMODES_OSCCARNG_SELFTEST_CPU_SIZE, MCUXCLRANDOMMODES_NCINIT_WACPU_SIZE), 0u);

    /* Initialize the PRNG */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(prngInitRet, prngInitToken, mcuxClRandom_ncInit(&session));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != prngInitToken) || (MCUXCLRANDOM_STATUS_OK != prngInitRet))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
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
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Random init                                                            */
    /**************************************************************************/
    /* We need a context for OSCCA Rng. */
    uint32_t ctx[MCUXCLOSCCARANDOMMODES_OSCCARNG_CONTEXT_SIZE_IN_WORDS];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClRandom_Context_t pCtx = (mcuxClRandom_Context_t)ctx;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

    /* Initialize the Random session with OSCCA TRNG mode. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomInitRet, InitToken, mcuxClRandom_init(
        &session,
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("pCtx has the correct type (mcuxClRandom_Context_t), the cast was valid.")
        pCtx,
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()
                                                  mcuxClOsccaRandomModes_Mode_TRNG));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init) != InitToken) || (MCUXCLRANDOM_STATUS_OK != randomInitRet))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Generate random values.                                                */
    /**************************************************************************/

    /* Generate random values of smaller amount than one word size. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ESCAPING_LOCAL_ADDRESS("Address of rng_buffer1 is for internal use only and does not escape")
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomGenRet, randomGenToken, mcuxClRandom_generate(
                                                  &session,
                                                  rng_buffer1,
                                                  3u));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate) != randomGenToken) || (MCUXCLRANDOM_STATUS_OK != randomGenRet))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ESCAPING_LOCAL_ADDRESS()

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Generate random values of multiple of word size. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ESCAPING_LOCAL_ADDRESS("Address of rng_buffer2 is for internal use only and does not escape")
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomGenRet2, randomGenToken2, mcuxClRandom_generate(
                                                  &session,
                                                  rng_buffer2,
                                                  4u));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate) != randomGenToken2) || (MCUXCLRANDOM_STATUS_OK != randomGenRet2))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ESCAPING_LOCAL_ADDRESS()

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Generate random values of larger amount than but not multiple of one word size. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ESCAPING_LOCAL_ADDRESS("Address of rng_buffer3 is for internal use only and does not escape")
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomGenRet3, randomGenToken3, mcuxClRandom_generate(
                                                  &session,
                                                  rng_buffer3,
                                                  5u));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate) != randomGenToken3) || (MCUXCLRANDOM_STATUS_OK != randomGenRet3))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ESCAPING_LOCAL_ADDRESS()

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Generate random values of larger amount than but not multiple of one word size. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ESCAPING_LOCAL_ADDRESS("Address of rng_buffer is for internal use only and does not escape")
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomGenRet4, randomGenToken4, mcuxClRandom_generate(
                                                  &session,
                                                  rng_buffer,
                                                  41u));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate) != randomGenToken4) || (MCUXCLRANDOM_STATUS_OK != randomGenRet4))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ESCAPING_LOCAL_ADDRESS()

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Random uninit. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomUninitresult, token6, mcuxClRandom_uninit(&session));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_uninit) != token6) || (MCUXCLRANDOM_STATUS_OK != randomUninitresult))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Cleanup                                                                */
    /**************************************************************************/
    /** Destroy Session and cleanup Session **/
    if(!mcuxClExample_Session_Clean(&session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /** Disable the ELS **/
    if(!mcuxClExample_Els_Disable())
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}
