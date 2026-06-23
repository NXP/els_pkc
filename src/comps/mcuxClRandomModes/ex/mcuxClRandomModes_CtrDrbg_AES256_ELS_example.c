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
 * @file  mcuxClRandomModes_CtrDrbg_AES256_ELS_example.c
 * @brief Example for the mcuxClRandomModes component
 *
 * @example mcuxClRandomModes_CtrDrbg_AES256_ELS_example.c
 * @brief   Example for the mcuxClRandomModes component
 */

#include <mcuxClToolchain.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h> // Code flow protection
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClCore_Examples.h> // Defines and assertions for examples
#include <mcuxClEls.h> // Interface to the entire mcuxClEls component
#include <mcuxClExample_ELS_Helper.h>


/** Performs an example usage of the mcuxClRandom and mcuxClRandomModes components with ELS mode.
 * @retval true  The example code completed successfully
 * @retval false The example code failed */
MCUXCLEXAMPLE_FUNCTION(mcuxClRandomModes_CtrDrbg_AES256_ELS_example)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /** Initialize ELS, Enable the ELS **/
    if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    //Allocate and initialize session
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLRANDOMMODES_MAX_CPU_WA_BUFFER_SIZE, 0u);

    /* selftest */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(selftestresult, token, mcuxClRandom_selftest(
                                                  session,
                                                  mcuxClRandomModes_Mode_CtrDrbg_AES256));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_selftest) != token) || (MCUXCLRANDOM_STATUS_OK != selftestresult))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    uint32_t context[MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE_IN_WORDS] = {0};
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClRandom_Context_t pRng_ctx = (mcuxClRandom_Context_t)context;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    /**************************************************************************/
    /* Random init                                                            */
    /**************************************************************************/

    /* Initialize the Random session with aes256 mode. */

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomInitresult, token, mcuxClRandom_init(
        session,
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("pRng_ctx has the correct type (mcuxClRandom_Context_t), the cast was valid.")
        pRng_ctx,
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()
        mcuxClRandomModes_Mode_CtrDrbg_AES256));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init) != token) || (MCUXCLRANDOM_STATUS_OK != randomInitresult))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Generate random values.                                                */
    /**************************************************************************/

    /* Buffers to store the generated random values in. */
    ALIGNED uint8_t drbg_buffer1[3u];
    ALIGNED uint8_t drbg_buffer2[4u];
    ALIGNED uint8_t drbg_buffer3[5u];


    /* Generate random values of smaller amount than one word size. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ESCAPING_LOCAL_ADDRESS("Address of drbg_buffer1 is for internal use only and does not escape")
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomGenerateresult1, token, mcuxClRandom_generate(
                                                  session,
                                                  drbg_buffer1,
                                                  sizeof(drbg_buffer1)));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ESCAPING_LOCAL_ADDRESS()

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate) != token) || (MCUXCLRANDOM_STATUS_OK != randomGenerateresult1))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Generate random values of multiple of word size. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ESCAPING_LOCAL_ADDRESS("Address of drbg_buffer2 is for internal use only and does not escape")
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomGenerateresult2, token, mcuxClRandom_generate(
                                                  session,
                                                  drbg_buffer2,
                                                  sizeof(drbg_buffer2)));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ESCAPING_LOCAL_ADDRESS()

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate) != token) || (MCUXCLRANDOM_STATUS_OK != randomGenerateresult2))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* reseed */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomReseedresult, token, mcuxClRandom_reseed(
                                                  session));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_reseed) != token) || (MCUXCLRANDOM_STATUS_OK != randomReseedresult))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Generate random values of larger amount than but not multiple of one word size. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ESCAPING_LOCAL_ADDRESS("Address of drbg_buffer3 is for internal use only and does not escape")
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomGenerateresult3, token, mcuxClRandom_generate(
                                                  session,
                                                  drbg_buffer3,
                                                  sizeof(drbg_buffer3)));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ESCAPING_LOCAL_ADDRESS()

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate) != token) || (MCUXCLRANDOM_STATUS_OK != randomGenerateresult3))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /**************************************************************************/
    /* Cleanup                                                                */
    /**************************************************************************/

    /* Random uninit. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomUninitresult, token, mcuxClRandom_uninit(session));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_uninit) != token) || (MCUXCLRANDOM_STATUS_OK != randomUninitresult))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /** Destroy Session and cleanup Session **/
    if(!mcuxClExample_Session_Clean(session))
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
