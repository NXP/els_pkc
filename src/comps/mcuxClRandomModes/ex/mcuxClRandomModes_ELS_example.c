/*--------------------------------------------------------------------------*/
/* Copyright 2021-2024 NXP                                                  */
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
 * @file  mcuxClRandomModes_ELS_example.c
 * @brief Example for the mcuxClRandomModes component
 *
 * @example mcuxClRandomModes_ELS_example.c
 * @brief   Example for the mcuxClRandomModes component
 */

#include <mcuxClToolchain.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClCore_Examples.h> // Defines and assertions for examples
#include <mcuxClEls.h> // Interface to the entire mcuxClEls component
#include <mcuxClExample_ELS_Helper.h>

/** Performs an example usage of the mcuxClRandom and mcuxClRandomModes components with ELS mode.
 * @retval true  The example code completed successfully
 * @retval false The example code failed */
MCUXCLEXAMPLE_FUNCTION(mcuxClRandomModes_ELS_example)
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
    ALIGNED uint8_t prng_buffer[10u];

    ALIGNED uint8_t drbg_buffer1[3u];
    ALIGNED uint8_t drbg_buffer2[4u];
    ALIGNED uint8_t drbg_buffer3[5u];

    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;
    //Allocate and initialize session
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLRANDOMMODES_NCINIT_WACPU_SIZE, MCUXCLRANDOMMODES_NCGENERATE_WACPU_SIZE), 0u);

    /* We don't need a context for ELS Rng. */
    mcuxClRandom_Context_t context = NULL;

    /**************************************************************************/
    /* Random init                                                            */
    /**************************************************************************/

    /* Initialize the Random session with ELS mode. */

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomInitresult, token, mcuxClRandom_init(
        session,
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEREFERENCE_NULL_POINTER("NULL argument (context) is not dereferenced with mode mcuxClRandomModes_Mode_ELS_Drbg")
        context,
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEREFERENCE_NULL_POINTER()
        mcuxClRandomModes_Mode_ELS_Drbg));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init) != token) || (MCUXCLRANDOM_STATUS_OK != randomInitresult))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Generate random values.                                                */
    /**************************************************************************/

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
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ESCAPING_LOCAL_ADDRESS("Address of drbg_buffer1 is for internal use only and does not escape")
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

    /* Generate random values of larger amount than but not multiple of one word size. */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ESCAPING_LOCAL_ADDRESS("Address of drbg_buffer1 is for internal use only and does not escape")
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
    /* Generate non-cryptographic random values.                              */
    /**************************************************************************/

    /* Initialize non-cryptographic Rng. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomNcInitresult, token, mcuxClRandom_ncInit(session));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != token) || (MCUXCLRANDOM_STATUS_OK != randomNcInitresult))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Generate random values. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomNcGenerateresult, token, mcuxClRandom_ncGenerate(
                                                  session,
                                                  prng_buffer,
                                                  sizeof(prng_buffer)));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncGenerate) != token) || (MCUXCLRANDOM_STATUS_OK != randomNcGenerateresult))
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
