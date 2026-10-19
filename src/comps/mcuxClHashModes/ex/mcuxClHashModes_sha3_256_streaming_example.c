/*--------------------------------------------------------------------------*/
/* Copyright 2023-2026 NXP                                                  */
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
 * @example mcuxClHashModes_sha3_256_streaming_example.c
 * @brief mcuxClHashModes example application
 */

#include <mcuxClSession.h>          // Interface to the entire mcuxClSession component
#include <mcuxClHash.h>             // Interface to the entire mcuxClHash component
#include <mcuxClHashModes.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_ELS_Helper.h>
#include <mcuxClExample_RNG_Helper.h>

/* Source of this example data is NIST CAVP SHA3_256ShortMsg.rsp */

static const uint8_t data1[] = {
    0xb3U, 0x2dU, 0xecU, 0x58U, 0x86U, 0x5aU, 0xb7U, 0x46U, 0x14U, 0xeaU, 0x98U, 0x2eU, 0xfbU, 0x93U, 0xc0U, 0x8dU
};
static const uint8_t data2[] = {
    0x9aU, 0xcbU, 0x1bU, 0xb0U
};

static const uint8_t hashExpected[] = {
    0x6aU, 0x12U, 0xe5U, 0x35U, 0xdbU, 0xfdU, 0xdaU, 0xb6U, 0xd3U, 0x74U, 0x05U, 0x8dU, 0x92U, 0x33U, 0x8eU, 0x76U,
    0x0bU, 0x1aU, 0x21U, 0x14U, 0x51U, 0xa6U, 0xc0U, 0x9bU, 0xe9U, 0xb6U, 0x1eU, 0xe2U, 0x2fU, 0x3bU, 0xb4U, 0x67U
};

MCUXCLEXAMPLE_FUNCTION(mcuxClHashModes_sha3_256_streaming_example)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/
    /* Enable ELS */
    if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLHASH_MAX_CPU_WA_BUFFER_SIZE, MCUXCLRANDOMMODES_NCINIT_WACPU_SIZE), 0U);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    uint32_t context[MCUXCLHASH_CONTEXT_SIZE_SHA3_256_IN_WORDS];
    mcuxClHash_Context_t pContext = (mcuxClHash_Context_t) context;

    MCUXCLBUFFER_INIT_RO(data1Buf, session, data1, sizeof(data1));
    MCUXCLBUFFER_INIT_RO(data2Buf, session, data2, sizeof(data2));

    /**************************************************************************/
    /* Hash computation                                                       */
    /**************************************************************************/

    uint8_t hash[MCUXCLHASH_OUTPUT_SIZE_SHA3_256];
    MCUXCLBUFFER_INIT_RW(hashBuf, session, hash, sizeof(hash));
    uint32_t hashOutputSize = 0U;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result1, token1, mcuxClHash_init(
    /* mcuxCLSession_Handle_t session: */ session,
    /* mcuxClHash_Context_t context:   */ pContext,
    /* mcuxClHash_Algo_t  algo:        */ mcuxClHash_Algorithm_Sha3_256
    ));
    // mcuxClHash_init is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_init) != token1) || (MCUXCLHASH_STATUS_OK != result1))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result2, token2, mcuxClHash_process(
            /* mcuxCLSession_Handle_t session: */ session,
            /* mcuxClHash_Context_t context:   */ pContext,
            /* const uint8_t * const in:      */ data1Buf,
            /* uint32_t inLength:             */ sizeof(data1)
    ));
    // mcuxClHash_process is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process) != token2) || (MCUXCLHASH_STATUS_OK != result2))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result3, token3, mcuxClHash_process(
            /* mcuxCLSession_Handle_t session: */ session,
            /* mcuxClHash_Context_t context:   */ pContext,
            /* const uint8_t * const in:      */ data2Buf,
            /* uint32_t inLength:             */ sizeof(data2)
    ));
    // mcuxClHash_process is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process) != token3) || (MCUXCLHASH_STATUS_OK != result3))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result4, token4, mcuxClHash_finish(
            /* mcuxCLSession_Handle_t session: */ session,
            /* mcuxClHash_Context_t context:   */ pContext,
            /* mcuxCl_Buffer_t pOut,        */    hashBuf,
            /* uint32_t *const pOutSize    */    &hashOutputSize
    ));
    // mcuxClHash_finish is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_finish) != token4) || (MCUXCLHASH_STATUS_OK != result4))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if(sizeof(hash) != hashOutputSize)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Verification                                                           */
    /**************************************************************************/
    for(size_t i = 0U; i < sizeof(hash); i++)
    {
        if(hashExpected[i] != hash[i])  // Expect that the resulting hash matches our expected output
        {
            return MCUXCLEXAMPLE_STATUS_ERROR;
        }
    }

    /**************************************************************************/
    /* Session clean-up                                                       */
    /**************************************************************************/
    /** Destroy Session and cleanup Session **/
    if(!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Disable ELS to leave it in a clean state for the next example. */
    if(!mcuxClExample_Els_Disable())
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }


    return MCUXCLEXAMPLE_STATUS_OK;
}
