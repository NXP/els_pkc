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
 * @example mcuxClHashModes_sha3_384_streaming_example.c
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

/* Source of this example data is NIST CAVP SHA3_384ShortMsg.rsp */

static const uint8_t data1[] = {
    0x9cU, 0x69U, 0x49U, 0x43U, 0x38U, 0x9bU, 0xdcU, 0x4eU, 0x05U, 0xadU, 0x7cU, 0x2fU, 0x63U, 0xceU, 0xacU, 0x28U
};
static const uint8_t data2[] = {
    0x20U, 0xe1U, 0xd2U, 0xd7U
};

static const uint8_t hashExpected[] = {
    0xf6U, 0x92U, 0xc0U, 0x25U, 0xc5U, 0xc5U, 0xf3U, 0xd1U, 0x27U, 0x52U, 0x13U, 0xc1U, 0xdfU, 0x9bU, 0xf9U, 0xebU,
    0x6dU, 0x21U, 0x88U, 0xedU, 0xa9U, 0x0aU, 0xb5U, 0xbfU, 0xfeU, 0x63U, 0x1fU, 0x1dU, 0xbfU, 0x70U, 0xebU, 0xd6U,
    0x28U, 0xcaU, 0xeeU, 0x88U, 0xb7U, 0xd1U, 0x49U, 0xe1U, 0xacU, 0x4eU, 0x26U, 0x28U, 0x73U, 0x97U, 0x9aU, 0xfeU
};

MCUXCLEXAMPLE_FUNCTION(mcuxClHashModes_sha3_384_streaming_example)
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

    uint32_t context[MCUXCLHASH_CONTEXT_SIZE_SHA3_384_IN_WORDS];
    mcuxClHash_Context_t pContext = (mcuxClHash_Context_t) context;

    MCUXCLBUFFER_INIT_RO(data1Buf, session, data1, sizeof(data1));
    MCUXCLBUFFER_INIT_RO(data2Buf, session, data2, sizeof(data2));

    /**************************************************************************/
    /* Hash computation                                                       */
    /**************************************************************************/

    uint8_t hash[MCUXCLHASH_OUTPUT_SIZE_SHA3_384];
    MCUXCLBUFFER_INIT_RW(hashBuf, session, hash, sizeof(hash));
    uint32_t hashOutputSize = 0U;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result1, token1, mcuxClHash_init(
    /* mcuxCLSession_Handle_t session: */ session,
    /* mcuxClHash_Context_t context:   */ pContext,
    /* mcuxClHash_Algo_t  algo:        */ mcuxClHash_Algorithm_Sha3_384
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
