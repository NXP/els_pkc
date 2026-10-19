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
 * @example mcuxClXofModes_shake_256_oneshot_example.c
 * @brief mcuxClXofModes example application
 */

#include <mcuxClSession.h>          // Interface to the entire mcuxClSession component
#include <mcuxClXof.h>
#include <mcuxClXofModes.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_ELS_Helper.h>
#include <mcuxClExample_RNG_Helper.h>

/* Source of this example data is NIST CAVP SHAKE256VariableOut.rsp */

static const uint8_t data[] = {
    0x8dU, 0x80U, 0x01U, 0xe2U, 0xc0U, 0x96U, 0xf1U, 0xb8U, 0x8eU, 0x7cU, 0x92U, 0x24U, 0xa0U, 0x86U, 0xefU, 0xd4U,
    0x79U, 0x7fU, 0xbfU, 0x74U, 0xa8U, 0x03U, 0x3aU, 0x2dU, 0x42U, 0x2aU, 0x2bU, 0x6bU, 0x8fU, 0x67U, 0x47U, 0xe4U
};

#define MCUXCLXOF_EXAMPLE_SHAKE_256_OUTSIZE 250U
static const uint32_t outSize = MCUXCLXOF_EXAMPLE_SHAKE_256_OUTSIZE; // arbitrary output size in bytes

static const uint8_t expectedOutput[MCUXCLXOF_EXAMPLE_SHAKE_256_OUTSIZE] = {
    0x2eU, 0x97U, 0x5fU, 0x6aU, 0x8aU, 0x14U, 0xf0U, 0x70U, 0x4dU, 0x51U, 0xb1U, 0x36U, 0x67U, 0xd8U, 0x19U, 0x5cU,
    0x21U, 0x9fU, 0x71U, 0xe6U, 0x34U, 0x56U, 0x96U, 0xc4U, 0x9fU, 0xa4U, 0xb9U, 0xd0U, 0x8eU, 0x92U, 0x25U, 0xd3U,
    0xd3U, 0x93U, 0x93U, 0x42U, 0x51U, 0x52U, 0xc9U, 0x7eU, 0x71U, 0xddU, 0x24U, 0x60U, 0x1cU, 0x11U, 0xabU, 0xcfU,
    0xa0U, 0xf1U, 0x2fU, 0x53U, 0xc6U, 0x80U, 0xbdU, 0x3aU, 0xe7U, 0x57U, 0xb8U, 0x13U, 0x4aU, 0x9cU, 0x10U, 0xd4U,
    0x29U, 0x61U, 0x58U, 0x69U, 0x21U, 0x7fU, 0xddU, 0x58U, 0x85U, 0xc4U, 0xdbU, 0x17U, 0x49U, 0x85U, 0x70U, 0x3aU,
    0x6dU, 0x6dU, 0xe9U, 0x4aU, 0x66U, 0x7eU, 0xacU, 0x30U, 0x23U, 0x44U, 0x3aU, 0x83U, 0x37U, 0xaeU, 0x1bU, 0xc6U,
    0x01U, 0xb7U, 0x6dU, 0x7dU, 0x38U, 0xecU, 0x3cU, 0x34U, 0x46U, 0x31U, 0x05U, 0xf0U, 0xd3U, 0x94U, 0x9dU, 0x78U,
    0xe5U, 0x62U, 0xa0U, 0x39U, 0xe4U, 0x46U, 0x95U, 0x48U, 0xb6U, 0x09U, 0x39U, 0x5dU, 0xe5U, 0xa4U, 0xfdU, 0x43U,
    0xc4U, 0x6cU, 0xa9U, 0xfdU, 0x6eU, 0xe2U, 0x9aU, 0xdaU, 0x5eU, 0xfcU, 0x07U, 0xd8U, 0x4dU, 0x55U, 0x32U, 0x49U,
    0x45U, 0x0dU, 0xabU, 0x4aU, 0x49U, 0xc4U, 0x83U, 0xdeU, 0xd2U, 0x50U, 0xc9U, 0x33U, 0x8fU, 0x85U, 0xcdU, 0x93U,
    0x7aU, 0xe6U, 0x6bU, 0xb4U, 0x36U, 0xf3U, 0xb4U, 0x02U, 0x6eU, 0x85U, 0x9fU, 0xdaU, 0x1cU, 0xa5U, 0x71U, 0x43U,
    0x2fU, 0x3bU, 0xfcU, 0x09U, 0xe7U, 0xc0U, 0x3cU, 0xa4U, 0xd1U, 0x83U, 0xb7U, 0x41U, 0x11U, 0x1cU, 0xa0U, 0x48U,
    0x3dU, 0x0eU, 0xdaU, 0xbcU, 0x03U, 0xfeU, 0xb2U, 0x3bU, 0x17U, 0xeeU, 0x48U, 0xe8U, 0x44U, 0xbaU, 0x24U, 0x08U,
    0xd9U, 0xdcU, 0xfdU, 0x01U, 0x39U, 0xd2U, 0xe8U, 0xc7U, 0x31U, 0x01U, 0x25U, 0xaeU, 0xe8U, 0x01U, 0xc6U, 0x1aU,
    0xb7U, 0x90U, 0x0dU, 0x1eU, 0xfcU, 0x47U, 0xc0U, 0x78U, 0x28U, 0x17U, 0x66U, 0xf3U, 0x61U, 0xc5U, 0xe6U, 0x11U,
    0x13U, 0x46U, 0x23U, 0x5eU, 0x1dU, 0xc3U, 0x83U, 0x25U, 0x66U, 0x6cU
};

MCUXCLEXAMPLE_FUNCTION(mcuxClXofModes_shake_256_oneshot_example)
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
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLXOF_COMPUTE_CPU_WA_BUFFER_SIZE_MAX, MCUXCLRANDOMMODES_NCINIT_WACPU_SIZE), 0U);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    /**************************************************************************/
    /* Output computation                                                     */
    /**************************************************************************/

    uint8_t output[MCUXCLXOF_EXAMPLE_SHAKE_256_OUTSIZE];
    MCUXCLBUFFER_INIT_RW(outputBuf, session, output, sizeof(output));
    MCUXCLBUFFER_INIT_RO(dataBuf, session, data, sizeof(data));
    MCUXCLBUFFER_INIT_RO(customizationBuf, session, NULL, 0U);

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(compute_result, compute_token, mcuxClXof_compute(
    /* mcuxClSession_Handle_t session:       */ session,
    /* mcuxClXof_Algo_t algorithm:           */ mcuxClXof_Algorithm_Shake_256,
    /* mcuxCl_InputBuffer_t pIn:             */ dataBuf,
    /* uint32_t inSize:                     */ sizeof(data),
    /* mcuxCl_InputBuffer_t pCustomization:  */ customizationBuf,
    /* uint32_t customizationSize:          */ 0U,
    /* mcuxCl_Buffer_t pOut                  */ outputBuf,
    /* uint32_t outSize,                    */ outSize)
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClXof_compute) != compute_token) || (MCUXCLXOF_STATUS_OK != compute_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Verification                                                           */
    /**************************************************************************/
    for(size_t i = 0U; i < outSize; i++)
    {
        if(expectedOutput[i] != output[i]) // Expect that the computed output matches our expected output
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
