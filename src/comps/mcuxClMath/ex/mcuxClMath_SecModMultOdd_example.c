/*--------------------------------------------------------------------------*/
/* Copyright 2024-2025 NXP                                                  */
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
 * @example mcuxClMath_SecModMultOdd_example.c
 * @brief   Example for the mcuxClMath component
 */

#include <mcuxClToolchain.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClSession.h>
#include <mcuxClBuffer.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClCore_Macros.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClRandom.h>
#include <mcuxClMath.h>
#include <mcuxClExample_RNG_Helper.h>
#include <mcuxClEls.h> // Interface to the entire mcuxClEls component
#include <mcuxClExample_ELS_Helper.h>

#define LEN_X 16u
#define LEN_Y 8u
#define LEN_N 16u
#define LEN_R LEN_N

static const ALIGNED uint8_t operandX[LEN_X] =
{
    /* X = 0x0123456789abcdef0123456789abcdef */
    0x01u, 0x23u, 0x45u, 0x67u, 0x89u, 0xabu, 0xcdu, 0xefu,
    0x01u, 0x23u, 0x45u, 0x67u, 0x89u, 0xabu, 0xcdu, 0xefu
};

static const ALIGNED uint8_t operandY[LEN_Y] =
{
    /* Y = 0x23456789abcdef10 */
    0x23u, 0x45u, 0x67u, 0x89u, 0xabu, 0xcdu, 0xefu, 0x10u
};

static const ALIGNED uint8_t operandN[LEN_N] =
{
    /* N = 0x23456789abcdef0123456789abcdef01 */
    0x23u, 0x45u, 0x67u, 0x89u, 0xabu, 0xcdu, 0xefu, 0x01u,
    0x23u, 0x45u, 0x67u, 0x89u, 0xabu, 0xcdu, 0xefu, 0x01u
};

static const ALIGNED uint8_t refR[LEN_R] =
{
    /* R = X*Y mod N = 0x11111111111111011111111111111101 */
    0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 0x01u,
    0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 0x01u
};

#define MAX_CPUWA_SIZE (MCUXCLRANDOMMODES_NCINIT_WACPU_SIZE + \
                        MCUXCLRANDOMMODES_NCGENERATE_WACPU_SIZE + \
                        MCUXCLMATH_MODMULT_CPU_WA_BUFFER_SIZE)

#define MAX_PKCWA_SIZE MCUXCLMATH_MODMULT_PKC_WA_BUFFER_SIZE(LEN_X, LEN_N)

/**
 * Performs an example secure modular multiplication using the mcuxClMath component.
 */
MCUXCLEXAMPLE_FUNCTION(mcuxClMath_SecModMultOdd_example)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

  /** Initialize ELS, Enable the ELS **/
  if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t pSession = &sessionDesc;
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(pSession, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);
    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(pSession);
    uint8_t resultData[LEN_R];
    MCUXCLBUFFER_INIT_RO(buffX, pSession, operandX, LEN_X);
    MCUXCLBUFFER_INIT_RO(buffY, pSession, operandY, LEN_Y);
    MCUXCLBUFFER_INIT_RO(buffN, pSession, operandN, LEN_N);
    MCUXCLBUFFER_INIT(buffR, pSession, resultData, LEN_R);

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(secModMultOdd_status, secModMultOdd_token,
        mcuxClMath_SecModMultOdd(pSession,
                                buffX,
                                LEN_X,
                                buffY,
                                LEN_Y,
                                buffN,
                                LEN_N,
                                buffR)
    );

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_SecModMultOdd) != secModMultOdd_token) || (MCUXCLMATH_STATUS_OK != secModMultOdd_status))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Verification                                                           */
    /**************************************************************************/
    if (!mcuxClCore_assertEqual(resultData, refR, sizeof(refR)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Clean session                                                          */
    /**************************************************************************/

    if (!mcuxClExample_Session_Clean(pSession))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}
