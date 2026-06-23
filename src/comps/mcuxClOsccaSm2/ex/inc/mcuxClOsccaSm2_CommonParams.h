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
 * @file:  mcuxClOsccaSm2_CommonParams.h
 * @brief: OSCCA SM2 common parameters (SM2FP256v1)
 */
/**@{*/


#ifndef MCUXCLOSCCASM2_COMMONPARAMS_H_
#define MCUXCLOSCCASM2_COMMONPARAMS_H_

#include <mcuxClCore_Examples.h>
#if MCUXCL_FEATURE_RANDOMMODES_OSCCA_TRNG == 0
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxClMemory.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#endif

#if MCUXCL_FEATURE_RANDOMMODES_OSCCA_TRNG == 0
static const uint8_t mcuxClOsscaSm2_Example_PatchedRngValue[MCUXCLOSCCASM2_EXAMPLE_PATCH_SIZE] = {
    0xa1, 0xba, 0xf0, 0xb2, 0x9f, 0x2b, 0x3d, 0x0d,
    0x12, 0x73, 0x2f, 0x43, 0x36, 0xb6, 0x6e, 0x77,
    0xd5, 0x21, 0x95, 0x72, 0x1e, 0xdb, 0x9a, 0x52,
    0xf8, 0x6d, 0x0a, 0x56, 0x55, 0xc2, 0x45, 0x82,
    0x10, 0x08, 0xe9, 0xd4, 0xbd, 0xce, 0xcd, 0x72,
    0x74, 0xd4, 0x70, 0x85, 0x09, 0x25, 0x7a, 0xe5,
    0xcf, 0x00, 0x98, 0x91, 0xce, 0x55, 0x5a, 0xce,
    0x5c, 0x81, 0xc2, 0x29, 0xda, 0xd5, 0x1b, 0x83
};

static mcuxClRandom_Status_t RNG_Patch_function(
    mcuxClSession_Handle_t session,
    mcuxClRandom_Context_t pCustomCtx,
    uint8_t *pOut,
    uint32_t outLength
)
{
    (void)pCustomCtx;
    (void)session;
    if(outLength > sizeof(mcuxClOsscaSm2_Example_PatchedRngValue))
    {
        return MCUXCLRANDOM_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN(memCopyToken, mcuxClMemory_copy(pOut, mcuxClOsscaSm2_Example_PatchedRngValue, outLength, outLength));
    if(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) != memCopyToken)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_VOID_END();

    return MCUXCLRANDOM_STATUS_OK;
}
#endif /* MCUXCL_FEATURE_RANDOMMODES_PATCHMODE */

#endif /* MCUXCLOSCCASM2_COMMONPARAMS_H_ */
