/*--------------------------------------------------------------------------*/
/* Copyright 2024 NXP                                                       */
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
 * @file  mcuxClEcc_EdDSA_VerifySignature_Invalid_Signature_Ed25519_example.c
 * @brief Example for the mcuxClEcc component
 *
 * @example mcuxClEcc_EdDSA_VerifySignature_Invalid_Signature_Ed25519_example.c
 * @brief   Example for the mcuxClEcc component EdDsa signature extended verification
 *          with preverification of exceptional points.
 */

#include <mcuxClToolchain.h>
#include <mcuxClBuffer.h>
#include <mcuxClEcc.h>
#include <mcuxClKey.h>
#include <mcuxClPkc_Types.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection

#include <mcuxClExample_ELS_Helper.h>
#include <mcuxCsslMemory.h>

#define MAX_CPUWA_SIZE MCUXCLECC_EDDSA_VERIFYSIGNATURE_ED25519_WACPU_SIZE
#define MAX_PKCWA_SIZE MCUXCLECC_EDDSA_VERIFYSIGNATURE_ED25519_WAPKC_SIZE

/* Input taken from "TEST SHA(abc)" from Section 7.1 of IRTF rfc 8032 */
static const ALIGNED uint8_t pIn[] =
{
    0xddu, 0xafu, 0x35u, 0xa1u, 0x93u, 0x61u, 0x7au, 0xbau,
    0xccu, 0x41u, 0x73u, 0x49u, 0xaeu, 0x20u, 0x41u, 0x31u,
    0x12u, 0xe6u, 0xfau, 0x4eu, 0x89u, 0xa9u, 0x7eu, 0xa2u,
    0x0au, 0x9eu, 0xeeu, 0xe6u, 0x4bu, 0x55u, 0xd3u, 0x9au,
    0x21u, 0x92u, 0x99u, 0x2au, 0x27u, 0x4fu, 0xc1u, 0xa8u,
    0x36u, 0xbau, 0x3cu, 0x23u, 0xa3u, 0xfeu, 0xebu, 0xbdu,
    0x45u, 0x4du, 0x44u, 0x23u, 0x64u, 0x3cu, 0xe8u, 0x0eu,
    0x2au, 0x9au, 0xc9u, 0x4fu, 0xa5u, 0x4cu, 0xa4u, 0x9fu
};

/* Signature taken from "TEST SHA(abc)" from Section 7.1 of IRTF rfc 8032 */
static ALIGNED uint8_t pSignature[MCUXCLECC_EDDSA_ED25519_SIZE_SIGNATURE] =
{
    0xdcu, 0x2au, 0x44u, 0x59u, 0xe7u, 0x36u, 0x96u, 0x33u,
    0xa5u, 0x2bu, 0x1bu, 0xf2u, 0x77u, 0x83u, 0x9au, 0x00u,
    0x20u, 0x10u, 0x09u, 0xa3u, 0xefu, 0xbfu, 0x3eu, 0xcbu,
    0x69u, 0xbeu, 0xa2u, 0x18u, 0x6cu, 0x26u, 0xb5u, 0x89u,
    0x09u, 0x35u, 0x1fu, 0xc9u, 0xacu, 0x90u, 0xb3u, 0xecu,
    0xfdu, 0xfbu, 0xc7u, 0xc6u, 0x64u, 0x31u, 0xe0u, 0x30u,
    0x3du, 0xcau, 0x17u, 0x9cu, 0x13u, 0x8au, 0xc1u, 0x7au,
    0xd9u, 0xbeu, 0xf1u, 0x17u, 0x73u, 0x31u, 0xa7u, 0x04u
};

/* Public key taken from "TEST SHA(abc)" from Section 7.1 of IRTF rfc 8032 */
static const ALIGNED uint8_t pPublicKey[MCUXCLECC_EDDSA_ED25519_SIZE_PUBLICKEY] =
{
    0xecu, 0x17u, 0x2bu, 0x93u, 0xadu, 0x5eu, 0x56u, 0x3bu,
    0xf4u, 0x93u, 0x2cu, 0x70u, 0xe1u, 0x24u, 0x50u, 0x34u,
    0xc3u, 0x54u, 0x67u, 0xefu, 0x2eu, 0xfdu, 0x4du, 0x64u,
    0xebu, 0xf8u, 0x19u, 0x68u, 0x34u, 0x67u, 0xe2u, 0xbfu
};


static mcuxClEcc_Status_t mcuxClEcc_EdDSA_VerifySignature_ExtendedCheck
(
    mcuxClSession_Handle_t session,
    mcuxClKey_Handle_t     key,
    const mcuxClEcc_EdDSA_SignatureProtocolDescriptor_t *mode,
    mcuxCl_InputBuffer_t   pIn,
    uint32_t              inSize,
    mcuxCl_InputBuffer_t   pSignatureBuf,
    uint32_t              signatureSize )
{
    #define EXCEPTIONAL_POINTS_NUM 11u
    #define EXCEPTIONAL_POINT_SIZE (MCUXCLECC_EDDSA_ED25519_SIZE_SIGNATURE / 2u)
    static const uint8_t exceptionalPoints[EXCEPTIONAL_POINTS_NUM][EXCEPTIONAL_POINT_SIZE] =
    {
        { 0xc7u, 0x17u, 0x6au, 0x70u, 0x3du, 0x4du, 0xd8u, 0x4fu, 
          0xbau, 0x3cu, 0x0bu, 0x76u, 0x0du, 0x10u, 0x67u, 0x0fu,
          0x2au, 0x20u, 0x53u, 0xfau, 0x2cu, 0x39u, 0xccu, 0xc6u,
          0x4eu, 0xc7u, 0xfdu, 0x77u, 0x92u, 0xacu, 0x03u, 0x7au },
        { 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
          0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
          0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
          0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u },
        { 0x26u, 0xe8u, 0x95u, 0x8fu, 0xc2u, 0xb2u, 0x27u, 0xb0u,
          0x45u, 0xc3u, 0xf4u, 0x89u, 0xf2u, 0xefu, 0x98u, 0xf0u,
          0xd5u, 0xdfu, 0xacu, 0x05u, 0xd3u, 0xc6u, 0x33u, 0x39u,
          0xb1u, 0x38u, 0x02u, 0x88u, 0x6du, 0x53u, 0xfcu, 0x05u },
        { 0xecu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
          0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
          0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 
          0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0x7fu },
        { 0x26u, 0xe8u, 0x95u, 0x8fu, 0xc2u, 0xb2u, 0x27u, 0xb0u,
          0x45u, 0xc3u, 0xf4u, 0x89u, 0xf2u, 0xefu, 0x98u, 0xf0u, 
          0xd5u, 0xdfu, 0xacu, 0x05u, 0xd3u, 0xc6u, 0x33u, 0x39u,
          0xb1u, 0x38u, 0x02u, 0x88u, 0x6du, 0x53u, 0xfcu, 0x85u },
        { 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
          0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
          0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
          0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u },
        { 0xc7u, 0x17u, 0x6au, 0x70u, 0x3du, 0x4du, 0xd8u, 0x4fu,
          0xbau, 0x3cu, 0x0bu, 0x76u, 0x0du, 0x10u, 0x67u, 0x0fu, 
          0x2au, 0x20u, 0x53u, 0xfau, 0x2cu, 0x39u, 0xccu, 0xc6u, 
          0x4eu, 0xc7u, 0xfdu, 0x77u, 0x92u, 0xacu, 0x03u, 0xfau },
        { 0x01u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
          0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
          0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
          0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u },
        { 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
          0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
          0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
          0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u },
        { 0xc7u, 0x17u, 0x6au, 0x70u, 0x3du, 0x4du, 0xd8u, 0x4fu,
          0xbau, 0x3cu, 0x0bu, 0x76u, 0x0du, 0x10u, 0x67u, 0x0fu,
          0x2au, 0x20u, 0x53u, 0xfau, 0x2cu, 0x39u, 0xccu, 0xc6u, 
          0x4eu, 0xc7u, 0xfdu, 0x77u, 0x92u, 0xacu, 0x03u, 0xfau },
        { 0x01u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
          0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
          0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
          0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u }
    };

    const uint8_t *pR = MCUXCLBUFFER_GET(pSignatureBuf);

    /* If signature R is equal to one of the invalid points, reject it immediately */
    for (size_t pntIdx = 0; pntIdx < EXCEPTIONAL_POINTS_NUM; pntIdx++)
    {
        MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(compareResult, compareToken, mcuxCsslMemory_Compare(
        /* mcuxCsslParamIntegrity_Checksum_t chk,*/ mcuxCsslParamIntegrity_Protect(3u, exceptionalPoints[pntIdx], pR, EXCEPTIONAL_POINT_SIZE),
        /* void const * lhs,                    */ exceptionalPoints[pntIdx],
        /* void const * rhs,                    */ pR,
        /* size_t length                        */ EXCEPTIONAL_POINT_SIZE));

        /* Check the return code of mcuxCsslMemory_Compare */
        if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Compare) != compareToken) || (MCUXCSSLMEMORY_STATUS_EQUAL == compareResult))
        {
            return MCUXCLECC_STATUS_INVALID_SIGNATURE;
        }

        MCUX_CSSL_FP_FUNCTION_CALL_END();
        
    }

    return mcuxClEcc_EdDSA_VerifySignature(
    /* mcuxClSession_Handle_t pSession                        */ session,
    /* mcuxClKey_Handle_t pubKey                              */ key,
    /* const mcuxClEcc_EdDSA_SignatureProtocolDescriptor_t*   */ mode,
    /* mcuxCl_InputBuffer_t pIn                               */ pIn,
    /* uint32_t inSize                                       */ inSize,
    /* mcuxCl_InputBuffer_t pSignature                        */ pSignatureBuf,
    /* uint32_t signatureSize                                */ signatureSize);
}


MCUXCLEXAMPLE_FUNCTION(mcuxClEcc_EdDSA_VerifySignature_Invalid_Signature_Ed25519_example)
{
    /******************************************/
    /* Set up the environment                 */
    /******************************************/

    /* Initialize ELS, Enable the ELS */
    if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t session;

    /* Allocate and initialize PKC workarea */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(&session, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);

    /******************************************/
    /* Initialize the public key              */
    /******************************************/

    /* Initialize public key */
    uint32_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKey_Handle_t pubKey = (mcuxClKey_Handle_t) pubKeyDesc;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(keyInit_status, keyInit_token, mcuxClKey_init(
        /* mcuxClSession_Handle_t session         */ &session,
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("The pointer pubKey is of the right type (mcuxClKey_Handle_t)")
        /* mcuxClKey_Handle_t key                 */ pubKey,
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()
        /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_EdDSA_Ed25519_Pub,
        /* const uint8_t * pKeyData              */ pPublicKey,
        /* uint32_t keyDataLength                */ sizeof(pPublicKey))
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != keyInit_token) || (MCUXCLKEY_STATUS_OK != keyInit_status))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUXCLBUFFER_INIT_RO(pSignatureBuf, NULL, pSignature, sizeof(pSignature));
    MCUXCLBUFFER_INIT_RO(pInBuf, NULL, pIn, sizeof(pIn));

    /**************************************************************************/
    /* Ed25519 signature verification                                         */
    /**************************************************************************/
    /* Call mcuxClEcc_EdDSA_VerifySignature to verify the signature */
    if (MCUXCLECC_STATUS_OK != mcuxClEcc_EdDSA_VerifySignature_ExtendedCheck(
    /* mcuxClSession_Handle_t pSession                        */ &session,
    /* mcuxClKey_Handle_t pubKey                              */ pubKey,
    /* const mcuxClEcc_EdDSA_SignatureProtocolDescriptor_t*   */ &mcuxClEcc_EdDsa_Ed25519ProtocolDescriptor,
    /* mcuxCl_InputBuffer_t pIn                               */ pInBuf,
    /* uint32_t inSize                                       */ sizeof(pIn),
    /* mcuxCl_InputBuffer_t pSignature                        */ pSignatureBuf,
    /* uint32_t signatureSize                                */ sizeof(pSignature)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }


    /* Destroy Session and cleanup Session */
    if(!mcuxClExample_Session_Clean(&session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Disable the ELS */
    if(!mcuxClExample_Els_Disable())
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}
