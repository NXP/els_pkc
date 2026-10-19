/*--------------------------------------------------------------------------*/
/* Copyright 2023-2024, 2026 NXP                                            */
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

#include <stdint.h>
#include <stdbool.h>

#include <mcuxClToolchain.h>
#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClHash.h>
#include <mcuxClEcc.h>
#include <mcuxClBuffer.h>
#include <mcuxClMemory.h>
#include <mcuxClPkc_Types.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClRandomModes.h>
#include <mcuxClExample_RNG_Helper.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClCore_Macros.h>
#include <mcuxClExample_ELS_Helper.h>

/* This example implements the ECDH key agreement directly on top of
 * mcuxClEcc_PointMult.
 *
 * The shared secret Z of an ECDH key agreement is the x-coordinate of the
 * point d * Q, where d is the own private key (scalar) and Q the peer public
 * key (point). This is exactly what mcuxClEcc_PointMult computes. 
 */

#define BYTE_LEN_P (MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIVATEKEY)      /* byteLen(p) = 32 */
#define BYTE_LEN_N (MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIVATEKEY)      /* byteLen(n) = 32 */

#define CPU_WA_BUFFER_SIZE MCUXCLCORE_MAX(MCUXCLECC_POINTMULT_WACPU_SIZE, \
                                MCUXCLRANDOMMODES_NCINIT_WACPU_SIZE)

#define PKC_WA_BUFFER_SIZE MCUXCLECC_POINTMULT_WAPKC_SIZE(BYTE_LEN_P, BYTE_LEN_N)
/**************************************************************************/
/* NIST P-256 domain parameters in BIG-endian format.                     */
/**************************************************************************/
static const uint8_t pCoefficientA[BYTE_LEN_P] =
{ /* a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC */
  0xFFu,0xFFu,0xFFu,0xFFu, 0x00u,0x00u,0x00u,0x01u, 
  0x00u,0x00u,0x00u,0x00u, 0x00u,0x00u,0x00u,0x00u,
  0x00u,0x00u,0x00u,0x00u, 0xFFu,0xFFu,0xFFu,0xFFu, 
  0xFFu,0xFFu,0xFFu,0xFFu, 0xFFu,0xFFu,0xFFu,0xFCu
};

static const uint8_t pCoefficientB[BYTE_LEN_P] =
{ /* b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B */
  0x5Au,0xC6u,0x35u,0xD8u, 0xAAu,0x3Au,0x93u,0xE7u, 
  0xB3u,0xEBu,0xBDu,0x55u, 0x76u,0x98u,0x86u,0xBCu,
  0x65u,0x1Du,0x06u,0xB0u, 0xCCu,0x53u,0xB0u,0xF6u, 
  0x3Bu,0xCEu,0x3Cu,0x3Eu, 0x27u,0xD2u,0x60u,0x4Bu
};

static const uint8_t pPrimeP[BYTE_LEN_P] =
{ /* p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF */
  0xFFu,0xFFu,0xFFu,0xFFu, 0x00u,0x00u,0x00u,0x01u, 
  0x00u,0x00u,0x00u,0x00u, 0x00u,0x00u,0x00u,0x00u,
  0x00u,0x00u,0x00u,0x00u, 0xFFu,0xFFu,0xFFu,0xFFu, 
  0xFFu,0xFFu,0xFFu,0xFFu, 0xFFu,0xFFu,0xFFu,0xFFu
};

static const uint8_t pOrderN[BYTE_LEN_N] =
{ /* n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 */
  0xFFu,0xFFu,0xFFu,0xFFu, 0x00u,0x00u,0x00u,0x00u, 
  0xFFu,0xFFu,0xFFu,0xFFu, 0xFFu,0xFFu,0xFFu,0xFFu,
  0xBCu,0xE6u,0xFAu,0xADu, 0xA7u,0x17u,0x9Eu,0x84u, 
  0xF3u,0xB9u,0xCAu,0xC2u, 0xFCu,0x63u,0x25u,0x51u
};

static const ALIGNED uint8_t pAlicePrivKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIVATEKEY] = 
{
  0x5Du, 0x37u, 0x8Du, 0xFDu, 0x5Cu, 0xDDu, 0x7Au, 0x37u,
  0xE7u, 0x0Fu, 0x1Au, 0xF7u, 0xFEu, 0x99u, 0xA5u, 0x16u,
  0xD4u, 0xE0u, 0xC4u, 0x34u, 0xD8u, 0x49u, 0x85u, 0xFBu,
  0x12u, 0x50u, 0x32u, 0x06u, 0x73u, 0x9Au, 0x96u, 0xF4u,
};

static const uint8_t pAlicePubKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY] = 
{
  0x0Cu, 0xB2u, 0x52u, 0x2Fu, 0x18u, 0xF9u, 0xB5u, 0xA3u,
  0xADu, 0x3Au, 0xE0u, 0x99u, 0x75u, 0x5Au, 0x49u, 0xCDu,
  0xCEu, 0x4Bu, 0x05u, 0x14u, 0xB5u, 0xC6u, 0x15u, 0x07u,
  0xF0u, 0xC6u, 0x39u, 0xE7u, 0x1Au, 0xB4u, 0x4Cu, 0xDEu,
  0x68u, 0xF8u, 0xDFu, 0x58u, 0xA9u, 0xC0u, 0xF8u, 0x62u,
  0x35u, 0x9Cu, 0xB2u, 0x36u, 0xF9u, 0x29u, 0xABu, 0x9Fu,
  0x89u, 0xB1u, 0xA7u, 0xA2u, 0x34u, 0xC1u, 0xE4u, 0x57u,
  0x23u, 0xC7u, 0xE9u, 0x41u, 0x25u, 0x80u, 0x46u, 0xBBu,
};

static const ALIGNED uint8_t pBobPrivKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIVATEKEY] = 
{
  0x90u, 0xA1u, 0x2Cu, 0xEDu, 0x78u, 0x9Au, 0x4Fu, 0x82u,
  0x95u, 0xBAu, 0x2Fu, 0x79u, 0x3Du, 0x52u, 0x15u, 0xABu,
  0xDEu, 0x98u, 0x4Cu, 0x4Bu, 0x08u, 0x87u, 0xBFu, 0x6Fu,
  0x75u, 0x1Bu, 0x1Bu, 0x19u, 0xF2u, 0xFDu, 0x76u, 0x03u
};

static const uint8_t pBobPubKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY] = 
{
  0xF4u, 0x7Au, 0x9Au, 0xA6u, 0x2Du, 0x6Bu, 0x5Cu, 0x57u,
  0x1Eu, 0xC6u, 0x6Au, 0xDFu, 0x00u, 0x1Eu, 0x2Cu, 0x2Du,
  0x21u, 0x72u, 0xDEu, 0x07u, 0x2Bu, 0xA5u, 0xB9u, 0xB4u,
  0xB2u, 0xB5u, 0xC3u, 0xEBu, 0xC9u, 0x50u, 0xE0u, 0x21u,
  0x12u, 0xF9u, 0xD0u, 0xA3u, 0xA8u, 0x85u, 0x0Bu, 0x9Bu,
  0xA6u, 0xE1u, 0x4Bu, 0x3Bu, 0x7Du, 0x54u, 0xD8u, 0x7Bu,
  0xF9u, 0x82u, 0xECu, 0x38u, 0x1Bu, 0x81u, 0x5Bu, 0x7Du,
  0x9Fu, 0x29u, 0x51u, 0x9Fu, 0x52u, 0x95u, 0x24u, 0xD6u
};

/**
 * @brief ECDH key agreement implemented on top of mcuxClEcc_PointMult.
 *
 * Computes the ECDH shared secret Z = x-coordinate of (d * Q) where d is the
 * own private key given by @p pPrivKeyData and Q the peer public key given by
 * @p pPubKeyData.
 *
 * The key material is passed in directly as the big-endian octet strings that
 * were also handed to mcuxClKey_init.
 *
 * @param[in]  pSession      Handle for the current CL session.
 * @param[in]  pPrivKeyData  Own private key d, exactly BYTE_LEN_N bytes big-endian.
 * @param[in]  pPubKeyData   Peer public key Q = Qx||Qy, exactly 2 * BYTE_LEN_P bytes big-endian.
 * @param[out] pResult       Buffer of result.
 *
 * @return true on success, false otherwise.
 *
 * @attention This function uses the PRNG, which has to be initialized before.
 */
static bool mcuxClEcc_Example_ECDH_PointMult(
  mcuxClSession_Handle_t pSession,
  const uint8_t * pPrivKeyData,
  const uint8_t * pPubKeyData,
  uint8_t * pResult)
{
  /* mcuxClEcc_PointMult always exports both coordinates of the result point,
   * although only the x-coordinate is used as the shared secret. */

  MCUXCLBUFFER_INIT_RO(buffA,      NULL, pCoefficientA, BYTE_LEN_P);
  MCUXCLBUFFER_INIT_RO(buffB,      NULL, pCoefficientB, BYTE_LEN_P);
  MCUXCLBUFFER_INIT_RO(buffP,      NULL, pPrimeP,       BYTE_LEN_P);
  MCUXCLBUFFER_INIT_RO(buffN,      NULL, pOrderN,       BYTE_LEN_N);
  MCUXCLBUFFER_INIT_RO(buffScalar, NULL, pPrivKeyData,  BYTE_LEN_N);
  MCUXCLBUFFER_INIT_RO(buffPoint,  NULL, pPubKeyData,   BYTE_LEN_P * 2u);
  MCUXCLBUFFER_INIT   (buffResult, NULL, pResult,       BYTE_LEN_P * 2u);

  const mcuxClEcc_PointMult_Param_t pointMultParams =
  {
    .curveParam = (mcuxClEcc_DomainParam_t)
    {
      .pA = buffA,
      .pB = buffB,
      .pP = buffP,
      .pN = buffN,
      .misc = mcuxClEcc_DomainParam_misc_Pack(BYTE_LEN_N, BYTE_LEN_P)
    },
    .pScalar = buffScalar,  /* own private key d      */
    .pPoint  = buffPoint,   /* peer public key Q      */
    .pResult = buffResult,  /* result point R = d * Q */
    .optLen  = 0u           /* reserved, must be 0    */
  };

  /* Compute R = d * Q. mcuxClEcc_PointMult internally checks that Q lies on the
   * curve (MCUXCLECC_STATUS_INVALID_PARAMS otherwise) and that neither d mod n = 0
   * nor the result is the neutral point (MCUXCLECC_STATUS_NEUTRAL_POINT). */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pointMult_result, pointMult_token,
    mcuxClEcc_PointMult(pSession, &pointMultParams));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointMult) == pointMult_token) && (MCUXCLECC_STATUS_OK == pointMult_result))
  {
    return true;
  }
  else
  {
    return false;    
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();
}

MCUXCLEXAMPLE_FUNCTION(mcuxClEcc_ECDH_KeyAgreement_NIST_P256_example)
{

  /**************************************************************************/
  /* Preparation                                                            */
  /**************************************************************************/

  /** Initialize ELS, Enable the ELS **/
  if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  /* Allocate and initialize session */
  mcuxClSession_Descriptor_t sessionDesc;
  mcuxClSession_Handle_t session = &sessionDesc;
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session,
                                              CPU_WA_BUFFER_SIZE,
                                              PKC_WA_BUFFER_SIZE);

  /* Initialize the PRNG */
  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(prngInit_status, prngInit_token, mcuxClRandom_ncInit(session));

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != prngInit_token) || (MCUXCLRANDOM_STATUS_OK != prngInit_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /**************************************************************************/
  /* ECDH key agreement on NIST P-256                                       */
  /**************************************************************************/

  /* Alice computes the shared key Z = xcoord(dA * QB) */
  uint8_t aliceSharedSecretFullPoint[BYTE_LEN_P * 2u];

  if(!mcuxClEcc_Example_ECDH_PointMult(
    /* mcuxClSession_Handle_t session:       */ session,
    /* const uint8_t * pPrivKeyData:        */ pAlicePrivKeyData,
    /* const uint8_t * pPubKeyData:         */ pBobPubKeyData,
    /* uint8_t * pSharedSecret:             */ aliceSharedSecretFullPoint))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  /* Bob computes the shared key Z = xcoord(dB * QA) */
  uint8_t bobSharedSecretFullPoint[BYTE_LEN_P * 2u];

  if(!mcuxClEcc_Example_ECDH_PointMult(
    /* mcuxClSession_Handle_t session:       */ session,
    /* const uint8_t * pPrivKeyData:        */ pBobPrivKeyData,
    /* const uint8_t * pPubKeyData:         */ pAlicePubKeyData,
    /* uint8_t * pSharedSecret:             */ bobSharedSecretFullPoint))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  /* Verify that Alice and Bob computed the same shared key 
  with length of MCUXCLECC_WEIERECC_NIST_P256_SIZE_SHAREDSECRET
   as only the x-coordinate is used as the shared secret */
  if(!mcuxClCore_assertEqual(bobSharedSecretFullPoint, aliceSharedSecretFullPoint, MCUXCLECC_WEIERECC_NIST_P256_SIZE_SHAREDSECRET))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }


  /* Destroy Session and cleanup Session */
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
