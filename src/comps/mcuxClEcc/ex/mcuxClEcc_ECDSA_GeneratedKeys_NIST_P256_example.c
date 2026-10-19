/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024, 2026 NXP                                            */
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
 * @file  mcuxClEcc_ECDSA_GeneratedKeys_NIST_P256_example.c
 * @brief Example for the mcuxClEcc component
 *
 * @example mcuxClEcc_ECDSA_GeneratedKeys_NIST_P256_example.c
 * @brief   Example for ECDSA key pair generation, signature generation and
 *          signature verification on NIST P-256, using the low level mcuxClEcc
 *          APIs mcuxClEcc_KeyGen, mcuxClEcc_Sign and mcuxClEcc_Verify.
 */

#include <mcuxClToolchain.h>
#include <mcuxClSession.h>
#include <mcuxClBuffer.h>
#include <mcuxClEcc.h>
#include <mcuxClPkc_Types.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_RNG_Helper.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClCore_Macros.h>
#include <mcuxClExample_ELS_Helper.h>

#define BYTE_LEN_P  (MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP)          /* byteLen(p) = 32 */
#define BYTE_LEN_N  (MCUXCLECC_WEIERECC_NIST_P256_SIZE_BASEPOINTORDER)  /* byteLen(n) = 32 */

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

static const uint8_t pPointG[BYTE_LEN_P * 2u] =
{ /* Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296 */
  0x6Bu,0x17u,0xD1u,0xF2u, 0xE1u,0x2Cu,0x42u,0x47u, 
  0xF8u,0xBCu,0xE6u,0xE5u, 0x63u,0xA4u,0x40u,0xF2u,
  0x77u,0x03u,0x7Du,0x81u, 0x2Du,0xEBu,0x33u,0xA0u, 
  0xF4u,0xA1u,0x39u,0x45u, 0xD8u,0x98u,0xC2u,0x96u,
  /* Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5 */
  0x4Fu,0xE3u,0x42u,0xE2u, 0xFEu,0x1Au,0x7Fu,0x9Bu, 
  0x8Eu,0xE7u,0xEBu,0x4Au, 0x7Cu,0x0Fu,0x9Eu,0x16u,
  0x2Bu,0xCEu,0x33u,0x57u, 0x6Bu,0x31u,0x5Eu,0xCEu, 
  0xCBu,0xB6u,0x40u,0x68u, 0x37u,0xBFu,0x51u,0xF5u
};

static const uint8_t pOrderN[BYTE_LEN_N] =
{ /* n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 */
  0xFFu,0xFFu,0xFFu,0xFFu, 0x00u,0x00u,0x00u,0x00u, 
  0xFFu,0xFFu,0xFFu,0xFFu, 0xFFu,0xFFu,0xFFu,0xFFu,
  0xBCu,0xE6u,0xFAu,0xADu, 0xA7u,0x17u,0x9Eu,0x84u, 
  0xF3u,0xB9u,0xCAu,0xC2u, 0xFCu,0x63u,0x25u,0x51u
};

/* Pre-computed point (2 ^ (byteLenN * 4)) * G, needed by mcuxClEcc_Verify */
static const uint8_t pPrecG[BYTE_LEN_P * 2u] =
{ /* x = 0x447D739BEEDB5E67FB982FD588C6766EFC35FF7DC297EAC357C84FC9D789BD85 */
  0x44u,0x7Du,0x73u,0x9Bu, 0xEEu,0xDBu,0x5Eu,0x67u, 
  0xFBu,0x98u,0x2Fu,0xD5u, 0x88u,0xC6u,0x76u,0x6Eu,
  0xFCu,0x35u,0xFFu,0x7Du, 0xC2u,0x97u,0xEAu,0xC3u, 
  0x57u,0xC8u,0x4Fu,0xC9u, 0xD7u,0x89u,0xBDu,0x85u,
  /* y = 0x2D4825AB834131EEE12E9D953A4AAFF73D349B95A7FAE5000C7E33C972E25B32 */
  0x2Du,0x48u,0x25u,0xABu, 0x83u,0x41u,0x31u,0xEEu, 
  0xE1u,0x2Eu,0x9Du,0x95u, 0x3Au,0x4Au,0xAFu,0xF7u,
  0x3Du,0x34u,0x9Bu,0x95u, 0xA7u,0xFAu,0xE5u,0x00u, 
  0x0Cu,0x7Eu,0x33u,0xC9u, 0x72u,0xE2u,0x5Bu,0x32u
};

static const uint8_t digest[] = 
{
  0xC4u, 0x93u, 0xCFu, 0x6Bu, 0xE5u, 0x11u, 0x35u, 0x22u,
  0x1Au, 0x3Fu, 0x5Cu, 0x7Bu, 0xCFu, 0xF4u, 0x6Du, 0xC6u,
  0x10u, 0x77u, 0x6Eu, 0x2Cu, 0x04u, 0xA3u, 0xB9u, 0x9Du,
  0x39u, 0x3Bu, 0x4Bu, 0xEEu, 0xD5u, 0xDDu, 0x88u, 0x86u,
};

/* The CPU workarea has to be large enough for all operations performed within
 * the session: RNG initialization, key generation, signature generation and
 * signature verification via the low level mcuxClEcc APIs. */
#define CPU_WA_BUFFER_SIZE MCUXCLCORE_MAX(MCUXCLECC_KEYGEN_WACPU_SIZE, \
                                 MCUXCLCORE_MAX(MCUXCLECC_SIGN_WACPU_SIZE, \
                                   MCUXCLCORE_MAX(MCUXCLECC_VERIFY_WACPU_SIZE, \
                                     MCUXCLCORE_MAX(MCUXCLRANDOMMODES_INIT_WACPU_SIZE, MCUXCLRANDOMMODES_NCINIT_WACPU_SIZE))))

/* The PKC workarea has to be large enough for key generation, signature
 * generation and signature verification on a 256 bit curve. */
#define PKC_WA_BUFFER_SIZE MCUXCLCORE_MAX(MCUXCLECC_KEYGEN_WAPKC_SIZE_256, \
                                 MCUXCLCORE_MAX(MCUXCLECC_SIGN_WAPKC_SIZE_256, MCUXCLECC_VERIFY_WAPKC_SIZE_256))

MCUXCLEXAMPLE_FUNCTION(mcuxClEcc_ECDSA_GeneratedKeys_NIST_P256_example)
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

  /* RNG initialized */
#if defined(MCUXCL_FEATURE_RANDOMMODES_SECSTRENGTH_256) && defined(MCUXCL_FEATURE_RANDOMMODES_CTRDRBG)
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(session, MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE, mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3);
#else
  MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(session, 0u, mcuxClRandomModes_Mode_ELS_Drbg);
#endif

  /* Initialize the InputBuffers for the NIST P-256 domain parameters */
  MCUXCLBUFFER_INIT_RO(buffA, NULL, pCoefficientA, BYTE_LEN_P);
  MCUXCLBUFFER_INIT_RO(buffB, NULL, pCoefficientB, BYTE_LEN_P);
  MCUXCLBUFFER_INIT_RO(buffP, NULL, pPrimeP,       BYTE_LEN_P);
  MCUXCLBUFFER_INIT_RO(buffG, NULL, pPointG,       BYTE_LEN_P * 2u);
  MCUXCLBUFFER_INIT_RO(buffN, NULL, pOrderN,       BYTE_LEN_N);

  /**************************************************************************/
  /* Key pair generation for ECDSA on NIST P-256                            */
  /**************************************************************************/

  ALIGNED uint8_t pPrivKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIVATEKEY];
  uint8_t pPubKeyData[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PUBLICKEY];

  mcuxClEcc_KeyGen_Param_t paramKeyGen;
  paramKeyGen.curveParam.pA = buffA;
  paramKeyGen.curveParam.pB = buffB;
  paramKeyGen.curveParam.pP = buffP;
  paramKeyGen.curveParam.pG = buffG;
  paramKeyGen.curveParam.pN = buffN;
  paramKeyGen.curveParam.misc = mcuxClEcc_DomainParam_misc_Pack(BYTE_LEN_N, BYTE_LEN_P);
  paramKeyGen.pPrivateKey = pPrivKeyData;
  paramKeyGen.pPublicKey = pPubKeyData;
  paramKeyGen.optLen = 0u;

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(gkp_status, gkp_token, mcuxClEcc_KeyGen(
      /* mcuxClSession_Handle_t pSession:               */ session,
      /* const mcuxClEcc_KeyGen_Param_t * pParam:       */ &paramKeyGen)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_KeyGen) != gkp_token) || (MCUXCLECC_STATUS_OK != gkp_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /**************************************************************************/
  /* ECDSA signature generation on NIST P-256                               */
  /**************************************************************************/

  uint8_t signature[MCUXCLECC_WEIERECC_NIST_P256_SIZE_SIGNATURE];
  MCUXCLBUFFER_INIT_RO(buffDigest, NULL, digest, sizeof(digest));
  MCUXCLBUFFER_INIT(buffSignature, NULL, signature, MCUXCLECC_WEIERECC_NIST_P256_SIZE_SIGNATURE);

  mcuxClEcc_Sign_Param_t paramSign;
  paramSign.curveParam.pA = buffA;
  paramSign.curveParam.pB = buffB;
  paramSign.curveParam.pP = buffP;
  paramSign.curveParam.pG = buffG;
  paramSign.curveParam.pN = buffN;
  paramSign.curveParam.misc = mcuxClEcc_DomainParam_misc_Pack(BYTE_LEN_N, BYTE_LEN_P);
  paramSign.pHash = buffDigest;
  paramSign.pPrivateKey = pPrivKeyData;
  paramSign.pSignature = buffSignature;
  paramSign.optLen = mcuxClEcc_Sign_Param_optLen_Pack(sizeof(digest));
  paramSign.pMode = &mcuxClEcc_ECDSA_ProtocolDescriptor;

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ss_status, ss_token, mcuxClEcc_Sign(
    /* mcuxClSession_Handle_t pSession:              */ session,
    /* const mcuxClEcc_Sign_Param_t * pParam:        */ &paramSign)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Sign) != ss_token) || (MCUXCLECC_STATUS_OK != ss_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();


  /**************************************************************************/
  /* ECDSA signature verification on NIST P-256                             */
  /**************************************************************************/

  uint8_t pOutputR[MCUXCLECC_WEIERECC_NIST_P256_SIZE_BASEPOINTORDER];
  MCUXCLBUFFER_INIT_RO(buffPrecG, NULL, pPrecG, BYTE_LEN_P * 2u);
  MCUXCLBUFFER_INIT_RO(buffSignatureIn, NULL, signature, MCUXCLECC_WEIERECC_NIST_P256_SIZE_SIGNATURE);
  MCUXCLBUFFER_INIT(buffOutputR, NULL, pOutputR, sizeof(pOutputR));

  mcuxClEcc_Verify_Param_t paramVerify;
  paramVerify.curveParam.pA = buffA;
  paramVerify.curveParam.pB = buffB;
  paramVerify.curveParam.pP = buffP;
  paramVerify.curveParam.pG = buffG;
  paramVerify.curveParam.pN = buffN;
  paramVerify.curveParam.misc = mcuxClEcc_DomainParam_misc_Pack(BYTE_LEN_N, BYTE_LEN_P);
  paramVerify.pPrecG = buffPrecG;
  paramVerify.pHash = buffDigest;
  paramVerify.pSignature = buffSignatureIn;
  paramVerify.pPublicKey = pPubKeyData;
  paramVerify.pOutputR = buffOutputR;
  paramVerify.optLen = mcuxClEcc_Verify_Param_optLen_Pack(sizeof(digest));

  MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(sv_status, sv_token, mcuxClEcc_Verify(
    /* mcuxClSession_Handle_t pSession:              */ session,
    /* const mcuxClEcc_Verify_Param_t * pParam:      */ &paramVerify)
  );

  if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Verify) != sv_token) || (MCUXCLECC_STATUS_OK != sv_status))
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  MCUX_CSSL_FP_FUNCTION_CALL_END();

  /* Clean ecc verify session. */
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
