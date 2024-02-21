/*--------------------------------------------------------------------------*/
/* Copyright 2023-2024 NXP                                                  */
/*                                                                          */
/* NXP Confidential. This software is owned or controlled by NXP and may    */
/* only be used strictly in accordance with the applicable license terms.   */
/* By expressly accepting such terms or by downloading, installing,         */
/* activating and/or otherwise using the software, you are agreeing that    */
/* you have read, and that you agree to comply with and are bound by, such  */
/* license terms. If you do not agree to be bound by the applicable license */
/* terms, then you may not retain, install, activate or otherwise use the   */
/* software.                                                                */
/*--------------------------------------------------------------------------*/

/**
 * @file:   mcuxClOsccaSm2_Signature_SignVerify_FullFlow_example.c
 * @brief:  Example OSCCA SM2 signature, including prehash, signature generation and signature
 *          verification
 */

/******************************************************************************
 * Includes
 ******************************************************************************/
#include <mcuxClSession.h>
#include <mcuxClRandom.h>
#include <mcuxClKey.h>
#include <mcuxClHash.h>
#include <mcuxClOsccaSm2.h>
#include <mcuxClOsccaSm3.h>
#include <mcuxClSignature.h>
#include <mcuxClOsccaSm2_CommonParams.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClOscca_FunctionIdentifiers.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_ELS_Helper.h>
#include <mcuxClCore_Examples.h>
#if MCUXCL_FEATURE_RANDOMMODES_OSCCA_TRNG == 1
#include <mcuxClOsccaRandomModes.h>
#else
#include <mcuxClRandomModes.h>
#include <mcuxClMemory.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#endif

/******************************************************************************
 * Defines
 ******************************************************************************/
/**
 * @brief Maximum of the CPU workarea
 */
#define SIZE_WA_CPU  MCUXCLCORE_MAX(MCUXCLOSCCASM3_PROCESS_CPU_WA_BUFFER_SIZE_SM3,\
                     MCUXCLCORE_MAX(MCUXCLOSCCASM2_COMPUTE_PREHASH_SIZEOF_WA_CPU, \
                     MCUXCLCORE_MAX(MCUXCLOSCCASM2_SIGN_SIZEOF_WA_CPU(MCUXCLOSCCASM2_SM2P256_SIZE_BASEPOINTORDER),\
                                      MCUXCLOSCCASM2_VERIFY_SIZEOF_WA_CPU)))
/**
 * @def SIZE_WA_PKC
 * @brief Maximum of the pkc workarea
 */
#define SIZE_WA_PKC  MCUXCLCORE_MAX(MCUXCLOSCCASM2_COMPUTE_PREHASH_SIZEOF_WA_PKC,\
                     MCUXCLCORE_MAX(MCUXCLOSCCASM2_SIGN_SIZEOF_WA_PKC_256(),     \
                                      MCUXCLOSCCASM2_VERIFY_SIZEOF_WA_PKC_256()))

/******************************************************************************
 * External variables
 ******************************************************************************/
/* none */

/**
 * @def Message
 */
const uint8_t Message[] = {
    0x77U, 0x69U, 0x6fU, 0xbaU,  0xf3U, 0x6bU, 0x49U, 0xcdU,
    0x1cU, 0x0eU, 0x45U, 0x6aU,  0xd1U, 0x86U, 0x59U, 0xfeU,
    0xdeU, 0x3fU, 0xcbU, 0x0cU,  0xceU, 0x69U, 0xa1U, 0xccU,
    0x01U, 0xb4U, 0x5aU, 0x19U,  0xfeU, 0x58U, 0xdbU, 0x8aU,
    0x09U, 0x59U, 0xacU, 0xdeU,  0xf9U, 0x09U, 0x64U, 0x9dU,
    0x44U, 0xceU, 0x62U, 0xfcU,  0x5cU, 0x25U, 0xbeU, 0x01U,
    0x3eU, 0xe7U, 0x7fU, 0xe9U,  0x47U, 0xccU, 0x0fU, 0xc7U,
    0x4aU, 0x2dU, 0xecU, 0x6dU,  0xe1U, 0x0eU, 0x9fU, 0x8fU,
    0x00U, 0x5bU, 0xf2U, 0x26U,  0xd0U, 0x72U, 0x5eU, 0x13U,
    0xbaU, 0xe2U, 0xc3U, 0x05U,  0xc1U, 0x72U, 0x5cU, 0x9cU,
    0x16U, 0x66U, 0xf1U, 0xcfU,  0xe6U, 0xfdU, 0x4eU, 0x8bU,
    0x77U, 0x3eU, 0xf5U, 0x9cU,  0x73U, 0xf4U, 0x10U, 0xd1U,
    0x84U, 0xf8U, 0xa9U, 0x5bU,  0x20U, 0xaeU, 0x1dU, 0x77U,
    0xa7U, 0xd2U, 0xceU, 0x4dU,  0xabU, 0x75U, 0x19U, 0x17U,
    0x8eU, 0x42U, 0x88U, 0x85U,  0x53U, 0x06U, 0x48U, 0x60U,
    0xaeU, 0x70U, 0xddU, 0x6fU,  0x5dU, 0x15U, 0x14U, 0x97U};

/**
 * @def pIDentifier for preHash
 */
const uint8_t pIDentifier[] = {0x01, 0x02, 0x03, 0x04};

/******************************************************************************
 * Local variables
 ******************************************************************************/
/* none */

/******************************************************************************
 * Local and global function declarations
 ******************************************************************************/
/**
 * @brief:  Example OSCCA SM2 signature, including
 *          prehash, signature generation and signature verification
 *
 * @return
 *    - true if selected algorithm processed successfully
 *    - false if selected algorithm caused an error
 *
 * @pre
 *  none
 *
 * @post
 *   the mcuxClOsccaSm2_Signature_SignVerify_FullFlow_example function will be triggered
 *
 * @note
 *   none
 *
 * @warning
 *   none
 */
bool mcuxClOsccaSm2_Signature_SignVerify_FullFlow_example(void)
{
    /**************************************************************************/
    /* Preparation: RNG initialization, CPU and PKC workarea allocation       */
    /**************************************************************************/

    /* Initialize ELS, Enable the ELS */
    if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t session;
    /* Allocate and initialize session with pkcWA on the beginning of PKC RAM */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(&session, SIZE_WA_CPU, SIZE_WA_PKC);
#if MCUXCL_FEATURE_RANDOMMODES_OSCCA_TRNG == 1
    /* Initialize the RNG context */
    /* We need a context for OSCCA Rng. */
    uint32_t rngCtx[MCUXCLOSCCARANDOMMODES_OSCCARNG_CONTEXT_SIZE_IN_WORDS];
    mcuxClRandom_Context_t pRngCtx = (mcuxClRandom_Context_t)rngCtx;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomInit_result, randomInit_token, mcuxClRandom_init(&session,
                                                               pRngCtx,
                                                               mcuxClOsccaRandomModes_Mode_TRNG));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init) != randomInit_token) || (MCUXCLRANDOM_STATUS_OK != randomInit_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
#else
    /* Fill mode descriptor with the relevant data */
    uint32_t customModeDescBytes[(MCUXCLRANDOMMODES_PATCHMODE_DESCRIPTOR_SIZE + sizeof(uint32_t) - 1U)/sizeof(uint32_t)];
    mcuxClRandom_ModeDescriptor_t *mcuxClRandomModes_Mode_Custom = (mcuxClRandom_ModeDescriptor_t *) customModeDescBytes;

    /**************************************************************************/
    /* RANDOM Patch Mode creation                                             */
    /**************************************************************************/
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomPatch_result, randomPatch_token, mcuxClRandomModes_createPatchMode(mcuxClRandomModes_Mode_Custom,
                                        (mcuxClRandomModes_CustomGenerateAlgorithm_t)RNG_Patch_function,
                                        NULL,
                                        256U));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_createPatchMode) != randomPatch_token) || (MCUXCLRANDOM_STATUS_OK != randomPatch_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    /**************************************************************************/
    /* patch mode initialization                                              */
    /**************************************************************************/
    uint32_t* rngContextPatched = NULL;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomInit_result, randomInit_token, mcuxClRandom_init(&session, (mcuxClRandom_Context_t)rngContextPatched, mcuxClRandomModes_Mode_Custom));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init) != randomInit_token) || (MCUXCLRANDOM_STATUS_OK != randomInit_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
#endif

    /* Initialize the PRNG */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(prngInit_result, prngInit_token, mcuxClRandom_ncInit(&session));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != prngInit_token) || (MCUXCLRANDOM_STATUS_OK != prngInit_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /****************************************************************/
    /* Preparation: setup SM2 key                                   */
    /****************************************************************/
    /* Initialize SM2 private key */
    uint32_t privKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t privKey = (mcuxClKey_Handle_t) &privKeyDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_priv_result, ki_priv_token, mcuxClKey_init(
      /* mcuxClSession_Handle_t session         */ &session,
      /* mcuxClKey_Handle_t key                 */ privKey,
      /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_SM2P256_Std_Private,
      /* const uint8_t * pKeyData              */ pPrivateKey,
      /* uint32_t keyDataLength                */ sizeof(pPrivateKey)
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_priv_token) || (MCUXCLKEY_STATUS_OK != ki_priv_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Initialize SM2 public key */
    uint32_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t pubKey = (mcuxClKey_Handle_t) &pubKeyDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_pub_result, ki_pub_token, mcuxClKey_init(
      /* mcuxClSession_Handle_t session         */ &session,
      /* mcuxClKey_Handle_t key                 */ pubKey,
      /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_SM2P256_Std_Public,
      /* const uint8_t * pKeyData              */ pPublicKey,
      /* uint32_t keyDataLength                */ sizeof(pPublicKey)
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_pub_token) || (MCUXCLKEY_STATUS_OK != ki_pub_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /****************************************************************/
    /* Compute e = SM3_HASH(Za||M)                                  */
    /****************************************************************/
    uint8_t pPrehash[MCUXCLOSCCASM3_OUTPUT_SIZE_SM3];
    uint32_t prehashSize = 0;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(prehash_Ret, prehash_Token, mcuxClOsccaSm2_Signature_PreHash(
      /* mcuxClSession_Handle_t session:   */ &session,
      /* mcuxClKey_Handle_t key:           */ pubKey,
      /* mcuxCl_InputBuffer_t pIdentifier: */ pIDentifier,
      /* uint32_t identifierSize:         */ sizeof(pIDentifier),
      /* mcuxCl_Buffer_t pPrehash:         */ pPrehash,
      /* uint32_t * const prehashSize:    */ &prehashSize
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClOsccaSm2_Signature_PreHash) != prehash_Token) || (MCUXCLOSCCASM2_STATUS_OK != prehash_Ret))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    /****************************************************************/
    /* SM3 Message digest calculation                               */
    /****************************************************************/
    uint32_t context[MCUXCLOSCCASM3_CONTEXT_SIZE_IN_WORDS];
    mcuxClHash_Context_t pHashCtx = (mcuxClHash_Context_t) context;

    uint8_t pDigest_SM2[MCUXCLOSCCASM3_OUTPUT_SIZE_SM3];
    /* Create parameter structure for Hash component */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result1, token1, mcuxClHash_init(&session, (mcuxClHash_Context_t)pHashCtx, mcuxClOsccaSm3_Algorithm_Sm3));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_init) != token1) || (MCUXCLHASH_STATUS_OK != result1))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result2, token2, mcuxClHash_process(&session,(mcuxClHash_Context_t)pHashCtx, pPrehash, MCUXCLOSCCASM3_OUTPUT_SIZE_SM3));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process) != token2) || (MCUXCLHASH_STATUS_OK != result2))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result3, token3, mcuxClHash_process(&session,(mcuxClHash_Context_t)pHashCtx, Message, sizeof(Message)));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_process) != token3) || (MCUXCLHASH_STATUS_OK != result3))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    uint32_t pOutSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result4, token4, mcuxClHash_finish(&session, (mcuxClHash_Context_t)pHashCtx, pDigest_SM2, &pOutSize));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_finish) != token4) || (MCUXCLHASH_STATUS_OK != result4))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    /****************************************************************/
    /* OSCCA SM2 signature generation                               */
    /****************************************************************/
    uint8_t signature[MCUXCLOSCCASM2_SM2P256_SIZE_SIGNATURE];
    uint32_t signatureSize = 0;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(signRet, signToken, mcuxClSignature_sign(
      /* mcuxClSession_Handle_t session:   */ &session,
      /* mcuxClKey_Handle_t key:           */ privKey,
      /* mcuxClSignature_Mode_t mode:      */ mcuxClSignature_Mode_SM2,
      /* mcuxCl_InputBuffer_t pIn:         */ pDigest_SM2,
      /* uint32_t inSize:                 */ sizeof(pDigest_SM2),
      /* mcuxCl_Buffer_t pSignature:       */ signature,
      /* uint32_t * const pSignatureSize: */ &signatureSize
    ));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_sign) != signToken) || (MCUXCLSIGNATURE_STATUS_OK != signRet))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    /****************************************************************/
    /* OSCCA SM2 signature verification                             */
    /****************************************************************/
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(verifyRet, verifyToken, mcuxClSignature_verify(
      /* mcuxClSession_Handle_t session:  */ &session,
      /* mcuxClKey_Handle_t key:          */ pubKey,
      /* mcuxClSignature_Mode_t mode:     */ mcuxClSignature_Mode_SM2,
      /* mcuxCl_InputBuffer_t pIn:        */ pDigest_SM2,
      /* uint32_t inSize:                */ sizeof(pDigest_SM2),
      /* mcuxCl_InputBuffer_t pSignature: */ signature,
      /* uint32_t signatureSize:         */ signatureSize
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_verify) != verifyToken) || (MCUXCLSIGNATURE_STATUS_OK != verifyRet))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    /** Destroy Session and cleanup Session **/
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
