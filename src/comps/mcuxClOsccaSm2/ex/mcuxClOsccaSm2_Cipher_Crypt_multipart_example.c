/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
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
 * @file:   mcuxClOsccaSm2_Cipher_Crypt_multipart_example.c
 * @brief:  Example OSCCA SM2 Cipher, include encryption and decryption
 */

/******************************************************************************
 * Includes
 ******************************************************************************/
#include <mcuxClSession.h>
#include <mcuxClRandom.h>
#include <mcuxClKey.h>
#include <mcuxClOsccaSm2.h>
#include <mcuxClOsccaSm3.h>
#include <mcuxClCipher.h>
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
 * Global variables
 ******************************************************************************/
/**
 * @def: BYTELENGTH_MSHORT_PART1
 * @brief: Length of first part of second message in bytes
 */
#define BYTELENGTH_MSHORT_PART1 (32U)
/**
 * @def: BYTELENGTH_MSHORT_PART2
 * @brief: Length of second part of second message in bytes
 */
#define BYTELENGTH_MSHORT_PART2 (15U)

/**
 * @def: BYTELENGTH_M
 * @brief: Length of message in bytes
 */
#define BYTELENGTH_M  (BYTELENGTH_MSHORT_PART2 + BYTELENGTH_MSHORT_PART1)

/**
 * @def pShortMessage_SM2
 * @brief Test vector: 47-byte message to be encrypted and decrypted in parts
 */
const uint8_t pShortMessage_SM2[BYTELENGTH_MSHORT_PART1 + BYTELENGTH_MSHORT_PART2] =
{
    0x77u, 0x69u, 0x6fu, 0xbau,  0xf3u, 0x6bu, 0x49u, 0xcdu,
    0x1cu, 0x0eu, 0x45u, 0x6au,  0xd1u, 0x86u, 0x59u, 0xfeu,
    0xdeu, 0x3fu, 0xcbu, 0x0cu,  0xceu, 0x69u, 0xa1u, 0xccu,
    0x01u, 0xb4u, 0x5au, 0x19u,  0xfeu, 0x58u, 0xdbu, 0x8au,
           0x89u, 0xCAu, 0x9Cu,  0x7Du, 0x58u, 0x08u, 0x73u,
    0x07u, 0xCAu, 0x93u, 0x09u,  0x2Du, 0x65u, 0x1Eu, 0xFAu
};

/******************************************************************************
 * Local variables
 ******************************************************************************/
/* none */

/******************************************************************************
 * Local and global function declarations
 ******************************************************************************/

/**
 * @brief:  Example OSCCA SM2 Cipher, including
 *          Encryption and Decryption
 *
 * @return
 *    - true if selected algorithm processed successfully
 *    - false if selected algorithm caused an error
 *
 * @pre
 *  none
 *
 * @post
 *   the mcuxClOsccaSm2_Cipher_Crypt_multipart_example function will be triggered
 *
 * @note
 *   none
 *
 * @warning
 *   none
 */
bool mcuxClOsccaSm2_Cipher_Crypt_multipart_example(void)
{
    /** Initialize ELS, MCUXCLELS_RESET_DO_NOT_CANCEL **/
    if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    /**************************************************************************/
    /* Preparation: RNG initialization, CPU and PKC workarea allocation       */
    /**************************************************************************/
    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t session;
    //Allocate and initialize session with pkcWA on the beginning of PKC RAM
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(&session, MCUXCLOSCCASM2_CIPHER_ENCDEC_SIZEOF_WA_CPU(MCUXCLOSCCASM2_SM2P256_SIZE_PRIMEP),
                                                           MCUXCLOSCCASM2_CIPHER_ENCDEC_SIZEOF_WA_PKC(MCUXCLOSCCASM2_SM2P256_SIZE_PRIMEP, MCUXCLOSCCASM2_SM2P256_SIZE_BASEPOINTORDER));
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
    /* OSCCA SM2 Encryption                                         */
    /****************************************************************/
    /* Create a buffer for the context */
    uint32_t ctxEncBuf[MCUXCLOSSCASM2_CIPHER_CRYPT_CONTEXT_SIZE/sizeof(uint32_t)];
    mcuxClCipher_Context_t * const pEncCtx = (mcuxClCipher_Context_t *) ctxEncBuf;

    /* Declare message buffer and size. */
    uint8_t msg_enc[BYTELENGTH_M + 2U * MCUXCLOSCCASM2_SM2P256_SIZE_PRIMEP + 1U + MCUXCLOSCCASM3_OUTPUT_SIZE_SM3];
    uint32_t msg_enc_size = 0u;

    /**************************************************************************/
    /* Init                                                                   */
    /**************************************************************************/

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(encInitRet, encInitToken, mcuxClCipher_init(
    /* mcuxClSession_Handle_t session,          */ &session,
    /* mcuxClCipher_Context_t * const pContext, */ pEncCtx,
    /* mcuxClKey_Handle_t key,                  */ pubKey,
    /* mcuxClCipher_Mode_t mode,                */ mcuxClCipher_Mode_SM2_ENC,
    /* const uint8_t * const pIv,              */ NULL,
    /* uint32_t ivLength,                      */ 0
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_init) != encInitToken) || (MCUXCLCIPHER_STATUS_OK != encInitRet))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /**************************************************************************/
    /* Process                                                                */
    /**************************************************************************/
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(encProRet, encProToken, mcuxClCipher_process(
    /* mcuxClSession_Handle_t session,         */ &session,
    /* mcuxClCipher_Context_t * const pContext */ pEncCtx,
    /* const uint8_t * const pIn,             */ pShortMessage_SM2,
    /* uint32_t inLength,                     */ BYTELENGTH_MSHORT_PART1,
    /* uint8_t * const pOut,                  */ msg_enc,
    /* uint32_t * const pOutLength            */ &msg_enc_size
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_process) != encProToken) || (MCUXCLCIPHER_STATUS_OK != encProRet))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(encProRet3, encProToken3, mcuxClCipher_process(
    /* mcuxClSession_Handle_t session,         */ &session,
    /* mcuxClCipher_Context_t * const pContext */ pEncCtx,
    /* const uint8_t * const pIn,             */ pShortMessage_SM2+BYTELENGTH_MSHORT_PART1,
    /* uint32_t inLength,                     */ BYTELENGTH_MSHORT_PART2,
    /* uint8_t * const pOut,                  */ &msg_enc[msg_enc_size],
    /* uint32_t * const pOutLength            */ &msg_enc_size
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_process) != encProToken3) || (MCUXCLCIPHER_STATUS_OK != encProRet3))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Finish                                                                 */
    /**************************************************************************/

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(encFinRet, encFinToken, mcuxClCipher_finish(
    /* mcuxClSession_Handle_t session,         */ &session,
    /* mcuxClCipher_Context_t * const pContext */ pEncCtx,
    /* uint8_t * const pOut,                  */ &msg_enc[msg_enc_size],
    /* uint32_t * const pOutLength            */ &msg_enc_size
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_finish) != encFinToken) || (MCUXCLCIPHER_STATUS_OK != encFinRet))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /****************************************************************/
    /* OSCCA SM2 Decryption                                         */
    /****************************************************************/
    /* Create a buffer for the context */
    uint32_t ctxDecBuf[MCUXCLOSSCASM2_CIPHER_CRYPT_CONTEXT_SIZE/sizeof(uint32_t)];
    mcuxClCipher_Context_t * const pDecCtx = (mcuxClCipher_Context_t *) ctxDecBuf;

    /* Declare message buffer and size. */
    uint8_t msg_dec[BYTELENGTH_MSHORT_PART1+BYTELENGTH_MSHORT_PART2];
    uint32_t msg_dec_size = 0u;

    /**************************************************************************/
    /* Init                                                                   */
    /**************************************************************************/

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(decInitRet, decInitToken, mcuxClCipher_init(
    /* mcuxClSession_Handle_t session,          */ &session,
    /* mcuxClCipher_Context_t * const pContext, */ pDecCtx,
    /* mcuxClKey_Handle_t key,                  */ privKey,
    /* mcuxClCipher_Mode_t mode,                */ mcuxClCipher_Mode_SM2_DEC,
    /* const uint8_t * const pIv,              */ NULL,
    /* uint32_t ivLength,                      */ 0
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_init) != decInitToken) || (MCUXCLCIPHER_STATUS_OK != decInitRet))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Process                                                                */
    /**************************************************************************/
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(decProRet, decProToken, mcuxClCipher_process(
    /* mcuxClSession_Handle_t session,         */ &session,
    /* mcuxClCipher_Context_t * const pContext */ pDecCtx,
    /* const uint8_t * const pIn,             */ msg_enc,
    /* uint32_t inLength,                     */ 1U,
    /* uint8_t * const pOut,                  */ &msg_dec[msg_dec_size],
    /* uint32_t * const pOutLength            */ &msg_dec_size
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_process) != decProToken) || (MCUXCLCIPHER_STATUS_OK != decProRet))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(decProRet2, decProToken2, mcuxClCipher_process(
    /* mcuxClSession_Handle_t session,         */ &session,
    /* mcuxClCipher_Context_t * const pContext */ pDecCtx,
    /* const uint8_t * const pIn,             */ &msg_enc[1U],
    /* uint32_t inLength,                     */ 2U * MCUXCLOSCCASM2_SM2P256_SIZE_PRIMEP + MCUXCLOSCCASM3_OUTPUT_SIZE_SM3,
    /* uint8_t * const pOut,                  */ &msg_dec[msg_dec_size],
    /* uint32_t * const pOutLength            */ &msg_dec_size
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_process) != decProToken2) || (MCUXCLCIPHER_STATUS_OK != decProRet2))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(decProRet3, decProToken3, mcuxClCipher_process(
    /* mcuxClSession_Handle_t session,         */ &session,
    /* mcuxClCipher_Context_t * const pContext */ pDecCtx,
    /* const uint8_t * const pIn,             */ &msg_enc[2U * MCUXCLOSCCASM2_SM2P256_SIZE_PRIMEP + 1U + MCUXCLOSCCASM3_OUTPUT_SIZE_SM3],
    /* uint32_t inLength,                     */ BYTELENGTH_MSHORT_PART1,
    /* uint8_t * const pOut,                  */ &msg_dec[msg_dec_size],
    /* uint32_t * const pOutLength            */ &msg_dec_size
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_process) != decProToken3) || (MCUXCLCIPHER_STATUS_OK != decProRet3))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(decProRet4, decProToken4, mcuxClCipher_process(
    /* mcuxClSession_Handle_t session,         */ &session,
    /* mcuxClCipher_Context_t * const pContext */ pDecCtx,
    /* const uint8_t * const pIn,             */ &msg_enc[2U * MCUXCLOSCCASM2_SM2P256_SIZE_PRIMEP + 1U + MCUXCLOSCCASM3_OUTPUT_SIZE_SM3 + msg_dec_size],
    /* uint32_t inLength,                     */ BYTELENGTH_MSHORT_PART2,
    /* uint8_t * const pOut,                  */ &msg_dec[msg_dec_size],
    /* uint32_t * const pOutLength            */ &msg_dec_size
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_process) != decProToken4) || (MCUXCLCIPHER_STATUS_OK != decProRet4))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Finish                                                                 */
    /**************************************************************************/

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(decFinRet, decFinToken, mcuxClCipher_finish(
    /* mcuxClSession_Handle_t session,         */ &session,
    /* mcuxClCipher_Context_t * const pContext */ pDecCtx,
    /* uint8_t * const pOut,                  */ &msg_dec[msg_dec_size],
    /* uint32_t * const pOutLength            */ &msg_dec_size
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_finish) != decFinToken) || (MCUXCLCIPHER_STATUS_OK != decFinRet))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Verification                                                           */
    /**************************************************************************/
    if (!mcuxClCore_assertEqual(pShortMessage_SM2, msg_dec, BYTELENGTH_MSHORT_PART1+BYTELENGTH_MSHORT_PART2))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Destroy the current session                                            */
    /**************************************************************************/

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
