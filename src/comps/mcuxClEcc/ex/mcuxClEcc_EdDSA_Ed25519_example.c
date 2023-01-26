/*--------------------------------------------------------------------------*/
/* Copyright 2022 NXP                                                       */
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
 * @file  mcuxClEcc_EdDSA_Ed25519_example.c
 * @brief Example for the mcuxClEcc component
 *
 * @example mcuxClEcc_EdDSA_Ed25519_example.c
 * @brief   Example for the mcuxClEcc component EdDsa related functions
 */

#include <mcuxClRandomModes.h>
#include <mcuxClEcc.h>
#include <mcuxClKey.h>
#include <mcuxClPkc_Types.h>
#include <mcuxClExample_ELS_Helper.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_RNG_Helper.h>

#define RAM_START_ADDRESS MCUXCLPKC_RAM_START_ADDRESS
#define MAX_CPUWA_SIZE MCUXCLECC_EDDSA_GENERATEKEYPAIR_ED25519_WACPU_SIZE //TODO: Max should be chosen
#define MAX_PKCWA_SIZE MCUXCLECC_EDDSA_GENERATEKEYPAIR_ED25519_WAPKC_SIZE //TODO: Max should be chosen

static uint8_t const input[] =     {0x11u, 0x11u, 0x11u, 0x11u,
                                    0x11u, 0x11u, 0x11u, 0x11u,
                                    0x11u, 0x11u, 0x11u, 0x11u,
                                    0x11u, 0x11u, 0x11u, 0x11u,
                                    0x11u, 0x11u, 0x11u, 0x11u,
                                    0x11u, 0x11u, 0x11u, 0x11u,
                                    0x11u, 0x11u, 0x11u, 0x11u,
                                    0x11u, 0x11u, 0x11u, 0x11u};

bool mcuxClEcc_EdDSA_Ed25519_example(void)
{
    /** Initialize ELS, Enable the ELS **/
    if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        return false;
    }

    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t session;
    //Allocate and initialize session with pkcWA on the beginning of PKC RAM
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(&session, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);

    /* Initialize the RNG context and Initialize the PRNG*/
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(&session, 0u, mcuxClRandomModes_Mode_ELS_Drbg)

    /* Prepare buffers for generated data */
    uint8_t privKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE];
    mcuxClKey_Handle_t privKeyHandler = (mcuxClKey_Handle_t) &privKeyDesc;
    uint8_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE];
    mcuxClKey_Handle_t pubKeyHandler = (mcuxClKey_Handle_t) &pubKeyDesc;
    uint8_t privKeyBuffer[MCUXCLECC_EDDSA_ED25519_SIZE_PRIVATEKEY]={0};
    uint8_t pubKeyBuffer[MCUXCLECC_EDDSA_ED25519_SIZE_PUBLICKEY]={0};
    uint32_t privKeySize = 0u;
    uint32_t pubKeySize = 0u;


    /* Call Ecc_TwEd_EdDsaKeyGen */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(keygen_result, keygen_token, mcuxClEcc_EdDSA_GenerateKeyPair(
    /*  mcuxClSession_Handle_t pSession  */ &session,
    /*  mcuxClKey_Type_t type            */ mcuxClKey_Type_EdDSA_Ed25519_Priv,
    /*  mcuxClKey_Protection_t protection*/ mcuxClKey_Protection_None,
    /*  const mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_t * */ &mcuxClEcc_EdDsa_GeneratePrivKeyDescriptor,
    /*  mcuxClKey_Handle_t privKey       */ privKeyHandler,
    /*  uint8_t *pPrivData              */ privKeyBuffer,
    /*  uint32_t *const pPrivDataLength */ &privKeySize,
    /*  mcuxClKey_Handle_t pubKey        */ pubKeyHandler,
    /*  uint8_t *pPubData               */ pubKeyBuffer,
    /*  uint32_t *const pPubDataLength  */ &pubKeySize
                                    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_GenerateKeyPair) != keygen_token) || (MCUXCLECC_STATUS_OK != keygen_result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    uint8_t pSignature[MCUXCLECC_EDDSA_ED25519_SIGNATURE_SIZE];
    uint32_t signatureSize = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(sign_result, sign_token, mcuxClEcc_EdDSA_GenerateSignature(
    /* mcuxClSession_Handle_t pSession  */ &session,
    /* mcuxClKey_Handle_t key           */ privKeyHandler,
    /* const mcuxClEcc_EdDSA_SignatureProtocolDescriptor_t * */ &mcuxClEcc_EdDsa_PureEdDsaProtocolDescriptor,
    /* const uint8_t *pIn              */ input,
    /* uint32_t inSize                 */ sizeof(input),
    /* uint8_t *pSignature             */ pSignature,
    /* uint32_t * const pSignatureSize */ &signatureSize
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_GenerateSignature) != sign_token) || (MCUXCLECC_STATUS_OK != sign_result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(verify_result, verify_token, mcuxClEcc_EdDSA_VerifySignature(
    /* mcuxClSession_Handle_t pSession */ &session,
    /* mcuxClKey_Handle_t key          */ pubKeyHandler,
    /* const mcuxClEcc_EdDSA_SignatureProtocolDescriptor_t * */ &mcuxClEcc_EdDsa_PureEdDsaProtocolDescriptor,
    /* const uint8_t *pIn             */ input,
    /* uint32_t inSize                */ sizeof(input),
    /* const uint8_t *pSignature      */ pSignature,
    /* uint32_t signatureSize         */ signatureSize
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_VerifySignature) != verify_token) || (MCUXCLECC_STATUS_OK != verify_result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /** Destroy Session and cleanup Session **/
    if(!mcuxClExample_Session_Clean(&session))
    {
        return false;
    }

    /** Disable the ELS **/
    if(!mcuxClExample_Els_Disable())
    {
        return false;
    }

    return true;
}
