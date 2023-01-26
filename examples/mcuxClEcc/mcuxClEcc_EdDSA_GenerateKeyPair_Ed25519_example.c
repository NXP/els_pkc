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
 * @file  mcuxClEcc_EdDSA_GenerateKeyPair_Ed25519_example.c
 * @brief Example for the mcuxClEcc component
 *
 * @example mcuxClEcc_EdDSA_GenerateKeyPair_Ed25519_example.c
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
#define MAX_CPUWA_SIZE MCUXCLECC_EDDSA_GENERATEKEYPAIR_ED25519_WACPU_SIZE
#define MAX_PKCWA_SIZE MCUXCLECC_EDDSA_GENERATEKEYPAIR_ED25519_WAPKC_SIZE


static const uint8_t pRefPubKey[MCUXCLECC_EDDSA_ED25519_SIZE_PUBLICKEY] __attribute__ ((aligned (4))) =
{
    0xecu, 0x17u, 0x2bu, 0x93u, 0xadu, 0x5eu, 0x56u, 0x3bu,
    0xf4u, 0x93u, 0x2cu, 0x70u, 0xe1u, 0x24u, 0x50u, 0x34u,
    0xc3u, 0x54u, 0x67u, 0xefu, 0x2eu, 0xfdu, 0x4du, 0x64u,
    0xebu, 0xf8u, 0x19u, 0x68u, 0x34u, 0x67u, 0xe2u, 0xbfu
};

bool mcuxClEcc_EdDSA_GenerateKeyPair_Ed25519_example(void)
{
    /** Initialize ELS, Enable the ELS **/
    if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        return false;
    }

    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t session;

    /* Allocate and initialize PKC workarea st the beginning of PKC RAM */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(&session, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);

    /* Initialize the RNG context and Initialize the PRNG */
    // TODO: Use AES-256 DRBG (CLNS-6508)
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(&session, 0u, mcuxClRandomModes_Mode_ELS_Drbg)

    /* Prepare buffers for generated data */
    uint8_t privKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE];
    mcuxClKey_Handle_t privKeyHandler = (mcuxClKey_Handle_t) &privKeyDesc;
    uint8_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE];
    mcuxClKey_Handle_t pubKeyHandler = (mcuxClKey_Handle_t) &pubKeyDesc;
    uint8_t privKeyBuffer[3u * MCUXCLECC_EDDSA_ED25519_SIZE_PRIVATEKEY + MCUXCLECC_EDDSA_ED25519_SIZE_PUBLICKEY] = {
        0x83u, 0x3fu, 0xe6u, 0x24u, 0x09u, 0x23u, 0x7bu, 0x9du,
        0x62u, 0xecu, 0x77u, 0x58u, 0x75u, 0x20u, 0x91u, 0x1eu,
        0x9au, 0x75u, 0x9cu, 0xecu, 0x1du, 0x19u, 0x75u, 0x5bu,
        0x7du, 0xa9u, 0x01u, 0xb9u, 0x6du, 0xcau, 0x3du, 0x42u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
    };
    uint8_t pubKeyBuffer[MCUXCLECC_EDDSA_ED25519_SIZE_PUBLICKEY] = {0};
    uint32_t privKeySize = 0u;
    uint32_t pubKeySize = 0u;


    /* Call Ecc_TwEd_EdDsaKeyGen */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(keygen_result, keygen_token, mcuxClEcc_EdDSA_GenerateKeyPair(
    /*  mcuxClSession_Handle_t pSession  */ &session,
    /*  mcuxClKey_Type_t type            */ mcuxClKey_Type_EdDSA_Ed25519_Priv,
    /*  mcuxClKey_Protection_t protection*/ mcuxClKey_Protection_None,
    /*  const mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_t * */ &mcuxClEcc_EdDsa_InputPrivKeyDescriptor,
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

    /* Compare the generated public key to the reference. */
    for(size_t i = 0u; i < MCUXCLECC_EDDSA_ED25519_SIZE_PRIVATEKEY; i++)
    {
        if(pubKeyBuffer[i] != pRefPubKey[i])
        {
            return false;
        }
    }

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
