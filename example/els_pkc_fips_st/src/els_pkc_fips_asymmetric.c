/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "els_pkc_fips_asymmetric.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
 * @brief Execute RSA PKCSV1.5 sign.
 */
static bool rsa_sign(const uint8_t *modulus,
                     const uint32_t modulus_size,
                     const uint8_t *exponent,
                     const uint32_t exponent_size,
                     const uint8_t *message,
                     const uint32_t message_size,
                     const uint8_t *signature,
                     const uint32_t signature_size,
                     mcuxClRsa_SignVerifyMode_t *sha_mode)
{
    /* Create session handle to be used by mcuxClRsa_sign */
    mcuxClSession_Descriptor_t session_desc;
    mcuxClSession_Handle_t session = &session_desc;

    if (modulus_size == 256U)
    {
        MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLRSA_SIGN_PLAIN_PKCS1V15ENCODE_2048_WACPU_SIZE,
                                                      MCUXCLRSA_SIGN_PLAIN_2048_WAPKC_SIZE);
    }
    else
    {
        MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLRSA_SIGN_PLAIN_PKCS1V15ENCODE_3072_WACPU_SIZE,
                                                      MCUXCLRSA_SIGN_PLAIN_3072_WAPKC_SIZE);
    }

    /* Initialize the PRNG */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(prngInit_result, prngInit_token, mcuxClRandom_ncInit(session));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != prngInit_token) ||
        (MCUXCLRANDOM_STATUS_OK != prngInit_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Create key struct of type MCUXCLRSA_KEY_PRIVATEPLAIN */
    const mcuxClRsa_KeyEntry_t mod1 = {.pKeyEntryData = (uint8_t *)modulus, .keyEntryLength = modulus_size};

    const mcuxClRsa_KeyEntry_t exp1 = {.pKeyEntryData = (uint8_t *)exponent, .keyEntryLength = exponent_size};

    const mcuxClRsa_Key private_key = {.keytype = MCUXCLRSA_KEY_PRIVATEPLAIN,
                                       .pMod1   = (mcuxClRsa_KeyEntry_t *)&mod1,
                                       .pMod2   = NULL,
                                       .pQInv   = NULL,
                                       .pExp1   = (mcuxClRsa_KeyEntry_t *)&exp1,
                                       .pExp2   = NULL,
                                       .pExp3   = NULL};

    /**************************************************************************/
    /* RSA signature generation call                                          */
    /**************************************************************************/

    uint8_t signature_buffer[384U] = {0U};
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        sign_result, sign_token,
        mcuxClRsa_sign(session, &private_key, message, message_size, (mcuxClRsa_SignVerifyMode_t *)sha_mode, 0U,
                       MCUXCLRSA_OPTION_MESSAGE_PLAIN, signature_buffer));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_sign) != sign_token || MCUXCLRSA_STATUS_SIGN_OK != sign_result)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (!mcuxClCore_assertEqual(signature_buffer, signature, signature_size))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Session clean-up                                                       */
    /**************************************************************************/
    /** Destroy Session and cleanup Session **/
    if (!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}

/*!
 * @brief Execute RSA PKCSV1.5 verify.
 */
static bool rsa_verify(const uint8_t *modulus,
                       const uint32_t modulus_size,
                       const uint8_t *exponent,
                       const uint32_t exponent_size,
                       const uint8_t *message,
                       const uint32_t message_size,
                       const uint8_t *signature,
                       const uint32_t signature_size,
                       mcuxClRsa_SignVerifyMode_t *sha_mode,
                       uint8_t result)
{
    /* Create session handle to be used by verify */
    mcuxClSession_Descriptor_t session_desc;
    mcuxClSession_Handle_t session = &session_desc;

    if (modulus_size == 128U)
    {
        MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLRSA_VERIFY_PKCS1V15VERIFY_WACPU_SIZE,
                                                      MCUXCLRSA_VERIFY_1024_WAPKC_SIZE);
    }
    else if (modulus_size == 256U)
    {
        MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLRSA_VERIFY_PKCS1V15VERIFY_WACPU_SIZE,
                                                      MCUXCLRSA_VERIFY_2048_WAPKC_SIZE);
    }
    else
    {
        MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLRSA_VERIFY_PKCS1V15VERIFY_WACPU_SIZE,
                                                      MCUXCLRSA_VERIFY_3072_WAPKC_SIZE);
    }

    /* Initialize the PRNG */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(prngInit_result, prngInit_token, mcuxClRandom_ncInit(session));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != prngInit_token) ||
        (MCUXCLRANDOM_STATUS_OK != prngInit_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Create key struct of type MCUXCLRSA_KEY_PUBLIC */
    const mcuxClRsa_KeyEntry_t mod1 = {.pKeyEntryData = (uint8_t *)modulus, .keyEntryLength = modulus_size};

    const mcuxClRsa_KeyEntry_t exp1 = {.pKeyEntryData = (uint8_t *)exponent, .keyEntryLength = exponent_size};

    const mcuxClRsa_Key public_key = {.keytype = MCUXCLRSA_KEY_PUBLIC,
                                      .pMod1   = (mcuxClRsa_KeyEntry_t *)&mod1,
                                      .pMod2   = NULL,
                                      .pQInv   = NULL,
                                      .pExp1   = (mcuxClRsa_KeyEntry_t *)&exp1,
                                      .pExp2   = NULL,
                                      .pExp3   = NULL};

    /**************************************************************************/
    /* RSA signature verification call                                        */
    /**************************************************************************/
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        verify_result, verify_token,
        mcuxClRsa_verify(session, &public_key, message, message_size, (uint8_t *)signature,
                         (mcuxClRsa_SignVerifyMode_t *)sha_mode, 0U, MCUXCLRSA_OPTION_MESSAGE_PLAIN, NULL));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_verify) != verify_token || MCUXCLRSA_STATUS_VERIFY_OK != verify_result)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Session clean-up                                                       */
    /**************************************************************************/
    /** Destroy Session and cleanup Session **/
    if (!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}

bool execute_rsa_kat(void)
{
    return true;
}
