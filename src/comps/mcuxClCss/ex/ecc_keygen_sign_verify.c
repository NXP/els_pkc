/*--------------------------------------------------------------------------*/
/* Copyright 2020-2022 NXP                                                  */
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
 * @file  ecc_keygen_sign_verify.c
 * @brief Example of ECC for key generation, signing and verification using the CSSv2 (CLNS component mcuxClCss)
 *
 * @example ecc_keygen_sign_verify.c
 * @brief   Example of ECC for key generation, signing and verification using the CSSv2 (CLNS component mcuxClCss)
 */

#include <mcuxClCss.h> // Interface to the entire mcuxClCss component
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <stdbool.h>  // bool type for the example's return code
#include <mcuxClExample_CSS_Helper.h>
#include <mcuxClExample_CSS_Key_Helper.h>


/** Pre-hashed data to be signed */
static uint32_t const ecc_digest[MCUXCLCSS_HASH_OUTPUT_SIZE_SHA_256 / sizeof(uint32_t)] = {0x11111111,
                                                                                           0x22222222,
                                                                                           0x33333333,
                                                                                           0x44444444,
                                                                                           0x55555555,
                                                                                           0x66666666,
                                                                                           0x77777777,
                                                                                           0x88888888};

/** Destination buffer to receive the public key of the mcuxClCss_EccKeyGen_Async operation. */
static uint32_t ecc_public_key[MCUXCLCSS_ECC_PUBLICKEY_SIZE / sizeof(uint32_t)];

/** Destination buffer to receive the signature of the mcuxClCss_EccSign_Async operation. */
static mcuxClCss_EccByte_t ecc_signature[MCUXCLCSS_ECC_SIGNATURE_SIZE];


/** Destination buffer to receive the signature part r of the VerifyOptions operation. */
static mcuxClCss_EccByte_t ecc_signature_r[MCUXCLCSS_ECC_SIGNATURE_R_SIZE];


/** Concatenation of the ECC signature and public key, needed for the mcuxClCss_EccVerify_Async operation. */
static mcuxClCss_EccByte_t ecc_signature_and_public_key[MCUXCLCSS_ECC_SIGNATURE_SIZE + MCUXCLCSS_ECC_PUBLICKEY_SIZE];


/**
 * Performs SHA2-256 hashing using mcuxClCss functions.
 * @retval true  The example code completed successfully
 * @retval false The example code failed */
bool ecc_keygen_sign_verify(void)
{
    /** Initialize CSS, Enable the CSSv2 **/
    if(!mcuxClExample_Css_Init(MCUXCLCSS_RESET_DO_NOT_CANCEL))
    {
        return false;
    }

    /* Generate signing key */
    mcuxClCss_EccKeyGenOption_t KeyGenOptions = {0};                      // Initialize a new configuration for the planned mcuxClCss_EccKeyGen_Async operation.
    KeyGenOptions.bits.kgsrc = MCUXCLCSS_ECC_OUTPUTKEY_RANDOM;            // Configure that a non-deterministic key is generated.
    KeyGenOptions.bits.kgsign = MCUXCLCSS_ECC_PUBLICKEY_SIGN_DISABLE;     // Configure that the generated public key is not signed
    KeyGenOptions.bits.kgsign_rnd = MCUXCLCSS_ECC_NO_RANDOM_DATA;         // Configure that no external random data is provided
    
    mcuxClCss_KeyProp_t GenKeyProp = {0};                                 // Initialize a new configuration for the mcuxClCss_EccKeyGen_Async generated key properties.
    GenKeyProp.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_FALSE; // Configure that user access rights: non-privileged access
    GenKeyProp.bits.upprot_sec = MCUXCLCSS_KEYPROPERTY_SECURE_TRUE;       // Configure that user access rights: non-secure access

    mcuxClCss_KeyIndex_t keyIdx = 10u;  // Set keystore index at which mcuxClCss_EccKeyGen_Async is storing the private key.

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_EccKeyGen_Async( // Perform key generation.
            KeyGenOptions,                                  // Set the prepared configuration.
            (mcuxClCss_KeyIndex_t) 0U,                       // This parameter (signingKeyIdx) is ignored, since no signature is requested in the configuration.
            keyIdx,                                         // Keystore index at which the generated private key is stored.
            GenKeyProp,                                     // Set the generated key properties.
            NULL,                                           // No random data is provided
            (uint8_t *) ecc_public_key                      // Output buffer, which the operation will write the public key to.
            ));
    // mcuxClCss_EccKeyGen_Async is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_EccKeyGen_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
    {
        return false; // Expect that no error occurred, meaning that the mcuxClCss_EccKeyGen_Async operation was started.
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_LimitedWaitForOperation(0x00100000U, MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_EccKeyGen_Async operation to complete.
    // mcuxClCss_LimitedWaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_LimitedWaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Sign message digest */
    mcuxClCss_EccSignOption_t SignOptions = {0}; // Initialize a new configuration for the planned mcuxClCss_EccSign_Async operation.

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_EccSign_Async(// Perform signature generation.
            SignOptions,                                                  // Set the prepared configuration.
            keyIdx,                                                       // Set index of private key in keystore.
            (const uint8_t *) ecc_digest, NULL, (size_t) 0U,              // Pre-hashed data to sign. Note that inputLength parameter is ignored since pre-hashed data has a fixed length.
            ecc_signature                                                 // Output buffer, which the operation will write the signature to.
            ));
    // mcuxClCss_EccSign_Async is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_EccSign_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
    {
        return false; // Expect that no error occurred, meaning that the mcuxClCss_EccSign_Async operation was started.
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_LimitedWaitForOperation(0x00100000U, MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_EccSign_Async operation to complete.
    // mcuxClCss_LimitedWaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_LimitedWaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Verify signature */
    /* Concatenate signature and public key to prepare input for EccVerify_Async */
    for(size_t i = 0u; i < MCUXCLCSS_ECC_SIGNATURE_SIZE; i++) {
        ecc_signature_and_public_key[i] = ecc_signature[i];
    }
    for(size_t i = 0u; i < MCUXCLCSS_ECC_PUBLICKEY_SIZE; i++) {
        ecc_signature_and_public_key[MCUXCLCSS_ECC_SIGNATURE_SIZE + i] = *((uint8_t *) ecc_public_key + i);
    }

    mcuxClCss_EccVerifyOption_t VerifyOptions = {0}; // Initialize a new configuration for the planned mcuxClCss_EccVerify_Async operation.

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_EccVerify_Async(// Perform signature verification.
            VerifyOptions,                                                  // Set the prepared configuration.
            (const uint8_t *) ecc_digest, NULL, (size_t) 0U,                // Pre-hashed data to verify. Note that inputLength parameter is ignored since pre-hashed data has a fixed length.
            ecc_signature_and_public_key,                                   // Concatenation of signature of the pre-hashed data and public key used
            ecc_signature_r                                                 // Output buffer, which the operation will write the signature part r to, to allow external comparison of between given and recalculated r.
            ));
    // mcuxClCss_EccVerify_Async is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_EccVerify_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
    {
        return false; // Expect that no error occurred, meaning that the mcuxClCss_EccVerify_Async operation was started.
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_LimitedWaitForOperation(0x00100000U, MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_EccVerify_Async operation to complete.
    // mcuxClCss_LimitedWaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_LimitedWaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    mcuxClCss_HwState_t state;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_GetHwState(&state));
    // mcuxClCss_GetHwState is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetHwState) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (MCUXCLCSS_STATUS_ECDSAVFY_OK != state.bits.ecdsavfy)
    {
        return false; // Expect that mcuxClCss_EccVerify_Async operation successfully performed the signature verification.
    }

    /** deleted keyIdx keySlot **/
    if(!mcuxClExample_CSS_KeyDelete(keyIdx))
    {
        return false;
    }

    /** Disable the CSSv2 **/
    if(!mcuxClExample_Css_Disable())
    {
        return false;
    }


    return true;
}
