/*--------------------------------------------------------------------------*/
/* Copyright 2020, 2022 NXP                                                 */
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
 * @file  ckdf_aes_128_ecb_encrypt.c
 * @brief Example CKDF key derivation using the ELS (CLNS component mcuxClEls)
 *
 * The example loads a key with CKDF property and uses it with the CKDF command to
 * create an AES key that is used subsequently in encryption and decrypton operations.
 * The value of the CKDF key is HW specific so the result cannot be compared to a reference.
 *
 * @example  ckdf_aes_128_ecb_encrypt.c
 * @brief    Example CKDF key derivation using the ELS (CLNS component mcuxClEls)
 */

#include <mcuxClEls.h> // Interface to the entire mcuxClEls component
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <stdbool.h>  // bool type for the example's return code
#include <mcuxClExample_ELS_Helper.h>
#include <mcuxClExample_ELS_Key_Helper.h>

#include <mcuxClEls_KeyManagement.h>

/** Plaintext input for the AES encryption. */
static const uint8_t aes128_input[MCUXCLELS_CIPHER_BLOCK_SIZE_AES]  = {
    0x6bu, 0xc1u, 0xbeu, 0xe2u, 0x2eu, 0x40u, 0x9fu, 0x96u, 
    0xe9u, 0x3du, 0x7eu, 0x11u, 0x73u, 0x93u, 0x17u, 0x2au
};
/** Derivation data for the CKDF operation */
static uint8_t ckdf_derivation_data[MCUXCLELS_CKDF_DERIVATIONDATA_SIZE] = {
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
};
/** Key provisioning input part 1 */
static const uint8_t keyprov_external_part1[32]  = {
    0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 
    0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 0x11u,
    0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 0x11u,
    0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 0x11u, 0x11u
};
/** Key provisioning input part 2 */
static const uint8_t keyprov_external_part2[36]  = {
    0x22u, 0x22u, 0x22u, 0x22u, 0x22u, 0x22u, 0x22u, 0x22u, 
    0x22u, 0x22u, 0x22u, 0x22u, 0x22u, 0x22u, 0x22u, 0x22u,
    0x22u, 0x22u, 0x22u, 0x22u, 0x22u, 0x22u, 0x22u, 0x22u, 
    0x22u, 0x22u, 0x22u, 0x22u, 0x22u, 0x22u, 0x22u, 0x22u,
    0x22u, 0x22u, 0x22u, 0x22u
};

/** Destination buffer to receive the ciphertext output of the AES encryption. */
static uint8_t aes128_output[MCUXCLELS_CIPHER_BLOCK_SIZE_AES];

/** Performs CKDF key derivation and AES ECB encryption using mcuxClEls functions.
 * @retval true  The example code completed successfully
 * @retval false The example code failed */
bool ckdf_aes_128_ecb_encrypt(void)
{
#ifdef MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV
  
    mcuxClEls_KeyIndex_t             key_idx_ckdf = 0u;
    mcuxClEls_KeyIndex_t             key_idx_aes  = 10u;

    mcuxClEls_KeyProp_t              key_properties;
    mcuxClEls_CipherOption_t         cipher_options;
    mcuxClEls_KeyProvisionOption_t   keyprov_options;

    mcuxClEls_Status_t            els_result;

    /* Step 0:
        Initializations
    */
    /** Initialize ELS, Enable the ELS **/
    if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        return false;
    }
    /*  Step 1:
        load CKDF into key register key_idx_ckdf
    */
    key_properties.word.value      = 0u;
    key_properties.bits.uckdf      = MCUXCLELS_KEYPROPERTY_CKDF_TRUE;
    key_properties.bits.wrpok      = MCUXCLELS_KEYPROPERTY_WRAP_TRUE;
    key_properties.bits.ksize      = MCUXCLELS_KEYPROPERTY_KEY_SIZE_256;
    key_properties.bits.kactv      = MCUXCLELS_KEYPROPERTY_ACTIVE_TRUE;
    key_properties.bits.upprot_sec = MCUXCLELS_KEYPROPERTY_SECURE_FALSE;

    keyprov_options.word.value     = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_KeyProvision_Async( // Load an initial key using the mcuxClEls_KeyProvision_Async command
        keyprov_options,
        keyprov_external_part1,
        keyprov_external_part2,
        sizeof(keyprov_external_part2),
        key_idx_ckdf,
        key_properties
    ));
    // mcuxClEls_KeyProvision_Async is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_KeyProvision_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        return false; // Expect that no error occurred, meaning that the mcuxClEls_KeyProvision_Async operation was started.
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClEls_KeyProvision_Async operation to complete.
    // mcuxClEls_WaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    
    /*  Step 2:
        Use CKDF to derive a key into key register key_idx_aes
    */
    key_properties.word.value      = 0u;
    key_properties.bits.uaes       = MCUXCLELS_KEYPROPERTY_AES_TRUE;
    key_properties.bits.wrpok      = MCUXCLELS_KEYPROPERTY_WRAP_TRUE;
    key_properties.bits.ksize      = MCUXCLELS_KEYPROPERTY_KEY_SIZE_128;
    key_properties.bits.kactv      = MCUXCLELS_KEYPROPERTY_ACTIVE_TRUE;
    key_properties.bits.upprot_sec = MCUXCLELS_KEYPROPERTY_SECURE_FALSE;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_Ckdf_Sp800108_Async( // Derive an AES key from the CKDF key
        key_idx_ckdf,
        key_idx_aes,
        key_properties,
        ckdf_derivation_data));
    // mcuxClEls_Ckdf_Sp800108_Async is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Ckdf_Sp800108_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        return false; // Expect that no error occurred, meaning that the mcuxClEls_Ckdf_Sp800108_Async operation was started.
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClEls_Ckdf_Sp800108_Async operation to complete.
    // mcuxClEls_WaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    
    /*  Step 3:
        Verify that the key can be used for performing an encryption
    */
    cipher_options.word.value  = 0u;
    cipher_options.bits.cphmde = MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_ECB;
    cipher_options.bits.dcrpt  = MCUXCLELS_CIPHER_ENCRYPT;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_Cipher_Async( // Use the derived AES key for performing an AES encryption
        cipher_options,
        key_idx_aes,
        NULL,
        (size_t) 0u,
        aes128_input,
        MCUXCLELS_CIPHER_BLOCK_SIZE_AES,
        NULL,
        aes128_output));
    // mcuxClEls_Cipher_Async is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cipher_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        return false; // Expect that no error occurred, meaning that the mcuxClEls_Cipher_Async operation was started.
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClEls_Cipher_Async operation to complete.
    // mcuxClEls_WaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /*  Step 4:
        Clean up
    */
    /** deleted key_idx_ckdf keySlot **/
    if(!mcuxClExample_Els_KeyDelete(key_idx_ckdf))
    {
        return false;
    }

    /** deleted key_idx_aes keySlot **/
    if(!mcuxClExample_Els_KeyDelete(key_idx_aes))
    {
        return false;
    }

    /** Disable the ELS **/
    if(!mcuxClExample_Els_Disable())
    {
        return false;
    }
 
#endif /* MCUXCL_FEATURE_ELS_KEY_MGMT_KEYPROV */    
    
    return true;
}
