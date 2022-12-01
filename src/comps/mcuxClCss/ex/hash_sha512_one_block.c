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
 * @file  hash_sha512_one_block.c
 * @brief Example of SHA2-512 hashing using the CSSv2 (CLNS component mcuxClCss)
 *
 * @example hash_sha512_one_block.c
 * @brief   Example of SHA2-512 hashing using the CSSv2 (CLNS component mcuxClCss)
 */

#include <mcuxClCss.h> // Interface to the entire mcuxClCss component
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <stdbool.h>  // bool type for the example's return code
#include <mcuxClExample_CSS_Helper.h>

/** Data input for SHA2-512 hashing. */
static uint8_t const sha512_padded_input[MCUXCLCSS_HASH_BLOCK_SIZE_SHA_512] = {0x61U, 0x62U, 0x63U, 0x80U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00u, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00u, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x18U};

/** Expected hash value. */
static uint8_t sha512_reference_digest[MCUXCLCSS_HASH_OUTPUT_SIZE_SHA_512] = {0xddU, 0xafU, 0x35U, 0xa1U,
                                                                             0x93U, 0x61U, 0x7aU, 0xbaU,
                                                                             0xccU, 0x41U, 0x73U, 0x49U,
                                                                             0xaeU, 0x20U, 0x41U, 0x31U,
                                                                             0x12U, 0xe6U, 0xfaU, 0x4eU,
                                                                             0x89U, 0xa9U, 0x7eU, 0xa2U,
                                                                             0x0aU, 0x9eU, 0xeeU, 0xe6U,
                                                                             0x4bU, 0x55U, 0xd3U, 0x9aU,
                                                                             0x21U, 0x92U, 0x99U, 0x2aU,
                                                                             0x27U, 0x4fU, 0xc1U, 0xa8U,
                                                                             0x36U, 0xbaU, 0x3cU, 0x23U,
                                                                             0xa3U, 0xfeU, 0xebU, 0xbdU,
                                                                             0x45U, 0x4dU, 0x44U, 0x23U,
                                                                             0x64U, 0x3cU, 0xe8U, 0x0eU,
                                                                             0x2aU, 0x9aU, 0xc9U, 0x4fU,
                                                                             0xa5U, 0x4cU, 0xa4U, 0x9fU};

/** Destination buffer to receive the hash output of the SHA2-512 hashing. */
static uint8_t sha2_512_digest[MCUXCLCSS_HASH_STATE_SIZE_SHA_512]; // MCUXCLCSS_HASH_STATE_SIZE_SHA_512 has to be used as the mcuxClCss_Hash_Async do not perform the truncation of the hash state.


/** Performs SHA2-512 hashing using mcuxClCss functions.
 * @retval true  The example code completed successfully
 * @retval false The example code failed */
bool hash_sha512_one_block(
    void)
{
    /** Initialize CSS, Enable the CSSv2 **/
    if(!mcuxClExample_Css_Init(MCUXCLCSS_RESET_DO_NOT_CANCEL))
    {
        return false;
    }
    
    mcuxClCss_HashOption_t hash_options = {0U};              // Initialize a new configuration for the planned mcuxClCss_Hash_Async operation.
    hash_options.bits.hashini = MCUXCLCSS_HASH_INIT_ENABLE;  // Configure that the mcuxClCss_Hash_Async operation shall initialized with the standard IV (Initialization Vector).
    hash_options.bits.hashoe = MCUXCLCSS_HASH_OUTPUT_ENABLE; // Configure the mcuxClCss_Hash_Async operation so that the hash digest is moved into memory at the end of the operation.
    hash_options.bits.hashmd = MCUXCLCSS_HASH_MODE_SHA_512;  // Configure the mcuxClCss_Hash_Async operation so that the Sha2-512 algorithm is used.

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_Hash_Async( // Perform the hashing.
            hash_options,                                               // Set the prepared configuration.
            sha512_padded_input, sizeof(sha512_padded_input),           // Set the data to be hashed. Note that this data's length is a multiple of the block length, so no padding is required
            sha2_512_digest                                             // Output buffer, which the operation will write the hash digest to.
            ));
    // mcuxClCss_Hash_Async is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Hash_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
    {
        return false; // Expect that no error occurred, meaning that the mcuxClCss_Hash_Async operation was started.
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_Hash_Async operation to complete.
    // mcuxClCss_WaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    
    for (size_t i = 0; i < sizeof(sha512_reference_digest); i++)
    {
        if (sha2_512_digest[i] != sha512_reference_digest[i])
        {
           return false; // Expect that the resulting hash digest matches our expected output
        }
    }
    
    /** Disable the CSSv2 **/
    if(!mcuxClExample_Css_Disable())
    {
        return false;
    }
    
    return true;
}
