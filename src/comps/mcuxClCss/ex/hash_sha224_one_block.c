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
 * @file  hash_sha224_one_block.c
 * @brief Example of SHA2-224 hashing using the CSSv2 (CLNS component mcuxClCss)
 *
 * @example hash_sha224_one_block.c
 * @brief   Example of SHA2-224 hashing using the CSSv2 (CLNS component mcuxClCss)
 */

#include <mcuxClCss.h> // Interface to the entire mcuxClCss component
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <stdbool.h>  // bool type for the example's return code
#include <mcuxClExample_CSS_Helper.h>

/** Data input for SHA2-224 hashing. */
static uint8_t const sha224_padded_input[MCUXCLCSS_HASH_BLOCK_SIZE_SHA_224] = {0x61U, 0x62U, 0x63U, 0x80U,
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
                                                                              0x00U, 0x00U, 0x00U, 0x18U};

/** Expected hash value. */
static uint8_t sha224_reference_digest[MCUXCLCSS_HASH_OUTPUT_SIZE_SHA_224] = {0x23U, 0x09U, 0x7dU, 0x22U,
                                                                             0x34U, 0x05U, 0xd8U, 0x22U,
                                                                             0x86U, 0x42U, 0xa4U, 0x77U,
                                                                             0xbdU, 0xa2U, 0x55U, 0xb3U,
                                                                             0x2aU, 0xadU, 0xbcU, 0xe4U,
                                                                             0xbdU, 0xa0U, 0xb3U, 0xf7U,
                                                                             0xe3U, 0x6cU, 0x9dU, 0xa7U};

/** Destination buffer to receive the hash output of the SHA2-224 hashing. */
static uint8_t sha2_224_digest[MCUXCLCSS_HASH_STATE_SIZE_SHA_224]; // MCUXCLCSS_HASH_STATE_SIZE_SHA_224 has to be used as the mcuxClCss_Hash_Async do not perform the truncation of the hash state.


/** Performs SHA2-224 hashing using mcuxClCss functions.
 * @retval true  The example code completed successfully
 * @retval false The example code failed */
bool hash_sha224_one_block(
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
    hash_options.bits.hashmd = MCUXCLCSS_HASH_MODE_SHA_224;  // Configure the mcuxClCss_Hash_Async operation so that the Sha2-224 algorithm is used.

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_Hash_Async( // Perform the hashing.
            hash_options,                                               // Set the prepared configuration.
            sha224_padded_input, sizeof(sha224_padded_input),           // Set the data to be hashed. Note that this data's length is a multiple of the block length, so no padding is required
            sha2_224_digest                                             // Output buffer, which the operation will write the hash digest to.
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
    
    for (size_t i = 0; i < sizeof(sha224_reference_digest); i++)
    {
        if (sha2_224_digest[i] != sha224_reference_digest[i])
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
