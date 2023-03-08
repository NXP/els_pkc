/*--------------------------------------------------------------------------*/
/* Copyright 2023 NXP                                                       */
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

#include "common.h"

#include <mcuxClEls.h> // Interface to the entire mcuxClEls component
#include <mcuxClSession.h> // Interface to the entire mcuxClSession component
#include <mcuxClKey.h> // Interface to the entire mcuxClKey component
#include <mcuxClMac.h> // Interface to the entire mcuxClMac component
#include <mcuxClMacModes.h> // Interface to the entire mcuxClMacModes component
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <nxpClToolchain.h> // memory segment definitions
#include <stdbool.h>  // bool type for the example's return code
#include <mcuxClPsaDriver.h>
#include <mcuxClCore_Examples.h>

#define LIFETIME_INTERNAL PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_LOCATION_EXTERNAL_STORAGE)
#define LIFETIME_EXTERNAL PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_LOCATION_LOCAL_STORAGE)

bool mcuxClPsaDriver_hmac_oneshot_example(void)
{
    /* Example (unpadded) key. */
    const uint8_t hmac_key[] = {
        0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
        0x88u, 0x99u, 0xaau, 0xbbu, 0xccu, 0xddu, 0xeeu, 0xffu,
        0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
        0x88u, 0x99u, 0xaau, 0xbbu, 0xccu, 0xddu, 0xeeu, 0xffu
    };

    /* Example input to the HMAC function. */
    const uint8_t hmac_input[MCUXCLELS_HASH_BLOCK_SIZE_SHA_256] = {
        0x00u, 0x9fu, 0x5eu, 0x39u, 0x94u, 0x30u, 0x03u, 0x82u,
        0x50u, 0x72u, 0x1bu, 0xe1u, 0x79u, 0x65u, 0x35u, 0xffu,
        0x21u, 0xa6u, 0x09u, 0xfdu, 0xf9u, 0xf0u, 0xf6u, 0x12u,
        0x66u, 0xe3u, 0xafu, 0x75u, 0xd7u, 0x04u, 0x31u, 0x7du,
        0x55u, 0x06u, 0xf8u, 0x06u, 0x5cu, 0x48u, 0x72u, 0x18u,
        0xe9u, 0x9eu, 0xb4u, 0xc3u, 0xd4u, 0x54u, 0x6cu, 0x4du,
        0x60u, 0x70u, 0x16u, 0x90u, 0x11u, 0x38u, 0x73u, 0x9du,
        0xbdu, 0xf4u, 0x37u, 0xa5u, 0xe6u, 0xf5u, 0x02u, 0x1au
    };

    /* Example reference HMAC. */
    const uint8_t hmac_output_reference[MCUXCLMAC_HMAC_SHA_256_OUTPUT_SIZE] = {
        0x06u, 0xb8u, 0xb8u, 0xc3u, 0x21u, 0x79u, 0x15u, 0xbeu,
        0x0bu, 0x0fu, 0x86u, 0x90u, 0x4fu, 0x76u, 0x74u, 0x1bu,
        0x1bu, 0xe2u, 0x86u, 0x79u, 0x38u, 0xf4u, 0xf0u, 0x5du,
        0x34u, 0x15u, 0xbbu, 0x36u, 0x8fu, 0x4au, 0x57u, 0xfbu
    };


    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultEnable, token, mcuxClEls_Enable_Async()); // Enable the ELS.
    // mcuxClEls_Enable_Async is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Enable_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != resultEnable))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultWait, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClEls_Enable_Async operation to complete.
    // mcuxClEls_WaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != resultWait))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Set up PSA key attributes. */
    psa_key_attributes_t attributes = {
        .core = {                                  // Core attributes
            .type = PSA_KEY_TYPE_HMAC,             // Key is for HMAC operations
            .bits = 0U,                            // No key bits
            .lifetime = LIFETIME_EXTERNAL,         // Volatile (RAM), External Storage (plain) key
            .id = 0U,                              // ID zero
            .policy = {
                .usage = PSA_KEY_USAGE_SIGN_HASH,      // Key may be used for encryption
                .alg = PSA_ALG_HMAC(PSA_ALG_SHA_256),  // HMAC with SHA256 requested
                .alg2 = PSA_ALG_NONE
            },
            .flags = 0u
        },                          // No flags
        .domain_parameters = NULL,                 // No domain parameters
        .domain_parameters_size = 0u
    };

    /* Variable for the output length of the encryption operation */
    size_t output_length;

    /* Output buffer for the computed MAC. */
    uint8_t result_buffer[MCUXCLMAC_HMAC_SHA_256_OUTPUT_SIZE];

    /* Copy the input data to temp buffer with proper size */
    uint8_t tempIn [MCUXCLMACMODES_GET_HMAC_INPUTBUFFER_LENGTH(sizeof(hmac_input))];

    for(int i=0 ; i < MCUXCLELS_HASH_BLOCK_SIZE_SHA_256; i++)
    {
       tempIn[i] =  hmac_input[i];
    }


    /* Call the encryption operation */
    psa_status_t result = psa_driver_wrapper_mac_compute(
        &attributes,                             // const psa_key_attributes_t *attributes,
        hmac_key,                                // const uint8_t *key_buffer
        sizeof(hmac_key),                        // size_t key_buffer_size
        PSA_ALG_HMAC(PSA_ALG_SHA_256),           // psa_algorithm_t alg
        tempIn,                                  // const uint8_t *input
        sizeof(hmac_input),                      // size_t input_length
        result_buffer,                           // uint8_t *output
        MCUXCLMAC_HMAC_SHA_256_OUTPUT_SIZE,               // size_t output_size
        &output_length);                         // size_t *output_length

    /* Check the return value */
    if(PSA_SUCCESS != result)
    {
        return MCUXCLEXAMPLE_FAILURE;
    }

    /* Check the output length */
    if(sizeof(hmac_output_reference) != output_length)
    {
        return MCUXCLEXAMPLE_FAILURE;
    }

    /* Check the content */
    if(!mcuxClCore_assertEqual(hmac_output_reference, result_buffer, sizeof(hmac_output_reference)))
    {
        return MCUXCLEXAMPLE_ERROR;
    }

    /* Return */
    return MCUXCLEXAMPLE_OK;
}
