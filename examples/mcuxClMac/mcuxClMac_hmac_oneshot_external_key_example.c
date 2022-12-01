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
/* Security Classification:  Company Confidential                           */
/*--------------------------------------------------------------------------*/


#include <stdbool.h>  // bool type for the example's return code
#include <mcuxClCore_Examples.h> // Defines and assertions for examples

#include <mcuxClCss.h> // Interface to the entire mcuxClCss component
#include <mcuxClKey.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection

#include <mcuxClMac.h>


/** Performs a HMAC computation using functions of the mcuxClKey component.
 * @retval MCUX_CL_EXAMPLE_OK         The example code completed successfully
 * @retval MCUX_CL_EXAMPLE_FAILURE    The example code failed */
bool mcuxClMac_hmac_oneshot_external_key_example(void)
{
    /* Example (unpadded) key. */
    const uint8_t hmac_key[] = {
        0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
        0x88u, 0x99u, 0xaau, 0xbbu, 0xccu, 0xddu, 0xeeu, 0xffu,
        0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
        0x88u, 0x99u, 0xaau, 0xbbu, 0xccu, 0xddu, 0xeeu, 0xffu
    };

    /* Example input to the HMAC function. */
    const uint8_t hmac_input[MCUXCLCSS_HASH_BLOCK_SIZE_SHA_256] = {
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
    const uint8_t hmac_output_reference[MCUXCLMAC_HMAC_OUTPUT_SIZE] = {
        0x06u, 0xb8u, 0xb8u, 0xc3u, 0x21u, 0x79u, 0x15u, 0xbeu,
        0x0bu, 0x0fu, 0x86u, 0x90u, 0x4fu, 0x76u, 0x74u, 0x1bu,
        0x1bu, 0xe2u, 0x86u, 0x79u, 0x38u, 0xf4u, 0xf0u, 0x5du,
        0x34u, 0x15u, 0xbbu, 0x36u, 0x8fu, 0x4au, 0x57u, 0xfbu
    };

    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /* Enable Css */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_Enable_Async()); // Enable the CSSv2.
    // mcuxClCss_Enable_Async is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Enable_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
    {
        return MCUX_CL_EXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_Enable_Async operation to complete.
    // mcuxClCss_WaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return MCUX_CL_EXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /* Key buffer for the key in memory. */
    uint32_t key_buffer[sizeof(hmac_key) / sizeof(uint32_t)];

    /* Output buffer for the computed MAC. */
    static uint8_t result_buffer[MCUXCLMAC_HMAC_OUTPUT_SIZE];

    /* Workarea. */
    uint32_t pWa[MCUXCLMAC_WA_SIZE_MAX / sizeof(uint32_t)];

    mcuxClSession_Descriptor_t session;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClSession_init(&session,
                                                                     pWa,
                                                                     MCUXCLMAC_WA_SIZE_MAX,
                                                                     NULL,
                                                                     NULL));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != token) || (MCUXCLSESSION_STATUS_OK != result))
    {
        return MCUX_CL_EXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /**************************************************************************/
    /* Key setup                                                              */
    /**************************************************************************/

    /* Create and initialize mcuxClKey_Descriptor_t structure. */
    uint32_t keyDesc[MCUX_CL_KEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) &keyDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClKey_init(
           /* mcuxClSession_Handle_t pSession:                */  &session,
           /* mcuxClKey_Handle_t key:                         */  key,
           /* const mcuxClKey_Type* type:                     */  mcuxClKey_Type_HmacSha256_variableLength,
           /* mcuxCl_Buffer_t pKeyData:                       */  (uint8_t *) hmac_key,
           /* uint32_t keyDataLength:                        */  sizeof(hmac_key)));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != token) || (MCUX_CL_KEY_STATUS_OK != result))
    {
        return MCUX_CL_EXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Load key to memory. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClKey_loadMemory(&session,
                                                                       key,
                                                                       key_buffer));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_loadMemory) != token) || (MCUX_CL_KEY_STATUS_OK != result))
    {
        return MCUX_CL_EXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* MAC computation                                                        */
    /**************************************************************************/
    /* Copy the input data to temp buffer with proper size */
    uint8_t tempIn [MCUXCLMAC_GET_HMAC_INPUTBUFFER_LENGTH(sizeof(hmac_input))];

    for(int i=0 ; i < MCUXCLCSS_HASH_BLOCK_SIZE_SHA_256; i++)
    {
       tempIn[i] =  hmac_input[i];
    }

    /* Call the mcuxClMac_compute function to compute a HMAC in one shot. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClMac_compute(&session,
                                                                    key,
                                                                    mcuxClMac_Mode_HMAC_SHA2_256_CSS,
                                                                    (uint8_t*) tempIn,
                                                                    sizeof(hmac_input),
                                                                    result_buffer));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_compute) != token) || (MCUXCLMAC_ERRORCODE_OK != result))
    {
        return MCUX_CL_EXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Verification                                                           */
    /**************************************************************************/

    /* Compare the result to the reference value. */
    if(!mcuxClCore_assertEqual(hmac_output_reference, result_buffer, sizeof(hmac_output_reference)))
    {
        return MCUX_CL_EXAMPLE_ERROR;
    }

    /**************************************************************************/
    /* Cleanup                                                                */
    /**************************************************************************/

    /* Flush the key. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClKey_flush(&session,
                                                                 key));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush) != token) || (MCUX_CL_KEY_STATUS_OK != result))
    {
        return MCUX_CL_EXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /* Clean-up and destroy the session. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(cleanup_result, cleanup_token, mcuxClSession_cleanup(
                /* mcuxClSession_Handle_t           pSession: */           &session));
    if(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != cleanup_token || MCUXCLSESSION_STATUS_OK != cleanup_result)
    {
        return MCUX_CL_EXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(destroy_result, destroy_token, mcuxClSession_destroy(
                /* mcuxClSession_Handle_t           pSession: */           &session));
    if(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != destroy_token || MCUXCLSESSION_STATUS_OK != destroy_result)
    {
        return MCUX_CL_EXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /* Disable Css */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_Disable()); // Disable the CSSv2.
    // mcuxClCss_Disable is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Disable) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return MCUX_CL_EXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    return MCUX_CL_EXAMPLE_OK;
}