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


#include <stdbool.h>  // bool type for the example's return code
#include <mcuxClCore_Examples.h> // Defines and assertions for examples

#include <mcuxClEls.h> // Interface to the entire mcuxClEls component
#include <mcuxClKey.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClMac.h> // Interface to the entire mcuxClMac component
#include <mcuxClMacModes.h> // Interface to the entire mcuxClMacModes component
#include <mcuxClExample_ELS_Helper.h>
#include <mcuxClExample_ELS_Key_Helper.h>
#include <mcuxClExample_Key_Helper.h>
#include <mcuxClExample_Session_Helper.h>


/** Performs a HMAC computation using functions of the mcuxClKey component.
 * @retval MCUXCLEXAMPLE_OK         The example code completed successfully
 * @retval MCUXCLEXAMPLE_FAILURE    The example code failed */
bool mcuxClMacModes_hmac_oneshot_internal_key_example(void)
{
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

    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /** Initialize ELS, Enable the ELS **/
    if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        return MCUXCLEXAMPLE_FAILURE;
    }

    /* load HMAC key into key register 6 */
    mcuxClEls_KeyIndex_t         key_idx_hmac = 6u;
    mcuxClEls_KeyProp_t          key_properties;

    key_properties.word.value = 0u;
    key_properties.bits.uhmac = MCUXCLELS_KEYPROPERTY_HMAC_TRUE;
    key_properties.bits.ksize = MCUXCLELS_KEYPROPERTY_KEY_SIZE_256;
    key_properties.bits.kactv = MCUXCLELS_KEYPROPERTY_ACTIVE_TRUE;

    if(true != mcuxClExample_provision_key(key_idx_hmac, key_properties))
    {
        return MCUXCLEXAMPLE_FAILURE;
    }

    /* Output buffer for the computed MAC. */
    static uint8_t result_buffer[MCUXCLMAC_HMAC_SHA_256_OUTPUT_SIZE];

    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;
    /* Allocate and initialize session / workarea */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLMAC_MAX_CPU_WA_BUFFER_SIZE, 0u);


    /**************************************************************************/
    /* Key setup                                                              */
    /**************************************************************************/

    /* Create and initialize mcuxClKey_Descriptor_t structure. */
    uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) &keyDesc;

    /* Initializes a key handle, sets key properties and loads key */
    if(!mcuxClExample_Key_Init_And_Load(session,
                                       key, mcuxClKey_Type_HmacSha256,
                                       NULL, 0u, /* not needed for internal keys */
                                       &key_properties,
                                       &key_idx_hmac, MCUXCLEXAMPLE_CONST_INTERNAL_KEY))
    {
        return MCUXCLEXAMPLE_FAILURE;
    }

    /**************************************************************************/
    /* MAC computation                                                        */
    /**************************************************************************/
    /* Copy the input data to temp buffer with proper size */
    uint8_t tempIn [MCUXCLMACMODES_GET_HMAC_INPUTBUFFER_LENGTH(sizeof(hmac_input))];

    for(int i=0 ; i < MCUXCLELS_HASH_BLOCK_SIZE_SHA_256; i++)
    {
       tempIn[i] =  hmac_input[i];
    }

    /* Call the mcuxClMac_compute function to compute a HMAC in one shot. */
    uint32_t result_size = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClMac_compute(
        /* mcuxClSession_Handle_t session:  */ session,
        /* const mcuxClKey_Handle_t key:    */ key,
        /* const mcuxClMac_Mode_t mode:     */ mcuxClMac_Mode_HMAC_SHA2_256_ELS,
        /* mcuxCl_InputBuffer_t pIn:        */ (uint8_t*) tempIn,
        /* uint32_t inLength:              */ sizeof(hmac_input),
        /* mcuxCl_Buffer_t pMac:            */ result_buffer,
        /* uint32_t * const pMacLength:    */ &result_size
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_compute) != token) || (MCUXCLMAC_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Verification                                                           */
    /**************************************************************************/

    /* Compare the output size with the expected MAC size */
    if(MCUXCLMAC_HMAC_SHA_256_OUTPUT_SIZE != result_size)
    {
        return MCUXCLEXAMPLE_FAILURE;
    }

    /* Verification of MAC result is not possible in this case, since the internal key differs based on platform. */

    /**************************************************************************/
    /* Cleanup                                                                */
    /**************************************************************************/

    /* Flush the key. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClKey_flush(session,
                                                                 key));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush) != token) || (MCUXCLKEY_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /* Clean-up and destroy the session. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(cleanup_result, cleanup_token, mcuxClSession_cleanup(
         /* mcuxClSession_Handle_t           pSession: */           session));
    if(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != cleanup_token || MCUXCLSESSION_STATUS_OK != cleanup_result)
    {
        return MCUXCLEXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(destroy_result, destroy_token, mcuxClSession_destroy(
         /* mcuxClSession_Handle_t           pSession: */           session));
    if(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != destroy_token || MCUXCLSESSION_STATUS_OK != destroy_result)
    {
        return MCUXCLEXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /* Disable ELS */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_Disable()); // Disable the ELS.
    // mcuxClEls_Disable is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Disable) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    return MCUXCLEXAMPLE_OK;
}
