/*--------------------------------------------------------------------------*/
/* Copyright 2021-2022 NXP                                                  */
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
 * @file  mcuxClMacModes_cmac_oneshot_internal_ckdf_key_example.c
 * @brief Example CMAC computation using functions of the mcuxClKey and mcuxClMac component
 *
 * @example mcuxClMac_cmac_oneshot_internal_ckdf_key_example.c
 * @brief   Example CMAC computation using functions of the mcuxClKey and mcuxClMac component
 */

#include <stdbool.h>  // bool type for the example's return code
#include <mcuxClCore_Examples.h> // Defines and assertions for examples

#include <mcuxClEls.h> // Interface to the entire mcuxClEls component
#include <mcuxClKey.h>
#include <mcuxClAes.h> // Interface to AES-related definitions and types
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClMac.h> // Interface to the entire mcuxClMac component
#include <mcuxClMacModes.h> // Interface to the entire mcuxClMacModes component
#include <mcuxClExample_ELS_Helper.h>
#include <mcuxClExample_ELS_Key_Helper.h>
#include <mcuxClExample_Key_Helper.h>
#include <mcuxClExample_Session_Helper.h>

/** Performs a CMAC computation using functions of the mcuxClKey component.
 * @retval MCUXCLEXAMPLE_OK         The example code completed successfully
 * @retval MCUXCLEXAMPLE_FAILURE    The example code failed */
bool mcuxClMacModes_cmac_oneshot_internal_ckdf_key_example(void)
{
    /* Example input size. */
    size_t cmac_input_size_16 = 32u;

    /* Example input to the CMAC function. */
    uint8_t cmac_input16_in[] = {
                                        0x1eu, 0xe0u, 0xecu, 0x46u,
                                        0x6du, 0x46u, 0xfdu, 0x84u,
                                        0x9bu, 0x40u, 0xc0u, 0x66u,
                                        0xb4u, 0xfbu, 0xbdu, 0x22u,
                                        0xa2u, 0x0au, 0x4du, 0x80u,
                                        0xa0u, 0x08u, 0xacu, 0x9au,
                                        0xf1u, 0x7eu, 0x4fu, 0xdfu,
                                        0xd1u, 0x06u, 0x78u, 0x5eu
    };

    uint8_t sw_drv_data[16] = {
         0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
    };


    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /** Initialize ELS, Enable the ELS **/
    if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        return MCUXCLEXAMPLE_FAILURE;
    }

    /* load ckdf key into key register 0 */
    mcuxClEls_KeyIndex_t         key_idx_ckdfk = 0u;
    mcuxClEls_KeyIndex_t         key_idx_cmack = 18u;
    mcuxClEls_KeyProp_t          key_properties;

    key_properties.word.value      = 0u;
    key_properties.bits.uckdf      = MCUXCLELS_KEYPROPERTY_CKDF_TRUE;
    key_properties.bits.ksize      = MCUXCLELS_KEYPROPERTY_KEY_SIZE_256;
    key_properties.bits.kactv      = MCUXCLELS_KEYPROPERTY_ACTIVE_TRUE;

    if(true != mcuxClExample_provision_key(key_idx_ckdfk, key_properties))
    {
        return MCUXCLEXAMPLE_FAILURE;
    }

    /* Output buffer for the computed MAC. */
    static uint8_t result_buffer[MCUXCLELS_CMAC_OUT_SIZE];

    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;
    //Allocate and initialize session
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLMAC_MAX_CPU_WA_BUFFER_SIZE, 0u);


    /**************************************************************************/
    /* Key setup                                                              */
    /**************************************************************************/

    /* Create and initialize mcuxClKey_Descriptor_t structure. */
    uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) &keyDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClKey_init(
        /* mcuxClSession_Handle_t pSession:                */  session,
        /* mcuxClKey_Handle_t key:                         */  key,
        /* mcuxClKey_Type type:                            */  mcuxClKey_Type_Aes128,
        /* mcuxCl_Buffer_t pKeyData:                       */  (mcuxCl_Buffer_t) sw_drv_data,
        /* uint32_t keyDataLength:                        */  sizeof(sw_drv_data)));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != token) || (MCUXCLKEY_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Create and initialize mcuxClKey_Descriptor_t structure for parent key. */
    uint32_t parentDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t parent = (mcuxClKey_Handle_t) &parentDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClKey_init(
        /* mcuxClSession_Handle_t pSession:                */  session,
        /* mcuxClKey_Handle_t key:                         */  parent,
        /* mcuxClKey_Type type:                            */  mcuxClKey_Type_Aes256,
        /* mcuxCl_Buffer_t pKeyData:                       */  NULL,
        /* uint32_t keyDataLength:                        */  0u));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != token) || (MCUXCLKEY_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Load parent key to ELS */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClKey_loadCopro(session,
                                                                      parent,
                                                                      key_idx_ckdfk));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_loadCopro) != token) || (MCUXCLKEY_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Set protection and parentKey */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClKey_setProtection(
        /* mcuxClSession_Handle_t pSession:               */  session,
        /* mcuxClKey_Handle_t key:                        */  key,
        /* mcuxClKey_Protection_t protection:             */  mcuxClKey_Protection_Ckdf,
        /* mcuxCl_Buffer_t pAuxData:                      */  NULL,
        /* mcuxClKey_Handle_t parentKey:                  */  parent));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_setProtection) != token) || (MCUXCLKEY_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Set key properties. */
    mcuxClEls_KeyProp_t cmac_key_properties;

    cmac_key_properties.word.value = 0u;
    cmac_key_properties.bits.ucmac = MCUXCLELS_KEYPROPERTY_CMAC_TRUE;
    cmac_key_properties.bits.ksize = MCUXCLELS_KEYPROPERTY_KEY_SIZE_128;
    cmac_key_properties.bits.kactv = MCUXCLELS_KEYPROPERTY_ACTIVE_TRUE;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClKey_setKeyproperties(key,
                                                                             &cmac_key_properties));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_setKeyproperties) != token) || (MCUXCLKEY_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /* Load key to ELS */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClKey_loadCopro(session,
          /* const mcuxClKey_Handle_t key:    */ key,
                                                                      key_idx_cmack));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_loadCopro) != token) || (MCUXCLKEY_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* MAC computation                                                        */
    /**************************************************************************/

    /* Call the mcuxClMac_compute function to compute a CMAC in one shot. */
    uint32_t result_size = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClMac_compute(
        /* mcuxClSession_Handle_t session:  */ session,
        /* const mcuxClKey_Handle_t key:    */ key,
        /* const mcuxClMac_Mode_t mode:     */ mcuxClMac_Mode_CMAC,
        /* mcuxCl_InputBuffer_t pIn:        */ cmac_input16_in,
        /* uint32_t inLength:              */ cmac_input_size_16,
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
    if(MCUXCLELS_CMAC_OUT_SIZE != result_size)
    {
        return MCUXCLEXAMPLE_FAILURE;
    }

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

    /** Destroy Session and cleanup Session **/
    if(!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_FAILURE;
    }

    /** deleted key_idx_ckdfk keySlot, clean-up ckdf key **/
    if(!mcuxClExample_Els_KeyDelete(key_idx_ckdfk))
    {
        return MCUXCLEXAMPLE_FAILURE;
    }

    /** Disable the ELS **/
    if(!mcuxClExample_Els_Disable())
    {
        return MCUXCLEXAMPLE_FAILURE;
    }

    return MCUXCLEXAMPLE_OK;
}
