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
 * @file  mcuxClMac_cmac_oneshot_example.c
 * @brief Example CMAC computation using functions of the mcuxClKey and mcuxClMac component
 *
 * @example mcuxClMac_cmac_oneshot_example.c
 * @brief   Example CMAC computation using functions of the mcuxClKey and mcuxClMac component
 */

#include <stdbool.h>  // bool type for the example's return code
#include <mcuxClCore_Examples.h> // Defines and assertions for examples

#include <mcuxClCss.h> // Interface to the entire mcuxClCss component
#include <mcuxClKey.h>
#include <mcuxClAes.h> // Interface to AES-related definitions and types
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection

#include <mcuxClMac.h>

#include <mcuxClExample_CSS_Helper.h>
#include <mcuxClExample_Key_Helper.h>
#include <mcuxClExample_Session_Helper.h>

/** Performs a CMAC computation using functions of the mcuxClKey component.
 * @retval MCUX_CL_EXAMPLE_OK         The example code completed successfully
 * @retval MCUX_CL_EXAMPLE_FAILURE    The example code failed */
bool mcuxClMac_cmac_oneshot_example(void)
{
    /* Example AES-128 key. */
    static uint8_t aes128_key[MCUX_CL_AES_AES128_KEY_SIZE] = {
                                        0x7c, 0x0b, 0x7d, 0xb9,
                                        0x81, 0x1f, 0x10, 0xd0,
                                        0x0e, 0x47, 0x6c, 0x7a,
                                        0x0d, 0x92, 0xf6, 0xe0
    };

    /* Example input size. */
    size_t cmac_input_size_16 = 32u;

    /* Example input to the CMAC function. */
    static uint8_t cmac_input16_in[] = {
                                        0x1eu, 0xe0u, 0xecu, 0x46u,
                                        0x6du, 0x46u, 0xfdu, 0x84u,
                                        0x9bu, 0x40u, 0xc0u, 0x66u,
                                        0xb4u, 0xfbu, 0xbdu, 0x22u,
                                        0xa2u, 0x0au, 0x4du, 0x80u,
                                        0xa0u, 0x08u, 0xacu, 0x9au,
                                        0xf1u, 0x7eu, 0x4fu, 0xdfu,
                                        0xd1u, 0x06u, 0x78u, 0x5eu
    };

    /* Example reference CMAC. */
    static uint8_t cmac_output_reference16[MCUXCLCSS_CMAC_OUT_SIZE] = {
                                        0xbau, 0xecu, 0xdcu, 0x91u,
                                        0xe9u, 0xa1u, 0xfcu, 0x35u,
                                        0x72u, 0xadu, 0xf1u, 0xe4u,
                                        0x23u, 0x2au, 0xe2u, 0x85u
    };
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/
    /** Initialize CSS, Enable the CSSv2 **/
    if(!mcuxClExample_Css_Init(MCUXCLCSS_RESET_DO_NOT_CANCEL))
    {
        return MCUX_CL_EXAMPLE_FAILURE;
    }


    /* Key buffer for the key in memory. */
    uint32_t key_buffer[MCUX_CL_AES_AES128_KEY_SIZE_IN_WORDS];

    /* Output buffer for the computed MAC. */
    static uint8_t result_buffer[MCUXCLCSS_CMAC_OUT_SIZE];

    mcuxClSession_Descriptor_t session;
    //Allocate and initialize session
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(&session, MCUXCLMAC_WA_SIZE_MAX, 0u);


    /**************************************************************************/
    /* Key setup                                                              */
    /**************************************************************************/

    /* Create and initialize mcuxClKey_Descriptor_t structure. */
    uint32_t keyDesc[MCUX_CL_KEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) &keyDesc;

    /* Set key properties. */
    mcuxClCss_KeyProp_t cmac_key_properties;

    cmac_key_properties.word.value = 0u;
    cmac_key_properties.bits.ucmac = MCUXCLCSS_KEYPROPERTY_CMAC_TRUE;
    cmac_key_properties.bits.ksize = MCUXCLCSS_KEYPROPERTY_KEY_SIZE_128;
    cmac_key_properties.bits.kactv = MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE;

    //Initializes a key handle, Set key properties and Load key.
    if(!mcuxClExample_Key_Init_And_Load(&session,
                                       key,
                                       mcuxClKey_Type_Aes128,
                                       (mcuxCl_Buffer_t) aes128_key,
                                       sizeof(aes128_key),
                                       &cmac_key_properties,
                                       key_buffer, MCUXCLEXAMPLE_CONST_EXTERNAL_KEY))
    {
        return MCUX_CL_EXAMPLE_FAILURE;
    }

    /**************************************************************************/
    /* MAC computation                                                        */
    /**************************************************************************/

    /* Call the mcuxClMac_compute function to compute a CMAC in one shot. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClMac_compute(&session,
                                                                    key,
                                                                    mcuxClMac_Mode_CMAC,
                                                                    (uint8_t*)cmac_input16_in,
                                                                    cmac_input_size_16,
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
    if(!mcuxClCore_assertEqual(cmac_output_reference16, result_buffer, sizeof(cmac_output_reference16)))
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

    /** Destroy Session and cleanup Session **/
    if(!mcuxClExample_Session_Clean(&session))
    {
        return MCUX_CL_EXAMPLE_FAILURE;
    }

    /** Disable the CSSv2 **/
    if(!mcuxClExample_Css_Disable())
    {
        return MCUX_CL_EXAMPLE_FAILURE;
    }


    return MCUX_CL_EXAMPLE_OK;
}
