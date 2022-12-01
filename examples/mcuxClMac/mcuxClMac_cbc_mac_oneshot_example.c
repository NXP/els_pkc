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
/* Security Classification:  Company Confidential                           */
/*--------------------------------------------------------------------------*/


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
bool mcuxClMac_cbc_mac_oneshot_example(void)
{
    /* Example AES-128 key. */
    static uint8_t aes128_key[MCUX_CL_AES_AES128_KEY_SIZE] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
    };

    /* Example input size. */
    size_t cmac_input_size_16 = 32u;

    /* Example input to the CMAC function. */
    static uint8_t cmac_input16_in[] = {
        0xddu, 0xddu, 0xddu, 0xddu, 0xddu, 0xddu, 0xddu, 0xddu,
        0xddu, 0xddu, 0xddu, 0xddu, 0xddu, 0xddu, 0xddu, 0xddu,
        0xddu, 0xddu, 0xddu, 0xddu, 0xddu, 0xddu, 0xddu, 0xddu,
        0xddu, 0xddu, 0xddu, 0xddu, 0xddu, 0xddu, 0xddu, 0xddu
    };

    /* Example reference CMAC. */
    static uint8_t cmac_output_reference16[MCUXCLCSS_CMAC_OUT_SIZE] = {
        0x55u, 0xffu, 0x3du, 0x8cu, 0xa5u, 0xc7u, 0x4eu, 0x8fu,
        0x75u, 0x4du, 0x57u, 0xabu, 0xfau, 0xb4u, 0x76u, 0x97u
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
        return MCUX_CL_EXAMPLE_ERROR;
    }

    /**************************************************************************/
    /* MAC computation                                                        */
    /**************************************************************************/

    /* Call the mcuxClMac_compute function to compute a CMAC in one shot. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClMac_compute(&session,
                                                                    key,
                                                                    mcuxClMac_Mode_CBCMAC_NoPadding,
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
            return MCUX_CL_EXAMPLE_FAILURE;
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
        return MCUX_CL_EXAMPLE_ERROR;
    }

    return MCUX_CL_EXAMPLE_OK;
}
