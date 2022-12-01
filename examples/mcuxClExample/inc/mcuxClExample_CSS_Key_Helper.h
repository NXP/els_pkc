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

#ifndef MCUX_CL_EXAMPLE_CSS_KEY_HELPER_H_
#define MCUX_CL_EXAMPLE_CSS_KEY_HELPER_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>
#include <mcuxClSession.h>
#include <mcuxClCss.h>
#include <mcuxClExample_RFC3394_Helper.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

/**
 * Delete keyslot via mcuxClCss_KeyDelete_Async.
 * [in]  keyIdx: The index of the key to be deleted
 **/
static inline bool mcuxClExample_CSS_KeyDelete(mcuxClCss_KeyIndex_t keyIdx)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_KeyDelete_Async(keyIdx));
    // mcuxClCss_KeyDelete_Async is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyDelete_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
    {
        return false; // Expect that no error occurred, meaning that the mcuxClCss_KeyDelete_Async operation was started.
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_KeyDelete_Async operation to complete.
    // mcuxClCss_WaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    return true;
}

/**
 * Delete all keyslot via mcuxClCss_Reset_Async.
 **/
static inline bool mcuxClExample_CSS_KeyDeleteAll(void)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_Reset_Async(0U));
    // mcuxClCss_Reset_Async is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Reset_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_Reset_Async operation to complete.
    // mcuxClCss_WaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    return true;
}

#if defined(MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV) || defined(MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV_ROM)
/**
 * Function that loads a known key into the CSS key store via mcuxClCss_KeyProvision_Async.
 * [in]    targetKeyIdx:              The key index at which the key shall be loaded
 * [in]    targetKeyProperties:       The target properties of the key
 **/

static bool mcuxClExample_provision_key(
    mcuxClCss_KeyIndex_t targetKeyIdx,       ///< The key index at which the key shall be loaded
    mcuxClCss_KeyProp_t targetKeyProperties ///< The target properties of the key
)
{
    #ifdef  MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV_ROM
    uint8_t tester_share[MCUXCLCSS_KEYPROV_TESTERSHARE_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint8_t key_share_idx  = 0x00;
    #else
    uint8_t keyprov_external_part1[MCUXCLCSS_KEYPROV_KEY_PART_1_SIZE]  = {
        0x02, 0xed, 0x0c, 0xee, 0x10, 0x3d, 0x7b, 0x5a,
        0x74, 0xbf, 0x2e, 0xdf, 0x9f, 0x08, 0x68, 0xb6,
        0x4c, 0xba, 0xb9, 0xa2, 0xe9, 0xb5, 0x66, 0x05,
        0xc2, 0x87, 0xa7, 0xa9, 0x40, 0x6f, 0xe6, 0x29
    };
    uint8_t keyprov_external_part2[36]  = {
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22
    };
    #endif

    #ifdef MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV_ROM
    mcuxClCss_KeyProvisionOption_t key_provision_options;
    key_provision_options.word.value = 0U;
    key_provision_options.bits.noic = MCUXCLCSS_KEYPROV_NOIC_ENABLE;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ret_KeyProvisionRom, token_KeyProvisionRom, mcuxClCss_KeyProvisionRom_Async(
            key_provision_options,
            tester_share,
            key_share_idx,
            targetKeyIdx,
            targetKeyProperties
    ));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyProvisionRom_Async) != token_KeyProvisionRom) || (MCUXCLCSS_STATUS_OK_WAIT != ret_KeyProvisionRom))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ret_WaitForOperation, token_WaitForOperation, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token_WaitForOperation) || (MCUXCLCSS_STATUS_OK != ret_WaitForOperation))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    #else
    mcuxClCss_KeyProvisionOption_t options;
    options.word.value = 0;
    options.bits.noic  = 1;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ret_KeyProvision, token_KeyProvision, mcuxClCss_KeyProvision_Async(
            options,
            keyprov_external_part1,
            keyprov_external_part2,
            sizeof(keyprov_external_part2),
            targetKeyIdx,
            targetKeyProperties
    ));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyProvision_Async) != token_KeyProvision) || (MCUXCLCSS_STATUS_OK_WAIT != ret_KeyProvision))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ret_WaitForOperation, token_WaitForOperation, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token_WaitForOperation) || (MCUXCLCSS_STATUS_OK != ret_WaitForOperation))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    #endif /* MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV */
    return true;
}
#endif /*((MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV == 1) || (MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV_ROM == 1))*/

/*
 * Check only if the mcuxClCss_KeyDelete_Async is defined "because mcuxClCss_KeyProvision_Async will be always defined"
 * via CL library or via the TEST OS
 * Function that loads a known key into the CSS key store
 * [in]    helperKeyIdx:              The index of the helper key
 * [in]    targetKeyIdx:              The key index at which the target key shall be loaded
 * [in]    targetKeyProperties:       The target properties of the key
 * [in]    pKey:                      Pointer to the key to be loaded
*/
#define CSS_RFC_PADDING_LENGTH 16U

static bool mcuxClExample_load_css_key(
    mcuxClCss_KeyIndex_t helperKeyIdx,
    mcuxClCss_KeyIndex_t targetKeyIdx,
    mcuxClCss_KeyProp_t properties,
    const uint8_t* pKey
)
{
    size_t key_size = ((MCUXCLCSS_KEYPROPERTY_KEY_SIZE_256 == properties.bits.ksize) ? MCUXCLCSS_CIPHER_KEY_SIZE_AES_256 : MCUXCLCSS_CIPHER_KEY_SIZE_AES_128);
    uint8_t wrapped_key[MCUXCLCSS_CIPHER_KEY_SIZE_AES_256 + CSS_RFC_PADDING_LENGTH];

    /**
    * Step 0: check if a key is already loaded in wrapping_key_slot, if so skip the next step
    */
    mcuxClCss_KeyProp_t key_properties_targeted;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_GetKeyProperties(targetKeyIdx, &key_properties_targeted));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetKeyProperties) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    if (MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE == key_properties_targeted.bits.kactv)
    {
        return true;
    }

    /**
    * Step 1: load the AES helper key using mcuxClExample_provision_key into helperKeyIdx
    */
    mcuxClCss_KeyProp_t AesHelperKeyProp = {0};
    AesHelperKeyProp.bits.ksize = MCUXCLCSS_KEYPROPERTY_KEY_SIZE_256;
    AesHelperKeyProp.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_TRUE;
    AesHelperKeyProp.bits.upprot_sec = MCUXCLCSS_KEYPROPERTY_SECURE_TRUE;
    AesHelperKeyProp.bits.uaes = MCUXCLCSS_KEYPROPERTY_AES_TRUE;
    AesHelperKeyProp.bits.kactv = MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE;
    AesHelperKeyProp.bits.kbase = MCUXCLCSS_KEYPROPERTY_BASE_SLOT;

    if(true != mcuxClExample_provision_key(helperKeyIdx, AesHelperKeyProp))
    {
        return false;
    }

    /**
    * Step 2: wrap the incoming key into a buffer on the stack and load the rfc3394-wrapped key into the targetKeyIdx
    */
    mcuxClExample_rfc3394_wrap(pKey, key_size, NULL, helperKeyIdx, MCUXCLCSS_CIPHER_INTERNAL_KEY, MCUXCLCSS_CIPHER_KEY_SIZE_AES_256, wrapped_key, properties);

    /**
    * Step 3: delete the AES helper key from helperKeyIdx
    */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_KeyDelete_Async(helperKeyIdx));
    // mcuxClCss_KeyDelete_Async is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyDelete_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
    {
        return false; // Expect that no error occurred, meaning that the mcuxClCss_KeyDelete_Async operation was started.
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_KeyDelete_Async operation to complete.
    // mcuxClCss_WaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**
    * Step 4: import the kwk using mcuxClExample_provision_key into helperKeyIdx
    */
    mcuxClCss_KeyProp_t kwkHelperKeyProp = {0};
    kwkHelperKeyProp.bits.ukwk = MCUXCLCSS_KEYPROPERTY_KWK_TRUE;
    kwkHelperKeyProp.bits.ksize = MCUXCLCSS_KEYPROPERTY_KEY_SIZE_256;
    kwkHelperKeyProp.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_TRUE;
    kwkHelperKeyProp.bits.upprot_sec = MCUXCLCSS_KEYPROPERTY_SECURE_TRUE;
    kwkHelperKeyProp.bits.kactv = MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE;
    kwkHelperKeyProp.bits.kbase = MCUXCLCSS_KEYPROPERTY_BASE_SLOT;

    if(true != mcuxClExample_provision_key(helperKeyIdx, kwkHelperKeyProp))
    {
        return false;
    }

    mcuxClCss_KeyImportOption_t wrapped_key_options = {0};
    wrapped_key_options.bits.kfmt = MCUXCLCSS_KEYIMPORT_KFMT_RFC3394;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_KeyImport_Async(wrapped_key_options, wrapped_key, key_size + CSS_RFC_PADDING_LENGTH, helperKeyIdx, targetKeyIdx));
    // mcuxClCss_KeyImport_Async is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyImport_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
    {
        return false; // Expect that no error occurred, meaning that the mcuxClCss_KeyDelete_Async operation was started.
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_KeyDelete_Async operation to complete.
    // mcuxClCss_WaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**
    * Step 5: delete kwk from helperKeyIdx
    */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_KeyDelete_Async(helperKeyIdx));
    // mcuxClCss_KeyDelete_Async is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyDelete_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
    {
        return false; // Expect that no error occurred, meaning that the mcuxClCss_KeyDelete_Async operation was started.
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_KeyDelete_Async operation to complete.
    // mcuxClCss_WaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    return true;
}

#endif /* MCUX_CL_EXAMPLE_CSS_KEY_HELPER_H_ */
