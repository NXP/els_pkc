/*--------------------------------------------------------------------------*/
/* Copyright 2020-2022 NXP                                                  */
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

/** @file  mcuxClKey_Protection.c
 *  @brief Implementation of the Key protection functions that are supported
 *  by component. */

#include <mcuxClCss.h>
#include <mcuxClKey.h>
#include <mcuxClMemory.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <internal/mcuxClKey_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_protect_fct_none)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_protect_fct_none(mcuxClKey_Handle_t key)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClKey_protect_fct_none);

    if(MCUX_CL_KEY_LOADSTATUS_MEMORY == mcuxClKey_getLoadStatus(key))
    {
        // copy key source to destination memory buffer
        uint32_t len = mcuxClKey_getSize(key);

        MCUX_CSSL_FP_FUNCTION_CALL(resultLen, mcuxClMemory_copy(mcuxClKey_getLoadedKeyData(key),
                                                              mcuxClKey_getKeyData(key),
                                                              len, len));
        if (0U != resultLen)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_protect_fct_none, MCUX_CL_KEY_STATUS_ERROR);
        }

        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_protect_fct_none, MCUX_CL_KEY_STATUS_OK, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy));
    }
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_protect_fct_none, MCUX_CL_KEY_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_protect_fct_ckdf)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_protect_fct_ckdf(mcuxClKey_Handle_t key)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClKey_protect_fct_ckdf, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Ckdf_Sp800108_Async));

    if(NULL == key->container.parentKey)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_protect_fct_ckdf, MCUX_CL_KEY_STATUS_ERROR);
    }

    mcuxClCss_KeyIndex_t key_idx_sk     = (mcuxClCss_KeyIndex_t) mcuxClKey_getLoadedKeySlot(mcuxClKey_getParentKey(key));
    mcuxClCss_KeyIndex_t key_idx_mack   = (mcuxClCss_KeyIndex_t) mcuxClKey_getLoadedKeySlot(key);
    /* MISRA Ex. 9 - Needed to correctly reinterpret the auxilary data */
    mcuxClCss_KeyProp_t  key_properties = *((mcuxClCss_KeyProp_t*) mcuxClKey_getAuxData(key));

    MCUX_CSSL_FP_FUNCTION_CALL(resultCkdf, mcuxClCss_Ckdf_Sp800108_Async(
                                 key_idx_sk,
                                 key_idx_mack,
                                 key_properties,
                                 mcuxClKey_getKeyData(key)
    ));
    // mcuxClCss_Ckdf_Async is a flow-protected function: Check the protection token and the return value
    if (MCUXCLCSS_STATUS_OK_WAIT != resultCkdf)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_protect_fct_ckdf, MCUX_CL_KEY_STATUS_ERROR); // Expect that no error occurred, meaning that the mcuxClCss_Ckdf_Async operation was started.
    }

    MCUX_CSSL_FP_FUNCTION_CALL(resultWait, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

    if (MCUXCLCSS_STATUS_OK != resultWait)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_protect_fct_ckdf, MCUX_CL_KEY_STATUS_ERROR, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_protect_fct_ckdf, MCUX_CL_KEY_STATUS_OK, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));
}

const mcuxClKey_ProtectionDescriptor_t mcuxClKey_ProtectionDescriptor_None = {&mcuxClKey_protect_fct_none,
                                                                            NULL,
                                                                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_protect_fct_none),
                                                                            0u};

const mcuxClKey_ProtectionDescriptor_t mcuxClKey_ProtectionDescriptor_Ckdf = {&mcuxClKey_protect_fct_ckdf,
                                                                            NULL,
                                                                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_protect_fct_ckdf),
                                                                            0u};

