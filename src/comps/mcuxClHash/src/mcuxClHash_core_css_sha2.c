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

#include <mcuxClHash.h>
#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClHash_Core_css_sha2.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCss.h>
#include <internal/mcuxClCss_Internal.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHash_css_core_sha2)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHash_css_core_sha2(
                        uint32_t options,
                        mcuxCl_InputBuffer_t pIn,
                        uint32_t inSize,
                        mcuxCl_Buffer_t pOut)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHash_css_core_sha2,
                               MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Hash_Async),
                               MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));

    mcuxClCss_HashOption_t hash_options;
    hash_options.word.value = options;

    MCUX_CSSL_FP_FUNCTION_CALL(result_hash, mcuxClCss_Hash_Async(hash_options,
                                                               pIn,
                                                               inSize,
                                                               pOut));

    if (MCUXCLCSS_STATUS_OK_WAIT != result_hash)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_core_sha2, MCUXCLHASH_FAILURE);
    }

    MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

    if (MCUXCLCSS_STATUS_OK != result)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_core_sha2, MCUXCLHASH_FAILURE);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_core_sha2, MCUXCLHASH_STATUS_OK);
}

