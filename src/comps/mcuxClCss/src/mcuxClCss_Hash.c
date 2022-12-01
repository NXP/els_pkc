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

/** @file  mcuxClCss_Hash.c
 *  @brief CSSv2 implementation for hashing.
 * This file implements the functions declared in mcuxClCss_Hash.h. */

#include <mcuxClCss_Hash.h>
#include <mcuxClMemory.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <stdbool.h>
#include <mcuxClCss.h>
#include <internal/mcuxClCss_Internal.h>
#include <internal/mcuxClMemory_Copy_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Hash_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Hash_Async(
    mcuxClCss_HashOption_t options,
    uint8_t const * pInput,
    size_t inputLength,
    uint8_t * pDigest)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Hash_Async);

    /* Length must not be zero and aligned with the block length */
    MCUXCLCSS_INPUT_PARAM_CHECK_PROTECTED(mcuxClCss_Hash_Async,
                               false
                               || ((MCUXCLCSS_HASH_MODE_SHA_224 == options.bits.hashmd) && (0u != (inputLength % MCUXCLCSS_HASH_BLOCK_SIZE_SHA_224)))
                               || ((MCUXCLCSS_HASH_MODE_SHA_256 == options.bits.hashmd) && (0u != (inputLength % MCUXCLCSS_HASH_BLOCK_SIZE_SHA_256)))
                               || ((MCUXCLCSS_HASH_RTF_UPDATE_ENABLE == options.bits.rtfupd) && (MCUXCLCSS_HASH_MODE_SHA_256 != options.bits.hashmd))
                               || ((MCUXCLCSS_HASH_RTF_UPDATE_ENABLE != options.bits.rtfupd) && (MCUXCLCSS_HASH_RTF_OUTPUT_ENABLE == options.bits.rtfoe))
                               || ((MCUXCLCSS_HASH_OUTPUT_ENABLE != options.bits.hashoe) && (MCUXCLCSS_HASH_RTF_OUTPUT_ENABLE == options.bits.rtfoe))
                               || ((MCUXCLCSS_HASH_MODE_SHA_384 == options.bits.hashmd) && (0u != (inputLength % MCUXCLCSS_HASH_BLOCK_SIZE_SHA_384)))
                               || ((MCUXCLCSS_HASH_MODE_SHA_512 == options.bits.hashmd) && (0u != (inputLength % MCUXCLCSS_HASH_BLOCK_SIZE_SHA_512)))
                               );

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Hash_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }
    
    mcuxClCss_setInput0(pInput, inputLength);
    mcuxClCss_setInput1_fixedSize(pDigest);
    mcuxClCss_setOutput_fixedSize(pDigest);
    mcuxClCss_startCommand(ID_CFG_CSS_CMD_HASH, options.word.value, CSS_CMD_BIG_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Hash_Async, MCUXCLCSS_STATUS_OK_WAIT);
}

