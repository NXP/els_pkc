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

/** @file  mcuxClCss_Cmac.c
 *  @brief CSSv2 implementation for CMAC support.
 * This file implements the functions declared in mcuxClCss_Cmac.h. */

#include <platform_specific_headers.h>
#include <mcuxClCss_Cmac.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <stdbool.h>
#include <mcuxClCss.h>
#include <internal/mcuxClCss_Internal.h>

#define MCUXCLCSS_CMAC_STATE_IN_DISABLE     0U ///< Set #mcuxClCss_CmacOption_t.sie to this value to use the CMAC state that is present inside CSS
#define MCUXCLCSS_CMAC_STATE_IN_ENABLE      1U ///< Set #mcuxClCss_CmacOption_t.sie to this value to import the CMAC state from memory
#define MCUXCLCSS_CMAC_STATE_OUT_DISABLE    0U ///< Set #mcuxClCss_CmacOption_t.soe to this value to keep the CMAC state inside CSS at the end of the command
#define MCUXCLCSS_CMAC_STATE_OUT_ENABLE     1U ///< Set #mcuxClCss_CmacOption_t.soe to this value to export the CMAC state to memory at the end of the command

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Cmac_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Cmac_Async(
    mcuxClCss_CmacOption_t options,
    mcuxClCss_KeyIndex_t keyIdx,
    uint8_t const * pKey,
    size_t keyLength,
    uint8_t const * pInput,
    size_t inputLength,
    uint8_t * pMac)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Cmac_Async);

    MCUXCLCSS_INPUT_PARAM_CHECK_PROTECTED(mcuxClCss_Cmac_Async, (MCUXCLCSS_CMAC_EXTERNAL_KEY_DISABLE == options.bits.extkey && CSS_KS_CNT <= keyIdx) || (MCUXCLCSS_CMAC_EXTERNAL_KEY_ENABLE == options.bits.extkey && ((MCUXCLCSS_CMAC_KEY_SIZE_128 != keyLength) && (MCUXCLCSS_CMAC_KEY_SIZE_256 != keyLength))));


    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Cmac_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    if(MCUXCLCSS_CMAC_INITIALIZE_ENABLE == options.bits.initialize)
    {
        options.bits.sie = MCUXCLCSS_CMAC_STATE_IN_DISABLE;
    }
    else
    {
        options.bits.sie = MCUXCLCSS_CMAC_STATE_IN_ENABLE;
    }
    if(MCUXCLCSS_CMAC_FINALIZE_ENABLE == options.bits.finalize)
    {
        options.bits.soe = MCUXCLCSS_CMAC_STATE_OUT_DISABLE;
    }
    else
    {
         options.bits.soe = MCUXCLCSS_CMAC_STATE_OUT_ENABLE;
    }

    if (0U == options.bits.extkey)
    {
        mcuxClCss_setKeystoreIndex0(keyIdx);
    }
    else
    {
        mcuxClCss_setInput2(pKey, keyLength);
    }

    mcuxClCss_setInput0(pInput, inputLength);
    mcuxClCss_setInput1_fixedSize(pMac);
    mcuxClCss_setOutput_fixedSize(pMac);
    mcuxClCss_startCommand(ID_CFG_CSS_CMD_CMAC, options.word.value, CSS_CMD_BIG_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Cmac_Async, MCUXCLCSS_STATUS_OK_WAIT);
}
