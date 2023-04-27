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

/** @file  mcuxClEls_GlitchDetector.c
 *  @brief CSSv2 implementation for key management.
 * This file implements the functions declared in mcuxClEls_GlitchDetector.h. */

#include <mcuxClEls_GlitchDetector.h>
#include <stdbool.h>
#include <mcuxClEls.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <internal/mcuxClEls_Internal.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_GlitchDetector_LoadConfig_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t)
    mcuxClEls_GlitchDetector_LoadConfig_Async(uint8_t const *pInput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_GlitchDetector_LoadConfig_Async);

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClEls_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_GlitchDetector_LoadConfig_Async, MCUXCLELS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClEls_setInput0_fixedSize(pInput);
    mcuxClEls_startCommand(ID_CFG_CSS_CMD_GDET_CFG_LOAD, 0U, ELS_CMD_BIG_ENDIAN);
    
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_GlitchDetector_LoadConfig_Async, MCUXCLELS_STATUS_OK_WAIT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_GlitchDetector_Trim_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_GlitchDetector_Trim_Async(uint8_t *pOutput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_GlitchDetector_Trim_Async);

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClEls_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_GlitchDetector_Trim_Async, MCUXCLELS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClEls_setOutput_fixedSize(pOutput);
    mcuxClEls_startCommand(ID_CFG_ELS_CMD_GDET_TRIM, 0U, ELS_CMD_BIG_ENDIAN);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_GlitchDetector_Trim_Async, MCUXCLELS_STATUS_OK_WAIT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_GlitchDetector_GetEventCounter)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_GlitchDetector_GetEventCounter(uint8_t *pCount)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_GlitchDetector_GetEventCounter);

    // Decode from Gray coding
    uint8_t count8 = (uint8_t)(ELS->ELS_GDET_EVTCNT & 0xFF);
    count8 ^= count8 >> 4u;
    count8 ^= count8 >> 2u;
    count8 ^= count8 >> 1u;

    // Assign to the result variable
    *pCount = count8;

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_GlitchDetector_GetEventCounter, MCUXCLELS_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_GlitchDetector_ResetEventCounter)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_GlitchDetector_ResetEventCounter(void)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_GlitchDetector_ResetEventCounter);

    // Start GDET Event Counter reset
    ELS->ELS_GDET_EVTCNT_CLR = 1u;

    // The actual reset occurs in a different clock domain from the CSS core clock, so we have to wait for synchroni-
    // zation. The spec states that this takes on the order of 2 cycles of the CSS core clock plus 2 cycles of the
    // Glitch Detector reference clock.
    while (1u != ((ELS->ELS_GDET_EVTCNT & 0x100) >> 8))
    {
        // Do nothing
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEls_GlitchDetector_ResetEventCounter, MCUXCLELS_STATUS_OK);
}
