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

/** @file  mcuxClCss_Common.c
 *  @brief CSSv2 implementation for common functionality.
 *  This file implements the functions declared in mcuxClCss_Common.h and adds helper functions used by other implementation headers. */

#include <stdbool.h>
#include <platform_specific_headers.h>
#include <mcuxClMemory.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCss.h>
#include <internal/mcuxClCss_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_GetHwVersion)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_GetHwVersion(
    mcuxClCss_HwVersion_t * result)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_GetHwVersion);
    result->word.value = MCUXCLCSS_SFR_READ(CSS_VERSION);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_GetHwVersion, MCUXCLCSS_STATUS_OK);
}

#ifdef MCUXCL_FEATURE_CSS_HWCONFIG
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_GetHwConfig)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_GetHwConfig(
    mcuxClCss_HwConfig_t * result)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_GetHwConfig);
    result->word.value = MCUXCLCSS_SFR_READ(CSS_CONFIG);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_GetHwConfig, MCUXCLCSS_STATUS_OK);
}
#endif /* MCUXCL_FEATURE_CSS_HWCONFIG */

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_GetHwState)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_GetHwState(
    mcuxClCss_HwState_t * result)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_GetHwState);
    result->word.value = MCUXCLCSS_SFR_READ(CSS_STATUS);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_GetHwState, MCUXCLCSS_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Enable_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Enable_Async(
    void)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Enable_Async);
    MCUXCLCSS_SFR_WRITE(CSS_CTRL, MCUXCLCSS_SFR_FIELD_FORMAT(CSS_CTRL, CSS_EN, 1u));
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Enable_Async, MCUXCLCSS_STATUS_OK_WAIT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Disable)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Disable(
    void)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Disable);
    MCUXCLCSS_SET_CTRL_FIELD(MCUXCLCSS_SFR_CSS_CTRL_CSS_EN, 0u);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Disable, MCUXCLCSS_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_GetErrorCode)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_GetErrorCode(
    mcuxClCss_ErrorHandling_t errorHandling)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_GetErrorCode);

    mcuxClCss_Status_t result = MCUXCLCSS_STATUS_SW_FAULT;
    if (1U == MCUXCLCSS_GET_STATUS_FIELD(MCUXCLCSS_SFR_CSS_STATUS_CSS_ERR))
    {
        if (MCUXCLCSS_IS_ERROR_BIT_SET(MCUXCLCSS_SFR_CSS_ERR_STATUS_FLT_ERR))
        {
            result = MCUXCLCSS_STATUS_HW_FAULT;
        }
        else if (MCUXCLCSS_IS_ERROR_BIT_SET(MCUXCLCSS_SFR_CSS_ERR_STATUS_ITG_ERR))
        {
            result = MCUXCLCSS_STATUS_HW_INTEGRITY;
        }
        else if (MCUXCLCSS_IS_ERROR_BIT_SET(MCUXCLCSS_SFR_CSS_ERR_STATUS_OPN_ERR))
        {
            result = MCUXCLCSS_STATUS_HW_OPERATIONAL;
        }
        else if (MCUXCLCSS_IS_ERROR_BIT_SET(MCUXCLCSS_SFR_CSS_ERR_STATUS_ALG_ERR))
        {
            result = MCUXCLCSS_STATUS_HW_ALGORITHM;
        }
        else if (MCUXCLCSS_IS_ERROR_BIT_SET(MCUXCLCSS_SFR_CSS_ERR_STATUS_BUS_ERR))
        {
            result = MCUXCLCSS_STATUS_HW_BUS;
        }
        else if (MCUXCLCSS_IS_ERROR_BIT_SET(MCUXCLCSS_SFR_CSS_ERR_STATUS_PRNG_ERR))
        {
            result = MCUXCLCSS_STATUS_HW_PRNG;
        }
        else if (MCUXCLCSS_IS_ERROR_BIT_SET(MCUXCLCSS_SFR_CSS_ERR_STATUS_DTRNG_ERR))
        {
            result = MCUXCLCSS_STATUS_HW_DTRNG;
        }
        else
        {
            result = MCUXCLCSS_STATUS_SW_FAULT;
        }
    }
    else
    {
        result = MCUXCLCSS_STATUS_OK;
    }

    if (MCUXCLCSS_ERROR_FLAGS_CLEAR == errorHandling){
        MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCss_ResetErrorFlags()); /* always returns MCUXCLCSS_STATUS_OK. */

        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_GetErrorCode, result,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_ResetErrorFlags));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_GetErrorCode, result);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_GetErrorLevel)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_GetErrorLevel(
    mcuxClCss_ErrorHandling_t errorHandling,
    uint32_t *errorLevel)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_GetErrorLevel);

    *errorLevel = MCUXCLCSS_GET_ERROR_STATUS_FIELD(MCUXCLCSS_SFR_CSS_ERR_STATUS_ERR_LVL);

    MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClCss_GetErrorCode(errorHandling));

    /* Exit function with expectation: mcuxClCss_GetErrorCode was called unconditionally */
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_GetErrorLevel, result,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetErrorCode));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_WaitForOperation)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_WaitForOperation(
    mcuxClCss_ErrorHandling_t errorHandling)
{
    /* Enter flow-protected function with expectation: mcuxClCss_GetErrorCode will be called (unconditionally) */
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_WaitForOperation,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetErrorCode));

    while (mcuxClCss_isBusy())
    {
        // Do nothing
    }

    MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClCss_GetErrorCode(errorHandling));

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_WaitForOperation, result);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_LimitedWaitForOperation)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_LimitedWaitForOperation(
    uint32_t counterLimit,
    mcuxClCss_ErrorHandling_t errorHandling)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_LimitedWaitForOperation);

    bool counterExpired = true;
    while (0U != counterLimit)
    {
        if (!mcuxClCss_isBusy())
        {
            counterExpired = false;
            break;
        }
        counterLimit--;
    }

    if (true == counterExpired)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_LimitedWaitForOperation, MCUXCLCSS_STATUS_SW_COUNTER_EXPIRED);
    }

    MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClCss_GetErrorCode(errorHandling));

    /* Exit function with expectation: mcuxClCss_GetErrorCode was called */
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_LimitedWaitForOperation, result,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetErrorCode));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_ResetErrorFlags)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_ResetErrorFlags(
    void)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_ResetErrorFlags);

    MCUXCLCSS_SFR_WRITE(CSS_ERR_STATUS_CLR, MCUXCLCSS_SFR_FIELD_FORMAT(CSS_ERR_STATUS, CLR_ERR_CLR, MCUXCLCSS_ERROR_FLAGS_CLEAR));
    // Poll error bit to be sure that error bits has been cleared. Required by HW spec.
    while(0u != MCUXCLCSS_GET_STATUS_FIELD(MCUXCLCSS_SFR_CSS_STATUS_CSS_ERR))
    {
        // Do nothing
    }
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_ResetErrorFlags, MCUXCLCSS_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Reset_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Reset_Async(
    mcuxClCss_ResetOption_t options)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Reset_Async);
    if (mcuxClCss_isBusy() && (MCUXCLCSS_RESET_DO_NOT_CANCEL == options))
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Reset_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    MCUXCLCSS_SET_CTRL_FIELD(MCUXCLCSS_SFR_CSS_CTRL_RESET, 1u);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Reset_Async, MCUXCLCSS_STATUS_OK_WAIT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_SetIntEnableFlags)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_SetIntEnableFlags(
    mcuxClCss_InterruptOptionEn_t options)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_SetIntEnableFlags);
    MCUXCLCSS_SFR_WRITE(CSS_INT_ENABLE, options.word.value);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_SetIntEnableFlags, MCUXCLCSS_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_GetIntEnableFlags)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_GetIntEnableFlags(
    mcuxClCss_InterruptOptionEn_t * result)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_GetIntEnableFlags);
    result->word.value = MCUXCLCSS_SFR_READ(CSS_INT_ENABLE);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_GetIntEnableFlags, MCUXCLCSS_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_ResetIntFlags)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_ResetIntFlags(
    mcuxClCss_InterruptOptionRst_t options)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_ResetIntFlags);
    MCUXCLCSS_SFR_WRITE(CSS_INT_STATUS_CLR, options.word.value);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_ResetIntFlags, MCUXCLCSS_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_SetIntFlags)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_SetIntFlags(
    mcuxClCss_InterruptOptionSet_t options)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_SetIntFlags);
    MCUXCLCSS_SFR_WRITE(CSS_INT_STATUS_SET, options.word.value);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_SetIntFlags, MCUXCLCSS_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_SetRandomStartDelay)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_SetRandomStartDelay(
    uint32_t delay)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_SetRandomStartDelay);
    MCUXCLCSS_INPUT_PARAM_CHECK_PROTECTED(mcuxClCss_SetRandomStartDelay, 1024u < delay);

    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_SetRandomStartDelay, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    MCUXCLCSS_SET_CFG_FIELD(MCUXCLCSS_SFR_CSS_CFG_ADCTRL, delay);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_SetRandomStartDelay, MCUXCLCSS_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_GetRandomStartDelay)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_GetRandomStartDelay(
    uint32_t *delay)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_GetRandomStartDelay);

    *delay = MCUXCLCSS_GET_CFG_FIELD(MCUXCLCSS_SFR_CSS_CFG_ADCTRL);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_GetRandomStartDelay, MCUXCLCSS_STATUS_OK);
}

#ifdef MCUXCL_FEATURE_CSS_LOCKING
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_GetLock)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_GetLock(
    uint32_t * pSessionId)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_GetLock);

    *pSessionId = MCUXCLCSS_SFR_READ(CSS_SESSION_ID);
    if(0u == *pSessionId)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_GetLock, MCUXCLCSS_STATUS_SW_LOCKING_FAILED);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_GetLock, MCUXCLCSS_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_ReleaseLock)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_ReleaseLock(
    uint32_t sessionId)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_ReleaseLock);
    MCUXCLCSS_SFR_WRITE(CSS_SESSION_ID, sessionId);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_ReleaseLock, MCUXCLCSS_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_IsLocked)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_IsLocked(
    void)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_IsLocked);

    if(1u == MCUXCLCSS_GET_STATUS_FIELD(MCUXCLCSS_SFR_CSS_STATUS_CSS_LOCKED))
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_IsLocked, MCUXCLCSS_STATUS_SW_STATUS_LOCKED);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_IsLocked, MCUXCLCSS_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_SetMasterUnlock)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_SetMasterUnlock(
    uint32_t masterId)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_SetMasterUnlock);
    MCUXCLCSS_SFR_WRITE(CSS_MASTER_ID, masterId);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_SetMasterUnlock, MCUXCLCSS_STATUS_OK);
}
#endif /* MCUXCL_FEATURE_CSS_LOCKING */


#ifdef MCUXCL_FEATURE_CSS_DMA_ADDRESS_READBACK
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_GetLastDmaAddress)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_GetLastDmaAddress(uint32_t* pLastAddress)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_GetLastDmaAddress);

    *pLastAddress = MCUXCLCSS_SFR_READ(CSS_DMA_FIN_ADDR);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_GetLastDmaAddress, MCUXCLCSS_STATUS_OK);

}
#endif /* MCUXCL_FEATURE_CSS_DMA_ADDRESS_READBACK */

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_CompareDmaFinalOutputAddress)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_CompareDmaFinalOutputAddress(
        uint8_t *outputStartAddress,
        size_t expectedLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_CompareDmaFinalOutputAddress,
                               MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetLastDmaAddress));

    /* Calculate the expected final address from the input */
    uint32_t expectedFinalAddress = (uint32_t)outputStartAddress + expectedLength;

    /* Get the actual final address from CSS - no result check as function always returns OK */
    uint32_t finalAddress;
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClCss_GetLastDmaAddress(&finalAddress));

    /* Compare the expected address to the actual one */
    if(finalAddress != expectedFinalAddress)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_CompareDmaFinalOutputAddress, MCUXCLCSS_STATUS_SW_COMPARISON_FAILED);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_CompareDmaFinalOutputAddress, MCUXCLCSS_STATUS_OK);

}
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */
