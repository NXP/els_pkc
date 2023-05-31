/*
 *     Copyright 2022 NXP
 *     All rights reserved.
 *
 *     SPDX-License-Identifier: BSD-3-Clause
 */

#include "mcux_els.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*******************************************************************************
 * Prototypes
 ******************************************************************************/
//static status_t ELS_PRNG_KickOff(void);
static status_t ELS_check_key(uint8_t keyIdx, mcuxClCss_KeyProp_t *pKeyProp);
/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
 * brief ELS Init after power down.
 *
 * This function enable all ELS related clocks, enable ELS and start ELS PRNG.
 * Normally all of these actions are done automatically by boot ROM, but if an application uses Power Down mode
 * this function must be called before using ELS after wake-up.
 *
 * param base ELS peripheral address.
 *
 * return kStatus_Success upon success, kStatus_Fail otherwise
 */
status_t ELS_PowerDownWakeupInit(S50_Type *base)
{
    status_t status = kStatus_Fail;

    /* Enable GDET and DTRNG clocks */
    SYSCON->ELS_CLK_CTRL =
        SYSCON_ELS_CLK_CTRL_SET_GDET_REFCLK_EN_SET_MASK | SYSCON_ELS_CLK_CTRL_SET_DTRNG_REFCLK_EN_SET_MASK;

    /* Enable ELS clock */
    CLOCK_EnableClock(kCLOCK_Css);

    /* Enable ELS and related clocks */
    /* Initialize ELS */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_Enable_Async()); // Enable the ELS.
    // mcuxClCss_Enable_Async is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Enable_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
    {
        status = kStatus_Fail;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        result, token,
        mcuxClCss_WaitForOperation(
            MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_Enable_Async operation to complete.
    // mcuxClCss_WaitForOperation is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        status = kStatus_Fail;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Kick-off ELS PRNG */
//    status = ELS_PRNG_KickOff();
    if (status != kStatus_Success)
    {
        return status;
    }

    return kStatus_Success;
}

static status_t ELS_check_key(uint8_t keyIdx, mcuxClCss_KeyProp_t *pKeyProp)
{
    /* Check if ELS required keys are available in ELS keystore */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token,
                                     mcuxClCss_GetKeyProperties(keyIdx, pKeyProp)); // Get key propertis from the ELS.
    // mcuxClCss_GetKeyProperties is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetKeyProperties) != token) || (MCUXCLCSS_STATUS_OK != result))
        return kStatus_Fail;
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return kStatus_Success;
}

//static status_t ELS_PRNG_KickOff(void)
//{
//
//    /* Check if PRNG already ready */
//    if ((ELS->ELS_STATUS & S50_ELS_STATUS_PRNG_RDY_MASK) == 0u)
//    {
//        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(result0, token0, mcuxClEls_Prng_Init_Async());
//        if ((token0 != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Prng_Init_Async)) ||
//            (result0 != MCUXCLCSS_STATUS_OK_WAIT))
//        {
//            return kStatus_Fail;
//        }
//
//        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(result1, token1, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
//        if ((token1 != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation)) || (result1 != MCUXCLCSS_STATUS_OK))
//        {
//            return kStatus_Fail;
//        }
//    }
//
//    return kStatus_Success;
//}