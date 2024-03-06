/*
 *     Copyright 2021 - 2023 NXP
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
static status_t ELS_PRNG_KickOff(void);
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
status_t ELS_PowerDownWakeupInit(ELS_Type *base)
{
    status_t status = kStatus_Fail;

    /* Enable ELS clock */
    CLOCK_EnableClock(kCLOCK_Els);
    
    /* Enable ELS */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_Enable_Async()); // Enable the ELS.
    // mcuxClEls_Enable_Async is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Enable_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        return kStatus_Fail ;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    //TODO: Load ELS internal TRNG config via mcuxClEls_Rng_Dtrng_ConfigLoad_Async() call
    
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClEls_Enable_Async operation to complete.
    // mcuxClEls_WaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        return kStatus_Fail;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
  
    /* Kick-off ELS PRNG */
    status = ELS_PRNG_KickOff();
    if (status != kStatus_Success)
    {
        return status;
    }
        
    return kStatus_Success;
}

static status_t ELS_PRNG_KickOff(void)
{

    /* Init ELS PRNG */
    /* Check if PRNG already ready */
    if ((ELS->ELS_STATUS & ELS_ELS_STATUS_PRNG_RDY_MASK) == 0u)
    {
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(result0, token0, mcuxClCss_Prng_Init_Async());
        if ((token0 != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Prng_Init_Async)) || (result0 != MCUXCLELS_STATUS_OK_WAIT))
        {
            return kStatus_Fail;
        }

        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(result1, token1, mcuxClCss_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
        if ((token1 != MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation)) || (result1 != MCUXCLELS_STATUS_OK))
        {
            return kStatus_Fail;
        }
    }

    return kStatus_Success;
}
