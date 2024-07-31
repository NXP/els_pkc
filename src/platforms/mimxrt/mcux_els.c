/*
 *     Copyright 2024 NXP
 *     All rights reserved.
 *
 *     SPDX-License-Identifier: BSD-3-Clause
 */

#include "mcux_els.h"
#include "fsl_glikey.h"

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

static status_t GlikeyWriteEnable(GLIKEY_Type *base, uint8_t idx)
{ 
    if (kStatus_Success != GLIKEY_StartEnable(base, 2u))
    {
        return kStatus_Fail;
    }
    if (kStatus_Success != GLIKEY_ContinueEnable(base, GLIKEY_CODEWORD_STEP1))
    {
        return kStatus_Fail;
    }
    if (kStatus_Success != GLIKEY_ContinueEnable(base, GLIKEY_CODEWORD_STEP2))
    {
        return kStatus_Fail;
    }
    if (kStatus_Success != GLIKEY_ContinueEnable(base, GLIKEY_CODEWORD_STEP3))
    {
        return kStatus_Fail;
    }
    if (kStatus_Success != GLIKEY_ContinueEnable(base, GLIKEY_CODEWORD_STEP_EN))
    {
        return kStatus_Fail;
    }
    
    return kStatus_Success;
}

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
    
    /* ELS CLK enable */
    /* SYSCON0->SEC_CLK_CTRL and SYSCON0->SEC_CLK_CTRL_SET are protected by GLIKEY3 (index 2) */
    if (kStatus_Success != GLIKEY_SyncReset(GLIKEY3))
    {
        return kStatus_Fail;
    }

    /* Move Glikey FSM to write enable */
    if (kStatus_Success != GlikeyWriteEnable(GLIKEY3, 2u))
    {
        return kStatus_Fail;
    }

    /* Enable ELS clock */
    SYSCON0->SEC_CLK_CTRL |= SYSCON0_SEC_CLK_CTRL_ELS_CLK_EN_MASK;
    CLOCK_EnableClock(kCLOCK_Els);
    
    /* End of write enable */
    GLIKEY_EndOperation(GLIKEY3);

    /* DTRNG CLK enable */
    /* SYSCON0->SEC_CLK_CTRL is protected by GLIKEY3 (index 1) */
    if (kStatus_Success != GLIKEY_SyncReset(GLIKEY3))
    {
        return kStatus_Fail;
    }

    /* Move GLIKEY FSM to write enable */
    if (kStatus_Success != GlikeyWriteEnable(GLIKEY3, 1u))
    {
        return kStatus_Fail;
    }

    /* TRNG enable CLK */
    SYSCON0->SEC_CLK_CTRL_SET |= SYSCON0_SEC_CLK_CTRL_SET_TRNG_REFCLK_EN_SET_MASK;

    /* End of write enable */
    GLIKEY_EndOperation(GLIKEY3);
    
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
