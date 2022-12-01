/*--------------------------------------------------------------------------*/
/* Copyright 2021 NXP                                                       */
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

/** @file  mcuxClRandom_PRNG_CSS.c
 *  @brief Implementation of the non-cryptographic PRNG functions using CSS. */


#include <mcuxClSession.h>
#include <mcuxClCss.h>
#include <mcuxClRandom.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_ncInit)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_ncInit(
    mcuxClSession_Handle_t pSession
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_ncInit);

    (void) pSession; // Parameter not needed.

#ifdef MCUXCL_FEATURE_CSS_PRND_INIT

    MCUX_CSSL_FP_FUNCTION_CALL(ret_Prng_Init, mcuxClCss_Prng_Init_Async());

    if(MCUXCLCSS_STATUS_OK_WAIT != ret_Prng_Init)
    {
       MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_ncInit, MCUXCLRANDOM_STATUS_ERROR,
                                 MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Prng_Init_Async));
    }

    MCUX_CSSL_FP_FUNCTION_CALL(ret_Wait, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

    if (MCUXCLCSS_STATUS_OK != ret_Wait)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_ncInit, MCUXCLRANDOM_STATUS_ERROR,
                                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Prng_Init_Async),
                                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClRandom_ncInit, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK,
                                         MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Prng_Init_Async),
                                         MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));

#else /* MCUXCL_FEATURE_CSS_PRND_INIT */

    /* Check whether the current security strength is sufficient. */
    mcuxClCss_HwState_t hwState = {0};

    MCUX_CSSL_FP_FUNCTION_CALL(ret_GetHwState, mcuxClCss_GetHwState(&hwState));

    if(MCUXCLCSS_STATUS_OK != ret_GetHwState)
    {
       MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_ncInit, MCUXCLRANDOM_STATUS_ERROR,
                                 MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetHwState));
    }

    /* If the security strength is already sufficient, finish here. */
    if(MCUXCLCSS_STATUS_DRBGENTLVL_NONE != hwState.bits.drbgentlvl)
    {
       MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClRandom_ncInit, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK,
                                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetHwState));
    }

    /**
     * If the current security strength is not sufficient, do the init procedure:
     * Loop through the key slots until an unused slot is found.
     * Delete that key in order to force PRNG initialization.
     */
    mcuxClCss_KeyProp_t keyProp = {0};
    uint8_t keyIdx = 0u;

    for(keyIdx = 0u; keyIdx < MCUXCLCSS_KEY_SLOTS; keyIdx++)
    {
        MCUX_CSSL_FP_FUNCTION_CALL(ret_GetKeyProperties, mcuxClCss_GetKeyProperties(keyIdx, &keyProp));

        if(MCUXCLCSS_STATUS_OK != ret_GetKeyProperties)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_ncInit, MCUXCLRANDOM_STATUS_ERROR,
                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetHwState),
                                        (keyIdx + 1u) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetKeyProperties));
        }

        if (MCUXCLCSS_KEYPROPERTY_ACTIVE_FALSE == keyProp.bits.kactv)
        {
            MCUX_CSSL_FP_FUNCTION_CALL(ret_KeyDelete_Async, mcuxClCss_KeyDelete_Async(keyIdx));

            if(MCUXCLCSS_STATUS_OK_WAIT != ret_KeyDelete_Async)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_ncInit, MCUXCLRANDOM_STATUS_ERROR,
                                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetHwState),
                                            (keyIdx + 1u) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetKeyProperties),
                                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyDelete_Async));
            }

            MCUX_CSSL_FP_FUNCTION_CALL(ret_Wait2, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

            if(MCUXCLCSS_STATUS_OK == ret_Wait2)
            {
                /* PRNG properly initialized. */
                MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClRandom_ncInit, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK,
                                                     MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetHwState),
                                                     (keyIdx + 1u) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetKeyProperties),
                                                     MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyDelete_Async),
                                                     MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));
            }
        }
    }

    /* PRNG could not be properly initialized. No free key slot? */
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_ncInit, MCUXCLRANDOM_STATUS_ERROR,
                                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetHwState),
                                MCUXCLCSS_KEY_SLOTS * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetKeyProperties));

#endif /* MCUXCL_FEATURE_CSS_PRND_INIT */
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_ncGenerate)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_ncGenerate(
    mcuxClSession_Handle_t pSession,
    uint8_t *             pOut,
    uint32_t              outLength
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_ncGenerate);

    (void) pSession; // Parameter not needed.

    MCUX_CSSL_FP_FUNCTION_CALL(ret_Prng_GetRandom, mcuxClCss_Prng_GetRandom(pOut, outLength));
    if (MCUXCLCSS_STATUS_OK != ret_Prng_GetRandom)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_ncGenerate, MCUXCLRANDOM_STATUS_ERROR,
                                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Prng_GetRandom));
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClRandom_ncGenerate, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK,
                                         MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Prng_GetRandom));
}
