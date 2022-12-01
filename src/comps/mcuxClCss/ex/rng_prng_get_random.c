/*--------------------------------------------------------------------------*/
/* Copyright 2020 NXP                                                       */
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

/**
 * @file  rng_prng_get_random.c
 * @brief Example of getting a random number from PRNG of CSSv2 (CLNS component mcuxClCss)
 *
 * @example rng_prng_get_random.c
 * @brief   Example of getting a random number from PRNG of CSSv2 (CLNS component mcuxClCss)
 */

#include <mcuxClCss.h> // Interface to the entire mcuxClCss component
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <stdbool.h>  // bool type for the example's return code
#include <mcuxClExample_CSS_Helper.h>
#include <mcuxClExample_CSS_Key_Helper.h>

/** Uses random number from PRNG of CSS.
 * @retval true  The example code completed successfully */
bool rng_prng_get_random(
    void)
{
    /** Initialize CSS, Enable the CSSv2 **/
    if(!mcuxClExample_Css_Init(MCUXCLCSS_RESET_DO_NOT_CANCEL))
    {
        return false;
    }

    // PRNG needs to be initialized; this can be done by calling mcuxClCss_KeyDelete_Async (delete any key slot, can be empty)
    /** deleted 18 keySlot **/
    if(!mcuxClExample_CSS_KeyDelete(18))
    {
        return false;
    }

    uint32_t dummy;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_Prng_GetRandomWord(&dummy));
    // mcuxClCss_Prng_GetRandomWord is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Prng_GetRandomWord) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false; // Expect that no error occurred, meaning that the mcuxClCss_Prng_GetRandomWord operation was started.
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    uint32_t random[16];  // buffers of 16 CPU words to be filled with random numbers from PRNG.

    // fill the buffer with random numbers from PRNG.
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_Prng_GetRandom((uint8_t*) random, sizeof(random)));
    // mcuxClCss_Prng_GetRandom is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Prng_GetRandom) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false; // Expect that no error occurred, meaning that the mcuxClCss_Prng_GetRandom operation was started.
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /** Disable the CSSv2 **/
    if(!mcuxClExample_Css_Disable())
    {
        return false;
    }

    return true;
}
