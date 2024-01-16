/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "app.h"
#include "els_pkc_fips_symmetric.h"
#include "els_pkc_fips_asymmetric.h"
#include "els_pkc_fips_hash.h"
#include "els_pkc_fips_hmac.h"
#include "els_pkc_fips_config.h"
#include "mcux_els.h" /* Power Down Wake-up Init */
#include "mcux_pkc.h" /* Power Down Wake-up Init */
#if defined(FSL_FEATURE_SOC_TRNG_COUNT) && (FSL_FEATURE_SOC_TRNG_COUNT > 0U)
#include "fsl_trng.h"
#endif

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
 * @brief Initialize crypto hardware
 */
static inline void CRYPTO_InitHardware(void)
{
    status_t status;

    status = ELS_PowerDownWakeupInit(ELS);
    if (status != kStatus_Success)
    {
        return;
    }
    /* Enable PKC related clocks and RAM zeroize */
    status = PKC_PowerDownWakeupInit(PKC);
    if (status != kStatus_Success)
    {
        return;
    }
#if defined(FSL_FEATURE_SOC_TRNG_COUNT) && (FSL_FEATURE_SOC_TRNG_COUNT > 0U)
    /* Initialize the TRNG driver */
    {
        trng_config_t trng_config;
        /* Get default TRNG configs*/
        TRNG_GetDefaultConfig(&trng_config);
        /* Set sample mode of the TRNG ring oscillator to Von Neumann, for better random data.*/
        /* Initialize TRNG */
        TRNG_Init(TRNG, &trng_config);
    }
#endif /* FSL_FEATURE_SOC_TRNG_COUNT */
}

/*!
 * @brief Function to execute all KATs based on the user options
 * defined in the els_pkc_fips_config.h file.
 */
static inline void execute_kat()
{
    for (size_t i = 0; i < sizeof(s_AlgorithmMappings) / sizeof(s_AlgorithmMappings[0]); ++i)
    {
        if (s_UserOptions & s_AlgorithmMappings[i].option)
        {
            s_AlgorithmMappings[i].executionFunction(s_AlgorithmMappings[i].option);
        }
    }
}

/*!
 * @brief Main function
 */
int main(void)
{
    /* Init hardware */
    BOARD_InitHardware();
    CRYPTO_InitHardware();

#if defined(SHOW_DEBUG_OUTPUT) && SHOW_DEBUG_OUTPUT == true
    PRINTF("START OF ELS PKC FIPS SELF-TEST\r\n");
#endif /* SHOW_DEBUG_OUTPUT */

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_Enable_Async());
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Enable_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
#if defined(SHOW_DEBUG_OUTPUT) && SHOW_DEBUG_OUTPUT == true
        PRINTF("[Error] Els enable async failed\r\n");
#endif /* SHOW_DEBUG_OUTPUT */
        return 1;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_wait, token_wait, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token_wait || MCUXCLELS_STATUS_OK != result_wait)
    {
        return 1;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    execute_kat();

    /* Disable the ELS */
    if (!mcuxClExample_Els_Disable())
    {
        return 1;
    }
#if defined(SHOW_DEBUG_OUTPUT) && SHOW_DEBUG_OUTPUT == true
    PRINTF("END OF ELS PKC FIPS SELF-TEST\r\n");
#endif /* SHOW_DEBUG_OUTPUT */

    return 0;
}
