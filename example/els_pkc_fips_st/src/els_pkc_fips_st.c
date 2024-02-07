/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "app.h"
#include "els_pkc_fips_config.h"
#include <mcux_els.h>
#include <mcux_pkc.h>
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
static inline void execute_kats()
{
    /* Execute all FIPS Self Tests if user has specified */
    if (s_UserOptions & FIPS_ALL_TESTS)
    {
        for (uint32_t i = 0U; i < sizeof(s_AlgorithmMappings) / sizeof(s_AlgorithmMappings[0U]); ++i)
        {
            s_AlgorithmMappings[i].executionFunction(s_AlgorithmMappings[i].option, s_AlgorithmMappings[i].name);
        }
        return;
    }
    for (uint32_t i = 0U; i < sizeof(s_AlgorithmMappings) / sizeof(s_AlgorithmMappings[0U]); ++i)
    {
        if (s_UserOptions & s_AlgorithmMappings[i].option)
        {
            s_AlgorithmMappings[i].executionFunction(s_AlgorithmMappings[i].option, s_AlgorithmMappings[i].name);
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

    PRINTF("START OF ELS PKC FIPS SELF-TEST\r\n");

    /* Enable the ELS */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_Enable_Async());
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_wait, token_wait, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    execute_kats();

    /* Disable the ELS */
    mcuxClExample_Els_Disable();
    PRINTF("END OF ELS PKC FIPS SELF-TEST\r\n");

    while (1U)
        ;
}
