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
 * @brief Print algorithm information, if HW acclereated or
 * only software implemenatation.
 */
static inline void print_algorithm_infos()
{
    PRINTF("HW ACCELERATION ALGORITHM INFORMATION:\r\n");
    PRINTF("    ECB DRBG: ELS\r\n");
    PRINTF("    CTR DRBG: ELS\r\n");
    PRINTF("    CKDF SP800-108: ELS\r\n");
    PRINTF("    HKDF RFC5869: ELS\r\n");
    PRINTF("    ECDSA NISTP 256: ELS\r\n");
    PRINTF("    ECDSA NISTP 384: PKC\r\n");
    PRINTF("    ECDSA NISTP 521: PKC\r\n");
    PRINTF("    EDDSA ED25519: PKC\r\n");
    PRINTF("    ECDH NISTP 256: ELS\r\n");
    PRINTF("    ECDH NISTP 384: PKC\r\n");
    PRINTF("    ECDH NISTP 521: PKC\r\n");
    PRINTF("    ECC KEYGEN NISTP 256: ELS\r\n");
    PRINTF("    ECC KEYGEN NISTP 384: PKC\r\n");
    PRINTF("    ECC KEYGEN NISTP 521: PKC\r\n");
    PRINTF("    RSA-PKCS15-2048: PKC\r\n");
    PRINTF("    RSA-PKCS15-3072: PKC\r\n");
    PRINTF("    RSA-PKCS15-4096: PKC\r\n");
    PRINTF("    RSA-PSS-2048: PKC\r\n");
    PRINTF("    RSA-PSS-3072: PKC\r\n");
    PRINTF("    RSA-PSS-4096: PKC\r\n");
    PRINTF("    AES-CCM-128: ELS\r\n");
    PRINTF("    AES-CCM-256: ELS\r\n");
    PRINTF("    AES-GCM-128: ELS\r\n");
    PRINTF("    AES-GCM-192: ELS\r\n");
    PRINTF("    AES-GCM-256: ELS\r\n");
    PRINTF("    AES-CTR-128: ELS\r\n");
    PRINTF("    AES-CTR-192: ELS\r\n");
    PRINTF("    AES-CTR-256: ELS\r\n");
    PRINTF("    AES-ECB-128: ELS\r\n");
    PRINTF("    AES-ECB-192: ELS\r\n");
    PRINTF("    AES-ECB-256: ELS\r\n");
    PRINTF("    AES-CBC-128: ELS\r\n");
    PRINTF("    AES-CBC-192: ELS\r\n");
    PRINTF("    AES-CBC-256: ELS\r\n");
    PRINTF("    AES-CMAC-128: ELS\r\n");
    PRINTF("    AES-CMAC-256: ELS\r\n");
    PRINTF("    HMAC-SHA224: SOFTWARE IMPLEMENTATION\r\n");
    PRINTF("    HMAC-SHA256: ELS\r\n");
    PRINTF("    HMAC-SHA384: SOFTWARE IMPLEMENTATION\r\n");
    PRINTF("    HMAC-SHA512: SOFTWARE IMPLEMENTATION\r\n");
    PRINTF("    SHA224: ELS\r\n");
    PRINTF("    SHA256: ELS\r\n");
    PRINTF("    SHA384: ELS\r\n");
    PRINTF("    SHA512: ELS\r\n");

    PRINTF("\r\n");
}

/*!
 * @brief Main function
 */
int main(void)
{
    /* Init hardware */
    BOARD_InitHardware();
    CRYPTO_InitHardware();

    PRINTF("START OF ELS PKC FIPS SELF-TEST...\r\n");
    print_algorithm_infos();
    /* Enable the ELS */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_Enable_Async());
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_wait, token_wait, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    execute_kats();

    /* Disable the ELS */
    mcuxClExample_Els_Disable();
    PRINTF("ELS PKC FIPS SELF-TEST FINISHED!\r\n");

    while (1U)
        ;
}
