/*
 * Copyright 2023 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "app.h"
#include "els_pkc_bm_symmetric.h"
#include "els_pkc_bm_asymmetric.h"
#include "els_pkc_bm_hash.h"
#include "els_pkc_bm_mac.h"

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
 * @brief Main function
 */
int main(void)
{
    SysTick_Config(CLOCK_GetCoreSysClkFreq() / 1000U);

    /* Init hardware */
    BOARD_InitHardware();

    /* Print BM information */
    PRINTF("#################################\r\n");
    PRINTF("#\r");
    PRINTF("\t\t\t\t#\r\n");
    PRINTF("#\r");
    PRINTF("#\tSTART OF BENCHMARK\t#\r\n");
    PRINTF("#\r");
    PRINTF("\t\t\t\t#\r\n");
    PRINTF("#################################\r\n");
    PRINTF("SYSTEM FREQUENCY: %d MHZ\r\n", CLOCK_GetCoreSysClkFreq() / 1000000U);
    PRINTF("BM INFORMATION:\r\n");
    PRINTF("   -EXPERIMENTAL CACHING (AES, AEAD, SHA, MAC) WITH MULTIPLE BLOCKS\r\n");
    PRINTF("   -SINGLE BLOCK: 1 * BLOCK_SIZE BLOCK\r\n");
    PRINTF("   -MULTIPLE BLOCKS: 1024 * BLOCK_SIZE BLOCKS\r\n");
    PRINTF("   -SMALL MESSAGE: 64 BYTE\r\n");
    PRINTF("   -LARGE MESSAGE: 2048 BYTE\r\n");
    PRINTF("   -AES BLOCK SIZE: 16 BYTE\r\n");
    PRINTF("   -SHA-256 BLOCK SIZE: 64 BYTE\r\n");
    PRINTF("   -SHA-384 BLOCK SIZE: 128 BYTE\r\n");
    PRINTF("   -SHA-512 BLOCK SIZE: 128 BYTE\r\n");
    PRINTF("\r\n\n");

    /* Run tests for AES symmetric-key cryptographic algorithms */
    run_tests_symmetric();

    /* Run tests for DSA asymmetric-key cryptographic algorithms */
    run_tests_asymmetric();

    /* Run tests for SHA hash algorithms */
    run_tests_hashing();

    /* Run tests for MAC algorithms */
    run_tests_mac();

    while (1)
    {
        char ch = GETCHAR();
        PUTCHAR(ch);
    }
}
