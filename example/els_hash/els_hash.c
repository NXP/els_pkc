/*
 * Copyright 2020-2022 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "board.h"
#include "app.h"
#include "mcuxCsslExamples.h"
#include "els_hash.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
 * @brief Main function
 */
int main(void)
{
    char ch;
    uint8_t pass = 0;
    uint8_t fail = 0;

    /* Init board hardware. */
    BOARD_InitHardware();

    PRINTF("\r\nELS hash example\r\n");
    PRINTF("\r\n============================\r\n");

    PRINTF("SHA224 one shot:");
    if (mcuxClHash_sha224_oneshot_example() == true)
    {
        pass++;
        PRINTF("pass \r\n");
    }
    else
    {
        fail++;
        PRINTF("fail \r\n");
    }

    PRINTF("SHA256 one shot:");
    if (mcuxClHash_sha256_oneshot_example() == true)
    {
        pass++;
        PRINTF("pass \r\n");
    }
    else
    {
        fail++;
        PRINTF("fail \r\n");
    }

    PRINTF("SHA256 streaming example:");
    if (mcuxClHash_sha256_streaming_example() == true)
    {
        pass++;
        PRINTF("pass \r\n");
    }
    else
    {
        fail++;
        PRINTF("fail \r\n");
    }

    PRINTF("SHA256 long message example:");
    if (mcuxClHash_sha256_longMsgOneshot_example() == true)
    {
        pass++;
        PRINTF("pass \r\n");
    }
    else
    {
        fail++;
        PRINTF("fail \r\n");
    }

    PRINTF("SHA384 one shot:");
    if (mcuxClHash_sha384_oneshot_example() == true)
    {
        pass++;
        PRINTF("pass \r\n");
    }
    else
    {
        fail++;
        PRINTF("fail \r\n");
    }

    PRINTF("SHA512 one shot:");
    if (mcuxClHash_sha512_oneshot_example() == true)
    {
        pass++;
        PRINTF("pass \r\n");
    }
    else
    {
        fail++;
        PRINTF("fail \r\n");
    }

    PRINTF("\r\n============================\r\n");
    PRINTF("RESULT: ");
    if (fail == 0)
    {
        PRINTF("All %d test PASS!!\r\n", pass);
    }
    else
    {
        PRINTF("%d / %d test PASSED, %d FAILED!!\r\n", pass, pass + fail, fail);
    }

    PRINTF("ELS example END \r\n");
    while (1)
    {
        ch = GETCHAR();
        PUTCHAR(ch);
    }
}