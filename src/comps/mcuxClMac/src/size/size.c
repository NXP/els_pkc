/*--------------------------------------------------------------------------*/
/* Copyright 2020-2022 NXP                                                  */
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

#include <internal/mcuxClMac_Internal.h>

/**
 * @brief Mac Cpu Work Area structure
 *
 */
struct mcuxClMac_WaCpu_t
{
  uint8_t aesBlock [4];  ///< Mac aes block
};

/**
 * @brief Mac Cpu Work Area type
 *
 */
typedef struct mcuxClMac_WaCpu_t mcuxClMac_WaCpu_t;

/* Mac Cpu Workarea size generation */
volatile uint8_t mcuxClMac_WaCpuMax [sizeof(mcuxClMac_WaCpu_t)];

/* Mac context size generation */
volatile struct mcuxClMac_Context mcuxClMac_Context_Size;
