/*--------------------------------------------------------------------------*/
/* Copyright 2022 NXP                                                       */
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
 *
 * @file:	size.c
 * @brief:	This file contains objects which will be used to measure size of particular types.
 *
 */
#include <internal/mcuxClRandomModes_Internal_SizeDefinitions.h>

#ifdef MCUXCL_FEATURE_RANDOMMODES_CTRDRBG
#include <internal/mcuxClRandomModes_Private_CtrDrbg.h>
#endif /* MCUXCL_FEATURE_RANDOMMODES_CTRDRBG */

/* *********************** */
/* *** Work area sizes *** */
/* *********************** */

#ifdef MCUXCL_FEATURE_RANDOMMODES_CTRDRBG
extern volatile mcuxClRandomModes_Context_CtrDrbg_Aes128_t mcuxClRandomModes_Context_Aes128;
volatile mcuxClRandomModes_Context_CtrDrbg_Aes128_t mcuxClRandomModes_Context_Aes128;

extern volatile mcuxClRandomModes_Context_CtrDrbg_Aes192_t mcuxClRandomModes_Context_Aes192;
volatile mcuxClRandomModes_Context_CtrDrbg_Aes192_t mcuxClRandomModes_Context_Aes192;

extern volatile mcuxClRandomModes_Context_CtrDrbg_Aes256_t mcuxClRandomModes_Context_Aes256;
volatile mcuxClRandomModes_Context_CtrDrbg_Aes256_t mcuxClRandomModes_Context_Aes256;
#endif /* MCUXCL_FEATURE_RANDOMMODES_CTRDRBG */

uint8_t mcuxClRandomModes_CpuWA_MaxSize[MCUXCLRANDOMMODES_CPUWA_MAXSIZE];
