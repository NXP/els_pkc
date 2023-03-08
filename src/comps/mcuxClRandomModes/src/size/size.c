/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023 NXP                                                  */
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

#include <mcuxClCore_Analysis.h>

#include <internal/mcuxClRandomModes_Internal_SizeDefinitions.h>

#include <internal/mcuxClRandomModes_Private_CtrDrbg.h>

/* *********************** */
/* *** Work area sizes *** */
/* *********************** */
MCUXCLCORE_ANALYSIS_START_PATTERN_OBJ_SIZES()

volatile mcuxClRandomModes_Context_CtrDrbg_Aes128_t mcuxClRandomModes_Context_Aes128;

volatile mcuxClRandomModes_Context_CtrDrbg_Aes192_t mcuxClRandomModes_Context_Aes192;

volatile mcuxClRandomModes_Context_CtrDrbg_Aes256_t mcuxClRandomModes_Context_Aes256;

uint8_t mcuxClRandomModes_CpuWA_MaxSize[MCUXCLRANDOMMODES_CPUWA_MAXSIZE];
MCUXCLCORE_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
