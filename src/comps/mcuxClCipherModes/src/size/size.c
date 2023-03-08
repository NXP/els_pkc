/*--------------------------------------------------------------------------*/
/* Copyright 2021-2022 NXP                                                  */
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
 * @file:  size.c
 * @brief: This file contains objects which will be used to measure size of particular types.
 *
 */

#include <mcuxClCore_Analysis.h>

#include <internal/mcuxClCipherModes_Wa.h>
#include <internal/mcuxClCipherModes_Internal_Types.h>

/* *********************** */
/* *** Work area sizes *** */
/* *********************** */

MCUXCLCORE_ANALYSIS_START_PATTERN_OBJ_SIZES()

volatile mcuxClCipherModes_Context_Aes_Els_t mcuxClCipherModes_WorkArea_Aes_Els_Oneshot; // ELS Oneshot Context needs to be in WA

volatile mcuxClCipherModes_Context_Aes_Els_t mcuxClCipherModes_Context_Aes_Els;


MCUXCLCORE_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
