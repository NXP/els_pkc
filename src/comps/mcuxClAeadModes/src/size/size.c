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
/* Security Classification:  Company Confidential                           */
/*--------------------------------------------------------------------------*/

/**
 *
 * @file:	size.c
 * @brief:	This file contains objects which will be used to measure size of particular types.
 *
 */

#include <mcuxClCore_Platform.h>
#include <mcuxClCore_Analysis.h>

/* ******************************* */
/* *** Work area and ctx sizes *** */
/* ******************************* */




#include <internal/mcuxClAeadModes_ELS_Types.h>

MCUXCLCORE_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile uint8_t mcuxClAead_WorkArea[1];
volatile uint8_t mcuxClAead_OneShot[sizeof(mcuxClAeadModes_Context_t)];
MCUXCLCORE_ANALYSIS_STOP_PATTERN_OBJ_SIZES()


MCUXCLCORE_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile struct mcuxClAeadModes_Context mcuxClAeadModes_Context;
MCUXCLCORE_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
