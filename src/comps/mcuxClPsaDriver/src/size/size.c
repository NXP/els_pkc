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
 * @file:   size.c
 * @brief:  This file contains objects which will be used to measure size of particular types.
 *
 */

#include <mcuxClCore_Analysis.h>

#include <internal/mcuxClPsaDriver_Internal.h>

/* ******************************** */
/* *** Internal structure sizes *** */
/* ******************************** */

MCUXCLCORE_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile mcuxClPsaDriver_ClnsData_Cipher_t mcuxClPsaDriver_ClnsData_Cipher;
volatile mcuxClPsaDriver_ClnsData_Aead_t mcuxClPsaDriver_ClnsData_Aead;
volatile mcuxClPsaDriver_ClnsData_Mac_t mcuxClPsaDriver_ClnsData_Mac;
volatile mcuxClPsaDriver_ClnsData_Hash_t mcuxClPsaDriver_ClnsData_Hash;
MCUXCLCORE_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
