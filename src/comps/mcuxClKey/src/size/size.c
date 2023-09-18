/*--------------------------------------------------------------------------*/
/* Copyright 2021-2023 NXP                                                  */
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

#include <mcuxClCore_Platform.h>
#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClKey_Types_Internal.h>




/** Round up a size (in bytes) to a multiple of the CPU wordsize (4 bytes). */
#define MCUXCLKEY_ROUND_UP_TO_CPU_WORDSIZE(size) \
    ((((size) + sizeof(uint32_t) - 1U ) / (sizeof(uint32_t))) * (sizeof(uint32_t)))

#define MCUXCLKEY_MAX(value0, value1)  (((value0) > (value1)) ? (value0) : (value1))

/* *********************** */
/* *** Structure sizes *** */
/* *********************** */

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile uint8_t mcuxClKey_DescriptorSize[sizeof(mcuxClKey_Descriptor_t)];
volatile uint8_t mcuxClKey_TypeDescriptorSize[sizeof(mcuxClKey_TypeDescriptor_t)];

MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
