/*--------------------------------------------------------------------------*/
/* Copyright 2020, 2022 NXP                                                 */
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

/** @file  mcuxClKey_KeyTypes.c
 *  @brief Instantiation of the key types supported by the mcuxClKey component. */

#include <stddef.h>
#include <mcuxClKey.h>
#include <internal/mcuxClKey_Types_Internal.h>


// Only support ELS internal keys, only supports 256 bits HMAC keys
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_HmacSha256_variableLength = {MCUXCLKEY_ALGO_ID_HMAC + MCUXCLKEY_ALGO_ID_SYMMETRIC_KEY, 0u, NULL};

/* key types supported by coprocessor keystore only */
// HMAC internal only supports 256-bit keys
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_HmacSha256 = {MCUXCLKEY_ALGO_ID_HMAC + MCUXCLKEY_ALGO_ID_SYMMETRIC_KEY, MCUXCLKEY_SIZE_256, NULL};

