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

/** @file  mcuxClMac_Internal_Constants.h
 *  @brief header for mac constants.
 */

#ifndef MCUXCLMAC_CONSTANTS_H_
#define MCUXCLMAC_CONSTANTS_H_

#include <mcuxClConfig.h> // Exported features flags header

/**********************************************
 * CONSTANTS
 **********************************************/

#define MCUXCLMAC_HASH_BLOCK_SIZE_SHA_256        (64U)
#define MCUXCLMAC_HMAC_OUTPUT_SIZE_SHA_256       (32U)

#define MCUXCLMAC_CMAC_OUTPUT_SIZE (16U) ///< Size of CMAC output: 128 bits (16 bytes)

#define  MCUXCLMAC_MAX_OUTPUT_SIZE ((MCUXCLMAC_HMAC_OUTPUT_SIZE_SHA_256 > MCUXCLMAC_CMAC_OUTPUT_SIZE) \
  ? MCUXCLMAC_HMAC_OUTPUT_SIZE_SHA_256 : MCUXCLMAC_CMAC_OUTPUT_SIZE)


#endif /* MCUXCLMAC_CONSTANTS_H_ */
