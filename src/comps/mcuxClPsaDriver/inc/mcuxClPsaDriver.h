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

/** @file  mcuxClPsaDriver.h
 *  @brief Additional macros for the ARM PSA driver
 */

#ifndef MCUXCLPSADRIVER_H_
#define MCUXCLPSADRIVER_H_


#include <crypto.h>
#include <psa_crypto_driver_wrappers.h>
#include <mcuxClConfig.h> // Exported features flags header

#define MCUXCLPSADRIVER_IS_LOCAL_STORAGE(location) ((location) == PSA_KEY_LOCATION_LOCAL_STORAGE)

#define PSA_KEY_LOCATION_EXTERNAL_STORAGE ((psa_key_location_t)(PSA_KEY_LOCATION_VENDOR_FLAG | 0x00U))

#endif /* MCUXCLPSADRIVER_H_ */
