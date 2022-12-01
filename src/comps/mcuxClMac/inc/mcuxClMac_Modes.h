/*--------------------------------------------------------------------------*/
/* Copyright 2021 NXP                                                       */
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

/** @file  mcuxClMac_Modes.h
 *  @brief Supported modes for the mcuxClMac component
 */

#ifndef MCUXCLMAC_MODES_H_
#define MCUXCLMAC_MODES_H_

#include <mcuxClConfig.h> // Exported features flags header
/**
 * @brief CMAC mode descriptor
 */
extern const mcuxClMac_ModeDescriptor_t mcuxClMac_ModeDescriptor_CMAC;

/**
 * \brief CMAC mode
 */
static mcuxClMac_Mode_t mcuxClMac_Mode_CMAC =  &mcuxClMac_ModeDescriptor_CMAC;

/**
 * @brief HMAC mode descriptor
 */
extern const mcuxClMac_ModeDescriptor_t mcuxClMac_ModeDescriptor_HMAC_CSS;

/**
 * \brief HMAC mode
 *
 * The input buffer @p in will be modified by applying padding to it. The caller
 * must ensure that the input buffer is large enough to hold this padding.
 * The total buffer size including padding can be calculated using the macro
 * #MCUXCLMAC_GET_HMAC_INPUTBUFFER_LENGTH on the data size @p inLength.
 *
 * Also note that #mcuxClMac_Mode_HMAC_SHA2_256_CSS only works with keys loaded
 * into coprocessor (see @ref mcuxClKey for details).
 *
 */
static mcuxClMac_Mode_t mcuxClMac_Mode_HMAC_SHA2_256_CSS =  &mcuxClMac_ModeDescriptor_HMAC_CSS;

/**
 * @brief CBC-MAC mode descriptor without padding
 */
extern const mcuxClMac_ModeDescriptor_t mcuxClMac_ModeDescriptor_CBCMAC_NoPadding;

/**
 * \brief CBC-MAC mode without padding
 */
static mcuxClMac_Mode_t mcuxClMac_Mode_CBCMAC_NoPadding =  &mcuxClMac_ModeDescriptor_CBCMAC_NoPadding;

/**
 * @brief CBC-MAC mode descriptor with ISO/IEC 9797-1 padding method 1 (zero padding)
 */
extern const mcuxClMac_ModeDescriptor_t mcuxClMac_ModeDescriptor_CBCMAC_PaddingISO9797_1_Method1;

/**
 * \brief CBC-MAC mode with ISO/IEC 9797-1 padding method 1 (zero padding)
 */
static mcuxClMac_Mode_t mcuxClMac_Mode_CBCMAC_PaddingISO9797_1_Method1 =  &mcuxClMac_ModeDescriptor_CBCMAC_PaddingISO9797_1_Method1;

/**
 * @brief CBC-MAC mode descriptor with ISO/IEC 9797-1 padding method 2
 */
extern const mcuxClMac_ModeDescriptor_t mcuxClMac_ModeDescriptor_CBCMAC_PaddingISO9797_1_Method2;

/**
 * \brief CBC-MAC mode with ISO/IEC 9797-1 padding method 2
 */
static mcuxClMac_Mode_t mcuxClMac_Mode_CBCMAC_PaddingISO9797_1_Method2 =  &mcuxClMac_ModeDescriptor_CBCMAC_PaddingISO9797_1_Method2;


#endif /* MCUXCLMAC_MODES_H_ */
