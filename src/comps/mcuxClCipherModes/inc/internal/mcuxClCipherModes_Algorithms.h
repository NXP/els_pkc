/*--------------------------------------------------------------------------*/
/* Copyright 2020-2022 NXP                                                  */
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

/** @file  mcuxClCipherModes_Algorithms.h
 *  @brief Supported algorithms for the mcuxClCipherModes component
 */

#ifndef MCUX_CL_CIPHERMODES_ALGORITHMS_H_
#define MCUX_CL_CIPHERMODES_ALGORITHMS_H_

#include <mcuxClConfig.h> // Exported features flags header

#include <internal/mcuxClCipherModes_Internal_Types.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @defgroup clCipherModesAlgorithms Cipher algorithm definitions
 * @brief Modes used by the Cipher operations.
 * @ingroup mcuxClCipherModes
 * @{
 */

/**
 * @brief AES ECB Encryption algorithm descriptor without padding, using CSS
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Css_t mcuxClCipherModes_AlgorithmDescriptor_AES_ECB_Enc_NoPadding_Css;

/**
 * @brief AES ECB Encryption algorithm descriptor with ISO/IEC 9797-1 padding method 1, using CSS
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Css_t mcuxClCipherModes_AlgorithmDescriptor_AES_ECB_Enc_PaddingISO9797_1_Method1_Css;

/**
 * @brief AES ECB Encryption algorithm descriptor with ISO/IEC 9797-1 padding method 2, using CSS
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Css_t mcuxClCipherModes_AlgorithmDescriptor_AES_ECB_Enc_PaddingISO9797_1_Method2_Css;

/**
 * @brief AES ECB Decryption algorithm descriptor, using CSS
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Css_t mcuxClCipherModes_AlgorithmDescriptor_AES_ECB_Dec_Css;

/**
 * @brief AES CBC Encryption algorithm descriptor without padding, using CSS
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Css_t mcuxClCipherModes_AlgorithmDescriptor_AES_CBC_Enc_NoPadding_Css;

/**
 * @brief AES CBC Encryption algorithm descriptor with ISO/IEC 9797-1 padding method 1, using CSS
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Css_t mcuxClCipherModes_AlgorithmDescriptor_AES_CBC_Enc_PaddingISO9797_1_Method1_Css;

/**
 * @brief AES CBC Encryption algorithm descriptor with ISO/IEC 9797-1 padding method 2, using CSS
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Css_t mcuxClCipherModes_AlgorithmDescriptor_AES_CBC_Enc_PaddingISO9797_1_Method2_Css;

/**
 * @brief AES CBC Decryption algorithm descriptor, using CSS
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Css_t mcuxClCipherModes_AlgorithmDescriptor_AES_CBC_Dec_Css;

/**
 * @brief CTR Encryption/Decryption algorithm descriptor, using CSS
 */
extern const mcuxClCipherModes_AlgorithmDescriptor_Aes_Css_t mcuxClCipherModes_AlgorithmDescriptor_AES_CTR_Css;






/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUX_CL_CIPHERMODES_ALGORITHMS_H_ */
