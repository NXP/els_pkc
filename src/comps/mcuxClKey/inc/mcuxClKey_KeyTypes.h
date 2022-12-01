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

/**
 * @file  mcuxClKey_KeyTypes.h
 * @brief Definition of supported key types in mcuxClKey component
 */

#ifndef MCUX_CL_KEY_KEYTYPES_H_
#define MCUX_CL_KEY_KEYTYPES_H_

#include <stdint.h>
#include <stdbool.h>

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClKey_Types.h>

/**
 * @defgroup mcuxClKey_KeyTypes mcuxClKey_KeyTypes
 * @brief Defines of supported key types of @ref mcuxClKey
 * @ingroup mcuxClKey
 * @{
 */

/**********************************************
 * TYPEDEFS
 **********************************************/


/**
 * \brief Key type structure for HMAC-SHA256 based keys with variable length.
 *
 */
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_HmacSha256_variableLength;

/**
 * \brief Key type pointer for HMAC-SHA256 based keys with variable length.
 */
static const mcuxClKey_Type_t mcuxClKey_Type_HmacSha256_variableLength = &mcuxClKey_TypeDescriptor_HmacSha256_variableLength;

/**
 * @brief Key type structure for HMAC-SHA256 based keys.
 *
 */
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_HmacSha256;

/**
 * @brief Key type pointer for HMAC-SHA256 based keys.
 */
static const mcuxClKey_Type_t mcuxClKey_Type_HmacSha256 = &mcuxClKey_TypeDescriptor_HmacSha256;

/**
 * @brief Key type structure for OSCCA SM4 based keys.
 *
 */
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_SM4;

/**
 * @brief Key type pointer for OSCCA SM4 keys.
 */
static const mcuxClKey_Type_t mcuxClKey_Type_SM4 = &mcuxClKey_TypeDescriptor_SM4;


/* TODO CLNS-5403: Move ECC keyTypes to ECC component */


/**
 * @brief Key type structure for public ECC Weierstrass P256 Keys.
 *
 */
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Ecc_Weier_NIST_P256_Pub;

/**
 * @brief Key type pointer for public ECC Weierstrass P256 Keys.
 *
 */
static const mcuxClKey_Type_t mcuxClKey_Type_Ecc_Weier_NIST_P256_Pub = &mcuxClKey_TypeDescriptor_Ecc_Weier_NIST_P256_Pub;

/**
 * @brief Key type structure for private ECC Weierstrass P256 Keys.
 *
 */
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Ecc_Weier_NIST_P256_Priv;

/**
 * @brief Key type pointer for private ECC Weierstrass P256 Keys.
 *
 */
static const mcuxClKey_Type_t mcuxClKey_Type_Ecc_Weier_NIST_P256_Priv = &mcuxClKey_TypeDescriptor_Ecc_Weier_NIST_P256_Priv;


/**
 * @brief Key type structure for ECC EdDSA Ed25519 Key pairs.
 *
 */
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_EdDSA_Ed25519_KeyPair;

/**
 * @brief Key type pointer for ECC EdDSA Ed25519 Key pairs.
 *
 */
static const mcuxClKey_Type_t mcuxClKey_Type_EdDSA_Ed25519_KeyPair = &mcuxClKey_TypeDescriptor_EdDSA_Ed25519_KeyPair;

/**
 * @brief Key type structure for ECC EdDSA Curve448 Key pairs.
 *
 */
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_EdDSA_Ed448_KeyPair;

/**
 * @brief Key type pointer for ECC EdDSA Curve448 Key pairs.
 *
 */
static const mcuxClKey_Type_t mcuxClKey_Type_EdDSA_Ed448_KeyPair = &mcuxClKey_TypeDescriptor_EdDSA_Ed448_KeyPair;


/**
 * @brief Key type structure for ECC MontDH Curve25519 Key pairs.
 *
 */
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Ecc_MontDH_Curve25519_KeyPair;

/**
 * @brief Key type pointer for ECC MontDH Curve25519 Key pairs.
 *
 */
static const mcuxClKey_Type_t mcuxClKey_Type_Ecc_MontDH_Curve25519_KeyPair = &mcuxClKey_TypeDescriptor_Ecc_MontDH_Curve25519_KeyPair;

/**
 * @brief Key type structure for ECC MontDH Curve448 Key pairs.
 *
 */
extern const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Ecc_MontDH_Curve448_KeyPair;

/**
 * @brief Key type pointer for ECC MontDH Curve448 Key pairs.
 *
 */
static const mcuxClKey_Type_t mcuxClKey_Type_Ecc_MontDH_Curve448_KeyPair = &mcuxClKey_TypeDescriptor_Ecc_MontDH_Curve448_KeyPair;


/**
 * @}
 */ /* mcuxClKey_KeyTypes */

#endif /* MCUX_CL_KEY_KEYTYPES_H_ */