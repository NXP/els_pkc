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
#include <mcuxClEcc.h>
#include <mcuxClEcc_Constants.h> // Direct include for backward compatibility on other platforms

// oscca sm4 key
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_SM4 = {MCUX_CL_KEY_ALGO_ID_SM4 + MCUX_CL_KEY_ALGO_ID_SYMMETRIC_KEY, MCUX_CL_KEY_SIZE_128, NULL};

// Only support CSS internal keys, only supports 256 bits HMAC keys
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_HmacSha256_variableLength = {MCUX_CL_KEY_ALGO_ID_HMAC + MCUX_CL_KEY_ALGO_ID_SYMMETRIC_KEY, 0u, NULL};

/* key types supported by coprocessor keystore only */
// HMAC internal only supports 256-bit keys
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_HmacSha256 = {MCUX_CL_KEY_ALGO_ID_HMAC + MCUX_CL_KEY_ALGO_ID_SYMMETRIC_KEY, MCUX_CL_KEY_SIZE_256, NULL};

// ECC keys
/* TODO CLNS-5403: Move ECC keyTypes to ECC component, and assure consistent naming (e.g.: Ecc_Weier_NIST_* could also include SHWS in the naming?)
 *                                                                + correct keysize. Discuss with Arch and CO how keyTypes are to be used within ECC! */
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Ecc_Weier_NIST_P256_Pub  = {MCUX_CL_KEY_ALGO_ID_ECC_SHWS_GFP + MCUX_CL_KEY_ALGO_ID_PUBLIC_KEY, MCUX_CL_KEY_SIZE_512, (void*) &mcuxClEcc_Weier_DomainParams_secp256r1};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Ecc_Weier_NIST_P256_Priv = {MCUX_CL_KEY_ALGO_ID_ECC_SHWS_GFP + MCUX_CL_KEY_ALGO_ID_PRIVATE_KEY, MCUX_CL_KEY_SIZE_256, (void*) &mcuxClEcc_Weier_DomainParams_secp256r1};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_EdDSA_Ed25519_KeyPair = {MCUX_CL_KEY_ALGO_ID_ECC_EDDSA | MCUX_CL_KEY_ALGO_ID_KEY_PAIR, MCUX_CL_KEY_SIZE_NOTUSED, (void*) &mcuxClEcc_EdDSA_DomainParams_Ed25519};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_EdDSA_Ed448_KeyPair = {MCUX_CL_KEY_ALGO_ID_ECC_EDDSA | MCUX_CL_KEY_ALGO_ID_KEY_PAIR, MCUX_CL_KEY_SIZE_NOTUSED, (void*) &mcuxClEcc_EdDSA_DomainParams_Ed448};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Ecc_MontDH_Curve25519_KeyPair = {MCUX_CL_KEY_ALGO_ID_ECC_MONTDH | MCUX_CL_KEY_ALGO_ID_KEY_PAIR, MCUX_CL_KEY_SIZE_NOTUSED, (void*) &mcuxClEcc_MontDH_DomainParams_Curve25519};
const mcuxClKey_TypeDescriptor_t mcuxClKey_TypeDescriptor_Ecc_MontDH_Curve448_KeyPair = {MCUX_CL_KEY_ALGO_ID_ECC_MONTDH | MCUX_CL_KEY_ALGO_ID_KEY_PAIR, MCUX_CL_KEY_SIZE_NOTUSED, (void*) &mcuxClEcc_MontDH_DomainParams_Curve448};
