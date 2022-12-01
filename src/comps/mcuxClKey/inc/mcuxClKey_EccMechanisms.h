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
 * @file  mcuxClKey_EccMechanisms.h
 * @brief Provide API for ECC key related mechanisms
 */

#ifndef MCUX_CL_KEY_ECC_MECHANISMS_H_
#define MCUX_CL_KEY_ECC_MECHANISMS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClKey_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup mcuxClAPI MCUX CL -- API
 *
 * @addtogroup mcuxClKey Key API
 * @brief Key handling operations.
 * @ingroup mcuxClAPI
 */

/**
 * @defgroup clEccKeyMechanisms Key mechanism definitions for ECC
 * @brief Mechanisms used by the ECC Key operations.
 * @ingroup mcuxClKey
 * @{
 */

/* TODO CLNS-5403: Move these ECC-specifics to the ECC component */

/**
 * @brief ECDH Key agreement algorithm descriptor
 */
extern const mcuxClKey_AgreementDescriptor_t mcuxClKey_AgreementDescriptor_ECDH;

/**
 * @brief ECDH Key agreement algorithm
 */
static mcuxClKey_Agreement_t mcuxClKey_Agreement_ECDH =
  &mcuxClKey_AgreementDescriptor_ECDH;

/**
 * @brief ECDH Key generation algorithm descriptor
 */
extern const mcuxClKey_GenerationDescriptor_t mcuxClKey_GenerationDescriptor_ECDH;

/**
 * @brief ECDH Key generation algorithm
 */
static mcuxClKey_Generation_t mcuxClKey_Generation_ECDH =
  &mcuxClKey_GenerationDescriptor_ECDH;

/**
 * @brief ECDSA Key generation algorithm descriptor
 */
extern const mcuxClKey_GenerationDescriptor_t mcuxClKey_GenerationDescriptor_ECDSA;

/**
 * @brief ECDSA Key generation algorithm
 */
static mcuxClKey_Generation_t mcuxClKey_Generation_ECDSA =
  &mcuxClKey_GenerationDescriptor_ECDSA;

/** @} */

#endif /* MCUX_CL_KEY_ECC_MECHANISMS_H_ */

#ifdef __cplusplus
} /* extern "C" */
#endif
