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
 * @file  mcuxClEcc_EdDSA_Internal.h
 * @brief internal header of mcuxClEcc EdDSA functionalities
 */


#ifndef MCUXCLECC_EDDSA_INTERNAL_H_
#define MCUXCLECC_EDDSA_INTERNAL_H_


#include <stdint.h>

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Buffer.h>
#include <mcuxClMemory.h>
#include <mcuxClPkc.h>
#include <mcuxClHash_Types.h>

#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_EdDSA_Internal_PkcWaLayout.h>


/**********************************************************/
/* Internal return codes for EdDSA functions              */
/**********************************************************/
// None


/**********************************************************/
/* Internal EdDSA defines                                 */
/**********************************************************/

/**
 * Options for EdDSA key pair generation descriptors
 */
#define MCUXCLECC_EDDSA_PRIVKEY_INPUT     (0xA5A5A5A5U)  ///< the private key d is passed as input
#define MCUXCLECC_EDDSA_PRIVKEY_GENERATE  (0X5A5A5A5AU)  ///< the private key is generated internally


/**********************************************************/
/* Internal EdDSA types                                   */
/**********************************************************/

/**
 * Domain parameter structure for TwEd functions.
 */
struct mcuxClEcc_EdDSA_DomainParams
{
    mcuxClEcc_CommonDomainParams_t common;  ///< structure containing pointers and lengths for common ECC parameters (see Common ECC Domain parameters)
    uint16_t b;                            ///< Integer satisfying 2^(b-1) > p. EdDSA public keys have exactly b bits, and EdDSA signatures have exactly 2*b bits.
    uint16_t c;                            ///< cofactor exponent
    uint16_t t;                            ///< bit position of MSBit of decoded scalar
    uint8_t *pSqrtMinusOne;                ///< Pointer to a square root of -1 modulo p which is needed for point decoding in case p = 5 mod 8 (i.e. only needed for Ed25519, not for Ed448)
    mcuxClHash_Algo_t algoSecHash;          ///< Hash algorithm descriptor of the hash function H() to be used for hashing the private key hash (see Public and private keys)
    mcuxClHash_Algo_t algoHash;             ///< Hash algorithm descriptor of the hash function H() to be used for hashing the private key, public data and plaintext messages
};

/**********************************************************/
/* Declarations for internal EdDSA functions              */
/**********************************************************/

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_EdDSA_SetupEnvironment)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_EdDSA_SetupEnvironment(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_EdDSA_DomainParams_t *pDomainParams,
    uint8_t noOfBuffers
    );


#endif /* MCUXCLECC_EDDSA_INTERNAL_H_ */
