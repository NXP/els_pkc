/*--------------------------------------------------------------------------*/
/* Copyright 2020-2024 NXP                                                  */
/*                                                                          */
/* NXP Proprietary. This software is owned or controlled by NXP and may     */
/* only be used strictly in accordance with the applicable license terms.   */
/* By expressly accepting such terms or by downloading, installing,         */
/* activating and/or otherwise using the software, you are agreeing that    */
/* you have read, and that you agree to comply with and are bound by, such  */
/* license terms.  If you do not agree to be bound by the applicable        */
/* license terms, then you may not retain, install, activate or otherwise   */
/* use the software.                                                        */
/*--------------------------------------------------------------------------*/

/**
 * @file  mcuxClEcc_ECDSA_Internal.h
 * @brief internal header for ECDSA
 */


#ifndef MCUXCLECC_ECDSA_INTERNAL_H_
#define MCUXCLECC_ECDSA_INTERNAL_H_


#include <mcuxClCore_Platform.h>
#include <mcuxClEcc_Types.h>
#include <mcuxClKey_Types.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClSession.h>
#include <mcuxClBuffer.h>
#ifdef MCUXCL_FEATURE_ECC_ECDSA_DETERMINISTIC
#include <mcuxClMac.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Blinded secret key generation function structure for ECDSA ephemeral key generation.
 */
MCUX_CSSL_FP_FUNCTION_POINTER(mcuxClEcc_ECDSA_EphemeralKeyGenFunction_t,
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) (*mcuxClEcc_ECDSA_EphemeralKeyGenFunction_t)(mcuxClSession_Handle_t pSession,
                                                                                                  const mcuxClEcc_Sign_Param_t * pParam));


/**
 * This function implements an ECDSA ephemeral key generation according to the method
 * "ECDSA Key Pair Generation using Extra Random Bits" specified in appendix A.2.1 of FIPS 186-5.
 * The generation is done in a blinded way and the ephemeral key k is output multiplicatively split
 * as k0 and k1, satisfying k0*k1 mod n = k = (c mod (n-1)) + 1, in which k is derived from a
 * (bitLen(n)+64)-bit true (DRBG) random number c and k0 is a 64-bit random number (with bit 63 set).
 *
 * Inputs:
 *   pSession: pointer to the current session
 *   pParam:   Pointer to the input parameters of the mcuxClEcc_Sign function
 *
 * Inputs in pOperands[] and PKC workarea: N/A.
 *
 * Prerequisites:
 *   ps1Len = (operandSize, operandSize);
 *   curve order n in N, NDash of n in NFULL;
 *   no on-going calculation on N;
 *   buffers S0, S1, S2 and S3 are with doubled-size (2*operandSize).
 *
 * Result in PKC workarea:
 *   buffers S0 and S1 contain multiplicative split private key k0 and k1 (operandSize);
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_ECDSA_BlindedEphemeralKeyGen_RandomWithExtraBits, mcuxClEcc_ECDSA_EphemeralKeyGenFunction_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_ECDSA_BlindedEphemeralKeyGen_RandomWithExtraBits(
    mcuxClSession_Handle_t pSession,
    const mcuxClEcc_Sign_Param_t * pParam);


#ifdef MCUXCL_FEATURE_ECC_ECDSA_DETERMINISTIC
/**
 * This function implements a deterministic ECDSA ephemeral key generation according to RFC 6979.
 * The generation is done in a blinded way and the ephemeral key k is output multiplicatively split
 * as k0 and k1, satisfying k0*k1 mod n = k = (c mod (n-1)) + 1, in which k is derived from a
 * (bitLen(n)+64)-bit true (DRBG) random number c and k0 is a 64-bit random number (with bit 63 set).
 *
 * Inputs:
 *   pSession: pointer to the current session
 *   pParam:   Pointer to the input parameters of the mcuxClEcc_Sign function
 *
 * Inputs in pOperands[] and PKC workarea: N/A.
 *
 * Prerequisites:
 *   ps1Len = (operandSize, operandSize);
 *   curve order n in N, NDash of n in NFULL;
 *   no on-going calculation on N;
 *   buffers S0, S1, S2 and S3 are with doubled-size (2*operandSize).
 *
 * Result in PKC workarea:
 *   buffers S0 and S1 contain multiplicative split private key k0 and k1 (operandSize);
 *
 * @attention The PKC calculation might be still on-going, call #mcuxClPkc_WaitForFinish before CPU accesses to the result.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_ECDSA_BlindedEphemeralKeyGen_Deterministic, mcuxClEcc_ECDSA_EphemeralKeyGenFunction_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_ECDSA_BlindedEphemeralKeyGen_Deterministic(
    mcuxClSession_Handle_t pSession,
    const mcuxClEcc_Sign_Param_t * pParam);
#endif /* MCUXCL_FEATURE_ECC_ECDSA_DETERMINISTIC */


/**
 *  ECDSA SignatureProtocol variant structure.
 */
struct mcuxClEcc_ECDSA_SignatureProtocolDescriptor
{
    mcuxClEcc_ECDSA_EphemeralKeyGenFunction_t pBlindedEphemeralKeyGenFct; ///< Function to be generate multiplicatively split ephemeral key in blinded way
    uint32_t pBlindedEphemeralKeyGenFct_FP_FuncId;                       ///< ID of function to be used for ephemeral key generation
#ifdef MCUXCL_FEATURE_ECC_ECDSA_DETERMINISTIC
    const mcuxClMac_ModeDescriptor_t *pHmacModeDesc;                      ///< HMAC mode
#endif /* MCUXCL_FEATURE_ECC_ECDSA_DETERMINISTIC */
};


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLECC_ECDSA_INTERNAL_H_ */
