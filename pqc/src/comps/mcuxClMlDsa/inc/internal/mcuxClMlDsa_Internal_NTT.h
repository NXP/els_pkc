/*--------------------------------------------------------------------------*/
/* Copyright 2021-2026 NXP                                                  */
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
 *
 * @file mcuxClMlDsa_Internal_NTT.h
 * @brief Interface for NTT computations in @ref mcuxClMlDsa.
 *
 */

#ifndef MCUXCLMLDSA_INTERNAL_NTT_H_
#define MCUXCLMLDSA_INTERNAL_NTT_H_

#include <mcuxCsslFlowProtection.h>
#include <internal/mcuxClMlDsa_Internal_Types.h>

/**
 * @brief
 * Montgomery reduction.
 *
 * For finite field element a with -2^{31}*Q <= a <= Q*2^31,
 * compute r \equiv a*2^{-32} (mod Q) such that -Q < r < Q.
 *
 * @param[in] a Finite field element
 *
 * @pre
 * -2^{31} * Q <= a <= +2^31 * Q
 *
 * @post
 * r \equiv a * 2^{-32} (mod Q) s.t. -Q < r < Q
 *
 * @return Returns the centered value r between -Q and Q.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_NTT_MontgomeryReduce)
MCUX_CSSL_FP_PROTECTED_TYPE(int32_t) mcuxClMlDsa_NTT_MontgomeryReduce(
  const int64_t a
);


MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("This function might be implemented in assembly, depending on feature flag.")
/**
 * @brief
 * ARM assembly implementation of in-place forward NTT.
 *
 * ARM assembly implementation of the forward Number Theoretic Transform.
 *
 * @param[in,out] pA Pointer to input/output polynomial coefficients (256 elements)
 * @param[in] zetas Pointer to a pre-computed list of the powers of zeta in NTT computations
 *
 * @pre
 * - pA points to a valid polynomial with 256 coefficients in NTT domain
 * - zetas points to a pre-computed list of the powers of zeta in NTT computations
 *
 * @post
 * - Expunges pA and zetas
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_NTT_ForwardNTT_asm)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_NTT_ForwardNTT_asm(mcuxClMlDsa_Poly_t* const pA, const int32_t* zetas);


/**
 * @brief
 * In-place forward NTT.
 * Coefficients can grow by 8*Q in absolute value.
 *
 * @param[in,out] pA Pointer to input/output polynomial
 *
 * @post
 * No modular reduction is performed, so output coefficients can be large.
 * The output vector is in bit-reversed order.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_NTT_ForwardNTT)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_NTT_ForwardNTT(
  mcuxClMlDsa_Poly_t* const pA
);
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()


MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("This function might be implemented in assembly, depending on feature flag.")
/**
 * @brief
 * ARM assembly implementation of in-place inverse NTT with Montgomery multiplication.
 *
 * ARM assembly implementation of the inverse Number Theoretic Transform.
 *
 * @param[in,out] pA Pointer to input/output polynomial coefficients (256 elements)
 * @param[in] zetas Pointer to a pre-computed list of the powers of zeta in NTT computations
 *
 * @pre
 * - pA points to a valid polynomial with 256 coefficients in NTT domain
 * - zetas points to a pre-computed list of the powers of zeta in NTT computations
 *
 * @post
 * - Expunges pA and zetas
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_NTT_InverseNTT_asm)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_NTT_InverseNTT_asm(mcuxClMlDsa_Poly_t* const pA, const int32_t* zetas);

/**
 * @brief
 * In-place inverse NTT and multiplication by 2^{32}.
 *
 * Inplace inverse NTT and multiplication by 2^{32}.
 * Input coefficients need to be less than Q in absolute
 * value and output coefficients are again bounded by Q.
 *
 * @pre
 * |a[i]| <= Q for all i
 *
 * @post
 * |a[i]| <= Q for all i
 *
 * @param[in,out] pA Pointer to input/output polynomial
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_NTT_InverseNTTToMont)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_NTT_InverseNTTToMont(
  mcuxClMlDsa_Poly_t* const pA
);
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()

MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("This function might be implemented in assembly, depending on feature flag.")
/**
 * @brief
 * ARM assembly implementation of pointwise Montgomery multiplication in NTT domain.
 *
 * Optimized ARM assembly implementation for pointwise multiplication of two
 * polynomials in NTT domain representation.
 *
 * @param[out] pC Pointer to output polynomial.
 * @param[in] pA Pointer to first input polynomial.
 * @param[in] pB Pointer to second input polynomial.
 *
 * @pre
 * - pA, pB, pC point to valid polynomials with 256 coefficients each
 *
 * @post
 * - pC contains the pointwise product pA[i] * pB[i] for i = 0..255
 * - Each product is multiplied by 2^{-32}
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_NTT_PointMont_asm)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_NTT_PointMont_asm(mcuxClMlDsa_Poly_t* const pC, const mcuxClMlDsa_Poly_t* const pA, const mcuxClMlDsa_Poly_t* const pB);

/**
 * @brief ML-DSA polynomial multiplication in the NTT domain
 *
 * Pointwise multiplication of polynomials in NTT domain representation
 * and multiplication of resulting polynomial by 2^{-32}.
 *
 * @param[out] pC Pointer to output polynomial
 * @param[in] pA Pointer to first input polynomial
 * @param[in] pB Pointer to second input polynomial
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMlDsa_NTT_PointwiseMontgomery)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_NTT_PointwiseMontgomery(
  mcuxClMlDsa_Poly_t* const pC,
  const mcuxClMlDsa_Poly_t* const pA,
  const mcuxClMlDsa_Poly_t* const pB
);
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()

#endif /* MCUXCLMLDSA_INTERNAL_NTT_H_ */
