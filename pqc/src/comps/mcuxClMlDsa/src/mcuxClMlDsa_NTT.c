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
 * @file mcuxClMlDsa_NTT.c
 * @brief Implementing the number-theoretic transform (NTT) and related
 * functions for fast polynomial operations in @ref mcuxClMlDsa.
 *
 */

#include <mcuxCsslAnalysis.h>

#include <internal/mcuxClMlDsa_Internal.h>

/**
 * @brief
 * A pre-computed list of the powers of zeta in NTT computations.
 */
static const int32_t mcuxClMlDsa_Zetas[MCUXCLMLDSA_N] =
{
           0,    25847, -2608894,  -518909,   237124,  1826347,  2353451,  -777960,
     -359251, -2091905,  -876248,  3119733, -2884855,   466468,  3111497,  2680103,
     2725464,  2706023,    95776,  1024112,  3077325,  3530437, -1079900, -1661693,
    -3592148,  3585928, -2537516,  3915439,  -549488, -3861115, -3043716, -1119584,
     3574422, -2867647,  2619752,  3539968,  -300467, -2108549,  2348700,  -539299,
    -2118186, -1699267, -1643818, -3859737,  3505694, -3821735, -1399561,  3507263,
    -2140649, -3277672, -1600420,  3699596,  1757237,   811944,   531354,   -19422,
      954230,  3881043,  4010497,  3900724, -2556880,   280005,  2071892, -2797779,
    -3930395,  2091667,  3407706, -1528703,  2316500,  3817976, -3677745, -3342478,
     2244091, -3041255, -2446433, -3562462, -1452451,   266997,  2434439,  3475950,
    -1235728,  3513181,  2176455, -3520352, -3759364, -1585221, -1197226, -3193378,
    -1257611,   900702,  1859098,  1939314,   909542,   819034, -4083598,   495491,
    -1613174, -1000202,   -43260,  -522500, -3190144,  -655327, -3122442, -3157330,
     2031748,  3207046, -3632928, -3556995,  -525098,   126922,  -768622, -3595838,
     3412210,   342297,   286988,  -983419, -2437823,  4108315,  2147896,  3437287,
    -3342277,  2715295,  1735879,   203044, -2967645,  2842341,  2691481, -3693493,
    -2590150,  1265009,  -411027,  4055324,  1247620, -2477047,  2486353,  1595974,
     -671102, -3767016,  1250494, -1228525,  2635921, -3548272,   -22981, -2994039,
     1869119, -1308169,  1903435, -1050970,  -381987, -1333058,  1237275,  1349076,
    -3318210, -1430225,  1852771,  -451100,  1312455, -1430430,  3306115, -1962642,
    -3343383, -1279661,  1917081,   264944, -2546312, -1374803,   508951,  1500165,
      777191,  3097992,  2235880,  3406031,    44288,  -542412, -2831860, -1100098,
    -1671176, -1846953,   904516, -2584293, -3724270,  3958618,   594136, -3776993,
    -3724342, -2013608,  2432395,    -8578,  2454455,  -164721,  1653064,  1957272,
     3369112, -3249728,   185531, -1207385,  2389356, -3183426,   162844,  -210977,
     1616392,  3014001,   759969,   810149,  1652634, -1316856, -3694233, -1799107,
      189548, -3038916,  3523897, -3553272,  3866901,   269760,  3159746,  2213111,
     -975884, -1851402,  1717735,   472078, -2409325,  -426683,  1723600,  -177440,
    -1803090,  1910376,  1315589, -1667432, -1104333,  1341330,  -260646, -3833893,
     1285669, -2939036, -2235985, -1584928,  -420899, -2286327,  -812732,   183443,
     -976891, -1439742,  1612842, -3545687, -3019102,  -554416,  3919660, -3881060,
      -48306, -1362209, -3628969,  3937738,  1400424,  3839961,  -846154,  1976782
};

/**
 * @brief
 * Montgomery reduction of a single finite field element.
 *
 * For finite field element a with -Q * 2^{31} <= a <= +Q * 2^31,
 * compute r \equiv a * 2^{-32} (mod Q) such that -Q < r < Q.
 *
 * @param[in] a Input finite field element.
 *
 * @pre
 * The input a must satisfy -Q * 2^{31} <= a <= +Q * 2^31.
 *
 * @post
 * The output r satisfies r = a * 2^{-32} (mod Q) and -Q < r < Q.
 *
 * @return
 * The value r satisfying the above condition.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_NTT_MontgomeryReduce)
MCUX_CSSL_FP_PROTECTED_TYPE(int32_t) mcuxClMlDsa_NTT_MontgomeryReduce(
  const int64_t a
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_NTT_MontgomeryReduce);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_OPERATIONS_ON_INAPPROPRIATE_TYPE("shifting a signed integer")
  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(a, -((int64_t) MCUXCLMLDSA_Q << 31), (int64_t) MCUXCLMLDSA_Q << 31, 0)
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_OPERATIONS_ON_INAPPROPRIATE_TYPE()

  int32_t t = 0;
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("Truncated upper bits are not needed. If a value of integral type is truncated to a shorter signed integral type, the result is obtained by discarding an appropriate number of most significant bits.")
  t = (int32_t) ((int64_t)(int32_t) a * (int32_t) MCUXCLMLDSA_QINV);
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_OPERATIONS_ON_INAPPROPRIATE_TYPE("shifting a signed integer")
  t = mcuxClMlDsa_SignedHi64_ToLo32(a - ((int64_t) t * (int32_t) MCUXCLMLDSA_Q));
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_OPERATIONS_ON_INAPPROPRIATE_TYPE()

  MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(t, INT32_MIN, INT32_MAX, 0)
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_NTT_MontgomeryReduce, t);
}

MCUX_CSSL_ANALYSIS_START_SUPPRESS_NESTED_COMMENTS("Links are allowed in comments.")
/**
 * @brief
 * In-place forward NTT computation.
 *
 * For implementation details, see Algorithm 35 (p.36) of
 *   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.ipd.pdf
 *
 * @param[in,out] pA Pointer to input/output polynomial.
 *
 * @pre
 * pA is not in the NTT domain.
 *
 * @post
 * pA is in the NTT domain.
 */
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NESTED_COMMENTS()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_NTT_ForwardNTT)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_NTT_ForwardNTT(
  mcuxClMlDsa_Poly_t* const pA
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_NTT_ForwardNTT);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_ForwardNTT_asm(pA, mcuxClMlDsa_Zetas));
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_NTT_ForwardNTT, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_ForwardNTT_asm));
}

MCUX_CSSL_ANALYSIS_START_SUPPRESS_NESTED_COMMENTS("Links are allowed in comments.")
/**
 * @brief
 * In-place inverse NTT calculation, and multiplication by 2^32.
 *
 * For implementation details, see Algorithm 36 (p.37) of
 *   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.ipd.pdf
 *
 * @param[in,out] pA Pointer to input/output polynomial.
 *
 * @pre
 * pA is in the NTT domain.
 *
 * @post
 * pA is converted back from the NTT domain.
 */
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_NESTED_COMMENTS()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_NTT_InverseNTTToMont)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_NTT_InverseNTTToMont(
  mcuxClMlDsa_Poly_t* const pA
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_NTT_InverseNTTToMont);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_InverseNTT_asm(pA, mcuxClMlDsa_Zetas));
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_NTT_InverseNTTToMont, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_InverseNTT_asm));
}

/**
 * @brief
 * Multiplication in the NTT domain and division by 2^{32}.
 *
 * Performs pointwise multiplication of polynomials in the NTT
 * domain representation and multiplies the resulting polynomial
 * by 2^{-32}.
 *
 * @param[out] pC Pointer to output polynomial.
 * @param[in] pA Pointer to first input polynomial.
 * @param[in] pB Pointer to second input polynomial.
 *
 * @pre
 * Both pA and pB are already in the NTT domain.
 *
 * @post
 * pC is the pointwise multiplication of pA and pB, divided by 2^{32}.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_NTT_PointwiseMontgomery)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_NTT_PointwiseMontgomery(
  mcuxClMlDsa_Poly_t* const pC,
  const mcuxClMlDsa_Poly_t* const pA,
  const mcuxClMlDsa_Poly_t* const pB
)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_NTT_PointwiseMontgomery);
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_NTT_PointMont_asm(pC, pA, pB));
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_NTT_PointwiseMontgomery, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_NTT_PointMont_asm));
}
