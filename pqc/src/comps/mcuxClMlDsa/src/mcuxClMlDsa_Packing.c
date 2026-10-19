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
 * @file mcuxClMlDsa_Packing.c
 * @brief Implementing packing/unpacking operations in @ref mcuxClMlDsa.
 *
 */

#include <mcuxCsslAnalysis.h>

#include <mcuxClCore_Macros.h>
#include <mcuxClBuffer.h>
#include <mcuxClMlDsa.h>

#include <internal/mcuxClBuffer_Internal.h>
#include <internal/mcuxClMemory_Internal.h>
#include <internal/mcuxClMlDsa_Internal.h>
#include <internal/mcuxClSession_Internal.h>

/*************************************************
 * Name:        mcuxClMlDsa_Packing_Eta_Pack
 *
 * Description: Bit-pack polynomial with coefficients in [-ETA,ETA].
 *
 * Arguments:   - uint8_t *r: pointer to output byte array with at least
 *                            POLYETA_PACKEDBYTES bytes
 *              - const mcuxClMlDsa_Poly_t *a: pointer to input polynomial
 *              - const mcuxClMlDsa_Params_t *params: ML-DSA parameter set structure
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_Eta_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_Eta_Pack(
  uint8_t *r,
  const mcuxClMlDsa_Poly_t *a,
  const mcuxClMlDsa_Params_t *params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_Eta_Pack);
  uint16_t i;
  int8_t t[8];
  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(params->eta, MCUXCLMLDSA_MLDSA44_ETA, MCUXCLMLDSA_MLDSA65_ETA)
  const int8_t ETA = (int8_t)params->eta;

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pTs are 8 bit aligned")
  uint8_t* pT = (uint8_t*)t;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  if(ETA == 2)
  {
    for(i = 0U; i < MCUXCLMLDSA_N / 8U; ++i)
    {
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("2 - x for x in [-2, 2] is in [0, 4]")
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("Signed numbers will be represented as compressed byte array for storage and transfer purposes")
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
      t[0U] = ETA - (int8_t)a->coefficients[8U * i + 0U];
      t[1U] = ETA - (int8_t)a->coefficients[8U * i + 1U];
      t[2U] = ETA - (int8_t)a->coefficients[8U * i + 2U];
      t[3U] = ETA - (int8_t)a->coefficients[8U * i + 3U];
      t[4U] = ETA - (int8_t)a->coefficients[8U * i + 4U];
      t[5U] = ETA - (int8_t)a->coefficients[8U * i + 5U];
      t[6U] = ETA - (int8_t)a->coefficients[8U * i + 6U];
      t[7U] = ETA - (int8_t)a->coefficients[8U * i + 7U];
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

      r[3U * i + 0U] = (uint8_t)(pT[0] >> 0U) | (uint8_t)(pT[1] << 3U) | (uint8_t)(pT[2] << 6U);
      r[3U * i + 1U] = (uint8_t)(pT[2] >> 2U) | (uint8_t)(pT[3] << 1U) | (uint8_t)(pT[4] << 4U) | (uint8_t)(pT[5] << 7U);
      r[3U * i + 2U] = (uint8_t)(pT[5] >> 1U) | (uint8_t)(pT[6] << 2U) | (uint8_t)(pT[7] << 5U);
    }
  }
  else if(ETA == 4)
  {
    for(i = 0U; i < MCUXCLMLDSA_N / 2U; ++i)
    {
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("4 - x for x in [-4, 4] is in [0, 8]")
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("Signed numbers will be represented as compressed byte array for storage and transfer purposes")
       MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
      t[0U] = ETA - (int8_t)a->coefficients[2U * i + 0U];
      t[1U] = ETA - (int8_t)a->coefficients[2U * i + 1U];
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
      r[i] = (uint8_t)pT[0U] | (uint8_t)(pT[1U] << 4U);
    }
  }
  else
  {
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_Eta_Pack);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_Eta_Pack);
}


/*************************************************
 * Name:        mcuxClMlDsa_Packing_Eta_Unpack
 *
 * Description: Unpack polynomial with coefficients in [-ETA,ETA].
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *r: pointer to output polynomial
 *              - const uint8_t *a: byte array with bit-packed polynomial
 *              - const mcuxClMlDsa_Params_t *params: ML-DSA parameter set structure
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_Eta_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_Eta_Unpack(
  mcuxClMlDsa_Poly_t *r,
  const uint8_t *a,
  const mcuxClMlDsa_Params_t *params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_Eta_Unpack);
  uint16_t i;
  int32_t ETA = (int32_t)params->eta;

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pCoeffs are 32 bit aligned")
  uint32_t* pCoeffs = (uint32_t*)r->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  if(ETA == 2)
  {
    for(i = 0U; i < MCUXCLMLDSA_N / 8U; ++i)
    {
      pCoeffs[8U * i + 0U] = (((uint32_t)a[3U * i + 0U] >> 0U) & 7U);
      pCoeffs[8U * i + 1U] = (((uint32_t)a[3U * i + 0U] >> 3U) & 7U);
      pCoeffs[8U * i + 2U] = ((((uint32_t)a[3U * i + 0U] >> 6U) | ((uint32_t)a[3U * i + 1U] << 2U)) & 7U);
      pCoeffs[8U * i + 3U] = (((uint32_t)a[3U * i + 1U] >> 1U) & 7U);
      pCoeffs[8U * i + 4U] = (((uint32_t)a[3U * i + 1U] >> 4U) & 7U);
      pCoeffs[8U * i + 5U] = ((((uint32_t)a[3U * i + 1U] >> 7U) | ((uint32_t)a[3U * i + 2U] << 1U)) & 7U);
      pCoeffs[8U * i + 6U] = (((uint32_t)a[3U * i + 2U] >> 2U) & 7U);
      pCoeffs[8U * i + 7U] = (((uint32_t)a[3U * i + 2U] >> 5U) & 7U);

      r->coefficients[8U * i + 0U] = ETA - r->coefficients[8U * i + 0U];
      r->coefficients[8U * i + 1U] = ETA - r->coefficients[8U * i + 1U];
      r->coefficients[8U * i + 2U] = ETA - r->coefficients[8U * i + 2U];
      r->coefficients[8U * i + 3U] = ETA - r->coefficients[8U * i + 3U];
      r->coefficients[8U * i + 4U] = ETA - r->coefficients[8U * i + 4U];
      r->coefficients[8U * i + 5U] = ETA - r->coefficients[8U * i + 5U];
      r->coefficients[8U * i + 6U] = ETA - r->coefficients[8U * i + 6U];
      r->coefficients[8U * i + 7U] = ETA - r->coefficients[8U * i + 7U];
    }
  }
  else if(ETA == 4)
  {
    for(i = 0U; i < MCUXCLMLDSA_N / 2U; ++i)
    {
      pCoeffs[2U * i + 0U] = ((uint32_t)a[i] & 0x0FU);
      pCoeffs[2U * i + 1U] = ((uint32_t)a[i] >> 4U);
      r->coefficients[2U * i + 0U] = ETA - r->coefficients[2U * i + 0U];
      r->coefficients[2U * i + 1U] = ETA - r->coefficients[2U * i + 1U];
    }
  }
  else
  {
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_Eta_Unpack);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_Eta_Unpack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_T1_Pack
 *
 * Description: Bit-pack polynomial t1 with coefficients fitting in 10 bits.
 *              Input coefficients are assumed to be standard representatives.
 *
 * Arguments:   - uint8_t *r: pointer to output byte array with at least
 *                            POLYT1_PACKEDBYTES bytes
 *              - const mcuxClMlDsa_Poly_t *a: pointer to input polynomial
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_T1_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_T1_Pack(uint8_t *r, const mcuxClMlDsa_Poly_t *a)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_T1_Pack);
  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pCoeffs are 32 bit aligned")
  const uint32_t* pCoeffs = (const uint32_t*)a->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  for(uint16_t i = 0U; i < MCUXCLMLDSA_N / 4U; ++i)
  {
    r[5U*i+0U] = (uint8_t)(pCoeffs[4U*i+0U] >> 0U & 0xFFU);
    r[5U*i+1U] = (uint8_t)(pCoeffs[4U*i+0U] >> 8U & 0xFFU) | (uint8_t)(pCoeffs[4U*i+1U] << 2U & 0xFFU);
    r[5U*i+2U] = (uint8_t)(pCoeffs[4U*i+1U] >> 6U & 0xFFU) | (uint8_t)(pCoeffs[4U*i+2U] << 4U & 0xFFU);
    r[5U*i+3U] = (uint8_t)(pCoeffs[4U*i+2U] >> 4U & 0xFFU) | (uint8_t)(pCoeffs[4U*i+3U] << 6U & 0xFFU);
    r[5U*i+4U] = (uint8_t)(pCoeffs[4U*i+3U] >> 2U & 0xFFU);
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_T1_Pack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_T1_Unpack
 *
 * Description: Unpack packed version of polynomial t1 into 10-bit coefficients.
 *              Output coefficients are standard representatives.
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *unpackedPoly: pointer to output polynomial
 *              - const uint8_t *packedPoly: byte array with bit-packed polynomial
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_T1_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_T1_Unpack(mcuxClMlDsa_Poly_t * unpackedPoly, const uint8_t * packedPoly)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_T1_Unpack);

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("coefficients are 32 bit aligned")
  uint32_t *pUnpacked = (uint32_t *)unpackedPoly->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  const uint8_t *pPacked = packedPoly;

  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(uint16_t i = 0U; i < MCUXCLMLDSA_N / 4U; ++i)
  {

    pUnpacked[0] = ((uint32_t)pPacked[0] >> 0U);
    pUnpacked[0] |= ((uint32_t)pPacked[1] << 8U);
    pUnpacked[0] &= 0x3FFU;

    pUnpacked[1] = ((uint32_t)pPacked[1] >> 2U);
    pUnpacked[1] |= ((uint32_t)pPacked[2] << 6U);
    pUnpacked[1] &= 0x3FFU;

    pUnpacked[2] = ((uint32_t)pPacked[2] >> 4U);
    pUnpacked[2] |= ((uint32_t)pPacked[3] << 4U);
    pUnpacked[2] &= 0x3FFU;

    pUnpacked[3] = ((uint32_t)pPacked[3] >> 6U);
    pUnpacked[3] |= ((uint32_t)pPacked[4] << 2U);
    pUnpacked[3] &= 0x3FFU;

    pUnpacked += 4U;
    pPacked += 5U;

    MCUX_CSSL_FP_LOOP_ITERATION(loop_1);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_T1_Unpack,
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, MCUXCLMLDSA_N / 4U));
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_T0_Pack
 *
 * Description: Bit-pack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
 *
 * Arguments:   - uint8_t *r: pointer to output byte array with at least
 *                            POLYT0_PACKEDBYTES bytes
 *              - const mcuxClMlDsa_Poly_t *a: pointer to input polynomial
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_T0_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_T0_Pack(uint8_t *r, const mcuxClMlDsa_Poly_t *a)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_T0_Pack);
  int32_t t[8];

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("t is 32 bit aligned")
  uint32_t* pT = (uint32_t*)t;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()


  for(uint16_t i = 0U; i < MCUXCLMLDSA_N/8U; ++i)
  {
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("2^{D-1} - x for x in [-2^{D-1}, 2^{D-1}] is in [0, 2^D]")
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
    t[0U] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - a->coefficients[8U*i+0U];
    t[1U] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - a->coefficients[8U*i+1U];
    t[2U] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - a->coefficients[8U*i+2U];
    t[3U] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - a->coefficients[8U*i+3U];
    t[4U] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - a->coefficients[8U*i+4U];
    t[5U] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - a->coefficients[8U*i+5U];
    t[6U] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - a->coefficients[8U*i+6U];
    t[7U] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - a->coefficients[8U*i+7U];
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

    r[13U*i+ 0U]  =  (uint8_t)(pT[0U] & 0xFFU);
    r[13U*i+ 1U]  =  (uint8_t)((pT[0U] >>  8U) & 0xFFU);
    r[13U*i+ 1U] |=  (uint8_t)((pT[1U] <<  5U) & 0xFFU);
    r[13U*i+ 2U]  =  (uint8_t)((pT[1U] >>  3U) & 0xFFU);
    r[13U*i+ 3U]  =  (uint8_t)((pT[1U] >> 11U) & 0xFFU);
    r[13U*i+ 3U] |=  (uint8_t)((pT[2U] <<  2U) & 0xFFU);
    r[13U*i+ 4U]  =  (uint8_t)((pT[2U] >>  6U) & 0xFFU);
    r[13U*i+ 4U] |=  (uint8_t)((pT[3U] <<  7U) & 0xFFU);
    r[13U*i+ 5U]  =  (uint8_t)((pT[3U] >>  1U) & 0xFFU);
    r[13U*i+ 6U]  =  (uint8_t)((pT[3U] >>  9U) & 0xFFU);
    r[13U*i+ 6U] |=  (uint8_t)((pT[4U] <<  4U) & 0xFFU);
    r[13U*i+ 7U]  =  (uint8_t)((pT[4U] >>  4U) & 0xFFU);
    r[13U*i+ 8U]  =  (uint8_t)((pT[4U] >> 12U) & 0xFFU);
    r[13U*i+ 8U] |=  (uint8_t)((pT[5U] <<  1U) & 0xFFU);
    r[13U*i+ 9U]  =  (uint8_t)((pT[5U] >>  7U) & 0xFFU);
    r[13U*i+ 9U] |=  (uint8_t)((pT[6U] <<  6U) & 0xFFU);
    r[13U*i+10U]  =  (uint8_t)((pT[6U] >>  2U) & 0xFFU);
    r[13U*i+11U]  =  (uint8_t)((pT[6U] >> 10U) & 0xFFU);
    r[13U*i+11U] |=  (uint8_t)((pT[7U] <<  3U) & 0xFFU);
    r[13U*i+12U]  =  (uint8_t)((pT[7U] >>  5U) & 0xFFU);
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_T0_Pack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_T0_Unpack
 *
 * Description: Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *unpackedPoly: pointer to output polynomial
 *              - const uint8_t *packedPoly: byte array with bit-packed polynomial
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_T0_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_T0_Unpack(mcuxClMlDsa_Poly_t * unpackedPoly, const uint8_t * packedPoly)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_T0_Unpack);

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pCoeffs are 32 bit aligned")
  uint32_t* pCoeffs = (uint32_t*)unpackedPoly->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  for(uint16_t i = 0U; i < MCUXCLMLDSA_N/8U; ++i)
  {
    pCoeffs[8U*i+0U]  = ((uint32_t)packedPoly[13U*i+0U] | ((uint32_t)packedPoly[13U*i+1U] << 8U)) & 0x1FFFU;
    pCoeffs[8U*i+1U]  = (((uint32_t)packedPoly[13U*i+1U] >> 5U) | ((uint32_t)packedPoly[13U*i+2U] << 3U) | ((uint32_t)packedPoly[13U*i+3U] << 11U) ) & 0x1FFFU;
    pCoeffs[8U*i+2U]  = (((uint32_t)packedPoly[13U*i+3U] >> 2U) | ((uint32_t)packedPoly[13U*i+4U] << 6U) ) & 0x1FFFU;
    pCoeffs[8U*i+3U]  = (((uint32_t)packedPoly[13U*i+4U] >> 7U) | ((uint32_t)packedPoly[13U*i+5U] << 1U) | ((uint32_t)packedPoly[13U*i+6U] << 9U) ) & 0x1FFFU;
    pCoeffs[8U*i+4U]  = (((uint32_t)packedPoly[13U*i+6U] >> 4U) | ((uint32_t)packedPoly[13U*i+7U] << 4U) | ((uint32_t)packedPoly[13U*i+8U] << 12U) ) & 0x1FFFU;
    pCoeffs[8U*i+5U]  = (((uint32_t)packedPoly[13U*i+8U] >> 1U) | ((uint32_t)packedPoly[13U*i+9U] << 7U) ) & 0x1FFFU;
    pCoeffs[8U*i+6U]  = (((uint32_t)packedPoly[13U*i+9U] >> 6U) | ((uint32_t)packedPoly[13U*i+10U] << 2U) | ((uint32_t)packedPoly[13U*i+11U] << 10U) ) & 0x1FFFU;
    pCoeffs[8U*i+7U]  = (((uint32_t)packedPoly[13U*i+11U] >> 3U) | ((uint32_t)packedPoly[13U*i+12U] << 5U) ) & 0x1FFFU;

    unpackedPoly->coefficients[8U*i+0U] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - unpackedPoly->coefficients[8U*i+0U];
    unpackedPoly->coefficients[8U*i+1U] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - unpackedPoly->coefficients[8U*i+1U];
    unpackedPoly->coefficients[8U*i+2U] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - unpackedPoly->coefficients[8U*i+2U];
    unpackedPoly->coefficients[8U*i+3U] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - unpackedPoly->coefficients[8U*i+3U];
    unpackedPoly->coefficients[8U*i+4U] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - unpackedPoly->coefficients[8U*i+4U];
    unpackedPoly->coefficients[8U*i+5U] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - unpackedPoly->coefficients[8U*i+5U];
    unpackedPoly->coefficients[8U*i+6U] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - unpackedPoly->coefficients[8U*i+6U];
    unpackedPoly->coefficients[8U*i+7U] = (int32_t)MCUXCLMLDSA_SHL_MLDSA_D - unpackedPoly->coefficients[8U*i+7U];
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_T0_Unpack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_Z_Pack
 *
 * Description: Bit-pack polynomial with coefficients
 *              in [-(GAMMA1 - 1), GAMMA1].
 *
 * Arguments:   - uint8_t *r: pointer to output byte array
 *              - const mcuxClMlDsa_Poly_t *a: pointer to input polynomial
 *              - const mcuxClMlDsa_Params_t *params: ML-DSA parameter set structure
 **************************************************/
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("It is indeed defined.")
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DEFINED_MORE_THAN_ONCE("It defined only once.")
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_Z_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_Z_Pack(
  mcuxCl_Buffer_t rBuf,
  const mcuxClMlDsa_Poly_t* a,
  const mcuxClMlDsa_Params_t* params)
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DEFINED_MORE_THAN_ONCE()
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_Z_Pack);
  MCUX_CSSL_ANALYSIS_COVERITY_ASSERT_FP_VOID(params->gamma1, MCUXCLMLDSA_MLDSA44_GAMMA1, MCUXCLMLDSA_MLDSA87_GAMMA2);
  uint32_t i;
  int32_t t[4];

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("t is 32 bit aligned")
  uint32_t* pT = (uint32_t*)t;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  if (MCUXCLMLDSA_MLDSA44_GAMMA1 == params->gamma1) /* Mode 2 */

  {
    for(i = 0U; i < MCUXCLMLDSA_N / 4U; ++i)
    {
      uint8_t r[9U];
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("GAMMA1 - x for x in [-(GAMMA1 - 1), GAMMA1] is in [0, 2GAMMA - 1]")
       MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
      t[0U] = (int32_t)params->gamma1 - a->coefficients[4U * i + 0U];
      t[1U] = (int32_t)params->gamma1 - a->coefficients[4U * i + 1U];
      t[2U] = (int32_t)params->gamma1 - a->coefficients[4U * i + 2U];
      t[3U] = (int32_t)params->gamma1 - a->coefficients[4U * i + 3U];
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

      r[0U] =  (uint8_t)(pT[0U] & 0xFFU);
      r[1U] =  (uint8_t)(pT[0U] >> 8U  & 0xFFU);
      r[2U] =  (uint8_t)(pT[0U] >> 16U & 0xFFU);
      r[2U] |= (uint8_t)(pT[1U] << 2U  & 0xFFU);
      r[3U] =  (uint8_t)(pT[1U] >> 6U  & 0xFFU);
      r[4U] =  (uint8_t)(pT[1U] >> 14U & 0xFFU);
      r[4U] |= (uint8_t)(pT[2U] << 4U  & 0xFFU);
      r[5U] =  (uint8_t)(pT[2U] >> 4U  & 0xFFU);
      r[6U] =  (uint8_t)(pT[2U] >> 12U & 0xFFU);
      r[6U] |= (uint8_t)(pT[3U] << 6U  & 0xFFU);
      r[7U] =  (uint8_t)(pT[3U] >> 2U  & 0xFFU);
      r[8U] =  (uint8_t)(pT[3U] >> 10U & 0xFFU);

      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write(rBuf, i * 9U, r, 9U));
    }
  }
  else if(MCUXCLMLDSA_MLDSA65_GAMMA1 == params->gamma1) /* Mode 3 or 5 */
  {
    for(i = 0U; i < MCUXCLMLDSA_N / 2U; ++i)
    {
      uint8_t r[5U];
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("GAMMA1 - x for x in [-(GAMMA1 - 1), GAMMA1] is in [0, 2GAMMA - 1]")
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("a->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
      t[0U] = (int32_t)params->gamma1 - a->coefficients[2U * i + 0U];
      t[1U] = (int32_t)params->gamma1 - a->coefficients[2U * i + 1U];
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

      r[0U] =  (uint8_t)(pT[0U] & 0xFFU);
      r[1U] =  (uint8_t)(pT[0U] >> 8U  & 0xFFU);
      r[2U] =  (uint8_t)(pT[0U] >> 16U & 0xFFU);
      r[2U] |= (uint8_t)(pT[1U] << 4U  & 0xFFU);
      r[3U] =  (uint8_t)(pT[1U] >> 4U  & 0xFFU);
      r[4U] =  (uint8_t)(pT[1U] >> 12U & 0xFFU);

      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_write(rBuf, i * 5U, r, 5U));
    }
  }
  else
  {
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_Z_Pack);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_Z_Pack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_Z_Unpack_17
 **************************************************/
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_Z_Unpack_17)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_Z_Unpack_17(int32_t *r, const uint8_t *a)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_Z_Unpack_17);
  /* we process the result twice, once as unsigned and once as signed */

  const uint8_t *pA = a;
  int32_t *pRSigned = r;

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pR are 32 bit aligned")
  uint32_t* pR = (uint32_t*)r;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pR won't overflow iff we point to a validly-sized subpart of z, we unpack 4 coefficents from 9 bytes")
  *pR = (uint32_t)*pA++;
  *pR |= ((uint32_t)*pA++ << 8U);
  *pR |= ((uint32_t)*pA << 16U);
  *pR &= 0x3FFFFU;
  pR++;

  *pR = ((uint32_t)*pA++ >> 2U);
  *pR |= ((uint32_t)*pA++ << 6U);
  *pR |= ((uint32_t)*pA << 14U);
  *pR &= 0x3FFFFU;
  pR++;

  *pR = ((uint32_t)*pA++ >> 4U);
  *pR |= ((uint32_t)*pA++ << 4U);
  *pR |= ((uint32_t)*pA << 12U);
  *pR &= 0x3FFFFU;
  pR++;

  *pR = ((uint32_t)*pA++ >> 6U);
  *pR |= ((uint32_t)*pA++ << 2U);
  *pR |= ((uint32_t)*pA << 10U);
  *pR &= 0x3FFFFU;

  *pRSigned = (int32_t)MCUXCLMLDSA_MLDSA44_GAMMA1 - *pRSigned;
  pRSigned++;
  *pRSigned = (int32_t)MCUXCLMLDSA_MLDSA44_GAMMA1 - *pRSigned;
  pRSigned++;
  *pRSigned = (int32_t)MCUXCLMLDSA_MLDSA44_GAMMA1 - *pRSigned;
  pRSigned++;
  *pRSigned = (int32_t)MCUXCLMLDSA_MLDSA44_GAMMA1 - *pRSigned;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_Z_Unpack_17);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_Z_Unpack_19
 **************************************************/
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_Z_Unpack_19)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_Z_Unpack_19(int32_t *r, const uint8_t *a)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_Z_Unpack_19);
  /* we process the result twice, once as unsigned and once as signed */

  const uint8_t *pA = a;
  int32_t *pRSigned = r;

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pR are 32 bit aligned")
  uint32_t* pR = (uint32_t*)r;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pR won't overflow iff we point to a validly-sized subpart of z, we unpack 4 coefficents from 9 bytes")
  *pR = (uint32_t)*pA++;
  *pR |= ((uint32_t)*pA++ << 8U);
  *pR |= ((uint32_t)*pA << 16U);
  *pR &= 0xFFFFFU;
  pR++;

  *pR = ((uint32_t)*pA++ >> 4U);
  *pR |= ((uint32_t)*pA++ << 4U);
  *pR |= ((uint32_t)*pA << 12U);
  *pR &= 0xFFFFFU;

  *pRSigned = (int32_t)MCUXCLMLDSA_MLDSA65_GAMMA1 - *pRSigned;
  pRSigned++;
  *pRSigned = (int32_t)MCUXCLMLDSA_MLDSA65_GAMMA1 - *pRSigned;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_Z_Unpack_19);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_Z_Unpack
 *
 * Description: Unpack polynomial z with coefficients
 *              in [-(GAMMA1 - 1), GAMMA1].
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *r: pointer to output polynomial
 *              - InputBuffer_t: buffer with bit-packed polynomial z
 *              - const mcuxClMlDsa_Params_t *params: ML-DSA parameter set structure
 * Used in: Sign, Verify
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_Z_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_Packing_Z_Unpack(
  mcuxClMlDsa_Poly_t *r,
  mcuxCl_InputBuffer_t zBuf,
  const mcuxClMlDsa_Params_t *params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_Z_Unpack);

  int32_t *pR = r->coefficients;


  uint32_t i;
  if (MCUXCLMLDSA_MLDSA44_GAMMA1 == params->gamma1) /* Mode 2 */
  {
    uint8_t t[9U];
    MCUX_CSSL_FP_LOOP_DECL(loop1);
    for (i = 0U; i < MCUXCLMLDSA_N / 4U; ++i)
    {
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(zBuf, 0U, t, 9U));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_Z_Unpack_17(pR, t));
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Won't overflow, these pointers are valid within r and z")
      pR += 4U;
      MCUXCLBUFFER_UPDATE(zBuf, 9U);
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
      MCUX_CSSL_FP_LOOP_ITERATION(loop1, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Z_Unpack_17));
    }
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_LOOP_ITERATIONS(loop1, MCUXCLMLDSA_N / 4U));
  }
  else if (MCUXCLMLDSA_MLDSA65_GAMMA1 == params->gamma1) /* Mode 3 or 5 */
  {
    uint8_t t[5U];
    MCUX_CSSL_FP_LOOP_DECL(loop2);
    for(i = 0U; i < MCUXCLMLDSA_N / 2U; ++i)
    {
      MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(zBuf, 0U, t, 5U));
      MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMlDsa_Packing_Z_Unpack_19(pR, t));
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("Won't overflow, these pointers are valid within r and z")
      pR += 2U;
      MCUXCLBUFFER_UPDATE(zBuf, 5U);
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
      MCUX_CSSL_FP_LOOP_ITERATION(loop2, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMlDsa_Packing_Z_Unpack_19));
    }
    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_LOOP_ITERATIONS(loop2, MCUXCLMLDSA_N / 2U));
  }
  else
  {
    /* This should never be reached unless a fault attack happened */
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Packing_Z_Unpack, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Packing_Z_Unpack, MCUXCLSIGNATURE_STATUS_OK);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_W1_Pack
 *
 * Description: Bit-pack polynomial w1 with coefficients in [0,15] or [0,43].
 *              Input coefficients are assumed to be standard representatives.
 *
 * Arguments:   - uint8_t *r: pointer to output byte array with at least
 *                            POLYW1_PACKEDBYTES bytes
 *              - const mcuxClMlDsa_Poly_t *a: pointer to input polynomial
 *              - const mcuxClMlDsa_Params_t *params: ML-DSA parameter set structure
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_W1_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_Packing_W1_Pack(
  uint8_t *r,
  const mcuxClMlDsa_Poly_t *a,
  const mcuxClMlDsa_Params_t *params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_W1_Pack);

  uint8_t *pR = r;
  uint16_t i;

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pR are 32 bit aligned")
  const uint32_t* pCoeffs = (const uint32_t*)a->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  if(MCUXCLMLDSA_MLDSA44_GAMMA2 == params->gamma2)      /* Mode 2 */
  {
    for(i = 0U; i < MCUXCLMLDSA_N / 4U; ++i)
    {
      pR[0U] = (uint8_t)(pCoeffs[0U] & 0xFFU);
      pR[0U] |= (uint8_t)(pCoeffs[1U] << 6U & 0xFFU);
      pR[1U] = (uint8_t)(pCoeffs[1U] >> 2U & 0xFFU);
      pR[1U] |= (uint8_t)(pCoeffs[2U] << 4U & 0xFFU);
      pR[2U] = (uint8_t)(pCoeffs[2U] >> 4U & 0xFFU);
      pR[2U] |= (uint8_t)(pCoeffs[3U] << 2U & 0xFFU);

      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pR and pCoeffs won't overflow if pointed at validly-sized w1 poly")
      pR += 3U;
      pCoeffs += 4U;
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    }
  }
  else if(MCUXCLMLDSA_MLDSA65_GAMMA2 == params->gamma2)   /* Mode 3 or 5 */
  {
    for(i = 0U; i < MCUXCLMLDSA_N / 2U; ++i)
    {
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pR and pCoeffs won't overflow if pointed at validly-sized w1 poly")
      *pR = (uint8_t)(*pCoeffs++ & 0xFFU);
      *pR |= (uint8_t)(*pCoeffs++ << 4U & 0xFFU);
      pR++;
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    }
  }
  else
  {
    /* can't happen, fault attack: return FAULT_ATTACK so caller early-exits */
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Packing_W1_Pack, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Packing_W1_Pack, MCUXCLSIGNATURE_STATUS_OK);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_W1_Unpack
 *
 * Description: Unpack polynomial w1 with coefficients in [0,15] or [0,43].
 *              Output coefficients are standard representatives.
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *a:   pointer to output polynomial
 *              - const uint8_t *r:       pointer to input byte array with at least POLYW1_PACKEDBYTES bytes
 *              - params:                 ML-DSA parameter set structure
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_W1_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_W1_Unpack(
  mcuxClMlDsa_Poly_t *a,
  const uint8_t *r,
  const mcuxClMlDsa_Params_t *params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_W1_Unpack);
  uint16_t i;

  if(MCUXCLMLDSA_MLDSA44_GAMMA2 == params->gamma2)    /* Mode 2: range [0, 15] */
  {
    for(i = 0U; i < MCUXCLMLDSA_N / 4U; ++i)
    {
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pCoeffs are 32 bit aligned")
      uint32_t* pCoeffs = (uint32_t*)&a->coefficients[4U*i + 0U];
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
      pCoeffs[0] = ((uint32_t)r[3U*i + 0U] & 0x3FU);
      pCoeffs[1] = (((uint32_t)r[3U*i + 0U] >> 6U) | (((uint32_t)r[3U*i + 1U] & 0xFU) << 2U));
      pCoeffs[2] = (((uint32_t)r[3U*i + 1U] >> 4U) | (((uint32_t)r[3U*i + 2U] & 0x3U) << 4U));
      pCoeffs[3] = ((uint32_t)r[3U*i + 2U] >> 2U);
    }
  }
  else if(MCUXCLMLDSA_MLDSA65_GAMMA2 == params->gamma2)     /* Mode 3 or 5: [0, 43] */
  {
    for(i = 0U; i < MCUXCLMLDSA_N / 2U; ++i)
    {
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pCoeffs are 32 bit aligned")
      uint32_t* pCoeffs = (uint32_t*)&a->coefficients[2U*i + 0U];
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
      pCoeffs[0] = ((uint32_t)r[i] & 0xFU);
      pCoeffs[1] = ((uint32_t)r[i] >> 4U);
    }
  }
  else
  {
    MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_W1_Unpack);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_W1_Unpack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_W_Pack
 *
 * Description: Pack full polynomial into 768 bytes
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *w: pointer to input polynomial
 *              - uint8_t *a: output byte array for w with at least
 *                            3*MCUXCLMLDSA_N = 768 bytes
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_W_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_W_Pack(uint8_t *a, const mcuxClMlDsa_Poly_t *w)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_W_Pack);

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pCoeffs are 32 bit aligned")
  const uint32_t* wCoeffs = (const uint32_t*)w->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  for(uint16_t i = 0U; i < MCUXCLMLDSA_N; ++i)
  {
    a[3U*i+0U] = (uint8_t)(wCoeffs[i] >> 0U  & 0xFFU);
    a[3U*i+1U] = (uint8_t)(wCoeffs[i] >> 8U  & 0xFFU);
    a[3U*i+2U] = (uint8_t)(wCoeffs[i] >> 16U & 0xFFU);
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_W_Pack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_W_Unpack
 *
 * Description: Unpack full polynomial from 768 bytes
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *w: pointer to output polynomial
 *              - uint8_t *a: input byte array for w with at least
 *                            3*MCUXCLMLDSA_N = 768 bytes
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_W_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_W_Unpack(mcuxClMlDsa_Poly_t *w, const uint8_t *a)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_W_Unpack);

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("pCoeffs are 32 bit aligned")
  uint32_t* wCoeffs = (uint32_t*)w->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  for(uint16_t i = 0U; i < MCUXCLMLDSA_N; ++i)
  {
    wCoeffs[i] = (((uint32_t)a[3U*i+0U]) | (((uint32_t)a[3U*i+1U]) << 8U) | (((uint32_t)a[3U*i+2U]) << 16U));
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_W_Unpack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_C_Pack
 *
 * Description: c is a polynomial with 256 coefficients, of which TAU < 64
 *              are in {-1,1}. We store this into 256 bits, where each
 *              set bit determines the coefficient being non-zero, and 64 > TAU
 *              bits that determine their sign.
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *c: pointer to input polynomial
 *              - uint8_t *cPacked: output byte array for c with at least
 *                                   32 + 8 = 40 bytes
 *              - params: ML-DSA parameter set structure
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_C_Pack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_C_Pack(
  uint8_t *cPacked,
  const mcuxClMlDsa_Poly_t *c,
  const mcuxClMlDsa_Params_t *const params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_C_Pack);

  MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("c->coefficients of type int32_t ( const *)[256] cast to type int32_t const * is needed")
  const int32_t *pC = c->coefficients;
  MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()

  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_set((uint8_t *)(cPacked), 0U, MCUXCLMLDSA_C_PACKED_BYTES, MCUXCLMLDSA_C_PACKED_BYTES));

  uint8_t sign = 0U, signInc = 0U;
  uint8_t signsPos = 0U;
  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for (uint16_t i = 0U; i < MCUXCLMLDSA_N; i++)
  {
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pC/signPos won't overflow because we have at most TAU/N elements")
    signInc = (*pC != 0) ? 1U : 0U;  // get if the coeff is equal to 0
    sign = ((*pC++) - 1 != 0) ? 1U : 0U; // get if the sign is pos or neg. 1 if neg.
    cPacked[i >> 3U] |= signInc << (i & 0x7U);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA("Recovering signed numbers which are represented as compressed byte array")
    cPacked[(MCUXCLMLDSA_N >> 3U) + (signsPos >> 3U)] |= (sign & signInc) << (signsPos & 0x7U);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_MAY_RESULT_IN_MISINTERPRETED_DATA()
    signsPos += signInc;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    MCUX_CSSL_FP_LOOP_ITERATION(loop_1);
  }


  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_C_Pack,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, MCUXCLMLDSA_N));
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_C_Unpack
 *
 * Description: c is a polynomial with 256 coefficients, of which TAU < 64
 *              are in {-1,1}. We retrieve this from 256 bits, where each
 *              set bit determines the coefficient being non-zero, and 64 > TAU
 *              bits that determine their sign.
 *
 * Arguments:   - mcuxClMlDsa_Poly_t *c: pointer to output polynomial
 *              - const uint8_t *cPacked: output byte array for c with at least
 *                                   32 + 8 = 40 bytes
 *              - const mcuxClMlDsa_Params_t *params: ML-DSA parameter set structure
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_C_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_C_Unpack(
  mcuxClMlDsa_Poly_t *c,
  const uint8_t *cPacked,
  const mcuxClMlDsa_Params_t *params)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_C_Unpack);

  int32_t *pC = c->coefficients;
  const uint8_t *pPacked = cPacked;

  uint16_t i, j;
  uint64_t signs;

  /* Initialize signs */
  signs = ((uint64_t)cPacked[(MCUXCLMLDSA_N >> 3U) + 0U] << (8U*0U)) |
          ((uint64_t)cPacked[(MCUXCLMLDSA_N >> 3U) + 1U] << (8U*1U)) |
          ((uint64_t)cPacked[(MCUXCLMLDSA_N >> 3U) + 2U] << (8U*2U)) |
          ((uint64_t)cPacked[(MCUXCLMLDSA_N >> 3U) + 3U] << (8U*3U)) |
          ((uint64_t)cPacked[(MCUXCLMLDSA_N >> 3U) + 4U] << (8U*4U)) |
          ((uint64_t)cPacked[(MCUXCLMLDSA_N >> 3U) + 5U] << (8U*5U)) |
          ((uint64_t)cPacked[(MCUXCLMLDSA_N >> 3U) + 6U] << (8U*6U)) |
          ((uint64_t)cPacked[(MCUXCLMLDSA_N >> 3U) + 7U] << (8U*7U));


  for(i = 0U; i < MCUXCLMLDSA_N >> 3U; ++i)
  {
    for(j = 0U; j < 8U; ++j)
    {
      /* If bit is set (m) then set to -1 if sign bit is set or to +1 is not set, 0 otherwise. */
      uint8_t m = (*pPacked >> j) & (uint8_t)1U;
      uint64_t s = signs & 1U;
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("will stay within polynomial bounds and thus not overflow")
      *pC++ = (1 - 2 * ((int32_t)s)) * (int32_t)m;
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
      signs >>= m;
    }
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("will stay within packed polynomial bounds and thus not overflow")
    pPacked++;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
  }

  for(i = 0U; i < MCUXCLMLDSA_N; ++i)
  {
    if (0 != c->coefficients[i])
    {
    }
  }

  /* Check the first loop, i.e., by checking that pC and pPacked advanced like expected */
  /* Check that we've seen tau 1's, individually */

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_C_Unpack);
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_H_Unpack
 *
 * Description: Unpack h[i] of signature sig = (c, z, h).
 *
 * Arguments:   - Session
                - mcuxClMlDsa_Poly_t *pH: output hint h
 *              - uint16_t i: index of h in hint vector
 *              - hintBuf: pointer to start of bit-packed signature
 *              - const mcuxClMlDsa_Params_t *pParams: ML-DSA parameter set structure
 *
 * Returns MCUXCLSIGNATURE_STATUS_NOT_OK in case of malformed h
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_H_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSignature_Status_t) mcuxClMlDsa_Packing_H_Unpack(
  mcuxClSession_Handle_t session,
  mcuxClMlDsa_Poly_t* pH,
  uint16_t i,
  uint8_t* const pHPacked,
  mcuxCl_InputBuffer_t hintBuf,
  const mcuxClMlDsa_Params_t* pParams)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_H_Unpack);
  uint16_t j, k;
  uint16_t secCounter;

  /* read the hints from the signature to a workarea buffer */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClBuffer_read(hintBuf, 0U, pHPacked, (uint32_t)pParams->omega + (uint32_t)pParams->k));

  /* Decode h */
  if(i == 0U)
  {
    k = 0U;
  }
  else
  {
    MCUX_CSSL_ANALYSIS_COVERITY_START_FALSE_POSITIVE(INTEGER_OVERFLOW, "Expression 'pParams->omega + i - 1u' does not underflow because 'i' >= 1")
    k = pHPacked[pParams->omega + i - 1U];
    MCUX_CSSL_ANALYSIS_COVERITY_STOP_FALSE_POSITIVE(INTEGER_OVERFLOW)
  }

  /* Clear coefficients in h */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear((uint8_t*) pH->coefficients, MCUXCLMLDSA_POLY_SIZE, MCUXCLMLDSA_POLY_SIZE));

  secCounter = 0x00U;

  /* delimiter indices are ordered for strong unforgeability requirement */
  if((pHPacked[pParams->omega + i] < k) || (pHPacked[pParams->omega + i] > pParams->omega))
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Packing_H_Unpack, MCUXCLSIGNATURE_STATUS_NOT_OK,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear));
  }

  const uint8_t *pHI = pHPacked + k;
  MCUX_CSSL_FP_LOOP_DECL(loop_1);
  for(j = k; j < pHPacked[pParams->omega + i]; ++j)
  {
    /* Coefficients are ordered for strong unforgeability */
    MCUX_CSSL_ANALYSIS_COVERITY_START_FALSE_POSITIVE(INTEGER_OVERFLOW, "Variable 'j' and expression 'j - 1u' does not overflow/underflow because 'j' > 'k'; 'k' is in {0,...,UINT16_MAX} and pHPacked is uint8_t*")
    if(j > k && pHPacked[j] <= pHPacked[j - 1U])
    MCUX_CSSL_ANALYSIS_COVERITY_STOP_FALSE_POSITIVE(INTEGER_OVERFLOW)
    {
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Packing_H_Unpack, MCUXCLSIGNATURE_STATUS_NOT_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear),
        MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, ((uint32_t)j - (uint32_t)k)));
    }
    else
    {
      MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(secCounter, 0U, MCUXCLMLDSA_MLDSA87_OMEGA, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
      secCounter++;
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("pHI won't overflow, hints are max omega bytes long")
      pH->coefficients[*pHI++] = 1;
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
    }

    MCUX_CSSL_FP_LOOP_ITERATION(loop_1);
  }

  /* Terminal FA path: skip DI/FP balancing for performance. */
  if(secCounter != pHPacked[pParams->omega + i] - k)
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Packing_H_Unpack, MCUXCLSIGNATURE_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMlDsa_Packing_H_Unpack, MCUXCLSIGNATURE_STATUS_OK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear),
    MCUX_CSSL_FP_CONDITIONAL(k < pHPacked[pParams->omega + i],
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop_1, ((uint32_t)pHPacked[pParams->omega + i] - (uint32_t)k))));
}

/*************************************************
 * Name:        mcuxClMlDsa_Packing_SK_Unpack
 *
 * Description: Partially unpack secret key sk = (rho, key, tr, s1, s2, t0).
 *              Unpacks rho, tr and key - t0, s1 and s2 are done on the fly.
 *
 * Arguments:   - const uint8_t rho[]: output byte array for rho
 *              - const uint8_t tr[]: output byte array for tr
 *              - const uint8_t key[]: output byte array for key
 *              - uint8_t sk[]: byte array containing bit-packed sk
 *
 **************************************************/
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMlDsa_Packing_SK_Unpack)
MCUX_CSSL_FP_PROTECTED_TYPE(void) mcuxClMlDsa_Packing_SK_Unpack(uint8_t *rho, uint8_t *tr, uint8_t *key, const uint8_t *sk)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMlDsa_Packing_SK_Unpack);

  /* Securely copy data from sk into rho */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy((uint8_t *)(rho), (const uint8_t *)(sk), MCUXCLMLDSA_SEEDBYTES, MCUXCLMLDSA_SEEDBYTES));

  /* Securely copy data from sk into key */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy((uint8_t *)(key), (const uint8_t *)(&sk[MCUXCLMLDSA_SEEDBYTES]), MCUXCLMLDSA_SEEDBYTES, MCUXCLMLDSA_SEEDBYTES));

  /* Securely copy data from sk into tr */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy((uint8_t *)(tr), (const uint8_t *)(&sk[2U * MCUXCLMLDSA_SEEDBYTES]), MCUXCLMLDSA_TRBYTES, MCUXCLMLDSA_TRBYTES));

  MCUX_CSSL_FP_FUNCTION_EXIT_VOID(mcuxClMlDsa_Packing_SK_Unpack,
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy));
}
