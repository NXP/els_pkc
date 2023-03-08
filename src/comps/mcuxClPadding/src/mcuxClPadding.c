/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023 NXP                                                  */
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

/** @file  mcuxClPadding.c
 *  @brief implementation of padding functions for different components */

#include <nxpClToolchain.h>
#include <internal/mcuxClPadding_Internal.h>
#include <mcuxClMemory.h>
#include <mcuxClSession.h>
#include <mcuxClCore_Analysis.h>

#define MCUXCLPADDING_ISO_PADDING_BYTE (0x80u)


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPadding_addPadding_None)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClPadding_Status_t) mcuxClPadding_addPadding_None(
  uint32_t blockLength UNUSED_PARAM,
  const uint8_t * const pIn UNUSED_PARAM,
  uint32_t lastBlockLength,
  uint32_t totalInputLength UNUSED_PARAM,
  uint8_t * const pOut UNUSED_PARAM,
  uint32_t * const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPadding_addPadding_None);

  if(0u != lastBlockLength)
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClPadding_addPadding_None, MCUXCLPADDING_STATUS_ERROR);
  }

  *pOutLength = 0u;
  MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClPadding_addPadding_None, MCUXCLPADDING_STATUS_OK, MCUXCLPADDING_STATUS_FAULT_ATTACK);
}


MCUXCLCORE_ANALYSIS_START_PATTERN_LONG_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPadding_addPadding_ISO9797_1_Method1)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClPadding_Status_t) mcuxClPadding_addPadding_ISO9797_1_Method1(
MCUXCLCORE_ANALYSIS_STOP_PATTERN_LONG_IDENTIFIER()
  uint32_t blockLength,
  const uint8_t * const pIn,
  uint32_t lastBlockLength,
  uint32_t totalInputLength,
  uint8_t * const pOut,
  uint32_t * const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPadding_addPadding_ISO9797_1_Method1);

  if((0u != totalInputLength) /* special case for zero-padding: add a padding block if totalInputLength is 0 */
       && (0u == lastBlockLength))
  {
    /* No padding needed */
    *pOutLength = 0;
    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClPadding_addPadding_ISO9797_1_Method1, MCUXCLPADDING_STATUS_OK, MCUXCLPADDING_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_CALL(copyResult, mcuxClMemory_copy(pOut, pIn, lastBlockLength, blockLength));

  if(0u != copyResult)
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClPadding_addPadding_ISO9797_1_Method1, MCUXCLPADDING_STATUS_ERROR,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy));
  }

  uint32_t paddingBytes = blockLength - lastBlockLength;

  MCUX_CSSL_FP_FUNCTION_CALL(padResult, mcuxClMemory_set(pOut + lastBlockLength, 0x00u, paddingBytes, paddingBytes));

  if(0u != padResult)
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClPadding_addPadding_ISO9797_1_Method1, MCUXCLPADDING_STATUS_ERROR,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set));
  }

  *pOutLength = blockLength;

  MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClPadding_addPadding_ISO9797_1_Method1, MCUXCLPADDING_STATUS_OK, MCUXCLPADDING_STATUS_FAULT_ATTACK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set));
}


MCUXCLCORE_ANALYSIS_START_PATTERN_LONG_IDENTIFIER()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPadding_addPadding_ISO9797_1_Method2)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClPadding_Status_t) mcuxClPadding_addPadding_ISO9797_1_Method2 (
MCUXCLCORE_ANALYSIS_STOP_PATTERN_LONG_IDENTIFIER()
  uint32_t blockLength,
  const uint8_t * const pIn,
  uint32_t lastBlockLength,
  uint32_t totalInputLength UNUSED_PARAM,
  uint8_t * const pOut,
  uint32_t * const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPadding_addPadding_ISO9797_1_Method2);

  uint8_t *pOutPtr = (uint8_t *) pOut;

  MCUX_CSSL_FP_FUNCTION_CALL(copyResult, mcuxClMemory_copy(pOutPtr, pIn, lastBlockLength, blockLength));

  if(0u != copyResult)
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClPadding_addPadding_ISO9797_1_Method2, MCUXCLPADDING_STATUS_ERROR,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy));
  }
  pOutPtr += lastBlockLength;

  *pOutPtr = MCUXCLPADDING_ISO_PADDING_BYTE;
  pOutPtr++;

  uint32_t paddingBytes = blockLength - lastBlockLength - 1u;

  MCUX_CSSL_FP_FUNCTION_CALL(padResult, mcuxClMemory_set((uint8_t *) pOutPtr, 0x00u, paddingBytes, paddingBytes));

  if(0u != padResult)
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClPadding_addPadding_ISO9797_1_Method2, MCUXCLPADDING_STATUS_ERROR,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set));
  }

  *pOutLength = blockLength;

  MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClPadding_addPadding_ISO9797_1_Method2, MCUXCLPADDING_STATUS_OK, MCUXCLPADDING_STATUS_FAULT_ATTACK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPadding_addPadding_MAC_ISO9797_1_Method2)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClPadding_Status_t) mcuxClPadding_addPadding_MAC_ISO9797_1_Method2(
  uint32_t blockLength,
  const uint8_t * const pIn,
  uint32_t lastBlockLength,
  uint32_t totalInputLength,
  uint8_t * const pOut,
  uint32_t * const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPadding_addPadding_MAC_ISO9797_1_Method2);
  if(blockLength == lastBlockLength)
  {
    /* No padding needed */
    *pOutLength = 0;
    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClPadding_addPadding_MAC_ISO9797_1_Method2, MCUXCLPADDING_STATUS_OK, MCUXCLPADDING_STATUS_FAULT_ATTACK);
  }

  MCUX_CSSL_FP_FUNCTION_CALL(padResult, mcuxClPadding_addPadding_ISO9797_1_Method2(blockLength, pIn, lastBlockLength, totalInputLength, pOut, pOutLength));

  if(MCUXCLPADDING_STATUS_OK != padResult)
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClPadding_addPadding_MAC_ISO9797_1_Method2, MCUXCLPADDING_STATUS_ERROR,
                                 MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_ISO9797_1_Method2));
  }
  MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClPadding_addPadding_MAC_ISO9797_1_Method2, MCUXCLPADDING_STATUS_OK, MCUXCLPADDING_STATUS_FAULT_ATTACK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_ISO9797_1_Method2));
}



/* TODO CLNS-3507: Replace by actual random padding (is currently a copy of M1) */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClPadding_addPadding_Random)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClPadding_Status_t) mcuxClPadding_addPadding_Random(
  uint32_t blockLength,
  const uint8_t * const pIn,
  uint32_t lastBlockLength,
  uint32_t totalInputLength,
  uint8_t * const pOut,
  uint32_t * const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClPadding_addPadding_Random);

  /* Empty input - return */
  if(0u == totalInputLength)
  {
    *pOutLength = 0u;
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClPadding_addPadding_Random, MCUXCLPADDING_STATUS_OK);
  }

  MCUX_CSSL_FP_FUNCTION_CALL(copyResult, mcuxClMemory_copy(pOut, pIn, lastBlockLength, blockLength));

  if(0u != copyResult)
  {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClPadding_addPadding_Random, MCUXCLPADDING_STATUS_ERROR,
       MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy));
  }

  uint32_t paddingBytes = blockLength - lastBlockLength;

  if(0u != paddingBytes)
  {
    MCUX_CSSL_FP_FUNCTION_CALL(padResult, mcuxClMemory_set(pOut + lastBlockLength, 0x00u, paddingBytes, paddingBytes));

    if(0u != padResult)
    {
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClPadding_addPadding_Random, MCUXCLPADDING_STATUS_ERROR,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set));
    }
  }

  *pOutLength = blockLength;

  MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClPadding_addPadding_Random, MCUXCLPADDING_STATUS_OK, MCUXCLPADDING_STATUS_FAULT_ATTACK,
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set));
}

