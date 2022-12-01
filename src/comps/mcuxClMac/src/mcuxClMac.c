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

/** @file  mcuxClMac.c
 *  @brief implementation of mcuxClMac component */

#include <mcuxClMac.h>
#include <mcuxClMemory.h>
#include <mcuxClKey.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCss.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClCss_Internal.h>
#include <internal/mcuxClMac_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMac_compute)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_compute(
                       mcuxClSession_Handle_t pSession,
                       const mcuxClKey_Handle_t key,
                       mcuxClMac_Mode_t mode,
                       mcuxCl_InputBuffer_t pIn,
                       uint32_t inLength,
                       mcuxCl_Buffer_t pMac)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMac_compute, mode->protectionTokenOneshot);
    uint32_t outSize = mode->macByteSize;
    mcuxClMac_Context_t context = {0};
    context.key = (mcuxClKey_Descriptor_t*)key;
    context.session = pSession;
    context.mode = mode;
    MCUX_CSSL_FP_FUNCTION_CALL(result, mode->engineOneshot(&context, pIn, inLength, pMac, &outSize));
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_compute, result);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMac_init)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_init(
  mcuxClSession_Handle_t pSession,
  mcuxClMac_Context_t *const pContext,
  const mcuxClKey_Handle_t key,
  mcuxClMac_Mode_t mode)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMac_init, mode->protectionTokenInit);
  pContext->key = (mcuxClKey_Descriptor_t*)key;
  pContext->session = pSession;
  pContext->mode = mode;
  uint32_t outSize = 0;
  MCUX_CSSL_FP_FUNCTION_CALL(result, mode->engineInit(pContext, NULL, 0, NULL, &outSize));
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_init, result);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMac_process)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_process(
  mcuxClSession_Handle_t pSession,
  mcuxClMac_Context_t *const pContext,
  const uint8_t *const pIn,
  uint32_t inLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMac_process, pContext->mode->protectionTokenUpdate);
  uint32_t outSize = 0;
  pContext->session = pSession;
  MCUX_CSSL_FP_FUNCTION_CALL(result, pContext->mode->engineUpdate(pContext, pIn, inLength, NULL, &outSize));
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_process, result);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMac_finish)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_finish(
  mcuxClSession_Handle_t pSession,
  mcuxClMac_Context_t *const pContext,
  uint8_t *const pMac)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMac_finish, pContext->mode->protectionTokenFinalize);
  uint32_t outSize = pContext->mode->macByteSize;
  pContext->session = pSession;
  MCUX_CSSL_FP_FUNCTION_CALL(result, pContext->mode->engineFinalize(pContext, NULL, 0, pMac, &outSize));
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_finish, result);
}
