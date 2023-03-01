/*--------------------------------------------------------------------------*/
/* Copyright 2020-2023 NXP                                                  */
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

/** @file  mcuxClMacModes_ELS_CMAC.c
 *  @brief implementation of CMAC part of mcuxClMac component */

#include <mcuxClEls.h>
#include <mcuxClEls_Cmac.h>
#include <mcuxClMemory.h>
#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal.h>
#include <mcuxClKey.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <nxpClToolchain.h>
#include <internal/mcuxClKey_Internal.h>
#include <mcuxClAes.h>

#include <internal/mcuxClMac_Internal_Types.h>
#include <mcuxClMacModes_MemoryConsumption.h>
#include <internal/mcuxClMacModes_ELS_Ctx.h>
#include <internal/mcuxClMacModes_Wa.h>
#include <internal/mcuxClMacModes_ELS_Types.h>
#include <internal/mcuxClMacModes_ELS_CMAC.h>
#include <internal/mcuxClMacModes_Algorithms.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_Engine_CMAC_Oneshot)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMacModes_Engine_CMAC_Oneshot(
    mcuxClSession_Handle_t session,
    mcuxClMacModes_Context_t * const pContext,
    const uint8_t *const pIn,
    uint32_t inLength,
    uint8_t *const pOut,
    uint32_t *const pOutLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_Engine_CMAC_Oneshot);
    size_t const completeLen = (inLength/MCUXCLAES_BLOCK_SIZE)*MCUXCLAES_BLOCK_SIZE;
    size_t bufLen = MCUXCLAES_BLOCK_SIZE;
    size_t const remainingLen = inLength - completeLen;

    // Check if key matches to the algorithm
    if (MCUXCLKEY_ALGO_ID_AES != mcuxClKey_getAlgorithm(pContext->key))
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Oneshot, MCUXCLMAC_STATUS_ERROR);
    }

    /* Create workarea */
    mcuxClMacModes_WorkArea_t * workArea;
    /* MISRA Ex. 9 to Rule 11.3 - reinterpret memory */
    MCUX_CSSL_FP_FUNCTION_CALL(allocateWA, mcuxClSession_allocateCpuBuffer(session, (uint32_t **) &workArea,
                                                                         sizeof(mcuxClMacModes_WorkArea_t) / sizeof(uint32_t)));
    if(MCUXCLSESSION_STATUS_OK != allocateWA)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Oneshot, MCUXCLMAC_STATUS_FAILURE);
    }

    pContext->cmac_options.bits.initialize = MCUXCLELS_CMAC_INITIALIZE_ENABLE;
    if(MCUXCLKEY_LOADSTATUS_MEMORY == mcuxClKey_getLoadStatus(pContext->key))
    {
      pContext->cmac_options.bits.extkey = MCUXCLELS_CMAC_EXTERNAL_KEY_ENABLE;
    }
    else if(MCUXCLKEY_LOADSTATUS_COPRO == mcuxClKey_getLoadStatus(pContext->key))
    {
      pContext->cmac_options.bits.extkey = MCUXCLELS_CMAC_EXTERNAL_KEY_DISABLE;
    }
    else
    {
      // error: no key loaded
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Oneshot, MCUXCLMAC_STATUS_ERROR);
    }

    //processing part of the data which is a multiple of the block size
    if (completeLen != 0u)
    {
      //data length is a multiple of the block size ==> no padding needed
      if(0u == remainingLen)
      {
        pContext->cmac_options.bits.finalize = MCUXCLELS_CMAC_FINALIZE_ENABLE;
      }

      MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClEls_Cmac_Async(
                            pContext->cmac_options,
                            (mcuxClEls_KeyIndex_t) mcuxClKey_getLoadedKeySlot(pContext->key),
                            (uint8_t const *) mcuxClKey_getLoadedKeyData(pContext->key),
                            (size_t) mcuxClKey_getSize(pContext->key),
                            pIn,
                            completeLen,
                            pOut
                            ));
      // mcuxClEls_Cmac_Async is a flow-protected function: Check the protection token and the return value
      if (MCUXCLELS_STATUS_OK_WAIT != result)
      {
          MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Oneshot, MCUXCLMAC_STATUS_ERROR,
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateCpuBuffer),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async) );
      }

      MCUX_CSSL_FP_FUNCTION_CALL(resultWait, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));

      if (MCUXCLELS_STATUS_OK != resultWait) {
          MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Oneshot, MCUXCLMAC_STATUS_ERROR,
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateCpuBuffer),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation));
      }


      pContext->cmac_options.bits.initialize = MCUXCLELS_CMAC_INITIALIZE_DISABLE;

    }

    //apply padding or process empty message
    if((0u != remainingLen) || (0u == inLength))
    {
      //maximum 15 bytes left to process
      MCUX_CSSL_FP_FUNCTION_CALL(copyResult, mcuxClMemory_copy(workArea->paddingBuff, pIn + completeLen, remainingLen, bufLen ));
      bufLen -= remainingLen;

      /* Check that the buffer is long enough */
      if(copyResult != 0U) {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Oneshot, MCUXCLMAC_STATUS_ERROR,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateCpuBuffer),
            MCUX_CSSL_FP_CONDITIONAL(completeLen != 0u,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation)),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) );
      }


      MCUX_CSSL_FP_FUNCTION_CALL(setResult1, mcuxClMemory_set(workArea->paddingBuff + remainingLen,0x80,0x01U,bufLen));
      bufLen--;

      if(setResult1 != 0U) {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Oneshot, MCUXCLMAC_STATUS_ERROR,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateCpuBuffer),
            MCUX_CSSL_FP_CONDITIONAL(completeLen != 0u,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation)),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set) );
      }

      //fill the rest of the buffer with 0x00
      MCUX_CSSL_FP_FUNCTION_CALL(setResult2, mcuxClMemory_set(workArea->paddingBuff + remainingLen + 1u, 0x00, bufLen, bufLen ));

      if(setResult2 != 0U) {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Oneshot, MCUXCLMAC_STATUS_ERROR,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateCpuBuffer),
            MCUX_CSSL_FP_CONDITIONAL(completeLen != 0u,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation)),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set) );
      }

      pContext->cmac_options.bits.finalize = MCUXCLELS_CMAC_FINALIZE_ENABLE;

      MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClEls_Cmac_Async(
                          pContext->cmac_options,
                          (mcuxClEls_KeyIndex_t) mcuxClKey_getLoadedKeySlot(pContext->key),
                          (uint8_t const *) mcuxClKey_getLoadedKeyData(pContext->key),
                          (size_t) mcuxClKey_getSize(pContext->key),
                          workArea->paddingBuff,
                          remainingLen,
                          pOut
                          ));

      if (MCUXCLELS_STATUS_OK_WAIT != result)
      {
          MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Oneshot, MCUXCLMAC_STATUS_ERROR,
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateCpuBuffer),
              MCUX_CSSL_FP_CONDITIONAL(completeLen != 0u,
                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async),
                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation)),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async) );
      }

      MCUX_CSSL_FP_FUNCTION_CALL(resultWait, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));

      if (MCUXCLELS_STATUS_OK != resultWait) {
          MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Oneshot, MCUXCLMAC_STATUS_ERROR,
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateCpuBuffer),
              MCUX_CSSL_FP_CONDITIONAL(completeLen != 0u,
                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async),
                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation)),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation));
      }

    }

    *pOutLength = MCUXCLELS_CMAC_OUT_SIZE;

    /* Free workArea in Session */
    MCUX_CSSL_FP_FUNCTION_CALL(freeSessionBuffers, mcuxClSession_freeAllCpuBuffers(session));
    if(MCUXCLSESSION_STATUS_OK != freeSessionBuffers)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Oneshot, MCUXCLMAC_STATUS_FAILURE);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClMacModes_Engine_CMAC_Oneshot, MCUXCLMAC_STATUS_OK, MCUXCLMAC_STATUS_FAULT_ATTACK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_allocateCpuBuffer),
        MCUX_CSSL_FP_CONDITIONAL(completeLen != 0u,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation),
          MCUX_CSSL_FP_CONDITIONAL(NULL != pOut,  MCUXCLELS_DMA_READBACK_PROTECTION_TOKEN)
        ),
        MCUX_CSSL_FP_CONDITIONAL((0u != remainingLen) || (0u == inLength),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation),
          MCUX_CSSL_FP_CONDITIONAL(NULL != pOut,  MCUXCLELS_DMA_READBACK_PROTECTION_TOKEN)
        ),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_freeAllCpuBuffers)
    );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_Engine_CMAC_Init)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMacModes_Engine_CMAC_Init(
  mcuxClSession_Handle_t session UNUSED_PARAM,
  mcuxClMacModes_Context_t * const pContext)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_Engine_CMAC_Init, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set), MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set));
  pContext->blockBufferUsed = 0;
  MCUX_CSSL_FP_FUNCTION_CALL(resultSet1, mcuxClMemory_set((uint8_t*)(pContext->blockBuffer),0x00,MCUXCLAES_BLOCK_SIZE,MCUXCLAES_BLOCK_SIZE));
  MCUX_CSSL_FP_FUNCTION_CALL(resultSet2, mcuxClMemory_set((uint8_t*)(pContext->state),0x00,MCUXCLAES_BLOCK_SIZE,MCUXCLAES_BLOCK_SIZE));
  if((resultSet1 != 0U) || (resultSet2 != 0U)) {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Init, MCUXCLMAC_STATUS_ERROR);
  }

  pContext->cmac_options.word.value = 0U;

  pContext->cmac_options.bits.initialize = MCUXCLELS_CMAC_INITIALIZE_ENABLE;
  if(MCUXCLKEY_LOADSTATUS_MEMORY == mcuxClKey_getLoadStatus(pContext->key))
  {
    pContext->cmac_options.bits.extkey = MCUXCLELS_CMAC_EXTERNAL_KEY_ENABLE;
  }
  else if(MCUXCLKEY_LOADSTATUS_COPRO == mcuxClKey_getLoadStatus(pContext->key))
  {
    pContext->cmac_options.bits.extkey = MCUXCLELS_CMAC_EXTERNAL_KEY_DISABLE;
  }
  else
  {
    // error: no key loaded
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Init, MCUXCLMAC_STATUS_ERROR);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClMacModes_Engine_CMAC_Init, MCUXCLMAC_STATUS_OK, MCUXCLMAC_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_Engine_CMAC_Update)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMacModes_Engine_CMAC_Update(
  mcuxClSession_Handle_t session UNUSED_PARAM,
  mcuxClMacModes_Context_t * const pContext,
  const uint8_t *const pIn,
  uint32_t inLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_Engine_CMAC_Update);
  size_t remainingLength = inLength;
  size_t alreadyProcessedBytes = 0;

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_CONDITIONAL(((pContext->blockBufferUsed > 0U) && ((pContext->blockBufferUsed + inLength) > MCUXCLAES_BLOCK_SIZE)),
                                    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                                    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async),
                                    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation),
                                    MCUXCLELS_DMA_READBACK_PROTECTION_TOKEN
                                    ));
  //check if there are "old" bytes to process
  if((pContext->blockBufferUsed > 0U) && ((pContext->blockBufferUsed + inLength) > MCUXCLAES_BLOCK_SIZE))
  {
    //copy new input data
    MCUX_CSSL_FP_FUNCTION_CALL(resultCopy, mcuxClMemory_copy((uint8_t*)pContext->blockBuffer + pContext->blockBufferUsed,
                      pIn,
                      MCUXCLAES_BLOCK_SIZE - pContext->blockBufferUsed,
                      MCUXCLAES_BLOCK_SIZE - pContext->blockBufferUsed ));

    if(resultCopy != 0U) {
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Update, MCUXCLMAC_STATUS_ERROR,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) );
    }

    //perform cmac operation
    MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClEls_Cmac_Async(
                        pContext->cmac_options,
                        (mcuxClEls_KeyIndex_t) mcuxClKey_getLoadedKeySlot(pContext->key),
                        (uint8_t const *) mcuxClKey_getLoadedKeyData(pContext->key),
                        (size_t) mcuxClKey_getSize(pContext->key),
                        (uint8_t*)pContext->blockBuffer,
                        MCUXCLAES_BLOCK_SIZE,
                        (uint8_t*)pContext->state
                        ));

    // mcuxClEls_Cmac_Async is a flow-protected function: Check the protection token and the return value
    if (MCUXCLELS_STATUS_OK_WAIT != result)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Update, MCUXCLMAC_STATUS_ERROR,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async) );
    }

    MCUX_CSSL_FP_FUNCTION_CALL(resultWait, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));

    if (MCUXCLELS_STATUS_OK != resultWait) {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Update, MCUXCLMAC_STATUS_ERROR,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) );
    }


    //update options for the next operations
    pContext->cmac_options.bits.initialize = MCUXCLELS_CMAC_INITIALIZE_DISABLE;

    remainingLength -= (MCUXCLAES_BLOCK_SIZE - pContext->blockBufferUsed);
    alreadyProcessedBytes = (MCUXCLAES_BLOCK_SIZE - pContext->blockBufferUsed);

    pContext->blockBufferUsed = 0;

  }

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_CONDITIONAL((MCUXCLAES_BLOCK_SIZE < remainingLength),
                      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async),
                      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation),
                      MCUXCLELS_DMA_READBACK_PROTECTION_TOKEN));

  //check if there are full block of input data available
  if(MCUXCLAES_BLOCK_SIZE < remainingLength)
  {
    size_t  completeLen = (remainingLength/MCUXCLAES_BLOCK_SIZE)*MCUXCLAES_BLOCK_SIZE;

    //if remaining length is a multiple of the block size,
    //keep on block. We need it for the finalize operation
    if(remainingLength == completeLen)
    {
      completeLen -= MCUXCLAES_BLOCK_SIZE;
    }

    //perform cmac operation
    MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClEls_Cmac_Async(
                                 pContext->cmac_options,
                                 (mcuxClEls_KeyIndex_t) mcuxClKey_getLoadedKeySlot(pContext->key),
                                 (uint8_t const *) mcuxClKey_getLoadedKeyData(pContext->key),
                                 (size_t) mcuxClKey_getSize(pContext->key),
                                 pIn + alreadyProcessedBytes,
                                 completeLen,
                                 (uint8_t*)pContext->state
                                 ));
    // mcuxClEls_Cmac_Async is a flow-protected function: Check the protection token and the return value
    if (MCUXCLELS_STATUS_OK_WAIT != result) {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Update, MCUXCLMAC_STATUS_ERROR,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async) );
    }

    MCUX_CSSL_FP_FUNCTION_CALL(resultWait, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));

    if (MCUXCLELS_STATUS_OK != resultWait) {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Update, MCUXCLMAC_STATUS_ERROR,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) );
    }


    pContext->cmac_options.bits.initialize = MCUXCLELS_CMAC_INITIALIZE_DISABLE;

    remainingLength -= completeLen;
    alreadyProcessedBytes += completeLen;

  }

  //check if there is still input data left that needs to be copied to the context
  if(remainingLength != 0u)
  {
    //maximum 16 bytes left
    MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClMemory_copy((uint8_t*)pContext->blockBuffer + pContext->blockBufferUsed,
                     pIn + alreadyProcessedBytes,
                     remainingLength,
                     sizeof(pContext->blockBuffer) - pContext->blockBufferUsed));

    if(result != 0U) {
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Update, MCUXCLMAC_STATUS_ERROR,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) );
    }

    pContext->blockBufferUsed += (uint8_t) remainingLength;
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClMacModes_Engine_CMAC_Update, MCUXCLMAC_STATUS_OK, MCUXCLMAC_STATUS_FAULT_ATTACK,
    MCUX_CSSL_FP_CONDITIONAL(remainingLength != 0u, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy))
  );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMacModes_Engine_CMAC_Finalize)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMacModes_Engine_CMAC_Finalize(
  mcuxClSession_Handle_t session UNUSED_PARAM,
  mcuxClMacModes_Context_t * const pContext,
  uint8_t *const pOut,
  uint32_t *const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMacModes_Engine_CMAC_Finalize);
  pContext->cmac_options.bits.finalize = MCUXCLELS_CMAC_FINALIZE_ENABLE;

  //apply padding if needed
  if(MCUXCLAES_BLOCK_SIZE > pContext->blockBufferUsed)
  {
    ((uint8_t*)(pContext->blockBuffer))[pContext->blockBufferUsed] = 0x80U;

    //fill the rest of the buffer with 0x00. In case pContext->blockBufferUsed==15, the length for mcuxClMemory_set will be zero
    MCUX_CSSL_FP_FUNCTION_CALL(resultSet1, mcuxClMemory_set(((uint8_t*)pContext->blockBuffer) + pContext->blockBufferUsed + 1u, 0x00,
                    MCUXCLAES_BLOCK_SIZE - ((size_t) pContext->blockBufferUsed + 1u),
                    MCUXCLAES_BLOCK_SIZE - ((size_t) pContext->blockBufferUsed + 1u) ));
    if(resultSet1 != 0U) {
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Finalize, MCUXCLMAC_STATUS_ERROR,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set) );
    }

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set));
  }

  //perform cmac operation
  MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClEls_Cmac_Async(pContext->cmac_options,
                               (mcuxClEls_KeyIndex_t) (mcuxClKey_getLoadedKeySlot(pContext->key)),
                               (uint8_t const *) mcuxClKey_getLoadedKeyData(pContext->key),
                               (size_t) mcuxClKey_getSize(pContext->key),
                               (uint8_t*)(pContext->blockBuffer),
                               pContext->blockBufferUsed,
                               (uint8_t*)(pContext->state)));
  // mcuxClEls_Cmac_Async is a flow-protected function: Check the protection token and the return value
  if (MCUXCLELS_STATUS_OK_WAIT != result) {
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Finalize, MCUXCLMAC_STATUS_ERROR,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async) );
  }

  MCUX_CSSL_FP_FUNCTION_CALL(resultWait, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));

  if (MCUXCLELS_STATUS_OK != resultWait) {
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Finalize, MCUXCLMAC_STATUS_ERROR,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) );
  }


  //copy result to output buffer
  MCUX_CSSL_FP_FUNCTION_CALL(resultCopy, mcuxClMemory_copy(pOut,
                   (uint8_t*)pContext->state,
                   pContext->common.pMode->common.macByteSize,
                   pContext->common.pMode->common.macByteSize));

  if(resultCopy != 0U) {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Finalize, MCUXCLMAC_STATUS_ERROR,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
        MCUXCLELS_DMA_READBACK_PROTECTION_TOKEN);
  }

  *pOutLength = MCUXCLELS_CMAC_OUT_SIZE;

  //context isn't needed any longer; destroy it
  MCUX_CSSL_FP_FUNCTION_CALL(resultSet, mcuxClMemory_set((uint8_t*)(pContext),0x00,sizeof(mcuxClMacModes_Context_t),sizeof(mcuxClMacModes_Context_t)));

  if(resultSet != 0U) {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMacModes_Engine_CMAC_Finalize, MCUXCLMAC_STATUS_ERROR,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
        MCUXCLELS_DMA_READBACK_PROTECTION_TOKEN);
  }


  MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClMacModes_Engine_CMAC_Finalize, MCUXCLMAC_STATUS_OK, MCUXCLMAC_STATUS_FAULT_ATTACK,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
        MCUXCLELS_DMA_READBACK_PROTECTION_TOKEN);
}

/* MISRA Ex. 20 - Rule 5.1 */
const mcuxClMacModes_AlgorithmDescriptor_t mcuxClMacModes_AlgorithmDescriptor_CMAC = {
  .engineInit = mcuxClMacModes_Engine_CMAC_Init,
  .protectionToken_engineInit =  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_Engine_CMAC_Init),
  .engineUpdate =  mcuxClMacModes_Engine_CMAC_Update,
  .protectionToken_engineUpdate =  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_Engine_CMAC_Update),
  .engineFinalize =  mcuxClMacModes_Engine_CMAC_Finalize,
  .protectionToken_engineFinalize =  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_Engine_CMAC_Finalize),
  .engineOneshot = mcuxClMacModes_Engine_CMAC_Oneshot,
  .protectionToken_engineOneshot = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMacModes_Engine_CMAC_Oneshot),
  .addPadding = NULL,
  .protectionToken_addPadding = 0u,
};
