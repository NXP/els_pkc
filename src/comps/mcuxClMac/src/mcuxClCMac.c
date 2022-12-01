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

/** @file  mcuxClCMac.c
 *  @brief implementation of CMAC part of mcuxClMac component */

#include <mcuxClMac.h>

#include <mcuxClCss.h>
#include <mcuxClCss_Cmac.h>
#include <mcuxClMemory.h>
#include <mcuxClKey.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <toolchain.h>
#include <internal/mcuxClMac_Internal.h>
#include <internal/mcuxClKey_Internal.h>
#include <mcuxClAes.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMac_Engine_CMAC_Oneshot)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_CMAC_Oneshot(mcuxClMac_Context_t *pContext, const uint8_t *const pIn, uint32_t inLength, uint8_t *const pOut, uint32_t *const pOutLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMac_Engine_CMAC_Oneshot);
    size_t const completeLen = (inLength/MCUX_CL_AES_BLOCK_SIZE)*MCUX_CL_AES_BLOCK_SIZE;
    /* MISRA Ex. 9 to Rule 11.3 */
    uint8_t *aesBlock = (uint8_t*) &(pContext->session->cpuWa.buffer[pContext->session->cpuWa.used]);
    size_t bufLen = MCUX_CL_AES_BLOCK_SIZE;
    size_t const remainingLen = inLength - completeLen;
    *pOutLength = MCUXCLCSS_CMAC_OUT_SIZE;

    // Check if key matches to the algorithm
    if (MCUX_CL_KEY_ALGO_ID_AES != mcuxClKey_getAlgorithm(pContext->key))
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR);
    }

    pContext->cmac_options.bits.initialize = MCUXCLCSS_CMAC_INITIALIZE_ENABLE;
    if(MCUX_CL_KEY_LOADSTATUS_MEMORY == mcuxClKey_getLoadStatus(pContext->key))
    {
      pContext->cmac_options.bits.extkey = MCUXCLCSS_CMAC_EXTERNAL_KEY_ENABLE;
    }
    else if(MCUX_CL_KEY_LOADSTATUS_COPRO == mcuxClKey_getLoadStatus(pContext->key))
    {
      pContext->cmac_options.bits.extkey = MCUXCLCSS_CMAC_EXTERNAL_KEY_DISABLE;
    }
    else
    {
      // error: no key loaded
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR);
    }

    //processing part of the data which is a multiple of the block size
    if (completeLen != 0u)
    {
      //data length is a multiple of the block size ==> no padding needed
      if(0u == remainingLen)
      {
        pContext->cmac_options.bits.finalize = MCUXCLCSS_CMAC_FINALIZE_ENABLE;
      }

      MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClCss_Cmac_Async(
                            pContext->cmac_options,
                            (mcuxClCss_KeyIndex_t) mcuxClKey_getLoadedKeySlot(pContext->key),
                            (uint8_t const *) mcuxClKey_getKeyData(pContext->key),
                            (size_t) mcuxClKey_getSize(pContext->key),
                            pIn,
                            completeLen,
                            pOut
                            ));
      // mcuxClCss_Cmac_Async is a flow-protected function: Check the protection token and the return value
      if (MCUXCLCSS_STATUS_OK_WAIT != result)
      {
          MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR,
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async) );
      }

      MCUX_CSSL_FP_FUNCTION_CALL(resultWait, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

      if (MCUXCLCSS_STATUS_OK != resultWait) {
          MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR,
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));
      }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
      if(NULL != pOut)
      {
          MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult1, mcuxClCss_CompareDmaFinalOutputAddress(pOut, MCUXCLCSS_CMAC_OUT_SIZE));

          if (MCUXCLCSS_STATUS_OK != addressComparisonResult1)
          {
              MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Oneshot, MCUXCLMAC_ERRORCODE_FAULT_ATTACK);
          }
      }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

      pContext->cmac_options.bits.initialize = MCUXCLCSS_CMAC_INITIALIZE_DISABLE;

    }

    //apply padding or process empty message
    if((0u != remainingLen) || (0u == inLength))
    {
      //maximum 15 bytes left to process
      MCUX_CSSL_FP_FUNCTION_CALL(copyResult, mcuxClMemory_copy(aesBlock, pIn + completeLen, remainingLen, bufLen ));
      bufLen -= remainingLen;

      /* Check that the buffer is long enough */
      if(copyResult != 0U) {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR,
            MCUX_CSSL_FP_CONDITIONAL(completeLen != 0u,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation)),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) );
      }


      MCUX_CSSL_FP_FUNCTION_CALL(setResult1, mcuxClMemory_set(aesBlock + remainingLen,0x80,0x01U,bufLen));
      bufLen--;

      if(setResult1 != 0U) {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR,
            MCUX_CSSL_FP_CONDITIONAL(completeLen != 0u,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation)),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set) );
      }

      //fill the rest of the buffer with 0x00
      MCUX_CSSL_FP_FUNCTION_CALL(setResult2, mcuxClMemory_set(aesBlock + remainingLen + 1u, 0x00, bufLen, bufLen ));

      if(setResult2 != 0U) {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR,
            MCUX_CSSL_FP_CONDITIONAL(completeLen != 0u,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation)),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set) );
      }

      pContext->cmac_options.bits.finalize = MCUXCLCSS_CMAC_FINALIZE_ENABLE;

      MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClCss_Cmac_Async(
                          pContext->cmac_options,
                          (mcuxClCss_KeyIndex_t) mcuxClKey_getLoadedKeySlot(pContext->key),
                          (uint8_t const *) mcuxClKey_getKeyData(pContext->key),
                          (size_t) mcuxClKey_getSize(pContext->key),
                          aesBlock,
                          remainingLen,
                          pOut
                          ));

      if (MCUXCLCSS_STATUS_OK_WAIT != result)
      {
          MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR,
              MCUX_CSSL_FP_CONDITIONAL(completeLen != 0u,
                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation)),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async) );
      }

      MCUX_CSSL_FP_FUNCTION_CALL(resultWait, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

      if (MCUXCLCSS_STATUS_OK != resultWait) {
          MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR,
              MCUX_CSSL_FP_CONDITIONAL(completeLen != 0u,
                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
                  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation)),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) );
      }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
      if(NULL != pOut)
      {
          MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult2, mcuxClCss_CompareDmaFinalOutputAddress(pOut, MCUXCLCSS_CMAC_OUT_SIZE));

          if (MCUXCLCSS_STATUS_OK != addressComparisonResult2)
          {
              MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Oneshot, MCUXCLMAC_ERRORCODE_FAULT_ATTACK);
          }
      }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

    }

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClMac_Engine_CMAC_Oneshot, MCUXCLMAC_ERRORCODE_OK, MCUXCLMAC_ERRORCODE_FAULT_ATTACK,
        MCUX_CSSL_FP_CONDITIONAL(completeLen != 0u, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async), MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation), MCUX_CSSL_FP_CONDITIONAL(NULL != pOut,  MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN)),
        MCUX_CSSL_FP_CONDITIONAL((0u != remainingLen) || (0u == inLength), MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy), MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set), MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set), MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async), MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
                          MCUX_CSSL_FP_CONDITIONAL(NULL != pOut,  MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN))
    );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMac_Engine_CMAC_Init)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_CMAC_Init(mcuxClMac_Context_t *pContext,
                                                                        const uint8_t *const pIn UNUSED_PARAM,
                                                                        uint32_t inLength UNUSED_PARAM,
                                                                        uint8_t *const pOut UNUSED_PARAM,
                                                                        uint32_t *const pOutLength UNUSED_PARAM)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMac_Engine_CMAC_Init, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set), MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set));
  pContext->nrOfUnprocessedBytes = 0;
  MCUX_CSSL_FP_FUNCTION_CALL(resultSet1, mcuxClMemory_set((uint8_t*)(pContext->unprocessed),0x00,MCUX_CL_AES_BLOCK_SIZE,MCUX_CL_AES_BLOCK_SIZE));
  MCUX_CSSL_FP_FUNCTION_CALL(resultSet2, mcuxClMemory_set((uint8_t*)(pContext->state),0x00,MCUX_CL_AES_BLOCK_SIZE,MCUX_CL_AES_BLOCK_SIZE));
  if((resultSet1 != 0U) || (resultSet2 != 0U)) {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Init, MCUXCLMAC_ERRORCODE_ERROR);
  }

  pContext->cmac_options.word.value = 0U;

  pContext->cmac_options.bits.initialize = MCUXCLCSS_CMAC_INITIALIZE_ENABLE;
  if(MCUX_CL_KEY_LOADSTATUS_MEMORY == mcuxClKey_getLoadStatus(pContext->key))
  {
    pContext->cmac_options.bits.extkey = MCUXCLCSS_CMAC_EXTERNAL_KEY_ENABLE;
  }
  else if(MCUX_CL_KEY_LOADSTATUS_COPRO == mcuxClKey_getLoadStatus(pContext->key))
  {
    pContext->cmac_options.bits.extkey = MCUXCLCSS_CMAC_EXTERNAL_KEY_DISABLE;
  }
  else
  {
    // error: no key loaded
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Init, MCUXCLMAC_ERRORCODE_ERROR);
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClMac_Engine_CMAC_Init, MCUXCLMAC_ERRORCODE_OK, MCUXCLMAC_ERRORCODE_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMac_Engine_CMAC_Update)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_CMAC_Update(mcuxClMac_Context_t *pContext,
                                                                          const uint8_t *const pIn,
                                                                          uint32_t inLength,
                                                                          uint8_t *const pOut UNUSED_PARAM,
                                                                          uint32_t *const pOutLength UNUSED_PARAM)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMac_Engine_CMAC_Update);
  size_t remainingLength = inLength;
  size_t alreadyProcessedBytes = 0;

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_CONDITIONAL(((pContext->nrOfUnprocessedBytes > 0U) && ((pContext->nrOfUnprocessedBytes + inLength) > MCUX_CL_AES_BLOCK_SIZE)),
                                    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                                    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
                                    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
                                    MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN
                                    ));
  //check if there are "old" bytes to process
  if((pContext->nrOfUnprocessedBytes > 0U) && ((pContext->nrOfUnprocessedBytes + inLength) > MCUX_CL_AES_BLOCK_SIZE))
  {
    //copy new input data
    MCUX_CSSL_FP_FUNCTION_CALL(resultCopy, mcuxClMemory_copy((uint8_t*)pContext->unprocessed + pContext->nrOfUnprocessedBytes,
                      pIn,
                      MCUX_CL_AES_BLOCK_SIZE - pContext->nrOfUnprocessedBytes,
                      MCUX_CL_AES_BLOCK_SIZE - pContext->nrOfUnprocessedBytes ));

    if(resultCopy != 0U) {
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Update, MCUXCLMAC_ERRORCODE_ERROR,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) );
    }

    //perform cmac operation
    MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClCss_Cmac_Async(
                        pContext->cmac_options,
                        (mcuxClCss_KeyIndex_t) mcuxClKey_getLoadedKeySlot(pContext->key),
                        (uint8_t const *) mcuxClKey_getKeyData(pContext->key),
                        (size_t) mcuxClKey_getSize(pContext->key),
                        (uint8_t*)pContext->unprocessed,
                        MCUX_CL_AES_BLOCK_SIZE,
                        (uint8_t*)pContext->state
                        ));

    // mcuxClCss_Cmac_Async is a flow-protected function: Check the protection token and the return value
    if (MCUXCLCSS_STATUS_OK_WAIT != result)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Update, MCUXCLMAC_ERRORCODE_ERROR,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async) );
    }

    MCUX_CSSL_FP_FUNCTION_CALL(resultWait, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

    if (MCUXCLCSS_STATUS_OK != resultWait) {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Update, MCUXCLMAC_ERRORCODE_ERROR,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) );
    }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
    MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult1, mcuxClCss_CompareDmaFinalOutputAddress((uint8_t*)pContext->state, MCUXCLCSS_CMAC_OUT_SIZE));

    if (MCUXCLCSS_STATUS_OK != addressComparisonResult1)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Update, MCUXCLMAC_ERRORCODE_FAULT_ATTACK);
    }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

    //update options for the next operations
    pContext->cmac_options.bits.initialize = MCUXCLCSS_CMAC_INITIALIZE_DISABLE;

    remainingLength -= (MCUX_CL_AES_BLOCK_SIZE - pContext->nrOfUnprocessedBytes);
    alreadyProcessedBytes = (MCUX_CL_AES_BLOCK_SIZE - pContext->nrOfUnprocessedBytes);

    pContext->nrOfUnprocessedBytes = 0;

  }

  MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_CONDITIONAL((MCUX_CL_AES_BLOCK_SIZE < remainingLength),
                      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
                      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
                      MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN));

  //check if there are full block of input data available
  if(MCUX_CL_AES_BLOCK_SIZE < remainingLength)
  {
    size_t  completeLen = (remainingLength/MCUX_CL_AES_BLOCK_SIZE)*MCUX_CL_AES_BLOCK_SIZE;

    //if remaining length is a multiple of the block size,
    //keep on block. We need it for the finalize operation
    if(remainingLength == completeLen)
    {
      completeLen -= MCUX_CL_AES_BLOCK_SIZE;
    }

    //perform cmac operation
    MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClCss_Cmac_Async(
                                 pContext->cmac_options,
                                 (mcuxClCss_KeyIndex_t) mcuxClKey_getLoadedKeySlot(pContext->key),
                                 (uint8_t const *) mcuxClKey_getKeyData(pContext->key),
                                 (size_t) mcuxClKey_getSize(pContext->key),
                                 pIn + alreadyProcessedBytes,
                                 completeLen,
                                 (uint8_t*)pContext->state
                                 ));
    // mcuxClCss_Cmac_Async is a flow-protected function: Check the protection token and the return value
    if (MCUXCLCSS_STATUS_OK_WAIT != result) {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Update, MCUXCLMAC_ERRORCODE_ERROR,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async) );
    }

    MCUX_CSSL_FP_FUNCTION_CALL(resultWait, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

    if (MCUXCLCSS_STATUS_OK != resultWait) {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Update, MCUXCLMAC_ERRORCODE_ERROR,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) );
    }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
    MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult2, mcuxClCss_CompareDmaFinalOutputAddress((uint8_t*)pContext->state, MCUXCLCSS_CMAC_OUT_SIZE));

    if (MCUXCLCSS_STATUS_OK != addressComparisonResult2)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Update, MCUXCLMAC_ERRORCODE_FAULT_ATTACK);
    }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

    pContext->cmac_options.bits.initialize = MCUXCLCSS_CMAC_INITIALIZE_DISABLE;

    remainingLength -= completeLen;
    alreadyProcessedBytes += completeLen;

  }

  //check if there is still input data left that needs to be copied to the context
  if(remainingLength != 0u)
  {
    //maximum 16 bytes left
    MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClMemory_copy((uint8_t*)pContext->unprocessed + pContext->nrOfUnprocessedBytes,
                     pIn + alreadyProcessedBytes,
                     remainingLength,
                     sizeof(pContext->unprocessed) - pContext->nrOfUnprocessedBytes));

    if(result != 0U) {
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Update, MCUXCLMAC_ERRORCODE_ERROR,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) );
    }

    pContext->nrOfUnprocessedBytes += (uint8_t) remainingLength;
  }

  MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClMac_Engine_CMAC_Update, MCUXCLMAC_ERRORCODE_OK, MCUXCLMAC_ERRORCODE_FAULT_ATTACK,
    MCUX_CSSL_FP_CONDITIONAL(remainingLength != 0u, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy))
  );
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMac_Engine_CMAC_Finalize)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_CMAC_Finalize(mcuxClMac_Context_t *pContext,
                                                                            const uint8_t *const pIn UNUSED_PARAM,
                                                                            uint32_t inLength UNUSED_PARAM,
                                                                            uint8_t *const pOut,
                                                                            uint32_t *const pOutLength)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMac_Engine_CMAC_Finalize);
  pContext->cmac_options.bits.finalize = MCUXCLCSS_CMAC_FINALIZE_ENABLE;

  //apply padding if needed
  if(MCUX_CL_AES_BLOCK_SIZE > pContext->nrOfUnprocessedBytes)
  {
    ((uint8_t*)(pContext->unprocessed))[pContext->nrOfUnprocessedBytes] = 0x80U;

    //fill the rest of the buffer with 0x00. In case pContext->nrOfUnprocessedBytes==15, the length for mcuxClMemory_set will be zero
    MCUX_CSSL_FP_FUNCTION_CALL(resultSet1, mcuxClMemory_set(((uint8_t*)pContext->unprocessed) + pContext->nrOfUnprocessedBytes + 1u, 0x00,
                    MCUX_CL_AES_BLOCK_SIZE - ((size_t) pContext->nrOfUnprocessedBytes + 1u),
                    MCUX_CL_AES_BLOCK_SIZE - ((size_t) pContext->nrOfUnprocessedBytes + 1u) ));
    if(resultSet1 != 0U) {
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Finalize, MCUXCLMAC_ERRORCODE_ERROR,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set) );
    }

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set));
  }

  //perform cmac operation
  MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClCss_Cmac_Async(pContext->cmac_options,
                               (mcuxClCss_KeyIndex_t) (mcuxClKey_getLoadedKeySlot(pContext->key)),
                               (uint8_t const *) mcuxClKey_getKeyData(pContext->key),
                               (size_t) mcuxClKey_getSize(pContext->key),
                               (uint8_t*)(pContext->unprocessed),
                               pContext->nrOfUnprocessedBytes,
                               (uint8_t*)(pContext->state)));
  // mcuxClCss_Cmac_Async is a flow-protected function: Check the protection token and the return value
  if (MCUXCLCSS_STATUS_OK_WAIT != result) {
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Finalize, MCUXCLMAC_ERRORCODE_ERROR,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async) );
  }

  MCUX_CSSL_FP_FUNCTION_CALL(resultWait, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

  if (MCUXCLCSS_STATUS_OK != resultWait) {
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Finalize, MCUXCLMAC_ERRORCODE_ERROR,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) );
  }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
  MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult1, mcuxClCss_CompareDmaFinalOutputAddress((uint8_t*)pContext->state, MCUXCLCSS_CMAC_OUT_SIZE));

  if (MCUXCLCSS_STATUS_OK != addressComparisonResult1)
  {
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Finalize, MCUXCLMAC_ERRORCODE_FAULT_ATTACK);
  }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

  if(MCUXCLCSS_CMAC_OUT_SIZE < *pOutLength) {
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Finalize, MCUXCLMAC_ERRORCODE_ERROR,
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) );
  }

  //copy result to output buffer
  MCUX_CSSL_FP_FUNCTION_CALL(resultCopy, mcuxClMemory_copy(pOut,
                   (uint8_t*)pContext->state,
                   *pOutLength,
                   *pOutLength ));

  if(resultCopy != 0U) {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Finalize, MCUXCLMAC_ERRORCODE_ERROR,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy), 
        MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN);
  }

  //context isn't needed any longer; destroy it
  MCUX_CSSL_FP_FUNCTION_CALL(resultSet, mcuxClMemory_set((uint8_t*)(pContext),0x00,sizeof(mcuxClMac_Context_t),sizeof(mcuxClMac_Context_t)));

  if(resultSet != 0U) {
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CMAC_Finalize, MCUXCLMAC_ERRORCODE_ERROR,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set) );
  }


  MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClMac_Engine_CMAC_Finalize, MCUXCLMAC_ERRORCODE_OK, MCUXCLMAC_ERRORCODE_FAULT_ATTACK,
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set) );
}

const mcuxClMac_ModeDescriptor_t  mcuxClMac_ModeDescriptor_CMAC = {
  .engineInit = mcuxClMac_Engine_CMAC_Init,
  .engineUpdate = mcuxClMac_Engine_CMAC_Update,
  .engineFinalize = mcuxClMac_Engine_CMAC_Finalize,
  .engineOneshot = mcuxClMac_Engine_CMAC_Oneshot,
  .protectionTokenInit = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_CMAC_Init),
  .protectionTokenUpdate = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_CMAC_Update),
  .protectionTokenFinalize = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_CMAC_Finalize),
  .protectionTokenOneshot = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_CMAC_Oneshot),
  .macByteSize = MCUXCLCSS_CMAC_OUT_SIZE
  };

