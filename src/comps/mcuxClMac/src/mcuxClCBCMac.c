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

/** @file  mcuxClCBCMac.c
 *  @brief implementation of CBC-MAC part of mcuxClMac component */

#include <mcuxClMac.h>
#include <mcuxClKey.h>
#include <mcuxClMemory.h>
#include <internal/mcuxClPadding_Internal.h>
#include <mcuxClAes.h>

#include <mcuxClCss.h>
#include <mcuxClCss_Cmac.h>

#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <internal/mcuxClKey_Internal.h>

#include <toolchain.h>
#include <internal/mcuxClMac_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMac_Engine_CBCMAC_Oneshot)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_CBCMAC_Oneshot(mcuxClMac_Context_t *pContext, 
                                                                             const uint8_t *const pIn, 
                                                                             uint32_t inLength, 
                                                                             uint8_t *const pOut,
                                                                             uint32_t *const pOutLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMac_Engine_CBCMAC_Oneshot);

    // Check if key matches the algorithm
    if (MCUX_CL_KEY_ALGO_ID_AES != mcuxClKey_getAlgorithm(pContext->key))
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR);
    }

    // Disable initialize/finalize for cbc-mac compitability.  
    pContext->cmac_options.bits.initialize = MCUXCLCSS_CMAC_INITIALIZE_DISABLE;
    pContext->cmac_options.bits.finalize = MCUXCLCSS_CMAC_FINALIZE_DISABLE;

    // Get key location
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
        // Error: no key loaded
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR);
    }

    size_t noOfFullBlocks = inLength / MCUX_CL_AES_BLOCK_SIZE;
    size_t remainingBytes = inLength - (noOfFullBlocks * MCUX_CL_AES_BLOCK_SIZE);
    MCUX_CSSL_FP_FUNCTION_CALL(setResult, mcuxClMemory_set(pOut, 0x00, MCUXCLCSS_CMAC_OUT_SIZE, MCUXCLCSS_CMAC_OUT_SIZE));
    if (0u != setResult)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR);
    }
    // Call css cmac on all full blocks
    MCUX_CSSL_FP_FUNCTION_CALL(cmacResult1, mcuxClCss_Cmac_Async(
                            pContext->cmac_options,
                            (mcuxClCss_KeyIndex_t) mcuxClKey_getLoadedKeySlot(pContext->key),
                            (uint8_t const *) mcuxClKey_getKeyData(pContext->key),
                            (size_t) mcuxClKey_getSize(pContext->key),
                            pIn,
                            noOfFullBlocks * MCUX_CL_AES_BLOCK_SIZE,
                            pOut));

    // mcuxClCss_Cmac_Async is a flow-protected function: Check the protection token and the return value
    if (MCUXCLCSS_STATUS_OK_WAIT != cmacResult1)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async));
    }

    MCUX_CSSL_FP_FUNCTION_CALL(waitResult1, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
    MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult, mcuxClCss_CompareDmaFinalOutputAddress(pOut, MCUXCLCSS_CMAC_OUT_SIZE));

    if (MCUXCLCSS_STATUS_OK != addressComparisonResult)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR);
    }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

    if (MCUXCLCSS_STATUS_OK != waitResult1) 
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));
    }
    
    uint32_t paddingOutLength = 0u;
    // Call padding function 
    MCUX_CSSL_FP_FUNCTION_CALL(paddingResult, pContext->mode->pPaddingFunction(
    /* uint32_t blockLength */          MCUX_CL_AES_BLOCK_SIZE,
    /* const uint8_t *const pIn */      (pIn + (MCUX_CL_AES_BLOCK_SIZE * noOfFullBlocks)), // this should be only the last block! 
    /* uint32_t lastBlockLength */      remainingBytes,
    /* uint32_t totalInputLength */     inLength,
    /* uint8_t *const pOut */           (uint8_t*)pContext->unprocessed,
    /* uint32_t *const pOutLength */    &paddingOutLength));
    
    // padding functions are flow-protected: Check the protection token and the return value
    if (MCUXCLPADDING_STATUS_OK != paddingResult)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR);
    }
    
    if(paddingOutLength != 0u)
    {
        // Call css cmac on the padded block
        MCUX_CSSL_FP_FUNCTION_CALL(cmacResult2, mcuxClCss_Cmac_Async(
                                pContext->cmac_options,
                                (mcuxClCss_KeyIndex_t) mcuxClKey_getLoadedKeySlot(pContext->key),
                                (uint8_t const *) mcuxClKey_getKeyData(pContext->key),
                                (size_t) mcuxClKey_getSize(pContext->key),
                                (uint8_t*)pContext->unprocessed,
                                MCUX_CL_AES_BLOCK_SIZE,
                                pOut));

        // mcuxClCss_Cmac_Async is a flow-protected function: Check the protection token and the return value
        if (MCUXCLCSS_STATUS_OK_WAIT != cmacResult2)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async));
        }

        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));

        MCUX_CSSL_FP_FUNCTION_CALL(waitResult2, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

        if (MCUXCLCSS_STATUS_OK != waitResult2) 
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR);
        }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK

        MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult, mcuxClCss_CompareDmaFinalOutputAddress(pOut, MCUXCLCSS_CMAC_OUT_SIZE));

        if (MCUXCLCSS_STATUS_OK != addressComparisonResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Update, MCUXCLMAC_ERRORCODE_ERROR);
        }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */
    }

    if((0u != inLength) || (paddingOutLength != 0u))
    {
        *pOutLength = MCUXCLCSS_CMAC_OUT_SIZE;
    }
    
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Oneshot, MCUXCLMAC_ERRORCODE_OK,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
            pContext->mode->protectionTokenPaddingFunction,
            MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN,
            MCUX_CSSL_FP_CONDITIONAL((paddingOutLength != 0u),
                MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async)),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMac_Engine_CBCMAC_Init)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_CBCMAC_Init(mcuxClMac_Context_t *pContext,
                                                                          const uint8_t *const pIn UNUSED_PARAM,
                                                                          uint32_t inLength UNUSED_PARAM,
                                                                          uint8_t *const pOut UNUSED_PARAM,
                                                                          uint32_t *const pOutLength UNUSED_PARAM)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMac_Engine_CBCMAC_Init, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set), MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set));
    
    pContext->nrOfUnprocessedBytes = 0;

    MCUX_CSSL_FP_FUNCTION_CALL(setResult1, mcuxClMemory_set((uint8_t*)(pContext->unprocessed), 0x00, MCUX_CL_AES_BLOCK_SIZE, MCUX_CL_AES_BLOCK_SIZE));
    MCUX_CSSL_FP_FUNCTION_CALL(setResult2, mcuxClMemory_set((uint8_t*)(pContext->state), 0x00, MCUX_CL_AES_BLOCK_SIZE, MCUX_CL_AES_BLOCK_SIZE));
    
    if((0U != setResult1) || (0U != setResult2)) 
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Init, MCUXCLMAC_ERRORCODE_ERROR);
    }

    pContext->cmac_options.word.value = 0U;

    // Disable initialize/finalize for cbc-mac compitability.  
    pContext->cmac_options.bits.initialize = MCUXCLCSS_CMAC_INITIALIZE_DISABLE;
    pContext->cmac_options.bits.finalize = MCUXCLCSS_CMAC_FINALIZE_DISABLE;

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
        // Error: no key loaded
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Init, MCUXCLMAC_ERRORCODE_ERROR);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClMac_Engine_CBCMAC_Init, MCUXCLMAC_ERRORCODE_OK, MCUXCLMAC_ERRORCODE_FAULT_ATTACK);
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMac_Engine_CBCMAC_Update)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_CBCMAC_Update(mcuxClMac_Context_t *pContext, 
                                                                            const uint8_t *const pIn,
                                                                            uint32_t inLength,
                                                                            uint8_t *const pOut UNUSED_PARAM,
                                                                            uint32_t *const pOutLength UNUSED_PARAM)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMac_Engine_CBCMAC_Update);

    size_t pInNrProcessedBytes = 0;

    // Check if there are remaining bytes in the context from previous calls to this function
    // pContext->nrOfUnprocessedBytes can be at most MCUX_CL_AES_BLOCK_SIZE - 1
    // The case where inLength + pContext->nrOfUnprocessedBytes is less than a block size is handeled later
    uint32_t unprocessedBytesToBlocksize = ((0u < pContext->nrOfUnprocessedBytes) && (MCUX_CL_AES_BLOCK_SIZE <= (inLength + pContext->nrOfUnprocessedBytes)));
    if ( unprocessedBytesToBlocksize != 0u )
    {
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy));
       
        // Copy as many bytes from pIn to pContext->unprocessed in order to create one full block
        MCUX_CSSL_FP_FUNCTION_CALL(copyResult, mcuxClMemory_copy(((uint8_t*)pContext->unprocessed + pContext->nrOfUnprocessedBytes), pIn, 
                        MCUX_CL_AES_BLOCK_SIZE - pContext->nrOfUnprocessedBytes, 
                        MCUX_CL_AES_BLOCK_SIZE - pContext->nrOfUnprocessedBytes));
        if (0u != copyResult) 
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Update, MCUXCLMAC_ERRORCODE_ERROR);
        }
        

        // Process this block 
        MCUX_CSSL_FP_FUNCTION_CALL(cmacResult, mcuxClCss_Cmac_Async(
                                pContext->cmac_options,
                                (mcuxClCss_KeyIndex_t) mcuxClKey_getLoadedKeySlot(pContext->key),
                                (uint8_t const *) mcuxClKey_getKeyData(pContext->key),
                                (size_t) mcuxClKey_getSize(pContext->key),
                                (uint8_t*) pContext->unprocessed,
                                MCUX_CL_AES_BLOCK_SIZE,
                                (uint8_t*) pContext->state));

        if (MCUXCLCSS_STATUS_OK_WAIT != cmacResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Update, MCUXCLMAC_ERRORCODE_ERROR);
        }

        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));
        MCUX_CSSL_FP_FUNCTION_CALL(waitResult, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

        if (MCUXCLCSS_STATUS_OK != waitResult) 
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Update, MCUXCLMAC_ERRORCODE_ERROR);
        }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK

        MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult, mcuxClCss_CompareDmaFinalOutputAddress((uint8_t*)pContext->state, MCUXCLCSS_CMAC_OUT_SIZE));

        if (MCUXCLCSS_STATUS_OK != addressComparisonResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Update, MCUXCLMAC_ERRORCODE_ERROR);
        }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

        pInNrProcessedBytes = MCUX_CL_AES_BLOCK_SIZE - pContext->nrOfUnprocessedBytes;

        pContext->nrOfUnprocessedBytes = 0;

    }

    // Check if there are full blocks to process
    uint32_t temp_FullBlocks = (MCUX_CL_AES_BLOCK_SIZE <= (inLength - pInNrProcessedBytes));
    if(temp_FullBlocks !=0 )
    {
        size_t noOfFullBlocks = (inLength - pInNrProcessedBytes) / MCUX_CL_AES_BLOCK_SIZE;

        MCUX_CSSL_FP_FUNCTION_CALL(cmacResult, mcuxClCss_Cmac_Async(
                                pContext->cmac_options,
                                (mcuxClCss_KeyIndex_t) mcuxClKey_getLoadedKeySlot(pContext->key),
                                (uint8_t const *) mcuxClKey_getKeyData(pContext->key),
                                (size_t) mcuxClKey_getSize(pContext->key),
                                pIn + pInNrProcessedBytes,
                                noOfFullBlocks * MCUX_CL_AES_BLOCK_SIZE,
                                (uint8_t*) pContext->state));

        if (MCUXCLCSS_STATUS_OK_WAIT != cmacResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Update, MCUXCLMAC_ERRORCODE_ERROR);
        }

        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));
        MCUX_CSSL_FP_FUNCTION_CALL(waitResult, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

        if (MCUXCLCSS_STATUS_OK != waitResult) 
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Update, MCUXCLMAC_ERRORCODE_ERROR);
        }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
        MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult, mcuxClCss_CompareDmaFinalOutputAddress((uint8_t*)pContext->state, MCUX_CL_AES_BLOCK_SIZE));

        if (MCUXCLCSS_STATUS_OK != addressComparisonResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Update, MCUXCLMAC_ERRORCODE_ERROR);
        }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

        pInNrProcessedBytes += (noOfFullBlocks * MCUX_CL_AES_BLOCK_SIZE);
    }

    // Check if there are remaining bytes and copy them to the context
    if(pInNrProcessedBytes < inLength)
    {
        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy));
        MCUX_CSSL_FP_FUNCTION_CALL(copyResult, mcuxClMemory_copy(((uint8_t*)pContext->unprocessed + pContext->nrOfUnprocessedBytes), (pIn + pInNrProcessedBytes), 
                    (inLength - pInNrProcessedBytes), 
                    (inLength - pInNrProcessedBytes)));

        if (0u != copyResult) 
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Update, MCUXCLMAC_ERRORCODE_ERROR);
        }

        // Update number of unprocessed bytes
        pContext->nrOfUnprocessedBytes += (inLength - pInNrProcessedBytes);
    } 

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Update, MCUXCLMAC_ERRORCODE_OK,
                        MCUX_CSSL_FP_CONDITIONAL(unprocessedBytesToBlocksize,
                            MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN,
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async)),
                        MCUX_CSSL_FP_CONDITIONAL(temp_FullBlocks,
                            MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN,
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async)));

}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMac_Engine_CBCMAC_Finalize)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_CBCMAC_Finalize(mcuxClMac_Context_t *pContext,
                                                                              const uint8_t *const pIn,
                                                                              uint32_t inLength,
                                                                              uint8_t *const pOut,
                                                                              uint32_t *const pOutLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMac_Engine_CBCMAC_Finalize);

    // Check if additional block needs to be processed
    uint32_t paddingOutLength = 0u;

    // Call padding function 
    MCUX_CSSL_FP_FUNCTION_CALL(paddingResult, pContext->mode->pPaddingFunction(
    /* uint32_t blockLength */          MCUXCLCSS_CIPHER_BLOCK_SIZE_AES,
    /* const uint8_t *const pIn */      (uint8_t*)pContext->unprocessed,
    /* uint32_t lastBlockLength */      pContext->nrOfUnprocessedBytes,
    /* uint32_t totalInputLength */     pContext->nrOfUnprocessedBytes,
    /* uint8_t *const pOut */           (uint8_t*)pContext->unprocessed,
    /* uint32_t *const pOutLength */    &paddingOutLength));

    // padding functions are flow-protected: Check the protection token and the return value
    if (MCUXCLPADDING_STATUS_OK != paddingResult)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Finalize, MCUXCLMAC_ERRORCODE_ERROR);
    }

    if(paddingOutLength != 0u)
    {
        // Call css cmac on padded block
        MCUX_CSSL_FP_FUNCTION_CALL(cmacResult, mcuxClCss_Cmac_Async(
                                pContext->cmac_options,
                                (mcuxClCss_KeyIndex_t) mcuxClKey_getLoadedKeySlot(pContext->key),
                                (uint8_t const *) mcuxClKey_getKeyData(pContext->key),
                                (size_t) mcuxClKey_getSize(pContext->key),
                                (uint8_t*)pContext->unprocessed,
                                MCUX_CL_AES_BLOCK_SIZE,
                                (uint8_t*)pContext->state));

        // mcuxClCss_Cmac_Async is a flow-protected function: Check the protection token and the return value
        if (MCUXCLCSS_STATUS_OK_WAIT != cmacResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Finalize, MCUXCLMAC_ERRORCODE_ERROR);
        }

        MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));

        MCUX_CSSL_FP_FUNCTION_CALL(waitResult, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

        if (MCUXCLCSS_STATUS_OK != waitResult) 
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Finalize, MCUXCLMAC_ERRORCODE_ERROR);
        }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK

        MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult, mcuxClCss_CompareDmaFinalOutputAddress((uint8_t*)pContext->state, MCUXCLCSS_CMAC_OUT_SIZE));

        if (MCUXCLCSS_STATUS_OK != addressComparisonResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Update, MCUXCLMAC_ERRORCODE_ERROR);
        }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

    }

    MCUX_CSSL_FP_EXPECT(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy));
    
    // Copy final result from the context to the output
    MCUX_CSSL_FP_FUNCTION_CALL(copyResult, mcuxClMemory_copy(pOut, (uint8_t*)pContext->state, MCUX_CL_AES_BLOCK_SIZE, MCUX_CL_AES_BLOCK_SIZE));
    if(0u != copyResult) 
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Finalize, MCUXCLMAC_ERRORCODE_ERROR);
    }
    
    if((0u != inLength) || (paddingOutLength != 0u))
    {
        *pOutLength = MCUXCLCSS_CMAC_OUT_SIZE;
    }
    
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_CBCMAC_Finalize, MCUXCLMAC_ERRORCODE_OK,
                        pContext->mode->protectionTokenPaddingFunction,
                        MCUX_CSSL_FP_CONDITIONAL((paddingOutLength != 0u), 
                            MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN,
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async)));
}

//#pragma coverity compliance block deviate "MISRA C-2012 Rule 5.1" "MISRA Ex. 20 - Rule 5.1 - Names with similar 31-character prefix are allowed"
const mcuxClMac_ModeDescriptor_t  mcuxClMac_ModeDescriptor_CBCMAC_NoPadding = {
//#pragma coverity compliance end_block "MISRA C-2012 Rule 5.1"
    .engineInit = mcuxClMac_Engine_CBCMAC_Init,
    .engineUpdate =  mcuxClMac_Engine_CBCMAC_Update,
    .engineFinalize =  mcuxClMac_Engine_CBCMAC_Finalize,
    .engineOneshot = mcuxClMac_Engine_CBCMAC_Oneshot,
    .pPaddingFunction = mcuxClPadding_addPadding_None,
    .protectionTokenInit =  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_CBCMAC_Init),
    .protectionTokenUpdate =  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_CBCMAC_Update),
    .protectionTokenFinalize =  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_CBCMAC_Finalize),
    .protectionTokenOneshot = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_CBCMAC_Oneshot),
    .protectionTokenPaddingFunction = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_None),
    .macByteSize = MCUXCLCSS_CMAC_OUT_SIZE,
};

//#pragma coverity compliance block deviate "MISRA C-2012 Rule 5.1" "MISRA Ex. 20 - Rule 5.1 - Names with similar 31-character prefix are allowed"
const mcuxClMac_ModeDescriptor_t  mcuxClMac_ModeDescriptor_CBCMAC_PaddingISO9797_1_Method1 = {
//#pragma coverity compliance end_block "MISRA C-2012 Rule 5.1"
    .engineInit = mcuxClMac_Engine_CBCMAC_Init,
    .engineUpdate =  mcuxClMac_Engine_CBCMAC_Update,
    .engineFinalize =  mcuxClMac_Engine_CBCMAC_Finalize,
    .engineOneshot = mcuxClMac_Engine_CBCMAC_Oneshot,
    .pPaddingFunction = mcuxClPadding_addPadding_ISO9797_1_Method1,
    .protectionTokenInit =  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_CBCMAC_Init),
    .protectionTokenUpdate =  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_CBCMAC_Update),
    .protectionTokenFinalize =  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_CBCMAC_Finalize),
    .protectionTokenOneshot = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_CBCMAC_Oneshot),
    .protectionTokenPaddingFunction = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_ISO9797_1_Method1),
    .macByteSize = MCUXCLCSS_CMAC_OUT_SIZE,
};

//#pragma coverity compliance block deviate "MISRA C-2012 Rule 5.1" "MISRA Ex. 20 - Rule 5.1 - Names with similar 31-character prefix are allowed"
const mcuxClMac_ModeDescriptor_t  mcuxClMac_ModeDescriptor_CBCMAC_PaddingISO9797_1_Method2 = {
//#pragma coverity compliance end_block "MISRA C-2012 Rule 5.1"
    .engineInit = mcuxClMac_Engine_CBCMAC_Init,
    .engineUpdate =  mcuxClMac_Engine_CBCMAC_Update,
    .engineFinalize =  mcuxClMac_Engine_CBCMAC_Finalize,
    .engineOneshot = mcuxClMac_Engine_CBCMAC_Oneshot,
    .pPaddingFunction = mcuxClPadding_addPadding_ISO9797_1_Method2,
    .protectionTokenInit =  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_CBCMAC_Init),
    .protectionTokenUpdate =  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_CBCMAC_Update),
    .protectionTokenFinalize =  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_CBCMAC_Finalize),
    .protectionTokenOneshot = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_CBCMAC_Oneshot),
    .protectionTokenPaddingFunction = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_ISO9797_1_Method2),
    .macByteSize = MCUXCLCSS_CMAC_OUT_SIZE,
};

