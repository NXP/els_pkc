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

#include <mcuxClHash.h>
#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClHash_Core_css_sha2.h>
#include <mcuxClMemory.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCss.h>

/**********************************************************
 * Helper functions
 **********************************************************/

/* Writes the correct RTF flags to the hashOptions struct, based on the rtf parameter */
static inline mcuxClHash_Status_t mcuxClHash_css_selectRtfFlags(mcuxClSession_Rtf_t rtf,
                                                              mcuxClCss_HashOption_t *hashOptions)
{
    /* Set RTF processing options */
    if(MCUXCLSESSION_RTF_UPDATE_TRUE == rtf)
    {
        hashOptions->bits.rtfupd = MCUXCLCSS_HASH_RTF_UPDATE_ENABLE;
    }
    else if(MCUXCLSESSION_RTF_UPDATE_FALSE == rtf)
    {
        hashOptions->bits.rtfupd = MCUXCLCSS_HASH_RTF_UPDATE_DISABLE;
    }
    else
    {
        return MCUXCLHASH_FAILURE;
    }
    return MCUXCLHASH_STATUS_OK;
}

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHash_css_dmaProtectionAddressReadback)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHash_css_dmaProtectionAddressReadback(uint8_t * startAddress,
                                                                                             size_t expectedLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHash_css_dmaProtectionAddressReadback,
                               MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_CompareDmaFinalOutputAddress));

    MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClCss_CompareDmaFinalOutputAddress(startAddress, expectedLength));

    if (MCUXCLCSS_STATUS_OK != result)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_dmaProtectionAddressReadback, MCUXCLHASH_STATUS_FAULT_ATTACK);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_dmaProtectionAddressReadback, MCUXCLHASH_STATUS_OK);
}
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */


/**********************************************************
 * *INTERNAL* layer functions
 **********************************************************/

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHash_css_oneShotSkeleton_sha2)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHash_css_oneShotSkeleton_sha2 (
                                    mcuxClSession_Handle_t session,
                                    mcuxClHash_Algo_t algorithm,
                                    mcuxCl_InputBuffer_t pIn,
                                    uint32_t inSize,
                                    mcuxCl_Buffer_t pOut,
                                    uint32_t *const pOutSize)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHash_css_oneShotSkeleton_sha2);

    /**************************************************************************************
     * Step 1: Set CSS options for initialization, continuation from external state, or from
     * internal state
     **************************************************************************************/

    /* Start setting initial options for CSS hash */
    mcuxClCss_HashOption_t hash_options = algorithm->hashOptions;
    hash_options.bits.hashoe = MCUXCLCSS_HASH_OUTPUT_DISABLE;
    hash_options.bits.hashini = MCUXCLCSS_HASH_INIT_ENABLE;
    hash_options.bits.hashld  = MCUXCLCSS_HASH_LOAD_DISABLE;

    /* Set RTF processing options */
    if(MCUXCLHASH_STATUS_OK != mcuxClHash_css_selectRtfFlags(session->rtf, &hash_options))
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_oneShotSkeleton_sha2, MCUXCLHASH_FAILURE);
    }

    /**************************************************************************************
     * Step 2: Process full blocks of input data
     **************************************************************************************/

    /* All blocks can be processed in bulk directly from in */
    size_t const sizeOfFullBlocks = (inSize / algorithm->blockSize) * algorithm->blockSize;
    if (0u < sizeOfFullBlocks)
    {
        MCUX_CSSL_FP_FUNCTION_CALL(result, algorithm->css_core(hash_options.word.value,
                                                       pIn,
                                                       sizeOfFullBlocks,
                                                       NULL));

        if (MCUXCLHASH_STATUS_OK != result)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_oneShotSkeleton_sha2, result);
        }

        hash_options.bits.hashini = MCUXCLCSS_HASH_INIT_DISABLE;
    }

    /**************************************************************************************
     * Step 3: Padd the input data and process last block
     **************************************************************************************/

    /* Buffer in CPU WA to store the last block of data in the finalization phase, if enough space available */
    if((session->cpuWa.used + (algorithm->blockSize / sizeof(uint32_t))) > session->cpuWa.size)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_oneShotSkeleton_sha2, MCUXCLHASH_FAILURE);
    }

    uint8_t *shablock = (uint8_t*) &(session->cpuWa.buffer[session->cpuWa.used]);
    size_t posdst = inSize - sizeOfFullBlocks;
    size_t buflen = algorithm->blockSize;

    /* Copy the data to the buffer in the workspace. */
    MCUX_CSSL_FP_FUNCTION_CALL(memcopy_result1, mcuxClMemory_copy(shablock, &pIn[sizeOfFullBlocks], posdst, buflen));
    if(0u != memcopy_result1)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_oneShotSkeleton_sha2, MCUXCLHASH_FAILURE);
    }

    buflen -= posdst;

    /* add first byte of the padding: (remaining) < (block length) so there is space in the buffer */
    shablock[posdst] = 0x80u;
    posdst += 1u;
    buflen -= 1u;

    /* Process partial padded block if needed */
    if ( (algorithm->blockSize - algorithm->counterSize) < posdst ) // need room for 64 bit counter and one additional byte
    {
        MCUX_CSSL_FP_FUNCTION_CALL(memset_result1, mcuxClMemory_set(&shablock[posdst], 0x00, buflen, buflen));
        if(0u != memset_result1)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_oneShotSkeleton_sha2, MCUXCLHASH_FAILURE);
        }

        /* It is currently necessary to set buflen to algorithm->blockSize to distinguish whether this if-branch was taken
         * (for the conditional expectations in the exit statement!). Otherwise we could set it to posdst here and save
         * some performance overhead */
        buflen = algorithm->blockSize;
        posdst = 0u;

        MCUX_CSSL_FP_FUNCTION_CALL(result, algorithm->css_core(hash_options.word.value,
                                                              shablock,
                                                              algorithm->blockSize,
                                                              NULL));

        if (MCUXCLHASH_STATUS_OK != result)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_oneShotSkeleton_sha2, result);
        }

        hash_options.bits.hashini = MCUXCLCSS_HASH_INIT_DISABLE;
    }

    /* Perform padding by adding data counter */
    MCUX_CSSL_FP_FUNCTION_CALL(memset_result2, mcuxClMemory_set(&shablock[posdst], 0x00, buflen, buflen));

    if(0u != memset_result2)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_oneShotSkeleton_sha2, MCUXCLHASH_FAILURE);
    }
    posdst = algorithm->blockSize;
    shablock[--posdst] = (uint8_t)(inSize <<  3u);
    shablock[--posdst] = (uint8_t)(inSize >>  5u);
    shablock[--posdst] = (uint8_t)(inSize >> 13u);
    shablock[--posdst] = (uint8_t)(inSize >> 21u);
    shablock[posdst-1u] = (uint8_t)(inSize >> 29u);

    /* Set output options */
    hash_options.bits.hashoe  = MCUXCLCSS_HASH_OUTPUT_ENABLE;
    hash_options.bits.rtfoe = hash_options.bits.rtfupd;

    /* Process last block */
    MCUX_CSSL_FP_FUNCTION_CALL(result, algorithm->css_core(hash_options.word.value,
                                                 shablock,
                                                 algorithm->blockSize,
                                                 shablock /* shablock is large enough to hold internal state of hash algorithm + RTF */));

    if (MCUXCLHASH_STATUS_OK != result)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_oneShotSkeleton_sha2, result);
    }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
    uint32_t rtfSize = 0;
    rtfSize = (MCUXCLSESSION_RTF_UPDATE_TRUE == session->rtf) ? algorithm->rtfSize : 0u;
    if(NULL != algorithm->dmaProtection)
    {
        MCUX_CSSL_FP_FUNCTION_CALL(resultDma, algorithm->dmaProtection(shablock,
                                                                      algorithm->stateSize + rtfSize));

        if (MCUXCLHASH_STATUS_OK != resultDma)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_oneShotSkeleton_sha2, resultDma);
        }
    }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

    /**************************************************************************************
     * Step 4: Copy result to output buffers
     **************************************************************************************/

    /* Copy RTF to corresponding buffer */
    if((MCUXCLSESSION_RTF_UPDATE_TRUE == session->rtf) && (NULL != session->pRtf))
    {
        MCUX_CSSL_FP_FUNCTION_CALL(memcopy_result2, mcuxClMemory_copy(session->pRtf, &shablock[algorithm->hashSize], algorithm->rtfSize, algorithm->rtfSize));

        if(0u != memcopy_result2)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_oneShotSkeleton_sha2, MCUXCLHASH_FAILURE);
        }
    }

    /* Copy hash digest to output buffer */
    MCUX_CSSL_FP_FUNCTION_CALL(memcopy_result3, mcuxClMemory_copy(pOut, shablock, algorithm->hashSize, algorithm->hashSize));
    if(0u != memcopy_result3)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_oneShotSkeleton_sha2, MCUXCLHASH_FAILURE);
    }
    *pOutSize += algorithm->hashSize;

    /* Set expectations and exit */
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_oneShotSkeleton_sha2, MCUXCLHASH_STATUS_OK,
                            MCUX_CSSL_FP_CONDITIONAL((0u != sizeOfFullBlocks), algorithm->protection_token_css_core),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                            MCUX_CSSL_FP_CONDITIONAL((buflen == algorithm->blockSize), MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set), algorithm->protection_token_css_core),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
                            (algorithm->protection_token_css_core),
                            #ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
                            (algorithm->protection_token_dma_protection),
                            #endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */
                            MCUX_CSSL_FP_CONDITIONAL((MCUXCLSESSION_RTF_UPDATE_TRUE == session->rtf),  MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy)),
                            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy));
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHash_css_process_sha2)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHash_css_process_sha2 (
                        mcuxClSession_Handle_t session,
                        mcuxClHash_Context_t context,
                        mcuxCl_InputBuffer_t pIn,
                        uint32_t inSize)
{

    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHash_css_process_sha2);

    /**************************************************************************************
     * Step 1: Initialization - Calculate sizes, set pointers, and set CSS options for
     * initialization, continuation from external state, or from internal state
     **************************************************************************************/

    /* Total length of data to be processed */
    size_t unprocessedTotalLength = context->data.unprocessedLength + inSize;

    const mcuxClHash_AlgorithmDescriptor_t * pAlgoDesc = context->algo;
    const size_t algoBlockSize = context->algo->blockSize;
    /* The amount of unprocessed data that fills complete blocks */
    size_t  unprocessedCompleteBlockLength = (unprocessedTotalLength / algoBlockSize) * (algoBlockSize);

    /* Need to store the initial values of these variables for correct calculation of flow protection values at the end of the function */
    MCUX_CSSL_FP_COUNTER_STMT(const size_t initialUnprocessedCompleteBlockLength = unprocessedCompleteBlockLength);
    MCUX_CSSL_FP_COUNTER_STMT(const size_t initialUnprocessedContextLength = context->data.unprocessedLength);

    /* Pointer to the buffer where the state is stored. Either it ends up in the work area, or in the state buffer of the context */
    uint8_t *partialdigest = context->buffer.state;

    /* Input pointer that changes throughout the function */
    const uint8_t *pInput = (const uint8_t *)pIn;
    if(NULL == pInput)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_process_sha2, MCUXCLHASH_STATUS_INVALID_PARAMS);
    }

    /* Start setting initial options for CSS hash */
    mcuxClCss_HashOption_t hash_options = pAlgoDesc->hashOptions;
    hash_options.bits.hashoe = MCUXCLCSS_HASH_OUTPUT_ENABLE;
    hash_options.bits.hashini = MCUXCLCSS_HASH_INIT_ENABLE;
    hash_options.bits.hashld  = MCUXCLCSS_HASH_LOAD_DISABLE;


    /**************************************************************************************
     * Step 2: Load state (partial digest), if data had been processed before
     **************************************************************************************/

    /* Set hash init/load flags depending on whether there is a valid state to load or not */
    int32_t processedLengthNotZero = mcuxClHash_processedLength_cmp(context->data.processedLength, 0, 0);
    if(0 != processedLengthNotZero)
    {
        /* There is already a valid state in the context -> load state from context */
        hash_options.bits.hashini = MCUXCLCSS_HASH_INIT_DISABLE;
        hash_options.bits.hashld  = MCUXCLCSS_HASH_LOAD_ENABLE;
    }

    /* Set RTF processing options */
    if(MCUXCLHASH_STATUS_OK != mcuxClHash_css_selectRtfFlags(session->rtf, &hash_options))
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_process_sha2, MCUXCLHASH_FAILURE);
    }

    /**************************************************************************************
     * Step 3: Process full blocks
     **************************************************************************************/

    /* The first block can either be completely in `pInput`, or partially in the context buffer. */
    if((0u != unprocessedCompleteBlockLength) && (0u != context->data.unprocessedLength))
    {
        /* There is some data in the context buffer. Append enough data from `pInput` to complete a block. */
        MCUX_CSSL_FP_FUNCTION_CALL(memcopy_result1, mcuxClMemory_copy(context->buffer.unprocessed + context->data.unprocessedLength,
                                                                    pInput,
                                                                    algoBlockSize - context->data.unprocessedLength,
                                                                    sizeof(context->buffer.unprocessed) - context->data.unprocessedLength));

        if(0u != memcopy_result1)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_process_sha2, MCUXCLHASH_FAILURE);
        }

        MCUX_CSSL_FP_FUNCTION_CALL(result, pAlgoDesc->css_core(hash_options.word.value,
                                                          context->buffer.unprocessed,
                                                          algoBlockSize,
                                                          partialdigest));

        if (MCUXCLHASH_STATUS_OK != result)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_process_sha2, result);
        }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
        if(NULL != pAlgoDesc->dmaProtection)
        {
            MCUX_CSSL_FP_FUNCTION_CALL(resultDma, pAlgoDesc->dmaProtection(partialdigest, pAlgoDesc->stateSize));

            if (MCUXCLHASH_STATUS_OK != resultDma)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_process_sha2, resultDma);
            }
        }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

        hash_options.bits.hashini = MCUXCLCSS_HASH_INIT_DISABLE;
        hash_options.bits.hashld = MCUXCLCSS_HASH_LOAD_DISABLE;

        pInput += algoBlockSize - context->data.unprocessedLength;

        mcuxClHash_processedLength_add(context->data.processedLength, algoBlockSize);
        context->data.unprocessedLength = 0u;

        unprocessedCompleteBlockLength -= algoBlockSize;
        unprocessedTotalLength -= algoBlockSize;
    }

    /* At this point, there is no more data in the context buffer, so remaining blocks can be processed in bulk directly from pIn */
    if (0u != unprocessedCompleteBlockLength)
    {
        MCUX_CSSL_FP_FUNCTION_CALL(result, pAlgoDesc->css_core(hash_options.word.value,
                                                          pInput,
                                                          unprocessedCompleteBlockLength,
                                                          partialdigest));

        if (MCUXCLHASH_STATUS_OK != result)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_process_sha2, result);
        }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
        if(NULL != pAlgoDesc->dmaProtection)
        {
            MCUX_CSSL_FP_FUNCTION_CALL(resultDma, pAlgoDesc->dmaProtection(partialdigest, pAlgoDesc->stateSize));

            if (MCUXCLHASH_STATUS_OK != resultDma)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_process_sha2, resultDma);
            }
        }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

        hash_options.bits.hashini = MCUXCLCSS_HASH_INIT_DISABLE;
        hash_options.bits.hashld = MCUXCLCSS_HASH_LOAD_DISABLE;

        pInput += unprocessedCompleteBlockLength;

        mcuxClHash_processedLength_add(context->data.processedLength, unprocessedCompleteBlockLength);

        unprocessedTotalLength -= unprocessedCompleteBlockLength;
    }

    /**************************************************************************************
     * Step 4: Process incomplete blocks
     **************************************************************************************/

    if(0u < unprocessedTotalLength)
    {
        /* Append data from `pInput` to accumulation buffer. */
        MCUX_CSSL_FP_FUNCTION_CALL(memcopy_result1, mcuxClMemory_copy(context->buffer.unprocessed + context->data.unprocessedLength,
                                                                    pInput,
                                                                    (unprocessedTotalLength - context->data.unprocessedLength),
                                                                    sizeof(context->buffer.unprocessed) - context->data.unprocessedLength));

        if (0u != memcopy_result1)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_process_sha2, MCUXCLHASH_FAILURE);
        }

        context->data.unprocessedLength = unprocessedTotalLength;

    }

    /**************************************************************************************
     * Step 5: Exit
     **************************************************************************************/

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_process_sha2, MCUXCLHASH_STATUS_OK,
                           MCUX_CSSL_FP_CONDITIONAL((0u != initialUnprocessedCompleteBlockLength) && (0u != initialUnprocessedContextLength),
                                                   pAlgoDesc->protection_token_css_core,
                                                   #ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
                                                   pAlgoDesc->protection_token_dma_protection,
                                                   #endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */
                                                   MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy)),
                           MCUX_CSSL_FP_CONDITIONAL((((0u != initialUnprocessedCompleteBlockLength) && (0u == initialUnprocessedContextLength)) || ((algoBlockSize < initialUnprocessedCompleteBlockLength) && (0u != initialUnprocessedContextLength))),
                                                   #ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
                                                   pAlgoDesc->protection_token_dma_protection,
                                                   #endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */
                                                   pAlgoDesc->protection_token_css_core),
                           MCUX_CSSL_FP_CONDITIONAL((0u < unprocessedTotalLength),
                                                   (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy))));
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHash_css_finish_sha2)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHash_css_finish_sha2 (
                        mcuxClSession_Handle_t session,
                        mcuxClHash_Context_t context,
                        mcuxCl_Buffer_t pOut,
                        uint32_t *const pOutSize)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHash_css_finish_sha2);

    /**************************************************************************************
     * Step 1: Initialization - Calculate sizes, set pointers, and set CSS options for
     * initialization, continuation from external state, or from internal state
     **************************************************************************************/

    if(NULL == pOut)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_finish_sha2, MCUXCLHASH_STATUS_INVALID_PARAMS);
    }

    /* Pointer to the buffer where the state is stored. Either it ends up in the work area, or in the state buffer of the context */
    uint8_t *partialdigest = context->buffer.state;

    /* Start setting initial options for CSS hash */
    const mcuxClHash_AlgorithmDescriptor_t *pAlgoDesc = context->algo;
    mcuxClCss_HashOption_t hash_options = pAlgoDesc->hashOptions;
    hash_options.bits.hashoe = MCUXCLCSS_HASH_OUTPUT_ENABLE;
    hash_options.bits.hashini = MCUXCLCSS_HASH_INIT_ENABLE;
    hash_options.bits.hashld  = MCUXCLCSS_HASH_LOAD_DISABLE;

    /* Set RTF processing options */
    if(MCUXCLHASH_STATUS_OK != mcuxClHash_css_selectRtfFlags(session->rtf, &hash_options))
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_finish_sha2, MCUXCLHASH_FAILURE);
    }

    /**************************************************************************************
     * Step 2: Load state (partial digest), if data had been processed before
     **************************************************************************************/

    /* Set hash init/load flags depending on whether there is a valid state to load or not */
    int32_t processedLengthNotZero = mcuxClHash_processedLength_cmp(context->data.processedLength, 0, 0);
    if(0 != processedLengthNotZero)
    {
        /* There is already a valid state in the context -> load state from context */
        hash_options.bits.hashini = MCUXCLCSS_HASH_INIT_DISABLE;
        hash_options.bits.hashld  = MCUXCLCSS_HASH_LOAD_ENABLE;
    }

    /**************************************************************************************
     * Step 3: Padd data and process last block
     **************************************************************************************/

    /* Pointer to the buffer where the last block of data is stored in the finalization phase */
    uint8_t *shablock = context->buffer.unprocessed;

    /* Buffer in CPU WA to store the digest and RTF output in the finalization phase, if enough space available */
    if((session->cpuWa.used + ((pAlgoDesc->stateSize + pAlgoDesc->rtfSize) / sizeof(uint32_t))) > session->cpuWa.size)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_finish_sha2, MCUXCLHASH_FAILURE);
    }

    uint8_t *pOutput = (uint8_t*) &(session->cpuWa.buffer[session->cpuWa.used]);
    /* No need to update cpuWa.used since no sub-function is called in between */

    size_t posdst, buflen;
    buflen = pAlgoDesc->blockSize - context->data.unprocessedLength;
    posdst  = context->data.unprocessedLength;

    // add first byte of the padding: (remaining) < (block length) so there is space in the buffer
    shablock[posdst] = 0x80u;
    posdst += 1u;
    buflen -= 1u;

    /* Process partial padded block if needed */
    if (pAlgoDesc->blockSize - pAlgoDesc->counterSize - 1u < context->data.unprocessedLength) // need room for 64 bit counter and one additional byte
    {
        MCUX_CSSL_FP_FUNCTION_CALL(memset_result1, mcuxClMemory_set(shablock + posdst, 0x00u, buflen, buflen));
        if(0u != memset_result1)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_finish_sha2, MCUXCLHASH_FAILURE);
        }
        buflen = pAlgoDesc->blockSize;
        posdst = 0u;

        MCUX_CSSL_FP_FUNCTION_CALL(result, pAlgoDesc->css_core(hash_options.word.value,
                                                         shablock,
                                                         pAlgoDesc->blockSize,
                                                         partialdigest));

        if (MCUXCLHASH_STATUS_OK != result)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_finish_sha2, result);
        }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
        if(NULL != pAlgoDesc->dmaProtection)
        {
            MCUX_CSSL_FP_FUNCTION_CALL(resultDma, pAlgoDesc->dmaProtection(partialdigest, pAlgoDesc->stateSize));

            if (MCUXCLHASH_STATUS_OK != resultDma)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_finish_sha2, resultDma);
            }
        }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

        hash_options.bits.hashini = MCUXCLCSS_HASH_INIT_DISABLE;
        hash_options.bits.hashld = MCUXCLCSS_HASH_LOAD_ENABLE;
    }

    /* Perform padding by adding data counter */
    MCUX_CSSL_FP_FUNCTION_CALL(memset_result2, mcuxClMemory_set(shablock + posdst, 0x00u, buflen, buflen));

    if(0u != memset_result2)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_finish_sha2, MCUXCLHASH_FAILURE);
    }

    posdst = pAlgoDesc->blockSize;
    mcuxClHash_processedLength_add(context->data.processedLength, context->data.unprocessedLength);
    shablock[--posdst] = (uint8_t)(context->data.processedLength[0] <<  3u);
    shablock[--posdst] = (uint8_t)(context->data.processedLength[0] >>  5u);
    shablock[--posdst] = (uint8_t)(context->data.processedLength[0] >> 13u);
    shablock[--posdst] = (uint8_t)(context->data.processedLength[0] >> 21u);
    shablock[--posdst] = (uint8_t)(context->data.processedLength[0] >> 29u);
    shablock[--posdst] = (uint8_t)(context->data.processedLength[0] >> 37u);
    shablock[--posdst] = (uint8_t)(context->data.processedLength[0] >> 45u);
    shablock[--posdst] = (uint8_t)(context->data.processedLength[0] >> 53u);
    if (context->algo->counterSize > 8u)
    {
        shablock[--posdst] = (uint8_t)(context->data.processedLength[0] >> 61u) |
            (uint8_t)(context->data.processedLength[1] << 5u);
        shablock[--posdst] = (uint8_t)(context->data.processedLength[1] >>  5u);
        shablock[--posdst] = (uint8_t)(context->data.processedLength[1] >> 13u);
        shablock[--posdst] = (uint8_t)(context->data.processedLength[1] >> 21u);
        shablock[--posdst] = (uint8_t)(context->data.processedLength[1] >> 29u);
        shablock[--posdst] = (uint8_t)(context->data.processedLength[1] >> 37u);
        shablock[--posdst] = (uint8_t)(context->data.processedLength[1] >> 45u);
        shablock[--posdst] = (uint8_t)(context->data.processedLength[1] >> 53u);
    }
    hash_options.bits.hashoe  = MCUXCLCSS_HASH_OUTPUT_ENABLE;

    MCUX_CSSL_FP_FUNCTION_CALL(memcopy_result_partial, mcuxClMemory_copy(pOutput, partialdigest, pAlgoDesc->stateSize, pAlgoDesc->stateSize));
    if(0u != memcopy_result_partial)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_finish_sha2, MCUXCLHASH_FAILURE);
    }

    /* Set RTF processing options */
    hash_options.bits.rtfoe = hash_options.bits.rtfupd;

    /* Process last block */
    MCUX_CSSL_FP_FUNCTION_CALL(result, pAlgoDesc->css_core(hash_options.word.value,
                                                      shablock,
                                                      pAlgoDesc->blockSize,
                                                      pOutput));

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
    uint32_t rtfSize = 0;
    rtfSize = (MCUXCLSESSION_RTF_UPDATE_TRUE == session->rtf) ? pAlgoDesc->rtfSize : 0u;
    if(NULL != pAlgoDesc->dmaProtection)
    {
        MCUX_CSSL_FP_FUNCTION_CALL(resultDma, pAlgoDesc->dmaProtection(pOutput,
                                                                      pAlgoDesc->stateSize + rtfSize));

        if (MCUXCLHASH_STATUS_OK != resultDma)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_finish_sha2, resultDma);
        }
    }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

    if (MCUXCLHASH_STATUS_OK != result)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_finish_sha2, result);
    }

    /**************************************************************************************
     * Step 4: Copy result to output buffers and clear context
     **************************************************************************************/

    /* Copy RTF to corresponding buffer */
    if((MCUXCLSESSION_RTF_UPDATE_TRUE == session->rtf))
    {
        if (NULL == session->pRtf)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_finish_sha2, MCUXCLHASH_STATUS_INVALID_PARAMS);
        }
        else
        {
            MCUX_CSSL_FP_FUNCTION_CALL(memcopy_result2, mcuxClMemory_copy(session->pRtf, pOutput + pAlgoDesc->hashSize, pAlgoDesc->rtfSize, pAlgoDesc->rtfSize));

            if(0u != memcopy_result2)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_finish_sha2, MCUXCLHASH_FAILURE);
            }
        }
    }

    /* Copy hash digest to output buffer */
    MCUX_CSSL_FP_FUNCTION_CALL(memcopy_result3, mcuxClMemory_copy(pOut, pOutput, pAlgoDesc->hashSize, pAlgoDesc->hashSize));

    if(0u != memcopy_result3)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_finish_sha2, MCUXCLHASH_FAILURE);
    }
    *pOutSize += pAlgoDesc->hashSize;

    /* Backup unprocessedLength before context clearing */
    MCUX_CSSL_FP_COUNTER_STMT(const size_t unprocessedLength = context->data.unprocessedLength);

    /* Clear context */
    MCUX_CSSL_FP_FUNCTION_CALL(memcopy_clear, mcuxClMemory_clear((uint8_t *)context,
                                                               sizeof(mcuxClHash_ContextDescriptor_t),
                                                               sizeof(mcuxClHash_ContextDescriptor_t)));

    if(0u != memcopy_clear)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_finish_sha2, MCUXCLHASH_FAILURE);
    }

    /**************************************************************************************
     * Step 5: Exit
     **************************************************************************************/

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHash_css_finish_sha2, MCUXCLHASH_STATUS_OK,
                              MCUX_CSSL_FP_CONDITIONAL(pAlgoDesc->blockSize - pAlgoDesc->counterSize - 1u < unprocessedLength,
                                                      #ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
                                                      pAlgoDesc->protection_token_dma_protection,
                                                      #endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */
                                                      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
                                                      pAlgoDesc->protection_token_css_core),
                              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
                              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                              pAlgoDesc->protection_token_css_core,
                              #ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
                              pAlgoDesc->protection_token_dma_protection,
                              #endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */
                              MCUX_CSSL_FP_CONDITIONAL((MCUXCLSESSION_RTF_UPDATE_TRUE == session->rtf),
                                                       MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy)),
                              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                              MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear));

}


/**********************************************************
 * Algorithm descriptor implementations
 **********************************************************/


//#pragma coverity compliance block deviate "MISRA C-2012 Rule 5.1" "MISRA Ex. 20 - Rule 5.1 - Names with similar 31-character prefix are allowed"
const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_Sha224 = {
//#pragma coverity compliance end_block "MISRA C-2012 Rule 5.1"
    .css_core                         = mcuxClHash_css_core_sha2,
    .protection_token_css_core        = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_core_sha2),
    .oneShotSkeleton                  = mcuxClHash_css_oneShotSkeleton_sha2,
    .protection_token_oneShotSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_oneShotSkeleton_sha2),
    .processSkeleton                  = mcuxClHash_css_process_sha2,
    .protection_token_processSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_process_sha2),
    .finishSkeleton                   = mcuxClHash_css_finish_sha2,
    .protection_token_finishSkeleton  = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_finish_sha2),
#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
    .dmaProtection                    = mcuxClHash_css_dmaProtectionAddressReadback,
    .protection_token_dma_protection  = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_dmaProtectionAddressReadback),
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */
    .blockSize                        = MCUXCLHASH_BLOCK_SIZE_SHA_224,
    .hashSize                         = MCUXCLHASH_OUTPUT_SIZE_SHA_224,
    .stateSize                        = MCUXCLHASH_STATE_SIZE_SHA_224,
    .counterSize                      = MCUXCLHASH_COUNTER_SIZE_SHA_224,
    .rtfSize                          = 0u,
    .hashOptions.word.value           = MCUXCLCSS_HASH_VALUE_MODE_SHA_224,
};


//#pragma coverity compliance block deviate "MISRA C-2012 Rule 5.1" "MISRA Ex. 20 - Rule 5.1 - Names with similar 31-character prefix are allowed"
const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_Sha256 = {
//#pragma coverity compliance end_block "MISRA C-2012 Rule 5.1"
    .css_core                         = mcuxClHash_css_core_sha2,
    .protection_token_css_core        = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_core_sha2),
    .oneShotSkeleton                  = mcuxClHash_css_oneShotSkeleton_sha2,
    .protection_token_oneShotSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_oneShotSkeleton_sha2),
    .processSkeleton                  = mcuxClHash_css_process_sha2,
    .protection_token_processSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_process_sha2),
    .finishSkeleton                   = mcuxClHash_css_finish_sha2,
    .protection_token_finishSkeleton  = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_finish_sha2),
#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
    .dmaProtection                    = mcuxClHash_css_dmaProtectionAddressReadback,
    .protection_token_dma_protection  = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_dmaProtectionAddressReadback),
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */
    .blockSize                        = MCUXCLHASH_BLOCK_SIZE_SHA_256,
    .hashSize                         = MCUXCLHASH_OUTPUT_SIZE_SHA_256,
    .stateSize                        = MCUXCLHASH_STATE_SIZE_SHA_256,
    .counterSize                      = MCUXCLHASH_COUNTER_SIZE_SHA_256,
    .rtfSize                          = MCUXCLCSS_HASH_RTF_OUTPUT_SIZE,
    .hashOptions.word.value           = MCUXCLCSS_HASH_VALUE_MODE_SHA_256,
};


//#pragma coverity compliance block deviate "MISRA C-2012 Rule 5.1" "MISRA Ex. 20 - Rule 5.1 - Names with similar 31-character prefix are allowed"
const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_Sha384 = {
//#pragma coverity compliance end_block "MISRA C-2012 Rule 5.1"
    .css_core                         = mcuxClHash_css_core_sha2,
    .protection_token_css_core        = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_core_sha2),
    .oneShotSkeleton                  = mcuxClHash_css_oneShotSkeleton_sha2,
    .protection_token_oneShotSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_oneShotSkeleton_sha2),
    .processSkeleton                  = mcuxClHash_css_process_sha2,
    .protection_token_processSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_process_sha2),
    .finishSkeleton                   = mcuxClHash_css_finish_sha2,
    .protection_token_finishSkeleton  = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_finish_sha2),
#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
    .dmaProtection                    = mcuxClHash_css_dmaProtectionAddressReadback,
    .protection_token_dma_protection  = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_dmaProtectionAddressReadback),
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */
    .blockSize                        = MCUXCLHASH_BLOCK_SIZE_SHA_384,
    .hashSize                         = MCUXCLHASH_OUTPUT_SIZE_SHA_384,
    .stateSize                        = MCUXCLHASH_STATE_SIZE_SHA_384,
    .counterSize                      = MCUXCLHASH_COUNTER_SIZE_SHA_384,
    .rtfSize                          = 0u,
    .hashOptions.word.value           = MCUXCLCSS_HASH_VALUE_MODE_SHA_384,
};


//#pragma coverity compliance block deviate "MISRA C-2012 Rule 5.1" "MISRA Ex. 20 - Rule 5.1 - Names with similar 31-character prefix are allowed"
const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_Sha512 = {
//#pragma coverity compliance end_block "MISRA C-2012 Rule 5.1"
    .css_core                         = mcuxClHash_css_core_sha2,
    .protection_token_css_core        = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_core_sha2),
    .oneShotSkeleton                  = mcuxClHash_css_oneShotSkeleton_sha2,
    .protection_token_oneShotSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_oneShotSkeleton_sha2),
    .processSkeleton                  = mcuxClHash_css_process_sha2,
    .protection_token_processSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_process_sha2),
    .finishSkeleton                   = mcuxClHash_css_finish_sha2,
    .protection_token_finishSkeleton  = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_finish_sha2),
#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
    .dmaProtection                    = mcuxClHash_css_dmaProtectionAddressReadback,
    .protection_token_dma_protection  = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_css_dmaProtectionAddressReadback),
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */
    .blockSize                        = MCUXCLHASH_BLOCK_SIZE_SHA_512,
    .hashSize                         = MCUXCLHASH_OUTPUT_SIZE_SHA_512,
    .stateSize                        = MCUXCLHASH_STATE_SIZE_SHA_512,
    .counterSize                      = MCUXCLHASH_COUNTER_SIZE_SHA_512,
    .rtfSize                          = 0u,
    .hashOptions.word.value           = MCUXCLCSS_HASH_VALUE_MODE_SHA_512,
};

