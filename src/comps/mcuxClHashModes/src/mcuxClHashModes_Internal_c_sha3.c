/*--------------------------------------------------------------------------*/
/* Copyright 2023-2026 NXP                                                  */
/*                                                                          */
/* SPDX-License-Identifier: BSD-3-Clause                                    */
/*                                                                          */
/* Redistribution and use in source and binary forms, with or without       */
/* modification, are permitted provided that the following conditions are   */
/* met:                                                                     */
/*                                                                          */
/* 1. Redistributions of source code must retain the above copyright        */
/*    notice, this list of conditions and the following disclaimer.         */
/*                                                                          */
/* 2. Redistributions in binary form must reproduce the above copyright     */
/*    notice, this list of conditions and the following disclaimer in the   */
/*    documentation and/or other materials provided with the distribution.  */
/*                                                                          */
/* 3. Neither the name of the copyright holder nor the names of its         */
/*    contributors may be used to endorse or promote products derived from  */
/*    this software without specific prior written permission.              */
/*                                                                          */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS  */
/* IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED    */
/* TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A          */
/* PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT       */
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,   */
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED */
/* TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR   */
/* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF   */
/* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS       */
/* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.             */
/*--------------------------------------------------------------------------*/

#include <mcuxClToolchain.h>
#include <mcuxCsslAnalysis.h>
#include <mcuxClHash.h>
#include <mcuxClHashModes.h>
#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClHashModes_Internal.h>
#include <internal/mcuxClHashModes_Core_c_sha3.h>
#include <mcuxClMemory.h>
#include <mcuxClSession.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClBuffer_Internal.h>

/**********************************************************
 * *INTERNAL* layer functions
 **********************************************************/
/**
 * @brief Shared one-shot core for SHA3 and SHAKE (software Keccak).
 *
 * Absorbs pIn, applies the given padding byte, and squeezes outSizeRequested
 * bytes to pOut. The padding byte selects the domain:
 *   0x06 -> SHA3, 0x1F -> SHAKE.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_C_oneShot_sha3_shake_core)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHashModes_C_oneShot_sha3_shake_core(
                                mcuxClSession_Handle_t session,
                                mcuxClHash_Algo_t algorithm,
                                mcuxCl_InputBuffer_t pIn,
                                uint32_t inSize,
                                uint32_t outSizeRequested,
                                mcuxCl_Buffer_t pOut,
                                uint32_t *const pOutSizeComputed,
                                uint8_t paddingByte)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_C_oneShot_sha3_shake_core);
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(algorithm->blockSize, 1u, 200u, MCUXCLHASH_STATUS_FAILURE)

    /**************************************************************************************/
    /*                Allocate working buffers and initialize state                       */
    /**************************************************************************************/
    uint32_t *pState = mcuxClSession_allocateWords_cpuWa(session,
                           MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLHASH_STATE_SIZE_SHA3));
    if (NULL == pState)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_oneShot_sha3_shake_core, MCUXCLHASH_STATUS_FAILURE);
    }

    uint8_t *pAccumulationBuffer = (uint8_t *) mcuxClSession_allocateWords_cpuWa(session,
                                       MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(algorithm->blockSize));
    if (NULL == pAccumulationBuffer)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_oneShot_sha3_shake_core, MCUXCLHASH_STATUS_FAILURE);
    }

    /* Initialize Keccak state to all-zero */
    MCUXCLMEMORY_FP_MEMORY_CLEAR(pState, MCUXCLHASH_STATE_SIZE_SHA3);

    /**************************************************************************************/
    /*                Absorb all complete input blocks                                    */
    /**************************************************************************************/
    uint32_t offset = 0u;
    uint32_t numOfFullBlocks = inSize / algorithm->blockSize;

    for (uint32_t copiedBlocks = 0u; copiedBlocks < numOfFullBlocks; copiedBlocks++)
    {
        /* Read one block into the accumulation buffer */
        MCUX_CSSL_FP_FUNCTION_CALL(bufferStatus1, mcuxClBuffer_read(pIn, offset, pAccumulationBuffer, algorithm->blockSize));
        if (MCUXCLBUFFER_STATUS_OK != bufferStatus1)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_oneShot_sha3_shake_core, bufferStatus1);
        }
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(offset, 0U, UINT32_MAX - algorithm->blockSize, MCUXCLHASH_STATUS_FAILURE)
        offset += algorithm->blockSize;

        /* Absorb: XOR block into state */
        /* TODO CLNS-10529 replace mcuxClHashModes_xor_buffers with unsecure XOR */
        mcuxClHashModes_xor_buffers((uint8_t *)pState, (uint8_t *)pState, pAccumulationBuffer, algorithm->blockSize);

        /* Keccak permutation */
        MCUX_CSSL_FP_FUNCTION_CALL(core_result, mcuxClHashModes_core_c_keccak(pState));
        if (MCUXCLHASH_STATUS_OK != core_result)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_oneShot_sha3_shake_core, MCUXCLHASH_STATUS_FAULT_ATTACK);
        }
    }
    uint32_t sizeCopiedBytes = numOfFullBlocks * algorithm->blockSize;

    /**************************************************************************************/
    /*                Build and absorb the final padded block                             */
    /**************************************************************************************/
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(inSize, sizeCopiedBytes, UINT32_MAX, MCUXCLHASH_STATUS_FAILURE)
    uint32_t sizeRemainingBytes = inSize - sizeCopiedBytes;

    /* Read any remaining input bytes */
    MCUX_CSSL_FP_FUNCTION_CALL(bufferStatus2, mcuxClBuffer_read(pIn, offset, pAccumulationBuffer, sizeRemainingBytes));
    if (MCUXCLBUFFER_STATUS_OK != bufferStatus2)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_oneShot_sha3_shake_core, bufferStatus2);
    }

    /* Append domain-separation / padding bytes */
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(sizeRemainingBytes, 0u, algorithm->blockSize - 1u, MCUXCLHASH_STATUS_FAILURE)
    MCUX_CSSL_ANALYSIS_COVERITY_START_FALSE_POSITIVE(INTEGER_OVERFLOW, "Variable 'sizeRemainingBytes' does not underflow because 'sizeCopiedBytes' <= 'inSize'")
    pAccumulationBuffer[sizeRemainingBytes++] = paddingByte;
    MCUX_CSSL_ANALYSIS_COVERITY_STOP_FALSE_POSITIVE(INTEGER_OVERFLOW)

    /* Zero-fill the rest of the block */
    MCUXCLMEMORY_FP_MEMORY_SET(pAccumulationBuffer + sizeRemainingBytes, 0x00u, algorithm->blockSize - sizeRemainingBytes);

    /* Set the high bit of the last byte (multi-rate padding) */
    pAccumulationBuffer[algorithm->blockSize - 1u] ^= 0x80u;

    /* Absorb the padded block into the state */
    /* TODO CLNS-10529 replace mcuxClHashModes_xor_buffers with unsecure XOR */
    mcuxClHashModes_xor_buffers((uint8_t *)pState, (uint8_t *)pState, pAccumulationBuffer, algorithm->blockSize);

    /**************************************************************************************/
    /*                Squeeze: produce outSizeRequested bytes of output                   */
    /**************************************************************************************/
    for (uint32_t squeezedBytes = 0u; squeezedBytes < outSizeRequested; squeezedBytes += algorithm->blockSize)
    {
        /* Keccak permutation before each output block */
        MCUX_CSSL_FP_FUNCTION_CALL(core_result2, mcuxClHashModes_core_c_keccak(pState));
        if (MCUXCLHASH_STATUS_OK != core_result2)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_oneShot_sha3_shake_core, MCUXCLHASH_STATUS_FAULT_ATTACK);
        }

        /* Write output (partial block on the last iteration) */
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(squeezedBytes, 0u, outSizeRequested, MCUXCLHASH_STATUS_FAILURE)
        uint32_t writeSize = (outSizeRequested - squeezedBytes > algorithm->blockSize)
                             ? algorithm->blockSize
                             : (outSizeRequested - squeezedBytes);
        MCUX_CSSL_FP_FUNCTION_CALL(bufferStatus3, mcuxClBuffer_write(pOut, squeezedBytes, (uint8_t *)pState, writeSize));
        if (MCUXCLBUFFER_STATUS_OK != bufferStatus3)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_oneShot_sha3_shake_core, bufferStatus3);
        }
    }

    /* Release both workarea slots allocated above */
    mcuxClSession_freeWords_cpuWa(session, MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(MCUXCLHASH_STATE_SIZE_SHA3)
                                        + MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(algorithm->blockSize));

    *pOutSizeComputed = outSizeRequested;

    /**************************************************************************************/
    /*                          Exit + FP balancing                                       */
    /**************************************************************************************/
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_oneShot_sha3_shake_core, MCUXCLHASH_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read)  * (inSize / algorithm->blockSize + 1u),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write) * ((outSizeRequested + algorithm->blockSize - 1u) / algorithm->blockSize),
        /* keccak calls: one per absorbed full block (numFullBlocks = inSize/blockSize),
         * plus one per squeezed output block (ceil(outSize/blockSize)).
         * NOTE: no keccak on the padded final absorb block - it is only XOR'd into state;
         * the first keccak of the squeeze phase advances it.  Earlier version added an
         * extra +1 here which caused a FP mismatch (oneshot examples failed, streaming
         * passed since streaming uses a different token path). */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_core_c_keccak) * ((inSize / algorithm->blockSize)
            + (outSizeRequested + algorithm->blockSize - 1u) / algorithm->blockSize)
    );
}

/* One-shot skeleton for SHA3 (fixed-length output, padding 0x06). */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_C_oneShot_sha3, mcuxClHash_AlgoSkeleton_OneShot_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHashModes_C_oneShot_sha3(
                                mcuxClSession_Handle_t session,
                                mcuxClHash_Algo_t algorithm,
                                mcuxCl_InputBuffer_t pIn,
                                uint32_t inSize,
                                mcuxCl_Buffer_t pOut,
                                uint32_t *const pOutSize)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_C_oneShot_sha3);

    MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClHashModes_C_oneShot_sha3_shake_core(
        session, algorithm, pIn, inSize,
        (uint32_t)algorithm->hashSize,
        pOut, pOutSize,
        0x06u /* SHA3 domain */));
    if (MCUXCLHASH_STATUS_OK != result)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_oneShot_sha3, result);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_oneShot_sha3, MCUXCLHASH_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_oneShot_sha3_shake_core)
    );
}

/**
 * @brief One-shot skeleton for SHAKE used via the Hash API.
 *
 * If the algorithm carries a non-zero hashSize (fixed-output Hash usage),
 * that value is the output length.  Otherwise (*pOutSize) is used (XOF usage).
 */
MCUX_CSSL_ANALYSIS_START_SUPPRESS_DECLARED_BUT_NEVER_DEFINED("It is indeed defined.")
MCUX_CSSL_ANALYSIS_START_PATTERN_SYMBOL_DEFINED_MORE_THAN_ONCE()
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_C_oneShot_sha3_shake, mcuxClHash_AlgoSkeleton_OneShot_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHashModes_C_oneShot_sha3_shake(
                                mcuxClSession_Handle_t session,
                                mcuxClHash_Algo_t algorithm,
                                mcuxCl_InputBuffer_t pIn,
                                uint32_t inSize,
                                mcuxCl_Buffer_t pOut,
                                uint32_t *const pOutSize)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_SYMBOL_DEFINED_MORE_THAN_ONCE()
MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DECLARED_BUT_NEVER_DEFINED()
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_C_oneShot_sha3_shake);

    uint32_t targetOutputSize;
    if (0u != *pOutSize)
    {
        targetOutputSize = *pOutSize;
    }
    else
    {
        targetOutputSize = (uint32_t)algorithm->hashSize;
    }

    MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClHashModes_C_oneShot_sha3_shake_core(
        session, algorithm, pIn, inSize,
        targetOutputSize,
        pOut, pOutSize,
        0x1Fu /* SHAKE domain */));
    if (MCUXCLHASH_STATUS_OK != result)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_oneShot_sha3_shake, result);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_oneShot_sha3_shake, MCUXCLHASH_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_oneShot_sha3_shake_core)
    );
}


/* Multi-part process skeleton for SHA3. */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_C_process_sha3, mcuxClHash_AlgoSkeleton_Process_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHashModes_C_process_sha3(
                        mcuxClSession_Handle_t session UNUSED_PARAM,
                        mcuxClHash_Context_t pContext,
                        mcuxCl_InputBuffer_t pIn,
                        uint32_t inSize)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_C_process_sha3);

    const mcuxClHash_AlgorithmDescriptor_t *algo = pContext->algo;
    uint32_t offset = 0u;
    uint8_t  *pUnprocessed = (uint8_t *)mcuxClHash_getUnprocessedPtr(pContext);
    uint32_t *pState       = mcuxClHash_getStatePtr(pContext);
    MCUX_CSSL_FP_COUNTER_STMT(uint32_t blocksProcessedCounter = 0u;)

    int32_t processedLengthNotZero = mcuxClHash_processedLength_cmp(pContext->processedLength, 0u);
    if (0 == processedLengthNotZero)
    {
        /* First call: initialize the Keccak state */
        MCUXCLMEMORY_FP_MEMORY_CLEAR(pState, MCUXCLHASH_STATE_SIZE_SHA3);
        /* Advance the phase flag so the state is not cleared on the next call */
        pContext->processedLength[0] = 1u;
    }

    /**************************************************************************************/
    /*                Absorb all complete blocks                                          */
    /**************************************************************************************/
    uint32_t inSizeCopy = inSize;
    while (0u < inSizeCopy)
    {
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pContext->unprocessedLength, 0u, algo->blockSize, MCUXCLHASH_STATUS_FAILURE)
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(offset, 0u, UINT32_MAX, MCUXCLHASH_STATUS_FAILURE)

        uint32_t dataToCopyLength = (inSizeCopy < (algo->blockSize - pContext->unprocessedLength))
                                    ? inSizeCopy
                                    : (algo->blockSize - pContext->unprocessedLength);

        MCUX_CSSL_FP_FUNCTION_CALL(bufferStatus, mcuxClBuffer_read(pIn, offset,
                                      pUnprocessed + pContext->unprocessedLength, dataToCopyLength));
        if (MCUXCLBUFFER_STATUS_OK != bufferStatus)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_process_sha3, bufferStatus);
        }

        inSizeCopy -= dataToCopyLength;
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("offset can't exceed UINT32_MAX.")
        offset += dataToCopyLength;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
        pContext->unprocessedLength += dataToCopyLength;

        if (pContext->unprocessedLength == algo->blockSize)
        {
            /* TODO CLNS-10529 replace mcuxClHashModes_xor_buffers with unsecure XOR */
            mcuxClHashModes_xor_buffers((uint8_t *)pState, (uint8_t *)pState, pUnprocessed, algo->blockSize);

            MCUX_CSSL_FP_FUNCTION_CALL(core_result, mcuxClHashModes_core_c_keccak(pState));
            if (MCUXCLHASH_STATUS_OK != core_result)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_process_sha3, MCUXCLHASH_STATUS_FAULT_ATTACK);
            }

            pContext->unprocessedLength = 0u;

            MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("FP counter wrap is handled by the FP framework.")
            MCUX_CSSL_FP_COUNTER_STMT(blocksProcessedCounter += 1u;)
            MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
        }
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_process_sha3, MCUXCLHASH_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear) * ((processedLengthNotZero == 0) ? 1u : 0u),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read)  * (((inSize == 0u) ? 0u : 1u)
            * (blocksProcessedCounter + ((pContext->unprocessedLength == 0u) ? 0u : 1u))),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_core_c_keccak) * blocksProcessedCounter
    );
}

/* Multi-part finish skeleton for SHA3 (pads with 0x06, single squeeze). */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_C_finish_sha3, mcuxClHash_AlgoSkeleton_Finish_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHashModes_C_finish_sha3(
                            mcuxClSession_Handle_t session UNUSED_PARAM,
                            mcuxClHash_Context_t pContext,
                            mcuxCl_Buffer_t pOut,
                            uint32_t *const pOutSize)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_C_finish_sha3);

    const mcuxClHash_AlgorithmDescriptor_t *algo = pContext->algo;
    uint8_t  *pUnprocessed = (uint8_t *)mcuxClHash_getUnprocessedPtr(pContext);
    uint32_t *pState       = mcuxClHash_getStatePtr(pContext);

    /**************************************************************************************/
    /*                Build the final padded block in the unprocessed buffer              */
    /**************************************************************************************/
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(algo->blockSize, 1u, 200u, MCUXCLHASH_STATUS_FAILURE)
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pContext->unprocessedLength, 0u, algo->blockSize - 1u, MCUXCLHASH_STATUS_FAILURE)
    pUnprocessed[pContext->unprocessedLength++] = 0x06u; /* SHA3 domain */

    uint32_t remainingBlockLength = algo->blockSize - pContext->unprocessedLength;
    MCUXCLMEMORY_FP_MEMORY_SET(pUnprocessed + pContext->unprocessedLength, 0x00u, remainingBlockLength);

    pUnprocessed[algo->blockSize - 1u] ^= 0x80u;

    /**************************************************************************************/
    /*                Absorb padded block, permute, copy output                           */
    /**************************************************************************************/
    /* TODO CLNS-10529 replace mcuxClHashModes_xor_buffers with unsecure XOR */
    mcuxClHashModes_xor_buffers((uint8_t *)pState, (uint8_t *)pState, pUnprocessed, algo->blockSize);

    MCUX_CSSL_FP_FUNCTION_CALL(core_result, mcuxClHashModes_core_c_keccak(pState));
    if (MCUXCLHASH_STATUS_OK != core_result)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_finish_sha3, MCUXCLHASH_STATUS_FAULT_ATTACK);
    }

    MCUXCLMEMORY_FP_MEMORY_COPY(pOut, pState, algo->hashSize);
    *pOutSize = (uint32_t)algo->hashSize;

    /* Clear the context */
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pContext->algo->stateSize, 1u, 200u, MCUXCLHASH_STATUS_FAILURE)
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pContext->algo->blockSize, 1u, 200u, MCUXCLHASH_STATUS_FAILURE)
    MCUXCLMEMORY_FP_MEMORY_CLEAR((uint8_t *)pContext->processedLength,
        sizeof(mcuxClHash_ContextDescriptor_t) + pContext->algo->blockSize + pContext->algo->stateSize);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_finish_sha3, MCUXCLHASH_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_core_c_keccak),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear)
    );
}

/* Multi-part process skeleton for SHAKE (pads with 0x1F). */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_C_process_sha3_shake, mcuxClHash_AlgoSkeleton_Process_t)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHashModes_C_process_sha3_shake(
                        mcuxClSession_Handle_t session UNUSED_PARAM,
                        mcuxClHash_Context_t pContext,
                        mcuxCl_InputBuffer_t pIn,
                        uint32_t inSize)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_C_process_sha3_shake);

    const mcuxClHash_AlgorithmDescriptor_t *algo = pContext->algo;
    uint32_t offset = 0u;
    uint8_t  *pUnprocessed = (uint8_t *)mcuxClHash_getUnprocessedPtr(pContext);
    uint32_t *pState       = mcuxClHash_getStatePtr(pContext);
    MCUX_CSSL_FP_COUNTER_STMT(uint32_t blocksProcessedCounter = 0u;)

    int32_t squeezeAlreadyCalled = mcuxClHash_processedLength_cmp(pContext->processedLength,
                                                                  MCUXCLHASHMODES_SHAKE_PHASE_SQUEEZE);
    if (0 == squeezeAlreadyCalled)
    {
        /* Cannot absorb more data after squeezing has started */
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_process_sha3_shake, MCUXCLHASH_STATUS_FAILURE);
    }

    int32_t firstBlockAbsorbed = mcuxClHash_processedLength_cmp(pContext->processedLength,
                                                                MCUXCLHASHMODES_SHAKE_PHASE_INIT);
    if (0 == firstBlockAbsorbed)
    {
        /* First call: initialize the Keccak state */
        MCUXCLMEMORY_FP_MEMORY_CLEAR(pState, MCUXCLHASH_STATE_SIZE_SHA3);
        pContext->processedLength[0] = MCUXCLHASHMODES_SHAKE_PHASE_ABSORB;
    }

    /**************************************************************************************/
    /*                Absorb all complete blocks                                          */
    /**************************************************************************************/
    uint32_t inSizeCopy = inSize;
    while (0u < inSizeCopy)
    {
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pContext->unprocessedLength, 0u, algo->blockSize, MCUXCLHASH_STATUS_FAILURE)
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(offset, 0u, UINT32_MAX, MCUXCLHASH_STATUS_FAILURE)

        uint32_t dataToCopyLength = (inSizeCopy < (algo->blockSize - pContext->unprocessedLength))
                                    ? inSizeCopy
                                    : (algo->blockSize - pContext->unprocessedLength);

        MCUX_CSSL_FP_FUNCTION_CALL(bufferStatus, mcuxClBuffer_read(pIn, offset,
                                      pUnprocessed + pContext->unprocessedLength, dataToCopyLength));
        if (MCUXCLBUFFER_STATUS_OK != bufferStatus)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_process_sha3_shake, bufferStatus);
        }

        inSizeCopy -= dataToCopyLength;
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("offset can't exceed UINT32_MAX.")
        offset += dataToCopyLength;
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()
        pContext->unprocessedLength += dataToCopyLength;

        if (pContext->unprocessedLength == algo->blockSize)
        {
            /* TODO CLNS-10529 replace mcuxClHashModes_xor_buffers with unsecure XOR */
            mcuxClHashModes_xor_buffers((uint8_t *)pState, (uint8_t *)pState, pUnprocessed, algo->blockSize);

            MCUX_CSSL_FP_FUNCTION_CALL(core_result, mcuxClHashModes_core_c_keccak(pState));
            if (MCUXCLHASH_STATUS_OK != core_result)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_process_sha3_shake, MCUXCLHASH_STATUS_FAULT_ATTACK);
            }

            pContext->unprocessedLength = 0u;

            MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_OVERFLOW("FP counter wrap is handled by the FP framework.")
            MCUX_CSSL_FP_COUNTER_STMT(blocksProcessedCounter += 1u;)
            MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_OVERFLOW()
        }
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_process_sha3_shake, MCUXCLHASH_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear) * ((firstBlockAbsorbed == 0) ? (uint32_t)1u : (uint32_t)0u),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_read)  * (((inSize == 0u) ? 0u : 1u)
            * (blocksProcessedCounter + ((pContext->unprocessedLength == 0u) ? 0u : 1u))),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_core_c_keccak) * blocksProcessedCounter
    );
}

/**
 * @brief Finish the absorb phase for SHAKE: pad with 0x1F, XOR padded block into
 *        the state, and transition to the squeeze phase.
 *
 * This function does NOT call Keccak.  The first Keccak call happens inside
 * mcuxClHashModes_C_shake_squeeze when the first output bytes are requested.
 * The unprocessedLength field is reset to 0 after padding so that squeeze can
 * repurpose it as a "bytes remaining in the current state block" counter.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_C_shake_finishAbsorb)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHashModes_C_shake_finishAbsorb(
                            mcuxClHash_Context_t pContext)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_C_shake_finishAbsorb);

    const mcuxClHash_AlgorithmDescriptor_t *algo = pContext->algo;
    uint8_t  *pUnprocessed = (uint8_t *)mcuxClHash_getUnprocessedPtr(pContext);
    uint32_t *pState       = mcuxClHash_getStatePtr(pContext);

    /* Initialize state. Needed if process has never been called */
    int32_t firstBlockAbsorbed = mcuxClHash_processedLength_cmp(pContext->processedLength,
                                                               MCUXCLHASHMODES_SHAKE_PHASE_INIT);
    if (0 == firstBlockAbsorbed)
    {
        MCUXCLMEMORY_FP_MEMORY_CLEAR(pState, MCUXCLHASH_STATE_SIZE_SHA3);
        /* The state has been cleared. Phase indicator is not advanced,
         * since it is not needed for padding and the context is cleared at the end of this function. */
    }

    /* Transition to squeeze phase (padding is applied only once) */
    pContext->processedLength[0] = MCUXCLHASHMODES_SHAKE_PHASE_SQUEEZE;

    /**************************************************************************************/
    /*                Build the SHAKE padded block (domain 0x1F)                         */
    /**************************************************************************************/
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(algo->blockSize, 1u, 200u, MCUXCLHASH_STATUS_FAILURE)
    MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pContext->unprocessedLength, 0u, algo->blockSize - 1u, MCUXCLHASH_STATUS_FAILURE)
    pUnprocessed[pContext->unprocessedLength++] = 0x1Fu; /* SHAKE domain */

    uint32_t remainingBlockLength = algo->blockSize - pContext->unprocessedLength;
    MCUXCLMEMORY_FP_MEMORY_SET(pUnprocessed + pContext->unprocessedLength, 0x00u, remainingBlockLength);

    pUnprocessed[algo->blockSize - 1u] ^= 0x80u;

    /* Absorb the padded block */
    /* TODO CLNS-10529 replace mcuxClHashModes_xor_buffers with unsecure XOR */
    mcuxClHashModes_xor_buffers((uint8_t *)pState, (uint8_t *)pState, pUnprocessed, algo->blockSize);

    /* Reset for use as squeeze position counter in mcuxClHashModes_C_shake_squeeze */
    pContext->unprocessedLength = 0u;

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_shake_finishAbsorb, MCUXCLHASH_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear) * ((firstBlockAbsorbed == 0) ? (uint32_t)1u : (uint32_t)0u),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set)
    );
}

/**
 * @brief SHAKE generate/squeeze: produce *pOutSize bytes of XOF output.
 *
 * Can be called repeatedly across multiple squeeze calls.  The
 * pContext->unprocessedLength field tracks how many bytes of the
 * current state block have not yet been consumed. If the SHAKE state is
 * still in the ABSORB phase, finishAbsorb is invoked first to apply the
 * 0x1F padding and transition into the SQUEEZE phase.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_C_generate_shake)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHashModes_C_generate_shake(
                            mcuxClSession_Handle_t session UNUSED_PARAM,
                            mcuxClHash_Context_t pContext,
                            mcuxCl_Buffer_t pOut,
                            uint32_t *pOutSize)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_C_generate_shake);

    const mcuxClHash_AlgorithmDescriptor_t *algo = pContext->algo;
    uint32_t *pState = mcuxClHash_getStatePtr(pContext);
    uint32_t outSize = *pOutSize;

    /* If still in ABSORB phase, run the padding step now. */
    int32_t alreadySqueezing = mcuxClHash_processedLength_cmp(pContext->processedLength,
                                                              MCUXCLHASHMODES_SHAKE_PHASE_SQUEEZE);
    if (0 != alreadySqueezing)
    {
        MCUX_CSSL_FP_FUNCTION_CALL(finAbs_result, mcuxClHashModes_C_shake_finishAbsorb(pContext));
        if (MCUXCLHASH_STATUS_OK != finAbs_result)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_generate_shake, finAbs_result);
        }
        /* finishAbsorb has reset unprocessedLength to 0 - compute fpLoopIterations
         * against the post-finishAbsorb value so counts match reality. */
    }
    MCUX_CSSL_FP_COUNTER_STMT(const uint32_t fpLoopIterations =
        (outSize <= pContext->unprocessedLength)
            ? 0u
            : (((outSize - pContext->unprocessedLength) + (algo->blockSize - 1u)) / algo->blockSize));


    if (outSize <= pContext->unprocessedLength)
    {
        /* Enough data remains in the current state block: copy directly */
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pContext->unprocessedLength, 0u, algo->blockSize, MCUXCLHASH_STATUS_FAILURE)
        MCUX_CSSL_FP_FUNCTION_CALL(bufferStatus, mcuxClBuffer_write(pOut, 0u,
            (uint8_t *)pState + (algo->blockSize - pContext->unprocessedLength), outSize));
        if (MCUXCLBUFFER_STATUS_OK != bufferStatus)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_generate_shake, bufferStatus);
        }
        pContext->unprocessedLength -= outSize;
    }
    else
    {
        /* Need to permute one or more times to get enough output */
        uint32_t outputGenerated = 0u;

        /* Drain whatever is left in the current block first */
        MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(pContext->unprocessedLength, 0u, algo->blockSize, MCUXCLHASH_STATUS_FAILURE)
        MCUX_CSSL_FP_FUNCTION_CALL(bufferStatus2, mcuxClBuffer_write(pOut, 0u,
            (uint8_t *)pState + (algo->blockSize - pContext->unprocessedLength),
            pContext->unprocessedLength));
        if (MCUXCLBUFFER_STATUS_OK != bufferStatus2)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_generate_shake, bufferStatus2);
        }
        outputGenerated += pContext->unprocessedLength;
        pContext->unprocessedLength = 0u;

        while (outSize != outputGenerated)
        {
            /* Permute to generate a new output block */
            MCUX_CSSL_FP_FUNCTION_CALL(core_result, mcuxClHashModes_core_c_keccak(pState));
            if (MCUXCLHASH_STATUS_OK != core_result)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_generate_shake, MCUXCLHASH_STATUS_FAULT_ATTACK);
            }

            MCUX_CSSL_ANALYSIS_ASSERT_PARAMETER(outputGenerated, 0u, outSize, MCUXCLHASH_STATUS_FAILURE)
            uint32_t currentOutSize = ((outSize - outputGenerated > algo->blockSize)
                                       ? algo->blockSize
                                       : (outSize - outputGenerated));
            MCUX_CSSL_FP_FUNCTION_CALL(bufferStatus3, mcuxClBuffer_write(pOut, outputGenerated,
                (uint8_t *)pState, currentOutSize));
            if (MCUXCLBUFFER_STATUS_OK != bufferStatus3)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_generate_shake, bufferStatus3);
            }
            pContext->unprocessedLength = algo->blockSize - currentOutSize;
            outputGenerated += currentOutSize;
        }
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_generate_shake, MCUXCLHASH_STATUS_OK,
        /* finishAbsorb is called exactly once - on the very first generate call
         * (when we transition from ABSORB to SQUEEZE phase).  On subsequent
         * generate calls the phase is already SQUEEZE so no call happens.
         * alreadySqueezing == 0 means "still in absorb phase" (cmp equal). */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_shake_finishAbsorb) * ((alreadySqueezing != 0) ? 1u : 0u),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClBuffer_write) * (1u + fpLoopIterations),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_core_c_keccak) * fpLoopIterations
    );
}


/*
 * Multi-part finish skeleton for SHAKE used via the Hash API.
 *
 * Calls finishAbsorb (adds SHAKE padding, transitions to squeeze phase) and
 * then squeezes the requested number of bytes.  If *pOutSize is 0 on entry,
 * algorithm->hashSize is used as the output length.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHashModes_C_finish_sha3_shake, mcuxClHash_AlgoSkeleton_Finish_t)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) mcuxClHashModes_C_finish_sha3_shake(
                            mcuxClSession_Handle_t session,
                            mcuxClHash_Context_t pContext,
                            mcuxCl_Buffer_t pOut,
                            uint32_t *const pOutSize)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClHashModes_C_finish_sha3_shake);

    MCUX_CSSL_FP_FUNCTION_CALL(finAbs_result, mcuxClHashModes_C_shake_finishAbsorb(pContext));
    if (MCUXCLHASH_STATUS_OK != finAbs_result)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_finish_sha3_shake, MCUXCLHASH_STATUS_FAULT_ATTACK);
    }

    /**************************************************************************************/
    /*                Determine output size and squeeze                                   */
    /**************************************************************************************/
    uint32_t outSize = *pOutSize;
    if (0u == outSize)
    {
        /* Hash usage: output length fixed by the algorithm descriptor */
        outSize = pContext->algo->hashSize;
    }
    else
    {
        /* Caller supplied a specific length (SHAKE via Hash API) */
        *pOutSize = 0u;
    }

    MCUX_CSSL_FP_FUNCTION_CALL(squeeze_result, mcuxClHashModes_C_generate_shake(session, pContext, pOut, &outSize));
    if (MCUXCLHASH_STATUS_OK != squeeze_result)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_finish_sha3_shake, MCUXCLHASH_STATUS_FAULT_ATTACK);
    }

    /* Report how many bytes were squeezed */
    *pOutSize = outSize;

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClHashModes_C_finish_sha3_shake, MCUXCLHASH_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_shake_finishAbsorb),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_generate_shake)
    );
}

/**********************************************************
 * Algorithm descriptor implementations
 **********************************************************/
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_C_Sha3_224 = {
    .oneShotSkeleton                  = mcuxClHashModes_C_oneShot_sha3,
    .protection_token_oneShotSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_oneShot_sha3),
    .processSkeleton                  = mcuxClHashModes_C_process_sha3,
    .protection_token_processSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_process_sha3),
    .finishSkeleton                   = mcuxClHashModes_C_finish_sha3,
    .protection_token_finishSkeleton  = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_finish_sha3),
    .processedLengthCheckMask         = MCUXCLHASH_PROCESSED_LENGTH_CHECK_MASK_SHA3,
    .blockSize                        = MCUXCLHASH_BLOCK_SIZE_SHA3_224,
    .hashSize                         = MCUXCLHASH_OUTPUT_SIZE_SHA3_224,
    .stateSize                        = MCUXCLHASH_STATE_SIZE_SHA3,
    .counterSize                      = MCUXCLHASH_COUNTER_SIZE_SHA3,
    .pOid                             = mcuxClHash_oidSha3_224,
    .oidSize                          = sizeof(mcuxClHash_oidSha3_224),
};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_C_Sha3_256 = {
    .oneShotSkeleton                  = mcuxClHashModes_C_oneShot_sha3,
    .protection_token_oneShotSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_oneShot_sha3),
    .processSkeleton                  = mcuxClHashModes_C_process_sha3,
    .protection_token_processSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_process_sha3),
    .finishSkeleton                   = mcuxClHashModes_C_finish_sha3,
    .protection_token_finishSkeleton  = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_finish_sha3),
    .processedLengthCheckMask         = MCUXCLHASH_PROCESSED_LENGTH_CHECK_MASK_SHA3,
    .blockSize                        = MCUXCLHASH_BLOCK_SIZE_SHA3_256,
    .hashSize                         = MCUXCLHASH_OUTPUT_SIZE_SHA3_256,
    .stateSize                        = MCUXCLHASH_STATE_SIZE_SHA3,
    .counterSize                      = MCUXCLHASH_COUNTER_SIZE_SHA3,
    .pOid                             = mcuxClHash_oidSha3_256,
    .oidSize                          = sizeof(mcuxClHash_oidSha3_256),
};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_C_Sha3_384 = {
    .oneShotSkeleton                  = mcuxClHashModes_C_oneShot_sha3,
    .protection_token_oneShotSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_oneShot_sha3),
    .processSkeleton                  = mcuxClHashModes_C_process_sha3,
    .protection_token_processSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_process_sha3),
    .finishSkeleton                   = mcuxClHashModes_C_finish_sha3,
    .protection_token_finishSkeleton  = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_finish_sha3),
    .processedLengthCheckMask         = MCUXCLHASH_PROCESSED_LENGTH_CHECK_MASK_SHA3,
    .blockSize                        = MCUXCLHASH_BLOCK_SIZE_SHA3_384,
    .hashSize                         = MCUXCLHASH_OUTPUT_SIZE_SHA3_384,
    .stateSize                        = MCUXCLHASH_STATE_SIZE_SHA3,
    .counterSize                      = MCUXCLHASH_COUNTER_SIZE_SHA3,
    .pOid                             = mcuxClHash_oidSha3_384,
    .oidSize                          = sizeof(mcuxClHash_oidSha3_384),
};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_C_Sha3_512 = {
    .oneShotSkeleton                  = mcuxClHashModes_C_oneShot_sha3,
    .protection_token_oneShotSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_oneShot_sha3),
    .processSkeleton                  = mcuxClHashModes_C_process_sha3,
    .protection_token_processSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_process_sha3),
    .finishSkeleton                   = mcuxClHashModes_C_finish_sha3,
    .protection_token_finishSkeleton  = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_finish_sha3),
    .processedLengthCheckMask         = MCUXCLHASH_PROCESSED_LENGTH_CHECK_MASK_SHA3,
    .blockSize                        = MCUXCLHASH_BLOCK_SIZE_SHA3_512,
    .hashSize                         = MCUXCLHASH_OUTPUT_SIZE_SHA3_512,
    .stateSize                        = MCUXCLHASH_STATE_SIZE_SHA3,
    .counterSize                      = MCUXCLHASH_COUNTER_SIZE_SHA3,
    .pOid                             = mcuxClHash_oidSha3_512,
    .oidSize                          = sizeof(mcuxClHash_oidSha3_512),
};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_C_Sha3_Shake_128 = {
    .oneShotSkeleton                  = mcuxClHashModes_C_oneShot_sha3_shake,
    .protection_token_oneShotSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_oneShot_sha3_shake),
    .processSkeleton                  = mcuxClHashModes_C_process_sha3_shake,
    .protection_token_processSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_process_sha3_shake),
    .finishSkeleton                   = mcuxClHashModes_C_finish_sha3_shake,
    .protection_token_finishSkeleton  = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_finish_sha3_shake),
    .processedLengthCheckMask         = MCUXCLHASH_PROCESSED_LENGTH_CHECK_MASK_SHA3,
    .blockSize                        = MCUXCLHASH_BLOCK_SIZE_SHA3_SHAKE_128,
    .hashSize                         = MCUXCLHASH_OUTPUT_SIZE_SHA3_SHAKE_128,
    .stateSize                        = MCUXCLHASH_STATE_SIZE_SHA3,
    .counterSize                      = MCUXCLHASH_COUNTER_SIZE_SHA3,
    .pOid                             = mcuxClHash_oidSha3_shake_128,
    .oidSize                          = sizeof(mcuxClHash_oidSha3_shake_128),
};

const mcuxClHash_AlgorithmDescriptor_t mcuxClHash_AlgorithmDescriptor_C_Sha3_Shake_256 = {
    .oneShotSkeleton                  = mcuxClHashModes_C_oneShot_sha3_shake,
    .protection_token_oneShotSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_oneShot_sha3_shake),
    .processSkeleton                  = mcuxClHashModes_C_process_sha3_shake,
    .protection_token_processSkeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_process_sha3_shake),
    .finishSkeleton                   = mcuxClHashModes_C_finish_sha3_shake,
    .protection_token_finishSkeleton  = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHashModes_C_finish_sha3_shake),
    .processedLengthCheckMask         = MCUXCLHASH_PROCESSED_LENGTH_CHECK_MASK_SHA3,
    .blockSize                        = MCUXCLHASH_BLOCK_SIZE_SHA3_SHAKE_256,
    .hashSize                         = MCUXCLHASH_OUTPUT_SIZE_SHA3_SHAKE_256,
    .stateSize                        = MCUXCLHASH_STATE_SIZE_SHA3,
    .counterSize                      = MCUXCLHASH_COUNTER_SIZE_SHA3,
    .pOid                             = mcuxClHash_oidSha3_shake_256,
    .oidSize                          = sizeof(mcuxClHash_oidSha3_shake_256),
};
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
