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

/** @file  mcuxClAead_AesCcm.c
 *  @brief implementation of the AES CCM skeleton functions of the mcuxClAead component */

#include <mcuxClAead.h>
#include <internal/mcuxClAead_Internal_Types.h>
#include <internal/mcuxClAead_Internal_Functions.h>
#include <mcuxClMemory.h>
#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxCsslMemory.h>
#include <mcuxCsslParamIntegrity.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCss.h>
#include <internal/mcuxClPadding_Internal.h>
#include <mcuxClAes.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAead_ModeSkeletonAesCcm)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t) mcuxClAead_ModeSkeletonAesCcm(
    mcuxClSession_Handle_t session,
    mcuxClAead_Context_t * const pContext,
    mcuxCl_InputBuffer_t pNonce,
    uint32_t nonceLength,
    mcuxCl_InputBuffer_t pIn,
    uint32_t inLength,
    mcuxCl_InputBuffer_t pAdata,
    uint32_t adataLength,
    mcuxCl_Buffer_t pOut,
    uint32_t * const pOutLength,
    mcuxCl_Buffer_t pTag,
    uint32_t tagLength,
    uint32_t options //!< options is a bitmask with one bit reserved for each of the operations
    )
{
    /* [Design]
        ATTN: pOutLength will be _incremented_ by the number of bytes of encrypted data that have been
              written to the @p pOut buffer. Except otherwise mentioned processing steps _output_ data
              to pOut and update pOutLength

        Note:
            - options is a bitmask: 1: init, 2: aad, 4: process, 8: finish, 15: oneshot, 16: verify

        - Preconditions
            - aadLength in context has been initialized
            - dataLength in context has been initialized
            - tagLength in context has been initialized
            - key in context has been initialized
            - mode in context has been initialized
            - processedDataLength in context has been initialized and maintained

        - Context usage:
            - the state contains both the CTR counter and the partial CBC-MAC

        - Common IV processing (options == oneshot / init)
            - set partialDataLength in context to zero
            - construct the first block using the nonce from the input and the dataLength, aadLength and tagLength from the
              context. partialData can be used for this as it is not in use yet.
            - process the first block using pEngine(option: auth+init) with zero IV (the engine will update the state in context)
            - construct the counter for CTR mode encryption and output to state in context, let it start at 'one'

        - AAD processing (options == oneshot / update aad)
            - if adataLength != 0 add the new data from the input to partialData[partialDataLength] and process using
              pEngine(option: auth) if possible, adapt partialDataLength and processedDataLength
            - process remaining complete blocks from the input using pEngine(option: auth), adapt processedDataLength
            - add remaining data to partialData, adapt partialDataLength and processedDataLength
            - [Assertion] aadLength <= processedDataLength
            - if aadLength == processedDataLength padd partialData with zeros and process using pEngine(option: auth), set
              partialDataLength to zero

        - Data processing (options == oneshot / update data)
            - if inLength != 0 add the new data from the input to partialData and process using pEngine(option: auth+enc) if possible,
              adapt partialDataLength and processedDataLength (this will never be the case for oneshot)
            - process remaining complete blocks from the input using pEngine(option: auth+enc), adapt processedDataLength
            - add remaining data to partialData, adapt partialDataLength and processedDataLength
            - [Assertion] aadLength + dataLength  <= processedDataLength
            - if aadLength + dataLength == processedDataLength padd partialData with zeros
              and process using pEngine(option: auth+enc), set partialDataLength to zero

        - Finalization processing (options == oneshot / finish / verify)
            - if partialDataLength != 0 exit with ERROR
            - reset counter value to 'zero' (leaving the other fields intact)
            - process the CBC-MAC state with pEngine(option: enc), and store the result in partialData

        - Finalization processing (options == oneshot / finish)
            - copy tagLength bytes from partialData to the tag
            - clean up context

        - Finalization processing (options == verify)
            - compare tagLength bytes from partialData to the tag
            - clean up context

        - exit
    */

    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAead_ModeSkeletonAesCcm,
        MCUX_CSSL_FP_CONDITIONAL(((options == MCUXCLAEAD_OPTION_ONESHOT) || (options == MCUXCLAEAD_OPTION_INIT)),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
            pContext->mode->protection_token_engine,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy)
        )
    );

/*
        - Common IV processing (options == oneshot / init)
            - set partialDataLength in context to zero
            - construct the first block using the nonce from the input and the dataLength, aadLength and tagLength from the
              context. partialData can be used for this as it is not in use yet.
            - process the first block using pEngine(option: auth+init) with zero IV (the engine will update the state in context)
            - construct the counter for CTR mode encryption and output to state in context, let it start at 'one'
*/
    if ((options == MCUXCLAEAD_OPTION_ONESHOT) || (options == MCUXCLAEAD_OPTION_INIT))
    {
        /* Init tag. For CCM, the state store the tag value */
        MCUX_CSSL_FP_FUNCTION_CALL(ret_memset_tag, mcuxClMemory_set(pContext->state,
                                                                  0u,
                                                                  MCUX_CL_AES_BLOCK_SIZE,
                                                                  MCUX_CL_AES_BLOCK_SIZE));
        if (ret_memset_tag != 0u)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
        }

        pContext->partialDataLength = 0u;

        /* Generate the plain tag -> CBC-MAC with zero IV */
        // Clear first blocks to guarantee zero padding
        MCUX_CSSL_FP_FUNCTION_CALL(ret_memset_block, mcuxClMemory_set(pContext->partialData,
                                                                  0u,
                                                                  MCUX_CL_AES_BLOCK_SIZE,
                                                                  MCUX_CL_AES_BLOCK_SIZE));
        if (ret_memset_block != 0u)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
        }

        //Determine whether the nonceLength is less than MCUX_CL_AES_BLOCK_SIZE -1 to prevent memory overflow later
        if(nonceLength > MCUX_CL_AES_BLOCK_SIZE - 1u)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
        }

        // Get length of auth field from parameter
        uint8_t t = (uint8_t)((tagLength - 2u) / 2u);
        // Get q-1 from parameter
        uint8_t q = (uint8_t)(15u - nonceLength);
        // Assemble the flags byte for B0
        // --------------------------------------------
        // |     7    |   6   |    5..3     |   2..0  |
        // | Reserved | Adata | [(t-2)/2]_3 | [q-1]_3 |
        // --------------------------------------------
        uint8_t isheaderLen = (uint8_t)(adataLength > 0u);
        pContext->partialData[0u] = (uint8_t)((uint8_t)((isheaderLen << 6u) | (t << 3u)) | (q - 1u));

        // Create B0
        // ----------------------------------
        // |   0   | 1 .. 15-q | 16-q .. 15 |
        // | Flags |     N     |      Q     |
        // ----------------------------------

        // Copy nonce N
        MCUX_CSSL_FP_FUNCTION_CALL(copyNonceResult, mcuxClMemory_copy(&pContext->partialData[1u],
                                                                   (uint8_t const*)pNonce,
                                                                   nonceLength,
                                                                   nonceLength));

        if (copyNonceResult != 0u)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
        }

        // Create Q
        uint32_t inMask = 0x000000FFu;
        for(int32_t it = 15; it >= (16 - ((int32_t)q)); --it)
        {
          pContext->partialData[it] = (uint8_t)((inLength & inMask) >> (((15u - (uint8_t)it) * 8u) & 0x0Fu));
          inMask = inMask << 8u;
        }

        //Calculate tag over B0
        //process the first block using pEngine(option: auth) with zero IV and output to state in context
        MCUX_CSSL_FP_FUNCTION_CALL(authRet, pContext->mode->pEngine(session, pContext,
                                                                   pContext->partialData,
                                                                   MCUX_CL_AES_BLOCK_SIZE,
                                                                   NULL,
                                                                   NULL,
                                                                   MCUXCLAEAD_ENGINE_OPTION_AUTH | MCUXCLAEAD_ENGINE_OPTION_INIT));

        if(MCUXCLAEAD_STATUS_OK != authRet)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
        }

        // Formatting of the associated data
        // Encode a and concatenate with associated data
        // Check if AAD has to be processed
        if(0u == adataLength)
        {
          pContext->partialDataLength = 0u;
        }
        // If 0 < a < 2^{16}-2^{8}, then a is encoded as [a]_16, i.e., two octets.
        else if(adataLength < ((1UL << 16u) - (1UL << 8u)))
        {
          // a < 2^{16}-2^{8}
          pContext->partialData[0] = (uint8_t)((adataLength & 0x0000FF00u) >> 8u);
          pContext->partialData[1] = (uint8_t)((adataLength & 0x000000FFu) >> 0u);

          pContext->partialDataLength = 2u;
        }
        // If 2^{16}-2^{8} <= a < 2^{32}, then a is encoded as 0xff || 0xfe || [a]_32, i.e., six octets.
        else
        {
          // a >= 2^{16}-2^{8}
          pContext->partialData[0] = (uint8_t)0xFFu;
          pContext->partialData[1] = (uint8_t)0xFEu;
          pContext->partialData[2] = (uint8_t)((adataLength & 0xFF000000u) >> 24u);
          pContext->partialData[3] = (uint8_t)((adataLength & 0x00FF0000u) >> 16u);
          pContext->partialData[4] = (uint8_t)((adataLength & 0x0000FF00u) >> 8u);
          pContext->partialData[5] = (uint8_t)((adataLength & 0x000000FFu) >> 0u);

          pContext->partialDataLength = 6u;
        }

        // If 2^{32} <= a < 2^{64}, then a is encoded as 0xff || 0xff || [a]_64, i.e., ten octets.
        // This case is not supported in CL and hence does not occur since inLength is uint32_t

        /*  Generate the counter for CTR mode encryption */
        // &pContext->state[32] won't be used in CCM mode, so write it to store the counter0Data.
        // Use &pContext->state[48] to store the counterData
        // Clear counter first
        MCUX_CSSL_FP_FUNCTION_CALL(ret_memset_counter, mcuxClMemory_set(&pContext->state[32],
                                                                  0u,
                                                                  MCUX_CL_AES_BLOCK_SIZE,
                                                                  MCUX_CL_AES_BLOCK_SIZE));
        if (ret_memset_counter != 0u)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
        }

        // Assemble the flags byte
        // ------------------------------------------
        // |     7    |     6    |  5..3  |   2..0  |
        // | Reserved | Reserved |   000  | [q-1]_3 |
        // ------------------------------------------
        pContext->state[32] = q - 1u;

        // Create CTR0
        // ----------------------------------
        // |   0   | 1 .. 15-q | 16-q .. 15 |
        // | Flags |     N     |      0     |
        // ----------------------------------

        // Copy nonce into counter block
        MCUX_CSSL_FP_FUNCTION_CALL(copyNonceRet, mcuxClMemory_copy(&pContext->state[33],
                                                                   (uint8_t *)pNonce,
                                                                   nonceLength,
                                                                   nonceLength));

        if (copyNonceRet != 0u)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
        }

        MCUX_CSSL_FP_FUNCTION_CALL(ctrCpyRet, mcuxClMemory_copy(&pContext->state[48],
                                                              &pContext->state[32],
                                                              MCUX_CL_AES_BLOCK_SIZE,
                                                              MCUX_CL_AES_BLOCK_SIZE));

        if (ctrCpyRet != 0u)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
        }
        // Last X bytes of counterData are always equal zero, set last byte to one for the next computation
        pContext->state[63] = 0x1u;
    }

/*
        - AAD processing (options == oneshot / update aad)
            - if adataLength != 0 add the new data from the input to partialData[partialDataLength] and process using
              pEngine(option: auth) if possible, adapt partialDataLength and processedDataLength
            - process remaining complete blocks from the input using pEngine(option: auth), adapt processedDataLength
            - add remaining data to partialData, adapt partialDataLength and processedDataLength
            - [Assertion] aadLength <= processedDataLength
            - if aadLength == processedDataLength padd partialData with zeros and process using pEngine(option: auth), set
              partialDataLength to zero
*/
    //below variable definitions are used for flow protection of AAD process
    uint32_t mainAadFpFlag = 0u;
    uint32_t secondAadFpFlag = 0u;
    uint32_t thirdAadFpFlag = 0u;
    uint32_t forthAadFpFlag = 0u;
    uint32_t fifthAadFpFlag = 0u;

    if ((options == MCUXCLAEAD_OPTION_ONESHOT) || (options == MCUXCLAEAD_OPTION_PROCESS_AAD))
    {
            uint32_t lenToCopy = adataLength;
            // adataLength is the length of AAD for this AAD process call
            if(0u != lenToCopy)
            {
                if((pContext->partialDataLength + lenToCopy) >= MCUX_CL_AES_BLOCK_SIZE)
                {
                    secondAadFpFlag = 1u;
                    uint8_t const* pAad = (uint8_t const*)pAdata;
                    MCUX_CSSL_FP_FUNCTION_CALL(cpyAadRet, mcuxClMemory_copy(&pContext->partialData[pContext->partialDataLength],
                                                                   pAad,
                                                                   MCUX_CL_AES_BLOCK_SIZE - pContext->partialDataLength,
                                                                   MCUX_CL_AES_BLOCK_SIZE - pContext->partialDataLength));
                    if (0u != cpyAadRet)
                    {
                        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
                    }
                    pAad += MCUX_CL_AES_BLOCK_SIZE - pContext->partialDataLength;

                    lenToCopy -= (MCUX_CL_AES_BLOCK_SIZE - pContext->partialDataLength);
                    pContext->partialDataLength = 0u;

                    //Calculate tag over adata
                    MCUX_CSSL_FP_FUNCTION_CALL(aadAuthRet, pContext->mode->pEngine(session, pContext,
                                                                               pContext->partialData,
                                                                               MCUX_CL_AES_BLOCK_SIZE,
                                                                               NULL,
                                                                               NULL,
                                                                               MCUXCLAEAD_ENGINE_OPTION_AUTH));

                    if(MCUXCLAEAD_STATUS_OK != aadAuthRet)
                    {
                        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
                    }

                    if(lenToCopy >= MCUX_CL_AES_BLOCK_SIZE)
                    {
                        thirdAadFpFlag = 1u;
                        uint32_t adataBlocks = lenToCopy / MCUX_CL_AES_BLOCK_SIZE;
                        MCUX_CSSL_FP_FUNCTION_CALL(aadBlkAuthRet, pContext->mode->pEngine(session, pContext,
                                                                               pAad,
                                                                               adataBlocks * MCUX_CL_AES_BLOCK_SIZE,
                                                                               NULL,
                                                                               NULL,
                                                                               MCUXCLAEAD_ENGINE_OPTION_AUTH));

                        if(MCUXCLAEAD_STATUS_OK != aadBlkAuthRet)
                        {
                            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
                        }
                        pAad += adataBlocks * MCUX_CL_AES_BLOCK_SIZE;

                        lenToCopy -= (adataBlocks * MCUX_CL_AES_BLOCK_SIZE);
                    }

                    if(0u != lenToCopy)
                    {
                        forthAadFpFlag = 1u;
                        //copy remaining data into partialData
                        MCUX_CSSL_FP_FUNCTION_CALL(cpyAadReRet, mcuxClMemory_copy(pContext->partialData,
                                                                   pAad,
                                                                   lenToCopy,
                                                                   lenToCopy));
                        if (0u != cpyAadReRet)
                        {
                            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
                        }
                        pContext->partialDataLength = lenToCopy;
                    }
                }
                else
                {
                    mainAadFpFlag = 1u;
                    //bytes in buffer and new adata is less then blockSize - save data into partialData
                    MCUX_CSSL_FP_FUNCTION_CALL(cpyAadReResult, mcuxClMemory_copy(&pContext->partialData[pContext->partialDataLength],
                                                                   pAdata,
                                                                   lenToCopy,
                                                                   lenToCopy));
                    if (cpyAadReResult != 0u)
                    {
                        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
                    }
                    pContext->partialDataLength += lenToCopy;
                }
            }

            //update adata size to processedDataLength in ctx
            pContext->processedDataLength += adataLength;//The processedDataLength add the length of each processing

            //Check if we done all adata and if we have some remaining data in buffer, this is for
            //the last adata block processing, add zero padding and calc pretag
            if((pContext->processedDataLength == pContext->aadLength) && (0u != pContext->partialDataLength))
            {
                fifthAadFpFlag = 1u;
                /* Apply the padding function specified in the mode on the partial data. */
                MCUX_CSSL_FP_FUNCTION_CALL(aadPaddResult, mcuxClMemory_set(&pContext->partialData[pContext->partialDataLength],
                                                                 0x00u,
                                                                 MCUX_CL_AES_BLOCK_SIZE - pContext->partialDataLength,
                                                                 MCUX_CL_AES_BLOCK_SIZE - pContext->partialDataLength));

                if (0u != aadPaddResult)
                {
                    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
                }
                //Process remaining adata and create pretag
                MCUX_CSSL_FP_FUNCTION_CALL(aadPadAuthRet, pContext->mode->pEngine(session, pContext,
                                                                       pContext->partialData,
                                                                       MCUX_CL_AES_BLOCK_SIZE,
                                                                       NULL,
                                                                       NULL,
                                                                       MCUXCLAEAD_ENGINE_OPTION_AUTH));

                if(MCUXCLAEAD_STATUS_OK != aadPadAuthRet)
                {
                    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
                }
                pContext->partialDataLength = 0u;
            }
    }

/*
        - Data processing (options == oneshot / update data)
            - if inLength != 0 add the new data from the input to partialData and process using pEngine(option: aead) if possible,
              adapt partialDataLength and processedDataLength (this will never be the case for oneshot)
            - process remaining complete blocks from the input using pEngine(option: aead), adapt processedDataLength
            - add remaining data to partialData, adapt partialDataLength and processedDataLength
            - [Assertion] aadLength + dataLength  <= processedDataLength
            - if aadLength + dataLength == processedDataLength padd partialData with zeros
              and process using pEngine(option: auth+enc), set partialDataLength to zero
*/
    //below variable definitions are used for flow protection of plaintext data process
    uint32_t mainProFpFlag = 0u;
    uint32_t secondProFpFlag = 0u;
    uint32_t thirdProFpFlag = 0u;
    uint32_t forthProFpFlag = 0u;
    uint8_t *pOutput = pOut;
    //below variable definitions are used for flow protection of final one block process
    uint32_t mainFinFpFlag = 0u;

    if ((options == MCUXCLAEAD_OPTION_ONESHOT) || (options == MCUXCLAEAD_OPTION_PROCESS))
    {
        if(0u != inLength)
        {
            uint8_t const* pInput = (uint8_t const*)pIn;
            if((pContext->partialDataLength + inLength) >= MCUX_CL_AES_BLOCK_SIZE)
            {
                 mainProFpFlag = 1u;
                 MCUX_CSSL_FP_FUNCTION_CALL(inCpyRet, mcuxClMemory_copy(&pContext->partialData[pContext->partialDataLength],
                                                                   pInput,
                                                                   MCUX_CL_AES_BLOCK_SIZE - pContext->partialDataLength,
                                                                   MCUX_CL_AES_BLOCK_SIZE - pContext->partialDataLength));

                if (inCpyRet != 0u)
                {
                    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
                }
                pInput += MCUX_CL_AES_BLOCK_SIZE - pContext->partialDataLength;
                inLength -= (MCUX_CL_AES_BLOCK_SIZE - pContext->partialDataLength);
                //update processed input data length to processedDataLength
                pContext->processedDataLength += (MCUX_CL_AES_BLOCK_SIZE - pContext->partialDataLength);
                pContext->partialDataLength = 0u;

                MCUX_CSSL_FP_FUNCTION_CALL(inAeadRet, pContext->mode->pEngine(session, pContext,
                                                                           pContext->partialData,
                                                                           MCUX_CL_AES_BLOCK_SIZE,
                                                                           pOutput,
                                                                           NULL,
                                                                           MCUXCLAEAD_ENGINE_OPTION_AEAD));

                if(MCUXCLAEAD_STATUS_OK != inAeadRet)
                {
                    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
                }

                pOutput +=  MCUX_CL_AES_BLOCK_SIZE;
                *pOutLength += MCUX_CL_AES_BLOCK_SIZE;

                if(inLength >= MCUX_CL_AES_BLOCK_SIZE)
                {
                    secondProFpFlag = 1u;
                    uint32_t inputBlocks = inLength / MCUX_CL_AES_BLOCK_SIZE;

                    MCUX_CSSL_FP_FUNCTION_CALL(inBlkAeadRet, pContext->mode->pEngine(session, pContext,
                                                                           pInput,
                                                                           inputBlocks * MCUX_CL_AES_BLOCK_SIZE,
                                                                           pOutput,
                                                                           NULL,
                                                                           MCUXCLAEAD_ENGINE_OPTION_AEAD));

                    if(MCUXCLAEAD_STATUS_OK != inBlkAeadRet)
                    {
                        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
                    }

                    pInput += inputBlocks * MCUX_CL_AES_BLOCK_SIZE;
                    inLength -= inputBlocks * MCUX_CL_AES_BLOCK_SIZE;
                    //update processed input data length to processedDataLength
                    pContext->processedDataLength += inputBlocks * MCUX_CL_AES_BLOCK_SIZE;
                    pOutput += inputBlocks * MCUX_CL_AES_BLOCK_SIZE;
                    *pOutLength += inputBlocks * MCUX_CL_AES_BLOCK_SIZE;
                }

                if(0u != inLength)
                {
                    thirdProFpFlag = 1u;
                    //copy remaining data into blockBuffer
                    MCUX_CSSL_FP_FUNCTION_CALL(inRmCpyRet, mcuxClMemory_copy(pContext->partialData,
                                                                   pInput,
                                                                   inLength,
                                                                   inLength));

                    if (inRmCpyRet != 0u)
                    {
                        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
                    }
                    pContext->partialDataLength = inLength;
                    //update processed input data length to processedDataLength
                    pContext->processedDataLength += inLength;
                }
            }
            else
            {
                forthProFpFlag = 1u;
                //bytes in buffer and new adata is less then blockSize - save data into partialData
                MCUX_CSSL_FP_FUNCTION_CALL(inCpyRet, mcuxClMemory_copy(&pContext->partialData[pContext->partialDataLength],
                                                                   pIn,
                                                                   inLength,
                                                                   inLength));

                if (inCpyRet != 0u)
                {
                    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
                }
                pContext->partialDataLength += inLength;
                //update processed input data length to processedDataLength
                pContext->processedDataLength += inLength;
            }
        }

        //Check if we done all input data and if we have some remaining data in buffer, this is for
        //the last input data block processing, add zero padding and calc final tag
        if((pContext->processedDataLength == pContext->dataLength + pContext->aadLength) && (0u != pContext->partialDataLength))
        {
            mainFinFpFlag = 1u;
            MCUX_CSSL_FP_FUNCTION_CALL(inPaddRet, mcuxClMemory_set(&pContext->partialData[pContext->partialDataLength],
                                                                 0x00u,
                                                                 MCUX_CL_AES_BLOCK_SIZE - pContext->partialDataLength,
                                                                 MCUX_CL_AES_BLOCK_SIZE - pContext->partialDataLength));

            if (0u != inPaddRet)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
            }
            //This last block length less then MCUX_CL_AES_BLOCK_SIZE, so can't directly write result to pOut
            //&pContext->state[16] have not been used, so can re-write it to store the CTR result
            MCUX_CSSL_FP_FUNCTION_CALL(inPaddEncRet, pContext->mode->pEngine(session, pContext,
                                                                               pContext->partialData,
                                                                               MCUX_CL_AES_BLOCK_SIZE,
                                                                               &pContext->state[16],
                                                                               NULL,
                                                                               MCUXCLAEAD_ENGINE_OPTION_ENC));

            if(MCUXCLAEAD_STATUS_OK != inPaddEncRet)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
            }

            /* Copy the padding to the output and update pOutLength accordingly. */
            MCUX_CSSL_FP_FUNCTION_CALL(outCpyRet, mcuxClMemory_copy(pOutput,
                                                               &pContext->state[16],
                                                               pContext->partialDataLength,
                                                               MCUX_CL_AES_BLOCK_SIZE));

            if (outCpyRet != 0u)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
            }

            *pOutLength += pContext->partialDataLength;

            if(MCUXCLCSS_AEAD_ENCRYPT == pContext->mode->direction)
            {
                //Process remaining data and create pretag
                MCUX_CSSL_FP_FUNCTION_CALL(inPaddAuthRet, pContext->mode->pEngine(session, pContext,
                                                                               pContext->partialData,
                                                                               MCUX_CL_AES_BLOCK_SIZE,
                                                                               NULL,
                                                                               NULL,
                                                                               MCUXCLAEAD_ENGINE_OPTION_AUTH));

                if(MCUXCLAEAD_STATUS_OK != inPaddAuthRet)
                {
                    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
                }
             }
            else
            {
                //Process remaining data and create pretag
                MCUX_CSSL_FP_FUNCTION_CALL(outPaddRet, mcuxClMemory_set(&pContext->state[16u + pContext->partialDataLength],
                                                                 0x00u,
                                                                 MCUX_CL_AES_BLOCK_SIZE - pContext->partialDataLength,
                                                                 MCUX_CL_AES_BLOCK_SIZE - pContext->partialDataLength));

                if (0u != outPaddRet)
                {
                    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
                }
                MCUX_CSSL_FP_FUNCTION_CALL(inPaddAuthRet, pContext->mode->pEngine(session, pContext,
                                                                               &pContext->state[16],
                                                                               MCUX_CL_AES_BLOCK_SIZE,
                                                                               NULL,
                                                                               NULL,
                                                                               MCUXCLAEAD_ENGINE_OPTION_AUTH));

                if(MCUXCLAEAD_STATUS_OK != inPaddAuthRet)
                {
                    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
                }
            }
            pContext->partialDataLength = 0u;
        }

    }

/*
        - Finalization processing (options == oneshot / finish / verify)
            - if partialDataLength != 0 exit with ERROR
            - reset counter value to 'zero' (leaving the other fields intact)
            - process the CBC-MAC state with pEngine(option: enc), and store the result in partialData
*/

    if ((options == MCUXCLAEAD_OPTION_ONESHOT) || (options == MCUXCLAEAD_OPTION_FINISH) || (options == MCUXCLAEAD_OPTION_VERIFY))
    {


        if (0u != pContext->partialDataLength)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
        }

        //reset counter value to 'zero' (leaving the other fields intact)
        MCUX_CSSL_FP_FUNCTION_CALL(ctrCpyRet, mcuxClMemory_copy(&pContext->state[48],
                                                              &pContext->state[32],
                                                              MCUX_CL_AES_BLOCK_SIZE,
                                                              MCUX_CL_AES_BLOCK_SIZE));

        if (ctrCpyRet != 0u)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
        }

        //Encrypt pretag with counter0 to get final tag
        MCUX_CSSL_FP_FUNCTION_CALL(finalTagEncRet, pContext->mode->pEngine(session, pContext,
                                                                           pContext->state,
                                                                           MCUX_CL_AES_BLOCK_SIZE,
                                                                           pContext->partialData,
                                                                           NULL,
                                                                           MCUXCLAEAD_ENGINE_OPTION_ENC));

        if(MCUXCLAEAD_STATUS_OK != finalTagEncRet)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
        }
    }

/*
        - Finalization processing (options == oneshot / finish)
            - copy tagLength bytes from partialData to the tag
            - clean up context
*/
    if ((options == MCUXCLAEAD_OPTION_ONESHOT) || (options == MCUXCLAEAD_OPTION_FINISH))
    {
        MCUX_CSSL_FP_FUNCTION_CALL(tagFinalRet, mcuxClMemory_copy(pTag,
                                                               pContext->partialData,
                                                               pContext->tagLength,
                                                               pContext->tagLength));

        if (tagFinalRet != 0u)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
        }

        //Clear Ctx content
        //it will still be used, so can't clear in this step
        // MCUX_CSSL_FP_FUNCTION_CALL(ctxClearRet, mcuxClMemory_set((uint8_t *)pContext,
                                                             // 0x00u,
                                                             // sizeof(mcuxClAead_Context_t),
                                                             // sizeof(mcuxClAead_Context_t)));

        // if (0u != ctxClearRet)
        // {
            // MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
        // }

    }

/*
        - Finalization processing (options == verify)
            - compare tagLength bytes from partialData to the tag
            - clean up context

        - exit
*/
    if (options == MCUXCLAEAD_OPTION_VERIFY)
    {
        MCUX_CSSL_FP_FUNCTION_CALL(compare_result, mcuxCsslMemory_Compare(mcuxCsslParamIntegrity_Protect(3u, pTag, pContext->partialData, pContext->tagLength),
                                                                      pTag,
                                                                      pContext->partialData,
                                                                      pContext->tagLength));

        if(compare_result != MCUXCSSLMEMORY_STATUS_EQUAL)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
        }

        //Clear Ctx content
        //it will still be used, so can't clear in this step
        // MCUX_CSSL_FP_FUNCTION_CALL(ctxClearRet, mcuxClMemory_set((uint8_t *)pContext,
                                                             // 0x00u,
                                                             // sizeof(mcuxClAead_Context_t),
                                                             // sizeof(mcuxClAead_Context_t)));

        // if (0u != ctxClearRet)
        // {
            // MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_ERROR);
        // }
    }

    /* Exit and balance the flow protection. */
    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClAead_ModeSkeletonAesCcm, MCUXCLAEAD_STATUS_OK, MCUXCLAEAD_STATUS_FAULT_ATTACK,
        MCUX_CSSL_FP_CONDITIONAL((((options == MCUXCLAEAD_OPTION_ONESHOT) || (options == MCUXCLAEAD_OPTION_PROCESS_AAD))),
            MCUX_CSSL_FP_CONDITIONAL((secondAadFpFlag == 1u), MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                                                             pContext->mode->protection_token_engine,
                MCUX_CSSL_FP_CONDITIONAL((thirdAadFpFlag == 1u),pContext->mode->protection_token_engine
                ),
                MCUX_CSSL_FP_CONDITIONAL((forthAadFpFlag == 1u),MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy)
                )
            ),
            MCUX_CSSL_FP_CONDITIONAL((mainAadFpFlag == 1u),MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy)
            ),
            MCUX_CSSL_FP_CONDITIONAL((fifthAadFpFlag == 1u),MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
                                                           pContext->mode->protection_token_engine
            )
        ),
        MCUX_CSSL_FP_CONDITIONAL((((options == MCUXCLAEAD_OPTION_ONESHOT) || (options == MCUXCLAEAD_OPTION_PROCESS))),
            MCUX_CSSL_FP_CONDITIONAL((mainProFpFlag == 1u), MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                                                           pContext->mode->protection_token_engine,
                MCUX_CSSL_FP_CONDITIONAL((secondProFpFlag == 1u),pContext->mode->protection_token_engine
                ),
                MCUX_CSSL_FP_CONDITIONAL((thirdProFpFlag == 1u),MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy)
                )
            ),
            MCUX_CSSL_FP_CONDITIONAL((forthProFpFlag == 1u),MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy)
            ),
            MCUX_CSSL_FP_CONDITIONAL((mainFinFpFlag == 1u),MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
                                                          pContext->mode->protection_token_engine,
                                                          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                                                          pContext->mode->protection_token_engine,
                MCUX_CSSL_FP_CONDITIONAL((MCUXCLCSS_AEAD_DECRYPT == pContext->mode->direction),MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set)
                )
            )
        ),
        MCUX_CSSL_FP_CONDITIONAL((((options == MCUXCLAEAD_OPTION_ONESHOT) || (options == MCUXCLAEAD_OPTION_FINISH) || (options == MCUXCLAEAD_OPTION_VERIFY))),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
            pContext->mode->protection_token_engine
        ),
        MCUX_CSSL_FP_CONDITIONAL((((options == MCUXCLAEAD_OPTION_ONESHOT) || (options == MCUXCLAEAD_OPTION_FINISH))),
            //MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy)
        ),
        MCUX_CSSL_FP_CONDITIONAL(((options == MCUXCLAEAD_OPTION_VERIFY)),
            //MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Compare)
        )
    );
}

