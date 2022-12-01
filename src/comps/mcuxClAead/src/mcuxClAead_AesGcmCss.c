/*--------------------------------------------------------------------------*/
/* Copyright 2021-2022 NXP                                                  */
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

/** @file  mcuxClAead_AesGcmCss.c
 *  @brief implementation of the AES GCM Engine functions of the mcuxClAead component */

#include <mcuxClAead.h>
#include <internal/mcuxClAead_Internal_Types.h>
#include <internal/mcuxClAead_Internal_Functions.h>
#include <mcuxClMemory.h>
#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <internal/mcuxClKey_Internal.h>
#include <mcuxCsslMemory.h>
#include <mcuxCsslParamIntegrity.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCss.h>
#include <internal/mcuxClPadding_Internal.h>
#include <mcuxClAes.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAead_ModeEngineAesGcmCss)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t) mcuxClAead_ModeEngineAesGcmCss (
  mcuxClSession_Handle_t session,
  mcuxClAead_Context_t * const pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_Buffer_t pOut,
  uint32_t * const pOutLength,
  uint32_t options  //!< options is a bitmask with one bit reserved for each of the operations
  )
{
    /* [Design]

        - Note:
            - options is a bitmask:  1: aad, 2: iv, 4: data, 8: finish

        - Preconditions
            - mode in context has been initialized
            - inLength is a multiple of the block size (16 bytes)

        - IV (options == iv)
            - if(options == finish), the IV final process
            - or use CSS in auth cipher mode initialize stage to create the partial starting counter state J0

        - AAD (options == aad)
            - use CSS in auth cipher mode AAD stage to create the starting tag

        - DATA (options == data)
            - use CSS in auth cipher mode Process message stage to output the processed text to pOut and update the tag to state of Context

        - FINAL  (options == finish)
            - use CSS in auth cipher mode Final stage to create the final tag to pOut

        - exit
    */

    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAead_ModeEngineAesGcmCss);

    /* Initialize CSS key info based on the key in the context. */
    mcuxClCss_KeyIndex_t keyIdx = (mcuxClCss_KeyIndex_t) mcuxClKey_getLoadedKeySlot(pContext->key);
    uint8_t const * pKey = mcuxClKey_getLoadedKeyData(pContext->key);
    uint32_t keyLength = mcuxClKey_getSize(pContext->key);

    /* Initialize CSS options. */
    mcuxClCss_AeadOption_t cssOptions;
    cssOptions.word.value = 0u;
    cssOptions.bits.dcrpt  = (uint8_t)pContext->mode->direction;
    cssOptions.bits.acpsie = (uint8_t)MCUXCLCSS_AEAD_STATE_IN_ENABLE;
    cssOptions.bits.lastinit = (uint8_t)MCUXCLCSS_AEAD_LASTINIT_FALSE;

    if (MCUX_CL_KEY_LOADSTATUS_MEMORY == mcuxClKey_getLoadStatus(pContext->key))
    {
        cssOptions.bits.extkey = MCUXCLCSS_CIPHER_EXTERNAL_KEY;
    }
    else if (MCUX_CL_KEY_LOADSTATUS_COPRO == mcuxClKey_getLoadStatus(pContext->key))
    {
        cssOptions.bits.extkey = MCUXCLCSS_CIPHER_INTERNAL_KEY;
    }
    else
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesGcmCss, MCUXCLAEAD_STATUS_ERROR);
    }

    if(0u != (options & MCUXCLAEAD_ENGINE_OPTION_IV_MASK))
    {
        if((options & MCUXCLAEAD_ENGINE_OPTION_IV_MASK) == MCUXCLAEAD_ENGINE_OPTION_IV_FINAL)
        {
            /* Disable state input for one-time init */
            cssOptions.bits.acpsie = MCUXCLCSS_AEAD_STATE_IN_DISABLE;

            MCUX_CSSL_FP_FUNCTION_CALL(retInit, mcuxClCss_Aead_Init_Async(cssOptions,
                                                                        keyIdx,
                                                                        pKey,
                                                                        keyLength,
                                                                        pIn,
                                                                        inLength,
                                                                        pContext->state));

            if (MCUXCLCSS_STATUS_OK_WAIT != retInit)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesGcmCss, MCUXCLAEAD_STATUS_ERROR);
            }
            MCUX_CSSL_FP_FUNCTION_CALL(ivWaitRet, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
            
#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
        MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult, mcuxClCss_CompareDmaFinalOutputAddress((uint8_t*)pContext->state, MCUXCLAEAD_DMA_STEP));

        if (MCUXCLCSS_STATUS_OK != addressComparisonResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesCcmCss, MCUXCLAEAD_STATUS_ERROR);
        }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

            if (MCUXCLCSS_STATUS_OK != ivWaitRet)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesGcmCss, MCUXCLAEAD_STATUS_ERROR);
            }
        }
        else
        {
            if((options & MCUXCLAEAD_ENGINE_OPTION_IV_PARTIAL_START) == MCUXCLAEAD_ENGINE_OPTION_IV_PARTIAL_START)
            {
                /* Disable state input for first partial init */
                cssOptions.bits.acpsie = MCUXCLCSS_AEAD_STATE_IN_DISABLE;
            }

            if((options & MCUXCLAEAD_ENGINE_OPTION_IV_FINAL) == MCUXCLAEAD_ENGINE_OPTION_IV_FINAL)
            {
                /* Enable lastinit for final partial init */
                cssOptions.bits.lastinit = (uint8_t)MCUXCLCSS_AEAD_LASTINIT_TRUE;
            }

            MCUX_CSSL_FP_FUNCTION_CALL(retInitPartial, mcuxClCss_Aead_PartialInit_Async(cssOptions,
                                                                                      keyIdx,
                                                                                      pKey,
                                                                                      keyLength,
                                                                                      pIn,
                                                                                      inLength,
                                                                                      pContext->state));

            if(MCUXCLCSS_STATUS_OK_WAIT != retInitPartial)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesGcmCss, MCUXCLAEAD_STATUS_ERROR);
            }

            MCUX_CSSL_FP_FUNCTION_CALL(ivWaitRet, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

            if (MCUXCLCSS_STATUS_OK != ivWaitRet)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesGcmCss, MCUXCLAEAD_STATUS_ERROR);
            }

            
#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
        MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult, mcuxClCss_CompareDmaFinalOutputAddress((uint8_t*)pContext->state, MCUXCLAEAD_DMA_STEP));

        if (MCUXCLCSS_STATUS_OK != addressComparisonResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesGcmCss, MCUXCLAEAD_STATUS_ERROR);
        }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */
        }
    }

    if((options & MCUXCLAEAD_ENGINE_OPTION_AAD) == MCUXCLAEAD_ENGINE_OPTION_AAD)
    {
        MCUX_CSSL_FP_FUNCTION_CALL(ret_updateAad, mcuxClCss_Aead_UpdateAad_Async(cssOptions,
                                                                               keyIdx,
                                                                               pKey,
                                                                               keyLength,
                                                                               pIn,
                                                                               inLength,
                                                                               pContext->state));

        if (ret_updateAad != MCUXCLCSS_STATUS_OK_WAIT)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesGcm, MCUXCLAEAD_STATUS_ERROR);
        }

        MCUX_CSSL_FP_FUNCTION_CALL(aadWait, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

        if (aadWait != MCUXCLCSS_STATUS_OK)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeSkeletonAesGcm, MCUXCLAEAD_STATUS_ERROR);
        }

        
#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
        MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult, mcuxClCss_CompareDmaFinalOutputAddress((uint8_t*)pContext->state  , MCUXCLAEAD_DMA_STEP));

        if (MCUXCLCSS_STATUS_OK != addressComparisonResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesGcmCss, MCUXCLAEAD_STATUS_ERROR);
        }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */
    }

    if(0u != (options & MCUXCLAEAD_ENGINE_OPTION_DATA_MASK))
    {
        if(((options & MCUXCLAEAD_ENGINE_OPTION_DATA_FINAL) == MCUXCLAEAD_ENGINE_OPTION_DATA_FINAL)
            && (MCUX_CL_AES_BLOCK_SIZE != pContext->partialDataLength))
        {
            /* Enable special processing for final, partial block */
            cssOptions.bits.msgendw = (uint8_t)pContext->partialDataLength;
        }

        MCUX_CSSL_FP_FUNCTION_CALL(ret_updateData, mcuxClCss_Aead_UpdateData_Async(cssOptions,
                                                                                 keyIdx,
                                                                                 pKey,
                                                                                 keyLength,
                                                                                 pIn,
                                                                                 inLength,
                                                                                 pOut,
                                                                                 pContext->state));

        if (ret_updateData != MCUXCLCSS_STATUS_OK_WAIT)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesGcmCss, MCUXCLAEAD_STATUS_ERROR);
        }

        MCUX_CSSL_FP_FUNCTION_CALL(waitData, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

        if (waitData != MCUXCLCSS_STATUS_OK)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesGcmCss, MCUXCLAEAD_STATUS_ERROR);
        }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
        MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult, mcuxClCss_CompareDmaFinalOutputAddress((uint8_t*)pContext->state  , MCUXCLAEAD_DMA_STEP));

        if (MCUXCLCSS_STATUS_OK != addressComparisonResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesGcmCss, MCUXCLAEAD_STATUS_ERROR);
        }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

    }

    if((options & MCUXCLAEAD_ENGINE_OPTION_FINISH) == MCUXCLAEAD_ENGINE_OPTION_FINISH)
    {
        MCUX_CSSL_FP_FUNCTION_CALL(ret_finish, mcuxClCss_Aead_Finalize_Async(cssOptions,
                                                                           keyIdx,
                                                                           pKey,
                                                                           keyLength,
                                                                           pContext->aadLength,
                                                                           pContext->dataLength,
                                                                           pOut,
                                                                           pContext->state));

        if (ret_finish != MCUXCLCSS_STATUS_OK_WAIT)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesGcmCss, MCUXCLAEAD_STATUS_ERROR);
        }

        MCUX_CSSL_FP_FUNCTION_CALL(waitFinish, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

        if (waitFinish != MCUXCLCSS_STATUS_OK)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesGcmCss, MCUXCLAEAD_STATUS_ERROR);
        }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
        MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult, mcuxClCss_CompareDmaFinalOutputAddress((uint8_t*)pOut  , MCUXCLCSS_AEAD_TAG_SIZE));

        if (MCUXCLCSS_STATUS_OK != addressComparisonResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesGcmCss, MCUXCLAEAD_STATUS_ERROR);
        }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

    }

    /* Exit and balance the flow protection. */
    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClAead_ModeEngineAesGcmCss, MCUXCLAEAD_STATUS_OK, MCUXCLAEAD_STATUS_FAULT_ATTACK,
        MCUX_CSSL_FP_CONDITIONAL(((options & MCUXCLAEAD_ENGINE_OPTION_IV_MASK) == MCUXCLAEAD_ENGINE_OPTION_IV_FINAL),
                                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Aead_Init_Async),
                                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
                                                                        MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN
        ),
        MCUX_CSSL_FP_CONDITIONAL(((options & MCUXCLAEAD_ENGINE_OPTION_IV_PARTIAL_START) == MCUXCLAEAD_ENGINE_OPTION_IV_PARTIAL_START)
                                 || ((options & MCUXCLAEAD_ENGINE_OPTION_IV_PARTIAL_CONT) == MCUXCLAEAD_ENGINE_OPTION_IV_PARTIAL_CONT),
                                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Aead_PartialInit_Async),
                                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
                                                                        MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN
        ),
        MCUX_CSSL_FP_CONDITIONAL(((options & MCUXCLAEAD_ENGINE_OPTION_AAD) == MCUXCLAEAD_ENGINE_OPTION_AAD),
                                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Aead_UpdateAad_Async),
                                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
                                                                        MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN
        ),
        MCUX_CSSL_FP_CONDITIONAL((0u != (options & MCUXCLAEAD_ENGINE_OPTION_DATA_MASK)),
                                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Aead_UpdateData_Async),
                                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
                                                                        MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN
        ),
        MCUX_CSSL_FP_CONDITIONAL(((options & MCUXCLAEAD_ENGINE_OPTION_FINISH) == MCUXCLAEAD_ENGINE_OPTION_FINISH),
                                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Aead_Finalize_Async),
                                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
                                                                        MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN
        )
    );
}

const mcuxClAead_ModeDescriptor_t mcuxClAead_ModeDescriptor_AES_GCM_ENC = {
    .pSkeleton = mcuxClAead_ModeSkeletonAesGcm,
    .pEngine = mcuxClAead_ModeEngineAesGcmCss,
    .protection_token_skeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_ModeSkeletonAesGcm),
    .protection_token_engine = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_ModeEngineAesGcmCss),
    .direction = MCUXCLCSS_AEAD_ENCRYPT
};

const mcuxClAead_ModeDescriptor_t mcuxClAead_ModeDescriptor_AES_GCM_DEC = {
    .pSkeleton = mcuxClAead_ModeSkeletonAesGcm,
    .pEngine = mcuxClAead_ModeEngineAesGcmCss,
    .protection_token_skeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_ModeSkeletonAesGcm),
    .protection_token_engine = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_ModeEngineAesGcmCss),
    .direction = MCUXCLCSS_AEAD_DECRYPT
};
