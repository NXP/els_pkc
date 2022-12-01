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

/** @file  mcuxClAead_AesCcmCss.c
 *  @brief implementation of the AES CCM Engine functions of the mcuxClAead component */

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


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClAead_ModeEngineAesCcmCss)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClAead_Status_t) mcuxClAead_ModeEngineAesCcmCss (
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
            - options is a bitmask:  1: auth, 2: enc, 3: aead, 4: init, 8: finish
            - processing is done in this particular order such that in-place encryption/decryption is supported

        - Preconditions
            - mode in context has been initialized
            - inLength is a multiple of the block size (16 bytes)

        - Initialization
            - set pData equal to pIn

        - Decryption  (options == enc / aead AND direction = decryption)
            - set pData equal to pOut
            - use CSS in CTR mode to decrypt the data pIn and store the output at pOut

        - Authentication (options == auth / aead)
            - use CSS in CBC-MAC mode to update the state in the context with the contents of pData

        - Encryption  (options == enc / aead AND direction = encryption)
            - use CSS in CTR mode to encrypt the data pIn and store the output at pOut

        - exit
    */

    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClAead_ModeEngineAesCcmCss);

    /* Initialize CSS key info based on the key in the context. */
    mcuxClCss_KeyIndex_t keyIdx = (mcuxClCss_KeyIndex_t) mcuxClKey_getLoadedKeySlot(pContext->key);
    uint8_t const * pKey = mcuxClKey_getLoadedKeyData(pContext->key);
    uint32_t keyLength = mcuxClKey_getSize(pContext->key);

    /* Initialize CSS CMAC options. */
    mcuxClCss_CmacOption_t cmacOpt;
    cmacOpt.bits.initialize = MCUXCLCSS_CMAC_INITIALIZE_DISABLE;
    cmacOpt.bits.finalize = MCUXCLCSS_CMAC_FINALIZE_DISABLE;

    /* Initialize CSS Cipher options. */
    mcuxClCss_CipherOption_t cipherCssOpt;
    cipherCssOpt.word.value = 0u;
    cipherCssOpt.bits.dcrpt  = MCUXCLCSS_CIPHER_ENCRYPT;
    cipherCssOpt.bits.cphmde = MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_CTR;
    cipherCssOpt.bits.cphsoe = MCUXCLCSS_CIPHER_STATE_OUT_ENABLE;
    #ifndef MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS
    cipherCssOpt.bits.cphsie = MCUXCLCSS_CIPHER_STATE_IN_ENABLE;
    #endif /* MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS */

    // Get key location
    if(MCUX_CL_KEY_LOADSTATUS_MEMORY == mcuxClKey_getLoadStatus(pContext->key))
    {
        cmacOpt.bits.extkey = MCUXCLCSS_CMAC_EXTERNAL_KEY_ENABLE;
        cipherCssOpt.bits.extkey = MCUXCLCSS_CIPHER_EXTERNAL_KEY;
    }
    else if(MCUX_CL_KEY_LOADSTATUS_COPRO == mcuxClKey_getLoadStatus(pContext->key))
    {
        cmacOpt.bits.extkey = MCUXCLCSS_CMAC_EXTERNAL_KEY_DISABLE;
        cipherCssOpt.bits.extkey = MCUXCLCSS_CIPHER_INTERNAL_KEY;
    }
    else
    {
        // Error: no key loaded
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesCcmCss, MCUXCLAEAD_STATUS_ERROR);
    }

    if(options == MCUXCLAEAD_ENGINE_OPTION_INIT)
    {

    }

    if(((options & MCUXCLAEAD_ENGINE_OPTION_ENC) == MCUXCLAEAD_ENGINE_OPTION_ENC)
        && (MCUXCLCSS_AEAD_DECRYPT == pContext->mode->direction))
    {
        MCUX_CSSL_FP_FUNCTION_CALL(ctrRet, mcuxClCss_Cipher_Async(cipherCssOpt,
                                                               keyIdx,
                                                               pKey,
                                                               keyLength,
                                                               pIn,
                                                               inLength,
                                                               &pContext->state[48],
                                                               pOut));

        if(MCUXCLCSS_STATUS_OK_WAIT != ctrRet)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesCcmCss, MCUXCLAEAD_STATUS_ERROR);
        }

        MCUX_CSSL_FP_FUNCTION_CALL(ctrWaitRet, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

        if (MCUXCLCSS_STATUS_OK != ctrWaitRet)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesCcmCss, MCUXCLAEAD_STATUS_ERROR);
        }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK

        MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult, mcuxClCss_CompareDmaFinalOutputAddress(&pContext->state[48], MCUXCLCSS_CMAC_OUT_SIZE));

        if (MCUXCLCSS_STATUS_OK != addressComparisonResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesCcmCss, MCUXCLAEAD_STATUS_ERROR);
        }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */


    }

    if((options & MCUXCLAEAD_ENGINE_OPTION_AUTH) == MCUXCLAEAD_ENGINE_OPTION_AUTH)
    {
        if((options == MCUXCLAEAD_ENGINE_OPTION_AEAD) && (MCUXCLCSS_AEAD_DECRYPT == pContext->mode->direction))
        {
            MCUX_CSSL_FP_FUNCTION_CALL(cmacResult, mcuxClCss_Cmac_Async(cmacOpt,
                                                                     keyIdx,
                                                                     pKey,
                                                                     keyLength,
                                                                     pOut,
                                                                     inLength,
                                                                     pContext->state));

            if( MCUXCLCSS_STATUS_OK_WAIT != cmacResult)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesCcmCss, MCUXCLAEAD_STATUS_ERROR);
            }
        }
        else
        {
            MCUX_CSSL_FP_FUNCTION_CALL(cmacResult, mcuxClCss_Cmac_Async(cmacOpt,
                                                                      keyIdx,
                                                                      pKey,
                                                                      keyLength,
                                                                      pIn,
                                                                      inLength,
                                                                      pContext->state));
            if( MCUXCLCSS_STATUS_OK_WAIT != cmacResult)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesCcmCss, MCUXCLAEAD_STATUS_ERROR);
            }
        }

        MCUX_CSSL_FP_FUNCTION_CALL(cmacWaitResult, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

        if (MCUXCLCSS_STATUS_OK != cmacWaitResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesCcmCss, MCUXCLAEAD_STATUS_ERROR);
        }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
        MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult, mcuxClCss_CompareDmaFinalOutputAddress((uint8_t*)pContext->state, MCUXCLCSS_CMAC_OUT_SIZE));

        if (MCUXCLCSS_STATUS_OK != addressComparisonResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesCcmCss, MCUXCLAEAD_STATUS_ERROR);
        }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

        
    }

    if(((options & MCUXCLAEAD_ENGINE_OPTION_ENC) == MCUXCLAEAD_ENGINE_OPTION_ENC)
      && (MCUXCLCSS_AEAD_ENCRYPT == pContext->mode->direction))
    {
        MCUX_CSSL_FP_FUNCTION_CALL(ctrRet, mcuxClCss_Cipher_Async(cipherCssOpt,
                                                               keyIdx,
                                                               pKey,
                                                               keyLength,
                                                               pIn,
                                                               inLength,
                                                               &pContext->state[48],
                                                               pOut));

        if(MCUXCLCSS_STATUS_OK_WAIT != ctrRet)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesCcmCss, MCUXCLAEAD_STATUS_ERROR);
        }

        MCUX_CSSL_FP_FUNCTION_CALL(ctrWaitRet, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

        if (MCUXCLCSS_STATUS_OK != ctrWaitRet)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesCcmCss, MCUXCLAEAD_STATUS_ERROR);
        }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
        MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult, mcuxClCss_CompareDmaFinalOutputAddress(&pContext->state[48], MCUXCLCSS_CMAC_OUT_SIZE));

        if (MCUXCLCSS_STATUS_OK != addressComparisonResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClAead_ModeEngineAesCcmCss, MCUXCLAEAD_STATUS_ERROR);
        }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

    }

    /* Exit and balance the flow protection. */
    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClAead_ModeEngineAesCcmCss, MCUXCLAEAD_STATUS_OK, MCUXCLAEAD_STATUS_FAULT_ATTACK,
        MCUX_CSSL_FP_CONDITIONAL(((options & MCUXCLAEAD_ENGINE_OPTION_ENC) == MCUXCLAEAD_ENGINE_OPTION_ENC)
                                && (MCUXCLCSS_AEAD_DECRYPT == pContext->mode->direction),
                                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cipher_Async),
                                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
                                                                        MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN
        ),
        MCUX_CSSL_FP_CONDITIONAL(((options & MCUXCLAEAD_ENGINE_OPTION_AUTH) == MCUXCLAEAD_ENGINE_OPTION_AUTH),
                                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async),
                                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
                                                                        MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN
        ),
        MCUX_CSSL_FP_CONDITIONAL(((options & MCUXCLAEAD_ENGINE_OPTION_ENC) == MCUXCLAEAD_ENGINE_OPTION_ENC)
                                && (MCUXCLCSS_AEAD_ENCRYPT == pContext->mode->direction),
                                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cipher_Async),
                                                                        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
                                                                        MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN
        )
    );
}

const mcuxClAead_ModeDescriptor_t mcuxClAead_ModeDescriptor_AES_CCM_ENC = {
    .pSkeleton = mcuxClAead_ModeSkeletonAesCcm,
    .pEngine = mcuxClAead_ModeEngineAesCcmCss,
    .protection_token_skeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_ModeSkeletonAesCcm),
    .protection_token_engine = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_ModeEngineAesCcmCss),
    .direction = MCUXCLCSS_AEAD_ENCRYPT
};

const mcuxClAead_ModeDescriptor_t mcuxClAead_ModeDescriptor_AES_CCM_DEC = {
    .pSkeleton = mcuxClAead_ModeSkeletonAesCcm,
    .pEngine = mcuxClAead_ModeEngineAesCcmCss,
    .protection_token_skeleton = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_ModeSkeletonAesCcm),
    .protection_token_engine = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_ModeEngineAesCcmCss),
    .direction = MCUXCLCSS_AEAD_DECRYPT
};
