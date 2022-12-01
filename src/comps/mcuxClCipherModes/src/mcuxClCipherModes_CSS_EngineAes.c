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

/** @file  mcuxClCipherModes_EngineCss.c
 *  @brief implementation of the Engine functions of the mcuxClCipher component */

#include <mcuxClCss.h>
#include <mcuxClMemory.h>
#include <mcuxClSession.h>
#include <internal/mcuxClPadding_Internal.h>
#include <mcuxClKey.h>
#include <internal/mcuxClKey_Internal.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <mcuxClAes.h>
#include <internal/mcuxClCipher_Internal.h>
#include <internal/mcuxClCipherModes_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCipherModes_EngineCss)
  MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCipher_Status_t) mcuxClCipherModes_EngineCss(
  mcuxClSession_Handle_t session,
  mcuxClCipherModes_Context_Aes_Css_t * const pContext,
  mcuxCl_InputBuffer_t pIn,
  uint32_t inLength,
  mcuxCl_Buffer_t pOut
)
{
    /* [Design]

        - Preconditions
            - mode and state in context have been initialized
            - inLength is a multiple of the block size (16 bytes)

        - Operation
            - set cssOptions according to mode's required operations
            - if (CBC Decryption) : copy last input block to temporary buffer
            - perform the required operation by calling mcuxClCss_Cipher_Async
            - if (CBC Encryption) : copy last output block to ivState
            - if (CBC Decryption) : copy temporary buffer to ivState

        - Exit
    */
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCipherModes_EngineCss);

    mcuxClCipherModes_Algorithm_Aes_Css_t pAlgo = (mcuxClCipherModes_Algorithm_Aes_Css_t) pContext->common.pMode->pAlgorithm;

    /* Initialize CSS key info based on the key in the context. */
    mcuxClCss_KeyIndex_t keyIdx = (mcuxClCss_KeyIndex_t) mcuxClKey_getLoadedKeySlot(pContext->pKey);
    uint8_t const * pKey = mcuxClKey_getLoadedKeyData(pContext->pKey);
    uint8_t tempBlock[MCUX_CL_AES_BLOCK_SIZE];
    uint8_t* nextState = NULL;
    uint32_t keyLength = mcuxClKey_getSize(pContext->pKey);

    /* Initialize CSS options. */
    mcuxClCss_CipherOption_t cssOptions;
    cssOptions.word.value = 0u;
    cssOptions.bits.dcrpt  = (uint8_t) pAlgo->direction;
    cssOptions.bits.cphmde = (uint8_t) pAlgo->mode;

    if(cssOptions.bits.cphmde != MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_ECB) {
        cssOptions.bits.cphsoe = MCUXCLCSS_CIPHER_STATE_OUT_ENABLE;
        #ifndef MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS
        cssOptions.bits.cphsie = MCUXCLCSS_CIPHER_STATE_IN_ENABLE;
        #endif /* MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS */
    }

    /* Copy last input block to a temp buffer to handle in-place operations. Needed in case of CBC Mode decryption */
    if(MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_CBC == cssOptions.bits.cphmde)
    {
        if (MCUXCLCSS_CIPHER_DECRYPT == pAlgo->direction)
        {
            MCUX_CSSL_FP_FUNCTION_CALL(copyState, mcuxClMemory_copy(tempBlock, (uint8_t const*)(pIn + inLength - MCUX_CL_AES_BLOCK_SIZE), MCUX_CL_AES_BLOCK_SIZE, MCUX_CL_AES_BLOCK_SIZE));
            if(copyState != 0U)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_EngineCss, MCUX_CL_CIPHER_STATUS_ERROR);
            }
            nextState = tempBlock;
        }
        else 
        {
            nextState = (uint8_t*)(pOut + inLength - MCUX_CL_AES_BLOCK_SIZE);
        }
    }
    if (MCUX_CL_KEY_LOADSTATUS_MEMORY == mcuxClKey_getLoadStatus(pContext->pKey))
    {
        cssOptions.bits.extkey = MCUXCLCSS_CIPHER_EXTERNAL_KEY;
    }
    else if (MCUX_CL_KEY_LOADSTATUS_COPRO == mcuxClKey_getLoadStatus(pContext->pKey))
    {
        cssOptions.bits.extkey = MCUXCLCSS_CIPHER_INTERNAL_KEY;
    }
    else
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_EngineCss, MCUX_CL_CIPHER_STATUS_ERROR);
    }

    MCUX_CSSL_FP_FUNCTION_CALL(cipherResult, mcuxClCss_Cipher_Async(cssOptions,
                                                                  keyIdx,
                                                                  pKey,
                                                                  keyLength,
                                                                  pIn,
                                                                  inLength,
                                                                  (uint8_t *) pContext->ivState,
                                                                  pOut));
    if (cipherResult != MCUXCLCSS_STATUS_OK_WAIT)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_EngineCss, MCUX_CL_CIPHER_STATUS_ERROR);
    }
    MCUX_CSSL_FP_FUNCTION_CALL(wait1, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
    if (wait1 != MCUXCLCSS_STATUS_OK)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_EngineCss, MCUX_CL_CIPHER_STATUS_ERROR);
    }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
    MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult, mcuxClCss_CompareDmaFinalOutputAddress(pOut, inLength));
    if (MCUXCLCSS_STATUS_OK != addressComparisonResult)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_EngineCss, MCUX_CL_CIPHER_STATUS_ERROR);
    }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

    if(MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_CBC == cssOptions.bits.cphmde)
    {
        MCUX_CSSL_FP_FUNCTION_CALL(copyState, mcuxClMemory_copy((uint8_t *) pContext->ivState, nextState, MCUX_CL_AES_BLOCK_SIZE, MCUX_CL_AES_BLOCK_SIZE));
        if(copyState != 0U)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_EngineCss, MCUX_CL_CIPHER_STATUS_ERROR);
        }
    }
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCipherModes_EngineCss, MCUX_CL_CIPHER_STATUS_OK,
		MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
        MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN,
        MCUX_CSSL_FP_CONDITIONAL((MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_CBC == cssOptions.bits.cphmde),
                                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                                MCUX_CSSL_FP_CONDITIONAL((MCUXCLCSS_CIPHER_DECRYPT == pAlgo->direction),
                                                    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy))
                                ),
		MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cipher_Async));

}

const mcuxClCipherModes_AlgorithmDescriptor_Aes_Css_t mcuxClCipherModes_AlgorithmDescriptor_AES_ECB_Enc_NoPadding_Css = {
/* [Design]
    mcuxClCipherModes_ModeSkeletonAes
    mcuxClPadding_addPadding_None
    granularity = 16
*/
    .cryptEngine = mcuxClCipherModes_EngineCss,
    .addPadding = mcuxClPadding_addPadding_None,
    .protection_token_engine = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_EngineCss),
    .protection_token_addPadding = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_None),
    .mode = MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_ECB,
    .direction = MCUXCLCSS_CIPHER_ENCRYPT,
    .blockLength = MCUX_CL_AES_BLOCK_SIZE,
    .ivLength = 0u,
    .granularity = 16u
};

const mcuxClCipherModes_AlgorithmDescriptor_Aes_Css_t mcuxClCipherModes_AlgorithmDescriptor_AES_ECB_Enc_PaddingISO9797_1_Method1_Css = {
/* [Design]
    mcuxClCipherModes_ModeSkeletonAes
    mcuxClPadding_addPadding_ISO9797_1_Method1
    granularity = 1
*/
    .cryptEngine = mcuxClCipherModes_EngineCss,
    .addPadding = mcuxClPadding_addPadding_ISO9797_1_Method1,
    .protection_token_engine = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_EngineCss),
    .protection_token_addPadding = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_ISO9797_1_Method1),
    .mode = MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_ECB,
    .direction = MCUXCLCSS_CIPHER_ENCRYPT,
    .blockLength = MCUX_CL_AES_BLOCK_SIZE,
    .ivLength = 0u,
    .granularity = 1u
};

const mcuxClCipherModes_AlgorithmDescriptor_Aes_Css_t mcuxClCipherModes_AlgorithmDescriptor_AES_ECB_Enc_PaddingISO9797_1_Method2_Css = {
/* [Design]
    mcuxClCipherModes_ModeSkeletonAes
    mcuxClPadding_addPadding_ISO9797_1_Method2
    granularity = 1
*/
    .cryptEngine = mcuxClCipherModes_EngineCss,
    .addPadding = mcuxClPadding_addPadding_ISO9797_1_Method2,
    .protection_token_engine = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_EngineCss),
    .protection_token_addPadding = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_ISO9797_1_Method2),
    .mode = MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_ECB,
    .direction = MCUXCLCSS_CIPHER_ENCRYPT,
    .blockLength = MCUX_CL_AES_BLOCK_SIZE,
    .ivLength = 0u,
    .granularity = 1u
};

const mcuxClCipherModes_AlgorithmDescriptor_Aes_Css_t mcuxClCipherModes_AlgorithmDescriptor_AES_ECB_Dec_Css = {
/* [Design]
    mcuxClCipherModes_ModeSkeletonAes
    mcuxClPadding_addPadding_None
    granularity = 16
*/
    .cryptEngine = mcuxClCipherModes_EngineCss,
    .addPadding = mcuxClPadding_addPadding_None,
    .protection_token_engine = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_EngineCss),
    .protection_token_addPadding = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_None),
    .mode = MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_ECB,
    .direction = MCUXCLCSS_CIPHER_DECRYPT,
    .blockLength = MCUX_CL_AES_BLOCK_SIZE,
    .ivLength = 0u,
    .granularity = 16u
};

const mcuxClCipherModes_AlgorithmDescriptor_Aes_Css_t mcuxClCipherModes_AlgorithmDescriptor_AES_CBC_Enc_NoPadding_Css = {
/* [Design]
    mcuxClCipherModes_ModeSkeletonAes
    mcuxClPadding_addPadding_None
    granularity = 16
*/
    .cryptEngine = mcuxClCipherModes_EngineCss,
    .addPadding = mcuxClPadding_addPadding_None,
    .protection_token_engine = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_EngineCss),
    .protection_token_addPadding = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_None),
    .mode = MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_CBC,
    .direction = MCUXCLCSS_CIPHER_ENCRYPT,
    .blockLength = MCUX_CL_AES_BLOCK_SIZE,
    .ivLength = MCUX_CL_AES_BLOCK_SIZE,
    .granularity = 16u
};

const mcuxClCipherModes_AlgorithmDescriptor_Aes_Css_t mcuxClCipherModes_AlgorithmDescriptor_AES_CBC_Enc_PaddingISO9797_1_Method1_Css = {
/* [Design]
    mcuxClCipherModes_ModeSkeletonAes
    mcuxClPadding_addPadding_ISO9797_1_Method1
    granularity = 1
*/
    .cryptEngine = mcuxClCipherModes_EngineCss,
    .addPadding = mcuxClPadding_addPadding_ISO9797_1_Method1,
    .protection_token_engine = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_EngineCss),
    .protection_token_addPadding = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_ISO9797_1_Method1),
    .mode = MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_CBC,
    .direction = MCUXCLCSS_CIPHER_ENCRYPT,
    .blockLength = MCUX_CL_AES_BLOCK_SIZE,
    .ivLength = MCUX_CL_AES_BLOCK_SIZE,
    .granularity = 1u
};

const mcuxClCipherModes_AlgorithmDescriptor_Aes_Css_t mcuxClCipherModes_AlgorithmDescriptor_AES_CBC_Enc_PaddingISO9797_1_Method2_Css = {
/* [Design]
    mcuxClCipherModes_ModeSkeletonAes
    mcuxClPadding_addPadding_ISO9797_1_Method2
    granularity = 1
*/
    .cryptEngine = mcuxClCipherModes_EngineCss,
    .addPadding = mcuxClPadding_addPadding_ISO9797_1_Method2,
    .protection_token_engine = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_EngineCss),
    .protection_token_addPadding = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_ISO9797_1_Method2),
    .mode = MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_CBC,
    .direction = MCUXCLCSS_CIPHER_ENCRYPT,
    .blockLength = MCUX_CL_AES_BLOCK_SIZE,
    .ivLength = MCUX_CL_AES_BLOCK_SIZE,
    .granularity = 1u
};

const mcuxClCipherModes_AlgorithmDescriptor_Aes_Css_t mcuxClCipherModes_AlgorithmDescriptor_AES_CBC_Dec_Css = {
/* [Design]
    mcuxClCipherModes_ModeSkeletonAes
    mcuxClPadding_addPadding_None
    granularity = 16
*/
    .cryptEngine = mcuxClCipherModes_EngineCss,
    .addPadding = mcuxClPadding_addPadding_None,
    .protection_token_engine = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_EngineCss),
    .protection_token_addPadding = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPadding_addPadding_None),
    .mode = MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_CBC,
    .direction = MCUXCLCSS_CIPHER_DECRYPT,
    .blockLength = MCUX_CL_AES_BLOCK_SIZE,
    .ivLength = MCUX_CL_AES_BLOCK_SIZE,
    .granularity = 16u
};

const mcuxClCipherModes_AlgorithmDescriptor_Aes_Css_t mcuxClCipherModes_AlgorithmDescriptor_AES_CTR_Css = {
/* [Design]
    mcuxClCipherModes_ModeSkeletonAes
    granularity = 1
*/
    .cryptEngine = mcuxClCipherModes_EngineCss,
    .addPadding = NULL,
    .protection_token_engine = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipherModes_EngineCss),
    .protection_token_addPadding = 0u,
    .mode = MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_CTR,
    .direction = MCUXCLCSS_CIPHER_ENCRYPT,
    .blockLength = MCUX_CL_AES_BLOCK_SIZE,
    .ivLength = MCUX_CL_AES_BLOCK_SIZE,
    .granularity = 1u
};
