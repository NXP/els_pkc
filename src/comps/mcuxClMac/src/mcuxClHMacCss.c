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

/** @file  mcuxClHMacCss.c
 *  @brief implementation of the HMAC part of mcuxClMac component using CSS */

#include <toolchain.h>
#include <mcuxClMac.h>

#include <mcuxClCss.h>
#include <mcuxClCss_Hash.h>
#include <mcuxClCss_Hmac.h>
#include <mcuxClMemory.h>
#include <mcuxClKey.h>
#include <mcuxCsslFlowProtection.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClMac_Internal.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClMac_Internal_Constants.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMac_Engine_HMAC_Init)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_HMAC_Init(mcuxClMac_Context_t *pContext UNUSED_PARAM,
                                                                        const uint8_t *const pIn UNUSED_PARAM,
                                                                        uint32_t inLength UNUSED_PARAM,
                                                                        uint8_t *const pOut UNUSED_PARAM,
                                                                        uint32_t *const pOutLength UNUSED_PARAM)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMac_Engine_HMAC_Init);
  //HMAC doesn't support partial processing
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_HMAC_Init, MCUXCLMAC_ERRORCODE_ERROR);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMac_Engine_HMAC_Update)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_HMAC_Update(mcuxClMac_Context_t *pContext UNUSED_PARAM,
                                                                          const uint8_t *const pIn UNUSED_PARAM,
                                                                          uint32_t inLength UNUSED_PARAM,
                                                                          uint8_t *const pOut UNUSED_PARAM,
                                                                          uint32_t *const pOutLength UNUSED_PARAM)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMac_Engine_HMAC_Update);
  //HMAC doesn't support partial processing
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_HMAC_Update, MCUXCLMAC_ERRORCODE_ERROR);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMac_Engine_HMAC_Finalize)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_HMAC_Finalize(mcuxClMac_Context_t *pContext UNUSED_PARAM,
                                                                            const uint8_t *const pIn UNUSED_PARAM,
                                                                            uint32_t inLength UNUSED_PARAM,
                                                                            uint8_t *const pOut UNUSED_PARAM,
                                                                            uint32_t *const pOutLength UNUSED_PARAM)
{
  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMac_Engine_HMAC_Finalize);
  //HMAC doesn't support partial processing
  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_HMAC_Finalize, MCUXCLMAC_ERRORCODE_ERROR);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMac_Engine_HMAC_Oneshot)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_HMAC_Oneshot(mcuxClMac_Context_t *pContext,
                                                                           const uint8_t *const pIn,
                                                                           uint32_t inLength,
                                                                           uint8_t *const pOut,
                                                                           uint32_t *const pOutLength UNUSED_PARAM)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMac_Engine_HMAC_Oneshot,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set));

    size_t completeLen = (inLength / MCUXCLMAC_HASH_BLOCK_SIZE_SHA_256) * MCUXCLMAC_HASH_BLOCK_SIZE_SHA_256;
    size_t lastDataChunkLength = inLength - completeLen;
    size_t totalPaddingLength = 0u;

    /* MISRA Ex. 12 - Rule 11.8 */
    uint8_t *pDataIn = (uint8_t*) pIn;

    /* Apply padding to the input buffer */
    //caller needs to assure that the buffer is big enough

    //compute total padding length
    if((MCUXCLMAC_HASH_BLOCK_SIZE_SHA_256 - MCUXCL_HMAC_MIN_PADDING_LENGTH) < lastDataChunkLength)
    {
        totalPaddingLength = (2u * MCUXCLMAC_HASH_BLOCK_SIZE_SHA_256) - lastDataChunkLength;
    }
    else
    {
        totalPaddingLength = MCUXCLMAC_HASH_BLOCK_SIZE_SHA_256 - lastDataChunkLength;
    }
    pDataIn += inLength;

    //set 0x80 byte
    MCUX_CSSL_FP_FUNCTION_CALL(setResult1, mcuxClMemory_set(pDataIn, 0x80, 1u, 1u));
    if(0u != setResult1)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_HMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR);
    }

    //set 0x00 bytes (+3 0x00 bytes because inLength is only 32 bits while length field in padding is 64 bits
    MCUX_CSSL_FP_FUNCTION_CALL(setResult2, mcuxClMemory_set(pDataIn + 1,
                                                          0x00,
                                                          totalPaddingLength - MCUXCL_HMAC_MIN_PADDING_LENGTH + 1u + 3u,
                                                          totalPaddingLength - 1u));
    if(0u != setResult2)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_HMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set));
    }
    pDataIn += totalPaddingLength - 1u;

    //length of the unpadded message in bits
    //css requires that the length of the key is added as well
    uint64_t lengthField = (uint64_t) inLength + MCUXCLCSS_HMAC_PADDED_KEY_SIZE;

    *pDataIn-- = (uint8_t)(lengthField << 3);
    *pDataIn-- = (uint8_t)(lengthField >> 5);
    *pDataIn-- = (uint8_t)(lengthField >> 13);
    *pDataIn-- = (uint8_t)(lengthField >> 21);
    *pDataIn-- = (uint8_t)(lengthField >> 29);

    /* Set-up the HMAC CSS options */
    mcuxClCss_HmacOption_t hmac_options;
    hmac_options.word.value = 0u;

    if(MCUX_CL_KEY_LOADSTATUS_MEMORY == mcuxClKey_getLoadStatus(pContext->key))
    {
        hmac_options.bits.extkey = MCUXCLCSS_HMAC_EXTERNAL_KEY_ENABLE;

        /* Prepare the external HMAC key */
        MCUX_CSSL_FP_FUNCTION_CALL(prepareKeyResult, mcuxClMac_prepareHMACKey(pContext));

        if(MCUXCLMAC_ERRORCODE_OK != prepareKeyResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_HMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_prepareHMACKey),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set));
        }
    }
    else if(MCUX_CL_KEY_LOADSTATUS_COPRO == mcuxClKey_getLoadStatus(pContext->key))
    {
        hmac_options.bits.extkey = MCUXCLCSS_HMAC_EXTERNAL_KEY_DISABLE;
    }
    else
    {
        // error: no key loaded
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_HMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR);
    }

    MCUX_CSSL_FP_FUNCTION_CALL(result, mcuxClCss_Hmac_Async(
                          hmac_options,
                          (mcuxClCss_KeyIndex_t) (mcuxClKey_getLoadedKeySlot(pContext->key)),
                          (uint8_t const *) pContext->preparedHmacKey,
                          pIn,
                          inLength + totalPaddingLength,
                          pOut));

    if (MCUXCLCSS_STATUS_OK_WAIT != result)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_HMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
            MCUX_CSSL_FP_CONDITIONAL((MCUX_CL_KEY_LOADSTATUS_MEMORY == mcuxClKey_getLoadStatus(pContext->key)),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_prepareHMACKey)
            ),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Hmac_Async));
    }

    MCUX_CSSL_FP_FUNCTION_CALL(resultWait, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));

    if ((MCUXCLCSS_STATUS_OK != resultWait))
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_HMAC_Oneshot, MCUXCLMAC_ERRORCODE_ERROR,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
            MCUX_CSSL_FP_CONDITIONAL((MCUX_CL_KEY_LOADSTATUS_MEMORY == mcuxClKey_getLoadStatus(pContext->key)),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_prepareHMACKey)
            ),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Hmac_Async),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation));
    }

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
    if(NULL != pOut)
    {

        MCUX_CSSL_FP_FUNCTION_CALL(addressComparisonResult, mcuxClCss_CompareDmaFinalOutputAddress(pOut, MCUXCLCSS_HMAC_OUTPUT_SIZE));

        if (MCUXCLCSS_STATUS_OK != addressComparisonResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_Engine_HMAC_Oneshot, MCUXCLMAC_ERRORCODE_FAULT_ATTACK);
        }
    }
#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClMac_Engine_HMAC_Oneshot, MCUXCLMAC_ERRORCODE_OK, MCUXCLMAC_ERRORCODE_FAULT_ATTACK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
        MCUX_CSSL_FP_CONDITIONAL((MCUX_CL_KEY_LOADSTATUS_MEMORY == mcuxClKey_getLoadStatus(pContext->key)),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_prepareHMACKey)
        ),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Hmac_Async),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
        MCUX_CSSL_FP_CONDITIONAL(NULL != pOut,  MCUXCLCSS_DMA_READBACK_PROTECTION_TOKEN)
         );
}

const mcuxClMac_ModeDescriptor_t mcuxClMac_ModeDescriptor_HMAC_CSS = {
  .engineInit = mcuxClMac_Engine_HMAC_Init,
  .engineUpdate = mcuxClMac_Engine_HMAC_Update,
  .engineFinalize = mcuxClMac_Engine_HMAC_Finalize,
  .engineOneshot = mcuxClMac_Engine_HMAC_Oneshot,
  .protectionTokenInit = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_HMAC_Init),
  .protectionTokenUpdate = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_HMAC_Update),
  .protectionTokenFinalize = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_HMAC_Finalize),
  .protectionTokenOneshot = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_Engine_HMAC_Oneshot),
  .macByteSize = MCUXCLMAC_HMAC_OUTPUT_SIZE_SHA_256
};
