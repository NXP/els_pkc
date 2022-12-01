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

/** @file  mcuxClCss_Aead.c
 *  @brief CSSv2 implementation for Authenticated Encryption with Associated Data (AEAD).
 * This file implements the functions declared in mcuxClCss_Aead.h. */

#include <platform_specific_headers.h>
#include <mcuxClMemory.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <stdbool.h>
#include <mcuxClCss.h>
#include <internal/mcuxClCss_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Aead_Init_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Aead_Init_Async(
    mcuxClCss_AeadOption_t options,
    mcuxClCss_KeyIndex_t keyIdx,
    uint8_t const * pKey,
    size_t keyLength,
    uint8_t const * pIV,
    size_t ivLength,
    uint8_t * pAeadCtx)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Aead_Init_Async);

    MCUXCLCSS_INPUT_PARAM_CHECK_PROTECTED(mcuxClCss_Aead_Init_Async, (MCUXCLCSS_AEAD_INTERN_KEY == options.bits.extkey && CSS_KS_CNT <= keyIdx) || ((MCUXCLCSS_AEAD_EXTERN_KEY == options.bits.extkey && ((MCUXCLCSS_CIPHER_KEY_SIZE_AES_128 != keyLength && MCUXCLCSS_CIPHER_KEY_SIZE_AES_192 != keyLength && MCUXCLCSS_CIPHER_KEY_SIZE_AES_256 != keyLength))))
            || (0u == ivLength) || (0u != ivLength % MCUXCLCSS_AEAD_IV_BLOCK_SIZE));

    uint8_t * pStartIpCtxArea = pAeadCtx + MCUXCLCSS_CIPHER_BLOCK_SIZE_AES;

    /* Set init mode */
    options.bits.acpmod = MCUXCLCSS_AEAD_ACPMOD_INIT;
    options.bits.lastinit = MCUXCLCSS_AEAD_LASTINIT_TRUE;

    options.bits.acpsie = MCUXCLCSS_AEAD_STATE_IN_DISABLE;
#ifndef MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS
    options.bits.acpsoe = MCUXCLCSS_AEAD_STATE_OUT_ENABLE;
#endif /* MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS */

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Aead_Init_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClCss_setInput0(pIV, ivLength);
    mcuxClCss_setInput1_fixedSize(pStartIpCtxArea);
    mcuxClCss_setInput2(pKey, keyLength);
    mcuxClCss_setKeystoreIndex0(keyIdx);
    mcuxClCss_startCommand(ID_CFG_CSS_CMD_AUTH_CIPHER, options.word.value, CSS_CMD_BIG_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Aead_Init_Async, MCUXCLCSS_STATUS_OK_WAIT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Aead_PartialInit_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Aead_PartialInit_Async(
    mcuxClCss_AeadOption_t options,
    mcuxClCss_KeyIndex_t keyIdx,
    uint8_t const * pKey,
    size_t keyLength,
    uint8_t const * pIV,
    size_t ivLength,
    uint8_t * pAeadCtx)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Aead_PartialInit_Async);

    MCUXCLCSS_INPUT_PARAM_CHECK_PROTECTED(mcuxClCss_Aead_PartialInit_Async, (MCUXCLCSS_AEAD_INTERN_KEY == options.bits.extkey && CSS_KS_CNT <= keyIdx) || ((MCUXCLCSS_AEAD_EXTERN_KEY == options.bits.extkey && ((MCUXCLCSS_CIPHER_KEY_SIZE_AES_128 != keyLength && MCUXCLCSS_CIPHER_KEY_SIZE_AES_192 != keyLength && MCUXCLCSS_CIPHER_KEY_SIZE_AES_256 != keyLength))))
            || (0u == ivLength) || (0u != ivLength % MCUXCLCSS_AEAD_IV_BLOCK_SIZE));

    uint8_t * pStartIpCtxArea = pAeadCtx + MCUXCLCSS_CIPHER_BLOCK_SIZE_AES;

    /* Set init mode */
    options.bits.acpmod = MCUXCLCSS_AEAD_ACPMOD_INIT;

#ifndef MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS
    options.bits.acpsoe = MCUXCLCSS_AEAD_STATE_OUT_ENABLE;
#endif /* MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS */

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Aead_PartialInit_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClCss_setInput0(pIV, ivLength);
    mcuxClCss_setInput1_fixedSize(pStartIpCtxArea);
    mcuxClCss_setInput2(pKey, keyLength);
    mcuxClCss_setKeystoreIndex0(keyIdx);
    mcuxClCss_startCommand(ID_CFG_CSS_CMD_AUTH_CIPHER, options.word.value, CSS_CMD_BIG_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Aead_PartialInit_Async, MCUXCLCSS_STATUS_OK_WAIT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Aead_UpdateAad_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Aead_UpdateAad_Async(
    mcuxClCss_AeadOption_t options,
    mcuxClCss_KeyIndex_t keyIdx,
    uint8_t const * pKey,
    size_t keyLength,
    uint8_t const * pAad,
    size_t aadLength,
    uint8_t * pAeadCtx)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Aead_UpdateAad_Async);

    MCUXCLCSS_INPUT_PARAM_CHECK_PROTECTED(mcuxClCss_Aead_UpdateAad_Async, (0U == aadLength) || (0u != aadLength % MCUXCLCSS_AEAD_AAD_BLOCK_SIZE));

    uint8_t * pStartIpCtxArea = pAeadCtx + MCUXCLCSS_CIPHER_BLOCK_SIZE_AES;

    options.bits.acpmod = MCUXCLCSS_AEAD_ACPMOD_AADPROC;

#ifndef MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS
    options.bits.acpsie = MCUXCLCSS_AEAD_STATE_IN_ENABLE;
    options.bits.acpsoe = MCUXCLCSS_AEAD_STATE_OUT_ENABLE;
#endif /* MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS */

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Aead_UpdateAad_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClCss_setInput2(pKey, keyLength);
    mcuxClCss_setKeystoreIndex0(keyIdx);
    mcuxClCss_setInput0(pAad, aadLength);
    mcuxClCss_setInput1_fixedSize(pStartIpCtxArea);
    mcuxClCss_startCommand(ID_CFG_CSS_CMD_AUTH_CIPHER, options.word.value, CSS_CMD_BIG_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Aead_UpdateAad_Async, MCUXCLCSS_STATUS_OK_WAIT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Aead_UpdateData_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Aead_UpdateData_Async(
    mcuxClCss_AeadOption_t options,
    mcuxClCss_KeyIndex_t keyIdx,
    uint8_t const * pKey,
    size_t keyLength,
    uint8_t const * pInput,
    size_t inputLength,
    uint8_t * pOutput,
    uint8_t * pAeadCtx)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Aead_UpdateData_Async);

    MCUXCLCSS_INPUT_PARAM_CHECK_PROTECTED(mcuxClCss_Aead_UpdateData_Async, (0U == inputLength)  || (0u != inputLength % MCUXCLCSS_CIPHER_BLOCK_SIZE_AES) || (MCUXCLCSS_AEAD_INTERN_KEY == options.bits.extkey && CSS_KS_CNT <= keyIdx)
            || (MCUXCLCSS_AEAD_EXTERN_KEY == options.bits.extkey && (MCUXCLCSS_CIPHER_KEY_SIZE_AES_128 != keyLength && MCUXCLCSS_CIPHER_KEY_SIZE_AES_192 != keyLength && MCUXCLCSS_CIPHER_KEY_SIZE_AES_256 != keyLength)));

    uint8_t * pStartIpCtxArea = pAeadCtx + MCUXCLCSS_CIPHER_BLOCK_SIZE_AES;

    options.bits.acpmod = MCUXCLCSS_AEAD_ACPMOD_MSGPROC;

#ifndef MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS
    options.bits.acpsie = MCUXCLCSS_AEAD_STATE_IN_ENABLE;
    options.bits.acpsoe = MCUXCLCSS_AEAD_STATE_OUT_ENABLE;
#endif /* MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS */

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Aead_UpdateData_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClCss_setInput2(pKey, keyLength);
    mcuxClCss_setKeystoreIndex0(keyIdx);
    mcuxClCss_setInput0(pInput, inputLength);
    mcuxClCss_setInput1_fixedSize(pStartIpCtxArea);
    mcuxClCss_setOutput_fixedSize(pOutput);
    mcuxClCss_startCommand(ID_CFG_CSS_CMD_AUTH_CIPHER, options.word.value, CSS_CMD_BIG_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Aead_UpdateData_Async, MCUXCLCSS_STATUS_OK_WAIT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_Aead_Finalize_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Aead_Finalize_Async(
    mcuxClCss_AeadOption_t options,
    mcuxClCss_KeyIndex_t keyIdx,
    uint8_t const * pKey,
    size_t keyLength,
    size_t aadLength,
    size_t dataLength,
    uint8_t * pTag,
    uint8_t * pAeadCtx)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_Aead_Finalize_Async);

    MCUXCLCSS_INPUT_PARAM_CHECK_PROTECTED(mcuxClCss_Aead_Finalize_Async, (MCUXCLCSS_AEAD_INTERN_KEY == options.bits.extkey && CSS_KS_CNT <= keyIdx) || (MCUXCLCSS_AEAD_EXTERN_KEY == options.bits.extkey && (16U != keyLength && 24U != keyLength && 32U != keyLength)));

    uint8_t * pStartIpCtxArea = pAeadCtx + MCUXCLCSS_CIPHER_BLOCK_SIZE_AES;

#ifndef MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS
    options.bits.acpsie = MCUXCLCSS_AEAD_STATE_IN_ENABLE;
#endif /* MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS */

    /* Update the length of the AAD to store in the context */
    aadLength <<= 3;
    /* Update the length of the data to store in the context */
    dataLength <<= 3;
    /* Store both in the context */
    mcuxClMemory_StoreBigEndian32(&pAeadCtx[ 0u], (uint32_t) 0U);
    mcuxClMemory_StoreBigEndian32(&pAeadCtx[ 4u], aadLength );
    mcuxClMemory_StoreBigEndian32(&pAeadCtx[ 8u], (uint32_t) 0U);
    mcuxClMemory_StoreBigEndian32(&pAeadCtx[12u], dataLength);

    options.bits.acpmod = MCUXCLCSS_AEAD_ACPMOD_FINAL;

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Aead_Finalize_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    mcuxClCss_setInput2(pKey, keyLength);
    mcuxClCss_setKeystoreIndex0(keyIdx);
    mcuxClCss_setInput0_fixedSize(pAeadCtx);
    mcuxClCss_setInput1_fixedSize(pStartIpCtxArea);
    mcuxClCss_setOutput_fixedSize(pTag);
    mcuxClCss_startCommand(ID_CFG_CSS_CMD_AUTH_CIPHER, options.word.value, CSS_CMD_BIG_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_Aead_Finalize_Async, MCUXCLCSS_STATUS_OK_WAIT);
}
