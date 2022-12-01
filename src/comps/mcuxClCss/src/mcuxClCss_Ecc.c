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

/**
 * @file  mcuxClCss_Ecc.c
 * @brief CSSv2 implementation for elliptic curve cryptography.
 * This file implements the functions declared in mcuxClCss_Ecc.h.
 */

#include <platform_specific_headers.h>
#include <mcuxClCss_Ecc.h>
#include <mcuxClMemory.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <stdbool.h>
#include <mcuxClCss.h>
#include <internal/mcuxClCss_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_EccKeyGen_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_EccKeyGen_Async(
    mcuxClCss_EccKeyGenOption_t options,
    mcuxClCss_KeyIndex_t signingKeyIdx,
    mcuxClCss_KeyIndex_t privateKeyIdx,
    mcuxClCss_KeyProp_t generatedKeyProperties,
    uint8_t const * pRandomData,
    uint8_t * pPublicKey)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_EccKeyGen_Async);

    MCUXCLCSS_INPUT_PARAM_CHECK_PROTECTED(mcuxClCss_EccKeyGen_Async, (CSS_KS_CNT <= signingKeyIdx) || (CSS_KS_CNT <= privateKeyIdx));

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_EccKeyGen_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    options.bits.revf = MCUXCLCSS_ECC_REVERSEFETCH_ENABLE;

    mcuxClCss_setKeystoreIndex0(privateKeyIdx);
    mcuxClCss_setKeystoreIndex1(signingKeyIdx);
    mcuxClCss_setRequestedKeyProperties(generatedKeyProperties.word.value);
    mcuxClCss_setInput0_fixedSize(pRandomData);
    mcuxClCss_setOutput_fixedSize(pPublicKey);
    mcuxClCss_startCommand(ID_CFG_CSS_CMD_KEYGEN, options.word.value, CSS_CMD_BIG_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_EccKeyGen_Async, MCUXCLCSS_STATUS_OK_WAIT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_EccKeyExchange_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_EccKeyExchange_Async(
        mcuxClCss_KeyIndex_t privateKeyIdx,
        uint8_t const * pPublicKey,
        mcuxClCss_KeyIndex_t sharedSecretIdx,
        mcuxClCss_KeyProp_t sharedSecretProperties)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_EccKeyExchange_Async);

    MCUXCLCSS_INPUT_PARAM_CHECK_PROTECTED(mcuxClCss_EccKeyExchange_Async, (CSS_KS_CNT <= privateKeyIdx) || (CSS_KS_CNT <= sharedSecretIdx));

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_EccKeyExchange_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }
    
    mcuxClCss_EccKeyExchOption_t options = {0};
    options.bits.revf = MCUXCLCSS_ECC_REVERSEFETCH_ENABLE;
#ifdef MCUXCL_FEATURE_CSS_PUK_INTERNAL_BIT
    options.bits.extkey = MCUXCLCSS_ECC_EXTKEY_EXTERNAL;
#endif /* MCUXCL_FEATURE_CSS_PUK_INTERNAL_BIT */

    mcuxClCss_setKeystoreIndex0(privateKeyIdx);
    mcuxClCss_setInput1_fixedSize(pPublicKey);
    mcuxClCss_setKeystoreIndex1(sharedSecretIdx);
    mcuxClCss_setRequestedKeyProperties(sharedSecretProperties.word.value);

    mcuxClCss_startCommand(ID_CFG_CSS_CMD_ECKXH, options.word.value, CSS_CMD_BIG_ENDIAN);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_EccKeyExchange_Async, MCUXCLCSS_STATUS_OK_WAIT);
}

#ifdef MCUXCL_FEATURE_CSS_PUK_INTERNAL

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_EccKeyExchangeInt_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_EccKeyExchangeInt_Async(
    mcuxClCss_KeyIndex_t privateKeyIdx,
    mcuxClCss_KeyIndex_t publicKeyIdx,
    mcuxClCss_KeyIndex_t sharedSecretIdx,
    mcuxClCss_KeyProp_t sharedSecretProperties)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_EccKeyExchangeInt_Async);

    MCUXCLCSS_INPUT_PARAM_CHECK_PROTECTED(mcuxClCss_EccKeyExchangeInt_Async, (CSS_KS_CNT <= privateKeyIdx)
                                                                        || (CSS_KS_CNT <= publicKeyIdx)
                                                                        || (CSS_KS_CNT <= sharedSecretIdx));

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_EccKeyExchangeInt_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }
	
    mcuxClCss_EccKeyExchOption_t options = {0};
    options.bits.revf = MCUXCLCSS_ECC_REVERSEFETCH_ENABLE;
    options.bits.extkey = MCUXCLCSS_ECC_EXTKEY_INTERNAL;

    mcuxClCss_setKeystoreIndex0(privateKeyIdx);
    mcuxClCss_setKeystoreIndex2(publicKeyIdx);
    mcuxClCss_setKeystoreIndex1(sharedSecretIdx);
    mcuxClCss_setRequestedKeyProperties(sharedSecretProperties.word.value);
    mcuxClCss_startCommand(ID_CFG_CSS_CMD_ECKXH, options.word.value, CSS_CMD_BIG_ENDIAN);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_EccKeyExchangeInt_Async, MCUXCLCSS_STATUS_OK_WAIT);
}
#endif /* MCUXCL_FEATURE_CSS_PUK_INTERNAL */


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_EccSign_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_EccSign_Async(
    mcuxClCss_EccSignOption_t options,
    mcuxClCss_KeyIndex_t keyIdx,
    uint8_t const * pInputHash,
    uint8_t const * pInputMessage,
    size_t inputMessageLength,
    uint8_t * pOutput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_EccSign_Async);

    MCUXCLCSS_INPUT_PARAM_CHECK_PROTECTED(mcuxClCss_EccSign_Async, (CSS_KS_CNT <= keyIdx));

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_EccSign_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    options.bits.revf = MCUXCLCSS_ECC_REVERSEFETCH_ENABLE;

    mcuxClCss_setKeystoreIndex0(keyIdx);
    mcuxClCss_setInput0((options.bits.echashchl == 0u) ? pInputHash : pInputMessage, inputMessageLength);
    mcuxClCss_setOutput_fixedSize(pOutput);
    mcuxClCss_startCommand(ID_CFG_CSS_CMD_ECSIGN, options.word.value, CSS_CMD_BIG_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_EccSign_Async, MCUXCLCSS_STATUS_OK_WAIT);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_EccVerify_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_EccVerify_Async(
    mcuxClCss_EccVerifyOption_t options,
    uint8_t const * pInputHash,
    uint8_t const * pInputMessage,
    size_t inputMessageLength,
    uint8_t const * pSignatureAndPubKey,
    uint8_t * pOutput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_EccVerify_Async);

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_EccVerify_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    options.bits.revf = MCUXCLCSS_ECC_REVERSEFETCH_ENABLE;
#ifdef MCUXCL_FEATURE_CSS_PUK_INTERNAL_BIT
    options.bits.extkey = MCUXCLCSS_ECC_EXTKEY_EXTERNAL;
#endif /* MCUXCL_FEATURE_CSS_PUK_INTERNAL_BIT */

    mcuxClCss_setInput0((options.bits.echashchl == 0u) ? pInputHash : pInputMessage, inputMessageLength);
    mcuxClCss_setInput1_fixedSize(pSignatureAndPubKey);
    mcuxClCss_setOutput_fixedSize(pOutput);
    mcuxClCss_startCommand(ID_CFG_CSS_CMD_ECVFY, options.word.value, CSS_CMD_BIG_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_EccVerify_Async, MCUXCLCSS_STATUS_OK_WAIT);
}

#ifdef MCUXCL_FEATURE_CSS_PUK_INTERNAL
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCss_EccVerifyInt_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_EccVerifyInt_Async(
    mcuxClCss_EccVerifyOption_t options,
    mcuxClCss_KeyIndex_t publicKeyIdx,
    uint8_t const * pInputHash,
    uint8_t const * pInputMessage,
    size_t inputMessageLength,
    uint8_t const * pSignature,
    uint8_t * pOutput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClCss_EccVerifyInt_Async);

    MCUXCLCSS_INPUT_PARAM_CHECK_PROTECTED(mcuxClCss_EccVerifyInt_Async, (CSS_KS_CNT <= publicKeyIdx));

    /* CSS SFRs are not cached => Tell SW to wait for CSS to come back from BUSY state before modifying the SFRs */
    if (mcuxClCss_isBusy())
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_EccVerifyInt_Async, MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT);
    }

    options.bits.revf   = MCUXCLCSS_ECC_REVERSEFETCH_ENABLE;
    options.bits.extkey = MCUXCLCSS_ECC_EXTKEY_INTERNAL;

    mcuxClCss_setInput0((options.bits.echashchl == 0u) ? pInputHash : pInputMessage, inputMessageLength);
    mcuxClCss_setInput1_fixedSize(pSignature);
    mcuxClCss_setOutput_fixedSize(pOutput);
    mcuxClCss_setKeystoreIndex2(publicKeyIdx);
    mcuxClCss_startCommand(ID_CFG_CSS_CMD_ECVFY, options.word.value, CSS_CMD_BIG_ENDIAN);


    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClCss_EccVerifyInt_Async, MCUXCLCSS_STATUS_OK_WAIT);
}
#endif /* MCUXCL_FEATURE_CSS_PUK_INTERNAL */
