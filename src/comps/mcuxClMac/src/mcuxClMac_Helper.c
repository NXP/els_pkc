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

/** @file  mcuxClMac_Helper.c
 *  @brief implementation of helper functions of mcuxClMac component */

#include <toolchain.h>
#include <mcuxClMac.h>

#include <mcuxClMemory.h>
#include <mcuxClKey.h>
#include <mcuxClHash.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClMac_Internal.h>
#include <internal/mcuxClKey_Functions_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMac_prepareHMACKey)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_prepareHMACKey(
    mcuxClMac_Context_t *pContext)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMac_prepareHMACKey);

    size_t alreadyFilledKeyDataSize = 0u;
    uint8_t *pPreparedHmacKey = (uint8_t *) pContext->preparedHmacKey;
    uint8_t *pKeyData = mcuxClKey_getLoadedKeyData(pContext->key);
    uint32_t keySize = mcuxClKey_getSize(pContext->key);
    
    if(mcuxClKey_getSize(pContext->key) <= MCUXCLMAC_HMAC_PADDED_KEY_SIZE)
    {
        /* Given key must be zero-padded up to MCUXCLMAC_HMAC_PADDED_KEY_SIZE */
        // TODO: use secure memory copy?
        MCUX_CSSL_FP_FUNCTION_CALL(copyResult, mcuxClMemory_copy(pPreparedHmacKey,
                                                               pKeyData,
                                                               keySize,
                                                               MCUXCLMAC_HMAC_PADDED_KEY_SIZE));

        if(0u != copyResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_prepareHMACKey, MCUXCLMAC_ERRORCODE_ERROR,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy));
        }

        alreadyFilledKeyDataSize = keySize;
    }
    else
    {
        uint32_t hashOutputSize = 0u;
        /* Given key must be hashed and then zero-padded up to MCUXCLMAC_HMAC_PADDED_KEY_SIZE */
        MCUX_CSSL_FP_FUNCTION_CALL(hashResult, mcuxClHash_compute(pContext->session,
                                                                mcuxClHash_Algorithm_Sha256,
                                                                pKeyData,
                                                                (uint32_t) keySize,
                                                                pPreparedHmacKey,
                                                                &hashOutputSize));

        if(MCUXCLCSS_STATUS_OK_WAIT != hashResult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_prepareHMACKey, MCUXCLMAC_ERRORCODE_ERROR,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute));
        }

        alreadyFilledKeyDataSize = MCUXCLHASH_OUTPUT_SIZE_SHA_256;
    }

    /* Zero-pad the key */
    MCUX_CSSL_FP_FUNCTION_CALL(setResult, mcuxClMemory_set(pPreparedHmacKey + alreadyFilledKeyDataSize,
                                                          0u,
                                                          MCUXCLMAC_HMAC_PADDED_KEY_SIZE - alreadyFilledKeyDataSize,
                                                          MCUXCLMAC_HMAC_PADDED_KEY_SIZE - alreadyFilledKeyDataSize));

    if(0u != setResult)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMac_prepareHMACKey, MCUXCLMAC_ERRORCODE_ERROR,
            MCUX_CSSL_FP_CONDITIONAL((mcuxClKey_getSize(pContext->key) <= MCUXCLMAC_HMAC_PADDED_KEY_SIZE),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy)
            ),
            MCUX_CSSL_FP_CONDITIONAL((mcuxClKey_getSize(pContext->key) > MCUXCLMAC_HMAC_PADDED_KEY_SIZE),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute)
            ),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set)
        );
    }

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClMac_prepareHMACKey, MCUXCLMAC_ERRORCODE_OK, MCUXCLMAC_ERRORCODE_FAULT_ATTACK,
        MCUX_CSSL_FP_CONDITIONAL((mcuxClKey_getSize(pContext->key) <= MCUXCLMAC_HMAC_PADDED_KEY_SIZE),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy)
        ),
        MCUX_CSSL_FP_CONDITIONAL((mcuxClKey_getSize(pContext->key) > MCUXCLMAC_HMAC_PADDED_KEY_SIZE),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute)
        ),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set)
    );
}
