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
 * @file  mcuxClKey_Functions.h
 * @brief Top-level API of the mcuxClKey component. It is capable to load and flush
 *        keys into memory locations or coprocessors.
 */

#ifndef MCUX_CL_KEY_FUNCTIONS_H_
#define MCUX_CL_KEY_FUNCTIONS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClSession.h>
#include <mcuxClSession_Types.h>

#include <mcuxClKey_Types.h>

#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Buffer.h>
#include <mcuxClCss.h>

/**********************************************
 * FUNCTIONS
 **********************************************/

/**
 * @addtogroup mcuxClAPI MCUX CL -- API
 *
 * @defgroup mcuxClKey Key API
 * @brief Key handling operations.
 * @ingroup mcuxClAPI
 */

/**
 * @defgroup mcuxClKey_Functions mcuxClKey_Functions
 * @brief Defines all functions of @ref mcuxClKey
 * @ingroup mcuxClKey
 * @{
 */

/**
 * @brief Initializes a key handle.
 *
 * Initializes a key handle with default protection values.
 *
 * @param[in]      pSession         Session handle to provide session dependent information
 * @param[in,out]  key              Key handle that will be initialized
 * @param[in]      type             Define which key type shall be initialized
 * @param[in]      pKeyData         Provide pointer to source data of the key. This can be a pointer to a plain key buffer, a share, or a key blob. The protection function defines the purpose of this parameter
 * @param[in]      keyDataLength    Length of the provided key data @p pKeyData
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUX_CL_KEY_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUX_CL_KEY_STATUS_, see individual documentation for more information
 * @endif
 *
 * @retval #MCUX_CL_KEY_STATUS_ERROR  on unsuccessful operation
 * @retval #MCUX_CL_KEY_STATUS_OK     on successful operation
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClKey_init)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_init(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Handle_t key,
    mcuxClKey_Type_t type,
    mcuxCl_Buffer_t pKeyData,
    uint32_t keyDataLength
);

/**
 * @brief Configures they protection mechanism for to the given key handle.
 *
 * @param[in]      pSession    Session handle to provide session dependent information
 * @param[in,out]  key         Key handle that will be configured
 * @param[in]      protection  Define the protection and flush mechanism that shall be used with this @p key
 * @param[in]      pAuxData    Provide pointer to additional data the protection function may use
 * @param[in]      parentKey   Provide parent key information in case it exists. The protection function defines the purpose of this parameter
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUX_CL_KEY_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUX_CL_KEY_STATUS_, see individual documentation for more information
 * @endif
 *
 * @retval #MCUX_CL_KEY_STATUS_ERROR  on unsuccessful operation
 * @retval #MCUX_CL_KEY_STATUS_OK     on successful operation
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClKey_setProtection)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_setProtection(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Handle_t key,
    mcuxClKey_Protection_t protection,
    mcuxCl_Buffer_t pAuxData,
    mcuxClKey_Handle_t parentKey
);

/**
 * @brief Load key into destination key slot of a coprocessor
 *
 * @param[in]  pSession Session handle to provide session dependent information
 * @param[in]  key      Key handle that provides information to load the key
 * @param[out] dstSlot  Provide destination key slot in case the key has to loaded to a key slot. The protection function defines the purpose of this parameter
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUX_CL_KEY_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUX_CL_KEY_STATUS_, see individual documentation for more information
 * @endif
 *
 * @retval #MCUX_CL_KEY_STATUS_ERROR  on unsuccessful operation
 * @retval #MCUX_CL_KEY_STATUS_OK     on successful operation
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClKey_loadCopro)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_loadCopro(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Handle_t key,
    uint32_t dstSlot
);

/**
 * @brief Load key into destination memory buffer
 *
 * @param[in]  pSession Session handle to provide session dependent information
 * @param[in]  key      Key handle that provides information to load the key
 * @param[out] dstData  Provide pointer to destination key memory in case the key has to be loaded to memory. The protection function defines the purpose of this parameter
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUX_CL_KEY_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUX_CL_KEY_STATUS_, see individual documentation for more information
 * @endif
 *
 * @retval #MCUX_CL_KEY_STATUS_ERROR  on unsuccessful operation
 * @retval #MCUX_CL_KEY_STATUS_OK     on successful operation
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClKey_loadMemory)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_loadMemory(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Handle_t key,
    uint32_t * dstData
);

/**
 * @brief Flush key from destination which can be a key slot of coprocessor or memory buffer
 *
 * @param[in] pSession Session handle to provide session dependent information
 * @param[in] key      Key handle that provides information to flush the key
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUX_CL_KEY_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUX_CL_KEY_STATUS_, see individual documentation for more information
 * @endif
 *
 * @retval #MCUX_CL_KEY_STATUS_ERROR  on unsuccessful operation
 * @retval #MCUX_CL_KEY_STATUS_OK     on successful operation
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClKey_flush)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_flush(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Handle_t key
);



/**
 * @brief Set the requested key properties of the destination key.
 *
 * @param[in,out]  key             key handle that provides information to flush the key
 * @param[in]      key_properties  Pointer to the requested key properties of the destination key. Will be set in key->container.pAuxData
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUX_CL_KEY_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUX_CL_KEY_STATUS_, see individual documentation for more information
 * @endif
 *
 * @retval #MCUX_CL_KEY_STATUS_ERROR  on unsuccessful operation
 * @retval #MCUX_CL_KEY_STATUS_OK     on successful operation
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClKey_setKeyproperties)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_setKeyproperties(
    mcuxClKey_Handle_t key,
    mcuxClCss_KeyProp_t * key_properties
);

/* TODO CLNS-5402: Add FP to all functions */
/**
 * @brief Key-pair generation function.
 * @api
 *
 * This function can be used to perform a key-pair generation operation.
 *
 * Note: the key handles @p privKey and @p pubKey must already be initialized
 * and contain a proper key type (matching to the @p generation algorithm),
 * protection mechanism and key data buffers.
 *
 * @param      pSession        Handle for the current CL session.
 * @param      generation      Key generation algorithm that determines the key
 *                             data stored in @p privKey and @p pubKey.
 * @param[out] privKey         Key handle for the generated private key.
 * @param[out] pubKey          Key handle for the generated public key.
 * @param[out] pPrivDataLength Will be incremented by the number of bytes of data
 *                             that have been written to the key data buffer of
 *                             @p privKey.
 * @param[out] pPubDataLength  Will be incremented by the number of bytes of data
 *                             that have been written to the key data buffer of
 *                             @p pubKey.
 * @return status
 */
mcuxClKey_Status_t mcuxClKey_generate_keypair(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Generation_t generation,
    mcuxClKey_Handle_t privKey,
    mcuxClKey_Handle_t pubKey,
    uint32_t * const pPrivDataLength,
    uint32_t * const pPubDataLength
); /* generate a fresh new key (pair) */

/**
 * @brief Key agreement function.
 * @api
 *
 * This function can be used to perform a key agreement operation.
 *
 * @param      pSession    Handle for the current CL session.
 * @param      agreement   Key agreement algorithm that determines the value of
 *                         @p pOut.
 * @param      key         First key to be used for the agreement operation.
 * @param      otherKey    Other key to be used for the agreement operation.
 * @param[out] pOut        Buffer to store the agreed key.
 * @param[out] pOutLength  Number of bytes written to the @p pOut buffer.
 * @return status
 */
mcuxClKey_Status_t mcuxClKey_agreement(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Agreement_t agreement,
    mcuxClKey_Handle_t key,
    mcuxClKey_Handle_t otherKey,
    mcuxCl_Buffer_t pOut,
    uint32_t * const pOutLength
); /* determine a shared key on based on public and private inputs */

/**
 * @brief Key descriptor initialization function including applying a
 * protection mechanism.
 * @api
 *
 * This function performs the initialization of a Key descriptor. In addition
 * the given @p protection mechanism gets applied to the given raw key data.
 *
 * @param      pSession                Handle for the current CL session.
 * @param      protection              Protection mechanism to be applied to the
 *                                     given @p pPlainKeyData.
 * @param      protectedKey            Key to be initialized and protected.
 * @param      type                    Type of the key.
 * @param[in]  pPlainKeyData           Plain raw key data.
 * @param      plainKeyDataLength      Number of bytes available in the
 *                                     @p pPlainKeyData buffer.
 * @param[in]  pAuxData                Auxilary data needed for the given key
 *                                     @p protection.
 * @param      auxDataLength           Number of bytes available in the
 *                                     @p pAuxData buffer.
 * @param[out] pProtectedKeyData       Protected raw key data (after applying
 *                                     @p protection to the @p pPlainKeyData)
 * @param[out] pProtectedKeyDataLength Number of bytes written to the
 *                                     @p pProtectedKeyData buffer.
 * @return status
 */
mcuxClKey_Status_t mcuxClKey_protect(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Protection_t protection,
    mcuxClKey_Handle_t protectedKey,
    mcuxClKey_Type_t type,
    mcuxCl_InputBuffer_t pPlainKeyData,
    uint32_t plainKeyDataLength,
    mcuxCl_InputBuffer_t pAuxData,
    uint32_t auxDataLength,
    mcuxCl_Buffer_t pProtectedKeyData,
    uint32_t * const pProtectedKeyDataLength
);


/**
 * @}
 */ /* mcuxClKey_Functions */

#endif /* MCUX_CL_KEY_FUNCTIONS_H_ */
