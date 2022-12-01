/*--------------------------------------------------------------------------*/
/* Copyright 2020-2021 NXP                                                  */
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
 * @file  mcuxClCss_KeyManagement.h
 * @brief CSSv2 header for key management.
 *
 * This header exposes functions that can be used to manage the keystore of CSSv2.
 * This includes:
 * - Importing keys
 * @if MCUXCL_FEATURE_CSS_KEY_MGMT_EXPORT
 * - Exporting keys
 * @endif
 * @if MCUXCL_FEATURE_CSS_KEY_MGMT_DELETE
 * - Deleting keys
 * @endif
 */

/**
 * @defgroup mcuxClCss_KeyManagement mcuxClCss_KeyManagement
 * @brief This part of the @ref mcuxClCss driver supports functionality for keys management
 * @ingroup mcuxClCss
 * @{
 */

#ifndef MCUXCLCSS_KEYMANAGEMENT_H_
#define MCUXCLCSS_KEYMANAGEMENT_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCss_Common.h> // Common functionality

/**********************************************
 * CONSTANTS
 **********************************************/
/**
 * @defgroup mcuxClCss_KeyManagement_Macros mcuxClCss_KeyManagement_Macros
 * @brief Defines all macros of @ref mcuxClCss_KeyManagement
 * @ingroup mcuxClCss_KeyManagement
 * @{
 */

/**
 * @defgroup MCUXCLCSS_KEYIMPORT_VALUE_KFMT_ MCUXCLCSS_KEYIMPORT_VALUE_KFMT_
 * @brief Defines valid options (word value) to be used by #mcuxClCss_KeyImport_Async
 * @ingroup mcuxClCss_KeyManagement_Macros
 *
 * @{
 */

#define MCUXCLCSS_KEYIMPORT_VALUE_KFMT_UDF      ((uint32_t) 0u<< 6u) ///< Key format UDF with shares in RTL or memory
#define MCUXCLCSS_KEYIMPORT_VALUE_KFMT_RFC3394  ((uint32_t) 1u<< 6u) ///< Key format RFC3394 with shares in memory
#define MCUXCLCSS_KEYIMPORT_VALUE_KFMT_PUF      ((uint32_t) 2u<< 6u) ///< Key from PUF
#ifdef MCUXCL_FEATURE_CSS_PUK_INTERNAL
#define MCUXCLCSS_KEYIMPORT_VALUE_KFMT_PBK      ((uint32_t) 3u<< 6u) ///< Key from Public Key Certificate
#endif /* MCUXCL_FEATURE_CSS_PUK_INTERNAL */

/**
 * @}
 */

/**
 * @defgroup MCUXCLCSS_KEYIMPORT_KFMT_ MCUXCLCSS_KEYIMPORT_KFMT_
 * @brief Defines valid options (bit values) to be used by #mcuxClCss_KeyImport_Async
 * @ingroup mcuxClCss_KeyManagement_Macros
 *
 * @{
 */
#define MCUXCLCSS_KEYIMPORT_KFMT_UDF             ((uint32_t) 0x00u) ///< Key format UDF with shares in RTL or memory
#define MCUXCLCSS_KEYIMPORT_KFMT_RFC3394         ((uint32_t) 0x01u) ///< Key format RFC3394 with shares in memory
#define MCUXCLCSS_KEYIMPORT_KFMT_PUF             ((uint32_t) 0x02u) ///< Key from PUF
#ifdef MCUXCL_FEATURE_CSS_PUK_INTERNAL
#define MCUXCLCSS_KEYIMPORT_KFMT_PBK             ((uint32_t) 0x03u) ///< Key from Public Key Certificate
#endif /* MCUXCL_FEATURE_CSS_PUK_INTERNAL */

#ifdef MCUXCL_FEATURE_CSS_PUK_INTERNAL
#define MCUXCLCSS_KEYIMPORT_REVERSEFETCH_ENABLE  ((uint32_t) 1U) ///< Reverse fetch enabled. For internal use
#define MCUXCLCSS_KEYIMPORT_REVERSEFETCH_DISABLE ((uint32_t) 0U) ///< Reverse fetch disabled. For internal use
#endif /* MCUXCL_FEATURE_CSS_PUK_INTERNAL */

#define MCUXCLCSS_RFC3394_OVERHEAD               ((size_t) 16u)     ///< Overhead between RFC3394 blob and key size
/**
 * @}
 */

/**
 * @defgroup MCUXCLCSS_RFC3394_ MCUXCLCSS_RFC3394_
 * @brief Defines specifying the length of RFC3394 containers
 * @ingroup mcuxClCss_KeyManagement_Macros
 *
 * @{
 */
#define MCUXCLCSS_RFC3394_CONTAINER_SIZE_128     ((size_t) 256u/8u) ///< Size of RFC3394 container for 128 bit key
#define MCUXCLCSS_RFC3394_CONTAINER_SIZE_256     ((size_t) 384u/8u) ///< Size of RFC3394 container for 256 bit key
#ifdef MCUXCL_FEATURE_CSS_PUK_INTERNAL
#define MCUXCLCSS_RFC3394_CONTAINER_SIZE_P256    ((size_t) 640u/8u) ///< Size of RFC3394 container for P256 bit public key
#endif /* MCUXCL_FEATURE_CSS_PUK_INTERNAL */
/**
 * @}
 */

#if defined(MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV) || defined(MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV_ROM) 
/**
 * @defgroup MCUXCLCSS_KEYPROV_ MCUXCLCSS_KEYPROV_
 * @brief Defines for #mcuxClCss_KeyProvision_Async
 * @ingroup mcuxClCss_KeyManagement_Macros
 *
 * @{
 */
#ifdef MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV
#define MCUXCLCSS_KEYPROV_KEY_PART_1_SIZE        ((uint32_t) 32u)     ///< Size of external UDF key part1
#endif /* MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV */

#ifdef MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV_ROM
#define MCUXCLCSS_KEYPROV_TESTERSHARE_SIZE       ((uint32_t) 32u)     ///< Size of external tester share
#define MCUXCLCSS_KEYPROV_KEYSHARE_TABLE_SIZE    ((uint32_t) 8u)		 ///< Number of key shares available in the key share table
#endif /* MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV_ROM */

#define MCUXCLCSS_KEYPROV_VALUE_NOIC             ((uint32_t) 1u<< 0u) ///< Exclude hardware data from key calculation

#define MCUXCLCSS_KEYPROV_NOIC_DISABLE           ((uint32_t) 0u)      ///< Include hardware date into key calculation
#define MCUXCLCSS_KEYPROV_NOIC_ENABLE            ((uint32_t) 1u)      ///< Exclude hardware data from key calculation

/**
 * @}
 */
#endif /* MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV */
/**
 * @}
 */

/**********************************************
 * TYPEDEFS
 **********************************************/
/**
 * @defgroup mcuxClCss_KeyManagement_Types mcuxClCss_KeyManagement_Types
 * @brief Defines all types of @ref mcuxClCss_KeyManagement
 * @ingroup mcuxClCss_KeyManagement
 * @{
 */

/**
 * @brief Command option bit field for #mcuxClCss_KeyImport_Async
 *
 * Bit field to configure #mcuxClCss_KeyImport_Async. 
 * See @ref MCUXCLCSS_KEYIMPORT_KFMT_ for possible options in case the struct is accessed bit-wise.
 * See @ref MCUXCLCSS_KEYIMPORT_VALUE_KFMT_ for possible options in case the struct is accessed word-wise.
 */
typedef union
{
    struct
    {
        uint32_t value;     ///< Accesses the bit field as a full word; initialize with a combination of constants from @ref MCUXCLCSS_KEYIMPORT_VALUE_KFMT_
    } word;                 ///< Access #mcuxClCss_KeyImportOption_t word-wise
    struct
    {
        uint32_t :4;        ///< RFU
        uint32_t revf :1;   ///< This field is managed internally
        uint32_t :1;        ///< RFU
        uint32_t kfmt :2;   ///< Defines the key import format, one of @ref MCUXCLCSS_KEYIMPORT_KFMT_
        uint32_t :24;       ///< RFU
    } bits;                 ///< Access #mcuxClCss_KeyImportOption_t bit-wise
} mcuxClCss_KeyImportOption_t;

#if defined(MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV) || defined(MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV_ROM) 
/**
 * @brief Command option bit field for @if CSS_KEY_MGMT_KEYPROV #mcuxClCss_KeyProvision_Async @if CSS_KEY_MGMT_KEYPROV_ROM and @endif @endif @if CSS_KEY_MGMT_KEYPROV_ROM #mcuxClCss_KeyProvisionRom_Async @endif
 *
 * Bit field to configure @if CSS_KEY_MGMT_KEYPROV #mcuxClCss_KeyProvision_Async @if CSS_KEY_MGMT_KEYPROV_ROM and @endif @endif @if CSS_KEY_MGMT_KEYPROV_ROM #mcuxClCss_KeyProvisionRom_Async @endif . See @ref MCUXCLCSS_KEYPROV_ for possible options.
 */
typedef union
{
    struct
    {
        uint32_t value;     ///< Accesses the bit field as a full word; initialize with a combination of constants from @ref MCUXCLCSS_KEYPROV_
    } word;                 ///< Access #mcuxClCss_KeyProvisionOption_t word-wise
    struct
    {
        uint32_t noic :1;   ///< Defines if hardware data shall be considered for key calculation
        uint32_t :31;       ///< RFU
    } bits;                 ///< Access #mcuxClCss_KeyProvisionOption_t bit-wise
} mcuxClCss_KeyProvisionOption_t;
#endif /* MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV */
/**
 * @}
 */

/**********************************************
 * FUNCTIONS
 **********************************************/
/**
 * @defgroup mcuxClCss_KeyManagement_Functions mcuxClCss_KeyManagement_Functions
 * @brief Defines all functions of @ref mcuxClCss_KeyManagement
 * @ingroup mcuxClCss_KeyManagement
 * @{
 */

/** 
 * @brief Deletes a key from keystore at the given index.
 * 
 * Before execution, CSS will wait until #mcuxClCss_HwState_t.drbgentlvl == #MCUXCLCSS_STATUS_DRBGENTLVL_LOW. This can lead to a delay if the DRBG is in a state with less security strength at the time of the call.
 *
 * Call #mcuxClCss_WaitForOperation to complete the operation.
 *
 * @param[in]    keyIdx  The index of the key to be deleted
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @endif
 * @retval #MCUXCLCSS_STATUS_SW_INVALID_PARAM    if invalid parameters were specified
 * @retval #MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT if a running operation prevented the request
 * @retval #MCUXCLCSS_STATUS_OK_WAIT             on successful request */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_KeyDelete_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_KeyDelete_Async(
        mcuxClCss_KeyIndex_t keyIdx
);

#ifdef MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV
/** @brief Restores a provisioned key to the CSSv2 keystore.
 *
 * Call #mcuxClCss_WaitForOperation to complete the operation.
 *
 * @param[in]    options              Include/Exclude hardware data. For more information, see #mcuxClCss_KeyProvisionOption_t
 * @param[in]    pKeyPart1            External key material part 1 (fixed size of #MCUXCLCSS_KEYPROV_KEY_PART_1_SIZE)
 * @param[in]    pKeyPart2            External key material part 2
 * @param[in]    part2Length          The length of pKeyPart2 (must be at least 36 byte)
 * @param[in]    targetKeyIdx         Keystore index of the output key
 * @param[in]    targetKeyProperties  Properties of the output key
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @endif
 * @retval #MCUXCLCSS_STATUS_SW_INVALID_PARAM    if invalid parameters were specified
 * @retval #MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT if a running operation prevented the request
 * @retval #MCUXCLCSS_STATUS_OK_WAIT             on successful request */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_KeyProvision_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_KeyProvision_Async(
        mcuxClCss_KeyProvisionOption_t options,
        uint8_t const * pKeyPart1,
        uint8_t const * pKeyPart2,
        size_t part2Length,
        mcuxClCss_KeyIndex_t targetKeyIdx,
        mcuxClCss_KeyProp_t targetKeyProperties
);
#endif /* MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV */

#ifdef MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV_ROM
/** @brief Restores a provisioned key to the CSSv2 keystore.  
 *                                                          
 * Call #mcuxClCss_WaitForOperation to complete the operation.
 *
 * @param[in]    options              Include/Exclude hardware data. For more information, see #mcuxClCss_KeyProvisionOption_t
 * @param[in]    pTesterShare         External Tester Share (fixed size of #MCUXCLCSS_KEYPROV_TESTERSHARE_SIZE)
 * @param[in]    keyShareIdx          Key share table index for the input key shares (up to #MCUXCLCSS_KEYPROV_KEYSHARE_TABLE_SIZE)
 * @param[in]    targetKeyIdx         Keystore index of the output key
 * @param[in]    targetKeyProperties  Properties of the output key
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @endif
 * @retval #MCUXCLCSS_STATUS_SW_INVALID_PARAM    if invalid parameters were specified
 * @retval #MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT if a running operation prevented the request
 * @retval #MCUXCLCSS_STATUS_OK_WAIT             on successful request */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_KeyProvisionRom_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_KeyProvisionRom_Async(
        mcuxClCss_KeyProvisionOption_t options,
        uint8_t const * pTesterShare,
        uint32_t keyShareIdx,
        mcuxClCss_KeyIndex_t targetKeyIdx,
        mcuxClCss_KeyProp_t targetKeyProperties
);
#endif /* MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV_ROM */

/** @brief Imports a key from external storage to an internal key register.
 * 
 * @if CSS_AES_WITH_SIDE_CHANNEL_PROTECTION
 * Before execution, CSS will wait until #mcuxClCss_HwState_t.drbgentlvl == #MCUXCLCSS_STATUS_DRBGENTLVL_LOW. This can lead to a delay if the DRBG is in a state with less security strength at the time of the call.
 * @endif
 *
 * Call #mcuxClCss_WaitForOperation to complete the operation.
 *
 * @param[in]    options          One of @ref MCUXCLCSS_KEYIMPORT_KFMT_
 * @param[in]    pImportKey       Pointer to the RFC3394 container of the key to be imported
 * @param[in]    importKeyLength  Length of the RFC3394 container of the key to be imported
 * @param[in]    wrappingKeyIdx   Index of the key wrapping key, if importing RFC3394 format
 * @param[in]    targetKeyIdx     The desired key index of the imported key
 *
 *  <dl>
 *   <dt>Parameter properties</dt>
 *   <dd><dl>
 *     <dt>@p options.kfmt != #MCUXCLCSS_KEYIMPORT_KFMT_RFC3394</dt><dd>
 *       <ul style="list-style: none;">
 *         <li>@p pImportKey is ignored.</li>
 *         <li>@p importKeyLength is ignored.</li>
 *         <li>@p wrappingKeyIdx is ignored.</li>
 *         <li>@p targetKeyIdx is ignored. The unpacked key is automatically stored in key slots 0, 1.</li>
 *       </ul></dd>
 *     </dt>
 *   </dl></dd>
 *  </dl>
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @endif
 * @retval #MCUXCLCSS_STATUS_SW_INVALID_PARAM    if invalid parameters were specified
 * @retval #MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT if a running operation prevented the request
 * @retval #MCUXCLCSS_STATUS_OK_WAIT             on successful request */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_KeyImport_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_KeyImport_Async(
    mcuxClCss_KeyImportOption_t options,
    uint8_t const * pImportKey,
    size_t importKeyLength,
    mcuxClCss_KeyIndex_t wrappingKeyIdx,
    mcuxClCss_KeyIndex_t targetKeyIdx
    );

#ifdef MCUXCL_FEATURE_CSS_PUK_INTERNAL
/** @brief Imports a public key to an internal key register if the signature verification of the provided public key against
 *         the provided signature is correct.
 * 
 * Call #mcuxClCss_WaitForOperation to complete the operation.
 *
 * @param[in]    pCertificate       Pointer to the Certificate structure
 * @param[in]    certificateLength  Length of the Certificate structure
 * @param[in]    publicKeyOffset    Offset of the Public key to be imported within @p pCertificate
 * @param[in]    pSignature         Signed challenge used to authenticate the imported key. Must be word aligned
 * @param[in]    verifyingKeyIdx    The key index of the verifying public key
 * @param[in]    keyProperties      The desired key properties of the imported key
 * @param[in]    targetKeyIdx       The desired key index of the imported key
 * @param[out]   pOutput            Pointer to the memory area which will receive the recalculated value of the R component in case of a successful
 *                                  certificate verification. Must be word aligned
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @endif
 * @retval #MCUXCLCSS_STATUS_SW_INVALID_PARAM    if invalid parameters were specified
 * @retval #MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT if a running operation prevented the request
 * @retval #MCUXCLCSS_STATUS_OK_WAIT             on successful request */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_KeyImportPuk_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_KeyImportPuk_Async(
    uint8_t const * pCertificate,
    size_t certificateLength,
    size_t publicKeyOffset,
    uint8_t const * pSignature,
    mcuxClCss_KeyIndex_t verifyingKeyIdx,
    mcuxClCss_KeyProp_t keyProperties,
    mcuxClCss_KeyIndex_t targetKeyIdx,
    uint8_t * pOutput	
    );
#endif /* MCUXCL_FEATURE_CSS_PUK_INTERNAL */

/** @brief Exports a key from an internal key register to external storage, using a wrapping key.
 * 
 * @if CSS_AES_WITH_SIDE_CHANNEL_PROTECTION
 * Before execution, CSS will wait until #mcuxClCss_HwState_t.drbgentlvl == #MCUXCLCSS_STATUS_DRBGENTLVL_LOW. This can lead to a delay if the DRBG is in a state with less security strength at the time of the call.
 * @endif
 *
 * Call #mcuxClCss_WaitForOperation to complete the operation.
 *
 * @param[in]    wrappingKeyIdx     The key used for key wrapping
 * @param[in]    exportKeyIdx       The key to export
 * @param[out]   pOutput            The memory address of the exported key
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @endif
 * @retval #MCUXCLCSS_STATUS_SW_INVALID_PARAM    if invalid parameters were specified
 * @retval #MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT if a running operation prevented the request
 * @retval #MCUXCLCSS_STATUS_OK_WAIT             on successful request */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_KeyExport_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_KeyExport_Async(
    mcuxClCss_KeyIndex_t wrappingKeyIdx, ///< [in]  The key used for key wrapping
    mcuxClCss_KeyIndex_t exportKeyIdx,   ///< [in]  The key to export
    uint8_t * pOutput                   ///< [out] The memory address of the exported key
    );

/** @brief Exports the properties of the keys stored in the CSS internal keystore
 *
 * Call #mcuxClCss_WaitForOperation to complete the operation.
 *
 * @param[in]    keyIdx     Request key properties of the index defined here
 * @param[out]   pKeyProp   Key properties of the index provided
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @endif
 * @retval #MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT if a running operation prevented the request
 * @retval #MCUXCLCSS_STATUS_OK                  on successful request */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_GetKeyProperties)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_GetKeyProperties(
    mcuxClCss_KeyIndex_t keyIdx,
    mcuxClCss_KeyProp_t * pKeyProp
    );

/**
 * @}
 */
#endif /* MCUXCLCSS_KEYMANAGEMENT_H_ */

/**
 * @}
 */
