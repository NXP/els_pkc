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
 * @file mcuxClCss_Rng.h
 * @brief CSSv2 header for random number generation.
 * This header exposes functions to configure the CSSv2 RNGs (DRBG and DTRNG) and to generate random data.
 */

#ifndef MCUXCLCSS_RNG_H_
#define MCUXCLCSS_RNG_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCss_Common.h> // Common functionality


/**
 * @defgroup mcuxClCss_Rng mcuxClCss_Rng
 * @brief This part of the @ref mcuxClCss driver supports functionality for random number generation
 * @ingroup mcuxClCss
 * @{
 */


/**********************************************
 * CONSTANTS
 **********************************************/
/**
 * @defgroup mcuxClCss_Rng_Macros mcuxClCss_Rng_Macros
 * @brief Defines all macros of @ref mcuxClCss_Rng
 * @ingroup mcuxClCss_Rng
 * @{
 */
#define MCUXCLCSS_RNG_DTRNG_CONFIG_SIZE       ((uint8_t) 84)   ///< Size of DTRNG configuration
#define MCUXCLCSS_RNG_DTRNG_EVAL_CONFIG_SIZE  ((uint8_t) 52)   ///< Size of DTRNG characterization data
#define MCUXCLCSS_RNG_DTRNG_EVAL_RESULT_SIZE  ((uint8_t) 188)  ///< Size of DTRNG characterization result

#define MCUXCLCSS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MIN_SIZE  4U                      ///< Minimum output size of #mcuxClCss_Rng_DrbgTestExtract_Async
#define MCUXCLCSS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MAX_SIZE  ((uint32_t) 1U << 16U)  ///< Maximum output size of #mcuxClCss_Rng_DrbgTestExtract_Async

#define MCUXCLCSS_RNG_DRBG_TEST_MODE_INSTANTIATE ((uint32_t) 0U) ///< Command options value for DRBG Test Instantiate command. For internal use
#define MCUXCLCSS_RNG_DRBG_TEST_MODE_EXTRACT     ((uint32_t) 1U) ///< Command options value for DRBG Test Extract command. For internal use
#define MCUXCLCSS_RNG_DRBG_TEST_MODE_AES_ECB     ((uint32_t) 3U) ///< Command options value for DRBG Test AES-ECB command. For internal use
#define MCUXCLCSS_RNG_DRBG_TEST_MODE_AES_CTR     ((uint32_t) 2U) ///< Command options value for DRBG Test AES-CTR command. For internal use

#ifdef MCUXCL_FEATURE_CSS_RND_RAW
#define MCUXCLCSS_RNG_RND_REQ_RND_RAW            ((uint32_t) 1U << 1) ///< Command options value for RND_REQ command. For internal use
#define MCUXCLCSS_RNG_RAW_ENTROPY_SIZE           ((uint32_t) 32U)     ///< Fixed size of raw entropy when using the DTRNG
#endif /* MCUXCL_FEATURE_CSS_RND_RAW */
#ifdef MCUXCL_FEATURE_CSS_PRND_INIT
#define MCUXCLCSS_RNG_RND_REQ_PRND_INIT          ((uint32_t) 1U << 0) ///< Command options value for PRND_INIT command. For internal use
#endif /* MCUXCL_FEATURE_CSS_PRND_INIT */
/**
 * @}
 */


/**********************************************
 * FUNCTIONS
 **********************************************/
/**
 * @defgroup mcuxClCss_Rng_Functions mcuxClCss_Rng_Functions
 * @brief Defines all functions of @ref mcuxClCss_Rng
 * @ingroup mcuxClCss_Rng
 * @{
 */

/**
 * @brief Writes random data from the CSS DRBG to the given buffer.
 *
 * This function fills a buffer with random values from the DRBG. The DRBG provides 128 bits of security strength.
 *
 * Before execution, CSS will wait until #mcuxClCss_HwState_t.drbgentlvl == #MCUXCLCSS_STATUS_DRBGENTLVL_HIGH. This can lead to a delay if the DRBG is in a state with less security strength at the time of the call.
 *
 * If the random values from the DRBG are later used as a cryptographic key, the security strength of the cryptographic operation using the generated key should not exceed that of the DRBG.
 *
 * To name a few examples, this means (as per NIST SP 800-57 Part 1 Rev. 5):
 * - AES-192 or AES-256 keys generated with this function will provide only 128 bits of security strength
 * - RSA keys longer than 3072 bits will provide only 128 bits of security strength
 * - ECC keys longer than 383 bits will provide only 128 bits of security strength
 *
 * Call #mcuxClCss_WaitForOperation to complete the operation.
 *
 * @param[out] pOutput       Pointer to the beginning of the memory area to fill with random data
 * @param[in]  outputLength  Number of requested random bytes
 *
 * <dl>
 *   <dt>Parameter properties</dt>
 *   <dd><dl>
 *     <dt>@p outputLength </dt>
 *       <dd>supported values are #MCUXCLCSS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MIN_SIZE bytes up to
 *           #MCUXCLCSS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MAX_SIZE bytes. The size must be a multiple of 4.</dd>
 *   </dl></dd>
 * </dl>
 * 
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @endif
 * @retval #MCUXCLCSS_STATUS_SW_INVALID_PARAM    if invalid parameters were specified
 * @retval #MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT if a running operation prevented the request
 * @retval #MCUXCLCSS_STATUS_OK_WAIT             on successful request
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_Rng_DrbgRequest_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Rng_DrbgRequest_Async(
    uint8_t * pOutput,
    size_t outputLength
    );

#ifdef MCUXCL_FEATURE_CSS_RND_RAW
/**
 * @brief Writes 32 bytes of raw random data from the CSS TRNG to the given buffer.
 *
 * This function fills a buffer with raw (unprocessed) random values from the TRNG. 
 *
 * Call #mcuxClCss_WaitForOperation to complete the operation.
 *
 * @param[out] pOutput       Pointer to the beginning of the memory area to fill with random data
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @endif
 * @retval #MCUXCLCSS_STATUS_SW_INVALID_PARAM    if invalid parameters were specified
 * @retval #MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT if a running operation prevented the request
 * @retval #MCUXCLCSS_STATUS_OK_WAIT             on successful request
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_Rng_DrbgRequestRaw_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Rng_DrbgRequestRaw_Async(
    uint8_t * pOutput
    );
#endif /* MCUXCL_FEATURE_CSS_RND_RAW */

/**
 * @brief Instantiates the DRBG in test mode.
 *
 * This function is a support function for FIPS CAVP testing. This function turns the CSS internal DRBG in test mode by loading known entropy from system memory.
 * Call #mcuxClCss_WaitForOperation to complete the operation.
 * Note that this function will alter the CSS internal entropy state which needs to be updated by the TRNG to use the DRBG in normal mode.
 * The update process is majorly impacted by the time the TRNG needs to provide fresh entropy.
 *
 * @param[in] pEntropy  Pointer to the input entropy data
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @endif
 * @retval #MCUXCLCSS_STATUS_SW_INVALID_PARAM    if invalid parameters were specified
 * @retval #MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT if a running operation prevented the request
 * @retval #MCUXCLCSS_STATUS_OK_WAIT             on successful request
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_Rng_DrbgTestInstantiate_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Rng_DrbgTestInstantiate_Async(
    uint8_t const * pEntropy
    );

/**
 * @brief Performs a DRBG extraction.
 *
 * This function is a support function for FIPS CAVP testing. This function mimics the behavior of #mcuxClCss_Rng_DrbgRequest_Async and fills a buffer with random data when DRBG is in test mode.
 * Call #mcuxClCss_WaitForOperation to complete the operation.
 * Note that this function will alter the CSS internal entropy state which needs to be updated by the TRNG to use the DRBG in normal mode.
 * The update process is majorly impacted by the time the TRNG needs to provide fresh entropy.
 *
 * @attention #mcuxClCss_Rng_DrbgTestInstantiate_Async must be called prior to this function.
 *
 * @param[out] pOutput       Pointer to the output random number
 * @param[in]  outputLength  Length of the random number
 *
 * <dl>
 *   <dt>Parameter properties</dt>
 *   <dd><dl>
 *     <dt>@p outputLength </dt>
 *       <dd>supported values are #MCUXCLCSS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MIN_SIZE bytes up to
 *           #MCUXCLCSS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MAX_SIZE bytes. The size must be a multiple of 4.</dd>
 *   </dl></dd>
 * </dl>
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref MCUXCLCSS_STATUS_ and @ref mcuxCsslFlowProtection)
 * @else
 *  @return An error code (see @ref MCUXCLCSS_STATUS_)
 * @endif
 * @retval #MCUXCLCSS_STATUS_SW_INVALID_PARAM    if invalid parameters were specified
 * @retval #MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT if a running operation prevented the request
 * @retval #MCUXCLCSS_STATUS_OK_WAIT             on successful request
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_Rng_DrbgTestExtract_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Rng_DrbgTestExtract_Async(
    uint8_t * pOutput,
    size_t outputLength
    );

/**
 * @brief Encrypts data using the AES-ECB engine of the DRBG.
 *
 * This function is a support function for FIPS CAVP testing. This function performs an AES-ECB encryption on system data to evaluate the encryption engine of the DRBG.
 * Call #mcuxClCss_WaitForOperation to complete the operation.
 * Note that this function will alter the CSS internal entropy state which needs to be updated by the TRNG to use the DRBG in normal mode.
 * The update process is majorly impacted by the time the TRNG needs to provide fresh entropy.
 *
 * @param[in]  pDataKey  Pointer to the data and key
 * @param[out] pOutput   Pointer to the encrypted output
 *
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @endif
 * @retval #MCUXCLCSS_STATUS_SW_INVALID_PARAM    if invalid parameters were specified
 * @retval #MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT if a running operation prevented the request
 * @retval #MCUXCLCSS_STATUS_OK_WAIT             on successful request
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_Rng_DrbgTestAesEcb_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Rng_DrbgTestAesEcb_Async(
    uint8_t const * pDataKey,
    uint8_t * pOutput
    );

/**
 * @brief Encrypts data using the AES-CTR engine of the DRBG.
 *

 * This function is a support function for FIPS CAVP testing. This function performs an AES-CTR encryption on system data to evaluate the encryption engine of the DRBG in test mode.
 * Call #mcuxClCss_WaitForOperation to complete the operation.
 * Note that this function will alter the CSS internal entropy state which needs to be updated by the TRNG to use the DRBG in normal mode.
 * The update process is majorly impacted by the time the TRNG needs to provide fresh entropy.
 *
 * @param[in]  pData       Pointer to the data to be encrypted
 * @param[in]  dataLength  Length of the data to be encrypted
 * @param[in]  pIvKey      Pointer to the IV and key
 * @param[out] pOutput     Pointer to the encrypted output
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @endif
 * @retval #MCUXCLCSS_STATUS_SW_INVALID_PARAM    if invalid parameters were specified
 * @retval #MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT if a running operation prevented the request
 * @retval #MCUXCLCSS_STATUS_OK_WAIT             on successful request
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_Rng_DrbgTestAesCtr_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Rng_DrbgTestAesCtr_Async(
    uint8_t const * pData,
    size_t dataLength,
    uint8_t const * pIvKey,
    uint8_t * pOutput
    );

/**
 * @brief Loads a configuration of the CSS DTRNG.
 *
 * This function overwrites the default DTRNG configuration in order to optimize or fine tune the DTRNG entropy gathering process.
 * Call #mcuxClCss_WaitForOperation to complete the operation.
 * Note that the TRNG configuration set by this function is non-persistent and any reset of the Css (e.g. a power-cycle or calling #mcuxClCss_Reset_Async) will resets the DTRNG configuration to its default value.
 *
 * @if MCUXCL_FEATURE_CSS_SHA_DIRECT
 * It must be ensured that SHA-Direct mode is disabled when calling this function (see #mcuxClCss_ShaDirect_Disable).
 * @endif
 *
 * @param[in] pInput  The pointer to DTRNG initialization data
 *
 * <dl>
 *   <dt>Parameter properties</dt>
 *   <dd><dl>
 *     <dt>@p pInput </dt>
 *       <dd>The size is #MCUXCLCSS_RNG_DTRNG_CONFIG_SIZE bytes.</dd>
 *   </dl></dd>
 * </dl>
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @endif
 * @retval #MCUXCLCSS_STATUS_SW_INVALID_PARAM    if invalid parameters were specified
 * @retval #MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT if a running operation prevented the request
 * @retval #MCUXCLCSS_STATUS_OK_WAIT             on successful request
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_Rng_Dtrng_ConfigLoad_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Rng_Dtrng_ConfigLoad_Async(
    uint8_t const * pInput
    );


/**
 * @brief Performs characterization of the CSS DTRNG.
 *
 * This function evaluates a DTRNG configuration for device specific characterization. The configuration used for characterization has to be placed in system memory.
 * Call #mcuxClCss_WaitForOperation to complete the operation.
 *
 * @attention If this function is called once, all other CSS commands except #mcuxClCss_Rng_Dtrng_ConfigEvaluate_Async are blocked until any reset of the Css (e.g. a power-cycle or calling #mcuxClCss_Reset_Async) is triggered.
 *
 * @param[in]  pInput  The pointer to DTRNG initialization data
 * @param[out] pOutput The pointer to the evaluation result
 *
 * <dl>
 *   <dt>Parameter properties</dt>
 *   <dd><dl>
 *     <dt>@p pInput </dt>
 *       <dd>The size is #MCUXCLCSS_RNG_DTRNG_EVAL_CONFIG_SIZE bytes.</dd>
 *     <dt>@p pOutput </dt>
 *       <dd>The size is #MCUXCLCSS_RNG_DTRNG_EVAL_RESULT_SIZE bytes.</dd>
 *   </dl></dd>
 * </dl>
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @endif
 * @retval #MCUXCLCSS_STATUS_SW_INVALID_PARAM    if invalid parameters were specified
 * @retval #MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT if a running operation prevented the request
 * @retval #MCUXCLCSS_STATUS_OK_WAIT             on successful request
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_Rng_Dtrng_ConfigEvaluate_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Rng_Dtrng_ConfigEvaluate_Async(
    uint8_t const * pInput,
    uint8_t * pOutput
    );

#ifdef MCUXCL_FEATURE_CSS_PRND_INIT
/**
 * @brief Initializes the CSS PRNG.
 *
 * This function initializes the PRNG. After this operation #mcuxClCss_HwState_t.drbgentlvl == #MCUXCLCSS_STATUS_DRBGENTLVL_LOW. This can lead to a delay if the DRBG is in a state with lower security strength at the time of the call.
 *
 * Call #mcuxClCss_WaitForOperation to complete the operation.
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @endif
 * @retval #MCUXCLCSS_STATUS_SW_CANNOT_INTERRUPT if a running operation prevented the request
 * @retval #MCUXCLCSS_STATUS_OK_WAIT             on successful request
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_Prng_Init_Async)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Prng_Init_Async(void);
#endif /* MCUXCL_FEATURE_CSS_PRND_INIT */

/**
 * @brief Returns one random word from the CSS PRNG.
 *
 * This function returns one low-quality random CPU word gathered from the PRNG.
 *
 * @attention PRNG has to be initialized prior to the first time calling this function.
 *
 * @param[out] pWord  The pointer to the random word
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @endif
 * @retval #MCUXCLCSS_STATUS_OK  on successful request
 * @retval #MCUXCLCSS_STATUS_HW_PRNG in case of insufficient entropy
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_Prng_GetRandomWord)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Prng_GetRandomWord(
    uint32_t * pWord
    );

/**
 * @brief Writes random data from the CSS PRNG to the given buffer.
 *
 * This function fills a buffer with low-quality random values gathered from the PRNG.
 *
 * @attention PRNG has to be initialized prior to the first time calling this function.
 *
 * @param[out] pOutput       Pointer to the beginning of the memory area to fill with random data from PRNG
 * @param[in]  outputLength  Size of @p pOutput in bytes
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @endif
 * @retval #MCUXCLCSS_STATUS_OK  on successful request
 * @retval #MCUXCLCSS_STATUS_HW_PRNG in case of insufficient entropy
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_Prng_GetRandom)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_Prng_GetRandom(
    uint8_t * pOutput,
    size_t outputLength
    );

/**
 * @}
 */ /* mcuxClCss_Rng_Functions */


/**
 * @}
 */ /* mcuxClCss_Rng */

#endif /* MCUXCLCSS_RNG_H_ */
