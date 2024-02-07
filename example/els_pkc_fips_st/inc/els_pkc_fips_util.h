/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _ELS_PKC_FIPS_UTIL_H_
#define _ELS_PKC_FIPS_UTIL_H_

#include "app.h"
#include <fsl_device_registers.h>
#include <fsl_debug_console.h>
#include <board.h>
#include <mcuxClAes.h>
#include <mcuxClEls.h>
#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClExample_RNG_Helper.h>
#include <mcuxClExample_ELS_Helper.h>
#include <mcuxClExample_Key_Helper.h>
#include <mcuxClAes_Constants.h>
#include <mcuxClExample_ELS_Helper.h>
#include <mcuxClHash_Constants.h>
#include <mcuxClEls_Hash.h>
#include <mcuxClEls_KeyManagement.h>
#include <mcuxClEls_Rng.h>
#include <mcuxClAes.h>
#include <mcuxClEls_Ecc.h>
#include <mcuxClEls_Kdf.h>
#include <mcuxClEls_Cipher.h>
#include <mcuxClEls_Cmac.h>
#include <mcuxClEls_Types.h>
#include "fsl_common.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "psa/crypto.h"
#include "psa/crypto_values.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/nist_kw.h"
#include "mbedtls/entropy.h"
#include "md_wrap.h"
#include "mbedtls/hkdf.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define MCUX_PKC_MIN(a, b) ((a) < (b) ? (a) : (b))

#define WEIER256_BIT_LENGTH (256U)
#define WEIER384_BIT_LENGTH (384U)
#define WEIER521_BIT_LENGTH (521U)

/* Execute all fips self tests */
#define FIPS_ALL_TESTS (1U << 0U)

/* AES */
#define FIPS_AES_CBC_128  (1U << 1U)
#define FIPS_AES_CBC_192  (1U << 2U)
#define FIPS_AES_CBC_256  (1U << 3U)
#define FIPS_AES_ECB_128  (1U << 4U)
#define FIPS_AES_ECB_192  (1U << 5U)
#define FIPS_AES_ECB_256  (1U << 6U)
#define FIPS_AES_CTR_128  (1U << 7U)
#define FIPS_AES_CTR_192  (1U << 8U)
#define FIPS_AES_CTR_256  (1U << 9U)
#define FIPS_AES_GCM_128  (1U << 10U)
#define FIPS_AES_GCM_192  (1U << 11U)
#define FIPS_AES_GCM_256  (1U << 12U)
#define FIPS_AES_CCM_128  (1U << 13U)
#define FIPS_AES_CCM_256  (1U << 14U)
#define FIPS_AES_CMAC_128 (1U << 15U)
#define FIPS_AES_CMAC_256 (1U << 16U)

/* KDF */
#define FIPS_CKDF (1U << 17U)
#define FIPS_HKDF (1U << 18U)

/* DRBG */
#define FIPS_CTR_DRBG (1U << 19U)
#define FIPS_ECB_DRBG (1U << 20U)

/* ECC, ECDH */
#define FIPS_EDDSA           (1U << 21U)
#define FIPS_ECDSA_256P      (1U << 22U)
#define FIPS_ECDSA_384P      (1U << 23U)
#define FIPS_ECDSA_521P      (1U << 24U)
#define FIPS_ECDH256P        (1U << 25U)
#define FIPS_ECDH384P        (uint64_t)((uint64_t)1U << (uint64_t)26U)
#define FIPS_ECDH521P        (uint64_t)((uint64_t)1U << (uint64_t)27U)
#define FIPS_ECC_KEYGEN_256P (uint64_t)((uint64_t)1U << (uint64_t)28U)
#define FIPS_ECC_KEYGEN_384P (uint64_t)((uint64_t)1U << (uint64_t)29U)
#define FIPS_ECC_KEYGEN_521P (uint64_t)((uint64_t)1U << (uint64_t)30U)

/* RSA */
#define FIPS_RSA_PKCS15_2048 (uint64_t)((uint64_t)1U << (uint64_t)31U)
#define FIPS_RSA_PKCS15_3072 (uint64_t)((uint64_t)1U << (uint64_t)32U)
#define FIPS_RSA_PKCS15_4096 (uint64_t)((uint64_t)1U << (uint64_t)33U)
#define FIPS_RSA_PSS_2048    (uint64_t)((uint64_t)1U << (uint64_t)34U)
#define FIPS_RSA_PSS_3072    (uint64_t)((uint64_t)1U << (uint64_t)35U)
#define FIPS_RSA_PSS_4096    (uint64_t)((uint64_t)1U << (uint64_t)36U)

/* HMAC */
#define FIPS_HMAC_SHA224 (uint64_t)((uint64_t)1U << (uint64_t)37U)
#define FIPS_HMAC_SHA256 (uint64_t)((uint64_t)1U << (uint64_t)38U)
#define FIPS_HMAC_SHA384 (uint64_t)((uint64_t)1U << (uint64_t)39U)
#define FIPS_HMAC_SHA512 (uint64_t)((uint64_t)1U << (uint64_t)40U)

/* SHA */
#define FIPS_SHA224 (uint64_t)((uint64_t)1U << (uint64_t)41U)
#define FIPS_SHA256 (uint64_t)((uint64_t)1U << (uint64_t)42U)
#define FIPS_SHA384 (uint64_t)((uint64_t)1U << (uint64_t)43U)
#define FIPS_SHA512 (uint64_t)((uint64_t)1U << (uint64_t)44U)

/* Import blob defines */
#define STATUS_SUCCESS       0U
#define STATUS_ERROR_GENERIC 1U

#define AES_BLOCK_SIZE      16U
#define DIE_INT_MK_SK_INDEX 0U

#define ELS_BLOB_METADATA_SIZE 8U
#define MAX_ELS_KEY_SIZE       32U
#define ELS_WRAP_OVERHEAD      8U

/* Defines for logging */
#define PLOG_ERROR(...)                           \
    for (;;)                                      \
    {                                             \
        PRINTF("ERROR  ");                        \
        PRINTF(__VA_ARGS__);                      \
        PRINTF(" (%s:%d)\n", __FILE__, __LINE__); \
        break;                                    \
    }

#define PLOG_INFO(...)       \
    for (;;)                 \
    {                        \
        PRINTF("INFO  ");    \
        PRINTF(__VA_ARGS__); \
        PRINTF("\n");        \
        break;               \
    }

#define PLOG_DEBUG(...)      \
    for (;;)                 \
    {                        \
        PRINTF("DEBUG  ");   \
        PRINTF(__VA_ARGS__); \
        PRINTF("\n");        \
        break;               \
    }

#define RET_MBEDTLS_SUCCESS_OR_EXIT()  \
    if (0U != ret)                     \
    {                                  \
        status = STATUS_ERROR_GENERIC; \
        goto exit;                     \
    }

#define STATUS_SUCCESS_OR_EXIT()  \
    if (STATUS_SUCCESS != status) \
    {                             \
        goto exit;                \
    }

#define PRINT_ARRAY(array, array_size)                                                             \
    do                                                                                             \
    {                                                                                              \
        PRINTF("0x");                                                                              \
        for (uint64_t print_array_index = 0U; print_array_index < array_size; ++print_array_index) \
        {                                                                                          \
            PRINTF("%02X", array[print_array_index]);                                              \
        }                                                                                          \
        PRINTF("\r\n");                                                                            \
    } while (0U);

/*!
 * @brief Import plain key into els keystore.
 *
 * @param plain_key Plain key to import to keystore.
 * @param plain_key_size Size of plain key.
 * @param key_properties The key properties of the key to import.
 * @param index_output Output index at keyslot of imported key.
 * @retval STATUS_SUCCESS If import was successful.
 * @retval STATUS_ERROR_GENERIC If import was unsuccessful.
 */
status_t import_plain_key_into_els(const uint8_t *plain_key,
                                   size_t plain_key_size,
                                   mcuxClEls_KeyProp_t key_properties,
                                   mcuxClEls_KeyIndex_t *index_output);

/*!
 * @brief Execute Ckdf with mbedTLS.
 *
 * @param input_key Input key to derive.
 * @param input_key_size Size of input key.
 * @param derivation_data Derivation data for Ckdf.
 * @param derivation_data_size Size of derivation data.
 * @param key_properties The key properties of the derived key.
 * @param output Output derived key.
 * @param output_size Size of derived output key.
 * @retval STATUS_SUCCESS If derivation was successful.
 * @retval STATUS_ERROR_GENERIC If derivation was unsuccessful.
 */
status_t host_derive_key(const uint8_t *input_key,
                         size_t input_key_size,
                         const uint8_t *derivation_data,
                         size_t derivation_data_size,
                         uint32_t key_properties,
                         uint8_t *output,
                         size_t *output_size);

/*!
 * @brief Delete key in els keystore.
 *
 * @param key_index Index of key to delete.
 * @retval STATUS_SUCCESS If deletion was successful.
 * @retval STATUS_ERROR_GENERIC If deletion was unsuccessful.
 */
status_t els_delete_key(mcuxClEls_KeyIndex_t key_index);

/*!
 * @brief Get index of free keyslot in els.
 *
 * @param required_keyslots Amount of required keyslots.
 * @retval mcuxClEls_KeyIndex_t Free key index.
 */
mcuxClEls_KeyIndex_t els_get_free_keyslot(uint32_t required_keyslots);

/*!
 * @brief Els key generation.
 *
 * @param key_index Index of key to generate key from.
 * @param public_key Public key generated.
 * @param public_key_size Public key size.
 * @retval STATUS_SUCCESS If generation was successful.
 * @retval STATUS_ERROR_GENERIC If generation was unsuccessful.
 */
status_t els_keygen(mcuxClEls_KeyIndex_t key_index, uint8_t *public_key, size_t *public_key_size);

#endif /* _ELS_PKC_FIPS_UTIL_H_ */
