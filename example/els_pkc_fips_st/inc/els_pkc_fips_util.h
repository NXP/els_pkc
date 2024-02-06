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

/* Execute all fips self tests */
#define FIPS_ALL_TESTS (1 << 0)

/* AES */
#define FIPS_AES_CBC_128 (1 << 1)
#define FIPS_AES_CBC_192 (1 << 2)
#define FIPS_AES_CBC_256 (1 << 3)
#define FIPS_AES_ECB_128 (1 << 4)
#define FIPS_AES_ECB_192 (1 << 5)
#define FIPS_AES_ECB_256 (1 << 6)
#define FIPS_AES_CTR_128 (1 << 7)
#define FIPS_AES_CTR_192 (1 << 8)
#define FIPS_AES_CTR_256 (1 << 9)
#define FIPS_AES_GCM_128 (1 << 10)
#define FIPS_AES_GCM_192 (1 << 11)
#define FIPS_AES_GCM_256 (1 << 12)
#define FIPS_AES_CCM_128 (1 << 13)
#define FIPS_AES_CCM_192 (1 << 14)
#define FIPS_AES_CCM_256 (1 << 15)

/* KDF */
#define FIPS_CKDF (1 << 16)
#define FIPS_HKDF (1 << 17)

/* DRBG */
#define FIPS_CTR_DRBG (1 << 18)
#define FIPS_ECB_DRBG (1 << 19)

/* ECC,ECDH */
#define FIPS_EDDSA      (1 << 20)
#define FIPS_ECDSA_256P (1 << 21)
#define FIPS_ECDSA_384P (1 << 22)
#define FIPS_ECDSA_521P (1 << 23)
#define FIPS_ECDH256P   (1 << 24)
#define FIPS_ECDH384P   (1 << 25)
#define FIPS_ECDH521P   (1 << 26)

/* RSA */
#define FIPS_RSA_PKCS15_2048 (uint64_t)((uint64_t)1 << (uint64_t)27)
#define FIPS_RSA_PKCS15_3072 (uint64_t)((uint64_t)1 << (uint64_t)28)
#define FIPS_RSA_PKCS15_4096 (uint64_t)((uint64_t)1 << (uint64_t)29)
#define FIPS_RSA_PSS_2048    (uint64_t)((uint64_t)1 << (uint64_t)30)
#define FIPS_RSA_PSS_3072    (uint64_t)((uint64_t)1 << (uint64_t)31)
#define FIPS_RSA_PSS_4096    (uint64_t)((uint64_t)1 << (uint64_t)32)

/* Import blob defines */
#define STATUS_SUCCESS       0
#define STATUS_ERROR_GENERIC 1

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

#define RET_MBEDTLS_SUCCESS_OR_EXIT_MSG(MSG, ...) \
    if (0 != ret)                                 \
    {                                             \
        status = STATUS_ERROR_GENERIC;            \
        PLOG_ERROR(MSG, __VA_ARGS__);             \
        goto exit;                                \
    }

#define STATUS_SUCCESS_OR_EXIT_MSG(MSG, ...) \
    if (STATUS_SUCCESS != status)            \
    {                                        \
        PLOG_ERROR(MSG, __VA_ARGS__);        \
        goto exit;                           \
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
