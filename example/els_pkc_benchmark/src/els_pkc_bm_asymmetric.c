/*
 * Copyright 2023 NxP
 * All rights reserved.
 *
 * SPDx-License-Identifier: BSD-3-Clause
 */

#include "els_pkc_bm_asymmetric.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define RAM_START_ADDRESS MCUXCLPKC_RAM_START_ADDRESS
#define MAX_CPUWA_SIZE                                                    \
    MCUXCLEXAMPLE_MAX(MCUXCLECC_EDDSA_GENERATEKEYPAIR_ED25519_WACPU_SIZE, \
                      MCUXCLECC_EDDSA_GENERATESIGNATURE_ED25519_WACPU_SIZE)
#define MAX_PKCWA_SIZE                                                    \
    MCUXCLEXAMPLE_MAX(MCUXCLECC_EDDSA_GENERATEKEYPAIR_ED25519_WAPKC_SIZE, \
                      MCUXCLECC_EDDSA_GENERATESIGNATURE_ED25519_WAPKC_SIZE)
#define MESSAGE_SMALL 64U
#define MESSAGE_LARGE 2048U

#define RSA_KEY_BIT_LENGTH        (2048U)                   /* The example uses a 2048-bit key */
#define RSA_KEY_BYTE_LENGTH       (RSA_KEY_BIT_LENGTH / 8U) /* Converting the key-bitlength to bytelength */
#define RSA_PSS_SALT_LENGTH       (0U)                      /* The salt length is set to 0 in this example */
#define RSA_MESSAGE_DIGEST_LENGTH (32U) /* The example uses a Sha2-256 digest, which is 32 bytes long */

#define GENERATE_RSA_SIGNATURE(data_from_ram, session, private_key, m_length)                                          \
    do                                                                                                                 \
    {                                                                                                                  \
        if (data_from_ram)                                                                                             \
        {                                                                                                              \
            MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(                                                                          \
                sign_result, sign_token,                                                                               \
                mcuxClRsa_sign(session, &private_key,                                                                  \
                               m_length == 32U ? s_MessageDigest32ByteRSA : s_MessageDigest64ByteRSA,                  \
                               m_length == 32U ? sizeof(s_MessageDigest32ByteRSA) : sizeof(s_MessageDigest64ByteRSA),  \
                               m_length == 32U ? (mcuxClRsa_SignVerifyMode_t *)&mcuxClRsa_Mode_Sign_Pss_Sha2_256 :     \
                                                 (mcuxClRsa_SignVerifyMode_t *)&mcuxClRsa_Mode_Sign_Pss_Sha2_512,      \
                               RSA_PSS_SALT_LENGTH, MCUXCLRSA_OPTION_MESSAGE_DIGEST, s_SignatureBuffer));              \
            if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_sign) != sign_token || MCUXCLRSA_STATUS_SIGN_OK != sign_result) \
            {                                                                                                          \
                PRINTF("[Error] RSA signature generation failed\r\n");                                                 \
                return MCUXCLEXAMPLE_STATUS_ERROR;                                                                     \
            }                                                                                                          \
            MCUX_CSSL_FP_FUNCTION_CALL_END();                                                                          \
        }                                                                                                              \
        else                                                                                                           \
        {                                                                                                              \
            MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(                                                                          \
                sign_result, sign_token,                                                                               \
                mcuxClRsa_sign(                                                                                        \
                    session, &private_key,                                                                             \
                    m_length == 32U ? s_MessageDigest32ByteRSAFlash : s_MessageDigest64ByteRSAFlash,                   \
                    m_length == 32U ? sizeof(s_MessageDigest32ByteRSAFlash) : sizeof(s_MessageDigest64ByteRSAFlash),   \
                    m_length == 32U ? (mcuxClRsa_SignVerifyMode_t *)&mcuxClRsa_Mode_Sign_Pss_Sha2_256 :                \
                                      (mcuxClRsa_SignVerifyMode_t *)&mcuxClRsa_Mode_Sign_Pss_Sha2_512,                 \
                    RSA_PSS_SALT_LENGTH, MCUXCLRSA_OPTION_MESSAGE_DIGEST, s_SignatureBuffer));                         \
            if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_sign) != sign_token || MCUXCLRSA_STATUS_SIGN_OK != sign_result) \
            {                                                                                                          \
                PRINTF("[Error] RSA signature generation failed\r\n");                                                 \
                return MCUXCLEXAMPLE_STATUS_ERROR;                                                                     \
            }                                                                                                          \
            MCUX_CSSL_FP_FUNCTION_CALL_END();                                                                          \
        }                                                                                                              \
    } while (0);

#define RSA_VERIFY(data_from_ram, session, public_key, m_length)                                                     \
    do                                                                                                               \
    {                                                                                                                \
        uint8_t encodedMessage[32];                                                                                  \
        if (data_from_ram)                                                                                           \
        {                                                                                                            \
            MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(                                                                        \
                verify_result, verify_token,                                                                         \
                mcuxClRsa_verify(                                                                                    \
                    session, &public_key, m_length == 32U ? s_MessageDigest32ByteRSA : s_MessageDigest64ByteRSA,     \
                    m_length == 32U ? sizeof(s_MessageDigest32ByteRSA) : sizeof(s_MessageDigest64ByteRSA),           \
                    s_SignatureBuffer,                                                                               \
                    m_length == 32U ? (mcuxClRsa_SignVerifyMode_t *)&mcuxClRsa_Mode_Verify_Pss_Sha2_256 :            \
                                      (mcuxClRsa_SignVerifyMode_t *)&mcuxClRsa_Mode_Verify_Pss_Sha2_512,             \
                    RSA_PSS_SALT_LENGTH, MCUXCLRSA_OPTION_MESSAGE_DIGEST, encodedMessage));                          \
            if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_verify) != verify_token) ||                                  \
                (MCUXCLRSA_STATUS_VERIFY_OK != verify_result))                                                       \
            {                                                                                                        \
                PRINTF("[Error] RSA signature verification failed\r\n");                                             \
                return MCUXCLEXAMPLE_STATUS_ERROR;                                                                   \
            }                                                                                                        \
            MCUX_CSSL_FP_FUNCTION_CALL_END();                                                                        \
        }                                                                                                            \
        else                                                                                                         \
        {                                                                                                            \
            MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(                                                                        \
                verify_result, verify_token,                                                                         \
                mcuxClRsa_verify(                                                                                    \
                    session, &public_key,                                                                            \
                    m_length == 32U ? s_MessageDigest32ByteRSAFlash : s_MessageDigest64ByteRSAFlash,                 \
                    m_length == 32U ? sizeof(s_MessageDigest32ByteRSAFlash) : sizeof(s_MessageDigest64ByteRSAFlash), \
                    s_SignatureBuffer,                                                                               \
                    m_length == 32U ? (mcuxClRsa_SignVerifyMode_t *)&mcuxClRsa_Mode_Verify_Pss_Sha2_256 :            \
                                      (mcuxClRsa_SignVerifyMode_t *)&mcuxClRsa_Mode_Verify_Pss_Sha2_512,             \
                    RSA_PSS_SALT_LENGTH, MCUXCLRSA_OPTION_MESSAGE_DIGEST, NULL));                                    \
            if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_verify) != verify_token) ||                                  \
                (MCUXCLRSA_STATUS_VERIFY_OK != verify_result))                                                       \
            {                                                                                                        \
                PRINTF("[Error] RSA signature verification failed\r\n");                                             \
                return MCUXCLEXAMPLE_STATUS_ERROR;                                                                   \
            }                                                                                                        \
            MCUX_CSSL_FP_FUNCTION_CALL_END();                                                                        \
        }                                                                                                            \
    } while (0);

#define GENERATE_ECC_SIGNATURE(data_from_ram, session, privKey, m_length)                                          \
    do                                                                                                             \
    {                                                                                                              \
        if (data_from_ram)                                                                                         \
        {                                                                                                          \
            uint32_t signatureSize = 0U;                                                                           \
            MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(                                                                      \
                sign_result, sign_token,                                                                           \
                mcuxClEcc_EdDSA_GenerateSignature(                                                                 \
                    &session, privKey, &mcuxClEcc_EdDsa_Ed25519ProtocolDescriptor,                                 \
                    m_length == MESSAGE_SMALL ? s_MessageSmallEcc : s_MessageLargeEcc,                             \
                    m_length == MESSAGE_SMALL ? sizeof(s_MessageSmallEcc) : sizeof(s_MessageLargeEcc),             \
                    s_SignatureBuffer, &signatureSize));                                                           \
            if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_GenerateSignature) != sign_token) ||                 \
                (MCUXCLECC_EDDSA_ED25519_SIZE_SIGNATURE != signatureSize) || (MCUXCLECC_STATUS_OK != sign_result)) \
            {                                                                                                      \
                PRINTF("[Error] ECC signature generation failed\r\n");                                             \
                return MCUXCLEXAMPLE_STATUS_ERROR;                                                                 \
            }                                                                                                      \
            MCUX_CSSL_FP_FUNCTION_CALL_END();                                                                      \
        }                                                                                                          \
        else                                                                                                       \
        {                                                                                                          \
            uint32_t signatureSize = 0U;                                                                           \
            MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(                                                                      \
                sign_result, sign_token,                                                                           \
                mcuxClEcc_EdDSA_GenerateSignature(                                                                 \
                    &session, privKey, &mcuxClEcc_EdDsa_Ed25519ProtocolDescriptor,                                 \
                    m_length == MESSAGE_SMALL ? s_MessageSmallEccFlash : s_MessageLargeEccFlash,                   \
                    m_length == MESSAGE_SMALL ? sizeof(s_MessageSmallEccFlash) : sizeof(s_MessageLargeEccFlash),   \
                    s_SignatureBuffer, &signatureSize));                                                           \
            if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_GenerateSignature) != sign_token) ||                 \
                (MCUXCLECC_EDDSA_ED25519_SIZE_SIGNATURE != signatureSize) || (MCUXCLECC_STATUS_OK != sign_result)) \
            {                                                                                                      \
                PRINTF("[Error] ECC signature generation failed\r\n");                                             \
                return MCUXCLEXAMPLE_STATUS_ERROR;                                                                 \
            }                                                                                                      \
            MCUX_CSSL_FP_FUNCTION_CALL_END();                                                                      \
        }                                                                                                          \
    } while (0);

#define ECC_VERIFY(data_from_ram, session, pubKeyHandler, m_length)                                              \
    do                                                                                                           \
    {                                                                                                            \
        if (data_from_ram)                                                                                       \
        {                                                                                                        \
            MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(                                                                    \
                verify_result, verify_token,                                                                     \
                mcuxClEcc_EdDSA_VerifySignature(                                                                 \
                    &session, pubKeyHandler, &mcuxClEcc_EdDsa_Ed25519ProtocolDescriptor,                         \
                    m_length == MESSAGE_SMALL ? s_MessageSmallEcc : s_MessageLargeEcc,                           \
                    m_length == MESSAGE_SMALL ? sizeof(s_MessageSmallEcc) : sizeof(s_MessageLargeEcc),           \
                    s_SignatureBuffer, sizeof(s_SignatureBuffer)));                                              \
            if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_VerifySignature) != verify_token) ||               \
                (MCUXCLECC_STATUS_OK != verify_result))                                                          \
            {                                                                                                    \
                PRINTF("[Error] ECC signature verification failed\r\n");                                         \
                return MCUXCLEXAMPLE_STATUS_ERROR;                                                               \
            }                                                                                                    \
            MCUX_CSSL_FP_FUNCTION_CALL_END();                                                                    \
        }                                                                                                        \
        else                                                                                                     \
        {                                                                                                        \
            MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(                                                                    \
                verify_result, verify_token,                                                                     \
                mcuxClEcc_EdDSA_VerifySignature(                                                                 \
                    &session, pubKeyHandler, &mcuxClEcc_EdDsa_Ed25519ProtocolDescriptor,                         \
                    m_length == MESSAGE_SMALL ? s_MessageSmallEccFlash : s_MessageLargeEccFlash,                 \
                    m_length == MESSAGE_SMALL ? sizeof(s_MessageSmallEccFlash) : sizeof(s_MessageLargeEccFlash), \
                    s_SignatureBuffer, sizeof(s_SignatureBuffer)));                                              \
            if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_VerifySignature) != verify_token) ||               \
                (MCUXCLECC_STATUS_OK != verify_result))                                                          \
            {                                                                                                    \
                PRINTF("[Error] ECC signature verification failed\r\n");                                         \
                return MCUXCLEXAMPLE_STATUS_ERROR;                                                               \
            }                                                                                                    \
            MCUX_CSSL_FP_FUNCTION_CALL_END();                                                                    \
        }                                                                                                        \
    } while (0);

/******************************************************************************* \
 * Prototypes                                                                    \
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/
/* Buffer for generated signature */
static uint8_t s_SignatureBuffer[MCUXCLECC_EDDSA_ED25519_SIZE_SIGNATURE];

/* Buffer for generated public key in ECC */
static uint8_t s_PublicKeyBufferEcc[MCUXCLECC_EDDSA_ED25519_SIZE_PUBLICKEY] __attribute__((aligned(4U)));

/* Variables stored in RAM */

/* Private key input for ECC */
static uint8_t s_PrivKeyInputEcc[MCUXCLECC_EDDSA_ED25519_SIZE_PRIVATEKEY] __attribute__((aligned(4U))) = {
    0x83U, 0x3FU, 0xE6U, 0x24U, 0x09U, 0x23U, 0x7BU, 0x9DU, 0x62U, 0xECU, 0x77U, 0x58U, 0x75U, 0x20U, 0x91U, 0x1EU,
    0x9AU, 0x75U, 0x9CU, 0xECU, 0x1DU, 0x19U, 0x75U, 0x5BU, 0x7DU, 0xA9U, 0x01U, 0xB9U, 0x6DU, 0xCAU, 0x3DU, 0x42U};

/* Small input message */
static uint8_t s_MessageSmallEcc[MESSAGE_SMALL] __attribute__((aligned(4U))) = {
    0xDDU, 0xAFU, 0x35U, 0xA1U, 0x93U, 0x61U, 0x7AU, 0xBAU, 0xCCU, 0x41U, 0x73U, 0x49U, 0xAEU, 0x20U, 0x41U, 0x31U,
    0x12U, 0xE6U, 0xFAU, 0x4EU, 0x89U, 0xA9U, 0x7EU, 0xA2U, 0x0AU, 0x9EU, 0xEEU, 0xE6U, 0x4BU, 0x55U, 0xD3U, 0x9AU,
    0x21U, 0x92U, 0x99U, 0x2AU, 0x27U, 0x4FU, 0xC1U, 0xA8U, 0x36U, 0xBAU, 0x3CU, 0x23U, 0xA3U, 0xFEU, 0xEBU, 0xBDU,
    0x45U, 0x4DU, 0x44U, 0x23U, 0x64U, 0x3CU, 0xE8U, 0x0EU, 0x2AU, 0x9AU, 0xC9U, 0x4FU, 0xA5U, 0x4CU, 0xA4U, 0x9FU};

/* Larger input message */
static uint8_t s_MessageLargeEcc[MESSAGE_LARGE] __attribute__((aligned(4U)));

/* Example value for private RSA exponent d */
static uint8_t s_ExponentDRSA[RSA_KEY_BYTE_LENGTH] __attribute__((aligned(4U))) = {
    0x15U, 0x5FU, 0xE6U, 0x60U, 0xCDU, 0xDEU, 0xAAU, 0x17U, 0x1BU, 0x5EU, 0xD6U, 0xBDU, 0xD0U, 0x3BU, 0xB3U, 0x56U,
    0xE0U, 0xF6U, 0xE8U, 0x6BU, 0x5AU, 0x3CU, 0x26U, 0xF3U, 0xCEU, 0x7DU, 0xAEU, 0x00U, 0x8CU, 0x4EU, 0x38U, 0xA9U,
    0xA9U, 0x7FU, 0xA5U, 0x97U, 0xB2U, 0xB9U, 0x0AU, 0x45U, 0x10U, 0xD2U, 0x23U, 0x8DU, 0x3FU, 0x15U, 0x8AU, 0xB8U,
    0x91U, 0x97U, 0xFBU, 0x08U, 0xA5U, 0xB7U, 0x4CU, 0xFEU, 0x5CU, 0xC8U, 0xF1U, 0x3DU, 0x47U, 0x09U, 0x62U, 0x91U,
    0xD0U, 0x05U, 0x38U, 0xAAU, 0x58U, 0x93U, 0xD8U, 0x2DU, 0xCEU, 0x55U, 0xB3U, 0x64U, 0x8CU, 0x6AU, 0x71U, 0x9AU,
    0xE3U, 0x87U, 0xDEU, 0xE5U, 0x5EU, 0xC5U, 0xBEU, 0xF0U, 0x89U, 0x76U, 0x3DU, 0xE7U, 0x1EU, 0x47U, 0x61U, 0xB7U,
    0x03U, 0xADU, 0x69U, 0x2EU, 0xD6U, 0x2DU, 0x7CU, 0x1FU, 0x4FU, 0x0FU, 0xF0U, 0x03U, 0xC1U, 0x67U, 0xEBU, 0x62U,
    0xD2U, 0xC6U, 0x79U, 0xCCU, 0x6FU, 0x13U, 0xB9U, 0x87U, 0xA1U, 0x42U, 0xF1U, 0x37U, 0x7AU, 0x40U, 0xBDU, 0xC0U,
    0xA0U, 0x36U, 0x60U, 0x72U, 0x94U, 0x40U, 0x14U, 0x63U, 0xA3U, 0x0EU, 0x82U, 0x91U, 0x2BU, 0x42U, 0x8AU, 0x1DU,
    0x3FU, 0x80U, 0xB5U, 0xD0U, 0xD3U, 0x3EU, 0xA8U, 0x4EU, 0x8BU, 0xB6U, 0x4CU, 0x36U, 0x22U, 0xB9U, 0xBEU, 0xE3U,
    0x56U, 0xF1U, 0x2CU, 0x6AU, 0x19U, 0x0EU, 0x55U, 0x7BU, 0xBFU, 0x25U, 0xE1U, 0x10U, 0x80U, 0x7BU, 0x85U, 0xCAU,
    0xD5U, 0x1BU, 0x39U, 0x87U, 0x57U, 0x08U, 0x06U, 0xBEU, 0x81U, 0xF3U, 0x71U, 0x3FU, 0x5DU, 0x17U, 0x40U, 0x74U,
    0x99U, 0xA5U, 0xDEU, 0xDAU, 0xC0U, 0xF3U, 0xE3U, 0xBCU, 0x79U, 0x96U, 0x35U, 0x95U, 0xF8U, 0xE0U, 0xCFU, 0x01U,
    0x29U, 0x1DU, 0xC1U, 0x02U, 0x09U, 0xC0U, 0x6EU, 0xB6U, 0x0EU, 0x2EU, 0x9CU, 0x47U, 0xECU, 0x91U, 0x42U, 0xEDU,
    0xA5U, 0xF3U, 0xB7U, 0x0AU, 0xC6U, 0x7FU, 0x72U, 0xBFU, 0x52U, 0xB3U, 0x31U, 0x37U, 0xD1U, 0x49U, 0xB6U, 0xF6U,
    0x06U, 0xE4U, 0x59U, 0x61U, 0x7DU, 0xAAU, 0x8EU, 0x10U, 0x18U, 0xA8U, 0x14U, 0x1DU, 0x89U, 0x4EU, 0xCAU, 0xFFU};

/* Example value for public RSA exponent e */
static uint8_t s_ExponentERSA[3U] __attribute__((aligned(4))) = {0x01U, 0x00U, 0x01U};

/* Example value for public RSA modulus N */
static uint8_t s_ModulusRSA[RSA_KEY_BYTE_LENGTH] __attribute__((aligned(4U))) = {
    0xD3U, 0x24U, 0x96U, 0xE6U, 0x2DU, 0x16U, 0x34U, 0x6EU, 0x06U, 0xE7U, 0xA3U, 0x1CU, 0x12U, 0x0AU, 0x21U, 0xB5U,
    0x45U, 0x32U, 0x32U, 0x35U, 0xEEU, 0x1DU, 0x90U, 0x72U, 0x1DU, 0xCEU, 0xAAU, 0xD4U, 0x6DU, 0xC4U, 0xCEU, 0xBDU,
    0x80U, 0xC1U, 0x34U, 0x5AU, 0xFFU, 0x95U, 0xB1U, 0xDDU, 0xF8U, 0x71U, 0xEBU, 0xB7U, 0xF2U, 0x0FU, 0xEDU, 0xB6U,
    0xE4U, 0x2EU, 0x67U, 0xA0U, 0xCCU, 0x59U, 0xB3U, 0x9FU, 0xFDU, 0x31U, 0xE9U, 0x83U, 0x42U, 0xF4U, 0x0AU, 0xD9U,
    0xAFU, 0xF9U, 0x3CU, 0x3CU, 0x51U, 0xCFU, 0x5FU, 0x3CU, 0x8AU, 0xD0U, 0x64U, 0xB8U, 0x33U, 0xF9U, 0xACU, 0x34U,
    0x22U, 0x9AU, 0x3EU, 0xD3U, 0xDDU, 0x29U, 0x41U, 0xBEU, 0x12U, 0x5BU, 0xC5U, 0xA2U, 0x0CU, 0xB6U, 0xD2U, 0x31U,
    0xB6U, 0xD1U, 0x84U, 0x7EU, 0xC4U, 0xFEU, 0xAEU, 0x2BU, 0x88U, 0x46U, 0xCFU, 0x00U, 0xC4U, 0xC6U, 0xE7U, 0x5AU,
    0x51U, 0x32U, 0x65U, 0x7AU, 0x68U, 0xECU, 0x04U, 0x38U, 0x36U, 0x46U, 0x34U, 0xEAU, 0xF8U, 0x27U, 0xF9U, 0xBBU,
    0x51U, 0x6CU, 0x93U, 0x27U, 0x48U, 0x1DU, 0x58U, 0xB8U, 0xFFU, 0x1EU, 0xA4U, 0xC0U, 0x1FU, 0xA1U, 0xA2U, 0x57U,
    0xA9U, 0x4EU, 0xA6U, 0xD4U, 0x72U, 0x60U, 0x3BU, 0x3FU, 0xB3U, 0x24U, 0x53U, 0x22U, 0x88U, 0xEAU, 0x3AU, 0x97U,
    0x43U, 0x53U, 0x59U, 0x15U, 0x33U, 0xA0U, 0xEBU, 0xBEU, 0xF2U, 0x9DU, 0xF4U, 0xF8U, 0xBCU, 0x4DU, 0xDBU, 0xF8U,
    0x8EU, 0x47U, 0x1FU, 0x1DU, 0xA5U, 0x00U, 0xB8U, 0xF5U, 0x7BU, 0xB8U, 0xC3U, 0x7CU, 0xA5U, 0xEAU, 0x17U, 0x7CU,
    0x4EU, 0x8AU, 0x39U, 0x06U, 0xB7U, 0xC1U, 0x42U, 0xF7U, 0x78U, 0x8CU, 0x45U, 0xEAU, 0xD0U, 0xC9U, 0xBCU, 0x36U,
    0x92U, 0x48U, 0x3AU, 0xD8U, 0x13U, 0x61U, 0x11U, 0x45U, 0xB4U, 0x1FU, 0x9CU, 0x01U, 0x2EU, 0xF2U, 0x87U, 0xBEU,
    0x8BU, 0xBFU, 0x93U, 0x19U, 0xCFU, 0x4BU, 0x91U, 0x84U, 0xDCU, 0x8EU, 0xFFU, 0x83U, 0x58U, 0x9BU, 0xE9U, 0x0CU,
    0x54U, 0x81U, 0x14U, 0xACU, 0xFAU, 0x5AU, 0xBFU, 0x79U, 0x54U, 0xBFU, 0x9FU, 0x7AU, 0xE5U, 0xB4U, 0x38U, 0xB5U};

/* Example value for Sha2-256 message digest */
static uint8_t s_MessageDigest32ByteRSA[RSA_MESSAGE_DIGEST_LENGTH] __attribute__((aligned(4U))) = {
    0xF4U, 0x45U, 0x80U, 0x1EU, 0x0CU, 0xB8U, 0x99U, 0x26U, 0x2CU, 0x9BU, 0x9EU, 0x21U, 0x98U, 0x36U, 0x88U, 0x0DU,
    0x73U, 0xCAU, 0x2DU, 0x1BU, 0x0BU, 0x9CU, 0x15U, 0xFBU, 0x95U, 0x9CU, 0x90U, 0xEBU, 0x12U, 0x12U, 0x34U, 0xE3U};

/* Example value for Sha2-512 message digest */
static uint8_t s_MessageDigest64ByteRSA[RSA_MESSAGE_DIGEST_LENGTH * 2U] __attribute__((aligned(4U))) = {
    0xF4U, 0x45U, 0x80U, 0x1EU, 0x0CU, 0xB8U, 0x99U, 0x26U, 0x2CU, 0x9BU, 0x9EU, 0x21U, 0x98U, 0x36U, 0x88U, 0x0DU,
    0x73U, 0xCAU, 0x2DU, 0x1BU, 0x0BU, 0x9CU, 0x15U, 0xFBU, 0x95U, 0x9CU, 0x90U, 0xEBU, 0x12U, 0x12U, 0x34U, 0xE3U,
    0xF4U, 0x45U, 0x80U, 0x1EU, 0x0CU, 0xB8U, 0x99U, 0x26U, 0x2CU, 0x9BU, 0x9EU, 0x21U, 0x98U, 0x36U, 0x88U, 0x0DU,
    0x73U, 0xCAU, 0x2DU, 0x1BU, 0x0BU, 0x9CU, 0x15U, 0xFBU, 0x95U, 0x9CU, 0x90U, 0xEBU, 0x12U, 0x12U, 0x34U, 0xE3U};

/* Variables stored in flash */

/* Private key input for ECC from flash */
static const uint8_t s_PrivKeyInputEccFlash[MCUXCLECC_EDDSA_ED25519_SIZE_PRIVATEKEY] __attribute__((aligned(4U))) = {
    0x83U, 0x3FU, 0xE6U, 0x24U, 0x09U, 0x23U, 0x7BU, 0x9DU, 0x62U, 0xECU, 0x77U, 0x58U, 0x75U, 0x20U, 0x91U, 0x1EU,
    0x9AU, 0x75U, 0x9CU, 0xECU, 0x1DU, 0x19U, 0x75U, 0x5BU, 0x7DU, 0xA9U, 0x01U, 0xB9U, 0x6DU, 0xCAU, 0x3DU, 0x42U};

/* Small input message from flash */
static const uint8_t s_MessageSmallEccFlash[MESSAGE_SMALL] __attribute__((aligned(4U))) = {
    0xDDU, 0xAFU, 0x35U, 0xA1U, 0x93U, 0x61U, 0x7AU, 0xBAU, 0xCCU, 0x41U, 0x73U, 0x49U, 0xAEU, 0x20U, 0x41U, 0x31U,
    0x12U, 0xE6U, 0xFAU, 0x4EU, 0x89U, 0xA9U, 0x7EU, 0xA2U, 0x0AU, 0x9EU, 0xEEU, 0xE6U, 0x4BU, 0x55U, 0xD3U, 0x9AU,
    0x21U, 0x92U, 0x99U, 0x2AU, 0x27U, 0x4FU, 0xC1U, 0xA8U, 0x36U, 0xBAU, 0x3CU, 0x23U, 0xA3U, 0xFEU, 0xEBU, 0xBDU,
    0x45U, 0x4DU, 0x44U, 0x23U, 0x64U, 0x3CU, 0xE8U, 0x0EU, 0x2AU, 0x9AU, 0xC9U, 0x4FU, 0xA5U, 0x4CU, 0xA4U, 0x9FU};

/* Large input message from flash */
static const uint8_t s_MessageLargeEccFlash[MESSAGE_LARGE] __attribute__((aligned(4U)));

/* Example value for private RSA exponent d stored in flash */
static const uint8_t s_ExponentDRSAFlash[RSA_KEY_BYTE_LENGTH] __attribute__((aligned(4U))) = {
    0x15U, 0x5FU, 0xE6U, 0x60U, 0xCDU, 0xDEU, 0xAAU, 0x17U, 0x1BU, 0x5EU, 0xD6U, 0xBDU, 0xD0U, 0x3BU, 0xB3U, 0x56U,
    0xE0U, 0xF6U, 0xE8U, 0x6BU, 0x5AU, 0x3CU, 0x26U, 0xF3U, 0xCEU, 0x7DU, 0xAEU, 0x00U, 0x8CU, 0x4EU, 0x38U, 0xA9U,
    0xA9U, 0x7FU, 0xA5U, 0x97U, 0xB2U, 0xB9U, 0x0AU, 0x45U, 0x10U, 0xD2U, 0x23U, 0x8DU, 0x3FU, 0x15U, 0x8AU, 0xB8U,
    0x91U, 0x97U, 0xFBU, 0x08U, 0xA5U, 0xB7U, 0x4CU, 0xFEU, 0x5CU, 0xC8U, 0xF1U, 0x3DU, 0x47U, 0x09U, 0x62U, 0x91U,
    0xD0U, 0x05U, 0x38U, 0xAAU, 0x58U, 0x93U, 0xD8U, 0x2DU, 0xCEU, 0x55U, 0xB3U, 0x64U, 0x8CU, 0x6AU, 0x71U, 0x9AU,
    0xE3U, 0x87U, 0xDEU, 0xE5U, 0x5EU, 0xC5U, 0xBEU, 0xF0U, 0x89U, 0x76U, 0x3DU, 0xE7U, 0x1EU, 0x47U, 0x61U, 0xB7U,
    0x03U, 0xADU, 0x69U, 0x2EU, 0xD6U, 0x2DU, 0x7CU, 0x1FU, 0x4FU, 0x0FU, 0xF0U, 0x03U, 0xC1U, 0x67U, 0xEBU, 0x62U,
    0xD2U, 0xC6U, 0x79U, 0xCCU, 0x6FU, 0x13U, 0xB9U, 0x87U, 0xA1U, 0x42U, 0xF1U, 0x37U, 0x7AU, 0x40U, 0xBDU, 0xC0U,
    0xA0U, 0x36U, 0x60U, 0x72U, 0x94U, 0x40U, 0x14U, 0x63U, 0xA3U, 0x0EU, 0x82U, 0x91U, 0x2BU, 0x42U, 0x8AU, 0x1DU,
    0x3FU, 0x80U, 0xB5U, 0xD0U, 0xD3U, 0x3EU, 0xA8U, 0x4EU, 0x8BU, 0xB6U, 0x4CU, 0x36U, 0x22U, 0xB9U, 0xBEU, 0xE3U,
    0x56U, 0xF1U, 0x2CU, 0x6AU, 0x19U, 0x0EU, 0x55U, 0x7BU, 0xBFU, 0x25U, 0xE1U, 0x10U, 0x80U, 0x7BU, 0x85U, 0xCAU,
    0xD5U, 0x1BU, 0x39U, 0x87U, 0x57U, 0x08U, 0x06U, 0xBEU, 0x81U, 0xF3U, 0x71U, 0x3FU, 0x5DU, 0x17U, 0x40U, 0x74U,
    0x99U, 0xA5U, 0xDEU, 0xDAU, 0xC0U, 0xF3U, 0xE3U, 0xBCU, 0x79U, 0x96U, 0x35U, 0x95U, 0xF8U, 0xE0U, 0xCFU, 0x01U,
    0x29U, 0x1DU, 0xC1U, 0x02U, 0x09U, 0xC0U, 0x6EU, 0xB6U, 0x0EU, 0x2EU, 0x9CU, 0x47U, 0xECU, 0x91U, 0x42U, 0xEDU,
    0xA5U, 0xF3U, 0xB7U, 0x0AU, 0xC6U, 0x7FU, 0x72U, 0xBFU, 0x52U, 0xB3U, 0x31U, 0x37U, 0xD1U, 0x49U, 0xB6U, 0xF6U,
    0x06U, 0xE4U, 0x59U, 0x61U, 0x7DU, 0xAAU, 0x8EU, 0x10U, 0x18U, 0xA8U, 0x14U, 0x1DU, 0x89U, 0x4EU, 0xCAU, 0xFFU};

/* Example value for public RSA exponent e */
static const uint8_t s_ExponentERSAFlash[3U] __attribute__((aligned(4))) = {0x01U, 0x00U, 0x01U};

/* Example value for public RSA modulus N stored in flash */
static const uint8_t s_ModulusRSAFlash[RSA_KEY_BYTE_LENGTH] __attribute__((aligned(4U))) = {
    0xD3U, 0x24U, 0x96U, 0xE6U, 0x2DU, 0x16U, 0x34U, 0x6EU, 0x06U, 0xE7U, 0xA3U, 0x1CU, 0x12U, 0x0AU, 0x21U, 0xB5U,
    0x45U, 0x32U, 0x32U, 0x35U, 0xEEU, 0x1DU, 0x90U, 0x72U, 0x1DU, 0xCEU, 0xAAU, 0xD4U, 0x6DU, 0xC4U, 0xCEU, 0xBDU,
    0x80U, 0xC1U, 0x34U, 0x5AU, 0xFFU, 0x95U, 0xB1U, 0xDDU, 0xF8U, 0x71U, 0xEBU, 0xB7U, 0xF2U, 0x0FU, 0xEDU, 0xB6U,
    0xE4U, 0x2EU, 0x67U, 0xA0U, 0xCCU, 0x59U, 0xB3U, 0x9FU, 0xFDU, 0x31U, 0xE9U, 0x83U, 0x42U, 0xF4U, 0x0AU, 0xD9U,
    0xAFU, 0xF9U, 0x3CU, 0x3CU, 0x51U, 0xCFU, 0x5FU, 0x3CU, 0x8AU, 0xD0U, 0x64U, 0xB8U, 0x33U, 0xF9U, 0xACU, 0x34U,
    0x22U, 0x9AU, 0x3EU, 0xD3U, 0xDDU, 0x29U, 0x41U, 0xBEU, 0x12U, 0x5BU, 0xC5U, 0xA2U, 0x0CU, 0xB6U, 0xD2U, 0x31U,
    0xB6U, 0xD1U, 0x84U, 0x7EU, 0xC4U, 0xFEU, 0xAEU, 0x2BU, 0x88U, 0x46U, 0xCFU, 0x00U, 0xC4U, 0xC6U, 0xE7U, 0x5AU,
    0x51U, 0x32U, 0x65U, 0x7AU, 0x68U, 0xECU, 0x04U, 0x38U, 0x36U, 0x46U, 0x34U, 0xEAU, 0xF8U, 0x27U, 0xF9U, 0xBBU,
    0x51U, 0x6CU, 0x93U, 0x27U, 0x48U, 0x1DU, 0x58U, 0xB8U, 0xFFU, 0x1EU, 0xA4U, 0xC0U, 0x1FU, 0xA1U, 0xA2U, 0x57U,
    0xA9U, 0x4EU, 0xA6U, 0xD4U, 0x72U, 0x60U, 0x3BU, 0x3FU, 0xB3U, 0x24U, 0x53U, 0x22U, 0x88U, 0xEAU, 0x3AU, 0x97U,
    0x43U, 0x53U, 0x59U, 0x15U, 0x33U, 0xA0U, 0xEBU, 0xBEU, 0xF2U, 0x9DU, 0xF4U, 0xF8U, 0xBCU, 0x4DU, 0xDBU, 0xF8U,
    0x8EU, 0x47U, 0x1FU, 0x1DU, 0xA5U, 0x00U, 0xB8U, 0xF5U, 0x7BU, 0xB8U, 0xC3U, 0x7CU, 0xA5U, 0xEAU, 0x17U, 0x7CU,
    0x4EU, 0x8AU, 0x39U, 0x06U, 0xB7U, 0xC1U, 0x42U, 0xF7U, 0x78U, 0x8CU, 0x45U, 0xEAU, 0xD0U, 0xC9U, 0xBCU, 0x36U,
    0x92U, 0x48U, 0x3AU, 0xD8U, 0x13U, 0x61U, 0x11U, 0x45U, 0xB4U, 0x1FU, 0x9CU, 0x01U, 0x2EU, 0xF2U, 0x87U, 0xBEU,
    0x8BU, 0xBFU, 0x93U, 0x19U, 0xCFU, 0x4BU, 0x91U, 0x84U, 0xDCU, 0x8EU, 0xFFU, 0x83U, 0x58U, 0x9BU, 0xE9U, 0x0CU,
    0x54U, 0x81U, 0x14U, 0xACU, 0xFAU, 0x5AU, 0xBFU, 0x79U, 0x54U, 0xBFU, 0x9FU, 0x7AU, 0xE5U, 0xB4U, 0x38U, 0xB5U};

/* Example value for Sha2-256 message digest */
static const uint8_t s_MessageDigest32ByteRSAFlash[RSA_MESSAGE_DIGEST_LENGTH] __attribute__((aligned(4U))) = {
    0xF4U, 0x45U, 0x80U, 0x1EU, 0x0CU, 0xB8U, 0x99U, 0x26U, 0x2CU, 0x9BU, 0x9EU, 0x21U, 0x98U, 0x36U, 0x88U, 0x0DU,
    0x73U, 0xCAU, 0x2DU, 0x1BU, 0x0BU, 0x9CU, 0x15U, 0xFBU, 0x95U, 0x9CU, 0x90U, 0xEBU, 0x12U, 0x12U, 0x34U, 0xE3U};

/* Example value for Sha2-512 message digest */
static const uint8_t s_MessageDigest64ByteRSAFlash[RSA_MESSAGE_DIGEST_LENGTH * 2U] __attribute__((aligned(4U))) = {
    0xF4U, 0x45U, 0x80U, 0x1EU, 0x0CU, 0xB8U, 0x99U, 0x26U, 0x2CU, 0x9BU, 0x9EU, 0x21U, 0x98U, 0x36U, 0x88U, 0x0DU,
    0x73U, 0xCAU, 0x2DU, 0x1BU, 0x0BU, 0x9CU, 0x15U, 0xFBU, 0x95U, 0x9CU, 0x90U, 0xEBU, 0x12U, 0x12U, 0x34U, 0xE3U,
    0xF4U, 0x45U, 0x80U, 0x1EU, 0x0CU, 0xB8U, 0x99U, 0x26U, 0x2CU, 0x9BU, 0x9EU, 0x21U, 0x98U, 0x36U, 0x88U, 0x0DU,
    0x73U, 0xCAU, 0x2DU, 0x1BU, 0x0BU, 0x9CU, 0x15U, 0xFBU, 0x95U, 0x9CU, 0x90U, 0xEBU, 0x12U, 0x12U, 0x34U, 0xE3U};

/*******************************************************************************
 * Code
 ******************************************************************************/
bool exec_rsa_sign_pss_sha(char *data_from, uint32_t m_length, signature_algorithm_result *a_result)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /** Initialize ELS, Enable the ELS **/
    if (!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        PRINTF("[Error] ELS initialization failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    bool data_from_ram = !strcmp(data_from, "RAM");

    /* Create session handle to be used by mcuxClRsa_sign */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLRSA_SIGN_PLAIN_PSSENCODE_2048_WACPU_SIZE,
                                                  MCUXCLRSA_SIGN_PLAIN_PSSENCODE_2048_WACPU_SIZE);

    /* Initialize the PRNG */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(prngInit_result, prngInit_token, mcuxClRandom_ncInit(session));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != prngInit_token) ||
        (MCUXCLRANDOM_STATUS_OK != prngInit_result))
    {
        PRINTF("[Error] PRNG initialization failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Create key struct of type MCUXCLRSA_KEY_PRIVATEPLAIN */
    const mcuxClRsa_KeyEntry_t Mod1 = {
        .pKeyEntryData  = data_from_ram ? (uint8_t *)s_ModulusRSA : (uint8_t *)s_ModulusRSAFlash,
        .keyEntryLength = RSA_KEY_BYTE_LENGTH};

    const mcuxClRsa_KeyEntry_t Exp1 = {
        .pKeyEntryData  = data_from_ram ? (uint8_t *)s_ExponentDRSA : (uint8_t *)s_ExponentDRSAFlash,
        .keyEntryLength = data_from_ram ? sizeof(s_ExponentDRSA) : sizeof(s_ExponentDRSAFlash)};

    const mcuxClRsa_Key private_key = {.keytype = MCUXCLRSA_KEY_PRIVATEPLAIN,
                                       .pMod1   = (mcuxClRsa_KeyEntry_t *)&Mod1,
                                       .pMod2   = NULL,
                                       .pQInv   = NULL,
                                       .pExp1   = (mcuxClRsa_KeyEntry_t *)&Exp1,
                                       .pExp2   = NULL,
                                       .pExp3   = NULL};

    /**************************************************************************/
    /* RSA signature generation call                                          */
    /**************************************************************************/
    a_result->signPerS = TIME_PUBLIC(GENERATE_RSA_SIGNATURE(data_from_ram, session, private_key, m_length));

    /**************************************************************************/
    /* Session clean-up                                                       */
    /**************************************************************************/
    /** Destroy Session and cleanup Session **/
    if (!mcuxClExample_Session_Clean(session))
    {
        PRINTF("[Error] Session cleaning failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /** Disable the ELS **/
    if (!mcuxClExample_Els_Disable())
    {
        PRINTF("[Error] Disabling ELS failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    return MCUXCLEXAMPLE_STATUS_OK;
}

bool exec_rsa_verify_pss_sha(char *data_from, uint32_t m_length, signature_algorithm_result *a_result)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /** Initialize ELS, Enable the ELS **/
    if (!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        PRINTF("[Error] ELS initialization failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    bool data_from_ram = !strcmp(data_from, "RAM");

    /* Create session handle to be used by verify function */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLRSA_VERIFY_PSSVERIFY_WACPU_SIZE,
                                                  MCUXCLRSA_VERIFY_2048_WAPKC_SIZE);

    /* Initialize the PRNG */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(prngInit_result, prngInit_token, mcuxClRandom_ncInit(session));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != prngInit_token) ||
        (MCUXCLRANDOM_STATUS_OK != prngInit_result))
    {
        PRINTF("[Error] PRNG initialization failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Create key struct of type MCUXCLRSA_KEY_PUBLIC */
    const mcuxClRsa_KeyEntry_t Mod1 = {
        .pKeyEntryData  = data_from_ram ? (uint8_t *)s_ModulusRSA : (uint8_t *)s_ModulusRSAFlash,
        .keyEntryLength = RSA_KEY_BYTE_LENGTH};

    const mcuxClRsa_KeyEntry_t Exp1 = {
        .pKeyEntryData  = data_from_ram ? (uint8_t *)s_ExponentERSA : (uint8_t *)s_ExponentERSAFlash,
        .keyEntryLength = data_from_ram ? sizeof(s_ExponentERSA) : sizeof(s_ExponentERSAFlash)};

    const mcuxClRsa_Key public_key = {.keytype = MCUXCLRSA_KEY_PUBLIC,
                                      .pMod1   = (mcuxClRsa_KeyEntry_t *)&Mod1,
                                      .pMod2   = NULL,
                                      .pQInv   = NULL,
                                      .pExp1   = (mcuxClRsa_KeyEntry_t *)&Exp1,
                                      .pExp2   = NULL,
                                      .pExp3   = NULL};

    /**************************************************************************/
    /* RSA verification call                                                  */
    /**************************************************************************/
    a_result->verifyPerS = TIME_PUBLIC(RSA_VERIFY(data_from_ram, session, public_key, m_length));

    /**************************************************************************/
    /* Session clean-up                                                       */
    /**************************************************************************/

    /** Destroy Session and cleanup Session **/
    if (!mcuxClExample_Session_Clean(session))
    {
        PRINTF("[Error] Session cleaning failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /** Disable the ELS **/
    if (!mcuxClExample_Els_Disable())
    {
        PRINTF("[Error] Disabling ELS failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}

bool exec_EdDSA_generate_signature_Ed25519(char *data_from, uint32_t m_length, signature_algorithm_result *a_result)
{
    /******************************************/
    /* Set Up the environment                 */
    /******************************************/

    /* Initialize ELS, Enable the ELS */
    if (!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        PRINTF("[Error] ELS initialization failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    bool data_from_ram = !strcmp(data_from, "RAM");

    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t session;

    /* Allocate and initialize PKC workarea */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(&session, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);

    /* Initialize the RNG context and Initialize the PRNG */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(&session, 0U, mcuxClRandomModes_Mode_ELS_Drbg);

    /******************************************/
    /* Initialize the private and public keys */
    /******************************************/

    /* Allocate space for and initialize private key handle for an Ed25519 private key */
    uint8_t privKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE];
    mcuxClKey_Handle_t privKey = (mcuxClKey_Handle_t)&privKeyDesc;
    uint8_t pPrivKeyData[MCUXCLECC_EDDSA_ED25519_SIZE_PRIVATEKEYDATA];

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(privkeyinit_result, privkeyinit_token,
                                     mcuxClKey_init(
                                         /* mcuxClSession_Handle_t session         */ &session,
                                         /* mcuxClKey_Handle_t key                 */ privKey,
                                         /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_EdDSA_Ed25519_Priv,
                                         /* mcuxCl_Buffer_t pKeyData               */ (mcuxCl_Buffer_t)pPrivKeyData,
                                         /* uint32_t keyDataLength                 */ sizeof(pPrivKeyData)));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != privkeyinit_token) ||
        (MCUXCLKEY_STATUS_OK != privkeyinit_result))
    {
        PRINTF("[Error] Private key initialization failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Allocate space for and initialize pbulic key handle for an Ed25519 public key */
    uint8_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE];
    mcuxClKey_Handle_t pubKey = (mcuxClKey_Handle_t)&pubKeyDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        pubkeyinit_result, pubkeyinit_token,
        mcuxClKey_init(
            /* mcuxClSession_Handle_t session         */ &session,
            /* mcuxClKey_Handle_t key                 */ pubKey,
            /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_EdDSA_Ed25519_Pub,
            /* mcuxCl_Buffer_t pKeyData               */ (mcuxCl_Buffer_t)s_PublicKeyBufferEcc,
            /* uint32_t keyDataLength                 */ sizeof(s_PublicKeyBufferEcc)));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != pubkeyinit_token) ||
        (MCUXCLKEY_STATUS_OK != pubkeyinit_result))
    {
        PRINTF("[Error] Public key initialization failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Allocate space for and initialize EdDSA key pair generation descriptor for private key input */
    uint8_t privKeyInputDescriptor[MCUXCLECC_EDDSA_GENERATEKEYPAIR_DESCRIPTOR_SIZE];
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(initmode_result, initmode_token,
                                     mcuxClEcc_EdDSA_InitPrivKeyInputMode(
                                         /* mcuxClSession_Handle_t pSession                   */ &session,
                                         /* mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_t *mode */
                                         (mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_t *)&privKeyInputDescriptor,
                                         /* const uint8_t *pPrivKey                          */
                                         data_from_ram ? s_PrivKeyInputEcc : s_PrivKeyInputEccFlash));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_InitPrivKeyInputMode) != initmode_token) ||
        (MCUXCLECC_STATUS_OK != initmode_result))
    {
        PRINTF("[Error] Key pair generation failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Key pair generation for EdDSA on Ed25519                               */
    /**************************************************************************/

    /* Call mcuxClEcc_EdDSA_GenerateKeyPair to derive the public key from the private one. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(keygen_result, keygen_token,
                                     mcuxClEcc_EdDSA_GenerateKeyPair(
                                         /*  mcuxClSession_Handle_t pSession                          */ &session,
                                         /*  const mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_t *mode  */
                                         (mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_t *)&privKeyInputDescriptor,
                                         /*  mcuxClKey_Handle_t privKey                               */ privKey,
                                         /*  mcuxClKey_Handle_t pubKey                                */ pubKey));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_GenerateKeyPair) != keygen_token) ||
        (MCUXCLECC_STATUS_OK != keygen_result))
    {
        PRINTF("[Error] Public key derivation failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Ed25519 signature generation                                           */
    /**************************************************************************/
    a_result->signPerS = TIME_PUBLIC(GENERATE_ECC_SIGNATURE(data_from_ram, session, privKey, m_length));

    /******************************************/
    /* Clean Up                               */
    /******************************************/

    /* Destroy Session and cleanup Session */
    if (!mcuxClExample_Session_Clean(&session))
    {
        PRINTF("[Error] Session cleaning failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Disable the ELS */
    if (!mcuxClExample_Els_Disable())
    {
        PRINTF("[Error] Disabling ELS failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}

bool exec_EdDSA_verify_signature_Ed25519(char *data_from, uint32_t m_length, signature_algorithm_result *a_result)
{
    /******************************************/
    /* Set up the environment                 */
    /******************************************/

    /* Initialize ELS, Enable the ELS */
    if (!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        PRINTF("[Error] ELS initialization failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    bool data_from_ram = !strcmp(data_from, "RAM");

    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t session;

    /* Allocate and initialize PKC workarea */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(&session, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);

    /******************************************/
    /* Initialize the public key              */
    /******************************************/

    /* Initialize public key */
    uint8_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE];
    mcuxClKey_Handle_t pubKeyHandler = (mcuxClKey_Handle_t)&pubKeyDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        keyInit_status, keyInit_token,
        mcuxClKey_init(
            /* mcuxClSession_Handle_t session         */ &session,
            /* mcuxClKey_Handle_t key                 */ pubKeyHandler,
            /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_EdDSA_Ed25519_Pub,
            /* mcuxCl_Buffer_t pKeyData               */ (mcuxCl_Buffer_t)s_PublicKeyBufferEcc,
            /* uint32_t keyDataLength                 */ sizeof(s_PublicKeyBufferEcc)));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != keyInit_token) || (MCUXCLKEY_STATUS_OK != keyInit_status))
    {
        PRINTF("[Error] Public key initialization failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Ed25519 signature verification                                         */
    /**************************************************************************/
    a_result->verifyPerS = TIME_PUBLIC(ECC_VERIFY(data_from_ram, session, pubKeyHandler, m_length));

    /* Destroy Session and cleanup Session */
    if (!mcuxClExample_Session_Clean(&session))
    {
        PRINTF("[Error] Session cleaning failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Disable the ELS */
    if (!mcuxClExample_Els_Disable())
    {
        PRINTF("[Error] Disabling ELS failed\r\n");
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}

void test_ecc_signature(char *code_from, char *data_from, uint32_t m_length)
{
    if (!strcmp(code_from, "RAM") && !strcmp(data_from, "FLASH"))
        return;
    signature_algorithm_result a_result;
    strcpy(a_result.code, code_from);
    strcpy(a_result.data, data_from);
    strcpy(a_result.execution, m_length == MESSAGE_SMALL ? "SMALL MESSAGE" : "LARGE MESSAGE");
    exec_EdDSA_generate_signature_Ed25519(data_from, m_length, &a_result);
    exec_EdDSA_verify_signature_Ed25519(data_from, m_length, &a_result);

    PRINT_SIGNATURE_RESULT(a_result);
}

void test_rsa_signature(char *code_from, char *data_from, uint32_t m_length)
{
    if (!strcmp(code_from, "RAM") && !strcmp(data_from, "FLASH"))
        return;
    signature_algorithm_result a_result;
    strcpy(a_result.code, code_from);
    strcpy(a_result.data, data_from);
    strcpy(a_result.execution, m_length == 32U ? "SHA-256" : "SHA-512");
    exec_rsa_sign_pss_sha(data_from, m_length, &a_result);
    exec_rsa_verify_pss_sha(data_from, m_length, &a_result);

    PRINT_SIGNATURE_RESULT(a_result);
}

void run_tests_asymmetric(void)
{
    char code_from[6U];
    strcpy(code_from, BOARD_IS_XIP() ? "FLASH" : "RAM");

    PRINTF("ECC-EDDSA-ED25519:\r\n");
    test_ecc_signature(code_from, "RAM", MESSAGE_LARGE);
    test_ecc_signature(code_from, "FLASH", MESSAGE_LARGE);
    test_ecc_signature(code_from, "RAM", MESSAGE_SMALL);
    test_ecc_signature(code_from, "FLASH", MESSAGE_SMALL);
    PRINTF("\r\n");

    PRINTF("RSA-PSS-SHA:\r\n");
    test_rsa_signature(code_from, "RAM", 64U);
    test_rsa_signature(code_from, "FLASH", 64U);
    test_rsa_signature(code_from, "RAM", 32U);
    test_rsa_signature(code_from, "FLASH", 32U);
    PRINTF("\r\n");
}
