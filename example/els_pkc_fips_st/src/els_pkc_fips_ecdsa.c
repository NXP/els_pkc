/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "els_pkc_fips_ecdsa.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define RSA2048_MODULUS (2048U)
#define RSA3072_MODULUS (3072U)
#define RSA4096_MODULUS (4096U)

#define MAX_CPUWA_SIZE                                                    \
    MCUXCLCORE_MAX(MCUXCLECC_EDDSA_GENERATEKEYPAIR_ED25519_WACPU_SIZE, \
                      MCUXCLECC_EDDSA_GENERATESIGNATURE_ED25519_WACPU_SIZE)
#define MAX_PKCWA_SIZE                                                    \
    MCUXCLCORE_MAX(MCUXCLECC_EDDSA_GENERATEKEYPAIR_ED25519_WAPKC_SIZE, \
                      MCUXCLECC_EDDSA_GENERATESIGNATURE_ED25519_WAPKC_SIZE)
/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/
/* Domain parameters for ECDSA Weierstrass curve */
static const uint8_t s_BN_P256_P[256U / 8U] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU};

static const uint8_t s_BN_P256_A[256U / 8U] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFCU};

static const uint8_t s_BN_P256_B[256U / 8U] = {
    0x5AU, 0xC6U, 0x35U, 0xD8U, 0xAAU, 0x3AU, 0x93U, 0xE7U, 0xB3U, 0xEBU, 0xBDU, 0x55U, 0x76U, 0x98U, 0x86U, 0xBCU,
    0x65U, 0x1DU, 0x06U, 0xB0U, 0xCCU, 0x53U, 0xB0U, 0xF6U, 0x3BU, 0xCEU, 0x3CU, 0x3EU, 0x27U, 0xD2U, 0x60U, 0x4BU};

static const uint8_t s_BN_P256_G[2U * 256U / 8U] = {
    0x6BU, 0x17U, 0xD1U, 0xF2U, 0xE1U, 0x2CU, 0x42U, 0x47U, 0xF8U, 0xBCU, 0xE6U, 0xE5U, 0x63U, 0xA4U, 0x40U, 0xF2U,
    0x77U, 0x03U, 0x7DU, 0x81U, 0x2DU, 0xEBU, 0x33U, 0xA0U, 0xF4U, 0xA1U, 0x39U, 0x45U, 0xD8U, 0x98U, 0xC2U, 0x96U,
    0x4FU, 0xE3U, 0x42U, 0xE2U, 0xFEU, 0x1AU, 0x7FU, 0x9BU, 0x8EU, 0xE7U, 0xEBU, 0x4AU, 0x7CU, 0x0FU, 0x9EU, 0x16U,
    0x2BU, 0xCEU, 0x33U, 0x57U, 0x6BU, 0x31U, 0x5EU, 0xCEU, 0xCBU, 0xB6U, 0x40U, 0x68U, 0x37U, 0xBFU, 0x51U, 0xF5U};

static const uint8_t s_BN_P256_N[256U / 8U] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xBCU, 0xE6U, 0xFAU, 0xADU, 0xA7U, 0x17U, 0x9EU, 0x84U, 0xF3U, 0xB9U, 0xCAU, 0xC2U, 0xFCU, 0x63U, 0x25U, 0x51U};

static const uint8_t s_BN_P384_P[48U] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU};

static const uint8_t s_BN_P384_A[48U] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFCU};

static const uint8_t s_BN_P384_B[48U] = {
    0xB3U, 0x31U, 0x2FU, 0xA7U, 0xE2U, 0x3EU, 0xE7U, 0xE4U, 0x98U, 0x8EU, 0x05U, 0x6BU, 0xE3U, 0xF8U, 0x2DU, 0x19U,
    0x18U, 0x1DU, 0x9CU, 0x6EU, 0xFEU, 0x81U, 0x41U, 0x12U, 0x03U, 0x14U, 0x08U, 0x8FU, 0x50U, 0x13U, 0x87U, 0x5AU,
    0xC6U, 0x56U, 0x39U, 0x8DU, 0x8AU, 0x2EU, 0xD1U, 0x9DU, 0x2AU, 0x85U, 0xC8U, 0xEDU, 0xD3U, 0xECU, 0x2AU, 0xEFU};

static const uint8_t s_BN_P384_G[96U] = {
    0xAAU, 0x87U, 0xCAU, 0x22U, 0xBEU, 0x8BU, 0x05U, 0x37U, 0x8EU, 0xB1U, 0xC7U, 0x1EU, 0xF3U, 0x20U, 0xADU, 0x74U,
    0x6EU, 0x1DU, 0x3BU, 0x62U, 0x8BU, 0xA7U, 0x9BU, 0x98U, 0x59U, 0xF7U, 0x41U, 0xE0U, 0x82U, 0x54U, 0x2AU, 0x38U,
    0x55U, 0x02U, 0xF2U, 0x5DU, 0xBFU, 0x55U, 0x29U, 0x6CU, 0x3AU, 0x54U, 0x5EU, 0x38U, 0x72U, 0x76U, 0x0AU, 0xB7U,
    0x36U, 0x17U, 0xDEU, 0x4AU, 0x96U, 0x26U, 0x2CU, 0x6FU, 0x5DU, 0x9EU, 0x98U, 0xBFU, 0x92U, 0x92U, 0xDCU, 0x29U,
    0xF8U, 0xF4U, 0x1DU, 0xBDU, 0x28U, 0x9AU, 0x14U, 0x7CU, 0xE9U, 0xDAU, 0x31U, 0x13U, 0xB5U, 0xF0U, 0xB8U, 0xC0U,
    0x0AU, 0x60U, 0xB1U, 0xCEU, 0x1DU, 0x7EU, 0x81U, 0x9DU, 0x7AU, 0x43U, 0x1DU, 0x7CU, 0x90U, 0xEAU, 0x0EU, 0x5FU};

static const uint8_t s_BN_P384_N[48U] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xC7U, 0x63U, 0x4DU, 0x81U, 0xF4U, 0x37U, 0x2DU, 0xDFU,
    0x58U, 0x1AU, 0x0DU, 0xB2U, 0x48U, 0xB0U, 0xA7U, 0x7AU, 0xECU, 0xECU, 0x19U, 0x6AU, 0xCCU, 0xC5U, 0x29U, 0x73U};

static const uint8_t s_BN_P521_P[66U] = {0x01U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                                         0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                                         0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                                         0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                                         0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                                         0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU};

static const uint8_t s_BN_P521_A[66U] = {0x01U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                                         0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                                         0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                                         0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                                         0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                                         0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFCU};

static const uint8_t s_BN_P521_B[66U] = {0x00U, 0x51U, 0x95U, 0x3EU, 0xB9U, 0x61U, 0x8EU, 0x1CU, 0x9AU, 0x1FU, 0x92U,
                                         0x9AU, 0x21U, 0xA0U, 0xB6U, 0x85U, 0x40U, 0xEEU, 0xA2U, 0xDAU, 0x72U, 0x5BU,
                                         0x99U, 0xB3U, 0x15U, 0xF3U, 0xB8U, 0xB4U, 0x89U, 0x91U, 0x8EU, 0xF1U, 0x09U,
                                         0xE1U, 0x56U, 0x19U, 0x39U, 0x51U, 0xECU, 0x7EU, 0x93U, 0x7BU, 0x16U, 0x52U,
                                         0xC0U, 0xBDU, 0x3BU, 0xB1U, 0xBFU, 0x07U, 0x35U, 0x73U, 0xDFU, 0x88U, 0x3DU,
                                         0x2CU, 0x34U, 0xF1U, 0xEFU, 0x45U, 0x1FU, 0xD4U, 0x6BU, 0x50U, 0x3FU, 0x00U};

static const uint8_t s_BN_P521_G[2U * 66U] = {
    0x00U, 0xC6U, 0x85U, 0x8EU, 0x06U, 0xB7U, 0x04U, 0x04U, 0xE9U, 0xCDU, 0x9EU, 0x3EU, 0xCBU, 0x66U, 0x23U,
    0x95U, 0xB4U, 0x42U, 0x9CU, 0x64U, 0x81U, 0x39U, 0x05U, 0x3FU, 0xB5U, 0x21U, 0xF8U, 0x28U, 0xAFU, 0x60U,
    0x6BU, 0x4DU, 0x3DU, 0xBAU, 0xA1U, 0x4BU, 0x5EU, 0x77U, 0xEFU, 0xE7U, 0x59U, 0x28U, 0xFEU, 0x1DU, 0xC1U,
    0x27U, 0xA2U, 0xFFU, 0xA8U, 0xDEU, 0x33U, 0x48U, 0xB3U, 0xC1U, 0x85U, 0x6AU, 0x42U, 0x9BU, 0xF9U, 0x7EU,
    0x7EU, 0x31U, 0xC2U, 0xE5U, 0xBDU, 0x66U, 0x01U, 0x18U, 0x39U, 0x29U, 0x6AU, 0x78U, 0x9AU, 0x3BU, 0xC0U,
    0x04U, 0x5CU, 0x8AU, 0x5FU, 0xB4U, 0x2CU, 0x7DU, 0x1BU, 0xD9U, 0x98U, 0xF5U, 0x44U, 0x49U, 0x57U, 0x9BU,
    0x44U, 0x68U, 0x17U, 0xAFU, 0xBDU, 0x17U, 0x27U, 0x3EU, 0x66U, 0x2CU, 0x97U, 0xEEU, 0x72U, 0x99U, 0x5EU,
    0xF4U, 0x26U, 0x40U, 0xC5U, 0x50U, 0xB9U, 0x01U, 0x3FU, 0xADU, 0x07U, 0x61U, 0x35U, 0x3CU, 0x70U, 0x86U,
    0xA2U, 0x72U, 0xC2U, 0x40U, 0x88U, 0xBEU, 0x94U, 0x76U, 0x9FU, 0xD1U, 0x66U, 0x50U};

static const uint8_t s_BN_P521_N[66U] = {0x01U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                                         0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                                         0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                                         0xFAU, 0x51U, 0x86U, 0x87U, 0x83U, 0xBFU, 0x2FU, 0x96U, 0x6BU, 0x7FU, 0xCCU,
                                         0x01U, 0x48U, 0xF7U, 0x09U, 0xA5U, 0xD0U, 0x3BU, 0xB5U, 0xC9U, 0xB8U, 0x89U,
                                         0x9CU, 0x47U, 0xAEU, 0xBBU, 0x6FU, 0xB7U, 0x1EU, 0x91U, 0x38U, 0x64U, 0x09U};

/* Private key input for ECC-Weier */
static const uint8_t s_PrivateKeyInputWeier256[32U] = {
    0xE9U, 0x46U, 0xFFU, 0x12U, 0xFFU, 0xB2U, 0xE7U, 0xBAU, 0x2CU, 0x5DU, 0x3AU, 0xAFU, 0x7DU, 0x9AU, 0xEEU, 0xE2U,
    0x00U, 0x59U, 0x7AU, 0xABU, 0x20U, 0xCAU, 0xB0U, 0xF9U, 0x6BU, 0xD4U, 0x84U, 0x75U, 0x3DU, 0x78U, 0xFEU, 0xF4U};

static const uint8_t s_PrivateKeyInputWeier384[48U] = {
    0x8EU, 0x49U, 0xBFU, 0x1CU, 0x5DU, 0x9CU, 0xBEU, 0x73U, 0xD5U, 0xD3U, 0xDCU, 0xD7U, 0xBBU, 0x57U, 0x6AU, 0x2BU,
    0xDEU, 0x17U, 0xB1U, 0xAAU, 0xA7U, 0xCCU, 0x31U, 0xD0U, 0x24U, 0x10U, 0xB0U, 0xE6U, 0x9FU, 0xF7U, 0x42U, 0x4BU,
    0xA6U, 0x58U, 0x87U, 0x41U, 0x6AU, 0x04U, 0x14U, 0x43U, 0x4CU, 0x25U, 0x5CU, 0xECU, 0x9DU, 0x84U, 0x36U, 0x88U};

static const uint8_t s_PrivateKeyInputWeier521[66U] = {
    0x00U, 0xA8U, 0x14U, 0x1AU, 0xE2U, 0xF5U, 0x5FU, 0xFCU, 0x6EU, 0x4AU, 0x39U, 0xF2U, 0x0FU, 0x3DU,
    0x53U, 0x47U, 0x19U, 0xB0U, 0x6BU, 0x32U, 0xC7U, 0xBDU, 0xEAU, 0x46U, 0x40U, 0x58U, 0xE2U, 0xC6U,
    0x73U, 0xD4U, 0xE2U, 0x35U, 0x73U, 0x8FU, 0x0FU, 0x49U, 0x08U, 0x2AU, 0x8FU, 0xE7U, 0xAAU, 0x47U,
    0x1DU, 0x2AU, 0x73U, 0x61U, 0xCAU, 0x2CU, 0xF7U, 0x60U, 0x6EU, 0x85U, 0xDBU, 0xD7U, 0x03U, 0xBEU,
    0xA6U, 0x3FU, 0xB3U, 0xCDU, 0x8CU, 0x78U, 0x72U, 0xA9U, 0x4BU, 0x20U};

/* Public key input for ECC-Weier */
static const uint8_t s_PublicKeyInputWeier256[64U] = {
    0x52U, 0x03U, 0x46U, 0xA7U, 0x4AU, 0x71U, 0xE0U, 0x4DU, 0x39U, 0xFEU, 0x4BU, 0x20U, 0x1BU, 0xF7U, 0x4CU, 0x92U,
    0xB6U, 0xBEU, 0x9FU, 0x88U, 0x11U, 0x1EU, 0x7CU, 0x31U, 0x63U, 0x13U, 0xB3U, 0xFCU, 0x94U, 0x85U, 0xDAU, 0xD9U,
    0x70U, 0x7AU, 0xBDU, 0x51U, 0x8EU, 0x51U, 0xC2U, 0xD6U, 0x56U, 0x54U, 0xC4U, 0xD9U, 0x86U, 0xE7U, 0x76U, 0x9FU,
    0x4EU, 0xA1U, 0xD9U, 0x37U, 0x39U, 0xF7U, 0xC3U, 0xABU, 0x73U, 0x89U, 0xBDU, 0x30U, 0x03U, 0x17U, 0x9BU, 0xD9U};

static const uint8_t s_PublicKeyInputWeier384[96U] = {
    0x89U, 0xF1U, 0xB7U, 0x32U, 0x2DU, 0x68U, 0xEFU, 0x8AU, 0x73U, 0x17U, 0xB2U, 0x98U, 0x72U, 0xF0U, 0xE1U, 0x10U,
    0x8AU, 0xFFU, 0xF7U, 0x19U, 0x53U, 0x83U, 0x79U, 0x4AU, 0x1CU, 0x94U, 0x08U, 0xA2U, 0x16U, 0xE6U, 0x18U, 0x0AU,
    0xF3U, 0xC3U, 0x7FU, 0x69U, 0x6AU, 0xE8U, 0xCBU, 0xF0U, 0x34U, 0x8DU, 0x14U, 0x8AU, 0x9AU, 0x22U, 0x75U, 0x1DU,
    0x57U, 0x39U, 0x14U, 0x3EU, 0xE8U, 0xAFU, 0xB6U, 0x51U, 0x35U, 0x83U, 0x6CU, 0xBDU, 0x35U, 0x97U, 0x4DU, 0x67U,
    0x53U, 0xB7U, 0x12U, 0x7DU, 0xAAU, 0xDDU, 0xB2U, 0xEEU, 0x0AU, 0x60U, 0x39U, 0xFBU, 0xF0U, 0xE5U, 0x77U, 0x8CU,
    0x76U, 0xD0U, 0x6CU, 0x28U, 0xBBU, 0x66U, 0xEAU, 0xA9U, 0x4EU, 0xA3U, 0x14U, 0x6BU, 0x53U, 0xA6U, 0xA6U, 0x22U};

static const uint8_t s_PublicKeyInputWeier521[132U] = {
    0x00U, 0x4BU, 0x29U, 0xF5U, 0xEFU, 0x68U, 0xBBU, 0x53U, 0x47U, 0xA5U, 0x4AU, 0x76U, 0x6AU, 0x09U, 0x80U,
    0xD6U, 0x1FU, 0x45U, 0xA1U, 0x90U, 0xD8U, 0xBBU, 0x4EU, 0xFDU, 0x88U, 0x90U, 0x5FU, 0xA6U, 0xABU, 0x6AU,
    0x6DU, 0x6BU, 0x5EU, 0xFAU, 0x5BU, 0x3EU, 0xB4U, 0xBCU, 0x4CU, 0xB4U, 0x98U, 0x6BU, 0xF0U, 0xB5U, 0x99U,
    0xACU, 0xB1U, 0xAAU, 0xD8U, 0x62U, 0xADU, 0xE0U, 0xCAU, 0x7AU, 0x22U, 0x4AU, 0xE0U, 0xC5U, 0xAEU, 0x6DU,
    0x6EU, 0x9EU, 0x97U, 0x88U, 0xDDU, 0xA0U, 0x01U, 0x01U, 0x08U, 0x21U, 0x53U, 0x9BU, 0xDAU, 0x45U, 0x0FU,
    0xCBU, 0x07U, 0x93U, 0x8EU, 0xFCU, 0x8EU, 0xE5U, 0x56U, 0xF8U, 0x8AU, 0xE0U, 0xC8U, 0x06U, 0xA8U, 0x7CU,
    0xD2U, 0x1AU, 0x1EU, 0x82U, 0x8EU, 0x3AU, 0xECU, 0x00U, 0x5EU, 0x0DU, 0x90U, 0x5FU, 0x13U, 0xF5U, 0x50U,
    0xE1U, 0xA1U, 0x95U, 0x6DU, 0x76U, 0x80U, 0xEEU, 0x9AU, 0xC5U, 0x88U, 0xBEU, 0x42U, 0x85U, 0x5CU, 0x15U,
    0xDDU, 0xCBU, 0x97U, 0xA9U, 0xFAU, 0x1BU, 0x24U, 0x91U, 0x98U, 0xA5U, 0x49U, 0x8EU};

/* Example value for Sha2-512 message digest used for ECDSA */
static const uint8_t s_MessageDigest64Byte[64U] = {
    0x8DU, 0xE6U, 0xC2U, 0x3DU, 0x6CU, 0xFCU, 0xDEU, 0x8EU, 0x3DU, 0x30U, 0x4FU, 0xEBU, 0x56U, 0x4EU, 0x69U, 0xEFU,
    0x2EU, 0x6CU, 0xD3U, 0xF4U, 0x62U, 0x2AU, 0x6CU, 0xE5U, 0x49U, 0xA8U, 0x84U, 0xFCU, 0x36U, 0xF7U, 0xACU, 0x59U,
    0xE8U, 0xE8U, 0xCBU, 0x96U, 0xC9U, 0xBFU, 0x73U, 0x67U, 0xD2U, 0xB9U, 0x0CU, 0x03U, 0x3CU, 0x30U, 0xA1U, 0xA6U,
    0xB2U, 0x4FU, 0xB3U, 0x79U, 0x80U, 0x2EU, 0xC1U, 0x86U, 0x12U, 0xECU, 0x50U, 0xCCU, 0xACU, 0x20U, 0x48U, 0xECU};

/* Example value for Sha2-256 message digest used for ECDSA NIST256P */
static const uint8_t s_MessageDigest32Byte[32U] = {
    0x44U, 0x2FU, 0x78U, 0xA5U, 0x3BU, 0x61U, 0x88U, 0xA6U, 0xB1U, 0x8AU, 0x22U, 0x5CU, 0x86U, 0xAEU, 0xB9U, 0xC7U,
    0x75U, 0x92U, 0xADU, 0xD0U, 0xD7U, 0x14U, 0xD2U, 0x6FU, 0x8DU, 0x84U, 0xC9U, 0xE4U, 0xF9U, 0xF5U, 0x9AU, 0x77U};

/* KATs for ECDSA */
static const uint8_t s_EcdsaSign256pKat[64U] = {
    0x6BU, 0x17U, 0xD1U, 0xF2U, 0xE1U, 0x2CU, 0x42U, 0x47U, 0xF8U, 0xBCU, 0xE6U, 0xE5U, 0x63U, 0xA4U, 0x40U, 0xF2U,
    0x77U, 0x03U, 0x7DU, 0x81U, 0x2DU, 0xEBU, 0x33U, 0xA0U, 0xF4U, 0xA1U, 0x39U, 0x45U, 0xD8U, 0x98U, 0xC2U, 0x96U,
    0x7AU, 0x2EU, 0x7DU, 0x49U, 0x58U, 0x7AU, 0xEAU, 0x97U, 0xEBU, 0xC5U, 0x0BU, 0x14U, 0x69U, 0x56U, 0xC0U, 0x2FU,
    0x95U, 0x9EU, 0xCAU, 0x6CU, 0x20U, 0x20U, 0x0AU, 0xD3U, 0xEDU, 0xE8U, 0xACU, 0x8CU, 0x52U, 0xF0U, 0x8EU, 0x0CU};

static const uint8_t s_EcdsaSign384pKat[96U] = {
    0xAAU, 0x87U, 0xCAU, 0x22U, 0xBEU, 0x8BU, 0x05U, 0x37U, 0x8EU, 0xB1U, 0xC7U, 0x1EU, 0xF3U, 0x20U, 0xADU, 0x74U,
    0x6EU, 0x1DU, 0x3BU, 0x62U, 0x8BU, 0xA7U, 0x9BU, 0x98U, 0x59U, 0xF7U, 0x41U, 0xE0U, 0x82U, 0x54U, 0x2AU, 0x38U,
    0x55U, 0x02U, 0xF2U, 0x5DU, 0xBFU, 0x55U, 0x29U, 0x6CU, 0x3AU, 0x54U, 0x5EU, 0x38U, 0x72U, 0x76U, 0x0AU, 0xB7U,
    0xE7U, 0x3EU, 0x6EU, 0x0EU, 0x09U, 0x69U, 0xF2U, 0xB5U, 0xCEU, 0xF1U, 0xD0U, 0xB0U, 0x49U, 0x09U, 0xB8U, 0x26U,
    0x17U, 0xD2U, 0x53U, 0xD4U, 0xB3U, 0xC7U, 0xAEU, 0x4CU, 0x7DU, 0x09U, 0xF0U, 0x3DU, 0x83U, 0xBAU, 0xDEU, 0x32U,
    0xBFU, 0x5BU, 0x9FU, 0x2DU, 0x8BU, 0x73U, 0x25U, 0xF5U, 0xDFU, 0x37U, 0x62U, 0x91U, 0x72U, 0x5DU, 0xD9U, 0x03U};

static const uint8_t s_EcdsaSign521pKat[132U] = {
    0x00U, 0xC6U, 0x85U, 0x8EU, 0x06U, 0xB7U, 0x04U, 0x04U, 0xE9U, 0xCDU, 0x9EU, 0x3EU, 0xCBU, 0x66U, 0x23U,
    0x95U, 0xB4U, 0x42U, 0x9CU, 0x64U, 0x81U, 0x39U, 0x05U, 0x3FU, 0xB5U, 0x21U, 0xF8U, 0x28U, 0xAFU, 0x60U,
    0x6BU, 0x4DU, 0x3DU, 0xBAU, 0xA1U, 0x4BU, 0x5EU, 0x77U, 0xEFU, 0xE7U, 0x59U, 0x28U, 0xFEU, 0x1DU, 0xC1U,
    0x27U, 0xA2U, 0xFFU, 0xA8U, 0xDEU, 0x33U, 0x48U, 0xB3U, 0xC1U, 0x85U, 0x6AU, 0x42U, 0x9BU, 0xF9U, 0x7EU,
    0x7EU, 0x31U, 0xC2U, 0xE5U, 0xBDU, 0x66U, 0x01U, 0x75U, 0x32U, 0x90U, 0xD9U, 0x00U, 0x12U, 0x23U, 0xC4U,
    0x57U, 0x98U, 0xC1U, 0x32U, 0x8AU, 0xAAU, 0xB9U, 0xBAU, 0xC4U, 0xD2U, 0xCFU, 0xC1U, 0x33U, 0xEAU, 0xB0U,
    0xBAU, 0x7CU, 0x57U, 0x25U, 0x0FU, 0x94U, 0xE3U, 0x07U, 0x93U, 0xECU, 0x50U, 0x3FU, 0xAEU, 0x6DU, 0x47U,
    0xE4U, 0x17U, 0x1EU, 0x4CU, 0x65U, 0xADU, 0x00U, 0x85U, 0x08U, 0x62U, 0xD9U, 0x66U, 0xA8U, 0xE0U, 0x14U,
    0x8BU, 0x67U, 0xFAU, 0x55U, 0x53U, 0x57U, 0x3AU, 0x10U, 0x95U, 0x78U, 0x9DU, 0xCAU};

static const uint8_t s_KeyEcdsa256[32U] = {
    0x2EU, 0x9FU, 0x73U, 0xDFU, 0xCBU, 0xAEU, 0x1AU, 0xD4U, 0xF1U, 0x25U, 0x44U, 0xC4U, 0x52U, 0xDCU, 0x78U, 0x98U,
    0xB7U, 0x10U, 0x79U, 0x78U, 0x47U, 0x3EU, 0x40U, 0x2BU, 0x66U, 0x5BU, 0xB2U, 0xF5U, 0x2BU, 0xEDU, 0xC2U, 0xD6U,
};

/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
 * @brief RNG Patch function.
 */
static inline mcuxClRandom_Status_t RNG_Patch_function(mcuxClSession_Handle_t session,
                                                       mcuxClRandom_Context_t p_custom_ctx,
                                                       uint8_t *p_out,
                                                       uint32_t out_length)
{
    for (uint32_t i = 0U; i < out_length; ++i)
    {
        p_out[i] = 0U;
    }
    return MCUXCLRANDOM_STATUS_OK;
}

/*!
 * @brief Execute ECDSA Sign NIST256P on ELS.
 */
static bool ecdsa_sign_els()
{
    mcuxClEls_KeyProp_t plain_key_properties = {
        .word = {.value = MCUXCLELS_KEYPROPERTY_VALUE_SECURE | MCUXCLELS_KEYPROPERTY_VALUE_PRIVILEGED |
                          MCUXCLELS_KEYPROPERTY_VALUE_KEY_SIZE_256 | MCUXCLELS_KEYPROPERTY_VALUE_KGSRC}};

    mcuxClEls_KeyIndex_t key_index = MCUXCLELS_KEY_SLOTS;
    if (import_plain_key_into_els(s_KeyEcdsa256, sizeof(s_KeyEcdsa256), plain_key_properties, &key_index) !=
        STATUS_SUCCESS)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    // For ECC keys that were created from plain key material, there is the
    // neceessity to convert them to a key. Converting to a key also yields the public key.
    // The conversion can be done either before re-wrapping (when importing the plain key)
    // or after (when importing the blob).
    uint8_t public_key[64U] = {0U};
    size_t public_key_size  = sizeof(public_key);
    els_keygen(key_index, &public_key[0U], &public_key_size);

    mcuxClEls_EccSignOption_t sign_options = {0U};
    sign_options.bits.signrtf              = MCUXCLELS_ECC_VALUE_NO_RTF;
    mcuxClEls_EccByte_t ecc_signature[MCUXCLELS_ECC_SIGNATURE_SIZE];
    mcuxClEls_EccByte_t ecc_signature_and_public_key[MCUXCLELS_ECC_SIGNATURE_SIZE + MCUXCLELS_ECC_PUBLICKEY_SIZE];
    mcuxClEls_EccByte_t ecc_signature_r[MCUXCLELS_ECC_SIGNATURE_R_SIZE];
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        result, token,
        mcuxClEls_EccSign_Async(                     // Perform signature generation.
            sign_options,                            // Set the prepared configuration.
            key_index,                               // Set index of private key in keystore.
            s_MessageDigest32Byte, NULL, (size_t)0U, // Pre-hashed data to sign. Note that inputLength parameter is
                                                     // ignored since pre-hashed data has a fixed length.
            ecc_signature                            // Output buffer, which the operation will write the signature to.
            ));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_EccSign_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    memcpy(&ecc_signature_and_public_key[0U], // Prepare the concatenation of signature and public key: First the
                                              // signature, ...
           &ecc_signature[0U], MCUXCLELS_ECC_SIGNATURE_SIZE);
    memcpy(&ecc_signature_and_public_key[MCUXCLELS_ECC_SIGNATURE_SIZE], // ... then the public key.
           &public_key[0U], MCUXCLELS_ECC_PUBLICKEY_SIZE);

    mcuxClEls_EccVerifyOption_t verify_options = {0U};
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        result, token,
        mcuxClEls_EccVerify_Async(
            verify_options,                          // Set the prepared configuration.
            s_MessageDigest32Byte, NULL, (size_t)0U, // Pre-hashed data to verify. Note that inputLength parameter is
                                                     // ignored since pre-hashed data has a fixed length.
            ecc_signature_and_public_key,            // Signature of the pre-hashed data
            ecc_signature_r // Output buffer, which the operation will write the signature part r to, to allow external
                            // comparison of between given and recalculated r.
            ));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_EccVerify_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    mcuxClEls_HwState_t state;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_GetHwState(&state));

    // mcuxClEls_GetHwState is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_GetHwState) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    if (MCUXCLELS_STATUS_ECDSAVFY_OK != state.bits.ecdsavfy)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    return MCUXCLEXAMPLE_STATUS_OK;
}

/*!
 * @brief Execute ECC-Weier Sign.
 */
static bool ecdsa_sign(uint32_t bit_length)
{
    const uint32_t p_byte_length = (bit_length + 7U) / 8U;
    const uint32_t n_byte_length = (bit_length + 7U) / 8U;

    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/
    mcuxClSession_Descriptor_t session_desc;
    mcuxClSession_Handle_t session = &session_desc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLECC_SIGN_WACPU_SIZE,
                                                  MCUXCLECC_SIGN_WAPKC_SIZE(p_byte_length, n_byte_length));

    /* Initialize random patch mode */
    uint32_t custom_mode_desc_bytes[(MCUXCLRANDOMMODES_PATCHMODE_DESCRIPTOR_SIZE + sizeof(uint32_t) - 1U) /
                                    sizeof(uint32_t)] = {0U};
    mcuxClRandom_ModeDescriptor_t *mcuxClRandomModes_Mode_Custom =
        (mcuxClRandom_ModeDescriptor_t *)custom_mode_desc_bytes;

    uint32_t rng_context[MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE_IN_WORDS] = {0U};

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        cp_status, cp_token,
        mcuxClRandomModes_createPatchMode(mcuxClRandomModes_Mode_Custom,
                                          (mcuxClRandomModes_CustomGenerateAlgorithm_t)RNG_Patch_function,
                                          (mcuxClRandom_Context_t)rng_context, 256U));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_createPatchMode) != cp_token) ||
        (MCUXCLRANDOM_STATUS_OK != cp_status))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    uint32_t *rng_context_patched = NULL;
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(
        randomInit_result, randomInit_token,
        mcuxClRandom_init(session, (mcuxClRandom_Context_t)rng_context_patched, mcuxClRandomModes_Mode_Custom));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init) != randomInit_token) ||
        (MCUXCLRANDOM_STATUS_OK != randomInit_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Generate signature                                                     */
    /**************************************************************************/
    uint8_t signature_buffer[2U * 66U] = {0U};
    mcuxClEcc_DomainParam_t domain_params;
    switch (bit_length)
    {
        case WEIER256_BIT_LENGTH:
            domain_params =
                (mcuxClEcc_DomainParam_t){.pA   = s_BN_P256_A,
                                          .pB   = s_BN_P256_B,
                                          .pG   = s_BN_P256_G,
                                          .pP   = s_BN_P256_P,
                                          .pN   = s_BN_P256_N,
                                          .misc = mcuxClEcc_DomainParam_misc_Pack(n_byte_length, p_byte_length)};
            break;
        case WEIER384_BIT_LENGTH:
            domain_params =
                (mcuxClEcc_DomainParam_t){.pA   = s_BN_P384_A,
                                          .pB   = s_BN_P384_B,
                                          .pG   = s_BN_P384_G,
                                          .pP   = s_BN_P384_P,
                                          .pN   = s_BN_P384_N,
                                          .misc = mcuxClEcc_DomainParam_misc_Pack(n_byte_length, p_byte_length)};
            break;
        case WEIER521_BIT_LENGTH:
            domain_params =
                (mcuxClEcc_DomainParam_t){.pA   = s_BN_P521_A,
                                          .pB   = s_BN_P521_B,
                                          .pG   = s_BN_P521_G,
                                          .pP   = s_BN_P521_P,
                                          .pN   = s_BN_P521_N,
                                          .misc = mcuxClEcc_DomainParam_misc_Pack(n_byte_length, p_byte_length)};
            break;
    }

    mcuxClEcc_Sign_Param_t sign_parameters;
    mcuxClEcc_ECDSA_SignatureProtocolDescriptor_t sign_mode;
    sign_mode.generateOption = MCUXCLECC_ECDSA_SIGNATURE_GENERATE_RANDOMIZED;

    switch (bit_length)
    {
        case WEIER256_BIT_LENGTH:
            sign_parameters = (mcuxClEcc_Sign_Param_t){.curveParam  = domain_params,
                                                       .pHash       = s_MessageDigest64Byte,
                                                       .pPrivateKey = s_PrivateKeyInputWeier256,
                                                       .pSignature  = signature_buffer,
                                                       .optLen      = mcuxClEcc_Sign_Param_optLen_Pack(64U),
                                                       .pMode       = &sign_mode};
            break;
        case WEIER384_BIT_LENGTH:
            sign_parameters = (mcuxClEcc_Sign_Param_t){.curveParam  = domain_params,
                                                       .pHash       = s_MessageDigest64Byte,
                                                       .pPrivateKey = s_PrivateKeyInputWeier384,
                                                       .pSignature  = signature_buffer,
                                                       .optLen      = mcuxClEcc_Sign_Param_optLen_Pack(64U),
                                                       .pMode       = &sign_mode};
            break;
        case WEIER521_BIT_LENGTH:
            sign_parameters = (mcuxClEcc_Sign_Param_t){.curveParam  = domain_params,
                                                       .pHash       = s_MessageDigest64Byte,
                                                       .pPrivateKey = s_PrivateKeyInputWeier521,
                                                       .pSignature  = signature_buffer,
                                                       .optLen      = mcuxClEcc_Sign_Param_optLen_Pack(64U),
                                                       .pMode       = &sign_mode};
            break;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(sign_result, sign_token, mcuxClEcc_Sign(session, &sign_parameters));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Sign) != sign_token))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    if (MCUXCLECC_STATUS_INVALID_PARAMS == sign_result)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    if (MCUXCLECC_STATUS_RNG_ERROR == sign_result)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    if (MCUXCLECC_STATUS_OK != sign_result)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    switch (bit_length)
    {
        case WEIER256_BIT_LENGTH:
        {
            if (!mcuxClCore_assertEqual(signature_buffer, s_EcdsaSign256pKat, bit_length / 8U * 2U))
            {
                return MCUXCLEXAMPLE_STATUS_ERROR;
            }
            break;
        }
        case WEIER384_BIT_LENGTH:
        {
            if (!mcuxClCore_assertEqual(signature_buffer, s_EcdsaSign384pKat, bit_length / 8U * 2U))
            {
                return MCUXCLEXAMPLE_STATUS_ERROR;
            }
            break;
        }
        case WEIER521_BIT_LENGTH:
        {
            if (!mcuxClCore_assertEqual(signature_buffer, s_EcdsaSign521pKat, bit_length / 8U * 2U))
            {
                return MCUXCLEXAMPLE_STATUS_ERROR;
            }
            break;
        }
    }

    /**************************************************************************/
    /* Clean session                                                          */
    /**************************************************************************/
    if (!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}

/*!
 * @brief Execute ECC-Weier Verify.
 */
static bool ecdsa_verify(uint32_t bit_length)
{
    const uint32_t p_byte_length = (bit_length + 7U) / 8U;
    const uint32_t n_byte_length = (bit_length + 7U) / 8U;

    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/
    mcuxClSession_Descriptor_t session_desc;
    mcuxClSession_Handle_t session = &session_desc;
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLECC_VERIFY_WACPU_SIZE,
                                                  MCUXCLECC_VERIFY_WAPKC_SIZE(p_byte_length, n_byte_length));

    mcuxClEcc_DomainParam_t domain_params;
    switch (bit_length)
    {
        case WEIER256_BIT_LENGTH:
            domain_params =
                (mcuxClEcc_DomainParam_t){.pA   = s_BN_P256_A,
                                          .pB   = s_BN_P256_B,
                                          .pG   = s_BN_P256_G,
                                          .pP   = s_BN_P256_P,
                                          .pN   = s_BN_P256_N,
                                          .misc = mcuxClEcc_DomainParam_misc_Pack(n_byte_length, p_byte_length)};
            break;
        case WEIER384_BIT_LENGTH:
            domain_params =
                (mcuxClEcc_DomainParam_t){.pA   = s_BN_P384_A,
                                          .pB   = s_BN_P384_B,
                                          .pG   = s_BN_P384_G,
                                          .pP   = s_BN_P384_P,
                                          .pN   = s_BN_P384_N,
                                          .misc = mcuxClEcc_DomainParam_misc_Pack(n_byte_length, p_byte_length)};
            break;
        case WEIER521_BIT_LENGTH:
            domain_params =
                (mcuxClEcc_DomainParam_t){.pA   = s_BN_P521_A,
                                          .pB   = s_BN_P521_B,
                                          .pG   = s_BN_P521_G,
                                          .pP   = s_BN_P521_P,
                                          .pN   = s_BN_P521_N,
                                          .misc = mcuxClEcc_DomainParam_misc_Pack(n_byte_length, p_byte_length)};
            break;
    }

    uint8_t scalar_prec_G[66U]                                  = {0U};
    uint32_t scalar_bit_index                                   = 4U * n_byte_length;
    scalar_prec_G[n_byte_length - 1U - (scalar_bit_index / 8U)] = (uint8_t)1U << (scalar_bit_index & 7U);

    uint8_t result[132U]                          = {0U};
    mcuxClEcc_PointMult_Param_t point_mult_params = {.curveParam = domain_params,
                                                     .pScalar    = scalar_prec_G,
                                                     .pPoint     = domain_params.pG,
                                                     .pResult    = result,
                                                     .optLen     = 0U};
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ret_ecc_point_mult, token_ecc_point_mult,
                                     mcuxClEcc_PointMult(session, &point_mult_params));

    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointMult) != token_ecc_point_mult)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    if (MCUXCLECC_STATUS_INVALID_PARAMS == ret_ecc_point_mult)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    else if (MCUXCLECC_STATUS_OK != ret_ecc_point_mult)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();
    uint8_t output_R[66U];
    mcuxClEcc_Verify_Param_t param_verify;

    param_verify.curveParam = domain_params;
    param_verify.pPrecG     = result;
    param_verify.pHash      = s_MessageDigest64Byte;
    switch (bit_length)
    {
        case WEIER256_BIT_LENGTH:
            param_verify.pPublicKey = s_PublicKeyInputWeier256;
            param_verify.pSignature = s_EcdsaSign256pKat;
            break;
        case WEIER384_BIT_LENGTH:
            param_verify.pPublicKey = s_PublicKeyInputWeier384;
            param_verify.pSignature = s_EcdsaSign384pKat;
            break;
        case WEIER521_BIT_LENGTH:
            param_verify.pPublicKey = s_PublicKeyInputWeier521;
            param_verify.pSignature = s_EcdsaSign521pKat;
            break;
    }
    param_verify.pOutputR = output_R;
    param_verify.optLen   = mcuxClEcc_Sign_Param_optLen_Pack(64U);

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ret_ecc_verify, token_ecc_verify, mcuxClEcc_Verify(session, &param_verify));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Verify) != token_ecc_verify) || (MCUXCLECC_STATUS_OK != ret_ecc_verify))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Clean session                                                          */
    /**************************************************************************/
    if (!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}

static bool Ed25519_sign()
{
    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t session;

    /* Allocate and initialize PKC workarea */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(&session, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);

    /* Initialize the RNG context and Initialize the PRNG */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(&session, 0U, mcuxClRandomModes_Mode_ELS_Drbg);

    /******************************************/
    /* Initialize the private key */
    /******************************************/
    /* Allocate space for and initialize private key handle for an Ed25519 private key */
    uint8_t priv_key_desc[MCUXCLKEY_DESCRIPTOR_SIZE];
    mcuxClKey_Handle_t priv_key = (mcuxClKey_Handle_t)&priv_key_desc;
    uint8_t priv_key_data[MCUXCLECC_EDDSA_ED25519_SIZE_PRIVATEKEYDATA];
    uint8_t priv_key_input[32U] = {0x83U, 0x3FU, 0xE6U, 0x24U, 0x09U, 0x23U, 0x7BU, 0x9DU, 0x62U, 0xECU, 0x77U,
                                   0x58U, 0x75U, 0x20U, 0x91U, 0x1EU, 0x9AU, 0x75U, 0x9CU, 0xECU, 0x1DU, 0x19U,
                                   0x75U, 0x5BU, 0x7DU, 0xA9U, 0x01U, 0xB9U, 0x6DU, 0xCAU, 0x3DU, 0x42U};
    uint8_t public_key[MCUXCLECC_EDDSA_ED25519_SIZE_PUBLICKEY] = {0U};

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(privkeyinit_result, privkeyinit_token,
                                     mcuxClKey_init(
                                         /* mcuxClSession_Handle_t session         */ &session,
                                         /* mcuxClKey_Handle_t key                 */ priv_key,
                                         /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_EdDSA_Ed25519_Priv,
                                         /* mcuxCl_Buffer_t pKeyData               */ (mcuxCl_Buffer_t)priv_key_data,
                                         /* uint32_t keyDataLength                 */ sizeof(priv_key_data)));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != privkeyinit_token) ||
        (MCUXCLKEY_STATUS_OK != privkeyinit_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Allocate space for and initialize pbulic key handle for an Ed25519 public key */
    uint8_t pub_key_desc[MCUXCLKEY_DESCRIPTOR_SIZE];
    mcuxClKey_Handle_t pub_key = (mcuxClKey_Handle_t)&pub_key_desc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pubkeyinit_result, pubkeyinit_token,
                                     mcuxClKey_init(
                                         /* mcuxClSession_Handle_t session         */ &session,
                                         /* mcuxClKey_Handle_t key                 */ pub_key,
                                         /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_EdDSA_Ed25519_Pub,
                                         /* mcuxCl_Buffer_t pKeyData               */ (mcuxCl_Buffer_t)public_key,
                                         /* uint32_t keyDataLength                 */ sizeof(public_key)));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != pubkeyinit_token) ||
        (MCUXCLKEY_STATUS_OK != pubkeyinit_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Allocate space for and initialize EdDSA key pair generation descriptor for private key input */
    uint8_t priv_key_input_descriptor[MCUXCLECC_EDDSA_GENERATEKEYPAIR_DESCRIPTOR_SIZE];
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(initmode_result, initmode_token,
                                     mcuxClEcc_EdDSA_InitPrivKeyInputMode(
                                         /* mcuxClSession_Handle_t pSession                   */ &session,
                                         /* mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_t *mode */
                                         (mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_t *)&priv_key_input_descriptor,
                                         /* const uint8_t *pPrivKey                          */
                                         priv_key_input));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_InitPrivKeyInputMode) != initmode_token) ||
        (MCUXCLECC_STATUS_OK != initmode_result))
    {
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
                                         (mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_t *)&priv_key_input_descriptor,
                                         /*  mcuxClKey_Handle_t privKey                               */ priv_key,
                                         /*  mcuxClKey_Handle_t pubKey                                */ pub_key));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_GenerateKeyPair) != keygen_token) ||
        (MCUXCLECC_STATUS_OK != keygen_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Ed25519 signature generation                                           */
    /**************************************************************************/
    uint8_t message[64U] = {0x0EU, 0xCDU, 0x0EU, 0x60U, 0xEDU, 0x33U, 0xADU, 0xEBU, 0xB2U, 0x18U, 0x07U, 0x77U, 0x7BU,
                            0xB4U, 0x83U, 0x45U, 0x7DU, 0x45U, 0x76U, 0xC5U, 0x91U, 0x19U, 0x83U, 0x17U, 0x71U, 0xAAU,
                            0xDDU, 0x5CU, 0xA6U, 0xE4U, 0x7DU, 0xA0U, 0x1FU, 0x05U, 0xC0U, 0x71U, 0x1DU, 0xFFU, 0xE0U,
                            0x0DU, 0x19U, 0x30U, 0xD1U, 0xE3U, 0xECU, 0xABU, 0xB7U, 0xC6U, 0x5FU, 0x54U, 0x8EU, 0x82U,
                            0x07U, 0x73U, 0x95U, 0x71U, 0x22U, 0x6FU, 0x24U, 0xC1U, 0x70U, 0x38U, 0x1CU, 0x0DU};

    uint8_t signature_buffer[64U] = {0U};
    uint32_t signature_size       = 0U;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        sign_result, sign_token,
        mcuxClEcc_EdDSA_GenerateSignature(&session, priv_key, &mcuxClEcc_EdDsa_Ed25519ProtocolDescriptor, message, 64U,
                                          signature_buffer, &signature_size));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_GenerateSignature) != sign_token) ||
        (MCUXCLECC_EDDSA_ED25519_SIZE_SIGNATURE != signature_size) || (MCUXCLECC_STATUS_OK != sign_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    uint8_t signature_kat[] = {
        0xEBU, 0x61U, 0xA1U, 0x61U, 0x16U, 0x5BU, 0x25U, 0x7FU, 0xC8U, 0xE2U, 0x7CU, 0xBAU, 0x68U, 0x28U, 0x08U, 0x76U,
        0xC2U, 0x42U, 0xC9U, 0x6EU, 0x70U, 0xC6U, 0x62U, 0x39U, 0x34U, 0x85U, 0xD5U, 0xC7U, 0xF0U, 0xB6U, 0xC6U, 0xC8U,
        0x0CU, 0x48U, 0x20U, 0x48U, 0xD7U, 0x5DU, 0xBDU, 0x1EU, 0xACU, 0x9FU, 0xD0U, 0x5BU, 0x45U, 0x12U, 0x69U, 0xFBU,
        0x88U, 0x1AU, 0x8BU, 0x21U, 0xA6U, 0x51U, 0x59U, 0xCAU, 0xEEU, 0x6DU, 0x13U, 0x9DU, 0x72U, 0xFDU, 0xDBU, 0x0FU};

    if (!mcuxClCore_assertEqual(signature_buffer, signature_kat, signature_size))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /******************************************/
    /* Clean Up                               */
    /******************************************/
    /* Destroy Session and cleanup Session */
    if (!mcuxClExample_Session_Clean(&session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}

static bool Ed25519_verify()
{
    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t session;

    uint8_t signature_kat[] = {
        0xEBU, 0x61U, 0xA1U, 0x61U, 0x16U, 0x5BU, 0x25U, 0x7FU, 0xC8U, 0xE2U, 0x7CU, 0xBAU, 0x68U, 0x28U, 0x08U, 0x76U,
        0xC2U, 0x42U, 0xC9U, 0x6EU, 0x70U, 0xC6U, 0x62U, 0x39U, 0x34U, 0x85U, 0xD5U, 0xC7U, 0xF0U, 0xB6U, 0xC6U, 0xC8U,
        0x0CU, 0x48U, 0x20U, 0x48U, 0xD7U, 0x5DU, 0xBDU, 0x1EU, 0xACU, 0x9FU, 0xD0U, 0x5BU, 0x45U, 0x12U, 0x69U, 0xFBU,
        0x88U, 0x1AU, 0x8BU, 0x21U, 0xA6U, 0x51U, 0x59U, 0xCAU, 0xEEU, 0x6DU, 0x13U, 0x9DU, 0x72U, 0xFDU, 0xDBU, 0x0FU};

    /* Allocate and initialize PKC workarea */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(&session, MAX_CPUWA_SIZE, MAX_PKCWA_SIZE);

    /******************************************/
    /* Initialize the public key              */
    /******************************************/
    /* Initialize public key */
    uint8_t pub_key_desc[MCUXCLKEY_DESCRIPTOR_SIZE];
    mcuxClKey_Handle_t pub_key_handler                         = (mcuxClKey_Handle_t)&pub_key_desc;
    uint8_t public_key[MCUXCLECC_EDDSA_ED25519_SIZE_PUBLICKEY] = {
        0xECU, 0x17U, 0x2BU, 0x93U, 0xADU, 0x5EU, 0x56U, 0x3BU, 0xF4U, 0x93U, 0x2CU, 0x70U, 0xE1U, 0x24U, 0x50U, 0x34U,
        0xC3U, 0x54U, 0x67U, 0xEFU, 0x2EU, 0xFDU, 0x4DU, 0x64U, 0xEBU, 0xF8U, 0x19U, 0x68U, 0x34U, 0x67U, 0xE2U, 0xBFU};

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(keyInit_status, keyInit_token,
                                     mcuxClKey_init(
                                         /* mcuxClSession_Handle_t session         */ &session,
                                         /* mcuxClKey_Handle_t key                 */ pub_key_handler,
                                         /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_EdDSA_Ed25519_Pub,
                                         /* mcuxCl_Buffer_t pKeyData               */ (mcuxCl_Buffer_t)public_key,
                                         /* uint32_t keyDataLength                 */ sizeof(public_key)));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != keyInit_token) || (MCUXCLKEY_STATUS_OK != keyInit_status))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Ed25519 signature verification                                         */
    /**************************************************************************/
    uint8_t message[64U] = {0x0EU, 0xCDU, 0x0EU, 0x60U, 0xEDU, 0x33U, 0xADU, 0xEBU, 0xB2U, 0x18U, 0x07U, 0x77U, 0x7BU,
                            0xB4U, 0x83U, 0x45U, 0x7DU, 0x45U, 0x76U, 0xC5U, 0x91U, 0x19U, 0x83U, 0x17U, 0x71U, 0xAAU,
                            0xDDU, 0x5CU, 0xA6U, 0xE4U, 0x7DU, 0xA0U, 0x1FU, 0x05U, 0xC0U, 0x71U, 0x1DU, 0xFFU, 0xE0U,
                            0x0DU, 0x19U, 0x30U, 0xD1U, 0xE3U, 0xECU, 0xABU, 0xB7U, 0xC6U, 0x5FU, 0x54U, 0x8EU, 0x82U,
                            0x07U, 0x73U, 0x95U, 0x71U, 0x22U, 0x6FU, 0x24U, 0xC1U, 0x70U, 0x38U, 0x1CU, 0x0DU};

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        verify_result, verify_token,
        mcuxClEcc_EdDSA_VerifySignature(&session, pub_key_handler, &mcuxClEcc_EdDsa_Ed25519ProtocolDescriptor, message,
                                        sizeof(message), signature_kat, sizeof(signature_kat)));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_VerifySignature) != verify_token) ||
        (MCUXCLECC_STATUS_OK != verify_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    if (!mcuxClExample_Session_Clean(&session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}

void execute_ecdsa_kat(uint64_t options, char name[])
{
    if ((options & FIPS_ECDSA_256P) || (options & FIPS_ALL_TESTS))
    {
        if (!ecdsa_sign_els())
        {
            PRINTF("[ERROR] NON DET. %s PCT FAILED\r\n", name);
        }
        if (!ecdsa_sign(WEIER256_BIT_LENGTH))
        {
            PRINTF("[ERROR] %s SIGN KAT FAILED\r\n", name);
        }
        if (!ecdsa_verify(WEIER256_BIT_LENGTH))
        {
            PRINTF("[ERROR] %s VERIFY KAT FAILED\r\n", name);
        }
    }
    if ((options & FIPS_ECDSA_384P) || (options & FIPS_ALL_TESTS))
    {
        if (!ecdsa_sign(WEIER384_BIT_LENGTH))
        {
            PRINTF("[ERROR] %s SIGN KAT FAILED\r\n", name);
        }
        if (!ecdsa_verify(WEIER384_BIT_LENGTH))
        {
            PRINTF("[ERROR] %s VERIFY KAT FAILED\r\n", name);
        }
    }
    if ((options & FIPS_ECDSA_521P) || (options & FIPS_ALL_TESTS))
    {
        if (!ecdsa_sign(WEIER521_BIT_LENGTH))
        {
            PRINTF("[ERROR] %s SIGN KAT FAILED\r\n", name);
        }
        if (!ecdsa_verify(WEIER521_BIT_LENGTH))
        {
            PRINTF("[ERROR] %s VERIFY KAT FAILED\r\n", name);
        }
    }
}

void execute_eddsa_kat(uint64_t options, char name[])
{
    if ((options & FIPS_EDDSA) || (options & FIPS_ALL_TESTS))
    {
        if (!Ed25519_sign())
        {
            PRINTF("[ERROR] %s SIGN KAT FAILED\r\n", name);
        }
        if (!Ed25519_verify())
        {
            PRINTF("[ERROR] %s VERIFY KAT FAILED\r\n", name);
        }
    }
}