/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023 NXP                                                  */
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
 * @file  mcuxClPsaDriver_els_eccp256_ecdsa_example.c
 * @brief Example for ECC signing using an internal ELS key
 *
 * @example mcuxClPsaDriver_els_eccp256_ecdsa_example.c
 * @brief Example for ECC signing using an internal ELS key
 */

#include "common.h"

#include <mcuxClEls.h> // Interface to the entire mcuxClEls component
#include <mcuxClSession.h> // Interface to the entire mcuxClSession component
#include <mcuxClKey.h> // Interface to the entire mcuxClKey component
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <toolchain.h> // memory segment definitions
#include <stdbool.h>  // bool type for the example's return code
#include <mcuxClPsaDriver.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_ELS_Helper.h>
#include <mcuxClExample_ELS_Key_Helper.h>
#include <psa_stub.h>

  /* Input digest to be signed */
  static uint32_t const ecc_digest[MCUXCLELS_HASH_OUTPUT_SIZE_SHA_256 / sizeof(uint32_t)] = { 0x11111111,
                                                                                              0x22222222,
                                                                                              0x33333333,
                                                                                              0x44444444,
                                                                                              0x55555555,
                                                                                              0x66666666,
                                                                                              0x77777777,
                                                                                              0x88888888};

/** Destination buffer to receive the public key of the mcuxClEls_EccKeyGen_Async operation. */
static uint32_t ecc_public_key[MCUXCLELS_ECC_PUBLICKEY_SIZE / sizeof(uint32_t)];
#define LIFETIME_INTERNAL PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_LOCATION_ORACLE_S50_STORAGE)
#define LIFETIME_EXTERNAL PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_LOCATION_LOCAL_STORAGE)

bool mcuxClPsaDriver_els_eccp256_ecdsa_example(void)
{
  uint32_t keyBuffer[32u/sizeof(uint32_t)] = {0}; //key buffer to be able to store whole 256bit long key, but key index inside. keyIdx 32bit long, so buffer word wise aligned

  /** Initialize ELS, Enable the ELS **/
  if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
  {
      return MCUXCLEXAMPLE_ERROR;
  }

  /* Generate signing key */
psa_key_attributes_t attributes = {
      .core = {                                                               // Core attributes
        .type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),            // Keypair family with curve SECP_R1
        .bits = MCUXCLKEY_SIZE_256 * 8u,                                     // Key bits of SECP_R1_P256
        .lifetime = LIFETIME_INTERNAL,                                        // Volatile (RAM), S50 Temporary Storage for private key
        .id = 0U,                                                             // ID zero
        .policy = {
          .usage =  PSA_KEY_USAGE_SIGN_HASH,      // Key may be used for sign message or hash
          .alg = PSA_ALG_ECDSA_ANY,
          .alg2 = PSA_ALG_NONE},
        .flags = 0U},                                                         // No flags
      .domain_parameters = NULL,
      .domain_parameters_size = 0U};

    /* Call generate_key operation */
    uint8_t key_buffer[MCUXCLKEY_SIZE_256] = {0U};
    size_t key_buffer_size = MCUXCLKEY_SIZE_256;
    size_t key_buffer_length = 0U;

    psa_status_t status = psa_driver_wrapper_generate_key(
                &attributes,
                key_buffer, key_buffer_size, &key_buffer_length);

    /* Check the return value */
    if(status != PSA_SUCCESS)
    {
        return MCUXCLEXAMPLE_ERROR;
    }

  /* Variable for the output length of the encryption operation */
  size_t output_length = 0U;

  /* Call the sign hash operation */
  uint32_t ecc_signature[MCUXCLELS_ECC_SIGNATURE_SIZE/sizeof(uint32_t)] = {0U};
  size_t signature_length = 0U;
  psa_status_t statusSignHash = psa_driver_wrapper_sign_hash(
              &attributes,                   // const psa_key_attributes_t *attributes,
              (uint8_t *)keyBuffer,          // const uint8_t *key_buffer,
              sizeof(keyBuffer),             // size_t key_buffer_size,
              PSA_ALG_ECDSA_ANY,             // psa_algorithm_t alg,
              (const uint8_t *)ecc_digest,   // const uint8_t *hash,
              sizeof(ecc_digest),            // size_t hash_length,
              (uint8_t *)&ecc_signature,     // uint8_t *signature,
              MCUXCLELS_ECC_SIGNATURE_SIZE,   // size_t signature_size,
              &signature_length              // size_t *signature_length
              );

  /* Check the return value */
  if(statusSignHash != PSA_SUCCESS)
  {
    return MCUXCLEXAMPLE_ERROR;
  }

  /* Check the output length */
  if(signature_length != MCUXCLELS_ECC_SIGNATURE_SIZE)
  {
    return MCUXCLEXAMPLE_ERROR;
  }

  /** Disable the ELS **/
  if(!mcuxClExample_Els_Disable())
  {
      return MCUXCLEXAMPLE_ERROR;
  }

  /* Return */
  return MCUXCLEXAMPLE_OK;
}
