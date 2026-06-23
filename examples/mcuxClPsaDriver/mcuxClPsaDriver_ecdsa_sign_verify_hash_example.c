/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
/*                                                                          */
/* SPDX-License-Identifier: BSD-3-Clause                                    */
/*                                                                          */
/* Redistribution and use in source and binary forms, with or without       */
/* modification, are permitted provided that the following conditions are   */
/* met:                                                                     */
/*                                                                          */
/* 1. Redistributions of source code must retain the above copyright        */
/*    notice, this list of conditions and the following disclaimer.         */
/*                                                                          */
/* 2. Redistributions in binary form must reproduce the above copyright     */
/*    notice, this list of conditions and the following disclaimer in the   */
/*    documentation and/or other materials provided with the distribution.  */
/*                                                                          */
/* 3. Neither the name of the copyright holder nor the names of its         */
/*    contributors may be used to endorse or promote products derived from  */
/*    this software without specific prior written permission.              */
/*                                                                          */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS  */
/* IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED    */
/* TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A          */
/* PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT       */
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,   */
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED */
/* TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR   */
/* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF   */
/* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS       */
/* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.             */
/*--------------------------------------------------------------------------*/

#include "common.h"

#include <mcuxClToolchain.h>
#include <mcuxClSession.h> // Interface to the entire mcuxClSession component
#include <mcuxCsslFlowProtection.h> // Code flow protection
#include <mcuxClPsaDriver.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_ELS_Helper.h>

/**
 * @brief ECC private key used in signature.
 */
static const ALIGNED uint8_t privateKeyBuffer[PSA_BITS_TO_BYTES(256u)] = {
  0x8F, 0xDF, 0x49, 0xC9, 0xDF, 0x2C, 0x3B, 0x91, 0x78, 0x5F, 0xE2, 0xF9, 0xF0, 0x1F, 0x94, 0x6D,
  0x07, 0x1A, 0x1C, 0xB3, 0x21, 0x1E, 0x8F, 0xD7, 0xA6, 0x2B, 0xEE, 0xF5, 0x48, 0x3E, 0xF7, 0x22
};

/**
 * @brief ECC public key used in verification.
 */
static const ALIGNED uint8_t publicKeyBuffer[2u * PSA_BITS_TO_BYTES(256u) + 1u] = {
  0x04,
  0x55, 0xAB, 0x4C, 0x42, 0x0E, 0x4B, 0x95, 0x79, 0x8D, 0x82, 0xC6, 0x29, 0x75, 0x99, 0x9A, 0x8F,
  0xBB, 0xFA, 0xD9, 0x72, 0xCB, 0x00, 0x68, 0x9B, 0x8A, 0xFA, 0x58, 0x6C, 0x55, 0xD5, 0xAE, 0xCE,
  0xFC, 0xE3, 0x04, 0xBE, 0x0F, 0xE9, 0x11, 0xED, 0xFA, 0x83, 0x07, 0x5D, 0x29, 0x9D, 0x0F, 0x2B,
  0xA1, 0x1B, 0xB9, 0x65, 0x83, 0xCC, 0x99, 0x92, 0x03, 0xEB, 0x71, 0xED, 0x72, 0xA7, 0x63, 0xA8
 };

/**
 * @brief Hash of message to be signed
 */
static const ALIGNED uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)] = {
  0x89, 0x01, 0x41, 0x9f, 0x26, 0x14, 0xc9, 0x42, 0xc9, 0xee, 0x5e, 0xfb, 0xdf, 0xba, 0x0c, 0xca,
  0x70, 0x6b, 0x3a, 0x4e, 0xd1, 0xa8, 0x5f, 0x69, 0x28, 0xb7, 0x60, 0xff, 0x1b, 0xba, 0xb0, 0xe7
};

/*
 *Example of ECDSA signature generation and verification for:
 * - key size 256
 * - SHA-256
 * - signature scheme PSA_ALG_ECDSA_ANY
 */
MCUXCLEXAMPLE_FUNCTION(mcuxClPsaDriver_ecdsa_sign_verify_hash_example)
{
  /**
   * @brief Signature
   */
  MCUX_CSSL_ANALYSIS_START_PATTERN_EXTERNAL_MACRO()
  ALIGNED uint8_t signature[PSA_SIGN_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR_BASE, 256u, PSA_ALG_ECDSA_ANY)];
  MCUX_CSSL_ANALYSIS_STOP_PATTERN_EXTERNAL_MACRO()

  /** Initialize ELS, Enable the ELS **/
  if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
  {
      return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  /*
   * Sign hash: PSA_ALG_ECDSA_ANY, SHA_256
   */

  /* Set up PSA key attributes. */
  const psa_key_attributes_t sign_attributes = {
    .core = {                                                                                                                // Core attributes
      .type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),                                                             // Curve secp256r1
      .bits = 256u,                                                                                                          // Key size in bits
      .lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_LOCATION_LOCAL_STORAGE), // Volatile (RAM), Local Storage for private key
      .id = 0U,                                                                                                              // ID zero
      .policy = {
        .usage = PSA_KEY_USAGE_SIGN_HASH,                                                                                    // Key may be used for signing a hash
        .alg = PSA_ALG_ECDSA_ANY,                                                                                            // ECDSA signature scheme without specifying a hash algorithm
        .alg2 = PSA_ALG_NONE},
      .flags = 0U},                                                                                                          // No flags
    .domain_parameters = NULL,
    .domain_parameters_size = 0U};

  size_t signature_length;

  psa_status_t sign_status = psa_driver_wrapper_sign_hash(
    &sign_attributes,           //const psa_key_attributes_t *attributes,
    privateKeyBuffer,           //const uint8_t *key_buffer,
    sizeof(privateKeyBuffer),   //size_t key_buffer_size,
    PSA_ALG_ECDSA_ANY,          //psa_algorithm_t alg,
    hash,                       //const uint8_t *hash,
    sizeof(hash),               //size_t hash_length,
    signature,                  //uint8_t *signature,
    sizeof(signature),          //size_t signature_size,
    &signature_length           //size_t *signature_length
    );

  /* Check the return value */
  if(sign_status != PSA_SUCCESS)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  /* Check the signature length */
MCUX_CSSL_ANALYSIS_START_PATTERN_EXTERNAL_MACRO()
  if(signature_length != PSA_SIGN_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR_BASE, 256u, PSA_ALG_ECDSA_ANY))
MCUX_CSSL_ANALYSIS_STOP_PATTERN_EXTERNAL_MACRO()
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }
  
  /*
   * Verify hash: PSA_ALG_ECDSA_ANY, SHA_256
   */

  /* Set up PSA key attributes. */
  const psa_key_attributes_t verify_attributes = {
    .core = {                                                                                                                // Core attributes
      .type = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1),                                                           // Curve secp256r1
      .bits = 256u,                                                                                                          // Key bits
      .lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_LOCATION_LOCAL_STORAGE), // Volatile (RAM), Local Storage for public key
      .id = 0U,                                                                                                              // ID zero
      .policy = {
        .usage = PSA_KEY_USAGE_VERIFY_HASH,                                                                                  // Key may be used for verify a hash
        .alg = PSA_ALG_ECDSA_ANY,                                                                                            // ECDSA signature scheme without specifying a hash algorithm
        .alg2 = PSA_ALG_NONE},
      .flags = 0U},                                                                                                          // No flags
    .domain_parameters = NULL,
    .domain_parameters_size = 0U};

  psa_status_t verify_status = psa_driver_wrapper_verify_hash(
    &verify_attributes,         //const psa_key_attributes_t *attributes,
    publicKeyBuffer,            //const uint8_t *key_buffer,
    sizeof(publicKeyBuffer),    //size_t key_buffer_size,
    PSA_ALG_ECDSA_ANY,          //psa_algorithm_t alg,
    hash,                       //const uint8_t *hash,
    sizeof(hash),               //size_t hash_length,
    signature,                  //const uint8_t *signature,
    sizeof(signature)           //size_t signature_length
    );

  /* Check the return value */
  if(verify_status != PSA_SUCCESS)
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  /* Disable the ELS */
  if(!mcuxClExample_Els_Disable())
  {
    return MCUXCLEXAMPLE_STATUS_ERROR;
  }

  /* Return */
  return MCUXCLEXAMPLE_STATUS_OK;
}

