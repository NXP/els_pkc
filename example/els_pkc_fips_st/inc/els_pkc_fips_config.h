/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _ELS_PKC_FIPS_CONFIG_H_
#define _ELS_PKC_FIPS_CONFIG_H_

#include "els_pkc_fips_symmetric.h"
#include "els_pkc_fips_rsa.h"
#include "els_pkc_fips_ecdsa.h"
#include "els_pkc_fips_hmac.h"
#include "els_pkc_fips_hash.h"
#include "els_pkc_fips_drbg.h"
#include "els_pkc_fips_kdf.h"
#include "els_pkc_fips_ecdh.h"
#include "els_pkc_fips_key_gen.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
typedef struct
{
    uint64_t option;
    char name[50U];
    void (*executionFunction)(uint64_t options, char name[]);
} AlgorithmMapping;

static AlgorithmMapping s_AlgorithmMappings[] = {{FIPS_ECB_DRBG, "ECB_DRBG", execute_drbg_kat},
                                                 {FIPS_CTR_DRBG, "CTR_DRBG", execute_drbg_kat},
                                                 {FIPS_CKDF, "CKDF SP800-108", execute_kdf_kat},
                                                 {FIPS_ECDSA_256P, "ECDSA-256P", execute_ecdsa_kat},
                                                 {FIPS_ECDSA_384P, "ECDSA-384P", execute_ecdsa_kat},
                                                 {FIPS_ECDSA_521P, "ECDSA-521P", execute_ecdsa_kat},
                                                 {FIPS_EDDSA, "ED25519", execute_eddsa_kat},
                                                 {FIPS_ECDH256P, "ECDH-256P", execute_ecdh_kat},
                                                 {FIPS_ECDH384P, "ECDH-384P", execute_ecdh_kat},
                                                 {FIPS_ECDH521P, "ECDH-521P", execute_ecdh_kat},
                                                 {FIPS_ECC_KEYGEN_256P, "ECC-KEY-GEN-256P", execute_ecc_keygen_pct},
                                                 {FIPS_ECC_KEYGEN_384P, "ECC-KEYGEN-384P", execute_ecc_keygen_pct},
                                                 {FIPS_ECC_KEYGEN_521P, "ECC-KEYGEN-521P", execute_ecc_keygen_pct},
                                                 {FIPS_RSA_PKCS15_2048, "RSA-PKCS15-2048", execute_rsa_kat},
                                                 {FIPS_RSA_PKCS15_3072, "RSA-PKCS15-3072", execute_rsa_kat},
                                                 {FIPS_RSA_PKCS15_4096, "RSA-PKCS15-4096", execute_rsa_kat},
                                                 {FIPS_RSA_PSS_2048, "RSA-PSS-2048", execute_rsa_kat},
                                                 {FIPS_RSA_PSS_3072, "RSA-PSS-3072", execute_rsa_kat},
                                                 {FIPS_RSA_PSS_4096, "RSA-PSS-4096", execute_rsa_kat}};

static uint64_t s_UserOptions = FIPS_RSA_PKCS15_2048 | FIPS_ECDSA_384P;

#endif /* _ELS_PKC_FIPS_CONFIG_H_ */
