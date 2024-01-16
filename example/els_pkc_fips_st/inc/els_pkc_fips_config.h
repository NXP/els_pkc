/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _ELS_PKC_FIPS_CONFIG_H_
#define _ELS_PKC_FIPS_CONFIG_H_

#include "els_pkc_fips_util.h"
#include "els_pkc_fips_symmetric.h"
#include "els_pkc_fips_asymmetric.h"
#include "els_pkc_fips_hmac.h"
#include "els_pkc_fips_hash.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define FIPS_AES_CBC_128 (1 << 0)
#define FIPS_AES_CBC_192 (1 << 1)
#define FIPS_AES_CBC_256 (1 << 2)
#define FIPS_AES_ECB_128 (1 << 3)
#define FIPS_AES_ECB_192 (1 << 4)
#define FIPS_AES_ECB_256 (1 << 5)
#define FIPS_AES_CTR_128 (1 << 6)
#define FIPS_AES_CTR_192 (1 << 7)
#define FIPS_AES_CTR_256 (1 << 8)
#define FIPS_AES_GCM_128 (1 << 9)
#define FIPS_AES_GCM_192 (1 << 10)
#define FIPS_AES_GCM_256 (1 << 11)
#define FIPS_AES_CCM_128 (1 << 12)
#define FIPS_AES_CCM_192 (1 << 13)
#define FIPS_AES_CCM_256 (1 << 14)

typedef struct
{
    uint64_t option;
    bool (*executionFunction)(uint64_t options);
} AlgorithmMapping;

static AlgorithmMapping s_AlgorithmMappings[] = {
    {FIPS_AES_CBC_128, execute_cbc_kat}, {FIPS_AES_CBC_192, execute_cbc_kat}, {FIPS_AES_CBC_256, execute_cbc_kat}};

static uint64_t s_UserOptions = FIPS_AES_CBC_128 | FIPS_AES_CBC_128;

#endif /* _ELS_PKC_FIPS_CONFIG_H_ */
