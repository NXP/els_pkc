/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _ELS_PKC_FIPS_CONFIG_H_
#define _ELS_PKC_FIPS_CONFIG_H_

#include "els_pkc_fips_symmetric.h"
#include "els_pkc_fips_asymmetric.h"
#include "els_pkc_fips_hmac.h"
#include "els_pkc_fips_hash.h"
#include "els_pkc_fips_drbg.h"
#include "els_pkc_fips_kdf.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
typedef struct
{
    uint64_t option;
    void (*executionFunction)(uint64_t options);
} AlgorithmMapping;

static AlgorithmMapping s_AlgorithmMappings[] = {
    {FIPS_ECB_DRBG, execute_drbg}, {FIPS_CTR_DRBG, execute_drbg}, {FIPS_CKDF, execute_kdf}};

static uint64_t s_UserOptions = FIPS_CTR_DRBG;

#endif /* _ELS_PKC_FIPS_CONFIG_H_ */
