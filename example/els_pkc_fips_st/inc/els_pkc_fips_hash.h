/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _ELS_PKC_FIPS_HASH_H_
#define _ELS_PKC_FIPS_HASH_H_

#include "els_pkc_fips_util.h"
#include <mcuxClHash.h>
#include <mcuxClHashModes.h>

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*!
 * @brief Execute KAT for SHA hash algorithms.
 *
 * @retval true if KAT passed.
 * @retval false if KAT fails.
#*/
bool execute_sha_kat(void);

#endif /* _ELS_PKC_FIPS_HASH_H_ */
