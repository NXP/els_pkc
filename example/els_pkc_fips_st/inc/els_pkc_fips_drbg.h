/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _ELS_PKC_FIPS_DRBG_H_
#define _ELS_PKC_FIPS_DRBG_H_

#include "els_pkc_fips_util.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*!
 * @brief Execute KAT for DRBG.
 *
 * @param options Containing which algorithm to execute.
 */
void execute_drbg(uint64_t options);

#endif /* _ELS_PKC_FIPS_DRBG_H_ */
