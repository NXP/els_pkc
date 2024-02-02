/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _ELS_PKC_FIPS_KDF_H_
#define _ELS_PKC_FIPS_KDF_H_

#include "els_pkc_fips_util.h"
#include "mcuxClEls_Ecc.h"
#include "mcuxClEls_Kdf.h"
#include "mcuxClEls_Cipher.h"
#include "mcuxClEls_Cmac.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*!
 * @brief Execute KAT for KDF.
 *
 * @param options Containing which algorithm to execute.
 */
void execute_kdf(uint64_t options);


#endif /* _ELS_PKC_FIPS_KDF_H_ */
