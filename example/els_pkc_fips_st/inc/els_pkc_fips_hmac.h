/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _ELS_PKC_FIPS_HMAC_H_
#define _ELS_PKC_FIPS_HMAC_H_

#include "els_pkc_fips_util.h"
#include <mcuxClHash.h>
#include <mcuxClMac.h>
#include <mcuxClHashModes.h>
#include <mcuxClMacModes.h>
#include <mcuxClHmac.h>

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*!
 * @brief Execute KAT for HMAC.
 *
 * @retval true if KAT passed.
 * @retval false if KAT fails.
#*/
bool execute_hmac_kat(void);

#endif /* _ELS_PKC_FIPS_HMAC_H_ */
