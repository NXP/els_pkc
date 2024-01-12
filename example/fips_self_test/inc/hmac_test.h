/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _HMAC_TESTS_H_
#define _HMAC_TESTS_H_
#include "SHA256ShortMsg.h"
#include "SHA384ShortMsg.h"
#include "SHA512ShortMsg.h"
#include "fips_self_test_util.h"
#include "HMAC.h"
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

#endif /* _HMAC_TESTS_H_ */
