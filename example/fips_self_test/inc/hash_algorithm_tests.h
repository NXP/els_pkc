/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _HASH_ALGORITHM_TESTS_H_
#define _HASH_ALGORITHM_TESTS_H_
#include "SHA256ShortMsg.h"
#include "SHA384ShortMsg.h"
#include "SHA512ShortMsg.h"
#include "fips_self_test_util.h"
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

#endif /* _HASH_ALGORITHM_TESTS_H_ */
