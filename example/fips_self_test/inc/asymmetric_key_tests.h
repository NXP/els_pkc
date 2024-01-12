/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _ASYMMETRIC_KEY_TESTS_H_
#define _ASYMMETRIC_KEY_TESTS_H_

#include "RSASigGen15_186_3.h"
#include "RSASigVer15_186_3.h"
#include "fips_self_test_util.h"

#include <mcuxClRsa.h>
#include <mcuxClPkc_Types.h>

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*!
 * @brief Execute KAT for RSA RSA PKCSV1.5 sign and verify.
 *
 * @retval true if KAT passed.
 * @retval false if KAT fails.
 */
bool execute_rsa_kat(void);

#endif /* _ASYMMETRIC_KEY_TESTS_H_ */
