/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _ELS_PKC_FIPS_ASYMMETRIC_H_
#define _ELS_PKC_FIPS_ASYMMETRIC_H_

#include "els_pkc_fips_util.h"
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

#endif /* _ELS_PKC_FIPS_ASYMMETRIC_H_ */
