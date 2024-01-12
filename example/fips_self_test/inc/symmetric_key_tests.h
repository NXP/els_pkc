/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _SYMMETRIC_KEY_TESTS_H_
#define _SYMMETRIC_KEY_TESTS_H_
#include "CBCVarKey128.h"
#include "CMACGenAES256.h"
#include "fips_self_test_util.h"
#include <mcuxClCipher.h>      /* Interface to the entire mcuxClCipher component */
#include <mcuxClCipherModes.h> /* Interface to the entire mcuxClCipherModes component */
#include <mcuxClAeadModes.h>
#include <mcuxClAead.h>     /* Interface to the entire mcuxClAead component */
#include <mcuxClMac.h>      /* Interface to the entire mcuxClMac component */
#include <mcuxClMacModes.h> /* Interface to the entire mcuxClMacModes component */

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*!
 * @brief Execute KAT for CBC encrypt and decrypt.
 *
 * @retval true if KAT passed.
 * @retval false if KAT fails.
 */
bool execute_cbc_kat(void);

/*!
 * @brief Execute KAT for CAMC encrypt and decrypt.
 *
 * @retval true if KAT passed.
 * @retval false if KAT fails.
 */
bool execute_cmac_kat(void);

#endif /* _SYMMETRIC_KEY_TESTS_H_ */
