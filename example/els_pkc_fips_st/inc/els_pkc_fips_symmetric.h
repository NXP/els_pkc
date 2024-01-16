/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _ELS_PKC_FIPS_SYMMETRIC_H_
#define _ELS_PKC_FIPS_SYMMETRIC_H_

#include "els_pkc_fips_util.h"
#include <mcuxClCipher.h>      /* Interface to the entire mcuxClCipher component */
#include <mcuxClCipherModes.h> /* Interface to the entire mcuxClCipherModes component */
#include <mcuxClAeadModes.h>
#include <mcuxClAead.h>        /* Interface to the entire mcuxClAead component */
#include <mcuxClMac.h>         /* Interface to the entire mcuxClMac component */
#include <mcuxClMacModes.h>    /* Interface to the entire mcuxClMacModes component */

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*!
 * @brief Execute KAT for CBC encrypt and decrypt.
 *
 * @param options .
 * @retval true if KAT passed.
 * @retval false if KAT fails.
 */
bool execute_cbc_kat(uint64_t options);

/*!
 * @brief Execute KAT for ECB encrypt and decrypt.
 *
 * @retval true if KAT passed.
 * @retval false if KAT fails.
 */
bool execute_ecb_kat(uint64_t options);

/*!
 * @brief Execute KAT for CCM encrypt and decrypt.
 *
 * @retval true if KAT passed.
 * @retval false if KAT fails.
 */
bool execute_ccm_kat(uint64_t options);

/*!
 * @brief Execute KAT for GCM encrypt and decrypt.
 *
 * @retval true if KAT passed.
 * @retval false if KAT fails.
 */
bool execute_gcm_kat(uint64_t options);

/*!
 * @brief Execute KAT for CTR encrypt and decrypt.
 *
 * @retval true if KAT passed.
 * @retval false if KAT fails.
 */
bool execute_ctr_kat(uint64_t options);

/*!
 * @brief Execute KAT for CAMC encrypt and decrypt.
 *
 * @retval true if KAT passed.
 * @retval false if KAT fails.
 */
bool execute_cmac_kat(void);

#endif /* _ELS_PKC_FIPS_SYMMETRIC_H_ */
