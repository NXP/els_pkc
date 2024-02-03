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
 * @param options Containing which algorithm to execute.
 * @param name Containing the name of the algorithm.
 */
void execute_cbc_kat(uint64_t options, char name[]);

/*!
 * @brief Execute KAT for ECB encrypt and decrypt.
 *
 * @param options Containing which algorithm to execute.
 * @param name Containing the name of the algorithm.
 */
void execute_ecb_kat(uint64_t options, char name[]);

/*!
 * @brief Execute KAT for CCM encrypt and decrypt.
 *
 * @param options Containing which algorithm to execute.
 * @param name Containing the name of the algorithm.
 */
void execute_ccm_kat(uint64_t options, char name[]);

/*!
 * @brief Execute KAT for GCM encrypt and decrypt.
 *
 * @param options Containing which algorithm to execute.
 * @param name Containing the name of the algorithm.
 */
void execute_gcm_kat(uint64_t options, char name[]);

/*!
 * @brief Execute KAT for CTR encrypt and decrypt.
 *
 * @param options Containing which algorithm to execute.
 * @param name Containing the name of the algorithm.
 */
void execute_ctr_kat(uint64_t options, char name[]);

/*!
 * @brief Execute KAT for CMAC encrypt and decrypt.
 *
 * @param options Containing which algorithm to execute.
 * @param name Containing the name of the algorithm.
 */
void execute_cmac_kat(uint64_t options, char name[]);

#endif /* _ELS_PKC_FIPS_SYMMETRIC_H_ */
