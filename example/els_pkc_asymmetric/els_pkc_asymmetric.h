/*
 * Copyright 2022 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _ELS_PKC_ASYMMETRIC_H_
#define _ELS_PKC_ASYMMETRIC_H_

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define EXIT_CODE_ERROR 0x00U
#define EXIT_CODE_OK    0x01U
/*******************************************************************************
 * API
 ******************************************************************************/
extern bool ecc_keygen_sign_verify(void);
extern bool mcuxClRsa_sign_NoEncode_example(void);
extern bool mcuxClRsa_sign_pss_sha2_256_example(void);
extern bool mcuxClRsa_verify_NoVerify_example(void);
extern bool mcuxClRsa_verify_pssverify_sha2_256_example(void);
extern bool mcuxClEcc_Mont_Curve25519_example(void);
extern bool tls_master_key_session_keys(void);

#endif /* _ELS_PKC_ASYMMETRIC_H_ */
