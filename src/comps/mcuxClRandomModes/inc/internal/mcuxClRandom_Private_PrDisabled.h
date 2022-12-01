/*--------------------------------------------------------------------------*/
/* Copyright 2021 NXP                                                       */
/*                                                                          */
/* NXP Confidential. This software is owned or controlled by NXP and may    */
/* only be used strictly in accordance with the applicable license terms.   */
/* By expressly accepting such terms or by downloading, installing,         */
/* activating and/or otherwise using the software, you are agreeing that    */
/* you have read, and that you agree to comply with and are bound by, such  */
/* license terms. If you do not agree to be bound by the applicable license */
/* terms, then you may not retain, install, activate or otherwise use the   */
/* software.                                                                */
/*--------------------------------------------------------------------------*/
/* Security Classification:  Company Confidential                           */
/*--------------------------------------------------------------------------*/

#ifndef MCUXCLRANDOM_PRIVATE_PRDISABLED_H_
#define MCUXCLRANDOM_PRIVATE_PRDISABLED_H_

#include <mcuxClConfig.h> // Exported features flags header

#ifdef __cplusplus
extern "C" {
#endif

#define MCUXCLRANDOM_TESTVECTORS_INDEX_ENTROPY_PRDISABLED        ( 0u)
#define MCUXCLRANDOM_TESTVECTORS_INDEX_ENTROPY_RESEED_PRDISABLED ( 1u)
#define MCUXCLRANDOM_TESTVECTORS_INDEX_INIT_KEY_PRDISABLED       ( 2u)
#define MCUXCLRANDOM_TESTVECTORS_INDEX_INIT_V_PRDISABLED         ( 3u)
#define MCUXCLRANDOM_TESTVECTORS_INDEX_RESEED_KEY_PRDISABLED     ( 4u)
#define MCUXCLRANDOM_TESTVECTORS_INDEX_RESEED_V_PRDISABLED       ( 5u)
#define MCUXCLRANDOM_TESTVECTORS_INDEX_GENONE_KEY_PRDISABLED     ( 6u)
#define MCUXCLRANDOM_TESTVECTORS_INDEX_GENONE_V_PRDISABLED       ( 7u)
#define MCUXCLRANDOM_TESTVECTORS_INDEX_GENTWO_KEY_PRDISABLED     ( 8u)
#define MCUXCLRANDOM_TESTVECTORS_INDEX_GENTWO_V_PRDISABLED       ( 9u)
#define MCUXCLRANDOM_TESTVECTORS_INDEX_RANDOMDATA_PRDISABLED     (10u)
#define MCUXCLRANDOM_NO_OF_TESTVECTORS_PRDISABLED (MCUXCLRANDOM_TESTVECTORS_INDEX_RANDOMDATA_PRDISABLED + 1u)

extern const uint32_t * const mcuxClRandom_TestVectors_Aes128_NoDf_PrDisabled[MCUXCLRANDOM_NO_OF_TESTVECTORS_PRDISABLED];
extern const uint32_t * const mcuxClRandom_TestVectors_Aes256_NoDf_PrDisabled[MCUXCLRANDOM_NO_OF_TESTVECTORS_PRDISABLED];

/* Internal function prototypes */
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_PrDisabled_generatePrHandler(mcuxClSession_Handle_t pSession);
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_PrDisabled_selftestPrHandler(mcuxClSession_Handle_t pSession, mcuxClRandom_Context_t testCtx, mcuxClRandom_Mode_t mode);

extern const mcuxClRandom_DrbgPrModeDescriptor_t mcuxClRandom_DrbgPrModeDescriptor_PrDisabled;

#endif /* MCUXCLRANDOM_PRIVATE_PRDISABLED_H_ */
