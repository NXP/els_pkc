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

#ifndef MCUXCLRANDOM_PRIVATE_NORMALMODE_H_
#define MCUXCLRANDOM_PRIVATE_NORMALMODE_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>

#include <mcuxClSession_Types.h>
#include <mcuxClRandom_Types.h>
#include <internal/mcuxClRandom_Private_Types.h>
#include <internal/mcuxClRandom_Private_Drbg.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Internal function prototypes */

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandom_NormalMode_initFunction)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_NormalMode_initFunction(mcuxClSession_Handle_t pSession);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandom_NormalMode_reseedFunction)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_NormalMode_reseedFunction(mcuxClSession_Handle_t pSession);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandom_NormalMode_generateFunction)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_NormalMode_generateFunction(mcuxClSession_Handle_t pSession, uint8_t *pOut, uint32_t outLength);

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandom_NormalMode_selftestFunction)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_NormalMode_selftestFunction(mcuxClSession_Handle_t pSession, mcuxClRandom_Mode_t mode);

mcuxClRandom_Status_t mcuxClRandom_selftest_VerifyArrays(uint32_t length, uint32_t *expected, uint32_t *actual);
mcuxClRandom_Status_t mcuxClRandom_selftest_CheckContext(mcuxClRandom_Context_Generic_t *pCtx, uint32_t *pExpectedKey, uint32_t *pExpectedCounterV);


extern const mcuxClRandom_OperationModeDescriptor_t mcuxClRandom_OperationModeDescriptor_NormalMode;

#endif /* MCUXCLRANDOM_PRIVATE_NORMALMODE_H_ */
