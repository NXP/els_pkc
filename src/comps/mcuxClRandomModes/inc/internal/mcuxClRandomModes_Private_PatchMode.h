/*--------------------------------------------------------------------------*/
/* Copyright 2021-2022 NXP                                                  */
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

#ifndef MCUXCLRANDOMMODES_PRIVATE_PATCHMODE_H_
#define MCUXCLRANDOMMODES_PRIVATE_PATCHMODE_H_

#include <mcuxClConfig.h> // Exported features flags header

#include <mcuxClSession.h>
#include <mcuxClRandom_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Internal function prototypes */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandomModes_PatchMode_initFunction)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandomModes_PatchMode_initFunction(mcuxClSession_Handle_t session);
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandomModes_PatchMode_reseedFunction)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandomModes_PatchMode_reseedFunction(mcuxClSession_Handle_t session);
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandomModes_PatchMode_generateFunction)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandomModes_PatchMode_generateFunction(mcuxClSession_Handle_t session, uint8_t *pOut, uint32_t outLength);
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandomModes_PatchMode_selftestFunction)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandomModes_PatchMode_selftestFunction(mcuxClSession_Handle_t session, mcuxClRandom_Mode_t mode);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLRANDOMMODES_PRIVATE_PATCHMODE_H_ */
