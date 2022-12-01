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

#ifndef MCUXCLRANDOM_PRIVATE_CTRDRBG_CSS_H_
#define MCUXCLRANDOM_PRIVATE_CTRDRBG_CSS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>

#include <internal/mcuxClRandom_Private_Drbg.h>


#ifdef __cplusplus
extern "C" {
#endif

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandom_DRBG_AES_Internal_blockcipher)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_DRBG_AES_Internal_blockcipher(
    uint8_t *pV,
    uint8_t *pKey,
    uint8_t *pOut,
    uint32_t keyLength
);

#endif /* MCUXCLRANDOM_PRIVATE_CTRDRBG_CSS_H_ */
