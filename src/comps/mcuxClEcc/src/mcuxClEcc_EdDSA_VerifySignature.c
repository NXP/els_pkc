/*--------------------------------------------------------------------------*/
/* Copyright 2022 NXP                                                       */
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

/**
 * @file  mcuxClEcc_EdDSA_VerifySignature.c
 * @brief implementation of TwEd_EdDsaVerify function
 */


#include <stdint.h>

#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <mcuxClEcc.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_EdDSA_VerifySignature)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_EdDSA_VerifySignature(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Handle_t key,
    const mcuxClEcc_EdDSA_SignatureProtocolDescriptor_t *mode,
    const uint8_t *pIn,
    uint32_t inSize,
    const uint8_t *pSignature,
    uint32_t signatureSize )
{
    (void)pSession;
    (void)key;
    (void)mode;
    (void)pIn;
    (void)inSize;
    (void)pSignature;
    (void)signatureSize;

    return MCUXCLECC_STATUS_FAULT_ATTACK;
}
