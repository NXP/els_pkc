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

/**
 * @file  mcuxClEcc_Mont_Internal_SecureScalarMult_XZMontLadder_FUP.h
 * @brief defines FUP programs byte arrays
 */


#ifndef MCUXCLECC_MONT_INTERNAL_SECURESCALARMULT_XZMONTLADDER_FUP_H_
#define MCUXCLECC_MONT_INTERNAL_SECURESCALARMULT_XZMONTLADDER_FUP_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <internal/mcuxClPkc_FupMacros.h>


/**
 * FUP program declaration mcuxClEcc_FUP_SecureScalarMult_XZMontLadder_LadderStep
 */
#define mcuxClEcc_FUP_SecureScalarMult_XZMontLadder_LadderStep_Affine_LEN  19u
#define mcuxClEcc_FUP_SecureScalarMult_XZMontLadder_LadderStep_Projective_LEN  22u
extern const mcuxClPkc_FUPEntry_t mcuxClEcc_FUP_SecureScalarMult_XZMontLadder_LadderStep[mcuxClEcc_FUP_SecureScalarMult_XZMontLadder_LadderStep_Projective_LEN];


#endif /* MCUXCLECC_MONT_INTERNAL_SECURESCALARMULT_XZMONTLADDER_FUP_H_ */
