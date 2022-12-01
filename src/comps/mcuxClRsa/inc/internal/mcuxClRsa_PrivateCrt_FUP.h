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

/** @file  mcuxClRsa_PrivateCrt_FUP.h
*  @brief defines FUP programs byte arrays for mcuxClRsa_PrivateCrt
*/
#ifndef MCUXCLRSA_PRIVATECRT_FUP_H_
#define MCUXCLRSA_PRIVATECRT_FUP_H_
#include <mcuxClConfig.h> // Exported features flags header
#include <internal/mcuxClPkc_FupMacros.h>

#define mcuxClRsa_PrivateCrt_T1mb_LEN            3u
#define mcuxClRsa_PrivateCrt_T2T3T4mb_LEN        6u
#define mcuxClRsa_PrivateCrt_CalcM_b_LEN         5u
#define mcuxClRsa_PrivateCrt_CalcM1_LEN          4u
#define mcuxClRsa_PrivateCrt_ReductionME_LEN     3u

extern const mcuxClPkc_FUPEntry_t mcuxClRsa_PrivateCrt_T2T3T4mb[mcuxClRsa_PrivateCrt_T2T3T4mb_LEN];
extern const mcuxClPkc_FUPEntry_t mcuxClRsa_PrivateCrt_T1mb[mcuxClRsa_PrivateCrt_T1mb_LEN];
extern const mcuxClPkc_FUPEntry_t mcuxClRsa_PrivateCrt_CalcM1[mcuxClRsa_PrivateCrt_CalcM1_LEN];
extern const mcuxClPkc_FUPEntry_t mcuxClRsa_PrivateCrt_CalcM_b[mcuxClRsa_PrivateCrt_CalcM_b_LEN];
extern const mcuxClPkc_FUPEntry_t mcuxClRsa_PrivateCrt_ReductionME[mcuxClRsa_PrivateCrt_ReductionME_LEN];

#endif /* MCUXCLRSA_PRIVATECRT_FUP_H_ */ 
