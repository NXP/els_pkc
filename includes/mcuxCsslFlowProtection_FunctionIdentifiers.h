/*--------------------------------------------------------------------------*/
/* Copyright 2020-2022 NXP                                                  */
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
 * @file  mcuxCsslFlowProtection_FunctionIdentifiers.h
 * @brief Definition of function identifiers for the flow protection mechanism.
 *
 * @note This file might be post-processed to update the identifier values to
 * proper/secure values.
 */

#ifndef MCUX_CSSL_FLOW_PROTECTION_FUNCTION_IDENTIFIERS_H_
#define MCUX_CSSL_FLOW_PROTECTION_FUNCTION_IDENTIFIERS_H_

/* Flow Protection example values: */
#define MCUX_CSSL_FP_FUNCID_functionOnly0                     (0x7692u)
#define MCUX_CSSL_FP_FUNCID_functionOnly1                     (0x7AB0u)
#define MCUX_CSSL_FP_FUNCID_functionOnly2                     (0x7A1Au)
#define MCUX_CSSL_FP_FUNCID_functionCall                      (0x3CAAu)
#define MCUX_CSSL_FP_FUNCID_functionCalls                     (0x26F8u)
#define MCUX_CSSL_FP_FUNCID_functionLoop                      (0x471Bu)
#define MCUX_CSSL_FP_FUNCID_functionBranch                    (0x1F92u)
#define MCUX_CSSL_FP_FUNCID_functionSwitch                    (0x5C47u)
#define MCUX_CSSL_FP_FUNCID_functionComplex                   (0x678Cu)
#define MCUX_CSSL_FP_FUNCID_data_invariant_memory_compare     (0x678Du)
#define MCUX_CSSL_FP_FUNCID_data_invariant_memory_copy        (0x678Eu)

/* Values for production use: */
#define MCUX_CSSL_FP_FUNCID_mcuxCsslParamIntegrity_Validate                           (0x6533u)
#define MCUX_CSSL_FP_FUNCID_mcuxCsslMemory_Compare                                    (0x7A0Du)
#define MCUX_CSSL_FP_FUNCID_mcuxCsslMemory_Copy                                       (0x5AA6u)
#define MCUX_CSSL_FP_FUNCID_mcuxCsslMemory_Clear                                      (0x4E36u)
#define MCUX_CSSL_FP_FUNCID_mcuxCsslMemory_Set                                        (0x24F3u)
#define MCUX_CSSL_FP_FUNCID_unused_0x17C        (0x21DEu)
#define MCUX_CSSL_FP_FUNCID_unused_0x17D        (0x7478u)
#define MCUX_CSSL_FP_FUNCID_unused_0x17E        (0x65D2u)
#define MCUX_CSSL_FP_FUNCID_unused_0x17F        (0x09DDu)
#define MCUX_CSSL_FP_FUNCID_unused_0x180        (0x2C6Du)

#endif /* MCUX_CSSL_FLOW_PROTECTION_FUNCTION_IDENTIFIERS_H_ */
