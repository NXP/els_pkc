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

/** @file  mcuxClHash_internal_css_sha2.h
 *  @brief Internal definitions and declarations of the *INTERNAL* layer dedicated to CSS
 */

#ifndef MCUXCLHASH_INTERNAL_CSS_SHA2_H_
#define MCUXCLHASH_INTERNAL_CSS_SHA2_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

/**********************************************************
 * Type declarations
 **********************************************************/

#ifdef MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
/**
 * @brief DMA protection function type
 *
 * This function will verify if the DMA transfer of the last hardware accelerator operation finished on the expected address
 *
 */
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClHash_Status_t) (*mcuxClHash_AlgoDmaProtection_t)(uint8_t *startAddress,
                                                        size_t expectedLength);

#endif /* MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK */

/**********************************************************
 * Function declarations
 **********************************************************/


#endif /* MCUXCLHASH_INTERNAL_CSS_SHA2_H_ */
