/*--------------------------------------------------------------------------*/
/* Copyright 2020-2021 NXP                                                  */
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

/** @file  mcuxClMemory_Clear.h
 *  @brief Memory header for clear functions.
 * This header exposes functions that enable using memory clear function.
 */


/**
 * @defgroup mcuxClMemory_Clear mcuxClMemory_Clear
 * @brief This function clears a memory region.
 * @ingroup mcuxClMemory
 * @{
 */


#ifndef MCUXCLMEMORY_CLEAR_H_
#define MCUXCLMEMORY_CLEAR_H_

#include <mcuxClConfig.h> // Exported features flags header

#include <mcuxClMemory_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************
 * FUNCTIONS
 **********************************************/

/**
 * Overwrites a memory buffer with null bytes.
 * 
 * @param[out]  pDst        Pointer to the buffer to be cleared.
 * @param[in]   length      size (in bytes) to be cleared.
 * @param[in]   bufLength   buffer size (if bufLength < len, only bufLength bytes are cleared).
 *
 * @return A flow-protected value (see @ref mcuxCsslFlowProtection), indicating the number of bytes not cleared (nonzero if the destination buffer is too small)
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMemory_clear)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMemory_Status_t) mcuxClMemory_clear (uint8_t *pDst, size_t length, size_t bufLength);


/**
 * @}
 */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLMEMORY_CLEAR_H_ */

/**
 * @}
 */
