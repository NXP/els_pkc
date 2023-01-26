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

/** @file  mcuxClMemory_Copy.h
 *  @brief Memory header for copy functions.
 * This header exposes functions that enable using memory copy function.
 */

/**
 * @defgroup mcuxClMemory_Copy mcuxClMemory_Copy
 * @brief This function copies a memory region from @p src to @p dst.
 * @ingroup mcuxClMemory
 * @{
 */

#ifndef MCUXCLMEMORY_COPY_H_
#define MCUXCLMEMORY_COPY_H_

#include <mcuxClConfig.h> // Exported features flags header

/**********************************************
 * FUNCTIONS
 **********************************************/

/**
 * Copies a memory buffer to another location.
 *
 * The two buffers must not overlap.
 * 
 * @param[out] pDst        pointer to the buffer to be copied to.
 * @param[in]  pSrc        pointer to the buffer to copy.
 * @param[in]  length      size (in bytes) to be copied.
 * @param[in]  bufLength   buffer size (if bufLength < length, only bufLength bytes are copied).
 *
 * @return A flow-protected value (see @ref mcuxCsslFlowProtection), indicating the number of bytes not copied (nonzero if the destination buffer is too small)
 */

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMemory_copy)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMemory_Status_t) mcuxClMemory_copy (uint8_t *pDst, uint8_t const *pSrc, size_t length, size_t bufLength);

#endif /* MCUXCLMEMORY_COPY_H_ */

/**
 * @}
 */
