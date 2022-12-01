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

/** @file  mcuxClMemory_Copy_Internal.h
 *  @brief Internal memory header for copy functions.
 * This header exposes functions that enable using memory copy function.
 */

#ifndef MCUXCLMEMORY_COPY_INTERNAL_H_
#define MCUXCLMEMORY_COPY_INTERNAL_H_

#include <mcuxClConfig.h> // Exported features flags header

/**
 * @ingroup mcuxClMemory_Copy
 * @{
 */


/**********************************************
 * MACROS
 **********************************************/

/** Helper macro to call #mcuxClMemory_copy with flow protection. */
#define MCUXCLMEMORY_FP_MEMORY_COPY(pTarget, pSource, byteLen)  \
    do {  \
        MCUX_CSSL_FP_FUNCTION_CALL(retCodeTemp,  \
            mcuxClMemory_copy((uint8_t *) (pTarget), (const uint8_t *) (pSource), byteLen, byteLen)); \
        (void) retCodeTemp;  \
    } while(false)


/**
 * @}
 */

#endif /* MCUXCLMEMORY_COPY_INTERNAL_H_ */
