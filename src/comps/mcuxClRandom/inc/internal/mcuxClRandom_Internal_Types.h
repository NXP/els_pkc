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
 * @file  mcuxClRandom_Internal_Types.h
 * @brief Internal type definitions of mcuxClRandom component
 */

#ifndef MCUXCLRANDOM_INTERNAL_TYPES_H_
#define MCUXCLRANDOM_INTERNAL_TYPES_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClRandom_Types.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Random config structure
 *
 * This structure is used to store context and mode pointers.
 */
struct mcuxClRandom_Config {
    mcuxClRandom_Mode_t    mode;      ///< Random data generation mode/algorithm
    mcuxClRandom_Context_t ctx;       ///< Context for the Rng
};

/**
 * @brief Random config type
 *
 * This type is used to store context and mode.
 */
typedef struct mcuxClRandom_Config mcuxClRandom_Config_t;

#endif /* MCUXCLRANDOM_INTERNAL_TYPES_H_ */
