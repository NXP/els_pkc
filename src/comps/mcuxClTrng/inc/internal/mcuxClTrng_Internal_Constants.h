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
 * @file  mcuxClTrng_Internal_Constants.h
 * @brief Constant definitions of mcuxClTrng component
 */


#ifndef MCUX_CL_TRNG_INTERNAL_CONSTANTS_H_
#define MCUX_CL_TRNG_INTERNAL_CONSTANTS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <stdint.h>
#include <internal/mcuxClTrng_Internal_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************************/
/* Constants of mcuxClTrng                                 */
/**********************************************************/
/**
 * @defgroup mcuxClTrng_Internal_Constants mcuxClTrng_Internal_Constants
 * @brief Defines all contstants of @ref mcuxClTrng
 * @ingroup mcuxClTrng
 * @{
 */

/** @addtogroup MCUXCLTRNG_STATUS_
 * mcuxClTrng return code definitions
 * @{ */
#define MCUXCLTRNG_STATUS_ERROR                  ((mcuxClTrng_Status_t) 0xC3ABB12Du)  ///< An error occurred during the TRNG operation
#define MCUXCLTRNG_STATUS_OK                     ((mcuxClTrng_Status_t) 0xAAA5D39Eu)  ///< TRNG operation returned successfully
#define MCUXCLTRNG_STATUS_FAULT_ATTACK           ((mcuxClTrng_Status_t) 0xAAA5F0F0u)  ///< A fault attack is detected
/** @} */

#ifdef MCUXCL_FEATURE_TRNG_CSS
/**
 * @brief Defines all macros of @ref mcuxClTrng_CSS
 * @ingroup mcuxClTrng_CSS
 * @{
 */
#define MCUXCLTRNG_CSS_TRNG_OUTPUT_SIZE  (32u / sizeof(uint32_t))                    ///< output word size of #mcuxClCss_Rng_DrbgRequestRaw_Async
#endif

/**
 * @}
 */ /* mcuxClTrng_Constants */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUX_CL_TRNG_INTERNAL_CONSTANTS_H_ */
