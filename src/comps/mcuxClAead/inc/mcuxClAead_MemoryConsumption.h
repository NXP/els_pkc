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

/** @file  mcuxClAead_MemoryConsumption.h
 *  @brief Defines the memory consumption for the mcuxClAead component */

#ifndef MCUXCLAEAD_MEMORY_CONSUMPTIOM_H
#define MCUXCLAEAD_MEMORY_CONSUMPTIOM_H
/**
 * @defgroup mcuxClAead_MemoryConsumption mcuxClAead_MemoryConsumption
 * @brief Defines the memory consumption for the mcuxClAead component
 * @ingroup mcuxClAead
 * @{
 */

/** @def MCUXCLAEAD_WA_SIZEW_MAX
 *  @brief Define the max workarea size in words required for this component
 */
#define MCUXCLAEAD_WA_SIZEW_MAX (1u)

/** @def MCUXCLAEAD_WA_SIZE_MAX
 *  @brief Define the max workarea size in bytes required for this component
 */
#define MCUXCLAEAD_WA_SIZE_MAX (MCUXCLAEAD_WA_SIZEW_MAX * sizeof(uint32_t))

/** @def MCUXCLAEAD_WA_SIZEW_CCM_ENC
 *  @brief Define the workarea size in words required for CCM ENC mode
 */
#define MCUXCLAEAD_WA_SIZEW_CCM_ENC (1u)

/** @def MCUXCLAEAD_WA_SIZE_CCM_ENC
 *  @brief Define the workarea size in bytes required for CCM ENC mode
 */
#define MCUXCLAEAD_WA_SIZE_CCM_ENC (MCUXCLAEAD_WA_SIZEW_CCM_ENC * sizeof(uint32_t))

/** @def MCUXCLAEAD_WA_SIZEW_CCM_DEC
 *  @brief Define the workarea size in words required for CCM DEC mode
 */
#define MCUXCLAEAD_WA_SIZEW_CCM_DEC (1u)

/** @def MCUXCLAEAD_WA_SIZE_CCM_DEC
 *  @brief Define the workarea size in bytes required for CCM DEC mode
 */
#define MCUXCLAEAD_WA_SIZE_CCM_DEC (MCUXCLAEAD_WA_SIZEW_CCM_DEC * sizeof(uint32_t))

/** @def MCUXCLAEAD_WA_SIZEW_GCM_ENC
 *  @brief Define the workarea size in words required for GCM ENC mode
 */
#define MCUXCLAEAD_WA_SIZEW_GCM_ENC (1u)

/** @def MCUXCLAEAD_WA_SIZE_GCM_ENC
 *  @brief Define the workarea size in bytes required for GCM ENC mode
 */
#define MCUXCLAEAD_WA_SIZE_GCM_ENC (MCUXCLAEAD_WA_SIZEW_GCM_ENC * sizeof(uint32_t))

/** @def MCUXCLAEAD_WA_SIZEW_GCM_DEC
 *  @brief Define the workarea size in words required for GCM DEC mode
 */
#define MCUXCLAEAD_WA_SIZEW_GCM_DEC (1u)

/** @def MCUXCLAEAD_WA_SIZE_GCM_DEC
 *  @brief Define the workarea size in bytes required for GCM DEC mode
 */
#define MCUXCLAEAD_WA_SIZE_GCM_DEC (MCUXCLAEAD_WA_SIZEW_GCM_DEC * sizeof(uint32_t))

/**
 * @}
 */ /* mcuxClAead_MemoryConsumption */
 
#endif /* MCUXCLAEAD_MEMORY_CONSUMPTIOM_H */
