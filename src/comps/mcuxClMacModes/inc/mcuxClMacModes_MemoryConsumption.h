/*--------------------------------------------------------------------------*/
/* Copyright 2020-2023 NXP                                                  */
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

/** @file  mcuxClMacModes_MemoryConsumption.h
 *  @brief Defines the memory consumption for the mcuxClMacModes component */

#ifndef MCUXCLMACMODES_MEMORYCONSUMPTION_H_
#define MCUXCLMACMODES_MEMORYCONSUMPTION_H_

/**
 * @defgroup mcuxClMacModes_MemoryConsumption mcuxClMacModes_MemoryConsumption
 * @brief Defines the memory consumption for the mcuxClMacModes component
 * @ingroup mcuxClMacModes
 * @{
 */

/* Workarea sizes */
#define MCUXCLMAC_MAX_CPU_WA_BUFFER_SIZE               (16u)
#define MCUXCLMAC_MAX_CPU_WA_BUFFER_SIZE_IN_WORDS      (MCUXCLMAC_MAX_CPU_WA_BUFFER_SIZE / sizeof(uint32_t))

#define MCUXCLMAC_COMPUTE_CPU_WA_BUFFER_SIZE           (16u)
#define MCUXCLMAC_COMPUTE_CPU_WA_BUFFER_SIZE_IN_WORDS  (MCUXCLMAC_COMPUTE_CPU_WA_BUFFER_SIZE / sizeof(uint32_t))
#define MCUXCLMAC_INIT_CPU_WA_BUFFER_SIZE              (sizeof(uint32_t))
#define MCUXCLMAC_INIT_CPU_WA_BUFFER_SIZE_IN_WORDS     (1u)
#define MCUXCLMAC_PROCESS_CPU_WA_BUFFER_SIZE           (sizeof(uint32_t))
#define MCUXCLMAC_PROCESS_CPU_WA_BUFFER_SIZE_IN_WORDS  (1u)
#define MCUXCLMAC_FINISH_CPU_WA_BUFFER_SIZE            (16u)
#define MCUXCLMAC_FINISH_CPU_WA_BUFFER_SIZE_IN_WORDS   (MCUXCLMAC_FINISH_CPU_WA_BUFFER_SIZE / sizeof(uint32_t))

/* Context sizes */
#define MCUXCLMAC_CONTEXT_SIZE                         (112u)
#define MCUXCLMAC_CONTEXT_SIZE_IN_WORDS                (MCUXCLMAC_CONTEXT_SIZE / sizeof(uint32_t))

/* Mode descriptor sizes */

/**
 * @}
 */ /* mcuxClMac_MemoryConsumption */

#endif /* MCUXCLMACMODES_MEMORYCONSUMPTION_H_ */
