/*--------------------------------------------------------------------------*/
/* Copyright 2021 - 2022 NXP                                                */
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

#ifndef MCUXCLAEADMODES_MEMORYCONSUMPTION_H_
#define MCUXCLAEADMODES_MEMORYCONSUMPTION_H_
/**
 * @defgroup mcuxClAead_MemoryConsumption mcuxClAead_MemoryConsumption
 * @brief Defines the memory consumption for the mcuxClAead component
 * @ingroup mcuxClAead
 * @{
 */


#define MCUXCLAEAD_CRYPT_CPU_WA_BUFFER_SIZE          (124u)
#define MCUXCLAEAD_CRYPT_CPU_WA_BUFFER_SIZE_IN_WORDS (MCUXCLAEAD_CRYPT_CPU_WA_BUFFER_SIZE / 4u)

#define MCUXCLAEAD_INIT_CPU_WA_BUFFER_SIZE     (1u)
#define MCUXCLAEAD_INIT_CPU_WA_BUFFER_SIZE_IN_WORDS     (MCUXCLAEAD_INIT_CPU_WA_BUFFER_SIZE / 4u )




#define MCUXCLAEAD_PROCESS_CPU_WA_BUFFER_SIZE          (1u)
#define MCUXCLAEAD_PROCESS_CPU_WA_BUFFER_SIZE_IN_WORDS          (MCUXCLAEAD_PROCESS_CPU_WA_BUFFER_SIZE / 4u )
#define MCUXCLAEAD_PROCESS_ADATA_CPU_WA_BUFFER_SIZE    (1u)
#define MCUXCLAEAD_PROCESS_ADATA_CPU_WA_BUFFER_SIZE_IN_WORDS    (MCUXCLAEAD_PROCESS_ADATA_CPU_WA_BUFFER_SIZE / 4u )
#define MCUXCLAEAD_FINISH_CPU_WA_BUFFER_SIZE           (1u)
#define MCUXCLAEAD_FINISH_CPU_WA_BUFFER_SIZE_IN_WORDS           (MCUXCLAEAD_FINISH_CPU_WA_BUFFER_SIZE / 4u )
#define MCUXCLAEAD_VERIFY_CPU_WA_BUFFER_SIZE           (1u)
#define MCUXCLAEAD_VERIFY_CPU_WA_BUFFER_SIZE_IN_WORDS           (MCUXCLAEAD_VERIFY_CPU_WA_BUFFER_SIZE / 4u )
#define MCUXCLAEAD_MAX_CPU_WA_BUFFER_SIZE              (124u)
#define MCUXCLAEAD_MAX_CPU_WA_BUFFER_SIZE_IN_WORDS              (MCUXCLAEAD_MAX_CPU_WA_BUFFER_SIZE / 4u )

#define MCUXCLAEAD_CONTEXT_SIZE (124u)


/** @def MCUXCLAEAD_WA_SIZE_MAX
 *  @brief Define the max workarea size in bytes required for this component
 */
#define MCUXCLAEAD_WA_SIZE_MAX (124u)
#define MCUXCLAEAD_WA_SIZE_IN_WORDS_MAX     (MCUXCLAEAD_WA_SIZE_MAX / 4u )

/**
 * @}
 */ /* mcuxClAead_MemoryConsumption */

#endif /* MCUXCLAEADMODES_MEMORYCONSUMPTION_H_ */
