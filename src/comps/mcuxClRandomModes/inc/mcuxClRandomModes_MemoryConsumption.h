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
 * @file  mcuxClRandomModes_MemoryConsumption.h
 * @brief Defines the memory consumption for the mcuxClRandom component
 */
 
#ifndef MCUXCLRANDOMMODES_MEMORYCONSUMPTION_H_
#define MCUXCLRANDOMMODES_MEMORYCONSUMPTION_H_

/**
 * @defgroup mcuxClRandomModes_MemoryConsumption mcuxClRandomModes_MemoryConsumption
 * @brief Defines the memory consumption for the @ref mcuxClRandom component
 * @ingroup mcuxClRandom
 * @{
 */

#define MCUXCLRANDOM_MAX_CPU_WA_BUFFER_SIZE 		                (72u)

#define MCUXCLRANDOM_INIT_WACPU_SIZE                         	MCUXCLRANDOM_MAX_CPU_WA_BUFFER_SIZE     
#define MCUXCLRANDOM_RESEED_WACPU_SIZE                           MCUXCLRANDOM_MAX_CPU_WA_BUFFER_SIZE 
#define MCUXCLRANDOM_GENERATE_WACPU_SIZE                         MCUXCLRANDOM_MAX_CPU_WA_BUFFER_SIZE
#define MCUXCLRANDOM_SELFTEST_WACPU_SIZE                         MCUXCLRANDOM_MAX_CPU_WA_BUFFER_SIZE
#define MCUXCLRANDOM_UNINIT_WACPU_SIZE                           (0u)
#define MCUXCLRANDOM_CHECKSECURITYSTRENGTH_WACPU_SIZE            (0u)
#define MCUXCLRANDOM_NCINIT_WACPU_SIZE                           (0u)
#define MCUXCLRANDOM_NCGENERATE_WACPU_SIZE                       (0u)
#define MCUXCLRANDOM_CREATEPATCHMODE_WACPU_SIZE                  (0u)
#define MCUXCLRANDOM_CREATETESTMODEFROMNORMALMODE_WACPU_SIZE 	(0u)

#ifdef MCUXCL_FEATURE_RANDOM_CTRDRBG 
#define MCUXCLRANDOM_CTR_DRBG_AES128_CONTEXT_SIZE (40u)
#define MCUXCLRANDOM_CTR_DRBG_AES192_CONTEXT_SIZE (48u)
#define MCUXCLRANDOM_CTR_DRBG_AES256_CONTEXT_SIZE (56u)
#endif /* MCUXCL_FEATURE_RANDOM_CTRDRBG */

#define MCUXCLRANDOM_TESTMODE_CTR_DRBG_AES128_INIT_ENTROPY_SIZE     (32u)
#define MCUXCLRANDOM_TESTMODE_CTR_DRBG_AES192_INIT_ENTROPY_SIZE     (40u)
#define MCUXCLRANDOM_TESTMODE_CTR_DRBG_AES256_INIT_ENTROPY_SIZE     (48u)
#define MCUXCLRANDOM_TESTMODE_CTR_DRBG_AES128_RESEED_ENTROPY_SIZE   (32u)
#define MCUXCLRANDOM_TESTMODE_CTR_DRBG_AES192_RESEED_ENTROPY_SIZE   (40u)
#define MCUXCLRANDOM_TESTMODE_CTR_DRBG_AES256_RESEED_ENTROPY_SIZE   (48u)

/**
 * @}
 */ /* mcuxClRandomModes_MemoryConsumption */
 
#endif /* MCUXCLRANDOMMODES_MEMORYCONSUMPTION_H_ */
