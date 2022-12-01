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
 *
 * @file:	size.c
 * @brief:	This file contains objects which will be used to measure size of particular types.
 *
 */
#include <mcuxClCore_Platform.h>
#include <mcuxClKey_Constants.h>
#include <mcuxClAes.h>

#ifdef MCUXCL_FEATURE_RANDOM_CTRDRBG
#include <internal/mcuxClRandom_Private_CtrDrbg.h>
#endif /* MCUXCL_FEATURE_RANDOM_CTRDRBG */

/* *********************** */
/* *** Work area sizes *** */
/* *********************** */

#ifdef MCUXCL_FEATURE_RANDOM_CTRDRBG
extern volatile mcuxClRandom_Context_CtrDrbg_Aes128_t mcuxClRandom_Context_Aes128;
volatile mcuxClRandom_Context_CtrDrbg_Aes128_t mcuxClRandom_Context_Aes128;

extern volatile mcuxClRandom_Context_CtrDrbg_Aes192_t mcuxClRandom_Context_Aes192;
volatile mcuxClRandom_Context_CtrDrbg_Aes192_t mcuxClRandom_Context_Aes192;

extern volatile mcuxClRandom_Context_CtrDrbg_Aes256_t mcuxClRandom_Context_Aes256;
volatile mcuxClRandom_Context_CtrDrbg_Aes256_t mcuxClRandom_Context_Aes256;
#endif /* MCUXCL_FEATURE_RANDOM_CTRDRBG */

#if defined(MCUXCL_FEATURE_RANDOM_DERIVATION_FUNCTION)
// (initSeedSize for instantiate) + (blockLen+(4+4+initSeedSize(64 for 256bit)+1+7(padding))+keyLen+2*blockLen for df function) + (initSeedSize) of 256bit security strength
uint8_t mcuxClRandom_CpuWA_MaxSize[(MCUXCLRANDOM_MODE_ENTROPYINPUT_SIZE_INIT_CTR_DRBG_AES256 + (4u + 4u + MCUXCLRANDOM_MODE_ENTROPYINPUT_SIZE_INIT_CTR_DRBG_AES256 + 1u + 7u) + MCUX_CL_KEY_SIZE_256 + 3u * MCUX_CL_AES_BLOCK_SIZE + MCUXCLRANDOM_MODE_ENTROPYINPUT_SIZE_INIT_CTR_DRBG_AES256 + sizeof(uint32_t) - 1u)/sizeof(uint32_t)];
#endif
