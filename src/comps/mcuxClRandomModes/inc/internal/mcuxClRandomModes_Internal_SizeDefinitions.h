/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023 NXP                                                  */
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
 * @file:   mcuxClRandomModes_Internal_SizeDefinitions.h
 * @brief:  This file contains size definitions to share them with other components
 *
 */

#define MCUXCLRANDOMMODES_MAX( x, y ) ( ( x ) > ( y ) ? ( x ) : ( y ) )

#include <mcuxClConfig.h> // Exported features flags header
#if defined(MCUXCL_FEATURE_RANDOMMODES_DERIVATION_FUNCTION)
#include <mcuxClAes.h>
#endif
#include <stdint.h>
#include <stdbool.h>
#ifdef MCUXCL_FEATURE_RANDOMMODES_CTRDRBG
#include <internal/mcuxClRandomModes_Private_CtrDrbg.h>
#include <mcuxClRandom_Types.h>
#include <internal/mcuxClRandomModes_Private_Drbg.h>
#endif /* MCUXCL_FEATURE_RANDOMMODES_CTRDRBG */

/* Helper Macros */
#define MCUXCLRANDOMMODES_CTRDRBG_AES256_SEED_MATERIAL  (MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(MCUXCLRANDOMMODES_MAX(MCUXCLRANDOMMODES_ENTROPYINPUT_SIZE_INIT_CTR_DRBG_AES256, MCUXCLRANDOMMODES_SEEDLEN_CTR_DRBG_AES256)) * sizeof(uint32_t))

#if defined(MCUXCL_FEATURE_RANDOMMODES_DERIVATION_FUNCTION)
/*
 * Description of how much cpu wa mcuxClRandomModes_CtrDrbg_bcc uses
 */
#define MCUXCLRANDOMMODES_CTRDRBG_BCC_CPUWA_SIZE     MCUXCLAES_BLOCK_SIZE

/*
 * Description of how much cpu wa mcuxClRandomModes_CtrDrbg_df uses at most, i.e. for the AES-256 CTR_DRBG case
 *
 * cpuWa          | IV | L | N | Seed | 0x80 | Padding over (L,N,Seed,0x80) | K            | X  | additionBlock  |
 * size in byte   | 16 | 4 | 4 | 64   | 1    |         0-7 => max=7         | 256 \ 8 = 32 | 16 |       16       |
 *
 */
#define MCUXCLRANDOMMODES_CTRDRBG_AES256_DF_IV                MCUXCLAES_BLOCK_SIZE
#define MCUXCLRANDOMMODES_CTRDRBG_AES256_DF_L                 (4)
#define MCUXCLRANDOMMODES_CTRDRBG_AES256_DF_N                 (4)
#define MCUXCLRANDOMMODES_CTRDRBG_AES256_DF_SEED              MCUXCLRANDOMMODES_ENTROPYINPUT_SIZE_INIT_CTR_DRBG_AES256
#define MCUXCLRANDOMMODES_CTRDRBG_AES256_DF_0X80              (1)
#define MCUXCLRANDOMMODES_CTRDRBG_AES256_DF_MAXPADDING        (7)
#define MCUXCLRANDOMMODES_CTRDRBG_AES256_DF_K_MAXSIZE         MCUXCLAES_AES256_KEY_SIZE
#define MCUXCLRANDOMMODES_CTRDRBG_AES256_DF_X                 MCUXCLAES_BLOCK_SIZE

#define MCUXCLRANDOMMODES_CTRDRBG_DERIVATIONFUNCTION_CPUWA_MAXSIZE     (\
                                                                        MCUXCLRANDOMMODES_CTRDRBG_AES256_DF_IV + \
                                                                        MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE( \
                                                                        MCUXCLRANDOMMODES_CTRDRBG_AES256_DF_L + \
                                                                        MCUXCLRANDOMMODES_CTRDRBG_AES256_DF_N + \
                                                                        MCUXCLRANDOMMODES_CTRDRBG_AES256_DF_SEED + \
                                                                        MCUXCLRANDOMMODES_CTRDRBG_AES256_DF_0X80 + \
                                                                        MCUXCLRANDOMMODES_CTRDRBG_AES256_DF_MAXPADDING) * sizeof(uint32_t) + \
                                                                        MCUXCLRANDOMMODES_CTRDRBG_AES256_DF_K_MAXSIZE + \
                                                                        MCUXCLRANDOMMODES_CTRDRBG_AES256_DF_X + \
                                                                        MCUXCLRANDOMMODES_CTRDRBG_BCC_CPUWA_SIZE \
                                                                      )
#endif

/*
 * Description of how much cpu wa mcuxClRandomModes_CtrDrbg_UpdateState uses at most, i.e. for the AES-256 CTR_DRBG case
 *
 * cpuWa          | Seed                                             |
 * size in byte   | entropy_input size for AES-256 for the init case |
 *
 */
#define MCUXCLRANDOMMODES_CTRDRBG_UPDATESTATE_CPUWA_MAXSIZE     (MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(MCUXCLRANDOMMODES_SEEDLEN_CTR_DRBG_AES256) * sizeof(uint32_t))

#if defined(MCUXCL_FEATURE_RANDOMMODES_DERIVATION_FUNCTION)
/*
 * Description of how much cpu wa mcuxClRandomModes_CtrDrbg_instantiateAlgorithm uses at most
 *
 * cpuWa          | Seed                                   | cpuWa used by called functions |
 * size in byte   | entropy_input size for the init case   | Max(cpuWaDF, cpuWaUpdateState) |
 *
 */
#define MCUXCLRANDOMMODES_CTRDRBG_INSTANTIATEALGO_CPUWA_MAXSIZE (       \
        MCUXCLRANDOMMODES_CTRDRBG_AES256_SEED_MATERIAL + \
        MCUXCLRANDOMMODES_MAX( \
            MCUXCLRANDOMMODES_CTRDRBG_DERIVATIONFUNCTION_CPUWA_MAXSIZE, \
            MCUXCLRANDOMMODES_CTRDRBG_UPDATESTATE_CPUWA_MAXSIZE         \
        ) \
    )
#endif


/*
 * Description of how much cpu wa mcuxClRandomModes_NormalMode_initFunction uses at most
 *
 * cpuWa          | Seed                                   | Call to instantiateAlgo |
 * size in byte   | entropy_input size for the init case   |  cpuWaInstantiateAlgo   |
 *
 */
#if defined(MCUXCL_FEATURE_RANDOMMODES_CTRDRBG)
#define MCUXCLRANDOMMODES_NORMALMODE_INIT_CPUWA_MAXSIZE ( \
            MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(MCUXCLRANDOMMODES_ENTROPYINPUT_SIZE_INIT_CTR_DRBG_AES256) * sizeof(uint32_t) +\
            MCUXCLRANDOMMODES_CTRDRBG_INSTANTIATEALGO_CPUWA_MAXSIZE \
        )
#else
#define MCUXCLRANDOMMODES_NORMALMODE_INIT_CPUWA_MAXSIZE 4u
#endif

/*
 * Description of how much cpu wa mcuxClRandomModes_NormalMode_selftestFunction_PrDisabled uses at most
 */
#if defined(MCUXCL_FEATURE_RANDOMMODES_CTRDRBG)
#define MCUXCLRANDOMMODES_NORMALMODE_SELFTEST_CPUWA_MAXSIZE ( \
            sizeof(mcuxClRandom_ModeDescriptor_t) +\
            sizeof(mcuxClRandomModes_Context_CtrDrbg_Aes256_t) \
        )
#else
#define MCUXCLRANDOMMODES_NORMALMODE_SELFTEST_CPUWA_MAXSIZE 4u
#endif

/*
 * Maximum cpuWa size for API functions
 */

#define MCUXCLRANDOMMODES_INIT_WACPU_SIZE_MAX     (MCUXCLRANDOMMODES_NORMALMODE_INIT_CPUWA_MAXSIZE)
#define MCUXCLRANDOMMODES_RESEED_WACPU_SIZE_MAX   (0u)
#define MCUXCLRANDOMMODES_GENERATE_WACPU_SIZE_MAX (0u)
#define MCUXCLRANDOMMODES_SELFTEST_WACPU_SIZE_MAX (MCUXCLRANDOMMODES_NORMALMODE_SELFTEST_CPUWA_MAXSIZE)

/*
 * Maximum cpuWa size over all API functions
 *
*/
#define MCUXCLRANDOMMODES_CPUWA_MAXSIZE ( \
        MCUXCLRANDOMMODES_MAX(MCUXCLRANDOMMODES_INIT_WACPU_SIZE_MAX, \
                              MCUXCLRANDOMMODES_MAX(MCUXCLRANDOMMODES_RESEED_WACPU_SIZE_MAX, \
                                                    MCUXCLRANDOMMODES_MAX(MCUXCLRANDOMMODES_GENERATE_WACPU_SIZE_MAX, \
                                                                          MCUXCLRANDOMMODES_SELFTEST_WACPU_SIZE_MAX \
                                                                          )\
                                                    )\
                              ) \
        )

