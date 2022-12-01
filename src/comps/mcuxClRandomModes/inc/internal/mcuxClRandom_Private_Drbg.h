/*--------------------------------------------------------------------------*/
/* Copyright 2021 NXP                                                       */
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
/* Security Classification:  Company Confidential                           */
/*--------------------------------------------------------------------------*/

#ifndef MCUXCLRANDOM_PRIVATE_DRBG_H_
#define MCUXCLRANDOM_PRIVATE_DRBG_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>

#include <mcuxClSession_Types.h>
#include <mcuxClRandom_Types.h>


#ifdef __cplusplus
extern "C" {
#endif


#define MCUXCLRANDOM_SELFTEST_RANDOMDATALENGTH (64u)

#define MCUXCLRANDOM_ROUND_UP_TO_CPU_WORDSIZE(size) \
    (((size) + sizeof(uint32_t) - 1U ) / (sizeof(uint32_t)))

/**
 * @brief Defines to specify which mode a DRBG is operated in
 */
#define MCUXCLRANDOM_NORMALMODE  (0xa5a5a5a5u)
#define MCUXCLRANDOM_TESTMODE    (0x5a5a5a5au)
#define MCUXCLRANDOM_CSSMODE     (0xd3d3d3d3u)
#define MCUXCLRANDOM_PATCHMODE   (0x3d3d3d3du)

/* Signatures for internal functions */
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) (* mcuxClRandom_instantiateAlgorithm_t)(
        mcuxClSession_Handle_t pSession,
        uint32_t *pEntropyInput
);

typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) (* mcuxClRandom_reseedAlgorithm_t)(
        mcuxClSession_Handle_t pSession,
        uint32_t *pEntropyInput
);

typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) (* mcuxClRandom_generateAlgorithm_t)(
        mcuxClSession_Handle_t pSession,
        uint8_t *pOut,
        uint32_t outLength
);

typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) (* mcuxClRandom_selftestPrHandler_t)(
        mcuxClSession_Handle_t pSession,
        mcuxClRandom_Context_t testCtx,
        mcuxClRandom_Mode_t mode
);

typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) (* mcuxClRandom_generatePrHandler_t)(
        mcuxClSession_Handle_t pSession
);

typedef struct
{
    /* Function pointers for DRBG algorithms */
    mcuxClRandom_instantiateAlgorithm_t instantiateAlgorithm;  ///< DRBG instantiation algorithm depending on the chosen DRBG variant
    mcuxClRandom_reseedAlgorithm_t reseedAlgorithm;            ///< DRBG reseeding algorithm depending on the chosen DRBG variant
    mcuxClRandom_generateAlgorithm_t generateAlgorithm;        ///< DRBG random number generation algorithm depending on the chosen DRBG variant

    /* Protection tokens of DRBG algorithm function pointers */
    uint32_t protectionTokenInstantiateAlgorithm;             ///< Protection token of DRBG instantiate algorithm
    uint32_t protectionTokenReseedAlgorithm;                  ///< Protection token of DRBG reseed algorithm
    uint32_t protectionTokenGenerateAlgorithm;                ///< Protection token of DRBG generate algorithm
} mcuxClRandom_DrbgAlgorithmsDescriptor_t;


typedef struct
{
    uint64_t reseedInterval;           ///< reseed interval of chosen DRBG variant
    uint16_t seedLen;                  ///< seedLen parameter defined in NIST SP 800-90A
    uint16_t initSeedSize;             ///< Size of entropy input used for instantiating the DRBG
    uint16_t reseedSeedSize;           ///< Size of entropy input used for reseeding the DRBG
} mcuxClRandom_DrbgVariantDescriptor_t;



typedef struct
{
    /* DRBG prediction resistance handlers */
    mcuxClRandom_generatePrHandler_t generatePrHandler;     ///< DRBG function handling reseeding done inside the generatFunction depending on the chosen PR variant
    mcuxClRandom_selftestPrHandler_t selftestPrHandler;     ///< DRBG function handling the CAVP self testing flow depending on the chosen PR variant

    /* Protection tokens of DRBG prediction resistance handlers */
    uint32_t protectionTokenGeneratePrHandler;             ///< Protection token of DRBG generate prediction resistance handler
    uint32_t protectionTokenSelftestPrHandler;             ///< Protection token of DRBG selftest prediction resistance handler
} mcuxClRandom_DrbgPrModeDescriptor_t;


typedef struct
{
    mcuxClRandom_DrbgAlgorithmsDescriptor_t *pDrbgAlgorithms;
    mcuxClRandom_DrbgVariantDescriptor_t *pDrbgVariant;
    mcuxClRandom_DrbgPrModeDescriptor_t *pDrbgPrMode;
    const uint32_t * const *pDrbgTestVectors;
} mcuxClRandom_DrbgModeDescriptor_t;


/* Shared generic internal structure of a random context used by DRBGs */
#define MCUXCLRANDOM_CONTEXT_DRBG_ENTRIES \
    uint64_t reseedCounter;

typedef struct
{
    MCUXCLRANDOM_CONTEXT_DRBG_ENTRIES
} mcuxClRandom_Context_Generic_t;


#endif /* MCUXCLRANDOM_PRIVATE_DRBG_H_ */
