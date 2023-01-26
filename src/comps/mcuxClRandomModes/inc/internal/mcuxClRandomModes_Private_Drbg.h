/*--------------------------------------------------------------------------*/
/* Copyright 2021-2022 NXP                                                  */
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

#ifndef MCUXCLRANDOMMODES_PRIVATE_DRBG_H_
#define MCUXCLRANDOMMODES_PRIVATE_DRBG_H_

#include <mcuxClConfig.h> // Exported features flags header

#include <mcuxClSession.h>
#include <mcuxClRandom_Types.h>


#ifdef __cplusplus
extern "C" {
#endif

#define MCUXCLRANDOMMODES_SELFTEST_RANDOMDATALENGTH (64u)

/*
 * Takes a byte size and returns a number of words
 */
#define MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(bytesize) \
    (((bytesize) + sizeof(uint32_t) - 1U ) / (sizeof(uint32_t)))

/**
 * @brief Defines to specify which mode a DRBG is operated in
 */
#define MCUXCLRANDOMMODES_NORMALMODE  (0xa5a5a5a5u)
#define MCUXCLRANDOMMODES_TESTMODE    (0x5a5a5a5au)
#define MCUXCLRANDOMMODES_ELSMODE     (0xd3d3d3d3u)
#define MCUXCLRANDOMMODES_PATCHMODE   (0x3d3d3d3du)

/* Shared generic internal structure of a random context used by DRBGs.
 * For DRG.3 and DRG.4 the reseedCounter is used to count the number of generate function calls.
 * For PTG.3 the reseedCounter is used to count the number of bytes drawn between reseeds */
#define MCUXCLRANDOMMODES_CONTEXT_DRBG_ENTRIES   \
        uint64_t reseedCounter;

typedef struct
{
    MCUXCLRANDOMMODES_CONTEXT_DRBG_ENTRIES
} mcuxClRandomModes_Context_Generic_t;

/* Signatures for internal functions */
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) (* mcuxClRandomModes_instantiateAlgorithm_t)(
        mcuxClSession_Handle_t pSession,
        uint32_t *pEntropyInput
);

typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) (* mcuxClRandomModes_reseedAlgorithm_t)(
        mcuxClSession_Handle_t pSession,
        uint32_t *pEntropyInput
);

typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) (* mcuxClRandomModes_generateAlgorithm_t)(
        mcuxClSession_Handle_t pSession,
        uint8_t *pOut,
        uint32_t outLength
);

typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) (* mcuxClRandomModes_selftestPrHandler_t)(
        mcuxClSession_Handle_t pSession,
        mcuxClRandom_Context_t testCtx,
        mcuxClRandom_Mode_t mode
);

typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) (* mcuxClRandomModes_generatePrHandler_t)(
        mcuxClSession_Handle_t pSession
);

typedef struct
{
    /* Function pointers for DRBG algorithms */
    mcuxClRandomModes_instantiateAlgorithm_t instantiateAlgorithm;  ///< DRBG instantiation algorithm depending on the chosen DRBG variant
    mcuxClRandomModes_reseedAlgorithm_t reseedAlgorithm;            ///< DRBG reseeding algorithm depending on the chosen DRBG variant
    mcuxClRandomModes_generateAlgorithm_t generateAlgorithm;        ///< DRBG random number generation algorithm depending on the chosen DRBG variant

    /* Protection tokens of DRBG algorithm function pointers */
    uint32_t protectionTokenInstantiateAlgorithm;             ///< Protection token of DRBG instantiate algorithm
    uint32_t protectionTokenReseedAlgorithm;                  ///< Protection token of DRBG reseed algorithm
    uint32_t protectionTokenGenerateAlgorithm;                ///< Protection token of DRBG generate algorithm
} mcuxClRandomModes_DrbgAlgorithmsDescriptor_t;

typedef struct
{
    uint64_t reseedInterval;           ///< reseed interval of chosen DRBG variant
    uint16_t seedLen;                  ///< seedLen parameter defined in NIST SP 800-90A
    uint16_t initSeedSize;             ///< Size of entropy input used for instantiating the DRBG
    uint16_t reseedSeedSize;           ///< Size of entropy input used for reseeding the DRBG
} mcuxClRandomModes_DrbgVariantDescriptor_t;

typedef struct
{
    const mcuxClRandomModes_DrbgAlgorithmsDescriptor_t *pDrbgAlgorithms;
    const mcuxClRandomModes_DrbgVariantDescriptor_t *pDrbgVariant;
    const uint32_t * const *pDrbgTestVectors;
} mcuxClRandomModes_DrbgModeDescriptor_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLRANDOMMODES_PRIVATE_DRBG_H_ */
