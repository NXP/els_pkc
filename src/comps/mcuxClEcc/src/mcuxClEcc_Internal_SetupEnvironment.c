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

/**
 * @file  mcuxClEcc_Internal_SetupEnvironment.c
 * @brief mcuxClEcc: implementation of mcuxClEcc_SetupEnvironment
 */


#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClPkc.h>
#include <mcuxClMath.h>
#include <mcuxClMemory.h>

#include <mcuxClEcc.h>

#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClMemory_Copy_Internal.h>
#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_Internal_SetupEnvironment_FUP.h>


/**
 * \brief This function setups environment of ECC APIs.
 *
 * This function setups CPU and PKC workarea for ECC APIs. CPU workarea of ECC APIs
 * will be placed in the beginning of free CPU memory according to the session descriptor.
 * ECC API needs to store the address of beginning of free CPU memory before
 * calling this setup environment function.
 *
 * Inputs:
 *  - pSession: pointer to session descriptor;
 *  - pCommonDomainParams: pointer to ECC common domain parameter structure;
 *  - noOfBuffers: number of buffers in PKC workarea used by calling API.
 *
 * Results:
 *  - ECC CPU workarea is placed in the beginning of free CPU memory;
 *  - PKC is initialized, and the original PKC status is stored in CPU workarea;
 *  - pOperands[] (UPTR table) is created in CPU workarea and initialized;
 *  - PKC PS1 LEN and MCLEN are initialized;
 *  - prime p and curve order n, and the Montgomery parameter of them are
 *    imported to corresponding buffers in PKC workarea;
 *  - R^2 of p and n are imported to corresponding buffers;
 *  - shifted modulus of p and n are calculated and stored in corresponding buffers.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_SetupEnvironment)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_SetupEnvironment(mcuxClSession_Handle_t pSession,
                                                                        mcuxClEcc_CommonDomainParams_t *pCommonDomainParams,
                                                                        uint8_t noOfBuffers)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_SetupEnvironment);

    const uint32_t byteLenP = (uint32_t) pCommonDomainParams->byteLenP;
    const uint32_t byteLenN = (uint32_t) pCommonDomainParams->byteLenN;
    const uint32_t byteLenMax = ((byteLenP > byteLenN) ? byteLenP : byteLenN);
    const uint32_t operandSize = MCUXCLPKC_ROUNDUP_SIZE(byteLenMax);
    const uint32_t bufferSize = operandSize + MCUXCLPKC_WORDSIZE;

    /* Setup CPU workarea and PKC buffer. */
    const uint32_t byteLenOperandsTable = (sizeof(uint16_t)) * (ECC_NO_OF_VIRTUALS + (uint32_t) noOfBuffers);
    const uint32_t alignedByteLenCpuWa = (sizeof(mcuxClEcc_CpuWa_t)) + MCUXCLECC_ALIGNED_SIZE(byteLenOperandsTable);
    const uint32_t wordNumCpuWa = alignedByteLenCpuWa / (sizeof(uint32_t));
    mcuxClEcc_CpuWa_t *pCpuWorkarea = (mcuxClEcc_CpuWa_t *) mcuxClSession_allocateWords_cpuWa(pSession, wordNumCpuWa);
    const uint32_t wordNumPkcWa = (bufferSize * (uint32_t) noOfBuffers) / (sizeof(uint32_t));  /* PKC bufferSize is a multiple of CPU word size. */
    const uint8_t *pPkcWorkarea = (uint8_t *) mcuxClSession_allocateWords_pkcWa(pSession, wordNumPkcWa);
    if ((NULL == pCpuWorkarea) || (NULL == pPkcWorkarea))
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_SetupEnvironment, MCUXCLECC_STATUS_FAULT_ATTACK);
    }
    pCpuWorkarea->wordNumCpuWa = wordNumCpuWa;
    pCpuWorkarea->wordNumPkcWa = wordNumPkcWa;

    /* Backup PKC state and initialize PKC. */
    MCUXCLPKC_FP_INITIALIZE(&pCpuWorkarea->pkcStateBackup);

    /* Set PS1 MCLEN and LEN. */
    MCUXCLPKC_PS1_SETLENGTH(operandSize, operandSize);

    /* Setup UPTR table. */
    /* MISRA Ex. 9 - Rule 11.3 - Cast to 16-bit pointer table */
    uint16_t *pOperands = (uint16_t *) pCpuWorkarea->pOperands32;
    /* MISRA Ex. 22, while(0) is allowed */
    MCUXCLPKC_FP_GENERATEUPTRT(& pOperands[ECC_NO_OF_VIRTUALS],
                              pPkcWorkarea,
                              (uint16_t) bufferSize,
                              noOfBuffers);
    MCUXCLPKC_SETUPTRT(pOperands);

    /* Setup virtual offsets to prime p and curve order n. */
    pOperands[ECC_P] = pOperands[ECC_PFULL] + MCUXCLPKC_WORDSIZE;
    pOperands[ECC_N] = pOperands[ECC_NFULL] + MCUXCLPKC_WORDSIZE;

    /* Initialize constants ONE = 0x0001 and ZERO = 0x0000 in uptr table. */
    pOperands[ECC_ONE]  = 0x0001u;
    pOperands[ECC_ZERO] = 0x0000u;

    /* Clear buffers P, N, PQSQR and NQSQR. */
    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_SetupEnvironment_ClearBuffers,
                        mcuxClEcc_FUP_SetupEnvironment_ClearBuffers_LEN);
    MCUXCLPKC_WAITFORFINISH();

    /* Import prime p and order n, and corresponding Montgomery parameter (NDash). */
    MCUXCLMEMORY_FP_MEMORY_COPY(MCUXCLPKC_OFFSET2PTR(pOperands[ECC_PFULL]), pCommonDomainParams->pFullModulusP, MCUXCLPKC_WORDSIZE + byteLenP);
    MCUXCLMEMORY_FP_MEMORY_COPY(MCUXCLPKC_OFFSET2PTR(pOperands[ECC_NFULL]), pCommonDomainParams->pFullModulusN, MCUXCLPKC_WORDSIZE + byteLenN);

    /* Import R^2 mod p and R^2 mod n. */
    MCUXCLMEMORY_FP_MEMORY_COPY(MCUXCLPKC_OFFSET2PTR(pOperands[ECC_PQSQR]), pCommonDomainParams->pR2P, byteLenP);
    MCUXCLMEMORY_FP_MEMORY_COPY(MCUXCLPKC_OFFSET2PTR(pOperands[ECC_NQSQR]), pCommonDomainParams->pR2N, byteLenN);

    /* Calculate shifted modulus of p and n. */
    MCUXCLMATH_FP_SHIFTMODULUS(ECC_PS, ECC_P);
    MCUXCLMATH_FP_SHIFTMODULUS(ECC_NS, ECC_N);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_SetupEnvironment, MCUXCLECC_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_Initialize),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_GenerateUPTRT),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ShiftModulus),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_ShiftModulus) );
}
