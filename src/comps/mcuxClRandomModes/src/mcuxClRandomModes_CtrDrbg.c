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
/* Security Classification:  Company Confidential                           */
/*--------------------------------------------------------------------------*/

#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxClSession.h>
#include <mcuxClMemory.h>
#include <mcuxClAes.h>

#include <internal/mcuxClRandomModes_Private_CtrDrbg.h>
#include <internal/mcuxClRandomModes_Private_NormalMode.h>
#include <internal/mcuxClRandomModes_Private_Drbg.h>
#include <internal/mcuxClRandomModes_Private_CtrDrbg_BlockCipher.h>
#include <internal/mcuxClMemory_Copy_Internal.h>
#include <internal/mcuxClSession_Internal.h>

const mcuxClRandomModes_DrbgAlgorithmsDescriptor_t mcuxClRandomModes_DrbgAlgorithmsDescriptor_CtrDrbg =
{
    .instantiateAlgorithm = mcuxClRandomModes_CtrDrbg_instantiateAlgorithm,
    .reseedAlgorithm = mcuxClRandomModes_CtrDrbg_reseedAlgorithm,
    .generateAlgorithm = mcuxClRandomModes_CtrDrbg_generateAlgorithm,
    .protectionTokenInstantiateAlgorithm = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_CtrDrbg_instantiateAlgorithm,
    .protectionTokenReseedAlgorithm = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_CtrDrbg_reseedAlgorithm,
    .protectionTokenGenerateAlgorithm = MCUX_CSSL_FP_FUNCID_mcuxClRandomModes_CtrDrbg_generateAlgorithm,
};

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandomModes_CtrDrbg_incV)
static MCUX_CSSL_FP_PROTECTED_TYPE(uint32_t) mcuxClRandomModes_CtrDrbg_incV(uint8_t *pV)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_incV);
    uint32_t beforeIncrement = *(uint32_t *)pV;
    /* MISRA Ex. 9 to Rule 11.3 - reinterpret memory */
    *(uint64_t *)pV += 1u;

    if(0u == *(uint64_t *)pV)
    {
        *(uint64_t *)&pV[8] += 1u;
    }
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_incV, beforeIncrement);
}


#define MCUXCLRANDOM_MAX_DF_BITS        512u

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_bcc)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandomModes_CtrDrbg_bcc(uint8_t const *pKey, uint32_t keyLength,
        uint32_t * const pData, uint32_t dataLen, uint32_t *pOut)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_bcc);

    uint32_t *pInputBlock = pData;

    /* clear the out buffer for the first xor with input */
    MCUX_CSSL_FP_FUNCTION_CALL(result_memset, mcuxClMemory_set((uint8_t *)pOut, 0u,
                MCUXCLAES_BLOCK_SIZE,
                MCUXCLAES_BLOCK_SIZE));
    (void)result_memset;

    uint32_t numBlocks = dataLen / MCUXCLAES_BLOCK_SIZE;
    uint32_t i, j;
    uint32_t blkSizeInWords = MCUXCLAES_BLOCK_SIZE/sizeof(uint32_t);

    for (i = 0; i < numBlocks; i++)
    {
        for (j = 0; j < blkSizeInWords; j++)
        {
            /* pInputBlock and pOut is aligned by 32bit in workarea */
            pInputBlock[j * blkSizeInWords] ^= pOut[j * blkSizeInWords];
        }
        MCUX_CSSL_FP_FUNCTION_CALL(ret_blockcipher,
            mcuxClRandomModes_DRBG_AES_Internal_blockcipher((uint8_t *)pInputBlock, (uint8_t *)pKey, (uint8_t *)pOut, keyLength));
        if (MCUXCLRANDOM_STATUS_OK != ret_blockcipher)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_bcc, MCUXCLRANDOM_STATUS_ERROR,
                    (i + 1u) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_DRBG_AES_Internal_blockcipher));
        }
        pInputBlock += blkSizeInWords;
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_bcc, MCUXCLRANDOM_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
        i * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_DRBG_AES_Internal_blockcipher));
}

static uint32_t const mcuxClRandomModes_CtrDrbg_df_key[8] = {
    0x03020100u, 0x04050607u, 0x08090a0bu, 0x0c0d0e0fu,
    0x10111213u, 0x14151617u, 0x18191a1bu, 0x1c1d1e1fu
};

/* Note: the pInputString use both input and output */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_df)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandomModes_CtrDrbg_df(
        mcuxClSession_Handle_t pSession, uint8_t *pInputString, uint32_t inputStringLen, uint32_t outputLen)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_df);

    mcuxClRandom_Mode_t pMode = pSession->randomCfg.mode;
    uint32_t seedLen = ((mcuxClRandomModes_DrbgModeDescriptor_t *) pMode->pDrbgMode)->pDrbgVariant->seedLen;
    uint32_t * allocateSuccess = NULL;

    if (MCUXCLRANDOM_MAX_DF_BITS < seedLen * 8u)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_df, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /*
     * CPU work area
     * Store IV and S, input of BCC function (see NIST SP800-90A), in CPU work area
     * layout: IV || L || N || input_string || 0x80 || 0 padding
     * length: 16    4    4     seed size      1       (16-(4+4+seedSize+1)%16)%16
     */
    uint32_t *pIV = (uint32_t *)&pSession->cpuWa.buffer[pSession->cpuWa.used];

    allocateSuccess = mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(MCUXCLAES_BLOCK_SIZE));
    if(NULL == allocateSuccess)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_df, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }
    allocateSuccess = NULL;

    /* clear the IV to padding 0 at the end */
    MCUX_CSSL_FP_FUNCTION_CALL(result_memset, mcuxClMemory_set((uint8_t*)pIV, 0u,
                 MCUXCLAES_BLOCK_SIZE,
                 MCUXCLAES_BLOCK_SIZE));
    (void)result_memset;

    uint32_t *pS= (uint32_t *)&pSession->cpuWa.buffer[pSession->cpuWa.used];
    uint8_t *pSByte= (uint8_t *)pS;
    /*
     * allocate (4+4+seedSize+1 + ((16-(4+4+seedSize+1)%16)%16))for S
     */
    uint32_t lenOfS = sizeof(uint32_t)+sizeof(uint32_t)+inputStringLen;
    uint32_t tempLen = lenOfS;
    /* add 1 for 0x80*/
    lenOfS += 1u;
    /* padding 0 if not align with outlen */
    if (0u != (lenOfS % MCUXCLAES_BLOCK_SIZE))
    {
        lenOfS += (MCUXCLAES_BLOCK_SIZE - (lenOfS % MCUXCLAES_BLOCK_SIZE));
    }

    allocateSuccess = mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(lenOfS));
    if(NULL == allocateSuccess)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_df, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }
    allocateSuccess = NULL;

    /* clear the S in case need padding 0 at the end */
    MCUX_CSSL_FP_FUNCTION_CALL(result_memset2, mcuxClMemory_set(pSByte, 0u,
                lenOfS, lenOfS));
    (void)result_memset2;

    pS[0] = inputStringLen;
    pS[1] = outputLen;
    MCUXCLMEMORY_FP_MEMORY_COPY((uint8_t *)&pS[2], (uint8_t const *)pInputString,
                     inputStringLen);
    pSByte[tempLen] = 0x80;

    uint32_t *pOutKey = (uint32_t *)&pSession->cpuWa.buffer[pSession->cpuWa.used];
    /*
     * CPU work area
     *    K    ||   X  || additionBlock
     *  keylen     16         16
     * allocate an addition block in case (keylen + 16) mod 16 != 0
     */
    uint32_t outKeyLen = (uint32_t)(pMode->securityStrength) / 8u + 2u * MCUXCLAES_BLOCK_SIZE;

    allocateSuccess = mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(outKeyLen));
    if(NULL == allocateSuccess)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_df, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }
    allocateSuccess = NULL;

    uint32_t outBlocks = (outKeyLen - 1u) / MCUXCLAES_BLOCK_SIZE;
    uint32_t i;
    for (i = 0; i < outBlocks; i++)
    {
        pIV[0] = i;
        MCUX_CSSL_FP_FUNCTION_CALL(result_bcc,
            mcuxClRandomModes_CtrDrbg_bcc((uint8_t const *)mcuxClRandomModes_CtrDrbg_df_key, (uint32_t)(pMode->securityStrength/8u),
                    pIV, MCUXCLAES_BLOCK_SIZE + lenOfS,
                    &pOutKey[i*MCUXCLAES_BLOCK_SIZE/sizeof(uint32_t)]));
        if (MCUXCLRANDOM_STATUS_OK != result_bcc)
        {
            mcuxClSession_freeWords_cpuWa(pSession, MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(outKeyLen + lenOfS + MCUXCLAES_BLOCK_SIZE));
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_df, MCUXCLRANDOM_STATUS_ERROR,
                    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                    2u * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
                    (i + 1u) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_bcc));
        }
    }

    uint32_t j;
    outBlocks = (uint32_t)((outputLen + MCUXCLAES_BLOCK_SIZE - 1) / MCUXCLAES_BLOCK_SIZE);
    /* use pIV as output X */
    /* generate the first X */
    MCUX_CSSL_FP_FUNCTION_CALL(ret_blockcipher1,
        mcuxClRandomModes_DRBG_AES_Internal_blockcipher((uint8_t *)&pOutKey[(uint32_t)(pMode->securityStrength/8u)/sizeof(uint32_t)],
                (uint8_t *)pOutKey, (uint8_t *)&pIV[0], (uint32_t)(pMode->securityStrength/8u)));
    if (MCUXCLRANDOM_STATUS_OK != ret_blockcipher1)
    {
        mcuxClSession_freeWords_cpuWa(pSession, MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(outKeyLen + lenOfS + MCUXCLAES_BLOCK_SIZE));
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_df, MCUXCLRANDOM_STATUS_ERROR,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                2u * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
                i * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_bcc),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_DRBG_AES_Internal_blockcipher));
    }
    /* generate the remained X */
    for (j = 1u; j < outBlocks; j++)
    {
        MCUX_CSSL_FP_FUNCTION_CALL(ret_blockcipher2,
                                  mcuxClRandomModes_DRBG_AES_Internal_blockcipher((uint8_t *)&pIV[(j-1u)*MCUXCLAES_BLOCK_SIZE/sizeof(uint32_t)],
                    (uint8_t *)pOutKey, (uint8_t *)&pIV[j*MCUXCLAES_BLOCK_SIZE/sizeof(uint32_t)], (uint32_t)(pMode->securityStrength/8u)));
        if (MCUXCLRANDOM_STATUS_OK != ret_blockcipher2)
        {
            mcuxClSession_freeWords_cpuWa(pSession, MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(outKeyLen + lenOfS + MCUXCLAES_BLOCK_SIZE));
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_df, MCUXCLRANDOM_STATUS_ERROR,
                    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                    2u * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
                    i * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_bcc),
                    (j + 1u) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_DRBG_AES_Internal_blockcipher));
        }
    }

    /* output the result */
    MCUXCLMEMORY_FP_MEMORY_COPY(pInputString, (uint8_t const *)pIV, outputLen);

    mcuxClSession_freeWords_cpuWa(pSession, MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(outKeyLen + lenOfS + MCUXCLAES_BLOCK_SIZE));
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_df, MCUXCLRANDOM_STATUS_OK,
            2u * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
            2u * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
            i * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_bcc),
            j  * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_DRBG_AES_Internal_blockcipher));
}


/* MISRA Ex. 20 - Rule 5.1 */
const mcuxClRandomModes_DrbgVariantDescriptor_t mcuxClRandomModes_DrbgVariantDescriptor_CtrDrbg_AES128 =
{
    .reseedInterval = MCUXCLRANDOMMODES_RESEED_INTERVAL_CTR_DRBG_AES128,
    .seedLen = MCUXCLRANDOMMODES_SEEDLEN_CTR_DRBG_AES128,
    .initSeedSize = MCUXCLRANDOMMODES_ENTROPYINPUT_SIZE_INIT_CTR_DRBG_AES128,
    .reseedSeedSize = MCUXCLRANDOMMODES_ENTROPYINPUT_SIZE_RESEED_CTR_DRBG_AES128
};

/* MISRA Ex. 20 - Rule 5.1 */
const mcuxClRandomModes_DrbgVariantDescriptor_t mcuxClRandomModes_DrbgVariantDescriptor_CtrDrbg_AES192 =
{
    .reseedInterval = MCUXCLRANDOMMODES_RESEED_INTERVAL_CTR_DRBG_AES192,
    .seedLen = MCUXCLRANDOMMODES_SEEDLEN_CTR_DRBG_AES192,
    .initSeedSize = MCUXCLRANDOMMODES_ENTROPYINPUT_SIZE_INIT_CTR_DRBG_AES192,
    .reseedSeedSize = MCUXCLRANDOMMODES_ENTROPYINPUT_SIZE_RESEED_CTR_DRBG_AES192
};

/* MISRA Ex. 20 - Rule 5.1 */
const mcuxClRandomModes_DrbgVariantDescriptor_t mcuxClRandomModes_DrbgVariantDescriptor_CtrDrbg_AES256 =
{
    .reseedInterval = MCUXCLRANDOMMODES_RESEED_INTERVAL_CTR_DRBG_AES256,
    .seedLen = MCUXCLRANDOMMODES_SEEDLEN_CTR_DRBG_AES256,
    .initSeedSize = MCUXCLRANDOMMODES_ENTROPYINPUT_SIZE_INIT_CTR_DRBG_AES256,
    .reseedSeedSize = MCUXCLRANDOMMODES_ENTROPYINPUT_SIZE_RESEED_CTR_DRBG_AES256
};

/**
 * \brief This function instantiates a CTR_DRBG following the lines of the function CTR_DRBG_Instantiate_algorithm as specified in NIST SP800-90A
 *
 * This function instantiates a CTR_DRBG in following the lines of the function CTR_DRBG_Instantiate_algorithm as specified in NIST SP800-90A.
 * The function obtains entropy input for the DRBG seed from the TRNG.
 *
 * \param  pSession             Handle for the current CL session
 * \param  pEntropyInput[in]    Pointer to entropy input
 *
 * \return
 *   - MCUXCLRANDOM_STATUS_OK         if the CTR_DRBG instantiation finished successfully
 *   - MCUXCLRANDOM_STATUS_FAULT_ATTACK    if the CTR_DRBG instantiation failed due to other unexpected reasons
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_instantiateAlgorithm)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandomModes_CtrDrbg_instantiateAlgorithm(
        mcuxClSession_Handle_t pSession, uint32_t *pEntropyInput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_instantiateAlgorithm);

    mcuxClRandomModes_Context_Generic_t *pRngCtx = (mcuxClRandomModes_Context_Generic_t *) pSession->randomCfg.ctx;
    mcuxClRandom_Mode_t pMode = pSession->randomCfg.mode;
    uint32_t seedLen = ((mcuxClRandomModes_DrbgModeDescriptor_t *) pMode->pDrbgMode)->pDrbgVariant->seedLen;
    uint32_t initSeedSize = ((mcuxClRandomModes_DrbgModeDescriptor_t *) pMode->pDrbgMode)->pDrbgVariant->initSeedSize;
    uint32_t *allocateSuccess = NULL;

    /* Pad entropyInput with zeros to obtain proper seedMaterial for the UpdateState function */
    uint32_t *pSeedMaterial = (uint32_t *)&pSession->cpuWa.buffer[pSession->cpuWa.used];
    allocateSuccess = mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(initSeedSize));
    if(NULL == allocateSuccess)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_instantiateAlgorithm, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }
    allocateSuccess = NULL;

    MCUX_CSSL_FP_FUNCTION_CALL(result_memset, mcuxClMemory_set((uint8_t *)pSeedMaterial, 0u,
                initSeedSize,
                initSeedSize));
    (void)result_memset;
    MCUXCLMEMORY_FP_MEMORY_COPY((uint8_t *)pSeedMaterial, (uint8_t const *)pEntropyInput,
                         initSeedSize);

    /* pSeedMaterial use as both input and output */
    MCUX_CSSL_FP_FUNCTION_CALL(ret_df, mcuxClRandomModes_CtrDrbg_df(pSession, (uint8_t *)pSeedMaterial,
                initSeedSize, seedLen));
    if (MCUXCLRANDOM_STATUS_OK != ret_df)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_instantiateAlgorithm, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Clear counter V and key K in context
     *
     * NOTE: V and K lie next to each other in the context */
    /* MISRA Ex. 9 to Rule 11.3 - reinterpret memory */
    uint32_t *pState = ((mcuxClRandomModes_Context_CtrDrbg_Aes128_t *) pRngCtx)->key;
    MCUX_CSSL_FP_FUNCTION_CALL(result_memset2, mcuxClMemory_set((uint8_t *)pState, 0u,
                seedLen,
                seedLen));
    (void)result_memset2;

    /* Update the CTR_DRBG state
     *
     * NOTE: The size of the provided DRBG seed equals seedLen, so no padding with zeros is needed to derive the seedMaterial from the entryopInput
     */
    MCUX_CSSL_FP_FUNCTION_CALL(result_updatestate, mcuxClRandomModes_CtrDrbg_UpdateState(pSession, (uint8_t *)pSeedMaterial));
    if (MCUXCLRANDOM_STATUS_OK != result_updatestate)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_instantiateAlgorithm, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    mcuxClSession_freeWords_cpuWa(pSession, MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(initSeedSize));

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_instantiateAlgorithm, MCUXCLRANDOM_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
        2u * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_df),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_UpdateState));
}


/**
 * \brief This function reseeds a CTR_DRBG following the lines of the function CTR_DRBG_Reseed_algorithm as specified in NIST SP800-90A
 *
 * This function reseeds a CTR_DRBG following the lines of the function CTR_DRBG_Instantiate_algorithm as specified in NIST SP800-90A.
 * The function obtains entropy input for the DRBG seed from the TRNG.
 *
 * \param  pSession[in]         Handle for the current CL session
 * \param  pEntropyInput[in]    Pointer to entropy input
 *
 * \return
 *   - MCUXCLRANDOM_STATUS_OK         if the CTR_DRBG instantiation finished successfully
 *   - MCUXCLRANDOM_STATUS_FAULT_ATTACK    if the CTR_DRBG instantiation failed due to other unexpected reasons
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_reseedAlgorithm)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandomModes_CtrDrbg_reseedAlgorithm(mcuxClSession_Handle_t pSession, uint32_t *pEntropyInput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_reseedAlgorithm);

    mcuxClRandom_Mode_t pMode = pSession->randomCfg.mode;
    uint32_t seedLen = ((mcuxClRandomModes_DrbgModeDescriptor_t *) pMode->pDrbgMode)->pDrbgVariant->seedLen;
    uint32_t reseedSeedSize = ((mcuxClRandomModes_DrbgModeDescriptor_t *) pMode->pDrbgMode)->pDrbgVariant->reseedSeedSize;
    uint32_t * allocateSuccess = NULL;

    /* Pad entropyInput with zeros to obtain proper seedMaterial for the UpdateState function */
    uint32_t *pSeedMaterial = (uint32_t *)&pSession->cpuWa.buffer[pSession->cpuWa.used];
    allocateSuccess = mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(reseedSeedSize));
    if(NULL == allocateSuccess)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_reseedAlgorithm, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }
    allocateSuccess = NULL;

    MCUX_CSSL_FP_FUNCTION_CALL(result_memset, mcuxClMemory_set((uint8_t *)pSeedMaterial, 0u,
                reseedSeedSize,
                reseedSeedSize));
    (void)result_memset;
    MCUXCLMEMORY_FP_MEMORY_COPY((uint8_t *)pSeedMaterial, (uint8_t const *)pEntropyInput,
                         reseedSeedSize);

    /* pSeedMaterial use as both input and output */
    MCUX_CSSL_FP_FUNCTION_CALL(ret_df, mcuxClRandomModes_CtrDrbg_df(pSession, (uint8_t *)pSeedMaterial,
                reseedSeedSize, seedLen));
    if (MCUXCLRANDOM_STATUS_OK != ret_df)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_reseedAlgorithm, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Update the CTR_DRBG state */
    MCUX_CSSL_FP_FUNCTION_CALL(result_updatestate, mcuxClRandomModes_CtrDrbg_UpdateState(pSession, (uint8_t *)pSeedMaterial));
    if (MCUXCLRANDOM_STATUS_OK != result_updatestate)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_reseedAlgorithm, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    mcuxClSession_freeWords_cpuWa(pSession, MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(reseedSeedSize));

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_reseedAlgorithm, MCUXCLRANDOM_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_df),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_UpdateState));
}


/**
 * \brief This function generates random numbers from a CTR_DRBG following the lines of the function CTR_DRBG_Generate_algorithm as specified in NIST SP800-90A
 *
 * \param  pSession             Handle for the current CL session
 * \param  pOut[out]            Output buffer to which the generated randomness will be written
 * \param  outLength[in]        Number of requested random bytes
 *
 * \return
 *   - MCUXCLRANDOM_STATUS_OK         if the random number generation finished successfully
 *   - MCUXCLRANDOM_STATUS_FAULT_ATTACK    if the random number generation failed due to other unexpected reasons
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_generateAlgorithm)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandomModes_CtrDrbg_generateAlgorithm(mcuxClSession_Handle_t pSession, uint8_t *pOut, uint32_t outLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_generateAlgorithm);

    mcuxClRandom_Mode_t pMode = pSession->randomCfg.mode;
    uint32_t seedLen = ((mcuxClRandomModes_DrbgModeDescriptor_t *) pMode->pDrbgMode)->pDrbgVariant->seedLen;
    uint32_t * allocateSuccess = NULL;

    MCUX_CSSL_FP_FUNCTION_CALL(result_generate,
        mcuxClRandomModes_CtrDrbg_generateOutput(pSession, pOut, outLength));
    if(MCUXCLRANDOM_STATUS_OK != result_generate)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_generateAlgorithm, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Init additionalInput for state update in CPU workarea to all zeros and update the CTR_DRBG state */
    uint32_t *pAdditionalInput = (uint32_t *)&pSession->cpuWa.buffer[pSession->cpuWa.used];
    allocateSuccess = mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(seedLen));
    if(NULL == allocateSuccess)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_generateAlgorithm, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }
    allocateSuccess = NULL;

    MCUX_CSSL_FP_FUNCTION_CALL(result_memset, mcuxClMemory_set((uint8_t *)pAdditionalInput, 0u,
                seedLen,
                seedLen));
    (void)result_memset;

    MCUX_CSSL_FP_FUNCTION_CALL(result_updatestate, mcuxClRandomModes_CtrDrbg_UpdateState(pSession, (uint8_t *)pAdditionalInput));
    if (MCUXCLRANDOM_STATUS_OK != result_updatestate)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_generateAlgorithm, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    mcuxClSession_freeWords_cpuWa(pSession, MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(seedLen));

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_generateAlgorithm, MCUXCLRANDOM_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_generateOutput),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_UpdateState));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_UpdateState)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandomModes_CtrDrbg_UpdateState(
    mcuxClSession_Handle_t pSession,
    uint8_t *pProvidedData
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_UpdateState);

    mcuxClRandomModes_Context_Generic_t *pCtx = (mcuxClRandomModes_Context_Generic_t *) pSession->randomCfg.ctx;
    mcuxClRandom_Mode_t pMode = pSession->randomCfg.mode;
    uint32_t seedLen = ((mcuxClRandomModes_DrbgModeDescriptor_t *) pMode->pDrbgMode)->pDrbgVariant->seedLen;
    uint32_t securityStrength = (uint32_t)(pMode->securityStrength);
    uint32_t * allocateSuccess = NULL;

    /* MISRA Ex. 9 to Rule 11.3 - reinterpret memory */
    uint8_t *pState = (uint8_t *)((mcuxClRandomModes_Context_CtrDrbg_Aes128_t *) pCtx)->key;
    uint8_t *pKey = (uint8_t *)pState;
    uint8_t *pV = &pState[securityStrength/8u];

    /* produce the new Key and V */
    uint32_t *pNewKV = (uint32_t *)&pSession->cpuWa.buffer[pSession->cpuWa.used];
    allocateSuccess = mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(seedLen));
    if(NULL == allocateSuccess)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_UpdateState, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }
    allocateSuccess = NULL;

    uint32_t keyLenInBlkSize = securityStrength/8u/MCUXCLAES_BLOCK_SIZE;
    uint32_t i, j;

    for (i = 0u; i < keyLenInBlkSize + 1u; i++)
    {
        /* MISRA Ex. 9 to Rule 11.3 - reinterpret memory */
        MCUX_CSSL_FP_FUNCTION_CALL(checkIncrement, mcuxClRandomModes_CtrDrbg_incV(pV));
        if(checkIncrement == *(uint32_t *)pV)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_UpdateState, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
        }
        MCUX_CSSL_FP_FUNCTION_CALL(ret_blockcipher, mcuxClRandomModes_DRBG_AES_Internal_blockcipher(pV, pKey,
                (uint8_t *)&pNewKV[(i * MCUXCLAES_BLOCK_SIZE_IN_WORDS)],
                securityStrength/8u));
        if (MCUXCLRANDOM_STATUS_OK != ret_blockcipher)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_UpdateState, MCUXCLRANDOM_STATUS_ERROR,
                (i + 1u) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_DRBG_AES_Internal_blockcipher),
                (i + 1u) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_incV));
        }
    }

    if (NULL != pProvidedData)
    {
        uint8_t *pNewKVByte = (uint8_t *)pNewKV;
        for (j = 0; j < (securityStrength/8u + MCUXCLAES_BLOCK_SIZE); j++)
        {
            pNewKVByte[j] = pNewKVByte[j] ^ pProvidedData[j];
        }
    }

    /* update the key V in context */
    MCUXCLMEMORY_FP_MEMORY_COPY((uint8_t *)pKey, (uint8_t const *)pNewKV,
                    securityStrength/8u + MCUXCLAES_BLOCK_SIZE);

    mcuxClSession_freeWords_cpuWa(pSession, MCUXCLRANDOMMODES_ROUND_UP_TO_CPU_WORDSIZE(seedLen));

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_UpdateState, MCUXCLRANDOM_STATUS_OK,
                i * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_DRBG_AES_Internal_blockcipher),
                i * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_incV),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandomModes_CtrDrbg_generateOutput)
/* MISRA Ex. 20 - Rule 5.1 */
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandomModes_CtrDrbg_generateOutput(
        mcuxClSession_Handle_t pSession,
        uint8_t *pOut, uint32_t outLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandomModes_CtrDrbg_generateOutput);

    mcuxClRandomModes_Context_Generic_t *pCtx = (mcuxClRandomModes_Context_Generic_t *) pSession->randomCfg.ctx;
    mcuxClRandom_Mode_t pMode = pSession->randomCfg.mode;
    uint32_t securityStrength = (uint32_t)(pMode->securityStrength);

    /**
     * We first request as much as possible directly, and then use a small buffer
     * to copy up to remaining bytes.
     */

    /**
     * Note: writing to pOut could be unaligned.
     * This could be improved by: - requesting a single word
     *                            - copying as many bytes as needed to achieve alignment
     *                            - requesting the following words to aligned addresses
     *                            - possibly requesting another single word to fill the remaining bytes
     */

    /* MISRA Ex. 9 to Rule 11.3 - reinterpret memory */
    uint8_t *pState = (uint8_t *)((mcuxClRandomModes_Context_CtrDrbg_Aes128_t *) pCtx)->key;
    uint8_t *pKey = (uint8_t *)pState;
    uint8_t *pV = &pState[securityStrength/8u];
    uint32_t requestSizeRemainingBytes = outLength % MCUXCLAES_BLOCK_SIZE;
    uint32_t requestSizeFullWordsBytes = outLength - requestSizeRemainingBytes;
    uint32_t outIndex = 0u;

    /* Request as many random bytes as possible with full word size. */
    while (requestSizeFullWordsBytes > 0u)
    {
        MCUX_CSSL_FP_FUNCTION_CALL(checkIncrement, mcuxClRandomModes_CtrDrbg_incV(pV));
        if(checkIncrement == *(uint32_t *)pV)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_generateOutput, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
        }

        MCUX_CSSL_FP_FUNCTION_CALL(ret_Internal_blockcipher,
            mcuxClRandomModes_DRBG_AES_Internal_blockcipher(pV, pKey, &pOut[outIndex], securityStrength/8u));
        if (MCUXCLRANDOM_STATUS_OK != ret_Internal_blockcipher)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_generateOutput, MCUXCLRANDOM_STATUS_ERROR,
                (outIndex/MCUXCLAES_BLOCK_SIZE + 1u) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_DRBG_AES_Internal_blockcipher),
                (outIndex/MCUXCLAES_BLOCK_SIZE + 1u) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_incV));
        }
        outIndex += MCUXCLAES_BLOCK_SIZE;
        requestSizeFullWordsBytes -= MCUXCLAES_BLOCK_SIZE;
    }

    /* If requested size is not a multiple of block size, request one (additional) block and use it only partially. */
    if (requestSizeRemainingBytes > 0u)
    {
        uint8_t requestRemainingBuffer[MCUXCLAES_BLOCK_SIZE] = {0u};

        MCUX_CSSL_FP_FUNCTION_CALL(checkIncrement, mcuxClRandomModes_CtrDrbg_incV(pV));
        if(checkIncrement == *(uint32_t *)pV)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_generateOutput, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
        }

        MCUX_CSSL_FP_FUNCTION_CALL(ret_Internal_blockcipher,
            mcuxClRandomModes_DRBG_AES_Internal_blockcipher(pV, pKey, requestRemainingBuffer, securityStrength/8u));
        if (MCUXCLRANDOM_STATUS_OK != ret_Internal_blockcipher)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandomModes_CtrDrbg_generateOutput, MCUXCLRANDOM_STATUS_ERROR,
                (outIndex/MCUXCLAES_BLOCK_SIZE + 1u) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_DRBG_AES_Internal_blockcipher),
                (outIndex/MCUXCLAES_BLOCK_SIZE + 1u) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_incV));
        }

        /* Copy the remaining bytes from the buffer to output. */
        MCUXCLMEMORY_FP_MEMORY_COPY(&pOut[outIndex], requestRemainingBuffer, requestSizeRemainingBytes);

    }

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClRandomModes_CtrDrbg_generateOutput, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK,
            (outIndex/MCUXCLAES_BLOCK_SIZE) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_DRBG_AES_Internal_blockcipher),
            (outIndex/MCUXCLAES_BLOCK_SIZE) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_incV),
            MCUX_CSSL_FP_CONDITIONAL((requestSizeRemainingBytes > 0u),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_DRBG_AES_Internal_blockcipher),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_CtrDrbg_incV))
            );
}
