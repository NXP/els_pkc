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
/* Security Classification:  Company Confidential                           */
/*--------------------------------------------------------------------------*/

#include <mcuxClRandom.h>
#include <mcuxClSession.h>
#include <mcuxClMemory.h>
#include <mcuxClAes.h>

#include <internal/mcuxClRandom_Internal_Types.h>
#include <internal/mcuxClRandom_Private_Types.h>
#include <internal/mcuxClRandom_Private_CtrDrbg.h>
#include <internal/mcuxClRandom_Private_NormalMode.h>
#include <internal/mcuxClRandom_Private_Drbg.h>
#include <internal/mcuxClRandom_Private_CtrDrbg_BlockCipher.h>
#include <internal/mcuxClMemory_Copy_Internal.h>

const mcuxClRandom_DrbgAlgorithmsDescriptor_t mcuxClRandom_DrbgAlgorithmsDescriptor_CtrDrbg =
{
    .instantiateAlgorithm = mcuxClRandom_CtrDrbg_instantiateAlgorithm,
    .reseedAlgorithm = mcuxClRandom_CtrDrbg_reseedAlgorithm,
    .generateAlgorithm = mcuxClRandom_CtrDrbg_generateAlgorithm,
    .protectionTokenInstantiateAlgorithm = MCUX_CSSL_FP_FUNCID_mcuxClRandom_CtrDrbg_instantiateAlgorithm,
    .protectionTokenReseedAlgorithm = MCUX_CSSL_FP_FUNCID_mcuxClRandom_CtrDrbg_reseedAlgorithm,
    .protectionTokenGenerateAlgorithm = MCUX_CSSL_FP_FUNCID_mcuxClRandom_CtrDrbg_generateAlgorithm,
};

#if defined(MCUXCL_FEATURE_RANDOM_DERIVATION_FUNCTION)

#define MCUXCL_RANDOM_MAX_DF_BITS        512u

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandom_CtrDrbg_bcc)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_CtrDrbg_bcc(uint8_t const *pKey, uint32_t keyLength,
        uint32_t *pData, uint32_t dataLen, uint32_t *pOut)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_CtrDrbg_bcc);

    /* clear the out buffer for the first xor with input */
    MCUX_CSSL_FP_FUNCTION_CALL(result_memset, mcuxClMemory_set((uint8_t *)pOut, 0,
                MCUX_CL_AES_BLOCK_SIZE,
                MCUX_CL_AES_BLOCK_SIZE));
    (void)result_memset;

    uint32_t numBlocks = dataLen / MCUX_CL_AES_BLOCK_SIZE;
    uint32_t i, j;
    uint32_t blkSizeInWords =  MCUX_CL_AES_BLOCK_SIZE/sizeof(uint32_t);

    for (i = 0; i < numBlocks; i++)
    {
        for (j = 0; j < MCUX_CL_AES_BLOCK_SIZE/sizeof(uint32_t); j++)
        {
            /* pData and pOut is aligned by 32bit in workarea */
            pData[j * blkSizeInWords] ^= pOut[j * blkSizeInWords];
        }
        MCUX_CSSL_FP_FUNCTION_CALL(ret_blockcipher,
                mcuxClRandom_DRBG_AES_Internal_blockcipher((uint8_t *)pData, (uint8_t *)pKey, (uint8_t *)pOut, keyLength));
        if (MCUXCLRANDOM_STATUS_OK != ret_blockcipher)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_bcc, MCUXCLRANDOM_STATUS_ERROR,
                    (i + 1u) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_DRBG_AES_Internal_blockcipher));
        }
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_bcc, MCUXCLRANDOM_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
        i * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_DRBG_AES_Internal_blockcipher));
}

static uint8_t const mcuxClRandom_CtrDrbg_df_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

/* Note: the pInputString use both input and output */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandom_CtrDrbg_df)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_CtrDrbg_df(
        mcuxClSession_Handle_t pSession, uint8_t *pInputString, uint32_t inputStringLen, uint32_t outputLen)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_CtrDrbg_df);

    mcuxClRandom_Mode_t pMode = pSession->randomCfg.mode;
    uint32_t seedLen = pMode->pDrbgMode->pDrbgVariant->seedLen;

    if (MCUXCL_RANDOM_MAX_DF_BITS < seedLen * 8u)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_df, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /*
     * CPU work area
     * layout: IV || L || N || input_string || 0x80 || 0 padding
     * length: 16    4    4     seed size      1       (16-(4+4+seedSize+1)%16)%16
     */
    uint32_t *pIV = (uint32_t *)&pSession->cpuWa.buffer[pSession->cpuWa.used];
    pSession->cpuWa.used += MCUXCLRANDOM_ROUND_UP_TO_CPU_WORDSIZE(MCUX_CL_AES_BLOCK_SIZE);
    /* clear the IV to padding 0 at the end */
    MCUX_CSSL_FP_FUNCTION_CALL(result_memset, mcuxClMemory_set((uint8_t*)pIV, 0,
                 MCUX_CL_AES_BLOCK_SIZE,
                 MCUX_CL_AES_BLOCK_SIZE));
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
    if (0u != (lenOfS % MCUX_CL_AES_BLOCK_SIZE))
    {
        lenOfS += (MCUX_CL_AES_BLOCK_SIZE - (lenOfS % MCUX_CL_AES_BLOCK_SIZE));
    }
    pSession->cpuWa.used += MCUXCLRANDOM_ROUND_UP_TO_CPU_WORDSIZE(lenOfS);
    /* clear the S in case need padding 0 at the end */
    MCUX_CSSL_FP_FUNCTION_CALL(result_memset2, mcuxClMemory_set(pSByte, 0,
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
    uint32_t outKeyLen = pMode->securityStrength/8u + 2u * MCUX_CL_AES_BLOCK_SIZE;
    pSession->cpuWa.used += MCUXCLRANDOM_ROUND_UP_TO_CPU_WORDSIZE(outKeyLen);

    uint32_t outBlocks = (outKeyLen - 1u) / MCUX_CL_AES_BLOCK_SIZE;
    uint32_t i;
    for (i = 0; i < outBlocks; i++)
    {
        pIV[0] = i;
        MCUX_CSSL_FP_FUNCTION_CALL(result_bcc,
                mcuxClRandom_CtrDrbg_bcc(mcuxClRandom_CtrDrbg_df_key, pMode->securityStrength/8u,
                    pIV, MCUX_CL_AES_BLOCK_SIZE + lenOfS,
                    &pOutKey[i*MCUX_CL_AES_BLOCK_SIZE/sizeof(uint32_t)]));
        if (MCUXCLRANDOM_STATUS_OK != result_bcc)
        {
            pSession->cpuWa.used -= MCUXCLRANDOM_ROUND_UP_TO_CPU_WORDSIZE(outKeyLen + seedLen + 24u + MCUX_CL_AES_BLOCK_SIZE);
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_df, MCUXCLRANDOM_STATUS_ERROR,
                    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                    2u * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
                    (i + 1u) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_CtrDrbg_bcc));
        }
    }

    uint32_t j;
    outBlocks = (outputLen + MCUX_CL_AES_BLOCK_SIZE - 1)/MCUX_CL_AES_BLOCK_SIZE;
    /* use pIV as output X */
    /* generate the first X */
    MCUX_CSSL_FP_FUNCTION_CALL(ret_blockcipher,
            mcuxClRandom_DRBG_AES_Internal_blockcipher((uint8_t *)&pOutKey[pMode->securityStrength/8u/sizeof(uint32_t)],
                (uint8_t *)pOutKey, (uint8_t *)&pIV[0], pMode->securityStrength/8u));
    if (MCUXCLRANDOM_STATUS_OK != ret_blockcipher)
    {
        pSession->cpuWa.used -= MCUXCLRANDOM_ROUND_UP_TO_CPU_WORDSIZE(outKeyLen + seedLen + 24u + MCUX_CL_AES_BLOCK_SIZE);
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_df, MCUXCLRANDOM_STATUS_ERROR,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                2u * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
                i * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_CtrDrbg_bcc),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_DRBG_AES_Internal_blockcipher));
    }
    /* generate the remained X */
    for (j = 1u; j < outBlocks; j++)
    {
        MCUX_CSSL_FP_FUNCTION_CALL(ret_blockcipher,
                mcuxClRandom_DRBG_AES_Internal_blockcipher((uint8_t *)&pIV[(j-1u)*MCUX_CL_AES_BLOCK_SIZE/sizeof(uint32_t)],
                    (uint8_t *)pOutKey, (uint8_t *)&pIV[j*MCUX_CL_AES_BLOCK_SIZE/sizeof(uint32_t)], pMode->securityStrength/8u));
        if (MCUXCLRANDOM_STATUS_OK != ret_blockcipher)
        {
            pSession->cpuWa.used -= MCUXCLRANDOM_ROUND_UP_TO_CPU_WORDSIZE(outKeyLen + seedLen + 24u + MCUX_CL_AES_BLOCK_SIZE);
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_df, MCUXCLRANDOM_STATUS_ERROR,
                    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                    2u * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
                    i * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_CtrDrbg_bcc),
                    (j + 1u) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_DRBG_AES_Internal_blockcipher));
        }
    }

    /* output the result */
    MCUXCLMEMORY_FP_MEMORY_COPY(pInputString, (uint8_t const *)pIV, outputLen);

    pSession->cpuWa.used -= MCUXCLRANDOM_ROUND_UP_TO_CPU_WORDSIZE(outKeyLen + seedLen + 24u + MCUX_CL_AES_BLOCK_SIZE);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_df, MCUXCLRANDOM_STATUS_OK,
            2u * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
            2u * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
            i * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_CtrDrbg_bcc),
            j  * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_DRBG_AES_Internal_blockcipher));
}

#endif

const mcuxClRandom_DrbgVariantDescriptor_t mcuxClRandom_DrbgVariantDescriptor_CtrDrbg_AES128 =
{
    .reseedInterval = MCUXCLRANDOM_MODE_RESEED_INTERVAL_CTR_DRBG_AES128,
    .seedLen = MCUXCLRANDOM_MODE_SEEDLEN_CTR_DRBG_AES128,
    .initSeedSize = MCUXCLRANDOM_MODE_ENTROPYINPUT_SIZE_INIT_CTR_DRBG_AES128,
    .reseedSeedSize = MCUXCLRANDOM_MODE_ENTROPYINPUT_SIZE_RESEED_CTR_DRBG_AES128
};

const mcuxClRandom_DrbgVariantDescriptor_t mcuxClRandom_DrbgVariantDescriptor_CtrDrbg_AES192 =
{
    .reseedInterval = MCUXCLRANDOM_MODE_RESEED_INTERVAL_CTR_DRBG_AES192,
    .seedLen = MCUXCLRANDOM_MODE_SEEDLEN_CTR_DRBG_AES192,
    .initSeedSize = MCUXCLRANDOM_MODE_ENTROPYINPUT_SIZE_INIT_CTR_DRBG_AES192,
    .reseedSeedSize = MCUXCLRANDOM_MODE_ENTROPYINPUT_SIZE_RESEED_CTR_DRBG_AES192
};

const mcuxClRandom_DrbgVariantDescriptor_t mcuxClRandom_DrbgVariantDescriptor_CtrDrbg_AES256 =
{
    .reseedInterval = MCUXCLRANDOM_MODE_RESEED_INTERVAL_CTR_DRBG_AES256,
    .seedLen = MCUXCLRANDOM_MODE_SEEDLEN_CTR_DRBG_AES256,
    .initSeedSize = MCUXCLRANDOM_MODE_ENTROPYINPUT_SIZE_INIT_CTR_DRBG_AES256,
    .reseedSeedSize = MCUXCLRANDOM_MODE_ENTROPYINPUT_SIZE_RESEED_CTR_DRBG_AES256
};

/**
 * \brief This function instantiates a CTR_DRBG following the lines of the function CTR_DRBG_Instantiate_algorithm as specified in NIST SP800-90A
 *
 * This function instantiates a CTR_DRBG in following the lines of the function CTR_DRBG_Instantiate_algorithm as specified in NIST SP800-90A.
 * The function obtains entropy input for the DRBG seed from the TRNG.
 *
 * \param  pRngCtx[in]          Random context pointer
 * \param  pEntropyInput[in]    Pointer to entropy input
 *
 * \return
 *   - MCUXCLRANDOM_STATUS_OK         if the CTR_DRBG instantiation finished successfully
 *   - MCUXCLRANDOM_STATUS_FAULT_ATTACK    if the CTR_DRBG instantiation failed due to other unexpected reasons
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandom_CtrDrbg_instantiateAlgorithm)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_CtrDrbg_instantiateAlgorithm(
        mcuxClSession_Handle_t pSession, uint32_t *pEntropyInput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_CtrDrbg_instantiateAlgorithm);

    mcuxClRandom_Context_Generic_t *pRngCtx = (mcuxClRandom_Context_Generic_t *) pSession->randomCfg.ctx;
    mcuxClRandom_Mode_t pMode = pSession->randomCfg.mode;
    uint32_t seedLen = pMode->pDrbgMode->pDrbgVariant->seedLen;
    uint32_t initSeedSize = pMode->pDrbgMode->pDrbgVariant->initSeedSize;

    /* Pad entropyInput with zeros to obtain proper seedMaterial for the UpdateState function */
    uint32_t *pSeedMaterial = (uint32_t *)&pSession->cpuWa.buffer[pSession->cpuWa.used];
    pSession->cpuWa.used += MCUXCLRANDOM_ROUND_UP_TO_CPU_WORDSIZE(initSeedSize);
    MCUX_CSSL_FP_FUNCTION_CALL(result_memset, mcuxClMemory_set((uint8_t *)pSeedMaterial, 0,
                initSeedSize,
                initSeedSize));
    (void)result_memset;
    MCUXCLMEMORY_FP_MEMORY_COPY((uint8_t *)pSeedMaterial, (uint8_t const *)pEntropyInput,
                         initSeedSize);

#ifdef MCUXCL_FEATURE_RANDOM_DERIVATION_FUNCTION
    /* pSeedMaterial use as both input and output */
    MCUX_CSSL_FP_FUNCTION_CALL(ret_df, mcuxClRandom_CtrDrbg_df(pSession, (uint8_t *)pSeedMaterial,
                initSeedSize, seedLen));
    if (MCUXCLRANDOM_STATUS_OK != ret_df)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_instantiateAlgorithm, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }
#endif

    /* Clear counter V and key K in context
     *
     * NOTE: V and K lie next to each other in the context */
    uint32_t *pState = ((mcuxClRandom_Context_CtrDrbg_Aes128_t *) pRngCtx)->key;
    MCUX_CSSL_FP_FUNCTION_CALL(result_memset2, mcuxClMemory_set((uint8_t *)pState, 0,
                seedLen,
                seedLen));
    (void)result_memset2;

    /* Update the CTR_DRBG state
     *
     * NOTE: The size of the provided DRBG seed equals seedLen, so no padding with zeros is needed to derive the seedMaterial from the entryopInput
     */
    MCUX_CSSL_FP_FUNCTION_CALL(result_updatestate, mcuxClRandom_CtrDrbg_UpdateState(pSession, (uint8_t *)pSeedMaterial));
    if (MCUXCLRANDOM_STATUS_OK != result_updatestate)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_instantiateAlgorithm, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Initialize the reseed counter */
    pRngCtx->reseedCounter = 1;

    pSession->cpuWa.used -= MCUXCLRANDOM_ROUND_UP_TO_CPU_WORDSIZE(initSeedSize);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_instantiateAlgorithm, MCUXCLRANDOM_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
        2u * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
#ifdef MCUXCL_FEATURE_RANDOM_DERIVATION_FUNCTION
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_CtrDrbg_df),
#endif
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_CtrDrbg_UpdateState));
}


/**
 * \brief This function reseeds a CTR_DRBG following the lines of the function CTR_DRBG_Reseed_algorithm as specified in NIST SP800-90A
 *
 * This function reseeds a CTR_DRBG following the lines of the function CTR_DRBG_Instantiate_algorithm as specified in NIST SP800-90A.
 * The function obtains entropy input for the DRBG seed from the TRNG.
 *
 * \param  pRngCtx[in]          Random context pointer
 * \param  pEntropyInput[in]    Pointer to entropy input
 *
 * \return
 *   - MCUXCLRANDOM_STATUS_OK         if the CTR_DRBG instantiation finished successfully
 *   - MCUXCLRANDOM_STATUS_FAULT_ATTACK    if the CTR_DRBG instantiation failed due to other unexpected reasons
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandom_CtrDrbg_reseedAlgorithm)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_CtrDrbg_reseedAlgorithm(mcuxClSession_Handle_t pSession, uint32_t *pEntropyInput)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_CtrDrbg_reseedAlgorithm);

    mcuxClRandom_Context_Generic_t *pRngCtx = (mcuxClRandom_Context_Generic_t *) pSession->randomCfg.ctx;
    mcuxClRandom_Mode_t pMode = pSession->randomCfg.mode;
#ifdef MCUXCL_FEATURE_RANDOM_DERIVATION_FUNCTION
    uint32_t seedLen = pMode->pDrbgMode->pDrbgVariant->seedLen;
#endif
    uint32_t reseedSeedSize = pMode->pDrbgMode->pDrbgVariant->reseedSeedSize;

    /* Pad entropyInput with zeros to obtain proper seedMaterial for the UpdateState function */
    uint32_t *pSeedMaterial = (uint32_t *)&pSession->cpuWa.buffer[pSession->cpuWa.used];
    pSession->cpuWa.used += MCUXCLRANDOM_ROUND_UP_TO_CPU_WORDSIZE(reseedSeedSize);
    MCUX_CSSL_FP_FUNCTION_CALL(result_memset, mcuxClMemory_set((uint8_t *)pSeedMaterial, 0,
                reseedSeedSize,
                reseedSeedSize));
    (void)result_memset;
    MCUXCLMEMORY_FP_MEMORY_COPY((uint8_t *)pSeedMaterial, (uint8_t const *)pEntropyInput,
                         reseedSeedSize);

#ifdef MCUXCL_FEATURE_RANDOM_DERIVATION_FUNCTION
    /* pSeedMaterial use as both input and output */
    MCUX_CSSL_FP_FUNCTION_CALL(ret_df, mcuxClRandom_CtrDrbg_df(pSession, (uint8_t *)pSeedMaterial,
                reseedSeedSize, seedLen));
    if (MCUXCLRANDOM_STATUS_OK != ret_df)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_reseedAlgorithm, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }
#endif

    /* Update the CTR_DRBG state */
    MCUX_CSSL_FP_FUNCTION_CALL(result_updatestate, mcuxClRandom_CtrDrbg_UpdateState(pSession, (uint8_t *)pSeedMaterial));
    if (MCUXCLRANDOM_STATUS_OK != result_updatestate)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_reseedAlgorithm, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Initialize the reseed counter */
    pRngCtx->reseedCounter = 1;

    pSession->cpuWa.used -= MCUXCLRANDOM_ROUND_UP_TO_CPU_WORDSIZE(reseedSeedSize);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_reseedAlgorithm, MCUXCLRANDOM_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
#ifdef MCUXCL_FEATURE_RANDOM_DERIVATION_FUNCTION
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_CtrDrbg_df),
#endif
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_CtrDrbg_UpdateState));
}


/**
 * \brief This function generates random numbers from a CTR_DRBG following the lines of the function CTR_DRBG_Generate_algorithm as specified in NIST SP800-90A
 *
 * \param  pRngCtx[in]          Random context pointer
 * \param  pCpuWa[in]           Pointer to CPU workarea
 * \param  pOut[out]            Output buffer to which the generated randomness will be written
 * \param  outLength            Number of requested random bytes
 *
 * \return
 *   - MCUXCLRANDOM_STATUS_OK         if the random number generation finished successfully
 *   - MCUXCLRANDOM_STATUS_FAULT_ATTACK    if the random number generation failed due to other unexpected reasons
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandom_CtrDrbg_generateAlgorithm)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_CtrDrbg_generateAlgorithm(mcuxClSession_Handle_t pSession, uint8_t *pOut, uint32_t outLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_CtrDrbg_generateAlgorithm);

    mcuxClRandom_Context_Generic_t *pRngCtx = (mcuxClRandom_Context_Generic_t *) pSession->randomCfg.ctx;
    mcuxClRandom_Mode_t pMode = pSession->randomCfg.mode;
    uint32_t seedLen = pMode->pDrbgMode->pDrbgVariant->seedLen;

    MCUX_CSSL_FP_FUNCTION_CALL(result_generate,
            mcuxClRandom_CtrDrbg_generateOutput(pSession, pOut, outLength));
    if(MCUXCLRANDOM_STATUS_OK != result_generate)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_generateAlgorithm, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Init additionalInput for state update in CPU workarea to all zeros and update the CTR_DRBG state */
    uint32_t *pAdditionalInput = (uint32_t *)&pSession->cpuWa.buffer[pSession->cpuWa.used];
    pSession->cpuWa.used += MCUXCLRANDOM_ROUND_UP_TO_CPU_WORDSIZE(seedLen);
    MCUX_CSSL_FP_FUNCTION_CALL(result_memset, mcuxClMemory_set((uint8_t *)pAdditionalInput, 0,
                seedLen,
                seedLen));
    (void)result_memset;

    MCUX_CSSL_FP_FUNCTION_CALL(result_updatestate, mcuxClRandom_CtrDrbg_UpdateState(pSession, (uint8_t *)pAdditionalInput));
    if (MCUXCLRANDOM_STATUS_OK != result_updatestate)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_generateAlgorithm, MCUXCLRANDOM_STATUS_FAULT_ATTACK);
    }

    /* Increment the reseed counter */
    pRngCtx->reseedCounter += 1;

    pSession->cpuWa.used -= MCUXCLRANDOM_ROUND_UP_TO_CPU_WORDSIZE(seedLen);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_generateAlgorithm, MCUXCLRANDOM_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_CtrDrbg_generateOutput),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_CtrDrbg_UpdateState));
}

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandom_CtrDrbg_UpdateState)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_CtrDrbg_UpdateState(
    mcuxClSession_Handle_t pSession,
    uint8_t *pProvidedData
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_CtrDrbg_UpdateState);

    mcuxClRandom_Context_Generic_t *pCtx = (mcuxClRandom_Context_Generic_t *) pSession->randomCfg.ctx;
    mcuxClRandom_Mode_t pMode = pSession->randomCfg.mode;
    uint32_t seedLen = pMode->pDrbgMode->pDrbgVariant->seedLen;
    uint32_t securityStrength = pMode->securityStrength;

    uint8_t *pState = (uint8_t *)((mcuxClRandom_Context_CtrDrbg_Aes128_t *) pCtx)->key;
    uint8_t *pKey = (uint8_t *)pState;
    uint8_t *pV = &pState[securityStrength/8u];

    /* produce the new Key and V */
    uint32_t *pNewKV = (uint32_t *)&pSession->cpuWa.buffer[pSession->cpuWa.used];
    pSession->cpuWa.used += MCUXCLRANDOM_ROUND_UP_TO_CPU_WORDSIZE(seedLen);

    uint32_t keyLenInBlkSize = securityStrength/8u/MCUX_CL_AES_BLOCK_SIZE;
    uint32_t i, j;

    for (i = 0; i < keyLenInBlkSize + 1; i++)
    {
        *(uint64_t *)pV += 1;
        MCUX_CSSL_FP_FUNCTION_CALL(ret_blockcipher, mcuxClRandom_DRBG_AES_Internal_blockcipher(pV, pKey,
                (uint8_t *)&pNewKV[(i * MCUX_CL_AES_BLOCK_SIZE_IN_WORDS)],
                securityStrength/8u));
        if (MCUXCLRANDOM_STATUS_OK != ret_blockcipher)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_UpdateState, MCUXCLRANDOM_STATUS_ERROR,
                (i + 1u) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_DRBG_AES_Internal_blockcipher));
        }
    }

    if (NULL != pProvidedData)
    {
        uint8_t *pNewKVByte = (uint8_t *)pNewKV;
        for (j = 0; j < (securityStrength/8u + MCUX_CL_AES_BLOCK_SIZE); j++)
        {
            pNewKVByte[j] = pNewKVByte[j] ^ pProvidedData[j];
        }
    }

    /* update the key V in context */
    MCUXCLMEMORY_FP_MEMORY_COPY((uint8_t *)pKey, (uint8_t const *)pNewKV,
                    securityStrength/8u + MCUX_CL_AES_BLOCK_SIZE);

    pSession->cpuWa.used -= MCUXCLRANDOM_ROUND_UP_TO_CPU_WORDSIZE(seedLen);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_UpdateState, MCUXCLRANDOM_STATUS_OK,
                i * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_DRBG_AES_Internal_blockcipher),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy));
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_CtrDrbg_generateOutput)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_CtrDrbg_generateOutput(
        mcuxClSession_Handle_t pSession,
        uint8_t *pOut, uint32_t outLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_CtrDrbg_generateOutput);

    mcuxClRandom_Context_Generic_t *pCtx = (mcuxClRandom_Context_Generic_t *) pSession->randomCfg.ctx;
    mcuxClRandom_Mode_t pMode = pSession->randomCfg.mode;
    uint32_t securityStrength = pMode->securityStrength;

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

    uint8_t *pState = (uint8_t *)((mcuxClRandom_Context_CtrDrbg_Aes128_t *) pCtx)->key;
    uint8_t *pKey = (uint8_t *)pState;
    uint8_t *pV = &pState[securityStrength/8u];
    uint32_t requestSizeRemainingBytes = outLength % MCUX_CL_AES_BLOCK_SIZE;
    uint32_t requestSizeFullWordsBytes = outLength - requestSizeRemainingBytes;
    uint32_t outIndex = 0;

    /* Request as many random bytes as possible with full word size. */
    while (requestSizeFullWordsBytes > 0u)
    {
        *(uint64_t *)pV += 1;
        MCUX_CSSL_FP_FUNCTION_CALL(ret_Internal_blockcipher,
                    mcuxClRandom_DRBG_AES_Internal_blockcipher(pV, pKey, &pOut[outIndex], securityStrength/8u));
        if (MCUXCLRANDOM_STATUS_OK != ret_Internal_blockcipher)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_generateOutput, MCUXCLRANDOM_STATUS_ERROR,
                (outIndex/MCUX_CL_AES_BLOCK_SIZE + 1u) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_DRBG_AES_Internal_blockcipher));
        }
        outIndex += MCUX_CL_AES_BLOCK_SIZE;
        requestSizeFullWordsBytes -= MCUX_CL_AES_BLOCK_SIZE;
    }

    /* If requested size is not a multiple of block size, request one (additional) block and use it only partially. */
    if (requestSizeRemainingBytes > 0u)
    {
        uint8_t requestRemainingBuffer[MCUX_CL_AES_BLOCK_SIZE] = {0u};

        *(uint64_t *)pV += 1;
        MCUX_CSSL_FP_FUNCTION_CALL(ret_Internal_blockcipher,
                mcuxClRandom_DRBG_AES_Internal_blockcipher(pV, pKey, requestRemainingBuffer, securityStrength/8u));
        if (MCUXCLRANDOM_STATUS_OK != ret_Internal_blockcipher)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_CtrDrbg_generateOutput, MCUXCLRANDOM_STATUS_ERROR,
                (outIndex/MCUX_CL_AES_BLOCK_SIZE + 1u) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_DRBG_AES_Internal_blockcipher));
        }

        /* Copy the remaining bytes from the buffer to output. */
        MCUXCLMEMORY_FP_MEMORY_COPY(&pOut[outIndex], requestRemainingBuffer, requestSizeRemainingBytes);

    }

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClRandom_CtrDrbg_generateOutput, MCUXCLRANDOM_STATUS_OK, MCUXCLRANDOM_STATUS_FAULT_ATTACK,
            MCUX_CSSL_FP_CONDITIONAL((requestSizeFullWordsBytes > 0u),
                (outIndex/MCUX_CL_AES_BLOCK_SIZE) * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_DRBG_AES_Internal_blockcipher)),
            MCUX_CSSL_FP_CONDITIONAL((requestSizeRemainingBytes > 0u),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_DRBG_AES_Internal_blockcipher))
            );
}
