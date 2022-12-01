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
 * @file  mcuxClEcc_EdDSA_GenerateKeyPair.c
 * @brief implementation of TwEd_EdDsaKeyGen function
 */


#include <stdint.h>

#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClKey.h>
#include <mcuxClPkc.h>
#include <mcuxClEcc.h>

#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_Internal_Random.h>
#include <internal/mcuxClEcc_EdDSA_Internal.h>
#include <internal/mcuxClEcc_EdDSA_Internal_Hash.h>
#include <internal/mcuxClEcc_EdDSA_GenerateKeyPair_FUP.h>


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_EdDSA_GenerateKeyPair)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_EdDSA_GenerateKeyPair(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Type_t type,
    mcuxClKey_Protection_t protection,
    const mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_t *mode,
    mcuxClKey_Handle_t privKey,
    uint8_t *pPrivData,
    uint32_t *const pPrivDataLength,
    mcuxClKey_Handle_t pubKey,
    uint8_t *pPubData,
    uint32_t *const pPubDataLength )
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_EdDSA_GenerateKeyPair);

    /* mcuxClEcc_CpuWa_t will be allocated and placed in the beginning of CPU workarea free space by SetupEnvironment. */
    mcuxClEcc_CpuWa_t * const pCpuWorkarea = (mcuxClEcc_CpuWa_t *) mcuxClSession_allocateWords_cpuWa(pSession, 0u);
    mcuxClEcc_EdDSA_DomainParams_t * const pDomainParams = (mcuxClEcc_EdDSA_DomainParams_t *) (type->info);

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(
        mcuxClEcc_EdDSA_SetupEnvironment(pSession,
                                        pDomainParams,
                                        ECC_EDDSA_NO_OF_BUFFERS) );

    /* private key length = M = 32-byte for Ed25519 (b = 256 = 32*8) */
    /*                       or 57-byte for Ed448 (b = 456 = 57*8).  */
    const uint32_t privKeyLength = (uint32_t) pDomainParams->b / 8u;
    uint8_t * pPrivKey = NULL;

    /* Generate or import private key d. */
    uint32_t options = mode->options;
    MCUX_CSSL_FP_BRANCH_DECL(privKeyOption);
    if (MCUXCLECC_EDDSA_PRIVKEY_GENERATE == options)
    {
        /* Reserve space on CPU workarea for the private key. */
        const uint32_t privKeyWords = MCUXCLECC_ALIGNED_SIZE(privKeyLength) / (sizeof(uint32_t));
        pPrivKey = (uint8_t *) mcuxClSession_allocateWords_cpuWa(pSession, privKeyWords);
        pCpuWorkarea->wordNumCpuWa += privKeyWords;

        MCUX_CSSL_FP_FUNCTION_CALL(retRandom,
            mcuxClRandom_generate(pSession, pPrivKey, privKeyLength) );

        if (MCUXCLRANDOM_STATUS_OK != retRandom)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_GenerateKeyPair,
                                      MCUXCLECC_STATUS_RNG_ERROR);
        }

        MCUX_CSSL_FP_BRANCH_POSITIVE(privKeyOption,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate) );
    }
    else if (MCUXCLECC_EDDSA_PRIVKEY_INPUT == options)
    {
        pPrivKey = (uint8_t *) pPrivData;

        MCUX_CSSL_FP_BRANCH_NEGATIVE(privKeyOption);
    }
    else
    {
        /* invalid option */
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_GenerateKeyPair,
                                  MCUXCLECC_STATUS_FAULT_ATTACK);
    }

    /* The 2b-bit private key hash will be stored in PKC workarea, such that  */
    /* the second half (bits b ~ 2b-1) is at the beginning of PKC operand S3. */
    uint16_t *pOperands = MCUXCLPKC_GETUPTRT();
    uint8_t *pS3 = MCUXCLPKC_OFFSET2PTR(pOperands[ECC_S3]);
    uint8_t *pPrivKeyHashPkc = pS3 - privKeyLength;

    /* Calculate 2b-bit hash of private key. */
    MCUXCLECC_FP_EDDSA_KEYGEN_HASH_PRIVKEY(pSession,
                                          pDomainParams->algoHash,
                                          pPrivKey, pPrivKeyHashPkc,
                                          privKeyLength);

    /* Prepare s in PKC operand S2. */
    /* The bits 0~(b-1) of private key hash is placed before and adjacent to PKC operand S3. */
    const uint32_t b = pDomainParams->b;  /* = 256 (Ed25519); 456 (Ed448) */
    const uint32_t c = pDomainParams->c;  /* =   3 (Ed25519);   2 (Ed448) */
    const uint32_t t = pDomainParams->t;  /* = 254 (Ed25519); 447 (Ed448) */
    const uint32_t offsetS3 = (uint32_t) pOperands[ECC_S3];
    /* V0 = PKC operand containing the first half of private key hash.       */
    /* V1 = V0 for Ed25519 (64/128-bit PkcWord) and Ed448 (128-bit PkcWord); */
    /*    = V0 + 64-bit for Ed448 (64-bit PkcWord).                          */
    /* ps, PKC will ignore non-aligned part of offsets.                      */
    pOperands[TWED_V0] = (uint16_t) (offsetS3 - (b/8u));
    pOperands[TWED_V1] = (uint16_t) (offsetS3 - (t/8u));
    /* V2/V3/V4 are shift/rotate amounts used in FUP program below. */
    /* V2 = 2 (Ed25519); 9 (Ed448). */
    /* V3 = -252 \equiv  4 (Ed25519);                */
    /*      -446 \equiv  2 (Ed448, 64-bit PkcWord)   */
    /*               or 66 (Ed448, 128-bit PkcWord). */
    pOperands[TWED_V2] = (uint16_t) (b - t);
    pOperands[TWED_V3] = (uint16_t) (c - 1u - t);
    pOperands[TWED_V4] = (uint16_t) c;
    uint32_t privKeyLengthPkc = MCUXCLPKC_ROUNDUP_SIZE(privKeyLength);
    MCUXCLPKC_PS2_SETLENGTH(0u, privKeyLengthPkc);
    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_EdDSA_GenerateKeyPair_Prepare_S,
                        mcuxClEcc_FUP_EdDSA_GenerateKeyPair_Prepare_S_LEN);



    (void)protection;
    (void)privKey;
    (void)pPrivData;
    (void)pPrivDataLength;
    (void)pubKey;
    (void)pPubData;
    (void)pPubDataLength;

    MCUXCLPKC_FP_DEINITIALIZE(&pCpuWorkarea->pkcStateBackup);
    mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
    mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClEcc_EdDSA_GenerateKeyPair,
                                         MCUXCLECC_STATUS_OK, MCUXCLECC_STATUS_FAULT_ATTACK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_SetupEnvironment),
        MCUX_CSSL_FP_BRANCH_TAKEN_POSITIVE(privKeyOption, MCUXCLECC_EDDSA_PRIVKEY_GENERATE == options),
        MCUX_CSSL_FP_BRANCH_TAKEN_NEGATIVE(privKeyOption, MCUXCLECC_EDDSA_PRIVKEY_INPUT == options),
        MCUXCLECC_FP_CALLED_EDDSA_KEYGEN_HASH_PRIVKEY,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),

        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_Deinitialize) );
}
