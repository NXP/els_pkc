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
 * @file  mcuxClEcc_EdDSA_Internal_Hash.h
 * @brief internal header for abstracting hash calls in mcuxClEcc EdDSA
 */


#ifndef MCUXCLECC_EDDSA_INTERNAL_HASH_H_
#define MCUXCLECC_EDDSA_INTERNAL_HASH_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClHash_Types.h>
#include <mcuxClHash_Functions.h>
#include <mcuxClHash_Constants.h>
#include <internal/mcuxClSession_Internal.h>


/******************************************************************************/
/* Macro to compute private key hash and store it in PKC workarea.            */
/* Since the parameter b of both Ed25519 and Ed448 is a multiple of 8,        */
/* byte length of private key hash (= 2b/8) can be derived from               */
/* byte length of private key (= b/8).                                        */
/******************************************************************************/
#if defined(MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND)
#include <mcuxClMemory_Copy.h>
#define MCUXCLECC_FP_EDDSA_KEYGEN_HASH_PRIVKEY(pSession, hashAlg, pPrivKey, pPrivKeyHash, privKeyLen)  \
    do{                                                                \
        const uint32_t privKeyHashLength = 2u * (privKeyLen);          \
        const uint32_t privKeyHashWord = MCUXCLECC_ALIGNED_SIZE(privKeyHashLength) / (sizeof(uint32_t));  \
        uint8_t *pTemp = (uint8_t *) mcuxClSession_allocateWords_cpuWa(pSession, privKeyHashWord);        \
        if (NULL == pTemp)                                             \
        {                                                              \
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_GenerateKeyPair,  \
                                      MCUXCLECC_STATUS_FAULT_ATTACK);   \
        }                                                              \
        uint32_t outLength = 0u;                                       \
        MCUX_CSSL_FP_FUNCTION_CALL(retHash,                             \
            mcuxClHash_compute(pSession,                                \
                              hashAlg,                                 \
                              (mcuxCl_InputBuffer_t) (pPrivKey),        \
                              privKeyLen,                              \
                              (mcuxCl_Buffer_t) pTemp,                  \
                              &outLength) );                           \
        if (MCUXCLHASH_STATUS_OK != retHash)                            \
        {                                                              \
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_GenerateKeyPair,  \
                                      MCUXCLECC_STATUS_FAULT_ATTACK);   \
        }                                                              \
        MCUXCLPKC_WAITFORFINISH();                                      \
        MCUX_CSSL_FP_FUNCTION_CALL(retMemCpy,                                                \
            mcuxClMemory_copy(pPrivKeyHash, pTemp, privKeyHashLength, privKeyHashLength) );  \
        if (0u != retMemCpy)                                           \
        {                                                              \
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_GenerateKeyPair,  \
                                      MCUXCLECC_STATUS_FAULT_ATTACK);   \
        }                                                              \
        mcuxClSession_freeWords_cpuWa(pSession, privKeyHashWord);       \
    } while(false)

#define MCUXCLECC_FP_CALLED_EDDSA_KEYGEN_HASH_PRIVKEY  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute),   \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy)

#define MCUXCLECC_EDDSA_GENKEYPAIR_HASHOUTPUT_CPUWA(hashOutputLength)    MCUXCLECC_ALIGNED_SIZE(hashOutputLength)
#else  /* !MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND */
#define MCUXCLECC_FP_EDDSA_KEYGEN_HASH_PRIVKEY(pSession, hashAlg, pPrivKey, pPrivKeyHash, privKeyLen)  \
    do{                                                                \
        uint32_t outLength = 0u;                                       \
        MCUXCLPKC_WAITFORFINISH();                                      \
        MCUX_CSSL_FP_FUNCTION_CALL(retHash,                             \
            mcuxClHash_compute(pSession,                                \
                              hashAlg,                                 \
                              (mcuxCl_InputBuffer_t) (pPrivKey),        \
                              privKeyLen,                              \
                              (mcuxCl_Buffer_t) (pPrivKeyHash),         \
                              &outLength) );                           \
        if (MCUXCLHASH_STATUS_OK != retHash)                            \
        {                                                              \
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_GenerateKeyPair,  \
                                      MCUXCLECC_STATUS_FAULT_ATTACK);   \
        }                                                              \
    } while(false)

#define MCUXCLECC_FP_CALLED_EDDSA_KEYGEN_HASH_PRIVKEY  \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute)

#define MCUXCLECC_EDDSA_GENKEYPAIR_HASHOUTPUT_CPUWA(hashOutputLength)    0u
#endif /* MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND */


#endif /* MCUXCLECC_EDDSA_INTERNAL_HASH_H_ */
