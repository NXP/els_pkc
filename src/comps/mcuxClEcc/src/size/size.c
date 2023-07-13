/*--------------------------------------------------------------------------*/
/* Copyright 2021-2023 NXP                                                  */
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

#include <mcuxClCore_Platform.h>
#include <mcuxCsslAnalysis.h>

#include <mcuxClPkc_Types.h>

#include <internal/mcuxClHash_Internal_Memory.h>
#include <internal/mcuxClRandomModes_Internal_SizeDefinitions.h>

#include <mcuxClEcc_ParameterSizes.h>
#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_Weier_Internal.h>
#include <internal/mcuxClEcc_WeierECC_Internal_GenerateDomainParams.h>

#define SIZEOF_ECCCPUWA_T  (MCUXCLECC_ALIGNED_SIZE(sizeof(mcuxClEcc_CpuWa_t)))
#define MCUXCLECC_MAX(value0, value1)  (((value0) > (value1)) ? (value0) : (value1))

/**
 * @brief Helper macro to calculate size aligned to PKC word.
 */
#define MCUXCLECC_ALIGN_SIZE_PKC(size)  ((((size) + MCUXCLPKC_WORDSIZE - 1u) / MCUXCLPKC_WORDSIZE) * MCUXCLPKC_WORDSIZE)

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile uint8_t mcuxClEcc_Weier_KeyGen_WaCPU_SIZE   [SIZEOF_ECCCPUWA_T + MCUXCLECC_ALIGNED_SIZE(sizeof(uint16_t) * (ECC_KEYGEN_NO_OF_BUFFERS    + ECC_KEYGEN_NO_OF_VIRTUALS)) + MCUXCLECC_ALIGNED_SIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)];
volatile uint8_t mcuxClEcc_Weier_Sign_WaCPU_SIZE     [SIZEOF_ECCCPUWA_T + MCUXCLECC_ALIGNED_SIZE(sizeof(uint16_t) * (ECC_SIGN_NO_OF_BUFFERS      + ECC_SIGN_NO_OF_VIRTUALS)) + MCUXCLECC_ALIGNED_SIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)];
volatile uint8_t mcuxClEcc_Weier_Verify_WaCPU_SIZE   [SIZEOF_ECCCPUWA_T + MCUXCLECC_ALIGNED_SIZE(sizeof(uint16_t) * (ECC_VERIFY_NO_OF_BUFFERS    + ECC_VERIFY_NO_OF_VIRTUALS)) + MCUXCLECC_ALIGNED_SIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)];
volatile uint8_t mcuxClEcc_Weier_PointMult_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + MCUXCLECC_ALIGNED_SIZE(sizeof(uint16_t) * (ECC_POINTMULT_NO_OF_BUFFERS + ECC_POINTMULT_NO_OF_VIRTUALS)) + MCUXCLECC_ALIGNED_SIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)];
volatile uint8_t mcuxClEcc_WeierECC_GenerateDomainParams_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + MCUXCLECC_ALIGNED_SIZE(sizeof(uint16_t) * (ECC_GENERATEDOMAINPARAMS_NO_OF_BUFFERS + ECC_GENERATEDOMAINPARAMS_NO_OF_VIRTUALS))];



volatile uint8_t mcuxClEcc_PKC_wordsize[MCUXCLPKC_WORDSIZE];

volatile uint8_t mcuxClEcc_KeyGen_WaPKC_NoOfBuffers   [ECC_KEYGEN_NO_OF_BUFFERS];
volatile uint8_t mcuxClEcc_Sign_WaPKC_NoOfBuffers     [ECC_SIGN_NO_OF_BUFFERS];
volatile uint8_t mcuxClEcc_Verify_WaPKC_NoOfBuffers   [ECC_VERIFY_NO_OF_BUFFERS];
volatile uint8_t mcuxClEcc_PointMult_WaPKC_NoOfBuffers[ECC_POINTMULT_NO_OF_BUFFERS];
volatile uint8_t mcuxClEcc_WeierECC_GenerateDomainParams_WaPKC_NoOfBuffers[ECC_GENERATEDOMAINPARAMS_NO_OF_BUFFERS];

volatile uint8_t mcuxClEcc_WeierECC_CustomDomainParamsSize_Fixed   [MCUXCLECC_CUSTOMPARAMS_SIZE_FIXED];
volatile uint8_t mcuxClEcc_WeierECC_CustomDomainParamsSize_NoOfPLen[MCUXCLECC_CUSTOMPARAMS_SIZE_NO_OF_PLEN];
volatile uint8_t mcuxClEcc_WeierECC_CustomDomainParamsSize_NoOfNLen[MCUXCLECC_CUSTOMPARAMS_SIZE_NO_OF_NLEN];




volatile uint8_t mcuxClEcc_Weierecc_GenerateDomainParams_WaPKC_Size_128 [(ECC_GENERATEDOMAINPARAMS_NO_OF_BUFFERS) * (MCUXCLECC_ALIGN_SIZE_PKC(16) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_Weierecc_GenerateDomainParams_WaPKC_Size_256 [(ECC_GENERATEDOMAINPARAMS_NO_OF_BUFFERS) * (MCUXCLECC_ALIGN_SIZE_PKC(32) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_Weierecc_GenerateDomainParams_WaPKC_Size_384 [(ECC_GENERATEDOMAINPARAMS_NO_OF_BUFFERS) * (MCUXCLECC_ALIGN_SIZE_PKC(48) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_Weierecc_GenerateDomainParams_WaPKC_Size_512 [(ECC_GENERATEDOMAINPARAMS_NO_OF_BUFFERS) * (MCUXCLECC_ALIGN_SIZE_PKC(64) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_Weierecc_GenerateDomainParams_WaPKC_Size_640 [(ECC_GENERATEDOMAINPARAMS_NO_OF_BUFFERS) * (MCUXCLECC_ALIGN_SIZE_PKC(80) + MCUXCLPKC_WORDSIZE)];




MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()


#include <internal/mcuxClEcc_Mont_Internal_PkcWaLayout.h>

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
#ifdef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
volatile uint8_t mcuxClEcc_Mont_DhKeyGeneration_Curve25519_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + MCUXCLECC_ALIGNED_SIZE(sizeof(uint16_t) * (ECC_MONTDH_NO_OF_BUFFERS + ECC_MONTDH_NO_OF_VIRTUALS)) + MCUXCLECC_MONT_CURVE25519_SIZE_BASEPOINTORDER + MCUXCLECC_ALIGNED_SIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)];
volatile uint8_t mcuxClEcc_Mont_DhKeyGeneration_Curve448_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + MCUXCLECC_ALIGNED_SIZE(sizeof(uint16_t) * (ECC_MONTDH_NO_OF_BUFFERS + ECC_MONTDH_NO_OF_VIRTUALS)) + MCUXCLECC_MONT_CURVE448_SIZE_BASEPOINTORDER + MCUXCLECC_ALIGNED_SIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)];
#else
volatile uint8_t mcuxClEcc_Mont_DhKeyGeneration_Curve25519_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + MCUXCLECC_ALIGNED_SIZE(sizeof(uint16_t) * (ECC_MONTDH_NO_OF_BUFFERS + ECC_MONTDH_NO_OF_VIRTUALS)) + MCUXCLECC_ALIGNED_SIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)];
volatile uint8_t mcuxClEcc_Mont_DhKeyGeneration_Curve448_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + MCUXCLECC_ALIGNED_SIZE(sizeof(uint16_t) * (ECC_MONTDH_NO_OF_BUFFERS + ECC_MONTDH_NO_OF_VIRTUALS)) + MCUXCLECC_ALIGNED_SIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)];
#endif /* MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND */
volatile uint8_t mcuxClEcc_Mont_DhKeyAgreement_Curve25519_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + MCUXCLECC_ALIGNED_SIZE(sizeof(uint16_t) * (ECC_MONTDH_NO_OF_BUFFERS + ECC_MONTDH_NO_OF_VIRTUALS))];
volatile uint8_t mcuxClEcc_Mont_DhKeyAgreement_Curve448_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + MCUXCLECC_ALIGNED_SIZE(sizeof(uint16_t) * (ECC_MONTDH_NO_OF_BUFFERS + ECC_MONTDH_NO_OF_VIRTUALS))];
volatile uint8_t mcuxClEcc_Mont_DhKeyGeneration_Curve25519_WaPKC_SIZE[ECC_MONTDH_NO_OF_BUFFERS * (MCUXCLPKC_ROUNDUP_SIZE(MCUXCLECC_MONT_CURVE25519_SIZE_PRIMEP) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_Mont_DhKeyGeneration_Curve448_WaPKC_SIZE[ECC_MONTDH_NO_OF_BUFFERS * (MCUXCLPKC_ROUNDUP_SIZE(MCUXCLECC_MONT_CURVE448_SIZE_PRIMEP) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_Mont_DhKeyAgreement_Curve25519_WaPKC_SIZE[ECC_MONTDH_NO_OF_BUFFERS * (MCUXCLPKC_ROUNDUP_SIZE(MCUXCLECC_MONT_CURVE25519_SIZE_PRIMEP) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_Mont_DhKeyAgreement_Curve448_WaPKC_SIZE[ECC_MONTDH_NO_OF_BUFFERS * (MCUXCLPKC_ROUNDUP_SIZE(MCUXCLECC_MONT_CURVE448_SIZE_PRIMEP) + MCUXCLPKC_WORDSIZE)];
MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()

#include <internal/mcuxClEcc_EdDSA_Internal.h>
#include <internal/mcuxClEcc_EdDSA_Internal_Hash.h>
#include <internal/mcuxClEcc_EdDSA_Internal_PkcWaLayout.h>
#include <internal/mcuxClHash_Internal.h>


#define SIZEOF_EDDSA_UPTRT  MCUXCLECC_ALIGNED_SIZE((sizeof(uint16_t)) * (ECC_EDDSA_NO_OF_VIRTUALS + ECC_EDDSA_NO_OF_BUFFERS))

MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
volatile uint8_t mcuxClEcc_EdDSA_GenerateKeyPair_Ed25519_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + SIZEOF_EDDSA_UPTRT
                                                                   + MCUXCLECC_ALIGNED_SIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)
                                                                   + MCUXCLECC_ALIGNED_SIZE(MCUXCLECC_EDDSA_ED25519_SIZE_PRIVATEKEY)
                                                                   + MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512];
volatile uint8_t mcuxClEcc_EdDSA_GenerateKeyPair_Ed448_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + SIZEOF_EDDSA_UPTRT
                                                                 + MCUXCLECC_ALIGNED_SIZE(MCUXCLRANDOMMODES_CPUWA_MAXSIZE)
                                                                 + MCUXCLECC_ALIGNED_SIZE(MCUXCLECC_EDDSA_ED448_SIZE_PRIVATEKEY)
                                                                 + 0u /* TODO: Add hash CPU workarea size (CLNS-4207) */];
volatile uint8_t mcuxClEcc_EdDSA_GenerateSignature_Ed25519_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + SIZEOF_EDDSA_UPTRT
                                                                     + MCUXCLECC_ALIGNED_SIZE(sizeof(mcuxClHash_ContextDescriptor_t))
                                                                     + MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512];
volatile uint8_t mcuxClEcc_EdDSA_GenerateSignature_Ed448_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + SIZEOF_EDDSA_UPTRT
                                                                   + MCUXCLECC_ALIGNED_SIZE(sizeof(mcuxClHash_ContextDescriptor_t))
                                                                   + 0u /* TODO: Add hash CPU workarea size (CLNS-4207) */];
volatile uint8_t mcuxClEcc_EdDSA_VerifySignature_Ed25519_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + SIZEOF_EDDSA_UPTRT
                                                                     + MCUXCLECC_ALIGNED_SIZE(sizeof(mcuxClHash_ContextDescriptor_t))
                                                                     + MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512];
volatile uint8_t mcuxClEcc_EdDSA_VerifySignature_Ed448_WaCPU_SIZE[SIZEOF_ECCCPUWA_T + SIZEOF_EDDSA_UPTRT
                                                                     + MCUXCLECC_ALIGNED_SIZE(sizeof(mcuxClHash_ContextDescriptor_t))
                                                                     + 0u]; /* TODO: Add hash CPU workarea size (CLNS-4207) */

/* byteLenP = byteLenN in both Ed25519 and Ed448. */
volatile uint8_t mcuxClEcc_EdDSA_GenerateKeyPair_Ed25519_WaPKC_SIZE[ECC_EDDSA_NO_OF_BUFFERS * (MCUXCLPKC_ROUNDUP_SIZE(MCUXCLECC_EDDSA_ED25519_SIZE_PRIMEP) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_EdDSA_GenerateKeyPair_Ed448_WaPKC_SIZE[ECC_EDDSA_NO_OF_BUFFERS * (MCUXCLPKC_ROUNDUP_SIZE(MCUXCLECC_EDDSA_ED448_SIZE_PRIMEP) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_EdDSA_GenerateSignature_Ed25519_WaPKC_SIZE[ECC_EDDSA_NO_OF_BUFFERS * (MCUXCLPKC_ROUNDUP_SIZE(MCUXCLECC_EDDSA_ED25519_SIZE_PRIMEP) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_EdDSA_GenerateSignature_Ed448_WaPKC_SIZE[ECC_EDDSA_NO_OF_BUFFERS * (MCUXCLPKC_ROUNDUP_SIZE(MCUXCLECC_EDDSA_ED448_SIZE_PRIMEP) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_EdDSA_VerifySignature_Ed25519_WaPKC_SIZE[ECC_EDDSA_NO_OF_BUFFERS * (MCUXCLPKC_ROUNDUP_SIZE(MCUXCLECC_EDDSA_ED25519_SIZE_PRIMEP) + MCUXCLPKC_WORDSIZE)];
volatile uint8_t mcuxClEcc_EdDSA_VerifySignature_Ed448_WaPKC_SIZE[ECC_EDDSA_NO_OF_BUFFERS * (MCUXCLPKC_ROUNDUP_SIZE(MCUXCLECC_EDDSA_ED448_SIZE_PRIMEP) + MCUXCLPKC_WORDSIZE)];

/* EdDSA key pair generation descriptor size */
volatile uint8_t mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_SIZE[MCUXCLECC_ALIGNED_SIZE(sizeof(mcuxClEcc_EdDSA_GenerateKeyPairDescriptor_t))];

/* EdDSA signature mode generation descriptor size */
volatile uint8_t mcuxClEcc_EdDSA_SignatureProtocolDescriptor_SIZE[MCUXCLECC_ALIGNED_SIZE(sizeof(mcuxClEcc_EdDSA_SignatureProtocolDescriptor_t))];


MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
