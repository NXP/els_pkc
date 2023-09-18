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

#include <mcuxCsslAnalysis.h>
#include <mcuxClCore_Platform.h>

#include <mcuxClHashModes_Constants.h> // hash output sizes
#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClHashModes_Internal_Memory.h>


MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()

/* Hash Cpu Workarea size generation */
volatile uint8_t mcuxClHash_compute_WaCpuMd5 [MCUXCLHASH_INTERNAL_WACPU_SIZE_MD5];
volatile uint8_t mcuxClHash_compute_WaCpuSha1 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA1];
volatile uint8_t mcuxClHash_compute_WaCpuSha2_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_224];
volatile uint8_t mcuxClHash_compute_WaCpuSha2_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_256];
volatile uint8_t mcuxClHash_compute_WaCpuSha2_384 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_384];
volatile uint8_t mcuxClHash_compute_WaCpuSha2_512 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512];
volatile uint8_t mcuxClHash_compute_WaCpuSha3 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA3];
volatile uint8_t mcuxClHash_compute_WaCpuSecSha1 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA_1];
volatile uint8_t mcuxClHash_compute_WaCpuSecSha2_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA2_224];
volatile uint8_t mcuxClHash_compute_WaCpuSecSha2_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA2_256];
volatile uint8_t mcuxClHash_compute_WaCpuSecSha2_384 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA2_384];
volatile uint8_t mcuxClHash_compute_WaCpuSecSha2_512 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA2_512];

volatile uint8_t mcuxClHash_finish_WaCpuMiyaguchiPreneel [MCUXCLHASH_INTERNAL_WACPU_SIZE_MIYAGUCHI_PRENEEL];
volatile uint8_t mcuxClHash_finish_WaCpuMd5 [MCUXCLHASH_INTERNAL_WACPU_SIZE_MD5];
volatile uint8_t mcuxClHash_finish_WaCpuSha1 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA1];
volatile uint8_t mcuxClHash_finish_WaCpuSha2_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_224];
volatile uint8_t mcuxClHash_finish_WaCpuSha2_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_256];
volatile uint8_t mcuxClHash_finish_WaCpuSha2_384 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_384];
volatile uint8_t mcuxClHash_finish_WaCpuSha2_512 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512];
volatile uint8_t mcuxClHash_finish_WaCpuSha3 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA3];
volatile uint8_t mcuxClHash_finish_WaCpuSecSha1 [4u];
volatile uint8_t mcuxClHash_finish_WaCpuSecSha2_224 [4u]; /* Not needed */
volatile uint8_t mcuxClHash_finish_WaCpuSecSha2_256 [4u];
volatile uint8_t mcuxClHash_finish_WaCpuSecSha2_384 [4u];
volatile uint8_t mcuxClHash_finish_WaCpuSecSha2_512 [4u];

/* Hash multipart context size generation */
volatile uint8_t mcuxClHash_Ctx_size_md5 [sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_BLOCK_SIZE_MD5 + MCUXCLHASH_STATE_SIZE_MD5];
volatile uint8_t mcuxClHash_Ctx_size_sha_1 [sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_BLOCK_SIZE_SHA_1 + MCUXCLHASH_STATE_SIZE_SHA_1];
volatile uint8_t mcuxClHash_Ctx_size_sha_256 [sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_BLOCK_SIZE_SHA_256 + MCUXCLHASH_STATE_SIZE_SHA_256];
volatile uint8_t mcuxClHash_Ctx_size_sha_512 [sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_BLOCK_SIZE_SHA_512 + MCUXCLHASH_STATE_SIZE_SHA_512];
volatile uint8_t mcuxClHash_Ctx_size_sha3_224 [sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_BLOCK_SIZE_SHA3_224 + MCUXCLHASH_STATE_SIZE_SHA3];
volatile uint8_t mcuxClHash_Ctx_size_sha3_256 [sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_BLOCK_SIZE_SHA3_256 + MCUXCLHASH_STATE_SIZE_SHA3];
volatile uint8_t mcuxClHash_Ctx_size_sha3_384 [sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_BLOCK_SIZE_SHA3_384 + MCUXCLHASH_STATE_SIZE_SHA3];
volatile uint8_t mcuxClHash_Ctx_size_sha3_512 [sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_BLOCK_SIZE_SHA3_512 + MCUXCLHASH_STATE_SIZE_SHA3];
volatile uint8_t mcuxClHash_Ctx_size_sha3_shake_128 [sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_BLOCK_SIZE_SHA3_SHAKE_128 + MCUXCLHASH_STATE_SIZE_SHA3];
volatile uint8_t mcuxClHash_Ctx_size_sha3_shake_256 [sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_BLOCK_SIZE_SHA3_SHAKE_256 + MCUXCLHASH_STATE_SIZE_SHA3];
volatile uint8_t mcuxClHash_Ctx_size_secsha_1 [sizeof(mcuxClHash_ContextDescriptor_t) + 2u * MCUXCLHASH_BLOCK_SIZE_SHA_1 + MCUXCLHASH_STATE_SIZE_SECSHA_1];
volatile uint8_t mcuxClHash_Ctx_size_secsha_256 [sizeof(mcuxClHash_ContextDescriptor_t) + 2u * MCUXCLHASH_BLOCK_SIZE_SHA_256 + MCUXCLHASH_STATE_SIZE_SECSHA_256];
volatile uint8_t mcuxClHash_Ctx_size_secsha_512 [sizeof(mcuxClHash_ContextDescriptor_t) + 2u * MCUXCLHASH_BLOCK_SIZE_SHA_512 + MCUXCLHASH_STATE_SIZE_SECSHA_512];
volatile uint8_t mcuxClHash_Ctx_size_secsha3_224 [sizeof(mcuxClHash_ContextDescriptor_t) + 2u * MCUXCLHASH_BLOCK_SIZE_SHA3_224 + MCUXCLHASH_STATE_SIZE_SECSHA3];
volatile uint8_t mcuxClHash_Ctx_size_secsha3_256 [sizeof(mcuxClHash_ContextDescriptor_t) + 2u * MCUXCLHASH_BLOCK_SIZE_SHA3_256 + MCUXCLHASH_STATE_SIZE_SECSHA3];
volatile uint8_t mcuxClHash_Ctx_size_secsha3_384 [sizeof(mcuxClHash_ContextDescriptor_t) + 2u * MCUXCLHASH_BLOCK_SIZE_SHA3_384 + MCUXCLHASH_STATE_SIZE_SECSHA3];
volatile uint8_t mcuxClHash_Ctx_size_secsha3_512 [sizeof(mcuxClHash_ContextDescriptor_t) + 2u * MCUXCLHASH_BLOCK_SIZE_SHA3_512 + MCUXCLHASH_STATE_SIZE_SECSHA3];

/* Hash multipart state export size generation */
volatile uint8_t mcuxClHash_export_import_size_md5 [MCUXCLHASH_STATE_SIZE_MD5 + MCUXCLHASH_COUNTER_SIZE_MD5];
volatile uint8_t mcuxClHash_export_import_size_sha_1 [MCUXCLHASH_STATE_SIZE_SHA_1 + MCUXCLHASH_COUNTER_SIZE_SHA_1];
volatile uint8_t mcuxClHash_export_import_size_sha_256 [MCUXCLHASH_STATE_SIZE_SHA_256 + MCUXCLHASH_COUNTER_SIZE_SHA_256];
volatile uint8_t mcuxClHash_export_import_size_sha_512 [MCUXCLHASH_STATE_SIZE_SHA_512 + MCUXCLHASH_COUNTER_SIZE_SHA_512];
volatile uint8_t mcuxClHash_export_import_size_sha3 [MCUXCLHASH_STATE_SIZE_SHA3 + MCUXCLHASH_COUNTER_SIZE_SHA3];
volatile uint8_t mcuxClHash_export_import_size_secsha_1 [MCUXCLHASH_STATE_SIZE_SECSHA_1 + MCUXCLHASH_COUNTER_SIZE_SHA_1];
volatile uint8_t mcuxClHash_export_import_size_secsha_256 [MCUXCLHASH_STATE_SIZE_SECSHA_256 + MCUXCLHASH_COUNTER_SIZE_SHA_256];
volatile uint8_t mcuxClHash_export_import_size_secsha_512 [MCUXCLHASH_STATE_SIZE_SECSHA_512 + MCUXCLHASH_COUNTER_SIZE_SHA_512];
volatile uint8_t mcuxClHash_export_import_size_secsha3 [MCUXCLHASH_STATE_SIZE_SECSHA3 + MCUXCLHASH_COUNTER_SIZE_SHA3];



MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
