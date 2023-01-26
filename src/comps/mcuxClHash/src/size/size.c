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

#include <stdint.h>
#include <internal/mcuxClHash_Internal_Memory.h>
#include <internal/mcuxClHash_Internal.h>

/* Hash Cpu Workarea size generation */
volatile uint8_t mcuxClHash_compute_WaCpuMd5 [MCUXCLHASH_INTERNAL_WACPU_SIZE_MD5];
volatile uint8_t mcuxClHash_compute_WaCpuSha1 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA1];
volatile uint8_t mcuxClHash_compute_WaCpuSha2_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_224];
volatile uint8_t mcuxClHash_compute_WaCpuSha2_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_256];
volatile uint8_t mcuxClHash_compute_WaCpuSha2_384 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_384];
volatile uint8_t mcuxClHash_compute_WaCpuSha2_512 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512];
volatile uint8_t mcuxClHash_compute_WaCpuMax [MCUXCLHASH_INTERNAL_WACPU_MAX];

volatile uint8_t mcuxClHash_finish_WaCpuMd5 [MCUXCLHASH_INTERNAL_WACPU_SIZE_MD5];
volatile uint8_t mcuxClHash_finish_WaCpuSha1 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA1];
volatile uint8_t mcuxClHash_finish_WaCpuSha2_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_224];
volatile uint8_t mcuxClHash_finish_WaCpuSha2_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_256];
volatile uint8_t mcuxClHash_finish_WaCpuSha2_384 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_384];
volatile uint8_t mcuxClHash_finish_WaCpuSha2_512 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512];
volatile uint8_t mcuxClHash_finish_WaCpuMax [MCUXCLHASH_INTERNAL_WACPU_MAX];

/* Hash multi-part context size generation */
volatile mcuxClHash_ContextDescriptor_t mcuxClHash_Ctx_size;
