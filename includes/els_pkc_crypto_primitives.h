/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
/*                                                                          */
/* SPDX-License-Identifier: BSD-3-Clause                                    */
/*                                                                          */
/* Redistribution and use in source and binary forms, with or without       */
/* modification, are permitted provided that the following conditions are   */
/* met:                                                                     */
/*                                                                          */
/* 1. Redistributions of source code must retain the above copyright        */
/*    notice, this list of conditions and the following disclaimer.         */
/*                                                                          */
/* 2. Redistributions in binary form must reproduce the above copyright     */
/*    notice, this list of conditions and the following disclaimer in the   */
/*    documentation and/or other materials provided with the distribution.  */
/*                                                                          */
/* 3. Neither the name of the copyright holder nor the names of its         */
/*    contributors may be used to endorse or promote products derived from  */
/*    this software without specific prior written permission.              */
/*                                                                          */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS  */
/* IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED    */
/* TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A          */
/* PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT       */
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,   */
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED */
/* TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR   */
/* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF   */
/* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS       */
/* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.             */
/*--------------------------------------------------------------------------*/

/*
 * Copyright 2023-2024 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ELS_PKC_CRYPTO_PRIMITIVES_H
#define ELS_PKC_CRYPTO_PRIMITIVES_H

/** \file els_pkc_crypto_primtives.h
 *
 * This file contains the declaration of the context structures related
 * to the els_pkc driver
 *
 */

/* Include CLNS header files */
#include <mcuxClPsaDriver_MemoryConsumption.h>
#include <mcuxClKey.h>
#include <mcuxClCipher.h>
#include <mcuxClCipherModes.h>
#include <mcuxClHash.h>

typedef struct {
    uint32_t clns_data[MCUXCLPSADRIVER_CLNSDATA_HASH_SIZE / sizeof(uint32_t)];
} els_pkc_hash_operation_t;

typedef struct {
    uint32_t clns_data[MCUXCLPSADRIVER_CLNSDATA_CIPHER_SIZE / sizeof(uint32_t)];

    uint16_t iv_required;
    uint16_t default_iv_length;
} els_pkc_transparent_cipher_operation_t,els_pkc_opaque_cipher_operation_t,els_pkc_cipher_operation_t;

#endif /* ELS_PKC_CRYPTO_PRIMITIVES_H */
