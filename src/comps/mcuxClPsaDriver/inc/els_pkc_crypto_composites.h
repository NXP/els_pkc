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

#ifndef ELS_PKC_CRYPTO_COMPOSITES_H
#define ELS_PKC_CRYPTO_COMPOSITES_H

/** \file els_pkc_crypto_composites.h
 *
 * This file contains the declaration of the context structures related
 * to the els_pkc driver
 *
 */

/* Include CLNS header files */
#include <mcuxClPsaDriver_MemoryConsumption.h>
#include <mcuxClKey.h>
#include <mcuxClMac.h>
#include <mcuxClMacModes.h>
#include <mcuxClAead.h>

typedef struct {
    uint32_t clns_data[MCUXCLPSADRIVER_CLNSDATA_MAC_SIZE / sizeof(uint32_t)];
} els_pkc_transparent_mac_operation_t,els_pkc_opaque_mac_operation_t,els_pkc_mac_operation_t;

#define ELS_PKC_PSA_MAC_OPERATION_INIT { .clns_data={ 0u } }

typedef struct {
    uint32_t clns_data[MCUXCLPSADRIVER_CLNSDATA_AEAD_SIZE / sizeof(uint32_t)];

    psa_algorithm_t alg;
    psa_key_type_t key_type;
    uint8_t is_encrypt;
    uint8_t tag_length;

    uint32_t body_started;
    uint32_t ad_remaining;
    uint32_t body_remaining;
    uint32_t nonce_set;

} els_pkc_transparent_aead_operation_t,els_pkc_opaque_aead_operation_t,els_pkc_aead_operation_t;

#define ELS_PKC_PSA_AEAD_OPERATION_INIT { .clns_data={ 0u }, .alg=0u, .key_type=0u, .is_encrypt=0u, .tag_length=0u, .body_started=0u, .ad_remaining=0u, .body_remaining=0u, .nonce_set=0u }

#endif /* ELS_PKC_CRYPTO_COMPOSITES_H */
