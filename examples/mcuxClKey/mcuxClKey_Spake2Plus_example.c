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

/**
 * @example mcuxClKey_Spake2Plus_example.c
 * @brief   Example showing the SPAKE2+ Password-Authenticated Key Exchange protocol
 */

#include <mcuxClToolchain.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClSession.h>
#include <mcuxClBuffer.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxCsslFlowProtection.h>
#include <mcuxCsslDataIntegrity.h>
#include <mcuxCsslMemory.h>

#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_RNG_Helper.h>
#include <mcuxClExample_ELS_Helper.h>

#include <mcuxClPkc.h>
#include <mcuxClEcc.h>
#include <mcuxClMemory_Copy.h>
#include <mcuxClHash.h>                     // Interface to the entire mcuxClHash component
#include <mcuxClHashModes.h>
#include <mcuxClKey.h>
#include <mcuxClHmac.h>

/* Testvector - Inputs */

/* Protocol Context */
static const ALIGNED uint8_t testvec_p256_context[56] =
    "SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors";

/* Parameter M (Decompressed in Preprocessing) */
static const ALIGNED uint8_t testvec_p256_M[64] = {
    0x88U, 0x6eU, 0x2fU, 0x97U, 0xacU, 0xe4U, 0x6eU, 0x55U,
    0xbaU, 0x9dU, 0xd7U, 0x24U,	0x25U, 0x79U, 0xf2U, 0x99U,
    0x3bU, 0x64U, 0xe1U, 0x6eU,	0xf3U, 0xdcU, 0xabU, 0x95U,
    0xafU, 0xd4U, 0x97U, 0x33U, 0x3dU, 0x8fU, 0xa1U, 0x2fU,
    0x5fU, 0xf3U, 0x55U, 0x16U, 0x3eU, 0x43U, 0xceU, 0x22U,
    0x4eU, 0x0bU, 0x0eU, 0x65U, 0xffU, 0x02U, 0xacU, 0x8eU,
    0x5cU, 0x7bU, 0xe0U, 0x94U, 0x19U, 0xc7U, 0x85U, 0xe0U,
    0xcaU, 0x54U, 0x7dU, 0x55U,	0xa1U, 0x2eU, 0x2dU, 0x20U
};

/* Parameter N (Decompressed in Preprocessing)*/
static const ALIGNED uint8_t testvec_p256_N[64] = {
    0xd8U, 0xbbU, 0xd6U, 0xc6U, 0x39U, 0xc6U, 0x29U, 0x37U,
    0xb0U, 0x4dU, 0x99U, 0x7fU,	0x38U, 0xc3U, 0x77U, 0x07U,
    0x19U, 0xc6U, 0x29U, 0xd7U, 0x01U, 0x4dU, 0x49U, 0xa2U,
    0x4bU, 0x4fU, 0x98U, 0xbaU,	0xa1U, 0x29U, 0x2bU, 0x49U,
    0x07U, 0xd6U, 0x0aU, 0xa6U, 0xbfU, 0xadU, 0xe4U, 0x50U,
    0x08U, 0xa6U, 0x36U, 0x33U, 0x7fU, 0x51U, 0x68U, 0xc6U,
    0x4dU, 0x9bU, 0xd3U, 0x60U,	0x34U, 0x80U, 0x8cU, 0xd5U,
    0x64U, 0x49U, 0x0bU, 0x1eU,	0x65U, 0x6eU, 0xdbU, 0xe7U
};

static const ALIGNED uint8_t testvec_p256_idProver[6] = {
    0x63U, 0x6cU, 0x69U, 0x65U, 0x6eU, 0x74U    /* b'client' */
};

static const ALIGNED uint8_t testvec_p256_idVerifier[6] = {
    0x73U, 0x65U, 0x72U, 0x76U, 0x65U, 0x72U    /* b'server' */
};

/* Parameter w0*/
static const ALIGNED uint8_t testvec_p256_w0[32] = {
    0xbbU, 0x8eU, 0x1bU, 0xbcU, 0xf3U, 0xc4U, 0x8fU, 0x62U,
    0xc0U, 0x8dU, 0xb2U, 0x43U, 0x65U, 0x2aU, 0xe5U, 0x5dU,
    0x3eU, 0x55U, 0x86U, 0x05U, 0x3fU, 0xcaU, 0x77U, 0x10U,
    0x29U, 0x94U, 0xf2U, 0x3aU, 0xd9U, 0x54U, 0x91U, 0xb3U
};

/* Parameter w1 */
static const ALIGNED uint8_t testvec_p256_w1[32] = {
    0x7eU, 0x94U, 0x5fU, 0x34U, 0xd7U, 0x87U, 0x85U, 0xb8U,
    0xa3U, 0xefU, 0x44U, 0xd0U, 0xdfU, 0x5aU, 0x1aU, 0x97U,
    0xd6U, 0xb3U, 0xb4U, 0x60U, 0x40U, 0x9aU, 0x34U, 0x5cU,
    0xa7U, 0x83U, 0x03U, 0x87U, 0xa7U, 0x4bU, 0x1dU, 0xbaU
};

/* Random Parameter x */
static const ALIGNED uint8_t testvec_p256_x[32] = {
    0xd1U, 0x23U, 0x2cU, 0x8eU, 0x86U, 0x93U, 0xd0U, 0x23U,
    0x68U, 0x97U, 0x6cU, 0x17U, 0x4eU, 0x20U, 0x88U, 0x85U,
    0x1bU, 0x83U, 0x65U, 0xd0U, 0xd7U, 0x9aU, 0x9eU, 0xeeU,
    0x70U, 0x9cU, 0x6aU, 0x05U, 0xa2U, 0xfaU, 0xd5U, 0x39U
};

/* Random Parameter y */
static const ALIGNED uint8_t testvec_p256_y[32] = {
    0x71U, 0x7aU, 0x72U, 0x34U, 0x8aU, 0x18U, 0x20U, 0x85U,
    0x10U, 0x9cU, 0x8dU, 0x39U, 0x17U, 0xd6U, 0xc4U, 0x3dU,
    0x59U, 0xb2U, 0x24U, 0xdcU, 0x6aU, 0x7fU, 0xc4U, 0xf0U,
    0x48U, 0x32U, 0x32U, 0xfaU, 0x65U, 0x16U, 0xd8U, 0xb3U
};

static const ALIGNED char fixedInfoConfirm[16] = "ConfirmationKeys";
static const ALIGNED char fixedInfoShare[9]    = "SharedKey";

/* Testvector - Expected Results */

static const ALIGNED uint8_t testvec_p256_L[64] = {
    0xebU, 0x7cU, 0x9dU, 0xb3U, 0xd9U, 0xa9U, 0xebU, 0x1fU,
    0x8aU, 0xdaU, 0xb8U, 0x1bU, 0x57U, 0x94U, 0xc1U, 0xf1U,
    0x3aU, 0xe3U, 0xe2U, 0x25U, 0xefU, 0xbeU, 0x91U, 0xeaU,
    0x48U, 0x74U, 0x25U, 0x85U, 0x4cU, 0x7fU, 0xc0U, 0x0fU,
    0x00U, 0xbfU, 0xedU, 0xcbU, 0xd0U, 0x9bU, 0x24U, 0x00U,
    0x14U, 0x2dU, 0x40U, 0xa1U, 0x4fU, 0x20U, 0x64U, 0xefU,
    0x31U, 0xdfU, 0xaaU, 0x90U, 0x3bU, 0x91U, 0xd1U, 0xfaU,
    0xeaU, 0x70U, 0x93U, 0xd8U, 0x35U, 0x96U, 0x6eU, 0xfdU
};

static const ALIGNED uint8_t testvec_p256_shareP[64] = {
    0xefU, 0x3bU, 0xd0U, 0x51U, 0xbfU, 0x78U, 0xa2U, 0x23U,
    0x4eU, 0xc0U, 0xdfU, 0x19U, 0x7fU, 0x78U, 0x28U, 0x06U,
    0x0fU, 0xe9U, 0x85U, 0x65U, 0x03U, 0x57U, 0x9bU, 0xb1U,
    0x73U, 0x30U, 0x09U, 0x04U, 0x2cU, 0x15U, 0xc0U, 0xc1U,
    0xdeU, 0x12U, 0x77U, 0x27U, 0xf4U, 0x18U, 0xb5U, 0x96U,
    0x6aU, 0xfaU, 0xdfU, 0xddU, 0x95U, 0xa6U, 0xe4U, 0x59U,
    0x1dU, 0x17U, 0x10U, 0x56U, 0xb3U, 0x33U, 0xdaU, 0xb9U,
    0x7aU, 0x79U, 0xc7U, 0x19U, 0x3eU, 0x34U, 0x17U, 0x27U
};

static const ALIGNED uint8_t testvec_p256_shareV[64] = {
    0xc0U, 0xf6U, 0x5dU, 0xa0U, 0xd1U, 0x19U, 0x27U, 0xbdU,
    0xf5U, 0xd5U, 0x60U, 0xc6U, 0x9eU, 0x1dU, 0x7dU, 0x93U,
    0x9aU, 0x05U, 0xb0U, 0xe8U, 0x82U, 0x91U, 0x88U, 0x7dU,
    0x67U, 0x9fU, 0xcaU, 0xdeU, 0xa7U, 0x58U, 0x10U, 0xfbU,
    0x5cU, 0xc1U, 0xcaU, 0x74U, 0x94U, 0xdbU, 0x39U, 0xe8U,
    0x2fU, 0xf2U, 0xf5U, 0x06U, 0x65U, 0x25U, 0x5dU, 0x76U,
    0x17U, 0x3eU, 0x09U, 0x98U, 0x6aU, 0xb4U, 0x67U, 0x42U,
    0xc7U, 0x98U, 0xa9U, 0xa6U, 0x84U, 0x37U, 0xb0U, 0x48U
};

static const ALIGNED uint8_t testvec_p256_Z[64] = {
    0xbbU, 0xfcU, 0xe7U, 0xddU, 0x7fU, 0x27U, 0x78U, 0x19U,
    0xc8U, 0xdaU, 0x21U, 0x54U, 0x4aU, 0xfbU, 0x79U, 0x64U,
    0x70U, 0x55U, 0x69U, 0xbdU, 0xf1U, 0x2fU, 0xb9U, 0x2aU,
    0xa3U, 0x88U, 0x05U, 0x94U, 0x08U, 0xd5U, 0x00U, 0x91U,
    0xa0U, 0xc5U, 0xf1U, 0xd3U, 0x12U, 0x7fU, 0x56U, 0x81U,
    0x3bU, 0x53U, 0x37U, 0xf9U, 0xe4U, 0xe6U, 0x7eU, 0x2cU,
    0xa6U, 0x33U, 0x11U, 0x7aU, 0x4fU, 0xbdU, 0x55U, 0x99U,
    0x46U, 0xabU, 0x47U, 0x43U, 0x56U, 0xc4U, 0x18U, 0x39U
};

static const ALIGNED uint8_t testvec_p256_V[64] = {
    0x58U, 0xbfU, 0x27U, 0xc6U, 0xbcU, 0xa0U, 0x11U, 0xc9U,
    0xceU, 0x19U, 0x30U, 0xe8U, 0x98U, 0x4aU, 0x79U, 0x7aU,
    0x34U, 0x19U, 0x79U, 0x7bU, 0x93U, 0x66U, 0x29U, 0xa5U,
    0xa9U, 0x37U, 0xcfU, 0x2fU, 0x11U, 0xc8U, 0xb9U, 0x51U,
    0x4bU, 0x82U, 0xb9U, 0x93U, 0xdaU, 0x8aU, 0x46U, 0xe6U,
    0x64U, 0xf2U, 0x3dU, 0xb7U, 0xc0U, 0x1eU, 0xdcU, 0x87U,
    0xfaU, 0xa5U, 0x30U, 0xdbU, 0x01U, 0xc2U, 0xeeU, 0x40U,
    0x52U, 0x30U, 0xb1U, 0x89U, 0x97U, 0xf1U, 0x6bU, 0x68U
};

static const ALIGNED uint8_t testvec_p256_TT[570] = {
    0x38U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x53U, 0x50U, 0x41U, 0x4bU, 0x45U, 0x32U, 0x2bU, 0x2dU,
    0x50U, 0x32U, 0x35U, 0x36U, 0x2dU, 0x53U, 0x48U, 0x41U, 0x32U, 0x35U, 0x36U, 0x2dU, 0x48U, 0x4bU, 0x44U, 0x46U,
    0x2dU, 0x53U, 0x48U, 0x41U, 0x32U, 0x35U, 0x36U, 0x2dU, 0x48U, 0x4dU, 0x41U, 0x43U, 0x2dU, 0x53U, 0x48U, 0x41U,
    0x32U, 0x35U, 0x36U, 0x20U, 0x54U, 0x65U, 0x73U, 0x74U, 0x20U, 0x56U, 0x65U, 0x63U, 0x74U, 0x6fU, 0x72U, 0x73U,
    0x06U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x63U, 0x6cU, 0x69U, 0x65U, 0x6eU, 0x74U, 0x06U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x73U, 0x65U, 0x72U, 0x76U, 0x65U, 0x72U, 0x41U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x04U, 0x88U, 0x6eU, 0x2fU, 0x97U, 0xacU, 0xe4U, 0x6eU, 0x55U, 0xbaU, 0x9dU, 0xd7U,
    0x24U, 0x25U, 0x79U, 0xf2U, 0x99U, 0x3bU, 0x64U, 0xe1U, 0x6eU, 0xf3U, 0xdcU, 0xabU, 0x95U, 0xafU, 0xd4U, 0x97U,
    0x33U, 0x3dU, 0x8fU, 0xa1U, 0x2fU, 0x5fU, 0xf3U, 0x55U, 0x16U, 0x3eU, 0x43U, 0xceU, 0x22U, 0x4eU, 0x0bU, 0x0eU,
    0x65U, 0xffU, 0x02U, 0xacU, 0x8eU, 0x5cU, 0x7bU, 0xe0U, 0x94U, 0x19U, 0xc7U, 0x85U, 0xe0U, 0xcaU, 0x54U, 0x7dU,
    0x55U, 0xa1U, 0x2eU, 0x2dU, 0x20U, 0x41U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x04U, 0xd8U, 0xbbU,
    0xd6U, 0xc6U, 0x39U, 0xc6U, 0x29U, 0x37U, 0xb0U, 0x4dU, 0x99U, 0x7fU, 0x38U, 0xc3U, 0x77U, 0x07U, 0x19U, 0xc6U,
    0x29U, 0xd7U, 0x01U, 0x4dU, 0x49U, 0xa2U, 0x4bU, 0x4fU, 0x98U, 0xbaU, 0xa1U, 0x29U, 0x2bU, 0x49U, 0x07U, 0xd6U,
    0x0aU, 0xa6U, 0xbfU, 0xadU, 0xe4U, 0x50U, 0x08U, 0xa6U, 0x36U, 0x33U, 0x7fU, 0x51U, 0x68U, 0xc6U, 0x4dU, 0x9bU,
    0xd3U, 0x60U, 0x34U, 0x80U, 0x8cU, 0xd5U, 0x64U, 0x49U, 0x0bU, 0x1eU, 0x65U, 0x6eU, 0xdbU, 0xe7U, 0x41U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x04U, 0xefU, 0x3bU, 0xd0U, 0x51U, 0xbfU, 0x78U, 0xa2U, 0x23U, 0x4eU,
    0xc0U, 0xdfU, 0x19U, 0x7fU, 0x78U, 0x28U, 0x06U, 0x0fU, 0xe9U, 0x85U, 0x65U, 0x03U, 0x57U, 0x9bU, 0xb1U, 0x73U,
    0x30U, 0x09U, 0x04U, 0x2cU, 0x15U, 0xc0U, 0xc1U, 0xdeU, 0x12U, 0x77U, 0x27U, 0xf4U, 0x18U, 0xb5U, 0x96U, 0x6aU,
    0xfaU, 0xdfU, 0xddU, 0x95U, 0xa6U, 0xe4U, 0x59U, 0x1dU, 0x17U, 0x10U, 0x56U, 0xb3U, 0x33U, 0xdaU, 0xb9U, 0x7aU,
    0x79U, 0xc7U, 0x19U, 0x3eU, 0x34U, 0x17U, 0x27U, 0x41U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x04U,
    0xc0U, 0xf6U, 0x5dU, 0xa0U, 0xd1U, 0x19U, 0x27U, 0xbdU, 0xf5U, 0xd5U, 0x60U, 0xc6U, 0x9eU, 0x1dU, 0x7dU, 0x93U,
    0x9aU, 0x05U, 0xb0U, 0xe8U, 0x82U, 0x91U, 0x88U, 0x7dU, 0x67U, 0x9fU, 0xcaU, 0xdeU, 0xa7U, 0x58U, 0x10U, 0xfbU,
    0x5cU, 0xc1U, 0xcaU, 0x74U, 0x94U, 0xdbU, 0x39U, 0xe8U, 0x2fU, 0xf2U, 0xf5U, 0x06U, 0x65U, 0x25U, 0x5dU, 0x76U,
    0x17U, 0x3eU, 0x09U, 0x98U, 0x6aU, 0xb4U, 0x67U, 0x42U, 0xc7U, 0x98U, 0xa9U, 0xa6U, 0x84U, 0x37U, 0xb0U, 0x48U,
    0x41U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x04U, 0xbbU, 0xfcU, 0xe7U, 0xddU, 0x7fU, 0x27U, 0x78U,
    0x19U, 0xc8U, 0xdaU, 0x21U, 0x54U, 0x4aU, 0xfbU, 0x79U, 0x64U, 0x70U, 0x55U, 0x69U, 0xbdU, 0xf1U, 0x2fU, 0xb9U,
    0x2aU, 0xa3U, 0x88U, 0x05U, 0x94U, 0x08U, 0xd5U, 0x00U, 0x91U, 0xa0U, 0xc5U, 0xf1U, 0xd3U, 0x12U, 0x7fU, 0x56U,
    0x81U, 0x3bU, 0x53U, 0x37U, 0xf9U, 0xe4U, 0xe6U, 0x7eU, 0x2cU, 0xa6U, 0x33U, 0x11U, 0x7aU, 0x4fU, 0xbdU, 0x55U,
    0x99U, 0x46U, 0xabU, 0x47U, 0x43U, 0x56U, 0xc4U, 0x18U, 0x39U, 0x41U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x04U, 0x58U, 0xbfU, 0x27U, 0xc6U, 0xbcU, 0xa0U, 0x11U, 0xc9U, 0xceU, 0x19U, 0x30U, 0xe8U, 0x98U, 0x4aU,
    0x79U, 0x7aU, 0x34U, 0x19U, 0x79U, 0x7bU, 0x93U, 0x66U, 0x29U, 0xa5U, 0xa9U, 0x37U, 0xcfU, 0x2fU, 0x11U, 0xc8U,
    0xb9U, 0x51U, 0x4bU, 0x82U, 0xb9U, 0x93U, 0xdaU, 0x8aU, 0x46U, 0xe6U, 0x64U, 0xf2U, 0x3dU, 0xb7U, 0xc0U, 0x1eU,
    0xdcU, 0x87U, 0xfaU, 0xa5U, 0x30U, 0xdbU, 0x01U, 0xc2U, 0xeeU, 0x40U, 0x52U, 0x30U, 0xb1U, 0x89U, 0x97U, 0xf1U,
    0x6bU, 0x68U, 0x20U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0xbbU, 0x8eU, 0x1bU, 0xbcU, 0xf3U, 0xc4U,
    0x8fU, 0x62U, 0xc0U, 0x8dU, 0xb2U, 0x43U, 0x65U, 0x2aU, 0xe5U, 0x5dU, 0x3eU, 0x55U, 0x86U, 0x05U, 0x3fU, 0xcaU,
    0x77U, 0x10U, 0x29U, 0x94U, 0xf2U, 0x3aU, 0xd9U, 0x54U, 0x91U, 0xb3U
};

static const ALIGNED uint8_t testvec_p256_K_main[32] = {
    0x4cU, 0x59U, 0xe1U, 0xccU, 0xf2U, 0xcfU, 0xb9U, 0x61U,
    0xaaU, 0x31U, 0xbdU, 0x94U, 0x34U, 0x47U, 0x8aU, 0x10U,
    0x89U, 0xb5U, 0x6cU, 0xd1U, 0x15U, 0x42U, 0xf5U, 0x3dU,
    0x35U, 0x76U, 0xfbU, 0x6cU, 0x2aU, 0x43U, 0x8aU, 0x29U
};

static const ALIGNED uint8_t testvec_p256_K_confirmP[32] = {
    0x87U, 0x1aU, 0xe3U, 0xf7U, 0xb7U, 0x84U, 0x45U, 0xe3U,
    0x44U, 0x38U, 0xfbU, 0x28U, 0x45U, 0x04U, 0x24U, 0x02U,
    0x39U, 0x03U, 0x1cU, 0x39U, 0xd8U, 0x0aU, 0xc2U, 0x3eU,
    0xb5U, 0xabU, 0x9bU, 0xe5U, 0xadU, 0x6dU, 0xb5U, 0x8aU
};

static const ALIGNED uint8_t testvec_p256_K_confirmV[32] = {
    0xccU, 0xd5U, 0x3cU, 0x7cU, 0x1fU, 0xa3U, 0x7bU, 0x64U,
    0xa4U, 0x62U, 0xb4U, 0x0dU, 0xb8U, 0xbeU, 0x10U, 0x1cU,
    0xedU, 0xcfU, 0x83U, 0x89U, 0x50U, 0x16U, 0x29U, 0x02U,
    0x05U, 0x4eU, 0x64U, 0x4bU, 0x40U, 0x0fU, 0x16U, 0x80U
};

static const ALIGNED uint8_t testvec_p256_K_shared[32] = {
    0x0cU, 0x5fU, 0x8cU, 0xcdU, 0x14U, 0x13U, 0x42U, 0x3aU,
    0x54U, 0xf6U, 0xc1U, 0xfbU, 0x26U, 0xffU, 0x01U, 0x53U,
    0x4aU, 0x87U, 0xf8U, 0x93U, 0x77U, 0x9cU, 0x6eU, 0x68U,
    0x66U, 0x6dU, 0x77U, 0x2bU, 0xfdU, 0x91U, 0xf3U, 0xe7U
};

static const ALIGNED uint8_t testvec_p256_confirmP[32] = {
    0x92U, 0x6cU, 0xc7U, 0x13U, 0x50U, 0x4bU, 0x9bU, 0x4dU,
    0x76U, 0xc9U, 0x16U, 0x2dU, 0xedU, 0x04U, 0xb5U, 0x49U,
    0x3eU, 0x89U, 0x10U, 0x9fU, 0x6dU, 0x89U, 0x46U, 0x2cU,
    0xd3U, 0x3aU, 0xdcU, 0x46U, 0xfdU, 0xa2U, 0x75U, 0x27U
};

static const ALIGNED uint8_t testvec_p256_confirmV[32] = {
    0x97U, 0x47U, 0xbcU, 0xc4U, 0xf8U, 0xfeU, 0x9fU, 0x63U,
    0xdeU, 0xfeU, 0xe5U, 0x3aU, 0xc9U, 0xb0U, 0x78U, 0x76U,
    0xd9U, 0x07U, 0xd5U, 0x50U, 0x47U, 0xe6U, 0xffU, 0x2dU,
    0xefU, 0x2eU, 0x75U, 0x29U, 0x08U, 0x9dU, 0x3eU, 0x68U
};


/* Curve Parameters (P256) */

static const ALIGNED uint8_t p256_G[64] = {
    0x6BU, 0x17U, 0xD1U, 0xF2U, 0xE1U, 0x2CU, 0x42U, 0x47U,
    0xF8U, 0xBCU, 0xE6U, 0xE5U, 0x63U, 0xA4U, 0x40U, 0xF2U,
    0x77U, 0x03U, 0x7DU, 0x81U, 0x2DU, 0xEBU, 0x33U, 0xA0U,
    0xF4U, 0xA1U, 0x39U, 0x45U, 0xD8U, 0x98U, 0xC2U, 0x96U,
    0x4FU, 0xE3U, 0x42U, 0xE2U, 0xFEU, 0x1AU, 0x7FU, 0x9BU,
    0x8EU, 0xE7U, 0xEBU, 0x4AU, 0x7CU, 0x0FU, 0x9EU, 0x16U,
    0x2BU, 0xCEU, 0x33U, 0x57U, 0x6BU, 0x31U, 0x5EU, 0xCEU,
    0xCBU, 0xB6U, 0x40U, 0x68U, 0x37U, 0xBFU, 0x51U, 0xF5U
};

static const ALIGNED uint8_t p256_A[32] =
{
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x01U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFCU
};

static const ALIGNED uint8_t p256_B[32] =
{
    0x5AU, 0xC6U, 0x35U, 0xD8U, 0xAAU, 0x3AU, 0x93U, 0xE7U,
    0xB3U, 0xEBU, 0xBDU, 0x55U, 0x76U, 0x98U, 0x86U, 0xBCU,
    0x65U, 0x1DU, 0x06U, 0xB0U, 0xCCU, 0x53U, 0xB0U, 0xF6U,
    0x3BU, 0xCEU, 0x3CU, 0x3EU, 0x27U, 0xD2U, 0x60U, 0x4BU
};

static const ALIGNED uint8_t p256_P[32] =
{
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x01U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};

static const ALIGNED uint8_t p256_N[32] =
{
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x00U,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xBCU, 0xE6U, 0xFAU, 0xADU, 0xA7U, 0x17U, 0x9EU, 0x84U,
    0xF3U, 0xB9U, 0xCAU, 0xC2U, 0xFCU, 0x63U, 0x25U, 0x51U
};

#define SPAKE2PLUS_KEYSIZE 32U

#define MAX_CPUWA_SIZE MCUXCLCORE_MAX(MCUXCLECC_ARITHMETICOPERATION_POINTADD_WACPU_SIZE,     \
                       MCUXCLCORE_MAX(MCUXCLECC_ARITHMETICOPERATION_POINTSUB_WACPU_SIZE,     \
                       MCUXCLCORE_MAX(MCUXCLECC_POINTMULT_WACPU_SIZE,                        \
                       MCUXCLCORE_MAX(MCUXCLRANDOMMODES_NCINIT_WACPU_SIZE,                   \
                       MCUXCLCORE_MAX(MCUXCLKEY_DERIVATION_HKDF_CPU_WA_SIZE,                 \
                       MCUXCLCORE_MAX(MCUXCLHASH_MAX_CPU_WA_BUFFER_SIZE,                     \
                       MCUXCLKEY_DERIVATION_HKDF_CPU_WA_SIZE))))))

#define MAX_PKCWA_SIZE MCUXCLCORE_MAX(MCUXCLECC_ARITHMETICOPERATION_POINTADD_WAPKC_SIZE_256, \
                       MCUXCLCORE_MAX(MCUXCLECC_ARITHMETICOPERATION_POINTSUB_WAPKC_SIZE_256, \
                                     MCUXCLECC_POINTMULT_WAPKC_SIZE_256))


/* Helper Macro to shorten code for Scalar x Point Multiplication + Checks */
#define MCUXCLKEY_SPAKE2PLUS_SCALARMULT(session, params)                                     \
 MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(scalarMult_status, scalarMult_token,                      \
        mcuxClEcc_PointMult(                                                                \
            (session),                                                                     \
            (params)                                                                       \
        )                                                                                  \
    );                                                                                     \
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointMult) != scalarMult_token) ||            \
       (MCUXCLECC_STATUS_OK != scalarMult_status))                                          \
    {                                                                                      \
        return MCUXCLEXAMPLE_STATUS_ERROR;                                                  \
    }                                                                                      \
    MCUX_CSSL_FP_FUNCTION_CALL_END();                                                       \

/* Helper Macro to shorten code for memory copying + checks                */
#define MCUXCLKEY_SPAKE2PLUS_MEMCPY(dst, src, length, bufLength)                            \
  MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN(copy_token, mcuxClMemory_copy(                       \
                 (dst),                                                                    \
                 (src),                                                                    \
                 (length),                                                                 \
                 (bufLength)                                                               \
            ));                                                                            \
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) != copy_token)                       \
    {                                                                                      \
        return MCUXCLEXAMPLE_STATUS_ERROR;                                                  \
    }                                                                                      \
    MCUX_CSSL_FP_FUNCTION_CALL_VOID_END();                                                  \


/**
 * @brief Performs the Offline Registration Phase of SPAKE2+ (with w0, w1 provided by Testvector)
 *
 * @param[in]      pSession    Session handle to provide session dependent information
 * @param[in]      pParams     Curve Parameters to use during Point Multiplication
 * @param[out]     pPointL     Result Buffer for the computed Curve Point L
 *
 * @return MCUXCLEXAMPLE_STATUS_OK on successful completion, MCUXCLEXMAPLE_STATUS_ERROR otherwise
 *
 * @note This example function was created to show the logical split of the SPAKE2+ algorithm into separate stages.
 *       User must ensure proper flow protection of each function on their end.
 */
static bool mcuxClKey_Spake2Plus_Registration(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_PointMult_Param_t * pParams,
    mcuxCl_Buffer_t pPointL
) {
    MCUXCLBUFFER_INIT_RO(pPointG, NULL, p256_G, sizeof(p256_G));
    MCUXCLBUFFER_INIT_RO(buffW1, NULL, testvec_p256_w1, sizeof(testvec_p256_w1));

    pParams->pScalar = buffW1;
    pParams->pPoint = pPointG;
    pParams->pResult = pPointL;

    /* Compute L = w1 * P */
    MCUXCLKEY_SPAKE2PLUS_SCALARMULT(pSession, pParams)
    return MCUXCLEXAMPLE_STATUS_OK;
}

/**
 * @brief Performs computation of shareP (also referre as X in the RFC) by the Prover
 *
 * @param[in]      pSession     Session handle to provide session dependent information
 * @param[in]      pParams      Curve Parameters to use during Point Multiplication
 * @param[in]      pScalarW0    Parameter w0
 * @param[in]      pScalarX     Random Parameter x
 * @param[out]     pPointShareP Resulting shared value shareP
 *
 * @return MCUXCLEXAMPLE_STATUS_OK on successful completion, MCUXCLEXMAPLE_STATUS_ERROR otherwise
 *
 * @note This example function was created to show the logical split of the SPAKE2+ algorithm into separate stages.
 *       User must ensure proper flow protection of each function on their end.
 */
static bool mcuxClKey_Spake2Plus_Prover_ComputeShareP(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_PointMult_Param_t * pParams,
    mcuxCl_InputBuffer_t pScalarW0,
    mcuxCl_InputBuffer_t pScalarX,
    mcuxCl_Buffer_t pPointShareP
) {
    MCUXCLBUFFER_INIT_RO(pPointG, NULL, p256_G, sizeof(p256_G));
    MCUXCLBUFFER_INIT_RO(pPointM, NULL, testvec_p256_M, sizeof(testvec_p256_M));

    uint8_t pXP[(MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U) + 1];
    MCUXCLBUFFER_INIT(buffXP, NULL, pXP, sizeof(pXP));

    pParams->pScalar = pScalarX;
    pParams->pPoint = pPointG;
    pParams->pResult = buffXP;
    MCUXCLKEY_SPAKE2PLUS_SCALARMULT(pSession, pParams)

    uint8_t pW0M[(MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U) + 1];
    MCUXCLBUFFER_INIT(buffW0M, NULL, pW0M, sizeof(pW0M));

    /* Compute w0 * M */
    pParams->pScalar = pScalarW0;
    pParams->pPoint = pPointM;
    pParams->pResult = buffW0M;
    MCUXCLKEY_SPAKE2PLUS_SCALARMULT(pSession, pParams)

    /* Point Addition of Results */
    uint32_t sharePSize = 0U;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pointAdd_status, pointAdd_token,
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t          */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t */ mcuxClEcc_ArithmeticOperation_PointAdd,
          MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Discarding const mirrors intended usage.")
          /* mcuxClEcc_Weier_DomainParams_t* */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
          /* mcuxCl_InputBuffer_t            */ (mcuxCl_InputBuffer_t) buffXP,
          /* uint32_t op1Size               */ MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U,
          /* mcuxCl_InputBuffer_t            */ (mcuxCl_InputBuffer_t) buffW0M,
          /* uint32_t                       */ MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U,
          /* mcuxCl_Buffer_t                 */ pPointShareP,
          /* uint32_t * const               */ &sharePSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != pointAdd_token) ||
       (MCUXCLECC_STATUS_OK != pointAdd_status) || sharePSize != MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return MCUXCLEXAMPLE_STATUS_OK;
}

/**
 * @brief Performs computation of Z by the Prover
 *
 * @param[in]      pSession           Session handle to provide session dependent information
 * @param[in]      pParams            Curve Parameters to use during Point Multiplication
 * @param[in]      pPointShareV       ShareV as received from the Verifier
 * @param[in]      pPointW0N          w0 * N as precomputed beforehand
 * @param[in]      pScalarX           Random/Testvector value x
 * @param[out]     pPointIntermediate Intermediate result shareV - w0 * N
 * @param[out]     pPointZ            Resulting Point Z
 *
 * @return MCUXCLEXAMPLE_STATUS_OK on successful completion, MCUXCLEXMAPLE_STATUS_ERROR otherwise
 *
 * @note This example function was created to show the logical split of the SPAKE2+ algorithm into separate stages.
 *       User must ensure proper flow protection of each function on their end.
 */
static bool mcuxClKey_Spake2Plus_Prover_ComputeZ(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_PointMult_Param_t * pParams,
    mcuxCl_InputBuffer_t pPointShareV,
    mcuxCl_InputBuffer_t pPointW0N,
    mcuxCl_InputBuffer_t pScalarX,
    mcuxCl_Buffer_t pPointIntermediate,
    mcuxCl_Buffer_t pPointZ
) {
    uint32_t z1Size = 0u;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pointSub_status_Z, pointSub_token_Z,
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t          */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t */ mcuxClEcc_ArithmeticOperation_PointSub,
          MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Discarding const mirrors intended usage.")
          /* mcuxClEcc_Weier_DomainParams_t* */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
          /* mcuxCl_InputBuffer_t            */ pPointShareV,
          /* uint32_t                       */ MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U,
          /* mcuxCl_InputBuffer_t            */ pPointW0N,
          /* uint32_t                       */ MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U,
          /* mcuxCl_Buffer_t                 */ pPointIntermediate,
          /* uint32_t * const               */ &z1Size
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != pointSub_token_Z) ||
       (MCUXCLECC_STATUS_OK != pointSub_status_Z) || z1Size != MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    pParams->pScalar = pScalarX;
    pParams->pPoint = pPointIntermediate,
    pParams->pResult = pPointZ;
    MCUXCLKEY_SPAKE2PLUS_SCALARMULT(pSession, pParams)


    /* Considered short Weierstrass curves have cofactor equal 1. Therefore scalar multiplication over h=1 is not needed. */

    return MCUXCLEXAMPLE_STATUS_OK;
}

/**
 * @brief Performs computation of V by the Prover
 *
 * @param[in]      pSession            Session handle to provide session dependent information
 * @param[in]      pParams             Curve Parameters to use during Point Multiplication
 * @param[in]      pScalarW1           Parameter W1
 * @param[in]      pPointZIntermediate Stored result of shareV - w0 * N
 * @param[out]     pPointIntermediate  Intermediate result shareV - w0 * N
 * @param[out]     pPointV             Resulting Point V
 *
 * @return MCUXCLEXAMPLE_STATUS_OK on successful completion, MCUXCLEXMAPLE_STATUS_ERROR otherwise
 *
 * @note This example function was created to show the logical split of the SPAKE2+ algorithm into separate stages.
 *       User must ensure proper flow protection of each function on their end.
 */
static bool mcuxClKey_Spake2Plus_Prover_ComputeV(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_PointMult_Param_t * pParams,
    mcuxCl_InputBuffer_t pScalarW1,
    mcuxCl_InputBuffer_t pPointZIntermediate,
    mcuxCl_Buffer_t pPointV
) {
    pParams->pScalar = pScalarW1;
    pParams->pPoint = pPointZIntermediate;
    pParams->pResult = pPointV;
    MCUXCLKEY_SPAKE2PLUS_SCALARMULT(pSession, pParams)

    /* Considered short Weierstrass curves have cofactor equal 1. Therefore scalar multiplication over h=1 is not needed. */

    return MCUXCLEXAMPLE_STATUS_OK;
}

/**
 * @brief Performs computation of ShareV
 *
 * @param[in]      pSession            Session handle to provide session dependent information
 * @param[in]      pParams             Curve Parameters to use during Point Multiplication
 * @param[in]      pScalarW0           Parameter w0
 * @param[in]      pScalarY            Parameter y
 * @param[out]     pPointShareV        Computed Point shareV
 *
 * @return MCUXCLEXAMPLE_STATUS_OK on successful completion, MCUXCLEXMAPLE_STATUS_ERROR otherwise
 *
 * @note This example function was created to show the logical split of the SPAKE2+ algorithm into separate stages.
 *       User must ensure proper flow protection of each function on their end.
 */
static bool mcuxClKey_Spake2Plus_Verifier_ComputeShareV(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_PointMult_Param_t * pParams,
    mcuxCl_InputBuffer_t pScalarW0,
    mcuxCl_InputBuffer_t pScalarY,
    mcuxCl_Buffer_t pPointShareV
) {

    MCUXCLBUFFER_INIT_RO(pPointG, NULL, p256_G, sizeof(p256_G));
    MCUXCLBUFFER_INIT_RO(pPointN, NULL, testvec_p256_N, sizeof(testvec_p256_N));

    /* Compute y * P */
    uint8_t pYP[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U];
    MCUXCLBUFFER_INIT(buffYP, NULL, pYP, sizeof(pYP));

    pParams->pScalar = pScalarY;
    pParams->pPoint = pPointG;
    pParams->pResult = buffYP;
    MCUXCLKEY_SPAKE2PLUS_SCALARMULT(pSession, pParams)

    uint8_t pPointW0n[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U];
    MCUXCLBUFFER_INIT(buffW0n, NULL, pPointW0n, sizeof(pPointW0n));

    /* Compute w0 * N */
    pParams->pScalar = pScalarW0;
    pParams->pPoint = pPointN;
    pParams->pResult = buffW0n;
    MCUXCLKEY_SPAKE2PLUS_SCALARMULT(pSession, pParams)

    /* Point Addition of Results */
    uint32_t shareVSize = 0u;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pointAdd_status_Y, pointAdd_token_Y,
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t          */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t */ mcuxClEcc_ArithmeticOperation_PointAdd,
          MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Discarding const mirrors intended usage.")
          /* mcuxClEcc_Weier_DomainParams_t* */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
          /* mcuxCl_InputBuffer_t            */ (mcuxCl_InputBuffer_t) buffYP,
          /* uint32_t                       */ MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U,
          /* mcuxCl_InputBuffer_t            */ (mcuxCl_InputBuffer_t) buffW0n,
          /* uint32_t                       */ MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U,
          /* mcuxCl_Buffer_t                 */ pPointShareV,
          /* uint32_t* const                */ &shareVSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != pointAdd_token_Y) ||
       (MCUXCLECC_STATUS_OK != pointAdd_status_Y) || shareVSize != MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return MCUXCLEXAMPLE_STATUS_OK;
   }

/**
 * @brief Performs computation of Z by the Verifier
 *
 * @param[in]      pSession            Session handle to provide session dependent information
 * @param[in]      pParams             Curve Parameters to use during Point Multiplication
 * @param[in]      pPointShareP        Point ShareP as received from the Prover
 * @param[in]      pScalarW0           Parameter w0
 * @param[in]      pScalarY            Parameter y
 * @param[out]     pPointZ             Resulting Point Z
 *
 * @return MCUXCLEXAMPLE_STATUS_OK on successful completion, MCUXCLEXMAPLE_STATUS_ERROR otherwise
 *
 * @note This example function was created to show the logical split of the SPAKE2+ algorithm into separate stages.
 *       User must ensure proper flow protection of each function on their end.
 */
static bool mcuxClKey_Spake2Plus_Verifier_ComputeZ(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_PointMult_Param_t * pParams,
    mcuxCl_InputBuffer_t pPointShareP,
    mcuxCl_InputBuffer_t pScalarW0,
    mcuxCl_InputBuffer_t pScalarY,
    mcuxCl_Buffer_t pPointZ
) {

    uint8_t pW0M[(MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U) + 1];
    MCUXCLBUFFER_INIT(buffW0M, NULL, pW0M, sizeof(pW0M));
    MCUXCLBUFFER_INIT_RO(pPointM, NULL, testvec_p256_M, sizeof(testvec_p256_M));

    /* Compute w0 * M */
    pParams->pScalar = pScalarW0;
    pParams->pPoint = pPointM;
    pParams->pResult = buffW0M;
    MCUXCLKEY_SPAKE2PLUS_SCALARMULT(pSession, pParams)

    uint8_t Z_Intermediate[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U];
    uint32_t zIntermediateSize = 0U;

    MCUXCLBUFFER_INIT(buffPointZIntermediate, NULL, Z_Intermediate, sizeof(Z_Intermediate));

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pointSub_status_Z3, pointSub_token_Z3,
        mcuxClEcc_ArithmeticOperation(
          /* mcuxClSession_Handle_t          */ pSession,
          /* mcuxClEcc_ArithmeticOperation_t */ mcuxClEcc_ArithmeticOperation_PointSub,
          MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Discarding const mirrors intended usage.")
          /* mcuxClEcc_Weier_DomainParams_t* */ (mcuxClEcc_Weier_DomainParams_t *) &mcuxClEcc_Weier_DomainParams_NIST_P256,
          MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
          /* mcuxCl_InputBuffer_t            */ pPointShareP,
          /* uint32_t                       */ MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U,
          /* mcuxCl_InputBuffer_t            */ (mcuxCl_InputBuffer_t) buffW0M,
          /* uint32_t                       */ MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U,
          /* mcuxCl_Buffer_t                 */ buffPointZIntermediate,
          /* uint32_t * const               */ &zIntermediateSize
        )
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_ArithmeticOperation) != pointSub_token_Z3) ||
       (MCUXCLECC_STATUS_OK != pointSub_status_Z3) || (zIntermediateSize != MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    pParams->pScalar = pScalarY;
    pParams->pPoint = buffPointZIntermediate;
    pParams->pResult = pPointZ;
    MCUXCLKEY_SPAKE2PLUS_SCALARMULT(pSession, pParams)

    /* Considered short Weierstrass curves have cofactor equal 1. Therefore scalar multiplication over h=1 is not needed. */

    return MCUXCLEXAMPLE_STATUS_OK;
}

/**
 * @brief Performs computation of V by the Verifier
 *
 * @param[in]      pSession            Session handle to provide session dependent information
 * @param[in]      pParams             Curve Parameters to use during Point Multiplication
 * @param[in]      pPointL             Registration Record L
 * @param[in]      pScalarY            Parameter y
 * @param[out]     pPointV             Resulting Point V
 *
 * @return MCUXCLEXAMPLE_STATUS_OK on successful completion, MCUXCLEXMAPLE_STATUS_ERROR otherwise
 *
 * @note This example function was created to show the logical split of the SPAKE2+ algorithm into separate stages.
 *       User must ensure proper flow protection of each function on their end.
 */
static bool mcuxClKey_Spake2Plus_Verifier_ComputeV(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_PointMult_Param_t * pParams,
    mcuxCl_InputBuffer_t pPointL,
    mcuxCl_InputBuffer_t pScalarY,
    mcuxCl_Buffer_t pPointV
) {
    pParams->pScalar = pScalarY;
    pParams->pPoint = pPointL;
    pParams->pResult = pPointV;
    MCUXCLKEY_SPAKE2PLUS_SCALARMULT(pSession, pParams)

    /* Considered short Weierstrass curves have cofactor equal 1. Therefore scalar multiplication over h=1 is not needed. */
    return MCUXCLEXAMPLE_STATUS_OK;
}

/**
 * @brief Constructs the Protocol Transcript for SPAKE2+
 *
 * @param[in]      pSession               Session handle to provide session dependent information
 * @param[in]      contextLength          Length of the context of the protocol run in bytes
 * @param[in]      pContext               Context of the protocol
 * @param[in]      idProverLength         Length of the prover ID in bytes
 * @param[in]      pIdProver               Prover ID
 * @param[in]      idVerifierLength       Length of the verifier ID in bytes
 * @param[in]      pIdVerifier             Verifier ID
 * @param[in]      pointMLength           Length of M in bytes
 * @param[in]      pPointM                 Protocol Parameter M
 * @param[in]      pointNLength           Length of N in bytes
 * @param[in]      pPointN                 Protocol Parameter N
 * @param[in]      sharePLength           Length of ShareP in bytes
 * @param[in]      pShareP                 Prover Share shareP
 * @param[in]      shareVLength           Length of ShareV in bytes
 * @param[in]      pShareV                 Verifier Share shareV
 * @param[in]      pointZLength           Length of Z in bytes
 * @param[in]      pointZ                 Z as computed by Prover/Verifier
 * @param[in]      pointVLength           Length of V in bytes
 * @param[in]      pointV                 V as computed by Prover/Verifier
 * @param[in]      w0length               Length of w0 in bytes
 * @param[in]      w0                     w0 as provided by registration/test vector
 * @param[in]      transcriptLength       Length of the provided buffer for writing the transcript in bytes
 * @param[out]     pTranscript            Buffer to write the protocol transcript to
 * @param[out]     transcriptBytesWritten Stores information on number of bytes written to transcript
 *
 * @return MCUXCLEXAMPLE_STATUS_OK on successful completion, MCUXCLEXMAPLE_STATUS_ERROR otherwise
 *
 * @note This example function was created to show the logical split of the SPAKE2+ algorithm into separate stages.
 *       User must ensure proper flow protection of each function on their end.
 */
static bool mcuxClKey_Spake2Plus_getTranscript(
    mcuxClSession_Handle_t pSession,
    const uint64_t contextLength,
    const uint8_t* pContext,
    const uint64_t idProverLength,
    const uint8_t* pIdProver,
    const uint64_t idVerifierLength,
    const uint8_t* pIdVerifier,
    const uint64_t pointMLength,
    const uint8_t* pPointM,
    const uint64_t pointNLength,
    const uint8_t* pPointN,
    const uint64_t sharePLength,
    const uint8_t* pShareP,
    const uint64_t shareVLength,
    const uint8_t* pShareV,
    const uint64_t pointZLength,
    const uint8_t* pPointZ,
    const uint64_t pointVLength,
    const uint8_t* pPointV,
    const uint64_t w0Length,
    const uint8_t* pW0,
    const uint64_t transcriptLength,
    uint8_t* pTranscript,
    uint64_t *transcriptBytesWritten
) {
    uint64_t offset = 0U;

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, (const uint8_t*) &contextLength,
            sizeof(contextLength), (uint32_t) (transcriptLength - offset))
    offset += sizeof(contextLength);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, pContext,
            (uint32_t) contextLength, (uint32_t) (transcriptLength - offset))
    offset += contextLength;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, (const uint8_t *) &idProverLength,
            sizeof(idProverLength), (uint32_t) (transcriptLength - offset))
    offset += sizeof(idProverLength);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, pIdProver,
            (uint32_t) idProverLength, (uint32_t) (transcriptLength - offset))
    offset += idProverLength;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, (const uint8_t *) &idVerifierLength,
            sizeof(idVerifierLength), (uint32_t) (transcriptLength - offset))
    offset += sizeof(idVerifierLength);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, pIdVerifier,
            (uint32_t) idVerifierLength, (uint32_t) (transcriptLength - offset))
    offset += idVerifierLength;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    uint64_t pointMEffective = pointMLength + 1U; // Increase by one as 0x04 is prepended to Points
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, (const uint8_t *) &pointMEffective,
            sizeof(pointMLength), (uint32_t) (transcriptLength - offset))
    offset += sizeof(pointMEffective);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    /* Testvector expects all points to begin with 0x04 */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    pTranscript[offset++] = 0x04;
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, pPointM,
            (uint32_t) pointMLength, (uint32_t) (transcriptLength - offset))
    offset += pointMLength;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    uint64_t pointNEffective = pointNLength + 1U; // Increase by one as 0x04 is prepended to Points
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, (const uint8_t *) &pointNEffective,
            sizeof(pointNLength), (uint32_t) (transcriptLength - offset))
    offset += sizeof(pointNEffective);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    /* Testvector expects all points to begin with 0x04 */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    pTranscript[offset++] = 0x04;
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, pPointN,
            (uint32_t) pointNLength, (uint32_t) (transcriptLength - offset))
    offset += pointNLength;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    uint64_t sharePEffective = sharePLength + 1U; // Increase by one as 0x04 is prepended to Points
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, (const uint8_t *) &sharePEffective,
            sizeof(sharePEffective), (uint32_t) (transcriptLength - offset))
    offset += sizeof(sharePEffective);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    /* Testvector expects all points to begin with 0x04 */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    pTranscript[offset++] = 0x04;
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, pShareP,
            (uint32_t) sharePLength, (uint32_t) (transcriptLength - offset))
    offset += sharePLength;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    uint64_t shareVEffective = shareVLength + 1U; // Increase by one as 0x04 is prepended to Points
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, (const uint8_t *) &shareVEffective,
            sizeof(shareVEffective), (uint32_t) (transcriptLength - offset))
    offset += sizeof(shareVEffective);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    /* Testvector expects all points to begin with 0x04 */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    pTranscript[offset++] = 0x04;
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, pShareV,
            (uint32_t) shareVLength, (uint32_t) (transcriptLength - offset))
    offset += shareVLength;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    uint64_t pointZEffective = pointZLength + 1U; // Increase by one as 0x04 is prepended to Points
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, (const uint8_t *) &pointZEffective,
            sizeof(pointZEffective), (uint32_t) (transcriptLength - offset))
    offset += sizeof(pointZEffective);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    /* Testvector expects all points to begin with 0x04 */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    pTranscript[offset++] = 0x04;
     MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, pPointZ,
            (uint32_t) pointZLength, (uint32_t) (transcriptLength - offset))
    offset += pointZLength;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    uint64_t pointVEffective = pointVLength + 1U; // Increase by one as 0x04 is prepended to Points
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, (const uint8_t *) &pointVEffective,
            sizeof(pointVEffective), (uint32_t) (transcriptLength - offset))
    offset += sizeof(pointVEffective);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    /* Testvector expects all points to begin with 0x04 */
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    pTranscript[offset++] = 0x04;
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, pPointV,
            (uint32_t) pointVLength, (uint32_t) (transcriptLength - offset))
    offset += pointZLength;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, (const uint8_t *) &w0Length,
            sizeof(w0Length), (uint32_t) (transcriptLength - offset))
    offset += sizeof(w0Length);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP_AND_CONVERSION("Upper 32-bits are guaranteed 0.")
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pTranscript + offset, pW0,
            (uint32_t) w0Length, (uint32_t) (transcriptLength - offset))
    offset += w0Length;
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP_AND_CONVERSION()

    *transcriptBytesWritten = offset;
    return MCUXCLEXAMPLE_STATUS_OK;
}

/**
 * @brief Performs initialization of the Prover party of the protocol
 *
 * @param[in]      pSession            Session handle to provide session dependent information
 * @param[in]      pParams             Curve Parameters to use during Point Multiplication
 * @param[in]      pW0                 Parameter w0 of the protocol run
 * @param[out]     pShareP             Resulting Point shareP
 *
 * @return MCUXCLEXAMPLE_STATUS_OK on successful completion, MCUXCLEXMAPLE_STATUS_ERROR otherwise
 *
 * @note This example function was created to show the logical split of the SPAKE2+ algorithm into separate stages.
 *       User must ensure proper flow protection of each function on their end.
 */
static bool mcuxClKey_Spake2Plus_ProverInit(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_PointMult_Param_t* pParams,
    mcuxCl_InputBuffer_t pW0,
    mcuxCl_Buffer_t pShareP
) {
    /* Under real protocol flow, we would choose x uniformly at random from the integers in [0, p-1] */
    MCUXCLBUFFER_INIT_RO(pX, NULL, testvec_p256_x, sizeof(testvec_p256_x));

    /* Compute Prover Key Share shareP = x * P + w0 * M            */
    /* In this implementation, we also return w0 * M for later use */

    return mcuxClKey_Spake2Plus_Prover_ComputeShareP(
    /* mcuxClSession_Handle_t */        pSession,
    /* mcuxClEcc_PointMult_Param_t* */ pParams,
    /* mcuxCl_InputBuffer_t */          pW0,
    /* mcuxCl_InputBuffer_t */          pX,
    /* mcuxCl_Buffer_t */               pShareP
    );
}

/**
 * @brief Performs steps taken by the prover after initial exchange with Verifier
 *
 * @param[in]      pSession            Session handle to provide session dependent information
 * @param[in]      pParams             Curve Parameters to use during Point Multiplication
 * @param[in]      pW0                 Protocol Parameter w0
 * @param[in]      pW1                 Protocol Parameter w1
 * @param[in]      pX                  Protocol Parameter x
 * @param[in]      pShareV             ShareV as provided by the verifier
 * @param[out]     pZ                  Resulting Point Z
 * @param[out]     pV                  Resulting Point V
 *
 * @return MCUXCLEXAMPLE_STATUS_OK on successful completion, MCUXCLEXMAPLE_STATUS_ERROR otherwise
 *
 * @note This example function was created to show the logical split of the SPAKE2+ algorithm into separate stages.
 *       User must ensure proper flow protection of each function on their end.
 */
static bool mcuxClKey_Spake2Plus_ProverFinish(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_PointMult_Param_t* pParams,
    mcuxCl_InputBuffer_t pW0,
    mcuxCl_InputBuffer_t pW1,
    mcuxCl_InputBuffer_t pX,
    mcuxCl_InputBuffer_t pShareV,
    mcuxCl_Buffer_t pZ,
    mcuxCl_Buffer_t pV
) {
    /* First, the Prover checks shareV for group membership          */
    /* As this check is implicit during Scalar Multiplication,       */
    /* it is not peformed explcitly here.                            */

    /* Cmpute w0 * N */
   MCUXCLBUFFER_INIT_RO(pPointN, NULL, testvec_p256_N, sizeof(testvec_p256_N));
   uint8_t pPointW0n[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U];
   MCUXCLBUFFER_INIT(buffW0n, NULL, pPointW0n, sizeof(pPointW0n));

    /* Compute w0 * N */
    pParams->pScalar = pW0;
    pParams->pPoint = pPointN;
    pParams->pResult = buffW0n;
    MCUXCLKEY_SPAKE2PLUS_SCALARMULT(pSession, pParams)

    /* Compute Z = h*x*(Y - w0 * N)                                  */
    /* Partial Result Y - w0 * N is stored for computing V           */
    uint8_t temp[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U];
    MCUXCLBUFFER_INIT(buffTemp, NULL, temp, sizeof(temp));

    bool status = mcuxClKey_Spake2Plus_Prover_ComputeZ(
        /* mcuxClSession_Handle_t        */ pSession,
        /* mcuxClEcc_PointMult_Param_t* */ pParams,
        /* mcuxCl_InputBuffer_t          */ pShareV,
        /* mcuxCl_InputBuffer_t          */ buffW0n,
        /* mcuxCl_InputBuffer_t          */ pX,
        /* mcuxCl_Buffer_t               */ buffTemp,
        /* mcuxCl_Buffer_t               */ pZ
    );

    if (status != MCUXCLEXAMPLE_STATUS_OK) {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Compute V = h * w1 * (Y - w0 * N), reusing Y - w0 * N.        */
    status = mcuxClKey_Spake2Plus_Prover_ComputeV(
        /* mcuxClSession_Handle_t        */ pSession,
        /* mcuxClEcc_PointMult_Param_t* */ pParams,
        /* mcuxCl_InputBuffer_t          */ pW1,
        /* mcuxCl_InputBuffer_t          */ (mcuxCl_InputBuffer_t) buffTemp,
        /* mcuxCl_Buffer_t               */ pV
    );

    return status;
}

/**
 * @brief Performs steps taken by the verifier after initial exchange with prover
 *
 * @param[in]      pSession            Session handle to provide session dependent information
 * @param[in]      pParams             Curve Parameters to use during Point Multiplication
 * @param[in]      pW0                 Protocol Parameter w0
 * @param[in]      pL                  Point L computed in registration
 * @param[in]      pShareP             ShareP as provided by the prover
 * @param[out]     pShareV             Resulting Point ShareV
 * @param[out]     pZ                  Resulting Point Z
 * @param[out]     pV                  Resulting Point V
 *
 * @return MCUXCLEXAMPLE_STATUS_OK on successful completion, MCUXCLEXMAPLE_STATUS_ERROR otherwise
 *
 * @note This example function was created to show the logical split of the SPAKE2+ algorithm into separate stages.
 *       User must ensure proper flow protection of each function on their end.
 */
static bool mcuxClKey_Spake2Plus_VerifierFinish(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_PointMult_Param_t* pParams,
    mcuxCl_InputBuffer_t pW0,
    mcuxCl_InputBuffer_t pL,
    mcuxCl_InputBuffer_t pShareP,
    mcuxCl_Buffer_t pShareV,
    mcuxCl_Buffer_t pZ,
    mcuxCl_Buffer_t pV
) {
    /* First, the Verifier checks shareP for group membership        */
    /* As this check is implicit during Scalar Multiplication,       */
    /* it is not peformed explicitly here.                            */

    /* Under real protocol flow, we would choose y <- [0, p-1]       */
    MCUXCLBUFFER_INIT_RO(pY, NULL, testvec_p256_y, sizeof(testvec_p256_y));

    /* Compute Verifier Key Share shareV = y * P + w0 * N            */
    /* We store w0 * N to simplify later steps in the protocol       */
    bool status = mcuxClKey_Spake2Plus_Verifier_ComputeShareV(
        /* mcuxClSession_Handle_t        */ pSession,
        /* mcuxClEcc_PointMult_Param_t* */ pParams,
        /* mcuxCl_InputBuffer_t          */ pW0,
        /* mcuxCl_InputBuffer_t          */ pY,
        /* mcuxCl_Buffer_t               */ pShareV
    );

    if (status != MCUXCLEXAMPLE_STATUS_OK) {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Compute Shared Value Z = h*y*(X - w0 * M)                     */
    status = mcuxClKey_Spake2Plus_Verifier_ComputeZ(
        /* mcuxClSession_Handle_t         */ pSession,
        /* mcuxClEcc_PointMult_Param_t*  */ pParams,
        /* mcuxCl_InputBuffer_t           */ pShareP,
        /* mcuxCl_InputBuffer_t           */ pW0,
        /* mcuxCl_InputBuffer_t           */ pY,
        /* mcuxCl_Buffer_t                */ pZ
    );

    if (status != MCUXCLEXAMPLE_STATUS_OK) {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Compute Shared Value V = h * y * L                            */
    status = mcuxClKey_Spake2Plus_Verifier_ComputeV(
        /* mcuxClSession_Handle_t        */ pSession,
        /* mcuxClEcc_PointMult_Param_t* */ pParams,
        /* mcuxCl_InputBuffer_t          */ pL,
        /* mcuxCl_InputBuffer_t          */ pY,
        /* mcuxCl_Buffer_t               */ pV
    );

    return status;
}

/**
 * @brief Performs Computation of KConfirmP, KConfirmV and KShared for a party in a protocol run
 *
 * @param[in]      pSession            Session handle to provide session dependent information
 * @param[in]      pTranscript         The transcript of the protocol run
 * @param[in]      transcriptSize      Size of the Transcript in bytes
 * @param[out]     pConfirmP           Confirmation Key KConfirmP
 * @param[out]     pConfirmV           Confirmation Key KConfirmV
 * @param[out]     pKShared            Confirmation Key KShared
 *
 * @return MCUXCLEXAMPLE_STATUS_OK on successful completion, MCUXCLEXMAPLE_STATUS_ERROR otherwise
 *
 * @note This example function was created to show the logical split of the SPAKE2+ algorithm into separate stages.
 *       User must ensure proper flow protection of each function on their end.
 */
static bool mcuxClKey_Spake2Plus_ComputeKeySchedule(
    mcuxClSession_Handle_t pSession,
    mcuxCl_InputBuffer_t pTranscript,
    uint32_t transcriptSize,
    mcuxCl_Buffer_t pConfirmP,
    mcuxCl_Buffer_t pConfirmV,
    mcuxCl_Buffer_t pKShared
) {
    /* Compute KMain = Hash(TT), TT being the Transcript */
    ALIGNED uint8_t K_Main[MCUXCLHASH_OUTPUT_SIZE_SHA_256];
    MCUXCLBUFFER_INIT_RW(hashBuf, session, K_Main, sizeof(K_Main));

    uint32_t hashOutputSize = 0U;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(status_hash, token_hash, mcuxClHash_compute(
    /* mcuxClSession_Handle_t */ pSession,
    /* mcuxClHash_Algo_t      */ mcuxClHash_Algorithm_Sha256,
    /* mcuxCl_InputBuffer_t   */ pTranscript,
    /* uint32_t              */ transcriptSize,
    /* mcuxCl_Buffer_t        */ hashBuf,
    /* uint32_t *const       */ &hashOutputSize
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute) != token_hash) || (MCUXCLHASH_STATUS_OK != status_hash))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if(!mcuxClCore_assertEqual(K_Main, testvec_p256_K_main, sizeof(testvec_p256_K_main)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* K_confirmP || K_confirmV = KDF(nil, K_Main, "ConfirmationKeys") */

    /* Create and initialize key descriptor structure for K_Main */
    uint32_t kMainDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t kMainHandle = (mcuxClKey_Handle_t) kMainDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultKeyInit1, tokenKeyInit1, mcuxClKey_init(
      /* mcuxClSession_Handle_t session         */ pSession,
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("The pointer sharedSecretHandle points to an object of the right type, the cast was valid.")
      /* mcuxClKey_Handle_t key                 */ kMainHandle,
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()
      /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Hmac_variableLength,
      /* const uint8_t * pKeyData              */ K_Main,
      /* uint32_t keyDataLength                */ sizeof(K_Main))
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != tokenKeyInit1) || (MCUXCLKEY_STATUS_OK != resultKeyInit1))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Key buffer for the key in memory. */
    uint32_t key_buffer[MCUXCLCORE_NUM_OF_CPUWORDS_CEIL(sizeof(K_Main))];
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultKeyLoadMemory, tokenKeyLoadMemory, mcuxClKey_loadMemory(pSession, kMainHandle, key_buffer));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_loadMemory) != tokenKeyLoadMemory) || (MCUXCLKEY_STATUS_OK != resultKeyLoadMemory))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Set up output structure. */
    uint8_t kConfirmPV[64];

    /* Create and initialize derivedKey descriptor structure. */
    uint32_t kConfirmPVDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t kConfirmPVHandle = (mcuxClKey_Handle_t) kConfirmPVDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultKeyInit2, tokenKeyInit2, mcuxClKey_init(
      /* mcuxClSession_Handle_t session         */ pSession,
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("The pointer derivedKey points to an object of the right type, the cast was valid.")
      /* mcuxClKey_Handle_t key                 */ kConfirmPVHandle,
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()
      /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Hmac_variableLength,
      /* const uint8_t * pKeyData              */ kConfirmPV,
      /* uint32_t keyDataLength                */ sizeof(kConfirmPV)
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != tokenKeyInit2) || (MCUXCLKEY_STATUS_OK != resultKeyInit2))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Create Hmac mode and Derivation mode                                   */
    /**************************************************************************/

    uint32_t hmacModeDescBuffer[MCUXCLHMAC_HMAC_MODE_DESCRIPTOR_SIZE_IN_WORDS];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClMac_CustomMode_t hmacSha256 = (mcuxClMac_CustomMode_t) hmacModeDescBuffer;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(hashCreateMode_result, hashCreateMode_token, mcuxClHmac_createHmacMode(
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("The pointer hmacSha256 is of the right type (mcuxClMac_CustomMode_t)")
      /* mcuxClMac_CustomMode_t mode:       */ hmacSha256,
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()
      /* mcuxClHash_Algo_t hashAlgorithm:   */ mcuxClHash_Algorithm_Sha256)
    );

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHmac_createHmacMode) != hashCreateMode_token) || (MCUXCLMAC_STATUS_OK != hashCreateMode_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    uint32_t derivationModeDescBuffer[MCUXCLKEY_DERIVATION_MODE_DESCRIPTOR_SIZE_IN_WORDS];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKey_DerivationMode_t * pDerivationMode = (mcuxClKey_DerivationMode_t *) derivationModeDescBuffer;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultModeConstruct, tokenModeConstruct, mcuxClKey_Derivation_ModeConstructor_HKDF(
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("The pointer pDerivationMode points to an object of the right type, the cast was valid.")
      /* mcuxClKey_DerivationMode_t *                      */ pDerivationMode,
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()
      /* const mcuxClKey_DerivationAlgorithmDescriptor_t * */ mcuxClKey_DerivationAlgorithm_HKDF,
      /* mcuxClMac_Mode_t                                  */ hmacSha256, // use this when using mac function as PRF
      /* uint32_t                                         */ 0U // no options for this mode
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_Derivation_ModeConstructor_HKDF) != tokenModeConstruct) || (MCUXCLKEY_STATUS_OK != resultModeConstruct))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Key Derivation                                                         */
    /**************************************************************************/

    /* Set up input parameter structures. */

    MCUXCLBUFFER_INIT_RO(fixedInfoBuf, pSession, fixedInfoConfirm, sizeof(fixedInfoConfirm));
    struct mcuxClKey_DerivationInput inputFixedInfo = {.input=fixedInfoBuf, .size=sizeof(fixedInfoConfirm)};
    struct mcuxClKey_DerivationInput inputSalt = {.input=NULL, .size=0};
    mcuxClKey_DerivationInput_t inputs[] = {inputFixedInfo, inputSalt};

    /* Call key derivation function. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultDeriv, tokenDeriv, mcuxClKey_derivation(
      /* mcuxClSession_Handle_t pSession         */ pSession,
      /* mcuxClKey_Derivation_t derivationMode   */ pDerivationMode,
      /* mcuxClKey_Handle_t derivationKey        */ kMainHandle,
      /* mcuxClKey_DerivationInput_t inputs[]    */ inputs,
      /* uint32_t numberOfInputs                */ 1U,
      /* mcuxClKey_Handle_t derivedKey           */ kConfirmPVHandle
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_derivation) != tokenDeriv) || (MCUXCLKEY_STATUS_OK != resultDeriv))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pConfirmP, kConfirmPV, SPAKE2PLUS_KEYSIZE, SPAKE2PLUS_KEYSIZE)
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pConfirmV, (uint8_t*)(kConfirmPV + SPAKE2PLUS_KEYSIZE), SPAKE2PLUS_KEYSIZE, SPAKE2PLUS_KEYSIZE)

    /* K_shared = KDF(nil, K_main, "SharedKey") */

    /* Set up output structure. */
    uint8_t kShared[SPAKE2PLUS_KEYSIZE];

    /* Create and initialize derivedKey descriptor structure. */
    uint32_t kSharedDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t kSharedHandle = (mcuxClKey_Handle_t) kSharedDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultKeyInit3, tokenKeyInit3, mcuxClKey_init(
      /* mcuxClSession_Handle_t session         */ pSession,
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("The pointer derivedKey points to an object of the right type, the cast was valid.")
      /* mcuxClKey_Handle_t key                 */ kSharedHandle,
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()
      /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Hmac_variableLength,
      /* const uint8_t * pKeyData              */ kShared,
      /* uint32_t keyDataLength                */ sizeof(kShared)
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != tokenKeyInit3) || (MCUXCLKEY_STATUS_OK != resultKeyInit3))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Key Derivation                                                         */
    /**************************************************************************/

    /* Set up input parameter structures. */

    MCUXCLBUFFER_INIT_RO(fixedInfoShareBuf, pSession, fixedInfoShare, sizeof(fixedInfoShare));
    struct mcuxClKey_DerivationInput inputShareFixedInfo = {.input=fixedInfoShareBuf, .size=sizeof(fixedInfoShare)};
    mcuxClKey_DerivationInput_t inputs_share[] = {inputShareFixedInfo, inputSalt};

    /* Call key derivation function. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultDeriv2, tokenDeriv2, mcuxClKey_derivation(
      /* mcuxClSession_Handle_t pSession         */ pSession,
      /* mcuxClKey_Derivation_t derivationMode   */ pDerivationMode,
      /* mcuxClKey_Handle_t derivationKey        */ kMainHandle,
      /* mcuxClKey_DerivationInput_t inputs[]    */ inputs_share,
      /* uint32_t numberOfInputs                */ 1U,
      /* mcuxClKey_Handle_t derivedKey           */ kSharedHandle
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_derivation) != tokenDeriv2) || (MCUXCLKEY_STATUS_OK != resultDeriv2))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    MCUXCLKEY_SPAKE2PLUS_MEMCPY(pKShared, kShared, SPAKE2PLUS_KEYSIZE, SPAKE2PLUS_KEYSIZE)

    /* Clean up created Keys */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_flush, token_flush, mcuxClKey_flush(pSession, kMainHandle));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush) != token_flush) || (MCUXCLKEY_STATUS_OK != result_flush))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_flush, token_flush, mcuxClKey_flush(pSession, kConfirmPVHandle));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush) != token_flush) || (MCUXCLKEY_STATUS_OK != result_flush))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_flush, token_flush, mcuxClKey_flush(pSession, kSharedHandle));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush) != token_flush) || (MCUXCLKEY_STATUS_OK != result_flush))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return MCUXCLEXAMPLE_STATUS_OK;
}

/**
 * @brief Computes relevant confirmation value given the confirmationKeys
 *
 * @param[in]      pSession            Session handle to provide session dependent information
 * @param[in]      pKey                The key to use for computing confirmation value
 * @param[in]      keySize             Size of the provided key in bytes
 * @param[in]      pMessage            The Message used for computing the confirmation value
 * @param[out]     pConfirmation       Computed confirmation value
 *
 * @return MCUXCLEXAMPLE_STATUS_OK on successful completion, MCUXCLEXMAPLE_STATUS_ERROR otherwise
 *
 * @note This example function was created to show the logical split of the SPAKE2+ algorithm into separate stages.
 *       User must ensure proper flow protection of each function on their end.
 */
static bool mcuxClKey_Spake2Plus_ComputeConfirmationValue(
    mcuxClSession_Handle_t pSession,
    mcuxCl_InputBuffer_t pKey,
    const uint32_t keySize,
    mcuxCl_InputBuffer_t pMessage,
    mcuxCl_Buffer_t pConfirmation
) {
    ALIGNED uint8_t tempIn [MCUXCLHMAC_ELS_INPUTBUFFER_LENGTH((MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U) + 1)];
    tempIn[0] = 0x04U;
    MCUXCLKEY_SPAKE2PLUS_MEMCPY(tempIn + 1U, (const uint8_t *) pMessage,
            sizeof(tempIn) - 1U, MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U)

    /* Create and initialize mcuxClKey_Descriptor_t structure. */
    uint32_t key_buffer[8];
    uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    MCUX_CSSL_ANALYSIS_START_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()
    mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) keyDesc;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_REINTERPRET_MEMORY_OF_OPAQUE_TYPES()

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_keyInit, token_keyInit, mcuxClKey_init(
      /* mcuxClSession_Handle_t pSession:                */  pSession,
      MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_INCOMPATIBLE("The pointer key points to an object of the right type, the cast was valid.")
      /* mcuxClKey_Handle_t key:                         */  key,
      MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_INCOMPATIBLE()
      /* const mcuxClKey_Type* type:                     */  mcuxClKey_Type_Hmac_variableLength,
      /* const uint8_t * pKeyData:                      */  pKey,
      /* uint32_t keyDataLength:                        */  keySize));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != token_keyInit) || (MCUXCLKEY_STATUS_OK != result_keyInit))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Load key to memory. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_loadMemory, token_loadMemory, mcuxClKey_loadMemory(pSession,
                                                                       key,
                                                                       key_buffer));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_loadMemory) != token_loadMemory) || (MCUXCLKEY_STATUS_OK != result_loadMemory))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    uint32_t result_size = 0U;
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_ESCAPING_LOCAL_ADDRESS("Address of tempIn is for internal use only and does not escape")
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_mac, token_mac, mcuxClMac_compute(
        /* mcuxClSession_Handle_t session:  */ pSession,
        /* const mcuxClKey_Handle_t key:    */ key,
        /* const mcuxClMac_Mode_t mode:     */ mcuxClMac_Mode_HMAC_SHA2_256_ELS,
        /* mcuxCl_InputBuffer_t pIn:        */ (mcuxCl_InputBuffer_t) tempIn,
        /* uint32_t inLength:              */ MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U + 1U,
        /* mcuxCl_Buffer_t pMac:            */ pConfirmation,
        /* uint32_t * const pMacLength:    */ &result_size
    ));
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_ESCAPING_LOCAL_ADDRESS()

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_compute) != token_mac) || (MCUXCLMAC_STATUS_OK != result_mac))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Clean-up created keys */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_flush, token_flush, mcuxClKey_flush(pSession, key));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush) != token_flush) || (MCUXCLKEY_STATUS_OK != result_flush))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return MCUXCLEXAMPLE_STATUS_OK;
}

MCUXCLEXAMPLE_FUNCTION(mcuxClKey_Spake2Plus_example)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /* Creates the Session Descriptor and relevant curve parameters.          */
    /**************************************************************************/

    /* Create a Session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t pSession = &sessionDesc;
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(pSession,
                                            MAX_CPUWA_SIZE,
                                            MAX_PKCWA_SIZE);

    /** Initialize ELS, MCUXCLELS_RESET_DO_NOT_CANCEL **/
    if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    MCUXCLEXAMPLE_INITIALIZE_PRNG(pSession);

    /* Create buffers for Parameters of the used curve */
    MCUXCLBUFFER_INIT_RO(buffG, NULL, p256_G, sizeof(p256_G));
    MCUXCLBUFFER_INIT_RO(buffA, NULL, p256_A, sizeof(p256_A));
    MCUXCLBUFFER_INIT_RO(buffB, NULL, p256_B, sizeof(p256_B));
    MCUXCLBUFFER_INIT_RO(buffP, NULL, p256_P, sizeof(p256_P));
    MCUXCLBUFFER_INIT_RO(buffN, NULL, p256_N, sizeof(p256_N));

    mcuxClEcc_PointMult_Param_t params =
    {
        .curveParam = (mcuxClEcc_DomainParam_t)
        {
            .pA = buffA,
            .pB = buffB,
            .pP = buffP,
            .pG = buffG,
            .pN = buffN,
            .misc = mcuxClEcc_DomainParam_misc_Pack(32U, 32U)
        },
        .optLen = 0U
    };

    /**************************************************************************/
    /* Offline Registration (RFC9383 Paragraph 3.2)                           */
    /* Derives parameters w0, w1 from the hash of the password and identities */
    /* of protocol participants. For the purpose of this example, w0 and w1   */
    /* are already provided. After this, the registration record L = w1 * P   */
    /* is computed.                                                           */
    /**************************************************************************/
    uint8_t pL[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U];
    MCUXCLBUFFER_INIT(buffL, NULL, pL, sizeof(pL));

    /* Compute L = w1 * P */
    bool status = mcuxClKey_Spake2Plus_Registration(
        /* mcuxClSession_Handle_t         */ &sessionDesc,
        /* mcuxClEcc_PointMult_Param_t*  */ &params,
        /* mcuxCl_Buffer_t                */ buffL
    );

    if (status != MCUXCLEXAMPLE_STATUS_OK) {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(pL, testvec_p256_L, MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Online Authentication (RFC9383 Paragraph 3.3)                          */
    /* Participating parties draw a random secret parameter in [0, p - 1].    */
    /* (Here, these are defined by the testvector). Shared values shareP and  */
    /* shareV are then derived from this secret and registration/curve        */
    /* parameters and exchanged between the parties. Both check the receied   */
    /* values for group membership, and upon success derive shared values     */
    /* Z and V. Finally, both parties construct the protocol transcript TT    */
    /* from these derived values and further context information              */
    /**************************************************************************/

    /* Prover                                                                 */
    /* Computes shareP from secret random parameter x in [0, p-1], which is   */
    /* already provided for the purpose of this example.                      */

    /* ShareP = X = x * P + w0 * M */
    MCUXCLBUFFER_INIT_RO(buffW0, NULL, testvec_p256_w0, sizeof(testvec_p256_w0));
    MCUXCLBUFFER_INIT_RO(buffX, NULL, testvec_p256_x, sizeof(testvec_p256_x));

    uint8_t shareP[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U];
    MCUXCLBUFFER_INIT(buffPointShareP, NULL, shareP, sizeof(shareP));

    status = mcuxClKey_Spake2Plus_ProverInit(
    /* mcuxClSession_Handle_t        */ &sessionDesc,
    /* mcuxClEcc_PointMult_Param_t* */ &params,
    /* mcuxCl_InputBuffer_t          */ buffW0,
    /* mcuxCl_Buffer_t               */ buffPointShareP
    );

    if (status != MCUXCLEXAMPLE_STATUS_OK) {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(shareP, testvec_p256_shareP, MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* The Prover now transmits shareP to the Verifier                        */

    /* Verifier                                                               */
    /* Upon receiving shareP, the Verifier computes values shareV, Z, and V   */
    uint8_t shareV[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U];
    MCUXCLBUFFER_INIT(buffPointShareV, NULL, shareV, sizeof(shareV));

    uint8_t Z_verifier[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U];
    MCUXCLBUFFER_INIT(buffZVerifier, NULL, Z_verifier, sizeof(Z_Verifier));

    uint8_t V_verifier[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U];
    MCUXCLBUFFER_INIT(buffVVerifier, NULL, V_verifier, sizeof(V_Verifier));

    status = mcuxClKey_Spake2Plus_VerifierFinish(
        /* mcuxClSession_Handle_t        */ &sessionDesc,
        /* mcuxClEcc_PointMult_Param_t* */ &params,
        /* mcuxCl_InputBuffer_t          */ buffW0,
        /* mcuxCl_InputBuffer_t          */ (mcuxCl_InputBuffer_t) buffL,
        /* mcuxCl_InputBuffer_t          */ (mcuxCl_InputBuffer_t) buffPointShareP,
        /* mcuxCl_Buffer_t               */ buffPointShareV,
        /* mcuxCl_Buffer_t               */ buffZVerifier,
        /* mcuxCl_Buffer_t               */ buffVVerifier
    );

    if (status != MCUXCLEXAMPLE_STATUS_OK) {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(shareV, testvec_p256_shareV, MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(Z_verifier, testvec_p256_Z, MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(V_verifier, testvec_p256_V, MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* The Verifier now transmits shareV to the Prover                        */

    /* Prover                                                                 */
    /* Upon receiving shareV, the Prover computes values Z and V              */

    /* Z = h * x * (Y - w0 * N) */
    MCUXCLBUFFER_INIT_RO(buffW1, NULL, testvec_p256_w1, sizeof(testvec_p256_w1));

    uint8_t Z_prover[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U];
    uint8_t V_prover[MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U];
    MCUXCLBUFFER_INIT(buffZProver, NULL, Z_prover, sizeof(Z_prover));
    MCUXCLBUFFER_INIT(buffVProver, NULL, V_prover, sizeof(V_prover));

    status = mcuxClKey_Spake2Plus_ProverFinish(
        /* mcuxClSession_Handle_t        */ &sessionDesc,
        /* mcuxClEcc_PointMult_Param_t* */ &params,
        /* mcuxCl_InputBuffer_t          */ buffW0,
        /* mcuxCl_InputBuffer_t          */ buffW1,
        /* mcuxCl_InputBuffer_t          */ (mcuxCl_InputBuffer_t) buffX,
        /* mcuxCl_InputBuffer_t          */ (mcuxCl_InputBuffer_t) buffPointShareV,
        /* mcuxCl_Buffer_t               */ buffZProver,
        /* mcuxCl_Buffer_t               */ buffVProver
    );

    if (status != MCUXCLEXAMPLE_STATUS_OK) {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(Z_prover, testvec_p256_Z, MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2U))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(V_prover, testvec_p256_V, MCUXCLECC_WEIERECC_NIST_P256_SIZE_PRIMEP * 2u))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Prover                                                                 */
    /* Using the computed values as well as protocol parameters, the Prover   */
    /* now constructs their transcript of the protocol run.                   */
    uint8_t TT_Prover[sizeof(testvec_p256_TT)];
    uint64_t TT_bytesWritten = 0;

    status = mcuxClKey_Spake2Plus_getTranscript(
     /* mcuxClSession_Handle_t */ &sessionDesc,
     /* const uint32_t        */ sizeof(testvec_p256_context),
     /* const uint8_t*        */ testvec_p256_context,
     /* const uint64_t        */ sizeof(testvec_p256_idProver),
     /* const uint8_t*        */ testvec_p256_idProver,
     /* const uint64_t        */ sizeof(testvec_p256_idVerifier),
     /* const uint8_t*        */ testvec_p256_idVerifier,
     /* const uint64_t        */ sizeof(testvec_p256_M),
     /* const uint8_t*        */ testvec_p256_M,
     /* const uint64_t        */ sizeof(testvec_p256_N),
     /* const uint8_t*        */ testvec_p256_N,
     /* const uint64_t        */ sizeof(shareP),
     /* const uint8_t*        */ shareP,
     /* const uint64_t        */ sizeof(shareV),
     /* const uint8_t*        */ shareV,
     /* const uint64_t        */ sizeof(Z_prover),
     /* const uint8_t*        */ Z_prover,
     /* const uint64_t        */ sizeof(V_prover),
     /* const uint8_t*        */ V_prover,
     /* const uint64_t        */ sizeof(testvec_p256_w0),
     /* const uint8_t*        */ testvec_p256_w0,
     /* const uint32_t        */ sizeof(TT_Prover),
     /* uint8_t*              */ TT_Prover,
     /* uint64_t*             */ &TT_bytesWritten
    );

    if (status != MCUXCLEXAMPLE_STATUS_OK || TT_bytesWritten != sizeof(testvec_p256_TT)) {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(TT_Prover, testvec_p256_TT, sizeof(testvec_p256_TT)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Verifier                                                               */
    /* Similarly, the Verifier now creates a transcript of the protocol run.  */
    uint8_t TT_Verifier[sizeof(testvec_p256_TT)];
    TT_bytesWritten = 0;

    status = mcuxClKey_Spake2Plus_getTranscript(
     /* mcuxClSession_Handle_t */ &sessionDesc,
     /* const uint32_t        */ sizeof(testvec_p256_context),
     /* const uint8_t*        */ testvec_p256_context,
     /* const uint64_t        */ sizeof(testvec_p256_idProver),
     /* const uint8_t*        */ testvec_p256_idProver,
     /* const uint64_t        */ sizeof(testvec_p256_idVerifier),
     /* const uint8_t*        */ testvec_p256_idVerifier,
     /* const uint64_t        */ sizeof(testvec_p256_M),
     /* const uint8_t*        */ testvec_p256_M,
     /* const uint64_t        */ sizeof(testvec_p256_N),
     /* const uint8_t*        */ testvec_p256_N,
     /* const uint64_t        */ sizeof(shareP),
     /* const uint8_t*        */ shareP,
     /* const uint64_t        */ sizeof(shareV),
     /* const uint8_t*        */ shareV,
     /* const uint64_t        */ sizeof(Z_verifier),
     /* const uint8_t*        */ Z_verifier,
     /* const uint64_t        */ sizeof(V_verifier),
     /* const uint8_t*        */ V_verifier,
     /* const uint64_t        */ sizeof(testvec_p256_w0),
     /* const uint8_t*        */ testvec_p256_w0,
     /* const uint32_t        */ sizeof(TT_Verifier),
     /* uint8_t*              */ TT_Verifier,
     /* uint64_t*             */ &TT_bytesWritten
    );

    if (status != MCUXCLEXAMPLE_STATUS_OK || TT_bytesWritten != sizeof(testvec_p256_TT)) {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(TT_Verifier, testvec_p256_TT, sizeof(testvec_p256_TT)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Key Schedule and Key Confirmation (RFC9383 Paragraph 3.4)              */
    /* Participating parties now derive a key K_Main from the hash of the     */
    /* protocol transcript TT, followed by a pair of confirmation keys        */
    /* derived using a Key-Derivation Function (as specified by the used      */
    /* Ciphersuite) from K_Main and the fixed input "Confirmation Keys".      */
    /* Finally, a final Shared Key K_shared is derived in the same manner,    */
    /* Using constant input "SharedKey" instead. Then, each party             */
    /* authenticates their respective confirmation key, and sends this MAC    */
    /* to the other party to verify. Only after this confirmation, K_shared   */
    /* is valid an may be used for deriving further keys or similar.          */
    /**************************************************************************/

    /* Prover                                                                 */
    /* The Prover now computes the Key Schedule, deriving two confirmation,   */
    /* as well as one shared key.                                             */ 

    MCUXCLBUFFER_INIT_RO(buffTTProver, session, TT_Prover, sizeof(TT_Prover));

    uint8_t kConfirmP_prover[32];
    uint8_t kConfirmV_prover[32];
    uint8_t kShared_prover[32];
    MCUXCLBUFFER_INIT(buffKConfirmP_prover, NULL, kConfirmP_prover, sizeof(kConfirmP_prover));
    MCUXCLBUFFER_INIT(buffKConfirmV_prover, NULL, kConfirmV_prover, sizeof(kConfirmV_prover));
    MCUXCLBUFFER_INIT(buffKShared_prover, NULL, kShared_prover, sizeof(kShared_prover));

    status = mcuxClKey_Spake2Plus_ComputeKeySchedule(
        /* mcuxClSession_Handle_t     */ pSession,
        /* mcuxCl_InputBuffer_t       */ buffTTProver,
        /* uint32_t                  */ sizeof(TT_Prover),
        /* mcuxCl_Buffer_t            */ buffKConfirmP_prover,
        /* mcuxCl_Buffer_t            */ buffKConfirmV_prover,
        /* mcuxCl_Buffer_t            */ buffKShared_prover
    );

    if (status != MCUXCLEXAMPLE_STATUS_OK) {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(kConfirmP_prover, testvec_p256_K_confirmP, sizeof(testvec_p256_K_confirmP)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(kConfirmV_prover, testvec_p256_K_confirmV, sizeof(testvec_p256_K_confirmV)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(kShared_prover, testvec_p256_K_shared, sizeof(testvec_p256_K_shared)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Verifier                                                               */
    /* The Verifier also computes the Key Schedule                            */

    MCUXCLBUFFER_INIT_RO(buffTTVerifier, session, TT_Verifier, sizeof(TT_Verifier));

    /* Set up output structure. */
    uint8_t kConfirmP_verifier[32];
    uint8_t kConfirmV_verifier[32];
    uint8_t kShared_verifier[32];
    MCUXCLBUFFER_INIT(buffKConfirmP_verifier, NULL, kConfirmP_verifier, sizeof(kConfirmP_verifier));
    MCUXCLBUFFER_INIT(buffKConfirmV_verifier, NULL, kConfirmV_verifier, sizeof(kConfirmV_verifier));
    MCUXCLBUFFER_INIT(buffKShared_verifier, NULL, kShared_verifier, sizeof(kShared_verifier));

    status = mcuxClKey_Spake2Plus_ComputeKeySchedule(
        /* mcuxClSession_Handle_t     */ pSession,
        /* mcuxCl_InputBuffer_t       */ buffTTVerifier,
        /* uint32_t                  */ sizeof(TT_Verifier),
        /* mcuxCl_Buffer_t            */ buffKConfirmP_verifier,
        /* mcuxCl_Buffer_t            */ buffKConfirmV_verifier,
        /* mcuxCl_Buffer_t            */ buffKShared_verifier
    );

    if (status != MCUXCLEXAMPLE_STATUS_OK) {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(kConfirmP_verifier, testvec_p256_K_confirmP, sizeof(testvec_p256_K_confirmP)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(kConfirmV_verifier, testvec_p256_K_confirmV, sizeof(testvec_p256_K_confirmV)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(kShared_verifier, testvec_p256_K_shared, sizeof(testvec_p256_K_shared)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }


    /* Verifier                                                               */
    /* The Verifier now computes confirmV, which is sent to the Prover        */

    /* confirmV = MAC(K_confirmV, X) */
    uint8_t confirmVVerifier[MCUXCLHMAC_ELS_OUTPUT_SIZE];
    MCUXCLBUFFER_INIT(buffConfirmVVerifier, NULL, confirmVVerifier, sizeof(confirmVVerifier));

    status = mcuxClKey_Spake2Plus_ComputeConfirmationValue(
    /* mcuxClSession_Handle_t     */ pSession,
    /* mcuxCl_InputBuffer_t       */ (mcuxCl_InputBuffer_t) buffKConfirmV_verifier,
    /* const uint32_t            */ sizeof(kConfirmV_verifier),
    /* mcuxCl_InputBuffer_t       */ (mcuxCl_InputBuffer_t) buffPointShareP,
    /* mcuxCl_Buffer_t            */ buffConfirmVVerifier
    );

    if (status != MCUXCLEXAMPLE_STATUS_OK) {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(confirmVVerifier, testvec_p256_confirmV, sizeof(testvec_p256_confirmV)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Prover                                                                 */
    /* The Prover derives the expected value of confirm V, and upon receipt   */
    /* compares it to the value provided. In case of a mismatch, the protocol */
    /* is aborted.                                                            */

    /* expectedConfirmV = MAC(K_confirmV, ShareP) */
    uint8_t confirmVProver[MCUXCLHMAC_ELS_OUTPUT_SIZE];
    MCUXCLBUFFER_INIT(buffConfirmVProver, NULL, confirmVProver, sizeof(confirmVProver));

    status = mcuxClKey_Spake2Plus_ComputeConfirmationValue(
    /* mcuxClSession_Handle_t     */ pSession,
    /* mcuxCl_InputBuffer_t       */ (mcuxCl_InputBuffer_t) buffKConfirmV_prover,
    /* const uint32_t            */ sizeof(kConfirmV_prover),
    /* mcuxCl_InputBuffer_t       */ (mcuxCl_InputBuffer_t) buffPointShareP,
    /* mcuxCl_Buffer_t            */ buffConfirmVProver
    );

    if (status != MCUXCLEXAMPLE_STATUS_OK) {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(confirmVProver, confirmVVerifier, sizeof(confirmVVerifier)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }


    /* Prover                                                                 */
    /* The Prover computes confirmP, which is sent to the verifier            */
    uint8_t confirmPProver[MCUXCLHMAC_ELS_OUTPUT_SIZE];
    MCUXCLBUFFER_INIT(buffConfirmPProver, NULL, confirmPProver, sizeof(confirmPProver));

    status = mcuxClKey_Spake2Plus_ComputeConfirmationValue(
    /* mcuxClSession_Handle_t     */ pSession,
    /* mcuxCl_InputBuffer_t       */ (mcuxCl_InputBuffer_t) buffKConfirmP_prover,
    /* const uint32_t            */ sizeof(kConfirmP_prover),
    /* mcuxCl_InputBuffer_t       */ (mcuxCl_InputBuffer_t) buffPointShareV,
    /* mcuxCl_Buffer_t            */ buffConfirmPProver
    );

    if (status != MCUXCLEXAMPLE_STATUS_OK) {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(confirmPProver, testvec_p256_confirmP, sizeof(testvec_p256_confirmP)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Verifier                                                               */
    /* The Verifier derives the expected value of confirm V, and upon receipt */
    /* compares it to the value provided. In case of a mismatch, the protocol */
    /* is aborted.                                                            */

    /* expected_confirmP = MAC(K_confirmP, shareV) */
    uint8_t confirmPVerifier[MCUXCLHMAC_ELS_OUTPUT_SIZE];
    MCUXCLBUFFER_INIT(buffConfirmPVerifier, NULL, confirmPVerifier, sizeof(confirmPVerifier));

    status = mcuxClKey_Spake2Plus_ComputeConfirmationValue(
    /* mcuxClSession_Handle_t     */ pSession,
    /* mcuxCl_InputBuffer_t       */ (mcuxCl_InputBuffer_t) buffKConfirmP_verifier,
    /* const uint32_t keySize    */ sizeof(kConfirmP_verifier),
    /* mcuxCl_InputBuffer_t       */ (mcuxCl_InputBuffer_t) buffPointShareV,
    /* mcuxCl_Buffer_t            */ buffConfirmPVerifier
    );

    if (status != MCUXCLEXAMPLE_STATUS_OK) {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClCore_assertEqual(confirmPVerifier, confirmPProver, sizeof(confirmPProver)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* After Confirmation, the protocol has successfully concluded, and keys  */
    /* may be derive from KShared.                                            */

    /**************************************************************************/
    /* Cleanup                                                                */
    /* Dispose of Session and disable ELS                                     */
    /**************************************************************************/

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(cleanup_result, cleanup_token, mcuxClSession_cleanup(
         /* mcuxClSession_Handle_t           pSession: */           pSession));
    if(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != cleanup_token || MCUXCLSESSION_STATUS_OK != cleanup_result)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(destroy_result, destroy_token, mcuxClSession_destroy(
         /* mcuxClSession_Handle_t           pSession: */           pSession));
    if(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != destroy_token || MCUXCLSESSION_STATUS_OK != destroy_result)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Disable ELS */
    if(!mcuxClExample_Els_Disable())
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    return MCUXCLEXAMPLE_STATUS_OK;
}
