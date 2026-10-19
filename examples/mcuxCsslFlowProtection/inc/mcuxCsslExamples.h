/*--------------------------------------------------------------------------*/
/* Copyright 2020-2022 NXP                                                  */
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

#ifndef MCUX_CSSL_EXAMPLES_H_
#define MCUX_CSSL_EXAMPLES_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define MCUX_CSSL_EX_FUNCTION(_name) __attribute__((section(".example"))) uint32_t _name(void)

/* Packed example status word: bits[31:24] = class (0xEE = error), bits[15:0] = line number.
 * Mirrors the MCUXCLEXAMPLE_STATUS_* scheme in mcuxClCore_Examples.h, but is defined locally
 * since mcuxCssl is a dependency of mcuxClCore and must not include its headers. */
#define MCUX_CSSL_EX_STATUS_CLASS_ERROR  0xEEu
#define MCUX_CSSL_EX_STATUS_CLASS_SHIFT  24u
#define MCUX_CSSL_EX_STATUS_LINE_MASK    0x0000FFFFu

#define MCUX_CSSL_EX_OK    0u
#define MCUX_CSSL_EX_ERROR (((uint32_t) MCUX_CSSL_EX_STATUS_CLASS_ERROR << MCUX_CSSL_EX_STATUS_CLASS_SHIFT) | ((uint32_t) __LINE__ & MCUX_CSSL_EX_STATUS_LINE_MASK))

static inline bool mcuxCsslExamples_assertEqual(const uint8_t * const x, const uint8_t * const y, uint32_t length)
{
  for (uint32_t i = 0; i < length; ++i)
  { 
  	if (x[i] != y[i]) 
  	{ 
  	  return false;
  	} 
  }

  return true;
}

MCUX_CSSL_EX_FUNCTION(mcuxCsslFlowProtection_example);

#endif /* MCUX_CSSL_EXAMPLES_H_ */
