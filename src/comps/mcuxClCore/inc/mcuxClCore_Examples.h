/*--------------------------------------------------------------------------*/
/* Copyright 2020-2023 NXP                                                  */
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

#ifndef MCUXCLCORE_EXAMPLES_H_
#define MCUXCLCORE_EXAMPLES_H_

#include <mcuxClCore_Platform.h>
#include <mcuxClCore_Macros.h>
#include <mcuxCsslFlowProtection.h>


/**
 * \def MCUXCLEXAMPLE_FUNCTION
 * \brief Macro to indicate that the symbol is an example function.
 */
// TODO CLNS-3599: #define MCUXCLEXAMPLE_FUNCTION(_name) uint32_t _name(void)
#define MCUXCLEXAMPLE_FUNCTION(_name) \
MCUX_CSSL_ANALYSIS_START_PATTERN_EXAMPLE_FUNCTION() \
uint32_t  _name(void) \
MCUX_CSSL_ANALYSIS_STOP_PATTERN_EXAMPLE_FUNCTION()

/**
 * \def MCUXCLEXAMPLE_STATUS_OK
 * \brief Example execution completed successfully.
 */
#define MCUXCLEXAMPLE_STATUS_OK      0

/**
 * \def MCUXCLEXAMPLE_OK
 * \brief Example execution completed successfully.
 * \deprecated{Replaced by MCUXCLEXAMPLE_STATUS_OK}
 */
#define MCUXCLEXAMPLE_OK      MCUXCLEXAMPLE_STATUS_OK

/**
 * An example status word packs an error class in the most-significant byte and
 * the source line number in the least-significant bytes:
 *
 *   bits [31:24] = error class (0xEE = errored, 0xFF = failed)
 *   bits [15:0]  = __LINE__ where the status was produced
 *
 * Use the class defines and the mask/accessor macros below to inspect a status
 * word (e.g. mask out the line number to obtain the error class); do not compare
 * against MCUXCLEXAMPLE_STATUS_ERROR / MCUXCLEXAMPLE_STATUS_FAILURE directly, as
 * those embed the line number.
 */

/**
 * \def MCUXCLEXAMPLE_STATUS_CLASS_ERROR
 * \brief Error class for an unexpected error (occupies the status class byte).
 */
#define MCUXCLEXAMPLE_STATUS_CLASS_ERROR    0xEEu

/**
 * \def MCUXCLEXAMPLE_STATUS_CLASS_FAILURE
 * \brief Error class for an expected failure (occupies the status class byte).
 */
#define MCUXCLEXAMPLE_STATUS_CLASS_FAILURE  0xFFu

/**
 * \def MCUXCLEXAMPLE_STATUS_CLASS_SHIFT
 * \brief Bit position of the error class within a status word.
 */
#define MCUXCLEXAMPLE_STATUS_CLASS_SHIFT    24u

/**
 * \def MCUXCLEXAMPLE_STATUS_CLASS_MASK
 * \brief Mask selecting the error class byte of a status word.
 */
#define MCUXCLEXAMPLE_STATUS_CLASS_MASK     0xFF000000u

/**
 * \def MCUXCLEXAMPLE_STATUS_LINE_MASK
 * \brief Mask selecting the embedded line number of a status word.
 */
#define MCUXCLEXAMPLE_STATUS_LINE_MASK      0x0000FFFFu

/**
 * \def MCUXCLEXAMPLE_STATUS_GET_CLASS
 * \brief Extract the error class from a status word (masks out the line number).
 */
#define MCUXCLEXAMPLE_STATUS_GET_CLASS(_status)  (((_status) & MCUXCLEXAMPLE_STATUS_CLASS_MASK) >> MCUXCLEXAMPLE_STATUS_CLASS_SHIFT)

/**
 * \def MCUXCLEXAMPLE_STATUS_GET_LINE
 * \brief Extract the embedded line number from a status word.
 */
#define MCUXCLEXAMPLE_STATUS_GET_LINE(_status)   ((_status) & MCUXCLEXAMPLE_STATUS_LINE_MASK)

/**
 * \def MCUXCLEXAMPLE_STATUS_ERROR
 * \brief Example execution resulted in an unexpected error.
 */
#define MCUXCLEXAMPLE_STATUS_ERROR   ((MCUXCLEXAMPLE_STATUS_CLASS_ERROR << MCUXCLEXAMPLE_STATUS_CLASS_SHIFT) | (__LINE__ & MCUXCLEXAMPLE_STATUS_LINE_MASK))

/**
 * \def MCUXCLEXAMPLE_ERROR
 * \brief Example execution resulted in an unexpected error.
 * \deprecated{Replaced by MCUXCLEXAMPLE_STATUS_ERROR}
 */
#define MCUXCLEXAMPLE_ERROR   MCUXCLEXAMPLE_STATUS_ERROR


/**
 * \def MCUXCLEXAMPLE_STATUS_FAILURE
 * \brief Example execution resulted in an expected failure.
 */
#define MCUXCLEXAMPLE_STATUS_FAILURE  ((MCUXCLEXAMPLE_STATUS_CLASS_FAILURE << MCUXCLEXAMPLE_STATUS_CLASS_SHIFT) | (__LINE__ & MCUXCLEXAMPLE_STATUS_LINE_MASK))

/**
 * \def MCUXCLEXAMPLE_FAILURE
 * \brief Example execution resulted in an expected failure.
 * \deprecated{Replaced by MCUXCLEXAMPLE_STATUS_FAILURE}
 */
#define MCUXCLEXAMPLE_FAILURE  MCUXCLEXAMPLE_STATUS_FAILURE

/**
 * \brief Assert whether two buffers are equal.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClCore_assertEqual)
static inline bool mcuxClCore_assertEqual(const uint8_t * const x, const uint8_t * const y, uint32_t length)
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

#endif /* MCUXCLCORE_EXAMPLES_H_ */
