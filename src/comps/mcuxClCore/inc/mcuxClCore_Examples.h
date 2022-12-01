/*--------------------------------------------------------------------------*/
/* Copyright 2020-2022 NXP                                                  */
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
/* Security Classification:  Company Confidential                           */
/*--------------------------------------------------------------------------*/

#ifndef MCUX_CL_CORE_EXAMPLES_H_
#define MCUX_CL_CORE_EXAMPLES_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>

/**
 * \def MCUX_CL_EXAMPLE_FUNCTION
 * \brief Macro to indicate that the symbol is an example function.
 */
// TODO CLNS-3599: #define MCUX_CL_EXAMPLE_FUNCTION(_name) uint32_t _name(void)
#define MCUX_CL_EXAMPLE_FUNCTION(_name) bool _name(void)

/**
 * \def MCUX_CL_EXAMPLE_OK
 * \brief Example execution completed successfully.
 */
#define MCUX_CL_EXAMPLE_OK      true // TODO CLNS-3599: 0xC001C0DEu

/**
 * \def MCUX_CL_EXAMPLE_ERROR
 * \brief Example execution resulted in an unexpected error.
 */
#define MCUX_CL_EXAMPLE_ERROR   false // TODO CLNS-3599: 0xEEEEEEEEu

/**
 * \def MCUX_CL_EXAMPLE_FAILURE
 * \brief Example execution resulted in an expected failure.
 */
#define MCUX_CL_EXAMPLE_FAILURE  false // TODO CLNS-3599: 0xFFFFFFFFu

/**
 * \brief Macro to calculate the maximum of two values.
 */
#define MCUX_CL_EXAMPLE_MAX( x, y ) ( ( x ) > ( y ) ? ( x ) : ( y ) )

/**
 * \brief Assert whether two buffers are equal.
 */
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

#endif /* MCUX_CL_CORE_EXAMPLES_H_ */
