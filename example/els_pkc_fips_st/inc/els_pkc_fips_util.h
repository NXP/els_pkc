/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _ELS_PKC_FIPS_UTIL_H_
#define _ELS_PKC_FIPS_UTIL_H_

#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include <board.h>
#include <mcuxClAes.h>                      /* Interface to AES-related definitions and types */
#include <mcuxClEls.h>                      /* Interface to the entire mcuxClEls component */
#include <mcuxClSession.h>                  /* Interface to the entire mcuxClSession component */
#include <mcuxClKey.h>                      /* Interface to the entire mcuxClKey component */
#include <mcuxClCore_FunctionIdentifiers.h> /* Code flow protection */
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClExample_RNG_Helper.h>
#include <mcuxClExample_ELS_Helper.h>
#include <mcuxClExample_Key_Helper.h>
#include <mcuxClAes_Constants.h>
#include <mcuxClExample_ELS_Helper.h>

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#ifndef SHOW_DEBUG_OUTPUT
#define SHOW_DEBUG_OUTPUT true
#endif /* SHOW_DEBUG_OUTPUT */

#define PRINT_ARRAY(array, array_size)                                                            \
    do                                                                                            \
    {                                                                                             \
        PRINTF("0x");                                                                             \
        for (uint64_t print_array_index = 0U; print_array_index < array_size; ++print_array_index) \
        {                                                                                         \
            PRINTF("%02X", array[print_array_index]);                                             \
        }                                                                                         \
        PRINTF("\r\n");                                                                           \
    } while (0U);

#endif /* _ELS_PKC_FIPS_UTIL_H_ */
