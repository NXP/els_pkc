/*--------------------------------------------------------------------------*/
/* Copyright 2021-2022 NXP                                                  */
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

/**
 * @file  mcuxClRandom_Private_Types.h
 * @brief Private type definitions of mcuxClRandom component
 */


#ifndef MCUX_CL_RANDOM_PRIVATE_TYPES_H_
#define MCUX_CL_RANDOM_PRIVATE_TYPES_H_


#include <stdint.h>
#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClSession.h>
#include <mcuxClRandom_Types.h>

#include <internal/mcuxClRandom_Private_Drbg.h>
#ifdef __cplusplus
extern "C" {
#endif

/**********************************************************/
/* Private types of mcuxClRandom                           */
/**********************************************************/
/**
 * @defgroup mcuxClRandom_Private_Types mcuxClRandom_Private_Types
 * @brief Defines all private types of @ref mcuxClRandom
 * @ingroup mcuxClRandom_Private
 * @{
 */

/**
 * @brief Function prototype for init function pointer in OperationMode structure.
 */
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) (* mcuxClRandom_initFunction_t)(mcuxClSession_Handle_t session);

/**
 * @brief Function prototype for reseed function pointer in OperationMode structure.
 */
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) (*mcuxClRandom_reseedFunction_t)(mcuxClSession_Handle_t session);

/**
 * @brief Function prototype for generate function pointer in OperationMode structure.
 */
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) (*mcuxClRandom_generateFunction_t)(mcuxClSession_Handle_t session,
                                                                                           uint8_t * pOut,
                                                                                           uint32_t outLength);

/**
 * @brief Function prototype for selftest function pointer in OperationMode structure.
 */
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) (*mcuxClRandom_selftestFunction_t)(mcuxClSession_Handle_t session,
                                                                                           mcuxClRandom_Mode_t mode);


/**
 * @brief Random operation mode descriptor structure
 *
 * This structure is used to store all information needed in the top level Random DRBG functions,
 * determines which mode the DRBG shall be operated in (normal, test or patch mode) and specifies
 * pointers to functions implementing the DRBG in the chosen operation mode.
 */
typedef struct mcuxClRandom_OperationModeDescriptor mcuxClRandom_OperationModeDescriptor_t;
struct mcuxClRandom_OperationModeDescriptor
{
    /* Function pointers for DRBG functions */
    mcuxClRandom_initFunction_t initFunction;          ///< Function to be called for DRBG instantiation depending on the chosen operationMode
    mcuxClRandom_reseedFunction_t reseedFunction;      ///< Function to be called for DRBG reseeding depending on the chosen operationMode
    mcuxClRandom_generateFunction_t generateFunction;  ///< Function to be called for DRBG random number generation depending on the chosen operationMode
    mcuxClRandom_selftestFunction_t selftestFunction;  ///< Function to be called for DRBG self testing depending on the chosen operationMode

    /* Protection tokens for DRBG functions */
    uint32_t protectionTokenInitFunction;             ///< Protection token of DRBG init function
    uint32_t protectionTokenReseedFunction;           ///< Protection token of DRBG reseed function
    uint32_t protectionTokenGenerateFunction;         ///< Protection token of DRBG generate function
    uint32_t protectionTokenSelftestFunction;         ///< Protection token of DRBG selftest function

    /* Operation mode definition */
    uint32_t operationMode;                           ///< operationMode
};

/**
 * @brief Random DRBG mode descriptor structure
 *
 * This structure contains all DRBG information required to execute the DRBG specific algorithms.
 */
//typedef struct mcuxClRandom_DrbgModeDescriptor mcuxClRandom_DrbgModeDescriptor_t;
//struct mcuxClRandom_DrbgModeDescriptor;

/**
 * @brief Random mode descriptor structure
 *
 * This structure stores all information needed to operate a DRBG in the chosen mode.
 */
struct mcuxClRandom_ModeDescriptor
{
    const mcuxClRandom_OperationModeDescriptor_t *pOperationMode;  ///< pointer to top level information about the DRBG mode operated in (NORMALMODE, TESTMODE, CSSMODE, PATCHMODE)
    mcuxClRandom_DrbgModeDescriptor_t *pDrbgMode;                  ///< pointer to DRBG specific information depending on the chosen mode
    uint32_t auxParam;                                            ///< auxiliary parameter depending on the chosen mode
    uint32_t contextSize;                                         ///< size of context
    uint16_t securityStrength;                                    ///< supported security strength of DRBG
};

/**
 * @}
 */ /* mcuxClRandom_Private_Types */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUX_CL_RANDOM_PRIVATE_TYPES_H_ */
