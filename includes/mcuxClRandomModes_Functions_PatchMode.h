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
/* Security Classification:  Company Confidential                           */
/*--------------------------------------------------------------------------*/

#ifndef MCUXCLRANDOM_FUNCTIONS_PATCHMODE_H_
#define MCUXCLRANDOM_FUNCTIONS_PATCHMODE_H_

#include <mcuxClConfig.h> // Exported features flags header

#include <mcuxClSession.h>
#include <mcuxClRandom_Types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup mcuxClAPI MCUX CL -- API
 *
 * \defgroup mcuxClRandomPatchMode Random PATCH_MODE API
 * \brief Random operations in PATCH_MODE.
 * \ingroup mcuxClAPI
 */

/**
 * \defgroup clRandomPatchMode Random interfaces
 * \brief Interfaces to perform Random handling operations.
 * \ingroup mcuxClRandom
 */

/* Interface definition for a custom RNG function */
typedef mcuxClRandom_Status_t (* mcuxClRandomModes_CustomGenerateAlgorithm_t)(
    mcuxClRandom_Context_t *pCustomCtx,
    uint32_t *pCpuWa,
    uint8_t *pOut,
    uint32_t outLength
);

/**
 * \brief This function creates a PATCH_MODE descriptor
 * \api
 * \ingroup clRandom
 *
 * This function creates a PATCH_MODE descriptor.
 * The function expects as input a custom function to be used inside the CL functions for random number generation as well as
 * a pointer to a context buffer which can be used by the custom generate function.
 * The custom generate function may also use all CPU workarea allocated for the mcuxClRandom_generate function.
 * The function shall be called prior to an mcuxClRandom_init call.
 *
 * \param  patchMode[out]               Pointer to PATCH_MODE descriptor to be initialized
 * \param  customGenerateAlgorithm[in]  Pointer to the custom generate function
 * \param  pEntropyInput[in]            Pointer to a custom context which shall be used by the passed custom generate function
 * \param  securityStrength[in]         Security level for which the patch DRBG shall be used
 *
 * \return status
 */

mcuxClRandom_Status_t mcuxClRandomModes_createPatchMode(
    mcuxClRandom_Mode_t patchMode,
    mcuxClRandomModes_CustomGenerateAlgorithm_t customGenerateAlgorithm,
    mcuxClRandom_Context_t *pCustomCtx,
    uint32_t securityStrength
);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLRANDOM_FUNCTIONS_PATCHMODE_H_ */
