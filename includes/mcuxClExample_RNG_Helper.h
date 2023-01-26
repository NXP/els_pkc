/*--------------------------------------------------------------------------*/
/* Copyright 2022 NXP                                                       */
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

#ifndef MCUXCLEXAMPLE_RNG_HELPER_H_
#define MCUXCLEXAMPLE_RNG_HELPER_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>
#include <mcuxClRandom.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

/**
 * Random data generator and Non-cryptographic PRNG initialization function via mcuxClRandom_init and mcuxClRandom_ncInit.
 * [in]     pSession   Handle for the current CL session.
 * [in]     pContext   Pointer to a Random data context buffer large enough
 * [in]     mode       Mode of operation for random data generator.
 **/

#define MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_RNG(pSession, contextSize, mode)                                                \
    mcuxClRandom_Context_t rng_ctx = NULL;                                                                                    \
    /* Initialize the RNG context */                                                                                         \
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomInit_result, randomInit_token, mcuxClRandom_init(pSession,                          \
                                                               rng_ctx,                                                      \
                                                               mode));                                                       \
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init) != randomInit_token) || (MCUXCLRANDOM_STATUS_OK != randomInit_result))  \
    {                                                                                                                        \
        return false;                                                                                                        \
    }                                                                                                                        \
    MCUX_CSSL_FP_FUNCTION_CALL_END();                                                                                         \
    /* Initialize the PRNG */                                                                                                \
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(prngInit_result, prngInit_token, mcuxClRandom_ncInit(pSession));                          \
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != prngInit_token) || (MCUXCLRANDOM_STATUS_OK != prngInit_result))    \
    {                                                                                                                        \
        return false;                                                                                                        \
    }                                                                                                                        \
    MCUX_CSSL_FP_FUNCTION_CALL_END();

#endif /* MCUXCLEXAMPLE_RNG_HELPER_H_ */