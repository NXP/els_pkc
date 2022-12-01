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

#ifndef MCUX_CL_EXAMPLE_SESSION_HELPER_H_
#define MCUX_CL_EXAMPLE_SESSION_HELPER_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCore_Platform.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClPkc.h>
/**
 * Init Session via mcuxClSession_init via mcuxClSession_init.
 * [in]  pSession     : Pointer to the session handle.
 * [in]  cpuWaLength  : Size of the workarea for CPU operations.
 * [in]  pkcWaLength  : Size of the workarea for PKC operations.
*/
#define MCUXCLEXAMPLE_ALLOCATE_CPUWA(cpuWaLength) (cpuWaLength?cpuWaLength:1u)  // always allocate a minimum size buffer to avoid issues
#define MCUXCLEXAMPLE_ALLOCATE_PKCWA(pkcWaLength) (pkcWaLength?pkcWaLength:1u)  // always allocate a minimum size buffer to avoid issues

#define MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(pSession, cpuWaLength, pkcWaLength)                              \
        uint32_t cpuWaBuffer[MCUXCLEXAMPLE_ALLOCATE_CPUWA(cpuWaLength)];                                               \
        MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(si_status, token, mcuxClSession_init(                                          \
            /* mcuxClSession_Handle_t session:      */ pSession,                                                       \
            /* uint32_t * const cpuWaBuffer:       */ cpuWaBuffer,                                                    \
            /* uint32_t cpuWaSize:                 */ cpuWaLength,                                                    \
            /* uint32_t * const pkcWaBuffer:       */ (uint32_t *) MCUXCLPKC_RAM_START_ADDRESS,                        \
            /* uint32_t pkcWaSize:                 */ pkcWaLength                                                     \
            ));                                                                                                       \
        /* mcuxClSession_init is a flow-protected function: Check the protection token and the return value */         \
        if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != token) || (MCUXCLSESSION_STATUS_OK != si_status))        \
        {                                                                                                             \
            return false;                                                                                             \
        }                                                                                                             \
        MCUX_CSSL_FP_FUNCTION_CALL_END();

/**
 * Destroy Session and cleanup Session via mcuxClSession_cleanup and mcuxClSession_destroy
 * [in]  pSession: Pointer to the session handle.
 **/
static inline bool mcuxClExample_Session_Clean(mcuxClSession_Handle_t pSession)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(cleanup_result, cleanup_token, mcuxClSession_cleanup(pSession));

    if(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != cleanup_token || MCUXCLSESSION_STATUS_OK != cleanup_result)
    {
        return false;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(destroy_result, destroy_token, mcuxClSession_destroy(pSession));

    if(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != destroy_token || MCUXCLSESSION_STATUS_OK != destroy_result)
    {
        return false;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();
    return true;
}

#endif /* MCUX_CL_EXAMPLE_SESSION_HELPER_H_ */
