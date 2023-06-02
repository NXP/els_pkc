/*--------------------------------------------------------------------------*/
/* Copyright 2020, 2022-2023 NXP                                            */
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
 * @file  mcuxClEls_Hash_HW_Security_Counter_example.c
 * @brief Example of SHA2-256 hashing using the ELS (CLNS component mcuxClEls)
 *
 * @example mcuxClEls_Hash_HW_Security_Counter_example.c
 * @brief   Example of SHA2-256 hashing using the ELS (CLNS component mcuxClEls)
 */
#include <mcuxClEls.h> // Interface to the entire mcuxClEls component
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_ELS_Helper.h>

/** Data input for SHA2-256 hashing. */
static uint8_t const sha256_padded_input[MCUXCLELS_HASH_BLOCK_SIZE_SHA_256] = {0x61U, 0x62U, 0x63U, 0x80U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00u, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x00U,
                                                                              0x00U, 0x00U, 0x00U, 0x18U};

/** Expected hash value. */
static uint8_t sha256_reference_digest[MCUXCLELS_HASH_OUTPUT_SIZE_SHA_256] = {0xBAU, 0x78U, 0x16U, 0xBFU,
                                                                             0x8FU, 0x01U, 0xCFU, 0xEAU,
                                                                             0x41U, 0x41U, 0x40U, 0xDEU,
                                                                             0x5DU, 0xAEU, 0x22U, 0x23U,
                                                                             0xB0U, 0x03U, 0x61U, 0xA3U,
                                                                             0x96U, 0x17U, 0x7AU, 0x9CU,
                                                                             0xB4U, 0x10U, 0xFFU, 0x61U,
                                                                             0xF2U, 0x00U, 0x15U, 0xADU};

/** Destination buffer to receive the hash output of the SHA2-256 hashing. */
static uint8_t sha2_256_digest[MCUXCLELS_HASH_STATE_SIZE_SHA_256]; // MCUXCLELS_HASH_STATE_SIZE_SHA_256 has to be used as the mcuxClEls_Hash_Async do not perform the truncation of the hash state.


#define kCDOG_LockCtrl_Unlock 2U
#define kCDOG_FaultCtrl_EnableReset 1U
#define kCDOG_IrqPauseCtrl_Run 1U
#define kCDOG_DebugHaltCtrl_Pause 2U

/** Performs SHA2-256 hashing using mcuxClEls functions.
 * @retval MCUXCLEXAMPLE_OK    The example code completed successfully
 * @retval MCUXCLEXAMPLE_ERROR The example code failed */
MCUXCLEXAMPLE_FUNCTION(mcuxClEls_Hash_HW_Security_Counter_example)
{
    // Watchdog setup
    // Clear pending errors, otherwise the device will rest itself immediately after enable Code Watchdog
    if (kCDOG_LockCtrl_Unlock == ((CDOG0->CONTROL & CDOG_CONTROL_LOCK_CTRL_MASK) >> CDOG_CONTROL_LOCK_CTRL_SHIFT))
    {
        CDOG0->FLAGS = 0;
    }
    else
    {
        CDOG0->FLAGS = 0xFFFFFFFFu;
    }

    CDOG0->RELOAD = 0xFFFFFFFFu;
    /* Do not lock the CDOG, so the customer can use it as well after leaving ROM */
    CDOG0->CONTROL = 
        CDOG_CONTROL_LOCK_CTRL(kCDOG_LockCtrl_Unlock) | /* Do not take action for the timeout operation because some
                                                           operation may be time-consuming and
                                                           the timeout is as expected
                                                         */
        CDOG_CONTROL_TIMEOUT_CTRL(kCDOG_FaultCtrl_EnableReset) | /* Enable Reset if the timeout event is triggered  */
        CDOG_CONTROL_MISCOMPARE_CTRL(
            kCDOG_FaultCtrl_EnableReset) | /* Enable Reset if the sequence error event is triggered  */
        CDOG_CONTROL_SEQUENCE_CTRL(
            kCDOG_FaultCtrl_EnableReset) | /* Enable Reset if the control error event is triggered  */
        CDOG_CONTROL_CONTROL_CTRL(
            kCDOG_FaultCtrl_EnableReset) | /* Enable Reset if the state error event is triggered  */
        CDOG_CONTROL_STATE_CTRL(
            kCDOG_FaultCtrl_EnableReset) | /* Enable Reset if the address error event is triggered  */
        CDOG_CONTROL_ADDRESS_CTRL(kCDOG_FaultCtrl_EnableReset) | /* Keep running during interrupts */
        CDOG_CONTROL_IRQ_PAUSE(
            kCDOG_IrqPauseCtrl_Run) | /* Halt CDOG timer during debug so we have chance to debug ROM code  */
        CDOG_CONTROL_DEBUG_HALT_CTRL(kCDOG_DebugHaltCtrl_Pause);

    // Initialize watchdog with zero.
    CDOG0->START = 0x0U;

    uint32_t const expectedSc = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Enable_Async)
                              + MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation)
                              + MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Hash_Async)
                              + MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation)
                              + MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Disable);

    /** Initialize ELS, Enable the ELS **/
    if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        return MCUXCLEXAMPLE_ERROR;
    }
    
    mcuxClEls_HashOption_t hash_options = {0U};              // Initialize a new configuration for the planned mcuxClEls_Hash_Async operation.
    hash_options.bits.hashini = MCUXCLELS_HASH_INIT_ENABLE;  // Configure that the mcuxClEls_Hash_Async operation shall initialized with the standard IV (Initialization Vector).
    hash_options.bits.hashoe = MCUXCLELS_HASH_OUTPUT_ENABLE; // Configure the mcuxClEls_Hash_Async operation so that the hash digest is moved into memory at the end of the operation.
    hash_options.bits.hashmd = MCUXCLELS_HASH_MODE_SHA_256;  // Configure the mcuxClEls_Hash_Async operation so that the Sha2-256 algorithm is used.
            
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_Hash_Async( // Perform the hashing.
            hash_options,                                               // Set the prepared configuration.
            sha256_padded_input, sizeof(sha256_padded_input),           // Set the data to be hashed. Note that this data's length is a multiple of the block length, so no padding is required
            sha2_256_digest                                             // Output buffer, which the operation will write the hash digest to.
            ));
    // mcuxClEls_Hash_Async is a flow-protected function: Add the protection token to the watchdog
    CDOG0->ADD = (uint32_t)(token);
    if (MCUXCLELS_STATUS_OK_WAIT != result) {
        return MCUXCLEXAMPLE_ERROR; // Expect that no error occurred, meaning that the mcuxClEls_Hash_Async operation was started.
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClEls_Hash_Async operation to complete.
    // mcuxClEls_WaitForOperation is a flow-protected function: Add the protection token to the watchdog
    CDOG0->ADD = (uint32_t)(token);
    if(MCUXCLELS_STATUS_OK != result) {
        return MCUXCLEXAMPLE_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    
    for (size_t i = 0; i < sizeof(sha256_reference_digest); i++)
    {
        if (sha2_256_digest[i] != sha256_reference_digest[i])
        {
           return MCUXCLEXAMPLE_ERROR; // Expect that the resulting hash digest matches our expected output
        }
    }
    
    /** Disable the ELS **/
    if(!mcuxClExample_Els_Disable())
    {
        return MCUXCLEXAMPLE_ERROR;
    }

    // Watchdog assertion
    CDOG0->STOP = expectedSc;
    if ((CDOG0->FLAGS & CDOG_FLAGS_MISCOM_FLAG_MASK) >> CDOG_FLAGS_MISCOM_FLAG_SHIFT != 0U)
    {
        return MCUXCLEXAMPLE_ERROR;
    }
    
    return MCUXCLEXAMPLE_OK;
}
