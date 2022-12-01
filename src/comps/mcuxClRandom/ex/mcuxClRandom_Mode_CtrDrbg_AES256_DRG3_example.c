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

/**
 * @file  mcuxClRandom_Mode_CtrDrbg_AES256_DRG3_example.c
 * @brief Example for the mcuxClRandom component
 *
 * @example mcuxClRandom_Mode_CtrDrbg_AES256_DRG3_example.c
 * @brief   Example for the mcuxClRandom component
 */

#include <stdbool.h>  // bool type for the example's return code
#include <stddef.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClCore_Examples.h> // Defines and assertions for examples

/** Performs an example usage of the mcuxClRandom component
 * @retval true  The example code completed successfully
 * @retval false The example code failed */
bool mcuxClRandom_Mode_CtrDrbg_AES256_DRG3_example(void)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    mcuxClSession_Descriptor_t session;
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(&session, MCUXCLRANDOM_MAX_CPU_WA_BUFFER_SIZE, 0u);


    /**************************************************************************/
    /* DRBG selftest.                                                         */
    /**************************************************************************/
    const mcuxClRandom_Status_t rs_status = mcuxClRandom_selftest(&session,
                                                                mcuxClRandom_Mode_CtrDrbg_AES256_DRG3);

    if (MCUXCLRANDOM_STATUS_OK != rs_status)
    {
      return MCUX_CL_EXAMPLE_ERROR;
    }

    uint32_t context[(MCUXCLRANDOM_CTR_DRBG_AES256_CONTEXT_SIZE + sizeof(uint32_t) - 1u) / sizeof(uint32_t)] = {0};

    /**************************************************************************/
    /* DRBG initialization                                                    */
    /**************************************************************************/

    /* Initialize an AES-256 CTR_DRBG DRG.3 */
    const mcuxClRandom_Status_t ri_status = mcuxClRandom_init(&session,
                                                            (mcuxClRandom_Context_t)context,
                                                            mcuxClRandom_Mode_CtrDrbg_AES256_DRG3);

    if (MCUXCLRANDOM_STATUS_OK != ri_status)
    {
      return MCUX_CL_EXAMPLE_ERROR;
    }

    /**************************************************************************/
    /* Generate several random byte strings and reseed the DRBG in between.   */
    /**************************************************************************/

    /* Buffers to store the generated random values in. */
    uint8_t drbg_buffer1[3u];
    uint8_t drbg_buffer2[16u];
    uint8_t drbg_buffer3[31u];


    /* Generate random values of smaller amount than one word size. */
    const mcuxClRandom_Status_t rg1_status = mcuxClRandom_generate(&session,
                                                                 drbg_buffer1,
                                                                 3u);

    if (MCUXCLRANDOM_STATUS_OK != rg1_status)
    {
      return MCUX_CL_EXAMPLE_ERROR;
    }

    /* Generate random values of multiple of word size. */
    const mcuxClRandom_Status_t rg2_status = mcuxClRandom_generate(&session,
                                                                 drbg_buffer2,
                                                                 16u);

    if (MCUXCLRANDOM_STATUS_OK != rg2_status)
    {
      return MCUX_CL_EXAMPLE_ERROR;
    }

    /* reseed */
    const mcuxClRandom_Status_t rr_status = mcuxClRandom_reseed(&session);

    if (MCUXCLRANDOM_STATUS_OK != rr_status)
    {
      return MCUX_CL_EXAMPLE_ERROR;
    }

    /* Generate random values of larger amount than but not multiple of one word size. */
    const mcuxClRandom_Status_t rg3_status = mcuxClRandom_generate(&session,
                                                                 drbg_buffer3,
                                                                 31u);

    if (MCUXCLRANDOM_STATUS_OK != rg3_status)
    {
      return MCUX_CL_EXAMPLE_ERROR;
    }

    /**************************************************************************/
    /* Cleanup                                                                */
    /**************************************************************************/

    /* Random uninit. */
    const mcuxClRandom_Status_t ru_status = mcuxClRandom_uninit(&session);

    if (MCUXCLRANDOM_STATUS_OK != ru_status)
    {
      return MCUX_CL_EXAMPLE_ERROR;
    }

    /** Destroy Session and cleanup Session **/
    if(!mcuxClExample_Session_Clean(&session))
    {
        return false;
    }

    return true;
}
