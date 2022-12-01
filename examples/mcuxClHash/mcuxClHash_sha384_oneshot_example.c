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

#include <mcuxClCss.h>              // Interface to the entire mcuxClCss component
#include <mcuxClExample_CSS_Helper.h>
#include <mcuxClSession.h>          // Interface to the entire mcuxClSession component
#include <mcuxClHash.h>             // Interface to the entire mcuxClHash component
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <toolchain.h>             // memory segment definitions
#include <stdbool.h>               // bool type for the example's return code
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClCore_Examples.h>

static const uint8_t data[3] CSS_CONST_SEGMENT = {
    0x61u, 0x62u, 0x63u
};

static const uint8_t hashExpected[48] CSS_CONST_SEGMENT = {
    0xCBu, 0x00u, 0x75u, 0x3Fu, 0x45u, 0xA3u, 0x5Eu, 0x8Bu,
    0xB5u, 0xA0u, 0x3Du, 0x69u, 0x9Au, 0xC6u, 0x50u, 0x07u,
    0x27u, 0x2Cu, 0x32u, 0xABu, 0x0Eu, 0xDEu, 0xD1u, 0x63u,
    0x1Au, 0x8Bu, 0x60u, 0x5Au, 0x43u, 0xFFu, 0x5Bu, 0xEDu,
    0x80u, 0x86u, 0x07u, 0x2Bu, 0xA1u, 0xE7u, 0xCCu, 0x23u,
    0x58u, 0xBAu, 0xECu, 0xA1u, 0x34u, 0xC8u, 0x25u, 0xA7u
};

bool mcuxClHash_sha384_oneshot_example(void)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/


    /** Initialize CSS, MCUXCLCSS_RESET_DO_NOT_CANCEL **/
    if(!mcuxClExample_Css_Init(MCUXCLCSS_RESET_DO_NOT_CANCEL))
    {
        return MCUX_CL_EXAMPLE_ERROR;
    }

    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    //Allocate and initialize session
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLHASH_COMPUTE_CPU_WA_BUFFER_SIZE_SHA2_384, 0u);

    /**************************************************************************/
    /* Hash computation                                                       */
    /**************************************************************************/

    uint8_t hash[MCUXCLHASH_OUTPUT_SIZE_SHA_384];
    uint32_t hashOutputSize = 0u;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token2, mcuxClHash_compute(
    /* mcuxClSession_Handle_t session: */ session,
    /* mcuxClHash_Algo_t algorithm:    */ mcuxClHash_Algorithm_Sha384,
    /* mcuxCl_InputBuffer_t pIn:       */ data,
    /* uint32_t inSize:               */ sizeof(data),
    /* mcuxCl_Buffer_t pOut            */ hash,
    /* uint32_t *const pOutSize,      */ &hashOutputSize
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute) != token2) || (MCUXCLHASH_STATUS_OK != result))
    {
        return MCUX_CL_EXAMPLE_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /**************************************************************************/
    /* Verification                                                           */
    /**************************************************************************/

    if(hashOutputSize != sizeof(hash))
	{
		return MCUX_CL_EXAMPLE_ERROR;
	}

    for (size_t i = 0u; i < sizeof(hash); i++)
    {
        if (hash[i] != hashExpected[i]) // Expect that the resulting hash matches our expected output
        {
            return MCUX_CL_EXAMPLE_ERROR;
        }
    }

    /** Disable the CSSv2 **/
    if(!mcuxClExample_Css_Disable())
    {
        return MCUX_CL_EXAMPLE_ERROR;
    }

    return MCUX_CL_EXAMPLE_OK;
}
