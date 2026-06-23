/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
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

#include <mcuxClToolchain.h>
#include <mcuxClEls.h> // Interface to the entire mcuxClEls component
#include <mcuxClSession.h> // Interface to the entire mcuxClSession component
#include <mcuxClHash.h>             // Interface to the entire mcuxClHash component
#include <mcuxClHashModes.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_ELS_Helper.h>
#include <mcuxClToolchain.h> // memory segment definitions
#include <stdbool.h>  // bool type for the example's return code
#include <mcuxClPsaDriver.h>

MCUXCLEXAMPLE_FUNCTION(mcuxClPsaDriver_sha224_oneshot_example)
{
	/* Input for the SHA-224 operation */
    const ALIGNED uint8_t data[3] = {
        0x61u, 0x62u, 0x63u
    };

	/* Expected output for the SHA-224 operation */
    const ALIGNED uint8_t hashExpected[MCUXCLHASH_OUTPUT_SIZE_SHA_224] = {
        0x23u, 0x09u, 0x7Du, 0x22u, 0x34u, 0x05u, 0xD8u, 0x22u,
        0x86u, 0x42u, 0xA4u, 0x77u, 0xBDu, 0xA2u, 0x55u, 0xB3u,
        0x2Au, 0xADu, 0xBCu, 0xE4u, 0xBDu, 0xA0u, 0xB3u, 0xF7u,
        0xE3u, 0x6Cu, 0x9Du, 0xA7u
    };

	/* Output buffer for the SHA-224 operation */
    ALIGNED uint8_t hashOutput[MCUXCLHASH_OUTPUT_SIZE_SHA_224];

    /** Initialize ELS, Enable the ELS **/
    if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

	/* Variable for the output length of the encryption operation */
	size_t hashOutput_length;

	/* Call the hashing operation */
	psa_status_t result = psa_driver_wrapper_hash_compute(
	    PSA_ALG_SHA_224,                     // psa_algorithm_t alg
	    data,                                // const uint8_t *input
	    sizeof(data),                        // size_t input_length
	    hashOutput,                          // uint8_t *hash
	    MCUXCLHASH_OUTPUT_SIZE_SHA_224,       // size_t hash_size
	    &hashOutput_length);                 // size_t *hash_length

	/* Check the return value */
	if(result != PSA_SUCCESS) {
		return MCUXCLEXAMPLE_STATUS_ERROR;
	}

	/* Check the output length */
	if(hashOutput_length != MCUXCLHASH_OUTPUT_SIZE_SHA_224) {
		return MCUXCLEXAMPLE_STATUS_ERROR;
	}

	/* Check the content */
    for (size_t i = 0U; i < MCUXCLHASH_OUTPUT_SIZE_SHA_224; i++)
    {
        if (hashOutput[i] != hashExpected[i]) // Expect that the resulting encrypted msg matches our initial message
        {
            return MCUXCLEXAMPLE_STATUS_ERROR;
        }
    }

	/* Disable the ELS */
    if(!mcuxClExample_Els_Disable())
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

	/* Return */
	return MCUXCLEXAMPLE_STATUS_OK;
}
