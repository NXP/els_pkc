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
/* Security Classification:  Company Confidential                           */
/*--------------------------------------------------------------------------*/

#include <mcuxClRandom.h>
#include <mcuxClSession.h>
#include <mcuxClCss.h>
#include <mcuxClMemory.h>
#include <mcuxClAes.h>

#include <mcuxClCss.h>
#include <internal/mcuxClRandom_Internal_Types.h>
#include <internal/mcuxClRandom_Private_CtrDrbg.h>
#include <internal/mcuxClRandom_Private_NormalMode.h>
#include <internal/mcuxClTrng_Internal.h>
#include <internal/mcuxClMemory_Copy_Internal.h>

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClRandom_DRBG_AES_Internal_blockcipher)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_DRBG_AES_Internal_blockcipher(
    uint8_t *pV,
    uint8_t *pKey,
    uint8_t *pOut,
    uint32_t keyLength
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_DRBG_AES_Internal_blockcipher);

    uint8_t cssOut[MCUX_CL_AES_BLOCK_SIZE];

    mcuxClCss_CipherOption_t cipher_options = {0};
    cipher_options.bits.cphmde = MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_ECB;
    cipher_options.bits.dcrpt = MCUXCLCSS_CIPHER_ENCRYPT;
    cipher_options.bits.extkey = MCUXCLCSS_CIPHER_EXTERNAL_KEY;
    MCUX_CSSL_FP_FUNCTION_CALL(result_cipher, mcuxClCss_Cipher_Async(
                cipher_options,
                (mcuxClCss_KeyIndex_t)0U,
                (uint8_t const *)pKey,
                keyLength,
                (uint8_t const *)pV,
                MCUX_CL_AES_BLOCK_SIZE,
                NULL,
                cssOut)); 
    if (MCUXCLCSS_STATUS_OK_WAIT != result_cipher)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_DRBG_AES_Internal_blockcipher, MCUXCLRANDOM_STATUS_ERROR,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cipher_Async));
    }

    MCUX_CSSL_FP_FUNCTION_CALL(result_wait, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
    if (MCUXCLCSS_STATUS_OK != result_wait)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_DRBG_AES_Internal_blockcipher, MCUXCLRANDOM_STATUS_ERROR,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cipher_Async));
    }

    /* Copy the bytes from the buffer to output. */
    MCUXCLMEMORY_FP_MEMORY_COPY(pOut, cssOut, MCUX_CL_AES_BLOCK_SIZE);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_DRBG_AES_Internal_blockcipher, MCUXCLRANDOM_STATUS_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cipher_Async));
}
