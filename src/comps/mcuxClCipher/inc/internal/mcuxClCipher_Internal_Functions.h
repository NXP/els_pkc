/*--------------------------------------------------------------------------*/
/* Copyright 2022 NXP                                                  */
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


#ifndef MCUX_CL_CIPHER_FUNCTONS_INTERNAL_H_
#define MCUX_CL_CIPHER_FUNCTONS_INTERNAL_H_



#ifdef __cplusplus
extern "C" {
#endif

static inline void mcuxClCipher_computeContextCrc(mcuxClCipher_Context_t * const pCtx, uint32_t contextSize)
{
}

static inline mcuxClCipher_Status_t mcuxClCipher_verifyContextCrc(mcuxClCipher_Context_t * const pCtx, uint32_t contextSize)
{
    return MCUX_CL_CIPHER_STATUS_OK;
}


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUX_CL_CIPHER_FUNCTONS_INTERNAL_H_ */
