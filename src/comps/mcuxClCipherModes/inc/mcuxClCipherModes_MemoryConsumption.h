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


/** @file  mcuxClCipher_MemoryConsumption.h
 *  @brief Memory consumption of the mcuxClCipher component */
 
#ifndef MCUX_CL_CIPHER_MEMORY_SPEC_H_
#define MCUX_CL_CIPHER_MEMORY_SPEC_H_

/* Workarea sizes */
#define MCUX_CL_CIPHER_AES_CRYPT_CPU_WA_BUFFER_SIZE                 (44u)
#define MCUX_CL_CIPHER_AES_CRYPT_CPU_WA_BUFFER_SIZE_IN_WORDS        (MCUX_CL_CIPHER_AES_CRYPT_CPU_WA_BUFFER_SIZE / 4u)

#define MCUX_CL_CIPHER_AES_INIT_CPU_WA_BUFFER_SIZE                  (4u)
#define MCUX_CL_CIPHER_AES_PROCESS_CPU_WA_BUFFER_SIZE               (4u)
#define MCUX_CL_CIPHER_AES_FINISH_CPU_WA_BUFFER_SIZE                (4u)
#define MCUX_CL_CIPHER_AES_INIT_CPU_WA_BUFFER_SIZE_IN_WORDS         (MCUX_CL_CIPHER_AES_INIT_CPU_WA_BUFFER_SIZE / 4u)
#define MCUX_CL_CIPHER_AES_PROCESS_CPU_WA_BUFFER_SIZE_IN_WORDS      (MCUX_CL_CIPHER_AES_PROCESS_CPU_WA_BUFFER_SIZE / 4u)
#define MCUX_CL_CIPHER_AES_FINISH_CPU_WA_BUFFER_SIZE_IN_WORDS       (MCUX_CL_CIPHER_AES_FINISH_CPU_WA_BUFFER_SIZE / 4u)

#define MCUX_CL_CIPHER_MAX_AES_CPU_WA_BUFFER_SIZE                   (MCUX_CL_CIPHER_AES_CRYPT_CPU_WA_BUFFER_SIZE)
#define MCUX_CL_CIPHER_MAX_AES_CPU_WA_BUFFER_SIZE_IN_WORDS          (MCUX_CL_CIPHER_AES_CRYPT_CPU_WA_BUFFER_SIZE_IN_WORDS)

/* Context sizes */
#define MCUX_CL_CIPHER_AES_CONTEXT_SIZE                             (44u)
#define MCUX_CL_CIPHER_AES_CONTEXT_SIZE_IN_WORDS                    (MCUX_CL_CIPHER_AES_CONTEXT_SIZE / 4u)


#endif /* MCUX_CL_CIPHER_MEMORY_SPEC_H_ */
