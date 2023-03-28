/*--------------------------------------------------------------------------*/
/* Copyright 2021-2023 NXP                                                  */
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

#include <mcuxClCore_Platform.h>
#include <mcuxClCore_Analysis.h>

#include <internal/mcuxClRsa_Internal_PkcDefs.h>
#include <internal/mcuxClRsa_Internal_Macros.h>
#include <internal/mcuxClRsa_Internal_MemoryConsumption.h>
#include <internal/mcuxClRsa_Internal_Types.h>


MCUXCLCORE_ANALYSIS_START_PATTERN_OBJ_SIZES()



/****************************************************************************/
/* Computation of workarea sizes for the Rsa_sign function.               */
/****************************************************************************/

volatile uint8_t mcuxClRsa_Sign_Plain_NoEncode_1024_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_NOENCODE_WACPU_SIZE(1024/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_NoEncode_2048_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_NOENCODE_WACPU_SIZE(2048/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_NoEncode_3072_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_NOENCODE_WACPU_SIZE(3072/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_NoEncode_4096_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_NOENCODE_WACPU_SIZE(4096/8)];

volatile uint8_t mcuxClRsa_Sign_Plain_Pkcs1v15Encode_1024_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PKCS1V15ENCODE_WACPU_SIZE(1024/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_Pkcs1v15Encode_2048_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PKCS1V15ENCODE_WACPU_SIZE(2048/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_Pkcs1v15Encode_3072_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PKCS1V15ENCODE_WACPU_SIZE(3072/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_Pkcs1v15Encode_4096_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PKCS1V15ENCODE_WACPU_SIZE(4096/8)];

volatile uint8_t mcuxClRsa_Sign_Plain_PssEncode_1024_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PSSENCODE_WACPU_SIZE(1024/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_PssEncode_2048_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PSSENCODE_WACPU_SIZE(2048/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_PssEncode_3072_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PSSENCODE_WACPU_SIZE(3072/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_PssEncode_4096_WaCPU[MCUXCLRSA_INTERNAL_SIGN_PLAIN_PSSENCODE_WACPU_SIZE(4096/8)];

volatile uint8_t mcuxClRsa_Sign_Plain_1024_WaPKC[MCUXCLRSA_INTERNAL_SIGN_PLAIN_WAPKC_SIZE(1024/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_2048_WaPKC[MCUXCLRSA_INTERNAL_SIGN_PLAIN_WAPKC_SIZE(2048/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_3072_WaPKC[MCUXCLRSA_INTERNAL_SIGN_PLAIN_WAPKC_SIZE(3072/8)];
volatile uint8_t mcuxClRsa_Sign_Plain_4096_WaPKC[MCUXCLRSA_INTERNAL_SIGN_PLAIN_WAPKC_SIZE(4096/8)];

volatile uint8_t mcuxClRsa_Sign_CRT_NoEncode_1024_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_NOENCODE_WACPU_SIZE(1024/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_NoEncode_2048_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_NOENCODE_WACPU_SIZE(2048/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_NoEncode_3072_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_NOENCODE_WACPU_SIZE(3072/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_NoEncode_4096_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_NOENCODE_WACPU_SIZE(4096/8/2)];

volatile uint8_t mcuxClRsa_Sign_CRT_Pkcs1v15Encode_1024_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_PKCS1V15ENCODE_WACPU_SIZE(1024/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_Pkcs1v15Encode_2048_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_PKCS1V15ENCODE_WACPU_SIZE(2048/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_Pkcs1v15Encode_3072_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_PKCS1V15ENCODE_WACPU_SIZE(3072/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_Pkcs1v15Encode_4096_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_PKCS1V15ENCODE_WACPU_SIZE(4096/8/2)];

volatile uint8_t mcuxClRsa_Sign_CRT_PssEncode_1024_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_PSSENCODE_WACPU_SIZE(1024/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_PssEncode_2048_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_PSSENCODE_WACPU_SIZE(2048/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_PssEncode_3072_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_PSSENCODE_WACPU_SIZE(3072/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_PssEncode_4096_WaCPU[MCUXCLRSA_INTERNAL_SIGN_CRT_PSSENCODE_WACPU_SIZE(4096/8/2)];

volatile uint8_t mcuxClRsa_Sign_CRT_1024_WaPKC[MCUXCLRSA_INTERNAL_SIGN_CRT_WAPKC_SIZE(1024/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_2048_WaPKC[MCUXCLRSA_INTERNAL_SIGN_CRT_WAPKC_SIZE(2048/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_3072_WaPKC[MCUXCLRSA_INTERNAL_SIGN_CRT_WAPKC_SIZE(3072/8/2)];
volatile uint8_t mcuxClRsa_Sign_CRT_4096_WaPKC[MCUXCLRSA_INTERNAL_SIGN_CRT_WAPKC_SIZE(4096/8/2)];

/****************************************************************************/
/* Computation of workarea sizes for the Rsa_verify function.               */
/****************************************************************************/

volatile uint8_t mcuxClRsa_Verify_NoVerify_WaCPU[MCUXCLRSA_INTERNAL_VERIFY_NOVERIFY_WACPU_SIZE];

volatile uint8_t mcuxClRsa_Verify_Pkcs1v15Verify_WaCPU[MCUXCLRSA_INTERNAL_VERIFY_PKCS1V15VERIFY_WACPU_SIZE];

volatile uint8_t mcuxClRsa_Verify_PssVerify_WaCPU[MCUXCLRSA_INTERNAL_VERIFY_PSSVERIFY_WACPU_SIZE];

volatile uint8_t mcuxClRsa_Verify_1024_WaPKC[MCUXCLRSA_INTERNAL_VERIFY_WAPKC_SIZE(1024/8)];
volatile uint8_t mcuxClRsa_Verify_2048_WaPKC[MCUXCLRSA_INTERNAL_VERIFY_WAPKC_SIZE(2048/8)];
volatile uint8_t mcuxClRsa_Verify_3072_WaPKC[MCUXCLRSA_INTERNAL_VERIFY_WAPKC_SIZE(3072/8)];
volatile uint8_t mcuxClRsa_Verify_4096_WaPKC[MCUXCLRSA_INTERNAL_VERIFY_WAPKC_SIZE(4096/8)];


/***************************************************************************************************************/
/* Computation of key data size for the mcuxClRsa_KeyGeneration_Crt and mcuxClRsa_KeyGeneration_Plain functions. */
/***************************************************************************************************************/
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_Key_Data_2048[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_KEY_DATA_SIZE(2048/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_Key_Data_3072[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_KEY_DATA_SIZE(3072/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_Key_Data_4096[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_KEY_DATA_SIZE(4096/8)];

volatile uint8_t mcuxClRsa_KeyGeneration_CRT_Key_Data_2048[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_KEY_DATA_SIZE(2048/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_CRT_Key_Data_3072[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_KEY_DATA_SIZE(3072/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_CRT_Key_Data_4096[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_KEY_DATA_SIZE(4096/8)];

volatile uint8_t mcuxClRsa_KeyGeneration_Public_Key_Data_2048[MCUXCLRSA_INTERNAL_KEYGENERATION_PUBLIC_KEY_DATA_SIZE(2048/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Public_Key_Data_3072[MCUXCLRSA_INTERNAL_KEYGENERATION_PUBLIC_KEY_DATA_SIZE(3072/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Public_Key_Data_4096[MCUXCLRSA_INTERNAL_KEYGENERATION_PUBLIC_KEY_DATA_SIZE(4096/8)];

/******************************************************************************************************/
/* Computation of workarea sizes for the mcuxClRsa_KeyGeneration_Plain function for typical key sizes. */
/******************************************************************************************************/
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_2048_WaPKC[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WAPKC_SIZE(2048/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_3072_WaPKC[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WAPKC_SIZE(3072/8)];
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_4096_WaPKC[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WAPKC_SIZE(4096/8)];

#ifndef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_2048_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WACPU_SIZE];
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_3072_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WACPU_SIZE];
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_4096_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WACPU_SIZE];
#else
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_2048_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WACPU_SIZE(2048/8/2)];
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_3072_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WACPU_SIZE(3072/8/2)];
volatile uint8_t mcuxClRsa_KeyGeneration_Plain_4096_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WACPU_SIZE(4096/8/2)];
#endif
/****************************************************************************************************/
/* Computation of workarea sizes for the mcuxClRsa_KeyGeneration_Crt function for typical key sizes. */
/****************************************************************************************************/
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_2048_WaPKC[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WAPKC_SIZE(2048/8/2)];
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_3072_WaPKC[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WAPKC_SIZE(3072/8/2)];
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_4096_WaPKC[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WAPKC_SIZE(4096/8/2)];
#ifndef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_2048_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WACPU_SIZE];
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_3072_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WACPU_SIZE];
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_4096_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WACPU_SIZE];
#else
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_2048_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WACPU_SIZE(2048/8/2)];
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_3072_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WACPU_SIZE(3072/8/2)];
volatile uint8_t mcuxClRsa_KeyGeneration_Crt_4096_WaCPU[MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WACPU_SIZE(4096/8/2)];
#endif


MCUXCLCORE_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
