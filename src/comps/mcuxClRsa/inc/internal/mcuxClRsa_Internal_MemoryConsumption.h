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

/** @file  mcuxClRsa_Internal_MemoryConsumption.h
 *  @brief Internal memory consumption definitions of the mcuxClRsa component */

#ifndef MCUXCLRSA_INTERNAL_MEMORY_CONSUMPTION_H_
#define MCUXCLRSA_INTERNAL_MEMORY_CONSUMPTION_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClPkc.h>
#include <internal/mcuxClHash_Internal_Memory.h>

#include <internal/mcuxClRsa_Internal_PkcDefs.h>
#include <internal/mcuxClRsa_Internal_Macros.h>
#include <internal/mcuxClRsa_Internal_Types.h>

#ifdef __cplusplus
extern "C" {
#endif


/****************************************************************************/
/* Definitions of workarea sizes for the mcuxClRsa_privatePlain function.    */
/****************************************************************************/
/**
 * @defgroup MCUXCLRSA_INTERNAL_PRIVATEPLAIN_WA MCUXCLRSA_INTERNAL_PRIVATEPLAIN_WA
 * @brief Workarea size macros of mcuxClRsa_privatePlain.
 * @ingroup mcuxClRsa_Internal_Macros
 * @{
 */
#define MCUXCLRSA_INTERNAL_PRIVATEPLAIN_WACPU_SIZE(keyByteLength)  \
    (MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE((MCUXCLRSA_INTERNAL_PRIVPLAIN_UPTRT_SIZE * sizeof(uint16_t))) \
     + MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE(keyByteLength))
    ///< Definition of CPU workarea size for the mcuxClRsa_privatePlain function depending on the key byte-length.
    ///< Internally, it depends on the byte-length of the exponent, and it is rounded up here, based on the fact that d < n.

#define MCUXCLRSA_INTERNAL_PRIVATEPLAIN_WAPKC_SIZE(keyByteLength)  \
    (6U * MCUXCLPKC_ROUNDUP_SIZE(keyByteLength) + 10U * MCUXCLPKC_WORDSIZE)
    ///< Definition of PKC workarea size for the mcuxClRsa_privatePlain function depending on the key byte-length.
/** @} */

/****************************************************************************/
/* Definitions of workarea sizes for the mcuxClRsa_privateCRT function.      */
/****************************************************************************/
/**
 * @defgroup MCUXCLRSA_INTERNAL_PRIVATECRT_WA MCUXCLRSA_INTERNAL_PRIVATECRT_WA
 * @brief Workarea size macros of mcuxClRsa_privateCRT.
 * @ingroup mcuxClRsa_Internal_Macros
 * @{
 */
#define MCUXCLRSA_INTERNAL_PRIVATECRT_BLINDING_SIZE (4UL)

#define MCUXCLRSA_INTERNAL_PRIVATECRT_WACPU_SIZE(primeByteLength)  \
    (MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE((MCUXCLRSA_INTERNAL_PRIVCRT_UPTRT_SIZE * sizeof(uint16_t))) \
     + MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE(primeByteLength))
    ///< Definition of CPU workarea size for the mcuxClRsa_privateCRT function depending on the byte-length of p (equal to the byte-length of q).
    ///< Internally, it depends on the byte-lengths of the exponents dp and dq, and it is rounded up here, based on the fact that dp and dq are smaller than p and q.

#define MCUXCLRSA_INTERNAL_PRIVATECRT_WAPKC_SIZE(primeByteLength)  \
    (MCUXCLPKC_ROUNDUP_SIZE(MCUXCLRSA_INTERNAL_PRIVATECRT_BLINDING_SIZE) \
     + MCUXCLRSA_MAX((8U * MCUXCLPKC_ROUNDUP_SIZE(primeByteLength)) + (8U * MCUXCLPKC_ROUNDUP_SIZE(MCUXCLRSA_INTERNAL_PRIVATECRT_BLINDING_SIZE)) + (12U * MCUXCLPKC_WORDSIZE), \
                    (6U * MCUXCLPKC_ROUNDUP_SIZE(primeByteLength * 2u)) + (8U * MCUXCLPKC_WORDSIZE)))
    ///< Definition of PKC workarea size for the mcuxClRsa_privateCRT function depending on the byte-length of p.
/** @} */


/****************************************************************************/
/* Definitions of workarea sizes for the mcuxClRsa_public function.          */
/****************************************************************************/
/**
 * @defgroup MCUXCLRSA_INTERNAL_PUBLIC_WA MCUXCLRSA_INTERNAL_PUBLIC_WA
 * @brief Workarea size macros of mcuxClRsa_public.
 * @ingroup mcuxClRsa_Internal_Macros
 * @{
 */
#define MCUXCLRSA_INTERNAL_PUBLIC_WACPU_SIZE  \
    (MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE((MCUXCLRSA_INTERNAL_PUBLIC_UPTRT_SIZE * sizeof(uint16_t))))
    ///< Definition of CPU workarea size for the mcuxClRsa_public function.

#define MCUXCLRSA_INTERNAL_PUBLIC_WAPKC_SIZE(keyByteLength)  \
    (5U * MCUXCLPKC_ROUNDUP_SIZE(keyByteLength) + 4U * MCUXCLPKC_WORDSIZE)
    ///< Definition of PKC workarea size for the mcuxClRsa_public function depending on the key byte-length.
/** @} */

/****************************************************************************/
/* Definitions of workarea sizes for the mcuxClRsa_noEncode function.        */
/****************************************************************************/
/**
 * @defgroup MCUXCLRSA_INTERNAL_NOENCODE_WA MCUXCLRSA_INTERNAL_NOENCODE_WA
 * @brief Workarea size macros of mcuxClRsa_noEncode.
 * @ingroup mcuxClRsa_Internal_Macros
 * @{
 */
#define MCUXCLRSA_INTERNAL_NOENCODE_WACPU_SIZE  \
    (MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE((MCUXCLRSA_INTERNAL_NOENCODE_UPTRT_SIZE * sizeof(uint16_t))))
    ///< Definition of CPU workarea size for the mcuxClRsa_noEncode function.

#define MCUXCLRSA_INTERNAL_NOENCODE_WAPKC_SIZE  \
    0u
    ///< Definition of PKC workarea size for the mcuxClRsa_noEncode function.
/** @} */

/****************************************************************************/
/* Definitions of workarea sizes for the mcuxClRsa_noVerify function.        */
/****************************************************************************/
/**
 * @defgroup MCUXCLRSA_INTERNAL_NOVERIFY_WA MCUXCLRSA_INTERNAL_NOVERIFY_WA
 * @brief Workarea size macros of mcuxClRsa_noVerify.
 * @ingroup mcuxClRsa_Internal_Macros
 * @{
 */
#define MCUXCLRSA_INTERNAL_NOVERIFY_WACPU_SIZE  \
    (MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE((MCUXCLRSA_INTERNAL_NOVERIFY_UPTRT_SIZE * sizeof(uint16_t))))
    ///< Definition of CPU workarea size for the mcuxClRsa_noVerify function.

#define MCUXCLRSA_INTERNAL_NOVERIFY_WAPKC_SIZE(keyByteLength)  \
    (MCUXCLPKC_ROUNDUP_SIZE(keyByteLength))
    ///< Definition of PKC workarea size for the mcuxClRsa_noVerify function depending on the key byte-length.
/** @} */

/****************************************************************************/
/* Definitions of workarea sizes for the mcuxClRsa_Mgf1 function.            */
/****************************************************************************/
/**
 * @defgroup MCUXCLRSA_INTERNAL_MGF1_WA MCUXCLRSA_INTERNAL_MGF1_WA
 * @brief Workarea size macros of mcuxClRsa_Mgf1.
 * @ingroup mcuxClRsa_Internal_Macros
 * @{
 */
#ifdef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
#define MCUXCLRSA_INTERNAL_MGF1_WACPU_SIZE(inputLen)  \
    (MCUXCLPKC_ROUNDUP_SIZE(inputLen + 4U) \
	 + MCUXCLHASH_INTERNAL_WACPU_MAX)
    ///< Definition of CPU workarea size for the mcuxClRsa_Mgf1 function.

#define MCUXCLRSA_INTERNAL_MGF1_WACPU_SIZE_WO_HASH(inputLen)  \
    (MCUXCLPKC_ROUNDUP_SIZE(inputLen + 4U))
    ///< Definition of CPU workarea size for the mcuxClRsa_Mgf1 function without hash compute.

/*
 * Definitions of maximum size of CPU workarea for the mcuxClRsa_Mgf1 function.
 * This function allocate space for Input, Hash output and 4B of the counter.
 * This macro takes into account the fact that:
 * inputLength = hashLen <= MCUXCLRSA_HASH_MAX_SIZE, for PSS encoding.
 * Note that it is valid only for PSS encoding, and not for OAEP encoding
 */
#define MCUXCLRSA_INTERNAL_MGF1_MAX_WACPU_SIZE \
    (MCUXCLRSA_INTERNAL_MGF1_WACPU_SIZE(MCUXCLRSA_HASH_MAX_SIZE))
    ///< Definition of CPU workarea size for the mcuxClRsa_Mgf1 function.
#else
//The parameters are just to keep the API consistent
#define MCUXCLRSA_INTERNAL_MGF1_WACPU_SIZE(inputLen)  \
    (MCUXCLHASH_INTERNAL_WACPU_MAX)
    ///< Definition of CPU workarea size for the mcuxClRsa_Mgf1 function.
#endif

#define MCUXCLRSA_INTERNAL_MGF1_WAPKC_SIZE(inputLen, hashLen)  \
    (MCUXCLPKC_ROUNDUP_SIZE((inputLen) + 4U + (hashLen)))
    ///< Definition of PKC workarea size for the mcuxClRsa_Mgf1 function.

/*
 * Definitions of maximum size of PKC workarea for the mcuxClRsa_Mgf1 function.
 * This function allocate space for Input, Hash output and 4B of the counter.
 * This macro takes into account the fact that:
 * inputLength = hashLen <= MCUXCLRSA_HASH_MAX_SIZE
 */
 #define MCUXCLRSA_INTERNAL_MGF1_MAX_WAPKC_SIZE  \
    (MCUXCLRSA_INTERNAL_MGF1_WAPKC_SIZE(MCUXCLRSA_HASH_MAX_SIZE, MCUXCLRSA_HASH_MAX_SIZE))
    ///< Definition of PKC workarea size for the mcuxClRsa_Mgf1 function.
/** @} */

/****************************************************************************/
/* Definitions of workarea sizes for the mcuxClRsa_pssEncode function.       */
/****************************************************************************/
/**
 * @defgroup MCUXCLRSA_INTERNAL_PSSENCODE_WA MCUXCLRSA_INTERNAL_PSSENCODE_WA
 * @brief Workarea size macros of mcuxClRsa_pssEncode.
 * @ingroup mcuxClRsa_Internal_Macros
 * @{
 */

#define MCUXCLRSA_INTERNAL_PSSENCODE_TEMPBUFFER_SIZE(hashLen, saltLen)  \
    (MCUXCLPKC_ROUNDUP_SIZE(MCUXCLRSA_PSS_PADDING1_LEN + (hashLen) + (saltLen)))
    ///< Definitions of the size for the buffer where temporary data is stored in mcuxClRsa_pssEncode function.

#define MCUXCLRSA_INTERNAL_PSSENCODE_TEMPBUFFER_MAX_SIZE(keyByteLength)  \
    (MCUXCLPKC_ROUNDUP_SIZE((keyByteLength - 2U) + MCUXCLRSA_PSS_PADDING1_LEN))
    ///< Maximum size for the temp buffer in mcuxClRsa_pssEncode, based on the fact that emLen >= hLen + sLen + 2.

#if defined(MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND) || defined(MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS)
#define MCUXCLRSA_INTERNAL_PSSENCODE_WACPU_SIZE(hashLen, saltLen)  \
    (MCUXCLRSA_MAX(MCUXCLHASH_INTERNAL_WACPU_MAX, MCUXCLRSA_INTERNAL_MGF1_WACPU_SIZE(hashLen)) \
     + MCUXCLRSA_INTERNAL_PSSENCODE_TEMPBUFFER_SIZE(hashLen, saltLen))
     ///< Definitions of CPU workarea size for the mcuxClRsa_pssEncode function.

#define MCUXCLRSA_INTERNAL_PSSENCODE_MAX_WACPU_SIZE(keyByteLength)  \
    (MCUXCLRSA_MAX(MCUXCLHASH_INTERNAL_WACPU_MAX, MCUXCLRSA_INTERNAL_MGF1_MAX_WACPU_SIZE)  \
     + MCUXCLRSA_INTERNAL_PSSENCODE_TEMPBUFFER_MAX_SIZE(keyByteLength))
     ///< Definitions of maximum size of CPU workarea for the mcuxClRsa_pssEncode function.

#define MCUXCLRSA_INTERNAL_PSSENCODE_WAPKC_SIZE(hashLen, saltLen)  \
    MCUXCLRSA_INTERNAL_MGF1_WAPKC_SIZE(hashLen, hashLen)
    ///< Definitions of PKC workarea sizes for the mcuxClRsa_pssEncode function.

#define MCUXCLRSA_INTERNAL_PSSENCODE_MAX_WAPKC_SIZE(keyByteLength)  \
    (MCUXCLRSA_INTERNAL_MGF1_MAX_WAPKC_SIZE)
    ///< Definitions of maximum size of PKC workarea for the mcuxClRsa_pssEncode function.

#else
#define MCUXCLRSA_INTERNAL_PSSENCODE_WACPU_SIZE(hashLen, saltLen)  \
    MCUXCLRSA_MAX(MCUXCLHASH_INTERNAL_WACPU_MAX, MCUXCLRSA_INTERNAL_MGF1_WACPU_SIZE(0u))
    ///< Definitions of CPU workarea size for the mcuxClRsa_pssEncode function.

#define MCUXCLRSA_INTERNAL_PSSENCODE_MAX_WACPU_SIZE(keyByteLength)  \
    (MCUXCLRSA_INTERNAL_PSSENCODE_WACPU_SIZE(0u, 0u))
    ///< Definitions of maximum size of CPU workarea for the mcuxClRsa_pssEncode function.

#define MCUXCLRSA_INTERNAL_PSSENCODE_WAPKC_SIZE(hashLen, saltLen)  \
    (MCUXCLRSA_INTERNAL_PSSENCODE_TEMPBUFFER_SIZE(hashLen, saltLen) \
     + MCUXCLRSA_INTERNAL_MGF1_WAPKC_SIZE(hashLen, hashLen))
    ///< Definitions of PKC workarea sizes for the mcuxClRsa_pssEncode function.

#define MCUXCLRSA_INTERNAL_PSSENCODE_MAX_WAPKC_SIZE(keyByteLength)  \
    (MCUXCLRSA_INTERNAL_PSSENCODE_TEMPBUFFER_MAX_SIZE(keyByteLength) \
     + MCUXCLRSA_INTERNAL_MGF1_MAX_WAPKC_SIZE)
    ///< Definitions of maximum size of PKC workarea for the mcuxClRsa_pssEncode function.
#endif
/** @} */

/****************************************************************************/
/* Definitions of workarea sizes for the mcuxClRsa_pssVerify function.       */
/****************************************************************************/

/* TODO CLNS-6084: the following macros should be cleaned up, after cleaning up CL code:
 * - the same macros should be used in CL functions and size definitions for RSA Verify, for all workarounds (same name, same parameters).
 *   The values of those macros may differ depending on the workarounds.
 * - unnecessary/redundant macros should be removed.
 * - common code copied into several macros should be moved into other macros (see what is done for MCUXCLRSA_INTERNAL_PSSENCODE_TEMPBUFFER_SIZE).
 * - macros should be double-checked for errors.
 *
 * This also applies, in a lesser extent, to MGF1 and pssEncode macros.
 */

/**
 * @defgroup MCUXCLRSA_INTERNAL_PSSVERIFY_WA MCUXCLRSA_INTERNAL_PSSVERIFY_WA
 * @brief Workarea size macros of mcuxClRsa_pssVerify.
 * @ingroup mcuxClRsa_Internal_Macros
 * @{
 */
#ifdef MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS
#define MCUXCLRSA_INTERNAL_PSSVERIFY_UNALIGNED_WORKAROUND_WACPU_SIZE(keyByteLength) \
    (MCUXCLPKC_ROUNDUP_SIZE(((keyByteLength - 2U /* hLen + sLen */) + MCUXCLRSA_PSS_PADDING1_LEN) \
     + ((keyByteLength) - 1U) /* maskedDB  + H' */))
#define MCUXCLRSA_INTERNAL_PSSVERIFY_UNALIGNED_WORKAROUND_WACPU_MAX_SIZE (MCUXCLRSA_INTERNAL_PSSVERIFY_UNALIGNED_WORKAROUND_WACPU_SIZE(4096/8))
#else
#define MCUXCLRSA_INTERNAL_PSSVERIFY_UNALIGNED_WORKAROUND_WACPU_SIZE(keyByteLen) (0u)
#define MCUXCLRSA_INTERNAL_PSSVERIFY_UNALIGNED_WORKAROUND_WACPU_MAX_SIZE (0u)
#endif /* MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS */
#ifndef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
//The parameters are just to keep the API consistent
#define MCUXCLRSA_INTERNAL_PSSVERIFY_WACPU_SIZE(keyByteLen, hashLen, saltLen)  \
    (MCUXCLRSA_MAX(MCUXCLHASH_INTERNAL_WACPU_MAX, MCUXCLRSA_INTERNAL_MGF1_WACPU_SIZE(0)))
    ///< Definition of CPU workarea size for the mcuxClRsa_pssVerify function.
#else
#define MCUXCLRSA_INTERNAL_PSSVERIFY_WACPU_SIZE_WO_MGF1(hashLen, saltLen)  \
    (MCUXCLPKC_ROUNDUP_SIZE(MCUXCLRSA_PSS_PADDING1_LEN + (hashLen) + (saltLen)))
    ///< Definitions of CPU workarea sizes for the mcuxClRsa_pssVerify function without workarea size for MGF1 function.

#define MCUXCLRSA_INTERNAL_PSSVERIFY_WACPU_SIZE(keyByteLen, hashLen, saltLen)  \
    (MCUXCLRSA_INTERNAL_PSSVERIFY_WACPU_SIZE_WO_MGF1(hashLen, saltLen)  \
     + MCUXCLPKC_ROUNDUP_SIZE(hashLen + saltLen + 2u)  \
	 + MCUXCLHASH_INTERNAL_WACPU_MAX \
     + MCUXCLRSA_INTERNAL_MGF1_WACPU_SIZE(hashLen)) \
     + MCUXCLRSA_INTERNAL_PSSVERIFY_UNALIGNED_WORKAROUND_WACPU_SIZE(keyByteLen)
    ///< Definitions of CPU workarea size for the mcuxClRsa_pssVerify function.

/*
 * Definitions of maximum size of CPU workarea for the mcuxClRsa_pssVerify function without workarea size for MGF1 function.
 * This macro specifies the size of the space allocated for Hash (size hLen), salt (sLen) and padding1.
 * It takes into account the condition that emLen >= hLen + sLen + 2 => hLen + sLen <= emLen - 2,
 * where emLen = keyByteLength (only byte-level granularity of keys is supported, thus keyBitLength is a multiple of 8)
 */
#define MCUXCLRSA_INTERNAL_PSSVERIFY_MAX_WACPU_SIZE_WO_MGF1(keyByteLength)  \
     (MCUXCLPKC_ROUNDUP_SIZE((keyByteLength - 2U /* hLen + sLen */) + MCUXCLRSA_PSS_PADDING1_LEN))
    ///< Definitions of CPU workarea sizes for the mcuxClRsa_pssVerify function without workarea size for MGF1 function.

#define MCUXCLRSA_INTERNAL_PSSVERIFY_MAX_WACPU_SIZE(keyByteLength)  \
    (MCUXCLRSA_INTERNAL_PSSVERIFY_MAX_WACPU_SIZE_WO_MGF1(keyByteLength)  \
     + MCUXCLPKC_ROUNDUP_SIZE(keyByteLength)  \
     + MCUXCLHASH_INTERNAL_WACPU_MAX \
     + MCUXCLRSA_INTERNAL_MGF1_MAX_WACPU_SIZE) \
     + MCUXCLRSA_INTERNAL_PSSVERIFY_UNALIGNED_WORKAROUND_WACPU_MAX_SIZE
    ///< Definitions of CPU workarea size for the mcuxClRsa_pssVerify function.
#endif

#define MCUXCLRSA_INTERNAL_PSSVERIFY_WAPKC_SIZE_WO_MGF1(keyByteLength, hashLen, saltLen)  \
    (MCUXCLPKC_ROUNDUP_SIZE(MCUXCLRSA_PSS_PADDING1_LEN + (hashLen) + (saltLen) \
                           + (keyByteLength) - 1U ))
    ///< Definition of PKC workarea size for the mcuxClRsa_pssVerify function without workarea size for MGF1 function.

#define MCUXCLRSA_INTERNAL_PSSVERIFY_WAPKC_SIZE(keyByteLength, hashLen, saltLen)  \
    (MCUXCLRSA_INTERNAL_PSSVERIFY_WAPKC_SIZE_WO_MGF1(keyByteLength, hashLen, saltLen) \
                         + MCUXCLRSA_INTERNAL_MGF1_WAPKC_SIZE(hashLen, hashLen))
    ///< Definition of PKC workarea size for the mcuxClRsa_pssVerify function.

/*
 * Definitions of maximum size of PKC workarea for the mcuxClRsa_pssVerify function without workarea size for MGF1 function.
 * This macro specifies the size of the space allocated for Hash (size hLen), salt (sLen) and padding1.
 * It takes into account the condition that emLen >= hLen + sLen + 2 => hLen + sLen <= emLen - 2,
 * where emLen = keyByteLength (only byte-level granularity of keys is supported, thus keyBitLength is a multiple of 8)
 */
#define MCUXCLRSA_INTERNAL_PSSVERIFY_MAX_WAPKC_SIZE_WO_MGF1(keyByteLength)  \
    (MCUXCLPKC_ROUNDUP_SIZE(((keyByteLength - 2U /* hLen + sLen */) + MCUXCLRSA_PSS_PADDING1_LEN) \
     + ((keyByteLength) - 1U) /* maskedDB  + H' */))

#define MCUXCLRSA_INTERNAL_PSSVERIFY_MAX_WAPKC_SIZE(keyByteLength)  \
    (MCUXCLRSA_INTERNAL_PSSVERIFY_MAX_WAPKC_SIZE_WO_MGF1(keyByteLength) \
     + MCUXCLRSA_INTERNAL_MGF1_MAX_WAPKC_SIZE) \
    ///< Definitions of maximum size of PKC workarea for the mcuxClRsa_pssVerify function.

/** @} */

/*********************************************************************************/
/* Definitions of workarea sizes for the mcuxClRsa_pkcs1v15Encode_sign function.  */
/*********************************************************************************/
/**
 * @defgroup MCUXCLRSA_INTERNAL_PKCS1V15ENCODE_SIGN_WA MCUXCLRSA_INTERNAL_PKCS1V15ENCODE_SIGN_WA
 * @brief Workarea size macros of mcuxClRsa_pkcs1v15Encode_sign.
 * @ingroup mcuxClRsa_Internal_Macros
 * @{
 */
#define MCUXCLRSA_INTERNAL_PKCS1V15ENCODE_SIGN_WACPU_SIZE  \
	MCUXCLHASH_INTERNAL_WACPU_MAX
    ///< Definition of CPU workarea size for the mcuxClRsa_pkcs1v15Encode_sign function.

#ifndef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
#define MCUXCLRSA_INTERNAL_PKCS1V15ENCODE_SIGN_WAPKC_SIZE(keyByteLength)  \
    (MCUXCLPKC_ROUNDUP_SIZE(keyByteLength))
#else
#define MCUXCLRSA_INTERNAL_PKCS1V15ENCODE_SIGN_WAPKC_SIZE(keyByteLength)  \
    (MCUXCLPKC_ROUNDUP_SIZE(keyByteLength + 8))
#endif
    ///< Definition of PKC workarea size for the mcuxClRsa_pkcs1v15Encode_sign function.
/** @} */

/****************************************************************************/
/* Definitions of workarea sizes for the mcuxClRsa_pkcs1v15Verify function.  */
/****************************************************************************/
/**
 * @defgroup MCUXCLRSA_INTERNAL_PKCS1V15VERIFY_WA MCUXCLRSA_INTERNAL_PKCS1V15VERIFY_WA
 * @brief Workarea size macros of mcuxClRsa_pkcs1v15Verify.
 * @ingroup mcuxClRsa_Internal_Macros
 * @{
 */
#define MCUXCLRSA_INTERNAL_PKCS1V15VERIFY_WACPU_SIZE  \
	MCUXCLHASH_INTERNAL_WACPU_MAX
    ///< Definition of CPU workarea size for the mcuxClRsa_pkcs1v15Verify function.

#define MCUXCLRSA_INTERNAL_PKCS1V15VERIFY_WAPKC_SIZE(keyByteLength)  \
    (MCUXCLPKC_ROUNDUP_SIZE(keyByteLength)) + \
     MCUXCLRSA_INTERNAL_PKCS1V15ENCODE_SIGN_WAPKC_SIZE(keyByteLength)
    ///< Definition of PKC workarea size for the mcuxClRsa_pkcs1v15Verify function.
/** @} */



/****************************************************************************/
/* Definitions of workarea sizes for the mcuxClRsa_verify function.          */
/****************************************************************************/
/**
 * @defgroup MCUXCLRSA_VERIFY_WA MCUXCLRSA_VERIFY_WA
 * @brief Workarea size macros of mcuxClRsa_verify.
 * @ingroup mcuxClRsa_Internal_Macros
 * @{
 */
#define MCUXCLRSA_INTERNAL_VERIFY_NOVERIFY_WACPU_SIZE  \
    (sizeof(mcuxClPkc_State_t)  \
     + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_NOVERIFY_WACPU_SIZE,  \
                  MCUXCLRSA_INTERNAL_PUBLIC_WACPU_SIZE))
    ///< Definition of CPU workarea size for the mcuxClRsa_verify function using NOVERIFY option.

#define MCUXCLRSA_INTERNAL_VERIFY_PKCS1V15VERIFY_WACPU_SIZE  \
    (sizeof(mcuxClPkc_State_t)  \
     + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_PKCS1V15VERIFY_WACPU_SIZE,  \
                  MCUXCLRSA_INTERNAL_PUBLIC_WACPU_SIZE))
    ///< Definition of CPU workarea size for the mcuxClRsa_verify function using PKCS1V15VERIFY option.

#ifndef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
#define MCUXCLRSA_INTERNAL_VERIFY_PSSVERIFY_WACPU_SIZE  \
    (sizeof(mcuxClPkc_State_t)  \
   + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_PSSVERIFY_WACPU_SIZE(0,0,0),  \
                MCUXCLRSA_INTERNAL_PUBLIC_WACPU_SIZE))
    ///< Definition of CPU workarea size for the mcuxClRsa_verify function using PSSVERIFY option.
#else
#define MCUXCLRSA_INTERNAL_VERIFY_PSSVERIFY_WACPU_SIZE(keyByteLength)  \
    (sizeof(mcuxClPkc_State_t)  \
    + MCUXCLPKC_ROUNDUP_SIZE(keyByteLength)  \
   + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_PSSVERIFY_MAX_WACPU_SIZE(keyByteLength),  \
                  MCUXCLRSA_INTERNAL_PUBLIC_WACPU_SIZE))
   ///< Definition of CPU workarea size for the mcuxClRsa_verify function using PSSVERIFY option.
#endif

#define MCUXCLRSA_INTERNAL_VERIFY_NOVERIFY_WAPKC_SIZE(keyByteLength)  \
    (MCUXCLPKC_ROUNDUP_SIZE(keyByteLength)  \
     + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_PUBLIC_WAPKC_SIZE(keyByteLength),  \
                  MCUXCLRSA_INTERNAL_NOVERIFY_WAPKC_SIZE(keyByteLength)))
    ///< Definition of PKC workarea size for the mcuxClRsa_Verify function using NOVERIFY option depending on the key byte-length.

#define MCUXCLRSA_INTERNAL_VERIFY_PKCS1V15VERIFY_WAPKC_SIZE(keyByteLength)  \
    (MCUXCLPKC_ROUNDUP_SIZE(keyByteLength)  \
     + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_PUBLIC_WAPKC_SIZE(keyByteLength),  \
                  MCUXCLRSA_INTERNAL_PKCS1V15VERIFY_WAPKC_SIZE(keyByteLength)))
    ///< Definition of PKC workarea size for the mcuxClRsa_Verify function using PKCS1V15VERIFY option depending on the key byte-length.

#define MCUXCLRSA_INTERNAL_VERIFY_PSSVERIFY_WAPKC_SIZE(keyByteLength)  \
    (MCUXCLPKC_ROUNDUP_SIZE(keyByteLength)  \
     + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_PUBLIC_WAPKC_SIZE(keyByteLength),  \
                  MCUXCLRSA_INTERNAL_PSSVERIFY_MAX_WAPKC_SIZE(keyByteLength)))
    ///< Definition of PKC workarea size for the mcuxClRsa_Verify function using PSSVERIFY option.

#define MCUXCLRSA_INTERNAL_VERIFY(keyByteLength)  \
    (MCUXCLRSA_MAX(MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_VERIFY_PKCS1V15VERIFY_WAPKC_SIZE(keyByteLength), \
                               MCUXCLRSA_INTERNAL_VERIFY_PSSVERIFY_WAPKC_SIZE(keyByteLength)), \
                  MCUXCLRSA_INTERNAL_VERIFY_NOVERIFY_WAPKC_SIZE(keyByteLength)))
    ///< Definition of PKC workarea size for the mcuxClRsa_Verify function depending on the key byte-length.

/** @} */

/****************************************************************************/
/* Definitions of workarea sizes for the mcuxClRsa_sign function.            */
/****************************************************************************/
/**
 * @defgroup MCUXCLRSA_SIGN_WA MCUXCLRSA_SIGN_WA
 * @brief Workarea size macros of mcuxClRsa_sign.
 * @ingroup mcuxClRsa_Internal_Macros
 * @{
 */
#define MCUXCLRSA_INTERNAL_SIGN_PLAIN_NOENCODE_WACPU_SIZE(keyByteLength)  \
    (sizeof(mcuxClPkc_State_t)  \
     + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_NOENCODE_WACPU_SIZE,  \
                    MCUXCLRSA_INTERNAL_PRIVATEPLAIN_WACPU_SIZE(keyByteLength)))
    ///< Definition of CPU workarea size for the mcuxClRsa_sign function using NOENCODE option and a private plain key.

#define MCUXCLRSA_INTERNAL_SIGN_PLAIN_PKCS1V15ENCODE_WACPU_SIZE(keyByteLength)  \
    (sizeof(mcuxClPkc_State_t)  \
     + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_PKCS1V15ENCODE_SIGN_WACPU_SIZE,  \
                    MCUXCLRSA_INTERNAL_PRIVATEPLAIN_WACPU_SIZE(keyByteLength)))
    ///< Definition of CPU workarea size for the mcuxClRsa_sign function with pkcs1v15 encoding and a private plain key.

#ifndef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
#define MCUXCLRSA_INTERNAL_SIGN_PLAIN_PSSENCODE_WACPU_SIZE(keyByteLength)  \
    (sizeof(mcuxClPkc_State_t)  \
     + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_PSSENCODE_WACPU_SIZE(0,0),  \
                    MCUXCLRSA_INTERNAL_PRIVATEPLAIN_WACPU_SIZE(keyByteLength)))
    ///< Definitions of CPU workarea size for the mcuxClRsa_sign function with pss encoding and a private plain key.
#else
#define MCUXCLRSA_INTERNAL_SIGN_PLAIN_PSSENCODE_WACPU_SIZE(keyByteLength)  \
    (sizeof(mcuxClPkc_State_t)  \
   + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_PSSENCODE_MAX_WACPU_SIZE(keyByteLength),  \
                  MCUXCLRSA_INTERNAL_PRIVATEPLAIN_WACPU_SIZE(keyByteLength)))
   ///< Definitions of CPU workarea size for the mcuxClRsa_sign function with pss encoding and a private plain key.
#endif

#define MCUXCLRSA_INTERNAL_SIGN_PLAIN_NOENCODE_WAPKC_SIZE(keyByteLength)  \
    (MCUXCLPKC_ROUNDUP_SIZE(keyByteLength)  \
     + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_NOENCODE_WAPKC_SIZE,  \
                    MCUXCLRSA_INTERNAL_PRIVATEPLAIN_WAPKC_SIZE(keyByteLength)))
    ///< Definition of PKC workarea size for the mcuxClRsa_Sign function using NOENCODE option and a private plain key.

#define MCUXCLRSA_INTERNAL_SIGN_PLAIN_PSSENCODE_WAPKC_SIZE(keyByteLength)  \
    (MCUXCLPKC_ROUNDUP_SIZE(keyByteLength)  \
     + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_PSSENCODE_MAX_WAPKC_SIZE(keyByteLength),  \
                    MCUXCLRSA_INTERNAL_PRIVATEPLAIN_WAPKC_SIZE(keyByteLength)))
    ///< Definition of PKC workarea size for the mcuxClRsa_sign function with pss encoding and a private plain key.

#define MCUXCLRSA_INTERNAL_SIGN_PLAIN_PKCS1V15ENCODE_WAPKC_SIZE(keyByteLength)  \
    (MCUXCLPKC_ROUNDUP_SIZE(keyByteLength)  \
     + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_PKCS1V15ENCODE_SIGN_WAPKC_SIZE(keyByteLength),  \
                    MCUXCLRSA_INTERNAL_PRIVATEPLAIN_WAPKC_SIZE(keyByteLength)))
    ///< Definition of PKC workarea size for the mcuxClRsa_sign function with pkcs1v15 encoding and a private plain key.

#define MCUXCLRSA_INTERNAL_SIGN_PLAIN_WAPKC_SIZE(keyByteLength)  \
    (MCUXCLRSA_MAX(MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_SIGN_PLAIN_PKCS1V15ENCODE_WAPKC_SIZE(keyByteLength), \
                               MCUXCLRSA_INTERNAL_SIGN_PLAIN_PSSENCODE_WAPKC_SIZE(keyByteLength)), \
                  MCUXCLRSA_INTERNAL_SIGN_PLAIN_NOENCODE_WAPKC_SIZE(keyByteLength)))
    ///< Definition of PKC workarea size for the mcuxClRsa_sign function keyByteLength private plain key.

#define MCUXCLRSA_INTERNAL_SIGN_CRT_NOENCODE_WACPU_SIZE(primeByteLength)  \
    (sizeof(mcuxClPkc_State_t)  \
     + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_NOENCODE_WACPU_SIZE,  \
                    MCUXCLRSA_INTERNAL_PRIVATECRT_WACPU_SIZE(primeByteLength)))
    ///< Definition of CPU workarea size for the mcuxClRsa_sign function using NOENCODE option and a private CRT key.

#define MCUXCLRSA_INTERNAL_SIGN_CRT_PKCS1V15ENCODE_WACPU_SIZE(primeByteLength)  \
    (sizeof(mcuxClPkc_State_t)  \
     + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_PKCS1V15ENCODE_SIGN_WACPU_SIZE,  \
                    MCUXCLRSA_INTERNAL_PRIVATECRT_WACPU_SIZE(primeByteLength)))
    ///< Definition of CPU workarea size for the mcuxClRsa_sign function with pkcs1v15 encoding and a private CRT key.

#define MCUXCLRSA_INTERNAL_SIGN_CRT_PSSENCODE_WACPU_SIZE(primeByteLength)  \
    (sizeof(mcuxClPkc_State_t)  \
   + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_PSSENCODE_MAX_WACPU_SIZE(2u*primeByteLength),  \
                  MCUXCLRSA_INTERNAL_PRIVATECRT_WACPU_SIZE(primeByteLength)))
   ///< Definitions of CPU workarea size for the mcuxClRsa_sign function with pss encoding and a private CRT key.

#define MCUXCLRSA_INTERNAL_SIGN_CRT_NOENCODE_WAPKC_SIZE(primeByteLength)  \
    (MCUXCLPKC_ROUNDUP_SIZE(2u * primeByteLength) + \
     MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_NOENCODE_WAPKC_SIZE, MCUXCLRSA_INTERNAL_PRIVATECRT_WAPKC_SIZE(primeByteLength)))
    ///< Definition of PKC workarea size for the mcuxClRsa_Sign function using NOENCODE option and a private CRT key.

#define MCUXCLRSA_INTERNAL_SIGN_CRT_PSSENCODE_WAPKC_SIZE(primeByteLength)  \
    ((MCUXCLPKC_ROUNDUP_SIZE(2u * primeByteLength) + \
     MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_PSSENCODE_MAX_WAPKC_SIZE(2u * primeByteLength), MCUXCLRSA_INTERNAL_PRIVATECRT_WAPKC_SIZE(primeByteLength))))
    ///< Definition of PKC workarea size for the mcuxClRsa_sign function with pss encoding and a private CRT key.

#define MCUXCLRSA_INTERNAL_SIGN_CRT_PKCS1V15ENCODE_WAPKC_SIZE(primeByteLength)  \
    (MCUXCLPKC_ROUNDUP_SIZE(2u * primeByteLength) + \
     MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_PKCS1V15ENCODE_SIGN_WAPKC_SIZE(2u * primeByteLength), MCUXCLRSA_INTERNAL_PRIVATECRT_WAPKC_SIZE(primeByteLength)))
    ///< Definition of PKC workarea size for the mcuxClRsa_sign function with pkcs1v15 encoding and a private CRT key.

#define MCUXCLRSA_INTERNAL_SIGN_CRT_WAPKC_SIZE(keyByteLength)  \
    (MCUXCLRSA_MAX(MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_SIGN_CRT_PKCS1V15ENCODE_WAPKC_SIZE(keyByteLength), \
                               MCUXCLRSA_INTERNAL_SIGN_CRT_PSSENCODE_WAPKC_SIZE(keyByteLength)), \
                  MCUXCLRSA_INTERNAL_SIGN_CRT_NOENCODE_WAPKC_SIZE(keyByteLength)))
    ///< Definition of PKC workarea size for the mcuxClRsa_sign function keyByteLength CRT key.

/** @} */


/*****************************************************************************************/
/* Definitions of workarea size for the mcuxClRsa_MillerRabinTest function.               */
/*****************************************************************************************/
/**
 * @defgroup MCUXCLRSA_INTERNAL_MILLERRABINTEST_WA MCUXCLRSA_INTERNAL_MILLERRABINTEST_WA
 * @brief Workarea size macros of mcuxClRsa_MillerRabinTest
 * @ingroup mcuxClRsa_Internal_Macros
 * @{
 */
#ifdef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
#define MCUXCLRSA_INTERNAL_MILLERRABINTEST_WACPU_SIZE(primeByteLength)  \
    (MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE(primeByteLength))
///< Definition of CPU workarea size for the mcuxClRsa_MillerRabinTest function depending on the byte-length of primeByteLength.
#else
//The parameters are just to keep the API consistent
#define MCUXCLRSA_INTERNAL_MILLERRABINTEST_WACPU_SIZE(primeByteLength)  \
    (0u)
///< Definition of CPU workarea size for the mcuxClRsa_MillerRabinTest function depending on the byte-length of primeByteLength.
#endif

#define MCUXCLRSA_INTERNAL_MILLERRABINTEST_T_BUFFER_SIZE(primeByteLength)  \
    (9u * MCUXCLPKC_ROUNDUP_SIZE(primeByteLength) + 10u * MCUXCLPKC_WORDSIZE)
    ///< Definition of PKC workarea size for the mcuxClRsa_MillerRabinTest function depending on the byte-length of primeByteLength.
/** @} */

/*****************************************************************************************/
/* Definitions of workarea sizes for the mcuxClRsa_TestPrimeCandidate function.           */
/*****************************************************************************************/
/**
 * @defgroup MCUXCLRSA_INTERNAL_TESTPRIMECANDIDATE_WA MCUXCLRSA_INTERNAL_TESTPRIMECANDIDATE_WA
 * @brief Workarea size macros of mcuxClRsa_TestPrimeCandidate
 * @ingroup mcuxClRsa_Internal_Macros
 * @{
 */

#define MCUXCLRSA_INTERNAL_TESTPRIMECANDIDATE_WACPU_SIZE_WO_MILLERRABIN \
    (MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE((MCUXCLRSA_INTERNAL_TESTPRIME_UPTRT_SIZE * sizeof(uint16_t))))
///< Definition of CPU workarea size for the mcuxClRsa_TestPrimeCandidate function depending on the byte-length of primeByteLength without mcuxClRsa_MillerRabinTest

#ifndef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
//The parameters are just to keep the API consistent
#define MCUXCLRSA_INTERNAL_TESTPRIMECANDIDATE_WACPU_SIZE(primeByteLength)  \
    (MCUXCLRSA_INTERNAL_TESTPRIMECANDIDATE_WACPU_SIZE_WO_MILLERRABIN)
#else
#define MCUXCLRSA_INTERNAL_TESTPRIMECANDIDATE_WACPU_SIZE(primeByteLength)  \
    (MCUXCLRSA_INTERNAL_TESTPRIMECANDIDATE_WACPU_SIZE_WO_MILLERRABIN  \
     + MCUXCLRSA_INTERNAL_MILLERRABINTEST_WACPU_SIZE(primeByteLength))
///< Definition of CPU workarea size for the mcuxClRsa_TestPrimeCandidate function depending on the byte-length of primeByteLength
#endif

#define MCUXCLRSA_INTERNAL_TESTPRIMECANDIDATE_WAPKC_SIZE(primeByteLength)  \
    (MCUXCLRSA_MAX(2u * MCUXCLPKC_ROUNDUP_SIZE(primeByteLength), \
                  MCUXCLRSA_INTERNAL_MILLERRABINTEST_T_BUFFER_SIZE(primeByteLength)))
    ///< Definition of PKC workarea size for the mcuxClRsa_TestPrimeCandidate function depending on the byte-length of primeByteLength.
/** @} */

/*****************************************************************************************/
/* Definitions of workarea sizes for the mcuxClRsa_GenerateProbablePrime function.        */
/*****************************************************************************************/
/**
 * @defgroup MCUXCLRSA_INTERNAL_GENERATEPROBABLEPRIME_WA MCUXCLRSA_INTERNAL_GENERATEPROBABLEPRIME_WA
 * @brief Workarea size macros of mcuxClRsa_GenerateProbablePrime
 * @ingroup mcuxClRsa_Internal_Macros
 * @{
 */
#ifndef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
//The parameters are just to keep the API consistent
#define MCUXCLRSA_INTERNAL_GENERATEPROBABLEPRIME_WACPU_SIZE_WO_TESTPRIME_AND_MILLERRABIN(primeByteLength)  \
    (MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE((MCUXCLRSA_INTERNAL_GENPRIME_UPTRT_SIZE * sizeof(uint16_t))))
    ///< Definition of CPU workarea size for the mcuxClRsa_GenerateProbablePrime function depending on the byte-length of primeByteLength without mcuxClRsa_TestPrimeCandidate and mcuxClRsa_MillerRabinTest
#else
#define MCUXCLRSA_INTERNAL_GENERATEPROBABLEPRIME_WACPU_SIZE_WO_TESTPRIME_AND_MILLERRABIN(primeByteLength)  \
    (MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE((MCUXCLRSA_INTERNAL_GENPRIME_UPTRT_SIZE * sizeof(uint16_t))) \
    + MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE(primeByteLength))
    ///< Definition of CPU workarea size for the mcuxClRsa_GenerateProbablePrime function depending on the byte-length of primeByteLength without mcuxClRsa_TestPrimeCandidate and mcuxClRsa_MillerRabinTest
#endif

#define MCUXCLRSA_INTERNAL_GENERATEPROBABLEPRIME_WACPU_SIZE(primeByteLength)  \
    (MCUXCLRSA_INTERNAL_GENERATEPROBABLEPRIME_WACPU_SIZE_WO_TESTPRIME_AND_MILLERRABIN(primeByteLength) \
     + MCUXCLRSA_INTERNAL_TESTPRIMECANDIDATE_WACPU_SIZE(primeByteLength))
    ///< Definition of CPU workarea size for the mcuxClRsa_GenerateProbablePrime function depending on the byte-length of primeByteLength.


#define MCUXCLRSA_INTERNAL_GENERATEPROBABLEPRIME_WAPKC_SIZE(primeByteLength)  \
    ((2u * MCUXCLPKC_WORDSIZE) \
     + MCUXCLRSA_INTERNAL_TESTPRIMECANDIDATE_WAPKC_SIZE(primeByteLength))
    ///< Definition of PKC workarea size for the mcuxClRsa_GenerateProbablePrime function depending on the byte-length of primeByteLength.
/** @} */

/****************************************************************************/
/* Definitions of workarea sizes for the mcuxClRsa_ComputeD function.        */
/****************************************************************************/
/**
 * @defgroup MCUXCLRSA_COMPD_WA MCUXCLRSA_COMPD_WA
 * @brief Workarea size macros of mcuxClRsa_ComputeD
 * @ingroup mcuxClRsa_Internal_Macros
 * @{
 */

#define MCUXCLRSA_INTERNAL_COMPUTED_WACPU_SIZE  \
    (MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE((MCUXCLRSA_INTERNAL_COMPD_UPTRT_SIZE * sizeof(uint16_t))))

#define MCUXCLRSA_INTERNAL_COMPUTED_WAPKC_SIZE(primeByteLength)  \
    ((2u * (MCUXCLPKC_ROUNDUP_SIZE(primeByteLength)))  \
     + (3u * MCUXCLPKC_ROUNDUP_SIZE(primeByteLength * 2u)) + (2u * MCUXCLPKC_WORDSIZE))
    ///< Definition of PKC workarea size for the mcuxClRsa_ComputeD function depending on the byte-length of p.
/** @} */

/*************************************************************************************************************************/
/* Definitions of generated key data size for the mcuxClRsa_KeyGeneration_Crt and mcuxClRsa_KeyGeneration_Plain functions. */
/*************************************************************************************************************************/
#ifndef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
#define MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WACPU_SIZE  \
    (MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE(sizeof(mcuxClPkc_State_t)) \
     + MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE((MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_UPTRT_SIZE * sizeof(uint16_t))) \
     + MCUXCLRSA_INTERNAL_GENERATEPROBABLEPRIME_WACPU_SIZE(0))
#else
#define MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WACPU_SIZE(primeByteLength)  \
    (MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE(sizeof(mcuxClPkc_State_t)) \
     + MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE((MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_UPTRT_SIZE * sizeof(uint16_t))) \
     + MCUXCLRSA_INTERNAL_GENERATEPROBABLEPRIME_WACPU_SIZE(primeByteLength))
#endif

#define MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_WAPKC_SIZE(primeByteLength)  \
    (MCUXCLPKC_ROUNDUP_SIZE(primeByteLength) \
     + (2u * (MCUXCLPKC_ROUNDUP_SIZE(primeByteLength) + MCUXCLPKC_WORDSIZE)) \
     + MCUXCLRSA_MAX(MCUXCLRSA_MAX(MCUXCLPKC_ROUNDUP_SIZE(primeByteLength * 2u) + 3u * ((MCUXCLPKC_ROUNDUP_SIZE(primeByteLength) + MCUXCLPKC_WORDSIZE)) , \
                                 (6u * (MCUXCLPKC_ROUNDUP_SIZE(primeByteLength) + MCUXCLPKC_WORDSIZE) + MCUXCLPKC_WORDSIZE)), \
                                  MCUXCLRSA_INTERNAL_GENERATEPROBABLEPRIME_WAPKC_SIZE(primeByteLength)))

#ifndef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
#define MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WACPU_SIZE  \
     (MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE(sizeof(mcuxClPkc_State_t)) \
     + MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE(MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_UPTRT_SIZE * sizeof(uint16_t)) \
     + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_GENERATEPROBABLEPRIME_WACPU_SIZE(0), MCUXCLRSA_INTERNAL_COMPUTED_WACPU_SIZE))
#else
#define MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WACPU_SIZE(primeByteLength)  \
    (MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE(sizeof(mcuxClPkc_State_t)) \
     + MCUXCLRSA_ROUND_UP_TO_CPU_WORDSIZE(MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_UPTRT_SIZE * sizeof(uint16_t)) \
     + MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_GENERATEPROBABLEPRIME_WACPU_SIZE(primeByteLength), MCUXCLRSA_INTERNAL_COMPUTED_WACPU_SIZE))
#endif

#define MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_WAPKC_SIZE(keyByteLength)  \
    ((2u * (MCUXCLPKC_ROUNDUP_SIZE(keyByteLength / 2u) + MCUXCLPKC_WORDSIZE)) \
      + MCUXCLPKC_ROUNDUP_SIZE(keyByteLength) \
      + MCUXCLRSA_MAX((2u *  MCUXCLPKC_ROUNDUP_SIZE(keyByteLength)), /* D and N */ \
                     MCUXCLRSA_MAX(MCUXCLRSA_INTERNAL_GENERATEPROBABLEPRIME_WAPKC_SIZE(keyByteLength / 2u), \
                                  (MCUXCLPKC_ROUNDUP_SIZE(keyByteLength) + MCUXCLPKC_WORDSIZE) /* D + FW */ \
                                   + MCUXCLRSA_INTERNAL_COMPUTED_WAPKC_SIZE(keyByteLength / 2u))))

/**
 * @defgroup MCUXCLRSA_INTERNAL_KEYGENERATION_KEY_DATA_SIZE MCUXCLRSA_INTERNAL_KEYGENERATION_KEY_DATA_SIZE
 * @brief Definitions of bufer sizes for the mcuxClRsa_KeyGeneration_Crt and mcuxClRsa_KeyGeneration_Plain functions.
 * @ingroup mcuxClRsa_Internal_Macros
 * @{
 */

#define MCUXCLRSA_INTERNAL_KEYGENERATION_PLAIN_KEY_DATA_SIZE(keyByteLength)  \
    (sizeof(mcuxClRsa_Key) + (2u * (sizeof(mcuxClRsa_KeyEntry_t) + keyByteLength)))
    ///< Definition of bufer size for the key generation functions for private plain key (key type and key entries followed by the key data, i.e.: n, d).

#define MCUXCLRSA_INTERNAL_KEYGENERATION_CRT_KEY_DATA_SIZE(keyByteLength)  \
    (sizeof(mcuxClRsa_Key) + (5U * (sizeof(mcuxClRsa_KeyEntry_t) + ((keyByteLength + 1u) / 2u))))
    ///< Definition of bufer size for the key generation functions for private CRT key (key type and key entries followed by the key data, i.e.: p, q, qInv, dp, dq).

#define MCUXCLRSA_INTERNAL_KEYGENERATION_PUBLIC_KEY_DATA_SIZE(keyByteLength)  \
    (sizeof(mcuxClRsa_Key) + (2u * (sizeof(mcuxClRsa_KeyEntry_t)+ keyByteLength)))
    ///< Definition of bufer size for the key generation functions for public key (key type and key entries followed by the key data, i.e.: n, e).

/** @} */



#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MCUXCLRSA_INTERNAL_MEMORY_CONSUMPTION_H_ */

