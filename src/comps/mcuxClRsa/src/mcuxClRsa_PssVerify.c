/*--------------------------------------------------------------------------*/
/* Copyright 2020-2022 NXP                                                  */
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

/** @file  mcuxClRsa_PssVerify.c
 *  @brief mcuxClRsa: function, which is called to execute EMSA-PSS-VERIFY
 */

#include <stdint.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <mcuxClMemory.h>

#include <mcuxClHash.h>
#include <internal/mcuxClHash_Internal.h>
#include <mcuxCsslParamIntegrity.h>
#include <mcuxCsslMemory.h>

#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClMemory_Copy_Internal.h>
#include <toolchain.h>

#include <mcuxClRsa.h>
#include <internal/mcuxClRsa_Internal_Functions.h>
#include <internal/mcuxClRsa_Internal_Types.h>
#include <internal/mcuxClRsa_Internal_Macros.h>
#include <internal/mcuxClRsa_Internal_MemoryConsumption.h>


/**********************************************************/
/* Specification of PSS-verify mode structures            */
/**********************************************************/
/* MISRA Ex. 20 - Rule 5.1 */
const mcuxClRsa_SignVerifyMode_t mcuxClRsa_Mode_Verify_Pss_Sha2_224 =
{
  .EncodeVerify_FunId = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_pssVerify),
  .pHashAlgo1 = &mcuxClHash_AlgorithmDescriptor_Sha224,
  .pHashAlgo2 = NULL,
  .pPaddingFunction = mcuxClRsa_pssVerify
};

/* MISRA Ex. 20 - Rule 5.1 */
const mcuxClRsa_SignVerifyMode_t mcuxClRsa_Mode_Verify_Pss_Sha2_256 =
{
  .EncodeVerify_FunId = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_pssVerify),
  .pHashAlgo1 = &mcuxClHash_AlgorithmDescriptor_Sha256,
  .pHashAlgo2 = NULL,
  .pPaddingFunction = mcuxClRsa_pssVerify
};
const mcuxClRsa_SignVerifyMode_t mcuxClRsa_Mode_Verify_Pss_Sha2_384 =
{
  .EncodeVerify_FunId = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_pssVerify),
  .pHashAlgo1 = &mcuxClHash_AlgorithmDescriptor_Sha384,
  .pHashAlgo2 = NULL,
  .pPaddingFunction = mcuxClRsa_pssVerify
};
const mcuxClRsa_SignVerifyMode_t mcuxClRsa_Mode_Verify_Pss_Sha2_512 =
{
  .EncodeVerify_FunId = MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_pssVerify),
  .pHashAlgo1 = &mcuxClHash_AlgorithmDescriptor_Sha512,
  .pHashAlgo2 = NULL,
  .pPaddingFunction = mcuxClRsa_pssVerify
};



MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_pssVerify)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRsa_Status_t) mcuxClRsa_pssVerify(
  mcuxClSession_Handle_t       pSession,
  mcuxCl_InputBuffer_t         pInput,
  const uint32_t              inputLength,
  mcuxCl_Buffer_t              pVerificationInput,
  mcuxClHash_Algo_t            pHashAlgo,
  const uint8_t *             pLabel,
  const uint32_t              saltlabelLength,
  const uint32_t              keyBitLength,
  const uint32_t              options,
  mcuxCl_Buffer_t              pOutput,
  uint32_t * const            pOutLength)
{

  MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_pssVerify);

  /* Setup session. */

  /* Length of the encoded message. */
  const uint32_t emLen = keyBitLength / 8U; /* only byte-level granularity of keys is supported, thus keyBitLength is a multiple of 8 */
  /* Length of padding with 8 zero bytes. */
  const uint32_t padding1Length = MCUXCLRSA_PSS_PADDING1_LEN;
  /* Length of the output of hash function. */
  const uint32_t hLen = pHashAlgo->hashSize;
  /* Length of the EMSA-PSS salt. */
  const uint32_t sLen = saltlabelLength;
  /* Length of DB (and maskedDB). */
  const uint32_t dbLen = emLen - hLen - 1U;

  const uint16_t wordSizeWa = MCUXCLRSA_INTERNAL_PSSVERIFY_WAPKC_SIZE_WO_MGF1(emLen, hLen, sLen) / sizeof(uint32_t);
#ifndef MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS
  uint8_t *pWorkarea = (uint8_t *) mcuxClSession_allocateWords_pkcWa(pSession, wordSizeWa);

  #ifdef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
  const uint16_t cpuWaSizeWord = MCUXCLRSA_INTERNAL_PSSVERIFY_WACPU_SIZE_WO_MGF1(hLen, sLen) / sizeof(uint32_t);
  /* Pointer to the cpu buffer for the M' = | padding_1 | mHash | salt | */
  uint8_t * pMprimCpu = (uint8_t *) mcuxClSession_allocateWords_cpuWa(pSession, cpuWaSizeWord);
  /* Update CPU workarea */

#endif /* MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND */
#else
  /* TODO CLNS-6084: instead of moving the unaligned accesses to CPU RAM, which requires a huge ammount of CPU RAM and unnecessary operations such as memcopy,
   * it should be analyzed, whether it is possible to just target the places where unaligned accessed in PKC RAM occur, and ensure that those particular memory
   * accesses are aligned, or moved to the CPU RAM.
   * Based on a first analysis, here are the only two pointers that may be unaligned in PKC RAM and cause issues due to word-aligned accesses:
   * - pHprim: output of hash (unlikely to cause issues there), input to cssl comparison (where data is accessed in a loop on words).
   *   Can be easily moved to be always aligned, which would require at most 3 bytes of PKC RAM and no extra operation.
   * - pH: second input to the cssl comparison.
   *   Should be copied somewhere else (CPU RAM or PKC RAM): requires one extra copy, on length hLen (which is still better than copying keyByteLen to the CPU RAM)
   *
   * Also, an analysis of the dependency between both workarounds ELS_ACCESS_PKCRAM_WORKAROUND and PKC_PKCRAM_NO_UNALIGNED_ACCESS should be done, and
   * workarounds should be either completely independent of each other, or merged more explicitly into a single workaround.
   */
  uint8_t *pWorkarea = (uint8_t *) mcuxClSession_allocateWords_cpuWa(pSession, wordSizeWa);
#endif /* MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS */

  /*
   * Set buffers in PKC workarea
   * PKC = | M'= (padding | mHash | salt) || dbMask (and DB) || H' |
   */
  /* Pointer to the encoded message */
  mcuxCl_Buffer_t pEm = pVerificationInput;
  /* Pointer to the buffer for the M' = | padding_1 | mHash | salt | */
  mcuxCl_Buffer_t pMprim = pWorkarea;
  /* Pointer to the buffer for the mHash in the M'*/
  mcuxCl_Buffer_t pMHash = pMprim + padding1Length;
  /* Pointer to the buffer for the salt in the M'*/
  mcuxCl_Buffer_t pSalt = pMHash + hLen;

  /* Pointer to the buffer for the dbMask'*/
  mcuxCl_Buffer_t pDbMask = pSalt + sLen;
  /* Pointer to the buffer for the H' */
  mcuxCl_Buffer_t pHprim = pDbMask + dbLen;

  const uint32_t mprimLen = padding1Length + hLen + sLen;

  /* Step 2: Let mHash = Hash(M), an octet string of length hLen. */
  if(MCUXCLRSA_OPTION_MESSAGE_PLAIN == (options & MCUXCLRSA_OPTION_MESSAGE_MASK))
  {
    /* Call hash function on pInput (Hash(pInput)) and store result in buffer mHash */
    uint32_t hashOutputSize = 0u;

    MCUX_CSSL_FP_FUNCTION_CALL(hash_result1, mcuxClHash_compute(pSession,
                                                              pHashAlgo,
                                                              pInput,
                                                              inputLength,
                                                              pMHash,
                                                              &hashOutputSize
    ));

    if(MCUXCLHASH_STATUS_OK != hash_result1)
    {
#ifndef MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS
      mcuxClSession_freeWords_pkcWa(pSession, wordSizeWa);
#ifdef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
      mcuxClSession_freeWords_cpuWa(pSession, cpuWaSizeWord);
#endif /* MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND */
#else
      mcuxClSession_freeWords_cpuWa(pSession, wordSizeWa);
#endif /* MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS */
      MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_pssVerify, MCUXCLRSA_STATUS_ERROR);
    }
  }
  else if (MCUXCLRSA_OPTION_MESSAGE_DIGEST == (options & MCUXCLRSA_OPTION_MESSAGE_MASK))
  {
    /* Copy pInput to buffer mHash */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy(pMHash, pInput, hLen, hLen));
  }
  else
  {
#ifndef MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS
      mcuxClSession_freeWords_pkcWa(pSession, wordSizeWa);
#ifdef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
      mcuxClSession_freeWords_cpuWa(pSession, cpuWaSizeWord);
#endif /* MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND */
#else
      mcuxClSession_freeWords_cpuWa(pSession, wordSizeWa);
#endif /* MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS */

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_pssVerify, MCUXCLRSA_STATUS_ERROR);
  }

  /* Step 3: If BYTE_LENGTH(keyBitLength) < (pHashAlgo->hashSize + saltlabelLength + 2)
  *  return MCUXCLRSA_STATUS_VERIFY_FAILED else continue operation. */
  /* Additional checks on salt-length for FIPS 186-4 compliance */
  /* Step 4: Check if the leftmost octet of Em (before endianess switch) has hexadecimal value 0xbc.*/
  if((((1024U == keyBitLength) && (512U == (8U * hLen)) && ((hLen - 2U) < sLen)) || (hLen < sLen))
          || (emLen < (hLen + sLen + 2U)) || (0xbcU != *pEm))
  {
#ifndef MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS
      mcuxClSession_freeWords_pkcWa(pSession, wordSizeWa);
#ifdef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
      mcuxClSession_freeWords_cpuWa(pSession, cpuWaSizeWord);
#endif /* MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND */
#else
      mcuxClSession_freeWords_cpuWa(pSession, wordSizeWa);
#endif /* MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS */

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_pssVerify, MCUXCLRSA_STATUS_VERIFY_FAILED,
      MCUX_CSSL_FP_CONDITIONAL((MCUXCLRSA_OPTION_MESSAGE_PLAIN == (options & MCUXCLRSA_OPTION_MESSAGE_MASK)),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute)),
      MCUX_CSSL_FP_CONDITIONAL((MCUXCLRSA_OPTION_MESSAGE_DIGEST == (options & MCUXCLRSA_OPTION_MESSAGE_MASK)),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy)));
  }

  /* Switch endianess of EM buffer to big-endian byte order in place */
  /* MISRA Ex. 9 to Rule 11.3 */
  MCUXCLPKC_FP_SWITCHENDIANNESS((uint32_t *) pEm, emLen);  /* the pEm PKC buffer is CPU word aligned. */

  /* Step 5: Let maskedDB be the leftmost emLen-hLen-1 octets of EM and let H be the next hLen octets. */
  mcuxCl_Buffer_t maskedDB = pEm;
  mcuxCl_Buffer_t pH = pEm + dbLen;

  /* Step 6: Check if 8*emLen-emBits leftmost bits equal to zero. Note that, as keyBitLength is a multiple of 8, 8 * emLen - emBits = 1 bit.*/
  if(0U != ((*maskedDB) & 0x80u))
  {
#ifndef MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS
      mcuxClSession_freeWords_pkcWa(pSession, wordSizeWa);
#ifdef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
      mcuxClSession_freeWords_cpuWa(pSession, cpuWaSizeWord);
#endif /* MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND */
#else
      mcuxClSession_freeWords_cpuWa(pSession, wordSizeWa);
#endif /* MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS */

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_pssVerify, MCUXCLRSA_STATUS_VERIFY_FAILED,
      MCUX_CSSL_FP_CONDITIONAL((MCUXCLRSA_OPTION_MESSAGE_PLAIN == (options & MCUXCLRSA_OPTION_MESSAGE_MASK)),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute)),
      MCUX_CSSL_FP_CONDITIONAL((MCUXCLRSA_OPTION_MESSAGE_DIGEST == (options & MCUXCLRSA_OPTION_MESSAGE_MASK)),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy)),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_SwitchEndianness));
  }

  /* Step 7: dbMask = MGF(H, BYTE_LENGTH(keyBitLength) - pHashAlgo->hashSize - 1) */

  MCUX_CSSL_FP_FUNCTION_CALL(retVal_mcuxClRsa_mgf1, mcuxClRsa_mgf1(pSession, pHashAlgo, pH, hLen, dbLen, pDbMask));

  if(MCUXCLRSA_INTERNAL_STATUS_MGF_OK != retVal_mcuxClRsa_mgf1)
  {
#ifndef MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS
      mcuxClSession_freeWords_pkcWa(pSession, wordSizeWa);
#ifdef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
      mcuxClSession_freeWords_cpuWa(pSession, cpuWaSizeWord);
#endif /* MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND */
#else
      mcuxClSession_freeWords_cpuWa(pSession, wordSizeWa);
#endif /* MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS */

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_pssVerify, MCUXCLRSA_STATUS_ERROR);
  }

  /* Step 8: DB = pOutput(0 : BYTE_LENGTH(keyBitLength) - pHashAlgo->hashSize - 1) XOR dbMask.*/
  mcuxCl_Buffer_t pDB = pDbMask; // reuse the space of DbMask

  MCUX_CSSL_FP_LOOP_DECL(loop1);
  for(uint32_t i = 0u; i < dbLen; ++i)
  {
    *(pDB + i) = *(maskedDB + i) ^ *(pDbMask + i);
     MCUX_CSSL_FP_LOOP_ITERATION(loop1);
  }

  /* Step 9: Set the leftmost 8emLen - emBits bits of the leftmost octet in DB to zero. */
  pDB[0] &= 0x7Fu;

  /* Step 10 */
  /* Check (DB(0 : BYTE_LENGTH(keyBitLength) - pHashAlgo->hashSize - saltlabelLength - 2) == [0x00, ..., 0x00])
   * and that (DB(BYTE_LENGTH(keyBitLength) - pHashAlgo->hashSize - saltlabelLength - 1) == 0x01) ? */
  uint32_t counterZeros = 0u;
  const uint32_t padding2Length = emLen - hLen - sLen - 2u;

  MCUX_CSSL_FP_LOOP_DECL(loop2);
  for(uint32_t i = 0u; i < padding2Length; ++i)
  {
    if(0u == pDB[i])
    {
        ++counterZeros;
    }
    MCUX_CSSL_FP_LOOP_ITERATION(loop2);
  }
  if((counterZeros != padding2Length) || (0x01u != pDB[padding2Length]))
  {
#ifndef MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS
      mcuxClSession_freeWords_pkcWa(pSession, wordSizeWa);
#ifdef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
      mcuxClSession_freeWords_cpuWa(pSession, cpuWaSizeWord);
#endif /* MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND */
#else
      mcuxClSession_freeWords_cpuWa(pSession, wordSizeWa);
#endif /* MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS */

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_pssVerify, MCUXCLRSA_STATUS_VERIFY_FAILED,
      MCUX_CSSL_FP_CONDITIONAL((MCUXCLRSA_OPTION_MESSAGE_PLAIN == (options & MCUXCLRSA_OPTION_MESSAGE_MASK)),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute)),
      MCUX_CSSL_FP_CONDITIONAL((MCUXCLRSA_OPTION_MESSAGE_DIGEST == (options & MCUXCLRSA_OPTION_MESSAGE_MASK)),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy)),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_SwitchEndianness),
          MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_mgf1),
          MCUX_CSSL_FP_LOOP_ITERATIONS(loop1, dbLen),
          MCUX_CSSL_FP_LOOP_ITERATIONS(loop2, padding2Length));
  }

  /* Step 11: Copy salt to mPrime buffer */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy(pSalt, pDB + dbLen - sLen, sLen, sLen));

  /* Step 12 */
  /* mPrime = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 || mHash || DB(BYTE_LENGTH(keyBitLength) - saltlabelLength: BYTE_LENGTH(keyBitLength))] */
  MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_clear(pMprim, padding1Length, padding1Length));

  /* Step 13: HPrime = Hash(mPrime) */
  uint32_t hashOutputSize = 0u;
#ifndef MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS
#ifdef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
  MCUX_CSSL_FP_FUNCTION_CALL(memcopy_result1, mcuxClMemory_copy(pMprimCpu, pMprim, mprimLen, mprimLen));
  if(0u != memcopy_result1)
  {
    mcuxClSession_freeWords_pkcWa(pSession, wordSizeWa);
    mcuxClSession_freeWords_cpuWa(pSession, cpuWaSizeWord);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_pssVerify, MCUXCLRSA_STATUS_ERROR);
  }
  MCUX_CSSL_FP_FUNCTION_CALL(hash_result_2, mcuxClHash_compute(pSession,
                                                             pHashAlgo,
                                                             pMprimCpu,
                                                             mprimLen,
                                                             pHprim,
                                                             &hashOutputSize
    ));

  if(MCUXCLHASH_STATUS_OK != hash_result_2)
  {
    mcuxClSession_freeWords_pkcWa(pSession, wordSizeWa);
    mcuxClSession_freeWords_cpuWa(pSession, cpuWaSizeWord);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_pssVerify, MCUXCLRSA_STATUS_ERROR);
  }
#else
  MCUX_CSSL_FP_FUNCTION_CALL(hash_result_2, mcuxClHash_compute(pSession,
                                                             pHashAlgo,
                                                             pMprim,
                                                             mprimLen,
                                                             pHprim,
                                                             &hashOutputSize
    ));

  if(MCUXCLHASH_STATUS_OK != hash_result_2)
  {
    mcuxClSession_freeWords_pkcWa(pSession, wordSizeWa);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_pssVerify, MCUXCLRSA_STATUS_ERROR);
  }
#endif /* MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND */
#else
  MCUX_CSSL_FP_FUNCTION_CALL(hash_result_2, mcuxClHash_compute(pSession,
                                                             pHashAlgo,
                                                             pMprim,
                                                             mprimLen,
                                                             pHprim,
                                                             &hashOutputSize
    ));

  if(MCUXCLHASH_STATUS_OK != hash_result_2)
  {
    mcuxClSession_freeWords_cpuWa(pSession, wordSizeWa);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_pssVerify, MCUXCLRSA_STATUS_ERROR);
  }
#endif /* MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS */

  /* Step 14 verify5 = (HPrime == H) ? true : false. */
  MCUX_CSSL_FP_FUNCTION_CALL(compare_result, mcuxCsslMemory_Compare(mcuxCsslParamIntegrity_Protect(3u, pH, pHprim, hLen),
                                                                  pH,
                                                                  pHprim,
                                                                  hLen));

  mcuxClRsa_Status_t pssVerifyStatus = MCUXCLRSA_STATUS_VERIFY_FAILED;
  if(compare_result == MCUXCSSLMEMORY_STATUS_EQUAL)
  {
    pssVerifyStatus = MCUXCLRSA_STATUS_VERIFY_OK;
  }

  /************************************************************************************************/
  /* Function exit                                                                                */
  /************************************************************************************************/
#ifndef MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS
      mcuxClSession_freeWords_pkcWa(pSession, wordSizeWa);
#ifdef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
      mcuxClSession_freeWords_cpuWa(pSession, cpuWaSizeWord);
#endif /* MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND */
#else
      mcuxClSession_freeWords_cpuWa(pSession, wordSizeWa);
#endif /* MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS */


/* Use temporary defines to avoid preprocessor directives inside the function exit macro below,
   as this would violate the MISRA rule 20.6 otherwise. */
#ifndef MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS
#ifdef MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND
  #define TMP_PKCRAM_WORKAROUND \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy), \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute)
#else
  #define TMP_PKCRAM_WORKAROUND \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute)
#endif /* MCUXCL_FEATURE_ELS_ACCESS_PKCRAM_WORKAROUND */
#else
#define TMP_PKCRAM_WORKAROUND \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute)
#endif /* MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS */

  #define TMP_ENABLE_COMPARE \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxCsslMemory_Compare), \
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_clear)

  MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_pssVerify, pssVerifyStatus,
    MCUX_CSSL_FP_CONDITIONAL((MCUXCLRSA_OPTION_MESSAGE_PLAIN == (options & MCUXCLRSA_OPTION_MESSAGE_MASK)),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClHash_compute)),
    MCUX_CSSL_FP_CONDITIONAL((MCUXCLRSA_OPTION_MESSAGE_DIGEST == (options & MCUXCLRSA_OPTION_MESSAGE_MASK)),
      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy)),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_SwitchEndianness),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_mgf1),
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop1, dbLen),
    MCUX_CSSL_FP_LOOP_ITERATIONS(loop2, padding2Length),
    MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
    TMP_PKCRAM_WORKAROUND,
    TMP_ENABLE_COMPARE
  );

#undef TMP_PKCRAM_WORKAROUND
#undef TMP_ENABLE_COMPARE

}
