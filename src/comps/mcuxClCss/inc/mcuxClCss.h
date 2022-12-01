/*--------------------------------------------------------------------------*/
/* Copyright 2020 NXP                                                       */
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
 * @file  mcuxClCss.h
 * @brief Top-level include file for the CSSv2 driver
 *
 * This includes headers for all of the functionality provided by the CSSv2 IP.
 *
 * @defgroup mcuxClCss mcuxClCss
 * @brief Css driver
 *
 * This component abstracts the hardware access to the CSSv2 IP.
 * The library exposes the following hardware functionality:
 * <ol>
 *      <li> COMMON
 *          <ul>
 *              <li> Determine information of the underlying CSS hardware IP
 *                  <ul> <li> #mcuxClCss_GetHwVersion </ul>
 *                  @if MCUXCL_FEATURE_CSS_HWCONFIG
 *                  <ul> <li> #mcuxClCss_GetHwConfig </ul>
 *                  @endif
 *                  <ul> <li> #mcuxClCss_GetHwState </ul>
 *              <li> CSSv2 enabling, disabling, and software reset
 *                  <ul> <li> #mcuxClCss_Enable_Async </ul>
 *                  <ul> <li> #mcuxClCss_Reset_Async </ul>
 *                  <ul> <li> #mcuxClCss_Disable </ul>
 *              <li> Interrupt management
 *                  <ul> <li> #mcuxClCss_SetIntEnableFlags </ul>
 *                  <ul> <li> #mcuxClCss_GetIntEnableFlags </ul>
 *                  <ul> <li> #mcuxClCss_ResetIntFlags </ul>
 *                  <ul> <li> #mcuxClCss_SetIntFlags </ul>
 *              <li> Wait for completion of a CSS operation
 *                  <ul> <li> #mcuxClCss_WaitForOperation </ul>
 *                  <ul> <li> #mcuxClCss_LimitedWaitForOperation </ul>
 *              <li> Error handling
 *                  <ul> <li> #mcuxClCss_ResetErrorFlags </ul>
 *                  <ul> <li> #mcuxClCss_GetErrorCode </ul>
 *                  <ul> <li> #mcuxClCss_GetErrorLevel </ul>
 *              <li> Random delay feature for AES based operations
 *                  <ul> <li> #mcuxClCss_SetRandomStartDelay </ul>
 *                  <ul> <li> #mcuxClCss_GetRandomStartDelay </ul>
 *              @if MCUXCL_FEATURE_CSS_LOCKING
 *              <li> CSS Locking
 *                  <ul> <li> #mcuxClCss_GetLock </ul>
 *                  <ul> <li> #mcuxClCss_ReleaseLock </ul>
 *                  <ul> <li> #mcuxClCss_IsLocked </ul>
 *                  <ul> <li> #mcuxClCss_SetMasterUnlock </ul>
 *              @endif
 *              @if MCUXCL_FEATURE_CSS_RESP_GEN
 *              <li> Calculate response to a hardware generated challenge
 *                  <ul> <li> #mcuxClCss_RespGen_Async </ul>
 *              @endif
 *              @if MCUXCL_FEATURE_CSS_DMA_ADDRESS_READBACK
 *              <li> Final Address Readback (security feature)
 *                  <ul> <li> #mcuxClCss_GetLastDmaAddress </ul>
 *              @endif
 *              @if MCUXCL_FEATURE_CSS_DMA_FINAL_ADDRESS_READBACK
 *              <li> Final Address Compare (security feature)
 *                  <ul> <li> #mcuxClCss_CompareDmaFinalOutputAddress </ul>
 *              @endif
 *          </ul>
 *      <li> CRC
 *          <ul>
 *              <li> Command CRC checks
 *                  <ul> <li> #mcuxClCss_ConfigureCommandCRC </ul>
 *                  <ul> <li> #mcuxClCss_GetCommandCRC </ul>
 *                  <ul> <li> #mcuxClCss_VerifyVsRefCRC </ul>
 *                  <ul> <li> #mcuxClCss_UpdateRefCRC </ul>
 *          </ul>
 *      <li> HASH
 *          <ul>
 *              <li> SHA-2 hashing
 *                  <ul> <li> #mcuxClCss_Hash_Async </ul>
 *          @if MCUXCL_FEATURE_CSS_SHA_DIRECT
 *              <li> SHA-2 hashing in direct mode
 *                  <ul> <li> #mcuxClCss_ShaDirect_Enable </ul>
 *                  <ul> <li> #mcuxClCss_ShaDirect_Disable </ul>
 *                  <ul> <li> #mcuxClCss_Hash_ShaDirect </ul>
 *          @endif
 *          </ul>
 *      @if MCUXCL_FEATURE_CSS_HMAC
 *      <li> HMAC (Keyed-Hash Message Authentication Code)
 *          <ul>
 *              <li> HMAC
 *                  <ul> <li> #mcuxClCss_Hmac_Async </ul>
 *          </ul>
 *      @endif
 *      @if MCUXCL_FEATURE_CSS_CMAC
 *      <li> CMAC (Cipher-Based Message Authentication Code)
 *          <ul>
 *              <li> CMAC
 *                  <ul> <li> #mcuxClCss_Cmac_Async </ul>
 *          </ul>
 *      @endif
 *      <li> CIPHER (Symmetric Encryption)
 *          <ul>
 *              <li> AES
 *                  <ul> <li> #mcuxClCss_Cipher_Async </ul>
 *          </ul>
 *      @if MCUXCL_FEATURE_CSS_AEAD
 *      <li> AEAD (Authenticated Encryption with Associated Data)
 *          <ul>
 *              <li> Authenticated Encryption with Associated Data
 *                  <ul>
 *                      <li> #mcuxClCss_Aead_Init_Async
 *                      <li> #mcuxClCss_Aead_UpdateAad_Async
 *                      <li> #mcuxClCss_Aead_UpdateData_Async
 *                      <li> #mcuxClCss_Aead_Finalize_Async
 *                  </ul>
 *          </ul>
 *      @endif
 *      <li> KEY MANAGEMENT
 *          <ul>
 *          @if MCUXCL_FEATURE_CSS_KEY_MGMT_DELETE
 *              <li> Key deletion
 *                  <ul> <li> #mcuxClCss_KeyDelete_Async </ul>
 *          @endif
 *          @if MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV
 *              <li> Key provisioning
 *                  <ul> <li> #mcuxClCss_KeyProvision_Async </ul>
 *          @endif
 *          @if MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV_ROM
 *              <li> Key provisioning (ROM)
 *                  <ul> <li> #mcuxClCss_KeyProvisionRom_Async </ul>
 *          @endif
 *              <li> Key import
 *                  <ul> <li> #mcuxClCss_KeyImport_Async </ul>
 *          @if MCUXCL_FEATURE_CSS_PUK_INTERNAL
 *              <li> Public key import
 *                  <ul> <li> #mcuxClCss_KeyImportPuk_Async </ul>
 *          @endif
 *          @if MCUXCL_FEATURE_CSS_KEY_MGMT_EXPORT
 *              <li> Key export
 *                  <ul> <li> #mcuxClCss_KeyExport_Async </ul>
 *          @endif
 *              <li> Key properties
 *                  <ul> <li> #mcuxClCss_GetKeyProperties </ul>
 *          </ul>
 *      @if MCUXCL_FEATURE_CSS_RNG
 *      <li> RNG
 *          <ul>
 *              <li> Random data generation using DRBG
 *                  <ul> <li> #mcuxClCss_Rng_DrbgRequest_Async </ul>
 *              @if MCUXCL_FEATURE_CSS_RND_RAW
 *              <li> Get raw (unprocessed) random data from the DTRNG
 *                  <ul> <li> #mcuxClCss_Rng_DrbgRequestRaw_Async </ul>
 *              @endif
 *              <li> FIPS CAVP test mode
 *                  <ul> <li> #mcuxClCss_Rng_DrbgTestInstantiate_Async </ul>
 *                  <ul> <li> #mcuxClCss_Rng_DrbgTestExtract_Async </ul>
 *                  <ul> <li> #mcuxClCss_Rng_DrbgTestAesEcb_Async </ul>
 *                  <ul> <li> #mcuxClCss_Rng_DrbgTestAesCtr_Async </ul>
 *              <li> Configuration of the DTRNG
 *                  <ul> <li> #mcuxClCss_Rng_Dtrng_ConfigLoad_Async </ul>
 *                  <ul> <li> #mcuxClCss_Rng_Dtrng_ConfigEvaluate_Async </ul>
 *              <li> PRNG
 *              @if MCUXCL_FEATURE_CSS_PRND_INIT
 *                  <ul> <li> #mcuxClCss_Prng_Init_Async </ul>
 *              @endif
 *                  <ul> <li> #mcuxClCss_Prng_GetRandomWord </ul>
 *                  <ul> <li> #mcuxClCss_Prng_GetRandom </ul>
 *          </ul>
 *      @endif
 *      <li> ECC (Elliptic Curve Cryptography)
 *          <ul>
 *              <li> ECC Key generation
 *                  <ul> <li> #mcuxClCss_EccKeyGen_Async </ul>
 *              @if MCUXCL_FEATURE_CSS_ECC_KEY_EXCHANGE
 *              <li> ECC key exchange
 *                  <ul> <li> #mcuxClCss_EccKeyExchange_Async </ul>
 *                  @if MCUXCL_FEATURE_CSS_PUK_INTERNAL
 *                  <ul> <li> #mcuxClCss_EccKeyExchangeInt_Async </ul>
 *                  @endif
 *              @endif
 *              <li> ECC signature generation
 *                  <ul> <li> #mcuxClCss_EccSign_Async </ul>
 *              <li> ECC signature verification
 *                  <ul> <li> #mcuxClCss_EccVerify_Async </ul>
 *              @if MCUXCL_FEATURE_CSS_PUK_INTERNAL
 *                  <ul> <li> #mcuxClCss_EccVerifyInt_Async </ul>
 *              @endif
 *          </ul>
 *      <li> KEY DERIVATION
 *          <ul>
 *              <li> Key derivation
 *                  <ul>
 *                      @if MCUXCL_FEATURE_CSS_CKDF
 *                      <li> #mcuxClCss_Ckdf_Sp800108_Async
 *                      @if  MCUXCL_FEATURE_CSS_CKDF_SP80056C
 *                      <li> #mcuxClCss_Ckdf_Sp80056c_Extract_Async
 *                      <li> #mcuxClCss_Ckdf_Sp80056c_Expand_Async
 *                      @endif
 *                      @endif
 *                      @if MCUXCL_FEATURE_CSS_HKDF
 *                      <li> #mcuxClCss_Hkdf_Rfc5869_Async
 *                      <li> #mcuxClCss_Hkdf_Sp80056c_Async
 *                      @endif
 *                  </ul>
 *              @if MCUXCL_FEATURE_CSS_TLS
 *              <li> Master Key and Session Key derivation
 *                  <ul>
 *                      <li> #mcuxClCss_TlsGenerateMasterKeyFromPreMasterKey_Async
 *                      <li> #mcuxClCss_TlsGenerateSessionKeysFromMasterKey_Async
 *                  </ul>
 *              @endif
 *          </ul>
 *      @if MCUXCL_FEATURE_CSS_GLITCHDETECTOR
 *      <li> CSSv2 Glitch Detector control
 *          <ul>
 *              <li> #mcuxClCss_GlitchDetector_LoadConfig_Async
 *              <li> #mcuxClCss_GlitchDetector_Trim_Async
 *              <li> #mcuxClCss_GlitchDetector_GetEventCounter
 *              <li> #mcuxClCss_GlitchDetector_ResetEventCounter
 *          </ul>
 *      @endif
 *  </ol>
 *
 *  After each call to a function ending in <tt>_Async</tt>, one of the waiting functions #mcuxClCss_WaitForOperation or #mcuxClCss_LimitedWaitForOperation must be called to ensure completion.
 *  The waiting functions may fail, e.g., when the CSSv2 enters an error state.
 */

#ifndef MCUXCLCSS_H_
#define MCUXCLCSS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <platform_specific_headers.h>

#include <mcuxClCss_Types.h>
#include <mcuxClCss_Common.h>
#ifdef MCUXCL_FEATURE_CSS_CMD_CRC
#include <mcuxClCss_Crc.h>
#endif /* MCUXCL_FEATURE_CSS_CMD_CRC */
#include <mcuxClCss_Hash.h>
#include <mcuxClCss_Hmac.h>
#include <mcuxClCss_Cmac.h>
#include <mcuxClCss_Cipher.h>
#include <mcuxClCss_Aead.h>
#include <mcuxClCss_KeyManagement.h>
#include <mcuxClCss_Rng.h>
#include <mcuxClCss_Ecc.h>
#include <mcuxClCss_Kdf.h>

#endif /* MCUXCLCSS_H_ */
