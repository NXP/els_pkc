/*--------------------------------------------------------------------------*/
/* Copyright 2021 NXP                                                       */
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
 * @file  mcuxClCss_Crc.h
 * @brief CSSv2 header for Command CRC functionality.
 *
 * This header exposes functions that support the usage of the Command CRC feature for CSSv2.
 */
/**
 * @defgroup mcuxClCss_Crc mcuxClCss_Crc
 * @brief This part of the @ref mcuxClCss driver defines the Command CRC functionality
 * @ingroup mcuxClCss
 * @{
 */
#ifndef MCUXCLCSS_CRC_H_
#define MCUXCLCSS_CRC_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClCss_Types.h> // Common types
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

/**********************************************
 * CONSTANTS
 **********************************************/
/**
 * @defgroup mcuxClCss_Crc_Macros mcuxClCss_Crc_Macros
 * @brief Defines all macros of @ref mcuxClCss_Crc
 * @ingroup mcuxClCss_Crc
 * @{
 */

/**
 * @defgroup MCUXCLCSS_CMD_CRC_ MCUXCLCSS_CMD_CRC_
 * @brief Constants for CSS Command CRC
 * @ingroup mcuxClCss_Crc_Macros
 * @{ */
#define MCUXCLCSS_CMD_CRC_VALUE_RESET    ((uint32_t) 0x1u) ///< Reset the Command CRC to initial value
#define MCUXCLCSS_CMD_CRC_VALUE_ENABLE   ((uint32_t) 0x2u) ///< Enable update of Command CRC value by executing commands
#define MCUXCLCSS_CMD_CRC_VALUE_DISABLE  ((uint32_t) 0x0u) ///< Disable update of Command CRC value by executing commands

#define MCUXCLCSS_CMD_CRC_RESET          ((uint32_t) 0x1u) ///< Reset the Command CRC to initial value
#define MCUXCLCSS_CMD_CRC_ENABLE         ((uint32_t) 0x1u) ///< Enable update of Command CRC value by executing commands
#define MCUXCLCSS_CMD_CRC_DISABLE        ((uint32_t) 0x0u) ///< Disable update of Command CRC value by executing commands

#define MCUXCLCSS_CMD_CRC_POLYNOMIAL     ((uint32_t) 0x04C11DB7u) ///< CRC polynomial for the Command CRC
#define MCUXCLCSS_CMD_CRC_INITIAL_VALUE  ((uint32_t) 0xA5A5A5A5u) ///< Initial value for the Command CRC
/** @} */

/**
 * @defgroup MCUXCLCSS_CMD_CRC_REFERENCE_ MCUXCLCSS_CMD_CRC_REFERENCE_
 * @brief Macros for reference CSS Command CRC
 * @ingroup mcuxClCss_Crc_Macros
 * @{
 */

/**
 * @brief Initializes a reference CRC variable with the command CRC initial value.
 *        The new variable has the given name.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_INIT(crc)  \
    uint32_t (crc) = MCUXCLCSS_CMD_CRC_INITIAL_VALUE

/**
 * @brief Resets the given reference CRC variable to the command CRC initial value.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_RESET(crc)  \
    (crc) = MCUXCLCSS_CMD_CRC_INITIAL_VALUE

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Aead_Init_Async.
 */
#ifndef MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_AEAD_INIT(crc, options)                \
  ({                                                                             \
    (options).bits.acpmod = MCUXCLCSS_AEAD_ACPMOD_INIT;                           \
    (options).bits.lastinit = MCUXCLCSS_AEAD_LASTINIT_TRUE;                       \
    (options).bits.acpsie = MCUXCLCSS_AEAD_STATE_IN_DISABLE;                      \
    (options).bits.acpsoe = MCUXCLCSS_AEAD_STATE_OUT_ENABLE;                      \
    mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_AUTH_CIPHER, (options).word.value, &(crc)); \
	(retVal);                                                                    \
  })
#else
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_AEAD_INIT(crc, options)                \
  ({                                                                             \
    (options).bits.acpmod = MCUXCLCSS_AEAD_ACPMOD_INIT;                           \
    (options).bits.lastinit = MCUXCLCSS_AEAD_LASTINIT_TRUE;                       \
    (options).bits.acpsie = MCUXCLCSS_AEAD_STATE_IN_DISABLE;                      \
    mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_AUTH_CIPHER, (options).word.value, &(crc)); \
    (retVal);                                                                    \
  })
#endif /* MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS */

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Aead_PartialInit_Async.
 */
#ifndef MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_AEAD_PARTIALINIT(crc, options)         \
  ({                                                                             \
    (options).bits.acpmod = MCUXCLCSS_AEAD_ACPMOD_INIT;                           \
    (options).bits.acpsoe = MCUXCLCSS_AEAD_STATE_OUT_ENABLE;                      \
    mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_AUTH_CIPHER, (options).word.value, &(crc)); \
    (retVal);                                                                    \
  })
#else
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_AEAD_PARTIALINIT(crc, options)         \
  ({                                                                             \
    (options).bits.acpmod = MCUXCLCSS_AEAD_ACPMOD_INIT;                           \
    mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_AUTH_CIPHER, (options).word.value, &(crc)); \
    (retVal);                                                                    \
  })
#endif /* MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS */

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Aead_UpdateAad_Async.
 */
#ifndef MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_AEAD_UPDATEAAD(crc, options)           \
  ({                                                                             \
    (options).bits.acpmod = MCUXCLCSS_AEAD_ACPMOD_AADPROC                         \
    (options).bits.acpsie = MCUXCLCSS_AEAD_STATE_IN_ENABLE;                       \
    (options).bits.acpsoe = MCUXCLCSS_AEAD_STATE_OUT_ENABLE;                      \
    mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_AUTH_CIPHER, (options).word.value, &(crc)); \
    (retVal);                                                                    \
  })
#else
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_AEAD_UPDATEAAD(crc, options)           \
  ({                                                                             \
    (options).bits.acpmod = MCUXCLCSS_AEAD_ACPMOD_AADPROC;                        \
    mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_AUTH_CIPHER, (options).word.value, &(crc)); \
    (retVal);                                                                    \
  })
#endif /* MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS */

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Aead_UpdateData_Async.
 */
#ifndef MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_AEAD_UPDATEDATA(crc, options)          \
  ({                                                                             \
    (options).bits.acpmod = MCUXCLCSS_AEAD_ACPMOD_MSGPROC                         \
    (options).bits.acpsie = MCUXCLCSS_AEAD_STATE_IN_ENABLE;                       \
    (options).bits.acpsoe = MCUXCLCSS_AEAD_STATE_OUT_ENABLE;                      \
    mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_AUTH_CIPHER, (options).word.value, &(crc)); \
    (retVal);                                                                    \
  })
#else
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_AEAD_UPDATEDATA(crc, options)          \
  ({                                                                             \
    (options).bits.acpmod = MCUXCLCSS_AEAD_ACPMOD_MSGPROC;                        \
    mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_AUTH_CIPHER, (options).word.value, &(crc)); \
    (retVal);                                                                    \
  })
#endif /* MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS */

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Aead_Finalize_Async.
 */
#ifndef MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_AEAD_FINALIZE(crc, options)            \
  ({                                                                             \
    (options).bits.acpmod = MCUXCLCSS_AEAD_ACPMOD_FINAL                           \
    (options).bits.acpsie = MCUXCLCSS_AEAD_STATE_IN_ENABLE;                       \
    mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_AUTH_CIPHER, (options).word.value, &(crc)); \
    (retVal);                                                                    \
  })
#else
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_AEAD_FINALIZE(crc, options)            \
  ({                                                                             \
    (options).bits.acpmod = MCUXCLCSS_AEAD_ACPMOD_FINAL;                          \
    mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_AUTH_CIPHER, (options).word.value, &(crc)); \
    (retVal);                                                                    \
  })
#endif /* MCUXCL_FEATURE_CSS_NO_INTERNAL_STATE_FLAGS */

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Cipher_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_CIPHER(crc, options)                   \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_CIPHER, (options).word.value, &(crc))

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Cmac_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_CMAC(crc, options)                     \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_CMAC, (options).word.value, &(crc))


/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_EccKeyGen_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_ECCKEYGEN(crc, options)                \
  ({                                                                             \
    (options).bits.revf = MCUXCLCSS_ECC_REVERSEFETCH_ENABLE;                      \
    mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_KEYGEN, (options).word.value, &(crc)); \
    (retVal);                                                                    \
  })

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_EccKeyExchange_Async.
 */
#ifdef MCUXCL_FEATURE_CSS_PUK_INTERNAL_BIT
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_ECCKEYEXCHANGE(crc)                                 \
    ({                                                                                        \
        mcuxClCss_EccKeyExchOption_t options = {0u};                                           \
        options.bits.revf = MCUXCLCSS_ECC_REVERSEFETCH_ENABLE;                                 \
        options.bits.extkey = MCUXCLCSS_ECC_EXTKEY_EXTERNAL;                                   \
        mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_ECKXH, options.word.value, &(crc));     \
        (retVal);                                                                             \
    })
#else
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_ECCKEYEXCHANGE(crc)                                 \
    ({                                                                                        \
        mcuxClCss_EccKeyExchOption_t options = {0u};                                           \
        options.bits.revf = MCUXCLCSS_ECC_REVERSEFETCH_ENABLE;                                 \
        mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_ECKXH, options.word.value, &(crc));     \
        (retVal);                                                                             \
    })
#endif /* MCUXCL_FEATURE_CSS_PUK_INTERNAL_BIT */

#ifdef MCUXCL_FEATURE_CSS_PUK_INTERNAL
/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_EccKeyExchangeInt_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_ECCKEYEXCHANGEINT(crc)                              \
    ({                                                                                        \
        mcuxClCss_EccKeyExchOption_t options = {0u};                                           \
        options.bits.revf = MCUXCLCSS_ECC_REVERSEFETCH_ENABLE;                                 \
        options.bits.extkey = MCUXCLCSS_ECC_EXTKEY_INTERNAL;                                   \
        mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_ECKXH, options.word.value, &(crc));     \
        (retVal);                                                                             \
    })
#endif /* MCUXCL_FEATURE_CSS_PUK_INTERNAL */

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_EccSign_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_ECCSIGN(crc, options)                             \
  ({                                                                                        \
    (options).bits.revf = MCUXCLCSS_ECC_REVERSEFETCH_ENABLE;                                 \
    mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_ECSIGN, (options).word.value, &(crc)); \
    (retVal);                                                                               \
  })

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_EccVerify_Async.
 */
#ifdef MCUXCL_FEATURE_CSS_PUK_INTERNAL_BIT
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_ECCVERFIFY(crc, options)                          \
  ({                                                                                        \
    (options).bits.revf = MCUXCLCSS_ECC_REVERSEFETCH_ENABLE;                                 \
    (options).bits.extkey = MCUXCLCSS_ECC_EXTKEY_EXTERNAL;                                   \
    mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_ECVFY, (options).word.value, &(crc)); \
    (retVal);                                                                               \
  })
#else
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_ECCVERFIFY(crc, options)                          \
  ({                                                                                        \
    (options).bits.revf = MCUXCLCSS_ECC_REVERSEFETCH_ENABLE;                                 \
    mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_ECVFY, (options).word.value, &(crc)); \
    (retVal);                                                                               \
  })
#endif /* MCUXCL_FEATURE_CSS_PUK_INTERNAL_BIT */

#ifdef MCUXCL_FEATURE_CSS_PUK_INTERNAL
/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_EccVerifyInt_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_ECCVERFIFYINT(crc, options)            \
  ({                                                                             \
    (options).bits.revf = MCUXCLCSS_ECC_REVERSEFETCH_ENABLE;                      \
    (options).bits.extkey = MCUXCLCSS_ECC_EXTKEY_INTERNAL;                        \
    mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_ECVFY, (options).word.value, &(crc)); \
    (retVal);                                                                    \
  })
#endif /* MCUXCL_FEATURE_CSS_PUK_INTERNAL */

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_GlitchDetector_LoadConfig_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_GLITCHDETECTOR_LOADCONFIG(crc)         \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_GDET_CFG_LOAD, 0u, &(crc))

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_GlitchDetector_Trim_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_GLITCHDETECTOR_TRIM(crc)               \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_GDET_TRIM, 0u, &(crc))

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Hash_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_HASH(crc, options)                     \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_HASH, (options).word.value, &(crc))

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Hmac_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_HMAC(crc, options)                     \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_HMAC, (options).word.value, &(crc))

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Ckdf_Sp800108_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_CKDF_SP800108(crc)                                 \
    ({                                                                                       \
        mcuxClCss_CkdfOption_t options = {0u};                                                \
        options.bits.ckdf_algo = MCUXCLCSS_CKDF_ALGO_SP800108;                                \
        mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_CKDF, options.word.value, &(crc));     \
        (retVal);                                                                            \
    })


/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Hkdf_Rfc5869_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_HKDF_RFC5869(crc, options)                                               \
  ({                                                                                                               \
    (options).bits.hkdf_algo = MCUXCLCSS_HKDF_ALGO_RFC5869;                                                         \
    mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_HKDF, (options).word.value, &(crc));    \
    (retVal);                                                                                                      \
  })

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Hkdf_Sp80056c_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_HKDF_SP80056C(crc)                                     \
    ({                                                                                           \
        mcuxClCss_HkdfOption_t options = {0u};                                                    \
        options.bits.hkdf_algo = MCUXCLCSS_HKDF_ALGO_SP80056C;                                    \
        mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_HKDF, options.word.value, &(crc));     \
        (retVal);                                                                                \
    })

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_TlsGenerateMasterKeyFromPreMasterKey_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_TLSGENERATEMASTERKEYFROMPREMASTERKEY(crc)              \
    ({                                                                                           \
        mcuxClCss_TlsOption_t options = {0u};                                                     \
        options.bits.mode = MCUXCLCSS_TLS_INIT;                                                   \
        mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_TLS, options.word.value, &(crc));          \
        (retVal);                                                                                \
    })

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_TlsGenerateSessionKeysFromMasterKey_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_TLSGENERATESESSIONKEYSFROMMASTERKEY(crc)               \
    ({                                                                                           \
        mcuxClCss_TlsOption_t options = {0u};                                                     \
        options.bits.mode = MCUXCLCSS_TLS_FINALIZE;                                               \
        mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_TLS, options.word.value, &(crc));          \
        (retVal);                                                                                \
    })

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_KeyDelete_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_KEYDELETE(crc)                         \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_KDELETE, 0u, &(crc))

#ifdef MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV
/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_KeyProvision_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_KEYPROVISION(crc, options)             \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_KEYPROV, (options).word.value, &(crc))
#endif /* MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV */

#ifdef MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV_ROM
/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_KeyProvisionRom_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_KEYPROVISIONROM(crc, options)          \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_KEYPROV, (options).word.value, &(crc))
#endif /* MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV_ROM */

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_KeyImport_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_KEYIMPORT(crc, options)                \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_KEYIN, (options).word.value, &(crc))

#ifdef MCUXCL_FEATURE_CSS_PUK_INTERNAL
/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_KeyImportPuk_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_KEYIMPORTPUK(crc)                                  \
    ({                                                                                       \
        mcuxClCss_KeyImportOption_t options = {0u};                                           \
        options.bits.revf = MCUXCLCSS_KEYIMPORT_REVERSEFETCH_ENABLE;                          \
        options.bits.kfmt = MCUXCLCSS_KEYIMPORT_KFMT_PBK;                                     \
        mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_KEYIN, options.word.value, &(crc));    \
        (retVal);                                                                            \
    })
#endif /* MCUXCL_FEATURE_CSS_PUK_INTERNAL */

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_KeyExport_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_KEYEXPORT(crc)                                                              \
    ({                                                                                                                \
        mcuxClCss_Status_t retVal = mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_KEYOUT, 0u, &(crc));                 \
        mcuxClCss_KeyImportOption_t import_options = {0u};                                                             \
        import_options.bits.kfmt = MCUXCLCSS_KEYIMPORT_KFMT_RFC3394;                                                   \
        retVal = MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_KEYDELETE(crc);                                                    \
        retVal = MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_KEYIMPORT(crc, import_options);                         \
        (retVal);                                                                                                     \
    })

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Rng_DrbgRequest_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_RNG_DRBGREQUEST(crc)                  \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_RND_REQ, 0u, &(crc))

#ifdef MCUXCL_FEATURE_CSS_RND_RAW
/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Rng_DrbgRequestRaw_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_RNG_DRBGREQUESTRAW(crc)               \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_RND_REQ, MCUXCLCSS_RNG_RND_REQ_RND_RAW, &(crc))
#endif /* MCUXCL_FEATURE_CSS_RND_RAW */

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Rng_DrbgTestInstantiate_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_RNG_DRBGTESTINSTANTIATE(crc)                        \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_DRBG_TEST, MCUXCLCSS_RNG_DRBG_TEST_MODE_INSTANTIATE, &(crc))

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Rng_DrbgTestExtract_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_RNG_DRBGTESTEXTRACT(crc)                             \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_DRBG_TEST, MCUXCLCSS_RNG_DRBG_TEST_MODE_EXTRACT, &(crc))

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Rng_DrbgTestAesEcb_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_RNG_DRBGTESTAESECB(crc)                             \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_DRBG_TEST, MCUXCLCSS_RNG_DRBG_TEST_MODE_AES_ECB, &(crc))

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Rng_DrbgTestAesCtr_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_RNG_DRBGTESTAESCTR(crc)                             \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_DRBG_TEST, MCUXCLCSS_RNG_DRBG_TEST_MODE_AES_CTR, &(crc))

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Rng_Dtrng_ConfigLoad_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_RNG_DTRNG_CONFIGLOAD(crc)             \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_DTRNG_CFG_LOAD, 0u, &(crc))

/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Rng_Dtrng_ConfigEvaluate_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_RNG_DTRNG_CONFIGEVALUATE(crc)         \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_DTRNG_EVAL, 0u, &(crc))

#ifdef MCUXCL_FEATURE_CSS_PRND_INIT
/**
 * @brief Updates given reference command CRC with command @ref mcuxClCss_Prng_Init_Async.
 */
#define MCUXCLCSS_CMD_CRC_REFERENCE_UPDATE_PRNG_INIT(crc)                               \
    mcuxClCss_UpdateRefCRC(MCUXCLCSS_CMD_CRC_CMD_ID_RND_REQ, MCUXCLCSS_RNG_RND_REQ_PRND_INIT, &(crc))
#endif /* MCUXCL_FEATURE_CSS_PRND_INIT */
/**
 * @}
 */

/**
 * @defgroup MCUXCLCSS_CMD_CRC_CMD_ID MCUXCLCSS_CMD_CRC_CMD_ID_
 * @brief Constants for CSS Command IDs
 * @ingroup mcuxClCss_Crc_Macros
 * @{
 */
#define MCUXCLCSS_CMD_CRC_CMD_ID_CIPHER          0 ///< CSS Command ID for CIPHER command
#define MCUXCLCSS_CMD_CRC_CMD_ID_AUTH_CIPHER     1 ///< CSS Command ID for AUTH_CIPHER command
#define MCUXCLCSS_CMD_CRC_CMD_ID_CHAL_RESP_GEN   3 ///< CSS Command ID for CHAL_RESP_GEN command
#define MCUXCLCSS_CMD_CRC_CMD_ID_ECSIGN          4 ///< CSS Command ID for ECSIGN command
#define MCUXCLCSS_CMD_CRC_CMD_ID_ECVFY           5 ///< CSS Command ID for ECVFY command
#define MCUXCLCSS_CMD_CRC_CMD_ID_ECKXH           6 ///< CSS Command ID for ECKXH command
#define MCUXCLCSS_CMD_CRC_CMD_ID_KEYGEN          8 ///< CSS Command ID for KEYGEN command
#define MCUXCLCSS_CMD_CRC_CMD_ID_KEYIN           9 ///< CSS Command ID for KEYIN command
#define MCUXCLCSS_CMD_CRC_CMD_ID_KEYOUT         10 ///< CSS Command ID for KEYOUT command
#define MCUXCLCSS_CMD_CRC_CMD_ID_KDELETE        11 ///< CSS Command ID for KDELETE command
#define MCUXCLCSS_CMD_CRC_CMD_ID_KEYPROV        12 ///< CSS Command ID for KEYPROV command
#define MCUXCLCSS_CMD_CRC_CMD_ID_CKDF           16 ///< CSS Command ID for CKDF command
#define MCUXCLCSS_CMD_CRC_CMD_ID_HKDF           17 ///< CSS Command ID for HKDF command
#define MCUXCLCSS_CMD_CRC_CMD_ID_TLS            18 ///< CSS Command ID for TLS command
#define MCUXCLCSS_CMD_CRC_CMD_ID_HASH           20 ///< CSS Command ID for HASH command
#define MCUXCLCSS_CMD_CRC_CMD_ID_HMAC           21 ///< CSS Command ID for HMAC command
#define MCUXCLCSS_CMD_CRC_CMD_ID_CMAC           22 ///< CSS Command ID for CMAC command
#define MCUXCLCSS_CMD_CRC_CMD_ID_RND_REQ        24 ///< CSS Command ID for RND_REQ command
#define MCUXCLCSS_CMD_CRC_CMD_ID_DRBG_TEST      25 ///< CSS Command ID for DRBG_TEST command
#define MCUXCLCSS_CMD_CRC_CMD_ID_DTRNG_CFG_LOAD 28 ///< CSS Command ID for DTRNG_CFG_LOAD command
#define MCUXCLCSS_CMD_CRC_CMD_ID_DTRNG_EVAL     29 ///< CSS Command ID for DTRNG_EVAL command
#define MCUXCLCSS_CMD_CRC_CMD_ID_GDET_CFG_LOAD  30 ///< CSS Command ID for GDET_CFG_LOAD command
#define MCUXCLCSS_CMD_CRC_CMD_ID_GDET_TRIM      31 ///< CSS Command ID for GDET_TRIM command
/**
 * @}
 *
 * @}
 */

/**********************************************
 * TYPEDEFS
 **********************************************/
/**
 * @defgroup mcuxClCss_Crc_Types mcuxClCss_Crc_Types
 * @brief Defines all types of @ref mcuxClCss_Crc
 * @ingroup mcuxClCss_Crc
 * @{
 */

/**
 * @brief Type to control CSS Command CRC
 */
typedef union
{
    struct
    {
        uint32_t value;         ///< Accesses the bit field as a full word
    } word;
    struct
    {
        uint32_t reset :1;      ///< Reset the Command CRC to initial value, set by #MCUXCLCSS_CMD_CRC_RESET
        uint32_t enable :1;     ///< Enable/Disable update of Command CRC value by executing commands, set with #MCUXCLCSS_CMD_CRC_ENABLE / #MCUXCLCSS_CMD_CRC_DISABLE
        uint32_t : 30;          ///< RFU
    } bits;                     ///< Access #mcuxClCss_CommandCrcConfig_t bit-wise
} mcuxClCss_CommandCrcConfig_t;

/**
 * @}
 */

/**********************************************
 * FUNCTIONS
 **********************************************/
/**
 * @defgroup mcuxClCss_Crc_Functions mcuxClCss_Crc_Functions
 * @brief Defines all functions of @ref mcuxClCss_Crc
 * @ingroup mcuxClCss_Crc
 * @{
 */

/**
 * @brief Set command CRC flags.
 *
 * @param[in] options    The command CRC options. For more information, see #mcuxClCss_CommandCrcConfig_t.
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code is always #MCUXCLCSS_STATUS_OK
 * @else
 *  @return An error code that is always #MCUXCLCSS_STATUS_OK
 * @endif
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_ConfigureCommandCRC)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_ConfigureCommandCRC(
    mcuxClCss_CommandCrcConfig_t options
    );

/**
 * @brief Get the current command CRC value.
 *
 * @param[out] commandCrc    The command CRC value.
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection).
 *  @retval MCUXCLCSS_STATUS_OK                Operation successful
 *  @retval MCUXCLCSS_STATUS_SW_INVALID_PARAM  Parameter commandCRC points to NULL
 * @else
 *  @return An error code
 *  @retval MCUXCLCSS_STATUS_OK                Operation successful
 *  @retval MCUXCLCSS_STATUS_SW_INVALID_PARAM  Parameter commandCRC points to NULL
 * @endif
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_GetCommandCRC)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_GetCommandCRC(
    uint32_t* commandCrc
    );

/**
 * @brief Verifies a reference CRC against the computed CSS command CRC.
 *
 * @param[in] refCrc The reference CRC value.
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection). The error code can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @else
 *  @return An error code that can be any error code in @ref MCUXCLCSS_STATUS_, see individual documentation for more information
 * @endif
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_VerifyVsRefCRC)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_VerifyVsRefCRC(
    uint32_t refCrc
    );

/**
 * @brief Updates a reference CRC with the parameters of a CSS command.
 *        This can be used to verify against the CSS command CRC.
 *
 * @param[in]     command  The CSS command ID.
 * @param[in]     options  The command options for the given CSS command.
 * @param[in,out] refCrc   The current reference CRC value to update.
 *
 * @if (MCUXCL_FEATURE_CSSL_FP_USE_SECURE_COUNTER && MCUXCL_FEATURE_CSSL_SC_USE_SW_LOCAL)
 *  @return A code-flow protected error code (see @ref mcuxCsslFlowProtection).
 *  @retval MCUXCLCSS_STATUS_OK                Operation successful
 *  @retval MCUXCLCSS_STATUS_SW_INVALID_PARAM  Parameter crc points to NULL
 * @else
 *  @return An error code
 *  @retval MCUXCLCSS_STATUS_OK                Operation successful
 *  @retval MCUXCLCSS_STATUS_SW_INVALID_PARAM  Parameter crc points to NULL
 * @endif
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClCss_UpdateRefCRC)
MCUXCLCSS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClCss_Status_t) mcuxClCss_UpdateRefCRC(
    uint8_t   command,
    uint32_t  options,
    uint32_t* refCrc
    );

#endif /* MCUXCLCSS_CRC_H_ */

/**
 * @}
 *
 * @}
 */


