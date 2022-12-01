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

/** @file  mcuxClMac_Internal.h
 *  @brief Header for MAC helper functions
 */

#ifndef MCUXCLMAC_INTERNAL_H_
#define MCUXCLMAC_INTERNAL_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <mcuxClMac_Types.h>
#include <mcuxClKey_Types.h>
#include <internal/mcuxClPadding_Internal.h>
#include <internal/mcuxClMac_Internal_Constants.h>

/**********************************************
 * INTERNAL TYPES
 **********************************************/

/**********************************************
 * CONSTANTS
 **********************************************/
#define MCUXCLMAC_HASH_BLOCK_SIZE_SHA_256        (64U)
#define MCUXCLMAC_HASH_OUTPUT_SIZE_SHA_256       (32U)

#define MCUXCLMAC_HMAC_PADDED_KEY_SIZE           ((mcuxClKey_Size_t) 64u)

/**
 * @brief Mac engine function type
 *
 * This function will perform the actual MAC operation
 *
 */
typedef MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) (*mcuxClMac_ModeEngine_t)(struct mcuxClMac_Context *context, const uint8_t *const pIn, uint32_t inLength, uint8_t *const pOut, uint32_t *const outLength);

/**
 * @brief Mac Mode structure
 *
 * This internal structure provides all implementation details for a mode to the top level mcuxClMac functions.
 * It consists of Init, Update, Finalize and Oneshot engines and the output size.
 *
 */
struct mcuxClMac_ModeDescriptor
{
  mcuxClMac_ModeEngine_t engineInit;     ///< engine function to perform the init operation
  mcuxClMac_ModeEngine_t engineUpdate;   ///< engine function to perform the update operation
  mcuxClMac_ModeEngine_t engineFinalize; ///< engine function to perform the finalize operation
  mcuxClMac_ModeEngine_t engineOneshot;  ///< engine function to perform the Mac operation in one shot
  mcuxClPadding_addPaddingMode_t pPaddingFunction; ///< padding function to be used. One of mcuxClPaddingMode
  uint32_t protectionTokenInit;     ///< protection token of the engine function to perform the init operation
  uint32_t protectionTokenUpdate;   ///< protection token of the engine function to perform the update operation
  uint32_t protectionTokenFinalize; ///< protection token of the engine function to perform the finalize operation
  uint32_t protectionTokenOneshot;  ///< protection token of the engine function to perform the Mac operation in one shot
  uint32_t protectionTokenPaddingFunction; ///< protection token of the padding funtion
  uint32_t macByteSize; ///< Default value(s) in predefined structs, for custom truncation length, provide a macro or function to construct a suitable structure
};

/**
 * @brief Mac context structure
 *
 * This structure captures all the information that the Mac interface needs to
 * know for a particular Mac mode/algorithm to work.
 */
struct mcuxClMac_Context
{
  mcuxClKey_Descriptor_t * key;                  ///< Key descriptor of the key to be used
  mcuxClSession_Descriptor_t * session;          ///< Session descriptor to be used
  const mcuxClMac_ModeDescriptor_t * mode;       ///< Mode of the Mac calculation. e.g mcuxClMac_Mode_CMAC
  uint32_t unprocessed[4];                      ///< Not yet processed input data from the input stream
  uint32_t state[4];                            ///< state/intermediate result of the mac operation
  uint32_t nrOfUnprocessedBytes;                ///< number of not yet processed bytes
  uint32_t preparedHmacKey[MCUXCLCSS_HMAC_PADDED_KEY_SIZE / sizeof(uint32_t)];   ///< Padded/Hashed HMAC key, buffer for external HMAC keys
  mcuxClCss_CmacOption_t cmac_options;                                           ///< Cmac Css options to be used
};

/**********************************************
 * INTERNAL FUNCTIONS
 **********************************************/


/**
 * @brief Internal helper functions for the MAC component
 */

/**
 * Prepares the given HMAC key by hashing and/or padding it to a length of MCUXCLCSS_HMAC_PADDED_KEY_SIZE bytes.
 * Both the input key and the output padded key are taken from/written to the context.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMac_prepareHMACKey)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_prepareHMACKey(
    mcuxClMac_Context_t *pContext            /*! HMAC context */
    );

/**
 * @brief Internal engine functions for the MAC component
 */

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMac_Engine_CMAC_Oneshot)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_CMAC_Oneshot(
    mcuxClMac_Context_t *pContext,            /*! CMAC context */
    const uint8_t *const pIn,                /*! CMAC input */
    uint32_t inLength,                       /*! Input size */
    uint8_t *const pOut,                     /*! CMAC output */
    uint32_t *const pOutLength               /*! Output size */
    );

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMac_Engine_HMAC_Oneshot)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_HMAC_Oneshot(
    mcuxClMac_Context_t *pContext,            /*! HMAC context */
    const uint8_t *const pIn,                /*! HMAC input */
    uint32_t inLength,                       /*! Input size */
    uint8_t *const pOut,                     /*! HMAC output */
    uint32_t *const pOutLength               /*! Output size */
    );

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMac_Engine_CBCMAC_Oneshot)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_CBCMAC_Oneshot(
    mcuxClMac_Context_t *pContext,            /*! CBC-MAC context */
    const uint8_t *const pIn,                /*! CBC-MAC input */
    uint32_t inLength,                       /*! Input size */
    uint8_t *const pOut,                     /*! CBC-MAC output */
    uint32_t *const pOutLength               /*! Output size */
    );

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMac_Engine_CMAC_Init)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_CMAC_Init(
    mcuxClMac_Context_t *pContext,            /*! CMAC context */
    const uint8_t *const pIn,                /*! CMAC input */
    uint32_t inLength,                       /*! Input size */
    uint8_t *const pOut,                     /*! CMAC output */
    uint32_t *const pOutLength               /*! Output size */
    );

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMac_Engine_HMAC_Init)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_HMAC_Init(
    mcuxClMac_Context_t *pContext,            /*! HMAC context */
    const uint8_t *const pIn,                /*! HMAC input */
    uint32_t inLength,                       /*! Input size */
    uint8_t *const pOut,                     /*! HMAC output */
    uint32_t *const pOutLength               /*! Output size */
    );

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMac_Engine_CBCMAC_Init)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_CBCMAC_Init(
    mcuxClMac_Context_t *pContext,            /*! CBC-MAC context */
    const uint8_t *const pIn,                /*! CBC-MAC input */
    uint32_t inLength,                       /*! Input size */
    uint8_t *const pOut,                     /*! CBC-MAC output */
    uint32_t *const pOutLength               /*! Output size */
    );

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMac_Engine_CMAC_Update)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_CMAC_Update(
    mcuxClMac_Context_t *pContext,            /*! CMAC context */
    const uint8_t *const pIn,                /*! CMAC input */
    uint32_t inLength,                       /*! Input size */
    uint8_t *const pOut,                     /*! CMAC output */
    uint32_t *const pOutLength               /*! Output size */
    );

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMac_Engine_HMAC_Update)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_HMAC_Update(
    mcuxClMac_Context_t *pContext,            /*! HMAC context */
    const uint8_t *const pIn,                /*! HMAC input */
    uint32_t inLength,                       /*! Input size */
    uint8_t *const pOut,                     /*! HMAC output */
    uint32_t *const pOutLength               /*! Output size */
    );

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMac_Engine_CBCMAC_Update)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_CBCMAC_Update(
    mcuxClMac_Context_t *pContext,            /*! CBC-MAC context */
    const uint8_t *const pIn,                /*! CBC-MAC input */
    uint32_t inLength,                       /*! Input size */
    uint8_t *const pOut,                     /*! CBC-MAC output */
    uint32_t *const pOutLength               /*! Output size */
    );

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMac_Engine_CMAC_Finalize)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_CMAC_Finalize(
    mcuxClMac_Context_t *pContext,            /*! CMAC context */
    const uint8_t *const pIn,                /*! CMAC input */
    uint32_t inLength,                       /*! Input size */
    uint8_t *const pOut,                     /*! CMAC output */
    uint32_t *const pOutLength               /*! Output size */
    );

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMac_Engine_HMAC_Finalize)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_HMAC_Finalize(
    mcuxClMac_Context_t *pContext,            /*! HMAC context */
    const uint8_t *const pIn,                /*! HMAC input */
    uint32_t inLength,                       /*! Input size */
    uint8_t *const pOut,                     /*! HMAC output */
    uint32_t *const pOutLength               /*! Output size */
    );

MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMac_Engine_CBCMAC_Finalize)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMac_Status_t) mcuxClMac_Engine_CBCMAC_Finalize(
    mcuxClMac_Context_t *pContext,            /*! CBC-MAC context */
    const uint8_t *const pIn,                /*! CBC-MAC input */
    uint32_t inLength,                       /*! Input size */
    uint8_t *const pOut,                     /*! CBC-MAC output */
    uint32_t *const pOutLength               /*! Output size */
    );

#endif /* MCUXCLMAC_INTERNAL_H_ */
