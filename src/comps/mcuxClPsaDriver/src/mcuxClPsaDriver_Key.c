/*--------------------------------------------------------------------------*/
/* Copyright 2023-2024 NXP                                                  */
/*                                                                          */
/* NXP Proprietary. This software is owned or controlled by NXP and may     */
/* only be used strictly in accordance with the applicable license terms.   */
/* By expressly accepting such terms or by downloading, installing,         */
/* activating and/or otherwise using the software, you are agreeing that    */
/* you have read, and that you agree to comply with and are bound by, such  */
/* license terms.  If you do not agree to be bound by the applicable        */
/* license terms, then you may not retain, install, activate or otherwise   */
/* use the software.                                                        */
/*--------------------------------------------------------------------------*/

#include "common.h"

#include <mcuxClAes_KeyTypes.h>
#include <mcuxClHmac_KeyTypes.h>
#include <mcuxClEls.h>
#include <mcuxClEcc.h>
#include <internal/mcuxClPkc_Macros.h>
#include <mcuxClKey.h>
#include <mcuxClSession.h>
#include <mcuxClBuffer.h>
#include <mcuxClRandom.h>
#include <internal/mcuxClRandom_Internal_Functions.h>
#include <mcuxClRandomModes.h>
#include <mcuxClMemory_Copy.h>
#include <mcuxClPsaDriver.h>
#include <mcuxClPsaDriver_Oracle.h>
#include <mcuxCsslFlowProtection.h>
#include <internal/mcuxClKey_Internal.h>
#include <internal/mcuxClPsaDriver_Functions.h>
#include <internal/mcuxClPsaDriver_Internal.h>
#include <internal/mcuxClEcc_Mont_Internal.h>
#include <internal/mcuxClPsaDriver_ExternalMacroWrappers.h>


static psa_status_t mcuxClPsaDriver_psa_driver_wrapper_generate_random( uint8_t *output,
                                                                       size_t output_size )
{
    mcuxClSession_Descriptor_t session;

    /* Allocate workarea space */
    uint32_t cpuWorkarea[MCUXCLRANDOMMODES_MAX_CPU_WA_BUFFER_SIZE / sizeof(uint32_t)];

    MCUX_CSSL_ANALYSIS_START_PATTERN_NULL_POINTER_CONSTANT()
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(retSessionInit, tokenSessionInit, mcuxClSession_init(&session,
                                                                     cpuWorkarea,
                                                                     MCUXCLRANDOMMODES_MAX_CPU_WA_BUFFER_SIZE,
                                                                     NULL,
                                                                     0u));
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_NULL_POINTER_CONSTANT()

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != tokenSessionInit) || (MCUXCLSESSION_STATUS_OK != retSessionInit))
    {
        return PSA_ERROR_GENERIC_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Random init                                                            */
    /**************************************************************************/

    /* Initialize the RNG context, with maximum size */
    uint32_t rng_ctx[MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE_IN_WORDS] = {0u};

    mcuxClRandom_Mode_t randomMode = NULL;
    if(output_size <= 16u)  /* 128-bit security strength */
    {
      randomMode = mcuxClRandomModes_Mode_ELS_Drbg;
    }
    else  /* 256-bit security strength */
    {
      randomMode = mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(retRandomInit, tokenRandInit, mcuxClRandom_init(
                                                  &session,
                                                  mcuxClRandom_castToContext(rng_ctx),
                                                  randomMode));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init) != tokenRandInit) || (MCUXCLRANDOM_STATUS_OK != retRandomInit))
    {
        return PSA_ERROR_GENERIC_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Generate random values.                                                */
    /**************************************************************************/

    /* Generate random values of smaller amount than one word size. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(retRandGen, tokenRandGen, mcuxClRandom_generate(
                                                  &session,
                                                  output,
                                                  output_size));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_generate) != tokenRandGen) || (MCUXCLRANDOM_STATUS_OK != retRandGen))
    {
        return PSA_ERROR_GENERIC_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(cleanup_result, cleanup_token, mcuxClSession_cleanup(&session));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != cleanup_token) || (MCUXCLSESSION_STATUS_OK != cleanup_result))
    {
        return PSA_ERROR_GENERIC_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(destroy_result, destroy_token, mcuxClSession_destroy(&session));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != destroy_token) || (MCUXCLSESSION_STATUS_OK != destroy_result))
    {
        return PSA_ERROR_GENERIC_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    /* Return with success */
    return PSA_SUCCESS;
}

/**
 * @brief Creates a CLNS key handle from information provided by the driver interface.
 *
 * The driver functions all receive: (1) key attributes along with a (2) key buffer and
 * (3) the key buffer size. The key attributes encode:
 *
 * 1. the key location, of which we support four:
 *
 *    +-------------------+-------------------+-------------------------+--------------------+
 *    | Key location name | Usage by (IP/SW)  | Storage-time            | Use-time           |
 *    +-------------------+-------------------+-------------------------+--------------------+
 *    | LOCAL_STORAGE     | S50/PKC and       | unencrypted, in memory                       |
 *    | (default)         | Software fallback |                                              |
 *    | (0x000000)        |                   |                                              |
 *    +-------------------+-------------------+-------------------------+--------------------+
 *    | S50_TEMP_STORAGE  | S50 only          | key slot number only    | already present in |
 *    | (0x800002)        |                   |                         | S50 keystore       |
 *    +-------------------+-------------------+-------------------------+--------------------+
 *    | S50_BLOB_STORAGE  | S50 only          | RFC3394-wrapped         | unwrap into S50    |
 *    | (0x800001)        |                   | in memory               | keystore           |
 *    +-------------------+-------------------+-------------------------+--------------------+
 *    | S50_ENC_STORAGE   | S50/PKC and       | AES-CBC encrpted        | decrypt on stack   |
 *    | (0x800000)        | Software fallback | in memory               |                    |
 *    +-------------------+-------------------+-------------------------+--------------------+
 *
 *    As of 7 May 2022, only LOCAL_STORAGE and S50_TEMP_STORAGE shall be implemented. For keys
 *    with LOCAL_STORAGE, the key_buffer (see below) contains the whole key in plain. For keys
 *    with S50_TEMP_STORAGE type, the key buffer contains the key slot number as a
 *    `psa_drv_slot_number_t`.
 *
 *    Update: Only LOCAL_STORAGE will be supported natively by the mcuxClPsaDriver, all other key
 *    types will be handled by a user provided Oracle for which CLNS contains the API definition.
 *    The Oracle API and functionality are described in the header file mcuxClPsaDriver_Oracle.h
 *
 * 2. the type of key, such as whether it is an AES key. Of these we support, possibly among
 *    others:
 *
 *    PSA_KEY_TYPE_HMAC, PSA_KEY_TYPE_AES, PSA_KEY_TYPE_RSA_PUBLIC_KEY,
 *    PSA_KEY_TYPE_RSA_KEY_PAIR, PSA_KEY_TYPE_ECC_KEY_PAIR(...) and PSA_KEY_TYPE_ECC_PUBLIC_KEY.
 *
 * 3. key persistence, i.e. whether it is volatile or persistent. Keys with LOCAL_STORAGE may
 *    be volatile or persistent, while keys with S50_TEMP_STORAGE are always volatile. (see
 *    documentation of `psa_key_lifetime_t`).
 *
 * 4. key usage bits (many of these can be set for a single key!), a list follows:
 *
 *    PSA_KEY_USAGE_EXPORT, PSA_KEY_USAGE_COPY, PSA_KEY_USAGE_ENCRYPT, PSA_KEY_USAGE_DECRYPT,
 *    PSA_KEY_USAGE_SIGN_MESSAGE, PSA_KEY_USAGE_VERIFY_MESSAGE, PSA_KEY_USAGE_SIGN_HASH,
 *    PSA_KEY_USAGE_VERIFY_HASH, PSA_KEY_USAGE_DERIVE, PSA_KEY_USAGE_VERIFY_DERIVATION
 *
 * 5. a key algorithm (only ONE of these can be set for a single key):
 *
 *    PSA_ALG_SHA_256, PSA_ALG_HMAC(PSA_ALG_SHA_256), PSA_ALG_CMAC, PSA_ALG_CTR,
 *    PSA_ALG_ECB_NO_PADDING, PSA_ALG_CBC_NO_PADDING, ...
 *
 * From this information we construct the key descriptor to use with CLNS functions.
 *
 * @param attributes The key attributes associated with the key.
 * @param key_buffer The PSA-provided key buffer.
 * @param key_buffer_size The PSA-provided key buffer size.
 * @param out_key_descriptor The output key handle.
 * @return A status indicating whether key creation was successful or an error occurred.
 */

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
psa_status_t mcuxClPsaDriver_psa_driver_wrapper_createClKey(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    mcuxClKey_Descriptor_t *out_key_descriptor
)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    psa_key_location_t location =
        PSA_KEY_LIFETIME_GET_LOCATION( attributes->core.lifetime );

    if(out_key_descriptor == NULL)
    {
        return PSA_ERROR_GENERIC_ERROR;
    }

    // store/backup the attributes and key buffer to the key container, the Oracle expects them to be there
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the generic structure member.")
    mcuxClKey_setKeyData(out_key_descriptor, (uint8_t*)key_buffer);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
    mcuxClKey_setKeyContainerSize(out_key_descriptor, (uint32_t)key_buffer_size);
    mcuxClKey_setKeyContainerUsedSize(out_key_descriptor, (uint32_t)key_buffer_size);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the generic structure member.")
    mcuxClKey_setAuxData(out_key_descriptor, (void*)attributes);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
    mcuxClKey_setLoadStatus(out_key_descriptor, MCUXCLKEY_LOADSTATUS_NOTLOADED);

    if(false == (MCUXCLPSADRIVER_IS_LOCAL_STORAGE(location)) )
    {
        psa_status_t retCode = mcuxClPsaDriver_Oracle_LoadKey(out_key_descriptor);
        if(PSA_ERROR_NOT_SUPPORTED == retCode)
        {
            return retCode;
        }
        if(PSA_SUCCESS !=  retCode)
        {
            return PSA_ERROR_GENERIC_ERROR;
        }
    }
    else
    {
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the generic structure member.")
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("Loaded key is aligned per user guidance.")
        mcuxClKey_setLoadedKeyData(out_key_descriptor, (uint32_t *) key_buffer);
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
        mcuxClKey_setLoadedKeyLength(out_key_descriptor, (uint32_t)key_buffer_size);
        mcuxClKey_setLoadedKeySlot(out_key_descriptor, 0xFFFFFFu);
        mcuxClKey_setLoadStatus(out_key_descriptor, MCUXCLKEY_LOADSTATUS_MEMORY);
    }

    mcuxClKey_setProtectionType(out_key_descriptor, mcuxClKey_Protection_None);
    mcuxClKey_TypeDescriptor_t keyTypeDesc;

    keyTypeDesc.info = NULL;
    MCUX_CSSL_ANALYSIS_START_PATTERN_SWITCH_STATEMENT_RETURN_TERMINATION()
    switch(attributes->core.type) {
        case PSA_KEY_TYPE_AES:
            switch(mcuxClKey_getLoadedKeyLength(out_key_descriptor)) {
                case 16u:
                    keyTypeDesc = mcuxClKey_TypeDescriptor_Aes128;
                    break;
                case 24u:
                    keyTypeDesc = mcuxClKey_TypeDescriptor_Aes192;
                    break;
                case 32u:
                    keyTypeDesc = mcuxClKey_TypeDescriptor_Aes256;
                    break;
                default:
                    return PSA_ERROR_NOT_SUPPORTED;
            }
            break;
        case PSA_KEY_TYPE_HMAC:
            if( MCUXCLKEY_LOADSTATUS_COPRO == mcuxClKey_getLoadStatus(out_key_descriptor) )
            {
                if(32u == mcuxClKey_getLoadedKeyLength(out_key_descriptor))
                {
                    // the internal key store only supports 256 bit HMAC keys
                    keyTypeDesc = mcuxClKey_TypeDescriptor_HmacSha256;
                }
                else
                {
                    return PSA_ERROR_NOT_SUPPORTED;
                }
            }
            else if( MCUXCLKEY_LOADSTATUS_MEMORY == mcuxClKey_getLoadStatus(out_key_descriptor) )
            {
                mcuxClKey_TypeDescriptor_t type = {MCUXCLKEY_ALGO_ID_HMAC + MCUXCLKEY_ALGO_ID_SYMMETRIC_KEY, key_buffer_size, NULL};
                keyTypeDesc = type;
            }
            else
            {
                return PSA_ERROR_CORRUPTION_DETECTED;
            }
            break;
/*
        Provisional support for the ECC iternal key type
*/
        case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1):
        case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1):
        case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1):
        case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY):
        case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS):
            keyTypeDesc.algoId = MCUXCLKEY_ALGO_ID_ECC_SHWS_GFP + MCUXCLKEY_ALGO_ID_KEY_PAIR; // not really needed for ECC operation for now
            keyTypeDesc.size = ((mcuxClKey_Size_t) attributes->core.bits + 7u) / 8u; // not really needed for ECC operation for now
            MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the generic structure member.")
            keyTypeDesc.info = (void *) mcuxClPsaDriver_psa_driver_wrapper_getEccDomainParams(attributes);
            MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
            break;
        case PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1):
        case PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_K1):
        case PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_BRAINPOOL_P_R1):
        case PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_MONTGOMERY):
        case PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS):
            keyTypeDesc.algoId = MCUXCLKEY_ALGO_ID_ECC_SHWS_GFP + MCUXCLKEY_ALGO_ID_PUBLIC_KEY;
            keyTypeDesc.size = ((mcuxClKey_Size_t) attributes->core.bits + 7u) / 8u;
            MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the generic structure member.")
            keyTypeDesc.info = (void *) mcuxClPsaDriver_psa_driver_wrapper_getEccDomainParams(attributes);
            MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()
            break;

        case PSA_KEY_TYPE_RSA_PUBLIC_KEY:
        case PSA_KEY_TYPE_RSA_KEY_PAIR:
            // for now only keys in LOCAL_STORAGE are supported
            keyTypeDesc.algoId = MCUXCLKEY_ALGO_ID_RSA;
            keyTypeDesc.size = ((mcuxClKey_Size_t) attributes->core.bits + 7u) / 8u;

            if( MCUXCLKEY_LOADSTATUS_MEMORY != mcuxClKey_getLoadStatus(out_key_descriptor) )
            {
                return PSA_ERROR_NOT_SUPPORTED;
            }
            if((attributes->core.type & PSA_KEY_TYPE_CATEGORY_FLAG_PAIR) == PSA_KEY_TYPE_CATEGORY_FLAG_PAIR)
            {
                keyTypeDesc.algoId |= MCUXCLKEY_ALGO_ID_KEY_PAIR;
            }
            else
            {
                keyTypeDesc.algoId |= MCUXCLKEY_ALGO_ID_PUBLIC_KEY;
            }
            break;

        case PSA_KEY_TYPE_RAW_DATA:
            {
                // used for psa export
                mcuxClKey_TypeDescriptor_t type = {0u, key_buffer_size, NULL};
                keyTypeDesc = type;
            }
            break;

        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_SWITCH_STATEMENT_RETURN_TERMINATION()

    mcuxClKey_setTypeDescriptor(out_key_descriptor, keyTypeDesc);

    return PSA_SUCCESS;
}

static inline psa_status_t mcuxClPsaDriver_psa_driver_wrapper_generate_s50_key(
    const psa_key_attributes_t *attributes,
    mcuxClEls_KeyIndex_t key_index_private_key,
    uint8_t * public_key_buffer, uint32_t public_key_buffer_size)
{
    size_t bitLength = psa_get_key_bits(attributes);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_INTEGER_WRAP("Converting the bit-length of a cryptographic key to its byte-length cannot wrap.")
    size_t bytes = (size_t)MCUXCLPSADRIVER_BITS_TO_BYTES(bitLength);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_INTEGER_WRAP()

    if(public_key_buffer_size < (2u * bytes))
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    if(bytes != MCUXCLKEY_SIZE_256)
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    mcuxClEls_KeyProp_t  keyProp;
    keyProp.word.value       = 0;
    MCUX_CSSL_ANALYSIS_START_PATTERN_0U_1U_ARE_UNSIGNED()
    keyProp.bits.ksize       = MCUXCLELS_KEYPROPERTY_KEY_SIZE_256;
    keyProp.bits.kactv       = MCUXCLELS_KEYPROPERTY_ACTIVE_TRUE;
    keyProp.bits.ukgsrc      = MCUXCLELS_KEYPROPERTY_INPUT_FOR_ECC_TRUE;
    keyProp.bits.upprot_priv = MCUXCLELS_KEYPROPERTY_PRIVILEGED_FALSE;
    keyProp.bits.upprot_sec  = MCUXCLELS_KEYPROPERTY_SECURE_FALSE;
    keyProp.bits.wrpok       = MCUXCLELS_KEYPROPERTY_WRAP_TRUE;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_0U_1U_ARE_UNSIGNED()

    mcuxClEls_EccKeyGenOption_t KeyGenOptions;
    KeyGenOptions.word.value    = 0u;
    MCUX_CSSL_ANALYSIS_START_PATTERN_0U_1U_ARE_UNSIGNED()
    KeyGenOptions.bits.kgsign   = MCUXCLELS_ECC_PUBLICKEY_SIGN_DISABLE;
    KeyGenOptions.bits.kgtypedh = MCUXCLELS_ECC_OUTPUTKEY_SIGN;
    KeyGenOptions.bits.kgsrc    = MCUXCLELS_ECC_OUTPUTKEY_RANDOM;
    KeyGenOptions.bits.skip_pbk = MCUXCLELS_ECC_GEN_PUBLIC_KEY;
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_0U_1U_ARE_UNSIGNED()

    /*Step 1:
        Generate Key pair:
        - Private key will be stored in ELS's KeyStore
        - Public Key will be stored in external RAM
    */
    MCUX_CSSL_ANALYSIS_START_PATTERN_NULL_POINTER_CONSTANT()
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_EccKeyGen_Async( // Perform key generation.
            KeyGenOptions,                   // Set the prepared configuration.
            (mcuxClEls_KeyIndex_t) 0U,        // This parameter (signingKeyIdx) is ignored, since no signature is requested in the configuration.
            key_index_private_key,           // Keystore index at which the generated private key is stored.
            keyProp,                         // Set the generated key properties.
            NULL,                            // No random data is provided
            public_key_buffer                // Output buffer, which the operation will write the public key to.
            ));
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_NULL_POINTER_CONSTANT()
    // mcuxClEls_EccKeyGen_Async is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_EccKeyGen_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        return PSA_ERROR_GENERIC_ERROR; // Expect that no error occurred, meaning that the mcuxClEls_EccKeyGen_Async operation was started.
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClEls_EccKeyGen_Async operation to complete.
    // mcuxClEls_LimitedWaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
         return PSA_ERROR_GENERIC_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return PSA_SUCCESS;
}


MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
psa_status_t mcuxClPsaDriver_psa_driver_wrapper_key_generate(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t type = attributes->core.type;
    psa_key_location_t location =
        PSA_KEY_LIFETIME_GET_LOCATION(attributes->core.lifetime);

    if((attributes->domain_parameters == NULL) &&
        (attributes->domain_parameters_size != 0u))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Step 1:
       Allocate storage for a key to be generated
    */
    mcuxClKey_Descriptor_t key = {0u};
    /* Initialize the key container */
    mcuxClKey_setKeyData(&key, (uint8_t *)key_buffer);
    mcuxClKey_setKeyContainerSize(&key, (uint32_t)key_buffer_size);
    MCUX_CSSL_ANALYSIS_START_SUPPRESS_DISCARD_CONST_QUALIFIER("Const must be discarded to initialize the generic structure member.")
    mcuxClKey_setAuxData(&key, (void*)attributes);
    MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_DISCARD_CONST_QUALIFIER()

    /* Initialize the loaded key data (location descr.) as a storage for the public key */
    if(false == (MCUXCLPSADRIVER_IS_LOCAL_STORAGE(location)))
    {
        /* key stored in orace - call Orcale to reserve memory for the key */
        status = mcuxClPsaDriver_Oracle_ReserveKey(&key);
        if(PSA_SUCCESS != status)
        {
            return status;
        }
    }
    else
    {
        /* local storage - setup loaded key with buffer from caller */
        MCUX_CSSL_ANALYSIS_START_SUPPRESS_POINTER_CASTING("Loaded key is aligned per user guidance.")
        mcuxClKey_setLoadedKeyData(&key, (uint32_t *)key_buffer);
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_POINTER_CASTING()
        mcuxClKey_setLoadedKeyLength(&key, (uint32_t)key_buffer_size);
        mcuxClKey_setLoadStatus(&key, MCUXCLKEY_LOADSTATUS_MEMORY);
    }

    /* Step 2:
       Depending on the location, see how to generate the private key
    */
    if(MCUXCLKEY_LOADSTATUS_COPRO == mcuxClKey_getLoadStatus(&key))
    {
        /* LoadedKeyData serves as a throw-away buffer for the public key.
           The private key will be kept in the given key slot of the keystore. */

        status = mcuxClPsaDriver_psa_driver_wrapper_generate_s50_key(
            /* const psa_key_attributes_t *attributes:     */ attributes,
            /* mcuxClEls_KeyIndex_t key_index_private_key:  */ mcuxClKey_getLoadedKeySlot(&key),
            /* uint8_t *public_key_buffer:                 */ mcuxClKey_getLoadedKeyData(&key),
            /* uint32_t public_key_buffer_size:            */ mcuxClKey_getLoadedKeyLength(&key)
        );

        if(status != PSA_SUCCESS)
        {
            return status;
        }
    }
    else /* MCUXCLKEY_LOADSTATUS_MEMORY */
    {
        if(key_type_is_raw_bytes(type))
        {
            status = mcuxClPsaDriver_psa_driver_wrapper_generate_random(mcuxClKey_getLoadedKeyData(&key), mcuxClKey_getLoadedKeyLength(&key));
            if(status != PSA_SUCCESS)
            {
                return status;
            }
            *key_buffer_length = mcuxClKey_getLoadedKeyLength(&key);
        }
        else if(type == PSA_KEY_TYPE_RSA_KEY_PAIR)
        {
            status = mcuxClPsaDriver_psa_driver_wrapper_rsa_key(attributes,
                                               mcuxClKey_getLoadedKeyData(&key),
                                               mcuxClKey_getLoadedKeyLength(&key),
                                               key_buffer_length);
            if(status != PSA_SUCCESS)
            {
                return status;
            }
        }
        else if(PSA_KEY_TYPE_IS_ECC(type) && PSA_KEY_TYPE_IS_KEY_PAIR(type))
        {
            status = mcuxClPsaDriver_psa_driver_wrapper_generate_ecp_key(attributes,
                                                  mcuxClKey_getLoadedKeyData(&key),
                                                  mcuxClKey_getLoadedKeyLength(&key),
                                                  key_buffer_length);
            if(status != PSA_SUCCESS)
            {
                return status;
            }
        }
        else
        {
            (void)key_buffer_length;
            return PSA_ERROR_NOT_SUPPORTED;
        }
    }

    /* Step 3:
       Store the generated private key in the buffer provided by the caller
    */
    if(false == (MCUXCLPSADRIVER_IS_LOCAL_STORAGE(location)))
    {
        status = mcuxClPsaDriver_Oracle_StoreKey(&key);
        if(PSA_SUCCESS != status)
        {
            return status;
        }
        *key_buffer_length = mcuxClKey_getKeyContainerUsedSize(&key);
    }
    /* Note: For keys in local storage no additional store or copy operation is needed,
             because the key_buffer was already used during the key generation. */

    return PSA_SUCCESS;
}


MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
const mcuxClEcc_Weier_DomainParams_t* mcuxClPsaDriver_psa_driver_wrapper_getEccDomainParams(
     const psa_key_attributes_t *attributes)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    MCUX_CSSL_ANALYSIS_START_PATTERN_SWITCH_STATEMENT_RETURN_TERMINATION()
    switch(attributes->core.type)
    {
        case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1):
        case PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1):
            switch((uint32_t)(MCUXCLPSADRIVER_BITS_TO_BYTES((uint32_t)attributes->core.bits))) {
                case MCUXCLKEY_SIZE_192:
                    return &mcuxClEcc_Weier_DomainParams_secp192r1;
                case MCUXCLKEY_SIZE_224:
                    return &mcuxClEcc_Weier_DomainParams_secp224r1;
                case MCUXCLKEY_SIZE_256:
                    return &mcuxClEcc_Weier_DomainParams_secp256r1;
                case MCUXCLKEY_SIZE_384:
                    return &mcuxClEcc_Weier_DomainParams_secp384r1;
                case MCUXCLKEY_SIZE_521:
                    return &mcuxClEcc_Weier_DomainParams_secp521r1;
                default:
                    return NULL;
            }
        case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1):
        case PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_K1):
            switch((uint32_t)(MCUXCLPSADRIVER_BITS_TO_BYTES((uint32_t)attributes->core.bits))) {
                case MCUXCLKEY_SIZE_192:
                    return &mcuxClEcc_Weier_DomainParams_secp192k1;
                case MCUXCLKEY_SIZE_224:
                    return &mcuxClEcc_Weier_DomainParams_secp224k1;
                case MCUXCLKEY_SIZE_256:
                    return &mcuxClEcc_Weier_DomainParams_secp256k1;
                default:
                    return NULL;
            }
        case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1):
        case PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_BRAINPOOL_P_R1):
            switch((uint32_t)(MCUXCLPSADRIVER_BITS_TO_BYTES((uint32_t)attributes->core.bits))) {
                case MCUXCLKEY_SIZE_160:
                    return &mcuxClEcc_Weier_DomainParams_brainpoolP160r1;
                case MCUXCLKEY_SIZE_192:
                    return &mcuxClEcc_Weier_DomainParams_brainpoolP192r1;
                case MCUXCLKEY_SIZE_224:
                    return &mcuxClEcc_Weier_DomainParams_brainpoolP224r1;
                case MCUXCLKEY_SIZE_256:
                    return &mcuxClEcc_Weier_DomainParams_brainpoolP256r1;
                case MCUXCLKEY_SIZE_320:
                    return &mcuxClEcc_Weier_DomainParams_brainpoolP320r1;
                case MCUXCLKEY_SIZE_384:
                    return &mcuxClEcc_Weier_DomainParams_brainpoolP384r1;
                case MCUXCLKEY_SIZE_512:
                    return &mcuxClEcc_Weier_DomainParams_brainpoolP512r1;
                default:
                    return NULL;
            }
        default:
            return NULL;
    }
    MCUX_CSSL_ANALYSIS_STOP_PATTERN_SWITCH_STATEMENT_RETURN_TERMINATION()
}


MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
psa_status_t mcuxClPsaDriver_psa_driver_wrapper_exportKey(const psa_key_attributes_t *attributes,
                                                         const uint8_t *key_buffer,
                                                         size_t key_buffer_size,
                                                         uint8_t *data,
                                                         size_t data_size,
                                                         size_t *data_length)
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
    psa_status_t psa_status = PSA_ERROR_NOT_SUPPORTED;
    mcuxClKey_Descriptor_t key = {0};

    psa_status = mcuxClPsaDriver_psa_driver_wrapper_createClKey(attributes, key_buffer, key_buffer_size, &key);
    if(PSA_SUCCESS == psa_status)
    {
        /* not supported for internal keys */
        if( MCUXCLKEY_LOADSTATUS_MEMORY != mcuxClKey_getLoadStatus(&key) )
        {
            (void)mcuxClPsaDriver_psa_driver_wrapper_UpdateKeyStatusUnload(&key);
            return PSA_ERROR_NOT_SUPPORTED;
        }

        /* check for buffer too small */
        if( key.location.length > data_size ) {
            (void)mcuxClPsaDriver_psa_driver_wrapper_UpdateKeyStatusUnload(&key);
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN(tokenNxpClMemory_copy, mcuxClMemory_copy(data,
                                                                                     key.location.pData,
                                                                                     key.location.length,
                                                                                     data_size));
        if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) != tokenNxpClMemory_copy)
        {
            return PSA_ERROR_GENERIC_ERROR;
        }
        MCUX_CSSL_FP_FUNCTION_CALL_VOID_END();

        *data_length = key.location.length;

        /* unload key */
        psa_status = mcuxClPsaDriver_psa_driver_wrapper_UpdateKeyStatusUnload(&key);
    }
    return psa_status;
}

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static psa_status_t mcuxClPsaDriver_psa_driver_wrapper_key_agreement_internal(
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *peer_key,
    size_t peer_key_length,
    uint8_t *shared_secret,
    size_t shared_secret_size,
    size_t *shared_secret_length)
{
    if(PSA_ALG_IS_ECDH(alg))
    {
        if (!PSA_KEY_TYPE_IS_ECC_KEY_PAIR(attributes->core.type))
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        MCUX_CSSL_ANALYSIS_START_SUPPRESS_CAST_OF_COMPOSITE_EXPRESSION("PSA_KEY_TYPE_ECC_GET_FAMILY macro comes from external library outside our control")
        psa_ecc_family_t curve = MCUXCLPSADRIVER_PSA_KEY_TYPE_ECC_GET_FAMILY(psa_get_key_type(attributes));
        MCUX_CSSL_ANALYSIS_STOP_SUPPRESS_CAST_OF_COMPOSITE_EXPRESSION()
        size_t privateKeySize = MCUXCLPSADRIVER_BITS_TO_BYTES(psa_get_key_bits(attributes));

        /* Setup one session to be used by all functions called */
        mcuxClSession_Descriptor_t session;

        //For Montgomery curves
        if(PSA_ECC_FAMILY_MONTGOMERY == curve)
        {
            if(attributes->domain_parameters_size != 0u)
            {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            /* Curve448 */
            if(MCUXCLECC_MONTDH_CURVE448_SIZE_PRIVATEKEY == privateKeySize)
            {
                if(MCUXCLECC_MONTDH_CURVE448_SIZE_PUBLICKEY != peer_key_length)
                {
                    return PSA_ERROR_INVALID_ARGUMENT;
                }

                uint32_t pCpuWa[MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE448_WACPU_SIZE / (sizeof(uint32_t))];
                /* Initialize session with pkcWA on the beginning of PKC RAM */
                MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(si_status, si_token, mcuxClSession_init(&session, pCpuWa, MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE448_WACPU_SIZE,
                                        mcuxClPkc_inline_getPointerToPkcRamStart(), MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE448_WAPKC_SIZE));


                if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != si_token) || (MCUXCLSESSION_STATUS_OK != si_status))
                {
                    return PSA_ERROR_GENERIC_ERROR;
                }
                MCUX_CSSL_FP_FUNCTION_CALL_END();

                /* Initialize the PRNG */
                MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(prngInit_result, prngInit_token, mcuxClRandom_ncInit(&session));
                if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != prngInit_token) || (MCUXCLRANDOM_STATUS_OK != prngInit_result))
                {
                    return PSA_ERROR_GENERIC_ERROR;
                }
                MCUX_CSSL_FP_FUNCTION_CALL_END();

                uint32_t privateKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
                mcuxClKey_Handle_t privKeyHandler = mcuxClKey_castToKeyHandle(privateKeyDesc);

                MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(privkeyinit_result, privkeyinit_token, mcuxClKey_init(
                /* mcuxClSession_Handle_t session         */ &session,
                /* mcuxClKey_Handle_t key                 */ privKeyHandler,
                /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Ecc_MontDH_Curve448_PrivateKey,
                /* const uint8_t * pKeyData              */ key_buffer,
                /* uint32_t keyDataLength                */ MCUXCLECC_MONTDH_CURVE448_SIZE_PRIVATEKEY));
                if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != privkeyinit_token) || (MCUXCLKEY_STATUS_OK != privkeyinit_result))
                {
                    return PSA_ERROR_GENERIC_ERROR;
                }
                MCUX_CSSL_FP_FUNCTION_CALL_END();

                uint32_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
                mcuxClKey_Handle_t pubKeyHandler = mcuxClKey_castToKeyHandle(pubKeyDesc);

                MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pubkeyinit_result, pubkeyinit_token, mcuxClKey_init(
                /* mcuxClSession_Handle_t session         */ &session,
                /* mcuxClKey_Handle_t key                 */ pubKeyHandler,
                /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Ecc_MontDH_Curve448_PublicKey,
                /* const uint8_t * pKeyData              */ peer_key,
                /* uint32_t keyDataLength                */ MCUXCLECC_MONTDH_CURVE448_SIZE_PUBLICKEY));
                if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != pubkeyinit_token) || (MCUXCLKEY_STATUS_OK != pubkeyinit_result))
                {
                    return PSA_ERROR_GENERIC_ERROR;
                }
                MCUX_CSSL_FP_FUNCTION_CALL_END();

                /* Call Dh KeyAgreement for shared secret generation and check FP and return code */
                uint32_t outLength = 0u;
                MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(keyagreement_result, keyagreement_token, mcuxClEcc_MontDH_KeyAgreement(&session,
                                                                                                privKeyHandler,
                                                                                                pubKeyHandler,
                                                                                                shared_secret,
                                                                                                &outLength));
                if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_MontDH_KeyAgreement) != keyagreement_token) || (MCUXCLECC_STATUS_OK != keyagreement_result))
                {
                    return PSA_ERROR_GENERIC_ERROR;
                }
                MCUX_CSSL_FP_FUNCTION_CALL_END();

                *shared_secret_length = (size_t)outLength;

                MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(cleanup_result, cleanup_token, mcuxClSession_cleanup(&session));
                if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != cleanup_token) || (MCUXCLSESSION_STATUS_OK != cleanup_result))
                {
                    return PSA_ERROR_GENERIC_ERROR;
                }
                MCUX_CSSL_FP_FUNCTION_CALL_END();

                MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(destroy_result, destroy_token, mcuxClSession_destroy(&session));
                if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != destroy_token) || (MCUXCLSESSION_STATUS_OK != destroy_result))
                {
                    return PSA_ERROR_GENERIC_ERROR;
                }
                MCUX_CSSL_FP_FUNCTION_CALL_END();

                return PSA_SUCCESS;
            }
            /* Curve25519 */
            else if(MCUXCLECC_MONTDH_CURVE25519_SIZE_PRIVATEKEY == privateKeySize)
            {
                if(MCUXCLECC_MONTDH_CURVE25519_SIZE_PUBLICKEY != peer_key_length)
                {
                    return PSA_ERROR_INVALID_ARGUMENT;
                }

                uint32_t pCpuWa[MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE25519_WACPU_SIZE / (sizeof(uint32_t))];
                /* Initialize session with pkcWA on the beginning of PKC RAM */
                MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(si_status, si_token, mcuxClSession_init(&session, pCpuWa, MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE25519_WACPU_SIZE,
                                        mcuxClPkc_inline_getPointerToPkcRamStart(), MCUXCLECC_MONTDH_KEYAGREEMENT_CURVE25519_WAPKC_SIZE));


                if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != si_token) || (MCUXCLSESSION_STATUS_OK != si_status))
                {
                    return PSA_ERROR_GENERIC_ERROR;
                }
                MCUX_CSSL_FP_FUNCTION_CALL_END();

                /* Initialize the PRNG */
                MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(prngInit_result, prngInit_token, mcuxClRandom_ncInit(&session));
                if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != prngInit_token) || (MCUXCLRANDOM_STATUS_OK != prngInit_result))
                {
                    return PSA_ERROR_GENERIC_ERROR;
                }
                MCUX_CSSL_FP_FUNCTION_CALL_END();

                uint32_t privateKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
                mcuxClKey_Handle_t privKeyHandler = mcuxClKey_castToKeyHandle(privateKeyDesc);

                MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(privkeyinit_result, privkeyinit_token, mcuxClKey_init(
                /* mcuxClSession_Handle_t session         */ &session,
                /* mcuxClKey_Handle_t key                 */ privKeyHandler,
                /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Ecc_MontDH_Curve25519_PrivateKey,
                /* const uint8_t * pKeyData              */ key_buffer,
                /* uint32_t keyDataLength                */ MCUXCLECC_MONTDH_CURVE25519_SIZE_PRIVATEKEY));
                if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != privkeyinit_token) || (MCUXCLKEY_STATUS_OK != privkeyinit_result))
                {
                    return PSA_ERROR_GENERIC_ERROR;
                }
                MCUX_CSSL_FP_FUNCTION_CALL_END();

                uint32_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
                mcuxClKey_Handle_t pubKeyHandler = mcuxClKey_castToKeyHandle(pubKeyDesc);

                MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pubkeyinit_result, pubkeyinit_token, mcuxClKey_init(
                /* mcuxClSession_Handle_t session         */ &session,
                /* mcuxClKey_Handle_t key                 */ pubKeyHandler,
                /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Ecc_MontDH_Curve25519_PublicKey,
                /* const uint8_t * pKeyData              */ peer_key,
                /* uint32_t keyDataLength                */ MCUXCLECC_MONTDH_CURVE25519_SIZE_PUBLICKEY));
                if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != pubkeyinit_token) || (MCUXCLKEY_STATUS_OK != pubkeyinit_result))
                {
                    return PSA_ERROR_GENERIC_ERROR;
                }
                MCUX_CSSL_FP_FUNCTION_CALL_END();

                /* Call Dh KeyAgreement for shared secret generation and check FP and return code */
                uint32_t outLength = 0u;
                MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(keyagreement_result, keyagreement_token, mcuxClEcc_MontDH_KeyAgreement(&session,
                                                                                                privKeyHandler,
                                                                                                pubKeyHandler,
                                                                                                shared_secret,
                                                                                                &outLength));
                if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_MontDH_KeyAgreement) != keyagreement_token) || (MCUXCLECC_STATUS_OK != keyagreement_result))
                {
                    return PSA_ERROR_GENERIC_ERROR;
                }
                MCUX_CSSL_FP_FUNCTION_CALL_END();

                *shared_secret_length = (size_t)outLength;

                MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(cleanup_result, cleanup_token, mcuxClSession_cleanup(&session));
                if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != cleanup_token) || (MCUXCLSESSION_STATUS_OK != cleanup_result))
                {
                    return PSA_ERROR_GENERIC_ERROR;
                }
                MCUX_CSSL_FP_FUNCTION_CALL_END();

                MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(destroy_result, destroy_token, mcuxClSession_destroy(&session));
                if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != destroy_token) || (MCUXCLSESSION_STATUS_OK != destroy_result))
                {
                    return PSA_ERROR_GENERIC_ERROR;
                }
                MCUX_CSSL_FP_FUNCTION_CALL_END();
                return PSA_SUCCESS;
            }
            else
            {
                return PSA_ERROR_NOT_SUPPORTED;
            }
        }
        /* For Weierstrass curves, curve_parameters are defined in mcuxClEcc_Constants.h */
        else if((PSA_ECC_FAMILY_SECP_R1 == curve) || (PSA_ECC_FAMILY_SECP_K1 == curve) || (PSA_ECC_FAMILY_BRAINPOOL_P_R1 == curve))
        {
            if(attributes->domain_parameters_size != 0u)
            {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            if ((peer_key_length & 1u) == 0u) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            const mcuxClEcc_Weier_DomainParams_t* curveParamData = mcuxClPsaDriver_psa_driver_wrapper_getEccDomainParams(attributes);
            if(NULL == curveParamData)
            {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            /* Initialize buffers on the stack for domain parameters endianess swap (LE -> BE) */
            const uint32_t byteLenP = curveParamData->common.byteLenP;
            const uint32_t byteLenN = curveParamData->common.byteLenN;

            /* Reverse endianess of domain parameters as current ECC component expects domain parameters in big endian */
            uint8_t pG[2u * MCUXCLECC_WEIERECC_MAX_SIZE_PRIMEP];
            uint8_t pA[MCUXCLECC_WEIERECC_MAX_SIZE_PRIMEP];
            uint8_t pB[MCUXCLECC_WEIERECC_MAX_SIZE_PRIMEP];
            uint8_t pP[MCUXCLECC_WEIERECC_MAX_SIZE_PRIMEP];
            uint8_t pN[MCUXCLECC_WEIERECC_MAX_SIZE_BASEPOINTORDER];
            for(uint32_t i = 0; i < byteLenP; i++)
            {
                pA[i] = curveParamData->common.pCurveParam1[byteLenP - i - 1u];
                pB[i] = curveParamData->common.pCurveParam2[byteLenP - i - 1u];
                pP[i] = curveParamData->common.pFullModulusP[byteLenP + MCUXCLPKC_WORDSIZE - i - 1u];
                pG[i] = curveParamData->common.pGx[byteLenP - i - 1u];
                pG[byteLenP + i] = curveParamData->common.pGy[byteLenP - i - 1u];
            }
            for(uint32_t i = 0; i < byteLenN; i++)
            {
                pN[i] = curveParamData->common.pFullModulusN[byteLenN + MCUXCLPKC_WORDSIZE - i - 1u];
            }

            uint8_t output[2u * MCUXCLECC_WEIERECC_MAX_SIZE_PRIMEP];

            if(peer_key[0] == 0x04u) {
                /* format == MBEDTLS_ECP_PF_UNCOMPRESSED */
                if (peer_key_length != 1u + byteLenP * 2u) {
                    return PSA_ERROR_INVALID_ARGUMENT;
                }
            }
            else if ((peer_key[0] == 0x02u) || (peer_key[0] == 0x03u))
            {
                /* format == MBEDTLS_ECP_PF_COMPRESSED */
                return PSA_ERROR_NOT_SUPPORTED;
            }
            else
            {
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }

            MCUXCLBUFFER_INIT_RO(buffA, NULL, pA, byteLenP);
            MCUXCLBUFFER_INIT_RO(buffB, NULL, pB, byteLenP);
            MCUXCLBUFFER_INIT_RO(buffP, NULL, pP, byteLenP);
            MCUXCLBUFFER_INIT_RO(buffG, NULL, pG, byteLenP * 2u);
            MCUXCLBUFFER_INIT_RO(buffN, NULL, pN, byteLenN);

            const uint8_t *pOtherPublic = peer_key + 1u;
            MCUXCLBUFFER_INIT_RO(buffKeyBuffer,   NULL, key_buffer,   byte_len_n);
            MCUXCLBUFFER_INIT_RO(buffOtherPublic, NULL, pOtherPublic, byte_len_p * 2u);
            MCUXCLBUFFER_INIT(buffOutput,         NULL, output,       byte_len_p * 2u);

            mcuxClEcc_PointMult_Param_t params =
            {
                .curveParam = (mcuxClEcc_DomainParam_t)
                {
                    .pA = buffA,
                    .pB = buffB,
                    .pP = buffP,
                    .pG = buffG,
                    .pN = buffN,
                    .misc = mcuxClEcc_DomainParam_misc_Pack(byteLenN, byteLenP)
                },
                .pScalar = buffKeyBuffer,
                .pPoint = buffOtherPublic,
                .pResult = buffOutput,
                .optLen = 0u
            };

            uint32_t pCpuWa[MCUXCLECC_POINTMULT_WACPU_SIZE / sizeof(uint32_t)];
            /* Initialize session with pkcWA on the beginning of PKC RAM */
            MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(si_status, si_token, mcuxClSession_init(&session, pCpuWa, MCUXCLECC_POINTMULT_WACPU_SIZE,
                                    mcuxClPkc_inline_getPointerToPkcRamStart(), MCUXCLECC_POINTMULT_WAPKC_SIZE(byteLenP,byteLenN)));


            if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != si_token) || (MCUXCLSESSION_STATUS_OK != si_status))
            {
                return PSA_ERROR_GENERIC_ERROR;
            }
            MCUX_CSSL_FP_FUNCTION_CALL_END();

            MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(prngInit_result, prngInit_token, mcuxClRandom_ncInit(&session));
            if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != prngInit_token) || (MCUXCLRANDOM_STATUS_OK != prngInit_result))
            {
                return PSA_ERROR_GENERIC_ERROR;
            }
            MCUX_CSSL_FP_FUNCTION_CALL_END();

            /* Call PointMult for public keys generation and check FP and return code */
            MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pointMult_result, pointMult_token, mcuxClEcc_PointMult(&session, &params));
            if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointMult) != pointMult_token) || (MCUXCLECC_STATUS_OK != pointMult_result))
            {
                return PSA_ERROR_GENERIC_ERROR;
            }
            MCUX_CSSL_FP_FUNCTION_CALL_END();

            *shared_secret_length = byteLenP;
            MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN(tokenNxpClMemory_copy, mcuxClMemory_copy(shared_secret,
                                                                                        output,
                                                                                        byteLenP,
                                                                                        byteLenP));
            if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) != tokenNxpClMemory_copy)
            {
                return PSA_ERROR_GENERIC_ERROR;
            }
            MCUX_CSSL_FP_FUNCTION_CALL_VOID_END();

            MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(cleanup_result, cleanup_token, mcuxClSession_cleanup(&session));
            if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != cleanup_token) || (MCUXCLSESSION_STATUS_OK != cleanup_result))
            {
                return PSA_ERROR_GENERIC_ERROR;
            }
            MCUX_CSSL_FP_FUNCTION_CALL_END();

            MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(destroy_result, destroy_token, mcuxClSession_destroy(&session));
            if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != destroy_token) || (MCUXCLSESSION_STATUS_OK != destroy_result))
            {
                return PSA_ERROR_GENERIC_ERROR;
            }
            MCUX_CSSL_FP_FUNCTION_CALL_END();

            return PSA_SUCCESS;
        }
        else
        {
            (void) attributes;
            (void) key_buffer;
            (void) key_buffer_size;
            (void) peer_key;
            (void) peer_key_length;
            (void) shared_secret;
            (void) shared_secret_size;
            (void) shared_secret_length;
            return PSA_ERROR_NOT_SUPPORTED;
        }
    }
    else
    {
        (void) attributes;
        (void) key_buffer;
        (void) key_buffer_size;
        (void) peer_key;
        (void) peer_key_length;
        (void) shared_secret;
        (void) shared_secret_size;
        (void) shared_secret_length;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
psa_status_t mcuxClPsaDriver_psa_driver_wrapper_key_agreement(
MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *peer_key,
    size_t peer_key_length,
    uint8_t *shared_secret,
    size_t shared_secret_size,
    size_t *shared_secret_length)
{
    psa_status_t psa_status = PSA_ERROR_NOT_SUPPORTED;
    mcuxClKey_Descriptor_t key = {0};

    psa_status = mcuxClPsaDriver_psa_driver_wrapper_createClKey(attributes, key_buffer, key_buffer_size, &key);

    if(PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }

    /* only supported for external keys */
    if( MCUXCLKEY_LOADSTATUS_COPRO != mcuxClKey_getLoadStatus(&key) )
    {
        psa_status = mcuxClPsaDriver_psa_driver_wrapper_key_agreement_internal(
            attributes,
            key.location.pData,
            key.location.length,
            alg,
            peer_key,
            peer_key_length,
            shared_secret,
            shared_secret_size,
            shared_secret_length);
    } else {
        psa_status = PSA_ERROR_NOT_SUPPORTED;
    }

    /* unload key */
    psa_status_t keyStatus = mcuxClPsaDriver_psa_driver_wrapper_UpdateKeyStatusUnload(&key);

    /* Overwrite status only when status has no error code */
    if(PSA_SUCCESS == psa_status)
    {
        psa_status = keyStatus;
    }

    return psa_status;
}
