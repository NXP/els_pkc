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

/**
 * @file  key_import_puk_der.c
 * @brief Example of PuK import from a DER-encoded certificate using the CSSv2 (CLNS component mcuxClCss)
 *
 * @example key_import_puk_der.c
 * @brief Example of PuK import from a DER-encoded certificate using the CSSv2 (CLNS component mcuxClCss)
 */

#include <mcuxClCss.h> // Interface to the entire mcuxClCss component
#include <mcuxClMemory.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <stdbool.h>  // bool type for the example's return code
#include <mcuxClExample_CSS_Helper.h>
#include <mcuxClExample_CSS_Key_Helper.h>
#include <mcuxClExample_RFC3394_Helper.h>


/** Key wrapping key. */
#ifdef MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV_ROM
const static uint8_t key_share[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#endif

#ifdef MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV
const uint8_t key_share[32] = {
    0x34, 0x9f, 0xf7, 0x65, 0x1f, 0xd0, 0x0b, 0xd4, 0xaf, 0x0a, 0xaa, 0xd8, 0x69, 0xcd, 0x5b, 0xfe,
    0x01, 0xc9, 0xaf, 0x6e, 0x65, 0x03, 0xeb, 0xd9, 0x33, 0x27, 0x89, 0x68, 0x8d, 0x83, 0xef, 0xc1
};
const static uint8_t key_share2[36]  = {
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22
};
#endif


/** Raw DER-encoded certificate. */
static uint8_t const der_certificate[450U] = {
    // certificate
    0x30U, 0x82U, 0x01U, 0xBEU, 0x30U, 0x82U, 0x01U, 0x63U, 0x02U, 0x14U, 0x14U, 0xFDU, 0x55U, 0xCAU, 0x4AU, 0x3BU,
    0x27U, 0xB7U, 0x47U, 0xCAU, 0x12U, 0x5CU, 0xD4U, 0x52U, 0x6DU, 0x82U, 0xC9U, 0xB5U, 0xB7U, 0xA7U, 0x30U, 0x0AU,
    0x06U, 0x08U, 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x04U, 0x03U, 0x02U, 0x30U, 0x61U, 0x31U, 0x0BU, 0x30U, 0x09U,
    0x06U, 0x03U, 0x55U, 0x04U, 0x06U, 0x13U, 0x02U, 0x30U, 0x30U, 0x31U, 0x0BU, 0x30U, 0x09U, 0x06U, 0x03U, 0x55U,
    0x04U, 0x08U, 0x0CU, 0x02U, 0x30U, 0x30U, 0x31U, 0x0BU, 0x30U, 0x09U, 0x06U, 0x03U, 0x55U, 0x04U, 0x07U, 0x0CU,
    0x02U, 0x30U, 0x30U, 0x31U, 0x0BU, 0x30U, 0x09U, 0x06U, 0x03U, 0x55U, 0x04U, 0x0AU, 0x0CU, 0x02U, 0x30U, 0x30U,
    0x31U, 0x0BU, 0x30U, 0x09U, 0x06U, 0x03U, 0x55U, 0x04U, 0x0BU, 0x0CU, 0x02U, 0x30U, 0x30U, 0x31U, 0x0BU, 0x30U,
    0x09U, 0x06U, 0x03U, 0x55U, 0x04U, 0x03U, 0x0CU, 0x02U, 0x30U, 0x30U, 0x31U, 0x11U, 0x30U, 0x0FU, 0x06U, 0x09U,
    0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x09U, 0x01U, 0x16U, 0x02U, 0x30U, 0x30U, 0x30U, 0x1EU, 0x17U,
    0x0DU, 0x32U, 0x31U, 0x31U, 0x32U, 0x31U, 0x33U, 0x31U, 0x30U, 0x31U, 0x32U, 0x30U, 0x35U, 0x5AU, 0x17U, 0x0DU,
    0x32U, 0x32U, 0x31U, 0x32U, 0x31U, 0x33U, 0x31U, 0x30U, 0x31U, 0x32U, 0x30U, 0x35U, 0x5AU, 0x30U, 0x61U, 0x31U,
    0x0BU, 0x30U, 0x09U, 0x06U, 0x03U, 0x55U, 0x04U, 0x06U, 0x13U, 0x02U, 0x30U, 0x30U, 0x31U, 0x0BU, 0x30U, 0x09U,
    0x06U, 0x03U, 0x55U, 0x04U, 0x08U, 0x0CU, 0x02U, 0x30U, 0x30U, 0x31U, 0x0BU, 0x30U, 0x09U, 0x06U, 0x03U, 0x55U,
    0x04U, 0x07U, 0x0CU, 0x02U, 0x30U, 0x30U, 0x31U, 0x0BU, 0x30U, 0x09U, 0x06U, 0x03U, 0x55U, 0x04U, 0x0AU, 0x0CU,
    0x02U, 0x30U, 0x30U, 0x31U, 0x0BU, 0x30U, 0x09U, 0x06U, 0x03U, 0x55U, 0x04U, 0x0BU, 0x0CU, 0x02U, 0x30U, 0x30U,
    0x31U, 0x0BU, 0x30U, 0x09U, 0x06U, 0x03U, 0x55U, 0x04U, 0x03U, 0x0CU, 0x02U, 0x30U, 0x30U, 0x31U, 0x11U, 0x30U,
    0x0FU, 0x06U, 0x09U, 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x09U, 0x01U, 0x16U, 0x02U, 0x30U, 0x30U,
    // public key metadata
    0x30U, 0x59U, 0x30U, 0x13U, 0x06U, 0x07U, 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x02U, 0x01U, 0x06U, 0x08U, 0x2AU,
    0x86U, 0x48U, 0xCEU, 0x3DU, 0x03U, 0x01U, 0x07U,
    // public key header
    0x03U, 0x42U, 0x00U, 0x04U,
    // public key
    0x12U, 0x54U, 0x6EU, 0xDBU, 0x7CU, 0xD4U, 0x85U, 0xBEU, 0xDDU, 0x5BU, 0x3BU, 0x71U, 0xB7U, 0x0EU, 0xC2U, 0x19U,
    0x34U, 0x76U, 0x3BU, 0xAFU, 0xD2U, 0xE5U, 0xA2U, 0x76U, 0xCAU, 0xB6U, 0x09U, 0x63U, 0x09U, 0xA5U, 0x7FU, 0xEEU,
    0xF9U, 0x74U, 0x18U, 0x5DU, 0x9AU, 0x4AU, 0x0EU, 0x88U, 0x4AU, 0xBEU, 0xF4U, 0xBEU, 0xBDU, 0xC9U, 0x96U, 0x64U,
    0xBBU, 0xD5U, 0x67U, 0x94U, 0xACU, 0x9CU, 0x30U, 0xBAU, 0xF7U, 0xCFU, 0x36U, 0x18U, 0x91U, 0x10U, 0xE6U, 0x7EU,
    /** The now following signature will not be used in this example.
     *  Instead, the certificate will be copied into a buffer, padded, and then signed with our own root key
     *  which will be generated inside of this example. */
    // signature header
    0x30U, 0x0AU, 0x06U, 0x08U, 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x04U, 0x03U, 0x02U, 0x03U, 0x49U, 0x00U, 0x30U,
    0x46U,
    // signature x header
    0x02U, 0x21U,
    // signature x
    0x00U, 0xC3U, 0x08U, 0x77U, 0xFBU, 0x74U, 0x0FU, 0x18U, 0x57U, 0xC0U, 0x1EU, 0xE1U, 0x22U, 0x5CU, 0x07U, 0x54U,
    0x29U, 0x2AU, 0xEAU, 0x79U, 0x1DU, 0x06U, 0xEFU, 0xF0U, 0x61U, 0xEAU, 0xB7U, 0xEDU, 0x83U, 0x5BU, 0x16U, 0x64U,
    0x9BU,
    // signature y header
    0x02U, 0x21U,
    // signature y
    0x00U, 0xB0U, 0x8BU, 0xFAU, 0x21U, 0x8EU, 0x03U, 0x9BU, 0xA4U, 0x14U, 0x69U, 0x1AU, 0x81U, 0x93U, 0xF2U, 0x13U,
    0x27U, 0x06U, 0x28U, 0x24U, 0xB1U, 0x1DU, 0x64U, 0x72U, 0x79U, 0xADU, 0x92U, 0x6EU, 0x9CU, 0xD2U, 0x79U, 0x8BU,
    0xFDU
};

#define SHA256_BLOCK_SIZE 64U

/** Offset of the public key that we want to import within the certificate. */
static size_t der_certificate_offset_pbk = 299U;

/** Total length of the certificate without signature. */
static size_t der_certificate_len_without_signature = 363U;


/** Output buffer for the wrapped ECC public root key. */
static uint8_t key_rfc3394[MCUXCLCSS_RFC3394_CONTAINER_SIZE_P256] = { 0U };


/** Output buffer for the certificate and padding. */
static uint8_t der_certificate_import[sizeof(der_certificate) + SHA256_BLOCK_SIZE] = { 0U };


/** Output buffers for the public key of the mcuxClCss_EccKeyGen_Async operation. */
static mcuxClCss_EccByte_t ecc_root_public_key[MCUXCLCSS_ECC_PUBLICKEY_SIZE] = { 0U };
static mcuxClCss_EccByte_t ecc_root_public_key_switched[MCUXCLCSS_ECC_PUBLICKEY_SIZE] = { 0U };

/** Output buffer for the signature of the mcuxClCss_EccSign_Async operation. Must be word-aligned! */
static mcuxClCss_EccByte_t ecc_signature[MCUXCLCSS_ECC_SIGNATURE_SIZE] __attribute__ ((aligned (4))) = { 0U };

/** Output buffer for the signature part r of the mcuxClCss_KeyImportPuk_Async operation. Must be word-aligned! */
static mcuxClCss_EccByte_t ecc_signature_r[MCUXCLCSS_ECC_SIGNATURE_R_SIZE] __attribute__ ((aligned (4))) = { 0U };



/**
 * Example for PuK import from DER-encoded certificate using mcuxClCss functions.
 * @retval true  The example code completed successfully
 * @retval false The example code failed */
bool key_import_puk_der(
    void)
{
    /** Initialize CSS, Enable the CSSv2 **/
    if(!mcuxClExample_Css_Init(MCUXCLCSS_RESET_DO_NOT_CANCEL))
    {
        return false;
    }

    /* Key indices in internal keystore. */
    uint8_t key_idx_helper_key            = 0u;
    uint8_t key_idx_ecc_root_private_key  = 8u;
    uint8_t key_idx_ecc_root_public_key   = 12u;
    uint8_t key_idx_ecc_import_public_key = 16u;


    /**
     * 1. Prepare certificate for import by copying certificate without signature and adding SHA-256 padding.
     */

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClMemory_set(
                 der_certificate_import,
                 0x00,
                 sizeof(der_certificate_import),
                 sizeof(der_certificate_import)
    ));
    // mcuxClMemory_set is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set) != token) || (0U != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClMemory_copy(
                 der_certificate_import,
                 der_certificate,
                 der_certificate_len_without_signature,
                 sizeof(der_certificate_import)
    ));
    // mcuxClMemory_copy is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) != token) || (0U != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Set one bit after the certificate. */
    der_certificate_import[der_certificate_len_without_signature] = 0x80;

    /* Compute length with added padding. */
    size_t der_certificate_paddedLength = (((uint32_t) (der_certificate_len_without_signature) + SHA256_BLOCK_SIZE - 1u) & (~((uint32_t) SHA256_BLOCK_SIZE - 1u)));

    /* Set certificate length in last padding bytes. */
    size_t padIndex = der_certificate_paddedLength;
    der_certificate_import[--padIndex] = (uint8_t)(der_certificate_len_without_signature <<  3u);
    der_certificate_import[--padIndex] = (uint8_t)(der_certificate_len_without_signature >>  5u);
    der_certificate_import[--padIndex] = (uint8_t)(der_certificate_len_without_signature >> 13u);
    der_certificate_import[--padIndex] = (uint8_t)(der_certificate_len_without_signature >> 21u);
    der_certificate_import[--padIndex] = (uint8_t)(der_certificate_len_without_signature >> 29u);


    /**
     * 2. Generace ECC key pair and sign the prepared certificate.
     */

    /* Generate signing key */
    mcuxClCss_EccKeyGenOption_t keygen_options = {0};                  // Initialize a new configuration for the planned mcuxClCss_EccKeyGen_Async operation.
    keygen_options.bits.kgsrc = MCUXCLCSS_ECC_OUTPUTKEY_RANDOM;        // Configure that a non-deterministic key is generated.
    keygen_options.bits.kgsign = MCUXCLCSS_ECC_PUBLICKEY_SIGN_DISABLE; // Configure that the key does not need to be signed.
    keygen_options.bits.kgtypedh = MCUXCLCSS_ECC_OUTPUTKEY_SIGN;       // Configure key to be a signing key.

    mcuxClCss_KeyProp_t keygen_prop = {0};                                // Initialize a new configuration for the mcuxClCss_EccKeyGen_Async generated key properties.
    keygen_prop.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_TRUE; // Configure that user access rights: privileged access
    keygen_prop.bits.upprot_sec = MCUXCLCSS_KEYPROPERTY_SECURE_FALSE;     // Configure that user access rights: non-secure access

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_EccKeyGen_Async( // Perform key generation.
            keygen_options,                                 // Set the prepared configuration.
            (mcuxClCss_KeyIndex_t) 0U,                       // This parameter (signingKeyIdx) is ignored, since no signature is requested in the configuration.
            key_idx_ecc_root_private_key,                   // Keystore index at which the generated private key is stored.
            keygen_prop,                                    // Set the generated key properties.
            NULL,                                           // No random data is provided
            ecc_root_public_key                                  // Output buffer, which the operation will write the public key to.
            ));
    // mcuxClCss_EccKeyGen_Async is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_EccKeyGen_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
    {
        return false; // Expect that no error occurred, meaning that the mcuxClCss_EccKeyGen_Async operation was started.
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_LimitedWaitForOperation(0x00100000U, MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_EccKeyGen_Async operation to complete.
    // mcuxClCss_LimitedWaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_LimitedWaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Sign certificate */
    mcuxClCss_EccSignOption_t sign_options = {0};           // Initialize a new configuration for the planned mcuxClCss_EccSign_Async operation.
    sign_options.bits.echashchl = MCUXCLCSS_ECC_NOT_HASHED; // Input is a full certificate, not a digest.

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_EccSign_Async( // Perform signature generation.
            sign_options,                      // Set the prepared configuration.
            key_idx_ecc_root_private_key,      // Set index of private key in keystore.
            NULL,                              // No input hash is provided
            der_certificate_import,            // Input is the certificate
            der_certificate_paddedLength,      // Length of the certificate
            ecc_signature                      // Output buffer, which the operation will write the signature to.
            ));
    // mcuxClCss_EccSign_Async is a flow-protected function: Check the protection token and the return value
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_EccSign_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
    {
        return false; // Expect that no error occurred, meaning that the mcuxClCss_EccSign_Async operation was started.
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_LimitedWaitForOperation(0x00100000U, MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_EccSign_Async operation to complete.
    // mcuxClCss_LimitedWaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_LimitedWaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /**
     * 3. Provision helper key and key wrapping key.
     */

    mcuxClCss_KeyProp_t key_properties;

    /* Provision helper key */

    key_properties.word.value = 0U;
    key_properties.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_TRUE;
    key_properties.bits.upprot_sec =  MCUXCLCSS_KEYPROPERTY_SECURE_TRUE;
    key_properties.bits.uaes = MCUXCLCSS_KEYPROPERTY_AES_TRUE;
    key_properties.bits.ukuok = MCUXCLCSS_KEYPROPERTY_KUOK_TRUE;
    key_properties.bits.ksize = MCUXCLCSS_KEYPROPERTY_KEY_SIZE_256;
    key_properties.bits.kactv = MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE;
    key_properties.bits.kbase = MCUXCLCSS_KEYPROPERTY_BASE_SLOT;

    mcuxClCss_KeyProvisionOption_t key_provision_options;
    key_provision_options.word.value = 0U;
    key_provision_options.bits.noic = MCUXCLCSS_KEYPROV_NOIC_ENABLE;

    #ifdef MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV_ROM
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_KeyProvisionRom_Async(
            key_provision_options,
            key_share,
            key_idx_helper_key,
            key_idx_helper_key,
            key_properties));
    // mcuxClCss_KeyProvisionRom_Async is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyProvisionRom_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    #elif defined MCUXCL_FEATURE_CSS_KEY_MGMT_KEYPROV

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_KeyProvision_Async(
            key_provision_options,
            key_share,
            key_share2,
            sizeof(key_share2),
            key_idx_helper_key,
            key_properties));
    // mcuxClCss_KeyProvision_Async is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyProvision_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    #else
        #error KEYPROV command not supported
    #endif

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_Enable_Async operation to complete.
    // mcuxClCss_WaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /**
     * 4. Convert the generated root public key and import it into keystore.
     */

    /* Switch X and Y coordinates. */
    for(size_t i = 0; i < MCUXCLCSS_ECC_PUBLICKEY_SIZE / 2u; i++)
    {
        ecc_root_public_key_switched[i] = ecc_root_public_key[i + MCUXCLCSS_ECC_PUBLICKEY_SIZE / 2u];
        ecc_root_public_key_switched[i + MCUXCLCSS_ECC_PUBLICKEY_SIZE / 2u] = ecc_root_public_key[i];
    }

    /* Wrap public key. */
    key_properties.word.value = 0u;
    key_properties.bits.ksize       = MCUXCLCSS_KEYPROPERTY_KEY_SIZE_512;
    key_properties.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_TRUE;
    key_properties.bits.upuk        = MCUXCLCSS_KEYPROPERTY_PUK_TRUE;
    key_properties.bits.upprot_sec  = MCUXCLCSS_KEYPROPERTY_SECURE_FALSE;
    key_properties.bits.kactv       = MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE;

    /** function that performs RFC3394 key wrapping  **/
    bool wrap_result = mcuxClExample_rfc3394_wrap(
    /*const uint8_t * pInput        */ ecc_root_public_key_switched, /*  pointer to key to be wrapped */
    /*size_t inputLength,           */ MCUXCLCSS_ECC_PUBLICKEY_SIZE,  /*  length of key to be wrapped in bytes */
    /*const uint8_t * pKek_in       */ NULL,                         /*  pointer to key wrapping key */
    /*mcuxClCss_KeyIndex_t keyIdx    */ key_idx_helper_key,           /*  keyslot index of key wrapping key */
    /*uint8_t extkey                */ 0U,                           /*  0-use key stored internally at keyIdx as wrapping key, 1-use external pKek_in as wrapping key */
    /*size_t kekLength              */ 0U,                           /*  length of key wrapping key in bytes */
    /*uint8_t * pOutput             */ key_rfc3394,                  /*  pointer to output buffer, size has to be inputLength + 16 bytes */
    /*mcuxClCss_KeyProp_t properties */ key_properties);              /*  properties of the key to be wrapped */
    if (!wrap_result)
    {
        return false;
    }

    /* Import root public key. */
    mcuxClCss_KeyImportOption_t import_options;
    import_options.word.value = 0u;
    import_options.bits.kfmt = MCUXCLCSS_KEYIMPORT_KFMT_RFC3394;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_KeyImport_Async(import_options,
                                                   key_rfc3394,
                                                   MCUXCLCSS_RFC3394_CONTAINER_SIZE_P256,
                                                   key_idx_helper_key,
                                                   key_idx_ecc_root_public_key
    )); // Wait for the mcuxClCss_KeyImportPuk_Async operation to complete.
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyImport_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_Enable_Async operation to complete.
    // mcuxClCss_WaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /**
     * 5. Import the public key from the certificate into keystore.
     */

    key_properties.word.value = 0u;
    key_properties.bits.upprot_priv = MCUXCLCSS_KEYPROPERTY_PRIVILEGED_TRUE;
    key_properties.bits.upprot_sec  = MCUXCLCSS_KEYPROPERTY_SECURE_FALSE;
    key_properties.bits.wrpok       = MCUXCLCSS_KEYPROPERTY_WRAP_TRUE;
    key_properties.bits.kactv       = MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE;
    key_properties.bits.ksize       = MCUXCLCSS_KEYPROPERTY_KEY_SIZE_512;
    key_properties.bits.upuk        = MCUXCLCSS_KEYPROPERTY_PUK_TRUE;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_KeyImportPuk_Async(der_certificate_import,
                                                der_certificate_paddedLength,
                                                der_certificate_offset_pbk,
                                                ecc_signature,
                                                key_idx_ecc_root_public_key,
                                                key_properties,
                                                key_idx_ecc_import_public_key,
                                                ecc_signature_r)); // Wait for the mcuxClCss_KeyImportPuk_Async operation to complete.
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyImportPuk_Async) != token) || (MCUXCLCSS_STATUS_OK_WAIT != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR)); // Wait for the mcuxClCss_Enable_Async operation to complete.
    // mcuxClCss_WaitForOperation is a flow-protected function: Check the protection token and the return value
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**
     * 6. Verify R and key properties.
     */

    /* Verify R. */
    for(size_t i = 0; i < MCUXCLCSS_ECC_SIGNATURE_R_SIZE; i++)
    {
        if ((uint8_t) ecc_signature[i] != (uint8_t) ecc_signature_r[i])
        {
            return false;
        }
    }

    /* Verify key properties of imported key. */
    mcuxClCss_KeyProp_t key_properties_imported;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_GetKeyProperties(key_idx_ecc_import_public_key, &key_properties_imported));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_GetKeyProperties) != token) || (MCUXCLCSS_STATUS_OK != result))
    {
        return false;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if (key_properties.bits.ksize != key_properties_imported.bits.ksize)
    {
        return false;
    }
    if (key_properties.bits.kactv != key_properties_imported.bits.kactv)
    {
        return false;
    }
    if (key_properties.bits.upuk != key_properties_imported.bits.upuk)
    {
        return false;
    }

    /**
     * 7. Cleanup.
     */

    /** deleted key_idx_helper_key keySlot **/
    if(!mcuxClExample_CSS_KeyDelete(key_idx_helper_key))
    {
        return false;
    }

    /** deleted key_idx_ecc_root_private_key keySlot **/
    if(!mcuxClExample_CSS_KeyDelete(key_idx_ecc_root_private_key))
    {
        return false;
    }

    /** deleted key_idx_ecc_root_public_key keySlot **/
    if(!mcuxClExample_CSS_KeyDelete(key_idx_ecc_root_public_key))
    {
        return false;
    }

    /** deleted key_idx_ecc_import_public_key keySlot **/
    if(!mcuxClExample_CSS_KeyDelete(key_idx_ecc_import_public_key))
    {
        return false;
    }

    /** Disable the CSSv2 **/
    if(!mcuxClExample_Css_Disable())
    {
        return false;
    }


    return true;
}
