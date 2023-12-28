#-------------------------------------------------------------------------------
# Copyright (c) 2023 NXP.
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
#Description: Component els_pkc_test; user_visible: False
include_guard(GLOBAL)
message("component_els_pkc_examples component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClAeadModes/mcuxClAeadModes_Multipart_Els_Ccm_Example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClAeadModes/mcuxClAeadModes_Oneshot_Els_Ccm_Example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClAeadModes/mcuxClAeadModes_Oneshot_Els_Gcm_Example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClCipherModes/mcuxClCipherModes_Multipart_Cbc_Els_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClCipherModes/mcuxClCipherModes_Multipart_Ctr_Els_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClCipherModes/mcuxClCipherModes_Multipart_Ecb_Els_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClCipherModes/mcuxClCipherModes_Multipart_Ecb_PaddingPKCS7_Els_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClCipherModes/mcuxClCipherModes_Oneshot_Cbc_Els_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClCipherModes/mcuxClCipherModes_Oneshot_Cbc_ZeroPadding_Els_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClCipherModes/mcuxClCipherModes_Oneshot_Ctr_Els_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClCipherModes/mcuxClCipherModes_Oneshot_Ecb_Els_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClCipherModes/mcuxClCipherModes_Oneshot_Ecb_PaddingPKCS7_Els_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClCipherModes/mcuxClCipherModes_Oneshot_Ecb_ZeroPadding_Els_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClEcc/mcuxClEcc_EdDSA_Ed25519_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClEcc/mcuxClEcc_EdDSA_GenerateSignature_Ed25519_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClEcc/mcuxClEcc_EdDSA_VerifySignature_Ed25519_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClEcc/mcuxClEcc_Mont_Curve25519_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClEcc/mcuxClEcc_Mont_Curve448_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClEcc/mcuxClEcc_WeierECC_CustomEccWeierType_BN256_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClEcc/mcuxClEcc_EdDSA_Ed25519ctx_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClEcc/mcuxClEcc_EdDSA_Ed25519ph_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClEls/mcuxClEls_Cipher_Aes128_Cbc_Encrypt_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClEls/mcuxClEls_Cipher_Aes128_Ecb_Encrypt_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClEls/mcuxClEls_Common_Get_Info_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClEls/mcuxClEls_Ecc_Keygen_Sign_Verify_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClEls/mcuxClEls_Hash_Sha224_One_Block_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClEls/mcuxClEls_Hash_Sha256_One_Block_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClEls/mcuxClEls_Hash_Sha384_One_Block_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClEls/mcuxClEls_Hash_Sha512_One_Block_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClEls/mcuxClEls_Rng_Prng_Get_Random_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClEls/mcuxClEls_Tls_Master_Key_Session_Keys_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClHashModes/mcuxClHashModes_sha224_oneshot_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClHashModes/mcuxClHashModes_sha256_longMsgOneshot_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClHashModes/mcuxClHashModes_sha256_oneshot_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClHashModes/mcuxClHashModes_sha256_streaming_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClHashModes/mcuxClHashModes_sha384_oneshot_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClHashModes/mcuxClHashModes_sha512_oneshot_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClHmac/mcuxClHmac_Els_Oneshot_External_Key_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClHmac/mcuxClHmac_Sw_Oneshot_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClKey/mcuxClKey_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClMacModes/mcuxClMacModes_cbc_mac_multipart_zero_padding_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClMacModes/mcuxClMacModes_cbc_mac_oneshot_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClMacModes/mcuxClMacModes_cmac_oneshot_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClRandomModes/mcuxClRandomModes_CtrDrbg_AES256_DRG3_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClRandomModes/mcuxClRandomModes_CtrDrbg_AES256_DRG4_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClRandomModes/mcuxClRandomModes_CtrDrbg_AES256_ELS_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClRandomModes/mcuxClRandomModes_Different_Sessions_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClRandomModes/mcuxClRandomModes_PatchMode_CtrDrbg_AES256_DRG3_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClRandomModes/mcuxClRandomModes_TestMode_CtrDrbg_AES256_DRG4_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClRandomModes/mcuxClRandomModes_ELS_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClRsa/mcuxClRsa_sign_NoEncode_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClRsa/mcuxClRsa_sign_pss_sha2_256_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClRsa/mcuxClRsa_verify_NoVerify_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxClRsa/mcuxClRsa_verify_pssverify_sha2_256_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxCsslFlowProtection/mcuxCsslFlowProtection_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxCsslMemory/data_invariant_memory_compare.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxCsslMemory/data_invariant_memory_copy.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxCsslMemory/mcuxCsslMemory_Clear_example.c
    ${CMAKE_CURRENT_LIST_DIR}/mcuxCsslMemory/mcuxCsslMemory_Set_example.c
)

target_compile_options(${MCUX_SDK_PROJECT_NAME}
    PRIVATE
        $<$<C_COMPILER_ID:GNU>:-Wno-unused-variable>
        $<$<C_COMPILER_ID:ARMClang>:-Wno-unused-variable>
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/.
    ${CMAKE_CURRENT_LIST_DIR}/mcuxCsslFlowProtection/inc
    ${CMAKE_CURRENT_LIST_DIR}/mcuxCsslMemory/inc
    ${CMAKE_CURRENT_LIST_DIR}/../src/comps/mcuxClExample/inc
	"$<TARGET_PROPERTY:McuxElsPkc,INTERFACE_INCLUDE_DIRECTORIES>"
)

target_link_libraries(${MCUX_SDK_PROJECT_NAME}
    PUBLIC
        McuxElsPkc
)

