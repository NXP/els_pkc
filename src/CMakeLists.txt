
target_include_directories(
    McuxElsPkc 
    PUBLIC
        inc
        compiler

        comps/common/inc
        comps/mcuxClAead/inc
        comps/mcuxClAeadModes/inc
        comps/mcuxClAes/inc
        comps/mcuxClCipher/inc
        comps/mcuxClCipherModes/inc
        comps/mcuxClCore/inc
        comps/mcuxClEcc/inc
        comps/mcuxClEls/inc
        comps/mcuxClExample/inc
        comps/mcuxClHash/inc
        comps/mcuxClHashModes/inc
        comps/mcuxClHmac/inc
        comps/mcuxClKey/inc
        comps/mcuxClMac/inc
        comps/mcuxClMacModes/inc
        comps/mcuxClMath/inc
        comps/mcuxClMemory/inc
        comps/mcuxClOsccaPkc/inc
        comps/mcuxClOsccaSm3/inc
        comps/mcuxClPadding/inc
        comps/mcuxClPkc/inc
        comps/mcuxClPrng/inc
        comps/mcuxClPsaDriver/inc
        comps/mcuxClRandom/inc
        comps/mcuxClRandomModes/inc
        comps/mcuxClRsa/inc
        comps/mcuxClSession/inc
        comps/mcuxClTrng/inc
        comps/mcuxClTrng/inc/internal
        comps/mcuxCsslCPreProcessor/inc
        comps/mcuxCsslDataIntegrity/inc
        # comps/mcuxCsslFlowProtection/ex/inc
        comps/mcuxCsslFlowProtection/inc
        # comps/mcuxCsslMemory/ex/inc
        comps/mcuxCsslMemory/inc
        comps/mcuxCsslParamIntegrity/inc
        comps/mcuxCsslSecureCounter/inc

)

target_sources(
    McuxElsPkc 
    PRIVATE
        comps/common/src/mcuxClOscca_CommonOperations.c
        comps/mcuxClAead/src/mcuxClAead.c
        # comps/mcuxClAeadModes/ex/mcuxClAeadModes_Multipart_Els_Ccm_Example.c
        # comps/mcuxClAeadModes/ex/mcuxClAeadModes_Oneshot_Els_Ccm_Example.c
        # comps/mcuxClAeadModes/ex/mcuxClAeadModes_Oneshot_Els_Gcm_Example.c
        comps/mcuxClAeadModes/src/mcuxClAeadModes_Els_AesCcm.c
        comps/mcuxClAeadModes/src/mcuxClAeadModes_Els_AesGcm.c
        comps/mcuxClAeadModes/src/mcuxClAeadModes_Els_CcmEngineAes.c
        comps/mcuxClAeadModes/src/mcuxClAeadModes_Els_GcmEngineAes.c
        comps/mcuxClAeadModes/src/mcuxClAeadModes_Els_Modes.c
        comps/mcuxClAeadModes/src/mcuxClAeadModes_Els_Multipart.c
        comps/mcuxClAeadModes/src/mcuxClAeadModes_Els_Oneshot.c
        comps/mcuxClAeadModes/src/size/size.c
        comps/mcuxClAes/src/mcuxClAes_KeyTypes.c
        comps/mcuxClCipher/src/mcuxClCipher.c
        # comps/mcuxClCipherModes/ex/mcuxClCipherModes_Multipart_Cbc_Els_example.c
        # comps/mcuxClCipherModes/ex/mcuxClCipherModes_Multipart_Ctr_Els_example.c
        # comps/mcuxClCipherModes/ex/mcuxClCipherModes_Multipart_Ecb_Els_example.c
        # comps/mcuxClCipherModes/ex/mcuxClCipherModes_Multipart_Ecb_PaddingPKCS7_Els_example.c
        # comps/mcuxClCipherModes/ex/mcuxClCipherModes_Oneshot_Cbc_Els_example.c
        # comps/mcuxClCipherModes/ex/mcuxClCipherModes_Oneshot_Cbc_ZeroPadding_Els_example.c
        # comps/mcuxClCipherModes/ex/mcuxClCipherModes_Oneshot_Ctr_Els_example.c
        # comps/mcuxClCipherModes/ex/mcuxClCipherModes_Oneshot_Ecb_Els_example.c
        # comps/mcuxClCipherModes/ex/mcuxClCipherModes_Oneshot_Ecb_PaddingPKCS7_Els_example.c
        # comps/mcuxClCipherModes/ex/mcuxClCipherModes_Oneshot_Ecb_ZeroPadding_Els_example.c
        comps/mcuxClCipherModes/src/mcuxClCipherModes_Els_Aes.c
        comps/mcuxClCipherModes/src/mcuxClCipherModes_Els_EngineAes.c
        comps/mcuxClCipherModes/src/mcuxClCipherModes_Helper.c
        comps/mcuxClCipherModes/src/mcuxClCipherModes_Modes.c
        comps/mcuxClCipherModes/src/size/size.c
        # comps/mcuxClEcc/ex/mcuxClEcc_EdDSA_Ed25519_example.c
        # comps/mcuxClEcc/ex/mcuxClEcc_EdDSA_Ed25519ctx_example.c
        # comps/mcuxClEcc/ex/mcuxClEcc_EdDSA_Ed25519ph_example.c
        # comps/mcuxClEcc/ex/mcuxClEcc_EdDSA_GenerateSignature_Ed25519_example.c
        # comps/mcuxClEcc/ex/mcuxClEcc_EdDSA_VerifySignature_Ed25519_example.c
        # comps/mcuxClEcc/ex/mcuxClEcc_Mont_Curve25519_example.c
        # comps/mcuxClEcc/ex/mcuxClEcc_Mont_Curve448_example.c
        # comps/mcuxClEcc/ex/mcuxClEcc_WeierECC_CustomEccWeierType_BN256_example.c
        comps/mcuxClEcc/src/mcuxClEcc_Constants.c
        comps/mcuxClEcc/src/mcuxClEcc_EdDSA_GenerateKeyPair.c
        comps/mcuxClEcc/src/mcuxClEcc_EdDSA_GenerateKeyPair_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_EdDSA_GenerateSignature.c
        comps/mcuxClEcc/src/mcuxClEcc_EdDSA_GenerateSignatureMode.c
        comps/mcuxClEcc/src/mcuxClEcc_EdDSA_GenerateSignature_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_EdDSA_InitPrivKeyInputMode.c
        comps/mcuxClEcc/src/mcuxClEcc_EdDSA_Internal_CalcHashModN.c
        comps/mcuxClEcc/src/mcuxClEcc_EdDSA_Internal_CalcHashModN_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_EdDSA_Internal_DecodePoint_Ed25519.c
        comps/mcuxClEcc/src/mcuxClEcc_EdDSA_Internal_DecodePoint_Ed448.c
        comps/mcuxClEcc/src/mcuxClEcc_EdDSA_Internal_DecodePoint_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_EdDSA_Internal_SetupEnvironment.c
        comps/mcuxClEcc/src/mcuxClEcc_EdDSA_Internal_SignatureMechanisms.c
        comps/mcuxClEcc/src/mcuxClEcc_EdDSA_VerifySignature.c
        comps/mcuxClEcc/src/mcuxClEcc_Internal_BlindedScalarMult.c
        comps/mcuxClEcc/src/mcuxClEcc_Internal_Convert_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_Internal_GenerateMultiplicativeBlinding.c
        comps/mcuxClEcc/src/mcuxClEcc_Internal_InterleaveScalar.c
        comps/mcuxClEcc/src/mcuxClEcc_Internal_InterleaveTwoScalars.c
        comps/mcuxClEcc/src/mcuxClEcc_Internal_Interleave_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_Internal_PointComparison_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_Internal_RecodeAndReorderScalar.c
        comps/mcuxClEcc/src/mcuxClEcc_Internal_SetupEnvironment.c
        comps/mcuxClEcc/src/mcuxClEcc_Internal_SetupEnvironment_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_Internal_Types.c
        comps/mcuxClEcc/src/mcuxClEcc_KeyTypes.c
        comps/mcuxClEcc/src/mcuxClEcc_Mont_DhKeyAgreement.c
        comps/mcuxClEcc/src/mcuxClEcc_Mont_DhKeyGeneration.c
        comps/mcuxClEcc/src/mcuxClEcc_Mont_Internal_DhSetupEnvironment.c
        comps/mcuxClEcc/src/mcuxClEcc_Mont_Internal_MontDhX.c
        comps/mcuxClEcc/src/mcuxClEcc_Mont_Internal_MontDhX_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_Mont_Internal_SecureScalarMult_XZMontLadder.c
        comps/mcuxClEcc/src/mcuxClEcc_Mont_Internal_SecureScalarMult_XZMontLadder_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_SignatureMechanisms.c
        comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_FixScalarMult.c
        comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_PlainFixScalarMult25519.c
        comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_PlainPtrSelectComb.c
        comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_PlainPtrSelectML.c
        comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_PlainVarScalarMult.c
        comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_PointArithmeticEd25519.c
        comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_PointArithmeticEd25519_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_PointSubtraction_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_PointValidation_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_PrecPointImportAndValidate.c
        comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_VarScalarMult.c
        comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_VarScalarMult_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_WeierECC_Internal_GenerateCustomKeyType.c
        comps/mcuxClEcc/src/mcuxClEcc_WeierECC_Internal_GenerateDomainParams.c
        comps/mcuxClEcc/src/mcuxClEcc_WeierECC_Internal_GenerateDomainParams_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_WeierECC_Internal_SetupEnvironment.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_ConvertPoint_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_KeyGen.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_KeyGen_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_PointArithmetic.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_PointArithmetic_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_PointCheck.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_PointCheck_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_PointMult.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_SecurePointMult_CoZMontLadder.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_SecurePointMult_CoZMontLadder_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_SetupEnvironment.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_KeyGen.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_KeyGen_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_PointMult.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_PointMult_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_Sign.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_Sign_FUP.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_Verify.c
        comps/mcuxClEcc/src/mcuxClEcc_Weier_Verify_FUP.c
        comps/mcuxClEcc/src/size/size.c
        # comps/mcuxClEls/ex/mcuxClEls_Cipher_Aes128_Cbc_Encrypt_example.c
        # comps/mcuxClEls/ex/mcuxClEls_Cipher_Aes128_Ecb_Encrypt_example.c
        # comps/mcuxClEls/ex/mcuxClEls_Common_Get_Info_example.c
        # comps/mcuxClEls/ex/mcuxClEls_Ecc_Keygen_Sign_Verify_example.c
        # comps/mcuxClEls/ex/mcuxClEls_Hash_HW_Security_Counter_example.c
        # comps/mcuxClEls/ex/mcuxClEls_Hash_Sha224_One_Block_example.c
        # comps/mcuxClEls/ex/mcuxClEls_Hash_Sha256_One_Block_example.c
        # comps/mcuxClEls/ex/mcuxClEls_Hash_Sha384_One_Block_example.c
        # comps/mcuxClEls/ex/mcuxClEls_Hash_Sha512_One_Block_example.c
        # comps/mcuxClEls/ex/mcuxClEls_Key_Import_Puk_DER_example.c
        # comps/mcuxClEls/ex/mcuxClEls_Rng_Prng_Get_Random_example.c
        # comps/mcuxClEls/ex/mcuxClEls_Tls_Master_Key_Session_Keys_example.c
        comps/mcuxClEls/src/mcuxClEls_Aead.c
        comps/mcuxClEls/src/mcuxClEls_Cipher.c
        comps/mcuxClEls/src/mcuxClEls_Cmac.c
        comps/mcuxClEls/src/mcuxClEls_Common.c
        comps/mcuxClEls/src/mcuxClEls_Crc.c
        comps/mcuxClEls/src/mcuxClEls_Ecc.c
        comps/mcuxClEls/src/mcuxClEls_GlitchDetector.c
        comps/mcuxClEls/src/mcuxClEls_Hash.c
        comps/mcuxClEls/src/mcuxClEls_Hmac.c
        comps/mcuxClEls/src/mcuxClEls_Kdf.c
        comps/mcuxClEls/src/mcuxClEls_KeyManagement.c
        comps/mcuxClEls/src/mcuxClEls_Rng.c
        comps/mcuxClHash/src/mcuxClHash_api_multipart_common.c
        comps/mcuxClHash/src/mcuxClHash_api_multipart_compute.c
        comps/mcuxClHash/src/mcuxClHash_api_oneshot_compute.c
        comps/mcuxClHash/src/size/size.c
        # comps/mcuxClHashModes/ex/mcuxClHashModes_sha224_oneshot_example.c
        # comps/mcuxClHashModes/ex/mcuxClHashModes_sha256_longMsgOneshot_example.c
        # comps/mcuxClHashModes/ex/mcuxClHashModes_sha256_oneshot_example.c
        # comps/mcuxClHashModes/ex/mcuxClHashModes_sha256_streaming_example.c
        # comps/mcuxClHashModes/ex/mcuxClHashModes_sha384_oneshot_example.c
        # comps/mcuxClHashModes/ex/mcuxClHashModes_sha512_oneshot_example.c
        comps/mcuxClHashModes/src/mcuxClHashModes_Core_els_sha2.c
        comps/mcuxClHashModes/src/mcuxClHashModes_Internal_els_sha2.c
        comps/mcuxClHashModes/src/size/size.c
        # comps/mcuxClHmac/ex/mcuxClHmac_Els_Oneshot_External_Key_example.c
        # comps/mcuxClHmac/ex/mcuxClHmac_Sw_Oneshot_example.c
        comps/mcuxClHmac/src/mcuxClHmac_Els.c
        comps/mcuxClHmac/src/mcuxClHmac_Functions.c
        comps/mcuxClHmac/src/mcuxClHmac_Helper.c
        comps/mcuxClHmac/src/mcuxClHmac_KeyTypes.c
        comps/mcuxClHmac/src/mcuxClHmac_Modes.c
        comps/mcuxClHmac/src/mcuxClHmac_Sw.c
        comps/mcuxClHmac/src/size/size.c
        # comps/mcuxClKey/ex/mcuxClKey_example.c
        comps/mcuxClKey/src/mcuxClKey.c
        comps/mcuxClKey/src/mcuxClKey_Protection.c
        comps/mcuxClKey/src/size/size.c
        comps/mcuxClMac/src/mcuxClMac.c
        # comps/mcuxClMacModes/ex/mcuxClMacModes_cbc_mac_multipart_zero_padding_example.c
        # comps/mcuxClMacModes/ex/mcuxClMacModes_cbc_mac_oneshot_example.c
        # comps/mcuxClMacModes/ex/mcuxClMacModes_cmac_oneshot_example.c
        comps/mcuxClMacModes/src/mcuxClMacModes.c
        comps/mcuxClMacModes/src/mcuxClMacModes_Els_Cbcmac.c
        comps/mcuxClMacModes/src/mcuxClMacModes_Els_Cmac.c
        comps/mcuxClMacModes/src/mcuxClMacModes_Els_Functions.c
        comps/mcuxClMacModes/src/mcuxClMacModes_Modes.c
        comps/mcuxClMacModes/src/size/size.c
        comps/mcuxClMath/src/mcuxClMath_ExactDivide.c
        comps/mcuxClMath/src/mcuxClMath_ExactDivideOdd.c
        comps/mcuxClMath/src/mcuxClMath_ExactDivideOdd_FUP.c
        comps/mcuxClMath/src/mcuxClMath_ModExp_SqrMultL2R.c
        comps/mcuxClMath/src/mcuxClMath_ModInv.c
        comps/mcuxClMath/src/mcuxClMath_ModInv_FUP.c
        comps/mcuxClMath/src/mcuxClMath_NDash.c
        comps/mcuxClMath/src/mcuxClMath_NDash_FUP.c
        comps/mcuxClMath/src/mcuxClMath_QDash.c
        comps/mcuxClMath/src/mcuxClMath_QDash_FUP.c
        comps/mcuxClMath/src/mcuxClMath_ReduceModEven.c
        comps/mcuxClMath/src/mcuxClMath_SecModExp.c
        comps/mcuxClMath/src/mcuxClMath_SecModExp_FUP.c
        comps/mcuxClMath/src/mcuxClMath_Utils.c
        comps/mcuxClMemory/src/mcuxClMemory.c
        # comps/mcuxClOsccaPkc/src/mcuxClOsccaPkc.c
        # comps/mcuxClOsccaSm3/ex/mcuxClOsccaSm3_oneshot_example.c
        # comps/mcuxClOsccaSm3/ex/mcuxClOsccaSm3_streaming_example.c
        # comps/mcuxClOsccaSm3/src/mcuxClOsccaSm3_core_sm3.c
        # comps/mcuxClOsccaSm3/src/mcuxClOsccaSm3_internal_sm3.c
        # comps/mcuxClOsccaSm3/src/size/size.c
        comps/mcuxClPadding/src/mcuxClPadding.c
        comps/mcuxClPkc/src/mcuxClPkc_Calculate.c
        comps/mcuxClPkc/src/mcuxClPkc_ImportExport.c
        comps/mcuxClPkc/src/mcuxClPkc_Initialize.c
        comps/mcuxClPkc/src/mcuxClPkc_UPTRT.c
        comps/mcuxClPrng/src/mcuxClPrng_ELS.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_aead_ccm_multipart_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_aead_ccm_oneshot_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_aead_gcm_multipart_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_aead_gcm_oneshot_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_aes_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_cipher_decrypt.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_cipher_multipart_CBC.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_cipher_multipart_CTR.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_cipher_multipart_ECB.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_eccsecp224k1_sign_verify_hash_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_ecdsa_keygen_oracleMemory_sign_verify_hash_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_ecdsa_keygen_oracleS50_sign_verify_hash_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_ecdsa_sign_verify_hash_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_ecdsa_sign_verify_message_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_keygen_export_public_key_brainpoolpr1_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_keygen_export_public_key_mont_curve25519_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_keygen_export_public_key_oracle_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_keygen_export_public_key_rsa_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_keygen_export_public_key_secpk1_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_keygen_export_public_key_secpr1_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_mac_oneshot_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_mac_sign_multipart_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_mac_verify_multipart_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_rsa_PKCS1V15_sign_verify_message_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_rsa_PSS_sign_verify_hash_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_sha224_oneshot_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_sha256_abort_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_sha256_clone_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_sha256_multipart_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_sha256_oneshot_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_sha384_oneshot_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_sha512_oneshot_example.c
        # comps/mcuxClPsaDriver/ex/mcuxClPsaDriver_truncated_mac_oneshot_example.c

        # TODO: excluded from build, requires upated in mbedtls
        # comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Aead.c
        # comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Cipher.c
        # comps/mcuxClPsaDriver/src/mcuxClPsaDriver_DER_functions.c
        # comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Hash.c
        # comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Key.c
        # comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Mac.c
        # comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Rsa.c
        # comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Sign.c
        # comps/mcuxClPsaDriver/src/mcuxClPsaDriver_UpdateKeyStatus.c
        # comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Verify.c
        # comps/mcuxClPsaDriver/src/mcuxClPsaDriver_export_public_key.c
        # comps/mcuxClPsaDriver/src/mcuxClPsaDriver_generate_ecp_key.c
        # comps/mcuxClPsaDriver/src/psa_crypto_driver_wrappers.c
        # comps/mcuxClPsaDriver/src/size/size.c

        comps/mcuxClRandom/src/mcuxClRandom_DRBG.c
        comps/mcuxClRandom/src/mcuxClRandom_PRNG.c
        # comps/mcuxClRandomModes/ex/mcuxClRandomModes_CtrDrbg_AES256_DRG3_example.c
        # comps/mcuxClRandomModes/ex/mcuxClRandomModes_CtrDrbg_AES256_DRG4_example.c
        # comps/mcuxClRandomModes/ex/mcuxClRandomModes_CtrDrbg_AES256_ELS_example.c
        # comps/mcuxClRandomModes/ex/mcuxClRandomModes_Different_Sessions_example.c
        # comps/mcuxClRandomModes/ex/mcuxClRandomModes_ELS_example.c
        # comps/mcuxClRandomModes/ex/mcuxClRandomModes_PatchMode_CtrDrbg_AES256_DRG3_example.c
        # comps/mcuxClRandomModes/ex/mcuxClRandomModes_TestMode_CtrDrbg_AES256_DRG4_example.c
        # comps/mcuxClRandomModes/ex/mcuxClRandomModes_TestMode_CtrDrbg_AES256_PTG3_example.c
        comps/mcuxClRandomModes/src/mcuxClRandomModes_CtrDrbg.c
        comps/mcuxClRandomModes/src/mcuxClRandomModes_CtrDrbg_Els.c
        comps/mcuxClRandomModes/src/mcuxClRandomModes_CtrDrbg_PrDisabled.c
        comps/mcuxClRandomModes/src/mcuxClRandomModes_ElsMode.c
        comps/mcuxClRandomModes/src/mcuxClRandomModes_NormalMode.c
        comps/mcuxClRandomModes/src/mcuxClRandomModes_PatchMode.c
        comps/mcuxClRandomModes/src/mcuxClRandomModes_PrDisabled.c
        comps/mcuxClRandomModes/src/mcuxClRandomModes_TestMode.c
        comps/mcuxClRandomModes/src/size/size.c
        # comps/mcuxClRsa/ex/mcuxClRsa_sign_NoEncode_example.c
        # comps/mcuxClRsa/ex/mcuxClRsa_sign_pss_sha2_256_example.c
        # comps/mcuxClRsa/ex/mcuxClRsa_verify_NoVerify_example.c
        # comps/mcuxClRsa/ex/mcuxClRsa_verify_pssverify_sha2_256_example.c
        comps/mcuxClRsa/src/mcuxClRsa_ComputeD.c
        comps/mcuxClRsa/src/mcuxClRsa_ComputeD_FUP.c
        comps/mcuxClRsa/src/mcuxClRsa_GenerateProbablePrime.c
        comps/mcuxClRsa/src/mcuxClRsa_KeyGeneration_Crt.c
        comps/mcuxClRsa/src/mcuxClRsa_KeyGeneration_Crt_FUP.c
        comps/mcuxClRsa/src/mcuxClRsa_KeyGeneration_Plain.c
        comps/mcuxClRsa/src/mcuxClRsa_Mgf1.c
        comps/mcuxClRsa/src/mcuxClRsa_MillerRabinTest.c
        comps/mcuxClRsa/src/mcuxClRsa_MillerRabinTest_FUP.c
        comps/mcuxClRsa/src/mcuxClRsa_ModInv.c
        comps/mcuxClRsa/src/mcuxClRsa_NoEncode.c
        comps/mcuxClRsa/src/mcuxClRsa_NoVerify.c
        comps/mcuxClRsa/src/mcuxClRsa_Pkcs1v15Encode_sign.c
        comps/mcuxClRsa/src/mcuxClRsa_Pkcs1v15Verify.c
        comps/mcuxClRsa/src/mcuxClRsa_PrivateCrt.c
        comps/mcuxClRsa/src/mcuxClRsa_PrivateCrt_FUP.c
        comps/mcuxClRsa/src/mcuxClRsa_PrivatePlain.c
        comps/mcuxClRsa/src/mcuxClRsa_PssEncode.c
        comps/mcuxClRsa/src/mcuxClRsa_PssVerify.c
        comps/mcuxClRsa/src/mcuxClRsa_Public.c
        comps/mcuxClRsa/src/mcuxClRsa_Public_FUP.c
        comps/mcuxClRsa/src/mcuxClRsa_RemoveBlinding.c
        comps/mcuxClRsa/src/mcuxClRsa_RemoveBlinding_FUP.c
        comps/mcuxClRsa/src/mcuxClRsa_Sign.c
        comps/mcuxClRsa/src/mcuxClRsa_TestPQDistance.c
        comps/mcuxClRsa/src/mcuxClRsa_TestPQDistance_FUP.c
        comps/mcuxClRsa/src/mcuxClRsa_TestPrimeCandidate.c
        comps/mcuxClRsa/src/mcuxClRsa_TestPrimeCandidate_FUP.c
        comps/mcuxClRsa/src/mcuxClRsa_Verify.c
        comps/mcuxClRsa/src/mcuxClRsa_VerifyE.c
        comps/mcuxClRsa/src/size/size.c
        comps/mcuxClSession/src/mcuxClSession.c
        comps/mcuxClSession/src/size/size.c

        # comps/mcuxClTrng/src/mcuxClTrng_ELS.c
        comps/mcuxClTrng/src/mcuxClTrng_SA_TRNG.c

        # comps/mcuxCsslFlowProtection/ex/mcuxCsslFlowProtection_example.c
        # comps/mcuxCsslMemory/ex/data_invariant_memory_compare.c
        # comps/mcuxCsslMemory/ex/data_invariant_memory_copy.c
        # comps/mcuxCsslMemory/ex/mcuxCsslMemory_Clear_example.c
        # comps/mcuxCsslMemory/ex/mcuxCsslMemory_Set_example.c
        comps/mcuxCsslMemory/src/mcuxCsslMemory_Clear.c
        comps/mcuxCsslMemory/src/mcuxCsslMemory_Compare.c
        comps/mcuxCsslMemory/src/mcuxCsslMemory_Copy.c
        comps/mcuxCsslMemory/src/mcuxCsslMemory_Internal_SecureCompare_Stub.c
        comps/mcuxCsslMemory/src/mcuxCsslMemory_Set.c
        comps/mcuxCsslParamIntegrity/src/mcuxCsslParamIntegrity.c
        # platforms/lpc/mcux_els.c
        # platforms/lpc/mcux_pkc.c
        # platforms/mcxn/mcux_els.c
        # platforms/mcxn/mcux_pkc.c

        src/mcuxCl_clns.c
)
