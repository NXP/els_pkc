
if (CONFIG_MCUX_COMPONENT_component.els_pkc.doc.lpc)
    mcux_add_source(
        SOURCES LICENSE.htm
                # TODO please change to relative dir
                softwareContentRegister.txt
                # TODO please change to relative dir
                ReleaseNotes.txt
                # TODO please change to relative dir
                doc/lpc_release/**
    )
    mcux_add_include(
        INCLUDES ./
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.doc.mcxn)
    mcux_add_source(
        SOURCES LICENSE.htm
                # TODO please change to relative dir
                softwareContentRegister.txt
                # TODO please change to relative dir
                ReleaseNotes.txt
                # TODO please change to relative dir
                doc/mcxn_release/**
    )
    mcux_add_include(
        INCLUDES ./
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.doc.rw61x)
    mcux_add_source(
        SOURCES LICENSE.htm
                # TODO please change to relative dir
                softwareContentRegister.txt
                # TODO please change to relative dir
                ReleaseNotes.txt
                # TODO please change to relative dir
                doc/rw61x_release/**
    )
    mcux_add_include(
        INCLUDES ./
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.doc.mimxrt)
    mcux_add_source(
        SOURCES LICENSE.htm
                # TODO please change to relative dir
                softwareContentRegister.txt
                # TODO please change to relative dir
                ReleaseNotes.txt
                # TODO please change to relative dir
                doc/mimxrt/**
    )
    mcux_add_include(
        INCLUDES ./
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.static_lib.mcxn)
    mcux_add_source(
        SOURCES static_library/mcxn/libclns.a
                # TODO please change to relative dir
                static_library/mcxn/libclns.a.libsize
                # TODO please change to relative dir
                static_library/mcxn/libclns.a.objsize
                # TODO please change to relative dir
                static_library/mcxn/libclns.stripped.a
    )
    mcux_add_include(
        INCLUDES ./
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.static_lib.rw61x)
    mcux_add_source(
        SOURCES static_library/rw61x/libclns.a
                # TODO please change to relative dir
                static_library/rw61x/libclns.a.libsize
                # TODO please change to relative dir
                static_library/rw61x/libclns.a.objsize
                # TODO please change to relative dir
                static_library/rw61x/libclns.stripped.a
    )
    mcux_add_include(
        INCLUDES ./
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.static_lib.lpc)
    mcux_add_source(
        SOURCES static_library/lpc/libclns.a
                # TODO please change to relative dir
                static_library/lpc/libclns.a.libsize
                # TODO please change to relative dir
                static_library/lpc/libclns.a.objsize
                # TODO please change to relative dir
                static_library/lpc/libclns.stripped.a
    )
    mcux_add_include(
        INCLUDES ./
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.static_lib.mimxrt)
    mcux_add_source(
        SOURCES static_library/mimxrt/libclns.a
                # TODO please change to relative dir
                static_library/mimxrt/libclns.a.libsize
                # TODO please change to relative dir
                static_library/mimxrt/libclns.a.objsize
                # TODO please change to relative dir
                static_library/mimxrt/libclns.stripped.a
    )
    mcux_add_include(
        INCLUDES ./
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.common)
    mcux_add_source(
        SOURCES src/comps/common/src/mcuxClOscca_CommonOperations.c
                # TODO please change to relative dir
                src/comps/common/inc/mcuxClOscca_FunctionIdentifiers.h
                # TODO please change to relative dir
                src/comps/common/inc/mcuxClOscca_Memory.h
                # TODO please change to relative dir
                src/comps/common/inc/mcuxClOscca_PlatformTypes.h
                # TODO please change to relative dir
                src/comps/common/inc/mcuxClOscca_Types.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/common/inc
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.aead)
    mcux_add_source(
        SOURCES src/comps/mcuxClAead/src/mcuxClAead.c
                # TODO please change to relative dir
                src/comps/mcuxClAead/inc/mcuxClAead.h
                # TODO please change to relative dir
                src/comps/mcuxClAead/inc/mcuxClAead_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClAead/inc/mcuxClAead_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClAead/inc/mcuxClAead_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClAead/inc/internal/mcuxClAead_Ctx.h
                # TODO please change to relative dir
                src/comps/mcuxClAead/inc/internal/mcuxClAead_Descriptor.h
                # TODO please change to relative dir
                src/comps/mcuxClAead/inc/internal/mcuxClAead_Internal_Functions.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClAead/inc
                 src/comps/mcuxClAead/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.aead_modes)
    mcux_add_source(
        SOURCES src/comps/mcuxClAeadModes/src/mcuxClAeadModes_Els_AesCcm.c
                # TODO please change to relative dir
                src/comps/mcuxClAeadModes/src/mcuxClAeadModes_Els_AesCcmEngine.c
                # TODO please change to relative dir
                src/comps/mcuxClAeadModes/src/mcuxClAeadModes_Els_AesGcm.c
                # TODO please change to relative dir
                src/comps/mcuxClAeadModes/src/mcuxClAeadModes_Els_AesGcmEngine.c
                # TODO please change to relative dir
                src/comps/mcuxClAeadModes/src/mcuxClAeadModes_Els_Modes.c
                # TODO please change to relative dir
                src/comps/mcuxClAeadModes/src/mcuxClAeadModes_Els_Multipart.c
                # TODO please change to relative dir
                src/comps/mcuxClAeadModes/src/mcuxClAeadModes_Els_Oneshot.c
                # TODO please change to relative dir
                src/comps/mcuxClAeadModes/inc/mcuxClAeadModes.h
                # TODO please change to relative dir
                src/comps/mcuxClAeadModes/inc/mcuxClAeadModes_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClAeadModes/inc/mcuxClAeadModes_Modes.h
                # TODO please change to relative dir
                src/comps/mcuxClAeadModes/inc/internal/mcuxClAeadModes_Common.h
                # TODO please change to relative dir
                src/comps/mcuxClAeadModes/inc/internal/mcuxClAeadModes_Common_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClAeadModes/inc/internal/mcuxClAeadModes_Common_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClAeadModes/inc/internal/mcuxClAeadModes_Els_Algorithms.h
                # TODO please change to relative dir
                src/comps/mcuxClAeadModes/inc/internal/mcuxClAeadModes_Els_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClAeadModes/inc/internal/mcuxClAeadModes_Els_Types.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClAeadModes/inc
                 src/comps/mcuxClAeadModes/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.aes)
    mcux_add_source(
        SOURCES src/comps/mcuxClAes/src/mcuxClAes_KeyTypes.c
                # TODO please change to relative dir
                src/comps/mcuxClAes/inc/mcuxClAes.h
                # TODO please change to relative dir
                src/comps/mcuxClAes/inc/mcuxClAes_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClAes/inc/mcuxClAes_KeyTypes.h
                # TODO please change to relative dir
                src/comps/mcuxClAes/inc/mcuxClAes_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClAes/inc/internal/mcuxClAes_Ctx.h
                # TODO please change to relative dir
                src/comps/mcuxClAes/inc/internal/mcuxClAes_Internal_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClAes/inc/internal/mcuxClAes_Internal_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClAes/inc/internal/mcuxClAes_Wa.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClAes/inc
                 src/comps/mcuxClAes/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.buffer)
    mcux_add_source(
        SOURCES src/comps/mcuxClBuffer/src/mcuxClBuffer.c
                # TODO please change to relative dir
                src/comps/mcuxClBuffer/inc/mcuxClBuffer.h
                # TODO please change to relative dir
                src/comps/mcuxClBuffer/inc/mcuxClBuffer_Cfg.h
                # TODO please change to relative dir
                src/comps/mcuxClBuffer/inc/mcuxClBuffer_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClBuffer/inc/mcuxClBuffer_Impl.h
                # TODO please change to relative dir
                src/comps/mcuxClBuffer/inc/mcuxClBuffer_Pointer.h
                # TODO please change to relative dir
                src/comps/mcuxClBuffer/inc/internal/mcuxClBuffer_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClBuffer/inc/internal/mcuxClBuffer_Internal_Pointer.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClBuffer/inc
                 src/comps/mcuxClBuffer/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.cipher)
    mcux_add_source(
        SOURCES src/comps/mcuxClCipher/src/mcuxClCipher.c
                # TODO please change to relative dir
                src/comps/mcuxClCipher/inc/mcuxClCipher.h
                # TODO please change to relative dir
                src/comps/mcuxClCipher/inc/mcuxClCipher_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClCipher/inc/mcuxClCipher_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClCipher/inc/mcuxClCipher_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClCipher/inc/internal/mcuxClCipher_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClCipher/inc/internal/mcuxClCipher_Internal_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClCipher/inc/internal/mcuxClCipher_Internal_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClCipher/inc/internal/mcuxClCipher_Internal_Types.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClCipher/inc
                 src/comps/mcuxClCipher/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.cipher_modes)
    mcux_add_source(
        SOURCES src/comps/mcuxClCipherModes/src/mcuxClCipherModes_Common_Helper.c
                # TODO please change to relative dir
                src/comps/mcuxClCipherModes/src/mcuxClCipherModes_Crypt_Els_Modes.c
                # TODO please change to relative dir
                src/comps/mcuxClCipherModes/src/mcuxClCipherModes_Els_Aes.c
                # TODO please change to relative dir
                src/comps/mcuxClCipherModes/src/mcuxClCipherModes_Els_AesEngine.c
                # TODO please change to relative dir
                src/comps/mcuxClCipherModes/src/mcuxClCipherModes_Els_Aes_Internal.c
                # TODO please change to relative dir
                src/comps/mcuxClCipherModes/inc/mcuxClCipherModes.h
                # TODO please change to relative dir
                src/comps/mcuxClCipherModes/inc/mcuxClCipherModes_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClCipherModes/inc/mcuxClCipherModes_Modes.h
                # TODO please change to relative dir
                src/comps/mcuxClCipherModes/inc/internal/mcuxClCipherModes_Common.h
                # TODO please change to relative dir
                src/comps/mcuxClCipherModes/inc/internal/mcuxClCipherModes_Common_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClCipherModes/inc/internal/mcuxClCipherModes_Common_Helper.h
                # TODO please change to relative dir
                src/comps/mcuxClCipherModes/inc/internal/mcuxClCipherModes_Common_Wa.h
                # TODO please change to relative dir
                src/comps/mcuxClCipherModes/inc/internal/mcuxClCipherModes_Els_Algorithms.h
                # TODO please change to relative dir
                src/comps/mcuxClCipherModes/inc/internal/mcuxClCipherModes_Els_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClCipherModes/inc/internal/mcuxClCipherModes_Els_Types.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClCipherModes/inc
                 src/comps/mcuxClCipherModes/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.core)
    mcux_add_source(
        SOURCES src/comps/mcuxClCore/inc/mcuxClCore_Examples.h
                # TODO please change to relative dir
                src/comps/mcuxClCore/inc/mcuxClCore_FunctionIdentifiers.h
                # TODO please change to relative dir
                src/comps/mcuxClCore/inc/mcuxClCore_Macros.h
                # TODO please change to relative dir
                src/comps/mcuxClCore/inc/mcuxClCore_Platform.h
                # TODO please change to relative dir
                src/comps/mcuxClCore/inc/mcuxClCore_Toolchain.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClCore/inc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.crc)
    mcux_add_source(
        SOURCES src/comps/mcuxClCrc/src/mcuxClCrc.c
                # TODO please change to relative dir
                src/comps/mcuxClCrc/src/mcuxClCrc_Sw.c
                # TODO please change to relative dir
                src/comps/mcuxClCrc/inc/mcuxClCrc.h
                # TODO please change to relative dir
                src/comps/mcuxClCrc/inc/internal/mcuxClCrc_Internal_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClCrc/inc/internal/mcuxClCrc_Internal_Functions.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClCrc/inc
                 src/comps/mcuxClCrc/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.ecc_deterministic)
    mcux_add_source(
        SOURCES src/comps/mcuxClEcc/src/mcuxClEcc_DeterministicECDSA.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_DeterministicECDSA_Internal_BlindedSecretKeyGen.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_DeterministicECDSA_Internal_BlindedSecretKeyGen_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_DeterministicECDSA_Internal_BlindedSecretKeyGen_FUP.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClEcc/inc/
                 src/comps/mcuxClEcc/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.ecc)
    mcux_add_source(
        SOURCES src/comps/mcuxClEcc/src/mcuxClEcc_Constants.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_EdDSA_GenerateKeyPair.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_EdDSA_GenerateKeyPair_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_EdDSA_GenerateSignature.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_EdDSA_GenerateSignatureMode.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_EdDSA_GenerateSignature_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_EdDSA_InitPrivKeyInputMode.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_EdDSA_Internal_CalcHashModN.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_EdDSA_Internal_CalcHashModN_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_EdDSA_Internal_DecodePoint_Ed25519.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_EdDSA_Internal_DecodePoint_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_EdDSA_Internal_SetupEnvironment.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_EdDSA_Internal_SignatureMechanisms.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_EdDSA_VerifySignature.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Internal_BlindedScalarMult.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Internal_Convert_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Internal_GenerateMultiplicativeBlinding.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Internal_InterleaveScalar.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Internal_InterleaveTwoScalars.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Internal_Interleave_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Internal_PointComparison_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Internal_RecodeAndReorderScalar.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Internal_SetupEnvironment.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Internal_SetupEnvironment_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Internal_Types.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_KeyTypes.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_MontDH_GenerateKeyPair.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_MontDH_KeyAgreement.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Mont_Internal_DhSetupEnvironment.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Mont_Internal_MontDhX.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Mont_Internal_MontDhX_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Mont_Internal_SecureScalarMult_XZMontLadder.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Mont_Internal_SecureScalarMult_XZMontLadder_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_FixScalarMult.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_PlainFixScalarMult25519.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_PlainPtrSelectComb.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_PlainPtrSelectML.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_PlainVarScalarMult.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_PointArithmeticEd25519.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_PointArithmeticEd25519_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_PointSubtraction_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_PointValidation_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_PrecPointImportAndValidate.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_VarScalarMult.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_TwEd_Internal_VarScalarMult_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_WeierECC_Internal_BlindedSecretKeyGen.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_WeierECC_Internal_BlindedSecretKeyGen_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_WeierECC_Internal_GenerateKeyPair.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_WeierECC_Internal_KeyAgreement_ECDH.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_WeierECC_Internal_SetupEnvironment.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_ConvertPoint_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_PointArithmetic.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_PointArithmetic_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_PointCheck.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_PointCheck_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_PointMult.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_SecurePointMult_CoZMontLadder.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_SecurePointMult_CoZMontLadder_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Weier_Internal_SetupEnvironment.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Weier_KeyGen.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Weier_KeyGen_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Weier_PointMult.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Weier_PointMult_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Weier_Sign.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Weier_Sign_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Weier_Verify.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/src/mcuxClEcc_Weier_Verify_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_EdDSA_GenerateKeyPair_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_EdDSA_GenerateSignature_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_EdDSA_Internal_CalcHashModN_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_EdDSA_Internal_DecodePoint_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_Internal_Convert_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_Internal_Interleave_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_Internal_PointComparison_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_Internal_SetupEnvironment_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_KeyTypes.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_Mont_Internal_MontDhX_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_Mont_Internal_SecureScalarMult_XZMontLadder_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_TwEd_Internal_PointArithmeticEd25519_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_TwEd_Internal_PointSubtraction_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_TwEd_Internal_PointValidation_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_TwEd_Internal_VarScalarMult_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_WeierECC_Internal_BlindedSecretKeyGen_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_Weier_Internal_ConvertPoint_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_Weier_Internal_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_Weier_Internal_PointArithmetic_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_Weier_Internal_PointCheck_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_Weier_Internal_SecurePointMult_CoZMontLadder_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_Weier_KeyGen_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_Weier_PointMult_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_Weier_Sign_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/mcuxClEcc_Weier_Verify_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_ECDH_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_ECDSA_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_ECDSA_Internal_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_EdDSA_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_EdDSA_Internal_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_EdDSA_Internal_Hash.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_Internal_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_Internal_PkcWaLayout.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_Internal_Random.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_Internal_SecurePointSelect.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_Internal_UPTRT_access.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_Mont_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_Mont_Internal_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_Mont_Internal_PkcWaLayout.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_TwEd_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_TwEd_Internal_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_TwEd_Internal_PkcWaLayout.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_WeierEcc_KeyGenerate_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_Weier_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_Weier_Internal_FP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_Weier_Internal_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClEcc/inc/internal/mcuxClEcc_Weier_Internal_PkcWaLayout.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClEcc/inc/
                 src/comps/mcuxClEcc/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.els_header_only)
    mcux_add_source(
        SOURCES src/comps/mcuxClEls/inc/mcuxClEls.h
                # TODO please change to relative dir
                src/comps/mcuxClEls/inc/mcuxClEls_Aead.h
                # TODO please change to relative dir
                src/comps/mcuxClEls/inc/mcuxClEls_Cipher.h
                # TODO please change to relative dir
                src/comps/mcuxClEls/inc/mcuxClEls_Cmac.h
                # TODO please change to relative dir
                src/comps/mcuxClEls/inc/mcuxClEls_Crc.h
                # TODO please change to relative dir
                src/comps/mcuxClEls/inc/mcuxClEls_Ecc.h
                # TODO please change to relative dir
                src/comps/mcuxClEls/inc/mcuxClEls_Hash.h
                # TODO please change to relative dir
                src/comps/mcuxClEls/inc/mcuxClEls_Hmac.h
                # TODO please change to relative dir
                src/comps/mcuxClEls/inc/mcuxClEls_Kdf.h
                # TODO please change to relative dir
                src/comps/mcuxClEls/inc/mcuxClEls_mapping.h
                # TODO please change to relative dir
                src/comps/mcuxClEls/inc/mcuxClEls_Rng.h
                # TODO please change to relative dir
                src/comps/mcuxClEls/inc/mcuxClEls_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClEls/inc/mcuxClEls_KeyManagement.h
                # TODO please change to relative dir
                src/comps/mcuxClEls/inc/internal/mcuxClEls_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClEls/inc/internal/mcuxClEls_Internal_mapping.h
                # TODO please change to relative dir
                src/comps/mcuxClEls/inc/internal/mcuxClEls_SfrAccess.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClEls/inc
                 src/comps/mcuxClEls/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.els_common)
    mcux_add_source(
        SOURCES src/comps/mcuxClEls/src/mcuxClEls_Common.c
                # TODO please change to relative dir
                src/comps/mcuxClEls/inc/mcuxClEls_Common.h
                # TODO please change to relative dir
                src/comps/mcuxClEls/inc/internal/mcuxClEls_Internal_Common.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClEls/inc
                 src/comps/mcuxClEls/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.standalone_gdet)
    mcux_add_source(
        SOURCES src/comps/mcuxClEls/src/mcuxClEls_GlitchDetector.c
                # TODO please change to relative dir
                src/comps/mcuxClEls/inc/mcuxClEls_GlitchDetector.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClEls/inc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.els)
    mcux_add_source(
        SOURCES src/comps/mcuxClEls/src/mcuxClEls_Aead.c
                # TODO please change to relative dir
                src/comps/mcuxClEls/src/mcuxClEls_Cipher.c
                # TODO please change to relative dir
                src/comps/mcuxClEls/src/mcuxClEls_Cmac.c
                # TODO please change to relative dir
                src/comps/mcuxClEls/src/mcuxClEls_Ecc.c
                # TODO please change to relative dir
                src/comps/mcuxClEls/src/mcuxClEls_Hash.c
                # TODO please change to relative dir
                src/comps/mcuxClEls/src/mcuxClEls_Hmac.c
                # TODO please change to relative dir
                src/comps/mcuxClEls/src/mcuxClEls_Kdf.c
                # TODO please change to relative dir
                src/comps/mcuxClEls/src/mcuxClEls_Rng.c
                # TODO please change to relative dir
                src/comps/mcuxClEls/src/mcuxClEls_KeyManagement.c
    )
    mcux_add_include(
        INCLUDES ./
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.glikey)
    mcux_add_source(
        SOURCES src/comps/mcuxClGlikey/src/mcuxClGlikey.c
                # TODO please change to relative dir
                src/comps/mcuxClGlikey/inc/mcuxClGlikey.h
                # TODO please change to relative dir
                src/comps/mcuxClGlikey/inc/internal/mcuxClGlikey_SfrAccess.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClGlikey/inc
                 src/comps/mcuxClGlikey/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.hash)
    mcux_add_source(
        SOURCES src/comps/mcuxClHash/src/mcuxClHash_api_multipart_common.c
                # TODO please change to relative dir
                src/comps/mcuxClHash/src/mcuxClHash_api_multipart_compute.c
                # TODO please change to relative dir
                src/comps/mcuxClHash/src/mcuxClHash_api_oneshot_compute.c
                # TODO please change to relative dir
                src/comps/mcuxClHash/src/mcuxClHash_Internal.c
                # TODO please change to relative dir
                src/comps/mcuxClHash/inc/mcuxClHash.h
                # TODO please change to relative dir
                src/comps/mcuxClHash/inc/mcuxClHash_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClHash/inc/mcuxClHash_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClHash/inc/mcuxClHash_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClHash/inc/mcuxClHash_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClHash/inc/internal/mcuxClHash_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClHash/inc/internal/mcuxClHash_Internal_Memory.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClHash/inc
                 src/comps/mcuxClHash/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.hashmodes)
    mcux_add_source(
        SOURCES src/comps/mcuxClHashModes/src/mcuxClHashModes_Core_c_sha1.c
                # TODO please change to relative dir
                src/comps/mcuxClHashModes/src/mcuxClHashModes_Core_els_sha2.c
                # TODO please change to relative dir
                src/comps/mcuxClHashModes/src/mcuxClHashModes_Internal_c_sha1.c
                # TODO please change to relative dir
                src/comps/mcuxClHashModes/src/mcuxClHashModes_Internal_els_sha2.c
                # TODO please change to relative dir
                src/comps/mcuxClHashModes/inc/mcuxClHashModes.h
                # TODO please change to relative dir
                src/comps/mcuxClHashModes/inc/mcuxClHashModes_Algorithms.h
                # TODO please change to relative dir
                src/comps/mcuxClHashModes/inc/mcuxClHashModes_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClHashModes/inc/mcuxClHashModes_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClHashModes/inc/mcuxClHashModes_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClHashModes/inc/internal/mcuxClHashModes_Core_c_sha1.h
                # TODO please change to relative dir
                src/comps/mcuxClHashModes/inc/internal/mcuxClHashModes_Core_els_sha2.h
                # TODO please change to relative dir
                src/comps/mcuxClHashModes/inc/internal/mcuxClHashModes_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClHashModes/inc/internal/mcuxClHashModes_Internal_els_sha2.h
                # TODO please change to relative dir
                src/comps/mcuxClHashModes/inc/internal/mcuxClHashModes_Internal_Memory.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClHashModes/inc
                 src/comps/mcuxClHashModes/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.hmac)
    mcux_add_source(
        SOURCES src/comps/mcuxClHmac/src/mcuxClHmac_Els.c
                # TODO please change to relative dir
                src/comps/mcuxClHmac/src/mcuxClHmac_Functions.c
                # TODO please change to relative dir
                src/comps/mcuxClHmac/src/mcuxClHmac_Helper.c
                # TODO please change to relative dir
                src/comps/mcuxClHmac/src/mcuxClHmac_KeyTypes.c
                # TODO please change to relative dir
                src/comps/mcuxClHmac/src/mcuxClHmac_Modes.c
                # TODO please change to relative dir
                src/comps/mcuxClHmac/src/mcuxClHmac_Sw.c
                # TODO please change to relative dir
                src/comps/mcuxClHmac/inc/mcuxClHmac.h
                # TODO please change to relative dir
                src/comps/mcuxClHmac/inc/mcuxClHmac_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClHmac/inc/mcuxClHmac_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClHmac/inc/mcuxClHmac_KeyTypes.h
                # TODO please change to relative dir
                src/comps/mcuxClHmac/inc/mcuxClHmac_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClHmac/inc/mcuxClHmac_Modes.h
                # TODO please change to relative dir
                src/comps/mcuxClHmac/inc/internal/mcuxClHmac_Core_Functions_Els.h
                # TODO please change to relative dir
                src/comps/mcuxClHmac/inc/internal/mcuxClHmac_Core_Functions_Sw.h
                # TODO please change to relative dir
                src/comps/mcuxClHmac/inc/internal/mcuxClHmac_Internal_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClHmac/inc/internal/mcuxClHmac_Internal_Memory.h
                # TODO please change to relative dir
                src/comps/mcuxClHmac/inc/internal/mcuxClHmac_Internal_Types.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClHmac/inc/
                 src/comps/mcuxClHmac/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.key_derivation)
    mcux_add_source(
        SOURCES src/comps/mcuxClKey/src/mcuxClKey_agreement.c
                # TODO please change to relative dir
                src/comps/mcuxClKey/src/mcuxClKey_agreement_selftest.c
                # TODO please change to relative dir
                src/comps/mcuxClKey/src/mcuxClKey_Derivation.c
                # TODO please change to relative dir
                src/comps/mcuxClKey/src/mcuxClKey_Derivation_HKDF.c
                # TODO please change to relative dir
                src/comps/mcuxClKey/src/mcuxClKey_Derivation_NIST_SP800_108.c
                # TODO please change to relative dir
                src/comps/mcuxClKey/src/mcuxClKey_Derivation_NIST_SP800_56C.c
                # TODO please change to relative dir
                src/comps/mcuxClKey/src/mcuxClKey_Derivation_PBKDF2.c
                # TODO please change to relative dir
                src/comps/mcuxClKey/src/mcuxClKey_generate_keypair.c
                # TODO please change to relative dir
                src/comps/mcuxClKey/inc/mcuxClKey_DerivationAlgorithms.h
                # TODO please change to relative dir
                src/comps/mcuxClKey/inc/mcuxClKey_DerivationAlgorithms_HKDF.h
                # TODO please change to relative dir
                src/comps/mcuxClKey/inc/mcuxClKey_DerivationAlgorithms_NIST_SP800_108.h
                # TODO please change to relative dir
                src/comps/mcuxClKey/inc/mcuxClKey_DerivationAlgorithms_NIST_SP800_56C.h
                # TODO please change to relative dir
                src/comps/mcuxClKey/inc/mcuxClKey_DerivationAlgorithms_PBKDF2.h
                # TODO please change to relative dir
                src/comps/mcuxClKey/inc/internal/mcuxClKey_DerivationAlgorithms_NIST_SP800_108_Internal.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClKey/inc
                 src/comps/mcuxClKey/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.key)
    mcux_add_source(
        SOURCES src/comps/mcuxClKey/src/mcuxClKey.c
                # TODO please change to relative dir
                src/comps/mcuxClKey/src/mcuxClKey_Protection.c
                # TODO please change to relative dir
                src/comps/mcuxClKey/inc/mcuxClKey.h
                # TODO please change to relative dir
                src/comps/mcuxClKey/inc/mcuxClKey_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClKey/inc/mcuxClKey_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClKey/inc/mcuxClKey_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClKey/inc/mcuxClKey_ProtectionMechanisms.h
                # TODO please change to relative dir
                src/comps/mcuxClKey/inc/mcuxClKey_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClKey/inc/internal/mcuxClKey_Functions_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClKey/inc/internal/mcuxClKey_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClKey/inc/internal/mcuxClKey_Protection_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClKey/inc/internal/mcuxClKey_Types_Internal.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClKey/inc
                 src/comps/mcuxClKey/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.mac)
    mcux_add_source(
        SOURCES src/comps/mcuxClMac/src/mcuxClMac.c
                # TODO please change to relative dir
                src/comps/mcuxClMac/inc/mcuxClMac.h
                # TODO please change to relative dir
                src/comps/mcuxClMac/inc/mcuxClMac_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClMac/inc/mcuxClMac_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClMac/inc/mcuxClMac_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClMac/inc/internal/mcuxClMac_Ctx.h
                # TODO please change to relative dir
                src/comps/mcuxClMac/inc/internal/mcuxClMac_Internal_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClMac/inc/internal/mcuxClMac_Internal_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClMac/inc/internal/mcuxClMac_Internal_Types.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClMac/inc/
                 src/comps/mcuxClMac/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.mac_modes)
    mcux_add_source(
        SOURCES src/comps/mcuxClMacModes/src/mcuxClMacModes_Common.c
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/src/mcuxClMacModes_Common_Modes.c
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/src/mcuxClMacModes_Els_Cbcmac.c
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/src/mcuxClMacModes_Els_Cmac.c
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/src/mcuxClMacModes_Els_Functions.c
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/inc/mcuxClMacModes.h
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/inc/mcuxClMacModes_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/inc/mcuxClMacModes_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/inc/mcuxClMacModes_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/inc/mcuxClMacModes_Modes.h
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/inc/internal/mcuxClMacModes_Common_Algorithms.h
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/inc/internal/mcuxClMacModes_Common_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/inc/internal/mcuxClMacModes_Common_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/inc/internal/mcuxClMacModes_Common_Memory.h
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/inc/internal/mcuxClMacModes_Common_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/inc/internal/mcuxClMacModes_Common_Wa.h
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/inc/internal/mcuxClMacModes_Els_Cbcmac.h
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/inc/internal/mcuxClMacModes_Els_Cmac.h
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/inc/internal/mcuxClMacModes_Els_Ctx.h
                # TODO please change to relative dir
                src/comps/mcuxClMacModes/inc/internal/mcuxClMacModes_Els_Types.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClMacModes/inc/
                 src/comps/mcuxClMacModes/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.math)
    mcux_add_source(
        SOURCES src/comps/mcuxClMath/src/mcuxClMath_ExactDivide.c
                # TODO please change to relative dir
                src/comps/mcuxClMath/src/mcuxClMath_ExactDivideOdd.c
                # TODO please change to relative dir
                src/comps/mcuxClMath/src/mcuxClMath_ExactDivideOdd_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClMath/src/mcuxClMath_ModExp_SqrMultL2R.c
                # TODO please change to relative dir
                src/comps/mcuxClMath/src/mcuxClMath_ModInv.c
                # TODO please change to relative dir
                src/comps/mcuxClMath/src/mcuxClMath_ModInv_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClMath/src/mcuxClMath_NDash.c
                # TODO please change to relative dir
                src/comps/mcuxClMath/src/mcuxClMath_NDash_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClMath/src/mcuxClMath_QDash.c
                # TODO please change to relative dir
                src/comps/mcuxClMath/src/mcuxClMath_QDash_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClMath/src/mcuxClMath_ReduceModEven.c
                # TODO please change to relative dir
                src/comps/mcuxClMath/src/mcuxClMath_SecModExp.c
                # TODO please change to relative dir
                src/comps/mcuxClMath/src/mcuxClMath_SecModExp_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClMath/src/mcuxClMath_Utils.c
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/mcuxClMath.h
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/mcuxClMath_ExactDivideOdd_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/mcuxClMath_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/mcuxClMath_ModInv_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/mcuxClMath_NDash_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/mcuxClMath_QDash_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/mcuxClMath_SecModExp_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/mcuxClMath_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/internal/mcuxClMath_ExactDivideOdd_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/internal/mcuxClMath_Internal_ExactDivideOdd.h
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/internal/mcuxClMath_Internal_ModInv.h
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/internal/mcuxClMath_Internal_NDash.h
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/internal/mcuxClMath_Internal_QDash.h
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/internal/mcuxClMath_Internal_SecModExp.h
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/internal/mcuxClMath_Internal_Utils.h
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/internal/mcuxClMath_ModInv_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/internal/mcuxClMath_NDash_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/internal/mcuxClMath_QDash_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClMath/inc/internal/mcuxClMath_SecModExp_FUP.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClMath/inc/
                 src/comps/mcuxClMath/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.memory)
    mcux_add_source(
        SOURCES src/comps/mcuxClMemory/src/mcuxClMemory.c
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/mcuxClMemory.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/mcuxClMemory_Clear.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/mcuxClMemory_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/mcuxClMemory_Copy.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/mcuxClMemory_Copy_Reversed.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/mcuxClMemory_Endianness.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/mcuxClMemory_Set.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/mcuxClMemory_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/mcuxClMemory_Xor.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/internal/mcuxClMemory_ClearSecure_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/internal/mcuxClMemory_Clear_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/internal/mcuxClMemory_CompareDPASecure_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/internal/mcuxClMemory_CompareSecure_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/internal/mcuxClMemory_Compare_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/internal/mcuxClMemory_CopySecurePow2_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/internal/mcuxClMemory_CopySecure_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/internal/mcuxClMemory_CopySecure_Reversed_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/internal/mcuxClMemory_CopyWords_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/internal/mcuxClMemory_Copy_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/internal/mcuxClMemory_Copy_Reversed_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/internal/mcuxClMemory_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/internal/mcuxClMemory_SetSecure_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClMemory/inc/internal/mcuxClMemory_Set_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxCsslMemory/src/mcuxCsslMemory_Clear.c
                # TODO please change to relative dir
                src/comps/mcuxCsslMemory/src/mcuxCsslMemory_Compare.c
                # TODO please change to relative dir
                src/comps/mcuxCsslMemory/src/mcuxCsslMemory_Copy.c
                # TODO please change to relative dir
                src/comps/mcuxCsslMemory/src/mcuxCsslMemory_Internal_SecureCompare_Stub.c
                # TODO please change to relative dir
                src/comps/mcuxCsslMemory/src/mcuxCsslMemory_Set.c
                # TODO please change to relative dir
                src/comps/mcuxCsslMemory/inc/mcuxCsslMemory.h
                # TODO please change to relative dir
                src/comps/mcuxCsslMemory/inc/mcuxCsslMemory_Clear.h
                # TODO please change to relative dir
                src/comps/mcuxCsslMemory/inc/mcuxCsslMemory_Compare.h
                # TODO please change to relative dir
                src/comps/mcuxCsslMemory/inc/mcuxCsslMemory_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxCsslMemory/inc/mcuxCsslMemory_Copy.h
                # TODO please change to relative dir
                src/comps/mcuxCsslMemory/inc/mcuxCsslMemory_Set.h
                # TODO please change to relative dir
                src/comps/mcuxCsslMemory/inc/mcuxCsslMemory_Types.h
                # TODO please change to relative dir
                src/comps/mcuxCsslMemory/inc/internal/mcuxCsslMemory_Internal_Compare_asm.h
                # TODO please change to relative dir
                src/comps/mcuxCsslMemory/inc/internal/mcuxCsslMemory_Internal_Copy_asm.h
                # TODO please change to relative dir
                src/comps/mcuxCsslMemory/inc/internal/mcuxCsslMemory_Internal_SecureCompare.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClMemory/inc
                 src/comps/mcuxClMemory/inc/internal
                 src/comps/mcuxCsslMemory/inc
                 src/comps/mcuxCsslMemory/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.oscca)
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.oscca_aeadmodes)
    mcux_add_source(
        SOURCES src/comps/mcuxClOsccaAeadModes/src/mcuxClOsccaAeadModes_Ccm_Common.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaAeadModes/src/mcuxClOsccaAeadModes_Constants.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaAeadModes/src/mcuxClOsccaAeadModes_EngineCcm.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaAeadModes/src/mcuxClOsccaAeadModes_SkeletonCcm.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaAeadModes/src/mcuxClOsccaAeadModes_SM4Ctr.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaAeadModes/src/mcuxClOsccaAeadModes_SM4_Multipart.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaAeadModes/src/mcuxClOsccaAeadModes_SM4_OneShot.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaAeadModes/inc/mcuxClOsccaAeadModes.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaAeadModes/inc/mcuxClOsccaAeadModes_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaAeadModes/inc/mcuxClOsccaAeadModes_Modes.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaAeadModes/inc/internal/mcuxClOsccaAeadModes_Internal_Algorithms.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaAeadModes/inc/internal/mcuxClOsccaAeadModes_Internal_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaAeadModes/inc/internal/mcuxClOsccaAeadModes_Internal_Types.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClOsccaAeadModes/inc
                 src/comps/mcuxClOsccaAeadModes/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.oscca_ciphermodes)
    mcux_add_source(
        SOURCES src/comps/mcuxClOsccaCipherModes/src/mcuxClOsccaCipherModes_Constants.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaCipherModes/src/mcuxClOsccaCipherModes_SM4_Crypt.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaCipherModes/src/mcuxClOsccaCipherModes_SM4_Crypt_Internal.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaCipherModes/inc/mcuxClOsccaCipherModes.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaCipherModes/inc/mcuxClOsccaCipherModes_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaCipherModes/inc/mcuxClOsccaCipherModes_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaCipherModes/inc/internal/mcuxClOsccaCipherModes_Algorithms.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaCipherModes/inc/internal/mcuxClOsccaCipherModes_Internal_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaCipherModes/inc/internal/mcuxClOsccaCipherModes_Internal_Types.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClOsccaCipherModes/inc
                 src/comps/mcuxClOsccaCipherModes/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.oscca_macmodes)
    mcux_add_source(
        SOURCES src/comps/mcuxClOsccaMacModes/src/mcuxClOsccaMacModes.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaMacModes/src/mcuxClOsccaMacModes_CBCMac.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaMacModes/src/mcuxClOsccaMacModes_CMac.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaMacModes/src/mcuxClOsccaMacModes_Helper.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaMacModes/src/mcuxClOsccaMacModes_KeyTypes.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaMacModes/src/mcuxClOsccaMacModes_Modes.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaMacModes/inc/mcuxClOsccaMacModes.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaMacModes/inc/mcuxClOsccaMacModes_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaMacModes/inc/mcuxClOsccaMacModes_KeyTypes.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaMacModes/inc/mcuxClOsccaMacModes_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaMacModes/inc/mcuxClOsccaMacModes_Modes.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaMacModes/inc/internal/mcuxClOsccaMacModes_Algorithms.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaMacModes/inc/internal/mcuxClOsccaMacModes_Ctx.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaMacModes/inc/internal/mcuxClOsccaMacModes_Internal_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaMacModes/inc/internal/mcuxClOsccaMacModes_SM4_CBCMAC.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaMacModes/inc/internal/mcuxClOsccaMacModes_SM4_CMAC.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaMacModes/inc/internal/mcuxClOsccaMacModes_Types.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClOsccaMacModes/inc
                 src/comps/mcuxClOsccaMacModes/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.oscca_pkc)
    mcux_add_source(
        SOURCES src/comps/mcuxClOsccaPkc/src/mcuxClOsccaPkc.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaPkc/inc/mcuxClOsccaPkc.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaPkc/inc/mcuxClOsccaPkc_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaPkc/inc/mcuxClOsccaPkc_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaPkc/inc/internal/mcuxClOsccaPkc_FupMacros.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaPkc/inc/internal/mcuxClOsccaPkc_Macros.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaPkc/inc/internal/mcuxClOsccaPkc_Operations.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaPkc/inc/internal/mcuxClOsccaPkc_SfrAccess.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClOsccaPkc/inc
                 src/comps/mcuxClOsccaPkc/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.oscca_randommodes)
    mcux_add_source(
        SOURCES src/comps/mcuxClOsccaRandomModes/src/mcuxClOsccaRandomModes_OsccaMode.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaRandomModes/inc/mcuxClOsccaRandomModes.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaRandomModes/inc/mcuxClOsccaRandomModes_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaRandomModes/inc/mcuxClOsccaRandomModes_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaRandomModes/inc/internal/mcuxClOsccaRandomModes_Private_RNG.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaRandomModes/inc/internal/mcuxClOsccaRandomModes_Private_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaRandomModes/inc/internal/mcuxClOsccaRandomModes_SfrAccess.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClOsccaRandomModes/inc
                 src/comps/mcuxClOsccaRandomModes/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.oscca_safo)
    mcux_add_source(
        SOURCES src/comps/mcuxClOsccaSafo/src/mcuxClOsccaSafo_Drv.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSafo/inc/mcuxClOsccaSafo.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSafo/inc/mcuxClOsccaSafo_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSafo/inc/mcuxClOsccaSafo_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSafo/inc/mcuxClOsccaSafo_SfrAccess.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSafo/inc/mcuxClOsccaSafo_Sfr_Ctrl.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSafo/inc/mcuxClOsccaSafo_Sfr_RegBank.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSafo/inc/mcuxClOsccaSafo_Sfr_Status.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSafo/inc/mcuxClOsccaSafo_Types.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClOsccaSafo/inc
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.oscca_sm2)
    mcux_add_source(
        SOURCES src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_Cipher_Crypt.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_ComputePrehash.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_Constants.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_CryptoUtils.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_Decrypt.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_Ecc.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_EccUtils.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_EncDec_Internal.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_Encrypt.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_GenerateKeyPair.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_Helper.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_InvertPrivateKey.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_Keyagreement.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_Keyagreement_SelfTest.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_KeyExchange.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_KeyTypes.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_SelfTest.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_Sign.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_Signature_Internal.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_Signature_PreHash.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_Signature_SelfTest.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/src/mcuxClOsccaSm2_Verify.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/mcuxClOsccaSm2.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/mcuxClOsccaSm2_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/mcuxClOsccaSm2_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/mcuxClOsccaSm2_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/mcuxClOsccaSm2_KeyTypes.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/mcuxClOsccaSm2_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/mcuxClOsccaSm2_ModeConstants.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/mcuxClOsccaSm2_SelfTest.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/mcuxClOsccaSm2_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/internal/mcuxClOsccaSm2_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/internal/mcuxClOsccaSm2_Internal_ConstructTypes.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/internal/mcuxClOsccaSm2_Internal_CryptoUtils.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/internal/mcuxClOsccaSm2_Internal_Ecc.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/internal/mcuxClOsccaSm2_Internal_FP.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/internal/mcuxClOsccaSm2_Internal_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/internal/mcuxClOsccaSm2_Internal_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/internal/mcuxClOsccaSm2_Internal_Hash.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/internal/mcuxClOsccaSm2_Internal_Helper.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/internal/mcuxClOsccaSm2_Internal_PkcWaLayout.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm2/inc/internal/mcuxClOsccaSm2_Internal_Types.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClOsccaSm2/inc
                 src/comps/mcuxClOsccaSm2/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.oscca_sm3)
    mcux_add_source(
        SOURCES src/comps/mcuxClOsccaSm3/src/mcuxClOsccaSm3_core_sm3.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm3/src/mcuxClOsccaSm3_internal_sm3.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm3/inc/mcuxClOsccaSm3.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm3/inc/mcuxClOsccaSm3_Algorithms.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm3/inc/mcuxClOsccaSm3_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm3/inc/mcuxClOsccaSm3_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm3/inc/internal/mcuxClOsccaSm3_Core_sm3.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm3/inc/internal/mcuxClOsccaSm3_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm3/inc/internal/mcuxClOsccaSm3_Internal_sm3.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClOsccaSm3/inc
                 src/comps/mcuxClOsccaSm3/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.oscca_sm4)
    mcux_add_source(
        SOURCES src/comps/mcuxClOsccaSm4/src/mcuxClOsccaSm4_CommonOperations.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm4/src/mcuxClOsccaSm4_Core.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm4/src/mcuxClOsccaSm4_KeyTypes.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm4/src/mcuxClOsccaSm4_LoadKey.c
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm4/inc/mcuxClOsccaSm4.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm4/inc/mcuxClOsccaSm4_KeyTypes.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm4/inc/internal/mcuxClOsccaSm4_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm4/inc/internal/mcuxClOsccaSm4_Internal_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClOsccaSm4/inc/internal/mcuxClOsccaSm4_Internal_Functions.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClOsccaSm4/inc
                 src/comps/mcuxClOsccaSm4/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.padding)
    mcux_add_source(
        SOURCES src/comps/mcuxClPadding/src/mcuxClPadding.c
                # TODO please change to relative dir
                src/comps/mcuxClPadding/inc/mcuxClPadding.h
                # TODO please change to relative dir
                src/comps/mcuxClPadding/inc/mcuxClPadding_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClPadding/inc/mcuxClPadding_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClPadding/inc/internal/mcuxClPadding_Functions_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClPadding/inc/internal/mcuxClPadding_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClPadding/inc/internal/mcuxClPadding_Types_Internal.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClPadding/inc/
                 src/comps/mcuxClPadding/inc/internal/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.pkc)
    mcux_add_source(
        SOURCES src/comps/mcuxClPkc/src/mcuxClPkc_Calculate.c
                # TODO please change to relative dir
                src/comps/mcuxClPkc/src/mcuxClPkc_ImportExport.c
                # TODO please change to relative dir
                src/comps/mcuxClPkc/src/mcuxClPkc_Initialize.c
                # TODO please change to relative dir
                src/comps/mcuxClPkc/src/mcuxClPkc_UPTRT.c
                # TODO please change to relative dir
                src/comps/mcuxClPkc/inc/mcuxClPkc.h
                # TODO please change to relative dir
                src/comps/mcuxClPkc/inc/mcuxClPkc_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClPkc/inc/mcuxClPkc_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClPkc/inc/internal/mcuxClPkc_FupMacros.h
                # TODO please change to relative dir
                src/comps/mcuxClPkc/inc/internal/mcuxClPkc_ImportExport.h
                # TODO please change to relative dir
                src/comps/mcuxClPkc/inc/internal/mcuxClPkc_Inline_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClPkc/inc/internal/mcuxClPkc_Macros.h
                # TODO please change to relative dir
                src/comps/mcuxClPkc/inc/internal/mcuxClPkc_Operations.h
                # TODO please change to relative dir
                src/comps/mcuxClPkc/inc/internal/mcuxClPkc_Resource.h
                # TODO please change to relative dir
                src/comps/mcuxClPkc/inc/internal/mcuxClPkc_SfrAccess.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClPkc/inc
                 src/comps/mcuxClPkc/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.prng)
    mcux_add_source(
        SOURCES src/comps/mcuxClPrng/src/mcuxClPrng_ELS.c
                # TODO please change to relative dir
                src/comps/mcuxClPrng/inc/internal/mcuxClPrng_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClPrng/inc/internal/mcuxClPrng_Internal_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClPrng/inc/internal/mcuxClPrng_Internal_ELS.h
                # TODO please change to relative dir
                src/comps/mcuxClPrng/inc/internal/mcuxClPrng_Internal_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClPrng/inc/internal/mcuxClPrng_Internal_Types.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClPrng/inc
                 src/comps/mcuxClPrng/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.psa_driver)
    mcux_add_source(
        SOURCES src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Aead.c
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Cipher.c
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_DER_functions.c
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_export_public_key.c
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_generate_ecp_key.c
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Hash.c
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Key.c
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Mac.c
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Rsa.c
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Sign.c
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_UpdateKeyStatus.c
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/src/mcuxClPsaDriver_Verify.c
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/inc/mcuxClPsaDriver.h
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/inc/mcuxClPsaDriver_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/inc/mcuxClPsaDriver_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/inc/mcuxClPsaDriver_Oracle.h
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/inc/internal/mcuxClPsaDriver_ExternalMacroWrappers.h
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/inc/internal/mcuxClPsaDriver_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/inc/internal/mcuxClPsaDriver_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClPsaDriver/inc/internal/mcuxClPsaDriver_Types.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClPsaDriver/inc
                 src/comps/mcuxClPsaDriver/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.random)
    mcux_add_source(
        SOURCES src/comps/mcuxClRandom/src/mcuxClRandom_DRBG.c
                # TODO please change to relative dir
                src/comps/mcuxClRandom/src/mcuxClRandom_PRNG.c
                # TODO please change to relative dir
                src/comps/mcuxClRandom/inc/mcuxClRandom.h
                # TODO please change to relative dir
                src/comps/mcuxClRandom/inc/mcuxClRandom_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClRandom/inc/mcuxClRandom_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClRandom/inc/mcuxClRandom_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClRandom/inc/internal/mcuxClRandom_Internal_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClRandom/inc/internal/mcuxClRandom_Internal_Memory.h
                # TODO please change to relative dir
                src/comps/mcuxClRandom/inc/internal/mcuxClRandom_Internal_Types.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClRandom/inc
                 src/comps/mcuxClRandom/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.random_modes_hmacdrbg)
    mcux_add_source(
        SOURCES src/comps/mcuxClRandomModes/src/mcuxClRandomModes_HmacDrbg.c
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/inc/internal/mcuxClRandomModes_Internal_HmacDrbg_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/inc/internal/mcuxClRandomModes_Private_HmacDrbg.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClRandomModes/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.random_modes)
    mcux_add_source(
        SOURCES src/comps/mcuxClRandomModes/src/mcuxClRandomModes_CtrDrbg_Els.c
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/src/mcuxClRandomModes_ElsMode.c
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/src/mcuxClRandomModes_PatchMode.c
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/src/mcuxClRandomModes_TestMode.c
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/inc/mcuxClRandomModes.h
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/inc/mcuxClRandomModes_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/inc/mcuxClRandomModes_Functions_PatchMode.h
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/inc/mcuxClRandomModes_Functions_TestMode.h
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/inc/mcuxClRandomModes_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/inc/internal/mcuxClRandomModes_Internal_SizeDefinitions.h
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/inc/internal/mcuxClRandomModes_Private_CtrDrbg.h
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/inc/internal/mcuxClRandomModes_Private_CtrDrbg_BlockCipher.h
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/inc/internal/mcuxClRandomModes_Private_Drbg.h
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/inc/internal/mcuxClRandomModes_Private_NormalMode.h
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/inc/internal/mcuxClRandomModes_Private_PatchMode.h
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/inc/internal/mcuxClRandomModes_Private_PrDisabled.h
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/inc/internal/mcuxClRandomModes_Private_TestMode.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClRandomModes/inc
                 src/comps/mcuxClRandomModes/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.random_modes_ctr)
    mcux_add_source(
        SOURCES src/comps/mcuxClRandomModes/src/mcuxClRandomModes_CtrDrbg.c
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/src/mcuxClRandomModes_CtrDrbg_PrDisabled.c
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/src/mcuxClRandomModes_NormalMode.c
                # TODO please change to relative dir
                src/comps/mcuxClRandomModes/src/mcuxClRandomModes_PrDisabled.c
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClRandomModes/inc
                 src/comps/mcuxClRandomModes/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.rsa_oaep)
    mcux_add_source(
        SOURCES src/comps/mcuxClRsa/src/mcuxClRsa_KeyTypes.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_ModeConstructors.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_OaepDecode.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_OaepEncode.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_pkcs1v15Decode_decrypt.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_Pkcs1v15Encode_encrypt.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_Util_Decrypt.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_Util_Encrypt.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/mcuxClRsa_KeyTypes.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/mcuxClRsa_ModeConstructors.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClRsa/inc
                 src/comps/mcuxClRsa/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.rsa)
    mcux_add_source(
        SOURCES src/comps/mcuxClRsa/src/mcuxClRsa_ComputeD.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_ComputeD_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_GenerateProbablePrime.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_getMillerRabinTestIterations.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_KeyGeneration_Crt.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_KeyGeneration_Crt_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_KeyGeneration_Plain.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_Mgf1.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_MillerRabinTest.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_MillerRabinTest_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_ModInv.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_Pkcs1v15Encode_sign.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_Pkcs1v15Verify.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_PrivateCrt.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_PrivateCrt_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_PrivatePlain.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_PssEncode.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_PssVerify.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_Public.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_PublicExp.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_RemoveBlinding.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_RemoveBlinding_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_Sign.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_Sign_NoEMSA.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_TestPQDistance.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_TestPQDistance_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_TestPrimeCandidate.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_TestPrimeCandidate_FUP.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_Verify.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_VerifyE.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/src/mcuxClRsa_Verify_NoEMSA.c
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/mcuxClRsa.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/mcuxClRsa_ComputeD_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/mcuxClRsa_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/mcuxClRsa_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/mcuxClRsa_KeyGeneration_Crt_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/mcuxClRsa_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/mcuxClRsa_MillerRabinTest_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/mcuxClRsa_PrivateCrt_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/mcuxClRsa_RemoveBlinding_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/mcuxClRsa_TestPQDistance_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/mcuxClRsa_TestPrimeCandidate_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/mcuxClRsa_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/internal/mcuxClRsa_ComputeD_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/internal/mcuxClRsa_Internal_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/internal/mcuxClRsa_Internal_Macros.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/internal/mcuxClRsa_Internal_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/internal/mcuxClRsa_Internal_PkcDefs.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/internal/mcuxClRsa_Internal_PkcTypes.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/internal/mcuxClRsa_Internal_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/internal/mcuxClRsa_KeyGeneration_Crt_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/internal/mcuxClRsa_MillerRabinTest_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/internal/mcuxClRsa_PrivateCrt_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/internal/mcuxClRsa_RemoveBlinding_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/internal/mcuxClRsa_TestPQDistance_FUP.h
                # TODO please change to relative dir
                src/comps/mcuxClRsa/inc/internal/mcuxClRsa_TestPrimeCandidate_FUP.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClRsa/inc
                 src/comps/mcuxClRsa/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.session)
    mcux_add_source(
        SOURCES src/comps/mcuxClSession/src/mcuxClSession.c
                # TODO please change to relative dir
                src/comps/mcuxClSession/inc/mcuxClSession.h
                # TODO please change to relative dir
                src/comps/mcuxClSession/inc/mcuxClSession_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClSession/inc/mcuxClSession_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClSession/inc/mcuxClSession_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClSession/inc/internal/mcuxClSession_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClSession/inc/internal/mcuxClSession_Internal_EntryExit.h
                # TODO please change to relative dir
                src/comps/mcuxClSession/inc/internal/mcuxClSession_Internal_EntryExit_RegularReturn.h
                # TODO please change to relative dir
                src/comps/mcuxClSession/inc/internal/mcuxClSession_Internal_Functions.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClSession/inc
                 src/comps/mcuxClSession/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.signature)
    mcux_add_source(
        SOURCES src/comps/mcuxClSignature/src/mcuxClSignature.c
                # TODO please change to relative dir
                src/comps/mcuxClSignature/inc/mcuxClSignature.h
                # TODO please change to relative dir
                src/comps/mcuxClSignature/inc/mcuxClSignature_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClSignature/inc/mcuxClSignature_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClSignature/inc/mcuxClSignature_MemoryConsumption.h
                # TODO please change to relative dir
                src/comps/mcuxClSignature/inc/mcuxClSignature_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClSignature/inc/internal/mcuxClSignature_Internal.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClSignature/inc
                 src/comps/mcuxClSignature/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.trng)
    mcux_add_source(
        SOURCES src/comps/mcuxClTrng/inc/internal/mcuxClTrng_Internal.h
                # TODO please change to relative dir
                src/comps/mcuxClTrng/inc/internal/mcuxClTrng_Internal_Constants.h
                # TODO please change to relative dir
                src/comps/mcuxClTrng/inc/internal/mcuxClTrng_Internal_Functions.h
                # TODO please change to relative dir
                src/comps/mcuxClTrng/inc/internal/mcuxClTrng_Internal_SA_TRNG.h
                # TODO please change to relative dir
                src/comps/mcuxClTrng/inc/internal/mcuxClTrng_Internal_Types.h
                # TODO please change to relative dir
                src/comps/mcuxClTrng/inc/internal/mcuxClTrng_SfrAccess.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClTrng/inc
                 src/comps/mcuxClTrng/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.trng.type_els)
    mcux_add_source(
        SOURCES src/comps/mcuxClRandomModes/src/mcuxClRandomModes_NormalMode.c
                # TODO please change to relative dir
                src/comps/mcuxClTrng/src/mcuxClTrng_ELS.c
    )
    mcux_add_include(
        INCLUDES ./
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.trng.type_rng4)
    mcux_add_source(
        SOURCES src/comps/mcuxClTrng/src/mcuxClTrng_SA_TRNG.c
                # TODO please change to relative dir
                src/comps/mcuxClTrng/inc/internal/mcuxClTrng_SfrAccess.h
                # TODO please change to relative dir
                src/comps/mcuxClTrng/inc/internal/mcuxClTrng_Internal_SA_TRNG.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClTrng/inc
                 src/comps/mcuxClTrng/inc/internal
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.pre_processor)
    mcux_add_source(
        SOURCES src/comps/mcuxCsslCPreProcessor/inc/mcuxCsslAnalysis.h
                # TODO please change to relative dir
                src/comps/mcuxCsslCPreProcessor/inc/mcuxCsslCPreProcessor.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxCsslCPreProcessor/inc
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.data_integrity)
    mcux_add_source(
        SOURCES src/comps/mcuxCsslDataIntegrity/inc/mcuxCsslDataIntegrity.h
                # TODO please change to relative dir
                src/comps/mcuxCsslDataIntegrity/inc/mcuxCsslDataIntegrity_Cfg.h
                # TODO please change to relative dir
                src/comps/mcuxCsslDataIntegrity/inc/mcuxCsslDataIntegrity_Impl.h
                # TODO please change to relative dir
                src/comps/mcuxCsslDataIntegrity/inc/mcuxCsslDataIntegrity_None.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxCsslDataIntegrity/inc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.flow_protection)
    mcux_add_source(
        SOURCES src/comps/mcuxCsslFlowProtection/inc/mcuxCsslFlowProtection.h
                # TODO please change to relative dir
                src/comps/mcuxCsslFlowProtection/inc/mcuxCsslFlowProtection_Cfg.h
                # TODO please change to relative dir
                src/comps/mcuxCsslFlowProtection/inc/mcuxCsslFlowProtection_FunctionIdentifiers.h
                # TODO please change to relative dir
                src/comps/mcuxCsslFlowProtection/inc/mcuxCsslFlowProtection_Impl.h
                # TODO please change to relative dir
                src/comps/mcuxCsslFlowProtection/inc/mcuxCsslFlowProtection_SecureCounter_Common.h
                # TODO please change to relative dir
                src/comps/mcuxCsslFlowProtection/inc/mcuxCsslFlowProtection_SecureCounter_Local.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxCsslFlowProtection/inc
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.param_integrity)
    mcux_add_source(
        SOURCES src/comps/mcuxCsslParamIntegrity/src/mcuxCsslParamIntegrity.c
                # TODO please change to relative dir
                src/comps/mcuxCsslParamIntegrity/inc/mcuxCsslParamIntegrity.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxCsslParamIntegrity/inc
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.secure_counter)
    mcux_add_source(
        SOURCES src/comps/mcuxCsslSecureCounter/inc/mcuxCsslSecureCounter.h
                # TODO please change to relative dir
                src/comps/mcuxCsslSecureCounter/inc/mcuxCsslSecureCounter_Cfg.h
                # TODO please change to relative dir
                src/comps/mcuxCsslSecureCounter/inc/mcuxCsslSecureCounter_Impl.h
                # TODO please change to relative dir
                src/comps/mcuxCsslSecureCounter/inc/mcuxCsslSecureCounter_None.h
                # TODO please change to relative dir
                src/comps/mcuxCsslSecureCounter/inc/mcuxCsslSecureCounter_SW_Local.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxCsslSecureCounter/inc
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc)
    mcux_add_source(
        SOURCES src/inc/mcuxCl_clns.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/inc
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.toolchain)
    mcux_add_source(
        SOURCES /src/compiler/mcuxClToolchain.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/compiler
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.platform.mcxn)
    mcux_add_source(
        SOURCES src/platforms/mcxn/platform_specific_headers.h
                # TODO please change to relative dir
                src/platforms/mcxn/mcuxClConfig.h
                # TODO please change to relative dir
                src/platforms/mcxn/inc/ip_css_constants.h
                # TODO please change to relative dir
                src/platforms/mcxn/inc/ip_css_design_configuration.h
                # TODO please change to relative dir
                src/platforms/mcxn/inc/ip_platform.h
                # TODO please change to relative dir
                src/platforms/mcxn/mcux_els.c
                # TODO please change to relative dir
                src/platforms/mcxn/mcux_els.h
                # TODO please change to relative dir
                src/platforms/mcxn/mcux_pkc.c
                # TODO please change to relative dir
                src/platforms/mcxn/mcux_pkc.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/platforms/mcxn
                 src/platforms/mcxn/inc
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.platform.rw61x_inf_header_only)
    mcux_add_source(
        SOURCES src/platforms/rw61x/platform_specific_headers.h
                # TODO please change to relative dir
                src/platforms/rw61x/mcuxClConfig.h
                # TODO please change to relative dir
                src/platforms/rw61x/inc/ip_css_constants.h
                # TODO please change to relative dir
                src/platforms/rw61x/inc/ip_css_design_configuration.h
                # TODO please change to relative dir
                src/platforms/rw61x/inc/ip_platform.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/platforms/rw61x
                 src/platforms/rw61x/inc
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.platform.rw61x_interface_files)
    mcux_add_source(
        SOURCES src/platforms/rw61x/mcux_els.c
                # TODO please change to relative dir
                src/platforms/rw61x/mcux_els.h
                # TODO please change to relative dir
                src/platforms/rw61x/mcux_pkc.c
                # TODO please change to relative dir
                src/platforms/rw61x/mcux_pkc.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/platforms/rw61x
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.platform.rw61x_standalone_clib_gdet_sensor)
    mcux_add_source(
        SOURCES src/platforms/rw61x/readme.txt
    )
    mcux_add_include(
        INCLUDES ./
                 src/platforms/rw61x
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.platform.rw61x)
    mcux_add_source(
        SOURCES src/platforms/rw61x/readme.txt
    )
    mcux_add_include(
        INCLUDES ./
                 src/platforms/rw61x
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.platform.lpc)
    mcux_add_source(
        SOURCES src/platforms/lpc/platform_specific_headers.h
                # TODO please change to relative dir
                src/platforms/lpc/mcuxClConfig.h
                # TODO please change to relative dir
                src/platforms/lpc/inc/ip_css_constants.h
                # TODO please change to relative dir
                src/platforms/lpc/inc/ip_css_design_configuration.h
                # TODO please change to relative dir
                src/platforms/lpc/inc/ip_platform.h
                # TODO please change to relative dir
                src/platforms/lpc/mcux_els.c
                # TODO please change to relative dir
                src/platforms/lpc/mcux_els.h
                # TODO please change to relative dir
                src/platforms/lpc/mcux_pkc.c
                # TODO please change to relative dir
                src/platforms/lpc/mcux_pkc.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/platforms/lpc
                 src/platforms/lpc/inc
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.platform.mimxrt)
    mcux_add_source(
        SOURCES src/platforms/mimxrt/platform_specific_headers.h
                # TODO please change to relative dir
                src/platforms/mimxrt/mcuxClConfig.h
                # TODO please change to relative dir
                src/platforms/mimxrt/inc/ip_css_constants.h
                # TODO please change to relative dir
                src/platforms/mimxrt/inc/ip_css_design_configuration.h
                # TODO please change to relative dir
                src/platforms/mimxrt/inc/ip_platform.h
                # TODO please change to relative dir
                src/platforms/mimxrt/mcux_els.c
                # TODO please change to relative dir
                src/platforms/mimxrt/mcux_els.h
                # TODO please change to relative dir
                src/platforms/mimxrt/mcux_pkc.c
                # TODO please change to relative dir
                src/platforms/mimxrt/mcux_pkc.h
    )
    mcux_add_include(
        INCLUDES ./
                 src/platforms/mimxrt
                 src/platforms/mimxrt/inc
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.examples)
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.examples_memory)
    mcux_add_source(
        SOURCES examples/mcuxCsslMemory/mcuxCsslMemory_Clear_example.c
                # TODO please change to relative dir
                examples/mcuxCsslMemory/mcuxCsslMemory_Compare_example.c
                # TODO please change to relative dir
                examples/mcuxCsslMemory/mcuxCsslMemory_Copy_example.c
                # TODO please change to relative dir
                examples/mcuxCsslMemory/mcuxCsslMemory_Set_example.c
                # TODO please change to relative dir
                examples/mcuxCsslMemory/inc/mcuxCsslMemory_Examples.h
    )
    mcux_add_include(
        INCLUDES ./
                 examples/mcuxCsslFlowProtection/inc/
                 examples/mcuxCsslMemory/inc/
                 src/comps/mcuxClExample/inc/
                 src/comps/mcuxClBuffer/inc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.examples_flow_protection)
    mcux_add_source(
        SOURCES examples/mcuxCsslFlowProtection/mcuxCsslFlowProtection_example.c
                # TODO please change to relative dir
                examples/mcuxCsslFlowProtection/inc/mcuxCsslExamples.h
    )
    mcux_add_include(
        INCLUDES ./
                 examples/mcuxCsslFlowProtection/inc/
                 examples/mcuxCsslMemory/inc/
                 src/comps/mcuxClExample/inc/
                 src/comps/mcuxClBuffer/inc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.examples_rsa)
    mcux_add_source(
        SOURCES examples/mcuxClRsa/mcuxClRsa_sign_NoEncode_example.c
                # TODO please change to relative dir
                examples/mcuxClRsa/mcuxClRsa_sign_pss_sha2_256_example.c
                # TODO please change to relative dir
                examples/mcuxClRsa/mcuxClRsa_verify_NoVerify_example.c
                # TODO please change to relative dir
                examples/mcuxClRsa/mcuxClRsa_verify_pssverify_sha2_256_example.c
    )
    mcux_add_include(
        INCLUDES ./
                 examples/mcuxCsslFlowProtection/inc/
                 examples/mcuxCsslMemory/inc/
                 src/comps/mcuxClExample/inc/
                 src/comps/mcuxClBuffer/inc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.examples_random_modes)
    mcux_add_source(
        SOURCES examples/mcuxClRandomModes/mcuxClRandomModes_CtrDrbg_AES256_DRG3_example.c
                # TODO please change to relative dir
                examples/mcuxClRandomModes/mcuxClRandomModes_CtrDrbg_AES256_DRG4_example.c
                # TODO please change to relative dir
                examples/mcuxClRandomModes/mcuxClRandomModes_CtrDrbg_AES256_ELS_example.c
                # TODO please change to relative dir
                examples/mcuxClRandomModes/mcuxClRandomModes_Different_Sessions_example.c
                # TODO please change to relative dir
                examples/mcuxClRandomModes/mcuxClRandomModes_PatchMode_CtrDrbg_AES256_DRG3_example.c
                # TODO please change to relative dir
                examples/mcuxClRandomModes/mcuxClRandomModes_TestMode_CtrDrbg_AES256_DRG4_example.c
    )
    mcux_add_include(
        INCLUDES ./
                 examples/mcuxCsslFlowProtection/inc/
                 examples/mcuxCsslMemory/inc/
                 src/comps/mcuxClExample/inc/
                 src/comps/mcuxClBuffer/inc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.examples_mac_modes)
    mcux_add_source(
        SOURCES examples/mcuxClMacModes/mcuxClMacModes_Els_Cbcmac_Aes128_Oneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClMacModes/mcuxClMacModes_Els_Cbcmac_Aes256_Multipart_PaddingZero_example.c
                # TODO please change to relative dir
                examples/mcuxClMacModes/mcuxClMacModes_Els_Cmac_Aes128_Oneshot_example.c
    )
    mcux_add_include(
        INCLUDES ./
                 examples/mcuxCsslFlowProtection/inc/
                 examples/mcuxCsslMemory/inc/
                 src/comps/mcuxClExample/inc/
                 src/comps/mcuxClBuffer/inc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.examples_key)
    mcux_add_source(
        SOURCES examples/mcuxClKey/mcuxClKey_example.c
    )
    mcux_add_include(
        INCLUDES ./
                 examples/mcuxCsslFlowProtection/inc/
                 examples/mcuxCsslMemory/inc/
                 src/comps/mcuxClExample/inc/
                 src/comps/mcuxClBuffer/inc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.examples_hmac)
    mcux_add_source(
        SOURCES examples/mcuxClHmac/mcuxClHmac_Els_Oneshot_External_Key_example.c
                # TODO please change to relative dir
                examples/mcuxClHmac/mcuxClHmac_Sw_Multipart_example.c
                # TODO please change to relative dir
                examples/mcuxClHmac/mcuxClHmac_Sw_Oneshot_example.c
    )
    mcux_add_include(
        INCLUDES ./
                 examples/mcuxCsslFlowProtection/inc/
                 examples/mcuxCsslMemory/inc/
                 src/comps/mcuxClExample/inc/
                 src/comps/mcuxClBuffer/inc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.examples_hash_modes)
    mcux_add_source(
        SOURCES examples/mcuxClHashModes/mcuxClHashModes_sha1_longMsgOneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClHashModes/mcuxClHashModes_sha1_oneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClHashModes/mcuxClHashModes_sha1_streaming_example.c
                # TODO please change to relative dir
                examples/mcuxClHashModes/mcuxClHashModes_sha224_oneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClHashModes/mcuxClHashModes_sha256_longMsgOneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClHashModes/mcuxClHashModes_sha256_oneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClHashModes/mcuxClHashModes_sha256_streaming_example.c
                # TODO please change to relative dir
                examples/mcuxClHashModes/mcuxClHashModes_sha384_oneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClHashModes/mcuxClHashModes_sha512_224_oneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClHashModes/mcuxClHashModes_sha512_256_oneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClHashModes/mcuxClHashModes_sha512_256_streaming_example.c
                # TODO please change to relative dir
                examples/mcuxClHashModes/mcuxClHashModes_sha512_oneshot_example.c
    )
    mcux_add_include(
        INCLUDES ./
                 examples/mcuxCsslFlowProtection/inc/
                 examples/mcuxCsslMemory/inc/
                 src/comps/mcuxClExample/inc/
                 src/comps/mcuxClBuffer/inc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.examples_els)
    mcux_add_source(
        SOURCES examples/mcuxClEls/mcuxClEls_Cipher_Aes128_Cbc_Encrypt_example.c
                # TODO please change to relative dir
                examples/mcuxClEls/mcuxClEls_Cipher_Aes128_Ecb_Encrypt_example.c
                # TODO please change to relative dir
                examples/mcuxClEls/mcuxClEls_Common_Get_Info_example.c
                # TODO please change to relative dir
                examples/mcuxClEls/mcuxClEls_Ecc_Keygen_Sign_Verify_example.c
                # TODO please change to relative dir
                examples/mcuxClEls/mcuxClEls_Hash_HW_Security_Counter_example.c
                # TODO please change to relative dir
                examples/mcuxClEls/mcuxClEls_Hash_Sha224_One_Block_example.c
                # TODO please change to relative dir
                examples/mcuxClEls/mcuxClEls_Hash_Sha256_One_Block_example.c
                # TODO please change to relative dir
                examples/mcuxClEls/mcuxClEls_Hash_Sha384_One_Block_example.c
                # TODO please change to relative dir
                examples/mcuxClEls/mcuxClEls_Hash_Sha512_One_Block_example.c
                # TODO please change to relative dir
                examples/mcuxClEls/mcuxClEls_Rng_Prng_Get_Random_example.c
                # TODO please change to relative dir
                examples/mcuxClEls/mcuxClEls_Tls_Master_Key_Session_Keys_example.c
                # TODO please change to relative dir
                examples/mcuxClEls/mcuxClEls_Cipher_Aes128_Cbc_Encrypt_example.c
                # TODO please change to relative dir
                examples/mcuxClEls/mcuxClEls_Cipher_Aes128_Ecb_Encrypt_example.c
                # TODO please change to relative dir
                examples/mcuxClEls/mcuxClEls_Common_Get_Info_example.c
                # TODO please change to relative dir
                examples/mcuxClEls/mcuxClEls_Ecc_Keygen_Sign_Verify_example.c
                # TODO please change to relative dir
                examples/mcuxClRandomModes/mcuxClRandomModes_ELS_example.c
                # TODO please change to relative dir
                src/comps/mcuxClExample/inc/mcuxClExample_ELS_Helper.h
                # TODO please change to relative dir
                src/comps/mcuxClExample/inc/mcuxClExample_ELS_Key_Helper.h
                # TODO please change to relative dir
                src/comps/mcuxClExample/inc/mcuxClExample_Key_Helper.h
                # TODO please change to relative dir
                src/comps/mcuxClExample/inc/mcuxClExample_RFC3394_Helper.h
                # TODO please change to relative dir
                src/comps/mcuxClExample/inc/mcuxClExample_RNG_Helper.h
                # TODO please change to relative dir
                src/comps/mcuxClExample/inc/mcuxClExample_Session_Helper.h
    )
    mcux_add_include(
        INCLUDES ./
                 examples/mcuxCsslFlowProtection/inc/
                 examples/mcuxCsslMemory/inc/
                 src/comps/mcuxClExample/inc/
                 src/comps/mcuxClBuffer/inc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.examples_ecc)
    mcux_add_source(
        SOURCES examples/mcuxClEcc/mcuxClEcc_EdDSA_Ed25519ctx_example.c
                # TODO please change to relative dir
                examples/mcuxClEcc/mcuxClEcc_EdDSA_Ed25519ph_example.c
                # TODO please change to relative dir
                examples/mcuxClEcc/mcuxClEcc_EdDSA_Ed25519_example.c
                # TODO please change to relative dir
                examples/mcuxClEcc/mcuxClEcc_EdDSA_GenerateSignature_Ed25519_example.c
                # TODO please change to relative dir
                examples/mcuxClEcc/mcuxClEcc_EdDSA_VerifySignature_Ed25519_example.c
                # TODO please change to relative dir
                examples/mcuxClEcc/mcuxClEcc_MontDH_Curve25519_example.c
                # TODO please change to relative dir
                examples/mcuxClEcc/mcuxClEcc_MontDH_Curve448_example.c
    )
    mcux_add_include(
        INCLUDES ./
                 examples/mcuxCsslFlowProtection/inc/
                 examples/mcuxCsslMemory/inc/
                 src/comps/mcuxClExample/inc/
                 src/comps/mcuxClBuffer/inc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.examples_aead)
    mcux_add_source(
        SOURCES examples/mcuxClAeadModes/mcuxClAeadModes_Els_Ccm_Aes128_Multipart_example.c
                # TODO please change to relative dir
                examples/mcuxClAeadModes/mcuxClAeadModes_Els_Ccm_Aes128_Oneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClAeadModes/mcuxClAeadModes_Els_Gcm_Aes128_Oneshot_example.c
    )
    mcux_add_include(
        INCLUDES ./
                 examples/mcuxCsslFlowProtection/inc/
                 examples/mcuxCsslMemory/inc/
                 src/comps/mcuxClExample/inc/
                 src/comps/mcuxClBuffer/inc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.examples_cipher_modes)
    mcux_add_source(
        SOURCES examples/mcuxClCipherModes/mcuxClCipherModes_Els_Cbc_Aes128_Multipart_example.c
                # TODO please change to relative dir
                examples/mcuxClCipherModes/mcuxClCipherModes_Els_Cbc_Aes128_Oneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClCipherModes/mcuxClCipherModes_Els_Cbc_Aes128_Oneshot_PaddingZero_example.c
                # TODO please change to relative dir
                examples/mcuxClCipherModes/mcuxClCipherModes_Els_Ctr_Aes128_Multipart_example.c
                # TODO please change to relative dir
                examples/mcuxClCipherModes/mcuxClCipherModes_Els_Ctr_Aes128_Oneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClCipherModes/mcuxClCipherModes_Els_Ecb_Aes128_Multipart_example.c
                # TODO please change to relative dir
                examples/mcuxClCipherModes/mcuxClCipherModes_Els_Ecb_Aes128_Multipart_PaddingPKCS7_example.c
                # TODO please change to relative dir
                examples/mcuxClCipherModes/mcuxClCipherModes_Els_Ecb_Aes128_Oneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClCipherModes/mcuxClCipherModes_Els_Ecb_Aes128_Oneshot_PaddingPKCS7_example.c
                # TODO please change to relative dir
                examples/mcuxClCipherModes/mcuxClCipherModes_Els_Ecb_Aes128_Oneshot_PaddingZero_example.c
    )
    mcux_add_include(
        INCLUDES ./
                 examples/mcuxCsslFlowProtection/inc/
                 examples/mcuxCsslMemory/inc/
                 src/comps/mcuxClExample/inc/
                 src/comps/mcuxClBuffer/inc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc.psa_driver_examples)
    mcux_add_source(
        SOURCES examples/mcuxClPsaDriver/mcuxClPsaDriver_aead_ccm_multipart_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_aead_ccm_oneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_aead_gcm_multipart_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_aead_gcm_oneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_aes_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_cipher_decrypt.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_cipher_multipart_CBC.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_cipher_multipart_CTR.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_cipher_multipart_ECB.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_eccsecp224k1_sign_verify_hash_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_ecdsa_keygen_oracleMemory_sign_verify_hash_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_ecdsa_keygen_oracleS50_sign_verify_hash_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_ecdsa_sign_verify_hash_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_ecdsa_sign_verify_message_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_keygen_export_public_key_brainpoolpr1_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_keygen_export_public_key_mont_curve25519_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_keygen_export_public_key_rsa_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_keygen_export_public_key_secpk1_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_keygen_export_public_key_secpr1_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_key_agreement_CURVE_25519_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_key_agreement_SECP_R1_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_mac_oneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_mac_sign_multipart_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_mac_verify_multipart_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_rsa_PKCS1V15_sign_verify_message_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_rsa_PSS_sign_verify_hash_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_sha224_oneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_sha256_abort_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_sha256_clone_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_sha256_multipart_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_sha256_oneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_sha384_oneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_sha512_oneshot_example.c
                # TODO please change to relative dir
                examples/mcuxClPsaDriver/mcuxClPsaDriver_truncated_mac_oneshot_example.c
    )
    mcux_add_include(
        INCLUDES ./
                 examples/mcuxCsslFlowProtection/inc
    )
endif()
