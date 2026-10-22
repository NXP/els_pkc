#---------------------------------------------
# Copyright 2026 NXP.
# SPDX-License-Identifier: BSD-3-Clause
#---------------------------------------------

########################
#    Documentation     #
########################
if (CONFIG_MCUX_COMPONENT_component.els_pkc_pqc.doc.mcxn)
    mcux_add_source(
        SOURCES
                doc/mcxn_pqc/html/*.*
                doc/mcxn_pqc/html/search/*.*
                LA_OPT_Online_Code_Hosting.htm
                ReleaseNotes_PQC.txt
                SBOM-MCU_CL-Nirvana_PQC_SDK_V6.0.0_PQC.spdx.json
                BASE_PATH ${SdkRootDirPath}/components/els_pkc/pqc/
    )

    mcux_add_include(
        INCLUDES ./
        BASE_PATH ${SdkRootDirPath}/components/els_pkc/pqc/
    )
endif()

########################
#    Static Libraries  #
########################
if (CONFIG_MCUX_COMPONENT_component.els_pkc_pqc.static_lib_pqc.mcxn)
    mcux_add_source(
        SOURCES static_library/mcxn/libclns_pqc.a
                static_library/mcxn/libclns_pqc.a.libsize
                static_library/mcxn/libclns_pqc.a.objsize
                BASE_PATH ${SdkRootDirPath}/components/els_pkc/pqc/
    )
    mcux_add_include(
        INCLUDES ./
        BASE_PATH ${SdkRootDirPath}/components/els_pkc/pqc/
    )
endif()

########################
#    Platform specific #
########################
if (CONFIG_MCUX_COMPONENT_component.els_pkc_pqc.platform_pqc.mcxn)
    mcux_add_source(
        SOURCES includes/platform/mcxn/mcuxClMlDsa_MemoryConsumption.h
                BASE_PATH ${SdkRootDirPath}/components/els_pkc/pqc/
    )
    mcux_add_include(
        INCLUDES ./
                 includes/platform/mcxn
                 BASE_PATH ${SdkRootDirPath}/components/els_pkc/pqc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc_pqc.platform_pqc.mimxrt)
    mcux_add_source(
        SOURCES includes/platform/mimxrt/mcuxClMlDsa_MemoryConsumption.h
                BASE_PATH ${SdkRootDirPath}/components/els_pkc/pqc/
    )
    mcux_add_include(
        INCLUDES ./
                 includes/platform/mimxrt
                 BASE_PATH ${SdkRootDirPath}/components/els_pkc/pqc/
    )
endif()

if (CONFIG_MCUX_COMPONENT_component.els_pkc_pqc.platform_pqc.rw61x)
    mcux_add_source(
        SOURCES includes/platform/rw61x/mcuxClMlDsa_MemoryConsumption.h
                BASE_PATH ${SdkRootDirPath}/components/els_pkc/pqc/
    )
    mcux_add_include(
        INCLUDES ./
                 includes/platform/rw61x
                 BASE_PATH ${SdkRootDirPath}/components/els_pkc/pqc/
    )
endif()

########################
#    Components        #
########################
if (CONFIG_MCUX_COMPONENT_component.els_pkc_pqc.mldsa)
    mcux_add_source(
        SOURCES src/comps/mcuxClMlDsa/src/mcuxClMlDsa_ExternalApi.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_KeyEncodings.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_KeyGen.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_KeyGenerationModes.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_KeyTypes.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_ModeConstructor.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_NTT.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_Packing.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_Params.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_Poly.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_Sign.c
                src/comps/mcuxClMlDsa/src/mcuxClMlDsa_Verify.c

                src/comps/mcuxClMlDsa/src/asm/mcuxClMlDsa_NTT_ForwardNTT_asm.S
                src/comps/mcuxClMlDsa/src/asm/mcuxClMlDsa_NTT_InverseNTT_asm.S
                src/comps/mcuxClMlDsa/src/asm/mcuxClMlDsa_NTT_PointMont_asm.S

                src/comps/mcuxClMlDsa/src/size/size.c

                src/comps/mcuxClMlDsa/inc/mcuxClMlDsa.h
                src/comps/mcuxClMlDsa/inc/mcuxClMlDsa_Constants.h
                src/comps/mcuxClMlDsa/inc/mcuxClMlDsa_KeyEncodings.h
                src/comps/mcuxClMlDsa/inc/mcuxClMlDsa_KeyTypes.h
                src/comps/mcuxClMlDsa/inc/mcuxClMlDsa_ModeConstructor.h
                src/comps/mcuxClMlDsa/inc/mcuxClMlDsa_Types.h

                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal.h
                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal_Constants.h
                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal_ExternalApi.h
                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal_Functions.h
                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal_InlineAssembly.h
                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal_NTT.h
                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal_Packing.h
                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal_Params.h
                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal_Poly.h
                src/comps/mcuxClMlDsa/inc/internal/mcuxClMlDsa_Internal_Types.h
                BASE_PATH ${SdkRootDirPath}/components/els_pkc/pqc/
    )
    mcux_add_include(
        INCLUDES ./
                 src/comps/mcuxClMlDsa/inc
                 src/comps/mcuxClMlDsa/inc/internal
                 BASE_PATH ${SdkRootDirPath}/components/els_pkc/pqc/
    )
endif()

########################
#    Examples          #
########################
if (CONFIG_MCUX_COMPONENT_component.els_pkc_pqc.examples_mldsa)
    mcux_add_source(
        SOURCES examples/mcuxClMlDsa/mcuxClSignature_MlDsa44_KeyGenDeterministic_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa44_KeyGenSignVerify_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa44_KeyGenSignVerify_PreHash_Ctx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa44_KeyGenSignVerify_PreHash_NoCtx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa44_KeyGenSignVerify_Pure_Ctx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa44_KeyGenSignVerify_Pure_NoCtx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa44_Verify_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa44_Verify_PreHash_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa65_KeyGenSignVerify_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa65_KeyGenSignVerify_PreHash_Ctx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa65_KeyGenSignVerify_PreHash_NoCtx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa65_KeyGenSignVerify_Pure_Ctx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa65_KeyGenSignVerify_Pure_NoCtx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa65_Verify_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa87_KeyGenSignVerify_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa87_KeyGenSignVerify_PreHash_Ctx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa87_KeyGenSignVerify_PreHash_NoCtx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa87_KeyGenSignVerify_Pure_Ctx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa87_KeyGenSignVerify_Pure_NoCtx_example.c
                examples/mcuxClMlDsa/mcuxClSignature_MlDsa87_Verify_example.c
                BASE_PATH ${SdkRootDirPath}/components/els_pkc/pqc/
    )
    mcux_add_include(
        INCLUDES ./
                 examples/mcuxClMlDsa
                 BASE_PATH ${SdkRootDirPath}/components/els_pkc/pqc/
    )
endif()
