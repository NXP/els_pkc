/*--------------------------------------------------------------------------*/
/* Copyright 2021-2023 NXP                                                  */
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
/* Security Classification:  Company Confidential                           */
/*--------------------------------------------------------------------------*/

#include <mcuxClRandomModes.h>
#include <mcuxClSession.h>
#include <mcuxClCore_Analysis.h>

#include <mcuxClRandomModes_MemoryConsumption.h>
#include <internal/mcuxClRandom_Internal_Types.h>
#include <internal/mcuxClRandomModes_Private_CtrDrbg.h>
#include <internal/mcuxClRandomModes_Private_NormalMode.h>
#include <internal/mcuxClRandomModes_Private_PrDisabled.h>
#include <internal/mcuxClRandomModes_Private_Drbg.h>

#ifdef RANDOMMODES_DERIVATION_FUNCTION
/* Constants for RNG health testing
 * This data originates from  NIST DRBG test vectors (NIST SP 800-90A DRBGVS)
 * Use DF,
 * No PR,
 * NonceLen = 0,
 * PersonalizationStringLen = 0,
 * AdditionalInputLen = 0
 * Random data is read after second generate call
 *
 * Data has been adapted from BE Byte Order to LE Byte Order
 */
// TODO: Add test vectors for the "use derivation function case"
#else
/* Constants for RNG health testing
 * This data originates from  NIST DRBG test vectors (NIST SP 800-90A DRBGVS)
 * No DF,
 * No PR,
 * NonceLen = 0,
 * PersonalizationStringLen = 0,
 * AdditionalInputLen = 0
 * Random data is read after second generate call
 *
 * Data has been adapted from BE Byte Order to LE Byte Order
 */


/* EntropyInput = db6a6c4d5f17710eb1a65e7f82b390ffaf8f2c43f43eef29e4ffc350a2f475339c7b2d12259c9d */
MCUXCLCORE_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static const uint32_t mcuxClRandomModes_TestVectors_Entropy_Init_Aes128_PrDisabled[] =
MCUXCLCORE_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  0x4d6c6adbu, 0x0e71175fu, 0x7f5ea6b1u, 0xff90b382u, 0x432c8fafu, 0x29ef3ef4u, 0x50c3ffe4u, 0x3375f4a2u,
  0x122d7b9cu, 0x009d9c25u
};
/* EntropyInput = 6c0764088dd3d30d93ed2cbbe6a8ac115098e458e74d34527ecd4183df2bb34a07c934a8793cc5c76a2a94cb7aa1fe2cd1b615d566b204 */
MCUXCLCORE_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static const uint32_t mcuxClRandomModes_TestVectors_Entropy_Init_Aes192_PrDisabled[] =
MCUXCLCORE_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  0x0864076cu, 0x0dd3d38du, 0xbb2ced93u, 0x11aca8e6u, 0x58e49850u, 0x52344de7u, 0x8341cd7eu, 0x4ab32bdfu,
  0xa834c907u, 0xc7c53c79u, 0xcb942a6au, 0x2cfea17au, 0xd515b6d1u, 0x0004b266u
};
/* EntropyInput = 04e6975d5082bf4593c1fd93c2020624ee887666cec3fec73d6bcd376cba3f0f18c07c7ef6773a145a7f9e926cb3cd2c42cc66b30a52ec1c7a75964712933985f5e8b42d4af007 */
MCUXCLCORE_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static const uint32_t mcuxClRandomModes_TestVectors_Entropy_Init_Aes256_PrDisabled[] =
MCUXCLCORE_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  0x5d97e604u, 0x45bf8250u, 0x93fdc193u, 0x240602c2u, 0x667688eeu, 0xc7fec3ceu, 0x37cd6b3du, 0x0f3fba6cu,
  0x7e7cc018u, 0x143a77f6u, 0x929e7f5au, 0x2ccdb36cu, 0xb366cc42u, 0x1cec520au, 0x4796757au, 0x85399312u,
  0x2db4e8f5u, 0x0007f04au
};


/* EntropyInputReseed = 3e3a397ad3edbd5d2505814805f51f20f356d541cb40f9 */
MCUXCLCORE_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static const uint32_t mcuxClRandomModes_TestVectors_Entropy_Reseed_Aes128_PrDisabled[] =
MCUXCLCORE_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  0x7a393a3eu, 0x5dbdedd3u, 0x48810525u, 0x201ff505u, 0x41d556f3u, 0x00f940cbu
};
/* EntropyInputReseed = 58c7b1da4f8b13a2acb8648ab51e36131ed31289c0924f2e6739e1b41c74039714d28c913573e5 */
MCUXCLCORE_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static const uint32_t mcuxClRandomModes_TestVectors_Entropy_Reseed_Aes192_PrDisabled[] =
MCUXCLCORE_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  0xdab1c758u, 0xa2138b4fu, 0x8a64b8acu, 0x13361eb5u, 0x8912d31eu, 0x2e4f92c0u, 0xb4e13967u, 0x9703741cu,
  0x918cd214u, 0x00e57335u
};
/* EntropyInputReseed = 41e7cf20e5b487d9d981ed7a0186872d774e610b4e246c5a899da1f4a0538c05c6d43b9726575560d3a6c4117f39cba6ba9eef65a8469d */
MCUXCLCORE_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static const uint32_t mcuxClRandomModes_TestVectors_Entropy_Reseed_Aes256_PrDisabled[] =
MCUXCLCORE_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  0x20cfe741u, 0xd987b4e5u, 0x7aed81d9u, 0x2d878601u, 0x0b614e77u, 0x5a6c244eu, 0xf4a19d89u, 0x058c53a0u,
  0x973bd4c6u, 0x60555726u, 0x11c4a6d3u, 0xa6cb397fu, 0x65ef9ebau, 0x009d46a8u
};


/* ReturnedBits = 7a766353d1b809fd97d89219972debbce3f53d1be1b3dbddf1e4c2e15954e1338d0ff1f411326348f1e85a29b5feeb93554eb54a98c3b0e691f244dad72fd80b */
MCUXCLCORE_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static const uint32_t mcuxClRandomModes_TestVectors_RandomData_Aes128_PrDisabled[] =
MCUXCLCORE_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  0x5363767au, 0xfd09b8d1u, 0x1992d897u, 0xbceb2d97u, 0x1b3df5e3u, 0xdddbb3e1u, 0xe1c2e4f1u, 0x33e15459u,
  0xf4f10f8du, 0x48633211u, 0x295ae8f1u, 0x93ebfeb5u, 0x4ab54e55u, 0xe6b0c398u, 0xda44f291u, 0x0bd82fd7u
};
/* ReturnedBits = 35f96c8d58335a75b537d3c794d6a363619bf76f1f28fe6595c9630e9e5e2770093c20bedffd17778105d52654cd27cd20ad46b8fba58926b2401344c8a493bc */
MCUXCLCORE_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static const uint32_t mcuxClRandomModes_TestVectors_RandomData_Aes192_PrDisabled[] =
MCUXCLCORE_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  0x8d6cf935u, 0x755a3358u, 0xc7d337b5u, 0x63a3d694u, 0x6ff79b61u, 0x65fe281fu, 0x0e63c995u, 0x70275e9eu,
  0xbe203c09u, 0x7717fddfu, 0x26d50581u, 0xcd27cd54u, 0xb846ad20u, 0x2689a5fbu, 0x441340b2u, 0xbc93a4c8u
};
/* ReturnedBits = 8e929981e59b246182c93b161a0f7900b1a65bff6579ab3dbf13ac040e9eb7964c23e17ece53d5e68adcae46c9feb06f4d48601f3483dbce99c314aa77a95f92 */
MCUXCLCORE_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static const uint32_t mcuxClRandomModes_TestVectors_RandomData_Aes256_PrDisabled[] = {
MCUXCLCORE_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
  0x8199928eu, 0x61249be5u, 0x163bc982u, 0x00790f1au, 0xff5ba6b1u, 0x3dab7965u, 0x04ac13bfu, 0x96b79e0eu,
  0x7ee1234cu, 0xe6d553ceu, 0x46aedc8au, 0x6fb0fec9u, 0x1f60484du, 0xcedb8334u, 0xaa14c399u, 0x925fa977u
};
#endif

static const uint32_t * const mcuxClRandomModes_TestVectors_Aes128_PrDisabled[MCUXCLRANDOMMODES_NO_OF_TESTVECTORS_PRDISABLED] =
{
  mcuxClRandomModes_TestVectors_Entropy_Init_Aes128_PrDisabled,
  mcuxClRandomModes_TestVectors_Entropy_Reseed_Aes128_PrDisabled,
  mcuxClRandomModes_TestVectors_RandomData_Aes128_PrDisabled
};

MCUXCLCORE_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static const uint32_t * const mcuxClRandomModes_TestVectors_Aes192_PrDisabled[MCUXCLRANDOMMODES_NO_OF_TESTVECTORS_PRDISABLED] =
MCUXCLCORE_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  mcuxClRandomModes_TestVectors_Entropy_Init_Aes192_PrDisabled,
  mcuxClRandomModes_TestVectors_Entropy_Reseed_Aes192_PrDisabled,
  mcuxClRandomModes_TestVectors_RandomData_Aes192_PrDisabled
};

MCUXCLCORE_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()
static const uint32_t * const mcuxClRandomModes_TestVectors_Aes256_PrDisabled[MCUXCLRANDOMMODES_NO_OF_TESTVECTORS_PRDISABLED] =
MCUXCLCORE_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
{
  mcuxClRandomModes_TestVectors_Entropy_Init_Aes256_PrDisabled,
  mcuxClRandomModes_TestVectors_Entropy_Reseed_Aes256_PrDisabled,
  mcuxClRandomModes_TestVectors_RandomData_Aes256_PrDisabled
};

/* MISRA Ex. 20 - Rule 5.1 */
static const mcuxClRandomModes_DrbgModeDescriptor_t mcuxClRandomModes_DrbgModeDescriptor_CtrDrbg_AES128_PrDisabled =
{
    .pDrbgAlgorithms = &mcuxClRandomModes_DrbgAlgorithmsDescriptor_CtrDrbg,
    .pDrbgVariant = &mcuxClRandomModes_DrbgVariantDescriptor_CtrDrbg_AES128,
    .pDrbgTestVectors = mcuxClRandomModes_TestVectors_Aes128_PrDisabled
};

/* MISRA Ex. 20 - Rule 5.1 */
static const mcuxClRandomModes_DrbgModeDescriptor_t mcuxClRandomModes_DrbgModeDescriptor_CtrDrbg_AES192_PrDisabled =
{
    .pDrbgAlgorithms = &mcuxClRandomModes_DrbgAlgorithmsDescriptor_CtrDrbg,
    .pDrbgVariant = &mcuxClRandomModes_DrbgVariantDescriptor_CtrDrbg_AES192,
    .pDrbgTestVectors = mcuxClRandomModes_TestVectors_Aes192_PrDisabled
};

/* MISRA Ex. 20 - Rule 5.1 */
static const mcuxClRandomModes_DrbgModeDescriptor_t mcuxClRandomModes_DrbgModeDescriptor_CtrDrbg_AES256_PrDisabled =
{
    .pDrbgAlgorithms = &mcuxClRandomModes_DrbgAlgorithmsDescriptor_CtrDrbg,
    .pDrbgVariant = &mcuxClRandomModes_DrbgVariantDescriptor_CtrDrbg_AES256,
    .pDrbgTestVectors = mcuxClRandomModes_TestVectors_Aes256_PrDisabled
};


/* MISRA Ex. 20 - Rule 5.1 */
/* Mode descriptors for NIST SP800-90A CTR_DRBGs with DRG.3 security level */
const mcuxClRandom_ModeDescriptor_t mcuxClRandomModes_mdCtrDrbg_AES128_DRG3 = {
    .pOperationMode   = &mcuxClRandomModes_OperationModeDescriptor_NormalMode_PrDisabled,
    .pDrbgMode        = (void *)&mcuxClRandomModes_DrbgModeDescriptor_CtrDrbg_AES128_PrDisabled,
    .contextSize      = MCUXCLRANDOMMODES_CTR_DRBG_AES128_CONTEXT_SIZE,
    .auxParam         = 0u,
    .securityStrength = MCUXCLRANDOMMODES_SECURITYSTRENGTH_CTR_DRBG_AES128
};

/* MISRA Ex. 20 - Rule 5.1 */
const mcuxClRandom_ModeDescriptor_t mcuxClRandomModes_mdCtrDrbg_AES192_DRG3 = {
    .pOperationMode   = &mcuxClRandomModes_OperationModeDescriptor_NormalMode_PrDisabled,
    .pDrbgMode        = (void *)&mcuxClRandomModes_DrbgModeDescriptor_CtrDrbg_AES192_PrDisabled,
    .contextSize      = MCUXCLRANDOMMODES_CTR_DRBG_AES192_CONTEXT_SIZE,
    .auxParam         = 0u,
    .securityStrength = MCUXCLRANDOMMODES_SECURITYSTRENGTH_CTR_DRBG_AES192
};

/* MISRA Ex. 20 - Rule 5.1 */
const mcuxClRandom_ModeDescriptor_t mcuxClRandomModes_mdCtrDrbg_AES256_DRG3 = {
    .pOperationMode   = &mcuxClRandomModes_OperationModeDescriptor_NormalMode_PrDisabled,
    .pDrbgMode        = (void *)&mcuxClRandomModes_DrbgModeDescriptor_CtrDrbg_AES256_PrDisabled,
    .contextSize      = MCUXCLRANDOMMODES_CTR_DRBG_AES256_CONTEXT_SIZE,
    .auxParam         = 0u,
    .securityStrength = MCUXCLRANDOMMODES_SECURITYSTRENGTH_CTR_DRBG_AES256
};


