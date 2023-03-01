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

// TODO: Add test vectors for AES-192

/* MISRA Ex. 20 - Rule 5.1 */
/* EntropyInput = ed1e7f21ef66ea5d8e2a85b9337245445b71d6393a4eecb0e63c193d0f72f9a9 */
static const uint32_t mcuxClRandomModes_TestVectors_Entropy_Aes128_PrDisabled[] =
{
  0x217f1eedu, 0x5dea66efu, 0xb9852a8eu, 0x44457233u,
  0x39d6715bu, 0xb0ec4e3au, 0x3d193ce6u, 0xa9f9720fu

};
/* MISRA Ex. 20 - Rule 5.1 */
/* EntropyInput = e4bc23c5089a19d86f4119cb3fa08c0a4991e0a1def17e101e4c14d9c323460a7c2fb58e0b086c6c57b55f56cae25bad */
static const uint32_t mcuxClRandomModes_TestVectors_Entropy_Aes256_PrDisabled[] =
{
  0xc523bce4u, 0xd8199a08u, 0xcb19416fu, 0x0a8ca03fu,
  0xa1e09149u, 0x107ef1deu, 0xd9144c1eu, 0x0a4623c3u,
  0x8eb52f7cu, 0x6c6c080bu, 0x565fb557u, 0xad5be2cau
};


/* MISRA Ex. 20 - Rule 5.1 */
/* EntropyInputReseed = 303fb519f0a4e17d6df0b6426aa0ecb2a36079bd48be47ad2a8dbfe48da3efad */
static const uint32_t mcuxClRandomModes_TestVectors_Entropy_Reseed_Aes128_PrDisabled[] =
{
  0x19b53f30u, 0x7de1a4f0u, 0x42b6f06du, 0xb2eca06au,
  0xbd7960a3u, 0xad47be48u, 0xe4bf8d2au, 0xadefa38du

};
/* MISRA Ex. 20 - Rule 5.1 */
/* EntropyInputReseed = fd85a836bba85019881e8c6bad23c9061adc75477659acaea8e4a01dfe07a1832dad1c136f59d70f8653a5dc118663d6 */
static const uint32_t mcuxClRandomModes_TestVectors_Entropy_Reseed_Aes256_PrDisabled[] =
{
  0x36a885fdu, 0x1950a8bbu, 0x6b8c1e88u, 0x06c923adu,
  0x4775dc1au, 0xaeac5976u, 0x1da0e4a8u, 0x83a107feu,
  0x131cad2du, 0x0fd7596fu, 0xdca55386u, 0xd6638611u
};


/* MISRA Ex. 20 - Rule 5.1 */
//Key, V after Init (No PR)
/* Key = b5fc83ef1518da3cb85598ee9795001e */
static const uint32_t mcuxClRandomModes_TestVectors_Init_Aes128_Key_PrDisabled[] =
{
  0xef83fcb5u, 0x3cda1815u, 0xee9855b8u, 0x1e009597u
};
/* MISRA Ex. 20 - Rule 5.1 */
/* Key = b7b3a93ecfdf2f61c622ad3afb6bff818736a09c9391157e1902d10a79d0db12 */
static const uint32_t mcuxClRandomModes_TestVectors_Init_Aes256_Key_PrDisabled[] = {
  0x3ea9b3b7u, 0x612fdfcfu, 0x3aad22c6u, 0x81ff6bfbu,
  0x9ca03687u, 0x7e159193u, 0x0ad10219u, 0x12dbd079u
};


/* MISRA Ex. 20 - Rule 5.1 */
/* V   = 58f90cf75af84f221514db847ec007d1 */
static const uint32_t mcuxClRandomModes_TestVectors_Init_Aes128_V_PrDisabled[] = {
  0xf70cf958u, 0x224ff85au, 0x84db1415u, 0xd107c07eu
};
/* MISRA Ex. 20 - Rule 5.1 */
/* V   = 0e4fb6443cae46188617aad8bfe46e23 */
static const uint32_t mcuxClRandomModes_TestVectors_Init_Aes256_V_PrDisabled[] = {
  0x44b64f0eu, 0x1846ae3cu, 0xd8aa1786u, 0x236ee4bfu
};


/* MISRA Ex. 20 - Rule 5.1 */
//Key, V after Reseed (No PR)
/* Key = 577a79cc512258c3e255fcf3f4cf0c1a */
static const uint32_t mcuxClRandomModes_TestVectors_Reseed_Aes128_Key_PrDisabled[] = {
  0xcc797a57u, 0xc3582251u, 0xf3fc55e2u, 0x1a0ccff4u,
};
/* MISRA Ex. 20 - Rule 5.1 */
/* Key = d230044c2594510d195ffe9923de8848bdbd19f24d0e7558b28e55b2d4de7841 */
static const uint32_t mcuxClRandomModes_TestVectors_Reseed_Aes256_Key_PrDisabled[] = {
  0x4c0430d2u, 0x0d519425u, 0x99fe5f19u, 0x4888de23u,
  0xf219bdbdu, 0x58750e4du, 0xb2558eb2u, 0x4178ded4u
};


/* MISRA Ex. 20 - Rule 5.1 */
/* V   = 531599fd616f33678192928bf771bb2b */
static const uint32_t mcuxClRandomModes_TestVectors_Reseed_Aes128_V_PrDisabled[] = {
  0xfd991553u, 0x67336f61u, 0x8b929281u, 0x2bbb71f7u

};
/* MISRA Ex. 20 - Rule 5.1 */
/* V   = e18637ff12f514f37adc2013a40f38c1 */
static const uint32_t mcuxClRandomModes_TestVectors_Reseed_Aes256_V_PrDisabled[] = {
  0xff3786e1u, 0xf314f512u, 0x1320dc7au, 0xc1380fa4u
};


/* MISRA Ex. 20 - Rule 5.1 */
//Key, V after first Generate (No PR)
/* Key = ac373fb3773597b0d6cb6f37e6b59293 */
static const uint32_t mcuxClRandomModes_TestVectors_GenOne_Aes128_Key_PrDisabled[] = {
  0xb33f37acu, 0xb0973577u, 0x376fcbd6u, 0x9392b5e6u

};
/* MISRA Ex. 20 - Rule 5.1 */
/* Key = ec871bb7a4f2c45dccdd0e514a21628959aa21e9643934f619b2709b3e38697c */
static const uint32_t mcuxClRandomModes_TestVectors_GenOne_Aes256_Key_PrDisabled[] = {
  0xb71b87ecu, 0x5dc4f2a4u, 0x510eddccu, 0x8962214au,
  0xe921aa59u, 0xf6343964u, 0x9b70b219u, 0x7c69383eu
};


/* MISRA Ex. 20 - Rule 5.1 */
/* V   = cd9bf115d35c60cbf7f2ebac8e43f53b */
static const uint32_t mcuxClRandomModes_TestVectors_GenOne_Aes128_V_PrDisabled[] = {
  0x15f19bcdu, 0xcb605cd3u, 0xacebf2f7u, 0x3bf5438eu
};
/* MISRA Ex. 20 - Rule 5.1 */
/* V   = d8bbe7bfc60bfb710f39acd1088c9f41 */
static const uint32_t mcuxClRandomModes_TestVectors_GenOne_Aes256_V_PrDisabled[] = {
  0xbfe7bbd8u, 0x71fb0bc6u, 0xd1ac390fu, 0x419f8c08u
};


/* MISRA Ex. 20 - Rule 5.1 */
//Key, V, Random after second Generate (No PR)
/* Key = 964c57946a104aa93fc3c2137bb9bc11 */
static const uint32_t mcuxClRandomModes_TestVectors_GenTwo_Aes128_Key_PrDisabled[] = {
  0x94574c96u, 0xa94a106au, 0x13c2c33fu, 0x11bcb97bu
};
/* MISRA Ex. 20 - Rule 5.1 */
/* Key = e728308a0e92cbacb269d12246d8e2d24cf5fcc678aa09564132e4972c456eda */
static const uint32_t mcuxClRandomModes_TestVectors_GenTwo_Aes256_Key_PrDisabled[] = {
  0x8a3028e7u, 0xaccb920eu, 0x22d169b2u, 0xd2e2d846u,
  0xc6fcf54cu, 0x5609aa78u, 0x97e43241u, 0xda6e452cu
};


/* MISRA Ex. 20 - Rule 5.1 */
/* V   = 9d58008033ac007c9ead254bfa8de2b6 */
static const uint32_t mcuxClRandomModes_TestVectors_GenTwo_Aes128_V_PrDisabled[] = {
  0x8000589du, 0x7c00ac33u, 0x4b25ad9eu, 0xb6e28dfau
};
/* MISRA Ex. 20 - Rule 5.1 */
/* V   = c95f38da34ecb65ebf8b34c32bc215a5 */
static const uint32_t mcuxClRandomModes_TestVectors_GenTwo_Aes256_V_PrDisabled[] = {
  0xda385fc9u, 0x5eb6ec34u, 0xc3348bbfu, 0xa515c22bu
};


/* MISRA Ex. 20 - Rule 5.1 */
/* ReturnedBits = f80111d08e874672f32f42997133a5210f7a9375e22cea70587f9cfafebe0f6a6aa2eb68e7dd9164536d53fa020fcab20f54caddfab7d6d91e5ffec1dfd8deaa */
static const uint32_t mcuxClRandomModes_TestVectors_RandomData_Aes128_PrDisabled[] = {
  0xd01101f8u, 0x7246878eu, 0x99422ff3u, 0x21a53371u,
  0x75937a0fu, 0x70ea2ce2u, 0xfa9c7f58u, 0x6a0fbefeu,
  0x68eba26au, 0x6491dde7u, 0xfa536d53u, 0xb2ca0f02u,
  0xddca540fu, 0xd9d6b7fau, 0xc1fe5f1eu, 0xaaded8dfu
};
/* MISRA Ex. 20 - Rule 5.1 */
/* ReturnedBits = b2cb8905c05e5950ca31895096be29ea3d5a3b82b269495554eb80fe07de43e193b9e7c3ece73b80e062b1c1f68202fbb1c52a040ea2478864295282234aaada */
static const uint32_t mcuxClRandomModes_TestVectors_RandomData_Aes256_PrDisabled[] = {
  0x0589cbb2u, 0x50595ec0u, 0x508931cau, 0xea29be96u,
  0x823b5a3du, 0x554969b2u, 0xfe80eb54u, 0xe143de07u,
  0xc3e7b993u, 0x803be7ecu, 0xc1b162e0u, 0xfb0282f6u,
  0x042ac5b1u, 0x8847a20eu, 0x82522964u, 0xdaaa4a23u
};
#endif

static const uint32_t * const mcuxClRandomModes_TestVectors_Aes128_PrDisabled[MCUXCLRANDOMMODES_NO_OF_TESTVECTORS_PRDISABLED] =
{
 mcuxClRandomModes_TestVectors_Entropy_Aes128_PrDisabled,
  mcuxClRandomModes_TestVectors_Entropy_Reseed_Aes128_PrDisabled,
  mcuxClRandomModes_TestVectors_Init_Aes128_Key_PrDisabled,
  mcuxClRandomModes_TestVectors_Init_Aes128_V_PrDisabled,
  mcuxClRandomModes_TestVectors_Reseed_Aes128_Key_PrDisabled,
  mcuxClRandomModes_TestVectors_Reseed_Aes128_V_PrDisabled,
  mcuxClRandomModes_TestVectors_GenOne_Aes128_Key_PrDisabled,
  mcuxClRandomModes_TestVectors_GenOne_Aes128_V_PrDisabled,
  mcuxClRandomModes_TestVectors_GenTwo_Aes128_Key_PrDisabled,
  mcuxClRandomModes_TestVectors_GenTwo_Aes128_V_PrDisabled,
  mcuxClRandomModes_TestVectors_RandomData_Aes128_PrDisabled
};

static const uint32_t * const mcuxClRandomModes_TestVectors_Aes256_PrDisabled[MCUXCLRANDOMMODES_NO_OF_TESTVECTORS_PRDISABLED] =
{
  mcuxClRandomModes_TestVectors_Entropy_Aes256_PrDisabled,
  mcuxClRandomModes_TestVectors_Entropy_Reseed_Aes256_PrDisabled,
  mcuxClRandomModes_TestVectors_Init_Aes256_Key_PrDisabled,
  mcuxClRandomModes_TestVectors_Init_Aes256_V_PrDisabled,
  mcuxClRandomModes_TestVectors_Reseed_Aes256_Key_PrDisabled,
  mcuxClRandomModes_TestVectors_Reseed_Aes256_V_PrDisabled,
  mcuxClRandomModes_TestVectors_GenOne_Aes256_Key_PrDisabled,
  mcuxClRandomModes_TestVectors_GenOne_Aes256_V_PrDisabled,
  mcuxClRandomModes_TestVectors_GenTwo_Aes256_Key_PrDisabled,
  mcuxClRandomModes_TestVectors_GenTwo_Aes256_V_PrDisabled,
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
    .pDrbgTestVectors = mcuxClRandomModes_TestVectors_Aes128_PrDisabled   /* ToDo done in CLNS-5053. */
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


