/*--------------------------------------------------------------------------*/
/* Copyright 2023 NXP                                                       */
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

#include <mcuxClSession.h>          // Interface to the entire mcuxClSession component
#include <mcuxClOsccaSafo.h>
#include <mcuxCsslFlowProtection.h> // Code flow protection
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>

static const uint32_t plaintext[4U] = {
    0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210
};
static const uint32_t key[4U] = {
    0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210
};
static const uint32_t reference_ciphertext[4U] = {
    0x681edf34, 0xd206965e, 0x86b3e94f, 0x536e4246
};

static const uint32_t reference_ciphertext_reversed[4U] = {
    0x681edf34, 0xd206965e, 0x86b3e94f, 0x536e4246
};

static const uint32_t plaintext_1[64U] = {
    0xcc76f7ed, 0x48e797d7, 0xf3411d2a, 0x3b07383a, 0xbb028be7, 0x0818bc71, 0x2584a8f5, 0x8b930f48, 0xb076e7f9, 0xddd0fb19,
    0x91bbee39, 0xcfaec42b, 0xc9728b01, 0x740d007d, 0x85a2d4c0, 0x64655f96, 0x8b5a5eef, 0x59aa1c92, 0x83bb6552, 0x28348541,
    0x4e1061fb, 0x3ea4331d, 0x7a8fa63c, 0x1f757103, 0xcf9b7077, 0x1c1c1034, 0xaa296211, 0x438212f4, 0x8ddcbbd9, 0x8adad563,
    0x562c4d61, 0x963a73fb, 0xc90ae940, 0x73ef771a, 0xe61d1d62, 0xc9668e50, 0xd2f94109, 0x9ed9d81b, 0x976f6428, 0xe9dc1de7,
    0x051272a2, 0xd9f0e160, 0x51ba0963, 0xa6d9e018, 0x3d40147e, 0xf92b006e, 0xe328080d, 0x9e373d4b, 0x5618eeaa, 0x027baeac,
    0x44cecaf7, 0xcd5f7095, 0xeb96042e, 0x9e8de364, 0x3639b659, 0x5958768d, 0x4699a2ae, 0xd75cfa4b, 0x125d25b0, 0x88de322e,
    0xeb0416e3, 0x84b78c30, 0xd3d38d3b, 0x5c4f6358,
};
static const uint32_t key_1[4U] = {
    0x7cac4fd7, 0xed3400b9, 0xa29f1808, 0xf6281332
};
static const uint32_t reference_ciphertext_1[64U] = {
    0x4b0505f3, 0x17af787a, 0x64194edd, 0xc189924c, 0x2bdb8fb1, 0x427fd61a, 0xb2f5aeb6, 0x4aa3f108, 0x38b57edc, 0x0faa4f9a,
    0x9f268b2c, 0xe84c95b5, 0x67aa4c1d, 0x854880e9, 0x6b92ab47, 0xcb012424, 0x2c68aaa1, 0x28955084, 0x4a16012f, 0x7a3c435f,
    0x446cb421, 0xed73c7d6, 0xc1d52ff4, 0x395a7617, 0xc9f0db0a, 0x44f16b5f, 0x258269d1, 0xa656812e, 0xe371f080, 0x302b4685,
    0xcd7ac9f2, 0xa380c2d9, 0x8629fdfa, 0x151916bb, 0x448d362e, 0xca81f1a8, 0x0f963c07, 0x53a559d1, 0x30034d64, 0xac36133e,
    0x59938073, 0xdf2d6b8a, 0xb8d73d5d, 0x5aacb18d, 0x3a9b6dc4, 0x822a91c8, 0x13ed832d, 0x6a4afb4c, 0xf69b95d2, 0x29583f2c,
    0x88f15cd1, 0xc5a4daf3, 0x9eeb2451, 0x403e4e3b, 0xe99670e5, 0xc7a6cab7, 0x4ad0c334, 0x1177a217, 0xf9464f98, 0x5d26b9ea,
    0x9baa5c88, 0xc98db450, 0x8e09ca37, 0x137714a6
};

static const uint32_t plaintext_2[16U] = {
    0x2e7c4271, 0x72299c55, 0x729651a0, 0x938b1ce9, 0x1aa917d3, 0xd6f8da3c, 0x482a5628, 0xc94d9089,
    0x0a1a0228, 0x58cc838c, 0x3c0df801, 0xb73d7b63, 0xb5b92e04, 0x09392591, 0x7dd04c41, 0xcf1b811b
};
static const uint32_t key_2[4U] = {
    0xdcbad818, 0x947e5137, 0x7bd311ee, 0x7fdcba0e
};
static const uint32_t reference_ciphertext_2[16U] = {
    0x9bbfcf91, 0x4be86872, 0x8990bbe9, 0x1febca41,
    0xf40528c4, 0xc4018712, 0x88b8402a, 0x66e5ea72,
    0xe46205cb, 0x3054f659, 0x539de41d, 0x19df6d8b,
    0xfc2b185c, 0xd44052c0, 0xe8181f78, 0x6428f1df
};

/*
 * decrypt = 0 -> perform encrypt operation
 * decrypt = 1 -> perform decrypt operation
 */
void SM4_Operation(uint8_t decrypt, const uint32_t *input, const uint32_t *key, uint32_t *result)
{
    /* load plaintext/ciphertext */
    mcuxClOsccaSafo_Drv_load(0, input[3]);
    mcuxClOsccaSafo_Drv_load(1, input[2]);
    mcuxClOsccaSafo_Drv_load(2, input[1]);
    mcuxClOsccaSafo_Drv_load(3, input[0]);

    /* load key */
    mcuxClOsccaSafo_Drv_loadKey(0, key[3]);
    mcuxClOsccaSafo_Drv_loadKey(1, key[2]);
    mcuxClOsccaSafo_Drv_loadKey(2, key[1]);
    mcuxClOsccaSafo_Drv_loadKey(3, key[0]);

    /* Setup control SFRs:
     * SM4_EN = 1'b1
     * CRYPTO_OP = 3'b110 (SM4)
     * DECRYPT = 1'b0 (ENC) / 1'b1 (DEC) ('decrypt' value)
     * DATOUT_RES = 2'b00 (END_UP)
     * INSEL = 'h0
     * INKEYSEL = 'h0
     * OUTSEL = 'h0
     * START = 1'b1
     */
    mcuxClOsccaSafo_Drv_start(MCUXCLOSCCASAFO_DRV_CTRL_SM4_EN
                      | MCUXCLOSCCASAFO_DRV_CTRL_SM4
                      | ((decrypt == 1u)?MCUXCLOSCCASAFO_DRV_CTRL_DEC:MCUXCLOSCCASAFO_DRV_CTRL_ENC)
                      | MCUXCLOSCCASAFO_DRV_CTRL_END_UP
                      | MCUXCLOSCCASAFO_DRV_CTRL_INSEL_DATIN0
                      | MCUXCLOSCCASAFO_DRV_CTRL_INKEYSEL(0u)
                      | MCUXCLOSCCASAFO_DRV_CTRL_OUTSEL_RES);

    /* wait for AES operation to complete (polling 'busy' status bit) */
    mcuxClOsccaSafo_Drv_wait();

    /* read the result */
    result[3] = mcuxClOsccaSafo_Drv_store(0);
    result[2] = mcuxClOsccaSafo_Drv_store(1);
    result[1] = mcuxClOsccaSafo_Drv_store(2);
    result[0] = mcuxClOsccaSafo_Drv_store(3);
}

bool mcuxClOsccaSafo_sm4_example(void)
{
    mcuxClOsccaSafo_Drv_enableFlush(MCUXCLOSCCASAFO_DRV_FLUSH_ALL);
    mcuxClOsccaSafo_Drv_init(0U);

    /*
    Encrypt test vector (1 block message)
    Input:
        message = 0123456789abcdeffedcba9876543210
        key = 0123456789abcdeffedcba9876543210

    Output (encrypt operation):
        ciphertext = 681edf34d206965e86b3e94f536e4246
    */
    uint32_t result_ciphertext[4U] = {0U};

    SM4_Operation(0x00, plaintext, key, result_ciphertext);
    /* check if actual result is equal to expected result */
    if (true != mcuxClCore_assertEqual((uint8_t*)result_ciphertext, (uint8_t*)reference_ciphertext, sizeof(reference_ciphertext)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }


    /*
    Decrypt test vector (1 block message)
    Input:
        message = 681edf34d206965e86b3e94f536e4246
        key = 0123456789abcdeffedcba9876543210

    Output (decrypt operation):
        ciphertext = 0123456789abcdeffedcba9876543210
    */
    uint32_t result_ciphertextRev[4U] = {0U};

    SM4_Operation(0x01, reference_ciphertext_reversed, key, result_ciphertextRev);
    /* check if actual result is equal to expected result */
    if (true != mcuxClCore_assertEqual((uint8_t*)result_ciphertextRev, (uint8_t*)plaintext, sizeof(plaintext)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /*
    Encrypt test vector (16 blocks message)
    Input:
        message = 2e7c427172299c55729651a0938b1ce91aa917d3d6f8da3c482a5628c94d90890a1a022858cc838c3c0df801b73d7b63b5b92e04093925917dd04c41cf1b811b
        key = dcbad818947e51377bd311ee7fdcba0e

    Output (encrypt operation):
        ciphertext = 9bbfcf914be868728990bbe91febca41f40528c4c401871288b8402a66e5ea72e46205cb3054f659539de41d19df6d8bfc2b185cd44052c0e8181f786428f1df
    */
    uint32_t result_ciphertext_1[64U];
    for (uint8_t i = 0; i < 16U; i++)
    {
        SM4_Operation(0x00, &plaintext_1[i * 4], key_1, &result_ciphertext_1[i * 4]);  /* process one SM4 block (16 bytes) per call */
    }
    /* check if actual result is equal to expected result */
    if (true != mcuxClCore_assertEqual((uint8_t*)result_ciphertext_1, (uint8_t*)reference_ciphertext_1, sizeof(reference_ciphertext_1)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /*
    Decrypt test vector (4 blocks message)
    Input:
        message = 2e7c427172299c55729651a0938b1ce91aa917d3d6f8da3c482a5628c94d90890a1a022858cc838c3c0df801b73d7b63b5b92e04093925917dd04c41cf1b811b
        key = dcbad818947e51377bd311ee7fdcba0e

    Output (encrypt operation):
        ciphertext = 9bbfcf914be868728990bbe91febca41f40528c4c401871288b8402a66e5ea72e46205cb3054f659539de41d19df6d8bfc2b185cd44052c0e8181f786428f1df
    */
    uint32_t result_ciphertext_2[16U];
    for (uint8_t i = 0U; i < 4U; i++)
    {
        SM4_Operation(0x01, &plaintext_2[i * 4], key_2, &result_ciphertext_2[i * 4]);  /* process one SM4 block (16 bytes) per call */
    }
    /* check if actual result is equal to expected result */
    if (true != mcuxClCore_assertEqual((uint8_t*)result_ciphertext_2, (uint8_t*)reference_ciphertext_2, sizeof(reference_ciphertext_2)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    uint32_t closeRet = mcuxClOsccaSafo_Drv_close();
    if(MCUXCLOSCCASAFO_STATUS_ERROR == closeRet)
    {
        /* If error flush whole SAFO */
        mcuxClOsccaSafo_Drv_enableFlush(MCUXCLOSCCASAFO_DRV_FLUSH_ALL);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}
