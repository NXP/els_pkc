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
#include <mcuxClMemory.h>
#include <mcuxClOsccaSafo.h>
#include <mcuxCsslFlowProtection.h> // Code flow protection
#include <mcuxClCore_Examples.h>
#include <mcuxClExample_Session_Helper.h>

#ifdef MCUXCL_FEATURE_HW_SAFO_SM4
/* xorWr_test test vector */
static const uint32_t message[4U] = {
    0x8f4ba8e0, 0x297da02b, 0x5cf2f7a2, 0x4167c487
};

static const uint32_t xormessage[4U] = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000
};

/* SM4 Encrypt test vector (1 block message) */
static const uint32_t plaintext[4U] = {
    0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210
};
static const uint32_t key[4U] = {
    0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210
};
static const uint32_t reference_ciphertext[4U] = {
    0x681edf34, 0xd206965e, 0x86b3e94f, 0x536e4246
};

/* SM4 Ctr test vector (4 block message) */
static const uint8_t sm4CtrKey[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                                    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };


static const uint8_t sm4CtrPtxt[] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                                     0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
                                     0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
                                     0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
                                     0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
                                     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                     0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                                     0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB};
static const uint8_t sm4CtrIv[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
static const uint8_t sm4CtrCtxt[] = {0xAC,0x32,0x36,0xCB,0x97,0x0C,0xC2,0x07,
                                     0x91,0x36,0x4C,0x39,0x5A,0x13,0x42,0xD1,
                                     0xA3,0xCB,0xC1,0x87,0x8C,0x6F,0x30,0xCD,
                                     0x07,0x4C,0xCE,0x38,0x5C,0xDD,0x70,0xC7,
                                     0xF2,0x34,0xBC,0x0E,0x24,0xC1,0x19,0x80,
                                     0xFD,0x12,0x86,0x31,0x0C,0xE3,0x7B,0x92,
                                     0x6E,0x02,0xFC,0xD0,0xFA,0xA0,0xBA,0xF3,
                                     0x8B,0x29,0x33,0x85,0x1D,0x82,0x45,0x14};

#endif /* MCUXCL_FEATURE_HW_SAFO_SM4 */

#ifdef MCUXCL_FEATURE_HW_SAFO_SM3
/* SM3 Automatic mode, partial processing (4 padded blocks) */
static const uint32_t message_hash[64U] = {
    0x64fce814, 0xfa17cecf, 0x9a97c6a8, 0x15183f0d, 0xb881d336, 0x7eb90024, 0x7d997ee0, 0x27a25ed2, 0xaac0a62f, 0x0718227d,
    0xd6e82f17, 0xe6f56301, 0x1945d3e5, 0x8002e5c5, 0xd0dc66e2, 0x9b55c71c, 0xde0d6d87, 0xcd211331, 0x056b122d, 0x069c5562,
    0x10d29e62, 0xdfdaca25, 0x87fe07e1, 0x635bc44f, 0xd07bb099, 0x0e6af75c, 0x9b1f0139, 0xa117ef56, 0x39ab73c5, 0xf7f7793b,
    0xb2277b97, 0x49af279b, 0xf722b9c8, 0x4a786f12, 0x9e441112, 0xf184a9fe, 0x745cd390, 0xd4f4dadc, 0x773c31d0, 0x89c39c2e,
    0xb610dac9, 0x73bd5e3f, 0x13b14bf5, 0x25b43dd0, 0xc8591380, 0xb0424647, 0x82e6d4b8, 0x336abcda, 0x80000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000600
};
static const uint32_t reference_hash_hash[8U] = {
    0x5cf5619a, 0x84adcfc1, 0x9165d942, 0x19b32dfc, 0xd5baecde, 0x3fa93ce7, 0x1e675e62, 0xe2aa7ce5
};
#endif /* MCUXCL_FEATURE_HW_SAFO_SM3 */

#ifdef MCUXCL_FEATURE_HW_SAFO_SM4
/* Cover test case for mcuxClOsccaSafo_Drv_enableXorWrite and mcuxClOsccaSafo_Drv_disableXorWrite */
static bool xorWr_test(void)
{
    /* Cover test case for mcuxClOsccaSafo_Drv_enableXorWrite and mcuxClOsccaSafo_Drv_disableXorWrite */
    uint32_t pXorWrOut[4];

    //Copy input to SAFO
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 0, message[0]);
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 1, message[1]);
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 2, message[2]);
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 3, message[3]);

    uint32_t ctrl2Backup = mcuxClOsccaSafo_Drv_enableXorWrite();

    //Copy input to SAFO
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 0, message[0]);
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 1, message[1]);
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 2, message[2]);
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 3, message[3]);

    pXorWrOut[0] = mcuxClOsccaSafo_Drv_storeInput(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 0u);
    pXorWrOut[1] = mcuxClOsccaSafo_Drv_storeInput(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 1u);
    pXorWrOut[2] = mcuxClOsccaSafo_Drv_storeInput(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 2u);
    pXorWrOut[3] = mcuxClOsccaSafo_Drv_storeInput(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 3u);

    if(true != mcuxClCore_assertEqual((uint8_t*)pXorWrOut, (uint8_t*)xormessage, sizeof(xormessage)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    mcuxClOsccaSafo_Drv_disableXorWrite();

    //Copy input to SAFO
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 0, message[0]);
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 1, message[1]);
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 2, message[2]);
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 3, message[3]);

    //Copy input to SAFO
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 0, message[0]);
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 1, message[1]);
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 2, message[2]);
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 3, message[3]);

    pXorWrOut[0] = mcuxClOsccaSafo_Drv_storeInput(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 0u);
    pXorWrOut[1] = mcuxClOsccaSafo_Drv_storeInput(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 1u);
    pXorWrOut[2] = mcuxClOsccaSafo_Drv_storeInput(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 2u);
    pXorWrOut[3] = mcuxClOsccaSafo_Drv_storeInput(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 3u);

    if(true != mcuxClCore_assertEqual((uint8_t*)pXorWrOut, (uint8_t*)message, sizeof(message)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    mcuxClOsccaSafo_Drv_setControl2(ctrl2Backup);
    return MCUXCLEXAMPLE_STATUS_OK;
}


/* Cover test case for mcuxClOsccaSafo_Drv_incrementData and mcuxClOsccaSafo_Drv_dataOut_res */
static void sm4Ctr_test(const uint32_t *key, const uint32_t *pIv, const uint32_t *input, uint32_t inSize, uint32_t *pOut, uint32_t* outSize)
{
    /* Flush SAFO key registers */
    mcuxClOsccaSafo_Drv_enableFlush(MCUXCLOSCCASAFO_DRV_FLUSH_KEY);
    mcuxClOsccaSafo_Drv_init(0U);
    mcuxClOsccaSafo_Drv_wait();

    (void)mcuxClOsccaSafo_Drv_setByteOrder(MCUXCLOSCCASAFO_DRV_BYTE_ORDER_LE);
    mcuxClOsccaSafo_Drv_loadKey(0u, key[3]);
    mcuxClOsccaSafo_Drv_loadKey(1u, key[2]);
    mcuxClOsccaSafo_Drv_loadKey(2u, key[1]);
    mcuxClOsccaSafo_Drv_loadKey(3u, key[0]);

    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN1_INDEX + 0u, pIv[3]);  /* load the IV in DATIN1 */
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN1_INDEX + 1u, pIv[2]);  /* load the IV in DATIN1 */
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN1_INDEX + 2u, pIv[1]);  /* load the IV in DATIN1 */
    mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN1_INDEX + 3u, pIv[0]);  /* load the IV in DATIN1 */

    uint32_t remainingBytes = inSize;
    while(remainingBytes >= 16u)
    {
        //Process the first block, which may be smaller than 16u
        //Copy input to SAFO
        mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 0u, input[3]);  /* load the IV in DATIN1 */
        mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 1u, input[2]);  /* load the IV in DATIN1 */
        mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 2u, input[1]);  /* load the IV in DATIN1 */
        mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 3u, input[0]);  /* load the IV in DATIN1 */

        /* Keep track of the input bytes that are already copied */
        input += 16u / sizeof(uint32_t);

        //start_up
        (void)mcuxClOsccaSafo_Drv_dataOut_res(MCUXCLOSCCASAFO_DRV_CTRL_END_UP |
                       MCUXCLOSCCASAFO_DRV_CTRL_ENC    |
                       MCUXCLOSCCASAFO_DRV_CTRL_INSEL_DATIN1 |
                       MCUXCLOSCCASAFO_DRV_CTRL_OUTSEL_RES_XOR_DATIN0 |
                       MCUXCLOSCCASAFO_DRV_CTRL_INKEYSEL_KEY0 |
                       MCUXCLOSCCASAFO_DRV_CTRL_SM4_EN         |         // enable SM4 kernel
                       MCUXCLOSCCASAFO_DRV_CTRL_SM4            |         // SM4 operation
                       MCUXCLOSCCASAFO_DRV_CTRL_START);
        //Increase counter value
        mcuxClOsccaSafo_Drv_incrementData(MCUXCLOSCCASAFO_DRV_DATIN1_INDEX, 16u);

        //wait for finish
        mcuxClOsccaSafo_Drv_wait();

        //Copy result to user
        pOut[3] = mcuxClOsccaSafo_Drv_storeInput(MCUXCLOSCCASAFO_DRV_DATOUT_INDEX + 0u);
        pOut[2] = mcuxClOsccaSafo_Drv_storeInput(MCUXCLOSCCASAFO_DRV_DATOUT_INDEX + 1u);
        pOut[1] = mcuxClOsccaSafo_Drv_storeInput(MCUXCLOSCCASAFO_DRV_DATOUT_INDEX + 2u);
        pOut[0] = mcuxClOsccaSafo_Drv_storeInput(MCUXCLOSCCASAFO_DRV_DATOUT_INDEX + 3u);
        pOut += 16u / sizeof(uint32_t);
        *outSize += 16u;
        remainingBytes -= 16u;
    }

   /*
    * Iterate over remaining blocks. Here, every block is assumed to be of full size
    */
   if(remainingBytes > 0u)
   {
        uint32_t pPaddingBuf[4] = {0u};
        uint32_t pPaddingOut[4] = {0u};
        /* Copy the padding to the output and update pOutLength accordingly. */
        mcuxClMemory_copy((uint8_t*)pPaddingBuf, (uint8_t*)input, remainingBytes, remainingBytes);
        //Copy input to SAFO
        mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 0u, pPaddingBuf[3]);  /* load the IV in DATIN1 */
        mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 1u, pPaddingBuf[2]);  /* load the IV in DATIN1 */
        mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 2u, pPaddingBuf[1]);  /* load the IV in DATIN1 */
        mcuxClOsccaSafo_Drv_load(MCUXCLOSCCASAFO_DRV_DATIN0_INDEX + 3u, pPaddingBuf[0]);  /* load the IV in DATIN1 */

        (void)mcuxClOsccaSafo_Drv_dataOut_res(MCUXCLOSCCASAFO_DRV_CTRL_END_UP |
                       MCUXCLOSCCASAFO_DRV_CTRL_ENC    |
                       MCUXCLOSCCASAFO_DRV_CTRL_INSEL_DATIN1 |
                       MCUXCLOSCCASAFO_DRV_CTRL_OUTSEL_RES_XOR_DATIN0 |
                       MCUXCLOSCCASAFO_DRV_CTRL_INKEYSEL_KEY0 |
                       MCUXCLOSCCASAFO_DRV_CTRL_SM4_EN         |         // enable SM4 kernel
                       MCUXCLOSCCASAFO_DRV_CTRL_SM4            |         // SM4 operation
                       MCUXCLOSCCASAFO_DRV_CTRL_START);
        //wait for finish
        mcuxClOsccaSafo_Drv_wait();

        //Copy result to user
        pPaddingOut[3] = mcuxClOsccaSafo_Drv_storeInput(MCUXCLOSCCASAFO_DRV_DATOUT_INDEX + 0u);
        pPaddingOut[2] = mcuxClOsccaSafo_Drv_storeInput(MCUXCLOSCCASAFO_DRV_DATOUT_INDEX + 1u);
        pPaddingOut[1] = mcuxClOsccaSafo_Drv_storeInput(MCUXCLOSCCASAFO_DRV_DATOUT_INDEX + 2u);
        pPaddingOut[0] = mcuxClOsccaSafo_Drv_storeInput(MCUXCLOSCCASAFO_DRV_DATOUT_INDEX + 3u);
        /* Copy the padding to the output and update pOutLength accordingly. */
        mcuxClMemory_copy((uint8_t*)pOut, (uint8_t*)pPaddingOut, remainingBytes, remainingBytes);
        *outSize += remainingBytes;
   }
}

/* Cover test case for mcuxClOsccaSafo_Drv_enableOutputToKey and mcuxClOsccaSafo_Drv_disableOutputToKey */
/*
 * decrypt = 0 -> perform encrypt operation
 * decrypt = 1 -> perform decrypt operation
 */
void sm4_Operation(uint8_t decrypt, const uint32_t *input, const uint32_t *key, uint32_t *result)
{
    /* Flush SAFO key registers */
    mcuxClOsccaSafo_Drv_enableFlush(MCUXCLOSCCASAFO_DRV_FLUSH_KEY);
    mcuxClOsccaSafo_Drv_init(0U);
    mcuxClOsccaSafo_Drv_wait();

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

    (void) mcuxClOsccaSafo_Drv_enableOutputToKey(MCUXCLOSCCASAFO_DRV_KEY2_INDEX);

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
    result[3] = mcuxClOsccaSafo_Drv_storeKey(0);
    result[2] = mcuxClOsccaSafo_Drv_storeKey(1);
    result[1] = mcuxClOsccaSafo_Drv_storeKey(2);
    result[0] = mcuxClOsccaSafo_Drv_storeKey(3);

    mcuxClOsccaSafo_Drv_disableOutputToKey();
}
#endif /* MCUXCL_FEATURE_HW_SAFO_SM4 */

#ifdef MCUXCL_FEATURE_HW_SAFO_SM3
static void Load_Partial_Hash(uint32_t *partial_hash)
{
    /*
    * SM3_EN = 1'b1
    * SM3_STOP = 1'b0
    * HASH_RELOAD = 1'b0
    * SM3_HIGH_LIM = 4'b1111 (SM3 FIFO high limit)
    * SM3_LOW_LIM  = 4'b0000 (SM3 FIFO low limit)
    * HASH_RELOAD = 1'b1
    * NO_AUTO_INIT = 1'b1
    * SM3_MODE = 1'b1 (SM3 automatic mode)
    */

    mcuxClOsccaSafo_Drv_configureSm3(MCUXCLOSCCASAFO_DRV_CONFIG_SM3_AUTOMODE_LOADDATA_USELOADEDIV);
    mcuxClOsccaSafo_Drv_enableHashReload();

    /*
    * START = 1'b1
    * CRYPTO_OP = 3'b111
    * DATOUT_RES = 2'b00 - END_UP
    */

    mcuxClOsccaSafo_Drv_start(MCUXCLOSCCASAFO_DRV_START_SM3);

    mcuxClOsccaSafo_Drv_setByteOrder(MCUXCLOSCCASAFO_DRV_BYTE_ORDER_BE);
    for(int i = 7; i >= 0; i--)
    {
        mcuxClOsccaSafo_Drv_loadFifo(partial_hash[i]);
    }

    /* set SM3 control SFRs to stop the AUTO mode (SM3_STOP = 1'b1) */
    mcuxClOsccaSafo_Drv_stopSm3();

    /* wait for SM3 operation to complete
     * (poll for SAFO_STATUS.BUSY)
     */
    mcuxClOsccaSafo_Drv_wait();
}

static void sm3_Operation_Auto_Mode(const uint32_t *message, uint32_t message_size_words, uint32_t *result_digest, bool partial_hash_reload)
{
    /* setup SM3 control_sm3 SFRs */
    /*
    * SM3_EN = 1'b1
    * SM3_STOP = 1'b0
    * HASH_RELOAD = 1'b0
    * SM3_HIGH_LIM = 4'b1111 (SM3 FIFO high limit)
    * SM3_LOW_LIM  = 4'b0000 (SM3 FIFO low limit)
    * SM3_MODE = 1'b1 (SM3 automatic mode)
    */
    mcuxClOsccaSafo_Drv_configureSm3(MCUXCLOSCCASAFO_DRV_CONFIG_SM3_AUTOMODE_LOADDATA_USELOADEDIV);

    if (partial_hash_reload)
    {
        /* NO_AUTO_INIT = 1'b1 (no SM3 automatic HASH initialisation) */
        mcuxClOsccaSafo_Drv_disableIvAutoInit();
    }
    else
    {
        /* NO_AUTO_INIT = 1'b0 (SM3 automatic HASH initialisation) */
        mcuxClOsccaSafo_Drv_enableIvAutoInit();
    }

    /* setup SAFO control SFRs */
    /* DATOUT_RES = 2'b00 - END_UP (load to DATOUT the SM3 result at the end of the current operation)
    * CRYPTO_OP = 3'b111 - SM3
    * START = 1'b1
    */
    mcuxClOsccaSafo_Drv_start(MCUXCLOSCCASAFO_DRV_START_SM3);

    /* load message blocks into SAFO_SM3_FIFO SFRs */
    for (uint32_t i = 0; i < message_size_words; i++)
    {
        mcuxClOsccaSafo_Drv_loadFifo(message[i]);
    }

    /* set SM3 control SFRs to stop the AUTO mode */
    mcuxClOsccaSafo_Drv_stopSm3();

    /* wait for SM3 operation to complete
     * (poll for SAFO_STATUS.BUSY)
     */
    mcuxClOsccaSafo_Drv_wait();

    /* read first bank(16 bytes) from the hash result */
    result_digest[0] = mcuxClOsccaSafo_Drv_store(0);
    result_digest[1] = mcuxClOsccaSafo_Drv_store(1);
    result_digest[2] = mcuxClOsccaSafo_Drv_store(2);
    result_digest[3] = mcuxClOsccaSafo_Drv_store(3);

    /* setup SAFO control SFRs */
    /*
     * DATOUT_RES = 2'b10 - TRIGGER_UP  (transfer result contents to DATOUT)
     * START = 1'b1
     */
    mcuxClOsccaSafo_Drv_triggerOutput();

    /* wait for SM3 operation to complete
     * (poll for SAFO_STATUS.BUSY)
     */
    mcuxClOsccaSafo_Drv_wait();

    /* read second bank(16 bytes) from the hash result */
    result_digest[4] = mcuxClOsccaSafo_Drv_store(0);
    result_digest[5] = mcuxClOsccaSafo_Drv_store(1);
    result_digest[6] = mcuxClOsccaSafo_Drv_store(2);
    result_digest[7] = mcuxClOsccaSafo_Drv_store(3);
}
#endif /* MCUXCL_FEATURE_HW_SAFO_SM3 */

/* Automatic mode (AUTO - the number of processed blocks is determined during the operation based on the amount of data written into the SM3 FIFO) */
/* Steps for executing SM3 hash operation:
 * - setup SM3 control SFRs
 * - setup SAFO control SFRs
 * - load all message blocks into SM4_FIFO SFRs
 * - set SM3 control SFRs to stop the AUTO mode
 * - wait for SM3 operation to complete (via pooling busy)
 * - read the hash result
 */
bool mcuxClOsccaSafo_Cover_Public_apis_example(void)
{
    mcuxClOsccaSafo_Drv_enableFlush(MCUXCLOSCCASAFO_DRV_FLUSH_ALL);
    mcuxClOsccaSafo_Drv_init(MCUXCLOSCCASAFO_DRV_BYTE_ORDER_BE);

#ifdef MCUXCL_FEATURE_HW_SAFO_SM4
    /******************************************************************************************************************/
    /******************************************************************************************************************/
    if(true != xorWr_test())
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    if(mcuxClOsccaSafo_Drv_isStatusError())
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /******************************************************************************************************************/
    /******************************************************************************************************************/
    /*
    SM4 Encrypt test vector (1 block message)
    Input:
        message = 0123456789abcdeffedcba9876543210
        key = 0123456789abcdeffedcba9876543210

    Output (encrypt operation):
        ciphertext = 681edf34d206965e86b3e94f536e4246
    */
    uint32_t result_ciphertext[4U] = {0U};

    sm4_Operation(0x00, plaintext, key, result_ciphertext);
    if(mcuxClOsccaSafo_Drv_isStatusError())
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    /* check if actual result is equal to expected result */
    if (true != mcuxClCore_assertEqual((uint8_t*)result_ciphertext, (uint8_t*)reference_ciphertext, sizeof(reference_ciphertext)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /******************************************************************************************************************/
    /******************************************************************************************************************/
    /*
    SM4 Ctr test vector (4 block message)
    Input:
        message = AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD
                  EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB
        key = 0123456789abcdeffedcba9876543210
        iv = 000102030405060708090A0B0C0D0E0F

    Output (encrypt operation):
        ciphertext = AC3236CB970CC20791364C395A1342D1 A3CBC1878C6F30CD074CCE385CDD70C7
                     F234BC0E24C11980FD1286310CE37B92 6E02FCD0FAA0BAF38B2933851D824514
    */
    uint32_t cipherCtrtext[4U] = {0U};
    uint32_t outLen = 0u;

    sm4Ctr_test((const uint32_t *)sm4CtrKey, (const uint32_t *)sm4CtrIv, (const uint32_t *)sm4CtrPtxt, sizeof(sm4CtrPtxt), cipherCtrtext, &outLen);
    if(mcuxClOsccaSafo_Drv_isStatusError())
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    /* check if actual result is equal to expected result */
    if (true != mcuxClCore_assertEqual((uint8_t*)cipherCtrtext, (uint8_t*)sm4CtrCtxt, outLen))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
#endif /* MCUXCL_FEATURE_HW_SAFO_SM4 */
#ifdef MCUXCL_FEATURE_HW_SAFO_SM3
    /******************************************************************************************************************/
    /******************************************************************************************************************/
    /* SM3 Automatic mode, partial processing (4 padded blocks).
     * Input:
     *  message        = "64fce814fa17cecf9a97c6a815183f0db881d3367eb900247d997ee027a25ed2aac0a62f0718227dd6e82f17e6f563011945d3e58002e5c5d0dc66e29b55c71cde0d6d87cd211331056b122d069c556210d29e62dfdaca2587fe07e1635bc44fd07bb0990e6af75c9b1f0139a117ef5639ab73c5f7f7793bb2277b9749af279bf722b9c84a786f129e441112f184a9fe745cd390d4f4dadc773c31d089c39c2eb610dac973bd5e3f13b14bf525b43dd0c8591380b042464782e6d4b8336abcda"
     *  message_padded = "64fce814fa17cecf9a97c6a815183f0db881d3367eb900247d997ee027a25ed2aac0a62f0718227dd6e82f17e6f563011945d3e58002e5c5d0dc66e29b55c71cde0d6d87cd211331056b122d069c556210d29e62dfdaca2587fe07e1635bc44fd07bb0990e6af75c9b1f0139a117ef5639ab73c5f7f7793bb2277b9749af279bf722b9c84a786f129e441112f184a9fe745cd390d4f4dadc773c31d089c39c2eb610dac973bd5e3f13b14bf525b43dd0c8591380b042464782e6d4b8336abcda80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600"
     *  (192 bytes = 3 SM3 blocks unpadded)
     * Output:
     *  sm3_hash = "e2aa7ce51e675e623fa93ce7d5baecde19b32dfc9165d94284adcfc15cf5619a"
     */
    mcuxClOsccaSafo_Drv_enableFlush(MCUXCLOSCCASAFO_DRV_FLUSH_ALL);
    mcuxClOsccaSafo_Drv_init(MCUXCLOSCCASAFO_DRV_BYTE_ORDER_BE);
    uint32_t result_digest[8U];
    /* SM3 Automatic mode, partial hash processing (load the partial HASH value while SAFO_SM3_CTRL.HASH_RELOAD is set to 1'b1) */
    for (uint8_t i = 0; i < 4; i++)
    {
        bool partial_hash_reload = true ? (i != 0) : false;
        sm3_Operation_Auto_Mode(&message_hash[i * 16], 16U, result_digest, partial_hash_reload); /* process one SM3 block (64 bytes) per call */
        if (i != 3)
        {
            Load_Partial_Hash(result_digest);
        }
    }
    if(mcuxClOsccaSafo_Drv_isStatusError())
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    /* check if actual result is equal to expected result */
    for (uint32_t word = 0U; word < 8U; word++)
    {
        if (reference_hash_hash[word] != result_digest[word])
        {
            return MCUXCLEXAMPLE_STATUS_ERROR;
        }
    }
#endif /* MCUXCL_FEATURE_HW_SAFO_SM3 */
    uint32_t closeRet = mcuxClOsccaSafo_Drv_close();
    if(MCUXCLOSCCASAFO_STATUS_ERROR == closeRet)
    {
        /* If error flush whole SAFO */
        mcuxClOsccaSafo_Drv_enableFlush(MCUXCLOSCCASAFO_DRV_FLUSH_ALL);
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    return MCUXCLEXAMPLE_STATUS_OK;
}
