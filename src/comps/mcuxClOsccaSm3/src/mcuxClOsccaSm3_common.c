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

#include <toolchain.h>
#include <mcuxClMemory.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClOscca_FunctionIdentifiers.h>

/**********************************************************
 * Helper functions
 **********************************************************/
/**
 * This function reverses a byte string in-place (switches the endianness).
 *
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClOsccaSm3_core_sm3_switch_endianness)
void mcuxClOsccaSm3_core_sm3_switch_endianness(uint32_t *ptr, uint32_t length)
{
#ifdef MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS
    if (0u != (length % (sizeof(uint32_t))))
    {
        uint8_t *ptrL = (uint8_t *) ptr;
        uint8_t *ptrH = ((uint8_t *) ptr + length);

        uint32_t remainLength = length / 2u;
        while (0u < remainLength)
        {
            ptrH--;
            uint8_t byteH = *ptrH;
            uint8_t byteL = *ptrL;

            *ptrL = byteH;
            *ptrH = byteL;
            ptrL++;

            remainLength--;
        }

        return;
    }

    /* When the length is a multiple of CPU word size, fall down to the original implementation. */
    /* length is a multiple of CPU word size (4). */
    uint32_t *ptrH32 = (uint32_t *) ((uint8_t *) ptr + length - 4u);
#else
    /* MISRA Ex. 9 - Rule 11.3 - Use of UNALIGNED keyword. */
    uint32_t UNALIGNED *ptrH32 = (uint32_t UNALIGNED *) ((uint8_t *) ptr + length - 4u);
#endif
   uint32_t *ptrL32 = ptr;

    /* While there are >= 4 bytes to switch the endianness. */
    while (ptrH32 >= ptrL32)
    {
        uint32_t wordL = *ptrL32;
        uint32_t wordH = *ptrH32;

        wordL = MCUXCLMEMORY_SWITCH_4BYTE_ENDIANNESS(wordL);
        wordH = MCUXCLMEMORY_SWITCH_4BYTE_ENDIANNESS(wordH);

        *ptrH32 = wordL;
        ptrH32--;
        *ptrL32 = wordH;
        ptrL32++;
    }
#ifdef MCUXCL_FEATURE_PKC_PKCRAM_NO_UNALIGNED_ACCESS
    /* Now, ptrH32 = phtL32 - 4 or ptrL32 - 8, nothing more to do. */
#else
    /* If ptrH <= ptrL - 4, nothing more to do. */
    /* If ptrH == ptrL - 3, swap ptrL[0] with ptrH[3] = ptrL[0], i.e., nothing to do. */
    /* If ptrH == ptrL - 2, swap ptrL[0] with ptrH[3] = ptrL[1]. */
    /* If ptrH == ptrL - 1, swap ptrL[0] with ptrH[3] = ptrL[2], and leave ptrL[1] unchanged. */
    uint8_t *ptrL8 = (uint8_t *) ptrL32;
    uint8_t *ptrH8 = (uint8_t *) ptrH32 + 3u;
    if (ptrH8 > ptrL8)
    {
        uint8_t byteL = *ptrL8;
        uint8_t byteH = *ptrH8;

        *ptrH8 = byteL;
        *ptrL8 = byteH;
    }
#endif
    return;
}
