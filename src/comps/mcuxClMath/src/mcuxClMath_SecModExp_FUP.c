/*--------------------------------------------------------------------------*/
/* Copyright 2021-2022 NXP                                                  */
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
 * @file  mcuxClMath_SecModExp_FUP.c
 * @brief mcuxClMath: FUP programs of secure modular exponentiation
 */

#include <internal/mcuxClMath_SecModExp_FUP.h>
#include <internal/mcuxClMath_Internal_SecModExp.h>
#include <internal/mcuxClPkc_FupMacros.h>

const mcuxClPkc_FUPEntry_t mcuxClMath_Fup_Aws_Init[5] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0x03u,0x38u,0x08u,0x40u},{0x80u,0x00u,0x02u,0x01u,0x07u,0x04u},{0x00u,0x1eu,0x00u,0x04u,0x0du,0x03u},{0x00u,0x09u,0x00u,0x00u,0x07u,0x00u},{0x00u,0x09u,0x00u,0x00u,0x07u,0x04u}};
const mcuxClPkc_FUPEntry_t mcuxClMath_Fup_EuclideanSplit_1[8] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0x7bu,0xd7u,0x1du,0xa7u},{0xc0u,0x00u,0x04u,0x00u,0x0au,0x01u},{0xc0u,0x00u,0x05u,0x00u,0x0au,0x03u},{0x80u,0x33u,0x01u,0x00u,0x0au,0x00u},{0x80u,0x33u,0x03u,0x00u,0x0au,0x01u},{0x80u,0x2au,0x0au,0x00u,0x0au,0x00u},{0x80u,0x2au,0x0au,0x01u,0x0au,0x01u},{0x80u,0x2au,0x0au,0x00u,0x01u,0x0bu}};
const mcuxClPkc_FUPEntry_t mcuxClMath_Fup_EuclideanSplit_2[7] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0x2cu,0xa9u,0x8au,0xa5u},{0x40u,0x09u,0x00u,0x00u,0x04u,0x04u},{0x40u,0x6au,0x00u,0x04u,0x01u,0x04u},{0x40u,0x6au,0x00u,0x04u,0x0bu,0x04u},{0x40u,0x09u,0x00u,0x00u,0x05u,0x05u},{0x40u,0x6au,0x00u,0x05u,0x01u,0x05u},{0x40u,0x3eu,0x00u,0x00u,0x0du,0x00u}};
const mcuxClPkc_FUPEntry_t mcuxClMath_Fup_ExactDivideLoop[9] MCUX_FUP_ATTRIBUTE = {{0x10u,0x00u,0xbbu,0x42u,0x33u,0x63u},{0x00u,0x00u,0x08u,0x06u,0x00u,0x0cu},{0x00u,0x00u,0x0cu,0x0au,0x00u,0x00u},{0x40u,0x0au,0x00u,0x08u,0x00u,0x08u},{0x00u,0x1eu,0x00u,0x0cu,0x0du,0x08u},{0x00u,0x00u,0x09u,0x06u,0x00u,0x0cu},{0x00u,0x00u,0x0cu,0x0au,0x00u,0x00u},{0x40u,0x0au,0x00u,0x09u,0x00u,0x09u},{0x00u,0x1eu,0x00u,0x0cu,0x0du,0x09u}};


/**
 * [DESIGN]
 * Prepare base numbers (M0/M1/M2/M3) and Accumulator (A0) of exponentiation.
 *
 * Since the operand M3 is of the size pkcLenN, the result of m1 * m2 is stored
 * in the operand A0 (size = pkcLenN + MCUXCLPKC_WORDSIZE) and then copied to M3.
 */
/* PS1 length = (          pkcLenN,           pkcLenN) */

/**
 * [DESIGN]
 * Euclidean splitting part #1: calculate "exponent mod b" on both shares of exponent.
 *
 * The modular reduction is implemented based on PKC MR (Modular Reduction).
 * The two shares of exponent are converted to their Montgomery representation
 * modulo b (length = MCUXCLPKC_WORDSIZE) by multiplying them with M0 = QDash.
 * They are converted back to their normal representation by PKC MR, and
 * results are in the range [0, b]. The PKC MS (Modular Subtraction) guarantees
 * the proper results in the range [0, b-1].
 *
 * CAUTION:
 * According to PKC specification, when calculating MM (Modular Multiplication)
 * with OPLEN = MCUXCLPKC_WORDSIZE, PKC will read the least significant PKC word
 * of the result buffer in PKC workarea (M2[0] and M3[0] in this FUP program)
 * before writing any intermediate result to it.
 * This pre-fetch will not affect the result, but caller shall ensure that
 * both PKC words M2[0] and M3[0] are initialized before this FUP program,
 * if the platform requires explicit memory initialization.
 *
 * ps, M2[0] and M3[0] have been initialized (used as temp buffer) when calculating
 * NDash and QDash before this FUP program.
 */
/* PS1 length = (MCUXCLPKC_WORDSIZE, MCUXCLPKC_WORDSIZE) */
/* PS2 length = (    pkcLenExpPlus, MCUXCLPKC_WORDSIZE) */

/**
 * [DESIGN]
 * Euclidean splitting part #2: prepare to calculate exact division:
 * "(exponent - (exponent mod b)) / b", on both shares of exponent.
 *
 * Exact division, x/b = q, assumes the dividend x must be exactly a multiple of
 * divisor b. So there is the quotient q satisfying (-x) + b*q = 0.
 */
/* PS2 length = (                -,     pkcLenExpPlus) */

/**
 * [DESIGN]
 * One iteration of exact division, where the divisor b is of the size, MCUXCLPKC_WORDSIZE.
 *
 * The algorithm of exact division q = x/b is to find q satisfying (-x) + b*q = 0.
 * Let y = -x mod 256^(pkcLenExpPlus), and y[i] and q[i] are the i-th PKC word of y and q.
 *
 * y + b*q[0] \equiv 0 mod Q, where Q = 256^(MCUXCLPKC_WORDSIZE).
 * q[0] = y * (-b)^(-1) mod Q = y[0] * NDash mod Q.
 * Assume for i > 0, y + b*q[i-1 ~ 0] \equiv 0 mod Q^i.
 * Then, q[i] = ((y + b*q[i-1 ~ 0])/(Q^i)) * NDash mod Q.
 *
 * In this implementation, the negative dividend (-x) will be overwritten by
 * quotient q word-wisely.
 */
/* PS1 length = (                -, MCUXCLPKC_WORDSIZE) */
/* PS2 length = (                -,      remainLength) */
