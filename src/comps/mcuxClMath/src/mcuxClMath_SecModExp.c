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
 * @file  mcuxClMath_SecModExp.c
 * @brief mcuxClMath: secure modular exponentiation
 */


#include <stdint.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>

#include <mcuxClEls_Rng.h>
#include <mcuxClPkc.h>
#include <mcuxClMath_Functions.h>
#include <mcuxClMath_Types.h>

#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClMath_Internal_SecModExp.h>
#include <internal/mcuxClMath_SecModExp_FUP.h>

/**
 * [DESIGN]
 * Internal square-and-multiply-always modular exponentiation function, which supports:
 * (1) when numSqr = 1, double-exponentiation (Shamir's trick), m1^e1 * m2^e2.
 *     m1 and m2 need to be stored in PKC operands M1 and M2, and
 *     exponent e1 and e2 should be interleaved.
 * (2) when numSqr = 2, fixed 2-bit window algorithm, x^e.
 *     x and x^2 need to be stored in PKC operands M1 and M2.
 *
 * CAUTION: pOperands[SECMODEXP_ZERO] needs to be initialized by caller.
 * CAUTION: expByteLength should be a multiple of CPU word length.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClMath_SecModExp_SqrMultAws)
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMath_SecModExp_SqrMultAws)
static MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMath_Status_t)
mcuxClMath_SecModExp_SqrMultAws(const uint32_t *pExp, uint32_t expByteLength, uint32_t numSqr)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMath_SecModExp_SqrMultAws);

    /* Prepare m3 = m1 * m2 mod n, m0 = 1, a0 = 1. */
    MCUXCLPKC_FP_CALCFUP(mcuxClMath_Fup_Aws_Init,
                        mcuxClMath_Fup_Aws_Init_LEN);

    const uint16_t *pOperands = MCUXCLPKC_GETUPTRT();
    const uint32_t *pOperands32 = (const uint32_t *) pOperands;  /* UPTR table is 32-bit aligned in SecModExp. */

    /* A0 and A1 will be the intermediate result A(t) and temp buffer A(1-t). */
    /* In the beginning, A0 is the intermediate result, i.e., t = 0. */
    uint16_t ofsN = pOperands[SECMODEXP_N];
    const uint32_t ofsA1_ofsA0 = pOperands32[SECMODEXP_A0 / 2u];  /* hi16 = ofsA1, lo16 = ofsA0. */
    uint32_t ofsAs = ofsA1_ofsA0;

    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_PS1_SETMODE(MCUXCLPKC_MC_MM);

    MCUX_CSSL_FP_LOOP_DECL(SquMulLoop);
    MCUX_CSSL_FP_LOOP_DECL(SquMulLoop_LoadExpWord);
    MCUX_CSSL_FP_LOOP_DECL(SquMulLoop_Square);

    /* Balance FP in advance to avoid keeping expByteLength in reg/stack. */
    MCUX_CSSL_FP_EXPECT(
        MCUX_CSSL_FP_LOOP_ITERATIONS(SquMulLoop, expByteLength * 4u),
        MCUX_CSSL_FP_LOOP_ITERATIONS(SquMulLoop_LoadExpWord, expByteLength / 4u),
        MCUX_CSSL_FP_LOOP_ITERATIONS(SquMulLoop_Square, expByteLength * 4u * numSqr) );

    /* Assume expByteLength is a multiple of CPU word size (4), otherwise, some higher bits of exponent will be ignored. */
    uint32_t expWord0 = 0u;
    uint32_t expWord1 = 0u;

    uint32_t ofsM3_ofsM1 = pOperands32[SECMODEXP_M1 / 2u];  /* (offsetM3, offsetM1) = (M3H, M3L, M1H, M1L) */
    uint32_t ofsM2_ofsM0 = pOperands32[SECMODEXP_M0 / 2u];  /* (offsetM2, offsetM0) = (M2H, M2L, M0H, M0L) */
    /* Prepare (M3H, M2H, M1H, M0H), where e.g., M3H is the higher 8 bits of the 16-bit offset M3. */
    uint32_t ofsMsHi8 = (ofsM3_ofsM1 & 0xFF00FF00u) | ((ofsM2_ofsM0 & 0xFF00FF00u) >> 8u);
    /* Prepare (M3L, M2L, M1L, M0L), where e.g., M3L is the lower 8 bits of the 16-bit offset M3. */
    uint32_t ofsMsLo8 = ((ofsM3_ofsM1 & 0x00FF00FFu) << 8u) | (ofsM2_ofsM0 & 0x00FF00FFu);

    /* Rotate left 4-bit, such that the rotation amount in SecureOffsetSelect is always nonzero (4/12/20/28). */
    ofsMsHi8 = (ofsMsHi8 << 4u) | (ofsMsHi8 >> 28u);
    ofsMsLo8 = (ofsMsLo8 << 4u) | (ofsMsLo8 >> 28u);

    /* Scan from most to least significant bits of exponent,        */
    /* which is stored in little-endian in CPU-word aligned buffer. */
    uint32_t bitLenExp = expByteLength * 8u;
    int32_t bitIndex = (int32_t) bitLenExp - 2;
    do
    {
        MCUX_CSSL_FP_LOOP_ITERATION(SquMulLoop,
                                   MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Prng_GetRandomWord));

        /* Load next CPU word of exponent. */
        if (0x1Eu == ((uint32_t) bitIndex & 0x1Fu))
        {
            MCUX_CSSL_FP_LOOP_ITERATION(SquMulLoop_LoadExpWord,
                                       MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Prng_GetRandomWord));

            /* Read one CPU word of exponent and mask it. */
            uint32_t randomWordStack;
            MCUX_CSSL_FP_FUNCTION_CALL(ret_PRNG_randWord, mcuxClEls_Prng_GetRandomWord(&randomWordStack));
            if (MCUXCLELS_STATUS_OK != ret_PRNG_randWord)
            {
                MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMath_SecModExp_SqrMultAws, MCUXCLMATH_ERRORCODE_ERROR);
            }
            expWord1 = randomWordStack;  /* avoid compiler writing randomWord back to stack */
            MCUXCLPKC_PKC_CPU_ARBITRATION_WORKAROUND();  // avoid CPU accessing to PKC workarea when PKC is busy
            expWord0 = pExp[(uint32_t) bitIndex / 32u] ^ expWord1;
        }

        uint32_t iterSqr = numSqr;
        do
        {
            MCUX_CSSL_FP_LOOP_ITERATION(SquMulLoop_Square);

            /* Swap intermediate result A(t) and temp buffer A(1-t), i.e., let t := 1-t. */
            ofsAs = (ofsAs << 16u) | (ofsAs >> 16u);  /* hi16 = ofsA(1-t), lo16 = ofsA(t). */

            /* Calculate A(t) = A(1-t) * A(1-t) mod N. */
            uint32_t Sqr_ofsY_ofsX = (ofsAs & 0xFFFF0000u) | (ofsAs >> 16u);
            uint32_t Sqr_ofsR_ofsZ = (ofsAs << 16u)        | ofsN;
            MCUXCLPKC_WAITFORREADY();
            MCUXCLPKC_PS1_SETXY_REG(Sqr_ofsY_ofsX);
            MCUXCLPKC_PS1_SETZR_REG(Sqr_ofsR_ofsZ);
            MCUXCLPKC_PS1_START_L1();

            iterSqr--;
        } while (0u < iterSqr);

        /* Generate a fresh random word for secure offset selection.*/
        uint32_t rndWordStack;
        MCUX_CSSL_FP_FUNCTION_CALL(ret_PRNG_randWord2, mcuxClEls_Prng_GetRandomWord(&rndWordStack));
        if (MCUXCLELS_STATUS_OK != ret_PRNG_randWord2)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMath_SecModExp_SqrMultAws, MCUXCLMATH_ERRORCODE_ERROR);
        }
        uint32_t rndWord = rndWordStack;                    /* avoid compiler writing rndWord back to stack */

        /* Modular Multiplication: X    * Y      mod Z =: R,    */
        /* for t = 0 or 1,         M[i] * A(1-t) mod N =: A(t). */

        /* Securely select ofsX, set ofsY_ofsX, and also swap A0 and A1 (i.e., let t := 1-t). */
        uint32_t ofsY_ofsX;
        MCUXCLMATH_SECMODEXP_SECUREOFFSETSELECT(expWord0, expWord1, ofsAs, ofsY_ofsX, rndWord, bitIndex, ofsMsHi8, ofsMsLo8);
        uint32_t ofsR_ofsZ = (ofsAs << 16u) | ofsN;

        MCUXCLPKC_WAITFORREADY();
        MCUXCLPKC_PS1_SETXY_REG(ofsY_ofsX);
        MCUXCLPKC_PS1_SETZR_REG(ofsR_ofsZ);
        MCUXCLPKC_PS1_START_L1();

        bitIndex -= 2;
    } while (0 <= bitIndex);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMath_SecModExp_SqrMultAws, MCUXCLMATH_ERRORCODE_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup) );
}


MCUX_CSSL_FP_FUNCTION_DEF(mcuxClMath_SecModExp)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClMath_Status_t) mcuxClMath_SecModExp(const uint8_t *pExp, uint32_t *pExpTemp, uint32_t expByteLength, uint32_t iT3_iX_iT2_iT1, uint32_t iN_iTE_iT0_iR)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClMath_SecModExp);

    /* Create local UPTR table. */
    uint32_t pOperands32[(SECMODEXP_UPTRT_SIZE + 1u) / 2u];
    /* MISRA Ex. 9 - Rule 11.3 - Cast to 16-bit pointer table */
    uint16_t *pOperands = (uint16_t *) pOperands32;
    /* Mapping to internal indices:                              M3  M1 M2  M0   N  TE  A1  A0 */
    const uint16_t *backupPtrUptrt = MCUXCLMATH_FP_INITLOCALUPTRT(iT3_iX_iT2_iT1, iN_iTE_iT0_iR, pOperands, 8u);

    uint32_t ps1LenBackup = MCUXCLPKC_PS1_GETLENGTH_REG();

    /* Import exponent (big-endian to little-endian). */
    uint32_t pkcLenExpPlus = MCUXCLPKC_ROUNDUP_SIZE(expByteLength + 1u);
    MCUXCLPKC_PS1_SETLENGTH_REG(pkcLenExpPlus);  /* MCLEN on higher 16 bits is not used. */

    MCUX_CSSL_FP_FUNCTION_CALL(ret_SecImport, mcuxClPkc_SecureImportBigEndianToPkc(MCUXCLPKC_PACKARGS2(SECMODEXP_A0, SECMODEXP_A1), pExp, expByteLength));
    if (MCUXCLPKC_STATUS_OK != ret_SecImport)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMath_SecModExp, MCUXCLMATH_ERRORCODE_ERROR);
    }

    /******************************************************/
    /* Euclidean exponent split: exp = b * q + r,         */
    /* where b is 32-bit random (MSb and LSb set)         */
    /******************************************************/

    /* Generate random expB and blind exponent, expA = exp + expB. */
    uint8_t *pA1 = MCUXCLPKC_OFFSET2PTR(pOperands[SECMODEXP_A1]);
    /* A1 = expB < (256^pkcLenExpPlus)/2. */
    MCUX_CSSL_FP_FUNCTION_CALL(ret_PRNG_GetRandom, mcuxClEls_Prng_GetRandom(pA1, pkcLenExpPlus));
    if (MCUXCLELS_STATUS_OK != ret_PRNG_GetRandom)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMath_SecModExp, MCUXCLMATH_ERRORCODE_ERROR);
    }
    pA1[pkcLenExpPlus - 1u] &= 0x7Fu;
    /* A0 = expA = exp + expB < 256^pkcLenExpPlus. */
    MCUXCLPKC_FP_CALC_OP1_ADD(SECMODEXP_A0, SECMODEXP_A0, SECMODEXP_A1);

    /* Partition buffer TE to "NDash || R0 || R1 || (R2L, R2H)". */
    uint32_t offsetTE = (uint32_t) pOperands[SECMODEXP_TE];
    uint32_t offsetR0 = offsetTE + MCUXCLPKC_WORDSIZE;
    uint32_t offsetR1 = offsetR0 + MCUXCLPKC_WORDSIZE;
    uint32_t offsetR2 = offsetR1 + MCUXCLPKC_WORDSIZE;
    pOperands32[SECMODEXP_R0 / 2u] = (offsetR1 << 16u) + offsetR0;
    pOperands32[SECMODEXP_R2 / 2u] = offsetR2;  /* Also initialize SECMODEXP_ZERO */

    /* Generate a 32-bit random b with both MSbit and LSbit set. */
    uint8_t *pR0 = MCUXCLPKC_OFFSET2PTR(offsetR0);
    uint32_t *p32R0 = (uint32_t *) pR0;  /* PKC buffer is CPU-word aligned. */
    MCUXCLPKC_PKC_CPU_ARBITRATION_WORKAROUND();  // avoid CPU accessing to PKC workarea when PKC is busy
    MCUX_CSSL_FP_FUNCTION_CALL(ret_PRNG_GetRandomWord, mcuxClEls_Prng_GetRandomWord(&p32R0[0]));
    if (MCUXCLELS_STATUS_OK != ret_PRNG_GetRandomWord)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMath_SecModExp, MCUXCLMATH_ERRORCODE_ERROR);
    }
    p32R0[0] |= 0x80000001u;
    p32R0[1] = 0u;

    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_PS1_SETLENGTH(MCUXCLPKC_WORDSIZE, MCUXCLPKC_WORDSIZE);

    /* Prepare shift modulus of R0 = b, and calculate NDash and QDash of b. */
    MCUXCLPKC_FP_CALC_OP1_SHL(SECMODEXP_R1, SECMODEXP_R0, 32u);
    MCUXCLMATH_FP_NDASH(SECMODEXP_R0, SECMODEXP_M2);
    MCUXCLMATH_FP_QDASH(SECMODEXP_M0, SECMODEXP_R1, SECMODEXP_R0, SECMODEXP_M3, (uint16_t) pkcLenExpPlus);

//  MCUXCLPKC_WAITFORREADY();  <== there is WAITFORREADY in QDASH
    MCUXCLPKC_PS2_SETLENGTH(pkcLenExpPlus, MCUXCLPKC_WORDSIZE);

    /* M2 = expB mod b, R1 = r = exp mod b. */
    MCUXCLPKC_FP_CALCFUP(mcuxClMath_Fup_EuclideanSplit_1,
                        mcuxClMath_Fup_EuclideanSplit_1_LEN);

    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_PS2_SETLENGTH_REG(pkcLenExpPlus);  /* MCLEN on higher 16 bits is not used. */

    /* A0 = -(expA - (expB mod b) - ((expA - expB) mod b)); */
    /* A1 = -(expB - (expB mod b)).                         */
    MCUXCLPKC_FP_CALCFUP(mcuxClMath_Fup_EuclideanSplit_2,
                        mcuxClMath_Fup_EuclideanSplit_2_LEN);

    MCUX_CSSL_FP_LOOP_DECL(ExactDivideLoop);

    /* Calculate exact division:                                 */
    /*   A0 = (expA - (expB mod b) - ((expA - expB) mod b)) / b; */
    /*   A1 = (expB - (expB mod b)) / b.                         */
    uint32_t ofsV1_ofsV0 = pOperands32[SECMODEXP_A0 / 2u];
    uint32_t remainLength = pkcLenExpPlus;
    do
    {
        MCUX_CSSL_FP_LOOP_ITERATION(ExactDivideLoop,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup) );

        MCUXCLPKC_WAITFORREADY();
        MCUXCLPKC_PS2_SETLENGTH_REG(remainLength);  /* MCLEN on higher 16 bits is not used. */
        pOperands32[SECMODEXP_V0 / 2u] = ofsV1_ofsV0;

        MCUXCLPKC_FP_CALCFUP(mcuxClMath_Fup_ExactDivideLoop,
                            mcuxClMath_Fup_ExactDivideLoop_LEN);

        ofsV1_ofsV0 += (((uint32_t) MCUXCLPKC_WORDSIZE << 16u) + MCUXCLPKC_WORDSIZE);
        remainLength -= MCUXCLPKC_WORDSIZE;
    } while(0u != remainLength);

    /* A0 = q = A0 - A1 = ((expA - expB) - ((expA - expB) mod b)) / b = (exp - (exp mod b)) / b. */
    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_PS2_SETLENGTH_REG(pkcLenExpPlus);  /* MCLEN on higher 16 bits is not used. */
    MCUXCLPKC_FP_CALC_OP2_SUB(SECMODEXP_A0, SECMODEXP_A0, SECMODEXP_A1);

    /* Interleave R0 = b and R1 = r. */
    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_ENABLEGF2();
    MCUXCLPKC_FP_CALC_OP1_MUL_GF2(SECMODEXP_R2, SECMODEXP_R0, SECMODEXP_R0);
    MCUXCLPKC_FP_CALC_OP1_SHL(SECMODEXP_TE, SECMODEXP_R2, 1u);
    MCUXCLPKC_FP_CALC_OP1_MUL_GF2(SECMODEXP_R2, SECMODEXP_R1, SECMODEXP_R1);
    MCUXCLPKC_FP_CALC_OP1_OR(SECMODEXP_TE, SECMODEXP_TE, SECMODEXP_R2);

    /* Export A0 = q. */
    const uint8_t *pA0 = MCUXCLPKC_OFFSET2PTR(pOperands[SECMODEXP_A0]);
    uint32_t wordLenExp = (expByteLength + 3u) & 0xFFFFFFFCu;
    MCUXCLPKC_PKC_CPU_ARBITRATION_WORKAROUND();
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMemory_copy((uint8_t *) pExpTemp, pA0, wordLenExp, wordLenExp));

    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_DISABLEGF2();
    MCUXCLPKC_PS1_SETLENGTH_REG(ps1LenBackup);

    /* Calculate 2-bit window exponentiation, A0 = m0 = m^q. */
    /* Prepare M2 = m^2. */
    MCUXCLPKC_FP_CALC_MC1_MM(SECMODEXP_A0, SECMODEXP_M1, SECMODEXP_M1, SECMODEXP_N);
    MCUXCLPKC_FP_CALC_OP1_OR_CONST(SECMODEXP_M2, SECMODEXP_A0, 0u);
    MCUX_CSSL_FP_FUNCTION_CALL(retSecModExp0, mcuxClMath_SecModExp_SqrMultAws(pExpTemp, wordLenExp, 2u));
    if (MCUXCLMATH_ERRORCODE_OK != retSecModExp0)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMath_SecModExp, MCUXCLMATH_ERRORCODE_ERROR);
    }

    /* Calculate double exponentiation, A0 = result = m^r * m0^b, with interleaved r and b. */
    MCUXCLPKC_FP_CALC_OP1_OR_CONST(SECMODEXP_M2, SECMODEXP_A0, 0u);
    /* MISRA Ex. 9 - Rule 11.3 - PKC buffer is CPU word aligned. */
    uint32_t *p32TE = (uint32_t *) MCUXCLPKC_OFFSET2PTR(pOperands[SECMODEXP_TE]);
    MCUX_CSSL_FP_FUNCTION_CALL(retSecModExp1, mcuxClMath_SecModExp_SqrMultAws(p32TE, 8u, 1u));
    if (MCUXCLMATH_ERRORCODE_OK != retSecModExp1)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMath_SecModExp, MCUXCLMATH_ERRORCODE_ERROR);
    }

    /* Restore pUptrt. */
    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_SETUPTRT(backupPtrUptrt);

    /* Clear the local UPTR table on stack. */
    for (uint32_t i = 0u; i < ((SECMODEXP_UPTRT_SIZE + 1u) / 2u); i++)
    {
        pOperands32[i] = 0u;
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClMath_SecModExp, MCUXCLMATH_ERRORCODE_OK,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_InitLocalUptrt),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_SecureImportBigEndianToPkc),
        /* Euclidean exponent splitting */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Prng_GetRandom),
        MCUXCLPKC_FP_CALLED_CALC_OP1_ADD,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Prng_GetRandomWord),
        MCUXCLPKC_FP_CALLED_CALC_OP1_SHL,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_NDash),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_QDash),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),
        MCUX_CSSL_FP_LOOP_ITERATIONS(ExactDivideLoop, MCUXCLPKC_ROUNDUP_SIZE(expByteLength + 1u) / MCUXCLPKC_WORDSIZE),
        MCUXCLPKC_FP_CALLED_CALC_OP2_SUB,
        /* Interleave b and r, and export q,  */
        MCUXCLPKC_FP_CALLED_CALC_OP1_MUL_GF2,
        MCUXCLPKC_FP_CALLED_CALC_OP1_SHL,
        MCUXCLPKC_FP_CALLED_CALC_OP1_MUL_GF2,
        MCUXCLPKC_FP_CALLED_CALC_OP1_OR,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy),
        /* Exponentiation 1 */
        MCUXCLPKC_FP_CALLED_CALC_MC1_MM,
        MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_SecModExp_SqrMultAws),
        /* Exponentiation 2 */
        MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST,
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_SecModExp_SqrMultAws) );
}
