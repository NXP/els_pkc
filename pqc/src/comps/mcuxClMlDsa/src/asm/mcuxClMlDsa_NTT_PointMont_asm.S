/*--------------------------------------------------------------------------*/
/* Copyright 2025-2026 NXP                                                  */
/*                                                                          */
/* NXP Proprietary. This software is owned or controlled by NXP and may     */
/* only be used strictly in accordance with the applicable license terms.   */
/* By expressly accepting such terms or by downloading, installing,         */
/* activating and/or otherwise using the software, you are agreeing that    */
/* you have read, and that you agree to comply with and are bound by, such  */
/* license terms.  If you do not agree to be bound by the applicable        */
/* license terms, then you may not retain, install, activate or otherwise   */
/* use the software.                                                        */
/*--------------------------------------------------------------------------*/

/**
 * @file  mcuxClMlDsa_NTT_PointMont_asm.S
 */

/* Define a flag to indicate we're in assembly context */
#define __ASSEMBLY_CONTEXT__
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslFlowProtection_SecureCounter_Local_AssemblyMacros.h>
#undef __ASSEMBLY_CONTEXT__

/* Register definitions */
#define rPCoeffsC    r0              /* pointer to output coefficients c[] */
#define rPCoeffsA    r1              /* pointer to input coefficients a[] */
#define rPCoeffsB    r2              /* pointer to input coefficients b[] */
#define rCounter     r3              /* loop counter */
#define rCoeffA0     r4              /* first coefficient from a[] */
#define rCoeffB0     r5              /* first coefficient from b[] */
#define rCoeffA1     r6              /* second coefficient from a[] */
#define rCoeffB1     r7              /* second coefficient from b[] */
#define rCoeffA2     r8              /* third coefficient from a[] */
#define rCoeffB2     r9              /* third coefficient from b[] */
#define rAux0        r10             /* auxiliary register 0 */
#define rAux1        r11             /* auxiliary register 1 */
#define rQinv        r12             /* QINV constant */
#define rMinusQ      r14             /* minus Q constant */

#define rSc          r11             /* Secure counter - temporary use only */
#define rToken       r1              /* Flow protection token return value */

#ifdef __IASMARM__
        NAME mcuxClMlDsa_NTT_PointMont_asm
        PUBLIC mcuxClMlDsa_NTT_PointMont_asm
        SECTION .text:CODE(2)
        THUMB
#else /* armclang */
.syntax unified
.align 2
.section .text.mcuxClMlDsa_NTT_PointMont_asm, "ax"
.global        mcuxClMlDsa_NTT_PointMont_asm
.type          mcuxClMlDsa_NTT_PointMont_asm, %function
#endif

/**
 * void mcuxClMlDsa_NTT_PointMont_asm(int32_t c[N], const int32_t a[N], const int32_t b[N])
 * r0 = c[N]
 * r1 = a[N]
 * r2 = b[N]
 */
mcuxClMlDsa_NTT_PointMont_asm:
    push {r3-r12, r14}

    MCUX_CSSL_FP_ASM_FUNCTION_ENTRY  rSc, rAux0, MCUX_CSSL_FP_FUNCID_mcuxClMlDsa_NTT_PointMont_asm
    push {rSc}                          /* Save secure counter (rSc==r11 is reused as rAux1 in the loops) */

    /* Load constants */
    ldr rQinv, =58728449
    ldr rMinusQ, =-8380417

    mov rCounter, #85

Loop_85:
    /* Load 3 coefficients from a[] */
    ldr rCoeffA0, [rPCoeffsA], #4   /* a[0] -> rCoeffA0, then a_ptr += 4 */
    ldr rCoeffA1, [rPCoeffsA], #4   /* a[1] -> rCoeffA1, then a_ptr += 4 */
    ldr rCoeffA2, [rPCoeffsA], #4   /* a[2] -> rCoeffA2, then a_ptr += 4 */

    /* Load 3 coefficients from b[] */
    ldr rCoeffB0, [rPCoeffsB], #4   /* b[0] -> rCoeffB0, then b_ptr += 4 */
    ldr rCoeffB1, [rPCoeffsB], #4   /* b[1] -> rCoeffB1, then b_ptr += 4 */
    ldr rCoeffB2, [rPCoeffsB], #4   /* b[2] -> rCoeffB2, then b_ptr += 4 */

    /* Montgomery multiplication for first coefficient pair (a[0] * b[0]) */
    smull rAux0, rCoeffB0, rCoeffA0, rCoeffB0
    mul rAux1, rAux0, rQinv
    smlal rAux0, rCoeffB0, rAux1, rMinusQ

    /* Montgomery multiplication for second coefficient pair (a[1] * b[1]) */
    smull rAux0, rCoeffB1, rCoeffA1, rCoeffB1
    mul rAux1, rAux0, rQinv
    smlal rAux0, rCoeffB1, rAux1, rMinusQ

    /* Montgomery multiplication for third coefficient pair (a[2] * b[2]) */
    smull rAux0, rCoeffB2, rCoeffA2, rCoeffB2
    mul rAux1, rAux0, rQinv
    smlal rAux0, rCoeffB2, rAux1, rMinusQ

    /* Store results to c[] */
    str rCoeffB0, [rPCoeffsC], #4   /* store result 0 to c[], then c_ptr += 4 */
    str rCoeffB1, [rPCoeffsC], #4   /* store result 1 to c[], then c_ptr += 4 */
    str rCoeffB2, [rPCoeffsC], #4   /* store result 2 to c[], then c_ptr += 4 */

    subs rCounter, rCounter, #1
    bne Loop_85

    /* Process final (256th) coefficient */
    ldr rCoeffA0, [rPCoeffsA]
    ldr rCoeffB0, [rPCoeffsB]
    smull rAux0, rCoeffB0, rCoeffA0, rCoeffB0
    mul rAux1, rAux0, rQinv
    smlal rAux0, rCoeffB0, rAux1, rMinusQ
    str rCoeffB0, [rPCoeffsC]

    pop {rSc}                           /* Restore secure counter */
    MCUX_CSSL_FP_ASM_FUNCTION_EXIT rSc, rAux0, MCUX_CSSL_FP_FUNCID_mcuxClMlDsa_NTT_PointMont_asm
    mov rToken, rSc                     /* Return the flow-protection token in r1 */

    pop {r3-r12, pc}

#ifdef __IASMARM__
        END
#endif
