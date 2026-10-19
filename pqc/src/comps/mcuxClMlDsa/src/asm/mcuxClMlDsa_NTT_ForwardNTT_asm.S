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
 * @file  mcuxClMlDsa_NTT_ForwardNTT_asm.S
 */

/* Define a flag to indicate we're in assembly context */
#define __ASSEMBLY_CONTEXT__
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslFlowProtection_FunctionIdentifiers.h>
#include <mcuxCsslFlowProtection_SecureCounter_Local_AssemblyMacros.h>
#undef __ASSEMBLY_CONTEXT__

/* Register definitions */

#define rPCoeffs     r0              /* pointer to coefficients */
#define rZetas       r1              /* pointer to zetas */
#define rCounter     r2              /* counter */
#define rZeta1       r3              /* zeta1 */
#define rZeta2       r4              /* zeta2 */
#define rZeta3       r5              /* zeta3 */
#define rCoeff0      r6              /* first coefficient loaded */
#define rCoeff1      r7              /* second coefficient loaded */
#define rCoeff2      r8              /* third coefficient loaded */
#define rCoeff3      r9              /* fourth coefficient loaded */
#define rAux0        r10             /* auxiliary register 0 */
#define rAux1        r11             /* auxiliary register 1 */
#define rQinv        r12             /* QINV constant */
#define rMinusQ      r14             /* minus Q constant */

#define rSc          r11             /* Secure counter - temporary use only */
#define rToken       r1              /* Flow protection token return value */

#ifdef __IASMARM__

        NAME mcuxClMlDsa_NTT_ForwardNTT_asm
        PUBLIC mcuxClMlDsa_NTT_ForwardNTT_asm
        SECTION .text:CODE(2)
        THUMB
#else /* armclang */
.syntax unified
.align 2
.section .text.mcuxClMlDsa_NTT_ForwardNTT_asm, "ax"
.global        mcuxClMlDsa_NTT_ForwardNTT_asm
.type          mcuxClMlDsa_NTT_ForwardNTT_asm, %function
#endif

/**
 * void mcuxClMlDsa_NTT_ForwardNTT_asm(pA, zetas)
 * r0 = pA
 * r1 = zetas
 */
mcuxClMlDsa_NTT_ForwardNTT_asm:
  push {r2-r12, r14}

  MCUX_CSSL_FP_ASM_FUNCTION_ENTRY  rSc, rAux0, MCUX_CSSL_FP_FUNCID_mcuxClMlDsa_NTT_ForwardNTT_asm
  push {rSc}                           /* Save secure counter (rSc==r11 is reused as rAux1 in the loops) */

  /* Load constants */

  ldr rQinv, =58728449
  ldr rMinusQ, =-8380417

  /* Load zeta1, zeta2, zeta3 & increment the index */
  ldr rZeta1, [rZetas, #4]          /* zeta 1 */
  ldr rZeta2, [rZetas, #8]          /* zeta 2 */
  ldr rZeta3, [rZetas, #12]         /* zeta 3 */

  mov rCounter, #64

mcuxClMlDsa_NTT_ForwardNTT_asm_Loop128:
  /* Load 4 coefficients at a time */
  ldr rCoeff0, [rPCoeffs]           /* load from rPCoeffs */
  ldr rCoeff1, [rPCoeffs, #256]     /* load from rPCoeffs + 64*4 */
  ldr rCoeff2, [rPCoeffs, #512]     /* load from rPCoeffs + 128*4 */
  ldr rCoeff3, [rPCoeffs, #768]     /* load from rPCoeffs + 192*4 */

  /* Level 7 - ct_butterfly_montgomery rZeta1,rCoeff0,rCoeff2 */
  smull rAux0, rAux1, rZeta1, rCoeff2
  mul rCoeff2, rAux0, rQinv
  smlal rAux0, rAux1, rCoeff2, rMinusQ
  sub rCoeff2, rCoeff0, rAux1
  add rCoeff0, rCoeff0, rAux1

  /* Level 7 - ct_butterfly_montgomery rZeta1,rCoeff1,rCoeff3 */
  smull rAux0, rAux1, rZeta1, rCoeff3
  mul rCoeff3, rAux0, rQinv
  smlal rAux0, rAux1, rCoeff3, rMinusQ
  sub rCoeff3, rCoeff1, rAux1
  add rCoeff1, rCoeff1, rAux1

  /* Level 6 - ct_butterfly_montgomery rZeta2,rCoeff0,rCoeff1 */
  smull rAux0, rAux1, rZeta2, rCoeff1
  mul rCoeff1, rAux0, rQinv
  smlal rAux0, rAux1, rCoeff1, rMinusQ
  sub rCoeff1, rCoeff0, rAux1
  add rCoeff0, rCoeff0, rAux1

  /* Level 6 - ct_butterfly_montgomery rZeta3,rCoeff2,rCoeff3 */
  smull rAux0, rAux1, rZeta3, rCoeff3
  mul rCoeff3, rAux0, rQinv
  smlal rAux0, rAux1, rCoeff3, rMinusQ
  sub rCoeff3, rCoeff2, rAux1
  add rCoeff2, rCoeff2, rAux1

  /* Store coefficients & increase pointer */
  str rCoeff1, [rPCoeffs, #256]     /* store at rPCoeffs + 64*4 */
  str rCoeff2, [rPCoeffs, #512]     /* store at rPCoeffs + 128*4 */
  str rCoeff3, [rPCoeffs, #768]     /* store at rPCoeffs + 192*4 */
  str rCoeff0, [rPCoeffs], #4       /* store at rPCoeffs, then increment */

  subs rCounter, rCounter, #1
  bne mcuxClMlDsa_NTT_ForwardNTT_asm_Loop128

  sub rPCoeffs, rPCoeffs, #256      /* return to adr rPCoeffs[0] */
  add rZetas, rZetas, #16

  mov rCounter, #64

mcuxClMlDsa_NTT_ForwardNTT_asm_Loop4:
  /* Load zeta1, zeta2, zeta3 */
  ldr rZeta1, [rZetas], #4          /* zeta 4 */
  ldr rZeta2, [rZetas], #4          /* zeta 8 */
  ldr rZeta3, [rZetas], #4          /* zeta 9 */

mcuxClMlDsa_NTT_ForwardNTT_asm_Loop16:
  /* Load 4 coefficients at a time */
  ldr rCoeff0, [rPCoeffs]           /* load from rPCoeffs */
  ldr rCoeff1, [rPCoeffs, #64]      /* load from rPCoeffs + 16*4 */
  ldr rCoeff2, [rPCoeffs, #128]     /* load from rPCoeffs + 32*4 */
  ldr rCoeff3, [rPCoeffs, #192]     /* load from rPCoeffs + 48*4 */

  /* Level 5 - ct_butterfly_montgomery rZeta1,rCoeff0,rCoeff2 */
  smull rAux0, rAux1, rZeta1, rCoeff2
  mul rCoeff2, rAux0, rQinv
  smlal rAux0, rAux1, rCoeff2, rMinusQ
  sub rCoeff2, rCoeff0, rAux1
  add rCoeff0, rCoeff0, rAux1

  /* Level 5 - ct_butterfly_montgomery rZeta1,rCoeff1,rCoeff3 */
  smull rAux0, rAux1, rZeta1, rCoeff3
  mul rCoeff3, rAux0, rQinv
  smlal rAux0, rAux1, rCoeff3, rMinusQ
  sub rCoeff3, rCoeff1, rAux1
  add rCoeff1, rCoeff1, rAux1

  /* Level 4 - ct_butterfly_montgomery rZeta2,rCoeff0,rCoeff1 */
  smull rAux0, rAux1, rZeta2, rCoeff1
  mul rCoeff1, rAux0, rQinv
  smlal rAux0, rAux1, rCoeff1, rMinusQ
  sub rCoeff1, rCoeff0, rAux1
  add rCoeff0, rCoeff0, rAux1

  /* Level 4 - ct_butterfly_montgomery rZeta3,rCoeff2,rCoeff3 */
  smull rAux0, rAux1, rZeta3, rCoeff3
  mul rCoeff3, rAux0, rQinv
  smlal rAux0, rAux1, rCoeff3, rMinusQ
  sub rCoeff3, rCoeff2, rAux1
  add rCoeff2, rCoeff2, rAux1

  /* Store coefficients & increase pointer */
  str rCoeff1, [rPCoeffs, #64]      /* store at rPCoeffs + 16*4 */
  str rCoeff2, [rPCoeffs, #128]     /* store at rPCoeffs + 32*4 */
  str rCoeff3, [rPCoeffs, #192]     /* store at rPCoeffs + 48*4 */
  str rCoeff0, [rPCoeffs], #4       /* store at rPCoeffs, then increment */

  subs rCounter, rCounter, #1
  beq mcuxClMlDsa_NTT_ForwardNTT_asm_End64
  ands rCoeff1, rCounter, #15       /* compute rCounter mod 16 */
  bne mcuxClMlDsa_NTT_ForwardNTT_asm_Loop16
  add rPCoeffs, rPCoeffs, #192      /* move pointer to next block */
  b mcuxClMlDsa_NTT_ForwardNTT_asm_Loop4

mcuxClMlDsa_NTT_ForwardNTT_asm_End64:
  sub rPCoeffs, rPCoeffs, #832      /* return to adr rPCoeffs[0] */

  mov rCounter, #64

mcuxClMlDsa_NTT_ForwardNTT_asm_Loop16Out:
  /* Load the correct zetas consecutively */
  ldr rZeta1, [rZetas], #4          /* zeta 16, 17 ... 31 */
  ldr rZeta2, [rZetas], #4          /* zeta 32, 34 ... 62 */
  ldr rZeta3, [rZetas], #4          /* zeta 33, 35 ... 63 */

mcuxClMlDsa_NTT_ForwardNTT_asm_Loop4In:
  /* Load 4 coefficients at a time */
  ldr rCoeff0, [rPCoeffs]           /* load from rPCoeffs */
  ldr rCoeff1, [rPCoeffs, #16]      /* load from rPCoeffs + 4*4 */
  ldr rCoeff2, [rPCoeffs, #32]      /* load from rPCoeffs + 8*4 */
  ldr rCoeff3, [rPCoeffs, #48]      /* load from rPCoeffs + 12*4 */

  /* Level 3 - ct_butterfly_montgomery rZeta1,rCoeff0,rCoeff2 */
  smull rAux0, rAux1, rZeta1, rCoeff2
  mul rCoeff2, rAux0, rQinv
  smlal rAux0, rAux1, rCoeff2, rMinusQ
  sub rCoeff2, rCoeff0, rAux1
  add rCoeff0, rCoeff0, rAux1

  /* Level 3 - ct_butterfly_montgomery rZeta1,rCoeff1,rCoeff3 */
  smull rAux0, rAux1, rZeta1, rCoeff3
  mul rCoeff3, rAux0, rQinv
  smlal rAux0, rAux1, rCoeff3, rMinusQ
  sub rCoeff3, rCoeff1, rAux1
  add rCoeff1, rCoeff1, rAux1

  /* Level 2 - ct_butterfly_montgomery rZeta2,rCoeff0,rCoeff1 */
  smull rAux0, rAux1, rZeta2, rCoeff1
  mul rCoeff1, rAux0, rQinv
  smlal rAux0, rAux1, rCoeff1, rMinusQ
  sub rCoeff1, rCoeff0, rAux1
  add rCoeff0, rCoeff0, rAux1

  /* Level 2 - ct_butterfly_montgomery rZeta3,rCoeff2,rCoeff3 */
  smull rAux0, rAux1, rZeta3, rCoeff3
  mul rCoeff3, rAux0, rQinv
  smlal rAux0, rAux1, rCoeff3, rMinusQ
  sub rCoeff3, rCoeff2, rAux1
  add rCoeff2, rCoeff2, rAux1

  /* Store coefficients & increase pointer */
  str rCoeff1, [rPCoeffs, #16]      /* store at rPCoeffs + 4*4 */
  str rCoeff2, [rPCoeffs, #32]      /* store at rPCoeffs + 8*4 */
  str rCoeff3, [rPCoeffs, #48]      /* store at rPCoeffs + 12*4 */
  str rCoeff0, [rPCoeffs], #4       /* store at rPCoeffs, then increment */

  subs rCounter, rCounter, #1
  beq mcuxClMlDsa_NTT_ForwardNTT_asm_End64A
  ands rCoeff1, rCounter, #3        /* compute rCounter mod 4 */
  bne mcuxClMlDsa_NTT_ForwardNTT_asm_Loop4In
  add rPCoeffs, rPCoeffs, #48
  b mcuxClMlDsa_NTT_ForwardNTT_asm_Loop16Out

mcuxClMlDsa_NTT_ForwardNTT_asm_End64A:
  add rPCoeffs, rPCoeffs, #48
  sub rPCoeffs, rPCoeffs, #1024     /* return to adr rPCoeffs[0] */

  mov rCounter, #64

mcuxClMlDsa_NTT_ForwardNTT_asm_Loop64:
  /* Load zetas */
  ldr rZeta1, [rZetas], #4          /* zeta 64, 65, ... 127 */
  ldr rZeta2, [rZetas], #4          /* zeta 128, 130, ... 254 */
  ldr rZeta3, [rZetas], #4          /* zeta 129, 131, ... 255 */

  /* Load 4 coefficients at a time */
  ldr rCoeff0, [rPCoeffs]           /* load from rPCoeffs */
  ldr rCoeff1, [rPCoeffs, #4]       /* load from rPCoeffs + 1*4 */
  ldr rCoeff2, [rPCoeffs, #8]       /* load from rPCoeffs + 2*4 */
  ldr rCoeff3, [rPCoeffs, #12]      /* load from rPCoeffs + 3*4 */

  /* Level 1 - ct_butterfly_montgomery rZeta1,rCoeff0,rCoeff2 */
  smull rAux0, rAux1, rZeta1, rCoeff2
  mul rCoeff2, rAux0, rQinv
  smlal rAux0, rAux1, rCoeff2, rMinusQ
  sub rCoeff2, rCoeff0, rAux1
  add rCoeff0, rCoeff0, rAux1

  /* Level 1 - ct_butterfly_montgomery rZeta1,rCoeff1,rCoeff3 */
  smull rAux0, rAux1, rZeta1, rCoeff3
  mul rCoeff3, rAux0, rQinv
  smlal rAux0, rAux1, rCoeff3, rMinusQ
  sub rCoeff3, rCoeff1, rAux1
  add rCoeff1, rCoeff1, rAux1

  /* Level 0 - ct_butterfly_montgomery rZeta2,rCoeff0,rCoeff1 */
  smull rAux0, rAux1, rZeta2, rCoeff1
  mul rCoeff1, rAux0, rQinv
  smlal rAux0, rAux1, rCoeff1, rMinusQ
  sub rCoeff1, rCoeff0, rAux1
  add rCoeff0, rCoeff0, rAux1

  /* Level 0 - ct_butterfly_montgomery rZeta3,rCoeff2,rCoeff3 */
  smull rAux0, rAux1, rZeta3, rCoeff3
  mul rCoeff3, rAux0, rQinv
  smlal rAux0, rAux1, rCoeff3, rMinusQ
  sub rCoeff3, rCoeff2, rAux1
  add rCoeff2, rCoeff2, rAux1

  /* Store coefficients & increase pointer */
  str rCoeff0, [rPCoeffs], #4       /* store at rPCoeffs */
  str rCoeff1, [rPCoeffs], #4       /* store at rPCoeffs + 1*4 */
  str rCoeff2, [rPCoeffs], #4       /* store at rPCoeffs + 2*4 */
  str rCoeff3, [rPCoeffs], #4       /* store at rPCoeffs + 3*4 */

  subs rCounter, rCounter, #1
  bne mcuxClMlDsa_NTT_ForwardNTT_asm_Loop64

  sub rPCoeffs, rPCoeffs, #1024     /* return to adr rPCoeffs[0] */

  pop {rSc}                                 /* Restore secure counter */
  MCUX_CSSL_FP_ASM_FUNCTION_EXIT rSc, rAux0, MCUX_CSSL_FP_FUNCID_mcuxClMlDsa_NTT_ForwardNTT_asm
  mov rToken, rSc                           /* Return the flow-protection token in r1 */

  pop {r2-r12, pc}


#ifdef __IASMARM__
        END
#endif
