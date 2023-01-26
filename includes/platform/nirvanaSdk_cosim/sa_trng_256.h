/*
** ###################################################################
**     Processor:
**     Compilers:           Freescale C/C++ for Embedded ARM
**                          GNU C Compiler
**                          GNU C Compiler - CodeSourcery Sourcery G++
**                          IAR ANSI C/C++ Compiler for ARM
**                          Keil ARM C/C++ Compiler
**                          MCUXpresso Compiler
**
**     Build:               b221006
**
**     Abstract:
**         CMSIS Peripheral Access Layer for sa_trng_256_nirvana1
**
**     Copyright 1997-2016 Freescale Semiconductor, Inc.
**     Copyright 2016-2022 NXP
**     All rights reserved.
**
**     SPDX-License-Identifier: BSD-3-Clause
**
**     http:                 www.nxp.com
**     mail:                 support@nxp.com
**
**     Revisions:
**
** ###################################################################
*/

/*!
 * @file sa_trng_256_nirvana1.h
 * @version 0.0
 * @date 0-00-00
 * @brief CMSIS Peripheral Access Layer for sa_trng_256_nirvana1
 *
 * CMSIS Peripheral Access Layer for sa_trng_256_nirvana1
 */

#ifndef _SA_TRNG_256_NIRVANA1_H_
#define _SA_TRNG_256_NIRVANA1_H_                 /**< Symbol preventing repeated inclusion */

/** Memory map major version (memory maps with equal major version number are
 * compatible) */
#define MCU_MEM_MAP_VERSION 0x0000U
/** Memory map minor version */
#define MCU_MEM_MAP_VERSION_MINOR 0x0000U


/* ----------------------------------------------------------------------------
   -- Device Peripheral Access Layer
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup Peripheral_access_layer Device Peripheral Access Layer
 * @{
 */


/*
** Start of section using anonymous unions
*/

#if defined(__ARMCC_VERSION)
  #if (__ARMCC_VERSION >= 6010050)
    #pragma clang diagnostic push
  #else
    #pragma push
    #pragma anon_unions
  #endif
#elif defined(__CWCC__)
  #pragma push
  #pragma cpp_extensions on
#elif defined(__GNUC__)
  /* anonymous unions are enabled by default */
#elif defined(__IAR_SYSTEMS_ICC__)
  #pragma language=extended
#else
  #error Not supported compiler type
#endif

/* ----------------------------------------------------------------------------
   -- TRNG Peripheral Access Layer
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup TRNG_Peripheral_Access_Layer TRNG Peripheral Access Layer
 * @{
 */

/** TRNG - Register Layout Typedef */
typedef struct {
  __IO uint32_t MCTL;                              /**< Miscellaneous Control Register, offset: 0x0 */
  __IO uint32_t SCMISC;                            /**< Statistical Check Miscellaneous Register, offset: 0x4 */
       uint8_t RESERVED_0[8];
  __IO uint32_t SDCTL;                             /**< Seed Control Register, offset: 0x10 */
       uint8_t RESERVED_1[4];
  union {                                          /* offset: 0x18 */
    __IO uint32_t FRQMIN;                            /**< Frequency Count Minimum Limit Register, offset: 0x18 */
    __I  uint32_t OSC2_FRQCNT;                       /**< Oscillator-2 Frequency Count Register, offset: 0x18 */
  };
  union {                                          /* offset: 0x1C */
    __I  uint32_t FRQCNT;                            /**< Frequency Count Register, offset: 0x1C */
    __IO uint32_t FRQMAX;                            /**< Frequency Count Maximum Limit Register, offset: 0x1C */
  };
  union {                                          /* offset: 0x20 */
    __I  uint32_t SCMC;                              /**< Statistical Check Monobit Count Register, offset: 0x20 */
    __IO uint32_t SCML;                              /**< Statistical Check Monobit Limit Register, offset: 0x20 */
  };
  union {                                          /* offset: 0x24 */
    __I  uint32_t SCR1C;                             /**< Statistical Check Run Length 1 Count Register, offset: 0x24 */
    __IO uint32_t SCR1L;                             /**< Statistical Check Run Length 1 Limit Register, offset: 0x24 */
  };
  union {                                          /* offset: 0x28 */
    __I  uint32_t SCR2C;                             /**< Statistical Check Run Length 2 Count Register, offset: 0x28 */
    __IO uint32_t SCR2L;                             /**< Statistical Check Run Length 2 Limit Register, offset: 0x28 */
  };
  union {                                          /* offset: 0x2C */
    __I  uint32_t SCR3C;                             /**< Statistical Check Run Length 3 Count Register, offset: 0x2C */
    __IO uint32_t SCR3L;                             /**< Statistical Check Run Length 3 Limit Register, offset: 0x2C */
  };
       uint8_t RESERVED_2[12];
  __I  uint32_t STATUS;                            /**< Status Register, offset: 0x3C */
  __I  uint32_t ENT[8];                            /**< Entropy Read Register, array offset: 0x40, array step: 0x4 */
       uint8_t RESERVED_3[64];
  __IO uint32_t SEC_CFG;                           /**< Security Configuration Register, offset: 0xA0 */
  __IO uint32_t INT_CTRL;                          /**< Interrupt Control Register, offset: 0xA4 */
  __IO uint32_t INT_MASK;                          /**< Mask Register, offset: 0xA8 */
  __I  uint32_t INT_STATUS;                        /**< Interrupt Status Register, offset: 0xAC */
       uint8_t RESERVED_4[60];
  __IO uint32_t OSC2_CTL;                          /**< TRNG Oscillator 2 Control Register, offset: 0xEC */
  __I  uint32_t VID1;                              /**< Version ID Register (MS), offset: 0xF0 */
  __I  uint32_t VID2;                              /**< Version ID Register (LS), offset: 0xF4 */
  __I  uint32_t OSC_INV_CHAIN_LEN;                 /**< Oscillator Inverter Chain Length Register, offset: 0xF8 */
} TRNG_Type;

/* ----------------------------------------------------------------------------
   -- TRNG Register Masks
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup TRNG_Register_Masks TRNG Register Masks
 * @{
 */

/*! @name MCTL - Miscellaneous Control Register */
/*! @{ */

#define TRNG_MCTL_OSC_DIV_MASK                   (0xCU)
#define TRNG_MCTL_OSC_DIV_SHIFT                  (2U)
/*! OSC_DIV
 *  0b00..use ring oscillator with no divide
 *  0b01..use ring oscillator divided-by-2
 *  0b10..use ring oscillator divided-by-4
 *  0b11..use ring oscillator divided-by-8
 */
#define TRNG_MCTL_OSC_DIV(x)                     (((uint32_t)(((uint32_t)(x)) << TRNG_MCTL_OSC_DIV_SHIFT)) & TRNG_MCTL_OSC_DIV_MASK)

#define TRNG_MCTL_RST_DEF_MASK                   (0x40U)
#define TRNG_MCTL_RST_DEF_SHIFT                  (6U)
/*! RST_DEF
 *  0b0..No impact.
 *  0b1..Writing a 1 to this bit clears various TRNG registers, and bits within registers, to their default state.
 */
#define TRNG_MCTL_RST_DEF(x)                     (((uint32_t)(((uint32_t)(x)) << TRNG_MCTL_RST_DEF_SHIFT)) & TRNG_MCTL_RST_DEF_MASK)

#define TRNG_MCTL_FOR_SCLK_MASK                  (0x80U)
#define TRNG_MCTL_FOR_SCLK_SHIFT                 (7U)
#define TRNG_MCTL_FOR_SCLK(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_MCTL_FOR_SCLK_SHIFT)) & TRNG_MCTL_FOR_SCLK_MASK)

#define TRNG_MCTL_FCT_FAIL_MASK                  (0x100U)
#define TRNG_MCTL_FCT_FAIL_SHIFT                 (8U)
#define TRNG_MCTL_FCT_FAIL(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_MCTL_FCT_FAIL_SHIFT)) & TRNG_MCTL_FCT_FAIL_MASK)

#define TRNG_MCTL_FCT_VAL_MASK                   (0x200U)
#define TRNG_MCTL_FCT_VAL_SHIFT                  (9U)
/*! FCT_VAL
 *  0b0..Frequency Count is not valid
 *  0b1..Frequency Count is valid
 */
#define TRNG_MCTL_FCT_VAL(x)                     (((uint32_t)(((uint32_t)(x)) << TRNG_MCTL_FCT_VAL_SHIFT)) & TRNG_MCTL_FCT_VAL_MASK)

#define TRNG_MCTL_ENT_VAL_MASK                   (0x400U)
#define TRNG_MCTL_ENT_VAL_SHIFT                  (10U)
/*! ENT_VAL
 *  0b0..Entropy is not valid
 *  0b1..Entropy is valid
 */
#define TRNG_MCTL_ENT_VAL(x)                     (((uint32_t)(((uint32_t)(x)) << TRNG_MCTL_ENT_VAL_SHIFT)) & TRNG_MCTL_ENT_VAL_MASK)

#define TRNG_MCTL_ERR_MASK                       (0x1000U)
#define TRNG_MCTL_ERR_SHIFT                      (12U)
/*! ERR
 *  0b0..No error
 *  0b1..Error detected
 */
#define TRNG_MCTL_ERR(x)                         (((uint32_t)(((uint32_t)(x)) << TRNG_MCTL_ERR_SHIFT)) & TRNG_MCTL_ERR_MASK)

#define TRNG_MCTL_TSTOP_OK_MASK                  (0x2000U)
#define TRNG_MCTL_TSTOP_OK_SHIFT                 (13U)
/*! TSTOP_OK
 *  0b0..TRNG is generating entropy and is not ok to stop
 *  0b1..TRNG is not generating entropy and is ok to stop
 */
#define TRNG_MCTL_TSTOP_OK(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_MCTL_TSTOP_OK_SHIFT)) & TRNG_MCTL_TSTOP_OK_MASK)

#define TRNG_MCTL_LRUN_CONT_MASK                 (0x4000U)
#define TRNG_MCTL_LRUN_CONT_SHIFT                (14U)
/*! LRUN_CONT
 *  0b0..The internal test's long run count is restarted for each entropy re-generation.
 *  0b1..The count value (of TRNG's internal long_run test), at the start of an entropy generation will continue
 *       where it left off at the end of the previous entropy generation.
 */
#define TRNG_MCTL_LRUN_CONT(x)                   (((uint32_t)(((uint32_t)(x)) << TRNG_MCTL_LRUN_CONT_SHIFT)) & TRNG_MCTL_LRUN_CONT_MASK)

#define TRNG_MCTL_OSC2_FAIL_MASK                 (0x8000U)
#define TRNG_MCTL_OSC2_FAIL_SHIFT                (15U)
/*! OSC2_FAIL - Oscillator 2 Failure
 *  0b0..Oscillator 2 is running.
 *  0b1..Oscillator 2 has failed (see OSC2_CTL[OSC_FAILSAFE_LMT]).
 */
#define TRNG_MCTL_OSC2_FAIL(x)                   (((uint32_t)(((uint32_t)(x)) << TRNG_MCTL_OSC2_FAIL_SHIFT)) & TRNG_MCTL_OSC2_FAIL_MASK)

#define TRNG_MCTL_PRGM_MASK                      (0x10000U)
#define TRNG_MCTL_PRGM_SHIFT                     (16U)
/*! PRGM
 *  0b0..TRNG is in Run Mode
 *  0b1..TRNG is in Program Mode
 */
#define TRNG_MCTL_PRGM(x)                        (((uint32_t)(((uint32_t)(x)) << TRNG_MCTL_PRGM_SHIFT)) & TRNG_MCTL_PRGM_MASK)
/*! @} */

/*! @name SCMISC - Statistical Check Miscellaneous Register */
/*! @{ */

#define TRNG_SCMISC_LRUN_MAX_MASK                (0xFFU)
#define TRNG_SCMISC_LRUN_MAX_SHIFT               (0U)
#define TRNG_SCMISC_LRUN_MAX(x)                  (((uint32_t)(((uint32_t)(x)) << TRNG_SCMISC_LRUN_MAX_SHIFT)) & TRNG_SCMISC_LRUN_MAX_MASK)

#define TRNG_SCMISC_RTY_CT_MASK                  (0xF0000U)
#define TRNG_SCMISC_RTY_CT_SHIFT                 (16U)
#define TRNG_SCMISC_RTY_CT(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_SCMISC_RTY_CT_SHIFT)) & TRNG_SCMISC_RTY_CT_MASK)
/*! @} */

/*! @name SDCTL - Seed Control Register */
/*! @{ */

#define TRNG_SDCTL_SAMP_SIZE_MASK                (0xFFFFU)
#define TRNG_SDCTL_SAMP_SIZE_SHIFT               (0U)
#define TRNG_SDCTL_SAMP_SIZE(x)                  (((uint32_t)(((uint32_t)(x)) << TRNG_SDCTL_SAMP_SIZE_SHIFT)) & TRNG_SDCTL_SAMP_SIZE_MASK)

#define TRNG_SDCTL_ENT_DLY_MASK                  (0xFFFF0000U)
#define TRNG_SDCTL_ENT_DLY_SHIFT                 (16U)
#define TRNG_SDCTL_ENT_DLY(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_SDCTL_ENT_DLY_SHIFT)) & TRNG_SDCTL_ENT_DLY_MASK)
/*! @} */

/*! @name FRQMIN - Frequency Count Minimum Limit Register */
/*! @{ */

#define TRNG_FRQMIN_FRQ_MIN_MASK                 (0x3FFFFFU)
#define TRNG_FRQMIN_FRQ_MIN_SHIFT                (0U)
#define TRNG_FRQMIN_FRQ_MIN(x)                   (((uint32_t)(((uint32_t)(x)) << TRNG_FRQMIN_FRQ_MIN_SHIFT)) & TRNG_FRQMIN_FRQ_MIN_MASK)
/*! @} */

/*! @name OSC2_FRQCNT - Oscillator-2 Frequency Count Register */
/*! @{ */

#define TRNG_OSC2_FRQCNT_OSC2_FRQ_CT_MASK        (0x3FFFFFU)
#define TRNG_OSC2_FRQCNT_OSC2_FRQ_CT_SHIFT       (0U)
#define TRNG_OSC2_FRQCNT_OSC2_FRQ_CT(x)          (((uint32_t)(((uint32_t)(x)) << TRNG_OSC2_FRQCNT_OSC2_FRQ_CT_SHIFT)) & TRNG_OSC2_FRQCNT_OSC2_FRQ_CT_MASK)
/*! @} */

/*! @name FRQCNT - Frequency Count Register */
/*! @{ */

#define TRNG_FRQCNT_FRQ_CT_MASK                  (0x3FFFFFU)
#define TRNG_FRQCNT_FRQ_CT_SHIFT                 (0U)
#define TRNG_FRQCNT_FRQ_CT(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_FRQCNT_FRQ_CT_SHIFT)) & TRNG_FRQCNT_FRQ_CT_MASK)
/*! @} */

/*! @name FRQMAX - Frequency Count Maximum Limit Register */
/*! @{ */

#define TRNG_FRQMAX_FRQ_MAX_MASK                 (0x3FFFFFU)
#define TRNG_FRQMAX_FRQ_MAX_SHIFT                (0U)
#define TRNG_FRQMAX_FRQ_MAX(x)                   (((uint32_t)(((uint32_t)(x)) << TRNG_FRQMAX_FRQ_MAX_SHIFT)) & TRNG_FRQMAX_FRQ_MAX_MASK)
/*! @} */

/*! @name SCMC - Statistical Check Monobit Count Register */
/*! @{ */

#define TRNG_SCMC_MONO_CT_MASK                   (0xFFFFU)
#define TRNG_SCMC_MONO_CT_SHIFT                  (0U)
#define TRNG_SCMC_MONO_CT(x)                     (((uint32_t)(((uint32_t)(x)) << TRNG_SCMC_MONO_CT_SHIFT)) & TRNG_SCMC_MONO_CT_MASK)
/*! @} */

/*! @name SCML - Statistical Check Monobit Limit Register */
/*! @{ */

#define TRNG_SCML_MONO_MAX_MASK                  (0xFFFFU)
#define TRNG_SCML_MONO_MAX_SHIFT                 (0U)
#define TRNG_SCML_MONO_MAX(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_SCML_MONO_MAX_SHIFT)) & TRNG_SCML_MONO_MAX_MASK)

#define TRNG_SCML_MONO_RNG_MASK                  (0xFFFF0000U)
#define TRNG_SCML_MONO_RNG_SHIFT                 (16U)
#define TRNG_SCML_MONO_RNG(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_SCML_MONO_RNG_SHIFT)) & TRNG_SCML_MONO_RNG_MASK)
/*! @} */

/*! @name SCR1C - Statistical Check Run Length 1 Count Register */
/*! @{ */

#define TRNG_SCR1C_R1_0_CT_MASK                  (0x7FFFU)
#define TRNG_SCR1C_R1_0_CT_SHIFT                 (0U)
#define TRNG_SCR1C_R1_0_CT(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_SCR1C_R1_0_CT_SHIFT)) & TRNG_SCR1C_R1_0_CT_MASK)

#define TRNG_SCR1C_R1_1_CT_MASK                  (0x7FFF0000U)
#define TRNG_SCR1C_R1_1_CT_SHIFT                 (16U)
#define TRNG_SCR1C_R1_1_CT(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_SCR1C_R1_1_CT_SHIFT)) & TRNG_SCR1C_R1_1_CT_MASK)
/*! @} */

/*! @name SCR1L - Statistical Check Run Length 1 Limit Register */
/*! @{ */

#define TRNG_SCR1L_RUN1_MAX_MASK                 (0x7FFFU)
#define TRNG_SCR1L_RUN1_MAX_SHIFT                (0U)
#define TRNG_SCR1L_RUN1_MAX(x)                   (((uint32_t)(((uint32_t)(x)) << TRNG_SCR1L_RUN1_MAX_SHIFT)) & TRNG_SCR1L_RUN1_MAX_MASK)

#define TRNG_SCR1L_RUN1_RNG_MASK                 (0x7FFF0000U)
#define TRNG_SCR1L_RUN1_RNG_SHIFT                (16U)
#define TRNG_SCR1L_RUN1_RNG(x)                   (((uint32_t)(((uint32_t)(x)) << TRNG_SCR1L_RUN1_RNG_SHIFT)) & TRNG_SCR1L_RUN1_RNG_MASK)
/*! @} */

/*! @name SCR2C - Statistical Check Run Length 2 Count Register */
/*! @{ */

#define TRNG_SCR2C_R2_0_CT_MASK                  (0x3FFFU)
#define TRNG_SCR2C_R2_0_CT_SHIFT                 (0U)
#define TRNG_SCR2C_R2_0_CT(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_SCR2C_R2_0_CT_SHIFT)) & TRNG_SCR2C_R2_0_CT_MASK)

#define TRNG_SCR2C_R2_1_CT_MASK                  (0x3FFF0000U)
#define TRNG_SCR2C_R2_1_CT_SHIFT                 (16U)
#define TRNG_SCR2C_R2_1_CT(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_SCR2C_R2_1_CT_SHIFT)) & TRNG_SCR2C_R2_1_CT_MASK)
/*! @} */

/*! @name SCR2L - Statistical Check Run Length 2 Limit Register */
/*! @{ */

#define TRNG_SCR2L_RUN2_MAX_MASK                 (0x3FFFU)
#define TRNG_SCR2L_RUN2_MAX_SHIFT                (0U)
#define TRNG_SCR2L_RUN2_MAX(x)                   (((uint32_t)(((uint32_t)(x)) << TRNG_SCR2L_RUN2_MAX_SHIFT)) & TRNG_SCR2L_RUN2_MAX_MASK)

#define TRNG_SCR2L_RUN2_RNG_MASK                 (0x3FFF0000U)
#define TRNG_SCR2L_RUN2_RNG_SHIFT                (16U)
#define TRNG_SCR2L_RUN2_RNG(x)                   (((uint32_t)(((uint32_t)(x)) << TRNG_SCR2L_RUN2_RNG_SHIFT)) & TRNG_SCR2L_RUN2_RNG_MASK)
/*! @} */

/*! @name SCR3C - Statistical Check Run Length 3 Count Register */
/*! @{ */

#define TRNG_SCR3C_R3_0_CT_MASK                  (0x1FFFU)
#define TRNG_SCR3C_R3_0_CT_SHIFT                 (0U)
#define TRNG_SCR3C_R3_0_CT(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_SCR3C_R3_0_CT_SHIFT)) & TRNG_SCR3C_R3_0_CT_MASK)

#define TRNG_SCR3C_R3_1_CT_MASK                  (0x1FFF0000U)
#define TRNG_SCR3C_R3_1_CT_SHIFT                 (16U)
#define TRNG_SCR3C_R3_1_CT(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_SCR3C_R3_1_CT_SHIFT)) & TRNG_SCR3C_R3_1_CT_MASK)
/*! @} */

/*! @name SCR3L - Statistical Check Run Length 3 Limit Register */
/*! @{ */

#define TRNG_SCR3L_RUN3_MAX_MASK                 (0x1FFFU)
#define TRNG_SCR3L_RUN3_MAX_SHIFT                (0U)
#define TRNG_SCR3L_RUN3_MAX(x)                   (((uint32_t)(((uint32_t)(x)) << TRNG_SCR3L_RUN3_MAX_SHIFT)) & TRNG_SCR3L_RUN3_MAX_MASK)

#define TRNG_SCR3L_RUN3_RNG_MASK                 (0x1FFF0000U)
#define TRNG_SCR3L_RUN3_RNG_SHIFT                (16U)
#define TRNG_SCR3L_RUN3_RNG(x)                   (((uint32_t)(((uint32_t)(x)) << TRNG_SCR3L_RUN3_RNG_SHIFT)) & TRNG_SCR3L_RUN3_RNG_MASK)
/*! @} */

/*! @name STATUS - Status Register */
/*! @{ */

#define TRNG_STATUS_TF1BR0_MASK                  (0x1U)
#define TRNG_STATUS_TF1BR0_SHIFT                 (0U)
/*! TF1BR0
 *  0b0..The 1-Bit Run, Sampling 0s Test has passed
 *  0b1..The 1-Bit Run, Sampling 0s Test has failed
 */
#define TRNG_STATUS_TF1BR0(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_STATUS_TF1BR0_SHIFT)) & TRNG_STATUS_TF1BR0_MASK)

#define TRNG_STATUS_TF1BR1_MASK                  (0x2U)
#define TRNG_STATUS_TF1BR1_SHIFT                 (1U)
/*! TF1BR1
 *  0b0..The 1-Bit Run, Sampling 1s Test has passed
 *  0b1..The 1-Bit Run, Sampling 1s Test has failed
 */
#define TRNG_STATUS_TF1BR1(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_STATUS_TF1BR1_SHIFT)) & TRNG_STATUS_TF1BR1_MASK)

#define TRNG_STATUS_TF2BR0_MASK                  (0x4U)
#define TRNG_STATUS_TF2BR0_SHIFT                 (2U)
/*! TF2BR0
 *  0b0..The 2-Bit Run, Sampling 0s Test has passed
 *  0b1..The 2-Bit Run, Sampling 0s Test has failed
 */
#define TRNG_STATUS_TF2BR0(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_STATUS_TF2BR0_SHIFT)) & TRNG_STATUS_TF2BR0_MASK)

#define TRNG_STATUS_TF2BR1_MASK                  (0x8U)
#define TRNG_STATUS_TF2BR1_SHIFT                 (3U)
/*! TF2BR1
 *  0b0..The 2-Bit Run, Sampling 1s Test has passed
 *  0b1..The 2-Bit Run, Sampling 1s Test has failed
 */
#define TRNG_STATUS_TF2BR1(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_STATUS_TF2BR1_SHIFT)) & TRNG_STATUS_TF2BR1_MASK)

#define TRNG_STATUS_TF3BR0_MASK                  (0x10U)
#define TRNG_STATUS_TF3BR0_SHIFT                 (4U)
/*! TF3BR0
 *  0b0..The 3-Bit Run, Sampling 0s Test has passed
 *  0b1..The 3-Bit Run, Sampling 0s Test has failed
 */
#define TRNG_STATUS_TF3BR0(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_STATUS_TF3BR0_SHIFT)) & TRNG_STATUS_TF3BR0_MASK)

#define TRNG_STATUS_TF3BR1_MASK                  (0x20U)
#define TRNG_STATUS_TF3BR1_SHIFT                 (5U)
/*! TF3BR1
 *  0b0..The 3-Bit Run, Sampling 1s Test has passed
 *  0b1..The 3-Bit Run, Sampling 1s Test has failed
 */
#define TRNG_STATUS_TF3BR1(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_STATUS_TF3BR1_SHIFT)) & TRNG_STATUS_TF3BR1_MASK)

#define TRNG_STATUS_TFLR_MASK                    (0x2000U)
#define TRNG_STATUS_TFLR_SHIFT                   (13U)
/*! TFLR
 *  0b0..The Long Run Test has passed
 *  0b1..The Long Run Test has failed
 */
#define TRNG_STATUS_TFLR(x)                      (((uint32_t)(((uint32_t)(x)) << TRNG_STATUS_TFLR_SHIFT)) & TRNG_STATUS_TFLR_MASK)

#define TRNG_STATUS_TFMB_MASK                    (0x8000U)
#define TRNG_STATUS_TFMB_SHIFT                   (15U)
/*! TFMB
 *  0b0..The Mono Bit Test has passed
 *  0b1..The Mono Bit Test has failed
 */
#define TRNG_STATUS_TFMB(x)                      (((uint32_t)(((uint32_t)(x)) << TRNG_STATUS_TFMB_SHIFT)) & TRNG_STATUS_TFMB_MASK)

#define TRNG_STATUS_RETRY_CT_MASK                (0xF0000U)
#define TRNG_STATUS_RETRY_CT_SHIFT               (16U)
#define TRNG_STATUS_RETRY_CT(x)                  (((uint32_t)(((uint32_t)(x)) << TRNG_STATUS_RETRY_CT_SHIFT)) & TRNG_STATUS_RETRY_CT_MASK)
/*! @} */

/*! @name ENT - Entropy Read Register */
/*! @{ */

#define TRNG_ENT_ENT_MASK                        (0xFFFFFFFFU)
#define TRNG_ENT_ENT_SHIFT                       (0U)
#define TRNG_ENT_ENT(x)                          (((uint32_t)(((uint32_t)(x)) << TRNG_ENT_ENT_SHIFT)) & TRNG_ENT_ENT_MASK)
/*! @} */

/* The count of TRNG_ENT */
#define TRNG_ENT_COUNT                           (8U)

/*! @name SEC_CFG - Security Configuration Register */
/*! @{ */

#define TRNG_SEC_CFG_NO_PRGM_MASK                (0x2U)
#define TRNG_SEC_CFG_NO_PRGM_SHIFT               (1U)
/*! NO_PRGM
 *  0b0..TRNG configuration registers can be modified.
 *  0b1..TRNG configuration registers cannot be modified.
 */
#define TRNG_SEC_CFG_NO_PRGM(x)                  (((uint32_t)(((uint32_t)(x)) << TRNG_SEC_CFG_NO_PRGM_SHIFT)) & TRNG_SEC_CFG_NO_PRGM_MASK)
/*! @} */

/*! @name INT_CTRL - Interrupt Control Register */
/*! @{ */

#define TRNG_INT_CTRL_HW_ERR_MASK                (0x1U)
#define TRNG_INT_CTRL_HW_ERR_SHIFT               (0U)
/*! HW_ERR
 *  0b0..Clears the INT_STATUS[HW_ERR] bit.
 *  0b1..Enables the INT_STATUS[HW_ERR] bit to be set, thereby enabling interrupt generation for the HW_ERR condition.
 */
#define TRNG_INT_CTRL_HW_ERR(x)                  (((uint32_t)(((uint32_t)(x)) << TRNG_INT_CTRL_HW_ERR_SHIFT)) & TRNG_INT_CTRL_HW_ERR_MASK)

#define TRNG_INT_CTRL_ENT_VAL_MASK               (0x2U)
#define TRNG_INT_CTRL_ENT_VAL_SHIFT              (1U)
/*! ENT_VAL
 *  0b0..Clears the INT_STATUS[ENT_VAL] bit.
 *  0b1..Enables the INT_STATUS[ENT_VAL] bit to be set, thereby enabling interrupt generation for the ENT_VAL condition.
 */
#define TRNG_INT_CTRL_ENT_VAL(x)                 (((uint32_t)(((uint32_t)(x)) << TRNG_INT_CTRL_ENT_VAL_SHIFT)) & TRNG_INT_CTRL_ENT_VAL_MASK)

#define TRNG_INT_CTRL_FRQ_CT_FAIL_MASK           (0x4U)
#define TRNG_INT_CTRL_FRQ_CT_FAIL_SHIFT          (2U)
/*! FRQ_CT_FAIL
 *  0b0..Clears the INT_STATUS[FRQ_CT_FAIL] bit.
 *  0b1..Enables the INT_STATUS[FRQ_CT_FAIL] bit to be set, thereby enabling interrupt generation for the FRQ_CT_FAIL condition.
 */
#define TRNG_INT_CTRL_FRQ_CT_FAIL(x)             (((uint32_t)(((uint32_t)(x)) << TRNG_INT_CTRL_FRQ_CT_FAIL_SHIFT)) & TRNG_INT_CTRL_FRQ_CT_FAIL_MASK)

#define TRNG_INT_CTRL_INTG_FLT_MASK              (0x8U)
#define TRNG_INT_CTRL_INTG_FLT_SHIFT             (3U)
/*! INTG_FLT
 *  0b0..Clears the INT_STATUS[INTG_FLT] bit.
 *  0b1..Enables the INT_STATUS[INTG_FLT] bit to be set, thereby enabling interrupt generation for the INTG_FLT condition.
 */
#define TRNG_INT_CTRL_INTG_FLT(x)                (((uint32_t)(((uint32_t)(x)) << TRNG_INT_CTRL_INTG_FLT_SHIFT)) & TRNG_INT_CTRL_INTG_FLT_MASK)

#define TRNG_INT_CTRL_UNUSED_MASK                (0xFFFFFFF0U)
#define TRNG_INT_CTRL_UNUSED_SHIFT               (4U)
#define TRNG_INT_CTRL_UNUSED(x)                  (((uint32_t)(((uint32_t)(x)) << TRNG_INT_CTRL_UNUSED_SHIFT)) & TRNG_INT_CTRL_UNUSED_MASK)
/*! @} */

/*! @name INT_MASK - Mask Register */
/*! @{ */

#define TRNG_INT_MASK_HW_ERR_MASK                (0x1U)
#define TRNG_INT_MASK_HW_ERR_SHIFT               (0U)
/*! HW_ERR
 *  0b0..HW_ERR interrupt is disabled.
 *  0b1..HW_ERR interrupt is enabled.
 */
#define TRNG_INT_MASK_HW_ERR(x)                  (((uint32_t)(((uint32_t)(x)) << TRNG_INT_MASK_HW_ERR_SHIFT)) & TRNG_INT_MASK_HW_ERR_MASK)

#define TRNG_INT_MASK_ENT_VAL_MASK               (0x2U)
#define TRNG_INT_MASK_ENT_VAL_SHIFT              (1U)
/*! ENT_VAL
 *  0b0..ENT_VAL interrupt is disabled.
 *  0b1..ENT_VAL interrupt is enabled.
 */
#define TRNG_INT_MASK_ENT_VAL(x)                 (((uint32_t)(((uint32_t)(x)) << TRNG_INT_MASK_ENT_VAL_SHIFT)) & TRNG_INT_MASK_ENT_VAL_MASK)

#define TRNG_INT_MASK_FRQ_CT_FAIL_MASK           (0x4U)
#define TRNG_INT_MASK_FRQ_CT_FAIL_SHIFT          (2U)
/*! FRQ_CT_FAIL
 *  0b0..FRQ_CT_FAIL interrupt is disabled.
 *  0b1..FRQ_CT_FAIL interrupt is enabled.
 */
#define TRNG_INT_MASK_FRQ_CT_FAIL(x)             (((uint32_t)(((uint32_t)(x)) << TRNG_INT_MASK_FRQ_CT_FAIL_SHIFT)) & TRNG_INT_MASK_FRQ_CT_FAIL_MASK)

#define TRNG_INT_MASK_INTG_FLT_MASK              (0x8U)
#define TRNG_INT_MASK_INTG_FLT_SHIFT             (3U)
/*! INTG_FLT
 *  0b0..INTG_FLT interrupt is disabled.
 *  0b1..INTG_FLT interrupt is enabled.
 */
#define TRNG_INT_MASK_INTG_FLT(x)                (((uint32_t)(((uint32_t)(x)) << TRNG_INT_MASK_INTG_FLT_SHIFT)) & TRNG_INT_MASK_INTG_FLT_MASK)
/*! @} */

/*! @name INT_STATUS - Interrupt Status Register */
/*! @{ */

#define TRNG_INT_STATUS_HW_ERR_MASK              (0x1U)
#define TRNG_INT_STATUS_HW_ERR_SHIFT             (0U)
/*! HW_ERR
 *  0b0..No error.
 *  0b1..Error detected.
 */
#define TRNG_INT_STATUS_HW_ERR(x)                (((uint32_t)(((uint32_t)(x)) << TRNG_INT_STATUS_HW_ERR_SHIFT)) & TRNG_INT_STATUS_HW_ERR_MASK)

#define TRNG_INT_STATUS_ENT_VAL_MASK             (0x2U)
#define TRNG_INT_STATUS_ENT_VAL_SHIFT            (1U)
/*! ENT_VAL
 *  0b0..Busy generating entropy. Any value read from the Entropy registers is invalid.
 *  0b1..Values read from the Entropy registers are valid.
 */
#define TRNG_INT_STATUS_ENT_VAL(x)               (((uint32_t)(((uint32_t)(x)) << TRNG_INT_STATUS_ENT_VAL_SHIFT)) & TRNG_INT_STATUS_ENT_VAL_MASK)

#define TRNG_INT_STATUS_FRQ_CT_FAIL_MASK         (0x4U)
#define TRNG_INT_STATUS_FRQ_CT_FAIL_SHIFT        (2U)
/*! FRQ_CT_FAIL
 *  0b0..No hardware nor self test frequency errors.
 *  0b1..The frequency counter has detected a failure.
 */
#define TRNG_INT_STATUS_FRQ_CT_FAIL(x)           (((uint32_t)(((uint32_t)(x)) << TRNG_INT_STATUS_FRQ_CT_FAIL_SHIFT)) & TRNG_INT_STATUS_FRQ_CT_FAIL_MASK)

#define TRNG_INT_STATUS_INTG_FLT_MASK            (0x8U)
#define TRNG_INT_STATUS_INTG_FLT_SHIFT           (3U)
/*! INTG_FLT
 *  0b0..No internal fault has been detected.
 *  0b1..TRNG has detected internal fault.
 */
#define TRNG_INT_STATUS_INTG_FLT(x)              (((uint32_t)(((uint32_t)(x)) << TRNG_INT_STATUS_INTG_FLT_SHIFT)) & TRNG_INT_STATUS_INTG_FLT_MASK)
/*! @} */

/*! @name OSC2_CTL - TRNG Oscillator 2 Control Register */
/*! @{ */

#define TRNG_OSC2_CTL_TRNG_ENT_CTL_MASK          (0x3U)
#define TRNG_OSC2_CTL_TRNG_ENT_CTL_SHIFT         (0U)
/*! TRNG_ENT_CTL - TRNG entropy generation control.
 *  0b00..Single oscillator mode, using OSC1 (default)
 *  0b01..Dual oscillator mode
 *  0b10..Single oscillator mode, using OSC2
 *  0b11..Unused, (bit field cannot be written to this value)
 */
#define TRNG_OSC2_CTL_TRNG_ENT_CTL(x)            (((uint32_t)(((uint32_t)(x)) << TRNG_OSC2_CTL_TRNG_ENT_CTL_SHIFT)) & TRNG_OSC2_CTL_TRNG_ENT_CTL_MASK)

#define TRNG_OSC2_CTL_OSC2_DIV_MASK              (0xCU)
#define TRNG_OSC2_CTL_OSC2_DIV_SHIFT             (2U)
/*! OSC2_DIV - Oscillator 2 Divide.
 *  0b00..Use ring oscillator 2 with no divide
 *  0b01..Use ring oscillator 2 divided-by-2
 *  0b10..Use ring oscillator 2 divided-by-4
 *  0b11..Use ring oscillator 2 divided-by-8
 */
#define TRNG_OSC2_CTL_OSC2_DIV(x)                (((uint32_t)(((uint32_t)(x)) << TRNG_OSC2_CTL_OSC2_DIV_SHIFT)) & TRNG_OSC2_CTL_OSC2_DIV_MASK)

#define TRNG_OSC2_CTL_OSC2_FCT_VAL_MASK          (0x200U)
#define TRNG_OSC2_CTL_OSC2_FCT_VAL_SHIFT         (9U)
/*! OSC2_FCT_VAL - TRNG Oscillator 2 Frequency Count Valid
 *  0b0..Frequency count is invalid.
 *  0b1..If TRNG_ENT_CTL = 10b, valid frequency count may be read from OSC2_FRQCNT.
 */
#define TRNG_OSC2_CTL_OSC2_FCT_VAL(x)            (((uint32_t)(((uint32_t)(x)) << TRNG_OSC2_CTL_OSC2_FCT_VAL_SHIFT)) & TRNG_OSC2_CTL_OSC2_FCT_VAL_MASK)

#define TRNG_OSC2_CTL_OSC_FAILSAFE_LMT_MASK      (0x3000U)
#define TRNG_OSC2_CTL_OSC_FAILSAFE_LMT_SHIFT     (12U)
/*! OSC_FAILSAFE_LMT - Oscillator fail safe limit.
 *  0b00..The limit N is 4096 (2^12) system clocks.
 *  0b01..The limit N is 65536 (2^16) system clocks. (default)
 *  0b10..N is 2^20 system clocks.
 *  0b11..N is 2^22 system clocks (full range of the counter being used).
 */
#define TRNG_OSC2_CTL_OSC_FAILSAFE_LMT(x)        (((uint32_t)(((uint32_t)(x)) << TRNG_OSC2_CTL_OSC_FAILSAFE_LMT_SHIFT)) & TRNG_OSC2_CTL_OSC_FAILSAFE_LMT_MASK)

#define TRNG_OSC2_CTL_OSC_FAILSAFE_TEST_MASK     (0x4000U)
#define TRNG_OSC2_CTL_OSC_FAILSAFE_TEST_SHIFT    (14U)
/*! OSC_FAILSAFE_TEST - Oscillator fail safe test.
 *  0b0..No impact.
 *  0b1..Disables oscillator 2 while in dual-oscillator mode (TRNG_ENT_CTL = 01b).
 */
#define TRNG_OSC2_CTL_OSC_FAILSAFE_TEST(x)       (((uint32_t)(((uint32_t)(x)) << TRNG_OSC2_CTL_OSC_FAILSAFE_TEST_SHIFT)) & TRNG_OSC2_CTL_OSC_FAILSAFE_TEST_MASK)
/*! @} */

/*! @name VID1 - Version ID Register (MS) */
/*! @{ */

#define TRNG_VID1_MIN_REV_MASK                   (0xFFU)
#define TRNG_VID1_MIN_REV_SHIFT                  (0U)
/*! MIN_REV
 *  0b00001011..Minor revision number for TRNG.
 */
#define TRNG_VID1_MIN_REV(x)                     (((uint32_t)(((uint32_t)(x)) << TRNG_VID1_MIN_REV_SHIFT)) & TRNG_VID1_MIN_REV_MASK)

#define TRNG_VID1_MAJ_REV_MASK                   (0xFF00U)
#define TRNG_VID1_MAJ_REV_SHIFT                  (8U)
/*! MAJ_REV
 *  0b00010100..Major revision number for TRNG.
 */
#define TRNG_VID1_MAJ_REV(x)                     (((uint32_t)(((uint32_t)(x)) << TRNG_VID1_MAJ_REV_SHIFT)) & TRNG_VID1_MAJ_REV_MASK)

#define TRNG_VID1_IP_ID_MASK                     (0xFFFF0000U)
#define TRNG_VID1_IP_ID_SHIFT                    (16U)
/*! IP_ID
 *  0b0000000000110000..ID for TRNG.
 */
#define TRNG_VID1_IP_ID(x)                       (((uint32_t)(((uint32_t)(x)) << TRNG_VID1_IP_ID_SHIFT)) & TRNG_VID1_IP_ID_MASK)
/*! @} */

/*! @name VID2 - Version ID Register (LS) */
/*! @{ */

#define TRNG_VID2_CONFIG_OPT_MASK                (0xFFU)
#define TRNG_VID2_CONFIG_OPT_SHIFT               (0U)
/*! CONFIG_OPT
 *  0b00000000..TRNG_CONFIG_OPT for TRNG.
 */
#define TRNG_VID2_CONFIG_OPT(x)                  (((uint32_t)(((uint32_t)(x)) << TRNG_VID2_CONFIG_OPT_SHIFT)) & TRNG_VID2_CONFIG_OPT_MASK)

#define TRNG_VID2_ECO_REV_MASK                   (0xFF00U)
#define TRNG_VID2_ECO_REV_SHIFT                  (8U)
/*! ECO_REV
 *  0b00000000..TRNG_ECO_REV for TRNG.
 */
#define TRNG_VID2_ECO_REV(x)                     (((uint32_t)(((uint32_t)(x)) << TRNG_VID2_ECO_REV_SHIFT)) & TRNG_VID2_ECO_REV_MASK)

#define TRNG_VID2_INTG_OPT_MASK                  (0xFF0000U)
#define TRNG_VID2_INTG_OPT_SHIFT                 (16U)
/*! INTG_OPT
 *  0b00001010..INTG_OPT for TRNG.
 */
#define TRNG_VID2_INTG_OPT(x)                    (((uint32_t)(((uint32_t)(x)) << TRNG_VID2_INTG_OPT_SHIFT)) & TRNG_VID2_INTG_OPT_MASK)

#define TRNG_VID2_ERA_MASK                       (0xFF000000U)
#define TRNG_VID2_ERA_SHIFT                      (24U)
/*! ERA
 *  0b00001011..ERA of the TRNG.
 */
#define TRNG_VID2_ERA(x)                         (((uint32_t)(((uint32_t)(x)) << TRNG_VID2_ERA_SHIFT)) & TRNG_VID2_ERA_MASK)
/*! @} */

/*! @name OSC_INV_CHAIN_LEN - Oscillator Inverter Chain Length Register */
/*! @{ */

#define TRNG_OSC_INV_CHAIN_LEN_OSC1_INV_CHAIN_LEN_MASK (0xFFU)
#define TRNG_OSC_INV_CHAIN_LEN_OSC1_INV_CHAIN_LEN_SHIFT (0U)
/*! OSC1_INV_CHAIN_LEN
 *  0b00010100..Adding 11 to this count are the total number of inversions occurring in ring oscillator 1.
 */
#define TRNG_OSC_INV_CHAIN_LEN_OSC1_INV_CHAIN_LEN(x) (((uint32_t)(((uint32_t)(x)) << TRNG_OSC_INV_CHAIN_LEN_OSC1_INV_CHAIN_LEN_SHIFT)) & TRNG_OSC_INV_CHAIN_LEN_OSC1_INV_CHAIN_LEN_MASK)

#define TRNG_OSC_INV_CHAIN_LEN_OSC2_INV_CHAIN_LEN_MASK (0xFF00U)
#define TRNG_OSC_INV_CHAIN_LEN_OSC2_INV_CHAIN_LEN_SHIFT (8U)
/*! OSC2_INV_CHAIN_LEN
 *  0b00011110..Adding 11 to this count are the total number of inversions occurring in ring oscillator 2.
 */
#define TRNG_OSC_INV_CHAIN_LEN_OSC2_INV_CHAIN_LEN(x) (((uint32_t)(((uint32_t)(x)) << TRNG_OSC_INV_CHAIN_LEN_OSC2_INV_CHAIN_LEN_SHIFT)) & TRNG_OSC_INV_CHAIN_LEN_OSC2_INV_CHAIN_LEN_MASK)
/*! @} */


/*!
 * @}
 */ /* end of group TRNG_Register_Masks */


/* TRNG - Peripheral instance base addresses */
/** Peripheral TRNG base address */
#define TRNG_BASE                                (0u)
/** Peripheral TRNG base pointer */
#define TRNG                                     ((TRNG_Type *)TRNG_BASE)
/** Array initializer of TRNG peripheral base addresses */
#define TRNG_BASE_ADDRS                          { TRNG_BASE }
/** Array initializer of TRNG peripheral base pointers */
#define TRNG_BASE_PTRS                           { TRNG }

/*!
 * @}
 */ /* end of group TRNG_Peripheral_Access_Layer */


/*
** End of section using anonymous unions
*/

#if defined(__ARMCC_VERSION)
  #if (__ARMCC_VERSION >= 6010050)
    #pragma clang diagnostic pop
  #else
    #pragma pop
  #endif
#elif defined(__CWCC__)
  #pragma pop
#elif defined(__GNUC__)
  /* leave anonymous unions enabled */
#elif defined(__IAR_SYSTEMS_ICC__)
  #pragma language=default
#else
  #error Not supported compiler type
#endif

/*!
 * @}
 */ /* end of group Peripheral_access_layer */


/* ----------------------------------------------------------------------------
   -- Macros for use with bit field definitions (xxx_SHIFT, xxx_MASK).
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup Bit_Field_Generic_Macros Macros for use with bit field definitions (xxx_SHIFT, xxx_MASK).
 * @{
 */

#if defined(__ARMCC_VERSION)
  #if (__ARMCC_VERSION >= 6010050)
    #pragma clang system_header
  #endif
#elif defined(__IAR_SYSTEMS_ICC__)
  #pragma system_include
#endif

/**
 * @brief Mask and left-shift a bit field value for use in a register bit range.
 * @param field Name of the register bit field.
 * @param value Value of the bit field.
 * @return Masked and shifted value.
 */
#define NXP_VAL2FLD(field, value)    (((value) << (field ## _SHIFT)) & (field ## _MASK))
/**
 * @brief Mask and right-shift a register value to extract a bit field value.
 * @param field Name of the register bit field.
 * @param value Value of the register.
 * @return Masked and shifted bit field value.
 */
#define NXP_FLD2VAL(field, value)    (((value) & (field ## _MASK)) >> (field ## _SHIFT))

/*!
 * @}
 */ /* end of group Bit_Field_Generic_Macros */


/* ----------------------------------------------------------------------------
   -- SDK Compatibility
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup SDK_Compatibility_Symbols SDK Compatibility
 * @{
 */

/* No SDK compatibility issues. */

/*!
 * @}
 */ /* end of group SDK_Compatibility_Symbols */


#endif  /* _SA_TRNG_256_NIRVANA1_H_ */

