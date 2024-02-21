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
**         CMSIS Peripheral Access Layer for ip_gdet
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
 * @file ip_gdet.h
 * @version 0.0
 * @date 0-00-00
 * @brief CMSIS Peripheral Access Layer for ip_gdet
 *
 * CMSIS Peripheral Access Layer for ip_gdet
 */

#ifndef _IP_GDET_H_
#define _IP_GDET_H_                              /**< Symbol preventing repeated inclusion */

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
   -- GDET Peripheral Access Layer
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup GDET_Peripheral_Access_Layer GDET Peripheral Access Layer
 * @{
 */

/** GDET - Register Layout Typedef */
typedef struct {
  __IO uint32_t GDET_UPDATE_TIMER;                 /**< Update timer control register, offset: 0x0 */
  __IO uint32_t GDET_CTRL1;                        /**< Reference update control register, offset: 0x4 */
  __IO uint32_t GDET_ENABLE1;                      /**< Enable register, offset: 0x8 */
  __IO uint32_t GDET_INIT_DEL1;                    /**< Initial delay register, offset: 0xC */
  __IO uint32_t GDET_INIT_DEL1_MODE1;              /**< Initial delay register, offset: 0x10 */
  __IO uint32_t GDET_INIT_DEL1_MODE2;              /**< Initial delay register, offset: 0x14 */
  __IO uint32_t GDET_MARGIN1;                      /**< Margin definition register, offset: 0x18 */
  __I  uint32_t GDET_STATUS1;                      /**< Status register, offset: 0x1C */
  __I  uint32_t GDET_RESULT1;                      /**< Result register, offset: 0x20 */
       uint8_t RESERVED_0[2012];
  __IO uint32_t GDET_AUTO_TRIM;                    /**< Auto Trim enable Register, offset: 0x800 */
  __I  uint32_t GDET_TRIM_RES;                     /**< Result of the auto trim procedure register, offset: 0x804 */
  __IO uint32_t GDET_DLY_CTRL;                     /**< GDET delay control register, offset: 0x808 */
  __O  uint32_t GDET_CTRL_CLR;                     /**< GDET Clear Control register, offset: 0x80C */
       uint8_t RESERVED_1[2028];
  __I  uint32_t GDET_IP_VERSION;                   /**< IP Version register, offset: 0xFFC */
} GDET_Type;

/* ----------------------------------------------------------------------------
   -- GDET Register Masks
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup GDET_Register_Masks GDET Register Masks
 * @{
 */

/*! @name GDET_UPDATE_TIMER - Update timer control register */
/*! @{ */

#define GDET_GDET_UPDATE_TIMER_UPD_RATE_MASK     (0xFU)
#define GDET_GDET_UPDATE_TIMER_UPD_RATE_SHIFT    (0U)
/*! upd_rate - Defines the number of clock cycle between two update pulses as a power of 2. A value
 *    of 0 defines a continuously active update pulse, 1 an update pulse every second cycle, 2 every
 *    4 cycles, ....
 */
#define GDET_GDET_UPDATE_TIMER_UPD_RATE(x)       (((uint32_t)(((uint32_t)(x)) << GDET_GDET_UPDATE_TIMER_UPD_RATE_SHIFT)) & GDET_GDET_UPDATE_TIMER_UPD_RATE_MASK)

#define GDET_GDET_UPDATE_TIMER_UPD_STOP_MASK     (0x10U)
#define GDET_GDET_UPDATE_TIMER_UPD_STOP_SHIFT    (4U)
/*! upd_stop - A value of 1 stops the timer and the timer will not be taken into account for generating update pulses
 */
#define GDET_GDET_UPDATE_TIMER_UPD_STOP(x)       (((uint32_t)(((uint32_t)(x)) << GDET_GDET_UPDATE_TIMER_UPD_STOP_SHIFT)) & GDET_GDET_UPDATE_TIMER_UPD_STOP_MASK)

#define GDET_GDET_UPDATE_TIMER_UPD_MAN_MASK      (0x20U)
#define GDET_GDET_UPDATE_TIMER_UPD_MAN_SHIFT     (5U)
/*! upd_man - Writing a 1 to this register creates a single update pulse and resets the timer. This register reads as 0
 */
#define GDET_GDET_UPDATE_TIMER_UPD_MAN(x)        (((uint32_t)(((uint32_t)(x)) << GDET_GDET_UPDATE_TIMER_UPD_MAN_SHIFT)) & GDET_GDET_UPDATE_TIMER_UPD_MAN_MASK)

#define GDET_GDET_UPDATE_TIMER_RFU_MASK          (0xFFFFFFC0U)
#define GDET_GDET_UPDATE_TIMER_RFU_SHIFT         (6U)
/*! rfu - Reserved for Future Use
 */
#define GDET_GDET_UPDATE_TIMER_RFU(x)            (((uint32_t)(((uint32_t)(x)) << GDET_GDET_UPDATE_TIMER_RFU_SHIFT)) & GDET_GDET_UPDATE_TIMER_RFU_MASK)
/*! @} */

/*! @name GDET_CTRL1 - Reference update control register */
/*! @{ */

#define GDET_GDET_CTRL1_CHG_SEL1_MASK            (0x3U)
#define GDET_GDET_CTRL1_CHG_SEL1_SHIFT           (0U)
/*! chg_sel1 - Selects the update value to be added to the reference value
 */
#define GDET_GDET_CTRL1_CHG_SEL1(x)              (((uint32_t)(((uint32_t)(x)) << GDET_GDET_CTRL1_CHG_SEL1_SHIFT)) & GDET_GDET_CTRL1_CHG_SEL1_MASK)

#define GDET_GDET_CTRL1_WEIGHT1_MASK             (0xCU)
#define GDET_GDET_CTRL1_WEIGHT1_SHIFT            (2U)
/*! weight1 - Selects the weight of the update value when added to the reference value.
 */
#define GDET_GDET_CTRL1_WEIGHT1(x)               (((uint32_t)(((uint32_t)(x)) << GDET_GDET_CTRL1_WEIGHT1_SHIFT)) & GDET_GDET_CTRL1_WEIGHT1_MASK)

#define GDET_GDET_CTRL1_IGN_ERR1_MASK            (0x10U)
#define GDET_GDET_CTRL1_IGN_ERR1_SHIFT           (4U)
/*! ign_err1 - Ignore error being set in min/max calculation
 */
#define GDET_GDET_CTRL1_IGN_ERR1(x)              (((uint32_t)(((uint32_t)(x)) << GDET_GDET_CTRL1_IGN_ERR1_SHIFT)) & GDET_GDET_CTRL1_IGN_ERR1_MASK)

#define GDET_GDET_CTRL1_IGN_POS1_MASK            (0x20U)
#define GDET_GDET_CTRL1_IGN_POS1_SHIFT           (5U)
/*! ign_pos1 - Ignore results based on the rising edge of the toggle pulse
 */
#define GDET_GDET_CTRL1_IGN_POS1(x)              (((uint32_t)(((uint32_t)(x)) << GDET_GDET_CTRL1_IGN_POS1_SHIFT)) & GDET_GDET_CTRL1_IGN_POS1_MASK)

#define GDET_GDET_CTRL1_IGN_NEG1_MASK            (0x40U)
#define GDET_GDET_CTRL1_IGN_NEG1_SHIFT           (6U)
/*! ign_neg1 - Ignore results based on the falling edge of the toggle pulse
 */
#define GDET_GDET_CTRL1_IGN_NEG1(x)              (((uint32_t)(((uint32_t)(x)) << GDET_GDET_CTRL1_IGN_NEG1_SHIFT)) & GDET_GDET_CTRL1_IGN_NEG1_MASK)

#define GDET_GDET_CTRL1_FULLCYC1_MASK            (0x80U)
#define GDET_GDET_CTRL1_FULLCYC1_SHIFT           (7U)
/*! fullcyc1 - Select full cycle coverage (toggle FF clocked with rising edge)
 */
#define GDET_GDET_CTRL1_FULLCYC1(x)              (((uint32_t)(((uint32_t)(x)) << GDET_GDET_CTRL1_FULLCYC1_SHIFT)) & GDET_GDET_CTRL1_FULLCYC1_MASK)

#define GDET_GDET_CTRL1_DBL_DLY1_MASK            (0x100U)
#define GDET_GDET_CTRL1_DBL_DLY1_SHIFT           (8U)
/*! dbl_dly1 - Doubles the delay in the delay chain
 */
#define GDET_GDET_CTRL1_DBL_DLY1(x)              (((uint32_t)(((uint32_t)(x)) << GDET_GDET_CTRL1_DBL_DLY1_SHIFT)) & GDET_GDET_CTRL1_DBL_DLY1_MASK)

#define GDET_GDET_CTRL1_EXTVPASS1_MASK           (0x400U)
#define GDET_GDET_CTRL1_EXTVPASS1_SHIFT          (10U)
/*! extvpass1 - If set, minimum and maximum results values will be not flagged as error
 */
#define GDET_GDET_CTRL1_EXTVPASS1(x)             (((uint32_t)(((uint32_t)(x)) << GDET_GDET_CTRL1_EXTVPASS1_SHIFT)) & GDET_GDET_CTRL1_EXTVPASS1_MASK)

#define GDET_GDET_CTRL1_RFU_MASK                 (0x800U)
#define GDET_GDET_CTRL1_RFU_SHIFT                (11U)
/*! rfu - Reserved for Future Use
 */
#define GDET_GDET_CTRL1_RFU(x)                   (((uint32_t)(((uint32_t)(x)) << GDET_GDET_CTRL1_RFU_SHIFT)) & GDET_GDET_CTRL1_RFU_MASK)

#define GDET_GDET_CTRL1_TARGET1_MASK             (0x3F000U)
#define GDET_GDET_CTRL1_TARGET1_SHIFT            (12U)
/*! target1 - Target result value for autotrim. Also reference value for fixed ref and for stab_ref
 */
#define GDET_GDET_CTRL1_TARGET1(x)               (((uint32_t)(((uint32_t)(x)) << GDET_GDET_CTRL1_TARGET1_SHIFT)) & GDET_GDET_CTRL1_TARGET1_MASK)

#define GDET_GDET_CTRL1_RFU2_MASK                (0xFFFC0000U)
#define GDET_GDET_CTRL1_RFU2_SHIFT               (18U)
/*! rfu2 - Reserved for Future Use
 */
#define GDET_GDET_CTRL1_RFU2(x)                  (((uint32_t)(((uint32_t)(x)) << GDET_GDET_CTRL1_RFU2_SHIFT)) & GDET_GDET_CTRL1_RFU2_MASK)
/*! @} */

/*! @name GDET_ENABLE1 - Enable register */
/*! @{ */

#define GDET_GDET_ENABLE1_EN1_MASK               (0x1U)
#define GDET_GDET_ENABLE1_EN1_SHIFT              (0U)
/*! en1 - If set, the detector will request the reference clock
 */
#define GDET_GDET_ENABLE1_EN1(x)                 (((uint32_t)(((uint32_t)(x)) << GDET_GDET_ENABLE1_EN1_SHIFT)) & GDET_GDET_ENABLE1_EN1_MASK)

#define GDET_GDET_ENABLE1_RFU_MASK               (0xFFFFFFFEU)
#define GDET_GDET_ENABLE1_RFU_SHIFT              (1U)
/*! rfu - Reserved for Future Use
 */
#define GDET_GDET_ENABLE1_RFU(x)                 (((uint32_t)(((uint32_t)(x)) << GDET_GDET_ENABLE1_RFU_SHIFT)) & GDET_GDET_ENABLE1_RFU_MASK)
/*! @} */

/*! @name GDET_INIT_DEL1 - Initial delay register */
/*! @{ */

#define GDET_GDET_INIT_DEL1_TRIM1_MASK           (0x7FU)
#define GDET_GDET_INIT_DEL1_TRIM1_SHIFT          (0U)
/*! trim1 - Trim setting defining the initial delay
 */
#define GDET_GDET_INIT_DEL1_TRIM1(x)             (((uint32_t)(((uint32_t)(x)) << GDET_GDET_INIT_DEL1_TRIM1_SHIFT)) & GDET_GDET_INIT_DEL1_TRIM1_MASK)

#define GDET_GDET_INIT_DEL1_RFU1_MASK            (0xFF80U)
#define GDET_GDET_INIT_DEL1_RFU1_SHIFT           (7U)
/*! rfu1 - Reserved for Future Use
 */
#define GDET_GDET_INIT_DEL1_RFU1(x)              (((uint32_t)(((uint32_t)(x)) << GDET_GDET_INIT_DEL1_RFU1_SHIFT)) & GDET_GDET_INIT_DEL1_RFU1_MASK)

#define GDET_GDET_INIT_DEL1_MIN_REF1_MASK        (0x3F0000U)
#define GDET_GDET_INIT_DEL1_MIN_REF1_SHIFT       (16U)
/*! min_ref1 - Smallest allowed reference value
 */
#define GDET_GDET_INIT_DEL1_MIN_REF1(x)          (((uint32_t)(((uint32_t)(x)) << GDET_GDET_INIT_DEL1_MIN_REF1_SHIFT)) & GDET_GDET_INIT_DEL1_MIN_REF1_MASK)

#define GDET_GDET_INIT_DEL1_RFU2_MASK            (0xC00000U)
#define GDET_GDET_INIT_DEL1_RFU2_SHIFT           (22U)
/*! rfu2 - Reserved for Future Use
 */
#define GDET_GDET_INIT_DEL1_RFU2(x)              (((uint32_t)(((uint32_t)(x)) << GDET_GDET_INIT_DEL1_RFU2_SHIFT)) & GDET_GDET_INIT_DEL1_RFU2_MASK)

#define GDET_GDET_INIT_DEL1_MAX_REF1_MASK        (0x3F000000U)
#define GDET_GDET_INIT_DEL1_MAX_REF1_SHIFT       (24U)
/*! max_ref1 - Highest allowed reference value
 */
#define GDET_GDET_INIT_DEL1_MAX_REF1(x)          (((uint32_t)(((uint32_t)(x)) << GDET_GDET_INIT_DEL1_MAX_REF1_SHIFT)) & GDET_GDET_INIT_DEL1_MAX_REF1_MASK)

#define GDET_GDET_INIT_DEL1_RFU3_MASK            (0xC0000000U)
#define GDET_GDET_INIT_DEL1_RFU3_SHIFT           (30U)
/*! rfu3 - Reserved for Future Use
 */
#define GDET_GDET_INIT_DEL1_RFU3(x)              (((uint32_t)(((uint32_t)(x)) << GDET_GDET_INIT_DEL1_RFU3_SHIFT)) & GDET_GDET_INIT_DEL1_RFU3_MASK)
/*! @} */

/*! @name GDET_INIT_DEL1_MODE1 - Initial delay register */
/*! @{ */

#define GDET_GDET_INIT_DEL1_MODE1_TRIM1_MASK     (0x7FU)
#define GDET_GDET_INIT_DEL1_MODE1_TRIM1_SHIFT    (0U)
/*! trim1 - Trim setting defining the initial delay
 */
#define GDET_GDET_INIT_DEL1_MODE1_TRIM1(x)       (((uint32_t)(((uint32_t)(x)) << GDET_GDET_INIT_DEL1_MODE1_TRIM1_SHIFT)) & GDET_GDET_INIT_DEL1_MODE1_TRIM1_MASK)

#define GDET_GDET_INIT_DEL1_MODE1_RFU1_MASK      (0xFFFFFF80U)
#define GDET_GDET_INIT_DEL1_MODE1_RFU1_SHIFT     (7U)
/*! rfu1 - Reserved for Future Use
 */
#define GDET_GDET_INIT_DEL1_MODE1_RFU1(x)        (((uint32_t)(((uint32_t)(x)) << GDET_GDET_INIT_DEL1_MODE1_RFU1_SHIFT)) & GDET_GDET_INIT_DEL1_MODE1_RFU1_MASK)
/*! @} */

/*! @name GDET_INIT_DEL1_MODE2 - Initial delay register */
/*! @{ */

#define GDET_GDET_INIT_DEL1_MODE2_TRIM1_MASK     (0x7FU)
#define GDET_GDET_INIT_DEL1_MODE2_TRIM1_SHIFT    (0U)
/*! trim1 - Trim setting defining the initial delay
 */
#define GDET_GDET_INIT_DEL1_MODE2_TRIM1(x)       (((uint32_t)(((uint32_t)(x)) << GDET_GDET_INIT_DEL1_MODE2_TRIM1_SHIFT)) & GDET_GDET_INIT_DEL1_MODE2_TRIM1_MASK)

#define GDET_GDET_INIT_DEL1_MODE2_RFU1_MASK      (0xFFFFFF80U)
#define GDET_GDET_INIT_DEL1_MODE2_RFU1_SHIFT     (7U)
/*! rfu1 - Reserved for Future Use
 */
#define GDET_GDET_INIT_DEL1_MODE2_RFU1(x)        (((uint32_t)(((uint32_t)(x)) << GDET_GDET_INIT_DEL1_MODE2_RFU1_SHIFT)) & GDET_GDET_INIT_DEL1_MODE2_RFU1_MASK)
/*! @} */

/*! @name GDET_MARGIN1 - Margin definition register */
/*! @{ */

#define GDET_GDET_MARGIN1_MNEG1_MASK             (0x3FU)
#define GDET_GDET_MARGIN1_MNEG1_SHIFT            (0U)
/*! mneg1 - Negative margin to be substracted from the reference before being compared against the measurement value
 */
#define GDET_GDET_MARGIN1_MNEG1(x)               (((uint32_t)(((uint32_t)(x)) << GDET_GDET_MARGIN1_MNEG1_SHIFT)) & GDET_GDET_MARGIN1_MNEG1_MASK)

#define GDET_GDET_MARGIN1_MPOS1_MASK             (0xFC0U)
#define GDET_GDET_MARGIN1_MPOS1_SHIFT            (6U)
/*! mpos1 - Positive margin to be added to the reference before being compared against the measurement value
 */
#define GDET_GDET_MARGIN1_MPOS1(x)               (((uint32_t)(((uint32_t)(x)) << GDET_GDET_MARGIN1_MPOS1_SHIFT)) & GDET_GDET_MARGIN1_MPOS1_MASK)

#define GDET_GDET_MARGIN1_RFU1_MASK              (0xFFFFF000U)
#define GDET_GDET_MARGIN1_RFU1_SHIFT             (12U)
/*! rfu1 - Reserved for Future Use
 */
#define GDET_GDET_MARGIN1_RFU1(x)                (((uint32_t)(((uint32_t)(x)) << GDET_GDET_MARGIN1_RFU1_SHIFT)) & GDET_GDET_MARGIN1_RFU1_MASK)
/*! @} */

/*! @name GDET_STATUS1 - Status register */
/*! @{ */

#define GDET_GDET_STATUS1_MIN1_MASK              (0x3FU)
#define GDET_GDET_STATUS1_MIN1_SHIFT             (0U)
/*! min1 - Minimum value found since last update pulse
 */
#define GDET_GDET_STATUS1_MIN1(x)                (((uint32_t)(((uint32_t)(x)) << GDET_GDET_STATUS1_MIN1_SHIFT)) & GDET_GDET_STATUS1_MIN1_MASK)

#define GDET_GDET_STATUS1_MAX1_MASK              (0xFC0U)
#define GDET_GDET_STATUS1_MAX1_SHIFT             (6U)
/*! max1 - Maximum value found since last update pulse
 */
#define GDET_GDET_STATUS1_MAX1(x)                (((uint32_t)(((uint32_t)(x)) << GDET_GDET_STATUS1_MAX1_SHIFT)) & GDET_GDET_STATUS1_MAX1_MASK)

#define GDET_GDET_STATUS1_REF1_MASK              (0x3F000U)
#define GDET_GDET_STATUS1_REF1_SHIFT             (12U)
/*! ref1 - Reference value found since last update pulse
 */
#define GDET_GDET_STATUS1_REF1(x)                (((uint32_t)(((uint32_t)(x)) << GDET_GDET_STATUS1_REF1_SHIFT)) & GDET_GDET_STATUS1_REF1_MASK)

#define GDET_GDET_STATUS1_RFU1_MASK              (0xFFFC0000U)
#define GDET_GDET_STATUS1_RFU1_SHIFT             (18U)
/*! rfu1 - Reserved for Future Use
 */
#define GDET_GDET_STATUS1_RFU1(x)                (((uint32_t)(((uint32_t)(x)) << GDET_GDET_STATUS1_RFU1_SHIFT)) & GDET_GDET_STATUS1_RFU1_MASK)
/*! @} */

/*! @name GDET_RESULT1 - Result register */
/*! @{ */

#define GDET_GDET_RESULT1_RESULT1_MASK           (0x3FU)
#define GDET_GDET_RESULT1_RESULT1_SHIFT          (0U)
/*! result1 - Latest result value
 */
#define GDET_GDET_RESULT1_RESULT1(x)             (((uint32_t)(((uint32_t)(x)) << GDET_GDET_RESULT1_RESULT1_SHIFT)) & GDET_GDET_RESULT1_RESULT1_MASK)

#define GDET_GDET_RESULT1_RFU_MASK               (0xFFFFFC0U)
#define GDET_GDET_RESULT1_RFU_SHIFT              (6U)
/*! rfu - Reserved for Future Use
 */
#define GDET_GDET_RESULT1_RFU(x)                 (((uint32_t)(((uint32_t)(x)) << GDET_GDET_RESULT1_RFU_SHIFT)) & GDET_GDET_RESULT1_RFU_MASK)

#define GDET_GDET_RESULT1_NEG_LAT1_MASK          (0x10000000U)
#define GDET_GDET_RESULT1_NEG_LAT1_SHIFT         (28U)
#define GDET_GDET_RESULT1_NEG_LAT1(x)            (((uint32_t)(((uint32_t)(x)) << GDET_GDET_RESULT1_NEG_LAT1_SHIFT)) & GDET_GDET_RESULT1_NEG_LAT1_MASK)

#define GDET_GDET_RESULT1_POS_LAT1_MASK          (0x20000000U)
#define GDET_GDET_RESULT1_POS_LAT1_SHIFT         (29U)
#define GDET_GDET_RESULT1_POS_LAT1(x)            (((uint32_t)(((uint32_t)(x)) << GDET_GDET_RESULT1_POS_LAT1_SHIFT)) & GDET_GDET_RESULT1_POS_LAT1_MASK)

#define GDET_GDET_RESULT1_ERR_NEG1_MASK          (0x40000000U)
#define GDET_GDET_RESULT1_ERR_NEG1_SHIFT         (30U)
/*! err_neg1 - Measurement below reference minus negative margin
 */
#define GDET_GDET_RESULT1_ERR_NEG1(x)            (((uint32_t)(((uint32_t)(x)) << GDET_GDET_RESULT1_ERR_NEG1_SHIFT)) & GDET_GDET_RESULT1_ERR_NEG1_MASK)

#define GDET_GDET_RESULT1_ERR_POS1_MASK          (0x80000000U)
#define GDET_GDET_RESULT1_ERR_POS1_SHIFT         (31U)
/*! err_pos1 - Measurement below reference plus positive margin
 */
#define GDET_GDET_RESULT1_ERR_POS1(x)            (((uint32_t)(((uint32_t)(x)) << GDET_GDET_RESULT1_ERR_POS1_SHIFT)) & GDET_GDET_RESULT1_ERR_POS1_MASK)
/*! @} */

/*! @name GDET_AUTO_TRIM - Auto Trim enable Register */
/*! @{ */

#define GDET_GDET_AUTO_TRIM_TRIM_EN_MASK         (0x1U)
#define GDET_GDET_AUTO_TRIM_TRIM_EN_SHIFT        (0U)
/*! trim_en - Auto Trim enable
 */
#define GDET_GDET_AUTO_TRIM_TRIM_EN(x)           (((uint32_t)(((uint32_t)(x)) << GDET_GDET_AUTO_TRIM_TRIM_EN_SHIFT)) & GDET_GDET_AUTO_TRIM_TRIM_EN_MASK)

#define GDET_GDET_AUTO_TRIM_RFU_MASK             (0xFFFFFFFEU)
#define GDET_GDET_AUTO_TRIM_RFU_SHIFT            (1U)
/*! rfu - Reserved for Future Use
 */
#define GDET_GDET_AUTO_TRIM_RFU(x)               (((uint32_t)(((uint32_t)(x)) << GDET_GDET_AUTO_TRIM_RFU_SHIFT)) & GDET_GDET_AUTO_TRIM_RFU_MASK)
/*! @} */

/*! @name GDET_TRIM_RES - Result of the auto trim procedure register */
/*! @{ */

#define GDET_GDET_TRIM_RES_TRIM_RES_MASK         (0x7FU)
#define GDET_GDET_TRIM_RES_TRIM_RES_SHIFT        (0U)
/*! trim_res - Result of the auto trim procedure
 */
#define GDET_GDET_TRIM_RES_TRIM_RES(x)           (((uint32_t)(((uint32_t)(x)) << GDET_GDET_TRIM_RES_TRIM_RES_SHIFT)) & GDET_GDET_TRIM_RES_TRIM_RES_MASK)

#define GDET_GDET_TRIM_RES_TRIM_FAIL_MASK        (0x80U)
#define GDET_GDET_TRIM_RES_TRIM_FAIL_SHIFT       (7U)
/*! trim_fail - Auto trim was not able to reach optimum result
 */
#define GDET_GDET_TRIM_RES_TRIM_FAIL(x)          (((uint32_t)(((uint32_t)(x)) << GDET_GDET_TRIM_RES_TRIM_FAIL_SHIFT)) & GDET_GDET_TRIM_RES_TRIM_FAIL_MASK)

#define GDET_GDET_TRIM_RES_TRIM_DONE_MASK        (0x100U)
#define GDET_GDET_TRIM_RES_TRIM_DONE_SHIFT       (8U)
/*! trim_done - Result of the auto trim procedure is available
 */
#define GDET_GDET_TRIM_RES_TRIM_DONE(x)          (((uint32_t)(((uint32_t)(x)) << GDET_GDET_TRIM_RES_TRIM_DONE_SHIFT)) & GDET_GDET_TRIM_RES_TRIM_DONE_MASK)

#define GDET_GDET_TRIM_RES_RFU3_MASK             (0xE00U)
#define GDET_GDET_TRIM_RES_RFU3_SHIFT            (9U)
/*! rfu3 - Reserved for Future Use
 */
#define GDET_GDET_TRIM_RES_RFU3(x)               (((uint32_t)(((uint32_t)(x)) << GDET_GDET_TRIM_RES_RFU3_SHIFT)) & GDET_GDET_TRIM_RES_RFU3_MASK)

#define GDET_GDET_TRIM_RES_RFU2_MASK             (0xFFFFF000U)
#define GDET_GDET_TRIM_RES_RFU2_SHIFT            (12U)
/*! rfu2 - Reserved for Future Use
 */
#define GDET_GDET_TRIM_RES_RFU2(x)               (((uint32_t)(((uint32_t)(x)) << GDET_GDET_TRIM_RES_RFU2_SHIFT)) & GDET_GDET_TRIM_RES_RFU2_MASK)
/*! @} */

/*! @name GDET_DLY_CTRL - GDET delay control register */
/*! @{ */

#define GDET_GDET_DLY_CTRL_VOL_SEL_MASK          (0x3U)
#define GDET_GDET_DLY_CTRL_VOL_SEL_SHIFT         (0U)
/*! vol_sel - GDET delay control of the voltage mode. Used to select the trim code appropiate to the voltage mode.
 */
#define GDET_GDET_DLY_CTRL_VOL_SEL(x)            (((uint32_t)(((uint32_t)(x)) << GDET_GDET_DLY_CTRL_VOL_SEL_SHIFT)) & GDET_GDET_DLY_CTRL_VOL_SEL_MASK)

#define GDET_GDET_DLY_CTRL_SW_VOL_CTRL_MASK      (0x4U)
#define GDET_GDET_DLY_CTRL_SW_VOL_CTRL_SHIFT     (2U)
/*! sw_vol_ctrl - Select the control of the trim code to the delay line via HW port (0) or SW SFR (1)
 */
#define GDET_GDET_DLY_CTRL_SW_VOL_CTRL(x)        (((uint32_t)(((uint32_t)(x)) << GDET_GDET_DLY_CTRL_SW_VOL_CTRL_SHIFT)) & GDET_GDET_DLY_CTRL_SW_VOL_CTRL_MASK)

#define GDET_GDET_DLY_CTRL_RFU_MASK              (0xFFFFFFF8U)
#define GDET_GDET_DLY_CTRL_RFU_SHIFT             (3U)
/*! rfu - Reserved for Future Use
 */
#define GDET_GDET_DLY_CTRL_RFU(x)                (((uint32_t)(((uint32_t)(x)) << GDET_GDET_DLY_CTRL_RFU_SHIFT)) & GDET_GDET_DLY_CTRL_RFU_MASK)
/*! @} */

/*! @name GDET_CTRL_CLR - GDET Clear Control register */
/*! @{ */

#define GDET_GDET_CTRL_CLR_SFT_RST_MASK          (0x1U)
#define GDET_GDET_CTRL_CLR_SFT_RST_SHIFT         (0U)
/*! sft_rst - Soft reset for the core reset (SFR configuration will be preseved).This register reads as 0
 */
#define GDET_GDET_CTRL_CLR_SFT_RST(x)            (((uint32_t)(((uint32_t)(x)) << GDET_GDET_CTRL_CLR_SFT_RST_SHIFT)) & GDET_GDET_CTRL_CLR_SFT_RST_MASK)
/*! @} */

/*! @name GDET_IP_VERSION - IP Version register */
/*! @{ */

#define GDET_GDET_IP_VERSION_Z_MASK              (0xFU)
#define GDET_GDET_IP_VERSION_Z_SHIFT             (0U)
/*! z - Extended revision number in X.Y1Y2.Z, e.g. 1.20.3.
 */
#define GDET_GDET_IP_VERSION_Z(x)                (((uint32_t)(((uint32_t)(x)) << GDET_GDET_IP_VERSION_Z_SHIFT)) & GDET_GDET_IP_VERSION_Z_MASK)

#define GDET_GDET_IP_VERSION_Y2_MASK             (0xF0U)
#define GDET_GDET_IP_VERSION_Y2_SHIFT            (4U)
/*! y2 - Minor revision number 2 in X.Y1Y2.Z, e.g. 1.20.3.
 */
#define GDET_GDET_IP_VERSION_Y2(x)               (((uint32_t)(((uint32_t)(x)) << GDET_GDET_IP_VERSION_Y2_SHIFT)) & GDET_GDET_IP_VERSION_Y2_MASK)

#define GDET_GDET_IP_VERSION_Y1_MASK             (0xF00U)
#define GDET_GDET_IP_VERSION_Y1_SHIFT            (8U)
/*! y1 - Minor revision number 1 in X.Y1Y2.Z, e.g. 1.20.3.
 */
#define GDET_GDET_IP_VERSION_Y1(x)               (((uint32_t)(((uint32_t)(x)) << GDET_GDET_IP_VERSION_Y1_SHIFT)) & GDET_GDET_IP_VERSION_Y1_MASK)

#define GDET_GDET_IP_VERSION_X_MASK              (0xF000U)
#define GDET_GDET_IP_VERSION_X_SHIFT             (12U)
/*! x - Major revision number in X.Y1Y2.Z, e.g. 1.20.3.
 */
#define GDET_GDET_IP_VERSION_X(x)                (((uint32_t)(((uint32_t)(x)) << GDET_GDET_IP_VERSION_X_SHIFT)) & GDET_GDET_IP_VERSION_X_MASK)

#define GDET_GDET_IP_VERSION_MILESTONE_MASK      (0x30000U)
#define GDET_GDET_IP_VERSION_MILESTONE_SHIFT     (16U)
/*! milestone - Release milestone. 00-PREL, 01-BR, 10-SI, 11-GO.
 */
#define GDET_GDET_IP_VERSION_MILESTONE(x)        (((uint32_t)(((uint32_t)(x)) << GDET_GDET_IP_VERSION_MILESTONE_SHIFT)) & GDET_GDET_IP_VERSION_MILESTONE_MASK)

#define GDET_GDET_IP_VERSION_RFU_MASK            (0xFFFC0000U)
#define GDET_GDET_IP_VERSION_RFU_SHIFT           (18U)
/*! rfu - Reserved for Future Use
 */
#define GDET_GDET_IP_VERSION_RFU(x)              (((uint32_t)(((uint32_t)(x)) << GDET_GDET_IP_VERSION_RFU_SHIFT)) & GDET_GDET_IP_VERSION_RFU_MASK)
/*! @} */


/*!
 * @}
 */ /* end of group GDET_Register_Masks */


/* GDET - Peripheral instance base addresses */
/** Peripheral GDET base address */
#define GDET_BASE                                 (0u)
/** Peripheral GDET base pointer */
#define GDET                                      ((GDET_Type *)GDET_BASE)
/** Array initializer of GDET peripheral base addresses */
#define GDET_BASE_ADDRS                          { GDET_BASE }
/** Array initializer of GDET peripheral base pointers */
#define GDET_BASE_PTRS                           { GDET }

/*!
 * @}
 */ /* end of group GDET_Peripheral_Access_Layer */


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


#endif  /* _IP_GDET_H_ */

