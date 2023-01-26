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
**     Build:               b220626
**
**     Abstract:
**         CMSIS Peripheral Access Layer for ip_glikey
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
 * @file ip_glikey.h
 * @version 0.0
 * @date 0-00-00
 * @brief CMSIS Peripheral Access Layer for ip_glikey
 *
 * CMSIS Peripheral Access Layer for ip_glikey
 */

#ifndef _IP_GLIKEY_H_
#define _IP_GLIKEY_H_                            /**< Symbol preventing repeated inclusion */

#ifdef NXPCL_FEATURE_EXPORTED_FEATURE_HEADER
#include <nxpClConfig.h> // Exported features flags header
#endif /* NXPCL_FEATURE_EXPORTED_FEATURE_HEADER */

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
   -- IP_GLIKEY Peripheral Access Layer
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup IP_GLIKEY_Peripheral_Access_Layer IP_GLIKEY Peripheral Access Layer
 * @{
 */


/** IP_GLIKEY - Register Layout Typedef */
typedef struct {
  __IO uint32_t IP_GLIKEY_CTRL_0;                  /**< Control Register 0 SFR, offset: 0x0 */
  __IO uint32_t IP_GLIKEY_CTRL_1;                  /**< Control Regsiter 1 SFR, offset: 0x4 */
  __IO uint32_t IP_GLIKEY_INTR_CTRL;               /**< Interrupt Control Register, offset: 0x8 */
  __I  uint32_t IP_GLIKEY_STATUS;                  /**< Status Register, offset: 0xC */
       uint8_t RESERVED_0[4076];
  __I  uint32_t IP_GLIKEY_VERSION;                 /**< IP Version register, offset: 0xFFC */
} IP_GLIKEY_Type;

/* ----------------------------------------------------------------------------
   -- IP_GLIKEY Register Masks
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup IP_GLIKEY_Register_Masks IP_GLIKEY Register Masks
 * @{
 */

/*! @name IP_GLIKEY_CTRL_0 - Control Register 0 SFR */
/*! @{ */

#define IP_GLIKEY_IP_GLIKEY_CTRL_0_WRITE_INDEX_MASK (0xFFU)
#define IP_GLIKEY_IP_GLIKEY_CTRL_0_WRITE_INDEX_SHIFT (0U)
/*! write_index - Write Index
 */
#define IP_GLIKEY_IP_GLIKEY_CTRL_0_WRITE_INDEX(x) (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_CTRL_0_WRITE_INDEX_SHIFT)) & IP_GLIKEY_IP_GLIKEY_CTRL_0_WRITE_INDEX_MASK)

#define IP_GLIKEY_IP_GLIKEY_CTRL_0_RESERVED15_MASK (0xFF00U)
#define IP_GLIKEY_IP_GLIKEY_CTRL_0_RESERVED15_SHIFT (8U)
/*! reserved15 - Reserved for Future Use
 */
#define IP_GLIKEY_IP_GLIKEY_CTRL_0_RESERVED15(x) (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_CTRL_0_RESERVED15_SHIFT)) & IP_GLIKEY_IP_GLIKEY_CTRL_0_RESERVED15_MASK)

#define IP_GLIKEY_IP_GLIKEY_CTRL_0_WR_EN_0_MASK  (0x30000U)
#define IP_GLIKEY_IP_GLIKEY_CTRL_0_WR_EN_0_SHIFT (16U)
/*! wr_en_0 - Write Enable 0
 */
#define IP_GLIKEY_IP_GLIKEY_CTRL_0_WR_EN_0(x)    (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_CTRL_0_WR_EN_0_SHIFT)) & IP_GLIKEY_IP_GLIKEY_CTRL_0_WR_EN_0_MASK)

#define IP_GLIKEY_IP_GLIKEY_CTRL_0_SFT_RST_MASK  (0x40000U)
#define IP_GLIKEY_IP_GLIKEY_CTRL_0_SFT_RST_SHIFT (18U)
/*! sft_rst - Soft reset for the core reset (SFR configuration will be preseved).This register reads as 0
 */
#define IP_GLIKEY_IP_GLIKEY_CTRL_0_SFT_RST(x)    (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_CTRL_0_SFT_RST_SHIFT)) & IP_GLIKEY_IP_GLIKEY_CTRL_0_SFT_RST_MASK)

#define IP_GLIKEY_IP_GLIKEY_CTRL_0_RESERVED31_MASK (0xFFF80000U)
#define IP_GLIKEY_IP_GLIKEY_CTRL_0_RESERVED31_SHIFT (19U)
/*! reserved31 - Reserved for Future Use
 */
#define IP_GLIKEY_IP_GLIKEY_CTRL_0_RESERVED31(x) (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_CTRL_0_RESERVED31_SHIFT)) & IP_GLIKEY_IP_GLIKEY_CTRL_0_RESERVED31_MASK)
/*! @} */

/*! @name IP_GLIKEY_CTRL_1 - Control Regsiter 1 SFR */
/*! @{ */

#define IP_GLIKEY_IP_GLIKEY_CTRL_1_READ_INDEX_MASK (0xFFU)
#define IP_GLIKEY_IP_GLIKEY_CTRL_1_READ_INDEX_SHIFT (0U)
/*! read_index - Index status, Writing an index value to this register will request the block to return the lock status of this index
 */
#define IP_GLIKEY_IP_GLIKEY_CTRL_1_READ_INDEX(x) (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_CTRL_1_READ_INDEX_SHIFT)) & IP_GLIKEY_IP_GLIKEY_CTRL_1_READ_INDEX_MASK)

#define IP_GLIKEY_IP_GLIKEY_CTRL_1_RESERVED15_MASK (0xFF00U)
#define IP_GLIKEY_IP_GLIKEY_CTRL_1_RESERVED15_SHIFT (8U)
/*! reserved15 - Reserved for Future Use
 */
#define IP_GLIKEY_IP_GLIKEY_CTRL_1_RESERVED15(x) (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_CTRL_1_RESERVED15_SHIFT)) & IP_GLIKEY_IP_GLIKEY_CTRL_1_RESERVED15_MASK)

#define IP_GLIKEY_IP_GLIKEY_CTRL_1_WR_EN_1_MASK  (0x30000U)
#define IP_GLIKEY_IP_GLIKEY_CTRL_1_WR_EN_1_SHIFT (16U)
/*! wr_en_1 - Write Enable Zero
 */
#define IP_GLIKEY_IP_GLIKEY_CTRL_1_WR_EN_1(x)    (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_CTRL_1_WR_EN_1_SHIFT)) & IP_GLIKEY_IP_GLIKEY_CTRL_1_WR_EN_1_MASK)

#define IP_GLIKEY_IP_GLIKEY_CTRL_1_SFR_LOCK_MASK (0x3C0000U)
#define IP_GLIKEY_IP_GLIKEY_CTRL_1_SFR_LOCK_SHIFT (18U)
/*! sfr_lock - LOCK register for GLIKEY
 */
#define IP_GLIKEY_IP_GLIKEY_CTRL_1_SFR_LOCK(x)   (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_CTRL_1_SFR_LOCK_SHIFT)) & IP_GLIKEY_IP_GLIKEY_CTRL_1_SFR_LOCK_MASK)

#define IP_GLIKEY_IP_GLIKEY_CTRL_1_RESERVED31_MASK (0xFFC00000U)
#define IP_GLIKEY_IP_GLIKEY_CTRL_1_RESERVED31_SHIFT (22U)
/*! reserved31 - Reserved for Future Use
 */
#define IP_GLIKEY_IP_GLIKEY_CTRL_1_RESERVED31(x) (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_CTRL_1_RESERVED31_SHIFT)) & IP_GLIKEY_IP_GLIKEY_CTRL_1_RESERVED31_MASK)
/*! @} */

/*! @name IP_GLIKEY_INTR_CTRL - Interrupt Control Register */
/*! @{ */

#define IP_GLIKEY_IP_GLIKEY_INTR_CTRL_INT_EN_MASK (0x1U)
#define IP_GLIKEY_IP_GLIKEY_INTR_CTRL_INT_EN_SHIFT (0U)
/*! int_en - Interrupt Enable. Writing a 1, Interrupt asserts on Interrupt output port
 */
#define IP_GLIKEY_IP_GLIKEY_INTR_CTRL_INT_EN(x)  (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_INTR_CTRL_INT_EN_SHIFT)) & IP_GLIKEY_IP_GLIKEY_INTR_CTRL_INT_EN_MASK)

#define IP_GLIKEY_IP_GLIKEY_INTR_CTRL_INT_CLR_MASK (0x2U)
#define IP_GLIKEY_IP_GLIKEY_INTR_CTRL_INT_CLR_SHIFT (1U)
/*! int_clr - Interrupt Clear. Writing a 1 to this register creates a single interrupt clear pulse. This register reads as 0
 */
#define IP_GLIKEY_IP_GLIKEY_INTR_CTRL_INT_CLR(x) (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_INTR_CTRL_INT_CLR_SHIFT)) & IP_GLIKEY_IP_GLIKEY_INTR_CTRL_INT_CLR_MASK)

#define IP_GLIKEY_IP_GLIKEY_INTR_CTRL_INT_SET_MASK (0x4U)
#define IP_GLIKEY_IP_GLIKEY_INTR_CTRL_INT_SET_SHIFT (2U)
/*! int_set - Interrupt Set. Writing a 1 to this register asserts the interrupt. This register reads as 0
 */
#define IP_GLIKEY_IP_GLIKEY_INTR_CTRL_INT_SET(x) (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_INTR_CTRL_INT_SET_SHIFT)) & IP_GLIKEY_IP_GLIKEY_INTR_CTRL_INT_SET_MASK)

#define IP_GLIKEY_IP_GLIKEY_INTR_CTRL_RESERVED31_MASK (0xFFFFFFF8U)
#define IP_GLIKEY_IP_GLIKEY_INTR_CTRL_RESERVED31_SHIFT (3U)
/*! reserved31 - Reserved for Future Use
 */
#define IP_GLIKEY_IP_GLIKEY_INTR_CTRL_RESERVED31(x) (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_INTR_CTRL_RESERVED31_SHIFT)) & IP_GLIKEY_IP_GLIKEY_INTR_CTRL_RESERVED31_MASK)
/*! @} */

/*! @name IP_GLIKEY_STATUS - Status Register */
/*! @{ */

#define IP_GLIKEY_IP_GLIKEY_STATUS_INT_STATUS_MASK (0x1U)
#define IP_GLIKEY_IP_GLIKEY_STATUS_INT_STATUS_SHIFT (0U)
/*! int_status - Interrupt Status. Reflects the current status of the interrupt
 */
#define IP_GLIKEY_IP_GLIKEY_STATUS_INT_STATUS(x) (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_STATUS_INT_STATUS_SHIFT)) & IP_GLIKEY_IP_GLIKEY_STATUS_INT_STATUS_MASK)

#define IP_GLIKEY_IP_GLIKEY_STATUS_LOCK_STATUS_MASK (0x2U)
#define IP_GLIKEY_IP_GLIKEY_STATUS_LOCK_STATUS_SHIFT (1U)
/*! lock_status - Status of wich Indexes are currently locked
 */
#define IP_GLIKEY_IP_GLIKEY_STATUS_LOCK_STATUS(x) (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_STATUS_LOCK_STATUS_SHIFT)) & IP_GLIKEY_IP_GLIKEY_STATUS_LOCK_STATUS_MASK)

#define IP_GLIKEY_IP_GLIKEY_STATUS_ERROR_STATUS_MASK (0x1CU)
#define IP_GLIKEY_IP_GLIKEY_STATUS_ERROR_STATUS_SHIFT (2U)
/*! error_status - Status of the Error
 */
#define IP_GLIKEY_IP_GLIKEY_STATUS_ERROR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_STATUS_ERROR_STATUS_SHIFT)) & IP_GLIKEY_IP_GLIKEY_STATUS_ERROR_STATUS_MASK)

#define IP_GLIKEY_IP_GLIKEY_STATUS_RESERVED18_MASK (0x7FFE0U)
#define IP_GLIKEY_IP_GLIKEY_STATUS_RESERVED18_SHIFT (5U)
/*! reserved18 - Reserved for Future Use
 */
#define IP_GLIKEY_IP_GLIKEY_STATUS_RESERVED18(x) (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_STATUS_RESERVED18_SHIFT)) & IP_GLIKEY_IP_GLIKEY_STATUS_RESERVED18_MASK)

#define IP_GLIKEY_IP_GLIKEY_STATUS_FSM_STATE_MASK (0xFFF80000U)
#define IP_GLIKEY_IP_GLIKEY_STATUS_FSM_STATE_SHIFT (19U)
/*! fsm_state - Status of FSM
 */
#define IP_GLIKEY_IP_GLIKEY_STATUS_FSM_STATE(x)  (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_STATUS_FSM_STATE_SHIFT)) & IP_GLIKEY_IP_GLIKEY_STATUS_FSM_STATE_MASK)
/*! @} */

/*! @name IP_GLIKEY_VERSION - IP Version register */
/*! @{ */

#define IP_GLIKEY_IP_GLIKEY_VERSION_Z_MASK       (0xFU)
#define IP_GLIKEY_IP_GLIKEY_VERSION_Z_SHIFT      (0U)
/*! z - Extended revision number in X.Y1Y2.Z, e.g. 1.20.3.
 */
#define IP_GLIKEY_IP_GLIKEY_VERSION_Z(x)         (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_VERSION_Z_SHIFT)) & IP_GLIKEY_IP_GLIKEY_VERSION_Z_MASK)

#define IP_GLIKEY_IP_GLIKEY_VERSION_Y2_MASK      (0xF0U)
#define IP_GLIKEY_IP_GLIKEY_VERSION_Y2_SHIFT     (4U)
/*! y2 - Minor revision number 2 in X.Y1Y2.Z, e.g. 1.20.3.
 */
#define IP_GLIKEY_IP_GLIKEY_VERSION_Y2(x)        (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_VERSION_Y2_SHIFT)) & IP_GLIKEY_IP_GLIKEY_VERSION_Y2_MASK)

#define IP_GLIKEY_IP_GLIKEY_VERSION_Y1_MASK      (0xF00U)
#define IP_GLIKEY_IP_GLIKEY_VERSION_Y1_SHIFT     (8U)
/*! y1 - Minor revision number 1 in X.Y1Y2.Z, e.g. 1.20.3.
 */
#define IP_GLIKEY_IP_GLIKEY_VERSION_Y1(x)        (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_VERSION_Y1_SHIFT)) & IP_GLIKEY_IP_GLIKEY_VERSION_Y1_MASK)

#define IP_GLIKEY_IP_GLIKEY_VERSION_X_MASK       (0xF000U)
#define IP_GLIKEY_IP_GLIKEY_VERSION_X_SHIFT      (12U)
/*! x - Major revision number in X.Y1Y2.Z, e.g. 1.20.3.
 */
#define IP_GLIKEY_IP_GLIKEY_VERSION_X(x)         (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_VERSION_X_SHIFT)) & IP_GLIKEY_IP_GLIKEY_VERSION_X_MASK)

#define IP_GLIKEY_IP_GLIKEY_VERSION_MILESTONE_MASK (0x30000U)
#define IP_GLIKEY_IP_GLIKEY_VERSION_MILESTONE_SHIFT (16U)
/*! milestone - Release milestone. 00-PREL, 01-BR, 10-SI, 11-GO.
 */
#define IP_GLIKEY_IP_GLIKEY_VERSION_MILESTONE(x) (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_VERSION_MILESTONE_SHIFT)) & IP_GLIKEY_IP_GLIKEY_VERSION_MILESTONE_MASK)

#define IP_GLIKEY_IP_GLIKEY_VERSION_FSM_CONFIG_MASK (0x40000U)
#define IP_GLIKEY_IP_GLIKEY_VERSION_FSM_CONFIG_SHIFT (18U)
/*! fsm_config - 0:4 step, 1:8 step
 */
#define IP_GLIKEY_IP_GLIKEY_VERSION_FSM_CONFIG(x) (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_VERSION_FSM_CONFIG_SHIFT)) & IP_GLIKEY_IP_GLIKEY_VERSION_FSM_CONFIG_MASK)

#define IP_GLIKEY_IP_GLIKEY_VERSION_INDEX_CONFIG_MASK (0x7F80000U)
#define IP_GLIKEY_IP_GLIKEY_VERSION_INDEX_CONFIG_SHIFT (19U)
/*! index_config - Configured number of addressable indexes
 */
#define IP_GLIKEY_IP_GLIKEY_VERSION_INDEX_CONFIG(x) (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_VERSION_INDEX_CONFIG_SHIFT)) & IP_GLIKEY_IP_GLIKEY_VERSION_INDEX_CONFIG_MASK)

#define IP_GLIKEY_IP_GLIKEY_VERSION_RESERVED31_MASK (0xF8000000U)
#define IP_GLIKEY_IP_GLIKEY_VERSION_RESERVED31_SHIFT (27U)
/*! reserved31 - Reserved for Future Use
 */
#define IP_GLIKEY_IP_GLIKEY_VERSION_RESERVED31(x) (((uint32_t)(((uint32_t)(x)) << IP_GLIKEY_IP_GLIKEY_VERSION_RESERVED31_SHIFT)) & IP_GLIKEY_IP_GLIKEY_VERSION_RESERVED31_MASK)
/*! @} */


/*!
 * @}
 */ /* end of group IP_GLIKEY_Register_Masks */


/* IP_GLIKEY - Peripheral instance base addresses */
/** Peripheral IP_GLIKEY base address */
#define IP_GLIKEY_BASE                           (0u)
/** Peripheral IP_GLIKEY base pointer */
#define IP_GLIKEY                                ((IP_GLIKEY_Type *)IP_GLIKEY_BASE)
/** Array initializer of IP_GLIKEY peripheral base addresses */
#define IP_GLIKEY_BASE_ADDRS                     { IP_GLIKEY_BASE }
/** Array initializer of IP_GLIKEY peripheral base pointers */
#define IP_GLIKEY_BASE_PTRS                      { IP_GLIKEY }

/*!
 * @}
 */ /* end of group IP_GLIKEY_Peripheral_Access_Layer */


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


#endif  /* _IP_GLIKEY_H_ */

