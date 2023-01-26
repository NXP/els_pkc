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
**         CMSIS Peripheral Access Layer for ip_puf
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
 * @file ip_puf.h
 * @version 0.0
 * @date 0-00-00
 * @brief CMSIS Peripheral Access Layer for ip_puf
 *
 * CMSIS Peripheral Access Layer for ip_puf
 */

#ifndef _IP_PUF_H_
#define _IP_PUF_H_                               /**< Symbol preventing repeated inclusion */

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
   -- IP_PUF Peripheral Access Layer
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup IP_PUF_Peripheral_Access_Layer IP_PUF Peripheral Access Layer
 * @{
 */

/** IP_PUF - Register Layout Typedef */
typedef struct {
  __IO uint32_t PUF_MODE;                          /**< Mode register, offset: 0x0 */
  __IO uint32_t PUF_CTRL;                          /**< Control register, offset: 0x4 */
  __I  uint32_t PUF_STATUS;                        /**< Status register, offset: 0x8 */
  __I  uint32_t PUF_VERSION;                       /**< Version register, offset: 0xC */
  __IO uint32_t PUF_CKSUM;                         /**< Checksum register, offset: 0x10 */
       uint8_t RESERVED_0[12];
  __IO uint32_t PUF_PARITY_0;                      /**< Parity register, offset: 0x20 */
  __IO uint32_t PUF_PARITY_1;                      /**< Parity register, offset: 0x24 */
  __IO uint32_t PUF_PARITY_2;                      /**< Parity register, offset: 0x28 */
       uint8_t RESERVED_1[20];
  __IO uint32_t PUF_IGNORE;                        /**< Ignore register, offset: 0x40 */
       uint8_t RESERVED_2[12];
  __IO uint32_t PUF_RNG;                           /**< Random Number register, offset: 0x50 */
       uint8_t RESERVED_3[12];
  __I  uint32_t PUF_KEY_0;                         /**< Key register, offset: 0x60 */
  __I  uint32_t PUF_KEY_1;                         /**< Key register, offset: 0x64 */
       uint8_t RESERVED_4[8];
  __IO uint32_t PUF_LOCK;                          /**< Lock register, offset: 0x70 */
  __I  uint32_t PUF_RO_FREQ;                       /**< RO Frequency register, offset: 0x74 */
  __I  uint32_t PUF_SLW_RO;                        /**< Slow RO register, offset: 0x78 */
       uint8_t RESERVED_5[16];
  __I  uint32_t PUF_BCH;                           /**< BCH register, offset: 0x8C */
       uint8_t RESERVED_6[3920];
  __I  uint32_t PUF_INT_STATUS;                    /**< Interrupt Status register, offset: 0xFE0 */
  __IO uint32_t PUF_INT_ENABLE;                    /**< Interrupt Enable register, offset: 0xFE4 */
  __IO uint32_t PUF_INT_STATUS_CLR;                /**< Interrupt Status Clear register, offset: 0xFE8 */
  __IO uint32_t PUF_INT_STATUS_SET;                /**< Interrupt Status Set register, offset: 0xFEC */
} IP_PUF_Type;

/* ----------------------------------------------------------------------------
   -- IP_PUF Register Masks
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup IP_PUF_Register_Masks IP_PUF Register Masks
 * @{
 */

/*! @name PUF_MODE - Mode register */
/*! @{ */

#define IP_PUF_PUF_MODE_START_MASK               (0x1U)
#define IP_PUF_PUF_MODE_START_SHIFT              (0U)
/*! start - Start
 */
#define IP_PUF_PUF_MODE_START(x)                 (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_MODE_START_SHIFT)) & IP_PUF_PUF_MODE_START_MASK)

#define IP_PUF_PUF_MODE_ENROLL_MASK              (0x2U)
#define IP_PUF_PUF_MODE_ENROLL_SHIFT             (1U)
/*! enroll - Enrollment
 */
#define IP_PUF_PUF_MODE_ENROLL(x)                (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_MODE_ENROLL_SHIFT)) & IP_PUF_PUF_MODE_ENROLL_MASK)

#define IP_PUF_PUF_MODE_MODE_RSVD_3_MASK         (0xCU)
#define IP_PUF_PUF_MODE_MODE_RSVD_3_SHIFT        (2U)
/*! mode_rsvd_3 - Reserved
 */
#define IP_PUF_PUF_MODE_MODE_RSVD_3(x)           (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_MODE_MODE_RSVD_3_SHIFT)) & IP_PUF_PUF_MODE_MODE_RSVD_3_MASK)

#define IP_PUF_PUF_MODE_SLW_LMT_MASK             (0xF0U)
#define IP_PUF_PUF_MODE_SLW_LMT_SHIFT            (4U)
/*! slw_lmt - Power of 2 count limit for slow limit
 */
#define IP_PUF_PUF_MODE_SLW_LMT(x)               (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_MODE_SLW_LMT_SHIFT)) & IP_PUF_PUF_MODE_SLW_LMT_MASK)

#define IP_PUF_PUF_MODE_MODE_RSVD_2_MASK         (0xF00U)
#define IP_PUF_PUF_MODE_MODE_RSVD_2_SHIFT        (8U)
/*! mode_rsvd_2 - Reserved
 */
#define IP_PUF_PUF_MODE_MODE_RSVD_2(x)           (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_MODE_MODE_RSVD_2_SHIFT)) & IP_PUF_PUF_MODE_MODE_RSVD_2_MASK)

#define IP_PUF_PUF_MODE_WRM_LMT_MASK             (0xF000U)
#define IP_PUF_PUF_MODE_WRM_LMT_SHIFT            (12U)
/*! wrm_lmt - Power of 2 count limit for warmup
 */
#define IP_PUF_PUF_MODE_WRM_LMT(x)               (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_MODE_WRM_LMT_SHIFT)) & IP_PUF_PUF_MODE_WRM_LMT_MASK)

#define IP_PUF_PUF_MODE_MODE_RSVD_1_MASK         (0xF0000U)
#define IP_PUF_PUF_MODE_MODE_RSVD_1_SHIFT        (16U)
/*! mode_rsvd_1 - Reserved
 */
#define IP_PUF_PUF_MODE_MODE_RSVD_1(x)           (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_MODE_MODE_RSVD_1_SHIFT)) & IP_PUF_PUF_MODE_MODE_RSVD_1_MASK)

#define IP_PUF_PUF_MODE_REC_LMT_MASK             (0xF00000U)
#define IP_PUF_PUF_MODE_REC_LMT_SHIFT            (20U)
/*! rec_lmt - Power of 2 count limit for reconstruction
 */
#define IP_PUF_PUF_MODE_REC_LMT(x)               (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_MODE_REC_LMT_SHIFT)) & IP_PUF_PUF_MODE_REC_LMT_MASK)

#define IP_PUF_PUF_MODE_MODE_RSVD_0_MASK         (0xF000000U)
#define IP_PUF_PUF_MODE_MODE_RSVD_0_SHIFT        (24U)
/*! mode_rsvd_0 - Reserved
 */
#define IP_PUF_PUF_MODE_MODE_RSVD_0(x)           (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_MODE_MODE_RSVD_0_SHIFT)) & IP_PUF_PUF_MODE_MODE_RSVD_0_MASK)

#define IP_PUF_PUF_MODE_ENR_LMT_MASK             (0xF0000000U)
#define IP_PUF_PUF_MODE_ENR_LMT_SHIFT            (28U)
/*! enr_lmt - Power of 2 count limit for enrollment
 */
#define IP_PUF_PUF_MODE_ENR_LMT(x)               (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_MODE_ENR_LMT_SHIFT)) & IP_PUF_PUF_MODE_ENR_LMT_MASK)
/*! @} */

/*! @name PUF_CTRL - Control register */
/*! @{ */

#define IP_PUF_PUF_CTRL_GEN_KEY_MASK             (0x1U)
#define IP_PUF_PUF_CTRL_GEN_KEY_SHIFT            (0U)
/*! gen_key - Generate Next Key
 */
#define IP_PUF_PUF_CTRL_GEN_KEY(x)               (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_CTRL_GEN_KEY_SHIFT)) & IP_PUF_PUF_CTRL_GEN_KEY_MASK)

#define IP_PUF_PUF_CTRL_NEXT_CHUNK_MASK          (0x2U)
#define IP_PUF_PUF_CTRL_NEXT_CHUNK_SHIFT         (1U)
/*! next_chunk - Next Key Chunk
 */
#define IP_PUF_PUF_CTRL_NEXT_CHUNK(x)            (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_CTRL_NEXT_CHUNK_SHIFT)) & IP_PUF_PUF_CTRL_NEXT_CHUNK_MASK)

#define IP_PUF_PUF_CTRL_CTRL_RSVD_1_MASK         (0xCU)
#define IP_PUF_PUF_CTRL_CTRL_RSVD_1_SHIFT        (2U)
/*! ctrl_rsvd_1 - Reserved
 */
#define IP_PUF_PUF_CTRL_CTRL_RSVD_1(x)           (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_CTRL_CTRL_RSVD_1_SHIFT)) & IP_PUF_PUF_CTRL_CTRL_RSVD_1_MASK)

#define IP_PUF_PUF_CTRL_KEY_ID_MASK              (0xF0U)
#define IP_PUF_PUF_CTRL_KEY_ID_SHIFT             (4U)
/*! key_id - Key ID
 */
#define IP_PUF_PUF_CTRL_KEY_ID(x)                (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_CTRL_KEY_ID_SHIFT)) & IP_PUF_PUF_CTRL_KEY_ID_MASK)

#define IP_PUF_PUF_CTRL_CTRL_RSVD_0_MASK         (0x7FFFFF00U)
#define IP_PUF_PUF_CTRL_CTRL_RSVD_0_SHIFT        (8U)
/*! ctrl_rsvd_0 - Reserved
 */
#define IP_PUF_PUF_CTRL_CTRL_RSVD_0(x)           (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_CTRL_CTRL_RSVD_0_SHIFT)) & IP_PUF_PUF_CTRL_CTRL_RSVD_0_MASK)

#define IP_PUF_PUF_CTRL_PUF_RST_MASK             (0x80000000U)
#define IP_PUF_PUF_CTRL_PUF_RST_SHIFT            (31U)
/*! puf_rst - Synchronous Reset
 */
#define IP_PUF_PUF_CTRL_PUF_RST(x)               (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_CTRL_PUF_RST_SHIFT)) & IP_PUF_PUF_CTRL_PUF_RST_MASK)
/*! @} */

/*! @name PUF_STATUS - Status register */
/*! @{ */

#define IP_PUF_PUF_STATUS_BUSY_MASK              (0x1U)
#define IP_PUF_PUF_STATUS_BUSY_SHIFT             (0U)
/*! busy - PUF is busy
 */
#define IP_PUF_PUF_STATUS_BUSY(x)                (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_STATUS_BUSY_SHIFT)) & IP_PUF_PUF_STATUS_BUSY_MASK)

#define IP_PUF_PUF_STATUS_STATUS_RSVD_1_MASK     (0xFFFFFEU)
#define IP_PUF_PUF_STATUS_STATUS_RSVD_1_SHIFT    (1U)
/*! status_rsvd_1 - Reserved
 */
#define IP_PUF_PUF_STATUS_STATUS_RSVD_1(x)       (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_STATUS_STATUS_RSVD_1_SHIFT)) & IP_PUF_PUF_STATUS_STATUS_RSVD_1_MASK)

#define IP_PUF_PUF_STATUS_ERROR_MASK             (0xF000000U)
#define IP_PUF_PUF_STATUS_ERROR_SHIFT            (24U)
/*! error - Error Code
 */
#define IP_PUF_PUF_STATUS_ERROR(x)               (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_STATUS_ERROR_SHIFT)) & IP_PUF_PUF_STATUS_ERROR_MASK)

#define IP_PUF_PUF_STATUS_STATUS_RSVD_0_MASK     (0xF0000000U)
#define IP_PUF_PUF_STATUS_STATUS_RSVD_0_SHIFT    (28U)
/*! status_rsvd_0 - Reserved
 */
#define IP_PUF_PUF_STATUS_STATUS_RSVD_0(x)       (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_STATUS_STATUS_RSVD_0_SHIFT)) & IP_PUF_PUF_STATUS_STATUS_RSVD_0_MASK)
/*! @} */

/*! @name PUF_VERSION - Version register */
/*! @{ */

#define IP_PUF_PUF_VERSION_ENTROPY_MASK          (0xFFU)
#define IP_PUF_PUF_VERSION_ENTROPY_SHIFT         (0U)
/*! entropy - Entropy Divided by Four
 */
#define IP_PUF_PUF_VERSION_ENTROPY(x)            (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_VERSION_ENTROPY_SHIFT)) & IP_PUF_PUF_VERSION_ENTROPY_MASK)

#define IP_PUF_PUF_VERSION_NUM_RO_GRP_MASK       (0xFF00U)
#define IP_PUF_PUF_VERSION_NUM_RO_GRP_SHIFT      (8U)
/*! num_ro_grp - Number of RO Groups
 */
#define IP_PUF_PUF_VERSION_NUM_RO_GRP(x)         (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_VERSION_NUM_RO_GRP_SHIFT)) & IP_PUF_PUF_VERSION_NUM_RO_GRP_MASK)

#define IP_PUF_PUF_VERSION_MIN_VER_MASK          (0xFF0000U)
#define IP_PUF_PUF_VERSION_MIN_VER_SHIFT         (16U)
/*! min_ver - Minor Version
 */
#define IP_PUF_PUF_VERSION_MIN_VER(x)            (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_VERSION_MIN_VER_SHIFT)) & IP_PUF_PUF_VERSION_MIN_VER_MASK)

#define IP_PUF_PUF_VERSION_MAJ_VER_MASK          (0xFF000000U)
#define IP_PUF_PUF_VERSION_MAJ_VER_SHIFT         (24U)
/*! maj_ver - Major Version
 */
#define IP_PUF_PUF_VERSION_MAJ_VER(x)            (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_VERSION_MAJ_VER_SHIFT)) & IP_PUF_PUF_VERSION_MAJ_VER_MASK)
/*! @} */

/*! @name PUF_CKSUM - Checksum register */
/*! @{ */

#define IP_PUF_PUF_CKSUM_CKSUM_MASK              (0xFFFFFFFFU)
#define IP_PUF_PUF_CKSUM_CKSUM_SHIFT             (0U)
/*! cksum - Checksum
 */
#define IP_PUF_PUF_CKSUM_CKSUM(x)                (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_CKSUM_CKSUM_SHIFT)) & IP_PUF_PUF_CKSUM_CKSUM_MASK)
/*! @} */

/*! @name PUF_PARITY_0 - Parity register */
/*! @{ */

#define IP_PUF_PUF_PARITY_0_PARITY_0_MASK        (0xFFFFFFFFU)
#define IP_PUF_PUF_PARITY_0_PARITY_0_SHIFT       (0U)
/*! parity_0 - Bits [31:0] of the helper parity data
 */
#define IP_PUF_PUF_PARITY_0_PARITY_0(x)          (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_PARITY_0_PARITY_0_SHIFT)) & IP_PUF_PUF_PARITY_0_PARITY_0_MASK)
/*! @} */

/*! @name PUF_PARITY_1 - Parity register */
/*! @{ */

#define IP_PUF_PUF_PARITY_1_PARITY_1_MASK        (0xFFFFFFFFU)
#define IP_PUF_PUF_PARITY_1_PARITY_1_SHIFT       (0U)
/*! parity_1 - Bits [63:32] of the helper parity data
 */
#define IP_PUF_PUF_PARITY_1_PARITY_1(x)          (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_PARITY_1_PARITY_1_SHIFT)) & IP_PUF_PUF_PARITY_1_PARITY_1_MASK)
/*! @} */

/*! @name PUF_PARITY_2 - Parity register */
/*! @{ */

#define IP_PUF_PUF_PARITY_2_PARITY_2_MASK        (0xFFFU)
#define IP_PUF_PUF_PARITY_2_PARITY_2_SHIFT       (0U)
/*! parity_2 - Bits [75:64] of the helper parity data
 */
#define IP_PUF_PUF_PARITY_2_PARITY_2(x)          (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_PARITY_2_PARITY_2_SHIFT)) & IP_PUF_PUF_PARITY_2_PARITY_2_MASK)

#define IP_PUF_PUF_PARITY_2_PAR_RSVD_MASK        (0xFFFFF000U)
#define IP_PUF_PUF_PARITY_2_PAR_RSVD_SHIFT       (12U)
/*! par_rsvd - Reserved
 */
#define IP_PUF_PUF_PARITY_2_PAR_RSVD(x)          (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_PARITY_2_PAR_RSVD_SHIFT)) & IP_PUF_PUF_PARITY_2_PAR_RSVD_MASK)
/*! @} */

/*! @name PUF_IGNORE - Ignore register */
/*! @{ */

#define IP_PUF_PUF_IGNORE_IGNORE_MASK            (0xFFFFFFFFU)
#define IP_PUF_PUF_IGNORE_IGNORE_SHIFT           (0U)
/*! ignore - Ignore data
 */
#define IP_PUF_PUF_IGNORE_IGNORE(x)              (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_IGNORE_IGNORE_SHIFT)) & IP_PUF_PUF_IGNORE_IGNORE_MASK)
/*! @} */

/*! @name PUF_RNG - Random Number register */
/*! @{ */

#define IP_PUF_PUF_RNG_RNG_MASK                  (0xFFFFFFFFU)
#define IP_PUF_PUF_RNG_RNG_SHIFT                 (0U)
/*! rng - Random bits used for masking during reconstruction
 */
#define IP_PUF_PUF_RNG_RNG(x)                    (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_RNG_RNG_SHIFT)) & IP_PUF_PUF_RNG_RNG_MASK)
/*! @} */

/*! @name PUF_KEY_0 - Key register */
/*! @{ */

#define IP_PUF_PUF_KEY_0_KEY_0_MASK              (0xFFFFFFFFU)
#define IP_PUF_PUF_KEY_0_KEY_0_SHIFT             (0U)
/*! key_0 - Bits [31:0] of generated key chunk
 */
#define IP_PUF_PUF_KEY_0_KEY_0(x)                (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_KEY_0_KEY_0_SHIFT)) & IP_PUF_PUF_KEY_0_KEY_0_MASK)
/*! @} */

/*! @name PUF_KEY_1 - Key register */
/*! @{ */

#define IP_PUF_PUF_KEY_1_KEY_1_MASK              (0xFFFFFFFFU)
#define IP_PUF_PUF_KEY_1_KEY_1_SHIFT             (0U)
/*! key_1 - Bits [63:32] of generated key chunk
 */
#define IP_PUF_PUF_KEY_1_KEY_1(x)                (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_KEY_1_KEY_1_SHIFT)) & IP_PUF_PUF_KEY_1_KEY_1_MASK)
/*! @} */

/*! @name PUF_LOCK - Lock register */
/*! @{ */

#define IP_PUF_PUF_LOCK_KEY_ID_LCK_MASK          (0xFFFFU)
#define IP_PUF_PUF_LOCK_KEY_ID_LCK_SHIFT         (0U)
/*! key_id_lck - Key Lock
 */
#define IP_PUF_PUF_LOCK_KEY_ID_LCK(x)            (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_LOCK_KEY_ID_LCK_SHIFT)) & IP_PUF_PUF_LOCK_KEY_ID_LCK_MASK)

#define IP_PUF_PUF_LOCK_LOCK_RSVD_MASK           (0xFF0000U)
#define IP_PUF_PUF_LOCK_LOCK_RSVD_SHIFT          (16U)
/*! lock_rsvd - Reserved
 */
#define IP_PUF_PUF_LOCK_LOCK_RSVD(x)             (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_LOCK_LOCK_RSVD_SHIFT)) & IP_PUF_PUF_LOCK_LOCK_RSVD_MASK)

#define IP_PUF_PUF_LOCK_REC_LCK_MASK             (0xF000000U)
#define IP_PUF_PUF_LOCK_REC_LCK_SHIFT            (24U)
/*! rec_lck - Reconstruction lock
 */
#define IP_PUF_PUF_LOCK_REC_LCK(x)               (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_LOCK_REC_LCK_SHIFT)) & IP_PUF_PUF_LOCK_REC_LCK_MASK)

#define IP_PUF_PUF_LOCK_ENR_LCK_MASK             (0xF0000000U)
#define IP_PUF_PUF_LOCK_ENR_LCK_SHIFT            (28U)
/*! enr_lck - Enrollment lock
 */
#define IP_PUF_PUF_LOCK_ENR_LCK(x)               (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_LOCK_ENR_LCK_SHIFT)) & IP_PUF_PUF_LOCK_ENR_LCK_MASK)
/*! @} */

/*! @name PUF_RO_FREQ - RO Frequency register */
/*! @{ */

#define IP_PUF_PUF_RO_FREQ_RO_FREQ_MASK          (0xFFFFFFFFU)
#define IP_PUF_PUF_RO_FREQ_RO_FREQ_SHIFT         (0U)
/*! ro_freq - System clock count it takes for the fastest RO of each group to reach the limit
 */
#define IP_PUF_PUF_RO_FREQ_RO_FREQ(x)            (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_RO_FREQ_RO_FREQ_SHIFT)) & IP_PUF_PUF_RO_FREQ_RO_FREQ_MASK)
/*! @} */

/*! @name PUF_SLW_RO - Slow RO register */
/*! @{ */

#define IP_PUF_PUF_SLW_RO_SLW_RO_MASK            (0x1FU)
#define IP_PUF_PUF_SLW_RO_SLW_RO_SHIFT           (0U)
/*! slw_ro - Number of slow ROs in the current group.
 */
#define IP_PUF_PUF_SLW_RO_SLW_RO(x)              (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_SLW_RO_SLW_RO_SHIFT)) & IP_PUF_PUF_SLW_RO_SLW_RO_MASK)

#define IP_PUF_PUF_SLW_RO_RESERVED7_MASK         (0xE0U)
#define IP_PUF_PUF_SLW_RO_RESERVED7_SHIFT        (5U)
/*! reserved7 - reserved
 */
#define IP_PUF_PUF_SLW_RO_RESERVED7(x)           (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_SLW_RO_RESERVED7_SHIFT)) & IP_PUF_PUF_SLW_RO_RESERVED7_MASK)

#define IP_PUF_PUF_SLW_RO_SLW_MAX_PER_GRP_MASK   (0x1F00U)
#define IP_PUF_PUF_SLW_RO_SLW_MAX_PER_GRP_SHIFT  (8U)
/*! slw_max_per_grp - Largest number of slow ROs detected in a single group
 */
#define IP_PUF_PUF_SLW_RO_SLW_MAX_PER_GRP(x)     (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_SLW_RO_SLW_MAX_PER_GRP_SHIFT)) & IP_PUF_PUF_SLW_RO_SLW_MAX_PER_GRP_MASK)

#define IP_PUF_PUF_SLW_RO_RESERVED15_MASK        (0xE000U)
#define IP_PUF_PUF_SLW_RO_RESERVED15_SHIFT       (13U)
/*! reserved15 - reserved
 */
#define IP_PUF_PUF_SLW_RO_RESERVED15(x)          (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_SLW_RO_RESERVED15_SHIFT)) & IP_PUF_PUF_SLW_RO_RESERVED15_MASK)

#define IP_PUF_PUF_SLW_RO_SLW_TOTAL_MASK         (0x1FF0000U)
#define IP_PUF_PUF_SLW_RO_SLW_TOTAL_SHIFT        (16U)
/*! slw_total - Running total number of slow ROs
 */
#define IP_PUF_PUF_SLW_RO_SLW_TOTAL(x)           (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_SLW_RO_SLW_TOTAL_SHIFT)) & IP_PUF_PUF_SLW_RO_SLW_TOTAL_MASK)

#define IP_PUF_PUF_SLW_RO_RESERVED31_MASK        (0xFE000000U)
#define IP_PUF_PUF_SLW_RO_RESERVED31_SHIFT       (25U)
/*! reserved31 - reserved
 */
#define IP_PUF_PUF_SLW_RO_RESERVED31(x)          (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_SLW_RO_RESERVED31_SHIFT)) & IP_PUF_PUF_SLW_RO_RESERVED31_MASK)
/*! @} */

/*! @name PUF_BCH - BCH register */
/*! @{ */

#define IP_PUF_PUF_BCH_BCH_ERR_MASK              (0xFU)
#define IP_PUF_PUF_BCH_BCH_ERR_SHIFT             (0U)
/*! bch_err - Number of errors PUF detected
 */
#define IP_PUF_PUF_BCH_BCH_ERR(x)                (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_BCH_BCH_ERR_SHIFT)) & IP_PUF_PUF_BCH_BCH_ERR_MASK)

#define IP_PUF_PUF_BCH_RSVD_7_MASK               (0xF0U)
#define IP_PUF_PUF_BCH_RSVD_7_SHIFT              (4U)
/*! rsvd_7 - Reserved
 */
#define IP_PUF_PUF_BCH_RSVD_7(x)                 (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_BCH_RSVD_7_SHIFT)) & IP_PUF_PUF_BCH_RSVD_7_MASK)

#define IP_PUF_PUF_BCH_ERR_LMT_MASK              (0xF00U)
#define IP_PUF_PUF_BCH_ERR_LMT_SHIFT             (8U)
/*! err_lmt - Number of errors PUF can detect
 */
#define IP_PUF_PUF_BCH_ERR_LMT(x)                (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_BCH_ERR_LMT_SHIFT)) & IP_PUF_PUF_BCH_ERR_LMT_MASK)

#define IP_PUF_PUF_BCH_RSVD_6_MASK               (0xFFFFF000U)
#define IP_PUF_PUF_BCH_RSVD_6_SHIFT              (12U)
/*! rsvd_6 - Reserved
 */
#define IP_PUF_PUF_BCH_RSVD_6(x)                 (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_BCH_RSVD_6_SHIFT)) & IP_PUF_PUF_BCH_RSVD_6_MASK)
/*! @} */

/*! @name PUF_INT_STATUS - Interrupt Status register */
/*! @{ */

#define IP_PUF_PUF_INT_STATUS_INT_ERROR_MASK     (0x1U)
#define IP_PUF_PUF_INT_STATUS_INT_ERROR_SHIFT    (0U)
/*! int_error - Error has occured
 */
#define IP_PUF_PUF_INT_STATUS_INT_ERROR(x)       (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_INT_ERROR_SHIFT)) & IP_PUF_PUF_INT_STATUS_INT_ERROR_MASK)

#define IP_PUF_PUF_INT_STATUS_RNG_RDY_MASK       (0x2U)
#define IP_PUF_PUF_INT_STATUS_RNG_RDY_SHIFT      (1U)
/*! rng_rdy - Reconstruction only: more random data is required
 */
#define IP_PUF_PUF_INT_STATUS_RNG_RDY(x)         (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_RNG_RDY_SHIFT)) & IP_PUF_PUF_INT_STATUS_RNG_RDY_MASK)

#define IP_PUF_PUF_INT_STATUS_RANK_DONE_MASK     (0x4U)
#define IP_PUF_PUF_INT_STATUS_RANK_DONE_SHIFT    (2U)
/*! rank_done - Enrollment only: Ranking is complete and ignore data is ready to be read
 */
#define IP_PUF_PUF_INT_STATUS_RANK_DONE(x)       (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_RANK_DONE_SHIFT)) & IP_PUF_PUF_INT_STATUS_RANK_DONE_MASK)

#define IP_PUF_PUF_INT_STATUS_PAR_RDY_MASK       (0x8U)
#define IP_PUF_PUF_INT_STATUS_PAR_RDY_SHIFT      (3U)
/*! par_rdy - Parity data has been calculated and ready to be read
 */
#define IP_PUF_PUF_INT_STATUS_PAR_RDY(x)         (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_PAR_RDY_SHIFT)) & IP_PUF_PUF_INT_STATUS_PAR_RDY_MASK)

#define IP_PUF_PUF_INT_STATUS_CKS_RDY_MASK       (0x10U)
#define IP_PUF_PUF_INT_STATUS_CKS_RDY_SHIFT      (4U)
/*! cks_rdy - Checksum has been calculated and ready to be read
 */
#define IP_PUF_PUF_INT_STATUS_CKS_RDY(x)         (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_CKS_RDY_SHIFT)) & IP_PUF_PUF_INT_STATUS_CKS_RDY_MASK)

#define IP_PUF_PUF_INT_STATUS_IGN_LOAD_MASK      (0x20U)
#define IP_PUF_PUF_INT_STATUS_IGN_LOAD_SHIFT     (5U)
/*! ign_load - Reconstruction only: ignore data is required to be loaded
 */
#define IP_PUF_PUF_INT_STATUS_IGN_LOAD(x)        (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_IGN_LOAD_SHIFT)) & IP_PUF_PUF_INT_STATUS_IGN_LOAD_MASK)

#define IP_PUF_PUF_INT_STATUS_KEY_RDY_MASK       (0x40U)
#define IP_PUF_PUF_INT_STATUS_KEY_RDY_SHIFT      (6U)
/*! key_rdy - Key chunk has been generated and ready to be read
 */
#define IP_PUF_PUF_INT_STATUS_KEY_RDY(x)         (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_KEY_RDY_SHIFT)) & IP_PUF_PUF_INT_STATUS_KEY_RDY_MASK)

#define IP_PUF_PUF_INT_STATUS_INT_RSVD_MASK      (0xFFFFFF80U)
#define IP_PUF_PUF_INT_STATUS_INT_RSVD_SHIFT     (7U)
/*! int_rsvd - Reserved
 */
#define IP_PUF_PUF_INT_STATUS_INT_RSVD(x)        (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_INT_RSVD_SHIFT)) & IP_PUF_PUF_INT_STATUS_INT_RSVD_MASK)
/*! @} */

/*! @name PUF_INT_ENABLE - Interrupt Enable register */
/*! @{ */

#define IP_PUF_PUF_INT_ENABLE_INT_EN_ERROR_MASK  (0x1U)
#define IP_PUF_PUF_INT_ENABLE_INT_EN_ERROR_SHIFT (0U)
/*! int_en_error - Interrupt enable for error interrupt
 */
#define IP_PUF_PUF_INT_ENABLE_INT_EN_ERROR(x)    (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_ENABLE_INT_EN_ERROR_SHIFT)) & IP_PUF_PUF_INT_ENABLE_INT_EN_ERROR_MASK)

#define IP_PUF_PUF_INT_ENABLE_INT_EN_RNG_RDY_MASK (0x2U)
#define IP_PUF_PUF_INT_ENABLE_INT_EN_RNG_RDY_SHIFT (1U)
/*! int_en_rng_rdy - Interrupt enable for RNG_RDY
 */
#define IP_PUF_PUF_INT_ENABLE_INT_EN_RNG_RDY(x)  (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_ENABLE_INT_EN_RNG_RDY_SHIFT)) & IP_PUF_PUF_INT_ENABLE_INT_EN_RNG_RDY_MASK)

#define IP_PUF_PUF_INT_ENABLE_INT_EN_RANK_DONE_MASK (0x4U)
#define IP_PUF_PUF_INT_ENABLE_INT_EN_RANK_DONE_SHIFT (2U)
/*! int_en_rank_done - Interrupt enable for RANK_DONE
 */
#define IP_PUF_PUF_INT_ENABLE_INT_EN_RANK_DONE(x) (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_ENABLE_INT_EN_RANK_DONE_SHIFT)) & IP_PUF_PUF_INT_ENABLE_INT_EN_RANK_DONE_MASK)

#define IP_PUF_PUF_INT_ENABLE_INT_EN_PAR_RDY_MASK (0x8U)
#define IP_PUF_PUF_INT_ENABLE_INT_EN_PAR_RDY_SHIFT (3U)
/*! int_en_par_rdy - Interrupt enable for PAR_RDY
 */
#define IP_PUF_PUF_INT_ENABLE_INT_EN_PAR_RDY(x)  (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_ENABLE_INT_EN_PAR_RDY_SHIFT)) & IP_PUF_PUF_INT_ENABLE_INT_EN_PAR_RDY_MASK)

#define IP_PUF_PUF_INT_ENABLE_INT_EN_CKS_RDY_MASK (0x10U)
#define IP_PUF_PUF_INT_ENABLE_INT_EN_CKS_RDY_SHIFT (4U)
/*! int_en_cks_rdy - Interrupt enable for CKS_RDY
 */
#define IP_PUF_PUF_INT_ENABLE_INT_EN_CKS_RDY(x)  (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_ENABLE_INT_EN_CKS_RDY_SHIFT)) & IP_PUF_PUF_INT_ENABLE_INT_EN_CKS_RDY_MASK)

#define IP_PUF_PUF_INT_ENABLE_INT_EN_IGN_LOAD_MASK (0x20U)
#define IP_PUF_PUF_INT_ENABLE_INT_EN_IGN_LOAD_SHIFT (5U)
/*! int_en_ign_load - Interrupt enable for IGN_LOAD
 */
#define IP_PUF_PUF_INT_ENABLE_INT_EN_IGN_LOAD(x) (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_ENABLE_INT_EN_IGN_LOAD_SHIFT)) & IP_PUF_PUF_INT_ENABLE_INT_EN_IGN_LOAD_MASK)

#define IP_PUF_PUF_INT_ENABLE_INT_EN_KEY_RDY_MASK (0x40U)
#define IP_PUF_PUF_INT_ENABLE_INT_EN_KEY_RDY_SHIFT (6U)
/*! int_en_key_rdy - Interrupt enable for KEY_RDY
 */
#define IP_PUF_PUF_INT_ENABLE_INT_EN_KEY_RDY(x)  (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_ENABLE_INT_EN_KEY_RDY_SHIFT)) & IP_PUF_PUF_INT_ENABLE_INT_EN_KEY_RDY_MASK)

#define IP_PUF_PUF_INT_ENABLE_INT_EN_RSVD_MASK   (0xFFFFFF80U)
#define IP_PUF_PUF_INT_ENABLE_INT_EN_RSVD_SHIFT  (7U)
/*! int_en_rsvd - Reserved
 */
#define IP_PUF_PUF_INT_ENABLE_INT_EN_RSVD(x)     (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_ENABLE_INT_EN_RSVD_SHIFT)) & IP_PUF_PUF_INT_ENABLE_INT_EN_RSVD_MASK)
/*! @} */

/*! @name PUF_INT_STATUS_CLR - Interrupt Status Clear register */
/*! @{ */

#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_ERROR_MASK (0x1U)
#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_ERROR_SHIFT (0U)
/*! int_clr_error - Interrupt clear for error interrupt
 */
#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_ERROR(x) (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_ERROR_SHIFT)) & IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_ERROR_MASK)

#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_RNG_RDY_MASK (0x2U)
#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_RNG_RDY_SHIFT (1U)
/*! int_clr_rng_rdy - Interrupt clear for RNG_RDY
 */
#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_RNG_RDY(x) (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_RNG_RDY_SHIFT)) & IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_RNG_RDY_MASK)

#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_RANK_DONE_MASK (0x4U)
#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_RANK_DONE_SHIFT (2U)
/*! int_clr_rank_done - Interrupt clear for RANK_DONE
 */
#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_RANK_DONE(x) (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_RANK_DONE_SHIFT)) & IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_RANK_DONE_MASK)

#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_PAR_RDY_MASK (0x8U)
#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_PAR_RDY_SHIFT (3U)
/*! int_clr_par_rdy - Interrupt clear for PAR_RDY
 */
#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_PAR_RDY(x) (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_PAR_RDY_SHIFT)) & IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_PAR_RDY_MASK)

#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_CKS_RDY_MASK (0x10U)
#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_CKS_RDY_SHIFT (4U)
/*! int_clr_cks_rdy - Interrupt clear for CKS_RDY
 */
#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_CKS_RDY(x) (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_CKS_RDY_SHIFT)) & IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_CKS_RDY_MASK)

#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_IGN_LOAD_MASK (0x20U)
#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_IGN_LOAD_SHIFT (5U)
/*! int_clr_ign_load - Interrupt clear for IGN_LOAD
 */
#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_IGN_LOAD(x) (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_IGN_LOAD_SHIFT)) & IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_IGN_LOAD_MASK)

#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_KEY_RDY_MASK (0x40U)
#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_KEY_RDY_SHIFT (6U)
/*! int_clr_key_rdy - Interrupt clear for KEY_RDY
 */
#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_KEY_RDY(x) (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_KEY_RDY_SHIFT)) & IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_KEY_RDY_MASK)

#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_RSVD_MASK (0xFFFFFF80U)
#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_RSVD_SHIFT (7U)
/*! int_clr_rsvd - Reserved
 */
#define IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_RSVD(x) (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_RSVD_SHIFT)) & IP_PUF_PUF_INT_STATUS_CLR_INT_CLR_RSVD_MASK)
/*! @} */

/*! @name PUF_INT_STATUS_SET - Interrupt Status Set register */
/*! @{ */

#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_ERROR_MASK (0x1U)
#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_ERROR_SHIFT (0U)
/*! int_set_error - Interrupt set for error interrupt
 */
#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_ERROR(x) (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_SET_INT_SET_ERROR_SHIFT)) & IP_PUF_PUF_INT_STATUS_SET_INT_SET_ERROR_MASK)

#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_RNG_RDY_MASK (0x2U)
#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_RNG_RDY_SHIFT (1U)
/*! int_set_rng_rdy - Interrupt set for RNG_RDY
 */
#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_RNG_RDY(x) (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_SET_INT_SET_RNG_RDY_SHIFT)) & IP_PUF_PUF_INT_STATUS_SET_INT_SET_RNG_RDY_MASK)

#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_RANK_DONE_MASK (0x4U)
#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_RANK_DONE_SHIFT (2U)
/*! int_set_rank_done - Interrupt set for RANK_DONE
 */
#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_RANK_DONE(x) (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_SET_INT_SET_RANK_DONE_SHIFT)) & IP_PUF_PUF_INT_STATUS_SET_INT_SET_RANK_DONE_MASK)

#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_PAR_RDY_MASK (0x8U)
#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_PAR_RDY_SHIFT (3U)
/*! int_set_par_rdy - Interrupt set for PAR_RDY
 */
#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_PAR_RDY(x) (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_SET_INT_SET_PAR_RDY_SHIFT)) & IP_PUF_PUF_INT_STATUS_SET_INT_SET_PAR_RDY_MASK)

#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_CKS_RDY_MASK (0x10U)
#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_CKS_RDY_SHIFT (4U)
/*! int_set_cks_rdy - Interrupt set for CKS_RDY
 */
#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_CKS_RDY(x) (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_SET_INT_SET_CKS_RDY_SHIFT)) & IP_PUF_PUF_INT_STATUS_SET_INT_SET_CKS_RDY_MASK)

#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_IGN_LOAD_MASK (0x20U)
#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_IGN_LOAD_SHIFT (5U)
/*! int_set_ign_load - Interrupt set for IGN_LOAD
 */
#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_IGN_LOAD(x) (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_SET_INT_SET_IGN_LOAD_SHIFT)) & IP_PUF_PUF_INT_STATUS_SET_INT_SET_IGN_LOAD_MASK)

#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_KEY_RDY_MASK (0x40U)
#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_KEY_RDY_SHIFT (6U)
/*! int_set_key_rdy - Interrupt set for KEY_RDY
 */
#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_KEY_RDY(x) (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_SET_INT_SET_KEY_RDY_SHIFT)) & IP_PUF_PUF_INT_STATUS_SET_INT_SET_KEY_RDY_MASK)

#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_RSVD_MASK (0xFFFFFF80U)
#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_RSVD_SHIFT (7U)
/*! int_set_rsvd - Reserved
 */
#define IP_PUF_PUF_INT_STATUS_SET_INT_SET_RSVD(x) (((uint32_t)(((uint32_t)(x)) << IP_PUF_PUF_INT_STATUS_SET_INT_SET_RSVD_SHIFT)) & IP_PUF_PUF_INT_STATUS_SET_INT_SET_RSVD_MASK)
/*! @} */


/*!
 * @}
 */ /* end of group IP_PUF_Register_Masks */


/* IP_PUF - Peripheral instance base addresses */
/** Peripheral IP_PUF base address */
#define IP_PUF_BASE                              (0u)
/** Peripheral IP_PUF base pointer */
#define IP_PUF                                   ((IP_PUF_Type *)IP_PUF_BASE)
/** Array initializer of IP_PUF peripheral base addresses */
#define IP_PUF_BASE_ADDRS                        { IP_PUF_BASE }
/** Array initializer of IP_PUF peripheral base pointers */
#define IP_PUF_BASE_PTRS                         { IP_PUF }

/*!
 * @}
 */ /* end of group IP_PUF_Peripheral_Access_Layer */


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


#endif  /* _IP_PUF_H_ */

