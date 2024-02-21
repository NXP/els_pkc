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
**     Build:               b220919
**
**     Abstract:
**         CMSIS Peripheral Access Layer for id_safo_sgi
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
 * @file id_safo_sgi.h
 * @version 0.0
 * @date 0-00-00
 * @brief CMSIS Peripheral Access Layer for id_safo_sgi
 *
 * CMSIS Peripheral Access Layer for id_safo_sgi
 */

#ifndef _ID_SAFO_SGI_H_
#define _ID_SAFO_SGI_H_                          /**< Symbol preventing repeated inclusion */

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
   -- ID_SAFO_SGI Peripheral Access Layer
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup ID_SAFO_SGI_Peripheral_Access_Layer ID_SAFO_SGI Peripheral Access Layer
 * @{
 */

/** ID_SAFO_SGI - Register Layout Typedef */
typedef struct {
       uint8_t RESERVED_0[512];
  __IO uint32_t SAFO_SGI_DATIN0A;                  /**< Input Data register 0 lower-bank low, offset: 0x200 */
  __IO uint32_t SAFO_SGI_DATIN0B;                  /**< Input Data register 0 lower-bank high, offset: 0x204 */
  __IO uint32_t SAFO_SGI_DATIN0C;                  /**< Input Data register 0 upper-bank low, offset: 0x208 */
  __IO uint32_t SAFO_SGI_DATIN0D;                  /**< Input Data register 0 upper-bank high, offset: 0x20C */
  __IO uint32_t SAFO_SGI_DATIN1A;                  /**< Input Data register 1 lower-bank low, offset: 0x210 */
  __IO uint32_t SAFO_SGI_DATIN1B;                  /**< Input Data register 1 lower-bank high, offset: 0x214 */
  __IO uint32_t SAFO_SGI_DATIN1C;                  /**< Input Data register 1 upper-bank low, offset: 0x218 */
  __IO uint32_t SAFO_SGI_DATIN1D;                  /**< Input Data register 1 upper-bank high, offset: 0x21C */
       uint8_t RESERVED_1[32];
  __IO uint32_t SAFO_SGI_KEY0A;                    /**< Input Key register 0 lower-bank low, offset: 0x240 */
  __IO uint32_t SAFO_SGI_KEY0B;                    /**< Input Key register 0 lower-bank high, offset: 0x244 */
  __IO uint32_t SAFO_SGI_KEY0C;                    /**< Input Key register 0 upper-bank low, offset: 0x248 */
  __IO uint32_t SAFO_SGI_KEY0D;                    /**< Input Key register 0 upper-bank high, offset: 0x24C */
  __IO uint32_t SAFO_SGI_KEY1A;                    /**< Input Key register 1 lower-bank low, offset: 0x250 */
  __IO uint32_t SAFO_SGI_KEY1B;                    /**< Input Key register 1 lower-bank high, offset: 0x254 */
  __IO uint32_t SAFO_SGI_KEY1C;                    /**< Input Key register 1 upper-bank low, offset: 0x258 */
  __IO uint32_t SAFO_SGI_KEY1D;                    /**< Input Key register 1 upper-bank high, offset: 0x25C */
       uint8_t RESERVED_2[96];
  __I  uint32_t SAFO_SGI_DATOUTA;                  /**< Output Data register lower-bank low, offset: 0x2C0 */
  __I  uint32_t SAFO_SGI_DATOUTB;                  /**< Ouput Data register lower-bank high, offset: 0x2C4 */
  __I  uint32_t SAFO_SGI_DATOUTC;                  /**< Ouput Data register upper-bank low, offset: 0x2C8 */
  __I  uint32_t SAFO_SGI_DATOUTD;                  /**< Output Data register upper-bank high, offset: 0x2CC */
       uint8_t RESERVED_3[2352];
  __I  uint32_t SAFO_SGI_STATUS;                   /**< Status Register, offset: 0xC00 */
  __IO uint32_t SAFO_SGI_COUNT;                    /**< Calculation Counter, offset: 0xC04 */
       uint8_t RESERVED_4[248];
  __IO uint32_t SAFO_SGI_CTRL;                     /**< SGI Control Register, offset: 0xD00 */
  __IO uint32_t SAFO_SGI_CTRL2;                    /**< SGI Control Register 2, offset: 0xD04 */
       uint8_t RESERVED_5[12];
  __IO uint32_t SAFO_SGI_SM3_CTRL;                 /**< SM3 Control Register, offset: 0xD14 */
  __O  uint32_t SAFO_SGI_SM3_FIFO;                 /**< SM3 FIFO Register, offset: 0xD18 */
  __I  uint32_t SAFO_SGI_CONFIG;                   /**< SGI Configuration Register, offset: 0xD1C */
       uint8_t RESERVED_6[708];
  __IO uint32_t SAFO_SGI_INT_ENABLE;               /**< Interrupt Enable, offset: 0xFE4 */
  __O  uint32_t SAFO_SGI_INT_STATUS_CLR;           /**< Interrupt Status Clear, offset: 0xFE8 */
  __O  uint32_t SAFO_SGI_INT_STATUS_SET;           /**< Interrupt Status Set, offset: 0xFEC */
} ID_SAFO_SGI_Type;

/* ----------------------------------------------------------------------------
   -- ID_SAFO_SGI Register Masks
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup ID_SAFO_SGI_Register_Masks ID_SAFO_SGI Register Masks
 * @{
 */

/*! @name SAFO_SGI_DATIN0A - Input Data register 0 lower-bank low */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_DATIN0A_DATIN0A_MASK (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_DATIN0A_DATIN0A_SHIFT (0U)
/*! DATIN0A - Input Data register
 */
#define ID_SAFO_SGI_SAFO_SGI_DATIN0A_DATIN0A(x)  (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_DATIN0A_DATIN0A_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_DATIN0A_DATIN0A_MASK)
/*! @} */

/*! @name SAFO_SGI_DATIN0B - Input Data register 0 lower-bank high */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_DATIN0B_DATIN0B_MASK (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_DATIN0B_DATIN0B_SHIFT (0U)
/*! DATIN0B - Input Data register
 */
#define ID_SAFO_SGI_SAFO_SGI_DATIN0B_DATIN0B(x)  (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_DATIN0B_DATIN0B_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_DATIN0B_DATIN0B_MASK)
/*! @} */

/*! @name SAFO_SGI_DATIN0C - Input Data register 0 upper-bank low */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_DATIN0C_DATIN0C_MASK (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_DATIN0C_DATIN0C_SHIFT (0U)
/*! DATIN0C - Input Data register
 */
#define ID_SAFO_SGI_SAFO_SGI_DATIN0C_DATIN0C(x)  (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_DATIN0C_DATIN0C_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_DATIN0C_DATIN0C_MASK)
/*! @} */

/*! @name SAFO_SGI_DATIN0D - Input Data register 0 upper-bank high */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_DATIN0D_DATIN0D_MASK (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_DATIN0D_DATIN0D_SHIFT (0U)
/*! DATIN0D - Input Data register
 */
#define ID_SAFO_SGI_SAFO_SGI_DATIN0D_DATIN0D(x)  (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_DATIN0D_DATIN0D_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_DATIN0D_DATIN0D_MASK)
/*! @} */

/*! @name SAFO_SGI_DATIN1A - Input Data register 1 lower-bank low */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_DATIN1A_DATIN1A_MASK (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_DATIN1A_DATIN1A_SHIFT (0U)
/*! DATIN1A - Input Data register
 */
#define ID_SAFO_SGI_SAFO_SGI_DATIN1A_DATIN1A(x)  (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_DATIN1A_DATIN1A_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_DATIN1A_DATIN1A_MASK)
/*! @} */

/*! @name SAFO_SGI_DATIN1B - Input Data register 1 lower-bank high */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_DATIN1B_DATIN1B_MASK (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_DATIN1B_DATIN1B_SHIFT (0U)
/*! DATIN1B - Input Data register
 */
#define ID_SAFO_SGI_SAFO_SGI_DATIN1B_DATIN1B(x)  (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_DATIN1B_DATIN1B_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_DATIN1B_DATIN1B_MASK)
/*! @} */

/*! @name SAFO_SGI_DATIN1C - Input Data register 1 upper-bank low */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_DATIN1C_DATIN1C_MASK (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_DATIN1C_DATIN1C_SHIFT (0U)
/*! DATIN1C - Input Data register
 */
#define ID_SAFO_SGI_SAFO_SGI_DATIN1C_DATIN1C(x)  (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_DATIN1C_DATIN1C_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_DATIN1C_DATIN1C_MASK)
/*! @} */

/*! @name SAFO_SGI_DATIN1D - Input Data register 1 upper-bank high */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_DATIN1D_DATIN1D_MASK (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_DATIN1D_DATIN1D_SHIFT (0U)
/*! DATIN1D - Input Data register
 */
#define ID_SAFO_SGI_SAFO_SGI_DATIN1D_DATIN1D(x)  (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_DATIN1D_DATIN1D_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_DATIN1D_DATIN1D_MASK)
/*! @} */

/*! @name SAFO_SGI_KEY0A - Input Key register 0 lower-bank low */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_KEY0A_KEY0A_MASK    (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_KEY0A_KEY0A_SHIFT   (0U)
/*! KEY0A - Input Key register
 */
#define ID_SAFO_SGI_SAFO_SGI_KEY0A_KEY0A(x)      (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_KEY0A_KEY0A_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_KEY0A_KEY0A_MASK)
/*! @} */

/*! @name SAFO_SGI_KEY0B - Input Key register 0 lower-bank high */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_KEY0B_KEY0B_MASK    (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_KEY0B_KEY0B_SHIFT   (0U)
/*! KEY0B - Input Key register
 */
#define ID_SAFO_SGI_SAFO_SGI_KEY0B_KEY0B(x)      (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_KEY0B_KEY0B_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_KEY0B_KEY0B_MASK)
/*! @} */

/*! @name SAFO_SGI_KEY0C - Input Key register 0 upper-bank low */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_KEY0C_KEY0C_MASK    (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_KEY0C_KEY0C_SHIFT   (0U)
/*! KEY0C - Input Key register
 */
#define ID_SAFO_SGI_SAFO_SGI_KEY0C_KEY0C(x)      (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_KEY0C_KEY0C_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_KEY0C_KEY0C_MASK)
/*! @} */

/*! @name SAFO_SGI_KEY0D - Input Key register 0 upper-bank high */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_KEY0D_KEY0D_MASK    (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_KEY0D_KEY0D_SHIFT   (0U)
/*! KEY0D - Input Key register
 */
#define ID_SAFO_SGI_SAFO_SGI_KEY0D_KEY0D(x)      (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_KEY0D_KEY0D_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_KEY0D_KEY0D_MASK)
/*! @} */

/*! @name SAFO_SGI_KEY1A - Input Key register 1 lower-bank low */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_KEY1A_KEY1A_MASK    (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_KEY1A_KEY1A_SHIFT   (0U)
/*! KEY1A - Input Key register
 */
#define ID_SAFO_SGI_SAFO_SGI_KEY1A_KEY1A(x)      (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_KEY1A_KEY1A_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_KEY1A_KEY1A_MASK)
/*! @} */

/*! @name SAFO_SGI_KEY1B - Input Key register 1 lower-bank high */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_KEY1B_KEY1B_MASK    (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_KEY1B_KEY1B_SHIFT   (0U)
/*! KEY1B - Input Key register
 */
#define ID_SAFO_SGI_SAFO_SGI_KEY1B_KEY1B(x)      (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_KEY1B_KEY1B_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_KEY1B_KEY1B_MASK)
/*! @} */

/*! @name SAFO_SGI_KEY1C - Input Key register 1 upper-bank low */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_KEY1C_KEY1C_MASK    (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_KEY1C_KEY1C_SHIFT   (0U)
/*! KEY1C - Input Key register
 */
#define ID_SAFO_SGI_SAFO_SGI_KEY1C_KEY1C(x)      (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_KEY1C_KEY1C_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_KEY1C_KEY1C_MASK)
/*! @} */

/*! @name SAFO_SGI_KEY1D - Input Key register 1 upper-bank high */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_KEY1D_KEY1D_MASK    (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_KEY1D_KEY1D_SHIFT   (0U)
/*! KEY1D - Input Key register
 */
#define ID_SAFO_SGI_SAFO_SGI_KEY1D_KEY1D(x)      (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_KEY1D_KEY1D_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_KEY1D_KEY1D_MASK)
/*! @} */

/*! @name SAFO_SGI_DATOUTA - Output Data register lower-bank low */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_DATOUTA_DATOUTA_MASK (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_DATOUTA_DATOUTA_SHIFT (0U)
/*! DATOUTA - Output Data register
 */
#define ID_SAFO_SGI_SAFO_SGI_DATOUTA_DATOUTA(x)  (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_DATOUTA_DATOUTA_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_DATOUTA_DATOUTA_MASK)
/*! @} */

/*! @name SAFO_SGI_DATOUTB - Ouput Data register lower-bank high */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_DATOUTB_DATOUTB_MASK (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_DATOUTB_DATOUTB_SHIFT (0U)
/*! DATOUTB - Ouput Data register
 */
#define ID_SAFO_SGI_SAFO_SGI_DATOUTB_DATOUTB(x)  (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_DATOUTB_DATOUTB_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_DATOUTB_DATOUTB_MASK)
/*! @} */

/*! @name SAFO_SGI_DATOUTC - Ouput Data register upper-bank low */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_DATOUTC_DATOUTC_MASK (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_DATOUTC_DATOUTC_SHIFT (0U)
/*! DATOUTC - Ouput Data register
 */
#define ID_SAFO_SGI_SAFO_SGI_DATOUTC_DATOUTC(x)  (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_DATOUTC_DATOUTC_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_DATOUTC_DATOUTC_MASK)
/*! @} */

/*! @name SAFO_SGI_DATOUTD - Output Data register upper-bank high */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_DATOUTD_DOUTD_MASK  (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_DATOUTD_DOUTD_SHIFT (0U)
/*! DOUTD - Output Data register
 */
#define ID_SAFO_SGI_SAFO_SGI_DATOUTD_DOUTD(x)    (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_DATOUTD_DOUTD_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_DATOUTD_DOUTD_MASK)
/*! @} */

/*! @name SAFO_SGI_STATUS - Status Register */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_STATUS_BUSY_MASK    (0x1U)
#define ID_SAFO_SGI_SAFO_SGI_STATUS_BUSY_SHIFT   (0U)
/*! BUSY - Busy Flag
 */
#define ID_SAFO_SGI_SAFO_SGI_STATUS_BUSY(x)      (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_STATUS_BUSY_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_STATUS_BUSY_MASK)

#define ID_SAFO_SGI_SAFO_SGI_STATUS_OFLOW_MASK   (0x2U)
#define ID_SAFO_SGI_SAFO_SGI_STATUS_OFLOW_SHIFT  (1U)
/*! OFLOW - Overflow Flag
 */
#define ID_SAFO_SGI_SAFO_SGI_STATUS_OFLOW(x)     (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_STATUS_OFLOW_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_STATUS_OFLOW_MASK)

#define ID_SAFO_SGI_SAFO_SGI_STATUS_PRNG_RDY_MASK (0x4U)
#define ID_SAFO_SGI_SAFO_SGI_STATUS_PRNG_RDY_SHIFT (2U)
/*! PRNG_RDY - PRNG Ready
 */
#define ID_SAFO_SGI_SAFO_SGI_STATUS_PRNG_RDY(x)  (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_STATUS_PRNG_RDY_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_STATUS_PRNG_RDY_MASK)

#define ID_SAFO_SGI_SAFO_SGI_STATUS_ERROR_MASK   (0x38U)
#define ID_SAFO_SGI_SAFO_SGI_STATUS_ERROR_SHIFT  (3U)
/*! ERROR - Error Indicator
 */
#define ID_SAFO_SGI_SAFO_SGI_STATUS_ERROR(x)     (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_STATUS_ERROR_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_STATUS_ERROR_MASK)

#define ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_BUSY_MASK (0x40U)
#define ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_BUSY_SHIFT (6U)
/*! SM3_BUSY - SM3 Busy Status Flag
 */
#define ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_BUSY(x)  (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_BUSY_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_BUSY_MASK)

#define ID_SAFO_SGI_SAFO_SGI_STATUS_IRQ_MASK     (0x80U)
#define ID_SAFO_SGI_SAFO_SGI_STATUS_IRQ_SHIFT    (7U)
/*! IRQ - Interrupt Status Flag
 */
#define ID_SAFO_SGI_SAFO_SGI_STATUS_IRQ(x)       (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_STATUS_IRQ_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_STATUS_IRQ_MASK)

#define ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_FIFO_FULL_MASK (0x100U)
#define ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_FIFO_FULL_SHIFT (8U)
/*! SM3_FIFO_FULL - SM3 FIFO Full Indicator
 */
#define ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_FIFO_FULL(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_FIFO_FULL_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_FIFO_FULL_MASK)

#define ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_FIFO_LEVEL_MASK (0x7E00U)
#define ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_FIFO_LEVEL_SHIFT (9U)
/*! SM3_FIFO_LEVEL - SM3 FIFO Level
 */
#define ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_FIFO_LEVEL(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_FIFO_LEVEL_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_FIFO_LEVEL_MASK)

#define ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_ERROR_MASK (0x8000U)
#define ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_ERROR_SHIFT (15U)
/*! SM3_ERROR - SM3 ERROR
 */
#define ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_ERROR(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_ERROR_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_STATUS_SM3_ERROR_MASK)
/*! @} */

/*! @name SAFO_SGI_COUNT - Calculation Counter */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_COUNT_COUNT_MASK    (0xFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_COUNT_COUNT_SHIFT   (0U)
/*! COUNT - Calculation Counter
 */
#define ID_SAFO_SGI_SAFO_SGI_COUNT_COUNT(x)      (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_COUNT_COUNT_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_COUNT_COUNT_MASK)
/*! @} */

/*! @name SAFO_SGI_CTRL - SGI Control Register */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_CTRL_START_MASK     (0x1U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL_START_SHIFT    (0U)
/*! START - Start Crypto Operation
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL_START(x)       (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL_START_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL_START_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CTRL_DECRYPT_MASK   (0x2U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL_DECRYPT_SHIFT  (1U)
/*! DECRYPT - Sets Cipher direction(SM4)
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL_DECRYPT(x)     (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL_DECRYPT_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL_DECRYPT_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CTRL_CRYPTO_OP_MASK (0x70U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL_CRYPTO_OP_SHIFT (4U)
/*! CRYPTO_OP - Crypto Operation Type
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL_CRYPTO_OP(x)   (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL_CRYPTO_OP_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL_CRYPTO_OP_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CTRL_INSEL_MASK     (0x780U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL_INSEL_SHIFT    (7U)
/*! INSEL - Kernel Input Configuration
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL_INSEL(x)       (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL_INSEL_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL_INSEL_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CTRL_OUTSEL_MASK    (0x3800U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL_OUTSEL_SHIFT   (11U)
/*! OUTSEL - Kernel Input Configuration
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL_OUTSEL(x)      (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL_OUTSEL_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL_OUTSEL_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CTRL_DATOUT_RES_MASK (0xC000U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL_DATOUT_RES_SHIFT (14U)
/*! DATOUT_RES - Kernels Data Out Options
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL_DATOUT_RES(x)  (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL_DATOUT_RES_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL_DATOUT_RES_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CTRL_INKEYSEL_MASK  (0x1F00000U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL_INKEYSEL_SHIFT (20U)
/*! INKEYSEL - Input key selection
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL_INKEYSEL(x)    (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL_INKEYSEL_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL_INKEYSEL_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CTRL_SM4_EN_MASK    (0x8000000U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL_SM4_EN_SHIFT   (27U)
/*! SM4_EN - SM4 Kernel Enable
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL_SM4_EN(x)      (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL_SM4_EN_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL_SM4_EN_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CTRL_SM4_NO_KL_MASK (0x10000000U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL_SM4_NO_KL_SHIFT (28U)
/*! SM4_NO_KL - SM4 No Decryption Key Schedule
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL_SM4_NO_KL(x)   (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL_SM4_NO_KL_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL_SM4_NO_KL_MASK)
/*! @} */

/*! @name SAFO_SGI_CTRL2 - SGI Control Register 2 */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_CTRL2_FLUSH_MASK    (0x1U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_FLUSH_SHIFT   (0U)
/*! FLUSH - Start Full SGI Flush
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_FLUSH(x)      (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL2_FLUSH_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL2_FLUSH_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CTRL2_KEY_FLUSH_MASK (0x2U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_KEY_FLUSH_SHIFT (1U)
/*! KEY_FLUSH - Start KEY register-bank Flush
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_KEY_FLUSH(x)  (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL2_KEY_FLUSH_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL2_KEY_FLUSH_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CTRL2_DATIN_FLUSH_MASK (0x4U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_DATIN_FLUSH_SHIFT (2U)
/*! DATIN_FLUSH - Start DATIN register-bank Flush
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_DATIN_FLUSH(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL2_DATIN_FLUSH_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL2_DATIN_FLUSH_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CTRL2_INCR_MASK     (0x8U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_INCR_SHIFT    (3U)
/*! INCR - Increment(Triggered by SFR write)
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_INCR(x)       (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL2_INCR_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL2_INCR_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CTRL2_XORWR_MASK    (0x10U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_XORWR_SHIFT   (4U)
/*! XORWR - Write-XOR control
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_XORWR(x)      (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL2_XORWR_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL2_XORWR_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CTRL2_FLUSHWR_MASK  (0x20U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_FLUSHWR_SHIFT (5U)
/*! FLUSHWR - Flush Write control
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_FLUSHWR(x)    (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL2_FLUSHWR_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL2_FLUSHWR_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CTRL2_INCR_CIN_MASK (0x40U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_INCR_CIN_SHIFT (6U)
/*! INCR_CIN - Increment Carry-In control
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_INCR_CIN(x)   (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL2_INCR_CIN_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL2_INCR_CIN_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CTRL2_KEYRES_MASK   (0x1F0000U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_KEYRES_SHIFT  (16U)
/*! KEYRES - Selects key registers to be updated when rkey=1
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_KEYRES(x)     (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL2_KEYRES_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL2_KEYRES_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CTRL2_RKEY_MASK     (0x200000U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_RKEY_SHIFT    (21U)
/*! RKEY - Crypto result location
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_RKEY(x)       (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL2_RKEY_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL2_RKEY_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CTRL2_BYTES_ORDER_MASK (0x400000U)
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_BYTES_ORDER_SHIFT (22U)
/*! BYTES_ORDER - Byte order of regbank read/write data
 */
#define ID_SAFO_SGI_SAFO_SGI_CTRL2_BYTES_ORDER(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CTRL2_BYTES_ORDER_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CTRL2_BYTES_ORDER_MASK)
/*! @} */

/*! @name SAFO_SGI_SM3_CTRL - SM3 Control Register */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_MODE_MASK (0x2U)
#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_MODE_SHIFT (1U)
/*! SM3_MODE - SM3 mode normal or automatic
 */
#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_MODE(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_MODE_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_MODE_MASK)

#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_LOW_LIM_MASK (0xF0U)
#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_LOW_LIM_SHIFT (4U)
/*! SM3_LOW_LIM - SM3 FIFO low limit
 */
#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_LOW_LIM(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_LOW_LIM_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_LOW_LIM_MASK)

#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_HIGH_LIM_MASK (0xF00U)
#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_HIGH_LIM_SHIFT (8U)
/*! SM3_HIGH_LIM - SM3 FIFO high limit
 */
#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_HIGH_LIM(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_HIGH_LIM_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_HIGH_LIM_MASK)

#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_COUNT_EN_MASK (0x1000U)
#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_COUNT_EN_SHIFT (12U)
/*! SM3_COUNT_EN - SM3 Calculation Counter Enable
 */
#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_COUNT_EN(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_COUNT_EN_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_COUNT_EN_MASK)

#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_HASH_RELOAD_MASK (0x2000U)
#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_HASH_RELOAD_SHIFT (13U)
/*! HASH_RELOAD - SM3 HASH reload
 */
#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_HASH_RELOAD(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_HASH_RELOAD_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_HASH_RELOAD_MASK)

#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_STOP_MASK (0x4000U)
#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_STOP_SHIFT (14U)
/*! SM3_STOP - STOP SM3 AUTO mode
 */
#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_STOP(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_STOP_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_STOP_MASK)

#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_NO_AUTO_INIT_MASK (0x8000U)
#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_NO_AUTO_INIT_SHIFT (15U)
/*! NO_AUTO_INIT - SM3 no automatic HASH initialisation.
 */
#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_NO_AUTO_INIT(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_NO_AUTO_INIT_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_NO_AUTO_INIT_MASK)

#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_EN_MASK (0x10000U)
#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_EN_SHIFT (16U)
/*! SM3_EN - SM3 enable
 */
#define ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_EN(x)  (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_EN_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_SM3_CTRL_SM3_EN_MASK)
/*! @} */

/*! @name SAFO_SGI_SM3_FIFO - SM3 FIFO Register */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_SM3_FIFO_FIFO_MASK  (0xFFFFFFFFU)
#define ID_SAFO_SGI_SAFO_SGI_SM3_FIFO_FIFO_SHIFT (0U)
/*! FIFO - SM3 FIFO Register
 */
#define ID_SAFO_SGI_SAFO_SGI_SM3_FIFO_FIFO(x)    (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_SM3_FIFO_FIFO_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_SM3_FIFO_FIFO_MASK)
/*! @} */

/*! @name SAFO_SGI_CONFIG - SGI Configuration Register */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_MOVEM_MASK (0x40U)
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_MOVEM_SHIFT (6U)
/*! HAS_MOVEM - Has MOVEM
 */
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_MOVEM(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_MOVEM_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_MOVEM_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_CMAC_MASK (0x80U)
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_CMAC_SHIFT (7U)
/*! HAS_CMAC - Has CMAC
 */
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_CMAC(x)  (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_CMAC_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_CMAC_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_GFMUL_MASK (0x100U)
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_GFMUL_SHIFT (8U)
/*! HAS_GFMUL - Has GFMUL
 */
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_GFMUL(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_GFMUL_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_GFMUL_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CONFIG_INTERNAL_PRNG_MASK (0x200U)
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_INTERNAL_PRNG_SHIFT (9U)
/*! INTERNAL_PRNG - Has internal PRNG
 */
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_INTERNAL_PRNG(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CONFIG_INTERNAL_PRNG_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CONFIG_INTERNAL_PRNG_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CONFIG_KEY_DIGEST_MASK (0x400U)
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_KEY_DIGEST_SHIFT (10U)
/*! KEY_DIGEST - Has key digest
 */
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_KEY_DIGEST(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CONFIG_KEY_DIGEST_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CONFIG_KEY_DIGEST_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CONFIG_FA_MASK      (0x2000U)
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_FA_SHIFT     (13U)
/*! FA - Has FA protection
 */
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_FA(x)        (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CONFIG_FA_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CONFIG_FA_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CONFIG_MST_MASK     (0x4000U)
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_MST_SHIFT    (14U)
/*! MST - Has MST
 */
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_MST(x)       (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CONFIG_MST_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CONFIG_MST_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CONFIG_BUS_WIDTH_MASK (0x8000U)
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_BUS_WIDTH_SHIFT (15U)
/*! BUS_WIDTH - Bus width
 */
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_BUS_WIDTH(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CONFIG_BUS_WIDTH_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CONFIG_BUS_WIDTH_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CONFIG_NUM_DATIN_MASK (0x30000U)
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_NUM_DATIN_SHIFT (16U)
/*! NUM_DATIN - Number DATIN
 */
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_NUM_DATIN(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CONFIG_NUM_DATIN_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CONFIG_NUM_DATIN_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CONFIG_NUM_KEY_MASK (0x1C0000U)
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_NUM_KEY_SHIFT (18U)
/*! NUM_KEY - Number KEY
 */
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_NUM_KEY(x)   (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CONFIG_NUM_KEY_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CONFIG_NUM_KEY_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CONFIG_EDC_MASK     (0x200000U)
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_EDC_SHIFT    (21U)
/*! EDC - EDC enable
 */
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_EDC(x)       (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CONFIG_EDC_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CONFIG_EDC_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CONFIG_DUAL_SGI_MASK (0x400000U)
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_DUAL_SGI_SHIFT (22U)
/*! DUAL_SGI - Has dual SGI
 */
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_DUAL_SGI(x)  (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CONFIG_DUAL_SGI_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CONFIG_DUAL_SGI_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CONFIG_SHA_256_ONLY_MASK (0x1000000U)
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_SHA_256_ONLY_SHIFT (24U)
/*! SHA_256_ONLY - Has SHA 256 only
 */
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_SHA_256_ONLY(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CONFIG_SHA_256_ONLY_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CONFIG_SHA_256_ONLY_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CONFIG_SPB_SUPPORT_MASK (0x2000000U)
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_SPB_SUPPORT_SHIFT (25U)
/*! SPB_SUPPORT - ID_CFG_SPB_SUPPORT is set
 */
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_SPB_SUPPORT(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CONFIG_SPB_SUPPORT_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CONFIG_SPB_SUPPORT_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CONFIG_SPB_MASKING_MASK (0x4000000U)
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_SPB_MASKING_SHIFT (26U)
/*! SPB_MASKING - ID_CFG_SAFO_SGI_SPB_MASKING is set
 */
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_SPB_MASKING(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CONFIG_SPB_MASKING_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CONFIG_SPB_MASKING_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CONFIG_SFR_SW_MASK_MASK (0x8000000U)
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_SFR_SW_MASK_SHIFT (27U)
/*! SFR_SW_MASK - ID_CFG_SAFO_SGI_USE_SFR_SW_MASK is set
 */
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_SFR_SW_MASK(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CONFIG_SFR_SW_MASK_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CONFIG_SFR_SW_MASK_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_SM3_MASK (0x10000000U)
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_SM3_SHIFT (28U)
/*! HAS_SM3 - Has SM3
 */
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_SM3(x)   (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_SM3_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_SM3_MASK)

#define ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_SM4_MASK (0x20000000U)
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_SM4_SHIFT (29U)
/*! HAS_SM4 - Has SM4
 */
#define ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_SM4(x)   (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_SM4_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_CONFIG_HAS_SM4_MASK)
/*! @} */

/*! @name SAFO_SGI_INT_ENABLE - Interrupt Enable */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_INT_ENABLE_INT_EN_MASK (0x1U)
#define ID_SAFO_SGI_SAFO_SGI_INT_ENABLE_INT_EN_SHIFT (0U)
/*! INT_EN - Interrupt enable bit
 */
#define ID_SAFO_SGI_SAFO_SGI_INT_ENABLE_INT_EN(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_INT_ENABLE_INT_EN_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_INT_ENABLE_INT_EN_MASK)
/*! @} */

/*! @name SAFO_SGI_INT_STATUS_CLR - Interrupt Status Clear */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_INT_STATUS_CLR_INT_CLR_MASK (0x1U)
#define ID_SAFO_SGI_SAFO_SGI_INT_STATUS_CLR_INT_CLR_SHIFT (0U)
/*! INT_CLR - Interrupt Status Clear
 */
#define ID_SAFO_SGI_SAFO_SGI_INT_STATUS_CLR_INT_CLR(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_INT_STATUS_CLR_INT_CLR_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_INT_STATUS_CLR_INT_CLR_MASK)
/*! @} */

/*! @name SAFO_SGI_INT_STATUS_SET - Interrupt Status Set */
/*! @{ */

#define ID_SAFO_SGI_SAFO_SGI_INT_STATUS_SET_INT_SET_MASK (0x1U)
#define ID_SAFO_SGI_SAFO_SGI_INT_STATUS_SET_INT_SET_SHIFT (0U)
/*! INT_SET - Set Interrupt by SW
 */
#define ID_SAFO_SGI_SAFO_SGI_INT_STATUS_SET_INT_SET(x) (((uint32_t)(((uint32_t)(x)) << ID_SAFO_SGI_SAFO_SGI_INT_STATUS_SET_INT_SET_SHIFT)) & ID_SAFO_SGI_SAFO_SGI_INT_STATUS_SET_INT_SET_MASK)
/*! @} */


/*!
 * @}
 */ /* end of group ID_SAFO_SGI_Register_Masks */


/* ID_SAFO_SGI - Peripheral instance base addresses */
/** Peripheral ID_SAFO_SGI base address */
#define ID_SAFO_SGI_BASE                         (0u)
/** Peripheral ID_SAFO_SGI base pointer */
#define ID_SAFO_SGI                              ((ID_SAFO_SGI_Type *)ID_SAFO_SGI_BASE)
/** Array initializer of ID_SAFO_SGI peripheral base addresses */
#define ID_SAFO_SGI_BASE_ADDRS                   { ID_SAFO_SGI_BASE }
/** Array initializer of ID_SAFO_SGI peripheral base pointers */
#define ID_SAFO_SGI_BASE_PTRS                    { ID_SAFO_SGI }

/*!
 * @}
 */ /* end of group ID_SAFO_SGI_Peripheral_Access_Layer */


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


#endif  /* _ID_SAFO_SGI_H_ */

