/*--------------------------------------------------------------------------*/
/* Copyright 2020-2022 NXP                                                  */
/*                                                                          */
/* All rights are reserved. Reproduction in whole or in part is prohibited  */
/* without the prior written consent of the copy-right owner.               */
/* This source code and any compilation or derivative thereof is the sole   */
/* property of NXP N.V. and is provided pursuant to a Software License      */
/* Agreement. This code is the proprietary information of NXP N.V. and      */
/* is confidential in nature. Its use and dissemination by any party other  */
/* than NXP N.V. is strictly limited by the confidential information        */
/* provisions of the agreement referenced above.                            */
/*--------------------------------------------------------------------------*/

/** @file  ip_platform.h
 *  @brief Include file for the IP.
 *
 * This includes the CMSIS for all of the functionality provided by the ELS IP and provides support for external base address linking. */

#ifndef IP_PLATFORM_H
#define IP_PLATFORM_H

#include "fsl_device_registers.h"

/* ================================================================================ */
/* ================             Peripheral declaration             ================ */
/* ================================================================================ */

// Define base address of ELS
#define ELS_SFR_BASE            ELS         ///< base of ELS SFRs
#define ELS_SFR_NAME(sfr)       sfr         ///< full name of SFR
#define ELS_SFR_PREFIX          S50_        ///< sfr field name prefix

// Define base address of PKC
#define PKC_SFR_BASE            PKC0        ///< base of PKC SFRs
#define PKC_SFR_NAME(sfr)       PKC_ ## sfr ///< full name of SFR
#define PKC_SFR_PREFIX          PKC_PKC_    ///< sfr field name prefix
#define PKC_SFR_SUFFIX_MSK      _MASK       ///< sfr field name suffix for mask
#define PKC_SFR_SUFFIX_POS      _SHIFT      ///< sfr field name suffix for bit position

// PKC_RAM base address is not defined in any header file
#define PKC_RAM_ADDR  ((uint32_t)0x400B3000u)
#define PKC_WORD_SIZE  8u

// Define base address of TRNG
#define TRNG_SFR_BASE           TRNG0       ///< base of TRNG SFRs
#define TRNG_SFR_NAME(sfr)      sfr         ///< full name of SFR
#define TRNG_SFR_PREFIX         TRNG_       ///< sfr field name prefix
#define TRNG_SFR_SUFFIX_MSK     _MASK       ///< sfr field name suffix for mask
#define TRNG_SFR_SUFFIX_POS     _SHIFT      ///< sfr field name suffix for bit position

// Define base address of SAFO
#define SAFO_SFR_BASE           SM3_0       ///< base of SAFO SFRs
#define SAFO_SFR_NAME(sfr)      sfr         ///< full name of SFR
#define SAFO_SFR_PREFIX         SM3_        ///< sfr field name prefix

// Workaround for the use of prefixed constants in the SM3 implementation (e.g. SAFO_SGI_SM3_CTRL --> CTRL)
#define SAFO_SGI_DATIN0A DATIN0A
#define SAFO_SGI_DATIN0B DATIN0B
#define SAFO_SGI_DATIN0C DATIN0C
#define SAFO_SGI_DATIN0D DATIN0D
#define SAFO_SGI_DATIN1A DATIN1A
#define SAFO_SGI_DATIN1B DATIN1B
#define SAFO_SGI_DATIN1C DATIN1C
#define SAFO_SGI_DATIN1D DATIN1D
#define SAFO_SGI_KEY0A KEY0A
#define SAFO_SGI_KEY0B KEY0B
#define SAFO_SGI_KEY0C KEY0C
#define SAFO_SGI_KEY0D KEY0D
#define SAFO_SGI_KEY1A KEY1A
#define SAFO_SGI_KEY1B KEY1B
#define SAFO_SGI_KEY1C KEY1C
#define SAFO_SGI_KEY1D KEY1D
#define SAFO_SGI_DATOUTA DATOUTA
#define SAFO_SGI_DATOUTB DATOUTB
#define SAFO_SGI_DATOUTC DATOUTC
#define SAFO_SGI_DATOUTD DATOUTD
#define SAFO_SGI_STATUS STATUS
#define SAFO_SGI_COUNT COUNT
#define SAFO_SGI_CTRL CTRL
#define SAFO_SGI_CTRL2 CTRL2
#define SAFO_SGI_SM3_CTRL SM3_CTRL
#define SAFO_SGI_SM3_FIFO SM3_FIFO
#define SAFO_SGI_CONFIG CONFIG
#define SAFO_SGI_INT_ENABLE INT_ENABLE
#define SAFO_SGI_INT_STATUS_CLR INT_STATUS_CLR
#define SAFO_SGI_INT_STATUS_SET INT_STATUS_SET


// CSS interrupt definitions
#define CSS_INTERRUPT_ERR_NUMBER   CSS_IRQn
#define CSS_INTERRUPT_IRQ_NUMBER   CSS_ERR_IRQn
//#define CSS_INTERRUPT_BUSY_NUMBER  // not supported


#define IP_PUF_BASE      0x5002C000UL
#define PUF_SRAM_CFG     *(volatile uint32_t *) (IP_PUF_BASE + 0x300)
#define PUF_SR           *(volatile uint32_t *) (IP_PUF_BASE + 0x8)
#define PUF_OR           *(volatile uint32_t *) (IP_PUF_BASE + 0x4)
#define PUF_CR           *(volatile uint32_t *) (IP_PUF_BASE + 0x0)
#define PUF_KEY_DEST     *(volatile uint32_t *) (IP_PUF_BASE + 0x20)
#define PUF_DIR          *(volatile uint32_t *) (IP_PUF_BASE + 0xA0)
#define PUF_DOR          *(volatile uint32_t *) (IP_PUF_BASE + 0xA8)


#define NXPCLELS_HW_VERSION_REVISION            0
#define NXPCLELS_HW_VERSION_MINOR               4
#define NXPCLELS_HW_VERSION_MAJOR               3
#define NXPCLELS_HW_VERSION_FW_REVISION         0
#define NXPCLELS_HW_VERSION_FW_MINOR            4
#define NXPCLELS_HW_VERSION_FW_MAJOR            2


#ifdef NXPCL_FEATURE_ELS_LINK_BASE_ADDRESS
/* If we are supposed to determine the CSSv2 base address at link time, do not use the definitions from the platform header file
 * Redefine IP_CSS as an extern pointer.
 */
#undef ELS_SFR_BASE
extern void * ip_css_base;
#define ELS_SFR_BASE           ((S50_Type *) ip_css_base)
#endif /* NXPCL_FEATURE_ELS_LINK_BASE_ADDRESS */

#endif
