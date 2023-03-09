/*--------------------------------------------------------------------------*/
/* Copyright 2020-2023 NXP                                                  */
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

/* Platform compatibility defines */
#ifndef ELS_DMA_SRC0
#define ELS_DMA_SRC0 DMA_SRC0
#endif

#ifndef ELS_DMA_SRC0_LEN
#define ELS_DMA_SRC0_LEN DMA_SRC0_LEN
#endif

#ifndef ELS_DMA_SRC1
#define ELS_DMA_SRC1 DMA_SRC1
#endif

#ifndef ELS_DMA_SRC2
#define ELS_DMA_SRC2 DMA_SRC2
#endif

#ifndef ELS_DMA_SRC2_LEN
#define ELS_DMA_SRC2_LEN DMA_SRC2_LEN
#endif

#ifndef ELS_DMA_RES0
#define ELS_DMA_RES0 DMA_RES0
#endif

#ifndef ELS_DMA_RES0_LEN
#define ELS_DMA_RES0_LEN DMA_RES0_LEN
#endif

#ifndef ELS_KIDX0
#define ELS_KIDX0 KIDX0
#endif

#ifndef ELS_KIDX1
#define ELS_KIDX1 KIDX1
#endif

#ifndef ELS_KIDX2
#define ELS_KIDX2 KIDX2
#endif

#ifndef ELS_KPROPIN
#define ELS_KPROPIN KPROPIN
#endif

#ifndef ELS_CTRL
#define ELS_CTRL CTRL
#endif

#ifndef ELS_CMDCFG0
#define ELS_CMDCFG0 CMDCFG0
#endif

#ifndef ELS_STATUS
#define ELS_STATUS STATUS
#endif

#ifndef ELS_VERSION
#define ELS_VERSION VERSION
#endif

#ifndef ELS_ERR_STATUS
#define ELS_ERR_STATUS ERR_STATUS
#endif

#ifndef ELS_ERR_STATUS_CLR
#define ELS_ERR_STATUS_CLR ERR_STATUS_CLR
#endif

#ifndef ELS_INT_ENABLE
#define ELS_INT_ENABLE INT_ENABLE
#endif

#ifndef ELS_INT_STATUS_CLR
#define ELS_INT_STATUS_CLR INT_STATUS_CLR
#endif

#ifndef ELS_INT_STATUS_SET
#define ELS_INT_STATUS_SET INT_STATUS_SET
#endif

#ifndef ELS_SESSION_ID
#define ELS_SESSION_ID SESSION_ID
#endif

#ifndef ELS_MASTER_ID
#define ELS_MASTER_ID MASTER_ID
#endif

#ifndef ELS_CFG
#define ELS_CFG CFG
#endif

#ifndef ELS_CMDCRC
#define ELS_CMDCRC CMDCRC
#endif

#ifndef ELS_CMDCRC_CTRL
#define ELS_CMDCRC_CTRL CMDCRC_CTRL
#endif

#ifndef ELS_PRNG_DATOUT
#define ELS_PRNG_DATOUT PRNG_DATOUT
#endif

#define MCUXCL_FEATURE_TRNG_RNG4_256
/* END of Platform compatibility defines */

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
#define PKC_RAM_SIZE  ((uint32_t)0x1000u)
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
