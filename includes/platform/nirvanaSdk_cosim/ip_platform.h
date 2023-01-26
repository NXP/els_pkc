/*--------------------------------------------------------------------------*/
/* Copyright 2020-2022 NXP                                                  */
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

/** @file  ip_platform.h
 *  @brief Include file for the IP.
 *
 * This includes the CMSIS for all of the functionality provided by the CSSv2 IP and provides support for external base address linking. */

#ifndef IP_PLATFORM_H
#define IP_PLATFORM_H

#ifdef COSIM_M0PLUS
#include "ARMM0PLUS.h"
#else
#include "ARMSC300.h"
#endif

#include "sfr_peripherals.h"

#include "ip_css.h"
#include "ip_pkc.h"
#include "sa_trng_256.h"
#include "ip_puf.h"
#include "id_safo_sgi.h"

/* ================================================================================ */
/* ================             Peripheral declaration             ================ */
/* ================================================================================ */

// Define base address of CSS
#define ELS_SFR_BASE            IP_CSS      ///< base of CSS SFRs
#define ELS_SFR_NAME(sfr)       sfr ///< full name of SFR
#define ELS_SFR_PREFIX          IP_CSS_     ///< sfr field name prefix

#define ELS_EN                  CSS_EN      ///< define ELS enable
#define ELS_DMA_SRC0            CSS_DMA_SRC0
#define ELS_DMA_SRC2            CSS_DMA_SRC2
#define ELS_DMA_SRC2_LEN        CSS_DMA_SRC2_LEN
#define ELS_DMA_RES0      CSS_DMA_RES0
#define ELS_DMA_RES0_LEN  CSS_DMA_RES0_LEN
#define ELS_KIDX0         CSS_KIDX0
#define ELS_KIDX1         CSS_KIDX1
#define ELS_KIDX2         CSS_KIDX2
#define ELS_CTRL          CSS_CTRL
#define ELS_DMA_SRC1       CSS_DMA_SRC1
#define ELS_DMA_SRC0_LEN   CSS_DMA_SRC0_LEN
#define ELS_KPROPIN        CSS_KPROPIN
#define ELS_CMDCFG0        CSS_CMDCFG0
#define ELS_KPROPIN        CSS_KPROPIN
#define ELS_STATUS         CSS_STATUS
#define ELS_CMD            CSS_CMD
#define ELS_START          CSS_START
#define ELS_BUSY           CSS_BUSY
#define ELS_CFG            CSS_CFG
#define ELS_CMDCRC         CSS_CMDCRC
#define ELS_CMDCRC_CTRL    CSS_CMDCRC_CTRL
#define ELS_PRNG_DATOUT    CSS_PRNG_DATOUT
#define ELS_KS0            CSS_KS0
#define ELS_INT_STATUS_SET CSS_INT_STATUS_SET
#define ELS_RESET          CSS_RESET
#define ELS_VERSION                CSS_VERSION
#define ELS_ERR                    CSS_ERR
#define ELS_ERR_STATUS_FLT_ERR     CSS_ERR_STATUS_FLT_ERR
#define ELS_ERR_STATUS_ITG_ERR     CSS_ERR_STATUS_ITG_ERR
#define ELS_ERR_STATUS_OPN_ERR     CSS_ERR_STATUS_OPN_ERR
#define ELS_ERR_STATUS_ALG_ERR     CSS_ERR_STATUS_ALG_ERR
#define ELS_ERR_STATUS_BUS_ERR     CSS_ERR_STATUS_BUS_ERR
#define ELS_ERR_STATUS_PRNG_ERR    CSS_ERR_STATUS_PRNG_ERR
#define ELS_ERR_STATUS_DTRNG_ERR   CSS_ERR_STATUS_DTRNG_ERR
#define ELS_ERR_STATUS_ERR_LVL     CSS_ERR_STATUS_ERR_LVL
#define ELS_ERR_STATUS_CLR         CSS_ERR_STATUS_CLR
#define ELS_DMA_FIN_ADDR       CSS_DMA_FIN_ADDR
#define ELS_MASTER_ID          CSS_MASTER_ID
#define ELS_LOCKED             CSS_LOCKED
#define ELS_SESSION_ID         CSS_SESSION_ID
#define ELS_ERR_STATUS         CSS_ERR_STATUS
#define ELS_CFG_ADCTRL         CSS_CFG_ADCTRL
#define ELS_INT_STATUS_CLR     CSS_INT_STATUS_CLR
#define ELS_INT_ENABLE         CSS_INT_ENABLE
#define ELS_CTRL_RESET         CSS_CTRL_RESET
#define ELS_CTRL_ELS_RESET_MASK  CSS_CTRL_CSS_RESET_MASK
#define ELS_IRQ                CSS_IRQ
#define ELS_CONFIG             CSS_CONFIG


// Define base address of PKC
#define PKC_SFR_BASE            IP_PKC      ///< base of PKC SFRs
#define PKC_SFR_NAME(sfr)       PKC_ ## sfr ///< full name of SFR
#define PKC_SFR_PREFIX          IP_PKC_PKC_ ///< sfr field name prefix
#define PKC_SFR_SUFFIX_MSK      _MASK       ///< sfr field name suffix for mask
#define PKC_SFR_SUFFIX_POS      _SHIFT      ///< sfr field name suffix for bit position

// Define base address of TRNG
#define TRNG_SFR_BASE           TRNG        ///< base of TRNG SFRs
#define TRNG_SFR_NAME(sfr)      sfr         ///< full name of SFR
#define TRNG_SFR_PREFIX         TRNG_       ///< sfr field name prefix
#define TRNG_SFR_SUFFIX_MSK     _MASK       ///< sfr field name suffix for mask
#define TRNG_SFR_SUFFIX_POS     _SHIFT      ///< sfr field name suffix for bit position

// Define base address of PUF
#define PUF_SFR_BASE            IP_PUF      ///< base of PUF SFRs
#define PUF_SFR_NAME(sfr)       sfr         ///< full name of SFR
#define PUF_SFR_PREFIX          IP_PUF_     ///< sfr field name prefix

// Define base address of SAFO
#define SAFO_SFR_BASE           ID_SAFO_SGI      ///< base of SAFO SFRs
#define SAFO_SFR_NAME(sfr)      SAFO_SGI_ ## sfr ///< full name of SFR
#define SAFO_SFR_PREFIX         ID_SAFO_SGI_     ///< sfr field name prefix


#undef IP_CSS_BASE
extern const uint32_t Image$$CSS_BASE_ADDRESS$$Base;
#define IP_CSS_BASE ((uint32_t) &Image$$CSS_BASE_ADDRESS$$Base)

#undef IP_PKC_BASE
extern const uint32_t Image$$PKC_BASE_ADDRESS$$Base;
#define IP_PKC_BASE ((uint32_t) &Image$$PKC_BASE_ADDRESS$$Base)

#undef TRNG_BASE
extern const uint32_t Image$$TRNG_BASE_ADDRESS$$Base;
#define TRNG_BASE ((uint32_t) &Image$$TRNG_BASE_ADDRESS$$Base)

#undef IP_PUF_BASE
extern const uint32_t Image$$PUF_BASE_ADDRESS$$Base;
#define IP_PUF_BASE ((uint32_t) &Image$$PUF_BASE_ADDRESS$$Base)

#undef ID_SAFO_SGI_BASE
extern const uint32_t Image$$SM3_BASE_ADDRESS$$Base ;
#define ID_SAFO_SGI_BASE 	((uint32_t) &Image$$SM3_BASE_ADDRESS$$Base )


#define CSS_INTERRUPT_BUSY_NUMBER  13
#define CSS_INTERRUPT_ERR_NUMBER   14
#define CSS_INTERRUPT_IRQ_NUMBER   15

// dcv2 interrupt line number
#define DCV2_INTERRUPT_NUMBER  27

#define MCUXCLELS_HW_VERSION_REVISION            0
#define MCUXCLELS_HW_VERSION_MINOR               4
#define MCUXCLELS_HW_VERSION_MAJOR               3
#define MCUXCLELS_HW_VERSION_FW_REVISION         0
#define MCUXCLELS_HW_VERSION_FW_MINOR            4
#define MCUXCLELS_HW_VERSION_FW_MAJOR            2

extern const uint32_t __ICFEDIT_region_RAM_PKC_start__;
#define PKC_RAM_ADDR  (&__ICFEDIT_region_RAM_PKC_start__)
#define PKC_WORD_SIZE  8u


#endif
