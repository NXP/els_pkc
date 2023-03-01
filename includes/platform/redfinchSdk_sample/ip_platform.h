/*--------------------------------------------------------------------------*/
/* Copyright 2022 NXP                                                       */
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
 * This file defines base addresses and types for all IP blocks used by CLNS. */

#ifndef IP_PLATFORM_H
#define IP_PLATFORM_H

#include <RW610.h>

/* ================================================================================ */
/* ================             Peripheral declaration             ================ */
/* ================================================================================ */

// Define base address of CSS
#define ELS_SFR_BASE            CSS         ///< base of CSS SFRs
#define ELS_SFR_NAME(sfr)       sfr         ///< full name of SFR
#define ELS_SFR_PREFIX          CSS_        ///< sfr field name prefix

// SFR remapping
#define ELS_STATUS              CSS_STATUS
#define ELS_CTRL                CSS_CTRL
#define ELS_CMDCFG0             CSS_CMDCFG0
#define ELS_CFG                 CSS_CFG
#define ELS_KIDX0               CSS_KIDX0
#define ELS_KIDX1               CSS_KIDX1
#define ELS_KPROPIN             CSS_KPROPIN
#define ELS_DMA_SRC0            CSS_DMA_SRC0
#define ELS_DMA_SRC0_LEN        CSS_DMA_SRC0_LEN
#define ELS_DMA_SRC1            CSS_DMA_SRC1
#define ELS_DMA_SRC2            CSS_DMA_SRC2
#define ELS_DMA_SRC2_LEN        CSS_DMA_SRC2_LEN
#define ELS_DMA_RES0            CSS_DMA_RES0
#define ELS_DMA_RES0_LEN        CSS_DMA_RES0_LEN
#define ELS_INT_ENABLE          CSS_INT_ENABLE
#define ELS_INT_STATUS_CLR      CSS_INT_STATUS_CLR
#define ELS_INT_STATUS_SET      CSS_INT_STATUS_SET
#define ELS_ERR_STATUS          CSS_ERR_STATUS
#define ELS_ERR_STATUS_CLR      CSS_ERR_STATUS_CLR
#define ELS_VERSION             CSS_VERSION
#define ELS_CONFIG              CSS_CONFIG
#define ELS_PRNG_DATOUT         CSS_PRNG_DATOUT
#define ELS_CMDCRC_CTRL         CSS_CMDCRC_CTRL
#define ELS_CMDCRC              CSS_CMDCRC
#define ELS_SESSION_ID          CSS_SESSION_ID
#define ELS_DMA_FIN_ADDR        CSS_DMA_FIN_ADDR
#define ELS_MASTER_ID           CSS_MASTER_ID
#define ELS_GDET_EVTCNT         CSS_GDET_EVTCNT
#define ELS_GDET_EVTCNT_CLR     CSS_GDET_EVTCNT_CLR
#define ELS_KIDX2               CSS_KIDX2
#define ELS_SHA2_STATUS         CSS_SHA2_STATUS
#define ELS_SHA2_CTRL           CSS_SHA2_CTRL
#define ELS_SHA2_DIN            CSS_SHA2_DIN
#define ELS_SHA2_DOUT0          CSS_SHA2_DOUT0
#define ELS_SHA2_DOUT1          CSS_SHA2_DOUT1
#define ELS_SHA2_DOUT2          CSS_SHA2_DOUT2
#define ELS_SHA2_DOUT3          CSS_SHA2_DOUT3
#define ELS_SHA2_DOUT4          CSS_SHA2_DOUT4
#define ELS_SHA2_DOUT5          CSS_SHA2_DOUT5
#define ELS_SHA2_DOUT6          CSS_SHA2_DOUT6
#define ELS_SHA2_DOUT7          CSS_SHA2_DOUT7
#define ELS_SHA2_DOUT8          CSS_SHA2_DOUT8
#define ELS_SHA2_DOUT9          CSS_SHA2_DOUT9
#define ELS_SHA2_DOUT10         CSS_SHA2_DOUT10
#define ELS_SHA2_DOUT11         CSS_SHA2_DOUT11
#define ELS_SHA2_DOUT12         CSS_SHA2_DOUT12
#define ELS_SHA2_DOUT13         CSS_SHA2_DOUT13
#define ELS_SHA2_DOUT14         CSS_SHA2_DOUT14
#define ELS_SHA2_DOUT15         CSS_SHA2_DOUT15
#define ELS_KS0                 CSS_KS0
#define ELS_KS1                 CSS_KS1
#define ELS_KS2                 CSS_KS2
#define ELS_KS3                 CSS_KS3
#define ELS_KS4                 CSS_KS4
#define ELS_KS5                 CSS_KS5
#define ELS_KS6                 CSS_KS6
#define ELS_KS7                 CSS_KS7
#define ELS_KS8                 CSS_KS8
#define ELS_KS9                 CSS_KS9
#define ELS_KS10                CSS_KS10
#define ELS_KS11                CSS_KS11
#define ELS_KS12                CSS_KS12
#define ELS_KS13                CSS_KS13
#define ELS_KS14                CSS_KS14
#define ELS_KS15                CSS_KS15
#define ELS_KS16                CSS_KS16
#define ELS_KS17                CSS_KS17
#define ELS_KS18                CSS_KS18
#define ELS_KS19                CSS_KS19
#define ELS_BOOT_ADDR           CSS_BOOT_ADDR
#define ELS_DBG_CFG             CSS_DBG_CFG

// bit fields of CSS_STATUS
#define ELS_BUSY    CSS_BUSY
#define ELS_IRQ     CSS_IRQ
#define ELS_ERR     CSS_ERR
#define ELS_LOCKED  CSS_LOCKED

// bit fields of CSS_CTRL
#define ELS_EN      CSS_EN
#define ELS_START   CSS_START
#define ELS_RESET   CSS_RESET
#define ELS_CMD     CSS_CMD

// Define base address of PKC
#define PKC_SFR_BASE            PKC         ///< base of PKC SFRs
#define PKC_SFR_NAME(sfr)       PKC_ ## sfr ///< full name of SFR
#define PKC_SFR_PREFIX          PKC_PKC_    ///< sfr field name prefix
#define PKC_SFR_SUFFIX_MSK      _MASK       ///< sfr field name suffix for mask
#define PKC_SFR_SUFFIX_POS      _SHIFT      ///< sfr field name suffix for bit position

// PKC_RAM base address is not defined in any header file
#define PKC_RAM_ADDR ((uint32_t) 0x5015A000)
#define PKC_RAM_SIZE  ((uint32_t)0x2000u)
#define PKC_WORD_SIZE  8u

// Define base address of TRNG
#define TRNG_SFR_BASE           TRNG         ///< base of TRNG SFRs
#define TRNG_SFR_NAME(sfr)      sfr          ///< full name of SFR
#define TRNG_SFR_PREFIX         TRNG_        ///< sfr field name prefix
#define TRNG_SFR_SUFFIX_MSK     _MASK        ///< sfr field name suffix for mask
#define TRNG_SFR_SUFFIX_POS     _SHIFT       ///< sfr field name suffix for bit position

// Define base address of RO-PUF


// CSS interrupt definitions (TODO: check)
#define CSS_INTERRUPT_BUSY_NUMBER  102
#define CSS_INTERRUPT_ERR_NUMBER   102
#define CSS_INTERRUPT_IRQ_NUMBER   102
#define GDET_INTERRUPT_IRQ_NUMBER   103
#define GDET_INTERRUPT_ERR_NUMBER   104


#ifdef NXPCL_FEATURE_ELS_LINK_BASE_ADDRESS
/* If we are supposed to determine the CSSv2 base address at link time, do not use the definitions from ip_css.h
 * Redefine CSS as an extern pointer.
 */
#undef CSS_BASE
extern void * ip_css_base;
#define CSS_BASE                     ip_css_base
#endif /* NXPCL_FEATURE_ELS_LINK_BASE_ADDRESS */

#endif
