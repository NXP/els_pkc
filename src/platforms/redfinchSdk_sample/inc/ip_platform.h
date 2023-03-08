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

#include "fsl_device_registers.h"

/* ================================================================================ */
/* ================             Peripheral declaration             ================ */
/* ================================================================================ */

// Define base address of CSS

#define ELS_SFR_BASE            ELS         ///< base of CSS SFRs
#define ELS_SFR_NAME(sfr)       sfr         ///< full name of SFR
#define ELS_SFR_PREFIX          ELS_        ///< sfr field name prefix



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
