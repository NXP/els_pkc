/*--------------------------------------------------------------------------*/
/* Copyright 2020-2023 NXP                                                  */
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
#elif defined(COSIM_R7)
#include "ARMR7.h"
#else
#include "ARMSC300.h"
#endif

#include "sfr_peripherals.h"

#ifdef MCUXCL_FEATURE_HW_GLIKEY
#include "ip_glikey.h"
#endif /* MCUXCL_FEATURE_HW_GLIKEY */
#include "ip_css.h"
#include "ip_pkc.h"
#ifdef MCUXCL_FEATURE_HW_TRNG
#include "sa_trng_256.h"
#endif /* MCUXCL_FEATURE_HW_TRNG */
#ifdef MCUXCL_FEATURE_HW_ROPUF
#include "ip_puf.h"
#endif /* MCUXCL_FEATURE_HW_ROPUF */
#ifdef MCUXCL_FEATURE_HW_SAFO_SM3
#include "id_safo_sgi.h"
#endif /* MCUXCL_FEATURE_HW_SAFO_SM3 */

/* ================================================================================ */
/* ================             Peripheral declaration             ================ */
/* ================================================================================ */

#ifdef MCUXCL_FEATURE_HW_GLIKEY
// Define base address of Glikey
#define GLIKEY0_BASEADDRESS        GLIKEY0_BASE  ///< Base address for GLIKEY instance 0
#define GLIKEY1_BASEADDRESS        GLIKEY1_BASE  ///< Base address for GLIKEY instance 1

// TODO: Remove this workaround from COSIM targets. This was added due to missing data for Glikey1 on rt700 sample
#define GLIKEY2_BASEADDRESS        GLIKEY1_BASE  ///< Base address for GLIKEY instance 1

#define GLIKEY_SFR_BASE(baseAddress)    ((IP_GLIKEY_Type *)baseAddress) ///< base of GLIKEY SFRs
#define GLIKEY_SFR_NAME(sfr)            IP_GLIKEY_ ## sfr               ///< full name of SFR
#define GLIKEY_SFR_PREFIX               IP_GLIKEY_IP_GLIKEY_            ///< sfr field name prefix
#define GLIKEY_SFR_SUFFIX_MSK           _MASK                           ///< sfr field name suffix for mask
#define GLIKEY_SFR_SUFFIX_POS           _SHIFT                          ///< sfr field name suffix for bit position

// Define number of indexes per Glikey instance
#define GLIKEY0_NUM_IDX         16  ///< Number of addressable indexes for GLIKEY instance 0
#define GLIKEY1_NUM_IDX         64  ///< Number of addressable indexes for GLIKEY instance 1
// TODO: Remove this workaround from COSIM targets. This was added due to missing data for Glikey1 on rt700 sample
#define GLIKEY2_NUM_IDX         64  ///< Number of addressable indexes for GLIKEY instance 1
#endif /* MCUXCL_FEATURE_HW_GLIKEY */

// Define base address of CSS
#define ELS_SFR_BASE            IP_CSS      ///< base of CSS SFRs
#define ELS_SFR_NAME(sfr)       sfr ///< full name of SFR
#define ELS_SFR_PREFIX          IP_CSS_     ///< sfr field name prefix

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
#define PKC_SFR_BASE            IP_PKC      ///< base of PKC SFRs
#define PKC_SFR_NAME(sfr)       PKC_ ## sfr ///< full name of SFR
#define PKC_SFR_PREFIX          IP_PKC_PKC_ ///< sfr field name prefix
#define PKC_SFR_SUFFIX_MSK      _MASK       ///< sfr field name suffix for mask
#define PKC_SFR_SUFFIX_POS      _SHIFT      ///< sfr field name suffix for bit position

#ifdef MCUXCL_FEATURE_HW_TRNG
// Define base address of TRNG
#define TRNG_SFR_BASE           TRNG        ///< base of TRNG SFRs
#define TRNG_SFR_NAME(sfr)      sfr         ///< full name of SFR
#define TRNG_SFR_PREFIX         TRNG_       ///< sfr field name prefix
#define TRNG_SFR_SUFFIX_MSK     _MASK       ///< sfr field name suffix for mask
#define TRNG_SFR_SUFFIX_POS     _SHIFT      ///< sfr field name suffix for bit position
#endif /* MCUXCL_FEATURE_HW_TRNG */

#ifdef MCUXCL_FEATURE_HW_ROPUF
// Define base address of PUF
#define PUF_SFR_BASE            IP_PUF      ///< base of PUF SFRs
#define PUF_SFR_NAME(sfr)       PUF_ ## sfr         ///< full name of SFR
#define PUF_SFR_PREFIX          IP_PUF_PUF_     ///< sfr field name prefix
#define PUF_SFR_SUFFIX_MSK     _MASK       ///< sfr field name suffix for mask
#define PUF_SFR_SUFFIX_POS     _SHIFT      ///< sfr field name suffix for bit position
#endif /* MCUXCL_FEATURE_HW_ROPUF */

#ifdef MCUXCL_FEATURE_HW_SAFO_SM3
// Define base address of SAFO
#define SAFO_SFR_BASE           ID_SAFO_SGI      ///< base of SAFO SFRs
#define SAFO_SFR_NAME(sfr)      SAFO_SGI_ ## sfr ///< full name of SFR
#define SAFO_SFR_PREFIX         ID_SAFO_SGI_SAFO_SGI_     ///< sfr field name prefix
#endif /* MCUXCL_FEATURE_HW_SAFO_SM3 */



#undef IP_CSS_BASE
extern const uint32_t Image$$CSS_BASE_ADDRESS$$Base;
#define IP_CSS_BASE ((uint32_t) &Image$$CSS_BASE_ADDRESS$$Base)

#undef IP_PKC_BASE
extern const uint32_t Image$$PKC_BASE_ADDRESS$$Base;
#define IP_PKC_BASE ((uint32_t) &Image$$PKC_BASE_ADDRESS$$Base)

#if defined ( __ICCARM__ )
extern const uint32_t __ICFEDIT_region_RAM_PKC_start__;
#define PKC_RAM_ADDR  (&__ICFEDIT_region_RAM_PKC_start__)
#define PKC_WORD_SIZE  8u

#else

extern const uint32_t Image$$PKC_RAM_BUF_ADDRESS$$Base;
#define PKC_RAM_ADDR ((uint32_t) &Image$$PKC_RAM_BUF_ADDRESS$$Base)
#define PKC_WORD_SIZE  8u

#endif /* __ICCARM__ */

#ifdef MCUXCL_FEATURE_HW_TRNG
#undef TRNG_BASE
extern const uint32_t Image$$TRNG_BASE_ADDRESS$$Base;
#define TRNG_BASE ((uint32_t) &Image$$TRNG_BASE_ADDRESS$$Base)
#endif /* MCUXCL_FEATURE_HW_TRNG */

#ifdef MCUXCL_FEATURE_HW_ROPUF
#undef IP_PUF_BASE
extern const uint32_t Image$$PUF_BASE_ADDRESS$$Base;
#define IP_PUF_BASE ((uint32_t) &Image$$PUF_BASE_ADDRESS$$Base)
#endif /* MCUXCL_FEATURE_HW_ROPUF */

#ifdef MCUXCL_FEATURE_HW_SAFO_SM3
#undef ID_SAFO_SGI_BASE
extern const uint32_t Image$$SM3_BASE_ADDRESS$$Base ;
#define ID_SAFO_SGI_BASE    ((uint32_t) &Image$$SM3_BASE_ADDRESS$$Base )
#endif /* MCUXCL_FEATURE_HW_SAFO_SM3 */


#ifdef COSIM_R7
#define CSS_INTERRUPT_BUSY_NUMBER           45
#define CSS_INTERRUPT_ERR_NUMBER            46
#define CSS_INTERRUPT_IRQ_NUMBER            47
#define PUF_INTERRUPT_IRQ_NUMBER            35
#define PUF_BEHAVIOR_INTERRUPT_IRQ_NUMBER   36
#define CSS_GDET_INTERRUPT_IRQ_NUMBER            37
#else
#define CSS_INTERRUPT_BUSY_NUMBER          13
#define CSS_INTERRUPT_ERR_NUMBER           14
#define CSS_INTERRUPT_IRQ_NUMBER           15
#define PUF_INTERRUPT_IRQ_NUMBER            3
#define PUF_BEHAVIOR_INTERRUPT_IRQ_NUMBER   4
#define CSS_GDET_INTERRUPT_IRQ_NUMBER             5
#endif


// dcv2 interrupt line number
#define DCV2_INTERRUPT_NUMBER  27

// Glikey interrupt number
#define GLIKEY0_INTERRUPT_NUMBER   6  // GLIKEY instance 0 with 16 indexes
#define GLIKEY1_INTERRUPT_NUMBER   7  // GLIKEY instance 1 with 64 indexes
// TODO: Remove this workaround from COSIM targets. This was added due to missing data for Glikey1 on rt700 sample
#define GLIKEY2_INTERRUPT_NUMBER   7  // GLIKEY instance 1 with 64 indexes

// Expected ELS HW version (project dependent)

#undef ELS_HW_VERSION_REVISION

#ifdef MCUXCL_FEATURE_PLATFORM_MIMXRT
#define ELS_HW_VERSION_REVISION            0
#define ELS_HW_VERSION_MINOR               16
#define ELS_HW_VERSION_MAJOR               3
#define ELS_HW_VERSION_FW_REVISION         0
#define ELS_HW_VERSION_FW_MINOR            16
#define ELS_HW_VERSION_FW_MAJOR            2
#endif

#ifdef MCUXCL_FEATURE_PLATFORM_MCXN
#define ELS_HW_VERSION_REVISION            0
#define ELS_HW_VERSION_MINOR               4
#define ELS_HW_VERSION_MAJOR               3
#define ELS_HW_VERSION_FW_REVISION         0
#define ELS_HW_VERSION_FW_MINOR            4
#define ELS_HW_VERSION_FW_MAJOR            2
#endif

#ifdef MCUXCL_FEATURE_PLATFORM_LPC
#define ELS_HW_VERSION_REVISION            0
#define ELS_HW_VERSION_MINOR               15
#define ELS_HW_VERSION_MAJOR               2
#define ELS_HW_VERSION_LEVEL               0
#endif




#ifndef ELS_HW_VERSION_REVISION
#define ELS_HW_VERSION_REVISION            0
#define ELS_HW_VERSION_MINOR               0
#define ELS_HW_VERSION_MAJOR               0
#define ELS_HW_VERSION_FW_REVISION         0
#define ELS_HW_VERSION_FW_MINOR            0
#define ELS_HW_VERSION_FW_MAJOR            0
#define ELS_HW_VERSION_LEVEL               0
#endif

/* If we are supposed to determine the CSSv2 base address at link time, do not use the definitions from ip_css.h
 * Redefine IP_CSS as an extern pointer.
 */
#undef IP_CSS_BASE
#undef IP_CSS
extern void * ip_css_base;
#define IP_CSS                          ((IP_CSS_Type             *) ip_css_base)

#define MCUXCL_CACHE_FLUSH(addr, len)
#define MCUXCL_CACHE_CLEAR(addr, len)
#ifndef MCUXCL_CACHE_ALIGNED
/* MCUXCL_CACHE_ALIGNED should be defined externally */
#define MCUXCL_CACHE_ALIGNED
#endif

#endif
