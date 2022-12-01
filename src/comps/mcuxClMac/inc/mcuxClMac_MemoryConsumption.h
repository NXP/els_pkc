/*--------------------------------------------------------------------------*/
/* Copyright 2020-2021 NXP                                                  */
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

/** @file  mcuxClMac_MemoryConsumption.h
 *  @brief Defines the memory consumption for the mcuxClMac component */

#ifndef MCUXCLMAC_MEMORYCONSUMPTION_H_
#define MCUXCLMAC_MEMORYCONSUMPTION_H_

/**
 * @defgroup mcuxClMac_MemoryConsumption mcuxClMac_MemoryConsumption
 * @brief Defines the memory consumption for the mcuxClMac component
 * @ingroup mcuxClMac
 * @{
 */
/**********************************************
 * HELPER MACRO
 **********************************************/
#define MCUXCL_MAC_MAX(a,b) (((a) > (b)) ? (a) : (b))
/**********************************************
 * TYPEDEFS
 **********************************************/

/** @def MCUXCLMAC_WA_SIZEW_MAX
 *  @brief Define the max workarea size in words required for this component
 */
#define MCUXCLMAC_WA_SIZEW_MAX (4)

/** @def MCUXCLMAC_WA_SIZE_MAX
 *  @brief Define the max workarea size in bytes required for this component
 */
#define MCUXCLMAC_WA_SIZE_MAX (MCUXCLMAC_WA_SIZEW_MAX * sizeof(uint32_t))

/**
 *  @brief Define the size of context for CMac
 */
#define MCUXCLMAC_CMAC_CTX_SIZE  (116u)

/**
 *  @brief Define the size of context for HMac
 */
#define MCUXCLMAC_HMAC_CTX_SIZE  (116u)

/**
 *  @brief Define the size of context for CBCMac
 */
#define MCUXCLMAC_CBCMAC_CTX_SIZE  (116u)


#define MCUXCL_MAC_MAXIMUM_CTX_SIZE MCUXCL_MAC_MAX(MCUXCLMAC_CMAC_CTX_SIZE, MCUXCL_MAC_MAX(MCUXCLMAC_HMAC_CTX_SIZE, MCUXCLMAC_CBCMAC_CTX_SIZE))

#define MCUXCL_MAC_MAXIMUM_OUTPUT_SIZE MCUXCL_MAC_MAX(MCUXCLCSS_HASH_OUTPUT_SIZE_SHA_256,MCUXCLCSS_CMAC_OUT_SIZE)

/** @def MCUXCLMAC_WA_SIZEW_CMAC
 *  @brief Define the workarea size in words required for CMAC mode
 */
#define MCUXCLMAC_WA_SIZEW_CMAC (4)

/** @def MCUXCLMAC_WA_SIZE_CMAC
 *  @brief Define the workarea size in bytes required for CMAC mode
 */
#define MCUXCLMAC_WA_SIZE_CMAC (MCUXCLMAC_WA_SIZEW_CMAC * sizeof(uint32_t))

/** @def MCUXCLMAC_WA_SIZEW_HMAC
 *  @brief Define the workarea size in words required for HMAC mode
 */
#define MCUXCLMAC_WA_SIZEW_HMAC (4)

/** @def MCUXCLMAC_WA_SIZE_HMAC
 *  @brief Define the workarea size in bytes required for HMAC mode
 */
#define MCUXCLMAC_WA_SIZE_HMAC (MCUXCLMAC_WA_SIZEW_HMAC * sizeof(uint32_t))

/** @def MCUXCLMAC_WA_SIZEW_CBC_MAC_NOPADDING
 *  @brief Define the workarea size in words required for CBC MAC mode
 */
#define MCUXCLMAC_WA_SIZEW_CBC_MAC_NOPADDING (4)

/** @def MCUXCLMAC_WA_SIZE_CBC_MAC_NOPADDING
 *  @brief Define the workarea size in bytes required for CBC MAC mode
 */
#define MCUXCLMAC_WA_SIZE_CBC_MAC_NOPADDING (MCUXCLMAC_WA_SIZEW_CBC_MAC_NOPADDING * sizeof(uint32_t))

/** @def MCUXCLMAC_WA_SIZEW_CBC_MAC_PADDINGISO1
 *  @brief Define the workarea size in words required for CBC MAC mode
 */
#define MCUXCLMAC_WA_SIZEW_CBC_MAC_PADDINGISO1 (4)

/** @def MCUXCLMAC_WA_SIZE_CBC_MAC_PADDINGISO1
 *  @brief Define the workarea size in bytes required for CBC MAC mode
 */
#define MCUXCLMAC_WA_SIZE_CBC_MAC_PADDINGISO1 (MCUXCLMAC_WA_SIZEW_CBC_MAC_PADDINGISO1 * sizeof(uint32_t))

/** @def MCUXCLMAC_WA_SIZEW_CBC_MAC_PADDINGISO2
 *  @brief Define the workarea size in words required for CBC MAC mode
 */
#define MCUXCLMAC_WA_SIZEW_CBC_MAC_PADDINGISO2 (4)

/** @def MCUXCLMAC_WA_SIZE_CBC_MAC_PADDINGISO2
 *  @brief Define the workarea size in bytes required for CBC MAC mode
 */
#define MCUXCLMAC_WA_SIZE_CBC_MAC_PADDINGISO2 (MCUXCLMAC_WA_SIZEW_CBC_MAC_PADDINGISO2 * sizeof(uint32_t))

/**
 * @}
 */ /* mcuxClMac_MemoryConsumption */

#endif /* MCUXCLMAC_MEMORYCONSUMPTION_H_ */
