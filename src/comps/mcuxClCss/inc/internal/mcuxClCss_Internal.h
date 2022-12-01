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

/** @file  mcuxClCss_Internal.h
 *  @brief Provide macros for mcuxClCss internal use.
 * This header declares internal macros to deduplicate code and support for internal use only. */

#ifndef MCUXCLCSS_INTERNAL_H_
#define MCUXCLCSS_INTERNAL_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <platform_specific_headers.h>
#include <stdint.h>
#include <stdbool.h>


/****                                ****/
/**** CSS Hardware Abstraction Layer ****/
/****                                ****/

/**
 * Definitions for accessing CSS SFRs via, e.g., IP_CSS->STATUS.
 */

/** Helper macros for constructing SFR field name constants */
#define MCUXCLCSS_PASTE(a,b)  a ## b
#define MCUXCLCSS_CONCAT(a,b) MCUXCLCSS_PASTE(a,b)
#define MCUXCLCSS_SFR_FIELD(prefix,sfr,field)        MCUXCLCSS_CONCAT(prefix, sfr ## _ ## field)

/** Helper macros to get the mask and shift values for a specific CSS SFR field */
#define MCUXCLCSS_SFR_FIELD_MASK(sfr, field)         MCUXCLCSS_CONCAT(MCUXCLCSS_SFR_FIELD(CSS_SFR_PREFIX,sfr,field), _MASK)
#define MCUXCLCSS_SFR_FIELD_SHIFT(sfr, field)        MCUXCLCSS_CONCAT(MCUXCLCSS_SFR_FIELD(CSS_SFR_PREFIX,sfr,field), _SHIFT)
#define MCUXCLCSS_SFR_FIELD_FORMAT(sfr, field, val)  (MCUXCLCSS_SFR_FIELD(CSS_SFR_PREFIX,sfr,field) (val))

/**********************************************************/
/* Helper macros for CSS SFR access                       */
/**********************************************************/

/** Read from CSS SFR */
#define MCUXCLCSS_SFR_READ(sfr)  (CSS_SFR_BASE->CSS_SFR_NAME(sfr))

/** Write to CSS SFR */
#define MCUXCLCSS_SFR_WRITE(sfr, value)  \
    do{ CSS_SFR_BASE->CSS_SFR_NAME(sfr) = (value); } while(false)

/** Read from CSS SFR bit field */
#define MCUXCLCSS_SFR_BITREAD(sfr, bit)  \
    ((CSS_SFR_BASE->CSS_SFR_NAME(sfr) & MCUXCLCSS_SFR_FIELD_MASK(sfr, bit)) >> MCUXCLCSS_SFR_FIELD_SHIFT(sfr, bit))

/** Set bit field of CSS SFR (read-modify-write) */
#define MCUXCLCSS_SFR_BITSET(sfr, bit)  \
    do{ CSS_SFR_BASE->CSS_SFR_NAME(sfr) |= MCUXCLCSS_SFR_FIELD_MASK(sfr, bit); } while(false)

/** Clear bit field of CSS SFR (read-modify-write) */
#define MCUXCLCSS_SFR_BITCLEAR(sfr, bit)  \
    do{ CSS_SFR_BASE->CSS_SFR_NAME(sfr) &= (~ (uint32_t) MCUXCLCSS_SFR_FIELD_MASK(sfr, bit)); } while(false)

/** Set value of multi-bit field of CSS SFR (read-modify-write) */
#define MCUXCLCSS_SFR_BITVALSET(sfr, bit, val)  \
    do{ uint32_t temp = CSS_SFR_BASE->CSS_SFR_NAME(sfr) & (~ (uint32_t) MCUXCLCSS_SFR_FIELD_MASK(sfr, bit)); \
        CSS_SFR_BASE->CSS_SFR_NAME(sfr) = ((val) << MCUXCLCSS_SFR_FIELD_SHIFT(sfr, bit)) & MCUXCLCSS_SFR_FIELD_MASK(sfr, bit); \
    } while(false)

/**** ------------------------------ ****/


/** Asserts the correctness of the supplied parameters*/
#define MCUXCLCSS_INPUT_PARAM_CHECK(x) if((x)) { return MCUXCLCSS_STATUS_SW_INVALID_PARAM; }
#define MCUXCLCSS_INPUT_PARAM_CHECK_PROTECTED(funcid, x)                         \
do                                                                              \
{                                                                               \
    if ((x))                                                                    \
    {                                                                           \
        MCUX_CSSL_FP_FUNCTION_EXIT(funcid, MCUXCLCSS_STATUS_SW_INVALID_PARAM);    \
    }                                                                           \
} while (0)

#define CSS_CMD_BIG_ENDIAN ((uint8_t) 0x01U)    ///< CSS command option specifying big-endian byte order
#define CSS_CMD_LITTLE_ENDIAN ((uint8_t) 0x00U) ///< CSS command option specifying little-endian byte order

// Utility code of mcuxClCss implementation

/** Sets the variable-size input buffer from which the input 0 of the CSS operation will be transferred via DMA. */
static inline void mcuxClCss_setInput0(const uint8_t *pInput, uint32_t inputSize)
{
    MCUXCLCSS_SFR_WRITE(CSS_DMA_SRC0,     (uint32_t) pInput);
    MCUXCLCSS_SFR_WRITE(CSS_DMA_SRC0_LEN, inputSize);
}

/** Sets the fixed-size input buffer from which the input 0 of the CSS operation will be transferred via DMA. */
static inline void mcuxClCss_setInput0_fixedSize(const uint8_t *pInput)
{
    MCUXCLCSS_SFR_WRITE(CSS_DMA_SRC0, (uint32_t) pInput);
}

/** Sets the fixed-size input buffer from which the input 1 of the CSS operation will be transferred via DMA. */
static inline void mcuxClCss_setInput1_fixedSize(const uint8_t *pInput)
{
    MCUXCLCSS_SFR_WRITE(CSS_DMA_SRC1, (uint32_t) pInput);
}

/** Sets the variable-size input buffer from which the input 2 of the CSS operation will be transferred via DMA. */
static inline void mcuxClCss_setInput2(const uint8_t *pInput, uint32_t inputSize)
{
    MCUXCLCSS_SFR_WRITE(CSS_DMA_SRC2,     (uint32_t) pInput);
    MCUXCLCSS_SFR_WRITE(CSS_DMA_SRC2_LEN, inputSize);
}

/** Sets the fixed-size input buffer from which the input 2 of the CSS operation will be transferred via DMA. */
static inline void mcuxClCss_setInput2_fixedSize(const uint8_t * pInput)
{
    MCUXCLCSS_SFR_WRITE(CSS_DMA_SRC2, (uint32_t) pInput);
}

/** Sets the variable-size output buffer to which the result of the CSS operation will be transferred via DMA. */
static inline void mcuxClCss_setOutput(uint8_t *pOutput, uint32_t outputSize)
{
    MCUXCLCSS_SFR_WRITE(CSS_DMA_RES0,     (uint32_t) pOutput);
    MCUXCLCSS_SFR_WRITE(CSS_DMA_RES0_LEN, outputSize);
}

/** Sets the output buffer to which the result of the CSS operation will be transferred via DMA. */
static inline void mcuxClCss_setOutput_fixedSize(uint8_t *pOutput)
{
    MCUXCLCSS_SFR_WRITE(CSS_DMA_RES0, (uint32_t) pOutput);
}

/** Sets the CSS keystore index 0, for commands that access a single key. */
static inline void mcuxClCss_setKeystoreIndex0(uint32_t index)
{
    MCUXCLCSS_SFR_WRITE(CSS_KIDX0, index);
}


/** Sets the CSS keystore index 1, for commands that access 2 keys. */
static inline void mcuxClCss_setKeystoreIndex1(uint32_t index)
{
    MCUXCLCSS_SFR_WRITE(CSS_KIDX1, index);
}

#ifdef MCUXCL_FEATURE_CSS_PUK_INTERNAL
/** Sets the CSS keystore index 2, for commands that access 3 keys. */
static inline void mcuxClCss_setKeystoreIndex2(uint32_t index)
{
    MCUXCLCSS_SFR_WRITE(CSS_KIDX2, index);
}
#endif /* MCUXCL_FEATURE_CSS_PUK_INTERNAL */

/** Sets the CSS requested key properties, for commands that create a key. */
static inline void mcuxClCss_setRequestedKeyProperties(uint32_t properties)
{
    MCUXCLCSS_SFR_WRITE(CSS_KPROPIN, properties);
}

/** Starts a CSS command. */
static inline void mcuxClCss_startCommand(uint32_t command, uint32_t cmdcfg0, uint32_t byteOrder)
{
    uint32_t ctrl = MCUXCLCSS_SFR_FIELD_FORMAT(CSS_CTRL, CSS_CMD, command)
                    | MCUXCLCSS_SFR_FIELD_FORMAT(CSS_CTRL, CSS_START, 1u)
                    | MCUXCLCSS_SFR_FIELD_FORMAT(CSS_CTRL, CSS_EN, 1u)
                    | MCUXCLCSS_SFR_FIELD_FORMAT(CSS_CTRL, BYTE_ORDER, byteOrder);

    MCUXCLCSS_SFR_WRITE(CSS_CMDCFG0, cmdcfg0);
    MCUXCLCSS_SFR_WRITE(CSS_CTRL,    ctrl);
}


/** Gets a specific field in the given SFR value, according to the given mask and shift value.
 *  @retval @c value of the requested field in the given CSS SFR value */
static inline uint32_t mcuxClCss_getSfrField(uint32_t sfrValue, uint32_t mask, uint32_t shift)
{
    return ((uint32_t)(sfrValue & mask) >> shift);
}

/** Set a specific field in the given SFR value, according to the given mask and shift value.
  * The unrelated fields/bits will not be changed */
static inline void mcuxClCss_setSfrField(volatile uint32_t *pSfr, uint32_t value, uint32_t mask, uint32_t shift)
{
	/* get the current value of the SFR and clear the bits that will be set */
    uint32_t sfrValue = *pSfr & (~mask);
	/* set the bits and re-write the full value to the SFR */
    *pSfr = sfrValue | (((uint32_t)(value << shift)) & mask);
}

/** Tests if the CSS is in BUSY state.
 *  @retval @c true if the CSS is in BUSY state */
static inline bool mcuxClCss_isBusy(void)
{
    return (0u != MCUXCLCSS_SFR_BITREAD(CSS_STATUS, CSS_BUSY) );
}


/** Macros to access the bit fields for the CSS_STATUS SFR */
#define MCUXCLCSS_SFR_CSS_STATUS_CSS_BUSY            CSS_BUSY
#define MCUXCLCSS_SFR_CSS_STATUS_CSS_IRQ             CSS_IRQ
#define MCUXCLCSS_SFR_CSS_STATUS_CSS_ERR             CSS_ERR
#define MCUXCLCSS_SFR_CSS_STATUS_PRNG_RDY            PRNG_RDY
#define MCUXCLCSS_SFR_CSS_STATUS_ECDSA_VFY_STATUS    ECDSA_VFY_STATUS
#define MCUXCLCSS_SFR_CSS_STATUS_PPROT               CSS_PPROT
#define MCUXCLCSS_SFR_CSS_STATUS_DRBG_ENT_LVL        CSS_DRBG_ENT_LVL
#define MCUXCLCSS_SFR_CSS_STATUS_DTRNG_BUSY          CSS_DTRNG_BUSY
#define MCUXCLCSS_SFR_CSS_STATUS_CSS_LOCKED          CSS_LOCKED

/** Gets a specific field in the CSS_STATUS SFR.
 *  @param field: Any field name in MCUXCLCSS_SFR_CSS_STATUS_* */
#define MCUXCLCSS_GET_STATUS_FIELD(field) \
  mcuxClCss_getSfrField(MCUXCLCSS_SFR_READ(CSS_STATUS), MCUXCLCSS_SFR_FIELD_MASK(CSS_STATUS, field), MCUXCLCSS_SFR_FIELD_SHIFT(CSS_STATUS, field))


/** Macros to access the bit fields for the CSS_CTRL SFR */
#define MCUXCLCSS_SFR_CSS_CTRL_CSS_EN                CSS_EN
#define MCUXCLCSS_SFR_CSS_CTRL_START                 CSS_START
#define MCUXCLCSS_SFR_CSS_CTRL_RESET                 CSS_RESET
#define MCUXCLCSS_SFR_CSS_CTRL_CMD                   CSS_CMD
#define MCUXCLCSS_SFR_CSS_CTRL_BYTE_ORDER            BYTE_ORDER

/** Gets a specific field in the CSS_CTRL SFR.
 *  @param field: Any field name in MCUXCLCSS_SFR_CSS_CTRL_* */
#define MCUXCLCSS_GET_CTRL_FIELD(field) \
  mcuxClCss_getSfrField(MCUXCLCSS_SFR_READ(CSS_CTRL), MCUXCLCSS_SFR_FIELD_MASK(CSS_CTRL, field), MCUXCLCSS_SFR_FIELD_SHIFT(CSS_CTRL, field))

/** Sets a specific field in the CSS_CTRL SFR. The unrelated fields/bits will not be changed
 *  @param field: Any field name in MCUXCLCSS_SFR_CSS_CTRL_*
 *  @param value: The value to set the requested SFR field to */
#define MCUXCLCSS_SET_CTRL_FIELD(field, value) \
  mcuxClCss_setSfrField(&MCUXCLCSS_SFR_READ(CSS_CTRL), (value), MCUXCLCSS_SFR_FIELD_MASK(CSS_CTRL, field), MCUXCLCSS_SFR_FIELD_SHIFT(CSS_CTRL, field))


/** Macros to access the bit fields for the CSS_CFG SFR */
#define MCUXCLCSS_SFR_CSS_CFG_ADCTRL                 ADCTRL
#define MCUXCLCSS_SFR_CSS_CFG_SHA2_DIRECT            SHA2_DIRECT

/** Gets a specific field in the CSS_CFG SFR.
 *  @param field: Any field name in MCUXCLCSS_SFR_CSS_CFG_* */
#define MCUXCLCSS_GET_CFG_FIELD(field) \
  mcuxClCss_getSfrField(MCUXCLCSS_SFR_READ(CSS_CFG), MCUXCLCSS_SFR_FIELD_MASK(CSS_CFG, field), MCUXCLCSS_SFR_FIELD_SHIFT(CSS_CFG, field))

/** Sets a specific field in the CSS_CFG SFR. The unrelated fields/bits will not be changed
 *  @param field: Any field name in MCUXCLCSS_SFR_CSS_CFG_*
 *  @param value: The value to set the requested SFR field to */
#define MCUXCLCSS_SET_CFG_FIELD(field, value) \
  mcuxClCss_setSfrField(&MCUXCLCSS_SFR_READ(CSS_CFG), (value), MCUXCLCSS_SFR_FIELD_MASK(CSS_CFG, field), MCUXCLCSS_SFR_FIELD_SHIFT(CSS_CFG, field))


/** Macros to access the bit fields for the CSS_ERR_STATUS SFR */
#define MCUXCLCSS_SFR_CSS_ERR_STATUS_BUS_ERR         BUS_ERR
#define MCUXCLCSS_SFR_CSS_ERR_STATUS_OPN_ERR         OPN_ERR
#define MCUXCLCSS_SFR_CSS_ERR_STATUS_ALG_ERR         ALG_ERR
#define MCUXCLCSS_SFR_CSS_ERR_STATUS_ITG_ERR         ITG_ERR
#define MCUXCLCSS_SFR_CSS_ERR_STATUS_FLT_ERR         FLT_ERR
#define MCUXCLCSS_SFR_CSS_ERR_STATUS_PRNG_ERR        PRNG_ERR
#define MCUXCLCSS_SFR_CSS_ERR_STATUS_ERR_LVL         ERR_LVL
#define MCUXCLCSS_SFR_CSS_ERR_STATUS_DTRNG_ERR       DTRNG_ERR

/** Gets a specific field in the CSS_ERR_STATUS SFR.
 *  @param field: Any field name in MCUXCLCSS_SFR_CSS_ERR_STATUS_* */
#define MCUXCLCSS_GET_ERROR_STATUS_FIELD(field) \
  mcuxClCss_getSfrField(MCUXCLCSS_SFR_READ(CSS_ERR_STATUS), MCUXCLCSS_SFR_FIELD_MASK(CSS_ERR_STATUS, field), MCUXCLCSS_SFR_FIELD_SHIFT(CSS_ERR_STATUS, field))

/** Checks if a specific error bit in the CSS_ERR_STATUS SFR is set.
 *  @retval @c true if the requested CSS error status bit is set */
#define MCUXCLCSS_IS_ERROR_BIT_SET(field) \
    (1u == MCUXCLCSS_GET_ERROR_STATUS_FIELD(field))


/** Macros to access the bit fields for the CSS_CMDCRC_CTRL SFR */
#define MCUXCLCSS_SFR_CSS_CMDCRC_CTRL_CMDCRC_RST     CMDCRC_RST
#define MCUXCLCSS_SFR_CSS_CMDCRC_CTRL_CMDCRC_EN      CMDCRC_EN

/** Sets a specific field in the CSS_CMDCRC_CTRL SFR. The unrelated fields/bits will not be changed
 *  @param field: Any field name in MCUXCLCSS_SFR_CSS_CMDCRC_CTRL_*
 *  @param value: The value to set the requested SFR field to */
#define MCUXCLCSS_SET_CMDCRC_CTRL_FIELD(field, value) \
  mcuxClCss_setSfrField(&MCUXCLCSS_SFR_READ(CSS_CMDCRC_CTRL), (value), MCUXCLCSS_SFR_FIELD_MASK(CSS_CMDCRC_CTRL, field), MCUXCLCSS_SFR_FIELD_SHIFT(CSS_CMDCRC_CTRL, field))

/** Macros to access the bit fields for the CSS_SHA2_CTRL SFR */
#define MCUXCLCSS_SFR_CSS_SHA2_CTRL_SHA2_START       SHA2_START
#define MCUXCLCSS_SFR_CSS_SHA2_CTRL_SHA2_RST         SHA2_RST
#define MCUXCLCSS_SFR_CSS_SHA2_CTRL_SHA2_INIT        SHA2_INIT
#define MCUXCLCSS_SFR_CSS_SHA2_CTRL_SHA2_LOAD        SHA2_LOAD
#define MCUXCLCSS_SFR_CSS_SHA2_CTRL_SHA2_MODE        SHA2_MODE
#define MCUXCLCSS_SFR_CSS_SHA2_CTRL_SHA2_BYTE_ORDER  SHA2_BYTE_ORDER

/** Gets a specific field in the CSS_SHA2_CTRL SFR.
 *  @param field: Any field name in MCUXCLCSS_SFR_CSS_SHA2_CTRL_* */
#define MCUXCLCSS_GET_SHA2_CTRL_FIELD(field) \
  mcuxClCss_getSfrField(MCUXCLCSS_SFR_READ(CSS_SHA2_CTRL), MCUXCLCSS_SFR_FIELD_MASK(CSS_SHA2_CTRL, field), MCUXCLCSS_SFR_FIELD_SHIFT(CSS_SHA2_CTRL, field))

/** Sets a specific field in the CSS_SHA2_CTRL SFR. The unrelated fields/bits will not be changed
 *  @param field: Any field name in MCUXCLCSS_SFR_CSS_SHA2_CTRL_*
 *  @param value: The value to set the requested SFR field to */
#define MCUXCLCSS_SET_SHA2_CTRL_FIELD(field, value) \
  mcuxClCss_setSfrField(&MCUXCLCSS_SFR_READ(CSS_SHA2_CTRL), (value), MCUXCLCSS_SFR_FIELD_MASK(CSS_SHA2_CTRL, field), MCUXCLCSS_SFR_FIELD_SHIFT(CSS_SHA2_CTRL, field))


/** Macro to access the bit fields for the CSS_SHA2_STATUS SFR */
#define MCUXCLCSS_SFR_CSS_SHA2_STATUS_SHA2_BUSY      SHA2_BUSY

/** Gets a specific field in the CSS_SHA2_STATUS SFR.
 *  @param field: Any field name in MCUXCLCSS_SFR_CSS_SHA2_STATUS_* */
#define MCUXCLCSS_GET_SHA2_STATUS_FIELD(field) \
  mcuxClCss_getSfrField(MCUXCLCSS_SFR_READ(CSS_SHA2_STATUS), MCUXCLCSS_SFR_FIELD_MASK(CSS_SHA2_STATUS, field), MCUXCLCSS_SFR_FIELD_SHIFT(CSS_SHA2_STATUS, field))


/** Macros to access the bit fields for the CSS_INT_ENABLE SFR */
#define MCUXCLCSS_SFR_CSS_INT_ENABLE_INT_EN           INT_EN

/** Gets a specific field in the CSS_INT_ENABLE SFR.
 *  @param field: Any field name in MCUXCLCSS_SFR_CSS_INT_ENABLE_* */
#define MCUXCLCSS_GET_INT_ENABLE_FIELD(field) \
  mcuxClCss_getSfrField(MCUXCLCSS_SFR_READ(CSS_INT_ENABLE), MCUXCLCSS_SFR_FIELD_MASK(CSS_INT_ENABLE, field), MCUXCLCSS_SFR_FIELD_SHIFT(CSS_INT_ENABLE, field))


/* Total buffer size in output, which is used for cache maintenance */
#define MCUXCLCSS_HASH_BUFFER_SIZE(options)  MCUXCLCSS_HASH_BUFFER_SIZE_DIGEST(options) +  MCUXCLCSS_HASH_BUFFER_SIZE_RTF(options)
#define MCUXCLCSS_HASH_BUFFER_SIZE_RTF(options) ( (MCUXCLCSS_HASH_RTF_OUTPUT_ENABLE == options.bits.rtfoe) ? MCUXCLCSS_HASH_RTF_OUTPUT_SIZE : 0u )
#define MCUXCLCSS_HASH_BUFFER_SIZE_DIGEST(options) ( (1u < options.bits.hashmd) ? MCUXCLCSS_HASH_OUTPUT_SIZE_SHA_512 : MCUXCLCSS_HASH_OUTPUT_SIZE_SHA_256 )

#endif /* MCUXCLCSS_INTERNAL_H_ */
