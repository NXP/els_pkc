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

/** @file  mcuxClOsccaSm3_SfrAccess.h
 *  @brief Provide macros for mcuxClOsccaSm3 internal use.
 * This header declares internal macros to deduplicate code and support for internal use only. */

#ifndef MCUXCLOSCCASM3_SFRACCESS_H_
#define MCUXCLOSCCASM3_SFRACCESS_H_

#include <mcuxClConfig.h> // Exported features flags header
#include <platform_specific_headers.h>
#include <stdint.h>
#include <stdbool.h>


/****                                     ****/
/**** SAFO SM3 Hardware Abstraction Layer ****/
/****                                     ****/

/**
 * Definitions for accessing SAFO SM3 SFRs via, e.g., ID_SAFO_SGI->STATUS.
 */

/** Helper macros for constructing SFR field name constants */
#define MCUXCLOSCCASM3_SAFO_SGI_PASTE(a,b)  a ## b
#define MCUXCLOSCCASM3_SAFO_SGI_CONCAT(a,b) MCUXCLOSCCASM3_SAFO_SGI_PASTE(a,b)
#define MCUXCLOSCCASM3_SAFO_SGI_SFR_FIELD(prefix,sfr,field)        MCUXCLOSCCASM3_SAFO_SGI_CONCAT(prefix, sfr ## _ ## field)

/** Helper macros to get the mask and shift values for a specific SAFO SM3 SFR field */
#define MCUXCLOSCCASM3_SAFO_SGI_SFR_FIELD_MASK(sfr, field)         MCUXCLOSCCASM3_SAFO_SGI_CONCAT(MCUXCLOSCCASM3_SAFO_SGI_SFR_FIELD(SAFO_SFR_PREFIX,sfr,field), _MASK)
#define MCUXCLOSCCASM3_SAFO_SGI_SFR_FIELD_SHIFT(sfr, field)        MCUXCLOSCCASM3_SAFO_SGI_CONCAT(MCUXCLOSCCASM3_SAFO_SGI_SFR_FIELD(SAFO_SFR_PREFIX,sfr,field), _SHIFT)
#define MCUXCLOSCCASM3_SAFO_SGI_SFR_FIELD_FORMAT(sfr, field, val)  (MCUXCLOSCCASM3_SAFO_SGI_SFR_FIELD(SAFO_SFR_PREFIX,sfr,field) (val))

/**********************************************************/
/* Helper macros for SAFO SM3 SFR access                  */
/**********************************************************/

/** Read from SAFO SM3 SFR */
#define MCUXCLOSCCASM3_SAFO_SGI_SFR_READ(sfr)  (SAFO_SFR_BASE->SAFO_SFR_NAME(sfr))

/** Write to SAFO SM3 SFR */
#define MCUXCLOSCCASM3_SAFO_SGI_SFR_WRITE(sfr, value)  \
    do{ SAFO_SFR_BASE->SAFO_SFR_NAME(sfr) = (value); } while(false)

/** Read from SAFO SM3 SFR bit field */
#define MCUXCLOSCCASM3_SAFO_SGI_SFR_BITREAD(sfr, bit)  \
    ((SAFO_SFR_BASE->SAFO_SFR_NAME(sfr) & MCUXCLOSCCASM3_SAFO_SGI_SFR_FIELD_MASK(SAFO_SFR_NAME(sfr), bit)) >> MCUXCLOSCCASM3_SAFO_SGI_SFR_FIELD_SHIFT(SAFO_SFR_NAME(sfr), bit))

/** Set bit field of SAFO SM3 SFR (read-modify-write) */
#define MCUXCLOSCCASM3_SAFO_SGI_SFR_BITSET(sfr, bit)  \
    do{ SAFO_SFR_BASE->SAFO_SFR_NAME(sfr) |= MCUXCLOSCCASM3_SAFO_SGI_SFR_FIELD_MASK(SAFO_SFR_NAME(sfr), bit); } while(false)

/** Clear bit field of SAFO SM3 SFR (read-modify-write) */
#define MCUXCLOSCCASM3_SAFO_SGI_SFR_BITCLEAR(sfr, bit)  \
    do{ SAFO_SFR_BASE->SAFO_SFR_NAME(sfr) &= (~ (uint32_t) MCUXCLOSCCASM3_SAFO_SGI_SFR_FIELD_MASK(SAFO_SFR_NAME(sfr), bit)); } while(false)

/** Set value of multi-bit field of SAFO SM3 SFR (read-modify-write) */
#define MCUXCLOSCCASM3_SAFO_SGI_SFR_BITVALSET(sfr, bit, val)  \
    do{ uint32_t temp = SAFO_SFR_BASE->SAFO_SFR_NAME(sfr) & (~ (uint32_t) MCUXCLOSCCASM3_SAFO_SGI_SFR_FIELD_MASK(SAFO_SFR_NAME(sfr), bit)); \
        SAFO_SFR_BASE->SAFO_SFR_NAME(sfr) = ((val) << MCUXCLOSCCASM3_SAFO_SGI_SFR_FIELD_SHIFT(SAFO_SFR_NAME(sfr), bit)) & MCUXCLOSCCASM3_SAFO_SGI_SFR_FIELD_MASK(SAFO_SFR_NAME(sfr), bit); \
    } while(false)

/**** ------------------------------ ****/


// Utility code of mcuxClOsccaSm3 implementation
/** Set a specific field in the given SFR value, according to the given mask and shift value.
  * The unrelated fields/bits will not be changed */
static inline void mcuxClOsccaSm3_setSfrField(volatile uint32_t *pSfr, uint32_t value, uint32_t mask, uint32_t shift)
{
    /* get the current value of the SFR and clear the bits that will be set */
    uint32_t sfrValue = *pSfr & (~mask);
    /* set the bits and re-write the full value to the SFR */
    *pSfr = sfrValue | (((uint32_t)(value << shift)) & mask);
}

/** Sets SAFO_SGI_SM3_FIFO input buffer from the input value*/
#define MCUXCLOSCCASM3_SET_FIFO_FIELD(value)\
    mcuxClOsccaSm3_setSfrField((uint32_t *)&MCUXCLOSCCASM3_SAFO_SGI_SFR_READ(SM3_FIFO), (value), MCUXCLOSCCASM3_SAFO_SGI_SFR_FIELD_MASK(SAFO_SGI_SM3_FIFO, FIFO), MCUXCLOSCCASM3_SAFO_SGI_SFR_FIELD_SHIFT(SAFO_SGI_SM3_FIFO, FIFO))

#endif /* MCUXCLOSCCASM3_SFRACCESS_H_ */
