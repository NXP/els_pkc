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

/**
 * @file  mcuxClEcc_Internal_RecodeAndReorderScalar.c
 * @brief mcuxClEcc: implementation of mcuxClEcc_RecodeAndReorderScalar
 */


#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClPkc.h>
#include <mcuxClMath.h>

#include <mcuxClEcc.h>

#include <internal/mcuxClMath_Internal_Utils.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClEcc_Internal.h>
#include <internal/mcuxClEcc_Internal_UPTRT_access.h>
#include <internal/mcuxClEcc_Internal_Interleave_FUP.h>


/**
 * This function recodes an odd, potentially secret, scalar lambda = (lambda_{f*K-1},...,lambda_0)_2 of (not necessarily exact) bit length f*K,
 * into non-zero BSD representation by rotating it right by one bit to obtain
 *
 *      lambda~ = (lambda~_{f*K-1},...,lambda~_0)_2 = (lambda_{f*K-1},...,lambda_0)_2.
 *
 * Further, it reorders the bits of lambda~ for usage within the comb method by splitting it into f parts and interleaving them to obtain
 *
 *      lambda' = (lambda~_{f*K-1}, lambda~_{(f-1)*K-1},...,lambda~_{K-1},...,lambda~_{(f-1)*K},lambda~_{(f-2)*K},...,lambda~_0)_2
 *
 * Input:
 *   - pSession         Handle for the current CL session
 *   - scalarIndex      Table index of buffer storing the scalar lambda to be blinded
 *   - f                Number of parts into which the scalar will be divided; must be a power of two
 *   - scalarBitLength  scalar length in bits, must be a multiple of f.
 *
 * Prerequisites:
 *   - ps1Len = (operandSize, operandSize)
 *
 * Result:
 *   - The recoded and reordered scalar lambda' is contained in the buffer with table index scalarIndex.
 *
 * Other modifications:
 *   - Buffers ECC_T0 and ECC_T1 are modified (as temp).
 *   - Offsets pOperands[ECC_V0/ECC_V1/ECC_V3] are modified.
 *   - ps2 LEN and MCLEN are modified.
 *
 * @attention The PKC calculation might be still on-going, call #mcuxClPkc_WaitForFinish before CPU accesses to the result.
 */
MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_RecodeAndReorderScalar)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_RecodeAndReorderScalar(mcuxClSession_Handle_t pSession,
                                                                        uint8_t scalarIndex,
                                                                        uint8_t f,
                                                                        uint32_t scalarBitLength)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_RecodeAndReorderScalar);

    uint32_t ps1LenRegBackup = MCUXCLPKC_PS1_GETLENGTH_REG();
    uint16_t *pOperands = MCUXCLPKC_GETUPTRT();
    uint32_t *pOperands32 = (uint32_t *) pOperands;  /* MISRA Ex. 9 to Rule 11.3 - UPTR table is 32-bit aligned in ECC component. */

    uint32_t bitLenHalfScalar = scalarBitLength - (scalarBitLength >> 1);  /* ceil(bitLen / 2) */
    uint32_t byteLenHalfScalarPkcAligned = ((bitLenHalfScalar + (MCUXCLPKC_WORDSIZE * 8u) - 1u) / (MCUXCLPKC_WORDSIZE * 8u)) * MCUXCLPKC_WORDSIZE;

    /* Step 1:
     * Set the pointer in ECC_V0 to the buffer corresponding to scalarIndex.
     * Also, initialize ECC_V1 (to pointer to upper scalar half) and ECC_V3 (to shift amount) for the invocation of mcuxClEcc_FUP_Interleave.
     */
    uint32_t offsets_V1_V0 = /* V0 */ (uint32_t) pOperands[scalarIndex]
                             /* V1 */ + (((uint32_t) pOperands[ECC_T0] + byteLenHalfScalarPkcAligned) << 16);
    MCUXCLPKC_WAITFORREADY();
    /* MISRA Ex. 9 to Rule 11.3 - pOperands32 is pointer to 16-bit offset table */
    MCUXCLECC_STORE_2OFFSETS(pOperands32, ECC_V0, ECC_V1, offsets_V1_V0);
    pOperands[ECC_V3] = (uint16_t) (0u - bitLenHalfScalar);  /* PKC will ignore higher bits of shifting amount. */

    /* Steps 2:
     * Use PKC to rotate the buffer ECC_V0 to the right by one bit.
     */
    MCUXCLPKC_FP_CALC_OP1_ROTR(ECC_V0, ECC_V0, 1u);

    /* Step 3:
     * Use the PKC to move the MSBit of the buffer to bit position f*K-1 of the buffer ECC_V0. The buffer now contains lambda~.
     */
    // TODO: Moving the MSBit still to be done (but not necessary for Ed25519 and Ed448) -> CLNS-6486

    /* Step 4:
     * Switch the PKC to GF(2) mode and prepare operand sizes for mcuxClEcc_FUP_Interleave.
     */
    MCUXCLPKC_ENABLEGF2();
    MCUXCLPKC_PS1_SETLENGTH(0u, 2u * byteLenHalfScalarPkcAligned);
    MCUXCLPKC_PS2_SETLENGTH(byteLenHalfScalarPkcAligned, byteLenHalfScalarPkcAligned);

    /* Step 5:
     * Successively ( log_2(f) times ) do the following:
     *   - Shift upper half of the f*K bit value in ECC_V0 to the next FAME word boundary
     *   - Use PKC to square lower and upper half of the value in ECC_V0 and store the results in ECC_T0 and ECC_T1, respectively
     *   - Left shift ECC_T1 by one bit
     *   - Set ECC_V0 = ECC_T0 | ECC_T1
     *
     * This is all done by mcuxClEcc_FUP_Interleave.
     */
    uint32_t fLog = 32u - mcuxClMath_CountLeadingZerosWord((uint32_t) f) - 1u;
    for(uint32_t i = fLog; i > 0u ; i--)
    {
        MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_Interleave, mcuxClEcc_FUP_Interleave_LEN);
    }

    /* Step 6:
     * Switch the PKC to GF(p) mode.
     */
    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_DISABLEGF2();
    MCUXCLPKC_PS1_SETLENGTH_REG(ps1LenRegBackup);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_RecodeAndReorderScalar, MCUXCLECC_STATUS_OK,
        MCUXCLPKC_FP_CALLED_CALC_OP1_ROTR,
        fLog * MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup));
}
