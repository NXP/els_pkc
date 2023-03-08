/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023 NXP                                                  */
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
 * @file  mcuxClEcc_EdDSA_VerifySignature.c
 * @brief implementation of TwEd_EdDsaVerify function
 */


#include <stdint.h>

#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClPkc.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClMath.h>
#include <mcuxClEcc.h>
#include <mcuxClHash.h>

#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClPkc_ImportExport.h>
#include <internal/mcuxClMemory_Copy_Internal.h>
#include <internal/mcuxClKey_Types_Internal.h>
#include <internal/mcuxClKey_Functions_Internal.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClEcc_EdDSA_Internal.h>
#include <internal/mcuxClEcc_Internal_PointComparison_FUP.h>
#include <internal/mcuxClEcc_TwEd_Internal_PointSubtraction_FUP.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_EdDSA_VerifySignature)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_EdDSA_VerifySignature(
    mcuxClSession_Handle_t pSession,
    mcuxClKey_Handle_t key,
    const mcuxClEcc_EdDSA_SignatureProtocolDescriptor_t *mode,
    const uint8_t *pIn,
    uint32_t inSize,
    const uint8_t *pSignature,
    uint32_t signatureSize )
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_EdDSA_VerifySignature);

    /*
     * Step 1: Set up the environment
     */

    /* mcuxClEcc_CpuWa_t will be allocated and placed in the beginning of CPU workarea free space by SetupEnvironment. */
    /* MISRA Ex. 9 to Rule 11.3 - re-interpreting the memory */
    mcuxClEcc_CpuWa_t * const pCpuWorkarea = (mcuxClEcc_CpuWa_t *) mcuxClSession_allocateWords_cpuWa(pSession, 0u);
    mcuxClEcc_EdDSA_DomainParams_t * const pDomainParams = (mcuxClEcc_EdDSA_DomainParams_t *) mcuxClKey_getTypeInfo(key);

    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClEcc_EdDSA_SetupEnvironment(pSession, pDomainParams, ECC_EDDSA_NO_OF_BUFFERS) );

    const uint32_t encodedLen = (uint32_t) pDomainParams->b / 8u;
    const uint32_t sigLength = encodedLen * 2u;
    const uint8_t *pSignatureR = pSignature;
    const uint8_t *pSignatureS = pSignature + encodedLen;

    /*
     * Step 2: Verify that the passed signatureSize value is as expected.
     */

    if (signatureSize != sigLength)
    {
        MCUXCLPKC_FP_DEINITIALIZE(&pCpuWorkarea->pkcStateBackup);
        mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
        mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_VerifySignature, MCUXCLECC_STATUS_INVALID_PARAMS,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_Deinitialize),             /* Clean up */
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_SetupEnvironment) ); /* Step 1 */
    }


    /*
     * Step 3: Import signature component S to buffer ECC_S0 and check if it is smaller than n.
     */

    /* Import S to ECC_S0 */
    MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC(ECC_S0, pSignatureS, encodedLen);

    /* Check s < n. */
    MCUXCLPKC_FP_CALC_OP1_CMP(ECC_S0, ECC_N);
    if (MCUXCLPKC_FLAG_NOCARRY == MCUXCLPKC_WAITFORFINISH_GETCARRY())
    {   /* s >= n. */
        MCUXCLPKC_FP_DEINITIALIZE(&pCpuWorkarea->pkcStateBackup);
        mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
        mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_VerifySignature, MCUXCLECC_STATUS_INVALID_SIGNATURE,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_Deinitialize),             /* Clean up */
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_SetupEnvironment),   /* Step 1 */
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ImportLittleEndianToPkc),  /* Step 3 */
            MCUXCLPKC_FP_CALLED_CALC_OP1_CMP);
    }


    /*
     * Step 4: Calculate P1 = S * G, and store the result in homogeneous coordinates in MR in buffers
     * ECC_COORD00, ECC_COORD01 and ECC_COORD02.
     */
    uint32_t operandSize = MCUXCLPKC_PS1_GETOPLEN();
    uint32_t leadingZeroN = 0u;
    /* mcuxClMath_LeadingZeros always returns _OK. */
    MCUX_CSSL_FP_FUNCTION_CALL_VOID(mcuxClMath_LeadingZeros(ECC_N, &leadingZeroN));
    uint32_t bitLenN = (operandSize * 8u) - leadingZeroN;

    /* Calculate P1 = S * G */
    MCUX_CSSL_FP_FUNCTION_CALL(ret_plainFixScalarMult,
        pDomainParams->common.pPlainFixScalarMultFctFP->pScalarMultFct(
            pSession,
            (mcuxClEcc_CommonDomainParams_t *)&pDomainParams->common,
            ECC_S0,
            bitLenN,
            0));
    if(MCUXCLECC_STATUS_OK != ret_plainFixScalarMult)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_VerifySignature, MCUXCLECC_STATUS_FAULT_ATTACK);
    }


    /*
     * Step 5: Back up the coordinates of P1 in buffers ECC_COORD25, ECC_COORD26 and ECC_COORD27.
     */

    MCUXCLPKC_FP_CALC_OP1_OR_CONST(ECC_COORD25, ECC_COORD00, 0u);
    MCUXCLPKC_FP_CALC_OP1_OR_CONST(ECC_COORD26, ECC_COORD01, 0u);
    MCUXCLPKC_FP_CALC_OP1_OR_CONST(ECC_COORD27, ECC_COORD02, 0u);


    /*
     * Step 6: Derive the hash prefix from the mode parameter and calculate H(prefix||Renc||Qenc||m') mod n
     * and store it in buffer ECC_S0.
     */

    const uint32_t *pHashPrefix = mode->pHashPrefix;
    uint32_t hashPrefixLen = mode->hashPrefixLen;
    uint8_t *pPubKey = mcuxClKey_getKeyData(key);
    const uint8_t *m = pIn;
    uint32_t mLen = inSize;

    /* Initialize hash context */
    mcuxClHash_Context_t pCtx = (mcuxClHash_Context_t) mcuxClSession_allocateWords_cpuWa(pSession, MCUXCLHASH_CONTEXT_SIZE / sizeof(uint32_t));

    MCUX_CSSL_FP_FUNCTION_CALL(ret_CalcHashModN,
        mcuxClEcc_EdDSA_CalcHashModN(
            pSession, pCtx, pDomainParams,
            pHashPrefix, hashPrefixLen,
            pSignatureR,
            (const uint8_t*)pPubKey,
            m, mLen) );
    if (MCUXCLECC_STATUS_OK != ret_CalcHashModN)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_VerifySignature, MCUXCLECC_STATUS_FAULT_ATTACK);
    }

    /* Free the hash context */
    mcuxClSession_freeWords_cpuWa(pSession, MCUXCLHASH_CONTEXT_SIZE / sizeof(uint32_t));


    /*
     * Step 7: Call function pDomainParams->pDecodePointFct to decode the public key Qenc and store
     * the homogeneous coordinates of the decoded point Q in buffers ECC_COORD00, ECC_COORD01 and ECC_COORD02.
     */

    MCUX_CSSL_FP_FUNCTION_CALL(ret_decodePoint,
        pDomainParams->pDecodePointFct(
            pDomainParams,
            (const uint8_t*)pPubKey) );
    if(MCUXCLECC_STATUS_INVALID_PARAMS == ret_decodePoint)
    {
        MCUXCLPKC_FP_DEINITIALIZE(&pCpuWorkarea->pkcStateBackup);
        mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
        mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_VerifySignature, MCUXCLECC_STATUS_INVALID_PARAMS,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_Deinitialize),             /* Clean up */
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_SetupEnvironment),   /* Step 1 */
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ImportLittleEndianToPkc),  /* Step 3 */
            MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_LeadingZeros),            /* Step 4 */
            pDomainParams->common.pPlainFixScalarMultFctFP->scalarMultFct_FP_FuncId,
            3u * MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST,                      /* Step 5 */
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_CalcHashModN),       /* Step 6 */
            pDomainParams->pDecodePoint_FP_FuncId);                         /* Step 7 */
    }
    else if(MCUXCLECC_STATUS_OK != ret_decodePoint)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_VerifySignature, MCUXCLECC_STATUS_FAULT_ATTACK);
    }
    else
    {
        /* Intentionally left empty */
    }


    /*
     * Step 8: Call function pDomainParameters->pPlainVarScalarMultFct to calculate
     * P2 = (H(prefix||Renc||Qenc||m') mod n)*Q and store the result in homogeneous coordinates in MR
     * in buffers ECC_COORD00, ECC_COORD01 and ECC_COORD02.
     */

    MCUX_CSSL_FP_FUNCTION_CALL(ret_plainVarScalarMult,
        pDomainParams->common.pPlainVarScalarMultFctFP->pScalarMultFct(
            pSession,
            &pDomainParams->common,
            ECC_S0,
            bitLenN,
            0));
    if(MCUXCLECC_STATUS_OK != ret_plainVarScalarMult)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_VerifySignature, MCUXCLECC_STATUS_FAULT_ATTACK);
    }


    /*
     * Step 9: Calculate R' = P1-P2 and store the homogeneous coordinates of R' in ECC_COORD00, ECC_COORD01 and ECC_COORD02.
     */

    MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_TwEd_PointSubtraction,
                        mcuxClEcc_FUP_TwEd_PointSubtraction_LEN);


    /*
     * Step 10: Derive the encoding (R')enc of R' and store it in ECC_COORD03.
     */
    MCUXCLPKC_WAITFORREADY();                                              /* TODO: PS2 length is not used in the above FUP, but this is required due to unknown reason (CLNS-7276) */
    uint32_t encodedLenPkc = MCUXCLPKC_ROUNDUP_SIZE(encodedLen);
    MCUXCLPKC_PS2_SETLENGTH(0u, encodedLenPkc);
    MCUXCLPKC_FP_CALC_OP2_CONST(ECC_COORD03, 0u);                          /* Clear encodedLenPkc bytes of buffer ECC_COORD03 */
    MCUXCLPKC_FP_CALC_OP1_OR_CONST(ECC_COORD03, ECC_COORD01, 0u);          /* Copy operandSize < encodedLenPkc bytes of the y-coordinate from ECC_COORD01 to ECC_COORD03 */
    uint16_t *pOperands = MCUXCLPKC_GETUPTRT();
    /* MISRA Ex. 9 to Rule 11.3 - pOperands is 32-bit aligned */
    uint32_t *pRX = (uint32_t*)MCUXCLPKC_OFFSET2PTR(pOperands[ECC_COORD00]);
    uint8_t *pREncLastByte = &MCUXCLPKC_OFFSET2PTR(pOperands[ECC_COORD03])[encodedLen - 1u];
    MCUXCLPKC_WAITFORFINISH();
    uint32_t lsbX = (*pRX) & (uint32_t)0x01u;                             /* Loading a word is usually cheaper than loading a byte */
    *pREncLastByte |= ((uint8_t)lsbX << 7u);

    /*
     * Step 11: Import the signature component Renc and compare it against (R')enc.
     */

    /* Import Renc to ECC_S0 */
    MCUXCLPKC_FP_IMPORTLITTLEENDIANTOPKC(ECC_S0, pSignature, encodedLen);

    /* Compare ECC_S0 against ECC_COORD03 */
    MCUXCLPKC_FP_CALC_OP1_CMP(ECC_S0, ECC_COORD03);


    /*
     * Step 12: If (R')enc != Renc, then compare if h*R' and h*R are equal points
     */

    uint32_t zeroFlag_check = MCUXCLPKC_WAITFORFINISH_GETZERO();
    MCUX_CSSL_FP_BRANCH_DECL(RencNotEqual);
    if (MCUXCLPKC_FLAG_ZERO != zeroFlag_check)
    {
        /*
        * Step 12a: Call function pDomainParameters->pPlainVarScalarMultFct to calculate h*R' and store the result in
        * homogeneous coordinates in MR in buffers ECC_COORD00, ECC_COORD01 and ECC_COORD02.
        */

        /* Compute h and store it in ECC_S1 */
        const uint8_t h = (uint8_t) (1u << ((uint32_t) pDomainParams->c & 0x1Fu));      /* c = cofactor exponent, i.e. cofactor: h = 2^c */
        uint8_t *pS1 = MCUXCLPKC_OFFSET2PTR(pOperands[ECC_S1]);
        pS1[0] = h;
        uint32_t bitLenH = (uint32_t)pDomainParams->c + (uint32_t)1u;

        /* Compute h*R' */
        MCUX_CSSL_FP_FUNCTION_CALL(ret2_plainVarScalarMult,
        pDomainParams->common.pPlainVarScalarMultFctFP->pScalarMultFct(
            pSession,
            &pDomainParams->common,
            ECC_S1,
            bitLenH,
            0));
        if(MCUXCLECC_STATUS_OK != ret2_plainVarScalarMult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_VerifySignature, MCUXCLECC_STATUS_FAULT_ATTACK);
        }


        /*
        * Step 12b: Back up the coordinates of h*R' in buffers ECC_COORD25, ECC_COORD26 and ECC_COORD27.
        */

        MCUXCLPKC_FP_CALC_OP1_OR_CONST(ECC_COORD25, ECC_COORD00, 0u);
        MCUXCLPKC_FP_CALC_OP1_OR_CONST(ECC_COORD26, ECC_COORD01, 0u);
        MCUXCLPKC_FP_CALC_OP1_OR_CONST(ECC_COORD27, ECC_COORD02, 0u);


        /*
        * Step 12c: Call function pDomainParams->pDecodePointFct to decode Renc and store the homogeneous coordinates of
        * the decoded point R in buffers ECC_COORD00, ECC_COORD01 and ECC_COORD02. If the decoding fails, return #MCUXCLECC_STATUS_INVALID_SIGNATURE.
        */

        MCUX_CSSL_FP_FUNCTION_CALL(ret2_decodePoint,
        pDomainParams->pDecodePointFct(
            pDomainParams,
            pSignature) );
        if(MCUXCLECC_STATUS_INVALID_PARAMS == ret2_decodePoint)
        {
            MCUXCLPKC_FP_DEINITIALIZE(&pCpuWorkarea->pkcStateBackup);
            mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
            mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_VerifySignature, MCUXCLECC_STATUS_INVALID_PARAMS,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_Deinitialize),             /* Clean up */
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_SetupEnvironment),   /* Step 1 */
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ImportLittleEndianToPkc),  /* Step 3 */
                MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_LeadingZeros),            /* Step 4 */
                pDomainParams->common.pPlainFixScalarMultFctFP->scalarMultFct_FP_FuncId,
                3u * MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST,                      /* Step 5 */
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_CalcHashModN),       /* Step 6 */
                pDomainParams->pDecodePoint_FP_FuncId,                          /* Step 7 */
                pDomainParams->common.pPlainVarScalarMultFctFP->scalarMultFct_FP_FuncId, /* Step 8 */
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),                  /* Step 9 */
                MCUXCLPKC_FP_CALLED_CALC_OP2_CONST,                              /* Step 10 */
                MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ImportLittleEndianToPkc),  /* Step 11 */
                MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,
                pDomainParams->common.pPlainVarScalarMultFctFP->scalarMultFct_FP_FuncId, /* Step 12a */
                3u * MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST,                      /* Step 12b */
                pDomainParams->pDecodePoint_FP_FuncId);                         /* Step 12c */
        }
        else if(MCUXCLECC_STATUS_OK != ret2_decodePoint)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_VerifySignature, MCUXCLECC_STATUS_FAULT_ATTACK);
        }
        else
        {
            /* Intentionally left empty */
        }


        /*
        * Step 12d: Call function pDomainParameters->pPlainVarScalarMultFct to calculate h*R and store the result in
        * homogeneous coordinates in MR in buffers ECC_COORD00, ECC_COORD01 and ECC_COORD02.
        */

        MCUX_CSSL_FP_FUNCTION_CALL(ret3_plainVarScalarMult,
        pDomainParams->common.pPlainVarScalarMultFctFP->pScalarMultFct(
            pSession,
            &pDomainParams->common,
            ECC_S1,
            bitLenH,
            0));
        if(MCUXCLECC_STATUS_OK != ret3_plainVarScalarMult)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_VerifySignature, MCUXCLECC_STATUS_FAULT_ATTACK);
        }


        /*
        * Step 12e: Bring h*R' and h*R to the same Z-coordinate and compare the coordinates.
        * If the points are not equal, return #MCUXCLECC_STATUS_INVALID_SIGNATURE.
        */
        pOperands[ECC_V0] = pOperands[ECC_COORD25];
        pOperands[ECC_V1] = pOperands[ECC_COORD26];
        pOperands[ECC_V2] = pOperands[ECC_COORD27];
        MCUXCLPKC_FP_CALCFUP(mcuxClEcc_FUP_PointComparisonHom,
                            mcuxClEcc_FUP_PointComparisonHom_LEN);

        /* The last result is only zero if and only if R'=R */
        if (MCUXCLPKC_FLAG_ZERO != MCUXCLPKC_WAITFORFINISH_GETZERO())
        {
            MCUXCLPKC_FP_DEINITIALIZE(&pCpuWorkarea->pkcStateBackup);
            mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
            mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_EdDSA_VerifySignature, MCUXCLECC_STATUS_INVALID_SIGNATURE,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_Deinitialize),             /* Clean up */
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_SetupEnvironment),   /* Step 1 */
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ImportLittleEndianToPkc),  /* Step 3 */
                MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_LeadingZeros),            /* Step 4 */
                pDomainParams->common.pPlainFixScalarMultFctFP->scalarMultFct_FP_FuncId,
                3u * MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST,                      /* Step 5 */
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_CalcHashModN),       /* Step 6 */
                pDomainParams->pDecodePoint_FP_FuncId,                          /* Step 7 */
                pDomainParams->common.pPlainVarScalarMultFctFP->scalarMultFct_FP_FuncId, /* Step 8 */
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),                  /* Step 9 */
                MCUXCLPKC_FP_CALLED_CALC_OP2_CONST,                              /* Step 10 */
                MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST,
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ImportLittleEndianToPkc),  /* Step 11 */
                MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,
                pDomainParams->common.pPlainVarScalarMultFctFP->scalarMultFct_FP_FuncId, /* Step 12a */
                3u * MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST,                      /* Step 12b */
                pDomainParams->pDecodePoint_FP_FuncId,                          /* Step 12c */
                pDomainParams->common.pPlainVarScalarMultFctFP->scalarMultFct_FP_FuncId, /* Step 12d */
                MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup));                 /* Step 12e */
        }

        MCUX_CSSL_FP_BRANCH_POSITIVE(RencNotEqual,
            /* Step 12a */
            pDomainParams->common.pPlainVarScalarMultFctFP->scalarMultFct_FP_FuncId,
            /* Step 12b */
            3u * MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST,
            /* Step 12c */
            pDomainParams->pDecodePoint_FP_FuncId,
            /* Step 12d */
            pDomainParams->common.pPlainVarScalarMultFctFP->scalarMultFct_FP_FuncId,
            /* Step 12e */
            MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup) );
    }

    /*
     * Step 13: Return #MCUXCLECC_STATUS_OK.
     */

    /* Clean up and exit */
    MCUXCLPKC_FP_DEINITIALIZE(&pCpuWorkarea->pkcStateBackup);
    mcuxClSession_freeWords_pkcWa(pSession, pCpuWorkarea->wordNumPkcWa);
    mcuxClSession_freeWords_cpuWa(pSession, pCpuWorkarea->wordNumCpuWa);

    MCUX_CSSL_FP_FUNCTION_EXIT_WITH_CHECK(mcuxClEcc_EdDSA_VerifySignature, MCUXCLECC_STATUS_OK, MCUXCLECC_STATUS_FAULT_ATTACK,
        /* Step 1 */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_SetupEnvironment),
        /* Step 3 */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ImportLittleEndianToPkc),
        MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,
        /* Step 4 */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMath_LeadingZeros),
        pDomainParams->common.pPlainFixScalarMultFctFP->scalarMultFct_FP_FuncId,
        /* Step 5 */
        3u * MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST,
        /* Step 6 */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_EdDSA_CalcHashModN),
        /* Step 7 */
        pDomainParams->pDecodePoint_FP_FuncId,
        /* Step 8 */
        pDomainParams->common.pPlainVarScalarMultFctFP->scalarMultFct_FP_FuncId,
        /* Step 9 */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_CalcFup),
        /* Step 10 */
        MCUXCLPKC_FP_CALLED_CALC_OP2_CONST,
        MCUXCLPKC_FP_CALLED_CALC_OP1_OR_CONST,
        /* Step 11 */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_ImportLittleEndianToPkc),
        MCUXCLPKC_FP_CALLED_CALC_OP1_CMP,
        /* Step 12 */
        MCUX_CSSL_FP_BRANCH_TAKEN_POSITIVE(RencNotEqual, MCUXCLPKC_FLAG_ZERO != zeroFlag_check),
        /* Step 13 */
        MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_Deinitialize) );
}
