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
 * @file  mcuxClEcc_WeierECC.h
 * @brief header of mcuxClEcc functionalities related to ECC protocols based on (short) Weierstrass curves
 */


#ifndef MCUXCLECC_WEIERECC_H_
#define MCUXCLECC_WEIERECC_H_


#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxClSession.h>
#include <mcuxClKey.h>
#include <mcuxClEcc_Types.h>


/**
 * @brief Structure to pass custom domain parameters for (short) Weierstrass curves with cofactor 1.
 */
typedef struct {
    const uint8_t *pP;
    uint32_t pLen;
    const uint8_t *pA;
    const uint8_t *pB;
    const uint8_t *pG;
    const uint8_t *pN;
    uint32_t nLen;
} mcuxClEcc_Weier_Params_t;

typedef uint32_t mcuxClEcc_Weier_ParamsOptimized_t;


/**
 * @brief ECC Weierstrass custom domain parameter generation function.
 *
 * Given pointers and lengths specifying domain parameters of a custom (short) Weierstrass curve with cofactor 1,
 * this function generates a corresponding optimized custom domain parameter struct.
 *
 * @param      pSession                  Handle for the current CL session.
 * @param[out] pEccWeierParamsOptimized  Pointer to memory area in which the optimized domain parameters shall be stored.
 * @param[in]  pEccWeierParams           Pointer to struct containing pointers and lengths specifying the custom domain parameters.
 * @param[in]  options                   Parameter specifying whether or not the pre-computed point (2 ^ (byteLenN * 4)) * G corresponding to
 *                                       the base point G shall be calculated or not, If set to
 *                                         - MCUXCLECC_OPTION_GENERATEPRECPOINT_YES, the pre-computed point will be calculated
 *                                         - MCUXCLECC_OPTION_GENERATEPRECPOINT_NO,  the pre-computed point will not be calculated
 *
 * @attention the generated optimized domain parameter cannot be copied or moved,
 *            but shall be used in the original memory address where it is generated.
 *
 * @return A code-flow protected error code (see @ref MCUXCLECC_STATUS_)
 * @retval #MCUXCLECC_STATUS_OK              if optimized domain parameter is generated successfully;
 * @retval #MCUXCLECC_STATUS_INVALID_PARAMS  if parameters are invalid;
 * @retval #MCUXCLECC_STATUS_FAULT_ATTACK    if fault attack (unexpected behavior) is detected.
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_WeierECC_GenerateDomainParams)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_WeierECC_GenerateDomainParams(
    mcuxClSession_Handle_t pSession,
    mcuxClEcc_Weier_ParamsOptimized_t *pEccWeierParamsOptimized,
    mcuxClEcc_Weier_Params_t *pEccWeierParams,
    uint32_t options
    );

#define MCUXCLECC_OPTION_GENERATEPRECPOINT_YES     (0x00000001u)
#define MCUXCLECC_OPTION_GENERATEPRECPOINT_NO      (0x00000002u)
#define MCUXCLECC_OPTION_GENERATEPRECPOINT_MASK    (MCUXCLECC_OPTION_GENERATEPRECPOINT_YES | MCUXCLECC_OPTION_GENERATEPRECPOINT_NO)
#define MCUXCLECC_OPTION_GENERATEPRECPOINT_OFFSET  0u


/**
 * @brief Key type constructor.
 * @api
 *
 * This function allows to generate custom key types according to the passed \p algoId.
 *
 * @param[out] customType     Handle for the custom key type.
 * @param[in]  algoId         Algorithm identifier specifying the key type descriptor to be generated. The supported algoIds are
 *                             - MCUX_CL_KEY_ALGO_ID_ECC_SHWS_GFP_EPHEMERAL_CUSTOM | MCUX_CL_KEY_ALGO_ID_PUBLIC_KEY
 *                             - MCUX_CL_KEY_ALGO_ID_ECC_SHWS_GFP_EPHEMERAL_CUSTOM | MCUX_CL_KEY_ALGO_ID_PRIVATE_KEY
 *                             - MCUX_CL_KEY_ALGO_ID_ECC_SHWS_GFP_EPHEMERAL_CUSTOM | MCUX_CL_KEY_ALGO_ID_KEY_PAIR
 *                             - MCUX_CL_KEY_ALGO_ID_ECC_SHWS_GFP_STATIC_CUSTOM | MCUX_CL_KEY_ALGO_ID_PUBLIC_KEY
 *                             - MCUX_CL_KEY_ALGO_ID_ECC_SHWS_GFP_STATIC_CUSTOM | MCUX_CL_KEY_ALGO_ID_PRIVATE_KEY
 *                             - MCUX_CL_KEY_ALGO_ID_ECC_SHWS_GFP_STATIC_CUSTOM | MCUX_CL_KEY_ALGO_ID_KEY_PAIR
 *                            All other values will trigger an error.
 * @param[in]  size           Algorithm based key size.
 * @param[in]  pCustomParams  Pointer to algorithm based custom parameters. If algoId & MCUX_CL_KEY_ALGO_ID_ALGO_MASK equals
 *                             - MCUX_CL_KEY_ALGO_ID_ECC_SHWS_GFP_EPHEMERAL_CUSTOM, a pointer to an mcuxClEcc_Weier_Params_t struct
 *                                                                                 specifying custom ECC Weierstrass domain parameters
 *                               TODO: Is this approach ok? The CL user would need to keep the mcuxClEcc_Weier_Params_t available for the lifetime of the key
 *                             - MCUX_CL_KEY_ALGO_ID_ECC_SHWS_GFP_STATIC_CUSTOM, a pointer to an mcuxClEcc_Weier_ParamsOptimized_t struct
 *                                                                              specifying optimized custom ECC Weierstrass domain parameters
 *                            In all other cases, the pointer shall be set to NULL
 * @return status
 * @retval #MCUXCLECC_STATUS_OK              if custom key type is generated successfully;
 * @retval #MCUXCLECC_STATUS_INVALID_PARAMS  if Parameters are invalid..
 */
MCUX_CSSL_FP_FUNCTION_DECL(mcuxClEcc_WeierECC_GenerateCustomKeyType)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClEcc_WeierECC_GenerateCustomKeyType(
    mcuxClKey_CustomType_t customType,
    mcuxClKey_AlgorithmId_t algoId,
    mcuxClKey_Size_t size,
    void *pCustomParams
    );


#endif /* MCUXCLECC_WEIERECC_H_ */
