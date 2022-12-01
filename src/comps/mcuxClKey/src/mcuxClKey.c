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

/** @file  mcuxClKey.c
 *  @brief Implementation of the Key component to deal with keys used by
 *  higher-level components. This file implements the functions declared in
 *  mcuxClKey.h. */

#include <mcuxClKey.h>
#include <mcuxClCss.h>
#include <mcuxClMemory.h>
#include <toolchain.h>
#include <internal/mcuxClKey_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_init)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_init(
    mcuxClSession_Handle_t pSession UNUSED_PARAM,
    mcuxClKey_Handle_t key,
    mcuxClKey_Type_t type,
    mcuxCl_Buffer_t pKeyData,
    uint32_t keyDataLength
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClKey_init);

    /* Fill key structure */
    mcuxClKey_setTypeDescriptor(key, *type);
    mcuxClKey_setProtectionType(key, mcuxClKey_Protection_None);
    mcuxClKey_setKeyData(key, pKeyData);
    mcuxClKey_setKeyContainerSize(key, keyDataLength);
    mcuxClKey_setKeyContainerUsedSize(key, keyDataLength);
    mcuxClKey_setLoadStatus(key, MCUX_CL_KEY_LOADSTATUS_NOTLOADED);

    /* Check if this is a variable-length external HMAC key */
    if(0u == type->size)
    {
        /* Overwrite the type's size with the given one */
        key->type.size = keyDataLength;
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_init, MCUX_CL_KEY_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_setProtection)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_setProtection(
    mcuxClSession_Handle_t pSession UNUSED_PARAM,
    mcuxClKey_Handle_t key,
    mcuxClKey_Protection_t protection,
    mcuxCl_Buffer_t pAuxData,
    mcuxClKey_Handle_t parentKey
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClKey_setProtection);

    /* Fill key structure */
    mcuxClKey_setProtectionType(key, protection);
    mcuxClKey_setAuxData(key, (uint8_t *) pAuxData);
    mcuxClKey_setParentKey(key, parentKey);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_setProtection, MCUX_CL_KEY_STATUS_OK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_loadMemory)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_loadMemory(
    mcuxClSession_Handle_t pSession UNUSED_PARAM,
    mcuxClKey_Handle_t key,
    uint32_t * dstData
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClKey_loadMemory, key->protection->protectionTokenLoad);

    /* Set additional parameters */
    mcuxClKey_setLoadStatus(key, MCUX_CL_KEY_LOADSTATUS_MEMORY);
    mcuxClKey_setLoadedKeyData(key, dstData);

    /* Perform key loading */
    MCUX_CSSL_FP_FUNCTION_CALL(result, key->protection->loadFunc(key));

    if(MCUX_CL_KEY_STATUS_OK != result)
    {

      mcuxClKey_setLoadedKeyData(key, NULL);
      mcuxClKey_setLoadStatus(key, MCUX_CL_KEY_LOADSTATUS_NOTLOADED);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_loadMemory, result);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_loadCopro)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_loadCopro(
    mcuxClSession_Handle_t pSession UNUSED_PARAM,
    mcuxClKey_Handle_t key,
    uint32_t dstSlot
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClKey_loadCopro, key->protection->protectionTokenLoad);

    /* Set additional parameters */
    mcuxClKey_setLoadedKeySlot(key, dstSlot);
    mcuxClKey_setLoadStatus(key, MCUX_CL_KEY_LOADSTATUS_COPRO);

    /* Perform key loading */
    MCUX_CSSL_FP_FUNCTION_CALL(result, key->protection->loadFunc(key));

    if(MCUX_CL_KEY_STATUS_OK != result)
    {
        /* Set additional parameters */
        mcuxClKey_setLoadedKeySlot(key, 0xFF);
        mcuxClKey_setLoadStatus(key, MCUX_CL_KEY_LOADSTATUS_NOTLOADED);
    }

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_loadCopro, result);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_flush)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_flush(
    mcuxClSession_Handle_t pSession UNUSED_PARAM,
    mcuxClKey_Handle_t key
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClKey_flush);
    
    mcuxClKey_LoadStatus_t location = mcuxClKey_getLoadStatus(key);

    if(MCUX_CL_KEY_LOADSTATUS_NOTLOADED == location)
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_flush, MCUX_CL_KEY_STATUS_OK);
    }
    else if(MCUX_CL_KEY_LOADSTATUS_MEMORY == location)
    {
        uint32_t len = mcuxClKey_getSize(key);
        //TODO may need to be replaced by a secure set function
        MCUX_CSSL_FP_FUNCTION_CALL(resultLen, mcuxClMemory_set(mcuxClKey_getLoadedKeyData(key), 0u, len, len));
        if (0U != resultLen)
        {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_flush, MCUX_CL_KEY_STATUS_ERROR, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set));
        }
        mcuxClKey_setLoadStatus(key, MCUX_CL_KEY_LOADSTATUS_NOTLOADED);
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_flush, MCUX_CL_KEY_STATUS_OK, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_set));
    }
    else if(MCUX_CL_KEY_LOADSTATUS_COPRO == location)
    {
        MCUX_CSSL_FP_FUNCTION_CALL(resultDelete, mcuxClCss_KeyDelete_Async((mcuxClCss_KeyIndex_t) mcuxClKey_getLoadedKeySlot(key)));
        if (MCUXCLCSS_STATUS_OK_WAIT != resultDelete) {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_flush, MCUX_CL_KEY_STATUS_ERROR, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyDelete_Async));
        }

        MCUX_CSSL_FP_FUNCTION_CALL(resultWait, mcuxClCss_WaitForOperation(MCUXCLCSS_ERROR_FLAGS_CLEAR));
        if ((MCUXCLCSS_STATUS_OK != resultWait)) {
            MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_flush, MCUX_CL_KEY_STATUS_ERROR, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
                                                                             MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyDelete_Async));
        }
        mcuxClKey_setLoadStatus(key, MCUX_CL_KEY_LOADSTATUS_NOTLOADED);
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_flush, MCUX_CL_KEY_STATUS_OK, MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation),
                                                                      MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_KeyDelete_Async));
    }
    else
    {
        MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_flush, MCUX_CL_KEY_STATUS_ERROR);
    }
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClKey_setKeyproperties)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClKey_Status_t) mcuxClKey_setKeyproperties(
    mcuxClKey_Handle_t key,
    mcuxClCss_KeyProp_t * key_properties
)
{
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClKey_setKeyproperties);

    mcuxClKey_setAuxData(key, (uint8_t *) key_properties);

    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClKey_setKeyproperties, MCUX_CL_KEY_STATUS_OK);
}
