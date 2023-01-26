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

/** @file  mcuxClPsaDriver_Oracle.h
 *  @brief API definition of the PSA driver Oracle */


#include <crypto.h>
#include <mcuxClKey.h>
#include <mcuxClConfig.h> // Exported features flags header

// GENERAL NOTE
// do not use mcuxClKey_setKeyproperties on any of these keys as it will overwrite pAuxData


/**
    @brief Oracle function for loading a key

    This function loads an encoded or internal key to memory or the S50 key store.

    PRECONDITION:
        The fields of @p pKey are initialized as follows:
        - container.pData    : points to the psa key buffer (key_buffer)
        - container.length   : set to the length of the psa key buffer (key_buffer_size)
        - container.used     : set to the length of the psa key buffer (key_buffer_size)
        - container.pAuxData : points to the psa attributes (attributes)
        All other fields can be uninitialized

    POSTCONDITION:
        In case the key is loaded into memory the fields of @p pKey are initialized as follows:
        - location.pData  : points to the memory location where the key is loaded, this memory is
                            allocated by the Oracle
        - location.length : the length of the key that was loaded to memory; i.e. the buffer length
        - location.slot   : does not matter, suggest using 0xFFFFFFu
        - location.status : MCUXCLKEY_LOADSTATUS_MEMORY
        In case the key is loaded into an S50 key slot the fields of @p pKey are initialized as follows:
        - location.pData  : does not matter, suggest NULL
        - location.length : the length of the key that was loaded to the S50 key slot
        - location.slot   : the S50 key slot to which the key was loaded
        - location.status : MCUXCLKEY_LOADSTATUS_COPRO

    OPERATION:
        Depending on the location attribute in the psa attributes, the Oracle allocates a memory location
        or free key slot in the S50 (the Oracle is responsible for the memory management) and loads the
        key there. How the location attributes map to endoding or derivation methods is entirely up to
        the design of the Oracle; e.g. a key could be decrypted from a blob or derived from a master key.

    @retval PSA_SUCCESS                 The operation was succesful
    @retval PSA_ERROR_NOT_SUPPORTED     The Oracle shall never return this error code
    @retval PSA_ERROR_GENERIC_ERROR     The operation failed (other error codes can be used as well if more specific)

*/
psa_status_t mcuxClPsaDriver_Oracle_LoadKey( mcuxClKey_Descriptor_t   *pKey );

/**
    @brief Oracle function for 'suspending' a key

    This function indicates to the Oracle that the key will temporarily not be used by the psa driver.
    This allows the Oracle to perform memory management operations on this key.

    @retval PSA_SUCCESS                 The operation was succesful
    @retval PSA_ERROR_NOT_SUPPORTED     The Oracle shall never return this error code
    @retval PSA_ERROR_GENERIC_ERROR     The operation failed (other error codes can be used as well if more specific)

*/
psa_status_t mcuxClPsaDriver_Oracle_suspendKey( mcuxClKey_Descriptor_t   *pKey );

/**
    @brief Oracle function for 'resuming' a previously 'suspended' key

    This function indicates to the Oracle that the key will be used agian by the psa driver.
    The Oracle should assure it is available again and may therefore need to re-allocate, re-load the key
    and update the key fields.

    @retval PSA_SUCCESS                 The operation was succesful
    @retval PSA_ERROR_NOT_SUPPORTED     The Oracle shall never return this error code
    @retval PSA_ERROR_GENERIC_ERROR     The operation failed (other error codes can be used as well if more specific)

*/
psa_status_t mcuxClPsaDriver_Oracle_resumeKey( mcuxClKey_Descriptor_t   *pKey );

/**
    @brief Oracle function for 'unloading' a previously loaded key

    This function indicates to the Oracle that the key will not be used any more by the psa driver.
    This allows the Oracle to free the allocated storage for this key.

    @retval PSA_SUCCESS                 The operation was succesful
    @retval PSA_ERROR_NOT_SUPPORTED     The Oracle shall never return this error code
    @retval PSA_ERROR_GENERIC_ERROR     The operation failed (other error codes can be used as well if more specific)

*/
psa_status_t mcuxClPsaDriver_Oracle_unloadKey( mcuxClKey_Descriptor_t   *pKey );

/**
    @brief Oracle function for allocating storage for a key that will be created by the psa driver

    This function requests storage space from the Oracle for a key that will be created by the psa driver.
    The Oracle shall allocate memory space or a key slot capable of holding the to be generated key.

    @retval PSA_SUCCESS                 The operation was succesful
    @retval PSA_ERROR_NOT_SUPPORTED     The Oracle shall never return this error code
    @retval PSA_ERROR_GENERIC_ERROR     The operation failed (other error codes can be used as well if more specific)

*/
psa_status_t mcuxClPsaDriver_Oracle_reserveKey( mcuxClKey_Descriptor_t   *pKey );
/**
    @brief Oracle function for saving a key

    This function saves a key from memory or the S50 key store to an encoded format (blob).

    @retval PSA_SUCCESS                 The operation was succesful
    @retval PSA_ERROR_NOT_SUPPORTED     The Oracle shall never return this error code
    @retval PSA_ERROR_GENERIC_ERROR     The operation failed (other error codes can be used as well if more specific)

*/
psa_status_t mcuxClPsaDriver_Oracle_storeKey( mcuxClKey_Descriptor_t   *pKey );



/**
    @brief Oracle function for checking the key before importing and getting the bit length of the key

    This function is to perform checks on an (encrypted) key object.

    @retval PSA_SUCCESS                 The operation was succesful
    @retval PSA_ERROR_NOT_SUPPORTED     The Oracle shall never return this error code
    @retval PSA_ERROR_GENERIC_ERROR     The operation failed (other error codes can be used as well if more specific)

*/
psa_status_t mcuxClPsaDriver_Oracle_importKey (  mcuxClKey_Descriptor_t *pKey,
                                                size_t                *bits);

