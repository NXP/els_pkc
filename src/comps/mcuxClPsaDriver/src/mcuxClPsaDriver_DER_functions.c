/*--------------------------------------------------------------------------*/
/* Copyright 2023 NXP                                                       */
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


#include "common.h"

#include <mcuxClMemory.h>
#include <mcuxClPsaDriver.h>
#include <mcuxClRsa.h>
/**
 * \brief       Updates the pointer to immediately behind the full tag.
 *
 * \param p     *p points to the start of the DER element.
 *              On successful completion, *p points to the first byte
 *              beyond the DER element.
 *              On error, the value of *p is undefined.
 *
 * \return      PSA_SUCCESS if successful.
 * \return      An PSA_ERROR_INVALID_ARGUMENT error code if the parsed input is incorrect
 */
psa_status_t mcuxClPsaDriver_psa_driver_wrapper_der_updatePointerTag(uint8_t **p,
                          uint8_t tag)
{
    uint32_t length = 0;

    if((NULL == p) || (NULL == *p) || (**p != tag))
    {
      return PSA_ERROR_INVALID_ARGUMENT;
    }
    (*p)++;

    //check length
    if((**p & 0x80u) == 0) //short from
    {
     length = **p;
     (*p)++;
    }
    else //long form
    {
      unsigned int numberBytes = **p & 0x7Fu;
      (*p)++;

      /* If length is less than 128bytes it should be short form */
      if ((numberBytes == 1u) && (**p < 128u))
      {
        return PSA_ERROR_INVALID_ARGUMENT;
      }

      for(unsigned int i = 0; i < numberBytes; ++i)
      {
       length = length << 8u;
       length |= **p;
       (*p)++;
      }
    }

    if((tag & 0x20) != 0x20)
    {
      // not constructed tag, skip the content
      *p += length;
    }
    return PSA_SUCCESS;
}

/**
 * \brief       Retrieve an integer DER tag and its value.
 *              Updates the pointer to immediately behind the full tag.
 *
 * \param p     *p points to the start of the DER element.
 *              On successful completion, *p points to the first byte
 *              beyond the DER element.
 *              On error, the value of *p is undefined.
 *
 * \return      PSA_SUCCESS if successful.
 * \return      An PSA_ERROR_INVALID_ARGUMENT error code if the parsed input is incorrect
 */
psa_status_t mcuxClPsaDriver_psa_driver_wrapper_der_get_integer(uint8_t **p,
                          mcuxClRsa_KeyEntry_t  * key)
{
    //check tag
    if(**p != 0x02)
    {
      return PSA_ERROR_INVALID_ARGUMENT;
    }
    (*p)++;

    //check length
    if((**p & 0x80u) == 0) //short from
    {
      key->keyEntryLength = **p;
      (*p)++;
    }
    else //long form
    {
      uint8_t numberBytes = **p & 0x7Fu;
      (*p)++;

      if(numberBytes > 4u) // too big to fit into uint32
      {
        return PSA_ERROR_INVALID_ARGUMENT;
      }

      // if length is less than 128 bytes it should be short form
      if ((numberBytes == 1u) && (**p < 128u))
      {
        return PSA_ERROR_INVALID_ARGUMENT;
      }

      key->keyEntryLength = 0;

      for(uint32_t i = 0; i < numberBytes; ++i)
      {
        key->keyEntryLength = key->keyEntryLength << 8;
        key->keyEntryLength |= **p;
       (*p)++;
      }
    }

    //check first and second octet of integers
    uint8_t first_octet = **p;
    uint8_t second_octet = *(*p + 1u);
    if((first_octet == 0) && ((second_octet & 0x80) == 0))
    {
      return PSA_ERROR_INVALID_ARGUMENT;
    }
    if((first_octet == 0xFF) && ((second_octet & 0x80) == 0x80))
    {
      return PSA_ERROR_INVALID_ARGUMENT;
    }

    if(first_octet == 0)
    {
      //take next non-zero octet, the key date is unsigned
      (*p)++;
      key->keyEntryLength -= 1u;
    }
    key->pKeyEntryData = *p;

    *p += key->keyEntryLength;

    return PSA_SUCCESS;
}

/**
 * \brief       Generate an integer DER tag and its value
 *              Updates the pointer to immediately behind the full tag.
 *
 * \param p     *p points to the start of the DER element.
 *              On successful completion, *p points to the first byte
 *              beyond the DER element.
 *              On error, the value of *p is undefined.
  * \param key  *key points to the origin key element.

 *
 * \return      PSA_SUCCESS if successful.
 * \return      An PSA_ERROR_INVALID_ARGUMENT error code if the parsed input is incorrect
 */
psa_status_t mcuxClPsaDriver_psa_driver_wrapper_der_integer(uint8_t **p,
                          mcuxClRsa_KeyEntry_t  * key)
{
    uint8_t *ptr = *p;
    //check tag
    *ptr = 0x02u;
    ptr++;
    if(key->keyEntryLength > 0x7Fu) //long form
    {
        uint8_t h3_byte = ((key->keyEntryLength) & 0xFF000000u) >> 24u;
        uint8_t h2_byte = ((key->keyEntryLength) & 0xFF0000u) >> 16u;
        uint8_t h1_byte = ((key->keyEntryLength) & 0xFF00u) >> 8u;
        uint8_t h0_byte = (key->keyEntryLength) & 0xFFu;
        if(h3_byte != 0u)
        {
            *ptr = 0x84u;
            ptr++;
            *ptr = h3_byte;
            ptr++;
            *ptr = h2_byte;
            ptr++;
            *ptr = h1_byte;
            ptr++;
            *ptr = h0_byte;
            ptr++;
        }
        else if(h2_byte != 0u)
        {
            *ptr = 0x83u;
            ptr++;
            *ptr = h2_byte;
            ptr++;
            *ptr = h1_byte;
            (*p)++;
            *ptr = h0_byte;
            ptr++;
        }
        else if(h1_byte != 0u)
        {
            *ptr = 0x82u;
            ptr++;
            *ptr = h1_byte;
            ptr++;
            *ptr = h0_byte;
            ptr++;
        }
        else
        {
            *ptr = 0x81u;
            ptr++;
            *ptr = h0_byte;
            ptr++;
        }
    }
    else                           //short from
    {
        *ptr = key->keyEntryLength;
        ptr++;
    }

    *p = ptr;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ret, token, mcuxClMemory_copy(
                                                  *p,
                                                  key->pKeyEntryData,
                                                  key->keyEntryLength,
                                                  key->keyEntryLength));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMemory_copy) != token) || (0u != ret))
    {
        return PSA_ERROR_GENERIC_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    *p += key->keyEntryLength;

    return PSA_SUCCESS;
}


