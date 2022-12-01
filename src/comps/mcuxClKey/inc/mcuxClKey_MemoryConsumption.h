/*--------------------------------------------------------------------------*/
/* Copyright 2021-2022 NXP                                                  */
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

#ifndef MCUXCLKEY_MEMORYCONSUMPTION_H_
#define MCUXCLKEY_MEMORYCONSUMPTION_H_

#include <mcuxClCore_Platform.h>

#define MCUX_CL_KEY_DESCRIPTOR_SIZE          (52u)
#define MCUX_CL_KEY_DESCRIPTOR_SIZE_IN_WORDS (MCUX_CL_KEY_DESCRIPTOR_SIZE / sizeof(uint32_t))

#define MCUX_CL_KEY_TYPEDESCRIPTOR_SIZE          (12u)
#define MCUX_CL_KEY_TYPEDESCRIPTOR_SIZE_IN_WORDS (MCUX_CL_KEY_TYPEDESCRIPTOR_SIZE / sizeof(uint32_t))

#define MCUX_CL_KEY_CUSTOMTYPEDESCRIPTOR_SIZE          (12u)
#define MCUX_CL_KEY_CUSTOMTYPEDESCRIPTOR_SIZE_IN_WORDS (MCUX_CL_KEY_CUSTOMTYPEDESCRIPTOR_SIZE / sizeof(uint32_t))


#endif /* MCUXCLKEY_MEMORYCONSUMPTION_H_ */
