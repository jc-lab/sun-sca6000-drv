/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2006 Sun Microsystems, Inc. All Rights Reserved.
 *
 *     Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * - Redistribution of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * - Redistribution in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *     Neither the name of Sun Microsystems, Inc. or the names of contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *     This software is provided "AS IS," without a warranty of any kind. ALL
 * EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND WARRANTIES, INCLUDING
 * ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
 * OR NON-INFRINGEMENT, ARE HEREBY EXCLUDED. SUN MICROSYSTEMS, INC. ("SUN")
 * AND ITS LICENSORS SHALL NOT BE LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE
 * AS A RESULT OF USING, MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS
 * DERIVATIVES. IN NO EVENT WILL SUN OR ITS LICENSORS BE LIABLE FOR ANY LOST
 * REVENUE, PROFIT OR DATA, OR FOR DIRECT, INDIRECT, SPECIAL, CONSEQUENTIAL,
 * INCIDENTAL OR PUNITIVE DAMAGES, HOWEVER CAUSED AND REGARDLESS OF THE THEORY
 * OF LIABILITY, ARISING OUT OF THE USE OF OR INABILITY TO USE THIS SOFTWARE,
 * EVEN IF SUN HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 *     You acknowledge that this software is not designed, licensed or
 * intended for use in the design, construction, operation or maintenance of
 * any nuclear facility.
 */

#ifndef	_SCA_ARGS_H
#define	_SCA_ARGS_H

#pragma ident	"@(#)sca_args.h	1.2	07/06/11 SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ioctl argument block definitions for requests/replies
 * This file is required for both host and the target code
 */

typedef struct CK_SLOT_INFO_32 {
	CK_CHAR		slotDescription[64];	/* blank padded */
	CK_CHAR		manufacturerID[32];	/* blank padded */
	CK_FLAGS_32	flags;
	CK_VERSION	hardwareVersion;	/* version of hardware */
	CK_VERSION	firmwareVersion;	/* version of firmware */
} CK_SLOT_INFO_32;

typedef struct _GetSlotList_Args
{
	CK_BBOOL			token_present;
	CK_ULONG_32			slot_count;
	CK_BBOOL			count_only;
	/*
	 * Slot list appends here.
	 * CK_SLOT_ID_PTR		slot_list;
	 */
} GetSlotList_Args;

typedef struct _GetSlotInfo_Args
{
	CK_SLOT_ID_32			 slot_id;
	CK_SLOT_INFO_32			 slot_info;
} GetSlotInfo_Args;

typedef struct _GetTokenInfo_Args
{
	CK_SLOT_ID_32			 slot_id;
	CK_TOKEN_INFO_32		 token_info;
} GetTokenInfo_Args;

typedef struct _GetMechList_Args
{
	CK_SLOT_ID_32			slot_id;
	CK_ULONG_32			list_length;
	CK_BBOOL			length_only;
	/*
	 * Mechanism list appends here.
	 * CK_MECHANISM_TYPE_32		*mechanisms;
	 */
} GetMechList_Args;

typedef struct _GetMechInfo_Args
{
	CK_SLOT_ID_32			slot_id;
	CK_MECHANISM_TYPE_32		mech_type;
	CK_MECHANISM_INFO_32		mech_info;
} GetMechInfo_Args;

typedef struct _InitPIN_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_BYTE			pin[MAX_PIN_LEN];
	CK_ULONG_32		pin_len;
} InitPIN_Args;

typedef struct _SetPIN_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_BYTE			old_pin[MAX_PIN_LEN];
	CK_ULONG_32		old_pin_len;
	CK_BYTE			new_pin[MAX_PIN_LEN];
	CK_ULONG_32		new_pin_len;
} SetPIN_Args;


typedef struct _OpenSession_Args
{
	CK_SLOT_ID_32		slot_id;
	CK_FLAGS_32		flags;
	CK_SESSION_HANDLE_32	session_handle;
} OpenSession_Args;

typedef struct _CloseSession_Args
{
	CK_SESSION_HANDLE_32	session_handle;
} CloseSession_Args;

typedef struct _Login_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_USER_TYPE_32		user_type;
	CK_BYTE			pin[MAX_PIN_LEN];
	CK_ULONG_32		pin_len;
} Login_Args;

typedef struct _Logout_Args
{
	CK_SESSION_HANDLE_32	session_handle;
} Logout_Args;

/*
 * CreateObject_Args is a bit different. The attributes themselves
 * are passed as a datablock immediately following this structure
 */
typedef struct _CommonObject_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_OBJECT_HANDLE_32	object_handle;
	CK_ULONG_32		attribute_count;
	CK_ULONG_32		attribute_block_len;
	/*
	 * Attributes append here.
	 * CK_BYTE_PTR		attributes;
	 */
} CommonObject_Args;

typedef struct _DestroyObject_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_OBJECT_HANDLE_32	object_handle;
} DestroyObject_Args;

typedef struct _GetObjectSize_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_OBJECT_HANDLE_32	object_handle;
	CK_ULONG_32		size;
} GetObjectSize_Args;

typedef struct _FindObjectsInit_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_ULONG_32		attribute_count;
	CK_ULONG_32		attribute_block_len;
	/*
	 * Attributes appends here.
	 * CK_BYTE_PTR		attributes;
	 */
} FindObjectsInit_Args;

typedef struct _FindObjects_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_ULONG_32		max_count;
	CK_ULONG_32		count;
	/*
	 * Handles append here.
	 * CK_BYTE_PTR		handles;
	 */
} FindObjects_Args;

typedef struct _FindObjectsFinal_Args
{
	CK_SESSION_HANDLE_32	session_handle;
} FindObjectsFinal_Args;

typedef struct _SeedRandom_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_ULONG_32		num_bytes;
	/*
	 * Seed buffer appends here.
	 * CK_BYTE_PTR		seed;
	 */
} SeedRandom_Args;

typedef struct _GenerateRandom_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_ULONG_32		num_bytes;
	/*
	 * Random buffer appends here.
	 * CK_BYTE_PTR		buf;
	 */
} GenerateRandom_Args;

typedef struct _GenerateKey_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_OBJECT_HANDLE_32	object_handle;
	CK_MECHANISM_TYPE_32	mech_type;
	CK_ULONG_32		mech_param_len;
	CK_ULONG_32		attribute_count;
	CK_ULONG_32		attribute_block_len;
	/*
	 * Parameter and attributes append here.
	 * CK_BYTE_PTR		param;
	 * CK_BYTE_PTR		attributes;
	 */
} GenerateKey_Args;

typedef struct _GenKeyPair_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_OBJECT_HANDLE_32	pub_object_handle;
	CK_OBJECT_HANDLE_32	pri_object_handle;
	CK_MECHANISM_TYPE_32	mech_type;
	CK_ULONG_32		mech_param_len;
	CK_ULONG_32	publ_key_attr_count;	/* # of attributes */
	CK_ULONG_32	publ_key_tmpl_len;	/* overall template length */
	CK_ULONG_32	priv_key_attr_count;	/* # of attributes */
	CK_ULONG_32	priv_key_tmpl_len;	/* overall template length */
	/*
	 * Parameter and attrbutes append here.
	 * CK_BYTE_PTR		param;
	 * CK_BYTE_PTR	publ_attributes;
	 * CK_BYTE_PTR	priv_attributes;
	 */
} GenKeyPair_Args;

/* for both C_EncryptInit and C_DecryptInit */
typedef struct _EncryptInit_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_OBJECT_HANDLE_32	key;
	CK_MECHANISM_TYPE_32	mech_type;
	CK_ULONG_32		param_len;	/* parameter length in bytes */
	/*
	 * parameter appends here.
	 * CK_BYTE_PTR		param;
	 */
} EncryptInit_Args;

/* for both C_Encrypt and C_Decrypt */
typedef struct _Encrypt_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_ULONG_32		in_data_len;
	CK_ULONG_32		out_data_len;
	/*
	 * Input and output data append here.
	 * CK_BYTE_PTR		in_data;
	 * CK_BYTE_PTR		out_data;
	 */
} Encrypt_Args;

/* for both C_EncryptUpdate and C_DecryptUpdate */
typedef struct _EncryptUpdate_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_ULONG_32		in_part_len;
	CK_ULONG_32		out_part_len;
	/*
	 * Input and output data append here.
	 * CK_BYTE_PTR		in_part;
	 * CK_BYTE_PTR		out_part;
	 */
} EncryptUpdate_Args;

/* for C_EncryptFinal, C_DecryptFinal, C_DigestFinal, and C_SignFinal */
typedef struct _EncryptFinal_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_ULONG_32		out_len;
	/*
	 * Output data append here.
	 * CK_BYTE_PTR		out_data;
	 */
} EncryptFinal_Args;

typedef struct _WrapKey_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_MECHANISM_TYPE_32	mech_type;
	CK_ULONG_32		mech_param_len;
	CK_OBJECT_HANDLE_32	wrapping_key;
	CK_OBJECT_HANDLE_32	key;		/* key to be wrapped */
	CK_ULONG_32		wrapped_key_len;
	/*
	 * Parameter and key append here.
	 * CK_BYTE_PTR		param;
	 * CK_BYTE_PTR		wrapped_key;
	 */
} WrapKey_Args;

typedef struct _UnWrapKey_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_OBJECT_HANDLE_32	object_handle;
	CK_MECHANISM_TYPE_32	mech_type;
	CK_ULONG_32		mech_param_len;
	CK_OBJECT_HANDLE_32	unwrapping_key;
	CK_ULONG_32		wrapped_key_len;
	CK_ULONG_32		attribute_count;
	CK_ULONG_32		attribute_block_len;
	/*
	 * Parameter, key and attributes append here.
	 * CK_BYTE_PTR		param;
	 * CK_BYTE_PTR		wrapped_key;
	 * CK_BYTE_PTR		attributes;
	 */
} UnWrapKey_Args;

typedef struct _DeriveKey_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_OBJECT_HANDLE_32	object_handle;
	CK_MECHANISM_TYPE_32	mech_type;
	CK_ULONG_32		mech_param_len;
	CK_OBJECT_HANDLE_32	base_key;
	CK_ULONG_32		attribute_count;
	CK_ULONG_32		attribute_block_len;
	/*
	 * Parameter and attributes append here.
	 * CK_BYTE_PTR		param;
	 * CK_BYTE_PTR		attributes;
	 */
} DeriveKey_Args;

typedef struct _DigestInit_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_MECHANISM_TYPE_32	mech_type;
	CK_ULONG_32		param_len;	/* len of parameter in bytes */
	/*
	 * Parameter appends here.
	 * CK_BYTE_PTR		param;
	 */
} DigestInit_Args;

/* for C_Digest, C_Sign, C_SignRecover, and C_VerifyRecover */
typedef struct _Digest_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_ULONG_32		in_data_len;
	CK_ULONG_32		out_data_len;
	/*
	 * Input and output data append here.
	 * CK_BYTE_PTR		in_data;
	 * CK_BYTE_PTR		out_data;
	 */
} Digest_Args;

typedef struct _DigestUpdate_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_ULONG_32		data_len;
	/*
	 * Data append here.
	 * CK_BYTE_PTR		data;
	 */
} DigestUpdate_Args;

typedef struct _DigestKey_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_OBJECT_HANDLE_32	key;
} DigestKey_Args;

/* for C_SignInint, C_VerifyInit, C_SignRecoverInit, and C_VerifyRecoverInit */
typedef struct _SignInit_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_OBJECT_HANDLE_32	key;
	CK_MECHANISM_TYPE_32	mech_type;
	CK_ULONG_32		param_len;	/* parameter length in bytes */
	/*
	 * Parameter appends here.
	 * CK_BYTE_PTR		param;
	 */
} SignInit_Args;

/* for C_SignUpdate and C_VerifyUpdate */
typedef struct _SignUpdate_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_ULONG_32		data_len;
	/*
	 * Data appends here.
	 * CK_BYTE_PTR		data;
	 */
} SignUpdate_Args;

typedef struct _Verify_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_ULONG_32		data_len;
	CK_ULONG_32		signature_len;
	/*
	 * Data and signature append here.
	 * CK_BYTE_PTR		data;
	 * CK_BYTE_PTR		signature;
	 */
} Verify_Args;

typedef struct _VerifyFinal_Args
{
	CK_SESSION_HANDLE_32	session_handle;
	CK_ULONG_32		signature_len;
	/*
	 * Signature appends here.
	 * CK_BYTE_PTR		signature;
	 */
} VerifyFinal_Args;

#ifdef	__cplusplus
}
#endif

#endif /* _SCA_ARGS_H */
