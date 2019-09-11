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

#ifndef _SCA_DEFS_H
#define	_SCA_DEFS_H

#pragma ident	"@(#)sca_defs.h	1.1	05/06/29 SMI"

/*
 * Contains various definitions needed by both host-side and target-side code.
 */

#include "pkcs11types.h"

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_PIN_LEN		128
#define	MIN_PIN_LEN		4
#define	MAX_SLOT_ID		32		/* Slot fm 0 to MAX_SLOT_ID-1 */
#define	THIRTY_TWO		32

#define	SCA_NAME		"scaf"		/* the framework module name */
#define	SCA_DEVICE_NAME		"/dev/"SCA_NAME	/* device node name */
#define	SCA_IOC_MAGIC		'A'		/* chosen starting value */
#define	SCA_IOC(x)		_IO(SCA_IOC_MAGIC, (x + 0x20))

#define	SCA_INITIALIZE		SCA_IOC(0)
#define	SCA_FINALIZE		SCA_IOC(1)
#define	SCA_GETINFO		SCA_IOC(2)
#define	SCA_GETFUNCTIONLIST	SCA_IOC(3)

#define	SCA_GETSLOTLIST		SCA_IOC(4)
#define	SCA_GETSLOTINFO		SCA_IOC(5)
#define	SCA_GETTOKENINFO	SCA_IOC(6)
#define	SCA_WAITFORSLOTEVENT	SCA_IOC(7)
#define	SCA_GETMECHANISMLIST	SCA_IOC(8)
#define	SCA_GETMECHANISMINFO	SCA_IOC(9)
#define	SCA_INITTOKEN		SCA_IOC(10)
#define	SCA_INITPIN		SCA_IOC(11)
#define	SCA_SETPIN		SCA_IOC(12)

#define	SCA_OPENSESSION		SCA_IOC(13)
#define	SCA_CLOSESESSION	SCA_IOC(14)
#define	SCA_CLOSEALLSESSIONS	SCA_IOC(15)
#define	SCA_GETSESSIONINFO	SCA_IOC(16)
#define	SCA_GETOPERATIONSTATE	SCA_IOC(17)
#define	SCA_SETOPERATIONSTATE	SCA_IOC(18)
#define	SCA_LOGIN		SCA_IOC(19)
#define	SCA_LOGOUT		SCA_IOC(20)

#define	SCA_CREATEOBJECT	SCA_IOC(21)
#define	SCA_COPYOBJECT		SCA_IOC(22)
#define	SCA_DESTROYOBJECT	SCA_IOC(23)
#define	SCA_GETOBJECTSIZE	SCA_IOC(24)
#define	SCA_GETATTRIBUTEVALUE	SCA_IOC(25)
#define	SCA_SETATTRIBUTEVALUE	SCA_IOC(26)
#define	SCA_FINDOBJECTSINIT	SCA_IOC(27)
#define	SCA_FINDOBJECTS		SCA_IOC(28)
#define	SCA_FINDOBJECTSFINAL	SCA_IOC(29)

#define	SCA_ENCRYPTINIT		SCA_IOC(30)
#define	SCA_ENCRYPT		SCA_IOC(31)
#define	SCA_ENCRYPTUPDATE	SCA_IOC(32)
#define	SCA_ENCRYPTFINAL	SCA_IOC(33)

#define	SCA_DECRYPTINIT		SCA_IOC(34)
#define	SCA_DECRYPT		SCA_IOC(35)
#define	SCA_DECRYPTUPDATE	SCA_IOC(36)
#define	SCA_DECRYPTFINAL	SCA_IOC(37)

#define	SCA_DIGESTINIT		SCA_IOC(38)
#define	SCA_DIGEST		SCA_IOC(39)
#define	SCA_DIGESTUPDATE	SCA_IOC(40)
#define	SCA_DIGESTKEY		SCA_IOC(41)
#define	SCA_DIGESTFINAL		SCA_IOC(42)

#define	SCA_SIGNINIT		SCA_IOC(43)
#define	SCA_SIGN		SCA_IOC(44)
#define	SCA_SIGNUPDATE		SCA_IOC(45)
#define	SCA_SIGNFINAL		SCA_IOC(46)
#define	SCA_SIGNRECOVERINIT	SCA_IOC(47)
#define	SCA_SIGNRECOVER		SCA_IOC(48)

#define	SCA_VERIFYINIT		SCA_IOC(49)
#define	SCA_VERIFY		SCA_IOC(50)
#define	SCA_VERIFYUPDATE	SCA_IOC(51)
#define	SCA_VERIFYFINAL		SCA_IOC(52)
#define	SCA_VERIFYRECOVERINIT	SCA_IOC(53)
#define	SCA_VERIFYRECOVER	SCA_IOC(54)

#define	SCA_DIGESTENCRYPTUPDATE	SCA_IOC(55)
#define	SCA_DECRYPTDIGESTUPDATE	SCA_IOC(56)
#define	SCA_SIGNENCRYPTUPDATE	SCA_IOC(57)
#define	SCA_DECRYPTVERIFYUPDATE	SCA_IOC(58)

#define	SCA_GENERATEKEY		SCA_IOC(59)
#define	SCA_GENERATEKEYPAIR	SCA_IOC(60)
#define	SCA_WRAPKEY		SCA_IOC(61)
#define	SCA_UNWRAPKEY		SCA_IOC(62)
#define	SCA_DERIVEKEY		SCA_IOC(63)

#define	SCA_SEEDRANDOM		SCA_IOC(64)
#define	SCA_GENERATERANDOM	SCA_IOC(65)

#define	SCA_GETFUNCTIONSTATUS	SCA_IOC(66)
#define	SCA_CANCELFUNCTION	SCA_IOC(67)

/*
 * this is the format of attributes that get passed between card and host
 *
 * this is different from the CK_ATTRIBUTE format defined by Cryptoki.
 * CK_ATTRIBUTE uses a pointer to the data field but we need a flat
 * structure to pass between the card and host DLL.  Further, we
 * need the length field to precede the data.
 */
typedef struct _ATTRIBUTE
{
	CK_ATTRIBUTE_TYPE_32	type;
	CK_ULONG_32		value_length;
	/* the value data is appended here */
} ATTRIBUTE;

/*
 * this is a flattened version of the CK_SSL3_RANDOM_DATA
 */
typedef struct _SSL3_RANDOM_DATA
{
	CK_ULONG_32	client_data_len;
	CK_ULONG_32	server_data_len;
	/* client data is appended here */
	/* server data is appended here */
} SSL3_RANDOM_DATA;

typedef struct _SSL3_MASTER_KEY_DERIVE_PARAMS
{
	CK_VERSION	version;
	CK_ULONG_32	client_data_len;
	CK_ULONG_32	server_data_len;
	/* client data is appended here */
	/* server data is appended here */
} SSL3_MASTER_KEY_DERIVE_PARAMS;

typedef struct _SSL3_KEY_MAT_OUT
{
	CK_OBJECT_HANDLE_32	client_mac_secret;
	CK_OBJECT_HANDLE_32	server_mac_secret;
	CK_OBJECT_HANDLE_32	client_key;
	CK_OBJECT_HANDLE_32	server_key;
	CK_ULONG_32		iv_len;		/* in bytes */
	/* client IV is appended here */
	/* server IV is appended here */
} SSL3_KEY_MAT_OUT;

typedef struct _SSL3_KEY_MAT_PARAMS
{
	CK_ULONG_32	mac_size_bits;
	CK_ULONG_32	key_size_bits;
	CK_ULONG_32	iv_size_bits;
	CK_BBOOL	export;
	CK_ULONG_32	client_data_len;
	CK_ULONG_32	server_data_len;
	/* client data is appended here */
	/* server data is appended here */
} SSL3_KEY_MAT_PARAMS;

#ifdef	__cplusplus
}
#endif

#endif /* _SCA_DEFS_H */
