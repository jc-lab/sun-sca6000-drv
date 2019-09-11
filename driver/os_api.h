/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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

#ifndef _OS_API_H
#define	_OS_API_H

#pragma ident	"@(#)os_api.h	1.48	07/08/22 SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * --------------------------------------------------------------------
 * Description: The CPG header file which describes the firmware
 *              object store.
 *
 * Modification History
 * --------------------
 * DATE       	ENGINEER	DESCRIPTION
 * ----------------------------------------
 * 9-16-2005	tsm       	Created
 * --------------------------------------------------------------------
 */

#ifdef LINUX
#include <linux/types.h>
#else
#include <sys/types.h>
#endif


#define	OBJSTORE_NAME_MAX	64
#define	DB_PATH_MAX		256
#define	DOMID_NAME_MAX		256	/* Max length of domain ID */
#define	OBJSTORE_MAX		255	/* The maximum number of keystores. */

#if !defined(digestSize)
#define	digestSize	20
#endif /* digestSize */

typedef enum
{
				/* ops used by the firmware only */
	DB_STANDBY = 1,

	DB_USER_READ,
	DB_USER_WRITE,
	DB_USER_DEL,		/* 4 */

	DB_OBJECT_READ,
	DB_OBJECT_WRITE,
	DB_OBJECT_DEL,

	DB_FILE_READ,		/* 8 */
	DB_FILE_WRITE,		/* 9 */
				/* ops used by the MOD only */

	DB_HELLO,		/* Who are we? */
	DB_FILE_PUSH,		/* DB_FILE_READ response */
	DB_USER_PUSH,		/* DB_USER_READ response */
	DB_OBJECT_PUSH,		/* DB_OBJECT_READ response. */

				/* ops used by both parties */
	DB_RESPONSE,		/* A generic status response. */
	DB_HANDSHAKE,
	DB_STATUS,		/* 16 */
				/* Other operations. */
	DB_PROVIDER_REGISTER,	/* Register as a provider */
	DB_PROVIDER_UNREGISTER,	/* Unregister as a provider */

	DB_INIT,		/* Create a new keystore DB */
	DB_GOODBYE,		/* MOD closed channel */
	DB_READ,		/* Read the complete DB */
	DB_DELETE,		/* Delete a DB */

	DB_CHECK,		/* Does a DB exists? */
	DB_JOIN,		/* We need a Hello (restore, etc.) */

	DB_ARCHIVE,		/* Create an archive file of a database. */
	DB_UNARCHIVE,		/* Unpack a keystore archive */
	DB_RENAME,		/* Rename a keystore */

	DB_CONFIG_READ,		/* Read a keystore configuration file. */
	DB_CONFIG_WRITE,	/* Write a keystore configuration file. */
	DB_CONFIG_PUSH,		/* DB_CONFIG_READ response. */

	DB_LOG_READ,		/* Read 1 or more audit log message. */
	DB_LOG_WRITE,		/* Write 1 or more audit log messages. */
	DB_LOG_PUSH,		/* DB_LOG_READ response. */
	DB_FILE_DEL		/* Delete a file */
} dbm_op_t;

#define	DBM_OK	0

typedef enum
{
	DBM_CONTINUE	= (1 << 0),
	DBM_DEBUG	= (1 << 1),
	DBM_TEST	= (1 << 2),
	DBM_FILE_AP	= (1 << 3), /* Append to file */
	DBM_FILE_EXCL	= (1 << 4), /* Overwrite file */
	DBM_REKEY	= (1 << 5), /* Rekey operation */
	DBM_COMPLETE	= (1 << 6), /* Rekey op complete */
	DBM_SYNC	= (1 << 7), /* This is a sync operation. */
	DBM_USR1	= (1 << 8), /* This is a user_defined operation. */
	DBM_USR2	= (1 << 9), /* And so is this. */
	DBM_OFFLINE	= (1 << 10),  /* Temporarily offline keystore */
	DBM_ARCHIVE	= (1 << 11)  /* Send audit logs from the archive. */

} dbm_flag_t;

typedef enum
{
	DBM_KS_LOCAL = 0,	/* Local (Berk. DB) keystore */
	DBM_KS_LDAP,		/* Centralized keystore using LDAP */
	DBM_KS_DEVICE		/* This keystore is the device keystore. */

} dbm_kstype_t;

// ------------------------------------------------------------
// Driver-originated DBM error codes.
// ------------------------------------------------------------
#define	DBM_ERROR_BASE	0x80000000

#define	DBM_EPIPE	(DBM_ERROR_BASE | EPIPE)

// ------------------------------------------------------------
// typedefs
// ------------------------------------------------------------
typedef int32_t		dbm_size_t;
typedef uint32_t	dbm_errno_t;
typedef uint32_t	dbm_handle_t;
typedef uint32_t	dbm_flags_t;
typedef uint32_t	dbm_ldom_t;

typedef struct
{
	uint32_t	cid;
	uint32_t	oid;

} dbm_recno_t;			/* A record number, i.e., a database key. */

typedef struct			/* This struct is 16 bytes big. */
{
	dbm_op_t	type;
	dbm_handle_t	handle;
	dbm_ldom_t	ldom;
	dbm_errno_t	status;
	dbm_flags_t	flags;
	dbm_size_t	extent;
	dbm_size_t	paramSize;
	/* How big the message is, including this header. */

} dbm_header_t;

// ------------------------------------------------------------
// The handshake request tells the MOD how big a buffer
// to allocate for the firmware.
// ------------------------------------------------------------
typedef struct
{
	dbm_header_t	h;	/* DB_HANDSHAKE */

	dbm_op_t	type;
	dbm_size_t	size;	/* How big to make the next data buffer. */

} dbm_handshake_t;

// ------------------------------------------------------------
// The create request asks the MOD to create a new database.
// ------------------------------------------------------------
typedef struct
{
	dbm_header_t	h;	/* DB_HELLO, DB_DELETE, DB_READ */

	char		name[OBJSTORE_NAME_MAX];
			/* The name of the database */
	char		domain[DOMID_NAME_MAX];
			/* The name of the domain, i.e., its hostname. */

} dbm_hello_t;

// ------------------------------------------------------------
// The init request asks the MOD to create a new database.
// ------------------------------------------------------------
typedef struct
{
	dbm_header_t	h;	/* DB_INIT, DB_CHECK, DB_JOIN */

	char		name[OBJSTORE_NAME_MAX];
			/* The name of the database */
	char		domain[DOMID_NAME_MAX];
			/* The name of the domain, i.e., its hostname. */
	dbm_kstype_t	kstype;
			/* The keystore type (i.e. local, centralized) */

} dbm_init_t;

// ------------------------------------------------------------
// The provider structure tells the driver to either register
// or unregister the device as a crypto framework provider.
// ------------------------------------------------------------
typedef struct
{
	dbm_header_t	h;	/* DB_PROVIDER_REGISTER/UNREGISTER */

	char		name[OBJSTORE_NAME_MAX];
	// The name of the object store to register

	dbm_handle_t	handle;
	dbm_kstype_t	type;

} dbm_provider_t;

// ------------------------------------------------------------
// The file request asks the MOD to either read a file from,
// or write a file to, disk on behalf of the firmware.
// ------------------------------------------------------------
typedef struct
{
	dbm_header_t	h;	/* DB_FILE_READ/WRITE/PUSH */

	char		name[OBJSTORE_NAME_MAX];
	// The name of the file to read or write.

	dbm_size_t	length;
	// If type == DB_FILE_WRITE, the length of <file>.
	// If type == DB_FILE_READ, 0,
	// If type == DB_FILE_PUSH, the length of the file
	//   requested for reading.

	// What immediately follows <length> is the file to write,
	// or the file requested for reading.

} dbm_file_req_t;

// ------------------------------------------------------------
// A user record request.
// If the firmware wants to READ a user record, it fills in
//   uid, and sets objSize to 0 (fetch this record for me).
// If the firmware wants to WRITE a user record, it fills in
//   uid, and sets objSize to sizeof(record), then appends
//   the record to objSize.
// If the MOD has a user record to PUSH, it sets type to
//   DB_USER_READ, sets objSize to sizeof(record), then appends
//   the record to objSize.
// ------------------------------------------------------------
//
// Here is a completed dbm_user_req_t structure.
//
// +------------------------------------+--------
// | dbm_op_t		type;		|
// +------------------------------------+
// | dbm_handle_t	handle;		|
// +------------------------------------+ - dbm_header_t [h]
// | dbm_flags_t	flags;		|
// +------------------------------------+
// | dbm_size_t		paramSize;	|
// +------------------------------------+--------
// | char		dbf[...]	|
// +------------------------------------+
// | dbm_size_t		objCount;	|
// +------------------------------------+--------
// | uint8_t		uid[20];	|
// +- - - - - - - - - - - - - - - - - - +
// |					|
// +- - - - - - - - - - - - - - - - - - +
// |					|
// +- - - - - - - - - - - - - - - - - - + - dbm_ur_t [first]
// |					|
// +- - - - - - - - - - - - - - - - - - +
// |					|
// +------------------------------------+
// | dbm_size_t		objSize;	|
// +------------------------------------+--------
// |					|
// | [the encrypted user record(s)]	|
// |					|
// +------------------------------------+--------
//
typedef struct
{
	uint8_t		uid[digestSize];
	/* The record key (H(U)). */
	dbm_size_t	objSize;
	/* 0 if a read; n > 0 if a write, or read response. */

	// What immediately follows <objSize> is the user record
	// to write, or the user record requested for reading.

} dbm_ur_t;

typedef struct
{
	dbm_header_t	h;	/* DB_USER_READ/WRITE/PUSH */

	char		dbf[OBJSTORE_NAME_MAX];
	/* The name of the user DB to read or write. */
	dbm_size_t	objCount; /* The number of user records to follow. */
	dbm_ur_t	first;	/* The first user record. */

	// If objCount > 1, then what immediately follows <first> is the
	// next dbm_ur_t.  That is, the second UR is appended to the first,
	// the third is appended to the second, etc.

} dbm_user_req_t;

// ------------------------------------------------------------
// Structures which hold objects
// ------------------------------------------------------------
typedef struct
{
	dbm_recno_t	recno;	// The record number

} dbm_object_t;

typedef struct
{
	uint8_t		uid[digestSize];
	dbm_size_t	objCount;
	// If objCount == 0, get /all/ this user's objects.
	dbm_recno_t	first;	// The first record number.

	// If objCount > 1, then what immediately follows <first> is
	// the next dbm_recno_t.  That is, the second record number is
	// appended to the first, the third is appended to the second, etc.

} dbm_uo_req_t;

typedef struct
{
	dbm_header_t	h;	/* DB_OBJECT_READ */

	char		name[OBJSTORE_NAME_MAX];
	dbm_size_t	uorCount;
	dbm_uo_req_t	first;

	// If uorCount > 1, then what immediately follows <first> is
	// the next dbm_uo_req_t.  That is, the second request is
	// appended to the first, the third is appended to the second, etc.

} dbm_gather_t;

// ------------------------------------------------------------
//
// Here is a complete DB_OBJECT_PUSH
//
// +------------------------------------+-------
// | dbm_op_t		type;		|
// +------------------------------------+
// | dbm_handle_t	handle;		|
// +------------------------------------+ - dbm_header_t [h]
// | dbm_flags_t	flags;		|
// +------------------------------------+
// | dbm_size_t		paramSize;	|
// +------------------------------------+-------
// | char		uid[20]		|
// +- - - - - - - - - - - - - - - - - - +
// +- - - - - - - - - - - - - - - - - - +
// +- - - - - - - - - - - - - - - - - - +
// +- - - - - - - - - - - - - - - - - - +
// +------------------------------------+
// | dbm_size_t		objCount;	|
// +------------------------------------+-------
// | dbm_recno_t	recno;		|
// +- - - - - - - - - - - - - - - - - - + - dbm_datum_t [first]
// |					|
// +------------------------------------+
// | dbm_size_t		objSize;	|
// +------------------------------------+-------
// |					|
// | [the encrypted object record)]	|
// |					|
// +------------------------------------+-------
//
typedef struct
{
	dbm_recno_t	recno;
	dbm_size_t	objSize;

	// What immediately follows <length> is the actual datum,
	// i.e., the object to be read or written.

} dbm_datum_t;

typedef struct
{
	dbm_header_t	h;	/* DB_OBJECT_WRITE/PUSH */

	uint8_t		dbf[OBJSTORE_NAME_MAX];
	uint8_t		uid[digestSize];
	dbm_size_t	objCount;
	dbm_datum_t	first;

	// If objCount > 1, then what immediately follows <first> is
	// the next dbm_datum_t.  That is, the second datum is
	// appended to the first, the third is appended to the second, etc.

} dbm_data_t;

// ------------------------------------------------------------
// Tags are used by the audit log functions.
// The first 16 bytes belong to the scakiod.
// The last 16 bytes belong to the device.
// ------------------------------------------------------------
typedef struct
{				/* In network byte order */
	uint32_t	host1; 	/* Reserved by the scakiod. */
	uint32_t	timestamp;
	uint32_t	host3; 	/* Reserved by the scakiod. */
	uint32_t	host4;	/* Reserved by the scakiod. */
	uint32_t	dev1;	/* The first set of tags. */
	uint32_t	dev2;	/* The second set of tags (unused) */
	uint32_t	dev3;	/* The third set of tags (unused) */
	uint32_t	sn;	/* The originating card's serial number. */

} dbm_tags_t;

typedef struct
{
	dbm_datum_t	datum;	/* The record number & size */
	dbm_tags_t	tags;	/* All the tags. */

	// What immediately follows <tags> is the log message,
	// padded to the nearest multiple of 4 bytes.

} dbm_log_hdr_t;

// ------------------------------------------------------------
//
// Here is a complete DB_LOG_PUSH
//
// +------------------------------------+-------
// | dbm_op_t		type;		|
// +------------------------------------+
// | dbm_handle_t	handle;		|
// +------------------------------------+ - dbm_header_t [h]
// | dbm_flags_t	flags;		|
// +------------------------------------+
// | dbm_size_t		paramSize;	|
// +------------------------------------+-------
// | char		uid[20]		| (ignored)
// +- - - - - - - - - - - - - - - - - - +
// +- - - - - - - - - - - - - - - - - - +
// +- - - - - - - - - - - - - - - - - - +
// +- - - - - - - - - - - - - - - - - - +
// +------------------------------------+
// | dbm_size_t		objCount;	|
// +------------------------------------+-------
// | dbm_recno_t	recno;		|
// +- - - - - - - - - - - - - - - - - - + - dbm_datum_t [first]
// |					|
// +------------------------------------+
// +- - - - - - - - - - - - - - - - - - +
// |			timestamp	|
// +- - - - - - - - - - - - - - - - - - +
// +- - - - - - - - - - - - - - - - - - +
// +- - - - - - - - - - - - - - - - - - + - dbm_tags_t
// |			tags1		|
// +- - - - - - - - - - - - - - - - - - +
// +- - - - - - - - - - - - - - - - - - +
// +- - - - - - - - - - - - - - - - - - +
// +------------------------------------+-------
// |					|
// |   [the text of the log message]	|
// |					|
// +------------------------------------+-------
//
typedef struct
{
	dbm_header_t	h;	/* DB_RENAME */

	char		name[OBJSTORE_NAME_MAX];
		/* The current name for the database */
	char		domain[DOMID_NAME_MAX];
		/* The name of the domain, i.e., its hostname.	*/
	char		newname[OBJSTORE_NAME_MAX];
		/* The new name for the database */
} dbm_rename_t;

typedef union
{
	dbm_header_t	h;	/* DB_STANDBY/RESPONSE */
	dbm_hello_t	hello;	/* DB_HELLO */
	dbm_init_t	init;	/* DB_INIT */
	dbm_handshake_t	size;	/* DB_HANDSHAKE */
	dbm_file_req_t	file;	/* DB_FILE_READ/WRITE/PUSH */
	dbm_user_req_t	user;	/* DB_USER_READ/WRITE/PUSH */
	dbm_gather_t	in;	/* DB_OBJECT_READ */
	dbm_data_t	out;	/* DB_OBJECT_WRITE/PUSH */
	dbm_rename_t	rename;	/* DB_RENAME */

} dbm_prim_t;

/*
 * MCA inter-domain communication header
 * used to carry routing info for admin
 * messages across domains.
 */

#define	SERVICE_DOMID	0

typedef uint64_t	mca_domain_t;
typedef int32_t		mca_channel_t;

typedef struct mca_idc_hdr {
	mca_domain_t	domId;
	mca_channel_t	chanId;
	uint32_t	magic;	/* pad to 64-bit alignment */
} mca_idc_hdr_t;

#define	MCA_IDC_MAGIC	0xdeaffeed

#define	MCA_IDC_SZ (sizeof (mca_idc_hdr_t))


/*
 * Size of dbm_prim_t buf - leave room for driver supplied IDC header
 * We set PRIM_BUFSIZE to 60K to workaround an x86 limitation.
 * Since PRIME_BUFSIZE is used by FW/Deriver/scamgr, it should always be
 * 60K for x86/sparc mix match.
 * Note: 0xefff (which is 60K - 1) is the max packet.
 */
#define	PRIM_BUFSIZE		((0xefff) - MCA_IDC_SZ)



#define	MAX_DBM_PAYLOAD	(PRIM_BUFSIZE - sizeof (dbm_prim_t))

typedef struct {

	mca_idc_hdr_t	idc;
	dbm_header_t	h;

} dbm_preamble_t;

#ifdef	__cplusplus
}
#endif

#endif /* _OS_API_H */
