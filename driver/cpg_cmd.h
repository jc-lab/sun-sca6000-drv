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

#ifndef _CPG_CMD_H
#define	_CPG_CMD_H

#pragma ident	"@(#)cpg_cmd.h	1.7	07/07/30 SMI"

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

/*
 * The following mask is used to extract the actual command
 */
#define	CMD_MASK		0xffff

/*
 * Operations for CB (bulk stuff).
 */
#define	CMD_IPSEC		0x0	/* IPsec packet processing */
#define	CMD_SSLMAC		0x1	/* SSL HMAC processing */
#define	CMD_TLSMAC		0x2	/* TLS HMAC processing */
#define	CMD_3DESENC		0x3	/* raw 3DES encryption */
#define	CMD_3DESDEC		0x4	/* raw 3DES decryption */
#define	CMD_RC4			0x5	/* ARCFOUR procesing */
#define	CMD_MD5			0x6	/* Pure MD5 hash processing */
#define	CMD_SHA1		0x7	/* Pure SHA1 hash processing */
#define	CMD_AESCBCENC		0x8	/* AES CBC encryption */
#define	CMD_AESCBCDEC		0x9	/* AES CBC decryption */
#define	CMD_RC2ENC		0xA	/* RC2 CBC encryption */
#define	CMD_RC2DEC		0xB	/* RC2 CBC decryption */
#define	CMD_AESCTRENC		0xC	/* AES CTR encryption */
#define	CMD_AESCTRDEC		0xD	/* AES CTR decryption */
#define	CMD_SHA512		0xE	/* Pure SHA512 hash processing */
/*
 * Operations for CA (assymetric).
 */
#define	CMD_DHPAIRGEN		0x10	/* DH public key generation */
#define	CMD_DHDERIVE		0x11	/* DH shared secret generation */
#define	CMD_RSAPUB		0x12	/* RSA public key operation */
#define	CMD_RSAPRV		0x13	/* RSA private key operation */
#define	CMD_DSASIGN		0x14	/* DSA signing operation */
#define	CMD_DSAVERIFY		0x15	/* DSA verification operation */
#define	CMD_RNGDIRECT		0x16	/* Direct access to the RNG */
#define	CMD_RNGSHA1		0x17	/* RNG output processed by SHA1 */
#define	CMD_RSAPADENC		0x18	/* RSA_PKCS #1 encrypt */
#define	CMD_RSAPADDEC		0x19	/* RSA_PKCS #1 decrypt */
#define	CMD_RSAPADSIGN		0x1A	/* RSA_PKCS #1 sign */
#define	CMD_RSAPADVRFY		0x1B	/* RSA PKCS #1 verify */
#define	CMD_ECPAIRGEN		0x1C	/* EC key pair generation */
#define	CMD_ECDHDERIVE		0x1D	/* EC DH key derivation */
#define	CMD_ECDSASIGN		0x1E	/* EC DSA sign */
#define	CMD_ECDSAVERIFY		0x1F	/* EC DSA verify */

/*
 * Operations for OM (object management).
 */
#define	CMD_LOGIN		0x20	/* Login */
#define	CMD_SETPASS		0x21	/* Change password */
#define	CMD_ENUMERATE_KEYS	0x22	/* Enumerate persistent keys */
#define	CMD_RETRIEVE_KEY	0x23	/* Get attributes for key */
#define	CMD_DELETE_KEY		0x24	/* Delete a key */
#define	CMD_CREATE_KEY		0x25	/* Create a key */
#define	CMD_MODIFY_KEY		0x26	/* Modify a key */
#define	CMD_COPY_KEY		0x27	/* Copy a key */
/*
 * Key generation.
 */
#define	CMD_KEYGEN_DES		0x30	/* Generate a DES key */
#define	CMD_KEYGEN_DES2		0x31	/* Generate a 2DES key */
#define	CMD_KEYGEN_DES3		0x32	/* Generate a 3DES key */
#define	CMD_KEYGEN_AES16	0x33	/* Generate a AES key */
#define	CMD_KEYGEN_AES24	0x34	/* Generate a AES key */
#define	CMD_KEYGEN_AES32	0x35	/* Generate a AES key */
/*
 * Key pair generation.
 */
#define	CMD_PAIRGEN_RSA		0x40	/* Generate an RSA key pair */
#define	CMD_PAIRGEN_DSA		0x41	/* Generate a DSA key pair */
/*
 * Key Wrap
 */
#define	CMD_WRAP		0x50	/* wrap */
#define	CMD_UNWRAP		0x51	/* unwrap */

#define	CMD_FIN_SVCS		0x60	/* financial services */

#define	CMD_HASH_INIT		0x70
#define	CMD_HASH_UPDATE		0x71
#define	CMD_HASH_KEY		0x72
#define	CMD_HASH_FINAL		0x73

/*
 * HMAC operations
 */
#define	CMD_HMAC_MD5		0x74	/* MD5 HMAC processing */
#define	CMD_HMAC_SHA1		0x75	/* SHA1 HMAC processing */
#define	CMD_HMAC_SHA512		0x76	/* SHA512 HMAC processing */
#define	CMD_HMAC_INIT		0x77	/* HMAC Init processing */
#define	CMD_HMAC_UPDATE		0x78	/* HMAC Update processing */
#define	CMD_HMAC_FINAL		0x79	/* HMAC Final processing */

#define	CPG_CMD_BASE		0x800
#define	CPG_CMD_DBM		(CPG_CMD_BASE + 1)

/*
 * Higher 16 bits are used to narraw down the type of operation.
 * CMD_HI_MASK is used to extract the supplement information
 * CMD_HI_SVMASK is used to extract the sign/verify code
 */
#define	CMD_HI_MASK		0xffff0000
#define	CMD_HI_SVMASK		0x001e0000

#define	CMD_HI_SINGLE		0x00010000 /* Single DES key operation */
#define	CMD_HI_SIGN		0x00020000 /* RSA Sign operation */
#define	CMD_HI_SIGNR		0x00040000 /* RSA SignRecover operation */
#define	CMD_HI_VRFY		0x00080000 /* RSA Verify operation */
#define	CMD_HI_VRFYR		0x00100000 /* RSA VerifyRecover operation */
#define	CMD_HI_KCF_INPLACE	0x00200000 /* Inplace for kCF */
#define	CMD_HI_PAD		0x00400000 /* Used to tag _PAD mode */
#define	CMD_HI_ADDPAD		0x00800000 /* Apply PADDING for this request */
#define	CMD_HI_REMOVEPAD	0x01000000 /* Remove PADDING for this request */
#define	CMD_HI_MULTI_PART	0x02000000 /* Multi-Part operation */
#define	CMD_HI_ATOMIC		0x04000000 /* Atomic operation */

#ifdef	__cplusplus
}
#endif

#endif /* _CPG_CMD_H */
