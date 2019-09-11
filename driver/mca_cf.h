/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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

#ifndef	_SYS_MCA_CF_H
#define	_SYS_MCA_CF_H

#pragma ident	"@(#)mca_cf.h	1.8	08/08/13 SMI"

#ifdef LINUX
#include <linux/types.h>
#include <linux/spinlock.h>
#include <mca.h>
#include <common.h>
#include <spi.h>
#include <mca_table.h>
#else
#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/mca.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>
#include <sys/mca_table.h>
#include <sys/mca_fs_internal.h>

#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Mars - pure cryptographic acceleration + secure keystore
 *
 * Note: Everything in this file is private to the Mars device
 */

#ifdef	_KERNEL


typedef struct mca_sessiontable	mca_sessiontable_t;

/*
 * Extended Provider Info
 */
#define	MCA_MANUFACTURER_ID		"SUNWmca"
#define	MCA_MODEL			"sca6000"

/*
 * PKCS#11 v2.11 Attribute Type
 */
#define	CPGA_CLASS		0x00000000
#define	CPGA_TOKEN		0x00000001
#define	CPGA_PRIVATE		0x00000002
#define	CPGA_LABEL		0x00000003
#define	CPGA_APPLICATION	0x00000010
#define	CPGA_VALUE		0x00000011
#define	CPGA_OBJECT_ID		0x00000012
#define	CPGA_CERTIFICATE_TYPE	0x00000080
#define	CPGA_ISSUER		0x00000081
#define	CPGA_SERIAL_NUMBER	0x00000082
#define	CPGA_AC_ISSUER		0x00000083
#define	CPGA_OWNER		0x00000084
#define	CPGA_ATTR_TYPES		0x00000085
#define	CPGA_TRUSTED		0x00000086
#define	CPGA_KEY_TYPE		0x00000100
#define	CPGA_SUBJECT		0x00000101
#define	CPGA_ID			0x00000102
#define	CPGA_SENSITIVE		0x00000103
#define	CPGA_ENCRYPT		0x00000104
#define	CPGA_DECRYPT		0x00000105
#define	CPGA_WRAP		0x00000106
#define	CPGA_UNWRAP		0x00000107
#define	CPGA_SIGN		0x00000108
#define	CPGA_SIGN_RECOVER	0x00000109
#define	CPGA_VERIFY		0x0000010A
#define	CPGA_VERIFY_RECOVER	0x0000010B
#define	CPGA_DERIVE		0x0000010C
#define	CPGA_START_DATE		0x00000110
#define	CPGA_END_DATE		0x00000111
#define	CPGA_MODULUS		0x00000120
#define	CPGA_MODULUS_BITS	0x00000121
#define	CPGA_PUBLIC_EXPONENT	0x00000122
#define	CPGA_PRIVATE_EXPONENT	0x00000123
#define	CPGA_PRIME_1		0x00000124
#define	CPGA_PRIME_2		0x00000125
#define	CPGA_EXPONENT_1		0x00000126
#define	CPGA_EXPONENT_2		0x00000127
#define	CPGA_COEFFICIENT	0x00000128
#define	CPGA_PRIME		0x00000130
#define	CPGA_SUBPRIME		0x00000131
#define	CPGA_BASE		0x00000132
#define	CPGA_PRIME_BITS		0x00000133
#define	CPGA_SUB_PRIME_BITS	0x00000134
#define	CPGA_VALUE_BITS		0x00000160
#define	CPGA_VALUE_LEN		0x00000161
#define	CPGA_EXTRACTABLE	0x00000162
#define	CPGA_LOCAL		0x00000163
#define	CPGA_NEVER_EXTRACTABLE	0x00000164
#define	CPGA_ALWAYS_SENSITIVE	0x00000165
#define	CPGA_KEY_GEN_MECHANISM	0x00000166
#define	CPGA_MODIFIABLE		0x00000170
#define	CPGA_EC_PARAMS		0x00000180
#define	CPGA_EC_POINT		0x00000181
#define	CPGA_SECONDARY_AUTH	0x00000200
#define	CPGA_AUTH_PIN_FLAGS	0x00000201
#define	CPGA_HW_FEATURE_TYPE	0x00000300
#define	CPGA_RESET_ON_INIT	0x00000301
#define	CPGA_HAS_RESET		0x00000302
#define	CPGA_VENDOR_DEFINED	0x80000000
#define	CPGA_SUNW_SESSION	0x81000001
#define	CPGA_SUNW_KEY_SCHED	0x81000003

/*
 * PKCS#11 v2.11 Object Type
 */
#define	CPGO_DATA		0x00000000
#define	CPGO_CERTIFICATE	0x00000001
#define	CPGO_PUBLIC_KEY		0x00000002
#define	CPGO_PRIVATE_KEY	0x00000003
#define	CPGO_SECRET_KEY		0x00000004
#define	CPGO_HW_FEATURE		0x00000005
#define	CPGO_DOMAIN_PARAMETERS	0x00000006
#define	CPGO_VENDOR_DEFINED	0x80000000

/*
 * PKCS#11 v2.11 Certificate Type
 */
#define	KCLC_X_509		0x00000000
#define	KCLC_X_509_ATTR_CERT	0x00000001
#define	KCLC_VENDOR_DEFINED	0x80000000

/*
 * PKCS#11 v2.11 Key Type
 */
#define	CPGK_RSA		0x00000000
#define	CPGK_DSA		0x00000001
#define	CPGK_DH			0x00000002
#define	CPGK_EC			0x00000003
#define	CPGK_X9_42_DH		0x00000004
#define	CPGK_KEA		0x00000005
#define	CPGK_GENERIC_SECRET	0x00000010
#define	CPGK_RC2		0x00000011
#define	CPGK_RC4		0x00000012
#define	CPGK_DES		0x00000013
#define	CPGK_DES2		0x00000014
#define	CPGK_DES3		0x00000015
#define	CPGK_CAST		0x00000016
#define	CPGK_CAST3		0x00000017
#define	CPGK_CAST128		0x00000018	/* CAST128=CAST5 */
#define	CPGK_RC5		0x00000019
#define	CPGK_IDEA		0x0000001A
#define	CPGK_SKIPJACK		0x0000001B
#define	CPGK_BATON		0x0000001C
#define	CPGK_JUNIPER		0x0000001D
#define	CPGK_CDMF		0x0000001E
#define	CPGK_AES		0x0000001F
#define	CPGK_VENDOR_DEFINED	0x80000000
#define	CPGK_FS			FS_KEY



/*
 * Function
 */

/* Provider access macros */

#define	MCA_PROVIDER2MCA(x) (((mca_provider_private_t *)x)->mp_mca)
#define	MCA_PROVIDER2KS(x) (((mca_provider_private_t *)x)->mp_ks)
#define	MCA_CTX2PRIVATE(ctx) \
	((mca_provider_private_t *)(((crypto_ctx_t *)(ctx))->cc_provider))
#define	MCA_CTX2MCA(ctx) \
	(MCA_CTX2PRIVATE(ctx)->mp_mca)
#define	MCA_CTX2KS(ctx) \
	(MCA_CTX2PRIVATE(ctx)->mp_ks)

#define	MCA_PROVIDER2SESSTBL(x) \
	(((mca_provider_private_t *)x)->mp_sessiontable)

#define	MCA_NOTIFY_BUSY(ring) \
    crypto_provider_notification( \
	((mca_ring_t *)ring)->mr_provinfo.mp_provhandle, \
	CRYPTO_PROVIDER_BUSY);
#define	MCA_NOTIFY_READY(ring) \
    crypto_provider_notification( \
	((mca_ring_t *)ring)->mr_provinfo.mp_provhandle, \
	CRYPTO_PROVIDER_READY);
#define	MCA_NOTIFY_FAILURE(ring) \
    crypto_provider_notification( \
	((mca_ring_t *)ring)->mr_provinfo.mp_provhandle, \
	CRYPTO_PROVIDER_FAILED);

/*
 * `in` is always copied to mr_tmpin, and mr_in points to mr_tmpin.
 * `in` must not be NULL.
 * `out` can be NULL.
 */
#define	MCA_SET_REQ_DATA(reqp, in, out) \
	if (in) { \
		reqp->mr_tmpin = *in; \
		reqp->mr_in = &reqp->mr_tmpin; \
	} else { \
		reqp->mr_in = NULL; \
	} \
	if (in == out) { \
		reqp->mr_out = in; \
	} else { \
		reqp->mr_out = out; \
	} \
	if (reqp->mr_out != NULL) { \
		reqp->mr_out->cd_length = 0; \
	}

#define	MCA_GET_MISCDATA(data, ctx, len) \
	if (data) { \
		if (((crypto_data_t *)(data))->cd_miscdata != NULL) { \
			bcopy(((crypto_data_t *)(data))->cd_miscdata, \
			    ((mca_privatectx_t *)(ctx))->mc_shortparam, len); \
			((mca_privatectx_t *)(ctx))->mc_shortparamlen = len; \
		} \
	}

/* logical session indicator */
#define	MCA_LOGICAL_SESSION	(1 << 30)

struct mca_sessiontable {
	kmutex_t	mst_lock;
	mca_table_t	mst_table;
};

/*
 * Find Object Context
 */
typedef struct mca_findobject {
	int	maxobjects;
	int	numobjects;
	int	objectsreturned;
} mca_findobject_t;


#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MCA_CF_H */
