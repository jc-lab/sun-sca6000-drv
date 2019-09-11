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

#pragma ident	"@(#)mca_keygen.c	1.24	07/08/17 SMI"

/*
 * Mars - pure cryptographic acceleration + secure keystore
 */

#ifdef LINUX
#include <linux/types.h>
#include <asm/div64.h>
#include "sol2lin.h"
#include "mca.h"
#include "mca_hw.h"
#else
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/atomic.h>
#include <sys/mca.h>
#include <sys/mca_hw.h>
#endif

/*
 * Key generation implementation.
 */

static void keygen_done(mca_request_t *);
static void pairgen_done(mca_request_t *);

/*
 * This function makes sure that the template passed by the caller
 * does not contain an inconsistent object_class and key_type.
 * Note: argclass and argkeytype is the expected object_class and key_type
 * for the keygen mechanism
 */
static int
check_keygen_template(cpg_attr_t *attr, uint32_t argclass,
    uint32_t argkeytype)
{
	int		rv;
	uint32_t	class, keytype;

	/*
	 * Check if CPGA_CLASS was supplied by the caller.
	 * If so, the class is checked against the expected class.
	 * If not, the expected class is added to the template.
	 */
	rv = cpg_attr_lookup_uint32(attr, CPGA_CLASS, &class);
	if (rv != CRYPTO_SUCCESS) {
		/*
		 * The CLASS attirbute does not exist in the template.
		 * Fluff the template.
		 */
		rv = cpg_attr_add_uint32(attr, CPGA_CLASS, argclass, 0);
		if (rv != CRYPTO_SUCCESS) {
			DBG(NULL, DCHATTY, "check_keygen_template: "
			    "failed to add CLASS");
			return (rv);
		}
	} else {
		if (class != argclass) {
			/* inconsistency between class and keygen mech */
			DBG(NULL, DCHATTY, "check_keygen_template: CLASS "
			    "0x%x was in the template (0x%x expected)",
			    class, argclass);
			return (CRYPTO_TEMPLATE_INCONSISTENT);
		}
	}

	/*
	 * Check if CPGA_KEY_TYPE was supplied by the caller.
	 * If so, the keytype is checked against the expected keytype.
	 * If not, the expected keytype is added to the template.
	 */
	rv = cpg_attr_lookup_uint32(attr, CPGA_KEY_TYPE, &keytype);
	if (rv != CRYPTO_SUCCESS) {
		/*
		 * The KEY_TYPE attirbute does not exist in the template.
		 * Fluff the template.
		 */
		rv = cpg_attr_add_uint32(attr, CPGA_KEY_TYPE, argkeytype, 0);
		if (rv != CRYPTO_SUCCESS) {
			DBG(NULL, DCHATTY, "check_keygen_template: "
			    "failed to add KEY_TYPE");
			return (rv);
		}
	} else {
		if (keytype != argkeytype) {
			/* inconsistency between keytype and keygen mech */
			DBG(NULL, DCHATTY, "check_keygen_template: KEY_TYPE "
			    "0x%x was in the template (0x%x expected)",
			    keytype, argkeytype);
			return (CRYPTO_TEMPLATE_INCONSISTENT);
		}
	}

	return (CRYPTO_SUCCESS);
}

/*
 * Set up for symmetric keys.  *flagsp points to the values for enc,
 * dec, sign, vrfy, wrap, unwrap, derive.  It gets set to all flags.
 * The template is presumed to have been checked for consistency and
 * fluffed.
 */
static int
keygen_flags(cpg_attr_t *template, uint32_t *flagsp, uint32_t p11keytype)
{
	int		rv;
	uint8_t		token = FALSE;
	uint8_t		priv = FALSE;
	uint8_t		sens = FALSE;
	uint8_t		extr = FALSE;

	rv = check_keygen_template(template, CPGO_SECRET_KEY, p11keytype);
	if (rv != CRYPTO_SUCCESS) {
		DBG(NULL, DCHATTY, "check_keygen_template failed: "
		    "class[0x%x] keytype[0x%x]", CPGO_SECRET_KEY, p11keytype);
		return (rv);
	}


	if (cpg_attr_add_uint8(template, CPGA_LOCAL, 1, 0)) {
		return (CRYPTO_HOST_MEMORY);
	}

	(void) cpg_attr_lookup_uint8(template, CPGA_TOKEN, &token);
	(void) cpg_attr_lookup_uint8(template, CPGA_PRIVATE, &priv);
	(void) cpg_attr_lookup_uint8(template, CPGA_SENSITIVE, &sens);
	(void) cpg_attr_lookup_uint8(template, CPGA_EXTRACTABLE, &extr);

	*flagsp = (token ? KEYFLAG_PERSIST : 0) |
	    (sens ? (KEYFLAG_SENSITIVE | KEYFLAG_ALWAYSSENS) : 0) |
	    (extr ? 0 : (KEYFLAG_NOWRAP | KEYFLAG_ALWAYSNOWRAP)) |
	    (priv ? KEYFLAG_PRIVATE : 0) |
	    KEYFLAG_ENCRYPT | KEYFLAG_DECRYPT | KEYFLAG_SIGN |
	    KEYFLAG_VERIFY | KEYFLAG_WRAP | KEYFLAG_UNWRAP |
	    KEYFLAG_DERIVE | KEYFLAG_LOCAL;


	return (CRYPTO_SUCCESS);
}

/*
 * Set up for public keys.
 */
static int
pubgen_flags(cpg_attr_t *template, uint32_t *flagsp, uint32_t type)
{
	uint8_t		token = FALSE;
	uint8_t		priv = TRUE;
	int		rv;

	/* make sure that templates are consistent with the mechanism */
	rv = check_keygen_template(template, CPGO_PUBLIC_KEY, type);
	if (rv != CRYPTO_SUCCESS) {
		return (rv);
	}


	if (cpg_attr_add_uint8(template, CPGA_LOCAL, 1, 0)) {
		return (CRYPTO_HOST_MEMORY);
	}

	(void) cpg_attr_lookup_uint8(template, CPGA_TOKEN, &token);
	(void) cpg_attr_lookup_uint8(template, CPGA_PRIVATE, &priv);

	*flagsp = (token ? KEYFLAG_PERSIST : 0) | KEYFLAG_ENCRYPT |
	    KEYFLAG_VERIFY | KEYFLAG_WRAP |
	    KEYFLAG_VERIFYR | KEYFLAG_DERIVE |
	    KEYFLAG_LOCAL | (priv ? KEYFLAG_PRIVATE : 0);

	return (CRYPTO_SUCCESS);
}

/*
 * Set up for private keys.  *flagsp points to the values for enc,
 * dec, sign, vrfy, wrap, unwarp, derive.  It gets set to all flags.
 */
static int
prvgen_flags(cpg_attr_t *template, uint32_t *flagsp, uint32_t type)
{
	uint8_t		token = FALSE;
	uint8_t		priv = FALSE;
	uint8_t		sens = FALSE;
	uint8_t		extr = FALSE;
	int		rv;

	/* make sure that templates are consistent with the mechanism */
	rv = check_keygen_template(template, CPGO_PRIVATE_KEY, type);
	if (rv != CRYPTO_SUCCESS) {
		return (rv);
	}

	if (cpg_attr_add_uint8(template, CPGA_LOCAL, 1, 0)) {
		return (CRYPTO_HOST_MEMORY);
	}

	(void) cpg_attr_lookup_uint8(template, CPGA_TOKEN, &token);
	(void) cpg_attr_lookup_uint8(template, CPGA_PRIVATE, &priv);
	(void) cpg_attr_lookup_uint8(template, CPGA_SENSITIVE, &sens);
	(void) cpg_attr_lookup_uint8(template, CPGA_EXTRACTABLE, &extr);

	*flagsp = (token ? KEYFLAG_PERSIST : 0) |
	    (sens ? KEYFLAG_SENSITIVE : 0) | KEYFLAG_DECRYPT  |
	    (extr ? 0 : (KEYFLAG_NOWRAP | KEYFLAG_ALWAYSNOWRAP)) |
	    KEYFLAG_SIGN | KEYFLAG_UNWRAP |
	    KEYFLAG_DERIVE | KEYFLAG_SIGNR |
	    KEYFLAG_LOCAL | (priv ? KEYFLAG_PRIVATE : 0);

	return (CRYPTO_SUCCESS);
}

static int
keygencmd2keytype(uint32_t cmd, int *mkeytype, uint32_t *p11keytype)
{
	switch (cmd & CMD_MASK) {
	case CMD_KEYGEN_DES:
		*mkeytype = KEYTYPE_DES;
		*p11keytype = CPGK_DES;
		return (CRYPTO_SUCCESS);
	case CMD_KEYGEN_DES2:
		*mkeytype = KEYTYPE_DES2;
		*p11keytype = CPGK_DES2;
		return (CRYPTO_SUCCESS);
	case CMD_KEYGEN_DES3:
		*mkeytype = KEYTYPE_DES3;
		*p11keytype = CPGK_DES3;
		return (CRYPTO_SUCCESS);
	case CMD_KEYGEN_AES16:
	case CMD_KEYGEN_AES24:
	case CMD_KEYGEN_AES32:
		*mkeytype = KEYTYPE_AES;
		*p11keytype = CPGK_AES;
		return (CRYPTO_SUCCESS);
	default:
		return (CRYPTO_TEMPLATE_INCONSISTENT);
	}
}

int
mca_keygen(mca_t *mca, mca_keystore_t *mks, mca_session_t *session,
    cpg_attr_t *template, uint32_t *id, uint32_t cmd,
    crypto_req_handle_t *cfreq)
{
	uint32_t	flags;
	mca_request_t	*reqp;
	int		rv;
	uint32_t	residlen;
	int		mkeytype;
	uint32_t	p11keytype;

	DBG(mca, DENTRY, "mca_keygen -->");

	/* make sure that the template is consistent with the mechanism */
	if (keygencmd2keytype(cmd, &mkeytype, &p11keytype) != CRYPTO_SUCCESS) {
		return (CRYPTO_TEMPLATE_INCONSISTENT);
	}
	if ((rv = keygen_flags(template, &flags, p11keytype))
	    != CRYPTO_SUCCESS) {
		return (rv);
	}

	if ((reqp = mca_getreq(&mca->mca_ring_om)) == NULL) {
		return (CRYPTO_BUSY);
	}

	/*
	 * If we are generating a key which will be managed by the
	 * firmware (either persistent or sensitive), we have to have
	 * a keystore, and (if key is persistent) be authenticated.
	 */
	if (flags & (KEYFLAG_PERSIST | KEYFLAG_PRIVATE)) {
		rv = mca_get_session_cred(session, reqp->mr_cred);
		if (rv != CRYPTO_SUCCESS) {
			mca_freereq(reqp);
			return (rv);
		}
	}

	if (flags & (KEYFLAG_PERSIST | KEYFLAG_SENSITIVE)) {
		if (mks == NULL) {
			DBG(mca, DWARN, "device has no keystore?");
			mca_freereq(reqp);
			return (CRYPTO_GENERAL_ERROR);
		}
	}

	reqp->mr_cmd = cmd;

	residlen = MAX_KEY_SIZE;
	rv = cpgattr2keyhead4keygen(template, mkeytype, reqp->mr_ibuf_kaddr,
	    &residlen);
	if (rv != CRYPTO_SUCCESS) {
		goto exit;
	}

	if (flags & KEYFLAG_PERSIST) {
		mca_user_wrlock(session->ms_user);
		reqp->mr_flags = MRF_TASKQ | MRF_KSUPDATE;
		reqp->mr_timeout = OMTIMEOUT;
	}

	if (residlen > reqp->mr_ibuf_sz) {
		MCA_TERMINATE_CHAINS(&reqp->mr_ibuf_chain, residlen);
		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_next_paddr = reqp->mr_ibuf_next_paddr;
		reqp->mr_in_len = residlen;
		reqp->mr_in_first_len = reqp->mr_ibuf_sz;
	} else {
		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_next_paddr = 0;
		reqp->mr_in_len = residlen;
		reqp->mr_in_first_len = residlen;
	}
	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_out_next_paddr = reqp->mr_obuf_next_paddr;
	reqp->mr_out_len = MAXPACKET;
	reqp->mr_out_first_len = reqp->mr_obuf_sz;

	reqp->mr_job_stat = MS_KEYGENJOBS;
	reqp->mr_cf_req = cfreq;
	reqp->mr_key_flags[0] = flags;
	reqp->mr_callback = keygen_done;
	reqp->mr_session = session;
	reqp->mr_template[0] = template;
	reqp->mr_keyidp[0] = id;
	if (mks) {
		reqp->mr_dbm_handle = mca_ks_get_handle(mks, mca);
	}

	if (mca_isfips(mca)) {
		mca_setiv(reqp);
	}

	ddi_dma_sync(reqp->mr_ibuf_dmah, 0, residlen, DDI_DMA_SYNC_FORDEV);
	/* sync key dma for input/output chains */
	ddi_dma_sync(reqp->mr_key_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	rv = mca_start(reqp);

exit:
	if (rv != CRYPTO_QUEUED) {
		if (reqp->mr_flags & MRF_KSUPDATE) {
			mca_user_unlock(session->ms_user);
		}
		mca_freereq(reqp);
	}

	DBG(mca, DENTRY, "mca_keygen <--[0x%x]", rv);

	return (rv);
}

static void
keygen_done(mca_request_t *reqp)
{
	mca_t		*mca = reqp->mr_mca;
	cpg_attr_t	*attr = reqp->mr_template[0];
	uint16_t	keyflags;
	int		rv;
	int		residlen;
	mca_key_head_t	*keyhead;
	mca_key_t	*mkey = NULL;

	if (reqp->mr_errno != 0) {
		DBG(mca, DWARN, "keygen failed, dev err %d", reqp->mr_errno);
		rv = reqp->mr_errno;
		goto exit;
	}

	keyhead = (mca_key_head_t *)reqp->mr_obuf_kaddr;
	residlen = reqp->mr_resultlen;

	ddi_dma_sync(reqp->mr_obuf_dmah, 0, reqp->mr_resultlen,
	    DDI_DMA_SYNC_FORKERNEL);

	if (mca_isfips(mca)) {
		mca_ktkdecryptbuf(reqp);
	}

	keyflags = reqp->mr_key_flags[0];

	rv = mca_parse_key(attr, keyhead, residlen, keyflags, &mkey);
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DCHATTY, "keygen_done: mca_parse_key failed "
		    "with 0x%x", rv);
		rv = CRYPTO_FAILED;
		goto exit;
	}

	/*
	 * Add the key to the UKT. The key is marked INVALID, and this
	 * thread should hold the refcnt.
	 */
	if (keyflags & KEYFLAG_PERSIST) {
		rv = mca_register_key(reqp->mr_session->ms_user, mkey);
		if (rv != CRYPTO_SUCCESS) {
			mca_key_free(mkey);
			mkey = NULL;
			goto exit;
		}
	}

	/*
	 * Create the key in the SKT
	 * Note: Session refcnt is decremented by mca_add_key
	 */
	rv = mca_add_key(reqp->mr_session, mkey, reqp->mr_keyidp[0]);

exit:
	/* on the error exit, free the mca_key/template */
	if (rv != CRYPTO_SUCCESS) {
		if (mkey == NULL) {
			cpg_attr_free(attr);
		} else {
			mca_key_free(mkey);
		}
		mca_session_releaseref(reqp->mr_session, UNLOCKED);
	}

	if (reqp->mr_flags & MRF_KSUPDATE) {
		mca_user_unlock(reqp->mr_session->ms_user);
	}

	crypto_op_notification(reqp->mr_cf_req, rv);
	mca_freereq(reqp);
}

int
mca_rsagen(mca_t *mca, mca_session_t *session, cpg_attr_t *pubtemplate,
    cpg_attr_t *prvtemplate, uint32_t *pubid, uint32_t *prvid,
    crypto_req_handle_t *cfreq, mca_keystore_t *mks)
{
	uint32_t	pubflags, prvflags, comflags;
	uint32_t	inlen;
	mca_request_t	*reqp;
	int		rv;
	uint32_t	nbits, elen;
	uint8_t		*e;
	caddr_t		kaddr;
	uint32_t	residlen;
	uint64_t	factor;

	DBG(mca, DENTRY, "mca_rsagen -->");

	/* RSA keys support pretty much all of the operations */
	pubflags = KEYFLAG_ENCRYPT | KEYFLAG_VERIFY | KEYFLAG_VERIFYR |
	    KEYFLAG_WRAP;
	prvflags = KEYFLAG_DECRYPT | KEYFLAG_SIGN | KEYFLAG_SIGNR |
	    KEYFLAG_UNWRAP;

	if (((rv = pubgen_flags(pubtemplate, &pubflags, CPGK_RSA))
		!= CRYPTO_SUCCESS) ||
	    ((rv = prvgen_flags(prvtemplate, &prvflags, CPGK_RSA))
		!= CRYPTO_SUCCESS)) {
		return (rv);
	}

	if (cpg_attr_lookup_uint32(pubtemplate, CPGA_MODULUS_BITS, &nbits) ||
	    cpg_attr_lookup_uint8_array(pubtemplate, CPGA_PUBLIC_EXPONENT,
	    &e, &elen) != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "missing modbits or exponent in RSA keygen");
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	if ((nbits < RSA_MIN_KEY_LEN) || (nbits > RSA_MAX_KEY_LEN)) {
		/*
		 * HW cannot generate RSA key that is greater than
		 * RSA_MAX_KEY_LEN.
		 */
		DBG(mca, DWARN, "modulus bits[%u] out of range for "
		    "RSA keygen", nbits);
		return (CRYPTO_KEY_SIZE_RANGE);
	}

	comflags = pubflags | prvflags;

	if ((reqp = mca_getreq(&mca->mca_ring_om)) == NULL) {
		return (CRYPTO_BUSY);
	}

	/*
	 * If we are generating a persistent key or a private key, we
	 * have to be authenticated.
	 */
	if (comflags & (KEYFLAG_PERSIST | KEYFLAG_PRIVATE)) {
		rv = mca_get_session_cred(session, reqp->mr_cred);
		if (rv != CRYPTO_SUCCESS) {
			mca_freereq(reqp);
			return (rv);
		}
	}


	/*
	 * Ensure device has keystore capabilities. While SENSITIVE
	 * keys are not stored in the keystore, they do require the
	 * keyid component of the keystore structure, and master
	 * backup key support that come with the device's keystore.
	 */
	if (comflags & (KEYFLAG_PERSIST | KEYFLAG_SENSITIVE)) {
		if (mks == NULL) {
			DBG(mca, DWARN, "device has no keystore?");
			mca_freereq(reqp);
			return (CRYPTO_GENERAL_ERROR);
		}
	}

	/* set KS handle if one exists */
	if (mks) {
		reqp->mr_dbm_handle = mca_ks_get_handle(mks, mca);
	} else {
		reqp->mr_dbm_handle = MCA_KS_BAD_HANDLE;
	}

	reqp->mr_job_stat = MS_KEYGENJOBS;
	reqp->mr_cf_req = cfreq;
	reqp->mr_session = session;

	reqp->mr_key_flags[0] = pubflags;
	reqp->mr_key_flags[1] = prvflags;
	reqp->mr_template[0] = pubtemplate;
	reqp->mr_template[1] = prvtemplate;
	reqp->mr_keyidp[0] = pubid;
	reqp->mr_keyidp[1] = prvid;
	reqp->mr_callback = pairgen_done;

	reqp->mr_cmd = CMD_PAIRGEN_RSA;

	kaddr = reqp->mr_ibuf_kaddr;
	residlen = MAX_KEY_SIZE;

	rv = cpgattr2keyhead4keygen(pubtemplate, KEYTYPE_RSA_PUBLIC,
	    kaddr, &residlen);
	kaddr += PAD32(residlen);
	inlen = PAD32(residlen);
	residlen = MAX_KEY_SIZE - PAD32(residlen);
	if (rv == CRYPTO_SUCCESS) {
		rv = cpgattr2keyhead4keygen(prvtemplate, KEYTYPE_RSA_PRIVATE,
		    kaddr, &residlen);
		inlen += PAD32(residlen);
	}
	if (rv != CRYPTO_SUCCESS) {
		mca_freereq(reqp);
		return (rv);
	}

	if (comflags & KEYFLAG_PERSIST) {
		mca_user_wrlock(session->ms_user);
		reqp->mr_flags = MRF_TASKQ | MRF_KSUPDATE;
	}

	if (inlen > reqp->mr_ibuf_sz) {
		MCA_TERMINATE_CHAINS(&reqp->mr_ibuf_chain, inlen);
		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_next_paddr = reqp->mr_ibuf_next_paddr;
		reqp->mr_in_len = inlen;
		reqp->mr_in_first_len = reqp->mr_ibuf_sz;
	} else {
		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_next_paddr = 0;
		reqp->mr_in_len = inlen;
		reqp->mr_in_first_len = inlen;
	}
	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_out_next_paddr = reqp->mr_obuf_next_paddr;
	reqp->mr_out_len = MAXPACKET;
	reqp->mr_out_first_len = reqp->mr_obuf_sz;

	/*
	 * We assume that the time to generate a 256 bit is under 4
	 * seconds for a reasonable default.  Note that since we
	 * figure it takes 8x every time we double the number of bits,
	 * this means we have to wait up to 2048 secs for a 2048 bit
	 * key (or over 4 minutes, in other words).  If multiple 2K
	 * key pairs are generated, this can lead to many minutes
	 * before a device stall is detected.  There isn't really any
	 * good answer to this other than to improve the speed of the
	 * on-device key generation.
	 */
	reqp->mr_timeout = drv_usectohz(4 * SECOND);
	if (nbits > 256) {
		factor = 100 * nbits / 256;
		factor = reqp->mr_timeout * factor * factor * factor;
#ifdef LINUX
		/*
		 * Need to use do_div since 32 bit kernel does not have
		 * __udivdi3 function.
		 * Divide factor by 1,000,000. The result is in factor.
		 */
		(void) do_div(factor, 1000000);
		reqp->mr_timeout = (clock_t)factor;
#else
		reqp->mr_timeout = (clock_t)(factor / 1000000);
#endif
	}

	ddi_dma_sync(reqp->mr_ibuf_dmah, 0, inlen, DDI_DMA_SYNC_FORDEV);
	/* sync key dma for input/output chains */
	ddi_dma_sync(reqp->mr_key_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	if (mca_isfips(mca)) {
		mca_setiv(reqp);
	}

	if ((rv = mca_start(reqp)) != CRYPTO_QUEUED) {
		if (reqp->mr_flags & MRF_KSUPDATE) {
			mca_user_unlock(session->ms_user);
		}
		mca_freereq(reqp);
	}

	DBG(mca, DENTRY, "mca_rsagen <--[0x%x]", rv);

	return (rv);
}

int
mca_dsagen(mca_t *mca, mca_session_t *session, cpg_attr_t *pubtemplate,
    cpg_attr_t *prvtemplate, uint32_t *pubid, uint32_t *prvid,
    crypto_req_handle_t *cfreq, mca_keystore_t *mks)
{
	uint32_t	pubflags, prvflags, comflags;
	mca_request_t	*reqp;
	int		rv;
	uint32_t	pbits, plen, glen, qlen;
	uint8_t		*p, *g, *q;
	caddr_t		kaddr;
	uint32_t	residlen;
	uint32_t	inlen;

	DBG(mca, DENTRY, "mca_dsagen -->");

	pubflags = KEYFLAG_VERIFY;
	prvflags = KEYFLAG_SIGN;

	if (((rv = pubgen_flags(pubtemplate, &pubflags, CPGK_DSA))
		!= CRYPTO_SUCCESS) ||
	    ((rv = prvgen_flags(prvtemplate, &prvflags, CPGK_DSA))
		!= CRYPTO_SUCCESS)) {
		return (rv);
	}

	/* remove any bogus value attributes */
	(void) cpg_attr_delete_attribute(pubtemplate, CPGA_VALUE);
	(void) cpg_attr_delete_attribute(prvtemplate, CPGA_VALUE);

	if (cpg_attr_lookup_uint8_array(pubtemplate, CPGA_PRIME, &p, &plen) ||
	    cpg_attr_lookup_uint8_array(pubtemplate, CPGA_SUBPRIME, &q,
		&qlen) ||
	    cpg_attr_lookup_uint8_array(pubtemplate, CPGA_BASE, &g, &glen)) {
		DBG(mca, DWARN, "missing parts in DSA keygen");
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	pbits = mca_bitlen((caddr_t)p, plen);
	if ((pbits < DSA_MIN_KEY_LEN) || (pbits > DSA_MAX_KEY_LEN)) {
		/* Unsupported key length */
		DBG(NULL, DWARN, "pbits(%u) not in range", pbits);
		return (CRYPTO_KEY_SIZE_RANGE);
	}
	if ((mca_bitlen((caddr_t)q, qlen) != 160) ||
	    (mca_numcmp((caddr_t)g, glen, (caddr_t)p, plen) > 0) ||
	    (pbits % 64)) {
		DBG(mca, DWARN, "bad template attribute values in DSA keygen");
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}

	/* copy prime, subprime, and base to private template */
	if (cpg_attr_add_uint8_array(prvtemplate, CPGA_PRIME, p, plen,
	    0) ||
	    cpg_attr_add_uint8_array(prvtemplate, CPGA_SUBPRIME, q, qlen,
		0) ||
	    cpg_attr_add_uint8_array(prvtemplate, CPGA_BASE, g, glen,
		0)) {
		return (CRYPTO_HOST_MEMORY);
	}

	comflags = pubflags | prvflags;

	if ((reqp = mca_getreq(&mca->mca_ring_om)) == NULL) {
		return (CRYPTO_BUSY);
	}

	/*
	 * If we are generating a persistent key, we have to be authenticated.
	 */
	if (comflags & (KEYFLAG_PERSIST | KEYFLAG_PRIVATE)) {
		rv = mca_get_session_cred(session, reqp->mr_cred);
		if (rv != CRYPTO_SUCCESS) {
			mca_freereq(reqp);
			return (rv);
		}
		reqp->mr_timeout = OMTIMEOUT;
	}


	/*
	 * Ensure device has keystore capabilities. While SENSITIVE
	 * keys are not stored in the keystore, they do require the
	 * keyid component of the keystore structure, and master
	 * backup key support that come with the device's keystore.
	 */
	if (comflags & (KEYFLAG_PERSIST | KEYFLAG_SENSITIVE)) {
		if (mks == NULL) {
			DBG(mca, DWARN, "device has no keystore?");
			mca_freereq(reqp);
			return (CRYPTO_GENERAL_ERROR);
		}
	}

	/* set KS handle if one exists */
	if (mks) {
		reqp->mr_dbm_handle = mca_ks_get_handle(mks, mca);
	} else {
		reqp->mr_dbm_handle = MCA_KS_BAD_HANDLE;
	}


	reqp->mr_job_stat = MS_KEYGENJOBS;
	reqp->mr_cf_req = cfreq;
	reqp->mr_session = session;

	reqp->mr_key_flags[0] = pubflags;
	reqp->mr_key_flags[1] = prvflags;
	reqp->mr_template[0] = pubtemplate;
	reqp->mr_template[1] = prvtemplate;
	reqp->mr_keyidp[0] = pubid;
	reqp->mr_keyidp[1] = prvid;
	reqp->mr_callback = pairgen_done;

	reqp->mr_cmd = CMD_PAIRGEN_DSA;

	kaddr = reqp->mr_ibuf_kaddr;
	residlen = MAX_KEY_SIZE;

	/* pbits shouldn't change in the lines below! */
	rv = cpgattr2keyhead4keygen(pubtemplate, KEYTYPE_DSA_PUBLIC,
	    kaddr, &residlen);
	inlen = PAD32(residlen);
	kaddr += PAD32(residlen);
	residlen = MAX_KEY_SIZE - PAD32(residlen);
	if (rv == CRYPTO_SUCCESS) {
		rv = cpgattr2keyhead4keygen(prvtemplate, KEYTYPE_DSA_PRIVATE,
		    kaddr, &residlen);
		inlen += PAD32(residlen);
	}
	if (rv != CRYPTO_SUCCESS) {
		mca_freereq(reqp);
		return (rv);
	}

	if (comflags & KEYFLAG_PERSIST) {
		mca_user_wrlock(session->ms_user);
		reqp->mr_flags = MRF_TASKQ | MRF_KSUPDATE;
	}

	if (inlen > reqp->mr_ibuf_sz) {
		MCA_TERMINATE_CHAINS(&reqp->mr_ibuf_chain, inlen);
		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_next_paddr = reqp->mr_ibuf_next_paddr;
		reqp->mr_in_len = inlen;
		reqp->mr_in_first_len = reqp->mr_ibuf_sz;
	} else {
		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_next_paddr = 0;
		reqp->mr_in_len = inlen;
		reqp->mr_in_first_len = inlen;
	}
	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_out_next_paddr = reqp->mr_obuf_next_paddr;
	reqp->mr_out_len = MAXPACKET;
	reqp->mr_out_first_len = reqp->mr_obuf_sz;

	/*
	 * DSA key pair generation is fast (just a modular
	 * exponentiation, no actual primes are generated here), so we
	 * just assume default timings are adequate.
	 */
	ddi_dma_sync(reqp->mr_ibuf_dmah, 0, inlen, DDI_DMA_SYNC_FORDEV);
	/* sync key dma for input/output chains */
	ddi_dma_sync(reqp->mr_key_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	if (mca_isfips(mca)) {
		mca_setiv(reqp);
	}

	if ((rv = mca_start(reqp)) != CRYPTO_QUEUED) {
		if (reqp->mr_flags & MRF_KSUPDATE) {
			mca_user_unlock(session->ms_user);
		}
		mca_freereq(reqp);
	}

	DBG(mca, DENTRY, "mca_dsagen <--[0x%x]", rv);

	return (rv);
}

int
mca_dhgen(mca_t *mca, mca_session_t *session, cpg_attr_t *pubtemplate,
    cpg_attr_t *prvtemplate, uint32_t *pubid, uint32_t *prvid,
    crypto_req_handle_t *cfreq, mca_keystore_t *mks)
{
	uint32_t	pubflags, prvflags, comflags;
	mca_request_t	*reqp;
	int		rv;
	uint32_t	pbits, plen, glen, xbits;
	uint8_t		*p, *g;
	caddr_t		kaddr;
	uint32_t	residlen;
	uint32_t	inlen;

	DBG(mca, DENTRY, "mca_dhgen -->");

	pubflags = 0;
	prvflags = KEYFLAG_DERIVE;

	if (((rv = pubgen_flags(pubtemplate, &pubflags, CPGK_DH))
		!= CRYPTO_SUCCESS) ||
	    ((rv = prvgen_flags(prvtemplate, &prvflags, CPGK_DH))
		!= CRYPTO_SUCCESS)) {
		return (rv);
	}

	/* remove any bogus value attributes */
	(void) cpg_attr_delete_attribute(pubtemplate, CPGA_VALUE);
	(void) cpg_attr_delete_attribute(prvtemplate, CPGA_VALUE);

	if (cpg_attr_lookup_uint8_array(pubtemplate, CPGA_PRIME, &p, &plen) ||
	    cpg_attr_lookup_uint8_array(pubtemplate, CPGA_BASE, &g, &glen)) {
		DBG(mca, DWARN, "missing parts in DH keygen");
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	rv = cpg_attr_lookup_uint32(prvtemplate, CPGA_VALUE_BITS, &xbits);
	if (rv == CRYPTO_SUCCESS) {
		/* private length is give. Make sure it's less than plen */
		if (BITS2BYTES(xbits) > plen) {
			DBG(mca, DWARN, "Invalid Private Length[%x]. Must "
			    "be less than %x bytes", BITS2BYTES(xbits), plen);
			return (CRYPTO_TEMPLATE_INCOMPLETE);
		}
	}

	pbits = mca_bitlen((caddr_t)p, plen);
	if ((pbits < DH_MIN_KEY_LEN) || (pbits > DH_MAX_KEY_LEN)) {
		/* Unsupported key length */
		DBG(NULL, DWARN, "pbits(%u) not in range", pbits);
		return (CRYPTO_KEY_SIZE_RANGE);
	}

	/* copy prime and base to private template */
	if (cpg_attr_add_uint8_array(prvtemplate, CPGA_PRIME, p, plen,
		CPG_ATTR_NOSLEEP) ||
	    cpg_attr_add_uint8_array(prvtemplate, CPGA_BASE, g, glen,
		CPG_ATTR_NOSLEEP)) {
		return (CRYPTO_HOST_MEMORY);
	}

	comflags = pubflags | prvflags;

	if ((reqp = mca_getreq(&mca->mca_ring_ca)) == NULL) {
		return (CRYPTO_BUSY);
	}

	/*
	 * If we are generating a persistent key, we have to be authenticated.
	 */
	if (comflags & (KEYFLAG_PERSIST | KEYFLAG_PRIVATE)) {
		rv = mca_get_session_cred(session, reqp->mr_cred);
		if (rv != CRYPTO_SUCCESS) {
			mca_freereq(reqp);
			return (rv);
		}
	}

	/*
	 * Ensure device has keystore capabilities. While SENSITIVE
	 * keys are not stored in the keystore, they do require the
	 * keyid component of the keystore structure, and master
	 * backup key support that come with the device's keystore.
	 */
	if (comflags & (KEYFLAG_PERSIST | KEYFLAG_SENSITIVE)) {
		if ((mks = session->ms_user->mu_keystore) == NULL) {
			DBG(mca, DWARN, "device has no keystore?");
			mca_freereq(reqp);
			return (CRYPTO_GENERAL_ERROR);
		}
	}

	/* set KS handle if one exists */
	if (mks) {
		reqp->mr_dbm_handle = mca_ks_get_handle(mks, mca);
	} else {
		reqp->mr_dbm_handle = MCA_KS_BAD_HANDLE;
	}

	reqp->mr_job_stat = MS_DHKEYGEN;
	reqp->mr_cf_req = cfreq;
	reqp->mr_session = session;

	reqp->mr_key_flags[0] = pubflags;
	reqp->mr_key_flags[1] = prvflags;
	reqp->mr_template[0] = pubtemplate;
	reqp->mr_template[1] = prvtemplate;
	reqp->mr_keyidp[0] = pubid;
	reqp->mr_keyidp[1] = prvid;
	reqp->mr_callback = pairgen_done;

	reqp->mr_cmd = CMD_DHPAIRGEN;

	kaddr = reqp->mr_ibuf_kaddr;
	residlen = MAX_KEY_SIZE;

	/* pbits shouldn't change in the lines below! */
	rv = cpgattr2keyhead4keygen(pubtemplate, KEYTYPE_DH_PUBLIC,
	    kaddr, &residlen);
	inlen = PAD32(residlen);
	kaddr += PAD32(residlen);
	residlen = MAX_KEY_SIZE - PAD32(residlen);
	if (rv == CRYPTO_SUCCESS) {
		rv = cpgattr2keyhead4keygen(prvtemplate, KEYTYPE_DH_PRIVATE,
		    kaddr, &residlen);
		inlen += PAD32(residlen);
	}
	if (rv != CRYPTO_SUCCESS) {
		mca_freereq(reqp);
		return (rv);
	}

	if (comflags & KEYFLAG_PERSIST) {
		mca_user_wrlock(session->ms_user);
		reqp->mr_flags = MRF_TASKQ | MRF_KSUPDATE;
	}

	if (inlen > reqp->mr_ibuf_sz) {
		MCA_TERMINATE_CHAINS(&reqp->mr_ibuf_chain, inlen);
		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_next_paddr = reqp->mr_ibuf_next_paddr;
		reqp->mr_in_len = inlen;
		reqp->mr_in_first_len = reqp->mr_ibuf_sz;
	} else {
		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_next_paddr = 0;
		reqp->mr_in_len = inlen;
		reqp->mr_in_first_len = inlen;
	}
	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_out_next_paddr = reqp->mr_obuf_next_paddr;
	reqp->mr_out_len = MAXPACKET;
	reqp->mr_out_first_len = reqp->mr_obuf_sz;

	/*
	 * DH key pair generation is fast (just a modular
	 * exponentiation, no actual primes are generated here), so we
	 * just assume default timings are adequate.
	 */
	ddi_dma_sync(reqp->mr_ibuf_dmah, 0, inlen, DDI_DMA_SYNC_FORDEV);
	/* sync key dma for input/output chains */
	ddi_dma_sync(reqp->mr_key_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	if (mca_isfips(mca)) {
		mca_setiv(reqp);
	}

	if ((rv = mca_start(reqp)) != CRYPTO_QUEUED) {
		if (reqp->mr_flags & MRF_KSUPDATE) {
			mca_user_unlock(session->ms_user);
		}
		mca_freereq(reqp);
	}

	DBG(mca, DENTRY, "mca_dhgen <--[0x%x]", rv);

	return (rv);
}


int
mca_ecgen(mca_t *mca, mca_session_t *session, cpg_attr_t *pubtemplate,
    cpg_attr_t *prvtemplate, uint32_t *pubid, uint32_t *prvid,
    crypto_req_handle_t *cfreq, mca_keystore_t *mks)
{
	uint32_t	pubflags, prvflags, comflags;
	mca_request_t	*reqp;
	int		rv;
	uint8_t		*ecparam;
	uint32_t	ecparamlen;
	caddr_t		kaddr;
	uint32_t	residlen;
	uint32_t	inlen;

	DBG(mca, DENTRY, "mca_ecgen -->");

	pubflags = 0;
	prvflags = KEYFLAG_DERIVE;

	if (((rv = pubgen_flags(pubtemplate, &pubflags, CPGK_EC))
		!= CRYPTO_SUCCESS) ||
	    ((rv = prvgen_flags(prvtemplate, &prvflags, CPGK_EC))
		!= CRYPTO_SUCCESS)) {
		return (rv);
	}

	if (cpg_attr_lookup_uint8_array(pubtemplate, CPGA_EC_PARAMS,
	    &ecparam, &ecparamlen)) {
		DBG(mca, DWARN, "missing EC_PARAMS in EC keygen");
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	/* remove any bogus value attributes */
	(void) cpg_attr_delete_attribute(pubtemplate, CPGA_EC_POINT);
	(void) cpg_attr_delete_attribute(prvtemplate, CPGA_EC_PARAMS);
	(void) cpg_attr_delete_attribute(prvtemplate, CPGA_VALUE);

	if ((rv = cpg_attr_add_uint8_array(prvtemplate, CPGA_EC_PARAMS,
	    ecparam, ecparamlen, 0)) != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "Failed to add EC_PARAMS to private template");
		return (rv);
	}
	comflags = pubflags | prvflags;

	if ((reqp = mca_getreq(&mca->mca_ring_ca)) == NULL) {
		return (CRYPTO_BUSY);
	}

	/*
	 * If we are generating a persistent key, we have to be authenticated.
	 */
	if (comflags & (KEYFLAG_PERSIST | KEYFLAG_PRIVATE)) {
		rv = mca_get_session_cred(session, reqp->mr_cred);
		if (rv != CRYPTO_SUCCESS) {
			mca_freereq(reqp);
			return (rv);
		}
		reqp->mr_timeout = OMTIMEOUT;
	}

	/*
	 * Ensure device has keystore capabilities. While SENSITIVE
	 * keys are not stored in the keystore, they do require the
	 * keyid component of the keystore structure, and master
	 * backup key support that come with the device's keystore.
	 */
	if (comflags & (KEYFLAG_PERSIST | KEYFLAG_SENSITIVE)) {
		if (mks == NULL) {
			DBG(mca, DWARN, "device has no keystore?");
			mca_freereq(reqp);
			return (CRYPTO_GENERAL_ERROR);
		}
	}

	/* set KS handle if one exists */
	if (mks) {
		reqp->mr_dbm_handle = mca_ks_get_handle(mks, mca);
	} else {
		reqp->mr_dbm_handle = MCA_KS_BAD_HANDLE;
	}

	reqp->mr_job_stat = MS_ECKEYGEN;
	reqp->mr_cf_req = cfreq;
	reqp->mr_session = session;

	reqp->mr_key_flags[0] = pubflags;
	reqp->mr_key_flags[1] = prvflags;
	reqp->mr_template[0] = pubtemplate;
	reqp->mr_template[1] = prvtemplate;
	reqp->mr_keyidp[0] = pubid;
	reqp->mr_keyidp[1] = prvid;
	reqp->mr_callback = pairgen_done;

	reqp->mr_cmd = CMD_ECPAIRGEN;

	kaddr = reqp->mr_ibuf_kaddr;
	residlen = MAX_KEY_SIZE;

	rv = cpgattr2keyhead4keygen(pubtemplate, KEYTYPE_EC_PUBLIC,
	    kaddr, &residlen);
	inlen = PAD32(residlen);
	kaddr += PAD32(residlen);
	residlen = MAX_KEY_SIZE - PAD32(residlen);
	if (rv == CRYPTO_SUCCESS) {
		rv = cpgattr2keyhead4keygen(prvtemplate, KEYTYPE_EC_PRIVATE,
		    kaddr, &residlen);
		inlen += PAD32(residlen);
	}
	if (rv != CRYPTO_SUCCESS) {
		mca_freereq(reqp);
		return (rv);
	}

	if (comflags & KEYFLAG_PERSIST) {
		mca_user_wrlock(session->ms_user);
		reqp->mr_flags = MRF_TASKQ | MRF_KSUPDATE;
	}

	if (inlen > reqp->mr_ibuf_sz) {
		MCA_TERMINATE_CHAINS(&reqp->mr_ibuf_chain, inlen);
		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_next_paddr = reqp->mr_ibuf_next_paddr;
		reqp->mr_in_len = inlen;
		reqp->mr_in_first_len = reqp->mr_ibuf_sz;
	} else {
		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_next_paddr = 0;
		reqp->mr_in_len = inlen;
		reqp->mr_in_first_len = inlen;
	}
	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_out_next_paddr = reqp->mr_obuf_next_paddr;
	reqp->mr_out_len = MAXPACKET;
	reqp->mr_out_first_len = reqp->mr_obuf_sz;

	ddi_dma_sync(reqp->mr_ibuf_dmah, 0, inlen, DDI_DMA_SYNC_FORDEV);
	/* sync key dma for input/output chains */
	ddi_dma_sync(reqp->mr_key_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	if (mca_isfips(mca)) {
		mca_setiv(reqp);
	}

	if ((rv = mca_start(reqp)) != CRYPTO_QUEUED) {
		if (reqp->mr_flags & MRF_KSUPDATE) {
			mca_user_unlock(session->ms_user);
		}
		mca_freereq(reqp);
	}

	DBG(mca, DENTRY, "mca_ecgen <--[0x%x]", rv);

	return (rv);
}

static void
pairgen_done(mca_request_t *reqp)
{
	mca_t		*mca = reqp->mr_mca;
	int		residlen;
	cpg_attr_t	*pubattrp, *prvattrp;
	uint16_t	pubflags, prvflags;
	int		pubregistered = 0, prvregistered = 0;
	int		rv;
	mca_user_t	*user = reqp->mr_session->ms_user;
	mca_key_head_t	*keyhead;
	mca_key_t	*pubmkey = NULL, *prvmkey = NULL;

	pubattrp = reqp->mr_template[0];
	prvattrp = reqp->mr_template[1];

	if (reqp->mr_errno != 0) {
		DBG(mca, DWARN, "keygen failed, dev err %d", reqp->mr_errno);
		rv = reqp->mr_errno;
		goto errorexit;
	}

	pubflags = reqp->mr_key_flags[0];
	prvflags = reqp->mr_key_flags[1];

	keyhead = (mca_key_head_t *)reqp->mr_obuf_kaddr;
	residlen = reqp->mr_resultlen;

	ddi_dma_sync(reqp->mr_obuf_dmah, 0, reqp->mr_resultlen,
	    DDI_DMA_SYNC_FORKERNEL);

	if (mca_isfips(mca)) {
		mca_ktkdecryptbuf(reqp);
	}

	if ((rv = mca_parse_key(pubattrp, keyhead, residlen,
	    pubflags, &pubmkey)) != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "pairgen_done(pubkey): "
		    "mca_parse_key failed with 0x%x", rv);
		goto errorexit;
	}

	keyhead = (mca_key_head_t *)
	    (reqp->mr_obuf_kaddr + PAD32(pubmkey->mk_keyheadsz));
	residlen = reqp->mr_resultlen - pubmkey->mk_keyheadsz;

	if ((rv = mca_parse_key(prvattrp, keyhead, residlen,
	    prvflags, &prvmkey)) != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "pairgen_done(prikey): "
		    "mca_parse_key failed with 0x%x", rv);
		goto errorexit;
	}


	/*
	 * Add the key to the UKT. The key is marked INVALID, and this
	 * thread should hold the refcnt.
	 */
	if (pubflags & KEYFLAG_PERSIST) {
		rv = mca_register_key(user, pubmkey);
		if (rv != CRYPTO_SUCCESS) {
			goto errorexit;
		}
		pubregistered = 1;
	}
	if (prvflags & KEYFLAG_PERSIST) {
		rv = mca_register_key(user, prvmkey);
		if (rv != CRYPTO_SUCCESS) {
			goto errorexit;
		}
		prvregistered = 1;
	}

	/*
	 * Create the keys in the SKT
	 * Note: Session refcnt is decremented by mca_add_keys
	 */
	rv = mca_add_keys(reqp->mr_session, pubmkey, prvmkey,
	    reqp->mr_keyidp[0], reqp->mr_keyidp[1]);
	if (rv != CRYPTO_SUCCESS) {
		goto errorexit;
	}

	if (reqp->mr_flags & MRF_KSUPDATE) {
		mca_user_unlock(user);
	}

	/* Success! */
	crypto_op_notification(reqp->mr_cf_req, CRYPTO_SUCCESS);
	mca_freereq(reqp);
	return;

errorexit:

	mca_session_releaseref(reqp->mr_session, UNLOCKED);

	/* take the keys out of the UKT if registered */
	if (pubregistered) {
		mca_unregister_key(pubmkey);
	}
	if (prvregistered) {
		mca_unregister_key(prvmkey);
	}

	if (reqp->mr_flags & MRF_KSUPDATE) {
		mca_user_unlock(user);
	}

	/* free the allocated template/mca_key on error exit */
	if (pubmkey == NULL) {
		cpg_attr_free(pubattrp);
	} else {
		mca_key_free(pubmkey);
	}
	if (prvmkey == NULL) {
		cpg_attr_free(prvattrp);
	} else {
		mca_key_free(prvmkey);
	}

	crypto_op_notification(reqp->mr_cf_req, rv);
	mca_freereq(reqp);
}
