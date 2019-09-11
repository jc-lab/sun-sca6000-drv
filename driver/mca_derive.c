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

#pragma ident	"@(#)mca_derive.c	1.18	07/08/17 SMI"

/*
 * Mars - pure cryptographic acceleration + secure keystore
 */

#ifdef LINUX
#include <linux/types.h>
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
#include <sys/crypto/ioctl.h>	/* for crypto_mechanism32 */

#endif

/*
 * Key deriveeration implementation.
 */

static void keyderive_done(mca_request_t *);


/*
 * This function is used by kEF to copyin the mechanism parameter for ECDH1.
 * Note: 'inmech' comes in the applications size structure
 * Note: 'outmech' is initialized by the driver so that the mech is in
 * the native size structure.
 */
int
mca_ecdh1_allocmech(crypto_mechanism_t *inmech, crypto_mechanism_t *outmech,
    int *error, int mode)
{
	STRUCT_DECL(crypto_mechanism, mech);
	STRUCT_DECL(CK_ECDH1_DERIVE_PARAMS, params);
	CK_ECDH1_DERIVE_PARAMS	*ecdh1_params = NULL;
	caddr_t			param;
	size_t			paramlen;
	uchar_t			*buf = NULL;
	size_t			len = 0;
	int			rv = CRYPTO_SUCCESS;

	DBG(NULL, DENTRY, "mca_ecdh1_allocmech -->");

	*error = 0;

	STRUCT_INIT(mech, mode);
	STRUCT_INIT(params, mode);
	bcopy(inmech, STRUCT_BUF(mech), STRUCT_SIZE(mech));
	param = STRUCT_FGETP(mech, cm_param);
	paramlen = STRUCT_FGET(mech, cm_param_len);

	/*
	 * Parameter is required for ecdh1 key derivation: there is no
	 * crypto_data passed to key derivation, thus, it must be passed
	 * through mechanism.param.
	 */
	if ((param == NULL) || (paramlen != STRUCT_SIZE(params))) {
		DBG(NULL, DCHATTY, "mca_ecdh1_allocmech: bad param");
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	outmech->cm_type = STRUCT_FGET(mech, cm_type);
	outmech->cm_param = NULL;
	outmech->cm_param_len = 0;

	if (ddi_copyin(param, STRUCT_BUF(params), paramlen, mode) != 0) {
		DBG(NULL, DWARN, "mca_ecdh1_allocmech: copyin(param) failure");
		return (CRYPTO_FAILED);
	}

	/* allocate the native size structure */
	ecdh1_params = (CK_ECDH1_DERIVE_PARAMS *)
	    kmem_alloc(sizeof (CK_ECDH1_DERIVE_PARAMS), KM_SLEEP);
	if (ecdh1_params == NULL) {
		DBG(NULL, DWARN, "mca_ecdh1_allocmech: kmem_alloc failure");
		*error = ENOMEM;
		return (CRYPTO_HOST_MEMORY);
	}

	ecdh1_params->kdf = STRUCT_FGET(params, kdf);

	/* XXX: we don't support SHA kdf. Change the rest of the code1 */
	if (ecdh1_params->kdf != CKD_NULL) {
		rv = CRYPTO_MECHANISM_PARAM_INVALID;
		goto error_exit;
	}

	if ((ecdh1_params->kdf != CKD_NULL) &&
	    (ecdh1_params->kdf != CKD_SHA1_KDF)) {
		DBG(NULL, DCHATTY, "mca_ecdh1_allocmech: invalid kdf[%d]",
		    ecdh1_params->kdf);
		rv = CRYPTO_MECHANISM_PARAM_INVALID;
		goto error_exit;
	}
	ecdh1_params->ulSharedDataLen =
	    STRUCT_FGET(params, ulSharedDataLen);
	ecdh1_params->ulPublicDataLen =
	    STRUCT_FGET(params, ulPublicDataLen);

	/* if kdf is CKD_NULL, shared len should be 0 */
	if ((ecdh1_params->kdf == CKD_NULL) &&
	    (ecdh1_params->ulSharedDataLen != 0)) {
		rv = CRYPTO_MECHANISM_PARAM_INVALID;
		goto error_exit;
	}

	/* allocate the buffer for shared data and public data */
	len = ecdh1_params->ulSharedDataLen + ecdh1_params->ulPublicDataLen;
	buf = kmem_alloc(len, KM_SLEEP);
	if (buf == NULL) {
		DBG(NULL, DCHATTY, "mca_ecdh1_allocmech: kmem_alloc failure");
		*error = ENOMEM;
		rv = CRYPTO_HOST_MEMORY;
		goto error_exit;
	}

	/* copyin the optional shared data */
	if (ecdh1_params->ulSharedDataLen > 0) {
		if (ddi_copyin(STRUCT_FGETP(params, pSharedData), buf,
		    ecdh1_params->ulSharedDataLen, mode) != 0) {
			DBG(NULL, DWARN, "mca_ecdh1_allocmech: "
			    "copyin(shared data) failure");
			*error = EFAULT;
			rv = CRYPTO_FAILED;
			goto error_exit;
		}
		ecdh1_params->pSharedData = buf;
	} else {
		ecdh1_params->pSharedData = NULL;
	}

	/* copyin the public data */
	if (ddi_copyin(STRUCT_FGETP(params, pPublicData),
	    buf + ecdh1_params->ulSharedDataLen,
	    ecdh1_params->ulPublicDataLen, mode) != 0) {
		DBG(NULL, DWARN, "mca_ecdh1_allocmech: "
		    "copyin(public data) failure");
		*error = EFAULT;
		rv = CRYPTO_FAILED;
		goto error_exit;
	}
	ecdh1_params->pPublicData = buf + ecdh1_params->ulSharedDataLen;

	outmech->cm_param = (char *)ecdh1_params;
	outmech->cm_param_len = sizeof (CK_ECDH1_DERIVE_PARAMS);

	DBG(NULL, DENTRY, "mca_ecdh1_allocmech was successful");
	return (CRYPTO_SUCCESS);

error_exit:
	if (ecdh1_params != NULL) {
		kmem_free(ecdh1_params, sizeof (CK_ECDH1_DERIVE_PARAMS));
	}
	if (buf != NULL) {
		kmem_free(buf, len);
	}
	return (rv);
}

int
mca_ecdh1_freemech(crypto_mechanism_t *mech)
{
	CK_ECDH1_DERIVE_PARAMS	*ecdh1_params;
	size_t			buflen;

	if ((mech->cm_param == NULL) || (mech->cm_param_len == 0)) {
		return (CRYPTO_SUCCESS);
	}
	/* if the parameter size is unexpected, return an error */
	if (mech->cm_param_len != sizeof (CK_ECDH1_DERIVE_PARAMS)) {
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	ecdh1_params = (CK_ECDH1_DERIVE_PARAMS *)mech->cm_param;
	buflen = ecdh1_params->ulSharedDataLen + ecdh1_params->ulPublicDataLen;
	if (ecdh1_params->pSharedData != NULL) {
		/*
		 * If pSharedData is non-NULL, that is the beginning of the
		 * data. Free for both shared data and public data.
		 */
		kmem_free(ecdh1_params->pSharedData, buflen);
	} else if (ecdh1_params->pPublicData != NULL) {
		/* free the public data */
		kmem_free(ecdh1_params->pPublicData, buflen);
	}

	/* free the parameter structure */
	kmem_free(mech->cm_param, mech->cm_param_len);

	return (CRYPTO_SUCCESS);
}


/*
 * Set up for symmetric keys.  *flagsp points to the values for enc,
 * dec, sign, vrfy, wrap, unwrap, derive.  It gets set to all flags.
 * The template is presumed to have been checked for consistency and
 * fluffed.
 */
static int
keyderive_flags(cpg_attr_t *template, uint32_t *flagsp)
{
	uint8_t		token = FALSE;
	uint8_t		priv = FALSE;
	uint8_t		sens = FALSE;
	uint8_t		extr = FALSE;

	if (cpg_attr_add_uint8(template, CPGA_LOCAL, 1, CPG_ATTR_NOSLEEP)) {
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

int
mca_dh_derive(mca_t *mca, crypto_session_id_t session_id,
    crypto_mechanism_t *mech, crypto_key_t *basekey, cpg_attr_t *template,
    uint32_t *keyid, crypto_req_handle_t *cfreq)
{
	int		mkeytype;
	uint32_t	keylen;
	uint32_t	inlen;
	uint32_t	basekeyflags, newkeyflags, comkeyflags;
	mca_request_t	*reqp;
	int		rv;
	caddr_t		keykaddr;
	uint32_t	residlen;
	mca_session_t	*session;
	mca_keystore_t	*ks;
	caddr_t		cursor;

	DBG(mca, DENTRY, "mca_dhderive -->");

	rv = cpgattr2keytype(template, &mkeytype);
	if (rv != CRYPTO_SUCCESS) {
		return (CRYPTO_TEMPLATE_INCONSISTENT);
	}
	rv = cpg_attr_add_uint32(template, CPGA_CLASS, CPGO_SECRET_KEY, 0);
	if (rv != CRYPTO_SUCCESS) {
		return (CRYPTO_HOST_MEMORY);
	}
	if ((rv = keyderive_flags(template, &newkeyflags)) != CRYPTO_SUCCESS) {
		return (rv);
	}

	if ((reqp = mca_getreq(&mca->mca_ring_ca)) == NULL) {
		return (CRYPTO_BUSY);
	}

	/* set the basekey in mca_key_head_t format */
	keykaddr = reqp->mr_key_kaddr;
	keylen = MAX_KEY_SIZE;
	rv = mca_write_key(mca, session_id, basekey, keykaddr,
	    &keylen, &basekeyflags);
	if (rv != CRYPTO_SUCCESS) {
		mca_freereq(reqp);
		return (rv);
	}
	reqp->mr_key_len = keylen;
	reqp->mr_key_id[0] = GETBUF32(&((mca_key_head_t *)keykaddr)->cardid);
	reqp->mr_key_id[1] = GETBUF32(&((mca_key_head_t *)keykaddr)->objectid);

	/*
	 * Set the value of the other party and the template for the new key in
	 * the mca_key_head format in ibuf
	 */
	residlen = MAXPACKET;
	cursor = reqp->mr_ibuf_kaddr;

	if (residlen < (PAD32(mech->cm_param_len) + sizeof (uint32_t))) {
		/* key is too big */
		mca_freereq(reqp);
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}
	if ((mech->cm_param_len < BITS2BYTES(DH_MIN_KEY_LEN)) ||
	    (mech->cm_param_len > BITS2BYTES(DH_MAX_KEY_LEN))) {
		/* invalid public value length */
		mca_freereq(reqp);
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	PUTBUF32((uint32_t *)cursor, mech->cm_param_len);
	cursor += sizeof (uint32_t);
	residlen -= sizeof (uint32_t);
	inlen = sizeof (uint32_t);

	bcopy(mech->cm_param, cursor, mech->cm_param_len);
	cursor += PAD32(mech->cm_param_len);
	residlen -= PAD32(mech->cm_param_len);
	inlen += PAD32(mech->cm_param_len);

	rv = cpgattr2keyhead4keygen(template, mkeytype, cursor, &residlen);
	if (rv != CRYPTO_SUCCESS) {
		mca_freereq(reqp);
		return (rv);
	}
	inlen += residlen;

	comkeyflags = basekeyflags | newkeyflags;

	session = mca_session_holdref(mca, session_id);
	if (session == NULL) {
		mca_freereq(reqp);
		return (CRYPTO_SESSION_HANDLE_INVALID);
	}


	/*
	 * If we are deriving a key which will be managed by the
	 * firmware (either persistent or sensitive), we have to have
	 * a keystore, and (if key is persistent) be authenticated.
	 */
	if (comkeyflags & (KEYFLAG_PERSIST | KEYFLAG_PRIVATE)) {
		rv = mca_get_session_cred(session, reqp->mr_cred);
		if (rv != CRYPTO_SUCCESS) {
			mca_freereq(reqp);
			mca_session_releaseref(session, UNLOCKED);
			return (rv);
		}
	}

	ks = mca_keystore_lookup_by_session(session_id);

	if (comkeyflags & (KEYFLAG_PERSIST | KEYFLAG_SENSITIVE)) {
		if (ks == NULL) {
			DBG(mca, DWARN, "device has no keystore?");
			mca_freereq(reqp);
			mca_session_releaseref(session, UNLOCKED);
			return (CRYPTO_GENERAL_ERROR);
		}
	}

	if (newkeyflags & KEYFLAG_PERSIST) {
		mca_user_wrlock(session->ms_user);
		reqp->mr_flags = MRF_TASKQ | MRF_KSUPDATE;
	} else if (basekeyflags & KEYFLAG_PERSIST) {
		mca_user_rdlock(session->ms_user);
		reqp->mr_flags = MRF_KSREAD;
	}

	reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
	reqp->mr_in_next_paddr = reqp->mr_ibuf_next_paddr;
	reqp->mr_in_len = inlen;
	reqp->mr_in_first_len = min((int)reqp->mr_ibuf_sz, (int)inlen);
	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_out_next_paddr = reqp->mr_obuf_next_paddr;
	reqp->mr_out_len = MAX_KEY_SIZE;
	reqp->mr_out_first_len = reqp->mr_obuf_sz;

	reqp->mr_job_stat = MS_DHDERIVE;
	reqp->mr_cf_req = cfreq;
	if (ks) {
		reqp->mr_dbm_handle = mca_ks_get_handle(ks, mca);
	}
	reqp->mr_key_flags[0] = newkeyflags;
	reqp->mr_callback = keyderive_done;
	reqp->mr_session = session;
	reqp->mr_template[0] = template;
	reqp->mr_keyidp[0] = keyid;
	reqp->mr_cmd = CMD_DHDERIVE;

	if (mca_isfips(mca)) {
		if ((reqp->mr_key_id[0] == 0) && (reqp->mr_key_id[1] == 0)) {
			mca_ktkencryptkey(reqp);
		} else {
			/* set IV for output buffer */
			mca_setiv(reqp);
		}

	}

	ddi_dma_sync(reqp->mr_ibuf_dmah, 0, reqp->mr_in_len,
	    DDI_DMA_SYNC_FORDEV);
	ddi_dma_sync(reqp->mr_key_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	rv = mca_start(reqp);

exit:
	if (rv != CRYPTO_QUEUED) {
		if (reqp->mr_flags & (MRF_KSUPDATE | MRF_KSREAD)) {
			mca_user_unlock(session->ms_user);
		}
		mca_freereq(reqp);
		mca_session_releaseref(session, UNLOCKED);
	}

	DBG(mca, DENTRY, "mca_dh_derive <--[0x%x]", rv);

	return (rv);
}


int
mca_ec_derive(mca_t *mca, crypto_session_id_t session_id,
    crypto_mechanism_t *mech, crypto_key_t *basekey, cpg_attr_t *template,
    uint32_t *keyid, crypto_req_handle_t *cfreq)
{
	mca_keystore_t	*ks;
	int		mkeytype;
	uint32_t	keylen;
	uint32_t	inlen;
	uint32_t	basekeyflags, newkeyflags, comkeyflags;
	mca_request_t	*reqp;
	int		rv;
	caddr_t		keykaddr;
	uint32_t	residlen;
	mca_session_t	*session;
	caddr_t		cursor;
	CK_ECDH1_DERIVE_PARAMS	*ecdh1_params;

	DBG(mca, DENTRY, "mca_ecderive -->");

	rv = cpgattr2keytype(template, &mkeytype);
	if (rv != CRYPTO_SUCCESS) {
		return (CRYPTO_TEMPLATE_INCONSISTENT);
	}
	rv = cpg_attr_add_uint32(template, CPGA_CLASS, CPGO_SECRET_KEY, 0);
	if (rv != CRYPTO_SUCCESS) {
		return (CRYPTO_HOST_MEMORY);
	}
	if ((rv = keyderive_flags(template, &newkeyflags)) != CRYPTO_SUCCESS) {
		return (rv);
	}

	if ((reqp = mca_getreq(&mca->mca_ring_ca)) == NULL) {
		return (CRYPTO_BUSY);
	}

	/* set the basekey in mca_key_head_t format */
	keykaddr = reqp->mr_key_kaddr;
	keylen = MAX_KEY_SIZE;
	rv = mca_write_key(mca, session_id, basekey, keykaddr,
	    &keylen, &basekeyflags);
	if (rv != CRYPTO_SUCCESS) {
		mca_freereq(reqp);
		return (rv);
	}
	reqp->mr_key_len = keylen;
	reqp->mr_key_id[0] = GETBUF32(&((mca_key_head_t *)keykaddr)->cardid);
	reqp->mr_key_id[1] = GETBUF32(&((mca_key_head_t *)keykaddr)->objectid);

	ecdh1_params = (CK_ECDH1_DERIVE_PARAMS *)mech->cm_param;

	/*
	 * Set KDF type, optional shared data, public data, and the template
	 * for the new key in the mca_key_head format in ibuf
	 */
	residlen = MAXPACKET;
	cursor = reqp->mr_ibuf_kaddr;

	/* XXX: we do not support "shared data" */
	if (residlen < (PAD32(ecdh1_params->ulSharedDataLen) +
	    PAD32(ecdh1_params->ulPublicDataLen) + 3 * sizeof (uint32_t))) {
		/* key is too big */
		mca_freereq(reqp);
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	/* copy public data: length followed by data */
	PUTBUF32((uint32_t *)cursor, ecdh1_params->ulPublicDataLen);
	cursor += sizeof (uint32_t);
	residlen -= sizeof (uint32_t);
	inlen = sizeof (uint32_t);
	if (ecdh1_params->pPublicData[0] != 0x04) {
		mca_freereq(reqp);
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}
	bcopy(ecdh1_params->pPublicData + 1, cursor,
	    ecdh1_params->ulPublicDataLen);
	cursor += PAD32(ecdh1_params->ulPublicDataLen);
	residlen -= PAD32(ecdh1_params->ulPublicDataLen);
	inlen += PAD32(ecdh1_params->ulPublicDataLen);

	/* copy the template for the new key */
	rv = cpgattr2keyhead4keygen(template, mkeytype, cursor, &residlen);
	if (rv != CRYPTO_SUCCESS) {
		mca_freereq(reqp);
		return (rv);
	}
	inlen += residlen;

	comkeyflags = basekeyflags | newkeyflags;

	session = mca_session_holdref(mca, session_id);
	if (session == NULL) {
		mca_freereq(reqp);
		return (CRYPTO_SESSION_HANDLE_INVALID);
	}

	/*
	 * If we are deriveing a key which will be managed by the
	 * firmware (either persistent or sensitive), we have to have
	 * a keystore, and (if key is persistent) be authenticated.
	 */
	if (comkeyflags & (KEYFLAG_PERSIST | KEYFLAG_PRIVATE)) {
		rv = mca_get_session_cred(session, reqp->mr_cred);
		if (rv != CRYPTO_SUCCESS) {
			mca_freereq(reqp);
			mca_session_releaseref(session, UNLOCKED);
			return (rv);
		}
	}

	ks = mca_keystore_lookup_by_session(session_id);

	if (comkeyflags & (KEYFLAG_PERSIST | KEYFLAG_SENSITIVE)) {
		if (ks == NULL) {
			DBG(mca, DWARN, "device has no keystore?");
			mca_freereq(reqp);
			mca_session_releaseref(session, UNLOCKED);
			return (CRYPTO_GENERAL_ERROR);
		}
	}

	if (newkeyflags & KEYFLAG_PERSIST) {
		mca_user_wrlock(session->ms_user);
		reqp->mr_flags = MRF_TASKQ | MRF_KSUPDATE;
	} else if (basekeyflags & KEYFLAG_PERSIST) {
		mca_user_rdlock(session->ms_user);
		reqp->mr_flags = MRF_KSREAD;
	}

	reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
	reqp->mr_in_next_paddr = reqp->mr_ibuf_next_paddr;
	reqp->mr_in_len = inlen;
	reqp->mr_in_first_len = min((int)reqp->mr_ibuf_sz, (int)inlen);
	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_out_next_paddr = reqp->mr_obuf_next_paddr;
	reqp->mr_out_len = MAX_KEY_SIZE;
	reqp->mr_out_first_len = reqp->mr_obuf_sz;
	reqp->mr_job_stat = MS_DHDERIVE;
	reqp->mr_cf_req = cfreq;
	if (ks) {
		reqp->mr_dbm_handle = mca_ks_get_handle(ks, mca);
	}
	reqp->mr_key_flags[0] = newkeyflags;
	reqp->mr_callback = keyderive_done;
	reqp->mr_session = session;
	reqp->mr_template[0] = template;
	reqp->mr_keyidp[0] = keyid;
	reqp->mr_cmd = CMD_ECDHDERIVE;
	reqp->mr_timeout = drv_usectohz(10 * SECOND);

	if (mca_isfips(mca)) {
		if ((reqp->mr_key_id[0] == 0) && (reqp->mr_key_id[1] == 0)) {
			mca_ktkencryptkey(reqp);
		} else {
			/* set IV for output buffer */
			mca_setiv(reqp);
		}

	}

	ddi_dma_sync(reqp->mr_ibuf_dmah, 0, reqp->mr_in_len,
	    DDI_DMA_SYNC_FORDEV);
	ddi_dma_sync(reqp->mr_key_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	rv = mca_start(reqp);

exit:
	if (rv != CRYPTO_QUEUED) {
		if (reqp->mr_flags & (MRF_KSUPDATE | MRF_KSREAD)) {
			mca_user_unlock(session->ms_user);
		}
		mca_freereq(reqp);
		mca_session_releaseref(session, UNLOCKED);
	}

	DBG(mca, DENTRY, "mca_ec_derive <--[0x%x]", rv);

	return (rv);
}


static void
keyderive_done(mca_request_t *reqp)
{
	mca_t		*mca = reqp->mr_mca;
	cpg_attr_t	*attr = reqp->mr_template[0];
	uint16_t	keyflags;
	int		rv;
	int		residlen;
	mca_key_head_t	*keyhead;
	mca_key_t	*mkey = NULL;

	if (reqp->mr_errno != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "keyderive failed, dev err %d", reqp->mr_errno);
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
		DBG(mca, DCHATTY, "keyderive_done: mca_parse_key failed "
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

	if (reqp->mr_flags & (MRF_KSUPDATE | MRF_KSREAD)) {
		mca_user_unlock(reqp->mr_session->ms_user);
	}

	crypto_op_notification(reqp->mr_cf_req, rv);
	mca_freereq(reqp);
}
