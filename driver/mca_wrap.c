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

#pragma ident	"@(#)mca_wrap.c	1.37	08/04/07 SMI"

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
#include <sys/byteorder.h>
#include <sys/kmem.h>
#include <sys/mca.h>
#include <sys/atomic.h>
#endif

#define	AES_KEYWRAP_IV_LEN	8

static uchar_t	AESKeyWrapDefaultIV[] =
	{ 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6 };

static void common_wrapdone(mca_request_t *);
static void common_unwrapdone(mca_request_t *);

/*
 * 3DES implementation.
 */

static int
des3_setup_req(mca_request_t *reqp, crypto_mechanism_t *mech)
{
	mca_key_head_t	*keyhead = (mca_key_head_t *)reqp->mr_key_kaddr;
	int		keyheadsz = reqp->mr_key_len;
	uint32_t	*env = (uint32_t *)KEYHEAD_ENVELOPE(keyhead);
	uint32_t	*value = (uint32_t *)KEYHEAD_VALUE(keyhead);
	int		keytype;
	char		param[DESBLOCK];
	int		paramlen = DESBLOCK;

	ASSERT((keyhead != NULL) && (keyheadsz >= sizeof (mca_key_head_t)));

	if (mca_get_mech_param(mech, param, &paramlen) != CRYPTO_SUCCESS) {
		DBG(NULL, DCHATTY, "des3_setup_req:"
		    "mca_get_mech_param failed");
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	/*
	 * make sure that the length is DESBLOCK bytes.
	 */
	if (paramlen != DESBLOCK) {
		DBG(NULL, DCHATTY, "des3_setup_req: paramlen = %d", paramlen);
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	/* copy the initial vector */
	reqp->mr_short_key[6] = GETBE32((uint32_t *)param);
	reqp->mr_short_key[7] = GETBE32((uint32_t *)(param + 4));

	reqp->mr_key_id[0] = GETBUF32(&keyhead->cardid);
	reqp->mr_key_id[1] = GETBUF32(&keyhead->objectid);
	keytype = GETBUF32(&keyhead->keytype);

	if (keyhead->envelopelen != 0) {
		/* KeyByEnvelope */
		switch (keytype) {
		case KEYTYPE_DES:
			reqp->mr_short_key[0] = GETBE32(env);
			reqp->mr_short_key[1] = GETBE32(env + 1);
			reqp->mr_short_key[2] = reqp->mr_short_key[0];
			reqp->mr_short_key[3] = reqp->mr_short_key[1];
			reqp->mr_short_key[4] = reqp->mr_short_key[0];
			reqp->mr_short_key[5] = reqp->mr_short_key[1];
			break;
		case KEYTYPE_DES2:
			reqp->mr_short_key[0] = GETBE32(env);
			reqp->mr_short_key[1] = GETBE32(env + 1);
			reqp->mr_short_key[2] = GETBE32(env + 2);
			reqp->mr_short_key[3] = GETBE32(env + 3);
			reqp->mr_short_key[4] = reqp->mr_short_key[0];
			reqp->mr_short_key[5] = reqp->mr_short_key[1];
			break;
		case KEYTYPE_DES3:
			reqp->mr_short_key[0] = GETBE32(env);
			reqp->mr_short_key[1] = GETBE32(env + 1);
			reqp->mr_short_key[2] = GETBE32(env + 2);
			reqp->mr_short_key[3] = GETBE32(env + 3);
			reqp->mr_short_key[4] = GETBE32(env + 4);
			reqp->mr_short_key[5] = GETBE32(env + 5);
			break;
		default:
			DBG(NULL, DWARN, "des3_setup_req: keytype[0x%x]",
			    keytype);
			return (CRYPTO_KEY_TYPE_INCONSISTENT);
		}
	} else if ((keyhead->cardid == 0) && (keyhead->objectid == 0)) {
		/* KeyByValue */
		switch (keytype) {
		case KEYTYPE_DES:
			reqp->mr_short_key[0] = GETBE32(value);
			reqp->mr_short_key[1] = GETBE32(value + 1);
			reqp->mr_short_key[2] = reqp->mr_short_key[0];
			reqp->mr_short_key[3] = reqp->mr_short_key[1];
			reqp->mr_short_key[4] = reqp->mr_short_key[0];
			reqp->mr_short_key[5] = reqp->mr_short_key[1];
			break;
		case KEYTYPE_DES2:
			reqp->mr_short_key[0] = GETBE32(value);
			reqp->mr_short_key[1] = GETBE32(value + 1);
			reqp->mr_short_key[2] = GETBE32(value + 2);
			reqp->mr_short_key[3] = GETBE32(value + 3);
			reqp->mr_short_key[4] = reqp->mr_short_key[0];
			reqp->mr_short_key[5] = reqp->mr_short_key[1];
			break;
		case KEYTYPE_DES3:
			reqp->mr_short_key[0] = GETBE32(value);
			reqp->mr_short_key[1] = GETBE32(value + 1);
			reqp->mr_short_key[2] = GETBE32(value + 2);
			reqp->mr_short_key[3] = GETBE32(value + 3);
			reqp->mr_short_key[4] = GETBE32(value + 4);
			reqp->mr_short_key[5] = GETBE32(value + 5);
			break;
		default:
			DBG(NULL, DWARN, "des3_setup_req: keytype[0x%x]",
			    keytype);
			return (CRYPTO_KEY_TYPE_INCONSISTENT);
		}
	}

	return (CRYPTO_SUCCESS);
}


static int
aes_setup_req(mca_request_t *reqp, crypto_mechanism_t *mech)
{
	char			param[AESBLOCK];
	int			paramlen = AESBLOCK;
	mca_key_head_t		*keyhead;

	if (mca_get_mech_param(mech, param, &paramlen) != CRYPTO_SUCCESS) {
		DBG(NULL, DCHATTY, "aes_setup_req:"
		    "mca_get_mech_param failed");
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	if (paramlen != AESBLOCK) {
		DBG(NULL, DCHATTY, "aes_setup_req: paramlen = %d", paramlen);
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	keyhead = (mca_key_head_t *)reqp->mr_key_kaddr;
	if (GETBUF32(&keyhead->keytype) != KEYTYPE_AES) {
		DBG(NULL, DCHATTY, "aes_setup_req: invalid "
		    "keytype[0x%x]", GETBUF32(&keyhead->keytype));
		return (CRYPTO_KEY_TYPE_INCONSISTENT);
	}

	reqp->mr_key_id[0] = GETBUF32(&keyhead->cardid);
	reqp->mr_key_id[1] = GETBUF32(&keyhead->objectid);

	if ((keyhead->cardid == 0) && (keyhead->objectid == 0)) {
		uint32_t		vallen;
		uint32_t		*value;
		int			i;
		mca_aes_keyhead_t	*aeshead;

		aeshead = (mca_aes_keyhead_t *)(keyhead + 1);
		vallen = GETBUF32(&aeshead->keysz);
		value = (uint32_t *)(aeshead + 1);

		reqp->mr_short_key[0] = vallen;

		for (i = 0; i < (vallen / sizeof (uint32_t)); i++) {
			reqp->mr_short_key[i + 1] = GETBE32(value + i);
		}
	}

	/*
	 * Set the IV for this operation. The IV is passed through
	 * shortkey[9-12]
	 */
	reqp->mr_short_key[9] = GETBE32((uint32_t *)param);
	reqp->mr_short_key[10] = GETBE32((uint32_t *)param + 1);
	reqp->mr_short_key[11] = GETBE32((uint32_t *)param + 2);
	reqp->mr_short_key[12] = GETBE32((uint32_t *)param + 3);

	return (CRYPTO_SUCCESS);
}


static int
aeskeywrap_setup_req(mca_request_t *reqp, crypto_mechanism_t *mech)
{
	char			param[AES_KEYWRAP_IV_LEN];
	int			paramlen = AES_KEYWRAP_IV_LEN;
	mca_key_head_t		*keyhead;

	if (mca_get_mech_param(mech, param, &paramlen) != CRYPTO_SUCCESS) {
		DBG(NULL, DCHATTY, "aeskeywrap_setup_req:"
		    "mca_get_mech_param failed");
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	/*
	 * Paramlen must be AES_KEYWRAP_IV_LEN bytes or 0(default IV)
	 */
	if ((paramlen != AES_KEYWRAP_IV_LEN) && (paramlen != 0)) {
		DBG(NULL, DCHATTY, "aeskeywrap_setup_req: paramlen = %d",
		    paramlen);
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}
	/* If the NULL IV is passed, use the default IV */
	if (paramlen == 0) {
		bcopy(AESKeyWrapDefaultIV, param, AES_KEYWRAP_IV_LEN);
	}

	keyhead = (mca_key_head_t *)reqp->mr_key_kaddr;
	if (GETBUF32(&keyhead->keytype) != KEYTYPE_AES) {
		DBG(NULL, DCHATTY, "aeskeywrap_setup_req: invalid "
		    "keytype[0x%x]", GETBUF32(&keyhead->keytype));
		return (CRYPTO_KEY_TYPE_INCONSISTENT);
	}
	reqp->mr_key_id[0] = GETBUF32(&keyhead->cardid);
	reqp->mr_key_id[1] = GETBUF32(&keyhead->objectid);

	if ((keyhead->cardid == 0) && (keyhead->objectid == 0)) {
		uint32_t		vallen;
		uint32_t		*value;
		int			i;
		mca_aes_keyhead_t	*aeshead;

		aeshead = (mca_aes_keyhead_t *)(keyhead + 1);
		vallen = GETBUF32(&aeshead->keysz);
		value = (uint32_t *)(aeshead + 1);

		reqp->mr_short_key[0] = vallen;

		for (i = 0; i < (vallen / sizeof (uint32_t)); i++) {
			reqp->mr_short_key[i + 1] = GETBE32(value + i);
		}
	}

	/*
	 * Set the IV for this operation. The IV is passed through
	 * shortkey[9-10]
	 */
	reqp->mr_short_key[9] = GETBE32((uint32_t *)param);
	reqp->mr_short_key[10] = GETBE32((uint32_t *)param + 1);

	return (CRYPTO_SUCCESS);
}

static int
aesctr_setup_req(mca_request_t *reqp, crypto_mechanism_t *mech)
{
	CK_AES_CTR_PARAMS	param;
	int			paramlen = sizeof (CK_AES_CTR_PARAMS);
	mca_key_head_t		*keyhead;

	if (mca_get_mech_param(mech,
	    (char *)&param, &paramlen) != CRYPTO_SUCCESS) {
		DBG(NULL, DCHATTY, "aesctr_setup_req:"
		    "mca_get_mech_param failed");
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	if (paramlen != sizeof (CK_AES_CTR_PARAMS)) {
		DBG(NULL, DCHATTY, "aesctr_setup_req: paramlen = %d", paramlen);
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	keyhead = (mca_key_head_t *)reqp->mr_key_kaddr;
	if (GETBUF32(&keyhead->keytype) != KEYTYPE_AES) {
		DBG(NULL, DCHATTY, "aesctr_setup_req: invalid "
		    "keytype[0x%x]", GETBUF32(&keyhead->keytype));
		return (CRYPTO_KEY_TYPE_INCONSISTENT);
	}
	reqp->mr_key_id[0] = GETBUF32(&keyhead->cardid);
	reqp->mr_key_id[1] = GETBUF32(&keyhead->objectid);

	if ((keyhead->cardid == 0) && (keyhead->objectid == 0)) {
		uint32_t		*value;
		uint32_t		vallen;
		int			i;
		mca_aes_keyhead_t	*aeshead;

		aeshead = (mca_aes_keyhead_t *)(keyhead + 1);
		vallen = GETBUF32(&aeshead->keysz);
		value = (uint32_t *)(aeshead + 1);

		reqp->mr_short_key[0] = vallen;

		for (i = 0; i < (vallen / sizeof (uint32_t)); i++) {
			reqp->mr_short_key[i + 1] = GETBE32(value + i);
		}
	}

	/*
	 * Set the IV for this operation. The IV is passed through
	 * shortkey[9-12]
	 */
	reqp->mr_short_key[9] = GETBE32((uint32_t *)param.iv);
	reqp->mr_short_key[10] = GETBE32((uint32_t *)param.iv + 1);
	reqp->mr_short_key[11] = GETBE32((uint32_t *)param.iv + 2);
	reqp->mr_short_key[12] = GETBE32((uint32_t *)param.iv + 3);

	return (CRYPTO_SUCCESS);
}

static int
rc2_setup_req(mca_request_t *reqp, crypto_mechanism_t *mech)
{
	mca_key_head_t		*keyhead;
	mca_rc2_keyhead_t	*rc2keyhead;
	mca_rc2_param_t		param;
	int			paramlen;

	paramlen = sizeof (param);
	if (mca_get_mech_param(mech, (char *)&param,
	    &paramlen) != CRYPTO_SUCCESS) {
		DBG(NULL, DCHATTY, "rc2_setup_req:"
		    "mca_get_mech_param failed");
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	if (paramlen != sizeof (mca_rc2_param_t)) {
		DBG(NULL, DCHATTY, "rc2_setup_req: paramlen = %d", paramlen);
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	keyhead = (mca_key_head_t *)reqp->mr_key_kaddr;
	if (GETBUF32(&keyhead->keytype) != KEYTYPE_RC2) {
		DBG(NULL, DCHATTY, "rc2_setup_req: invalid "
		    "keytype[0x%x]", GETBUF32(&keyhead->keytype));
		return (CRYPTO_KEY_TYPE_INCONSISTENT);
	}
	rc2keyhead = (mca_rc2_keyhead_t *)(keyhead  + 1);
	bcopy(param.iv, rc2keyhead->iv, RC2BLOCK);
	PUTBUF32(&rc2keyhead->effbits, param.effbits);

	reqp->mr_key_id[0] = GETBUF32(&(keyhead->cardid));
	reqp->mr_key_id[1] = GETBUF32(&(keyhead->objectid));

	return (CRYPTO_SUCCESS);
}

static int
rsa_setup_req(mca_request_t *reqp, /* ARGSUSED */ crypto_mechanism_t *mech)
{
	mca_key_head_t	*keyhead;
	uint32_t	keytype;
	uint32_t	modlen;

	keyhead = (mca_key_head_t *)reqp->mr_key_kaddr;

	reqp->mr_key_id[0] = GETBUF32(&(keyhead->cardid));
	reqp->mr_key_id[1] = GETBUF32(&(keyhead->objectid));

	keytype = GETBUF32(&(keyhead->keytype));
	if (keytype == KEYTYPE_RSA_PUBLIC) {
		pubrsa_head_t	*rsahead;
		rsahead = (pubrsa_head_t *)((char *)keyhead +
		    sizeof (mca_key_head_t) + GETBUF32(&(keyhead->descrlen)));
		modlen = GETBUF32(&rsahead->modlen);
	} else if (keytype == KEYTYPE_RSA_PRIVATE) {
		prirsa_head_t	*rsahead;
		rsahead = (prirsa_head_t *)((char *)keyhead +
		    sizeof (mca_key_head_t) + GETBUF32(&(keyhead->descrlen)));
		modlen = GETBUF32(&rsahead->modlen);
	} else {
		DBG(NULL, DCHATTY, "rsa_setup_req: invalid "
		    "keytype[0x%x]", GETBUF32(&keyhead->keytype));
		return (CRYPTO_KEY_TYPE_INCONSISTENT);
	}
	/* set the key length in mr_short_key */
	reqp->mr_short_key[4] = modlen;
	reqp->mr_out_len = modlen;
	reqp->mr_out_first_len = modlen;

	return (CRYPTO_SUCCESS);
}

int
mca_common_wrap(mca_t *mca, crypto_session_id_t session_id,
    crypto_mechanism_t *mech, crypto_key_t *wrappingkey, crypto_key_t *key,
    uchar_t *buf, size_t *buflen, crypto_req_handle_t *cfreq, uint32_t cmd)
{
	mca_request_t	*reqp;
	int		rv;
	uint32_t	keylen;
	uint32_t	keyflags;
	uint32_t	comkeyflags;
	char		*kaddr;
	char		*wkeykaddr;
	uint32_t	wkeylen;
	uint32_t	wkeyflags;
	mca_keystore_t	*ks;
	mca_session_t	*session = NULL;
	uint32_t	wrapmech = 0;

	if ((reqp = mca_getreq(&mca->mca_ring_om)) == NULL) {
		mca_error(mca, "unable to allocate request for wrap");
		return (CRYPTO_BUSY);
	}

	/*
	 * Set the mca_key_head for the key in ibuf.
	 * ibuf should be (mechtype + mca_key_head)
	 */
	kaddr = reqp->mr_ibuf_kaddr + sizeof (uint32_t);
	keylen = MAX_KEY_SIZE - sizeof (uint32_t);
	wkeykaddr = reqp->mr_key_kaddr;
	wkeylen = MAX_KEY_SIZE;
	rv = mca_write_keys(mca, session_id, key, wrappingkey, kaddr, &keylen,
	    wkeykaddr, &wkeylen, &keyflags, &wkeyflags);
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "common_wrap:mca_write_keys failed with 0x%x",
		    rv);
		goto done;
	}

	/* Make sure the keys have the right permission */
	if (keyflags & KEYFLAG_NOWRAP) {
		rv = CRYPTO_KEY_NOT_WRAPPABLE;
		goto done;
	}
	if (!(wkeyflags & KEYFLAG_WRAP)) {
		rv = CRYPTO_WRAPPING_KEY_HANDLE_INVALID;
		goto done;
	}
	reqp->mr_key_len = wkeylen;
	reqp->mr_key_flags[0] = keyflags;

	comkeyflags = keyflags | wkeyflags;

	ks = mca_keystore_lookup_by_session(session_id);

	if (ks) {
		reqp->mr_dbm_handle = mca_ks_get_handle(ks, mca);
	}

	/* setup the request */
	switch (cmd & CMD_MASK) {
	case CMD_3DESDEC:
		rv = des3_setup_req(reqp, mech);
		wrapmech = (cmd & CMD_HI_PAD) ?
		    MCA_WRAP_MECH_DES3_CBC_PAD : MCA_WRAP_MECH_DES3_CBC;
		break;
	case CMD_AESCBCDEC:
		rv = aes_setup_req(reqp, mech);
		wrapmech = (cmd & CMD_HI_PAD) ?
		    MCA_WRAP_MECH_AES_CBC_PAD : MCA_WRAP_MECH_AES_CBC;
		break;
	case CMD_AESCTRDEC:
		rv = aesctr_setup_req(reqp, mech);
		wrapmech = MCA_WRAP_MECH_AES_CTR;
		break;
	case MCA_CMD_AES_KEY_WRAP:
		rv = aeskeywrap_setup_req(reqp, mech);
		wrapmech = MCA_WRAP_MECH_AES_KEY_WRAP;
		break;
	case CMD_RC2DEC:
		rv = rc2_setup_req(reqp, mech);
		wrapmech = (cmd & CMD_HI_PAD) ?
		    MCA_WRAP_MECH_RC2_CBC_PAD : MCA_WRAP_MECH_RC2_CBC;
		break;
	case CMD_RSAPUB:
		rv = rsa_setup_req(reqp, mech);
		wrapmech = MCA_WRAP_MECH_RSA_X509;
		break;
	case CMD_RSAPADENC:
		rv = rsa_setup_req(reqp, mech);
		wrapmech = MCA_WRAP_MECH_RSA_PKCS;
		break;
	default:
		rv = CRYPTO_MECHANISM_INVALID;
		break;
	}
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "common_wrap: req setup failed with 0x%x", rv);
		mca_freereq(reqp);
		return (rv);
	}

	/* set the wrapmech type */
	PUTBUF32((uint32_t *)reqp->mr_ibuf_kaddr, wrapmech);
	keylen += sizeof (uint32_t);

	/*
	 * If the wrapping key is non-sensitive session key, and the
	 * card is in FIPS mode, encrypt the key
	 */
	if (mca_isfips(mca)) {
		if ((reqp->mr_key_id[0] == 0) && (reqp->mr_key_id[1] == 0)) {
			/* the key is non-sensitive session key */
			if (((cmd & CMD_MASK) == CMD_3DESDEC) ||
			    ((cmd & CMD_MASK) == CMD_AESCBCDEC) ||
			    ((cmd & CMD_MASK) == CMD_AESCTRDEC) ||
			    ((cmd & CMD_MASK) == MCA_CMD_AES_KEY_WRAP)) {
				mca_ktkencryptshortkey(reqp);
			} else {
				mca_ktkencryptkey(reqp);
			}
		} else {
			/* set IV for output buffer and/or key to be wrapped */
			mca_setiv(reqp);
		}
	}

	if (comkeyflags & (KEYFLAG_SENSITIVE | KEYFLAG_PERSIST)) {
		session = mca_session_holdref(mca, session_id);
		if (session == NULL) {
			rv = CRYPTO_SESSION_HANDLE_INVALID;
			goto done;
		}

		/* set the authentication cookie if the key is token key */
		if (comkeyflags & KEYFLAG_PERSIST) {
			rv = mca_get_session_cred(session, reqp->mr_cred);
			if (rv != CRYPTO_SUCCESS) {
				goto done;
			}
			/*
			 * For wrapping, grab the read lock if
			 * either the wrapping key or key to
			 * be wrapped is a token key. No new
			 * key is created so the write lock is
			 * necessary.
			 */
			mca_user_rdlock(session->ms_user);
			reqp->mr_flags |= MRF_KSREAD;
		}
	}

	reqp->mr_cf_req = cfreq;
	reqp->mr_session = session;
	reqp->mr_cmd = CMD_WRAP;
	reqp->mr_buf = buf;
	reqp->mr_buflen = buflen;
	reqp->mr_job_stat = MS_WRAPJOBS;
	reqp->mr_callback = common_wrapdone;

	/* In FIPS mode we have to encrypt the input buffer under the KTK. */
	if (mca_isfips(mca)) {
		keylen = PADAES(keylen);
		mca_aes_cbc_encrypt(&mca_ktk,
		    reqp->mr_short_key,
		    (uchar_t *)reqp->mr_ibuf_kaddr,
		    (uchar_t *)reqp->mr_ibuf_kaddr, keylen);
	}

	if (keylen > reqp->mr_ibuf_sz) {
		MCA_TERMINATE_CHAINS(&reqp->mr_ibuf_chain, keylen);
		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_next_paddr = reqp->mr_ibuf_next_paddr;
		reqp->mr_in_len = keylen;
		reqp->mr_in_first_len = reqp->mr_ibuf_sz;
	} else {
		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_next_paddr = 0;
		reqp->mr_in_len = keylen;
		reqp->mr_in_first_len = reqp->mr_in_len;
	}
	/* XXX: large wrapped key is not supported */
	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_out_len = reqp->mr_obuf_sz;
	reqp->mr_out_first_len = reqp->mr_obuf_sz;
	reqp->mr_out_next_paddr = 0;

	reqp->mr_byte_stat = -1;

	ddi_dma_sync(reqp->mr_ibuf_dmah, 0, reqp->mr_in_len,
	    DDI_DMA_SYNC_FORDEV);

	/* schedule the work by doing a submit */
	rv = mca_start(reqp);

done:
	if (rv != CRYPTO_QUEUED) {
		if (session) {
			if (reqp->mr_flags & MRF_KSREAD) {
				mca_user_unlock(session->ms_user);
			}
			mca_session_releaseref(session, UNLOCKED);
		}
		mca_freereq(reqp);
	}
	return (rv);
}

int
mca_common_unwrap(mca_t *mca, crypto_session_id_t session_id,
    crypto_mechanism_t *mech, crypto_key_t *wrappingkey, uchar_t *buf,
    size_t buflen, cpg_attr_t *template, uint32_t *keyid,
    crypto_req_handle_t *cfreq, uint32_t cmd)
{
	mca_request_t	*reqp;
	int		rv;
	uint32_t	newkeyflags;
	uint32_t	comkeyflags;
	char		*cursor;
	uint32_t	residlen;
	uint32_t	inlen;
	int		keytype;
	char		*wkeykaddr;
	uint32_t	wkeylen;
	uint32_t	wkeyflags;
	uint32_t	wrapmech;
	mca_session_t	*session = NULL;
	mca_keystore_t	*ks;

	if ((reqp = mca_getreq(&mca->mca_ring_om)) == NULL) {
		mca_error(mca, "unable to allocate request for unwrap");
		return (CRYPTO_BUSY);
	}

	/*
	 * Set the mca_key_head for the key in ibuf.
	 * ibuf should be (mechtype + mca_key_head)
	 */
	wkeykaddr = reqp->mr_key_kaddr;
	wkeylen = MAX_KEY_SIZE;
	rv = mca_write_key(mca, session_id, wrappingkey, wkeykaddr,
	    &wkeylen, &wkeyflags);
	if (rv != CRYPTO_SUCCESS) {
		goto done;
	}
	reqp->mr_key_len = wkeylen;

	/* setup the request */
	switch (cmd & CMD_MASK) {
	case CMD_3DESDEC:
		rv = des3_setup_req(reqp, mech);
		wrapmech = (cmd & CMD_HI_PAD) ?
		    MCA_WRAP_MECH_DES3_CBC_PAD : MCA_WRAP_MECH_DES3_CBC;
		break;
	case CMD_AESCBCDEC:
		rv = aes_setup_req(reqp, mech);
		wrapmech = (cmd & CMD_HI_PAD) ?
		    MCA_WRAP_MECH_AES_CBC_PAD : MCA_WRAP_MECH_AES_CBC;
		break;
	case CMD_AESCTRDEC:
		rv = aesctr_setup_req(reqp, mech);
		wrapmech = MCA_WRAP_MECH_AES_CTR;
		break;
	case MCA_CMD_AES_KEY_WRAP:
		rv = aeskeywrap_setup_req(reqp, mech);
		wrapmech = MCA_WRAP_MECH_AES_KEY_WRAP;
		break;
	case CMD_RC2DEC:
		rv = rc2_setup_req(reqp, mech);
		wrapmech = (cmd & CMD_HI_PAD) ?
		    MCA_WRAP_MECH_RC2_CBC_PAD : MCA_WRAP_MECH_RC2_CBC;
		break;
	case CMD_RSAPRV:
		rv = rsa_setup_req(reqp, mech);
		wrapmech = MCA_WRAP_MECH_RSA_X509;
		break;
	case CMD_RSAPADDEC:
		rv = rsa_setup_req(reqp, mech);
		wrapmech = MCA_WRAP_MECH_RSA_PKCS;
		break;
	default:
		rv = CRYPTO_MECHANISM_INVALID;
		goto done;
	}
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "common_wrap: req setup failed with 0x%x", rv);
		mca_freereq(reqp);
		return (rv);
	}

	/*
	 * Setup the key template.
	 *	uint32_t		mechtype;
	 *	uint32_t		wrapped_key_len;
	 *	uint32_t		wrapped_key[];
	 *	mca_key_head_t		keyhead;
	 */
	PUTBUF32((uint32_t *)(reqp->mr_ibuf_kaddr), wrapmech);
	cursor = reqp->mr_ibuf_kaddr + sizeof (uint32_t);
	residlen = MAX_KEY_SIZE - sizeof (uint32_t);
	inlen = sizeof (uint32_t);

	/*
	 * Copy the wrapped key value into 'cursor' and set the valuelen.
	 * Advance the cursor.
	 */
	if (residlen < (PAD32(buflen) + sizeof (uint32_t))) {
		/* key is too big */
		mca_freereq(reqp);
		return (CRYPTO_KEY_SIZE_RANGE);
	}

	PUTBUF32((uint32_t *)cursor, buflen);
	cursor += sizeof (uint32_t);
	residlen -= sizeof (uint32_t);
	inlen += sizeof (uint32_t);

	bcopy(buf, cursor, buflen);
	cursor += PAD32(buflen);
	residlen -= PAD32(buflen);
	inlen += PAD32(buflen);

	if ((rv = cpgattr2keytype(template, &keytype)) != CRYPTO_SUCCESS) {
		DBG(mca, DCHATTY, "mca_unwrapkey: cpgattr2keytype failed"
		    "with 0x%x", rv);
		mca_freereq(reqp);
		return (rv);
	}
	rv = cpgattr2keyhead4unwrap(template, keytype, cursor, &residlen);
	if (rv != CRYPTO_SUCCESS) {
		mca_freereq(reqp);
		return (rv);
	}
	inlen += residlen;

	rv = mca_createkey_flags(template, &newkeyflags);
	if (rv != CRYPTO_SUCCESS) {
		/* public token key is not supported */
		mca_freereq(reqp);
		return (rv);
	}
	comkeyflags = newkeyflags | wkeyflags;
	reqp->mr_key_flags[0] = newkeyflags;

	if (inlen > reqp->mr_ibuf_sz) {
		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_next_paddr = reqp->mr_ibuf_next_paddr;
		reqp->mr_in_len = inlen;
		reqp->mr_in_first_len = reqp->mr_ibuf_sz;
	} else {
		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_next_paddr = 0;
		reqp->mr_in_len = inlen;
		reqp->mr_in_first_len = reqp->mr_in_len;
	}
	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_out_next_paddr = reqp->mr_obuf_next_paddr;
	reqp->mr_out_len = MAXPACKET;
	reqp->mr_out_first_len = reqp->mr_obuf_sz;

	if (mca_isfips(reqp->mr_mca)) {
		if ((reqp->mr_key_id[0] == 0) &&
		    (reqp->mr_key_id[1] == 0)) {
			if (((cmd & CMD_MASK) == CMD_3DESDEC) ||
			    ((cmd & CMD_MASK) == CMD_AESCBCDEC) ||
			    ((cmd & CMD_MASK) == CMD_AESCTRDEC) ||
			    ((cmd & CMD_MASK) == MCA_CMD_AES_KEY_WRAP)) {
				mca_ktkencryptshortkey(reqp);
			} else {
				mca_ktkencryptkey(reqp);
			}
		} else {
			/* set IV for output buffer */
			mca_setiv(reqp);
		}
	}

	/*
	 * If the input is chained, the descriptor chain must be adjusted.
	 * This must be called after mca_ktkencryptbuf, which may pad
	 * the input to be multiple of AES blocksz.
	 */
	if (reqp->mr_in_next_paddr != 0) {
		/*EMPTY*/
		MCA_TERMINATE_CHAINS(&reqp->mr_ibuf_chain, inlen);
	}

	ks = mca_keystore_lookup_by_session(session_id);

	if (ks) {
		reqp->mr_dbm_handle = mca_ks_get_handle(ks, mca);
	}

	session = mca_session_holdref(mca, session_id);
	if (session == NULL) {
		rv = CRYPTO_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (newkeyflags & KEYFLAG_PERSIST) {
		if (session->ms_user == NULL) {
			rv = CRYPTO_ATTRIBUTE_VALUE_INVALID;
			goto done;
		}
		mca_user_wrlock(session->ms_user);
		reqp->mr_flags = MRF_TASKQ | MRF_KSUPDATE;
	} else if (comkeyflags & KEYFLAG_PERSIST) {
		if (session->ms_user == NULL) {
			rv = CRYPTO_ATTRIBUTE_VALUE_INVALID;
			goto done;
		}
		mca_user_rdlock(session->ms_user);
		reqp->mr_flags |= MRF_KSREAD;
	}

	/* set the authentication cookie if the key is token key */
	if (comkeyflags & KEYFLAG_PERSIST) {
		rv = mca_get_session_cred(session, reqp->mr_cred);
		if (rv != CRYPTO_SUCCESS) {
			goto done;
		}
		reqp->mr_timeout = OMTIMEOUT;
	}

	reqp->mr_cf_req = cfreq;
	reqp->mr_session = session;
	reqp->mr_cmd = CMD_UNWRAP;
	reqp->mr_job_stat = MS_UNWRAPJOBS;
	reqp->mr_byte_stat = -1;
	reqp->mr_callback = common_unwrapdone;
	reqp->mr_template[0] = template;
	reqp->mr_keyidp[0] = keyid;

	ddi_dma_sync(reqp->mr_ibuf_dmah, 0, reqp->mr_in_len,
	    DDI_DMA_SYNC_FORDEV);

	/* schedule the work */
	rv = mca_start(reqp);

done:
	if (rv != CRYPTO_QUEUED) {
		if (session) {
			if (reqp->mr_flags &
			    (MRF_KSUPDATE | MRF_KSREAD)) {
				mca_user_unlock(session->ms_user);
			}
			mca_session_releaseref(session, UNLOCKED);
		}
		mca_freereq(reqp);
	}

	return (rv);
}


static void
common_wrapdone(mca_request_t *reqp)
{
	if (reqp->mr_errno == CRYPTO_SUCCESS) {
		uchar_t		*buf = reqp->mr_buf;
		size_t		*buflen = reqp->mr_buflen;

		ddi_dma_sync(reqp->mr_obuf_dmah, 0, reqp->mr_resultlen,
		    DDI_DMA_SYNC_FORKERNEL);
		if (*buflen < reqp->mr_resultlen) {
			DBG(reqp->mr_mca, DCHATTY, "common_wrapdone: "
			    "buflen[%d] resultlen[%d]", *buflen,
			    reqp->mr_resultlen);
			reqp->mr_errno = CRYPTO_BUFFER_TOO_SMALL;
			*buflen = reqp->mr_resultlen;
			goto done;
		}
		*buflen = reqp->mr_resultlen;
		bcopy(reqp->mr_obuf_kaddr, buf, reqp->mr_resultlen);
	}

done:
	if (reqp->mr_session) {
		if (reqp->mr_flags & MRF_KSREAD) {
			mca_user_unlock(reqp->mr_session->ms_user);
		}
		mca_session_releaseref(reqp->mr_session, UNLOCKED);
	}

	crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
	mca_freereq(reqp);
}



static void
common_unwrapdone(mca_request_t *reqp)
{
	mca_t			*mca = reqp->mr_mca;
	int			residlen;
	mca_key_head_t		*keyhead;
	uint16_t		keyflags;
	cpg_attr_t		*attrp = reqp->mr_template[0];
	mca_key_t		*mkey = NULL;
	int			rv = CRYPTO_SUCCESS;

	if (reqp->mr_errno != CRYPTO_SUCCESS) {
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

	rv = mca_parse_key(attrp, keyhead, residlen, keyflags, &mkey);
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DCHATTY, "common_unwrapdone: mca_parse_key failed "
		    "with 0x%x", rv);
		goto exit;
	}

	/*
	 * Add the key to the UKT if the key is token. The key is marked
	 * INVALID.
	 */
	if (keyflags & KEYFLAG_PERSIST) {
		rv = mca_register_key(reqp->mr_session->ms_user, mkey);
		if (rv != CRYPTO_SUCCESS) {
			goto exit;
		}
	}

	/*
	 * Create the key in the SKT
	 * mca_add_keys is used because the key for unwrap is altenate
	 * key for KCL. (CPG?)
	 * Note: Session refcnt is decremented by mca_add_keys
	 */
	rv = mca_add_keys(reqp->mr_session, NULL, mkey,
	    NULL, reqp->mr_keyidp[0]);
	if (rv != CRYPTO_SUCCESS) {
		if (keyflags & KEYFLAG_PERSIST) {
			mca_unregister_key(mkey);
		}
		goto exit;
	}

exit:
	/* on the error exit, free the mca_key/template */
	if (rv != CRYPTO_SUCCESS) {
		if (mkey == NULL) {
			cpg_attr_free(attrp);
		} else {
			mca_key_free(mkey);
		}
	}

	if (reqp->mr_flags & (MRF_KSUPDATE | MRF_KSREAD)) {
		mca_user_unlock(reqp->mr_session->ms_user);
	}
	/*
	 * session refcnt was decrement by mca_add_keys. Thus mc_session
	 * field should be set to NULL to avoid double-decrement
	 */
	reqp->mr_session = NULL;

	crypto_op_notification(reqp->mr_cf_req, rv);
	mca_freereq(reqp);
}
