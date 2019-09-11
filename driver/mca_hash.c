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

#pragma ident	"@(#)mca_hash.c	1.12	08/08/13 SMI"

/*
 * Mars - pure cryptographic acceleration + secure keystore
 */

#ifdef LINUX
#include <linux/types.h>
#include "sol2lin.h"
#include "mca.h"
#else
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/mca.h>
#endif

/*
 * MD5/SHA1/SHA512 implementation.
 */
static int	hash_start(mca_request_t *, size_t, size_t);
static int	hash_update(mca_request_t *);
static int	hash_key(mca_request_t *);
static int	hash_final(mca_request_t *);
static void	hash_init_done(mca_request_t *);
static void	hash_update_done(mca_request_t *);
static void	hash_key_done(mca_request_t *);
static void	hash_done(mca_request_t *);

/*
 * The chip cannot process zero-length input buffers (chip hang, or
 * DMA access error.)  To work around this, we special case the "null"
 * input cases with known answers in software.  Since there are only
 * two of them, this isn't as bad as it seems.  (In practice this code
 * will not get exercised, since there is no reason to ever run a hash
 * over a NULL input buffer.)
 */
static uchar_t mca_nullmd5[] = {
	0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
	0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
};

static uchar_t mca_nullsha1[] = {
	0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55,
	0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09,
};

static uchar_t mca_nullsha512[] = {
	0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
	0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
	0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
	0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
	0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
	0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
	0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
	0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
};


/*
 * 'req' is not used since this is a synchronous operation.
 */
/*ARGSUSED*/
int
mca_hash_allocctx(crypto_ctx_t *ctx, crypto_req_handle_t *req,
    crypto_mechanism_t *mech, mca_privatectx_t **privctx)
{
	int		rv;
	uint32_t	cmd;

	switch (mech->cm_type) {
	case MCAM_SHA_1:
		cmd = CMD_SHA1;
		break;
	case MCAM_SHA512:
		cmd = CMD_SHA512;
		break;
	case MCAM_MD5:
		cmd = CMD_MD5;
		break;
	default:
		cmd = 0;
		return (CRYPTO_MECHANISM_INVALID);
	}

	/* hash operation needs mech-name only for the context */
	rv = mca_allocctx(MCA_CTX2MCA(ctx), ctx->cc_session,
	    NULL, cmd, 0, privctx);

	/* set the ctxid to NULL */
	if (rv == CRYPTO_SUCCESS) {
		(*privctx)->mc_shortparam[0] = -1;
	}

	return (rv);
}

/*
 * This function initialized the operation: get a context ID from HW.
 * This functions may be called for digest single part and atomic operations
 * if the data is greater than 64KB. In which case, output buffer 'digest'
 * must be provided by the caller.
 */
int
mca_hash_init(mca_t *mca, mca_privatectx_t *ctx, uint32_t cmd,
    crypto_data_t *data, crypto_data_t *digest, crypto_req_handle_t *cfreq)
{
	mca_request_t	*reqp;
	int		rv;
	int		jobstat;
	int		bytestat;
	int		outsz;

	switch (cmd & CMD_MASK) {
	case CMD_MD5:
		jobstat = MS_MD5JOBS;
		bytestat = MS_MD5BYTES;
		outsz = MD5LEN;
		break;
	case CMD_SHA1:
		jobstat = MS_SHA1JOBS;
		bytestat = MS_SHA1BYTES;
		outsz = SHA1LEN;
		break;
	case CMD_SHA512:
		jobstat = MS_SHA512JOBS;
		bytestat = MS_SHA512BYTES;
		outsz = SHA512LEN;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	/*
	 * Single-part/atomic operation: make sure that the output buffer is
	 * large enough
	 */
	if (digest) {
		if (outsz > mca_get_datalen(digest)) {
			DBG(mca, DCHATTY, "inadequate output space (need %d, "
			    "got %d)", outsz, mca_get_datalen(digest));
			mca_set_datalen(digest, outsz);
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}

	if ((reqp = mca_getreq(&mca->mca_ring_cb)) == NULL) {
		mca_error(mca, "unable to allocate request for "
		    "multi-part hash");
		return (CRYPTO_BUSY);
	}

	MCA_SET_REQ_DATA(reqp, data, digest);
	reqp->mr_out_len = sizeof (uint32_t);
	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_cmd = CMD_HASH_INIT;
	reqp->mr_context = ctx;
	reqp->mr_short_key[SK_HASH_CMD] = cmd & CMD_MASK;
	reqp->mr_short_key[SK_HASH_DIGESTSZ] = outsz;
	reqp->mr_job_stat = jobstat;
	reqp->mr_byte_stat = bytestat;
	reqp->mr_cf_req = cfreq;
	reqp->mr_callback = hash_init_done;

	rv = mca_start(reqp);
	if ((rv != CRYPTO_SUCCESS) && (rv != CRYPTO_QUEUED)) {
		mca_freereq(reqp);
	}

	return (rv);
}

/*
 * The mca_request structure already allocated can be reused. In which case,
 * 'cmd'
 * If it has not already been allocated, 'reqp' should be NULL.
 */
int
mca_hash_update(mca_t *mca, uint32_t ctxid, uint32_t cmd,
    crypto_data_t *data, crypto_req_handle_t *cfreq)
{
	mca_request_t	*reqp;
	int		rv;
	int		jobstat;
	int		bytestat;

	switch (cmd & CMD_MASK) {
	case CMD_MD5:
		jobstat = MS_MD5JOBS;
		bytestat = MS_MD5BYTES;
		break;
	case CMD_SHA1:
		jobstat = MS_SHA1JOBS;
		bytestat = MS_SHA1BYTES;
		break;
	case CMD_SHA512:
		jobstat = MS_SHA512JOBS;
		bytestat = MS_SHA512BYTES;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	if ((reqp = mca_getreq(&mca->mca_ring_cb)) == NULL) {
		mca_error(mca, "unable to allocate request for "
		    "multi-part hash");
		return (CRYPTO_BUSY);
	}

	reqp->mr_tmpin = *data;
	reqp->mr_in = &reqp->mr_tmpin;
	reqp->mr_out = NULL;
	reqp->mr_out_len = 0;
	reqp->mr_job_stat = jobstat;
	reqp->mr_byte_stat = bytestat;
	reqp->mr_short_key[SK_HASH_CTXID] = ctxid;
	reqp->mr_cf_req = cfreq;
	reqp->mr_cmd = cmd;

	if ((rv = hash_update(reqp)) != CRYPTO_QUEUED) {
		mca_freereq(reqp);
	}

	return (rv);
}

static int
hash_update(mca_request_t *reqp)
{
	int			len;
	int			rv;

	/*
	 * If this is a "null" input, nothing to process: early exit
	 */
	len = reqp->mr_in->cd_length;
	if (len == 0) {
		return (CRYPTO_SUCCESS);
	}
	if (len > MAXPACKET) {
		len = MAXPACKET;
	}

	reqp->mr_cmd = CMD_HASH_UPDATE;
	reqp->mr_callback = hash_update_done;
	reqp->mr_byte_count = len;
	reqp->mr_flags &= ~MRF_GATHER;

	/* Try to do direct DMA for input */
	if ((len < mca_mindma) || mca_sg(reqp->mr_in)) {
		reqp->mr_flags |= MRF_GATHER;
	}
	if (!(reqp->mr_flags & MRF_GATHER)) {
		/*
		 * By passing 0 in the third argument (outlen) to
		 * mca_bindchains, we avoid direct DMA for output.
		 */
		if (mca_bindchains(reqp, len, 0) != DDI_SUCCESS)
			return (CRYPTO_FAILED);
	}

	/* Otherwise we do a pullup (extra data copy) */
	if (reqp->mr_flags & MRF_GATHER) {
		/* terminate the pre-mapped chain */
		MCA_TERMINATE_CHAINS(&reqp->mr_ibuf_chain, len);

		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_first_len = min((int)reqp->mr_ibuf_sz, len);
		reqp->mr_in_len = len;
		if (reqp->mr_in_first_len == len) {
			reqp->mr_in_next_paddr = 0;
		} else {
			reqp->mr_in_next_paddr = reqp->mr_ibuf_next_paddr;
		}

		if ((rv = mca_gather(reqp->mr_in, reqp->mr_ibuf_kaddr,
		    reqp->mr_in_len)) != CRYPTO_SUCCESS) {
			return (rv);
		}
		ddi_dma_sync(reqp->mr_ibuf_dmah, 0, reqp->mr_in_len,
		    DDI_DMA_SYNC_FORDEV);
	}

	/* schedule the work by doing a submit */
	return (mca_start(reqp));
}


int
mca_hash_key(crypto_ctx_t *ctx, crypto_key_t *key, crypto_req_handle_t *cfreq)
{
	mca_privatectx_t	*privctx = ctx->cc_provider_private;
	mca_t			*mca = privctx->mc_mca;
	mca_request_t		*reqp;
	mca_key_head_t		*keyhead;
	int			rv;
	uint32_t		buflen;
	uint32_t		keyflags;

	if ((reqp = mca_getreq(&mca->mca_ring_cb)) == NULL) {
		mca_error(mca, "unable to allocate request for "
		    "pure hash");
		return (CRYPTO_BUSY);
	}

	buflen = MAX_KEY_SIZE;
	rv = mca_write_key(mca, ctx->cc_session, key,
	    reqp->mr_key_kaddr, &buflen, &keyflags);
	if (rv != CRYPTO_SUCCESS) {
		mca_freereq(reqp);
		DBG(mca, DWARN, "mca_hash_key: mca_write_key failed with 0x%x",
		    rv);
		return (rv);
	}

	keyhead = (mca_key_head_t *)reqp->mr_key_kaddr;
	switch (GETBUF32(&(keyhead->keytype))) {
	case KEYTYPE_DES:
	case KEYTYPE_DES2:
	case KEYTYPE_DES3:
	case KEYTYPE_AES:
	case KEYTYPE_GENERIC_SECRET:
	case KEYTYPE_RC2:
	case KEYTYPE_RC4:
		/* secret keys are digestible */
		break;
	default:
		DBG(mca, DCHATTY, "mca_hash_key: key must be a secret key");
		mca_freereq(reqp);
		return (CRYPTO_KEY_INDIGESTIBLE);
	}

	reqp->mr_key_flags[0] = keyflags;
	reqp->mr_short_key[SK_HASH_SESSIONID] = ctx->cc_session;
	reqp->mr_short_key[SK_HASH_KEYFLAGS] = keyflags;
	reqp->mr_cf_req = cfreq;
	reqp->mr_key_len = buflen;
	reqp->mr_in = NULL;
	reqp->mr_out = NULL;

	/*
	 * If this is the first digest update/key, the operation
	 * must be initialized in FW: Get a context id.
	 */
	if (!(privctx->mc_cmd & CMD_HI_MULTI_PART)) {
		privctx->mc_cmd |= CMD_HI_MULTI_PART;
		reqp->mr_cmd = CMD_HASH_INIT;
		reqp->mr_context = privctx;
		reqp->mr_short_key[SK_HASH_CMD] = (privctx->mc_cmd & CMD_MASK);
		reqp->mr_cf_req = cfreq;
		reqp->mr_callback = hash_init_done;
		reqp->mr_out_len = sizeof (uint32_t);
		reqp->mr_out_paddr = reqp->mr_obuf_paddr;
		reqp->mr_out_next_paddr = 0;
		rv = mca_start(reqp);
		if (rv != CRYPTO_QUEUED) {
			mca_freereq(reqp);
		}
		return (rv);
	}

	if ((rv = hash_key(reqp)) != CRYPTO_QUEUED) {
		mca_freereq(reqp);
	}

	return (rv);
}

static int
hash_key(mca_request_t *reqp)
{
	int			rv;
	mca_t			*mca = reqp->mr_mca;
	mca_privatectx_t	*privctx = reqp->mr_context;
	mca_session_t		*session = NULL;
	mca_key_head_t		*keyhead;

	/* set the context id */
	reqp->mr_short_key[SK_HASH_CTXID] = privctx->mc_shortparam[0];

	/*
	 * If it is a token or sensitive key, hold on to the session and
	 * grab the user lock
	 */
	keyhead = (mca_key_head_t *)reqp->mr_key_kaddr;
	if ((keyhead->cardid != 0) || (keyhead->objectid != 0)) {
		int		session_id;
		uint16_t	keyflags;

		session_id = reqp->mr_short_key[SK_HASH_SESSIONID];
		keyflags = reqp->mr_short_key[SK_HASH_KEYFLAGS];

		if (keyflags & (KEYFLAG_PERSIST | KEYFLAG_SENSITIVE)) {
			mca_keystore_t *ks;
			ks = mca_keystore_lookup_by_session(session_id);
			reqp->mr_dbm_handle = mca_ks_get_handle(ks, mca);
		}

		if (keyflags & KEYFLAG_PERSIST) {
			session = mca_session_holdref(mca, session_id);
			if (session == NULL) {
				return (CRYPTO_SESSION_HANDLE_INVALID);
			}

			rv = mca_get_session_cred(session, reqp->mr_cred);
			if (rv != CRYPTO_SUCCESS) {
				mca_session_releaseref(session, UNLOCKED);
				return (rv);
			}

			reqp->mr_session = session;
			mca_user_rdlock(session->ms_user);
			reqp->mr_flags |= MRF_KSREAD;
		}
	}

	reqp->mr_cmd = CMD_HASH_KEY;
	reqp->mr_callback = hash_key_done;
	reqp->mr_job_stat = MS_HASHKEYJOBS;
	reqp->mr_in_len = 0;
	reqp->mr_out_len = 0;

	/* schedule the work by doing a submit */
	rv = mca_start(reqp);
	if ((rv != CRYPTO_QUEUED) && (reqp->mr_flags & MRF_KSREAD)) {
		mca_user_unlock(session->ms_user);
		mca_session_releaseref(session, UNLOCKED);
	}

	return (rv);
}

/*
 * The mca_request structure already allocated can be reused.
 * If it has not already been allocated, 'reqp' should be NULL.
 */
int
mca_hash_final(mca_t *mca, uint32_t ctxid, uint32_t cmd,
    crypto_data_t *digest, crypto_req_handle_t *cfreq)
{
	mca_request_t	*reqp;
	int		rv;
	uchar_t		*nullhash;
	int		jobstat;
	int		bytestat;
	int		outsz;

	switch (cmd & CMD_MASK) {
	case CMD_MD5:
		jobstat = MS_MD5JOBS;
		bytestat = MS_MD5BYTES;
		nullhash = mca_nullmd5;
		outsz = MD5LEN;
		break;
	case CMD_SHA1:
		jobstat = MS_SHA1JOBS;
		bytestat = MS_SHA1BYTES;
		nullhash = mca_nullsha1;
		outsz = SHA1LEN;
		break;
	case CMD_SHA512:
		jobstat = MS_SHA512JOBS;
		bytestat = MS_SHA512BYTES;
		nullhash = mca_nullsha512;
		outsz = SHA512LEN;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	/*
	 * There has been no hash_update: consided NULL input.
	 * Return the known hash value.
	 */
	if ((int)cmd < 0) {
		/*
		 * scatter the pre-calculated hash value among one or
		 * more buffers in 'digest'
		 */
		return (mca_scatter((char *)nullhash, outsz, digest));
	}

	if (outsz > mca_get_datalen(digest)) {
		DBG(mca, DCHATTY, "inadequate output space (need %d, got %d)",
		    outsz, mca_get_datalen(digest));
		mca_set_datalen(digest, outsz);
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	if ((reqp = mca_getreq(&mca->mca_ring_cb)) == NULL) {
		mca_error(mca, "unable to allocate request for "
		    "pure hash");
		return (CRYPTO_BUSY);
	}

	reqp->mr_out = digest;
	reqp->mr_out_len = outsz;

	reqp->mr_cf_req = cfreq;
	reqp->mr_job_stat = jobstat;
	reqp->mr_byte_stat = bytestat;
	reqp->mr_byte_count = 0;
	reqp->mr_short_key[SK_HASH_CTXID] = ctxid;

	if ((rv = hash_final(reqp)) != CRYPTO_QUEUED) {
		mca_freereq(reqp);
	}
	return (rv);
}

static int
hash_final(mca_request_t *reqp)
{
	reqp->mr_cmd = CMD_HASH_FINAL;

	/*
	 * Since output for digest op is always smaller than mca_dma,
	 * we do scattering instead of direct DMA.
	 * mr_out_len should be set by the caller.
	 */
	reqp->mr_flags |= MRF_SCATTER;
	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_out_next_paddr = 0;

	/* no input for multi_final */
	reqp->mr_in = NULL;
	reqp->mr_in_len = 0;
	reqp->mr_byte_count = 0;

	if (reqp->mr_out == NULL) {
		return (CRYPTO_ARGUMENTS_BAD);
	} else {
		/* clear the length field: updated by mca_scatter */
		reqp->mr_out->cd_length = 0;
	}

	reqp->mr_callback = hash_done;

	/* schedule the work by doing a submit */
	return (mca_start(reqp));
}


int
mca_hash(mca_t *mca, uint32_t cmd, crypto_data_t *data, crypto_data_t *digest,
    crypto_req_handle_t *cfreq)
{
	mca_request_t		*reqp;
	int			len;
	int			outsz;
	int			rv;
	int			jobstat;
	int			bytestat;
	uchar_t			*nullhash;

	switch (cmd & CMD_MASK) {
	case CMD_MD5:
		outsz = MD5LEN;
		jobstat = MS_MD5JOBS;
		bytestat = MS_MD5BYTES;
		nullhash = mca_nullmd5;
		break;
	case CMD_SHA1:
		outsz = SHA1LEN;
		jobstat = MS_SHA1JOBS;
		bytestat = MS_SHA1BYTES;
		nullhash = mca_nullsha1;
		break;
	case CMD_SHA512:
		outsz = SHA512LEN;
		jobstat = MS_SHA512JOBS;
		bytestat = MS_SHA512BYTES;
		nullhash = mca_nullsha512;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	if (outsz > mca_get_datalen(digest)) {
		DBG(mca, DCHATTY, "inadequate output space (need %d, got %d)",
		    outsz, mca_get_datalen(digest));
		mca_set_datalen(digest, outsz);
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	if ((reqp = mca_getreq(&mca->mca_ring_cb)) == NULL) {
		mca_error(mca, "unable to allocate request for pure hash");
		return (CRYPTO_BUSY);
	}

	MCA_SET_REQ_DATA(reqp, data, digest);

	/*
	 * If this is a "null" input, then we special case it in software
	 * using a constant known answer.  See the comments above for more
	 * detail.
	 */
	len = mca_get_datalen(data);
	if (len == 0) {
		/*
		 * scatter the pre-calculated hash value among one or
		 * more buffers in 'digest'
		 */
		rv = mca_scatter((char *)nullhash, outsz, reqp->mr_out);
		mca_freereq(reqp);
		return (rv);
	}

	reqp->mr_cf_req = cfreq;
	reqp->mr_out_len = outsz;
	reqp->mr_job_stat = jobstat;
	reqp->mr_byte_stat = bytestat;
	reqp->mr_byte_count = len;
	reqp->mr_cmd = cmd;

	rv = hash_start(reqp, len, outsz);
	if (rv != CRYPTO_QUEUED) {
		mca_freereq(reqp);
	}
	return (rv);
}


static int
hash_start(mca_request_t *reqp, size_t len, size_t outlen)
{
	int rv;

	reqp->mr_flags &= ~MRF_GATHER;
	/*
	 * Since output for digest op is always smaller than mca_dma,
	 * we do scattering instead of direct DMA.
	 */
	reqp->mr_flags |= MRF_SCATTER;
	if ((len < mca_mindma) || mca_sg(reqp->mr_in)) {
		reqp->mr_flags |= MRF_GATHER;
	}

	/* Try to do direct DMA for input */
	if (!(reqp->mr_flags & MRF_GATHER)) {
		/*
		 * By passing 0 in the third argument (outlen) to
		 * mca_bindchains, we avoid direct DMA for output.
		 */
		if (mca_bindchains(reqp, len, 0) != DDI_SUCCESS) {
			return (CRYPTO_FAILED);
		}

		if (!(reqp->mr_flags & MRF_GATHER)) {
			/* mca_bindchains clears <mr_out_len> */
			/* upon success.  Re-set it here. */
			reqp->mr_out_len = outlen;
		}
	}

	/* Otherwise we do a pullup (extra data copy) */
	if (reqp->mr_flags & MRF_GATHER) {
		/* terminate the pre-mapped chain */
		MCA_TERMINATE_CHAINS(&reqp->mr_ibuf_chain, len);

		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_first_len = min(reqp->mr_ibuf_sz, len);
		reqp->mr_in_len = len;
		if (reqp->mr_in_first_len == len) {
			reqp->mr_in_next_paddr = 0;
		} else {
			reqp->mr_in_next_paddr = reqp->mr_ibuf_next_paddr;
		}

		if ((rv = mca_gather(reqp->mr_in, reqp->mr_ibuf_kaddr,
		    reqp->mr_in_len)) != CRYPTO_SUCCESS) {
			goto exit;
		}
		ddi_dma_sync(reqp->mr_ibuf_dmah, 0, reqp->mr_in_len,
		    DDI_DMA_SYNC_FORDEV);
	}

	/* Funky hash output buffer */
	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_out_next_paddr = 0;
	reqp->mr_callback = hash_done;

	/* schedule the work by doing a submit */
	rv = mca_start(reqp);

exit:
	if (rv != CRYPTO_QUEUED) {
		/*EMPTY*/
		MCA_RESTORE_CHAIN(&reqp->mr_ibuf_chain);
	}

	return (rv);
}

static void
hash_init_done(mca_request_t *reqp)
{
	int		rv;
	uint32_t	ctxid;

	if (reqp->mr_errno != CRYPTO_SUCCESS) {
		crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
		mca_freereq(reqp);
		return;
	}

	ddi_dma_sync(reqp->mr_obuf_dmah, 0, sizeof (uint32_t),
	    DDI_DMA_SYNC_FORKERNEL);

	ctxid = GETBUF32((uint32_t *)reqp->mr_obuf_kaddr);
	reqp->mr_short_key[SK_HASH_CTXID] = ctxid;

	/* If this is digeset_update, store the ctxid to the privctx */
	if (reqp->mr_context != NULL) {
		mca_privatectx_t *privctx;
		privctx = reqp->mr_context;
		privctx->mc_shortparam[0] = ctxid;
	}

	if (reqp->mr_in == NULL) {
		/*
		 * If mr_in was NULL, hash_init was called for digest key:
		 * call hash_key
		 */
		rv = hash_key(reqp);
	} else {
		/*
		 * hash_init was called for digest_update, call hash_update
		 */
		rv = hash_update(reqp);
	}
	if (rv != CRYPTO_QUEUED) {
		crypto_op_notification(reqp->mr_cf_req, rv);
		mca_freereq(reqp);
		return;
	}
	/* the job was submitted to the HW */
}

static void
hash_key_done(mca_request_t *reqp)
{
	if (reqp->mr_flags & MRF_KSREAD) {
		mca_user_unlock(reqp->mr_session->ms_user);
	}

	crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
	mca_freereq(reqp);
}

static void
hash_update_done(mca_request_t *reqp)
{
	int	rv;

	MCA_RESTORE_CHAIN(&reqp->mr_ibuf_chain);

	if (reqp->mr_errno != CRYPTO_SUCCESS) {
		goto done;
	}

	if (mca_get_datalen(reqp->mr_in) > 0) {
		if ((rv = hash_update(reqp)) != CRYPTO_QUEUED) {
			reqp->mr_errno = rv;
			goto done;
		}
		/* the job was submitted to the HW */
		return;
	}

	/*
	 * If the cmd is a sigle_part or atomic operation and got here,
	 * the operation must be finalized here.
	 */
	if (reqp->mr_out != NULL) {
		reqp->mr_out_len = reqp->mr_short_key[SK_HASH_DIGESTSZ];
		if ((rv = hash_final(reqp)) == CRYPTO_QUEUED) {
			/* the job was submitted to the HW */
			return;
		}
		reqp->mr_errno = rv;
	}

done:
	crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
	mca_freereq(reqp);
}

static void
hash_done(mca_request_t *reqp)
{
	MCA_RESTORE_CHAIN(&reqp->mr_ibuf_chain);

	if (reqp->mr_errno == CRYPTO_SUCCESS) {
		int	rv;

		ddi_dma_sync(reqp->mr_obuf_dmah, 0, reqp->mr_out_len,
		    DDI_DMA_SYNC_FORKERNEL);
		if ((rv = mca_scatter(reqp->mr_obuf_kaddr, reqp->mr_out_len,
		    reqp->mr_out)) != CRYPTO_SUCCESS) {
			reqp->mr_errno = rv;
		}
	}

	crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
	mca_freereq(reqp);
}
