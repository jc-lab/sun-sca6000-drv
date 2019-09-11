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

#pragma ident	"@(#)mca_hmac.c	1.3	08/08/13 SMI"

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
 * MD5/SHA1/SHA512 HMAC implementation.
 */
static int	hmac_start(mca_request_t *, size_t, size_t);
static int	hmac_update(mca_request_t *);
static int	hmac_final(mca_request_t *);
static void	hmac_init_done(mca_request_t *);
static void	hmac_update_done(mca_request_t *);
static void	hmac_done(mca_request_t *);
static void	hmac_verifydone(mca_request_t *);

/*
 * Conver the parameter to integer, which is the output length for the HMAC
 * operation. It returns -1 if the peramaeter is malformed.
 */
static int
param2outlen(crypto_mechanism_t *mech)
{
	if (mech->cm_param == NULL) {
		return (-1);
	}

	if (mech->cm_param_len == sizeof (uint64_t)) {
		return (*(uint64_t *)mech->cm_param);
	} else if (mech->cm_param_len == sizeof (uint32_t)) {
		return (*(uint32_t *)mech->cm_param);
	} else {
		return (-1);
	}
}

int
mca_hmac_allocctx(mca_t *mca, crypto_session_id_t session_id,
    crypto_mechanism_t *mech, crypto_key_t *key, mca_privatectx_t **privctx)
{
	int		rv;
	uint32_t	cmd;
	int		outlen = -1;

	switch (mech->cm_type) {
	case MCAM_SHA_1_HMAC_GENERAL:
		outlen = param2outlen(mech);
		if ((outlen == -1) || (outlen > SHA1LEN)) {
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		}
		cmd = CMD_HMAC_SHA1;
		break;
	case MCAM_SHA_1_HMAC:
		outlen = SHA1LEN;
		cmd = CMD_HMAC_SHA1;
		break;
	case MCAM_SHA512_HMAC_GENERAL:
		outlen = param2outlen(mech);
		if ((outlen == -1) || (outlen > SHA512LEN)) {
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		}
		cmd = CMD_HMAC_SHA512;
		break;
	case MCAM_SHA512_HMAC:
		outlen = SHA512LEN;
		cmd = CMD_HMAC_SHA512;
		break;
	case MCAM_MD5_HMAC_GENERAL:
		outlen = param2outlen(mech);
		if ((outlen == -1) || (outlen > MD5LEN)) {
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		}
		cmd = CMD_HMAC_MD5;
		break;
	case MCAM_MD5_HMAC:
		outlen = MD5LEN;
		cmd = CMD_HMAC_MD5;
		break;
	default:
		cmd = 0;
		return (CRYPTO_MECHANISM_INVALID);
	}

	/* hmac operation needs mech-name only for the context */
	rv = mca_allocctx(mca, session_id, key, cmd, 0, privctx);

	/* set the ctxid to NULL, and expected outlen */
	if (rv == CRYPTO_SUCCESS) {
		(*privctx)->mc_shortparam[0] = -1;
		(*privctx)->mc_shortparam[1] = outlen;
	}

	return (rv);
}


static int
hmac_set_request(mca_request_t *reqp, mca_privatectx_t *ctx)
{
	int	rv;

	bcopy(ctx->mc_keyhead, reqp->mr_key_kaddr, ctx->mc_keyheadsz);
	reqp->mr_key_len = ctx->mc_keyheadsz;

	reqp->mr_key_id[0] = GETBUF32(&(ctx->mc_keyhead->cardid));
	reqp->mr_key_id[1] = GETBUF32(&(ctx->mc_keyhead->objectid));
	reqp->mr_key_flags[0] = ctx->mc_keyflags;

	if (ctx->mc_session != NULL) {
		rv = mca_get_session_cred(ctx->mc_session, reqp->mr_cred);
		if (rv != CRYPTO_SUCCESS) {
			return (rv);
		}
	}

	/*
	 * Setup the key.  In FIPS mode we have to encrypt the key
	 * under the KTK, but only if we are passing an actual key's
	 * value in the clear.  (I.e. we do not do this if we have a
	 * token or sensitive key, in which case the key id is
	 * non-zero.)
	 */
	if (mca_isfips(reqp->mr_mca) &&
	    (reqp->mr_key_id[0] == 0) && (reqp->mr_key_id[1] == 0)) {
		mca_ktkencryptkey(reqp);
	}

	reqp->mr_context = ctx;

	return (CRYPTO_SUCCESS);
}


/*
 * This function initialized the operation: get a context ID from HW.
 * This functions may be called for signature single part and atomic operations
 * if the data is greater than 64KB. In which case, output buffer 'signature'
 * must be provided by the caller.
 * Note: short_key[4] for the init operation is used to pass the mechanism
 * ID, and short_key[4] for the update/final is used to pass the context ID.
 * short_key[5] is used to pass the hash size.
 */
int
mca_hmac_init(mca_t *mca, mca_privatectx_t *ctx, uint32_t cmd,
    crypto_data_t *data, crypto_data_t *signature, crypto_req_handle_t *cfreq)
{
	mca_request_t	*reqp;
	int		rv;
	int		jobstat;
	int		bytestat;
	int		outsz;

	switch (cmd & CMD_MASK) {
	case CMD_HMAC_MD5:
		jobstat = MS_MD5HMACJOBS;
		bytestat = MS_MD5HMACBYTES;
		outsz = MD5LEN;
		break;
	case CMD_HMAC_SHA1:
		jobstat = MS_SHA1HMACJOBS;
		bytestat = MS_SHA1HMACBYTES;
		outsz = SHA1LEN;
		break;
	case CMD_HMAC_SHA512:
		jobstat = MS_SHA512HMACJOBS;
		bytestat = MS_SHA512HMACBYTES;
		outsz = SHA512LEN;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	/*
	 * Single-part/atomic operation: make sure that the output buffer is
	 * large enough
	 */
	if (signature) {
		if (outsz > mca_get_datalen(signature)) {
			DBG(mca, DCHATTY, "inadequate output space (need %d, "
			    "got %d)", outsz, mca_get_datalen(signature));
			mca_set_datalen(signature, outsz);
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}

	if ((reqp = mca_getreq(&mca->mca_ring_cb)) == NULL) {
		mca_error(mca, "unable to allocate request for "
		    "multi-part hmac");
		return (CRYPTO_BUSY);
	}
	if ((rv = hmac_set_request(reqp, ctx)) != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "hmac_set_requset failed");
		mca_freereq(reqp);
		return (rv);
	}

	/* if the key is token key, hold the keystore readlock */
	if (ctx->mc_session != NULL) {
		reqp->mr_session = ctx->mc_session;
		mca_user_rdlock(ctx->mc_session->ms_user);
		reqp->mr_flags |= MRF_KSREAD;
	}
	/* if this is a token or senstitive session key - set the ks handle */
	if (ctx->mc_keystore) {
		reqp->mr_dbm_handle =
		    mca_ks_get_handle(ctx->mc_keystore, reqp->mr_mca);
	}

	reqp->mr_tmpin = *data;
	reqp->mr_in = &reqp->mr_tmpin;
	reqp->mr_out = signature;
	if ((cmd & CMD_HI_SIGN) && (reqp->mr_out != NULL)) {
		reqp->mr_out->cd_length = 0;
	}
	reqp->mr_out_len = sizeof (uint32_t);
	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_cmd = CMD_HMAC_INIT;
	reqp->mr_context = ctx;
	reqp->mr_short_key[SK_HASH_CMD] = cmd & CMD_MASK;
	reqp->mr_short_key[SK_HASH_DIGESTSZ] = outsz;
	reqp->mr_job_stat = jobstat;
	reqp->mr_byte_stat = bytestat;
	reqp->mr_cf_req = cfreq;
	reqp->mr_callback = hmac_init_done;

	rv = mca_start(reqp);
	if ((rv != CRYPTO_QUEUED) && (reqp->mr_flags & MRF_KSREAD)) {
		mca_user_unlock(reqp->mr_context->mc_session->ms_user);
	}
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
mca_hmac_update(mca_t *mca, uint32_t ctxid, uint32_t cmd,
    crypto_data_t *data, crypto_req_handle_t *cfreq)
{
	mca_request_t	*reqp;
	int		rv;
	int		jobstat;
	int		bytestat;

	switch (cmd & CMD_MASK) {
	case CMD_HMAC_MD5:
		jobstat = MS_MD5HMACJOBS;
		bytestat = MS_MD5HMACBYTES;
		break;
	case CMD_HMAC_SHA1:
		jobstat = MS_SHA1HMACJOBS;
		bytestat = MS_SHA1HMACBYTES;
		break;
	case CMD_HMAC_SHA512:
		jobstat = MS_SHA512HMACJOBS;
		bytestat = MS_SHA512HMACBYTES;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	if ((reqp = mca_getreq(&mca->mca_ring_cb)) == NULL) {
		mca_error(mca, "unable to allocate request for "
		    "multi-part hmac");
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
	reqp->mr_cmd = CMD_HMAC_UPDATE;

	if ((rv = hmac_update(reqp)) != CRYPTO_QUEUED) {
		mca_freereq(reqp);
	}

	return (rv);
}

static int
hmac_update(mca_request_t *reqp)
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
	len = min(len, MAXPACKET);

	reqp->mr_cmd = CMD_HMAC_UPDATE;
	reqp->mr_callback = hmac_update_done;
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


/*
 * The mca_request structure already allocated can be reused.
 * If it has not already been allocated, 'reqp' should be NULL.
 */
int
mca_hmac_final(mca_t *mca, mca_privatectx_t *ctx,
    crypto_data_t *signature, crypto_req_handle_t *cfreq)
{
	mca_request_t	*reqp;
	int		rv;
	int		jobstat;
	int		bytestat;
	int		outsz;

	switch (ctx->mc_cmd & CMD_MASK) {
	case CMD_HMAC_MD5:
		jobstat = MS_MD5HMACJOBS;
		bytestat = MS_MD5HMACBYTES;
		outsz = MD5LEN;
		break;
	case CMD_HMAC_SHA1:
		jobstat = MS_SHA1HMACJOBS;
		bytestat = MS_SHA1HMACBYTES;
		outsz = SHA1LEN;
		break;
	case CMD_HMAC_SHA512:
		jobstat = MS_SHA512HMACJOBS;
		bytestat = MS_SHA512HMACBYTES;
		outsz = SHA512LEN;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	if (ctx->mc_shortparam[1] > mca_get_datalen(signature)) {
		DBG(mca, DCHATTY, "inadequate output space (need %d, got %d)",
		    outsz, mca_get_datalen(signature));
		if (ctx->mc_cmd & CMD_HI_SIGN) {
			mca_set_datalen(signature, outsz);
			return (CRYPTO_BUFFER_TOO_SMALL);
		} else {
			return (CRYPTO_SIGNATURE_LEN_RANGE);
		}
	}

	if ((reqp = mca_getreq(&mca->mca_ring_cb)) == NULL) {
		mca_error(mca, "unable to allocate request for "
		    "pure hmac");
		return (CRYPTO_BUSY);
	}

	reqp->mr_context = ctx;
	reqp->mr_out = signature;
	reqp->mr_out_len = outsz;

	reqp->mr_cf_req = cfreq;
	reqp->mr_job_stat = jobstat;
	reqp->mr_byte_stat = bytestat;
	reqp->mr_byte_count = 0;
	reqp->mr_short_key[SK_HASH_CTXID] = ctx->mc_shortparam[0];

	if ((rv = hmac_final(reqp)) != CRYPTO_QUEUED) {
		mca_freereq(reqp);
	}
	return (rv);
}

static int
hmac_final(mca_request_t *reqp)
{
	mca_privatectx_t	*ctx;

	reqp->mr_cmd = CMD_HMAC_FINAL;

	/*
	 * Since output for signature op is always smaller than mca_dma,
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
	}

	ctx = reqp->mr_context;
	if (ctx->mc_cmd & CMD_HI_SIGN) {
		/* clear the length field: updated by mca_scatter */
		reqp->mr_out->cd_length = 0;
		reqp->mr_callback = hmac_done;
	} else {
		reqp->mr_callback = hmac_verifydone;
	}

	/* schedule the work by doing a submit */
	return (mca_start(reqp));
}


/*
 * HMAC atomic operation.
 * The data length must be less than or equal to MAXPACKET.
 */
int
mca_hmac_atomic(mca_t *mca, crypto_session_id_t session_id,
    crypto_mechanism_t *mech, crypto_key_t *key,
    crypto_data_t *data, crypto_data_t *signature,
    crypto_req_handle_t *cfreq, uint32_t cmd)
{
	int			rv;
	mca_privatectx_t	*privctx;

	rv = mca_hmac_allocctx(mca, session_id, mech, key, &privctx);
	if (rv != CRYPTO_SUCCESS) {
		return (rv);
	}
	if (cmd & CMD_HI_SIGN) {
		privctx->mc_cmd |= CMD_HI_SIGN;
	} else {
		privctx->mc_cmd |= CMD_HI_VRFY;
	}

	rv = mca_hmac(privctx, data, signature, cfreq, cmd);
	if (rv != CRYPTO_QUEUED) {
		mca_freectx(privctx);
		return (rv);
	}

	return (rv);
}


/*
 * HMAC single part operation.
 * The data length must be less than or equal to MAXPACKET.
 */
int
mca_hmac(mca_privatectx_t *privctx, crypto_data_t *data,
    crypto_data_t *signature, crypto_req_handle_t *cfreq, uint32_t cmd)
{
	mca_t			*mca = privctx->mc_mca;
	mca_request_t		*reqp;
	int			len;
	int			hashlen;
	int			outsz;
	int			rv;
	int			jobstat;
	int			bytestat;

	if (privctx == NULL) {
		return (CRYPTO_OPERATION_NOT_INITIALIZED);
	}

	/*
	 * outsz may be specified by the caller if the operation
	 * is HMAC_GENERAL
	 */
	outsz = privctx->mc_shortparam[1];

	switch (cmd & CMD_MASK) {
	case CMD_HMAC_MD5:
		jobstat = MS_MD5HMACJOBS;
		bytestat = MS_MD5HMACBYTES;
		hashlen = MD5LEN;
		break;
	case CMD_HMAC_SHA1:
		jobstat = MS_SHA1HMACJOBS;
		bytestat = MS_SHA1HMACBYTES;
		hashlen = SHA1LEN;
		break;
	case CMD_HMAC_SHA512:
		jobstat = MS_SHA512HMACJOBS;
		bytestat = MS_SHA512HMACBYTES;
		hashlen = SHA512LEN;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	if ((privctx->mc_cmd & CMD_HI_SIGN) &&
	    outsz > mca_get_datalen(signature)) {
		DBG(mca, DCHATTY, "inadequate output space (need %d, got %d)",
		    outsz, mca_get_datalen(signature));
		mca_set_datalen(signature, outsz);
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	if ((reqp = mca_getreq(&mca->mca_ring_cb)) == NULL) {
		mca_error(mca, "unable to allocate request for pure hmac");
		return (CRYPTO_BUSY);
	}

	if ((rv = hmac_set_request(reqp, privctx)) != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "hmac_set_requset failed");
		mca_freereq(reqp);
		return (rv);
	}

	if (cmd & CMD_HI_SIGN) {
		MCA_SET_REQ_DATA(reqp, data, signature);
	} else {
		reqp->mr_tmpin = *data;
		reqp->mr_in = &reqp->mr_tmpin;
		reqp->mr_out = signature;
	}

	len = mca_get_datalen(data);

	reqp->mr_cf_req = cfreq;
	reqp->mr_out_len = hashlen;
	reqp->mr_job_stat = jobstat;
	reqp->mr_byte_stat = bytestat;
	reqp->mr_byte_count = len;
	reqp->mr_cmd = cmd;

	rv = hmac_start(reqp, len, hashlen);
	if (rv != CRYPTO_QUEUED) {
		mca_freereq(reqp);
	}
	return (rv);
}


static int
hmac_start(mca_request_t *reqp, size_t len, size_t outlen)
{
	int			rv;
	mca_privatectx_t	*ctx;

	reqp->mr_flags &= ~MRF_GATHER;
	/*
	 * Since output for signature op is always smaller than mca_dma,
	 * we do scattering instead of direct DMA.
	 */
	reqp->mr_flags |= MRF_SCATTER;
	ASSERT(len <= MAXPACKET);

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

	/* Funky hmac output buffer */
	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_out_next_paddr = 0;

	ctx = reqp->mr_context;
	if (ctx->mc_cmd & CMD_HI_SIGN) {
		/* clear the length field: updated by mca_scatter */
		reqp->mr_out->cd_length = 0;
		reqp->mr_callback = hmac_done;
	} else {
		reqp->mr_callback = hmac_verifydone;
	}

	/* if the key is token key, hold the keystore readlock */
	if (reqp->mr_context->mc_session != NULL) {
		reqp->mr_session = reqp->mr_context->mc_session;
		mca_user_rdlock(reqp->mr_context->mc_session->ms_user);
		reqp->mr_flags |= MRF_KSREAD;
	}
	/* if this is a token or senstitive session key - set the ks handle */
	if (reqp->mr_context->mc_keystore) {
		reqp->mr_dbm_handle =
		    mca_ks_get_handle(reqp->mr_context->mc_keystore,
		    reqp->mr_mca);
	}

	/* schedule the work by doing a submit */
	rv = mca_start(reqp);

exit:
	if (rv != CRYPTO_QUEUED) {
		MCA_RESTORE_CHAIN(&reqp->mr_ibuf_chain);
		if (reqp->mr_flags & MRF_KSREAD) {
			mca_user_unlock(
			    reqp->mr_context->mc_session->ms_user);
		}
	}

	return (rv);
}

static void
hmac_init_done(mca_request_t *reqp)
{
	int		rv;
	uint32_t	ctxid;

	if (reqp->mr_flags & MRF_KSREAD) {
		mca_user_unlock(reqp->mr_session->ms_user);
	}

	if (reqp->mr_errno != CRYPTO_SUCCESS) {
		crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
		mca_freereq(reqp);
		return;
	}

	ddi_dma_sync(reqp->mr_obuf_dmah, 0, sizeof (uint32_t),
	    DDI_DMA_SYNC_FORKERNEL);

	ctxid = GETBUF32((uint32_t *)reqp->mr_obuf_kaddr);
	reqp->mr_short_key[SK_HASH_CTXID] = ctxid;

	/* If this is hmac_update, store the ctxid to the privctx */
	if (reqp->mr_context != NULL) {
		mca_privatectx_t *privctx;
		privctx = reqp->mr_context;
		privctx->mc_shortparam[0] = ctxid;
	}

	rv = hmac_update(reqp);
	if (rv != CRYPTO_QUEUED) {
		crypto_op_notification(reqp->mr_cf_req, rv);
		mca_freereq(reqp);
		return;
	}
	/* the job was submitted to the HW */
}

static void
hmac_update_done(mca_request_t *reqp)
{
	int	rv;

	MCA_RESTORE_CHAIN(&reqp->mr_ibuf_chain);

	if (reqp->mr_errno != CRYPTO_SUCCESS) {
		goto done;
	}

	if (mca_get_datalen(reqp->mr_in) > 0) {
		if ((rv = hmac_update(reqp)) != CRYPTO_QUEUED) {
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
		if ((rv = hmac_final(reqp)) == CRYPTO_QUEUED) {
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
hmac_done(mca_request_t *reqp)
{
	uint32_t		cmd = reqp->mr_cmd;
	mca_privatectx_t	*ctx = reqp->mr_context;

	MCA_RESTORE_CHAIN(&reqp->mr_ibuf_chain);

	if (reqp->mr_flags & MRF_KSREAD) {
		mca_user_unlock(reqp->mr_session->ms_user);
	}

	if (reqp->mr_errno == CRYPTO_SUCCESS) {
		int	rv;

		ddi_dma_sync(reqp->mr_obuf_dmah, 0, reqp->mr_resultlen,
		    DDI_DMA_SYNC_FORKERNEL);
		if ((rv = mca_scatter(reqp->mr_obuf_kaddr,
		    ctx->mc_shortparam[1], reqp->mr_out)) != CRYPTO_SUCCESS) {
			reqp->mr_errno = rv;
		}
	}

	crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
	mca_freereq(reqp);

	if (cmd  & CMD_HI_ATOMIC) {
		mca_freectx(ctx);
	}
}


static void
hmac_verifydone(mca_request_t *reqp)
{
	uint32_t		cmd = reqp->mr_cmd;
	mca_privatectx_t	*ctx = reqp->mr_context;

	MCA_RESTORE_CHAIN(&reqp->mr_ibuf_chain);

	if (reqp->mr_flags & MRF_KSREAD) {
		mca_user_unlock(reqp->mr_session->ms_user);
	}

	if (reqp->mr_errno == CRYPTO_SUCCESS) {
		char		buf[SHA512LEN];

		ddi_dma_sync(reqp->mr_obuf_dmah, 0, reqp->mr_resultlen,
		    DDI_DMA_SYNC_FORKERNEL);

		if (reqp->mr_resultlen < ctx->mc_shortparam[1]) {
			reqp->mr_errno = CRYPTO_SIGNATURE_LEN_RANGE;
			goto done;
		}

		if (mca_gather(reqp->mr_out, buf, ctx->mc_shortparam[1])
		    != CRYPTO_SUCCESS) {
			reqp->mr_errno = CRYPTO_ARGUMENTS_BAD;
			goto done;
		}

		if (memcmp(buf, reqp->mr_obuf_kaddr,
		    ctx->mc_shortparam[1])) {
			reqp->mr_errno = CRYPTO_SIGNATURE_INVALID;
		}
	}

done:
	crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
	mca_freereq(reqp);

	if (cmd  & CMD_HI_ATOMIC) {
		mca_freectx(ctx);
	}
}
