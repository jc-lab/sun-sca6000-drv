/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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

#pragma ident	"@(#)mca_rsa.c	1.6	06/12/01 SMI"

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
#include <sys/kmem.h>
#include <sys/mca.h>
#endif

/*
 * RSA implementation.
 */

static int rsa_start(mca_t *, mca_request_t *,
    crypto_data_t *, crypto_data_t *, crypto_req_handle_t *, uint32_t);
static void rsa_verifydone(mca_request_t *);
static void rsa_done(mca_request_t *);

static int
rsa_set_request(mca_request_t *reqp, mca_privatectx_t *ctx)
{
	int rv;

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

	reqp->mr_context = ctx;

	return (CRYPTO_SUCCESS);
}

static void
rsa_get_modulus(mca_key_head_t *keyhead, char **modulus, int *modlen)
{
	int	keytype = GETBUF32(&(keyhead->keytype));
	int	keyheadsz = GETBUF32(&(keyhead->valuelen));

	if (keytype == KEYTYPE_RSA_PUBLIC) {
		pubrsa_head_t	*rsahead;
		rsahead = (pubrsa_head_t *)((char *)keyhead +
		    sizeof (mca_key_head_t) + GETBUF32(&(keyhead->descrlen)));

		if (keyheadsz < sizeof (pubrsa_head_t)) {
			*modulus = NULL;
			*modlen = 0;
			return;
		}

		*modulus = (char *)rsahead + sizeof (pubrsa_head_t);
		*modlen = GETBUF32(&rsahead->modlen);
	} else if (keytype == KEYTYPE_RSA_PRIVATE) {
		prirsa_head_t	*rsahead;
		rsahead = (prirsa_head_t *)((char *)keyhead +
		    sizeof (mca_key_head_t) + GETBUF32(&(keyhead->descrlen)));

		if (keyheadsz < sizeof (prirsa_head_t)) {
			*modulus = NULL;
			*modlen = 0;
			return;
		}

		*modulus = (char *)rsahead + sizeof (prirsa_head_t);
		*modlen = GETBUF32(&rsahead->modlen);
	} else {
		*modulus = NULL;
		*modlen = 0;
	}
}


/*ARGSUSED*/
int
mca_rsainit(crypto_ctx_t *ctx, crypto_mechanism_t *mech, crypto_key_t *key,
    int kmflag, uint32_t cmd, mca_privatectx_t **privctx)
{
	return (mca_allocctx(MCA_CTX2MCA(ctx), ctx->cc_session, key,
	    cmd, sizeof (int), privctx));
}


int
mca_rsa(crypto_ctx_t *ctx, crypto_data_t *in, crypto_data_t *out,
    crypto_req_handle_t *cfreq, uint32_t cmd)
{
	mca_privatectx_t	*privctx;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_request_t		*reqp;
	int			rv;

	privctx = ctx->cc_provider_private;
	if (privctx == NULL) {
		return (CRYPTO_OPERATION_NOT_INITIALIZED);
	}

	if ((reqp = mca_getreq(&mca->mca_ring_ca)) == NULL) {
		mca_error(mca, "unable to allocate request for RSA");
		return (CRYPTO_BUSY);
	}

	if ((rv = rsa_set_request(reqp, privctx)) != CRYPTO_SUCCESS) {
		mca_freereq(reqp);
		return (rv);
	}

	if (privctx->mc_keystore) {
		reqp->mr_dbm_handle = mca_ks_get_handle(
		    privctx->mc_keystore, mca);
	}

	rv = rsa_start(mca, reqp, in, out, cfreq, cmd);
	if (rv != CRYPTO_QUEUED) {
		mca_freereq(reqp);
	}

	return (rv);
}

/*ARGSUSED*/
int
mca_rsaatomic(mca_t *mca, crypto_session_id_t session_id, crypto_key_t *key,
    crypto_data_t *in, crypto_data_t *out, crypto_req_handle_t *cfreq,
    uint32_t cmd)
{
	mca_privatectx_t	*privctx;
	mca_request_t		*reqp;
	int			rv;

	/* temporarily allocate the context */
	rv = mca_allocctx(mca, session_id, key, cmd, sizeof (int), &privctx);
	if (rv != CRYPTO_SUCCESS) {
		return (rv);
	}

	if ((reqp = mca_getreq(&mca->mca_ring_ca)) == NULL) {
		mca_error(mca, "unable to allocate request for RSA");
		mca_freectx(privctx);
		return (CRYPTO_BUSY);
	}

	if ((rv = rsa_set_request(reqp, privctx)) != CRYPTO_SUCCESS) {
		mca_freectx(privctx);
		mca_freereq(reqp);
		return (rv);
	}

	if (privctx->mc_keystore) {
		reqp->mr_dbm_handle = mca_ks_get_handle(
		    privctx->mc_keystore, mca);
	}

	rv = rsa_start(mca, reqp, in, out, cfreq, cmd);
	if (rv != CRYPTO_QUEUED) {
		mca_freereq(reqp);
	}

	mca_freectx(privctx);

	return (rv);
}


static int
rsa_start(mca_t *mca, mca_request_t *reqp, crypto_data_t *in,
    crypto_data_t *out, crypto_req_handle_t *cfreq, uint32_t cmd)
{
	int	rv;
	int	inlen;
	int	outlen;
	char	*modulus;
	int	modlen;
	int	jobstat = 0;

	/* we don't support non-contiguous buffers for RSA */
#if 0
	if ((in->av_forw != NULL) || (out->av_forw != NULL)) {
		return (CRYPTO_DATA_INVALID);
	}
#endif
	/* get modlen and modulus */
	rsa_get_modulus((mca_key_head_t *)reqp->mr_key_kaddr,
	    &modulus, &modlen);
	inlen = mca_get_datalen(in);
	if (modulus == NULL) {
		DBG(mca, DWARN, "modulus missing in rsa_start");
		return (CRYPTO_KEY_HANDLE_INVALID);
	}

	outlen = mca_get_datalen(out);

	switch (cmd & ~CMD_HI_KCF_INPLACE) {
	case CMD_RSAPUB:
		/* X509 Encrypt */
		jobstat = MS_RSAPUBLIC;
		if (inlen > modlen) {
			return (CRYPTO_DATA_LEN_RANGE);
		}
		if (outlen < modlen) {
			mca_set_datalen(out, modlen);
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
		outlen = modlen;
		break;
	case CMD_RSAPRV:
		/* X509 Decrypt */
		jobstat = MS_RSAPRIVATE;
		if (inlen != modlen) {
			return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);
		}
		if (outlen < modlen) {
			mca_set_datalen(out, modlen);
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
		outlen = modlen;
		break;
	case (CMD_HI_SIGN | CMD_RSAPRV):
	case (CMD_HI_SIGNR | CMD_RSAPRV):
		/* X509 Sign/SignRecover */
		jobstat = MS_RSAPRIVATE;
		if (inlen > modlen) {
			return (CRYPTO_DATA_LEN_RANGE);
		}
		if (outlen < modlen) {
			mca_set_datalen(out, modlen);
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
		outlen = modlen;
		break;
	case (CMD_HI_VRFY | CMD_RSAPUB):
		/* X509 Verify */
		jobstat = MS_RSAPUBLIC;
		if (inlen != modlen) {
			return (CRYPTO_SIGNATURE_LEN_RANGE);
		}
		if (outlen > modlen) {
			return (CRYPTO_DATA_LEN_RANGE);
		}
		break;
	case (CMD_HI_VRFYR | CMD_RSAPUB):
		/* X509 VerifyRecover */
		jobstat = MS_RSAPUBLIC;
		if (inlen != modlen) {
			return (CRYPTO_SIGNATURE_LEN_RANGE);
		}
		if (outlen < modlen) {
			mca_set_datalen(out, modlen);
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
		outlen = modlen;
		break;
	case CMD_RSAPADENC:
		/* RSA_PKCS Encrypt */
		jobstat = MS_RSAPUBLIC;
		if (inlen > (modlen - 11)) {
			return (CRYPTO_DATA_LEN_RANGE);
		}
		if (outlen < modlen) {
			mca_set_datalen(out, modlen);
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
		outlen = modlen;
		break;
	case CMD_RSAPADDEC:
		/* RSA_PKCS Decrypt */
		jobstat = MS_RSAPRIVATE;
		if (inlen != modlen) {
			return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);
		}
		break;
	case (CMD_HI_SIGN | CMD_RSAPADSIGN):
	case (CMD_HI_SIGNR | CMD_RSAPADSIGN):
		/* RSA_PKCS Sign/SignRecover */
		jobstat = MS_RSAPRIVATE;
		if (inlen > (modlen - 11)) {
			return (CRYPTO_DATA_LEN_RANGE);
		}
		if (outlen < modlen) {
			mca_set_datalen(out, modlen);
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
		outlen = modlen;
		break;
	case (CMD_HI_VRFY | CMD_RSAPADVRFY):
		/* RSA_PKCS Verify */
		jobstat = MS_RSAPUBLIC;
		if (inlen != modlen) {
			return (CRYPTO_SIGNATURE_LEN_RANGE);
		}
		if (outlen > (modlen - 11)) {
			return (CRYPTO_DATA_LEN_RANGE);
		}
		break;
	case (CMD_HI_VRFYR | CMD_RSAPADVRFY):
		/* RSA_PKCS VerifyRecover */
		jobstat = MS_RSAPUBLIC;
		if (inlen != modlen) {
			return (CRYPTO_SIGNATURE_LEN_RANGE);
		}
		break;
	}

	if (mca_cmp_numnbuf(in, (char *)modulus, modlen) > 0) {
		DBG(mca, DWARN, "input larger (numerically) than modulus!");
		switch (cmd & CMD_HI_SVMASK) {
		case 0:
			switch (cmd & CMD_MASK) {
			case CMD_RSAPUB:
			case CMD_RSAPADENC:
				return (CRYPTO_DATA_INVALID);
			case CMD_RSAPRV:
			case CMD_RSAPADDEC:
				return (CRYPTO_ENCRYPTED_DATA_INVALID);
			}
			return (CRYPTO_DATA_INVALID);
		case CMD_HI_SIGN:
		case CMD_HI_SIGNR:
		case CMD_HI_VRFY:
		case CMD_HI_VRFYR:
			return (CRYPTO_SIGNATURE_INVALID);
		default:
			return (CRYPTO_DATA_INVALID);
		}
	}

	reqp->mr_byte_stat = -1;
	reqp->mr_in_len = inlen;
	reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
	reqp->mr_in_next_paddr = 0;
	reqp->mr_out_len = outlen;
	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_out_next_paddr = 0;
	reqp->mr_cf_req = cfreq;
	reqp->mr_flags |= (MRF_GATHER | MRF_SCATTER);
	reqp->mr_job_stat = jobstat;
	reqp->mr_cmd = cmd;
	reqp->mr_short_key[4] = modlen;
	if ((cmd & CMD_HI_SVMASK) == CMD_HI_VRFY) {
		reqp->mr_callback = rsa_verifydone;
	} else {
		reqp->mr_callback = rsa_done;
	}

	MCA_SET_REQ_DATA(reqp, in, out);

	/* if the key is sensitive or token, hold the keystore readlock */
	if (reqp->mr_context->mc_session != NULL) {
		mca_user_rdlock(reqp->mr_context->mc_session->ms_user);
		reqp->mr_flags |= MRF_KSREAD;
	}

	/*
	 * If the key is an RSA private key, and the board is in FIPS mode,
	 * mr_key_kaddr field must be encrypted with ktk key
	 */
	if (mca_isfips(mca) && (jobstat == MS_RSAPRIVATE) &&
	    (reqp->mr_key_id[0] == 0) && (reqp->mr_key_id[1] == 0)) {
		mca_ktkencryptkey(reqp);
	}

	/* gather input data */
	rv = mca_gather(reqp->mr_in, reqp->mr_ibuf_kaddr, reqp->mr_in_len);
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "rsa_start: mca_gather failed "
		    "with 0x%x", rv);
		if (reqp->mr_flags & MRF_KSREAD) {
			mca_user_unlock(
			    reqp->mr_context->mc_session->ms_user);
		}
		return (rv);
	}
	ddi_dma_sync(reqp->mr_ibuf_dmah, 0, reqp->mr_in_len,
	    DDI_DMA_SYNC_FORDEV);

	/* schedule the work by doing a submit */
	if ((rv = mca_start(reqp)) != CRYPTO_QUEUED) {
		if (reqp->mr_flags & MRF_KSREAD) {
			mca_user_unlock(
			    reqp->mr_context->mc_session->ms_user);
		}
	}
	return (rv);
}

static void
rsa_done(mca_request_t *reqp)
{
	if (reqp->mr_flags & MRF_KSREAD) {
		mca_user_unlock(reqp->mr_context->mc_session->ms_user);
	}
	if (reqp->mr_errno == CRYPTO_SUCCESS) {
		int rv;

		if (reqp->mr_resultlen > reqp->mr_out_len) {
			reqp->mr_errno = CRYPTO_BUFFER_TOO_SMALL;
			goto exit;
		}

		ddi_dma_sync(reqp->mr_obuf_dmah, 0, reqp->mr_resultlen,
		    DDI_DMA_SYNC_FORKERNEL);
		rv = mca_scatter(reqp->mr_obuf_kaddr, reqp->mr_resultlen,
		    reqp->mr_out);
		if (rv != CRYPTO_SUCCESS) {
			reqp->mr_errno = rv;
		}
	}
	if (reqp->mr_errno == CRYPTO_SIGNATURE_INVALID) {
		reqp->mr_errno = CRYPTO_ENCRYPTED_DATA_INVALID;
	}
exit:
	mca_set_datalen(reqp->mr_out, reqp->mr_resultlen);
	crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
	mca_freereq(reqp);
}

static void
rsa_verifydone(mca_request_t *reqp)
{
	if (reqp->mr_flags & MRF_KSREAD) {
		mca_user_unlock(reqp->mr_context->mc_session->ms_user);
	}
	if (reqp->mr_errno == CRYPTO_SUCCESS) {
		ddi_dma_sync(reqp->mr_obuf_dmah, 0, reqp->mr_resultlen,
		    DDI_DMA_SYNC_FORKERNEL);

		if (mca_cmp_numnbuf(reqp->mr_out,
		    reqp->mr_obuf_kaddr, reqp->mr_resultlen) != 0) {
			/* verify failure */
			reqp->mr_errno = CRYPTO_SIGNATURE_INVALID;
		}
	} else if (reqp->mr_errno == CRYPTO_BUFFER_TOO_SMALL) {
		/*
		 * FW returns CRYPTO_BUFFER_TOO_SMALL if the length of
		 * the recovered data is longer than expected data length.
		 * In which case, CRYPTO_SIGNATURE_INVALID should be
		 * returned instead.
		 */
		reqp->mr_errno = CRYPTO_SIGNATURE_INVALID;
	}
	crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
	mca_freereq(reqp);
}
