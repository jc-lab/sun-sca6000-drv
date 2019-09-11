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

#pragma ident	"@(#)mca_dsa.c	1.10	08/08/13 SMI"

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
 * DSA implementation.
 */
static int dsa_start(mca_t *, mca_request_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t *, uint32_t);
static void dsa_signdone(mca_request_t *);
static void dsa_verifydone(mca_request_t *);

/* used for single-part operation */
static int
dsa_set_request(mca_request_t *reqp, mca_privatectx_t *ctx)
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

	reqp->mr_context = ctx;

	return (CRYPTO_SUCCESS);
}

static void
dsa_get_prime(mca_key_head_t *keyhead, char **p, int *plen)
{
	int		keyheadsz = GETBUF32(&(keyhead->valuelen));
	dsa_head_t	*dsahead;
	dsahead = (dsa_head_t *)((char *)keyhead +
	    sizeof (mca_key_head_t) + GETBUF32(&(keyhead->descrlen)));

	if (keyheadsz < sizeof (dsa_head_t)) {
		*p = NULL;
		*plen = 0;
	} else {
		*p = (char *)dsahead + sizeof (dsa_head_t) +
		    PAD32(20);	/* 20: SubPrime length */
		*plen = GETBUF32(&dsahead->plen);
	}
}

/*ARGSUSED*/
int
mca_dsainit(crypto_ctx_t *ctx, crypto_mechanism_t *mech, crypto_key_t *key,
    int kmflag, uint32_t cmd, mca_privatectx_t **privctx)
{
	return (mca_allocctx(MCA_CTX2MCA(ctx), ctx->cc_session,
	    key, cmd, 0, privctx));
}

int
mca_dsa(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_data_t *sig, crypto_req_handle_t *cfreq, uint32_t cmd)
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
		mca_error(mca, "unable to allocate request for DSA");
		return (CRYPTO_BUSY);
	}

	if ((rv = dsa_set_request(reqp, privctx)) != CRYPTO_SUCCESS) {
		mca_freereq(reqp);
		return (rv);
	}

	rv = dsa_start(mca, reqp, data, sig, cfreq, cmd);
	if (rv != CRYPTO_QUEUED) {
		mca_freereq(reqp);
	}

	return (rv);
}

int
mca_dsaatomic(mca_t *mca, crypto_session_id_t session_id, crypto_key_t *key,
    crypto_data_t *data, crypto_data_t *sig, crypto_req_handle_t *cfreq,
    uint32_t cmd)
{
	mca_privatectx_t	*privctx;
	int			rv;
	mca_request_t		*reqp;

	/* temporarily allocate the context */
	rv = mca_allocctx(mca, session_id, key, cmd, sizeof (int), &privctx);
	if (rv != CRYPTO_SUCCESS) {
		return (rv);
	}

	if ((reqp = mca_getreq(&mca->mca_ring_ca)) == NULL) {
		mca_error(mca, "unable to allocate request for DSA");
		mca_freectx(privctx);
		return (CRYPTO_BUSY);
	}

	if ((rv = dsa_set_request(reqp, privctx))
	    != CRYPTO_SUCCESS) {
		mca_freectx(privctx);
		mca_freereq(reqp);
		return (rv);
	}

	rv = dsa_start(mca, reqp, data, sig, cfreq, cmd);
	if (rv != CRYPTO_QUEUED) {
		mca_freereq(reqp);
	}

	mca_freectx(privctx);

	return (rv);
}

static int
dsa_start(mca_t *mca, mca_request_t *reqp, crypto_data_t *data,
    crypto_data_t *sig, crypto_req_handle_t *cfreq, uint32_t cmd)
{
	int	rv;
	int	plen;
	char	*p;

	DBG(mca, DENTRY, "dsa_start -->");

	if (mca_get_datalen(data) != SHA1LEN) {
		DBG(mca, DCHATTY, "input length != 20");
		return (CRYPTO_DATA_LEN_RANGE);
	}

	dsa_get_prime((mca_key_head_t *)reqp->mr_key_kaddr, &p, &plen);
	if (p == NULL) {
		/* unable to retrieve prime attr from the key_head */
		return (CRYPTO_KEY_HANDLE_INVALID);
	} else if ((plen < BITS2BYTES(DSA_MIN_KEY_LEN)) ||
	    (plen > BITS2BYTES(DSA_MAX_KEY_LEN))) {
		/*
		 * maximum 1Kbit key on 5821, larger key may be used in userland
		 */
		return (CRYPTO_KEY_SIZE_RANGE);
	}

	if (mca_isfips(mca) && (cmd == CMD_DSASIGN) &&
	    (reqp->mr_key_id[0] == 0) && (reqp->mr_key_id[1] == 0)) {
		mca_ktkencryptkey(reqp);
	}

	if (cmd == CMD_DSASIGN) {
		if (mca_get_datalen(sig) < DSASIGLEN) {
			DBG(mca, DCHATTY, "signature buffer too small");
			mca_set_datalen(sig, DSASIGLEN);
			return (CRYPTO_BUFFER_TOO_SMALL);
		}

		MCA_SET_REQ_DATA(reqp, data, sig);
		reqp->mr_cmd = CMD_DSASIGN;
		reqp->mr_job_stat = MS_DSASIGN;
		reqp->mr_callback = dsa_signdone;
		reqp->mr_in_len = SHA1LEN;
		/* r & s */
		reqp->mr_out_paddr = reqp->mr_obuf_paddr;
		reqp->mr_out_next_paddr = 0;
		reqp->mr_out_len = DSASIGLEN;
		rv = mca_gather(reqp->mr_in, reqp->mr_ibuf_kaddr,
		    reqp->mr_in_len);
	} else {
		reqp->mr_cmd = CMD_DSAVERIFY;
		reqp->mr_job_stat = MS_DSAVERIFY;
		reqp->mr_callback = dsa_verifydone;
		reqp->mr_out_len = 0;

		if (mca_get_datalen(sig) != DSASIGLEN) {
			DBG(NULL, DCHATTY, "Invalid Signature Length [%d]",
			    mca_get_datalen(sig));
			return (CRYPTO_SIGNATURE_LEN_RANGE);
		}

		/* append the 'data' at the end of 'sig' */
		reqp->mr_tmpin = *sig;
		reqp->mr_in_len = SHA1LEN + DSASIGLEN;
		rv = mca_gather(&reqp->mr_tmpin, reqp->mr_ibuf_kaddr,
		    DSASIGLEN);
		if (rv == CRYPTO_SUCCESS) {
			reqp->mr_tmpin = *data;
			rv = mca_gather(&reqp->mr_tmpin,
			    reqp->mr_ibuf_kaddr + DSASIGLEN, SHA1LEN);
		}
	}
	/* check the return value of mca_gather */
	if (rv != CRYPTO_SUCCESS) {
		return (rv);
	}
	ddi_dma_sync(reqp->mr_ibuf_dmah, 0, reqp->mr_in_len,
	    DDI_DMA_SYNC_FORDEV);

	reqp->mr_byte_stat = -1;
	reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
	reqp->mr_in_next_paddr = 0;
	reqp->mr_cf_req = cfreq;
	reqp->mr_flags |= (MRF_GATHER | MRF_SCATTER);

	/* if the key is token key, hold the keystore readlock */
	if (reqp->mr_context->mc_session != NULL) {
		mca_user_rdlock(reqp->mr_context->mc_session->ms_user);
		reqp->mr_flags |= MRF_KSREAD;
	}
	/* if this is a token or senstitive session key - set the ks handle */
	if (reqp->mr_context->mc_keystore) {
		reqp->mr_dbm_handle =
		    mca_ks_get_handle(reqp->mr_context->mc_keystore, mca);
	}


	/* schedule the work by doing a submit */
	if ((rv = mca_start(reqp)) != CRYPTO_QUEUED) {
		if (reqp->mr_flags & MRF_KSREAD) {
			mca_user_unlock(
			    reqp->mr_context->mc_session->ms_user);
		}
	}

	DBG(mca, DENTRY, "dsa_start <-- [0x%x]", rv);

	return (rv);
}

static void
dsa_signdone(mca_request_t *reqp)
{
	if (reqp->mr_flags & MRF_KSREAD) {
		mca_user_unlock(reqp->mr_context->mc_session->ms_user);
	}
	if (reqp->mr_errno == CRYPTO_SUCCESS) {
		ddi_dma_sync(reqp->mr_obuf_dmah, 0, reqp->mr_resultlen,
		    DDI_DMA_SYNC_FORKERNEL);
		reqp->mr_errno = mca_scatter(reqp->mr_obuf_kaddr,
		    reqp->mr_out_len, reqp->mr_out);

	}
	crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
	mca_freereq(reqp);
}

static void
dsa_verifydone(mca_request_t *reqp)
{
	if (reqp->mr_flags & MRF_KSREAD) {
		mca_user_unlock(reqp->mr_context->mc_session->ms_user);
	}
	crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
	mca_freereq(reqp);
}
