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

#pragma ident	"@(#)mca_ecdsa.c	1.5	08/08/13 SMI"

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


/* Per PKCS#11 restriction, reject the job larger than 1024 bits */
#define	ECDSA_MAX_INLEN		BITS2BYTES(1024)
#define	ECDSA_MAX_SIGLEN	(2 * ECDSA_MAX_INLEN)

/*
 * ECDSA implementation.
 */
static int ecdsa_start(mca_t *, mca_request_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t *, uint32_t);
static void ecdsa_signdone(mca_request_t *);
static void ecdsa_verifydone(mca_request_t *);

/* used for single-part operation */
static int
ecdsa_set_request(mca_request_t *reqp, mca_privatectx_t *ctx)
{
	int	rv;

	bcopy(ctx->mc_keyhead, reqp->mr_key_kaddr, ctx->mc_keyheadsz);
	reqp->mr_key_len = ctx->mc_keyheadsz;

	reqp->mr_key_id[0] = GETBUF32(&(ctx->mc_keyhead->cardid));
	reqp->mr_key_id[1] = GETBUF32(&(ctx->mc_keyhead->objectid));
	reqp->mr_key_flags[0] = ctx->mc_keyflags;

	if (ctx->mc_keyflags & KEYFLAG_PERSIST) {
		if (ctx->mc_session == NULL) {
			return (CRYPTO_USER_NOT_LOGGED_IN);
		}
		rv = mca_get_session_cred(ctx->mc_session, reqp->mr_cred);
		if (rv != CRYPTO_SUCCESS) {
			return (rv);
		}
	}

	reqp->mr_context = ctx;

	return (CRYPTO_SUCCESS);
}


/*ARGSUSED*/
int
mca_ecdsainit(crypto_ctx_t *ctx, crypto_mechanism_t *mech, crypto_key_t *key,
    int kmflag, uint32_t cmd, mca_privatectx_t **privctx)
{
	return (mca_allocctx(MCA_CTX2MCA(ctx), ctx->cc_session,
	    key, cmd, 0, privctx));
}

int
mca_ecdsa(crypto_ctx_t *ctx, crypto_data_t *data,
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
		mca_error(mca, "unable to allocate request for ECDSA");
		return (CRYPTO_BUSY);
	}

	if ((rv = ecdsa_set_request(reqp, privctx)) != CRYPTO_SUCCESS) {
		mca_freereq(reqp);
		return (rv);
	}

	rv = ecdsa_start(mca, reqp, data, sig, cfreq, cmd);
	if (rv != CRYPTO_QUEUED) {
		mca_freereq(reqp);
	}

	return (rv);
}

int
mca_ecdsaatomic(mca_t *mca, crypto_session_id_t session_id, crypto_key_t *key,
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
		mca_error(mca, "unable to allocate request for ECDSA");
		mca_freectx(privctx);
		return (CRYPTO_BUSY);
	}

	if ((rv = ecdsa_set_request(reqp, privctx)) != CRYPTO_SUCCESS) {
		mca_freectx(privctx);
		mca_freereq(reqp);
		return (rv);
	}

	rv = ecdsa_start(mca, reqp, data, sig, cfreq, cmd);
	if (rv != CRYPTO_QUEUED) {
		mca_freereq(reqp);
	}

	mca_freectx(privctx);

	return (rv);
}

static int
ecdsa_start(mca_t *mca, mca_request_t *reqp, crypto_data_t *data,
    crypto_data_t *sig, crypto_req_handle_t *cfreq, uint32_t cmd)
{
	int	rv;

	DBG(mca, DENTRY, "ecdsa_start -->");


	if (mca_isfips(mca) && (cmd == CMD_ECDSASIGN) &&
	    (reqp->mr_key_id[0] == 0) && (reqp->mr_key_id[1] == 0)) {
		mca_ktkencryptkey(reqp);
	}

	if (cmd == CMD_ECDSASIGN) {
		/*
		 * Per PKCS#11 restriction, reject the job larger than
		 * 1024 bits
		 */
		if (mca_get_datalen(data) > ECDSA_MAX_INLEN) {
			DBG(mca, DCHATTY, "input length is greater than "
			    "1024 bits");
			return (CRYPTO_DATA_LEN_RANGE);
		}

		reqp->mr_cmd = CMD_ECDSASIGN;
		reqp->mr_job_stat = MS_ECDSASIGN;
		reqp->mr_callback = ecdsa_signdone;
		reqp->mr_in_len = mca_get_datalen(data);
		/* r & s */
		reqp->mr_out_paddr = reqp->mr_obuf_paddr;
		reqp->mr_out_next_paddr = 0;
		reqp->mr_out_len = (mca_get_datalen(sig) > ECDSA_MAX_SIGLEN) ?
		    ECDSA_MAX_SIGLEN : mca_get_datalen(sig);
		MCA_SET_REQ_DATA(reqp, data, sig);
		rv = mca_gather(reqp->mr_in, reqp->mr_ibuf_kaddr,
		    reqp->mr_in_len);
	} else {
		char	*cursor;
		int	len;

		reqp->mr_cmd = CMD_ECDSAVERIFY;
		reqp->mr_job_stat = MS_ECDSAVERIFY;
		reqp->mr_callback = ecdsa_verifydone;
		reqp->mr_out_len = 0;

		/*
		 * Per PKCS#11 restriction, reject the job larger than
		 * 1024 bits
		 */
		if (mca_get_datalen(data) > ECDSA_MAX_INLEN) {
			DBG(mca, DCHATTY, "input length is greater than "
			    "1024 bits");
			return (CRYPTO_DATA_LEN_RANGE);
		}

		if (mca_get_datalen(sig) > ECDSA_MAX_SIGLEN) {
			DBG(NULL, DCHATTY, "Invalid Signature Length [%d]",
			    mca_get_datalen(sig));
			return (CRYPTO_SIGNATURE_LEN_RANGE);
		}

		/* append the 'data' at the end of 'sig' */
		reqp->mr_in_len = sizeof (uint32_t) + mca_get_datalen(sig) +
		    mca_get_datalen(data);

		PUTBUF32((uint32_t *)reqp->mr_ibuf_kaddr,
		    mca_get_datalen(sig));
		cursor = reqp->mr_ibuf_kaddr + sizeof (uint32_t);

		len = mca_get_datalen(sig);
		reqp->mr_tmpin = *sig;
		rv = mca_gather(&reqp->mr_tmpin, cursor, len);
		mca_set_datalen(sig, len);
		cursor += len;
		if (rv == CRYPTO_SUCCESS) {
			len = mca_get_datalen(data);
			reqp->mr_tmpin = *data;
			rv = mca_gather(&reqp->mr_tmpin, cursor, len);
			mca_set_datalen(data, len);
			cursor += len;
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
	reqp->mr_timeout = drv_usectohz(10 * SECOND);

	/* if the key is token key, hold the keystore readlock */
	if (reqp->mr_context->mc_session != NULL) {
		mca_user_rdlock(reqp->mr_context->mc_session->ms_user);
		reqp->mr_flags |= MRF_KSREAD;
	}

	/* set the ks handle for token and sensitive session keys */
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

	DBG(mca, DENTRY, "ecdsa_start <-- [0x%x]", rv);

	return (rv);
}

static void
ecdsa_signdone(mca_request_t *reqp)
{
	if (reqp->mr_flags & MRF_KSREAD) {
		mca_user_unlock(reqp->mr_context->mc_session->ms_user);
	}
	if (reqp->mr_errno == CRYPTO_SUCCESS) {
		ddi_dma_sync(reqp->mr_obuf_dmah, 0, reqp->mr_resultlen,
		    DDI_DMA_SYNC_FORKERNEL);
		reqp->mr_errno = mca_scatter(reqp->mr_obuf_kaddr,
		    reqp->mr_resultlen, reqp->mr_out);

	} else if (reqp->mr_errno == CRYPTO_BUFFER_TOO_SMALL) {
		mca_set_datalen(reqp->mr_out, reqp->mr_resultlen);
	}
	crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
	mca_freereq(reqp);
}

static void
ecdsa_verifydone(mca_request_t *reqp)
{
	if (reqp->mr_flags & MRF_KSREAD) {
		mca_user_unlock(reqp->mr_context->mc_session->ms_user);
	}
	crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
	mca_freereq(reqp);
}
