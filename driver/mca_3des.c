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

#pragma ident	"@(#)mca_3des.c	1.31	06/12/01 SMI"

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
#include <sys/mca.h>
#endif

static int des3_start(mca_request_t *);
static void des3_done(mca_request_t *);
static void des3_atomicdone(mca_request_t *);

/*
 * 3DES implementation.
 */

static int
des3_ctxinit(crypto_mechanism_t *mech, mca_privatectx_t *ctx)
{
	mca_3des_ctx_t	*des3ctx = (mca_3des_ctx_t *)(ctx + 1);

	ctx->mc_shortparamlen = DESBLOCK;
	if (mca_get_mech_param(mech, (char *)ctx->mc_shortparam,
	    &ctx->mc_shortparamlen) != CRYPTO_SUCCESS) {
		DBG(NULL, DCHATTY, "des3_ctxinit:"
		    "mca_get_mech_param failed");
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	/*
	 * If IV was supplied through 'mech', make sure that the length is
	 * DESBLOCK bytes. Note that for EF framework, the parameter might
	 * be passed through data field, in which case, mc_shorparamlen
	 * should be 0 byte.
	 */
	if ((ctx->mc_shortparamlen != DESBLOCK) &&
	    (ctx->mc_shortparamlen != 0)) {
		DBG(NULL, DCHATTY, "des3_ctxinit: paramlen = %d",
		    ctx->mc_shortparamlen);
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	des3ctx->residlen = 0;
	des3ctx->lastblocklen = 0;

	return (CRYPTO_SUCCESS);
}

static int
des3_set_reqkey_ctx(mca_request_t *reqp, mca_privatectx_t *ctx)
{
	mca_key_head_t	*keyhead = ctx->mc_keyhead;
	int		keyheadsz = ctx->mc_keyheadsz;
	uint32_t	*env = (uint32_t *)KEYHEAD_ENVELOPE(keyhead);
	uint32_t	*value = (uint32_t *)KEYHEAD_VALUE(keyhead);
	int		keytype;

	ASSERT((keyhead != NULL) && (keyheadsz >= sizeof (mca_key_head_t)));

	bcopy(keyhead, reqp->mr_key_kaddr, keyheadsz);
	reqp->mr_key_len = keyheadsz;

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
			DBG(NULL, DWARN, "des3_set_reqkey_ctx: keytype[0x%x]",
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
			DBG(NULL, DWARN, "des3_set_reqkey_ctx: keytype[0x%x]",
			    keytype);
			return (CRYPTO_KEY_TYPE_INCONSISTENT);
		}
	}
	reqp->mr_key_flags[0] = ctx->mc_keyflags;

	return (CRYPTO_SUCCESS);
}

/*
 * This function checks to make sure that input and output length are valid
 * for single-part/atomic operation.
 * This returns CRYPTO erro code.
 * When the return code is CRYPTO_BUFFER_TOO_SMALL, cd_length of 'out'
 * is set to the expected outlen.
 */
static int
check_data_length_single(uint32_t cmd, crypto_data_t *in, crypto_data_t *out)
{
	uint32_t		inlen, outlen;

	inlen = mca_get_datalen(in);
	outlen = mca_get_datalen(out);

	if ((cmd & CMD_HI_PAD) && ((cmd & CMD_MASK) == CMD_3DESENC)) {
		uint32_t	expoutlen;
		/*
		 * Note: this is different from ROUNDUP(inlen, DESBLOCK) when
		 * inlen is multiple of DESBLOCK
		 */
		expoutlen = ROUNDDOWN(inlen + DESBLOCK, DESBLOCK);
		if (expoutlen > outlen) {
			mca_set_datalen(out, expoutlen);
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	} else if ((cmd & CMD_HI_PAD) && ((cmd & CMD_MASK) == CMD_3DESDEC)) {
		/* inlen for DES CBC PAD decrypt must be multiple of blocksz */
		if ((inlen == 0) || (inlen % DESBLOCK)) {
			return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);
		}
		/*
		 * outlen for DES CBC PAD decrypt must be between (len-1)
		 * and (len-DESBLOCK). Make sure there is minimal space in
		 * out. If not, ask for maximum space.
		 */
		if (outlen < (inlen - DESBLOCK)) {
			mca_set_datalen(out, inlen - 1);
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	} else {
		/*
		 * XXX: None-PAD 3DES operation. Note: it assumes that
		 * 3DESENC and 3DESDEC are the only cmd supported for PAD mode
		 */
		/* inlen for DES CBC en/decrypt must be multiple of blocksz */
		if (inlen % DESBLOCK) {
			return (((cmd & CMD_MASK) == CMD_3DESENC) ?
			    CRYPTO_DATA_LEN_RANGE :
			    CRYPTO_ENCRYPTED_DATA_LEN_RANGE);
		}
		/* outlen must be at least inlen */
		if (outlen < inlen) {
			mca_set_datalen(out, inlen);
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}

	return (CRYPTO_SUCCESS);
}

/*
 * This function checks to make sure that output length are valid
 * for multi-part operation.
 * This returns CRYPTO erro code.
 * When the return code is CRYPTO_BUFFER_TOO_SMALL, cd_length field of 'out'
 * is set to the expected outlen.
 * Note: for multipart operation, input length can be anylength.
 */
static int
check_data_length_multi(uint32_t cmd, crypto_ctx_t *ctx,
    crypto_data_t *in, crypto_data_t *out)
{
	uint32_t		maxoutlen, outsz, expoutlen;
	mca_privatectx_t	*privctx;
	mca_3des_ctx_t		*des3ctx;

	privctx = ctx->cc_provider_private;
	if (privctx == NULL) {
		return (CRYPTO_OPERATION_NOT_INITIALIZED);
	}
	des3ctx = (mca_3des_ctx_t *)(privctx + 1);

	maxoutlen = mca_get_datalen(in) + des3ctx->residlen +
	    des3ctx->lastblocklen;
	outsz = mca_get_datalen(out);

	if ((cmd & CMD_HI_PAD) && ((cmd & CMD_MASK) == CMD_3DESDEC) &&
	    ((maxoutlen % DESBLOCK) == 0)) {
		/*
		 * Save the last BLOCK size in case this is the last
		 * update operation so that the padding can be removed at
		 * decrypt_final
		 */
		expoutlen = maxoutlen - DESBLOCK;
	} else {
		expoutlen = ROUNDDOWN(maxoutlen, DESBLOCK);
	}

	if (outsz < expoutlen) {
		mca_set_datalen(out, expoutlen);
		return (CRYPTO_BUFFER_TOO_SMALL);
	}
	return (CRYPTO_SUCCESS);
}

/*ARGSUSED*/
int
mca_3desinit(crypto_ctx_t *ctx, crypto_mechanism_t *mech, crypto_key_t *key,
    int kmflag, uint32_t cmd, mca_privatectx_t **privctx)
{
	int		rv;

	DBG(NULL, DENTRY, "mca_3des_init -->");

	rv = mca_allocctx(MCA_CTX2MCA(ctx), ctx->cc_session, key,
	    cmd, sizeof (mca_3des_ctx_t), privctx);
	if (rv != CRYPTO_SUCCESS) {
		return (rv);
	}

	/* set the 3DES specific continuation state */
	if ((rv = des3_ctxinit(mech, *privctx)) != CRYPTO_SUCCESS) {
		mca_freectx(*privctx);
		*privctx = NULL;
		return (rv);
	}

	DBG(NULL, DENTRY, "mca_3desinit <--");
	return (CRYPTO_SUCCESS);
}


int
mca_3des(crypto_ctx_t *ctx, crypto_data_t *in, crypto_data_t *out,
    crypto_req_handle_t *cfreq, uint32_t cmd)
{
	mca_privatectx_t	*privctx;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_request_t		*reqp;
	int			rv;
	uint32_t		len;

	DBG(NULL, DENTRY, "mca_3des -->");

	privctx = ctx->cc_provider_private;
	if (privctx == NULL) {
		DBG(NULL, DENTRY, "mca_3des: privctx is NULL");
		return (CRYPTO_OPERATION_NOT_INITIALIZED);
	}

	/* check the validity of the input and output */
	if ((rv = check_data_length_single(cmd, in, out)) != CRYPTO_SUCCESS) {
		return (rv);
	}

	/* special handling for null-sized input buffers */
	len = mca_get_datalen(in);
	if ((len == 0) && !(cmd & CMD_HI_PAD)) {
		mca_set_datalen(out, 0);
		return (CRYPTO_SUCCESS);
	}

	/* prepare the request */
	if ((reqp = mca_getreq(&mca->mca_ring_cb)) == NULL) {
		mca_error(mca, "unable to allocate request for DES");
		return (CRYPTO_BUSY);
	}

	/*
	 * For kEF, the IV may come from the data struct. If so, overwrite the
	 * existing IV
	 */
	MCA_GET_MISCDATA(in, privctx, DESBLOCK);

	MCA_SET_REQ_DATA(reqp, in, out);

	/* add padding if the op is CBC_PAD encryption */
	if ((cmd & CMD_HI_PAD) && ((cmd & CMD_MASK) == CMD_3DESENC)) {
		cmd |= CMD_HI_ADDPAD;
	}
	if ((cmd & CMD_HI_PAD) && ((cmd & CMD_MASK) == CMD_3DESDEC)) {
		cmd |= CMD_HI_REMOVEPAD;
	}

	reqp->mr_cmd = cmd;
	reqp->mr_mca = mca;
	reqp->mr_cf_req = cfreq;
	reqp->mr_context = privctx;
	if (privctx->mc_keystore) {
		reqp->mr_dbm_handle =
		    mca_ks_get_handle(privctx->mc_keystore, mca);
	}
	reqp->mr_callback = des3_done;

	rv = des3_start(reqp);
	if ((rv != CRYPTO_SUCCESS) && (rv != CRYPTO_QUEUED)) {
		mca_freereq(reqp);
	}
	DBG(NULL, DENTRY, "mca_3des <-- [0x%x]", rv);
	return (rv);
}

int
mca_3desupdate(crypto_ctx_t *ctx, crypto_data_t *in, crypto_data_t *out,
    crypto_req_handle_t *cfreq, uint32_t cmd)
{
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_request_t		*reqp;
	int			rv;
	mca_privatectx_t	*privctx;

	DBG(NULL, DENTRY, "mca_3desupdate -->");

	privctx = ctx->cc_provider_private;
	if (privctx == NULL) {
		return (CRYPTO_OPERATION_NOT_INITIALIZED);
	}

	/* check the validity of the input and output */
	if ((rv = check_data_length_multi(cmd, ctx, in, out))
	    != CRYPTO_SUCCESS) {
		return (rv);
	}

	/* prepare the request */
	if ((reqp = mca_getreq(&mca->mca_ring_cb)) == NULL) {
		mca_error(mca, "unable to allocate request for 3DES");
		return (CRYPTO_BUSY);
	}

	/*
	 * For kEF, the IV may come from the data struct. If so, overwrite the
	 * existing IV
	 */
	MCA_GET_MISCDATA(in, privctx, DESBLOCK);

	MCA_SET_REQ_DATA(reqp, in, out);

	reqp->mr_cmd = cmd;
	reqp->mr_mca = mca;
	reqp->mr_cf_req = cfreq;
	reqp->mr_context = privctx;
	if (privctx->mc_keystore) {
		reqp->mr_dbm_handle =
		    mca_ks_get_handle(privctx->mc_keystore, mca);
	}
	reqp->mr_callback = des3_done;

	rv = des3_start(reqp);
	if ((rv != CRYPTO_SUCCESS) && (rv != CRYPTO_QUEUED)) {
		mca_freereq(reqp);
	}
	DBG(NULL, DENTRY, "mca_3desupdate <-- [0x%x]", rv);
	return (rv);
}

int
mca_3desfinal(crypto_ctx_t *ctx, crypto_data_t *out,
    crypto_req_handle_t *cfreq, uint32_t cmd)
{
	mca_privatectx_t	*privctx;
	mca_3des_ctx_t		*des3ctx;
	int			rv = CRYPTO_SUCCESS;

	DBG(NULL, DENTRY, "mca_3desfinal -->");

	privctx = ctx->cc_provider_private;
	if (privctx == NULL) {
		return (CRYPTO_OPERATION_NOT_INITIALIZED);
	}

	des3ctx = (mca_3des_ctx_t *)(privctx + 1);
	if ((cmd & CMD_HI_PAD) && ((cmd & CMD_MASK) == CMD_3DESDEC)) {
		if (des3ctx->lastblocklen == 0) {
			/*
			 * If there is no saved output from the previous
			 * decrypt update, the input length is incorrect.
			 */
			return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);
		}
		/* cbc pad final */
		mca_set_datalen(out, 0);
		rv = mca_unpad_scatter(des3ctx->lastblock,
		    des3ctx->lastblocklen, out, DESBLOCK);
		des3ctx->lastblocklen = 0;
	} else if ((cmd & CMD_HI_PAD) && ((cmd & CMD_MASK) == CMD_3DESENC)) {
		/* process resid + pad */
		rv = mca_3des(ctx, NULL, out, cfreq, cmd);
	} else if (des3ctx->residlen != 0) {
		/*
		 * Illegal none-PAD 3DES operation. Total input length
		 * was not multiple of the blocksz.
		 */
		DBG(NULL, DCHATTY, "invalid nonzero residual (%d)",
		    des3ctx->residlen);
		if ((cmd & CMD_MASK) == CMD_3DESDEC) {
			return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);
		} else {
			return (CRYPTO_DATA_LEN_RANGE);
		}
	} else {
		/*
		 * Successful none-PAD 3DES operation.
		 * XXX: Note: it assumes that 3DESENC and 3DESDEC are
		 * the only cmd supported for PAD mode
		 */
		mca_set_datalen(out, 0);
	}

	DBG(NULL, DENTRY, "mca_3desfinal <-- [0x%x]", rv);

	return (rv);
}

int
mca_3desatomic(mca_t *mca, crypto_session_id_t session_id,
    crypto_mechanism_t *mech, crypto_key_t *key, crypto_data_t *in,
    crypto_data_t *out, crypto_req_handle_t *cfreq, uint32_t cmd)
{
	mca_request_t		*reqp;
	int			len;
	int			rv;
	mca_privatectx_t	*privctx;

	DBG(mca, DENTRY, "mca_3desatomic -->");

	/* check the validity of the input and output */
	if ((rv = check_data_length_single(cmd, in, out)) != CRYPTO_SUCCESS) {
		return (rv);
	}

	/* special handling for null-sized input buffers */
	len = mca_get_datalen(in);
	if ((len == 0) && !(cmd & CMD_HI_PAD)) {
		mca_set_datalen(out, 0);
		return (CRYPTO_SUCCESS);
	}

	/*
	 * Eventhough, an atomic operation does not require a continuation
	 * state, create an mca_privatectx for use by des3_start
	 */
	if ((rv = mca_allocctx(mca, session_id, key, cmd,
	    sizeof (mca_3des_ctx_t), &privctx)) != CRYPTO_SUCCESS) {
		return (rv);
	}
	if ((rv = des3_ctxinit(mech, privctx)) != CRYPTO_SUCCESS) {
		mca_freectx(privctx);
		return (rv);
	}

	if ((reqp = mca_getreq(&mca->mca_ring_cb)) == NULL) {
		mca_error(mca, "unable to allocate request for 3DES");
		mca_freectx(privctx);
		return (CRYPTO_BUSY);
	}

	/*
	 * For kEF, the IV may come from the data struct. If so, overwrite the
	 * existing IV
	 */
	MCA_GET_MISCDATA(in, privctx, DESBLOCK);

	MCA_SET_REQ_DATA(reqp, in, out);

	/* add padding if the op is CBC_PAD encryption */
	if ((cmd & CMD_HI_PAD) && ((cmd & CMD_MASK) == CMD_3DESENC)) {
		cmd |= CMD_HI_ADDPAD;
	}
	if ((cmd & CMD_HI_PAD) && ((cmd & CMD_MASK) == CMD_3DESDEC)) {
		cmd |= CMD_HI_REMOVEPAD;
	}

	reqp->mr_cmd = cmd;
	reqp->mr_mca = mca;
	reqp->mr_cf_req = cfreq;
	reqp->mr_context = privctx;
	if (privctx->mc_keystore) {
		reqp->mr_dbm_handle =
		    mca_ks_get_handle(privctx->mc_keystore, mca);
	}
	reqp->mr_callback = des3_atomicdone;

	rv = des3_start(reqp);
	if ((rv != CRYPTO_SUCCESS) && (rv != CRYPTO_QUEUED)) {
		mca_freereq(reqp);
	}

	DBG(NULL, DENTRY, "mca_3desatomic <-- [0x%x]", rv);

	return (rv);
}

static int
des3_start(mca_request_t *reqp)
{
	mca_privatectx_t	*privctx = reqp->mr_context;
	mca_3des_ctx_t		*des3ctx;
	crypto_data_t		*in = reqp->mr_in;
	int			len;
	uint32_t		inlen;
	uint32_t		padlen = 0;	/* actual padding length */
	int			rv;
	char			*in_addr = NULL;

	DBG(NULL, DENTRY, "des3_start -->");

	des3ctx = (mca_3des_ctx_t *)(privctx + 1);

	inlen = mca_get_datalen(in) + des3ctx->residlen;
	if (reqp->mr_cmd & CMD_HI_ADDPAD) {
		padlen = (DESBLOCK - (inlen % DESBLOCK));
	}

	if (inlen + padlen > MAXPACKET) {
		/*
		 * Padding does not fit in this request.
		 * Leave 'CMD_HI_ADDPAD' so that the callback function
		 * can process the remainder later.
		 */
		len = ROUNDDOWN(MAXPACKET, DESBLOCK);
		inlen = len;
		padlen = 0;
	} else {
		/*
		 * Padding fits in this request.
		 * Turn off CMD_HI_ADDPAD to indicate that the padding
		 * is processed by this request
		 */
		len = ROUNDDOWN(inlen + padlen, DESBLOCK);
		reqp->mr_cmd &= ~CMD_HI_ADDPAD;
	}
	reqp->mr_byte_count = len;

	if (len == 0) {
		/*
		 * No blocks being encrypted, so we just accumulate the
		 * input for the next pass and return.
		 */
		mca_getbufbytes(in, 0, mca_get_datalen(in),
		    des3ctx->resid + des3ctx->residlen);
		des3ctx->residlen = inlen;

		mca_set_datalen(reqp->mr_out, 0);

		mca_freereq(reqp);
		return (CRYPTO_SUCCESS);
	}

	/*
	 * Copy the current initial vector to mr_short_key.
	 * And also, for decrypt, collect the IV for the next pass.  For
	 * decrypt, the IV must be collected BEFORE decryption, or else
	 * we will lose it.  (For encrypt, we grab the IV AFTER encryption,
	 * in des3_done.
	 */
	reqp->mr_short_key[6] = GETBE32((uint32_t *)privctx->mc_shortparam);
	reqp->mr_short_key[7] =
	    GETBE32((uint32_t *)((char *)privctx->mc_shortparam + 4));

	rv = des3_set_reqkey_ctx(reqp, privctx);
	if (rv != CRYPTO_SUCCESS) {
		DBG(NULL, DWARN, "des3_set_reqkey_ctx failed with 0x%x", rv);
		return (rv);
	}

	/*
	 * Start by assuming direct DMA is okay, then check for conditions
	 * which cause it to be inappropriate.
	 */
	reqp->mr_flags &= ~(MRF_SCATTER | MRF_GATHER);
	if ((len < mca_mindma) || mca_sg(reqp->mr_in) || mca_sg(reqp->mr_out) ||
	    (des3ctx->residlen > 0) || (reqp->mr_cmd & CMD_HI_PAD)) {
		reqp->mr_flags |= MRF_SCATTER | MRF_GATHER;
	} else {
		/* try to bind the kernel address for DMA */
		in_addr = mca_get_dataaddr(reqp->mr_in);
		if (mca_bindchains(reqp, len, len) != DDI_SUCCESS) {
			return (CRYPTO_FAILED);
		}
	}

	/* and setup for scattering the result back out */
	if (reqp->mr_flags & MRF_SCATTER) {
		/* terminate the pre-mapped chain */
		MCA_TERMINATE_CHAINS(&reqp->mr_obuf_chain, len);

		reqp->mr_out_paddr = reqp->mr_obuf_paddr;
		reqp->mr_out_first_len = min((int)(reqp->mr_obuf_sz), len);
		reqp->mr_out_len = len;
		if (reqp->mr_out_first_len == len) {
			reqp->mr_out_next_paddr = 0;
		} else {
			reqp->mr_out_next_paddr = reqp->mr_obuf_next_paddr;
		}
	}
	/* gather the data into the device */
	if (reqp->mr_flags & MRF_GATHER) {
		/* terminate the pre-mapped chain */
		MCA_TERMINATE_CHAINS(&reqp->mr_ibuf_chain, len);

		/* now gather up the data from the buf chain */
		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_first_len = min((int)(reqp->mr_ibuf_sz), len);
		reqp->mr_in_len = len;
		if (reqp->mr_in_first_len == len) {
			reqp->mr_in_next_paddr = 0;
		} else {
			reqp->mr_in_next_paddr = reqp->mr_ibuf_next_paddr;
		}

		in_addr = reqp->mr_ibuf_kaddr;

		/* first copy the resid from the previous update */
		if (des3ctx->residlen > 0) {
			bcopy(des3ctx->resid, reqp->mr_ibuf_kaddr,
			    des3ctx->residlen);
			len -= des3ctx->residlen;
		}

		/* copy the rest of the data */
		if (padlen > 0) {
			rv = mca_gather_pad(reqp->mr_in,
			    reqp->mr_ibuf_kaddr + des3ctx->residlen,
			    mca_get_datalen(in), (char)padlen);
		} else {
			rv = mca_gather(reqp->mr_in,
			    reqp->mr_ibuf_kaddr + des3ctx->residlen, len);
		}
		if (rv != CRYPTO_SUCCESS) {
			goto done;
		}
		ddi_dma_sync(reqp->mr_ibuf_dmah, 0, reqp->mr_in_len,
		    DDI_DMA_SYNC_FORDEV);

		/* the data in des3ctx->resid are copied into the buf */
		des3ctx->residlen = 0;
	}

	if ((reqp->mr_cmd & CMD_MASK) == CMD_3DESDEC) {
		char *nextiv;

		/* get DESBLOCK bytes from the end of the data buf */
		nextiv = in_addr + reqp->mr_in_len - DESBLOCK;
		bcopy(nextiv, privctx->mc_shortparam, DESBLOCK);
	}

	reqp->mr_job_stat = MS_3DESJOBS;
	reqp->mr_byte_stat = MS_3DESBYTES;

	/*
	 * Setup the key.  In FIPS mode we have to encrypt the key
	 * under the KTK, but only if we are passing an actual key's
	 * value in the clear.  (I.e. we do not do this if we have a
	 * token or sensitive key, in which case the key id is
	 * non-zero.)
	 */
	if (mca_isfips(reqp->mr_mca) &&
	    (reqp->mr_key_id[0] == 0) && (reqp->mr_key_id[1] == 0)) {
		mca_ktkencryptshortkey(reqp);
	}

	if (privctx->mc_keyflags & KEYFLAG_PERSIST) {
		if (privctx->mc_session == NULL) {
			rv = CRYPTO_USER_NOT_LOGGED_IN;
			goto done;
		}
		rv = mca_get_session_cred(privctx->mc_session,
		    reqp->mr_cred);
		if (rv != CRYPTO_SUCCESS) {
			goto done;
		}
	}

	if (privctx->mc_session) {
		if (!(reqp->mr_flags & MRF_KSREAD)) {
			mca_user_rdlock(privctx->mc_session->ms_user);
			reqp->mr_flags |= MRF_KSREAD;
		}
	}

	/* schedule the work by doing a submit */
	if ((rv = mca_start(reqp)) != CRYPTO_QUEUED) {
		if (reqp->mr_flags & MRF_KSREAD) {
			mca_user_unlock(privctx->mc_session->ms_user);
			reqp->mr_flags &= ~MRF_KSREAD;
		}
	}

done:
	if (rv != CRYPTO_QUEUED) {
		/*EMPTY*/
		MCA_RESTORE_CHAIN(&reqp->mr_ibuf_chain);
		MCA_RESTORE_CHAIN(&reqp->mr_obuf_chain);
	}

	DBG(NULL, DENTRY, "des3_start <--[0x%x]", rv);

	return (rv);
}

static void
des3_done(mca_request_t *reqp)
{
	crypto_data_t		*out = reqp->mr_out;
	mca_privatectx_t	*privctx;
	mca_3des_ctx_t		*des3ctx;
	int			ispaddecrypt;
	int			residlen = 0;
	int			rv = CRYPTO_SUCCESS;

	DBG(NULL, DENTRY, "des3_done -->");

	privctx = reqp->mr_context;
	des3ctx = (mca_3des_ctx_t *)(privctx + 1);

	MCA_RESTORE_CHAIN(&reqp->mr_ibuf_chain);
	MCA_RESTORE_CHAIN(&reqp->mr_obuf_chain);

	ispaddecrypt = ((reqp->mr_cmd & CMD_HI_PAD) &&
	    ((reqp->mr_cmd & CMD_MASK) == CMD_3DESDEC)) ?  1 : 0;

	if (reqp->mr_errno != CRYPTO_SUCCESS) {
		rv = reqp->mr_errno;
		goto done;
	}

	/* findout the residual len */
	if (reqp->mr_in) {
		residlen = mca_get_datalen(reqp->mr_in);
	}

	if (ispaddecrypt) {
		ddi_dma_sync(reqp->mr_obuf_dmah, 0, reqp->mr_resultlen,
		    DDI_DMA_SYNC_FORKERNEL);

		/*
		 * copy the last block from the previous update
		 * to the output buffer if there is any
		 */
		rv = mca_scatter(des3ctx->lastblock, des3ctx->lastblocklen,
		    reqp->mr_out);
		if (rv != CRYPTO_SUCCESS) {
			goto done;
		}
		des3ctx->lastblocklen = 0;

		/* copy the new output */
		if ((residlen == 0) && (reqp->mr_cmd & CMD_HI_REMOVEPAD)) {
			/* end of the pad op. remove the padding */
			rv = mca_unpad_scatter(reqp->mr_obuf_kaddr,
			    reqp->mr_resultlen, reqp->mr_out, DESBLOCK);
			goto done;
		} else if (des3ctx->residlen || residlen) {
			/*
			 * If there is a residual, we know that this
			 * buf does not contain the padding. Return
			 * everything to the caller.
			 */
			rv = mca_scatter(reqp->mr_obuf_kaddr,
			    reqp->mr_resultlen, reqp->mr_out);
			if (rv != CRYPTO_SUCCESS) {
				goto done;
			}
		} else {
			/*
			 * If there is no residual, this buf may contain the
			 * padding. Save the last 8-byte of the output.
			 */
			rv = mca_scatter(reqp->mr_obuf_kaddr,
			    reqp->mr_resultlen - DESBLOCK, reqp->mr_out);
			if (rv != CRYPTO_SUCCESS) {
				goto done;
			}

			/* save last block to the ctx */
			bcopy(reqp->mr_obuf_kaddr + reqp->mr_resultlen -
			    DESBLOCK, des3ctx->lastblock, DESBLOCK);
			des3ctx->lastblocklen = DESBLOCK;
		}
	} else if (reqp->mr_flags & MRF_SCATTER) {
		ddi_dma_sync(reqp->mr_obuf_dmah, 0, reqp->mr_resultlen,
		    DDI_DMA_SYNC_FORKERNEL);

		rv = mca_scatter(reqp->mr_obuf_kaddr, reqp->mr_resultlen,
		    reqp->mr_out);
		if (rv != CRYPTO_SUCCESS) {
			goto done;
		}
	} else {
		/* we've processed some more data */
		mca_updateoutlen(out, reqp->mr_byte_count);
	}

	/*
	 * For encryption only, we have to grab the IV for the
	 * next pass AFTER encryption.
	 */
	if ((reqp->mr_cmd & CMD_MASK) == CMD_3DESENC) {
		/* get last 8 bytes for IV of next op */
		mca_getbufbytes(out, out->cd_length - DESBLOCK,
		    DESBLOCK, (char *)privctx->mc_shortparam);
	}

	/*
	 * If there is more to do, then reschedule another
	 * pass. Otherwise, save the residual in the ctx and exit.
	 */
	if ((des3ctx->residlen + residlen >= DESBLOCK) ||
	    (reqp->mr_cmd & CMD_HI_ADDPAD)) {
		/* reset the key len field */
		reqp->mr_key_len = 0;
		/* more work to do, schedule another pass */
		rv = des3_start(reqp);
		if (rv == CRYPTO_QUEUED) {
			return;
		}
	} else {
		/* copyin the residual to the context */
		if (residlen > 0) {
			mca_getbufbytes(reqp->mr_in, 0, residlen,
			    des3ctx->resid + des3ctx->residlen);
		}
		des3ctx->residlen += residlen;

		/* residual was stashed in the context */
		mca_setresid(reqp->mr_in, 0);
	}

done:

	if (reqp->mr_flags & MRF_KSREAD) {
		mca_user_unlock(privctx->mc_session->ms_user);
	}
	crypto_op_notification(reqp->mr_cf_req, rv);
	mca_freereq(reqp);

	DBG(NULL, DENTRY, "des3_done <-- [0x%x]", rv);
}


static void
des3_atomicdone(mca_request_t *reqp)
{
	mca_privatectx_t	*privctx = reqp->mr_context;
	int			residlen;

	residlen = mca_get_datalen(reqp->mr_in);

	des3_done(reqp);

	/*
	 * Free the context allocated for atomic operation if there is
	 * no more data to process. des3_done() may schedule another
	 * asynchronous operation. In which case, we don't want to free
	 * the context.
	 * Note: the context for single/multi-part operation is freed
	 * by the framework
	 */
	if (residlen == 0) {
		mca_freectx(privctx);
	}
}
