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

#pragma ident	"@(#)mca_login.c	1.30	08/07/29 SMI"

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
#include <sys/atomic.h>
#include <sys/mca.h>
#include <sys/mca_hw.h>
#endif

static void createkey_done(mca_request_t *);
static void deletekey_done(mca_request_t *);
static void login_done(mca_request_t *);
static void loadkeys_done(mca_request_t *);
static void setpass_done(mca_request_t *);
static void copykey_done(mca_request_t *);
static void modifykey_done(mca_request_t *);
static mca_user_t *mca_get_user(mca_keystore_t *, char *, boolean_t);
static void mca_clear_user(mca_user_t *);

/* this must be large enough to account for timeouts on failed attempts */
#define	AUTHTIMEOUT	drv_usectohz(2 * SECOND)

void
mca_user_rdlock(mca_user_t *user)
{
	DBG(NULL, DAUTH, "mca_user_rdlock [%p]", user);
	mutex_enter(&user->mu_mx);
	while (user->mu_wantw | user->mu_wlock) {
		cv_wait(&user->mu_cv, &user->mu_mx);
	}
	user->mu_readers++;
	mutex_exit(&user->mu_mx);
}

void
mca_user_wrlock(mca_user_t *user)
{
	DBG(NULL, DAUTH, "mca_user_wrlock [%p]", user);
	mutex_enter(&user->mu_mx);
	while (user->mu_readers | user->mu_wlock) {
		user->mu_wantw = 1;
		cv_wait(&user->mu_cv, &user->mu_mx);
	}
	user->mu_wantw = 0;
	user->mu_wlock = 1;
	mutex_exit(&user->mu_mx);
}

void
mca_user_unlock(mca_user_t *user)
{
	DBG(NULL, DAUTH, "mca_user_unlock [%p]", user);
	mutex_enter(&user->mu_mx);
	if (user->mu_wlock) {
		user->mu_wlock = 0;
	} else {
		user->mu_readers--;
	}
	cv_broadcast(&user->mu_cv);
	mutex_exit(&user->mu_mx);
}


/*
 * Login implementation.
 */
static void
login_done(mca_request_t *reqp)
{
	mca_t		*mca = reqp->mr_mca;
	mca_user_t	*user = (mca_user_t *)reqp->mr_context;
	char		*name = reqp->mr_ibuf_kaddr;
	int		rv;

	DBG(mca, DAUTH, "login_done[%s] -->", name);

	if (reqp->mr_errno != CRYPTO_SUCCESS) {
		DBG(mca, DAUTH, "Login failed -- %d.", reqp->mr_errno);
		rv = reqp->mr_errno;
		goto error;
	}

	ddi_dma_sync(reqp->mr_obuf_dmah, 0, 4 * sizeof (uint32_t),
	    DDI_DMA_SYNC_FORKERNEL);

	if (mca_set_session_cred(reqp->mr_session,
	    (uint32_t *)reqp->mr_obuf_kaddr, user) != CRYPTO_SUCCESS) {
		rv = CRYPTO_HOST_MEMORY;
		goto error;
	}

	/* zero out password */
	bzero(reqp->mr_ibuf_kaddr, reqp->mr_in_len);

	/* post-login-process */
	mca_post_login(reqp);

	return;

error:
	/* login failed: release the refcnt */
	if (user->mu_flags & MUF_LOADED) {
		/* holding user rd lock: needs write lock */
		mca_user_unlock(user);
		mca_delete_user(user);
	} else {
		/* holding user wr lock */
		mca_clear_user(user);
		mca_user_unlock(user);
	}
	reqp->mr_session->ms_user = NULL;

	mca_session_releaseref(reqp->mr_session, UNLOCKED);
	crypto_op_notification(reqp->mr_cf_req, rv);
	/* zero out password */
	bzero(reqp->mr_ibuf_kaddr, reqp->mr_in_len);
	mca_freereq(reqp);
}

/*
 * This function looks up a user (designated with 'name') in the user table,
 * and return the user structure for the user. It returns NULL only when
 * memory allocation fails.
 *
 * If the user slot exists and has already been loaded, grab the user's rdlock.
 * If the user slot exists but has not been loaded (an error occured when the
 * user was being loaded last time), grab the user' wrlock.
 * If the user slot does not exist, allocated a slot for the user and grab
 * the user's wrlock. If the table is full, rellocated the table with 10 more
 * slots.
 * Note: this function may grab keystore wrlock. Be aware!
 */
static mca_user_t *
mca_get_user(mca_keystore_t *ks, char *name, boolean_t force_wrlock)
{
	mca_user_t	*user = NULL;
	mca_user_t	*emptyslot = NULL;

	mca_keystore_rdlock(ks);

	while ((user = (mca_user_t *)mca_nextqueue(
	    &ks->mks_users, (mca_listnode_t *)user)) != NULL) {
		if (strcmp(user->mu_name, name) == 0) {
			if (user->mu_flags & MUF_INIT) {
				if (force_wrlock) {
					mca_user_wrlock(user);
				} else {
					mca_user_rdlock(user);
				}
				if (user->mu_flags & MUF_LOADED) {
					user->mu_refcnt++;
					mca_keystore_unlock(ks);
					return (user);
				}
				mca_user_unlock(user);
				break;
			}
		}
	}

	/* switch to a write lock on the keystore */
	mca_keystore_unlock(ks);
	mca_keystore_wrlock(ks);

	/*
	 * Check to make sure that there is no slot for the user
	 * with the keystore wrlock.
	 */
	user = NULL;
	while ((user = (mca_user_t *)mca_nextqueue(
	    &ks->mks_users, (mca_listnode_t *)user)) != NULL) {
		if (strcmp(user->mu_name, name) == 0) {
			if (user->mu_flags & MUF_INIT) {
				if (force_wrlock) {
					mca_user_wrlock(user);
				} else {
					mca_user_rdlock(user);
				}
				if (user->mu_flags & MUF_LOADED) {
					user->mu_refcnt++;
					mca_keystore_unlock(ks);
					return (user);
				}
				mca_user_unlock(user);
			}
		}

		if (!(user->mu_flags & MUF_PENDING) &&
		    !(user->mu_flags & MUF_LOADED)) {
			/* This record is not used: reuse it */
			if (emptyslot == NULL) {
				emptyslot = user;
			}
		}
	}

	/*
	 * The user does not exist in the user's keytable. Allocate a slot
	 * for the user.
	 */

	if (emptyslot == NULL) {
		emptyslot = kmem_zalloc(sizeof (mca_user_t), KM_SLEEP);
		mca_initq(&(emptyslot->mu_linkage));
		mca_enqueue(&ks->mks_users, (mca_listnode_t *)emptyslot);
		mutex_init(&emptyslot->mu_mx, NULL, MUTEX_DRIVER, NULL);
		cv_init(&emptyslot->mu_cv, NULL, CV_DRIVER, NULL);
		emptyslot->mu_wantw = 0;
		emptyslot->mu_wlock = 0;
		emptyslot->mu_readers = 0;
		mca_initq(&(emptyslot->mu_keys));
	}

	mca_user_wrlock(emptyslot);

	/* initialize the user's structure */
	(void) strncpy(emptyslot->mu_name, name, MAX_USERNAMESZ);
	emptyslot->mu_keystore = ks;
	emptyslot->mu_refcnt = 1;
	emptyslot->mu_ks_seq = 0;
	emptyslot->mu_flags = (MUF_INIT | MUF_PENDING);

	mca_keystore_unlock(ks);

	return (emptyslot);
}

/*
 * The caller must hold the user's write lock
 */
static void
mca_clear_user(mca_user_t *user)
{
	mca_key_t 	*key;

	user->mu_refcnt--;

	if (user->mu_refcnt == 0) {
		/* delete all of the user's keys from the driver */
		while ((key = (mca_key_t *)mca_peekqueue(&user->mu_keys)) !=
		    NULL) {
			mca_unregister_key(key);
		}
		user->mu_flags = MUF_INIT;
		bzero((void *)user->mu_name, MAX_USERNAMESZ);
	}
}

void
mca_delete_user(mca_user_t *user)
{
	mca_keystore_wrlock(user->mu_keystore);
	mca_user_wrlock(user);

	mca_clear_user(user);

	mca_user_unlock(user);
	mca_keystore_unlock(user->mu_keystore);
}

int
mca_login(mca_t *mca, mca_keystore_t *ks, mca_session_t *session,
    char *name, char *pass,
    crypto_req_handle_t *cfreq)
{
	mca_ring_t	*ring = &mca->mca_ring_om;
	mca_request_t	*reqp;
	mca_user_t	*user;
	int		ulen, plen;
	int		rv;

	DBG(mca, DAUTH, "mca_login -->");

	if (ks == NULL) {
		mca_error(mca, "Device keystore not initialized.");
		return (CRYPTO_FAILED);
	}

	if (((ulen = strlen(name)) > 256) || ((plen = strlen(pass)) > 256)) {
		DBG(mca, DAUTH, "User or password too long?");
		return (CRYPTO_PIN_INCORRECT);
	}

	if ((reqp = mca_getreq(ring)) == NULL) {
		DBG(mca, DWARN, "mca_login: mca_getreq failed");
		return (CRYPTO_BUSY);
	}

	reqp->mr_dbm_handle = mca_ks_get_handle(ks, mca);

	/*
	 * Look up the user in the user table. If the user exists, grab
	 * the user's rdlock. If the user does not exist, a slot is allocated
	 * and grab the user's wrlock.
	 */
	user = mca_get_user(ks, name, B_FALSE /* do not force wrlock */);
	if (user == NULL) {
		DBG(mca, DAUTH, "mca_login: mca_get_user failed");
		mca_freereq(reqp);
		return (CRYPTO_HOST_MEMORY);
	}
	reqp->mr_context = (mca_privatectx_t *)user;
	session->ms_user = user;

	bcopy(name, reqp->mr_ibuf_kaddr, ulen + 1);
	bcopy(pass, reqp->mr_ibuf_kaddr + ulen + 1, plen + 1);

	/* both input and output are less than a pagesz: no chaining */
	reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
	reqp->mr_in_len = ulen + plen + 2;
	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_out_len = sizeof (uint32_t) * 4;
	reqp->mr_callback = login_done;
	reqp->mr_session = session;
	reqp->mr_cf_req = cfreq;
	reqp->mr_cmd = CMD_LOGIN;
	reqp->mr_byte_stat = -1;
	reqp->mr_job_stat = -1;
	reqp->mr_timeout = AUTHTIMEOUT;
	reqp->mr_flags = MRF_TASKQ;

	if (mca_isfips(mca)) {
		mca_ktkencryptbuf(reqp);
	}

	ddi_dma_sync(reqp->mr_ibuf_dmah, 0, reqp->mr_in_len,
	    DDI_DMA_SYNC_FORDEV);

	if ((rv = mca_start(reqp)) != CRYPTO_QUEUED) {
		/* login failed: release the refcnt */
		if (user->mu_flags & MUF_LOADED) {
			/* it holds user rd lock */
			mca_user_unlock(user);
			mca_delete_user(user);
		} else {
			/* it holds user wr lock */
			mca_clear_user(user);
			mca_user_unlock(user);
		}
		session->ms_user = NULL;

		/* zero out password */
		bzero(reqp->mr_ibuf_kaddr, reqp->mr_in_len);
		DBG(mca, DWARN, "mca_login: mca_start failed[0x%x]", rv);
		mca_freereq(reqp);
	}
	return (rv);
}

int
mca_setpass(mca_t *mca, char *username, char *oldpass, char *newpass,
    crypto_req_handle_t *cfreq, mca_keystore_t *ks,
    crypto_session_id_t session_id)
{
	mca_ring_t	*ring = &mca->mca_ring_om;
	mca_request_t	*reqp;
	int		ulen, olen, nlen;
	int		rv;
	mca_session_t	*session;
	mca_user_t	*user = NULL;

	if (((ulen = strlen(username)) > 256) ||
	    ((olen = strlen(oldpass)) > 256) ||
	    ((nlen = strlen(newpass)) > 256)) {
		DBG(mca, DWARN, "User or password too long?");
		return (CRYPTO_PIN_LEN_RANGE);
	}

	if ((reqp = mca_getreq(ring)) == NULL) {
		return (CRYPTO_BUSY);
	}

	session = mca_session_holdref(mca, session_id);
	if (session == NULL) {
		mca_freereq(reqp);
		return (CRYPTO_SESSION_HANDLE_INVALID);
	}

	if (session->ms_user) {
		/*
		 * The user is already logged in. Grab the user's write lock.
		 */
		mca_user_wrlock(session->ms_user);
	} else {
		/*
		 * The user is not logged in. Look up the user and grab
		 * the user's write lock.
		 */
		user = mca_get_user(ks, username, B_TRUE /* force wrlock */);
		if (user == NULL) {
			DBG(mca, DAUTH, "mca_login: mca_get_user failed");
			mca_session_releaseref(session, UNLOCKED);
			mca_freereq(reqp);
			return (CRYPTO_HOST_MEMORY);
		}
		reqp->mr_context = (mca_privatectx_t *)user;
	}
	reqp->mr_flags = MRF_TASKQ | MRF_KSUPDATE;
	reqp->mr_dbm_handle = mca_ks_get_handle(ks, mca);

	bcopy(username, reqp->mr_ibuf_kaddr, ulen + 1);
	bcopy(oldpass, reqp->mr_ibuf_kaddr + ulen + 1, olen + 1);
	bcopy(newpass, reqp->mr_ibuf_kaddr + ulen + olen + 2, nlen + 1);

	reqp->mr_in_len = ulen + olen + nlen + 3;
	reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
	reqp->mr_in_len = ulen + olen + nlen + 3;
	reqp->mr_out_paddr = 0;
	reqp->mr_out_len = 0;
	reqp->mr_callback = setpass_done;
	reqp->mr_cf_req = cfreq;
	reqp->mr_cmd = CMD_SETPASS;
	reqp->mr_byte_stat = -1;
	reqp->mr_job_stat = -1;
	reqp->mr_timeout = AUTHTIMEOUT;
	reqp->mr_session = session;

	if (mca_isfips(mca)) {
		mca_ktkencryptbuf(reqp);
	}

	ddi_dma_sync(reqp->mr_ibuf_dmah, 0, reqp->mr_in_len,
	    DDI_DMA_SYNC_FORDEV);

	if ((rv = mca_start(reqp)) != CRYPTO_QUEUED) {
		if (session->ms_user) {
			mca_user_unlock(session->ms_user);
		} else {
			/* decrement the user's refcnt */
			mca_clear_user(user);
			mca_user_unlock(user);
		}
		mca_session_releaseref(session, UNLOCKED);
		/* zero out password */
		bzero(reqp->mr_ibuf_kaddr, reqp->mr_in_len);
		mca_freereq(reqp);
	}
	return (rv);
}

static void
setpass_done(mca_request_t *reqp)
{
	mca_t		*mca = reqp->mr_mca;

	/* zero out password */
	bzero(reqp->mr_ibuf_kaddr, reqp->mr_in_len);

	/* drop the user lock */
	if (reqp->mr_session->ms_user) {
		mca_user_unlock(reqp->mr_session->ms_user);
	} else {
		/* release the refcnt on the user */
		mca_clear_user((mca_user_t *)reqp->mr_context);
		mca_user_unlock((mca_user_t *)reqp->mr_context);
	}

	/* release the session */
	mca_session_releaseref(reqp->mr_session, UNLOCKED);

	if (reqp->mr_errno != 0) {
		DBG(mca, DAUTH, "Setpass failed -- %d.", reqp->mr_errno);
		crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
		mca_freereq(reqp);
		return;
	}

	crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
	mca_freereq(reqp);
}

int
mca_loadkeys_ctxalloc(mca_t *mca, mca_key_t **keys, size_t keyssz,
    mca_user_t *user, mca_loadkeys_ctx_t **ctxp)
{
	mca_loadkeys_ctx_t	*ctx;
	ddi_dma_cookie_t	c;
	unsigned		ccnt;

	/*
	 * Allocate a context with DMA region to receive an
	 * arbitrarily large result from key enumeration.
	 */
	ctx = (mca_loadkeys_ctx_t *)kmem_zalloc(sizeof (*ctx), KM_NOSLEEP);
	if (ctx == NULL) {
		DBG(mca, DWARN, "unable to alloc loadkeys ctx");
		return (CRYPTO_HOST_MEMORY);
	}

	ctx->mlk_nkeyids = keyssz / sizeof (mca_key_t *);
	ctx->mlk_keyidssz = ctx->mlk_nkeyids * sizeof (ctx->mlk_keyids[0]);
	/* round up to a whole page */
	ctx->mlk_keyidssz = ROUNDUP(ctx->mlk_keyidssz, mca->mca_pagesize);
	ctx->mlk_keys = keys;
	ctx->mlk_keyssz = keyssz;
	ctx->mlk_user = user;

	if (ddi_dma_alloc_handle(mca->mca_dip, &no_sg_dma_attr,
	    DDI_DMA_DONTWAIT, NULL, &ctx->mlk_dmah) != DDI_SUCCESS) {
		DBG(mca, DWARN, "unable to alloc loadkeys dma handle");
		mca_loadkeys_ctxfree(ctx);
		return (CRYPTO_HOST_MEMORY);
	}

	if (ctx->mlk_keyidssz) {
		if (ddi_dma_mem_alloc(ctx->mlk_dmah, ctx->mlk_keyidssz,
		    &mca_bufattr,
		    DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, NULL,
		    (caddr_t *)&ctx->mlk_keyids, &ctx->mlk_keyidssz,
		    &ctx->mlk_acch) != DDI_SUCCESS) {
			DBG(mca, DWARN,
			    "unable to alloc loadkeys dma (%ld) memory",
			    ctx->mlk_keyidssz);
			mca_loadkeys_ctxfree(ctx);
			return (CRYPTO_HOST_MEMORY);
		}

		if (ddi_dma_addr_bind_handle(ctx->mlk_dmah, NULL,
		    (caddr_t)ctx->mlk_keyids, ctx->mlk_keyidssz,
		    DDI_DMA_READ | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, NULL,
		    &c, &ccnt) != DDI_DMA_MAPPED) {
			DBG(mca, DWARN, "unable to map loadkeys dma memory");
			mca_loadkeys_ctxfree(ctx);
			return (CRYPTO_HOST_MEMORY);
		}
		ctx->mlk_paddr = c.dmac_address;
	} else {
		ctx->mlk_paddr = 0;
	}
	ctx->mlk_nextid = 0;
	ctx->mlk_nextkey = 0;

	*ctxp = ctx;

	return (CRYPTO_SUCCESS);
}

void
mca_loadkeys_ctxfree(void *arg)
{
	mca_loadkeys_ctx_t	*ctx = (mca_loadkeys_ctx_t *)arg;
	if (ctx->mlk_paddr) {
		(void) ddi_dma_unbind_handle(ctx->mlk_dmah);
	}
	if (ctx->mlk_acch) {
		ddi_dma_mem_free(&ctx->mlk_acch);
	}
	if (ctx->mlk_dmah) {
		ddi_dma_free_handle(&ctx->mlk_dmah);
	}
	kmem_free(ctx, sizeof (mca_loadkeys_ctx_t));
}

/*
 * keystore lock should be released by the caller
 */
int
mca_loadkeys(mca_request_t *reqp)
{
	mca_t			*mca = reqp->mr_mca;
	mca_session_t		*session = reqp->mr_session;
	mca_loadkeys_ctx_t	*ctx = (mca_loadkeys_ctx_t *)reqp->mr_context;
	int			rv;

	DBG(mca, DAUTH, "mca_loadkeys -->");

	if (session->ms_user->mu_keystore == NULL) {
		DBG(mca, DWARN, "Device has no keystore");
		return (CRYPTO_GENERAL_ERROR);
	}

	rv = mca_get_session_cred(session, reqp->mr_cred);
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "mca_loadkeys: mca_get_session_cred "
		    "failed with 0x%x", rv);
		return (CRYPTO_GENERAL_ERROR);
	}

	reqp->mr_out_paddr = ctx->mlk_paddr;
	reqp->mr_out_len = ctx->mlk_keyidssz;
	reqp->mr_out = NULL;
	reqp->mr_in_paddr = 0;
	reqp->mr_in_len = 0;
	reqp->mr_in = NULL;
	reqp->mr_cmd = CMD_ENUMERATE_KEYS;
	reqp->mr_callback = loadkeys_done;
	reqp->mr_flags = MRF_TASKQ;

	if ((rv = mca_start(reqp)) != CRYPTO_QUEUED) {
		DBG(mca, DWARN, "mca_loadkeys: mca_start failed with 0x%x", rv);
	}
	return (rv);
}

static void
loadkeys_done(mca_request_t *reqp)
{
	mca_t			*mca = reqp->mr_mca;
	mca_loadkeys_ctx_t	*ctx;
	int			rv;
	mca_key_t		**mkeys;
	mca_key_t		*mkey;
	int			nkeyids;

	ctx = (mca_loadkeys_ctx_t *)reqp->mr_context;
	mkeys = ctx->mlk_keys;

	if (reqp->mr_cmd == CMD_ENUMERATE_KEYS) {
		DBG(mca, DAUTH, "loadkeys_done[ENUMERATE_KEYS] -->");

		nkeyids = reqp->mr_resultlen / sizeof (ctx->mlk_keyids[0]);
		if (nkeyids > ctx->mlk_nkeyids) {
			ctx->mlk_nkeyids = nkeyids;
			reqp->mr_errno = CRYPTO_BUFFER_TOO_SMALL;
			goto failed;
		}

		ctx->mlk_nkeyids = nkeyids;
		if (reqp->mr_errno != CRYPTO_SUCCESS) {
			DBG(mca, DWARN, "device error %d in loadkeys",
			    reqp->mr_errno);
			goto failed;
		}

		/* we were enumerating keys, and haven't loaded anything yet */
		ctx->mlk_nextid = 0;
		ctx->mlk_nextkey = 0;
		/* unbinding the handle does an implicit sync */
		(void) ddi_dma_unbind_handle(ctx->mlk_dmah);
		ctx->mlk_paddr = 0;	/* so we don't try to unbind again */
		goto nextkey;
	}

	if (reqp->mr_errno == CRYPTO_OBJECT_HANDLE_INVALID) {
		/* the key was deleted while we were trying to retrieve it */
		ctx->mlk_nkeyids--;
		goto nextkey;
	}
	if (reqp->mr_errno != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "device error %d in loadkeys", reqp->mr_errno);
		goto failed;
	}

	/* if we got the template of the last key, proceed... */
	if (reqp->mr_cmd == CMD_RETRIEVE_KEY) {
		cpg_attr_t	*attr = NULL;
		uint16_t	keyflags;
		int		residlen;
		mca_key_head_t	*keyhead;
		uint32_t	attrlen;
		void		*keybuf;
		char		*kaddr;

		DBG(mca, DAUTH, "loadkeys_done[RETRIEVE_KEY] -->");

		keyflags = reqp->mr_key_flags[0];
		keyhead = (mca_key_head_t *)reqp->mr_obuf_kaddr;
		residlen = reqp->mr_resultlen;

		ddi_dma_sync(reqp->mr_obuf_dmah, 0, reqp->mr_resultlen,
		    DDI_DMA_SYNC_FORKERNEL);

		if (mca_isfips(reqp->mr_mca)) {
			mca_ktkdecryptbuf(reqp);
		}

		/* Setup the template */
		attrlen = GETBUF32(&keyhead->descrlen);
		if (attrlen <= 0) {
			DBG(mca, DWARN, "loadkeys_done: 0 byte descrlen");
			reqp->mr_errno = CRYPTO_GENERAL_ERROR;
			goto failed;
		}
		if ((keybuf = kmem_zalloc(attrlen, KM_NOSLEEP)) == NULL) {
			DBG(mca, DWARN, "loadkeys_done: failed to allocate %d "
			    "bytes", attrlen);
			reqp->mr_errno = CRYPTO_HOST_MEMORY;
			goto failed;
		}
		kaddr = (char *)(keyhead + 1);
		bcopy(kaddr, keybuf, attrlen);

		/* The ..._EXTRA_CARE flag checks the data coming in */
		if ((rv = cpg_attr_alloc_attach_data(&attr,
		    (cpg_attr_data_t *)keybuf,
		    attrlen, &mca_global_attr_infobase,
		    CPG_ATTR_NOSLEEP | CPG_ATTR_USE_EXTRA_CARE)) !=
		    CRYPTO_SUCCESS) {
			DBG(mca, DWARN, "cpg_attr_attach_data failed 0x%x, "
			    "attrlen %u", rv, attrlen);
			attr = NULL;
			kmem_free(keybuf, attrlen);
			reqp->mr_errno = rv;
			goto failed;
		}
		/*
		 * If this is a cpg_attr version 1 key (i.e. from back
		 * when it was kcl_attr), it's policy is NULL_POLICY.
		 * Force the policy to be ACTIVE_OBJECT_POLICY.  If we
		 * every have object policies that depend on the
		 * object type, we will have to look up the object
		 * type and send the policy accordingly.
		 */
		if (cpg_attr_get_policy(attr) != ACTIVE_OBJECT_POLICY) {
			rv = cpg_attr_set_policy(attr, ACTIVE_OBJECT_POLICY);
			if (rv) {
				DBG(mca, DWARN, "loadkeys_done: "
				    "cpg_attr_set_policy "
				    "failed with 0x%x", rv);
				cpg_attr_free(attr);
				reqp->mr_errno = rv;
				goto failed;
			}
		}

		rv = mca_parse_key(attr, keyhead, residlen, keyflags, &mkey);
		if (rv != CRYPTO_SUCCESS) {
			DBG(mca, DWARN, "loadkeys_done: mca_parse_key "
			    "failed with 0x%x", rv);
			cpg_attr_free(attr);
			reqp->mr_errno = rv;
			goto failed;
		}

		mkey->mk_keyflags |= KEYFLAG_VALID;

		/*
		 * Add the key to the UKT: already holding user wrlock
		 * UKT's keystore sequence number is incremented.
		 */
		rv = mca_register_key(reqp->mr_session->ms_user, mkey);
		if (rv != CRYPTO_SUCCESS) {
			DBG(mca, DWARN, "loadkeys_done: mca_register_key "
			    "failed with 0x%x", rv);
			mkey->mk_refcnt = 0;
			mca_key_free(mkey);
			reqp->mr_errno = rv;
			goto failed;
		}

		mkeys[ctx->mlk_nextkey++] = mkey;
	}

nextkey:
	if (ctx->mlk_nextid >= ctx->mlk_nkeyids) {
		/* we are done! */
		ctx->mlk_user->mu_flags &= ~MUF_PENDING;
		ctx->mlk_user->mu_flags |= MUF_LOADED;
		goto done;
	}

	/* now we need to set up to load another key */
	reqp->mr_key_id[0] = GETBUF32(
	    &(ctx->mlk_keyids[ctx->mlk_nextid].mlk_keyid[0]));
	reqp->mr_key_id[1] = GETBUF32(
	    &(ctx->mlk_keyids[ctx->mlk_nextid].mlk_keyid[1]));
	ctx->mlk_nextid++;

	if ((reqp->mr_key_id[0] == 0) && (reqp->mr_key_id[1] == 0)) {
		goto nextkey;
	}

	/* try to locate the key in our in-memory cache */
	mkey = mca_find_key(ctx->mlk_user, reqp->mr_key_id);
	if (mkey != NULL) {
		mkeys[ctx->mlk_nextkey++] = mkey;
		goto nextkey;
	}

	/* now submit the request and return */
	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_out_next_paddr = reqp->mr_obuf_next_paddr;
	reqp->mr_out_len = MAXPACKET;
	reqp->mr_out_first_len = reqp->mr_obuf_sz;

	reqp->mr_out = NULL;
	reqp->mr_in_paddr = 0;
	reqp->mr_in_len = 0;
	reqp->mr_in = NULL;
	reqp->mr_cmd = CMD_RETRIEVE_KEY;
	reqp->mr_callback = loadkeys_done;
	reqp->mr_flags = MRF_TASKQ;

	/* sync key dma for output chains */
	ddi_dma_sync(reqp->mr_key_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	if (mca_isfips(reqp->mr_mca)) {
		mca_setiv(reqp);
	}
	if ((rv = mca_start(reqp)) != CRYPTO_QUEUED) {
		reqp->mr_errno = rv;
		goto failed;
	}

	return;
done:
	/* all keys were loaded */
	reqp->mr_errno = CRYPTO_SUCCESS;
failed:
	if (reqp->mr_errno != CRYPTO_SUCCESS) {
		/* release any keys we have loaded so far */
		int	i;
		for (i = 0; i < ctx->mlk_nextkey; i++) {
			if (mkeys[i]) {
				/* drop the refcnt held for the SKT */
				mca_key_releaseref(mkeys[i], UNLOCKED);
				mkeys[i] = NULL;
			}
		}
		DBG(mca, DCHATTY, "loadkeys_done: error %d", reqp->mr_errno);
	}

	/*
	 * Post process the loaded keys for each framework holding a keystore
	 * readlock.
	 */
	mca_post_loadkeys(reqp);
}

int
mca_deletekey(mca_t *mca, mca_session_t *session, mca_key_t *mkey,
    crypto_req_handle_t *cfreq)
{
	mca_request_t		*reqp;
	mca_keystore_t		*mks;
	mca_key_head_t		*keyhead = (mca_key_head_t *)(mkey + 1);
	int			rv;

	if ((reqp = mca_getreq(&mca->mca_ring_om)) == NULL) {
		return (CRYPTO_BUSY);
	}

	rv = mca_get_session_cred(session, reqp->mr_cred);
	if (rv != CRYPTO_SUCCESS) {
		mca_freereq(reqp);
		return (rv);
	}

	mks = session->ms_user->mu_keystore;

	mca_user_wrlock(session->ms_user);
	reqp->mr_flags = MRF_TASKQ | MRF_KSUPDATE;
	reqp->mr_dbm_handle = mca_ks_get_handle(mks, mca);

	reqp->mr_key_id[0] = GETBUF32(&(keyhead->cardid));
	reqp->mr_key_id[1] = GETBUF32(&(keyhead->objectid));
	reqp->mr_in_paddr = 0;
	reqp->mr_in_len = 0;
	reqp->mr_out_paddr = 0;
	reqp->mr_out_len = 0;
	reqp->mr_cmd = CMD_DELETE_KEY;
	reqp->mr_byte_stat = -1;
	reqp->mr_job_stat = -1;
	reqp->mr_cf_req = cfreq;
	reqp->mr_callback = deletekey_done;
	reqp->mr_session = session;
	reqp->mr_mkey = mkey;
	reqp->mr_key_flags[0] = mkey->mk_keyflags;
	reqp->mr_timeout = OMTIMEOUT;

	if ((rv = mca_start(reqp)) != CRYPTO_QUEUED) {
		mca_user_unlock(session->ms_user);
		mca_freereq(reqp);
	}
	return (rv);
}

static void
deletekey_done(mca_request_t *reqp)
{
	mca_t		*mca = reqp->mr_mca;
	/*LINTED E_FUNC_SET_NOT_USED*/
	mca_key_t	*mkey = reqp->mr_mkey;

	if (reqp->mr_errno != 0) {
		DBG(mca, DWARN, "key delete failed, err %d", reqp->mr_errno);
		mca_user_unlock(reqp->mr_session->ms_user);
		mca_validate_key(mkey);
		mca_session_releaseref(reqp->mr_session, UNLOCKED);
		crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
		mca_freereq(reqp);
		return;
	}

	/* delete the key from the UKT if token */
	if (mkey->mk_keyflags & KEYFLAG_PERSIST) {
		mca_unregister_key(mkey);
	}

	mca_user_unlock(reqp->mr_session->ms_user);

	/*
	 * Delete the key on the session, and release the key refcnt
	 * Session refcnt is also dropped.
	 */
	mca_delete_key(reqp->mr_session, mkey->mk_skt_keyid);

	crypto_op_notification(reqp->mr_cf_req, CRYPTO_SUCCESS);
	mca_freereq(reqp);
}

/*
 * mca_createkey_flags fluffs certain attributes in template, sets
 * *pflags, and checks for some illegal combinations.
 */
int
mca_createkey_flags(cpg_attr_t *template, uint32_t *pflags)
{
	uint32_t	flags = 0;
	uint8_t		bool;
	uint8_t		isextractable;
	int		rv;

	*pflags = 0;

	isextractable = 1; /* CPGA_EXTRACTABLE defaults to true */
	(void) cpg_attr_lookup_uint8(template, CPGA_EXTRACTABLE,
	    &isextractable);
	flags |= isextractable ? 0 : KEYFLAG_NOWRAP;

	/* CKA_SENSTIIVE defaults to the opposite of CKA_EXTRACTABLE. */
	bool = !isextractable;
	rv = cpg_attr_lookup_uint8(template, CPGA_SENSITIVE, &bool);
	if ((rv == CRYPTO_ATTRIBUTE_TYPE_INVALID) ||
	    (rv == CRYPTO_TEMPLATE_INCONSISTENT)) {
		/* Fluff CKA_SENSITIVE */
		if (cpg_attr_add_uint8(template, CPGA_SENSITIVE, bool,
		    CPG_ATTR_NOSLEEP)) {
			return (CRYPTO_HOST_MEMORY);
		}
	}
	flags |= bool ? KEYFLAG_SENSITIVE : 0;

	if (!isextractable && !bool) {
		/*
		 * The case CKA_EXTRACTABLE and CKA_SENSITIVE both
		 * false is disallowed by Mars (not by PKCS#11).
		 */
		DBG(NULL, DCHATTY, "mca_create_flags: fail: attempt to create "
		    "flags with sensitive and extractable false");
		return (CRYPTO_TEMPLATE_INCONSISTENT);
	}

	bool = 0;
	(void) cpg_attr_lookup_uint8(template, CPGA_TOKEN, &bool);
	flags |= bool ? KEYFLAG_PERSIST : 0;
	DBG(NULL, DCHATTY, "mca_createkey_flags: token=%d flags=0x%x",
	    bool, flags);

	/*
	 * CPGA_PRIVATE default to TRUE if the key is a token key, default
	 * to FALSE otherwise.
	 */
	bool = !!(flags & KEYFLAG_PERSIST); /* Set to default */
	rv = cpg_attr_lookup_uint8(template, CPGA_PRIVATE, &bool);
	if ((rv == CRYPTO_ATTRIBUTE_TYPE_INVALID) ||
	    (rv == CRYPTO_TEMPLATE_INCONSISTENT)) {
		/* Fluff CPGA_PRIVATE if not present */
		DBG(NULL, DCHATTY, "mca_createkey_flags: fluffing "
		    "CPGA_PRIVATE to %d", bool);
		if (cpg_attr_add_uint8(template, CPGA_PRIVATE, bool,
		    CPG_ATTR_NOSLEEP)) {
			return (CRYPTO_HOST_MEMORY);
		}
	}
	flags |= bool ? KEYFLAG_PRIVATE : 0;
	DBG(NULL, DCHATTY, "mca_createkey_flags: private=%d flags=0x%x",
	    bool, flags);


	if ((flags & KEYFLAG_PERSIST) && !bool) {
		/* public token object is not supported by Mars */
		DBG(NULL, DCHATTY, "mca_create_flags: fail: attempt to create "
		    "public token object");
		return (CRYPTO_TEMPLATE_INCONSISTENT);
	}

	/*
	 * Most permission flags used to be tested here.  Now we just
	 * do CPGA_MODIFIABLE and set the others to true.  This is
	 * because these other flags are never actually enforced in
	 * the present code, so there is no point spending a lot of
	 * cycles setting them in *pflags.
	 */

	(void) cpg_attr_lookup_uint8(template, CPGA_MODIFIABLE, &bool);
	flags |= bool ? 0 : KEYFLAG_READONLY;

	flags |= KEYFLAG_ENCRYPT | KEYFLAG_DECRYPT | KEYFLAG_SIGN |
	    KEYFLAG_VERIFY | KEYFLAG_DERIVE | KEYFLAG_WRAP | KEYFLAG_UNWRAP |
	    KEYFLAG_SIGNR | KEYFLAG_VERIFYR;

	*pflags = flags;
	return (CRYPTO_SUCCESS);
}

/*
 * This function creates a key on the HW. The key should be a sensitive and/or
 * token key. Note: mca_createkey takes over 'template' and therefore it is
 * responsible for freeing it in the error exit.
 */
int
mca_createkey(mca_t *mca, mca_session_t *session, cpg_attr_t *template,
    uint32_t *id, crypto_req_handle_t *cfreq, mca_keystore_t *mks)
{
	mca_request_t	*reqp;
	uint32_t	flags = 0;
	int		rv;
	caddr_t		kaddr;
	uint32_t	residlen;
	int		keytype;

	if ((rv = cpgattr2keytype(template, &keytype)) != CRYPTO_SUCCESS) {
		cpg_attr_free(template);
		return (rv);
	}

	/* check and get flags */
	rv = mca_createkey_flags(template, &flags);
	if (rv != CRYPTO_SUCCESS) {
		cpg_attr_free(template);
		return (rv);
	}

	if (mks == NULL) {
		DBG(mca, DWARN, "device has no keystore?");
		cpg_attr_free(template);
		return (CRYPTO_GENERAL_ERROR);
	}

	if ((reqp = mca_getreq(&mca->mca_ring_om)) == NULL) {
		cpg_attr_free(template);
		return (CRYPTO_BUSY);
	}

	kaddr = reqp->mr_ibuf_kaddr;
	residlen = MAX_KEY_SIZE;
	rv = cpgattr2keyhead(template, keytype, kaddr, &residlen);
	if (rv != CRYPTO_SUCCESS) {
		rv = (rv == CRYPTO_BUFFER_TOO_SMALL) ?
		    CRYPTO_KEY_SIZE_RANGE : rv;
		goto errorexit;
	}

	if (flags & KEYFLAG_PERSIST) {
		/* note: we do not support public token objects */
		rv = mca_get_session_cred(session, reqp->mr_cred);
		if (rv != CRYPTO_SUCCESS) {
			goto errorexit;
		}

		mca_user_wrlock(session->ms_user);
		reqp->mr_flags = MRF_TASKQ | MRF_KSUPDATE;
	}

	DBG(mca, DKEYSTORE, "mca_createkey(%0xp, %d)", kaddr, residlen);
	DBGCALL(DKEYSTORE, mca_dumphex(kaddr, residlen));

	reqp->mr_byte_stat = -1;
	reqp->mr_job_stat = -1;
	reqp->mr_cf_req = cfreq;
	reqp->mr_key_flags[0] = flags;
	reqp->mr_callback = createkey_done;
	reqp->mr_cmd = CMD_CREATE_KEY;
	reqp->mr_template[0] = template;
	reqp->mr_session = session;
	reqp->mr_dbm_handle = mca_ks_get_handle(mks, mca);


	if (residlen > reqp->mr_ibuf_sz) {
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

	reqp->mr_key_id[0] = 0;
	reqp->mr_key_id[1] = 0;
	reqp->mr_keyidp[0] = id;
	reqp->mr_timeout = OMTIMEOUT;

	if (mca_isfips(mca)) {
		mca_ktkencryptbuf(reqp);
	}

	/*
	 * If the input is chained, the descriptor chain must be adjusted.
	 * This must be called after mca_ktkencryptbuf, which may pad
	 * the input to be multiple of AES blocksz.
	 */
	if (reqp->mr_in_next_paddr != 0) {
		/*EMPTY*/
		MCA_TERMINATE_CHAINS(&reqp->mr_ibuf_chain, reqp->mr_in_len);
	}

	ddi_dma_sync(reqp->mr_ibuf_dmah, 0, reqp->mr_in_len,
	    DDI_DMA_SYNC_FORDEV);
	/* sync key dma for input/output chains */
	ddi_dma_sync(reqp->mr_key_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	if ((rv = mca_start(reqp)) != CRYPTO_QUEUED) {
		goto errorexit;
	}

	return (rv);

errorexit:
	if (reqp->mr_flags & MRF_KSUPDATE) {
		mca_user_unlock(session->ms_user);
	}
	MCA_RESTORE_CHAIN(&reqp->mr_ibuf_chain);
	mca_freereq(reqp);
	cpg_attr_free(template);
	return (rv);
}

static void
createkey_done(mca_request_t *reqp)
{
	mca_t		*mca = reqp->mr_mca;
	cpg_attr_t	*attr = reqp->mr_template[0];
	mca_key_t	*mkey = NULL;
	int		rv;
	int		residlen;
	mca_key_head_t	*keyhead;
	uint16_t	keyflags;

	DBG(mca, DKEYSTORE, "createkey_done called");

	MCA_RESTORE_CHAIN(&reqp->mr_ibuf_chain);

	if (reqp->mr_errno != 0) {
		DBG(mca, DWARN, "key create fail, error %d", reqp->mr_errno);
		rv = reqp->mr_errno;
		cpg_attr_free(attr);
		attr = NULL;
		goto exit;
	}

	ddi_dma_sync(reqp->mr_obuf_dmah, 0, reqp->mr_resultlen,
	    DDI_DMA_SYNC_FORKERNEL);
	residlen = reqp->mr_resultlen;

	keyhead = (mca_key_head_t *)reqp->mr_obuf_kaddr;
	keyflags = reqp->mr_key_flags[0];

	rv = mca_parse_key(attr, keyhead, residlen, keyflags, &mkey);
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DCHATTY, "createkey_done: mca_parse_key failed "
		    "with 0x%x", rv);
		rv = CRYPTO_FAILED;
		cpg_attr_free(attr);
		attr = NULL;
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
			attr = NULL;
			goto exit;
		}
	}

	/*
	 * Create the key for the session. The key become visible and the
	 * key refcnt is incremented. (refcnt should be 2 for the token key,
	 * and 1 for the session key)
	 * Note: Session refcnt is decremented by mca_add_key
	 */
	rv = mca_add_key(reqp->mr_session, mkey, reqp->mr_keyidp[0]);
	if (rv != CRYPTO_SUCCESS) {
		if (keyflags & KEYFLAG_PERSIST) {
			mca_unregister_key(mkey);
		} else {
			mca_key_free(mkey);
		}
	}

exit:
	if (reqp->mr_flags & MRF_KSUPDATE) {
		mca_user_unlock(reqp->mr_session->ms_user);
	}

	/* free mca_key/template on the error exit */
	if (rv != CRYPTO_SUCCESS) {
		mca_session_releaseref(reqp->mr_session, UNLOCKED);
	}


	crypto_op_notification(reqp->mr_cf_req, rv);
	mca_freereq(reqp);
}

static int
mca_attr_ro8(cpg_attr_t *target, cpg_attr_t *template, uint32_t attrname)
{
	uint8_t		old, new;
	int		rv;

	if (cpg_attr_lookup_uint8(template, attrname, &new)) {
		return (CRYPTO_SUCCESS);
	}

	rv = cpg_attr_lookup_uint8(target, attrname, &old);
	if (rv != CRYPTO_SUCCESS) {
		return (rv);
	}

	if (old != new) {
		switch (attrname) {
		case CPGA_SENSITIVE:
			if (!new) {
				return (CRYPTO_ATTRIBUTE_READ_ONLY);
			}
			break;
		case CPGA_EXTRACTABLE:
			if (new) {
				return (CRYPTO_ATTRIBUTE_READ_ONLY);
			}
			break;
		default:
			return (CRYPTO_ATTRIBUTE_READ_ONLY);
		}
	}
	return (CRYPTO_SUCCESS);
}

static int
mca_attr_ro32(cpg_attr_t *target, cpg_attr_t *template, uint32_t attrname)
{
	uint32_t old, new;
	if (cpg_attr_lookup_uint32(template, attrname, &new)) {
		return (CRYPTO_SUCCESS);
	}
	if (cpg_attr_lookup_uint32(target, attrname, &old)) {
		return (CRYPTO_ATTRIBUTE_READ_ONLY);
	}
	if (old != new) {
		return (CRYPTO_ATTRIBUTE_READ_ONLY);
	}
	return (CRYPTO_SUCCESS);
}

/*
 * It appears that in all cases target is a duplicate of the real target.
 * We modify it in place.
 */
int
mca_merge_templates4copy(cpg_attr_t *newattrs, cpg_attr_t *target,
    uint32_t *argflags)
{
	int			rv;
	cpg_attr_walk_state_t	walkstate;
	uint32_t		name;
	uint32_t		flags; /* throw away variable */

	/*
	 * Certain attributes cannot be modified or can be modified
	 * only in limited ways.  Check that this is not violated.
	 * (mca_attr_ro8 knows that CPGA_SENSITIVE and
	 * CPGA_EXTRACTABLE are "one-way".)
	 */
	cpg_attr_walk_init(&walkstate, newattrs);
	while (cpg_attr_walk_more_q(&walkstate)) {
		cpg_attr_walk_get_info(&walkstate, &name, &flags);
		switch (name) {
		case CPGA_SENSITIVE:
		case CPGA_EXTRACTABLE:
		case CPGA_ALWAYS_SENSITIVE:
		case CPGA_NEVER_EXTRACTABLE:
		case CPGA_LOCAL:
		case CPGA_TRUSTED:
			rv = mca_attr_ro8(target, newattrs, name);
			if (rv) {
				return (rv);
			}
			break;
		case CPGA_CLASS:
		case CPGA_KEY_TYPE:
		case CPGA_CERTIFICATE_TYPE:
			rv = mca_attr_ro32(target, newattrs, name);
			if (rv) {
				return (rv);
			}
			break;
		}
		cpg_attr_walk_next(&walkstate);
	}

	rv = cpg_attr_merge(newattrs, target, CPG_ATTR_NOSLEEP);
	if (rv != CRYPTO_SUCCESS) {
		DBG(NULL, DCHATTY, "mca_merge_templates4copy: cpg_attr_merge "
		    "failed with 0x%x", rv);
		return (rv);
	}

	/*
	 * Set targetflags, and check for some prohibited
	 * combinations.  mca_create_flags can also fluff some fields,
	 * but they have already been fluffed at this point.
	 */
	rv = mca_createkey_flags(target, argflags);

	return (rv);
}

/*
 * The template parameter is the source object.  This function takes
 * ownership of template, and frees it.
 */
int
mca_copykey(mca_t *mca, mca_session_t *session, mca_key_t *mkey,
    cpg_attr_t *template, uint32_t *newkeyid, crypto_req_handle_t *cfreq,
    mca_keystore_t *mks)
{
	cpg_attr_t	*attrp;
	cpg_attr_t	*newattrp = NULL;
	mca_request_t	*reqp = NULL;
	int		rv;
	int		mkeylocked = 0;
	caddr_t		kaddr;
	uint32_t	residlen;
	int		keytype;
	uint32_t	srcflags, dstflags;

	mutex_enter(&mkey->mk_lock);
	mkeylocked = 1;

	attrp = mkey->mk_cpgattr;
	srcflags = mkey->mk_keyflags;

	if ((rv = cpgattr2keytype(attrp, &keytype)) != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "mca_copykey: template incomplete");
		cpg_attr_free(template);
		mutex_exit(&mkey->mk_lock);
		return (rv);
	}
	/*
	 * Create a template with new attributes. (FW treats a template
	 * (description field) as an opaque field, and it does not merge
	 * the src template with the dst template)
	 * Note: cpg_attr_merge(attrp, &template,..) does not work since
	 * attributes in 'template' will be overwritten by the attributes in
	 * 'attrp'. Template duplication is necessary.
	 */
	rv = cpg_attr_alloc_dup(attrp, &newattrp, 0, CPG_ATTR_NOSLEEP);
	if (rv != CRYPTO_SUCCESS) {
		mutex_exit(&mkey->mk_lock);
		cpg_attr_free(template);
		return (rv);
	}

	rv = mca_merge_templates4copy(template, newattrp, &dstflags);
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DCHATTY, "mca_copykey: mca_merge_templates4copy"
		    "failed with 0x%x", rv);
		cpg_attr_free(template);
		template = NULL;
		goto exit;
	}
	cpg_attr_free(template);

	if ((reqp = mca_getreq(&mca->mca_ring_om)) == NULL) {
		rv = CRYPTO_BUSY;
		goto exit;
	}

	/* src key */
	kaddr = (caddr_t)(mkey + 1);
	bcopy(kaddr, reqp->mr_key_kaddr, mkey->mk_keyheadsz);
	reqp->mr_key_id[0] = mkey->mk_keyid[0];
	reqp->mr_key_id[1] = mkey->mk_keyid[1];

	mutex_exit(&mkey->mk_lock);
	mkeylocked = 0;

	if (mks == NULL) {
		DBG(mca, DWARN, "device has no keystore?");
		rv = CRYPTO_GENERAL_ERROR;
		goto exit;
	}

	reqp->mr_dbm_handle = mca_ks_get_handle(mks, mca);

	if ((srcflags | dstflags) & KEYFLAG_PERSIST) {
		/* note: we do not support public token objects */
		rv = mca_get_session_cred(session, reqp->mr_cred);
		if (rv != CRYPTO_SUCCESS) {
			goto exit;
		}

		if (dstflags & KEYFLAG_PERSIST) {
			mca_user_wrlock(session->ms_user);
			reqp->mr_flags = MRF_TASKQ | MRF_KSUPDATE;
		} else if (srcflags & KEYFLAG_PERSIST) {
			mca_user_rdlock(session->ms_user);
			reqp->mr_flags = MRF_KSREAD;
		}
	}

	/* dst key */
	kaddr = reqp->mr_ibuf_kaddr;
	residlen = MAX_KEY_SIZE;
	rv = cpgattr2keyhead(newattrp, keytype, reqp->mr_ibuf_kaddr, &residlen);
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "mca_copykey: cpgattr2keyhead failed"
		    "with 0x%x", rv);
		rv = (rv == CRYPTO_BUFFER_TOO_SMALL) ?
		    CRYPTO_KEY_SIZE_RANGE : rv;
		goto exit;
	}

	DBG(mca, DKEYSTORE, "mca_copykey newattr(%0xp, %d)", kaddr, residlen);
	DBGCALL(DKEYSTORE, mca_dumphex(kaddr, residlen));

	reqp->mr_cmd = CMD_COPY_KEY;
	reqp->mr_byte_stat = -1;
	reqp->mr_job_stat = -1;
	reqp->mr_cf_req = cfreq;
	reqp->mr_key_flags[0] = dstflags;
	reqp->mr_callback = copykey_done;
	reqp->mr_session = session;
	reqp->mr_keyidp[0] = newkeyid;
	reqp->mr_template[0] = newattrp;
	reqp->mr_timeout = OMTIMEOUT;

	if (residlen > reqp->mr_ibuf_sz) {
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

	if (mca_isfips(mca)) {
		mca_ktkencryptbuf(reqp);
		reqp->mr_key_len = PADAES(reqp->mr_key_len);
		mca_aes_cbc_encrypt(&mca_ktk, reqp->mr_short_key,
		    (uchar_t *)reqp->mr_key_kaddr,
		    (uchar_t *)reqp->mr_key_kaddr, reqp->mr_key_len);
	}

	/*
	 * If the input is chained, the descriptor chain must be adjusted.
	 * This must be called after mca_ktkencryptbuf, which may pad
	 * the input to be multiple of AES blocksz.
	 */
	if (reqp->mr_in_next_paddr != 0) {
		/*EMPTY*/
		MCA_TERMINATE_CHAINS(&reqp->mr_ibuf_chain, reqp->mr_in_len);
	}

	ddi_dma_sync(reqp->mr_ibuf_dmah, 0, reqp->mr_in_len,
	    DDI_DMA_SYNC_FORDEV);
	/* sync key dma for input/output chains */
	ddi_dma_sync(reqp->mr_key_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	if ((rv = mca_start(reqp)) != CRYPTO_QUEUED) {
		goto exit;
	}

	return (rv);

exit:
	if (reqp) {
		if (reqp->mr_flags & (MRF_KSUPDATE | MRF_KSREAD)) {
			mca_user_unlock(session->ms_user);
		}
		mca_freereq(reqp);
	}
	if (newattrp) {
		cpg_attr_free(newattrp);
	}
	if (mkeylocked) {
		mutex_exit(&mkey->mk_lock);
	}
	return (rv);
}

static void
copykey_done(mca_request_t *reqp)
{
	mca_t		*mca = reqp->mr_mca;
	cpg_attr_t	*newattr;
	mca_key_t	*mkey;
	int		rv;
	int		residlen;
	mca_key_head_t	*keyhead;
	uint16_t	keyflags;

	newattr = reqp->mr_template[0];


	if (reqp->mr_errno != 0) {
		DBG(mca, DWARN, "key dup fail, error %d", reqp->mr_errno);
		rv = reqp->mr_errno;
		goto exit;
	}

	ddi_dma_sync(reqp->mr_obuf_dmah, 0, reqp->mr_resultlen,
	    DDI_DMA_SYNC_FORKERNEL);
	residlen = reqp->mr_resultlen;

	keyhead = (mca_key_head_t *)reqp->mr_obuf_kaddr;
	keyflags = reqp->mr_key_flags[0];

	rv = mca_parse_key(newattr, keyhead, residlen, keyflags, &mkey);
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DCHATTY, "createkey_done: mca_parse_key failed "
		    "with 0x%x", rv);
		rv = CRYPTO_FAILED;
		goto exit;
	}
	newattr = NULL;

	/*
	 * Add the key to the UKT. The key is marked INVALID, and this
	 * thread should hold the refcnt.
	 */
	if (keyflags & KEYFLAG_PERSIST) {
		rv = mca_register_key(reqp->mr_session->ms_user, mkey);
		if (rv != CRYPTO_SUCCESS) {
			mca_key_free(mkey);
			goto exit;
		}
	}

	/*
	 * Create the key for the session. The key become visible and the
	 * key refcnt is incremented. (refcnt should be 2 for the token key,
	 * and 1 for the session key)
	 * Note: Session refcnt is decremented by mca_add_key
	 */
	rv = mca_add_key(reqp->mr_session, mkey, reqp->mr_keyidp[0]);
	if (rv != CRYPTO_SUCCESS) {
		if (keyflags & KEYFLAG_PERSIST) {
			mca_unregister_key(mkey);
		} else {
			mca_key_free(mkey);
		}
	}

exit:
	/* free mca_key/template on the error exit */
	if (rv != CRYPTO_SUCCESS) {
		mca_session_releaseref(reqp->mr_session, UNLOCKED);
	}

	if (reqp->mr_flags & (MRF_KSUPDATE | MRF_KSREAD)) {
		mca_user_unlock(reqp->mr_session->ms_user);
	}

	if (newattr != NULL) {
		cpg_attr_free(newattr);
	}

	crypto_op_notification(reqp->mr_cf_req, rv);
	mca_freereq(reqp);
}

int
mca_merge_templates(cpg_attr_t *newattrs, cpg_attr_t *target,
    uint32_t *argflags)
{
	int			rv;
	cpg_attr_walk_state_t	walkstate;
	uint32_t		name;
	uint32_t		flags;

	/*
	 * Certain attributes cannot be modified or can be modified
	 * only in limited ways.  Check that this is not violated.
	 * (mca_attr_ro8 knows that CPGA_SENSITIVE and
	 * CPGA_EXTRACTABLE are "one-way".)
	 */
	cpg_attr_walk_init(&walkstate, newattrs);
	while (cpg_attr_walk_more_q(&walkstate)) {
		cpg_attr_walk_get_info(&walkstate, &name, &flags);
		switch (name) {
		case CPGA_TOKEN:
		case CPGA_PRIVATE:
		case CPGA_MODIFIABLE:
		case CPGA_SENSITIVE:
		case CPGA_EXTRACTABLE:
		case CPGA_ALWAYS_SENSITIVE:
		case CPGA_NEVER_EXTRACTABLE:
		case CPGA_LOCAL:
		case CPGA_TRUSTED:
			rv = mca_attr_ro8(target, newattrs, name);
			if (rv) {
				return (rv);
			}
			break;
		case CPGA_CLASS:
		case CPGA_KEY_TYPE:
		case CPGA_CERTIFICATE_TYPE:
			rv = mca_attr_ro32(target, newattrs, name);
			if (rv) {
				return (rv);
			}
			break;
		}
		cpg_attr_walk_next(&walkstate);
	}

	rv = cpg_attr_merge(newattrs, target, 0);
	if (rv != CRYPTO_SUCCESS) {
		DBG(NULL, DCHATTY, "mca_merge_templates: cpg_attr_merge "
		    "failed with 0x%x", rv);
		return (rv);
	}

	rv = mca_createkey_flags(target, argflags);

	return (rv);
}


/*
 * This function should be called on a token key only
 */
int
mca_modifykey(mca_t *mca, mca_session_t *session, mca_key_t *mkey,
    cpg_attr_t *attr, crypto_req_handle_t *cfreq)
{
	int		rv;
	mca_keystore_t	*mks;
	mca_request_t	*reqp;
	uint32_t	buflen;
	int		keytype;
	uint32_t	keyflags;

	/*
	 * Note: We only should be called to process persistent objects.
	 * In which case, the device must be initialized.
	 */

	if ((mks = session->ms_user->mu_keystore) == NULL) {
		DBG(mca, DWARN, "device has no keystore?");
		return (CRYPTO_GENERAL_ERROR);
	}

	if ((rv = cpgattr2keytype(attr, &keytype)) != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "mca_modifykey: Invalid key template");
		return (rv);
	}
	rv = mca_createkey_flags(attr, &keyflags);
	if (rv != CRYPTO_SUCCESS) {
		return (rv);
	}

	if ((reqp = mca_getreq(&mca->mca_ring_om)) == NULL) {
		DBG(mca, DWARN, "mca_modifykey: mca_getreq failed");
		return (CRYPTO_BUSY);
	}

	/*
	 * since we only support token key modification in mca,
	 * keyid is the only field needed for the original key
	 * Note: mk_keyid field is immutable, so no need to lock
	 */
	reqp->mr_key_id[0] = mkey->mk_keyid[0];
	reqp->mr_key_id[1] = mkey->mk_keyid[1];

	rv = mca_get_session_cred(session, reqp->mr_cred);
	if (rv != CRYPTO_SUCCESS) {
		goto exit;
	}

	mca_user_wrlock(session->ms_user);
	reqp->mr_flags = MRF_TASKQ | MRF_KSUPDATE;
	reqp->mr_dbm_handle = mca_ks_get_handle(mks, mca);

	/*
	 * ibuf contains the template only in mca_key_head format.
	 */
	buflen = MAX_KEY_SIZE;
	rv = cpgattr2keyhead(attr, keytype, reqp->mr_ibuf_kaddr, &buflen);
	if (rv != CRYPTO_SUCCESS) {
		rv = (rv == CRYPTO_BUFFER_TOO_SMALL) ?
		    CRYPTO_KEY_SIZE_RANGE : rv;
		goto exit;
	}

	reqp->mr_cf_req = cfreq;
	reqp->mr_byte_stat = -1;
	reqp->mr_job_stat = -1;
	if (buflen > reqp->mr_ibuf_sz) {
		MCA_TERMINATE_CHAINS(&reqp->mr_ibuf_chain, buflen);
		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_next_paddr = reqp->mr_ibuf_next_paddr;
		reqp->mr_in_len = buflen;
		reqp->mr_in_first_len = reqp->mr_ibuf_sz;
	} else {
		reqp->mr_in_paddr = reqp->mr_ibuf_paddr;
		reqp->mr_in_next_paddr = 0;
		reqp->mr_in_len = buflen;
		reqp->mr_in_first_len = buflen;
	}
	reqp->mr_out_paddr = 0;
	reqp->mr_out_next_paddr = 0;
	reqp->mr_out_len = 0;
	reqp->mr_out_first_len = 0;
	reqp->mr_key_flags[0] = keyflags;
	reqp->mr_callback = modifykey_done;
	reqp->mr_cmd = CMD_MODIFY_KEY;
	reqp->mr_mkey = mkey;
	reqp->mr_template[0] = attr;
	reqp->mr_timeout = OMTIMEOUT;
	reqp->mr_session = session;

	ddi_dma_sync(reqp->mr_ibuf_dmah, 0, reqp->mr_in_len,
	    DDI_DMA_SYNC_FORDEV);
	/* sync key dma for input/output chains */
	ddi_dma_sync(reqp->mr_key_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	rv = mca_start(reqp);

exit:
	if (rv == CRYPTO_QUEUED) {
		mca_session_releaseref(session, UNLOCKED);
	} else {
		if (reqp->mr_flags & MRF_KSUPDATE) {
			mca_user_unlock(session->ms_user);
		}
		mca_freereq(reqp);
	}
	return (rv);
}

static void
modifykey_done(mca_request_t *reqp)
{
	mca_t		*mca = reqp->mr_mca;
	mca_key_t	*mkey = reqp->mr_mkey;
	cpg_attr_t	*oattr;

	if (reqp->mr_errno != 0) {
		DBG(mca, DWARN, "key modify fail, error %d", reqp->mr_errno);
		if (reqp->mr_flags & MRF_KSUPDATE) {
			mca_keystore_unlock(
			    reqp->mr_session->ms_user->mu_keystore);
		}
		crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
		mca_freereq(reqp);
		return;
	}


	if (reqp->mr_flags & MRF_KSUPDATE) {
		mca_user_unlock(reqp->mr_session->ms_user);
		reqp->mr_flags &= ~MRF_KSUPDATE;
	}

	mutex_enter(&mkey->mk_lock);

	oattr = mkey->mk_cpgattr;
	mkey->mk_cpgattr = reqp->mr_template[0];
	mkey->mk_keyflags = reqp->mr_key_flags[0] | KEYFLAG_VALID;

	mutex_exit(&mkey->mk_lock);

	cpg_attr_free(oattr);

	mca_key_releaseref(mkey, UNLOCKED);

	crypto_op_notification(reqp->mr_cf_req, CRYPTO_SUCCESS);
	mca_freereq(reqp);
}
