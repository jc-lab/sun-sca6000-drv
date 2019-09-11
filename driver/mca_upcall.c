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

#pragma ident	"@(#)mca_upcall.c	1.48	08/06/04 SMI"

/*
 * Mars - pure cryptographic acceleration + secure keystore
 */

#ifdef LINUX
#include <linux/types.h>
#include "sol2lin.h"
#include "mca.h"
#include "mcactl.h"
#include "mca_hw.h"
#else
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/mca.h>
#include <sys/mcactl.h>	/* needed for IOCTL values */
#include <sys/mca_hw.h>
#include <sys/byteorder.h>
#endif

/*
 * Keystore implementation -- this is just the file management logic
 * coordinated with mcactl and keystore I/O service.
 */


/* engineering tunable for keystore I/O service wait timer */
int			mca_uctime = 90;

#define	MCAUCATTACHED	0x1	/* daemon is standing by */
#define	MCAUCBUSY	0x2	/* operation in progress */
#define	MCAUCPOST	0x4	/* operation posted for mcactl */
#define	MCAUCMASKERR	0x8	/* mask error reporting */
#define	MCAUCDBM	0x10	/* this channel is DBM related */
#define	MCAUCFRI	0x20	/* this channel processing FRI msg */
#define	MCAUCWAIT	0x40	/* waiting for channel to unbusy */

#define	MCA_CTL_CHANNEL	"<control channel>"


/* per channel upcall info */
typedef struct mca_ucinfo {
	kmutex_t	mca_ucmx;
	kcondvar_t	mca_uccv;	/* Signals upcall complete */
	kcondvar_t	mca_ucbcv;	/* Signals upcall not busy */
	kcondvar_t	mca_dbmcv;	/* Signals DBM complete */
	int		mca_ucflags;
	void		*mca_ucarg;
	int		mca_ucarglen;
	mca_t		*mca_ucmca;
	char		mca_ucbuff[sizeof (dbm_header_t)];
	char		mca_ucksname[OBJSTORE_NAME_MAX];
	mca_channel_t	mca_ucchan;
} mca_ucinfo_t;


/* Global upcall data */
static mca_table_t	mca_uctable;
static kmutex_t		mca_uctable_lock;
static timeout_id_t	mca_uctid;	/* KS I/O error report timer */
static int		mca_ucflags = 0;

/* local prototypes */
static void mca_upcall_timeout(void *);
static void mca_upcall_error(void);

static void dbm_responsedone(mca_request_t *);

static mca_ucinfo_t *
mca_upcall_element_alloc(mca_channel_t chan)
{
	mca_ucinfo_t	*info;

#ifdef LINUX
	info = (mca_ucinfo_t *)kmem_zalloc(sizeof (*info), GFP_ATOMIC);
#else
	info = (mca_ucinfo_t *)kmem_zalloc(sizeof (*info), KM_SLEEP);
#endif /* LINUX */
	if (info == NULL) {
		return (NULL);
	}

	mutex_init(&info->mca_ucmx, NULL, MUTEX_DRIVER, NULL);
	cv_init(&info->mca_uccv, NULL, CV_DRIVER, NULL);
	cv_init(&info->mca_ucbcv, NULL, CV_DRIVER, NULL);
	cv_init(&info->mca_dbmcv, NULL, CV_DRIVER, NULL);
	info->mca_ucchan = chan;

	return (info);
}


static void
mca_upcall_element_free(mca_ucinfo_t *info)
{
	mutex_destroy(&info->mca_ucmx);
	cv_destroy(&info->mca_uccv);
	cv_destroy(&info->mca_ucbcv);
	cv_destroy(&info->mca_dbmcv);
	kmem_free(info, sizeof (*info));
}



void
mca_upcall_init(void)
{
	mutex_init(&mca_uctable_lock, NULL, MUTEX_DRIVER, NULL);
	mca_table_init(&mca_uctable, sizeof (mca_ucinfo_t), 1,
		1, NULL);
	mca_uctid = 0;
	mca_ucflags = 0;
}

void
mca_upcall_fini(void)
{
	mca_ucinfo_t	*info;

	int		id = -1;
	int		rv;

	if (mca_uctid) {
		untimeout(mca_uctid);
	}

	while (mca_table_next_slot(&mca_uctable, &id) != DDI_FAILURE) {
		rv = mca_table_lookup(&mca_uctable, id, (void **)&info);
		if (rv != DDI_SUCCESS) {
			continue;
		}
		mca_upcall_element_free(info);
	}

	mca_table_destroy(&mca_uctable);
	mutex_destroy(&mca_uctable_lock);
}

/*
 * Called by mcactl when the daemon first attaches.  Probably this needs to
 * also set up to get any keystore data which are waiting.
 */
int
mca_upcall_attach(mca_channel_t channel)
{
	mca_ucinfo_t	*info = NULL;

	DBG(NULL, DDBM, "mca_upcall_attach for channel %d\n", channel);

	mutex_enter(&mca_uctable_lock);

	/* see if we've already attached */
	if (mca_table_lookup(&mca_uctable, channel, (void **)&info) ==
		DDI_SUCCESS) {
		return (EALREADY);
	}

	if (!(info = mca_upcall_element_alloc(channel))) {
		return (ENOMEM);
	}

	/* associate this upcall info with the mcactl minor number */
	if (mca_table_set_slot(&mca_uctable, channel, (void *)info, KM_SLEEP)
		!= DDI_SUCCESS) {
		return (ENOMEM);
	}

	info->mca_ucflags |= MCAUCATTACHED;

	mutex_exit(&mca_uctable_lock);

	return (0);
}

/*
 * mca_upcall_lookup()
 *
 * locate the file descriptor specific upcall info via the minor number.
 *
 * Note: the upcall table mutex must be held by the caller.
 */
mca_ucinfo_t *
mca_upcall_lookup(mca_channel_t channel)
{
	mca_ucinfo_t	*info = NULL;

	ASSERT(mutex_owned(&mca_uctable_lock));

	if (mca_table_lookup(&mca_uctable, channel, (void **)&info) !=
		DDI_SUCCESS) {
		DBG(NULL, DWARN, "mca_upcall_lookup failed for %x", channel);
	}

	return (info);
}


void
mca_close_channel(mca_channel_t channel)
{
	int		rv;
	int		inst = -1;
	mca_t		*mca;
	char		*obuf;
	int		obuflen;
	dbm_preamble_t	msg;
	void		*ctx;

	/* build DB_CLOSE message */
	bzero((void *)&msg, sizeof (msg));

	msg.h.type = htonl(DB_GOODBYE);

	/* set up idc header */
	mca_update_idc_hdr(&msg.idc, channel,
	    mca_get_domain());

	while (mca_get_next_instance(&inst) == 0) {

		if ((mca = mca_hold_instance(inst)) == NULL) {
			DBG(NULL, DWARN, "mca_hold_instance[%d] "
			    "failed", inst);
			continue;
		}

		/* if card in failsafe - don't send anything */
		if (mca_fm_isfailsafe(mca)) {
			DBG(mca, DDBM,
			    "Device is in failsafe state");
			mca_rele_instance(mca);
			continue;
		}

		/* send message to the card */
		rv = mca_dbm_response(mca, (void *)&msg,
		    sizeof (msg), &obuf, &obuflen, &ctx,
		    (mca_app_handle_t)channel);

		if (rv == CRYPTO_SUCCESS) {
			mca_dbm_freereq(ctx);
		}
		mca_rele_instance(mca);
	}
}


/*
 * Called by mcactl when the Keystore I/O service thread closes its file handle.
 */
void
mca_upcall_detach(mca_channel_t channel)
{
	mca_ucinfo_t	*info;
	int		busy;

	DBG(NULL, DDBM, "mca_upcall_detach for channel %d\n", channel);

	mutex_enter(&mca_uctable_lock);

	/* get the fd specific upcall info */
	if (!(info = mca_upcall_lookup(channel))) {
		mutex_exit(&mca_uctable_lock);
		return;
	}

	/* mark as unattached to prevent scakiod bound messages */
	info->mca_ucflags &= ~MCAUCATTACHED;

	mutex_exit(&mca_uctable_lock);

	/* notify the firmware that the chanel has closed */
	mca_close_channel(channel);

	mutex_enter(&mca_uctable_lock);
	mutex_enter(&info->mca_ucmx);

	if (info->mca_ucflags & MCAUCDBM) {
		DBG(NULL, DWARN, "Keystore I/O service down for %s",
		    info->mca_ucksname[0] ? info->mca_ucksname :
		    MCA_CTL_CHANNEL);
	}


	/* check if upcall facility is busy */
	busy = info->mca_ucflags & MCAUCWAIT;

	mutex_exit(&info->mca_ucmx);

	/*
	 * don't remove the slot/memory if we're busy.
	 * driver detach will remove the slot and free
	 * the associated memory.
	 */
	if (!busy) {
		mca_table_remove_slot(&mca_uctable, channel);
		mca_upcall_element_free(info);
	}

	/*
	 * XXX only report keystore service down when no open
	 * file descriptors remain.
	 */
	if (mca_uctable.t_usedslots == 0) {
		DBG(NULL, DWARN, "All keystore I/O services down");
	}

	mutex_exit(&mca_uctable_lock);

}


static int
mca_upcall_hold_info(mca_ucinfo_t *info)
{
	ASSERT(mutex_owned(&info->mca_ucmx));

	if ((info->mca_ucflags & MCAUCATTACHED) == 0) {
		mca_upcall_error();
		return (DBM_EPIPE);
	}

	info->mca_ucflags |= MCAUCWAIT;

	/* Make sure an upcall is not already in progress (busy) */
	while (info->mca_ucflags & MCAUCBUSY) {
		/*
		 * Wait for current upcall to complete (not busy)
		 * Times out in one minute.
		 */
		if (cv_timedwait(&info->mca_ucbcv, &info->mca_ucmx,
		    ddi_get_lbolt() + drv_usectohz(60 * SECOND)) < 0) {
			DBG(NULL, DWARN, "mca_upcall_hold: timed out");
			mca_upcall_error();
			info->mca_ucflags &= ~MCAUCWAIT;
			return (DBM_EPIPE);
		}
	}
	/* clear wait state */
	info->mca_ucflags &= ~MCAUCWAIT;
	/* Flag upcall in progress (busy) */
	info->mca_ucflags |= MCAUCBUSY;

	return (0);
}

/*
 * Called by driver to setup for an upcall.  This pretty much just acquires
 * exclusive ownership of the upcall facility.
 */
int
mca_upcall_hold(mca_channel_t channel)
{
	int		rv;
	mca_ucinfo_t	*info;

	mutex_enter(&mca_uctable_lock);
	if (!(info = mca_upcall_lookup(channel))) {
		mutex_exit(&mca_uctable_lock);
		mca_upcall_error();
		return (DBM_EPIPE);
	}

	mutex_enter(&info->mca_ucmx);
	mutex_exit(&mca_uctable_lock);

	rv = mca_upcall_hold_info(info);
	mutex_exit(&info->mca_ucmx);

	return (rv);
}

/* ARGSUSED */
static void
mca_upcall_timeout(void *arg)
{
	int	slots;
	mutex_enter(&mca_uctable_lock);
	mca_uctid = 0;
	slots = mca_uctable.t_usedslots;
	mutex_exit(&mca_uctable_lock);

	/* no slots == no keystore I/O service */
	if (slots == 0) {
		mca_upcall_error();
	}
}

/*
 * Called by driver to check if the keystore I/O service is down
 */
int
mca_upcall_check(void)
{
	int	count;

	mutex_enter(&mca_uctable_lock);
	count = mca_uctable.t_usedslots;
	if ((mca_uctid == 0) && (count == 0)) {
		mca_uctid = timeout(mca_upcall_timeout,
		    NULL, drv_usectohz(mca_uctime * SECOND));
	}
	mutex_exit(&mca_uctable_lock);

	return (count != 0);
}


/*
 * mca_upcall_error()
 *
 * upcall error reporting - used to inform user that no
 * keystore service is present.
 *
 * XXX - we may want to o/p info about which keystore service
 * is down.
 *
 * Note: do not call holding the upcall table mutex
 */

static void
mca_upcall_error(void)
{
	mutex_enter(&mca_uctable_lock);
	if ((mca_uctid == 0) && !(mca_ucflags & MCAUCMASKERR)) {
		/* report error and then disable future reporting */
		mca_ucflags |= MCAUCMASKERR;
		mca_note(NULL, "Keystore I/O service not present");
	}
	mutex_exit(&mca_uctable_lock);
}


void
mca_upcall_release_info(mca_ucinfo_t *info)
{
	info->mca_ucflags &= ~(MCAUCBUSY | MCAUCPOST);

	/*
	 * If this was a FRI initiated command,
	 * notify FW that it can submit more jobs
	 */
	if (info->mca_ucmca && (info->mca_ucflags & MCAUCFRI)) {
		info->mca_ucflags &= ~MCAUCFRI;
		mca_fri_release(info->mca_ucmca);
	}
	/* Signal upcall complete */
	cv_broadcast(&info->mca_ucbcv);
}

void
mca_upcall_release(mca_channel_t channel)
{
	mca_ucinfo_t	*info;

	mutex_enter(&mca_uctable_lock);

	if ((info = mca_upcall_lookup(channel)) == NULL) {
		DBG(NULL, DWARN, "mca_upcall_release info not found (%d)",
			channel);
		mutex_exit(&mca_uctable_lock);
		return;
	}

	mutex_enter(&info->mca_ucmx);
	mutex_exit(&mca_uctable_lock);
	mca_upcall_release_info(info);
	mutex_exit(&info->mca_ucmx);
}


static int
mca_upcall_post_info(mca_t *mca, mca_ucinfo_t *info, void *arg, int len,
    int isfri)
{
	info->mca_ucarg = arg;
	info->mca_ucarglen = len;
	info->mca_ucflags |= MCAUCPOST;

	if (isfri) {
		info->mca_ucflags |= MCAUCFRI;
	}

	info->mca_ucmca = mca;

	/* is the Service thread still there? */
	if ((info->mca_ucflags & MCAUCATTACHED) == 0) {
		info->mca_ucflags &= ~MCAUCPOST;
		return (DBM_EPIPE);
	}

	/* it is, so wake it up */
	cv_broadcast(&info->mca_uccv);
	return (0);
}

/*
 * Called by driver to submit an upcall.
 *
 * Note that if an upcall is submitted before the previous upcall is
 * completed, the previous upcall is overwritten by the new upcall.
 * It's caller's responsibility to make sure that there is no outstanding
 * upcall before calling to this function.
 *
 * mca_upcall_hold should be called prior to this function to avoid
 * overwriting an outstanding upcall.
 */
int
mca_upcall_post(mca_t *mca, mca_channel_t channel, void *arg, int len,
    int isfri)
{
	int 		rv;
	mca_ucinfo_t	*info;

	DBG(mca, DDBM, "mca_upcall_post: posting msg len %d, for chan %d",
	    len, channel);

	mutex_enter(&mca_uctable_lock);
	info = mca_upcall_lookup(channel);

	if (!info) {
		mutex_exit(&mca_uctable_lock);
		return (DBM_EPIPE);
	}

	mutex_enter(&info->mca_ucmx);
	mutex_exit(&mca_uctable_lock);

	rv = mca_upcall_post_info(mca, info, arg, len, isfri);

	mutex_exit(&info->mca_ucmx);
	DBG(mca, DDBM, "mca_upcall_post: posted msg len %d, for chan %d",
	    len, channel);

	return (rv);
}

/*
 * Called by mcactl IOCTL thread to indicate that it is standing by to
 * receive an upcall command from mca proper.  Returns zero on success,
 * or EINTR if a signal is received.  (Thereby allowing KS I/O to terminate
 * gracefully on a signal without blocking forever here.)
 */
int
mca_upcall_service(mca_channel_t channel, void **arg, int *buflen)
{
	mca_ucinfo_t	*info;

	mutex_enter(&mca_uctable_lock);
	if (!(info = mca_upcall_lookup(channel))) {
		mutex_exit(&mca_uctable_lock);
		DBG(NULL, DWARN, "mca_upcall_service channel %d not found",
		    channel);
		return (EINVAL);
	}

	mutex_enter(&info->mca_ucmx);
	mutex_exit(&mca_uctable_lock);

	while ((info->mca_ucflags & MCAUCPOST) == 0) {
		if (cv_wait_sig(&info->mca_uccv, &info->mca_ucmx) == 0) {
			mutex_exit(&info->mca_ucmx);
			return (EINTR);
		}
	}

	DBG(NULL, DDBM, "mca_upcall_service recv'd msg lsn %d\n",
	    info->mca_ucarglen);

	/* okay, we have a pending file command, so service it */
	*arg = info->mca_ucarg;
	*buflen = info->mca_ucarglen;
	mutex_exit(&info->mca_ucmx);

	return (0);
}


/*
 * send the reuqest from mod down to the fw
 */
int
mca_dbm_response(mca_t *mca, void *arg, int arglen, char **out,
    int *outlen, void **ctx, mca_app_handle_t handle)
{
	mca_request_t	*reqp;
	dbm_header_t	*dbm;
	uint32_t	chainlen;
	int rv;
	mca_ucinfo_t	*info;
	int		out_off = MCA_IDC_SZ;

	DBG(mca, DDBM,
	    "mca_dbm_response: sending mesg len %d for channel %d",
	    arglen, handle);


	/* get the upcall info */
#ifdef LINUX
	spin_lock(&mca_uctable_lock.lock);
	if (!(info = mca_upcall_lookup(handle))) {
		spin_unlock(&mca_uctable_lock.lock);
		DBG(NULL, DWARN, "mca_dbm_response: handle %d not found",
		    handle);
		return (EINVAL);
	}

	mutex_enter(&info->mca_ucmx);
	spin_unlock(&mca_uctable_lock.lock);
#else
	mutex_enter(&mca_uctable_lock);
	if (!(info = mca_upcall_lookup(handle))) {
		mutex_exit(&mca_uctable_lock);
		DBG(NULL, DWARN, "mca_dbm_response: handle %d not found",
		    handle);
		return (EINVAL);
	}

	mutex_enter(&info->mca_ucmx);
	mutex_exit(&mca_uctable_lock);
#endif

	/* prepare the request */
	if ((reqp = mca_getreq(&mca->mca_ring_om)) == NULL) {
		mca_error(mca, "unable to allocate request for DBM");
		mutex_exit(&info->mca_ucmx);
		return (ENOSPC);
	}

	/*
	 * reset the highest order byte of the dbm handle to zero before
	 * sending the request down to the firmware
	 */
	dbm = (dbm_header_t *)((caddr_t)arg + MCA_IDC_SZ);
	*((uchar_t *)&(dbm->handle)) = 0;

	/* strip IDC if older firmware */
	if (MCA_FW_IF_COMP_VERSION(mca) <= MCA_IF_VERSION_1_0) {
		arg = (caddr_t)arg + MCA_IDC_SZ;
		arglen -= MCA_IDC_SZ;
		out_off = 0;
	}
	reqp->mr_cmd = CPG_CMD_DBM;
	reqp->mr_callback = dbm_responsedone;
	reqp->mr_app_handle = (mca_app_handle_t)info->mca_ucchan;

	/* Setup the chains for the data in mr_key_addr */
	if ((rv = mca_create_om_chain(&reqp->mr_ibuf_chain, arglen,
	    reqp->mr_key_kaddr, &chainlen)) != 0) {
		mutex_exit(&info->mca_ucmx);
		return (rv);
	}

	/* DBM request expects the input to be the chains */
	reqp->mr_in_paddr = reqp->mr_key_paddr;
	reqp->mr_in_len = chainlen;
	reqp->mr_in_first_len = chainlen;
	reqp->mr_in_next_paddr = 0;
	bcopy(arg, reqp->mr_ibuf_kaddr, arglen);
	ddi_dma_sync(reqp->mr_key_dmah, 0, chainlen, DDI_DMA_SYNC_FORDEV);
	ddi_dma_sync(reqp->mr_ibuf_dmah, 0, arglen, DDI_DMA_SYNC_FORDEV);

	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_out_next_paddr = reqp->mr_obuf_next_paddr;
	reqp->mr_out_len = MAXPACKET;
	reqp->mr_out_first_len = reqp->mr_obuf_sz;


	if (mca_start(reqp) != CRYPTO_QUEUED) {
		mutex_exit(&info->mca_ucmx);
		mca_freereq(reqp);
		DBG(mca, DWARN, "unable to submit DBM request");
		return (EINVAL);
	}

	cv_wait(&info->mca_dbmcv, &info->mca_ucmx);
	mutex_exit(&info->mca_ucmx);

	ddi_dma_sync(reqp->mr_obuf_dmah, 0, reqp->mr_resultlen,
	    DDI_DMA_SYNC_FORKERNEL);

	if (reqp->mr_resultlen == 0) {
		mca_freereq(reqp);
		DBG(mca, DWARN, "Invalid DBM response length");
		return (EIO);
	}
	*out = reqp->mr_obuf_kaddr + out_off;
	/* Use the device instance as a part of the handle. */
	*(uchar_t *)(((uint32_t *)(*out)) + 1) = ddi_get_instance(mca->mca_dip);
	*outlen = reqp->mr_resultlen - out_off;
	*ctx = reqp;

	return (0);
}

void
mca_dbm_freereq(void *ctx)
{
	mca_freereq((mca_request_t *)ctx);
}


static void
dbm_responsedone(mca_request_t *reqp)
{
	mca_ucinfo_t	*info;
	mutex_enter(&mca_uctable_lock);
	if (!(info = mca_upcall_lookup(reqp->mr_app_handle))) {
		mutex_exit(&mca_uctable_lock);
		DBG(NULL, DWARN, "dbm_responsedone: handle %d not found",
		    reqp->mr_app_handle);
		mca_freereq(reqp);
		return;
	}

	DBG(reqp->mr_mca, DDBM,
	    "dbm_responsedone: fw response for channel %d",
	    reqp->mr_app_handle);

	mutex_enter(&info->mca_ucmx);
	mutex_exit(&mca_uctable_lock);
	cv_signal(&info->mca_dbmcv);
	mutex_exit(&info->mca_ucmx);
}

/*
 * mca_update_idc_hdr()
 *
 * fill in the interdomain communication information.
 * for non LDOM environments we still need the channel.
 *
 * the header is in Big Endian format.
 */
void
mca_update_idc_hdr(mca_idc_hdr_t *hdr, mca_channel_t chan, mca_domain_t dom)
{
	/* idc is big endian */
	hdr->chanId = htonl(chan);
	hdr->domId = BE_64(dom);
	hdr->magic = htonl(MCA_IDC_MAGIC);
}

/* for now hardcode to return 0 */
mca_domain_t
mca_get_domain(void)
{
	return (0);
}



/*
 * get the basename from a full keystore name
 * assume format for full name is as follows:
 * 	basename.serial #.{nonce}
 */
static int
get_basename(char *base, char *full)
{
	int	i, len;
	int	dots = 0;

	strcpy(base, full);

	len = strlen(base);

	for (i = len - 1; i >= 0; i--) {
		if (base[i] == '.') {
			dots++;
			if (dots == 2) {
				base[i] = '\0';
				return (0);
			}
		}
	}
	return (-1);
}

/* lookup channel info using base name */
static mca_ucinfo_t *
lookup_upcall_by_name(char *name)
{
	mca_ucinfo_t	*info;
	int		id = -1;
	int		rv;
	char		basename[OBJSTORE_NAME_MAX];


	mutex_enter(&mca_uctable_lock);
	while (mca_table_next_slot(&mca_uctable, &id) != DDI_FAILURE) {
		rv = mca_table_lookup(&mca_uctable, id, (void **)&info);
		if (rv != DDI_SUCCESS) {
			continue;
		}

		mutex_enter(&info->mca_ucmx);
		/* get the basename and match against provided name */
		if (get_basename(basename, info->mca_ucksname) == 0) {
			DBG(NULL, DDBM,
			    "lookup_upcall_by_name(%s vs. %s)",
			    basename, name);
			if (strcmp(name, basename) == 0) {
				mutex_exit(&mca_uctable_lock);
				return (info);
			}
		}
		mutex_exit(&info->mca_ucmx);
	}
	mutex_exit(&mca_uctable_lock);
	return (NULL);
}

/* lookup channel using full name */
mca_channel_t
mca_upcall_lookup_channel(char *name)
{
	mca_channel_t	chan = -1;
	mca_ucinfo_t 	*info;
	char		basename[OBJSTORE_NAME_MAX];

	if (get_basename(basename, name) == 0) {
		if ((info = lookup_upcall_by_name(basename)) != NULL) {
			chan = info->mca_ucchan;
			/* lookup_upcall_by_name acquires upcall mutex */
			mutex_exit(&info->mca_ucmx);
		}
	}
	return (chan);
}

mca_channel_t
mca_upcall_lookup_control_channel(void)
{
	mca_ucinfo_t	*info;
	int		id = -1;
	int		rv;
	mca_channel_t	chan = -1;

	mutex_enter(&mca_uctable_lock);
	while (mca_table_next_slot(&mca_uctable, &id) != DDI_FAILURE) {
		rv = mca_table_lookup(&mca_uctable, id, (void **)&info);
		if (rv != DDI_SUCCESS) {
			continue;
		}

		mutex_enter(&info->mca_ucmx);
		if (info->mca_ucksname[0] == '\0') {
			chan = info->mca_ucchan;
			mutex_exit(&info->mca_ucmx);
			break;
		}
		mutex_exit(&info->mca_ucmx);
	}
	mutex_exit(&mca_uctable_lock);
	return (chan);
}

/*
 * mca_upcall_dbm_register()
 *
 * mark the channel as a DBM channel.  We need this so we know
 * who to inform about card resets.  That is needed because
 * scakiod will need to let the card know about all of the
 * keystores after a reset.
 */
int
mca_upcall_dbm_register(mca_channel_t chan, char *name)
{
	mca_ucinfo_t	*info;

	mutex_enter(&mca_uctable_lock);
	if (!(info = mca_upcall_lookup(chan))) {
		mutex_exit(&mca_uctable_lock);
		DBG(NULL, DWARN, "mca_upcall_dbm_register channel %d not found",
		    chan);
		return (EINVAL);
	}

	mutex_enter(&info->mca_ucmx);
	mutex_exit(&mca_uctable_lock);

	/* mark as a DBM channel */
	info->mca_ucflags |= MCAUCDBM;

	/* keep the KS name */
	strcpy(info->mca_ucksname, name);

	DBG(NULL, DWARN, "Keystore I/O service up for %s",
	    name[0] ? name : MCA_CTL_CHANNEL);

	mutex_exit(&info->mca_ucmx);

	return (0);
}

void
mca_upcall_send(const void *msg, size_t len, mca_ucinfo_t *info, mca_t *mca)
{
	/* take control of the channel's upcall mech */
	if (mca_upcall_hold_info(info) == 0) {
		/* copy hello into upcall buffer */
		bcopy(msg, (void *)info->mca_ucbuff, len);

		DBG(mca, DDBM, "notifying channel %d", info->mca_ucchan);

		if (mca_upcall_post_info(mca, info, info->mca_ucbuff,
			len, FALSE) != 0) {
			mca_upcall_release_info(info);
		}
	}
}

/*
 * mca_upcall_reset()
 *
 * Notify scakiod that the card has been reset.  This should kick
 * scakiod into notifying the card about all keystores.
 */
void
mca_upcall_reset(mca_t *mca)
{
	mca_ucinfo_t	*info;
	int		id = -1;
	int		rv;
	dbm_header_t	dbm;


	DBG(mca, DDBM, "mca_upcall_reset");

	/* build the hello message */
	bzero((void *)&dbm, sizeof (dbm));

	dbm.type = htonl(DB_HELLO);
	dbm.paramSize = htonl(sizeof (dbm));

	mutex_enter(&mca_uctable_lock);

	while (mca_table_next_slot(&mca_uctable, &id) != DDI_FAILURE) {
		rv = mca_table_lookup(&mca_uctable, id, (void **)&info);
		if (rv != DDI_SUCCESS) {
			continue;
		}

		/* check for DBM related channels */
		if (!info || !(info->mca_ucflags & MCAUCDBM)) {
			continue;
		}


		mutex_enter(&info->mca_ucmx);

		/* release table lock, it is acquired by mca_upcall_hold */
		mutex_exit(&mca_uctable_lock);

		mca_upcall_send((const void *)&dbm, sizeof (dbm), info, mca);

		mutex_exit(&info->mca_ucmx);

		mutex_enter(&mca_uctable_lock);
	}
	mutex_exit(&mca_uctable_lock);
}

/*
 * Notify scakiod when a keystore has been deleted
 */
void
mca_upcall_send_goodbye(char *name, mca_t *mca)
{
	dbm_header_t	dbm;
	mca_ucinfo_t	*info;

	DBG(mca, DDBM, "mca_upcall_send_goodbye for %s", name);

	/* build the goodbye message */
	bzero((void *)&dbm, sizeof (dbm));

	dbm.type = htonl(DB_GOODBYE);
	dbm.paramSize = htonl(sizeof (dbm));

	if ((info = lookup_upcall_by_name(name)) != NULL) {
		mca_upcall_send((void *)&dbm, sizeof (dbm), info, mca);
		mutex_exit(&info->mca_ucmx);
	}

}
