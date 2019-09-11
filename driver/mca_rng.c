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

#pragma ident	"@(#)mca_rng.c	1.15	08/08/13 SMI"

/*
 * Mars - pure cryptographic acceleration + secure keystore
 */

#ifdef LINUX
#include <linux/types.h>
#include "sol2lin.h"
#include "mca.h"
#include "mca_csrs.h"
#else
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/mca.h>
#include <sys/mca_csrs.h>
#endif

/*
 * Random number implementation.
 */

static int rng_start(mca_request_t *);
static void rng_done(mca_request_t *);

/*
 * Temporarily store the number of RNG bytes still needed to be generated
 * in mr_tmpin.cd_length field.
 */
#define	resid_len(reqp)	((reqp)->mr_tmpin.cd_length)


int
mca_rng(mca_t *mca, crypto_data_t *data, crypto_req_handle_t *cfreq,
    uint32_t cmd)
{
	mca_request_t	*reqp;
	int		rv;

	if ((reqp = mca_getreq(&mca->mca_ring_ca)) == NULL) {
		mca_error(mca, "unable to allocate request for RNG");
		if (cmd & CMD_HI_KCF_INPLACE) {
			kmem_free(data, sizeof (crypto_data_t));
		}
		return (CRYPTO_BUSY);
	}

	reqp->mr_cf_req = cfreq;
	resid_len(reqp) = mca_get_datalen(data);
	reqp->mr_job_stat = MS_RNGJOBS;
	reqp->mr_byte_stat = MS_RNGBYTES;
	reqp->mr_cmd = cmd;

	/* RNG jobs can take a second or so */
	reqp->mr_timeout = 10 * drv_usectohz(mca_staletime);

	reqp->mr_out = data;
	data->cd_length = 0;

	rv = rng_start(reqp);
	if (rv != CRYPTO_QUEUED) {
		mca_freereq(reqp);
	}
	return (rv);
}

static int
rng_start(mca_request_t *reqp)
{
	int		len;
	crypto_data_t	*out = reqp->mr_out;

	len = min((int)resid_len(reqp), MAXPACKET & ~0xf);

	/*
	 * If the output length is *not* a whole number of dwords in
	 * length, then we have to use scatter.  IT IS VERY IMPORTANT
	 * to realize that the device will always return a whole number
	 * of dwords (uint32_t), and it will round up.  So if you only
	 * ask for 3 bytes of data, you will really get 4 bytes back.
	 * Because of this, we have to use the scratch buffer since the
	 * consumers buffer won't necessarily have space for the extra
	 * byte (or two or three) that might be needed.
	 */
	reqp->mr_flags &= ~MRF_SCATTER;
	if ((len < mca_mindma) || mca_sg(out)) {
		reqp->mr_flags |= MRF_SCATTER;
		reqp->mr_out_paddr = reqp->mr_obuf_paddr;
		reqp->mr_out_next_paddr = reqp->mr_obuf_next_paddr;
		reqp->mr_out_len = MAXPACKET;
		reqp->mr_out_first_len = reqp->mr_obuf_sz;
	} else {
		/* Try to bind the kernel addr for DMA */
		if (mca_bindchains(reqp, 0, len) != DDI_SUCCESS)
			return (CRYPTO_FAILED);
	}

	/* mr_in_len is the length of RNG data wanted */
	reqp->mr_in_len = len;
	reqp->mr_in_first_len = 0;
	reqp->mr_in_paddr = 0;

	reqp->mr_byte_count = len;
	reqp->mr_callback = rng_done;
	ddi_dma_sync(reqp->mr_key_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	/* schedule the work by doing a submit */
	return (mca_start(reqp));
}


static void
rng_done(mca_request_t *reqp)
{
	if (reqp->mr_errno == CRYPTO_SUCCESS) {
		ASSERT(reqp->mr_byte_count == reqp->mr_resultlen);
		if (reqp->mr_flags & MRF_SCATTER) {
			int rv;
			ddi_dma_sync(reqp->mr_obuf_dmah, 0, reqp->mr_resultlen,
			    DDI_DMA_SYNC_FORKERNEL);
			rv = mca_scatter(reqp->mr_obuf_kaddr,
			    reqp->mr_resultlen, reqp->mr_out);
			if (rv != CRYPTO_SUCCESS) {
				rv = reqp->mr_errno;
				goto done;
			}
		} else {
			/* we've processed some more data */
			mca_updateoutlen(reqp->mr_out, reqp->mr_resultlen);
		}

		resid_len(reqp) -= reqp->mr_resultlen;

		/*
		 * If there is more to do, then reschedule another
		 * pass.
		 */
		if (resid_len(reqp) > 0) {
			reqp->mr_errno = rng_start(reqp);
			if (reqp->mr_errno == CRYPTO_QUEUED) {
				return;
			}
		}
	}

done:

	crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
	mca_freereq(reqp);
}
