/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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

#pragma ident	"@(#)mca_log.c	1.3	07/02/09 SMI"

/*
 * Mars - pure cryptographic acceleration + secure keystore
 */

#ifdef LINUX
#include <linux/types.h>
#include "sol2lin.h"
#include "mca.h"
#include "mca_hw.h"
#include "mca_log.h"
#include "mca_csrs.h"
#else /* LINUX */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>

#include <sys/mca.h>
#include <sys/mca_hw.h>
#include <sys/mca_log.h>
#include <sys/mca_csrs.h>

#ifdef FMA_COMPLIANT
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#endif
#endif /* LINUX */

/*
 * Device message log support.
 */

#ifdef FMA_COMPLIANT
char *
mca_fm_class_string(mca_t *mca, uint8_t class_id)
{
	/* Convert an error class ID to an error class string */
	switch (class_id) {
	case MCA_FMA_NO_CLASS_ID:
		return ("none");
	case MCA_FMA_FW_PROBLEM_ID:
		return ("fw.misop");
	case MCA_FMA_FW_EXCEPTION_ID:
		return ("fw.exc");
	case MCA_FMA_FW_NO_REPORT_ID:
		return ("fw.no_rpt");
	case MCA_FMA_FW_FAILSAFE_ID:
		return ("fw.fs");
	case MCA_FMA_FW_VERSION_ID:
		return ("fw.ver");
	case MCA_FMA_SW_PROBLEM_ID:
		return ("sw.misop");
	case MCA_FMA_SW_KS_ID:
		return ("sw.ks");
	case MCA_FMA_TO_INIT_ID:
		return ("to.init");
	case MCA_FMA_TO_CTL_ID:
		return ("to.ctl");
	case MCA_FMA_TO_CRYPTO_ID:
		return ("to.crypto");
	case MCA_FMA_IPOST_ID:
		return ("ipost");
	case MCA_FMA_POST_ID:
		return ("post");
	case MCA_FMA_HALT_ID:
		return ("halt");
	case MCA_FMA_MEM_UE_ID:
		return ("mem.ue");
	case MCA_FMA_MEM_EX_CE_ID:
		return ("mem.ex_ce");
	case MCA_FMA_BAD_DATA_ID:
		return ("bad_data");
	case MCA_FMA_RESTORE_DATA_ID:
		return ("res_data");
	case MCA_FMA_DETECT_PERR_ID:
		return ("rpe");
	case MCA_FMA_REPORT_PERR_ID:
		return ("mdpe");
	case MCA_FMA_DETECT_SERR_ID:
		return ("rserr");
	case MCA_FMA_REPORT_SERR_ID:
		return ("sserr");
	case MCA_FMA_MA_ID:
		return ("ma");
	case MCA_FMA_INT_MA_ID:
		return ("ima");
	case MCA_FMA_DETECT_TA_ID:
		return ("rta");
	case MCA_FMA_REPORT_TA_ID:
		return ("sta");
	case MCA_FMA_DMA_ID:
		return ("dma");
	case MCA_FMA_BAD_FW_ID:
		return ("bad_fw");
	case MCA_FMA_HEALTH_ID:
		return ("hc");
	case MCA_FMA_ZEROIZE_JMP_ID:
		return ("zj");
	case MCA_FMA_POWER_ID:
		return ("power");
	default:
		mca_note(mca, "Unknown ereport class ID (%d) reported by "
		    "firmware", class_id);
		return ("sw");
	}
}
#endif /* FMA_COMPLIANT */


/*
 * Decode firmware ereport data and post it to the FMA
 */
#ifdef FMA_COMPLIANT
static void
mca_log_ereport(mca_t *mca, uint8_t impact, uint8_t class, char *msg)
{
	switch (impact) {
	case MCA_IMPACT_ERROR:
		/*
		 * This error will result in a fault interrupt and a call
		 * to mca_failure which will check ena to verify that an
		 * ereport has already been filed.  If multiple errors of this
		 * level are reported prior to the service impact report,
		 * continue the ENA chain.
		 */

		/* Check for previously generated ENA */
		mutex_enter(&mca->fm_lock);
		if (mca->fm_ena == 0) {
			/* Start new ENA chain */
			mca->fm_ena = fm_ena_generate(0, FM_ENA_FMT1);
		} else {
			/* Increment ENA stored in mca_t and continue chain */
			mca->fm_ena = fm_ena_increment(mca->fm_ena);
		}
		mutex_exit(&mca->fm_lock);

		/* Post the ereport */
		mca_fm_ereport_post(mca, mca->fm_ena, class, msg);
		break;

	case MCA_IMPACT_WARNING:
	case MCA_IMPACT_NOTICE:
	case MCA_IMPACT_INFO:
		/*
		 * Just post an ereport (with generated ENA) for all these
		 * impact levels.
		 */
		mca_fm_ereport_post(mca, 0, class, msg);
		break;


	default:
		/*
		 * Reset the card and post an ereport and to log this
		 * firmware error
		 */
		mca_failure(mca, MCA_FMA_FW_PROBLEM_ID,
		    "Invalid firmware ereport impact level (%d)", impact);
		break;
	}
}
#endif /* FMA_COMPLIANT */

/*
 * Obtain logged messages from log ring.
 */
void
mca_getlog(mca_t *mca)
{
	int			count = 0;
	uint8_t			size;
	mca_log_t		*log;
	mca_ereport_log_t	*ereport;
	uint8_t			head, tail;
	char			msg[MCA_LOG_ENTRY_SIZE];

	size = GETCSR8(mca, CSR_LOGRINGSZ);
	DBG(mca, DGETLOG, "log ring size = %d", size);

	/*
	 * This is just going through the completion ring.
	 */
	for (;;) {

		head = GETCSR8(mca, CSR_LOGRINGHEAD);
		tail = GETCSR8(mca, CSR_LOGRINGTAIL);

		DBG(mca, DGETLOG, "log head = %d, tail = %d", head, tail);
		if (head == tail) {
			/* ring is empty */
			break;
		}

		if ((head >= size) || (tail >= size)) {
			mca_failure(mca, MCA_FMA_FW_PROBLEM_ID,
			    "illegal log ring indices");
			return;
		}

		log = (mca_log_t *)mca->mca_log_buff.kaddr + head;
		ddi_dma_sync(mca->mca_log_buff.dmah, sizeof (mca_log_t) * head,
		    sizeof (mca_log_t), DDI_DMA_SYNC_FORKERNEL);

		switch (log->type) {
		case MCA_SYS_LOG_MSG:
			/* Just log message to system log */
			strncpy(msg, log->entry.msg, sizeof (msg));
			/* Insure null termination */
			msg[MCA_LOG_ENTRY_SIZE - 1] = '\0';
			mca_log_system_msg(mca, log->level, msg);
			break;

		case MCA_FMA_EREPORT:

			ereport = (mca_ereport_log_t *)&log->entry.ereport;
			strncpy(msg, ereport->msg, sizeof (msg));
			/* Insure null termination */
			msg[MCA_LOG_ENTRY_SIZE - 1] = '\0';
#ifdef FMA_COMPLIANT
			/* Make sure FMA is enabled */
			if (!DDI_FM_EREPORT_CAP(mca->fm_capabilities)) {

				/* Just log message to system log */
				mca_log_system_msg(mca, log->level, msg);
			} else {
				/* Log an ereport to the FMA */
				mca_log_ereport(mca, log->level,
				    ereport->event.class, msg);
			}
#else
			/* Just log message to system log */
			mca_log_system_msg(mca, log->level, msg);
#endif /* FMA_COMPLIANT */
			break;
		default:
			mca_note(mca, "Received unknown log type (0x%02x) "
			    "from firmware", log->type);
		}

		/*
		 * Make completion entry available for hardware.
		 */
		head++;

		/* loop below is optimized version of "head %= size;" */
		while (head >= size) {
			head -= size;
		}

		DBG(mca, DGETLOG, "saving new log head = %d", head);
		PUTCSR8(mca, CSR_LOGRINGHEAD, head);
		count++;
	}
	PUTCSR16(mca, CSR_SIGNAL, SIGNAL_LOG);
	DBG(mca, DGETLOG, "logged %d messages", count);
}
