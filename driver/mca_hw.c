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

#pragma ident	"@(#)mca_hw.c	1.97	08/11/26 SMI"

/*
 * Mars - pure cryptographic acceleration + secure keystore
 */

#ifdef LINUX
#include <linux/types.h>
#include "sol2lin.h"
#include "mca.h"
#include "mca_table.h"
#include "mca_hw.h"
#include "mca_csrs.h"
#include "mcactl.h"
#include "os_api.h"
#else /* LINUX */
#include <stddef.h>		/* offsetof() */

#include <sys/types.h>
#include <sys/byteorder.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kstat.h>
#include <sys/disp.h>			/* servicing_interrupt() */
#include <sys/time.h>			/* gethrtime() */
#include <sys/mca.h>
#include <sys/mca_table.h>
#include <sys/mca_hw.h>
#include <sys/mca_csrs.h>
#include <sys/mcactl.h>	/* for MCASECCMD_ flags */
#include <sys/stream.h> /* for mblk_t */
#include <sys/os_api.h>
#ifdef FMA_COMPLIANT
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#endif
#endif /* LINUX */

static int mca_activate(mca_t *);
static int mca_deactivate(mca_t *);
static int mca_post(mca_t *);
static int mca_enablewindow(mca_t *);
static void mca_inithw(mca_t *);
static int  mca_msgwait(mca_t *, clock_t);
static int  mca_setktikey(mca_t *);
static void hardreset(mca_t *);
static int  reset_send(mca_t *, mca_reset_t, int);
static void mca_fri_settime(mca_t *);
static void mca_fri_ind(mca_t *);

static char *mca_dbm_type(int type);

#if !defined(DEBUG)
#pragma inline(reset_send)
#endif

/*
 * Hardware access stuff.
 */

static int mca_resettime = 90 * SECOND;
static int mca_posttime = 90 * SECOND;
static int mca_boottime = 30 * SECOND;

#ifdef LINUX
#define	MAX_NUM_WORK_WRAP	10

typedef struct work_wrap_ {
	struct work_struct	taskq;
	mca_t			*mca;
	int			inuse;
} work_wrap_t;

static work_wrap_t work_wrap[MAX_NUM_WORK_WRAP];
static int work_wrap_index = 0;
extern spinlock_t sca_work_lock;
#endif

/*
 * This starts up the device, possibly resetting it if necessary.
 * At the end of this routine, on success the device will be in
 * the ACTIVE or FAILSAFE state.  On failure, the state is unknown,
 * and the device should be assumed to be unusable.
 */
int
mca_masterstart(mca_t *mca)
{
	int		time = 0;
	int		resetdone = 0;
	int		state;
	uint32_t	config;
	uint16_t	version;
	uint64_t	ena = MCA_ENA_GEN;

	config = INVALID_CSR_CONFIG;	/* Insure valid read */
	config = GETCSR32(mca, CSR_CONFIG);
	if (config & CONFIG_UPDATED) {
		mca_note(mca, "Updated firmware present, "
		    "resetting to activate new firmware.");
		hardreset(mca);
		resetdone++;
	}

	config = INVALID_CSR_CONFIG;	/* Insure valid read */
	config = GETCSR32(mca, CSR_CONFIG);
	/* when first starting up, must be in POST, IPOST, DISABLED, or IDLE */
	switch (config & CONFIG_FWSTATE) {
	case FWSTATE_IPOST:
	case FWSTATE_POST:
	case FWSTATE_DISABLED:
	case FWSTATE_IDLE:
		break;
	case FWSTATE_RESET:
	case FWSTATE_HALTED:
		/* no need to note this */
		hardreset(mca);
		resetdone++;
		break;
	default:
		mca_note(mca, "Device in bad initial state %x, "
		    "attempting to reset.", config & CONFIG_FWSTATE);
		hardreset(mca);
		resetdone++;
	}

	for (;;) {

		config = INVALID_CSR_CONFIG;	/* Insure valid read */
		config = GETCSR32(mca, CSR_CONFIG);
		state = config & CONFIG_FWSTATE;
		switch (state) {
		case FWSTATE_IPOST:
			if (time > mca_resettime) {
				if (resetdone) {
					MCA_EREPORT_POST(mca, LOGMASK_ERROR,
					    ena, MCA_FMA_IPOST_ID,
					    "Timed out waiting for IPOST");
					return (DDI_FAILURE);
				}
				/*
				 * Don't log an ereport when a retry will be
				 * attempted, only if the retry fails.
				 */
				mca_note(mca, "Timed out waiting for IPOST, "
				    "attempting to reset device");
				ena = MCA_ENA_INC(ena);
				hardreset(mca);
				resetdone++;
				time = 0;
			} else {
				delay(1);
				time += drv_hztousec(1);
			}
			break;

		case FWSTATE_POST:
			if (time > mca_posttime) {
				if (resetdone) {
					MCA_EREPORT_POST(mca, LOGMASK_ERROR,
					    ena, MCA_FMA_TO_INIT_ID,
					    "Timeout waiting for POST");
					return (DDI_FAILURE);
				}
				/*
				 * Don't log an ereport when a retry will be
				 * attempted, only if the retry fails.
				 */
				mca_note(mca, "Timed out waiting for POST, "
				    "attempting to reset device");
				ena = MCA_ENA_INC(ena);
				hardreset(mca);
				resetdone++;
				time = 0;
			} else {
				delay(1);
				time += drv_hztousec(1);
			}
			break;

		case FWSTATE_DISABLED:
			/* enable the register window */
			if (mca_enablewindow(mca) == DDI_FAILURE) {
				if (resetdone) {
					MCA_EREPORT_POST(mca, LOGMASK_ERROR,
					    ena, MCA_FMA_TO_INIT_ID,
					    "Failed enabling CSR window");
					return (DDI_FAILURE);
				}
				/*
				 * Don't log an ereport when a retry will be
				 * attempted, only if the retry fails.
				 */
				mca_note(mca, "Failed enabling CSR window, "
				    "attempting to reset device");
				ena = MCA_ENA_INC(ena);
				hardreset(mca);
				resetdone++;
				time = 0;
			}
			break;

		case FWSTATE_IDLE:
			/* send the start command */
			if (mca_activate(mca) == DDI_FAILURE) {
				if (resetdone) {
					MCA_EREPORT_POST(mca, LOGMASK_ERROR,
					    ena, MCA_FMA_TO_INIT_ID,
					    "Failed trying to start device");
					return (DDI_FAILURE);
				}
				/*
				 * Don't log an ereport when a retry will be
				 * attempted, only if the retry fails.
				 */
				mca_note(mca,  "Failed trying to start "
				    "device, attempting to reset device.");
				ena = MCA_ENA_INC(ena);
				hardreset(mca);
				resetdone++;
				time = 0;
			}
			break;

		case FWSTATE_FAILSAFE:
		case FWSTATE_ACTIVE:
			/*
			 * Check interface version compatibility.
			 * Only major and minor numbers must match for
			 * compatibility
			 */
			version = MCA_INVALID_CSR16; /* Insure valid read */
			version = MCA_FW_IF_COMP_VERSION(mca);

			if (version != MCA_IF_COMP_VERSION) {
				mca_note(mca,
				    "Driver interface version: %d.%d.%d",
				    MCA_IF_MAJOR_VERSION,
				    MCA_IF_MINOR_VERSION,
				    MCA_IF_MICRO_VERSION);
				mca_note(mca,
				    "Firmware interface version: %d.%d.%d",
				    MCA_FW_IF_MAJOR_VERSION(mca),
				    MCA_FW_IF_MINOR_VERSION(mca),
				    MCA_FW_IF_MICRO_VERSION(mca));
				/*
				 * Enter failsafe mode on all version mismatches
				 * Minor interface mismatches may be allowed in
				 * the future but not in the current release.
				 */
				mca_error(mca,
				    "Driver and firmware incompatible -- "
				    "device placed in FAILSAFE mode.");
				mutex_enter(&mca->fm_lock);
				mca_fm_setfailsafe(mca);
				mutex_exit(&mca->fm_lock);
				goto ok;
			} else {
				/* send the health check command */
				if (mca_post(mca) == DDI_FAILURE) {
					mca_fm_setfailed(mca);
					MCA_EREPORT_POST(mca,
					    LOGMASK_ERROR, ena,
					    MCA_FMA_HEALTH_ID,
					    "Device failed POST.");
					return (DDI_FAILURE);
				}
				if (!(mca_fm_isoffline(mca)) &&
				    !(mca_isattaching(mca))) {
					/* notify scakiod */
					mca_upcall_reset(mca);
				}

				/* successful startup! */
				goto ok;
			}

		case FWSTATE_HALTED:
			if (resetdone) {
				MCA_EREPORT_POST(mca, LOGMASK_ERROR, ena,
				    MCA_FMA_HALT_ID,
				    "Device in halted (error) state");
				return (DDI_FAILURE);
			}
			/*
			 * Don't log an ereport when a retry will be
			 * attempted, only if the retry fails.
			 */
			mca_note(mca, "Device in halted (error) state, "
			    "attempting to reset device.");
			ena = MCA_ENA_INC(ena);
			hardreset(mca);
			resetdone++;
			time = 0;
			break;

		case FWSTATE_RESET:
			MCA_EREPORT_POST(mca, LOGMASK_ERROR, ena,
			    MCA_FMA_TO_INIT_ID,
			    "Device stuck in reset state");
			return (DDI_FAILURE);

		default:
			/* bogus unknown unknown state */
			if (resetdone) {
				MCA_EREPORT_POST(mca, LOGMASK_ERROR, ena,
				    MCA_FMA_BAD_DATA_ID,
				    "Device stuck in unknown state");
				mca_error(mca, "Device stuck in unknown "
				    "state 0x%x", state);
				return (DDI_FAILURE);
			}
			/*
			 * Don't log an ereport when a retry will be
			 * attempted, only if the retry fails.
			 */
			mca_error(mca, "Bad device state %x, "
			    "attempting to reset device.", state);
			ena = MCA_ENA_INC(ena);
			hardreset(mca);
			resetdone++;
			time = 0;
			break;
		}
	}

ok:
	/* At this point we have read config and verified a valid state */

	/*
	 * We don't let the user proceed from zeroize until they
	 * remove the jumper.  Otherwise they might upgrade the
	 * firmware only to have it zeroized the next time the card
	 * resets!
	 */
	if (config & CONFIG_ZEROIZE) {
		MCA_EREPORT_POST(mca, LOGMASK_ERROR, ena,
		    MCA_FMA_ZEROIZE_JMP_ID,
		    "ZEROIZE jumper detected!  Remove jumper, "
		    "and update firmware.");
		return (DDI_FAILURE);
	}

	/*
	 * This is a bad thing, so we fail hard.
	 */
	if (config & CONFIG_FACTBAD) {
		MCA_EREPORT_POST(mca, LOGMASK_ERROR, ena,
		    MCA_FMA_BAD_FW_ID,
		    "Factory firmware is corrupt!");
#ifndef DEBUG
		return (DDI_FAILURE);
#endif
	}

	if (config & CONFIG_POSTERR) {
		/*
		 * Report the error.  We don't decode the post
		 * results, since that information is not likely to be
		 * useful to a typical customer.  We report it, so
		 * that it can be decoded manually by service
		 * personnel, or by engineering.
		 */
		MCA_EREPORT_POST(mca, LOGMASK_ERROR, ena,
		    MCA_FMA_POST_ID,
		    "Error encountered during post -- "
		    "device placed in FAILSAFE mode.");
		mca_error(mca, "Error 0x%04x encountered during post -- "
		    "device placed in FAILSAFE mode.",
		    GETCSR16(mca, CSR_POSTRESULT));
		ena = MCA_ENA_INC(ena);

		/* put device in failsafe mode - all it can do is fw upgrade */
		mutex_enter(&mca->fm_lock);
		mca_fm_setfailsafe(mca);
		mutex_exit(&mca->fm_lock);
	}

	if (config & CONFIG_FACTORY) {
		MCA_EREPORT_POST(mca, LOGMASK_ERROR, ena,
		    MCA_FMA_FW_FAILSAFE_ID,
		    "FAILSAFE firmware running -- update firmware.");
		ena = MCA_ENA_INC(ena);
		mutex_enter(&mca->fm_lock);
		mca_fm_setfailsafe(mca);
		mutex_exit(&mca->fm_lock);
	} else if (config & CONFIG_FWBAD) {
		MCA_EREPORT_POST(mca, LOGMASK_ERROR, ena,
		    MCA_FMA_FW_FAILSAFE_ID,
		    "Operational firmware is corrupt or missing -- "
		    "update firmware.");
		ena = MCA_ENA_INC(ena);
		mutex_enter(&mca->fm_lock);
		mca_fm_setfailsafe(mca);
		mutex_exit(&mca->fm_lock);
	}
	if (config & CONFIG_LOGFULL) {
		mca_note(mca, "On-board message log is full, "
		    "some messages may be lost.");
	}
	if (config & CONFIG_UPDATED) {
		/*
		 * This should have triggered a reset.  So why are we
		 * here?  Note it and just move on for now.
		 */
		mca_error(mca, "Updated firmware present, but not in use.");
	}

	mca_note(mca, "Device standing by.");
	return (DDI_SUCCESS);
}


int
mca_hostready(
	mca_t *mca,
	int ready)
{
	PUTCSR16(mca, CSR_FWSTAT, 1);	/* Force a failure on timeout. */
	PUTCSR32(mca, CSR_FWCTLSZ, sizeof (uint32_t));
	PUTCSR32(mca, CSR_FWCTLDATA, ready);
	PUTCSR16(mca, CSR_FWCTL, FWCTL_HOSTREADY);

	/* Clear the interrupt bit */
	PUTCSR16(mca, CSR_INTSTAT, INTSTAT_CTL);

	/* Write the kick register */
	PUTCSR16(mca, CSR_SIGNAL, SIGNAL_CTL);

	if (ready) {
		/* give the fw time to process the hostready */
		if (MCA_FW_IF_COMP_VERSION(mca) <= MCA_IF_VERSION_1_0) {
			/* 1.0 needs a little more delay */
			delay(MCA_ENABLE_DELAY_1_0);
		} else {
			delay(MCA_ENABLE_DELAY);
		}
	} else {
		/* give the fw time to process the host absent */
		delay(MCA_DISABLE_DELAY);
	}

	return (DDI_SUCCESS);
}

int
mca_fdi_req(mca_t *mca, uint32_t *src)
{
	int argc,	i;
	uint32_t	*dst;
	uint8_t		*s1;
	char		*s2;
	uint16_t	status;

	mca_ctlbusy(mca);

	PUTCSR16(mca, CSR_FWSTAT, 1);	/* Force a failure on timeout. */
	PUTCSR32(mca, CSR_FWCTLSZ, 0);
	PUTCSR32(mca, CSR_FWCTLDATA, sizeof (fdi_request_t));
	PUTCSR16(mca, CSR_FWCTL, FWCTL_FDIREQ);

	/* Copy the debug request data structure to its window. */
	/* Each argument to the debug request is 32 bits wide. */
	dst = (uint32_t *)(mca->mca_regs + CSR_FDI_WINDOW);
	argc = offsetof(fdi_request_t, cmd) / sizeof (uint32_t);
	for (i = 0; i < argc; i++, dst++) {
		ddi_put32(mca->mca_regshandle, dst, src[i]);
	}

	/* Copy the function string, too. */
	s1 = (uint8_t *)
	    (mca->mca_regs + CSR_FDI_WINDOW + offsetof(fdi_request_t, cmd));
	s2 = (char *)src + offsetof(fdi_request_t, cmd);
	for (i = 0; i < FDI_LKUP_MAX; i++, s1++, s2++) {
		ddi_put8(mca->mca_regshandle, s1, *s2);
		if (*s2 == 0)
			break;				/* We're done early. */
	}

	/* clear the interrupt bit */
	PUTCSR16(mca, CSR_INTSTAT, INTSTAT_CTL);
	/* write the kick register */
	DBG(mca, DCHATTY, "Kicking debug signal");
	PUTCSR16(mca, CSR_SIGNAL, SIGNAL_CTL);

/*
 * now wait for the job to complete -- we have a one minute
 * timer for this.
 */
	if (mca_ctlwait(mca, drv_usectohz(300 * SECOND)) != 0) {
		mca_ctlunbusy(mca);
		mca_failure(mca, MCA_FMA_TO_CTL_ID,
		    "Timeout waiting for debug request");
		return (ETIME);
	}

	status = MCA_INVALID_CSR16;	/* Insure valid data read */
	status = GETCSR16(mca, CSR_FWSTAT);
	if (status != 0) {
		mca_ctlunbusy(mca);
		mca_error(mca, "Debug request completed with failure, "
		    "result = %x", GETCSR16(mca, CSR_POSTRESULT));
		return (EIO);
	}

	mca_ctlunbusy(mca);

	return (DDI_SUCCESS);
}

static void
hardreset(mca_t *mca)
{
	mca_note(mca, "Resetting board...");

	/*
	 * Clobber the configuration register.  This is necessary so
	 * that the wait for the transition from POST to IDLE can be
	 * detected.
	 */
	PUTCSR32(mca, CSR_CONFIG, 0);

	/* Send a reset interrupt to the firmware */
	PUTCSR32(mca, CSR_SIGNAL, SIGNAL_RESET);

	/* Delay 5 seconds to insure bootstrap firmware comes up */
	delay(drv_usectohz(5000000));

	/*
	 * Device reset clears device state flags.  Clear device related state
	 * in both sets of state flags.
	 */
	mca_reset_device_flags(mca);
	mutex_enter(&mca->fm_lock);
	mca_fm_reset_device_flags(mca);
	mutex_exit(&mca->fm_lock);

	mca->reset.lbolt = ddi_get_lbolt();
}

static int
reset_send(
	mca_t *mca,
	mca_reset_t reset,
	int seconds)
{
	/* Tell the firmware to reset - giving it a chance to */
	/* tidy up, and log any messages it may want to. */
	PUTCSR32(mca, CSR_FWCTLSZ, 0);
	PUTCSR32(mca, CSR_FWCTLDATA, reset);
	PUTCSR16(mca, CSR_FWCTL, FWCTL_FWRESET);

	/* Clear the interrupt bit - waiting for this in mca_ctlwait(). */
	PUTCSR16(mca, CSR_INTSTAT, INTSTAT_CTL);

	/* Signal the firmware. */
	DBG(mca, DCHATTY, "Kicking reset signal");
	PUTCSR16(mca, CSR_SIGNAL, SIGNAL_CTL);

	/* Wait at least <seconds> seconds for the firmware to respond. */
	return (mca_ctlwait(mca, drv_usectohz(seconds * SECOND)));
}


/*
 * N.B., this function may not be called from interrupt context.
 */

void
mca_hardreset(
	mca_t *mca,
	mca_reset_t command)
{
	int status;

	/* This error check may be unnecessary. */
	if (command < MCA_RESET_HARD || command > MCA_RESET_FAST) {
		mca_error(mca, "Invalid reset command = %d", command);
		return;
	}

	if ((command == MCA_RESET_HARD) || (command == MCA_RESET_FIRM)) {
		/* Just do a hardware reset now. */
		hardreset(mca);
		return;
	}

	/* If the card isn't listening, don't bother. */
	if (!(mca_fm_isdeaf(mca))) {
		if (command == MCA_RESET_SOFT) {
			mca_ctlbusy(mca);
			/* This is the first pass. */
			status = reset_send(mca, MCA_RESET_SOFT, 30);
			/* Wait at least 30 seconds for the card to respond. */
			mca_ctlunbusy(mca);

			if (status != 0) {	/* No answer? */
				mca_error(mca, "Reset preparation timeout.");
			}
		}

		/* Now flush the firmware's message log. */
		(void) mca_msgwait(mca, drv_usectohz(SECOND));

		/* The 2nd & final pass - tell the firmware to shutdown. */
		mca_ctlbusy(mca);
		/*
		 * Fix me:
		 * Polling more 5 seconds inside a spinlock on Linux causes
		 * a panic. Needs to rework this reset by either changing from
		 * 10 to under 5 or not polling inside a spinlock.
		 */
		status = reset_send(mca, MCA_RESET_FAST, 10);
		mca_ctlunbusy(mca);

		if (status != 0) { /* No answer? */
			mca_error(mca, "Reset shutdown timeout.");
		}

	} else {
		/* Attempt to flush the firmware's message log */
		(void) mca_msgwait(mca, drv_usectohz(SECOND));
	}

	/* This is a standard reset, if a reset is ever standard! */
	/* In other words, the sca6000 did not generate a fault. */
	if (!(mca_fm_hw_faulted(mca))) {

		if (mca->reset.logic != mca_resetsoft_wait &&
		    mca->reset.logic != mca_resethard_wait) {
			hardreset(mca); /* Hardware Reset. */
		}

	/* But, if the sca6000 generated a fault, do not reset it. */
	} else {
		/* Clear the FAULTED flag, so mca_safereset() can */
		/* eventually reset it. */
		mutex_enter(&mca->fm_lock);
		mca_fm_clr_hw_fault(mca);
		/* Set the DEAF flag, so we can cut to the chase */
		/* when mca_safereset() is called. */
		mca_fm_setdeaf(mca);
		mutex_exit(&mca->fm_lock);
	}

	mca->reset.tqid = 0;
}

void
mca_shutdown(mca_t *mca)
{
	int	state;

	/* turn off interrupts, they cause us problems */
	mca_disableinterrupts(mca, 0);

	state = FWSTATE_INVALID;	/* Insure valid read */
	state = GETCSR32(mca, CSR_CONFIG) & CONFIG_FWSTATE;
	switch (state) {
	case FWSTATE_ACTIVE:
	case FWSTATE_FAILSAFE:
		/* clean shutdown OK */
		if (mca_deactivate(mca) == DDI_SUCCESS) {
			return;
		}
		break;
	case FWSTATE_DISABLED:
	case FWSTATE_IDLE:
		/* device is already shutdown */
		DBG(mca, DBRINGUP, "device already shutdown or disabled");
		return;
	case FWSTATE_HALTED:
		DBG(mca, DBRINGUP, "device already hard-halted (error)");
		return;
	case FWSTATE_IPOST:
	case FWSTATE_POST:
		DBG(mca, DBRINGUP, "device is running iPOST/POST");
		return;
	case FWSTATE_RESET:
		/* device wants a reset anyway */
		break;
	default:
		/* invalid state, should never occur! */
		mca_error(mca, "invalid shutdown state (%x)", state);
		break;
	}
	/* We couldn't shutdown cleanly, so just reset it instead. */
	hardreset(mca);
}

/*
 * This enables the CSR window for MCA.  It is assumed that the device
 * is operational at this point.  A precondition is that we are called
 * in the DISABLED state.
 */
static int
mca_enablewindow(mca_t *mca)
{
	int	state;

	state = FWSTATE_INVALID;	/* Insure valid read */
	state = GETCSR32(mca, CSR_CONFIG) & CONFIG_FWSTATE;
	if (state != FWSTATE_DISABLED) {
		/* called out of state, should never occur! */
		mca_error(mca, "Enablewindow out of state (%x)", state);
		return (DDI_FAILURE);
	}

	/* send the enable CSR signal to the device */
	PUTCSR16(mca, CSR_SIGNAL, SIGNAL_ENABLE);

	/* Wait up to a minute for firmware to respond with interrupt */
	if (mca_ctlwait(mca, drv_usectohz(60 * SECOND)) != 0) {
		/* Details of failure already logged */
		return (DDI_FAILURE);
	}
	DBG(mca, DBRINGUP, "Enabled CSR window");
	return (DDI_SUCCESS);
}

/*
 * This sends the START command, and expects to end up in either
 * the ACTIVE or FAILSAFE state.  A precondition is that we are called
 * in the IDLE state.
 *
 * It also programs up the ring addresses, since that needs to be done
 * before issuing the start command.
 */
static int
mca_activate(mca_t *mca)
{
	int	state;

	state = INVALID_CSR_CONFIG;	/* Insure valid read */
	state = GETCSR32(mca, CSR_CONFIG) & CONFIG_FWSTATE;
	if (state != FWSTATE_IDLE) {
		/* called out of state, should never occur! */
		mca_error(mca, "Activate out of state (%x)", state);
		return (DDI_FAILURE);
	}

	/* initialize the hardware */
	mca_inithw(mca);

	mca_ctlbusy(mca);

	PUTCSR16(mca, CSR_INTSTAT, INTSTAT_CTL);

	/* send the start/stop command */
	PUTCSR16(mca, CSR_FWCTL, FWCTL_STARTSTOP);
	PUTCSR16(mca, CSR_SIGNAL, SIGNAL_CTL);

	if (mca_ctlwait(mca, drv_usectohz(5 * SECOND)) != 0) {
		mca_error(mca,
		    "Timed out waiting for start, state = %x", state);
		mca_ctlunbusy(mca);
		return (DDI_FAILURE);
	}
	mca_ctlunbusy(mca);
	state = GETCSR32(mca, CSR_CONFIG) & CONFIG_FWSTATE;
	if ((state == FWSTATE_ACTIVE) || (state == FWSTATE_FAILSAFE)) {
		DBG(mca, DBRINGUP, "Start command OK");
		return (DDI_SUCCESS);
	}
	mca_error(mca, "mca_activate failed");
	return (DDI_FAILURE);
}

int
mca_getpubkey(mca_t *mca, char **datap, size_t *sizep)
{
	ddi_dma_cookie_t	cookie;
	char			*data;
	size_t			size;
	unsigned		nc;
	uint16_t		status;
	size = mca->mca_pagesize;
	if ((data = kmem_zalloc(size, KM_SLEEP)) == NULL) {
		mca_error(mca,
		    "getpubkey: Unable to allocate memory of %d bytes", size);
		return (DDI_FAILURE);
	}

	/* mark us busy to lockout drains */
	mca_ctlbusy(mca);

	if (ddi_dma_addr_bind_handle(mca->mca_ctldmah, NULL, data, size,
	    DDI_DMA_READ | DDI_DMA_STREAMING,
	    DDI_DMA_SLEEP, NULL, &cookie, &nc) != DDI_DMA_MAPPED) {
		mca_error(mca, "Unable to map public key for DMA");
		mca_ctlunbusy(mca);
		kmem_free(data, size);
		return (DDI_FAILURE);
	}
	mca->mca_ctlcmd = FWCTL_GETPUBKEY;

	ddi_dma_sync(mca->mca_ctldmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	PUTCSR16(mca, CSR_FWSTAT, 1);	/* force failure on timeout */
	PUTCSR32(mca, CSR_FWCTLSZ, size);
	PUTCSR32(mca, CSR_FWCTLDATA, cookie.dmac_address);

	/* start by clearing the status bit */
	PUTCSR16(mca, CSR_INTSTAT, INTSTAT_CTL);

	/* send the get pubkey command */
	PUTCSR16(mca, CSR_FWCTL, FWCTL_GETPUBKEY);
	DBG(mca, DBRINGUP, "kicking public key retrieve signal");
	PUTCSR16(mca, CSR_SIGNAL, SIGNAL_CTL);

	/*
	 * wait up to five seconds for it to complete (firware delays at
	 * least 1 second)
	 */
	if (mca_ctlwait(mca, drv_usectohz(5 * SECOND)) != 0) {
		(void) ddi_dma_unbind_handle(mca->mca_ctldmah);
		mca->mca_ctlcmd = FWCTL_NULL;
		mca_ctlunbusy(mca);
		kmem_free(data, size);
		mca_failure(mca, MCA_FMA_TO_CTL_ID,
		    "Failure obtaining device public key.");
		return (DDI_FAILURE);
	}

	status = MCA_INVALID_CSR16;	/* Insure valid read */
	*sizep = MCA_INVALID_CSR32;	/* Insure valid read */
	status = GETCSR16(mca, CSR_FWSTAT);
	*sizep = GETCSR32(mca, CSR_FWCTLSZ);

	(void) ddi_dma_unbind_handle(mca->mca_ctldmah);
	mca->mca_ctlcmd = FWCTL_NULL;

	mca_ctlunbusy(mca);

	if (status != 0) {
		kmem_free(data, size);
		mca_error(mca, "Public key retrieval failure, status = 0x%04x",
		    status);
		return (DDI_FAILURE);
	}
	if (*sizep > size) {
		kmem_free(data, size);
		mca_error(mca, "Bad public key length");
		return (DDI_FAILURE);
	}
	if ((*datap = kmem_alloc(*sizep, KM_SLEEP)) == NULL) {
		kmem_free(data, size);
		mca_error(mca,
		    "getpubkey: Unable to allocate memory of %d bytes", *sizep);
		return (DDI_FAILURE);
	}
	bcopy(data, *datap, *sizep);
	kmem_free(data, size);
	DBG(mca, DBRINGUP, "Got public key OK (%d bytes)", *sizep);

	return (DDI_SUCCESS);
}

/*
 * This takes the KTI transfer key, which should have been generated
 * the first time attach(9e) was called, and hands it off to the firmware,
 * after first encrypting it under the firmware's public key.
 */
static int
mca_setktikey(mca_t *mca)
{
	size_t			pubkeysz, encsz;
	char			*pubkeybuf, *encbuf;
	unsigned		modlen, explen;
	uchar_t			*ptr, *mod, *exp;
	ddi_dma_cookie_t	cookie;
	unsigned		nc;
	uint16_t		status;
	mca_kti_data_t		*kti;
#ifdef DEBUG
	char			*prop_val;
	int			prop_len;
#endif /* DEBUG */

	/* first we have to obtain the firwmare's RSA public key */
	if (mca_getpubkey(mca, &pubkeybuf, &pubkeysz) != DDI_SUCCESS) {
		DBG(mca, DWARN, "setktikey: unable to get public key");
		return (DDI_FAILURE);
	}

	if (pubkeysz < (sizeof (uint32_t) * 3)) {
		DBG(mca, DWARN, "setktikey: runt public key buffer");
		kmem_free(pubkeybuf, pubkeysz);
		return (DDI_FAILURE);
	}

	/* now parse the public key */
	ptr = (uchar_t *)pubkeybuf;
	/* we don't care about the modulus bitlength right now, skip it */
	ptr += sizeof (uint32_t);
	modlen = GETBUF32((unsigned *)ptr);
	ptr += sizeof (uint32_t);
	explen = GETBUF32((unsigned *)ptr);
	ptr += sizeof (uint32_t);
	mod = ptr;
	exp = mod + modlen;

	if (pubkeysz < ((sizeof (uint32_t) * 3) + modlen + explen)) {
		DBG(mca, DWARN, "setktikey: short public key buffer (%d, %d)",
		    modlen, explen);
		kmem_free(pubkeybuf, pubkeysz);
		return (DDI_FAILURE);
	}

	encsz = ROUNDUP(sizeof (uint32_t) + modlen, mca->mca_pagesize);
	if ((encbuf = kmem_alloc(encsz, KM_SLEEP)) == NULL) {
		kmem_free(pubkeybuf, pubkeysz);
		mca_error(mca,
		    "setktikey: Unable to allocate memory of %d bytes", encsz);
		return (DDI_FAILURE);
	}
	kti = (mca_kti_data_t *)encbuf;

	PUTBUF32((uint32_t *)&kti->size, mca_ktisz);
	bcopy(mca_kti, kti->data, mca_ktisz);

	/*
	 * Set kti name and password to default values for now until the
	 * problem of how to best manage them in the driver is solved.
	 * The values set in the firmware must match these default values in
	 * order to exchange the kti key in fips mode using this driver.
	 */
	(void) strncpy(kti->name, MCA_DEFAULT_KTI_NAME, MAX_KTI_NAME_SZ);
	(void) strncpy(kti->pass, MCA_DEFAULT_KTI_PASS, MAX_KTI_PASS_SZ);

#ifndef LINUX
	/* Hard to support these ddi functions on Linux */
#ifdef DEBUG
	/*
	 * Look for "ktiname" and "ktipass" in the .conf file.  Since the .conf
	 * file tends to be world readable this approach was deemed
	 * insufficient for the production driver.  In addition, both
	 * the firmware and driver values should both probably be modified
	 * via mcaadm (or a similiar tool) at the same time rather than using
	 * different methods for each.
	 */

	/* Check for kti name in .conf file */
	if (ddi_getlongprop(DDI_DEV_T_ANY, mca->mca_dip, DDI_PROP_DONTPASS,
	    "ktiname", (caddr_t)&prop_val, &prop_len) == DDI_PROP_SUCCESS) {
		/* Overwrite default value with .conf value */
		(void) strncpy(kti->name, prop_val, MAX_KTI_NAME_SZ);
		kmem_free(prop_val, prop_len);
	}

	/* Check for kti password in .conf file */
	if (ddi_getlongprop(DDI_DEV_T_ANY, mca->mca_dip, DDI_PROP_DONTPASS,
	    "ktipass", (caddr_t)&prop_val, &prop_len) == DDI_PROP_SUCCESS) {
		/* Overwrite default value with .conf value */
		(void) strncpy(kti->pass, prop_val, MAX_KTI_PASS_SZ);
		kmem_free(prop_val, prop_len);
	}
#endif /* DEBUG */
#endif

	/* perform the RSA public key encryption -- this is expensive! */
	if (mca_swrsa((char *)kti, sizeof (mca_kti_data_t), encbuf,
	    mod, modlen, exp, explen) != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "public RSA encrypt of KTK failed!");
		kmem_free(pubkeybuf, pubkeysz);
		kmem_free(encbuf, encsz);
		return (DDI_FAILURE);
	}

	/* done with public key, toss it */
	kmem_free(pubkeybuf, pubkeysz);

	/* mark us busy to lockout drains */
	mca_ctlbusy(mca);

	if (ddi_dma_addr_bind_handle(mca->mca_ctldmah, NULL, encbuf, encsz,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING,
	    DDI_DMA_SLEEP, NULL, &cookie, &nc) != DDI_DMA_MAPPED) {
		mca_error(mca, "Unable to map KTI key for DMA");
		mca_ctlunbusy(mca);
		kmem_free(encbuf, encsz);
		return (DDI_FAILURE);
	}
	mca->mca_ctlcmd = FWCTL_SETKTIKEY;

	ddi_dma_sync(mca->mca_ctldmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	/* force failure on timeout */
	PUTCSR16(mca, CSR_FWSTAT, 1);

	/* Set size of encrypted kti data for firmware download */
	PUTCSR32(mca, CSR_FWCTLSZ, modlen);

	/* Set address encrypted kti data for firmware download */
	PUTCSR32(mca, CSR_FWCTLDATA, cookie.dmac_address);

	/* start by clearing the status bit */
	PUTCSR16(mca, CSR_INTSTAT, INTSTAT_CTL);

	/* send the set pubkey command */
	PUTCSR16(mca, CSR_FWCTL, FWCTL_SETKTIKEY);
	DBG(mca, DBRINGUP, "kicking kti key send signal (modlen %d)", modlen);
	PUTCSR16(mca, CSR_SIGNAL, SIGNAL_CTL);

	/* wait up to five seconds (500 hz, usually) for it to complete */
	if (mca_ctlwait(mca, drv_usectohz(5 * SECOND)) != 0) {
		(void) ddi_dma_unbind_handle(mca->mca_ctldmah);
		mca->mca_ctlcmd = FWCTL_NULL;
		mca_ctlunbusy(mca);
		kmem_free(encbuf, encsz);
		mca_failure(mca, MCA_FMA_TO_CTL_ID,
		    "failure setting KTI transfer key.");
		return (DDI_FAILURE);
	}

	status = MCA_INVALID_CSR16;	/* Insure valid read */
	status = GETCSR16(mca, CSR_FWSTAT);

	(void) ddi_dma_unbind_handle(mca->mca_ctldmah);
	mca->mca_ctlcmd = FWCTL_NULL;
	kmem_free(encbuf, encsz);

	mca_ctlunbusy(mca);

	if (status != 0) {
		mca_error(mca, "Failure setting KTI transport key, "
		    "status = 0x%04x", status);
		return (DDI_FAILURE);
	}
	DBG(mca, DBRINGUP, "Set KTI transfer key OK");
	return (DDI_SUCCESS);
}

/*
 * This sends the POST command, and expects to end up in either
 * the ACTIVE or FAILSAFE state.  A precondition is that we are already
 * in one of these two states.  This gets called with the INTSTAT_CTL
 * interrupt masked off, so we poll it directly.  This should also get
 * called before we register our interrupt handler, anyway.
 */
static int
mca_post(mca_t *mca)
{
	uint16_t	status;

	mca_ctlbusy(mca);

	/* start by clearing the status bit */
	PUTCSR16(mca, CSR_INTSTAT, INTSTAT_CTL);

	/* send the health check command */
	PUTCSR16(mca, CSR_FWCTL, FWCTL_POST);
	PUTCSR16(mca, CSR_SIGNAL, SIGNAL_CTL);

	/* wait up to 10 seconds (1000 hz, usually) for it to complete */
	if (mca_ctlwait(mca, drv_usectohz(10 * SECOND)) != 0) {
		mca_error(mca, "Failure during POST.");
		mca_ctlunbusy(mca);
		return (DDI_FAILURE);
	}

	/* get any logged messages */
	mca_getlog(mca);

	status = MCA_INVALID_CSR16;	/* Insure valid read */
	status = GETCSR16(mca, CSR_FWSTAT);

	if (status != 0) {
		mca_error(mca, "Health check completed with "
		    "failure, result = 0x%04x",
		    GETCSR16(mca, CSR_POSTRESULT));
		mca_ctlunbusy(mca);
		return (DDI_FAILURE);
	}

	mca_ctlunbusy(mca);
	DBG(mca, DBRINGUP, "Health check OK");
	return (DDI_SUCCESS);
}
/*
 * This sends the STOP command, and expects to end up in either
 * the IDLE state.  A precondition is that we are called
 * in the ACTIVE or FAILSAFE state.
 */
static int
mca_deactivate(mca_t *mca)
{
	int	i, state;

	state = INVALID_CSR_CONFIG;	/* Insure valid read */
	state = GETCSR32(mca, CSR_CONFIG) & CONFIG_FWSTATE;
	if ((state != FWSTATE_ACTIVE) && (state != FWSTATE_FAILSAFE)) {
		/* called out of state, should never occur! */
		mca_error(mca, "Deactivate out of state (%x)", state);
		return (DDI_FAILURE);
	}

	/* send the start/stop command */
	PUTCSR16(mca, CSR_FWCTL, FWCTL_STARTSTOP);
	PUTCSR16(mca, CSR_SIGNAL, SIGNAL_CTL);

	/* wait up to a second (100 clocks, usually) for it to take effect */
	i = drv_usectohz(SECOND);
	while (i > 0) {
		delay(1);
		i--;
		state = GETCSR32(mca, CSR_CONFIG) & CONFIG_FWSTATE;
		if ((state == FWSTATE_IDLE) ||
		    (state == FWSTATE_DISABLED)) {
			DBG(mca, DBRINGUP, "Stop command OK");
			return (DDI_SUCCESS);
		}
	}
	mca_error(mca, "Timed out waiting for stop, state = %x", state);
	return (DDI_FAILURE);
}

/*
 * Interrupt service routine.
 */
uint_t
#ifdef LINUX
mca_intr(int irq, char *arg, struct pt_regs *regs)
#else
mca_intr(char *arg)
#endif
{
	mca_t		*mca = (mca_t *)arg;
	uint32_t	status;

	mutex_enter(&mca->mca_intrlock);

	if (mca_fm_isoffline(mca) || !(mca_isinten(mca))) {
		mutex_exit(&mca->mca_intrlock);
#ifndef LINUX
		if (mca->mca_intrstats) {
			KIOIP(mca)->intrs[KSTAT_INTR_SPURIOUS]++;
		}
#endif
		return (DDI_INTR_UNCLAIMED);
	}

	status = MCA_INVALID_CSR16;	/* Insure valid read */
	status = GETCSR16(mca, CSR_INTSTAT);
	PUTCSR16(mca, CSR_INTSTAT, status);

	/*
	 * Perform an extra pci read to check that the clear interrupt status
	 * register write has completed.  This will insure the de-assertion
	 * of the interrupt in a timely manner.
	 */
	(void) GETCSR16(mca, CSR_INTSTAT);

	DBG(mca, DINTR, "Interrupted! status = %x\n", status);

	if (status == 0) {
		mutex_exit(&mca->mca_intrlock);
#ifndef LINUX
		if (mca->mca_intrstats) {
			KIOIP(mca)->intrs[KSTAT_INTR_SPURIOUS]++;
		}
#endif
		return (DDI_INTR_UNCLAIMED);
	}
#ifndef LINUX
	if (mca->mca_intrstats) {
		KIOIP(mca)->intrs[KSTAT_INTR_HARD]++;
	}
#endif
	if (status & (INTSTAT_CTL | INTSTAT_SECCMD)) {
		DBG(mca, DINTR, "command interrupted");
		/* command completion, signal waiter */
		mutex_enter(&mca->mca_ctllock);
		mca->mca_ctlint++;
		cv_broadcast(&mca->mca_ctlcv);
		mutex_exit(&mca->mca_ctllock);
	}
	if (status & INTSTAT_OMDONE) {
		DBG(mca, DINTR, "OM ring interrupted");
		mutex_enter(&mca->mca_ring_om.mr_lock);
		mca_reclaim(&mca->mca_ring_om);
		mutex_exit(&mca->mca_ring_om.mr_lock);
	}
	if (status & INTSTAT_CADONE) {
		DBG(mca, DINTR, "CA ring interrupted");
		mutex_enter(&mca->mca_ring_ca.mr_lock);
		mca_reclaim(&mca->mca_ring_ca);
		mutex_exit(&mca->mca_ring_ca.mr_lock);
	}
	if (status & INTSTAT_CBDONE) {
		DBG(mca, DINTR, "CB ring interrupted");
		mutex_enter(&mca->mca_ring_cb.mr_lock);
		mca_reclaim(&mca->mca_ring_cb);
		mutex_exit(&mca->mca_ring_cb.mr_lock);
	}
	if (status & INTSTAT_LOGLOST) {
		mca_error(mca, "On-device log buffer full; "
		    "messages may be lost");
	}
	if (status & INTSTAT_LOG) {
		DBG(mca, DINTR, "Message log interrupted");
		mutex_enter(&mca->log.lock);
		cv_broadcast(&mca->log.cv);
		mutex_exit(&mca->log.lock);
		mca_getlog(mca);
	}
	if (status & INTSTAT_ENABLED) {
		DBG(mca, DINTR, "Enable interrupted");
		mutex_enter(&mca->log.lock);
		cv_broadcast(&mca->log.cv);
		mutex_exit(&mca->log.lock);
	}
	if (status & INTSTAT_FRI_IND) {
		DBG(mca, DINTR, "Firmware Request/Indication received");
		mca_fri_ind(mca);
	}
	mutex_exit(&mca->mca_intrlock);

	if (status & INTSTAT_FAULT) {
		mutex_enter(&mca->fm_lock);
		mca_fm_set_hw_fault(mca);
		mca_fm_setdeaf(mca);
		mutex_exit(&mca->fm_lock);
		/*
		 * If this fault interrupt was received as a result of a
		 * hardware failure the correct ereport will have already
		 * been posted.  Otherwise assume a firmware reporting fault
		 * (defect).
		 */
		mca_failure(mca, MCA_FMA_FW_NO_REPORT_ID,
		    "Fault interrupt received, halting device");
	}

	DBG(mca, DINTR, "interrupt done");
	return (DDI_INTR_CLAIMED);
}

/*
 * Initialize hardware settings.  Note that this has as its side
 * effect, enabling interrupts on the device.  So everything else
 * must be ready to go before calling this function.  (I.e. the
 * rings have to be setup, etc.)
 */
static void
mca_inithw(mca_t *mca)
{
	int32_t		status = 0;
	uint8_t		logmask;
	uint8_t		logintmask;

	/* Set driver information registers */
	PUTCSR32(mca, CSR_DRV_IFVERSION, MCA_IF_VERSION);
	PUTCSR32(mca, CSR_DRV_INSTANCE, ddi_get_instance(mca->mca_dip));
	PUTCSR64(mca, CSR_DRV_DOM, mca_get_domain());

	/* write the base addresses of our rings */
	PUTCSR32(mca, CSR_OMRINGADDR, mca->mca_ring_om.mr_paddr);
	PUTCSR32(mca, CSR_OMCOMPADDR, ((mca->mca_ring_om.mr_paddr) +
	    sizeof (mca_submission_t) * RINGSIZE));

	PUTCSR32(mca, CSR_CARINGADDR, mca->mca_ring_ca.mr_paddr);
	PUTCSR32(mca, CSR_CACOMPADDR, ((mca->mca_ring_ca.mr_paddr) +
	    sizeof (mca_submission_t) * RINGSIZE));

	PUTCSR32(mca, CSR_CBRINGADDR, mca->mca_ring_cb.mr_paddr);
	PUTCSR32(mca, CSR_CBCOMPADDR, ((mca->mca_ring_cb.mr_paddr) +
		sizeof (mca_submission_t) * RINGSIZE));

	status = (RINGSIZEVAL) | ((RINGSIZEVAL) << 4) | ((RINGSIZEVAL) << 8);

	/* crypto configuration setup */
	PUTCSR32(mca, CSR_CRYPTOCONF, status);

	/* initialize head and tail registers */
	PUTCSR16(mca, CSR_CAHEAD, 0);
	PUTCSR16(mca, CSR_CATAIL, 0);
	PUTCSR16(mca, CSR_CBHEAD, 0);
	PUTCSR16(mca, CSR_CBTAIL, 0);
	PUTCSR16(mca, CSR_OMHEAD, 0);
	PUTCSR16(mca, CSR_OMTAIL, 0);
	PUTCSR16(mca, CSR_CACOMPHEAD, 0);
	PUTCSR16(mca, CSR_CACOMPTAIL, 0);
	PUTCSR16(mca, CSR_CBCOMPHEAD, 0);
	PUTCSR16(mca, CSR_CBCOMPTAIL, 0);
	PUTCSR16(mca, CSR_OMCOMPHEAD, 0);
	PUTCSR16(mca, CSR_OMCOMPTAIL, 0);

	/* initialize message log ring */
	PUTCSR8(mca, CSR_LOGRINGSZ, mca->mca_pagesize / sizeof (mca_log_t));
	PUTCSR8(mca, CSR_LOGRINGHEAD, 0);
	PUTCSR8(mca, CSR_LOGRINGTAIL, 0);
	PUTCSR32(mca, CSR_LOGRINGADDR, mca->mca_log_buff.paddr);

	/* Initialize the FRI data structure. */
	if (MCA_FW_IF_COMP_VERSION(mca) < MCA_IF_VERSION_CHAIN) {
		/*
		 * If FW is an old version, we only support upto 4KB,
		 * and therefore no chaining.
		 */
		PUTCSR32(mca, CSR_FRI_ADDRESS, mca->mca_fri_buff.paddr);
		PUTCSR16(mca, CSR_FRI_MAXLEN, mca->mca_pagesize);
		PUTCSR16(mca, CSR_FRI_FLAG, 0);
	} else if (mca->mca_fri_chain_buff.bsize == 0) {
		/*
		 * If the FRI buffer is contiguous in memory, no chaining
		 * is required.
		 */
		PUTCSR32(mca, CSR_FRI_ADDRESS, mca->mca_fri_buff.paddr);
		PUTCSR16(mca, CSR_FRI_MAXLEN, mca->mca_fri_buff.bsize);
		PUTCSR16(mca, CSR_FRI_FLAG, 0);
	} else {
		/*
		 * If the FRI buffer is not contiguous in memory, chaining
		 * is required.
		 */
		PUTCSR32(mca, CSR_FRI_ADDRESS, mca->mca_fri_chain_buff.paddr);
		PUTCSR16(mca, CSR_FRI_MAXLEN, mca->mca_fri_chain_buff.bsize);
		PUTCSR16(mca, CSR_FRI_FLAG, CSR_FRIF_CHAINED);
	}

	/*
	 * Check for "fwlogmask" and "fwlogintmask" in mca.conf and set log
	 * level and interrupt level accordingly
	 */
	logmask = ddi_getprop(DDI_DEV_T_ANY, mca->mca_dip,
		    DDI_PROP_DONTPASS, "fwlogmask", DEFAULT_LOGMASK);
	logintmask = ddi_getprop(DDI_DEV_T_ANY, mca->mca_dip,
		    DDI_PROP_DONTPASS, "fwlogintmask", DEFAULT_LOGINTMASK);
	PUTCSR8(mca, CSR_LOGMASK, LOGMASK_UPTO(logmask));
	PUTCSR8(mca, CSR_LOGINTMASK, LOGMASK_UPTO(logintmask));
	PUTCSR32(mca, CSR_SCRATCHADDR, mca->mca_diag_buff.paddr);
	PUTCSR32(mca, CSR_SCRATCHSZ, mca->mca_diag_buff.bsize);
	DBG(mca, DBRINGUP, "scratch phys = 0x%x, kern = 0x%p, sz = %d",
	    mca->mca_diag_buff.paddr, mca->mca_diag_buff.kaddr,
	    mca->mca_diag_buff.bsize);
}

/*
 * -----------------------------------------------------------------
 * mca_ctlwait
 *
 * Wait until the Mars device responds to our control command.
 * If interrupts are enabled, wait until the variable <mca_ctlint>
 * is non-zero, or until <ticks> is decremented to zero.
 *
 * If cv_timedwait() returns -1, we've timed out, we're done waiting.
 *
 * If cv_timedwait returns a number >0, one of two things happended:
 * 1) We were signalled (the common case).
 * 2) cv_timedwait() returned prematurely, for whatever reason.
 *
 * In both cases, cv_timedwait() returns the number of ticks left in our
 * timeout.  That is, we may use this number the next time we call
 * cv_timedwait().
 *
 * If we returned prematurely, we will call cv_timedwait() again,
 * using as our timeout value [ddi_get_lbolt() + <ticks>], where <ticks>
 * IS THE VALUE RETURNED BY cv_timedwait().  Eventually, we will time
 * out or see the condition we were looking for.
 *
 * Parameters:
 *   clock_t ticks - How long to wait for the device to respond to us
 *   before giving up and returning.
 *
 */
int
mca_ctlwait(
	mca_t *mca,
	clock_t ticks)
{
	int state = ETIME;

	mutex_enter(&mca->mca_ctllock);

	if (mca_isinten(mca)) {
		DBG(mca, DBRINGUP, "ctlwait: interrupts enabled.");
		while (ticks > 0) {
			ticks = cv_timedwait(&mca->mca_ctlcv,
			    &mca->mca_ctllock, ddi_get_lbolt() + ticks);
			if (mca->mca_ctlint) {
				state = 0; break;
			} else if (ticks < 0) {
				break; /* ETIME. */
			}
			/* If <ticks> > 0, it's equal to the time left. */
		}
	} else {
		DBG(mca, DINTR, "ctlwait: polling for completion.");
		while (ticks > 0) {
			uint16_t status = 0;	/* Insure valid read */
#ifdef LINUX
			mutex_exit(&mca->mca_ctllock);
			delay(1);
			mutex_enter(&mca->mca_ctllock);
#else
			delay(1);
#endif
			ticks--;

			status = GETCSR16(mca, CSR_INTSTAT);
			PUTCSR16(mca, CSR_INTSTAT, status);

			/* These checks are ordered. */
			if (status & INTSTAT_FAULT) {
				state = EIO; break;
			}
			/* If there's a log message, go get it. */
			if (status & INTSTAT_LOG) {
				mca_getlog(mca);
			}
			/* The firmware responded, or somebody wants us to */
			/* wake up - either way, we're done waiting. */
			if ((status & (INTSTAT_CTL | INTSTAT_ENABLED)) ||
			    mca->mca_ctlint) {
				state = 0;
				break;
			}
		} /* while(ticks > 0) */
	}

	mutex_exit(&mca->mca_ctllock);

	switch (state) {
	case EIO:
		mca_error(mca, "Device faulted."); break;
	case ETIME:
		mca_error(mca, "Device control command timed out."); break;
	default: break;
	}

	return (state);
}

/*
 * -----------------------------------------------------------------
 * mca_msgwait
 *
 * Wait until the Mars device has sent us all the messages it
 * wants to.  In other words, flush its message log.
 *
 * Parameters:
 *   clock_t ticks - The number of ticks the device is silent,
 *   before we assume that it is done, and so are we.  That is,
 *   if we receive no message from the device in <ticks> ticks,
 *   we return.
 *
 *   <ticks> should probably be no more than 1 second long.
 *
 */
static int
mca_msgwait(
	mca_t *mca,
	clock_t ticks)
{

	mutex_enter(&mca->log.lock);

	if (mca_isinten(mca)) {	/* If interrupts are enabled. */
		DBG(mca, DBRINGUP, "waiting for a message interrupt");
		for (;;) {
			/* If no messages were received, we will time out. */
			if (cv_timedwait(&mca->log.cv, &mca->log.lock,
			    ddi_get_lbolt() + ticks) < 0)
				break;
			if (mca->log.interrupt)
				break;
		}
	} else { /* Interrupts are disabled, so poll. */
		int quiet = 0;

		DBG(mca, DBRINGUP, "polling for messages");
		for (;;) {
			uint16_t status = 0;		/* Insure valid read */
#ifdef LINUX
			mutex_exit(&mca->log.lock);
			delay(1);
			mutex_enter(&mca->log.lock);
#else
			delay(1);
#endif
			status = GETCSR16(mca, CSR_INTSTAT);
			PUTCSR16(mca, CSR_INTSTAT, status);
			if (status & INTSTAT_FAULT) {
				mutex_exit(&mca->log.lock);
				mca_error(mca, "Device faulted.");
				return (EIO);
			}
			if (status & INTSTAT_LOG) {
				mca_getlog(mca);
				quiet = 0;
			}
			/* The firmware was quiet long enough, or somebody */
			/* wants us to wake up - either way, we're done. */
			else if (++quiet == ticks || mca->log.interrupt) {
				break;
			}
		}
	}

	mutex_exit(&mca->log.lock);

	return (0);
}

int
mca_create_dma_chain(mca_t *mca, ddi_dma_handle_t handle, size_t bsize,
    ddi_dma_cookie_t *cookie, unsigned nc, mca_dma_buffinfo_t *chain_buff)
{
	size_t			chain_size;
	mca_dma_chain_hdr_t	*hdr;
	mca_dma_chain_link_t	*chain;
	int			i;

	/* Insure dma chain buffer is big enough to hold chain */
	chain_size = (chain_buff->bsize - sizeof (mca_dma_chain_hdr_t)) /
	    sizeof (mca_dma_chain_link_t);
	DBG(mca, DBRINGUP, "mca_create_dma_chain> chain_size = %d, nc = %d",
		chain_size, nc);
	if (nc > chain_size) {
		mca_failure(mca, MCA_FMA_SW_PROBLEM_ID,
		    "Insufficient memory for DMA chain, needed = %d, "
		    "available = %d", nc, chain_size);
		return (ENOMEM);
	}

	/* Create DMA chain */
	hdr = (mca_dma_chain_hdr_t *)chain_buff->kaddr;
	chain = (mca_dma_chain_link_t *)
	    (chain_buff->kaddr + sizeof (mca_dma_chain_hdr_t));
	PUTBUF32(&(hdr->tsize), bsize);
	PUTBUF32(&(hdr->vsize), bsize);
	PUTBUF32(&(hdr->links), nc);
	for (i = 0; i < nc; i++) {
		PUTBUF32(&(chain[i].address), cookie->dmac_address);
		PUTBUF32(&(chain[i].bsize), cookie->dmac_size);

		if (i < nc-1) {
			ddi_dma_nextcookie(handle, cookie);
		}
	}

	ddi_dma_sync(chain_buff->dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	return (0);
}

/*
 * Setup the DMA chains for the OM ring. Note that OM ring expects the chain
 * to be an array of mca_dma_chain_link_t (different from CA and CB ring)
 * following mca_dma_chain_hdr_t.
 * Args:
 *  'chain' - the data chains in the format that CA/CB expects.
 *  'inlen' - total data size
 *  'descs' - the beginning of the chain header for OM (output)
 *  'chainlen' - size of chains (output)
 */
int
mca_create_om_chain(mca_chain_t *chain, uint32_t inlen,
    caddr_t descs, uint32_t *chainlen)
{
	caddr_t			deschead = chain->mc_desc_head;
	mca_dma_chain_hdr_t	*chainhdr = (mca_dma_chain_hdr_t *)descs;
	mca_dma_chain_link_t	*chaincursor;
	uint32_t		len;
	int			nc = 0; /* numburs of chains */

#ifdef LINUX
	if (inlen > chain->mc_length) {
		mca_error(NULL, "mca_create_om_chain: the input length %d "
		    " is larger than allowed %d on Linux\n",
		    inlen, chain->mc_length);
		return (EINVAL);
	}
#endif

	/* total buf size and valid data size are the same: inlen */
	PUTBUF32(&(chainhdr->tsize), inlen);
	PUTBUF32(&(chainhdr->vsize), inlen);

	/* setup the chain for the first buffer */
	len = min(inlen, (uint32_t)chain->mc_length);
	chaincursor = (mca_dma_chain_link_t *)(chainhdr + 1);
	PUTBUF32(&(chaincursor->bsize), len);
	PUTBUF32(&(chaincursor->address), chain->mc_paddr);
	inlen -= len;
	chaincursor++;
	nc++;

	/* setup the rest of the chains */
	while (inlen > 0) {
		len = min(inlen,
		    GETBUF32((uint32_t *)(deschead + DESC_LENGTH)));
		PUTBUF32(&(chaincursor->bsize), len);
		PUTBUF32(&(chaincursor->address),
		    GETBUF32((uint32_t *)(deschead + DESC_BUFADDR)));
		inlen -= len;
		chaincursor++;
		deschead += DESC_SIZE;
		nc++;
	}

	PUTBUF32(&(chainhdr->links), nc);
	*chainlen = ((caddr_t)chaincursor - descs);

	return (0);
}


void
mca_enableinterrupts(mca_t *mca, int isbusy)
{
	uint16_t	status;

	DBG(mca, DINTR, "enabling interrupts");

	/* Mask all MU interrupts */
	PUTCSR32(mca, CSR_OB_INT_MASK, MU_OUT_ALL_INTS);

	/* Clear all MU interrupts */
	PUTCSR32(mca, CSR_OB_DOORBELL, MU_DOORBELL_ALL_INTS);

	/* clear CSR interrupt bits */
	status = GETCSR16(mca, CSR_INTSTAT);
	PUTCSR16(mca, CSR_INTSTAT, status);

	/* set interrupt enabled flag */
	mutex_enter(&mca->fm_lock);
	mca_setinten(mca);
	mutex_exit(&mca->fm_lock);

	/* Only enable MU doorbell interrupts */
	PUTCSR32(mca, CSR_OB_INT_MASK, ~MU_OUT_DB_BIT);

	/* enable INTx interrupts from the ATU */
	pci_config_put16(mca->mca_pcihandle, PCI_CONF_COMM,
	    pci_config_get16(mca->mca_pcihandle, PCI_CONF_COMM)
	    & ~PCI_COMM_INTX_DISABLE);

	/* must hold control interface when calling hostready */
	if (!isbusy) {
		mca_ctlbusy(mca);
	}
	delay(1);
	(void) mca_hostready(mca, 1);

	if (!isbusy) {
		mca_ctlunbusy(mca);
	}
}

void
mca_disableinterrupts(mca_t *mca, int isbusy)
{
	uint16_t	status;

	DBG(mca, DINTR, "disabling interrupts");

	/* disable INTx interrupts to guard against spurious ints */
	pci_config_put16(mca->mca_pcihandle, PCI_CONF_COMM,
	    pci_config_get16(mca->mca_pcihandle, PCI_CONF_COMM) |
	    PCI_COMM_INTX_DISABLE);

	/* Mask all MU interrupts */
	PUTCSR32(mca, CSR_OB_INT_MASK, MU_OUT_ALL_INTS);

	/* Clear all pending MU interrupts */
	PUTCSR32(mca, CSR_OB_DOORBELL, MU_DOORBELL_ALL_INTS);

	/* clear CSR interrupt bits */
	status = GETCSR16(mca, CSR_INTSTAT);
	PUTCSR16(mca, CSR_INTSTAT, status);

	/* clear interrupt enabled flag */
	mutex_enter(&mca->fm_lock);
	mca_unsetinten(mca);
	mutex_exit(&mca->fm_lock);

#ifdef LINUX
	drv_usecwait(drv_hztousec(1));
#else
	delay(1);
#endif
	/* must hold control interface when calling hostready */
	if (!isbusy) {
		mca_ctlbusy(mca);
	}
	(void) mca_hostready(mca, 0);
	if (!isbusy) {
		mca_ctlunbusy(mca);
	}
}

int
mca_fwupdate(mca_t *mca, int fw_select, char *data, size_t size)
{
	ddi_dma_cookie_t	cookie;
	unsigned		nc;
	mca_dma_chain_hdr_t	*hdr;
	int			rv;
	uint16_t		fwstat;

	/*
	 * Don't even attempt to update the firmware on an owned card when
	 * running a non-debug driver.  This gives a slightly more meaningful
	 * error message in scadiag.
	 */
	if ((fw_select == MCAFWUPDATE_FW) && (mca_isowned(mca))) {
#ifdef DEBUG
		DBG(mca, DWARN, "Upgrading firmware on owned card");
#else
		return (EPERM);
#endif /* DEBUG */
	}

	/* mark us busy to lockout drains */
	mca_ctlbusy(mca);

	if (ddi_dma_addr_bind_handle(mca->mca_ctldmah, NULL, data, size,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING,
	    DDI_DMA_SLEEP, NULL, &cookie, &nc) != DDI_DMA_MAPPED) {
		DBG(mca, DWARN, "unable to map fwupdate data for DMA");
		mca_ctlunbusy(mca);
		return (EIO);
	}
	mca->mca_ctlcmd = FWCTL_UPGRADE;
	ddi_dma_sync(mca->mca_ctldmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	/*
	 * Check the number of returned cookies to see if we are bound to
	 * contiguous memory or a scatter gather list.  If it is a scatter
	 * gather list and the firmware is not capable of processing dma
	 * chains, copy the data into the contiguous diagnostics buffer.
	 */
	if (nc == 1) {
		/* Contiguous memory, load buffer size and address directly */
		PUTCSR32(mca, CSR_FWCTLSZ, size);
		PUTCSR32(mca, CSR_FWCTLDATA, cookie.dmac_address);

	} else {
		/* Create DMA chain */
		rv = mca_create_dma_chain(mca, mca->mca_ctldmah, size,
		    &cookie, nc, &mca->mca_ctl_chain_buff);
		if (rv) {
			(void) ddi_dma_unbind_handle(mca->mca_ctldmah);
			mca->mca_ctlcmd = FWCTL_NULL;
			mca_ctlunbusy(mca);
			return (rv);
		}
		/* Load chain buffer size and address */
		hdr = (mca_dma_chain_hdr_t *)mca->mca_ctl_chain_buff.kaddr;
		size = MCA_DMA_CHAIN_SIZE(hdr);
		PUTCSR32(mca, CSR_FWCTLSZ, MCA_SET_DMA_CHAIN_FLAG(size));
		PUTCSR32(mca, CSR_FWCTLDATA, mca->mca_ctl_chain_buff.paddr);
	}

	PUTCSR16(mca, CSR_FWSTAT, 1);	/* force failure on timeout */

	switch (fw_select) {
	case MCAFWUPDATE_BS:
		PUTCSR16(mca, CSR_FWCTL, FWCTL_UPGRADE_BS);
		break;
	default:
		PUTCSR16(mca, CSR_FWCTL, FWCTL_UPGRADE);
		break;
	}

	/* clear the interrupt bit */
	PUTCSR16(mca, CSR_INTSTAT, INTSTAT_CTL);
	/* write the kick register */
	DBG(mca, DBRINGUP, "kicking firmware update signal");
	PUTCSR16(mca, CSR_SIGNAL, SIGNAL_CTL);

	/*
	 * now wait for the job to complete -- we have a 5 minute
	 * timer on this, as well.
	 */
	if (mca_ctlwait(mca, drv_usectohz(5 * 60 * SECOND)) != 0) {
		(void) ddi_dma_unbind_handle(mca->mca_ctldmah);
		mca->mca_ctlcmd = FWCTL_NULL;
		mca_ctlunbusy(mca);
		mca_failure(mca, MCA_FMA_TO_CTL_ID,
		    "timeout updating firmware");
		return (ETIME);
	}

	fwstat = MCA_INVALID_CSR16;	/* Insure valid read */
	fwstat = GETCSR16(mca, CSR_FWSTAT);

	(void) ddi_dma_unbind_handle(mca->mca_ctldmah);
	mca->mca_ctlcmd = FWCTL_NULL;
	mca_ctlunbusy(mca);

	if (mca_fm_isfailed(mca)) {
		DBG(mca, DWARN, "device failure encountered during update");
		return (EIO);
	}

	DBG(mca, DBRINGUP, "firmware upgrade complete, status = %d", fwstat);

	return (fwstat ? EIO : 0);
}

int
mca_fdi_dl(
	mca_t *mca,
	char *data,
	size_t size)
{
	ddi_dma_cookie_t	cookie;
	unsigned		nc;
	uint16_t		fwstat;
	int			rv;
	mca_dma_chain_hdr_t	*hdr;

	/* mark us busy to lockout drains */
	mca_ctlbusy(mca);

	if (ddi_dma_addr_bind_handle(mca->mca_ctldmah, NULL, data, size,
		DDI_DMA_WRITE | DDI_DMA_STREAMING,
		DDI_DMA_SLEEP, NULL, &cookie, &nc) != DDI_DMA_MAPPED) {
		DBG(mca, DWARN, "unable to map download data for DMA");
		mca_ctlunbusy(mca);
		return (EIO);
	}
	mca->mca_ctlcmd = FWCTL_DOWNLOAD;

	ddi_dma_sync(mca->mca_ctldmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	/*
	 * Check the number of returned cookies to see if we are bound to
	 * contiguous memory or a scatter gather list.
	 */
	if (nc == 1) {
		/* Contiguous memory, load buffer size and address directly */
		PUTCSR32(mca, CSR_FWCTLSZ, size);
		PUTCSR32(mca, CSR_FWCTLDATA, cookie.dmac_address);

	} else {
		/* Create DMA chain */
		rv = mca_create_dma_chain(mca, mca->mca_ctldmah, size,
		    &cookie, nc, &mca->mca_ctl_chain_buff);
		if (rv) {
			(void) ddi_dma_unbind_handle(mca->mca_ctldmah);
			mca->mca_ctlcmd = FWCTL_NULL;
			mca_ctlunbusy(mca);
			return (rv);
		}
		/* Load chain buffer size and address */
		hdr = (mca_dma_chain_hdr_t *)mca->mca_ctl_chain_buff.kaddr;
		size = MCA_DMA_CHAIN_SIZE(hdr);
		PUTCSR32(mca, CSR_FWCTLSZ, MCA_SET_DMA_CHAIN_FLAG(size));
		PUTCSR32(mca, CSR_FWCTLDATA, mca->mca_ctl_chain_buff.paddr);
	}

	PUTCSR16(mca, CSR_FWSTAT, 1);	/* force failure on timeout */
	PUTCSR16(mca, CSR_FWCTL, FWCTL_DOWNLOAD);

	/* clear the interrupt bit */
	PUTCSR16(mca, CSR_INTSTAT, INTSTAT_CTL);

	/* write the kick register */
	DBG(mca, DBRINGUP, "kicking firmware update signal");
	PUTCSR16(mca, CSR_SIGNAL, SIGNAL_CTL);

/*
 * now wait for the job to complete -- we have a 2 minute
 * timer on this.
 */
	if (mca_ctlwait(mca, drv_usectohz(2 * 60 * SECOND)) != 0) {
		(void) ddi_dma_unbind_handle(mca->mca_ctldmah);
		mca->mca_ctlcmd = FWCTL_NULL;
		mca_ctlunbusy(mca);
		mca_failure(mca, MCA_FMA_TO_CTL_ID,
		    "timeout downloading data to firmware");
		return (ETIME);
	}

	fwstat = MCA_INVALID_CSR16;	/* Insure valid read */
	fwstat = GETCSR16(mca, CSR_FWSTAT);

	(void) ddi_dma_unbind_handle(mca->mca_ctldmah);
	mca->mca_ctlcmd = FWCTL_NULL;
	mca_ctlunbusy(mca);

	if (mca_fm_isfailed(mca)) {
		DBG(mca, DWARN, "device failure encountered during download");
		return (EIO);
	}

	DBG(mca, DBRINGUP, "download complete, status = %d", fwstat);
	return (fwstat ? EIO : 0);
}

int
mca_getcsr(mca_t *mca, int offset, int width, uint64_t *valp)
{
	int	rv = 0;
	/*
	 * the trick below checks for proper alignment of the offset
	 */
	if (((width / 8) - 1) & offset) {
		/* illegal address */
		DBG(mca, DWARN, "bad CSR register alignment");
		return (EINVAL);
	}

	mca_ctlbusy(mca);
	*valp = MCA_INVALID_CSR64;	/* Insure valid read */
	switch (width) {
	case 8:
		*valp = GETCSR8(mca, offset);
		break;
	case 16:
		*valp = GETCSR16(mca, offset);
		break;
	case 32:
		*valp = GETCSR32(mca, offset);
		break;
	case 64:
		*valp = GETCSR64(mca, offset);
		break;
	default:
		rv = EINVAL;
		DBG(mca, DWARN, "invalid CSR register width");
		break;
	}

	mca_ctlunbusy(mca);

	return (rv);
}

int
mca_getpci(mca_t *mca, int offset, int width, uint64_t *valp)
{
	int	rv = 0;

	/*
	 * the trick below checks for proper alignment of the offset
	 */
	if (((width / 8) - 1) & offset) {
		/* illegal address */
		DBG(mca, DWARN, "bad PCI register alignment");
		return (EINVAL);
	}

	mca_ctlbusy(mca);
	*valp = MCA_INVALID_CSR64;	/* Insure valid read */
	switch (width) {
	case 8:
		*valp = GETPCI8(mca, offset);
		break;
	case 16:
		*valp = GETPCI16(mca, offset);
		break;
	case 32:
		*valp = GETPCI32(mca, offset);
		break;
	case 64:
		*valp = GETPCI64(mca, offset);
		break;
	default:
		DBG(mca, DWARN, "invalid PCI register width");
		rv = EINVAL;
		break;
	}

	mca_ctlunbusy(mca);

	return (rv);
}

int
mca_putcsr(mca_t *mca, int offset, int width, uint64_t val)
{
	int	rv = 0;
	if (((width / 8) - 1) & offset) {
		DBG(mca, DWARN, "bad CSR register alignment");
		return (EINVAL);
	}

	mca_ctlbusy(mca);

	switch (width) {
	case 8:
		PUTCSR8(mca, offset, (uint8_t)(val & 0xff));
		break;
	case 16:
		PUTCSR16(mca, offset, (uint16_t)(val & 0xffff));
		break;
	case 32:
		PUTCSR32(mca, offset, (uint32_t)(val & 0xffffffffU));
		break;
	case 64:
		PUTCSR64(mca, offset, val);
		break;
	default:
		DBG(mca, DWARN, "invalid CSR register width");
		rv = EINVAL;
		break;
	}

	mca_ctlunbusy(mca);

	return (rv);
}

int
mca_putpci(mca_t *mca, int offset, int width, uint64_t val)
{
	int	rv = 0;
	if (((width / 8) - 1) & offset) {
		DBG(mca, DWARN, "bad PCI register alignment");
		return (EINVAL);
	}

	mca_ctlbusy(mca);

	switch (width) {
	case 8:
		PUTPCI8(mca, offset, (uint8_t)(val & 0xff));
		break;
	case 16:
		PUTPCI16(mca, offset, (uint16_t)(val & 0xffff));
		break;
	case 32:
		PUTPCI32(mca, offset, (uint32_t)(val & 0xffffffffU));
		break;
	case 64:
		PUTPCI64(mca, offset, val);
		break;
	default:
		DBG(mca, DWARN, "invalid PCI register width");
		rv = EINVAL;
		break;
	}

	mca_ctlunbusy(mca);

	return (rv);
}

int
mca_diagnostics(mca_t *mca)
{
	uint16_t	fwstat;

	mca_ctlbusy(mca);

	PUTCSR16(mca, CSR_FWSTAT, 1);	/* force failure on timeout */
	PUTCSR32(mca, CSR_FWCTLSZ, 0);
	/* this means one iteration, the iteration count is in the high word */
	PUTCSR32(mca, CSR_FWCTLDATA, 0x00010000);
	PUTCSR16(mca, CSR_FWCTL, FWCTL_DIAG);

	/* clear the interrupt bit */
	PUTCSR16(mca, CSR_INTSTAT, INTSTAT_CTL);
	/* write the kick register */
	DBG(mca, DBRINGUP, "kicking diagnostic signal");
	PUTCSR16(mca, CSR_SIGNAL, SIGNAL_CTL);

	/*
	 * now wait for the job to complete -- we have a one minute
	 * timer on this, as well.
	 */
	if (mca_ctlwait(mca, drv_usectohz(60 * SECOND)) != 0) {
		mca_ctlunbusy(mca);
		mca_failure(mca, MCA_FMA_TO_CTL_ID,
		    "timeout waiting for diagnostics");
		return (ETIME);
	}
	fwstat = MCA_INVALID_CSR16;	/* Insure valid read */
	fwstat = GETCSR16(mca, CSR_FWSTAT);
	if (fwstat != 0) {
		mca_ctlunbusy(mca);
		mca_error(mca, "Diagnostics completed with failure, "
		    "result = 0x%04x", GETCSR16(mca, CSR_POSTRESULT));
		return (EIO);
	}

	mca_ctlunbusy(mca);

	if (mca_fm_isfailed(mca)) {
		DBG(mca, DWARN, "device failure encountered during update");
		return (EIO);
	}

	DBG(mca, DBRINGUP, "Diagnostics OK");
	return (0);
}

int
mca_zeroize(mca_t *mca)
{
	int		rv;
	uint32_t	config;
	uint16_t	status;

	/* drain and block all new requests during zeroize */
	if ((rv = mca_drain(mca, MCA_NORMAL_DRAIN)) != 0) {
		return (rv);
	}

	/* turn off "ctldrain", since we don't want to block ourself */
	mca_undrainctl(mca);

	mca_ctlbusy(mca);

	/* unregister the provider to prevent jobs while we're zeroizing */
	if (mca_hw_provider_unregister(mca) != CRYPTO_SUCCESS) {
		mca_ctlunbusy(mca);
		rv = EIO;
		goto exit;
	}

	PUTCSR16(mca, CSR_FWSTAT, 1);	/* force failure on timeout */
	PUTCSR32(mca, CSR_FWCTLSZ, 0);

	/* this means one iteration, the iteration count is in the high word */
	PUTCSR16(mca, CSR_FWCTL, FWCTL_ZEROIZE);

	/* clear the interrupt bit */
	PUTCSR16(mca, CSR_INTSTAT, INTSTAT_CTL);
	/* write the kick register */
	DBG(mca, DBRINGUP, "kicking zeroize signal");
	PUTCSR16(mca, CSR_SIGNAL, SIGNAL_CTL);

	/*
	 * now wait for the job to complete -- we have a one minute
	 * timer on this, as well.
	 */
	if (mca_ctlwait(mca, drv_usectohz(60 * SECOND)) != 0) {
		mca_ctlunbusy(mca);
		mca_failure(mca, MCA_FMA_TO_CTL_ID,
		    "timeout waiting for zeroize");
		rv = ETIME;
		goto exit;
	}
	status = MCA_INVALID_CSR16;	/* Insure valid read */
	status = GETCSR16(mca, CSR_FWSTAT);
	if (status != 0) {
		mca_ctlunbusy(mca);
		mca_failure(mca, MCA_FMA_BAD_DATA_ID,
		    "zeroize failure, result = 0x%04x",
		    GETCSR16(mca, CSR_POSTRESULT));
		rv = EIO;
		goto exit;
	}

	/* allow DBM requests now, but continue to block kCF */
	mca_undrain_dbm(mca);

	/*
	 * We have to reset the device so it figures out its new state.
	 */
	/* check if device wants reset */
	config = INVALID_CSR_CONFIG;	/* Insure valid read */
	config = GETCSR32(mca, CSR_CONFIG);

	if ((config & CONFIG_FWSTATE) == FWSTATE_RESET) {
		/* device wants us to reset it */
		mca_disableinterrupts(mca, 1);
		/*
		 * drop busy flag while we are doing this, it is acquired
		 * again by masterstart...
		 */
		mca_ctlunbusy(mca);
		if (mca_masterstart(mca) != DDI_SUCCESS) {
			/* Ereport already filed in mca_masterstart */
			mca_failure(mca, MCA_FMA_NO_CLASS_ID,
			    "device error during post-zeroize reset");
			rv = EIO;
			goto exit;
		}
		/* reacquire busy flag while we chat with device */
		mca_ctlbusy(mca);
		/* refresh config register value */
		config = INVALID_CSR_CONFIG;	/* Insure valid read */
		config = GETCSR32(mca, CSR_CONFIG);
		/* reenable interrupts */
		mca_enableinterrupts(mca, 1);
	}

	mca_ctlunbusy(mca);

	/* allow all requests, including kCF, now */
	mca_undrain(mca);

	if (mca_fm_isfailed(mca)) {
		DBG(mca, DWARN, "device failure encountered during zeroize");
		rv = EIO;
		goto exit;
	}

	rv = 0;
	DBG(mca, DBRINGUP, "Zeroize OK");
exit:

	return (rv);
}

int
mca_seccmd(mca_t *mca, char *data, size_t size, size_t *used, unsigned flags)
{
	ddi_dma_cookie_t	cookie;
	unsigned		nc;
	int			rv = 0;
	int			rv_supplemental = 0;
	uint32_t		config;
	uint32_t		failsafe = mca_fm_isfailsafe(mca);
	mca_dma_chain_hdr_t	*hdr;
	int			count = 0;


	mca_ctlbusy(mca);

	if (ddi_dma_addr_bind_handle(mca->mca_ctldmah, NULL, data, size,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL, &cookie, &nc) != DDI_DMA_MAPPED) {
		mca_ctlunbusy(mca);
		DBG(mca, DWARN, "unable to map seccmd data for DMA");
		return (EIO);
	}
	mca->mca_ctlcmd = FWCTL_SECCMD;

	ddi_dma_sync(mca->mca_ctldmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	/*
	 * Check the number of returned cookies to see if we are bound to
	 * contiguous memory or a scatter gather list.  If it is a scatter
	 * gather list and the firmware is not capable of processing dma
	 * chains, copy the data into the contiguous diagnostics buffer.
	 */
	if (nc == 1) {
		/* Contiguous memory, load buffer size and address directly */
		PUTCSR32(mca, CSR_SECCMDSZ, (uint32_t)*used);
		PUTCSR32(mca, CSR_SECCMDADDR, cookie.dmac_address);
	} else {
		/* Create DMA chain */
		rv = mca_create_dma_chain(mca, mca->mca_ctldmah, size,
		    &cookie, nc, &mca->mca_ctl_chain_buff);
		if (rv) {
			(void) ddi_dma_unbind_handle(mca->mca_ctldmah);
			mca->mca_ctlcmd = FWCTL_NULL;
			mca_ctlunbusy(mca);
			return (rv);
		}
		/* Load chain buffer size and address */
		hdr = (mca_dma_chain_hdr_t *)mca->mca_ctl_chain_buff.kaddr;
		size = MCA_DMA_CHAIN_SIZE(hdr);
		hdr->vsize = *used;
		PUTCSR32(mca, CSR_SECCMDSZ, MCA_SET_DMA_CHAIN_FLAG(size));
		PUTCSR32(mca, CSR_SECCMDADDR, mca->mca_ctl_chain_buff.paddr);
	}

	PUTCSR32(mca, CSR_SECCMDBUFSZ, (uint32_t)size);

	/* clear the interrupt/status bit */
	PUTCSR16(mca, CSR_INTSTAT, INTSTAT_SECCMD);

	/* write the kick register */
	DBG(mca, DBRINGUP, "kicking secure command signal");
	PUTCSR16(mca, CSR_SIGNAL, SIGNAL_SECCMD);
	/*
	 * we need to make sure this timeout is longer than any
	 * timeout being set by the firmware. We only really want
	 * to detect the case where the firmware is hung.
	 * Currently the max timeout is 2 minutes - so use 3 minutes
	 */
	if (mca_ctlwait(mca, drv_usectohz(3 * 60 * SECOND)) != 0) {
		mca_failure(mca, MCA_FMA_TO_CTL_ID,
		    "timeout in secure command");
		rv = ETIME;
		goto exit;
	}

	/* record how big the result is -- before device reset */
	*used = 0;	/* Insure valid read */
	*used = GETCSR32(mca, CSR_SECCMDSZ);

	/* check if device wants reset */
	config = INVALID_CSR_CONFIG;	/* Insure valid read */
	config = GETCSR32(mca, CSR_CONFIG);

	/* Done with dma handle, release it */
	(void) ddi_dma_unbind_handle(mca->mca_ctldmah);
	mca->mca_ctlcmd = FWCTL_NULL;

	if ((config & CONFIG_FWSTATE) == FWSTATE_RESET) {
		/* drop busy flag across device reset */
		mca_ctlunbusy(mca);
		/* device wants us to reset it */
		if (flags & (MCASECCMD_ZEROIZE | MCASECCMD_RESET)) {

			mca_disableinterrupts(mca, 0);
			if (mca_masterstart(mca) != DDI_SUCCESS) {
				/* Ereport already filed in mca_masterstart */
				mca_failure(mca, MCA_FMA_NO_CLASS_ID,
				    "device error during reset");
				rv = ETIME;
				goto exit;
			}
			/* refresh config register value */
			config = INVALID_CSR_CONFIG;	/* Insure valid read */
			config = GETCSR32(mca, CSR_CONFIG);
			/* reenable interrupts */
			mca_enableinterrupts(mca, 0);

			/*
			 * if the card was previously in FAILSAFE mode
			 * we need to re-register with the framwork. If just
			 * going into FAILSAFE, unregister from framework.
			 *
			 * NOTE: zeroize currently handles this somewhere else
			 * only addressing the reset case.
			 * XXX - should fix this issue.
			 */
			if (flags & MCASECCMD_RESET) {
				if (failsafe && !mca_fm_isfailsafe(mca)) {
					if (mca_hw_provider_register(mca, 0) !=
					    CRYPTO_SUCCESS) {
					    mca_failure(mca,
						MCA_FMA_NO_CLASS_ID,
						"Failed to add device to the "
						"framework");
					    rv = EIO;
					    goto exit;
					}
				} else if (!failsafe &&
				    mca_fm_isfailsafe(mca)) {
					if (mca_hw_provider_unregister(mca)
					    != CRYPTO_SUCCESS) {
					    rv = EIO;
					    goto exit;
					}
				}
			}
		} else {
			mca_failure(mca, MCA_FMA_FW_PROBLEM_ID,
			    "device requesting inappropriate reset");
			rv = EPROTO;
			goto exit;
		}
		/* go ahead and mark us busy again */
		mca_ctlbusy(mca);
	}

	/*
	 * It is in process of rekeying. Wait until it's done.
	 * This may take a long time since rekey has to reset all device
	 * which uses the same keystore. (Times out in 5 minutes);
	 */
	while (mca_isrekey(mca)) {
		delay(drv_usectohz(2 * SECOND));

		if (count++ > 150) {
			rv = ETIME;
			mca_error(mca, "Rekey: Timed out");
			mca_unsetrekey(mca);
			mca_ctlunbusy(mca);
			goto exit;
		}
	}

	mca_ctlunbusy(mca);

	if (mca_fm_isfailed(mca)) {
		DBG(mca, DWARN, "device failure encountered during seccmd");
		rv = EIO;
		goto exit;
	}

exit:
	/* Check if we still have the dma handle */
	if (mca->mca_ctlcmd == FWCTL_SECCMD) {
		(void) ddi_dma_unbind_handle(mca->mca_ctldmah);
		mca->mca_ctlcmd = FWCTL_NULL;
		mca_ctlunbusy(mca);
	}

#ifdef FMA_COMPLIANT
	DBG(mca, DBRINGUP, "mca_seccmd> ddi_get_devstate() = %d",
	    ddi_get_devstate(mca->mca_dip));

	/* Report service degraded if we entered fail-safe mode */
	if (mca_fm_isfailsafe(mca) &&
	    (ddi_get_devstate(mca->mca_dip) != DDI_DEVSTATE_DEGRADED)) {
		ddi_fm_service_impact(mca->mca_dip,
		    DDI_SERVICE_DEGRADED);
	}
#endif /* FMA_COMPLIANT */

	DBG(mca, DBRINGUP, "secure command complete");
	return (rv ? rv : rv_supplemental);
}

void
mca_seccmd_disconnect(mca_t *mca, mca_domain_t dom, mca_channel_t chan)
{
	PUTCSR64(mca, CSR_DISCONNECT_DOM, dom);
	PUTCSR32(mca, CSR_DISCONNECT_CHAN, chan);
	PUTCSR16(mca, CSR_SIGNAL, SIGNAL_ADMDIS);
}

static int
mca_provider_unregister(mca_t *mca, dbm_provider_t *provider)
{
	int		rv = 0;
	mca_keystore_t	*ks;

	DBG(mca, DDBM, "Unregistering keystore %s(type=%d)",
	    provider->name, ntohl(provider->type));

	/*
	 * if this is the device keystore - device is
	 * being zeroized.
	 */
	if (ntohl(provider->type) == DBM_KS_DEVICE) {

		/* clear fips & mark as uninitialized */
		mca_unsetfips(mca);
		mca_unsetowned(mca);

		/* if all keystores not already unregistered, release them */
		if (mca->mca_keystore_count) {
			mca_keystore_rele_all(mca);
		}
	} else {
		/* verify that the keystore exists */
		if ((ks = mca_keystore_lookup_mca(provider->name, mca))
		    != NULL) {

			/* release the keystore */
			mca_keystore_rele(ks, mca);

			/* is this a short trerm offline operation? */
			if (!(ntohl(provider->h.flags) & DBM_OFFLINE)) {
				int notify = (ks->mks_refcnt <= 1);

				/*
				 * if this was only card using KS,
				 * request that scakiod close the channel.
				 */
				if (notify) {
					mca_upcall_send_goodbye(
					    provider->name,
					    mca);
				}
			}
		} else {
			mca_error(mca,
			    "unregister failed: keystore %s not found",
			    provider->name);
			return (ENOENT);
		}
	}

	/*
	 * need to unregister and re-register the hw provider to update
	 * logical provider list.
	 */
	if ((rv = mca_hw_provider_unregister(mca)) != CRYPTO_SUCCESS) {
		mca_error(mca, "mca_hw_provider_unregister() failed: %d", rv);
		return (EIO);
	}
	if (!mca_fm_isfailsafe(mca)) {
		/*
		 * A failure of mca_hw_provider_register should
		 * not be fatal.  Rather we wish to have the device
		 * still be administratable, but not otherwise
		 * usable.  We enter failsafe mode so it
		 * cannot be otherwise used, and set rv to EEXIST.
		 */
		if ((rv = mca_hw_provider_register(mca, 0)) != CRYPTO_SUCCESS) {
			mutex_enter(&mca->fm_lock);
			mca_fm_setfailsafe(mca);
			mutex_exit(&mca->fm_lock);
			mca_error(mca,
			    "mca_hw_provider_register() failed: %d", rv);
			return (EEXIST);
		}
	}

	return (0);
}

static int
mca_provider_register(mca_t *mca, dbm_provider_t *provider)
{
	int		rv = 0;
	mca_keystore_t	*ks = NULL;

	DBG(mca, DDBM, "Registering keystore %s(type=%d)",
	    provider->name, ntohl(provider->type));

	/*
	 * If the card has just been initialized, set the owned and fips
	 * flags accordingly.
	 */
	if (ntohl(provider->type) == DBM_KS_DEVICE) {
		uint32_t	config = INVALID_CSR_CONFIG;

		/* unregister from kCF - re-register after device setup */
		if ((rv = mca_hw_provider_unregister(mca)) != CRYPTO_SUCCESS) {
			mca_error(mca,
			    "mca_hw_provider_unregister() failed: %d", rv);
			return (EIO);
		}

		mca_setowned(mca);

		config = GETCSR32(mca, CSR_CONFIG);
		if (config & CONFIG_FIPS) {
			mca_setfips(mca);
		}

		if (mca_isfips(mca)) {
			DBG(mca, DDBM, "Device is in FIPS mode");
		}

		/*
		 * Perform initial kti key exchange.
		 *
		 * Note: always setup the KTK since it Is used
		 * to generate a unique login cookie.
		 */
		if (mca_setktikey(mca) == DDI_SUCCESS) {
			mca_setktiok(mca);
		} else {
			/*
			 * Key exchange failed, enter failsafe
			 * mode.
			 */
			mca_error(mca, "Unable to establish "
			    "transport key -- device placed in "
			    "FAILSAFE mode.");
			mutex_enter(&mca->fm_lock);
			mca_fm_setfailsafe(mca);
			mutex_exit(&mca->fm_lock);
			/*
			 * Return an access violation to mcaadm
			 * for now.  Should never happen since
			 * the default name and password cannot
			 * be changed in the production build.
			 * May need to re-think this when
			 * changes are allowed.
			 */
			mca_keystore_rele_all(mca);
			if (mca_isfips(mca)) {
				mca_unsetfips(mca);
			}
			return (EACCES);
		}
	} else {

		/*
		 * see if any keystores are registered for this device instance.
		 * if so, then mca_provider_register was called because of
		 * a reset. No need to re-register the provider
		 */
		if ((ks = mca_keystore_lookup_mca(provider->name, mca))
		    != NULL) {
			/* update the DBM handle since it may have changed */
			mca_ks_set_handle(ks, ntohl(provider->handle), mca);
			return (0);
		}

		/* create the keystore and register the logical provider */
		if ((ks = mca_keystore_hold(mca, provider)) == NULL) {
			mca_error(mca, "mca_keystore_hold() failed");
			return (EIO);
		}
		/*
		 * unregister the hw provider - will re-register referring
		 * to logical provider/keystore.
		 */
		if ((rv = mca_hw_provider_unregister(mca)) != CRYPTO_SUCCESS) {
			mca_error(mca,
			    "mca_hw_provider_unregister() failed: %d", rv);
			mca_keystore_rele(ks, mca);
			return (EIO);
		}
	}
	if (!mca_fm_isfailsafe(mca)) {
		/*
		 * A failure of mca_hw_provider_register should
		 * not be fatal.  Rather we wish to have the device
		 * still be administratable, but not otherwise
		 * usable.  We enter failsafe mode so it
		 * cannot be otherwise used, and set rv to EEXIST.
		 */
		if ((rv = mca_hw_provider_register(mca, 0)) != CRYPTO_SUCCESS) {
			mutex_enter(&mca->fm_lock);
			mca_fm_setfailsafe(mca);
			mutex_exit(&mca->fm_lock);
			mca_error(mca,
			    "mca_hw_provider_register() failed: %d", rv);
			if (ks) {
				mca_keystore_rele(ks, mca);
			}
			return (EEXIST);
		}
	}

	return (0);
}


static void
mca_fri_settime(mca_t *mca)
{
	time_t now;

	/* Write time data to the debug csr window */
	now = ddi_get_time();
	PUTCSR32(mca, CSR_FDI_WINDOW, (uint32_t)now);

	mca_fri_release(mca);

	DBG(mca, DBRINGUP, "firmware time update complete");
}


static void
fri_notify_failure_done(mca_request_t *reqp)
{
	dbm_header_t *dbm;

	ddi_dma_sync(reqp->mr_obuf_dmah, 0, reqp->mr_resultlen,
	    DDI_DMA_SYNC_FORKERNEL);

	/*
	 * Make sure that it is a handshake request which indicates
	 * that a failure notification was acknowledged
	 */
	dbm = (dbm_header_t *)(reqp->mr_obuf_kaddr + MCA_IDC_SZ);
	if (ntohl(dbm->type) != DB_HANDSHAKE) {
		mca_error(reqp->mr_mca, "Upcall Failure Notification: "
		    "Invalid dbm type[0x%x]\n", ntohl(dbm->type));
	}

	mca_freereq(reqp);
}


/*
 * Upcall failure, Notify FW.
 */
static void
fri_notify_upcall_failure(mca_t *mca, caddr_t buf, dbm_header_t *dbm,
    size_t len, int error)
{
	mca_request_t	*reqp;
	uint32_t	chainlen;

	/* prepare the request */
	if ((reqp = mca_getreq(&mca->mca_ring_om)) == NULL) {
		mca_error(mca, "fri_notify_failure: unable to allocate "
		    "request for DBM");
		return;
	}

	DBG(mca, DWARN,
	    "fri_notify_upcall_failure for DBM type %d, handle 0x%x, error %d",
	    ntohl(dbm->type), ntohl(dbm->handle), error);

	/* Set the error code */
	dbm->status = htonl(error);

	reqp->mr_cmd = CPG_CMD_DBM;
	reqp->mr_callback = fri_notify_failure_done;
	reqp->mr_dbm_handle = dbm->ldom;

	/* setup the input chain */
	if (mca_create_om_chain(&reqp->mr_ibuf_chain, len,
	    reqp->mr_key_kaddr, &chainlen) != 0)
		return;
	reqp->mr_in_paddr = reqp->mr_key_paddr;
	reqp->mr_in_len = chainlen;
	reqp->mr_in_first_len = chainlen;
	reqp->mr_in_next_paddr = 0;

	/*
	 * clear the most significant byte used by driver to store
	 * driver inst
	 */
	*((uchar_t *)&(dbm->handle)) = 0;
	bcopy(buf, reqp->mr_ibuf_kaddr, len);
	ddi_dma_sync(reqp->mr_key_dmah, 0, chainlen, DDI_DMA_SYNC_FORDEV);
	ddi_dma_sync(reqp->mr_ibuf_dmah, 0, len, DDI_DMA_SYNC_FORDEV);

	reqp->mr_out_paddr = reqp->mr_obuf_paddr;
	reqp->mr_out_next_paddr = reqp->mr_obuf_next_paddr;
	reqp->mr_out_len = MAXPACKET;
	reqp->mr_out_first_len = reqp->mr_obuf_sz;

	/* release the FRI interface */
	mca_fri_release(mca);

	if (mca_start(reqp) != CRYPTO_QUEUED) {
		mca_freereq(reqp);
	}
}


static
void
mca_fri_dbm(
#ifdef LINUX
	work_wrap_t *ww)
{
	mca_t *mca = ww->mca;
	unsigned long lock_flags;
#else
	mca_t *mca)
{
#endif
	dbm_header_t	*dbm;
	mca_channel_t	chan;
	mca_idc_hdr_t	*idc;

	mca_idc_hdr_t	hdr_1_0;
	dbm_op_t	op;
	size_t		len;

	len = GETCSR16(mca, CSR_FRI_LEN);
	ddi_dma_sync(mca->mca_fri_buff.dmah, 0, len,
	    DDI_DMA_SYNC_FORKERNEL);

	/* old firmware */
	if (MCA_FW_IF_COMP_VERSION(mca) <= MCA_IF_VERSION_1_0) {
		mca_channel_t	chan = mca_upcall_lookup_control_channel();
		dbm = (dbm_header_t *)mca->mca_fri_buff.kaddr;
		if (chan == -1) {
			fri_notify_upcall_failure(mca, (caddr_t)dbm, dbm,
			    len, DBM_EPIPE);
#ifdef LINUX
			spin_lock_irqsave(&sca_work_lock, lock_flags);
			ww->inuse = 0;
			spin_unlock_irqrestore(&sca_work_lock, lock_flags);
#endif
			return;
		}
		idc = &hdr_1_0;
		idc->chanId = htonl(chan);
	} else {
		idc = (mca_idc_hdr_t *)mca->mca_fri_buff.kaddr;
		dbm = (dbm_header_t *)(mca->mca_fri_buff.kaddr + MCA_IDC_SZ);
	}

	op = ntohl(dbm->type);
	len = ntohl(dbm->paramSize);

	DBG(mca, DDBM, "mca_fri_dbm: received type 0x%x, handle 0x%x, "
	    "size 0x%x", op, ntohl(dbm->handle), len);

	switch (op) {
		dbm_provider_t *provider;
	case DB_PROVIDER_REGISTER:
		if (MCA_FW_IF_COMP_VERSION(mca) > MCA_IF_VERSION_1_0) {
			provider = (dbm_provider_t *)dbm;
			/* Don't register device OS if suspending */
			if (mca_issuspending(mca) &&
			    (ntohl(provider->type) == DBM_KS_DEVICE)) {
				/*
				 * Clear suspending flag and signal that
				 * suspended jobs can now be processed
				 */
				mca_unsuspend(mca);
			} else {
				(void) mca_provider_register(mca, provider);
			}
		}
		mca_fri_release(mca);
		break;
	case DB_PROVIDER_UNREGISTER:
		if (MCA_FW_IF_COMP_VERSION(mca) > MCA_IF_VERSION_1_0) {
			provider = (dbm_provider_t *)dbm;
			(void) mca_provider_unregister(mca, provider);
		}
		mca_fri_release(mca);
		break;

	case DB_JOIN:
		/*
		 * DB_JOIN is sent when we are loading/restoring a
		 * keystore.  If this keystore is already in use
		 * then we send a DB_HELLO on that channel otherwise
		 * we send the DB_JOIN on the selected channel (control).
		 */
		DBG(mca, DDBM, "mca_fri_dbm: received DB_JOIN for %s",
		    ((dbm_init_t *)dbm)->name);

		/* old firmware */
		if (MCA_FW_IF_COMP_VERSION(mca) <= MCA_IF_VERSION_1_0) {
			fri_notify_upcall_failure(mca, (caddr_t)dbm, dbm,
			    len, DBM_EPIPE);
			break;
		}
		chan = mca_upcall_lookup_channel(((dbm_init_t *)dbm)->name);
		if (chan != -1) {
			dbm->type = htonl(DB_HELLO);
			len = sizeof (dbm);
			dbm->paramSize = htonl(len);
			idc->chanId = htonl(chan);
		}
		/* fall through */
	default:
		/* Use the device instance as a part of the handle. */
		*((uchar_t *)&(dbm->handle)) = ddi_get_instance(mca->mca_dip);


		if (mca_upcall_hold(ntohl(idc->chanId)) != 0) {
			fri_notify_upcall_failure(mca, (caddr_t)idc, dbm,
			    len, DBM_EPIPE);
		} else if (mca_upcall_post(mca, ntohl(idc->chanId),
			    dbm, len, TRUE) != 0) {
			mca_upcall_release(ntohl(idc->chanId));
			fri_notify_upcall_failure(mca, (caddr_t)idc, dbm,
			    len, DBM_EPIPE);
			mca_note(mca, "Failed to post an upcall!\n");
		}
		break;
		// else: another thread will call mca_fri_release().
	}

#ifdef LINUX
	spin_lock_irqsave(&sca_work_lock, lock_flags);
	ww->inuse = 0;
	spin_unlock_irqrestore(&sca_work_lock, lock_flags);
#endif
}

void
mca_fri_release(mca_t *mca)
{
	/*
	 * Don't do anything if not attached.
	 */
	if (mca_isdetached(mca)) {
		DBG(mca, DBRINGUP, "mca_fri_release: driver detached\n");
		return;
	}

	/*
	 * Notify FW that we are ready to process another upcall job.
	 */
	PUTCSR32(mca, CSR_SIGNAL, SIGNAL_FRI);
}

static void
mca_fri_ind(
	mca_t *mca)
{
	extern int mca_driver_debug;

	mca_fri_ind_t ind;
#ifdef LINUX
	work_wrap_t *ww;
	unsigned long flags;
	int i;
#endif

	ind = MCA_INVALID_CSR32;	/* Ensure valid read */
	ind = GETCSR32(mca, CSR_FRI_REQUEST);

	switch (ind) {
	case FRI_IND_TIME:
		/* Initiate firmware time update on a new thread */
		if (ddi_taskq_dispatch(mca->mca_taskq,
		    (task_func_t *)mca_fri_settime,
		    (void *)mca, DDI_NOSLEEP) != DDI_SUCCESS) {
			mca_error(mca, "unable to dispatch time update");
		} else {
			DBG(mca, DCHATTY, "dispatched time update");
		}
		break;

	case FRI_IND_DEBUG_ON:
		/* Currently, toggle <mca_driver_debug> on. */
		mca_driver_debug = ~0;
		break;

	case FRI_IND_DEBUG_OFF:
		/* Currently, toggle <mca_driver_debug> off. */
		mca_driver_debug = 0;
		break;

	case FRI_IND_DBM:
		/* Process DBM requests on a new thread */
#ifdef LINUX
		spin_lock_irqsave(&sca_work_lock, flags);
		for (i = 0; i < MAX_NUM_WORK_WRAP; i++) {
			ww = &work_wrap[work_wrap_index++];
			if (work_wrap_index >= MAX_NUM_WORK_WRAP)
				work_wrap_index = 0;
			if (!ww->inuse) {
				ww->inuse = 1;
				break;
			}
		}
		spin_unlock_irqrestore(&sca_work_lock, flags);
		if (i == MAX_NUM_WORK_WRAP)
			mca_error(mca, "unable to find a free work queue item");

		ww->mca = mca;
		if (ddi_taskq_dispatch(mca->mca_taskq,
		    (task_func_t *)mca_fri_dbm,
		    (void *)ww, DDI_NOSLEEP) != DDI_SUCCESS) {
#else
		if (ddi_taskq_dispatch(mca->mca_taskq,
		    (task_func_t *)mca_fri_dbm,
		    (void *)mca, DDI_NOSLEEP) != DDI_SUCCESS) {
#endif

			mca_error(mca, "unable to dispatch DBM request");
		} else {
			DBG(mca, DDBM, "dispatched DBM request");
		}
		break;

	default:
		mca_note(mca, "mca_fri_ind.error: "
		    "received unknown request from firmware: %d", ind);
		break;
	}
}


#ifdef LINUX
#define	printf	printk
#endif
void
mca_dump_dbm_header(dbm_header_t *head, char *str)
{
	printf("%s%sDBM Header[%p]\n", (str ? str : ""),
	    (str ? " " : ""), (void *)head);
	switch (head->type) {
	case DB_STANDBY:
		printf("  type     : STANDBY\n");
		break;
	case DB_USER_READ:
		printf("  type     : USER_READ\n");
		break;
	case DB_USER_WRITE:
		printf("  type     : USER_WRITE\n");
		break;
	case DB_USER_DEL:
		printf("  type     : USER_DEL\n");
		break;
	case DB_OBJECT_READ:
		printf("  type     : OBJECT_READ\n");
		break;
	case DB_OBJECT_WRITE:
		printf("  type     : OBJECT_WRITE\n");
		break;
	case DB_OBJECT_DEL:
		printf("  type     : OBJECT_DEL\n");
		break;
	case DB_FILE_READ:
		printf("  type     : FILE_READ\n");
		break;
	case DB_FILE_WRITE:
		printf("  type     : FILE_WRITE\n");
		break;
	case DB_HELLO:
		printf("  type     : HELLO\n");
		break;
	case DB_FILE_PUSH:
		printf("  type     : FILE_PUSH\n");
		break;
	case DB_USER_PUSH:
		printf("  type     : USER_PUSH\n");
		break;
	case DB_OBJECT_PUSH:
		printf("  type     : OBJECT_PUSH\n");
		break;
	case DB_RESPONSE:
		printf("  type     : RESPONSE\n");
		break;
	case DB_HANDSHAKE:
		printf("  type     : HANDHSAKE\n");
		break;
	case DB_STATUS:
		printf("  type     : STATUS\n");
		break;
	default:
		break;
	}

	printf("  handle   : %d\n", ntohl(head->handle));
	printf("  ldom     : %d\n", ntohl(head->ldom));
	printf("  status   : %d\n", ntohl(head->status));
	printf("  flags    : 0x%x\n", ntohl(head->flags));
	printf("  extent   : %d\n", ntohl(head->extent));
	printf("  paramSize: %d\n", ntohl(head->paramSize));
}

char *
mca_dbm_type(int type)
{
	switch (type) {
	case DB_STANDBY:
		return ("STANDBY");
	case DB_USER_READ:
		return ("USER_READ");
	case DB_USER_WRITE:
		return ("USER_WRITE");
	case DB_USER_DEL:
		return ("USER_DEL");
	case DB_OBJECT_READ:
		return ("OBJECT_READ");
	case DB_OBJECT_WRITE:
		return ("OBJECT_WRITE");
	case DB_OBJECT_DEL:
		return ("OBJECT_DEL");
	case DB_FILE_READ:
		return ("FILE_READ");
	case DB_FILE_WRITE:
		return ("FILE_WRITE");
	case DB_HELLO:
		return ("HELLO");
	case DB_FILE_PUSH:
		return ("FILE_PUSH");
	case DB_USER_PUSH:
		return ("USER_PUSH");
	case DB_OBJECT_PUSH:
		return ("OBJECT_PUSH");
	case DB_RESPONSE:
		return ("RESPONSE");
	case DB_HANDSHAKE:
		return ("HANDHSAKE");
	case DB_STATUS:
		return ("STATUS");
	case DB_PROVIDER_REGISTER:
		return ("PROVIDER_REGISTER");
	case DB_PROVIDER_UNREGISTER:
		return ("PROVIDER_UNREGISTER");
	default:
		return ("Unknown Type");
	}
}

void
mca_boot_wait(mca_t *mca)
{
	uint32_t	bootrom = 0;
	int		time = 0;

	while (time < mca_boottime) {
		bootrom = MCA_BOOT_VERSION(mca);
		if (!bootrom) {
			delay(1);
			time += drv_hztousec(1);
		} else {
			break;
		}
	}
	DBG(mca, DBRINGUP, "Detected bootroom %d.%d.%d after %d usecs\n",
	    MCA_BOOT_MAJOR_VERSION(mca), MCA_BOOT_MINOR_VERSION(mca),
	    MCA_BOOT_MICRO_VERSION(mca), time);
}
