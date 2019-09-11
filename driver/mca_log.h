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

#ifndef	_MCA_LOG_H
#define	_MCA_LOG_H

#pragma ident	"@(#)mca_log.h	1.13	07/02/09 SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Log entry types
 */
#define	MCA_LOG_ENTRY_SIZE	256	/* Size of log ring buffers */
#define	MCA_LOG_HDR_SIZE	((2 * sizeof (uint8_t)) +  sizeof (uint16_t))
#define	MCA_LOG_BUF_SIZE	(MCA_LOG_ENTRY_SIZE - MCA_LOG_HDR_SIZE)

typedef struct mca_fma_event {
	uint8_t		class;	/* FMA ereport class */
	uint8_t		spare1;	/* Spare FMA data byte */
	uint16_t	spare2;	/* Spare FMA data word */
} mca_fma_event_t;

#define	MCA_FMA_EVENT_SIZE	(sizeof (mca_fma_event_t))
#define	MCA_EREPORT_MSG_SIZE	(MCA_LOG_BUF_SIZE - MCA_FMA_EVENT_SIZE)

typedef struct mca_ereport_log {
	mca_fma_event_t	event;			   /* FMA event */
	char		msg[MCA_EREPORT_MSG_SIZE]; /* Informational message */
} mca_ereport_log_t;


typedef struct mca_log {
	uint8_t		level;	/* Message level (bit 0 = extended 2.0 data) */
	uint8_t		type;	/* Extended log data type (if applicable */
	uint16_t	size;	/* Size of remaining valid log data */
	union {
		char			msg[MCA_LOG_BUF_SIZE];	/* Log msg */
		mca_ereport_log_t	ereport;		/* FMA data */
	} entry;
} mca_log_t;

/*
 * Log entry constants and macros
 */

/* Message log levels (maskable) */
#define	LOGMASK_UNUSED  	0x01	/* Unused bit */
#define	LOGMASK_DEBUG3		0x02	/* noisy! */
#define	LOGMASK_DEBUG2		0x04	/* normal debug */
#define	LOGMASK_DEBUG1		0x08	/* quieter debug (oxymoron?) */
#define	LOGMASK_INFO		0x10	/* informational messages */
#define	LOGMASK_NOTICE		0x20	/* important informational messages */
#define	LOGMASK_WARN		0x40	/* warnings */
#define	LOGMASK_ERROR		0x80	/* errors (fatal to device) */
#define	LOGMASK_UPTO(x)		((x) - 1)

/*
 * Define default firmware log mask and log interrupt mask.  These values
 * can be overridden by "fwlogmask" and "fwlogintmask" in the mca.conf file.
 */
#ifdef	DEBUG
#define	DEFAULT_LOGMASK		LOGMASK_DEBUG2
#define	DEFAULT_LOGINTMASK	LOGMASK_DEBUG2
#else
#define	DEFAULT_LOGMASK		LOGMASK_INFO
#define	DEFAULT_LOGINTMASK	LOGMASK_INFO
#endif

/* XXX - FMA needs work */

/* FMA service impact levels */
#define	MCA_IMPACT_ERROR	LOGMASK_ERROR
#define	MCA_IMPACT_WARNING	LOGMASK_WARN
#define	MCA_IMPACT_NOTICE	LOGMASK_NOTICE
#define	MCA_IMPACT_INFO		LOGMASK_INFO

/* Log entry Types */
#define	MCA_SYS_LOG_MSG		0x00
#define	MCA_FMA_EREPORT		0x01

/* FMA ereport classes */
#define	MCA_FMA_NO_CLASS_ID	0x00
#define	MCA_FMA_FW_PROBLEM_ID	0x01
#define	MCA_FMA_FW_EXCEPTION_ID	0x02
#define	MCA_FMA_FW_NO_REPORT_ID	0x03
#define	MCA_FMA_FW_FAILSAFE_ID	0x04
#define	MCA_FMA_FW_VERSION_ID	0x05
#define	MCA_FMA_SW_PROBLEM_ID	0x06
#define	MCA_FMA_SW_KS_ID	0x07
#define	MCA_FMA_TO_INIT_ID	0x08
#define	MCA_FMA_TO_CTL_ID	0x09
#define	MCA_FMA_TO_CRYPTO_ID	0x0a
#define	MCA_FMA_IPOST_ID	0x0b
#define	MCA_FMA_POST_ID		0x0c
#define	MCA_FMA_HALT_ID		0x0d
#define	MCA_FMA_MEM_UE_ID	0x0e
#define	MCA_FMA_MEM_EX_CE_ID	0x0f
#define	MCA_FMA_BAD_DATA_ID	0x10
#define	MCA_FMA_RESTORE_DATA_ID	0x11
#define	MCA_FMA_DETECT_PERR_ID	0x12
#define	MCA_FMA_REPORT_PERR_ID	0x13
#define	MCA_FMA_DETECT_SERR_ID	0x14
#define	MCA_FMA_REPORT_SERR_ID	0x15
#define	MCA_FMA_MA_ID		0x16
#define	MCA_FMA_INT_MA_ID	0x17
#define	MCA_FMA_DETECT_TA_ID	0x18
#define	MCA_FMA_REPORT_TA_ID	0x19
#define	MCA_FMA_DMA_ID		0x1a
#define	MCA_FMA_BAD_FW_ID	0x1b
#define	MCA_FMA_HEALTH_ID	0x1c
#define	MCA_FMA_ZEROIZE_JMP_ID	0x1d
#define	MCA_FMA_POWER_ID	0x1e
#define	MCA_FMA_SCM_ID		0x1f
#define	MCA_FMA_RESERVED_ID    	0x20

#define	MCA_MAX_FMA_EREPORT_ID	MCA_FMA_SCM_ID

/*
 * FMA Hardware Busses
 */
#define	MCA_FMA_NO_BUS_ID	0x00
#define	MCA_FMA_CORE_BUS_ID	0x01
#define	MCA_FMA_DATA_BUS_ID	0x02
#define	MCA_FMA_PAR_BUS_ID	0x03
#define	MCA_FMA_SER_BUS_ID	0x04
#define	MCA_FMA_PCI_BUS_ID	0x05

/*
 * FMA Hardware Components (Devices)
 */
#define	MCA_FMA_NO_DEV_ID	0x00
#define	MCA_FMA_CPU_ID		0x01
#define	MCA_FMA_CIO_ID		0x02
#define	MCA_FMA_MCU_ID		0x03
#define	MCA_FMA_SDRAM_ID	0x04
#define	MCA_FMA_FLASH_ID	0x05
#define	MCA_FMA_EEPROM_ID	0x06
#define	MCA_FMA_PCI_IF_ID	0x07
#define	MCA_FMA_ATU_ID		0x08
#define	MCA_FMA_DMA_0_ID	0x09
#define	MCA_FMA_DMA_1_ID	0x0a
#define	MCA_FMA_CRYPTO_ID	0x0b
#define	MCA_FMA_USB_ID		0x0c

/*
 * Mars FMA constants
 */
#define	MCA_ERROR_SUBCLASS	"sca6000"	/* FMA sub class */

#define	MCA_FMA_DRV_MSG		"mca-msg"	/* nv-pair name */
#define	MCA_FMA_FW_MSG		"fw-msg"	/* nv-pair name */
#define	MCA_FMA_INSTANCE	"instance"	/* nv-pair name */

#ifdef	__cplusplus
}
#endif

#endif	/* _MCA_LOG_H */
