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

#ifndef	_MCA_CSRS_H
#define	_MCA_CSRS_H

#pragma ident	"@(#)mca_csrs.h	1.40	08/04/07 SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Mars CSR info for use by both the mca driver and firmware.
 */

/*
 * CSR constants
 */
#define	KS_NAME_MAX_LENGTH	32
#define	KTI_NAME_MAX_LENGTH	33
#define	KTI_PASS_MAX_LENGTH	33
#define	KTK_MAX_LENGTH		32

/* Maintain venus kti defaults for initial development compatibility */
#define	MCA_DEFAULT_KTI_NAME	"mca1.0"
#define	MCA_DEFAULT_KTI_PASS	"sca6000"

#define	MCA_MAJOR_VERSION(x)	((x >> 24) & 0xFF)
#define	MCA_MINOR_VERSION(x)	((x >> 16) & 0xFF)
#define	MCA_MICRO_VERSION(x)	(x & 0xFFFF)
#define	MCA_MAJ_MIN_VERSION(x)	((x >> 16) & 0xFFFF)

#define	P11_HW_MAJOR_VERSION	0x00
#define	P11_HW_MINOR_VERSION	0x02
#define	P11_HW_MICRO_VERSION	0x0001
#define	P11_HW_VERSION		((P11_HW_MAJOR_VERSION << 24) | \
				(P11_HW_MINOR_VERSION << 16) | \
				(P11_HW_MICRO_VERSION))

#define	P12_HW_MAJOR_VERSION	0x00
#define	P12_HW_MINOR_VERSION	0x04
#define	P12_HW_MICRO_VERSION	0x0001
#define	P12_HW_VERSION		((P12_HW_MAJOR_VERSION << 24) | \
				(P12_HW_MINOR_VERSION << 16) | \
				(P12_HW_MICRO_VERSION))

#define	P20_HW_MAJOR_VERSION	0x01
#define	P20_HW_MINOR_VERSION	0x02
#define	P20_HW_MICRO_VERSION	0x0050
#define	P20_HW_VERSION		((P20_HW_MAJOR_VERSION << 24) | \
				(P20_HW_MINOR_VERSION << 16) | \
				(P20_HW_MICRO_VERSION))

#define	P21_HW_MAJOR_VERSION	0x01
#define	P21_HW_MINOR_VERSION	0x03
#define	P21_HW_MICRO_VERSION	0x0050
#define	P21_HW_VERSION		((P21_HW_MAJOR_VERSION << 24) | \
				(P21_HW_MINOR_VERSION << 16) | \
				(P21_HW_MICRO_VERSION))

#define	FCS_BOOT_MAJOR_VERSION	0x01
#define	FCS_BOOT_MINOR_VERSION	0x00
#define	FCS_BOOT_MICRO_VERSION	0x0001
#define	FCS_BOOT_VERSION	((FCS_BOOT_MAJOR_VERSION << 24) | \
				(FCS_BOOT_MINOR_VERSION << 16) | \
				(FCS_BOOT_MICRO_VERSION))

#define	MCA_IF_MAJOR_VERSION	0x02
#define	MCA_IF_MINOR_VERSION	0x00
#define	MCA_IF_MICRO_VERSION	0x0000
#define	MCA_IF_VERSION		((MCA_IF_MAJOR_VERSION << 24) | \
				(MCA_IF_MINOR_VERSION << 16) | \
				(MCA_IF_MICRO_VERSION))
#define	MCA_IF_COMP_VERSION	((MCA_IF_MAJOR_VERSION << 8) | \
				MCA_IF_MINOR_VERSION)

#define	MCA_IF_VERSION_1_0	0x01ff
/* DMA chaining was introduced in version 1.1 (I/F 2.0) */
#define	MCA_IF_VERSION_CHAIN	0x0200

typedef enum {
	MCA_RESET_NONE = 0,	/* No reset (checked by bootstrap firmware) */
	MCA_RESET_HARD = 1,	/* Hardware reset (currently not used) */
	MCA_RESET_FIRM = 2,	/* vxWorks reboot (initiated by firmware) */
	MCA_RESET_SOFT = 3,	/* Extensive reset preparation */
	MCA_RESET_FAST = 4,	/* Fast (shutdown) reset preparation */
	MCA_RESET_ANY  = 5,	/* Any reset (firmware use only) */
} mca_reset_t;

/*
 * Define mars CSRS.
 */

/*
 * ATU PCI configuration and status register (PCSR)
 */
#define	CSR_PCSR		0x00000084	/* PCSR, 32 bits */
#define	CSR_PCSR_RESET		0x00000020	/* reset internal bus */
#define	CSR_PCSR_IN_BUSY	0x00004000	/* outbound Q busy */
#define	CSR_PCSR_OUT_BUSY	0x00008000	/* inbound Q busy */

/*
 * IOP333 MU Registers
 */
#define	CSR_IB_MSG_0		0x0010	/* inbound message register 0 */
#define	CSR_IB_MSG_1		0x0014	/* inbound message register 1 */
#define	CSR_OB_MSG_0		0x0018	/* outbound message register 0 */
#define	CSR_OB_MSG_1		0x001c	/* outbound message register 0 */
#define	CSR_IB_DOORBELL		0x0020  /* inbound doorbell register */
#define	CSR_IB_INT_STAT		0x0024	/* inbound doorbell status register */
#define	CSR_IB_INT_MASK		0x0028	/* inbound doorbell mask register */
#define	CSR_OB_DOORBELL		0x002C  /* outbound doorbell register */
#define	CSR_OB_INT_STAT		0x0030	/* outbound doorbell status register */
#define	CSR_OB_INT_MASK		0x0034	/* outbound doorbell mask register */
#define	CSR_INTSTAT		CSR_OB_DOORBELL
#define	CSR_SIGNAL		CSR_IB_DOORBELL
#define	CSR_BOOT_VERSION	CSR_OB_MSG_0 /* Running bootstrap version */
/*
 * Messaging Unit (MU) interrupt status/mask bits
 */
#define	MU_IN_MSG0_BIT		(1<<0)
#define	MU_IN_MSG1_BIT		(1<<1)
#define	MU_IN_DB_BIT		(1<<2)
#define	MU_IN_DB_ERROR_BIT	(1<<3)
#define	MU_IN_POSTQ_BIT		(1<<4)
#define	MU_IN_POSTQ_FULL_BIT	(1<<5)
#define	MU_IN_INDEX_BIT		(1<<6)
#define	MU_IN_ALL_INTS		0x0000007F

#define	MU_OUT_MSG0_BIT		(1<<0)
#define	MU_OUT_MSG1_BIT		(1<<1)
#define	MU_OUT_DB_BIT		(1<<2)
#define	MU_OUT_POSTQ_BIT	(1<<3)
#define	MU_OUT_PCI_BIT		(1<<4)
#define	MU_OUT_ALL_INTS		0x0000001F

#define	MU_DOORBELL_ALL_INTS	0xFFFFFFFF

/*
 * Mars CSRs
 */

/* Primary control/status registers */
#define	CSR_CONFIG		0x1000	/* mars configuration, 32 bits */
#define	CSR_HWVERSION		0x1004	/* hardware version, 32 bits */
#define	CSR_FWVERSION		0x1008	/* firmware version, 32 bits */
#define	CSR_IFVERSION		0x100C	/* interface version, 32 bits */
#define	CSR_POSTRESULT		0x1010	/* post results, 32 bits */
#define	CSR_FWCTL		0x1014	/* firmware control, 16 bits */
#define	CSR_FWSTAT		0x1016	/* firmware status, 16 bits */
#define	CSR_FWCTLSZ		0x1018	/* FWCTL buffer size, 32 bits */
#define	CSR_FWCTLDATA		0x101C	/* FWCTL buffer pointer, 32 bits */
#define	CSR_SECCMDBUFSZ		0x1020	/* secure command buf size, 32 bits */
#define	CSR_SECCMDADDR		0x1024	/* secure command address, 32 bits */
#define	CSR_SECCMDSZ		0x1028	/* secure command size, 32 bits */
#define	CSR_SCRATCHSZ		0x102C	/* size of diag. scratch DMA block */
#define	CSR_SCRATCHADDR		0x1030	/* diagnostic scratch DMA block */
#define	CSR_DIAGFAILADDR	0x1034	/* diagnostic failure address */
#define	CSR_DIAGFAILEXPECTED	0x1038	/* diagnostic failure expected value */
#define	CSR_DIAGFAILACTUAL	0x103c	/* diagnostic failure actual value */
#define	CSR_LOGRINGSZ		0x1040	/* log ring size (# entries), 8 bits */
#define	CSR_LOGRINGHEAD		0x1041	/* log ring head, 8 bits */
#define	CSR_LOGRINGTAIL		0x1042	/* log ring tail, 8 bits */
#define	CSR_LOGINTMASK		0x1044	/* log interrupt mask, 8 bits */
#define	CSR_LOGMASK		0x1045	/* log mask, 8 bits */
#define	CSR_LOGFACMASK		0x1046	/* log facility mask, 16 bits */
#define	CSR_LOGRINGADDR		0x1048	/* log ring address, 32 bits */
#define	CSR_DRV_IFVERSION	0x104C	/* Driver interface version, 32 bits */
#define	CSR_DRV_INSTANCE	0x1050	/* Driver instance assigned to card */
#define	CSR_DRV_DOM		0x1058	/* Domain ID of the physical driver */
#define	CSR_DISCONNECT_DOM	0x1060	/* Domain ID seccmd disconnect */
#define	CSR_DISCONNECT_CHAN	0x1068  /* Channel ID of seccmd disconnect */

/* Data base Management Interface (DBMI) registers */
#define	CSR_DBMI_OFFSET		0x10d4	/* Offset to DBMI csrs */
#define	CSR_DBMI_DID		0x10d4	/* DBM domain, 32 bits */
#define	CSR_DBMI_ZID		0x10d8	/* DBM zone, 32 bits */
#define	CSR_DBMI_CID		0x10dc	/* DBM channel, 32 bits */

/* Firmware Request Interface (FRI) registers */
#define	CSR_FRI_OFFSET		0x10e0	/* Offset to FRI csrs */
#define	CSR_FRI_ADDRESS		0x10e0	/* FRI command address, 32 bits */
#define	CSR_FRI_MAXLEN		0x10e4	/* FRI command max size, 16 bits */
#define	CSR_FRI_LEN		0x10e6	/* FRI command actual size, 16 bits */
#define	CSR_FRI_REQUEST		0x10e8	/* firmware request, 32 bits */
#define	CSR_FRI_HANDLE		0x10ec	/* firmware request handle, 32 bits */
#define	CSR_FRI_STATUS		0x10f0	/* FRI status, 32 bits */
#define	CSR_FRI_DID		0x10f4	/* FRI domain, 32 bits */
#define	CSR_FRI_ZID		0x10f8	/* FRI zone, 32 bits */
#define	CSR_FRI_FLAG		0x10fc	/* FRI channel, 16 bits */

/* 16-bit FRI related flags */
#define	CSR_FRIF_CHAINED	0x01	/* FRI ADDRESS is an address of chain */


/*
 * Firmware Request Interface CSR pointers
 */
#define	FRI_HANDLE_P		UINT32_P(csrBaseAddr() + CSR_FRI_HANDLE)
#define	FRI_STATUS_P		UINT32_P(csrBaseAddr() + CSR_FRI_STATUS)
#define	FRI_WINDOW_BASE		UINT32_P(csrBaseAddr() + CSR_FDI_WINDOW)

typedef enum {
	FRIS_IDLE,
	FRIS_BUSY,
	FRIS_UNINITIALIZED

} cpg_fri_status_t;

/*
 * Crypto registers
 */
#define	CSR_CRYPTOCONF		0x1100	/* crypto configuration, 32 bits */
#define	CSR_CAHEAD		0x1104	/* CA (assymetric) head, 16 bits */
#define	CSR_CBHEAD		0x1106	/* CB (bulk) head, 16 bits */
#define	CSR_OMHEAD		0x1108	/* OM (object mgmt) head, 16 bits */
#define	CSR_CACOMPHEAD		0x110A	/* CA completion head, 16 bits */
#define	CSR_CBCOMPHEAD		0x110C	/* CB completion head, 16 bits */
#define	CSR_OMCOMPHEAD		0x110E	/* OM completion head, 16 bits */
#define	CSR_CATAIL		0x1110	/* CA tail, 16 bits */
#define	CSR_CBTAIL		0x1112	/* CB tail, 16 bits */
#define	CSR_OMTAIL		0x1114	/* OM tail, 16 bits */
#define	CSR_CACOMPTAIL		0x1116	/* CA completion tail, 16 bits */
#define	CSR_CBCOMPTAIL		0x1118	/* CB completion tail, 16 bits */
#define	CSR_OMCOMPTAIL		0x111A	/* OM completion tail, 16 bits */
#define	CSR_CARINGADDR		0x111C	/* CA ring base address, 32 bits */
#define	CSR_CACOMPADDR		0x1120	/* CA cmopletion address, 32 bits */
#define	CSR_CBRINGADDR		0x1124	/* CB ring base address, 32 bits */
#define	CSR_CBCOMPADDR		0x1128	/* CB completion address, 32 bits */
#define	CSR_OMRINGADDR		0x112C	/* OM ring base address, 32 bits */
#define	CSR_OMCOMPADDR		0x1130	/* OM completion address, 32 bits */

/*
 * ------------------------------------------------------------
 * DBM Ring CSRs: these registers are arranged differently from
 * those of the other rings, in order to be able to see each ring
 * as a data structure.
 * ------------------------------------------------------------
 * The recv (Receive) ring
 * ------------------------------------------------------------
 */
#define	CSR_DB_RECV_ADDRESS	0x1140 /* 32 bits, the address of the ring. */
#define	CSR_DB_RECV_HEAD	0x1144 /* 16 bits, the head index. */
#define	CSR_DB_RECV_TAIL	0x1146 /* 16 bits, the tail index. */

/*
 * ------------------------------------------------------------
 * The send ring
 * ------------------------------------------------------------
 */
#define	CSR_DB_SEND_ADDRESS	0x1148
#define	CSR_DB_SEND_HEAD	0x114c
#define	CSR_DB_SEND_TAIL	0x114e

#define	CSR_DB_CONF		0x1150	/* DBM configuration, 32 bits */

/* Firmware debug interface (FDI) data window. */
#define	CSR_FDI_WINDOW		0x1200   /* Start (lowest) address of window */

typedef struct
{
	uint32_t	version_low;
	uint32_t	version_high;
	uint32_t	ldom_low;
	uint32_t	ldom_high;
	uint32_t	io_timeout;

} cpg_io_map_t;

/*
 * Interrupt status bits for CSR_OB_DOORBELL
 */
#define	INTSTAT_FAULT	(1<<0)	/* device faulted */
#define	INTSTAT_CTL	(1<<1)	/* control complete */
#define	INTSTAT_SECCMD	(1<<2)	/* secure command complete */
#define	INTSTAT_CADONE	(1<<3)	/* assymetric crypto completion */
#define	INTSTAT_CBDONE	(1<<4)	/* bulk crypto completion */
#define	INTSTAT_OMDONE	(1<<5)	/* object management completion */
#define	INTSTAT_ENABLED	(1<<6)	/* firmware has been enabled */
#define	INTSTAT_DBM_SND	(1<<7)	/* A DBM request from the firmware */
#define	INTSTAT_DBM_RCV	(1<<8)	/* A DBM response from the host */
#define	INTSTAT_FRI_IND	(1<<11)	/* A request from the firmware. */
#define	INTSTAT_LOG	(1<<13)	/* log entry available */
#define	INTSTAT_LOGLOST	(1<<14)	/* log messages are being lost */

/*
 * Interrupt signal bits for CSR_IB_DOORBELL
 */

/* Firmware uses bit position values for interrupt handlers */
#define	MF_ENABLE_ID	0	/* CSR enable irq ID */
#define	MF_CTL_ID	1	/* Control irq ID */
#define	MF_CMD_ID	2	/* Command irq ID */
#define	MF_MSG_TAKE_ID	3	/* Message tail update irq ID */
#define	MF_FRI_ID	5	/* FRI irq ID */
#define	MF_DBM_SND_ID	6	/* DBM send irq ID */
#define	MF_DBM_RCV_ID	7	/* DBM receive irq ID */
#define	MF_ADM_DIS_ID	10	/* Secure administration disconnect */
#define	MF_CA_KICK_ID	12	/* asym crypto kick register irq ID */
#define	MF_CB_KICK_ID	13	/* bulk crypto kick register irq ID */
#define	MF_OM_KICK_ID	14	/* object management kick regi irq ID */
#define	MF_RESET_ID	29	/* Hardware reset request interrupt */
#define	MF_DIAG_ID	30	/* Diagnostic CSR enable irq ID */

/* Signal bit names used by driver and firmware */
#define	SIGNAL_ENABLE	(1<<MF_ENABLE_ID)	/* enable CSR window */
#define	SIGNAL_CTL	(1<<MF_CTL_ID)		/* control sent to device */
#define	SIGNAL_SECCMD	(1<<MF_CMD_ID)		/* command sent to device */
#define	SIGNAL_LOG	(1<<MF_MSG_TAKE_ID)	/* space avail in log ring */
#define	SIGNAL_KSKICK	(1<<MF_KS_UPDATE_ID)	/* keystore update kick */
#define	SIGNAL_FRI	(1<<MF_FRI_ID)		/* FRI update */
#define	SIGNAL_DBM_SND	(1<<MF_DBM_SND_ID)	/* DBM request submitted */
#define	SIGNAL_DBM_RCV	(1<<MF_DBM_RCV_ID)	/* DBM response submitted */
#define	SIGNAL_ADMDIS	(1<<MF_ADM_DIS_ID)	/* mcaadm disconnect */
#define	SIGNAL_CAKICK	(1<<MF_CA_KICK_ID)	/* job submitted to CA ring */
#define	SIGNAL_CBKICK	(1<<MF_CB_KICK_ID)	/* job submitted to CB ring */
#define	SIGNAL_OMKICK	(1<<MF_OM_KICK_ID)	/* job submitted to OM ring */
#define	SIGNAL_RESET	(1<<MF_RESET_ID)	/* diagnostic use only */
#define	SIGNAL_DIAG	(1<<MF_DIAG_ID)		/* diagnostic use only */
#define	SIGNAL_ALL	0xFFFFFFFF		/* All doorbell interrupts */

/*
 * State bits for CSR_CONFIG (venus bit positions maintained)
 */
#define	CONFIG_FWSTATE		0x0000000f	/* fw state mask */
#define	CONFIG_FIPS		0x00000010	/* fips mode */
#define	CONFIG_POSTERR		0x00000020	/* post error */
#define	CONFIG_ZEROIZE		0x00000040	/* zeroize jumper enabled */
#define	CONFIG_FACTORY		0x00000100	/* running factory firmware */
#define	CONFIG_OWNED		0x00000200	/* card initialized */
#define	CONFIG_FACTBAD		0x00000400	/* factory firmware corrupt */
#define	CONFIG_FWBAD		0x00000800	/* firmware copy corrupt */
#define	CONFIG_LOGFULL		0x00001000	/* message log is full */
#define	CONFIG_ENABLED		0x00002000	/* CSR window enabled */
#define	CONFIG_UPDATED		0x00004000	/* updated firmware present */
#define	CONFIG_PCI_SPEED  	0x00018000	/* PCI speed mask */
#define	CONFIG_DEBUG		0x00020000	/* running debug firmware */

#define	FWSTATE_IPOST		0x00000000	/* running IPOST */
#define	FWSTATE_POST		0x00000001	/* running POST */
#define	FWSTATE_DISABLED	0x00000002	/* ready to be enabled */
#define	FWSTATE_IDLE		0x00000003	/* card is idle */
#define	FWSTATE_ACTIVE		0x00000004	/* card is operational */
#define	FWSTATE_FAILSAFE	0x00000005	/* failsafe (factory fw) */
#define	FWSTATE_RESET		0x00000006	/* card needs to be reset */
#define	FWSTATE_HALTED		0x0000000F	/* card halted due to error */
#define	FWSTATE_INVALID		0x0000000A	/* for valid data checks */

/* Alternate state names used by firmware */
#define	IPOST_STATE		FWSTATE_IPOST
#define	POST_STATE		FWSTATE_POST
#define	DISABLED_STATE		FWSTATE_DISABLED
#define	IDLE_STATE		FWSTATE_IDLE
#define	ACTIVE_STATE		FWSTATE_ACTIVE
#define	FAILSAFE_STATE		FWSTATE_FAILSAFE
#define	RESET_STATE		FWSTATE_RESET
#define	HALTED_STATE		FWSTATE_HALTED
#define	INVALID_STATE		FWSTATE_INVALID

#define	BUS_SPEED_66		0x00008000	/* Bus running at 66 Mhz */
#define	BUS_SPEED_100		0x00010000	/* Bus running at 100 Mhz */
#define	BUS_SPEED_133		0x00018000	/* Bus running at 133 Mhz */

/*
 * Diagnostic results fields
 */
#define	DIAG_MEM_ERROR_MASK	0x80

/*
 * Command values
 */
typedef enum {
	FWCTL_NULL	 = 0x0000,	/* null (unused) command */
	FWCTL_FWRESET	 = 0x0001,	/* reset firmware only */
	FWCTL_DIAG	 = 0x0002,	/* diagnostics */
	FWCTL_POST	 = 0x0004,	/* complete power on self tests */
	FWCTL_STARTSTOP	 = 0x0008,	/* start crypto processing */
	FWCTL_UPGRADE	 = 0x0010,	/* firmware upgrade */
	FWCTL_ZEROIZE	 = 0x0020,	/* zeroize the board, destroys keys */
	FWCTL_UPGRADE_BS = 0x0080,	/* bootstrap firmware upgrade */
	FWCTL_GETPUBKEY	 = 0x0100,	/* get firmware public key */
	FWCTL_SETKTIKEY	 = 0x0200,	/* set (encrypted) transport key */
	FWCTL_FDIREQ	 = 0x0400,	/* Retrieve some sort of info */
	FWCTL_FDIREPLY	 = 0x0800,	/* Reply to a firmware request */
	FWCTL_DOWNLOAD	 = 0x1000,	/* Download an object file */
	FWCTL_GETFRUID	 = 0x2000,	/* Upload fruid data from the board */
	FWCTL_HOSTREADY	 = 0x4000,	/* The Host is ready and waiting. */
	FWCTL_SECCMD	 = 0xFFFF	/* Indicates dma seccmd in progress */
} mca_fw_cmd_t;

/* status values */
typedef enum {
	FWCTL_CMD_SUCCESS = 0,
	FWCTL_CMD_ERROR,
	FWCTL_CMD_INVALID,
	FWCTL_CMD_BAD_SIZE,
	FWCTL_CMD_UNKNOWN,
	FWCTL_CMD_ACCESS_ERROR
} mca_fw_stat_t;

typedef enum {
	FRI_IND_TIME = 2, /* Maintain venus values */
	FRI_IND_DEBUG_ON,
	FRI_IND_DEBUG_OFF,
	FRI_IND_DBM,
	FRI_IND_BROADCAST
} mca_fri_ind_t;

/*
 * Constants used for DMA chaining via address/size CSRs.  The most
 * significant in size registers will be used to indicate dma chaining.
 */
#define	MCA_DMA_CHAIN_FLAG		0x80000000
#define	MCA_SET_DMA_CHAIN_FLAG(size)	(size | MCA_DMA_CHAIN_FLAG)
#define	MCA_CLR_DMA_CHAIN_FLAG(size)	(size & (~MCA_DMA_CHAIN_FLAG))
#define	MCA_DMA_CHAIN_FLAG_SET(size)	(size & MCA_DMA_CHAIN_FLAG)

typedef struct mca_dma_chain_hdr_s {
	uint32_t	tsize;		/* Total size of chain in bytes */
	uint32_t	vsize;		/* Size of valid data within chain */
	uint32_t	links;		/* Number of links (frags) in chain */
} mca_dma_chain_hdr_t;

typedef struct mca_dma_chain_link_s {
	uint32_t	bsize;		/* Size of data fragment in bytes */
	uint32_t	address;	/* Host pci address of fragment */
} mca_dma_chain_link_t;

#define	MCA_DMA_CHAIN_SIZE(hdr)	(sizeof (mca_dma_chain_hdr_t) + \
				(hdr->links * sizeof (mca_dma_chain_link_t)))

#ifdef	CPU_XSCALE

#include <mPci.h>

#define	UINT64_P	(uint64_t *)
#define	UINT32_P	(uint32_t *)
#define	UINT16_P	(uint16_t *)
#define	UINT8_P		(uint8_t *)

/*
 * ATU csr access pointers
 */

/*
 * Core Firmware CSRs
 */
#define	MARS_CFG_P		UINT32_P(csrBaseAddr() + CSR_CONFIG)
#define	MCF_HW_VER_P		UINT32_P(csrBaseAddr() + CSR_HWVERSION)
#define	MCF_FW_VER_P		UINT32_P(csrBaseAddr() + CSR_FWVERSION)
#define	MCF_IF_VER_P		UINT32_P(csrBaseAddr() + CSR_IFVERSION)
#define	MCF_POST_DEVICE_P	UINT8_P(csrBaseAddr() + CSR_POSTRESULT)
#define	MCF_POST_STATUS_P	UINT8_P(csrBaseAddr() + CSR_POSTRESULT + 1)
#define	MCF_CONTROL_P		UINT16_P(csrBaseAddr() + CSR_FWCTL)
#define	MCF_STATUS_P		UINT16_P(csrBaseAddr() + CSR_FWSTAT)
#define	MCF_CTL_DATA_SZ_P	UINT32_P(csrBaseAddr() + CSR_FWCTLSZ)
#define	MCF_CTL_DATA_ADR_P	UINT32_P(csrBaseAddr() + CSR_FWCTLDATA)
#define	MCF_SECURE_CMD_BUF_SZ_P	UINT32_P(csrBaseAddr() + CSR_SECCMDBUFSZ)
#define	MCF_SECURE_CMD_ADR_P	UINT32_P(csrBaseAddr() + CSR_SECCMDADDR)
#define	MCF_SECURE_CMD_SZ_P	UINT32_P(csrBaseAddr() + CSR_SECCMDSZ)
#define	MCF_DMA_SZ_P		UINT32_P(csrBaseAddr() + CSR_SCRATCHSZ)
#define	MCF_DMA_ADR_P		UINT32_P(csrBaseAddr() + CSR_SCRATCHADDR)
#define	MCF_DIAG_ADR_P		UINT32_P(csrBaseAddr() + CSR_DIAGFAILADDR)
#define	MCF_DIAG_EXP_P		UINT32_P(csrBaseAddr() + CSR_DIAGFAILEXPECTED)
#define	MCF_DIAG_ACT_P		UINT32_P(csrBaseAddr() + CSR_DIAGFAILACTUAL)
#define	MCF_MSG_RING_SZ_P	UINT8_P(csrBaseAddr() + CSR_LOGRINGSZ)
#define	MCF_MSG_RING_HEAD_P	UINT8_P(csrBaseAddr() + CSR_LOGRINGHEAD)
#define	MCF_MSG_RING_TAIL_P	UINT8_P(csrBaseAddr() + CSR_LOGRINGTAIL)
#define	MCF_MSG_LOG_IMASK_P	UINT8_P(csrBaseAddr() + CSR_LOGINTMASK)
#define	MCF_MSG_LOG_MASK_P	UINT8_P(csrBaseAddr() + CSR_LOGMASK)
#define	MCF_MSG_LOG_FMASK_P	UINT16_P(csrBaseAddr() + CSR_LOGFACMASK)
#define	MCF_MSG_RING_ADR_P	UINT32_P(csrBaseAddr() + CSR_LOGRINGADDR)
#define	MCF_DRV_IFVERSION_P	UINT32_P(csrBaseAddr() + CSR_DRV_IFVERSION)
#define	MCF_DRV_INSTANCE_P	UINT32_P(csrBaseAddr() + CSR_DRV_INSTANCE)
#define	MCF_DRV_DOM		UINT64_P(csrBaseAddr() + CSR_DRV_DOM)
#define	MCF_DISCONNECT_DOM_P	UINT64_P(csrBaseAddr() + CSR_DISCONNECT_DOM)
#define	MCF_DISCONNECT_CHAN_P	UINT32_P(csrBaseAddr() + CSR_DISCONNECT_CHAN)

#define	MCF_CSR_BASE		MARS_CFG_P
#define	MKS_CSR_BASE		MCF_KEYSTORE_P
#define	MSC_CSR_BASE		UINT32_P(csrBaseAddr() + CSR_CRYPTOCONF)
#define	FRI_CSR_BASE		UINT32_P(csrBaseAddr() + CSR_FRI_OFFSET)
#define	DBMI_CSR_BASE		UINT32_P(csrBaseAddr() + CSR_DBMI_OFFSET)

/*
 * Mars I/O driver area.
 */
#define	CIO_CSR_BASE		UINT32_P(csrBaseAddr() + CSR_IO_BASE)

/*
 * CSR access structures
 */
typedef struct mcf_csr {
	uint32_t	cfg;		/* Mars configuration register */
	uint32_t	hw_ver;		/* Hardware Version Number */
	uint32_t	fw_ver;		/* Firmware Version Number */
	uint32_t	if_ver;		/* Interface Version Number */
	uint8_t		post_dev;	/* POST failed device */
	uint8_t		post_status;	/* POST status */
	uint16_t	res_word;	/* Reserved word (16 bits) */
	uint16_t	control;	/* Firmware Control */
	uint16_t	status;		/* Firmware Status */
	uint32_t	ctl_data_size;	/* Control Command Buffer Size */
	uint32_t	ctl_data_add;	/* Control Command Buffer Address */
	uint32_t	cmd_buff_size;	/* Secure Command Buffer Size */
	uint32_t	cmd_address;	/* Secure Command Buffer Address */
	uint32_t	cmd_size;	/* Secure Command Size */
	uint32_t	dma_size;	/* DMA Diagnostic Buffer Size */
	uint32_t	dma_address;	/* DMA Diagnostic Buffer Address */
	uint32_t	diag_address;	/* Diagnostics Failure Address */
	uint32_t	diag_expected;	/* Diagnostics Expected Value */
	uint32_t	diag_actual;	/* Diagnostics Actual Value */
	uint8_t		ring_size;	/* Host Message Ring Size */
	uint8_t		ring_head;	/* Host Message Ring Head */
	uint8_t		ring_tail;	/* Host Message Ring Tail */
	uint8_t		res_byte;	/* Reserved byte */
	uint8_t		log_imask;	/* Message Log Interrupt Level Mask */
	uint8_t		log_mask;	/* Message Log Level Mask */
	uint16_t	log_fmask;	/* Message Log Facility Mask */
	uint32_t	ring_address;	/* Host Message Descriptor Ring Addr */
	uint32_t	drv_if_ver;	/* Driver IF Version Number */
	uint32_t	drv_instance;	/* Driver Instance number */
	uint32_t	res_long;	/* Reserved longword */
	uint64_t	drv_dom;	/* Driver Domain */
	uint64_t	dc_dom;		/* Disconnect Domain */
	uint32_t	dc_chan;	/* Disconnect Channel ID */
} mcf_csr_t;

typedef struct diag_cmd {
	uint8_t		device;	/* Device to be tested */
	uint8_t		pat;	/* Pattern to use for memory tests */
	uint16_t	times;	/* Iterations of the test to be run */
} diag_cmd_t;

typedef struct kti_data {
	uint32_t	size;				/* KTK size in bytes */
	uint8_t		data[KTK_MAX_LENGTH];		/* KTK data */
	char		name[KTI_NAME_MAX_LENGTH];	/* KTI client name */
	char		pass[KTI_PASS_MAX_LENGTH];	/* KTI client passwd */
} kti_data_t;

#endif	/* CPU_XSCALE */

#ifdef	__cplusplus
}
#endif

#endif	/* _MCA_CSRS_H */
