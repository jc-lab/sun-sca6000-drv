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

#ifndef	_SYS_MCACTL_H
#define	_SYS_MCACTL_H

#pragma ident	"@(#)mcactl.h	1.11	08/12/02 SMI"

#ifdef LINUX
#include <linux/types.h>
#include <mcactl_adm.h>
#else
#include <sys/types.h>
#include <sys/mcactl_adm.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Mars - pure cryptographic acceleration + secure keystore
 *
 * Note: Everything in this file is private to the Mars device
 *	 driver!  Do not include this in any other file.
 *
 * The values in the uint32_t flags field for administrative commands
 * are defined in mcactl_adm.h
 */

#ifdef LINUX
/* 0x20 - 0x6f are reserved for framework ioctl */
#define	MCA_IOC_MAGIC		'A'
#define	MCACTL(x)		_IO(MCA_IOC_MAGIC, (x + 0x70))
/* Linux has no errno.h definition for ENOTACTIVE (73) so overload it here */
#define	ENOTACTIVE		73
#else
#define	MCACTL(x)		(('V' << 8) | (x))
#endif

#define	MCACTLBIND		MCACTL(1)
#define	MCACTLUNBIND		MCACTL(2)
#define	MCACTLGETCSR		MCACTL(3)
#define	MCACTLPUTCSR		MCACTL(4)
#define	MCACTLFWUPDATE		MCACTL(5)
#define	MCACTLGETPCI		MCACTL(6)
#define	MCACTLPUTPCI		MCACTL(7)
#define	MCACTLRESET		MCACTL(8)
#define	MCACTLDIAGNOSTICS	MCACTL(9)
#define	MCACTLFAULT		MCACTL(10)
#define	MCACTLREPAIR		MCACTL(11)	/* obsolete */
#define	MCACTLFILESTDBY		MCACTL(12)
#define	MCACTLFILEGET		MCACTL(13)
#define	MCACTLFILEPUT		MCACTL(14)
#define	MCACTLFILERESP		MCACTL(15)
#define	MCACTLSECCMD		MCACTL(16)
#define	MCACTLZEROIZE		MCACTL(17)
#define	MCACTLGETPUBKEY		MCACTL(18)
#define	MCACTLFDIREQ		MCACTL(19)
#define	MCACTLFDIDL		MCACTL(20)
#define	MCACTLCHECKDR		MCACTL(21)
#define	MCACTLCHGSTATE		MCACTL(22)
#define	MCACTLPROBE		MCACTL(23)
#define	MCACTLGETINFO		MCACTL(24)
#define	MCACTLDBM		MCACTL(25)
#define	MCACTLRESUMEDR		MCACTL(26)
#define	MCACTLSUSPENDDR		MCACTL(27)
#define	MCACTLGETVER		MCACTL(28)

struct mcactl_reg {
	int			mr_offset;
	int			mr_width;
	union {
		uint8_t		mr_val8;
		uint16_t	mr_val16;
		uint32_t	mr_val32;
		uint64_t	mr_val64;
	}			mr_val;
};

struct mcactl_fwupdate {
	int			mfu_select;
	size_t			mfu_size;
	caddr_t			mfu_addr;
};

#define	MCAFWUPDATE_FW		0	/* Operational firmware */
#define	MCAFWUPDATE_BS		1	/* Bootstrap firmware */

struct mcactl_fileop {
	int			mfo_cmd;
	int			mfo_error;
	char			mfo_name[128];
	size_t			mfo_filesz;
	char			*mfo_filebuf;
};

/* Start with 100K as min size, dynamically allocate if we need more */
#define	MCAMAXSECCMD		(1024 * 100)

struct mcactl_seccmd {
	uint32_t		msc_flags;
	uint32_t		msc_actsize;
	uint32_t		msc_blksize;
	char			*msc_buf;
};

struct mcactl_getpubkey {
	size_t			mpk_modlen;
	size_t			mpk_explen;
	caddr_t			mpk_modulus;
	caddr_t			mpk_exponent;
};

struct mcactl_getver {
	uint32_t		hw;
	uint32_t		fw;
	uint32_t		boot;
};

#define	MAX_DEVS	32
struct mcactl_probe {
	int			mpr_ndevs;
	int			mpr_devinst[MAX_DEVS];
};

/*
 * MCACTLCHGSTATE take one of the following state as parameter. Type is 'int'
 * These are also used for mcactl_getinfo'mgi_state
 */
#define	MCASTATE_OFFLINE	0
#define	MCASTATE_DIAG		1
#define	MCASTATE_ONLINE		2
#define	MCASTATE_FAILED		3

/*
 * mcactl_getinfo'mgi_status
 */
#define	MCASTATUS_UNINIT	0
#define	MCASTATUS_INIT		1
#define	MCASTATUS_FIPS		2

struct mcactl_getinfo {
	int			mgi_state;
	int			mgi_status;
};

#define	FDI_LKUP_MAX 32

typedef struct {
	uint32_t type;
	uint32_t arg1;
	uint32_t arg2;
	uint32_t arg3;
	uint32_t arg4;
	uint32_t arg5;
	uint32_t arg6;
	uint32_t arg7;
	char	cmd[FDI_LKUP_MAX];

} fdi_request_t;

#ifdef	_SYSCALL32
struct mcactl_fwupdate32 {
	int			mfu_select;
	size32_t		mfu_size;
	caddr32_t		mfu_addr;
};

struct mcactl_fileop32 {
	int			mfo_cmd;
	int			mfo_error;
	char			mfo_name[128];
	size32_t		mfo_filesz;
	caddr32_t		mfo_filebuf;
};

struct mcactl_seccmd32 {
	uint32_t		msc_flags;
	uint32_t		msc_actsize;
	uint32_t		msc_blksize;
	caddr32_t		msc_buf;
};

struct mcactl_getpubkey32 {
	size32_t		mpk_modlen;
	size32_t		mpk_explen;
	caddr32_t		mpk_modulus;
	caddr32_t		mpk_exponent;
};

#endif	/* _SYSCALL32 */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MCACTL_H */
