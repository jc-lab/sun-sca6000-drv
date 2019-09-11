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

#ifndef	_SYS_MCA_HW_H
#define	_SYS_MCA_HW_H

#pragma ident	"@(#)mca_hw.h	1.18	08/09/25 SMI"

#ifdef LINUX
#include <linux/types.h>
#include <mca_csrs.h>
#else
#include <sys/types.h>
#include <sys/mca_csrs.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Mars - pure cryptographic acceleration + secure keystore
 *
 * Note: Everything in this file is private to the Mars device
 *	 driver!  Do not include this in any other file.
 */

/*
 * Register access.
 */
#define	GETPCI8(mca, reg)	pci_config_get8(mca->mca_pcihandle, reg)
#define	GETPCI16(mca, reg)	pci_config_get16(mca->mca_pcihandle, reg)
#define	GETPCI32(mca, reg)	pci_config_get32(mca->mca_pcihandle, reg)
#define	GETPCI64(mca, reg)	pci_config_get64(mca->mca_pcihandle, reg)

#define	PUTPCI8(mca, reg, v)	pci_config_put8(mca->mca_pcihandle, reg, v)
#define	PUTPCI16(mca, reg, v)	pci_config_put16(mca->mca_pcihandle, reg, v)
#define	PUTPCI32(mca, reg, v)	pci_config_put32(mca->mca_pcihandle, reg, v)
#define	PUTPCI64(mca, reg, v)	pci_config_put64(mca->mca_pcihandle, reg, v)


#define	GETCSR64(mca, reg)	\
	ddi_get64(mca->mca_regshandle, (uint64_t *)(mca->mca_regs + reg))

#define	GETCSR32(mca, reg)	\
	ddi_get32(mca->mca_regshandle, (uint32_t *)(mca->mca_regs + reg))

#define	GETCSR16(mca, reg)	\
	ddi_get16(mca->mca_regshandle, (uint16_t *)(mca->mca_regs + reg))

#define	GETCSR8(mca, reg)	\
	ddi_get8(mca->mca_regshandle, (uint8_t *)(mca->mca_regs + reg))

#define	PUTCSR64(mca, reg, val)	\
	ddi_put64(mca->mca_regshandle, (uint64_t *)(mca->mca_regs + reg), val)

#define	PUTCSR32(mca, reg, val)	\
	ddi_put32(mca->mca_regshandle, (uint32_t *)(mca->mca_regs + reg), val)

#define	PUTCSR16(mca, reg, val)	\
	ddi_put16(mca->mca_regshandle, (uint16_t *)(mca->mca_regs + reg), val)

#define	PUTCSR8(mca, reg, val)	\
	ddi_put8(mca->mca_regshandle, (uint8_t *)(mca->mca_regs + reg), val)

/*
 * Driver hardening related.
 */
#define	CHECK_PCI(mca)		ddi_check_acc_handle(mca->mca_pcihandle)
#define	CHECK_CSR(mca)		ddi_check_acc_handle(mca->mca_regshandle)

/*
 * FMA  related.
 */
#define	MARS_HALTED(mca)	((GETCSR32(mca, CSR_CONFIG) & CONFIG_FWSTATE) \
				== FWSTATE_HALTED)
#define	MCA_INVALID_CSR8	0xFF
#define	MCA_INVALID_CSR16	0xFFFF
#define	MCA_INVALID_CSR32	0xFFFFFFFF
#ifdef LINUX	/* to eliminate a compiler warning */
#define	MCA_INVALID_CSR64	0x0
#else
#define	MCA_INVALID_CSR64	0xFFFFFFFFFFFFFFFF
#endif
#define	INVALID_CSR_CONFIG	FWSTATE_INVALID

/*
 * Ring access routines.
 */
#define	GETCOMPLETION16(ringp, index, field)	\
	ddi_get16(ringp->mr_acch, &(ringp->mr_completions[index].field))

#define	GETCOMPLETION32(ringp, index, field)	\
	ddi_get32(ringp->mr_acch, &(ringp->mr_completions[index].field))

#define	PUTSUBMIT64(ringp, index, field, val)	\
	ddi_put64(ringp->mr_acch, &(ringp->mr_submissions[index].field), val)

#define	PUTSUBMIT32(ringp, index, field, val)	\
	ddi_put32(ringp->mr_acch, &(ringp->mr_submissions[index].field), val)

#define	PUTSUBMIT16(ringp, index, field, val)	\
	ddi_put16(ringp->mr_acch, &(ringp->mr_submissions[index].field), val)

/*
 * Prototypes.
 */
#ifdef LINUX
uint_t	mca_intr(int, char *, struct pt_regs *regs);
#else
uint_t	mca_intr(char *);
#endif
void	mca_fri_release(mca_t *mca);
int	mca_fdi_req(mca_t *, uint32_t *);
int	mca_fdi_dl(mca_t *, char *, size_t);
void	mca_hardreset(mca_t *, mca_reset_t);
int	mca_masterstart(mca_t *);
void	mca_shutdown(mca_t *);
void	mca_enableinterrupts(mca_t *, int);
void	mca_disableinterrupts(mca_t *, int);
int	mca_getpubkey(mca_t *, char **, size_t *);
int	mca_fwupdate(mca_t *, int, char *, size_t);
int	mca_create_om_chain(mca_chain_t *, uint32_t, caddr_t, uint32_t *);
int	mca_ctlwait(mca_t *, clock_t);
int	mca_getcsr(mca_t *, int, int, uint64_t *);
int	mca_getpci(mca_t *, int, int, uint64_t *);
int	mca_putcsr(mca_t *, int, int, uint64_t);
int	mca_putpci(mca_t *, int, int, uint64_t);
int	mca_diagnostics(mca_t *);
int	mca_keystore_update(mca_t *);
int	mca_seccmd(mca_t *, char *, size_t, size_t *, unsigned);
void	mca_seccmd_disconnect(mca_t *, mca_domain_t, mca_channel_t);
int	mca_zeroize(mca_t *);
int	mca_update_firmware_sadb(mca_t *, mca_sa_t *);
void	mca_boot_wait(mca_t *);
int	mca_create_dma_chain(mca_t *, ddi_dma_handle_t, size_t,
    ddi_dma_cookie_t *, unsigned, mca_dma_buffinfo_t *);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MCA_HW_H */
