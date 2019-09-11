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

#pragma ident	"@(#)mcactl.c	1.36	08/12/02 SMI"

/*
 * Mars - pure cryptographic acceleration + secure keystore
 */

#ifdef LINUX
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/wait.h>
#include <linux/kmod.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/moduleparam.h>
#include "sol2lin.h"
#include "mca_table.h"
#include "mca.h"
#include "mca_hw.h"
#include "mcactl.h"
#include "os_api.h"
#else
#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/cmn_err.h>
#include <sys/byteorder.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/open.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/mca.h>
#include <sys/mca_table.h>
#include <sys/mca_hw.h>
#include <sys/mcactl.h>
#include <sys/os_api.h>
#endif

#ifdef LINUX
/* To display copyright in the object or executable files */
char copywrite[] = "Copyright 2006 Sun Microsystems, Inc. "
	"All rights reserved. Use is subject to license terms.";
#endif

/*
 * Mars control node.
 */

typedef struct mcactl_minor mcactl_minor_t;

static int mcactl_attach(dev_info_t *, ddi_attach_cmd_t);
static int mcactl_detach(dev_info_t *, ddi_detach_cmd_t);
static int mcactl_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int mcactl_open(dev_t *, int, int, cred_t *);
static int mcactl_close(dev_t, int, int, cred_t *);
static int mcactl_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int mcactl_bind(mcactl_minor_t *, intptr_t);
static int mcactl_unbind(mcactl_minor_t *);
static int mcactl_fwupdate(mcactl_minor_t *, intptr_t, int);
static int mcactl_getcsr(mcactl_minor_t *, intptr_t, int);
static int mcactl_getpci(mcactl_minor_t *, intptr_t, int);
static int mcactl_putcsr(mcactl_minor_t *, intptr_t, int);
static int mcactl_putpci(mcactl_minor_t *, intptr_t, int);
static int mcactl_reset(mcactl_minor_t *);
static int mcactl_diagnostics(mcactl_minor_t *);
static int mcactl_failure(mcactl_minor_t *);
static int mcactl_getpubkey(mcactl_minor_t *, intptr_t, int);
static int mcactl_seccmd(mcactl_minor_t *, intptr_t, int);
static int mcactl_zeroize(mcactl_minor_t *);
static int mcactl_fdi_req(mcactl_minor_t *, intptr_t, int);
static int mcactl_fdi_dl(mcactl_minor_t *, intptr_t, int);
static int mcactl_check_dr(mcactl_minor_t *, int *);
static int mcactl_change_state(mcactl_minor_t *, intptr_t, int);
static int mcactl_probe(intptr_t, int);
static int mcactl_get_info(mcactl_minor_t *, intptr_t, int);
static int mcactl_get_versions(mcactl_minor_t *, intptr_t, int);
static int mcactl_dbm(mcactl_minor_t *, intptr_t, int);
static int mcactl_suspend(mcactl_minor_t *, int *);
static int mcactl_resume(mcactl_minor_t *, int *);

static dev_info_t	*mcactl_dip = NULL;

struct mcactl_minor {
	minor_t			mc_minor;
	mca_t			*mc_mca;
	kmutex_t		mc_lock;
	int			mc_busy;
	int			mc_isupcall;	/* is it backing keystore? */
	int			mc_isseccmd;	/* is it scamgr? */
};

static mca_table_t	mcactl_minors;
static kmutex_t		mcactl_lock;
#define	MCACTL_NAME	"mcactl"

static struct ddi_device_acc_attr dev_buf_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
#ifdef FMA_COMPLIANT
	DDI_STRICTORDER_ACC,
	DDI_FLAGERR_ACC
#else
	DDI_STRICTORDER_ACC,
#endif
};

#ifdef LINUX

static int mcactl_open_lin(struct inode *inode, struct file *filp);
static int mcactl_close_lin(struct inode *inode, struct file *filp);
static int mcactl_ioctl_lin(struct inode *inode, struct file *filp,
    unsigned int cmd, unsigned long arg);

static int	g_mcactl_major_number = 0;

/* This struct indicates which standard device functions are supported */
static struct file_operations g_mcactl_fops =
{
	ioctl:		mcactl_ioctl_lin,
	open:		mcactl_open_lin,
	release:	mcactl_close_lin,
	owner:		THIS_MODULE
};

int
mcactl_module_init(void)
{
	dev_info_t *dip;

	if ((dip = kmalloc(sizeof (dev_info_t), GFP_ATOMIC)) == NULL)
		return (-ENOMEM);
	memset(dip, 0, sizeof (dev_info_t));

	/* initialize the major number using the automatic method */
	g_mcactl_major_number = register_chrdev(0, MCACTL_NAME, &g_mcactl_fops);
	if (g_mcactl_major_number < 0) {
		DBG(NULL, DWARN,
		    "scactl_module_init: Failed to get major # for module %s\n",
		    MCACTL_NAME);
		kfree(dip);
		return (g_mcactl_major_number);
	}

	if (mcactl_attach(dip, DDI_ATTACH) != DDI_SUCCESS) {
		unregister_chrdev(g_mcactl_major_number, MCACTL_NAME);
		kfree(dip);
		return (-ENODEV);
	}

	return (0);
}

void
mcactl_module_exit(void)
{
	dev_info_t *dip = mcactl_dip;

	mcactl_detach(dip, DDI_DETACH);
	kfree(dip);

	/* Unregister the device and free the major number */
	unregister_chrdev(g_mcactl_major_number, MCACTL_NAME);
}

module_init(mcactl_module_init);
module_exit(mcactl_module_exit);

/*
 * The return code difference between Solaris and Linux.
 * On Linux: positive return code will preserve, 0 is OK, a negative return
 *           code indicates an error and will set errno.
 * On Solaris: positive return code will set errno and the system call will
 *             return -1, 0 is OK.
 */
static int
mcactl_open_lin(struct inode *inode, struct file *filp)
{
	dev_t dev;
	int rv;
	long tmp;

	if ((rv = mcactl_open(&dev, 0, OTYP_CHR, NULL)) != 0)
		return (-rv);

	tmp = dev;
	filp->private_data = (void *)tmp;

	return (0);
}

static int
mcactl_close_lin(struct inode *inode, struct file *filp)
{
	long tmp = (long)(filp->private_data);
	dev_t dev = (dev_t)tmp;
	return (-mcactl_close(dev, 0, OTYP_CHR, NULL));
}

static int
mcactl_ioctl_lin(struct inode *inode, struct file *filp, unsigned int cmd,
    unsigned long arg)
{
	int rval;
	long tmp = (long)(filp->private_data);
	dev_t dev = (dev_t)tmp;
	return (-mcactl_ioctl(dev, cmd, arg, 0, NULL, &rval));
}

#else /* LINUX */

static struct cb_ops mcactl_cbops = {
	mcactl_open,		/* cb_open */
	mcactl_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	mcactl_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_streamtab */
	D_MP,			/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_awrite */
};

/*
 * Device operations.
 */
static struct dev_ops devops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	mcactl_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	mcactl_attach,		/* devo_attach */
	mcactl_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&mcactl_cbops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	ddi_power		/* devo_power */
};

/*
 * Module linkage.
 */
static struct modldrv modldrv = {
	&mod_driverops,			/* drv_modops */
	"MCA Control " DRIVER_VERSION,	/* drv_linkinfo */
	&devops,			/* drv_dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,			/* ml_rev */
	&modldrv,			/* ml_linkage */
	NULL
};

/*
 * DDI entry points.
 */
int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
mcactl_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = mcactl_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *) ((long)ddi_get_instance(mcactl_dip));
		break;
	}
	return (DDI_SUCCESS);
}

#endif /* LINUX */

static int
mcactl_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	mca_table_init(&mcactl_minors, sizeof (struct mcactl_minor),
	    1, 1, NULL);
	mcactl_dip = dip;

	mutex_init(&mcactl_lock, NULL, MUTEX_DRIVER, NULL);

	if (ddi_create_minor_node(dip, "mcactl", S_IFCHR, 0, DDI_PSEUDO, 0) !=
		DDI_SUCCESS) {
		DBG(NULL, DWARN, "unable to create minor node");
		mca_table_destroy(&mcactl_minors);
		mutex_destroy(&mcactl_lock);
		mcactl_dip = NULL;
		return (DDI_FAILURE);
	}

	/* create minor (cloneable?) node */
	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

static int
mcactl_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	/* remove minor nodes */
	ddi_remove_minor_node(dip, NULL);

	mca_table_destroy(&mcactl_minors);
	mutex_destroy(&mcactl_lock);

	mcactl_dip = NULL;
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
mcactl_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	mcactl_minor_t	*mmp;
	int		index;

	/* we do not support layered driver or block device opens */
	if (otyp != OTYP_CHR) {
		DBG(NULL, DWARN, "otyp != OPTYP_CHR");
		return (ENXIO);
	}

	if (mcactl_dip == NULL) {
		DBG(NULL, DWARN, "driver not attached yet");
		return (ENXIO);
	}

	/* exclusive opens are not supported */
	if (flag & FEXCL) {
		DBG(NULL, DWARN, "exclusive open not supported");
		return (ENOTSUP);
	}

	mutex_enter(&mcactl_lock);

	if (mca_table_alloc_slot(&mcactl_minors, &index, (void **)&mmp,
	    KM_SLEEP)) {
		mutex_exit(&mcactl_lock);
		DBG(NULL, DWARN, "unable to allocate minor structure");
		return (ENOMEM);
	}

	mutex_exit(&mcactl_lock);

	if (getminor(makedevice(getmajor(*devp), (minor_t)index)) != index) {
		/* minor overrun */
		DBG(NULL, DWARN, "minor numbers exhausted");
		return (ENXIO);
	}

	mmp->mc_minor = (minor_t)index;
	mmp->mc_mca = NULL;
	mutex_init(&mmp->mc_lock, NULL, MUTEX_DRIVER, NULL);
	mmp->mc_isupcall = 0;

	*devp = makedevice(getmajor(*devp), mmp->mc_minor);

	return (0);
}

/*ARGSUSED*/
static int
mcactl_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	mcactl_minor_t *mmp;

	mutex_enter(&mcactl_lock);
	if (mca_table_lookup(&mcactl_minors, getminor(dev), (void **)&mmp)) {
		mutex_exit(&mcactl_lock);
		return (ENXIO);
	}
	mutex_exit(&mcactl_lock);

	if (mmp->mc_isseccmd) {
		/*
		 * let firmware we are disconnecting so it can drop
		 * any authentication credentials.
		 */
		mca_seccmd_disconnect(mmp->mc_mca, mca_get_domain(),
			mmp->mc_minor);
	}
	/* release any held control node */
	if (mmp->mc_mca != NULL) {
		mca_rele_ctl(mmp->mc_mca);
		mmp->mc_mca = NULL;
	}

	/* release exclusive mcad file thread */
	if (mmp->mc_isupcall) {
		mca_upcall_detach(mmp->mc_minor);
	}
	mutex_destroy(&mmp->mc_lock);

	mutex_enter(&mcactl_lock);
	mca_table_free_slot(&mcactl_minors, mmp->mc_minor);
	mutex_exit(&mcactl_lock);

	return (0);
}

/*ARGSUSED*/
static int
mcactl_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int		rv;
	mcactl_minor_t	*mmp;

	/* start with a zero result */
	*rvalp = 0;

	/* lock the table */
	mutex_enter(&mcactl_lock);
	if (mca_table_lookup(&mcactl_minors, getminor(dev), (void **)&mmp)) {
		mutex_exit(&mcactl_lock);
		return (ENXIO);
	}

	mutex_exit(&mcactl_lock);

	/* mark the node busy */
	mutex_enter(&mmp->mc_lock);
	if (mmp->mc_busy) {
		mutex_exit(&mmp->mc_lock);
		return (EBUSY);
	}
	mmp->mc_busy++;
	mutex_exit(&mmp->mc_lock);

	switch (cmd) {
	case MCACTLBIND:
		rv = mcactl_bind(mmp, arg);
		break;
	case MCACTLUNBIND:
		rv = mcactl_unbind(mmp);
		break;
	case MCACTLFWUPDATE:
		rv = mcactl_fwupdate(mmp, arg, mode);
		break;
	case MCACTLGETCSR:
		rv = mcactl_getcsr(mmp, arg, mode);
		break;
	case MCACTLGETPCI:
		rv = mcactl_getpci(mmp, arg, mode);
		break;
	case MCACTLPUTCSR:
		rv = mcactl_putcsr(mmp, arg, mode);
		break;
	case MCACTLPUTPCI:
		rv = mcactl_putpci(mmp, arg, mode);
		break;
	case MCACTLRESET:
		rv = mcactl_reset(mmp);
		break;
	case MCACTLDIAGNOSTICS:
		rv = mcactl_diagnostics(mmp);
		break;
	case MCACTLFAULT:
		rv = mcactl_failure(mmp);
		break;
	case MCACTLGETPUBKEY:
		rv = mcactl_getpubkey(mmp, arg, mode);
		break;
	case MCACTLDBM:
		rv = mcactl_dbm(mmp, arg, mode);
		break;
	case MCACTLSECCMD:
		rv = mcactl_seccmd(mmp, arg, mode);
		break;
	case MCACTLZEROIZE:
		rv = mcactl_zeroize(mmp);
		break;
	case MCACTLFDIREQ:
		rv = mcactl_fdi_req(mmp, arg, mode);
		break;
	case MCACTLFDIDL:
		rv = mcactl_fdi_dl(mmp, arg, mode);
		break;
	case MCACTLCHECKDR:
		rv = mcactl_check_dr(mmp, rvalp);
		break;
	case MCACTLCHGSTATE:
		rv = mcactl_change_state(mmp, arg, mode);
		break;
	case MCACTLPROBE:
		rv = mcactl_probe(arg, mode);
		break;
	case MCACTLGETINFO:
		rv = mcactl_get_info(mmp, arg, mode);
		break;
	case MCACTLRESUMEDR:
		rv = mcactl_resume(mmp, rvalp);
		break;
	case MCACTLSUSPENDDR:
		rv = mcactl_suspend(mmp, rvalp);
		break;
	case MCACTLGETVER:
		rv = mcactl_get_versions(mmp, arg, mode);
		break;
	default:
		rv = EINVAL;
		break;
	}

	mutex_enter(&mmp->mc_lock);
	mmp->mc_busy = 0;
	mutex_exit(&mmp->mc_lock);
	return (rv);
}

static int
mcactl_bind(mcactl_minor_t *mmp, intptr_t arg)
{
	int	rv;
	if (mmp->mc_mca != NULL) {
		DBG(mmp->mc_mca, DWARN, "already bound");
		return (EALREADY);
	}

	if (mmp->mc_isupcall) {
		DBG(mmp->mc_mca, DWARN, "cannot bind upcall file");
		return (EINVAL);
	}

	if ((rv = mca_hold_ctl((int)arg, &mmp->mc_mca)) != 0) {
		DBG(NULL, DWARN, "failed to bind, rv = %d", rv);
		return (rv);
	}

	return (0);
}

static int
mcactl_unbind(mcactl_minor_t *mmp)
{
	if (mmp->mc_mca == NULL) {
		DBG(NULL, DWARN, "not bound");
		return (EALREADY);
	}

	mca_rele_ctl(mmp->mc_mca);
	mmp->mc_mca = NULL;
	return (0);
}

static int
mcactl_fwupdate(mcactl_minor_t *mmp, intptr_t arg, int mode)
{
	mca_t *mca = mmp->mc_mca;
	ddi_acc_handle_t handle;

	int	fw_select, rv;
	size_t	size, real_length;
	caddr_t	data;

	STRUCT_DECL(mcactl_fwupdate, update);
	STRUCT_INIT(update, mode);

	if (mca == NULL) {
		DBG(NULL, DWARN, "fwupgrade: device not bound");
		return (EINVAL);
	}

	if (mca_fm_isfailed(mca)) {
		DBG(NULL, DWARN, "fwupgrade: device in failed state");
		return (EIO);
	}

	if (ddi_copyin((void *)arg, STRUCT_BUF(update), STRUCT_SIZE(update),
	    mode)) {
		DBG(mca, DWARN, "unable to copyin update struct");
		return (EFAULT);
	}

	size = STRUCT_FGET(update, mfu_size);
	if (size > (4 * 1024 * 1024)) {
		/* we don't allow firmware images larger than 4 Mb */
		return (E2BIG);
	}
	if ((rv = ddi_dma_mem_alloc(mca->mca_ctldmah, size,
		&dev_buf_attr, DDI_DMA_STREAMING,
		DDI_DMA_SLEEP, 0, &data, &real_length,
		&handle)) != DDI_SUCCESS) {
		DBG(NULL, DWARN, "fwupdate: ddi_dma_mem_alloc(%d) failed: %x",
		    size, rv);
		return (ENOMEM);
	}
#ifdef LINUX
	if (mca->mca_ctldmah->sglist == NULL) {
		if (ddi_copyin(STRUCT_FGETP(update, mfu_addr), data, size,
		    mode)) {
			ddi_dma_mem_free(&handle);
			return (EFAULT);
		}
	} else {
		int offset = 0;
		caddr_t tmp = STRUCT_FGETP(update, mfu_addr);
		ddi_dma_handle_t dma_handle = mca->mca_ctldmah;
		int i;
		for (i = 0; i < dma_handle->n_pages; i++) {
			if (ddi_copyin(tmp + offset, dma_handle->sglist[i].page,
			    dma_handle->sglist[i].length, mode)) {
				ddi_dma_mem_free(&handle);
				return (EFAULT);
			}
			offset += dma_handle->sglist[i].length;
		}
	}
#else
	if (ddi_copyin(STRUCT_FGETP(update, mfu_addr), data, size,
		mode)) {
		ddi_dma_mem_free(&handle);
		return (EFAULT);
	}
#endif

	fw_select = STRUCT_FGET(update, mfu_select);

	rv = mca_fwupdate(mca, fw_select, data, size);

	ddi_dma_mem_free(&handle);
	return (rv);
}

static int
mcactl_fdi_dl(mcactl_minor_t *mmp, intptr_t arg, int mode)
{
	mca_t *mca = mmp->mc_mca;
	ddi_acc_handle_t handle;

	caddr_t	data;
	size_t	size, real_length;
	int	rv;

	STRUCT_DECL(mcactl_fwupdate, download);

	if (mca == NULL) {
		DBG(NULL, DWARN, "FDI download: device not bound");
		return (EINVAL);
	}

	if (mca_fm_isoffline(mca)) {
		DBG(NULL, DWARN, "FDI download: device is offline");
		return (EIO);
	}

	STRUCT_INIT(download, mode);

	if (ddi_copyin((void *)arg, STRUCT_BUF(download), STRUCT_SIZE(download),
	    mode)) {
		DBG(mca, DWARN, "unable to copyin download struct");
		return (EFAULT);
	}

	size = STRUCT_FGET(download, mfu_size);
	if ((rv = ddi_dma_mem_alloc(mca->mca_ctldmah, size,
		&dev_buf_attr, DDI_DMA_STREAMING,
		DDI_DMA_SLEEP, 0, &data, &real_length,
		&handle)) != DDI_SUCCESS) {
		DBG(NULL, DWARN, "fdi_dl: ddi_dma_mem_alloc(%d) failed: %x",
		    size, rv);
		return (ENOMEM);
	}
#ifdef LINUX
	if (mca->mca_ctldmah->sglist == NULL) {
		if (ddi_copyin(STRUCT_FGETP(download, mfu_addr), data, size,
		    mode)) {
			ddi_dma_mem_free(&handle);
			return (EFAULT);
		}
	} else {
		int offset = 0;
		caddr_t tmp = STRUCT_FGETP(download, mfu_addr);
		ddi_dma_handle_t dma_handle = mca->mca_ctldmah;
		int i;
		for (i = 0; i < dma_handle->n_pages; i++) {
			if (ddi_copyin(tmp + offset, dma_handle->sglist[i].page,
			    dma_handle->sglist[i].length, mode)) {
				ddi_dma_mem_free(&handle);
				return (EFAULT);
			}
			offset += dma_handle->sglist[i].length;
		}
	}
#else
	if (ddi_copyin(STRUCT_FGETP(download, mfu_addr), data, size, mode)) {
		ddi_dma_mem_free(&handle);
		return (EFAULT);
	}
#endif

	rv = mca_fdi_dl(mca, data, size);

	ddi_dma_mem_free(&handle);
	return (rv);
}

static int
mcactl_getcsr(mcactl_minor_t *mmp, intptr_t arg, int mode)
{
	int			rv;
	struct mcactl_reg	reg;
	uint64_t		val;

	if (mmp->mc_mca == NULL) {
		DBG(NULL, DWARN, "getcsr: device not bound");
		return (EINVAL);
	}

	if (mca_fm_isfailed(mmp->mc_mca)) {
		DBG(NULL, DWARN, "getcsr: device in failed state");
		return (EIO);
	}

	if (ddi_copyin((void *)arg, (void *)&reg, sizeof (reg), mode)) {
		DBG(NULL, DWARN, "getcsr: unable to copyin reg structure");
		return (EFAULT);
	}

	rv = mca_getcsr(mmp->mc_mca, reg.mr_offset, reg.mr_width, &val);
	if (rv != 0) {
		return (rv);
	}

	switch (reg.mr_width) {
	case 8:
		reg.mr_val.mr_val8 = (uint8_t)(val & 0xff);
		break;
	case 16:
		reg.mr_val.mr_val16 = (uint16_t)(val & 0xffff);
		break;
	case 32:
		reg.mr_val.mr_val32 = (uint32_t)(val & 0xffffffffU);
		break;
	case 64:
		reg.mr_val.mr_val64 = val;
		break;
	}

	if (ddi_copyout((void *)&reg, (void *)arg, sizeof (reg), mode)) {
		return (EFAULT);
	}
	return (0);
}

static int
mcactl_getpci(mcactl_minor_t *mmp, intptr_t arg, int mode)
{
	int			rv;
	struct mcactl_reg	reg;
	uint64_t		val;

	if (mmp->mc_mca == NULL) {
		DBG(NULL, DWARN, "getpci: device not bound");
		return (EINVAL);
	}

	if (mca_fm_isfailed(mmp->mc_mca)) {
		DBG(NULL, DWARN, "getpci: device in failed state");
		return (EIO);
	}

	if (ddi_copyin((void *)arg, (void *)&reg, sizeof (reg), mode)) {
		DBG(NULL, DWARN, "getpci: unable to copyin reg structure");
		return (EFAULT);
	}

	rv = mca_getpci(mmp->mc_mca, reg.mr_offset, reg.mr_width, &val);
	if (rv != 0) {
		return (rv);
	}

	switch (reg.mr_width) {
	case 8:
		reg.mr_val.mr_val8 = (uint8_t)(val & 0xff);
		break;
	case 16:
		reg.mr_val.mr_val16 = (uint16_t)(val & 0xffff);
		break;
	case 32:
		reg.mr_val.mr_val32 = (uint32_t)(val & 0xffffffffU);
		break;
	case 64:
		reg.mr_val.mr_val64 = val;
		break;
	}

	if (ddi_copyout((void *)&reg, (void *)arg, sizeof (reg), mode)) {
		return (EFAULT);
	}
	return (0);
}

static int
mcactl_putcsr(mcactl_minor_t *mmp, intptr_t arg, int mode)
{
	int			rv;
	struct mcactl_reg	reg;
	uint64_t		val;

	if (mmp->mc_mca == NULL) {
		DBG(NULL, DWARN, "putcsr: device not bound");
		return (EINVAL);
	}

	if (mca_fm_isfailed(mmp->mc_mca)) {
		DBG(NULL, DWARN, "putcsr: device in failed state");
		return (EIO);
	}

	if (ddi_copyin((void *)arg, (void *)&reg, sizeof (reg), mode)) {
		DBG(NULL, DWARN, "putcsr: unable to copyin reg structure");
		return (EFAULT);
	}

	switch (reg.mr_width) {
	case 8:
		val = reg.mr_val.mr_val8;
		break;
	case 16:
		val = reg.mr_val.mr_val16;
		break;
	case 32:
		val = reg.mr_val.mr_val32;
		break;
	case 64:
		val = reg.mr_val.mr_val64;
		break;
	default:
		return (EINVAL);
	}

	rv = mca_putcsr(mmp->mc_mca, reg.mr_offset, reg.mr_width, val);
	if (rv != 0) {
		return (rv);
	}

	return (0);
}

static int
mcactl_putpci(mcactl_minor_t *mmp, intptr_t arg, int mode)
{
	int			rv;
	struct mcactl_reg	reg;
	uint64_t		val;

	if (mmp->mc_mca == NULL) {
		DBG(NULL, DWARN, "putpci: device not bound");
		return (EINVAL);
	}

	if (mca_fm_isfailed(mmp->mc_mca)) {
		DBG(NULL, DWARN, "putpci: device in failed state");
		return (EIO);
	}

	if (ddi_copyin((void *)arg, (void *)&reg, sizeof (reg), mode)) {
		DBG(NULL, DWARN, "putpci: unable to copyin reg structure");
		return (EFAULT);
	}

	switch (reg.mr_width) {
	case 8:
		val = reg.mr_val.mr_val8;
		break;
	case 16:
		val = reg.mr_val.mr_val16;
		break;
	case 32:
		val = reg.mr_val.mr_val32;
		break;
	case 64:
		val = reg.mr_val.mr_val64;
		break;
	default:
		return (EINVAL);
	}

	rv = mca_putpci(mmp->mc_mca, reg.mr_offset, reg.mr_width, val);
	if (rv != 0) {
		return (rv);
	}

	return (0);
}

static int
mcactl_fdi_req(mcactl_minor_t *mmp, intptr_t arg, int mode)
{
	fdi_request_t request;

	if (mmp->mc_mca == NULL) {
		DBG(NULL, DWARN, "FDI request: device not bound");
		return (EINVAL);
	}

	if (mca_fm_isoffline(mmp->mc_mca)) {
		DBG(NULL, DWARN, "FDI request: device is offline");
		return (EIO);
	}

	if (ddi_copyin((void *)arg, &request, sizeof (request), mode)) {
		DBG(mmp->mc_mca, DWARN, "unable to copyin FDI request struct");
		return (EFAULT);
	}

	return (mca_fdi_req(mmp->mc_mca, (uint32_t *)&request));
}

static int
mcactl_reset(mcactl_minor_t *mmp)
{
	if (mmp->mc_mca == NULL) {
		DBG(NULL, DWARN, "reset: device not bound");
		return (EINVAL);
	}

	return (mca_safereset(mmp->mc_mca));
}

static int
mcactl_diagnostics(mcactl_minor_t *mmp)
{
	if (mmp->mc_mca == NULL) {
		DBG(NULL, DWARN, "diagnostics: device not bound");
		return (EINVAL);
	}

	if (mca_fm_isfailed(mmp->mc_mca)) {
		DBG(NULL, DWARN, "diagnostics: device in failed state");
		return (EIO);
	}

	return (mca_diagnostics(mmp->mc_mca));
}

static int
mcactl_failure(mcactl_minor_t *mmp)
{
	if (mmp->mc_mca == NULL) {
		DBG(NULL, DWARN, "failure: device not bound");
		return (EINVAL);
	}
#ifdef FMA_COMPLIANT
	mutex_enter(&mmp->mc_mca->fm_lock);
	mca_fm_set_softint(mmp->mc_mca);
	mca_fm_set_io_fault(mmp->mc_mca);
	mutex_exit(&mmp->mc_mca->fm_lock);
	mmp->mc_mca->fm_acc_handle = mmp->mc_mca->mca_regshandle;
	ddi_trigger_softintr(mmp->mc_mca->mca_soft_intr);
#else
	mca_failure(mmp->mc_mca, MCA_FMA_NO_CLASS_ID,
	    "mcactl induced failure");
#endif /* FMA_COMPLIANT */

	return (0);
}

static int
mcactl_getpubkey(mcactl_minor_t *mmp, intptr_t arg, int mode)
{
	char		*buf;
	size_t		size;
	int		rv;
	char		*mod, *exp;
	unsigned	modlen, explen;
	char		*ptr;
	mca_t		*mca = mmp->mc_mca;
	STRUCT_DECL(mcactl_getpubkey, hdl);

	STRUCT_INIT(hdl, mode);

	if (mca == NULL) {
		DBG(NULL, DWARN, "getpubkey: device not bound");
		return (EINVAL);
	}

	if (mca_fm_isfailed(mmp->mc_mca)) {
		DBG(NULL, DWARN, "getpubkey: device in failed state");
		return (EIO);
	}

	if (ddi_copyin((void *)arg, STRUCT_BUF(hdl), STRUCT_SIZE(hdl), mode)) {
		DBG(mca, DWARN, "getpubkey: unable to copyin structure");
		return (EFAULT);
	}

	if (mca_getpubkey(mca, &buf, &size) != DDI_SUCCESS) {
		DBG(mca, DWARN, "getpubkey: unable to get public key");
		return (EIO);
	}

	if (size < (sizeof (uint32_t) * 3)) {
		DBG(mca, DWARN, "getpubkey: runt public key buffer");
		rv = EIO;
		goto done;
	}

	ptr = buf;
	/* we don't care about the modulus bitlength right now, skip it */
	/* modbits = GETBUF32((unsigned *)ptr); */
	ptr += sizeof (uint32_t);
	modlen = GETBUF32((unsigned *)ptr);
	ptr += sizeof (uint32_t);
	explen = GETBUF32((unsigned *)ptr);
	ptr += sizeof (uint32_t);
	mod = ptr;
	exp = mod + modlen;

	if (size < ((sizeof (uint32_t) * 3) + modlen + explen)) {
		DBG(mca, DWARN, "getpubkey: short public key buffer (%d, %d)",
		    modlen, explen);
		rv = EIO;
		goto done;
	}

	STRUCT_FSET(hdl, mpk_modlen, modlen);
	STRUCT_FSET(hdl, mpk_explen, explen);

	if ((modlen > STRUCT_FGET(hdl, mpk_modlen)) ||
	    (explen > STRUCT_FGET(hdl, mpk_explen))) {
		rv = ENOSPC;
	} else if (ddi_copyout(mod, STRUCT_FGETP(hdl, mpk_modulus), modlen,
	    mode)) {
		DBG(mca, DWARN, "fault copying out public modulus");
		rv = EFAULT;
	} else if (ddi_copyout(exp, STRUCT_FGETP(hdl, mpk_exponent), explen,
	    mode)) {
		DBG(mca, DWARN, "fault copying out public exponent");
		rv = EFAULT;
	} else {
		rv = 0;
	}
	if (ddi_copyout(STRUCT_BUF(hdl), (void *)arg, STRUCT_SIZE(hdl),
	    mode)) {
		DBG(NULL, DWARN, "fault copying out structure");
		rv = EFAULT;
	}

done:
	kmem_free(buf, size);
	return (rv);
}


static int
mcactl_seccmd(mcactl_minor_t *mmp, intptr_t arg, int mode)
{
	mca_t *mca = mmp->mc_mca;
	ddi_acc_handle_t handle;

	caddr_t		data;
	char		*ubuf;
	size_t		size, used, real_length;
	unsigned	flags;
	int		rv;
	int 		offset = MCA_IDC_SZ;

	STRUCT_DECL(mcactl_seccmd, hdl);
	STRUCT_INIT(hdl, mode);

	if (mca == NULL) {
		DBG(NULL, DWARN, "seccmd: device not bound");
		return (EINVAL);
	}

	if (!mmp->mc_isseccmd) {
		mmp->mc_isseccmd = 1;
	}

	if (mca_fm_isfailed(mca)) {
		DBG(NULL, DWARN, "seccmd: device in failed state");
		return (EIO);
	}

	if (mca_isrekey(mca)) {
		DBG(NULL, DWARN, "seccmd: device in rekey state");
		return (EIO);
	}

	/* pre 1.1 does not understand the IDC header */
	if (MCA_FW_IF_COMP_VERSION(mca) <= MCA_IF_VERSION_1_0) {
		DBG(mca, DCHATTY, "pre 1.1 firmware - IDC not supported");
		offset = 0;
	}

	if (ddi_copyin((void *)arg, STRUCT_BUF(hdl), STRUCT_SIZE(hdl), mode)) {
		DBG(NULL, DWARN, "unable to copyin seccmd structure");
		return (EFAULT);
	}

	ubuf = STRUCT_FGETP(hdl, msc_buf);
	size = STRUCT_FGET(hdl, msc_blksize);
	used = STRUCT_FGET(hdl, msc_actsize);
	flags = STRUCT_FGET(hdl, msc_flags);

	/* upper limit on inbound sizes */
	if ((size > ((4 * 1024 * 1024) - offset)) || (used > size)) {
		return (E2BIG);
	}
	if ((rv = ddi_dma_mem_alloc(mca->mca_ctldmah, size + offset,
		&dev_buf_attr, DDI_DMA_STREAMING,
		DDI_DMA_SLEEP, 0, &data, &real_length,
		&handle)) != DDI_SUCCESS) {
		DBG(NULL, DWARN, "seccmd: ddi_dma_mem_alloc(%d) failed: %x",
		    size, rv);
		return (ENOMEM);
	}
#ifdef LINUX
	if (mca->mca_ctldmah->sglist == NULL) {
		/* we only copyin the data that is used in the inbound buf */
		if (ddi_copyin(ubuf, data + offset, used, mode)) {
			ddi_dma_mem_free(&handle);
			return (EFAULT);
		}
	} else {
		int copied = 0;
		caddr_t tmp = ubuf;
		ddi_dma_handle_t dma_handle = mca->mca_ctldmah;
		int i;
		for (i = 0; i < dma_handle->n_pages; i++) {
			/* 1st page has pre-pended IDC header - so skip it */
			if (i == 0) {
				if (ddi_copyin(tmp,
				    dma_handle->sglist[i].page + offset,
				    dma_handle->sglist[i].length - offset,
				    mode)) {
					ddi_dma_mem_free(&handle);
					return (EFAULT);
				}
				copied += dma_handle->sglist[i].length - offset;

			} else {
				if (ddi_copyin(tmp + copied,
				    dma_handle->sglist[i].page,
				    dma_handle->sglist[i].length, mode)) {
					ddi_dma_mem_free(&handle);
					return (EFAULT);
				}
				copied += dma_handle->sglist[i].length;
			}
		}
	}
#else
	DBG(mca, DADMIN, "copying in seccmd 0x%x(0x%x), %d\n",
			data, data + offset, used);
	/* we only copyin the data that is used in the inbound buf */
	if (ddi_copyin(ubuf, data + offset, used, mode)) {
		ddi_dma_mem_free(&handle);
		return (EFAULT);
	}
#endif

	/* does the fw understand the IDC header? */
	if (offset) {
		mca_update_idc_hdr((mca_idc_hdr_t *)data, mmp->mc_minor,
		    mca_get_domain());
	}
	used += offset;

	rv = mca_seccmd(mca, data, size + offset, &used, flags);

	/* strip off IDC if present */
	used -= offset;

	STRUCT_FSET(hdl, msc_actsize, used);

	if ((rv == 0) || (rv == ENOSPC)) {
		/* only copyout as many bytes as there is room for */
		if (ddi_copyout(data + offset, ubuf,
		    max(used, size), mode)) {
			rv = EFAULT;
		}
		if (ddi_copyout(STRUCT_BUF(hdl), (void *)arg,
		    STRUCT_SIZE(hdl), mode)) {
			rv = EFAULT;
		}
	}

	ddi_dma_mem_free(&handle);
	return (rv);
}

static int
mcactl_zeroize(mcactl_minor_t *mmp)
{
	if (mmp->mc_mca == NULL) {
		DBG(NULL, DWARN, "zeroize: device not bound");
		return (EINVAL);
	}

	if (mca_fm_isfailed(mmp->mc_mca)) {
		DBG(NULL, DWARN, "zeroize: device in failed state");
		return (EIO);
	}

	return (mca_zeroize(mmp->mc_mca));
}

static int
mcactl_check_dr(mcactl_minor_t *mmp, int *rvalp)
{
	if (mmp->mc_mca == NULL) {
		DBG(NULL, DWARN, "check_dr: device not bound");
		return (EINVAL);
	}

	/*
	 * see if provider is busy.  rvalp is being used to
	 * return a boolean return value.
	 */
	*rvalp = mca_provider_in_use(mmp->mc_mca);

	return (0);
}

/*
 * Change the state of the device.
 * note; state = [DIAG, OFFLINE, ONLINE]
 */
static int
mcactl_change_state(mcactl_minor_t *mmp, intptr_t arg, int mode)
{
	int		state;

	if (mmp->mc_mca == NULL) {
		DBG(NULL, DWARN, "change_state: device not bound");
		return (EINVAL);
	}

	if (ddi_copyin((void *)arg, (void *)&state, sizeof (int), mode)) {
		DBG(NULL, DWARN, "change_state: unable to copyin state");
		return (EFAULT);
	}

	switch (state) {
	case MCASTATE_OFFLINE:
		return (mca_chgstate_offline(mmp->mc_mca));
	case MCASTATE_DIAG:
		return (mca_chgstate_diag(mmp->mc_mca));
	case MCASTATE_ONLINE:
		return (mca_chgstate_online(mmp->mc_mca));
	default:
		return (EINVAL);
	}
}

/*
 * Enumerate the devices, and returns an array of device minor numbers.
 * Note: Max number of devices is MAX_DEVS(32)
 */
static int
mcactl_probe(intptr_t arg, int mode)
{
	struct mcactl_probe	probe;

	probe.mpr_ndevs = MAX_DEVS;
	mca_probe(probe.mpr_devinst, &probe.mpr_ndevs);

	if (ddi_copyout((void *)&probe, (void *)arg, sizeof (probe), mode)) {
		DBG(NULL, DWARN, "probe: failed to copyout");
		return (EFAULT);
	}

	return (0);
}

/*
 * Return state(offline, online, diag) and status (initialized, uninitialized)
 * of a device.
 */
static int
mcactl_get_info(mcactl_minor_t *mmp, intptr_t arg, int mode)
{
	struct mcactl_getinfo	info;

	if (mmp->mc_mca == NULL) {
		DBG(NULL, DWARN, "get_info: device not bound");
		return (EINVAL);
	}

	mca_get_devinfo(mmp->mc_mca, &info.mgi_state, &info.mgi_status);

	if (ddi_copyout((void *)&info, (void *)arg, sizeof (info), mode)) {
		return (EFAULT);
	}

	return (0);
}



/*
 * Return device version numbers (hardware, bootstrap, and firmware)
 */
static int
mcactl_get_versions(mcactl_minor_t *mmp, intptr_t arg, int mode)
{
	struct mcactl_getver	ver;

	if (mmp->mc_mca == NULL) {
		DBG(NULL, DWARN, "get_info: device not bound");
		return (EINVAL);
	}

	mca_get_verinfo(mmp->mc_mca, &ver.hw, &ver.fw, &ver.boot);

	if (ddi_copyout((void *)&ver, (void *)arg, sizeof (ver), mode)) {
		return (EFAULT);
	}

	return (0);
}


static int
mcactl_dbm(mcactl_minor_t *mmp, intptr_t arg, int mode)
{
	int			rv;
	dbm_size_t		paramsz, extent;
	dbm_header_t		head;
	char			*ibuf;
	size_t			ibufsz;
	uint32_t		type;
	mca_t			*mca;
	char			*obuf;
	int			obuflen;
	void			*ctx;



	if (!mmp->mc_isupcall) {
		if ((rv = mca_upcall_attach(mmp->mc_minor)) != 0) {
			DBG(NULL, DWARN, "fileop: another minor bound?");
			return (rv);
		}
		mmp->mc_isupcall = 1;
	}

	if (ddi_copyin((void *)arg, &head, sizeof (head), mode)) {
		DBG(NULL, DWARN, "unable to copyin fileop struct");
		return (EFAULT);
	}

	type = ntohl(head.type);
	extent = ntohl(head.extent);
	paramsz = ntohl(head.paramSize);

	DBG(NULL, DDBM, "mcactl_dbm: DBM message type %d,  "
	    "extent %d, paramsz %d", type, extent, paramsz);

	switch (type) {
	case DB_HELLO:
	{
		int			inst = -1;
		int			isOk = FALSE;
		int			isFailsafe = FALSE;
		dbm_errno_t		status;

		ibufsz = paramsz + MCA_IDC_SZ;

		ibuf = kmem_alloc(ibufsz, KM_NOSLEEP);
		if (ibuf == NULL) {
			return (ENOMEM);
		}

		if (ddi_copyin((void *)arg, ibuf + MCA_IDC_SZ,
			paramsz, mode)) {
			DBG(NULL, DWARN, "unable to copyin "
			    "fileop struct");
			kmem_free(ibuf, ibufsz);
			return (EFAULT);
		}

		mca_update_idc_hdr((mca_idc_hdr_t *)ibuf,
		    mmp->mc_minor, mca_get_domain());

		rv = ENOENT;

		/*
		 * DB_HELLOs must be sent to every mars instance.
		 * As long as any respond positively, a positive
		 * response will be provided to scakiod.  This
		 * is necessary since scakiod does not have any
		 * awareness of actual physical devices. As long
		 * as one card recognizes the keystore, scakiod
		 * will keep that thread open.
		 */
		while (mca_get_next_instance(&inst) == 0) {

			if ((mca = mca_hold_instance(inst)) == NULL) {
				DBG(NULL, DWARN, "mca_hold_instance[%d] "
				    "failed", inst);
				continue;
			}

			/*
			 * if the hardware in the failsafe mode, don't send
			 * the response to the firmware. Return success so
			 * that daemon can go to the standby mode.
			 */
			if (mca_fm_isfailsafe(mca)) {
				DBG(mca, DDBM,
				    "Device is in failsafe state");
				mca_rele_instance(mca);
				isFailsafe = TRUE;
				continue;
			}

			DBG(mca, DDBM,
			    "DB_HELLO issued for channel %d, %s",
			    mmp->mc_minor,
			    ((dbm_hello_t *)(ibuf + MCA_IDC_SZ))->name);

			/* request needs to be sent to FW */
			rv = mca_dbm_response(mca, (void *)ibuf, ibufsz,
			    &obuf, &obuflen, &ctx,
			    (mca_app_handle_t)mmp->mc_minor);

			if (rv != CRYPTO_SUCCESS) {
				DBG(mca, DWARN,
				    "mca_dbm_response eror %d", rv);
				mca_rele_instance(mca);
				continue;
			}

			/* we need only save the 1st good response */
			if (isOk == TRUE) {
				mca_dbm_freereq(ctx);
				mca_rele_instance(mca);
				continue;
			}


			/* note if we've received a good response */
			if ((status = ntohl(((dbm_hello_t *)obuf)->h.status))
			    == 0) {
				isOk = TRUE;
				DBG(mca, DDBM,
				    "mcactl_dbm: DB_HELLO for %s accepted",
				    ((dbm_hello_t *)(ibuf + MCA_IDC_SZ))->name);
			}

			/* save the response */
			if (obuflen > extent) {
				DBG(NULL, DWARN,
				    "DBM 0x%x msg too big(1), "
				    "ext %d, obuflen %d",
				    type, extent, obuflen);
				obuflen = sizeof (head);
			}

			/* copyout the data */
			if (ddi_copyout(obuf, (void *)arg,
			    obuflen, mode)) {
				mca_dbm_freereq(ctx);
				kmem_free(ibuf, ibufsz);
				DBG(NULL, DWARN,
				    "unable to copyout response");
				return (EFAULT);
			}
			mca_dbm_freereq(ctx);
			mca_rele_instance(mca);
		}


		/* no card recognized the keystore */
		if (isOk == FALSE) {
			/*
			 * if there is a firmware mismatch,
			 * we leave the DBM channels open, so go
			 * ahead and register this channel as
			 * a DBM channel.
			 */
			if (isFailsafe == TRUE) {
				rv = ENOTACTIVE;
				(void) mca_upcall_dbm_register(
				    mmp->mc_minor,
				    ((dbm_hello_t *)
				    (ibuf + MCA_IDC_SZ))->name);
			}

			if (rv) {
				kmem_free(ibuf, ibufsz);
				DBG(NULL, DDBM,
				    "mcactl_dbm: DB_HELLO for %s failed (%d)",
				    ((dbm_hello_t *)(ibuf + MCA_IDC_SZ))->name,
				    rv);
				return (rv);
			}

			DBG(NULL, DDBM,
			    "mcactl_dbm: DB_HELLO for %s rejected (%d)",
			    ((dbm_hello_t *)(ibuf + MCA_IDC_SZ))->name, status);
		} else {
			/* register this as a DBM channel */
			if (mca_upcall_dbm_register(mmp->mc_minor,
			    ((dbm_hello_t *)(ibuf + MCA_IDC_SZ))->name) != 0) {
				kmem_free(ibuf, ibufsz);
				return (ENOENT);
			}
		}
		kmem_free(ibuf, ibufsz);
		break;
	}
	case DB_STANDBY:
	{
		int	size;
		void	*param;

		/* standby: waiting for upcall request from FW */
		if ((rv = mca_upcall_service(mmp->mc_minor, &param,
			&size)) != 0) {
			/* probably EINTR */
			mca_upcall_release(mmp->mc_minor);
			return (rv);
		}

		/*
		 * Firmware should never send the data greater than what's
		 * allocated by the mcaadm (64K).
		 */
		ASSERT(size <= extent);

		/* copyout the data */
		if (ddi_copyout(param, (void *)arg, size, mode)) {
			DBG(NULL, DWARN, "unable to copyout fileop struct");
			mca_upcall_release(mmp->mc_minor);
			return (EFAULT);
		}
		mca_upcall_release(mmp->mc_minor);
		break;
	}
	default:
	{
		int			inst;

		inst = *((char *)&(head.handle));

		if ((mca = mca_hold_instance(inst)) == NULL) {
			DBG(NULL, DWARN, "mca_hold_instance[%d] failed", inst);
			return (EFAULT);
		}

		ibufsz = paramsz + MCA_IDC_SZ;

		ibuf = kmem_alloc(ibufsz, KM_NOSLEEP);
		if (ibuf == NULL) {
			mca_rele_instance(mca);
			DBG(NULL, DWARN, "mcactl_dbm: failed to allocate %d",
			    paramsz);
			return (ENOMEM);
		}

		if (ddi_copyin((void *)arg, ibuf + MCA_IDC_SZ,
		    paramsz, mode)) {
			DBG(NULL, DWARN, "unable to copyin fileop struct");
			mca_rele_instance(mca);
			kmem_free(ibuf, ibufsz);
			return (EFAULT);
		}

		mca_update_idc_hdr((mca_idc_hdr_t *)ibuf,
		    mmp->mc_minor, mca_get_domain());


		/* request needs to be sent to FW */
		rv = mca_dbm_response(mca, (void *)ibuf, ibufsz,
		    &obuf, &obuflen, &ctx, (mca_app_handle_t)mmp->mc_minor);
		if (rv != CRYPTO_SUCCESS) {
			DBG(NULL, DWARN, "mca_dbm_response failed with 0x%x",
			    rv);
			kmem_free(ibuf, ibufsz);
			mca_rele_instance(mca);
			return (rv);
		}


		if (obuflen > extent) {
			DBG(NULL, DWARN,
			    "DBM 0x%x msg too big(2), ext %d, obuflen %d",
			    type, extent, obuflen);
			obuflen = sizeof (head);
		}

		/* copyout the data */
		if (ddi_copyout(obuf, (void *)arg, obuflen, mode)) {
			kmem_free(ibuf, ibufsz);
			mca_rele_instance(mca);
			mca_dbm_freereq(ctx);
			DBG(NULL, DWARN, "unable to copyout fileop struct");
			return (EFAULT);
		}
		kmem_free(ibuf, ibufsz);
		mca_rele_instance(mca);
		mca_dbm_freereq(ctx);
	}
	}

	return (0);
}

static int
mcactl_resume(mcactl_minor_t *mmp, int *rvalp)
{
	if (mmp->mc_mca == NULL) {
		DBG(NULL, DWARN, "resume: device not bound");
		return (EINVAL);
	}

	/*
	 * Attempt to resume driver
	 */
	*rvalp = mca_postresume(mmp->mc_mca, 1);

	return (0);
}

static int
mcactl_suspend(mcactl_minor_t *mmp, int *rvalp)
{
	if (mmp->mc_mca == NULL) {
		DBG(NULL, DWARN, "suspend: device not bound");
		return (EINVAL);
	}

	/*
	 * Attempt to suspend driver
	 */
	*rvalp = mca_presuspend(mmp->mc_mca, 1);

	return (0);
}
