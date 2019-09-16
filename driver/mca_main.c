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

#pragma ident	"@(#)mca.c	1.112	08/12/10 SMI"

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
#include <linux/version.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>
#include "sol2lin.h"
#include "mca_table.h"
#include "mca.h"
#include "mca_hw.h"
#include "mca_log.h"
#include "mca_csrs.h"
#include "mca_attr_infobase.h"
#else /* LINUX */
#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/taskq.h>
#include <sys/random.h>
#include <sys/pci.h>

#include <sys/mca_table.h>
#include <sys/mca.h>
#include <sys/mca_hw.h>
#include <sys/mca_log.h>
#include <sys/mca_csrs.h>

#ifdef FMA_COMPLIANT
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>
#endif /* FMA_COMPLIANT */

#include <sys/mca_attr_infobase.h>
#include <sys/mca_fs_internal.h>
#endif


#ifndef DMA_64BIT_MASK
#define DMA_64BIT_MASK  0xffffffffffffffffULL
#endif

#ifndef DMA_32BIT_MASK
#define DMA_32BIT_MASK  0x00000000ffffffffULL
#endif


/* To display copyright in the object or executable files */
char copywrite[] = "Copyright 2007 Sun Microsystems, Inc. "
	"All rights reserved. Use is subject to license terms.";


/*
 * Global policy structures for cpg_attr stuff.  See also mca.h where
 * symbols corresponding to these entries are defined.
 */
static cpg_attr_info_t a_info_pure[] = CPG_ATTR_POLICY_PKCS11_PURE_INITIALIZER;
static cpg_attr_info_t a_info_active[] =
    CPG_ATTR_POLICY_PKCS11_ACTIVE_INITIALIZER;
static cpg_attr_info_t a_info_create[] =
    CPG_ATTR_POLICY_PKCS11_CREATE_INITIALIZER;
static cpg_attr_info_t a_info_generate[] =
    CPG_ATTR_POLICY_PKCS11_GEN_INITIALIZER;
static cpg_attr_info_t a_info_unwrap[] =
    CPG_ATTR_POLICY_PKCS11_UNWRAP_INITIALIZER;

cpg_attr_info_t *mca_global_policy_array[] = {
	NULL,
	a_info_active,
	a_info_pure,
	a_info_create,
	a_info_generate,
	a_info_unwrap
};

cpg_attr_infobase_t mca_global_attr_infobase = {
	6,  /* number of entries */
	mca_global_policy_array
};

/*
 * Core Mars driver.
 */

static int		mca_attach(dev_info_t *, ddi_attach_cmd_t);
static int		mca_detach(dev_info_t *, ddi_detach_cmd_t);
static int		mca_suspend(mca_t *);
static int		mca_resume(mca_t *);
static void		mca_postresume_timeout(void *);
static int		mca_alloc_dma_buff(mca_t *, struct ddi_dma_attr *,
			mca_dma_buffinfo_t *, size_t *, char *name);
static int		mca_alloc_resources(mca_t *);
static void		mca_free_dma_buff(mca_dma_buffinfo_t *);
static void		mca_free_resources(mca_t *);
static int		mca_realloc_resources(mca_t *);
static void		mca_fm_init(mca_t *);
static int		mca_init(mca_t *);
static int		mca_initring(mca_t *, mca_ring_t *);
static void		mca_uninitring(mca_ring_t *);
static mca_request_t	*mca_newreq(mca_t *);
static void		mca_destroyreq(mca_request_t *);
static void		mca_create_sd_chains(ddi_dma_handle_t, size_t,
			ddi_dma_cookie_t *, unsigned, caddr_t);
static void		jobtimeout(mca_t *mca);
static void		jobtimedout(mca_t *mca);
static void		mca_jobtimeout(void *);
static int		mca_drainring(mca_ring_t *, int isSeccmd);
static int		mca_drainctl(mca_t *);
static void		mca_undrainring(mca_ring_t *);
static void		mca_failring(mca_ring_t *, uint16_t);

static void		mca_failure2(mca_t *);
static int		mca_restart(mca_t *);
static void		reset_count(mca_t *);
static void		serial_reset(void *);

#ifdef FMA_COMPLIANT
static int	mca_chk_ctl_acch(mca_t *, ddi_acc_handle_t);
static int	mca_chk_ctl_dmah(mca_t *, ddi_dma_handle_t);
static int	mca_chk_ring_acch(mca_ring_t *, ddi_acc_handle_t, char *);
static int	mca_chk_ring_dmah(mca_ring_t *, ddi_dma_handle_t, char *);
static int	mca_chk_crypto_acch(mca_t *, ddi_acc_handle_t);
static int	mca_chk_crypto_dmah(mca_t *, ddi_dma_handle_t);
static int	mca_chk_acch(mca_t *, ddi_acc_handle_t);
static int	mca_chk_dmah(mca_t *, ddi_dma_handle_t);
static int	mca_fm_error_cb(dev_info_t *, ddi_fm_error_t *, const void *);
#endif /* FMA_COMPLIANT */

static uint_t	mca_soft_intr(char *);
static void	mca_init_job_timeout_info(mca_t *);
/*LINTED E_STATIC_UNUSED*/
static void	mca_dump_io_chains(mca_request_t *);

/*
 * We want these inlined for performance.
 */
#ifndef	DEBUG
#pragma inline(mca_freereq)
#pragma inline(mca_enqueue, mca_dequeue, mca_rmqueue, mca_done)
#pragma inline(jobtimeout, jobtimedout)
#endif

#define	MCA_TASKQ_DEFAULT_THREADS		4

#ifdef LINUX

struct timer_list sca_timer[MAX_NUM_TIMER];
spinlock_t sca_timer_lock;
int sca_timer_last_index = 0;
int sca_timer_lock_initialized;
spinlock_t sca_work_lock;

#define	MCA_VENDOR_ID			0x108E
#define	MCA_DEVICE_ID			0x5CA0

/* For compilation purpose */
static void _fini(void);

static dev_info_t	*mca_devices[MAX_NUM_SCA_DEVICE];
static int		num_mca_devices;
struct proc_dir_entry	*mca_proc_dir;

/*
 * The parameters can be specified at module loading time as follows:
 * insmod mca mca_fwlogmask=10 mca_fwlogintmask=20
 */
static uint16_t	mca_fwlogmask = DEFAULT_LOGMASK; /* mca_hw.c, "fwlogmask" */
static uint16_t	mca_fwlogintmask = DEFAULT_LOGINTMASK;
						/* mca_hw.c, "fwlogintmask" */
static int	mca_enableaes = 1;		/* mca_kcf.c, "enable-aes" */
static int	mca_enable_rc2cbc = 0;		/* mca_kcf.c, "enable-rc2cbc" */
static int	mca_nostats = 0;		/* mca_kstat.c, "nostats" */
static int	mca_ktibits = 128;		/* mca.c, "ktisz" */
static int	mca_rngdirect = 0;		/* mca.c, "rngdirect" */
static int	mca_dma_chain_size = PAGE_SIZE;	/* mca.c, "dma_chain_size" */
static int	mca_cb_lowater = CBLOWATER;	/* mca.c, "cb_lowater" */
static int	mca_cb_hiwater = CBHIWATER;	/* mca.c, "cb_hiwater" */
static int	mca_ca_lowater = CALOWATER;	/* mca.c, "ca_lowater" */
static int	mca_ca_hiwater = CAHIWATER;	/* mca.c, "ca_hiwater" */
static int	mca_om_lowater = OMLOWATER;	/* mca.c, "om_lowater" */
static int	mca_om_hiwater = OMHIWATER;	/* mca.c, "om_hiwater" */
static int	mca_enable_sha512 = 0;
static int	mca_enable_multi_part_md5 = 0;
static int	mca_enable_multi_part_sha1 = 0;
static int	mca_enable_multi_part_sha512 = 0;
static int	mca_enable_hmac = 0;
static int	mca_taskq_threads = MCA_TASKQ_DEFAULT_THREADS;

module_param(mca_fwlogmask, short, S_IRUGO);
module_param(mca_fwlogintmask, short, S_IRUGO);
module_param(mca_enableaes, int, S_IRUGO);
module_param(mca_enable_rc2cbc, int, S_IRUGO);
module_param(mca_nostats, int, S_IRUGO);
module_param(mca_ktibits, int, S_IRUGO);
module_param(mca_rngdirect, int, S_IRUGO);
module_param(mca_dma_chain_size, int, S_IRUGO);
module_param(mca_cb_lowater, int, S_IRUGO);
module_param(mca_cb_hiwater, int, S_IRUGO);
module_param(mca_ca_lowater, int, S_IRUGO);
module_param(mca_ca_hiwater, int, S_IRUGO);
module_param(mca_om_lowater, int, S_IRUGO);
module_param(mca_om_hiwater, int, S_IRUGO);
module_param(mca_enable_sha512, int, S_IRUGO);
module_param(mca_enable_multi_part_md5, int, S_IRUGO);
module_param(mca_enable_multi_part_sha1, int, S_IRUGO);
module_param(mca_enable_multi_part_sha512, int, S_IRUGO);
module_param(mca_enable_hmac, int, S_IRUGO);
module_param(mca_taskq_threads, int, S_IRUGO);

/*
 * This function needs to be updated for any new parameters or
 * updates of existing parameters.
 */
int
mca_ddi_getprop(char *name)
{
	/*
	 * Performance is not concerned here since it is used only during
	 * initialization
	 */
	if (strcmp(name, "fwlogmask") == 0)
		return (mca_fwlogmask);
	else if (strcmp(name, "fwlogintmask") == 0)
		return (mca_fwlogintmask);
	else if (strcmp(name, "enable-aes") == 0)
		return (mca_enableaes);
	else if (strcmp(name, "enable-rc2cbc") == 0)
		return (mca_enable_rc2cbc);
	else if (strcmp(name, "nostats") == 0)
		return (mca_nostats);
	else if (strcmp(name, "ktisz") == 0)
		return (mca_ktibits);
	else if (strcmp(name, "rngdirect") == 0)
		return (mca_rngdirect);
	else if (strcmp(name, "dma_chain_size") == 0)
		return (mca_dma_chain_size);
	else if (strcmp(name, "cb_lowater") == 0)
		return (mca_cb_lowater);
	else if (strcmp(name, "cb_hiwater") == 0)
		return (mca_cb_hiwater);
	else if (strcmp(name, "ca_lowater") == 0)
		return (mca_ca_lowater);
	else if (strcmp(name, "ca_hiwater") == 0)
		return (mca_ca_hiwater);
	else if (strcmp(name, "om_lowater") == 0)
		return (mca_om_lowater);
	else if (strcmp(name, "om_hiwater") == 0)
		return (mca_om_hiwater);
	else if (strcmp(name, "enable-sha512") == 0)
		return (mca_enable_sha512);
	else if (strcmp(name, "enable-multi-part-md5") == 0)
		return (mca_enable_multi_part_md5);
	else if (strcmp(name, "enable-multi-part-sha1") == 0)
		return (mca_enable_multi_part_sha1);
	else if (strcmp(name, "enable-multi-part-sha512") == 0)
		return (mca_enable_multi_part_sha512);
	else if (strcmp(name, "enable-hmac") == 0)
		return (mca_enable_hmac);
	else if (strcmp(name, "taskq_threads") == 0)
		return (mca_taskq_threads);
	else {
		cmn_err(CE_WARN,
		    "mca_ddi_getprop: unknown param name: %s\n", name);
		return (-1);
	}
}

#else /* LINUX */

/*
 * Device operations.
 */
static struct dev_ops devops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	nodev,			/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	mca_attach,		/* devo_attach */
	mca_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	NULL,			/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	ddi_power		/* devo_power */
};

/*
 * Module linkage.
 */
static struct modldrv modldrv = {
	&mod_driverops,			/* drv_modops */
	"MCA Driver " DRIVER_VERSION,	/* drv_linkinfo */
	&devops,			/* drv_dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* ml_rev */
	&modldrv,		/* ml_linkage */
	NULL
};

#endif /* LINUX */

/*
 * Device attributes.
 */
struct ddi_device_acc_attr mca_regsattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
#ifdef FMA_COMPLIANT
	DDI_STRICTORDER_ACC,
	DDI_FLAGERR_ACC
#else
	DDI_STRICTORDER_ACC,
#endif
};

struct ddi_device_acc_attr mca_devattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
#ifdef FMA_COMPLIANT
	DDI_STRICTORDER_ACC,
	DDI_FLAGERR_ACC
#else
	DDI_STRICTORDER_ACC,
#endif
};

struct ddi_device_acc_attr mca_bufattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
#ifdef FMA_COMPLIANT
	DDI_STRICTORDER_ACC,
	DDI_FLAGERR_ACC
#else
	DDI_STRICTORDER_ACC,
#endif
};


struct ddi_dma_attr mca_dmaattr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0x0,			/* dma_attr_addr_lo */
	0xffffffffUL,		/* dma_attr_addr_hi */
	0x00ffffffUL,		/* dma_attr_count_max */
	0x40,			/* dma_attr_align */
	0x40,			/* dma_attr_burstsizes */
	0x1,			/* dma_attr_minxfer */
	0x00ffffffUL,		/* dma_attr_maxxfer */
	0xffffffffUL,		/* dma_attr_seg */
#if defined(i386) || defined(__i386) || defined(__amd64)
	DMA_COOKIE_MAX,		/* dma_attr_sgllen */
#else
	1,			/* dma_attr_sgllen */
#endif
	1,			/* dma_attr_granular */
#ifdef FMA_COMPLIANT
	DDI_DMA_FLAGERR		/* dma_attr_flags */
#else
	0			/* dma_attr_flags */
#endif
};

struct ddi_dma_attr no_sg_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0x0,			/* dma_attr_addr_lo */
	0xffffffffUL,		/* dma_attr_addr_hi */
	0x00ffffffUL,		/* dma_attr_count_max */
	0x40,			/* dma_attr_align */
	0x40,			/* dma_attr_burstsizes */
	0x1,			/* dma_attr_minxfer */
	0x00ffffffUL,		/* dma_attr_maxxfer */
	0xffffffffUL,		/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
#ifdef FMA_COMPLIANT
	DDI_DMA_FLAGERR		/* dma_attr_flags */
#else
	0			/* dma_attr_flags */
#endif
};

#define	STALETIME	(SECOND)
#define	POSTRESUME_TIME	(120 * SECOND)

/*
 * This lock protects mca_state and mca->mca_refcnt.  We
 * hold it during attach, detach, and when doing operations which
 * under-the covers acquisition of the soft state.  We also protect
 * the KTI (transport key) under the mca_lock.
 */
mca_table_t	mca_state;
kmutex_t	mca_lock;

/* tunable threshold for doing DMA vs. bcopy */
int		mca_mindma = 2500;
int		mca_staletime = STALETIME;
int		mca_default_ktibits = 128;
int		mca_ktisz = 0;
uchar_t		*mca_kti = NULL;
mca_aes_key_t	mca_ktk;
int		mca_taskq_maxalloc = RINGSIZE * 4;
int		mca_taskq_default_threads = MCA_TASKQ_DEFAULT_THREADS;

/*
 * Engineering driver tuneables (not for public consumption).
 */
int		mca_disable_crypto_resets = B_FALSE;
int		mca_disable_crypto_timeouts = B_FALSE;
int		mca_disable_crypto_timeout_msgs = B_FALSE;

static void fini_cleanup(void)
{
	/* cleanup here */
	mca_table_destroy(&mca_state);
	mutex_destroy(&mca_lock);
	mca_upcall_fini();
	mca_keystore_fini();
	kmem_free(mca_kti, mca_ktisz);
	mca_ktisz = 0;
}

/*
 * DDI entry points.
 */
int
_init(void)
{
	int rv;
#ifdef LINUX
	struct pci_dev *mca_device_tmp;
	char dir[64];
	int i;

	DBG(NULL, DENTRY, "_init: enter\n");

	sca_work_lock = SPIN_LOCK_UNLOCKED;
#endif
	mutex_init(&mca_lock, NULL, MUTEX_DRIVER, NULL);
	mca_table_init(&mca_state, sizeof (mca_t), 1, 1, NULL);
	mca_upcall_init();
	mca_keystore_init();

#ifndef LINUX
	if ((rv = mod_install(&modlinkage)) != 0) {
		/* cleanup here */
		mca_table_destroy(&mca_state);
		mutex_destroy(&mca_lock);
		mca_upcall_fini();
		mca_keystore_fini();
		return (rv);
	}

	return (0);
#else
	/*
	 * For each device in the system:
	 *   1) kmalloc dev_info_t data structures
	 *   2) Find the device in the system's pci structures
	 *   3) Enable the PCI device
	 *   4) Turn on bus mastering if needed
	 *   5) Request an IRQ number
	 *   6) Request PCI BAR resources
	 *   7) Verify memory resources are available
	 *   8) Request memory resources
	 *   9) Remap the register
	 *  10) Enable interrupts on the device
	 */
	num_mca_devices = 0;
	memset(mca_devices, 0, MAX_NUM_SCA_DEVICE * sizeof (dev_info_t *));
	mca_device_tmp = NULL;
	for (i = 0; i < MAX_NUM_SCA_DEVICE; ++i) {
		DBG(NULL, DWARN, "_init: setting up device: %d\n", i);
		/* Allocate memory for each device's data structures */
		mca_devices[i] = (dev_info_t *)kmalloc(sizeof (dev_info_t),
		    GFP_ATOMIC);
		if (mca_devices[i] == NULL) {
			cmn_err(CE_WARN, "mca_module_init: kmalloc failed "
			    "to allocate memory for mca_devices[%d]\n", i);
			goto exit;
		}

		/*
		 * Find the device in the system's PCI structure and enable it
		 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10))
		mca_devices[i]->device = pci_find_device(MCA_VENDOR_ID,
		    MCA_DEVICE_ID, mca_device_tmp);
#else
		mca_devices[i]->device = pci_get_device(MCA_VENDOR_ID,
		    MCA_DEVICE_ID, mca_device_tmp);
#endif

		if ((mca_device_tmp = mca_devices[i]->device) == NULL) {
			kfree(mca_devices[i]);
			mca_devices[i] = NULL;
			break; /* We have found all of the devices */
		} else {
			if (pci_set_dma_mask(mca_devices[i]->device,
			    DMA_32BIT_MASK)) {
				cmn_err(CE_WARN, "mca unable to set "
				    "mask for mca_devices[%d]\n.", i);
				kfree(mca_devices[i]);
				mca_devices[i] = NULL;
				break;
			}
			if (pci_set_consistent_dma_mask(mca_devices[i]->device,
			    DMA_32BIT_MASK)) {
				cmn_err(CE_WARN, "mca unable to set "
				    "coherent mask for mca_devices[%d]\n.", i);
				kfree(mca_devices[i]);
				mca_devices[i] = NULL;
				break;
			}

			pci_enable_device(mca_devices[i]->device);
			++num_mca_devices;
		}
		DBG(NULL, DWARN, "_init: enabled device: %d\n", i);

		/* Init this device instance and name */
		mca_devices[i]->instance = i;
		strcpy(mca_devices[i]->name, MCA_DRIVER_TEXT_NAME);

		DBG(NULL, DWARN, "Found device: %d, Total: %d\n",
		    i, num_mca_devices);

		/*
		 * The mca_attach function should finish the rest:
		 *   4) Turn on bus mastering if needed
		 *   5) Request an IRQ number
		 *   6) Request PCI BAR resources
		 *   7) Verify memory resources are available
		 *   8) Request memory resources
		 *   9) Remap the register
		 *  10) Enable interrupts on the device
		 */
		/* Note that always pass in DDI_ATTACH */
		if ((rv = mca_attach(mca_devices[i], DDI_ATTACH)) !=
		    DDI_SUCCESS) {
			mca_error(0,
			    "mca_attach failed for device: %d, rv: %d\n",
			    i, rv);

			/* Detach any previously attached devices. */
			num_mca_devices--;
			for (i = 0; i < num_mca_devices; i++) {
				/* mca_detach() always passes with DDI_DETACH */
				mca_detach(mca_devices[i], DDI_DETACH);
				kfree(mca_devices[i]);
				mca_error(0, "device %d is detached due to "
				    "failure in attaching another device.\n",
				    i);
			}

			goto exit;
		}
	}

	/*
	 * Should never have more than MAX_NUM_SCA_DEVICE (8) devices
	 * in the system.
	 */
	if (i == MAX_NUM_SCA_DEVICE) {
		cmn_err(CE_WARN, "mca_module_init: there are more than %d "
		    "mca devices found.\n", MAX_NUM_SCA_DEVICE);
	}

	/* Check how many devices are in the system */
	if (num_mca_devices == 0) {
		cmn_err(CE_WARN, "mca_module_init: no sca device found\n");
		goto exit;
	}

	DBG(NULL, DENTRY, "_init: done!\n");
	return (DDI_SUCCESS);

exit:

	/* Clean up */
	fini_cleanup();

	DBG(NULL, DENTRY, "_init: done failed!\n");
	return (DDI_FAILURE);
#endif
}

#ifdef LINUX

void
_fini(void)
{
	char dir[64];
	int i;

	DBG(NULL, DENTRY, "_fini: entry\n");

	for (i = 0; i < num_mca_devices; i++) {
		/* Note that always pass in DDI_DETTACH */
		mca_detach(mca_devices[i], DDI_DETACH);
		kfree(mca_devices[i]);
	}

	fini_cleanup();

	DBG(NULL, DENTRY, "_fini: done!\n");
}

module_init(_init);
module_exit(_fini);
MODULE_LICENSE("GPL");

#else

int
_fini(void)
{
	int rv = DDI_SUCCESS;
	if ((rv = mod_remove(&modlinkage)) == 0) {
		fini_cleanup();
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

#endif

static int
mca_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance;
	ddi_iblock_cookie_t	ibc;
	mca_t			*mca;
	uint16_t		version;
	int			intrdone = 0;
	int			taskq_threads;
	char			taskq_name[32];

	instance = ddi_get_instance(dip);
	DBG(NULL, DENTRY, "mca_attach: enter: instance: %d\n", instance);

	switch (cmd) {
	case DDI_RESUME:
		if ((mca = (mca_t *)ddi_get_driver_private(dip)) == NULL) {
			mca_diperror(dip, "no soft state in detach");
			return (DDI_FAILURE);
		}
		/* assumption: we won't be DDI_DETACHed until we return */
		return (mca_resume(mca));
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	if (ddi_slaveonly(dip) == DDI_SUCCESS) {
		mca_diperror(dip, "Slot does not support PCI bus-master!");
		return (DDI_FAILURE);
	}

	if (ddi_intr_hilevel(dip, 0) != 0) {
		mca_diperror(dip, "Hilevel interrupts not supported!");
		return (DDI_FAILURE);
	}

	/* if not already done, initialize the KTI transport key */
	mutex_enter(&mca_lock);
	if (mca_ktisz == 0) {
		int	ktibits = 0;
		ktibits = ddi_getprop(DDI_DEV_T_ANY, dip,
		    DDI_PROP_CANSLEEP, "ktisz", mca_default_ktibits);
		switch (ktibits) {
		case 128:
		case 192:
		case 256:
			break;
		default:
			ktibits = 128;
			mca_diperror(dip, "Illegal value for ktisz, "
			    "assuming %d bits", ktibits);
			break;
		}
		/* convert to bytes */
		mca_ktisz = ktibits / 8;

		mca_kti = kmem_alloc(mca_ktisz, KM_NOSLEEP);
		if (mca_kti == NULL) {
			mca_diperror(dip,
			    "Unable to allocate memory for mca_kti!");
			return (DDI_FAILURE);
		}

		/* first try "good" RNG, then fallback to pseudo RNG */
		if ((random_get_bytes(mca_kti, mca_ktisz) != 0) &&
		    (random_get_pseudo_bytes(mca_kti, mca_ktisz) != 0)) {
			DBG(NULL, DWARN, "Unable to generate transport key!");
			kmem_free(mca_kti, mca_ktisz);
			mca_ktisz = 0;
			mutex_exit(&mca_lock);
			return (DDI_FAILURE);
		}

		/* initialize KTK key schedule */
		mca_aes_setupkeys(&mca_ktk, mca_kti, ktibits);
	}
	mutex_exit(&mca_lock);

	if ((mca = kmem_zalloc(sizeof (mca_t), KM_SLEEP)) == NULL) {
		mca_diperror(dip, "Unable to allocate soft state!");
		return (DDI_FAILURE);
	}

	ASSERT(mca != NULL);
	mca->mca_dip = dip;
	/* figure pagesize */
	mca->mca_pagesize = ddi_ptob(dip, 1);

	/* Update our ddi_dma_attr structures. */
	mca_dmaattr.dma_attr_align = mca->mca_pagesize;
	no_sg_dma_attr.dma_attr_align = mca->mca_pagesize;

	mca->mca_flags = 0;
	mca->fm_flags = 0;
	mca->mca_ring_cb.mr_mca = NULL;
	mca->mca_ring_ca.mr_mca = NULL;
	mca->mca_ring_om.mr_mca = NULL;
	DBG(mca, DBRINGUP, "soft state = %p", mca);

	/* Mark the driver as being in the attaching state. */
	mca_setattaching(mca);

	/*
	 * initialize locks, etc.
	 */
	if (ddi_get_iblock_cookie(dip, 0, &ibc) != DDI_SUCCESS) {
		mca_error(mca, "Unable to get interrupt cookie!");
		kmem_free(mca, sizeof (mca_t));
		return (DDI_FAILURE);
	}
	mutex_init(&mca->mca_intrlock, NULL, MUTEX_DRIVER, (void *)ibc);
	mutex_init(&mca->mca_reglock, NULL, MUTEX_DRIVER, (void *)ibc);
	mutex_init(&mca->mca_ctllock, NULL, MUTEX_DRIVER, (void *)ibc);
	mutex_init(&mca->mca_job_lock, NULL, MUTEX_DRIVER, (void *)ibc);
	mutex_init(&mca->mca_dbmlock, NULL, MUTEX_DRIVER, (void *)ibc);
	mutex_init(&mca->log.lock, NULL, MUTEX_DRIVER, (void *)ibc);
	mutex_init(&mca->reset.lock, NULL, MUTEX_DRIVER, (void *)ibc);
	cv_init(&mca->mca_ctlcv, NULL, CV_DRIVER, NULL);
	cv_init(&mca->mca_job_cv, NULL, CV_DRIVER, NULL);
	cv_init(&mca->mca_dbmcv, NULL, CV_DRIVER, NULL);
	cv_init(&mca->log.cv, NULL, CV_DRIVER, NULL);
	mca->mca_icookie = ibc;

	/* Initialize the ctx list */
	mutex_init(&mca->mca_ctxlist_lock, NULL, MUTEX_DRIVER, NULL);
	mca_initq(&mca->mca_ctxlist);

	/*
	 * initialize soft interrupts locks, etc.
	 */
	if (ddi_get_soft_iblock_cookie(dip, DDI_SOFTINT_MED, &ibc) !=
	    DDI_SUCCESS) {
		mca_error(mca, "Unable to get soft interrupt cookie!");
		mutex_destroy(&mca->mca_intrlock);
		mutex_destroy(&mca->mca_reglock);
		mutex_destroy(&mca->mca_ctllock);
		mutex_destroy(&mca->mca_job_lock);
		mutex_destroy(&mca->mca_dbmlock);
		mutex_destroy(&mca->log.lock);
		mutex_destroy(&mca->reset.lock);
		mutex_destroy(&mca->mca_ctxlist_lock);
		cv_destroy(&mca->mca_ctlcv);
		cv_destroy(&mca->mca_job_cv);
		cv_destroy(&mca->mca_dbmcv);
		cv_destroy(&mca->log.cv);
		kmem_free(mca, sizeof (mca_t));
		return (DDI_FAILURE);
	}
	mutex_init(&mca->mca_soft_intrlock, "mca soft mutex",
	    MUTEX_DRIVER, (void *)ibc);
	mca->mca_soft_icookie = ibc;

	/* Initialize FMA functionality */
	mca_fm_init(mca);

	/*
	 * What style of RNG do we use?  Use SHA1 postprocessing by default.
	 */
	if (ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "rngdirect", 0) == 0) {
		mca_setrngsha1(mca);
	}

	/* Create task queue with configurable number of service threads */
	taskq_threads = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "taskq_threads",
	    mca_taskq_default_threads);
	(void) sprintf(taskq_name, "%s%d", MCA_TASKQNAME, instance);
	DBG(mca, DBRINGUP, "Creating %s, taskq_threads = %d", taskq_name,
	    taskq_threads);
	if ((mca->mca_taskq = ddi_taskq_create(dip, taskq_name, taskq_threads,
		    TASKQ_DEFAULTPRI, 0)) == NULL) {
		mca_error(mca, "Unable to create %s with %d threads",
		    taskq_name, taskq_threads);
		goto failed;
	}

	/* initialize crypto data structures */
	if (mca_init(mca) != DDI_SUCCESS) {
		mca_error(mca, "Unable to initialize key data structures!");
		goto failed;
	}

	/* Allocate device access and dma resources */
	if (mca_alloc_resources(mca) != DDI_SUCCESS) {
		mca_error(mca, "Unable to allocate dma resources!");
		goto failed;
	}

	/* disable INTx interrupts to guard against spurious ints */
	pci_config_put16(mca->mca_pcihandle, PCI_CONF_COMM,
	    pci_config_get16(mca->mca_pcihandle, PCI_CONF_COMM) |
	    PCI_COMM_INTX_DISABLE);

	/* Mask all MU interrupts */
	PUTCSR32(mca, CSR_OB_INT_MASK, MU_OUT_ALL_INTS);

	/* Clear all pending MU interrupts */
	PUTCSR32(mca, CSR_OB_DOORBELL, MU_DOORBELL_ALL_INTS);

	/* add the interrupt handler */
	if (ddi_add_intr(dip, 0, NULL, NULL, mca_intr, (void *)mca) !=
	    DDI_SUCCESS) {
		mca_error(mca, "Unable to register interrupt handler!");
		goto failed;
	}

	/* add the soft interrupt handler */
	if (ddi_add_softintr(dip, DDI_SOFTINT_MED, &mca->mca_soft_intr,
	    NULL, NULL, mca_soft_intr, (void *)mca) !=
	    DDI_SUCCESS) {
		mca_error(mca, "Unable to register soft interrupt handler!");
		ddi_remove_intr(dip, 0, mca->mca_icookie);
		goto failed;
	}

	intrdone = 1;

	/* initialize PCI access settings */
	PUTPCI16(mca, PCI_CONF_COMM, PCI_COMM_SERR_ENABLE |
	    PCI_COMM_BACK2BACK_ENAB | PCI_COMM_PARITY_DETECT | PCI_COMM_ME |
	    PCI_COMM_MAE | PCI_COMM_INTX_DISABLE);

#ifndef LINUX
	/* Wait for firmware to boot */
	mca_boot_wait(mca);
#endif

	/* Startup the device/firmware */
	if (mca_masterstart(mca) != DDI_SUCCESS) {
		mca_error(mca, "Unable to initialize device!");
		goto failed;
	}

	/* Initialize the driver's reset variables. */
	mca->reset.logic = mca_resethard_continue;

	/* initialize interrupt register */
	mca_enableinterrupts(mca, 0);

	ddi_set_driver_private(dip, (caddr_t)mca);

	version = GETCSR16(mca, CSR_IFVERSION);
	DBG(mca, DBRINGUP, "Interface version: %d.%d",
	    (version & 0xff00) >> 8, version & 0xff);

	version = GETCSR16(mca, CSR_FWVERSION);
	DBG(mca, DBRINGUP, "Firmware version: %d.%d",
	    (version & 0xff00) >> 8, version & 0xff);

	version = GETCSR16(mca, CSR_HWVERSION);
	DBG(mca, DBRINGUP, "Hardware version: %d.%d",
	    (version & 0xff00) >> 8, version & 0xff);

	/* register soft state */
	mutex_enter(&mca_lock);
	if (mca_table_set_slot(&mca_state, instance, mca, KM_SLEEP) !=
	    DDI_SUCCESS) {
		mca_error(mca, "Unable to register soft state!");
		mutex_exit(&mca_lock);
		goto failed;
	} else {
		DBG(mca, DBRINGUP, "Registered soft state");
	}
	mutex_exit(&mca_lock);

	/* let scakiod know the card is up */
	if (mca_upcall_check()) {
		mca_upcall_reset(mca);
	}

	mca_init_job_timeout_info(mca);
	if (!mca_fm_isfailsafe(mca)) {
		if (mca_hw_provider_register(mca, 0) != DDI_SUCCESS) {
			mca_error(mca, "Failed to register mca to framework; "
			    "entering failsafe mode");
			mutex_enter(&mca->fm_lock);
			mca_fm_setfailsafe(mca);
			mutex_exit(&mca->fm_lock);
		} else {
			DBG(mca, DBRINGUP, "Registered with crypto framework");
		}
	}

	/* Start the job timeout routine */
	mutex_enter(&mca->mca_job_lock);
	mca->job.timeout.id =
	    timeout(mca_jobtimeout, (void *)mca, mca->job.timeout.ticks);
	mutex_exit(&mca->mca_job_lock);

	/* Print our banner. */
	ddi_report_dev(dip);

#ifdef FMA_COMPLIANT
	/* Report service degraded if we are in fail-safe mode */
	if (mca_fm_isfailsafe(mca) &&
	    (ddi_get_devstate(mca->mca_dip) != DDI_DEVSTATE_DEGRADED)) {
		ddi_fm_service_impact(mca->mca_dip,
		    DDI_SERVICE_DEGRADED);
	}
#endif /* FMA_COMPLIANT */

	/* initialize kstats */
	mca_ksinit(mca);

	/* We are no longer attaching - we are attached. */
	mca_unsetattaching(mca);
	mca_setattached(mca);

	return (DDI_SUCCESS);

failed:
	/*
	 * shutdown the device to silence interrupts, etc.
	 * this is only needed if registers are available for use
	 */
	if (mca->mca_regshandle) {
		mca_shutdown(mca);
	}

	(void) mca_hw_provider_unregister(mca);

	if (intrdone) {

		if (mca_isinten(mca)) {
			/* disable device interrupts */
			mca_disableinterrupts(mca, 0);
		}

		/* unregister intr handler */
		ddi_remove_intr(dip, 0, mca->mca_icookie);

		/* unregister soft intr handler */
		ddi_remove_softintr(mca->mca_soft_intr);
	}

	if (mca->mca_intrstats) {
		kstat_delete(mca->mca_intrstats);
	}
	if (mca->mca_ksp) {
		kstat_delete(mca->mca_ksp);
	}

#ifdef FMA_COMPLIANT
	/* Only unregister FMA capabilities if we registered some */
	if (mca_fm_is_enabled(mca)) {

		/*
		 * Release any resources allocated by pci_ereport_setup()
		 */
		if (DDI_FM_EREPORT_CAP(mca->fm_capabilities)) {
			pci_ereport_teardown(mca->mca_dip);
		}

		/* Unregister error callback if error callback capable */
		if (DDI_FM_ERRCB_CAP(mca->fm_capabilities)) {
			ddi_fm_handler_unregister(mca->mca_dip);
		}

		/* Unregister from IO Fault Services */
		ddi_fm_fini(mca->mca_dip);
		DBG(mca, DBRINGUP, "fm_capable() = 0x%x",
		    ddi_fm_capable(mca->mca_dip));

		mca_fm_clr_enabled(mca);
	}
#endif /* FMA_COMPLIANT */

	mca_free_resources(mca);
	mutex_destroy(&mca->mca_intrlock);
	mutex_destroy(&mca->mca_reglock);
	mutex_destroy(&mca->mca_ctllock);
	mutex_destroy(&mca->mca_job_lock);
	mutex_destroy(&mca->mca_dbmlock);
	mutex_destroy(&mca->log.lock);
	mutex_destroy(&mca->reset.lock);
	mutex_destroy(&mca->mca_ctxlist_lock);
	mutex_destroy(&mca->mca_soft_intrlock);
	mutex_destroy(&mca->fm_lock);
	cv_destroy(&mca->mca_ctlcv);
	cv_destroy(&mca->mca_job_cv);
	cv_destroy(&mca->mca_dbmcv);
	cv_destroy(&mca->log.cv);

	if (mca->mca_taskq != NULL) {
		ddi_taskq_destroy(mca->mca_taskq);
		mca->mca_taskq = NULL;
	}

	kmem_free(mca, sizeof (mca_t));
	ddi_set_driver_private(dip, NULL);

	return (DDI_FAILURE);
}

static int
mca_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	mca_t		*mca;
	timeout_id_t	job_tid;
	timeout_id_t	resume_tid;

	DBG(NULL, DENTRY, "mca_detach: enter.\n");

	if ((mca = (mca_t *)ddi_get_driver_private(dip)) == NULL) {
		mca_diperror(dip, "no soft state in detach");
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_SUSPEND:
		/* assumption: we won't be DDI_DETACHed until we return */
		return (mca_suspend(mca));

	case DDI_DETACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	/*
	 * Drain firmware jobs on mr_runq and any mcactl jobs. Note that a
	 * side affect of this call is that mca_ctldrain is set. See
	 * mca_undrainctl() call below.
	 */
	if (mca_drain(mca, MCA_NORMAL_DRAIN) != 0) {
		goto fail;
	}

	/* Make sure no one has a hold on us */
	mutex_enter(&mca_lock);
	if (mca->mca_refcnt > 0) {
		DBG(mca, DWARN, "mca_detach: ref count (%d) > 0\n",
		    mca->mca_refcnt);
			mutex_exit(&mca_lock);
		mca_undrain(mca);
		return (DDI_FAILURE);
	}

	/* Don't allow any new holds */
	mca_setdetached(mca);
	mutex_exit(&mca_lock);

	/* untimeout the timeouts */
	mutex_enter(&mca->mca_job_lock);
	job_tid = mca->job.timeout.id;
	mca->job.timeout.id = 0;
	resume_tid = mca->mca_resume_tid;
	mca->mca_resume_tid = 0;
	mutex_exit(&mca->mca_job_lock);
	if (job_tid) {
		untimeout(job_tid);
	}
	if (resume_tid) {
		untimeout(resume_tid);
	}

	/* kill reset timer if running */
	mutex_enter(&mca->reset.lock);

	if (mca->reset.tid) {
		untimeout(mca->reset.tid);
		mca->reset.tid = 0;
	}

	mutex_exit(&mca->reset.lock);


	/*
	 * At this point we now know:
	 *	1) No references are left to our device:
	 *		- mca_refcnt == 0.
	 *		- mca_flags contains MCA_DETACH flag.
	 * 	2) No mcactl jobs are left and no new mcactl jobs can be
	 *	   submitted:
	 *		- mca_ctldrain == 1.
	 *		- mca_flags contains MCA_DETACH flag.
	 *	2) The framework won't submit any new jobs to us:
	 *	3) The firmware does not have any jobs:
	 *		- ring->mr_runq empty
	 *
	 * There may be jobs "in-flight" executing their *_done routines.
	 * The mca_hw_provider_unregister() called below will wait for these
	 * jobs * to complete. Note that these jobs may need to grab
	 * mca_ctldrain or mca_ctlbusy, E.g:
	 *
	 * 	taskq_thread()
	 *	    mca_deletekey_done()
	 *		mca_set_firmware_keystore()
	 *			mca_ctlbusy()
	 *
	 * Drop mca_ctldrain so any jobs executing their *_done routines
	 * that might need mca_ctldrain can complete.
	 */
	mca_undrainctl(mca);

	/*
	 * Unregister from the framework, waiting for any "in-flight" jobs to
	 * complete.
	 */
	if (mca_hw_provider_unregister(mca) != CRYPTO_SUCCESS) {
		goto fail;
	}

	/*
	 * release our hold on all keystores -- may also result in
	 * keystore resources being released.
	 */
	if (mca->mca_keystore_count) {
		mca_keystore_rele_all(mca);
	}

	/* shutdown the device -- also shuts off interrupts */
	mca_shutdown(mca);

	/* unregister interrupt handlers */
	ddi_remove_intr(dip, 0, mca->mca_icookie);
	ddi_remove_softintr(mca->mca_soft_intr);

	/* toss out kstats */
	if (mca->mca_intrstats) {
		kstat_delete(mca->mca_intrstats);
	}
	if (mca->mca_ksp) {
		kstat_delete(mca->mca_ksp);
	}

#ifdef FMA_COMPLIANT
	/* Only unregister FMA capabilities if we registered some */
	if (mca_fm_is_enabled(mca)) {

		/*
		 * Release any resources allocated by pci_ereport_setup()
		 */
		if (DDI_FM_EREPORT_CAP(mca->fm_capabilities)) {
			pci_ereport_teardown(mca->mca_dip);
		}

		/* Unregister error callback if error callback capable */
		if (DDI_FM_ERRCB_CAP(mca->fm_capabilities)) {
			ddi_fm_handler_unregister(mca->mca_dip);
		}

		/* Unregister from IO Fault Services */
		ddi_fm_fini(mca->mca_dip);
		DBG(mca, DBRINGUP, "fm_capable() = 0x%x",
		    ddi_fm_capable(mca->mca_dip));

		mca_fm_clr_enabled(mca);
	}
#endif /* FMA_COMPLIANT */

	if (mca->mca_taskq != NULL) {
		ddi_taskq_destroy(mca->mca_taskq);
		mca->mca_taskq = NULL;
	}

	mca_ctlbusy(mca);
	mca_free_resources(mca);
	mca_ctlunbusy(mca);

	mutex_destroy(&mca->mca_intrlock);
	mutex_destroy(&mca->mca_reglock);
	mutex_destroy(&mca->mca_ctllock);
	mutex_destroy(&mca->mca_job_lock);
	mutex_destroy(&mca->mca_dbmlock);
	mutex_destroy(&mca->log.lock);
	mutex_destroy(&mca->reset.lock);
	mutex_destroy(&mca->mca_ctxlist_lock);
	mutex_destroy(&mca->mca_soft_intrlock);
	mutex_destroy(&mca->fm_lock);
	cv_destroy(&mca->mca_ctlcv);
	cv_destroy(&mca->mca_job_cv);
	cv_destroy(&mca->mca_dbmcv);
	cv_destroy(&mca->log.cv);

	mutex_enter(&mca_lock);
	mca_table_free_slot(&mca_state, ddi_get_instance(dip));
	mutex_exit(&mca_lock);

	DBG(NULL, DENTRY, "mca_detach: done!\n");
	return (DDI_SUCCESS);
fail:
	mca_undrain(mca);

	/* restart job timeouts */
	mutex_enter(&mca->mca_job_lock);
	if (mca->job.timeout.id == 0) {
		mca->job.timeout.id =
		    timeout(mca_jobtimeout, (void *)mca,
			mca->job.timeout.ticks);
	}
	mutex_exit(&mca->mca_job_lock);

	/* we're not going to detach after all */
	mutex_enter(&mca_lock);
	mca_setattached(mca);
	mutex_exit(&mca_lock);

	DBG(NULL, DENTRY, "mca_detach: done failed!\n");
	return (DDI_FAILURE);
}

void
mca_unsuspend(mca_t *mca)
{
	DBG(mca, DENTRY, "mca_unsuspend: enter.");

	/* Clear suspending flag and resume any suspended jobs */
	mutex_enter(&mca->mca_job_lock);
	mca_unsetsuspending(mca);
	cv_broadcast(&mca->mca_job_cv);
	mutex_exit(&mca->mca_job_lock);
}

static int
mca_resume(mca_t *mca)
{
	DBG(mca, DENTRY, "mca_resume: enter.");

	/*
	 * Since mars suspend/resume requires that scakiod be running, all
	 * of the resume processing is done in mca_postresume().  Set a
	 * timeout to insure that mca_postresume() is called if it is not
	 * called correctly by the OS (via scadiag).
	 */
	mutex_enter(&mca->mca_job_lock);
	mca->mca_resume_tid = timeout(mca_postresume_timeout, (void *)mca,
	    drv_usectohz(POSTRESUME_TIME));
	mutex_exit(&mca->mca_job_lock);

	/*
	 * Set state flags to attached early so scadiag can successfully
	 * connect to make the call to mca_post_resume()
	 */
	mutex_enter(&mca_lock);
	mca_setattached(mca);
	mutex_exit(&mca_lock);

	return (DDI_SUCCESS);
}

int
mca_postresume(mca_t *mca, int ctl)
{
	timeout_id_t	tid;

	DBG(mca, DENTRY, "mca_postresume: enter.");

	/* Just log a messsage and return if not currently suspended */
	if (!mca_issuspending(mca)) {
		cmn_err(CE_NOTE, "Attempt to resume a non-suspended driver");
		return (DDI_SUCCESS);
	}

	/* Initialize PCI access settings in config space */
	PUTPCI16(mca, PCI_CONF_COMM, PCI_COMM_SERR_ENABLE |
	    PCI_COMM_BACK2BACK_ENAB | PCI_COMM_PARITY_DETECT | PCI_COMM_ME |
	    PCI_COMM_MAE);

	if (ctl) {
		/* Untimeout postresume timeout since scadiag made the call */
		mutex_enter(&mca->mca_job_lock);
		tid = mca->mca_resume_tid;
		mca->mca_resume_tid = 0;
		mutex_exit(&mca->mca_job_lock);
		if (tid) {
			untimeout(tid);
		}
	}

	/* Don't do anything else if a hardware failure has occured */
	if (mca_fm_isfailed(mca)) {
		cmn_err(CE_NOTE,
		    "driver resumed for card in failed state");
		return (DDI_SUCCESS);
	}


	/*
	 * Restore the interrupt settings
	 *
	 * The pre-suspend code marked the control interface
	 * busy. Prevent mca_enableinterrupts() from doing the
	 * same by passing in the busy flag (1) and  avoid
	 * a deadlock.
	 */
	mca_enableinterrupts(mca, 1);

	/* Resume scheduling jobs on the device */
	mca_undrain(mca);

	/* Set all rings ready (not busy) */
	mca_unbusy(mca);

	/* Re-start the job timeout routine */
	mutex_enter(&mca->mca_job_lock);
	mca->job.timeout.id = timeout(mca_jobtimeout, (void *)mca,
	    mca->job.timeout.ticks);
	mutex_exit(&mca->mca_job_lock);

	return (DDI_SUCCESS);
}

void
mca_postresume_timeout(void *arg)
{
	mca_t *mca = (mca_t *)arg;

	/* If we are still suspending, call mca_postresume() */
	if (mca_issuspending(mca)) {
		DBG(mca, DENTRY, "mca_postresume_task: resume not complete");
		(void) mca_postresume(mca, 0);
	} else {
		DBG(mca, DENTRY, "mca_postresume_task: resume complete");
	}
}

int
mca_presuspend(mca_t *mca, int ctl)
{
	timeout_id_t	tid;

	DBG(mca, DENTRY, "mca_presuspend: enter.");

	/*
	 * Set state to suspending so subsequent calls to mca_suspend() and
	 * mca_postresume_timeout() know the drain has already been done.
	 * Note: Should probably take a global mca lock when modifying
	 * mca->mca_flags, but won't since it isn't done for other flags.
	 */
	mutex_enter(&mca->mca_job_lock);
	mca_setsuspending(mca);

	/* untimeout job timeouts so they don't happen during drain */
	tid = mca->job.timeout.id;
	mca->job.timeout.id = 0;
	mutex_exit(&mca->mca_job_lock);
	if (tid) {
		untimeout(tid);
	}

	/* Set all rings busy */
	mca_busy(mca);

	/* Wait for in flight kcf jobs to arrive */
	delay(drv_usectohz(QUARTER_SECOND));

	/*
	 * Drain firmware jobs on mr_runq and any mcactl jobs but allow dbm
	 * jobs to continue until keystore related jobs finish
	 */
	if (mca_drain(mca, MCA_SUSPEND_DRAIN) != 0) {
		goto errorexit;
	}

	/* Wait for in flight dbm responses to be processed and check again */
	delay(drv_usectohz(QUARTER_SECOND));
	if (mca_drain(mca, MCA_SUSPEND_DRAIN) != 0) {
		goto errorexit;
	}

	/* Prevent jobs of any kind from entering the runq */
	if (mca_drain(mca, MCA_NORMAL_DRAIN) != 0) {
		goto errorexit;
	}

	/* Make sure no one except scadiag -S has a hold on us */
	mutex_enter(&mca_lock);
	if (mca->mca_refcnt > ctl) {
		DBG(mca, DCHATTY, "mca_presuspend: ref count %d > %d\n",
		    mca->mca_refcnt, ctl);
		mutex_exit(&mca_lock);
		/* Wait a little longer for all holds to be released */
		delay(drv_usectohz(QUARTER_SECOND));
		mutex_enter(&mca_lock);
		if (mca->mca_refcnt > ctl) {
			DBG(mca, DWARN,
			    "mca_presuspend: retry ref count %d > %d\n",
			    mca->mca_refcnt, ctl);
			mutex_exit(&mca_lock);
			mca_undrain(mca);
			goto errorexit;
		} else {
			DBG(mca, DCHATTY,
			    "mca_presuspend: retry ref count %d\n",
			    mca->mca_refcnt);
		}
	}
	/* Don't allow any new holds */
	mca_setdetached(mca);
	mutex_exit(&mca_lock);

	/*
	 * Because of mca_drain() above - the control interface
	 * has effectively been taken over/made busy. Prevent
	 * mca_disableinterrupts() from doing the same by
	 * passing in the busy flag (1) and avoid a deadlock.
	 */
	mca_disableinterrupts(mca, 1);

	return (DDI_SUCCESS);

errorexit:
	/* Clear suspending flag and resume any suspended jobs */
	mca_unsuspend(mca);

	/* Set all rings ready */
	mca_unbusy(mca);

	/* Re-start the job timeout routine */
	mutex_enter(&mca->mca_job_lock);
	mca->job.timeout.id = timeout(mca_jobtimeout, (void *)mca,
	    mca->job.timeout.ticks);
	mutex_exit(&mca->mca_job_lock);
	return (DDI_FAILURE);
}

static int
mca_suspend(mca_t *mca)
{
	DBG(mca, DENTRY, "mca_suspend: enter.");

	/*
	 * If not already suspended by an RCM call to mca_presuspend(),
	 * call it now.
	 */
	if (!mca_issuspending(mca)) {
		return (mca_presuspend(mca, 0));
	}
	return (DDI_SUCCESS);
}

/*
 * Instance/soft state management.
 */
mca_t *
mca_hold_instance(int instance)
{
	mca_t *mca;
	mutex_enter(&mca_lock);
	if ((mca_table_lookup(&mca_state, instance, (void **)&mca)) !=
	    DDI_SUCCESS) {
		mutex_exit(&mca_lock);
		return (NULL);
	}
	if (mca_isdetached(mca)) {
		mutex_exit(&mca_lock);
		return (NULL);
	}
	mca->mca_refcnt++;
	mutex_exit(&mca_lock);
	return (mca);
}

int
mca_get_next_instance(int *instance)
{
	mutex_enter(&mca_lock);

	if (mca_table_next_slot(&mca_state, instance) != DDI_SUCCESS) {
		mutex_exit(&mca_lock);
		return (ENOENT);
	}

	mutex_exit(&mca_lock);

	return (0);
}

void
mca_rele_instance(mca_t *mca)
{
	mutex_enter(&mca_lock);
	mca->mca_refcnt--;
	mutex_exit(&mca_lock);
}

/* hold an instance exclusively for the mcactl driver */
int
mca_hold_ctl(int instance, mca_t **mcap)
{
	mca_t	*mca;
	if ((mca = mca_hold_instance(instance)) == NULL) {
		return (ENODEV);
	}
	*mcap = mca;
	return (0);
}

void
mca_rele_ctl(mca_t *mca)
{
	mca_rele_instance(mca);
}


static int
mca_initring(mca_t *mca, mca_ring_t *ringp)
{
	size_t			sz;
	caddr_t			kaddr;
	ddi_dma_cookie_t	c;
	unsigned		nc;
	uint16_t		index;

	/* Make sure the ring is not already initialized */
	if (ringp->mr_mca != NULL) {
		mca_error(mca, "ring already initialized");
		return (DDI_FAILURE);
	}

	mutex_init(&ringp->mr_lock, NULL, MUTEX_DRIVER,
	    (void *)mca->mca_icookie);
	cv_init(&ringp->mr_draincv, NULL, CV_DRIVER, NULL);
	cv_init(&ringp->mr_waitcv, NULL, CV_DRIVER, NULL);

	mca_initq(&ringp->mr_freereqs);
	mca_initq(&ringp->mr_runq);
	sz = ringp->mr_nreqs * sizeof (mca_request_t *);
	ringp->mr_reqs = (mca_request_t **)kmem_zalloc(sz, KM_SLEEP);

	/* setup DMA region for submit and completion rings */
	if (ddi_dma_alloc_handle(mca->mca_dip, &no_sg_dma_attr,
	    DDI_DMA_SLEEP, NULL, &ringp->mr_dmah) != DDI_SUCCESS) {
		mca_error(mca, "unable to allocate DMA handle for ring");
		mca_uninitring(ringp);
		return (DDI_FAILURE);
	}
	sz = (sizeof (mca_submission_t) + sizeof (mca_completion_t)) *
	    RINGSIZE;
	if (ddi_dma_mem_alloc(ringp->mr_dmah,
	    ROUNDUP(sz, mca->mca_pagesize), &mca_devattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL, &kaddr, &sz,
	    &ringp->mr_acch) != DDI_SUCCESS) {
		mca_error(mca, "unable to allocate DMA memory for ring (%d)",
		    ROUNDUP(sz, mca->mca_pagesize));
		mca_uninitring(ringp);
		return (DDI_FAILURE);
	}

	ringp->mr_submissions = (mca_submission_t *)kaddr;
	ringp->mr_completions = (mca_completion_t *)(kaddr +
	    sizeof (mca_submission_t) * RINGSIZE);

	if (ddi_dma_addr_bind_handle(ringp->mr_dmah, NULL, kaddr, sz,
	    DDI_DMA_CONSISTENT | DDI_DMA_RDWR, DDI_DMA_SLEEP, NULL,
	    &c, &nc) != DDI_SUCCESS) {
		mca_error(mca, "unable to map DMA memory for ring");
		mca_uninitring(ringp);
		return (DDI_FAILURE);
	}

	/* save physical address */
	ringp->mr_paddr = c.dmac_address;

	for (index = 0; index < ringp->mr_nreqs; index++) {
		mca_request_t *reqp;

		reqp = mca_newreq(mca);
		if (reqp == NULL) {
			for (index = 0; index < ringp->mr_nreqs; index++) {
				if (ringp->mr_reqs[index] == 0)
					break;
				mca_destroyreq(ringp->mr_reqs[index]);
				ringp->mr_reqs[index] = NULL;
			}
			mca_error(mca, "unable to allocate request");
			mca_uninitring(ringp);
			return (DDI_FAILURE);
		}
		reqp->mr_ringp = ringp;
		reqp->mr_index = index;
		ringp->mr_reqs[index] = reqp;
		mca_freereq(reqp);
	}


	/* reset count back to zero (otherwise its negative due to freereq) */
	ringp->mr_count = 0;
	ringp->mr_mca = mca;
	return (DDI_SUCCESS);
}

static void
mca_uninitring(mca_ring_t *ringp)
{
	int i;

	if (ringp->mr_mca) {

		for (i = 0; i < ringp->mr_nreqs; i++) {
			if (ringp->mr_reqs[i]) {
				mca_destroyreq(ringp->mr_reqs[i]);
				ringp->mr_reqs[i] = NULL;
			}
		}
		if (ringp->mr_submissions) {
			(void) ddi_dma_unbind_handle(ringp->mr_dmah);
			ringp->mr_submissions = NULL;
			ringp->mr_completions = NULL;
		}
		if (ringp->mr_acch) {
			ddi_dma_mem_free(&ringp->mr_acch);
		}
		if (ringp->mr_dmah) {
			ddi_dma_free_handle(&ringp->mr_dmah);
		}
		kmem_free(ringp->mr_reqs,
		    ringp->mr_nreqs * sizeof (mca_request_t *));
		cv_destroy(&ringp->mr_draincv);
		cv_destroy(&ringp->mr_waitcv);
		mutex_destroy(&ringp->mr_lock);

		ringp->mr_mca = NULL;
	}
}

static void
mca_fm_init(mca_t *mca)
{
#ifdef FMA_COMPLIANT
	ddi_iblock_cookie_t	fm_ibc;

	/* Read FMA capabilities from mca.conf file (if present) */
	mca->fm_capabilities = ddi_getprop(DDI_DEV_T_ANY, mca->mca_dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "fm-capable", 0);

	DBG(mca, DBRINGUP, "mca->fm_capabilities = 0x%x",
	    mca->fm_capabilities);

	/* Adjust access and dma attributes for FMA */
	MCA_ADJUST_FLAGERR_ACC(mca, mca_regsattr);
	MCA_ADJUST_FLAGERR_ACC(mca, mca_devattr);
	MCA_ADJUST_FLAGERR_ACC(mca, mca_bufattr);
	MCA_ADJUST_DMA_FLAGERR(mca, mca_dmaattr);
	MCA_ADJUST_DMA_FLAGERR(mca, no_sg_dma_attr);

	/* Only register with IO Fault Services if we have some capability */
	if (mca->fm_capabilities) {

		/*
		 * Register capabilities with IO Fault Services.
		 * mca->fm_capabilities will be updated to indicate
		 * capabilities actually supported (not requested)
		 */
		ddi_fm_init(mca->mca_dip, &mca->fm_capabilities, &fm_ibc);
		DBG(mca, DBRINGUP, "fm_capable() =  0x%x",
		    ddi_fm_capable(mca->mca_dip));

		/* Check registration results */
		if (ddi_fm_capable(mca->mca_dip)) {

			/*
			 * Set flag indicating at least some FMA capabilities
			 * have been enabled.
			 */
			mca_fm_set_enabled(mca);

			/*
			 * Initialize pci ereport capabilities if ereport
			 * capable (should always be)
			 */
			if (DDI_FM_EREPORT_CAP(mca->fm_capabilities)) {
				pci_ereport_setup(mca->mca_dip);
			}

			/*
			 * Initialize fma callback mutex and register error
			 * callback if error callback capable.
			 */
			mutex_init(&mca->fm_lock, NULL, MUTEX_DRIVER,
			    (void *)fm_ibc);
			if (DDI_FM_ERRCB_CAP(mca->fm_capabilities)) {
				ddi_fm_handler_register(mca->mca_dip,
				    mca_fm_error_cb, (void *)mca);
			}
		} else {
			/* Initialize fma mutex with "normal" iblock cookie */
			mutex_init(&mca->fm_lock, NULL, MUTEX_DRIVER,
			    (void *)mca->mca_icookie);
		}
	} else {
		/* Initialize fma mutex with "normal" iblock cookie */
		mutex_init(&mca->fm_lock, NULL, MUTEX_DRIVER,
		    (void *)mca->mca_icookie);
	}

#else
	/* Initialize fma mutex with "normal" iblock cookie */
	mutex_init(&mca->fm_lock, NULL, MUTEX_DRIVER, (void *)mca->mca_icookie);
	mca->fm_capabilities = 0;
#endif /* FMA_COMPLIANT */
}

static int
mca_alloc_dma_buff(mca_t *mca, struct ddi_dma_attr *dma_attr,
    mca_dma_buffinfo_t *buff, size_t *size, char *name)
{
	ddi_dma_cookie_t	c;
	unsigned		nc;
	int			rv;

	/* Allocate dma handle */
	rv = ddi_dma_alloc_handle(mca->mca_dip, dma_attr, DDI_DMA_SLEEP,
	    NULL, &buff->dmah);
	if (rv != DDI_SUCCESS) {
		mca_error(mca, "failed allocating %s dma handle", name);
		goto failed;
	}

	/* Allocate dma buffer.  Allocate in pages for driver hardening */
	rv = ddi_dma_mem_alloc(buff->dmah, ROUNDUP(*size, mca->mca_pagesize),
	    &mca_bufattr, DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
	    &buff->kaddr, size, &buff->acch);

	if (rv != DDI_SUCCESS) {
		mca_error(mca, "unable to alloc %s memory", name);
		ddi_dma_free_handle(&buff->dmah);
		goto failed;
	}

	/* Bind dma handle to buffer */
	rv = ddi_dma_addr_bind_handle(buff->dmah, NULL, buff->kaddr, *size,
	    DDI_DMA_STREAMING | DDI_DMA_RDWR, DDI_DMA_SLEEP, 0, &c, &nc);
	if (rv != DDI_DMA_MAPPED) {
		mca_error(mca, "failed binding %s handle", name);
		ddi_dma_mem_free(&buff->acch);
		ddi_dma_free_handle(&buff->dmah);
		goto failed;
	}

	buff->paddr = c.dmac_address;
	buff->bsize = *size;
	return (DDI_SUCCESS);

failed:
	buff->dmah = NULL;
	buff->acch = NULL;
	buff->kaddr = 0;
	buff->paddr = 0;
	buff->bsize = 0;
	return (DDI_FAILURE);
}

/*
 * This routine should be called while holding mca_ctlbusy() if not called from
 * mca_attach()
 */
static int
mca_alloc_resources(mca_t *mca)
{
	ddi_dma_cookie_t	c;
	unsigned		nc;
	size_t			frisize;
	size_t			size;
	int			rv;

	DBG(mca, DBRINGUP, "mca_alloc_resources() ==>");

	/*
	 * Map in PCI config space.
	 */
	if (pci_config_setup(mca->mca_dip, &mca->mca_pcihandle) !=
	    DDI_SUCCESS) {
		mca_error(mca, "Unable to map PCI config space!");
		goto failed;
	}
	/*
	 * Map in the register window.
	 */
	if (ddi_dev_regsize(mca->mca_dip, 1, &mca->mca_regslen) !=
	    DDI_SUCCESS) {
		mca_error(mca, "Unable to get size of register window!");
		goto failed;
	}

	if (ddi_regs_map_setup(mca->mca_dip, 1, &mca->mca_regs,
	    0, 0, &mca_regsattr, &mca->mca_regshandle) != DDI_SUCCESS) {
		mca_error(mca, "Unable to map register window!");
		goto failed;
	}
	DBG(mca, DBRINGUP, "Mapped mca registers, addr 0x%p, len %ld",
	    mca->mca_regs, mca->mca_regslen);


	/*
	 * Allocate DMA buffers
	 */

	/*
	 * Always allocate one page of memory for diagnostic dma buffer.
	 * This buffer will be re-allocated if necessary to support x86
	 * firmware upgrades.
	 */
	size = mca->mca_pagesize;
	if (mca_alloc_dma_buff(mca, &mca_dmaattr, &mca->mca_diag_buff, &size,
	    "diagnostic") != DDI_SUCCESS) {
		goto failed;
	}

	/* Allocate one page buffer for firmware message log */
	size = mca->mca_pagesize;
	if (mca_alloc_dma_buff(mca, &no_sg_dma_attr, &mca->mca_log_buff, &size,
		"msg log") != DDI_SUCCESS) {
		goto failed;
	}


	/*
	 * Allocate buffer for chaining control command data.
	 * Read dma chain size from mca.conf file (default to page size).
	 */
	size = ddi_getprop(DDI_DEV_T_ANY,
	    mca->mca_dip, DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
	    "dma_chain_size", mca->mca_pagesize);
	if (mca_alloc_dma_buff(mca, &no_sg_dma_attr, &mca->mca_ctl_chain_buff,
		&size, "control chain") != DDI_SUCCESS) {
		goto failed;
	}


	/* Allocate one large buffer for firmware requests. */
	rv = ddi_dma_alloc_handle(mca->mca_dip, &mca_dmaattr, DDI_DMA_SLEEP,
	    NULL, &mca->mca_fri_buff.dmah);
	if (rv != DDI_SUCCESS) {
		mca_error(mca, "failure allocating FRI DMA handle");
		goto failed;
	}

	/* for driver hardening, allocate in whole pages */
	frisize = ROUNDUP(MAXPACKET, mca->mca_pagesize);
	rv = ddi_dma_mem_alloc(mca->mca_fri_buff.dmah, frisize,
	    &mca_bufattr, DDI_DMA_STREAMING,
	    DDI_DMA_SLEEP, NULL, &mca->mca_fri_buff.kaddr, &frisize,
	    &mca->mca_fri_buff.acch);
	if (rv != DDI_SUCCESS) {
		mca_error(mca, "unable to alloc FRI DMA memory");
		goto failed;
	}

	rv = ddi_dma_addr_bind_handle(mca->mca_fri_buff.dmah, NULL,
	    mca->mca_fri_buff.kaddr, frisize, DDI_DMA_STREAMING | DDI_DMA_RDWR,
	    DDI_DMA_SLEEP, 0, &c, &nc);
	if (rv != DDI_DMA_MAPPED) {
		mca_error(mca, "failed binding key DMA handle");
		/* FREE? */
		goto failed;
	}
	mca->mca_fri_buff.bsize = frisize;
	mca->mca_fri_buff.paddr = c.dmac_address;

	/*
	 * Check the number of returned cookies to see if we are bound to
	 * contiguous memory or a scatter gather list.  If it is a scatter
	 * gather list and the firmware is not capable of processing dma
	 * chains, copy the data into the contiguous diagnostics buffer.
	 */
	if (nc > 1) {
		uint32_t chainsz;
		/*
		 * Allocate buffer for chaining FRI data.  Read dma chain
		 * size from mca.conf file (default to page size).
		 */
		size = ddi_getprop(DDI_DEV_T_ANY,
		    mca->mca_dip, DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
		    "dma_chain_size", MAXPACKET);
		if (mca_alloc_dma_buff(mca, &no_sg_dma_attr,
		    &mca->mca_fri_chain_buff,
		    &size, "keystore chain") != DDI_SUCCESS) {
			goto failed;
		}

		/* Create DMA chain */
		rv = mca_create_dma_chain(mca, mca->mca_fri_buff.dmah, frisize,
		    &c, nc, &mca->mca_fri_chain_buff);
		if (rv) {
			(void) ddi_dma_unbind_handle(mca->mca_fri_buff.dmah);
			/* FREE? */
			goto failed;
		}
		chainsz = sizeof (mca_dma_chain_hdr_t) +
		    nc * sizeof (mca_dma_chain_link_t);
		mca->mca_fri_chain_buff.bsize = chainsz;
	}

	/*
	 * Allocate dma handle for control commands, memory will be allocated
	 * and bound on a per command basis (protected with mca_ctllock)
	 */
	rv = ddi_dma_alloc_handle(mca->mca_dip, &mca_dmaattr, DDI_DMA_SLEEP,
	    NULL, &mca->mca_ctldmah);
	if (rv != DDI_SUCCESS) {
		mca_error(mca, "failed allocating control command handle");
		goto failed;
	}
	mca->mca_ctlcmd = FWCTL_NULL;

	/*
	 * Allocate crypto rings
	 */

	/* CB (MCR1, bulk) mechanisms */
	if (mca_initring(mca, &mca->mca_ring_cb) != DDI_SUCCESS) {
		goto failed;
	}

	/* CA (MCR2, assymetric) mechanisms */
	if (mca_initring(mca, &mca->mca_ring_ca) != DDI_SUCCESS) {
		goto failed;
	}

	/* OM (Object Management) mechanisms */
	if (mca_initring(mca, &mca->mca_ring_om) != DDI_SUCCESS) {
		goto failed;
	}

	DBG(mca, DBRINGUP, "mca_alloc_resources() <==");

	return (DDI_SUCCESS);

failed:
	mca_free_resources(mca);
	return (DDI_FAILURE);
}

static void
mca_free_dma_buff(mca_dma_buffinfo_t *buff)
{
	if (buff->paddr) {
		(void) ddi_dma_unbind_handle(buff->dmah);
		buff->paddr = 0;
	}
	if (buff->acch) {
		ddi_dma_mem_free(&buff->acch);
		buff->acch = NULL;
	}
	if (buff->dmah) {
		ddi_dma_free_handle(&buff->dmah);
		buff->dmah = NULL;
	}
}

/*
 * This routine should be called while holding mca_ctlbusy() if not called from
 * mca_attach()
 */
void
mca_free_resources(mca_t *mca)
{
	DBG(mca, DBRINGUP, "mca_free_resources() ==>");

	/* Free crypto rings */
	mca_uninitring(&mca->mca_ring_cb);
	mca_uninitring(&mca->mca_ring_ca);
	mca_uninitring(&mca->mca_ring_om);

	/* Free DMA handles */
	if (mca->mca_ctldmah) {
		ddi_dma_free_handle(&mca->mca_ctldmah);
		mca->mca_ctldmah = NULL;
	}
	/* Free DMA buffer resources */
	mca_free_dma_buff(&mca->mca_fri_chain_buff);
	mca_free_dma_buff(&mca->mca_ctl_chain_buff);
	mca_free_dma_buff(&mca->mca_log_buff);
	mca_free_dma_buff(&mca->mca_fri_buff);
	mca_free_dma_buff(&mca->mca_diag_buff);

	/* Free device access handles */
	if (mca->mca_regshandle) {
		ddi_regs_map_free(&mca->mca_regshandle);
		mca->mca_regshandle = NULL;
	}

	if (mca->mca_pcihandle) {
		pci_config_teardown(&mca->mca_pcihandle);
		mca->mca_pcihandle = NULL;
	}

	DBG(mca, DBRINGUP, "mca_free_resources() <==");
}

/*
 * This routine should be called while holding mca_ctlbusy() if not called from
 * mca_attach()
 */
static int
mca_realloc_resources(mca_t *mca)
{
	/* Free current dma resources */
	mca_free_resources(mca);

	/* Re-allocate dma resources */
	return (mca_alloc_resources(mca));
}

static int
mca_init(mca_t *mca)
{
	int	nreqs = RINGSIZE - 1;

	/*
	 * CB (MCR1, bulk) mechanisms.
	 */
	mca->mca_ring_cb.mr_lowater = ddi_getprop(DDI_DEV_T_ANY,
	    mca->mca_dip, DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
	    "cb_lowater", CBLOWATER);
	mca->mca_ring_cb.mr_hiwater = ddi_getprop(DDI_DEV_T_ANY,
	    mca->mca_dip, DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
	    "cb_hiwater", CBHIWATER);
	if ((mca->mca_ring_cb.mr_hiwater > nreqs) ||
	    (mca->mca_ring_cb.mr_lowater >= mca->mca_ring_cb.mr_hiwater)) {
		mca_error(mca, "illegal parameters for CB ring");
		return (DDI_FAILURE);
	}
	mca->mca_ring_cb.mr_mca = NULL;
	mca->mca_ring_cb.mr_nreqs = nreqs;
	mca->mca_ring_cb.mr_head = CSR_CBHEAD;
	mca->mca_ring_cb.mr_tail = CSR_CBTAIL;
	mca->mca_ring_cb.mr_comphead = CSR_CBCOMPHEAD;
	mca->mca_ring_cb.mr_comptail = CSR_CBCOMPTAIL;
	mca->mca_ring_cb.mr_kick = SIGNAL_CBKICK;
	(void) strncpy(mca->mca_ring_cb.mr_name, "CB",
	    sizeof (mca->mca_ring_cb.mr_name));

	/*
	 * CA (MCR2, assymetric) mechanisms.
	 */
	mca->mca_ring_ca.mr_lowater = ddi_getprop(DDI_DEV_T_ANY,
	    mca->mca_dip, DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
	    "ca_lowater", CALOWATER);
	mca->mca_ring_ca.mr_hiwater = ddi_getprop(DDI_DEV_T_ANY,
	    mca->mca_dip, DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
	    "ca_hiwater", CAHIWATER);
	if ((mca->mca_ring_ca.mr_hiwater > nreqs) ||
	    (mca->mca_ring_ca.mr_lowater >= mca->mca_ring_ca.mr_hiwater)) {
		mca_error(mca, "illegal parameters for CA ring");
		return (DDI_FAILURE);
	}
	mca->mca_ring_ca.mr_mca = NULL;
	mca->mca_ring_ca.mr_nreqs = nreqs;
	mca->mca_ring_ca.mr_head = CSR_CAHEAD;
	mca->mca_ring_ca.mr_tail = CSR_CATAIL;
	mca->mca_ring_ca.mr_comphead = CSR_CACOMPHEAD;
	mca->mca_ring_ca.mr_comptail = CSR_CACOMPTAIL;
	mca->mca_ring_ca.mr_kick = SIGNAL_CAKICK;
	(void) strncpy(mca->mca_ring_ca.mr_name, "CA",
	    sizeof (mca->mca_ring_ca.mr_name));

	/*
	 * OM (Object Management) mechanisms.
	 */
	mca->mca_ring_om.mr_lowater = ddi_getprop(DDI_DEV_T_ANY,
	    mca->mca_dip, DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
	    "om_lowater", OMLOWATER);
	mca->mca_ring_om.mr_hiwater = ddi_getprop(DDI_DEV_T_ANY,
	    mca->mca_dip, DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
	    "om_hiwater", OMHIWATER);
	if ((mca->mca_ring_om.mr_hiwater > nreqs) ||
	    (mca->mca_ring_om.mr_lowater >= mca->mca_ring_om.mr_hiwater)) {
		mca_error(mca, "illegal parameters for OM ring");
		return (DDI_FAILURE);
	}
	mca->mca_ring_om.mr_mca = NULL;
	mca->mca_ring_om.mr_nreqs = nreqs;
	mca->mca_ring_om.mr_head = CSR_OMHEAD;
	mca->mca_ring_om.mr_tail = CSR_OMTAIL;
	mca->mca_ring_om.mr_comphead = CSR_OMCOMPHEAD;
	mca->mca_ring_om.mr_comptail = CSR_OMCOMPTAIL;
	mca->mca_ring_om.mr_kick = SIGNAL_OMKICK;
	(void) strncpy(mca->mca_ring_om.mr_name, "OM",
	    sizeof (mca->mca_ring_om.mr_name));

	return (DDI_SUCCESS);
}

void
mca_initq(mca_listnode_t *q)
{
	q->ml_next = q;
	q->ml_prev = q;
}

void
mca_enqueue(mca_listnode_t *q, mca_listnode_t *node)
{
	/*
	 * Enqueue submits at the "tail" of the list, i.e. just
	 * behind the sentinel.
	 */
	node->ml_next = q;
	node->ml_prev = q->ml_prev;
	node->ml_next->ml_prev = node;
	node->ml_prev->ml_next = node;
}

void
mca_rmqueue(mca_listnode_t *node)
{
	node->ml_next->ml_prev = node->ml_prev;
	node->ml_prev->ml_next = node->ml_next;
	node->ml_next = node;
	node->ml_prev = node;
}

mca_listnode_t *
mca_dequeue(mca_listnode_t *q)
{
	mca_listnode_t *node;
	/*
	 * Dequeue takes from the "head" of the list, i.e. just after
	 * the sentinel.
	 */
	if ((node = q->ml_next) == q) {
		/* queue is empty */
		return (NULL);
	}
	mca_rmqueue(node);
	return (node);
}

mca_listnode_t *
mca_nextqueue(mca_listnode_t *q, mca_listnode_t *node)
{
	if (node == NULL) {
		node = q;
	}
	node = node->ml_next;
	if (node == q) {
		return (NULL);
	}
	return (node);
}

mca_listnode_t *
mca_peekqueue(mca_listnode_t *q)
{
	mca_listnode_t *node;

	if ((node = q->ml_next) == q) {
		return (NULL);
	} else {
		return (node);
	}
}

void
mca_dumpreq(mca_request_t *req)
{
	cmn_err(CE_NOTE, "\trequest[%d] 0x%p\n", req->mr_index, (void *)req);
	cmn_err(CE_NOTE, "\t======================\n");
	cmn_err(CE_NOTE, "\tmr_key_id[0]: 0x%08X\n", req->mr_key_id[0]);
	cmn_err(CE_NOTE, "\tmr_key_id[1]: 0x%08X\n", req->mr_key_id[1]);
	cmn_err(CE_NOTE, "\tmr_cmd: 0x%04X\n", req->mr_cmd);
	cmn_err(CE_NOTE, "\tmr_index: 0x%04X\n", req->mr_index);
	cmn_err(CE_NOTE, "\tmr_key_flags[0]: 0x%X\n", req->mr_key_flags[0]);
	cmn_err(CE_NOTE, "\tmr_key_flags[1]: 0x%X\n", req->mr_key_flags[1]);
	cmn_err(CE_NOTE, "\tmr_in_len: 0x%x\n", req->mr_in_len);
	cmn_err(CE_NOTE, "\tmr_out_len: 0x%x\n", req->mr_out_len);
	cmn_err(CE_NOTE, "\tmr_in_first_len: 0x%x\n", req->mr_in_first_len);
	cmn_err(CE_NOTE, "\tmr_out_first_len: 0x%x\n", req->mr_out_first_len);
	cmn_err(CE_NOTE, "\tmr_in_paddr: 0x%x\n", req->mr_in_paddr);
	cmn_err(CE_NOTE, "\tmr_in_next_paddr: 0x%x\n", req->mr_in_next_paddr);
	cmn_err(CE_NOTE, "\tmr_out_paddr: 0x%x\n", req->mr_out_paddr);
	cmn_err(CE_NOTE, "\tmr_out_next_paddr: 0x%x\n", req->mr_out_next_paddr);
	cmn_err(CE_NOTE, "\tmr_flags: 0x%x\n", req->mr_flags);
}


static mca_request_t *
mca_newreq(mca_t *mca)
{
	mca_request_t		*reqp;
	size_t			size;
	ddi_dma_cookie_t	c;
	unsigned		nc;
	int			rv;
	int			n_chain = 0;

	reqp = kmem_zalloc(sizeof (mca_request_t), KM_SLEEP);
	if (reqp == NULL) {
		mca_error(mca, "unable to alloc request structure");
		return (NULL);
	}

	reqp->mr_mca = mca;

	/* for driver hardening, allocate in whole pages */
	size = ROUNDUP(MAXPACKET, mca->mca_pagesize);
	reqp->mr_ibuf_sz = reqp->mr_obuf_sz = MAXPACKET;

	/*
	 * Setup the DMA region for the key.
	 */
	rv = ddi_dma_alloc_handle(mca->mca_dip, &mca_dmaattr, DDI_DMA_SLEEP,
	    NULL, &reqp->mr_key_dmah);
	if (rv != DDI_SUCCESS) {
		mca_error(mca, "failure allocating request DMA handle");
		mca_destroyreq(reqp);
		return (NULL);
	}

	/* for driver hardening, allocate in whole pages */
	rv = ddi_dma_mem_alloc(reqp->mr_key_dmah, size,
	    &mca_bufattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL, &reqp->mr_key_kaddr, &size,
	    &reqp->mr_key_acch);
	if (rv != DDI_SUCCESS) {
		mca_error(mca, "unable to alloc request key DMA memory");
		mca_destroyreq(reqp);
		return (NULL);
	}

	rv = ddi_dma_addr_bind_handle(reqp->mr_key_dmah, NULL,
	    reqp->mr_key_kaddr, size, DDI_DMA_CONSISTENT | DDI_DMA_WRITE,
	    DDI_DMA_SLEEP, 0, &c, &nc);
	if (rv != DDI_DMA_MAPPED) {
		mca_error(mca, "failed binding request key DMA handle");
		mca_destroyreq(reqp);
		return (NULL);
	}
	reqp->mr_key_paddr = c.dmac_address;
	reqp->mr_key_len = c.dmac_size;

	/*
	 * If the key is chained (nc is greater than 1), construct a
	 * descriptor array for the key.
	 */
	if (nc > 1) {
		int			i;
		ddi_dma_cookie_t	cookie;

		bzero(&cookie, sizeof (cookie));

		/* go to the end of the chain */
		for (i = 1; i < nc; i++) {
			ddi_dma_nextcookie(reqp->mr_key_dmah, &cookie);
		}
		reqp->mr_key_chain_head = reqp->mr_key_kaddr + DESC_OFFSET;
		reqp->mr_key_chain_paddr = cookie.dmac_address +
		    cookie.dmac_size - 4096;

		/* create the descriptor chain */
		mca_create_sd_chains(reqp->mr_key_dmah, DESC_OFFSET,
		    &c, nc, reqp->mr_key_kaddr + DESC_OFFSET);
		reqp->mr_key_chain_len = sizeof (mca_dma_chain_hdr_t) +
		    nc * sizeof (mca_dma_chain_link_t);
		reqp->mr_offset = reqp->mr_key_chain_len;
	} else {
		reqp->mr_key_chain_head = reqp->mr_key_kaddr + DESC_OFFSET;
		reqp->mr_key_chain_paddr = c.dmac_address + DESC_OFFSET;
		reqp->mr_key_chain_len = 0;
		reqp->mr_offset = 0;
	}

	/*
	 * Set up the dma for our scratch/shared buffers.
	 */
	rv = ddi_dma_alloc_handle(mca->mca_dip, &mca_dmaattr,
	    DDI_DMA_SLEEP, NULL, &reqp->mr_ibuf_dmah);
	if (rv != DDI_SUCCESS) {
		mca_error(mca, "failure allocating ibuf DMA handle");
		mca_destroyreq(reqp);
		return (NULL);
	}
	rv = ddi_dma_alloc_handle(mca->mca_dip, &mca_dmaattr,
	    DDI_DMA_SLEEP, NULL, &reqp->mr_obuf_dmah);
	if (rv != DDI_SUCCESS) {
		mca_error(mca, "failure allocating obuf DMA handle");
		mca_destroyreq(reqp);
		return (NULL);
	}

	rv = ddi_dma_mem_alloc(reqp->mr_ibuf_dmah, size,
	    &mca_bufattr, DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
	    &reqp->mr_ibuf_kaddr, &size, &reqp->mr_ibuf_acch);
	if (rv != DDI_SUCCESS) {
		mca_error(mca, "newreq:dma_alloc(input, %d) "
		    "failed [%x]", size, rv);
		mca_destroyreq(reqp);
		return (NULL);
	}

	rv = ddi_dma_mem_alloc(reqp->mr_obuf_dmah, size,
	    &mca_bufattr, DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
	    &reqp->mr_obuf_kaddr, &size, &reqp->mr_obuf_acch);
	if (rv != DDI_SUCCESS) {
		mca_error(mca, "newreq:dma_alloc(output, %d) "
		    "failed [%x]", size, rv);
		mca_destroyreq(reqp);
		return (NULL);
	}

	/* Skip the used portion in the key */
	if ((rv = mca_bindchains_one(reqp, size, reqp->mr_offset,
	    reqp->mr_ibuf_kaddr, reqp->mr_ibuf_dmah,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING,
	    &reqp->mr_ibuf_chain, &n_chain)) != DDI_SUCCESS) {
		(void) mca_destroyreq(reqp);
		return (NULL);
	}
	/* Skip the space used by the input buffer */
	reqp->mr_offset += DESC_SIZE * n_chain;

	if ((rv = mca_bindchains_one(reqp, size, reqp->mr_offset,
	    reqp->mr_obuf_kaddr, reqp->mr_obuf_dmah,
	    DDI_DMA_READ | DDI_DMA_STREAMING,
	    &reqp->mr_obuf_chain, &n_chain)) != DDI_SUCCESS) {
		(void) mca_destroyreq(reqp);
		return (NULL);
	}
	/* Skip the space used by the output buffer */
	reqp->mr_offset += DESC_SIZE * n_chain;

	/*
	 * Now cache up the direct DMA access handles.
	 */
	if (ddi_dma_alloc_handle(mca->mca_dip, &mca_dmaattr, DDI_DMA_SLEEP,
	    NULL, &reqp->mr_in_direct_dmah) != DDI_SUCCESS) {
		mca_error(mca, "unable to alloc input direct DMA handle");
		mca_destroyreq(reqp);
		return (NULL);
	}
	if (ddi_dma_alloc_handle(mca->mca_dip, &mca_dmaattr, DDI_DMA_SLEEP,
	    NULL, &reqp->mr_out_direct_dmah) != DDI_SUCCESS) {
		mca_error(mca, "unable to alloc output direct DMA handle");
		mca_destroyreq(reqp);
		return (NULL);
	}

	return (reqp);
}

static void
mca_destroyreq(mca_request_t *reqp)
{
	/*
	 * Clean up DMA for the context structure.
	 */
	if (reqp->mr_key_paddr) {
		(void) ddi_dma_unbind_handle(reqp->mr_key_dmah);
	}

	if (reqp->mr_key_acch) {
		ddi_dma_mem_free(&reqp->mr_key_acch);
	}

	if (reqp->mr_key_dmah) {
		ddi_dma_free_handle(&reqp->mr_key_dmah);
	}

	/*
	 * Clean up DMA for the scratch buffer.
	 */
	if (reqp->mr_ibuf_paddr) {
		(void) ddi_dma_unbind_handle(reqp->mr_ibuf_dmah);
	}
	if (reqp->mr_obuf_paddr) {
		(void) ddi_dma_unbind_handle(reqp->mr_obuf_dmah);
	}

	if (reqp->mr_ibuf_acch) {
		ddi_dma_mem_free(&reqp->mr_ibuf_acch);
	}
	if (reqp->mr_obuf_acch) {
		ddi_dma_mem_free(&reqp->mr_obuf_acch);
	}

	if (reqp->mr_ibuf_dmah) {
		ddi_dma_free_handle(&reqp->mr_ibuf_dmah);
	}
	if (reqp->mr_obuf_dmah) {
		ddi_dma_free_handle(&reqp->mr_obuf_dmah);
	}

	if (reqp->mr_in_direct_dmah) {
		ddi_dma_free_handle(&reqp->mr_in_direct_dmah);
	}
	if (reqp->mr_out_direct_dmah) {
		ddi_dma_free_handle(&reqp->mr_out_direct_dmah);
	}
	kmem_free(reqp, sizeof (mca_request_t));
	reqp = NULL;
}

mca_request_t *
mca_getreq(mca_ring_t *ringp)
{
	mca_request_t	*reqp;

	mutex_enter(&ringp->mr_lock);

	while (!(reqp =
	    (mca_request_t *)mca_dequeue(&ringp->mr_freereqs))) {
		ringp->mr_waiting++;
		/* wait for something to free up */
		cv_wait(&ringp->mr_waitcv, &ringp->mr_lock);
		ringp->mr_waiting--;

		/*
		 * if we're draining, fail all of these requests
		 */
		if (ringp->mr_drain == MCA_NORMAL_DRAIN) {
			if (ringp->mr_waiting) {
				cv_signal(&ringp->mr_waitcv);
			}
			mutex_exit(&ringp->mr_lock);
			return (NULL);
		}
	}

	if (reqp) {
		ringp->mr_count++;
		reqp->mr_flags = 0;
		reqp->mr_callback = NULL;
		reqp->mr_key_len = 0;
		reqp->mr_key_id[0] = 0;
		reqp->mr_key_id[1] = 0;
		reqp->mr_context = NULL;
		reqp->mr_dbm_handle = 0;
		reqp->mr_byte_stat = -1;
		reqp->mr_job_stat = -1;

		/*
		 * this is a default value, and may be overridden
		 * by specific algorithms or commands.
		 */
		reqp->mr_timeout = drv_usectohz(mca_staletime);
	}
	if ((ringp->mr_count == ringp->mr_hiwater) && (ringp->mr_busy == 0)) {
		/* we are fully loaded now, let crypto framework know */
		ringp->mr_flowctl++;
		ringp->mr_busy = 1;
		MCA_NOTIFY_BUSY(ringp);
	}

	mutex_exit(&ringp->mr_lock);
	return (reqp);
}

void
mca_freereq(mca_request_t *reqp)
{
	mca_ring_t	*ringp = reqp->mr_ringp;

	reqp->mr_cf_req = NULL;
	if (reqp->mr_cmd & CMD_HI_KCF_INPLACE) {
		kmem_free(reqp->mr_out, sizeof (crypto_data_t));
		reqp->mr_out = NULL;
	}

	reqp->mr_cmd = 0;

	/* zero out the authentication cookie */
	reqp->mr_cred[0] = 0;
	reqp->mr_cred[1] = 0;
	reqp->mr_cred[2] = 0;
	reqp->mr_cred[3] = 0;

	MCA_RESTORE_CHAIN(&reqp->mr_ibuf_chain);
	MCA_RESTORE_CHAIN(&reqp->mr_obuf_chain);

	mutex_enter(&ringp->mr_lock);
	mca_enqueue(&ringp->mr_freereqs, (mca_listnode_t *)reqp);

	ringp->mr_count--;

	/* signal waiting threads */
	if (ringp->mr_waiting) {
		cv_signal(&ringp->mr_waitcv);
	}

	if ((ringp->mr_count == ringp->mr_lowater) && (ringp->mr_busy) &&
	    !mca_issuspending(ringp->mr_mca)) {
		ringp->mr_busy = 0;
		MCA_NOTIFY_READY(ringp);
	}

	mutex_exit(&ringp->mr_lock);
}

void
mca_dumpchains(mca_chain_t *chain, uint32_t nextpaddr)
{
	caddr_t		chain_kaddr;

	chain_kaddr = chain->mc_desc_head;
	/*
	 * chain->mc_length is size_t type which is unsigned long.
	 * Use a cast here to avoid a warning on i386 Linux.
	 */
	cmn_err(CE_NOTE, "\tpaddr[0x%x] next_paddr[0x%x] len[%ld]",
	    chain->mc_paddr, nextpaddr, (unsigned long)chain->mc_length);

	while (nextpaddr != 0) {
		cmn_err(CE_NOTE, "\tpaddr[0x%x] next_paddr[0x%x] len[%d]",
		    GETBUF32((uint32_t *)(chain_kaddr + DESC_BUFADDR)),
		    GETBUF32((uint32_t *)(chain_kaddr + DESC_NEXT)),
		    GETBUF16((uint16_t *)(chain_kaddr + DESC_LENGTH)));
		nextpaddr = GETBUF32((uint32_t *)(chain_kaddr + DESC_NEXT));
		chain_kaddr += DESC_SIZE;
	}
}

static void
mca_dump_io_chains(mca_request_t *reqp)
{
	if (reqp->mr_flags & MRF_GATHER) {
		DBG(NULL, DWARN, "INPUT(pre-mapped)[%d]:", reqp->mr_in_len);
		mca_dumpchains(&reqp->mr_ibuf_chain, reqp->mr_in_next_paddr);
	} else {
		DBG(NULL, DWARN, "INPUT(direct DMA)[%d]:", reqp->mr_in_len);
		mca_dumpchains(&reqp->mr_in_direct_dma_chain,
		    reqp->mr_in_next_paddr);
	}
	if (reqp->mr_flags & MRF_SCATTER) {
		DBG(NULL, DWARN, "OUTPUT(pre-mapped)[%d]:", reqp->mr_out_len);
		mca_dumpchains(&reqp->mr_obuf_chain, reqp->mr_out_next_paddr);
	} else {
		DBG(NULL, DWARN, "OUTPUT(direct DMA)[%d]:", reqp->mr_out_len);
		mca_dumpchains(&reqp->mr_out_direct_dma_chain,
		    reqp->mr_out_next_paddr);
	}
}


static void
mca_create_sd_chains(ddi_dma_handle_t handle, size_t bsize,
    ddi_dma_cookie_t *cookie, unsigned nc, caddr_t kaddr)
{
	mca_dma_chain_hdr_t	*hdr;
	mca_dma_chain_link_t	*chain;
	int			i;

	/* Create DMA chain */
	hdr = (mca_dma_chain_hdr_t *)kaddr;
	chain = (mca_dma_chain_link_t *)(kaddr + sizeof (mca_dma_chain_hdr_t));
	PUTBUF32(&(hdr->tsize), bsize);
	PUTBUF32(&(hdr->vsize), bsize);
	PUTBUF32(&(hdr->links), nc);
	for (i = 0; i < nc; i++) {
		PUTBUF32(&(chain[i].address), cookie->dmac_address);
		PUTBUF32(&(chain[i].bsize), cookie->dmac_size);
		bsize -= cookie->dmac_size;

		if ((i < nc - 1) && (bsize != 0)) {
			ddi_dma_nextcookie(handle, cookie);
		} else {
			break;
		}
	}
}


/*
 * Build either input chain or output chain. It is single-item chain for Sparc,
 * and possible mutiple-item chain for x86.
 */
int
mca_bindchains_one(mca_request_t *reqp, size_t cnt, int offset,
    caddr_t kaddr, ddi_dma_handle_t handle, uint_t flags,
    mca_chain_t *head, int *n_chain)
{
	ddi_dma_cookie_t	c;
	uint_t			nc;
	int			rv;
	caddr_t			chain_kaddr_pre;
	caddr_t			chain_kaddr;
	uint32_t		chain_paddr;
	int			i;

	/* Advance past the context structure to the starting address */
	chain_paddr = reqp->mr_key_chain_paddr + offset;
	chain_kaddr = reqp->mr_key_kaddr + DESC_OFFSET + offset;

	/*
	 * Bind the kernel address to the DMA handle. On x86, the actual
	 * buffer is mapped into multiple physical addresses. On Sparc,
	 * the actual buffer is mapped into a single address.
	 */
	rv = ddi_dma_addr_bind_handle(handle,
	    NULL, kaddr, cnt, flags, DDI_DMA_DONTWAIT, NULL, &c, &nc);
	if (rv != DDI_DMA_MAPPED) {
		return (DDI_FAILURE);
	}

	/* We cannot handle more than this. */
	if (nc > DMA_CRYPTO_COOKIE_MAX) {
		ddi_dma_unbind_handle(handle);
		mca_error(0, "Number of DMA cookies > %d",
		    DMA_CRYPTO_COOKIE_MAX);
		return (DDI_FAILURE);
	}

	ddi_dma_sync(handle, 0, cnt, DDI_DMA_SYNC_FORDEV);
	*n_chain = nc;

	/* Setup the data buffer chain for DMA transfer */
	chain_kaddr_pre = NULL;

	/* Remember the head of the chain */
	head->mc_desc_head = chain_kaddr;
	head->mc_paddr = c.dmac_address;
	head->mc_length = min((int)c.dmac_size, MAXPACKET);
	head->mc_next_paddr = 0;

	if (nc == 1) {
		/*
		 * The buffer is not chained. No need to construct the
		 * descriptor array.
		 */
		return (DDI_SUCCESS);
	}

	for (i = 1; i < nc; i++) {
		/* Retrieve the next cookie */
		ddi_dma_nextcookie(handle, &c);

		/* PIO */
		PUTBUF32((uint32_t *)(chain_kaddr + DESC_BUFADDR),
		    c.dmac_address);
		PUTBUF16((uint16_t *)(chain_kaddr + DESC_RSVD), 0);
		PUTBUF16((uint16_t *)(chain_kaddr + DESC_LENGTH), c.dmac_size);

		/* Link to the previous one if one exists */
		if (chain_kaddr_pre) {
			PUTBUF32((uint32_t *)(chain_kaddr_pre + DESC_NEXT),
			    chain_paddr);
		} else {
			head->mc_next_paddr = chain_paddr;
		}
		chain_kaddr_pre = chain_kaddr;

		/* Maintain pointers */
		chain_paddr += DESC_SIZE;
		chain_kaddr += DESC_SIZE;
	}

	/* Set the next pointer in the last entry to NULL */
	PUTBUF32((uint32_t *)(chain_kaddr_pre + DESC_NEXT), 0);

	/* Ensure that the saved index contains a well-known value. */
	head->mc_saved_dscr_index = -1;

	return (DDI_SUCCESS);
}


#if defined(i386) || defined(__i386) || defined(__amd64)


/*
 * Walk though the descriptor array to find the numbers of buffers needed
 * to store the data. Remember the last descriptor (save next_paddr and
 * and length in mca_chain_t), and set next_paddr to NULL and set length
 * to the residual length.
 */
void
mca_terminate_chains(mca_chain_t *chain, int len)
{
	caddr_t		desc_head;
	int		desc_len;
	int		index = 0;

	desc_head = chain->mc_desc_head;
	desc_len = chain->mc_length;
	chain->mc_saved_dscr_index = -1;

	while (len >= 0) {
		/*
		 * If the residlen is less than the length of the descr,
		 * terminate the chain
		 */
		if (len <= desc_len) {
			if (index == 0) {
				/* No need to save the state */
				return;
			}

			/*
			 * First save this descriptor
			 * Note: the first desc in the desc array is the
			 * second buffer in the buffer chain.
			 */
			chain->mc_saved_dscr_index = index - 1;
			chain->mc_saved_next_paddr =
			    GETBUF32((uint32_t *)(desc_head + DESC_NEXT));
			chain->mc_saved_length = desc_len;

			/* terminate the chain */
			PUTBUF32((uint32_t *)(desc_head + DESC_NEXT), 0);
			PUTBUF16((uint16_t *)(desc_head + DESC_LENGTH), len);
			return;
		}

		len -= desc_len;

		/* get the next descr len */
		desc_head = chain->mc_desc_head + index * DESC_SIZE;
		desc_len = GETBUF16((uint16_t *)(desc_head + DESC_LENGTH));
		index++;
	}
}

/*
 * Restore next_paddr and length that are saved in mca_terminate_chains.
 */
void
mca_restore_chain(mca_chain_t *chain)
{
	caddr_t		desc_head;

	/* nothing to restore */
	if (chain->mc_saved_dscr_index == -1) {
		return;
	}

	desc_head = chain->mc_desc_head +
	    DESC_SIZE * chain->mc_saved_dscr_index;

	chain->mc_saved_dscr_index = -1;
	PUTBUF32((uint32_t *)(desc_head + DESC_NEXT),
	    chain->mc_saved_next_paddr);
	PUTBUF16((uint16_t *)(desc_head + DESC_LENGTH), chain->mc_saved_length);
}


#endif /* #if defined(i386) || defined(__i386) || defined(__amd64) */


void
mca_unbindchains(mca_request_t *reqp)
{
	if (reqp->mr_flags & MRF_IN_DIRECT) {
		(void) ddi_dma_unbind_handle(reqp->mr_in_direct_dmah);
	}
	if (reqp->mr_flags & MRF_OUT_DIRECT) {
		(void) ddi_dma_unbind_handle(reqp->mr_out_direct_dmah);
	}
}

/*
 * Schedule some work.
 */
int
mca_start(mca_request_t *reqp)
{
	mca_t		*mca = reqp->mr_mca;
	mca_ring_t	*ringp = reqp->mr_ringp;
	mca_dma_chain_hdr_t *keychainhdr;
	mca_dma_chain_link_t *keychainlink;
	uint16_t	head, tail, ntail;
	int		i;

	/*
	 * Suspend jobs if suspending, draining, and this is not a
	 * dbm message received during a suspend drain.
	 */
	if (mca_issuspending(mca) && ringp->mr_drain &&
	    ((ringp->mr_drain == MCA_SUSPEND_DRAIN) &&
		(reqp->mr_cmd != CPG_CMD_DBM))) {
		DBG(ringp->mr_mca, DCHATTY, "mca_start suspending cmd 0x%x, "
		    "index %d,", reqp->mr_cmd, reqp->mr_index);
		/* Spin until we are no longer suspending */
		mutex_enter(&mca->mca_job_lock);
		while (mca_issuspending(mca)) {
			cv_wait(&mca->mca_job_cv, &mca->mca_job_lock);
		}
		mutex_exit(&mca->mca_job_lock);
		DBG(ringp->mr_mca, DCHATTY, "mca_start resuming cmd 0x%x, "
		    "index %d,", reqp->mr_cmd, reqp->mr_index);
	}

	mutex_enter(&ringp->mr_lock);

	/*
	 * If the card is draining, offline (failed or booting),
	 * or failsafe, don't add anything to the run queue. If the device is
	 * in drain state while running seccmd, DBM job can be submitted.
	 */
	if ((ringp->mr_drain == MCA_NORMAL_DRAIN) || mca_fm_isoffline(mca) ||
	    (mca_fm_isfailsafe(mca) && (reqp->mr_cmd != CPG_CMD_DBM)) ||
	    (((ringp->mr_drain == MCA_DBM_DRAIN) ||
		(ringp->mr_drain == MCA_SUSPEND_DRAIN)) &&
		(reqp->mr_cmd != CPG_CMD_DBM))) {
		mutex_exit(&ringp->mr_lock);
		return (CRYPTO_BUSY);
	}

	DBG(ringp->mr_mca, DCHATTY, "mca_start cmd 0x%x, index %d",
	    reqp->mr_cmd, reqp->mr_index);
	DBG(ringp->mr_mca, DCHATTY,
	    "req=%p, in=%p, out=%p, key=%p, ibuf=%p, obuf=%p",
	    reqp, reqp->mr_in, reqp->mr_out, reqp->mr_key_kaddr,
	    reqp->mr_ibuf_kaddr, reqp->mr_obuf_kaddr);
	DBG(ringp->mr_mca, DCHATTY,
	    "key paddr = %x, ibuf paddr = %x, obuf paddr = %x",
	    reqp->mr_key_paddr, reqp->mr_ibuf_paddr, reqp->mr_obuf_paddr);
	/* sync out the entire key storage */
	ddi_dma_sync(reqp->mr_key_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);
	reqp->mr_ringp = ringp;

	head = RINGSIZE;	/* Insure valid read */
	tail = RINGSIZE;	/* Insure valid read */
	head = GETCSR16(mca, ringp->mr_head);
	tail = GETCSR16(mca, ringp->mr_tail);
	if ((head >= RINGSIZE) || (tail >= RINGSIZE)) {
		mutex_exit(&ringp->mr_lock);
		mca_failure(mca, MCA_FMA_BAD_DATA_ID,
		    "illegal crypto ring indices "
		    "(tail %u, head %u)", head, tail);
		return (CRYPTO_DEVICE_ERROR);
	}
	ntail = tail + 1;
	ntail %= RINGSIZE;

	if (ntail == head) {
		/* ring is full */
		DBG(ringp->mr_mca, DWARN, "ring is full");
		mutex_exit(&ringp->mr_lock);
		return (CRYPTO_BUSY);
	}

	/*
	 * Update the ring element.
	 */
	PUTSUBMIT16(ringp, tail, ms_cmd, (reqp->mr_cmd & CMD_MASK));
	PUTSUBMIT16(ringp, tail, ms_id, reqp->mr_index);
	PUTSUBMIT16(ringp, tail, ms_key_flags[0],
	    reqp->mr_key_flags[0]);
	PUTSUBMIT16(ringp, tail, ms_key_flags[1],
	    reqp->mr_key_flags[1]);
	/* update authentication data */
	PUTSUBMIT32(ringp, tail, ms_auth[0], reqp->mr_cred[0]);
	PUTSUBMIT32(ringp, tail, ms_auth[1], reqp->mr_cred[1]);
	PUTSUBMIT32(ringp, tail, ms_auth[2], reqp->mr_cred[2]);
	PUTSUBMIT32(ringp, tail, ms_auth[3], reqp->mr_cred[3]);

	/* update key data */
	PUTSUBMIT32(ringp, tail, ms_key_id[0], reqp->mr_key_id[0]);
	PUTSUBMIT32(ringp, tail, ms_key_id[1], reqp->mr_key_id[1]);

	keychainhdr =
	    (mca_dma_chain_hdr_t *)(reqp->mr_key_kaddr + DESC_OFFSET);
	keychainlink = (mca_dma_chain_link_t *)(keychainhdr + 1);
	if ((reqp->mr_key_chain_len > 0) &&
	    (reqp->mr_key_len > GETBUF32(&keychainlink->bsize))) {
		PUTSUBMIT32(ringp, tail, ms_key_addr, reqp->mr_key_chain_paddr);
		PUTSUBMIT32(ringp, tail, ms_key_length,
		    MCA_SET_DMA_CHAIN_FLAG(reqp->mr_key_chain_len));
	} else {
		PUTSUBMIT32(ringp, tail, ms_key_length, reqp->mr_key_len);
		PUTSUBMIT32(ringp, tail, ms_key_addr, reqp->mr_key_paddr);
	}
	for (i = 0; i < 16; i++) {
		PUTSUBMIT32(ringp, tail, ms_short_key[i],
		    reqp->mr_short_key[i]);
	}

	ASSERT(reqp->mr_in_len <= MAXPACKET);
	ASSERT(reqp->mr_out_len <= MAXPACKET);
	PUTSUBMIT32(ringp, tail, ms_in_addr, reqp->mr_in_paddr);
	PUTSUBMIT32(ringp, tail, ms_in_next, reqp->mr_in_next_paddr);
	PUTSUBMIT16(ringp, tail, ms_in_length, reqp->mr_in_len);
	PUTSUBMIT16(ringp, tail, ms_in_1stlen, reqp->mr_in_first_len);
	PUTSUBMIT32(ringp, tail, ms_out_addr, reqp->mr_out_paddr);
	PUTSUBMIT32(ringp, tail, ms_out_next, reqp->mr_out_next_paddr);
	PUTSUBMIT16(ringp, tail, ms_out_length, reqp->mr_out_len);
	PUTSUBMIT16(ringp, tail, ms_out_1stlen, reqp->mr_out_first_len);
	PUTSUBMIT32(ringp, tail, ms_ldom, reqp->mr_dbm_handle);

	/*
	 * Note submission.
	 */
	if (reqp->mr_cmd != CPG_CMD_DBM) {
		ringp->mr_submit++;
	}

	/* increment the current job count */
	atomic_inc_32(&ringp->mr_ncurrjobs);
	if (ringp->mr_ncurrjobs > ringp->mr_nmaxjobs) {
		ringp->mr_nmaxjobs = ringp->mr_ncurrjobs;
	}

	mutex_enter(&mca->reset.lock);
	mca->job.submitted++;
	/* Add the job's timeout to the cumulative timeout. */
	mca->job.stalled.limit += reqp->mr_timeout;
	mutex_exit(&mca->reset.lock);

	/* if first job into queue, note starting time */
	if (QEMPTY(&ringp->mr_runq)) {
		/* Initialize ring timeout info */
		ASSERT(ringp->mr_timeout == 0);
		ringp->mr_timeout = reqp->mr_timeout;
		ringp->mr_lbolt = ddi_get_lbolt();
	} else {
		/* otherwise add job timeout to cumulative timeout */
		ringp->mr_timeout += reqp->mr_timeout;
	}

	/* note the submission in the job */
	reqp->mr_flags |= MRF_ONDEVICE;
	reqp->mr_runqed = ddi_get_lbolt();

	/* Make sure MCR is synced out to device. */
	ddi_dma_sync(ringp->mr_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);
	mca_enqueue(&ringp->mr_runq, (mca_listnode_t *)reqp);

	/* update firmware's view of the ring */
	PUTCSR16(mca, ringp->mr_tail, ntail);
	/* Kick the firmware... */
	PUTCSR16(mca, CSR_SIGNAL, ringp->mr_kick);

	mutex_exit(&ringp->mr_lock);

	return (CRYPTO_QUEUED);
}

/*
 * Reclaim completed work, called in interrupt context.
 */
void
mca_reclaim(mca_ring_t *ringp)
{
	mca_t		*mca = ringp->mr_mca;
	int		nreclaimed = 0;

	DBG(mca, DRECLAIM, "ring = 0x%p", ringp);
	ASSERT(mutex_owned(&ringp->mr_lock));

	/*
	 * This is just going through the completion ring.
	 */
	for (;;) {
		uint16_t	head, tail, id, err;
		uint16_t	keyflags[2];
		uint32_t	outlen;
		mca_request_t	*reqp;

		head = RINGSIZE;	/* Insure valid read */
		tail = RINGSIZE;	/* Insure valid read */

		head = GETCSR16(mca, ringp->mr_comphead);
		tail = GETCSR16(mca, ringp->mr_comptail);

		if ((head >= RINGSIZE) || (tail >= RINGSIZE)) {
			mutex_exit(&ringp->mr_lock);
			mca_failure(mca, MCA_FMA_BAD_DATA_ID,
			    "illegal completion ring indices "
			    "(tail %u, head %u)", head, tail);
			mutex_enter(&ringp->mr_lock);
			return;
		}

		if (head == tail) {
			/* ring is empty */
			break;
		}

		/*
		 * Since ddi_dma_sync on a consistent handle is mostly
		 * a no-op, we think we're better off skipping the
		 * pointer arithmetic and just sync the whole handle.
		 * The call is quite a bit cleaner, too.
		 */
		ddi_dma_sync(ringp->mr_dmah, 0, 0, DDI_DMA_SYNC_FORKERNEL);

		id = GETCOMPLETION16(ringp, head, mc_id);
		err = GETCOMPLETION16(ringp, head, mc_error);
		keyflags[0] = GETCOMPLETION16(ringp, head, mc_key_flags[0]);
		keyflags[1] = GETCOMPLETION16(ringp, head, mc_key_flags[1]);
		outlen = GETCOMPLETION32(ringp, head, mc_out_length);

		/*
		 * Make completion entry available for hardware.
		 */
		head++;
		head %= RINGSIZE;

		PUTCSR16(mca, ringp->mr_comphead, head);

		if (id > ringp->mr_nreqs) {
			mutex_exit(&ringp->mr_lock);
			mca_failure(mca, MCA_FMA_BAD_DATA_ID,
			    "illegal completion id (%u) returned, nreqs %u",
			    id, ringp->mr_nreqs);
			mutex_enter(&ringp->mr_lock);
			return;
		}
		reqp = ringp->mr_reqs[id];

		if (!(reqp->mr_flags & MRF_ONDEVICE)) {
			mutex_exit(&ringp->mr_lock);
			mca_failure(mca, MCA_FMA_BAD_DATA_ID,
			    "unexpected completion id (%u) head %d",
			    id, (head - 1) % RINGSIZE);
			mutex_enter(&ringp->mr_lock);
			return;
		}
		reqp->mr_rundqed = ddi_get_lbolt(); /* To calculate duration */

		mutex_enter(&mca->reset.lock);
		mca->job.reclaimed++; /* To mark device activity. */
		mca->job.stalled.limit -= reqp->mr_timeout;
		mutex_exit(&mca->reset.lock);

		/* its really for us, so remove it from the queue */
		mca_rmqueue((mca_listnode_t *)reqp);
		reqp->mr_flags &= ~MRF_ONDEVICE;

		/*
		 * reset timeout state, deducting our time from the
		 * expected timeout
		 */
		ringp->mr_lbolt = ddi_get_lbolt();
		ringp->mr_timeout -= reqp->mr_timeout;

		/* if we were draining, signal on the cv */
		if (ringp->mr_drain && QEMPTY(&ringp->mr_runq)) {
			cv_signal(&ringp->mr_draincv);
		}

		/* update statistics, done under the lock */
		if (reqp->mr_byte_stat >= 0) {
			mca->mca_stats[reqp->mr_byte_stat] +=
			    reqp->mr_byte_count;
		}
		if (reqp->mr_job_stat >= 0) {
			mca->mca_stats[reqp->mr_job_stat]++;
		}

		mutex_exit(&ringp->mr_lock);

		switch (err) {
		case MERR_OK:
			reqp->mr_errno = CRYPTO_SUCCESS;
			break;
		case MERR_NO_KEYSTORE:
			DBG(mca, DWARN, "no keystore");
			reqp->mr_errno = CRYPTO_FAILED;
			break;
		case MERR_BAD_LOGIN:
			DBG(mca, DWARN, "bad login");
			reqp->mr_errno = CRYPTO_PIN_INCORRECT;
			break;
		case MERR_HARDWARE:
			DBG(mca, DWARN, "hardware error");
			reqp->mr_errno = CRYPTO_DEVICE_ERROR;
			break;
		case MERR_BAD_COOKIE:
			DBG(mca, DWARN, "bad cookie");
			reqp->mr_errno = CRYPTO_USER_NOT_LOGGED_IN;
			break;
		case MERR_NO_MEMORY:
			DBG(mca, DWARN, "device out of memory");
			reqp->mr_errno = CRYPTO_DEVICE_MEMORY;
			break;
		case MERR_BAD_KEY:
			DBG(mca, DWARN, "bad key");
			reqp->mr_errno = CRYPTO_KEY_HANDLE_INVALID;
			break;
		case MERR_BAD_PARAM:
			DBG(mca, DWARN, "bad parameter");
			reqp->mr_errno = CRYPTO_GENERAL_ERROR;
			break;
		case MERR_BUF_TOO_SMALL:
			DBG(mca, DCHATTY, "buffer too small");
			reqp->mr_errno = CRYPTO_BUFFER_TOO_SMALL;
			break;
		case MERR_BAD_SIGNATURE:
			DBG(mca, DCHATTY, "signature invalid");
			reqp->mr_errno = CRYPTO_SIGNATURE_INVALID;
			break;
		case MERR_NOT_SUPPORTED:
			DBG(mca, DCHATTY, "operation not supported");
			reqp->mr_errno = CRYPTO_MECHANISM_INVALID;
			break;
		case MERR_BAD_PADDING:
			DBG(mca, DCHATTY, "bad padding");
			reqp->mr_errno = CRYPTO_SIGNATURE_INVALID;
			break;
		default:
			DBG(mca, DWARN, "bad device error %d", err);
			reqp->mr_errno = CRYPTO_DEVICE_ERROR;
			break;
		}

		reqp->mr_resultlen = outlen;
		reqp->mr_key_flags[0] = keyflags[0];
		reqp->mr_key_flags[1] = keyflags[1];

		/* Do the callback. */
		mca_done(reqp);
		nreclaimed++;

		mutex_enter(&ringp->mr_lock);
	}
	DBG(mca, DRECLAIM, "reclaimed %d cmds", nreclaimed);
}

/*
 * This is the callback function called from the interrupt when a crypto job
 * completes.  It does some driver-specific things, and then calls the
 * provided callback.  Finally, it cleans up the state for the work
 * request and drops the reference count to allow for DR.
 */
void
mca_done(mca_request_t *reqp)
{
	/* decrement the current job count */
	atomic_dec_32(&reqp->mr_ringp->mr_ncurrjobs);

	/* unbind any chains we were using */
	mca_unbindchains(reqp);

	if (reqp->mr_callback) {
		/*
		 * If the job needs to be completed on a separate thread,
		 * (usually to get out of interrupt context), then do it on
		 * the taskq.
		 */
		/* Always use a separate thread on Linux to avoid a panic */
#ifndef LINUX
		if (reqp->mr_flags & MRF_TASKQ) {
#endif
			if (ddi_taskq_dispatch(reqp->mr_mca->mca_taskq,
			    (void (*)(void *))reqp->mr_callback,
			    (void *)reqp, DDI_NOSLEEP) != DDI_SUCCESS) {
				mca_error(reqp->mr_mca,
				    "unable to tq dispatch");
				reqp->mr_errno = CRYPTO_HOST_MEMORY;
				/* execute error path on stack now */
				reqp->mr_callback(reqp);
			}
#ifndef LINUX
		} else {
			reqp->mr_callback(reqp);
		}
#endif
	} else {
		if (reqp->mr_cf_req) {
			crypto_op_notification(reqp->mr_cf_req, reqp->mr_errno);
		}
		mca_freereq(reqp);
	}
}

/*
 * Find all the requests submitted on the ring and cancel
 * them.  They are treated as failed jobs, since we cannot
 * know what the status of each job really is.
 */
static void
mca_failring(mca_ring_t *ringp, uint16_t errno)
{
	for (;;) {
		mca_request_t	*reqp;

		mutex_enter(&ringp->mr_lock);
		reqp = (mca_request_t *)mca_dequeue(&ringp->mr_runq);
		if (reqp == NULL) {
			ringp->mr_timeout = 0;
			mutex_exit(&ringp->mr_lock);
			break;
		}
		reqp->mr_flags &= ~MRF_ONDEVICE;
		mutex_exit(&ringp->mr_lock);

		reqp->mr_errno = errno;
		mca_done(reqp);

		/*
		 * If waiting to drain, signal on the waiter.
		 */
		mutex_enter(&ringp->mr_lock);
		if (ringp->mr_drain && QEMPTY(&ringp->mr_runq)) {
			cv_signal(&ringp->mr_draincv);
		}
		mutex_exit(&ringp->mr_lock);
	}
}

/*
 * This performs a "safe" reset, in that it ensures no accesses to the
 * device are in progress when it performs the actual reset.  The device
 * is "drained" prior to the reset, and all services are restored once
 * the reset is complete.  If the drain can't complete, EBUSY is returned.
 */
int
mca_safereset(mca_t *mca)
{
	int		rv;
	uint32_t	failsafe = mca_fm_isfailsafe(mca);
	int		failed = mca_fm_isfailed(mca);

	/*
	 * specify MCA_DBM_DRAIN to allow DBM messages to be sent
	 * we need this to allow post reset DB_HELLO's to make
	 * it to the card.
	 */

	if ((rv = mca_drain(mca, MCA_DBM_DRAIN)) != 0) {
		return (rv);
	}

	/*
	 * Turn off "ctldrain", since we don't want to block ourself.
	 * (ctlbusy is called by masterstart below.)  Since we are
	 * only called from the control node, presumably we are
	 * already exclusive.
	 */
	mca_undrainctl(mca);

	mca_disableinterrupts(mca, 0);

	mca_hardreset(mca, MCA_RESET_FAST);

	if (mca_masterstart(mca) != DDI_SUCCESS) {
		/* Ereport already posted in mca_masterstart */
		mca_failure(mca, MCA_FMA_NO_CLASS_ID,
		    "unable to restore service after reset");
		return (EIO);
	}
	mutex_enter(&mca->fm_lock);
	mca_fm_setonline(mca);
	mutex_exit(&mca->fm_lock);
	mca_enableinterrupts(mca, 0);

	/* if no longer in FAILSAFE mode, register with crypto framework */
	if (failsafe && !mca_fm_isfailsafe(mca)) {
		if (mca_hw_provider_register(mca, 0) != DDI_SUCCESS) {
			mca_failure(mca, MCA_FMA_NO_CLASS_ID,
			    "Failed to add device to cryptographic framework");
			return (EIO);
		}
	} else if (!failsafe && mca_fm_isfailsafe(mca)) {
		/*
		 * if card now in FAILSAFE mode - unregister
		 * from cryptographic framework.
		 */
		if (mca_hw_provider_unregister(mca) != CRYPTO_SUCCESS) {
			mca_failure(mca, MCA_FMA_NO_CLASS_ID,
			    "Failed to unregister device from cryptographic "
			    "framework");
			return (EIO);
		}
	}

	/*
	 * don't bother undraining if in FAILSAFE mode since
	 * we're not even registered with crypto framework.
	 */
	if (!(mca_fm_isfailsafe(mca))) {
		mca_undrain(mca);
	}

	/*
	 * Report the restored service to crypto framework.
	 */
	if (failed) {
		MCA_NOTIFY_READY(&mca->mca_ring_ca);
		MCA_NOTIFY_READY(&mca->mca_ring_cb);
		MCA_NOTIFY_READY(&mca->mca_ring_om);
	}

#ifdef FMA_COMPLIANT
	/* Report service degraded if we are in fail-safe mode */
	if (mca_fm_isfailsafe(mca) &&
	    (ddi_get_devstate(mca->mca_dip) != DDI_DEVSTATE_DEGRADED)) {
		ddi_fm_service_impact(mca->mca_dip,
		    DDI_SERVICE_DEGRADED);
	}
#endif /* FMA_COMPLIANT */
	return (0);
}

/*
 * Check for stalled jobs.
 */
mca_request_t	mca_stalled_request;

void
mca_get_ring_timeout(mca_ring_t *ringp, clock_t *lbolt, clock_t *timeout)
{
	mutex_enter(&ringp->mr_lock);

	if (QEMPTY(&ringp->mr_runq)) {
		/* nothing sitting in the queue */
		ASSERT(ringp->mr_timeout == 0);
		*lbolt = 0;
		*timeout = 0;
	} else {
		*lbolt = ringp->mr_lbolt;
		*timeout = ringp->mr_timeout;
	}

	mutex_exit(&ringp->mr_lock);
}


#ifdef OLD_STALLCHECK
int
mca_stallcheck(mca_ring_t *ringp)
{
	clock_t		when;
	clock_t		jobs_time;
	clock_t		jobs_timeout;
	mca_request_t	*reqp;

	mutex_enter(&ringp->mr_lock);
	when = ddi_get_lbolt();

	if (QEMPTY(&ringp->mr_runq)) {
		/* nothing sitting in the queue */
		ASSERT(ringp->mr_timeout == 0);
		mutex_exit(&ringp->mr_lock);
		return (DDI_SUCCESS);
	}

	/* we do the timeouts per ring */
	if ((when - ringp->mr_lbolt) < ringp->mr_timeout) {
		/* request has been queued for less than STALETIME */
		mutex_exit(&ringp->mr_lock);
		return (DDI_SUCCESS);
	}

	/* Save ring state for logging below after dropping ring lock */
	jobs_time = when - ringp->mr_lbolt;
	jobs_timeout = ringp->mr_timeout;
	reqp = (mca_request_t *)mca_peekqueue(&ringp->mr_runq);
	mca_stalled_request = *reqp;

	mutex_exit(&ringp->mr_lock);

	if (!mca_disable_crypto_timeout_msgs) {
		cmn_err(CE_WARN, "stale job(s), ticks %ld allowed %ld "
		    "found in ring %p", jobs_time, jobs_timeout, (void *)ringp);
		mca_dumpreq(&mca_stalled_request);
	}

	if (!mca_disable_crypto_timeouts) {
		/* Time to declare the device failed/hung */
		return (DDI_FAILURE);
	} else {
		/* Just continue w/o failure */
		return (DDI_SUCCESS);
	}
}
#endif

void
mca_crypto_jobcheck(mca_ring_t *ringp)
{
	mca_request_t	*reqp;

	mutex_enter(&ringp->mr_lock);
	if (QEMPTY(&ringp->mr_runq)) {
		/* nothing sitting in the queue */
		ASSERT(ringp->mr_timeout == 0);
		mutex_exit(&ringp->mr_lock);
		return;
	}

	reqp = (mca_request_t *)mca_peekqueue(&ringp->mr_runq);
	mca_stalled_request = *reqp;

	mutex_exit(&ringp->mr_lock);

	if (!mca_disable_crypto_timeout_msgs) {
		cmn_err(CE_WARN, "stale job(s) found in ring %p",
		    (void *)ringp);
		mca_dumpreq(&mca_stalled_request);
	}
}

static int
mca_drainring(mca_ring_t *ringp, int drain_type)
{
	mutex_enter(&ringp->mr_lock);

	ringp->mr_drain = drain_type;

	/* give some time to drain from the chip */
	if (!QEMPTY(&ringp->mr_runq)) {
		cv_timedwait(&ringp->mr_draincv, &ringp->mr_lock,
		    ddi_get_lbolt() + ringp->mr_timeout);

		if (!QEMPTY(&ringp->mr_runq)) {
			mca_error(ringp->mr_mca, "unable to drain device");
			mutex_exit(&ringp->mr_lock);
			return (EBUSY);
		}
	}

	mutex_exit(&ringp->mr_lock);
	return (0);
}

static int
mca_drainctl(mca_t *mca)
{
	mutex_enter(&mca->mca_ctllock);
	mca->mca_ctldrain = 1;
	if (mca->mca_ctlbusy) {
		cv_timedwait(&mca->mca_ctlcv, &mca->mca_ctllock,
		    ddi_get_lbolt() + drv_usectohz(mca_staletime));
		if (mca->mca_ctlbusy) {
			mca_error(mca, "control node is busy");
			mca->mca_ctldrain = 0;
			mutex_exit(&mca->mca_ctllock);
			return (EBUSY);
		}
	}
	mutex_exit(&mca->mca_ctllock);
	return (0);
}

void
mca_ctlbusy(mca_t *mca)
{
	mutex_enter(&mca->mca_ctllock);
	while (mca->mca_ctldrain | mca->mca_ctlbusy) {
		cv_wait(&mca->mca_ctlcv, &mca->mca_ctllock);
	}
	mca->mca_ctlbusy = 1;
	mca->mca_ctlint = 0;
	mutex_exit(&mca->mca_ctllock);
}

void
mca_ctlunbusy(mca_t *mca)
{
	mutex_enter(&mca->mca_ctllock);
	mca->mca_ctlbusy = 0;
	cv_broadcast(&mca->mca_ctlcv);
	mutex_exit(&mca->mca_ctllock);
}

/* only allow DBM messages to be processed */
void
mca_undrain_dbm(mca_t *mca)
{
	mca_ring_t *ringp = &mca->mca_ring_om;

	mutex_enter(&ringp->mr_lock);
	ringp->mr_drain = MCA_DBM_DRAIN;
	mutex_exit(&ringp->mr_lock);
}

int
mca_drain(mca_t *mca, int drain_type)
{
	int	rv;

	/* Only normal drains can be performed on CB ring */
	if ((rv = mca_drainring(&mca->mca_ring_cb, MCA_NORMAL_DRAIN)) != 0) {
		DBG(mca, DWARN, "unable to drain CB ring");
		return (rv);
	}
	/* Only normal drains can be performed on CB ring */
	if ((rv = mca_drainring(&mca->mca_ring_ca, MCA_NORMAL_DRAIN)) != 0) {
		DBG(mca, DWARN, "unable to drain CA ring");
		mca_undrainring(&mca->mca_ring_cb);
		return (rv);
	}
	if ((rv = mca_drainring(&mca->mca_ring_om, drain_type)) != 0) {
		DBG(mca, DWARN, "unable to drain OM ring");
		mca_undrainring(&mca->mca_ring_cb);
		mca_undrainring(&mca->mca_ring_ca);
		return (rv);
	}
	if ((rv = mca_drainctl(mca)) != 0) {
		mca_undrainring(&mca->mca_ring_cb);
		mca_undrainring(&mca->mca_ring_ca);
		mca_undrainring(&mca->mca_ring_om);
		return (rv);
	}
	return (0);
}

static void
mca_undrainring(mca_ring_t *ringp)
{
	mutex_enter(&ringp->mr_lock);
	ringp->mr_drain = 0;
	mutex_exit(&ringp->mr_lock);
}

void
mca_undrainctl(mca_t *mca)
{
	mutex_enter(&mca->mca_ctllock);
	mca->mca_ctldrain = 0;
	cv_broadcast(&mca->mca_ctlcv);
	mutex_exit(&mca->mca_ctllock);
}

void
mca_undrain(mca_t *mca)
{
	mca_undrainring(&mca->mca_ring_cb);
	mca_undrainring(&mca->mca_ring_ca);
	mca_undrainring(&mca->mca_ring_om);
	mca_undrainctl(mca);
}

static void
mca_busyring(mca_ring_t *ringp)
{
	mutex_enter(&ringp->mr_lock);
	if (!ringp->mr_busy) {
		ringp->mr_busy = 1;
		MCA_NOTIFY_BUSY(ringp);
	}
	mutex_exit(&ringp->mr_lock);
}

void
mca_busy(mca_t *mca)
{
	mca_busyring(&mca->mca_ring_ca);
	mca_busyring(&mca->mca_ring_cb);
	mca_busyring(&mca->mca_ring_om);
}

static void
mca_unbusyring(mca_ring_t *ringp)
{
	mutex_enter(&ringp->mr_lock);
	if (ringp->mr_busy) {
		ringp->mr_busy = 0;
		MCA_NOTIFY_READY(ringp);
	}
	mutex_exit(&ringp->mr_lock);
}

void
mca_unbusy(mca_t *mca)
{
	mca_unbusyring(&mca->mca_ring_ca);
	mca_unbusyring(&mca->mca_ring_cb);
	mca_unbusyring(&mca->mca_ring_om);
}

uint16_t
mca_loadswap16(uint16_t *addr)
{
	return (ddi_swap16(*addr));
}

uint32_t
mca_loadswap32(uint32_t *addr)
{
	return (ddi_swap32(*addr));
}

void
mca_storeswap16(uint16_t *addr, uint16_t val)
{
	*addr = ddi_swap16(val);
}

void
mca_storeswap32(uint32_t *addr, uint32_t val)
{
	*addr = ddi_swap32(val);
}

/*
 *
 * New timeout code.
 */

/*
 * Check the rings for a job timeout condition.
 *
 * The timeout logic works as follows:
 *
 * Once a second, we check to see if any job has been reclaimed from
 * one of our three (3) rings.  I stress the word `any'.  If /any/ job
 * has been reclaimed, i.e., completed, then we assume that the crypto
 * device is still in good, working condition.  But if we find that
 * no job has been reclaimed in, oh, 3 seconds, then we assume the
 * worst: the device is hung.  So what do we do?
 *
 * 1) We attempt to drain the rings.
 *  a) Set the drain timeout to some default value (30 seconds or less).
 *  b) Wait for the rings to drain.
 * 2) If the drain succeeds, reschedule mca_jobtimeout() and continue.
 * 3) If the drain fails, dump any stalled jobs, and call mca_failure().
 *
 * The function calling tree looks something like this:
 *
 * mca_jobtimeout()
 * ================> taskq_dispatch(draining)
 * ...
 * new thread: draining()
 * ======================> mca_failure()
 *
 */

/*
 * jobtimedout
 *
 * void jobtimeout ( mca_t* mca )
 *
 * Prototyped in: mca.c
 *
 * Calls: mutex_enter(), mutex_exit(), timeout()
 *
 * Called by:
 * draining() mca.c
 * mca_jobtimeout() mca.c
 * mca_restart() mca.c
 * References Functions: mca_jobtimeout() mca.c
 *
 * Reschedule ourself to run again.
 *
 */
static void
jobtimeout(
	mca_t *mca)
{
	/* Reschedule ourself. */
	mutex_enter(&mca->mca_job_lock);

	if (mca_isattached(mca)) {
		/* Check again in <job.timeout.ticks>. */
		mca->job.timeout.id =
		    timeout(mca_jobtimeout,
			(void *)mca,
			mca->job.timeout.ticks);
	}

	mutex_exit(&mca->mca_job_lock);
}

/*
 * jobtimedout
 *
 * static void jobtimedout ( mca_t* mca )
 *
 * Prototyped in: mca.c
 *
 * Calls:
 * mca_crypto_jobcheck() mca.c
 * mca_failure() mca.c
 *
 * Called by:
 * draining() mca.c
 * mca_jobtimeout() mca.c
 *
 * References Variables: mca_disable_crypto_timeouts mca.c
 *
 * Dump any stalled jobs, and call mca_failure().
 *
 */
static void
jobtimedout(
	mca_t *mca)
{
	/* Print out something about the stalled jobs. */
	mca_crypto_jobcheck(&mca->mca_ring_cb);
	mca_crypto_jobcheck(&mca->mca_ring_ca);
	mca_crypto_jobcheck(&mca->mca_ring_om);

	/* Then, unless requested not to, */
	if (!mca_disable_crypto_timeouts) {
		/* restart the sca6000. */
		mca_failure(mca, MCA_FMA_TO_CRYPTO_ID,
		    "crypto job timeout");
	}
}

/*
 * draining
 *
 * static void draining ( mca_t* mca )
 *
 * Calls:
 * jobtimedout() mca.c
 * jobtimeout() mca.c
 * mca_drain() mca.c
 * mca_undrain() mca.c
 * drv_usectohz(), mutex_enter(), mutex_exit()
 *
 * Used in: mca_jobtimeout() mca.c
 *
 * Try to drain the rings first, before assuming that some job is stalled.
 *
 */
static void
draining(
	mca_t *mca)
{
	/* If every job was properly drained, just continue. */
	if (mca_drain(mca, 0) == MCA_NORMAL_DRAIN) {
		mca_undrain(mca);
		jobtimeout(mca);
	} else {
		jobtimedout(mca);
	}
}

int mca_driver_debug;

/*
 * mca_jobtimeout
 * void mca_jobtimeout ( void* arg )
 *
 * Prototyped in: mca.c
 *
 * Calls:
 * jobtimedout() mca.c
 * jobtimeout() mca.c
 * mca_failure() mca.c
 * cmn_err(), mutex_enter(), mutex_exit(), taskq_dispatch()
 *
 * Used in:
 * jobtimeout() mca.c
 * mca_attach() mca.c
 * mca_detach() mca.c
 * mca_jobtimeout_() mca.c
 *
 * References Functions: draining() mca.c
 *
 * References Variables:
 * mca_job_timeout_debug mca.c
 * mca_taskq mca.c
 *
 */
static void
mca_jobtimeout(
	void *arg)
{
	mca_t *mca = (mca_t *)arg;
	mca_counter_t submitted, reclaimed;
	int limit;

	mca->job.timeout.count++;

	mutex_enter(&mca->reset.lock);
	submitted = mca->job.submitted;
	reclaimed = mca->job.reclaimed;
	limit = mca->job.stalled.limit;
	mutex_exit(&mca->reset.lock);

	/* XXX Use this to debug the timeout additions & subtractions. */
	if (mca_driver_debug && mca->job.stalled.addend) {
		int seconds = mca->job.stalled.count / mca->job.stalled.addend;
		/* If we've been stalled for any number of seconds, */
		/* or <count> has been set back to zero (0), record the */
		/* the new value of <seconds>. */
		if (mca->job.stalled.seconds != seconds) {
			if (!(seconds & ((2 << 4) - 1))) { /* once/32s. */
				cmn_err(CE_CONT,
				    "Crypto job stalled: %ld / %d",
				    mca->job.stalled.count, limit);
			}
			mca->job.stalled.seconds = seconds;
		}
	}

	/*
	 * There are 2 `impossible' error conditions we ought to look for:
	 * 1. submitted < reclaimed
	 * 2. reclaimed < watermark
	 * `1' is possible if submitted wraps.
	 * `2' is possible if reclaimed wraps.
	 * But considering that UINT64_MAX == 18446744073709551615ULL,
	 * it seems extremely unlikely that either event would happen.
	 * For now, we'll keep these error checks until we
	 * are sure the corresponding errors won't show up.
	 */

	if (submitted < reclaimed || reclaimed < mca->job.watermark) {
		mca_failure(mca, MCA_FMA_NO_CLASS_ID,
		    "in [%d] / out [%d] / high [%d]",
		    submitted, reclaimed, mca->job.watermark);
		return;
	}

	if (submitted == reclaimed || /* We're caught up. */
	    mca->job.watermark < reclaimed) { /* There was activity. */
		mca->job.watermark = reclaimed;
		mca->job.stalled.count = 0;
		jobtimeout(mca);
		return;
	}

	/* submitted > reclaimed && mca->job.watermark == reclaimed */

	mca->job.stalled.count += mca->job.stalled.addend;

	if (mca->job.stalled.count < limit) {
		jobtimeout(mca);
	} else {		/* >=limit */
		cmn_err(CE_WARN, "STALL: count [%ld] / limit [%d]",
		    mca->job.stalled.count, limit);
		if (ddi_taskq_dispatch(mca->mca_taskq,
		    (task_func_t *)draining,
		    (void *)mca, DDI_NOSLEEP) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "mca_jobtimeout.taskq_dispatch.error");
			/* If <dispatch> fails, don't try to drain. */
			jobtimedout(mca);
		}
		/* Do /not/ schedule mca_jobtimeout() again. */
		/* draining() will do that after it runs. */
	}
}

/*
 *
 * New failure code.
 */

/*
 * mca_failure
 *
 * Call this when a failure is detected.  It will inform the system of
 * a failure, log a message, reset the board, maybe alert crypto framework, and
 * mark all jobs in the run queue as failed.
 *
 * void mca_failure ( mca_t* mca, ddi_fault_location_t loc, uint16_t errno,
 *                    char* format, ... )
 *
 * Prototyped in: /workspace/tm144005/ws1/usr/src/uts/common/sys/mca.h
 *
 * Calls:
 * mca_disableinterrupts() mca_hw.c
 * __builtin_va_end(), __builtin_va_start(), cmn_err(), ddi_dev_report_fault(),
 * ddi_get_devstate(), taskq_dispatch(), vsprintf()
 *
 * Called by:
 * jobtimedout() mca.c
 * mca_diagnostics() mca_hw.c
 * mca_fdi_dl() mca_hw.c
 * mca_fdi_req() mca_hw.c
 * mca_fwupdate() mca_hw.c
 * mca_get_firmware_keystore() mca_hw.c
 * mca_getlog() mca_log.c
 * mca_getpubkey() mca_hw.c
 * mca_intr() mca_hw.c
 * mca_jobtimeout() mca.c
 * mca_reclaim() mca.c
 * mca_restart() mca.c
 * mca_resume() mca.c
 * mca_safereset() mca.c
 * mca_seccmd() mca_hw.c
 * mca_setktikey() mca_hw.c
 * mca_zeroize() mca_hw.c
 * mcactl_failure() mcactl.c
 *
 * References Functions: mca_failure2() mca.c
 * References Variables: mca_taskq mca.c
 *
 * The function calling tree looks something like this:
 *
 * mca_failure()
 * =============> mca_disableinterrupts();
 * =============> ddi_dev_report_fault()
 * =============> taskq_dispatch(mca_failure2)
 * ...
 * new thread: mca_failure2()
 * ==========================> mca_hardreset()
 * ==========================> taskq_dispatch(mca_restart)
 * ...
 * new thread: mca_restart()
 * =========================> mca_masterstart()
 * =========================> mca_enableinterrupts();
 *
 */

/*ARGSUSED2*/
void
mca_failure(mca_t *mca, uint8_t eclass, char *format, ...)
{
	va_list ap;

	/* Schedule this once only. */
	if (mca_fm_isfailed(mca) || mca_fm_is_fail_sched(mca))
	    return;

	/*
	 * Prevent any new interrupts from being generated by the
	 * device.  Note that an interrupt handler might still be
	 * executing concurrently.
	 */
	mca_disableinterrupts(mca, 0);
	mca_driver_debug = 0;

	/*
	 * Prevent any more jobs from being scheduled.
	 */
	mutex_enter(&mca->fm_lock);
	if (mca->reset.logic == mca_resetsoft_wait ||
	    mca->reset.logic == mca_resethard_wait ||
	    mca_disable_crypto_resets ||
	    mca_fm_hw_faulted(mca)) {
		mca_fm_setfailed(mca);
	} else {
		mca_fm_setoffline(mca);
	}
	mutex_exit(&mca->fm_lock);

	/*
	 * If mca_failure() is called from the attach function,
	 * do nothing more: the driver's data structures are in
	 * an incomplete state.  In particular, we should return
	 * without creating the new failure thread.  mca_attach()
	 * is going to kmem_free() /mca/.  We would have nothing
	 * to work with.
	 */
	if (mca_isattaching(mca)) {
		return;
	}

	/*
	 * Save ereport error class and message string for later
	 * logging by mca_failure2()
	 */
	mutex_enter(&mca->fm_lock);
	if (mca->fm_eclass == MCA_FMA_NO_CLASS_ID) {
		va_start(ap, format);
		(void) vsprintf(mca->fm_msg, format, ap);
		va_end(ap);
		mca->fm_eclass = eclass;
	}
	mutex_exit(&mca->fm_lock);

	if (ddi_taskq_dispatch(mca->mca_taskq, (task_func_t *)mca_failure2,
		(void *)mca, DDI_NOSLEEP) != DDI_SUCCESS) {
		mutex_enter(&mca->fm_lock);
		mca_fm_clr_fail_sched(mca);
		mutex_exit(&mca->fm_lock);
		cmn_err(CE_WARN, "mca_failure.taskq_dispatch.error");
	} else {
		mutex_enter(&mca->fm_lock);
		mca_fm_set_fail_sched(mca);
		mutex_exit(&mca->fm_lock);
	}
}

static void
mca_failure2(mca_t *mca)
{
#ifdef FMA_COMPLIANT
	uint16_t	pci_status;
	ddi_fm_error_t	pci_err;

	mutex_enter(&mca->fm_lock);

	if (DDI_FM_EREPORT_CAP(mca->fm_capabilities)) {

		/* Log ereport if available */
		if (mca->fm_eclass != MCA_FMA_NO_CLASS_ID) {

			/* Create or increment ENA */
			if (mca->fm_ena == 0) {
				mca->fm_ena = MCA_ENA_GEN;
				MCA_EREPORT_POST(mca, LOGMASK_ERROR,
				    mca->fm_ena, mca->fm_eclass, mca->fm_msg);
			} else {
				/*
				 * Don't post a deliquent hardware
				 * ereport if the firmware did indeed post
				 * one (ena != 0)
				 */
				if (mca->fm_eclass != MCA_FMA_FW_NO_REPORT_ID) {
					mca->fm_ena = MCA_ENA_INC(mca->fm_ena);
					MCA_EREPORT_POST(mca, LOGMASK_ERROR,
					    mca->fm_ena, mca->fm_eclass,
					    mca->fm_msg);
				}
			}

			/*
			 * See if there is a pci error as well.
			 *
			 * Note: We currently don't attempt to chain the ENA of
			 *	 hardware errors and pci errors since the
			 *	 delayed mars logging process makes it
			 *	 unclear there would be any benefit in doing
			 *	 so.  Generic pci errors induced by the mars
			 *	 hardware will likely be reported via the fma
			 *	 error callback function long before we get
			 *	 here.  If we decide to do so at a later time,
			 *	 an additional flag would be required to
			 *	 indicate when chaining should be done by
			 *	 setting pci_err.fme_ena = mca->fm_ena
			 */

			/* Insure unused fields are initialized to zero */
			bzero(&pci_err, sizeof (ddi_fm_error_t));
			pci_err.fme_version = DDI_FME_VERSION;
			pci_err.fme_flag = DDI_FM_ERR_UNEXPECTED;
			pci_err.fme_ena = 0;		 /* Generate ENA */
			pci_ereport_post(mca->mca_dip, &pci_err, &pci_status);

			if (mca_pcierror(pci_status)) {
				DBG(mca, DWARN, "mca_failure2> pci_status = "
				    "%04x", pci_status);
			}

		} else {
			/* Just log the error string to the message log */
			mca_log_system_msg(mca, LOGMASK_ERROR, mca->fm_msg);
		}

		/* Report the impact of the failure to the DDI. */
		ddi_fm_service_impact(
			mca->mca_dip, mca_fm_isfailed(mca) ?
			DDI_SERVICE_LOST : DDI_SERVICE_DEGRADED);
	} else {
		/* Just log the error string to the message log */
		mca_log_system_msg(mca, LOGMASK_ERROR, mca->fm_msg);
	}


	mca->fm_eclass = MCA_FMA_NO_CLASS_ID;
	mca->fm_ena = 0;
	mutex_exit(&mca->fm_lock);

#endif /* FMA_COMPLIANT */

	/*
	 * If mca_failure2() is called while the driver is detached, don't do
	 * anything other than log the error message.  The hardware access
	 * structures are likely to be invalid, the crypto rings should already
	 * be drained, and the driver should not be registered.
	 */
	if (mca_isdetached(mca)) {
		DBG(mca, DBRINGUP, "mca_failure2: driver detached\n");
		return;
	}

	/* Untimeout the job timeout, if necessary. */
	mutex_enter(&mca->mca_job_lock);
	if (mca->job.timeout.id) {
		untimeout(mca->job.timeout.id);
		mca->job.timeout.id = 0;
	}
	mutex_exit(&mca->mca_job_lock);

	/*
	 * Signal the various condition variables.
	 */

	/* Force a thread in ctlwait() to stop waiting. */
	/* If a thread calls ctlwait() while interrupts are disabled, */
	/* it will spin until done waiting.  That could take a while. */
	/* Making <mca_ctlint> non-zero forces it to quit early. */
	mca->mca_ctlint = 1;

	mutex_enter(&mca->mca_ctllock);
	cv_broadcast(&mca->mca_ctlcv);
	mutex_exit(&mca->mca_ctllock);

	/* Force a thread in msgwait() to stop waiting. */
	mca->log.interrupt = 1;

	mutex_enter(&mca->log.lock);
	cv_broadcast(&mca->log.cv);
	mutex_exit(&mca->log.lock);

	/*
	 * Reset the sca6000
	 */
	if (!mca_disable_crypto_resets) {
		reset_count(mca);
		mca_hardreset(mca, MCA_RESET_SOFT);
	}

	if (mca_fm_isfailed(mca)) {
		/*
		 * Report the failure to the framework.
		 */
		MCA_NOTIFY_FAILURE(&mca->mca_ring_ca);
		MCA_NOTIFY_FAILURE(&mca->mca_ring_cb);
		MCA_NOTIFY_FAILURE(&mca->mca_ring_om);
	}

	/*
	 * From this point on, no new work should be arriving,
	 * and the device should not be doing any active DMA.
	 */
	mca_failring(&mca->mca_ring_ca, CRYPTO_DEVICE_ERROR);
	mca_failring(&mca->mca_ring_cb, CRYPTO_DEVICE_ERROR);
	mca_failring(&mca->mca_ring_om, CRYPTO_DEVICE_ERROR);

	/* Finally, if the board has not been failed, */
	/* schedule a thread to bring it back to life. */
	if (!(mca_fm_isfailed(mca))) {
		if (ddi_taskq_dispatch(mca->mca_taskq,
			(task_func_t *)mca_restart, (void *)mca,
			DDI_NOSLEEP) != DDI_SUCCESS) {
			mutex_enter(&mca->fm_lock);
			mca_fm_clr_fail_sched(mca);
			mutex_exit(&mca->fm_lock);
			cmn_err(CE_WARN, "mca_failure2.taskq_dispatch.error");
		} else {
			mutex_enter(&mca->fm_lock);
			mca_fm_set_fail_sched(mca);
			mutex_exit(&mca->fm_lock);
		}
	} else {
		/* Reallocate resources not working on Linux */
		/* Free and re-allocate dma resources */
		mca_ctlbusy(mca);

		/* this guarantees that no jobs will be submitted from kEF */
		(void) mca_hw_provider_unregister(mca);

		(void) mca_realloc_resources(mca);

		/* re-register the providers, but mark it failed */
		(void) mca_hw_provider_register(mca, 0 /* not diag */);
		MCA_NOTIFY_FAILURE(&mca->mca_ring_ca);
		MCA_NOTIFY_FAILURE(&mca->mca_ring_cb);
		MCA_NOTIFY_FAILURE(&mca->mca_ring_om);
		mca_ctlunbusy(mca);

		/* Clear so we can fail again. */
		mutex_enter(&mca->fm_lock);
		mca_fm_clr_fail_sched(mca);
		mutex_exit(&mca->fm_lock);
	}
}

/*
 * mca_restart
 *
 * int mca_restart ( mca_t* mca )
 *
 * Prototyped in: mca.c
 *
 * Calls:
 * jobtimeout() mca.c
 * mca_enableinterrupts() mca_hw.c
 * mca_failure() mca.c
 * mca_masterstart() mca_hw.c
 * mca_undrain() mca.c
 * mca_undrainctl() mca.c
 * bzero(), ddi_dev_report_fault(), ddi_get_devstate()
 *
 * Used in: mca_failure2() mca.c
 *
 * restart the sca6000 card.
 */
static int
mca_restart(
	mca_t *mca)
{
	mca_init_job_timeout_info(mca);

	/*
	 * Turn off "ctldrain", since we don't want to block ourself.
	 * (ctlbusy is called by masterstart below.)  [It is?]
	 */
	mca_undrainctl(mca);

	if (mca_masterstart(mca) != DDI_SUCCESS) {
		/* Ereport already filed in mca_masterstart */
		mca_failure(mca, MCA_FMA_NO_CLASS_ID,
			"unable to restore service after reset");
		return (EIO);
	}

	mutex_enter(&mca->fm_lock);
	mca_fm_setonline(mca);
	mutex_exit(&mca->fm_lock);

	mca_enableinterrupts(mca, 0);

	mca_undrain(mca);

	/* notify scakiod */
	mca_upcall_reset(mca);

#ifdef FMA_COMPLIANT
	/* Report service degraded if we are in fail-safe mode */
	if (mca_fm_isfailsafe(mca) &&
	    (ddi_get_devstate(mca->mca_dip) != DDI_DEVSTATE_DEGRADED)) {
		ddi_fm_service_impact(mca->mca_dip,
		    DDI_SERVICE_DEGRADED);
	}
#endif /* FMA_COMPLIANT */

	/* Restart the MCA job timer. */
	jobtimeout(mca);

	/* Clear flag so we can fail again. */
	mutex_enter(&mca->fm_lock);
	mca_fm_clr_fail_sched(mca);
	mutex_exit(&mca->fm_lock);

	return (0);
}

static void
reset_count(
	mca_t *mca)
{
	int already_failed = mca_fm_isfailed(mca);

	/* Is this the first reset? */
	if (mca->reset.first == 0) {
		mca->reset.first = ddi_get_time();
	}

	mutex_enter(&mca->reset.lock);

	/* Has the device been reset recently? */
	if (mca->reset.tid) {	/* <= timeout() id. */

		untimeout(mca->reset.tid);

		mca->reset.tid = 0;
		mca->reset.serial++;

		/* Has the device been reset too often recently? */
		if (mca->reset.serial == MCA_SERIAL_RESET_MAX) {
			mutex_enter(&mca->fm_lock);
			mca_fm_setfailed(mca);
			mutex_exit(&mca->fm_lock);
		}
	}

	mutex_exit(&mca->reset.lock);

	mca->reset.count++;
	if (mca->reset.count == MCA_RESET_MAX) {

		/* If we have reset MCA_RESET_MAX times in the last hour, */
		/* something's gotta be wrong.  Fail the device. */
		if (ddi_get_time() - mca->reset.first < (60 * 60)) {
			mutex_enter(&mca->fm_lock);
			mca_fm_setfailed(mca);
			mutex_exit(&mca->fm_lock);
		} else {
			/* Start our count all over again. */
			mca->reset.count = 1;
			mca->reset.first = ddi_get_time();
		}
	}

	/* Did we just decide to fail? */
	/* (We don't want to report the same failure twice.) */
	if (mca_fm_isfailed(mca) && !already_failed) {

		/* Juist log a message in the message log */
		mca_note(mca, "driver has been reset too often "
		    "(%d times in the last %ld minutes)", mca->reset.count,
		    (ddi_get_time() - mca->reset.first) / 60);

		mutex_enter(&mca->fm_lock);
		mca_fm_setfailed(mca);
		mutex_exit(&mca->fm_lock);
	}

	/* If the device has not been failed, create this timeout. */
	if (!(mca_fm_isfailed(mca))) {
		mca->reset.tid =
		    timeout(serial_reset,
			(void *)mca,
			drv_usectohz(2 * 60 * SECOND));
	}

}

static void
serial_reset(
	void *arg)
{
	mca_t *mca = (mca_t *)arg;

	mutex_enter(&mca->reset.lock);
	mca->reset.serial = 0;
	mca->reset.tid = 0;
	mutex_exit(&mca->reset.lock);
}

/*
 * This compares two bignums (in big-endian order).  It ignores
 * leading null bytes.  The result semantics follow bcmp, mempcmp,
 * strcmp, etc.
 */
int
mca_numcmp(caddr_t n1, int n1len, caddr_t n2, int n2len)
{
	while ((n1len > 1) && (*n1 == 0)) {
		n1len--;
		n1++;
	}
	while ((n2len > 1) && (*n2 == 0)) {
		n2len--;
		n2++;
	}
	if (n1len != n2len) {
		return (n1len - n2len);
	}
	while ((n1len > 1) && (*n1 == *n2)) {
		n1++;
		n2++;
		n1len--;
	}
	return ((int)(*(uchar_t *)n1) - (int)(*(uchar_t *)n2));
}

/*
 * This is used to remove leading null bytes from a bignum.
 * If the bignum zero is passed in, the last byte is left alone.
 */
void
mca_stripzeros(caddr_t *np, unsigned *nlenp)
{
	caddr_t	n = *np;
	int	nlen = *nlenp;
	while ((nlen > 1) && !*n) {
		nlen--;
		n++;
	}
	*nlenp = nlen;
	*np = n;
}

int
mca_bitlen(caddr_t n, unsigned len)
{
	len = BYTES2BITS(len);
	while (len && !*n) {
		len -= 8;
		n++;
	}
	if (len) {
		uint8_t x = 0x80;
		while (x && ((x & *n) == 0)) {
			x >>= 1;
			len--;
		}
	}
	return (len);
}


/*
 * Generate a new IV, and stuff it into the request short-key.  We start
 * with a random number (from /dev/random) and then just increment/decrement
 * the values returned.
 */
void
mca_setiv(mca_request_t *reqp)
{
	static int	generated = 0;
	static uint64_t	iv[2];
	uint64_t	newiv[2];

	if (!generated) {
		/* initialize the IV registers */
		if (random_get_bytes((uchar_t *)iv, sizeof (iv)) == 0) {
			generated = 1;
		}
	}

	/*
	 * I don't believe there is any compelling reason (from a
	 * security standpoint) to worry about performing these
	 * operations atomically.  Occasional (rare) reuse of an IV
	 * should be acceptable, though less than desirable.
	 */
	newiv[0] = iv[0]++;
	newiv[1] = iv[1]--;
	reqp->mr_short_key[0] = newiv[0] >> 32;
	reqp->mr_short_key[1] = newiv[0] & 0xffffffff;
	reqp->mr_short_key[2] = newiv[1] >> 32;
	reqp->mr_short_key[3] = newiv[1] & 0xffffffff;
}

void
mca_ktkencryptbuf(mca_request_t *reqp)
{
	DBG(NULL, DFIPS, "mca_ktkencryptbuf--->");

	reqp->mr_in_len = PADAES(reqp->mr_in_len);

	mca_setiv(reqp);
	mca_aes_cbc_encrypt(&mca_ktk, reqp->mr_short_key,
	    (uchar_t *)reqp->mr_ibuf_kaddr,
	    (uchar_t *)reqp->mr_ibuf_kaddr, reqp->mr_in_len);
}

void
mca_ktkdecryptbuf(mca_request_t *reqp)
{
	DBG(NULL, DFIPS, "mca_ktkdecryptbuf--->");

	/* IV should already be in the short_key */
	mca_aes_cbc_decrypt(&mca_ktk, reqp->mr_short_key,
	    (uchar_t *)reqp->mr_obuf_kaddr,
	    (uchar_t *)reqp->mr_obuf_kaddr, PADAES(reqp->mr_resultlen));
}

void
mca_ktkencryptkey(mca_request_t *reqp)
{
	DBG(NULL, DFIPS, "mca_ktkencryptkey--->");
	reqp->mr_key_len = PADAES(reqp->mr_key_len);
	mca_setiv(reqp);
	mca_aes_cbc_encrypt(&mca_ktk, reqp->mr_short_key,
	    (uchar_t *)reqp->mr_key_kaddr,
	    (uchar_t *)reqp->mr_key_kaddr, reqp->mr_key_len);
}

void
mca_ktkencryptshortkey(mca_request_t *reqp)
{
	/* use a null (zero) IV for KTK */
	uint32_t	nulliv[4] = { 0, 0, 0, 0 };
	uchar_t		b_short_key[64];
	int		i;

	for (i = 0; i < 16; i++) {
		PUTBE32((uint32_t *)b_short_key + i, reqp->mr_short_key[i]);
	}
	mca_aes_cbc_encrypt(&mca_ktk, nulliv, b_short_key, b_short_key, 64);
	for (i = 0; i < 16; i++) {
		PUTBE32(&(reqp->mr_short_key[i]),
		    *((uint32_t *)b_short_key + i));
	}
}

void
mca_key_free(mca_key_t *key)
{
	int		allocsz = key->mk_allocsz;

	DBG(NULL, DCHATTY, "mca_key_free[%p]", key);

	if (key->mk_cpgattr) {
		cpg_attr_free(key->mk_cpgattr);
		key->mk_cpgattr = NULL;
	}

	mutex_destroy(&(key->mk_lock));

	bzero(key, allocsz);
	kmem_free(key, allocsz);
}


/*
 * CPG_ATTR Related Functions
 */

#ifdef FINSVCS
static int
cpgattr2fs(cpg_attr_t *attr, int keytype, caddr_t buf, uint32_t *buflen)
{
	unsigned	valsz = 0;
	uint8_t		*val = NULL;
	int		expkeytype;

	if (cpg_attr_lookup_uint8_array(attr, CPGA_VALUE, &val, &valsz)) {
		/*
		 * the value field is required
		 */
		DBG(NULL, DCHATTY, "cpgattr2fs: value missing");
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	} else {
		if (valsz != 8) {
			DBG(NULL, DWARN, "keytype[0x%x] has its value "
			    "length %d", keytype, valsz);
			return (CRYPTO_TEMPLATE_INCONSISTENT);
		} else {
			expkeytype = KEYTYPE_FS;
		}

		if (keytype != expkeytype) {
			DBG(NULL, DWARN, "keytype[0x%x] has its value "
			    "length %d", keytype, valsz);
			return (CRYPTO_TEMPLATE_INCONSISTENT);
		}
	}

	if (valsz > *buflen) {
		*buflen = valsz;
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = valsz;

	bcopy((caddr_t)val, buf, valsz);

	return (CRYPTO_SUCCESS);
}
#endif /* FINSVCS */

static int
cpgattr2des(cpg_attr_t *attr, int keytype, caddr_t buf, uint32_t *buflen)
{
	unsigned	valsz = 0;
	uint8_t		*val = NULL;
	int		expkeytype;

	if (cpg_attr_lookup_uint8_array(attr, CPGA_VALUE, &val, &valsz)) {
		uint8_t sensitive;
		if (cpg_attr_lookup_uint8(attr, CPGA_SENSITIVE, &sensitive) !=
		    CRYPTO_SUCCESS) {
			DBG(NULL, DWARN, "cpgattr2des: CPGA_SENSITIVE not set");
			return (CRYPTO_GENERAL_ERROR);
		}
		if (!sensitive) {
			/*
			 * if the key is not sensitive, the value field
			 * is required
			 */
			DBG(NULL, DCHATTY, "cpgattr2des: value missing");
			return (CRYPTO_TEMPLATE_INCOMPLETE);
		}
		*buflen = 0;
		return (CRYPTO_SUCCESS);
	} else {

		switch (valsz) {
		case 8:
			expkeytype = KEYTYPE_DES;
			break;
		case 16:
			expkeytype = KEYTYPE_DES2;
			break;
		case 24:
			expkeytype = KEYTYPE_DES3;
			break;
		default:
			DBG(NULL, DWARN, "keytype[0x%x] has its value "
			    "length %d", keytype, valsz);
			return (CRYPTO_TEMPLATE_INCONSISTENT);
		}

		if (keytype != expkeytype) {
			DBG(NULL, DWARN, "keytype[0x%x] has its value "
			    "length %d", keytype, valsz);
			return (CRYPTO_TEMPLATE_INCONSISTENT);
		}
	}

	if (valsz > *buflen) {
		*buflen = valsz;
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = valsz;

	bcopy((caddr_t)val, buf, valsz);

	return (CRYPTO_SUCCESS);
}

/*
 * This function fills the 'keysz' and 'key' field of the mca_rc2_keyhead_t
 * structure.
 * For COPCODE_USE, 'effbits' and 'iv' field should be filled by the caller
 */
static int
cpgattr2rc2(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen)
{
	unsigned	valsz = 0;
	uint8_t		*val = NULL;
	mca_rc2_keyhead_t *rc2keyhead = (mca_rc2_keyhead_t *)buf;

	if (cpg_attr_lookup_uint8_array(attr, CPGA_VALUE, &val, &valsz)) {
		uint8_t sensitive;
		if (cpg_attr_lookup_uint8(attr, CPGA_SENSITIVE, &sensitive) !=
		    CRYPTO_SUCCESS) {
			DBG(NULL, DWARN, "cpgattr2rc2: CPGA_SENSITIVE not set");
			return (CRYPTO_GENERAL_ERROR);
		}

		if (!sensitive) {
			/*
			 * if the key is not sensitive, the value field
			 * is required
			 */
			DBG(NULL, DCHATTY, "cpgattr2rc2: value missing");
			return (CRYPTO_TEMPLATE_INCOMPLETE);
		}
	} else {
		if ((valsz > 128) || (valsz < 1)) {
			DBG(NULL, DWARN, "rc2:value length mismatch "
			    "(got %u)", valsz);
			return (CRYPTO_TEMPLATE_INCONSISTENT);
		}
	}

	if ((valsz + sizeof (mca_rc2_keyhead_t)) > *buflen) {
		*buflen = valsz + sizeof (mca_rc2_keyhead_t);
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = valsz + sizeof (mca_rc2_keyhead_t);

	buf += sizeof (mca_rc2_keyhead_t);
	PUTBUF32(&rc2keyhead->keysz, valsz);
	bcopy((caddr_t)val, buf, valsz);

	return (CRYPTO_SUCCESS);
}

/*
 * This function will extract CKA_VALUE from the template and stuff in buf.
 * No key length restriction for CKK_GENERIC_SECRET key.
 */
static int
cpgattr2genericsecret(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen)
{
	unsigned	valsz = 0;
	uint8_t		*val = NULL;

	if (cpg_attr_lookup_uint8_array(attr, CPGA_VALUE, &val, &valsz)) {
		uint8_t sensitive;
		if (cpg_attr_lookup_uint8(attr, CPGA_SENSITIVE, &sensitive) !=
		    CRYPTO_SUCCESS) {
			DBG(NULL, DWARN, "cpgatt2des: CPGA_SENSITIVE not set");
			return (CRYPTO_GENERAL_ERROR);
		}
		if (!sensitive) {
			/*
			 * if the key is not sensitive, the value field
			 * is required
			 */
			DBG(NULL, DCHATTY, "cpgattr2des: value missing");
			return (CRYPTO_TEMPLATE_INCOMPLETE);
		}
		*buflen = 0;
		return (CRYPTO_SUCCESS);
	}

	if (valsz > *buflen) {
		*buflen = valsz;
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = valsz;

	bcopy((caddr_t)val, buf, valsz);

	return (CRYPTO_SUCCESS);
}

/*
 * This function fills the 'keysz' and 'key' field of the mca_aes_keyhead_t
 * structure.
 */
static int
cpgattr2aes(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen)
{
	unsigned	valsz = 0;
	uint8_t		*val = NULL;
	mca_aes_keyhead_t *aeskeyhead = (mca_aes_keyhead_t *)buf;

	if (cpg_attr_lookup_uint8_array(attr, CPGA_VALUE, &val, &valsz)) {
		uint8_t sensitive;
		if (cpg_attr_lookup_uint8(attr, CPGA_SENSITIVE, &sensitive) !=
		    CRYPTO_SUCCESS) {
			DBG(NULL, DWARN, "cpgattr2aes: CPGA_SENSITIVE not set");
			return (CRYPTO_GENERAL_ERROR);
		}

		if (!sensitive) {
			/*
			 * if the key is not sensitive, the value field
			 * is required
			 */
			DBG(NULL, DCHATTY, "cpgattr2aes: value missing");
			return (CRYPTO_TEMPLATE_INCOMPLETE);
		}
	} else {
		switch (valsz) {
		case 16:
		case 24:
		case 32:
			break;
		default:
			DBG(NULL, DWARN, "cpgattr2aes:value length "
			    "mismatch (got %u)", valsz);
			return (CRYPTO_TEMPLATE_INCONSISTENT);
		}
	}

	if ((valsz + sizeof (mca_aes_keyhead_t)) > *buflen) {
		*buflen = valsz + sizeof (mca_aes_keyhead_t);
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = valsz + sizeof (mca_aes_keyhead_t);

	PUTBUF32(&aeskeyhead->keysz, valsz);
	buf += sizeof (mca_aes_keyhead_t);
	bcopy((caddr_t)val, buf, valsz);

	return (CRYPTO_SUCCESS);
}

static int
cpgattr2ecpublic(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen)
{
	uint8_t		*param, *point;
	unsigned	paramlen = 0, pointlen = 0, len;
	size_t		sz;
	pubec_head_t	*echead = (pubec_head_t *)buf;

	if (cpg_attr_lookup_uint8_array(attr, CPGA_EC_PARAMS,
		&param, &paramlen) ||
	    cpg_attr_lookup_uint8_array(attr, CPGA_EC_POINT,
		&point, &pointlen)) {
		/* these fields are required */
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	if (paramlen > MAX_EC_OID_LEN) {
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}
	/* Make sure ECPoint comes in as 0x04|X|Y */
	if (point[0] != 0x04) {
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}
	pointlen--;
	point++;
	if ((pointlen % 2) != 0) {
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}

	len = pointlen / 2;
	sz = sizeof (pubec_head_t) + PAD32(len) + PAD32(len);
	if (sz > *buflen) {
		*buflen = sz;
		DBG(NULL, DCHATTY, "ec key is too large! sz = %d", sz);
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = sz;

	mca_stripzeros((caddr_t *)&param, &paramlen);

	/*
	 * Write out param, and x and y.
	 */
	bcopy(param, echead->ec_oid, paramlen);
	PUTBUF32(&echead->xlen, len);
	PUTBUF32(&echead->ylen, len);
	buf += PAD32(sizeof (pubec_head_t));
	bcopy(point, buf, len);
	buf += PAD32(len);
	bcopy(point + len, buf, len);

	return (CRYPTO_SUCCESS);
}

static int
cpgattr2ecprivate(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen)
{
	uint8_t		*param, *d;
	uint32_t	paramlen = 0, dlen = 0;
	size_t		sz;
	priec_head_t	*echead = (priec_head_t *)buf;

	if (cpg_attr_lookup_uint8_array(attr, CPGA_EC_PARAMS,
		&param, &paramlen)) {
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	if (cpg_attr_lookup_uint8_array(attr, CPGA_VALUE, &d, &dlen)) {
		/* these fields are required */
		uint8_t sensitive = 0;
		if (cpg_attr_lookup_uint8(attr, CPGA_SENSITIVE, &sensitive) !=
		    CRYPTO_SUCCESS) {
			DBG(NULL, DWARN,
			    "cpgattr2ecprivate: CPGA_SENSITIVE not set");
			return (CRYPTO_GENERAL_ERROR);
		}
		if (!sensitive) {
			/* CPGA_VALUE is required for a non-sensitive key */
			return (CRYPTO_TEMPLATE_INCOMPLETE);
		}
	}

	if (paramlen > MAX_EC_OID_LEN) {
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}
	sz = sizeof (priec_head_t) + PAD32(dlen);
	if (sz > *buflen) {
		*buflen = sz;
		DBG(NULL, DCHATTY, "ec key is too large! sz = %d", sz);
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = sz;

	mca_stripzeros((caddr_t *)&param, &paramlen);
	mca_stripzeros((caddr_t *)&d, &dlen);

	/* write out param: d (private value) */
	bcopy(param, echead->ec_oid, paramlen);
	PUTBUF32(&echead->dlen, dlen);
	buf += PAD32(sizeof (priec_head_t));

	bcopy(d, buf, dlen);
	buf += PAD32(sizeof (dlen));

	return (CRYPTO_SUCCESS);
}

static int
cpgattr2dhpublic(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen)
{
	uint8_t		*p, *g, *v;
	unsigned	plen = 0, glen = 0, vlen = 0;
	size_t		sz;
	pubdh_head_t	*dhhead = (pubdh_head_t *)buf;

	if (cpg_attr_lookup_uint8_array(attr, CPGA_PRIME, &p, &plen) ||
	    cpg_attr_lookup_uint8_array(attr, CPGA_BASE, &g, &glen)) {
		/* these fields are required */
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}
	if (cpg_attr_lookup_uint8_array(attr, CPGA_VALUE, &v, &vlen)) {
		/* CPGA_VALUE is required for a public key */
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	sz = sizeof (pubdh_head_t) + PAD32(plen) + PAD32(glen) + PAD32(vlen);
	if (sz > *buflen) {
		*buflen = sz;
		DBG(NULL, DCHATTY, "dh key is too large! sz = %d", sz);
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = sz;

	mca_stripzeros((caddr_t *)&p, &plen);
	mca_stripzeros((caddr_t *)&g, &glen);
	mca_stripzeros((caddr_t *)&v, &vlen);

	/* Make sure that the key is in the supported range */
	if ((plen < BITS2BYTES(DH_MIN_KEY_LEN)) ||
	    (plen > BITS2BYTES(DH_MAX_KEY_LEN))) {
		DBG(NULL, DWARN, "plen(%u) not in range", plen);
		return (CRYPTO_KEY_SIZE_RANGE);
	}

	/* write out p, g, and the value. */
	PUTBUF32(&dhhead->plen, plen);
	PUTBUF32(&dhhead->glen, glen);
	PUTBUF32(&dhhead->vlen, vlen);
	buf += PAD32(sizeof (pubdh_head_t));

	bcopy(p, buf, plen);
	buf += PAD32(plen);

	bcopy(g, buf, glen);
	buf += PAD32(glen);

	bcopy(v, buf, vlen);
	buf += PAD32(vlen);

	return (CRYPTO_SUCCESS);
}

static int
cpgattr2dhprivate(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen)
{
	uint8_t		*p, *g, *v;
	unsigned	plen = 0, glen = 0, vlen = 0;
	size_t		sz;
	uint32_t	vbits;
	pridh_head_t	*dhhead = (pridh_head_t *)buf;

	if (cpg_attr_lookup_uint8_array(attr, CPGA_PRIME, &p, &plen) ||
	    cpg_attr_lookup_uint8_array(attr, CPGA_BASE, &g, &glen)) {
		/* these fields are required */
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}
	if (cpg_attr_lookup_uint8_array(attr, CPGA_VALUE, &v, &vlen)) {
		uint8_t sensitive = 0;
		if (cpg_attr_lookup_uint8(attr, CPGA_SENSITIVE, &sensitive) !=
		    CRYPTO_SUCCESS) {
			DBG(NULL, DWARN,
			    "cpgattr2dhprivate: CPGA_SENSITIVE not set");
			return (CRYPTO_GENERAL_ERROR);
		}
		if (!sensitive) {
			/* CPGA_VALUE is required for a non-sensitive key */
			return (CRYPTO_TEMPLATE_INCOMPLETE);
		}
	}

	sz = sizeof (pridh_head_t) + PAD32(plen) + PAD32(glen) + PAD32(vlen);
	if (sz > *buflen) {
		*buflen = sz;
		DBG(NULL, DCHATTY, "dh key is too large! sz = %d", sz);
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = sz;

	mca_stripzeros((caddr_t *)&p, &plen);
	mca_stripzeros((caddr_t *)&g, &glen);
	mca_stripzeros((caddr_t *)&v, &vlen);

	/* Make sure that the key is in the supported range */
	if ((plen < BITS2BYTES(DH_MIN_KEY_LEN)) ||
	    (plen > BITS2BYTES(DH_MAX_KEY_LEN))) {
		DBG(NULL, DWARN, "plen(%u) not in range", plen);
		return (CRYPTO_KEY_SIZE_RANGE);
	}

	/* write out p, g, and the value. */
	PUTBUF32(&dhhead->plen, plen);
	PUTBUF32(&dhhead->glen, glen);
	PUTBUF32(&dhhead->vlen, vlen);
	buf += PAD32(sizeof (pridh_head_t));

	bcopy(p, buf, plen);
	buf += PAD32(plen);

	bcopy(g, buf, glen);
	buf += PAD32(glen);

	bcopy(v, buf, vlen);
	buf += PAD32(vlen);

	if (cpg_attr_lookup_uint32(attr, CPGA_VALUE_BITS, &vbits)) {
		vbits = BYTES2BITS(GETBUF32(&dhhead->plen));
	} else {
		if (GETBUF32(&dhhead->plen) < BITS2BYTES(vbits)) {
			return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
		}
	}
	PUTBUF32(&dhhead->vbits, vbits);

	return (CRYPTO_SUCCESS);
}

static int
cpgattr2dsakey(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen, uint32_t class)
{
	uint8_t		*p, *q, *g, *v;
	unsigned	plen = 0, qlen = 0, glen = 0, vlen = 0;
	size_t		sz;
	dsa_head_t	*dsahead = (dsa_head_t *)buf;

	if (cpg_attr_lookup_uint8_array(attr, CPGA_PRIME, &p, &plen) ||
	    cpg_attr_lookup_uint8_array(attr, CPGA_SUBPRIME, &q, &qlen) ||
	    cpg_attr_lookup_uint8_array(attr, CPGA_BASE, &g, &glen)) {
		/* these fields are required */
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}
	if (cpg_attr_lookup_uint8_array(attr, CPGA_VALUE, &v, &vlen)) {
		uint8_t sensitive = 0;
		if (cpg_attr_lookup_uint8(attr, CPGA_SENSITIVE, &sensitive) !=
		    CRYPTO_SUCCESS) {
			DBG(NULL, DWARN,
			    "cpgattr2dsakey: CPGA_SENSITIVE not set");
			return (CRYPTO_GENERAL_ERROR);
		}
		if (!sensitive) {
			/* this field is required for a non-sensitive key */
			return (CRYPTO_TEMPLATE_INCOMPLETE);
		}
	}

	sz = sizeof (dsa_head_t) + PAD32(plen) + PAD32(qlen) +
	    PAD32(glen) + PAD32(vlen);
	if (sz > *buflen) {
		*buflen = sz;
		DBG(NULL, DCHATTY, "dsa key is too large! sz = %d", sz);
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = sz;

	mca_stripzeros((caddr_t *)&p, &plen);
	mca_stripzeros((caddr_t *)&q, &qlen);
	mca_stripzeros((caddr_t *)&g, &glen);
	mca_stripzeros((caddr_t *)&v, &vlen);

	/* Make sure that the key is in the supported range */
	if ((plen < BITS2BYTES(DSA_MIN_KEY_LEN)) ||
	    (plen > BITS2BYTES(DSA_MAX_KEY_LEN))) {
		DBG(NULL, DWARN, "plen(%u) not in range", plen);
		return (CRYPTO_KEY_SIZE_RANGE);
	}

	/*
	 * p must be a whole number of 64-bit quantities, q must be 160 bits.
	 */
	if ((BYTES2BITS(plen) % 64) || (qlen != BITS2BYTES(160))) {
		DBG(NULL, DWARN, "p(%u) or q(%u) lengths incorrect",
		    plen, qlen);
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}

	if (class == CPGO_PRIVATE_KEY) {
		/* a private key value v must be numerically smaller than q */
		if (mca_numcmp((caddr_t)v, vlen, (caddr_t)q, qlen) > 0) {
			DBG(NULL, DWARN, "private DSA value v > q!");
			return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
		}
	} else {
		/* a public key value v must be numerically smaller than p */
		if (mca_numcmp((caddr_t)v, vlen, (caddr_t)p, plen) > 0) {
			DBG(NULL, DWARN, "public DSA value v > p!");
			return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
		}
	}
	if (mca_numcmp((caddr_t)g, glen, (caddr_t)p, plen) > 0) {
		DBG(NULL, DWARN, "base DSA value g > p!");
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}

	/* write out p, q, g, and the value. */
	PUTBUF32(&dsahead->plen, plen);
	PUTBUF32(&dsahead->glen, glen);
	PUTBUF32(&dsahead->vlen, vlen);
	buf += PAD32(sizeof (dsa_head_t));

	bcopy(q, buf, qlen);
	buf += PAD32(qlen);

	bcopy(p, buf, plen);
	buf += PAD32(plen);

	bcopy(g, buf, glen);
	buf += PAD32(glen);

	bcopy(v, buf, vlen);
	buf += PAD32(vlen);

	return (CRYPTO_SUCCESS);
}

static int
cpgattr2dsapublic(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen)
{
	return (cpgattr2dsakey(attr, buf, buflen, CPGO_PUBLIC_KEY));
}

static int
cpgattr2dsaprivate(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen)
{
	return (cpgattr2dsakey(attr, buf, buflen, CPGO_PRIVATE_KEY));
}


static int
cpgattr2rsapublic(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen)
{
	uint32_t	mbits, mlen, elen;
	uint8_t		*m, *e;
	size_t		sz;
	pubrsa_head_t	*rsahead;

	if (cpg_attr_lookup_uint8_array(attr, CPGA_MODULUS,
	    &m, &mlen)) {
		DBG(NULL, DWARN, "RSA public key modulus missing");
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	if (cpg_attr_lookup_uint8_array(attr, CPGA_PUBLIC_EXPONENT,
	    &e, &elen)) {
		DBG(NULL, DWARN, "RSA public exponent missing");
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	sz = sizeof (pubrsa_head_t) + PAD32(mlen) + PAD32(elen);
	if (sz > *buflen) {
		*buflen = sz;

		/* not sure about the error, but the object is too large */
		DBG(NULL, DCHATTY, "rsa public key is too large!");
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = sz;

	/* calculate modulus bits */
	mbits = mca_bitlen((caddr_t)m, mlen);

	/* if key is not in the supported range, return an error */
	if ((mbits < RSA_MIN_KEY_LEN) || (mbits > RSA_MAX_KEY_LEN)) {
		DBG(NULL, DWARN, "mbits(%u) not in range", mbits);
		return (CRYPTO_KEY_SIZE_RANGE);
	}

	mca_stripzeros((caddr_t *)&m, &mlen);
	mca_stripzeros((caddr_t *)&e, &elen);

	DBG(NULL, DBRINGUP, "m (%d) is %p", mlen, (void *)m);
	DBG(NULL, DBRINGUP, "e (%d) is %p", elen, (void *)e);

	rsahead = (pubrsa_head_t *)buf;
	buf += PAD32(sizeof (pubrsa_head_t));

	/* write out the value, mbits, modulus, exponent */
	PUTBUF32(&rsahead->modbits, mbits);
	PUTBUF32(&rsahead->modlen, mlen);
	PUTBUF32(&rsahead->pubexplen, elen);

	bcopy(m, buf, mlen);
	buf += PAD32(mlen);

	bcopy(e, buf, elen);
	buf += PAD32(elen);

	return (CRYPTO_SUCCESS);
}


static int
cpgattr2rsaprivate(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen)
{
	prirsa_head_t	*rsahead;
	uint32_t	mbits;
	uint32_t	mlen = 0, dlen = 0;
	uint32_t	elen = 0, plen = 0, qlen = 0;
	uint32_t	dplen = 0, dqlen = 0, qinvlen = 0;
	uint8_t		*m, *d, *e, *p, *q, *dp, *dq, *qinv;
	size_t		sz;

	if (cpg_attr_lookup_uint8_array(attr, CPGA_MODULUS, &m, &mlen)) {
		DBG(NULL, DWARN, "RSA private modulus missing");
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}
	/* calculate modulus bits */
	mbits = mca_bitlen((caddr_t)m, mlen);

	/* if key is not in the supported range, return an error */
	if ((mbits < RSA_MIN_KEY_LEN) || (mbits > RSA_MAX_KEY_LEN)) {
		DBG(NULL, DWARN, "mbits(%u) not in range", mbits);
		return (CRYPTO_KEY_SIZE_RANGE);
	}

	if (cpg_attr_lookup_uint8_array(attr, CPGA_PRIVATE_EXPONENT,
	    &d, &dlen)) {
		uint8_t sensitive = 0;
		if (cpg_attr_lookup_uint8(attr, CPGA_SENSITIVE, &sensitive) !=
		    CRYPTO_SUCCESS) {
			DBG(NULL, DWARN,
			    "cpgattr2rsaprivate: CPGA_SENSITIVE not set");
			return (CRYPTO_GENERAL_ERROR);
		}
		if (!sensitive) {
			/* nonsensitive key requires PrivateExpo */
			DBG(NULL, DWARN, "RSA private expo missing");
			return (CRYPTO_TEMPLATE_INCOMPLETE);
		}
	}

	/* following fields are optional */
	(void) cpg_attr_lookup_uint8_array(attr, CPGA_PUBLIC_EXPONENT,
	    &e, &elen);
	(void) cpg_attr_lookup_uint8_array(attr, CPGA_PRIME_1,
	    &p, &plen);
	(void) cpg_attr_lookup_uint8_array(attr, CPGA_PRIME_2,
	    &q, &qlen);
	(void) cpg_attr_lookup_uint8_array(attr, CPGA_EXPONENT_1,
	    &dp, &dplen);
	(void) cpg_attr_lookup_uint8_array(attr, CPGA_EXPONENT_2,
	    &dq, &dqlen);
	(void) cpg_attr_lookup_uint8_array(attr, CPGA_COEFFICIENT,
	    &qinv, &qinvlen);

	sz = PAD32(sizeof (prirsa_head_t)) + PAD32(mlen) + PAD32(elen) +
	    PAD32(dlen) + PAD32(plen) + PAD32(qlen) + PAD32(dplen) +
	    PAD32(dqlen) + PAD32(qinvlen);
	if (sz > *buflen) {
		*buflen = sz;
		/* not sure about the error, but the object is too large */
		DBG(NULL, DCHATTY, "rsa private key is too large!");
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = sz;

	mca_stripzeros((caddr_t *)&m, &mlen);
	mca_stripzeros((caddr_t *)&e, &elen);
	mca_stripzeros((caddr_t *)&p, &plen);
	mca_stripzeros((caddr_t *)&q, &qlen);
	mca_stripzeros((caddr_t *)&dp, &dplen);
	mca_stripzeros((caddr_t *)&dq, &dqlen);
	mca_stripzeros((caddr_t *)&qinv, &qinvlen);

	if ((mca_numcmp((caddr_t)d, dlen, (caddr_t)m, mlen) > 0) ||
	    (mca_numcmp((caddr_t)p, plen, (caddr_t)m, mlen) > 0) ||
	    (mca_numcmp((caddr_t)q, qlen, (caddr_t)m, mlen) > 0)) {
		/* numeric values out of range */
		DBG(NULL, DWARN, "RSA d, p, or q out of range");
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}
	if (plen) {
		if ((mca_numcmp((caddr_t)dp, dplen,
		    (caddr_t)p, plen) > 0) ||
		    (mca_numcmp((caddr_t)qinv, qinvlen,
			(caddr_t)p, plen)) > 0) {
			DBG(NULL, DWARN, "RSA dp/qinv out of range");
			return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
		}
	}
	if (qlen) {
		if (mca_numcmp((caddr_t)dq, dqlen,
		    (caddr_t)q, qlen) > 0) {
			DBG(NULL, DWARN, "RSA dq out of range");
			return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
		}
	}

	/* write out the attr */
	rsahead = (prirsa_head_t *)buf;
	buf += PAD32(sizeof (prirsa_head_t));

	/* write out the value, mbits, modulus, exponents, primes, etc. */
	PUTBUF32(&rsahead->modbits, mbits);
	PUTBUF32(&rsahead->modlen, mlen);
	PUTBUF32(&rsahead->pubexplen, elen);
	PUTBUF32(&rsahead->privexplen, dlen);
	PUTBUF32(&rsahead->plen, plen);
	PUTBUF32(&rsahead->qlen, qlen);
	PUTBUF32(&rsahead->dplen, dplen);
	PUTBUF32(&rsahead->dqlen, dqlen);
	PUTBUF32(&rsahead->qinvlen, qinvlen);

	bcopy(m, buf, mlen);
	buf += PAD32(mlen);

	bcopy(e, buf, elen);
	buf += PAD32(elen);

	bcopy(d, buf, dlen);
	buf += PAD32(dlen);

	bcopy(p, buf, plen);
	buf += PAD32(plen);

	bcopy(q, buf, qlen);
	buf += PAD32(qlen);

	bcopy(dp, buf, dplen);
	buf += PAD32(dplen);

	bcopy(dq, buf, dqlen);
	buf += PAD32(dqlen);

	bcopy(qinv, buf, qinvlen);
	buf += PAD32(qinvlen);

	return (CRYPTO_SUCCESS);
}

/*
 * If the key is sensitive, delete the sensitive key fields from the attr.
 * The attr will be sanitized and defragmented.
 */
int
mca_delete_sensitive_key_value(cpg_attr_t *attr)
{
	uint8_t		sensitive = 0;

	(void) cpg_attr_lookup_uint8(attr, CPGA_SENSITIVE, &sensitive);
	if (!sensitive) {
		return (CRYPTO_SUCCESS);
	}

	/* cleanup the deleted fields */
	return (cpg_attr_filter(attr, CPG_ATTR_SANITIZE | CPG_ATTR_NOSLEEP));
}


/*
 * If the key is non-sensitive, add the sensitive key fields to the attr.
 * This function is used in mca_parse_key().
 */
int
mca_add_key_value(mca_key_head_t *keyhead, cpg_attr_t *attr)
{
	uint32_t	keytype;
	uint32_t	class;
	uint8_t		sensitive = 0, add_value_len = FALSE;
	uint8_t		*buf;
	uint32_t	buflen;
	int		rv;

	if (cpg_attr_lookup_uint32(attr, CPGA_CLASS, &class)) {
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	keytype = (uint32_t)-1;
	(void) cpg_attr_lookup_uint32(attr, CPGA_KEY_TYPE, &keytype);

	/*
	 * If the key is a sensitive key, key value should not be in
	 * the template except for RSA key. If the key is RSA key,
	 * non-sensitive fields (Modulus, PubExpo) should be in the
	 * template.
	 */
	if (cpg_attr_lookup_uint8(attr, CPGA_SENSITIVE, &sensitive) !=
	    CRYPTO_SUCCESS) {
		DBG(NULL, DWARN,
		    "mca_add_key_value: CPGA_SENSITIVE not supplied");
		return (CRYPTO_GENERAL_ERROR);
	}

	buf = (uint8_t *)(keyhead + 1) + PAD32(GETBUF32(&keyhead->descrlen));
	buflen = GETBUF32(&keyhead->valuelen);

	if (buflen == 0) {
		/*
		 * If valuelen is 0, it must be a key creation operation.
		 * The actual key values should be in the template already.
		 */
		return (CRYPTO_SUCCESS);
	}

	switch (class) {
	case CPGO_SECRET_KEY:
		if (sensitive) {
			/* sensitive attribute should not be added */
			return (CRYPTO_SUCCESS);
		}
		switch (keytype) {
		case CPGK_DES:
			if (buflen != 8) {
				DBG(NULL, DWARN,
				    "mca_add_key_value: buffer length %d, "
				    "want 8", buflen);
				if (buflen > 8) {
					/*
					 * Workaround for fw reporting invalid
					 * valuelen. FW was not changed to
					 * avoid FIPs process delay.
					 */
					buflen = 8;
				} else {
					DBG(NULL, DWARN,
					    "mca_add_key_value: adding DES "
					    "key: buffersize=%d should be 8",
					    buflen);
					return (CRYPTO_GENERAL_ERROR);
				}
			}
			break;
		case CPGK_DES2:
			if (buflen != 16) {
				DBG(NULL, DWARN,
				    "mca_add_key_value: buffer length %d, "
				    "want 16", buflen);
				if (buflen > 16) {
					/*
					 * Workaround for fw reporting invalid
					 * valuelen. FW was not changed to
					 * avoid FIPs process delay.
					 */
					buflen = 16;
				} else {
					DBG(NULL, DWARN,
					    "mca_add_key_value: adding DES2 "
					    "key: buffersize=%d, should be 16",
					    buflen);
					return (CRYPTO_GENERAL_ERROR);
				}
			}
			break;
		case CPGK_DES3:
			if (buflen != 24) {
				DBG(NULL, DWARN,
				    "mca_add_key_value: buffer length %d, "
				    "want 24", buflen);
				if (buflen > 24) {
					/*
					 * Workaround for fw reporting invalid
					 * valuelen. FW was not changed to
					 * avoid FIPs process delay.
					 */
					buflen = 24;
				} else {
					DBG(NULL, DWARN,
					    "mca_add_key_value: adding DES3 "
					    "key: buffersize=%d, need 24",
					    buflen);

					return (CRYPTO_GENERAL_ERROR);
				}
			}
			break;
		case CPGK_AES:
		{
			mca_aes_keyhead_t *aeshead = (mca_aes_keyhead_t *)buf;
			buflen = GETBUF32(&aeshead->keysz);
			if ((buflen != 16) && (buflen != 24) &&
			    (buflen != 32)) {
				DBG(NULL, DWARN,
				    "mca_add_key_value: buffer length %d, "
				    "want 16, 24, or 32", buflen);
				/*
				 * When FW reports an invalid valuelen,
				 * 'buflen' is set to the closest valid
				 * valuelen. FW was not changed to avoid
				 * FIPs process delay.
				 */
				if (buflen > 32) {
					buflen = 32;
				} else if (buflen > 24) {
					buflen = 24;
				} else if (buflen > 16) {
					buflen = 16;
				} else {
					DBG(NULL, DWARN,
					    "mca_add_key_value: adding AES "
					    "key: buffersize=%d, should be 16, "
					    "24, or 32", buflen);
					return (CRYPTO_GENERAL_ERROR);
				}
			}
			buf = (uint8_t *)(aeshead + 1);
			add_value_len = TRUE;
			break;
		}
		case CPGK_RC2:
		{
			mca_rc2_keyhead_t *rc2head = (mca_rc2_keyhead_t *)buf;
			buflen = GETBUF32(&rc2head->keysz);
			if ((buflen > 128) || (buflen < 1)) {
				DBG(NULL, DWARN,
				    "mca_add_key_value: buffer length %d, "
				    "want between 1 and 128 (inclusive)",
				    buflen);
				/*
				 * When FW reports an invalid valuelen,
				 * 'buflen' is set to the closest valid
				 * valuelen. FW was not changed to avoid
				 * FIPs process delay.
				 */
				if (buflen > 128) {
					buflen = 128;
				} else {
					DBG(NULL, DWARN,
					    "mca_add_key_value: adding RC2 "
					    "key: buffersize=%d, should be "
					    "1..128", buflen);

					return (CRYPTO_GENERAL_ERROR);
				}
			}
			buf = (uint8_t *)(rc2head + 1);
			add_value_len = TRUE;
			break;
		}
#ifdef FINSVCS
		case CPGK_FS:
#endif /* FINSVCS */
		case CPGK_GENERIC_SECRET:
		case CPGK_RC4:
			/* no key length constraints */
			add_value_len = TRUE;
			break;
		default:
			return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
		}
		if (add_value_len == TRUE) {
			rv = cpg_attr_add_uint32(attr, CPGA_VALUE_LEN,
			    buflen, 0);
			if (rv != CRYPTO_SUCCESS) {
				return (rv);
			}
		}
		return (cpg_attr_add_uint8_array(attr, CPGA_VALUE,
		    buf, buflen, 0));
	case CPGO_PRIVATE_KEY:
		switch (keytype) {
		case CPGK_RSA:
		{
			prirsa_head_t	*rsahead = (prirsa_head_t *)buf;

			buf = (uint8_t *)(rsahead + 1) +
			    PAD32(GETBUF32(&rsahead->modlen)) +
			    PAD32(GETBUF32(&rsahead->pubexplen));
			buflen = GETBUF32(&rsahead->privexplen);

			buf = (uint8_t *)(rsahead + 1);
			buflen = GETBUF32(&rsahead->modlen);
			rv = cpg_attr_add_uint8_array(attr, CPGA_MODULUS,
			    buf, buflen, 0);
			if (rv != CRYPTO_SUCCESS) {
				return (rv);
			}

			buf += PAD32(buflen);
			buflen = GETBUF32(&rsahead->pubexplen);
			if (buflen != 0) {
				rv = cpg_attr_add_uint8_array(attr,
				    CPGA_PUBLIC_EXPONENT, buf, buflen, 0);
				if (rv != CRYPTO_SUCCESS) {
					return (rv);
				}
			}

			/*
			 * if the key is sensitive, the following values won't
			 * exist in the key_head, and should not be added
			 * to the template.
			 */
			if (sensitive) {
				return (CRYPTO_SUCCESS);
			}

			buf += PAD32(buflen);
			buflen = GETBUF32(&rsahead->privexplen);
			rv = cpg_attr_add_uint8_array(attr,
			    CPGA_PRIVATE_EXPONENT, buf, buflen, 0);
			if (rv != CRYPTO_SUCCESS) {
				return (rv);
			}

			buf += PAD32(buflen);
			buflen = GETBUF32(&rsahead->plen);
			if (buflen != 0) {
				rv = cpg_attr_add_uint8_array(attr,
				    CPGA_PRIME_1, buf, buflen, 0);
				if (rv != CRYPTO_SUCCESS) {
					return (rv);
				}
			}

			buf += PAD32(buflen);
			buflen = GETBUF32(&rsahead->qlen);
			if (buflen != 0) {
				rv = cpg_attr_add_uint8_array(attr,
				    CPGA_PRIME_2, buf, buflen, 0);
				if (rv != CRYPTO_SUCCESS) {
					return (rv);
				}
			}

			buf += PAD32(buflen);
			buflen = GETBUF32(&rsahead->dplen);
			if (buflen != 0) {
				rv = cpg_attr_add_uint8_array(attr,
				    CPGA_EXPONENT_1, buf, buflen, 0);
				if (rv != CRYPTO_SUCCESS) {
					return (rv);
				}
			}

			buf += PAD32(buflen);
			buflen = GETBUF32(&rsahead->dqlen);
			if (buflen != 0) {
				rv = cpg_attr_add_uint8_array(attr,
				    CPGA_EXPONENT_2, buf, buflen, 0);
				if (rv != CRYPTO_SUCCESS) {
					return (rv);
				}
			}

			buf += PAD32(buflen);
			buflen = GETBUF32(&rsahead->qinvlen);
			if (buflen != 0) {
				return (cpg_attr_add_uint8_array(attr,
				    CPGA_COEFFICIENT, buf, buflen, 0));
			}
			break;
		}
		case CPGK_DSA:
		{
			dsa_head_t *dsahead = (dsa_head_t *)buf;

			if (sensitive) {
				/* sensitive attribute should not be added */
				return (CRYPTO_SUCCESS);
			}

			buf = (uint8_t *)(dsahead + 1) + PAD32(20) +
			    PAD32(GETBUF32(&dsahead->plen)) +
			    PAD32(GETBUF32(&dsahead->glen));
			buflen = GETBUF32(&dsahead->vlen);

			return (cpg_attr_add_uint8_array(attr, CPGA_VALUE,
			    buf, buflen, 0));
		}
		case CPGK_EC:
		{
			priec_head_t	*echead = (priec_head_t *)buf;
			int		oidlen;

			if (echead->ec_oid[0] != OID_TAG) {
				/* mal-formed oid */
				return (CRYPTO_FAILED);
			}
			oidlen = echead->ec_oid[1];
			if ((oidlen < 0) || (oidlen > (MAX_EC_OID_LEN - 2))) {
				/* invalid oid */
				return (CRYPTO_FAILED);
			}
			rv = cpg_attr_add_uint8_array(attr,
			    CPGA_EC_PARAMS, echead->ec_oid, oidlen + 2, 0);
			if (rv != CRYPTO_SUCCESS) {
				return (rv);
			}

			if (sensitive) {
				/* sensitive attribute should not be added */
				return (CRYPTO_SUCCESS);
			}

			buf = (uint8_t *)(echead + 1);
			buflen = GETBUF32(&echead->dlen);
			return (cpg_attr_add_uint8_array(attr, CPGA_VALUE,
			    buf, buflen, 0));
		}
		case CPGK_DH:
		{
			pridh_head_t *dhhead = (pridh_head_t *)buf;

			if (sensitive) {
				/* sensitive attribute should not be added */
				return (CRYPTO_SUCCESS);
			}

			buf = (uint8_t *)(dhhead + 1) +
			    PAD32(GETBUF32(&dhhead->plen)) +
			    PAD32(GETBUF32(&dhhead->glen));
			buflen = GETBUF32(&dhhead->vlen);

			return (cpg_attr_add_uint8_array(attr, CPGA_VALUE,
			    buf, buflen, 0));
		}
		default:
			/* RSA/DSA/DH are the only supported private keys */
			return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
		}
		break;
	case CPGO_PUBLIC_KEY:
		switch (keytype) {
		case CPGK_RSA:
		{
			pubrsa_head_t	*rsahead = (pubrsa_head_t *)buf;

			buf = (uint8_t *)(rsahead + 1);
			buflen = GETBUF32(&rsahead->modlen);
			return (cpg_attr_add_uint8_array(attr, CPGA_MODULUS,
			    buf, buflen, 0));
		}
		case CPGK_DSA:
		{
			dsa_head_t *dsahead = (dsa_head_t *)buf;

			buf = (uint8_t *)(dsahead + 1) + PAD32(20) +
			    PAD32(GETBUF32(&dsahead->plen)) +
			    PAD32(GETBUF32(&dsahead->glen));
			buflen = GETBUF32(&dsahead->vlen);

			return (cpg_attr_add_uint8_array(attr, CPGA_VALUE,
			    buf, buflen, 0));
		}
		case CPGK_EC:
		{
			pubec_head_t	*echead = (pubec_head_t *)buf;
			uint32_t	xlen, ylen;
			uchar_t tmpbuf[1 + 2 * BITS2BYTES(EC_MAX_KEY_LEN)];

			/* check the validity of xlen and ylen */
			xlen = GETBUF32(&echead->xlen);
			ylen = GETBUF32(&echead->ylen);
			if (xlen != ylen) {
				return (CRYPTO_DEVICE_ERROR);
			}
			if (xlen > BITS2BYTES(EC_MAX_KEY_LEN)) {
				return (CRYPTO_DEVICE_ERROR);
			}

			/*
			 * Concatenate x and y.  ECPoint is 0x4|X|Y.
			 */
			buflen = xlen + ylen + 1;
			tmpbuf[0] = 0x04;
			buf = (uint8_t *)(echead + 1);
			bcopy(buf, tmpbuf + 1, xlen);
			buf += PAD32(xlen);
			bcopy(buf, tmpbuf + xlen + 1, ylen);

			return (cpg_attr_add_uint8_array(attr, CPGA_EC_POINT,
			    tmpbuf, buflen, 0));
		}
		case CPGK_DH:
		{
			pubdh_head_t *dhhead = (pubdh_head_t *)buf;

			buf = (uint8_t *)(dhhead + 1) +
			    PAD32(GETBUF32(&dhhead->plen)) +
			    PAD32(GETBUF32(&dhhead->glen));
			buflen = GETBUF32(&dhhead->vlen);

			return (cpg_attr_add_uint8_array(attr, CPGA_VALUE,
			    buf, buflen, 0));
		}
		default:
			return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
		}
	} /* switch class */

	return (CRYPTO_SUCCESS);
}


/*
 * This functions fills the key type, description if token, and value field
 * Note that the sensitive key fields will be stripped out of the
 * attr if the key is sensitive.
 */
int
cpgattr2keyhead(cpg_attr_t *attr, int keytype, caddr_t buf, uint32_t *buflen)
{
	mca_key_head_t	*keyhead = (mca_key_head_t *)buf;
	uint32_t	len, descrlen;
	int		rv;
	uint8_t		token = 0;

	if (buf != NULL) {
		PUTBUF32(&keyhead->keytype, keytype);
		PUTBUF32(&keyhead->cardid, 0);
		PUTBUF32(&keyhead->objectid, 0);
		PUTBUF32(&keyhead->envelopelen, 0);
		buf += sizeof (mca_key_head_t);
		len = *buflen - sizeof (mca_key_head_t);
	} else {
		len = 0;
	}

	/*
	 * If the key is a token key, add the description field
	 */
	(void) cpg_attr_lookup_uint8(attr, CPGA_TOKEN, &token);
	if (token) {
		cpg_attr_data_t	*datap;
		uint8_t		sensitive;

		/*
		 * This code path is only exercised for persistent key
		 * creation.  Therefore, the performance of this path
		 * is not critical.  The CPG_ATTR_SANITIZE flag
		 * sanitizes entries that are are marked sensitive.
		 */
		(void) cpg_attr_lookup_uint8(attr, CPGA_SENSITIVE, &sensitive);

		rv = cpg_attr_store_data(attr, &datap, &descrlen,
		    CPG_ATTR_NATIVE_ENDIAN |
		    (sensitive ? CPG_ATTR_SANITIZE : 0) |
		    CPG_ATTR_NOSLEEP);
		if (rv != CRYPTO_SUCCESS) {
			return (rv);
		}

		if (buf != NULL) {
			if (descrlen > len) {
				DBG(NULL, DWARN, "cpgattr2keyhead: "
				    "descrlen[%d] > len[%d]", descrlen, len);
				return (CRYPTO_BUFFER_TOO_SMALL);
			}
			PUTBUF32(&keyhead->descrlen, descrlen);
			bcopy(datap, buf, descrlen);
			buf += PAD32(descrlen);
			len -= PAD32(descrlen);
		}

		kmem_free(datap, descrlen);
	} else {
		if (buf != NULL) {
			PUTBUF32(&keyhead->descrlen, 0);
		}
		descrlen = 0;
	}

	switch (keytype) {
	case KEYTYPE_DES:
	case KEYTYPE_DES2:
	case KEYTYPE_DES3:
		rv = cpgattr2des(attr, keytype, buf, &len);
		break;
	case KEYTYPE_RC2:
		rv = cpgattr2rc2(attr, buf, &len);
		break;
	case KEYTYPE_AES:
		rv = cpgattr2aes(attr, buf, &len);
		break;
	case KEYTYPE_GENERIC_SECRET:
	case KEYTYPE_RC4:
		rv = cpgattr2genericsecret(attr, buf, &len);
		break;
	case KEYTYPE_RSA_PUBLIC:
		rv = cpgattr2rsapublic(attr, buf, &len);
		break;
	case KEYTYPE_RSA_PRIVATE:
		rv = cpgattr2rsaprivate(attr, buf, &len);
		break;
	case KEYTYPE_DSA_PUBLIC:
		rv = cpgattr2dsapublic(attr, buf, &len);
		break;
	case KEYTYPE_DSA_PRIVATE:
		rv = cpgattr2dsaprivate(attr, buf, &len);
		break;
#ifdef FINSVCS
	case KEYTYPE_FS:
		rv = cpgattr2fs(attr, keytype, buf, &len);
		break;
#endif /* FINSVCS */
	case KEYTYPE_EC_PUBLIC:
		rv = cpgattr2ecpublic(attr, buf, &len);
		break;
	case KEYTYPE_EC_PRIVATE:
		rv = cpgattr2ecprivate(attr, buf, &len);
		break;
	case KEYTYPE_DH_PUBLIC:
		rv = cpgattr2dhpublic(attr, buf, &len);
		break;
	case KEYTYPE_DH_PRIVATE:
		rv = cpgattr2dhprivate(attr, buf, &len);
		break;
	case KEYTYPE_NOKEY:
		/* other objects do not have key field */
		len = 0;
		rv = CRYPTO_SUCCESS;
		break;
	default:
		/* unsupported object type */
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}

	if ((rv == CRYPTO_SUCCESS) || (rv == CRYPTO_BUFFER_TOO_SMALL)) {
		*buflen = sizeof (mca_key_head_t) + descrlen + len;
		if (keyhead) {
			PUTBUF32(&keyhead->valuelen, len);
		}
	}

	return (rv);
}

/*
 * This functions fills the key type and value field
 * Note that the sensitive key fields will be stripped out of the
 * attr if the key is sensitive.
 */
int
cpgattr2keyhead4unwrap(cpg_attr_t *attr, int keytype,
    caddr_t buf, uint32_t *buflen)
{
	mca_key_head_t	*keyhead = (mca_key_head_t *)buf;
	cpg_attr_data_t	*datap;
	unsigned	datasz;
	uint32_t	len;
	uint8_t		istoken = 0;
	int		rv = CRYPTO_SUCCESS;

	if (buf != NULL) {
		PUTBUF32(&keyhead->keytype, keytype);
		PUTBUF32(&keyhead->cardid, 0);
		PUTBUF32(&keyhead->objectid, 0);
		PUTBUF32(&keyhead->envelopelen, 0);
		PUTBUF32(&keyhead->valuelen, 0);
		buf += sizeof (mca_key_head_t);
		len = *buflen - sizeof (mca_key_head_t);
	} else {
		len = 0;
	}

	/*
	 * Add description for persistent key. Assume that the template for
	 * keygen does not contain sensitive key value.
	 */
	(void) cpg_attr_lookup_uint8(attr, CPGA_TOKEN, &istoken);
	datasz = 0;
	if (istoken) {
		cpg_attr_ref_data(attr, &datap, &datasz);
		if (len < datasz) {
			rv = CRYPTO_BUFFER_TOO_SMALL;
		} else {
			if (buf != NULL) {
				bcopy((caddr_t)datap, buf, datasz);
			}
		}
	}
	if (buf != NULL) {
		PUTBUF32(&keyhead->descrlen, datasz);
	}

	/*
	 * No key value and envelope for unwrap
	 */

	*buflen = sizeof (mca_key_head_t) + datasz;

	return (rv);
}


/*
 * This function fills the 'keysz' field of the aes keyhead structure.
 */
static int
cpgattr2aes4keygen(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen)
{
	uint32_t		valsz;
	mca_aes_keyhead_t	*aeskeyhead = (mca_aes_keyhead_t *)buf;

	if (*buflen < sizeof (mca_aes_keyhead_t)) {
		*buflen = sizeof (mca_aes_keyhead_t);
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}

	if (cpg_attr_lookup_uint32(attr, CPGA_VALUE_LEN, &valsz)) {
		DBG(NULL, DCHATTY, "cpgattr2aes: VALUE_LEN missing");
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}
	switch (valsz) {
	case 16:
	case 24:
	case 32:
		break;
	default:
		DBG(NULL, DWARN, "aes:value length mismatch (got %u)", valsz);
		return (CRYPTO_KEY_SIZE_RANGE);
	}

	*buflen = sizeof (mca_aes_keyhead_t);
	PUTBUF32(&aeskeyhead->keysz, valsz);

	return (CRYPTO_SUCCESS);
}


static int
cpgattr2dsa4keygen(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen)
{
	uint8_t		*p, *q, *g;
	unsigned	plen = 0, qlen = 0, glen = 0;
	size_t		sz;
	dsa_head_t	*dsahead = (dsa_head_t *)buf;

	if (cpg_attr_lookup_uint8_array(attr, CPGA_PRIME, &p, &plen) ||
	    cpg_attr_lookup_uint8_array(attr, CPGA_SUBPRIME, &q, &qlen) ||
	    cpg_attr_lookup_uint8_array(attr, CPGA_BASE, &g, &glen)) {
		/*
		 * all operations other than unwrap requires
		 * these field to exist in the attr
		 */
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	sz = sizeof (dsa_head_t) + PAD32(plen) + PAD32(qlen) + PAD32(glen);
	if (sz > *buflen) {
		*buflen = sz;
		DBG(NULL, DCHATTY, "dsa key is too large! sz = %d", sz);
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = sz;

	mca_stripzeros((caddr_t *)&p, &plen);
	mca_stripzeros((caddr_t *)&q, &qlen);
	mca_stripzeros((caddr_t *)&g, &glen);

	/* Make sure that the key is in the supported range */
	if ((plen < BITS2BYTES(DSA_MIN_KEY_LEN)) ||
	    (plen > BITS2BYTES(DSA_MAX_KEY_LEN))) {
		DBG(NULL, DWARN, "plen(%u) not in range", plen);
		return (CRYPTO_KEY_SIZE_RANGE);
	}

	/*
	 * p must be a whole number of 64-bit quantities, q must be 160 bits.
	 */
	if ((BYTES2BITS(plen) % 64) || (qlen != BITS2BYTES(160))) {
		DBG(NULL, DWARN, "p(%u) or q(%u) lengths incorrect",
		    plen, qlen);
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}

	if (mca_numcmp((caddr_t)g, glen, (caddr_t)p, plen) > 0) {
		DBG(NULL, DWARN, "base DSA value g > p!");
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}

	/* write out p, q, g, and the value. */
	PUTBUF32(&dsahead->plen, plen);
	PUTBUF32(&dsahead->glen, glen);
	PUTBUF32(&dsahead->vlen, 0);
	buf += PAD32(sizeof (dsa_head_t));

	bcopy(q, buf, qlen);
	buf += PAD32(qlen);

	bcopy(p, buf, plen);
	buf += PAD32(plen);

	bcopy(g, buf, glen);
	buf += PAD32(glen);

	return (CRYPTO_SUCCESS);
}

static int
cpgattr2rsa4keygen(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen)
{
	uint32_t	mbits, elen;
	uint8_t		*e;
	size_t		sz;
	pubrsa_head_t	*rsahead;

	/* if the modulus is missing, lookup the modulus bits */
	if (cpg_attr_lookup_uint32(attr, CPGA_MODULUS_BITS, &mbits)) {
		DBG(NULL, DWARN, "RSA public key modulus bits missing");
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	if (cpg_attr_lookup_uint8_array(attr, CPGA_PUBLIC_EXPONENT,
	    &e, &elen)) {
		DBG(NULL, DWARN, "RSA public exponent missing");
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	sz = sizeof (pubrsa_head_t) + PAD32(elen);
	if (sz > *buflen) {
		*buflen = sz;

		/* not sure about the error, but the object is too large */
		DBG(NULL, DCHATTY, "rsa public key is too large!");
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = sz;

	/* if key is not in the supported range, return an error */
	if ((mbits < RSA_MIN_KEY_LEN) || (mbits > RSA_MAX_KEY_LEN)) {
		DBG(NULL, DWARN, "mbits(%u) not in range", mbits);
		return (CRYPTO_KEY_SIZE_RANGE);
	}

	mca_stripzeros((caddr_t *)&e, &elen);
	DBG(NULL, DBRINGUP, "e (%d) is %p", elen, (void *)e);

	rsahead = (pubrsa_head_t *)buf;
	buf += PAD32(sizeof (pubrsa_head_t));

	/* write out the value, mbits, modulus, exponent */
	PUTBUF32(&rsahead->modbits, mbits);
	PUTBUF32(&rsahead->modlen, 0);
	PUTBUF32(&rsahead->pubexplen, elen);

	bcopy(e, buf, elen);
	buf += PAD32(elen);

	return (CRYPTO_SUCCESS);
}


static int
cpgattr2ec4keygen(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen)
{
	uint8_t		*ecparam;
	uint32_t	paramlen;
	pubec_head_t	*echead = (pubec_head_t *)buf;

	if (cpg_attr_lookup_uint8_array(attr, CPGA_EC_PARAMS,
	    &ecparam, &paramlen)) {
		/* CPGA_EC_PARAMS is necessary for public key gen */
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	if (paramlen > MAX_EC_OID_LEN) {
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}
	if (*buflen < sizeof (pubec_head_t)) {
		*buflen = sizeof (pubec_head_t);
		DBG(NULL, DCHATTY, "ec key is too large!");
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = sizeof (pubec_head_t);

	/* write out xlen and ylen */
	bcopy(ecparam, echead->ec_oid, paramlen);
	PUTBUF32(&echead->xlen, 0);
	PUTBUF32(&echead->ylen, 0);

	return (CRYPTO_SUCCESS);
}

static int
cpgattr2dh4keygen(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen)
{
	uint8_t		*p, *g;
	unsigned	plen = 0, glen = 0;
	size_t		sz;
	pubdh_head_t	*dhhead = (pubdh_head_t *)buf;

	if (cpg_attr_lookup_uint8_array(attr, CPGA_PRIME, &p, &plen) ||
	    cpg_attr_lookup_uint8_array(attr, CPGA_BASE, &g, &glen)) {
		/* those fields are required for keygen */
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	sz = sizeof (pubdh_head_t) + PAD32(plen) + PAD32(glen);
	if (sz > *buflen) {
		*buflen = sz;
		DBG(NULL, DCHATTY, "dh key is too large! sz = %d", sz);
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = sz;

	mca_stripzeros((caddr_t *)&p, &plen);
	mca_stripzeros((caddr_t *)&g, &glen);

	/* write out p and g */
	PUTBUF32(&dhhead->plen, plen);
	PUTBUF32(&dhhead->glen, glen);
	PUTBUF32(&dhhead->vlen, 0);
	buf += PAD32(sizeof (pubdh_head_t));

	bcopy(p, buf, plen);
	buf += PAD32(plen);

	bcopy(g, buf, glen);
	buf += PAD32(glen);

	return (CRYPTO_SUCCESS);
}

static int
cpgattr2pridh4keygen(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen)
{
	pridh_head_t	*dhhead = (pridh_head_t *)buf;
	uint32_t	vbits = 0;
	size_t		sz;

	(void) cpg_attr_lookup_uint32(attr, CPGA_VALUE_BITS, &vbits);

	sz = sizeof (pridh_head_t);
	if (sz > *buflen) {
		*buflen = sz;
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = sz;

	/* setup the dh_head */
	PUTBUF32(&dhhead->plen, 0);
	PUTBUF32(&dhhead->glen, 0);
	PUTBUF32(&dhhead->vlen, 0);
	PUTBUF32(&dhhead->vbits, vbits);

	return (CRYPTO_SUCCESS);
}

/*
 * This functions fills the key type and value field
 * Note that the sensitive key fields will be stripped out of the
 * attr if the key is sensitive.
 */
int
cpgattr2keyhead4keygen(cpg_attr_t *attr, int keytype, caddr_t buf,
    uint32_t *buflen)
{
	mca_key_head_t	*keyhead = (mca_key_head_t *)buf;
	uint32_t	len;
	int		rv;
	uint8_t		istoken = 0;
	uint32_t	totallen = sizeof (mca_key_head_t);
	cpg_attr_data_t	*datap;
	unsigned	datasz;

	if (buf != NULL) {
		PUTBUF32(&keyhead->keytype, keytype);
		PUTBUF32(&keyhead->cardid, 0);
		PUTBUF32(&keyhead->objectid, 0);
		PUTBUF32(&keyhead->envelopelen, 0);
		buf += sizeof (mca_key_head_t);
		len = *buflen - sizeof (mca_key_head_t);
	} else {
		len = 0;
	}

	/*
	 * Add description for persistent key. Assume that the template for
	 * keygen does not contain sensitive key value.
	 */
	(void) cpg_attr_lookup_uint8(attr, CPGA_TOKEN, &istoken);
	datasz = 0;
	if (istoken) {
		cpg_attr_ref_data(attr, &datap, &datasz);
		totallen += datasz;
		if (len < datasz) {
			return (CRYPTO_BUFFER_TOO_SMALL);
		} else {
			if (buf != NULL) {
				bcopy((caddr_t)datap, buf, datasz);
			}
		}
	}
	if (buf != NULL) {
		PUTBUF32(&keyhead->descrlen, datasz);
		buf += PAD32(datasz);
	}

	/* add value field */
	len = *buflen - totallen;
	switch (keytype) {
	case KEYTYPE_DES:
	case KEYTYPE_DES2:
	case KEYTYPE_DES3:
	case KEYTYPE_RSA_PRIVATE:
	case KEYTYPE_DSA_PRIVATE:
	case KEYTYPE_EC_PRIVATE:
		len = 0;
		rv = CRYPTO_SUCCESS;
		break;
	case KEYTYPE_GENERIC_SECRET:
	case KEYTYPE_RC4:
		rv = cpg_attr_lookup_uint32(attr, CPGA_VALUE_LEN, &len);
		if (rv != CRYPTO_SUCCESS) {
			len = 0;
			rv = CRYPTO_SUCCESS;
		}
		break;
	case KEYTYPE_AES:
		rv = cpgattr2aes4keygen(attr, buf, &len);
		break;
	case KEYTYPE_RSA_PUBLIC:
		rv = cpgattr2rsa4keygen(attr, buf, &len);
		break;
	case KEYTYPE_DSA_PUBLIC:
		rv = cpgattr2dsa4keygen(attr, buf, &len);
		break;
	case KEYTYPE_EC_PUBLIC:
		rv = cpgattr2ec4keygen(attr, buf, &len);
		break;
	case KEYTYPE_DH_PUBLIC:
		rv = cpgattr2dh4keygen(attr, buf, &len);
		break;
	case KEYTYPE_DH_PRIVATE:
		rv = cpgattr2pridh4keygen(attr, buf, &len);
		break;
	default:
		/* unsupported object type */
		return (CRYPTO_MECHANISM_INVALID);
	}

	if (rv == CRYPTO_SUCCESS) {
		if ((keytype != KEYTYPE_GENERIC_SECRET) &&
		    (keytype != KEYTYPE_RC4)) {
			totallen += len;
		}
		*buflen = totallen;
		PUTBUF32(&keyhead->valuelen, len);
	}

	return (rv);
}

#ifdef FMA_COMPLIANT
/*
 * Post an ereport with an optional message.
 */
void
mca_fm_ereport_post(mca_t *mca, uint64_t ena, uint8_t error_id, char *msg)
{
	char buf[FM_MAX_CLASS];

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", MCA_ERROR_SUBCLASS,
	    mca_fm_class_string(mca, error_id));

	/* Only log ereports if we are ereport capable */
	if (DDI_FM_EREPORT_CAP(mca->fm_capabilities)) {

		/* Check for and log optional error message */
		if (msg != NULL) {
			mca_error(mca, "FMA> %s", msg);
		}

		/* Post FMA ereport */
		ddi_fm_ereport_post(mca->mca_dip, buf, ena,
		    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8,
		    MCA_EREPORT_VERSION, MCA_FMA_INSTANCE, DATA_TYPE_INT32,
		    ddi_get_instance(mca->mca_dip), NULL);
	} else {
		/* Just log an error message if one is provided  */
		if (msg != NULL) {
			mca_error(mca, "FMA> %s", msg);
		} else {
			/* Shouldn't happen, but log ereport class if it does */
			mca_error(mca, "FMA> Error class = %s", buf);
		}
	}
}

static int
mca_chk_ctl_acch(mca_t *mca, ddi_acc_handle_t acch)
{
	/* Check pci configuration register access handle */
	if (mca->mca_pcihandle == acch) {
		mca_error(mca, "Configuration register access error");
		return (DDI_FAILURE);
	} else {
		DBG(mca, DBRINGUP, "Configuration register access handle OK",
		    mca->mca_ctlcmd);
	}

	/* Check pci CSR access handle */
	if (mca->mca_regshandle == acch) {
		mca_error(mca, "CSR access error");
		return (DDI_FAILURE);
	} else {
		DBG(mca, DBRINGUP, "CSR access handle OK",
		    mca->mca_ctlcmd);
	}

	/* Check message log access handle */
	if (mca->mca_log_buff.acch == acch) {
		mca_error(mca, "Message log access error");
		return (DDI_FAILURE);
	} else {
		DBG(mca, DBRINGUP, "Message log access handle OK",
		    mca->mca_ctlcmd);
	}

	/* Check diagnostics access handle */
	if (mca->mca_diag_buff.acch == acch) {
		mca_error(mca, "Diagnostics access error");
		return (DDI_FAILURE);
	} else {
		DBG(mca, DBRINGUP, "Diagnostics access handle OK",
		    mca->mca_ctlcmd);
	}

	/* Check control dma chain access handle */
	if (mca->mca_ctl_chain_buff.acch == acch) {
		mca_error(mca, "Control DMA chain access error");
		return (DDI_FAILURE);
	} else {
		DBG(mca, DBRINGUP, "Control DMA chain access handle OK",
		    mca->mca_ctlcmd);
	}

	/* Check fri dma chain access handle */
	if (mca->mca_fri_chain_buff.acch == acch) {
		mca_error(mca, "FRI DMA chain access error");
		return (DDI_FAILURE);
	} else {
		DBG(mca, DBRINGUP, "FRI DMA chain access handle OK",
		    mca->mca_ctlcmd);
	}

	return (DDI_SUCCESS);
}

int
mca_chk_ctl_dmah(mca_t *mca, ddi_dma_handle_t dmah)
{
	/* Check fri dma handle */
	if (mca->mca_fri_buff.dmah == dmah) {
		mca_error(mca, "FRI DMA error");
		return (DDI_FAILURE);
	} else {
		DBG(mca, DBRINGUP, "FRI DMA handle OK", mca->mca_ctlcmd);
	}

	/* Check control command dma handle */
	if (mca->mca_ctldmah == dmah) {
		mca_error(mca, "Control DMA error for "
		    "cmd = 0x%04x", mca->mca_ctlcmd);
		return (DDI_FAILURE);
	} else {
		DBG(mca, DBRINGUP, "Control DMA handle OK",
		    mca->mca_ctlcmd);
	}

	/* Check message log dma handle */
	if (mca->mca_log_buff.dmah == dmah) {
		mca_error(mca, "Message log DMA error for "
		    "cmd = 0x%04x", mca->mca_ctlcmd);
		return (DDI_FAILURE);
	} else {
		DBG(mca, DBRINGUP, "Message log DMA access handle OK",
		    mca->mca_ctlcmd);
	}

	/* Check diagnostics dma handle */
	if (mca->mca_diag_buff.dmah == dmah) {
		mca_error(mca, "Diagnostics DMA error");
		return (DDI_FAILURE);
	} else {
		DBG(mca, DBRINGUP,
		    "Diagnostics DMA access handle OK",
		    mca->mca_ctlcmd);
	}

	/* Check control dma chain dma handle */
	if (mca->mca_ctl_chain_buff.dmah == dmah) {
		mca_error(mca, "Control DMA chain DMA error");
		return (DDI_FAILURE);
	} else {
		DBG(mca, DBRINGUP, "Control DMA chain DMA access handle OK",
		    mca->mca_ctlcmd);
	}

	/* Check fyi dma chain dma handle */
	if (mca->mca_fri_chain_buff.dmah == dmah) {
		mca_error(mca, "FRI DMA chain DMA error");
		return (DDI_FAILURE);
	} else {
		DBG(mca, DBRINGUP, "FRI DMA chain DMA access handle OK",

		    mca->mca_ctlcmd);
	}

	return (DDI_SUCCESS);
}

static int
mca_chk_ring_acch(mca_ring_t *ring, ddi_acc_handle_t acch, char *string)
{
	int i;

	/* Check ring access handle */
	if (ring->mr_acch == acch) {
		mca_error(ring->mr_mca, "%s ring access error", string);
		return (DDI_FAILURE);
	} else {
		DBG(ring->mr_mca, DBRINGUP,
		    "%s ring access handle OK", string);
	}

	/* Check dma handles in crypto requests */
	for (i = 0; i < ring->mr_nreqs; i++) {

		/* Check key handle */
		if (ring->mr_reqs[i]->mr_key_acch == acch) {
			mca_error(ring->mr_mca,
			    "%s ring key access error for entry %d",
			    string, i);
			return (DDI_FAILURE);
		}

		/* Check input buffer handle */
		if (ring->mr_reqs[i]->mr_ibuf_acch == acch) {
			mca_error(ring->mr_mca,
			    "%s ring input access error for entry %d",
			    string, i);
			return (DDI_FAILURE);
		}

		/* Check output buffer handle */
		if (ring->mr_reqs[i]->mr_obuf_acch == acch) {
			mca_error(ring->mr_mca,
			    "%s ring output access error for entry %d",
			    string, i);
			return (DDI_FAILURE);
		}
	}
	DBG(ring->mr_mca, DBRINGUP,
	    "%s ring request access handles OK", string);

	return (DDI_SUCCESS);
}

static int
mca_chk_ring_dmah(mca_ring_t *ring, ddi_dma_handle_t dmah, char *string)
{
	int i;

	/* Check ring dma handle */
	if (ring->mr_dmah == dmah) {
		mca_error(ring->mr_mca, "%s ring DMA error", string);
		return (DDI_FAILURE);
	} else {
		DBG(ring->mr_mca, DBRINGUP, "%s ring DMA handle OK", string);
	}

	/* Check dma handles in crypto requests */
	for (i = 0; i < ring->mr_nreqs; i++) {

		/* Check key handle */
		if (ring->mr_reqs[i]->mr_key_dmah == dmah) {
			mca_error(ring->mr_mca,
			    "%s ring key DMA error for entry %d", string, i);
			return (DDI_FAILURE);
		}

		/* Check input buffer handle */
		if (ring->mr_reqs[i]->mr_ibuf_dmah == dmah) {
			mca_error(ring->mr_mca,
			    "%s ring input DMA error for entry %d", string, i);
			return (DDI_FAILURE);
		}

		/* Check output buffer handle */
		if (ring->mr_reqs[i]->mr_obuf_dmah == dmah) {
			mca_error(ring->mr_mca,
			    "%s ring output DMA error for entry %d",
			    string, i);
			return (DDI_FAILURE);
		}

		/* Check direct input buffer handle */
		if (ring->mr_reqs[i]->mr_in_direct_dmah == dmah) {
			mca_error(ring->mr_mca,
			    "%s ring direct input DMA error for entry %d",
			    string, i);
			return (DDI_FAILURE);
		}

		/* Check direct output buffer handle */
		if (ring->mr_reqs[i]->mr_out_direct_dmah == dmah) {
			mca_error(ring->mr_mca,
			    "%s ring direct output DMA error for entry %d",
			    string, i);
			return (DDI_FAILURE);
		}
	}

	DBG(ring->mr_mca, DBRINGUP, "%s ring request dma handles OK", string);
	return (DDI_SUCCESS);
}

int
mca_chk_crypto_acch(mca_t *mca, ddi_acc_handle_t acch)
{
	int	rv;

	/* Check bulk crypto ring access handles */
	rv = mca_chk_ring_acch(&mca->mca_ring_cb, acch, "Bulk crypto");
	if (rv != DDI_SUCCESS) {
		return (rv);
	}

	/* Check asymetric crypto ring access handles */
	rv = mca_chk_ring_acch(&mca->mca_ring_ca, acch, "Asymetric crypto ");
	if (rv != DDI_SUCCESS) {
		return (rv);
	}

	/* Check object management ring access handles */
	rv = mca_chk_ring_acch(&mca->mca_ring_om, acch, "Object management ");
	if (rv != DDI_SUCCESS) {
		return (rv);
	}

	return (DDI_SUCCESS);
}

static int
mca_chk_crypto_dmah(mca_t *mca, ddi_dma_handle_t dmah)
{
	int	rv;

	/* Check bulk crypto ring dma handles */
	rv = mca_chk_ring_dmah(&mca->mca_ring_cb, dmah, "Bulk crypto");
	if (rv != DDI_SUCCESS) {
		return (rv);
	}

	/* Check asymetric crypto ring dma handles */
	rv = mca_chk_ring_dmah(&mca->mca_ring_ca, dmah, "Asymetric crypto ");
	if (rv != DDI_SUCCESS) {
		return (rv);
	}

	/* Check object management ring dma handles */
	rv = mca_chk_ring_dmah(&mca->mca_ring_om, dmah, "Object management ");
	if (rv != DDI_SUCCESS) {
		return (rv);
	}

	return (DDI_SUCCESS);
}

static int
mca_chk_acch(mca_t *mca, ddi_acc_handle_t acch)
{
	int rv;

	DBG(mca, DWARN, "Checking access handle = 0x%x", acch);
	/* Check control access handles */
	rv = mca_chk_ctl_acch(mca, acch);
	if (rv != DDI_SUCCESS) {
		return (rv);
	}

	/* Check crypto access handles */
	rv = mca_chk_crypto_acch(mca, acch);
	if (rv != DDI_SUCCESS) {
		return (rv);
	}
	DBG(mca, DWARN, "Unknown access handle = 0x%x", acch);
	return (DDI_SUCCESS);
}

static int
mca_chk_dmah(mca_t *mca, ddi_dma_handle_t dmah)
{
	int rv;

	DBG(mca, DWARN, "Checking dma handle = 0x%x", dmah);
	/* Check control dma handles */
	rv = mca_chk_ctl_dmah(mca, dmah);
	if (rv != DDI_SUCCESS) {
		return (rv);
	}

	/* Check crypto dma handles */
	rv = mca_chk_crypto_dmah(mca, dmah);
	if (rv != DDI_SUCCESS) {
		return (rv);
	}

	DBG(mca, DWARN, "Unknown dma handle = 0x%x", dmah);
	return (DDI_SUCCESS);
}

static int
mca_chk_pci_status(mca_t *mca, uint16_t status)
{
	int rv = DDI_FM_OK;

	/* Check for non-fatal errors first */
	if (status & MCA_PCI_NONFATAL_ERRORS) {
		rv = DDI_FM_NONFATAL;
	}

	/* Over-ride non-fatal status if fatal errors are found */
	if (status & MCA_PCI_FATAL_ERRORS) {
		rv = DDI_FM_FATAL;
	}

	if (rv != DDI_FM_OK) {
		/* EMPTY */
		DBG(mca, DBRINGUP,
		    "mca_chk_pci_status> status = %04x, rv = %d", status, rv);
	}

	return (rv);
}

static int
mca_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data)
{
	int		rv = DDI_FM_UNKNOWN;
	mca_t		*mca = (mca_t *)impl_data;
	uint16_t	pci_status;
	int		pci_rv;
	ddi_fm_error_t	pci_err;

	DBG(mca, DBRINGUP, "mca_fm_error_cb> ena = %x, dma_h = %x, acc_h = %x",
	    err->fme_ena, err->fme_dma_handle, err->fme_acc_handle);

	if (err->fme_flag == DDI_FM_ERR_EXPECTED) {
		/*
		 * mca never perfrom DDI_ACC_CAUTIOUS protected operations
		 * but if it did. we would handle it here
		 */
		return (DDI_FM_OK);
	}

	mutex_enter(&mca->fm_lock);

	/* Check if valid device access or dma handles were provided */
	if ((err->fme_acc_handle == NULL) && (err->fme_dma_handle == NULL)) {

		/* No DMA/access handle provided, see if card has failed */
		if (mca_fm_hw_faulted(mca)) {
			rv = DDI_FM_FATAL;
		} else {
			rv = DDI_FM_OK;
		}
	}

	/* See if there is a pci error to report (generate new ena) */
	bzero(&pci_err, sizeof (ddi_fm_error_t)); /* Initialize unused fields */
	pci_err.fme_version = DDI_FME_VERSION;
	pci_err.fme_flag = DDI_FM_ERR_UNEXPECTED;
	pci_err.fme_ena = 0;		 /* ENA will will be generated */
	pci_ereport_post(dip, &pci_err, &pci_status);
	pci_rv = mca_chk_pci_status(mca, pci_status);
	if (pci_rv != DDI_FM_OK) {
		rv = pci_rv;
	}

	if (rv != DDI_FM_OK) {

		/* Save error handles for later analysis in soft int handler */
		mca->fm_dma_handle = err->fme_dma_handle;
		mca->fm_acc_handle = err->fme_acc_handle;

		/*
		 * Indicate io fault in fm_flags every time we either receive
		 * a handle that is identified as ours or a generice pci error
		 * is detected so that all handles will be released.
		 */
		mca_fm_set_io_fault(mca);

		/*
		 * Trigger a soft interrupt.  Service impact will be reported
		 * in the interrupt handler.
		 */
		mca_fm_set_softint(mca);
		ddi_trigger_softintr(mca->mca_soft_intr);
	}

	mutex_exit(&mca->fm_lock);

	return (rv);
}
#endif /* FMA_COMPLIANT */

void
mca_log_system_msg(mca_t *mca, uint8_t level, char *msg)
{
	switch (level) {
	case LOGMASK_ERROR:
	case LOGMASK_WARN:
		mca_error(mca, "%s", msg);
		break;
	case LOGMASK_NOTICE:
		mca_note(mca, "%s", msg);
		break;
	case LOGMASK_INFO:
		mca_info(mca, "%s", msg);
		break;
	default:
		/*
		 * Log all firmware messages (including debug) that make it
		 * past filters.  Use mca.conf to disable firmware debug
		 * messages when running a debug version of the driver.
		 */
		mca_info(mca, "%s", msg);
		break;
	}
}

int
cpgattr2keytype(cpg_attr_t *attr, int *keytype)
{
	uint32_t	type = (uint32_t)-1;
	uint32_t	class = CPGO_SECRET_KEY;

	(void) cpg_attr_lookup_uint32(attr, CPGA_CLASS, &class);
	(void) cpg_attr_lookup_uint32(attr, CPGA_KEY_TYPE, &type);

	DBG(NULL, DCHATTY, "cpgattr2keytype: class[0x%x], keytype[0x%x]",
	    class, type);

	switch (class) {
	case CPGO_SECRET_KEY:
		switch (type) {
		case CPGK_DES3:
			*keytype = KEYTYPE_DES3;
			break;
		case CPGK_DES2:
			*keytype = KEYTYPE_DES2;
			break;
		case CPGK_DES:
			*keytype = KEYTYPE_DES;
			break;
		case CPGK_RC2:
			*keytype = KEYTYPE_RC2;
			break;
		case CPGK_RC4:
			*keytype = KEYTYPE_RC4;
			break;
		case CPGK_AES:
			*keytype = KEYTYPE_AES;
			break;
		case CPGK_GENERIC_SECRET:
			*keytype = KEYTYPE_GENERIC_SECRET;
			break;
#ifdef FINSVCS
		case CPGK_FS:
			*keytype = KEYTYPE_FS;
			break;
#endif /* FINSVCS */
		default:
			return (CRYPTO_TEMPLATE_INCONSISTENT);
		}
		break;
	case CPGO_PRIVATE_KEY:
		switch (type) {
		case CPGK_RSA:
			*keytype = KEYTYPE_RSA_PRIVATE;
			break;
		case CPGK_DSA:
			*keytype = KEYTYPE_DSA_PRIVATE;
			break;
		case CPGK_DH:
			*keytype = KEYTYPE_DH_PRIVATE;
			break;
		case CPGK_EC:
			*keytype = KEYTYPE_EC_PRIVATE;
			break;
		default:
			return (CRYPTO_TEMPLATE_INCONSISTENT);
		}
		break;
	case CPGO_PUBLIC_KEY:
		switch (type) {
		case CPGK_RSA:
			*keytype = KEYTYPE_RSA_PUBLIC;
			break;
		case CPGK_DSA:
			*keytype = KEYTYPE_DSA_PUBLIC;
			break;
		case CPGK_DH:
			*keytype = KEYTYPE_DH_PUBLIC;
			break;
		case CPGK_EC:
			*keytype = KEYTYPE_EC_PUBLIC;
			break;
		default:
			return (CRYPTO_TEMPLATE_INCONSISTENT);
		}
		break;
	case CPGO_CERTIFICATE:
	case CPGO_DATA:
		*keytype = KEYTYPE_NOKEY;
		break;
	default:
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}

	return (CRYPTO_SUCCESS);
}


/*
 * Soft interrupt service routine
 */
static uint_t
mca_soft_intr(char *arg)
{
	uint_t		status = DDI_INTR_UNCLAIMED;

#ifdef FMA_COMPLIANT
	mca_t		*mca = (mca_t *)arg;

	mutex_enter(&mca->mca_soft_intrlock);

	/* Check if a soft interrupt was triggered by the driver */
	if (mca_fm_is_softint(mca)) {

		DBG(mca, DBRINGUP, "Solaris IO Fault Services error reported");
		status = DDI_INTR_CLAIMED;

		mutex_enter(&mca->fm_lock);
		mca_fm_clr_softint(mca);
		/* Check if an io fault is indicated in fm_flags */
		if (mca_fm_io_faulted(mca)) {
			mca_fm_clr_io_fault(mca);
			mca_fm_setfailed(mca);
		}
		mutex_exit(&mca->fm_lock);

		/* Check for device access error */
		if (mca->fm_acc_handle != NULL) {

			/* Check if it is really our handle */
			if (mca_chk_acch(mca, mca->fm_acc_handle) ==
			    DDI_SUCCESS) {

				/* Unknown handle, log error message */
				mca_error(mca, "Error reported in unknown "
				    "access handle");
			}
			mca->fm_acc_handle = NULL;
		}

		/* Check for dma error */
		if (mca->fm_dma_handle != NULL) {

			/* Check if it is really our handle */
			if (mca_chk_dmah(mca, mca->fm_dma_handle) ==
			    DDI_SUCCESS) {

				/* Unknown handle, log error message */
				mca_error(mca, "Error reported in unknown "
				    "dma handle");
			}
			mca->fm_dma_handle = NULL;
		}

		/* Call mca_failure() to shutdown the card on failures */
		if (mca_fm_isfailed(mca)) {
			mca_failure(mca, MCA_FMA_NO_CLASS_ID,
			    "Solaris IO Fault Services error reported");
		}
	} else {
		DBG(mca, DBRINGUP, "Unclaimed soft interrupt received");
	}

	mutex_exit(&mca->mca_soft_intrlock);

#else
	mca_t		*mca = (mca_t *)arg;
	DBG(mca, DBRINGUP, "Unexpected (unclaimed) soft interrupt received");
	status = DDI_INTR_UNCLAIMED;

#endif /* FMA_COMPLIANT */

	return (status);
}

static void
mca_init_job_timeout_info(mca_t *mcap)
{
	bzero(&mcap->job, sizeof (mcap->job));

	/* set ticks for one second granularity */
	mcap->job.timeout.ticks = drv_usectohz(SECOND);

	/* setup base amount to add per outstanding job */
	mcap->job.stalled.addend = mcap->job.timeout.ticks;

	/* setup the stall margin  */
	mcap->job.stalled.limit = MCA_JOB_STALL_LIMIT * mcap->job.timeout.ticks;

}

int
mca_chgstate_offline(mca_t *mca)
{
	if (mca_fm_isfailsafe(mca)) {
		/* the board is in the failsafe mode */
		return (EIO);
	}

	if (mca_isunregistered(mca)) {
		/* already in the right state */
		return (0);
	}
	if (mca_hw_provider_unregister(mca) != CRYPTO_SUCCESS) {
		/* failed to unregister from the framework */
		return (EIO);
	}
	mca_setunregistered(mca);

	mca_note(mca, "State changed to: Offline");

	return (0);
}

int
mca_chgstate_diag(mca_t *mca)
{
	if (mca_fm_isfailsafe(mca)) {
		/* the board is in the failsafe mode */
		return (EIO);
	}

	/*
	 * If it is already in the diag mode, or if the device is not
	 * yet owened but registered, nothing needs to be done.
	 */
	if (mca_isdiag(mca) ||
	    (!mca_isowned(mca) && mca_isregistered(mca))) {
		mca_setdiag(mca);
		return (0);
	}
	if (mca_isregistered(mca)) {
		if (mca_hw_provider_unregister(mca) != CRYPTO_SUCCESS) {
			/* failed to unregister from the framework */
			return (EIO);
		}
	}
	if (mca_hw_provider_register(mca, MCA_DIAG) != CRYPTO_SUCCESS) {
		/*
		 * Failed to register to the framework. Cannot
		 * recover from this error.
		 */
		return (EIO);
	}

	mca_note(mca, "State changed to: Diag");

	return (0);
}

int
mca_chgstate_online(mca_t *mca)
{
	if (mca_fm_isfailsafe(mca)) {
		/* the board is in the failsafe mode */
		return (EIO);
	}

	if (mca_isregistered(mca)) {
		/* already in the right state */
		return (0);
	}
	if (mca_isdiag(mca)) {
		if (mca_hw_provider_unregister(mca) != CRYPTO_SUCCESS) {
			/* failed to unregister from the framework */
			return (EIO);
		}
	}
	if (mca_hw_provider_register(mca, 0) != CRYPTO_SUCCESS) {
		/*
		 * Failed to register to the framework. Cannot
		 * recover from this error.
		 */
		mca_setunregistered(mca);
		return (EIO);
	}
	mca_setregistered(mca);

	mca_note(mca, "State changed to: Online");

	return (0);
}

/*
 * Enumerate the devices, and returns an array of minor numbers.
 * Note: Used by mcadiag
 */
void
mca_probe(int *devs, int *ndevs)
{
	int	i;
	int	id = -1;

	for (i = 0; i < *ndevs; i++) {
		/* look up devices in the mca_state table */
		if (mca_table_next_slot(&mca_state, &id) == DDI_SUCCESS) {
			devs[i] = id;
		} else {
			*ndevs = i;
			return;
		}
	}
}

/*
 * Get information on the device (state and status)
 */
void
mca_get_devinfo(mca_t *mca, int *state, int *status)
{
	/* state */
	if (mca_fm_isfailsafe(mca) ||
	    mca_fm_isfailed(mca)) {
		*state = MCASTATE_FAILED;
	} else if (mca_isdiag(mca)) {
		*state = MCASTATE_DIAG;
	} else if (mca_isregistered(mca)) {
		*state = MCASTATE_ONLINE;
	} else {
		*state = MCASTATE_OFFLINE;
	}

	/* status */
	if (mca_isfips(mca)) {
		*status = MCASTATUS_FIPS;
	} else if (mca_isowned(mca)) {
		*status = MCASTATUS_INIT;
	} else {
		*status = MCASTATUS_UNINIT;
	}
}


/*
 * Get version information for the device (hardware, firmware and bootrom)
 */
void
mca_get_verinfo(mca_t *mca, uint32_t *hw, uint32_t *fw, uint32_t *boot)
{
	*hw = GETCSR32(mca, CSR_HWVERSION);
	*fw = GETCSR32(mca, CSR_FWVERSION);
	*boot = GETCSR32(mca, CSR_BOOT_VERSION);
}


#ifdef LINUX
#ifdef DEBUG
EXPORT_SYMBOL(mca_dprintf);
#endif
EXPORT_SYMBOL(mca_upcall_detach);
EXPORT_SYMBOL(mca_safereset);
EXPORT_SYMBOL(mca_fdi_req);
EXPORT_SYMBOL(mca_fdi_dl);
EXPORT_SYMBOL(mca_table_alloc_slot);
EXPORT_SYMBOL(mca_upcall_attach);
EXPORT_SYMBOL(mca_table_lookup);
EXPORT_SYMBOL(mca_zeroize);
EXPORT_SYMBOL(mca_get_next_instance);
EXPORT_SYMBOL(mca_hold_ctl);
EXPORT_SYMBOL(mca_table_free_slot);
EXPORT_SYMBOL(mca_keystore_serial);
EXPORT_SYMBOL(mca_upcall_service);
EXPORT_SYMBOL(mca_failure);
EXPORT_SYMBOL(mca_seccmd_disconnect);
EXPORT_SYMBOL(mca_keystore_name);
EXPORT_SYMBOL(mca_getcsr);
EXPORT_SYMBOL(mca_table_destroy);
EXPORT_SYMBOL(mca_putpci);
EXPORT_SYMBOL(mca_getpubkey);
EXPORT_SYMBOL(mca_getpci);
EXPORT_SYMBOL(mca_rele_ctl);
EXPORT_SYMBOL(mca_diagnostics);
EXPORT_SYMBOL(mca_table_init);
EXPORT_SYMBOL(mca_fwupdate);
EXPORT_SYMBOL(mca_seccmd);
EXPORT_SYMBOL(mca_provider_in_use);
EXPORT_SYMBOL(mca_putcsr);
EXPORT_SYMBOL(mca_get_devinfo);
EXPORT_SYMBOL(mca_get_verinfo);
EXPORT_SYMBOL(mca_chgstate_offline);
EXPORT_SYMBOL(mca_chgstate_diag);
EXPORT_SYMBOL(mca_chgstate_online);
EXPORT_SYMBOL(mca_probe);
EXPORT_SYMBOL(mca_dbm_response);
EXPORT_SYMBOL(mca_dbm_freereq);
EXPORT_SYMBOL(mca_rele_instance);
EXPORT_SYMBOL(mca_hold_instance);
EXPORT_SYMBOL(mca_loadswap32);
EXPORT_SYMBOL(mca_upcall_release);
EXPORT_SYMBOL(mca_dh_derive);
EXPORT_SYMBOL(mca_storeswap32);
EXPORT_SYMBOL(mca_update_idc_hdr);
EXPORT_SYMBOL(mca_get_domain);
EXPORT_SYMBOL(mca_upcall_dbm_register);
EXPORT_SYMBOL(mca_presuspend);
EXPORT_SYMBOL(mca_postresume);
#endif
