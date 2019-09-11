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

#pragma ident	"@(#)sca_io.c	1.41	08/08/18 SMI"

/*
 * The ioctl interface for the Sun Crypto Accelerator Framework commands.
 */

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
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>

#include "sol2lin.h"
#include "common.h"
#include "spi.h"
#include "pkcs11types.h"
#include "pkcs32.h"
#include "sca_defs.h"
#include "sca_args.h"
#include "sca_private.h"
#include "sca_rc.h"

/* To display copyright in the object or executable files */
char copywrite[] = "Copyright 2006 Sun Microsystems, Inc. "
	"All rights reserved. Use is subject to license terms.";

static int sca_ioctl(struct inode *inode, struct file *filp, unsigned int cmd,
    unsigned long arg);
static int sca_open(struct inode *inode, struct file *filp);
static int sca_release(struct inode *inode, struct file *filp);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9))
static long sca_ioctl_compat(struct file *filp, unsigned int cmd,
    unsigned long arg);
#endif

static int sca_cipher_init(unsigned long arg, EncryptInit_Args *encrypt_init,
    sca_session_t *sp, sca_provider_t *real, crypto_ops_t *ops_vector,
    crypto_session_id_t psid,
    int (*init)(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t));

static int sca_common_digest(unsigned long arg,
    Digest_Args *crypto_digest, sca_session_t *sp, crypto_ops_t *ops_vector,
    int (*single)(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t));

static int sca_cipher(unsigned long arg, Encrypt_Args *encrypt,
    sca_session_t *sp, crypto_ops_t *ops_vector,
    int (*single)(crypto_ctx_t *,
    crypto_data_t *, crypto_data_t *, crypto_req_handle_t));

static int sca_cipher_update(unsigned long arg,
    EncryptUpdate_Args *encrypt_update,
    sca_session_t *sp, crypto_ops_t *ops_vector,
    int (*update)(crypto_ctx_t *,
    crypto_data_t *, crypto_data_t *, crypto_req_handle_t));

static int sca_common_final(unsigned long arg,
    EncryptFinal_Args *encrypt_final, sca_session_t *sp,
    crypto_ops_t *ops_vector,
    int (*final)(crypto_ctx_t *, crypto_data_t *, crypto_req_handle_t));

static int sca_sign_verify_init(unsigned long arg, SignInit_Args *sign_init,
    sca_session_t *sp, sca_provider_t *real, crypto_ops_t *ops_vector,
    crypto_session_id_t psid, int (*init)(crypto_ctx_t *,
    crypto_mechanism_t *, crypto_key_t *, crypto_spi_ctx_template_t,
    crypto_req_handle_t));

static int sca_sign_verify_update(unsigned long arg,
    SignUpdate_Args *sign_update,
    sca_session_t *sp, crypto_ops_t *ops_vector,
    int (*update)(crypto_ctx_t *, crypto_data_t *, crypto_req_handle_t));

static void sca_release_provider_session(sca_file_private_t *,
    sca_provider_session_t *);
static void sca_close_provider_session(sca_file_private_t *cm);
static int sca_free_find_ctx(sca_session_t *);
static int sca_get_session_ptr(crypto_session_id_t i, sca_file_private_t *cm,
    sca_session_t **session_ptr);
static int sca_get_co_ctx_ops(sca_session_t *sp, crypto_ops_t **ops_vector,
    sca_provider_t **real);
static void sca_free_session(sca_file_private_t *jp, sca_session_t *sp,
    uint_t i);

static int sca_copyin_mech(caddr_t arg, crypto_mechanism_t *in_mech);
static int sca_get_provider_session(sca_file_private_t *cm,
    crypto_provider_id_t provider_index, sca_provider_session_t **output_ps);
static int sca_grow_session_table(sca_file_private_t *cm);
static int sca_get_attrs(uint_t count, uint_t block_len, caddr_t attrs_in,
    crypto_object_attribute_t **k_attrs_out);
static int sca_set_attrs(uint_t count, uint_t block_len, caddr_t u_attrs,
    crypto_object_attribute_t *k_attrs);

static int sca_make_slot_list(CK_SLOT_ID_32 *slot_list);
static uint_t sca_make_mechanism_list(sca_provider_t *provider,
    CK_MECHANISM_TYPE_32 *mechanisms);
static int sca_wait_on_queued(sca_session_t *sp, int rv, long timeout_secs);
static int sca_get_ops_from_ctx(crypto_ctx_t *ctx, crypto_ops_t **ops_vector,
    long timeout_secs);
static int sca_wait_for_busy_provider(sca_provider_t *real, long timeout_secs);
static int sca_init_raw_crypto_data(crypto_data_t *data, size_t len);

static void register_sca_ioctl32(void);
static void unregister_sca_ioctl32(void);

/*
 * The max kernel memory may be allocated is 128 Kbytes.
 */
#define	CRYPTO_MAX_BUFFER_LEN	(128 * 1024)
#define	CRYPTO_MAX_FIND_COUNT	512

/* The session table grows by CRYPTO_SESSION_CHUNK increments */
#define	CRYPTO_SESSION_CHUNK	100

#define	SCA_LONG_TIMEOUT	600
#define	SCA_SHORT_TIMEOUT	10
#define	SCA_PROVIDER_TIMEOUT	900

static long crypto_max_buffer_len = CRYPTO_MAX_BUFFER_LEN;

/*
 * A mechanism with any of the following bits set should be
 * visible in the userland. This is to filter out atomic-only mechs
 */
static crypto_func_group_t g_sca_userland_flags =
	CRYPTO_FG_ENCRYPT | CRYPTO_FG_DECRYPT |
	CRYPTO_FG_DIGEST | CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_RECOVER |
	CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_RECOVER |
	CRYPTO_FG_GENERATE | CRYPTO_FG_GENERATE_KEY_PAIR |
	CRYPTO_FG_WRAP | CRYPTO_FG_UNWRAP | CRYPTO_FG_DERIVE |
	CRYPTO_FG_MAC | CRYPTO_FG_ENCRYPT_MAC | CRYPTO_FG_MAC_DECRYPT;

/*
 * SuSE 9.0 (Linux 2.6.5 kernel) does not have wait_event_timeout macro,
 * Redhat 4.0 (Linux 2.6.9 kernel) does. We borrow the following code
 * from Redhat 4.0 and rename it as wait_event_timeout_local so that we can
 * use the same on both Redhat 4.0 and SuSE 9.0. Make sure to delete it
 * once not needed.
 */

#define	__wait_event_timeout_local(wq, condition, ret)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_UNINTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		ret = schedule_timeout(ret);				\
		if (!ret)						\
			break;						\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)

#define	wait_event_timeout_local(wq, condition, timeout) {		\
	long __ret = timeout;						\
	if (!(condition)) 						\
		__wait_event_timeout_local(wq, condition, __ret);	\
	__ret;								\
}


#define	SCA_GET_PRIVATE(cm, filp, msg) {				\
	if ((cm = (sca_file_private_t *)filp->private_data) == NULL) {	\
		SCA_ERR_PRINT("%s", msg);				\
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);			\
	}								\
}

#define	SCA_GET_OPS_SUB(prov, real, ops_vector, ops, funct, rc) {	\
	rc = CRYPTO_SUCCESS;						\
	if (prov_info->pi_provider_type == CRYPTO_HW_PROVIDER) {	\
		real = prov;						\
		ops_vector = real->sp_info->pi_ops_vector;		\
		if (ops_vector->ops == NULL ||				\
		    ops_vector->ops->funct == NULL) {			\
			rc = CRYPTO_NOT_SUPPORTED;			\
		}							\
	} else if (prov_info->pi_provider_type ==			\
	    CRYPTO_LOGICAL_PROVIDER) {					\
		sca_provider_t *np = NULL, *bp = NULL;			\
		int not_supported = 0, prov_failed = 0;			\
		int i;							\
									\
		for (i = 0; i < prov->sp_hp_count; i++) {		\
			np = prov->sp_hp_list[prov->sp_next_hp_index];	\
			prov->sp_next_hp_index++;			\
			if (prov->sp_next_hp_index >= prov->sp_hp_count)\
				prov->sp_next_hp_index = 0;		\
									\
			ops_vector = np->sp_info->pi_ops_vector;	\
			if (ops_vector->ops == NULL ||			\
			    ops_vector->ops->funct == NULL) {		\
				not_supported = 1;			\
				continue;				\
			}						\
									\
			if (np->sp_state == CRYPTO_PROVIDER_READY)	\
				break;					\
			else if (np->sp_state == CRYPTO_PROVIDER_BUSY)	\
				bp = np;				\
			else						\
				prov_failed = 1;			\
		}							\
									\
		if (i < prov->sp_hp_count) {				\
			real = np;					\
		} else if (bp) {					\
			/* This can handle it but busy, wait later */	\
			real = bp;					\
		} else if (prov_failed)					\
			rc = CRYPTO_FAILED;				\
		else if (not_supported)					\
			rc = CRYPTO_NOT_SUPPORTED;			\
		else							\
			rc = CRYPTO_FAILED;				\
	} else {							\
		rc = CRYPTO_FAILED;					\
	}								\
}									\

/*
 * Choose a provider that supports the given operation.
 * Needs to use macro since "ops" and "funct" need to be expanded.
 */
#define	SCA_GET_OPS(sp, real, ops_vector, ph, psid, ops, funct) {	\
	crypto_provider_info_t *prov_info;				\
	sca_provider_t *prov;						\
	unsigned long lock_flags;					\
	int r_v = CRYPTO_SUCCESS;					\
									\
	spin_lock_irqsave(&g_sca_lock, lock_flags);			\
									\
	prov = sp->ss_provider_session->ps_provider;			\
	psid = sp->ss_provider_session->ps_session;			\
	prov_info = prov->sp_info;					\
	ops_vector = NULL;						\
	real = NULL;							\
	ph = NULL;							\
									\
	SCA_GET_OPS_SUB(prov, real, ops_vector, ops, funct, r_v);	\
									\
	if (r_v != CRYPTO_SUCCESS) {					\
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);	\
		SCA_SESSION_RELE(sp);					\
		return (sca_rc[r_v]);					\
	}								\
									\
	ops_vector = real->sp_info->pi_ops_vector;			\
	ph = real->sp_info->pi_provider_handle;				\
	atomic_inc(&real->sp_ref_count);				\
	spin_unlock_irqrestore(&g_sca_lock, lock_flags);		\
}

/*
 * Choose a provider that supports the given operation.
 * Needs to use macro since "ops" and "funct" need to be expanded.
 */
#define	SCA_GET_OPS_PROV(prov, real, ops_vector, ops, funct, r_v) {	\
	crypto_provider_info_t *prov_info;				\
	unsigned long lock_flags;					\
	r_v = CRYPTO_SUCCESS;						\
									\
	spin_lock_irqsave(&g_sca_lock, lock_flags);			\
									\
	prov_info = prov->sp_info;					\
	ops_vector = NULL;						\
	real = NULL;							\
									\
	SCA_GET_OPS_SUB(prov, real, ops_vector, ops, funct, r_v);	\
									\
	if (r_v == CRYPTO_SUCCESS) {					\
		ops_vector = real->sp_info->pi_ops_vector;		\
		atomic_inc(&real->sp_ref_count);			\
	}								\
									\
	spin_unlock_irqrestore(&g_sca_lock, lock_flags);		\
}

/*
 * Choose a provider that supports the given mechanism.
 * For a logical provider, need to use the provider handle (ph) and
 * ops vector (ops_vector) from a real provider. The provider session ID
 * (psid) is still from the logical provider.
 * Need to use a macro since "ops" and "funct" need to be expanded.
 */
#define	SCA_GET_OPS_MECH(sp, real, ops_vector, psid, ops, funct, mech) {\
	sca_provider_session_t *ps;					\
	crypto_provider_info_t *prov_info;				\
	sca_provider_t *prov;						\
	unsigned long lock_flags;					\
	int r_v = CRYPTO_SUCCESS;					\
									\
	spin_lock_irqsave(&g_sca_lock, lock_flags);			\
									\
	ps = sp->ss_provider_session;					\
	psid = ps->ps_session;						\
	prov = ps->ps_provider; 					\
	prov_info = prov->sp_info;					\
	ops_vector = NULL;						\
	real = NULL;							\
									\
	if (prov_info->pi_provider_type == CRYPTO_HW_PROVIDER) {	\
		real = prov;						\
		ops_vector = real->sp_info->pi_ops_vector;		\
		if (ops_vector->ops == NULL ||				\
		    ops_vector->ops->funct == NULL) {			\
			r_v = CRYPTO_NOT_SUPPORTED;			\
		}							\
	} else if (prov_info->pi_provider_type ==			\
	    CRYPTO_LOGICAL_PROVIDER) {					\
		uint_t count;						\
		crypto_mech_info_t *list;				\
		sca_provider_t *np, *bp;				\
		int i, j;						\
		int not_supported, mech_invalid, prov_failed;		\
									\
		not_supported = mech_invalid = 0, prov_failed = 0;	\
		np = bp = NULL;						\
		r_v = CRYPTO_SUCCESS;					\
		for (i = 0; i < prov->sp_hp_count; i++) {		\
			np = prov->sp_hp_list[prov->sp_next_hp_index];	\
			prov->sp_next_hp_index++;			\
			if (prov->sp_next_hp_index >= prov->sp_hp_count)\
				prov->sp_next_hp_index = 0;		\
									\
			ops_vector = np->sp_info->pi_ops_vector;	\
			if (ops_vector->ops == NULL ||			\
			    ops_vector->ops->funct == NULL) {		\
				not_supported = 1;			\
				continue;				\
			}						\
									\
			count = np->sp_info->pi_mech_list_count;	\
			list = np->sp_info->pi_mechanisms;		\
			for (j = 0; j < count; j++) {			\
				if ((list[j].cm_mech_number == mech) &&	\
				    (list[j].cm_func_group_mask &	\
				    g_sca_userland_flags))		\
					break;				\
			}						\
									\
			if (j == count) {				\
				mech_invalid = 1;			\
				continue;				\
			}						\
									\
			if (np->sp_state == CRYPTO_PROVIDER_READY)	\
				break;					\
			else if (np->sp_state == CRYPTO_PROVIDER_BUSY)	\
				bp = np;				\
			else						\
				prov_failed = 1;			\
		}							\
									\
		if (i < prov->sp_hp_count) {				\
			real = np;					\
		} else if (bp) {					\
			/* This can handle it but busy, wait later */	\
			real = bp;					\
		} else if (prov_failed)					\
			r_v = CRYPTO_FAILED;				\
		else if (mech_invalid)					\
			r_v = CRYPTO_MECHANISM_INVALID;			\
		else if (not_supported)					\
			r_v = CRYPTO_NOT_SUPPORTED;			\
		else							\
			r_v = CRYPTO_FAILED;				\
	} else {							\
		r_v = CRYPTO_FAILED;					\
	}								\
									\
	if (r_v != CRYPTO_SUCCESS) {					\
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);	\
		SCA_SESSION_RELE(sp);					\
		return (sca_rc[r_v]);					\
	}								\
									\
	ops_vector = real->sp_info->pi_ops_vector;			\
	atomic_inc(&real->sp_ref_count);				\
	spin_unlock_irqrestore(&g_sca_lock, lock_flags);		\
}

#define	SCA_SESSION_RELE(s) {				\
	spin_lock(&sp->ss_lock);			\
	(s)->ss_flags &= ~SCA_SESSION_IS_BUSY;		\
	wake_up_interruptible(&((s)->ss_busy_wait));	\
	spin_unlock(&sp->ss_lock);			\
}

/* Decrement the reference count and wake up any waiting processes */
#define	SCA_PROVIDER_RELE(prov_ptr) {				\
	sca_provider_t *rp = (sca_provider_t *)(prov_ptr);	\
	if (rp && atomic_dec_and_test(&rp->sp_ref_count))	\
		wake_up(&rp->sp_wait);		\
}

#define	SCA_ROUNDUP(x, y) (((x)+(y)) & ~(y))

/*
 * The object handles returned from the provider start from 0. However, 0
 * is CK_INVALID_HANDLE in the userland. Thus we need to do a translation here.
 */
#define	OBJ_HANDLE_INC(handle)	((handle) + 1)
#define	OBJ_HANDLE_DEC(handle)	((handle) - 1)

/*
 * Major number received in init_module as part of the driver
 * registration process.  This is a global because we need it in
 * cleanup_module to unregister the driver.
 */
static int	g_sca_major_number = 0;
static int	g_sca_handles_in_use = 0;

spinlock_t	g_sca_lock = SPIN_LOCK_UNLOCKED;

/*
 * openCryptoki requires slot numbers are consecutive integers. The
 * g_sca_provider_array may have logical providers between hardware providers.
 * If we show logical providers only, the logical provider indexes (IDs) may not
 * be consecutive integers. Thus the g_sca_index array is introduced
 * which indirects into the g_sca_provider array. The logical providers are
 * arranged at the beginning of the g_sca_index array. The indexes of
 * g_sca_index is used as the slot IDs by openCryptoki.
 */
sca_provider_t	*g_sca_provider_array[MAX_NUMBER_PROVIDER];
int		g_sca_index[MAX_NUMBER_PROVIDER];
uint_t		g_sca_provider_count = 0;


/* Module parameters */
/*
 * By default, we hide the hardware providers that are associated with any
 * logical providers. This behavior may be disabled at module loading time using
 * "insmod scaf sca_hide_hardware_provider=0"
 */
static int	sca_hide_hardware_provider = 1;
module_param(sca_hide_hardware_provider, int, S_IRUGO);


/* This struct indicates which standard device functions are supported */
static struct file_operations g_sca_fops =
{
	ioctl:		sca_ioctl,
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9))
	compat_ioctl:	sca_ioctl_compat,
#endif
	open:		sca_open,
	release:	sca_release,
	owner:		THIS_MODULE
};


int
sca_module_init(void)
{
	/* initialize the major number using the automatic method */
	g_sca_major_number = register_chrdev(0, SCA_NAME, &g_sca_fops);
	if (g_sca_major_number < 0) {
		SCA_ERR_PRINT(
		    "sca_module_init: Failed to get major # for module %s\n",
		    SCA_NAME);
		return (g_sca_major_number);
	}

	g_sca_handles_in_use = 0;

	/* initialize providers */
	memset(g_sca_provider_array, 0,
	    MAX_NUMBER_PROVIDER * sizeof (sca_provider_t *));
	memset(g_sca_index, 0, MAX_NUMBER_PROVIDER * sizeof (int));
	g_sca_provider_count = 0;

#if !defined(i386) && !defined(__i386) && \
    (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,9))
	register_sca_ioctl32();
#endif

	return (0);
}

void
sca_module_exit(void)
{
	/* Check if there are any providers still registered */
	if (g_sca_provider_count > 0)
		return;

	/* Unregister the device and free the major number */
	unregister_chrdev(g_sca_major_number, SCA_NAME);

#if !defined(i386) && !defined(__i386) && \
    (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,9))
	unregister_sca_ioctl32();
#endif
}

module_init(sca_module_init);
module_exit(sca_module_exit);
MODULE_LICENSE("Dual BSD/GPL");

/*
 * Open a file descriptor. Allocate and initialize a private data structure.
 */
static int
sca_open(struct inode *inode, struct file *filp)
{
	sca_file_private_t *fp;
	unsigned long lock_flags;

	if ((fp = kmalloc(sizeof (sca_file_private_t), GFP_KERNEL)) == NULL) {
		return (-ENOMEM);
	}

	/* Initialize all the private fields */
	memset(fp, 0, sizeof (sca_file_private_t));
	spin_lock_init(&fp->fp_lock);

	/* Associate the private data structure to the file descriptor */
	filp->private_data = (void *)fp;

	spin_lock_irqsave(&g_sca_lock, lock_flags);

	++g_sca_handles_in_use;

	spin_unlock_irqrestore(&g_sca_lock, lock_flags);

	return (0);
}

/*
 * Free all sessions before freeing the private data structure and
 * closing the file descriptor.
 */
static int
sca_release(struct inode *inode, struct file *filp)
{
	sca_session_t *sp;
	uint_t i;
	sca_file_private_t *fp;
	unsigned long lock_flags;

	fp = filp->private_data;
	if (fp == NULL)
		return (EINVAL);

	spin_lock(&fp->fp_lock);

	/* free all session table entries starting with 1 */
	for (i = 1; i < fp->fp_session_table_count; i++) {
		if (fp->fp_session_table[i] == NULL)
			continue;

		sp = fp->fp_session_table[i];
		sca_free_session(fp, sp, i);
	}

	/* free the session table */
	if (fp->fp_session_table != NULL && fp->fp_session_table_count > 0)
		kmem_free(fp->fp_session_table,
		    fp->fp_session_table_count * sizeof (void *));

	/*
	 * Close all provider sessions since the file descriptor
	 * has been closed
	 */
	sca_close_provider_session(fp);

	spin_unlock(&fp->fp_lock);

	kfree(fp);
	filp->private_data = NULL;

	spin_lock_irqsave(&g_sca_lock, lock_flags);

	g_sca_handles_in_use--;

	spin_unlock_irqrestore(&g_sca_lock, lock_flags);

	return (0);
}


/* ioctl entry should return PKCS11 error code */
static int
sca_get_slot_list(struct inode *inode, struct file *filp, unsigned long arg)
{
	GetSlotList_Args get_slot_list;
	uint_t slot_count;
	uint_t req_count;
	CK_SLOT_ID_32 slot_list[MAX_NUMBER_PROVIDER];

	SCA_DBG_PRINT("sca_get_slot_list: enter\n");

	if (copy_from_user(&get_slot_list, (void *) arg,
	    sizeof (get_slot_list)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	SCA_DBG_PRINT("sca_get_slot_list: req_count: %d\n",
	    get_slot_list.slot_count);

	slot_count = sca_make_slot_list(slot_list);

	/* The number of slots requested */
	req_count = get_slot_list.slot_count;

	/*
	 * Return the number of slots only if the caller does not
	 * provide storage
	 */
	if (get_slot_list.count_only) {
		get_slot_list.slot_count = slot_count;
		if (copy_to_user((void *) arg, &get_slot_list,
		    sizeof (get_slot_list)) != 0) {
			return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
		}
		return (sca_rc[CRYPTO_SUCCESS]);
	}

	/*
	 * check if buffer is too small. If so, return the number of slots only.
	 */
	if (slot_count > req_count) {
		get_slot_list.slot_count = slot_count;
		if (copy_to_user((void *) arg, &get_slot_list,
		    sizeof (get_slot_list)) != 0) {
			return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
		}
		return (sca_rc[CRYPTO_BUFFER_TOO_SMALL]);
	}

	/*
	 * Return the number of slots and the slot numbers
	 */
	get_slot_list.slot_count = slot_count;
	if (copy_to_user((caddr_t)arg + sizeof (get_slot_list), slot_list,
	    sizeof (CK_SLOT_ID_32) * slot_count) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	SCA_DBG_PRINT("slot_count: %d\n", (int)get_slot_list.slot_count);
	if (copy_to_user((void *) arg, &get_slot_list,
	    sizeof (get_slot_list)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	SCA_DBG_PRINT("sca_get_slot_list: done!\n");

	return (sca_rc[CRYPTO_SUCCESS]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_get_slot_info(struct inode *inode, struct file *filp, unsigned long arg)
{
	GetSlotInfo_Args get_slot_info;
	uint_t slot_id;
	unsigned long lock_flags;
	CK_SLOT_INFO_32 new_slot_info;
	crypto_provider_info_t *prov_info;

	SCA_DBG_PRINT("sca_get_slot_info: enter.\n");

	if (copy_from_user(&get_slot_info, (void *) arg,
	    sizeof (get_slot_info)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	/* The global lock is used here since no need to call the provider */
	spin_lock_irqsave(&g_sca_lock, lock_flags);

	if (get_slot_info.slot_id >= g_sca_provider_count) {
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		return (sca_rc[CRYPTO_INVALID_PROVIDER_ID]);
	}

	slot_id = g_sca_index[get_slot_info.slot_id];
	memset(&new_slot_info, 0, sizeof (new_slot_info));

	if (g_sca_provider_array[slot_id] == NULL) {
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		return (sca_rc[CRYPTO_INVALID_PROVIDER_ID]);
	}

	/* Provider description is the slot description */
	prov_info = g_sca_provider_array[slot_id]->sp_info;
	memcpy(new_slot_info.slotDescription,
	    prov_info->pi_provider_description, CRYPTO_PROVIDER_DESCR_MAX_LEN);

	/* Manufacture ID is "SUNW" padded with blanks */
	memset(new_slot_info.manufacturerID, ' ', 32);
	memcpy(new_slot_info.manufacturerID, "SUNW", 4);

	/*
	 * Token is always present and it is always non-removable.
	 * A real provider is a hardware slot and a logical slot is not
	 * a hardware slot in order to distinguish the two kind.
	 */
	if (prov_info->pi_provider_type == CRYPTO_LOGICAL_PROVIDER)
		new_slot_info.flags = CKF_TOKEN_PRESENT;
	else
		new_slot_info.flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;

	memcpy(&get_slot_info.slot_info, &new_slot_info,
	    sizeof (new_slot_info));

	if (copy_to_user((void *)arg, &get_slot_info,
	    sizeof (get_slot_info)) != 0) {
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	spin_unlock_irqrestore(&g_sca_lock, lock_flags);

	SCA_DBG_PRINT("sca_get_slot_info: done.\n");

	return (sca_rc[CRYPTO_SUCCESS]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_get_token_info(struct inode *inode, struct file *filp, unsigned long arg)
{
	GetTokenInfo_Args get_token_info;
	CK_TOKEN_INFO_32 token_info;
	crypto_provider_handle_t *ph;
	sca_provider_t *provider, *real = NULL;
	crypto_provider_ext_info_t ext_info;
	crypto_ops_t *ops_vector = NULL;
	CK_SLOT_ID slot_id;
	unsigned long lock_flags;
	int rv;

	SCA_DBG_PRINT("sca_get_token_info: enter\n");

	if (copy_from_user(&get_token_info, (caddr_t)arg,
	    sizeof (get_token_info)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	spin_lock_irqsave(&g_sca_lock, lock_flags);

	if (get_token_info.slot_id >= g_sca_provider_count) {
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		return (sca_rc[CRYPTO_INVALID_PROVIDER_ID]);
	}

	slot_id = g_sca_index[get_token_info.slot_id];

	if (g_sca_provider_array[slot_id] == NULL) {
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		return (sca_rc[CRYPTO_INVALID_PROVIDER_ID]);
	}

	provider = g_sca_provider_array[slot_id];
	if (provider == NULL) {
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		return (sca_rc[CRYPTO_INVALID_PROVIDER_ID]);
	}

	/* Use the provider handle whether it is real or logical */
	ph = provider->sp_info->pi_provider_handle;

	spin_unlock_irqrestore(&g_sca_lock, lock_flags);

	SCA_GET_OPS_PROV(provider, real, ops_vector,
	    co_provider_ops, ext_info, rv);

	if (rv != CRYPTO_SUCCESS)
		return (sca_rc[rv]);

	if ((rv = ops_vector->co_provider_ops->ext_info(ph, &ext_info,
	    NULL)) != CRYPTO_SUCCESS) {
		SCA_PROVIDER_RELE(real);
		return (sca_rc[rv]);
	}

	/* Release the reference to the provider after using it */
	SCA_PROVIDER_RELE(real);

	memcpy(token_info.label, ext_info.ei_label, 32);
	memcpy(token_info.manufacturerID, ext_info.ei_manufacturerID, 32);
	memcpy(token_info.model, ext_info.ei_model, 16);
	memcpy(token_info.serialNumber, ext_info.ei_serial_number, 16);
	token_info.flags = ext_info.ei_flags;

	token_info.ulMaxSessionCount = ext_info.ei_max_session_count;
	token_info.ulSessionCount = (int)CRYPTO_UNAVAILABLE_INFO;
	token_info.ulMaxRwSessionCount = (int)CRYPTO_UNAVAILABLE_INFO;
	token_info.ulRwSessionCount = (int)CRYPTO_UNAVAILABLE_INFO;
	token_info.ulMaxPinLen = ext_info.ei_max_pin_len;
	token_info.ulMinPinLen = ext_info.ei_min_pin_len;
	token_info.ulTotalPublicMemory = ext_info.ei_total_public_memory;
	token_info.ulFreePublicMemory = ext_info.ei_free_public_memory;
	token_info.ulTotalPrivateMemory = ext_info.ei_total_private_memory;
	token_info.ulFreePrivateMemory = ext_info.ei_free_private_memory;

	memcpy(&token_info.hardwareVersion, &ext_info.ei_hardware_version,
	    sizeof (CK_VERSION));
	memcpy(&token_info.firmwareVersion, &ext_info.ei_firmware_version,
	    sizeof (CK_VERSION));
	memcpy(token_info.utcTime, ext_info.ei_time, 16);

	memcpy(&get_token_info.token_info, &token_info, sizeof (token_info));

	if (copy_to_user((void *)arg, &get_token_info,
	    sizeof (get_token_info)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	SCA_DBG_PRINT("sca_get_token_info: done\n");

	return (sca_rc[CRYPTO_SUCCESS]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_get_mechanism_list(struct inode *inode, struct file *filp,
    unsigned long arg)
{
	GetMechList_Args get_mech;
	size_t copyout_size;
	uint_t req_count;
	sca_provider_t *provider;
	uint_t mech_list_count;
	CK_MECHANISM_TYPE_32 mechanisms[128];
	CK_SLOT_ID slot_id;
	CK_BYTE *ptr;
	unsigned long lock_flags;

	SCA_DBG_PRINT("sca_get_mechanism_list: enter\n");

	if (copy_from_user(&get_mech, (void *) arg, sizeof (get_mech)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	spin_lock_irqsave(&g_sca_lock, lock_flags);

	if (get_mech.slot_id >= g_sca_provider_count) {
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		return (sca_rc[CRYPTO_INVALID_PROVIDER_ID]);
	}

	/* Mechanisms from the given slot */
	slot_id = g_sca_index[get_mech.slot_id];

	if (g_sca_provider_array[slot_id] == NULL) {
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		return (sca_rc[CRYPTO_INVALID_PROVIDER_ID]);
	}

	provider = g_sca_provider_array[slot_id];
	mech_list_count = sca_make_mechanism_list(provider, mechanisms);

	spin_unlock_irqrestore(&g_sca_lock, lock_flags);

	/* Number of mechs caller thinks we have */
	req_count = get_mech.list_length;

	SCA_DBG_PRINT("sca_get_mechanism_list: mech_count: %d, req_count: %d\n",
	    mech_list_count, req_count);

	/* Check if caller is just requesting a count of mechanisms */
	if (req_count == 0) {
		get_mech.list_length = mech_list_count;
		if (copy_to_user((void *) arg, &get_mech,
		    sizeof (get_mech)) != 0) {
			return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
		}
		return (sca_rc[CRYPTO_SUCCESS]);
	}

	/* check if buffer is too small */
	if (mech_list_count > req_count) {
		get_mech.list_length = mech_list_count;
		if (copy_to_user((void *) arg, &get_mech,
		    sizeof (get_mech)) != 0) {
			return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
		}
		return (sca_rc[CRYPTO_BUFFER_TOO_SMALL]);
	}

	get_mech.list_length = mech_list_count;
	copyout_size = mech_list_count * sizeof (CK_MECHANISM_TYPE_32);

	ptr = (CK_BYTE *)arg;
	ptr += sizeof (get_mech);
	/* copyout mechs to the end */
	if (copy_to_user(ptr, mechanisms, copyout_size) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	/* copyout the number of mechs */
	if (copy_to_user((void *) arg, &get_mech, sizeof (get_mech)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	SCA_DBG_PRINT("sca_get_mechanism_list: done!\n");

	return (sca_rc[CRYPTO_SUCCESS]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_get_mechanism_info(struct inode *inode, struct file *filp,
    unsigned long arg)
{
	GetMechInfo_Args mech_info;
	sca_provider_t *provider, *hp;
	crypto_provider_info_t *pi;
	uint_t mech_list_count;
	crypto_mech_info_t *mech_list;
	crypto_mech_info_t *mech_ptr;
	CK_MECHANISM_TYPE mech_type;
	CK_SLOT_ID slot_id;
	unsigned long lock_flags;
	int i, j;

	SCA_DBG_PRINT("sca_get_mechanism_info: enter\n");

	if (copy_from_user(&mech_info, (caddr_t)arg,
	    sizeof (mech_info)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	spin_lock_irqsave(&g_sca_lock, lock_flags);

	if (mech_info.slot_id >= g_sca_provider_count) {
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		return (sca_rc[CRYPTO_INVALID_PROVIDER_ID]);
	}

	/* Mechanisms from the given slot */
	mech_type = mech_info.mech_type;
	slot_id = g_sca_index[mech_info.slot_id];

	if (slot_id < 0 || slot_id >= g_sca_provider_count ||
	    g_sca_provider_array[slot_id] == NULL) {
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		return (sca_rc[CRYPTO_INVALID_PROVIDER_ID]);
	}

	provider = g_sca_provider_array[slot_id];
	pi = provider->sp_info;

	/* Find the mechanism from the provider(s) */
	mech_ptr = NULL;
	if (pi->pi_provider_type == CRYPTO_LOGICAL_PROVIDER &&
	    pi->pi_mechanisms == NULL) {
		/*
		 * Search its hardware providers if a logical provider
		 * does not have a mechanism list.
		 */
		for (j = 0; j < provider->sp_hp_count; j++) {
			hp = provider->sp_hp_list[j];
			mech_list_count = hp->sp_info->pi_mech_list_count;
			mech_list = hp->sp_info->pi_mechanisms;
			for (i = 0; i < mech_list_count; i++) {
				if (mech_type == mech_list[i].cm_mech_number &&
				    (mech_list[i].cm_func_group_mask &
				    g_sca_userland_flags)) {
					mech_ptr = &mech_list[i];
					break;
				}
			}

			if (i < mech_list_count)
				break;
		}
	} else {
		mech_list_count = provider->sp_info->pi_mech_list_count;
		mech_list = provider->sp_info->pi_mechanisms;
		for (i = 0; i < mech_list_count; i++) {
			if (mech_type == mech_list[i].cm_mech_number &&
			    (mech_list[i].cm_func_group_mask &
			    g_sca_userland_flags)) {
				mech_ptr = &mech_list[i];
				break;
			}
		}
	}

	spin_unlock_irqrestore(&g_sca_lock, lock_flags);

	if (mech_ptr == NULL)
		return (sca_rc[CRYPTO_MECHANISM_INVALID]);

	mech_info.mech_info.ulMinKeySize = mech_ptr->cm_min_key_length;
	mech_info.mech_info.ulMaxKeySize = mech_ptr->cm_max_key_length;
	/*
	 * Transform CRYPTO flags to CKF flags. They differ by 8 bits.
	 * The following are defined in PKCS11:
	 *
	 * #define CKF_ENCRYPT			0x00000100
	 * #define CKF_DECRYPT			0x00000200
	 * #define CKF_DIGEST			0x00000400
	 * #define CKF_SIGN			0x00000800
	 * #define CKF_SIGN_RECOVER		0x00001000
	 * #define CKF_VERIFY			0x00002000
	 * #define CKF_VERIFY_RECOVER		0x00004000
	 * #define CKF_GENERATE			0x00008000
	 * #define CKF_GENERATE_KEY_PAIR	0x00010000
	 * #define CKF_WRAP			0x00020000
	 * #define CKF_UNWRAP			0x00040000
	 * #define CKF_DERIVE			0x00080000
	 * #define CKF_EC_F_P			0x00100000
	 * #define CKF_EC_F_2M			0x00200000
	 * #define CKF_EC_ECPARAMETERS		0x00400000
	 * #define CKF_EC_NAMEDCURVE		0x00800000
	 * #define CKF_EC_UNCOMPRESS		0x01000000
	 * #define CKF_EC_COMPRESS		0x02000000
	 * #define CKF_EXTENSION		0x80000000
	 *
	 * The following are defined in SPI:
	 *
	 * #define CRYPTO_FG_ENCRYPT			0x00000001
	 * #define CRYPTO_FG_DECRYPT			0x00000002
	 * #define CRYPTO_FG_DIGEST			0x00000004
	 * #define CRYPTO_FG_SIGN			0x00000008
	 * #define CRYPTO_FG_SIGN_RECOVER		0x00000010
	 * #define CRYPTO_FG_VERIFY			0x00000020
	 * #define CRYPTO_FG_VERIFY_RECOVER		0x00000040
	 * #define CRYPTO_FG_GENERATE			0x00000080
	 * #define CRYPTO_FG_GENERATE_KEY_PAIR		0x00000100
	 * #define CRYPTO_FG_WRAP			0x00000200
	 * #define CRYPTO_FG_UNWRAP			0x00000400
	 * #define CRYPTO_FG_DERIVE			0x00000800
	 * #define CRYPTO_FG_MAC			0x00001000
	 * #define CRYPTO_FG_ENCRYPT_MAC		0x00002000
	 * #define CRYPTO_FG_MAC_DECRYPT		0x00004000
	 * #define CRYPTO_FG_ENCRYPT_ATOMIC		0x00008000
	 * #define CRYPTO_FG_DECRYPT_ATOMIC		0x00010000
	 * #define CRYPTO_FG_MAC_ATOMIC			0x00020000
	 * #define CRYPTO_FG_DIGEST_ATOMIC		0x00040000
	 * #define CRYPTO_FG_SIGN_ATOMIC		0x00080000
	 * #define CRYPTO_FG_SIGN_RECOVER_ATOMIC	0x00100000
	 * #define CRYPTO_FG_VERIFY_ATOMIC		0x00200000
	 * #define CRYPTO_FG_VERIFY_RECOVER_ATOMIC	0x00400000
	 * #define CRYPTO_FG_ENCRYPT_MAC_ATOMIC		0x00800000
	 * #define CRYPTO_FG_MAC_DECRYPT_ATOMIC		0x01000000
	 * #define CRYPTO_FG_RESERVED			0x80000000
	 *
	 * The ones are useful for us are up to CKF_DERIVE or CRYPTO_FG_DERIVE.
	 * The rest are not used in the userland.
	 * Also need to mask off the atomic operations since they are not
	 * available in the userland.
	 */
	mech_info.mech_info.flags =
	    mech_ptr->cm_func_group_mask & g_sca_userland_flags;
	mech_info.mech_info.flags = mech_info.mech_info.flags << 8;
	if (mech_ptr->cm_func_group_mask & CRYPTO_FG_RESERVED)
		mech_info.mech_info.flags =
		    mech_info.mech_info.flags | CKF_EXTENSION;

	/* Set the hardware provider bit since it is a hardware provider */
	mech_info.mech_info.flags = mech_info.mech_info.flags | CKF_HW;

	/* Copy the mechanism info to the userland */
	if (copy_to_user((void *)arg,
	    &mech_info, sizeof (GetMechInfo_Args)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	SCA_DBG_PRINT("sca_get_mechanism_info: done!\n");

	return (sca_rc[CRYPTO_SUCCESS]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_encrypt_init(struct inode *inode, struct file *filp, unsigned long arg)
{
	EncryptInit_Args encrypt_init;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real = NULL;
	int rv;

	SCA_DBG_PRINT("sca_encrypt_init: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_encrypt_init: failed finding private");

	if (copy_from_user(&encrypt_init, (caddr_t)arg,
	    sizeof (encrypt_init)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(encrypt_init.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS_MECH(sp, real, ops_vector, psid, co_cipher_ops,
	    encrypt_init, encrypt_init.mech_type)

	rv = sca_cipher_init(arg, &encrypt_init, sp, real,
	    ops_vector, psid, ops_vector->co_cipher_ops->encrypt_init);

	if (rv != CRYPTO_SUCCESS)
		SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_encrypt_init: done: rv: %d\n", rv);

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_decrypt_init(struct inode *inode, struct file *filp, unsigned long arg)
{
	EncryptInit_Args decrypt_init;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real = NULL;
	int rv;

	SCA_DBG_PRINT("sca_decrypt_init: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_decrypt_init: failed finding private");

	if (copy_from_user(&decrypt_init, (caddr_t)arg,
	    sizeof (decrypt_init)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(decrypt_init.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS_MECH(sp, real, ops_vector, psid, co_cipher_ops,
	    decrypt_init, decrypt_init.mech_type)

	rv = sca_cipher_init(arg, &decrypt_init, sp, real,
	    ops_vector, psid, ops_vector->co_cipher_ops->decrypt_init);

	if (rv != CRYPTO_SUCCESS)
		SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_decrypt_init: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_encrypt(struct inode *inode, struct file *filp, unsigned long arg)
{
	Encrypt_Args encrypt;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	int rv;

	SCA_DBG_PRINT("sca_encrypt: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_encrypt: failed finding private");

	if (copy_from_user(&encrypt, (caddr_t)arg, sizeof (encrypt)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(encrypt.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	if ((rv = sca_get_ops_from_ctx(sp->ss_encr_ctx, &ops_vector,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[rv]);
	}

	if (ops_vector->co_cipher_ops->encrypt == NULL) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[CRYPTO_NOT_SUPPORTED]);
	}

	rv = sca_cipher(arg, &encrypt, sp, ops_vector,
	    ops_vector->co_cipher_ops->encrypt);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_encrypt: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_decrypt(struct inode *inode, struct file *filp, unsigned long arg)
{
	Encrypt_Args decrypt;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	int rv;

	SCA_DBG_PRINT("sca_decrypt: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_decrypt: failed finding private");

	if (copy_from_user(&decrypt, (caddr_t)arg, sizeof (decrypt)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(decrypt.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	if ((rv = sca_get_ops_from_ctx(sp->ss_decr_ctx, &ops_vector,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[rv]);
	}

	if (ops_vector->co_cipher_ops->decrypt == NULL) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[CRYPTO_NOT_SUPPORTED]);
	}

	rv = sca_cipher(arg, &decrypt, sp, ops_vector,
	    ops_vector->co_cipher_ops->decrypt);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_decrypt: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_encrypt_update(struct inode *inode, struct file *filp, unsigned long arg)
{
	EncryptUpdate_Args encrypt_update;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	int rv;

	SCA_DBG_PRINT("sca_encrypt_update: enter\n");

	SCA_GET_PRIVATE(cm, filp, "sca_encrypt_update: failed finding private");

	if (copy_from_user(&encrypt_update, (caddr_t)arg,
	    sizeof (encrypt_update)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(encrypt_update.session_handle, cm,
	    &sp)) != CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	if ((rv = sca_get_ops_from_ctx(sp->ss_encr_ctx, &ops_vector,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[rv]);
	}

	if (ops_vector->co_cipher_ops->encrypt_update == NULL) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[CRYPTO_NOT_SUPPORTED]);
	}

	rv = sca_cipher_update(arg, &encrypt_update, sp, ops_vector,
	    ops_vector->co_cipher_ops->encrypt_update);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_encrypt_update: done\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_decrypt_update(struct inode *inode, struct file *filp, unsigned long arg)
{
	EncryptUpdate_Args decrypt_update;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	int rv;

	SCA_DBG_PRINT("sca_decrypt_update: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_decrypt_update: failed finding private");

	if (copy_from_user(&decrypt_update, (caddr_t)arg,
	    sizeof (decrypt_update)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(decrypt_update.session_handle, cm,
	    &sp)) != CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	if ((rv = sca_get_ops_from_ctx(sp->ss_decr_ctx, &ops_vector,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[rv]);
	}

	if (ops_vector->co_cipher_ops->decrypt_update == NULL) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[CRYPTO_NOT_SUPPORTED]);
	}

	rv = sca_cipher_update(arg, &decrypt_update, sp, ops_vector,
	    ops_vector->co_cipher_ops->decrypt_update);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_decrypt_update: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_encrypt_final(struct inode *inode, struct file *filp, unsigned long arg)
{
	EncryptFinal_Args encrypt_final;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	int rv;

	SCA_DBG_PRINT("sca_encrypt_final: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_encrypt_final: failed finding private");

	if (copy_from_user(&encrypt_final, (caddr_t)arg,
	    sizeof (encrypt_final)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(encrypt_final.session_handle, cm, &sp))
	    != CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	if ((rv = sca_get_ops_from_ctx(sp->ss_encr_ctx, &ops_vector,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[rv]);
	}

	if (ops_vector->co_cipher_ops->encrypt_final == NULL) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[CRYPTO_NOT_SUPPORTED]);
	}

	rv = sca_common_final(arg, &encrypt_final, sp, ops_vector,
	    ops_vector->co_cipher_ops->encrypt_final);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_encrypt_final: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_decrypt_final(struct inode *inode, struct file *filp, unsigned long arg)
{
	EncryptFinal_Args decrypt_final;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	int rv;

	SCA_DBG_PRINT("sca_decrypt_final: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_decrypt_final: failed finding private");

	if (copy_from_user(&decrypt_final, (caddr_t)arg,
	    sizeof (decrypt_final)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(decrypt_final.session_handle, cm, &sp))
	    != CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	if ((rv = sca_get_ops_from_ctx(sp->ss_decr_ctx, &ops_vector,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[rv]);
	}

	if (ops_vector->co_cipher_ops->decrypt_final == NULL) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[CRYPTO_NOT_SUPPORTED]);
	}

	rv = sca_common_final(arg, &decrypt_final, sp, ops_vector,
	    ops_vector->co_cipher_ops->decrypt_final);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_decrypt_final: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_digest_init(struct inode *inode, struct file *filp, unsigned long arg)
{
	DigestInit_Args digest_init;
	crypto_mechanism_t mech;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real = NULL;
	int rv;

	SCA_DBG_PRINT("sca_digest_init: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_digest_init: failed finding private");

	if (copy_from_user(&digest_init, (caddr_t)arg,
	    sizeof (digest_init)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(digest_init.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS_MECH(sp, real, ops_vector, psid, co_digest_ops, digest_init,
	    digest_init.mech_type)

	mech.cm_param = NULL;
	mech.cm_type = digest_init.mech_type;
	mech.cm_param_len = digest_init.param_len;
	if ((rv = sca_copyin_mech((caddr_t)arg + sizeof (digest_init), &mech))
	    != CRYPTO_SUCCESS)
		goto release_job;

	if (sp->ss_digest_ctx == NULL) {
		if ((sp->ss_digest_ctx = kmalloc(sizeof (crypto_ctx_t),
		    GFP_KERNEL)) == NULL) {
			rv = CRYPTO_HOST_MEMORY;
			goto release_job;
		}
	} else {
		/*
		 * Make sure to free the provider ctx and release its
		 * reference when reusing a context.
		 */
		ops_vector->co_ctx_ops->free_context(sp->ss_digest_ctx);
		SCA_PROVIDER_RELE(sp->ss_digest_ctx->cc_framework_private);
	}

	memset(sp->ss_digest_ctx, 0, sizeof (crypto_ctx_t));
	sp->ss_digest_ctx->cc_provider = real->sp_info->pi_provider_handle;
	sp->ss_digest_ctx->cc_session = psid;
	sp->ss_digest_ctx->cc_framework_private = real;
	rv = ops_vector->co_digest_ops->digest_init(sp->ss_digest_ctx, &mech,
	    sp);

release_job:

	if (rv != CRYPTO_SUCCESS) {
		SCA_PROVIDER_RELE(real);
		kfree(sp->ss_digest_ctx);
		sp->ss_digest_ctx = NULL;
	}

	SCA_SESSION_RELE(sp);

	if (mech.cm_param != NULL)
		kfree(mech.cm_param);

	SCA_DBG_PRINT("sca_digest_init: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_digest_update(struct inode *inode, struct file *filp, unsigned long arg)
{
	DigestUpdate_Args digest_update;
	crypto_data_t data;
	size_t datalen;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	int rv;

	SCA_DBG_PRINT("sca_digest_update: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_digest_update: failed finding private");

	if (copy_from_user(&digest_update, (caddr_t)arg,
	    sizeof (digest_update)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(digest_update.session_handle, cm, &sp))
	    != CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	if ((rv = sca_get_ops_from_ctx(sp->ss_digest_ctx, &ops_vector,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[rv]);
	}

	if (ops_vector->co_digest_ops->digest_update == NULL) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[CRYPTO_NOT_SUPPORTED]);
	}

	data.cd_format = CRYPTO_DATA_RAW;
	data.cd_raw.iov_base = NULL;

	datalen = digest_update.data_len;
	if (datalen > crypto_max_buffer_len) {
		printk(KERN_ALERT "sca_digest_update: buffer greater than %ld "
		    "bytes, pid = %d\n", crypto_max_buffer_len, current->pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	data.cd_raw.iov_len = datalen;
	if ((data.cd_raw.iov_base = kmalloc(datalen, GFP_KERNEL)) == NULL) {
		rv = CRYPTO_HOST_MEMORY;
		goto release_job;
	}

	if (datalen != 0 && copy_from_user(data.cd_raw.iov_base,
	    (caddr_t)arg + sizeof (digest_update), datalen) != 0) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	data.cd_offset = 0;
	data.cd_length = datalen;

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_digest_ops->digest_update(sp->ss_digest_ctx,
	    &data, sp);

	/* Determine whether to wait for this job. Will wait only if needed */
	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

release_job:

	if (rv != CRYPTO_SUCCESS) {
		SCA_PROVIDER_RELE(sp->ss_digest_ctx->cc_framework_private);
		ops_vector->co_ctx_ops->free_context(sp->ss_digest_ctx);
		kfree(sp->ss_digest_ctx);
		sp->ss_digest_ctx = NULL;
	}

	SCA_SESSION_RELE(sp);

	if (data.cd_raw.iov_base != NULL)
		kfree(data.cd_raw.iov_base);

	SCA_DBG_PRINT("sca_digest_update: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_digest_key(struct inode *inode, struct file *filp, unsigned long arg)
{
	DigestKey_Args digest_key;
	crypto_key_t key;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	int rv;

	SCA_DBG_PRINT("sca_digest_key: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_digest_key: failed finding private");

	if (copy_from_user(&digest_key, (caddr_t)arg,
	    sizeof (digest_key)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(digest_key.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	if ((rv = sca_get_ops_from_ctx(sp->ss_digest_ctx, &ops_vector,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[rv]);
	}

	if (ops_vector->co_digest_ops->digest_key == NULL) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[CRYPTO_NOT_SUPPORTED]);
	}

	memset(&key, 0, sizeof (crypto_key_t));
	key.ck_format = CRYPTO_KEY_REFERENCE;
	key.ck_obj_id = OBJ_HANDLE_DEC(digest_key.key);

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_digest_ops->digest_key(sp->ss_digest_ctx, &key, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

release_job:

	if (rv != CRYPTO_SUCCESS) {
		SCA_PROVIDER_RELE(sp->ss_digest_ctx->cc_framework_private);
		ops_vector->co_ctx_ops->free_context(sp->ss_digest_ctx);
		kfree(sp->ss_digest_ctx);
		sp->ss_digest_ctx = NULL;
	}

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_digest_key: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_digest_final(struct inode *inode, struct file *filp, unsigned long arg)
{
	EncryptFinal_Args digest_final;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	int rv;

	SCA_DBG_PRINT("sca_digest_final: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_digest_final: failed finding private");

	if (copy_from_user(&digest_final, (caddr_t)arg,
	    sizeof (digest_final)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(digest_final.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	if ((rv = sca_get_ops_from_ctx(sp->ss_digest_ctx, &ops_vector,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[rv]);
	}

	if (ops_vector->co_digest_ops->digest_final == NULL) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[CRYPTO_NOT_SUPPORTED]);
	}

	SCA_DBG_PRINT("sca_digest_final: done.\n");

	rv = sca_common_final(arg, &digest_final, sp, ops_vector,
	    ops_vector->co_digest_ops->digest_final);

	SCA_SESSION_RELE(sp);

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_digest(struct inode *inode, struct file *filp, unsigned long arg)
{
	Digest_Args digest;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	int rv;

	SCA_DBG_PRINT("sca_digest: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_digest: failed finding private");

	if (copy_from_user(&digest, (caddr_t)arg, sizeof (digest)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(digest.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	if ((rv = sca_get_ops_from_ctx(sp->ss_digest_ctx, &ops_vector,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[rv]);
	}

	if (ops_vector->co_digest_ops->digest == NULL) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[CRYPTO_NOT_SUPPORTED]);
	}

	SCA_DBG_PRINT("sca_digest: done.\n");

	rv = sca_common_digest(arg, &digest, sp, ops_vector,
	    ops_vector->co_digest_ops->digest);

	SCA_SESSION_RELE(sp);

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_set_pin(struct inode *inode, struct file *filp, unsigned long arg)
{
	SetPIN_Args set_pin;
	sca_file_private_t *cm;
	crypto_provider_handle_t *ph;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real;
	int rv;

	SCA_DBG_PRINT("sca_set_pin: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_set_pin: failed finding private");

	if (copy_from_user(&set_pin, (caddr_t)arg, sizeof (set_pin)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(set_pin.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS(sp, real, ops_vector, ph, psid, co_provider_ops, set_pin)

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_provider_ops->set_pin(ph, psid, set_pin.old_pin,
	    set_pin.old_pin_len, set_pin.new_pin, set_pin.new_pin_len, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

release_job:

	SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_set_pin: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_open_session(struct inode *inode, struct file *filp, unsigned long arg)
{
	OpenSession_Args open_session;
	uint_t flags;
	crypto_provider_id_t provider_id;
	sca_session_t **session_table;
	sca_session_t *sp;
	sca_file_private_t *cm;
	uint_t session_table_count;
	uint_t i;
	int rv;
	sca_provider_session_t *ps;

	SCA_DBG_PRINT("sca_open_session: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_open_session: failed finding private");

	if (copy_from_user(&open_session, (caddr_t)arg,
	    sizeof (open_session)) != 0)
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);

	if (open_session.slot_id >= g_sca_provider_count)
		return (sca_rc[CRYPTO_INVALID_PROVIDER_ID]);

	flags = open_session.flags;
	provider_id = g_sca_index[open_session.slot_id];

	if ((rv = sca_get_provider_session(cm, provider_id, &ps)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	/* Allocate memory outside of the spinlock */
	if ((sp = kmalloc(sizeof (sca_session_t), GFP_KERNEL)) == NULL) {
		sca_release_provider_session(cm, ps);
		return (sca_rc[CRYPTO_HOST_MEMORY]);
	}
	memset(sp, 0, sizeof (sca_session_t));

	spin_lock(&cm->fp_lock);

again:
	session_table_count = cm->fp_session_table_count;
	session_table = cm->fp_session_table;

	/* session handles start with 1 */
	for (i = 1; i < session_table_count; i++) {
		if (session_table[i] == NULL)
			break;
	}

	if (i == session_table_count || session_table_count == 0) {
		if ((rv = sca_grow_session_table(cm)) != CRYPTO_SUCCESS) {
			spin_unlock(&cm->fp_lock);
			sca_release_provider_session(cm, ps);
			kfree(sp);
			return (sca_rc[rv]);
		}
		goto again;
	}

	sp->ss_provider_session = ps;
	spin_lock_init(&sp->ss_lock);
	init_waitqueue_head(&sp->ss_busy_wait);
	init_waitqueue_head(&sp->ss_wait);

	cm->fp_session_table[i] = sp;

	spin_unlock(&cm->fp_lock);

	open_session.session_handle = i;

	if (copy_to_user((caddr_t)arg, &open_session,
	    sizeof (open_session)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	SCA_DBG_PRINT("sca_open_session: done.\n");

	return (sca_rc[CRYPTO_SUCCESS]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_close_session(struct inode *inode, struct file *filp, unsigned long arg)
{
	CloseSession_Args close_session;
	sca_session_t **session_table;
	sca_session_t *sp;
	sca_file_private_t *cm;
	crypto_session_id_t session_index;

	SCA_DBG_PRINT("sca_close_session: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_close_session: failed finding private");

	if (copy_from_user(&close_session, (caddr_t)arg,
	    sizeof (close_session)) != 0)
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);

	session_index = close_session.session_handle;

	spin_lock(&cm->fp_lock);
	session_table = cm->fp_session_table;

	if ((session_index) == 0 ||
	    (session_index >= cm->fp_session_table_count)) {
		spin_unlock(&cm->fp_lock);
		return (sca_rc[CRYPTO_SESSION_HANDLE_INVALID]);
	}

	sp = session_table[session_index];
	if (sp == NULL) {
		spin_unlock(&cm->fp_lock);
		return (sca_rc[CRYPTO_SESSION_HANDLE_INVALID]);
	}
	/*
	 * If session is in use, free it when the thread
	 * finishes with the session.
	 */
	spin_lock(&sp->ss_lock);
	if (sp->ss_flags & SCA_SESSION_IS_BUSY) {
		sp->ss_flags |= SCA_SESSION_IS_CLOSED;
		spin_unlock(&sp->ss_lock);
	} else {
		spin_unlock(&sp->ss_lock);
		sca_free_session(cm, sp, session_index);
	}

	spin_unlock(&cm->fp_lock);

	SCA_DBG_PRINT("sca_close_session: done.\n");

	return (sca_rc[CRYPTO_SUCCESS]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_close_all_session(struct inode *inode, struct file *filp, unsigned long arg)
{
	sca_session_t **session_table;
	sca_session_t *sp;
	sca_file_private_t *cm;
	crypto_session_id_t si;

	SCA_DBG_PRINT("sca_close_all_session: enter.\n");

	SCA_GET_PRIVATE(cm, filp,
	    "sca_close_all_session: failed finding private");

	spin_lock(&cm->fp_lock);
	session_table = cm->fp_session_table;

	for (si = 1; si < cm->fp_session_table_count; si++) {
		if ((sp = session_table[si]) == NULL)
			continue;

		/*
		 * If session is in use, free it when the thread
		 * finishes with the session.
		 */
		spin_lock(&sp->ss_lock);
		if (sp->ss_flags & SCA_SESSION_IS_BUSY) {
			sp->ss_flags |= SCA_SESSION_IS_CLOSED;
			spin_unlock(&sp->ss_lock);
		} else {
			spin_unlock(&sp->ss_lock);
			sca_free_session(cm, sp, si);
		}
	}

	/*
	 * Close all provider sessions since the C_Finalize function
	 * has been called
	 */
	sca_close_provider_session(cm);

	spin_unlock(&cm->fp_lock);

	SCA_DBG_PRINT("sca_close_all_session: done.\n");

	return (sca_rc[CRYPTO_SUCCESS]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_login(struct inode *inode, struct file *filp, unsigned long arg)
{
	Login_Args login;
	sca_file_private_t *cm;
	crypto_provider_handle_t *ph;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real;
	int rv;

	SCA_DBG_PRINT("sca_login: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_login: failed finding private");

	if (copy_from_user(&login, (caddr_t)arg, sizeof (login)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(login.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS(sp, real, ops_vector, ph, psid, co_session_ops,
	    session_login)

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_session_ops->session_login(ph, psid,
	    login.user_type, login.pin, login.pin_len, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_LONG_TIMEOUT);

release_job:

	SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_login: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_logout(struct inode *inode, struct file *filp, unsigned long arg)
{
	Logout_Args logout;
	sca_file_private_t *cm;
	crypto_provider_handle_t *ph;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real;
	int rv;

	SCA_DBG_PRINT("sca_logout: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_logout: failed finding private");

	if (copy_from_user(&logout, (caddr_t)arg, sizeof (logout)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(logout.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS(sp, real, ops_vector, ph, psid, co_session_ops,
	    session_logout)

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_session_ops->session_logout(ph, psid, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_LONG_TIMEOUT);

release_job:

	SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_logout: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_object_create(struct inode *inode, struct file *filp, unsigned long arg)
{
	CommonObject_Args object_create;
	crypto_object_attribute_t *k_attrs = NULL;
	sca_file_private_t *cm;
	crypto_object_id_t object_handle;
	caddr_t attrs;
	uint_t count;
	uint_t block_len;
	crypto_provider_handle_t *ph;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real;
	int rv;

	SCA_DBG_PRINT("sca_object_create: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_object_create: failed finding private");

	if (copy_from_user(&object_create, (caddr_t)arg,
	    sizeof (object_create)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(object_create.session_handle, cm, &sp))
	    != CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS(sp, real, ops_vector, ph, psid, co_object_ops,
	    object_create)

	count = object_create.attribute_count;
	block_len = object_create.attribute_block_len;
	attrs = (caddr_t)arg + sizeof (object_create);

	if ((rv = sca_get_attrs(count, block_len, attrs, &k_attrs)) !=
	    CRYPTO_SUCCESS) {
		goto release_job;
	}

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_object_ops->object_create(ph, psid,
	    k_attrs, count, &object_handle, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

	if (rv != CRYPTO_SUCCESS)
		goto release_job;

	object_create.object_handle = OBJ_HANDLE_INC(object_handle);
	if (copy_to_user((caddr_t)arg, &object_create,
	    sizeof (object_create)) != 0) {
		sp->ss_state = JS_RUNNING;
		rv = ops_vector->co_object_ops->object_destroy(
		    ph, psid, object_handle, sp);
		(void) sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);
		rv = CRYPTO_ARGUMENTS_BAD;
	}

release_job:

	SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	if (k_attrs != NULL)
		kfree(k_attrs);

	SCA_DBG_PRINT("sca_object_create: done: rv: 0x%x\n", rv);

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_object_copy(struct inode *inode, struct file *filp, unsigned long arg)
{
	CommonObject_Args object_copy;
	crypto_object_attribute_t *k_attrs = NULL;
	sca_file_private_t *cm;
	crypto_object_id_t new_handle;
	caddr_t attrs;
	uint_t count;
	uint_t block_len;
	crypto_provider_handle_t *ph;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real;
	int rv;

	SCA_DBG_PRINT("sca_object_copy: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_object_copy: failed finding private");

	if (copy_from_user(&object_copy, (caddr_t)arg,
	    sizeof (object_copy)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(object_copy.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS(sp, real, ops_vector, ph, psid, co_object_ops, object_copy)

	count = object_copy.attribute_count;
	block_len = object_copy.attribute_block_len;
	attrs = (caddr_t)arg + sizeof (object_copy);

	if ((rv = sca_get_attrs(count, block_len, attrs, &k_attrs)) !=
	    CRYPTO_SUCCESS) {
		goto release_job;
	}

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_object_ops->object_copy(ph, psid,
	    OBJ_HANDLE_DEC(object_copy.object_handle), k_attrs, count,
	    &new_handle, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

	if (rv != CRYPTO_SUCCESS)
		goto release_job;

	object_copy.object_handle = OBJ_HANDLE_INC(new_handle);
	if (copy_to_user((caddr_t)arg, &object_copy,
	    sizeof (object_copy)) != 0) {
		sp->ss_state = JS_RUNNING;
		rv = ops_vector->co_object_ops->object_destroy(
		    ph, psid, new_handle, sp);
		(void) sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);
		rv = CRYPTO_ARGUMENTS_BAD;
	}

release_job:

	SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	if (k_attrs != NULL)
		kfree(k_attrs);

	SCA_DBG_PRINT("sca_object_copy: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_object_destroy(struct inode *inode, struct file *filp, unsigned long arg)
{
	DestroyObject_Args destroy;
	sca_file_private_t *cm;
	crypto_provider_handle_t *ph;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real;
	int rv;

	SCA_DBG_PRINT("sca_object_destroy: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_object_destroy: failed finding private");

	if (copy_from_user(&destroy, (caddr_t)arg, sizeof (destroy)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(destroy.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS(sp, real, ops_vector, ph, psid, co_object_ops,
	    object_destroy)

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_object_ops->object_destroy(ph, psid,
	    OBJ_HANDLE_DEC(destroy.object_handle), sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

release_job:

	SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_object_destroy: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_object_get_attribute_value(struct inode *inode, struct file *filp,
    unsigned long arg)
{
	CommonObject_Args attr_value;
	crypto_object_attribute_t *k_attrs = NULL;
	sca_file_private_t *cm;
	caddr_t u_attrs;
	uint_t count;
	uint_t block_len;
	crypto_provider_handle_t *ph;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real;
	int rv, rv1;

	SCA_DBG_PRINT("sca_object_get_attribute_value: enter.\n");

	SCA_GET_PRIVATE(cm, filp,
	    "sca_object_get_attribute_value: failed finding private");
	if (copy_from_user(&attr_value, (caddr_t)arg,
	    sizeof (attr_value)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(attr_value.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS(sp, real, ops_vector, ph, psid, co_object_ops,
	    object_get_attribute_value)

	count = attr_value.attribute_count;
	block_len = attr_value.attribute_block_len;
	u_attrs = (caddr_t)arg + sizeof (attr_value);

	if ((rv = sca_get_attrs(count, block_len, u_attrs, &k_attrs)) !=
	    CRYPTO_SUCCESS) {
		goto release_job;
	}

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_object_ops->object_get_attribute_value(
	    ph, psid, OBJ_HANDLE_DEC(attr_value.object_handle), k_attrs,
	    count, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

	if (rv == CRYPTO_SUCCESS || rv == CRYPTO_ATTRIBUTE_SENSITIVE ||
	    rv == CRYPTO_ATTRIBUTE_TYPE_INVALID ||
	    rv == CRYPTO_BUFFER_TOO_SMALL) {
		if ((rv1 = sca_set_attrs(count, block_len, u_attrs, k_attrs)) !=
		    CRYPTO_SUCCESS) {
			rv = rv1;
		}
	}

release_job:

	SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	if (k_attrs != NULL)
		kfree(k_attrs);

	SCA_DBG_PRINT("sca_object_get_attribute_value: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_object_get_size(struct inode *inode, struct file *filp, unsigned long arg)
{
	GetObjectSize_Args get_size;
	sca_file_private_t *cm;
	size_t size;
	crypto_provider_handle_t *ph;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real;
	int rv;

	SCA_DBG_PRINT("sca_object_get_size: enter.\n");

	SCA_GET_PRIVATE(cm, filp,
	    "sca_object_get_size: failed finding private");

	if (copy_from_user(&get_size, (caddr_t)arg, sizeof (get_size)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(get_size.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS(sp, real, ops_vector, ph, psid, co_object_ops,
	    object_get_size)

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_object_ops->object_get_size(
	    ph, psid, OBJ_HANDLE_DEC(get_size.object_handle), &size, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

	if (rv == CRYPTO_SUCCESS) {
		get_size.size = size;
		if (copy_to_user((caddr_t)arg, &get_size,
		    sizeof (get_size)) != 0) {
			rv = CRYPTO_ARGUMENTS_BAD;
		}
	}

release_job:

	SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_object_get_size: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_object_set_attribute_value(struct inode *inode, struct file *filp,
    unsigned long arg)
{
	CommonObject_Args attr_value;
	crypto_object_attribute_t *k_attrs = NULL;
	sca_file_private_t *cm;
	uint_t count;
	crypto_provider_handle_t *ph;
	sca_session_t *sp;
	uint_t block_len;
	caddr_t attrs;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real;
	int rv;

	SCA_DBG_PRINT("sca_object_set_attribute_value: enter.\n");

	SCA_GET_PRIVATE(cm, filp,
	    "sca_object_set_attribute_value: failed finding private");

	if (copy_from_user(&attr_value, (caddr_t)arg,
	    sizeof (attr_value)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(attr_value.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS(sp, real, ops_vector, ph, psid, co_object_ops,
	    object_set_attribute_value)

	count = attr_value.attribute_count;
	block_len = attr_value.attribute_block_len;
	attrs = (caddr_t)arg + sizeof (attr_value);

	if ((rv = sca_get_attrs(count, block_len, attrs, &k_attrs)) !=
	    CRYPTO_SUCCESS) {
		goto release_job;
	}

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_object_ops->object_set_attribute_value(
	    ph, psid, OBJ_HANDLE_DEC(attr_value.object_handle), k_attrs,
	    count, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

release_job:

	SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	if (k_attrs != NULL)
		kfree(k_attrs);

	SCA_DBG_PRINT("sca_object_set_attribute_value: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_object_find_init(struct inode *inode, struct file *filp, unsigned long arg)
{
	FindObjectsInit_Args find_init;
	crypto_object_attribute_t *k_attrs = NULL;
	sca_file_private_t *cm;
	uint_t count;
	void *cookie = NULL;
	crypto_provider_handle_t *ph;
	sca_session_t *sp;
	uint_t block_len;
	caddr_t attrs;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real;
	int rv;

	SCA_DBG_PRINT("sca_object_find_init: enter.\n");

	SCA_GET_PRIVATE(cm, filp,
	    "sca_object_find_init: failed finding private");

	if (copy_from_user(&find_init, (caddr_t)arg,
	    sizeof (find_init)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(find_init.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS(sp, real, ops_vector, ph, psid, co_object_ops,
	    object_find_init)

	count = find_init.attribute_count;
	block_len = find_init.attribute_block_len;
	attrs = (caddr_t)arg + sizeof (find_init);

	if ((rv = sca_get_attrs(count, block_len, attrs, &k_attrs)) !=
	    CRYPTO_SUCCESS) {
		goto release_job;
	}

	if (sp->ss_find_init_cookie != NULL) {
		rv = CRYPTO_OPERATION_IS_ACTIVE;
		goto release_job;
	}

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	rv = ops_vector->co_object_ops->object_find_init(ph, psid,
	    k_attrs, count, &cookie, sp);

	if (rv == CRYPTO_SUCCESS) {
		/*
		 * The cookie is allocated by a provider at the start of an
		 * object search.  It is freed when the search is terminated
		 * by a final operation, or when the session is closed.
		 * It contains state information about which object handles
		 * have been returned to the caller.
		 */
		sp->ss_find_init_cookie = cookie;
	}

release_job:

	SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	if (k_attrs != NULL)
		kfree(k_attrs);

	SCA_DBG_PRINT("sca_object_find_init: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_object_find_update(struct inode *inode, struct file *filp,
    unsigned long arg)
{
	FindObjects_Args find_update;
	sca_file_private_t *cm;
	crypto_object_id_t *buffer = NULL;
	CK_OBJECT_HANDLE_32 *handle = NULL;
	size_t len;
	uint_t count, max_count;
	crypto_provider_handle_t *ph;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real;
	int rv;

	SCA_DBG_PRINT("sca_object_find_update: enter.\n");

	SCA_GET_PRIVATE(cm, filp,
	    "sca_object_find_update: failed finding private");

	if (copy_from_user(&find_update, (caddr_t)arg,
	    sizeof (find_update)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(find_update.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS(sp, real, ops_vector, ph, psid, co_object_ops, object_find)

	max_count = find_update.max_count;
	if (max_count > CRYPTO_MAX_FIND_COUNT) {
		printk(KERN_ALERT "object_find_update: count greater than %d, "
		    "pid = %d\n", CRYPTO_MAX_FIND_COUNT, current->pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	len = max_count * sizeof (crypto_object_id_t);
	if ((buffer = kmalloc(len, GFP_KERNEL)) == NULL) {
		rv = CRYPTO_HOST_MEMORY;
		goto release_job;
	}

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	rv = ops_vector->co_object_ops->object_find(ph, sp->ss_find_init_cookie,
	    buffer, max_count, &count, sp);

	if (rv == CRYPTO_SUCCESS) {
		if (count > max_count) {
			/* bad bad provider */
			rv = CRYPTO_FAILED;
			goto release_job;
		}
		if (count != 0) {
			/* copyout handles */
			int i;
			handle = (CK_OBJECT_HANDLE_32 *)
			    kmalloc(count * sizeof (CK_OBJECT_HANDLE_32),
			    GFP_KERNEL);
			if (handle == NULL) {
				rv = CRYPTO_HOST_MEMORY;
				goto release_job;
			}

			for (i = 0; i < count; i++)
				handle[i] = OBJ_HANDLE_INC(buffer[i]);

			if (copy_to_user((caddr_t)arg + sizeof (find_update),
			    handle,
			    count * sizeof (CK_OBJECT_HANDLE_32)) != 0) {
				rv = CRYPTO_ARGUMENTS_BAD;
				goto release_job;
			}
		}
		find_update.count = count;
	}

release_job:

	if (buffer != NULL)
		kfree(buffer);
	if (handle != NULL)
		kfree(handle);

	SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	if (rv == CRYPTO_SUCCESS) {
		if (copy_to_user((caddr_t)arg, &find_update,
		    sizeof (find_update)) != 0) {
			return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
		}
	}

	SCA_DBG_PRINT("sca_object_find_update: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_object_find_final(struct inode *inode, struct file *filp, unsigned long arg)
{
	FindObjectsFinal_Args find_final;
	sca_file_private_t *cm;
	crypto_provider_handle_t *ph;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real;
	int rv;

	SCA_DBG_PRINT("sca_object_find_final: enter.\n");

	SCA_GET_PRIVATE(cm, filp,
	    "sca_object_find_final: failed finding private");

	if (copy_from_user(&find_final, (caddr_t)arg,
	    sizeof (find_final)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(find_final.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS(sp, real, ops_vector, ph, psid, co_object_ops,
	    object_find_final)

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	rv = ops_vector->co_object_ops->object_find_final(
	    ph, sp->ss_find_init_cookie, sp);
	sp->ss_find_init_cookie = NULL;

release_job:

	SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_object_find_final: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_sign_init(struct inode *inode, struct file *filp, unsigned long arg)
{
	SignInit_Args sign_init;
	sca_file_private_t *cm;
	sca_session_t *sp;
	sca_provider_t *real = NULL;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	int rv;

	SCA_DBG_PRINT("sca_sign_init: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_sign_init: failed finding private");

	if (copy_from_user(&sign_init, (caddr_t)arg,
	    sizeof (sign_init)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(sign_init.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS_MECH(sp, real, ops_vector, psid, co_sign_ops, sign_init,
	    sign_init.mech_type)

	rv = sca_sign_verify_init(arg, &sign_init, sp, real, ops_vector,
	    psid, ops_vector->co_sign_ops->sign_init);

	if (rv != CRYPTO_SUCCESS)
		SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_sign_init: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_sign_recover_init(struct inode *inode, struct file *filp, unsigned long arg)
{
	SignInit_Args sign_init;
	sca_file_private_t *cm;
	sca_session_t *sp;
	sca_provider_t *real = NULL;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	int rv;

	SCA_DBG_PRINT("sca_sign_recover_init: enter.\n");

	SCA_GET_PRIVATE(cm, filp,
	    "sca_sign_recover_init: failed finding private");

	if (copy_from_user(&sign_init, (caddr_t)arg,
	    sizeof (sign_init)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(sign_init.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS_MECH(sp, real, ops_vector, psid, co_sign_ops,
	    sign_recover_init, sign_init.mech_type)

	rv = sca_sign_verify_init(arg, &sign_init, sp, real, ops_vector,
	    psid, ops_vector->co_sign_ops->sign_recover_init);

	if (rv != CRYPTO_SUCCESS)
		SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_sign_recover_init: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_verify_init(struct inode *inode, struct file *filp, unsigned long arg)
{
	SignInit_Args sign_init;
	sca_file_private_t *cm;
	sca_session_t *sp;
	sca_provider_t *real = NULL;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	int rv;

	SCA_DBG_PRINT("sca_verify_init: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_verify_init: failed finding private");

	if (copy_from_user(&sign_init, (caddr_t)arg,
	    sizeof (sign_init)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(sign_init.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS_MECH(sp, real, ops_vector, psid, co_verify_ops, verify_init,
	    sign_init.mech_type)

	rv = sca_sign_verify_init(arg, &sign_init, sp, real, ops_vector,
	    psid, ops_vector->co_verify_ops->verify_init);

	if (rv != CRYPTO_SUCCESS)
		SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_verify_init: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_verify_recover_init(struct inode *inode, struct file *filp,
    unsigned long arg)
{
	SignInit_Args sign_init;
	sca_file_private_t *cm;
	sca_session_t *sp;
	sca_provider_t *real = NULL;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	int rv;

	SCA_DBG_PRINT("sca_verify_recover_init: enter.\n");

	SCA_GET_PRIVATE(cm, filp,
	    "sca_verify_recover_init: failed finding private");

	if (copy_from_user(&sign_init, (caddr_t)arg,
	    sizeof (sign_init)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(sign_init.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS_MECH(sp, real, ops_vector, psid, co_verify_ops,
	    verify_recover_init, sign_init.mech_type)

	rv = sca_sign_verify_init(arg, &sign_init, sp, real, ops_vector,
	    psid, ops_vector->co_verify_ops->verify_recover_init);

	if (rv != CRYPTO_SUCCESS)
		SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_verify_recover_init: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_sign(struct inode *inode, struct file *filp, unsigned long arg)
{
	Digest_Args digest;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	int rv;

	SCA_DBG_PRINT("sca_sign: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_sign: failed finding private");

	if (copy_from_user(&digest, (caddr_t)arg, sizeof (digest)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(digest.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	if ((rv = sca_get_ops_from_ctx(sp->ss_sign_ctx, &ops_vector,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[rv]);
	}

	if (ops_vector->co_sign_ops->sign == NULL) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[CRYPTO_NOT_SUPPORTED]);
	}

	rv = sca_common_digest(arg, &digest, sp, ops_vector,
	    ops_vector->co_sign_ops->sign);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_sign: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_sign_recover(struct inode *inode, struct file *filp, unsigned long arg)
{
	Digest_Args digest;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	int rv;

	SCA_DBG_PRINT("sca_sign_recover: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_sign_recover: failed finding private");

	if (copy_from_user(&digest, (caddr_t)arg, sizeof (digest)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(digest.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	if ((rv = sca_get_ops_from_ctx(sp->ss_sign_recover_ctx, &ops_vector,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[rv]);
	}

	if (ops_vector->co_sign_ops->sign_recover == NULL) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[CRYPTO_NOT_SUPPORTED]);
	}

	rv = sca_common_digest(arg, &digest, sp, ops_vector,
	    ops_vector->co_sign_ops->sign_recover);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_sign_recover: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_verify(struct inode *inode, struct file *filp, unsigned long arg)
{
	Verify_Args verify;
	uint_t args_len = sizeof (Verify_Args);
	crypto_data_t data, sign;
	size_t datalen, signlen;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	int rv;

	SCA_DBG_PRINT("sca_verify: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_verify: failed finding private");

	if (copy_from_user(&verify, (caddr_t)arg, sizeof (verify)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(verify.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	if ((rv = sca_get_ops_from_ctx(sp->ss_verify_ctx, &ops_vector,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[rv]);
	}

	if (ops_vector->co_verify_ops->verify == NULL) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[CRYPTO_NOT_SUPPORTED]);
	}

	data.cd_raw.iov_base = NULL;
	sign.cd_raw.iov_base = NULL;

	datalen = verify.data_len;
	signlen = verify.signature_len;
	if (datalen > crypto_max_buffer_len ||
	    signlen > crypto_max_buffer_len) {
		printk(KERN_ALERT "sca_verify: buffer greater than %ld bytes, "
		"pid = %d\n", crypto_max_buffer_len, current->pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	if ((rv = sca_init_raw_crypto_data(&data, datalen)) != CRYPTO_SUCCESS)
		goto release_job;

	if ((rv = sca_init_raw_crypto_data(&sign, signlen)) != CRYPTO_SUCCESS)
		goto release_job;

	if (datalen != 0 && copy_from_user(data.cd_raw.iov_base,
	    (caddr_t)arg + args_len, datalen) != 0) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	if (signlen != 0 && copy_from_user(sign.cd_raw.iov_base,
	    (caddr_t)arg + args_len + datalen, signlen) != 0) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_verify_ops->verify(sp->ss_verify_ctx, &data,
	    &sign, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

release_job:

	SCA_PROVIDER_RELE(sp->ss_verify_ctx->cc_framework_private);
	ops_vector->co_ctx_ops->free_context(sp->ss_verify_ctx);
	kfree(sp->ss_verify_ctx);
	sp->ss_verify_ctx = NULL;

	SCA_SESSION_RELE(sp);

	if (data.cd_raw.iov_base != NULL)
		kfree(data.cd_raw.iov_base);

	if (sign.cd_raw.iov_base != NULL)
		kfree(sign.cd_raw.iov_base);

	SCA_DBG_PRINT("sca_verify: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_verify_recover(struct inode *inode, struct file *filp, unsigned long arg)
{
	Digest_Args digest;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	int rv;

	SCA_DBG_PRINT("sca_verify_recover: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_verify_recover: failed finding private");

	if (copy_from_user(&digest, (caddr_t)arg, sizeof (digest)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(digest.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	if ((rv = sca_get_ops_from_ctx(sp->ss_verify_recover_ctx, &ops_vector,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[rv]);
	}

	if (ops_vector->co_verify_ops->verify_recover == NULL) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[CRYPTO_NOT_SUPPORTED]);
	}

	rv = sca_common_digest(arg, &digest, sp, ops_vector,
	    ops_vector->co_verify_ops->verify_recover);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_verify_recover: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_sign_update(struct inode *inode, struct file *filp, unsigned long arg)
{
	SignUpdate_Args update;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	int rv;

	SCA_DBG_PRINT("sca_sign_update: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_sign_update: failed finding private");

	if (copy_from_user(&update, (caddr_t)arg, sizeof (update)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(update.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	if ((rv = sca_get_ops_from_ctx(sp->ss_sign_ctx, &ops_vector,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[rv]);
	}

	if (ops_vector->co_sign_ops->sign_update == NULL) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[CRYPTO_NOT_SUPPORTED]);
	}

	rv = sca_sign_verify_update(arg, &update, sp, ops_vector,
	    ops_vector->co_sign_ops->sign_update);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_sign_update: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_verify_update(struct inode *inode, struct file *filp, unsigned long arg)
{
	SignUpdate_Args update;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	int rv;

	SCA_DBG_PRINT("sca_verify_update: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_verify_update: failed finding private");

	if (copy_from_user(&update, (caddr_t)arg, sizeof (update)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(update.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	if ((rv = sca_get_ops_from_ctx(sp->ss_verify_ctx, &ops_vector,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[rv]);
	}

	if (ops_vector->co_verify_ops->verify_update == NULL) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[CRYPTO_NOT_SUPPORTED]);
	}

	rv = sca_sign_verify_update(arg, &update, sp, ops_vector,
	    ops_vector->co_verify_ops->verify_update);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_verify_update: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_sign_final(struct inode *inode, struct file *filp, unsigned long arg)
{
	EncryptFinal_Args encrypt_final;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	int rv;

	SCA_DBG_PRINT("sca_sign_final: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_sign_final: failed finding private");

	if (copy_from_user(&encrypt_final, (caddr_t)arg,
	    sizeof (encrypt_final)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(encrypt_final.session_handle, cm, &sp))
	    != CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	if ((rv = sca_get_ops_from_ctx(sp->ss_sign_ctx, &ops_vector,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[rv]);
	}

	if (ops_vector->co_sign_ops->sign_final == NULL) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[CRYPTO_NOT_SUPPORTED]);
	}

	rv = sca_common_final(arg, &encrypt_final, sp, ops_vector,
	    ops_vector->co_sign_ops->sign_final);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_sign_final: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
/*
 * Can't use the common final because it does a copyout of the final part.
 */
static int
sca_verify_final(struct inode *inode, struct file *filp, unsigned long arg)
{
	VerifyFinal_Args verify_final;
	crypto_data_t sign;
	size_t signlen;
	sca_file_private_t *cm;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	int rv;

	SCA_DBG_PRINT("sca_verify_final: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_verify_final: failed finding private");

	if (copy_from_user(&verify_final, (caddr_t)arg,
	    sizeof (verify_final)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(verify_final.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	if ((rv = sca_get_ops_from_ctx(sp->ss_verify_ctx, &ops_vector,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[rv]);
	}

	if (ops_vector->co_verify_ops->verify_final == NULL) {
		SCA_SESSION_RELE(sp);
		return (sca_rc[CRYPTO_NOT_SUPPORTED]);
	}

	sign.cd_raw.iov_base = NULL;

	signlen = verify_final.signature_len;
	if (signlen > crypto_max_buffer_len) {
		printk(KERN_ALERT "sca_verify_final: buffer greater than %ld "
		    "bytes, pid = %d\n", crypto_max_buffer_len, current->pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	if ((rv = sca_init_raw_crypto_data(&sign, signlen)) != CRYPTO_SUCCESS)
		goto release_job;

	if (signlen != 0 && copy_from_user(sign.cd_raw.iov_base,
	    (caddr_t)arg + sizeof (VerifyFinal_Args), signlen) != 0) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_verify_ops->verify_final(sp->ss_verify_ctx, &sign,
	    sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

release_job:

	if (sp->ss_verify_ctx) {
		SCA_PROVIDER_RELE(sp->ss_verify_ctx->cc_framework_private);
		ops_vector->co_ctx_ops->free_context(sp->ss_verify_ctx);
		kfree(sp->ss_verify_ctx);
		sp->ss_verify_ctx = NULL;
	}
	SCA_SESSION_RELE(sp);

	if (sign.cd_raw.iov_base != NULL)
		kfree(sign.cd_raw.iov_base);

	SCA_DBG_PRINT("sca_verify_final: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_seed_random(struct inode *inode, struct file *filp, unsigned long arg)
{
	SeedRandom_Args seed_random;
	uchar_t *seed_buffer = NULL;
	size_t seed_len;
	sca_file_private_t *cm;
	crypto_provider_handle_t *ph;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real;
	int rv;

	SCA_DBG_PRINT("sca_seed_random: enter.\n");

	SCA_GET_PRIVATE(cm, filp, "sca_seed_random: failed finding private");

	if (copy_from_user(&seed_random, (caddr_t)arg,
	    sizeof (seed_random)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(seed_random.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS(sp, real, ops_vector, ph, psid, co_random_ops, seed_random)

	seed_len = seed_random.num_bytes;
	if (seed_len > crypto_max_buffer_len) {
		printk(KERN_ALERT "sca_seed_random: buffer greater than %ld "
		    "bytes, pid = %d\n", crypto_max_buffer_len, current->pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	if ((seed_buffer = kmalloc(seed_len, GFP_KERNEL)) == NULL) {
		rv = CRYPTO_HOST_MEMORY;
		goto release_job;
	}

	if (seed_len != 0 && copy_from_user(seed_buffer,
	    (caddr_t)arg + sizeof (seed_random), seed_len) != 0) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_random_ops->seed_random(ph, psid, seed_buffer,
	    seed_len, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

release_job:

	SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	if (seed_buffer != NULL)
		kfree(seed_buffer);

	SCA_DBG_PRINT("sca_seed_random: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_generate_random(struct inode *inode, struct file *filp, unsigned long arg)
{
	GenerateRandom_Args random;
	uchar_t *buffer = NULL;
	size_t len;
	sca_file_private_t *cm;
	crypto_provider_handle_t *ph;
	sca_session_t *sp = NULL;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real;
	int rv;

	SCA_DBG_PRINT("sca_generate_random: enter.\n");

	SCA_GET_PRIVATE(cm, filp,
	    "sca_generate_random: failed finding private");

	if (copy_from_user(&random, (caddr_t)arg, sizeof (random)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(random.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS(sp, real, ops_vector, ph, psid, co_random_ops,
	    generate_random)

	len = random.num_bytes;
	if (len > crypto_max_buffer_len) {
		printk(
		    KERN_ALERT "sca_generate_random: buffer greater than %ld "
		    "bytes, pid = %d\n", crypto_max_buffer_len, current->pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	if ((buffer = kmalloc(len, GFP_KERNEL)) == NULL) {
		rv = CRYPTO_HOST_MEMORY;
		goto release_job;
	}

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_random_ops->generate_random(ph, psid, buffer, len,
	    sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

	if (rv == CRYPTO_SUCCESS) {
		if (len != 0 && copy_to_user((caddr_t)arg + sizeof (random),
		    buffer, len) != 0) {
			rv = CRYPTO_ARGUMENTS_BAD;
		}
	}

release_job:

	SCA_PROVIDER_RELE(real);

	SCA_SESSION_RELE(sp);

	if (buffer != NULL) {
		/* random numbers are often used to create keys */
		memset(buffer, 0, len);
		kfree(buffer);
	}

	SCA_DBG_PRINT("sca_generate_random: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_object_generate_key(struct inode *inode, struct file *filp,
    unsigned long arg)
{
	GenerateKey_Args generate_key;
	uint_t args_len = sizeof (GenerateKey_Args);
	crypto_mechanism_t mech;
	crypto_object_attribute_t *k_attrs = NULL;
	crypto_object_id_t key_handle;
	caddr_t attributes;
	uint_t count;
	uint_t block_len;
	sca_file_private_t *cm;
	crypto_provider_handle_t *ph;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real = NULL;
	int rv;

	SCA_DBG_PRINT("sca_object_generate_key: enter.\n");

	SCA_GET_PRIVATE(cm, filp,
	    "sca_object_generate_key: failed finding private");

	if (copy_from_user(&generate_key, (caddr_t)arg,
	    sizeof (generate_key)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(generate_key.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS_MECH(sp, real, ops_vector, psid, co_key_ops, key_generate,
	    generate_key.mech_type)
	ph = real->sp_info->pi_provider_handle;

	mech.cm_type = generate_key.mech_type;
	mech.cm_param_len = generate_key.mech_param_len;
	mech.cm_param = NULL;
	if ((rv = sca_copyin_mech((caddr_t)arg + args_len, &mech)) !=
	    CRYPTO_SUCCESS)
		goto release_job;

	count = generate_key.attribute_count;
	block_len = generate_key.attribute_block_len;
	attributes = (caddr_t)arg + args_len + mech.cm_param_len;
	if ((rv = sca_get_attrs(count, block_len, attributes, &k_attrs)) !=
	    CRYPTO_SUCCESS) {
		goto release_job;
	}

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_key_ops->key_generate(ph, psid, &mech, k_attrs,
	    count, &key_handle, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_LONG_TIMEOUT);

	if (rv != CRYPTO_SUCCESS)
		goto release_job;

	generate_key.object_handle = OBJ_HANDLE_INC(key_handle);
	if (copy_to_user((caddr_t)arg, &generate_key,
	    sizeof (generate_key)) != 0) {
		sp->ss_state = JS_RUNNING;
		rv = ops_vector->co_object_ops->object_destroy(
		    ph, psid, key_handle, sp);
		(void) sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);
		rv = CRYPTO_ARGUMENTS_BAD;
	}

release_job:

	SCA_PROVIDER_RELE(real);

	if (k_attrs != NULL)
		kfree(k_attrs);

	if (mech.cm_param)
		kfree(mech.cm_param);

	SCA_SESSION_RELE(sp);

	SCA_DBG_PRINT("sca_object_generate_key: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_object_generate_key_pair(struct inode *inode, struct file *filp,
    unsigned long arg)
{
	GenKeyPair_Args key_pair;
	uint_t args_len = sizeof (GenKeyPair_Args);
	crypto_mechanism_t mech;
	crypto_object_attribute_t *k_pub_attrs = NULL;
	crypto_object_attribute_t *k_pri_attrs = NULL;
	crypto_object_id_t pub_handle;
	crypto_object_id_t pri_handle;
	caddr_t pri_attributes;
	caddr_t pub_attributes;
	uint_t pub_count;
	uint_t pri_count;
	uint_t pub_block_len;
	uint_t pri_block_len;
	sca_file_private_t *cm;
	crypto_provider_handle_t *ph;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real = NULL;
	uint8_t is_token, is_private;
	int i, token_index;
	int rv;

	SCA_DBG_PRINT("sca_object_generate_key_pair: enter.\n");

	SCA_GET_PRIVATE(cm, filp,
	    "sca_object_generate_key_pair: failed finding private");

	if (copy_from_user(&key_pair, (caddr_t)arg, sizeof (key_pair)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(key_pair.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS_MECH(sp, real, ops_vector, psid, co_key_ops,
	    key_generate_pair, key_pair.mech_type)
	ph = real->sp_info->pi_provider_handle;

	mech.cm_type = key_pair.mech_type;
	mech.cm_param_len = key_pair.mech_param_len;
	mech.cm_param = NULL;
	if ((rv = sca_copyin_mech((caddr_t)arg + args_len, &mech)) !=
	    CRYPTO_SUCCESS)
		goto release_job;

	pub_count = key_pair.publ_key_attr_count;
	pub_block_len = key_pair.publ_key_tmpl_len;
	pub_attributes = (caddr_t)arg + args_len + mech.cm_param_len;
	if ((rv = sca_get_attrs(pub_count, pub_block_len, pub_attributes,
	    &k_pub_attrs)) != CRYPTO_SUCCESS) {
		goto release_job;
	}

	/* Change public token key to session key */
	is_token = 0;
	is_private = 1;
	token_index = 0;
	for (i = 0; i < pub_count; i++) {
		if (k_pub_attrs[i].oa_type == CKA_TOKEN) {
			is_token = *(uint8_t *)k_pub_attrs[i].oa_value;
			token_index = i;
		}

		if (k_pub_attrs[i].oa_type == CKA_PRIVATE)
			is_private = *(uint8_t *)k_pub_attrs[i].oa_value;
	}

	if (is_token && !is_private)
		*(uint8_t *)k_pub_attrs[token_index].oa_value = 0;

	pri_count = key_pair.priv_key_attr_count;
	pri_block_len = key_pair.priv_key_tmpl_len;
	pri_attributes = (caddr_t)arg + args_len + mech.cm_param_len +
	    pub_block_len;
	if ((rv = sca_get_attrs(pri_count, pri_block_len, pri_attributes,
	    &k_pri_attrs)) != CRYPTO_SUCCESS) {
		goto release_job;
	}

	/* Change public token key to session key */
	is_token = 0;
	is_private = 1;
	token_index = 0;
	for (i = 0; i < pri_count; i++) {
		if (k_pri_attrs[i].oa_type == CKA_TOKEN) {
			is_token = *(uint8_t *)k_pri_attrs[i].oa_value;
			token_index = i;
		}

		if (k_pri_attrs[i].oa_type == CKA_PRIVATE)
			is_private = *(uint8_t *)k_pri_attrs[i].oa_value;
	}

	if (is_token && !is_private)
		*(uint8_t *)k_pri_attrs[token_index].oa_value = 0;

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_key_ops->key_generate_pair(ph, psid, &mech,
	    k_pub_attrs, pub_count, k_pri_attrs, pri_count,
	    &pub_handle, &pri_handle, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_LONG_TIMEOUT);

	if (rv != CRYPTO_SUCCESS)
		goto release_job;

	key_pair.pub_object_handle = OBJ_HANDLE_INC(pub_handle);
	key_pair.pri_object_handle = OBJ_HANDLE_INC(pri_handle);
	if (copy_to_user((caddr_t)arg, &key_pair, sizeof (key_pair)) != 0) {
		sp->ss_state = JS_RUNNING;
		rv = ops_vector->co_object_ops->object_destroy(
		    ph, psid, pub_handle, sp);
		(void) sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

		sp->ss_state = JS_RUNNING;
		rv = ops_vector->co_object_ops->object_destroy(
		    ph, psid, pri_handle, sp);
		(void) sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

		rv = CRYPTO_ARGUMENTS_BAD;
	}

release_job:

	SCA_PROVIDER_RELE(real);

	if (mech.cm_param)
		kfree(mech.cm_param);

	SCA_SESSION_RELE(sp);

	if (k_pub_attrs != NULL)
		kfree(k_pub_attrs);

	if (k_pri_attrs != NULL)
		kfree(k_pri_attrs);

	SCA_DBG_PRINT("sca_object_generate_key_pair: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_object_wrap_key(struct inode *inode, struct file *filp, unsigned long arg)
{
	WrapKey_Args wrap_key;
	uint_t args_len = sizeof (WrapKey_Args);
	crypto_mechanism_t mech;
	crypto_key_t wrapping_key;
	crypto_object_id_t handle;
	size_t wrapped_key_len;
	size_t wrapped_key_need = 0;
	uchar_t *wrapped_key = NULL;
	sca_file_private_t *cm;
	crypto_provider_handle_t *ph;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real = NULL;
	int rv;

	SCA_DBG_PRINT("sca_object_wrap_key: enter.\n");

	SCA_GET_PRIVATE(cm, filp,
	    "sca_object_wrap_key: failed finding private");

	if (copy_from_user(&wrap_key, (caddr_t)arg, sizeof (wrap_key)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(wrap_key.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS_MECH(sp, real, ops_vector, psid, co_key_ops, key_wrap,
	    wrap_key.mech_type)
	ph = real->sp_info->pi_provider_handle;

	mech.cm_type = wrap_key.mech_type;
	mech.cm_param_len = wrap_key.mech_param_len;
	mech.cm_param = NULL;
	if ((rv = sca_copyin_mech((caddr_t)arg + args_len, &mech)) !=
	    CRYPTO_SUCCESS)
		goto release_job;

	memset(&wrapping_key, 0, sizeof (crypto_key_t));
	wrapping_key.ck_format = CRYPTO_KEY_REFERENCE;
	wrapping_key.ck_obj_id = OBJ_HANDLE_DEC(wrap_key.wrapping_key);

	wrapped_key_len = wrap_key.wrapped_key_len;
	if (wrapped_key_len > crypto_max_buffer_len) {
		printk(
		    KERN_ALERT "sca_object_wrap_key: buffer greater than %ld "
		    "bytes, pid = %d\n", crypto_max_buffer_len, current->pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	wrapped_key_need = wrapped_key_len;
	if ((wrapped_key = kmalloc(wrapped_key_len, GFP_KERNEL)) == NULL) {
		rv = CRYPTO_HOST_MEMORY;
		goto release_job;
	}

	handle = OBJ_HANDLE_DEC(wrap_key.key);

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_key_ops->key_wrap(ph, psid, &mech, &wrapping_key,
	    &handle, wrapped_key, &wrapped_key_len, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

	if (rv == CRYPTO_SUCCESS) {
		if (wrapped_key_len != 0 &&
		    copy_to_user((caddr_t)arg + args_len + mech.cm_param_len,
		    wrapped_key, wrapped_key_len) != 0) {
			rv = CRYPTO_ARGUMENTS_BAD;
			goto release_job;
		}
		wrap_key.wrapped_key_len = wrapped_key_len;
	}

	if (rv == CRYPTO_BUFFER_TOO_SMALL) {
		/*
		 * The providers return CRYPTO_BUFFER_TOO_SMALL even for case 1
		 * of section 11.2 of the pkcs11 spec. We catch it here and
		 * provide the correct pkcs11 return value.
		 */
		if (wrapped_key_need == 0)
			rv = CRYPTO_SUCCESS;
		wrap_key.wrapped_key_len = wrapped_key_len;
	}

release_job:

	SCA_PROVIDER_RELE(real);

	if (mech.cm_param)
		kfree(mech.cm_param);

	SCA_SESSION_RELE(sp);

	if (wrapped_key != NULL)
		kfree(wrapped_key);

	if (copy_to_user((caddr_t)arg, &wrap_key, sizeof (wrap_key)) != 0) {
		rv = CRYPTO_ARGUMENTS_BAD;
	}

	SCA_DBG_PRINT("sca_object_wrap_key: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_object_unwrap_key(struct inode *inode, struct file *filp,
    unsigned long arg)
{
	UnWrapKey_Args unwrap_key;
	uint_t args_len = sizeof (UnWrapKey_Args);
	crypto_mechanism_t mech;
	crypto_key_t unwrapping_key;
	crypto_object_id_t handle;
	crypto_object_attribute_t *k_attrs = NULL;
	size_t wrapped_key_len;
	uchar_t *wrapped_key = NULL;
	uint_t block_len;
	uint_t count;
	caddr_t uk_attributes;
	sca_file_private_t *cm;
	crypto_provider_handle_t *ph;
	sca_session_t *sp;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real = NULL;
	int rv;

	SCA_DBG_PRINT("sca_object_unwrap_key: enter.\n");

	SCA_GET_PRIVATE(cm, filp,
	    "sca_object_unwrap_key: failed finding private");

	if (copy_from_user(&unwrap_key, (caddr_t)arg,
	    sizeof (unwrap_key)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(unwrap_key.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS_MECH(sp, real, ops_vector, psid, co_key_ops, key_unwrap,
	    unwrap_key.mech_type)
	ph = real->sp_info->pi_provider_handle;

	/* get mechanism parameter if there is one */
	mech.cm_type = unwrap_key.mech_type;
	mech.cm_param_len = unwrap_key.mech_param_len;
	mech.cm_param = NULL;
	if ((rv = sca_copyin_mech((caddr_t)arg + args_len, &mech)) !=
	    CRYPTO_SUCCESS)
		goto release_job;

	memset(&unwrapping_key, 0, sizeof (unwrapping_key));
	unwrapping_key.ck_format = CRYPTO_KEY_REFERENCE;
	unwrapping_key.ck_obj_id = OBJ_HANDLE_DEC(unwrap_key.unwrapping_key);

	/* get the wrapped key */
	wrapped_key_len = unwrap_key.wrapped_key_len;
	if (wrapped_key_len > crypto_max_buffer_len) {
		printk(KERN_ALERT
		    "sca_object_unwrap_key: buffer greater than %ld "
		    "bytes, pid = %d\n", crypto_max_buffer_len, current->pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	if ((wrapped_key = kmalloc(wrapped_key_len, GFP_KERNEL)) == NULL) {
		rv = CRYPTO_HOST_MEMORY;
		goto release_job;
	}

	if (wrapped_key_len != 0 && copy_from_user(wrapped_key,
	    (caddr_t)arg + args_len + mech.cm_param_len,
	    wrapped_key_len) != 0) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	/* get the object attributes */
	count = unwrap_key.attribute_count;
	block_len = unwrap_key.attribute_block_len;
	uk_attributes = (caddr_t)arg + args_len + mech.cm_param_len +
	    wrapped_key_len;
	if ((rv = sca_get_attrs(count, block_len, uk_attributes,
	    &k_attrs)) != CRYPTO_SUCCESS) {
		goto release_job;
	}

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_key_ops->key_unwrap(ph, psid, &mech,
	    &unwrapping_key,
	    wrapped_key, &wrapped_key_len, k_attrs, count, &handle, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

	if (rv != CRYPTO_SUCCESS)
		goto release_job;

	unwrap_key.object_handle = OBJ_HANDLE_INC(handle);
	if (copy_to_user((caddr_t)arg, &unwrap_key,
	    sizeof (unwrap_key)) != 0) {
		sp->ss_state = JS_RUNNING;
		rv = ops_vector->co_object_ops->object_destroy(
		    ph, psid, handle, sp);
		(void) sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);
		rv = CRYPTO_ARGUMENTS_BAD;
	}

release_job:

	SCA_PROVIDER_RELE(real);

	if (mech.cm_param)
		kfree(mech.cm_param);

	SCA_SESSION_RELE(sp);

	if (k_attrs != NULL)
		kfree(k_attrs);

	if (wrapped_key != NULL)
		kfree(wrapped_key);

	SCA_DBG_PRINT("sca_object_unwrap_key: done.\n");

	return (sca_rc[rv]);
}

/* ioctl entry should return PKCS11 error code */
static int
sca_object_derive_key(struct inode *inode, struct file *filp, unsigned long arg)
{
	DeriveKey_Args derive_key;
	uint_t args_len = sizeof (DeriveKey_Args);
	crypto_object_attribute_t *k_attrs = NULL;
	crypto_mechanism_t mech;
	crypto_key_t base_key;
	sca_file_private_t *cm;
	sca_session_t *sp = NULL;
	crypto_object_id_t handle;
	caddr_t attributes;
	uint_t count;
	uint_t block_len;
	crypto_provider_handle_t *ph;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real = NULL;
	int rv;

	SCA_DBG_PRINT("sca_object_derive_key: enter.\n");

	SCA_GET_PRIVATE(cm, filp,
	    "sca_object_derive_key: failed finding private");

	if (copy_from_user(&derive_key, (caddr_t)arg,
	    sizeof (derive_key)) != 0) {
		return (sca_rc[CRYPTO_ARGUMENTS_BAD]);
	}

	if ((rv = sca_get_session_ptr(derive_key.session_handle, cm, &sp)) !=
	    CRYPTO_SUCCESS) {
		return (sca_rc[rv]);
	}

	SCA_GET_OPS_MECH(sp, real, ops_vector, psid, co_key_ops, key_derive,
	    derive_key.mech_type)
	ph = real->sp_info->pi_provider_handle;

	mech.cm_type = derive_key.mech_type;
	mech.cm_param_len = derive_key.mech_param_len;
	mech.cm_param = NULL;
	if ((rv = sca_copyin_mech((caddr_t)arg + args_len, &mech)) !=
	    CRYPTO_SUCCESS)
		goto release_job;

	memset(&base_key, 0, sizeof (base_key));
	base_key.ck_format = CRYPTO_KEY_REFERENCE;
	base_key.ck_obj_id = OBJ_HANDLE_DEC(derive_key.base_key);

	count = derive_key.attribute_count;
	block_len = derive_key.attribute_block_len;
	attributes = (caddr_t)arg + args_len + mech.cm_param_len;
	if ((rv = sca_get_attrs(count, block_len, attributes,
	    &k_attrs)) != CRYPTO_SUCCESS) {
		goto release_job;
	}

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = ops_vector->co_key_ops->key_derive(ph, psid, &mech,
	    &base_key, k_attrs, count, &handle, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

	if (rv != CRYPTO_SUCCESS)
		goto release_job;

	derive_key.object_handle = OBJ_HANDLE_INC(handle);
	if (copy_to_user((caddr_t)arg, &derive_key,
	    sizeof (derive_key)) != 0) {
		sp->ss_state = JS_RUNNING;
		rv = ops_vector->co_object_ops->object_destroy(ph, psid,
		    handle, sp);
		(void) sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);
		rv = CRYPTO_ARGUMENTS_BAD;
	}

release_job:

	SCA_PROVIDER_RELE(real);

	if (mech.cm_param)
		kfree(mech.cm_param);

	SCA_SESSION_RELE(sp);

	if (k_attrs != NULL)
		kfree(k_attrs);

	SCA_DBG_PRINT("sca_object_derive_key: done.\n");

	return (sca_rc[rv]);
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9))
static long
sca_ioctl_compat(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return (sca_ioctl(NULL, filp, cmd, arg));
}
#endif

static int
sca_ioctl(struct inode *inode, struct file *filp, unsigned int cmd,
    unsigned long arg)
{
	SCA_DBG_PRINT("sca_ioctl: enter: cmd: %d\n", cmd);

	switch (cmd) {
/*
 * Supported in the userland library
	SCA_INITIALIZE
	SCA_FINALIZE
	SCA_GETINFO
	SCA_GETFUNCTIONLIST
*/
	case SCA_GETSLOTLIST:
		return (sca_get_slot_list(inode, filp, arg));

	case SCA_GETSLOTINFO:
		return (sca_get_slot_info(inode, filp, arg));

	case SCA_GETTOKENINFO:
		return (sca_get_token_info(inode, filp, arg));
/*
 * Mars does not support these functions
	SCA_WAITFORSLOTEVENT
*/

	case SCA_GETMECHANISMLIST:
		return (sca_get_mechanism_list(inode, filp, arg));

	case SCA_GETMECHANISMINFO:
		return (sca_get_mechanism_info(inode, filp, arg));

/*
 * Mars does not support these functions
	SCA_INITTOKEN
	SCA_INITPIN
*/
	case SCA_SETPIN:
		return (sca_set_pin(inode, filp, arg));


	case SCA_OPENSESSION:
		return (sca_open_session(inode, filp, arg));

	case SCA_CLOSESESSION:
		return (sca_close_session(inode, filp, arg));

	case SCA_CLOSEALLSESSIONS:
		return (sca_close_all_session(inode, filp, arg));

/*
 * Supported in the userland library
	SCA_GETSESSIONINFO
 */
/*
 * Mars does not support these functions
	SCA_GETOPERATIONSTATE
	SCA_SETOPERATIONSTATE
*/

	case SCA_LOGIN:
		return (sca_login(inode, filp, arg));

	case SCA_LOGOUT:
		return (sca_logout(inode, filp, arg));


	case SCA_CREATEOBJECT:
		return (sca_object_create(inode, filp, arg));

	case SCA_COPYOBJECT:
		return (sca_object_copy(inode, filp, arg));

	case SCA_DESTROYOBJECT:
		return (sca_object_destroy(inode, filp, arg));

	case SCA_GETOBJECTSIZE:
		return (sca_object_get_size(inode, filp, arg));

	case SCA_GETATTRIBUTEVALUE:
		return (sca_object_get_attribute_value(inode, filp, arg));

	case SCA_SETATTRIBUTEVALUE:
		return (sca_object_set_attribute_value(inode, filp, arg));

	case SCA_FINDOBJECTSINIT:
		return (sca_object_find_init(inode, filp, arg));

	case SCA_FINDOBJECTS:
		return (sca_object_find_update(inode, filp, arg));

	case SCA_FINDOBJECTSFINAL:
		return (sca_object_find_final(inode, filp, arg));


	case SCA_ENCRYPTINIT:
		return (sca_encrypt_init(inode, filp, arg));

	case SCA_ENCRYPT:
		return (sca_encrypt(inode, filp, arg));

	case SCA_ENCRYPTUPDATE:
		return (sca_encrypt_update(inode, filp, arg));

	case SCA_ENCRYPTFINAL:
		return (sca_encrypt_final(inode, filp, arg));


	case SCA_DECRYPTINIT:
		return (sca_decrypt_init(inode, filp, arg));

	case SCA_DECRYPT:
		return (sca_decrypt(inode, filp, arg));

	case SCA_DECRYPTUPDATE:
		return (sca_decrypt_update(inode, filp, arg));

	case SCA_DECRYPTFINAL:
		return (sca_decrypt_final(inode, filp, arg));


	case SCA_DIGESTINIT:
		return (sca_digest_init(inode, filp, arg));

	case SCA_DIGEST:
		return (sca_digest(inode, filp, arg));

	case SCA_DIGESTUPDATE:
		return (sca_digest_update(inode, filp, arg));

	case SCA_DIGESTKEY:
		return (sca_digest_key(inode, filp, arg));

	case SCA_DIGESTFINAL:
		return (sca_digest_final(inode, filp, arg));


	case SCA_SIGNINIT:
		return (sca_sign_init(inode, filp, arg));

	case SCA_SIGN:
		return (sca_sign(inode, filp, arg));

	case SCA_SIGNUPDATE:
		return (sca_sign_update(inode, filp, arg));

	case SCA_SIGNFINAL:
		return (sca_sign_final(inode, filp, arg));

	case SCA_SIGNRECOVERINIT:
		return (sca_sign_recover_init(inode, filp, arg));

	case SCA_SIGNRECOVER:
		return (sca_sign_recover(inode, filp, arg));


	case SCA_VERIFYINIT:
		return (sca_verify_init(inode, filp, arg));

	case SCA_VERIFY:
		return (sca_verify(inode, filp, arg));

	case SCA_VERIFYUPDATE:
		return (sca_verify_update(inode, filp, arg));

	case SCA_VERIFYFINAL:
		return (sca_verify_final(inode, filp, arg));

	case SCA_VERIFYRECOVERINIT:
		return (sca_verify_recover_init(inode, filp, arg));

	case SCA_VERIFYRECOVER:
		return (sca_verify_recover(inode, filp, arg));

/*
 * Mars does not support these functions
	SCA_DIGESTENCRYPTUPDATE
	SCA_DECRYPTDIGESTUPDATE
	SCA_SIGNENCRYPTUPDATE
	SCA_DECRYPTVERIFYUPDATE
*/

	case SCA_GENERATEKEY:
		return (sca_object_generate_key(inode, filp, arg));

	case SCA_GENERATEKEYPAIR:
		return (sca_object_generate_key_pair(inode, filp, arg));

	case SCA_WRAPKEY:
		return (sca_object_wrap_key(inode, filp, arg));

	case SCA_UNWRAPKEY:
		return (sca_object_unwrap_key(inode, filp, arg));

	case SCA_DERIVEKEY:
		return (sca_object_derive_key(inode, filp, arg));


	case SCA_SEEDRANDOM:
		return (sca_seed_random(inode, filp, arg));

	case SCA_GENERATERANDOM:
		return (sca_generate_random(inode, filp, arg));

/*
 * Mars does not support these functions
	SCA_GETFUNCTIONSTATUS
	SCA_CANCELFUNCTION
*/
	}

	SCA_DBG_PRINT("sca_ioctl: done.\n");

	return (EINVAL);
}

/*
 * ASSUMPTION: crypto_sign_update and crypto_verify_update structures
 * are identical except for field names.
 */
static int
sca_sign_verify_update(unsigned long arg, SignUpdate_Args *sign_update,
    sca_session_t *sp, crypto_ops_t *ops_vector,
    int (*update)(crypto_ctx_t *, crypto_data_t *, crypto_req_handle_t))
{
	crypto_ctx_t **ctxpp = NULL;
	crypto_data_t data;
	size_t datalen;
	int rv;

	SCA_DBG_PRINT("sca_sign_verify_update: enter.\n");

	ctxpp = (update == ops_vector->co_sign_ops->sign_update) ?
	    &sp->ss_sign_ctx : &sp->ss_verify_ctx;

	data.cd_raw.iov_base = NULL;

	datalen = sign_update->data_len;
	if (datalen > crypto_max_buffer_len) {
		printk(KERN_ALERT
		    "sca_sign_verify_update: buffer greater than %ld "
		    "bytes, pid = %d\n", crypto_max_buffer_len, current->pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	if ((rv = sca_init_raw_crypto_data(&data, datalen)) != CRYPTO_SUCCESS)
		goto release_job;

	if (datalen != 0 && copy_from_user(data.cd_raw.iov_base,
	    (caddr_t)arg + sizeof (SignUpdate_Args), datalen) != 0) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	sp->ss_state = JS_RUNNING;
	rv = (update)(*ctxpp, &data, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

release_job:

	if (rv != CRYPTO_SUCCESS) {
		SCA_PROVIDER_RELE((*ctxpp)->cc_framework_private);
		ops_vector->co_ctx_ops->free_context(*ctxpp);
		kfree(*ctxpp);
		*ctxpp = NULL;
	}

	if (data.cd_raw.iov_base != NULL)
		kfree(data.cd_raw.iov_base);

	SCA_DBG_PRINT("sca_sign_verify_update: done.\n");

	return (rv);
}

/*
 * ASSUMPTION: crypto_sign_init, crypto_verify_init, crypto_sign_recover_init,
 * and crypto_verify_recover_init structures are identical
 * except for field names.
 */
static int
sca_sign_verify_init(unsigned long arg, SignInit_Args *sign_init,
    sca_session_t *sp, sca_provider_t *real, crypto_ops_t *ops_vector,
    crypto_session_id_t psid, int (*init)(crypto_ctx_t *,
    crypto_mechanism_t *, crypto_key_t *, crypto_spi_ctx_template_t,
    crypto_req_handle_t))
{
	crypto_mechanism_t mech;
	crypto_key_t key;
	crypto_ctx_t **ctxpp = NULL;
	int rv;

	SCA_DBG_PRINT("sca_sign_verify_init: enter.\n");

	mech.cm_param = NULL;
	mech.cm_type = sign_init->mech_type;
	mech.cm_param_len = sign_init->param_len;
	if ((rv = sca_copyin_mech((caddr_t)arg + sizeof (SignInit_Args), &mech))
	    != CRYPTO_SUCCESS)
		goto release_job;

	memset(&key, 0, sizeof (key));
	key.ck_format = CRYPTO_KEY_REFERENCE;
	key.ck_obj_id = OBJ_HANDLE_DEC(sign_init->key);

	if (init == ops_vector->co_sign_ops->sign_init) {
		ctxpp = &sp->ss_sign_ctx;
	} else if (init == ops_vector->co_verify_ops->verify_init) {
		ctxpp = &sp->ss_verify_ctx;
	} else if (init == ops_vector->co_sign_ops->sign_recover_init) {
		ctxpp = &sp->ss_sign_recover_ctx;
	} else if (init == ops_vector->co_verify_ops->verify_recover_init) {
		ctxpp = &sp->ss_verify_recover_ctx;
	}

	if (*ctxpp == NULL) {
		if ((*ctxpp = kmalloc(sizeof (crypto_ctx_t), GFP_KERNEL)) ==
		    NULL) {
			rv = CRYPTO_HOST_MEMORY;
			goto release_job;
		}
	} else {
		/*
		 * Make sure to free the provider ctx and release its
		 * reference when reusing a context.
		 */
		ops_vector->co_ctx_ops->free_context(*ctxpp);
		SCA_PROVIDER_RELE((*ctxpp)->cc_framework_private);
	}

	memset(*ctxpp, 0, sizeof (crypto_ctx_t));
	(*ctxpp)->cc_provider = real->sp_info->pi_provider_handle;
	(*ctxpp)->cc_session = psid;
	(*ctxpp)->cc_framework_private = real;
	rv = (init)(*ctxpp, &mech, &key, NULL, sp);

	if (rv != CRYPTO_SUCCESS) {
		kfree(*ctxpp);
		*ctxpp = NULL;
	}

release_job:

	if (mech.cm_param != NULL)
		kfree(mech.cm_param);

	SCA_DBG_PRINT("sca_sign_verify_init: done.\n");

	return (rv);
}

/*
 * Free provider-allocated storage used for find object searches.
 */
static int
sca_free_find_ctx(sca_session_t *sp)
{
	crypto_provider_handle_t *ph;
	crypto_ops_t *ops_vector;
	crypto_session_id_t psid;
	sca_provider_t *real;
	int rv;

	SCA_DBG_PRINT("sca_free_find_ctx: enter.\n");

	SCA_GET_OPS(sp, real, ops_vector, ph, psid, co_object_ops,
	    object_find_final)

	if ((rv = sca_wait_for_busy_provider(real,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		goto release_job;

	rv = ops_vector->co_object_ops->object_find_final(
	    ph, sp->ss_find_init_cookie, sp);
	sp->ss_find_init_cookie = NULL;

release_job:

	SCA_PROVIDER_RELE(real);

	SCA_DBG_PRINT("sca_free_find_ctx: done: 0x%x\n", rv);

	return (rv);
}

/*
 * ASSUMPTION: crypto_digest, crypto_sign, crypto_sign_recover,
 * and crypto_verify_recover are identical except for field names.
 */
static int
sca_common_digest(unsigned long arg,
    Digest_Args *crypto_digest, sca_session_t *sp, crypto_ops_t *ops_vector,
    int (*single)(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t))
{
	crypto_data_t data, digest;
	uint_t args_len = sizeof (Digest_Args);
	crypto_ctx_t **ctxpp = NULL;
	size_t datalen, digestlen;
	int length_only = 0;
	int rv;

	if (ops_vector->co_digest_ops &&
	    single == ops_vector->co_digest_ops->digest) {
		ctxpp = &sp->ss_digest_ctx;
	} else if (ops_vector->co_sign_ops &&
	    single == ops_vector->co_sign_ops->sign) {
		ctxpp = &sp->ss_sign_ctx;
	} else if (ops_vector->co_verify_ops &&
	    single == ops_vector->co_verify_ops->verify_recover) {
		ctxpp = &sp->ss_verify_recover_ctx;
	} else {
		ctxpp = &sp->ss_sign_recover_ctx;
	}

	data.cd_raw.iov_base = NULL;
	digest.cd_raw.iov_base = NULL;

	datalen = crypto_digest->in_data_len;
	digestlen = crypto_digest->out_data_len;

	if (datalen > crypto_max_buffer_len ||
	    digestlen > crypto_max_buffer_len) {
		printk(KERN_ALERT "sca_common_digest: buffer greater than %ld "
		    "bytes, pid = %d\n", crypto_max_buffer_len, current->pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	if ((rv = sca_init_raw_crypto_data(&data, datalen)) != CRYPTO_SUCCESS)
		goto release_job;
	if (datalen != 0 && copy_from_user(data.cd_raw.iov_base,
	    (caddr_t)arg + args_len, datalen) != 0) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	if ((rv = sca_init_raw_crypto_data(&digest, digestlen)) !=
	    CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = (single)(*ctxpp, &data, &digest, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

	if (rv == CRYPTO_SUCCESS) {
		ASSERT(digest.cd_length <= digestlen);
		if (digest.cd_length != 0 &&
		    copy_to_user((caddr_t)arg + args_len + datalen,
		    digest.cd_raw.iov_base, digest.cd_length) != 0) {
			rv = CRYPTO_ARGUMENTS_BAD;
			goto release_job;
		}
		crypto_digest->out_data_len = digest.cd_length;
	}

	if (rv == CRYPTO_BUFFER_TOO_SMALL) {
		/*
		 * The providers return CRYPTO_BUFFER_TOO_SMALL even for case 1
		 * of section 11.2 of the pkcs11 spec. We catch it here and
		 * provide the correct pkcs11 return value.
		 */
		if (digestlen == 0) {
			length_only = 1;
			rv = CRYPTO_SUCCESS;
		}
		crypto_digest->out_data_len = digest.cd_length;
	}

release_job:

	/* Free the context here if it is not buffer too small */
	if (rv != CRYPTO_BUFFER_TOO_SMALL && !length_only) {
		SCA_PROVIDER_RELE((*ctxpp)->cc_framework_private);
		ops_vector->co_ctx_ops->free_context(*ctxpp);
		kfree(*ctxpp);
		*ctxpp = NULL;
	}

	if (data.cd_raw.iov_base != NULL)
		kfree(data.cd_raw.iov_base);

	if (digest.cd_raw.iov_base != NULL)
		kfree(digest.cd_raw.iov_base);

	if (copy_to_user((caddr_t)arg, crypto_digest,
	    sizeof (Digest_Args)) != 0) {
		rv = CRYPTO_ARGUMENTS_BAD;
	}

	return (rv);
}

/*
 * ASSUMPTION: crypto_encrypt_final, crypto_decrypt_final, crypto_sign_final,
 * and crypto_digest_final structures are identical except for field names.
 */
static int
sca_common_final(unsigned long arg,
    EncryptFinal_Args *encrypt_final, sca_session_t *sp,
    crypto_ops_t *ops_vector,
    int (*final)(crypto_ctx_t *, crypto_data_t *, crypto_req_handle_t))
{
	crypto_ctx_t **ctxpp = NULL;
	crypto_data_t encr;
	size_t encrlen;
	int length_only = 0;
	uint_t args_len = sizeof (EncryptFinal_Args);
	int rv;

	if (final == ops_vector->co_cipher_ops->encrypt_final) {
		ctxpp = &sp->ss_encr_ctx;
	} else if (final == ops_vector->co_cipher_ops->decrypt_final) {
		ctxpp = &sp->ss_decr_ctx;
	} else if (final == ops_vector->co_sign_ops->sign_final) {
		ctxpp = &sp->ss_sign_ctx;
	} else {
		ctxpp = &sp->ss_digest_ctx;
	}

	encrlen = encrypt_final->out_len;
	if (encrlen > crypto_max_buffer_len) {
		printk(KERN_ALERT "sca_common_final: buffer greater than %ld "
		    "bytes, pid = %d\n", crypto_max_buffer_len, current->pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	if ((rv = sca_init_raw_crypto_data(&encr, encrlen)) != CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = (final)(*ctxpp, &encr, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

	if (rv == CRYPTO_SUCCESS) {
		ASSERT(encr.cd_length <= encrlen);
		if (encr.cd_length != 0 && copy_to_user(
		    (caddr_t)arg + args_len, encr.cd_raw.iov_base,
		    encr.cd_length) != 0) {
			rv = CRYPTO_ARGUMENTS_BAD;
			goto release_job;
		}
		encrypt_final->out_len = encr.cd_length;
	}

	if (rv == CRYPTO_BUFFER_TOO_SMALL) {
		/* request for output length only */
		if (encrlen == 0) {
			length_only = 1;
			rv = CRYPTO_SUCCESS;
		}
		encrypt_final->out_len = encr.cd_length;
	}

release_job:

	if (rv != CRYPTO_BUFFER_TOO_SMALL && !length_only) {
		SCA_PROVIDER_RELE((*ctxpp)->cc_framework_private);
		ops_vector->co_ctx_ops->free_context(*ctxpp);
		kfree(*ctxpp);
		*ctxpp = NULL;
	}

	if (encr.cd_raw.iov_base != NULL)
		kfree(encr.cd_raw.iov_base);

	if (copy_to_user((caddr_t)arg, encrypt_final,
	    sizeof (*encrypt_final)) != 0) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	return (rv);
}

/*
 * ASSUMPTION: crypto_encrypt_update and crypto_decrypt_update
 * structures are identical except for field names.
 */
static int
sca_cipher_update(unsigned long arg, EncryptUpdate_Args *encrypt_update,
    sca_session_t *sp, crypto_ops_t *ops_vector,
    int (*update)(crypto_ctx_t *,
    crypto_data_t *, crypto_data_t *, crypto_req_handle_t))
{
	crypto_ctx_t **ctxpp = NULL;
	crypto_data_t data, encr;
	size_t datalen, encrlen;
	uint_t args_len = sizeof (EncryptUpdate_Args);
	int rv;

	data.cd_raw.iov_base = NULL;
	encr.cd_raw.iov_base = NULL;

	datalen = encrypt_update->in_part_len;
	encrlen = encrypt_update->out_part_len;
	if (datalen > crypto_max_buffer_len ||
	    encrlen > crypto_max_buffer_len) {
		printk(KERN_ALERT "sca_cipher_update: buffer greater than %ld "
		    "bytes, pid = %d\n", crypto_max_buffer_len, current->pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	if ((rv = sca_init_raw_crypto_data(&data, datalen)) != CRYPTO_SUCCESS)
		goto release_job;
	data.cd_miscdata = NULL;

	if (datalen != 0 && copy_from_user(data.cd_raw.iov_base,
	    (caddr_t)arg + args_len, datalen) != 0) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	if ((rv = sca_init_raw_crypto_data(&encr, encrlen)) != CRYPTO_SUCCESS)
		goto release_job;

	ctxpp = (update == ops_vector->co_cipher_ops->encrypt_update) ?
	    &sp->ss_encr_ctx : &sp->ss_decr_ctx;

	sp->ss_state = JS_RUNNING;
	rv = (update)(*ctxpp, &data, &encr, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

	if (rv == CRYPTO_SUCCESS || rv == CRYPTO_BUFFER_TOO_SMALL) {
		if (rv == CRYPTO_SUCCESS) {
			ASSERT(encr.cd_length <= encrlen);
			if (encr.cd_length != 0 && copy_to_user(
			    (caddr_t)arg + args_len + datalen,
			    encr.cd_raw.iov_base, encr.cd_length) != 0) {
				rv = CRYPTO_ARGUMENTS_BAD;
				goto release_job;
			}
		} else {
			/* request for output data length only */
			if (encrlen == 0)
				rv = CRYPTO_SUCCESS;
		}
		encrypt_update->out_part_len = encr.cd_length;
	} else {
		SCA_PROVIDER_RELE((*ctxpp)->cc_framework_private);
		ops_vector->co_ctx_ops->free_context(*ctxpp);
		kfree(*ctxpp);
		*ctxpp = NULL;
	}

release_job:

	if (data.cd_raw.iov_base != NULL)
		kfree(data.cd_raw.iov_base);

	if (encr.cd_raw.iov_base != NULL)
		kfree(encr.cd_raw.iov_base);

	if (copy_to_user((caddr_t)arg, encrypt_update,
	    sizeof (EncryptUpdate_Args)) != 0) {
		return (CRYPTO_ARGUMENTS_BAD);
	}
	return (rv);
}

/*
 * ASSUMPTION: crypto_encrypt and crypto_decrypt structures
 * are identical except for field names.
 */
static int
sca_cipher(unsigned long arg,
    Encrypt_Args *encrypt, sca_session_t *sp, crypto_ops_t *ops_vector,
    int (*single)(crypto_ctx_t *,
    crypto_data_t *, crypto_data_t *, crypto_req_handle_t))
{
	crypto_ctx_t **ctxpp = NULL;
	crypto_data_t data, encr;
	size_t datalen, encrlen;
	int datalen_only = 0;
	uint_t args_len = sizeof (Encrypt_Args);
	int rv;

	ctxpp = (single == ops_vector->co_cipher_ops->encrypt) ?
	    &sp->ss_encr_ctx : &sp->ss_decr_ctx;

	data.cd_raw.iov_base = NULL;
	encr.cd_raw.iov_base = NULL;

	datalen = encrypt->in_data_len;
	encrlen = encrypt->out_data_len;
	if (datalen > crypto_max_buffer_len ||
	    encrlen > crypto_max_buffer_len) {
		printk(KERN_ALERT "sca_cipher: buffer greater than %ld bytes, "
		    "pid = %d\n", crypto_max_buffer_len, current->pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	if ((rv = sca_init_raw_crypto_data(&data, datalen)) != CRYPTO_SUCCESS)
		goto release_job;
	data.cd_miscdata = NULL;

	if (datalen != 0 && copy_from_user(data.cd_raw.iov_base,
	    (caddr_t)arg + args_len, datalen) != 0) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_job;
	}

	if ((rv = sca_init_raw_crypto_data(&encr, encrlen)) != CRYPTO_SUCCESS)
		goto release_job;

	sp->ss_state = JS_RUNNING;
	rv = (single)(*ctxpp, &data, &encr, sp);

	rv = sca_wait_on_queued(sp, rv, SCA_SHORT_TIMEOUT);

	if (rv == CRYPTO_SUCCESS) {
		ASSERT(encr.cd_length <= encrlen);
		if (encr.cd_length != 0 && copy_to_user((caddr_t)arg +
		    args_len +
		    datalen, encr.cd_raw.iov_base, encr.cd_length) != 0) {
			rv = CRYPTO_ARGUMENTS_BAD;
			goto release_job;
		}
		encrypt->out_data_len = encr.cd_length;
	}

	if (rv == CRYPTO_BUFFER_TOO_SMALL) {
		/* request for output data length only */
		if (encrlen == 0) {
			datalen_only = 1;
			rv = CRYPTO_SUCCESS;
		}
		encrypt->out_data_len = encr.cd_length;
	}

release_job:

	if (rv != CRYPTO_BUFFER_TOO_SMALL && !datalen_only) {
		SCA_PROVIDER_RELE((*ctxpp)->cc_framework_private);
		ops_vector->co_ctx_ops->free_context(*ctxpp);
		kfree(*ctxpp);
		*ctxpp = NULL;
	}

	if (data.cd_raw.iov_base != NULL)
		kfree(data.cd_raw.iov_base);

	if (encr.cd_raw.iov_base != NULL)
		kfree(encr.cd_raw.iov_base);

	if (copy_to_user((caddr_t)arg, encrypt, sizeof (Encrypt_Args)) != 0) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	return (rv);
}

/*
 * ASSUMPTION: crypto_encrypt_init and crypto_decrypt_init
 * structures are identical except for field names.
 */
static int
sca_cipher_init(unsigned long arg, EncryptInit_Args *encrypt_init,
    sca_session_t *sp, sca_provider_t *real, crypto_ops_t *ops_vector,
    crypto_session_id_t psid,
    int (*init)(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t))
{
	crypto_mechanism_t mech;
	crypto_key_t key;
	crypto_ctx_t **ctxpp;
	int rv;

	SCA_DBG_PRINT("sca_cipher_init: enter.\n");

	mech.cm_type = encrypt_init->mech_type;
	mech.cm_param_len = encrypt_init->param_len;
	mech.cm_param = NULL;
	if ((rv = sca_copyin_mech((caddr_t)arg + sizeof (EncryptInit_Args),
	    &mech)) != CRYPTO_SUCCESS)
		goto out;

	memset(&key, 0, sizeof (crypto_key_t));
	key.ck_format = CRYPTO_KEY_REFERENCE;
	key.ck_obj_id = OBJ_HANDLE_DEC(encrypt_init->key);

	ctxpp = (init == ops_vector->co_cipher_ops->encrypt_init) ?
	    &sp->ss_encr_ctx : &sp->ss_decr_ctx;

	if (*ctxpp == NULL) {
		if ((*ctxpp = kmalloc(sizeof (crypto_ctx_t), GFP_KERNEL)) ==
		    NULL) {
			rv = CRYPTO_HOST_MEMORY;
			goto out;
		}
	} else {
		/*
		 * Make sure to free the provider ctx and release its
		 * reference when reusing a context.
		 */
		ops_vector->co_ctx_ops->free_context(*ctxpp);
		SCA_PROVIDER_RELE((*ctxpp)->cc_framework_private);
	}

	memset(*ctxpp, 0, sizeof (crypto_ctx_t));
	(*ctxpp)->cc_provider = real->sp_info->pi_provider_handle;
	(*ctxpp)->cc_session = psid;
	(*ctxpp)->cc_framework_private = real;

	if ((rv = init(*ctxpp, &mech, &key, NULL, NULL)) != CRYPTO_SUCCESS) {
		kfree(*ctxpp);
		*ctxpp = NULL;
	}
out:

	if (mech.cm_param)
		kfree(mech.cm_param);

	SCA_DBG_PRINT("sca_cipher_init: done.\n");

	return (rv);
}

/*
 * This function uses the global lock since it needs to
 * change the reference to the global provider.
 */
static int
sca_get_provider_session(sca_file_private_t *cm,
    crypto_provider_id_t provider_index, sca_provider_session_t **output_ps)
{
	sca_provider_t *pd, *real_prov = NULL;
	sca_provider_session_t *ps, *new_ps;
	crypto_session_id_t provider_session_id = 0;
	crypto_ops_t *ops_vector = NULL;
	unsigned long lock_flags;
	int rv;
	int i;

	SCA_DBG_PRINT("sca_get_provider_session: enter. provider_index:%d\n",
	    provider_index);

	spin_lock_irqsave(&g_sca_lock, lock_flags);

	if (provider_index >= g_sca_provider_count) {
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		return (CRYPTO_FAILED);
	}

	pd = g_sca_provider_array[provider_index];

	/* Check if there is already a session to the provider. */
	for (ps = cm->fp_provider_session; ps != NULL; ps = ps->ps_next) {
		if (ps->ps_provider == pd)
			break;
	}

	/* found existing session */
	if (ps != NULL) {
		ps->ps_refcnt++;
		*output_ps = ps;
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		return (CRYPTO_SUCCESS);
	}

	/* This reference will be released in sca_release_provider_session() */
	atomic_inc(&pd->sp_ref_count);

	spin_unlock_irqrestore(&g_sca_lock, lock_flags);

	/*
	 * Find a session open function entry point.
	 * A real/hardware provider has such an entry point.
	 * For a logical provider, we need to borrow one from the
	 * next available real/hardware provider.
	 */
	SCA_GET_OPS_PROV(pd, real_prov, ops_vector,
	    co_session_ops, session_open, rv);

	if (rv != CRYPTO_SUCCESS) {
		SCA_PROVIDER_RELE(pd);
		return (rv);
	}

	/* allocate crypto_provider_session structure */
	if ((new_ps = kmalloc(sizeof (sca_provider_session_t),
	    GFP_KERNEL)) == NULL) {
		SCA_PROVIDER_RELE(real_prov);
		SCA_PROVIDER_RELE(pd);
		return (CRYPTO_HOST_MEMORY);
	}
	memset(new_ps, 0, sizeof (sca_provider_session_t));

	/*
	 * Open a provider session
	 * The provider handle may be from a real or a logical provider.
	 * However, the session open function entry point is always
	 * from a read provider.
	 */
	if ((rv = ops_vector->co_session_ops->session_open(
	    pd->sp_info->pi_provider_handle,
	    &provider_session_id, NULL)) != CRYPTO_SUCCESS) {
		SCA_PROVIDER_RELE(real_prov);
		SCA_PROVIDER_RELE(pd);
		kfree(new_ps);
		return (rv);
	}

	SCA_PROVIDER_RELE(real_prov);

	/* initialize reference for the session */
	new_ps->ps_refcnt = 1;

	/*
	 * Save the provider session id and the provider reference
	 * Note that the original provider is saved inside the new session
	 * no matter it is logical or real.
	 */
	new_ps->ps_session = provider_session_id;
	new_ps->ps_provider = pd;

	/* Insert in the link list */
	new_ps->ps_next = cm->fp_provider_session;
	cm->fp_provider_session = new_ps;

	*output_ps = new_ps;

	SCA_DBG_PRINT("sca_get_provider_session: done!\n");
	return (CRYPTO_SUCCESS);
}

/*
 * Reduce the reference counter to the provider session.
 */
static void
sca_release_provider_session(sca_file_private_t *cm,
    sca_provider_session_t *provider_session)
{
	sca_provider_session_t *ps = NULL, **prev;
	unsigned long lock_flags;

	SCA_DBG_PRINT("sca_release_provider_session: enter.\n");

	/* verify that provider_session is valid */
	for (ps = cm->fp_provider_session, prev = &cm->fp_provider_session;
	    ps != NULL; prev = &ps->ps_next, ps = ps->ps_next) {
		if (ps == provider_session) {
			break;
		}
	}

	if (ps == NULL)
		return;

	spin_lock_irqsave(&g_sca_lock, lock_flags);

	ps->ps_refcnt--;

	spin_unlock_irqrestore(&g_sca_lock, lock_flags);

	SCA_DBG_PRINT("sca_release_provider_session: done!\n");
}


/*
 * Close the session to the provider. It may be called from
 * C_Finalize or the file descriptor is closed.
 */
static void
sca_close_provider_session(sca_file_private_t *cm)
{
	sca_provider_session_t *ps = NULL, *ps_tmp;
	sca_provider_t *pd, *real_prov = NULL;
	crypto_ops_t *ops_vector = NULL;
	unsigned long lock_flags;
	int rv = CRYPTO_SUCCESS;

	SCA_DBG_PRINT("sca_close_provider_session: enter.\n");

	/* Go through the provider_session list */
	for (ps = cm->fp_provider_session; ps != NULL; ) {
		/* close the session to the provider */
		pd = ps->ps_provider;

		/*
		 * The logical provider does not have session close function
		 * entry point. Need to borrow one from the next available
		 * real provider
		 */
		SCA_GET_OPS_PROV(pd, real_prov, ops_vector,
		    co_session_ops, session_open, rv);

		/*
		 * Skip this if the function entry point is not available for
		 * a logical provider. The provider will cleanup the sessions
		 * at the end.
		 */
		if (rv == CRYPTO_SUCCESS) {
			(void) ops_vector->co_session_ops->session_close(
			    pd->sp_info->pi_provider_handle, ps->ps_session,
			    NULL);
			SCA_PROVIDER_RELE(real_prov);
		}

		/*
		 * Wake up any waiting processes in crypto_unregister_provider.
		 */
		SCA_PROVIDER_RELE(pd);

		ps_tmp = ps;
		ps = ps->ps_next;

		kfree(ps_tmp);
	}

	cm->fp_provider_session = NULL;

	SCA_DBG_PRINT("sca_close_provider_session: done!\n");
}


/*
 * This function is called within the cm->fp_lock lock
 */
static int
sca_grow_session_table(sca_file_private_t *cm)
{
	sca_session_t **session_table;
	sca_session_t **new;
	uint_t session_table_count;
	uint_t need;
	size_t current_allocation;
	size_t new_allocation;

	session_table_count = cm->fp_session_table_count;
	session_table = cm->fp_session_table;
	need = session_table_count + CRYPTO_SESSION_CHUNK;

	SCA_DBG_PRINT("sca_grow_session_table: session_table_count: %d\n",
	    session_table_count);

	current_allocation = session_table_count * sizeof (void *);
	new_allocation = need * sizeof (void *);

	new = kmem_alloc(new_allocation, GFP_ATOMIC);
	if (new == NULL)
		return (CRYPTO_HOST_MEMORY);
	memset(new, 0, new_allocation);

	/* Copy the old session table to the new one and free the old one */
	if (session_table_count > 0)
		memcpy(new, session_table, current_allocation);
	if (session_table)
		kmem_free(session_table, current_allocation);

	cm->fp_session_table = new;
	cm->fp_session_table_count += CRYPTO_SESSION_CHUNK;

	SCA_DBG_PRINT("sca_grow_session_table: session_table_count: %d\n",
	    cm->fp_session_table_count);

	return (CRYPTO_SUCCESS);
}


/*
 * Copy mechanism parameter if there is one.
 */
static int
sca_copyin_mech(caddr_t arg, crypto_mechanism_t *in_mech)
{
	if (in_mech->cm_param_len > crypto_max_buffer_len)
		return (CRYPTO_ARGUMENTS_BAD);

	if (in_mech->cm_param_len > 0) {
		in_mech->cm_param = kmalloc(in_mech->cm_param_len, GFP_KERNEL);
		if (in_mech->cm_param == NULL)
			return (CRYPTO_HOST_MEMORY);

		if (copy_from_user(in_mech->cm_param, (caddr_t)arg,
		    in_mech->cm_param_len) != 0) {
			kfree(in_mech->cm_param);
			in_mech->cm_param = NULL;
			return (CRYPTO_ARGUMENTS_BAD);
		}
	}

	return (CRYPTO_SUCCESS);
}

/*
 * Convert user space attrs to kernel space k_attrs.
 */
static int
sca_get_attrs(uint_t count, uint_t block_len, caddr_t attrs_in,
    crypto_object_attribute_t **k_attrs_out)
{
	crypto_object_attribute_t *k_attrs = NULL;
	caddr_t attrs = NULL, ap, p;
	caddr_t k_attrs_buf;
	size_t k_attrs_len;
	size_t k_attrs_buf_len = 0;
	size_t tmp_len;
	size_t need = 0;
	size_t len = 0;
	size_t value_len;
	int i;
	ATTRIBUTE *aptr;

	SCA_DBG_PRINT("sca_get_attrs: enter: count: %d, block_len: %d\n",
	    count, block_len);

	if (count == 0) {
		return (CRYPTO_SUCCESS);
	}

	if (count > CRYPTO_MAX_ATTRIBUTE_COUNT) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	len = block_len;
	if ((attrs = kmalloc(len, GFP_KERNEL)) == NULL)
		return (CRYPTO_HOST_MEMORY);

	if (copy_from_user(attrs, attrs_in, len) != 0) {
		kfree(attrs);
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/*
	 * figure out how much memory to allocate for all of the attributes.
	 * User space attr format,
	 * ATTRIBUTE 1 + buf 1 + ATTRIBUTE 2 + buf 2 + ...
	 */
	ap = attrs;
	aptr = (ATTRIBUTE *) ap;

	for (i = 0; i < count; i++) {
		tmp_len = SCA_ROUNDUP(aptr->value_length, sizeof (caddr_t));
		if (tmp_len > crypto_max_buffer_len) {
			SCA_ERR_PRINT("sca_get_attrs: buffer greater "
			    "than %ld bytes, pid = %d\n", crypto_max_buffer_len,
			    current->pid);
			kfree(attrs);
			return (CRYPTO_ARGUMENTS_BAD);
		}
		k_attrs_buf_len += tmp_len;

		ap += sizeof (ATTRIBUTE) + aptr->value_length;
		aptr = (ATTRIBUTE *) ap;
	}

	k_attrs_len = count * sizeof (crypto_object_attribute_t);
	need = k_attrs_buf_len + k_attrs_len;

	/*
	 * one big allocation for everything
	 * Kernel space attr format,
	 * crypto_object_attribute_t 1 + crypto_object_attribute_t 2 + ... +
	 * buf 1 + buf 2 + ...
	 */
	if ((k_attrs = kmalloc(need, GFP_KERNEL)) == NULL)
		return (CRYPTO_HOST_MEMORY);
	k_attrs_buf = (char *)k_attrs + k_attrs_len;

	ap = attrs;
	p = k_attrs_buf;
	aptr = (ATTRIBUTE *) ap;
	for (i = 0; i < count; i++) {
		value_len = aptr->value_length;
		if (value_len != 0) {
			memcpy(p, ap + sizeof (ATTRIBUTE), value_len);
		}

		k_attrs[i].oa_type = aptr->type;
		k_attrs[i].oa_value = (value_len == 0) ? NULL : p;
		k_attrs[i].oa_value_len = value_len;

		/* Advance to the next attribute */
		ap += sizeof (ATTRIBUTE) + aptr->value_length;
		p += SCA_ROUNDUP(value_len, sizeof (caddr_t));
		aptr = (ATTRIBUTE *) ap;
	}

	kfree(attrs);
	*k_attrs_out = k_attrs;

	SCA_DBG_PRINT("sca_get_attrs: done!\n");

	return (CRYPTO_SUCCESS);
}

/*
 * Copyout a kernel array of attributes to user space.
 * u_attrs is the corresponding user space array containing
 * user space pointers necessary for the copyout.
 */
static int
sca_set_attrs(uint_t count, uint_t block_len, caddr_t u_attrs,
    crypto_object_attribute_t *k_attrs)
{
	int i;
	caddr_t attrs = NULL;
	ATTRIBUTE *aptr;
	caddr_t ap;
	int value_len;

	if (count == 0)
		return (CRYPTO_SUCCESS);

	if ((attrs = kmalloc(block_len, GFP_KERNEL)) == NULL)
		return (CRYPTO_HOST_MEMORY);

	if (copy_from_user(attrs, u_attrs, block_len) != 0) {
		kfree(attrs);
		return (CRYPTO_ARGUMENTS_BAD);
	}

	ap = attrs;
	aptr = (ATTRIBUTE *) ap;
	for (i = 0; i < count; i++) {
		aptr->value_length = k_attrs[i].oa_value_len;
		aptr->type = k_attrs[i].oa_type;
		value_len = aptr->value_length;
		if (k_attrs[i].oa_value == NULL)
			value_len = 0;

		/* A NULL oa_value means length only */
		if (value_len > 0 && k_attrs[i].oa_value) {
			memcpy(ap + sizeof (ATTRIBUTE), k_attrs[i].oa_value,
			    value_len);
			ap += sizeof (ATTRIBUTE) + value_len;
		} else {
			ap += sizeof (ATTRIBUTE);
		}
		aptr = (ATTRIBUTE *) ap;
	}

	if (copy_to_user(u_attrs, attrs, block_len) != 0) {
		kfree(attrs);
		return (CRYPTO_ARGUMENTS_BAD);
	}

	kfree(attrs);

	return (CRYPTO_SUCCESS);
}

/*
 * This routine does two things:
 * 1. Given a crypto_minor structure and a session ID, it returns
 *    a valid session pointer.
 * 2. It checks that the provider, to which the session has been opened,
 *    has not been removed.
 */
static int
sca_get_session_ptr(crypto_session_id_t i, sca_file_private_t *cm,
    sca_session_t **session_ptr)
{
	sca_session_t *sp = NULL;
	int rv = CRYPTO_SESSION_HANDLE_INVALID;

	spin_lock(&cm->fp_lock);
	if ((i < cm->fp_session_table_count) &&
	    (cm->fp_session_table[i] != NULL)) {
		sp = cm->fp_session_table[i];
		spin_lock(&sp->ss_lock);
		spin_unlock(&cm->fp_lock);

		/* Wait here if the session is busy */
		while (sp->ss_flags & SCA_SESSION_IS_BUSY) {
			spin_unlock(&sp->ss_lock);
			if (wait_event_interruptible(sp->ss_busy_wait,
			    !(sp->ss_flags & SCA_SESSION_IS_BUSY)) != 0) {
				return (CRYPTO_GENERAL_ERROR);
			}
			spin_lock(&sp->ss_lock);
		}

		if (sp->ss_flags & SCA_SESSION_IS_CLOSED) {
			spin_unlock(&sp->ss_lock);
			return (CRYPTO_SESSION_HANDLE_INVALID);
		}

		rv = CRYPTO_SUCCESS;
		sp->ss_flags |= SCA_SESSION_IS_BUSY;
		spin_unlock(&sp->ss_lock);
	} else {
		spin_unlock(&cm->fp_lock);
	}

	*session_ptr = sp;

	return (rv);
}

static int sca_get_co_ctx_ops(sca_session_t *sp, crypto_ops_t **ops_vector,
    sca_provider_t **real)
{
	crypto_provider_handle_t *ph;
	crypto_session_id_t psid;
	sca_provider_t *real_local;
	crypto_ops_t *ops_vector_local;
	int rv;

	SCA_GET_OPS(sp, real_local, ops_vector_local, ph, psid, co_ctx_ops,
	    free_context)

	if ((rv = sca_wait_for_busy_provider(real_local,
	    SCA_PROVIDER_TIMEOUT)) != CRYPTO_SUCCESS)
		return (rv);

	*ops_vector = ops_vector_local;
	*real = real_local;

	return (CRYPTO_SUCCESS);
}


/*
 * Free a session
 */
static void
sca_free_session(sca_file_private_t *jp, sca_session_t *sp, uint_t i)
{
	sca_provider_t *real = NULL;
	crypto_ops_t *ops_vector = NULL;

	if (sp->ss_find_init_cookie != NULL)
		(void) sca_free_find_ctx(sp);

	if (sca_get_co_ctx_ops(sp, &ops_vector, &real) != CRYPTO_SUCCESS) {
		SCA_ERR_PRINT(
		    "sca_free_session: Failed to get free_context function\n");
	}

	/* Free any context */
	if (sp->ss_digest_ctx) {
		SCA_PROVIDER_RELE(sp->ss_digest_ctx->cc_framework_private);
		if (ops_vector != NULL)
			ops_vector->co_ctx_ops->free_context(sp->ss_digest_ctx);
		kfree(sp->ss_digest_ctx);
	}

	if (sp->ss_encr_ctx) {
		SCA_PROVIDER_RELE(sp->ss_encr_ctx->cc_framework_private);
		if (ops_vector != NULL)
			ops_vector->co_ctx_ops->free_context(sp->ss_encr_ctx);
		kfree(sp->ss_encr_ctx);
	}

	if (sp->ss_decr_ctx) {
		SCA_PROVIDER_RELE(sp->ss_decr_ctx->cc_framework_private);
		if (ops_vector != NULL)
			ops_vector->co_ctx_ops->free_context(sp->ss_decr_ctx);
		kfree(sp->ss_decr_ctx);
	}

	if (sp->ss_sign_ctx) {
		SCA_PROVIDER_RELE(sp->ss_sign_ctx->cc_framework_private);
		if (ops_vector != NULL)
			ops_vector->co_ctx_ops->free_context(sp->ss_sign_ctx);
		kfree(sp->ss_sign_ctx);
	}

	if (sp->ss_verify_ctx) {
		SCA_PROVIDER_RELE(sp->ss_verify_ctx->cc_framework_private);
		if (ops_vector != NULL)
			ops_vector->co_ctx_ops->free_context(sp->ss_verify_ctx);
		kfree(sp->ss_verify_ctx);
	}

	if (sp->ss_sign_recover_ctx) {
		SCA_PROVIDER_RELE(
		    sp->ss_sign_recover_ctx->cc_framework_private);
		if (ops_vector != NULL)
			ops_vector->co_ctx_ops->free_context(
			    sp->ss_sign_recover_ctx);
		kfree(sp->ss_sign_recover_ctx);
	}

	if (sp->ss_verify_recover_ctx) {
		SCA_PROVIDER_RELE(
		    sp->ss_verify_recover_ctx->cc_framework_private);
		if (ops_vector != NULL)
			ops_vector->co_ctx_ops->free_context(
			    sp->ss_verify_recover_ctx);
		kfree(sp->ss_verify_recover_ctx);
	}

	sca_release_provider_session(jp, sp->ss_provider_session);

	if (real != NULL)
		SCA_PROVIDER_RELE(real);

	kfree(jp->fp_session_table[i]);
	jp->fp_session_table[i] = NULL;
}

static int
sca_make_slot_list(CK_SLOT_ID_32 *slot_list)
{
	sca_provider_t *provider;
	unsigned long lock_flags;
	int i;
	int count = 0;
	spin_lock_irqsave(&g_sca_lock, lock_flags);
	if (sca_hide_hardware_provider) {
		/*
		 * Only count the logical providers and the hardware providers
		 * that do not belong to any logical providers.
		 */
		for (i = 0; i < g_sca_provider_count; i++) {
			provider = g_sca_provider_array[g_sca_index[i]];
			if (provider->sp_info->pi_provider_type ==
			    CRYPTO_LOGICAL_PROVIDER ||
			    provider->sp_info->pi_logical_provider_count == 0) {
				slot_list[count++] = i;
			}
		}
	} else {
		/* Count all registered providers */
		for (i = 0; i < g_sca_provider_count; i++) {
			slot_list[count++] = i;
		}
	}

	spin_unlock_irqrestore(&g_sca_lock, lock_flags);
	return (count);
}

/*
 * cm_mech_number is the mechanism number defined in the PKCS#11 spec
 *
 * #define CKM_RSA_PKCS_KEY_PAIR_GEN      0x00000000
 * #define CKM_RSA_PKCS                   0x00000001
 * #define CKM_RSA_9796                   0x00000002
 * #define CKM_RSA_X_509                  0x00000003
 * ... ...
 */
static uint_t
sca_make_mechanism_list(sca_provider_t *provider,
    CK_MECHANISM_TYPE_32 *mechanisms)
{
	uint_t mech_list_count;
	crypto_mech_info_t *mech_list;
	crypto_provider_info_t *pi;
	crypto_provider_info_t *info;
	int i, j;
	int count;

	pi = provider->sp_info;
	if (pi->pi_provider_type == CRYPTO_LOGICAL_PROVIDER &&
	    pi->pi_mechanisms == NULL) {
		/*
		 * For the logical provider that does not have a mechanism
		 * list, need to build one from the associated hardware provs.
		 */
		for (count = 0, j = 0; j < provider->sp_hp_count; j++) {
			info = provider->sp_hp_list[j]->sp_info;

			mech_list_count = info->pi_mech_list_count;
			mech_list = info->pi_mechanisms;

			for (i = 0; i < mech_list_count; i++) {
				if (mech_list[i].cm_func_group_mask &
				    g_sca_userland_flags)
					mechanisms[count++] =
					    mech_list[i].cm_mech_number;
			}
		}
	} else {
		mech_list_count = pi->pi_mech_list_count;
		mech_list = pi->pi_mechanisms;

		count = 0;
		for (i = 0; i < mech_list_count; i++) {
			if (mech_list[i].cm_func_group_mask &
			    g_sca_userland_flags)
				mechanisms[count++] =
				    mech_list[i].cm_mech_number;
		}
	}

	return (count);
}

/*
 * A job has been submitted and we wait here for hardware interrupt.
 *
 * Note that wait_event_interruptible() should not be used here, since
 * a hardware interrupt coming back after a user signal (interrupt) may
 * crash the system.
 *
 * Note also that we should not use a timeout here either. If a job is timed
 * out here and eventually the provider comes back and accesses the "sp"
 * pointer, the system may crash. The provider should always handle any
 * hardware/firmware hungs and always call back to let the framework know.
 * It is the provider's responsibility to always call back.
 */
static int sca_wait_on_queued(sca_session_t *sp, int rv, long timeout_secs)
{
	if (rv == CRYPTO_QUEUED) {
		if (sp->ss_state == JS_RUNNING) {
			wait_event(sp->ss_wait,
			    (sp->ss_state == JS_DATA_AVAILABLE));
		}
		rv = sp->ss_rv;
	}

	return (rv);
}

/*
 * Get ops_vector from the ctx of a real provider.
 * Also wait until the provider is ready or failed.
 */
static int sca_get_ops_from_ctx(crypto_ctx_t *ctx, crypto_ops_t **ops_vector,
    long timeout_secs)
{
	sca_provider_t *real;

	if (ctx == NULL || ctx->cc_framework_private == NULL) {
		return (CRYPTO_OPERATION_NOT_INITIALIZED);
	}

	real = (sca_provider_t *)ctx->cc_framework_private;
	*ops_vector = real->sp_info->pi_ops_vector;

	if (real->sp_state == CRYPTO_PROVIDER_BUSY) {
		if ((wait_event_timeout_local(real->sp_busy_queue,
		    (real->sp_state != CRYPTO_PROVIDER_BUSY),
		    timeout_secs * HZ)) == 0) {
			return (CRYPTO_GENERAL_ERROR);
		}
	}

	return (CRYPTO_SUCCESS);
}

static int sca_wait_for_busy_provider(sca_provider_t *real, long timeout_secs)
{
	if (real->sp_state == CRYPTO_PROVIDER_BUSY) {
		wait_event(real->sp_busy_queue,
		    (real->sp_state != CRYPTO_PROVIDER_BUSY));
	}

	if (real->sp_state == CRYPTO_PROVIDER_FAILED)
		return (CRYPTO_GENERAL_ERROR);
	else
		return (CRYPTO_SUCCESS);
}

static int sca_init_raw_crypto_data(crypto_data_t *data, size_t len)
{
	data->cd_format = CRYPTO_DATA_RAW;
	data->cd_raw.iov_base = kmalloc(len, GFP_KERNEL);
	if (data->cd_raw.iov_base == NULL)
		return (CRYPTO_HOST_MEMORY);

	data->cd_raw.iov_len = len;
	data->cd_offset = 0;
	data->cd_length = len;

	return (CRYPTO_SUCCESS);
}

#if !defined(i386) && !defined(__i386) && \
    (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,9))
/* for AMD 64 bit kernel compatibility with 32-bit userland ioctls */
extern long sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);
extern int register_ioctl32_conversion(unsigned int cmd,
    int (*handler)(unsigned int, unsigned int, unsigned long, struct file *));
extern int unregister_ioctl32_conversion(unsigned int cmd);

typedef int (*handler_type) (unsigned int, unsigned int, unsigned long,
    struct file *);

static struct ioctl32_map {
	unsigned int cmd;
	handler_type handler;
	int registered;
} sca_ioctl32_map[] = {
	{SCA_INITIALIZE,		(handler_type) sys_ioctl, 0},
	{SCA_FINALIZE,			(handler_type) sys_ioctl, 0},
	{SCA_GETINFO,			(handler_type) sys_ioctl, 0},
	{SCA_GETFUNCTIONLIST,		(handler_type) sys_ioctl, 0},
	{SCA_GETSLOTLIST,		(handler_type) sys_ioctl, 0},
	{SCA_GETSLOTINFO,		(handler_type) sys_ioctl, 0},
	{SCA_GETTOKENINFO,		(handler_type) sys_ioctl, 0},
	{SCA_WAITFORSLOTEVENT,		(handler_type) sys_ioctl, 0},
	{SCA_GETMECHANISMLIST,		(handler_type) sys_ioctl, 0},
	{SCA_GETMECHANISMINFO,		(handler_type) sys_ioctl, 0},
	{SCA_INITTOKEN,			(handler_type) sys_ioctl, 0},
	{SCA_INITPIN,			(handler_type) sys_ioctl, 0},
	{SCA_SETPIN,			(handler_type) sys_ioctl, 0},

	{SCA_OPENSESSION,		(handler_type) sys_ioctl, 0},
	{SCA_CLOSESESSION,		(handler_type) sys_ioctl, 0},
	{SCA_CLOSEALLSESSIONS,		(handler_type) sys_ioctl, 0},
	{SCA_GETSESSIONINFO,		(handler_type) sys_ioctl, 0},
	{SCA_GETOPERATIONSTATE,		(handler_type) sys_ioctl, 0},
	{SCA_SETOPERATIONSTATE,		(handler_type) sys_ioctl, 0},
	{SCA_LOGIN,			(handler_type) sys_ioctl, 0},
	{SCA_LOGOUT,			(handler_type) sys_ioctl, 0},

	{SCA_CREATEOBJECT,		(handler_type) sys_ioctl, 0},
	{SCA_COPYOBJECT,		(handler_type) sys_ioctl, 0},
	{SCA_DESTROYOBJECT,		(handler_type) sys_ioctl, 0},
	{SCA_GETOBJECTSIZE,		(handler_type) sys_ioctl, 0},
	{SCA_GETATTRIBUTEVALUE,		(handler_type) sys_ioctl, 0},
	{SCA_SETATTRIBUTEVALUE,		(handler_type) sys_ioctl, 0},
	{SCA_FINDOBJECTSINIT,		(handler_type) sys_ioctl, 0},
	{SCA_FINDOBJECTS,		(handler_type) sys_ioctl, 0},
	{SCA_FINDOBJECTSFINAL,		(handler_type) sys_ioctl, 0},

	{SCA_ENCRYPTINIT,		(handler_type) sys_ioctl, 0},
	{SCA_ENCRYPT,			(handler_type) sys_ioctl, 0},
	{SCA_ENCRYPTUPDATE,		(handler_type) sys_ioctl, 0},
	{SCA_ENCRYPTFINAL,		(handler_type) sys_ioctl, 0},

	{SCA_DECRYPTINIT,		(handler_type) sys_ioctl, 0},
	{SCA_DECRYPT,			(handler_type) sys_ioctl, 0},
	{SCA_DECRYPTUPDATE,		(handler_type) sys_ioctl, 0},
	{SCA_DECRYPTFINAL,		(handler_type) sys_ioctl, 0},

	{SCA_DIGESTINIT,		(handler_type) sys_ioctl, 0},
	{SCA_DIGEST,			(handler_type) sys_ioctl, 0},
	{SCA_DIGESTUPDATE,		(handler_type) sys_ioctl, 0},
	{SCA_DIGESTKEY,			(handler_type) sys_ioctl, 0},
	{SCA_DIGESTFINAL,		(handler_type) sys_ioctl, 0},

	{SCA_SIGNINIT,			(handler_type) sys_ioctl, 0},
	{SCA_SIGN,			(handler_type) sys_ioctl, 0},
	{SCA_SIGNUPDATE,		(handler_type) sys_ioctl, 0},
	{SCA_SIGNFINAL,			(handler_type) sys_ioctl, 0},
	{SCA_SIGNRECOVERINIT,		(handler_type) sys_ioctl, 0},
	{SCA_SIGNRECOVER,		(handler_type) sys_ioctl, 0},

	{SCA_VERIFYINIT,		(handler_type) sys_ioctl, 0},
	{SCA_VERIFY,			(handler_type) sys_ioctl, 0},
	{SCA_VERIFYUPDATE,		(handler_type) sys_ioctl, 0},
	{SCA_VERIFYFINAL,		(handler_type) sys_ioctl, 0},
	{SCA_VERIFYRECOVERINIT,		(handler_type) sys_ioctl, 0},
	{SCA_VERIFYRECOVER,		(handler_type) sys_ioctl, 0},

	{SCA_DIGESTENCRYPTUPDATE,	(handler_type) sys_ioctl, 0},
	{SCA_DECRYPTDIGESTUPDATE,	(handler_type) sys_ioctl, 0},
	{SCA_SIGNENCRYPTUPDATE,		(handler_type) sys_ioctl, 0},
	{SCA_DECRYPTVERIFYUPDATE,	(handler_type) sys_ioctl, 0},

	{SCA_GENERATEKEY,		(handler_type) sys_ioctl, 0},
	{SCA_GENERATEKEYPAIR,		(handler_type) sys_ioctl, 0},
	{SCA_WRAPKEY,			(handler_type) sys_ioctl, 0},
	{SCA_UNWRAPKEY,			(handler_type) sys_ioctl, 0},
	{SCA_DERIVEKEY,			(handler_type) sys_ioctl, 0},

	{SCA_SEEDRANDOM,		(handler_type) sys_ioctl, 0},
	{SCA_GENERATERANDOM,		(handler_type) sys_ioctl, 0},

	{SCA_GETFUNCTIONSTATUS,		(handler_type) sys_ioctl, 0},
	{SCA_CANCELFUNCTION,		(handler_type) sys_ioctl, 0},
};

#define	SCA_IOCTL32_ENTRIES	\
	(sizeof (sca_ioctl32_map) / sizeof (sca_ioctl32_map[0]))

static void register_sca_ioctl32(void)
{
	int i, rc;

	for (i = 0; i < SCA_IOCTL32_ENTRIES; i++) {
		rc = register_ioctl32_conversion(
			sca_ioctl32_map[i].cmd,
			sca_ioctl32_map[i].handler);
		if (rc != 0) {
			printk(KERN_WARNING "register_sca_ioctl32: failed to "
			    "register 32 bit compatible ioctl 0x%08x\n",
			    sca_ioctl32_map[i].cmd);
			sca_ioctl32_map[i].registered = 0;
		} else {
			sca_ioctl32_map[i].registered = 1;
		}
	}
}
static void unregister_sca_ioctl32(void)
{
	int i, rc;

	for (i = 0; i < SCA_IOCTL32_ENTRIES; i++) {
		if (!sca_ioctl32_map[i].registered)
			continue;
		rc = unregister_ioctl32_conversion(sca_ioctl32_map[i].cmd);
		if (rc == 0) {
			sca_ioctl32_map[i].registered = 0;
			continue;
		}
		printk(KERN_WARNING "sca: failed to unregister "
			"32 bit compatible ioctl 0x%08x\n",
			sca_ioctl32_map[i].cmd);
	}
}
#endif
