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

#pragma ident	"@(#)sca_spi.c	1.11	07/06/25 SMI"

/*
 * The SPI interface for the Sun Crypto Accelerator Framework on Linux platform
 */

#include "sol2lin.h"
#include "common.h"
#include "spi.h"
#include "pkcs11types.h"
#include "pkcs32.h"
#include "sca_defs.h"
#include "sca_private.h"

extern spinlock_t		g_sca_lock;
extern sca_provider_t		*g_sca_provider_array[MAX_NUMBER_PROVIDER];
extern uint_t			g_sca_provider_count;
extern int			g_sca_index[MAX_NUMBER_PROVIDER];

static int sca_alloc_provider_info(crypto_provider_info_t *desc,
    crypto_provider_info_t *info);
static int sca_add_hardware_to_logical_provider(crypto_provider_info_t *pi,
    sca_provider_t *sp);
static int sca_remove_hardware_from_logical_provider(sca_provider_t *sp);
static int sca_rem_logical_from_hw_providers(sca_provider_t *sp);
static void sca_free_provider_info(crypto_provider_info_t *info);

static void sca_insert_provider_to_slot_list(
    crypto_provider_type_t provider_type, uint_t logical_provider_count,
    int index, int provider_count);
static void sca_delete_provider_from_slot_list(int index, int provider_count);

/*
 * The API for provider registration.
 */
int crypto_register_provider(crypto_provider_info_t *pi,
    crypto_kcf_provider_handle_t *ph)
{
	sca_provider_t *sp = NULL;
	unsigned long lock_flags;
	int index;
	int rv;

	SCA_DBG_PRINT("crypto_register_provider: enter\n");

	if (pi == NULL || ph == NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/*
	 * Check provider type, must be hardware or logical.
	 */
	if (pi->pi_provider_type == CRYPTO_LOGICAL_PROVIDER) {
		/* Requirements for logical providers */
		if (pi->pi_ops_vector != NULL ||
		    pi->pi_logical_provider_count != 0 ||
		    pi->pi_logical_providers != NULL) {
			SCA_ERR_PRINT("crypto_register_provider: Bad parameters"
			    " for a logical provider\n");
			return (CRYPTO_ARGUMENTS_BAD);
		}
		SCA_DBG_PRINT("crypto_register_provider: "
		    " registering a logical provider\n");
	} else if (pi->pi_provider_type == CRYPTO_HW_PROVIDER) {
		/* Requirements for hardware providers */
		if (pi->pi_ops_vector == NULL) {
			SCA_ERR_PRINT("crypto_register_provider: Bad parameters"
			    " for a hardware provider\n");
			return (CRYPTO_ARGUMENTS_BAD);
		}
		SCA_DBG_PRINT("crypto_register_provider: "
		    "registering a hardware provider\n");
	} else {
		SCA_ERR_PRINT("crypto_register_provider: unknown provider "
		    "type: %d\n", pi->pi_provider_type);
		return (CRYPTO_ARGUMENTS_BAD);
	}

	spin_lock_irqsave(&g_sca_lock, lock_flags);

	/*
	 * Find an unused spot on the global provider array.
	 * The spot is set to NULL when a provider is unregistered.
	 * The ordering of slots is unimportant here.
	 * A hardware provider could be before or after its logical provider.
	 */
	for (index = 0; index < MAX_NUMBER_PROVIDER; index++) {
		if (g_sca_provider_array[index] == NULL)
			break;
	}

	/*
	 * Limited number of providers may be registered.
	 * Should never have more than this number of providers.
	 */
	if (index == MAX_NUMBER_PROVIDER) {
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		SCA_ERR_PRINT("crypto_register_provider: there are %d "
		    "providers already\n", MAX_NUMBER_PROVIDER);
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/* Allocate provider and provider information */
	if ((sp = kmalloc(sizeof (sca_provider_t), GFP_ATOMIC)) == NULL) {
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		return (CRYPTO_HOST_MEMORY);
	}
	memset(sp, 0, sizeof (sca_provider_t));

	if ((sp->sp_info = kmalloc(sizeof (crypto_provider_info_t),
	    GFP_ATOMIC)) == NULL) {
		kfree(sp);
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		return (CRYPTO_HOST_MEMORY);
	}
	memset(sp->sp_info, 0, sizeof (crypto_provider_info_t));

	/* Copy the provider information */
	if ((rv = sca_alloc_provider_info(sp->sp_info, pi)) != CRYPTO_SUCCESS) {
		kfree(sp->sp_info);
		kfree(sp);
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		return (rv);
	}

	if ((rv = sca_add_hardware_to_logical_provider(pi, sp)) !=
	    CRYPTO_SUCCESS) {
		sca_free_provider_info(sp->sp_info);
		kfree(sp->sp_info);
		kfree(sp);
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		return (rv);
	}

	/* Initialize the provider state and other parameters */
	sp->sp_state = CRYPTO_PROVIDER_READY;
	sp->sp_id = index;
	init_waitqueue_head(&sp->sp_wait);
	init_waitqueue_head(&sp->sp_busy_queue);
	g_sca_provider_array[index] = sp;

	sca_insert_provider_to_slot_list(pi->pi_provider_type,
	    pi->pi_logical_provider_count, index, g_sca_provider_count);

	/* Count this provider */
	g_sca_provider_count++;

	/*
	 * Return the provider ID (index+1) to the provider.
	 * 0 is used as an invalid handler inside providers.
	 */
	*ph = index+1;

	spin_unlock_irqrestore(&g_sca_lock, lock_flags);

	SCA_DBG_PRINT("crypto_register_provider: done: ID: %d, total: %d\n",
	    index, g_sca_provider_count);

	return (CRYPTO_SUCCESS);
}

int
crypto_unregister_provider(crypto_kcf_provider_handle_t ph_in)
{
	sca_provider_t *sp = NULL;
	unsigned long lock_flags;
	crypto_kcf_provider_handle_t ph = ph_in - 1;
	int rv;

	SCA_DBG_PRINT("crypto_unregister_provider: enter\n");

	spin_lock_irqsave(&g_sca_lock, lock_flags);

	if (ph >= 0 && ph < MAX_NUMBER_PROVIDER &&
	    g_sca_provider_array[ph] != NULL) {
		sp = g_sca_provider_array[ph];
	} else {
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		SCA_ERR_PRINT("crypto_unregister_provider: invalid provider "
		    "ID: %d\n", ph);
		return (CRYPTO_UNKNOWN_PROVIDER);
	}

	/*
	 * Prevent any further use of this provider.
	 * Let any waitors know that this provider is no longer
	 * in service
	 */
	sp->sp_state = CRYPTO_PROVIDER_FAILED;
	wake_up(&sp->sp_busy_queue);

	if (atomic_read(&sp->sp_ref_count) != 0) {
		/*
		 * There are unfinished jobs on this provider,
		 * needs to wait here until all of them are done.
		 * When a job is returned from the provider, the count will be
		 * decremented and a wakeup will be called on the sp_wait queue.
		 */
		SCA_DBG_PRINT("crypto_unregister_provider: ref_count: %d\n",
		    atomic_read(&sp->sp_ref_count));
		spin_unlock_irqrestore(&g_sca_lock, lock_flags);
		wait_event(sp->sp_wait, atomic_read(&sp->sp_ref_count) == 0);
		/*
		 * Once we are here, the provider is unreferenced and thus
		 * ready to be removed. Grab the lock first.
		 */
		spin_lock_irqsave(&g_sca_lock, lock_flags);
	}

	/*
	 * It must be either hardware or logical provider.
	 * This has been inforced during provider registration.
	 */
	if (sp->sp_info->pi_provider_type == CRYPTO_HW_PROVIDER) {
		/* Dissociate a hardware provider from its logical provider */
		if ((rv = sca_remove_hardware_from_logical_provider(sp)) !=
		    CRYPTO_SUCCESS) {
			spin_unlock_irqrestore(&g_sca_lock, lock_flags);
			return (rv);
		}
	} else {
		/* Dissociate a logical provider from its hardware providers */
		if ((rv = sca_rem_logical_from_hw_providers(sp)) !=
		    CRYPTO_SUCCESS) {
			spin_unlock_irqrestore(&g_sca_lock, lock_flags);
			return (rv);
		}
	}

	sca_free_provider_info(sp->sp_info);
	kfree(sp->sp_info);
	kfree(sp);

	sca_delete_provider_from_slot_list(ph, g_sca_provider_count);

	g_sca_provider_array[ph] = NULL;
	g_sca_provider_count--;

	spin_unlock_irqrestore(&g_sca_lock, lock_flags);

	SCA_DBG_PRINT("crypto_unregister_provider: done: ID: %d, total: %d\n",
	    ph, g_sca_provider_count);

	return (CRYPTO_SUCCESS);
}

void crypto_provider_notification(crypto_kcf_provider_handle_t ph_in,
    uint_t state)
{
	unsigned long lock_flags;
	crypto_kcf_provider_handle_t ph = ph_in - 1;

	SCA_DBG_PRINT("crypto_provider_notification: enter: "
	    "ID: %d, state: %d\n", ph, state);

	spin_lock_irqsave(&g_sca_lock, lock_flags);

	if (ph >= 0 && ph < MAX_NUMBER_PROVIDER &&
	    g_sca_provider_array[ph] != NULL) {
		g_sca_provider_array[ph]->sp_state = state;
		if (state != CRYPTO_PROVIDER_BUSY)
			wake_up(&g_sca_provider_array[ph]->sp_busy_queue);
	}

	spin_unlock_irqrestore(&g_sca_lock, lock_flags);

	SCA_DBG_PRINT("crypto_provider_notification: done!\n");
}

void
crypto_op_notification(crypto_req_handle_t rh, int rv)
{
	sca_session_t *jp = (sca_session_t *)rh;

	SCA_DBG_PRINT("crypto_op_notification: enter: rv: 0x%x\n", rv);

	if (jp != NULL) {
		jp->ss_rv = rv;
		jp->ss_state = JS_DATA_AVAILABLE;
		wake_up(&jp->ss_wait);
	}

	SCA_DBG_PRINT("crypto_op_notification: done!\n");
}

static int
sca_alloc_provider_info(crypto_provider_info_t *desc,
    crypto_provider_info_t *info)
{
	uint_t mech_list_count = info->pi_mech_list_count;
	crypto_ops_t *src_ops = info->pi_ops_vector;
	crypto_ops_t *dst_ops;
	int len;
	int slen;

	/*
	 * Allocate enough room for one extra null terminator.
	 */
	if ((desc->pi_provider_description =
	    kmalloc(CRYPTO_PROVIDER_DESCR_MAX_LEN + 1, GFP_ATOMIC)) == NULL) {
		return (CRYPTO_HOST_MEMORY);
	}

	/* Initialize the string to the padding char */
	(void) memset(desc->pi_provider_description, ' ',
	    CRYPTO_PROVIDER_DESCR_MAX_LEN);
	desc->pi_provider_description[CRYPTO_PROVIDER_DESCR_MAX_LEN] = '\0';

	slen = strlen(info->pi_provider_description);
	len = slen < CRYPTO_PROVIDER_DESCR_MAX_LEN ?
	    slen : CRYPTO_PROVIDER_DESCR_MAX_LEN;
	memcpy(desc->pi_provider_description, info->pi_provider_description,
	    len);

	/* Copy the mechanism list if it exists */
	if (info->pi_mechanisms != NULL && mech_list_count > 0) {
		if ((desc->pi_mechanisms =
		    kmalloc(sizeof (crypto_mech_info_t) * mech_list_count,
		    GFP_ATOMIC)) == NULL) {
			kfree(desc->pi_provider_description);
			desc->pi_provider_description = NULL;
			return (CRYPTO_HOST_MEMORY);
		}
		memcpy(desc->pi_mechanisms, info->pi_mechanisms,
		    sizeof (crypto_mech_info_t) * mech_list_count);
		desc->pi_mech_list_count = mech_list_count;
	}

	/* Copy the logical provider list if it exists */
	if (info->pi_logical_providers != NULL &&
	    info->pi_logical_provider_count > 0) {
		if ((desc->pi_logical_providers =
		    kmalloc(sizeof (crypto_kcf_provider_handle_t) *
		    info->pi_logical_provider_count,
		    GFP_ATOMIC)) == NULL) {
			kfree(desc->pi_provider_description);
			kfree(desc->pi_mechanisms);
			desc->pi_provider_description = NULL;
			desc->pi_mechanisms = NULL;
			return (CRYPTO_HOST_MEMORY);
		}
		memcpy(desc->pi_logical_providers, info->pi_logical_providers,
		    info->pi_logical_provider_count *
		    sizeof (crypto_kcf_provider_handle_t));
	}

	/* Copy other parameters */
	desc->pi_interface_version = info->pi_interface_version;
	desc->pi_provider_type = info->pi_provider_type;
	desc->pi_provider_dev = info->pi_provider_dev;
	desc->pi_provider_handle = info->pi_provider_handle;
	desc->pi_logical_provider_count = info->pi_logical_provider_count;

	/*
	 * Logical provider does not have function entry points.
	 * Thus return here.
	 */
	if (desc->pi_provider_type == CRYPTO_LOGICAL_PROVIDER)
		return (CRYPTO_SUCCESS);

	/*
	 * Since the framework does not require the ops vector specified
	 * by the providers during registration to be persistent,
	 * scaf needs to allocate storage where copies of the ops
	 * vectors are stored.
	 */
	if ((desc->pi_ops_vector = kmalloc(sizeof (crypto_ops_t), GFP_ATOMIC))
	    == NULL) {
		kfree(desc->pi_provider_description);
		kfree(desc->pi_mechanisms);
		kfree(desc->pi_logical_providers);
		memset(desc, 0, sizeof (crypto_provider_info_t));
		return (CRYPTO_HOST_MEMORY);
	}
	memset(desc->pi_ops_vector, 0, sizeof (crypto_ops_t));
	dst_ops = desc->pi_ops_vector;

	if (src_ops->co_control_ops != NULL) {
		if ((dst_ops->co_control_ops = kmalloc(
		    sizeof (crypto_control_ops_t), GFP_ATOMIC)) == NULL)
			goto free_exit;
		memcpy(dst_ops->co_control_ops, src_ops->co_control_ops,
		    sizeof (crypto_control_ops_t));
	}

	if (src_ops->co_digest_ops != NULL) {
		if ((dst_ops->co_digest_ops = kmalloc(
		    sizeof (crypto_digest_ops_t), GFP_ATOMIC)) == NULL)
			goto free_exit;
		memcpy(dst_ops->co_digest_ops, src_ops->co_digest_ops,
		    sizeof (crypto_digest_ops_t));
	}

	if (src_ops->co_cipher_ops != NULL) {
		if ((dst_ops->co_cipher_ops = kmalloc(
		    sizeof (crypto_cipher_ops_t), GFP_ATOMIC)) == NULL)
			goto free_exit;
		memcpy(dst_ops->co_cipher_ops, src_ops->co_cipher_ops,
		    sizeof (crypto_cipher_ops_t));
	}

	if (src_ops->co_mac_ops != NULL) {
		if ((dst_ops->co_mac_ops = kmalloc(
		    sizeof (crypto_mac_ops_t), GFP_ATOMIC)) == NULL)
			goto free_exit;
		memcpy(dst_ops->co_mac_ops, src_ops->co_mac_ops,
		    sizeof (crypto_mac_ops_t));
	}

	if (src_ops->co_sign_ops != NULL) {
		if ((dst_ops->co_sign_ops = kmalloc(
		    sizeof (crypto_sign_ops_t), GFP_ATOMIC)) == NULL)
			goto free_exit;
		memcpy(dst_ops->co_sign_ops, src_ops->co_sign_ops,
		    sizeof (crypto_sign_ops_t));
	}

	if (src_ops->co_verify_ops != NULL) {
		if ((dst_ops->co_verify_ops = kmalloc(
		    sizeof (crypto_verify_ops_t), GFP_ATOMIC)) == NULL)
			goto free_exit;
		memcpy(dst_ops->co_verify_ops, src_ops->co_verify_ops,
		    sizeof (crypto_verify_ops_t));
	}

	if (src_ops->co_dual_ops != NULL) {
		if ((dst_ops->co_dual_ops = kmalloc(
		    sizeof (crypto_dual_ops_t), GFP_ATOMIC)) == NULL)
			goto free_exit;
		memcpy(dst_ops->co_dual_ops, src_ops->co_dual_ops,
		    sizeof (crypto_dual_ops_t));
	}

	if (src_ops->co_dual_cipher_mac_ops != NULL) {
		if ((dst_ops->co_dual_cipher_mac_ops = kmalloc(
		    sizeof (crypto_dual_cipher_mac_ops_t), GFP_ATOMIC)) == NULL)
			goto free_exit;
		memcpy(dst_ops->co_dual_cipher_mac_ops,
		    src_ops->co_dual_cipher_mac_ops,
		    sizeof (crypto_dual_cipher_mac_ops_t));
	}

	if (src_ops->co_session_ops != NULL) {
		if ((dst_ops->co_session_ops = kmalloc(
		    sizeof (crypto_session_ops_t), GFP_ATOMIC)) == NULL)
			goto free_exit;
		memcpy(dst_ops->co_session_ops, src_ops->co_session_ops,
		    sizeof (crypto_session_ops_t));
	}

	if (src_ops->co_object_ops != NULL) {
		if ((dst_ops->co_object_ops = kmalloc(
		    sizeof (crypto_object_ops_t), GFP_ATOMIC)) == NULL)
			goto free_exit;
		memcpy(dst_ops->co_object_ops, src_ops->co_object_ops,
		    sizeof (crypto_object_ops_t));
	}

	if (src_ops->co_key_ops != NULL) {
		if ((dst_ops->co_key_ops = kmalloc(
		    sizeof (crypto_key_ops_t), GFP_ATOMIC)) == NULL)
			goto free_exit;
		memcpy(dst_ops->co_key_ops, src_ops->co_key_ops,
		    sizeof (crypto_key_ops_t));
	}

	if (src_ops->co_provider_ops != NULL) {
		if ((dst_ops->co_provider_ops = kmalloc(
		    sizeof (crypto_provider_management_ops_t), GFP_ATOMIC)) ==
		    NULL)
			goto free_exit;
		memcpy(dst_ops->co_provider_ops, src_ops->co_provider_ops,
		    sizeof (crypto_provider_management_ops_t));
	}

	if (src_ops->co_ctx_ops != NULL) {
		if ((dst_ops->co_ctx_ops = kmalloc(
		    sizeof (crypto_ctx_ops_t), GFP_ATOMIC)) == NULL)
			goto free_exit;
		memcpy(dst_ops->co_ctx_ops, src_ops->co_ctx_ops,
		    sizeof (crypto_ctx_ops_t));
	}

	if (src_ops->co_random_ops != NULL) {
		if ((dst_ops->co_random_ops = kmalloc(
		    sizeof (crypto_random_number_ops_t), GFP_ATOMIC)) == NULL)
			goto free_exit;
		memcpy(dst_ops->co_random_ops, src_ops->co_random_ops,
		    sizeof (crypto_random_number_ops_t));
	}

	return (CRYPTO_SUCCESS);

free_exit:

	/* Free the memory upon error */
	sca_free_provider_info(info);

	return (CRYPTO_HOST_MEMORY);
}


/*
 * Add the hardware provider to its logical provider's hardware provider list.
 * This function is called within the global spin lock.
 */
static int
sca_add_hardware_to_logical_provider(crypto_provider_info_t *pi,
    sca_provider_t *sp)
{
	sca_provider_t *lp;
	int lp_id;
	int i, j;

	if (pi->pi_provider_type != CRYPTO_HW_PROVIDER ||
	    pi->pi_logical_provider_count <= 0) {
		/*
		 * It is either not a hardware provider or a hardware
		 * provider that does not belond to any logical providers.
		 */
		return (CRYPTO_SUCCESS);
	}

	for (i = 0; i < pi->pi_logical_provider_count; i++) {
		/* Subtract provider id by 1 */
		lp_id = pi->pi_logical_providers[i] - 1;
		/* Verify the logical provider ID */
		if (lp_id < 0 || lp_id >= MAX_NUMBER_PROVIDER ||
		    g_sca_provider_array[lp_id] == NULL) {
			return (CRYPTO_FAILED);
		}

		lp = g_sca_provider_array[lp_id];

		/* Increment the hardware provider count of the logical prov */
		lp->sp_hp_count++;

		/*
		 * Find the first empty spot in the logical provider's
		 * list and insert the hardware provider there.
		 */
		for (j = 0; j < lp->sp_hp_count; j++) {
			if (lp->sp_hp_list[j] == NULL) {
				lp->sp_hp_list[j] = sp;
				break;
			}
		}

		/* Sanity check */
		if (j == lp->sp_hp_count) {
			lp->sp_hp_count--;
			return (CRYPTO_FAILED);
		}
	}

	return (CRYPTO_SUCCESS);
}

/*
 * Remove a hardware provider from its logical provider's hardware provider
 * list.
 * This function is called within the global spin lock.
 */
static int
sca_remove_hardware_from_logical_provider(sca_provider_t *sp)
{
	sca_provider_t *lp;
	crypto_provider_info_t *pi = sp->sp_info;
	int lp_id;
	int i, j;

	for (i = 0; i < pi->pi_logical_provider_count; i++) {
		/* Subtract provider id by 1 */
		lp_id = pi->pi_logical_providers[i] - 1;

		/* Verify the logical provider ID */
		if (lp_id < 0 || lp_id >= MAX_NUMBER_PROVIDER ||
		    g_sca_provider_array[lp_id] == NULL) {
			return (CRYPTO_FAILED);
		}

		lp = g_sca_provider_array[lp_id];

		/* The hardware provider list is a list of references */
		for (j = 0; j < MAX_NUMBER_PROVIDER; j++) {
			if (lp->sp_hp_list[j] == sp) {
				lp->sp_hp_count--;
				if (lp->sp_next_hp_index >= lp->sp_hp_count)
					lp->sp_next_hp_index = 0;
				lp->sp_hp_list[j] = NULL;
				break;
			}
		}
		for (; j < MAX_NUMBER_PROVIDER - 1; j++)
			lp->sp_hp_list[j] = lp->sp_hp_list[j + 1];
	}

	return (CRYPTO_SUCCESS);
}

/*
 * Remove a logical provider from its associated hardware providers.
 * This function is called within the global spin lock.
 */
static int
sca_rem_logical_from_hw_providers(sca_provider_t *sp)
{
	sca_provider_t *hp;
	crypto_provider_info_t *hpi;
	int lp_id;
	int i, j;

	/* Loop through the hardware provider list */
	for (i = 0; i < sp->sp_hp_count; i++) {
		hp = sp->sp_hp_list[i];
		hpi = hp->sp_info;

		/* For each hw provider, locate the current logical provider */
		for (j = 0; j < hpi->pi_logical_provider_count; j++) {
			/* Subtract provider id by 1 */
			lp_id = hpi->pi_logical_providers[j] - 1;

			if (lp_id == sp->sp_id)
				break;
		}

		/* Remove the logical provider from the hw provider */
		if (j < hpi->pi_logical_provider_count) {
			SCA_DBG_PRINT("sca_rem_logical_from_hw_providers: "
			    "hw: %d, lc: %d\n", hp->sp_id, sp->sp_id);
			/*
			 * "j" is the logical provider index found.
			 * Shift the provider IDs down to erase "j".
			 */
			for (; j < hpi->pi_logical_provider_count - 1; j++) {
				hpi->pi_logical_providers[j] =
				    hpi->pi_logical_providers[j + 1];
			}

			/*
			 * Decrement the logical provider count and free
			 * the logical provider array if nothing in there.
			 */
			hpi->pi_logical_provider_count--;
			if (hpi->pi_logical_provider_count == 0) {
				kfree(hpi->pi_logical_providers);
				hpi->pi_logical_providers = NULL;
			}
		}

		/* NULL the hardware provider from the logical provider */
		sp->sp_hp_list[i] = NULL;
	}

	/* Dissociated all the hardware providers */
	sp->sp_hp_count = 0;

	return (CRYPTO_SUCCESS);
}

/*
 * Free the contents of a crypto_provider_info_t data structure.
 */
static void sca_free_provider_info(crypto_provider_info_t *info)
{
	crypto_ops_t *ops;

	if (info->pi_provider_description != NULL)
		kfree(info->pi_provider_description);

	if (info->pi_mechanisms != NULL)
		kfree(info->pi_mechanisms);

	if (info->pi_logical_providers != NULL)
		kfree(info->pi_logical_providers);

	if (info->pi_ops_vector != NULL) {
		ops = info->pi_ops_vector;

		if (ops->co_control_ops)
			kfree(ops->co_control_ops);

		if (ops->co_digest_ops)
			kfree(ops->co_digest_ops);

		if (ops->co_cipher_ops)
			kfree(ops->co_cipher_ops);

		if (ops->co_mac_ops)
			kfree(ops->co_mac_ops);

		if (ops->co_sign_ops)
			kfree(ops->co_sign_ops);

		if (ops->co_verify_ops)
			kfree(ops->co_verify_ops);

		if (ops->co_dual_ops)
			kfree(ops->co_dual_ops);

		if (ops->co_dual_cipher_mac_ops)
			kfree(ops->co_dual_cipher_mac_ops);

		if (ops->co_session_ops)
			kfree(ops->co_session_ops);

		if (ops->co_object_ops)
			kfree(ops->co_object_ops);

		if (ops->co_key_ops)
			kfree(ops->co_key_ops);

		if (ops->co_provider_ops)
			kfree(ops->co_provider_ops);

		if (ops->co_ctx_ops)
			kfree(ops->co_ctx_ops);

		if (ops->co_random_ops)
			kfree(ops->co_random_ops);

		kfree(info->pi_ops_vector);
	}

	memset(info, 0, sizeof (crypto_provider_info_t));
}

/*
 * g_sca_index[] is an indirect array. It is used to arrange the provider
 * sequence which is the slot list seen from the apps.
 *
 * We put all logical providers first, then the independent hardware
 * providers, and at last the dependent hardware providers. Thus whether
 * the dependent hardware providers are shown or not on the slot list,
 * the slot ID of other providers will not change. The dependent hardware
 * providers are not shown on the slot list by default.
 */
static void
sca_insert_provider_to_slot_list(crypto_provider_type_t provider_type,
    uint_t logical_provider_count, int index, int provider_count)
{
	int i, n;

	if (provider_type == CRYPTO_HW_PROVIDER &&
	    logical_provider_count != 0) {
		/*
		 * Append the dependent hardware provider at the end of
		 * the slot list
		 */
		g_sca_index[provider_count] = index;
	} else {
		/*
		 * Insert the logical provider or an independent hardware
		 * provider right before the first hardware provider on
		 * the slot list.
		 */
		for (i = provider_count - 1; i >= 0; i--) {
			n = g_sca_index[i];
			if (g_sca_provider_array[n]->sp_info->pi_provider_type
			    == CRYPTO_HW_PROVIDER) {
				/* Shift up the hardware provider */
				g_sca_index[i+1] = g_sca_index[i];
			} else {
				break;
			}
		}

		g_sca_index[i+1] = index;
	}
}

static void
sca_delete_provider_from_slot_list(int index, int provider_count)
{
	int i, j;

	for (i = 0; i < provider_count; i++) {
		if (g_sca_index[i] == index)
			break;
	}

	/* The last one will be reinitialized to 0 */
	for (j = i; j < provider_count; j++) {
		g_sca_index[j] = g_sca_index[j+1];
	}
}

EXPORT_SYMBOL(crypto_register_provider);
EXPORT_SYMBOL(crypto_unregister_provider);
EXPORT_SYMBOL(crypto_provider_notification);
EXPORT_SYMBOL(crypto_op_notification);
