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

#pragma ident	"@(#)mca_keystore.c	1.28	07/10/05 SMI"

/*
 * Mars - pure cryptographic acceleration + secure keystore
 */

#ifdef LINUX
#include <linux/types.h>
#include "sol2lin.h"
#include "mca.h"
#include "mca_table.h"
#include "mcactl.h"
#else
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>
#include <sys/byteorder.h>
#include <sys/mca.h>
#include <sys/mca_table.h>
#include <sys/mcactl.h>	/* needed for IOCTL values */
#endif

/*
 * Keystore implementation -- this is just the file management logic
 * coordinated with mcactl and mcad.
 */

static mca_table_t	mca_keystores;
static kmutex_t		mca_ksreglock;	/* lock protects above table */


/*
 * Local prototypes
 */
static void mca_ks_init_handles(mca_keystore_t *);
static void mca_ks_clear_handle(mca_keystore_t *, mca_t *);


/* these flags aren't legal for public keys */
#define	BADPUBLICFLAGS	(KEYFLAG_SENSITIVE | \
	KEYFLAG_NOWRAP | KEYFLAG_DECRYPT | KEYFLAG_SIGN | KEYFLAG_SIGNR | \
	KEYFLAG_UNWRAP | KEYFLAG_ALWAYSSENS | KEYFLAG_ALWAYSNOWRAP)

/* these flags aren't legal for private keys */
#define	BADPRIVATEFLAGS	(KEYFLAG_ENCRYPT | KEYFLAG_VERIFY | KEYFLAG_VERIFYR | \
	KEYFLAG_WRAP)

void
mca_keystore_init(void)
{
	mutex_init(&mca_ksreglock, NULL, MUTEX_DRIVER, NULL);
	mca_table_init(&mca_keystores, sizeof (mca_keystore_t), 1, 1, NULL);
}

void
mca_keystore_fini(void)
{
	mutex_destroy(&mca_ksreglock);
	mca_table_destroy(&mca_keystores);
}

static mca_keystore_t *
mca_keystore_lookup(char *name, uint64_t serial)
{
	int		index = -1;
	mca_keystore_t	*ks;

	while (mca_table_next_slot(&mca_keystores, &index) == DDI_SUCCESS) {
		if (mca_table_lookup(&mca_keystores, index, (void **)&ks) ==
		    DDI_FAILURE) {
			continue;
		}
		if ((strcmp(name, ks->mks_name) == 0) &&
		    (serial == ks->mks_serial)) {
			return (ks);
		}
	}
	return (NULL);
}

mca_keystore_t *
mca_keystore_lookup_by_session(crypto_session_id_t sess)
{
	mca_keystore_t	*ks = NULL;
	int	index = MCA_GET_KS_INDEX(sess);

	if (index < 0) {
		return (NULL);
	}

	mutex_enter(&mca_ksreglock);
	(void) mca_table_lookup(&mca_keystores, index, (void **)&ks);
	mutex_exit(&mca_ksreglock);

	return (ks);
}


mca_keystore_t *
mca_keystore_lookup_by_handle(mca_t *mca, dbm_handle_t handle)
{
	int		index = -1;
	mca_keystore_t	*ks;

	mutex_enter(&mca_ksreglock);
	while (mca_table_next_slot(&mca_keystores, &index) == DDI_SUCCESS) {
		if (mca_table_lookup(&mca_keystores, index, (void **)&ks) ==
		    DDI_FAILURE) {
			continue;
		}
		/* check if this mca device supports this keystore */
		if (MKS_CHECK_MCA(ks, mca) &&
		    (handle == mca_ks_get_handle(ks, mca))) {
			mutex_exit(&mca_ksreglock);
			return (ks);
		}
	}
	mutex_exit(&mca_ksreglock);
	DBG(mca, DWARN,
	    "mca_keystore_lookup_by_handle failed for handle 0x%x", handle);
	return (NULL);
}


/*
 * lookup keystore associated with a specific device instance.
 */
mca_keystore_t *
mca_keystore_lookup_mca(char *name, mca_t *mca)
{
	mca_keystore_t	*ks;

	mutex_enter(&mca_ksreglock);
	if ((ks = mca_keystore_lookup(name, mca->mca_keystore_serial))
	    != NULL) {
		if (MKS_CHECK_MCA(ks, mca) == FALSE) {
			mutex_exit(&mca_ksreglock);
			return (NULL);
		}
	}

	mutex_exit(&mca_ksreglock);
	return (ks);
}

int
mca_keystore_DR_safe(mca_t *mca)
{
	int			index = -1;
	mca_keystore_t		*ks;
	mca_sessiontable_t	*st;

	mutex_enter(&mca_ksreglock);
	while (mca_table_next_slot(&mca_keystores, &index) == DDI_SUCCESS) {
		if (mca_table_lookup(&mca_keystores, index, (void **)&ks) ==
		    DDI_FAILURE) {
			continue;
		}
		/* check if this device supports this KS */
		if (MKS_CHECK_MCA(ks, mca) == FALSE) {
			continue;
		}

		/* any other devices using this ks? */
		if (ks->mks_refcnt > 1) {
			continue;
		}

		st = MCA_PROVIDER2SESSTBL(&ks->mks_provinfo);

		if (mca_provider_DR_safe(st) == FALSE) {
			mutex_exit(&mca_ksreglock);
			return (FALSE);
		}

	}
	mutex_exit(&mca_ksreglock);
	return (TRUE);
}

void
mca_keystore_prepare_wait(mca_keystore_t *ks)
{
	mutex_enter(&ks->mks_ucmx);
}

void
mca_keystore_cancel_wait(mca_keystore_t *ks)
{
	mutex_exit(&ks->mks_ucmx);
}

int
mca_keystore_wait(mca_keystore_t *ks)
{
	int rv;

	ASSERT(mutex_owned(&ks->mks_ucmx));
	cv_wait(&ks->mks_uccv, &ks->mks_ucmx);
	rv = ks->mks_ucrv;
	mutex_exit(&ks->mks_ucmx);
	return (rv);
}

void
mca_keystore_done(int errno, void *arg)
{
	mca_keystore_t *ks = (mca_keystore_t *)arg;

	mutex_enter(&ks->mks_ucmx);
	ks->mks_ucrv = errno;
	cv_signal(&ks->mks_uccv);
	mutex_exit(&ks->mks_ucmx);
}

/*
 * Keystore access routines.
 */
void
mca_keystore_rdlock(mca_keystore_t *ks)
{
	DBG(NULL, DKEYSTORE, "mca_keystore_rdlock [%p]", ks);
	mutex_enter(&ks->mks_mx);
	while (ks->mks_wantw | ks->mks_wlock) {
		cv_wait(&ks->mks_cv, &ks->mks_mx);
	}
	ks->mks_readers++;
	mutex_exit(&ks->mks_mx);
}

void
mca_keystore_wrlock(mca_keystore_t *ks)
{
	DBG(NULL, DKEYSTORE, "mca_keystore_wrlock [%p]", ks);
	mutex_enter(&ks->mks_mx);
	while (ks->mks_readers | ks->mks_wlock) {
		ks->mks_wantw = 1;
		cv_wait(&ks->mks_cv, &ks->mks_mx);
	}
	ks->mks_wantw = 0;
	ks->mks_wlock = 1;
	mutex_exit(&ks->mks_mx);
}

void
mca_keystore_unlock(mca_keystore_t *ks)
{
	DBG(NULL, DKEYSTORE, "mca_keystore_unlock [%p]", ks);
	mutex_enter(&ks->mks_mx);
	if (ks->mks_wlock) {
		ks->mks_wlock = 0;
	} else {
		if (ks->mks_readers > 0) {
			ks->mks_readers--;
		} else {
			/*LINTED*/
			DBG(NULL, DWARN, "Invalid KS reader count [%d]",
			    ks->mks_readers);
		}
	}
	cv_broadcast(&ks->mks_cv);
	mutex_exit(&ks->mks_mx);
}

void
mca_keystore_lock_degrade(mca_keystore_t *ks)
{
	DBG(NULL, DKEYSTORE, "mca_keystore_lock_degrade [%p]", ks);
	mutex_enter(&ks->mks_mx);
	if (ks->mks_wlock) {
		/* if the user has the wrlock, switch it to the rdlock */
		ks->mks_wlock = 0;
		ks->mks_readers++;

		cv_broadcast(&ks->mks_cv);
	}
	/* if the user has readlock, do nothing */
	mutex_exit(&ks->mks_mx);
}

/*
 * Hold a keystore by name -- this is typically only called during provider
 * registration.  It acquires the writelock, so the lock must not be
 * held when it is called.
 */
mca_keystore_t *
mca_keystore_hold(mca_t *mca, dbm_provider_t *provider)
{
	mca_keystore_t	*ks;
	int		index;

	mutex_enter(&mca_ksreglock);
	if ((ks = mca_keystore_lookup(provider->name,
		mca->mca_keystore_serial)) != NULL) {

		mca_keystore_wrlock(ks);
		/* drop registry lock */
		mutex_exit(&mca_ksreglock);

		if (MKS_CHECK_MCA(ks, mca)) {

			DBG(mca, DWARN,
			    "Duplicate keystore registration for %s (%x:%x)",
			    ks->mks_name, ntohl(provider->handle),
			    mca_ks_get_handle(ks, mca));

			mca_keystore_unlock(ks);
			return (ks);
		} else {
			ks->mks_refcnt++;
		}
	} else {
		/* allocate a new entry */
		if (mca_table_alloc_slot(&mca_keystores, &index, (void **)&ks,
		    KM_SLEEP) != DDI_SUCCESS) {
			DBG(mca, DWARN,
			    "mca_keystore_hold: mca_table_alloc_slot failed");
			mutex_exit(&mca_ksreglock);
			return (NULL);
		}

		ks->mks_wantw = 0;
		ks->mks_wlock = 0;
		ks->mks_readers = 0;
		mutex_init(&ks->mks_mx, NULL, MUTEX_DRIVER, NULL);
		cv_init(&ks->mks_cv, NULL, CV_DRIVER, NULL);
		mutex_init(&ks->mks_ucmx, NULL, MUTEX_DRIVER, NULL);
		cv_init(&ks->mks_uccv, NULL, CV_DRIVER, NULL);

		ks->mks_refcnt = 1;
		mca_keystore_wrlock(ks);

		/* drop registry lock */
		mutex_exit(&mca_ksreglock);

		ks->mks_index = index;
		/* set name and serial number in request */
		strcpy(ks->mks_name, provider->name);
		ks->mks_serial = mca->mca_keystore_serial;
		ks->mks_type = ntohl(provider->type);

		mca_initq(&ks->mks_users);

		/* initialize ks handle info */
		mca_ks_init_handles(ks);

		/* don't register the device keystore */
		if (ks->mks_type != DBM_KS_DEVICE) {
			/* register the logical provider */
			(void) mca_logical_provider_register(ks, mca);
		}
	}

	mca_ks_set_handle(ks, ntohl(provider->handle), mca);
	MKS_SET_MCA(ks, mca);
	mca->mca_keystore_count++;

	mca_keystore_unlock(ks);
	return (ks);
}

/* caller must hold the keystore wrlock */
void
mca_keystore_delete_users(mca_keystore_t *ks)
{
	mca_key_t	*k;
	mca_user_t	*user;

	while ((user = (mca_user_t *)mca_dequeue(&ks->mks_users)) != NULL) {
		mca_user_wrlock(user);
		do {
			k = (mca_key_t *)mca_peekqueue(&user->mu_keys);
			if (k != NULL) {
				/* remove the key from the UKT */
				mca_unregister_key(k);
			}
		} while (k != NULL);
		mca_user_unlock(user);
		cv_destroy(&user->mu_cv);
		mutex_destroy(&user->mu_mx);
		kmem_free(user, sizeof (mca_user_t));
	}
}

/*
 * Complement to mca_keystore_hold(), with identical lock
 * requirements.
 */
void
mca_keystore_rele(mca_keystore_t *ks, mca_t *mca)
{
	int remove = 0;

	/* first remove it from the table */
	mutex_enter(&mca_ksreglock);
	ks->mks_refcnt--;
	DBG(mca, DKEYSTORE,
	    "mca_keystore_rele %s, refcnt %d",
	    ks->mks_name, ks->mks_refcnt);
	if (ks->mks_refcnt == 0) {
		mca_table_remove_slot(&mca_keystores, ks->mks_index);
		(void) mca_logical_provider_unregister(ks);
		remove = 1;
	}
	mutex_exit(&mca_ksreglock);

	if (remove) {
		/* nothing else should be referring to it from here on out */
		mca_keystore_delete_users(ks);

		cv_destroy(&ks->mks_cv);
		mutex_destroy(&ks->mks_mx);
		cv_destroy(&ks->mks_uccv);
		mutex_destroy(&ks->mks_ucmx);
		kmem_free(ks, sizeof (mca_keystore_t));
	} else {
		mca_ks_clear_handle(ks, mca);
		MKS_CLEAR_MCA(ks, mca);
	}
	mca->mca_keystore_count--;
}

/*
 * release all keystores associated with a device instance
 */
void
mca_keystore_rele_all(mca_t *mca)
{
	int		index = -1;
	mca_keystore_t	*ks;

	mutex_enter(&mca_ksreglock);
	while (mca_table_next_slot(&mca_keystores, &index) == DDI_SUCCESS) {
		if (mca_table_lookup(&mca_keystores, index, (void **)&ks) ==
		    DDI_FAILURE) {
			continue;
		}

		if (MKS_CHECK_MCA(ks, mca)) {
			mutex_exit(&mca_ksreglock);
			mca_keystore_rele(ks, mca);
			mutex_enter(&mca_ksreglock);
		}
	}
	mutex_exit(&mca_ksreglock);
}

char *
mca_keystore_name(mca_keystore_t *ks)
{
	return (ks->mks_name);
}

uint64_t
mca_keystore_serial(mca_keystore_t *ks)
{
	return (ks->mks_serial);
}

/*
 * Add 'key' to the UKT.
 * Caller must hold the user's wrlock.
 */
int
mca_register_key(mca_user_t *user, mca_key_t *key)
{
	mca_key_t	*s = NULL;

	DBG(NULL, DENTRY, "mca_register_key[key = %p] -->", key);

	while ((s = (mca_key_t *)mca_nextqueue(&user->mu_keys,
	    (mca_listnode_t *)s)) != NULL) {
		if ((s->mk_keyid[0] == key->mk_keyid[0]) &&
		    (s->mk_keyid[1] == key->mk_keyid[1])) {
			/* already registered! */
			return (DDI_FAILURE);
		}
	}

	key->mk_refcnt++;
	key->mk_user = user;
	mca_enqueue(&user->mu_keys, (mca_listnode_t *)key);

	user->mu_ks_seq++;

	DBG(NULL, DENTRY, "mca_register_key <--");

	return (DDI_SUCCESS);
}

void
mca_unregister_key(mca_key_t *key)
{
	mca_user_t	*user = key->mk_user;

	DBG(NULL, DENTRY, "mca_unregister_key[key = %p] -->", key);

	if (user) {
		/*
		 * Since this is token key deletion, the caller must
		 * have the ks wrlock.
		 */
		mca_rmqueue((mca_listnode_t *)key);
		key->mk_user = NULL;
		/* make the key invalid, and decrement the refcnt */
		mca_invalidate_key(key);
		user->mu_ks_seq++;
	}


	DBG(NULL, DENTRY, "mca_unregister_key <--");
}

/*
 * This function looks up a key in the UKT. If there is a matching key,
 * the refcnt of the key is incremented and return the reference. If there
 * is no matching key, return NULL.
 * The caller must have the user's wrlock.
 */
mca_key_t *
mca_find_key(mca_user_t *user, uint32_t *id)
{
	mca_key_t *key = NULL;

	DBG(NULL, DENTRY, "mca_find_key -->");

	while ((key = (mca_key_t *)mca_nextqueue(&user->mu_keys,
	    (mca_listnode_t *)key)) != NULL) {
		if ((key->mk_keyid[0] == id[0]) &&
		    (key->mk_keyid[1] == id[1])) {
			mutex_enter(&key->mk_lock);
			if (!(key->mk_keyflags & KEYFLAG_VALID)) {
				/*
				 * another thread is in the process of
				 * deleting this 'key'.
				 */
				mutex_exit(&key->mk_lock);
				continue;
			}
			key->mk_refcnt++;	/* used for this session */
			mutex_exit(&key->mk_lock);
			break;
		}
	}

	DBG(NULL, DENTRY, "mca_find_key <--[key = %p]", key);

	return (key);
}

static int
get_modulus(int keytype, cpg_attr_t *attr, caddr_t buf, uint32_t *buflen,
    uint32_t *keylen)
{
	prirsa_head_t	*prvhead;
	pubrsa_head_t	*pubhead;
	uint32_t	mlen, elen = 0;
	uint32_t	mbits;
	uint8_t		*m, *e = NULL;
	size_t		sz;
	int		rv;

	if (cpg_attr_lookup_uint8_array(attr, CPGA_MODULUS, &m, &mlen)) {
		DBG(NULL, DWARN, "get_modulus: RSA modulus missing");
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}
	mca_stripzeros((caddr_t *)&m, &mlen);
	mbits = mca_bitlen((caddr_t)m, mlen);
	if (keylen) {
		*keylen = mlen;
	}

	rv = cpg_attr_lookup_uint8_array(attr, CPGA_PUBLIC_EXPONENT,
	    &e, &elen);
	if (keytype == KEYTYPE_RSA_PUBLIC) {
		if (rv != CRYPTO_SUCCESS) {
			DBG(NULL, DWARN, "get_modulus: RSA pub expo missing");
			return (CRYPTO_TEMPLATE_INCOMPLETE);
		}
		sz = PAD32(sizeof (pubrsa_head_t)) + PAD32(mlen) + PAD32(elen);
	} else {
		sz = PAD32(sizeof (prirsa_head_t)) + PAD32(mlen) + PAD32(elen);
	}
	if (sz > *buflen) {
		*buflen = sz;
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = sz;

	/* write out the attr */
	if (keytype == KEYTYPE_RSA_PUBLIC) {
		pubhead = (pubrsa_head_t *)buf;
		buf += PAD32(sizeof (pubrsa_head_t));
		/* write out the value, mbits, modulus */
		PUTBUF32(&pubhead->modbits, mbits);
		PUTBUF32(&pubhead->modlen, mlen);
		PUTBUF32(&pubhead->pubexplen, elen);
	} else {
		prvhead = (prirsa_head_t *)buf;
		buf += PAD32(sizeof (prirsa_head_t));
		/*
		 * write out the value, mbits, modulus, exponents,
		 * primes, etc.
		 */
		PUTBUF32(&prvhead->modbits, mbits);
		PUTBUF32(&prvhead->modlen, mlen);
		PUTBUF32(&prvhead->pubexplen, elen);
		PUTBUF32(&prvhead->privexplen, 0);
		PUTBUF32(&prvhead->plen, 0);
		PUTBUF32(&prvhead->qlen, 0);
		PUTBUF32(&prvhead->dplen, 0);
		PUTBUF32(&prvhead->dqlen, 0);
		PUTBUF32(&prvhead->qinvlen, 0);
	}

	/* add modulus */
	bcopy(m, buf, mlen);
	buf += PAD32(mlen);
	if (elen != 0) {
		bcopy(e, buf, elen);
	}

	return (CRYPTO_SUCCESS);
}


static int
get_prime(cpg_attr_t *attr, caddr_t buf, uint32_t *buflen, uint32_t *keylen)
{
	uint8_t		*p;
	unsigned	plen;
	size_t		sz;
	dsa_head_t	*dsahead = (dsa_head_t *)buf;


	if (cpg_attr_lookup_uint8_array(attr, CPGA_PRIME, &p, &plen)) {
		/* these fields are required */
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}
	if (keylen) {
		*keylen = plen;
	}

	sz = sizeof (dsa_head_t) + PAD32(20) + PAD32(plen);
	if (sz > *buflen) {
		*buflen = sz;
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = sz;

	mca_stripzeros((caddr_t *)&p, &plen);

	/* write out p, q, g, and the value. */
	PUTBUF32(&dsahead->plen, plen);
	PUTBUF32(&dsahead->glen, 0);
	PUTBUF32(&dsahead->vlen, 0);
	buf += PAD32(sizeof (dsa_head_t));

	/* subprime comes first: skip 20 bytes */
	buf += PAD32(20);	/* subprime */

	bcopy(p, buf, plen);
	buf += PAD32(plen);

	return (CRYPTO_SUCCESS);
}

static int
get_aeshead(caddr_t buf, uint32_t *buflen)
{
	size_t			sz;
	mca_aes_keyhead_t	*keyhead;

	sz = sizeof (mca_aes_keyhead_t);
	if (sz > *buflen) {
		*buflen = sz;
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}

	*buflen = sz;
	keyhead = (mca_aes_keyhead_t *)buf;
	PUTBUF32(&keyhead->keysz, 0);

	return (CRYPTO_SUCCESS);
}


/*
 * This function parse the mca_key_head, and allocate and create a mca_key.
 *
 * Format of the keyhead:
 *      mca_key_head_t  keyhead;
 *      uint32_t        attr[];
 *      uint32_t        value[];
 *      uint32_t        envelope[];
 *
 * Note that the value parts are proceessed by key-type-specific subroutines
 */
int
mca_parse_key(cpg_attr_t *attr, mca_key_head_t *keyhead, int keyheadlen,
    uint16_t keyflags, mca_key_t **mkey)
{
	uint32_t	keylen = 0;
	uint32_t	keytype;
	uint32_t	attrlen;
	uint32_t	vallen;
	uint32_t	envlen;
	uint32_t	totallen;
	uint8_t		priv = FALSE;
	uint8_t		extr = TRUE;
	uint8_t		sens = FALSE;
	caddr_t		val = NULL;
	caddr_t		env = NULL;
	caddr_t		buf;
	int		rv;

	if (sizeof (mca_key_head_t) > keyheadlen) {
		DBG(NULL, DWARN, "key head truncated");
		return (CRYPTO_DEVICE_ERROR);
	}

	keytype = GETBUF32(&keyhead->keytype);
	attrlen = GETBUF32(&keyhead->descrlen);
	envlen = GETBUF32(&keyhead->envelopelen);
	vallen = GETBUF32(&keyhead->valuelen);
	DBG(NULL, DKEYSTORE, "parsing key type %d", keytype);

	totallen = PAD32(sizeof (mca_key_head_t));
	if (envlen != 0) {
		totallen += PAD32(attrlen) + PAD32(vallen) + envlen;
	} else if (vallen != 0) {
		totallen += PAD32(attrlen) + vallen;
	} else {
		totallen += attrlen;
	}
	if (keyheadlen < totallen) {
		DBG(NULL, DWARN, "keys truncated: attrlen = %d, vallen = %d, "
		    "envlen = %d", attrlen, vallen, envlen);
		return (CRYPTO_DEVICE_ERROR);
	}

	if (vallen != 0) {
		val = KEYHEAD_VALUE(keyhead);
		switch (keytype) {
		case KEYTYPE_RSA_PRIVATE:
		case KEYTYPE_RSA_PUBLIC:
			keylen = GETBUF32(&((pubrsa_head_t *)val)->modlen);
			break;
		case KEYTYPE_DSA_PRIVATE:
		case KEYTYPE_DSA_PUBLIC:
			keylen = GETBUF32(&((dsa_head_t *)val)->plen);
			break;
		default:
			/* key length not needed for symmetric key */
			keylen = 0;
		}
	} else {
		switch (keytype) {
		case KEYTYPE_RSA_PRIVATE:
		case KEYTYPE_RSA_PUBLIC:
			rv = get_modulus(keytype, attr, NULL, &vallen, &keylen);
			break;
		case KEYTYPE_DSA_PRIVATE:
		case KEYTYPE_DSA_PUBLIC:
			rv = get_prime(attr, NULL, &vallen, &keylen);
			break;
		case KEYTYPE_AES:
			rv = get_aeshead(NULL, &vallen);
			/* keylen not need for symmetric key */
			keylen = 0;
			break;
		default:
			/* keylen not need for symmetric key */
			rv = CRYPTO_SUCCESS;
			keylen = 0;
		}
		if (rv != CRYPTO_SUCCESS) {
			return (rv);
		}
	}
	if (envlen != 0) {
		env = KEYHEAD_ENVELOPE(keyhead);
	}

	keyheadlen = (PAD32(sizeof (mca_key_head_t)) + PAD32(vallen) +
	    PAD32(envlen));
	if (keyheadlen > MAX_KEY_SIZE) {
		/*
		 * 3KB is allocated for keyhead. Apparently that is not
		 * large enough.
		 */
		mca_error(NULL, "keyheadlen[%d] is greater than "
		    "MAX_KEY_SIZE[%d]", keyheadlen, MAX_KEY_SIZE);
		return (CRYPTO_GENERAL_ERROR);
	}

	/*
	 * allocate enough memory for mca_key_t + mca_key_head_t and
	 * its associated components
	 */
	totallen = PAD32(sizeof (mca_key_t)) + keyheadlen;
	*mkey = (mca_key_t *)kmem_alloc(totallen, KM_NOSLEEP);
	if (*mkey == NULL) {
		return (CRYPTO_HOST_MEMORY);
	}

	/*
	 * Set private flag if applicable.  This should already be set
	 * in the cpg_attr, but just in case it is not, we provide the
	 * proper default, which depends on whether the object is
	 * persistant.  If it is inconsistent (i.e. declaring that
	 * object is a public token object) we force it to be private.
	 */
	priv = !!(keyflags & KEYFLAG_PERSIST);
	rv = cpg_attr_lookup_uint8(attr, CPGA_PRIVATE, &priv);
	switch (rv) {
	case CRYPTO_SUCCESS:
		if (keyflags & KEYFLAG_PERSIST && /* token */
		    !priv) {
			/* Inconsistent: force private true and fallthrough */
			priv = TRUE;
		} else {
			/* Consistent, break out of switch */
			break;
		}
		/*FALLTHROUGH*/
	case CRYPTO_TEMPLATE_INCONSISTENT:
	case CRYPTO_ATTRIBUTE_TYPE_INVALID:
		/* Set explicit CPGA_PRIVATE attribute */
		rv = cpg_attr_add_uint8(attr, CPGA_PRIVATE, priv, 0);
		if (rv) {
			kmem_free(*mkey, totallen);
			*mkey = NULL;
			return (rv);
		}
		break;
	default:
		kmem_free(*mkey, totallen);
		*mkey = NULL;
		return (rv);
	}


	/*
	 * Set the sensitive flag if not supplied.  If inconsistent
	 * with extractable, force sensitive true.
	 */
	(void) cpg_attr_lookup_uint8(attr, CPGA_EXTRACTABLE, &extr);
	sens = !extr;
	rv = cpg_attr_lookup_uint8(attr, CPGA_SENSITIVE, &sens);
	switch (rv) {
	case CRYPTO_SUCCESS:
		if (!sens && !extr) {
			/* Inconsistent: force sensitive true, fallthrough */
			sens = TRUE;
		} else {
			/* Consistent, break out of switch */
			break;
		}
		/*FALLTHROUGH*/
	case CRYPTO_TEMPLATE_INCONSISTENT:
	case CRYPTO_ATTRIBUTE_TYPE_INVALID:
		/* Set explicit CPGA_SENSITIVE attribute */
		rv = cpg_attr_add_uint8(attr, CPGA_SENSITIVE, sens,
		    0);
		if (rv) {
			kmem_free(*mkey, totallen);
			*mkey = NULL;
			return (rv);
		}
		break;
	default:
		kmem_free(*mkey, totallen);
		*mkey = NULL;
		return (rv);
	}

	/*
	 * Setup the mca_key_t
	 */
	(*mkey)->mk_keyflags = keyflags | (priv ? KEYFLAG_PRIVATE : 0) |
	    (sens ? KEYFLAG_SENSITIVE : 0);
	(*mkey)->mk_cpgattr = attr;
	(*mkey)->mk_allocsz = totallen;
	(*mkey)->mk_keyheadsz = keyheadlen;
	(*mkey)->mk_refcnt = 1;	/* this refcnt is used for SKT eventually */
	(*mkey)->mk_keyid[0] = GETBUF32(&keyhead->cardid);
	(*mkey)->mk_keyid[1] = GETBUF32(&keyhead->objectid);

	/*
	 * Copy the mca_key_head_t
	 */
	buf = (caddr_t)(*mkey) + PAD32(sizeof (mca_key_t));
	bcopy(keyhead, buf, sizeof (mca_key_head_t));

	/*
	 * No Description needed for crypto operations
	 */
	PUTBUF32(&(((mca_key_head_t *)buf)->descrlen), 0);

	/*
	 * Copy the value
	 */
	PUTBUF32(&(((mca_key_head_t *)buf)->valuelen), vallen);
	buf += PAD32(sizeof (mca_key_head_t));
	if (val == NULL) {
		switch (keytype) {
		case KEYTYPE_RSA_PRIVATE:
		case KEYTYPE_RSA_PUBLIC:
			rv = get_modulus(keytype, attr, buf, &vallen, NULL);
			break;
		case KEYTYPE_DSA_PRIVATE:
		case KEYTYPE_DSA_PUBLIC:
			rv = get_prime(attr, buf, &vallen, NULL);
			break;
		case KEYTYPE_AES:
			rv = get_aeshead(buf, &vallen);
			break;
		}
		if (rv != CRYPTO_SUCCESS) {
			kmem_free(*mkey, totallen);
			*mkey = NULL;
			return (rv);
		}
	} else {
		bcopy(val, buf, vallen);
	}

	/*
	 * Copy the envelope
	 */
	buf += PAD32(vallen);
	if (env) {
		bcopy(env, buf, envlen);
	}

	/*
	 * It is really important that CPGA_TOKEN match what the
	 * keystore/firmware used.  So we force CPGA_TOKEN to the same
	 * as the bit in keyflags.  (It's just as fast to set as to
	 * lookup.)
	 */
	if (cpg_attr_add_uint8(attr, CPGA_TOKEN,
		!!(keyflags & KEYFLAG_PERSIST), 0)) {
		kmem_free(*mkey, totallen);
		*mkey = NULL;
		return (CRYPTO_HOST_MEMORY);
	}

	/* if the key is sensitive, remove sensitive values */
	if (sens) {
		(void) mca_delete_sensitive_key_value(attr);
	}

	/*
	 * If the key is non-sensitive, add key value to the cpg_attr.
	 * If it is RSA private key, add Modulus and PubExpo to the cpg_attr.
	 */
	if ((rv = mca_add_key_value(keyhead, attr)) != CRYPTO_SUCCESS) {
		DBG(NULL, DWARN, "mca_parse_key: mca_add_key_value "
		    "failed with 0x%x", rv);
		kmem_free(*mkey, totallen);
		*mkey = NULL;
		return (rv);
	}

	mutex_init(&((*mkey)->mk_lock), NULL, MUTEX_DRIVER, NULL);


	return (CRYPTO_SUCCESS);
}

/*
 * fill in information about logical providers/keystores
 * associated with a specific mca instance.  Needed to
 * register with the crypto framework.
 */
crypto_kcf_provider_handle_t *
mca_keystore_create_lp_array(mca_t *mca)
{

	int		i = 0;
	int		index = -1;
	mca_keystore_t	*ks;

	crypto_kcf_provider_handle_t *providers;

	if (mca->mca_keystore_count <= 0) {
		return (NULL);
	}

#ifdef LINUX
	providers = kmem_zalloc(sizeof (crypto_kcf_provider_handle_t) *
			mca->mca_keystore_count, GFP_ATOMIC);
#else
	providers = kmem_zalloc(sizeof (crypto_kcf_provider_handle_t) *
			mca->mca_keystore_count, KM_SLEEP);
#endif
	if (providers == NULL) {
		return (NULL);
	}

	mutex_enter(&mca_ksreglock);
	while (mca_table_next_slot(&mca_keystores, &index) == DDI_SUCCESS) {
		if (mca_table_lookup(&mca_keystores, index, (void **)&ks) ==
		    DDI_FAILURE) {
			continue;
		}

		/*
		 * build the logical provider list - make sure
		 * keystore belongs to this card and is not the
		 * device keystore.
		 */
		if (MKS_CHECK_MCA(ks, mca) &&
		    (ks->mks_type != DBM_KS_DEVICE)) {
			providers[i] = ks->mks_provinfo.mp_provhandle;
			i++;
			if (i == mca->mca_keystore_count) {
				break;
			}
		}
	}
	mutex_exit(&mca_ksreglock);

	return (providers);
}


void
mca_keystore_destroy_lp_array(crypto_kcf_provider_handle_t *data, int count)
{
	if (count && data) {
		kmem_free((void *)data, sizeof (*data) * count);
	}
}

dbm_handle_t
mca_ks_get_handle(mca_keystore_t *ks, mca_t *mca)
{
	int	i;

	for (i = 0; i < MAX_KS_HANDLES; i++) {
		if (ks->mks_handle[i].mh_mca == mca) {
		DBG(mca, DKEYSTORE, "got handle 0x%x for ks %s",
			ks->mks_handle[i].mh_handle, ks->mks_name);
			return (ks->mks_handle[i].mh_handle);
		}
	}

	DBG(mca, DCHATTY, "unable to find keystore handle for ks %s",
	    ks->mks_name);
	return (MCA_KS_BAD_HANDLE);
}


void
mca_ks_set_handle(mca_keystore_t *ks, dbm_handle_t handle, mca_t *mca)
{
	int	i;

	for (i = 0; i < MAX_KS_HANDLES; i++) {
		if (ks->mks_handle[i].mh_handle == MCA_KS_BAD_HANDLE) {
			ks->mks_handle[i].mh_handle = handle;
			ks->mks_handle[i].mh_mca = mca;
			return;
		} else if (ks->mks_handle[i].mh_mca == mca) {
			ks->mks_handle[i].mh_handle = handle;
			return;
		}
	}
	DBG(mca, DWARN, "Unable to set keystore handle");
}

static void
mca_ks_init_handles(mca_keystore_t *ks)
{
	int i;

	for (i = 0; i < MAX_KS_HANDLES; i++) {
		ks->mks_handle[i].mh_mca = NULL;
		ks->mks_handle[i].mh_handle = MCA_KS_BAD_HANDLE;
	}
}

static void
mca_ks_clear_handle(mca_keystore_t *ks, mca_t *mca)
{
	int i;

	for (i = 0; i < MAX_KS_HANDLES; i++) {
		if (ks->mks_handle[i].mh_mca == mca) {
			ks->mks_handle[i].mh_mca = NULL;
			ks->mks_handle[i].mh_handle = MCA_KS_BAD_HANDLE;
			return;
		}
	}
	DBG(mca, DWARN, "mca_ks_clear_handle failed for ks %s",
	    ks->mks_name);
}
