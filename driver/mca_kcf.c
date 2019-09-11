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

#pragma ident	"@(#)mca_kcf.c	1.78	08/10/13 SMI"


/*
 * Mars - pure cryptographic acceleration + secure keystore
 *
 * File       : mca_kcf.c
 * Description: This file contains structures and layer necessary for
 *		kCF kernel Service Provider Interface (kSPI)
 */


#ifdef LINUX
#include <linux/types.h>
#include "sol2lin.h"
#include "common.h"
#include "mca.h"
#include "mca_hw.h"
#include "mca_csrs.h"
#else
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stream.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
#include <sys/kmem.h>
#include <sys/random.h>
#include <sys/crypto/common.h>
#include <sys/crypto/ioctl.h>
#include <sys/mca.h>
#include <sys/mca_hw.h>
#include <sys/mca_attr_infobase.h>
#include <sys/mca_csrs.h>
#include <sys/mca_fs.h>
#endif

#define	SPI_V2

/*
 * If DO_CHECK is defined, cryptoattr2cpgattr checks that all required
 * attributes are supplied and only legal attributes are supplied.
 * Comment out the following line to eliminate this check.  (Runs
 * faster.)
 */
#define	DO_CHECK


#define	NO_FLUFF		0
#define	MINI_FLUFF		1
#define	FULL_FLUFF		2
#define	MCA_SESSION_CHUNK	10
#define	MCA_KEY_CHUNK		10
#define	INITIAL_KEYNUM		32
#define	AES_MECHS_NUM		3


#define	MAX_NUMMECH		(NUMMECH(mca_cb_mech_info_tab) + \
				NUMMECH(mca_ca_mech_info_tab) + \
				NUMMECH(mca_om_mech_info_tab))
#define	NUMMECH(mechs)		(sizeof (mechs) / sizeof (crypto_mech_info_t))
#define	ROUNDUP8(m)		ROUNDUP(m, 8)
#define	MAX_CPG_ATTR_SIZE	1048576 /* 1 MB limit on cgp_attr size */
/* 2048 should be large enough to store the key_head for most keys */
#define	INITIAL_HEAD_SIZE	2048

#define	FATAL_RV(rv) \
	(((rv) != CRYPTO_QUEUED) && \
	((rv) != CRYPTO_SUCCESS) && \
	((rv) != CRYPTO_BUFFER_TOO_SMALL) && \
	((rv) != CRYPTO_BUSY))
#define	RETRY_RV(rv) \
	(((rv) == CRYPTO_QUEUED) || \
	((rv) == CRYPTO_BUFFER_TOO_SMALL) || \
	((rv) == CRYPTO_BUSY))

static void mca_provider_status(crypto_provider_handle_t, uint_t *);
static int mca_digest_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_req_handle_t);
static int mca_digest_update(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int mca_digest_key(crypto_ctx_t *, crypto_key_t *, crypto_req_handle_t);
static int mca_digest_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int mca_digest(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int mca_digest_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int mca_encrypt_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int mca_encrypt(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int mca_encrypt_update(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t);
static int mca_encrypt_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int mca_encrypt_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int mca_decrypt_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int mca_decrypt(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int mca_decrypt_update(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t);
static int mca_decrypt_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int mca_decrypt_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int mca_sign_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int mca_sign_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int mca_sign(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int mca_signrecover_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int mca_signrecover_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int mca_signrecover(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int mca_verify_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int mca_verify_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int mca_verify(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int mca_verifyrecover_atomic(crypto_provider_handle_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int mca_verifyrecover_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int mca_verifyrecover(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);


/* CB Sign */
static int mca_cb_sign_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int mca_cb_sign_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int mca_cb_sign(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int mca_cb_sign_update(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int mca_cb_sign_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int mca_cb_verify_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int mca_cb_verify_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int mca_cb_verify(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int mca_cb_verify_update(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int mca_cb_verify_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);


static int mca_random_number(crypto_provider_handle_t,
    crypto_session_id_t, uchar_t *, size_t, crypto_req_handle_t);
static crypto_data_t *alloccryptodata(uchar_t *, size_t);
static int rawkey2keyhead(int, caddr_t, uint32_t, caddr_t, uint32_t *);
static int cryptoattr_lookup_uint8(crypto_object_attribute_t *,
    uint_t, int, uint8_t *);
static int cryptoattr_lookup_uint32(crypto_object_attribute_t *,
    uint_t, int, uint32_t *);
static int cryptoattr_lookup_uint64(crypto_object_attribute_t *,
    uint_t, int, uint64_t *);
static int cryptoattr_lookup_uint8_array(crypto_object_attribute_t *,
    uint_t, int, uint8_t **, uint32_t *);
static int mca_freectx_kcf(crypto_ctx_t *ctx);
/* Session Ops */
static mca_session_t *session_hold(mca_sessiontable_t *, int);
static void session_free(mca_session_t *);
static mca_key_t *session_get_key(mca_session_t *, crypto_object_id_t);
static void session_table_init(mca_sessiontable_t *);
static void session_table_fini(mca_sessiontable_t *);
static mca_sessiontable_t *session_table_get(mca_t *, crypto_session_id_t);
static int mca_session_open(crypto_provider_handle_t, crypto_session_id_t *,
    crypto_req_handle_t);
static int mca_session_close(crypto_provider_handle_t, crypto_session_id_t,
    crypto_req_handle_t);
static int session_login(crypto_provider_handle_t, crypto_session_id_t,
    crypto_user_type_t, char *, size_t, crypto_req_handle_t);
static int session_logout(crypto_provider_handle_t, crypto_session_id_t,
    crypto_req_handle_t);
static int ext_info(crypto_provider_handle_t, crypto_provider_ext_info_t *,
    crypto_req_handle_t);
static int set_pin(crypto_provider_handle_t, crypto_session_id_t,
    char *, size_t, char *, size_t, crypto_req_handle_t);
/* Object Ops */
static void key_table_fini(mca_table_t *);
static void key_destructor(void *);
static int write_key_internal(mca_session_t *, crypto_key_t *,
    int, caddr_t, uint32_t *, uint32_t *);
static int object_create_internal(crypto_provider_handle_t,
    crypto_session_id_t, cpg_attr_t *template, crypto_object_id_t *,
    crypto_req_handle_t);
static int mca_object_create(crypto_provider_handle_t, crypto_session_id_t,
    crypto_object_attribute_t *, uint_t, crypto_object_id_t *,
    crypto_req_handle_t);
static int mca_object_destroy(crypto_provider_handle_t, crypto_session_id_t,
    crypto_object_id_t, crypto_req_handle_t);
static int object_copy(crypto_provider_handle_t, crypto_session_id_t,
    crypto_object_id_t, crypto_object_attribute_t *, uint_t,
    crypto_object_id_t *, crypto_req_handle_t);
static int mca_object_get_attribute_value(crypto_provider_handle_t,
    crypto_session_id_t, crypto_object_id_t, crypto_object_attribute_t *,
    uint_t, crypto_req_handle_t);
static int object_set_attribute_value(crypto_provider_handle_t,
    crypto_session_id_t, crypto_object_id_t, crypto_object_attribute_t *,
    uint_t, crypto_req_handle_t);
static int mca_object_find_init(crypto_provider_handle_t, crypto_session_id_t,
    crypto_object_attribute_t *, uint_t, void **,
    crypto_req_handle_t);
static int mca_object_find(crypto_provider_handle_t, void *,
    crypto_object_id_t *, uint_t, uint_t *, crypto_req_handle_t);
static int mca_object_find_final(crypto_provider_handle_t, void *,
    crypto_req_handle_t);
/* Key Ops */
static int mca_key_gen(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_object_attribute_t *, uint_t,
    crypto_object_id_t *, crypto_req_handle_t);
static int mca_key_pair_gen(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_object_attribute_t *, uint_t,
    crypto_object_attribute_t *, uint_t, crypto_object_id_t *,
    crypto_object_id_t *, crypto_req_handle_t);
static int mca_key_wrap(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_object_id_t *,
    uchar_t *, size_t *, crypto_req_handle_t);
static int mca_key_unwrap(crypto_provider_handle_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *,
    uchar_t *, size_t *, crypto_object_attribute_t *, uint_t,
    crypto_object_id_t *, crypto_req_handle_t);
static int mca_allocate_mechanism(crypto_provider_handle_t,
    crypto_mechanism_t *, crypto_mechanism_t *, int *error, int);
static int mca_free_mechanism(crypto_provider_handle_t,
    crypto_mechanism_t *);
static int mca_key_derive(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_object_attribute_t *,
    uint_t, crypto_object_id_t *, crypto_req_handle_t);


static crypto_control_ops_t mca_control_ops = {
	mca_provider_status
};

static crypto_digest_ops_t mca_digest_ops = {
	mca_digest_init,
	mca_digest,
	mca_digest_update,
	mca_digest_key,
	mca_digest_final,
	mca_digest_atomic
};

static crypto_cipher_ops_t mca_cipher_ops = {
	mca_encrypt_init,
	mca_encrypt,
	mca_encrypt_update,
	mca_encrypt_final,
	mca_encrypt_atomic,
	mca_decrypt_init,
	mca_decrypt,
	mca_decrypt_update,
	mca_decrypt_final,
	mca_decrypt_atomic
};


#ifdef FINSVCS
/* financial services ops */
static crypto_cipher_ops_t mca_fs_ops = {
	mca_encrypt_init,
	mca_encrypt,
	mca_encrypt_update,
	mca_encrypt_final,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};
#endif


static crypto_sign_ops_t mca_sign_ops = {
	mca_sign_init,
	mca_sign,
	NULL,			/* mca_sign_update */
	NULL,			/* mca_sign_final */
	mca_sign_atomic,
	mca_signrecover_init,
	mca_signrecover,
	mca_signrecover_atomic
};

static crypto_verify_ops_t mca_verify_ops = {
	mca_verify_init,
	mca_verify,
	NULL,			/* mca_verify_update */
	NULL,			/* mca_verify_final */
	mca_verify_atomic,
	mca_verifyrecover_init,
	mca_verifyrecover,
	mca_verifyrecover_atomic
};

/*
 * CB Sign (for HMAC)
 */
static crypto_sign_ops_t mca_cb_sign_ops = {
	mca_cb_sign_init,
	mca_cb_sign,
	mca_cb_sign_update,
	mca_cb_sign_final,
	mca_cb_sign_atomic,
	NULL,
	NULL,
	NULL
};

static crypto_verify_ops_t mca_cb_verify_ops = {
	mca_cb_verify_init,
	mca_cb_verify,
	mca_cb_verify_update,
	mca_cb_verify_final,
	mca_cb_verify_atomic,
	NULL,
	NULL,
	NULL
};

static crypto_mac_ops_t mca_mac_ops = {
	mca_cb_sign_init,
	mca_cb_sign,
	mca_cb_sign_update,
	mca_cb_sign_final,
	mca_cb_sign_atomic,
	mca_cb_verify_atomic
};

static crypto_random_number_ops_t mca_rng_ops = {
	NULL,		/* seed_random */
	mca_random_number
};

static crypto_session_ops_t mca_session_ops = {
	mca_session_open,
	mca_session_close,
	session_login,
	session_logout,
};

static crypto_provider_management_ops_t mca_extinfo_op = {
	ext_info,	/* ext_info */
	NULL,		/* init_token */
	NULL, 		/* init_pin */
	NULL,		/* set_pin */
};

static crypto_provider_management_ops_t mca_provmanage_ops = {
	ext_info,	/* ext_info */
	NULL,		/* init_token */
	NULL, 		/* init_pin */
	set_pin
};

static crypto_object_ops_t mca_object_ops = {
	mca_object_create,
	object_copy,
	mca_object_destroy,
	NULL,			/* object_get_size */
	mca_object_get_attribute_value,
	object_set_attribute_value,
	mca_object_find_init,
	mca_object_find,
	mca_object_find_final
};

static crypto_key_ops_t mca_key_ops = {
	mca_key_gen,		/* key_generate */
	mca_key_pair_gen,	/* key_generate_pair */
	mca_key_wrap,		/* key_wrap */
	mca_key_unwrap,		/* key_unwrap */
	NULL,			/* key_derive */
	NULL,			/* key_check */
};

static crypto_key_ops_t mca_dh_ops = {
	NULL,			/* key_generate */
	mca_key_pair_gen,	/* key_generate_pair */
	NULL,			/* key_wrap */
	NULL,			/* key_unwrap */
	mca_key_derive,		/* key_derive */
	NULL,			/* key_check */
};

static crypto_ctx_ops_t	mca_ctx_ops = {
	NULL,		/* create_ctx_template */
	mca_freectx_kcf,
};

static crypto_mech_ops_t mca_mech_ops = {
	mca_allocate_mechanism,	/* copyin_mechanism */
	NULL,			/* copyout_mechanism */
	mca_free_mechanism	/* free_mechanism */
};

static crypto_ops_t mca_sym_ops = {
	&mca_control_ops,
	&mca_digest_ops,		/* digest_ops */
	&mca_cipher_ops,		/* cipher_ops */
	&mca_mac_ops,			/* mac_ops */
	&mca_cb_sign_ops,		/* sign_ops */
	&mca_cb_verify_ops,		/* verify_ops */
	NULL,				/* dual_ops */
	NULL,				/* mac_ops */
	NULL,				/* rng_ops */
	NULL,				/* session_ops */
	NULL,				/* object_ops */
	NULL,				/* key_ops */
	&mca_extinfo_op,		/* management_ops */
	&mca_ctx_ops,			/* ctx_ops */
	&mca_mech_ops,			/* mech_ops */
};

static crypto_ops_t mca_asym_ops = {
	&mca_control_ops,
	NULL,				/* digest_ops */
	&mca_cipher_ops,		/* cipher_ops */
	NULL,				/* mac_ops */
	&mca_sign_ops,			/* sign_ops */
	&mca_verify_ops,		/* verify_ops */
	NULL,				/* dual_ops */
	NULL,				/* cipher_mac_ops */
	&mca_rng_ops,			/* rng_ops */
	NULL,				/* session_ops */
	&mca_object_ops,		/* object_ops */
	&mca_dh_ops,			/* key_ops */
	&mca_extinfo_op,		/* management_ops */
	&mca_ctx_ops,			/* ctx_ops */
	&mca_mech_ops,			/* mech_ops */
};

static crypto_ops_t mca_om_ops = {
	&mca_control_ops,
	NULL,				/* digest_ops */
#ifdef FINSVCS
	&mca_fs_ops,			/* cipher_ops */
#else
	NULL,				/* cipher_ops */
#endif
	NULL,				/* mac_ops */
	NULL,				/* sign_ops */
	NULL,				/* verify_ops */
	NULL,				/* dual_ops */
	NULL,				/* cipher_mac_ops */
	NULL,				/* rng_ops */
	&mca_session_ops,		/* session_ops */
	&mca_object_ops,		/* object_ops */
	&mca_key_ops,			/* key_ops */
	&mca_provmanage_ops,		/* management_ops */
	&mca_ctx_ops,			/* ctx_ops */
	&mca_mech_ops,			/* mech_ops */
};

#define	MCASTR_CKM_SHA_1			"CKM_SHA_1"
#define	MCASTR_CKM_SHA_1_HMAC			"CKM_SHA_1_HMAC"
#define	MCASTR_CKM_SHA_1_HMAC_GENERAL		"CKM_SHA_1_HMAC_GENERAL"
#define	MCASTR_CKM_SHA512			"CKM_SHA512"
#define	MCASTR_CKM_SHA512_HMAC			"CKM_SHA512_HMAC"
#define	MCASTR_CKM_SHA512_HMAC_GENERAL		"CKM_SHA512_HMAC_GENERAL"
#define	MCASTR_CKM_MD5				"CKM_MD5"
#define	MCASTR_CKM_MD5_HMAC			"CKM_MD5_HMAC"
#define	MCASTR_CKM_MD5_HMAC_GENERAL		"CKM_MD5_HMAC_GENERAL"
#define	MCASTR_CKM_RSA_PKCS			"CKM_RSA_PKCS"
#define	MCASTR_CKM_RSA_X_509			"CKM_RSA_X_509"
#define	MCASTR_CKM_DSA				"CKM_DSA"
#define	MCASTR_CKM_DES_CBC			"CKM_DES_CBC"
#define	MCASTR_CKM_DES3_CBC			"CKM_DES3_CBC"
#define	MCASTR_CKM_AES_CBC			"CKM_AES_CBC"
#define	MCASTR_CKM_RC2_CBC			"CKM_RC2_CBC"
#define	MCASTR_CKM_AES_CTR			"CKM_AES_CTR"
#define	MCASTR_CKM_DES_KEY_GEN			"CKM_DES_KEY_GEN"
#define	MCASTR_CKM_DES2_KEY_GEN			"CKM_DES2_KEY_GEN"
#define	MCASTR_CKM_DES3_KEY_GEN			"CKM_DES3_KEY_GEN"
#define	MCASTR_CKM_AES_KEY_GEN			"CKM_AES_KEY_GEN"
#define	MCASTR_CKM_RSA_PKCS_KEY_PAIR_GEN	"CKM_RSA_PKCS_KEY_PAIR_GEN"
#define	MCASTR_CKM_DSA_KEY_PAIR_GEN		"CKM_DSA_KEY_PAIR_GEN"
#define	MCASTR_CKM_DH_PKCS_KEY_PAIR_GEN		"CKM_DH_PKCS_KEY_PAIR_GEN"

/*
 * Different builds of OS(EF) require the use of different strings for
 * EC key generation. Register both strings to accomodate both versions
 * of OS(EF).
 */
#define	MCASTR_CKM_EC_KEY_PAIR_GEN		"CKM_EC_KEY_PAIR_GEN"
#define	MCASTR_CKM_ECDSA_KEY_PAIR_GEN		"CKM_ECDSA_KEY_PAIR_GEN"

#define	MCASTR_CKM_ECDH1_DERIVE			"CKM_ECDH1_DERIVE"
#define	MCASTR_CKM_ECDSA			"CKM_ECDSA"
#define	MCASTR_CKM_DH_PKCS_DERIVE		"CKM_DH_PKCS_DERIVE"
#define	MCASTR_CKM_DES_CBC_PAD			"CKM_DES_CBC_PAD"
#define	MCASTR_CKM_DES3_CBC_PAD			"CKM_DES3_CBC_PAD"
#define	MCASTR_CKM_AES_CBC_PAD			"CKM_AES_CBC_PAD"
#define	MCASTR_CKM_RC2_CBC_PAD			"CKM_RC2_CBC_PAD"
/*
 * XXX: Vendor defined version of CKM_AES_CTR. This lets us test AES_CTR
 * from PKCS#11. Note: this is temporally added until CKM_AES_CTR is officially
 * added to PKCS#11 spec.
 */
#define	MCASTR_CPG_AES_CTR			"0x80001086"
#ifdef FINSVCS
/*
 * vendor specific mechanisms must be registered as ASCII
 * representation of mechanism number.
 */
#define	MCASTR_CKM_FIN_SVCS			"0x80004653"
#endif /* FINSVCS */

/* vendor specif mechanism for AES key wrap */
#define	MCASTR_CKM_AES_KEY_WRAP			"0x80414b57"

static crypto_mech_info_t mca_cb_mech_info_tab[] = {
	/* SHA1 */
	{MCASTR_CKM_SHA_1, MCAM_SHA_1,
	    CRYPTO_FG_DIGEST | CRYPTO_FG_DIGEST_ATOMIC,
	    0, 0, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA512 */
	{MCASTR_CKM_SHA512, MCAM_SHA512,
	    CRYPTO_FG_DIGEST | CRYPTO_FG_DIGEST_ATOMIC,
	    0, 0, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* MD5 */
	{MCASTR_CKM_MD5, MCAM_MD5,
	    CRYPTO_FG_DIGEST | CRYPTO_FG_DIGEST_ATOMIC,
	    0, 0, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	{MCASTR_CKM_DES_CBC, MCAM_DES_CBC,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    DES_KEY_LEN, DES_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	{MCASTR_CKM_DES3_CBC, MCAM_DES3_CBC,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    DES2_KEY_LEN, DES3_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	{MCASTR_CKM_AES_CBC, MCAM_AES_CBC,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    AES_MIN_KEY_LEN, AES_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* Currently openCryptoki on Linux does not support this mechanism */
#ifndef LINUX
	{MCASTR_CKM_AES_CTR, MCAM_AES_CTR,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    AES_MIN_KEY_LEN, AES_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
#endif
#ifdef	DEBUG
	/*
	 * XXX: register AES_CTR as a vendor defined mechanism so that it
	 * is accessible from userland PKCS#11 for testing
	 */
	{MCASTR_CPG_AES_CTR, MCAM_CPG_AES_CTR,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    AES_MIN_KEY_LEN, AES_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
#endif
	{MCASTR_CKM_DES_CBC_PAD, MCAM_DES_CBC_PAD,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    DES_KEY_LEN, DES_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	{MCASTR_CKM_DES3_CBC_PAD, MCAM_DES3_CBC_PAD,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    DES2_KEY_LEN, DES3_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	{MCASTR_CKM_AES_CBC_PAD, MCAM_AES_CBC_PAD,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    AES_MIN_KEY_LEN, AES_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* HMAC */
	{MCASTR_CKM_MD5_HMAC, MCAM_MD5_HMAC,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC,
	    HMAC_MIN_KEY_LEN, HMAC_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	{MCASTR_CKM_SHA_1_HMAC, MCAM_SHA_1_HMAC,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC,
	    HMAC_MIN_KEY_LEN, HMAC_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	{MCASTR_CKM_SHA512_HMAC, MCAM_SHA512_HMAC,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC,
	    HMAC_MIN_KEY_LEN, HMAC_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	{MCASTR_CKM_MD5_HMAC_GENERAL, MCAM_MD5_HMAC_GENERAL,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC,
	    HMAC_MIN_KEY_LEN, HMAC_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	{MCASTR_CKM_SHA_1_HMAC_GENERAL, MCAM_SHA_1_HMAC_GENERAL,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC,
	    HMAC_MIN_KEY_LEN, HMAC_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	{MCASTR_CKM_SHA512_HMAC_GENERAL, MCAM_SHA512_HMAC_GENERAL,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC,
	    HMAC_MIN_KEY_LEN, HMAC_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES}
};

static crypto_mech_info_t mca_ca_mech_info_tab[] = {
	/* RSA */
	{MCASTR_CKM_RSA_X_509, MCAM_RSA_X_509,
	    CRYPTO_FG_ENCRYPT_ATOMIC | CRYPTO_FG_ENCRYPT |
	    CRYPTO_FG_DECRYPT_ATOMIC | CRYPTO_FG_DECRYPT |
	    CRYPTO_FG_SIGN_ATOMIC | CRYPTO_FG_SIGN |
	    CRYPTO_FG_SIGN_RECOVER_ATOMIC | CRYPTO_FG_SIGN_RECOVER |
	    CRYPTO_FG_VERIFY_ATOMIC | CRYPTO_FG_VERIFY |
	    CRYPTO_FG_VERIFY_RECOVER_ATOMIC | CRYPTO_FG_VERIFY_RECOVER,
	    RSA_MIN_KEY_LEN, RSA_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	{MCASTR_CKM_RSA_PKCS, MCAM_RSA_PKCS,
	    CRYPTO_FG_ENCRYPT_ATOMIC | CRYPTO_FG_ENCRYPT |
	    CRYPTO_FG_DECRYPT_ATOMIC | CRYPTO_FG_DECRYPT |
	    CRYPTO_FG_SIGN_ATOMIC | CRYPTO_FG_SIGN |
	    CRYPTO_FG_SIGN_RECOVER_ATOMIC | CRYPTO_FG_SIGN_RECOVER |
	    CRYPTO_FG_VERIFY_ATOMIC | CRYPTO_FG_VERIFY |
	    CRYPTO_FG_VERIFY_RECOVER_ATOMIC | CRYPTO_FG_VERIFY_RECOVER,
	    RSA_MIN_KEY_LEN, RSA_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* DSA */
	{MCASTR_CKM_DSA, MCAM_DSA,
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC,
	    DSA_MIN_KEY_LEN, DSA_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* DH */
	{MCASTR_CKM_DH_PKCS_KEY_PAIR_GEN, MCAM_DH_PKCS_KEY_PAIR_GEN,
	    CRYPTO_FG_GENERATE_KEY_PAIR,
	    DH_MIN_KEY_LEN, DH_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	{MCASTR_CKM_DH_PKCS_DERIVE, MCAM_DH_PKCS_DERIVE,
	    CRYPTO_FG_DERIVE,
	    DH_MIN_KEY_LEN, DH_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
#ifndef LINUX
	/* EC */
	{MCASTR_CKM_EC_KEY_PAIR_GEN, MCAM_EC_KEY_PAIR_GEN,
	    CRYPTO_FG_GENERATE_KEY_PAIR,
	    EC_MIN_KEY_LEN, EC_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	{MCASTR_CKM_ECDSA_KEY_PAIR_GEN, MCAM_ECDSA_KEY_PAIR_GEN,
	    CRYPTO_FG_GENERATE_KEY_PAIR,
	    EC_MIN_KEY_LEN, EC_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	{MCASTR_CKM_ECDH1_DERIVE, MCAM_ECDH1_DERIVE,
	    CRYPTO_FG_DERIVE,
	    EC_MIN_KEY_LEN, EC_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	{MCASTR_CKM_ECDSA, MCAM_ECDSA,
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC,
	    EC_MIN_KEY_LEN, EC_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
#endif
};

static crypto_mech_info_t mca_om_mech_info_tab[] = {
	/* Key Pair Gen */
	{MCASTR_CKM_RSA_PKCS_KEY_PAIR_GEN, MCAM_RSA_KEY_PAIR_GEN,
	    CRYPTO_FG_GENERATE_KEY_PAIR,
	    RSA_MIN_KEY_LEN, RSA_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	{MCASTR_CKM_DSA_KEY_PAIR_GEN, MCAM_DSA_KEY_PAIR_GEN,
	    CRYPTO_FG_GENERATE_KEY_PAIR,
	    DSA_MIN_KEY_LEN, DSA_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* Key Gen */
	{MCASTR_CKM_DES_KEY_GEN, MCAM_DES_KEY_GEN, CRYPTO_FG_GENERATE,
	    DES_KEY_LEN, DES_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	{MCASTR_CKM_DES2_KEY_GEN, MCAM_DES2_KEY_GEN, CRYPTO_FG_GENERATE,
	    DES2_KEY_LEN, DES2_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	{MCASTR_CKM_DES3_KEY_GEN, MCAM_DES3_KEY_GEN, CRYPTO_FG_GENERATE,
	    DES3_KEY_LEN, DES3_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	{MCASTR_CKM_AES_KEY_GEN, MCAM_AES_KEY_GEN, CRYPTO_FG_GENERATE,
	    AES_MIN_KEY_LEN, AES_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* Wrap/Unwrap */
	{MCASTR_CKM_DES_CBC_PAD, MCAM_DES_CBC_PAD,
	    CRYPTO_FG_WRAP | CRYPTO_FG_UNWRAP,
	    DES_KEY_LEN, DES_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	{MCASTR_CKM_DES3_CBC_PAD, MCAM_DES3_CBC_PAD,
	    CRYPTO_FG_WRAP | CRYPTO_FG_UNWRAP,
	    DES2_KEY_LEN, DES3_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	{MCASTR_CKM_AES_CBC_PAD, MCAM_AES_CBC_PAD,
	    CRYPTO_FG_WRAP | CRYPTO_FG_UNWRAP,
	    AES_MIN_KEY_LEN, AES_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	{MCASTR_CKM_RC2_CBC_PAD, MCAM_RC2_CBC_PAD,
	    CRYPTO_FG_WRAP | CRYPTO_FG_UNWRAP,
	    BYTES2BITS(RC2_MIN_KEY_LEN), BYTES2BITS(RC2_MAX_KEY_LEN),
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	{MCASTR_CKM_DES_CBC, MCAM_DES_CBC,
	    CRYPTO_FG_WRAP | CRYPTO_FG_UNWRAP,
	    DES_KEY_LEN, DES_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	{MCASTR_CKM_DES3_CBC, MCAM_DES3_CBC,
	    CRYPTO_FG_WRAP | CRYPTO_FG_UNWRAP,
	    DES2_KEY_LEN, DES3_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	{MCASTR_CKM_AES_CBC, MCAM_AES_CBC,
	    CRYPTO_FG_WRAP | CRYPTO_FG_UNWRAP,
	    AES_MIN_KEY_LEN, AES_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
#ifndef LINUX
	{MCASTR_CKM_AES_CTR, MCAM_AES_CTR,
	    CRYPTO_FG_WRAP | CRYPTO_FG_UNWRAP,
	    AES_MIN_KEY_LEN, AES_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	{MCASTR_CKM_AES_KEY_WRAP, MCAM_AES_KEY_WRAP,
	    CRYPTO_FG_WRAP | CRYPTO_FG_UNWRAP,
	    AES_MIN_KEY_LEN, AES_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
#endif
#ifdef	DEBUG
	/*
	 * XXX: register AES_CTR as a vendor defined mechanism so that it
	 * is accessible from userland PKCS#11 for testing
	 */
	{MCASTR_CPG_AES_CTR, MCAM_CPG_AES_CTR,
	    CRYPTO_FG_WRAP | CRYPTO_FG_UNWRAP,
	    AES_MIN_KEY_LEN, AES_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
#endif
	{MCASTR_CKM_RC2_CBC, MCAM_RC2_CBC,
	    CRYPTO_FG_WRAP | CRYPTO_FG_UNWRAP,
	    BYTES2BITS(RC2_MIN_KEY_LEN), BYTES2BITS(RC2_MAX_KEY_LEN),
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	{MCASTR_CKM_RSA_X_509, MCAM_RSA_X_509,
	    CRYPTO_FG_WRAP | CRYPTO_FG_UNWRAP,
	    RSA_MIN_KEY_LEN, RSA_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	{MCASTR_CKM_RSA_PKCS, MCAM_RSA_PKCS,
	    CRYPTO_FG_WRAP | CRYPTO_FG_UNWRAP,
	    RSA_MIN_KEY_LEN, RSA_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
#ifdef FINSVCS
	/* financial services mechanism */
	{MCASTR_CKM_FIN_SVCS, MCAM_FIN_SVCS, CRYPTO_FG_ENCRYPT,
	    DES_KEY_LEN, DES3_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
#endif /* FINSVCS */
};


/* XXX: IMPLEMENT ME!!! */
/* ARGSUSED */
static void
mca_provider_status(crypto_provider_handle_t provider, uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}


/*
 * mca_logical_provider_unregister()
 *
 * handle logical provider unregistration
 */
int
mca_logical_provider_unregister(mca_keystore_t *ks)
{
	int			rv = CRYPTO_SUCCESS;
	mca_provider_private_t	*pi = &ks->mks_provinfo;


	DBG(NULL, DENTRY, "mca_logical_provider_unregister(%s)",
		ks->mks_name);

	/* unregister the logical provider */
	rv = crypto_unregister_provider(pi->mp_provhandle);
	if (rv == CRYPTO_SUCCESS) {
		pi->mp_provhandle = 0;

		/* uninitialize the session table */
		session_table_fini(&ks->mks_sessiontable);

	}
	return (rv);
}


/*
 * This function builds crypto_mech_info list by adding 'smechinfo' to
 * 'dmechinfo'. (s for src, and d for dst)
 * 'snummech' is the number of mechanisms in the 'smechinfo'.
 * 'dnummech' is the number of entries that 'dmechinfo' can store.
 * 'dmechinfo' may contain some valid mechanisms already, and cm_mech_number
 * being -1 in the mech_info array indicates the end of the valid entries.
 *
 * Caller must set the cm_mech_number of the element after the last
 * valid element to -1. Also note that, this function will set the
 * cm_mech_number of the first entry after the newly added entries to -1.
 *
 * Note: MD5 and RC2 mechs are removed from the list if the board is
 * in FIPS mode.
 */
static void
adjust_mech_list(mca_t *mca, crypto_mech_info_t *smechinfo, int snummech,
    crypto_mech_info_t *dmechinfo, int *dnummech)
{
	int		enablerc2cbc;
	int		enablesha512;
	dev_info_t	*dip = mca->mca_dip;
	int		i, j, mechnum = 0;
	int		enable_md5update;
	int		enable_sha1update;
	int		enable_sha512update;
	int		enable_hmac;
	uint32_t	func_group_mask = (uint32_t)-1;

	/*
	 * S1WS calls C_EncryptInit with CKM_RC2_CBC even when we advertise only
	 * wrap and unwrap modes for RC2_CBC
	 * We decided to disable RC2_CBC by default.
	 */
	enablerc2cbc = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "enable-rc2cbc", 0);

	/*
	 * SHA512 is implemented in the FW and it is known to be
	 * slow. Disable it by default.
	 */
	enablesha512 = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "enable-sha512", 0);

	/*
	 * MD5 multi-part is implemented in the FW and it is known to be slow.
	 * Disable it by default.
	 */
	enable_md5update = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "enable-multi-part-md5", 0);

	/*
	 * SHA1 multi-part is implemented in the FW and it is known to be slow.
	 * Disable it by default.
	 */
	enable_sha1update = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "enable-multi-part-sha1", 0);

	/*
	 * SHA512 multi-part is implemented in the FW and it is known to
	 * be slow. Disable it by default.
	 */
	enable_sha512update = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
	    "enable-multi-part-sha512", 0);

	/*
	 * HMAC is known to be slow. Disable it by default.
	 */
	enable_hmac = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "enable-hmac", 0);

	/* find out how many valid mech_infos are in 'dmechinfo' */
	for (j = 0; j < *dnummech; j++) {
		if (dmechinfo[j].cm_mech_number == -1) {
			break;
		}
		mechnum++;
	}

	for (i = 0; i < snummech; i++) {
		int	add = 1;

		/*
		 * This function merges 'smechinfo' and 'dmechinfo'.
		 * 'smechinfo' and 'dmechinfo' may contain the same mech
		 * with different cm_func_groupt_mask, and therefore, the masks
		 * must be combined.
		 */
		for (j = 0; j < mechnum; j++) {
			if (smechinfo[i].cm_mech_number ==
			    dmechinfo[j].cm_mech_number) {
				/* the mech already exist, update the flags */
				dmechinfo[j].cm_func_group_mask |=
				    smechinfo[i].cm_func_group_mask;
				add = 0;
				break;
			}
		}

		switch (smechinfo[i].cm_mech_number) {
		case MCAM_RC2_CBC:
			/*
			 * If RC2CBC mech is configured to be disabled, do
			 * not add them to the list
			 */
			if (!enablerc2cbc) {
				add = 0;
			}
			/*FALLTHROUGH*/
		case MCAM_RC2_CBC_PAD:
			/*
			 * If the board in the FIPS mode, do not add
			 * non-approved mechs to the list
			 */
			if (mca_isfips(mca)) {
				add = 0;
			}
			break;
		case MCAM_MD5_HMAC:
		case MCAM_MD5_HMAC_GENERAL:
			if (!enable_hmac) {
				add = 0;
			}
			/*FALLTHROUGH*/
		case MCAM_MD5:
			/*
			 * If the board in the FIPS mode, do not add
			 * non-approved mechs to the list
			 */
			if (mca_isfips(mca)) {
				add = 0;
			}

			/* disable multi-part */
			if (!enable_md5update) {
				func_group_mask &= ~CRYPTO_FG_DIGEST;
			}
			break;
		case MCAM_SHA_1_HMAC:
		case MCAM_SHA_1_HMAC_GENERAL:
			if (!enable_hmac) {
				add = 0;
			}
			/*FALLTHROUGH*/
		case MCAM_SHA_1:
			/* disable multi-part */
			if (!enable_sha1update) {
				func_group_mask &= ~CRYPTO_FG_DIGEST;
			}
			break;
		case MCAM_SHA512_HMAC:
		case MCAM_SHA512_HMAC_GENERAL:
			if (!enable_hmac) {
				add = 0;
			}
			/*FALLTHROUGH*/
		case MCAM_SHA512:
			/*
			 * If SHA512 mechs are configured to be disabled, do
			 * not add them to the list
			 */
			if (!enablesha512) {
				add = 0;
			}

			/* disable multi-part */
			if (!enable_sha512update) {
				func_group_mask &= ~CRYPTO_FG_DIGEST;
			}
			break;
		default:
			/* all other mechs should be added */
			break;
		}
		if (add && (mechnum < *dnummech)) {
			dmechinfo[mechnum] = smechinfo[i];
			dmechinfo[mechnum++].cm_func_group_mask &=
			    func_group_mask;
		}
		/* reset the func_group_mask: enable all */
		func_group_mask = (uint32_t)-1;
	}

	if (mechnum < *dnummech) {
		/*
		 * set cm_mech_number of the first entry after the
		 * newly added entries to -1.
		 */
		dmechinfo[mechnum].cm_mech_number = -1;
	} else {
		DBG(NULL, DWARN, "adjust_mechanism: BUFFER_TOO_SMALL "
		    "mechnum=%d dmechnum=%d", mechnum, *dnummech);
	}

	*dnummech = mechnum;
}

/*
 * mca_logical_provider_register()
 *
 * handle logical provider registration
 */
int
mca_logical_provider_register(mca_keystore_t *ks, mca_t *mca)
{
	int			rv;
	int			nummech;
	crypto_provider_info_t	prov_info;
	char			identstr[CRYPTO_PROVIDER_DESCR_MAX_LEN + 1];
	crypto_mech_info_t	mech_infos[MAX_NUMMECH];

	DBG(NULL, DENTRY, "mca_logical_provider_register %s",
		ks->mks_name);

	/*
	 * First real provider associated with the keystore.
	 * Allocate the logical provider info structure and
	 * initialize the provider info.
	 */

	/* initialize the session table */
	session_table_init(&ks->mks_sessiontable);

	ks->mks_provinfo.mp_mca = NULL;
	ks->mks_provinfo.mp_ks = ks;
	ks->mks_provinfo.mp_type = CRYPTO_LOGICAL_PROVIDER;
	ks->mks_provinfo.mp_sessiontable = &ks->mks_sessiontable;

#ifdef SPI_V2
	prov_info.pi_interface_version = CRYPTO_SPI_VERSION_2;
#else
	prov_info.pi_interface_version = CRYPTO_SPI_VERSION_1;
#endif
	prov_info.pi_provider_type = CRYPTO_LOGICAL_PROVIDER;
	prov_info.pi_provider_dev.pd_hw = mca->mca_dip;
	prov_info.pi_provider_handle = &ks->mks_provinfo;
	prov_info.pi_ops_vector = NULL;
	prov_info.pi_provider_description = identstr;
	prov_info.pi_logical_provider_count = 0;
	prov_info.pi_logical_providers = NULL;

	/* register the keystore name */
	snprintf(identstr, sizeof (identstr), "%s", ks->mks_name);


	/*
	 * empty mech_infos: set the cm_mech_number field of the first
	 * mech_info
	 */
	mech_infos[0].cm_mech_number = -1;

	/*
	 * Adjust the mechanism list based on mca.conf.
	 */
	nummech = MAX_NUMMECH;
	adjust_mech_list(mca,
	    mca_cb_mech_info_tab, NUMMECH(mca_cb_mech_info_tab),
	    mech_infos, &nummech);

	nummech = MAX_NUMMECH;
	adjust_mech_list(mca,
	    mca_ca_mech_info_tab, NUMMECH(mca_ca_mech_info_tab),
	    mech_infos, &nummech);

	nummech = MAX_NUMMECH;
	adjust_mech_list(mca,
	    mca_om_mech_info_tab, NUMMECH(mca_om_mech_info_tab),
	    mech_infos, &nummech);

	prov_info.pi_mechanisms = mech_infos;
	prov_info.pi_mech_list_count = nummech;

	/* register the logical provider with kCF */
	if ((rv = crypto_register_provider(&prov_info,
	    &ks->mks_provinfo.mp_provhandle)) != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "crypto_register_provider() "
		    "failed (0x%x)", rv);
		return (rv);
	}

	return (rv);
}


static int
register_hw_provider(mca_t *mca, mca_ring_t *ringp,
    crypto_mech_info_t *mechs, int mechnum, crypto_ops_t *ops, int mode)
{
	int			rv;
	char			identstr[CRYPTO_PROVIDER_DESCR_MAX_LEN + 1];
	mca_provider_private_t	*prov = NULL;
	crypto_mech_info_t	tmpmechs[MAX_NUMMECH];
	int			tmpmechnum = MAX_NUMMECH;
	crypto_provider_info_t	prov_info;

	prov = &ringp->mr_provinfo;
	if (prov->mp_provhandle != 0) {
		DBG(mca, DENTRY, "provider already registered");
		return (CRYPTO_SUCCESS);
	}

#ifdef SPI_V2
	prov_info.pi_interface_version = CRYPTO_SPI_VERSION_2;
#else
	prov_info.pi_interface_version = CRYPTO_SPI_VERSION_1;
#endif
	prov_info.pi_provider_type = CRYPTO_HW_PROVIDER;
	prov_info.pi_provider_dev.pd_hw = mca->mca_dip;
	prov_info.pi_flags = 0;
	if (mode == MCA_DIAG) {
		/*
		 * register the provider as a HW  provider without
		 * logical provider for diagnosis.
		 */
		prov_info.pi_logical_provider_count = 0;
		prov_info.pi_logical_providers = NULL;
	} else {
		/*
		 * if there's an associated keystore - a logical
		 * provider exists
		 */
		if (mca->mca_keystore_count) {
			prov_info.pi_flags = CRYPTO_HIDE_PROVIDER;
			prov_info.pi_logical_provider_count =
			    mca->mca_keystore_count;
			prov_info.pi_logical_providers =
				mca_keystore_create_lp_array(mca);
		} else {
			prov_info.pi_logical_provider_count = 0;
			prov_info.pi_logical_providers = NULL;
		}
	}

	prov->mp_mca = mca;
	prov->mp_ks = NULL;
	prov->mp_type = CRYPTO_HW_PROVIDER;
	prov->mp_ring = ringp;

	/* Adjust the mechanism list based on mca.conf & FIPS mode */
	tmpmechs[0].cm_mech_number = -1;
	adjust_mech_list(mca, mechs, mechnum, tmpmechs, &tmpmechnum);

	prov_info.pi_mechanisms = tmpmechs;
	prov_info.pi_mech_list_count = tmpmechnum;
	prov_info.pi_provider_handle = prov;
	prov_info.pi_ops_vector = ops;
	prov_info.pi_provider_description = identstr;
	snprintf(identstr, sizeof (identstr), "%s/%d Crypto Accel %s 1.0",
	    ddi_driver_name(mca->mca_dip), ddi_get_instance(mca->mca_dip),
	    ringp->mr_name);

	if ((rv = crypto_register_provider(&prov_info,
	    &prov->mp_provhandle)) != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "crypto_register_provider() "
		    "failed for %s (0x%x)", ringp->mr_name, rv);
		return (rv);
	}

	if (prov_info.pi_logical_provider_count) {
		mca_keystore_destroy_lp_array(
		    prov_info.pi_logical_providers,
		    prov_info.pi_logical_provider_count);
	}

	return (CRYPTO_SUCCESS);
}

int
mca_hw_provider_register(mca_t *mca, int mode)
{
	int			rv;

	DBG(mca, DENTRY, "mca_hw_provider_register -->");

	mutex_enter(&mca->mca_reglock);

	if (mca_isregistered(mca) ||
	    mca_isdiag(mca)) {
		mutex_exit(&mca->mca_reglock);
		return (CRYPTO_SUCCESS);
	}

	mca->mca_ring_cb.mr_provinfo.mp_sessiontable = NULL;
	mca->mca_ring_ca.mr_provinfo.mp_sessiontable = NULL;
	mca->mca_ring_om.mr_provinfo.mp_sessiontable = &mca->mca_sessiontable;

	rv = register_hw_provider(mca, &mca->mca_ring_cb,
	    mca_cb_mech_info_tab, NUMMECH(mca_cb_mech_info_tab),
	    &mca_sym_ops, mode);
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "register_hw_provider failed (%d) for CB ring",
			rv);
		mutex_exit(&mca->mca_reglock);
		return (rv);
	}
	DBG(mca, DENTRY, "registered CB ring");
	rv = register_hw_provider(mca, &mca->mca_ring_ca,
	    mca_ca_mech_info_tab, NUMMECH(mca_ca_mech_info_tab),
	    &mca_asym_ops, mode);
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "register_hw_provider failed (%d) for CA ring",
			rv);
		goto errorexit;
	}
	DBG(mca, DENTRY, "registered CA ring");

	/* Initialize the session table: Used by OM provider */
	session_table_init(&mca->mca_sessiontable);
	rv = register_hw_provider(mca, &mca->mca_ring_om,
	    mca_om_mech_info_tab, NUMMECH(mca_om_mech_info_tab),
	    &mca_om_ops, mode);
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DWARN, "register_hw_provider failed (%d) for OM ring",
			rv);
		session_table_fini(&mca->mca_sessiontable);
		goto errorexit;
	}
	DBG(mca, DENTRY, "registered OM ring");

	if (mode == MCA_DIAG) {
		mca_setdiag(mca);
	} else {
		mca_setregistered(mca);
	}

	mutex_exit(&mca->mca_reglock);

	return (CRYPTO_SUCCESS);

errorexit:
	if (mca->mca_ring_cb.mr_provinfo.mp_provhandle) {
		(void) crypto_unregister_provider(
		    mca->mca_ring_cb.mr_provinfo.mp_provhandle);
		mca->mca_ring_cb.mr_provinfo.mp_provhandle = 0;
	}
	if (mca->mca_ring_ca.mr_provinfo.mp_provhandle) {
		(void) crypto_unregister_provider(
		    mca->mca_ring_ca.mr_provinfo.mp_provhandle);
		mca->mca_ring_ca.mr_provinfo.mp_provhandle = 0;
	}

	mutex_exit(&mca->mca_reglock);

	return (rv);
}

int
mca_hw_provider_unregister(mca_t *mca)
{
	int			rv = CRYPTO_SUCCESS;
	mca_provider_private_t	*prov;
	mca_privatectx_t	*ctx;

	DBG(mca, DENTRY, "mca_hw_provider_unregister");

	mutex_enter(&mca->mca_reglock);

	if (mca_isunregistered(mca)) {

		/*
		 * The providers have never been registered.
		 * An uninitialized mutex will be used in session_table_fini
		 * if we do not return here.
		 */
		mutex_exit(&mca->mca_reglock);
		return (CRYPTO_SUCCESS);
	}

	prov = &mca->mca_ring_cb.mr_provinfo;
	if (prov->mp_provhandle) {
		/* unregiser the real provider */
		rv = crypto_unregister_provider(prov->mp_provhandle);
		if (rv != CRYPTO_SUCCESS) {
			/* XXX: don't know how to recover from it */
			cmn_err(CE_WARN, "Unable unregister CB provider: "
			    "[0x%x]", rv);
			mutex_exit(&mca->mca_reglock);
			return (CRYPTO_GENERAL_ERROR);
		}
		DBG(mca, DENTRY, "mca_hw_provider_unregister: unregistered CB");
		prov->mp_provhandle = 0;
	}

	prov = &mca->mca_ring_ca.mr_provinfo;
	if (prov->mp_provhandle) {
		/* unregiser the real provider */
		rv = crypto_unregister_provider(prov->mp_provhandle);
		if (rv != CRYPTO_SUCCESS) {
			/* XXX: don't know how to recover from it */
			cmn_err(CE_WARN, "Unable unregister CA provider: "
			    "[0x%x]", rv);
			mutex_exit(&mca->mca_reglock);
			return (CRYPTO_GENERAL_ERROR);
		}
		DBG(mca, DENTRY, "mca_hw_provider_unregister: unregistered CA");
		prov->mp_provhandle = 0;
	}

	prov = &mca->mca_ring_om.mr_provinfo;
	if (prov->mp_provhandle) {
		/* unregiser the real provider */
		rv = crypto_unregister_provider(prov->mp_provhandle);
		if (rv != CRYPTO_SUCCESS) {
			/* XXX: don't know how to recover from it */
			cmn_err(CE_WARN, "Unable unregister OM provider: "
			    "[0x%x]", rv);
			mutex_exit(&mca->mca_reglock);
			return (CRYPTO_GENERAL_ERROR);
		}
		DBG(mca, DENTRY, "mca_hw_provider_unregister: unregistered OM");
		prov->mp_provhandle = 0;

		/* uninitialize the session table associated with OM prov */
		session_table_fini(&mca->mca_sessiontable);
	}

	/* delete undeleted contexts */
	for (;;) {
		mutex_enter(&mca->mca_ctxlist_lock);
		ctx = (mca_privatectx_t *)mca_dequeue(&mca->mca_ctxlist);
		mutex_exit(&mca->mca_ctxlist_lock);

		if (ctx != NULL) {
			mca_freectx(ctx);
		} else {
			break;
		}
	}

	mca_setunregistered(mca);

	mutex_exit(&mca->mca_reglock);
	return (CRYPTO_SUCCESS);
}

int
mca_get_datalen(crypto_data_t *data)
{
	if (data) {
		return (data->cd_length);
	} else {
		return (0);
	}
}

void
mca_set_datalen(crypto_data_t *data, size_t outlen)
{
	if (data) {
		data->cd_length = outlen;
	}
}

/*
 * This functions returns the address of the buffer at the current position
 * XXX: At this point, we assume that 'buf' is a contiguous data.
 */
char *
mca_get_dataaddr(crypto_data_t *buf)
{
	switch (buf->cd_format) {
	case CRYPTO_DATA_RAW:
		return (buf->cd_raw.iov_base + buf->cd_offset);
	case CRYPTO_DATA_UIO:
		return (buf->cd_uio->uio_iov[0].iov_base + buf->cd_offset);
	case CRYPTO_DATA_MBLK:
		return ((char *)buf->cd_mp->b_rptr + buf->cd_offset);
	}
	return (NULL);
}

/*
 * This is called for input buffer
 */
void
mca_setresid(crypto_data_t *data, int len)
{
	if (data) {
		data->cd_offset += (data->cd_length - len);
		data->cd_length = len;
	}
}

/*
 * This is called for output buffer
 */
void
mca_updateoutlen(crypto_data_t *data, int len)
{
	data->cd_length += len;
}

/* context destructor */
static int
mca_freectx_kcf(crypto_ctx_t *ctx)
{
	/* the ctx has already been freed */
	if (ctx->cc_provider_private == NULL) {
		return (CRYPTO_SUCCESS);
	}

	mca_freectx(ctx->cc_provider_private);
	ctx->cc_provider_private = NULL;
	return (CRYPTO_SUCCESS);
}

/*
 * this context destruction function takes void ptr for KCL compatibility
 */
void
mca_freectx(void *arg)
{
	mca_privatectx_t *privctx = (mca_privatectx_t *)arg;
	mca_t		*mca;
	size_t		ctxsz;

	DBG(NULL, DENTRY, "mca_freectx -->");

	/* the ctx has already been freed */
	if (privctx == NULL) {
		return;
	}

	mca = privctx->mc_mca;
	ctxsz = privctx->mc_size;

	/* remove the context from the ctxlist */
	mutex_enter(&mca->mca_ctxlist_lock);
	mca_rmqueue((mca_listnode_t *)privctx);
	mutex_exit(&mca->mca_ctxlist_lock);

	if (privctx->mc_ctxdtr) {
		privctx->mc_ctxdtr(privctx + 1);
	}

	if (privctx->mc_param) {
		kmem_free(privctx->mc_param, privctx->mc_paramlen);
	}

	if (privctx->mc_keyhead != NULL) {
		kmem_free(privctx->mc_keyhead, privctx->mc_keyheadsz);
	}

	if (privctx->mc_session != NULL) {
		mca_session_releaseref(privctx->mc_session, UNLOCKED);
	}

	bzero(privctx, ctxsz);
	kmem_free(privctx, ctxsz);

	DBG(NULL, DENTRY, "mca_freectx <--");
}

/*
 * This function returns expected keytype for the cmd.
 * At this point, it assumes that it is called only by mca_allocctx().
 */
static int
cmd2keytype(uint32_t cmd, int *keytype)
{
	switch (cmd & CMD_MASK) {
	case CMD_RSAPUB:
	case CMD_RSAPADENC:
	case CMD_RSAPADVRFY:
		*keytype = KEYTYPE_RSA_PUBLIC;
		break;
	case CMD_RSAPRV:
	case CMD_RSAPADDEC:
	case CMD_RSAPADSIGN:
		*keytype = KEYTYPE_RSA_PRIVATE;
		break;
	case CMD_DSASIGN:
		*keytype = KEYTYPE_DSA_PRIVATE;
		break;
	case CMD_DSAVERIFY:
		*keytype = KEYTYPE_DSA_PUBLIC;
		break;
	case CMD_ECDSASIGN:
		*keytype = KEYTYPE_EC_PRIVATE;
		break;
	case CMD_ECDSAVERIFY:
		*keytype = KEYTYPE_EC_PUBLIC;
		break;
	case CMD_3DESENC:
	case CMD_3DESDEC:
		if (cmd & CMD_HI_SINGLE) {
			*keytype = KEYTYPE_DES;
		} else {
			*keytype = KEYTYPE_DES3;
		}
		break;
	case CMD_AESCBCENC:
	case CMD_AESCBCDEC:
	case CMD_AESCTRENC:
	case CMD_AESCTRDEC:
		*keytype = KEYTYPE_AES;
		break;
	case CMD_RC2ENC:
	case CMD_RC2DEC:
		*keytype = KEYTYPE_RC2;
		break;
	case CMD_FIN_SVCS:
		*keytype = KEYTYPE_FS;
		break;
	case CMD_HMAC_MD5:
	case CMD_HMAC_SHA1:
	case CMD_HMAC_SHA512:
		*keytype = KEYTYPE_GENERIC_SECRET;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	return (CRYPTO_SUCCESS);
}


/* context */
int
mca_allocctx(mca_t *mca, crypto_session_id_t session_id,
    crypto_key_t *key, int cmd, int size, mca_privatectx_t **privctx)
{
	mca_session_t		*session = NULL;
	mca_privatectx_t	*ctx;
	caddr_t			keybuf = NULL;
	uint32_t		keybuflen = 0;
	uint32_t		keyflags = 0;
	int			rv;
	int			keytype = -1;


	ctx = kmem_alloc(sizeof (mca_privatectx_t) + size, KM_SLEEP);
	if (ctx == NULL) {
		return (CRYPTO_HOST_MEMORY);
	}

	ctx->mc_mca = mca;
	ctx->mc_cmd = cmd;
	ctx->mc_shortparamlen = 0;
	ctx->mc_paramlen = 0;
	ctx->mc_size = sizeof (mca_privatectx_t) + size;
	ctx->mc_ctxdtr = NULL;
	ctx->mc_param = NULL;
	ctx->mc_keystore = NULL;
	ctx->mc_session = NULL;

	if (key == NULL) {
		/* operation without key (i.e. hash) */
		ctx->mc_keyhead = NULL;
		ctx->mc_keyheadsz = 0;
		/* add the context to the ctxlist */
		mutex_enter(&mca->mca_ctxlist_lock);
		mca_enqueue(&mca->mca_ctxlist, (mca_listnode_t *)ctx);
		mutex_exit(&mca->mca_ctxlist_lock);
		*privctx = ctx;
		return (CRYPTO_SUCCESS);
	}

	rv = cmd2keytype(cmd, &keytype);
	if (rv != CRYPTO_SUCCESS) {
		kmem_free(ctx, ctx->mc_size);
		return (rv);
	}

	if (key->ck_format == CRYPTO_KEY_REFERENCE) {
		session = session_hold(session_table_get(mca, session_id),
					session_id);
		if (session == NULL) {
			kmem_free(ctx, ctx->mc_size);
			return (CRYPTO_SESSION_HANDLE_INVALID);
		}
	}

	/* first find out the size needed for mca keyhead */
	rv = write_key_internal(session, key, keytype, NULL, &keybuflen, NULL);
	if (rv != CRYPTO_SUCCESS) {
		goto exit;
	}
	if (keybuflen > 0) {
		int keybufsz = keybuflen;
#ifdef LINUX
		keybuf = kmem_alloc(keybuflen, GFP_ATOMIC);
#else
		keybuf = kmem_alloc(keybuflen, KM_SLEEP);
#endif
		if (keybuf == NULL) {
			rv = CRYPTO_HOST_MEMORY;
			goto exit;
		}
		/* get the mca keyhead */
		rv = write_key_internal(session, key, keytype, keybuf,
		    &keybuflen, &keyflags);
		if (rv != CRYPTO_SUCCESS) {
			DBG(NULL, DWARN, "mca_write_key failed with "
			    "0x%x (keybuflen = %d, keybufsz = %d)",
			    rv, keybuflen, keybufsz);
			if (keybuf != NULL) {
				kmem_free(keybuf, keybufsz);
				keybuf = NULL;
			}
			goto exit;
		}
	}

	ctx->mc_keyhead = (mca_key_head_t *)keybuf;
	ctx->mc_keyheadsz = keybuflen;
	ctx->mc_keyflags = keyflags;
	if (keyflags & KEYFLAG_PERSIST) {
		/*
		 * If the key is token key, hold the session refcnt
		 * The session refcnt is directly incremented here since
		 * we are already holding the session mutex.
		 */
		session->ms_refcnt++;
		ctx->mc_session = session;
	}
	if ((keyflags & KEYFLAG_PERSIST) || (keyflags & KEYFLAG_SENSITIVE)) {
		ctx->mc_keystore = mca_keystore_lookup_by_session(session_id);
	}
	if (session) {
		mutex_exit(&session->ms_lock);
	}

	/* add the context to the ctxlist */
	mutex_enter(&mca->mca_ctxlist_lock);
	mca_enqueue(&mca->mca_ctxlist, (mca_listnode_t *)ctx);
	mutex_exit(&mca->mca_ctxlist_lock);

	*privctx = ctx;

	return (CRYPTO_SUCCESS);

exit:
	if (ctx != NULL) {
		kmem_free(ctx, ctx->mc_size);
	}
	if (session) {
		mutex_exit(&session->ms_lock);
	}

	return (rv);
}

/*
 * DIGEST OPERATIONS
 */

/*
 * Atomic Digest
 * Digest atomic operation does not use key, thus 'session_id' need not be used
 */
/*ARGSUSED*/
static int
mca_digest_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_data_t *data, crypto_data_t *digest, crypto_req_handle_t req)
{
	int		rv;
	mca_t		*mca = MCA_PROVIDER2MCA(provider);
	uint32_t	cmd;

	DBG(mca, DENTRY, "mca_digest_atomic -->");

	switch (mechanism->cm_type) {
	case MCAM_MD5:
		if (mca_isfips(mca)) {
			return (CRYPTO_MECHANISM_INVALID);
		}
		cmd = CMD_MD5;
		break;
	case MCAM_SHA_1:
		cmd = CMD_SHA1;
		break;
	case MCAM_SHA512:
		cmd = CMD_SHA512;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	/*
	 * In-place operations (input == output) are indicated by having a
	 * NULL output. In this case set the output to point to the input.
	 */
	if (digest == NULL) {
		digest = data;
	}

	/*
	 * If the data is too large, it cannot be submitted
	 * as a single request: process it in multi-part
	 */
	if (data->cd_length > MAXPACKET) {
		rv = mca_hash_init(mca, NULL, cmd, data, digest, req);
	} else {
		rv = mca_hash(mca, cmd, data, digest, req);
	}

	if ((rv != CRYPTO_QUEUED) && (rv != CRYPTO_SUCCESS) &&
	    (rv != CRYPTO_BUFFER_TOO_SMALL)) {
		mca_set_datalen(digest, 0);
	}
	DBG(mca, DENTRY, "mca_digest_atomic <--[0x%x]", rv);

	return (rv);
}


/*
 * Digest Init: allocate a private ctx
 */
static int
mca_digest_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_req_handle_t req)
{
	int			rv;
	mca_privatectx_t	*privctx = NULL;

	DBG(NULL, DENTRY, "mca_digest_init -->");

	/* attach the mechanism specific context */
	rv = mca_hash_allocctx(ctx, req, mechanism, &privctx);
	ctx->cc_provider_private = privctx;

	DBG(NULL, DENTRY, "mca_digest_init <--[0x%x]", rv);

	return (rv);
}

/*
 * Digest Update: multi-part digest operation
 * If this is the first digest_update call, initialize the multi-part
 * operation in FW and process the data from the callback.
 * If this is not the first digest update call, the context ID is stored in
 * the private ctx.  Simply submit the request to the HW.
 */
static int
mca_digest_update(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	int			rv = CRYPTO_FAILED;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = ctx->cc_provider_private;

	DBG(mca, DENTRY, "mca_digest_update: started");

	/*
	 * If 'MULTI_PART' flag is not turned on, this is the first
	 * digest_update call: need to get a context ID from the hardware.
	 * Processing of the data is handled by the callback function
	 * of mca_hash_init.
	 */
	if (!(privctx->mc_cmd & CMD_HI_MULTI_PART)) {
		rv = mca_hash_init(mca, privctx, privctx->mc_cmd,
		    data, NULL, req);
		/* mark it multi-part */
		privctx->mc_cmd |= CMD_HI_MULTI_PART;
	} else {
		/* Submit the job to the hardware */
		rv = mca_hash_update(mca, privctx->mc_shortparam[0],
		    privctx->mc_cmd, data, req);
	}

	/*
	 * If the op is terminated with a fatal error, free the context
	 */
	if (FATAL_RV(rv)) {
		(void) mca_freectx_kcf(ctx);
	}

	DBG(mca, DENTRY, "mca_digest_update: done, err = 0x%x", rv);

	return (rv);
}

static int
mca_digest_key(crypto_ctx_t *ctx, crypto_key_t *key, crypto_req_handle_t req)
{
	int	rv;

	DBG(NULL, DENTRY, "mca_digest_key: started");

	rv = mca_hash_key(ctx, key, req);

	/*
	 * If the op is terminated with a fatal error, free the context
	 */
	if (FATAL_RV(rv)) {
		(void) mca_freectx_kcf(ctx);
	}

	DBG(NULL, DENTRY, "mca_digest_key: done, err = 0x%x", rv);

	return (rv);
}


static int
mca_digest_final(crypto_ctx_t *ctx, crypto_data_t *digest,
    crypto_req_handle_t req)
{
	int			rv = CRYPTO_FAILED;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = ctx->cc_provider_private;

	DBG(mca, DENTRY, "mca_digest_final: started");

	if (privctx == NULL) {
		return (CRYPTO_OPERATION_NOT_INITIALIZED);
	}

	rv = mca_hash_final(mca, privctx->mc_shortparam[0],
	    privctx->mc_cmd, digest, req);

	/*
	 * If the op is terminated (successfully or with a fatal error),
	 * free the context
	 */
	if (!RETRY_RV(rv)) {
		(void) mca_freectx_kcf(ctx);
	}

	DBG(mca, DENTRY, "mca_digest_final: done, err = 0x%x", rv);

	return (rv);
}

static int
mca_digest(crypto_ctx_t *ctx, crypto_data_t *data, crypto_data_t *digest,
    crypto_req_handle_t req)
{
	int			rv;
	mca_privatectx_t	*privctx = ctx->cc_provider_private;
	uint32_t		cmd = privctx->mc_cmd;
	mca_t			*mca = privctx->mc_mca;

	DBG(MCA_CTX2MCA(ctx), DENTRY, "mca_digest -->");

	if (cmd & CMD_HI_MULTI_PART) {
		DBG(mca, DENTRY, "mca_digest: this context is for multi-part");
		return (CRYPTO_FAILED);
	}

	/*
	 * In-place operations (input == output) are indicated by having a
	 * NULL output. In this case set the output to point to the input.
	 */
	if (digest == NULL) {
		digest = data;
	}

	/*
	 * If the data is too long, it cannot be submitted
	 * as a single request: process it in multi-part
	 */
	if (data->cd_length > MAXPACKET) {
		rv = mca_hash_init(mca, privctx, cmd, data, digest, req);
		if (FATAL_RV(rv)) {
			(void) mca_freectx_kcf(ctx);
		}
		DBG(mca, DENTRY, "mca_digest: first update, err[0x%x]", rv);
		return (rv);
	}

	/* attach the mechanism specific context */
	rv = mca_hash(mca, cmd, data, digest, req);
	if ((rv != CRYPTO_QUEUED) && (rv != CRYPTO_SUCCESS) &&
	    (rv != CRYPTO_BUFFER_TOO_SMALL)) {
		mca_set_datalen(digest, 0);
	}
	/*
	 * If the op is terminated (successfully or with a fatal error),
	 * free the context.
	 */
	if ((rv != CRYPTO_QUEUED) && (rv != CRYPTO_BUFFER_TOO_SMALL)) {
		(void) mca_freectx_kcf(ctx);
	}

	DBG(MCA_CTX2MCA(ctx), DENTRY, "mca_digest <--[0x%x]", rv);

	return (rv);
}


/*
 * CIPHER OPERATIONS
 */
/*ARGSUSED3*/
static int
mca_encrypt_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t cfreq)
{
	int			rv;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = NULL;

	/* extract mca and instance number from context */
	DBG(mca, DENTRY, "mca_encrypt_init: started");

	/* check mechanism */
	switch (mechanism->cm_type) {
	case MCAM_DES_CBC:
		rv = mca_3desinit(ctx, mechanism, key, KM_SLEEP,
		    CMD_HI_SINGLE | CMD_3DESENC, &privctx);
		break;
	case MCAM_DES3_CBC:
		rv = mca_3desinit(ctx, mechanism, key, KM_SLEEP,
		    CMD_3DESENC, &privctx);
		break;
	case MCAM_DES_CBC_PAD:
		rv = mca_3desinit(ctx, mechanism, key, KM_SLEEP,
		    CMD_HI_PAD | CMD_HI_SINGLE | CMD_3DESENC, &privctx);
		break;
	case MCAM_DES3_CBC_PAD:
		rv = mca_3desinit(ctx, mechanism, key, KM_SLEEP,
		    CMD_HI_PAD | CMD_3DESENC, &privctx);
		break;
	case MCAM_AES_CBC:
		rv = mca_aesinit(ctx, mechanism, key, KM_SLEEP,
		    CMD_AESCBCENC, &privctx);
		break;
	case MCAM_AES_CTR:
#ifdef	DEBUG
	case MCAM_CPG_AES_CTR:
#endif
		rv = mca_aesinit(ctx, mechanism, key, KM_SLEEP,
		    CMD_AESCTRENC, &privctx);
		break;
	case MCAM_AES_CBC_PAD:
		rv = mca_aesinit(ctx, mechanism, key, KM_SLEEP,
		    CMD_HI_PAD | CMD_AESCBCENC, &privctx);
		break;
	case MCAM_RSA_X_509:
		rv = mca_rsainit(ctx, mechanism, key, KM_SLEEP,
		    CMD_RSAPUB, &privctx);
		break;
	case MCAM_RSA_PKCS:
		rv = mca_rsainit(ctx, mechanism, key, KM_SLEEP,
		    CMD_RSAPADENC, &privctx);
		break;
#ifdef FINSVCS
	case MCAM_FIN_SVCS:
		rv = mca_fs_init(ctx, mechanism, key, KM_SLEEP,
		    CMD_FIN_SVCS, &privctx);
		break;
#endif /* FINSVCS */
	default:
		cmn_err(CE_WARN, "mca_encrypt_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		rv = CRYPTO_MECHANISM_INVALID;
	}

	ctx->cc_provider_private = privctx;
	DBG(mca, DENTRY, "mca_encrypt_init: done, err = 0x%x", rv);

	return (rv);
}

static int
mca_encrypt(crypto_ctx_t *ctx, crypto_data_t *plain, crypto_data_t *cipher,
    crypto_req_handle_t cfreq)
{
	int			rv = CRYPTO_FAILED;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = ctx->cc_provider_private;

	DBG(mca, DENTRY, "mca_encrypt: started");

	if (privctx == NULL) {
		DBG(mca, DWARN, "mca_encrypt: privctx NULL\n");
		return (CRYPTO_FAILED);
	}

	/*
	 * In-place operations (input == output) are indicated by having a
	 * NULL output. In this case set the output to point to the input.
	 */
	if (cipher == NULL) {
		cipher = plain;
	}

	/* check mechanism */
	switch (privctx->mc_cmd & CMD_MASK) {
	case CMD_3DESENC:
		rv = mca_3des(ctx, plain, cipher, cfreq, privctx->mc_cmd);
		break;
	case CMD_AESCBCENC:
	case CMD_AESCTRENC:
		rv = mca_aes(ctx, plain, cipher, cfreq, privctx->mc_cmd);
		break;
	case CMD_RSAPUB:
		rv = mca_rsa(ctx, plain, cipher, cfreq, privctx->mc_cmd);
		break;
	case CMD_RSAPADENC:
		rv = mca_rsa(ctx, plain, cipher, cfreq, privctx->mc_cmd);
		break;
#ifdef FINSVCS
	case CMD_FIN_SVCS:
		rv = CRYPTO_NOT_SUPPORTED;
		break;
#endif /* FINSVCS */
	default:
		/* Should never reach here */
		cmn_err(CE_WARN, "mca_encrypt: unexpected cmd type "
		    "0x%x\n", privctx->mc_cmd);
	}

	/* If it is an fatal error, set the output length to 0 */
	if (FATAL_RV(rv)) {
		mca_set_datalen(cipher, 0);
	}
	/*
	 * If the op is terminated (successfully or with a fatal error),
	 * free the context.
	 */
	if (!RETRY_RV(rv)) {
		(void) mca_freectx_kcf(ctx);
	}

	DBG(mca, DENTRY, "mca_encrypt: done, err = 0x%x", rv);

	return (rv);
}

static int
mca_encrypt_update(crypto_ctx_t *ctx, crypto_data_t *plain,
    crypto_data_t *cipher, crypto_req_handle_t cfreq)
{
	int			rv = CRYPTO_FAILED;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = ctx->cc_provider_private;

	DBG(mca, DENTRY, "mca_encryptupdate: started");

	/*
	 * In-place operations (input == output) are indicated by having a
	 * NULL output. In this case set the output to point to the input.
	 */
	if (cipher == NULL) {
		cipher = plain;
	}

	/* check mechanism */
	switch (privctx->mc_cmd & CMD_MASK) {
	case CMD_3DESENC:
		rv = mca_3desupdate(ctx, plain, cipher, cfreq, privctx->mc_cmd);
		break;
	case CMD_AESCBCENC:
	case CMD_AESCTRENC:
		rv = mca_aesupdate(ctx, plain, cipher, cfreq, privctx->mc_cmd);
		break;
#ifdef FINSVCS
	case CMD_FIN_SVCS:
		rv = mca_fs_request(ctx, plain, cipher, cfreq);
		break;
#endif /* FINSVCS */
	default:
		/* Should never reach here */
		cmn_err(CE_WARN, "mca_encryptupdate: unexpected cmd type "
		    "0x%x\n", privctx->mc_cmd);
	}

	/*
	 * If the op is terminated with a fatal error, set the output length
	 * to zero and free the context
	 */
	if (FATAL_RV(rv)) {
		mca_set_datalen(cipher, 0);
		(void) mca_freectx_kcf(ctx);
	}

	DBG(mca, DENTRY, "mca_encryptupdate: done, err = 0x%x", rv);

	return (rv);
}

static int
mca_encrypt_final(crypto_ctx_t *ctx, crypto_data_t *cipher,
    crypto_req_handle_t cfreq)
{
	int			rv = CRYPTO_FAILED;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = ctx->cc_provider_private;

	DBG(mca, DENTRY, "mca_encryptfinal: started");

	/* check mechanism */
	switch (privctx->mc_cmd & CMD_MASK) {
	case CMD_3DESENC:
		rv = mca_3desfinal(ctx, cipher, cfreq, privctx->mc_cmd);
		break;
	case CMD_AESCBCENC:
	case CMD_AESCTRENC:
		rv = mca_aesfinal(ctx, cipher, cfreq, privctx->mc_cmd);
		break;
#ifdef FINSVCS
	case CMD_FIN_SVCS:
		rv = CRYPTO_SUCCESS;
		break;
#endif /* FINSVCS */
	default:
		/* Should never reach here */
		cmn_err(CE_WARN, "mca_encrypt_final: unexpected cmd type "
		    "0x%x\n", privctx->mc_cmd);
	}

	if (FATAL_RV(rv)) {
		mca_set_datalen(cipher, 0);
	}
	/*
	 * If the op is terminated (successfully or with a fatal error),
	 * free the context
	 */
	if (!RETRY_RV(rv)) {
		(void) mca_freectx_kcf(ctx);
	}

	DBG(mca, DENTRY, "mca_encryptfinal: done, err = 0x%x", rv);

	return (rv);
}


/*ARGSUSED6*/
static int
mca_encrypt_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *plain, crypto_data_t *cipher,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t cfreq)
{
	int		rv = CRYPTO_FAILED;
	mca_t		*mca = MCA_PROVIDER2MCA(provider);

	DBG(mca, DENTRY, "mca_encrypt_atomic: started");

	if (ctx_template != NULL) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/*
	 * In-place operations (input == output) are indicated by having a
	 * NULL output. In this case set the output to point to the input.
	 */
	if (cipher == NULL) {
		cipher = plain;
	}

	/* check mechanism */
	switch (mechanism->cm_type) {
	case MCAM_DES_CBC:
		rv = mca_3desatomic(mca, session_id, mechanism,
		    key, plain, cipher, cfreq, CMD_HI_SINGLE | CMD_3DESENC);
		break;
	case MCAM_DES3_CBC:
		rv = mca_3desatomic(mca, session_id, mechanism,
		    key, plain, cipher, cfreq, CMD_3DESENC);
		break;
	case MCAM_DES_CBC_PAD:
		rv = mca_3desatomic(mca, session_id, mechanism,
		    key, plain, cipher, cfreq,
		    CMD_HI_PAD | CMD_HI_SINGLE | CMD_3DESENC);
		break;
	case MCAM_DES3_CBC_PAD:
		rv = mca_3desatomic(mca, session_id, mechanism,
		    key, plain, cipher, cfreq, CMD_HI_PAD | CMD_3DESENC);
		break;
	case MCAM_AES_CBC:
		rv = mca_aesatomic(mca, session_id, mechanism,
		    key, plain, cipher, cfreq, CMD_AESCBCENC);
		break;
	case MCAM_AES_CTR:
#ifdef	DEBUG
	case MCAM_CPG_AES_CTR:
#endif
		rv = mca_aesatomic(mca, session_id, mechanism,
		    key, plain, cipher, cfreq, CMD_AESCTRENC);
		break;
	case MCAM_AES_CBC_PAD:
		rv = mca_aesatomic(mca, session_id, mechanism,
		    key, plain, cipher, cfreq, CMD_HI_PAD | CMD_AESCBCENC);
		break;
	case MCAM_RSA_X_509:
		rv = mca_rsaatomic(mca, session_id, key,
		    plain, cipher, cfreq, CMD_RSAPUB);
		break;
	case MCAM_RSA_PKCS:
		rv = mca_rsaatomic(mca, session_id, key,
		    plain, cipher, cfreq, CMD_RSAPADENC);
		break;
	default:
		cmn_err(CE_WARN, "mca_encrypt_atomic: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		rv = CRYPTO_MECHANISM_INVALID;
	}

	if (FATAL_RV(rv)) {
		mca_set_datalen(cipher, 0);
	}

	DBG(mca, DENTRY, "mca_encrypt_atomic: done, err = 0x%x", rv);

	return (rv);
}

/*ARGSUSED3*/
static int
mca_decrypt_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t cfreq)
{
	int			rv;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = NULL;

	DBG(mca, DENTRY, "mca_decrypt_init: started");

	/* check mechanism */
	switch (mechanism->cm_type) {
	case MCAM_DES_CBC:
		rv = mca_3desinit(ctx, mechanism, key, KM_SLEEP,
		    CMD_HI_SINGLE | CMD_3DESDEC, &privctx);
		break;
	case MCAM_DES3_CBC:
		rv = mca_3desinit(ctx, mechanism, key, KM_SLEEP,
		    CMD_3DESDEC, &privctx);
		break;
	case MCAM_DES_CBC_PAD:
		rv = mca_3desinit(ctx, mechanism, key, KM_SLEEP,
		    CMD_HI_PAD | CMD_HI_SINGLE | CMD_3DESDEC, &privctx);
		break;
	case MCAM_DES3_CBC_PAD:
		rv = mca_3desinit(ctx, mechanism, key, KM_SLEEP,
		    CMD_HI_PAD | CMD_3DESDEC, &privctx);
		break;
	case MCAM_AES_CBC:
		rv = mca_aesinit(ctx, mechanism, key, KM_SLEEP,
		    CMD_AESCBCDEC, &privctx);
		break;
	case MCAM_AES_CTR:
#ifdef	DEBUG
	case MCAM_CPG_AES_CTR:
#endif
		rv = mca_aesinit(ctx, mechanism, key, KM_SLEEP,
		    CMD_AESCTRDEC, &privctx);
		break;
	case MCAM_AES_CBC_PAD:
		rv = mca_aesinit(ctx, mechanism, key, KM_SLEEP,
		    CMD_HI_PAD | CMD_AESCBCDEC, &privctx);
		break;
	case MCAM_RSA_X_509:
		rv = mca_rsainit(ctx, mechanism, key, KM_SLEEP,
		    CMD_RSAPRV, &privctx);
		break;
	case MCAM_RSA_PKCS:
		rv = mca_rsainit(ctx, mechanism, key, KM_SLEEP,
		    CMD_RSAPADDEC, &privctx);
		break;
	default:
		cmn_err(CE_WARN, "mca_decrypt_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		rv = CRYPTO_MECHANISM_INVALID;
	}

	ctx->cc_provider_private = privctx;
	DBG(mca, DENTRY, "mca_decrypt_init: done, err = 0x%x", rv);

	return (rv);
}

static int
mca_decrypt(crypto_ctx_t *ctx, crypto_data_t *cipher,
    crypto_data_t *plain, crypto_req_handle_t cfreq)
{
	int			rv = CRYPTO_FAILED;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = ctx->cc_provider_private;

	DBG(mca, DENTRY, "mca_decrypt: started");

	/*
	 * In-place operations (input == output) are indicated by having a
	 * NULL output. In this case set the output to point to the input.
	 */
	if (plain == NULL) {
		plain = cipher;
	}

	/* check mechanism */
	switch (privctx->mc_cmd & CMD_MASK) {
	case CMD_3DESDEC:
		rv = mca_3des(ctx, cipher, plain, cfreq, privctx->mc_cmd);
		break;
	case CMD_AESCBCDEC:
	case CMD_AESCTRDEC:
		rv = mca_aes(ctx, cipher, plain, cfreq, privctx->mc_cmd);
		break;
	case CMD_RSAPRV:
		rv = mca_rsa(ctx, cipher, plain, cfreq, privctx->mc_cmd);
		break;
	case CMD_RSAPADDEC:
		rv = mca_rsa(ctx, cipher, plain, cfreq, privctx->mc_cmd);
		break;
	default:
		/* Should never reach here */
		cmn_err(CE_WARN, "mca_decrypt: unexpected cmd type "
		    "0x%x\n", privctx->mc_cmd);
	}

	if (FATAL_RV(rv)) {
		mca_set_datalen(plain, 0);
	}
	/*
	 * If the op is terminated (successfully or with a fatal error),
	 * free the context
	 */
	if (!RETRY_RV(rv)) {
		(void) mca_freectx_kcf(ctx);
	}

	DBG(mca, DENTRY, "mca_decrypt: done, err = 0x%x", rv);

	return (rv);
}

static int
mca_decrypt_update(crypto_ctx_t *ctx, crypto_data_t *cipher,
    crypto_data_t *plain, crypto_req_handle_t cfreq)
{
	int			rv = CRYPTO_FAILED;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = ctx->cc_provider_private;

	DBG(mca, DENTRY, "mca_decryptupdate: started");

	/*
	 * In-place operations (input == output) are indicated by having a
	 * NULL output. In this case set the output to point to the input.
	 */
	if (plain == NULL) {
		plain = cipher;
	}

	/* check mechanism */
	switch (privctx->mc_cmd & CMD_MASK) {
	case CMD_3DESDEC:
		rv = mca_3desupdate(ctx, cipher, plain, cfreq, privctx->mc_cmd);
		break;
	case CMD_AESCBCDEC:
	case CMD_AESCTRDEC:
		rv = mca_aesupdate(ctx, cipher, plain, cfreq, privctx->mc_cmd);
		break;
	default:
		/* Should never reach here */
		cmn_err(CE_WARN, "mca_decrypt_update: unexpected cmd type "
		    "0x%x\n", privctx->mc_cmd);
	}

	/*
	 * If the op is terminated with a fatal error, set the output length
	 * to zero and free the context
	 */
	if (FATAL_RV(rv)) {
		mca_set_datalen(plain, 0);
		(void) mca_freectx_kcf(ctx);
	}

	DBG(mca, DENTRY, "mca_decryptupdate: done, err = 0x%x", rv);

	return (rv);
}

/*ARGSUSED*/
static int
mca_decrypt_final(crypto_ctx_t *ctx, crypto_data_t *plain,
    crypto_req_handle_t cfreq)
{
	int			rv = CRYPTO_FAILED;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = ctx->cc_provider_private;

	DBG(mca, DENTRY, "mca_decryptfinal: started");

	/* check mechanism */
	switch (privctx->mc_cmd & CMD_MASK) {
	case CMD_3DESDEC:
		rv = mca_3desfinal(ctx, plain, cfreq, privctx->mc_cmd);
		break;
	case CMD_AESCBCDEC:
	case CMD_AESCTRDEC:
		rv = mca_aesfinal(ctx, plain, cfreq, privctx->mc_cmd);
		break;
	default:
		/* Should never reach here */
		cmn_err(CE_WARN, "mca_decrypt_final: unexpected cmd type "
		    "0x%x\n", privctx->mc_cmd);
	}

	if (FATAL_RV(rv)) {
		mca_set_datalen(plain, 0);
	}
	/*
	 * If the op is terminated (successfully or with a fatal error),
	 * free the context
	 */
	if (!RETRY_RV(rv)) {
		(void) mca_freectx_kcf(ctx);
	}

	DBG(mca, DENTRY, "mca_decryptfinal: done, err = 0x%x", rv);

	return (rv);
}


/*ARGSUSED6*/
static int
mca_decrypt_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *cipher, crypto_data_t *plain,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t cfreq)
{
	int		rv = CRYPTO_FAILED;
	mca_t		*mca = MCA_PROVIDER2MCA(provider);

	DBG(mca, DENTRY, "mca_decrypt_atomic: started");

	if (ctx_template != NULL) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/*
	 * In-place operations (input == output) are indicated by having a
	 * NULL output. In this case set the output to point to the input.
	 */
	if (plain == NULL) {
		plain = cipher;
	}

	/* check mechanism */
	switch (mechanism->cm_type) {
	case MCAM_DES_CBC:
		rv = mca_3desatomic(mca, session_id, mechanism,
		    key, cipher, plain, cfreq, CMD_HI_SINGLE | CMD_3DESDEC);
		break;
	case MCAM_DES3_CBC:
		rv = mca_3desatomic(mca, session_id, mechanism,
		    key, cipher, plain, cfreq, CMD_3DESDEC);
		break;
	case MCAM_DES_CBC_PAD:
		rv = mca_3desatomic(mca, session_id, mechanism,
		    key, cipher, plain, cfreq,
		    CMD_HI_PAD | CMD_HI_SINGLE | CMD_3DESDEC);
		break;
	case MCAM_DES3_CBC_PAD:
		rv = mca_3desatomic(mca, session_id, mechanism,
		    key, cipher, plain, cfreq, CMD_HI_PAD | CMD_3DESDEC);
		break;
	case MCAM_AES_CBC:
		rv = mca_aesatomic(mca, session_id, mechanism,
		    key, cipher, plain, cfreq, CMD_AESCBCDEC);
		break;
	case MCAM_AES_CTR:
#ifdef	DEBUG
	case MCAM_CPG_AES_CTR:
#endif
		rv = mca_aesatomic(mca, session_id, mechanism,
		    key, cipher, plain, cfreq, CMD_AESCTRDEC);
		break;
	case MCAM_AES_CBC_PAD:
		rv = mca_aesatomic(mca, session_id, mechanism,
		    key, cipher, plain, cfreq, CMD_HI_PAD | CMD_AESCBCDEC);
		break;
	case MCAM_RSA_X_509:
		rv = mca_rsaatomic(mca, session_id, key,
		    cipher, plain, cfreq, CMD_RSAPRV);
		break;
	case MCAM_RSA_PKCS:
		rv = mca_rsaatomic(mca, session_id, key,
		    cipher, plain, cfreq, CMD_RSAPADDEC);
		break;
	default:
		cmn_err(CE_WARN, "mca_decrypt_atomic: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		rv = CRYPTO_MECHANISM_INVALID;
	}

	if (FATAL_RV(rv)) {
		mca_set_datalen(plain, 0);
	}

	DBG(mca, DENTRY, "mca_decrypt_atomic: done, err = 0x%x", rv);

	return (rv);
}

/*
 * SIGN OPERATIONS
 */
/*ARGSUSED6*/
static int
mca_sign_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *signature,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t cfreq)
{
	int		rv = CRYPTO_FAILED;
	mca_t		*mca = MCA_PROVIDER2MCA(provider);

	DBG(mca, DENTRY, "mca_sign_atomic: started\n");

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/*
	 * In-place operations (input == output) are indicated by having a
	 * NULL output. In this case set the output to point to the input.
	 */
	if (signature == NULL) {
		signature = data;
	}

	/* check mechanism */
	switch (mechanism->cm_type) {
	case MCAM_RSA_X_509:
		rv = mca_rsaatomic(mca, session_id, key,
		    data, signature, cfreq, CMD_HI_SIGN | CMD_RSAPRV);
		break;
	case MCAM_RSA_PKCS:
		rv = mca_rsaatomic(mca, session_id, key,
		    data, signature, cfreq, CMD_HI_SIGN | CMD_RSAPADSIGN);
		break;
	case MCAM_DSA:
		rv = mca_dsaatomic(mca, session_id, key,
		    data, signature, cfreq, CMD_DSASIGN);
		break;
	case MCAM_ECDSA:
		rv = mca_ecdsaatomic(mca, session_id, key,
		    data, signature, cfreq, CMD_ECDSASIGN);
		break;
	default:
		cmn_err(CE_WARN, "mca_sign_atomic: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		rv = CRYPTO_MECHANISM_INVALID;
	}

	if (FATAL_RV(rv)) {
		mca_set_datalen(signature, 0);
	}

	DBG(mca, DENTRY, "mca_sign_atomic: done, err = 0x%x", rv);

	return (rv);
}

/*ARGSUSED*/
static int
mca_sign_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t cfreq)
{
	int			rv;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = NULL;

	DBG(mca, DENTRY, "mca_sign_init: started\n");

	if (ctx_template != NULL) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/* check mechanism */
	switch (mechanism->cm_type) {
	case MCAM_RSA_X_509:
		rv = mca_rsainit(ctx, mechanism, key, KM_SLEEP,
		    CMD_HI_SIGN | CMD_RSAPRV, &privctx);
		break;
	case MCAM_RSA_PKCS:
		rv = mca_rsainit(ctx, mechanism, key, KM_SLEEP,
		    CMD_HI_SIGN | CMD_RSAPADSIGN, &privctx);
		break;
	case MCAM_DSA:
		rv = mca_dsainit(ctx, mechanism, key, KM_SLEEP,
		    CMD_DSASIGN, &privctx);
		break;
	case MCAM_ECDSA:
		rv = mca_ecdsainit(ctx, mechanism, key, KM_SLEEP,
		    CMD_ECDSASIGN, &privctx);
		break;
	default:
		cmn_err(CE_WARN, "mca_sign_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		rv = CRYPTO_MECHANISM_INVALID;
	}

	ctx->cc_provider_private = privctx;

	DBG(mca, DENTRY, "mca_sign_init: done, rv = 0x%x", rv);

	return (rv);
}

static int
mca_sign(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_data_t *signature, crypto_req_handle_t cfreq)
{
	int			rv = CRYPTO_FAILED;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = ctx->cc_provider_private;

	DBG(mca, DENTRY, "mca_sign: started\n");

	/*
	 * In-place operations (input == output) are indicated by having a
	 * NULL output. In this case set the output to point to the input.
	 */
	if (signature == NULL) {
		signature = data;
	}

	/* check mechanism */
	switch (privctx->mc_cmd & CMD_MASK) {
	case CMD_RSAPRV:
	case CMD_RSAPADSIGN:
		rv = mca_rsa(ctx, data, signature, cfreq, privctx->mc_cmd);
		break;
	case CMD_DSASIGN:
		rv = mca_dsa(ctx, data, signature, cfreq, privctx->mc_cmd);
		break;
	case CMD_ECDSASIGN:
		rv = mca_ecdsa(ctx, data, signature, cfreq, privctx->mc_cmd);
		break;
	default:
		cmn_err(CE_WARN, "mca_sign: unexpected cmd type "
		    "0x%x\n", privctx->mc_cmd);
	}

	if (FATAL_RV(rv)) {
		mca_set_datalen(signature, 0);
	}
	/*
	 * If the op is terminated (successfully or with a fatal error),
	 * free the context
	 */
	if (!RETRY_RV(rv)) {
		(void) mca_freectx_kcf(ctx);
	}

	DBG(mca, DENTRY, "mca_sign: done, err = 0x%x", rv);

	return (rv);
}

/*ARGSUSED6*/
static int
mca_signrecover_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *signature,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t cfreq)
{
	int		rv = CRYPTO_FAILED;
	mca_t		*mca = MCA_PROVIDER2MCA(provider);

	DBG(mca, DENTRY, "mca_signrecover_atomic: started\n");

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/*
	 * In-place operations (input == output) are indicated by having a
	 * NULL output. In this case set the output to point to the input.
	 */
	if (signature == NULL) {
		signature = data;
	}

	/* check mechanism */
	switch (mechanism->cm_type) {
	case MCAM_RSA_X_509:
		rv = mca_rsaatomic(mca, session_id, key,
		    data, signature, cfreq, CMD_HI_SIGNR | CMD_RSAPRV);
		break;
	case MCAM_RSA_PKCS:
		rv = mca_rsaatomic(mca, session_id, key,
		    data, signature, cfreq, CMD_HI_SIGNR | CMD_RSAPADSIGN);
		break;
	default:
		cmn_err(CE_WARN, "mca_signrecover_atomic: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		rv = CRYPTO_MECHANISM_INVALID;
	}

	if (FATAL_RV(rv)) {
		mca_set_datalen(signature, 0);
	}

	DBG(mca, DENTRY, "mca_signrecover_atomic: done, err = 0x%x", rv);

	return (rv);
}

/*ARGSUSED*/
static int
mca_signrecover_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t cfreq)
{
	int			rv;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = NULL;

	DBG(mca, DENTRY, "mca_signrecover_init: started\n");

	if (ctx_template != NULL) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/* check mechanism */
	switch (mechanism->cm_type) {
	case MCAM_RSA_X_509:
		rv = mca_rsainit(ctx, mechanism, key, KM_SLEEP,
		    CMD_HI_SIGNR | CMD_RSAPRV, &privctx);
		break;
	case MCAM_RSA_PKCS:
		rv = mca_rsainit(ctx, mechanism, key, KM_SLEEP,
		    CMD_HI_SIGNR | CMD_RSAPADSIGN, &privctx);
		break;
	default:
		cmn_err(CE_WARN, "mca_signrecover_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		rv = CRYPTO_MECHANISM_INVALID;
	}

	ctx->cc_provider_private = privctx;

	DBG(mca, DENTRY, "mca_signrecover_init: done, rv = 0x%x", rv);

	return (rv);
}

static int
mca_signrecover(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_data_t *signature, crypto_req_handle_t cfreq)
{
	int			rv;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = ctx->cc_provider_private;

	DBG(mca, DENTRY, "mca_signrecover: started\n");

	/*
	 * In-place operations (input == output) are indicated by having a
	 * NULL output. In this case set the output to point to the input.
	 */
	if (signature == NULL) {
		signature = data;
	}

	/* check mechanism */
	switch (privctx->mc_cmd & CMD_MASK) {
	case CMD_RSAPRV:
	case CMD_RSAPADSIGN:
		rv = mca_rsa(ctx, data, signature, cfreq, privctx->mc_cmd);
		break;
	default:
		cmn_err(CE_WARN, "mca_signrecover: unexpected cmd type "
		    "0x%x\n", privctx->mc_cmd);
		rv = CRYPTO_MECHANISM_INVALID;
	}

	if (FATAL_RV(rv)) {
		mca_set_datalen(signature, 0);
	}
	/*
	 * If the op is terminated (successfully or with a fatal error),
	 * free the context
	 */
	if (!RETRY_RV(rv)) {
		(void) mca_freectx_kcf(ctx);
	}

	DBG(mca, DENTRY, "mca_signrecover: done, err = 0x%x", rv);

	return (rv);
}


/*
 * VERIFY OPERATIONS
 */

/*ARGSUSED6*/
static int
mca_verify_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *signature,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t cfreq)
{
	int		rv = CRYPTO_FAILED;
	mca_t		*mca = MCA_PROVIDER2MCA(provider);

	DBG(mca, DENTRY, "mca_verify_atomic: started\n");

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* check mechanism */
	switch (mechanism->cm_type) {
	case MCAM_RSA_X_509:
		rv = mca_rsaatomic(mca, session_id, key,
		    data, signature, cfreq, CMD_HI_VRFY | CMD_RSAPUB);
		break;
	case MCAM_RSA_PKCS:
		rv = mca_rsaatomic(mca, session_id, key,
		    data, signature, cfreq, CMD_HI_VRFY | CMD_RSAPADVRFY);
		break;
	case MCAM_DSA:
		rv = mca_dsaatomic(mca, session_id, key,
		    data, signature, cfreq, CMD_DSAVERIFY);
		break;
	case MCAM_ECDSA:
		rv = mca_ecdsaatomic(mca, session_id, key,
		    data, signature, cfreq, CMD_ECDSAVERIFY);
		break;
	default:
		cmn_err(CE_WARN, "mca_verify_atomic: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		rv = CRYPTO_MECHANISM_INVALID;
	}

	DBG(mca, DENTRY, "mca_verify_atomic: done, err = 0x%x", rv);

	return (rv);
}

/*ARGSUSED*/
static int
mca_verify_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t cfreq)
{
	int			rv;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = NULL;

	DBG(mca, DENTRY, "mca_verify_init: started\n");

	if (ctx_template != NULL) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/* check mechanism */
	switch (mechanism->cm_type) {
	case MCAM_RSA_X_509:
		rv = mca_rsainit(ctx, mechanism, key, KM_SLEEP,
		    CMD_HI_VRFY | CMD_RSAPUB, &privctx);
		break;
	case MCAM_RSA_PKCS:
		rv = mca_rsainit(ctx, mechanism, key, KM_SLEEP,
		    CMD_HI_VRFY | CMD_RSAPADVRFY, &privctx);
		break;
	case MCAM_DSA:
		rv = mca_dsainit(ctx, mechanism, key, KM_SLEEP,
		    CMD_DSAVERIFY, &privctx);
		break;
	case MCAM_ECDSA:
		rv = mca_ecdsainit(ctx, mechanism, key, KM_SLEEP,
		    CMD_ECDSAVERIFY, &privctx);
		break;
	default:
		cmn_err(CE_WARN, "mca_verify_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		rv = CRYPTO_MECHANISM_INVALID;
	}

	ctx->cc_provider_private = privctx;

	DBG(mca, DENTRY, "mca_verify_init: done, rv = 0x%x", rv);

	return (rv);
}

static int
mca_verify(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_data_t *signature, crypto_req_handle_t cfreq)
{
	int			rv = CRYPTO_FAILED;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = ctx->cc_provider_private;

	DBG(mca, DENTRY, "mca_verify: started\n");

	/* check mechanism */
	switch (privctx->mc_cmd & CMD_MASK) {
	case CMD_RSAPUB:
	case CMD_RSAPADVRFY:
		rv = mca_rsa(ctx, signature, data,
		    cfreq, privctx->mc_cmd);
		break;
	case CMD_DSAVERIFY:
		rv = mca_dsa(ctx, data, signature,
		    cfreq, privctx->mc_cmd);
		break;
	case CMD_ECDSAVERIFY:
		rv = mca_ecdsa(ctx, data, signature,
		    cfreq, privctx->mc_cmd);
		break;
	default:
		cmn_err(CE_WARN, "mca_verify: unexpected cmd type "
		    "0x%x\n", privctx->mc_cmd);
	}
	/*
	 * If the op is terminated (successfully or with a fatal error),
	 * free the context
	 */
	if (!RETRY_RV(rv)) {
		(void) mca_freectx_kcf(ctx);
	}

	DBG(mca, DENTRY, "mca_verify: done, err = 0x%x", rv);

	return (rv);
}



/*ARGSUSED6*/
static int
mca_verifyrecover_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *signature,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t cfreq)
{
	int		rv = CRYPTO_FAILED;
	mca_t		*mca = MCA_PROVIDER2MCA(provider);

	DBG(mca, DENTRY, "mca_verifyrecover_atomic: started\n");

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/*
	 * In-place operations (input == output) are indicated by having a
	 * NULL output. In this case set the output to point to the input.
	 */
	if (data == NULL) {
		data = signature;
	}

	/* check mechanism */
	switch (mechanism->cm_type) {
	case MCAM_RSA_X_509:
		rv = mca_rsaatomic(mca, session_id, key,
		    signature, data, cfreq, CMD_HI_VRFYR | CMD_RSAPUB);
		break;
	case MCAM_RSA_PKCS:
		rv = mca_rsaatomic(mca, session_id, key,
		    signature, data, cfreq, CMD_HI_VRFYR | CMD_RSAPADVRFY);
		break;
	default:
		cmn_err(CE_WARN, "mca_verifyrecover_atomic: unexpected mech "
		    "type 0x%llx\n", (unsigned long long)mechanism->cm_type);
		rv = CRYPTO_MECHANISM_INVALID;
	}

	if (FATAL_RV(rv)) {
		mca_set_datalen(data, 0);
	}

	DBG(mca, DENTRY, "mca_verifyrecover_atomic: done, err = 0x%x", rv);

	return (rv);
}

/*ARGSUSED*/
static int
mca_verifyrecover_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t cfreq)
{
	int			rv;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = NULL;

	DBG(mca, DENTRY, "mca_verifyrecover_init: started\n");

	if (ctx_template != NULL) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/* check mechanism */
	switch (mechanism->cm_type) {
	case MCAM_RSA_X_509:
		rv = mca_rsainit(ctx, mechanism, key, KM_SLEEP,
		    CMD_HI_VRFYR | CMD_RSAPUB, &privctx);
		break;
	case MCAM_RSA_PKCS:
		rv = mca_rsainit(ctx, mechanism, key, KM_SLEEP,
		    CMD_HI_VRFYR | CMD_RSAPADVRFY, &privctx);
		break;
	default:
		cmn_err(CE_WARN, "mca_verifyrecover_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		rv = CRYPTO_MECHANISM_INVALID;
	}

	ctx->cc_provider_private = privctx;

	DBG(mca, DENTRY, "mca_verifyrecover_init: done, rv = 0x%x", rv);

	return (rv);
}

static int
mca_verifyrecover(crypto_ctx_t *ctx, crypto_data_t *signature,
    crypto_data_t *data, crypto_req_handle_t cfreq)
{
	int			rv = CRYPTO_FAILED;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = ctx->cc_provider_private;

	DBG(mca, DENTRY, "mca_verifyrecover: started\n");

	/*
	 * In-place operations (input == output) are indicated by having a
	 * NULL output. In this case set the output to point to the input.
	 */
	if (data == NULL) {
		data = signature;
	}

	/* check mechanism */
	switch (privctx->mc_cmd & CMD_MASK) {
	case CMD_RSAPUB:
	case CMD_RSAPADVRFY:
		rv = mca_rsa(ctx, signature, data, cfreq, privctx->mc_cmd);
		break;
	default:
		cmn_err(CE_WARN, "mca_verifyrecover: unexpected cmd type "
		    "0x%x\n", privctx->mc_cmd);
	}

	if (FATAL_RV(rv)) {
		mca_set_datalen(data, 0);
	}
	/*
	 * If the op is terminated (successfully or with a fatal error),
	 * free the context
	 */
	if (!RETRY_RV(rv)) {
		(void) mca_freectx_kcf(ctx);
	}

	DBG(mca, DENTRY, "mca_verifyrecover: done, err = 0x%x", rv);

	return (rv);
}


/*
 * HMACOPERATIONS
 */
/*ARGSUSED6*/
static int
mca_cb_sign_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *signature,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t cfreq)
{
	int		rv;
	mca_t		*mca = MCA_PROVIDER2MCA(provider);
	uint32_t	cmd;

	DBG(mca, DENTRY, "mca_cb_sign_atomic -->");

	switch (mechanism->cm_type) {
	case MCAM_MD5_HMAC:
	case MCAM_MD5_HMAC_GENERAL:
		if (mca_isfips(mca)) {
			return (CRYPTO_MECHANISM_INVALID);
		}
		cmd = CMD_HI_ATOMIC | CMD_HI_SIGN | CMD_HMAC_MD5;
		break;
	case MCAM_SHA_1_HMAC:
	case MCAM_SHA_1_HMAC_GENERAL:
		cmd = CMD_HI_ATOMIC | CMD_HI_SIGN | CMD_HMAC_SHA1;
		break;
	case MCAM_SHA512_HMAC:
	case MCAM_SHA512_HMAC_GENERAL:
		cmd = CMD_HI_ATOMIC | CMD_HI_SIGN | CMD_HMAC_SHA512;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	/*
	 * In-place operations (input == output) are indicated by having a
	 * NULL output. In this case set the output to point to the input.
	 */
	if (signature == NULL) {
		signature = data;
	}

	/*
	 * If the data is too large, it cannot be submitted
	 * as a single request: process it in multi-part
	 */
	if (data->cd_length > MAXPACKET) {
		mca_privatectx_t	*privctx = NULL;
		rv = mca_hmac_allocctx(mca, session_id, mechanism,
		    key, &privctx);
		if (rv != CRYPTO_SUCCESS) {
			goto done;
		}
		privctx->mc_cmd |= CMD_HI_ATOMIC | CMD_HI_SIGN;
		rv = mca_hmac_init(mca, privctx, cmd, data, signature, cfreq);
		if (rv != CRYPTO_QUEUED) {
			mca_freectx(privctx);
		}
	} else {
		rv = mca_hmac_atomic(mca, session_id, mechanism, key,
		    data, signature, cfreq, cmd);
	}

done:

	if ((rv != CRYPTO_QUEUED) && (rv != CRYPTO_SUCCESS) &&
	    (rv != CRYPTO_BUFFER_TOO_SMALL)) {
		mca_set_datalen(signature, 0);
	}
	DBG(mca, DENTRY, "mca_cb_sign_atomic <--[0x%x]", rv);

	return (rv);
}

/*ARGSUSED*/
static int
mca_cb_sign_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t cfreq)
{
	int			rv;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = NULL;

	DBG(mca, DENTRY, "mca_cb_sign_init: started\n");

	if (ctx_template != NULL) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/* check mechanism */
	switch (mechanism->cm_type) {
	case MCAM_MD5_HMAC:
	case MCAM_MD5_HMAC_GENERAL:
		if (mca_isfips(mca)) {
			return (CRYPTO_MECHANISM_INVALID);
		}
		/*FALLTHROUGH*/
	case MCAM_SHA_1_HMAC:
	case MCAM_SHA_1_HMAC_GENERAL:
	case MCAM_SHA512_HMAC:
	case MCAM_SHA512_HMAC_GENERAL:
		rv = mca_hmac_allocctx(mca, ctx->cc_session, mechanism,
		    key, &privctx);
		break;
	default:
		cmn_err(CE_WARN, "mca_cb_sign_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		rv = CRYPTO_MECHANISM_INVALID;
	}

	if (rv == CRYPTO_SUCCESS) {
		ctx->cc_provider_private = privctx;
		privctx->mc_cmd |= CMD_HI_SIGN;
	}

	DBG(mca, DENTRY, "mca_cb_sign_init: done, rv = 0x%x", rv);

	return (rv);
}

static int
mca_cb_sign(crypto_ctx_t *ctx, crypto_data_t *data, crypto_data_t *signature,
    crypto_req_handle_t cfreq)
{
	int			rv = CRYPTO_FAILED;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = ctx->cc_provider_private;

	DBG(mca, DENTRY, "mca_cb_sign: started\n");

	/*
	 * In-place operations (input == output) are indicated by having a
	 * NULL output. In this case set the output to point to the input.
	 */
	if (signature == NULL) {
		signature = data;
	}

	/* check mechanism */
	switch (privctx->mc_cmd & CMD_MASK) {
	case CMD_HMAC_MD5:
		if (mca_isfips(mca)) {
			return (CRYPTO_MECHANISM_INVALID);
		}
		/*FALLTHROUGH*/
	case CMD_HMAC_SHA1:
	case CMD_HMAC_SHA512:
		if (data->cd_length > MAXPACKET) {
			privctx->mc_cmd |= CMD_HI_SIGN;
			rv = mca_hmac_init(mca, privctx, privctx->mc_cmd,
			    data, signature, cfreq);
		} else {
			rv = mca_hmac(privctx, data, signature, cfreq,
			    privctx->mc_cmd);
		}
		break;
	default:
		cmn_err(CE_WARN, "mca_cb_sign: unexpected cmd type "
		    "0x%x\n", privctx->mc_cmd);
	}

	if (FATAL_RV(rv)) {
		mca_set_datalen(signature, 0);
	}
	/*
	 * If the op is terminated (successfully or with a fatal error),
	 * free the context
	 */
	if (!RETRY_RV(rv)) {
		(void) mca_freectx_kcf(ctx);
	}

	DBG(mca, DENTRY, "mca_cb_sign: done, err = 0x%x", rv);

	return (rv);
}


static int
mca_cb_sign_update(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	int			rv = CRYPTO_FAILED;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = ctx->cc_provider_private;

	DBG(mca, DENTRY, "mca_cb_sign_update: started");

	/*
	 * If 'MULTI_PART' flag is not turned on, this is the first
	 * mca_cb_sign_update call: need to get a context ID from the hardware.
	 * Processing of the data is handled by the callback function
	 * of mca_hash_init.
	 */
	if (!(privctx->mc_cmd & CMD_HI_MULTI_PART)) {
		rv = mca_hmac_init(mca, privctx, privctx->mc_cmd,
		    data, NULL, req);
		/* mark it multi-part */
		privctx->mc_cmd |= CMD_HI_MULTI_PART;
	} else {
		/* Submit the job to the hardware */
		rv = mca_hmac_update(mca, privctx->mc_shortparam[0],
		    privctx->mc_cmd, data, req);
	}

	/*
	 * If the op is terminated with a fatal error, free the context
	 */
	if (FATAL_RV(rv)) {
		(void) mca_freectx_kcf(ctx);
	}

	DBG(mca, DENTRY, "mca_cb_sign_update: done, err = 0x%x", rv);

	return (rv);
}

static int
mca_cb_sign_final(crypto_ctx_t *ctx, crypto_data_t *signature,
    crypto_req_handle_t req)
{
	int			rv = CRYPTO_FAILED;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = ctx->cc_provider_private;

	DBG(mca, DENTRY, "mca_cb_sign_final: started");

	if (privctx == NULL) {
		return (CRYPTO_OPERATION_NOT_INITIALIZED);
	}

	rv = mca_hmac_final(mca, privctx, signature, req);

	/*
	 * If the op is terminated (successfully or with a fatal error),
	 * free the context
	 */
	if (!RETRY_RV(rv)) {
		(void) mca_freectx_kcf(ctx);
	}

	DBG(mca, DENTRY, "mca_cb_sign_final: done, err = 0x%x", rv);

	return (rv);
}

/*ARGSUSED6*/
static int
mca_cb_verify_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *signature,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t cfreq)
{
	int		rv;
	mca_t		*mca = MCA_PROVIDER2MCA(provider);
	uint32_t	cmd;

	DBG(mca, DENTRY, "mca_cb_verify_atomic -->");

	switch (mechanism->cm_type) {
	case MCAM_MD5_HMAC:
	case MCAM_MD5_HMAC_GENERAL:
		if (mca_isfips(mca)) {
			return (CRYPTO_MECHANISM_INVALID);
		}
		cmd = CMD_HMAC_MD5 | CMD_HI_VRFY | CMD_HI_ATOMIC;
		break;
	case MCAM_SHA_1_HMAC:
	case MCAM_SHA_1_HMAC_GENERAL:
		cmd = CMD_HMAC_SHA1 | CMD_HI_VRFY | CMD_HI_ATOMIC;
		break;
	case MCAM_SHA512_HMAC:
	case MCAM_SHA512_HMAC_GENERAL:
		cmd = CMD_HMAC_SHA512 | CMD_HI_VRFY | CMD_HI_ATOMIC;
		break;
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	/*
	 * In-place operations (input == output) are indicated by having a
	 * NULL output. In this case set the output to point to the input.
	 */
	if (signature == NULL) {
		signature = data;
	}

	/*
	 * If the data is too large, it cannot be submitted
	 * as a single request: process it in multi-part
	 */
	if (data->cd_length > MAXPACKET) {
		mca_privatectx_t	*privctx = NULL;
		rv = mca_hmac_allocctx(mca, session_id, mechanism,
		    key, &privctx);
		if (rv != CRYPTO_SUCCESS) {
			goto done;
		}
		privctx->mc_cmd |= CMD_HI_ATOMIC | CMD_HI_VRFY;
		rv = mca_hmac_init(mca, privctx, cmd, data, signature, cfreq);
		if (rv != CRYPTO_QUEUED) {
			mca_freectx(privctx);
		}
	} else {
		rv = mca_hmac_atomic(mca, session_id, mechanism, key,
		    data, signature, cfreq, cmd);
	}

done:

	if ((rv != CRYPTO_QUEUED) && (rv != CRYPTO_SUCCESS) &&
	    (rv != CRYPTO_BUFFER_TOO_SMALL)) {
		mca_set_datalen(signature, 0);
	}
	DBG(mca, DENTRY, "mca_cb_verify_atomic <--[0x%x]", rv);

	return (rv);
}


/*ARGSUSED*/
static int
mca_cb_verify_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t cfreq)
{
	int			rv;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = NULL;

	DBG(mca, DENTRY, "mca_cb_verify_init: started\n");

	if (ctx_template != NULL) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/* check mechanism */
	switch (mechanism->cm_type) {
	case MCAM_MD5_HMAC:
	case MCAM_MD5_HMAC_GENERAL:
		if (mca_isfips(mca)) {
			return (CRYPTO_MECHANISM_INVALID);
		}
		/*FALLTHROUGH*/
	case MCAM_SHA_1_HMAC:
	case MCAM_SHA_1_HMAC_GENERAL:
	case MCAM_SHA512_HMAC:
	case MCAM_SHA512_HMAC_GENERAL:
		rv = mca_hmac_allocctx(mca, ctx->cc_session, mechanism,
		    key, &privctx);
		break;
	default:
		cmn_err(CE_WARN, "mca_cb_verify_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		rv = CRYPTO_MECHANISM_INVALID;
	}

	if (rv == CRYPTO_SUCCESS) {
		ctx->cc_provider_private = privctx;
		privctx->mc_cmd |= CMD_HI_VRFY;
	}

	DBG(mca, DENTRY, "mca_cb_verify_init: done, rv = 0x%x", rv);

	return (rv);
}

static int
mca_cb_verify(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_data_t *signature, crypto_req_handle_t cfreq)
{
	int			rv = CRYPTO_FAILED;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = ctx->cc_provider_private;

	DBG(mca, DENTRY, "mca_cb_verify: started\n");

	/* check mechanism */
	switch (privctx->mc_cmd & CMD_MASK) {
	case CMD_HMAC_MD5:
		if (mca_isfips(mca)) {
			return (CRYPTO_MECHANISM_INVALID);
		}
		/*FALLTHROUGH*/
	case CMD_HMAC_SHA1:
	case CMD_HMAC_SHA512:
		if (data->cd_length > MAXPACKET) {
			privctx->mc_cmd |= CMD_HI_VRFY;
			rv = mca_hmac_init(mca, privctx, privctx->mc_cmd,
			    data, signature, cfreq);
		} else {
			rv = mca_hmac(privctx, data, signature, cfreq,
			    privctx->mc_cmd);
		}
		break;
	default:
		cmn_err(CE_WARN, "mca_cb_verify: unexpected cmd type "
		    "0x%x\n", privctx->mc_cmd);
	}
	/*
	 * If the op is terminated (successfully or with a fatal error),
	 * free the context
	 */
	if (!RETRY_RV(rv)) {
		(void) mca_freectx_kcf(ctx);
	}

	DBG(mca, DENTRY, "mca_cb_verify: done, err = 0x%x", rv);

	return (rv);
}


static int
mca_cb_verify_update(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	int			rv = CRYPTO_FAILED;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = ctx->cc_provider_private;

	DBG(mca, DENTRY, "mca_cb_verify_update: started");

	/*
	 * If 'MULTI_PART' flag is not turned on, this is the first
	 * mca_cb_verify_update call: need to get a context ID from the
	 * hardware.  Processing of the data is handled by the callback
	 * function of mca_hash_init.
	 */
	if (!(privctx->mc_cmd & CMD_HI_MULTI_PART)) {
		rv = mca_hmac_init(mca, privctx, privctx->mc_cmd,
		    data, NULL, req);
		/* mark it multi-part */
		privctx->mc_cmd |= CMD_HI_MULTI_PART;
	} else {
		/* Submit the job to the hardware */
		rv = mca_hmac_update(mca, privctx->mc_shortparam[0],
		    privctx->mc_cmd, data, req);
	}

	/*
	 * If the op is terminated with a fatal error, free the context
	 */
	if (FATAL_RV(rv)) {
		(void) mca_freectx_kcf(ctx);
	}

	DBG(mca, DENTRY, "mca_cb_verify_update: done, err = 0x%x", rv);

	return (rv);
}

static int
mca_cb_verify_final(crypto_ctx_t *ctx, crypto_data_t *signature,
    crypto_req_handle_t req)
{
	int			rv = CRYPTO_FAILED;
	mca_t			*mca = MCA_CTX2MCA(ctx);
	mca_privatectx_t	*privctx = ctx->cc_provider_private;

	DBG(mca, DENTRY, "mca_cb_verify_final: started");

	if (privctx == NULL) {
		return (CRYPTO_OPERATION_NOT_INITIALIZED);
	}

	rv = mca_hmac_final(mca, privctx, signature, req);

	/*
	 * If the op is terminated (successfully or with a fatal error),
	 * free the context
	 */
	if (!RETRY_RV(rv)) {
		(void) mca_freectx_kcf(ctx);
	}

	DBG(mca, DENTRY, "mca_cb_verify_final: done, err = 0x%x", rv);

	return (rv);
}


/*ARGSUSED*/
static int
mca_random_number(crypto_provider_handle_t provider,
	crypto_session_id_t sess, uchar_t *buf, size_t buflen,
	crypto_req_handle_t cfreq)
{
	mca_t		*mca = MCA_PROVIDER2MCA(provider);
	uint32_t	cmd;
	crypto_data_t	*data;
	int		rv;

	DBG(NULL, DENTRY, "mca_random_number -->");

	/*
	 * 'cmd' is picked based on the RNG style configuration.
	 * Although rng is not an InPlace operation, CMD_HI_KCF_INPLACE
	 * flag is turned on so that crypto_data_t struct will be freed
	 * when the operation is done
	 */
	if (mca_isrngsha1(mca)) {
		cmd = CMD_RNGSHA1 | CMD_HI_KCF_INPLACE;
	} else {
		cmd = CMD_RNGDIRECT | CMD_HI_KCF_INPLACE;
	}

	data = alloccryptodata(buf, buflen);
	if (data == NULL) {
		DBG(NULL, DWARN, "mca_random_number: alloccryptodata failed");
		return (CRYPTO_HOST_MEMORY);
	}

	/*
	 * Schedule the rng request.
	 * Note: mca_rng is responsible for freeing the allocated data
	 */
	rv = mca_rng(mca, data, cfreq, cmd);

	DBG(NULL, DENTRY, "mca_random_number <--[0x%x]", rv);

	return (rv);
}


/*
 * Key Related Operations
 */

int
mca_key_lookup_uint8(crypto_key_t *key, int type, uint8_t *value)
{
	/* at this point, it only allows lookup of constructed key/template */
	if (key->ck_format != CRYPTO_KEY_ATTR_LIST) {
		return (CRYPTO_FAILED);
	}

	return (cryptoattr_lookup_uint8(key->ck_attrs, key->ck_count,
	    type, value));
}

int
mca_key_lookup_uint32(crypto_key_t *key, int type, uint32_t *value)
{
	/* at this point, it only allows lookup of constructed key/template */
	if (key->ck_format != CRYPTO_KEY_ATTR_LIST) {
		return (CRYPTO_FAILED);
	}

	return (cryptoattr_lookup_uint32(key->ck_attrs, key->ck_count,
	    type, value));
}

int
mca_key_lookup_uint64(crypto_key_t *key, int type, uint64_t *value)
{
	/* at this point, it only allows lookup of constructed key/template */
	if (key->ck_format != CRYPTO_KEY_ATTR_LIST) {
		return (CRYPTO_FAILED);
	}

	return (cryptoattr_lookup_uint64(key->ck_attrs, key->ck_count,
	    type, value));
}

int
mca_key_lookup_uint8_array(crypto_key_t *key, int type, uint8_t **value,
    uint32_t *valuelen)
{
	/* at this point, it only allows lookup of constructed key/template */
	if (key->ck_format != CRYPTO_KEY_ATTR_LIST) {
		return (CRYPTO_FAILED);
	}

	return (cryptoattr_lookup_uint8_array(key->ck_attrs, key->ck_count,
	    type, value, valuelen));
}

int
mca_get_mech_param(crypto_mechanism_t *mech, char *buf, int *buflen)
{
	char	*param;
	size_t	paramlen;

	param = mech->cm_param;
	paramlen = mech->cm_param_len;

	if (param == NULL) {
		*buflen = 0;
		return (CRYPTO_SUCCESS);
	}

	if (buf == NULL) {
		*buflen = paramlen;
		return (CRYPTO_SUCCESS);
	} else if (*buflen < paramlen) {
		*buflen = paramlen;
		return (CRYPTO_BUFFER_TOO_SMALL);
	} else {
		*buflen = paramlen;
		bcopy(param, buf, paramlen);
		return (CRYPTO_SUCCESS);
	}
}

/*
 * data: source crypto_data_t struct
 * off: offset into the source of the current position before commencing copy
 * count: the amount of data to copy
 * dest: destination buffer
 */
void
mca_getbufbytes(crypto_data_t *data, int off, int count, char *dest)
{
	uio_t *uiop;
	uint_t vec_idx;
	size_t cur_len;
	mblk_t *mp;

	if (count == 0) {
		/* We don't want anything so we're done. */
		return;
	}

	/*
	 * Sanity check that we haven't specified a length greater than the
	 * offset adjusted size of the buffer.
	 */
	ASSERT(count <= (data->cd_length - off));

	/* Add the internal crypto_data offset to the requested offset. */
	off += data->cd_offset;

	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		bcopy(data->cd_raw.iov_base + off, dest, count);
		break;

	case CRYPTO_DATA_UIO:
		/*
		 * Jump to the first iovec containing data to be
		 * processed.
		 */
		uiop = data->cd_uio;
		for (vec_idx = 0; vec_idx < uiop->uio_iovcnt &&
		    off >= uiop->uio_iov[vec_idx].iov_len;
		    off -= uiop->uio_iov[vec_idx++].iov_len);

		/*
		 * The caller specified an offset that is larger than
		 * the total size of the buffers it provided.
		 */
		ASSERT(vec_idx != uiop->uio_iovcnt);


		/*
		 * Now process the iovecs.
		 */
		while (vec_idx < uiop->uio_iovcnt && count > 0) {
			cur_len = min((int)(uiop->uio_iov[vec_idx].iov_len) -
			    off, count);
			bcopy(uiop->uio_iov[vec_idx].iov_base + off, dest,
			    cur_len);
			count -= cur_len;
			dest += cur_len;
			vec_idx++;
			off = 0;
		}

		/*
		 * The end of the specified iovec's was reached but the
		 * length requested could not be processed requested to
		 * digest more data than it provided
		 */
		ASSERT((vec_idx != uiop->uio_iovcnt) || (count == 0));

		break;
	case CRYPTO_DATA_MBLK:
		/*
		 * Jump to the first mblk_t containing data to be processed.
		 */
		for (mp = data->cd_mp; mp != NULL && off >= MBLKL(mp);
		    off -= MBLKL(mp), mp = mp->b_cont);
		/*
		 * The caller specified an offset that is larger than
		 * the total size of the buffers it provided.
		 */
		ASSERT(mp != NULL);

		/*
		 * Now do the processing on the mblk chain.
		 */
		while (mp != NULL && count > 0) {
			cur_len = min((int)((int)(MBLKL(mp) - off)), count);
			bcopy((char *)(mp->b_rptr + off), dest, cur_len);
			count -= cur_len;
			dest += cur_len;
			mp = mp->b_cont;
			off = 0;
		}

		/*
		 * The end of the mblk was reached but the length
		 * requested could not be processed, (requested to
		 * digest more data than it provided).
		 */
		ASSERT((mp != NULL) || (count == 0));

		break;
	default:
		DBG(NULL, DWARN, "unrecognised crypto data format");
	}
}



/*
 * This function compare the buffer in the data with buf.
 * The result semantics follow bcmp, mempcmp, strcmp, etc.
 * Note: 'data' must not be chained
 */
int
mca_cmp_numnbuf(crypto_data_t *data, char *buf, int buflen)
{
	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		return (mca_numcmp(data->cd_raw.iov_base, data->cd_raw.iov_len,
		    buf, buflen));
	case CRYPTO_DATA_UIO:
	{
		uio_t	*uiop = data->cd_uio;

		if (uiop->uio_iovcnt > 1) {
			/* 'data' is chained */
			return (-1);
		}
		return (mca_numcmp(uiop->uio_iov[0].iov_base,
		    uiop->uio_iov[0].iov_len, buf, buflen));
	}
	case CRYPTO_DATA_MBLK:
	{
		mblk_t	*mp = data->cd_mp;

		if (mp->b_cont != NULL) {
			/* 'data' is chained */
			return (-1);
		}
		return (mca_numcmp((char *)mp->b_rptr, MBLKL(mp), buf, buflen));
	}
	default:
		return (-1);
	}
}


/*
 * This function checks whether 'data' is scatter-gather in nature: contiguous
 * buffer whose address is word aligned is NOT scatter-gather in nature
 */
int
mca_sg(crypto_data_t *data)
{
	if (data == NULL) {
		return (TRUE);
	}
	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
	{
		/* Contiguous in nature */
		if ((data->cd_raw.iov_len % sizeof (uint32_t)) ||
		    ((uintptr_t)data->cd_raw.iov_base % sizeof (uint32_t))) {
			return (TRUE);
		}
		break;
	}
	case CRYPTO_DATA_UIO:
	{
		uio_t	*uiop = data->cd_uio;
		if (uiop->uio_iovcnt > 1) {
			return (TRUE);
		}
		/* So there is only one iovec */
		if ((uiop->uio_iov[0].iov_len % sizeof (uint32_t)) ||
		    ((uintptr_t)uiop->uio_iov[0].iov_base %
		    sizeof (uint32_t))) {
			return (TRUE);
		}
		break;
	}
	case CRYPTO_DATA_MBLK:
	{
		mblk_t	*mp = data->cd_mp;

		if (mp->b_cont != NULL) {
			return (TRUE);
		}
		/* So there is only one mblk in the chain */
		if ((MBLKL(mp) % sizeof (uint32_t)) ||
		    ((uintptr_t)mp->b_rptr % sizeof (uint32_t))) {
			return (TRUE);
		}
		break;
	}
	default:
		DBG(NULL, DWARN, "unrecognised crypto data format");
	}
	return (FALSE);
}

int
mca_scatter(caddr_t buf, size_t buflen, crypto_data_t *data)
{
	off_t	offset = data->cd_offset + data->cd_length;
	uint_t	vec_idx;
	uio_t	*uiop;
	size_t	cur_len;
	mblk_t	*mp;
	int	count = buflen;

	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		if (data->cd_raw.iov_len - offset < count) {
			/* Trying to write out more than space available. */
			DBG(NULL, DENTRY, "mca_scatter[RAW] failed. "
			    "iov_len[%d] offset[%d] count[%d]",
			    data->cd_raw.iov_len, offset, count);
			return (CRYPTO_DATA_LEN_RANGE);
		}
		bcopy(buf, data->cd_raw.iov_base + offset, count);
		data->cd_length += count;
		break;

	case CRYPTO_DATA_UIO:
		/*
		 * Jump to the first iovec that can be written to.
		 */
		uiop = data->cd_uio;
		for (vec_idx = 0; vec_idx < uiop->uio_iovcnt &&
		    offset >= uiop->uio_iov[vec_idx].iov_len;
		    offset -= uiop->uio_iov[vec_idx++].iov_len);
		if (vec_idx == uiop->uio_iovcnt) {
			/*
			 * The caller specified an offset that is larger than
			 * the total size of the buffers it provided.
			 */
			DBG(NULL, DENTRY, "mca_scatter[UIO] failed");
			return (CRYPTO_DATA_LEN_RANGE);
		}

		/*
		 * Now process the iovecs.
		 */
		while (vec_idx < uiop->uio_iovcnt && count > 0) {
			cur_len = min((int)(uiop->uio_iov[vec_idx].iov_len -
			    offset), count);
			bcopy(buf, uiop->uio_iov[vec_idx].iov_base + offset,
			    cur_len);
			count -= cur_len;
			buf += cur_len;
			data->cd_length += cur_len;
			vec_idx++;
			offset = 0;
		}


		if (vec_idx == uiop->uio_iovcnt && count > 0) {
			/*
			 * The end of the specified iovec's was reached but
			 * the length requested could not be processed
			 * (requested to write more data than space provided).
			 */
			DBG(NULL, DENTRY, "mca_scatter[UIO] failed");
			return (CRYPTO_DATA_LEN_RANGE);
		}
		break;

	case CRYPTO_DATA_MBLK:
		/*
		 * Jump to the first mblk_t that can be written to.
		 */
		for (mp = data->cd_mp; mp != NULL && offset >= MBLKL(mp);
		    offset -= MBLKL(mp), mp = mp->b_cont);
		if (mp == NULL) {
			/*
			 * The caller specified an offset that is larger than
			 * the total size of the buffers it provided.
			 */
			DBG(NULL, DENTRY, "mca_scatter[MBLK] failed");
			return (CRYPTO_DATA_LEN_RANGE);
		}

		/*
		 * Now do the processing on the mblk chain.
		 */
		while (mp != NULL && count > 0) {
			cur_len = min((int)(MBLKL(mp) - offset), count);
			bcopy(buf, (char *)(mp->b_rptr + offset), cur_len);
			count -= cur_len;
			buf += cur_len;
			data->cd_length += cur_len;
			mp = mp->b_cont;
			offset = 0;
		}

		if (mp == NULL && count > 0) {
			/*
			 * The end of the mblk was reached but the length
			 * requested could not be processed, (requested to
			 * digest more data than it provided).
			 */
			DBG(NULL, DENTRY, "mca_scatter[MBLK] failed");
			return (CRYPTO_DATA_LEN_RANGE);
		}
		break;

	default:
		DBG(NULL, DWARN, "mca_scatter:unrecognised crypto "
		    "data format");
		return (CRYPTO_ARGUMENTS_BAD);
	}

	return (CRYPTO_SUCCESS);
}

int
mca_unpad_scatter(caddr_t buf, size_t buflen, crypto_data_t *data,
    uint32_t blocksz)
{
	int	i;
	uchar_t	c;
	caddr_t	cursor;

	/* Find out how many bytes of paddings were applied to the buffer */
	c = buf[buflen - 1];
	if (c > blocksz) {
		/* padding must be less than blocksz */
		return (CRYPTO_ENCRYPTED_DATA_INVALID);
	}

	/*
	 * Make sure that the value of the padding is correct
	 * i.e. if there is 3 padding bytes, the padding must be 0x030303
	 */
	cursor = buf + buflen - 1;
	for (i = 0; i < c; i++) {
		if (*cursor != c) {
			return (CRYPTO_ENCRYPTED_DATA_INVALID);
		}
		cursor--;
	}

	return (mca_scatter(buf, buflen - c, data));
}

/*
 */
int
mca_gather(crypto_data_t *in, caddr_t dest, size_t count)
{
	int	rv = CRYPTO_SUCCESS;
	uint_t	vec_idx;
	uio_t	*uiop;
	off_t	off = in->cd_offset;
	size_t	cur_len;
	mblk_t	*mp;

	switch (in->cd_format) {
	case CRYPTO_DATA_RAW:
		if (count > in->cd_length) {
			/*
			 * The caller specified a length greater than the
			 * size of the buffer.
			 */
			DBG(NULL, DENTRY, "mca_gather[DATA_RAW] failed "
			    "with CRYPTO_DATA_LEN_RANGE"
			    "(count[%d], cd_length[%d])", count, in->cd_length);
			return (CRYPTO_DATA_LEN_RANGE);
		}
		bcopy(in->cd_raw.iov_base + in->cd_offset, dest, count);
		in->cd_offset += count;
		in->cd_length -= count;
		break;

	case CRYPTO_DATA_UIO:
		/*
		 * Jump to the first iovec containing data to be processed.
		 */
		uiop = in->cd_uio;
		for (vec_idx = 0; vec_idx < uiop->uio_iovcnt &&
		    off >= uiop->uio_iov[vec_idx].iov_len;
		    off -= uiop->uio_iov[vec_idx++].iov_len);
		if (vec_idx == uiop->uio_iovcnt) {
			/*
			 * The caller specified an offset that is larger than
			 * the total size of the buffers it provided.
			 */
			DBG(NULL, DENTRY, "mca_gather[DATA_UIO] failed "
			    "with 0x%x", CRYPTO_DATA_LEN_RANGE);
			return (CRYPTO_DATA_LEN_RANGE);
		}

		/*
		 * Now process the iovecs.
		 */
		while (vec_idx < uiop->uio_iovcnt && count > 0) {
			/*
			 * count is size_t type which is unsigned long.
			 * Use a cast here to avoid a warning on i386 Linux.
			 */
			cur_len = min(uiop->uio_iov[vec_idx].iov_len -
			    off, (unsigned long)count);
			bcopy(uiop->uio_iov[vec_idx].iov_base + off, dest,
			    cur_len);
			count -= cur_len;
			dest += cur_len;
			in->cd_offset += cur_len;
			in->cd_length -= cur_len;
			vec_idx++;
			off = 0;
		}

		if (vec_idx == uiop->uio_iovcnt && count > 0) {
			/*
			 * The end of the specified iovec's was reached but
			 * the length requested could not be processed
			 * (requested to digest more data than it provided).
			 */
			DBG(NULL, DENTRY, "mca_gather[DATA_UIO] failed "
			    "with 0x%x", CRYPTO_DATA_LEN_RANGE);
			return (CRYPTO_DATA_LEN_RANGE);
		}
		break;

	case CRYPTO_DATA_MBLK:
		/*
		 * Jump to the first mblk_t containing data to be processed.
		 */
		for (mp = in->cd_mp; mp != NULL && off >= MBLKL(mp);
		    off -= MBLKL(mp), mp = mp->b_cont);
		if (mp == NULL) {
			/*
			 * The caller specified an offset that is larger than
			 * the total size of the buffers it provided.
			 */
			DBG(NULL, DENTRY, "mca_gather[DATA_MBLK] failed "
			    "with 0x%x", CRYPTO_DATA_LEN_RANGE);
			return (CRYPTO_DATA_LEN_RANGE);
		}

		/*
		 * Now do the processing on the mblk chain.
		 */
		while (mp != NULL && count > 0) {
			cur_len = min((size_t)(MBLKL(mp) - off), count);
			bcopy((char *)(mp->b_rptr + off), dest, cur_len);
			count -= cur_len;
			dest += cur_len;
			in->cd_offset += cur_len;
			in->cd_length -= cur_len;
			mp = mp->b_cont;
			off = 0;
		}

		if (mp == NULL && count > 0) {
			/*
			 * The end of the mblk was reached but the length
			 * requested could not be processed, (requested to
			 * digest more data than it provided).
			 */
			DBG(NULL, DENTRY, "mca_gather[DATA_MBLK] failed "
			    "with 0x%x", CRYPTO_DATA_LEN_RANGE);
			return (CRYPTO_DATA_LEN_RANGE);
		}
		break;

	default:
		DBG(NULL, DWARN, "mca_gather: unrecognised crypto "
		    "data format");
		rv = CRYPTO_ARGUMENTS_BAD;
	}
	return (rv);
}

int
mca_gather_pad(crypto_data_t *in, caddr_t dest, size_t inlen, char padlen)
{
	int	rv;

	if (in && (inlen > 0)) {
		rv = mca_gather(in, dest, inlen);
		if (rv != CRYPTO_SUCCESS) {
			return (rv);
		}
	}

	/*
	 * pad the end of the dest buffer
	 * i.e. if 3-byte needs to be added, append '0x030303' to the dest buf
	 */
	(void) memset(dest + inlen, padlen, padlen);

	return (CRYPTO_SUCCESS);
}

int
mca_gather_zero_pad(crypto_data_t *in, caddr_t dest, size_t inlen, int padlen)
{
	int	rv;

	if (in && (inlen > 0)) {
		rv = mca_gather(in, dest, inlen);
		if (rv != CRYPTO_SUCCESS) {
			return (rv);
		}
	}

	/*
	 * pad the end of the dest buffer with zeros
	 */
	(void) memset(dest + inlen, 0, padlen);

	return (CRYPTO_SUCCESS);
}

/*
 * mca_bindchains() returns 0 so long as there is no unrecoverable
 * error.  Its side effects are:
 * 1. If we cannot bind the input chain, we set the VRF_GATHER flag and,
 *    if there's an output buffer, the VRF_SCATTER flag.
 * 2. If we cannot bind the output chain, we set the VRF_SCATTER flag.
 */
int
mca_bindchains(mca_request_t *reqp, size_t incnt, size_t outcnt)
{
	int			rv;
	caddr_t			kaddr;
	uint_t			flags;
	int			n_chain = 0;

	if (reqp->mr_flags & MRF_INPLACE) {
		flags = DDI_DMA_RDWR | DDI_DMA_CONSISTENT;
	} else {
		flags = DDI_DMA_WRITE | DDI_DMA_STREAMING;
	}

	/* first the input */
	if (incnt) {
		switch (reqp->mr_in->cd_format) {
		case CRYPTO_DATA_RAW:
			kaddr = reqp->mr_in->cd_raw.iov_base +
			    reqp->mr_in->cd_offset;
			break;

		case CRYPTO_DATA_UIO:
			/* There will only be one iovec to handle */
			kaddr = reqp->mr_in->cd_uio->uio_iov[0].iov_base +
			    reqp->mr_in->cd_offset;
			break;

		case CRYPTO_DATA_MBLK:
			/* There will only be one mblk to handle */
			kaddr = (char *)reqp->mr_in->cd_mp->b_rptr +
			    reqp->mr_in->cd_offset;
			break;

		default:
			DBG(NULL, DWARN, "unrecognised crypto data format");
			return (DDI_FAILURE);
		}
		if ((rv = mca_bindchains_one(reqp, incnt, reqp->mr_offset,
		    kaddr, reqp->mr_in_direct_dmah, flags,
		    &reqp->mr_in_direct_dma_chain, &n_chain)) != DDI_SUCCESS) {
			reqp->mr_flags |= MRF_GATHER;
			if (outcnt)
				reqp->mr_flags |= MRF_SCATTER;
			return (DDI_SUCCESS);
		}

		/* update the resid len */
		reqp->mr_in->cd_length -= incnt;
		reqp->mr_in->cd_offset += incnt;

		/* Save the first one in the chain for MCR */
		reqp->mr_in_paddr = reqp->mr_in_direct_paddr;
		reqp->mr_in_next_paddr = reqp->mr_in_direct_next_paddr;
		reqp->mr_in_len = incnt;
		reqp->mr_in_first_len = reqp->mr_in_direct_length;
		reqp->mr_flags |= MRF_IN_DIRECT;
	} else {
		reqp->mr_in_paddr = 0;
		reqp->mr_in_next_paddr = 0;
		reqp->mr_in_len = 0;
		reqp->mr_in_first_len = 0;
	}

	if (reqp->mr_flags & MRF_INPLACE) {
		reqp->mr_out_paddr = reqp->mr_in_paddr;
		reqp->mr_out_len = reqp->mr_in_len;
		reqp->mr_out_first_len = reqp->mr_in_first_len;
		reqp->mr_out_next_paddr = reqp->mr_in_next_paddr;
		return (DDI_SUCCESS);
	}

	/* then the output */
	if (outcnt) {
		flags = DDI_DMA_READ | DDI_DMA_STREAMING;
		switch (reqp->mr_out->cd_format) {
		case CRYPTO_DATA_RAW:
			kaddr = reqp->mr_out->cd_raw.iov_base +
			    reqp->mr_out->cd_length +
			    reqp->mr_out->cd_offset;
			break;

		case CRYPTO_DATA_UIO:
			/* There will only be one iovec to handle */
			kaddr = reqp->mr_out->cd_uio->uio_iov[0].iov_base +
			    reqp->mr_out->cd_length +
			    reqp->mr_out->cd_offset;
			break;

		case CRYPTO_DATA_MBLK:
			/* There will only be one mblk to handle */
			kaddr = (char *)reqp->mr_out->cd_mp->b_rptr +
			    reqp->mr_out->cd_length +
			    reqp->mr_out->cd_offset;
			break;

		default:
			DBG(NULL, DWARN, "unrecognised crypto data format");
			return (DDI_FAILURE);
		}
		rv = mca_bindchains_one(reqp, outcnt, reqp->mr_offset +
		    n_chain * DESC_SIZE, kaddr, reqp->mr_out_direct_dmah,
		    flags, &reqp->mr_out_direct_dma_chain, &n_chain);
		if (rv != DDI_SUCCESS) {
			reqp->mr_flags |= MRF_SCATTER;
			return (DDI_SUCCESS);
		}

		/* Save the first one in the chain for MCR */
		reqp->mr_out_paddr = reqp->mr_out_direct_paddr;
		reqp->mr_out_next_paddr = reqp->mr_out_direct_next_paddr;
		reqp->mr_out_len = outcnt;
		reqp->mr_out_first_len = reqp->mr_out_direct_length;

		reqp->mr_flags |= MRF_OUT_DIRECT;
	} else {
		reqp->mr_out_paddr = 0;
		reqp->mr_out_next_paddr = 0;
		reqp->mr_out_len = 0;
		reqp->mr_out_first_len = 0;
	}

	return (DDI_SUCCESS);
}


static crypto_data_t *
alloccryptodata(uchar_t *buf, size_t buflen)
{
	crypto_data_t	*newdata;

	if ((newdata = kmem_zalloc(sizeof (crypto_data_t), KM_SLEEP)) == NULL) {
		DBG(NULL, DWARN, "dupcryptodata: no memory available");
		return (NULL);
	}

	newdata->cd_format = CRYPTO_DATA_RAW;
	newdata->cd_offset = 0;
	newdata->cd_length = buflen;
	newdata->cd_miscdata = NULL;
	newdata->cd_raw.iov_base = (char *)buf;
	newdata->cd_raw.iov_len = buflen;

	return (newdata);
}


static int
cryptoattr2symkey(crypto_object_attribute_t *attr, uint_t acount, int keytype,
    caddr_t buf, uint32_t *buflen)
{
	caddr_t		value = NULL;
	uint32_t	valuelen = 0;
	int		i;

	for (i = 0; i < acount; i++) {
		if (attr[i].oa_type == CPGA_VALUE) {
			value = attr[i].oa_value;
			valuelen = attr[i].oa_value_len;
		}
	}

	return (rawkey2keyhead(keytype, value, valuelen, buf, buflen));
}

static int
cryptoattr2rsapublic(crypto_object_attribute_t *attr, uint_t acount,
    caddr_t buf, uint32_t *buflen)
{
	uint32_t	mbits, mlen, elen;
	uint8_t		*m, *e;
	size_t		sz;
	pubrsa_head_t	*rsahead = (pubrsa_head_t *)buf;

	if (cryptoattr_lookup_uint8_array(attr, acount, CPGA_MODULUS,
	    &m, &mlen)) {
		DBG(NULL, DWARN, "RSA public key modulus missing");
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}
	if (cryptoattr_lookup_uint8_array(attr, acount, CPGA_PUBLIC_EXPONENT,
	    &e, &elen)) {
		DBG(NULL, DWARN, "RSA public exponent missing");
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	sz = sizeof (pubrsa_head_t) + PAD32(mlen) + PAD32(elen);
	if (sz > *buflen) {
		*buflen = sz;
		if (buf == NULL) {
			return (CRYPTO_SUCCESS);
		} else {
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}
	*buflen = sz;

	/* calculate modulus bits */
	mbits = mca_bitlen((caddr_t)m, mlen);

	/* if key is not in the supported range, return an error code */
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
cryptoattr2rsaprivate(crypto_object_attribute_t *attr, uint_t acount,
    caddr_t buf, uint32_t *buflen)
{
	prirsa_head_t	*rsahead;
	uint32_t	mbits;
	uint32_t	mlen = 0, dlen = 0;
	uint32_t	elen = 0, plen = 0, qlen = 0;
	uint32_t	dplen = 0, dqlen = 0, qinvlen = 0;
	uint8_t		*m, *d, *e, *p, *q, *dp, *dq, *qinv;
	size_t		sz;

	if (cryptoattr_lookup_uint8_array(attr, acount, CPGA_MODULUS,
	    &m, &mlen)) {
		DBG(NULL, DWARN, "RSA private modulus missing");
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	if (cryptoattr_lookup_uint8_array(attr, acount, CPGA_PRIVATE_EXPONENT,
	    &d, &dlen)) {
		DBG(NULL, DWARN, "RSA private expo missing");
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	/* following fields are optional */
	(void) cryptoattr_lookup_uint8_array(attr, acount, CPGA_PUBLIC_EXPONENT,
	    &e, &elen);
	(void) cryptoattr_lookup_uint8_array(attr, acount, CPGA_PRIME_1,
	    &p, &plen);
	(void) cryptoattr_lookup_uint8_array(attr, acount, CPGA_PRIME_2,
	    &q, &qlen);
	(void) cryptoattr_lookup_uint8_array(attr, acount, CPGA_EXPONENT_1,
	    &dp, &dplen);
	(void) cryptoattr_lookup_uint8_array(attr, acount, CPGA_EXPONENT_2,
	    &dq, &dqlen);
	(void) cryptoattr_lookup_uint8_array(attr, acount, CPGA_COEFFICIENT,
	    &qinv, &qinvlen);

	sz = PAD32(sizeof (prirsa_head_t)) + PAD32(mlen) + PAD32(elen) +
	    PAD32(dlen) + PAD32(plen) + PAD32(qlen) + PAD32(dplen) +
	    PAD32(dqlen) + PAD32(qinvlen);
	if (sz > *buflen) {
		*buflen = sz;
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
		if ((mca_numcmp((caddr_t)dp, dplen, (caddr_t)p, plen) > 0) ||
		    (mca_numcmp((caddr_t)qinv, qinvlen,
			(caddr_t)p, plen)) > 0) {
			DBG(NULL, DWARN, "RSA dp/qinv out of range");
			return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
		}
	}
	if (qlen) {
		if (mca_numcmp((caddr_t)dq, dqlen, (caddr_t)q, qlen) > 0) {
			DBG(NULL, DWARN, "RSA dq out of range");
			return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
		}
	}

	/* calculate modulus bits */
	mbits = mca_bitlen((caddr_t)m, mlen);

	/* if key is not in the supported range, return an error code */
	if ((mbits < RSA_MIN_KEY_LEN) || (mbits > RSA_MAX_KEY_LEN)) {
		DBG(NULL, DWARN, "mbits(%u) not in range", mbits);
		return (CRYPTO_KEY_SIZE_RANGE);
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
 */
static int
cryptoattr2dsakey(crypto_object_attribute_t *attr, uint_t acount,
    caddr_t buf, uint32_t *buflen, uint32_t class)
{
	uint8_t		*p, *q, *g, *v;
	unsigned	plen = 0, qlen = 0, glen = 0, vlen = 0;
	size_t		sz;
	dsa_head_t	*dsahead = (dsa_head_t *)buf;


	if (cryptoattr_lookup_uint8_array(attr, acount, CPGA_PRIME,
		&p, &plen) ||
	    cryptoattr_lookup_uint8_array(attr, acount, CPGA_SUBPRIME,
		&q, &qlen) ||
	    cryptoattr_lookup_uint8_array(attr, acount, CPGA_BASE,
		&g, &glen) ||
	    cryptoattr_lookup_uint8_array(attr, acount, CPGA_VALUE,
		&v, &vlen)) {
		/* these fields are required */
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	sz = sizeof (dsa_head_t) + PAD32(plen) + PAD32(qlen) +
	    PAD32(glen) + PAD32(vlen);
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
	mca_stripzeros((caddr_t *)&q, &qlen);
	mca_stripzeros((caddr_t *)&g, &glen);
	mca_stripzeros((caddr_t *)&v, &vlen);

	/*
	 * Make sure that the key is in the supported range
	 */
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
		/* must be a private key, value v < q */
		if (mca_numcmp((caddr_t)v, vlen, (caddr_t)q, qlen) > 0) {
			DBG(NULL, DWARN, "private DSA value v > q!");
			return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
		}
	} else if (mca_numcmp((caddr_t)v, vlen, (caddr_t)p, plen) > 0) {
		DBG(NULL, DWARN, "public DSA value v > p!");
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
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


/*
 * This function converts the key in crypto_object_attribute format to
 * key-specific format. This function should be used only for key-by-value
 * operations. Thus, only keytype and keyvalue fields are filled by this
 * function.
 */
static int
cryptoattr2keyhead(crypto_object_attribute_t *attr, uint_t acount,
    int keytype, caddr_t buf, uint32_t *buflen)
{
	int		rv;

	switch (keytype) {
	case KEYTYPE_DES:
	case KEYTYPE_DES2:
	case KEYTYPE_DES3:
	case KEYTYPE_RC2:
	case KEYTYPE_AES:
		rv = cryptoattr2symkey(attr, acount, keytype, buf, buflen);
		break;
	case KEYTYPE_RSA_PUBLIC:
		rv = cryptoattr2rsapublic(attr, acount, buf, buflen);
		break;
	case KEYTYPE_RSA_PRIVATE:
		rv = cryptoattr2rsaprivate(attr, acount, buf, buflen);
		break;
	case KEYTYPE_DSA_PUBLIC:
		rv = cryptoattr2dsakey(attr, acount, buf, buflen,
		    CPGO_PUBLIC_KEY);
		break;
	case KEYTYPE_DSA_PRIVATE:
		rv = cryptoattr2dsakey(attr, acount, buf, buflen,
		    CPGO_PRIVATE_KEY);
		break;
	case KEYTYPE_NOKEY:
		/* other objects do not have key field */
		*buflen = 0;
		return (CRYPTO_SUCCESS);
	case KEYTYPE_RC4:
	default:
		/* unsupported object type */
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}

	return (rv);
}

static int
rawdes2keyhead(int expkeylen, caddr_t key, uint32_t keylen,
    caddr_t buf, uint32_t *buflen)
{
	if (expkeylen != keylen) {
		return (CRYPTO_KEY_SIZE_RANGE);
	}

	if (keylen == 16) {
		/*
		 * If the key is DES2(16 bytes), expand it to be 24 bytes
		 * so that it can be used for DES3 operation.
		 */
		if (*buflen < 24) {
			*buflen = 24;
			return (buf ? CRYPTO_BUFFER_TOO_SMALL : CRYPTO_SUCCESS);
		}
		bcopy(key, buf, 16);
		bcopy(key, buf + 16, 8);
		*buflen = 24;
	} else {
		if (*buflen < keylen) {
			*buflen = keylen;
			return (buf ? CRYPTO_BUFFER_TOO_SMALL : CRYPTO_SUCCESS);
		}

		bcopy(key, buf, keylen);
		*buflen = keylen;
	}

	return (CRYPTO_SUCCESS);
}


/*
 * This function fills the 'keysz' and 'key' field of the mca_aes_keyhead_t
 * structure.  'iv' field should be filled by the caller
 */
static int
rawaes2keyhead(caddr_t key, uint32_t keylen, caddr_t buf, uint32_t *buflen)
{
	mca_aes_keyhead_t *aeskeyhead = (mca_aes_keyhead_t *)buf;

	switch (keylen) {
	case 16:
	case 24:
	case 32:
		break;
	default:
		DBG(NULL, DWARN, "aes:value length mismatch (got %u)", keylen);
		return (CRYPTO_KEY_SIZE_RANGE);
	}

	/*
	 * make sure mca_aes_keyhead_t and key value fits in the
	 * output buffer
	 */
	if ((keylen + sizeof (mca_aes_keyhead_t)) > *buflen) {
		*buflen = keylen + sizeof (mca_aes_keyhead_t);
		return (buf ? CRYPTO_BUFFER_TOO_SMALL : CRYPTO_SUCCESS);
	}

	*buflen = keylen + sizeof (mca_aes_keyhead_t);

	PUTBUF32(&aeskeyhead->keysz, keylen);
	buf += sizeof (mca_aes_keyhead_t);
	bcopy(key, buf, keylen);

	return (CRYPTO_SUCCESS);
}

/*
 * This function fills the 'keysz' and 'key' field of the mca_rc2_keyhead_t
 * structure.  'effbits' and 'iv' field should be filled by the caller
 */
static int
rawrc22keyhead(caddr_t key, uint32_t keylen, caddr_t buf, uint32_t *buflen)
{
	mca_rc2_keyhead_t *rc2keyhead = (mca_rc2_keyhead_t *)buf;

	if ((keylen > 128) || (keylen < 1)) {
		DBG(NULL, DWARN, "rc2:value length mismatch (got %u)", keylen);
		return (CRYPTO_KEY_SIZE_RANGE);
	}

	/*
	 * make sure mca_aes_keyhead_t and key value fits in the
	 * output buffer
	 */
	if ((keylen + sizeof (mca_rc2_keyhead_t)) > *buflen) {
		*buflen = keylen + sizeof (mca_rc2_keyhead_t);
		return (buf ? CRYPTO_BUFFER_TOO_SMALL : CRYPTO_SUCCESS);
	}
	*buflen = keylen + sizeof (mca_rc2_keyhead_t);

	PUTBUF32(&rc2keyhead->keysz, keylen);
	buf += sizeof (mca_rc2_keyhead_t);
	bcopy(key, buf, keylen);

	return (CRYPTO_SUCCESS);
}

static int
rawgeneric2keyhead(caddr_t key, uint32_t keylen, caddr_t buf, uint32_t *buflen)
{
	/*
	 * make sure the key value fits in the output buffer
	 */
	if (keylen > *buflen) {
		*buflen = keylen;
		return (buf ? CRYPTO_BUFFER_TOO_SMALL : CRYPTO_SUCCESS);
	}
	bcopy(key, buf, keylen);
	*buflen = keylen;

	return (CRYPTO_SUCCESS);
}

static int
rawkey2keyhead(int keytype, caddr_t key, uint32_t keylen,
    caddr_t buf, uint32_t *buflen)
{
	switch (keytype) {
	case KEYTYPE_DES:
		return (rawdes2keyhead(8, key, keylen, buf, buflen));
	case KEYTYPE_DES2:
		return (rawdes2keyhead(16, key, keylen, buf, buflen));
	case KEYTYPE_DES3:
		return (rawdes2keyhead(24, key, keylen, buf, buflen));
	case KEYTYPE_AES:
		return (rawaes2keyhead(key, keylen, buf, buflen));
	case KEYTYPE_RC2:
		return (rawrc22keyhead(key, keylen, buf, buflen));
	case KEYTYPE_RC4:
	case KEYTYPE_GENERIC_SECRET:
		return (rawgeneric2keyhead(key, keylen, buf, buflen));
	default:
		return (CRYPTO_TEMPLATE_INCONSISTENT);
	}
}

/*
 * This function should convert a key in crypto_key_t format into mca_key_head
 * format.
 * It is used for key use (i.e. encrypt, decrypt, wrap) only. For key template,
 * cpgattr2keyhead() in mca.c should be used.
 */
int
mca_write_key(mca_t *mca, crypto_session_id_t session_id, crypto_key_t *key,
    caddr_t buf, uint32_t *buflen, uint32_t *pkeyflags)
{
	if (key->ck_format == CRYPTO_KEY_REFERENCE) {
		int		rv;
		mca_session_t	*session;

		session = session_hold(session_table_get(mca, session_id),
					session_id);
		if (session == NULL) {
			return (CRYPTO_SESSION_HANDLE_INVALID);
		}
		rv = write_key_internal(session, key, 0, buf,
		    buflen, pkeyflags);
		mutex_exit(&session->ms_lock);
		return (rv);
	} else {
		return (write_key_internal(NULL, key, 0, buf,
		    buflen, pkeyflags));
	}
}

int
mca_write_keys(mca_t *mca, crypto_session_id_t session_id,
    crypto_key_t *key1, crypto_key_t *key2, caddr_t buf1,
    uint32_t *buf1len, caddr_t buf2, uint32_t *buf2len,
    uint32_t *pkey1flags, uint32_t *pkey2flags)
{
	mca_session_t	*session = NULL;
	int		rv;

	if ((key1->ck_format == CRYPTO_KEY_REFERENCE) ||
	    (key2->ck_format == CRYPTO_KEY_REFERENCE)) {
		session = session_hold(session_table_get(mca, session_id),
					session_id);
		if (session == NULL) {
			return (CRYPTO_SESSION_HANDLE_INVALID);
		}
	}

	rv = write_key_internal(session, key1, 0, buf1, buf1len, pkey1flags);
	if (rv != CRYPTO_SUCCESS) {
		if (session != NULL) {
			mutex_exit(&session->ms_lock);
		}
		return (rv);
	}

	rv = write_key_internal(session, key2, 0, buf2, buf2len, pkey2flags);
	if (session != NULL) {
		mutex_exit(&session->ms_lock);
	}

	return (rv);
}

static int
write_key_internal(mca_session_t *session, crypto_key_t *key,
    int keytype, caddr_t buf, uint32_t *buflen, uint32_t *pkeyflags)
{
	mca_key_head_t	*keyhead = (mca_key_head_t *)buf;
	uint32_t	len = *buflen;
	int		rv;

	/*
	 * set 'buf' to point to the beginning of the key value if it
	 * is given by the caller
	 */
	if (buf != NULL) {
		PUTBUF32(&keyhead->keytype, keytype);
		PUTBUF32(&keyhead->cardid, 0);
		PUTBUF32(&keyhead->objectid, 0);
		PUTBUF32(&keyhead->descrlen, 0);
		PUTBUF32(&keyhead->envelopelen, 0);

		buf += sizeof (mca_key_head_t);
		len -= sizeof (mca_key_head_t);
	} else {
		len = 0;
	}

	if (key->ck_format == CRYPTO_KEY_RAW) {
		/*
		 * If the expected keytype is DES3 and the actual key value
		 * length is 16 bytes, the keytype should be DES2 key
		 */
		if ((keytype == KEYTYPE_DES3) &&
		    (BITS2BYTES(key->ck_length) == 16)) {
			keytype = KEYTYPE_DES2;
		}

		/* Add key value field */
		rv = rawkey2keyhead(keytype, key->ck_data,
		    BITS2BYTES(key->ck_length), buf, &len);
		if ((rv == CRYPTO_SUCCESS) || (rv == CRYPTO_BUFFER_TOO_SMALL)) {
			*buflen = sizeof (mca_key_head_t) + len;
		}
		if (keyhead) {
			PUTBUF32(&keyhead->valuelen, len);
		}
		if (pkeyflags) {
			*pkeyflags = 0;
		}

		return (rv);
	} else if (key->ck_format == CRYPTO_KEY_ATTR_LIST) {
		/* Add key value field */
		rv = cryptoattr2keyhead(key->ck_attrs, key->ck_count, keytype,
		    buf, &len);
		if ((rv == CRYPTO_SUCCESS) || (rv == CRYPTO_BUFFER_TOO_SMALL)) {
			*buflen = sizeof (mca_key_head_t) + len;
		}
		if (keyhead) {
			PUTBUF32(&keyhead->valuelen, len);
		}
		if (pkeyflags) {
			*pkeyflags = 0;
		}
		return (rv);
	} else {
		mca_key_t	*mkey;
		mca_key_head_t	*origkeyhead;
		int		keytype_found;
		/*
		 * Key By Reference
		 */
		mkey = session_get_key(session, key->ck_obj_id);
		if (mkey == NULL) {
			return (CRYPTO_KEY_HANDLE_INVALID);
		}

		(void) cpgattr2keytype(mkey->mk_cpgattr, &keytype_found);
		/*
		 * If type of this key(keytype_found) is inconsistent with
		 * the expected keytype(keytype), then return an error code.
		 * Note: if keytype is 0, then this key is used for non-crypto
		 * operation, and therefore this keytype can be anything.
		 * Note: if expected keytype is DES3, the DES2 key is acceptable
		 */
		if ((keytype_found != keytype) &&
		    (keytype != 0) &&
		    ((keytype_found != KEYTYPE_DES2) ||
		    (keytype != KEYTYPE_DES3))) {
			DBG(NULL, DWARN,
			    "write_key_internal:  invalid key type (%d, %d)",
			    keytype, keytype_found);
			mutex_exit(&(mkey->mk_lock));
			return (CRYPTO_KEY_TYPE_INCONSISTENT);
		}

		origkeyhead = (mca_key_head_t *)(mkey + 1);

		if (mkey->mk_keyheadsz > *buflen) {
			mutex_exit(&(mkey->mk_lock));
			DBG(NULL, DCHATTY, "mca_write_key: keyhead[%d] > "
			    "buflen[%d]", mkey->mk_keyheadsz, *buflen);
			*buflen = mkey->mk_keyheadsz;
			return (buf == NULL ? CRYPTO_SUCCESS :
			    CRYPTO_BUFFER_TOO_SMALL);
		}
		*buflen = mkey->mk_keyheadsz;
		if (keyhead) {
			bcopy(origkeyhead, keyhead, *buflen);
		}
		if (pkeyflags) {
			*pkeyflags = mkey->mk_keyflags;
		}
		mutex_exit(&(mkey->mk_lock));

		return (CRYPTO_SUCCESS);
	}
}

/*
 * Lookup routines for crypto_object_attribute_t
 */
static int
cryptoattr_lookup_uint8(crypto_object_attribute_t *attr, uint_t acount,
    int type, uint8_t *value)
{
	int	i;

	for (i = 0; i < acount; i++) {
		if ((attr[i].oa_type == type) &&
		    (attr[i].oa_value_len == sizeof (uint8_t))) {
			*value = *(uint8_t *)(attr[i].oa_value);
			return (CRYPTO_SUCCESS);
		}
	}
	return (CRYPTO_ATTRIBUTE_TYPE_INVALID);
}

static int
cryptoattr_lookup_uint32(crypto_object_attribute_t *attr, uint_t acount,
    int type, uint32_t *value)
{
	int	i;

	for (i = 0; i < acount; i++) {
		if ((attr[i].oa_type == type) &&
		    (attr[i].oa_value_len == sizeof (uint32_t))) {
			*value = *(uint32_t *)(attr[i].oa_value);
			return (CRYPTO_SUCCESS);
		}
	}
	return (CRYPTO_ATTRIBUTE_TYPE_INVALID);
}


static int
cryptoattr_lookup_uint64(crypto_object_attribute_t *attr, uint_t acount,
    int type, uint64_t *value)
{
	int	i;

	for (i = 0; i < acount; i++) {
		if ((attr[i].oa_type == type) &&
		    (attr[i].oa_value_len == sizeof (uint64_t))) {
			*value = *(uint64_t *)(attr[i].oa_value);
			return (CRYPTO_SUCCESS);
		}
	}
	return (CRYPTO_ATTRIBUTE_TYPE_INVALID);
}

static int
cryptoattr_lookup_uint8_array(crypto_object_attribute_t *attr, uint_t acount,
    int type, uint8_t **buf, uint32_t *buflen)
{
	int	i;
	int	rv = CRYPTO_ATTRIBUTE_TYPE_INVALID;
	int	len = *buflen;

	for (i = 0; i < acount; i++) {
		if (attr[i].oa_type == type) {
			*buflen = attr[i].oa_value_len;
			*buf = (uint8_t *)attr[i].oa_value;
			return (CRYPTO_SUCCESS);
		}
	}

	*buflen = len;
	return (rv);
}
/*
 * Session Ops
 */

/*
 * This function initialize the session table
 * At the beginning, no session elements will be allocated.
 * The Session table will glow by MCA_SESSION_CHUNK every time.
 */
static void
session_table_init(mca_sessiontable_t *st)
{
	mca_table_init(&(st->mst_table), sizeof (mca_session_t), 0,
	    MCA_SESSION_CHUNK, NULL);
	mutex_init(&(st->mst_lock), NULL, MUTEX_DRIVER, NULL);
}

/*
 * This function cleans up the session table
 * All sessions are closed, and associated session objects are destroyed.
 */
static void
session_table_fini(mca_sessiontable_t *st)
{
	int	id = -1;
	int	rv;

	mutex_enter(&(st->mst_lock));

	/* Close all active sessions */
	while (mca_table_next_slot(&(st->mst_table), &id) != DDI_FAILURE) {
		mca_session_t	*session;

		rv = mca_table_lookup(&(st->mst_table), id, (void **)&session);
		if (rv != DDI_SUCCESS) {
			continue;
		}
		/*
		 * Remove the session from the session table, and release the
		 * reference for the session table.
		 */
		mca_table_remove_slot(&(st->mst_table), id);
		mca_session_releaseref(session, UNLOCKED);
	}

	mca_table_destroy(&(st->mst_table));

	mutex_exit(&(st->mst_lock));
	mutex_destroy(&(st->mst_lock));
}

/*
 * This function allocate and initialize session struct.
 * The session refcnt is set to 1.
 */
static mca_session_t *
session_alloc(int kmflag)
{
	mca_session_t	*session;

	session = kmem_zalloc(sizeof (mca_session_t), kmflag);
	if (session == NULL) {
		return (NULL);
	}

	mutex_init(&(session->ms_lock), NULL, MUTEX_DRIVER, NULL);

	mca_table_init(&(session->ms_keytable), sizeof (mca_key_t),
	    0, MCA_KEY_CHUNK, key_destructor);

	session->ms_refcnt = 1;

	return (session);
}

/*
 * This function cleanup the session struct. Associated session objects
 * are destroyed, and associated token objects are unloaded.  Also clear
 * the credential info indicating that the session is deauthenticated.
 * Session mutex should be held by the caller.
 */
static void
session_free(mca_session_t *session)
{
	ASSERT(session->ms_refcnt == 0);

	/* destroy the key table */
	key_table_fini(&(session->ms_keytable));

	/* clear the credential info (auth cookie) */
	session->ms_cred[0] = 0;
	session->ms_cred[1] = 0;
	session->ms_cred[2] = 0;
	session->ms_cred[3] = 0;

	mutex_exit(&(session->ms_lock));
	mutex_destroy(&(session->ms_lock));

	kmem_free(session, sizeof (mca_session_t));
}

/*
 * This function deletes the session from the sessiontable, and return
 * the pointer to the session. The session still has the refcnt from
 * the session table.
 */
static mca_session_t *
session_delete(mca_sessiontable_t *st, int sessionid)
{
	int		rv;
	mca_session_t	*session;

	if (st == NULL) {
		return (NULL);
	}

	/* clear the logical session indicator */
	sessionid = MCA_GET_SESS_ID(sessionid);

	mutex_enter(&(st->mst_lock));
	rv = mca_table_lookup(&(st->mst_table), sessionid, (void **)&session);
	if (rv != DDI_SUCCESS) {
		mutex_exit(&(st->mst_lock));
		return (NULL);
	}

	mca_table_remove_slot(&(st->mst_table), sessionid);

	mutex_exit(&(st->mst_lock));

	return (session);
}

/*
 * This function adds the key into the SKT, and returns the key id.
 * If the key is a token key, it increments the SKT's sequence number.
 * The caller must hold the session mutex
 */
static int
session_add_key(mca_session_t *session, mca_key_t *mkey,
    crypto_object_id_t *keyid)
{
	int	id;
	int	rv;

	rv = mca_table_add_slot(&(session->ms_keytable), &id, mkey, KM_SLEEP);
	if (rv != CRYPTO_SUCCESS) {
		return (rv);
	}

	mutex_enter(&(mkey->mk_lock));
	mkey->mk_keyflags |= KEYFLAG_VALID;
	if (mkey->mk_keyflags & KEYFLAG_PERSIST) {
		session->ms_ks_seq++;
	}
	mutex_exit(&(mkey->mk_lock));

	*keyid = id;
	return (CRYPTO_SUCCESS);
}

/*
 * This function looks up the key in the SKT, and returns the pointer to the
 * key with its mutex held.
 * The caller must hold the session mutex
 */
static mca_key_t *
session_get_key(mca_session_t *session, crypto_object_id_t keyid)
{
	int		rv;
	mca_key_t	*mkey;

	rv = mca_table_lookup(&(session->ms_keytable), keyid, (void **)&mkey);
	if (rv != CRYPTO_SUCCESS) {
		return (NULL);
	}

	mutex_enter(&mkey->mk_lock);

	/*
	 * If the key is invalidated, the key is pending for deletion.
	 * Thus, the key can not be held.
	 */
	if (!(mkey->mk_keyflags & KEYFLAG_VALID)) {
		mutex_exit(&(mkey->mk_lock));
		return (NULL);
	}

	return (mkey);
}

/*
 * The caller must hold the session mutex
 */
static void
session_unload_privatekeys(mca_session_t *session)
{
	int		id = -1;
	int		rv;

	/* Close all key */
	while (mca_table_next_slot(&session->ms_keytable, &id) != DDI_FAILURE) {
		mca_key_t	*key;

		rv = mca_table_lookup(&session->ms_keytable, id, (void **)&key);
		if (rv != DDI_SUCCESS) {
			continue;
		}

		mutex_enter(&key->mk_lock);
		if (key->mk_keyflags & KEYFLAG_PRIVATE) {
			/*
			 * Remove the key from the key table, and release the
			 * reference on the key for the table.
			 */
			mca_table_remove_slot(&session->ms_keytable, id);
			mca_key_releaseref(key, LOCKED);
		} else {
			mutex_exit(&key->mk_lock);
		}
	}
}

/*
 * This function looks up the session ID in the session table.
 * Post: session mutex is held
 */
static mca_session_t *
session_hold(mca_sessiontable_t *st, int sessionid)
{
	int		rv;
	mca_session_t	*session;

	if (st == NULL) {
		return (NULL);
	}

	/* clear the logical session indicator */
	sessionid = MCA_GET_SESS_ID(sessionid);

	mutex_enter(&(st->mst_lock));

	rv = mca_table_lookup(&(st->mst_table), sessionid, (void **)&session);
	if (rv != DDI_SUCCESS) {
		mutex_exit(&(st->mst_lock));
		return (NULL);
	}

	mutex_enter(&(session->ms_lock));

	mutex_exit(&(st->mst_lock));

	return (session);
}


/*
 * This function looks up the session ID in the session table.
 * Post: session mutex is held
 */
mca_session_t *
mca_session_holdref(mca_t *mca, crypto_session_id_t sessionid)
{
	int			rv;
	mca_sessiontable_t	*st;
	mca_session_t		*session;

	st = session_table_get(mca, sessionid);
	if (st == NULL) {
		/*
		 * mcakiod has probably killed, and therefore, the
		 * logical provider's handle is not usable anylonger
		 */
		return (NULL);
	}

	/* clear the logical session indicator */
	sessionid =  MCA_GET_SESS_ID(sessionid);

#ifdef LINUX
	spin_lock(&(st->mst_lock.lock));
#else
	mutex_enter(&(st->mst_lock));
#endif

	rv = mca_table_lookup(&(st->mst_table), sessionid, (void **)&session);
	if (rv != DDI_SUCCESS) {
		mutex_exit(&(st->mst_lock));
		return (NULL);
	}

#ifdef LINUX
	/*
	 * Should not disable interrupts when calling spinlock inside another
	 * spinlock. Use spin_lock/unlock directly here since mutex_enter/exit
	 * disable interrupts.
	 */
	spin_lock(&(session->ms_lock.lock));

	spin_unlock(&(st->mst_lock.lock));
#else
	mutex_enter(&(session->ms_lock));

	mutex_exit(&(st->mst_lock));
#endif

	session->ms_refcnt++;
	DBG(NULL, DENTRY, "mca_session_holdref[0x%x][%p] ref[%d]",
	    sessionid, session, session->ms_refcnt);

#ifdef LINUX
	spin_unlock(&(session->ms_lock.lock));
#else
	mutex_exit(&(session->ms_lock));
#endif

	return (session);
}

/*
 * release session reference
 */
void
mca_session_releaseref(mca_session_t *session, int locked)
{
	if (locked == UNLOCKED) {
		mutex_enter(&(session->ms_lock));
	}

	ASSERT(session->ms_refcnt > 0);

	session->ms_refcnt--;
	DBG(NULL, DENTRY, "mca_session_releaseref[%p] ref=[%d]",
	    session, session->ms_refcnt);

	if (session->ms_refcnt > 0) {
		mutex_exit(&(session->ms_lock));
		return;
	}

	DBG(NULL, DCHATTY, "mca_session_releaseref: session[%p] was freed",
	    session);

	/* There is no reference to this session. Clean the session */
	session_free(session);
}


/*ARGSUSED*/
static int
mca_session_open(crypto_provider_handle_t provider,
    crypto_session_id_t *sessionid, crypto_req_handle_t cfreq)
{
	mca_t			*mca = MCA_PROVIDER2MCA(provider);
	mca_sessiontable_t	*st = MCA_PROVIDER2SESSTBL(provider);
	mca_session_t		*session;
	crypto_session_id_t	id;
	int			rv;

	DBG(mca, DENTRY, "mca_session_open -->");

	if (st == NULL) {
		/* either CB or CA provider */
		return (CRYPTO_FAILED);
	}

	session = session_alloc(KM_SLEEP);
	if (session == NULL) {
		DBG(NULL, DWARN, "session_open: session_alloc failed: ENOMEM");
		return (CRYPTO_HOST_MEMORY);
	}

	mutex_enter(&(st->mst_lock));

	rv = mca_table_add_slot(&(st->mst_table), (int *)&id,
	    session, KM_SLEEP);
	if (rv != DDI_SUCCESS) {
		DBG(NULL, DWARN, "session_open: mca_table_add_slot "
		    "failed: ENOMEM");
		mutex_exit(&(st->mst_lock));
		return (CRYPTO_HOST_MEMORY);
	}

	/* no associated mca instance if session for logical provider */
	if (!mca) {
		/*
		 * set the logical session indicator
		 * we will need to use the KS index
		 * in order to support multiple keystores
		 * per device.
		 */
		id = MCA_SET_SESS_ID(id, MCA_PROVIDER2KS(provider));
	}
	*sessionid = id;

	mutex_exit(&(st->mst_lock));

	DBG(mca, DENTRY, "mca_session_open (0x%x) <--", id);

	return (CRYPTO_SUCCESS);
}

/*ARGSUSED*/
static int
mca_session_close(crypto_provider_handle_t provider,
    crypto_session_id_t sessionid, crypto_req_handle_t cfreq)
{
	mca_t			*mca = MCA_PROVIDER2MCA(provider);
	mca_sessiontable_t	*st = MCA_PROVIDER2SESSTBL(provider);
	mca_session_t		*session;
	mca_keystore_t		*ks;

	DBG(mca, DENTRY, "mca_session_close (0x%x) -->", sessionid);

	/* XXX work around for kCF bug */
	if (MCA_CHECK_LOGICAL_SESSION(sessionid) && mca) {
		/* better be a keystore present */
		if ((ks = mca_keystore_lookup_by_session(sessionid))) {
			st = MCA_PROVIDER2SESSTBL(
				&ks->mks_provinfo);
			if (st == NULL) {
				DBG(NULL, DENTRY, "mca_session_close: "
				    "logical provider problem");
				return (CRYPTO_SESSION_HANDLE_INVALID);
			}
		} else {
			DBG(NULL, DENTRY,
				"mca_session_close: logical provider problem");
			return (CRYPTO_SESSION_HANDLE_INVALID);
		}
	}

	/* delete the session from the session table */
	session = session_delete(st, sessionid);
	if (session == NULL) {
		DBG(NULL, DCHATTY, "mca_session_close: session ID[%d] invalid",
		    sessionid);
		return (CRYPTO_SESSION_HANDLE_INVALID);
	}
	if (session->ms_user) {
		/* delete user */
		mca_delete_user(session->ms_user);
	}

	/* drop the session refcnt for the session table */
	mca_session_releaseref(session, UNLOCKED);

	DBG(mca, DENTRY, "mca_session_close <--");

	return (CRYPTO_SUCCESS);
}


int
mca_set_session_cred(mca_session_t *session, uint32_t *kaddr,
    mca_user_t *user)
{
	mutex_enter(&session->ms_lock);
	session->ms_cred[0] = GETBUF32(kaddr++);
	session->ms_cred[1] = GETBUF32(kaddr++);
	session->ms_cred[2] = GETBUF32(kaddr++);
	session->ms_cred[3] = GETBUF32(kaddr++);

	session->ms_flags |= MSF_AUTHENTICATED;

	session->ms_user = user;

	mutex_exit(&session->ms_lock);
	return (CRYPTO_SUCCESS);
}


static void
session_unset_cred(mca_session_t *session)
{
	mutex_enter(&session->ms_lock);
	session->ms_cred[0] = 0;
	session->ms_cred[1] = 0;
	session->ms_cred[2] = 0;
	session->ms_cred[3] = 0;

	session->ms_user = NULL;

	session->ms_flags &= ~MSF_AUTHENTICATED;

	mutex_exit(&session->ms_lock);
}

int
mca_get_session_cred(mca_session_t *session, uint32_t *cred)
{
	mutex_enter(&session->ms_lock);
	if (session->ms_flags & MSF_AUTHENTICATED) {
		cred[0] = session->ms_cred[0];
		cred[1] = session->ms_cred[1];
		cred[2] = session->ms_cred[2];
		cred[3] = session->ms_cred[3];
		mutex_exit(&session->ms_lock);
		return (CRYPTO_SUCCESS);
	} else {
		mutex_exit(&session->ms_lock);
		return (CRYPTO_USER_NOT_LOGGED_IN);
	}
}

/*
 * Login/Logout
 */

/*
 * Login entrypoint
 * Note: pin is not NULL terminated
 */
static int
session_login(crypto_provider_handle_t prov, crypto_session_id_t session_id,
    crypto_user_type_t usertype, char *pin, size_t pinlen,
    crypto_req_handle_t cfreq)
{
	mca_t		*mca = MCA_PROVIDER2MCA(prov);
	mca_session_t	*session;
	mca_keystore_t	*ks;
	int		rv;
	char		userpass[MAX_PINSZ + 1];
	char		*user, *pass = NULL;
	int		i;

	DBG(mca, DENTRY, "session_login -->");

	if (usertype != CRYPTO_USER) {
		/* we only support 'user' (no SO) */
		DBG(mca, DWARN, "Unsupport User type[0x%x]", usertype);
		return (CRYPTO_USER_TYPE_INVALID);
	}

	session = mca_session_holdref(mca, session_id);
	if (session == NULL) {
		return (CRYPTO_SESSION_HANDLE_INVALID);
	}

	/* XXX: is sessionreference good enough to check the AUTH flag? */
	if (session->ms_flags & MSF_AUTHENTICATED) {
		mca_session_releaseref(session, UNLOCKED);
		return (CRYPTO_USER_ALREADY_LOGGED_IN);
	}

	if (pinlen > MAX_PINSZ) {
		/* PIN length is too long */
		DBG(mca, DCHATTY, "Invalid PIN Length[%d]", pinlen);
		mca_session_releaseref(session, UNLOCKED);
		return (CRYPTO_PIN_INVALID);
	}

	user = userpass;
	bcopy(pin, userpass, pinlen);
	userpass[pinlen] = '\000';

	for (i = 0; i < pinlen; ++i) {
		if (userpass[i] == ':') {
			userpass[i] = '\000';
			pass = &userpass[i + 1];
			break;
		}
	}


	if (pass == NULL) {
		/* the pin is not in "username:pass" format */
		DBG(mca, DWARN, "session_login: Wrong PIN format[%s]",
		    userpass);
		mca_session_releaseref(session, UNLOCKED);
		/* zero out password */
		bzero(userpass, MAX_PINSZ);
		return (CRYPTO_PIN_INVALID);
	}

	ks = mca_keystore_lookup_by_session(session_id);

	DBG(mca, DCHATTY, "mca_login[user=%s][pass=%s]", user, pass);

	rv = mca_login(mca, ks, session, user, pass, cfreq);
	if (rv != CRYPTO_QUEUED) {
		mca_session_releaseref(session, UNLOCKED);
	}

	/* zero out password */
	bzero(userpass, MAX_PINSZ);

	DBG(mca, DENTRY, "session_login <--[0x%x]", rv);

	return (rv);
}

/*
 * the user must hold the user write lock, and keystore rdlock
 */
static void
load_keys(mca_request_t *reqp)
{
	mca_key_t		**keys = NULL;
	size_t			size = INITIAL_KEYNUM * sizeof (mca_key_t *);
	mca_loadkeys_ctx_t	*ctx = NULL;
	mca_user_t		*user = (mca_user_t *)reqp->mr_context;
	int			rv;

	keys = (mca_key_t **)kmem_alloc(size, KM_NOSLEEP);
	if (keys == NULL) {
		DBG(reqp->mr_mca, DWARN, "load_keys: failed to "
		    "allocate %d bytes", size);
		rv = CRYPTO_HOST_MEMORY;
		goto exit;
	}

	rv = mca_loadkeys_ctxalloc(reqp->mr_mca, keys, size, user, &ctx);
	if (rv != CRYPTO_SUCCESS) {
		DBG(reqp->mr_mca, DWARN, "load_keys: failed to "
		    "allocate loadkey ctx");
		goto exit;
	}

	reqp->mr_context = (mca_privatectx_t *)ctx;

	rv = mca_loadkeys(reqp);

exit:
	if (rv != CRYPTO_QUEUED) {
		session_unset_cred(reqp->mr_session);
		mca_session_releaseref(reqp->mr_session, UNLOCKED);
		crypto_op_notification(reqp->mr_cf_req, rv);

		/* release the user lock if the operation failed */
		mca_user_unlock(user);

		mca_freereq(reqp);
		if (ctx != NULL) {
			mca_loadkeys_ctxfree(ctx);
		}
		if (keys != NULL) {
			kmem_free(keys, size);
		}
	}

	DBG(reqp->mr_mca, DAUTH, "load_keys <--[0x%x]", rv);
}

/*
 * If SKT is outdated, synchronize it with UKT.
 * Caller must hold session lock and user's rdlock
 */
static int
sync_skt(mca_session_t *session, mca_user_t *user)
{
	int		rv;
	int		id = -1;
	mca_key_t	*ukey = NULL;
	mca_key_t	*skey = NULL;
	mca_table_t	*kt = &(session->ms_keytable);

	/* unload all deleted keys from session */
	while (mca_table_next_slot(kt, &id) != DDI_FAILURE) {
		rv = mca_table_lookup(kt, id, (void **)&skey);
		if (rv != DDI_SUCCESS) {
			continue;
		}

		if (!(skey->mk_keyflags & KEYFLAG_VALID)) {
			/* drop the key refcnt for the key table */
			mca_table_remove_slot(kt, id);
			mca_key_releaseref(skey, UNLOCKED);
		}
	}

	/* load new keys */
	while ((ukey = (mca_key_t *)mca_nextqueue(&user->mu_keys,
	    (mca_listnode_t *)ukey)) != NULL) {
		uint32_t	keyid;

		mutex_enter(&ukey->mk_lock);
		if (!(ukey->mk_keyflags & KEYFLAG_VALID)) {
			/*
			 * another thread is in the process of
			 * deleting this 'ukey' XXX: never happens?
			 */
			mutex_exit(&ukey->mk_lock);
			continue;
		}

		id = -1;
		while ((rv = mca_table_next_slot(kt, &id)) != DDI_FAILURE) {
			rv = mca_table_lookup(kt, id, (void **)&skey);
			if (rv != DDI_SUCCESS) {
				break;
			}
			/* the key is already in the skt */
			if ((ukey->mk_keyid[0] == skey->mk_keyid[0]) &&
			    (ukey->mk_keyid[1] == skey->mk_keyid[1])) {
				break;
			}
		}
		if (rv == DDI_SUCCESS) {
			/*
			 * the key is already in the skt, do not add it
			 * to the SKT
			 */
			mutex_exit(&ukey->mk_lock);
			continue;
		}

		/*
		 * The key is new: the key did not exist in the SKT.
		 * Add it to the SKT.
		 */

		/* grab the refcnt for the skt */
		ukey->mk_refcnt++;
		mutex_exit(&ukey->mk_lock);

		/* create the key in the SKT */
		rv = session_add_key(session, ukey, &keyid);
		if (rv != CRYPTO_SUCCESS) {
			return (rv);
		}
	}

	session->ms_ks_seq = user->mu_ks_seq;

	return (CRYPTO_SUCCESS);
}

/*
 * Note: caller must hold the user rdlock, and keystore rdlock
 */
static void
load_keys_from_ukt(mca_request_t *reqp)
{
	mca_session_t		*session = reqp->mr_session;
	mca_user_t		*user = (mca_user_t *)reqp->mr_context;
	mca_key_t		*mkey = NULL;
	int			rv = CRYPTO_SUCCESS;

	mutex_enter(&(session->ms_lock));

	while ((mkey = (mca_key_t *)mca_nextqueue(&user->mu_keys,
	    (mca_listnode_t *)mkey)) != NULL) {
		uint32_t	keyid;

		mutex_enter(&mkey->mk_lock);
		if (!(mkey->mk_keyflags & KEYFLAG_VALID)) {
			/*
			 * another thread is in the process of
			 * deleting this 'mkey' XXX: never happens?
			 */
			mutex_exit(&mkey->mk_lock);
			continue;
		}

		/* grab the refcnt for the skt */
		mkey->mk_refcnt++;
		mutex_exit(&mkey->mk_lock);

		/* create the key in the SKT */
		rv = session_add_key(session, mkey, &keyid);
		if (rv != CRYPTO_SUCCESS) {
			/* unload private keys from the SKT */
			session_unload_privatekeys(session);

			/*
			 * Load-key is part of the login. Thus, load-key failure
			 * means login failure. Unset the cred.
			 */
			session_unset_cred(session);
			goto exit;
		}
	}
	session->ms_ks_seq = user->mu_ks_seq;

exit:
	crypto_op_notification(reqp->mr_cf_req, rv);
	mca_session_releaseref(session, TRUE /* holding the lock */);

	/*
	 * login and loadkeys are done. unlock user.
	 */
	mca_user_unlock(user);

	mca_freereq(reqp);
}

/*
 * This function is called when login was successful. It now try to load
 * the keys that belong to the user.
 */
void
mca_post_login(mca_request_t *reqp)
{
	mca_user_t	*user = (mca_user_t *)reqp->mr_context;

	DBG(reqp->mr_mca, DAUTH, "mca_cf_post_login -->");

	if (user->mu_flags & MUF_LOADED) {
		/*
		 * The user's keys are already loaded to the UKT. Synchronize
		 * the SKT with the UKT.
		 */
		load_keys_from_ukt(reqp);
	} else {
		/*
		 * The user's keys have not been loaded to the UKT. Enumerate
		 * keys from the FW, and load them.
		 */
		load_keys(reqp);
	}
}

/*
 * the call must hold a user wrlock
 */
void
mca_post_loadkeys(mca_request_t *reqp)
{
	mca_session_t		*session = reqp->mr_session;
	int			sessionlocked = UNLOCKED;
	mca_loadkeys_ctx_t	*ctx;
	mca_user_t		*user;
	int			rv = CRYPTO_SUCCESS;
	int			i;

	ctx = (mca_loadkeys_ctx_t *)reqp->mr_context;
	user = ctx->mlk_user;

	DBG(reqp->mr_mca, DAUTH, "mca_post_loadkeys[%d keys] -->",
	    ctx->mlk_nkeyids);

	if (reqp->mr_errno == CRYPTO_BUFFER_TOO_SMALL) {
		mca_key_t	**keys;
		size_t		size = ctx->mlk_nkeyids * sizeof (mca_key_t *);

		/*
		 * INITIAL_KEYNUM was insufficient. Reallocate the buffer
		 * and call mca_loadkeys() again
		 */
		kmem_free(ctx->mlk_keys, ctx->mlk_keyssz);
		mca_loadkeys_ctxfree(ctx);
		ctx = NULL;

		keys = (mca_key_t **)kmem_alloc(size, KM_NOSLEEP);
		if (keys == NULL) {
			rv = CRYPTO_HOST_MEMORY;
			DBG(reqp->mr_mca, DWARN, "mca_post_loadkeys: "
			    "kmem_alloc failed");
			goto exit;
		}
		rv = mca_loadkeys_ctxalloc(reqp->mr_mca, keys, size,
		    user, &ctx);
		if (rv != CRYPTO_SUCCESS) {
			kmem_free(keys, size);
			DBG(reqp->mr_mca, DWARN, "mca_post_loadkeys: "
			    "failed to allocate loadkey ctx");
			goto exit;
		}

		reqp->mr_context = (mca_privatectx_t *)ctx;

		if ((rv = mca_loadkeys(reqp)) != CRYPTO_QUEUED) {
			goto exit;
		}
		return;
	}


	if (reqp->mr_errno != CRYPTO_SUCCESS) {
		rv = reqp->mr_errno;
		goto exit;
	}

	mutex_enter(&(session->ms_lock));
	sessionlocked = LOCKED;

	for (i = 0; i < ctx->mlk_nkeyids; i++) {
		uint32_t	keyid;

		/* create the key in the SKT */
		rv = session_add_key(session, ctx->mlk_keys[i], &keyid);
		if (rv != CRYPTO_SUCCESS) {
			/* unload private keys from the SKT */
			session_unload_privatekeys(session);
			goto exit;
		}
	}
	session->ms_ks_seq = user->mu_ks_seq;

exit:
	if (rv != CRYPTO_SUCCESS) {
		/*
		 * Load-key is part of the login. Thus, load-key failure
		 * means login failure. Unset the cred.
		 */
		session_unset_cred(session);
	}
	crypto_op_notification(reqp->mr_cf_req, rv);
	mca_session_releaseref(session, sessionlocked);
	if (ctx != NULL) {
		kmem_free(ctx->mlk_keys, ctx->mlk_keyssz);
		mca_loadkeys_ctxfree(ctx);
	}
	/*
	 * login and loadkeys are done. unlock the user.
	 */
	mca_user_unlock(user);
	mca_freereq(reqp);
	DBG(reqp->mr_mca, DAUTH, "mca_post_loadkeys <--[0x%x]", rv);
}

/*ARGSUSED*/
static int
session_logout(crypto_provider_handle_t prov, crypto_session_id_t session_id,
    crypto_req_handle_t cfreq)
{
	mca_t		*mca = MCA_PROVIDER2MCA(prov);
	mca_session_t	*session;

	DBG(mca, DENTRY, "logout -->");

	session = session_hold(session_table_get(mca, session_id),
			session_id);
	if (session == NULL) {
		return (CRYPTO_SESSION_HANDLE_INVALID);
	}

	if (!(session->ms_flags & MSF_AUTHENTICATED)) {
		mutex_exit(&session->ms_lock);
		return (CRYPTO_USER_NOT_LOGGED_IN);
	}

	/* unload private keys from the SKT */
	session_unload_privatekeys(session);

	/* delete user */
	mca_delete_user(session->ms_user);
	session->ms_user = NULL;

	/*
	 * zero-out the credential field, and unset the MSF_AUTHENTICATED flag
	 */
	session->ms_cred[0] = 0;
	session->ms_cred[1] = 0;
	session->ms_cred[2] = 0;
	session->ms_cred[3] = 0;

	session->ms_flags &= ~MSF_AUTHENTICATED;
	session->ms_ks_seq = 0;
	mutex_exit(&session->ms_lock);

	DBG(mca, DENTRY, "session_logout <--");

	return (CRYPTO_SUCCESS);
}

/*
 * Provider Management Ops
 */
static void
strncpy_spacepad(uchar_t *s1, char *s2, int n)
{
	int s2len = strlen(s2);

	if (s2len >= n) {
		strncpy((char *)s1, s2, n);
	} else {
		strncpy((char *)s1, s2, n);
		memset(s1 + s2len, ' ', n - s2len);
	}
}

/*ARGSUSED*/
static int
ext_info(crypto_provider_handle_t prov, crypto_provider_ext_info_t *ext_info,
    crypto_req_handle_t cfreq)
{
#define	BUFSZ	64
	mca_provider_private_t	*priv = (mca_provider_private_t *)prov;
	mca_t	*mca = MCA_PROVIDER2MCA(prov);
	char	buf[64];

	/* handle info common to logical and hardware provider */

	/* Manufacturer ID */
	strncpy_spacepad(ext_info->ei_manufacturerID, MCA_MANUFACTURER_ID,
	    CRYPTO_EXT_SIZE_MANUF);

	/* Model */
	strncpy_spacepad(ext_info->ei_model, MCA_MODEL, CRYPTO_EXT_SIZE_MODEL);

	/* Token flags */
	ext_info->ei_flags = CRYPTO_EXTF_RNG | CRYPTO_EXTF_SO_PIN_LOCKED;

	ext_info->ei_max_session_count = CRYPTO_EFFECTIVELY_INFINITE;
	ext_info->ei_max_pin_len = MAX_PINSZ;
	ext_info->ei_min_pin_len = 0;
	ext_info->ei_total_public_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_free_public_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_total_private_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_free_private_memory = CRYPTO_UNAVAILABLE_INFO;

	/* Time. No need to be supplied for token without a clock */
	ext_info->ei_time[0] = '\000';

	/* handle logical provider specific fields */
	if (priv->mp_type == CRYPTO_LOGICAL_PROVIDER) {
		/* Token label */
		snprintf(buf, BUFSZ, "%s",
			mca_keystore_name(priv->mp_ks));

		/* Serial number (use blank string) */
		strncpy_spacepad(ext_info->ei_serial_number,
			" ",
			CRYPTO_EXT_SIZE_SERIAL);

		/* Version info */
		ext_info->ei_hardware_version.cv_major = 0;
		ext_info->ei_hardware_version.cv_minor = 0;
		ext_info->ei_firmware_version.cv_major = 0;
		ext_info->ei_firmware_version.cv_minor = 0;

		/* Token flags */
		ext_info->ei_flags |= CRYPTO_EXTF_TOKEN_INITIALIZED |
		    CRYPTO_EXTF_USER_PIN_INITIALIZED |
		    CRYPTO_EXTF_LOGIN_REQUIRED;
	} else { /* handle hardware provider specific fields */

		/* Token label */
		snprintf(buf, BUFSZ, "%s/%d Crypto Accel %s 1.0",
			ddi_driver_name(mca->mca_dip),
			ddi_get_instance(mca->mca_dip),
			priv->mp_ring->mr_name);

		/* Serial number */
		strncpy_spacepad(ext_info->ei_serial_number,
			mca->mca_device_serial,
			CRYPTO_EXT_SIZE_SERIAL);

		/* Version info */
		ext_info->ei_hardware_version.cv_major =
			MCA_HW_MAJOR_VERSION(mca);
		ext_info->ei_hardware_version.cv_minor =
			MCA_HW_MINOR_VERSION(mca);
		ext_info->ei_firmware_version.cv_major =
			MCA_FW_MAJOR_VERSION(mca);
		ext_info->ei_firmware_version.cv_minor =
			MCA_FW_MINOR_VERSION(mca);
		if (priv->mp_sessiontable && mca->mca_keystore_count) {
			/* token flags */
			ext_info->ei_flags |= CRYPTO_EXTF_TOKEN_INITIALIZED |
				CRYPTO_EXTF_USER_PIN_INITIALIZED |
				CRYPTO_EXTF_LOGIN_REQUIRED;
		} else {
			ext_info->ei_flags |= CRYPTO_EXTF_WRITE_PROTECTED;
		}
	}
	buf[BUFSZ - 1] = '\000';
	/* set the token label */
	strncpy_spacepad(ext_info->ei_label, buf, CRYPTO_EXT_SIZE_LABEL);

	DBG(mca, DCHATTY, "ext_info: token label %s, token flags 0x%x",
	    ext_info->ei_label, ext_info->ei_flags);

#undef	BUFSZ

	return (CRYPTO_SUCCESS);
}


/*ARGSUSED*/
static int
set_pin(crypto_provider_handle_t prov, crypto_session_id_t session_id,
    char *oldpin, size_t oldpinlen, char *newpin, size_t newpinlen,
    crypto_req_handle_t cfreq)
{
	mca_t		*mca = MCA_PROVIDER2MCA(prov);
	int		rv;
	char		olduserpass[MAX_PINSZ + 1];
	char		newuserpass[MAX_PINSZ + 1];
	char		*olduser, *oldpass = NULL;
	char		*newuser, *newpass = NULL;
	mca_keystore_t	*ks;
	int		i;

	DBG(mca, DENTRY, "set_pin-->");

	if ((oldpinlen > MAX_PINSZ) ||
	    (newpinlen > MAX_PINSZ)) {
		/* PIN length is too long */
		DBG(mca, DCHATTY, "Invalid PIN Length:old[%d], new[%d]",
		    oldpinlen, newpinlen);
		return (CRYPTO_PIN_INVALID);
	}

	/* verify keystore exists */
	if ((ks = mca_keystore_lookup_by_session(session_id)) == NULL) {
		DBG(mca, DWARN, "Device has no keystore?");
		return (CRYPTO_GENERAL_ERROR);
	}

	olduser = olduserpass;
	newuser = newuserpass;
	bcopy(oldpin, olduserpass, oldpinlen);
	bcopy(newpin, newuserpass, newpinlen);
	olduserpass[oldpinlen] = '\000';
	newuserpass[newpinlen] = '\000';

	for (i = 0; i < oldpinlen; ++i) {
		if (olduserpass[i] == ':') {
			olduserpass[i] = '\000';
			oldpass = &olduserpass[i + 1];
			break;
		}
	}
	for (i = 0; i < newpinlen; ++i) {
		if (newuserpass[i] == ':') {
			newuserpass[i] = '\000';
			newpass = &newuserpass[i + 1];
			break;
		}
	}

	if ((oldpass == NULL) || (newpass == NULL)) {
		/* the pin is not in "username:pass" format */
		DBG(mca, DWARN, "set_pin: Wrong PIN format");
		rv = CRYPTO_PIN_INVALID;
		goto done;
	}

	if (strcmp(olduser, newuser) != 0) {
		/* the user did not match */
		DBG(mca, DWARN, "set_pin: User Mismatch old[%s], new [%s]",
		    olduser, newuser);
		rv = CRYPTO_PIN_INVALID;
		goto done;
	}

	rv = mca_setpass(mca, olduser, oldpass, newpass, cfreq,
	    ks, session_id);

done:
	/* zero out password */
	bzero(olduserpass, MAX_PINSZ);
	bzero(newuserpass, MAX_PINSZ);

	DBG(mca, DENTRY, "set_pin <--[0x%x]", rv);

	return (rv);
}


/*
 * crypto_object_attribute_t vs cpg_attr_t
 */


/*
 * At present we call the allocating versions of the
 * cpg_attr_{init|dup|attach_data}.  Eventually, we might cause it to
 * be allocated by the caller.  This can often be faster, since it
 * might be a field of some larger structure.
 */

/*
 * This function converts template from crypto_object_attribute_t
 * format to cpg_attr_t format.  attrpolicy is the attrbute policy
 * from the global_attr_infobase, full can be one of 3 values:
 * NO_FLUFF, MINI_FLUFF (just fluffs sensitive and private---the usual
 * case, and FULL_FLUFF (fluffs every attribute---don't do this unless
 * you really know what you are doing).
 */
static int
cryptoattr2cpgattr(crypto_object_attribute_t *attr, uint_t attrnum,
    cpg_attr_t **cpgattrp, int attrpolicy, int fluff)
{
	int		i;
	int		rv = CRYPTO_SUCCESS;
	int		rv1;
	uint32_t	attrinfo;
	cpg_attr_t	*cpgattr;
	/* Allow 3 extra for fluffing */
	int		attr_growth_estimate = 0;
	uint8_t		istoken = 0;
	uint8_t		isprivate = 0;
	uint8_t		issensitive = 0;
	uint8_t		isextractable = 1;
	/* uint8_t		explicittoken = 0; */
	uint8_t		explicitsensitive = 0;
	uint8_t		explicitprivate = 0;
	int		offender;

	*cpgattrp = NULL;

	if (attrpolicy >= mca_global_attr_infobase.num_entries) {
		DBG(NULL, DWARN, "cryptoatt2cpgattr: "
		    "attrpolicy %d is illegal", attrpolicy);
		return (CRYPTO_ARGUMENTS_BAD);
	}
	/*
	 * Estimate size of cpg_attr (Remember, the malloc you save
	 * may be your own) and find out if sensitive, extractable,
	 * token or private.
	 */
	for (i = 0; i < attrnum; ++i) {
		if ((attr[i].oa_value == NULL) &&
		    (attr[i].oa_value_len != 0)) {
			/* an attribute has an invalid value pointer */
			return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
		}

		attr_growth_estimate +=
		    ROUNDUP8(attr[i].oa_value_len) + sizeof (cpg_attribute_t);

		/* deal with the ones we have to do "manually" */

		if (fluff & MINI_FLUFF) {
			switch (attr[i].oa_type) {
			case CPGA_SENSITIVE:
				issensitive = *(uint8_t *)attr[i].oa_value;
				explicitsensitive = TRUE;
				break;
			case CPGA_EXTRACTABLE:
				isextractable = *(uint8_t *)attr[i].oa_value;
				break;
			case CPGA_TOKEN:
				istoken = *(uint8_t *)attr[i].oa_value;
				/* explicittoken = TRUE; */
				break;
			case CPGA_PRIVATE:
				isprivate = *(uint8_t *)attr[i].oa_value;
				explicitprivate = TRUE;
				break;
			}
		}
	}

	/*
	 * Just a sanity check so we don't run out of kernel memory on
	 * a bogus attribute.
	 */
	if (attr_growth_estimate > MAX_CPG_ATTR_SIZE) {
		cmn_err(CE_NOTE, "crypto request failed because it "
		    "would have required %d bytes",
		    attr_growth_estimate);
		*cpgattrp = NULL;
		return (CRYPTO_FAILED);
	}

	/*
	 * Allocate and initialize a new cpg_attr.  mca_cpg_infobase is
	 * a global variable "database" of default policies.  Right
	 * now we use the ACITIVE_OBJECT_POLICY and below check
	 * against the supplied policy.  But if we go to having
	 * type-dependent defaults we will have to use the correct
	 * policy here.
	 */
	if ((rv = cpg_attr_alloc_init(&cpgattr, &mca_global_attr_infobase,
	    ACTIVE_OBJECT_POLICY, attr_growth_estimate, 0)) !=
	    CRYPTO_SUCCESS) {
		return (rv);
	}

	for (i = 0; i < attrnum; i++) {
		rv1 = cpg_attr_info_query(&mca_global_attr_infobase,
		    attrpolicy, attr[i].oa_type, &attrinfo);
		if (rv1) {
			/* attr is invalid, skip it */
			rv = CRYPTO_ATTRIBUTE_TYPE_INVALID;
			continue;
		}
		if (attrinfo == 0) {
			/*
			 * cpg_attr_info_query returns success but
			 * attrinfo is zero means that the attribute
			 * is unknown, but policy allows unknown
			 * attributes.  Assume it is a byte array, and
			 * not sensitive.
			 */
			attrinfo = CPG_ATTR_ISARRAY  | CPG_ATTR_ISUNSIGNED |
			    CPG_ATTR_DATASIZE8;
		}
		if ((attrinfo & CPG_ATTR_TYPE_MASK) == (CPG_ATTR_ISUNSIGNED |
		    CPG_ATTR_DATASIZE8)) {
			/* boolean, check that it is a single byte */
			if (attr[i].oa_value_len != 1) {
				DBG(NULL, DCHATTY, "cryptoatt2cpgattr: "
				    "BOOL (type=0x%x vallen = %d)",
				    attr[i].oa_type, attr[i].oa_value_len);
				if (rv == CRYPTO_SUCCESS) {
					rv = CRYPTO_ATTRIBUTE_VALUE_INVALID;
				}
				break;
			}
		}

		if (attrinfo & CPG_ATTR_ISARRAY) {
			/* array-valued attribute */
			rv1 = cpg_attr_add_uint8_array(cpgattr,
			    attr[i].oa_type, (uint8_t *)attr[i].oa_value,
			    (uint32_t)attr[i].oa_value_len, 0);
			if (rv == CRYPTO_SUCCESS) {
				rv = rv1;
			}
		} else {
			/*
			 * Scalar-valued attribute.  We accept
			 * whatever size the user supplies, as long as
			 * it is machine supported.
			 */
			switch (attr[i].oa_value_len) {
			case 1:
				rv1 = cpg_attr_add_uint8(cpgattr,
				    attr[i].oa_type,
				    *(uint8_t *)attr[i].oa_value, 0);
				if (rv == CRYPTO_SUCCESS) {
					rv = rv1;
				}
				break;
			case 2:
				rv1 = cpg_attr_add_uint16(cpgattr,
				    attr[i].oa_type,
				    *(uint16_t *)attr[i].oa_value, 0);
				if (rv == CRYPTO_SUCCESS) {
					rv = rv1;
				}
				break;
			case 4:
				rv1 = cpg_attr_add_uint32(cpgattr,
				    attr[i].oa_type,
				    *(uint32_t *)attr[i].oa_value, 0);
				if (rv == CRYPTO_SUCCESS) {
					rv = rv1;
				}
				break;
			case 8:
				rv1 = cpg_attr_add_uint64(cpgattr,
				    attr[i].oa_type,
				    *(uint64_t *)attr[i].oa_value, 0);
				if (rv == CRYPTO_SUCCESS) {
					rv = rv1;
				}
				break;
			default:
				DBG(NULL, DCHATTY, "cryptoatt2cpgattr: "
				    "scalar (vallen = %d)",
				    attr[i].oa_value_len);
				if (rv == CRYPTO_SUCCESS) {
					rv = CRYPTO_ATTRIBUTE_VALUE_INVALID;
				}
			}
		}
	}

	if (fluff != NO_FLUFF) {

		/* do the mini-fluffing */

		/* fail if not extractable, but also not sensitive */
		if (!issensitive && !isextractable) {
			if (rv == CRYPTO_SUCCESS) {
				DBG(NULL, DCHATTY, "cryptoatt2cpgattr: "
				    "unsupported combination: not extractable "
				    "and not sensitive");
				rv = CRYPTO_TEMPLATE_INCONSISTENT;
			}
		}

		/* Fail if public token object */
		if (explicitprivate && istoken && !isprivate) {
			if (rv == CRYPTO_SUCCESS) {
				DBG(NULL, DCHATTY, "cryptoatt2cpgattr: "
				    "unsupported combination: public token "
				    "object");
				rv = CRYPTO_TEMPLATE_INCONSISTENT;
			}
		}

		/*
		 * Fluff sensitive.
		 */
		if (!explicitsensitive) {
			/* CKA_SENSITIVE not explicitly set; fluff it */
			rv1 = cpg_attr_add_uint8(cpgattr, CPGA_SENSITIVE,
			    !isextractable, 0);
			if (rv == CRYPTO_SUCCESS) {
				rv = rv1;
			}
		}

		/*
		 * Fluff private
		 */
		if (!explicitprivate) {
			/* CKA_PRIVATE not explicitly set; fluff it */
			rv1 = cpg_attr_add_uint8(cpgattr, CPGA_PRIVATE,
			    istoken, 0);
			if (rv == CRYPTO_SUCCESS) {
				rv = rv1;
			}
		}

		if (fluff == FULL_FLUFF) {
			/*
			 * Fluff every attribute.  This is really expensive,
			 * and makes the cpg_attr really big.
			 */
			rv1 = cpg_attr_filter(cpgattr,
			    CPG_ATTR_FLUFF | CPG_ATTR_NOSLEEP);
			if (rv == CRYPTO_SUCCESS) {
				rv = rv1;
			}
		}
	}

#ifdef DO_CHECK
	rv1 = cpg_attr_check(cpgattr, mca_global_attr_infobase.info[attrpolicy],
	    CPG_ATTR_REPORT_BOGUS, &offender);
	if (rv1) {
		DBG(NULL, DENTRY, "cryptoattr2cpgattr found bogus attribute "
		    "type 0x%x", offender);
		if (rv == CRYPTO_SUCCESS) {
			rv = rv1;
		}
	}
#endif

	if (rv != CRYPTO_SUCCESS) {
		cpg_attr_free(cpgattr);
		*cpgattrp = NULL;
	} else {
		*cpgattrp = cpgattr;
	}

	return (rv);
}


/*
 * Object Ops
 */

/*
 * This function deletes the keys in the key table, and destroy the key
 * table itself.
 * Pre: session mutex must be held for SKT, and keystore mutex must
 *	be held for UKT
 */
static void
key_table_fini(mca_table_t *kt)
{
	int		id = -1;
	int		rv;

	/* Close all key */
	while (mca_table_next_slot(kt, &id) != DDI_FAILURE) {
		mca_key_t	*key;

		rv = mca_table_lookup(kt, id, (void **)&key);
		if (rv != DDI_SUCCESS) {
			continue;
		}

		/*
		 * Remove the key from the key table, and release the
		 * reference on the key for the table.
		 */
		mca_table_remove_slot(kt, id);
		mca_key_releaseref(key, UNLOCKED);
	}

	mca_table_destroy(kt);
}

void
mca_key_releaseref(mca_key_t *key, int locked)
{
	if (locked == UNLOCKED) {
		mutex_enter(&(key->mk_lock));
	}
	key->mk_refcnt--;
	DBG(NULL, DENTRY, "mca_key_releaseref: key[addr = %p] [ref = %d]",
	    key, key->mk_refcnt);

	if (key->mk_refcnt > 0) {
		mutex_exit(&(key->mk_lock));
		return;
	}

	mca_key_free(key);
}

/*
 * This functions is called when the key table deletes the key.
 * This function is necessary since each key slot is different in size.
 */
static void
key_destructor(void *key)
{
	DBG(NULL, DENTRY, "key_destructor: key[addr = %p]", key);

	mca_key_releaseref((mca_key_t *)key, UNLOCKED);
}

/*
 * Turn off the the valid bit. From here on, this thread owns the
 * refcnt for the key table.
 */
static mca_key_t *
invalidate_key(mca_session_t *session, crypto_object_id_t keyid)
{
	int		rv;
	mca_key_t	*mkey;

	DBG(NULL, DENTRY, "invalidate_key -->");

	mutex_enter(&(session->ms_lock));

	rv = mca_table_lookup(&(session->ms_keytable), keyid, (void **)&mkey);
	if (rv != DDI_SUCCESS) {
		mutex_exit(&(session->ms_lock));
		return (NULL);
	}

	mutex_enter(&(mkey->mk_lock));

	/*
	 * If the key is invalidated, the key is pending for deletion.
	 * Thus, the key can not be held.
	 */
	if (!(mkey->mk_keyflags & KEYFLAG_VALID)) {
		/* drop the key refcnt for the key table */
		mca_table_remove_slot(&(session->ms_keytable), keyid);
		mca_key_releaseref(mkey, LOCKED);

		mutex_exit(&(session->ms_lock));
		return (NULL);
	}
	mutex_exit(&(session->ms_lock));

	mkey->mk_keyflags &= ~KEYFLAG_VALID;

	mutex_exit(&(mkey->mk_lock));

	DBG(NULL, DENTRY, "invalidate_key <--");

	return (mkey);
}

/*
 * Turn on the valid flag. Key is available to other threads.
 * The owner of the reference will be returned to the key table.
 */
void
mca_validate_key(mca_key_t *mkey)
{
	DBG(NULL, DENTRY, "mca_validate_key -->");

	mutex_enter(&(mkey->mk_lock));
	mkey->mk_keyflags |= KEYFLAG_VALID;
	mutex_exit(&(mkey->mk_lock));

	DBG(NULL, DENTRY, "mca_validate_key <--");
}

void
mca_invalidate_key(mca_key_t *mkey)
{
	DBG(NULL, DENTRY, "mca_invalidate_key -->");

	mutex_enter(&(mkey->mk_lock));
	mkey->mk_keyflags &= ~KEYFLAG_VALID;

	mca_key_releaseref(mkey, LOCKED);

	DBG(NULL, DENTRY, "mca_invalidate_key <--");
}

/*
 * This function adds 'mkey' to the session key table.
 * As a side effect, the session refcount is decremented on successful exit.
 */
int
mca_add_key(mca_session_t *session, mca_key_t *mkey,
    crypto_object_id_t *keyid)
{
	int	rv;

	DBG(NULL, DENTRY, "mca_add_key -->");

	mutex_enter(&(session->ms_lock));

	rv = session_add_key(session, mkey, keyid);
	if (rv != CRYPTO_SUCCESS) {
		mutex_exit(&(session->ms_lock));
		return (rv);
	}

	/* release the session refcnt and lock */
	mca_session_releaseref(session, LOCKED);

	DBG(NULL, DENTRY, "mca_add_key[keyid = %d] <--", *keyid);

	return (CRYPTO_SUCCESS);
}

/*
 * This function adds pubmkey and prvmkey to the SKT.
 * As a side effect, the session reference is released on successful exit
 */
int
mca_add_keys(mca_session_t *session, mca_key_t *pubmkey, mca_key_t *prvmkey,
    crypto_object_id_t *pubkeyid, crypto_object_id_t *prvkeyid)
{
	int	rv;
	int	pubid = -1, prvid = -1;

	DBG(NULL, DENTRY, "mca_add_keys -->");

	mutex_enter(&(session->ms_lock));

	if (pubmkey) {
		rv = mca_table_add_slot(&(session->ms_keytable), &pubid,
		    pubmkey, KM_SLEEP);
		if (rv != CRYPTO_SUCCESS) {
			mutex_exit(&(session->ms_lock));
			return (rv);
		}
		mutex_enter(&(pubmkey->mk_lock));
		pubmkey->mk_keyflags |= KEYFLAG_VALID;
		mutex_exit(&(pubmkey->mk_lock));

		*pubkeyid = pubid;
	}

	if (prvmkey) {
		rv = mca_table_add_slot(&(session->ms_keytable), &prvid,
		    prvmkey, KM_SLEEP);
		if (rv != CRYPTO_SUCCESS) {
			if (pubmkey) {
				mca_table_remove_slot(&(session->ms_keytable),
				    pubid);
			}
			mutex_exit(&(session->ms_lock));
			return (rv);
		}
		mutex_enter(&(prvmkey->mk_lock));
		prvmkey->mk_keyflags |= KEYFLAG_VALID;
		mutex_exit(&(prvmkey->mk_lock));

		*prvkeyid = prvid;
	}

	/* release the session refcnt and lock */
	mca_session_releaseref(session, LOCKED);

	DBG(NULL, DENTRY, "mca_add_keys[pubkeyid = %d, prvkeyid = %d] <--",
	    pubid, prvid);

	return (CRYPTO_SUCCESS);
}

static mca_sessiontable_t *
session_table_get(mca_t *mca, crypto_session_id_t sessionid)
{
	/*
	 * for logical sessions - use the keystore
	 * associated session table.
	 */
	if (MCA_CHECK_LOGICAL_SESSION(sessionid)) {
		mca_keystore_t *ks;
		if ((ks = mca_keystore_lookup_by_session(sessionid))) {
			return (&ks->mks_sessiontable);
		} else {
			return (NULL);
		}
	} else {
		return (&mca->mca_sessiontable);
	}
}

/*
 * This function creates a key in the SKT.  If the key is sensitive or token,
 * it also creates the key on the card, and add the entry to the UKT.
 */
static int
mca_object_create(crypto_provider_handle_t provider,
    crypto_session_id_t sessionid, crypto_object_attribute_t *attr,
    uint_t attrnum, crypto_object_id_t *keyid, crypto_req_handle_t cfreq)
{
	int		rv;
	cpg_attr_t	*template;

	DBG(MCA_PROVIDER2MCA(provider), DENTRY, "mca_object_create -->");

	rv = cryptoattr2cpgattr(attr, attrnum, &template, CREATE_POLICY,
	    MINI_FLUFF);
	if (rv != CRYPTO_SUCCESS) {
		DBG(MCA_PROVIDER2MCA(provider), DCHATTY, "mca_object_create: "
		    "cryptoattr2cpgattr failed with 0x%x", rv);
		return (rv);
	}

	rv = object_create_internal(provider, sessionid, template,
	    keyid, cfreq);

	DBG(MCA_PROVIDER2MCA(provider), DENTRY, "mca_object_create <--[0x%x]",
	    rv);

	return (rv);
}

static int
object_create_internal(crypto_provider_handle_t provider,
    crypto_session_id_t sessionid, cpg_attr_t *template,
    crypto_object_id_t *keyid, crypto_req_handle_t cfreq)
{
	mca_t			*mca = MCA_PROVIDER2MCA(provider);
	mca_session_t		*session;
	int			rv;
	uint32_t		keyflags;

	rv = mca_createkey_flags(template, &keyflags);
	if (rv != CRYPTO_SUCCESS) {
		/* public token key is not supported */
		cpg_attr_free(template);
		return (rv);
	}

	session = mca_session_holdref(mca, sessionid);
	if (session == NULL) {
		DBG(mca, DCHATTY, "mca_object_create: session ID[%d] "
		    "invalid", sessionid);
		cpg_attr_free(template);
		return (CRYPTO_SESSION_HANDLE_INVALID);
	}

	if ((keyflags & KEYFLAG_PRIVATE) &&
	    !(session->ms_flags & MSF_AUTHENTICATED)) {
		DBG(mca, DCHATTY, "object_create_internal: private key "
		    "cannot be created before login");
		cpg_attr_free(template);
		mca_session_releaseref(session, UNLOCKED);
		return (CRYPTO_USER_NOT_LOGGED_IN);
	}

	if (!(keyflags & KEYFLAG_PERSIST) && !(keyflags & KEYFLAG_SENSITIVE)) {
		char		*buf;
		uint32_t	buflen = INITIAL_HEAD_SIZE;
		uint32_t	buflen_alloc;
		mca_key_t	*mkey;
		int		keytype;
		uint32_t	residlen;

		/*
		 * Non-Sensitive Session key: no need to create a key on HW
		 */
		rv = cpgattr2keytype(template, &keytype);
		if (rv != CRYPTO_SUCCESS) {
			cpg_attr_free(template);
			mca_session_releaseref(session, UNLOCKED);
			return (rv);
		}

		buf = kmem_alloc(buflen, KM_SLEEP);
		buflen_alloc = buflen;
		if (buf == NULL) {
			cpg_attr_free(template);
			mca_session_releaseref(session, UNLOCKED);
			return (CRYPTO_HOST_MEMORY);
		}

		/* XXX: maybe write cpgattr2mcakey */
		rv = cpgattr2keyhead(template, keytype, buf, &buflen);
		residlen = buflen;
		if (rv == CRYPTO_BUFFER_TOO_SMALL) {
			kmem_free(buf, buflen_alloc);

			buf = kmem_alloc(buflen, KM_SLEEP);
			if (buf == NULL) {
				cpg_attr_free(template);
				mca_session_releaseref(session, UNLOCKED);
				return (CRYPTO_HOST_MEMORY);
			}
			buflen_alloc = buflen;
			rv = cpgattr2keyhead(template, keytype, buf, &residlen);
		}
		if (rv != CRYPTO_SUCCESS) {
			cpg_attr_free(template);
			kmem_free(buf, buflen_alloc);
			mca_session_releaseref(session, UNLOCKED);
			return (rv);
		}
		rv = mca_parse_key(template, (mca_key_head_t *)buf,
		    residlen, keyflags, &mkey);

		/* free the buffer used for keyhead if it was alloced */
		kmem_free(buf, buflen_alloc);
		buf = NULL;
		if (rv != CRYPTO_SUCCESS) {
			mca_session_releaseref(session, UNLOCKED);
			cpg_attr_free(template);
			return (rv);
		}

		/*
		 * Create the key in the session key table.
		 * Sesion refcnt is dropped.
		 */
		rv = mca_add_key(session, mkey, keyid);
		if (rv != CRYPTO_SUCCESS) {
			mca_key_free(mkey);
		}
	} else {
		/* create key in hardware */
		rv = mca_createkey(mca, session, template, keyid, cfreq,
		    mca_keystore_lookup_by_session(sessionid));
		/*
		 * if the operation fails, the session reference should
		 * be released.
		 */
		if (rv != CRYPTO_QUEUED) {
			/* failure: release the session ref */
			mca_session_releaseref(session, UNLOCKED);
		}

	}

	return (rv);
}

/*
 * Delete the key from the SKT. Free the key if its refcnt goes to zero.
 * The key is already deleted from the card. This function will not fail.
 * As a side effect, the session refcnt is decremented.
 */
void
mca_delete_key(mca_session_t *session, crypto_object_id_t keyid)
{
	mca_key_t	*mkey;
	mca_table_t	*kt;
	int		rv;

	DBG(NULL, DENTRY, "mca_delete_key -->");

	mutex_enter(&(session->ms_lock));

	kt = &session->ms_keytable;

	/* delete the key from the SKT */
	rv = mca_table_lookup(kt, keyid, (void **)&mkey);
	if (rv != DDI_SUCCESS) {
		DBG(NULL, DWARN, "mca_delete_key: KeyID[%d] "
		    "invalid", keyid);
		mca_session_releaseref(session, LOCKED);
		return;
	}
	mca_table_remove_slot(kt, keyid);

	if (mkey->mk_keyflags & KEYFLAG_PERSIST) {
		session->ms_ks_seq++;
	}

	/* drop the session reference and lock */
	mca_session_releaseref(session, LOCKED);

	/* drop the key refcnt for the key table */
	mca_key_releaseref(mkey, UNLOCKED);

	DBG(NULL, DENTRY, "mca_delete_key <--");
}

/*
 * This function deletes a key from the card, UKT, and SKT.
 * If the key is referenced by another thread, the key will be deleted
 * from the table, and marked invalid.
 */
static int
mca_object_destroy(crypto_provider_handle_t provider,
    crypto_session_id_t sessionid, crypto_object_id_t keyid,
    crypto_req_handle_t cfreq)
{
	mca_t			*mca = MCA_PROVIDER2MCA(provider);
	mca_session_t		*session;
	mca_key_t		*mkey;
	int			rv;

	DBG(mca, DENTRY, "mca_object_destroy -->");

	session = mca_session_holdref(mca, sessionid);
	if (session == NULL) {
		DBG(mca, DCHATTY, "mca_object_destroy: session ID[%d] "
		    "invalid", sessionid);
		return (CRYPTO_SESSION_HANDLE_INVALID);
	}

	/*
	 * Turn off the valid flag. By doing so, the refcnt on the key for
	 * the SKT is now owned by this thread. No other thread can access
	 * this key. The slot in the SKT is reserved in case of key deletion
	 * failure in the firmware to preserve the key ID.
	 */
	mkey = invalidate_key(session, keyid);
	if (mkey == NULL) {
		DBG(mca, DWARN, "mca_object_destroy: invalidate_key failed");
		mca_session_releaseref(session, UNLOCKED);
		return (CRYPTO_OBJECT_HANDLE_INVALID);
	}

	/*
	 * mkey is now owned by this thread. Set mk_skt_keyid to this
	 * session's SKT ID so that the key can be deleted from the SKT
	 * when the key deletion in FW is completed.
	 */
	mkey->mk_skt_keyid = keyid;

	if (mkey->mk_keyflags & KEYFLAG_PERSIST) {
		/* delete the key from the card */
		rv = mca_deletekey(mca, session, mkey, cfreq);
		if (rv != CRYPTO_QUEUED) {
			/*
			 * key deletion failure: turn on the valid flag, and
			 * turn on the refcnt on the key. By doing so, the
			 * the refcnt is returned back to the SKT
			 */
			mca_validate_key(mkey);
			mca_session_releaseref(session, UNLOCKED);
		}
		DBG(mca, DENTRY, "mca_object_destroy <--[0x%x]", rv);
		return (rv);
	} else {
		/*
		 * Delete the key from the SKT, and release the session refcnt
		 */
		mca_delete_key(session, keyid);
		DBG(mca, DENTRY, "mca_object_destroy <--");
		return (CRYPTO_SUCCESS);
	}
}

/*
 * get_attributes has the following policy regarding the size of data.
 * If the attr_info_base says that the size is larger than the
 * supplied buffer, CPGR_BUFFER_TOO_SMALL is returned.  Arrays are
 * handled in the obvious way.  Scalar values are converted to the
 * size given in the attr_infobase (or supplied by the setter if
 * CPG_ATTR_OVERRIDE was supplied when the attribute was set), and
 * stored according, with one important exception: If the buffer size
 * is >=8, they are converted to uint64_t's and stored accordingly.
 */

static int
get_attributes(cpg_attr_t *cpgattr, crypto_object_attribute_t *template,
    uint_t acount)
{
	int		i;
	int		rv = CRYPTO_SUCCESS;
	int		rv1;
	uint8_t		issensitive = 0;

	(void) cpg_attr_lookup_uint8(cpgattr, CPGA_SENSITIVE, &issensitive);

	for (i = 0; i < acount; ++i) {
		unsigned int	fieldsize;
		void		*valp;
		uint32_t	attrflags;

		rv1 = cpg_attr_lookup_generic(cpgattr,	template[i].oa_type,
		    &valp, &fieldsize, &attrflags, NULL);

		/*
		 * Promote 4-byte scalar values to 8-byte, if space
		 * allows, and it is really a lookup and it's not
		 * failing.
		 */
		if (rv1 == CRYPTO_SUCCESS &&
		    !(attrflags & CPG_ATTR_ISARRAY) &&
		    template[i].oa_value != NULL &&
		    template[i].oa_value_len >= 8 &&
		    fieldsize == 4) {
			fieldsize = 8;
		}

		if (rv1 == CRYPTO_SUCCESS &&
		    issensitive && attrflags & CPG_ATTR_SENSITIVE) {
			/*
			 * The data is senstive, and has not been
			 * stripped out by the firmware, etc.  Strip
			 * it out at the interface.
			 */
			template[i].oa_value_len = -1;
			rv1 = CRYPTO_ATTRIBUTE_SENSITIVE;
		} else if (rv1) {
			/* some error */
			template[i].oa_value_len = -1;
		} else if (fieldsize == (unsigned int)(-1)) {
			/*
			 * All cases where fieldsize is -1 should have
			 * been handled by the previous cases.
			 */
			cmn_err(CE_WARN, "get_attributes: "
			    "cpg_attr_lookup_generic (type=0x%llx) says "
			    "length is -1.",
			    (unsigned long long)template[i].oa_type);
			rv1 = CRYPTO_GENERAL_ERROR;
		} else if (template[i].oa_value == NULL) {
			/* size query */
			if (!(attrflags & CPG_ATTR_ISARRAY) &&
			    fieldsize == 4) {
				/* special case for CK_ULONG */
				template[i]. oa_value_len = 8;
			} else {
				/* everything else */
				template[i].oa_value_len = fieldsize;
			}
		} else if (attrflags & CPG_ATTR_ISARRAY) {
			/* array  */
			if (fieldsize <= template[i].oa_value_len) {
				template[i].oa_value_len = fieldsize;
				if (valp) {  /* Be safe and avoid a panic */
					bcopy(valp, template[i].oa_value,
					    fieldsize);
				} else if (fieldsize > 0) {
					cmn_err(CE_WARN,
					    "mca: get_attributes: "
					    "cpg_attr_lookup_generic "
					    "(type=0x%llx) returns "
					    "null data pointer (vector case)",
					    (unsigned long
						long)template[i].oa_type);
					template[i].oa_value_len = -1;
					rv1 = CRYPTO_GENERAL_ERROR;
					/* override any previous error */
					rv = rv1;
				}
			} else {
				template[i].oa_value_len = -1;
				rv1 = CRYPTO_BUFFER_TOO_SMALL;
			}
		} else if (fieldsize > template[i].oa_value_len) {
			/* scalar, buffer too small */
			template[i].oa_value_len = -1;
			rv1 = CRYPTO_BUFFER_TOO_SMALL;
		} else if (valp) {
			/* normal scalar case; test valp to avoid a panic */
			switch (fieldsize) {
			case 1:
				*(uint8_t *)template[i].oa_value =
				    (uint8_t)*(uint64_t *)valp;
				break;
			case 2:
				*(uint16_t *)template[i].oa_value =
				    (uint16_t)*(uint64_t *)valp;
				break;
			case 4:
				*(uint32_t *)template[i].oa_value =
				    (uint32_t)*(uint64_t *)valp;
				break;
			case 8:
				*(uint64_t *)template[i].oa_value =
				    *(uint64_t *)valp;
				break;
			default:
				cmn_err(CE_WARN,
				    "mca: get_attributes: invalid length in "
				    "scalar attribute (type=0x%llx, "
				    "vallen = %d)",
				    (unsigned long
					long)template[i].oa_type, fieldsize);
				rv1 = CRYPTO_GENERAL_ERROR;
				rv = rv1; /* override any previous error */
			}
			template[i].oa_value_len = fieldsize;
		} else {
			/* scaler, and valp is NULL (can't happen) */
			cmn_err(CE_WARN, "mca: get_attributes: "
			    "cpg_attr_lookup_generic (type=0x%llx) returns "
			    "null data pointer (scalar case)",
			    (unsigned long long)template[i].oa_type);
			template[i].oa_value_len = -1;
			rv1 = CRYPTO_GENERAL_ERROR;
			rv = rv1;
		}

		if (rv == CRYPTO_SUCCESS) {
			rv = rv1;
		}
	} /* end of for loop */

	return (rv);
}


/*ARGSUSED*/
static int
mca_object_get_attribute_value(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_object_id_t keyid,
    crypto_object_attribute_t *attr, uint_t acount, crypto_req_handle_t cfreq)
{
	mca_t			*mca = MCA_PROVIDER2MCA(provider);
	mca_sessiontable_t	*st;
	mca_session_t		*session;
	mca_key_t		*mkey;
	int			rv;

	DBG(mca, DENTRY, "mca_object_get_attribute_value -->");

	/*
	 * Lookup the key in the session key table, and hold the lock
	 * on the key
	 */

	st = session_table_get(mca, session_id);
	session = session_hold(st, session_id);
	if (session == NULL) {
		DBG(mca, DCHATTY, "mca_object_get_attribute_value: "
		    "session ID[%d] invalid", session_id);
		return (CRYPTO_SESSION_HANDLE_INVALID);
	}
	rv = mca_table_lookup(&session->ms_keytable, keyid, (void **)&mkey);
	if (rv != DDI_SUCCESS) {
		mutex_exit(&(session->ms_lock));
		return (CRYPTO_OBJECT_HANDLE_INVALID);
	}
	mutex_enter(&mkey->mk_lock);
	mutex_exit(&(session->ms_lock));

	rv = get_attributes(mkey->mk_cpgattr, attr, acount);

	mutex_exit(&mkey->mk_lock);

	DBG(mca, DENTRY, "mca_object_get_attribute_value <--[0x%x]", rv);

	return (rv);
}

static int
object_copy(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_object_id_t keyid,
    crypto_object_attribute_t *attr, uint_t acount,
    crypto_object_id_t *newkeyid, crypto_req_handle_t cfreq)
{
	mca_t		*mca = MCA_PROVIDER2MCA(provider);
	mca_session_t	*session;
	mca_key_t	*mkey;
	int		rv;
	cpg_attr_t	*cpgattr;

	DBG(mca, DENTRY, "object_copy-->");

	rv = cryptoattr2cpgattr(attr, acount, &cpgattr, PURE_ATTR_POLICY,
	    NO_FLUFF);
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DCHATTY, "object_copy: "
		    "cryptoattr2cpgattr failed with 0x%x", rv);
		return (rv);
	}

	/*
	 * Lookup the key in the session key table, and hold the lock
	 * on the key
	 */
	session = session_hold(session_table_get(mca, session_id),
			session_id);
	if (session == NULL) {
		DBG(mca, DCHATTY, "object_copy: "
		    "session ID[%d] invalid", session_id);
		cpg_attr_free(cpgattr);
		return (CRYPTO_SESSION_HANDLE_INVALID);
	}
	rv = mca_table_lookup(&session->ms_keytable, keyid, (void **)&mkey);
	if (rv != DDI_SUCCESS) {
		mutex_exit(&(session->ms_lock));
		cpg_attr_free(cpgattr);
		return (CRYPTO_OBJECT_HANDLE_INVALID);
	}
	mutex_enter(&mkey->mk_lock);

	if (mkey->mk_keyflags & KEYFLAG_SENSITIVE) {
		/* hold session refcnt */
		session->ms_refcnt++;
		mutex_exit(&(session->ms_lock));

		/* hold key refcnt */
		mkey->mk_refcnt++;
		mutex_exit(&mkey->mk_lock);

		rv = mca_copykey(mca, session, mkey, cpgattr, newkeyid, cfreq,
		    mca_keystore_lookup_by_session(session_id));
		if (rv != CRYPTO_QUEUED) {
			/* cpgattr was freed by mca_copykey */
			mca_session_releaseref(session, UNLOCKED);
			mca_key_releaseref(mkey, UNLOCKED);
		}
		DBG(mca, DENTRY, "object_copy <--[0x%x]", rv);
		return (rv);
	} else {
		cpg_attr_t	*newattr;
		uint32_t	keyflags;

		mutex_exit(&(session->ms_lock));

		rv = cpg_attr_alloc_dup(mkey->mk_cpgattr, &newattr, 0,
		    CPG_ATTR_NOSLEEP);
		if (rv != CRYPTO_SUCCESS) {
			DBG(mca, DCHATTY, "object_copy: cpg_attr_dup "
			    "failed with 0x%x", rv);
			mutex_exit(&mkey->mk_lock);
			cpg_attr_free(cpgattr);
			return (rv);
		}
		rv = mca_merge_templates4copy(cpgattr, newattr, &keyflags);
		if (rv != CRYPTO_SUCCESS) {
			DBG(mca, DCHATTY, "object_copy: "
			    "mca_merge_templates4copy failed with 0x%x", rv);
			mutex_exit(&mkey->mk_lock);
			cpg_attr_free(newattr);
			cpg_attr_free(cpgattr);
			return (rv);
		}

		mutex_exit(&mkey->mk_lock);

		cpg_attr_free(cpgattr);

		rv = object_create_internal(provider, session_id, newattr,
		    newkeyid, cfreq);
		DBG(mca, DENTRY, "object_copy <--[0x%x]", rv);
		return (rv);
	}
}

static int
object_set_attribute_value(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_object_id_t keyid,
    crypto_object_attribute_t *attr, uint_t acount,
    crypto_req_handle_t cfreq)
{
	mca_t		*mca = MCA_PROVIDER2MCA(provider);
	mca_session_t	*session;
	mca_key_t	*mkey;
	int		rv;
	cpg_attr_t	*template;

	DBG(mca, DENTRY, "object_set_attribute_value -->");

	rv = cryptoattr2cpgattr(attr, acount, &template, PURE_ATTR_POLICY,
	    NO_FLUFF);
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DCHATTY, "object_set_attribute_value: "
		    "cryptoattr2cpgattr failed with 0x%x", rv);
		return (rv);
	}

	/*
	 * Lookup the key in the session key table, and hold the lock
	 * on the key
	 */
	session = session_hold(session_table_get(mca, session_id),
			session_id);
	if (session == NULL) {
		DBG(mca, DCHATTY, "object_set_attribute_value: "
		    "session ID[%d] invalid", session_id);
		cpg_attr_free(template);
		return (CRYPTO_SESSION_HANDLE_INVALID);
	}
	rv = mca_table_lookup(&session->ms_keytable, keyid, (void **)&mkey);
	if (rv != DDI_SUCCESS) {
		mutex_exit(&(session->ms_lock));
		cpg_attr_free(template);
		return (CRYPTO_OBJECT_HANDLE_INVALID);
	}
	mutex_enter(&mkey->mk_lock);

	if (mkey->mk_keyflags & KEYFLAG_PERSIST) {
		cpg_attr_t	*newattr;
		uint32_t	keyflags;

		/* hold session refcnt */
		session->ms_refcnt++;
		mutex_exit(&(session->ms_lock));

		/*
		 * Duplicate the target object's template.  Thus if
		 * mca_modify_key fails, we still have the old
		 * attributes.
		 *
		 * cpg_attr_set_attribute_value not called in
		 * interrupt context.  So CPG_ATTR_NOSLEEP not
		 * provided.
		 */
		rv = cpg_attr_alloc_dup(mkey->mk_cpgattr, &newattr, 0,
		    CPG_ATTR_NOSLEEP);
		if (rv != CRYPTO_SUCCESS) {
			DBG(mca, DCHATTY, "object_copy: cpg_attr_dup "
			    "failed with 0x%x", rv);
			mca_session_releaseref(session, UNLOCKED);
			mutex_exit(&mkey->mk_lock);
			cpg_attr_free(template);
			return (rv);
		}

		rv = mca_merge_templates(template, newattr, &keyflags);
		if (rv != CRYPTO_SUCCESS) {
			mca_session_releaseref(session, UNLOCKED);
			mutex_exit(&mkey->mk_lock);
			cpg_attr_free(newattr);
			cpg_attr_free(template);
			return (rv);
		}

		/* hold key refcnt */
		mkey->mk_refcnt++;
		mutex_exit(&mkey->mk_lock);

		rv = mca_modifykey(mca, session, mkey, newattr, cfreq);
		if (rv != CRYPTO_QUEUED) {
			mca_session_releaseref(session, UNLOCKED);
			mca_key_releaseref(mkey, UNLOCKED);
			cpg_attr_free(newattr);
		}

		cpg_attr_free(template);

		DBG(mca, DENTRY, "object_set_attribute_value <--[0x%x]", rv);

		return (rv);
	} else {
		uint32_t	keyflags;

		mutex_exit(&(session->ms_lock));

		rv = mca_merge_templates(template, mkey->mk_cpgattr, &keyflags);
		if (rv != CRYPTO_SUCCESS) {
			mutex_exit(&mkey->mk_lock);
			cpg_attr_free(template);
			return (rv);
		}

		mkey->mk_keyflags = keyflags | KEYFLAG_VALID;
		mutex_exit(&mkey->mk_lock);
		cpg_attr_free(template);

		DBG(mca, DENTRY, "object_set_attribute_value <--[0x0]");
		return (CRYPTO_SUCCESS);
	}
}


/*
 * Find Object
 */
static void
findobject_free(mca_findobject_t *fo)
{
	int len;
	len = sizeof (mca_findobject_t) + fo->maxobjects * sizeof (int);
	kmem_free(fo, len);
}

static mca_findobject_t *
findobject_realloc(mca_findobject_t *fo)
{
	int len;

	if (fo == (mca_findobject_t *)-1) {
		/* allocate a findobject buf (20 elements) */
		len = sizeof (mca_findobject_t) + (20 * sizeof (int));
		if ((fo = kmem_alloc(len, KM_NOSLEEP)) == NULL) {
			return (NULL);
		}
		fo->maxobjects = 20;
		fo->numobjects = 0;
		fo->objectsreturned = 0;
		return (fo);
	} else if (fo->numobjects == fo->maxobjects) {
		mca_findobject_t *newfo;

		len = sizeof (mca_findobject_t) + fo->maxobjects * sizeof (int);

		/* allocate the new findobject buf (20 more elements) */
		newfo = kmem_alloc(len + 20 * sizeof (int), KM_NOSLEEP);
		if (newfo == NULL) {
			return (NULL);
		}
		bcopy(fo, newfo, len);
		newfo->maxobjects += 20;

		/* free the old findobject buf */
		kmem_free(fo, len);

		return (newfo);
	}
	return (fo);
}

static mca_findobject_t *
findobject_add(mca_findobject_t *fo, int keyid)
{
	int			*keyids;
	mca_findobject_t	*newfo;

	if ((newfo = findobject_realloc(fo)) == NULL) {
		findobject_free(fo);
		return (NULL);
	}

	keyids = (int *)(newfo + 1);
	keyids[newfo->numobjects] = keyid;
	newfo->numobjects++;

	return (newfo);
}


/*
 * This function return CRYPTO_SUCCESS if the template matchs the
 * cpg_attr.  Whether it is an array or scalar comes from the
 * cpg_attribute_list.
 */
static int
findobject_cmp_template(cpg_attr_t *cpgattr,
    crypto_object_attribute_t *template, uint_t acount)
{
	int	i;

	for (i = 0; i < acount; ++i) {
		uint64_t	templval64;
		void		*data_p;
		unsigned int	fieldsize;
		uint32_t	attrinfo;
		int		rvtmpl;

		if ((template[i].oa_value == NULL) &&
		    (template[i].oa_value_len != 0)) {
			/* an attribute has an invalid value pointer */
			return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
		}

		rvtmpl = cpg_attr_lookup_generic(cpgattr, template[i].oa_type,
		    &data_p, &fieldsize, &attrinfo, NULL);
		if (rvtmpl != CRYPTO_SUCCESS) {
			return (rvtmpl);
		}

		if (attrinfo & CPG_ATTR_ISARRAY) {
			/* array */
			if (fieldsize != template[i].oa_value_len) {
				return (CRYPTO_TEMPLATE_INCONSISTENT);
			}
			if (memcmp(data_p, template[i].oa_value, fieldsize)) {
				return (CRYPTO_TEMPLATE_INCONSISTENT);
			}
		} else {
			/* scalar */
			switch (template[i].oa_value_len) {
			case 1:
				templval64 = *(uint8_t *)template[i].oa_value;
				break;
			case 2:
				templval64 = *(uint16_t *)template[i].oa_value;
				break;
			case 4:
				templval64 = *(uint32_t *)template[i].oa_value;
				break;

			case 8:
				templval64 = *(uint64_t *)template[i].oa_value;
				break;
			default:
				return (CRYPTO_TEMPLATE_INCONSISTENT);
			}
			/* do the actual comparison */
			if (templval64 != *(uint64_t *)data_p) {
				return (CRYPTO_TEMPLATE_INCONSISTENT);
			}
		}
	} /* end of for loop */

	return (CRYPTO_SUCCESS);
}


/*ARGSUSED*/
static int
mca_object_find_init(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_object_attribute_t *attr,
    uint_t acount, void **private, crypto_req_handle_t cfreq)
{
	mca_t			*mca = MCA_PROVIDER2MCA(provider);
	mca_session_t		*session;
	mca_table_t		*skt;
	mca_key_t		*mkey;
	int			rv;
	int			keyid = -1;
	mca_findobject_t	*fo = (mca_findobject_t *)-1;

	DBG(mca, DENTRY, "mca_object_find_init -->");

	session = mca_session_holdref(mca, session_id);
	if (session == NULL) {
		DBG(mca, DCHATTY, "mca_object_find_init: session ID[%d] "
		    "invalid", session_id);
		return (CRYPTO_SESSION_HANDLE_INVALID);
	}

	/*
	 * A user has been authenticated to the session. Make sure the SKT
	 * is synchronized with the UKT.
	 */
	if (session->ms_user != NULL) {
		mca_user_rdlock(session->ms_user);
		if (session->ms_user->mu_ks_seq != session->ms_ks_seq) {
			rv = sync_skt(session, session->ms_user);
			if (rv != CRYPTO_SUCCESS) {
				mca_user_unlock(session->ms_user);
				mutex_exit(&(session->ms_lock));
				return (rv);
			}
		}
		mca_user_unlock(session->ms_user);
	}

	mutex_enter(&(session->ms_lock));

	skt = &session->ms_keytable;
	while (mca_table_next_slot(skt, &keyid) != DDI_FAILURE) {
		rv = mca_table_lookup(skt, keyid, (void **)&mkey);
		if (rv != DDI_SUCCESS) {
			continue;
		}

		mutex_enter(&mkey->mk_lock);
		rv = findobject_cmp_template(mkey->mk_cpgattr, attr, acount);
		if (rv == CRYPTO_SUCCESS) {
			/* add this key ID to the list */
			fo = findobject_add(fo, keyid);
			if (fo == NULL) {
				mutex_exit(&mkey->mk_lock);
				mutex_exit(&(session->ms_lock));
				return (CRYPTO_HOST_MEMORY);
			}
		}
		mutex_exit(&mkey->mk_lock);
	}

	*private = fo;


	mca_session_releaseref(session, LOCKED);

	DBG(mca, DENTRY, "mca_object_find_init <--");

	return (CRYPTO_SUCCESS);
}

/*ARGSUSED*/
static int
mca_object_find(crypto_provider_handle_t provider, void *private,
    crypto_object_id_t *keyids, uint_t keymaxcount, uint_t *keycount,
    crypto_req_handle_t cfreq)
{
	mca_findobject_t	*fo = private;
	int			num;
	int			i;
	int			*foundkeyids;

	DBG(NULL, DENTRY, "mca_object_find -->");

	if (fo == (mca_findobject_t *)-1) {
		*keycount = 0;
		return (CRYPTO_SUCCESS);
	} else if (fo == NULL) {
		return (CRYPTO_OPERATION_NOT_INITIALIZED);
	}

	num = min((int)keymaxcount, (fo->numobjects - fo->objectsreturned));
	foundkeyids = (int *)(fo + 1);

	for (i = 0; i < num; i++) {
		keyids[i] = foundkeyids[fo->objectsreturned + i];
	}

	fo->objectsreturned += num;
	*keycount = num;

	DBG(NULL, DENTRY, "mca_object_find [%d returned]<--", *keycount);

	return (CRYPTO_SUCCESS);
}

/*ARGSUSED*/
static int
mca_object_find_final(crypto_provider_handle_t provider, void *private,
    crypto_req_handle_t cfreq)
{
	DBG(NULL, DENTRY, "mca_object_find_final -->");

	if (private == (void *)-1) {
		return (CRYPTO_SUCCESS);
	} else if (private == NULL) {
		return (CRYPTO_OPERATION_NOT_INITIALIZED);
	}

	findobject_free((mca_findobject_t *)private);
	DBG(NULL, DENTRY, "mca_object_find_final <--");
	return (CRYPTO_SUCCESS);
}

static int
mca_key_gen(crypto_provider_handle_t provider, crypto_session_id_t session_id,
    crypto_mechanism_t *mech, crypto_object_attribute_t *attr, uint_t acount,
    crypto_object_id_t *keyid, crypto_req_handle_t cfreq)
{
	mca_t			*mca = MCA_PROVIDER2MCA(provider);
	mca_session_t		*session;
	int			rv;
	cpg_attr_t		*template;
	uint32_t		cmd;

	DBG(mca, DENTRY, "mca_key_gen -->");

	rv = cryptoattr2cpgattr(attr, acount, &template, GENERATE_POLICY,
	    MINI_FLUFF);
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DCHATTY, "mca_key_gen : cryptoattr2cpgattr "
		    "failed with 0x%x", rv);
		return (rv);
	}

	switch (mech->cm_type) {
	case MCAM_DES_KEY_GEN:
		cmd = CMD_KEYGEN_DES;
		break;
	case MCAM_DES2_KEY_GEN:
		cmd = CMD_KEYGEN_DES2;
		break;
	case MCAM_DES3_KEY_GEN:
		cmd = CMD_KEYGEN_DES3;
		break;
	case MCAM_AES_KEY_GEN:
	{
		uint32_t keylen = 0;

		(void) cpg_attr_lookup_uint32(template,
		    CPGA_VALUE_LEN, &keylen);
		switch (keylen) {
		case 16:
			cmd = CMD_KEYGEN_AES16;
			break;
		case 24:
			cmd = CMD_KEYGEN_AES24;
			break;
		case 32:
			cmd = CMD_KEYGEN_AES32;
			break;
		default:
			cpg_attr_free(template);
			return (CRYPTO_TEMPLATE_INCONSISTENT);
		}
		break;
	}
	default:
		cpg_attr_free(template);
		return (CRYPTO_MECHANISM_INVALID);
	}

	session = mca_session_holdref(mca, session_id);
	if (session == NULL) {
		cpg_attr_free(template);
		DBG(mca, DCHATTY, "mca_key_gen : session ID[%d] "
		    "invalid", session_id);
		return (CRYPTO_SESSION_HANDLE_INVALID);
	}

	rv = mca_keygen(mca, mca_keystore_lookup_by_session(session_id),
	    session, template, keyid, cmd, cfreq);
	if (rv != CRYPTO_QUEUED) {
		mca_session_releaseref(session, UNLOCKED);
		cpg_attr_free(template);
	}

	DBG(mca, DENTRY, "mca_key_gen <--[0x%x]", rv);

	return (rv);
}

static int
mca_key_pair_gen(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mech,
    crypto_object_attribute_t *pubattr, uint_t pubacount,
    crypto_object_attribute_t *prvattr, uint_t prvacount,
    crypto_object_id_t *pubkeyid, crypto_object_id_t *prvkeyid,
    crypto_req_handle_t cfreq)
{
	mca_t			*mca = MCA_PROVIDER2MCA(provider);
	mca_session_t		*session;
	mca_keystore_t		*ks;
	int			rv;
	cpg_attr_t		*pubtemplate, *prvtemplate;

	DBG(mca, DENTRY, "mca_key_pair_gen -->");

	rv = cryptoattr2cpgattr(pubattr, pubacount, &pubtemplate,
	    GENERATE_POLICY, MINI_FLUFF);
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DCHATTY, "mca_key_pair_gen : cryptoattr2cpgattr "
		    "failed with 0x%x", rv);
		return (rv);
	}
	rv = cryptoattr2cpgattr(prvattr, prvacount, &prvtemplate,
	    GENERATE_POLICY, MINI_FLUFF);
	if (rv != CRYPTO_SUCCESS) {
		cpg_attr_free(pubtemplate);
		DBG(mca, DCHATTY, "mca_key_pair_gen : cryptoattr2cpgattr "
		    "failed with 0x%x", rv);
		return (rv);
	}

	session = mca_session_holdref(mca, session_id);
	if (session == NULL) {
		DBG(mca, DCHATTY, "mca_key_pair_gen : session ID[%d] "
		    "invalid", session_id);
		cpg_attr_free(pubtemplate);
		cpg_attr_free(prvtemplate);
		return (CRYPTO_SESSION_HANDLE_INVALID);
	}

	ks = mca_keystore_lookup_by_session(session_id);

	switch (mech->cm_type) {
	case MCAM_RSA_KEY_PAIR_GEN:
		rv = mca_rsagen(mca, session, pubtemplate, prvtemplate,
		    pubkeyid, prvkeyid, cfreq, ks);
		break;
	case MCAM_DSA_KEY_PAIR_GEN:
		rv = mca_dsagen(mca, session, pubtemplate, prvtemplate,
		    pubkeyid, prvkeyid, cfreq, ks);
		break;
	case MCAM_DH_PKCS_KEY_PAIR_GEN:
		rv = mca_dhgen(mca, session, pubtemplate, prvtemplate,
		    pubkeyid, prvkeyid, cfreq, ks);
		break;
	case MCAM_EC_KEY_PAIR_GEN:
	case MCAM_ECDSA_KEY_PAIR_GEN:
		rv = mca_ecgen(mca, session, pubtemplate, prvtemplate,
		    pubkeyid, prvkeyid, cfreq, ks);
		break;
	default:
		rv = CRYPTO_MECHANISM_INVALID;
	}

	if (rv != CRYPTO_QUEUED) {
		mca_session_releaseref(session, UNLOCKED);
		cpg_attr_free(pubtemplate);
		cpg_attr_free(prvtemplate);
	}

	DBG(mca, DENTRY, "mca_key_pair_gen <--[0x%x]", rv);

	return (rv);
}


/*
 * Wrap/Unwrap Key
 */

static int
mca_key_wrap(crypto_provider_handle_t provider, crypto_session_id_t session_id,
    crypto_mechanism_t *mech, crypto_key_t *wrappingkey,
    crypto_object_id_t *keyid, uchar_t *buf, size_t *bufsz,
    crypto_req_handle_t cfreq)
{
	mca_t			*mca = MCA_PROVIDER2MCA(provider);
	crypto_key_t		key;
	int			rv;
	int			cmd;

	DBG(mca, DENTRY, "mca_key_wrap -->");

	key.ck_format = CRYPTO_KEY_REFERENCE;
	key.ck_obj_id = *keyid;

	switch (mech->cm_type) {
	case MCAM_DES_CBC_PAD:
		cmd = CMD_HI_PAD | CMD_HI_SINGLE | CMD_3DESDEC;
		break;
	case MCAM_DES_CBC:
		cmd = CMD_HI_SINGLE | CMD_3DESDEC;
		break;
	case MCAM_DES3_CBC_PAD:
		cmd = CMD_HI_PAD | CMD_3DESDEC;
		break;
	case MCAM_DES3_CBC:
		cmd = CMD_3DESDEC;
		break;
	case MCAM_AES_CBC_PAD:
		cmd = CMD_HI_PAD | CMD_AESCBCDEC;
		break;
	case MCAM_AES_CBC:
		cmd = CMD_AESCBCDEC;
		break;
	case MCAM_AES_CTR:
#ifdef	DEBUG
	case MCAM_CPG_AES_CTR:
#endif
		cmd = CMD_AESCTRDEC;
		break;
	case MCAM_AES_KEY_WRAP:
		cmd = MCA_CMD_AES_KEY_WRAP;
		break;
	case MCAM_RC2_CBC_PAD:
		/* RC2 is not a FIPS approved algorithm */
		if (mca_isfips(mca)) {
			return (CRYPTO_MECHANISM_INVALID);
		}
		cmd = CMD_HI_PAD | CMD_RC2DEC;
		break;
	case MCAM_RC2_CBC:
		/* RC2 is not a FIPS approved algorithm */
		if (mca_isfips(mca)) {
			return (CRYPTO_MECHANISM_INVALID);
		}
		cmd = CMD_RC2DEC;
		break;
	case MCAM_RSA_X_509:
		cmd = CMD_RSAPUB;
		break;
	case MCAM_RSA_PKCS:
		cmd = CMD_RSAPADENC;
		break;
	default:
		*bufsz = 0;
		return (CRYPTO_MECHANISM_INVALID);
	}

	rv = mca_common_wrap(mca, session_id, mech, wrappingkey, &key,
	    buf, bufsz, cfreq, cmd);
	if ((rv != CRYPTO_QUEUED) && (rv != CRYPTO_SUCCESS) &&
	    (rv != CRYPTO_BUFFER_TOO_SMALL)) {
		*bufsz = 0;
	}

	DBG(mca, DENTRY, "mca_key_wrap <--[0x%x]", rv);

	return (rv);
}

static int
mca_key_unwrap(crypto_provider_handle_t provider,
    crypto_session_id_t sessionid, crypto_mechanism_t *mech,
    crypto_key_t *wrappingkey, uchar_t *buf, size_t *buflen,
    crypto_object_attribute_t *attr, uint_t attrnum,
    crypto_object_id_t *keyid, crypto_req_handle_t cfreq)
{
	mca_t		*mca = MCA_PROVIDER2MCA(provider);
	int		rv;
	cpg_attr_t	*template;
	uint32_t	cmd = 0;

	DBG(mca, DENTRY, "mca_key_unwrap -->");

	rv = cryptoattr2cpgattr(attr, attrnum, &template, UNWRAP_POLICY,
	    MINI_FLUFF);
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DCHATTY, "mca_key_unwrap: cryptoattr2cpgattr "
		    "failed with 0x%x", rv);
		return (rv);
	}

	switch (mech->cm_type) {
	case MCAM_DES_CBC_PAD:
		cmd = CMD_HI_PAD | CMD_HI_SINGLE | CMD_3DESDEC;
		break;
	case MCAM_DES_CBC:
		cmd = CMD_HI_SINGLE | CMD_3DESDEC;
		break;
	case MCAM_DES3_CBC_PAD:
		cmd = CMD_HI_PAD | CMD_3DESDEC;
		break;
	case MCAM_DES3_CBC:
		cmd = CMD_3DESDEC;
		break;
	case MCAM_AES_CBC_PAD:
		cmd = CMD_HI_PAD | CMD_AESCBCDEC;
		break;
	case MCAM_AES_CBC:
		cmd = CMD_AESCBCDEC;
		break;
	case MCAM_AES_KEY_WRAP:
		cmd = MCA_CMD_AES_KEY_WRAP;
		break;
	case MCAM_AES_CTR:
#ifdef	DEBUG
	case MCAM_CPG_AES_CTR:
#endif
		cmd = CMD_AESCTRDEC;
		break;
	case MCAM_RC2_CBC_PAD:
		/* RC2 is not a FIPS approved algorithm */
		if (mca_isfips(mca)) {
			return (CRYPTO_MECHANISM_INVALID);
		}
		cmd = CMD_HI_PAD | CMD_RC2DEC;
		break;
	case MCAM_RC2_CBC:
		/* RC2 is not a FIPS approved algorithm */
		if (mca_isfips(mca)) {
			return (CRYPTO_MECHANISM_INVALID);
		}
		cmd = CMD_RC2DEC;
		break;
	case MCAM_RSA_X_509:
		cmd = CMD_RSAPRV;
		break;
	case MCAM_RSA_PKCS:
		cmd = CMD_RSAPADDEC;
		break;
	default:
		cpg_attr_free(template);
		return (CRYPTO_MECHANISM_INVALID);
	}

	rv = mca_common_unwrap(mca, sessionid, mech, wrappingkey, buf,
	    *buflen, template, keyid, cfreq, cmd);
	if ((rv != CRYPTO_QUEUED) && (rv != CRYPTO_SUCCESS)) {
		cpg_attr_free(template);
	}

	DBG(mca, DENTRY, "mca_key_unwrap <--[0x%x]", rv);

	return (rv);
}

static int
mca_key_derive(crypto_provider_handle_t provider,
    crypto_session_id_t sessionid, crypto_mechanism_t *mech,
    crypto_key_t *key, crypto_object_attribute_t *attr, uint_t attrnum,
    crypto_object_id_t *keyid, crypto_req_handle_t cfreq)
{
	mca_t		*mca = MCA_PROVIDER2MCA(provider);
	int		rv;
	cpg_attr_t	*template;

	DBG(mca, DENTRY, "mca_key_derive-->");

	rv = cryptoattr2cpgattr(attr, attrnum, &template, PURE_ATTR_POLICY,
	    NO_FLUFF);
	if (rv != CRYPTO_SUCCESS) {
		DBG(mca, DCHATTY, "mca_key_derive: cryptoattr2cpgattr "
		    "failed with 0x%x", rv);
		return (rv);
	}

	switch (mech->cm_type) {
	case MCAM_DH_PKCS_DERIVE:
		rv = mca_dh_derive(mca, sessionid, mech, key, template,
		    keyid, cfreq);
		break;
	case MCAM_ECDH1_DERIVE:
		rv = mca_ec_derive(mca, sessionid, mech, key, template,
		    keyid, cfreq);
		break;
	default:
		rv = CRYPTO_MECHANISM_INVALID;
		break;
	}

	if ((rv != CRYPTO_QUEUED) && (rv != CRYPTO_SUCCESS)) {
		cpg_attr_free(template);
	}

	DBG(mca, DENTRY, "mca_key_derive<--[0x%x]", rv);

	return (rv);
}


static int
nullparam_allocmech(crypto_mechanism_t *inmech, crypto_mechanism_t *outmech,
    int *error, int mode)
{
	STRUCT_DECL(crypto_mechanism, mech);
	size_t			paramlen;

	DBG(NULL, DENTRY, "mca_aes_ctr_allocmech -->");

	*error = CRYPTO_SUCCESS;

	STRUCT_INIT(mech, mode);
	bcopy(inmech, STRUCT_BUF(mech), STRUCT_SIZE(mech));
	paramlen = STRUCT_FGET(mech, cm_param_len);

	if (paramlen != 0) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	outmech->cm_type = STRUCT_FGET(mech, cm_type);
	outmech->cm_param = NULL;
	outmech->cm_param_len = 0;

	return (CRYPTO_SUCCESS);
}



/*ARGSUSED*/
static int
mca_allocate_mechanism(crypto_provider_handle_t provider,
    crypto_mechanism_t *in_mech, crypto_mechanism_t *out_mech,
    int *error, int mode)
{
	DBG(NULL, DENTRY, "mca_allocate_mechanism entered");

	*error = 0;	/* system related error */

	switch (out_mech->cm_type) {
	case MCAM_AES_CTR:
	case MCAM_CPG_AES_CTR:
		return (mca_aes_ctr_allocmech(in_mech, out_mech, error, mode));
	case MCAM_EC_KEY_PAIR_GEN:
	case MCAM_ECDSA_KEY_PAIR_GEN:
	case MCAM_SHA_1_HMAC:
	case MCAM_SHA512_HMAC:
	case MCAM_MD5_HMAC:
		/* make sure there is no parameter */
		return (nullparam_allocmech(in_mech, out_mech, error, mode));
	case MCAM_ECDH1_DERIVE:
		return (mca_ecdh1_allocmech(in_mech, out_mech, error, mode));
	default:
		/* crypto module does alloc/copyin of flat params */
		DBG(NULL, DENTRY, "mca_allocate_mechanism <- [%d]",
		    out_mech->cm_type);
		return (CRYPTO_NOT_SUPPORTED);
	}
}

/*ARGSUSED*/
static int
mca_free_mechanism(crypto_provider_handle_t provider,
    crypto_mechanism_t *mech)
{
	DBG(NULL, DENTRY, "mca_free_mechanism entered");
	switch (mech->cm_type) {
	case MCAM_AES_CTR:
	case MCAM_CPG_AES_CTR:
		return (mca_aes_ctr_freemech(mech));
	case MCAM_ECDH1_DERIVE:
		return (mca_ecdh1_freemech(mech));
	default:
		DBG(NULL, DENTRY, "mca_free_mechanism <- [%d]", mech->cm_type);
		return (CRYPTO_NOT_SUPPORTED);
	}
}

/*
 * This function returns TRUE if the session is not busy.
 * Note: The session is busy if there is at least one key in the SKT, or
 * a user is logged into the session.
 * Note: The mutex on the session must be held by the caller
 */
static int
session_DR_safe(mca_session_t *session)
{
	int		rv;
	int		id = -1;

	/* Check to see if there is a key in the SKT */
	rv = mca_table_next_slot(&session->ms_keytable, &id);
	if ((rv == DDI_SUCCESS) && (id != -1)) {
		/*
		 * There is at least one key in the SKT. The session is busy.
		 */
		return (FALSE);
	}

	if (session->ms_flags & MSF_AUTHENTICATED) {
		/*
		 * A user is logged on to the session. The session is busy
		 */
		return (FALSE);
	}

	return (TRUE);
}

/*
 * This function returns TRUE if the provider is not busy.
 * Note: The provider is busy, if for all session on the provider, there
 * is more than one key in the SKT or a user is logged into the session.
 * Note: The mutex on the session table must not be held by the caller
 */
int
mca_provider_DR_safe(mca_sessiontable_t *st)
{
	int	id = -1;

	mutex_enter(&(st->mst_lock));

	while (mca_table_next_slot(&(st->mst_table), &id) != DDI_FAILURE) {
		mca_session_t	*session;

		(void) mca_table_lookup(&(st->mst_table),
		    id, (void **)&session);

		mutex_enter(&(session->ms_lock));
		if (session_DR_safe(session) == FALSE) {
			mutex_exit(&(session->ms_lock));
			mutex_exit(&(st->mst_lock));
			return (FALSE);
		}
		mutex_exit(&(session->ms_lock));
	}

	mutex_exit(&(st->mst_lock));

	return (TRUE);
}


/*
 * mca_provider_in_use()
 *
 * see if the provider is in use (for DR).  The criteria for this
 * determination is as follows:
 *
 * 	1) a user is logged in or more than one key on the real provider
 *	2) a user is logged in or more than one key on the logical provider
 *	   and there is only a single associated real provider.
 *
 * returns: TRUE if in use
 *	    FALSE otherwise.
 */
int
mca_provider_in_use(mca_t *mca)
{
	mca_sessiontable_t	*st;

	/*
	 * If the mca is unregistered (session table is freed),
	 * the provider is not in use.
	 */
	if (mca_isunregistered(mca)) {
		return (FALSE);
	}

	/* check if the real provider is DR safe */
	st = &mca->mca_sessiontable;
	if (mca_provider_DR_safe(st) == FALSE) {
		/* the provider is not DR safe: busy */
		return (TRUE);
	}

	/*
	 * If the mca instance is associated with a keystore, its logical
	 * provider must also be examined.
	 */
	if (mca->mca_keystore_count == 0) {
		/*
		 * The provider is DR-safe and it is not associated with a
		 * logical provider. The device can be removed.
		 */
		return (FALSE);
	}

	/*
	 * If all associated keystores have more than one real
	 * provider, the device can be removed.
	 */

	if (mca_keystore_DR_safe(mca) == FALSE) {
		return (TRUE);
	}

	return (FALSE);
}
