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

#ifndef	_SYS_MCA_H
#define	_SYS_MCA_H

#pragma ident	"@(#)mca.h	1.83	08/12/02 SMI"

#ifdef LINUX
#include <linux/types.h>
#include <linux/pci.h>
#include <mca_cf.h>
#include <mca_log.h>
#include <mca_csrs.h>
#include <spi.h>
#include <common.h>
#include <cpg_attr.h>
#include <mcactl.h>
#include <cpg_cmd.h>
#include <os_api.h>
#include <mca_csrs.h>
#else
#include <sys/types.h>
#include <sys/taskq.h>
#include <inet/common.h>
#include <sys/dlpi.h>
#include <sys/mca_cf.h>
#include <sys/mcactl.h>
#include <sys/mca_log.h>
#include <sys/mca_csrs.h>
#include <sys/pci.h>
#include <sys/crypto/spi.h>
#include <sys/crypto/common.h>
#include <sys/cpg_attr.h>
#include <sys/cpg_cmd.h>
#include <sys/os_api.h>
#include <sys/mca_csrs.h>
#endif
#ifdef FMA_COMPLIANT
#include <sys/fm/protocol.h>
#endif

#include "../work_ex.h"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Mars - pure cryptographic acceleration + secure keystore
 *
 * Note: Everything in this file is private to the Mars device
 *	 driver!  Do not include this in any other file.
 */

#ifdef _KERNEL

/*
 * Well known constant symbols
 */

#ifndef TRUE
#define	TRUE 1
#else
#if TRUE != 1
#error
#endif
#endif

#ifndef FALSE
#define	FALSE 0
#else
#if FALSE != 0
#error
#endif
#endif

/*
 * NO_SLEEP stuff
 */

#if !defined(TQ_NOSLEEP)
#define	TQ_NOSLEEP	KM_NOSLEEP /* cannot block for memory; may fail */
#endif

/* this must be large enough for keystore update */
#define	OMTIMEOUT	drv_usectohz(10 * SECOND)

/* delay to wait for firmware to come up */
#define	MCA_ENABLE_DELAY	drv_usectohz(1 * SECOND)

/* 1.0 needs more time */
#define	MCA_ENABLE_DELAY_1_0	drv_usectohz(3 * SECOND)

/* delay to allow firmware to process the host absent command */
#define	MCA_DISABLE_DELAY	1

/*
 * The new cpg_attr system provides in infobase with many possible
 * policies.  Some policies (the higher numbered ones) describe
 * requirements for templates for different kinds of operations.  Some
 * policies (the lower numbered ones) describe objects resident in the
 * system.  The NULL_POLICY means that there are not restrictions, and
 * no defaults.  (At present it applies only to legacy objects in
 * keystores created by Venus.)  Eventually we may have different
 * defaults for different kinds of objects, but right now all objects
 * created in Mars have ACTIVE_OBJECT_POLICY.  (Note that as soon as
 * we really do anything with the policy stored in the object making a
 * difference, we will ahve to lock in the meaning and numbering of
 * policies.)  The higher numbered policies are used with templates
 * supplied for various kinds of operations.
 */


#define	NULL_POLICY 0
#define	ACTIVE_OBJECT_POLICY 1
#define	PURE_ATTR_POLICY 2
#define	CREATE_POLICY 3
#define	GENERATE_POLICY 4
#define	UNWRAP_POLICY 5

/*
 * The cpg_attr system has a current policy in the data part, and that
 * is stored with cpg_attr_store data, and set with
 * cpg_attr_attach_data.  But we do not want to use that.  So right
 * after every call to cpg_attr_attach_data and as part of object
 * creation, generation, etc., there should be a call to
 * cpg_attr_set_policy to set it to ACTIVE_OBJECT_POLICY.  Overwriting
 * the value immediately after getting it from the keystore relieves
 * us from having to lock down the meaning of these numbers.
 */

/* And here is the policy structure */
extern cpg_attr_infobase_t mca_global_attr_infobase;


/*
 * Tunables.
 */

/* the RINGSIZE and RINGSIZEVAL must be changed together */
#define	RINGSIZE	128	/* must power of 2,  32 <= x <= 8192 */
#define	RINGSIZEVAL	2	/* value to use in conf register */

#define	CBLOWATER	123
#define	CBHIWATER	124

#define	CALOWATER	123
#define	CAHIWATER	124

#define	OMLOWATER	115
#define	OMHIWATER	116	/* reduced to leave room for DBM requests */

#define	MCA_IDNUM	0x7663	/* hex for "vc" */
#define	MCA_IDNAME	"mca"
#define	MCA_TASKQNAME	"mca_taskq"
#define	MCA_MINPSZ	(0)
#define	MCA_MAXPSZ	(ETHERMTU + 14)
#define	MCA_HIWAT	(96 * MCA_MAXPSZ)	/* XXX: from where? */
#define	MCA_LOWAT	(1)
#define	MCA_MAXINST	0x3ff
#define	MCA_CLONEBASE	(MCA_MAXINST + 1)
#define	MCA_STRCHUNK	16	/* number of minors to alloc at a time */

#define	MCA_BOOT_VERSION(mca)		GETCSR32(mca, CSR_BOOT_VERSION)
#define	MCA_BOOT_MAJOR_VERSION(mca)	MCA_MAJOR_VERSION(MCA_BOOT_VERSION(mca))
#define	MCA_BOOT_MINOR_VERSION(mca)	MCA_MINOR_VERSION(MCA_BOOT_VERSION(mca))
#define	MCA_BOOT_MICRO_VERSION(mca)	MCA_MICRO_VERSION(MCA_BOOT_VERSION(mca))
#define	MCA_FW_VERSION(mca)		GETCSR32(mca, CSR_FWVERSION)
#define	MCA_FW_MAJOR_VERSION(mca)	MCA_MAJOR_VERSION(MCA_FW_VERSION(mca))
#define	MCA_FW_MINOR_VERSION(mca)	MCA_MINOR_VERSION(MCA_FW_VERSION(mca))
#define	MCA_FW_MICRO_VERSION(mca)	MCA_MICRO_VERSION(MCA_FW_VERSION(mca))
#define	MCA_HW_VERSION(mca)		GETCSR32(mca, CSR_HWVERSION)
#define	MCA_HW_MAJOR_VERSION(mca)	MCA_MAJOR_VERSION(MCA_HW_VERSION(mca))
#define	MCA_HW_MINOR_VERSION(mca)	MCA_MINOR_VERSION(MCA_HW_VERSION(mca))
#define	MCA_HW_MICRO_VERSION(mca)	MCA_MICRO_VERSION(MCA_HW_VERSION(mca))
#define	MCA_FW_IF_VERSION(mca)		GETCSR32(mca, CSR_IFVERSION)
#define	MCA_FW_IF_MAJOR_VERSION(mca)	MCA_MAJOR_VERSION \
					(MCA_FW_IF_VERSION(mca))
#define	MCA_FW_IF_MINOR_VERSION(mca)	MCA_MINOR_VERSION \
					(MCA_FW_IF_VERSION(mca))
#define	MCA_FW_IF_MICRO_VERSION(mca)	MCA_MICRO_VERSION \
					(MCA_FW_IF_VERSION(mca))
#define	MCA_FW_IF_COMP_VERSION(mca)	MCA_MAJ_MIN_VERSION \
					(MCA_FW_IF_VERSION(mca))


/*
 * These are constants.  Do not change them.
 */

/*
 * Currently, the i86pc rootnex module allocates an intermediate DMA buffer
 * that is only 64k bytes big.  In order to handle buffers that may not be
 * page-aligned, the maximum size buffer that can be copied to this
 * intermediate buffer is 0x10000 - 0x1000 [64k - 4k].
 *
 * The Venus card has 2 Broadcom crypto chips built-in.  These chips may
 * handle buffers up to 64k in length.  Therefore, we have defined the
 * maximum size of a crypto packet to be 64k (minus the size of a DES block).
 *
 * The problem is that on an i86pc system with more than 2Gb of memory,
 * after an initial period of success, many calls to
 * ddi_dma_addr_bind_handle() fail.  The error returned is DMA_TOO_BIG.
 * It is because our maximum-sized packet is a few thousand bytes too
 * big for the rootnex's intermediate buffer.
 *
 * Therefore, we have shrunk MAXPACKET to a more manageable 0xefff for
 * i86pc systems.  That is, we shrank it by MMU_PAGESIZE, or 4096
 * bytes (in i86pc kernels).
 *
 * N.B. This will go away, once Solaris has been updated with the two
 * fixes we've requested.  Perhaps as early as S10U2.
 */

#if defined(i386) || defined(__i386) || defined(__amd64)
#define	MAXPACKET	0xefff	/* rootnex INT_MAX_BUF hack. */
#else
#define	MAXPACKET	0xffff	/* Max size of a packet or fragment */
#endif

#define	DESBLOCK	8	/* Size of a DES or 3DES block */
#define	AESBLOCK	16	/* Size of an AES block */
#define	RC2BLOCK	8	/* Size of a RC2 block */
#define	DSAPARTLEN	20	/* Size of fixed DSA parts (r, s, q, x, v) */
#define	DSASIGLEN	40	/* Size of a DSA signature */
#define	SHA1LEN		20	/* Size of a SHA1 hash */
#define	SHA512LEN	64	/* Size of a SHA512 hash */
#define	MD5LEN		16	/* Size of an MD5 hash */

#define	VENDOR		"Sun Microsystems, Inc."
#define	MODEL		"Sun Crypto Accelerator 6000"
#define	MAXKSSIZE	(16 * 1024 * 1024)
#define	RSA_MIN_KEY_LEN	256	/* in bits */
#define	RSA_MAX_KEY_LEN	2048	/* in bits */
#define	DSA_MIN_KEY_LEN	512	/* in bits */
#define	DSA_MAX_KEY_LEN	1024	/* in bits */
#define	DH_MIN_KEY_LEN	64	/* in bits */
#define	DH_MAX_KEY_LEN	2048	/* in bits */
#define	EC_MIN_KEY_LEN	163	/* in bits */
#define	EC_MAX_KEY_LEN	571	/* in bits */
#define	DES_KEY_LEN	8	/* in bytes */
#define	DES2_KEY_LEN	16	/* in bytes */
#define	DES3_KEY_LEN	24	/* in bytes */
#define	AES_MIN_KEY_LEN	16	/* in bytes */
#define	AES_MAX_KEY_LEN	32	/* in bytes */
#define	RC2_MIN_KEY_LEN	1	/* in bytes */
#define	RC2_MAX_KEY_LEN	128	/* in bytes */
#define	HMAC_MIN_KEY_LEN	1
#define	HMAC_MAX_KEY_LEN	MAX_KEY_SIZE

#define	FM_MSG_SZ	128	/* Maximum size of FMA message string */

#define	MCA_MAX_FW_SZ	(3 * 1024 * 1024) /* Max size of a firmware image */

#define	SECOND		1000000		/* One second in usec */
#define	HALF_SECOND    	(SECOND / 2)	/* Half a second in usec */
#define	QUARTER_SECOND	(SECOND / 4)	/* Quarter of a second in usec */
#define	MSEC		1000		/* One millisecond in usec */


/*
 * Mechanism type used for Wrap operation
 */
#define	MCA_WRAP_MECH_DES3_CBC		0
#define	MCA_WRAP_MECH_DES3_CBC_PAD	1
#define	MCA_WRAP_MECH_AES_CBC_PAD	2
#define	MCA_WRAP_MECH_AES_CBC		3
#define	MCA_WRAP_MECH_AES_ECB		4
#define	MCA_WRAP_MECH_RC2_CBC_PAD	5
#define	MCA_WRAP_MECH_RC2_CBC		6
#define	MCA_WRAP_MECH_RC2_ECB		7
#define	MCA_WRAP_MECH_RSA_X509		8
#define	MCA_WRAP_MECH_RSA_PKCS		9
#define	MCA_WRAP_MECH_AES_CTR		10
#define	MCA_WRAP_MECH_RSA_OAEP		11
#define	MCA_WRAP_MECH_AES_KEY_WRAP	12

/*
 * opcode
 */
#define	COPCODE_CREATE		1
#define	COPCODE_GENERATE	2
#define	COPCODE_USE		3
#define	COPCODE_UNWRAP		4
#define	COPCODE_WRAP		5
#define	COPCODE_MODIFY		6
#define	COPCODE_DUP		7

#define	LOCKED		1
#define	UNLOCKED	0

/*
 * Fields within a descriptor (data buffer chain).
 * +-------+-----------+--------+------+
 * | paddr | nextpaddr | length | rsvd |
 * +-------+-----------+--------+------+
 */
#define	DESC_BUFADDR	0	/* 32 bits */
#define	DESC_NEXT	4	/* 32 bits */
#define	DESC_LENGTH	8	/* 16 bits */
#define	DESC_RSVD	10	/* 16 bits */
#define	DESC_SIZE	16	/* ROUNDUP(12, 16) - descriptor size (bytes) */

/*
 * The chained buffer-descriptor array is stored in key_kaddr, after the
 * key or certificate stored at location 0.  4K is reserved for the descr array.
 */
#define	MAX_KEY_SIZE	(MAXPACKET - 4096)
#define	DESC_OFFSET	(MAX_KEY_SIZE + 1)

/*
 * DMA_COOKIE_MAX is the maxiumum numbers of cookies that the firmware
 * can process per DMA transfer.  For example, during a firmware upgrade.
 *
 * DMA_CRYPTO_COOKIE_MAX is the maxiumum numbers of cookies (buffer
 * descriptors) that we can fit inside a key buffer, after setting aside
 * MAX_KEY_SIZE bytes for the key or certificate itself.
 */
#define	DMA_COOKIE_MAX		510
#define	DMA_CRYPTO_COOKIE_MAX	17

/*
 * Username and Password max length
 */
#define	MAX_USERNAMESZ		126
#define	MAX_PASSSZ		126
#define	MAX_PINSZ		(MAX_USERNAMESZ + MAX_PASSSZ + 1)


/*
 * Forward typedefs.
 */
typedef struct mca mca_t;
typedef struct mca_listnode mca_listnode_t;
typedef struct mca_submission mca_submission_t;
typedef struct mca_completion mca_completion_t;
typedef struct mca_ring mca_ring_t;
typedef struct mca_request mca_request_t;
typedef struct mca_privatectx mca_privatectx_t;
typedef struct mca_stat mca_stat_t;
typedef struct mca_cookie mca_cookie_t;
typedef struct mca_str mca_str_t;
typedef	struct mca_ks_handle mca_ks_handle_t;
typedef struct mca_keystore mca_keystore_t;
typedef struct mca_key mca_key_t;
typedef struct mca_user mca_user_t;
typedef struct mca_session mca_session_t;
typedef struct mca_key_head mca_key_head_t;
typedef struct mca_aes_key mca_aes_key_t;
typedef struct mca_sa_hdr mca_sa_hdr_t;
typedef struct mca_sa mca_sa_t;
typedef struct mca_sadb_ent mca_sadb_ent_t;
typedef	struct mca_sadb mca_sadb_t;

/*
 * Linked-list linkage.
 */
struct mca_listnode {
	mca_listnode_t		*ml_next;
	mca_listnode_t		*ml_prev;
};

#define	AES_32BIT_KS	32
#define	AES_64BIT_KS	64
#define	MAX_AES_NR	14
#define	MAX_KTI_NAME_SZ	33
#define	MAX_KTI_PASS_SZ	33
#define	MAX_KTK_SZ	32

typedef union {
	uint64_t	ks64[(MAX_AES_NR + 1) * 4];
	uint32_t	ks32[(MAX_AES_NR + 1) * 4];
} mca_aes_ks_t;

struct mca_aes_key {
	int		nr;
	int		type;
	mca_aes_ks_t	encr_ks;
	mca_aes_ks_t	decr_ks;
};

typedef struct mca_kti_data {
	uint32_t	size;			/* KTK size in bytes */
	uint8_t		data[MAX_KTK_SZ];	/* KTK data */
	char		name[MAX_KTI_NAME_SZ];	/* KTI client name */
	char		pass[MAX_KTI_PASS_SZ];	/* KTI client passwd */
} mca_kti_data_t;


typedef struct mca_chain {
	ddi_dma_handle_t	mc_dmah;
	caddr_t			mc_kaddr;	/* kaddr of first buf */
	uint32_t		mc_paddr;	/* paddr of first buf */
	size_t			mc_length;	/* sz of first buf */
	uint32_t		mc_next_paddr;	/* paddr of 2nd dscr */
	caddr_t			mc_desc_head;	/* kaddr of 2nd dscr */
	int			mc_saved_dscr_index;
	uint32_t		mc_saved_next_paddr;
	uint16_t		mc_saved_length;
} mca_chain_t;

#define	mr_ibuf_sz		mr_ibuf_chain.mc_length
#define	mr_ibuf_dmah		mr_ibuf_chain.mc_dmah
#define	mr_ibuf_kaddr		mr_ibuf_chain.mc_kaddr
#define	mr_ibuf_paddr		mr_ibuf_chain.mc_paddr
#define	mr_ibuf_next_paddr	mr_ibuf_chain.mc_next_paddr
#define	mr_obuf_sz		mr_obuf_chain.mc_length
#define	mr_obuf_dmah		mr_obuf_chain.mc_dmah
#define	mr_obuf_kaddr		mr_obuf_chain.mc_kaddr
#define	mr_obuf_paddr		mr_obuf_chain.mc_paddr
#define	mr_obuf_next_paddr	mr_obuf_chain.mc_next_paddr
#define	mr_in_direct_length	mr_in_direct_dma_chain.mc_length
#define	mr_in_direct_dmah	mr_in_direct_dma_chain.mc_dmah
#define	mr_in_direct_kaddr	mr_in_direct_dma_chain.mc_kaddr
#define	mr_in_direct_paddr	mr_in_direct_dma_chain.mc_paddr
#define	mr_in_direct_next_paddr	mr_in_direct_dma_chain.mc_next_paddr
#define	mr_out_direct_length	mr_out_direct_dma_chain.mc_length
#define	mr_out_direct_dmah	mr_out_direct_dma_chain.mc_dmah
#define	mr_out_direct_kaddr	mr_out_direct_dma_chain.mc_kaddr
#define	mr_out_direct_paddr	mr_out_direct_dma_chain.mc_paddr
#define	mr_out_direct_next_paddr	mr_out_direct_dma_chain.mc_next_paddr
#define	mr_key_dmah		mr_key_chain.mc_dmah
#define	mr_key_kaddr		mr_key_chain.mc_kaddr
#define	mr_key_paddr		mr_key_chain.mc_paddr
#define	mr_key_chain_head	mr_key_chain.mc_desc_head
#define	mr_key_chain_paddr	mr_key_chain.mc_next_paddr

typedef mca_channel_t mca_app_handle_t;

/*
 * Request structure.  One of these per actual job submitted to the
 * device.  Contains everything we need to submit the job, and
 * everything we need to notify caller and release resources when the
 * completion interrupt comes.
 */
struct mca_request {
#ifdef LINUX
	/* This needs to be on the first line */
	struct work_ex_struct	taskq;
#endif
	mca_listnode_t		mr_linkage;
	crypto_req_handle_t	*mr_cf_req;
	mca_app_handle_t	mr_app_handle;
	dbm_handle_t		mr_dbm_handle;
	mca_privatectx_t	*mr_context;
	mca_key_t		*mr_mkey;
	mca_session_t		*mr_session;
	mca_t			*mr_mca;
	mca_ring_t		*mr_ringp;
	uint16_t		mr_index;
	uint32_t		mr_errno;
	uint32_t		mr_resultlen;
	clock_t			mr_timeout;
	/*
	 * Consumer's I/O buffers.
	 */
	crypto_data_t		*mr_in;
	crypto_data_t		*mr_out;
	crypto_data_t		mr_tmpin;
	/*
	 * Consumer's I/O raw buffer
	 */
	uchar_t			*mr_buf;
	size_t			*mr_buflen;
	/*
	 * DMA structures.
	 */
	ddi_acc_handle_t	mr_key_acch;	/* per-job key acc handle */
	mca_chain_t		mr_key_chain;
	uint32_t		mr_key_chain_len;

	/* Offset in the context page for storing dynamic buffer chains */
	int			mr_offset;

	/*
	 * Pre-alloced DMA buffer.
	 */
	ddi_acc_handle_t	mr_ibuf_acch;
	mca_chain_t		mr_ibuf_chain;
	ddi_acc_handle_t	mr_obuf_acch;
	mca_chain_t		mr_obuf_chain;
	/*
	 * Values to program ring element with.
	 */
	uint32_t		mr_cmd;
	uint16_t		mr_key_flags[2];
	uint32_t		mr_key_len;
	uint32_t		mr_in_paddr;
	uint32_t		mr_out_paddr;
	uint32_t		mr_in_next_paddr;
	uint32_t		mr_out_next_paddr;
	uint32_t		mr_in_len;
	uint32_t		mr_in_first_len;
	uint32_t		mr_out_len;
	uint32_t		mr_out_first_len;
	uint32_t		mr_short_key[16];
	uint32_t		mr_cred[4];
	uint32_t		mr_key_id[2];	/* key ID used by FW */

	cpg_attr_t		*mr_template[2];
	uint32_t		*mr_keyidp[2];	/* key ID ptr passed by CF */
	/*
	 * Callback.
	 */
	void			(*mr_callback)(mca_request_t *);
	/*
	 * Other stuff.
	 */
	uint32_t		mr_flags;
	/*
	 * Statistics.
	 */
	int			mr_job_stat;
	int			mr_byte_stat;
	int			mr_byte_count;
	/*
	 * Chains for the Direct DMA.
	 */
	mca_chain_t		mr_in_direct_dma_chain;
	mca_chain_t		mr_out_direct_dma_chain;

	clock_t			mr_runqed;
	clock_t			mr_rundqed;
};

/*
 * Use of mr_short_key
 */
#define	SK_HASH_CMD		4	/* for init operation */
#define	SK_HASH_CTXID		4	/* for update/final */
#define	SK_HASH_DIGESTSZ	5	/* size of digest: driver internal */
#define	SK_HASH_SESSIONID	6	/* session id: driver internal */
#define	SK_HASH_KEYFLAGS	7	/* key flags: driver internal */

/*
 * Request flags (mca_request_t.mr_flags).
 */
#define	MRF_ONDEVICE		0x0001	/* request is on device queue */
#define	MRF_INPLACE		0x0002
#define	MRF_SCATTER		0x0004
#define	MRF_GATHER		0x0008
#define	MRF_TRIPLE		0x0010	/* triple des vs single des */
#define	MRF_TASKQ		0x0020	/* use taskq for completion */
#define	MRF_KSUPDATE		0x0040	/* keystore update expected */
#define	MRF_KSREAD		0x0080	/* keystore read done */
#define	MRF_PAD			0x0100	/* cbc_pad vs cbc */
#define	MRF_ECB			0x0200
#define	MRF_IN_DIRECT		0x0800
#define	MRF_OUT_DIRECT		0x1000

/*
 * Entry (physical structure) in a submit ring.
 */
struct mca_submission {
	uint16_t	ms_cmd;			/* command */
	uint16_t	ms_id;			/* completion id */
	uint16_t	ms_key_flags[2];	/* key flags */
	uint32_t	ms_auth[4];		/* authentication cookie */
	uint32_t	ms_key_id[2];		/* unique ID for key */
	uint32_t	ms_key_addr;		/* address of key/envelope */
	uint32_t	ms_key_length;		/* length of key address */
	uint32_t	ms_short_key[16];	/* key data (DES/3DES/AES) */
	uint32_t	ms_in_addr;		/* input address */
	uint32_t	ms_in_next;		/* input next desc address */
	uint16_t	ms_in_length;		/* input total length */
	uint16_t	ms_in_1stlen;		/* input 1st buffer length */
	uint32_t	ms_out_addr;		/* output address */
	uint32_t	ms_out_next;		/* output next desc address */
	uint16_t	ms_out_length;		/* output length */
	uint16_t	ms_out_1stlen;		/* output first buffer length */
	uint32_t	ms_ldom; 		/* The logical domain. */
};

/*
 * Entry (physical) in a completion ring.
 */
struct mca_completion {
	uint16_t	mc_error;		/* PKCS#11 error value */
	uint16_t	mc_id;			/* completion id */
	uint16_t	mc_key_flags[2];
	uint32_t	mc_out_length;		/* output length */
};

/* provider private info */
typedef struct mca_provider_private {
	crypto_provider_type_t		mp_type;
	mca_t				*mp_mca;
	mca_keystore_t			*mp_ks;
	mca_ring_t			*mp_ring;
	mca_sessiontable_t		*mp_sessiontable;
	crypto_kcf_provider_handle_t	mp_provhandle;
} mca_provider_private_t;

/* mu_flags */
#define	MUF_INIT		0x1
#define	MUF_PENDING		0x2
#define	MUF_LOADED		0x4

struct mca_user {
	mca_listnode_t		mu_linkage;
	char			mu_name[MAX_USERNAMESZ + 1];
	uint32_t		mu_flags;
	mca_listnode_t		mu_keys;
	mca_keystore_t		*mu_keystore;
	uint32_t		mu_ks_seq;
	/*
	 * These are essentially just a rwlock.  However, we cannot
	 * use stock rwlock's because the unlock needs to happen on
	 * a different thread (interrupt) than the lock.  This creates
	 * a panic in Solaris (rwlock not owned by unlocker) when
	 * krwlock_t's are used.  So we cobble our own.
	 *
	 * Note: we must never take the user read/write lock while
	 * holding the session lock.
	 */
	kmutex_t		mu_mx;
	kcondvar_t		mu_cv;
	int			mu_wantw;
	int			mu_wlock;
	int			mu_readers;
	int			mu_refcnt;
};


struct mca_ks_handle {
	mca_t		*mh_mca;
	dbm_handle_t	mh_handle;
};


#define	MAX_KS_HANDLES		2
#define	MCA_KS_BAD_HANDLE	0

/*
 * Mars notion of a keystore.
 */
struct mca_keystore {
	char			mks_name[33];	/* file name */
	uint64_t		mks_serial;	/* serial number */
	int			mks_refcnt;	/* # providers using this */
	int			mks_index;	/* table index */

	/* firmware handles */
	mca_ks_handle_t		mks_handle[MAX_KS_HANDLES];
	dbm_kstype_t		mks_type;	/* keystore type */
	/*
	 * These are essentially just a rwlock.  However, we cannot
	 * use stock rwlock's because the unlock needs to happen on
	 * a different thread (interrupt) than the lock.  This creates
	 * a panic in Solaris (rwlock not owned by unlocker) when
	 * krwlock_t's are used.  So we cobble our own.
	 */
	kmutex_t		mks_mx;
	kcondvar_t		mks_cv;
	int			mks_readers;
	int			mks_wantw;
	int			mks_wlock;
	/*
	 * these are used for synchronization with the
	 * IOCTL upcall.  They are not for external consumption.
	 */
	kmutex_t		mks_ucmx;
	kcondvar_t		mks_uccv;
	int			mks_ucrv;
	/*
	 * Cached keys for this keystore.
	 */
	mca_listnode_t		mks_users;
	mca_provider_private_t	mks_provinfo;	/* for logical provider */
	mca_sessiontable_t	mks_sessiontable;
	uint32_t		mks_devices;	/* bit map of mca instances */
};

#define	MKS_MCA_ID(mca) \
	(1 <<  ddi_get_instance(mca->mca_dip))

#define	MKS_CHECK_MCA(ks, mca) \
	(ks->mks_devices & MKS_MCA_ID(mca))

#define	MKS_SET_MCA(ks, mca) \
	ks->mks_devices |= MKS_MCA_ID(mca)

#define	MKS_CLEAR_MCA(ks, mca) \
	ks->mks_devices &= ~MKS_MCA_ID(mca)

#define	MCA_KS_SHIFT_SZ		24

#define	MCA_SESS_MASK		0xffffff

#define	MCA_SET_SESS_ID(id, ks) \
	(((ks->mks_index + 1) << MCA_KS_SHIFT_SZ) | id)

#define	MCA_GET_SESS_ID(id) \
	(id & MCA_SESS_MASK)

#define	MCA_GET_KS_INDEX(id) \
	((id >> MCA_KS_SHIFT_SZ) - 1)

#define	MCA_CHECK_LOGICAL_SESSION(id) \
	((id >> MCA_KS_SHIFT_SZ) > 0)

#define	MKS_WANTW		1	/* writer(s) waiting */
#define	MKS_WLOCK		2	/* writelocked */

struct mca_key {
	mca_listnode_t		mk_linkage;
	mca_user_t		*mk_user;
	uint32_t		mk_keyid[2];
	cpg_attr_t		*mk_cpgattr;
	uint32_t		mk_keyflags;
	uint32_t		mk_allocsz; /* sizeof(mca_key) + keyheadsz) */
	uint32_t		mk_keyheadsz;
	int			mk_skt_keyid;
	kmutex_t		mk_lock;
	int			mk_refcnt;
	/* mca_key_head follows */
};

/*
 * Ring, representing crypto job queue.
 */
struct mca_ring {
	mca_t			*mr_mca;
	mca_provider_private_t	mr_provinfo;
	kmutex_t		mr_lock;
	kcondvar_t		mr_draincv;	/* waiting for drain cv */
	kcondvar_t		mr_waitcv;	/* waiting for ring reqs cv */
	int			mr_waiting;	/* number of waiting threads */
	clock_t			mr_lbolt;	/* starting time for timeout */
	clock_t			mr_timeout;	/* maximum time for lbolt */
	mca_request_t		**mr_reqs;	/* indexed array of jobs */
	mca_listnode_t		mr_freereqs;	/* jobs available */
	mca_listnode_t		mr_runq;	/* jobs waiting on chip */
	char			mr_name[16];	/* provider name */
	int			mr_nreqs;	/* size of mr_reqs in reqs */
	uint32_t		mr_ncurrjobs;	/* jobs in-flight */
	uint32_t		mr_nmaxjobs;	/* max jobs */
	int			mr_count;
	int			mr_busy;	/* currently flow controlled */
	int			mr_lowater;
	int			mr_hiwater;
	int			mr_drain;	/* for DR */
	/* Register offsets */
	int			mr_head;
	int			mr_tail;
	int			mr_comphead;
	int			mr_comptail;
	uint16_t		mr_kick;
	/* Kstats */
	u_longlong_t		mr_submit;
	u_longlong_t		mr_flowctl;
	/*
	 * Ring related stuff.
	 */
	ddi_dma_handle_t	mr_dmah;
	ddi_acc_handle_t	mr_acch;
	uint32_t		mr_paddr;
	mca_submission_t	*mr_submissions;
	mca_completion_t	*mr_completions;
};

/*
 * Values for mr_drain
 */
#define	MCA_NO_DRAIN		0	/* No drain */
#define	MCA_NORMAL_DRAIN	1	/* Normal ring drain */
#define	MCA_DBM_DRAIN		2	/* Allow DBM job processing */
#define	MCA_SUSPEND_DRAIN	3	/* Suspend non-DBM OM processing */

/*
 * commands that is used internally by the driver
 */
#define	MCA_CMD_AES_KEY_WRAP		0x8001

/*
 * PKCS#11-like Mechanism Type (cm_type of crypto_mechanism_t)
 */
#define	MCAM_SHA_1			0x00000220
#define	MCAM_SHA_1_HMAC			0x00000221
#define	MCAM_SHA_1_HMAC_GENERAL		0x00000222
#define	MCAM_SHA512			0x00000270
#define	MCAM_SHA512_HMAC		0x00000271
#define	MCAM_SHA512_HMAC_GENERAL	0x00000272
#define	MCAM_MD5			0x00000210
#define	MCAM_MD5_HMAC			0x00000211
#define	MCAM_MD5_HMAC_GENERAL		0x00000212
#define	MCAM_RSA_X_509			0x00000003
#define	MCAM_RSA_PKCS			0x00000001
#define	MCAM_DSA			0x00000011
#define	MCAM_DES_CBC			0x00000122
#define	MCAM_DES_CBC_PAD		0x00000125
#define	MCAM_CDMF_CBC			0x00000142
#define	MCAM_CDMF_CBC_PAD		0x00000145
#define	MCAM_DES3_CBC			0x00000133
#define	MCAM_DES3_CBC_PAD		0x00000136
#define	MCAM_RC2_CBC			0x00000102
#define	MCAM_RC2_CBC_PAD		0x00000105
#define	MCAM_AES_CBC			0x00001082
#define	MCAM_AES_CBC_PAD		0x00001085
#define	MCAM_AES_CTR			0x00001086
#define	MCAM_CPG_AES_CTR		0x80001086
#define	MCAM_RSA_KEY_PAIR_GEN		0x00000000
#define	MCAM_DSA_KEY_PAIR_GEN		0x00000010
#define	MCAM_DES_KEY_GEN		0x00000120
#define	MCAM_DES2_KEY_GEN		0x00000130
#define	MCAM_DES3_KEY_GEN		0x00000131
#define	MCAM_AES_KEY_GEN		0x00001080
#define	MCAM_DH_PKCS_KEY_PAIR_GEN	0x00000020
#define	MCAM_DH_PKCS_DERIVE		0x00000021
#define	MCAM_EC_KEY_PAIR_GEN		0x00001040
#define	MCAM_ECDSA_KEY_PAIR_GEN		0x80001040
#define	MCAM_ECDSA			0x00001041
#define	MCAM_ECDH1_DERIVE		0x00001050
#define	MCAM_FIN_SVCS			0x80004653
#define	MCAM_AES_KEY_WRAP		0x80414b57
/*
 * Key flags.
 */
#define	KEYFLAG_ENCRYPT		0x00001
#define	KEYFLAG_DECRYPT		0x00002
#define	KEYFLAG_SIGN		0x00004
#define	KEYFLAG_VERIFY		0x00008
#define	KEYFLAG_WRAP		0x00010
#define	KEYFLAG_UNWRAP		0x00020
#define	KEYFLAG_DERIVE		0x00040
#define	KEYFLAG_LOCAL		0x00080
#define	KEYFLAG_SIGNR		0x00100
#define	KEYFLAG_VERIFYR		0x00200
#define	KEYFLAG_ALWAYSSENS	0x00400
#define	KEYFLAG_ALWAYSNOWRAP	0x00800
#define	KEYFLAG_READONLY	0x01000
#define	KEYFLAG_NOWRAP		0x02000
#define	KEYFLAG_SENSITIVE	0x04000
#define	KEYFLAG_PERSIST		0x08000
#define	KEYFLAG_PRIVATE		0x10000
#define	KEYFLAG_VALID		0x20000
/*
 * Key types.
 */
#define	KEYTYPE_NOKEY		0
#define	KEYTYPE_DES		1
#define	KEYTYPE_DES2		2
#define	KEYTYPE_DES3		3
#define	KEYTYPE_RSA_PUBLIC	4
#define	KEYTYPE_RSA_PRIVATE	5
#define	KEYTYPE_DSA_PUBLIC	6
#define	KEYTYPE_DSA_PRIVATE	7
#define	KEYTYPE_AES		8
#define	KEYTYPE_DH_PUBLIC	9
#define	KEYTYPE_DH_PRIVATE	10
#define	KEYTYPE_GENERIC_SECRET	11
#define	KEYTYPE_FS		12
#define	KEYTYPE_RC2		13
#define	KEYTYPE_RC4		14
#define	KEYTYPE_EC_PUBLIC	15
#define	KEYTYPE_EC_PRIVATE	16


/*
 * Error codes.
 */
#define	MERR_OK			0
#define	MERR_NO_KEYSTORE	1
#define	MERR_BAD_LOGIN		2
#define	MERR_HARDWARE		3
#define	MERR_BAD_COOKIE		4
#define	MERR_NO_MEMORY		5
#define	MERR_BAD_KEY		6
#define	MERR_BAD_PARAM		7
#define	MERR_BUF_TOO_SMALL	8
#define	MERR_BAD_SIGNATURE	9
#define	MERR_NOT_SUPPORTED	10
#define	MERR_BAD_PADDING	11
/*
 * Kstats.
 */
#define	MS_3DESJOBS		0
#define	MS_3DESBYTES		1
#define	MS_RSAPUBLIC		2
#define	MS_RSAPRIVATE		3
#define	MS_DSASIGN		4
#define	MS_DSAVERIFY		5
#define	MS_RNGJOBS		6
#define	MS_RNGBYTES		7
#define	MS_MD5JOBS		8
#define	MS_MD5BYTES		9
#define	MS_SHA1JOBS		10
#define	MS_SHA1BYTES		11
#define	MS_DHKEYGEN		12
#define	MS_DHDERIVE		13
#define	MS_KEYGENJOBS		14
#define	MS_WRAPJOBS		15
#define	MS_UNWRAPJOBS		16
#define	MS_AESJOBS		17
#define	MS_AESBYTES		18
#define	MS_FSJOBS		19
#define	MS_FSBYTES		20
#define	MS_SHA512JOBS		21
#define	MS_SHA512BYTES		22
#define	MS_HASHKEYJOBS		23
#define	MS_ECKEYGEN		24
#define	MS_ECDSASIGN		25
#define	MS_ECDSAVERIFY		26
#define	MS_ECDHDERIVE		27
#define	MS_SHA1HMACJOBS		28
#define	MS_SHA1HMACBYTES	29
#define	MS_SHA512HMACJOBS	30
#define	MS_SHA512HMACBYTES	31
#define	MS_MD5HMACJOBS		32
#define	MS_MD5HMACBYTES		33
#define	MS_MAX			34

struct mca_stat {
	/* Crypto counters */
	kstat_named_t		ms_algs[MS_MAX];
	/* Hardware/firmware properties */
	kstat_named_t		ms_mode;
	kstat_named_t		ms_status;
	/* Crypto properties */
	kstat_named_t		ms_cbsubmit;
	kstat_named_t		ms_cbflowctl;
	kstat_named_t		ms_cblowater;
	kstat_named_t		ms_cbhiwater;
	kstat_named_t		ms_cbringsize;
	kstat_named_t		ms_cbcurrjobs;
	kstat_named_t		ms_cbmaxjobs;
	kstat_named_t		ms_casubmit;
	kstat_named_t		ms_caflowctl;
	kstat_named_t		ms_calowater;
	kstat_named_t		ms_cahiwater;
	kstat_named_t		ms_caringsize;
	kstat_named_t		ms_cacurrjobs;
	kstat_named_t		ms_camaxjobs;
	kstat_named_t		ms_omsubmit;
	kstat_named_t		ms_omflowctl;
	kstat_named_t		ms_omlowater;
	kstat_named_t		ms_omhiwater;
	kstat_named_t		ms_omringsize;
	kstat_named_t		ms_omcurrjobs;
	kstat_named_t		ms_ommaxjobs;
};

typedef struct {
	kmutex_t		lock;
	kcondvar_t		cv;
	int			interrupt;
} mca_lock_t;

#define	MCA_JOB_STALL_LIMIT	120

typedef enum {
	mca_resethard_continue,	/* The default */
	mca_resethard_retry,	/* An experiment */
	mca_resetsoft_wait,	/* For debugging purposes */
	mca_resethard_wait	/* The 1.0 behavior */
} mca_reset_type_t;

typedef u_longlong_t mca_counter_t;

typedef struct {
	clock_t		ticks;
	timeout_id_t	id;
	mca_counter_t   count;	/* A statistic. */
} mca_timeout_t;

#define	MCA_SERIAL_RESET_MAX 3
#define	MCA_RESET_MAX 5

typedef struct {
	kmutex_t		lock; /* To protect <tid> & <serial> below. */

	mca_reset_type_t	logic; /* Dictates reset behavior. */

	uintptr_t		tqid; /* To prevent rescheduling. */

	clock_t			lbolt; /* The timestamp of the last reset. */

	/* These 2 variables are used to prevent serial resets. */
	timeout_id_t		tid;
	int			serial;

	/* These 2 variables are used as a more long-term checker. */
	time_t			first; /* The first reset. */
	int			count; /* A running count of resets. */
} mca_resetinfo_t;

typedef struct {
	ddi_dma_handle_t	dmah;
	ddi_acc_handle_t	acch;
	caddr_t			kaddr;
	uint32_t		paddr;
	uint32_t		bsize;
} mca_dma_buffinfo_t;

/*
 * Per instance structure.  Protected by mca_lock except for STREAMs fields
 * noted below, which are protected by the STREAMs perimeter.
 */
struct mca {
#ifdef LINUX
	/* This needs to be on the first line */
	struct work_ex_struct	taskq;
#endif
	dev_info_t		*mca_dip;
	int			mca_refcnt;
	kmutex_t		mca_intrlock;

	/* kCF registration lock */
	kmutex_t		mca_reglock;

	ddi_acc_handle_t	mca_pcihandle;
	ddi_acc_handle_t	mca_regshandle;
	caddr_t			mca_regs;
	off_t			mca_regslen;

	ddi_iblock_cookie_t	mca_icookie;
	timeout_id_t		mca_resume_tid;
	ulong_t			mca_pagesize;
	uint32_t		mca_dma_mode;
	uint32_t		mca_flags;	/* dev state flags */

	/*
	 * Mars control register.
	 */
	kmutex_t		mca_ctllock;
	kcondvar_t		mca_ctlcv;
	ddi_dma_handle_t	mca_ctldmah;	/* control cmd dma handle */
	uint16_t		mca_ctlcmd;	/* dma cmd in progress */
	int			mca_ctlint;	/* interrupted? */
	int			mca_ctldrain;	/* drain in progress */
	int			mca_ctlheld;	/* exclusive access */
	int			mca_ctlbusy;	/* block out drain */

	/*
	 * Mars DBM condition variable. Used to wait for FW to
	 * return the DBM request from daemon on the OM ring.
	 */
	kmutex_t		mca_dbmlock;
	kcondvar_t		mca_dbmcv;

	mca_lock_t		log;

	/*
	 * Serial numbers and keystore support.
	 */
	char			mca_device_serial[15];		/* formatted */
	uint64_t		mca_keystore_serial;
	int			mca_keystore_count;

	/*
	 * Crypto Rings.
	 */
	mca_sessiontable_t	mca_sessiontable;
	mca_ring_t		mca_ring_cb;
	mca_ring_t		mca_ring_ca;
	mca_ring_t		mca_ring_om;

	mca_listnode_t		mca_ctxlist;	/* linked list of ctx */
	kmutex_t		mca_ctxlist_lock;

	struct {
		mca_counter_t	submitted;
		mca_counter_t	reclaimed;
		mca_counter_t	watermark;
		mca_timeout_t	timeout;
		struct {
			clock_t	count;
			clock_t	addend;
			clock_t	limit;
			int	seconds;
		} stalled;
	} job;

	/*
	 * Job lock and condition variable. Used to protect job timeout
	 * data and suspend jobs during DR operations (suspend/resume).
	 */
	kmutex_t		mca_job_lock;
	kcondvar_t		mca_job_cv;

	/*
	 * Failure & reset handling.
	 */
	mca_resetinfo_t		reset;

	/*
	 * Logging support.
	 */
	mca_dma_buffinfo_t	mca_log_buff;

	/*
	 * Firmware Request Interface (FRI) support.
	 */
	mca_dma_buffinfo_t	mca_fri_buff;

	/*
	 * Kstats.  There is no standard for what standards
	 * Cryptographic Providers should supply, so we're
	 * making them up for now.
	 */
	kstat_t			*mca_ksp;
	kstat_t			*mca_intrstats;
	u_longlong_t		mca_stats[MS_MAX];

	/* Diagnostic dma buffer */
	mca_dma_buffinfo_t	mca_diag_buff;

	/* FMA Capabilities */
	int			fm_capabilities;   /* FMA capabilities */
	kmutex_t		fm_lock;	   /* FMA callback lock */
	uint32_t		fm_flags;	   /* FMA related state */
	uint64_t		fm_ena;		   /* Firmware ereport ENA */
	uint8_t			fm_eclass;	   /* Driver ereport class */
	char			fm_msg[FM_MSG_SZ]; /* Ereport msg string */
	ddi_dma_handle_t	fm_dma_handle;	   /* FMA dma error handle */
	ddi_acc_handle_t	fm_acc_handle;	   /* FMA acc error handle */

	/* Soft Interrupt Fields */
	ddi_iblock_cookie_t	mca_soft_icookie;
	ddi_softintr_t		mca_soft_intr;
	kmutex_t		mca_soft_intrlock;

	/* DMA Chain Buffers */
	mca_dma_buffinfo_t	mca_ctl_chain_buff; /* Chains control cmds */
	mca_dma_buffinfo_t	mca_fri_chain_buff;  /* Chains FRI data */

	/* Per instance task queue */
	ddi_taskq_t		*mca_taskq;
};

/*
 * Session Flags (ms_flags)
 */
#define	MSF_AUTHENTICATED	1

struct mca_session {
	/*
	 * Note: never hold the ms_lock when taking the user read/write lock.
	 */
	kmutex_t	ms_lock;
	uint32_t	ms_cred[4];
	mca_user_t	*ms_user;
	mca_table_t	ms_keytable;
	uint32_t	ms_ks_seq;
	uint32_t	ms_flags;
	int		ms_refcnt;
};

struct mca_privatectx {
	mca_listnode_t	mc_linkage;
	mca_t		*mc_mca;
	uint32_t	mc_cmd;
	int		mc_size;	/* size of this context */
	int		mc_kmflag;
	uint32_t	mc_keyflags;
	mca_key_head_t	*mc_keyhead;
	uint32_t	mc_keyheadsz;

	/* used for block cipher etc: must be double word aligned */
	uint64_t	mc_shortparam[8];
	int		mc_shortparamlen;

	caddr_t		mc_param;
	int		mc_paramlen;
	mca_session_t	*mc_session;
	mca_keystore_t	*mc_keystore;
	void		(*mc_ctxdtr)(void *);	/* mech specific destructor */
	/* mechanism specific context follows */
};

/*
 * Block Cipher CTX
 * - resid: 'resid' is the unprocessed input. When the total input length
 *   is not multiple of blocksz, the tailing end of the input cannot be
 *   processed: thus store it in 'resid' field.
 * - lastblock: 'lastblock' is the last block of the recovered message.
 *   For multi-part CBC_PAD decryption, when the total input length is
 *   multiple of blocksz, the last block of the recovered message *may*
 *   contain the padding. Thus, it won't be returned to the caller, and
 *   kept in the context. The padding is removed when decrypt_final is called.
 */

typedef struct mca_3des_ctx {
	int		residlen;
	char		resid[DESBLOCK];
	int		lastblocklen;
	char		lastblock[DESBLOCK];
} mca_3des_ctx_t;

typedef struct mca_aes_ctx {
	int		residlen;
	char		resid[AESBLOCK];
	int		lastblocklen;
	char		lastblock[AESBLOCK];
} mca_aes_ctx_t;


/*
 * Digest ctx: mc_shortparam[0] contains the ctx id
 */


/*
 * The parameter structure for RC2 operation.
 * This fits to the mca_privatectx.mc_shortparam
 */
typedef struct mca_rc2_param {
	uint32_t	effbits;
	char		iv[RC2BLOCK];
} mca_rc2_param_t;

typedef struct mca_loadkeys_ctx {
	struct {
		uint32_t	mlk_keyid[2];
	}			*mlk_keyids;
	size_t			mlk_keyidssz;
	ddi_dma_handle_t	mlk_dmah;
	ddi_acc_handle_t	mlk_acch;
	mca_key_t		**mlk_keys;
	size_t			mlk_keyssz;
	mca_user_t		*mlk_user;
	uint32_t		mlk_paddr;
	int			mlk_nkeyids;
	int			mlk_nextkey;
	int			mlk_nextid;
} mca_loadkeys_ctx_t;


#define	KEYHEAD_DESCR(keyhead) (char *)(keyhead + 1)
#define	KEYHEAD_VALUE(keyhead) KEYHEAD_DESCR(keyhead) + \
    PAD32(GETBUF32(&(((mca_key_head_t *)(keyhead))->descrlen)))
#define	KEYHEAD_ENVELOPE(keyhead) KEYHEAD_VALUE(keyhead) + \
    PAD32(GETBUF32(&(((mca_key_head_t *)(keyhead))->valuelen)))

struct mca_key_head {
	uint32_t	keytype;	/* type of the key */
	uint32_t	cardid;		/* unique ID for key */
	uint32_t	objectid;	/* unique ID for key */
	uint32_t	descrlen;	/* lenth of the key description */
	uint32_t	valuelen;	/* length of the key value */
	uint32_t	envelopelen;	/* length of envelope key */
	/*
	 * This is followed by the opaque description of the key (in the  case
	 * when this is used as a template for creating a persistent key and
	 * when such a  key is retrieved),
	 * followed by (at the next 4-byte boundary) the keytype-specific
	 * value of the key (for nonsensitive keys),
	 * followed by (at the next 4-byte boundary) the envelope containing
	 * the value of the key (for sensitive session keys)
	 */
};

typedef struct pubrsa_head {
	uint32_t	modbits;
	uint32_t	modlen;
	uint32_t	pubexplen;
} pubrsa_head_t;

typedef struct prirsa_head {
	uint32_t	modbits;
	uint32_t	modlen;
	uint32_t	pubexplen;
	uint32_t	privexplen;
	uint32_t	plen;
	uint32_t	qlen;
	uint32_t	dplen;
	uint32_t	dqlen;
	uint32_t	qinvlen;
} prirsa_head_t;

typedef struct dsa_head {
	uint32_t	plen;
	uint32_t	glen;
	uint32_t	vlen;
} dsa_head_t;

typedef struct pubdh_head {
	uint32_t	plen;
	uint32_t	glen;
	uint32_t	vlen;
} pubdh_head_t;

typedef struct pridh_head {
	uint32_t	plen;
	uint32_t	glen;
	uint32_t	vlen;
	uint32_t	vbits;
} pridh_head_t;


#define	OID_TAG		0x06
#define	MAX_EC_OID_LEN	16

typedef struct pubec_head {
	uint8_t		ec_oid[MAX_EC_OID_LEN];
	uint32_t	xlen;
	uint32_t	ylen;
} pubec_head_t;

typedef struct priec_head {
	uint8_t		ec_oid[MAX_EC_OID_LEN];
	uint32_t	dlen;
} priec_head_t;


typedef struct mca_rc2_keyhead {
	uint32_t	keysz;
	uint32_t	effbits;
	uchar_t		iv[RC2BLOCK];
} mca_rc2_keyhead_t;

typedef struct mca_aes_keyhead {
	uint32_t	keysz;
	uchar_t		iv[AESBLOCK];
} mca_aes_keyhead_t;

typedef struct mca_aes_ctr_keyhead {
	uint32_t	keysz;
	uint32_t	ctrbits;
	uchar_t		iv[AESBLOCK];
} mca_aes_ctr_keyhead_t;


/*
 * Device configuration and driver state flags (mca_t.mca_flags)
 */
#define	MCA_ATTACHING	0x00000001	/* The driver is attaching. */
#define	MCA_DETACH	0x00000002	/* detach in progress */
#define	MCA_RNGSHA1	0x00000004	/* SHA1 postprocessing of RNG output */
#define	MCA_OWNED	0x00000008	/* device is owned */
#define	MCA_FIPS	0x00000010	/* FIPS mode */
#define	MCA_INTEN	0x00000020	/* interrupts enabled */
#define	MCA_KTIOK	0x00000040	/* KTI set ok */
#define	MCA_SUSPENDING	0x00000080	/* Driver suspend in progress */
#define	MCA_REGISTERED	0x00001000	/* Offline mode: Not registered to EF */
#define	MCA_DIAG	0x00002000	/* Diag mode: Registered as HW prov */
#define	MCA_REKEYING	0x00004000	/* In the middle of rekey */

#define	mca_setattaching(mca)	(mca->mca_flags |= MCA_ATTACHING)
#define	mca_isattaching(mca)	(mca->mca_flags & MCA_ATTACHING)
#define	mca_unsetattaching(mca) (mca->mca_flags &= (~MCA_ATTACHING))

#define	mca_setsuspending(mca)	(mca->mca_flags |= MCA_SUSPENDING)
#define	mca_issuspending(mca)	(mca->mca_flags & MCA_SUSPENDING)
#define	mca_unsetsuspending(mca) (mca->mca_flags &= (~MCA_SUSPENDING))

#define	mca_setdetached(mca)	(mca->mca_flags |= MCA_DETACH)
#define	mca_isdetached(mca)	(mca->mca_flags & MCA_DETACH)

#define	mca_setattached(mca)	(mca->mca_flags &= (~MCA_DETACH))
#define	mca_isattached(mca)	(!(mca->mca_flags & MCA_DETACH))

#define	mca_setrngsha1(mca)	(mca->mca_flags |= MCA_RNGSHA1)
#define	mca_isrngsha1(mca)	(mca->mca_flags & MCA_RNGSHA1)

#define	mca_setowned(mca)	(mca->mca_flags |= MCA_OWNED)
#define	mca_unsetowned(mca)	(mca->mca_flags &= ~MCA_OWNED)
#define	mca_isowned(mca)	(mca->mca_flags & MCA_OWNED)

#define	mca_setfips(mca)	(mca->mca_flags |= MCA_FIPS)
#define	mca_unsetfips(mca)	(mca->mca_flags &= ~MCA_FIPS)
#define	mca_isfips(mca)		(mca->mca_flags & MCA_FIPS)

#define	mca_setinten(mca)	(mca->mca_flags |= MCA_INTEN)
#define	mca_unsetinten(mca)	(mca->mca_flags &= ~MCA_INTEN)
#define	mca_isinten(mca)	(mca->mca_flags & MCA_INTEN)

#define	mca_setktiok(mca)	(mca->mca_flags |= MCA_KTIOK)
#define	mca_isktiok(mca)	(mca->mca_flags & MCA_KTIOK)

#define	mca_isregistered(mca)	(mca->mca_flags & MCA_REGISTERED)
#define	mca_isunregistered(mca)	(!(mca->mca_flags & MCA_REGISTERED) && \
					!(mca->mca_flags & MCA_DIAG))
#define	mca_isdiag(mca)	(mca->mca_flags & MCA_DIAG)
#define	mca_setregistered(mca) \
	(mca)->mca_flags &= ~MCA_DIAG; \
	(mca)->mca_flags |= MCA_REGISTERED
#define	mca_setdiag(mca) \
	(mca)->mca_flags &= ~MCA_REGISTERED; \
	(mca)->mca_flags |= MCA_DIAG
#define	mca_setunregistered(mca) \
	(mca)->mca_flags &= ~(MCA_REGISTERED | MCA_DIAG)

#define	mca_setrekey(mca) \
	((mca)->mca_flags |= MCA_REKEYING)
#define	mca_unsetrekey(mca) \
	((mca)->mca_flags &= ~MCA_REKEYING)
#define	mca_isrekey(mca) \
	((mca)->mca_flags & MCA_REKEYING)

#define	mca_reset_device_flags(mca) \
	(mca->mca_flags &= ~(MCA_INTEN | MCA_KTIOK))

#define	MCA_PCI_STATUS_ERRORS	(PCI_STAT_S_PERROR | PCI_STAT_S_TARG_AB | \
				PCI_STAT_R_TARG_AB | PCI_STAT_R_MAST_AB | \
				PCI_STAT_S_SYSERR | PCI_STAT_PERROR)
#define	MCA_PCI_FATAL_ERRORS	(PCI_STAT_S_PERROR | PCI_STAT_R_MAST_AB | \
				PCI_STAT_S_SYSERR | PCI_STAT_PERROR)
#define	MCA_PCI_NONFATAL_ERRORS	(PCI_STAT_S_TARG_AB | PCI_STAT_R_TARG_AB)
#define	mca_pcierror(status)	(status & MCA_PCI_STATUS_ERRORS)

#define	KIOIP(mca)		KSTAT_INTR_PTR((mca)->mca_intrstats)

/*
 * Device state flags (mca_t.fm_flags - protected by mca_t.fm_lock)
 *
 * Note: All routines that call the below mca_fm_xxx() routines to set
 *	 flags within fm_flags should first take the fm_lock.
 */
#define	MCA_FAILED	0x00000001	/* device failure noted */
#define	MCA_BOOTING	0x00000002	/* device (re)booting. */
#define	MCA_FAILSAFE	0x00000004	/* failsafe mode, fw update only */
#define	MCA_DEAF	0x00000008	/* The sca is no longer listening. */
#define	MCA_HW_FAULT	0x00000010	/* Hardware generated fault */
#define	MCA_IO_FAULT	0x00000020	/* IO fault services generated fault */
#define	MCA_SOFT_INT	0x00000040	/* Soft interrupt triggered */
#define	MCA_FMA_ENABLED	0x00000080	/* FMA has been enabled */
#define	MCA_KS_FAULT	0x00000100	/* Keystore load has failed */
#define	MCA_FAIL_SCHED	0x00000200	/* Failure task has been dispatched */

#define	mca_fm_setfailed(mca)		(mca->fm_flags |= MCA_FAILED)
#define	mca_fm_isfailed(mca)		(mca->fm_flags & MCA_FAILED)

#define	MCA_OFFLINE			(MCA_FAILED | MCA_BOOTING)
#define	mca_fm_setoffline(mca)		(mca->fm_flags |= MCA_BOOTING)
#define	mca_fm_isoffline(mca)		(mca->fm_flags & MCA_OFFLINE)
#define	mca_fm_setonline(mca)		(mca->fm_flags &= (~MCA_OFFLINE))

#define	mca_fm_setfailsafe(mca)		(mca->fm_flags |= MCA_FAILSAFE)
#define	mca_fm_isfailsafe(mca)		(mca->fm_flags & MCA_FAILSAFE)

#define	MCA_NETWORK_FAILED		(MCA_FAILED | MCA_FAILSAFE)
#define	mca_fm_networkfailed(mca)	(mca->fm_flags & MCA_NETWORK_FAILED)

#define	mca_fm_setdeaf(mca)		(mca->fm_flags |= MCA_DEAF)
#define	mca_fm_isdeaf(mca)		(mca->fm_flags & MCA_DEAF)
#define	mca_fm_setlistening(mca)	(mca->fm_flags &= (~MCA_DEAF))

#define	mca_fm_set_hw_fault(mca)	(mca->fm_flags |= MCA_HW_FAULT)
#define	mca_fm_hw_faulted(mca)		(mca->fm_flags & MCA_HW_FAULT)
#define	mca_fm_clr_hw_fault(mca)	(mca->fm_flags &= (~MCA_HW_FAULT))

#define	mca_fm_set_io_fault(mca)	(mca->fm_flags |= MCA_IO_FAULT)
#define	mca_fm_io_faulted(mca)		(mca->fm_flags & MCA_IO_FAULT)
#define	mca_fm_clr_io_fault(mca)	(mca->fm_flags &= (~MCA_IO_FAULT))

#define	mca_fm_set_softint(mca)		(mca->fm_flags |= MCA_SOFT_INT)
#define	mca_fm_is_softint(mca)		(mca->fm_flags & MCA_SOFT_INT)
#define	mca_fm_clr_softint(mca)		(mca->fm_flags &= (~MCA_SOFT_INT))

#define	mca_fm_set_enabled(mca)		(mca->fm_flags |= MCA_FMA_ENABLED)
#define	mca_fm_is_enabled(mca)		(mca->fm_flags & MCA_FMA_ENABLED)
#define	mca_fm_clr_enabled(mca)		(mca->fm_flags &= (~MCA_FMA_ENABLED))

#define	mca_fm_set_ks_fault(mca)	(mca->fm_flags |= MCA_KS_FAULT)
#define	mca_fm_is_ks_fault(mca)		(mca->fm_flags & MCA_KS_FAULT)
#define	mca_fm_clr_ks_fault(mca)	(mca->fm_flags &= (~MCA_KS_FAULT))

#define	mca_fm_set_fail_sched(mca)	(mca->fm_flags |= MCA_FAIL_SCHED)
#define	mca_fm_is_fail_sched(mca)	(mca->fm_flags & MCA_FAIL_SCHED)
#define	mca_fm_clr_fail_sched(mca)	(mca->fm_flags &= (~MCA_FAIL_SCHED))

#define	mca_fm_reset_device_flags(mca)	(mca->fm_flags &= \
					~(MCA_FAILSAFE | MCA_DEAF))

/*
 * Macros to access fields within the context and descriptors.
 */

#ifdef	_BIG_ENDIAN
#define	GETLE16(addr)		mca_loadswap16((addr))
#define	GETLE32(addr)		mca_loadswap32((addr))
#define	PUTLE16(addr, val)	mca_storeswap16((addr), (val))
#define	PUTLE32(addr, val)	mca_storeswap32((addr), (val))
#define	GETBE16(addr)		(*(addr))
#define	GETBE32(addr)		(*(addr))
#define	PUTBE16(addr, val)	(*(addr) = (val))
#define	PUTBE32(addr, val)	(*(addr) = (val))
#else
#define	GETLE16(addr)		(*(addr))
#define	GETLE32(addr)		(*(addr))
#define	PUTLE16(addr, val)	(*(addr) = (val))
#define	PUTLE32(addr, val)	(*(addr) = (val))
#define	GETBE16(addr)		mca_loadswap16((addr))
#define	GETBE32(addr)		mca_loadswap32((addr))
#define	PUTBE16(addr, val)	mca_storeswap16((addr), (val))
#define	PUTBE32(addr, val)	mca_storeswap32((addr), (val))
#endif

#define	GETBUF16(addr)		GETLE16(addr)
#define	GETBUF32(addr)		GETLE32(addr)
#define	PUTBUF16(addr, val)	PUTLE16(addr, val)
#define	PUTBUF32(addr, val)	PUTLE32(addr, val)

/*
 * Used to guarantee alignment.
 */
#define	ROUNDUP(a, n)	(((a) + ((n) - 1)) & ~((n) - 1))
#define	ROUNDDOWN(a, n)	(((a) & ~((n) - 1)))
#define	PAD32(x)	ROUNDUP(x, sizeof (uint32_t))
#define	PADAES(x)	ROUNDUP(x, AESBLOCK)

/*
 * Other utility macros.
 */
#define	QEMPTY(q)	((q)->ml_next == (q))
#define	BITS2BYTES(b)	((b + 7) >> 3)
#define	BYTES2BITS(b)	((b) << 3)

/*
 * FMA Constants and Macros
 */
#define	MCA_EREPORT_VERSION	FM_EREPORT_VERS0

#ifdef FMA_COMPLIANT
#define	MCA_ENA_GEN	fm_ena_generate(0, FM_ENA_FMT1)
#define	MCA_ENA_INC(e)	fm_ena_increment(e)
#define	MCA_ADJUST_FLAGERR_ACC(mca, attr) \
	attr.devacc_attr_access = DDI_FM_EREPORT_CAP(mca->fm_capabilities) ? \
	DDI_FLAGERR_ACC : DDI_DEFAULT_ACC
#define	MCA_ADJUST_DMA_FLAGERR(mca, attr) \
	attr.dma_attr_flags = DDI_FM_EREPORT_CAP(mca->fm_capabilities) ? \
	DDI_DMA_FLAGERR : 0
#else
#define	MCA_ENA_GEN	0xBADCAFE0
#ifdef LINUX
#define	MCA_ENA_INC(e)	(e+1)
#else
#define	MCA_ENA_INC(e)	e++
#endif
#define	MCA_ADJUST_FLAGERR_ACC(mca, attr)
#define	MCA_ADJUST_DMA_FLAGERR_ACC(mca, attr)
#endif /* FMA_COMPLIANT */

/*
 * Debug stuff.
 */
#if defined(DEBUG)

#define	DWARN		0x00000001
#define	DINTR		0x00000002
#define	DRECLAIM	0x00000004
#define	DCHATTY		0x00000008
#define	DDBM		0x00000010
#define	DBRINGUP	0x00000020
#define	DGETLOG		0x00000040
#define	DADMIN		0x00000080
#define	DAUTH		0x00000100
#define	DKEYSTORE	0x00000200
#define	DFIPS		0x00000400
#define	DENTRY		0x00000800
#define	DFMA		0x00001000
#define	DTEST		0x00002000
#define	DALL		0xFFFFFFFF


void	mca_dprintf(mca_t *, int, const char *, ...);
void	mca_dumphex(void *, int);
int	mca_dflagset(int);

#define	DBG	mca_dprintf
#define	DBGCALL(flag, func)	{ if (mca_dflagset(flag)) (void) func; }

#define	CPG_TRACE_1(arg0)		cpg_trace_1(__func__, arg0)
#define	CPG_TRACE_2(arg0, arg1)		cpg_trace_2(__func__, arg0, arg1)
#define	CPG_TRACE_3(arg0, arg1, arg2)	\
	cpg_trace_3(__func__, arg0, arg1, arg2)
#define	CPG_TRACE_4(arg0, arg1, arg2, arg3)	\
	cpg_trace_4(__func__, arg0, arg1, arg2, arg3)

#else	/* !defined(DEBUG) */

#define	DBG(mca, lvl, ...)
#define	DBGCALL(flag, func)

#define	CPG_TRACE_1(arg0)
#define	CPG_TRACE_2(arg0, arg1)
#define	CPG_TRACE_3(arg0, arg1, arg2)
#define	CPG_TRACE_4(arg0, arg1, arg2, arg3)

#endif

/*
 * Driver globals.
 */
extern int		mca_mindma;
extern struct cb_ops	mca_cbops;
extern struct mca_table	mca_streams;
extern struct mca_table	mca_devs;
extern int		mca_staletime;
extern int		mca_checksum_disable;
extern int		mca_jumboframe_mtu;

/*
 * Engineering knobs to select DLPI style (defaults to style 1 support only).
 */
extern int		mca_style1_enable;
extern int		mca_style2_enable;


/*
 * Prototypes.
 */
/*
 * mca_aes.c
 */
void	mca_aes_setupkeys(mca_aes_key_t *, uchar_t *, int);
void	mca_aes_cbc_encrypt(mca_aes_key_t *, uint32_t *, const uchar_t *,
    uchar_t *, int);
void	mca_aes_cbc_decrypt(mca_aes_key_t *, uint32_t *, const uchar_t *,
    uchar_t *, int);
int	mca_aesinit(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *,
    int, uint32_t, mca_privatectx_t **);
int	mca_aes(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t *, uint32_t);
int	mca_aesupdate(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t *, uint32_t);
int	mca_aesfinal(crypto_ctx_t *, crypto_data_t *, crypto_req_handle_t *,
    uint32_t);
int	mca_aesatomic(mca_t *, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t *, uint32_t);
int	mca_aes_ctr_allocmech(crypto_mechanism_t *, crypto_mechanism_t *,
    int *, int);
int	mca_aes_ctr_freemech(crypto_mechanism_t *);

/* CK_AES_CTR_PARAMS provides the parameters to the CKM_AES_CTR mechanism */
typedef struct CK_AES_CTR_PARAMS {
	ulong_t		ulCounterBits;
	uint8_t		iv[16];
} CK_AES_CTR_PARAMS;

typedef struct CK_AES_CTR_PARAMS32 {
	uint32_t	ulCounterBits;
	uint8_t		iv[16];
} CK_AES_CTR_PARAMS32;

#ifdef LINUX

/* CK_ECDH1_DERIVE_PARAMS provides the parameters to the CKM_ECDH1_DERIVE */
typedef struct CK_ECDH1_DERIVE_PARAMS {
	ulong_t		kdf;
	ulong_t		ulSharedDataLen;
	uchar_t		*pSharedData;
	ulong_t		ulPublicDataLen;
	uchar_t		*pPublicData;
} CK_ECDH1_DERIVE_PARAMS;

typedef struct CK_ECDH1_DERIVE_PARAMS32 {
	uint32_t	kdf;
	uint32_t	ulSharedDataLen;
	caddr32_t	pSharedData;
	uint32_t	ulPublicDataLen;
	caddr32_t	pPublicData;
} CK_ECDH1_DERIVE_PARAMS32;

#endif

/* the value of CK_ECDH1_DERIVE_PARAM.kdf */
#define	CKD_NULL	1
#define	CKD_SHA1_KDF	2


/*
 * mca_wrap.c
 */
int mca_common_wrap(mca_t *, crypto_session_id_t, crypto_mechanism_t *,
    crypto_key_t *, crypto_key_t *, uchar_t *, size_t *, crypto_req_handle_t *,
    uint32_t);
int mca_common_unwrap(mca_t *, crypto_session_id_t, crypto_mechanism_t *,
    crypto_key_t *, uchar_t *, size_t, cpg_attr_t *, uint32_t *,
    crypto_req_handle_t *, uint32_t);

/*
 * mca_debug.c
 */
void	mca_error(mca_t *, const char *, ...);
void	mca_note(mca_t *, const char *, ...);
void	mca_info(mca_t *, const char *, ...);
void	mca_diperror(dev_info_t *, const char *, ...);
void	mca_dump_dbm_header(dbm_header_t *, char *);

uintptr_t cpg_trace_1(const char *, uintptr_t);
uintptr_t cpg_trace_2(const char *, uintptr_t, uintptr_t);
uintptr_t cpg_trace_3(const char *, uintptr_t, uintptr_t, uintptr_t);
uintptr_t cpg_trace_4(const char *, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
/*
 * mca_keygen.c
 */
int	mca_keygen_boolean(cpg_attr_t *, int, uint8_t, uint8_t *);
int	mca_keygen(mca_t *, mca_keystore_t *, mca_session_t *, cpg_attr_t *,
    uint32_t *, uint32_t, crypto_req_handle_t *);
int	mca_rsagen(mca_t *, mca_session_t *, cpg_attr_t *, cpg_attr_t *,
    uint32_t *, uint32_t *, crypto_req_handle_t *, mca_keystore_t *);
int	mca_dsagen(mca_t *, mca_session_t *, cpg_attr_t *, cpg_attr_t *,
    uint32_t *, uint32_t *, crypto_req_handle_t *, mca_keystore_t *);
int	mca_dhgen(mca_t *, mca_session_t *, cpg_attr_t *, cpg_attr_t *,
    uint32_t *, uint32_t *, crypto_req_handle_t *, mca_keystore_t *);
int	mca_ecgen(mca_t *, mca_session_t *, cpg_attr_t *, cpg_attr_t *,
    uint32_t *, uint32_t *, crypto_req_handle_t *, mca_keystore_t *);
/*
 * mca_derive.c
 */
int	mca_dh_derive(mca_t *, crypto_session_id_t, crypto_mechanism_t *mech,
    crypto_key_t *basekey, cpg_attr_t *, uint32_t *, crypto_req_handle_t *);
int	mca_ecdh1_allocmech(crypto_mechanism_t *, crypto_mechanism_t *,
    int *, int);
int	mca_ecdh1_freemech(crypto_mechanism_t *);
int	mca_ec_derive(mca_t *, crypto_session_id_t, crypto_mechanism_t *mech,
    crypto_key_t *basekey, cpg_attr_t *, uint32_t *, crypto_req_handle_t *);


/*
 * mca_kstat.c
 */
void	mca_ksinit(mca_t *);

/*
 * mca_log.c
 */
void	mca_getlog(mca_t *);


/*
 * mca_upcall.c
 */
void	mca_upcall_init(void);
void	mca_upcall_fini(void);
int	mca_upcall_attach(mca_channel_t);
void	mca_upcall_detach(mca_channel_t);
int	mca_upcall_hold(mca_channel_t);
void	mca_upcall_release(mca_channel_t);
int	mca_upcall_post(mca_t *, mca_channel_t, void *, int, int);
int	mca_upcall_service(mca_channel_t, void **, int *);
void	mca_upcall_reset(mca_t *);
int	mca_upcall_check(void);
int	mca_upcall_dbm_register(mca_channel_t, char *);
void	mca_update_idc_hdr(mca_idc_hdr_t *, mca_channel_t, mca_domain_t);
mca_domain_t mca_get_domain(void);
int	mca_dbm_response(mca_t *, void *, int, char **, int *, void **,
	mca_app_handle_t);
void	mca_dbm_freereq(void *);
mca_channel_t mca_upcall_lookup_channel(char *);
mca_channel_t mca_upcall_lookup_control_channel(void);
void	mca_upcall_send_goodbye(char *, mca_t *);

/*
 * mca_keystore.c
 */
void	mca_keystore_init(void);
void	mca_keystore_fini(void);
void	mca_keystore_rdlock(mca_keystore_t *);
void	mca_keystore_wrlock(mca_keystore_t *);
void	mca_keystore_lock_degrade(mca_keystore_t *);
void	mca_keystore_unlock(mca_keystore_t *);
mca_keystore_t *mca_keystore_hold(mca_t *, dbm_provider_t *);
int	mca_keystore_load(mca_t *, mca_keystore_t *);
void	mca_keystore_rele(mca_keystore_t *, mca_t *);
void	mca_keystore_rele_all(mca_t *);
void	mca_keystore_delete_users(mca_keystore_t *);
char	*mca_keystore_name(mca_keystore_t *);
void	mca_keystore_prepare_wait(mca_keystore_t *);
void	mca_keystore_cancel_wait(mca_keystore_t *);
int	mca_keystore_wait(mca_keystore_t *);
void	mca_keystore_done(int, void *);

uint64_t	mca_keystore_serial(mca_keystore_t *);
mca_key_t	*mca_find_key(mca_user_t *, uint32_t *);

crypto_kcf_provider_handle_t *mca_keystore_create_lp_array(mca_t *);
void	mca_keystore_destroy_lp_array(crypto_kcf_provider_handle_t *, int);
mca_keystore_t *mca_keystore_lookup_by_session(crypto_session_id_t);
mca_keystore_t *mca_keystore_lookup_by_handle(mca_t *, dbm_handle_t);
mca_keystore_t *mca_keystore_lookup_mca(char *, mca_t *);
int	mca_keystore_DR_safe(mca_t *);
int	mca_provider_DR_safe(mca_sessiontable_t *);
dbm_handle_t mca_ks_get_handle(mca_keystore_t *, mca_t *);
void	mca_ks_set_handle(mca_keystore_t *, dbm_handle_t, mca_t *);

int	mca_register_key(mca_user_t *, mca_key_t *);
void	mca_unregister_key(mca_key_t *);
void	mca_keydtor(void *);
int	mca_parse_key(cpg_attr_t *, mca_key_head_t *, int,
    uint16_t, mca_key_t **);

/*
 * mca.c
 */
mca_t	*mca_hold_instance(int);
void	mca_rele_instance(mca_t *);
int	mca_get_next_instance(int *);
int	mca_hold_ctl(int, mca_t **);
void	mca_rele_ctl(mca_t *);
void	mca_rmqueue(mca_listnode_t *);
void	mca_enqueue(mca_listnode_t *, mca_listnode_t *);
mca_listnode_t	*mca_dequeue(mca_listnode_t *);
mca_listnode_t	*mca_nextqueue(mca_listnode_t *, mca_listnode_t *);
mca_listnode_t	*mca_peekqueue(mca_listnode_t *);
void	mca_initq(mca_listnode_t *);
mca_request_t *mca_getreq(mca_ring_t *);
void	mca_freereq(mca_request_t *);
int	mca_bindchains_one(mca_request_t *, size_t, int, caddr_t,
    ddi_dma_handle_t, uint_t, mca_chain_t *, int *);
void	mca_unbindchains(mca_request_t *);

int	mca_start(mca_request_t *);
void	mca_reclaim(mca_ring_t *);
void	mca_done(mca_request_t *);
void	mca_failure(mca_t *, uint8_t, char *, ...);
int	mca_safereset(mca_t *);
int	mca_drain(mca_t *, int);
void	mca_undrain(mca_t *);
void	mca_undrainctl(mca_t *);
void	mca_undrain_dbm(mca_t *);
void	mca_ctlbusy(mca_t *);
void	mca_ctlunbusy(mca_t *);
void	mca_busy(mca_t *);
void	mca_unbusy(mca_t *);

void	mca_setiv(mca_request_t *);
void	mca_ktkencryptbuf(mca_request_t *);
void	mca_ktkencryptkey(mca_request_t *);
void	mca_ktkencryptshortkey(mca_request_t *);
void	mca_ktkdecryptbuf(mca_request_t *);
uint16_t	mca_loadswap16(uint16_t *);
uint32_t	mca_loadswap32(uint32_t *);
void	mca_storeswap16(uint16_t *, uint16_t);
void	mca_storeswap32(uint32_t *, uint32_t);
extern struct ddi_device_acc_attr mca_devattr;
int	mca_cmp_numnbuf(crypto_data_t *, char *, int);
void	mca_key_free(mca_key_t *);
int	mca_delete_sensitive_key_value(cpg_attr_t *);
int	mca_add_key_value(mca_key_head_t *, cpg_attr_t *);
int	cpgattr2keyhead(cpg_attr_t *, int, caddr_t, uint32_t *);
int	cpgattr2keyhead4keygen(cpg_attr_t *, int, caddr_t, uint32_t *);
int	cpgattr2keyhead4unwrap(cpg_attr_t *, int, caddr_t, uint32_t *);
int	cpgattr2keytype(cpg_attr_t *, int *);

extern struct ddi_dma_attr mca_dmaattr;
extern struct ddi_dma_attr no_sg_dma_attr;
extern struct ddi_device_acc_attr mca_bufattr;
extern int		mca_ktisz;
extern uchar_t		*mca_kti;
extern mca_aes_key_t	mca_ktk;
extern kmutex_t		mca_lock;

#if defined(i386) || defined(__i386) || defined(__amd64)
void	mca_terminate_chains(mca_chain_t *, int);
void	mca_restore_chain(mca_chain_t *);
#define	MCA_TERMINATE_CHAINS(chain, len)	mca_terminate_chains(chain, len)
#define	MCA_RESTORE_CHAIN(chain)		mca_restore_chain(chain)
#else
#define	MCA_TERMINATE_CHAINS(chain, len)
#define	MCA_RESTORE_CHAIN(chain)
#endif

/*
 * mca_swrsa.c
 */
int	mca_swrsa(char *, size_t, char *, uchar_t *, int, uchar_t *, int);


int	mca_numcmp(caddr_t, int, caddr_t, int);
void	mca_stripzeros(caddr_t *, unsigned *);
int	mca_bitlen(caddr_t, unsigned);

/*
 * mca.c
 */
int	mca_allocctx(mca_t *, crypto_session_id_t, crypto_key_t *,
    int cmd, int size, mca_privatectx_t **);
int	mca_add_key(mca_session_t *, mca_key_t *, crypto_object_id_t *);
int	mca_add_keys(mca_session_t *, mca_key_t *, mca_key_t *,
    crypto_object_id_t *, crypto_object_id_t *);
void	mca_delete_key(mca_session_t *, uint32_t);
void	mca_validate_key(mca_key_t *);
void	mca_session_releaseref(mca_session_t *, int);
void	mca_key_releaseref(mca_key_t *, int);
mca_session_t *mca_session_holdref(mca_t *, crypto_session_id_t);
int	mca_write_key(mca_t *, crypto_session_id_t, crypto_key_t *,
    caddr_t, uint32_t *, uint32_t *);
int	mca_write_keys(mca_t *, crypto_session_id_t, crypto_key_t *,
    crypto_key_t *, caddr_t, uint32_t *, caddr_t, uint32_t *,
    uint32_t *, uint32_t *);
int	mca_hw_provider_register(mca_t *, int);
int	mca_hw_provider_unregister(mca_t *);
int	mca_logical_provider_register(mca_keystore_t *, mca_t *);
int	mca_logical_provider_unregister(mca_keystore_t *);
int	mca_provider_in_use(mca_t *);
int	mca_chgstate_offline(mca_t *);
int	mca_chgstate_diag(mca_t *);
int	mca_chgstate_online(mca_t *);
void	mca_probe(int *, int *);
void	mca_get_devinfo(mca_t *mca, int *, int *);
void	mca_get_verinfo(mca_t *mca, uint32_t *, uint32_t *, uint32_t *);
int	mca_presuspend(mca_t *, int);
int	mca_postresume(mca_t *, int);
void	mca_unsuspend(mca_t *);

/*
 * mca_rsa.c
 */
int mca_rsainit(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, int, uint32_t, mca_privatectx_t **);
int mca_rsa(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t *, uint32_t);
int mca_rsaatomic(mca_t *, crypto_session_id_t,
    crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t *, uint32_t);


/*
 * mca_dsa.c
 */
int mca_dsainit(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, int, uint32_t, mca_privatectx_t **);
int mca_dsa(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t *, uint32_t);
int mca_dsaatomic(mca_t *, crypto_session_id_t,
    crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t *, uint32_t);

/*
 * mca_ecdsa.c
 */
int mca_ecdsainit(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, int, uint32_t, mca_privatectx_t **);
int mca_ecdsa(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t *, uint32_t);
int mca_ecdsaatomic(mca_t *, crypto_session_id_t,
    crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t *, uint32_t);

/*
 * mca_3des.c
 */
int mca_3desinit(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *,
    int, uint32_t, mca_privatectx_t **);
int mca_3des(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t *, uint32_t);
int mca_3desupdate(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t *, uint32_t);
int mca_3desfinal(crypto_ctx_t *, crypto_data_t *, crypto_req_handle_t *,
    uint32_t);
int mca_3desatomic(mca_t *, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t *, uint32_t);


/*
 * mca_hash.c
 */
int mca_hash_allocctx(crypto_ctx_t *, crypto_req_handle_t *,
    crypto_mechanism_t *, mca_privatectx_t **);
int mca_hash_init(mca_t *, mca_privatectx_t *, uint32_t cmd,
    crypto_data_t *, crypto_data_t *, crypto_req_handle_t *);
int mca_hash_update(mca_t *, uint32_t ctxid, uint32_t cmd,
    crypto_data_t *, crypto_req_handle_t *);
int mca_hash_key(crypto_ctx_t *, crypto_key_t *, crypto_req_handle_t *);
int mca_hash_final(mca_t *, uint32_t ctxid, uint32_t cmd,
    crypto_data_t *, crypto_req_handle_t *);
int mca_hash(mca_t *, uint32_t cmd, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t *);


/*
 * mca_hmac.c
 */
int mca_hmac_allocctx(mca_t *mca, crypto_session_id_t, crypto_mechanism_t *,
    crypto_key_t *, mca_privatectx_t **);
int mca_hmac_init(mca_t *, mca_privatectx_t *, uint32_t cmd,
    crypto_data_t *, crypto_data_t *, crypto_req_handle_t *);
int mca_hmac_update(mca_t *, uint32_t ctxid, uint32_t cmd,
    crypto_data_t *, crypto_req_handle_t *);
int mca_hmac_final(mca_t *, mca_privatectx_t *, crypto_data_t *,
    crypto_req_handle_t *);
int mca_hmac(mca_privatectx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t *, uint32_t);
int mca_hmac_atomic(mca_t *, crypto_session_id_t, crypto_mechanism_t *,
    crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t *, uint32_t cmd);



/*
 * mca_rng.c
 */
int mca_rng(mca_t *, crypto_data_t *, crypto_req_handle_t *, uint32_t);

/*
 * mca_login.c
 */
int mca_login(mca_t *, mca_keystore_t *, mca_session_t *, char *, char *,
    crypto_req_handle_t *);
int mca_createkey_flags(cpg_attr_t *, uint32_t *);
int mca_createkey(mca_t *, mca_session_t *, cpg_attr_t *,
    uint32_t *, crypto_req_handle_t *, mca_keystore_t *);
int mca_deletekey(mca_t *, mca_session_t *, mca_key_t *,
    crypto_req_handle_t *);
int mca_loadkeys(mca_request_t *);
int mca_loadkeys_ctxalloc(mca_t *, mca_key_t **, size_t, mca_user_t *,
    mca_loadkeys_ctx_t **);
void mca_loadkeys_ctxfree(void *);
int mca_merge_templates(cpg_attr_t *, cpg_attr_t *, uint32_t *);
int mca_merge_templates4copy(cpg_attr_t *, cpg_attr_t *, uint32_t *);
int mca_copykey(mca_t *, mca_session_t *, mca_key_t *, cpg_attr_t *,
    uint32_t *, crypto_req_handle_t *, mca_keystore_t *);
int mca_modifykey(mca_t *, mca_session_t *, mca_key_t *,
    cpg_attr_t *, crypto_req_handle_t *);
int mca_setpass(mca_t *, char *, char *, char *, crypto_req_handle_t *,
    mca_keystore_t *, crypto_session_id_t);
void	mca_user_rdlock(mca_user_t *);
void	mca_user_wrlock(mca_user_t *);
void	mca_user_unlock(mca_user_t *);



/*
 * mca.c
 */
int	mca_key_lookup_uint32(crypto_key_t *, int, uint32_t *);
int	mca_key_lookup_uint8_array(crypto_key_t *, int, uint8_t **,
    uint32_t *);
int	mca_get_mech_param(crypto_mechanism_t *, char *, int *);
mca_key_t *mca_get_key_private(crypto_key_t *);
void	mca_getbufbytes(crypto_data_t *, int, int, char *);
int	mca_getresid(crypto_data_t *);
void	mca_setresid(crypto_data_t *, int);
void	mca_updateoutlen(crypto_data_t *, int);

int	mca_sg(crypto_data_t *);
int	mca_scatter(caddr_t, size_t, crypto_data_t *);
int	mca_unpad_scatter(caddr_t, size_t, crypto_data_t *, uint32_t);
int	mca_gather(crypto_data_t *, caddr_t, size_t);
int	mca_gather_pad(crypto_data_t *, caddr_t, size_t, char);
int	mca_gather_zero_pad(crypto_data_t *, caddr_t, size_t, int);

int	mca_get_datalen(crypto_data_t *);
void	mca_set_datalen(crypto_data_t *, size_t);
char	*mca_get_dataaddr(crypto_data_t *buf);
void	mca_freectx(void *);
int	mca_bindchains(mca_request_t *, size_t, size_t);
int	mca_get_session_cred(mca_session_t *, uint32_t *);
int	mca_set_session_cred(mca_session_t *, uint32_t *, mca_user_t *);
int	mca_add_key(mca_session_t *, mca_key_t *, uint32_t *);
int	mca_add_keys(mca_session_t *, mca_key_t *, mca_key_t *,
    uint32_t *, uint32_t *);
void	mca_post_login(mca_request_t *);
void	mca_post_loadkeys(mca_request_t *);
void	mca_invalidate_key(mca_key_t *);
void	mca_delete_user(mca_user_t *);

void	mca_log_system_msg(mca_t *, uint8_t, char *);

/* FMA prototypes for external consumption */
#ifdef FMA_COMPLIANT
void	mca_fm_ereport_post(mca_t *, uint64_t, uint8_t, char *);
char	*mca_fm_class_string(mca_t *, uint8_t);
#define	MCA_EREPORT_POST(mca, level, ena, error_id, msg) \
	mca_fm_ereport_post(mca, ena, error_id, msg);
#else
#define	MCA_EREPORT_POST(mca, level, ena, error_id, msg) \
	mca_log_system_msg(mca, level, msg);
#endif /* FMA_COMPLIANT */

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MCA_H */
