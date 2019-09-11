/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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

#ifndef _SCA_PRIVATE_H
#define	_SCA_PRIVATE_H

#pragma ident	"@(#)sca_private.h	1.2	05/07/18 SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	SCA_SESSION_IN_USE		0x00000001
#define	SCA_SESSION_IS_BUSY		0x00000002
#define	SCA_SESSION_IS_CLOSED		0x00000004

/*
 * We have defined MAX_NUM_SCA_DEVICE which is the number of hardware cards
 * on the same system. Each hardware card may have more than one provider.
 */
#define	MAX_NUMBER_PROVIDER	(MAX_SLOT_ID-1) /* leave room for 1 soft slot */

/*
 * The state of a crypto job. It is used in the sca_session structure. It is
 * set to JS_RUNNING state when a job is submited by the framework. When a
 * provider finished a job, it will call the callback function provided by the
 * framework. The latter will set the state to JS_DATA_AVAILABLE and wake up
 * the waiting process.
 */
typedef enum sca_job_states {
	JS_FREE,
	JS_RUNNING,
	JS_ABORTED,
	JS_PENDING,
	JS_DATA_AVAILABLE
} sca_job_states_t;

/*
 * The wrapper data structure for the crypto_provider_info structure.
 * We need to add a few members for a given provider.
 */
typedef struct sca_provider {
	uint32_t		sp_id;
	uint32_t		sp_state;
	atomic_t		sp_ref_count;
	wait_queue_head_t	sp_wait;
	uint32_t		sp_hp_count;
	struct sca_provider	*sp_hp_list[MAX_NUMBER_PROVIDER];
	crypto_provider_info_t	*sp_info;
	uint32_t		sp_next_hp_index;
	wait_queue_head_t	sp_busy_queue;
} sca_provider_t;

/*
 * Encapsulate a provider session and its related information.
 * It also maintains a list pointer.
 */
typedef struct sca_provider_session {
	struct sca_provider_session	*ps_next;
	crypto_session_id_t		ps_session;
	sca_provider_t			*ps_provider;
	uint_t				ps_refcnt;
} sca_provider_session_t;

/*
 * A crypto session data structure corresponds to a userland PKCS#11
 * session ID. It contains a job state and a context. It is used to submit
 * a crypto job to a provider.
 */
typedef struct sca_session {
	spinlock_t			ss_lock;
	wait_queue_head_t		ss_wait;
	wait_queue_head_t		ss_busy_wait;
	sca_job_states_t		ss_state;
	int				ss_rv;
	uint32_t			ss_flags;
	crypto_ctx_t			*ss_digest_ctx;
	crypto_ctx_t			*ss_encr_ctx;
	crypto_ctx_t			*ss_decr_ctx;
	crypto_ctx_t			*ss_sign_ctx;
	crypto_ctx_t			*ss_verify_ctx;
	crypto_ctx_t			*ss_sign_recover_ctx;
	crypto_ctx_t			*ss_verify_recover_ctx;
	void				*ss_find_init_cookie;
	sca_provider_session_t		*ss_provider_session;
} sca_session_t;

/*
 * A private data structure associates to a file descriptor. It stores
 * a session table and a linked-list of provider sessions.
 */
typedef struct sca_file_private {
	spinlock_t			fp_lock;
	sca_session_t			**fp_session_table;
	uint_t				fp_session_table_count;
	sca_provider_session_t		*fp_provider_session;
} sca_file_private_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SCA_PRIVATE_H */
