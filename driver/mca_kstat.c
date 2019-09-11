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

#pragma ident	"@(#)mca_kstat.c	1.13	07/07/30 SMI"

/*
 * Mars - pure cryptographic acceleration + secure keystore
 */

#ifdef LINUX
#include <linux/types.h>
#include "sol2lin.h"
#include "mca.h"
#else
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kstat.h>
#include <sys/mca.h>
#endif

/*
 * Kernel statistics.
 */
#ifdef LINUX
static int mca_ksupdate(char *, char **, off_t, int, int *, void *);
#else
static int mca_ksupdate(kstat_t *, int);
#endif

/*
 * Initialize Kstats.
 */
void
mca_ksinit(mca_t *mca)
{
	char	buf[64];
	int	instance;

	instance = ddi_get_instance(mca->mca_dip);

	/*
	 * Interrupt kstats.
	 */
	(void) sprintf(buf, "%sc%d", MCA_IDNAME, instance);
	if ((mca->mca_intrstats = kstat_create(MCA_IDNAME, instance, buf,
	    "controller", KSTAT_TYPE_INTR, 1, 0)) == NULL) {
		mca_error(mca, "unable to create interrupt kstat");
	} else {
		kstat_install(mca->mca_intrstats);
	}

	/*
	 * Named kstats.
	 */
	if ((mca->mca_ksp = kstat_create(MCA_IDNAME, instance, NULL, "misc",
	    KSTAT_TYPE_NAMED, sizeof (mca_stat_t) / sizeof (kstat_named_t),
	    0)) == NULL) {
		mca_error(mca, "unable to create kstats");
	} else {
		mca_stat_t *mkp = (mca_stat_t *)mca->mca_ksp->ks_data;
		kstat_named_init(&mkp->ms_mode, "mode", KSTAT_DATA_CHAR);
		kstat_named_init(&mkp->ms_status, "status", KSTAT_DATA_CHAR);

		/*
		 * Only register crypto kstats if sysadmin has not explicity
		 * disabled them to prevent covert channel.
		 */
		if (ddi_getprop(DDI_DEV_T_ANY, mca->mca_dip,
		    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
		    "nostats", 0) == 0) {
			kstat_named_init(&mkp->ms_cbsubmit, "cbsubmit",
			    KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_cbflowctl, "cbflowctl",
			    KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_cblowater, "cblowater",
			    KSTAT_DATA_ULONG);
			kstat_named_init(&mkp->ms_cbhiwater, "cbhiwater",
			    KSTAT_DATA_ULONG);
			kstat_named_init(&mkp->ms_cbringsize, "cbringsize",
			    KSTAT_DATA_ULONG);
			kstat_named_init(&mkp->ms_cbcurrjobs, "cbcurrjobs",
			    KSTAT_DATA_ULONG);
			kstat_named_init(&mkp->ms_cbmaxjobs, "cbmaxjobs",
			    KSTAT_DATA_ULONG);

			kstat_named_init(&mkp->ms_casubmit, "casubmit",
			    KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_caflowctl, "caflowctl",
			    KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_calowater, "calowater",
			    KSTAT_DATA_ULONG);
			kstat_named_init(&mkp->ms_cahiwater, "cahiwater",
			    KSTAT_DATA_ULONG);
			kstat_named_init(&mkp->ms_caringsize, "caringsize",
			    KSTAT_DATA_ULONG);
			kstat_named_init(&mkp->ms_cacurrjobs, "cacurrjobs",
			    KSTAT_DATA_ULONG);
			kstat_named_init(&mkp->ms_camaxjobs, "camaxjobs",
			    KSTAT_DATA_ULONG);

			kstat_named_init(&mkp->ms_omsubmit, "omsubmit",
			    KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_omflowctl, "omflowctl",
			    KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_omlowater, "omlowater",
			    KSTAT_DATA_ULONG);
			kstat_named_init(&mkp->ms_omhiwater, "omhiwater",
			    KSTAT_DATA_ULONG);
			kstat_named_init(&mkp->ms_omringsize, "omringsize",
			    KSTAT_DATA_ULONG);
			kstat_named_init(&mkp->ms_omcurrjobs, "omcurrjobs",
			    KSTAT_DATA_ULONG);
			kstat_named_init(&mkp->ms_ommaxjobs, "ommaxjobs",
			    KSTAT_DATA_ULONG);

			/* md5 */
			kstat_named_init(&mkp->ms_algs[MS_MD5JOBS], "md5jobs",
			    KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_MD5BYTES],
			    "md5bytes", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_MD5HMACJOBS],
			    "md5hmacjobs", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_MD5HMACBYTES],
			    "md5hmacbytes", KSTAT_DATA_ULONGLONG);
			/* sha1 */
			kstat_named_init(&mkp->ms_algs[MS_SHA1JOBS],
			    "sha1jobs", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_SHA1BYTES],
			    "sha1bytes", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_SHA1HMACJOBS],
			    "sha1hmacjobs", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_SHA1HMACBYTES],
			    "sha1hmacbytes", KSTAT_DATA_ULONGLONG);
			/* sha512 */
			kstat_named_init(&mkp->ms_algs[MS_SHA512JOBS],
			    "sha512jobs", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_SHA512BYTES],
			    "sha512bytes", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_SHA512HMACJOBS],
			    "sha512hmacjobs", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_SHA512HMACBYTES],
			    "sha512hmacbytes", KSTAT_DATA_ULONGLONG);
			/* 3des */
			kstat_named_init(&mkp->ms_algs[MS_3DESJOBS],
			    "3desjobs", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_3DESBYTES],
			    "3desbytes", KSTAT_DATA_ULONGLONG);
			/* aes */
			kstat_named_init(&mkp->ms_algs[MS_AESJOBS],
			    "aesjobs", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_AESBYTES],
			    "aesbytes", KSTAT_DATA_ULONGLONG);
			/* financial services */
			kstat_named_init(&mkp->ms_algs[MS_FSJOBS],
			    "fsjobs", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_FSBYTES],
			    "fsbytes", KSTAT_DATA_ULONGLONG);
			/* rsa */
			kstat_named_init(&mkp->ms_algs[MS_RSAPUBLIC],
			    "rsapublic", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_RSAPRIVATE],
			    "rsaprivate", KSTAT_DATA_ULONGLONG);
			/* dsa */
			kstat_named_init(&mkp->ms_algs[MS_DSASIGN], "dsasign",
			    KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_DSAVERIFY],
			    "dsaverify", KSTAT_DATA_ULONGLONG);
			/* diffie-hellman */
			kstat_named_init(&mkp->ms_algs[MS_DHKEYGEN],
			    "dhkeygen", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_DHDERIVE],
			    "dhderive", KSTAT_DATA_ULONGLONG);
			/* ecc */
			kstat_named_init(&mkp->ms_algs[MS_ECKEYGEN],
			    "eckeygen", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_ECDHDERIVE],
			    "ecdhderive", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_ECDSASIGN],
			    "ecdsasign", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_ECDSAVERIFY],
			    "ecdsaverify", KSTAT_DATA_ULONGLONG);
			/* random number jobs */
			kstat_named_init(&mkp->ms_algs[MS_RNGJOBS], "rngjobs",
			    KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_RNGBYTES],
			    "rngbytes", KSTAT_DATA_ULONGLONG);
			/* secret key generations */
			kstat_named_init(&mkp->ms_algs[MS_KEYGENJOBS],
			    "keygenjobs", KSTAT_DATA_ULONGLONG);
			/* wrap/unwrap jobs */
			kstat_named_init(&mkp->ms_algs[MS_WRAPJOBS],
			    "wrapjobs", KSTAT_DATA_ULONGLONG);
			kstat_named_init(&mkp->ms_algs[MS_UNWRAPJOBS],
			    "unwrapjobs", KSTAT_DATA_ULONGLONG);
			/* digestkey jobs */
			kstat_named_init(&mkp->ms_algs[MS_HASHKEYJOBS],
			    "hashkeyjobs", KSTAT_DATA_ULONGLONG);
		}

		mca->mca_ksp->ks_update = mca_ksupdate;
		mca->mca_ksp->ks_private = mca;
		kstat_install(mca->mca_ksp);
	}
}

/*
 * Update Kstat.
 */
#ifdef LINUX
#define	CHECK_BUFFER(len, limit, eof)		\
	{					\
		if (len > limit) {		\
			*eof = 1;		\
			return (len);		\
		}				\
	}

static int
mca_ksupdate(char *page, char **start, off_t offset, int count,
    int *eof, void *data)
{
	mca_t		*mca;
	mca_stat_t	*mkp;
	kstat_t		*ksp;
	int		i;
	int		len = 0;
	int		limit = count - 80;

	mca = (mca_t *)data;
	ksp = mca->mca_ksp;
	mkp = (mca_stat_t *)ksp->ks_data;

	for (i = 0; i < MS_MAX && len <= limit; i++) {
		if (strlen(mkp->ms_algs[i].name) < 8)
			len += sprintf(page+len, "%s\t\t\t%lld\n",
			    mkp->ms_algs[i].name, mca->mca_stats[i]);
		else
			len += sprintf(page+len, "%s\t\t%lld\n",
			    mkp->ms_algs[i].name, mca->mca_stats[i]);
	}

	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t\t%s\n", mkp->ms_mode.name,
	    mca_isfips(mca) ? "FIPS" :
	    mca_isowned(mca) ? "standard" : "uninitialized");

	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t\t%s\n", mkp->ms_status.name,
	    mca_fm_isfailed(mca) ? "faulted" :
	    mca_fm_isfailsafe(mca) ? "failsafe" :
	    mca_isunregistered(mca) ? "offline" : "online");

	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%lld\n", mkp->ms_cbsubmit.name,
	    mca->mca_ring_cb.mr_submit);
	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%lld\n", mkp->ms_cbflowctl.name,
	    mca->mca_ring_cb.mr_flowctl);
	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%d\n", mkp->ms_cblowater.name,
	    mca->mca_ring_cb.mr_lowater);
	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%d\n", mkp->ms_cbhiwater.name,
	    mca->mca_ring_cb.mr_hiwater);
	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%d\n", mkp->ms_cbringsize.name,
	    mca->mca_ring_cb.mr_nreqs);
	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%d\n", mkp->ms_cbcurrjobs.name,
	    mca->mca_ring_cb.mr_ncurrjobs);
	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%d\n", mkp->ms_cbmaxjobs.name,
	    mca->mca_ring_cb.mr_nmaxjobs);

	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%lld\n", mkp->ms_casubmit.name,
	    mca->mca_ring_ca.mr_submit);
	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%lld\n", mkp->ms_caflowctl.name,
	    mca->mca_ring_ca.mr_flowctl);
	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%d\n", mkp->ms_calowater.name,
	    mca->mca_ring_ca.mr_lowater);
	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%d\n", mkp->ms_cahiwater.name,
	    mca->mca_ring_ca.mr_hiwater);
	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%d\n", mkp->ms_caringsize.name,
	    mca->mca_ring_ca.mr_nreqs);
	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%d\n", mkp->ms_cacurrjobs.name,
	    mca->mca_ring_cb.mr_ncurrjobs);
	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%d\n", mkp->ms_camaxjobs.name,
	    mca->mca_ring_cb.mr_nmaxjobs);

	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%lld\n", mkp->ms_omsubmit.name,
	    mca->mca_ring_om.mr_submit);
	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%lld\n", mkp->ms_omflowctl.name,
	    mca->mca_ring_om.mr_flowctl);
	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%d\n", mkp->ms_omlowater.name,
	    mca->mca_ring_om.mr_lowater);
	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%d\n", mkp->ms_omhiwater.name,
	    mca->mca_ring_om.mr_hiwater);
	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%d\n", mkp->ms_omringsize.name,
	    mca->mca_ring_om.mr_nreqs);
	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%d\n", mkp->ms_omcurrjobs.name,
	    mca->mca_ring_cb.mr_ncurrjobs);
	CHECK_BUFFER(len, limit, eof);
	len += sprintf(page+len, "%s\t\t%d\n", mkp->ms_ommaxjobs.name,
	    mca->mca_ring_cb.mr_nmaxjobs);

	*eof = 1;

	return (len);
}
#else
/*ARGSUSED*/
int
mca_ksupdate(kstat_t *ksp, int rw)
{
	mca_t		*mca;
	mca_stat_t	*mkp;
	int		i;

	mca = (mca_t *)ksp->ks_private;
	mkp = (mca_stat_t *)ksp->ks_data;

	for (i = 0; i < MS_MAX; i++) {
		mkp->ms_algs[i].value.ull = mca->mca_stats[i];
	}
	bzero(mkp->ms_mode.value.c, sizeof (mkp->ms_mode.value.c));
	strcpy(mkp->ms_mode.value.c,
	    mca_isfips(mca) ? "FIPS" :
	    mca_isowned(mca) ? "standard" :
	    "uninitialized");

	bzero(mkp->ms_status.value.c, sizeof (mkp->ms_status.value.c));
	strcpy(mkp->ms_status.value.c,
	    mca_fm_isfailed(mca) ? "faulted" :
	    mca_fm_isfailsafe(mca) ? "failsafe" :
	    mca_isdiag(mca) ? "diag" :
	    mca_isunregistered(mca) ? "offline" : "online");

	mkp->ms_cbsubmit.value.ull = mca->mca_ring_cb.mr_submit;
	mkp->ms_cbflowctl.value.ull = mca->mca_ring_cb.mr_flowctl;
	mkp->ms_cblowater.value.ul = mca->mca_ring_cb.mr_lowater;
	mkp->ms_cbhiwater.value.ul = mca->mca_ring_cb.mr_hiwater;
	mkp->ms_cbringsize.value.ul = mca->mca_ring_cb.mr_nreqs;
	mkp->ms_cbcurrjobs.value.ul = mca->mca_ring_cb.mr_ncurrjobs;
	mkp->ms_cbmaxjobs.value.ul = mca->mca_ring_cb.mr_nmaxjobs;

	mkp->ms_casubmit.value.ull = mca->mca_ring_ca.mr_submit;
	mkp->ms_caflowctl.value.ull = mca->mca_ring_ca.mr_flowctl;
	mkp->ms_calowater.value.ul = mca->mca_ring_ca.mr_lowater;
	mkp->ms_cahiwater.value.ul = mca->mca_ring_ca.mr_hiwater;
	mkp->ms_caringsize.value.ul = mca->mca_ring_ca.mr_nreqs;
	mkp->ms_cacurrjobs.value.ul = mca->mca_ring_ca.mr_ncurrjobs;
	mkp->ms_camaxjobs.value.ul = mca->mca_ring_ca.mr_nmaxjobs;

	mkp->ms_omsubmit.value.ull = mca->mca_ring_om.mr_submit;
	mkp->ms_omflowctl.value.ull = mca->mca_ring_om.mr_flowctl;
	mkp->ms_omlowater.value.ul = mca->mca_ring_om.mr_lowater;
	mkp->ms_omhiwater.value.ul = mca->mca_ring_om.mr_hiwater;
	mkp->ms_omringsize.value.ul = mca->mca_ring_om.mr_nreqs;
	mkp->ms_omcurrjobs.value.ul = mca->mca_ring_om.mr_ncurrjobs;
	mkp->ms_ommaxjobs.value.ul = mca->mca_ring_om.mr_nmaxjobs;

	return (0);
}
#endif
