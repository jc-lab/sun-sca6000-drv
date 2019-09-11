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

#pragma ident	"@(#)mca_debug.c	1.4	07/02/09 SMI"

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
#include <sys/cmn_err.h>
#include <sys/varargs.h>
#include <sys/mca.h>
#endif

/*
 * Debugging and messaging.
 */
static void	mca_dipverror(dev_info_t *, int, const char *, va_list);

#ifdef DEBUG
static int mca_debug = DWARN;
#else
static int mca_debug = 0;
#endif

void
mca_dprintf(mca_t *mca, int level, const char *fmt, ...)
{
	va_list ap;
	if (mca_debug & level) {
		va_start(ap, fmt);
		mca_dipverror(mca ? mca->mca_dip : NULL, CE_CONT, fmt, ap);
		va_end(ap);
	}
}

void
mca_info(mca_t *mca, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	mca_dipverror(mca->mca_dip, CE_CONT, fmt, ap);
	va_end(ap);
}

void
mca_note(mca_t *mca, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (mca)
		mca_dipverror(mca->mca_dip, CE_NOTE, fmt, ap);
	else
		mca_dipverror(NULL, CE_NOTE, fmt, ap);
	va_end(ap);
}

void
mca_error(mca_t *mca, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (mca != NULL)
		mca_dipverror(mca->mca_dip, CE_WARN, fmt, ap);
	else
		mca_dipverror(NULL, CE_WARN, fmt, ap);
	va_end(ap);
}

void
mca_diperror(dev_info_t *dip, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	mca_dipverror(dip, CE_WARN, fmt, ap);
	va_end(ap);
}

void
mca_dipverror(dev_info_t *dip, int lvl, const char *fmt, va_list ap)
{
	char	buf[256];
	if (dip != NULL) {
		sprintf(buf, "%s%d: %s%s",
		    ddi_driver_name(dip), ddi_get_instance(dip), fmt,
		    lvl == CE_CONT ? "\n" : "");
	} else {
		sprintf(buf, "%s%s",
		    fmt, lvl == CE_CONT ? "\n" : "");
	}
	vcmn_err(lvl, buf, ap);
}

int
mca_dflagset(int flag)
{
	return (flag & mca_debug);
}

void
mca_dumphex(void *data, int len)
{
	uchar_t	*buff;
	int	i, j, tlen;
	char	scratch[128];
	char	*out;
	if (data == NULL) {
		(void) cmn_err(CE_WARN, "data is NULL");
		return;
	}

	buff = (uchar_t *)data;
	for (i = 0; i < len; i += 16) {
		out = scratch;
		tlen = i + 16;
		tlen = len < tlen ? len : tlen;
		(void) sprintf(out, "%p: ", (void *)(buff + i));
		while (*out) {
			out++;
		}
		out += strlen(out);
		for (j = i; j < tlen; j++) {
			(void) sprintf(out, "%02X ", buff[j]);
			out += 3;
		}
		for (j = len; j < i + 16; j++) {
			(void) strcpy(out, "   ");
			out += 3;
		}
		(void) sprintf(out, "    ");
		out += 4;
		for (j = i; j < tlen; j++) {
			/* poor man's isprint() */
			if ((buff[j] > 32) && (buff[j] < 127)) {
				*(out++) = buff[j];
			} else {
				*(out++) = '.';
			}
			*(out) = 0;
		}
		cmn_err(CE_NOTE, "%s\n", scratch);
	}
}

/*
 * dtrace functions.
 */
static uintptr_t value_holder;

static uintptr_t
dummy_store(
	uintptr_t value)
{
	value_holder = value;

	return (value_holder);
}

uintptr_t
cpg_trace_1(
	/* ARGSUSED */
	const char *__function__,
	uintptr_t value1)
{
	return (dummy_store(value1));
}

uintptr_t
cpg_trace_2(
	/* ARGSUSED */
	const char *__function__,
	uintptr_t value1,
	uintptr_t value2)
{
	return (dummy_store(value1));
}

uintptr_t
cpg_trace_3(
	/* ARGSUSED */
	const char *__function__,
	uintptr_t value1,
	uintptr_t value2,
	uintptr_t value3)
{
	return (dummy_store(value1));
}

uintptr_t
cpg_trace_4(
	/* ARGSUSED */
	const char *__function__,
	uintptr_t value1,
	uintptr_t value2,
	uintptr_t value3,
	uintptr_t value4)
{
	return (dummy_store(value1));
}
