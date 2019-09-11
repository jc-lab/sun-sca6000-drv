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

#ifndef	_SYS_MCA_TABLE_H
#define	_SYS_MCA_TABLE_H

#pragma ident	"@(#)mca_table.h	1.2	08/01/09 SMI"

#ifdef LINUX
#include <linux/types.h>
#else
#include <sys/types.h>
#include <sys/ksynch.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Mars - pure cryptographic acceleration + secure keystore
 *
 * Note: Everything in this file is private to the Mars device
 *	 driver!  Do not include this in any other file.
 */

#ifdef	_KERNEL

#define	ROW_LENGTH		8192
#define	NROW_INIT		10

typedef struct mca_table {
	int		t_slotsize;
	int		t_numslots;
	int		t_usedslots;
	int		t_nextslot;
	int		t_slotchunk;
	int		t_nrow;
	int		t_rowlen;
	void		***t_slots;
	void		(*t_slotdtr)(void *);
} mca_table_t;

void	mca_table_init(mca_table_t *, int slotsize, int initsize, int chunk,
    void (*slotdtr)(void *));
void	mca_table_destroy(mca_table_t *);
int	mca_table_add_slot(mca_table_t *, int *indexp, void *slot, int km);
int	mca_table_set_slot(mca_table_t *, int index, void *slot, int km);
void	mca_table_remove_slot(mca_table_t *, int index);
int	mca_table_alloc_slot(mca_table_t *, int *indexp, void **slotp, int km);
void	mca_table_free_slot(mca_table_t *, int index);
int	mca_table_lookup(mca_table_t *, int index, void **slotp);
int	mca_table_next_slot(mca_table_t *, int *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MCA_TABLE_H */
