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

#pragma ident	"@(#)mca_table.c	1.4	08/01/09 SMI"

/*
 * Mars - pure cryptographic acceleration + secure keystore
 */

#ifdef LINUX
#include <linux/types.h>
#include "sol2lin.h"
#include "mca_table.h"
#else
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/mca_table.h>
#endif

/*
 * Generic table code.  We use this instead of ddi_soft_state because
 * unlike ddi_soft_state, this table can grow easily, *without* wasting
 * resources.  (We do a proper-realloc, rather than leaving the old
 * table storage around.)  We also have a non-sleeping version of
 * slot allocation, unlike ddi_soft_state_zalloc.  Furthermore, unlike
 * ddi_soft_state, the ID numbers returned are dynamic, so we don't
 * have to find a free slot explicitly.  We also have an enumeration
 * interface.  We do allow for preallocating the soft state prior to
 * registration (avoids an attach() race condition), and for inserting
 * the softstate into a specific slot (which gives compatibility with
 * the ddi_soft_state routines.)
 *
 * NOTE: the mca_table user is responsible for protecting the table
 * resources. The table logic itself provides no resource locking.
 */

static int mca_table_resize(mca_table_t *, int newsize, int kmflag);

void
mca_table_init(mca_table_t *t, int slotsize, int initsize, int chunk,
    void (*slotdtr)(void *))
{
	t->t_slotsize = slotsize;
	t->t_numslots = 0;
	t->t_usedslots = 0;
	t->t_nextslot = 0;
	t->t_slotchunk = chunk > 0 ? chunk : 1;
	t->t_slotdtr = slotdtr;
	t->t_nrow = NROW_INIT;
	t->t_rowlen = ROW_LENGTH;

#ifdef LINUX
	t->t_slots = kmem_alloc(t->t_nrow * sizeof (void **), GFP_ATOMIC);
#else
	t->t_slots = kmem_alloc(t->t_nrow * sizeof (void **), KM_SLEEP);
#endif
	bzero(t->t_slots, t->t_nrow * sizeof (void **));

	if (initsize > 0) {
		(void) mca_table_resize(t, initsize, KM_SLEEP);
	}
}

void
mca_table_destroy(mca_table_t *t)
{
	int	i;
	int	row;
	int	col;

	for (i = 0; i < t->t_numslots; i++) {
		row = i / t->t_rowlen;
		col = i % t->t_rowlen;
		if (t->t_slots[row][col] != NULL) {
			if (t->t_slotdtr != NULL) {
				t->t_slotdtr(t->t_slots[row][col]);
			} else {
				kmem_free(t->t_slots[row][col], t->t_slotsize);
			}
		}

		/* Free the previous empty row */
		if (i != 0 && col == 0)
			kmem_free(t->t_slots[row - 1],
				t->t_rowlen * sizeof (void *));
	}

	/* Free the last row if exists */
	row = (t->t_numslots - 1) / t->t_rowlen;
	col = (t->t_numslots - 1) % t->t_rowlen;
	if (t->t_numslots > 0)
		kmem_free(t->t_slots[row], (col+1) * sizeof (void *));

	kmem_free(t->t_slots, t->t_nrow * sizeof (void **));
}

/*
 * Allocate a slot and add it to the table.
 */
int
mca_table_alloc_slot(mca_table_t *t, int *indexp, void **slotp, int kmflag)
{
#ifdef LINUX
	if ((*slotp = kmem_zalloc(t->t_slotsize, KM_NOSLEEP)) == NULL) {
		return (DDI_FAILURE);
	}

	if (mca_table_add_slot(t, indexp, *slotp, KM_NOSLEEP) != DDI_SUCCESS) {
		kmem_free(*slotp, t->t_slotsize);
		return (DDI_FAILURE);
	}
#else
	if ((*slotp = kmem_zalloc(t->t_slotsize, kmflag)) == NULL) {
		return (DDI_FAILURE);
	}

	if (mca_table_add_slot(t, indexp, *slotp, kmflag) != DDI_SUCCESS) {
		kmem_free(*slotp, t->t_slotsize);
		return (DDI_FAILURE);
	}
#endif
	return (DDI_SUCCESS);
}

/*
 * Add a preallocated slot to the table.
 */
int
mca_table_add_slot(mca_table_t *t, int *indexp, void *slot, int kmflag)
{
	int		index;
	int		rv;
	int		row = 0, col = 0;

	while (t->t_usedslots >= t->t_numslots) {
		rv = mca_table_resize(t, t->t_numslots + t->t_slotchunk,
		    kmflag);
		if (rv != 0) {
			return (rv);
		}
	}

	/* find a free slot */
	for (index = t->t_nextslot; ; index++) {
		row = index / t->t_rowlen;
		col = index % t->t_rowlen;
		if (t->t_slots[row][col] == NULL)
			break;
	}

	t->t_slots[row][col] = slot;
	*indexp = index;
	t->t_nextslot = index + 1;
	t->t_usedslots++;

	return (DDI_SUCCESS);
}

/*
 * This sets a given slot entry.  This is useful when the index
 * into the slot will be some fixed value, like the instance number
 * of a device.  In such a case, the nextslot value will not be
 * updated, since we are not necessarily densly packing the array.
 * Normally, this function won't be used with the add_slot or
 * alloc_slot, so this won't even matter.
 */
int
mca_table_set_slot(mca_table_t *t, int index, void *slot, int kmflag)
{
	int		rv;

	while (max(index, t->t_usedslots) >= t->t_numslots) {
		rv = mca_table_resize(t, t->t_numslots + t->t_slotchunk,
		    kmflag);
		if (rv != 0) {
			return (rv);
		}
	}

	t->t_slots[index / t->t_rowlen][index % t->t_rowlen] = slot;
	t->t_usedslots++;

	return (DDI_SUCCESS);
}

/*
 * Remove a slot from the table without freeing it.
 */
void
mca_table_remove_slot(mca_table_t *t, int index)
{
	ASSERT((index >= 0) && (index < t->t_numslots));
	t->t_slots[index / t->t_rowlen][index % t->t_rowlen] = NULL;
	if (t->t_nextslot > index) {
		t->t_nextslot = index;
	}
	t->t_usedslots--;
}

/*
 * Remove a slot from the table, *and* free it.
 */
void
mca_table_free_slot(mca_table_t *t, int index)
{
	void	*p;

	ASSERT((index >= 0) && (index < t->t_numslots));
	p = t->t_slots[index / t->t_rowlen][index % t->t_rowlen];
	ASSERT(p != NULL);
	t->t_slots[index / t->t_rowlen][index % t->t_rowlen] = NULL;
	if (t->t_nextslot > index) {
		t->t_nextslot = index;
	}
	t->t_usedslots--;

	kmem_free(p, t->t_slotsize);
}

int
mca_table_lookup(mca_table_t *t, int index, void **slotp)
{
	void *p;
	if ((index < 0) || (index >= t->t_numslots)) {
		return (DDI_FAILURE);
	}
	if ((p = t->t_slots[index / t->t_rowlen][index % t->t_rowlen]) ==
	    NULL) {
		return (DDI_FAILURE);
	}
	*slotp = p;
	return (DDI_SUCCESS);
}

/*
 * This is an interator function.  The id should be -1 to start the
 * iteration.  On exit it will have the index of a valid slot in it,
 * or -1 if there are no more slots.
 */
int
mca_table_next_slot(mca_table_t *t, int *id)
{
	int slot = *id + 1;
	if (slot < 0) {
		*id = -1;
		return (DDI_FAILURE);
	}
	while (slot < t->t_numslots) {
		if (t->t_slots[slot / t->t_rowlen][slot % t->t_rowlen] !=
		    NULL) {
			*id = slot;
			return (DDI_SUCCESS);
		}
		slot++;
	}
	*id = -1;
	return (DDI_FAILURE);
}

/* resize the table, call with t_lock held */
static int
mca_table_resize(mca_table_t *t, int nslots, int kmflag)
{
	int		slot;
	int		nsize;
	void		**newslots;
	int		row, col;
	int		row_old, col_old;
	int		n_entries;
	int		mem_flag;

#ifdef LINUX
	/*
	 * Memory allocation function may be called within spinlocks,
	 * so have to use atomic
	 */
	mem_flag = GFP_ATOMIC;
#else
	mem_flag = kmflag;
#endif

	/*
	 * The last row and the last entry in the last row.
	 * If t->t_numslots == 0, row_old and col_old will be 0 and -1
	 * respectively
	 */
	row_old = (t->t_numslots - 1) / t->t_rowlen;
	col_old = (t->t_numslots - 1) % t->t_rowlen;

	/* The new last row and the last entry in the new last row */
	row = (nslots - 1) / t->t_rowlen;
	col = (nslots - 1) % t->t_rowlen;

	if (col_old < t->t_rowlen - 1) {
		/*
		 * The old row still has space.
		 * Reallocate the row and copy over the results
		 */
		n_entries = (col_old + 1) + (nslots - t->t_numslots);
		if (n_entries > t->t_rowlen)
			n_entries = t->t_rowlen;
		nsize = sizeof (void *) * n_entries;

		newslots = kmem_alloc(nsize, mem_flag);
		if (newslots == NULL) {
			return (DDI_FAILURE);
		}
		for (slot = 0; slot < n_entries; slot++) {
			if (slot <= col_old) {
				newslots[slot] = t->t_slots[row_old][slot];
			} else {
				newslots[slot] = NULL;
			}
		}
		/* this is safe even if (col_old + 1) is zero! */
		kmem_free(t->t_slots[row_old], (col_old + 1) * sizeof (void *));

		t->t_slots[row_old] = newslots;
	}

	if (row > row_old) {
		if (row >= t->t_nrow) {
			void ***tmp;
			int nrow = t->t_nrow + 1;

			tmp = kmem_alloc(nrow * sizeof (void **), mem_flag);
			memcpy(tmp, t->t_slots, t->t_nrow * sizeof (void **));
			kmem_free(t->t_slots, t->t_nrow * sizeof (void **));

			t->t_slots = tmp;
			t->t_nrow = nrow;
		}

		/* Start another row for the remainings */
		nsize = sizeof (void *) * (col + 1);

		newslots = kmem_alloc(nsize, mem_flag);
		if (newslots == NULL) {
			return (DDI_FAILURE);
		}
		for (slot = 0; slot <= col; slot++) {
			newslots[slot] = NULL;
		}

		t->t_slots[row] = newslots;
	}

	t->t_numslots = nslots;
	return (DDI_SUCCESS);
}
