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

#pragma ident	"@(#)cpg_attr.c	1.16	07/07/09 SMI"

#ifdef LINUX
#include <linux/types.h>
#include "sol2lin.h"
#include "cpg_attr.h"

#define	NOTE CE_NOTE
#define	REPORT_ERROR(level, ...) {cmn_err(level, __VA_ARGS__); }
#define	MALLOC(size, flags) kmem_alloc(size, KM_NOSLEEP)
#define	ZMALLOC(size, flags) kmem_zalloc(size, KM_NOSLEEP)
#define	FREE(addr, size) kmem_free(addr, size)

#else /* LINUX */

#include <sys/types.h>
#include <sys/cpg_attr.h>
#include <values.h>

/*
 * Set up error logging
 */

#ifdef _KERNEL

#include <sys/cmn_err.h>

#define	NOTE CE_NOTE
#define	REPORT_ERROR(level, ...) {cmn_err(level, __VA_ARGS__); }

#else

#include <syslog.h>

#define	NOTE LOG_ERR
#ifdef DEBUG
#define	REPORT_ERROR(level, ...) {syslog(level, __VA_ARGS__); abort(); }
#else
#define	REPORT_ERROR(level, ...) {syslog(level, __VA_ARGS__); }
#endif
#endif


/*
 * Set up memory managment
 */

#ifdef _KERNEL
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#define	MALLOC(size, flags) kmem_alloc(size, \
	((flags) & CPG_ATTR_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP)
#define	ZMALLOC(size, flags) kmem_zalloc(size, \
	((flags) & CPG_ATTR_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP)
#define	FREE(addr, size) kmem_free(addr, size)
#else
#include <stdlib.h>
#include <strings.h>  /* for bcopy and bzero */
#define	MALLOC(size, flags) malloc(size)
#define	ZMALLOC(size, flags) calloc(size, 1)
#define	FREE(addr, size) free(addr)
#endif

#endif /* LINUX */

#define	CPG_ATTR_VERSION 2

/*
 * DEREF(type typesig, int offset, void *basep) computes an address
 * +*offset bytes beyond basep, and casts it to (typesig *).  The
 * (void *) cast keeps lint happy.  Note that DEREF works even with
 * 64-bit pointers and offsets.  DEREF_N is like DEREF but returns
 * null on zero offsets.
 */
#define	DEREF(typesig, offset, basep) \
	((typesig *)(void *)((char *)(basep) + offset))
#define	DEREF_N(typesig, offset, basep) \
	((offset) ? DEREF(typesig, offset, basep) : NULL)
#define	ARRAY_ADDR(blobp, entryp) \
	DEREF(void, entryp->data.array_descriptor.offset, blobp)
#define	ARRAY_LENGTH(p) (p->data.array_descriptor.length * \
	(p->flags & CPG_ATTR_DATASIZE_MASK))
#define	FREE_SPACE_ADDR(bp) DEREF(void, bp->size, bp)

/*
 * ATTRHASH XORs 4 groups of 3 bits into 3 bits.  It does this in two
 * XORs, first of 6 bit chunks, then 3 bit chunks.  h, which must be
 * an l-value, gets assigned first, because k is sometimes a very
 * expensive expression to evaluate (SWAP32...).
 */
#define	ATTRHASH(h, k) h = (k); h ^= (h >> 6); h ^= (h >> 3); h &= 0x7
#define	DATASIZE(flags) ((flags) & CPG_ATTR_DATASIZE_MASK)


/*
 * Byte swapping macros.  Borrowed from byteorder.h on Solaris x86.
 */
#define	SWAP8F(x)	((x) & 0xff)
#define	SWAP16F(x)	((SWAP8F(x) << 8) | SWAP8F((x) >> 8))
#define	SWAP32F(x)	((SWAP16F(x) << 16) | SWAP16F((x) >> 16))
#define	SWAP64F(x)	((SWAP32F(x) << 32) | SWAP32F((x) >> 32))

#define	SWAP16(lval) (lval = SWAP16F(lval))
#define	SWAP32(lval) (lval = SWAP32F(lval))
#define	SWAP64(lval) (lval = SWAP64F(lval))

#define	ROUNDUP8(x) (((x)+7) & ~7)

/*
 * Macro for the pad word in a cpg_attribute.  The value does not
 * matter, but this sets it to 0xbabennnn where nnnn is the offset of
 * the attribute.  This makes it easy to find a given attribute using
 * the debugger.
 */
#define	PADVAL(offset) (0xbabe0000 + (offset))

#define	LEGAL_ADD_ENTRY_FLAGS (CPG_ATTR_SENSITIVE | CPG_ATTR_LOCAL | \
    CPG_ATTR_NOSLEEP | CPG_ATTR_OVERRIDE)

/* These can actually go in the flags field of a cpg_attribute_t */
#define	LEGAL_ATTR_FLAGS (CPG_ATTR_SENSITIVE | CPG_ATTR_LOCAL | \
    CPG_ATTR_TYPE_MASK | CPG_ATTR_OVERRIDE | CPG_ATTR_REQUIRED)

/* These (this) can go in the sysflags field of a cpg_attr_t */
#define	LEGAL_SYSFLAGS (CPG_ATTR_NOSLEEP)


/*
 * GROW_DATAPART macro.  A macro is provided, as this is called very
 * frequently, but most of the time the test fails, so we want to
 * avoid an unnecessary procedure call.
 */

#define	GROW_DATAPART(p, requiredsize, growthhint, flags) \
	(((requiredsize) > (p)->datapart->allocsize) ? \
	grow_datapart(p, requiredsize, growthhint, flags) : \
	CPGR_OK)


/*
 * Size parameters
 */

#define	CPG_ATTR_LG2_INFO_SIZE 7
#define	CPG_ATTR_INFO_SIZE (1 <<  CPG_ATTR_LG2_INFO_SIZE)


/*
 * symbolic things
 */
#define	ALLOCATE_OK 1
#define	NO_ALLOCATE 0
#define	DEFAULT_MASK (0xf << 12)

/*
 * Performance tuning parameters
 */

#define	INITIAL_GROWING_ROOM 256
#define	SIZE_POLICY(size) ROUNDUP8(size + 256)
#define	DEFRAG_THRESHOLD 0
#define	FLUFF_ALLOWANCE (CPG_ATTR_INFO_SIZE * sizeof (cpg_attr_info_t))

static void dup_data(cpg_attr_data_t *olddata, cpg_attr_data_t *newdata,
    unsigned int size, uint32_t flags);

static int store_data(cpg_attr_t *cpg_attr_p, cpg_attr_data_t **obuf,
    unsigned int *size, uint32_t flags, int growth_hint);

static cpg_attribute_t *find_attribute(cpg_attr_data_t *data_p, int name,
    int newok);


static int add_vector_attribute(cpg_attr_t *cpg_attr_p, int name,
    uint32_t flags, void *val, unsigned int numelems);

static int add_scalar_attribute(cpg_attr_t *cpg_attr_p, int name,
    uint32_t flags, uint64_t val);

static int fluff(cpg_attr_data_t **data_pp, const cpg_attr_infobase_t *ibasep,
    uint32_t flags);

/*
 * Constants to pass to user when we need a hard zero or one.  Even
 * though they are constants, it would be difficlt to use the const
 * attriubute, so we don't.
 */
static uint64_t ZERO64 = 0ULL;
static uint64_t ONE64 = 1ULL;

static void
safefree(void *buf, unsigned int bufsize)
{
	(void) bzero(buf, bufsize);
	FREE(buf, bufsize);
}

/*
 * This supports all the functionality of realloc(3c), but works in
 * the use space or the kernel, and if flags contains
 * CPG_ATTR_SENSITIVE, it will zeroize data being returend to the
 * pool.  Also in the kernel if flags contains CPG_ATTR_NOSLEEP it
 * will provide KM_NOSLEEP to kmem_alloc.
 */
/*ARGSUSED*/
static void *
localrealloc(void *buf, unsigned oldsize, unsigned newsize, uint32_t flags)
{
	void *newbuf;
	int usemalloc;

#ifdef _KERNEL
	usemalloc = 1;
#else
	usemalloc = flags & CPG_ATTR_SENSITIVE;
#endif

	if (usemalloc) {
		/*
		 * This branch copies the old data to a new buffer,
		 * then bzeros and frees the old data.  Thus it avoids
		 * freeing sensitive data and can be used in the
		 * kernel.
		 */
		/* second arg will be evaluated only if _KERNEL is defined */
		newbuf = MALLOC(newsize, flags);
		if (newbuf == NULL) {
			return (NULL);
		}
		if (newsize > oldsize) {
			/* zeroize tail */
			(void) bzero((char *)newbuf + oldsize,
			    newsize - oldsize);
			(void) bcopy(buf, newbuf, oldsize);
		} else {
			(void) bcopy(buf, newbuf, newsize);
		}
		if (flags & CPG_ATTR_SENSITIVE) {
			safefree(buf, oldsize);
		} else {
			FREE(buf, oldsize);
		}
	}
/*
 * No realloc is available in the kernel.  So we use an ifdef to
 * stop complaints about unresolved symbols.
 */
#ifndef	_KERNEL
	else {
		newbuf = realloc(buf, newsize);
		if (newbuf && (newsize > oldsize)) {
			/* zeroize tail */
			(void) bzero((char *)newbuf + oldsize,
			    newsize - oldsize);
		}
	}
#endif
	return (newbuf);
}


static void
byteorder_to_native1(cpg_attr_data1_t *data_p)
{

	cpg_attribute_t *sap;
	cpg_offset_t entryoffs;
	cpg_offset_t nextentryoffs;

	if ((data_p->flags & CPG_ATTR_ENDIAN_MASK) == CPG_ATTR_NATIVE_ENDIAN) {
		return;
	}

	/* presently not native */

	SWAP16(data_p->version);
	SWAP32(data_p->flags);
	data_p->flags ^= CPG_ATTR_ENDIAN_MASK;
	SWAP32(data_p->size);
	SWAP32(data_p->lastattr);

	/*
	 * walk the entry list
	 */
	for (entryoffs = data_p->lastattr ? sizeof (cpg_attr_data1_t) : 0;
	    entryoffs;
	    entryoffs = nextentryoffs) {
		int i;

		sap = DEREF(cpg_attribute_t, entryoffs, data_p);

		SWAP32(sap->name);
		SWAP32(sap->flags);
		SWAP32(sap->next);

		nextentryoffs = sap->next;

		if (!(sap->flags & CPG_ATTR_ISARRAY)) {
				SWAP64(sap->data.d_uint64);
		} else {
			SWAP32(sap->data.array_descriptor.length);
			SWAP32(sap->data.array_descriptor.offset);
			switch (sap->flags & CPG_ATTR_DATASIZE_MASK) {
			case CPG_ATTR_DATASIZE16:
				for (i = 0;
				    i < sap->data.array_descriptor.length;
				    ++i) {
					SWAP16(DEREF(uint16_t,
					    sap->data.array_descriptor.offset,
					    data_p)[i]);
				}
				break;
			case CPG_ATTR_DATASIZE32:
				for (i = 0;
				    i < sap->data.array_descriptor.length;
				    ++i) {
					SWAP32(DEREF(uint32_t,
					    sap->data.array_descriptor.offset,
					    data_p)[i]);
				}
				break;
			case CPG_ATTR_DATASIZE64:
				for (i = 0;
				    i < sap->data.array_descriptor.length;
				    ++i) {
					SWAP64(DEREF(uint64_t,
					    sap->data.array_descriptor.offset,
					    data_p)[i]);
				}
				break;
			}
		}
	}
}


static void
byteorder_to_antinative1(cpg_attr_data1_t *data_p)
{

	cpg_attribute_t *sap;
	cpg_offset_t entryoffs;
	cpg_offset_t nextentryoffs = 0; /* just for safety */

	if ((data_p->flags & CPG_ATTR_ENDIAN_MASK) != CPG_ATTR_NATIVE_ENDIAN) {
		return;
	}

	/*
	 * walk the entry list; presently in native byte order
	 */

	for (entryoffs = data_p->lastattr ? sizeof (cpg_attr_data1_t) : 0;
	    entryoffs;
	    entryoffs = nextentryoffs) {
		int i;

		sap = DEREF(cpg_attribute_t, entryoffs, data_p);
		nextentryoffs = sap->next;
		if (!(sap->flags & CPG_ATTR_ISARRAY)) {
				SWAP64(sap->data.d_uint64);
		} else {
			switch (sap->flags & CPG_ATTR_DATASIZE_MASK) {
			case CPG_ATTR_DATASIZE16:
				for (i = 0;
				    i < sap->data.array_descriptor.length;
				    ++i) {
					SWAP16(DEREF(uint16_t,
					    sap->data.array_descriptor.offset,
					    data_p)[i]);
				}
				break;
			case CPG_ATTR_DATASIZE32:
				for (i = 0;
				    i < sap->data.array_descriptor.length;
				    ++i) {
					SWAP32(DEREF(uint32_t,
					    sap->data.array_descriptor.offset,
					    data_p)[i]);
				}
				break;
			case CPG_ATTR_DATASIZE64:
				for (i = 0;
				    i < sap->data.array_descriptor.length;
				    ++i) {
					SWAP64(DEREF(uint64_t,
					    sap->data.array_descriptor.offset,
					    data_p)[i]);
				}
				break;
			}
			SWAP32(sap->data.array_descriptor.length);
			SWAP32(sap->data.array_descriptor.offset);
		}
		SWAP32(sap->name);
		SWAP32(sap->flags);
		SWAP32(sap->next);
	}

	SWAP16(data_p->version);
	SWAP32(data_p->size);
	data_p->flags ^= CPG_ATTR_LITTLE_ENDIAN;
	SWAP32(data_p->flags);
	SWAP32(data_p->lastattr);

}

static void
byteorder_to_native2(cpg_attr_data_t *data_p)
{

	cpg_attribute_t *sap;
	cpg_offset_t	entryoffs;
	cpg_offset_t	nextentryoffs;
	int		hdx;

	if ((data_p->flags & CPG_ATTR_ENDIAN_MASK) == CPG_ATTR_NATIVE_ENDIAN) {
		return;
	}

	/* presently not native */

	SWAP16(data_p->version);
	SWAP16(data_p->attr_policy);
	SWAP32(data_p->flags);
	data_p->flags ^= CPG_ATTR_ENDIAN_MASK;
	SWAP32(data_p->allocsize);
	SWAP32(data_p->firstfree);
	for (hdx = 0; hdx < CPG_ATTR_NUM_LISTS; ++hdx) {
		SWAP32(data_p->listheads[hdx]);
	}

	/*
	 * walk the entry lists
	 */
	for (hdx = 0; hdx < CPG_ATTR_NUM_LISTS; ++hdx) {
		for (entryoffs = data_p->listheads[hdx];
		    entryoffs;
		    entryoffs = nextentryoffs) {

			int i;

			sap = DEREF(cpg_attribute_t, entryoffs, data_p);

			SWAP32(sap->name);
			SWAP32(sap->flags);
			SWAP32(sap->next);

			nextentryoffs = sap->next;

			if (!(sap->flags & CPG_ATTR_ISARRAY)) {
				SWAP64(sap->data.d_uint64);
			} else {
				SWAP32(sap->data.array_descriptor.length);
				SWAP32(sap->data.array_descriptor.offset);
				switch (sap->flags & CPG_ATTR_DATASIZE_MASK) {
				case CPG_ATTR_DATASIZE16:
					for (i = 0;
					    i < sap->data.array_descriptor.
						length;
					    ++i) {
						SWAP16(DEREF(uint16_t,
						    sap->data.array_descriptor.
						    offset,
						    data_p)[i]);
					}
					break;
				case CPG_ATTR_DATASIZE32:
					for (i = 0;
					    i < sap->data.array_descriptor.
						length;
					    ++i) {
						SWAP32(DEREF(uint32_t,
						    sap->data.array_descriptor.
						    offset,
						    data_p)[i]);
					}
					break;
				case CPG_ATTR_DATASIZE64:
					for (i = 0;
					    i < sap->data.array_descriptor.
						length;
					    ++i) {
						SWAP64(DEREF(uint64_t,
						    sap->data.array_descriptor.
						    offset,
						    data_p)[i]);
					}
					break;
				}
			}
		}
	}
}


static void
byteorder_to_antinative2(cpg_attr_data_t *data_p)
{

	cpg_attribute_t	*sap;
	cpg_offset_t	entryoffs;
	cpg_offset_t	nextentryoffs = 0; /* just for safety */
	int		hdx;

	if ((data_p->flags & CPG_ATTR_ENDIAN_MASK) != CPG_ATTR_NATIVE_ENDIAN) {
		return;
	}

	/*
	 * walk the entry list; presently in native byte order.
	 * Switch the list head when we are done with that list.
	 */
	for (hdx = 0; hdx < CPG_ATTR_NUM_LISTS; ++hdx) {
		for (entryoffs = data_p->listheads[hdx];
		    entryoffs;
		    entryoffs = nextentryoffs) {
			int i;

			sap = DEREF(cpg_attribute_t, entryoffs, data_p);
			nextentryoffs = sap->next;
			if (!(sap->flags & CPG_ATTR_ISARRAY)) {
				SWAP64(sap->data.d_uint64);
			} else {
				switch (sap->flags & CPG_ATTR_DATASIZE_MASK) {
				case CPG_ATTR_DATASIZE16:
					for (i = 0;
					    i < sap->data.array_descriptor.
						length;
					    ++i) {
						SWAP16(DEREF(uint16_t,
						    sap->data.array_descriptor.
						    offset,
						    data_p)[i]);
					}
					break;
				case CPG_ATTR_DATASIZE32:
					for (i = 0;
					    i < sap->data.array_descriptor.
						length;
					    ++i) {
						SWAP32(DEREF(uint32_t,
						    sap->data.array_descriptor.
						    offset,
						    data_p)[i]);
					}
					break;
				case CPG_ATTR_DATASIZE64:
					for (i = 0;
					    i < sap->data.array_descriptor.
						length;
					    ++i) {
						SWAP64(DEREF(uint64_t,
						    sap->data.array_descriptor.
						    offset,
						    data_p)[i]);
					}
					break;
				}
				SWAP32(sap->data.array_descriptor.length);
				SWAP32(sap->data.array_descriptor.offset);
			}
			SWAP32(sap->name);
			SWAP32(sap->flags);
			SWAP32(sap->next);
		}
		SWAP32(data_p->listheads[hdx]);
	}

	SWAP16(data_p->version);
	SWAP16(data_p->attr_policy);
	SWAP32(data_p->allocsize);
	data_p->flags ^= CPG_ATTR_LITTLE_ENDIAN;
	SWAP32(data_p->flags);
	SWAP32(data_p->firstfree);
}


/*
 * cpg_attr_data_size returns the consumed size (not necessarily the
 * allocated size) of an arbitrary cpg_attr_data_t, in either byte
 * order.
 */
unsigned
cpg_attr_data_size(cpg_attr_data_t *data_p)
{
	if ((data_p->flags & CPG_ATTR_ENDIAN_MASK) == CPG_ATTR_NATIVE_ENDIAN) {
		return (data_p->firstfree);
	} else {
		uint32_t size = data_p->firstfree;
		SWAP32(size);
		return (size);
	}
}

/*
 * walks the data part calculating the required size.  Has the side
 * effect of recalculating the flags word and nextentry. (The last
 * sensitive entry might have been deleted, etc.)
 */
static unsigned
required_size(cpg_attr_data_t *bp, uint32_t flags)
{
	unsigned	reqsize = sizeof (cpg_attr_data_t);
	cpg_offset_t	entryoffs;
	cpg_attribute_t	*p;
	uint32_t	newflags = CPG_ATTR_NATIVE_ENDIAN;
	int		hdx; /* hash table index */
	cpg_offset_t	nextentryoffs = 0; /* just for safety */

	for (hdx = 0; hdx < CPG_ATTR_NUM_LISTS; ++hdx) {
		for (entryoffs = bp->listheads[hdx];
		    entryoffs;
		    entryoffs = nextentryoffs) {
			p = DEREF(cpg_attribute_t, entryoffs, bp);
			nextentryoffs = p->next;

			if (p->flags & CPG_ATTR_DEFUNCT) {
				continue;
			}
			/* accumulate flags */
			newflags |= p->flags;
			/* accumulate size */
			if (!(flags & CPG_ATTR_DELETE_LOCAL &&
			    p->flags & CPG_ATTR_LOCAL)) {
				reqsize += sizeof (cpg_attribute_t);
				/*
				 * Accumulate array size, for arrays
				 * that are actually there, unless it
				 * is sensitive and the flags call for
				 * suppressing sensitive stuff.
				 */
				if (p->flags & CPG_ATTR_ISARRAY &&
				    !(flags & CPG_ATTR_SANITIZE &&
					p->flags &
					CPG_ATTR_SENSITIVE)) {
					reqsize +=
					    ROUNDUP8(ARRAY_LENGTH(p));
				}
			}
		}
	}

	bp->flags = newflags;

	return (reqsize);
}


/*
 * walks the attributes in the data part and refreshes the flags word
 * in the data part.
 */
static void
refresh_flags(cpg_attr_data_t *bp)
{
	cpg_offset_t entryoffs;
	cpg_offset_t nextentryoffs;
	cpg_attribute_t *p;
	uint32_t newflags = CPG_ATTR_NATIVE_ENDIAN;
	int		hdx = 0;

	for (hdx = 0; hdx < CPG_ATTR_NUM_LISTS; ++hdx) {
		for (entryoffs = bp->listheads[hdx];
		    entryoffs;
		    entryoffs = nextentryoffs) {
			p = DEREF(cpg_attribute_t, entryoffs, bp);
			nextentryoffs = p->next;
			if (!(p->flags & CPG_ATTR_DEFUNCT)) {
				/* accumulate flags */
				newflags |= p->flags;
			} else {
				newflags |= CPG_ATTR_DEFUNCT;
			}
		}
	}
	bp->flags = newflags;
}

/*
 * Sanity checks a data part, which must be in native endian format.
 */
static int
sanity_check_datapart1_native(cpg_attr_data1_t *data_p,
    unsigned int allocated_size)
{
	cpg_offset_t	offset;
	cpg_offset_t	lastoffset = 0;
	cpg_attribute_t	*p;
	unsigned int	declared_size;

	/* Safe to dereference header fields? */
	if (allocated_size < sizeof (cpg_attr_data_t)) {
		REPORT_ERROR(NOTE, "cpg_attr: sanity_check_datapart1_native: "
		    "allocated size (%d), impossibly small", allocated_size);
		return (CPGR_SAVED_STATE_INVALID);
	}

	declared_size = data_p->size;

	/* Will it's self-declared size fit? */
	if (allocated_size < declared_size) {
		REPORT_ERROR(NOTE, "cpg_attr: sanity_check_datapart1_native: "
		    "allocated size (%d) smaller that internal size (%d)",
		    allocated_size, declared_size);
		return (CPGR_SAVED_STATE_INVALID);
	}
	/* Will the header fit? */
	if (sizeof (cpg_attr_data_t) > declared_size) {
		REPORT_ERROR(NOTE, "cpg_attr: sanity_check_datapart1_native: "
		    "internal size (%d), impossibly small", allocated_size);
		return (CPGR_SAVED_STATE_INVALID);
	}
	/*
	 * Walk the cpg_attr checking that all pointers are within
	 * declared size.  Also update observed_size.
	 */
	offset = data_p->lastattr ? sizeof (cpg_attr_data1_t) : 0;
	while (offset) {
		uint32_t	flags;
		int		elemsize;
		int		next;

		/* check alignment */
		if (offset & 0x7) {
			REPORT_ERROR(NOTE, "cpg_attr: "
				    "sanity_check_datapart1_native: "
				    "attribute 0x%x unaligned", offset);
			return (CPGR_SAVED_STATE_INVALID);
		}
		/* 64 bit arithmetic to avoid arithmetic overflow */
		if ((uint64_t)offset +
		    sizeof (cpg_attribute_t) > declared_size) {
			REPORT_ERROR(NOTE,  "cpg_attr: "
			    "sanity_check_datapart1_native: element "
			    "attribute 0x%x extends beyond allocated space",
			    offset);
			return (CPGR_SAVED_STATE_INVALID);
		}
		p = DEREF(cpg_attribute_t, offset, data_p);
		flags = p->flags;
		elemsize = flags & CPG_ATTR_DATASIZE_MASK;
		next = p->next;

		if (elemsize & (elemsize - 1)) {
			/* elemsize not a power of 2 */
			REPORT_ERROR(NOTE, "cpg_attr: "
			    "sanity_check_datapart1_native: element "
			    "size (%d) not a power of 2",
			    elemsize);
			return (CPGR_SAVED_STATE_INVALID);
		}
		if (flags & CPG_ATTR_ISARRAY) {
			unsigned int	offset =
			    p->data.array_descriptor.offset;
			unsigned int	numelems =
			    p->data.array_descriptor.length;

			/* check array offset alignment */
			if (offset & 0x7) {
				REPORT_ERROR(NOTE, "cpg_attr: "
				    "sanity_check_datapart1_native: "
				    "unaligned array offset");
				return (CPGR_SAVED_STATE_INVALID);
			}
			/* 64-bit arithmetic to avoid arithmetic overflow */
			if ((uint64_t)offset +
			    (uint64_t)numelems * elemsize >
			    declared_size) {
				REPORT_ERROR(NOTE, "cpg_attr: "
				    "sanity_check_datapart1_native: "
				    "array overflows internal space");
				return (CPGR_SAVED_STATE_INVALID);
			}
		}
		/*
		 * The offset must increase by at least the size of a
		 * cpg_attribute.  This turns out to be very
		 * fortuitous.  This one check finds both loops and
		 * overlapping attributes.
		 */
		if (next &&
		    next < (uint64_t)offset + sizeof (cpg_attribute_t)) {
			REPORT_ERROR(NOTE, "cpg_attr: "
				    "sanity_check_datapart1_native: "
				    "non-monotonic or overlapping allocation");
			return (CPGR_SAVED_STATE_INVALID);
		}

		lastoffset = offset;
		offset = next;
	}

	if (data_p->lastattr != lastoffset) {
		REPORT_ERROR(NOTE, "cpg_attr: "
		    "sanity_check_datapart1_native: "
		    "invalid last offset field");
		return (CPGR_SAVED_STATE_INVALID);
	}


	/*
	 * Now, the data structure is known okay. Well, actually
	 * arrays could overlap anything, but it can't cause a
	 * segfault or panic.  Arrays are not updated in place.
	 */

	return (CPGR_OK);
}

/*
 * Sanity checks a data part, which must be in anti-native endian format.
 */
static int
sanity_check_datapart1_antinative(cpg_attr_data1_t *data_p,
    unsigned int allocated_size)
{
	cpg_offset_t	offset;
	cpg_offset_t	lastoffset = 0;
	cpg_attribute_t	*p;
	unsigned int	declared_size;

	/* Safe to dereference header fields? */
	if (allocated_size < sizeof (cpg_attr_data_t)) {
		REPORT_ERROR(NOTE, "cpg_attr: "
		    "sanity_check_datapart1_antinative: "
		    "allocated size (0x%x) impossibly small",
		    allocated_size);
		return (CPGR_SAVED_STATE_INVALID);
	}

	declared_size = SWAP32F(data_p->size);

	/* Will it's self-declared size fit? */
	if (allocated_size < declared_size) {
		REPORT_ERROR(NOTE, "cpg_attr: "
		    "sanity_check_datapart1_antinative: "
		    "allocated size (0x%x) smaller than internal size (0x%x)",
		    allocated_size, declared_size);

		return (CPGR_SAVED_STATE_INVALID);
	}
	/* Will the header fit? */
	if (declared_size < sizeof (cpg_attr_data_t)) {
		REPORT_ERROR(NOTE, "cpg_attr: "
		    "sanity_check_datapart1_antinative: "
		    "internal size (0x%x) impossibly small",
		    declared_size);
		return (CPGR_SAVED_STATE_INVALID);
	}

	/*
	 * Walk the cpg_attr checking that all pointers are within range.
	 */
	offset = SWAP32F(data_p->lastattr) ? sizeof (cpg_attr_data1_t) : 0;
	while (offset) {
		uint32_t	flags;
		int		elemsize;
		int		next;

		if ((uint64_t)offset +
		    sizeof (cpg_attribute_t) > declared_size) {
			REPORT_ERROR(NOTE, "cpg_attr: "
			    "sanity_check_datapart1_antinative: "
			    "attribute 0x%x extends past internal size",
			    offset);
			return (CPGR_SAVED_STATE_INVALID);
		}
		/* check alignment */
		if (offset & 0x7) {
			REPORT_ERROR(NOTE, "cpg_attr: "
			    "sanity_check_datapart1_antinative: "
			    "attribute 0x%x not aligned",
			    offset);
			return (CPGR_SAVED_STATE_INVALID);
		}
		p = DEREF(cpg_attribute_t, offset, data_p);
		flags = SWAP32F(p->flags);
		elemsize = flags & CPG_ATTR_DATASIZE_MASK;
		next = SWAP32F(p->next);

		if (elemsize & (elemsize - 1)) {
			/* elemsize not a power of 2 */
			REPORT_ERROR(NOTE, "cpg_attr: "
			    "sanity_check_datapart1_antinative: "
			    "attribute 0x%x element size not a power of 2",
			    offset);
			return (CPGR_SAVED_STATE_INVALID);
		}
		if (flags & CPG_ATTR_ISARRAY) {
			unsigned int	a_offset =
			    SWAP32F(p->data.array_descriptor.offset);
			unsigned int	numelems =
			    SWAP32F(p->data.array_descriptor.length);

			/* check array offset alignment */
			if (a_offset & 0x7) {
				REPORT_ERROR(NOTE, "cpg_attr: "
				    "sanity_check_datapart1_antinative: "
				    "attribute 0x%x element size "
				    "not a power of 2",
				    a_offset);
				return (CPGR_SAVED_STATE_INVALID);
			}
			/* 64-bit arithmetic to avoid arithmetic overflow */
			if ((uint64_t)a_offset +
			    (uint64_t)numelems * elemsize >
			    declared_size) {
				REPORT_ERROR(NOTE, "cpg_attr: "
				    "sanity_check_datapart1_antinative: "
				    "attribute 0x%x array too large",
				    offset);
				return (CPGR_SAVED_STATE_INVALID);
			}
		}
		/*
		 * The offset must increase by at least the size of a
		 * cpg_attribute.  This turns out to be very
		 * fortuitous.  This one check finds both loops and
		 * overlapping attributes.
		 */
		if (next &&
		    next < (uint64_t)offset + sizeof (cpg_attribute_t)) {
			REPORT_ERROR(NOTE, "cpg_attr: "
			    "sanity_check_datapart1_antinative: "
			    "non-monotonic or overlapping "
			    "attibutes (0x%x, 0x%x)",
			    offset, next);
			return (CPGR_SAVED_STATE_INVALID);
		}

		lastoffset = offset;
		offset = next;
	}

	if (SWAP32F(data_p->lastattr) != lastoffset) {
		REPORT_ERROR(NOTE, "cpg_attr: "
		    "sanity_check_datapart1_antinative: "
		    "non-monotonic or overlapping "
		    "invalid lastoffset");
		return (CPGR_SAVED_STATE_INVALID);
	}

	/*
	 * Now, the data structure is known okay.  Well, actually
	 * arrays could overlap anything, but it can't cause a
	 * segfault or panic.  Arrays are not updated in place.
	 */

	return (CPGR_OK);
}


/*
 * returns CPGR_CANCEL if needs rehashing.  Does not check attr info
 * stuff.
 */
static int
sanity_check_datapart2_native(cpg_attr_data_t *data_p,
    unsigned int allocated_size)
{

	cpg_offset_t	entryoffs;
	cpg_offset_t	nextentryoffs;
	cpg_attribute_t	*p;
	int		hdx;  /* hash index */
	int		h;    /* test hash index */
	int		rv = CPGR_OK;

	if (allocated_size < data_p->allocsize) {
		return (CPGR_SAVED_STATE_INVALID);
	}

	if (data_p->firstfree > data_p->allocsize) {
		return (CPGR_SAVED_STATE_INVALID);
	}

	for (hdx = 0; hdx < CPG_ATTR_NUM_LISTS; ++hdx) {
		for (entryoffs = data_p->listheads[hdx];
		    entryoffs;
		    entryoffs = nextentryoffs) {
			if (entryoffs != ROUNDUP8(entryoffs)) {
				REPORT_ERROR(NOTE, "cpg_attr: "
				    "sanity_check_datapart2_native: "
				    "misaligned datapart: dp at 0x%p, "
				    "offset 0x%x",
				    (void *)data_p, entryoffs);

				return (CPGR_SAVED_STATE_INVALID);
			}
			if (entryoffs + sizeof (cpg_attribute_t) >
			    data_p->firstfree) {
				REPORT_ERROR(NOTE, "cpg_attr: "
				    "sanity_check_datapart2_native: "
				    "datapart 0x%p: entryoffs 0x%x "
				    "extends into free zone 0x%x",
				    (void *)data_p, entryoffs,
				    data_p->firstfree);
				return (CPGR_SAVED_STATE_INVALID);
			}
			if (entryoffs < sizeof (cpg_attr_data_t)) {
				REPORT_ERROR(NOTE, "cpg_attr: "
				    "sanity_check_datapart2_native: "
				    "datapart 0x%p: entryoffs 0x%x "
				    "overlaps header",
				    (void *)data_p, entryoffs);
				return (CPGR_SAVED_STATE_INVALID);
			}
			p = DEREF(cpg_attribute_t, entryoffs, data_p);
			nextentryoffs = p->next;
			/* list only grows at end */
			if (nextentryoffs && nextentryoffs <
			    entryoffs + sizeof (cpg_attribute_t)) {
				REPORT_ERROR(CE_NOTE, "cpg_attr: "
				    "sanity_check_datapart2_native: "
				    "datapart 0x%p: entryoffs 0x%x "
				    "overlaps entryoffs 0x%x",
				    (void *)data_p, entryoffs, nextentryoffs);
				return (CPGR_SAVED_STATE_INVALID);
			}
			if (p->flags & CPG_ATTR_ISARRAY) {
				unsigned int	offset =
				    p->data.array_descriptor.offset;
				unsigned int	numelems =
				    p->data.array_descriptor.length;
				unsigned int	elemsize =
				    p->flags & CPG_ATTR_DATASIZE_MASK;

				/* check array offset alignment */
				if (offset & 0x7) {
					REPORT_ERROR(NOTE, "cpg_attr: "
					    "sanity_check_datapart2_native: "
					    "datapart 0x%p: entryoffs 0x%x "
					    "array misaligned",
					    (void *)data_p, entryoffs);
					return (CPGR_SAVED_STATE_INVALID);
				}
				/* 64-bit arithmetic to avoid arith o'flow */
				if ((uint64_t)offset +
				    (uint64_t)numelems * elemsize >
				    data_p->firstfree) {
				REPORT_ERROR(NOTE, "cpg_attr: "
				    "sanity_check_datapart2_native: "
				    "datapart 0x%p: entryoffs 0x%x "
				    "array extents into free area",
				    (void *)data_p, entryoffs);
					return (CPGR_SAVED_STATE_INVALID);
				}
			}
			ATTRHASH(h, p->name);
			if (h != hdx) {
				rv = CPGR_CANCEL;
			}

		}
	}
	return (rv);
}


/*
 * returns CPGR_CANCEL if needs rehashing.  Does not check attr info
 * stuff.
 */
static int
sanity_check_datapart2_antinative(cpg_attr_data_t *data_p,
    unsigned int allocated_size)
{

	cpg_offset_t	entryoffs;
	cpg_offset_t	nextentryoffs;
	cpg_attribute_t	*p;
	int		hdx;  /* hash index */
	int		h;    /* test hash index */
	unsigned int	firstfree;
	int		rv = CPGR_OK;

	firstfree = SWAP32F(data_p->firstfree);

	if (allocated_size < SWAP32F(data_p->allocsize)) {
		REPORT_ERROR(NOTE, "cpg_attr: "
		    "sanity_check_datapart2_antinative: "
		    "allocated size (%d) smaller that internal size (%d)",
		    allocated_size, SWAP32F(data_p->allocsize));
		return (CPGR_SAVED_STATE_INVALID);
	}
	if (firstfree > data_p->allocsize) {
		REPORT_ERROR(NOTE, "cpg_attr: "
		    "sanity_check_datapart2_antinative: "
		    "firstfree exceeds internal size");
		return (CPGR_SAVED_STATE_INVALID);
	}

	for (hdx = 0; hdx < CPG_ATTR_NUM_LISTS; ++hdx) {
		for (entryoffs = SWAP32F(data_p->listheads[hdx]);
		    entryoffs;
		    entryoffs = nextentryoffs) {
			if (entryoffs != ROUNDUP8(entryoffs)) {
				REPORT_ERROR(NOTE, "cpg_attr: "
				    "sanity_check_datapart2_antinative: "
				    "unaligned attribute (0x%x)", entryoffs);
				return (CPGR_SAVED_STATE_INVALID);
			}
			if (entryoffs + sizeof (cpg_attribute_t) > firstfree) {
				REPORT_ERROR(NOTE, "cpg_attr: "
				    "sanity_check_datapart2_antinative: "
				    "attribute (0x%x) in free area", entryoffs);
				return (CPGR_SAVED_STATE_INVALID);
			}
			if (entryoffs < sizeof (cpg_attr_data_t)) {
				REPORT_ERROR(NOTE, "cpg_attr: "
				    "sanity_check_datapart2_antinative: "
				    "attribute overlaps header");
				return (CPGR_SAVED_STATE_INVALID);
			}
			p = DEREF(cpg_attribute_t, entryoffs, data_p);
			nextentryoffs = SWAP32F(p->next);
			/* list only grows at end */
			if (nextentryoffs &&
			    nextentryoffs <
			    entryoffs + sizeof (cpg_attribute_t)) {
				REPORT_ERROR(NOTE, "cpg_attr: "
				    "sanity_check_datapart2_antinative: "
				    "non-monotonic or overlapping "
				    "attibutes (0x%x, 0x%x)",
				    entryoffs, nextentryoffs);
				return (CPGR_SAVED_STATE_INVALID);
			}
			if (SWAP32F(p->flags) & CPG_ATTR_ISARRAY) {
				unsigned int	offset =
				    SWAP32F(p->data.array_descriptor.offset);
				unsigned int	numelems =
				    SWAP32F(p->data.array_descriptor.length);
				unsigned int	elemsize =
				    SWAP32F(p->flags) & CPG_ATTR_DATASIZE_MASK;


				/* check array offset alignment */
				if (offset & 0x7) {
					REPORT_ERROR(NOTE, "cpg_attr: "
					    "sanity_check_"
					    "datapart2_antinative: "
					    "unaligned array in attribute 0x%x",
					    entryoffs);
					return (CPGR_SAVED_STATE_INVALID);
				}
				/* 64-bit arithmetic to avoid arith overflow */
				if ((uint64_t)offset +
				    (uint64_t)numelems * elemsize > firstfree) {
					REPORT_ERROR(NOTE, "cpg_attr: "
					    "sanity_check_"
					    "datapart2_antinative: "
					    "array too large in attribute 0x%x",
					    entryoffs);
					return (CPGR_SAVED_STATE_INVALID);
				}
			}
			ATTRHASH(h, SWAP32F(p->name));
			if (h != hdx) {
				rv = CPGR_CANCEL;
			}
		}
	}
	return (rv);
}


static int
sanity_check_datapart2(cpg_attr_data_t *data_p, unsigned int allocated_size)
{
	if (allocated_size < sizeof (cpg_attr_data_t)) {
		return (CPGR_SAVED_STATE_INVALID);
	}
	if ((data_p->flags & CPG_ATTR_ENDIAN_MASK) != CPG_ATTR_NATIVE_ENDIAN) {
		return (sanity_check_datapart2_antinative(data_p,
		    allocated_size));
	} else {
		return (sanity_check_datapart2_native(data_p, allocated_size));
	}
}





/*
 * Checks a datapart for validity.  Works on both little endian and
 * big endian data.  Returns CPGR_SAVED_STATE_INVALID or CPGR_OK.
 */
static int
cpg_attr_sanity_check_datapart1(cpg_attr_data1_t *data_p, int allocated_size)
{
	if (allocated_size < sizeof (cpg_attr_data_t)) {
		return (CPGR_SAVED_STATE_INVALID);
	}
	if ((data_p->flags & CPG_ATTR_ENDIAN_MASK) != CPG_ATTR_NATIVE_ENDIAN) {
		return (sanity_check_datapart1_antinative(data_p,
		    allocated_size));
	} else {
		return (sanity_check_datapart1_native(data_p, allocated_size));
	}
}

static int
cpg_attr_sanity_check_datapart2(cpg_attr_data_t *data_p, int allocated_size)
{
	if (allocated_size < sizeof (cpg_attr_data_t)) {
		return (CPGR_SAVED_STATE_INVALID);
	}
	if ((data_p->flags & CPG_ATTR_ENDIAN_MASK) != CPG_ATTR_NATIVE_ENDIAN) {
		return (sanity_check_datapart2_antinative(data_p,
		    allocated_size));
	} else {
		return (sanity_check_datapart2_native(data_p, allocated_size));
	}
}



int
cpg_attr_attach_data1(cpg_attr_t *restrict cpg_attr_p,
    cpg_attr_data1_t *restrict data_p, unsigned allocated_size,
    const cpg_attr_infobase_t *attrinfobase_p,
    uint32_t flags)
{
	int		rv;
	cpg_offset_t	entryoffs;
	cpg_offset_t	nextentryoffs;

	rv = cpg_attr_sanity_check_datapart1(data_p, allocated_size);
	if (rv) {
		return (rv);
	}

	byteorder_to_native1(data_p);
	/* We could do better guessing the size, but this is easy */
	rv = cpg_attr_init(cpg_attr_p, attrinfobase_p, 0,
	    allocated_size - sizeof (cpg_attr_data1_t), flags);
	if (rv) {
		return (rv);
	}

	for (entryoffs = data_p->lastattr ? sizeof (cpg_attr_data1_t) : 0;
	    entryoffs;
	    entryoffs = nextentryoffs) {

		cpg_attribute_t	*p;

		p = DEREF(cpg_attribute_t, entryoffs, data_p);
		nextentryoffs = p->next;
		if (p->flags & CPG_ATTR_DEFUNCT) {
			continue;
		}

		if (p->flags & CPG_ATTR_ISARRAY) {
			rv = add_vector_attribute(cpg_attr_p, p->name,
			    (flags & LEGAL_SYSFLAGS) |
			    (p->flags &
			    (CPG_ATTR_TYPE_MASK | CPG_ATTR_SENSITIVE)),
			    DEREF_N(void, p->data.array_descriptor.offset,
				data_p),
			    p->data.array_descriptor.length);
		} else {
			rv = add_scalar_attribute(cpg_attr_p, p->name,
			    (flags & LEGAL_SYSFLAGS) |
			    (p->flags &
			    (CPG_ATTR_TYPE_MASK | CPG_ATTR_SENSITIVE)),
			    p->data.d_uint64);
		}
		if (rv) {
			cpg_attr_p->datapart = NULL;
			return (rv);
		}
		entryoffs = p->next;
	}

	if (data_p->flags & CPG_ATTR_SENSITIVE) {
		safefree(data_p, allocated_size);
	} else {
		FREE(data_p, allocated_size);
	}

	return (CPGR_OK);
}

int
cpg_attr_attach_data(cpg_attr_t *restrict cpg_attr_p,
    cpg_attr_data_t *restrict data_p, unsigned allocated_size,
    cpg_attr_infobase_t const *attrinfop, uint32_t flags)
{
	int		rv;

	if (allocated_size < sizeof (cpg_attr_data_t)) {
		return (CPGR_SAVED_STATE_INVALID);
	}

	switch (((data_p->flags & CPG_ATTR_ENDIAN_MASK) ==
	    CPG_ATTR_NATIVE_ENDIAN) ? data_p->version :
	    SWAP16F(data_p->version)) {
	case 1:
		return (cpg_attr_attach_data1(cpg_attr_p,
		    (cpg_attr_data1_t *)data_p,
		    allocated_size, attrinfop, flags));
	case CPG_ATTR_VERSION:
		/* normal case: current version */
		break;
	default:
		return (CPGR_SAVED_STATE_INVALID);
	}

	if (flags & CPG_ATTR_USE_EXTRA_CARE) {
		rv = cpg_attr_sanity_check_datapart2(data_p, allocated_size);
		switch (rv) {
		case CPGR_OK:
		case CPGR_CANCEL:
			break;
		default:
			return (rv);
		}

	} else {
		/*
		 * Just check that the allocated size is at least as
		 * large as the used region.
		 */
		if (allocated_size < (((data_p->flags & CPG_ATTR_ENDIAN_MASK) ==
		    CPG_ATTR_NATIVE_ENDIAN) ? data_p->firstfree :
		    SWAP32F(data_p->firstfree))) {
			return (CPGR_SAVED_STATE_INVALID);
		}
	}

	byteorder_to_native2(data_p);

	data_p->allocsize = allocated_size;
	/* Check that policy number is valid */
	if (data_p->attr_policy >= attrinfop->num_entries) {
		return (CPGR_SAVED_STATE_INVALID);
	}
	cpg_attr_p->sysflags = flags & LEGAL_SYSFLAGS;
	cpg_attr_p->datapart = data_p;
	cpg_attr_p->attrinfobase = attrinfop;
	/* set up cache */
	cpg_attr_p->thisattrinfo = attrinfop->info[data_p->attr_policy];
	cpg_attr_p->discarded_bytes = 0;  /* not necessarily right */
	if (flags &
	    (CPG_ATTR_USE_EXTRA_CARE |
		CPG_ATTR_DELETE_LOCAL |
		CPG_ATTR_SANITIZE |
		CPG_ATTR_FLUFF)) {
		/*
		 * Call cpg_attr_filter if CPG_ATTR_DELETE_LOCAL or
		 * CPG_ATTR_SANIIZE or CPG_ATTR_FLUFF are supplied.
		 *
		 * Also call cpg_attr_filter if the
		 * CPG_ATTR_USE_EXTRA_CARE flag is supplied, since
		 * cpg_attr_filter will call dup_data, which will
		 * rehash all the entries.
		 */
		return (cpg_attr_filter(cpg_attr_p, flags));
	} else {
		return (CPGR_OK);
	}
}

int
cpg_attr_alloc_attach_data(cpg_attr_t **restrict cpg_attr_p,
    cpg_attr_data_t *restrict data_p, unsigned allocated_size,
    cpg_attr_infobase_t const *attrinfop, uint32_t flags)
{
	int		rv;
	cpg_attr_t	*p;

	p = MALLOC(sizeof (cpg_attr_t), flags);
	if (p == NULL) {
		*cpg_attr_p = NULL;
		return (CPGR_HOST_MEMORY);
	}

	rv = cpg_attr_attach_data(p, data_p, allocated_size,
	    attrinfop, flags);

	if (rv != CPGR_OK) {
		FREE(p, sizeof (cpg_attr_t));
		*cpg_attr_p = NULL;
		return (rv);
	}
	*cpg_attr_p = p;
	return (CPGR_OK);
}

/*
 * initializes *cpg_attr_p
 */
int
cpg_attr_init(cpg_attr_t *restrict cpg_attr_p,
    const cpg_attr_infobase_t *attrbasep, int attrpolicy,
    unsigned int growthhint, uint32_t flags)
{
	int		rv;
	cpg_attr_data_t *data_p;
	unsigned int	datapartsize = sizeof (cpg_attr_data_t) +
	    INITIAL_GROWING_ROOM + ROUNDUP8(growthhint);

	if (attrpolicy >= attrbasep->num_entries) {
		cpg_attr_p->datapart = NULL;
		REPORT_ERROR(CE_NOTE, "cpg_attr: cpg_attr_init: "
		    "attrpolicy is %d, "
		    "which is invalid", attrpolicy);
		return (CPGR_GENERAL_ERROR);
	}

	data_p = (cpg_attr_data_t *)ZMALLOC(datapartsize, flags);
	if (data_p == NULL) {
		cpg_attr_p->datapart = NULL;
		return (CPGR_HOST_MEMORY);
	}
	data_p->version = CPG_ATTR_VERSION;
	data_p->attr_policy = attrpolicy;
	data_p->flags = CPG_ATTR_NATIVE_ENDIAN;
	data_p->allocsize = datapartsize;
	data_p->firstfree = ROUNDUP8(sizeof (cpg_attr_data_t));
	rv = cpg_attr_attach_data(cpg_attr_p, data_p, datapartsize, attrbasep,
	    flags);
	if (rv) {
		cpg_attr_p->datapart = NULL;
		FREE(data_p, datapartsize);
		return (rv);
	}

	return (CPGR_OK);
}

int
cpg_attr_alloc_init(cpg_attr_t **restrict cpg_attr_p,
    const cpg_attr_infobase_t *attrbasep, int attrpolicy,
    unsigned int growthhint, uint32_t flags)
{
	int		rv;
	cpg_attr_t	*p;

	p = MALLOC(sizeof (cpg_attr_t), flags);
	if (p == NULL) {
		*cpg_attr_p = NULL;
		return (CPGR_HOST_MEMORY);
	}
	rv = cpg_attr_init(p, attrbasep, attrpolicy, growthhint, flags);
	if (rv != CPGR_OK) {
		FREE(p, sizeof (cpg_attr_t));
		*cpg_attr_p = NULL;
		return (rv);
	}
	*cpg_attr_p = p;
	return (CPGR_OK);
}

void
cpg_attr_destroy(cpg_attr_t *cpg_attr_p)
{
	if (cpg_attr_p->datapart->flags & CPG_ATTR_SENSITIVE) {
		safefree(cpg_attr_p->datapart, cpg_attr_p->datapart->allocsize);
	} else {
		FREE(cpg_attr_p->datapart, cpg_attr_p->datapart->allocsize);
	}
}

void
cpg_attr_free(cpg_attr_t *cpg_attr_p)
{
	cpg_attr_destroy(cpg_attr_p);
	FREE(cpg_attr_p, sizeof (cpg_attr_t));
}

/*
 * Golden ratio * 2^31 = ((sqrt(5) - 1)/2 * 2*31 = .618... *
 * 2^31. Think of this as a fixed point representation of the golden
 * ratio with the binary point just right of the sign bit. (Note, some
 * authorities define the golden ratio as (sqrt(5) + 1)/2 = 1.618...)
 * We could actually put the binary point clear at the left if we used
 * unsigned arithmetic.  But we need to also do this in perl, which
 * does not easily support unsigned integers.
 */
#define	GR31 0x4F1BBCDD

static int
lookup_attr_info(const cpg_attr_info_t *attrinfo,
    unsigned int k, uint32_t *flags)
{
	int hashval;

	if (attrinfo == NULL) {
		return (CPGR_ATTRIBUTE_TYPE_INVALID);
	}

	hashval = ((GR31 * k) >> (31 - CPG_ATTR_LG2_INFO_SIZE)) &
	    (CPG_ATTR_INFO_SIZE - 1);

	/*CONSTCOND*/
	while (1) {
		if (attrinfo[hashval].flags == ~0) {
			return (CPGR_ATTRIBUTE_TYPE_INVALID);
		}
		if (attrinfo[hashval].name == k) {
			*flags = attrinfo[hashval].flags;
			return (CPGR_OK);
		} else {
			hashval = (hashval + 1) & (CPG_ATTR_INFO_SIZE - 1);
		}
	}
	/* lint complains about falling off bottom with no return */
	/*LINTED*/
}


/*
 * Returns attr info for a particular attribute based on the
 * attrinfobase and the specified policy.  Returns
 * CPGR_ATTRIBUTE_TYPE_INVALID if the attribute is not listed.  The
 * request will succeed and returned flags will be zero if the entry
 * in the attr infobase is a NULL pointer.  (This will normally be the
 * case if attrpolicy is zero.)  The zero should be interpreted to
 * mean that nothing is known about the attribute, and everything is
 * allowed.
 */
int
cpg_attr_info_query(const cpg_attr_infobase_t *defaultattrinfo_p,
    int attrpolicy, uint32_t name, uint32_t *infop)
{
	if (attrpolicy < 0 || attrpolicy >= defaultattrinfo_p->num_entries) {
		return (CPGR_ARGUMENTS_BAD);
	}
	if (defaultattrinfo_p->info[attrpolicy] == NULL) {
		*infop = 0;
		return (CPGR_OK);
	}
	return (lookup_attr_info(defaultattrinfo_p->info[attrpolicy],
	    name, infop));

}

/*
 * Copies the old data to the new data.  The newdata block must be
 * already allocated and large enough. No check is done. (The size
 * parameter is only used to set the allocsize field.)  The flags word
 * may contain CPG_ATTR_DELETE_LOCAL, which causes it to skip entries
 * with the CPG_ATTR_LOCAL flag set.  The flags word may contain
 * CPG_ATTR_SANITIZE, which causes data with the CPG_ATTR_SENSITIVE
 * bit set to be copied, but with the data suppressed.  As a side
 * effect, the flags word in the olddata is recomputed.
 */
static void
dup_data(cpg_attr_data_t *olddata, cpg_attr_data_t *newdata, unsigned int size,
    uint32_t flags)
{
	cpg_attribute_t *sap; /* source attribute pointer */
	cpg_attribute_t *dap; /* destination attribute pointer */
	cpg_offset_t	entryoffs;
	/* we recompute flags in the old data, as a courtesy */
	uint32_t	oldflags = CPG_ATTR_NATIVE_ENDIAN;
	int		hdi;

	newdata->version = CPG_ATTR_VERSION;
	newdata->attr_policy = olddata->attr_policy;
	newdata->firstfree = ROUNDUP8(sizeof (cpg_attr_data_t));
	newdata->allocsize = size;
	newdata->flags = CPG_ATTR_NATIVE_ENDIAN;  /* depends on environment */
	bzero(newdata->listheads, sizeof (newdata->listheads));

	for (hdi = 0; hdi < CPG_ATTR_NUM_LISTS; ++hdi) {
		for (entryoffs = olddata->listheads[hdi];
		    entryoffs;
		    entryoffs = DEREF(cpg_attribute_t, entryoffs, olddata)->
			next) {
			sap = DEREF(cpg_attribute_t, entryoffs, olddata);

			if (flags & CPG_ATTR_DEFUNCT) {
				continue;
			}

			oldflags |= sap->flags;

			if (flags & CPG_ATTR_DELETE_LOCAL &&
			    sap->flags & CPG_ATTR_LOCAL) {
				continue;
			}
			/*
			 * Allocate takes care of name, next, and pad.
			 * The flags field is set to CPA_ATTR_DEFUNCT,
			 * be we will overwrite that.
			 */
			dap = find_attribute(newdata, sap->name, ALLOCATE_OK);
			/*
			 * Delete this debugging code when this has
			 * been thoroughly tested.  The precondtions
			 * guarantee that find_attribute always
			 * succeeds.
			 */
			if (dap == NULL) {
				REPORT_ERROR(NOTE, "cpg_attr: dup_data: "
				    "find_attribute failed to allocate");
				goto bailout;
			}

			/* sanitize, array, or scalar? */
			if (flags & CPG_ATTR_SANITIZE &&
			    sap->flags & CPG_ATTR_SENSITIVE) {
				/* sanitize */
				dap->flags = sap->flags | CPG_ATTR_SANITIZE;
				dap->data.d_uint64 = 0LL;
			} else if (sap->flags & CPG_ATTR_ISARRAY) {
				/* process array */
				int ru_size = ROUNDUP8(ARRAY_LENGTH(sap));
				/* set flags; allocate array */
				dap->flags = sap->flags;
				dap->data.array_descriptor.offset =
				    newdata->firstfree;
				dap->data.array_descriptor.length =
				    sap->data.array_descriptor.length;
				newdata->firstfree += ru_size;
				/* copy array, including tail region */
				bcopy(ARRAY_ADDR(olddata, sap),
				    ARRAY_ADDR(newdata, dap), ru_size);
			} else {
				/* scalar */
				dap->flags = sap->flags;
				dap->data.d_uint64 = sap->data.d_uint64;
			}
			/* accumulate flags */
			newdata->flags |= dap->flags;
		}
	}
bailout:
	olddata->flags = oldflags;
}


/*
 * Duplicate a cpg_attr_list.  growthhint suggests extra size to add
 * to the datapart of the new cpg_attr_list. The following flags are
 * recognized: CPG_ATTR_SANITIZE, CPG_ATTR_DELETE_LOCAL, and
 * CPG_ATTR_NOSLEEP.  XXX in the present implementation growthhint is
 * not used.  I think it is easy to fix by just reallocing newdata with a
 * bigger buffer, and adjusting newdatasize.  Later...
 */
/*ARGSUSED*/
int
cpg_attr_dup(cpg_attr_t *cpg_attr_p, cpg_attr_t *newcpg_attr_p,
    unsigned int growthhint, uint32_t flags)
{
	int			rv;
	unsigned		newdatasize;
	cpg_attr_data_t		*newdata;

	rv = cpg_attr_store_data(cpg_attr_p, &newdata, &newdatasize, flags);
	if (rv) {
		return (rv);
	}

	/*
	 * Sanitizing, deleting local attributes, fluffing, and
	 * attribute-by-attribute copying all happened above; no need
	 * to do it twice.
	 */
	rv = cpg_attr_attach_data(newcpg_attr_p, newdata, newdatasize,
	    cpg_attr_p->attrinfobase, flags &
	    ~(CPG_ATTR_SANITIZE | CPG_ATTR_DELETE_LOCAL | CPG_ATTR_FLUFF |
		    CPG_ATTR_USE_EXTRA_CARE));
	if (rv) {
		/* error branch; go for simplest code, i.e. call safefree */
		safefree(newdata, newdatasize);
		cpg_attr_p->datapart = NULL;
	}
	return (rv);
}


int
cpg_attr_alloc_dup(cpg_attr_t *cpg_attr_p, cpg_attr_t **newcpg_attr_p,
    unsigned int growthhint, uint32_t flags)
{
	int		rv;
	cpg_attr_t	*p;

	p = MALLOC(sizeof (cpg_attr_t), flags);
	if (p == NULL) {
		*newcpg_attr_p = NULL;
		return (CPGR_HOST_MEMORY);
	}

	rv = cpg_attr_dup(cpg_attr_p, p, growthhint, flags);
	if (rv != CPGR_OK) {
		FREE(p, sizeof (cpg_attr_t));
		*newcpg_attr_p = NULL;
		return (rv);
	}

	*newcpg_attr_p = p;
	return (rv);
}



/*
 * The following flags are recognized: CPG_ATTR_SANITIZE,
 * CPG_ATTR_DELETE_LOCAL, CPG_ATTR_NOSLEEP, CPG_ATTR_NO_GROWING_ROOM,
 * CPG_ATTR_USE_EXTRA_CARE.  The CPG_ATTR_USE_EXTRA_CARE flag causes
 * the size to be computed from scratch and forces a full copy, which
 * will rehash all the entires.  This flag is intended for use in an
 * internal call from cpg_attr_attach_data.  In the present
 * implemenation a new data part is always created.
 */
int
cpg_attr_filter(cpg_attr_t *cpg_attr_p, uint32_t flags)
{
	unsigned	newdata_allocated_size;
	cpg_attr_data_t	*newdata;
	int		rv;

	if (flags & CPG_ATTR_USE_EXTRA_CARE) {
		newdata_allocated_size = required_size(cpg_attr_p->datapart,
		    flags);
	} else {
		newdata_allocated_size =  cpg_attr_p->datapart->firstfree;
	}

	if (!(flags & CPG_ATTR_NO_GROWING_ROOM)) {
		newdata_allocated_size = SIZE_POLICY(newdata_allocated_size);
	}

	newdata = (cpg_attr_data_t *)ZMALLOC(newdata_allocated_size,
	    flags | cpg_attr_p->sysflags);
	if (newdata == NULL) {
		return (CPGR_HOST_MEMORY);
	}

	dup_data(cpg_attr_p->datapart, newdata, newdata_allocated_size, flags);

	if (cpg_attr_p->datapart->flags & CPG_ATTR_SENSITIVE) {
		/* datapart may have sensitive data */
		safefree(cpg_attr_p->datapart, cpg_attr_p->datapart->allocsize);
	} else {
		FREE(cpg_attr_p->datapart, cpg_attr_p->datapart->allocsize);
	}

	if (flags & CPG_ATTR_FLUFF) {
		rv = fluff(&newdata, cpg_attr_p->attrinfobase,
		    flags | (cpg_attr_p->sysflags & LEGAL_SYSFLAGS));
		if (rv) {
			return (rv);
		}
	}

	cpg_attr_p->datapart = newdata;

	return (CPGR_OK);
}


/*
 * Makes a detached copy of the cpg_attr_list's data part (the
 * cpg_attr_data_t plus) in a new buffer and stores the address in
 * *obuf.  The amount of buffer space used is stored in *size.  Under
 * control of various flags, the output buffer can be written in
 * either little endian or big endian format, and various fields can
 * be suppressed.  It is the user's responsiblity to manage the output
 * buffer.  Recognized flags are CPG_ATTR_NOSLEEP,
 * CPG_ATTR_NO_GROWING_ROOM, CPG_ATTR_SANITIZE, CPG_ATTR_DELETE_LOCAL,
 * CPG_ATTR_FLUFF, CPG_ATTR_LITTLE_ENDIAN, CPG_ATTR_BIG_ENDIAN (the
 * default byte order), and CPG_ATTR_NATIVE_ENDIAN.
 */
int
cpg_attr_store_data(cpg_attr_t *cpg_attr_p, cpg_attr_data_t **obuf,
    unsigned int *size, uint32_t flags)
{
	return (store_data(cpg_attr_p, obuf, size, flags, 0));
}

/* at one time, there were calls to this other than the above */
static int
store_data(cpg_attr_t *cpg_attr_p, cpg_attr_data_t **obuf, unsigned int *size,
    uint32_t flags, int growth_hint)
{
	cpg_attr_data_t		*data_p = cpg_attr_p->datapart; /* mutable */
	cpg_attr_data_t		*orig_data_p = data_p;
	cpg_attr_data_t		*newbuf;
	int			rv;
	int			will_dup =
	    (flags & CPG_ATTR_NO_GROWING_ROOM &&
	    cpg_attr_p->discarded_bytes > DEFRAG_THRESHOLD) ||
	    (flags & (CPG_ATTR_SANITIZE | CPG_ATTR_DELETE_LOCAL));

	/*
	 * Must bcopy if fluffing or we will not be duping later.
	 * (store_data must make a copy sometime, and we always need a
	 * copy if we are fluffing.)  Of this block and the third
	 * block below, at least one will be executed.
	 */
	if (flags & CPG_ATTR_FLUFF || !will_dup) {
		unsigned	newsize;

		/* pick size */
		if (flags & CPG_ATTR_FLUFF) {
			newsize = cpg_attr_p->datapart->firstfree +
			    FLUFF_ALLOWANCE + growth_hint;
		} else if (flags & CPG_ATTR_NO_GROWING_ROOM) {
			newsize =  cpg_attr_p->datapart->firstfree;
		} else {
			newsize = SIZE_POLICY(cpg_attr_p->datapart->firstfree +
			    growth_hint);
		}
		/* now allocate */
		newbuf = (cpg_attr_data_t *)MALLOC(newsize,
		    flags | cpg_attr_p->sysflags);
		if (newbuf == NULL) {
			return (CPGR_HOST_MEMORY);
		}
		bzero((char *)newbuf + data_p->firstfree,
		    newsize - data_p->firstfree);
		bcopy(data_p, newbuf, data_p->firstfree);
		data_p = newbuf;
		data_p->allocsize = newsize;
	}

	/*
	 * Fluff if requested
	 */
	if (flags & CPG_ATTR_FLUFF) {
		/*
		 * Probably changes data_p.  Clipping off extra room
		 * is expensive; only do it if we aren't going to dup
		 * next.  fluff may increase the size.  If that
		 * happens data_p->allocsize will be adjusted
		 * automatically.
		 */
		rv = fluff(&data_p, cpg_attr_p->attrinfobase,
		    (will_dup ? flags & ~CPG_ATTR_NO_GROWING_ROOM : flags)
		    | (cpg_attr_p->sysflags & LEGAL_SYSFLAGS));
		if (rv) {
			return (rv);
		}
	}

	/*
	 * dup if necessary, ie must shrink or filter.
	 */
	if (will_dup) {
		unsigned	newsize;
		newsize = required_size(data_p, flags);
		newbuf = (cpg_attr_data_t *)MALLOC(newsize,
		    flags | cpg_attr_p->sysflags);
		if (newbuf == NULL) {
			/* this is an error branch; go for simplest code */
			if (data_p != orig_data_p) {
				safefree(data_p, data_p->allocsize);
			}
			return (CPGR_HOST_MEMORY);
		}
		/*
		 * copy it over, sanitizing, etc., as we go.  dup_data
		 * sets the allocsize field in newbuf from the newsize
		 * parameter.
		 */
		dup_data(data_p, newbuf, newsize,
		    flags & ~CPG_ATTR_ENDIAN_MASK);
		/* delete data_p if it is an intermediate buffer */
		if (data_p != orig_data_p) {
			if (data_p->flags & CPG_ATTR_SENSITIVE) {
				safefree(data_p, data_p->allocsize);
			} else {
				FREE(data_p, data_p->allocsize);
			}
		}
		data_p = newbuf;
	};

	if (size) {
		*size = data_p->allocsize;
	}

	/* convert to proper endian format */
	if ((flags & CPG_ATTR_ENDIAN_MASK) != CPG_ATTR_NATIVE_ENDIAN) {
		byteorder_to_antinative2(data_p);
	}

	/* set out parameters and return */
	*obuf = data_p;
	return (CPGR_OK);
}

/*
 * Returns address and length of live data.
 */
void
cpg_attr_ref_data(cpg_attr_t *restrict cpg_attr_p, cpg_attr_data_t **obuf,
    unsigned *size)
{
	if (obuf) {
		*obuf = cpg_attr_p->datapart;
	}
	if (size) {
		*size = cpg_attr_p->datapart->allocsize;
	}
}


/*
 * The cpg_attr walk group.  These functions support walking through
 * the attributes.
 */


#define	TAKE_A_STEP(statep) \
	if (statep->currentp == NULL) { \
		/* advance bucket, go to first */ \
		++statep->hashbucket; \
		statep->currentp = DEREF_N(cpg_attribute_t, \
		    statep->datapart_p->listheads[statep->hashbucket], \
		    statep->datapart_p); \
	} else { \
		/* go to the next one */ \
		statep->currentp = DEREF_N(cpg_attribute_t, \
		    statep->currentp->next, \
		    statep->datapart_p); \
	}


void
cpg_attr_walk_init(cpg_attr_walk_state_t *state, cpg_attr_t *p)
{
	state->datapart_p = p->datapart;
	/* set to first possible entry */
	state->hashbucket = 0;
	state->currentp =  DEREF_N(cpg_attribute_t,
	    state->datapart_p->listheads[state->hashbucket],
	    state->datapart_p);
	/* advance */
	while (state->hashbucket < CPG_ATTR_NUM_LISTS &&
	    (state->currentp == NULL ||
		state->currentp->flags & CPG_ATTR_DEFUNCT)) {
		TAKE_A_STEP(state);
	}
}

/*
 * Return non-zero if more data is avaiable.
 */
int
cpg_attr_walk_more_q(cpg_attr_walk_state_t *state)
{
	return (state->hashbucket < CPG_ATTR_NUM_LISTS);
}

/*
 * Advance to next entry
 */
void
cpg_attr_walk_next(cpg_attr_walk_state_t *state)
{
	TAKE_A_STEP(state);
	while (state->hashbucket < CPG_ATTR_NUM_LISTS &&
	    (state->currentp == NULL ||
		state->currentp->flags & CPG_ATTR_DEFUNCT)) {
		TAKE_A_STEP(state);
	}
}

/*
 * Gets name and flags.
 */
void
cpg_attr_walk_get_info(cpg_attr_walk_state_t *state, uint32_t *name,
    uint32_t *flags) {

	if (state->currentp) {
		*name = state->currentp->name;
		*flags = state->currentp->flags;
	} else {
		*name = 0;
		*flags = 0;
	}
}

/*
 * Gets pointer to attribute (internal only)
 */
static cpg_attribute_t *
walk_get_addr(cpg_attr_walk_state_t *state)
{
	return (state->currentp);
}



/*
 * Finds entry of specified name.  If newok is false, null is returned
 * if the entry cannot be found.  If newok is true, an existing
 * defunct entry will be found if one exists, or a new one will be
 * allocated, if there is sufficient space.  In this case the new
 * element will have its name field set to name, and the flags field
 * will be set to defunct.  Finally, if there is
 * insufficient space, null will be returned.
 */
static cpg_attribute_t *
find_attribute(cpg_attr_data_t *data_p, int name, int newok)
{
	cpg_offset_t		entryoffs;
	cpg_attribute_t		*bap = NULL;
	cpg_attribute_t		*defunctp = NULL;
	uint32_t		h;
	cpg_offset_t		nextentryoffs = 0;

	ATTRHASH(h, name);

	for (entryoffs = data_p->listheads[h];
	    entryoffs;
	    entryoffs = nextentryoffs) {
		bap = DEREF(cpg_attribute_t, entryoffs, data_p);
		nextentryoffs = bap->next;
		if (bap->flags & CPG_ATTR_DEFUNCT) {
			defunctp = bap;
		} else {
			if (bap->name == name) {
				return (bap);
			}
		}
	}
	/*
	 * Note, bap is still pointing to last entry in list or is
	 * null (list is empty), if we get here.
	 */
	if (!newok) {
		return (NULL);
	}

	if (defunctp) {
		defunctp->name = name;
		defunctp->flags = CPG_ATTR_DEFUNCT;
		bap->data.d_uint64 = 0ULL;
		return (defunctp);
	}

	/*
	 * Try to allocate one. bap points to last entry in chain, or
	 * is null if chain is empty.
	 */
	if (data_p->firstfree + sizeof (cpg_attribute_t) <= data_p->allocsize) {
		entryoffs = data_p->firstfree;
		if (bap == NULL) {
			data_p->listheads[h] = entryoffs;
		} else {
			bap->next = entryoffs;
		}
		data_p->firstfree = entryoffs +
		    ROUNDUP8(sizeof (cpg_attribute_t));
		/* set bap to point to new entry */
		bap = DEREF(cpg_attribute_t, entryoffs, data_p);
		/* fill in data */
		bap->name = name;
		bap->flags = CPG_ATTR_DEFUNCT;
		bap->data.d_uint64 = 0ULL;
		bap->next = 0;  /* end of list */
		bap->pad = PADVAL(entryoffs);
		return (bap);
	}
	return (NULL);
}

/*
 * Increases the size of the data part by calling localrealloc on
 * it. If it actually grows, the size will be increased by
 * growthhint.
 */
static int
grow_datapart(cpg_attr_t *cpg_attr_p, unsigned requiredsize,
    unsigned growthhint, uint32_t flags)
{
	cpg_attr_data_t *newdata;

	requiredsize = ROUNDUP8(requiredsize);

	if (requiredsize > cpg_attr_p->datapart->allocsize) {
		uint32_t flagsunion =
		    /* things like CPG_ATTR_SENSITIVE */
		    cpg_attr_p->datapart->flags |
		    /* CPG_ATTR_NOSLEEP as remembered from ...alloc, etc. */
		    cpg_attr_p->sysflags |
		    /* CPG_ATTR_NOSLEEP passed in at time of call */
		    flags;
		/* SIZE_POLICY already has ROUNDUP8 in it */
		requiredsize = SIZE_POLICY(requiredsize + growthhint);

		newdata = localrealloc(cpg_attr_p->datapart,
		    cpg_attr_p->datapart->allocsize, requiredsize, flagsunion);

		if (newdata == NULL) {
			return (CPGR_HOST_MEMORY);
		} else {
			newdata->allocsize = requiredsize;
			/* flip to new cpg_attr */
			cpg_attr_p->datapart = newdata;
		}
	}

	return (CPGR_OK);
}

static void
discard_array(cpg_attr_t *cpg_attr_p, cpg_attribute_t *atp)
{
	/*
	 * The ROUNDUP8 causes complete long longs to be zeroized.
	 * This prevents partial zeroing of offsets in malformed
	 * dataparts.
	 */
	if (atp->flags & CPG_ATTR_SENSITIVE) {
		(void) bzero(ARRAY_ADDR(cpg_attr_p->datapart, atp),
		    ROUNDUP8(ARRAY_LENGTH(atp)));
	}
	cpg_attr_p->discarded_bytes += ROUNDUP8(ARRAY_LENGTH(atp));
	atp->data.d_uint64 = 0LL;
	atp->flags &= ~(CPG_ATTR_SENSITIVE | CPG_ATTR_ISARRAY);
}

/*
 * Allocates a new array.  Reallocates the whole data part if needed.
 * atp points to the entry pointer, and will be adjusted if the blob
 * is reallocated.  Flags must be clean, i.e. only contain stuff that
 * should go in attributes.  Sets the size of the array in the
 * attribute, but leaves the data unset.
 */
static int
allocate_array(cpg_attr_t *cpg_attr_p, cpg_attribute_t **atp,
    unsigned int length, uint32_t flags)
{
	int		rv;
	ptrdiff_t	atpoffset = (char *)*atp -
	    (char *)cpg_attr_p->datapart;
	unsigned int	ru_arraysize =
	    ROUNDUP8(length * (flags & CPG_ATTR_DATASIZE_MASK));


	rv = GROW_DATAPART(cpg_attr_p,
	    cpg_attr_p->datapart->firstfree + ru_arraysize,
	    0 /* growth hint */, flags);
	if (rv) {
		return (rv);
	}

	/*
	 * Update *atp (entry pointer).  If grow_datapart does not
	 * allocate a new buffer (and thus change
	 * cpg_attr_p->datapart), *atp will be unchanged.
	 */
	*atp = (cpg_attribute_t *)((char *)cpg_attr_p->datapart + atpoffset);

	/* set header data structures */
	(*atp)->data.array_descriptor.length = length;
	(*atp)->data.array_descriptor.offset = cpg_attr_p->datapart->firstfree;
	cpg_attr_p->datapart->firstfree += ru_arraysize;
	/*
	 * Set the flags word in the attribute to supply only flags
	 * that are appropriate for attributes, specifically not
	 * CPG_ATTR_NOSLEEP.  Also OR in CPG_ATTR_ISARRAY, since this
	 * is an array.
	 */
	(*atp)->flags = (flags & LEGAL_ATTR_FLAGS) | CPG_ATTR_ISARRAY;
	cpg_attr_p->datapart->flags |= flags | CPG_ATTR_ISARRAY;

	return (CPGR_OK);
}

/*
 * add_attribute adds an attribute.  Any array previously associated
 * with the attribute is discarded.  The growthhint attribute adds
 * some extra size, but only in case the datapart actually needs to
 * grow.  Use it when you know the next thing will be the allocation
 * of a big array.
 */
static int
add_attribute(cpg_attr_t *cpg_attr_p, int name, unsigned growthhint,
    uint32_t flags, cpg_attribute_t **ap)
{
	int	rv;

	cpg_attribute_t *p = find_attribute(cpg_attr_p->datapart, name,
	    ALLOCATE_OK);

	if (p == NULL) {
		/* need to grow */
		unsigned newsize = cpg_attr_p->datapart->firstfree +
		    ROUNDUP8(sizeof (cpg_attribute_t));
		/*
		 * GROW_DATAPART does nothing if datapart does not
		 * need to grow.  The cpg_attr_p->sysflags is for the
		 * CPG_ATTR_NOSLEEP remembered from when the
		 * cpg_attr_t was created.
		 */
		rv = GROW_DATAPART(cpg_attr_p, newsize, growthhint,
		    flags | cpg_attr_p->sysflags);
		if (rv) {
			return (rv);
		}

		p = find_attribute(cpg_attr_p->datapart, name,
		    ALLOCATE_OK);
		if (p == NULL) {
			REPORT_ERROR(NOTE, "cpg_attr: add_attribute: "
			    "find_attribute failed to allocate entry");
			return (CPGR_GENERAL_ERROR);
		}
	}
	p->flags  = 0;
	/* name, flags, next, and pad set, data uninitialized */
	*ap = p;
	return (CPGR_OK);
}

/*
 * Adds a scalar entry.
 */
static int
add_scalar_attribute(cpg_attr_t *cpg_attr_p, int name, uint32_t flags,
    uint64_t val)
{
	int		rv;
	cpg_attribute_t *p;
	uint32_t	attrinfoflags;

	if (cpg_attr_p->thisattrinfo == NULL) {
		attrinfoflags = flags & LEGAL_ADD_ENTRY_FLAGS;
	} else {
		rv = lookup_attr_info(cpg_attr_p->thisattrinfo, name,
		    &attrinfoflags);
		if (rv) {
			if (flags & CPG_ATTR_OVERRIDE) {
				/* CPG_ATTR_OVERRIDE will be set */
				attrinfoflags = flags & LEGAL_ADD_ENTRY_FLAGS;
			} else {
				return (rv);
			}
		} else {
			/*
			 * Found in attrinfo.  Make sure we are
			 * consistent.  CPG_ATTR_OVERRIDE not set
			 * here.
			 */
			attrinfoflags &= LEGAL_ATTR_FLAGS;
			if (attrinfoflags & CPG_ATTR_ISARRAY) {
				return (CPGR_TEMPLATE_INCONSISTENT);
			}
		}
	}

	/* the zero is the growthhint */
	rv = add_attribute(cpg_attr_p, name, 0,
	    attrinfoflags | (flags & LEGAL_SYSFLAGS), &p);
	if (rv) {
		return (rv);
	}

	p->data.d_uint64 = val;
	p->flags = attrinfoflags;
	cpg_attr_p->datapart->flags |= attrinfoflags;

	return (CPGR_OK);
}


/*
 * Adds a vector entry.
 */
static int
add_vector_attribute(cpg_attr_t *cpg_attr_p, int name,
    uint32_t flags, void *val, unsigned int numelems)
{
	int		rv;
	cpg_attribute_t *p;
	unsigned	int raw_arraysize;
	uint32_t	attrinfoflags;

	if (!cpg_attr_p->thisattrinfo || flags & CPG_ATTR_OVERRIDE) {
		attrinfoflags = (flags &
		    (LEGAL_ADD_ENTRY_FLAGS | CPG_ATTR_DATASIZE_MASK)) |
		    CPG_ATTR_ISARRAY;
	} else {
		rv = lookup_attr_info(cpg_attr_p->thisattrinfo, name,
		    &attrinfoflags);
		if (rv) {
			if (flags & CPG_ATTR_OVERRIDE) {
				/* CPG_ATTR_OVERRIDE will be set */
				attrinfoflags = flags &
				    (LEGAL_ATTR_FLAGS | CPG_ATTR_DATASIZE_MASK);
			} else {
				return (rv);
			}
		} else {
			/*
			 * Found in attrinfo.  Make sure we are
			 * consistent.  CPG_ATTR_OVERRIDE not set
			 * here, as it is not needed.
			 */
			attrinfoflags &= LEGAL_ATTR_FLAGS;
			if (!(attrinfoflags & CPG_ATTR_ISARRAY)) {
				return (CPGR_TEMPLATE_INCONSISTENT);
			}
			if ((attrinfoflags ^ flags) & CPG_ATTR_DATASIZE_MASK) {
				return (CPGR_TEMPLATE_INCONSISTENT);
			}
		}
	}

	raw_arraysize = (attrinfoflags & CPG_ATTR_DATASIZE_MASK) * numelems;

	/*
	 * rawarraysize is the growthhint.  (If it has to grow to add
	 * the attribute, allow enough space for the array too.)
	 * ROUNDUP8 gets applied at a lower level.
	 */
	rv = add_attribute(cpg_attr_p, name, raw_arraysize, flags, &p);
	if (rv) {
		return (rv);
	}

	rv = allocate_array(cpg_attr_p, &p, numelems, flags);
	if (rv) {
		return (rv);
	}

	p->flags = attrinfoflags & LEGAL_ATTR_FLAGS;
	cpg_attr_p->datapart->flags |= p->flags;

	/* now copy the data */
	(void) bcopy(val, ARRAY_ADDR(cpg_attr_p->datapart, p), raw_arraysize);

	return (CPGR_OK);
}


static int
get_scalar_value(cpg_attr_t *cpg_attr_p, int name, int flags,
    void *val_p) {
	cpg_attribute_t *bap;
	int		rv;
	cpg_attribute_t	a;
	uint64_t	garbage;  /* target for val_p == NULL */

	bap = find_attribute(cpg_attr_p->datapart, name, NO_ALLOCATE);
	if (bap == NULL) {
		rv = lookup_attr_info(cpg_attr_p->thisattrinfo, name, &a.flags);
		if (rv) {
			return (rv);
		}
		switch (a.flags & DEFAULT_MASK) {
		case 0:
			return (CPGR_ATTRIBUTE_TYPE_INVALID);
		case CPG_ATTR_DEFAULT_0:
			a.data.d_uint64 = 0;
			break;
		case CPG_ATTR_DEFAULT_1:
			a.data.d_uint64 = 1;
			break;
		default:
			REPORT_ERROR(NOTE, "cpg_attr: get_scalar_value: "
			    "invalid "
			    "default code in attrinfo for attribute 0x%x: "
			    "0x%x",
			    name, a.flags & DEFAULT_MASK);
			return (CPGR_ATTRIBUTE_TYPE_INVALID);
		}
		bap = &a;
	}

	if (bap->flags & CPG_ATTR_ISARRAY) {
		return (CPGR_DATA_INVALID);
	}

	/* was it sanitized? */
	if (bap->flags & CPG_ATTR_SANITIZE) {
		return (CPGR_ATTRIBUTE_SENSITIVE);
	}

	if (val_p == NULL) {
		val_p = &garbage;
	}

	/*
	 * Copy everything as unsigned values.  I suppose it would be
	 * more proper to copy the signed values as signed values, but
	 * it really won't make any difference.
	 */
	switch (flags & CPG_ATTR_DATASIZE_MASK) {
	case CPG_ATTR_DATASIZE8:
		*(uint8_t *)val_p = (uint8_t)bap->data.d_uint64;
		break;
	case CPG_ATTR_DATASIZE16:
		*(uint16_t *)val_p = (uint16_t)bap->data.d_uint64;
		break;
	case CPG_ATTR_DATASIZE32:
		*(uint32_t *)val_p = (uint32_t)bap->data.d_uint64;
		break;
	case CPG_ATTR_DATASIZE64:
		*(uint64_t *)val_p = bap->data.d_uint64;
		break;
	default:
		return (CPGR_ARGUMENTS_BAD);
	}

	return (CPGR_OK);
}



int
cpg_attr_delete_attribute(cpg_attr_t *restrict cpg_attr_p, int name)
{

	cpg_attribute_t *bap;

	bap = find_attribute(cpg_attr_p->datapart, name, NO_ALLOCATE);
	if (bap == NULL) {
		return (CPGR_ATTRIBUTE_TYPE_INVALID);
	}

	if (bap->flags & CPG_ATTR_ISARRAY) {
		discard_array(cpg_attr_p, bap);
	}
	bap->name = 0;  /* not really necessary, in fact, 0 is valid */
	bap->flags = CPG_ATTR_DEFUNCT;
	bap->data.d_uint64 = 0LL;

	return (CPGR_OK);
}

int
cpg_attr_get_attribute_flags(cpg_attr_t *cpg_attr_p, int name, uint32_t *flags)
{
	cpg_attribute_t *bap;

	bap = find_attribute(cpg_attr_p->datapart, name, NO_ALLOCATE);
	if (bap) {
		*flags = bap->flags;
		return (CPGR_OK);
	}
	/* not actually there, check attr infobase */
	return (cpg_attr_info_query(cpg_attr_p->attrinfobase,
	    cpg_attr_p->datapart->attr_policy, name, flags));
}


uint32_t
cpg_attr_get_flag_union(cpg_attr_t *cpg_attr_p)
{
	return (cpg_attr_p->datapart->flags);
}

/*
 * cpg_attr_copy_attribute copies the named attribute from the source
 * cpg_attr_list to the destination cpg_attr_list, without regard to
 * the type.  The new attribute has all the flags of the old one, plus
 * CPG_ATTR_SENSITIVE or CPG_ATTR_LOCAL as provided in the flags
 * argument.  If the attribute does not exist in the source
 * cpg_attr_list, CPGR_ATTRIBUTE_TYPE_INVALID is returned.
 */
int
cpg_attr_copy_attribute(cpg_attr_t *cpg_attr_src_p, cpg_attr_t *cpg_attr_dest_p,
    int name, uint32_t flags)
{
	int			rv = 0;
	int			rv1;
	cpg_attribute_t		*p;

	flags &= LEGAL_ADD_ENTRY_FLAGS;

	p = find_attribute(cpg_attr_src_p->datapart, name, NO_ALLOCATE);
	if (p == NULL) {
		/* no such entry */
		return (CPGR_ATTRIBUTE_TYPE_INVALID);
	}

	if (!(p->flags & CPG_ATTR_ISARRAY)) {
		rv1 = add_scalar_attribute(cpg_attr_dest_p, p->name,
		    p->flags | flags, p->data.d_uint64);
	} else {
		rv1 = add_vector_attribute(cpg_attr_dest_p, p->name,
		    p->flags | flags, ARRAY_ADDR(cpg_attr_src_p->datapart, p),
		    p->data.array_descriptor.length);
	}
	if (rv == 0) {
		rv = rv1;
	}

	return (rv);
}

static int
fluff(cpg_attr_data_t **data_pp, const cpg_attr_infobase_t *ibasep,
    uint32_t flags)
{
	const cpg_attr_info_t	*infop = ibasep->info[(*data_pp)->attr_policy];
	int		i;
	int		rv;
	cpg_attr_t	tmpattr;

	tmpattr.datapart = *data_pp;
	tmpattr.attrinfobase = ibasep;
	tmpattr.thisattrinfo = ibasep->info[(*data_pp)->attr_policy];
	tmpattr.sysflags = flags & LEGAL_SYSFLAGS;
	tmpattr.discarded_bytes = 0;


	for (i = 0; i < CPG_ATTR_INFO_SIZE; ++i) {
		cpg_attribute_t	*p;
		if (infop[i].flags == ~0) {
			continue;
		}
		p = find_attribute(*data_pp, infop[i].name, NO_ALLOCATE);
		if (p) {
			continue;
		}
		if ((infop[i].flags & DEFAULT_MASK) == CPG_ATTR_NO_DEFAULT) {
			continue;
		}
		if (infop[i].flags & CPG_ATTR_ISARRAY) {
			switch (infop[i].flags & DEFAULT_MASK) {
			case CPG_ATTR_DEFAULT_0:
				rv = add_vector_attribute(&tmpattr,
				    infop[i].name,
				    /* not CPG_ATTR_NO_GROWING_ROOM */
				    (flags & LEGAL_SYSFLAGS) |
				    (infop[i].flags & LEGAL_ATTR_FLAGS),
				    NULL, 0);
				if (rv) {
					return (rv);
				}
				break;
			default:
				REPORT_ERROR(NOTE, "cpg_attr: fluff: invalid "
				    "default code in attrinfo for attribute "
				    "0x%x: 0x%x",
				    infop[i].name,
				    infop[i].flags & DEFAULT_MASK);
			}
		} else {
			switch (infop[i].flags & DEFAULT_MASK) {
			case CPG_ATTR_DEFAULT_0:
				rv = add_scalar_attribute(&tmpattr,
				    infop[i].name,
				    /* not CPG_ATTR_NO_GROWING_ROOM */
				    (flags & LEGAL_SYSFLAGS) |
				    (infop[i].flags & LEGAL_ATTR_FLAGS),
				    0ULL);
				if (rv) {
					return (rv);
				}
				break;
			case CPG_ATTR_DEFAULT_1:
				rv = add_scalar_attribute(&tmpattr,
				    infop[i].name,
				    /* not CPG_ATTR_NO_GROWING_ROOM */
				    (flags & LEGAL_SYSFLAGS) |
				    (infop[i].flags & LEGAL_ATTR_FLAGS),
				    1ULL);
				if (rv) {
					return (rv);
				}
				break;
			default:
				REPORT_ERROR(NOTE, "cpg_attr: fluff: invalid "
				    "default code in attrinfo for attribute "
				    "0x%x: 0x%x",
				    infop[i].name,
				    infop[i].flags & DEFAULT_MASK);
			}
		}
	}


	/*
	 * If the caller wants no growing room, we shrink back by
	 * reallocing.  We don't worry about zeroizing, since no
	 * sensitive info can be after firstfree.
	 */
	if (flags & CPG_ATTR_NO_GROWING_ROOM) {
		int newsize = tmpattr.datapart->firstfree;
		cpg_attr_data_t *newbuf;

		newbuf = localrealloc(tmpattr.datapart,
		    tmpattr.datapart->allocsize, newsize,
		    tmpattr.datapart->flags);
		if (newbuf == NULL) {
			/*
			 * Make it simple, after all
			 * CPGA_ATTR_NO_GROWING_ROOM is just a hint.
			 */
			goto skipshrink;
		}
		newbuf->allocsize = newsize;
		tmpattr.datapart = newbuf;
	}

skipshrink:

	*data_pp = tmpattr.datapart;
	return (CPGR_OK);
}

/*
 * cpg_attr_merge copies attributes from the source cpg_attr_list into
 * the desintation cpg_attr_list.
 */
int
cpg_attr_merge(cpg_attr_t *cpg_attr_src_p, cpg_attr_t *cpg_attr_dest_p,
    uint32_t flags)
{
	int		rv = 0;
	int		rv1;
	cpg_attribute_t *p;
	cpg_attr_walk_state_t ws;
	uint32_t	flagsunion;

	flags &= ~(CPG_ATTR_NOSLEEP | CPG_ATTR_DEFUNCT);

	for (cpg_attr_walk_init(&ws, cpg_attr_src_p);
	    cpg_attr_walk_more_q(&ws);
	    cpg_attr_walk_next(&ws)) {
		p = walk_get_addr(&ws);
		/*
		 * p->flags contains all the attribute-specific info
		 * about size, signed, sensitive, local, etc.
		 * cpg_attr_dest_p->sysflags will contain
		 * CPG_ATTR_NOSLEEP if it was provided when the
		 * cpg_attr was allocated.
		 */
		flagsunion =
		    p->flags |
		    cpg_attr_dest_p->sysflags |
		    (flags & CPG_ATTR_NOSLEEP);
		if (!(p->flags & CPG_ATTR_ISARRAY)) {
			rv1 = add_scalar_attribute(cpg_attr_dest_p,
			    p->name, flagsunion, p->data.d_uint64);
		} else {
			rv1 = add_vector_attribute(cpg_attr_dest_p,
			    p->name, flagsunion,
			    ARRAY_ADDR(cpg_attr_src_p->datapart, p),
			    p->data.array_descriptor.length);
		}
		if (rv == 0) {
			rv = rv1;
		}
	}

	return (rv);
}

/*
 * Changes the policy to attrpolicy.
 */
int
cpg_attr_set_policy(cpg_attr_t *cpg_attr_p, int policy)
{
	if (policy >= cpg_attr_p->attrinfobase->num_entries) {
		REPORT_ERROR(CE_NOTE, "cpg_attr: cpg_attr_set_policy: "
		    "new policy "
		    "is %d, which is invalid", policy);
		return (CPGR_GENERAL_ERROR);
	}

	cpg_attr_p->datapart->attr_policy = policy;
	cpg_attr_p->thisattrinfo = cpg_attr_p->attrinfobase->info[policy];

	return (CPGR_OK);
}

/* Returns the policy though the funtion name */
int
cpg_attr_get_policy(cpg_attr_t *cpg_attr_p)
{
	return (cpg_attr_p->datapart->attr_policy);
}

/*
 * Checks that every attr marked required is present. If not, it
 * returns CPGR_TEMPLATE_INCOMPLETE.  Checks that the type of every
 * attribute is sufficiently correct.  More specifically the
 * CPG_ATTR_ISARRAY flag must match, and if CPG_ATTR_ISARRAY is set,
 * the size must match.  If not it returns CPGR_TEMPLATE_INCONISTENT.
 * The check is against the array attrarray.  If attrarray is null,
 * the policy in the datapart is used.  If flags contains
 * CPG_ATTR_REPORT_BOGUS, it also reports attributes that should not be
 * in the list, unless if they have CPG_ATTR_OVERRIDE set.  In case of
 * error, *offender is set to the name of the first offending entry.
 */
int
cpg_attr_check(cpg_attr_t *restrict cpg_attr_p,
    const cpg_attr_info_t *attrarray,
    int flags, int *offender)
{

	int		j;
	cpg_attr_data_t	*data_p = cpg_attr_p->datapart;
	cpg_attribute_t	*p;
	uint16_t	policy = data_p->attr_policy;

	if (attrarray == NULL) {
		if (policy >= cpg_attr_p->attrinfobase->num_entries) {
			REPORT_ERROR(NOTE, "cpg_attr: cpg_attr_check: "
			    "attrpolicy is %d, "
			    "which is invalid", policy);
			return (CPGR_GENERAL_ERROR);
		}
		attrarray = cpg_attr_p->attrinfobase->info[policy];
	}

	if (attrarray == NULL) {
		return (CPGR_OK);
	}

	/*
	 * Make sure that (a) each required attribute is present, (b)
	 * each attribute is in agreement on array vs scalar, and (c)
	 * the elementsize of each array is correct.
	 */
	for (j = 0; j < CPG_ATTR_INFO_SIZE; ++j) {
		if (attrarray[j].flags == ~0) {
			continue;
		}
		p = find_attribute(data_p, attrarray[j].name, NO_ALLOCATE);
		if (p == NULL) {
			if (attrarray[j].flags & CPG_ATTR_REQUIRED) {
				*offender =  attrarray[j].name;
				return (CPGR_TEMPLATE_INCOMPLETE);
			} else {
				continue;
			}
		}
		if ((p->flags ^ attrarray[j].flags) & CPG_ATTR_ISARRAY) {
			*offender =  attrarray[j].name;
			return (CPGR_TEMPLATE_INCONSISTENT);
		}
		if (p->flags & CPG_ATTR_ISARRAY &&
		    (p->flags ^ attrarray[j].flags) & CPG_ATTR_DATASIZE_MASK) {
			*offender =  attrarray[j].name;
			return (CPGR_TEMPLATE_INCONSISTENT);
		}
	}

	/*
	 * Check for attriutes not in the attrarray.
	 */
	if (attrarray && flags & CPG_ATTR_REPORT_BOGUS) {
		cpg_attr_walk_state_t	ws;
		int			rv;
		uint32_t		attrflags;  /* throw away */

		for (cpg_attr_walk_init(&ws, cpg_attr_p);
		    cpg_attr_walk_more_q(&ws);
		    cpg_attr_walk_next(&ws)) {
			p = walk_get_addr(&ws);
			if (p->flags & CPG_ATTR_OVERRIDE) {
				continue;
			}
			rv = lookup_attr_info(attrarray, p->name, &attrflags);
			if (rv) {
				*offender = p->name;
				return (rv);
			}
		}
	}

	return (CPGR_OK);
}

/*
 * The following function works for any sort of data type. \*value,
 * \*len, and \*attrflags are always set.  \*attrp is set if attrp is
 * non-null.  See the table below.  This function does not suppress
 * sensitive entries, but if the entry has been removed elsewhere
 * because a CPGR_SANITIZE flag was supplied to a dup, filter, store,
 * etc., operation, the value pointer is set to null, the length is
 * set to -1, and the return code is CPGR_ATTRIBUTE_SENSITIVE.  If the
 * value is a scaler, \*value is set to point to a uint64_t
 * representation of the value.  Note: \*value may point to the
 * internals of the cpg_attr_list, and thus \*value should be
 * considered invalid after any modification of the cpg_attr_list.
 * \*value must be never be modified.
 *
 * case      *value                *len (bytes)   attrflags
 * ------    -------------------   -------------  -----------
 * scalar    pointer to uint64_t   see note       entry flags
 * array     pointer to data       from entry     entry flags
 * sensitive null                  -1             entry flags
 * error     null                  -1             0
 *
 * Note, in the scalar case the len will is normally taken from the
 * attrinfo, but will be taken from the entry if there is no attrinfo
 * entry or the entry has the CPG_ATTR_OVERRIDE flag set.
 *
 * \*attrp will be set to the address of the live internal attribute.
 * It becomes invalid if the attribute is modified in any way.
 * Ordinarily pass null.  This is for experts only.
 */
int
cpg_attr_lookup_generic(cpg_attr_t *restrict cpg_attr_p, int name,
    void **value, unsigned int *len, uint32_t *attrflags,
    cpg_attribute_t **attrp)
{
	cpg_attribute_t *bap;
	int		inforv = CPGR_OK;
	uint32_t	attrinfo_flags = 0;
	uint32_t	final_flags = 0;

	/*
	 * lookup attr_info returns CPGR_ATTRIBUTE_TYPE_INVALID if its
	 * first arg is null.
	 */
	inforv = lookup_attr_info(cpg_attr_p->thisattrinfo, name,
		    &attrinfo_flags);
	bap = find_attribute(cpg_attr_p->datapart, name, NO_ALLOCATE);

	if (attrp) {
		*attrp = bap;
	}

	if (bap == NULL && inforv) {
		/* no entry and no attrinfo */
		*value = NULL;
		*len = (unsigned)(-1);
		*attrflags = 0;
		return (inforv);
	}

	if (bap && (inforv != CPGR_OK || bap->flags & CPG_ATTR_OVERRIDE)) {
		final_flags = bap->flags;
	} else {
		final_flags = attrinfo_flags;
		if (bap) {
			final_flags |= bap->flags &
			    (CPG_ATTR_SENSITIVE | CPG_ATTR_SANITIZE);
		}
	}

	if (final_flags & CPG_ATTR_SANITIZE) {
		*value = NULL;
		*len = (unsigned)(-1);
		*attrflags = final_flags;
		return (CPGR_ATTRIBUTE_SENSITIVE);
	}

	if (final_flags & CPG_ATTR_ISARRAY) {
		if (bap) {
			/* explicit value */
			*value = DEREF_N(void *,
			    bap->data.array_descriptor.offset,
			    cpg_attr_p->datapart);
			*len = ARRAY_LENGTH(bap);
		} else if (attrinfo_flags & CPG_ATTR_DEFAULT_0) {
			/* defaults to empty string */
			*value = NULL;
			*len = 0;
		} else {
			/* no default */
			*value = NULL;
			*len = (unsigned)(-1);
			*attrflags = 0;
			return (CPGR_ATTRIBUTE_TYPE_INVALID);
		}
	} else {
		/* scalar variable */
		if (bap) {
			*value = &bap->data.d_uint64;
			*len = DATASIZE(final_flags);
		} else {
			switch (attrinfo_flags & CPG_ATTR_DEFAULT_MASK) {
			case CPG_ATTR_DEFAULT_0:
				*value = &ZERO64;
				*len = DATASIZE(final_flags);
				break;
			case CPG_ATTR_DEFAULT_1:
				*value = &ONE64;
				*len = DATASIZE(final_flags);
				break;
			default:
				*value = NULL;
				*len = (unsigned)(-1);
				*attrflags = 0;
				return (CPGR_ATTRIBUTE_TYPE_INVALID);
			}
		}
	}
	*attrflags = final_flags;
	return (CPGR_OK);
}

int
cpg_attr_add_int8(cpg_attr_t *restrict cpg_attr_p, int name, int8_t val,
    uint32_t flags)
{
	return (add_scalar_attribute(cpg_attr_p, name,
	    CPG_ATTR_DATASIZE8 | (flags & LEGAL_ADD_ENTRY_FLAGS),
	    (uint64_t)val));
}

int
cpg_attr_add_uint8(cpg_attr_t *restrict cpg_attr_p, int name, uint8_t val,
    uint32_t flags)
{
	return (add_scalar_attribute(cpg_attr_p, name,
	    CPG_ATTR_DATASIZE8 | CPG_ATTR_ISUNSIGNED |
	    (flags & LEGAL_ADD_ENTRY_FLAGS), (uint64_t)val));
}

int
cpg_attr_add_int16(cpg_attr_t *restrict cpg_attr_p, int name, int16_t val,
    uint32_t flags)
{
	return (add_scalar_attribute(cpg_attr_p, name,
	    CPG_ATTR_DATASIZE16 |
	    (flags & LEGAL_ADD_ENTRY_FLAGS),
	    (uint64_t)val));
}

int
cpg_attr_add_uint16(cpg_attr_t *restrict cpg_attr_p, int name, int16_t val,
    uint32_t flags)
{
	return (add_scalar_attribute(cpg_attr_p, name,
	    CPG_ATTR_DATASIZE16 | CPG_ATTR_ISUNSIGNED |
	    (flags & LEGAL_ADD_ENTRY_FLAGS), (uint64_t)val));

}

int
cpg_attr_add_int32(cpg_attr_t *restrict cpg_attr_p, int name, int32_t val,
    uint32_t flags)
{
	return (add_scalar_attribute(cpg_attr_p, name,
	    CPG_ATTR_DATASIZE32 |
	    (flags & LEGAL_ADD_ENTRY_FLAGS),
	    (uint64_t)val));
}

int
cpg_attr_add_uint32(cpg_attr_t *restrict cpg_attr_p, int name, uint32_t val,
    uint32_t flags)
{
	return (add_scalar_attribute(cpg_attr_p, name,
	    CPG_ATTR_DATASIZE32 | CPG_ATTR_ISUNSIGNED |
	    (flags & LEGAL_ADD_ENTRY_FLAGS), (uint64_t)val));

}

int
cpg_attr_add_int64(cpg_attr_t *restrict cpg_attr_p, int name, int64_t val,
    uint32_t flags)
{
	return (add_scalar_attribute(cpg_attr_p, name,
	    CPG_ATTR_DATASIZE64 |
	    (flags & LEGAL_ADD_ENTRY_FLAGS), (uint64_t)val));
}

int
cpg_attr_add_uint64(cpg_attr_t *restrict cpg_attr_p, int name, uint64_t val,
    uint32_t flags)
{
	return (add_scalar_attribute(cpg_attr_p, name,
	    CPG_ATTR_DATASIZE64 | CPG_ATTR_ISUNSIGNED |
	    (flags & LEGAL_ADD_ENTRY_FLAGS), (uint64_t)val));

}

int
cpg_attr_add_int8_array(cpg_attr_t *restrict cpg_attr_p, int name, int8_t *val,
    uint_t nelem, uint32_t flags)
{
	return (add_vector_attribute(cpg_attr_p, name,
	    CPG_ATTR_DATASIZE8 | (flags & LEGAL_ADD_ENTRY_FLAGS), val,
	    nelem));
}

int
cpg_attr_add_uint8_array(cpg_attr_t *restrict cpg_attr_p, int name,
    uchar_t *val, uint_t nelem, uint32_t flags)
{
	return (add_vector_attribute(cpg_attr_p, name,
	    CPG_ATTR_DATASIZE8 | CPG_ATTR_ISUNSIGNED |
	    (flags & LEGAL_ADD_ENTRY_FLAGS), val, nelem));
}


int
cpg_attr_add_int16_array(cpg_attr_t *restrict cpg_attr_p, int name,
    int16_t *val, uint_t nelem, uint32_t flags)
{
	return (add_vector_attribute(cpg_attr_p, name,
	    CPG_ATTR_DATASIZE16 | (flags & LEGAL_ADD_ENTRY_FLAGS), val,
	    nelem));
}

int
cpg_attr_add_uint16_array(cpg_attr_t *restrict cpg_attr_p, int name,
    uint16_t *val, uint_t nelem, uint32_t flags)
{
	return (add_vector_attribute(cpg_attr_p, name,
	    CPG_ATTR_DATASIZE16 | CPG_ATTR_ISUNSIGNED |
	    (flags & LEGAL_ADD_ENTRY_FLAGS), val, nelem));
}


int
cpg_attr_add_int32_array(cpg_attr_t *restrict cpg_attr_p, int name,
    int32_t *val, uint_t nelem, uint32_t flags)
{
	return (add_vector_attribute(cpg_attr_p, name,
	    CPG_ATTR_DATASIZE32 | (flags & LEGAL_ADD_ENTRY_FLAGS), val,
	    nelem));
}


int
cpg_attr_add_uint32_array(cpg_attr_t *restrict cpg_attr_p, int name,
    uint32_t *val, uint_t nelem, uint32_t flags)
{
	return (add_vector_attribute(cpg_attr_p, name,
	    CPG_ATTR_DATASIZE32 | CPG_ATTR_ISUNSIGNED |
	    (flags & LEGAL_ADD_ENTRY_FLAGS), val, nelem));
}


int
cpg_attr_add_int64_array(cpg_attr_t *restrict cpg_attr_p, int name,
    int64_t *val, uint_t nelem, uint32_t flags)
{
	return (add_vector_attribute(cpg_attr_p, name,
	    CPG_ATTR_DATASIZE64 | (flags & LEGAL_ADD_ENTRY_FLAGS), val,
	    nelem));
}


int
cpg_attr_add_uint64_array(cpg_attr_t *restrict cpg_attr_p, int name,
    uint64_t *val, uint_t nelem, uint32_t flags)
{
	return (add_vector_attribute(cpg_attr_p, name,
	    CPG_ATTR_DATASIZE64 | CPG_ATTR_ISUNSIGNED |
	    (flags & LEGAL_ADD_ENTRY_FLAGS), val, nelem));
}


int
cpg_attr_lookup_int8(cpg_attr_t *restrict cpg_attr_p, int name, int8_t *val)
{
	int		rv;
	unsigned int	len;
	uint32_t	flags;
	uint64_t	*valp;

	rv = cpg_attr_lookup_generic(cpg_attr_p, name, (void **)&valp,
	    &len, &flags, NULL);
	if (rv == CPGR_OK && !(flags & CPG_ATTR_ISARRAY)) {
		*val = (int8_t)*valp;
	} else {
		rv = CPGR_TEMPLATE_INCONSISTENT;
	}
	return (rv);
}

int
cpg_attr_lookup_uint8(cpg_attr_t *restrict cpg_attr_p, int name, uchar_t *val)
{
	int		rv;
	unsigned int	len;
	uint32_t	flags;
	uint64_t	*valp;

	rv = cpg_attr_lookup_generic(cpg_attr_p, name,
	    (void **)&valp, &len, &flags, NULL);
	if (rv == CPGR_OK && !(flags & CPG_ATTR_ISARRAY)) {
		*val = (uint8_t)*valp;
	} else {
		rv = CPGR_TEMPLATE_INCONSISTENT;
	}
	return (rv);
}


int
cpg_attr_lookup_int16(cpg_attr_t *restrict cpg_attr_p, int name, int16_t *val)
{
	int		rv;
	unsigned int	len;
	uint32_t	flags;
	uint64_t	*valp;

	rv = cpg_attr_lookup_generic(cpg_attr_p, name,
	    (void **)&valp, &len, &flags, NULL);
	if (rv == CPGR_OK && !(flags & CPG_ATTR_ISARRAY)) {
		*val = (int16_t)*valp;
	} else {
		rv = CPGR_TEMPLATE_INCONSISTENT;
	}
	return (rv);
}

int
cpg_attr_lookup_uint16(cpg_attr_t *restrict cpg_attr_p, int name, uint16_t *val)
{
	int		rv;
	unsigned int	len;
	uint32_t	flags;
	uint64_t	*valp;

	rv = cpg_attr_lookup_generic(cpg_attr_p, name,
	    (void **)&valp, &len, &flags, NULL);
	if (rv == CPGR_OK && !(flags & CPG_ATTR_ISARRAY)) {
		*val = (uint16_t)*valp;
	} else {
		rv = CPGR_TEMPLATE_INCONSISTENT;
	}
	return (rv);
}


int
cpg_attr_lookup_int32(cpg_attr_t *restrict cpg_attr_p, int name, int32_t *val)
{
	int		rv;
	unsigned int	len;
	uint32_t	flags;
	uint64_t	*valp;

	rv = cpg_attr_lookup_generic(cpg_attr_p, name,
	    (void **)&valp, &len, &flags, NULL);
	if (rv == CPGR_OK && !(flags & CPG_ATTR_ISARRAY)) {
		*val = (int32_t)*valp;
	} else {
		rv = CPGR_TEMPLATE_INCONSISTENT;
	}
	return (rv);
}


int
cpg_attr_lookup_uint32(cpg_attr_t *restrict cpg_attr_p, int name, uint32_t *val)
{
	int		rv;
	unsigned int	len;
	uint32_t	flags;
	uint64_t	*valp;

	rv = cpg_attr_lookup_generic(cpg_attr_p, name,
	    (void **)&valp, &len, &flags, NULL);
	if (rv == CPGR_OK && !(flags & CPG_ATTR_ISARRAY)) {
		*val = (uint32_t)*valp;
	} else {
		rv = CPGR_TEMPLATE_INCONSISTENT;
	}
	return (rv);
}


int
cpg_attr_lookup_int64(cpg_attr_t *restrict cpg_attr_p, int name, int64_t *val)
{
	int		rv;
	unsigned int	len;
	uint32_t	flags;
	uint64_t	*valp;

	rv = cpg_attr_lookup_generic(cpg_attr_p, name,
	    (void **)&valp, &len, &flags, NULL);
	if (rv == CPGR_OK && !(flags & CPG_ATTR_ISARRAY)) {
		*val = (int64_t)*valp;
	} else {
		rv = CPGR_TEMPLATE_INCONSISTENT;
	}
	return (rv);

}


int
cpg_attr_lookup_uint64(cpg_attr_t *restrict cpg_attr_p, int name, uint64_t *val)
{
	int		rv;
	unsigned int	len;
	uint32_t	flags;
	uint64_t	*valp;

	rv = cpg_attr_lookup_generic(cpg_attr_p, name,
	    (void **)&valp, &len, &flags, NULL);
	if (rv == CPGR_OK && !(flags & CPG_ATTR_ISARRAY)) {
		*val = *valp;
	} else {
		rv = CPGR_TEMPLATE_INCONSISTENT;
	}
	return (rv);
}


/*
 * The following functions return pointers to live internal data.  The
 * caller must be careful.
 */
int
cpg_attr_lookup_int8_array(cpg_attr_t *restrict cpg_attr_p, int name,
    int8_t **val, uint_t *nelem)
{
	int		rv;
	unsigned int	len;
	uint32_t	flags;
	void		*valp;

	rv = cpg_attr_lookup_generic(cpg_attr_p, name,
	    (void **)&valp, &len, &flags, NULL);
	if (rv != CPGR_OK) {
		return (rv);
	}
	if (!(flags & CPG_ATTR_ISARRAY)) {
		return (CPGR_TEMPLATE_INCONSISTENT);
	}
	*val = (int8_t *)valp;
	*nelem = len;
	return (CPGR_OK);
}

int
cpg_attr_lookup_uint8_array(cpg_attr_t *restrict cpg_attr_p, int name,
    uint8_t **val, uint_t *nelem)
{
	int		rv;
	unsigned int		len;
	uint32_t	flags;
	void		*valp;

	rv = cpg_attr_lookup_generic(cpg_attr_p, name,
	    (void **)&valp, &len, &flags, NULL);
	if (rv != CPGR_OK) {
		return (rv);
	}
	if (!(flags & CPG_ATTR_ISARRAY)) {
		return (CPGR_TEMPLATE_INCONSISTENT);
	}
	*val = (uint8_t *)valp;
	*nelem = len;
	return (CPGR_OK);
}


int
cpg_attr_lookup_int16_array(cpg_attr_t *restrict cpg_attr_p, int name,
    int16_t **val, uint_t *nelem)
{
	int		rv;
	unsigned int	len;
	uint32_t	flags;
	void		*valp;

	rv = cpg_attr_lookup_generic(cpg_attr_p, name,
	    (void **)&valp, &len, &flags, NULL);
	if (rv != CPGR_OK) {
		return (rv);
	}
	if (!(flags & CPG_ATTR_ISARRAY)) {
		return (CPGR_TEMPLATE_INCONSISTENT);
	}
	*val = (int16_t *)valp;
	*nelem = (uint_t)((int)len / 2);
	return (CPGR_OK);
}


int
cpg_attr_lookup_uint16_array(cpg_attr_t	 *restrict cpg_attr_p, int name,
    uint16_t **val, uint_t *nelem)
{
	int		rv;
	unsigned int	len;
	uint32_t	flags;
	void		*valp;

	rv = cpg_attr_lookup_generic(cpg_attr_p, name,
	    (void **)&valp, &len, &flags, NULL);
	if (rv != CPGR_OK) {
		return (rv);
	}
	if (!(flags & CPG_ATTR_ISARRAY)) {
		return (CPGR_TEMPLATE_INCONSISTENT);
	}
	*val = (uint16_t *)valp;
	*nelem = (uint_t)((int)len / 2);
	return (CPGR_OK);
}

int
cpg_attr_lookup_int32_array(cpg_attr_t *restrict cpg_attr_p,  int name,
    int32_t **val, uint_t *nelem)
{
	int		rv;
	unsigned int	len;
	uint32_t	flags;
	void		*valp;

	rv = cpg_attr_lookup_generic(cpg_attr_p, name,
	    (void **)&valp, &len, &flags, NULL);
	if (rv != CPGR_OK) {
		return (rv);
	}
	if (!(flags & CPG_ATTR_ISARRAY)) {
		return (CPGR_TEMPLATE_INCONSISTENT);
	}
	*val = (int32_t *)valp;
	*nelem = (uint_t)((int)len / 4);
	return (CPGR_OK);
}

int
cpg_attr_lookup_uint32_array(cpg_attr_t *restrict cpg_attr_p, int name,
    uint32_t **val, uint_t *nelem)
{
	int		rv;
	unsigned int	len;
	uint32_t	flags;
	void		*valp;

	rv = cpg_attr_lookup_generic(cpg_attr_p, name,
	    (void **)&valp, &len, &flags, NULL);
	if (rv != CPGR_OK) {
		return (rv);
	}
	if (!(flags & CPG_ATTR_ISARRAY)) {
		return (CPGR_TEMPLATE_INCONSISTENT);
	}
	*val = (uint32_t *)valp;
	*nelem = (uint_t)((int)len / 4);
	return (CPGR_OK);
}

int
cpg_attr_lookup_int64_array(cpg_attr_t *restrict cpg_attr_p,  int name,
    int64_t **val, uint_t *nelem)
{
	int		rv;
	unsigned int	len;
	uint32_t	flags;
	void		*valp;

	rv = cpg_attr_lookup_generic(cpg_attr_p, name,
	    (void **)&valp, &len, &flags, NULL);
	if (rv != CPGR_OK) {
		return (rv);
	}
	if (!(flags & CPG_ATTR_ISARRAY)) {
		return (CPGR_TEMPLATE_INCONSISTENT);
	}
	*val = (int64_t *)valp;
	*nelem = (uint_t)((int)len / 8);
	return (CPGR_OK);
}

int
cpg_attr_lookup_uint64_array(cpg_attr_t	 *restrict cpg_attr_p, int name,
    uint64_t **val, uint_t *nelem)
{
	int		rv;
	unsigned int	len;
	uint32_t	flags;
	void		*valp;

	rv = cpg_attr_lookup_generic(cpg_attr_p, name,
	    (void **)&valp, &len, &flags, NULL);
	if (rv != CPGR_OK) {
		return (rv);
	}
	if (!(flags & CPG_ATTR_ISARRAY)) {
		return (CPGR_TEMPLATE_INCONSISTENT);
	}
	*val = (uint64_t *)valp;
	*nelem = (uint_t)((int)len / 8);
	return (CPGR_OK);
}
