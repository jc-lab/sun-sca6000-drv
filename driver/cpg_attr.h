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

#ifndef _CPG_ATTR_H
#define	_CPG_ATTR_H

#pragma ident	"@(#)cpg_attr.h	1.4	07/03/29 SMI"

#ifdef	__cplusplus
extern "C" {
#endif


#ifdef LINUX
#include <linux/types.h>
#else
#include <sys/types.h>
#endif

#ifdef CPG_ATTR_USE_PK11_RETURNS

#define	CPGR_OK	0
#define	CPGR_SAVED_STATE_INVALID 0x160
#define	CPGR_CANCEL 0x1
#define	CPGR_GENERAL_ERROR 0x5
#define	CPGR_HOST_MEMORY 0x2
#define	CPGR_ATTRIBUTE_TYPE_INVALID 0x12
#define	CPGR_TEMPLATE_INCONSISTENT 0xd1
#define	CPGR_DATA_INVALID 0x20
#define	CPGR_ATTRIBUTE_SENSITIVE 0x11
#define	CPGR_ARGUMENTS_BAD 0x7
#define	CPGR_TEMPLATE_INCOMPLETE 0xd0

#else

#ifdef LINUX
#include "common.h"
#else
#include <sys/crypto/common.h>
#endif
#define	CPGR_OK	CRYPTO_SUCCESS
/* CRYPTO_... does not have a saved state invalid error */
#define	CPGR_SAVED_STATE_INVALID CRYPTO_DEVICE_ERROR
#define	CPGR_CANCEL CRYPTO_CANCEL
#define	CPGR_GENERAL_ERROR CRYPTO_GENERAL_ERROR
#define	CPGR_HOST_MEMORY CRYPTO_HOST_MEMORY
#define	CPGR_ATTRIBUTE_TYPE_INVALID CRYPTO_ATTRIBUTE_TYPE_INVALID
#define	CPGR_TEMPLATE_INCONSISTENT CRYPTO_TEMPLATE_INCONSISTENT
#define	CPGR_DATA_INVALID CRYPTO_DATA_INVALID
#define	CPGR_ATTRIBUTE_SENSITIVE CRYPTO_ATTRIBUTE_SENSITIVE
#define	CPGR_ARGUMENTS_BAD CRYPTO_ARGUMENTS_BAD
#define	CPGR_TEMPLATE_INCOMPLETE CRYPTO_TEMPLATE_INCOMPLETE

#endif

/*
 * General info
 */


/*
 * cpg_attr_lists (a human readable name only) are a name-value pair
 * system following the general idea of nvlists (see libnvpar(3lib)).
 * The main difference is that in cpg_attr_lists the "name" is an
 * integer, while in nvlists it is a string.  Another difference is
 * that cpg_attr_lists attach flags to entries to support limited
 * containment.  (See the CPG_ATTR_LOCAL and CPG_ATTR_SENSITIVE
 * flags.)  cpg_attr_lists are much more efficient than nvlists.  In
 * addition, there is an elaborate defauting structure, so that
 * entries not present will get their default values.
 *
 * A cpg_attr_list consists of two chunks of memory.  There is a
 * header of type cpg_attr_t, and a data part.  It is the header that
 * the user directly accesses.  The data part is a cpg_attr_data_t,
 * followed by a table of entries of type cpg_attribute_t and possibly
 * array data.  (The implementation has 8 hash buckets and linked
 * lists.)  Ideally this is compact, except that everything has 8-byte
 * alignment.  However, deleting attributes or changing array values
 * can leave it fragmented.  Links are not real pointers, rather they
 * are offsets relative to the beginning of the cpg_attr_data_t.  The
 * space between the end of the data and the allocated size indicated
 * in the header is assumed to be free, and the cpg_attr_list will
 * consume it when it needs to grow.  The cpg_attr_t also contains a
 * pointer to an attr_info block (array of cpg_attr_info_t), which has
 * (constant) information about types and default values.  Typically
 * there would be just one attr_info array shared amongst all
 * cpg_attr_lists.
 *
 * The user can create a detached data part for writing to disk or
 * network, or for transferring across an interface.  The user can
 * also attach a data part.  Detached data parts can be in either
 * big endian or litle endian byte order.  Attached data parts are
 * always in the native byte order.  The user can also directly access
 * the live data part with cpg_attr_ref_data, which, of course, is
 * always in native byte order.
 *
 * A cpg_attr_t is primarily a pointer to the cpg_attr_data_t, and a
 * field holding the allocated size. This indirection allows the
 * cpg_attr_data_t to be cleaned by copying and to expand.  Other
 * fields are the compressed size field, which is the size datapart
 * would be with no wasted space other than that required for 8-byte
 * alignment, and a pointer to an array of cpg_attr_info_t structures
 * that form the attr_info_block.  The compressed size field is used
 * in copying and defragmenting the data part.  If _KERNEL is defined,
 * there is the flag to supply to all calls to kmem_alloc and
 * kmem_zalloc.
 *
 * The attr_info array is an array of cpg_attr_info_t structures (just
 * a integer name and flags word).  The name field of the first
 * element holds the size of the remainder of the array.  An
 * attribute's position as found by using the hash function (here
 * expressed in floating point, but actually coded using integer
 * arithmetic):
 *
 * h = (int)(goldenratio * name * CPG_ATTR_INFO_SIZE) % CPG_ATTR_INFO_SIZE
 *
 * and then stepping (with wrapping) until the desired entry or a
 * blank entry (name == ~0) is found.
 *
 * The flags word in the cpg_attr_data_t is the logical OR of the
 * flags of each cpg_attribute entry plus some other flags (see
 * below).
 *
 * The header of the data part contains the list heads for
 * CPG_ATTR_NUM_LISTS linked lists.  Entries are put on a list
 * selected by hashing the name.
 *
 * These functions provide no locking of their own; the caller must
 * manage concurrency issues herself.
 *
 * Sizes and offsets are limited to 2^32-1.  However, no check is done.
 *
 * All the data accessing functions that store through pointers
 * (cpg_attr_lookup_... and cpg_attr_copyout_...) leave the pointer
 * target(s) unmodified when there is an error.
 *
 * When calling from the kernel, there is a distinction between
 * sleeping allocation and non-sleeping allocation.  (Only the latter
 * can be used in interrupt context.)  There are flags to force
 * non-sleeping allocation.  When supplied to the funtions that
 * allocate a cpg_attr, they not only affect the immediate operation,
 * but all subsequent operations on the cpg_attr.  If the table was
 * initalized with CPG_ATTR_NO_SLEEP, that flag will be supplied
 * automatically to all calls.
 */

/*
 * Overall structure
 */

/*
 *
 *               Arrays of cpg_attr_info_t, one for each numbered policy.
 *                                        Each array is actually
 *               +---+   +---+  +---+     128 entries long.
 *               |   |   |   |  |   |     Initialzied with macros
 *               |   |   |   |  |   |     generated by perl script.
 *               +---+   +---+  +---+
 *               |   |   |   |  |   |
 *               |   |   |   |  |   |
 *               +---+   +---+  +---+
 *               |   |   |   |  |   |
 *               |   |   |   |  |   |
 *               +---+   +---+  +---+
 *               |   |   |   |  |   |
 *               |   |   |   |  |   |
 *               +---+   +---+  +---+
 *                ^        ^      ^
 *                !    +===+      !
 *                !    !    +=====+
 *         +----+-!--+-!--+-!--+
 *         |null| @  | @  | @  |   array, num_entries long, set up
 *         |    |    |    |    |   by user (no fancy initializers)
 *         +----+----+----+----+
 *           ^
 *           !
 *           +=====================================+
 *                                                 !
 *                                                 !
 *                                                 !
 *  +------------------------------------------+   !
 *  | infobase (cpg_attr_infobase_t)           |   !
 *  | (set up by user---no fancy initializers) |   !
 *  |                                          |   !
 *  | num_entries               (4 in example) |   !
 *  | info                      @==================+
 *  +------------------------------------------+
 *                              ^
 *                              !
 *                              !       +--------------------------------+
 *                              !       | datapart (cpg_attr_data_t ...) |
 *  +---------------------+     !       | (see detail below)             |
 *  | base (cpg_attr_t)   |     !       +--------------------------------+
 *  |                     |     !         ^
 *  | attrinfobase @============+         !
 *  | datapart     @======================+
 *  | (other misc stuff)  |
 *  +---------------------+
 *
 * The infobase stuff is constant data.  The expected usage is
 * that there is just one global shared copy, systemwide, to which
 * every cpg_attr_t instance points.
 */



/*
 * The datapart (version 2)
 */

/*
 *  |<-------cpg_attr_data_t--------->|
 *
 *  +----------------------------+----+------------------------------------+
 *  | datapart (cpg_attr_data_t) |    | allocated attrs        | free area |
 *  |                            +----+ and data blocks                    |
 *  | version (16 bits)          |    |                        |           |
 *  | attr_policy (16 bits)      +----+  +-----+      +-----+              |
 *  | flags                      | @====>|name |    +>|name |  |           |
 *  | firstfree   @              +----+  |flags|    ! |flags|              |
 *  | allocsize@  !              |    |  |offset@=+ ! |value|  |           |
 *  |          !  !              +----+  |len  |  ! ! |     |              |
 *  |          !  !              |    |  |next @==!=+ |next @=>null        |
 *  |          !  !              +----+  +-----+  !   +-----+              |
 *  |          !  !              |8   |   +=======+            |           |
 *  |          !  !              +----+   v                                |
 *  |          !  !              |list|  +----------------+    |           |
 *  |          !  !              +----+  | data array     |                |
 *  |          !  !              |heads  +----------------+    |           |
 *  +----------!--!--------------+----+------------------------------------+
 *             !  !                                             ^           ^
 *             !  +=============================================+           !
 *             +============================================================+
 *
 * The data part begins with a cpg_attr_data_t and must be 8-byte
 * aligned.  Attribute structures (cpg_attribute_t) and data for
 * array-valued attributes are allocated sequentially from the free
 * area, and are all 8-byte aligned.  All offsets are relative to the
 * beginning of the datapart; a zero offset indicates a null
 * reference. An attribute is array-valued if CPG_ATTR_ISARRAY is set
 * in its flags field.  Freed attributes are marked CPG_ATTR_DEFUNCT
 * in the flags field, but not unlinked.  They will be reused if a new
 * entry is needed in the linked list that contains them.  The data
 * arrays for freed or overwritten array-valued attributes are simply
 * abandoned.  (They will be garbaged collected the next time the
 * datapart is copied if the wasted space exceeds DEFRAG_THRESHOLD (in
 * cpg_attr.c)).  Note that because there is only a free area, not a
 * free list, and nothing is really freed, all offsets are either null
 * or "right pointing".  Attaching code can verify that this is true
 * and infer that there are no cycles, then an attribute-by-attribute
 * copy will ensure that no arrays overlay attributue structures in
 * the copy.  (See CPG_ATTR_USE_EXTRA_CARE.)  The list head is
 * determined by the ATTRHASH macro in cpg_attr.c.  All fields are
 * little endian if the flags word in the data part contains 0x80 in
 * the first and last bytes.
 */

/*
 * Datapart (version 1)
 */

/*
 *  |<-------cpg_attr_data_t----->|
 *
 *  +----------------------------------------------------------------------+
 *  | datapart (cpg_attr_data1_t) | first attribute is right   | free area |
 *  |                               after cpg_attr_data1_t                 |
 *  | version (16 bits)           |                            |           |
 *  | pad (16 bits)                +-----+      +-----+                    |
 *  | flags                       ||name |    +>|name |        |           |
 *  | size @=====+                 |flags|    ! |flags|                    |
 *  | lastattr @ !                ||offset@=+ ! |value|        |           |
 *  |          ! !                 |len  |  ! ! |     |                    |
 *  |          ! !                ||next @==!=+ |next @==>null |           |
 *  |          ! !                 +-----+  ! ! +-----+                    |
 *  |          +============================!=+                |           |
 *  |            !                          v                              |
 *  |            !                |        +----------------+  |           |
 *  |            !                         | data array     |              |
 *  |            !                |        +----------------+  |           |
 *  +------------!---------------------------------------------------------+
 *               !                                              ^
 *               +==============================================+
 *
 *
 *
 *
 * Similar to version 2 with the following exceptions.  There is a
 * single linked list and no list head variable or array.  The first
 * attribute (if present) is right after the cpg_attr_data_t.  The
 * firstfree field is named size in version 1 (same meaning).  In
 * place of the allocsize field in version 2, version has lastattr. It
 * is the offset of the last attribute, and null if no attributes have
 * been allocated.  The allocated size must be kept track of
 * separately.  (There is a field for the allocated size of the
 * datapart in a version-1 cpg_attr_t.)  The only thing the version 2
 * system does with version 1 dataparts is attach them, and
 * cpg_attr_attach_data takes the allocated size as one of its
 * parameters.
 */


/*
 * Common flags, accepted most everywhere
 *
 * CPG_ATTR_NOSLEEP  (allocate with KM_NOSLEEP)
 * CPG_ATTR_NO_GROWING_ROOM (hint to minimize free area of datapart)
 */


/*
 * The following flags are used in the cpg_add_...add functions and
 * cpg_attr_copy_attribute.
 *
 * CPG_ATTR_NOSLEEP (recognized in kernel only)
 * CPG_ATTR_LOCAL
 * CPG_ATTR_SENSITIVE (add functions only; ignored unless CPG_ATTR_OVERRIDE
 *	is also supplied)
 * CPG_ATTR_OVERRIDE
 */

/*
 * The following flags are honored by cpg_attr_filter,
 * cpg_attr_store_data, cpg_attr_attach_data, and cpg_attr_dup.
 *
 * CPG_ATTR_DELETE_LOCAL
 * CPG_ATTR_SANITIZE
 * CPG_ATTR_FLUFF
 * CPG_ATTR_NO_GROWING_ROOM
 * CPG_ATTR_NOSLEEP (recognized in kernel only)
 * CPG_ATTR_USE_EXTRA_CARE (cpg_attr_attach_data only)
 * CPG_ATTR_LITTLE_ENDIAN (cpg_attr_store data only)
 * CPG_ATTR_BIG_ENDIAN    (cpg_attr_store_data only)
 * CPG_ATTR_NATIVE_ENDIAN (cpg_attr_store_data only)
 */


/*
 * The following flags are returned by cpg_attr_get_attribute_flags
 * and cpg_attr_get_flag_union.
 *
 * CPG_ATTR_LOCAL
 * CPG_ATTR_SENSITIVE
 * CPG_ATTR_ISARRAY
 * CPG_ATTR_ISUNSIGNED
 * CPG_ATTR_DATASIZE8
 * CPG_ATTR_DATASIZE16
 * CPG_ATTR_DATASIZE32
 * CPG_ATTR_DATASIZE64
 * CPG_ATTR_OVERRIDE
 * CPG_ATTR_LITTLE_ENDIAN (cpg_attr_get_flag_union only)
 */


/*
 * The following flags are used in the flags field of the
 * cpg_attr_info_t type, which is used to describe the attributes.
 *
 * CPG_ATTR_SENSITIVE
 * CPG_ATTR_ISARRAY
 * CPG_ATTR_ISUNSIGNED
 * CPG_ATTR_DATASIZE8
 * CPG_ATTR_DATASIZE16
 * CPG_ATTR_DATASIZE32
 * CPG_ATTR_DATASIZE64
 * CPG_ATTR_OVERRIDE
 * CPG_ATTR_DEFAULT_0
 * CPG_ATTR_DEFAULT_1
 */


/*
 * Actual code and explanation for individual flags.
 */


/*
 * The CPG_ATTR_LOCAL flag marks an entry as "local".  The intent is
 * that this restricts its crossing beyond certain boundaries.  It can
 * be passed to any of the add functions.  All CPG_ATTR_LOCAL entries
 * will be suppressed if CPG_ATTR_DELETE_LOCAL is supplied to
 * cpg_attr_dup, cpg_attr_filter, cpg_attr_store_data, or
 * cpg_attr_attach data.
 */
#define	CPG_ATTR_LOCAL 0x100

/*
 * CPG_ATTR_DELETE_LOCAL is a flag to cpg_attr_dup, cpg_attr_filter,
 * cpg_attr_store_data, or cpg_attr_attach_data to suppress
 * CPG_ATTR_LOCAL entries.
 */
#define	CPG_ATTR_DELETE_LOCAL 0x10000
/*
 * The CPG_ATTR_SENSITIVE flag marks an entry as sensitive.  It can be
 * passed to any of the add routines or cpg_attr_set_entry_flags.  All
 * such fields will have their data suppressed and the
 * CPG_ATTR_SANITIZE flag set if the CPG_ATTR_SANITIZE flag is
 * supplied to cpg_attr_dup, cpg_attr_filter, cpg_attr_store_data, or
 * cpg_attr_attach_data.
 */
#define	CPG_ATTR_SENSITIVE 0x200
/*
 * The CPG_ATTR_SANITIZE flag is a directive to cpg_attr_dup,
 * cpg_attr_filter, cpg_attr_store_data, or cpg_attr_attach_data to
 * suppress CPG_ATTR_SENSITIVE entries.  An entry whose value is
 * missing because it has been sanitized has CPG_ATTR_SANITIZE set.
 */
#define	CPG_ATTR_SANITIZE 0x20000

/*
 * CPG_ATTR_FLUFF is a directive to cpg_attr_dup, cpg_attr_filter, and
 * cpg_attr_attr_store_data, or cpg_attr_attach_data to fluff all the
 * attributes with defined defaults.
 */
#define	CPG_ATTR_FLUFF 0x40000

/*
 * CPG_ATTR_REPORT_BOGUS is a flag to cpg_attr_check that causes it to
 * report entries that should not be in the cpg_attr_list, unless they
 * have the CPG_ATTR_OVERRIDE flag set.
 */
#define	CPG_ATTR_REPORT_BOGUS 0x80000
/*
 * CPG_ATTR_NO_GROWING_ROOM is a hint to cpg_attr_store_data,
 * cpg_attr_attach_data, cpg_attr_dup, and cpg_attr_filter, etc., to
 * not allocate extra space for the cpg_attr to grow.
 */
#define	CPG_ATTR_NO_GROWING_ROOM 0x100000

/*
 * CPG_ATTR_NOSLEEP indicates that internal calls to kmem_alloc should
 * provide the KM_NOSLEEP flag.  When supplied to cpg_attr_alloc,
 * cpg_attr_attach_data, or cpg_attr_dup, it is remembered and affects
 * all subsequent operations on the returned cpg_attr.  This flag has
 * an effect only when the library is compiled with _KERNEL defined.
 */
#define	CPG_ATTR_NOSLEEP 0x200000
/*
 * CPG_ATTR_OVERRIDE when supplied to a cpg_attr_add... function
 * causes the attr_info_block to be ignored.  When this flag is
 * supplied, entries can be created that are not in the
 * attr_info_block, and all the information about size and sensitive
 * comes solely from supplied flags.  It also affects cpg_attr_check.
 */
#define	CPG_ATTR_OVERRIDE 0x400000

/*
 * CPG_ATTR_USE_EXTRA_CARE causes cpg_attr_attach_data to do a sanity
 * check on the data being attached.  This flag should be supplied any
 * time the data is coming from an untrusted source and chaos and
 * corrution are unacceptable (e.g. in the kernel after a copyin, and
 * in the firmware when parsing a keystore file).  This flag is also
 * recognized by cpg_attr_filter, where it forces an
 * attribute-by-attribute copy to be made.
 */
#define	CPG_ATTR_USE_EXTRA_CARE 0x800000

/*
 * The following group of flags encode the type of data associated
 * with an attribute.  They are returned by cpg_attr_get_flags.
 */
#define	CPG_ATTR_ISARRAY 0x40
#define	CPG_ATTR_ISUNSIGNED 0x20

/*
 * Note that the values directly encode the data element size (for
 * arrays) in bytes.
 */
#define	CPG_ATTR_DATASIZE8 0x1
#define	CPG_ATTR_DATASIZE16 0x2
#define	CPG_ATTR_DATASIZE32 0x4
#define	CPG_ATTR_DATASIZE64 0x8
/* Thest two masks select useful subsets of the bits. */
#define	CPG_ATTR_DATASIZE_MASK 0xf
#define	CPG_ATTR_TYPE_MASK 0x6f
#define	CPG_ATTR_INFO_MASK (CPG_ATTR_TYPE_MASK | CPG_ATTR_SENSITIVE | \
    CPG_ATTR_LOCAL)

/*
 * CPG_ATTR_REQUIRED indicates that the attribute must be explicitly
 * provided.
 */
#define	CPG_ATTR_REQUIRED 0x400

/*
 * Default value flags are used only in the cpg_attr_info_t's flags
 * field.  The bit range indicated by mask 0xf000 are reserved for
 * default value flags.
 */

#define	CPG_ATTR_DEFAULT_MASK 0xf000

/*
 * CPG_ATTR_NO_DEFAULT means that no default value is
 * provided. However, it is not an error for the value to not be
 * provided.  (This is typically used for values that are
 * programmatically set.  This is not normally used since it is the
 * default.
 */
#define	CPG_ATTR_NO_DEFAULT (0 << 12)

/*
 * CPG_ATTR_DEFAULT_0 indicates that scalars should default to
 * zero and arrays should default to empty.
 */
#define	CPG_ATTR_DEFAULT_0 (1 << 12)

/*
 * CPG_ATTR_DEFAULT_1 indicates that scalars should default to 1.
 */
#define	CPG_ATTR_DEFAULT_1 (2 << 12)

/*
 * Add more default flags here as needed (up to 15 << 12).
 */

/*
 * The endian-related flags are used as subcommands to
 * cpg_attr_store_data to indicate the desired format.  In
 * cpg_attr_data_t flags field they indicate the byte order of a data
 * buffer.  Note that CPG_ATTR_LITTLE_ENDIAN is symmetrical with
 * respect to byte reversal.
 */

#define	CPG_ATTR_LITTLE_ENDIAN 0x80000080
#define	CPG_ATTR_BIG_ENDIAN 0
#define	CPG_ATTR_ENDIAN_MASK CPG_ATTR_LITTLE_ENDIAN
#ifdef _BIG_ENDIAN
#define	CPG_ATTR_NATIVE_ENDIAN 0
#else
#define	CPG_ATTR_NATIVE_ENDIAN CPG_ATTR_LITTLE_ENDIAN
#endif

/*
 * CPG_ATTR_DEFUNCT means that the associated cpg_attribute_t has been
 * deleted.  This flag is not needed in client code if only official
 * interfaces are used.
 */
#define	CPG_ATTR_DEFUNCT 0x10

/* The number is hash table entries and hence the number of lists */
#define	CPG_ATTR_NUM_LISTS 8


/*
 * typedefs and structure definitions
 */

/*
 * The cpg_offset_t type is similar to a pointer, but is relative to the
 * beginning of a kcs_attr_t.
 */
typedef uint32_t cpg_offset_t;

/* note: requires 8-byte alignment */
typedef struct cpg_attribute {
	uint32_t	name;
	uint32_t	flags;
	union {
		uint64_t d_uint64;
		struct ptr {
			cpg_offset_t	offset;	 /* always multiple of 8 */
			uint32_t	length;
		} array_descriptor;
	} data;
	cpg_offset_t	next;
	uint32_t	pad;
} cpg_attribute_t;


/*
 * the data part of a cpg_attr_list, version 1
 */
typedef struct cpg_attr_data1 {
	uint16_t	version; /* always 1 */
	uint16_t	pad1;
	uint32_t	flags;	/* endian flag OR flags of each attribute */
	uint32_t	size;	/* size of data, 8-byte rounded up */
	cpg_offset_t	lastattr; /* points to last entry, or zero if none */
} cpg_attr_data1_t;

/* version 2 */

typedef struct cpg_attr_data2 {
	uint16_t	version; /* always 2 */
	/* integer index into the info array of a cpg_attr_default _t */
	uint16_t	attr_policy;
	uint32_t	flags;	/* endian flag OR flags of each attribute */
	cpg_offset_t	firstfree; /* offset to next place to allocate */
	uint32_t	allocsize; /* total size allocated */
	cpg_offset_t	listheads[CPG_ATTR_NUM_LISTS];
} cpg_attr_data_t;

/*
 * The info structure is an array of these.  The size of the array (in
 * entries) is specified by CPG_ATTR_INFO_SIZE, which comes from the
 * machine-generated file cpg_attr_info.h, which is generated by
 * cpg_attr_info.pl.
 */
typedef struct cpg_attr_info {
	uint32_t	name;
	uint32_t	flags;
} cpg_attr_info_t;

/*
 * cpg_attr_infobase_t is a struture that points to a bunch of
 * cpg_attr_info_t arrays.  The is on open structure.  The user is
 * responsible for setting it up.
 */
typedef struct cpg_attr_infobase {
	int	num_entries;
	cpg_attr_info_t	**info;  /* array of length num_policies */
} cpg_attr_infobase_t;

/*
 * the header part of a cpg_attr_list
 */
typedef struct cpg_attr {
	cpg_attr_data_t	*restrict datapart;
	const cpg_attr_infobase_t *attrinfobase;
	const cpg_attr_info_t	*thisattrinfo; /* a cache */
	uint32_t		sysflags;
	/* only a hint, only arrays count */
	uint32_t		discarded_bytes;
} cpg_attr_t;


/*
 * Function prototypes and descriptions.
 */

/*
 * Returns flags for a particular attribute based on the attrinfobase
 * and the specified policy.  Returns CPGR_ATTRIBUTE_TYPE_INVALID if
 * the attribute is not listed.  The request will succeed and returned
 * flags will be zero if the entry in the attr infobase is a NULL
 * pointer.  (This will normally be the case if attrpolicy is zero.)
 * The zero should be interpreted to mean that nothing is known about
 * the attribute, and everything is allowed.
 */
int cpg_attr_info_query(const cpg_attr_infobase_t *defaultattrinfo_p,
    int attrpolicy, uint32_t name, uint32_t *flagsp);


/*
 * Initializes a cpg_attr_list.  attrinfo is a pointer to the
 * cpg_attr_default_t with the current policies (null ok if
 * defaultpolicy is zero).  defaultpoicy names the current policy
 * (index into defaultattrinfo_p[], zero always means no defaults.)
 * Growthhint suggests expected growth in bytes.  The only recognized
 * flag is CPG_ATTR_NOSLEEP.
 */
int cpg_attr_init(cpg_attr_t *restrict cpg_attr_p,
    const cpg_attr_infobase_t *defaultattrinfo_p,
    int attrpolicy, unsigned int growthhint, uint32_t flags);

/*
 * Allocates a cpg_attr_t, then calls cpg_attr_init.
 */
int cpg_attr_alloc_init(cpg_attr_t **restrict cpg_attr_p,
    const cpg_attr_infobase_t *defaultattrinfo_p,
    int attrpolicy, unsigned int growthhint, uint32_t flags);



/*
 * Attaches a newly allocated header (cpg_attr_t) to a data part
 * (cpg_attr_data_t and following bits) and a attrinfo array.  Use
 * this when the data part has been read from disk or network or
 * passed across an interface.  If CPG_ATTR_DO_SANITY_CHECK is
 * supplied, the buffer to be attached is checked for structural
 * validity; it is either forced to correctness or the function
 * returns CPGR_SAVED_STATE_INVALID.  (In the present implementation,
 * supplying CPG_ATTR_DO_SANITY_CHECK may cause the data to be
 * copied.)  Also recognized are CPG_ATTR_NOSLEEP and
 * CPG_ATTR_NO_GROWING_ROOM flags.  After this function has been
 * called, the buffer is managed by the cpg_attr system and should not
 * be directly accessed or freed by the user.  The size in the header
 * is forced to allocated_size; and some minimal checks are done even
 * in the absense of CPG_ATTR_DO_SANITY_CHECK.
 */
int cpg_attr_attach_data(cpg_attr_t *restrict cpg_attr_p,
    cpg_attr_data_t *restrict datapart,
    unsigned int allocated_size, cpg_attr_infobase_t const *attrinfobase_p,
    uint32_t flags);


/*
 * Allocates a cpg_attr_t, then calls cpg_attr_attach_data.
 */
int cpg_attr_alloc_attach_data(cpg_attr_t **restrict cpg_attr_p,
    cpg_attr_data_t *restrict datapart,
    unsigned int allocated_size, cpg_attr_infobase_t const *attrinfobase_p,
    uint32_t flags);



/*
 * Makes a detached copy of the cpg_attr_list's data part (the
 * cpg_attr_data_t plus) in a new buffer and stores the address in
 * *obuf.  The amount of buffer space used is stored in *size.  Under
 * control of various flags, the output buffer can be written in
 * either little endian or big endian format, and various fields can
 * be suppressed.  It is the user's responsiblity to manage the output
 * buffer.  Recognized flags are CPG_ATTR_NOSLEEP,
 * CPG_ATTR_NO_GROWING_ROOM, CPG_ATTR_SANITIZE, CPG_ATTR_DELETE_LOCAL,
 * CPG_ATTR_LITTLE_ENDIAN, CPG_ATTR_BIG_ENDIAN (the default byte
 * order), and CPG_ATTR_NATIVE_ENDIAN.
 */
int cpg_attr_store_data(cpg_attr_t *restrict cpg_attr_p, cpg_attr_data_t **obuf,
    unsigned int *size, uint32_t flags);

/*
 * Returns a pointer to the live datapart.
 */
void cpg_attr_ref_data(cpg_attr_t *restrict cpg_attr_p,
    cpg_attr_data_t **datapart_pp,
    unsigned int *size);

/* Changes the policy to attrpolicy */
int cpg_attr_set_policy(cpg_attr_t *cpg_attr_p, int attrpolicy);
/* Returns the current attrpolicy */
int cpg_attr_get_policy(cpg_attr_t *cpg_attr_p);


/*
 * Checks that every attr marked required is present. If not, it
 * returns CPGR_TEMPLATE_INCOMPLETE.  Checks that the type of every
 * attribute is sufficiently correct.  More specifically the
 * CPG_ATTR_ISARRAY flag must match, and if CPG_ATTR_ISARRAY is set,
 * the size must match.  If not it returns CPGR_TEMPLATE_INCONISTENT.
 * The check is against the array attrarray.  If attrarray is null,
 * the policy in the datapart is used.  If flags contains
 * CPG_ATTR_REPORT_BOGUS, it also reports attributes that should not
 * be in the list, unless they have CPG_ATTR_OVERRIDE set.  In case of
 * error, *offender is set to the name of the first offeding entry.
 */
int cpg_attr_check(cpg_attr_t *restrict cpg_attr_p,
    const cpg_attr_info_t *attrarray,
    int flags, int *offender);


/*
 * Frees all parts of cpg_attr except the cpg_attr_info array.
 * Sensitive fields are zeroized before being freed.
 */
void cpg_attr_destroy(cpg_attr_t *restrict cpg_attr_p);

/*
 * Calls cpg_attr_destroy, then frees the cpg_attr_t.
 */
void cpg_attr_free(cpg_attr_t *restrict cpg_attr_p);


/*
 * Returns the size of a data part, regardless of its byte order.
 */
unsigned int cpg_attr_data_size(cpg_attr_data_t *cpg_attr_p);


/*
 * The following type and four functions enable walking a cpg_attr and
 * discovering its contents.  These functions are designed for easy
 * use in a 'for' loop.
 */
typedef struct cpg_attr_walk_state {
	cpg_attr_data_t		*datapart_p;
	int			hashbucket;
	cpg_attribute_t		*currentp;
} cpg_attr_walk_state_t;

/*
 * cpg_attr_walk_init initializes the cpg_attr_walk_state_t variable.
 */
void cpg_attr_walk_init(cpg_attr_walk_state_t *restrict state,
    cpg_attr_t *cpg_attr_p);

/*
 * Return non-zero if more data is avaiable.
 */
int cpg_attr_walk_more_q(cpg_attr_walk_state_t *restrict state);

/*
 * Advance to next entry
 */
void cpg_attr_walk_next(cpg_attr_walk_state_t *restrict state);

/*
 * Get data on current attribute
 */
void cpg_attr_walk_get_info(cpg_attr_walk_state_t *restrict state,
    uint32_t *name, uint32_t *flags);


/*
 * Copies the cpg_attr_list (both base part and data part).
 * Recognized flags are CPG_ATTR_SANITIZE, CPG_ATTR_DELETE_LOCAL,
 * CPG_ATTR_FLUFF, and CPG_ATTR_NOSLEEP.  The growthhint parameter
 * suggests an expected amount of growth, in bytes.
 */
int cpg_attr_dup(cpg_attr_t *restrict cpg_attr_p,
    cpg_attr_t *restrict newcpg_attr_p,
    unsigned int growthhint, uint32_t flags);


/*
 * Allocates at cpg_attr_t, then calls cpg_attr_dup
 */
int cpg_attr_alloc_dup(cpg_attr_t *restrict cpg_attr_p,
    cpg_attr_t **restrict newcpg_attr_p,
    unsigned int growthhint, uint32_t flags);

/*
 * Filters the attributes in the entry.  The following flags are
 * recognized: CPG_ATTR_SANITIZE, CPG_ATTR_DELETE_LOCAL,
 * CPG_ATTR_NOSLEEP, CPGR_USE_EXTRA_CARE, CPG_ATTR_FLUFF.  The
 * CPG_ATTR_USE_EXTRA_CARE flag causes the size to be computed from
 * scratch and forces a full copy, which will rehash all the entires.
 * This flag is intended for use in an internal call from
 * cpg_attr_attach_data.  In the present implemenation a new data part
 * is always created.
 */
int cpg_attr_filter(cpg_attr_t *restrict cpg_attr_p, uint32_t flags);

/*
 * Access entry flags.  If not present, access attr_infobase.
 */
int cpg_attr_get_attribute_flags(cpg_attr_t *cpg_attr_p, int name,
    uint32_t *flags);

/*
 * Returns the union of flags that are present in all the attributes
 * plus CPG_ATTR_LITTLE_ENDIAN, if appropriate.
 */
uint32_t cpg_attr_get_flag_union(cpg_attr_t *restrict cpg_attr_p);

/*
 * cpg_attr_copy_attribute copies the named attribute from the source
 * cpg_attr_list to the destination cpg_attr_list, regardless of the
 * type.  The new attribute has all the flags of the old one, plus any
 * given in the flags argument except for CPG_ATTR_NOSLEEP.  If the
 * attribute does not exist in the source cpg_attr_list and there is
 * not default value, CPGR_ATTRIBUTE_TYPE_INVALID is returned.  The
 * semantics are equivalent to a lookup followed by an add.
 */
int
cpg_attr_copy_attribute(cpg_attr_t *restrict cpg_attr_srcp,
    cpg_attr_t *restrict cpg_attr_destp,
    int name, uint32_t flags);

/*
 * cpg_attr_merge copies attributes from the source cpg_attr_list into
 * the destination cpg_attr_list.
 */
int cpg_attr_merge(cpg_attr_t *restrict cpg_attr_src_p,
    cpg_attr_t *restrict cpg_attr_dest_p,
    uint32_t flags);

/*
 * The cpg_attr_add... functions return CPGR_HOST_MEMORY if sufficient
 * memory cannot be allocated.  The recognized flags are
 * CPG_ATTR_SENSITIVE, CPG_ATTR_LOCAL, CPG_ATTR_OVERRIDE, and
 * CPG_ATTR_NOSLEEP.  The CPG_ATTR_SENSITIVE flag and the type
 * information will be taken from the cpg_attr_info array unless
 * CPG_ATTR_OVERRIDE is supplied.  If CPG_ATTR_OVERRIDE is not
 * supplied, and the field is not described in the cpg_attr_info
 * array, CPG_ATTR_INVALID_TYPE is returned.
 */
int cpg_attr_add_int8(cpg_attr_t *restrict cpg_attr_p, int name, int8_t val,
    uint32_t flags);

int cpg_attr_add_uint8(cpg_attr_t *restrict cpg_attr_p, int name, uint8_t val,
    uint32_t flags);

int cpg_attr_add_int16(cpg_attr_t *restrict cpg_attr_p, int name, int16_t val,
    uint32_t flags);

int cpg_attr_add_uint16(cpg_attr_t *restrict cpg_attr_p, int name,
    int16_t val, uint32_t flags);

int cpg_attr_add_int32(cpg_attr_t *restrict cpg_attr_p,	int name,
    int32_t val, uint32_t flags);

int cpg_attr_add_uint32(cpg_attr_t *restrict cpg_attr_p, int name,
    uint32_t val, uint32_t flags);

int cpg_attr_add_int64(cpg_attr_t *restrict cpg_attr_p,	int name,
    int64_t val, uint32_t flags);

int cpg_attr_add_uint64(cpg_attr_t *restrict cpg_attr_p, int name,
    uint64_t val, uint32_t flags);

int cpg_attr_add_int8_array(cpg_attr_t *restrict cpg_attr_p, int name,
    int8_t *restrict val, uint_t nelem, uint32_t flags);

int cpg_attr_add_uint8_array(cpg_attr_t *restrict cpg_attr_p, int name,
    uint8_t *restrict val, uint_t nelem, uint32_t flags);

int cpg_attr_add_int16_array(cpg_attr_t *restrict cpg_attr_p, int name,
    int16_t *restrict val, uint_t nelem, uint32_t flags);

int cpg_attr_add_uint16_array(cpg_attr_t *restrict cpg_attr_p, int name,
    uint16_t *restrict val, uint_t nelem, uint32_t flags);

int cpg_attr_add_int32_array(cpg_attr_t *restrict cpg_attr_p, int name,
    int32_t *restrict val, uint_t nelem, uint32_t flags);

int cpg_attr_add_uint32_array(cpg_attr_t *restrict cpg_attr_p, int name,
    uint32_t *restrict val, uint_t nelem, uint32_t flags);

int cpg_attr_add_int64_array(cpg_attr_t *restrict cpg_attr_p, int name,
    int64_t *restrict val, uint_t nelem, uint32_t flags);

int cpg_attr_add_uint64_array(cpg_attr_t *restrict cpg_attr_p, int name,
    uint64_t *restrict val, uint_t nelem, uint32_t flags);

int cpg_attr_lookup_int8(cpg_attr_t *restrict cpg_attr_p, int name,
    int8_t *restrict val);

int cpg_attr_lookup_uint8(cpg_attr_t *restrict cpg_attr_p,  int name,
    uint8_t *restrict val);

int cpg_attr_lookup_int16(cpg_attr_t *restrict cpg_attr_p,  int name,
    int16_t *restrict val);

int cpg_attr_lookup_uint16(cpg_attr_t *restrict cpg_attr_p,  int name,
    uint16_t *restrict val);

int cpg_attr_lookup_int32(cpg_attr_t *restrict cpg_attr_p,  int name,
    int32_t *restrict val);

int cpg_attr_lookup_uint32(cpg_attr_t *restrict cpg_attr_p,  int name,
    uint32_t *restrict val);

int cpg_attr_lookup_int64(cpg_attr_t *restrict cpg_attr_p,  int name,
    int64_t *restrict val);

int cpg_attr_lookup_uint64(cpg_attr_t *restrict cpg_attr_p,  int name,
    uint64_t *restrict val);

/*
 * The following functions return pointers to internal data.  The
 * pointer becomes invalid when any of the function that may modify
 * the cpg_attr is called on the same cpg_attr_p.  Such functions
 * include cpg_attr_add..., cpg_attr_delete_attribute,
 * cpg_attr_filter, cpg_attr_free.
 */
int cpg_attr_lookup_int8_array(cpg_attr_t *restrict cpg_attr_p, int name,
    int8_t **restrict val, uint_t *nelem);

int cpg_attr_lookup_uint8_array(cpg_attr_t *restrict cpg_attr_p, int name,
    uint8_t **restrict val, uint_t *nelem);

int cpg_attr_lookup_int16_array(cpg_attr_t *restrict cpg_attr_p, int name,
    int16_t **restrict val, uint_t *nelem);

int cpg_attr_lookup_uint16_array(cpg_attr_t *restrict cpg_attr_p, int name,
    uint16_t **restrict val, uint_t *nelem);

int cpg_attr_lookup_int32_array(cpg_attr_t *restrict cpg_attr_p, int name,
    int32_t **restrict val, uint_t *nelem);

int cpg_attr_lookup_uint32_array(cpg_attr_t *restrict cpg_attr_p, int name,
    uint32_t **restrict val, uint_t *nelem);

int cpg_attr_lookup_int64_array(cpg_attr_t *restrict cpg_attr_p, int name,
    int64_t **restrict val, uint_t *nelem);

int cpg_attr_lookup_uint64_array(cpg_attr_t  *restrict cpg_attr_p, int name,
    uint64_t **restrict val, uint_t *nelem);


/*
 * The following function works for any sort of data type. *value,
 * *len, and *attrflags are always set.  See the table below.  If the
 * value cannot be returned because the entry is sensitive and
 * CPG_ATTR_SANITIZE has (at some time) suppresed it, , the return
 * code is CPGR_ATTRIBUTE_SENSITIVE.  If the values is a scaler,
 * \*value is set to point to a uint64_t representation of the value.
 * Note: when non-null, *value points to the internals of the
 * cpg_attr_list; *value should be considered invalid after any
 * modification of the cpg_attr_list.
 *
 * case      *value                *len           attrflags
 * ------    -------------------   -------------  -----------
 * scalar    pointer to uint64_t   8              entry flags
 * array     pointer to data       size in bytes  entry flags
 * sensitive null                  -1             entry flags
 * other     null                  -1             0
 */
int cpg_attr_lookup_generic(cpg_attr_t *restrict cpg_attr_p, int name,
    void **value, unsigned int *len, uint32_t *attrflags,
    cpg_attribute_t **attrp);


/*
 * delete an attribute
 */
int cpg_attr_delete_attribute(cpg_attr_t *restrict cpg_attr_p, int name);

#ifdef	__cplusplus
}
#endif

#endif /* _CPG_ATTR_H */
