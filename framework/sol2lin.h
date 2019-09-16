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

#ifndef	_SOL2LIN_H
#define	_SOL2LIN_H

#pragma ident	"@(#)sol2lin.h	1.38	08/08/11 SMI"

#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/dma-mapping.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <asm/uaccess.h>

#include "../work_ex.h"

#ifdef	__cplusplus
extern "C" {
#endif

#define SPIN_LOCK_UNLOCKED	__SPIN_LOCK_UNLOCKED(old_style_spin_init)
#define RW_LOCK_UNLOCKED	__RW_LOCK_UNLOCKED(old_style_rw_init)

#define DEFINE_SPINLOCK(x)	spinlock_t x = __SPIN_LOCK_UNLOCKED(x)
#define DEFINE_RWLOCK(x)	rwlock_t x = __RW_LOCK_UNLOCKED(x)


#ifdef _BIG_ENDIAN
#define	BE_64(x)		(x)
#else
#define	BSWAP_8(x)		((x) & 0xff)
#define	BSWAP_16(x)		((BSWAP_8(x) << 8) | BSWAP_8((x) >> 8))
#define	BSWAP_32(x)		((BSWAP_16(x) << 16) | BSWAP_16((x) >> 16))
#define	BSWAP_64(x)		((BSWAP_32(x) << 32) | BSWAP_32((x) >> 32))
#define	BE_64(x)		BSWAP_64(x)
#endif


#ifdef DEBUG
#define	SCA_DBG_PRINT(fmt, args...) \
	printk(KERN_WARNING "SCA DEBUG:" fmt, ## args)
#define	ASSERT(expr)							\
	if (!(expr)) {							\
		printk(KERN_ERR "Assertion failed! %s,%s,%s,line=%d\n",	\
#expr, __FILE__, __FUNCTION__, __LINE__);				\
	}
#else
#define	SCA_DBG_PRINT(fmt, args...)
#define	ASSERT(expr)
#endif

#define	SCA_WRN_PRINT(fmt, args...) \
	printk(KERN_WARNING "SCA WARNING:" fmt, ## args)

#define	SCA_ERR_PRINT(fmt, args...) \
	printk(KERN_ERR "SCA ERROR:" fmt, ## args)

#define	MAX_NUM_SCA_DEVICE		8
#define	MAXNAMELEN			32
#define	SIXTY_FOUR_K			65536

#define	DDI_SUCCESS		(0)	/* successful return */
#define	DDI_FAILURE		(-1)	/* unsuccessful return */

#define	ENOTSUP			EOPNOTSUPP	/* Operation not supported */

/*
 * Use spin_lock_irqsave/spin_unlock_irqrestore in the interrupt context.
 * Use spin_lock/spin_unlock otherwise.
 */
/* mutex conflicts with Linux kernel mutex */
typedef struct kmutex {
	spinlock_t	lock;
	unsigned long	flag;
	int		interrupt;
	int		locked;
} kmutex_t;

typedef enum {
	MUTEX_ADAPTIVE = 0,
	MUTEX_SPIN = 1,
	MUTEX_DRIVER = 4,
	MUTEX_DEFAULT = 6
} kmutex_type_t;

/*
 * mutex_init macro has been defined since 2.6.10 kernel and causes
 * a name conflict. Undefine it here since we do not use the kernel mutex.
 */
#ifdef mutex_init
#undef mutex_init
#endif
static inline void mutex_init(kmutex_t *lock, char *name, kmutex_type_t type,
    void *inter)
{
	/*
	 * Determine whether the lock should be used in the interrupt context.
	 * inter is not NULL if it can be called from an interrupt context.
	 * See ddi_get_iblock_cookie() and ddi_get_soft_iblock_cookie().
	 */
	lock->interrupt = inter ? 1 : 0;
	spin_lock_init(&lock->lock);
	lock->locked = 0;
}

static inline void mutex_enter(kmutex_t *lock)
{
	/*
	 * The driver sometimes uses mutex in the interrupt context
	 * without saying so in mutex_init. Using
	 * spin_lock in interrupt context causes panic on Linux.
	 * Thus we always save IRQ on Linux.
	 */
	spin_lock_irqsave(&lock->lock, lock->flag);
	lock->locked = 1;
}

static inline void mutex_exit(kmutex_t *lock)
{
	spin_unlock_irqrestore(&lock->lock, lock->flag);
	lock->locked = 0;
}

/*
 * mutex_destroy macro has been defined since 2.6.10 kernel and causes
 * a name conflict. Undefine it here since we do not use the kernel mutex.
 */
#ifdef mutex_destroy
#undef mutex_destroy
#endif
/* Does not need to be destroyed on Linux */
#define	mutex_destroy(lock)			\
	{					\
		if ((lock)->locked)		\
			mutex_exit(lock);	\
	}

/* Used only in ASSERT */
#define	mutex_owned(mp)			1

/*
 * Linux kernel does not have these.
 */
#define	bzero(s, n)			memset(s, 0, n)
#define	bcopy(s1, s2, n)		memcpy(s2, s1, n)
#define	bcmp(s1, s2, n)			memcmp(s1, s2, (__kernel_size_t)n)

/*
 * Use wait queues in place of conditional variables.
 * wait_event is the recommended method to use on Linux. It has a boolean
 * variable as an argument. The variable must be FALSE in order for
 * wait_event to starting waiting and it must be TRUE in order to be
 * waken up. We need to keep this boolean variable in kcondvar structure.
 */
typedef struct kcondvar {
	wait_queue_head_t		wqh;
	atomic_t			condition;
} kcondvar_t;

typedef int				kcv_type_t;

static inline void cv_init(kcondvar_t *cvp, char *name, kcv_type_t type,
    void *arg)
{
	init_waitqueue_head(&cvp->wqh);
	atomic_set(&cvp->condition, 0);
}

/* Not need for wait queue on Linux */
static inline void cv_destroy(kcondvar_t *cvp)
{
}

static inline void cv_wait(kcondvar_t *cvp, kmutex_t *mp)
{
	unsigned long flags;
	wait_queue_t wait;

	mutex_exit(mp);

	/*
	 * This is the inline of sleep_on() kernel function on Linux. Although
	 * it has been deprecated on Linux, Solaris is using exactly the same
	 * thing.
	 */
	init_waitqueue_entry(&wait, current);

	current->state = TASK_UNINTERRUPTIBLE;

	spin_lock_irqsave(&cvp->wqh.lock, flags);
	__add_wait_queue(&cvp->wqh, &wait);
	spin_unlock(&cvp->wqh.lock);

	schedule();

	spin_lock_irq(&cvp->wqh.lock);
	__remove_wait_queue(&cvp->wqh, &wait);
	spin_unlock_irqrestore(&cvp->wqh.lock, flags);

	/* Inline end */

	mutex_enter(mp);
}

static inline void cv_signal(kcondvar_t *cvp)
{
	atomic_set(&cvp->condition, 1);
	wake_up(&cvp->wqh);
}

static inline void cv_broadcast(kcondvar_t *cvp)
{
	atomic_set(&cvp->condition, 1);
	wake_up(&cvp->wqh);
}

/* Similar to wait_event_interruptible */
static inline int cv_wait_sig(kcondvar_t *cvp, kmutex_t *mp)
{
	int rv;

	atomic_set(&cvp->condition, 0);
	mutex_exit(mp);
	rv = wait_event_interruptible(cvp->wqh, atomic_read(&cvp->condition));
	mutex_enter(mp);

	return (rv == -ERESTARTSYS ? 0 : 1);
}

/*
 * On Solaris, timeout is ticks from the last boot.
 * On Linux, timeout is a time interval starting from now.
 */
static inline clock_t cv_timedwait(kcondvar_t *cvp, kmutex_t *mp,
    clock_t timeout)
{
	int rv;
	clock_t dt = timeout - jiffies;

	if (dt <= 0)
		return (-1);

	atomic_set(&cvp->condition, 0);
	mutex_exit(mp);
	/*
	 * SUSE 9/2.6.5 kernel does not have this function.
	 * rv = wait_event_timeout(*cvp, 1, timeout);
	 */
	rv = wait_event_interruptible_timeout(cvp->wqh,
	    atomic_read(&cvp->condition), dt);
	mutex_enter(mp);

	/*
	 * On Linux: 0 -- timed out, non-zero -- interrupted.
	 * On Solaris: -1 -- timed out, > 0 -- interrupted.
	 */
	return (rv == 0 ? -1 : rv);
}

/*
 * On Solaris, timeout is ticks from the last boot.
 * On Linux, timeout is a time interval starting from now.
 */
static inline clock_t cv_timedwait_sig(kcondvar_t *cvp, kmutex_t *mp,
    clock_t timeout)
{
	int rv;
	clock_t dt = timeout - jiffies;

	if (dt <= 0)
		return (-1);

	atomic_set(&cvp->condition, 0);
	mutex_exit(mp);
	rv = wait_event_interruptible_timeout(cvp->wqh,
	    atomic_read(&cvp->condition), dt);
	mutex_enter(mp);

	return (rv);
}

/*
 * Memory management functions.
 * There are more flags. But these two are the only ones used currently.
 */
#define	KM_SLEEP			GFP_KERNEL
#define	KM_NOSLEEP			GFP_ATOMIC
#define	MAX_MEM_KMALLOC			131072		/* 128K */

static inline void *kmem_alloc(size_t size, int flag)
{
	if (size <= MAX_MEM_KMALLOC) {
		/* The max size of kmalloc is 128K */
		return (kmalloc(size, flag));
	} else {
		/*
		 * The max order is 9 according to the Linux Device Drivers
		 * book. Order 10 may also work on some architectures.
		 * Since PAGE_SIZE = 4096, the max memory allocation is 4M.
		 */
		unsigned long order = 0;
		unsigned long npages0;
		unsigned long npages = size / PAGE_SIZE;

		if (size % PAGE_SIZE)
			npages++;

		npages0 = npages;
		while ((npages = npages >> 1) > 0)
			order++;

		if (npages0 > (0x1 << order))
			order++;

		if (order > 10) {
			SCA_ERR_PRINT("kmem_alloc: size %d is too large\n",
			    (int)size);
			return (NULL);
		}

		return ((void*)__get_dma_pages(flag, order));
	}
}

static inline void kmem_free(void *buf, size_t size)
{
	if (size <= MAX_MEM_KMALLOC) {
		return (kfree(buf));
	} else {
		unsigned long order = 0;
		unsigned long npages0;
		unsigned long npages = size / PAGE_SIZE;

		if (size % PAGE_SIZE)
			npages++;

		npages0 = npages;
		while ((npages = npages >> 1) > 0)
			order++;

		if (npages0 > (0x1 << order))
			order++;

		if (order > 10) {
			SCA_ERR_PRINT("kmem_free: size %d is too large\n",
			    (int)size);
			return;
		}

		return (free_pages((unsigned long)buf, order));
	}
}

static inline void *kmem_zalloc(size_t size, int flag)
{
	void *ptr = kmem_alloc(size, flag);
	if (ptr == NULL)
		return (NULL);
	memset(ptr, 0, size);
	return (ptr);
}

#define	CRYPTO_MAX_ATTRIBUTE_COUNT	128


typedef void				*crypto_context_t;
typedef void				*crypto_ctx_template_t;
typedef struct iovec			iovec_t;
typedef long long			offset_t;
typedef offset_t			lloff_t;
typedef unsigned int			uint_t;
typedef unsigned char			uchar_t;
typedef unsigned short			ushort_t;
typedef unsigned long			ulong_t;
typedef unsigned long long		u_longlong_t;
typedef enum { B_FALSE, B_TRUE }	boolean_t;
typedef int				minor_t;
typedef int				major_t;
typedef void				*ddi_idevice_cookie_t;
typedef int				ddi_softintr_t;
typedef unsigned long			uintptr_t;
typedef short				pri_t;
typedef void				(task_func_t)(void *);
typedef void				*timeout_id_t;
typedef	int				ddi_info_cmd_t;
typedef int				cred_t;
typedef long				intptr_t;
typedef	uint32_t			caddr32_t;

/*
 * uio and mblk data structures are for compilation
 */

/* Segment flag values. */
typedef enum uio_seg { UIO_USERSPACE, UIO_SYSSPACE, UIO_USERISPACE } uio_seg_t;

typedef struct uio {
	iovec_t		*uio_iov;	/* pointer to array of iovecs */
	int		uio_iovcnt;	/* number of iovecs */
	lloff_t		_uio_offset;	/* file offset */
	uio_seg_t	uio_segflg;	/* address space (kernel or user) */
	short		uio_fmode;	/* file mode flags */
	lloff_t		_uio_limit;	/* u-limit (maximum byte offset) */
	ssize_t		uio_resid;	/* residual count */
} uio_t;

/* Message block descriptor */
typedef struct  msgb {
	struct  msgb    *b_next;
	struct  msgb    *b_prev;
	struct  msgb    *b_cont;
	unsigned char   *b_rptr;
	unsigned char   *b_wptr;
	/* struct datab    *b_datap; */
	unsigned char   b_band;
	unsigned char   b_ftflag;	/* flow trace flag */
	unsigned short  b_flag;
	/* queue_t	 *b_queue; */	/* for sync queues */
} mblk_t;

#define	MBLKL(mp)	((mp)->b_wptr - (mp)->b_rptr)

#define	uio_loffset	_uio_offset._f
#define	uio_offset	_uio_offset._p._l

#define	uio_llimit	_uio_limit._f
#define	uio_limit	_uio_limit._p._l


/*
 * SCA and MCA names
 */
#define	SCA_DRIVER_TEXT_NAME	"sca"
#define	MCA_DRIVER_TEXT_NAME	"mca"

/*
 * Device info data structure. One for each instance (card).
 */
typedef struct dev_info
{
	/* PCI device structure used by the Linux kernel */
	struct pci_dev	*device;
	char		name[MAXNAMELEN];

	/* Start, end, and size of the memory mapped registers */
	unsigned long	register_memory_start;
	unsigned long	register_memory_end;
	unsigned int	register_memory_size;

	/* Virtual address of memory mapped registers */
	unsigned char	*virtual_register_memory;

	/* IRQ assigned to this device */
	unsigned char	irq;

	/* Interrupt pending register for this device */
	uint32_t	int_pending_reg;

	/* The device instance number */
	int		instance;

	/* The master data structure of this device instance */
	void		*private;
} dev_info_t;


/* sca scatter-gather list - includes dma addr info */
typedef struct sca_sglist {
	void		*page;
	int		length;
	dma_addr_t	dma_addr;
} sca_sglist_t;

/*
 * Save enough info in our handle data structure. It is used to carry
 * information from one function to another.
 * Note that both ddi_dma_handle_t and ddi_acc_handle_t point to this.
 */
typedef struct sca_ddi_handle {
	int		type;
	int		direction;
	struct pci_dev	*pdev;
	size_t		size;
	void		*cpu_addr;
	dma_addr_t	bus_addr;
	dev_info_t	*dip;

	int		index;
	int		n_pages;
	int		n_dma_pages;
	sca_sglist_t 	*sglist;
} sca_ddi_handle_t;

typedef struct sca_ddi_handle *ddi_dma_handle_t;
typedef struct sca_ddi_handle *ddi_acc_handle_t;

typedef struct {
	uint32_t	dmac_address;	/* 32 bit DMA address */
	size_t		dmac_size;	/* DMA cookie size */
	uint_t		dmac_type;	/* bus specific type bits */
} ddi_dma_cookie_t;

typedef unsigned long	ddi_iblock_cookie_t;
typedef	struct as	as_t;

/*
 * For compilation
 */
typedef enum {
	DDI_ATTACH = 0,
	DDI_RESUME = 1,
	DDI_PM_RESUME = 2
} ddi_attach_cmd_t;

typedef enum {
	DDI_DETACH = 0,
	DDI_SUSPEND = 1,
	DDI_PM_SUSPEND = 2,
	DDI_HOTPLUG_DETACH = 3
} ddi_detach_cmd_t;

/* The attr stuff for compilation */
typedef struct ddi_device_acc_attr {
	ushort_t devacc_attr_version;
	uchar_t devacc_attr_endian_flags;
	uchar_t devacc_attr_dataorder;
	uchar_t devacc_attr_access;
} ddi_device_acc_attr_t;

#define	DMA_ATTR_V0		0
#define	DMA_ATTR_VERSION	DMA_ATTR_V0

typedef struct ddi_dma_attr {
	uint_t		dma_attr_version;
	uint64_t	dma_attr_addr_lo;
	uint64_t	dma_attr_addr_hi;
	uint64_t	dma_attr_count_max;
	uint64_t	dma_attr_align;
	uint_t		dma_attr_burstsizes;
	uint32_t	dma_attr_minxfer;
	uint64_t	dma_attr_maxxfer;
	uint64_t	dma_attr_seg;
	int		dma_attr_sgllen;
	uint32_t	dma_attr_granular;
	uint_t		dma_attr_flags;
} ddi_dma_attr_t;

#define	DDI_DEVICE_ATTR_V0	0x0001
#define	DDI_DEVICE_ATTR_V1	0x0002

#define	DDI_NEVERSWAP_ACC	0x00
#define	DDI_STRUCTURE_LE_ACC	0x01
#define	DDI_STRUCTURE_BE_ACC	0x02

#define	DDI_STRICTORDER_ACC	0x00
#define	DDI_UNORDERED_OK_ACC	0x01
#define	DDI_MERGING_OK_ACC	0x02
#define	DDI_LOADCACHING_OK_ACC	0x03
#define	DDI_STORECACHING_OK_ACC	0x04

#define	DDI_DATA_SZ01_ACC	1
#define	DDI_DATA_SZ02_ACC	2
#define	DDI_DATA_SZ04_ACC	4
#define	DDI_DATA_SZ08_ACC	8


#define	DDI_DMA_CONSISTENT	0x0010
#define	DDI_DMA_EXCLUSIVE	0x0020
#define	DDI_DMA_STREAMING	0x0040
#define	DDI_DMA_RELAXED_ORDERING	0x0400
#define	DDI_DMA_SBUS_64BIT	0x2000

#define	DDI_DMA_SYNC_FORDEV	0x0
#define	DDI_DMA_SYNC_FORCPU	0x1
#define	DDI_DMA_SYNC_FORKERNEL	0x2

#define	DDI_DEV_T_ANY		0
#define	DDI_DEV_AUTOINCR	0

#define	DDI_PROP_CANSLEEP	0
#define	DDI_PROP_DONTPASS	0

#define	CV_DRIVER		0
#define	DDI_SOFTINT_MED		0

#define	DDI_PSEUDO		"ddi_pseudo"
#define	DDI_NOSLEEP		1

/*
 * Error logging mapping
 */
#define	CE_CONT			0
#define	CE_NOTE			1
#define	CE_WARN			2
#define	CE_PANIC		3

/* Ignore the level for now */
#define	cmn_err(level, fmt, args...)	printk(fmt, ## args); printk("\n");
#define	vcmn_err(level, fmt, ap) {					\
	char printk_buf[1024];						\
	memset(printk_buf, 0, 1024);					\
	vscnprintf(printk_buf, sizeof (printk_buf), fmt, ap);		\
	printk("%s\n", printk_buf);					\
}

/*
 * To fix compilation problems
 */
#define	TASKQ_PREPOPULATE	0x0001
#define	TASKQ_CPR_SAFE		0x0002
#define	TASKQ_DYNAMIC		0x0004
#define	TASKQ_DEFAULTPRI	-1

#define	TQ_SLEEP		0x00
#define	TQ_NOSLEEP		0x01
#define	TQ_NOQUEUE		0x02

#define	DDI_DMA_DONTWAIT	((int (*)())0)
#define	DDI_DMA_SLEEP		((int (*)())1)

#define	DDI_DMA_WRITE		0x0001
#define	DDI_DMA_READ		0x0002
#define	DDI_DMA_RDWR		0x0004

#define	DDI_DMA_MAPPED		0
#define	DDI_DMA_MAPOK		0
#define	DDI_DMA_PARTIAL_MAP	1
#define	DDI_DMA_DONE		2

#define	DDI_INTR_CLAIMED	1
#define	DDI_INTR_UNCLAIMED	0

/*
 * Standard PCI constants. The corresponding Linux names are in comments.
 */
#define	PCI_CONF_COMM		0x4	/* PCI_COMMAND */

#define	PCI_COMM_MAE		0x0002	/* PCI_COMMAND_MEMORY */
#define	PCI_COMM_ME		0x0004	/* PCI_COMMAND_MASTER */
#define	PCI_COMM_PARITY_DETECT	0x0040	/* PCI_COMMAND_PARITY */
#define	PCI_COMM_SERR_ENABLE	0x0100	/* PCI_COMMAND_SERR */
#define	PCI_COMM_BACK2BACK_ENAB	0x0200	/* PCI_COMMAND_FAST_BACK */
#define	PCI_COMM_INTX_DISABLE	0x400	/* INTx emulation disable */

/*
 * The following functions are used to access the configuration registers
 */
static inline uint8_t pci_config_get8(ddi_acc_handle_t handle, off_t offset)
{
	uint8_t tmp;
	pci_read_config_byte(handle->pdev, offset, &tmp);
	return (tmp);
}

static inline uint16_t pci_config_get16(ddi_acc_handle_t handle, off_t offset)
{
	uint16_t tmp;
	pci_read_config_word(handle->pdev, offset, &tmp);
	return (tmp);
}

static inline uint32_t pci_config_get32(ddi_acc_handle_t handle, off_t offset)
{
	uint32_t tmp;
	pci_read_config_dword(handle->pdev, offset, &tmp);
	return (tmp);
}

static inline uint64_t pci_config_get64(ddi_acc_handle_t handle, off_t offset)
{
	uint32_t tmp0;
	uint32_t tmp1;
	uint64_t tmp = 0;

	/* Assume the host is LE as well */
	pci_read_config_dword(handle->pdev, offset, &tmp0);
	pci_read_config_dword(handle->pdev, offset + 4, &tmp1);

	tmp = tmp1;
	tmp = (tmp << 32) | tmp0;
	return (tmp);
}

static inline void pci_config_put8(ddi_acc_handle_t handle, off_t  offset,
    uint8_t value)
{
	(void) pci_write_config_byte(handle->pdev, offset, value);
}

static inline void pci_config_put16(ddi_acc_handle_t handle, off_t  offset,
    uint16_t value)
{
	(void) pci_write_config_word(handle->pdev, offset, value);
}

static inline void pci_config_put32(ddi_acc_handle_t handle, off_t  offset,
    uint32_t value)
{
	(void) pci_write_config_dword(handle->pdev, offset, value);
}

static inline void pci_config_put64(ddi_acc_handle_t handle, off_t  offset,
    uint64_t value)
{
	uint32_t tmp;
	/* Assume the host is LE as well */
	tmp = value & 0xFFFFFFFF;
	(void) pci_write_config_dword(handle->pdev, offset, tmp);
	tmp = (value >> 32) & 0xFFFFFFFF;
	(void) pci_write_config_dword(handle->pdev, offset + 4, tmp);
}

/*
 * The following functions are used to access device memory and registers
 * Note that the handle is not used in these functions.
 */

static inline uint8_t ddi_get8(ddi_acc_handle_t handle, uint8_t *dev_addr)
{
	return (readb(dev_addr));
}

static inline uint16_t ddi_get16(ddi_acc_handle_t handle, uint16_t *dev_addr)
{
	return (readw(dev_addr));
}

static inline uint32_t ddi_get32(ddi_acc_handle_t handle, uint32_t *dev_addr)
{
	return (readl(dev_addr));
}

#if defined(i386) || defined(__i386)
static inline uint64_t ddi_get64(ddi_acc_handle_t handle, uint64_t *dev_addr)
{
	uint32_t tmp0;
	uint32_t tmp1;
	uint64_t tmp = 0;

	/* Assume the host is LE as well */
	tmp0 = readl(dev_addr);
	tmp1 = readl(dev_addr + 4);

	tmp = tmp1;
	tmp = (tmp << 32) | tmp0;
	return (tmp);
}
#else
static inline uint64_t ddi_get64(ddi_acc_handle_t handle, uint64_t *dev_addr)
{
	return (readq(dev_addr));
}
#endif

static inline void ddi_rep_get8(ddi_acc_handle_t handle, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	memcpy_fromio(host_addr, dev_addr, repcount);
}

static inline void ddi_put8(ddi_acc_handle_t handle, uint8_t *dev_addr,
    uint8_t value)
{
	writeb(value, dev_addr);
}

static inline void ddi_put16(ddi_acc_handle_t handle, uint16_t *dev_addr,
    uint16_t value)
{
	writew(value, dev_addr);
}

static inline void ddi_put32(ddi_acc_handle_t handle, uint32_t *dev_addr,
    uint32_t value)
{
	writel(value, dev_addr);
}

#if defined(i386) || defined(__i386)
static inline void ddi_put64(ddi_acc_handle_t handle, uint64_t *dev_addr,
    uint64_t value)
{
	uint32_t tmp;
	/* Assume the host is LE as well */
	tmp = value & 0xFFFFFFFF;
	writel(tmp, dev_addr);
	tmp = (value >> 32) & 0xFFFFFFFF;
	writel(tmp, dev_addr + 4);
}
#else
static inline void ddi_put64(ddi_acc_handle_t handle, uint64_t *dev_addr,
    uint64_t value)
{
	writeq(value, dev_addr);
}
#endif

/* The instance number is the index of the device */
static inline int ddi_get_instance(dev_info_t *dip)
{
	return (dip->instance);
}

/* The device name is initialized in the init_module function */
static inline const char *ddi_driver_name(dev_info_t *devi)
{
	return (devi->name);
}

/* The private data is the master data structure of the driver */
static inline void ddi_set_driver_private(dev_info_t *dip, caddr_t data)
{
	dip->private = data;
}

static inline caddr_t ddi_get_driver_private(dev_info_t *dip)
{
	return (dip->private);
}

/*
 * The device should be a master. On Linux, we enable it if it is not a
 * master already. This could happen on some hardware.
 */
static inline int ddi_slaveonly(dev_info_t *dip)
{
	unsigned char bus_master_cmd;

	/*
	 * Enable bus mastering for the PCI device if needed. Perform a
	 * read-modify-write to ensure all other command bits are unchanged.
	 */
	pci_read_config_byte(dip->device, PCI_COMMAND, &bus_master_cmd);

	/*
	 * need to check whether PCI_COMMAND_MASTER is right for this (2 or 4)
	 */
	if (!(bus_master_cmd & (1 << PCI_COMMAND_MASTER))) {
		bus_master_cmd |= (1 << PCI_COMMAND_MASTER);
		pci_write_config_byte(dip->device, PCI_COMMAND, bus_master_cmd);
	}

	/* Failure for non-slaveonly location */
	return (DDI_FAILURE);
}

/* Linux does not need such function */
static inline int ddi_intr_hilevel(dev_info_t *dip, uint_t inumber)
{
	/* Return low interrupt (0) */

	return (0);
}

extern int mca_ddi_getprop(char *name);
static inline int ddi_getprop(dev_t dev, dev_info_t *dip, int flags,
    char *name, int defvalue)
{
	int param;

	/*
	 * Parameters can be passed to a module at load time.
	 */
	param = mca_ddi_getprop(name);
	if (param < 0)
		/* Return the default value on error. */
		return (defvalue);
	else
		return (param);
}

/* Use get_random_bytes() for both */
static inline int random_get_bytes(void *buf, size_t size)
{
	/* It is a void function */
	get_random_bytes(buf, size);
	return (0);
}

static inline int random_get_pseudo_bytes(void *buf, size_t size)
{
	/* It is a void function */
	SCA_DBG_PRINT("random_get_pseudo_bytes:\n");
	get_random_bytes(buf, size);
	return (0);
}

/*
 * Converts the given number of pages to the  number
 * of bytes that it corresponds to.
 */
static inline unsigned long ddi_ptob(dev_info_t *dip, unsigned long pages)
{
	return (pages * PAGE_SIZE);
}

static inline int ddi_get_iblock_cookie(dev_info_t *dip, uint_t inumber,
	ddi_iblock_cookie_t *iblock_cookiep)
{
	/*
	 * Just set it as a flag to indicate the mutex is useable in
	 * an interrupt context. The flag is used to init a mutex
	 */
	*iblock_cookiep = 1;
	return (DDI_SUCCESS);
}

static inline int ddi_get_soft_iblock_cookie(dev_info_t *dip, int preference,
	ddi_iblock_cookie_t *iblock_cookiep)
{
	/*
	 * Just set it as a flag to indicate the mutex is useable in
	 * an interrupt context. The flag is used to init a mutex
	 */
	*iblock_cookiep = 1;
	return (DDI_SUCCESS);
}

#define	OTYP_CHR		2
#define	FEXCL			0x0400

#define	STRUCT_DECL(struct_type, handle)	struct struct_type handle
#define	STRUCT_INIT(handle, umodel)
#define	STRUCT_SIZE(handle)			sizeof (handle)
#define	STRUCT_BUF(handle)			(&handle)
#define	STRUCT_FGET(handle, field)		handle.field
#define	STRUCT_FGETP(handle, field)		handle.field
#define	STRUCT_FSET(handle, field, val)		handle.field = (val)

static inline int ddi_copyin(const void *buf, void *driverbuf, size_t  cn,
    int flags)
{
	return (copy_from_user(driverbuf, buf, cn));
}

static inline int ddi_copyout(const void *driverbuf, void *buf, size_t cn,
    int flags)
{
	return (copy_to_user(buf, driverbuf, cn));
}

static inline int ddi_create_minor_node(dev_info_t *dip, char *name, int
    spec_type, minor_t minor_num, char *node_type, int flag)
{
	/* no need to create the minor node */
	return (DDI_SUCCESS);
}

static inline void ddi_remove_minor_node(dev_info_t *dip, char *name)
{
	/* Does nothing */
}

static inline dev_t makedevice(major_t majnum, minor_t minnum)
{
	return ((dev_t)minnum);
}

static inline minor_t getminor(dev_t dev)
{
	return ((minor_t)dev);
}

static inline major_t getmajor(dev_t dev)
{
	return ((major_t)dev);
}

static inline int ddi_add_intr(dev_info_t *dip, uint_t inumber,
    ddi_iblock_cookie_t *iblock_cookiep, ddi_idevice_cookie_t *idevice_cookiep,
    uint_t (*int_handler) (int, char *, struct pt_regs *),
    caddr_t int_handler_arg)
{
	char device_name[32];

	/*
	 * Set the private field here in case it is needed before
	 * ddi_set_driver_private() is called.
	 * We should be ok without setting this, but just in case.
	 */
	dip->private = int_handler_arg;

	/*
	 * Device name suffixed by its instance number (mca0)
	 * This name will appear in /proc/interrupts
	 */
	sprintf(device_name, "%s%d", dip->name, inumber);

	/*
	 * int_handler_arg is the master device data structure (mca).
	 * It is passed in as the dev_id.
	 */
	if (request_irq(dip->device->irq, (void *)int_handler,
	    IRQF_SHARED, MCA_DRIVER_TEXT_NAME, int_handler_arg)) {
		SCA_ERR_PRINT("ddi_add_intr: request_irq failed on: %d\n",
		dip->device->irq);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static inline void ddi_remove_intr(dev_info_t *dip, uint_t inumber,
    ddi_iblock_cookie_t iblock_cookie)
{
	/*
	 * dip->private (mca) is the master device data structure which
	 * is used as the dev_id in request_irq().
	 */
	free_irq(dip->device->irq, dip->private);
}

/*
 * The softintr is used only in FMA support which is not relavent on Linux.
 */
static inline int ddi_add_softintr(dev_info_t *dip, int preference,
    ddi_softintr_t *idp, ddi_iblock_cookie_t *iblock_cookiep,
    ddi_idevice_cookie_t *idevice_cookiep,
    uint_t(*int_handler) (caddr_t int_handler_arg), caddr_t int_handler_arg)
{
	return (DDI_SUCCESS);
}

static inline void ddi_remove_softintr(ddi_softintr_t id)
{
}

static inline void ddi_report_dev(dev_info_t *dip)
{
/*
 * ddi_report_dev() prints a banner at boot  time,   announcing
 * the device pointed to by dip. The banner is always placed in
 * the system logfile (displayed by  dmesg(1M)),  but  is  only
 * displayed  on  the console if the system was booted with the
 * verbose (-v) argument.
 */
}

/*
 * kstat maps to the /proc fs. Only keep the ones we need.
 */
#define	KSTAT_STRLEN		31

#define	KSTAT_TYPE_NAMED	1
#define	KSTAT_TYPE_INTR		2

/* Just for compilation */
#define	KSTAT_DATA_CHAR		0
#define	KSTAT_DATA_ULONG	8
#define	KSTAT_DATA_ULONGLONG	9

typedef struct kstat_named {
	char	name[KSTAT_STRLEN];	/* name of counter */
} kstat_named_t;

typedef struct kstat_ {
	char	ks_module[KSTAT_STRLEN];	/* provider module name */
	int	ks_instance;			/* provider module's instance */
	char	ks_name[KSTAT_STRLEN];		/* kstat name */
	char	ks_class[KSTAT_STRLEN];		/* kstat class */
	uchar_t	ks_type;			/* kstat data type */
	uchar_t	ks_flags;			/* kstat flags */
	void	*ks_data;			/* kstat type-specific data */
	int	ndata;
	int	(*ks_update)(char *, char **, off_t, int, int *, void *);
	void	*ks_private;		/* arbitrary provider-private data */
} kstat_t;

static inline kstat_t *kstat_create(char *module, int instance, char *name,
    char *class, uchar_t type, ulong_t ndata, uchar_t ks_flag)
{
	kstat_t *ks;

	if ((ks = kmem_alloc(sizeof (kstat_t), GFP_KERNEL)) == NULL)
		return (NULL);
	memset(ks, 0, sizeof (kstat_t));

	if (module) {
		if (strlen(module) < KSTAT_STRLEN) {
			strcpy(ks->ks_module, module);
		} else {
			strncpy(ks->ks_module, module, KSTAT_STRLEN-1);
		}
	}

	ks->ks_type = type;
	ks->ks_instance = instance;

	if (name) {
		if (strlen(name) < KSTAT_STRLEN) {
			strcpy(ks->ks_name, name);
		} else {
			strncpy(ks->ks_name, name, KSTAT_STRLEN-1);
		}
	}

	if (ks->ks_type == KSTAT_TYPE_NAMED) {
		ks->ks_data = kmem_alloc(ndata * sizeof (kstat_named_t),
		    GFP_KERNEL);
		ks->ndata = ndata;
		if (ks->ks_data == NULL) {
			kmem_free(ks, sizeof (kstat_t));
			return (NULL);
		}
	}

	return (ks);
}

static inline void kstat_delete(kstat_t *ksp)
{
	char dir[64];

	/* Only have named stats on Linux */
	if (ksp->ks_type == KSTAT_TYPE_NAMED) {
		kmem_free(ksp->ks_data, ksp->ndata * sizeof (kstat_named_t));
		sprintf(dir, "driver/%s%d", MCA_DRIVER_TEXT_NAME,
		    ksp->ks_instance);
		remove_proc_entry(dir, NULL);
	}

	kmem_free(ksp, sizeof (kstat_t));
}

static inline void  kstat_named_init(kstat_named_t   *knp,   char   *name,
    uchar_t data_type)
{
	/* Only need the name here */
	if (strlen(name) < KSTAT_STRLEN) {
		strcpy(knp->name, name);
	} else {
		strncpy(knp->name, name, KSTAT_STRLEN-1);
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
static int kstat_show(struct seq_file *seq, void *v) {
	kstat_t *ksp = (kstat_t*)v;
	char buffer[2048];
	char *start = buffer;
	int eof = 0;
	ksp->ks_update(buffer, &start, 0, 2048, &eof, ksp->ks_private);
	seq_puts(seq, start);
	return 0;

}
static int kstat_open(struct inode *inode, struct file *file)
{
	#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		kstat_t *ksp = (kstat_t*)PDE(inode)->data;
	#endif
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		kstat_t *ksp = PDE_DATA(inode);
	#endif
	return single_open(file, kstat_show, ksp);
}
static struct file_operations kstat_fops = {
	.open		= kstat_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif
static inline void kstat_install(kstat_t *ksp)
{
	char dir[64];

	/* Only have named stats on Linux */
	if (ksp->ks_type == KSTAT_TYPE_NAMED) {
		sprintf(dir, "driver/%s%d", MCA_DRIVER_TEXT_NAME,
		    ksp->ks_instance);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		create_proc_read_entry(dir, 0, NULL, ksp->ks_update,
		    ksp->ks_private);
#else
		proc_create_data(dir, 0, NULL, &kstat_fops, ksp);
#endif
	}
}

static inline int ddi_dma_alloc_handle(dev_info_t *dip, ddi_dma_attr_t *attr,
    int (*callback) (caddr_t param), caddr_t arg, ddi_dma_handle_t *handlep)
{
	sca_ddi_handle_t *handle;

	if (!(handle = kmem_alloc(sizeof (sca_ddi_handle_t), GFP_ATOMIC))) {
		return (DDI_FAILURE);
	}
	memset(handle, 0, sizeof (sca_ddi_handle_t));

	/*
	 * Use ddi_dma_handle_t to store pci_dev object
	 * Note that "typedef struct sca_ddi_handle *ddi_dma_handle_t"
	 */
	handle->pdev = dip->device;
	*handlep = handle;

	return (DDI_SUCCESS);
}

static inline void ddi_dma_free_handle(ddi_dma_handle_t *handle)
{
	kmem_free(*handle, sizeof (**handle));
}

/*
 * handle -- struct pci_dev *
 * length -- size
 * flags  -- DDI_DMA_CONSISTENT or DDI_DMA_STREAMING
 * kaddrp -- kernel address
 * handlep-- store bus_addr and other information
 */
static inline int ddi_dma_mem_alloc(ddi_dma_handle_t handle, size_t length,
    ddi_device_acc_attr_t *accattrp, uint_t flags, int (*waitfp) (caddr_t),
    caddr_t arg,  caddr_t  *kaddrp,  size_t *real_length,
    ddi_acc_handle_t *handlep)
{
	dma_addr_t bus_addr;
	sca_ddi_handle_t *acc_handle;
	sca_ddi_handle_t *dma_handle = handle;
	int gfp_flag = (waitfp == DDI_DMA_DONTWAIT) ? GFP_ATOMIC : GFP_KERNEL;

	if ((acc_handle = (sca_ddi_handle_t *)
	    kmem_alloc(sizeof (sca_ddi_handle_t), gfp_flag)) == NULL) {
		return (DDI_FAILURE);
	}
	memset(acc_handle, 0, sizeof (sca_ddi_handle_t));
	dma_handle->sglist = NULL;
	dma_handle->bus_addr = 0;
	dma_handle->cpu_addr = NULL;

	if (flags & DDI_DMA_CONSISTENT) {
		/* The max memory in this case is 128 KB */
		if (length > MAX_MEM_KMALLOC) {
			kmem_free(acc_handle, sizeof (*acc_handle));
			return (DDI_FAILURE);
		}

		/*
		 * void *dma_alloc_coherent(struct device *dev, size_t size,
		 * dma_addr_t *dma_handle, unsigned gfp);
		 * Cannot use GFP_ATOMIC here since it may fail when the RAM
		 * is used by file/disk cache. The cached RAM is available
		 * when GFP_KERNEL is used.
		 */
		*kaddrp = dma_alloc_coherent(&(dma_handle->pdev->dev), length,
		    &bus_addr, gfp_flag);
		if (*kaddrp == NULL) {
			kmem_free(acc_handle, sizeof (*acc_handle));
			return (DDI_FAILURE);
		}

		/*
		 * The mapping is done here. Nothing needs to be done in
		 * ddi_dma_addr_bind_handle().
		 */
		dma_handle->bus_addr = bus_addr;
	} else {
		/*
		 * Allocate memory here. Max is up to 4 MB.
		 * Use GFP_KERNEL to be consistent with above.
		 */
		/*
		 * On some SMP systems, it fails to allocate 2 MB and triggers
		 * some kernel debug messages. To avoid that we limit the max
		 * allocation here to 1 MB. Make a scatter-gather list for
		 * memory size larger than 1 MB. This is used for firmware
		 * upgrade.
		 */
		*kaddrp = NULL;
		if (length <= 1024*1024)
			*kaddrp = kmem_alloc(length, gfp_flag);

		/*
		 * If kmalloc fails, we have to make a scatter-gather list.
		 * We allocate 64K chunks until enough to hold all data.
		 * Note that vmalloc does not work since it allocates memory
		 * in high address space. It would be easier if we could use
		 * vmalloc. It does work on some hardware.
		 */
		if (*kaddrp == NULL) {
			int i;
			int n_bytes = length;

			dma_handle->n_pages = n_bytes / SIXTY_FOUR_K;
			if (n_bytes % SIXTY_FOUR_K)
				dma_handle->n_pages++;
			dma_handle->n_dma_pages = dma_handle->n_pages;

			/* allocate scatter/gather list */
			dma_handle->sglist = kmem_alloc(dma_handle->n_pages *
			    sizeof (sca_sglist_t), GFP_KERNEL);
			if (!dma_handle->sglist) {
				kmem_free(acc_handle, sizeof (*acc_handle));
				return (DDI_FAILURE);
			}
			memset(dma_handle->sglist, 0, dma_handle->n_pages *
			    sizeof (sca_sglist_t));

			/* Allocate chunks */
			for (i = 0; i < dma_handle->n_pages; i++) {
				int c_length = SIXTY_FOUR_K;
				if (c_length > n_bytes)
					c_length = n_bytes;
				dma_handle->sglist[i].length = c_length;
				dma_handle->sglist[i].page =
				    kmem_alloc(c_length, GFP_KERNEL);
				if (dma_handle->sglist[i].page == NULL) {
					int j;
					for (j = 0; j < i; j++) {
						kmem_free(
						    dma_handle->sglist[j].page,
						    dma_handle->sglist[j].
						    length);
					}
					kmem_free(dma_handle->sglist,
					    dma_handle->n_pages *
					    sizeof (sca_sglist_t));
					dma_handle->sglist = NULL;
					kmem_free(acc_handle,
					    sizeof (*acc_handle));
					return (DDI_FAILURE);
				}

				n_bytes -= c_length;
			}
			*kaddrp = (void *)dma_handle->sglist[0].page;
		}

		/* The mapping will be done in ddi_dma_addr_bind_handle() */
		dma_handle->bus_addr = 0;
		dma_handle->direction = DMA_BIDIRECTIONAL;
	}

	/* Save information for later use */
	dma_handle->type = flags;
	dma_handle->size = length;
	dma_handle->cpu_addr = *kaddrp;
	memcpy(acc_handle, dma_handle, sizeof (sca_ddi_handle_t));

	/* Return data */
	*handlep = acc_handle;
	*real_length = length;

	return (DDI_SUCCESS);
}

static inline void ddi_dma_mem_free(ddi_acc_handle_t *handlep)
{
	sca_ddi_handle_t *acc_handle = *handlep;
	if (acc_handle->type & DDI_DMA_CONSISTENT) {
		dma_free_coherent(&(acc_handle->pdev->dev), acc_handle->size,
		    acc_handle->cpu_addr, acc_handle->bus_addr);
	} else {
		if (acc_handle->sglist) {
			int i;
			for (i = 0; i < acc_handle->n_pages; i++)
				kmem_free(acc_handle->sglist[i].page,
				    acc_handle->sglist[i].length);

			kmem_free(acc_handle->sglist, acc_handle->n_pages *
			    sizeof (sca_sglist_t));
			acc_handle->sglist = NULL;
		} else {
			/*
			 * Unmap the buffer is done in ddi_dma_unbind_handle().
			 * Only needs to free the buffer here.
			 */
			kmem_free(acc_handle->cpu_addr, acc_handle->size);
		}
	}

	/* Free the access handle here too */
	kmem_free(*handlep, sizeof (**handlep));
}

static inline int ddi_dma_addr_bind_handle(ddi_dma_handle_t handle,
    as_t *asp, caddr_t addr, size_t len, uint_t flags,
    int (*callback) (caddr_t), caddr_t arg, ddi_dma_cookie_t *cookiep,
    uint_t *ccountp)
{

	/* set the direction based on DDI DMA flags */
	if (flags & DDI_DMA_WRITE) {
		handle->direction = DMA_TO_DEVICE;
	} else if (flags & DDI_DMA_READ) {
		handle->direction = DMA_FROM_DEVICE;
	} else {
		/* assume its DDI_DMA_RDWR */
		handle->direction = DMA_BIDIRECTIONAL;
	}

	/*
	 * If a buffer is not allocated using ddi_dma_mem_alloc(),
	 * the handle->type field will be 0 and fall into default.
	 * Note that the handle->type field should not be changed here.
	 */
	if (handle->type & DDI_DMA_CONSISTENT) {
		/* The mapping is already done in ddi_dma_mem_alloc() */
		/*
		 * kmalloc ensures contiguous memory pages.
		 * Thus we are safe to use one cookie.
		 */
		cookiep->dmac_address = handle->bus_addr;
		cookiep->dmac_size = handle->size;
		cookiep->dmac_type = 0;

		*ccountp = 1;
	} else {
		if (handle->sglist) {
			int	i;
			for (i = 0; i < handle->n_pages; i++) {
				handle->sglist[i].dma_addr =
				    dma_map_single(&(handle->pdev->dev),
				    handle->sglist[i].page,
				    handle->sglist[i].length,
				    handle->direction);
				if (dma_mapping_error(&(handle->pdev->dev), 
				    handle->sglist[i].dma_addr)) {
					return (DDI_FAILURE);
				}
			}
			/* only set cookie for 1st page */
			cookiep->dmac_address =
			    handle->sglist[0].dma_addr;
			cookiep->dmac_size = handle->sglist[0].length;
			cookiep->dmac_type = 0;
			handle->index = 0;
			*ccountp = handle->n_dma_pages;
		} else {
			/*
			 * The memory is allocated either in
			 * ddi_dma_mem_alloc() or
			 * in other user functions using kmalloc().
			 * In either case, a mapping needs to be done here.
			 *
			 * dma_addr_t dma_map_single(struct device *hwdev,
			 * void *ptr, size_t size, int direction);
			 */
			handle->bus_addr =
			    dma_map_single(&(handle->pdev->dev), addr,
			    len, handle->direction);

			if (dma_mapping_error(&(handle->pdev->dev), handle->bus_addr)) {
				return (DDI_FAILURE);
			}

			/* Save information for later use */
			handle->size = len;
			handle->cpu_addr = addr;

			/*
			 * kmalloc ensures contiguous memory pages.
			 * Thus we are safe to use one cookie.
			 */
			cookiep->dmac_address = handle->bus_addr;
			cookiep->dmac_size = handle->size;
			cookiep->dmac_type = 0;

			*ccountp = 1;
		}
	}

	return (DDI_DMA_MAPPED);
}

static inline int ddi_dma_unbind_handle(ddi_dma_handle_t handle)
{
	if (handle->type & DDI_DMA_CONSISTENT) {
		/* Unmapping and free are both done in ddi_dma_mem_free() */
	} else {
		if (handle->sglist == NULL) {
			/*
			 * Only unmap the buffer here.
			 * The memory will be freed in either ddi_dma_mem_free()
			 * or in user functions using kfree().
			 */
			if (dma_mapping_error(&(handle->pdev->dev), handle->bus_addr) == 0) {
				dma_unmap_single(&(handle->pdev->dev),
				    handle->bus_addr,
				    handle->size, handle->direction);
			}
		} else {
			int	i;
			for (i = 0; i < handle->n_pages; i++) {
				if (dma_mapping_error(&(handle->pdev->dev), 
				    handle->sglist[i].dma_addr) == 0) {
					dma_unmap_single(&(handle->pdev->dev),
					    handle->sglist[i].dma_addr,
					    handle->sglist[i].length,
					    handle->direction);
				}
			}
		}
	}

	handle->bus_addr = 0;
	handle->direction = 0;
	handle->type = 0;
	handle->size = 0;
	handle->cpu_addr = 0;

	return (DDI_SUCCESS);
}

static inline void ddi_dma_nextcookie(ddi_dma_handle_t handle,
    ddi_dma_cookie_t *cookiep)
{
	/* pre-increment to get the next cookie */
	if (++handle->index >= handle->n_dma_pages)
		return;

	cookiep->dmac_address =
	    (unsigned long)(handle->sglist[handle->index].dma_addr);
	cookiep->dmac_size = handle->sglist[handle->index].length;
	cookiep->dmac_type = 0;
}

static inline int ddi_dma_sync(ddi_dma_handle_t handle, off_t offset,
    size_t length, uint_t type)
{
	int i, size, rem = length;

	switch (type) {
	case DDI_DMA_SYNC_FORDEV:
		if (handle->sglist == NULL) {
			dma_sync_single_for_device(&(handle->pdev->dev),
			    handle->bus_addr, handle->size, handle->direction);
		} else if (length == 0) {
			for (i = 0; i < handle->n_pages; i++) {
				size = handle->sglist[i].length;
				dma_sync_single_for_device(&(handle->pdev->dev),
				    (unsigned long)handle->sglist[i].dma_addr,
				    size, handle->direction);
			}
		} else {
			for (i = 0; i < handle->n_pages; i++) {
				size = handle->sglist[i].length;
				if (size > rem)
					size = rem;
				if (size <= 0)
					break;
				dma_sync_single_for_device(&(handle->pdev->dev),
				    (unsigned long)handle->sglist[i].dma_addr,
				    size, handle->direction);
				rem -= size;
			}
		}
		break;
	case DDI_DMA_SYNC_FORKERNEL:
		if (handle->sglist == NULL) {
			dma_sync_single_for_cpu(&(handle->pdev->dev),
			    handle->bus_addr, handle->size, handle->direction);
		} else if (length == 0) {
			for (i = 0; i < handle->n_pages; i++) {
				size = handle->sglist[i].length;
				dma_sync_single_for_cpu(&(handle->pdev->dev),
				    (unsigned long)handle->sglist[i].page, size,
				    handle->direction);
			}
		} else {
			for (i = 0; i < handle->n_pages; i++) {
				size = handle->sglist[i].length;
				if (size > rem)
					size = rem;
				if (size <= 0)
					break;
				dma_sync_single_for_cpu(&(handle->pdev->dev),
				    (unsigned long)handle->sglist[i].page, size,
				    handle->direction);
				rem -= size;
			}
		}
		break;
	default:
		/* Should never get here */
		SCA_ERR_PRINT("ddi_dma_sync: unknown direction: %d\n", type);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

#define	BAR0		0
#define	BAR1		1

static inline int pci_config_setup(dev_info_t *dip, ddi_acc_handle_t *handlep)
{
	sca_ddi_handle_t *acc_handle;

	/*
	 * This handle is needed in pci_config_teardown() and
	 * pci_config_put/get functions.
	 */
	if ((acc_handle = (sca_ddi_handle_t *)
	    kmem_alloc(sizeof (sca_ddi_handle_t), GFP_ATOMIC)) == NULL)
		return (DDI_FAILURE);

	/* Get info on BAR0 -- the register memory segment */
	dip->register_memory_start = pci_resource_start(dip->device, BAR0);
	dip->register_memory_end = pci_resource_end(dip->device, BAR0);
	dip->register_memory_size =
	    dip->register_memory_end - dip->register_memory_start + 1;

	/* Verify memory resources are available */
	if (check_mem_region(dip->register_memory_start,
	    dip->register_memory_size)) {
		SCA_WRN_PRINT("Device %d: pci register memory is in use\n",
		    dip->instance);
		return (DDI_FAILURE);
	}

	/* Request memory resources */
	request_mem_region(dip->register_memory_start,
	    dip->register_memory_size, SCA_DRIVER_TEXT_NAME);

	/* Remap the register and DDR memory */
	dip->virtual_register_memory =
	    (unsigned char *)ioremap_nocache(dip->register_memory_start,
	    dip->register_memory_size);

	if (dip->virtual_register_memory == NULL) {
		SCA_ERR_PRINT("Device %d: can't get virtual "
		    "address for register memory.\n", dip->instance);
		goto error_out;
	}

	/* Save a reference to the device info structure */
	acc_handle->dip = dip;
	acc_handle->pdev = dip->device;

	/* Return the handle to the calling function */
	*handlep = acc_handle;

	return (DDI_SUCCESS);

error_out:

	/* Unmap and release the pci register memory */
	if (check_mem_region(dip->register_memory_start,
	    dip->register_memory_size)) {
		SCA_DBG_PRINT("releasing reg mem\n");
		release_mem_region(dip->register_memory_start,
		    dip->register_memory_size);
	}
	if (dip->virtual_register_memory != NULL) {
		SCA_DBG_PRINT("unmapping virtual regs\n");
		iounmap(dip->virtual_register_memory);
		dip->virtual_register_memory = NULL;
	}

	kmem_free(acc_handle, sizeof (*acc_handle));

	return (DDI_FAILURE);
}

static inline void pci_config_teardown(ddi_acc_handle_t *handle)
{
	sca_ddi_handle_t *acc_handle = *handle;
	dev_info_t *dip = acc_handle->dip;

	/* Unmap and release the pci register memory */
	if (check_mem_region(dip->register_memory_start,
	    dip->register_memory_size)) {
		release_mem_region(dip->register_memory_start,
		    dip->register_memory_size);
	}

	if (dip->virtual_register_memory != NULL) {
		iounmap(dip->virtual_register_memory);
		dip->virtual_register_memory = NULL;
	}

	/* Free the handle here too */
	kmem_free(*handle, sizeof (**handle));
}

static inline int ddi_dev_regsize(dev_info_t *dip, uint_t rnumber,
	off_t *resultp)
{
	/* Return the size of the register */
	*resultp = dip->register_memory_size;
	return (DDI_SUCCESS);
}

static inline int ddi_regs_map_setup(dev_info_t *dip, uint_t rnumber,
	caddr_t *addrp, offset_t offset, offset_t len,
	ddi_device_acc_attr_t *accattrp, ddi_acc_handle_t *handlep)
{
	sca_ddi_handle_t *handle;
	if ((handle = (sca_ddi_handle_t *)kmem_alloc(sizeof (sca_ddi_handle_t),
	    GFP_ATOMIC)) == NULL)
		return (DDI_FAILURE);
	memset(handle, 0, sizeof (sca_ddi_handle_t));

	handle->dip = dip;
	*handlep = handle;

	/* Return the kernel address. It is used in ddi_get/put functions */
	*addrp = dip->virtual_register_memory;

	return (DDI_SUCCESS);
}

static inline void ddi_regs_map_free(ddi_acc_handle_t *handlep)
{
	kmem_free(*handlep, sizeof (**handlep));
}

/*
 * From microsec to ticks. HZ is the number of ticks per second
 */
static inline clock_t drv_usectohz(clock_t microsecs)
{
	/*
	 * It should be (microsecs/1000000)*HZ. To avoid underflow,
	 * do the following. We know HZ is 100 or 1000.
	 */
	return (microsecs * (HZ / 100) / 10000);
}

/* From ticks to microsecs */
static inline clock_t drv_hztousec(clock_t hertz)
{
	/*
	 * It should be (hertz/HZ)*1000000. To avoid underflow,
	 * do the following. We know HZ is 100 or 1000.
	 */
	return (hertz * (1000000 / HZ));
}

/*
 * taskq to workqueue mapping
 */
typedef struct workqueue_struct		ddi_taskq_t;
typedef uintptr_t			taskqid_t;

static inline ddi_taskq_t *ddi_taskq_create(dev_info_t  *dip, const char *name,
    int nthreads, pri_t priority, uint_t flags)
{
	return (create_workqueue(name));
}

static inline void ddi_taskq_destroy(ddi_taskq_t *tq)
{
	destroy_workqueue(tq);
}

static void task_work_invoker(struct work_struct *work) {
	work_ex_t* head = (work_ex_t*)work;
	(*head->cb)((void*)work);
}

static inline taskqid_t ddi_taskq_dispatch(ddi_taskq_t *tq, task_func_t func,
    void * arg, uint_t flags)
{
	struct work_struct *work;
	work_ex_t *head = (work_ex_t*)arg;
	/*
	 * The arg parameter is either mca_t or request_t.
	 * The first entry is a struct work_struct type field.
	 */
	work = (struct work_struct *)arg;
	
	head->cb = func;
	
	/* Init the workqueue with the function and the argument */
	INIT_WORK(work, task_work_invoker);

	/* Schedule the work */
	queue_work(tq, work);

	/* The calling function requires a return value "0" for success. */
	return (0);
}

#define	MAX_NUM_TIMER		10
extern struct timer_list sca_timer[MAX_NUM_TIMER];
extern spinlock_t sca_timer_lock;
extern int sca_timer_last_index;
extern int sca_timer_lock_initialized;

/*
 * timeout
 */
static inline timeout_id_t timeout(void (* func)(void *), void *arg,
    clock_t ticks)
{
	int i, index;
	struct timer_list *free_timer;
	unsigned long flags;

	if (!sca_timer_lock_initialized) {
		sca_timer_lock_initialized = 1;
		sca_timer_lock = SPIN_LOCK_UNLOCKED;
	}

	spin_lock_irqsave(&sca_timer_lock, flags);

	/* Find a free timer */
	for (i = 0; i < MAX_NUM_TIMER; i++) {
		index = sca_timer_last_index++;
		if (sca_timer_last_index >= MAX_NUM_TIMER)
			sca_timer_last_index = 0;

		if (!timer_pending(&sca_timer[index])) {
			/*
			 * Add a timer to do the timeout.
			 * The timer will be removed when it is expired.
			 */
			init_timer(&sca_timer[index]);
			sca_timer[index].function =
			    (void(*)(unsigned long))func;
			sca_timer[index].data = (unsigned long) arg;
			sca_timer[index].expires = jiffies + ticks;
			add_timer(&sca_timer[index]);

			spin_unlock_irqrestore(&sca_timer_lock, flags);

			return (&sca_timer[index]);
		}
	}

	spin_unlock_irqrestore(&sca_timer_lock, flags);

	return (NULL);
}

static inline clock_t untimeout(timeout_id_t id)
{
	int rv = 0;

	if (id && timer_pending(id))
		rv = del_timer_sync(id);

	return (rv);
}

static inline clock_t ddi_get_lbolt(void)
{
	return (jiffies);
}

static inline uint16_t ddi_swap16(uint16_t word)
{
	return (((word >> 8) & 0x00ff) | ((word << 8) & 0xff00));
}

static inline uint32_t ddi_swap32(uint32_t w)
{
	return (((w >> 24) | ((w >> 8) & 0xff00) |
	    ((w << 8) & 0xff0000) | (w << 24)));
}

/*
 * ddi_get_time() returns the current  time  in  seconds  since
 * 00:00:00 UTC, January 1, 1970.
 */
static inline time_t ddi_get_time(void)
{
	/*
	 * ddi_get_time() may be called from any context. Certain context
	 * does not like do_gettimeofday(), such as a tasklet which is used
	 * to implement the Solaris task queue. The current_kernel_time()
	 * function works fine in tasklet context.
	 *
	 * struct timeval time;
	 * do_gettimeofday(&time);
	 * return (time.tv_sec);
	 */

	struct timespec time = current_kernel_time();

	/* Ignore the tv_nsec part since it is just a fraction of a sec. */
	return (time.tv_sec);
}

static inline uint64_t atomic_add_64_nv(uint64_t *target, int64_t delta)
{
	/* Solaris does not have an atomic_t type. Needs a cast here. */
	atomic_add((int)delta, (atomic_t *)target);
	return (*target);
}

static inline void atomic_inc_32(volatile uint32_t *target)
{
	atomic_inc((atomic_t *)target);
}

static inline void atomic_dec_32(volatile uint32_t *target)
{
	atomic_dec((atomic_t *)target);
}

static inline void delay(clock_t ticks)
{
	wait_queue_head_t	wqh;
	DEFINE_WAIT(wait);

	init_waitqueue_head(&wqh);
	prepare_to_wait(&wqh, &wait, TASK_UNINTERRUPTIBLE);
	schedule_timeout(ticks);
	finish_wait(&wqh, &wait);
}

static inline void drv_usecwait(clock_t microsecs)
{
	udelay(microsecs);
}

#ifdef	__cplusplus
}
#endif

#endif /* _SOL2LIN_H */
