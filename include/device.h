/*
 * device.h - Exports for low level device io. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2003 Anton Altaparmakov
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _NTFS_DEVICE_H
#define _NTFS_DEVICE_H

#include "types.h"
#include "support.h"

/*
 * Defined bits for the state field in the ntfs_device structure.
 */
typedef enum {
	ND_Open,	/* 1: Device is open. */
	ND_ReadOnly,	/* 1: Device is read-only. */
	ND_Dirty,	/* 1: Device is dirty, needs sync. */
} ntfs_device_state_bits;

#define  test_ndev_flag(nd, flag)	   test_bit(ND_##flag, (nd)->d_state)
#define   set_ndev_flag(nd, flag)	    set_bit(ND_##flag, (nd)->d_state)
#define clear_ndev_flag(nd, flag)	  clear_bit(ND_##flag, (nd)->d_state)

#define NDevOpen(nd)		 test_ndev_flag(nd, Open)
#define NDevSetOpen(nd)		  set_ndev_flag(nd, Open)
#define NDevClearOpen(nd)	clear_ndev_flag(nd, Open)

#define NDevReadOnly(nd)	 test_ndev_flag(nd, ReadOnly)
#define NDevSetReadOnly(nd)	  set_ndev_flag(nd, ReadOnly)
#define NDevClearReadOnly(nd)	clear_ndev_flag(nd, ReadOnly)

#define NDevDirty(nd)		 test_ndev_flag(nd, Dirty)
#define NDevSetDirty(nd)	  set_ndev_flag(nd, Dirty)
#define NDevClearDirty(nd)	clear_ndev_flag(nd, Dirty)

/* Forward declaration. */
struct ntfs_device_operations;

/*
 * The ntfs device structure defining all operations needed to access the low
 * level device underlying the ntfs volume.
 */
struct ntfs_device {
	struct ntfs_device_operations *d_ops;	/* Device operations. */
	unsigned long d_state;			/* State of the device. */
	char *d_name;				/* Name of device. */
	void *d_private;			/* Private data used by the
						   device operations. */
};

/*
 * The ntfs device operations defining all operations that can be performed on
 * the low level device described by a ntfs device structure.
 */
struct ntfs_device_operations {
	struct ntfs_device *(*open)(const char *pathname, int flags);
	int (*close)(struct ntfs_device *dev);
	int (*sync)(struct ntfs_device *dev);
	s64 (*seek)(struct ntfs_device *dev, s64 offset, int whence);
	s64 (*read)(struct ntfs_device *dev, void *buf, s64 count);
	s64 (*write)(struct ntfs_device *dev, const void *buf, s64 count);
	s64 (*pread)(struct ntfs_device *dev, void *buf, s64 count, s64 offset);
	s64 (*pwrite)(struct ntfs_device *dev, const void *buf, s64 count,
			s64 offset);
};

struct ntfs_device *ntfs_device_alloc(void);
int ntfs_device_free(struct ntfs_device *dev);

#endif /* defined _NTFS_DEVICE_H */
