/*
 * device.c - Low level device io functions. Part of the Linux-NTFS project.
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

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "device.h"

/**
 * ntfs_device_alloc - allocate an ntfs device structure and pre-initialize it
 * name:	name of the device (must be present)
 * state:	initial device state (usually zero)
 * dops:	ntfs device operations to use with the device (must be present)
 * private:	pointer to private data (optional)
 *
 * Allocate an ntfs device structure and pre-initialize it with the user-
 * specified device operations @dops, device state @state, device name @name,
 * and optional private data @private.
 *
 * Note, @name is copied and can hence be freed after this functions returns.
 *
 * On success return a pointer to the allocated ntfs device structure and on
 * error return NULL with errno set to the error code returned by malloc().
 */
struct ntfs_device *ntfs_device_alloc(const char *name, const long state,
		struct ntfs_device_operations *dops, void *private)
{
	struct ntfs_device *dev;

	if (!name) {
		errno = EINVAL;
		return NULL;
	}

	dev = (struct ntfs_device *)malloc(sizeof(struct ntfs_device));
	if (dev) {
		if (!(dev->d_name = strdup(name))) {
			int eo = errno;
			free(dev);
			errno = eo;
			return NULL;
		}
		dev->d_ops = dops;
		dev->d_state = state;
		dev->d_private = private;
	}
	return dev;
}

/**
 * ntfs_device_free - free an ntfs device structure
 * @dev:	ntfs device structure to free
 *
 * Free the ntfs device structure @dev.
 *
 * Return 0 on success or -1 on error with errno set to the error code. The
 * following error codes are defined:
 *	EINVAL		Invalid pointer @dev.
 *	EBUSY		Device is still open. Close it before freeing it!
 */
int ntfs_device_free(struct ntfs_device *dev)
{
	if (!dev) {
		errno = EINVAL;
		return -1;
	}
	if (NDevOpen(dev)) {
		errno = EBUSY;
		return -1;
	}
	if (dev->d_name)
		free(dev->d_name);
	free(dev);
	return 0;
}

