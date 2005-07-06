/*
 * unix_io.c - Unix style disk io functions. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2000-2003 Anton Altaparmakov
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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#ifdef HAVE_LINUX_FD_H
#	include <linux/fd.h>
#endif

#include "types.h"
#include "mst.h"
#include "debug.h"
#include "device.h"

#if defined(linux) && defined(_IO) && !defined(BLKGETSIZE)
#	define BLKGETSIZE _IO(0x12,96) /* Get device size in 512byte blocks. */
#endif

#define DEV_FD(dev)	(*(int *)dev->d_private)

static int ntfs_device_unix_io_open(struct ntfs_device *dev, int flags)
{
	struct flock flk;
	int err;

	if (NDevOpen(dev)) {
		errno = EBUSY;
		return -1;
	}
	if (!(dev->d_private = malloc(sizeof(int))))
		return -1;
	/* Open the device/file obtaining the file descriptor. */
	if ((*(int *)dev->d_private = open(dev->d_name, flags)) == -1) {
		err = errno;
		goto err_out;
	}
	/* Setup our read-only flag. */
	if ((flags & O_RDWR) != O_RDWR)
		NDevSetReadOnly(dev);
	/* Acquire exclusive (mandatory) lock on the whole device. */
	memset(&flk, 0, sizeof(flk));
	if (NDevReadOnly(dev))
		flk.l_type = F_RDLCK;
	else
		flk.l_type = F_WRLCK;
	flk.l_whence = SEEK_SET;
	flk.l_start = flk.l_len = 0LL;
	if (fcntl(DEV_FD(dev), F_SETLK, &flk)) {
		err = errno;
		Dprintf("ntfs_device_unix_io_open: Could not lock %s for %s: "
				"%s\n", dev->d_name, NDevReadOnly(dev) ?
				"reading" : "writing", strerror(errno));
		if (close(DEV_FD(dev)))
			Dprintf("ntfs_device_unix_io_open: Warning: Could not "
					"close %s: %s\n", dev->d_name,
					strerror(errno));
		goto err_out;
	}
	/* Set our open flag. */
	NDevSetOpen(dev);
	return 0;
err_out:
	free(dev->d_private);
	dev->d_private = NULL;
	errno = err;
	return -1;
}

static int ntfs_device_unix_io_close(struct ntfs_device *dev)
{
	struct flock flk;

	if (!NDevOpen(dev)) {
		errno = EBADF;
		return -1;
	}
	if (NDevDirty(dev))
		fsync(DEV_FD(dev));
	/* Release exclusive (mandatory) lock on the whole device. */
	memset(&flk, 0, sizeof(flk));
	flk.l_type = F_UNLCK;
	flk.l_whence = SEEK_SET;
	flk.l_start = flk.l_len = 0LL;
	if (fcntl(DEV_FD(dev), F_SETLK, &flk))
		Dprintf("ntfs_device_unix_io_close: Warning: Could not unlock "
				"%s: %s\n", dev->d_name, strerror(errno));
	/* Close the file descriptor and clear our open flag. */
	if (close(DEV_FD(dev)))
		return -1;
	NDevClearOpen(dev);
	free(dev->d_private);
	dev->d_private = NULL;
	return 0;
}

static s64 ntfs_device_unix_io_seek(struct ntfs_device *dev, s64 offset,
		int whence)
{
	return lseek(DEV_FD(dev), offset, whence);
}

static s64 ntfs_device_unix_io_read(struct ntfs_device *dev, void *buf,
		s64 count)
{
	return read(DEV_FD(dev), buf, count);
}

static s64 ntfs_device_unix_io_write(struct ntfs_device *dev, const void *buf,
		s64 count)
{
	if (NDevReadOnly(dev)) {
		errno = EROFS;
		return -1;
	}
	NDevSetDirty(dev);
	return write(DEV_FD(dev), buf, count);
}

static s64 ntfs_device_unix_io_pread(struct ntfs_device *dev, void *buf,
		s64 count, s64 offset)
{
	return ntfs_pread(dev, offset, count, buf);
}

static s64 ntfs_device_unix_io_pwrite(struct ntfs_device *dev, const void *buf,
		s64 count, s64 offset)
{
	if (NDevReadOnly(dev)) {
		errno = EROFS;
		return -1;
	}
	NDevSetDirty(dev);
	return ntfs_pwrite(dev, offset, count, buf);
}

static int ntfs_device_unix_io_sync(struct ntfs_device *dev)
{
	if (!NDevReadOnly(dev) && NDevDirty(dev)) {
		int res = fsync(DEV_FD(dev));
		if (!res)
			NDevClearDirty(dev);
		return res;
	}
	return 0;
}

static int ntfs_device_unix_io_stat(struct ntfs_device *dev, struct stat *buf)
{
	return fstat(DEV_FD(dev), buf);
}

static int ntfs_device_unix_io_ioctl(struct ntfs_device *dev, int request,
		void *argp)
{
	return ioctl(DEV_FD(dev), request, argp);
}

/**
 * Device operations for working with unix style devices and files.
 */
struct ntfs_device_operations ntfs_device_unix_io_ops = {
	.open		= ntfs_device_unix_io_open,
	.close		= ntfs_device_unix_io_close,
	.seek		= ntfs_device_unix_io_seek,
	.read		= ntfs_device_unix_io_read,
	.write		= ntfs_device_unix_io_write,
	.pread		= ntfs_device_unix_io_pread,
	.pwrite		= ntfs_device_unix_io_pwrite,
	.sync		= ntfs_device_unix_io_sync,
	.stat		= ntfs_device_unix_io_stat,
	.ioctl		= ntfs_device_unix_io_ioctl,
};

