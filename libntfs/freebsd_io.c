/**
 * freebsd_io.c - FreeBSD disk io functions. Part of the Linux-NTFS project.
 *
 * FreeBSD 5.0+ does not have block devices and requires read/writes from/to
 * character devices to be sector aligned.
 *
 * Copyright (c) 2006 Max Khon
 * Copyright (c) 2006 Anton Altaparmakov
 * Copyright (c) 2006 Yura Pakhuchiy
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
 * along with this program (in the main directory of the NTFS-3G
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_LINUX_FD_H
#include <linux/fd.h>
#endif
#include <sys/disk.h>

#include "types.h"
#include "mst.h"
#include "debug.h"
#include "device.h"
#include "logging.h"

typedef struct {
	int fd;
	s64 pos;
	s32 block_size;
	s64 media_size;
} freebsd_fd;

#define DEV_FD(dev)	(((freebsd_fd *) dev->d_private))
#define RAW_IO_ALIGNED(dev, offset, count)			\
	(DEV_FD(dev)->block_size == 0 ||			\
	 ((offset) % DEV_FD(dev)->block_size == 0 &&		\
	  (count) % DEV_FD(dev)->block_size == 0))
#define RAW_IO_ALIGN(dev, offset)				\
	((offset) / DEV_FD(dev)->block_size * DEV_FD(dev)->block_size)
#define RAW_IO_MAX_SIZE (128 * 1024 * 1024)

/* Define to nothing if not present on this system. */
#ifndef O_EXCL
#	define O_EXCL 0
#endif

/**
 * Get block_size and media_size
 */
static int freebsd_get_size(struct ntfs_device *dev)
{
	off_t ms;
	int bs;
	struct stat sb;

	if (fstat(DEV_FD(dev)->fd, &sb) < 0) {
		ntfs_log_perror("Failed to stat '%s'", dev->d_name);
		return -1;
	}
	if (S_ISREG(sb.st_mode)) {
		DEV_FD(dev)->media_size = sb.st_size;
		ntfs_log_trace("%s: regular file (media_size %lld)\n",
		    dev->d_name, DEV_FD(dev)->media_size);
		return 0;
	}
	if (ioctl(DEV_FD(dev)->fd, DIOCGSECTORSIZE, &bs) < 0) {
		ntfs_log_perror("Failed to ioctl(DIOCGSECTORSIZE) '%s'",
		    dev->d_name);
		return -1;
	}
	DEV_FD(dev)->block_size = bs;
	ntfs_log_trace("%s: block size %d\n", dev->d_name, bs);
	if (ioctl(DEV_FD(dev)->fd, DIOCGMEDIASIZE, &ms) < 0) {
		ntfs_log_perror("Failed to ioctl(DIOCGMEDIASIZE) '%s'",
		    dev->d_name);
		return -1;
	}
	DEV_FD(dev)->media_size = ms;
	ntfs_log_trace("%s: media size %lld\n", dev->d_name, ms);
	return 0;
}

/**
 * freebsd_pread - Aligned read
 */
static inline ssize_t freebsd_pread(struct ntfs_device *dev, char *buf,
		size_t count, s64 offset)
{
	return pread(DEV_FD(dev)->fd, buf, count, offset);
}

/**
 * freebsd_pwrite - Aligned write
 */
static inline ssize_t freebsd_pwrite(struct ntfs_device *dev, const char *buf,
		size_t count, s64 offset)
{
	return pwrite(DEV_FD(dev)->fd, buf, count, offset);
}

/**
 * ntfs_device_freebsd_io_open - Open a device and lock it exclusively
 * @dev:
 * @flags:
 *
 * Description...
 *
 * Returns:
 */
static int ntfs_device_freebsd_io_open(struct ntfs_device *dev, int flags)
{
#if 0
	struct flock flk;
#endif
	struct stat sbuf;
	int err;

	if (NDevOpen(dev)) {
		errno = EBUSY;
		return -1;
	}
	if (stat(dev->d_name, &sbuf)) {
		ntfs_log_perror("Failed to access '%s'", dev->d_name);
		return -1;
	}
	if (S_ISBLK(sbuf.st_mode) || S_ISCHR(sbuf.st_mode))
		NDevSetBlock(dev);

	dev->d_private = malloc(sizeof(freebsd_fd));
	if (!dev->d_private)
		return -1;
	DEV_FD(dev)->fd = -1;
	DEV_FD(dev)->pos = 0;
	DEV_FD(dev)->block_size = 0;
	DEV_FD(dev)->media_size = 0;

	DEV_FD(dev)->fd = open(dev->d_name, flags);
	if (DEV_FD(dev)->fd == -1) {
		err = errno;
		goto err_out;
	}

	if ((flags & O_RDWR) != O_RDWR)
		NDevSetReadOnly(dev);

#if 0
	memset(&flk, 0, sizeof(flk));
	if (NDevReadOnly(dev))
		flk.l_type = F_RDLCK;
	else
		flk.l_type = F_WRLCK;
	flk.l_whence = SEEK_SET;
	flk.l_start = flk.l_len = 0LL;
	if (fcntl(DEV_FD(dev)->fd, F_SETLK, &flk)) {
		err = errno;
		ntfs_log_perror("Failed to %s lock '%s'", NDevReadOnly(dev) ?
				"read" : "write", dev->d_name);
		if (close(DEV_FD(dev)->fd))
			ntfs_log_perror("Failed to close '%s'", dev->d_name);
		goto err_out;
	}
#endif

	if (freebsd_get_size(dev) < 0) {
		err = errno;
		close(DEV_FD(dev)->fd);
		goto err_out;
	}

	NDevSetOpen(dev);
	return 0;
err_out:
	free(dev->d_private);
	dev->d_private = NULL;
	errno = err;
	return -1;
}

/**
 * ntfs_device_freebsd_io_close - Close the device, releasing the lock
 * @dev:
 *
 * Description...
 *
 * Returns:
 */
static int ntfs_device_freebsd_io_close(struct ntfs_device *dev)
{
#if 0
	struct flock flk;
#endif

	if (!NDevOpen(dev)) {
		errno = EBADF;
		return -1;
	}
	if (NDevDirty(dev))
		fsync(DEV_FD(dev)->fd);

#if 0
	/* Release exclusive (mandatory) lock on the whole device. */
	memset(&flk, 0, sizeof(flk));
	flk.l_type = F_UNLCK;
	flk.l_whence = SEEK_SET;
	flk.l_start = flk.l_len = 0LL;
	if (fcntl(DEV_FD(dev)->fd, F_SETLK, &flk))
		ntfs_log_perror("ntfs_device_freebsd_io_close: Warning: Could not "
				"unlock %s", dev->d_name);
#endif

	/* Close the file descriptor and clear our open flag. */
	if (close(DEV_FD(dev)->fd))
		return -1;
	NDevClearOpen(dev);
	free(dev->d_private);
	dev->d_private = NULL;
	return 0;
}

/**
 * ntfs_device_freebsd_io_seek - Seek to a place on the device
 * @dev:
 * @offset:
 * @whence:
 *
 * Description...
 *
 * Returns:
 */
static s64 ntfs_device_freebsd_io_seek(struct ntfs_device *dev, s64 offset,
		int whence)
{
	s64 abs_pos;

	ntfs_log_trace("seek offset = 0x%llx, whence = %d.\n", offset, whence);
	switch (whence) {
	case SEEK_SET:
		abs_pos = offset;
		break;

	case SEEK_CUR:
		abs_pos = DEV_FD(dev)->pos + offset;
		break;

	case SEEK_END:
		abs_pos = DEV_FD(dev)->media_size + offset;
		break;

	default:
		ntfs_log_trace("Wrong mode %d.\n", whence);
		errno = EINVAL;
		return -1;
	}

	if (abs_pos < 0 || abs_pos > DEV_FD(dev)->media_size) {
		ntfs_log_trace("Seeking outsize seekable area.\n");
		errno = EINVAL;
		return -1;
	}
	DEV_FD(dev)->pos = abs_pos;
	return abs_pos;
}

/**
 * ntfs_device_freebsd_io_read - Read from the device, from the current location
 * @dev:
 * @buf:
 * @count:
 *
 * Description...
 *
 * Returns:
 */
static s64 ntfs_device_freebsd_io_read(struct ntfs_device *dev, void *buf,
		s64 count)
{
	s64 start, start_aligned;
	s64 end, end_aligned;
	size_t count_aligned;
	char *buf_aligned;
	ssize_t nr;

	/* short-circuit for regular files */
	start = DEV_FD(dev)->pos;
	if (count > RAW_IO_MAX_SIZE)
		count = RAW_IO_MAX_SIZE;
	if (RAW_IO_ALIGNED(dev, start, count)) {
		nr = freebsd_pread(dev, buf, count, start);
		if (nr <= 0)
			return nr;

		DEV_FD(dev)->pos += nr;
		return nr;
	}

	/*
	 * +- start_aligned                 +- end_aligned
	 * |                                |
	 * |     +- start           +- end  |
	 * v     v                  v       v
	 * |----------|----------|----------|
	 *       ^                  ^
	 *       +----- count ------+
	 * ^                                ^
	 * +-------- count_aligned ---------+
	 */
	start_aligned = RAW_IO_ALIGN(dev, start);
	end = start + count;
	end_aligned = RAW_IO_ALIGN(dev, end) +
	    (RAW_IO_ALIGNED(dev, end, 0) ? 0 : DEV_FD(dev)->block_size);
	count_aligned = end_aligned - start_aligned;
	ntfs_log_trace(
	    "%s: count = 0x%llx/0x%x, start = 0x%llx/0x%llx, end = 0x%llx/0x%llx\n",
	    dev->d_name, count, count_aligned,
	    start, start_aligned, end, end_aligned);

	/* allocate buffer */
	buf_aligned = malloc(count_aligned);
	if (buf_aligned == NULL) {
		ntfs_log_trace("malloc(%d) failed\n", count_aligned);
		return -1;
	}

	/* read aligned data */
	nr = freebsd_pread(dev, buf_aligned, count_aligned, start_aligned);
	if (nr == 0)
		return 0;
	if (nr < 0 || nr < start - start_aligned) {
		free(buf_aligned);
		return -1;
	}

	/* copy out */
	memcpy(buf, buf_aligned + (start - start_aligned), count);
	free(buf_aligned);

	nr -= start - start_aligned;
	if (nr > count)
		nr = count;
	DEV_FD(dev)->pos += nr;
	return nr;
}

/**
 * ntfs_device_freebsd_io_write - Write to the device, at the current location
 * @dev:
 * @buf:
 * @count:
 *
 * Description...
 *
 * Returns:
 */
static s64 ntfs_device_freebsd_io_write(struct ntfs_device *dev, const void *buf,
		s64 count)
{
	s64 start, start_aligned;
	s64 end, end_aligned;
	size_t count_aligned;
	char *buf_aligned;
	ssize_t nw;

	if (NDevReadOnly(dev)) {
		errno = EROFS;
		return -1;
	}
	NDevSetDirty(dev);

	/* short-circuit for regular files */
	start = DEV_FD(dev)->pos;
	if (count > RAW_IO_MAX_SIZE)
		count = RAW_IO_MAX_SIZE;
	if (RAW_IO_ALIGNED(dev, start, count)) {
		nw = freebsd_pwrite(dev, buf, count, start);
		if (nw <= 0)
			return nw;

		DEV_FD(dev)->pos += nw;
		return nw;
	}

	/*
	 * +- start_aligned                 +- end_aligned
	 * |                                |
	 * |     +- start           +- end  |
	 * v     v                  v       v
	 * |----------|----------|----------|
	 *       ^                  ^
	 *       +----- count ------+
	 * ^                                ^
	 * +-------- count_aligned ---------+
	 */
	start_aligned = RAW_IO_ALIGN(dev, start);
	end = start + count;
	end_aligned = RAW_IO_ALIGN(dev, end) +
	    (RAW_IO_ALIGNED(dev, end, 0) ? 0 : DEV_FD(dev)->block_size);
	count_aligned = end_aligned - start_aligned;
	ntfs_log_trace(
	    "%s: count = 0x%llx/0x%x, start = 0x%llx/0x%llx, end = 0x%llx/0x%llx\n",
	    dev->d_name, count, count_aligned,
	    start, start_aligned, end, end_aligned);

	/* allocate buffer */
	buf_aligned = malloc(count_aligned);
	if (buf_aligned == NULL) {
		ntfs_log_trace("malloc(%d) failed\n", count_aligned);
		return -1;
	}

	/* read aligned lead-in */
	if (freebsd_pread(dev, buf_aligned, DEV_FD(dev)->block_size, start_aligned) != DEV_FD(dev)->block_size) {
		ntfs_log_trace("read lead-in failed\n");
		free(buf_aligned);
		return -1;
	}

	/* read aligned lead-out */
	if (end != end_aligned && count_aligned > DEV_FD(dev)->block_size) {
		if (freebsd_pread(dev, buf_aligned + count_aligned - DEV_FD(dev)->block_size, DEV_FD(dev)->block_size, end_aligned - DEV_FD(dev)->block_size) != DEV_FD(dev)->block_size) {
			ntfs_log_trace("read lead-out failed\n");
			free(buf_aligned);
			return -1;
		}
	}

	/* copy data to write */
	memcpy(buf_aligned + (start - start_aligned), buf, count);

	/* write aligned data */
	nw = freebsd_pwrite(dev, buf_aligned, count_aligned, start_aligned);
	free(buf_aligned);
	if (nw < 0 || nw < start - start_aligned)
		return -1;

	nw -= start - start_aligned;
	if (nw > count)
		nw = count;
	DEV_FD(dev)->pos += nw;
	return nw;
}

/**
 * ntfs_device_freebsd_io_sync - Flush any buffered changes to the device
 * @dev:
 *
 * Description...
 *
 * Returns:
 */
static int ntfs_device_freebsd_io_sync(struct ntfs_device *dev)
{
	if (!NDevReadOnly(dev)) {
		int res = fsync(DEV_FD(dev)->fd);
		if (!res)
			NDevClearDirty(dev);
		return res;
	}
	return 0;
}

/**
 * ntfs_device_freebsd_io_stat - Get information about the device
 * @dev:
 * @buf:
 *
 * Description...
 *
 * Returns:
 */
static int ntfs_device_freebsd_io_stat(struct ntfs_device *dev, struct stat *buf)
{
	return fstat(DEV_FD(dev)->fd, buf);
}

/**
 * ntfs_device_freebsd_io_ioctl - Perform an ioctl on the device
 * @dev:
 * @request:
 * @argp:
 *
 * Description...
 *
 * Returns:
 */
static int ntfs_device_freebsd_io_ioctl(struct ntfs_device *dev, int request,
		void *argp)
{
	return ioctl(DEV_FD(dev)->fd, request, argp);
}

/**
 * Device operations for working with unix style devices and files.
 */
struct ntfs_device_operations ntfs_device_unix_io_ops = {
	.open		= ntfs_device_freebsd_io_open,
	.close		= ntfs_device_freebsd_io_close,
	.seek		= ntfs_device_freebsd_io_seek,
	.read		= ntfs_device_freebsd_io_read,
	.write		= ntfs_device_freebsd_io_write,
	.sync		= ntfs_device_freebsd_io_sync,
	.stat		= ntfs_device_freebsd_io_stat,
	.ioctl		= ntfs_device_freebsd_io_ioctl,
};
