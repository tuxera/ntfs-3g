/*
 * disk_io.c - Disk io functions. Part of the Linux-NTFS project.
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
#ifdef HAVE_LINUX_FD_H
#	include <sys/ioctl.h>
#	include <linux/fd.h>
#endif

#include "types.h"
#include "disk_io.h"
#include "mst.h"
#include "debug.h"

#if defined(__linux__) && defined(_IO) && !defined(BLKGETSIZE)
#	define BLKGETSIZE _IO(0x12,96) /* Get device size in 512byte blocks. */
#endif

/**
 * ntfs_pread - positioned read from disk
 * @fd:		file descriptor to read from
 * @pos:	position in file descriptor to read from
 * @count:	number of bytes to read
 * @b:		output data buffer
 *
 * This function will read @count bytes from file descriptor @fd at position
 * @pos into the data buffer @b.
 *
 * On success, return the number of successfully read bytes. If this number is
 * lower than @count this means that we have either reached end of file or
 * encountered an error during the read so that the read is partial. 0 means
 * end of file or nothing to read (@count is 0).
 *
 * On error and nothing has been read, return -1 with errno set appropriately
 * to the return code of either lseek, read, or set to EINVAL in case of
 * invalid arguments.
 */
s64 ntfs_pread(const int fd, const s64 pos, s64 count, const void *b)
{
	s64 br, total;

	Dprintf("%s(): Entering for pos 0x%Lx, count 0x%Lx.\n", __FUNCTION__,
			pos, count);
	if (!b || count < 0 || pos < 0) {
		errno = EINVAL;
		return -1;
	}
	if (!count)
		return 0;
	/* Locate to position. */
	if (lseek(fd, pos, SEEK_SET) == (off_t)-1) {
		Dprintf("ntfs_pread: lseek to 0x%Lx returned error: %s\n", pos,
				strerror(errno));
		return -1;
	}
	/* Read the data. */
	for (total = 0; count; count -= br, total += br) {
		br = read(fd, (char*)b + total, count);
		/* If everything ok, continue. */
		if (br > 0)
			continue;
		/* If EOF or error return number of bytes read. */
		if (!br || total)
			return total;
		/* Nothing read and error, return error status. */
		return br;
	}
	/* Finally, return the number of bytes read. */
	return total;
}

/**
 * ntfs_pwrite - positioned write to disk
 * @fd:		file descriptor to write to
 * @pos:	position in file descriptor to write to
 * @count:	number of bytes to write
 * @b:		data buffer to write to disk
 *
 * This function will write @count bytes from data buffer @b to file descriptor
 * @fd at position @pos.
 *
 * On success, return the number of successfully written bytes. If this number
 * is lower than @count this means that the write has been interrupted in
 * flight or that an error was encountered during the write so that the write
 * is partial. 0 means nothing was written (also return 0 when @count is 0).
 *
 * On error and nothing has been written, return -1 with errno set
 * appropriately to the return code of either lseek, write, fdatasync, or set
 * to EINVAL in case of invalid arguments.
 */
s64 ntfs_pwrite(const int fd, const s64 pos, s64 count, const void *b)
{
	s64 written, total;

	Dprintf("%s(): Entering for pos 0x%Lx, count 0x%Lx.\n", __FUNCTION__,
			pos, count);
	if (!b || count < 0 || pos < 0) {
		errno = EINVAL;
		return -1;
	}
	if (!count)
		return 0;
	/* Locate to position. */
	if (lseek(fd, pos, SEEK_SET) == (off_t)-1) {
		Dprintf("ntfs_pwrite: lseek to 0x%Lx returned error: %s\n",
				pos, strerror(errno));
		return -1;
	}
	/* Write the data. */
	for (total = 0; count; count -= written, total += written) {
		written = write(fd, (char*)b + total, count);
		/* If everything ok, continue. */
		if (written > 0)
			continue;
		/*
		 * If nothing written or error return number of bytes written.
		 */
		if (!written || total)
			break;
		/* Nothing written and error, return error status. */
		return written;
	}
	/* Sync write to disk. */
	if (fdatasync(fd) == -1)
		return -1;
	/* Finally, return the number of bytes written. */
	return total;
}

/**
 * ntfs_mst_pread - multi sector transfer (mst) positioned read
 * @fd:		file descriptor to read from
 * @pos:	position in file descriptor to read from
 * @count:	number of blocks to read
 * @bksize:	size of each block that needs mst deprotecting
 * @b:		output data buffer
 *
 * Multi sector transfer (mst) positioned read. This function will read @count
 * blocks of size @bksize bytes each from file descriptor @fd at position @pos
 * into the data buffer @b.
 *
 * On success, return the number of successfully read blocks. If this number is
 * lower than @count this means that we have reached end of file, that the read
 * was interrupted, or that an error was encountered during the read so that
 * the read is partial. 0 means end of file or nothing was read (also return 0
 * when @count or @bksize are 0).
 *
 * On error and nothing was read, return -1 with errno set appropriately to the
 * return code of either lseek, read, or set to EINVAL in case of invalid
 * arguments.
 *
 * NOTE: If an incomplete multi sector transfer has been detected the magic
 * will have been changed to magic_BAAD but no error will be returned. Thus it
 * is possible that we return count blocks as being read but that any number
 * (between zero and count!) of these blocks is actually subject to a multi
 * sector transfer error. This should be detected by the caller by checking for
 * the magic being "BAAD".
 */
s64 ntfs_mst_pread(const int fd, const s64 pos, s64 count,
		const u32 bksize, const void *b)
{
	s64 br, i;

	if (bksize & (bksize - 1) || bksize % NTFS_SECTOR_SIZE) {
		errno = EINVAL;
		return -1;
	}
	/* Do the read. */
	br = ntfs_pread(fd, pos, count * bksize, b);
	if (br < 0)
		return br;
	/*
	 * Apply fixups to successfully read data, disregarding any errors
	 * returned from the MST fixup function. This is because we want to
	 * fixup everything possible and we rely on the fact that the "BAAD"
	 * magic will be detected later on.
	 */
	count = br / bksize;
	for (i = 0; i < count; ++i)
		ntfs_mst_post_read_fixup((NTFS_RECORD*)
				((u8*)b + i * bksize), bksize);
	/* Finally, return the number of complete blocks read. */
	return count;
}

/**
 * ntfs_mst_pwrite - multi sector transfer (mst) positioned write
 * @fd:		file descriptor to write to
 * @pos:	position in file descriptor to write to
 * @count:	number of blocks to write
 * @bksize:	size of each block that needs mst protecting
 * @b:		data buffer to write to disk
 *
 * Multi sector transfer (mst) positioned write. This function will write
 * @count blocks of size @bksize bytes each from data buffer @b to file
 * descriptor @fd at position @pos.
 *
 * On success, return the number of successfully written blocks. If this number
 * is lower than @count this means that the write has been interrutped or that
 * an error was encountered during the write so that the write is partial. 0
 * means nothing was written (also return 0 when @count or @bksize are 0).
 *
 * On error and nothing has been written, return -1 with errno set
 * appropriately to the return code of either lseek, write, fdatasync, or set
 * to EINVAL in case of invalid arguments.
 *
 * NOTE: We mst protect the data, write it, then mst deprotect it using a quick
 * deprotect algorithm (no checking). This saves us from making a copy before
 * the write and at the same time causes the usn to be incremented in the
 * buffer. This conceptually fits in better with the idea that cached data is
 * always deprotected and protection is performed when the data is actually
 * going to hit the disk and the cache is immediately deprotected again
 * simulating an mst read on the written data. This way cache coherency is
 * achieved.
 */
s64 ntfs_mst_pwrite(const int fd, const s64 pos, s64 count,
		const u32 bksize, const void *b)
{
	s64 written, i;

	if (count < 0 || bksize % NTFS_SECTOR_SIZE) {
		errno = EINVAL;
		return -1;
	}
	if (!count)
		return 0;
	/* Prepare data for writing. */
	for (i = 0; i < count; ++i) {
		int err;

		err = ntfs_mst_pre_write_fixup((NTFS_RECORD*)
				((u8*)b + i * bksize), bksize);
		if (err < 0) {
			/* Abort write at this position. */
			if (!i)
				return err;
			count = i;
			break;
		}
	}
	/* Write the prepared data. */
	written = ntfs_pwrite(fd, pos, count * bksize, b);
	/* Quickly deprotect the data again. */
	for (i = 0; i < count; ++i)
		ntfs_mst_post_write_fixup((NTFS_RECORD*)((u8*)b + i * bksize));
	if (written <= 0)
		return written;
	/* Finally, return the number of complete blocks written. */
	return written / bksize;
}

/**
 * ntfs_cluster_read - read ntfs clusters
 * @vol:	volume to read from
 * @lcn:	starting logical cluster number
 * @count:	number of clusters to read
 * @b:		output data buffer
 *
 * Read @count ntfs clusters starting at logical cluster number @lcn from
 * volume @vol into buffer @b. Return number of clusters read or -1 on error,
 * with errno set to the error code.
 */
s64 ntfs_cluster_read(const ntfs_volume *vol, const s64 lcn,
		const s64 count, const void *b)
{
	s64 br;

	if (!vol || lcn < 0 || count < 0) {
		errno = EINVAL;
		return -1;
	}
	if (vol->nr_clusters <= lcn + count) {
		errno = ESPIPE;
		return -1;
	}
	br = ntfs_pread(vol->fd, lcn << vol->cluster_size_bits,
			count << vol->cluster_size_bits, b);
	if (br < 0) {
		Dperror("Error reading cluster(s)");
		return br;
	}
	return br >> vol->cluster_size_bits;
}

/**
 * ntfs_cluster_write - write ntfs clusters
 * @vol:	volume to write to
 * @lcn:	starting logical cluster number
 * @count:	number of clusters to write
 * @b:		data buffer to write to disk
 *
 * Write @count ntfs clusters starting at logical cluster number @lcn from
 * buffer @b to volume @vol. Return the number of clusters written or -1 on
 * error, with errno set to the error code.
 */
s64 ntfs_cluster_write(const ntfs_volume *vol, const s64 lcn,
		const s64 count, const void *b)
{
	s64 bw;

	if (!vol || lcn < 0 || count < 0) {
		errno = EINVAL;
		return -1;
	}
	if (vol->nr_clusters <= lcn + count) {
		errno = ESPIPE;
		return -1;
	}
	if (!NVolReadOnly(vol))
		bw = ntfs_pwrite(vol->fd, lcn << vol->cluster_size_bits,
				count << vol->cluster_size_bits, b);
	else
		bw = count << vol->cluster_size_bits;
	if (bw < 0) {
		Dperror("Error writing cluster(s)");
		return bw;
	}
	return bw >> vol->cluster_size_bits;
}

/**
 * ntfs_device_offset_valid - test if a device offset is valid
 * @f:		open file descriptor of device
 * @ofs:	offset to test for validity
 *
 * Test if the offset @ofs is an existing location on the device described
 * by the open file descriptor @f.
 *
 * Return 0 if it is valid and -1 if it is not valid.
 */
static inline int ntfs_device_offset_valid(int f, s64 ofs)
{
	char ch;

	if (lseek(f, ofs, SEEK_SET) >= 0 && read(f, &ch, 1) == 1)
		return 0;
	return -1;
}

/**
 * ntfs_device_size_get - return the size of a device in blocks
 * @f:		open file descriptor of device
 * @block_size:	block size in bytes in which to return the result
 *
 * Return the number of @block_size sized blocks in the device described by the
 * open file descriptor @f.
 *
 * Adapted from e2fsutils-1.19, Copyright (C) 1995 Theodore Ts'o.
 */
s64 ntfs_device_size_get(int f, int block_size)
{
	s64 high, low;
#ifdef BLKGETSIZE
	long size;

	if (ioctl(f, BLKGETSIZE, &size) >= 0) {
		Dprintf("BLKGETSIZE nr 512 byte blocks = %ld (0x%ld)\n", size,
				size);
		return (s64)size * 512 / block_size;
	}
#endif
#ifdef FDGETPRM
	{       struct floppy_struct this_floppy;

		if (ioctl(f, FDGETPRM, &this_floppy) >= 0) {
			Dprintf("FDGETPRM nr 512 byte blocks = %ld (0x%ld)\n",
					this_floppy.size, this_floppy.size);
			return (s64)this_floppy.size * 512 / block_size;
		}
	}
#endif
	/*
	 * We couldn't figure it out by using a specialized ioctl,
	 * so do binary search to find the size of the device.
	 */
	low = 0LL;
	for (high = 1024LL; !ntfs_device_offset_valid(f, high); high <<= 1)
		low = high;
	while (low < high - 1LL) {
		const s64 mid = (low + high) / 2;

		if (!ntfs_device_offset_valid(f, mid))
			low = mid;
		else
			high = mid;
	}
	lseek(f, 0LL, SEEK_SET);
	return (low + 1LL) / block_size;
}

