/*
 * win32_io.c - A stdio-like disk I/O implementation for low-level disk access
 *		on Win32.  Can access an NTFS volume while it is mounted.
 *		Part of the Linux-NTFS project.
 *
 * Copyright (c) 2003-2004 Lode Leroy
 * Copyright (c) 2003-2004 Anton Altaparmakov
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

#include <windows.h>
#include <winioctl.h>

#include <stdio.h>
#include <ctype.h>
#include <errno.h>

/*
 * Cannot use "../include/types.h" since it conflicts with "wintypes.h".
 * define our own...
 */
typedef long long int s64;
typedef unsigned long int u32;
struct flock;
struct stat;
struct ntfs_volume;
typedef struct ntfs_volume ntfs_volume;

#include "config.h"

/* Need device, but prevent ../include/types.h to be loaded. */
#define _NTFS_TYPES_H
#define _NTFS_SUPPORT_H
#define _NTFS_VOLUME_H
#include "device.h"

#define FORCE_ALIGNED_READ

typedef struct win32_fd {
	HANDLE handle;
	LARGE_INTEGER part_start;
	LARGE_INTEGER part_end;
	LARGE_INTEGER current_pos;
} win32_fd;

#ifdef DEBUG
static __inline__ void Dprintf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}
#else
static __inline__ void Dprintf(const char *fmt, ...) {}
#endif

#define perror(msg) win32_perror(__FILE__,__LINE__,__FUNCTION__,msg)

int win32_perror(char *file, int line, char *func, char *msg)
{
	char buffer[1024] = "";
	DWORD err = GetLastError();

	if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, buffer,
			sizeof(buffer), NULL) <= 0)
		sprintf(buffer, "HRESULT 0x%lx", err);
	fprintf(stderr, "%s(%d): %s\t%s %s\n", file, line, func, buffer, msg);
	return 0;
}

/**
 * ntfs_device_win32_open - open a device
 * @dev:	ntfs device to open
 * @flags:	open flags
 *
 * If name is in format "(hd[0-9],[0-9])" then open a partition.
 * If name is in format "(hd[0-9])" then open a volume.
 * Otherwise open a file.
 */
static int ntfs_device_win32_open(struct ntfs_device *dev, int flags)
{
	int drive = 0, part = 0, numparams;
	HANDLE handle;
	win32_fd fd;
	char drive_char, filename[256];

	numparams = sscanf(dev->d_name, "/dev/hd%c%d", &drive_char, &part);
	drive = toupper(drive_char) - 'A';

	if (numparams >= 1) {
		if (numparams == 2)
			Dprintf("win32_open(%s) -> drive %d, part %d\n",
					dev->d_name, drive, part);
		else
			Dprintf("win32_open(%s) -> drive %d\n", dev->d_name,
					drive);

		sprintf(filename, "\\\\.\\PhysicalDrive%d", drive);

		handle = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ,
				NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM,
				NULL);

		if (handle == INVALID_HANDLE_VALUE) {
			char msg[1024];
			int err = errno;

			sprintf(msg, "CreateFile(%s) failed", filename);
			perror(msg);
			errno = err;
			return -1;
		}

		if (numparams == 1) {
			fd.handle = handle;
			fd.part_start.QuadPart = 0;
			fd.part_end.QuadPart = -1;
			fd.current_pos.QuadPart = 0;
		} else {
			char buffer[10240];
			DWORD numread;
			DRIVE_LAYOUT_INFORMATION *drive_layout;
			BOOL rvl;
			int i;
			int found = 0;

			rvl = DeviceIoControl(handle,
					IOCTL_DISK_GET_DRIVE_LAYOUT, NULL, 0,
					&buffer, sizeof (buffer), &numread,
					NULL);
			if (!rvl) {
				int err = errno;
				perror("ioctl failed");
				errno = err;
				return -1;
			}

			drive_layout = (DRIVE_LAYOUT_INFORMATION *)buffer;

			for (i = 0; i < drive_layout->PartitionCount; i++) {
				if (drive_layout->PartitionEntry[i].
						PartitionNumber == part) {
					fd.handle = handle;
					fd.part_start = drive_layout->
							PartitionEntry[i].
							StartingOffset;
					fd.part_end.QuadPart = drive_layout->
							PartitionEntry[i].
							StartingOffset.
							QuadPart +
							drive_layout->
							PartitionEntry[i].
							PartitionLength.
							QuadPart;
					fd.current_pos.QuadPart = 0;
					found = 1;
					break;
				}
			}

			if (!found) {
				int err = errno;
				fprintf(stderr, "partition %d not found on "
						"drive %d\n", part, drive);
				errno = err;
				return -1;
			}
		}
	} else {
		BY_HANDLE_FILE_INFORMATION info;
		BOOL rvl;

		Dprintf("win32_open(%s) -> file\n", dev->d_name);

		handle = CreateFile(dev->d_name, GENERIC_READ, FILE_SHARE_READ,
				NULL, OPEN_EXISTING, 0, NULL);

		rvl = GetFileInformationByHandle(handle, &info);
		if (!rvl) {
			int err = errno;
			perror("ioctl failed");
			errno = err;
			return -1;
		}

		fd.handle = handle;
		fd.part_start.QuadPart = 0;
		fd.part_end.QuadPart = (((s64) info.nFileSizeHigh) << 32) +
				((s64) info.nFileSizeLow);
		fd.current_pos.QuadPart = 0;
	}

	Dprintf("win32_open(%s) -> %p, offset 0x%llx\n", dev->d_name, dev,
			fd.part_start);

	dev->d_private = malloc(sizeof (win32_fd));
	memcpy(dev->d_private, &fd, sizeof (win32_fd));

	return 0;
}

static s64 ntfs_device_win32_seek(struct ntfs_device *dev, s64 offset,
		int whence)
{
	LARGE_INTEGER abs_offset;
	struct win32_fd *fd = (win32_fd *)dev->d_private;
	int disp;
	BOOL rvl;

	Dprintf("win32_seek(%lld=0x%llx,%d)\n", offset, offset, whence);

	switch (whence) {
	case SEEK_SET:
		disp = FILE_BEGIN;
		abs_offset.QuadPart = fd->part_start.QuadPart + offset;
		break;
	case SEEK_CUR:
		disp = FILE_CURRENT;
		abs_offset.QuadPart = offset;
		break;
	case SEEK_END:
		/* end of partition != end of disk */
		disp = FILE_BEGIN;
		if (fd->part_end.QuadPart == -1) {
			fprintf(stderr, "win32_seek: position relative to end "
					"of disk not implemented\n");
			errno = ENOTSUP;
			return -1;
		}
		abs_offset.QuadPart = fd->part_end.QuadPart + offset;
		break;
	default:
		printf("win32_seek() wrong mode %d\n", whence);
		errno = EINVAL;
		return -1;
	}

	rvl = SetFilePointerEx(fd->handle, abs_offset, &fd->current_pos, disp);
	if (!rvl) {
		int err = errno;
		perror("SetFilePointer failed");
		errno = err;
		return -1;
	}

	return offset;
}

static s64 ntfs_device_win32_read(struct ntfs_device *dev, void *buf, s64 count)
{
	struct win32_fd *fd = (win32_fd *)dev->d_private;
	LARGE_INTEGER base, offset, numtoread;
	DWORD numread = 0;
	BOOL rvl;

	offset.QuadPart = fd->current_pos.QuadPart & 0x1FF;
	base.QuadPart = fd->current_pos.QuadPart - offset.QuadPart;
	numtoread.QuadPart = ((count + offset.QuadPart - 1) | 0x1FF) + 1;

	Dprintf("win32_read(fd=%p,b=%p,count=0x%llx)->(%llx+%llx:%llx)\n", fd,
			buf, count, base, offset, numtoread);

#ifndef FORCE_ALIGNED_READ
	if (((((long)buf) & ((s64)0x1FF)) == 0) && ((count & ((s64)0x1FF)) == 0)
			&& ((fd->current_pos.QuadPart & 0x1FF) == 0)) {
		Dprintf("normal read\n");

		rvl = ReadFile(fd->handle, (LPVOID)buf, count, &numread,
				(LPOVERLAPPED)NULL);
		if (!rvl) {
			int err = errno;
			perror("ReadFile failed");
			errno = err;
			return -1;
		}
	} else {
		BYTE *alignedbuffer;

		Dprintf("aligned read\n");
#else
	{
		BYTE *alignedbuffer;
#endif
		LARGE_INTEGER new_pos;

		alignedbuffer = (BYTE *)VirtualAlloc(NULL, count, MEM_COMMIT,
				PAGE_READWRITE);

		Dprintf("set SetFilePointerEx(%llx)\n", base.QuadPart);

		rvl = SetFilePointerEx(fd->handle, base, NULL, FILE_BEGIN);
		if (!rvl) {
			int err = errno;
			fprintf(stderr, "SetFilePointerEx failed\n");
			VirtualFree(alignedbuffer, 0, MEM_RELEASE);
			errno = err;
			return -1;
		}

		rvl = ReadFile(fd->handle, (LPVOID) alignedbuffer,
				numtoread.QuadPart, &numread,
				(LPOVERLAPPED)NULL);
		if (!rvl) {
			int err = errno;
			fprintf(stderr, "ReadFile failed\n");
			VirtualFree(alignedbuffer, 0, MEM_RELEASE);
			errno = err;
			return -1;
		}
		new_pos.QuadPart = fd->current_pos.QuadPart + count;
		Dprintf("reset SetFilePointerEx(%llx)\n", new_pos.QuadPart);
		rvl = SetFilePointerEx(fd->handle, new_pos, &fd->current_pos,
				FILE_BEGIN);
		if (!rvl) {
			int err = errno;
			fprintf(stderr, "SetFilePointerEx failed\n");
			VirtualFree(alignedbuffer, 0, MEM_RELEASE);
			errno = err;
			return -1;
		}

		memcpy((void *)buf, alignedbuffer + offset.QuadPart, count);
		VirtualFree(alignedbuffer, 0, MEM_RELEASE);
	}

	if (numread > count)
		return count;
	return numread;
}

static int ntfs_device_win32_close(struct ntfs_device *dev)
{
	struct win32_fd *fd = (win32_fd *)dev->d_private;
	BOOL rvl;

	Dprintf("win32_close(%p)\n", dev);

	rvl = CloseHandle(fd->handle);
	fd->handle = 0;

	free(fd);

	if (!rvl) {
		int err = errno;
		perror("CloseHandle failed");
		errno = err;
		return -1;
	}

	return 0;
}

s64 win32_bias(struct ntfs_device *dev)
{
	struct win32_fd *fd = (win32_fd *)dev->d_private;

	return fd->part_start.QuadPart;
}

s64 win32_filepos(struct ntfs_device *dev)
{
	struct win32_fd *fd = (win32_fd *)dev->d_private;

	return fd->current_pos.QuadPart;
}

static int ntfs_device_win32_sync(struct ntfs_device *dev)
{
	fprintf(stderr, "win32_fsync() unimplemented\n");
	errno = ENOTSUP;
	return -1;
}

static s64 ntfs_device_win32_write(struct ntfs_device *dev, const void *buffer,
		s64 count)
{
	fprintf(stderr, "win32_write() unimplemented\n");
	errno = ENOTSUP;
	return -1;
}

static int ntfs_device_win32_stat(struct ntfs_device *dev, struct stat *buf)
{
	fprintf(stderr, "win32_fstat() unimplemented\n");
	errno = ENOTSUP;
	return -1;
}

static int ntfs_device_win32_ioctl(struct ntfs_device *dev, int request,
		void *argp)
{
	fprintf(stderr, "win32_ioctl() unimplemented\n");
	errno = ENOTSUP;
	return -1;
}

extern s64 ntfs_pread(struct ntfs_device *dev, const s64 pos, s64 count,
		void *b);

static s64 ntfs_device_win32_pread(struct ntfs_device *dev, void *buf,
		s64 count, s64 offset)
{
	return ntfs_pread(dev, offset, count, buf);
}

extern s64 ntfs_pwrite(struct ntfs_device *dev, const s64 pos, s64 count,
		const void *b);

static s64 ntfs_device_win32_pwrite(struct ntfs_device *dev, const void *buf,
		s64 count, s64 offset)
{
	return ntfs_pwrite(dev, offset, count, buf);
}

struct ntfs_device_operations ntfs_device_win32_io_ops = {
	.open		= ntfs_device_win32_open,
	.close		= ntfs_device_win32_close,
	.seek		= ntfs_device_win32_seek,
	.read		= ntfs_device_win32_read,
	.write		= ntfs_device_win32_write,
	.pread		= ntfs_device_win32_pread,
	.pwrite		= ntfs_device_win32_pwrite,
	.sync		= ntfs_device_win32_sync,
	.stat		= ntfs_device_win32_stat,
	.ioctl		= ntfs_device_win32_ioctl
};

