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
#include <fcntl.h>

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
#include "debug.h"

/* Need device, but prevent ../include/types.h to be loaded. */
#define _NTFS_TYPES_H
#define _NTFS_SUPPORT_H
#define _NTFS_VOLUME_H
#include "device.h"

#define FORCE_ALIGNED_READ

typedef struct win32_fd {
	HANDLE handle;
	s64 part_start;
	s64 part_end;
	LARGE_INTEGER current_pos;
	int part_hidden_sectors;
} win32_fd;

#define perror(msg) win32_perror(__FILE__,__LINE__,__FUNCTION__,msg)

static int win32_perror(const char *file, int line, const char *func,
		const char *msg)
{
	char buffer[1024] = "";
	DWORD err = GetLastError();

	if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, buffer,
			sizeof(buffer), NULL) <= 0)
		sprintf(buffer, "HRESULT 0x%lx", err);
	fprintf(stderr, "%s(%d): %s\t%s %s\n", file, line, func, buffer, msg);
	return 0;
}

#ifdef EMULATE_SETFILEPOINTEREX
static BOOL WINAPI SetFilePointerEx(HANDLE hFile,
		LARGE_INTEGER liDistanceToMove,
		PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod)
{
	liDistanceToMove.LowPart = SetFilePointer(hFile,
			liDistanceToMove.LowPart, &liDistanceToMove.HighPart,
			dwMoveMethod);
	if (liDistanceToMove.LowPart == INVALID_SET_FILE_POINTER &&
			GetLastError() != NO_ERROR) {
		lpNewFilePointer->QuadPart = -1;
		return FALSE;
	}
	lpNewFilePointer->QuadPart = liDistanceToMove.QuadPart;
	return TRUE;
}
#endif

/**
 * ntfs_w32error_to_errno - Convert a win32 error code to the unix one
 * @w32error	The win32 error code.
 *
 * Limited to a reletevly small but useful number of codes
 */
static int ntfs_w32error_to_errno(DWORD w32error)
{
	switch (w32error) {
		case ERROR_FILE_NOT_FOUND:
		case ERROR_PATH_NOT_FOUND:
			return ENOENT;
		case ERROR_TOO_MANY_OPEN_FILES:
			return EMFILE;
		case ERROR_ACCESS_DENIED:
			return EACCES;
		case ERROR_INVALID_HANDLE:
			return EBADF;
		case ERROR_NOT_ENOUGH_MEMORY:
			return ENOMEM;
		case ERROR_OUTOFMEMORY:
			return ENOSPC;
		case ERROR_INVALID_DRIVE:
		case ERROR_BAD_UNIT:
			return ENODEV;
		case ERROR_WRITE_PROTECT:
			return EROFS;
		case ERROR_NOT_READY:
			return EBUSY;
		case ERROR_BAD_COMMAND:
			return EINVAL;
		case ERROR_SEEK:
			return ESPIPE;
		case ERROR_NOT_SUPPORTED:
			return ENOTSUP;
		default:
			/* generic message */
			return ENOMSG;
	}
}

/**
 * ntfs_device_win32_simple_open_file - Just open a file via win32 API
 * @filename:	Name of the file to open.
 * @handle:		Pointer the a HADNLE in which to put the result.
 * @flags:		Unix open status flags.
 *
 * Supported flags are O_RDONLY, O_WRONLY and O_RDWR.
 *
 * Return 0 if o.k.
 *        -errno if not, in this case handle is trashed.
 */
static int ntfs_device_win32_simple_open_file(char *filename,
		HANDLE *handle, int flags)
{
	int win32flags;

	switch (flags && O_ACCMODE) {
		case O_RDONLY:
			win32flags = FILE_READ_DATA;
			break;
		case O_WRONLY:
/*			win32flags = FILE_WRITE_DATA;
			break; */
		case O_RDWR:
/*			win32flags = FILE_READ_DATA || FILE_WRITE_DATA;
			break; */
			errno = ENOTSUP;
			return -errno;
		default:
			/* error */
			return -EINVAL;
	}

	*handle = CreateFile(filename, win32flags, FILE_SHARE_READ,
			NULL, OPEN_EXISTING, 0, NULL);

	if (*handle == INVALID_HANDLE_VALUE) {
		char msg[1024];

		sprintf(msg, "CreateFile(%s) failed", filename);
		perror(msg);
		errno = ntfs_w32error_to_errno(GetLastError());

 		return -errno;
	} else {
		return 0;
	}
}

/**
 * ntfs_win32_getsize - Get file size via win32 API
 * @handle:		Pointer the file HADNLE obtained via open.
 * @argp:		Pointer to result buffer.
 *
 * Return 0 if o.k.
 *        -errno if not, in this case handle is trashed.
 */
static int ntfs_win32_getsize(HANDLE handle,s64 *argp)
{
	DWORD loword, hiword;

	loword = GetFileSize(handle, &hiword);
	if (loword==INVALID_FILE_SIZE) {
		perror("ntfs_win32_getblksize(): FAILED!");
		errno = ntfs_w32error_to_errno(GetLastError());
		return -errno;
	}
	*argp=((s64)hiword << 32) + (s64)loword;
	return 0;
}

/**
 * ntfs_device_win32_open_file - Open a file via win32 API
 * @filename:	Name of the file to open.
 * @fd:			Pointer to win32 file device in which to put the result.
 * @flags:		Unix open status flags.
 *
 * Return 0 if o.k.
 *        -errno if not
 */
static __inline__ int ntfs_device_win32_open_file(char *filename, win32_fd *fd,
		int flags)
{
	HANDLE handle;
	s64 size;
	int err;

	if ((err = ntfs_device_win32_simple_open_file(filename, &handle, flags))) {
		/* open error */
 		return err;
	}

	if ((err = ntfs_win32_getsize(handle, &size))) {
		/* error while getting the information */
		perror("ioctl failed");
		errno = err;
		return -err;
	} else {
		/* success */
		fd->handle = handle;
		fd->part_start = 0;
		fd->part_end = size;
		fd->current_pos.QuadPart = 0;
		fd->part_hidden_sectors = -1;
		return 0;
	}
}

/**
 * ntfs_device_win32_open_drive - Open a drive via win32 API
 * @dev:		NTFS_DEVICE to open
 * @handle:		Win32 file handle to return
 * @flags:		Unix open status flags.
 *
 * return 0 if o.k.
 *        -errno if not
 */
static __inline__ int ntfs_device_win32_open_drive(int drive_id, win32_fd *fd,
		int flags)
{
	char filename[256];
	HANDLE handle;
	s64 size;
	int err;

	sprintf(filename, "\\\\.\\PhysicalDrive%d", drive_id);

	if ((err = ntfs_device_win32_simple_open_file(filename, &handle, flags))) {
		/* open error */
 		return err;
	}

	if ((err = ntfs_win32_getsize(handle, &size))) {
		/* error while getting the information */
		perror("ioctl failed");
		errno = err;
		return -err;
	} else {
		/* success */
		fd->handle = handle;
		fd->part_start = 0;
		fd->part_end = size;
		fd->current_pos.QuadPart = 0;
		fd->part_hidden_sectors = -1;
		return 0;
	}
}

/**
 * ntfs_device_win32_open_partition - Open a partition via win32 API
 * @dev:		NTFS_DEVICE to open
 * @fd:			Win32 file device to return
 * @flags:		Unix open status flags.
 *
 * Return 0 if o.k.
 *        -errno if not
 *
 * When fails, fd contents may have not been preserved.
 */
static __inline__ int ntfs_device_win32_open_partition(int drive_id,
		unsigned int partition_id, win32_fd *fd, int flags)
{
	DRIVE_LAYOUT_INFORMATION *drive_layout;
	char buffer[10240];
	unsigned int i;
	DWORD numread;
	HANDLE handle;
	int err;

	sprintf(buffer, "\\\\.\\PhysicalDrive%d", drive_id);

	if ((err = ntfs_device_win32_simple_open_file(buffer, &handle, flags))) {
		/* error */
		return err;
	}

	if (!DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_LAYOUT, NULL, 0,
			&buffer, sizeof (buffer), &numread,	NULL)) {
		perror("ioctl failed");
		errno = ntfs_w32error_to_errno(GetLastError());
		return -errno;
	}

	drive_layout = (DRIVE_LAYOUT_INFORMATION *)buffer;
	for (i = 0; i < drive_layout->PartitionCount; i++) {
		if (drive_layout->PartitionEntry[i].PartitionNumber == partition_id) {
			fd->handle = handle;
			fd->part_start =
				drive_layout->PartitionEntry[i].StartingOffset.QuadPart;
			fd->part_end =
				drive_layout->PartitionEntry[i].StartingOffset.QuadPart +
				drive_layout->PartitionEntry[i].PartitionLength.QuadPart;
			fd->current_pos.QuadPart = 0;
			fd->part_hidden_sectors =
				drive_layout->PartitionEntry[i].HiddenSectors;
			return 0;
		}
	}

	fprintf(stderr,"partition %u not found on drive %d\n",
		partition_id, drive_id);
	errno = ENODEV;
	return -ENODEV;
}

/**
 * ntfs_device_win32_open - Open a device
 * @dev:		A pointer to the NTFS_DEVICE to open
 *					dev->d_name must hold the device name, the rest is ignored.
 * @flags:		Unix open status flags.
 *
 * Supported flags are O_RDONLY, O_WRONLY and O_RDWR.
 *
 * If name is in format "(hd[0-9],[0-9])" then open a partition.
 * If name is in format "(hd[0-9])" then open a volume.
 * Otherwise open a file.
 */
static int ntfs_device_win32_open(struct ntfs_device *dev, int flags)
{
	int drive_id = 0, numparams;
	unsigned int part = 0;
	char drive_char;
	win32_fd fd;
	int err;

	numparams = sscanf(dev->d_name, "/dev/hd%c%u", &drive_char, &part);
	drive_id = toupper(drive_char) - 'A';

	switch (numparams) {
		case 0:
			Dprintf("win32_open(%s) -> file\n", dev->d_name);
			err = ntfs_device_win32_open_file(dev->d_name,&fd,flags);
			break;
		case 1:
			Dprintf("win32_open(%s) -> drive %d\n", dev->d_name, drive_id);
			err = ntfs_device_win32_open_drive(drive_id,&fd,flags);
			break;
		case 2:
			Dprintf("win32_open(%s) -> drive %d, part %u\n",
					dev->d_name, drive_id, part);
			err = ntfs_device_win32_open_partition(drive_id,part,&fd,flags);
			break;
		default:
			Dprintf("win32_open(%s) -> unknwon file format\n", dev->d_name);
			err = -1;
			break;
	}

	if (err) {
		/* error */
		return err;
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
		abs_offset.QuadPart = fd->part_start + offset;
		break;
	case SEEK_CUR:
		disp = FILE_CURRENT;
		abs_offset.QuadPart = offset;
		break;
	case SEEK_END:
		/* end of partition != end of disk */
		disp = FILE_BEGIN;
		if (fd->part_end == -1) {
			fprintf(stderr, "win32_seek: position relative to end "
					"of disk not implemented\n");
			errno = ENOTSUP;
			return -1;
		}
		abs_offset.QuadPart = fd->part_end + offset;
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

static s64 win32_bias(struct ntfs_device *dev)
{
	struct win32_fd *fd = (win32_fd *)dev->d_private;

	return fd->part_start;
}

static s64 win32_filepos(struct ntfs_device *dev)
{
	struct win32_fd *fd = (win32_fd *)dev->d_private;

	return fd->current_pos.QuadPart;
}

/**
 * ntfs_device_win32_sync - Flush write buffers to disk.
 * @dev:		An NTFS_DEVICE obtained via the open command.
 *
 * Return 0 if o.k.
 *        -errno if not, in this case handle is trashed.
 */
static int ntfs_device_win32_sync(struct ntfs_device *dev)
{
	if (FlushFileBuffers(((win32_fd *)dev->d_private)->handle)) {
 		return 0;
	} else {
		errno = ntfs_w32error_to_errno(GetLastError());
		return -errno;
	}
}

static s64 ntfs_device_win32_write(struct ntfs_device *dev, const void *buffer,
		s64 count)
{
	fprintf(stderr, "win32_write() unimplemented\n");
	errno = ENOTSUP;
	return -1;
}

/**
 * ntfs_device_win32_stat - Get a Unix-like stat structure for the file.
 * @dev:		An NTFS_DEVICE obtained via the open command.
 * @argp:		A pointer to where to put the output.
 *
 * Only st_mode & st_size are filled.
 *
 * Return 0 if o.k.
 *        -errno if not, in this case handle is trashed.
 */
static int ntfs_device_win32_stat(struct ntfs_device *dev, struct stat *buf)
{
	mode_t st_mode;
	s64 st_size = 0;
	int ret;

	switch (GetFileType(((win32_fd *)dev->d_private)->handle)) {
		case FILE_TYPE_CHAR:
			st_mode = S_IFCHR;
		case FILE_TYPE_DISK:
			st_mode = S_IFBLK;
		case FILE_TYPE_PIPE:
			st_mode = S_IFIFO;
		default:
			st_mode = 0;
	}

	ret = ntfs_win32_getsize(dev,&st_size);
	if (ret)
		Dprintf("ntfs_device_win32_stat(): getsize failed");

	memset(buf,0,sizeof (struct stat));
	buf->st_mode = st_mode;
	buf->st_size = st_size;

	return 0;
}

/**
 * ntfs_win32_hdio_getgeo - Get drive geometry.
 * @dev:		An NTFS_DEVICE obtained via the open command.
 * @argp:		A pointer to where to put the output.
 *
 * Requires windows NT/2k/XP only
 *
 * Currently only the 'start' field is filled
 *
 * Return 0 if o.k.
 *        -errno if not, in this case handle is trashed.
 */
static __inline__ int ntfs_win32_hdio_getgeo(struct ntfs_device *dev,
		struct hd_geometry *argp)
{
	win32_fd *fd;

  	fd = (win32_fd *)dev->d_private;

	if (fd->part_hidden_sectors==-1) {
		/* not a partition */
		Dprintf("ntfs_win32_hdio_getgeo(): error: not a partition");
		fprintf(stderr, "ntfs_win32_hdio_getgeo(): unimplemented\n");
		errno = ENOTSUP;
		return -1;
	} else {
		/* only fake the 'start' value, others are unsupported */
		/* heads are returned by disk_int13_info on winXP only */
		argp->heads = -1;
		argp->sectors = -1;
		argp->cylinders = -1;
		argp->start = fd->part_hidden_sectors;
		return 0;
	}
}

/**
 * ntfs_win32_blksszget - Get block device sector size.
 * @dev:		An NTFS_DEVICE obtained via the open command.
 * @argp:		A pointer to where to put the output.
 *
 * Works on windows NT/2k/XP only
 *
 * Return 0 if o.k.
 *        -errno if not, in this case handle is trashed.
 */
static __inline__ int ntfs_win32_blksszget(struct ntfs_device *dev,int *argp)
{
	win32_fd *fd;
	DISK_GEOMETRY dg;
	DWORD bytesReturned;

  	fd = (win32_fd *)dev->d_private;

 	if (DeviceIoControl(fd->handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
 			&dg, sizeof(DISK_GEOMETRY), &bytesReturned, NULL)) {
		/* success */
		*argp=dg.BytesPerSector;
		return 0;
	} else {
		perror("ntfs_win32_blksszget(): FAILED!");
		errno = ntfs_w32error_to_errno(GetLastError());
		return -errno;
	}
}

static int ntfs_device_win32_ioctl(struct ntfs_device *dev, int request,
		void *argp)
{
	win32_fd *fd = (win32_fd *)dev->d_private;

	fprintf(stderr, "win32_ioctl(%d) called\n",request);

	switch (request) {
#if defined(BLKGETSIZE)
		case BLKGETSIZE:
			Dprintf("win32_ioctl: BLKGETSIZE detected");
			if ((fd->part_end>=0) && (fd->part_start>=0)) {
				*(int *)argp = (int)((fd->part_end - fd->part_start) / 512);
				return 0;
			} else {
   				errno = ENOTSUP;
				return -ENOTSUP;
			}
#endif
#if defined(BLKGETSIZE64)
		case BLKGETSIZE64:
			Dprintf("win32_ioctl: BLKGETSIZE64 detected");
			if ((fd->part_end>=0) && (fd->part_start>=0)) {
				*(s64 *)argp = (s64)(fd->part_end -	fd->part_start);
				return 0;
			} else {
   				errno = ENOTSUP;
				return -ENOTSUP;
			}
#endif
#ifdef HDIO_GETGEO
		case HDIO_GETGEO:
			Dprintf("win32_ioctl: HDIO_GETGEO detected");
			return ntfs_win32_hdio_getgeo(dev,(struct hd_geometry *)argp);
#endif
#ifdef BLKSSZGET
		case BLKSSZGET:
			Dprintf("win32_ioctl: BLKSSZGET detected");
			return ntfs_win32_blksszget(dev,(int *)argp);
			break;
#endif
		default:
			fprintf(stderr, "win32_ioctl(): unimplemented ioctl %d\n",request);
			errno = ENOTSUP;
			return -1;
	}
}

static s64 ntfs_device_win32_pread(struct ntfs_device *dev, void *buf,
		s64 count, s64 offset)
{
	return ntfs_pread(dev, offset, count, buf);
}

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
