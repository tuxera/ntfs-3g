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
struct stat;
struct ntfs_volume;
typedef struct ntfs_volume ntfs_volume;

#include "config.h"
#include "debug.h"

/* Need device, but prevent ../include/types.h to be loaded. */
#define _NTFS_TYPES_H
#define _NTFS_VOLUME_H
#include "device.h"

#ifndef IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
#define IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS 5636096
#endif

/* windows 2k+ imports */
typedef HANDLE (WINAPI *LPFN_FINDFIRSTVOLUME) (LPTSTR,DWORD);
typedef BOOL (WINAPI *LPFN_FINDNEXTVOLUME) (HANDLE,LPTSTR,DWORD);
typedef BOOL (WINAPI *LPFN_FINDVOLUMECLOSE) (HANDLE);
static LPFN_FINDFIRSTVOLUME fnFindFirstVolume = NULL;
static LPFN_FINDNEXTVOLUME fnFindNextVolume = NULL;
static LPFN_FINDVOLUMECLOSE fnFindVolumeClose = NULL;
#ifdef UNICODE
#define FUNCTIONPOSTFIX "W"
#else
#define FUNCTIONPOSTFIX "A"
#endif

#define FORCE_ALIGNED_READ

typedef struct win32_fd {
	HANDLE handle;
	s64 part_start;
	s64 part_end;
	LARGE_INTEGER current_pos;
	int part_hidden_sectors;
} win32_fd;

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
	Dprintf("win32_w32error_to_errno(%d).\n",w32error);
	switch (w32error) {
		case ERROR_INVALID_FUNCTION:
			return ENOSYS;
		case ERROR_FILE_NOT_FOUND:
		case ERROR_PATH_NOT_FOUND:
		case ERROR_INVALID_NAME:
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
		case ERROR_BAD_NETPATH:
			return ENOSHARE;
		default:
			/* generic message */
			return ENOMSG;
	}
}

/**
 * ntfs_device_unix_status_flags_to_win32 - convert unix->win32 open flags
 * @flags:		Unix open status flags.
 *
 * Supported flags are O_RDONLY, O_WRONLY and O_RDWR.
 */
static __inline__ int ntfs_device_unix_status_flags_to_win32(int flags)
{
	switch (flags & O_ACCMODE) {
		case O_RDONLY:
			return FILE_READ_DATA;
			break;
		case O_WRONLY:
			return FILE_WRITE_DATA;
			break;
		case O_RDWR:
			return FILE_READ_DATA | FILE_WRITE_DATA;
			break;
		default:
			/* error */
			Dputs("win32_unix_status_flags_to_win32: flags unknown");
			return 0;
	}
}


/**
 * ntfs_device_win32_simple_open_file - Just open a file via win32 API
 * @filename:	Name of the file to open.
 * @handle:		Pointer the a HADNLE in which to put the result.
 * @flags:		Unix open status flags.
 * @locking:	will the function gain an exclusive lock on the file?
 *
 * Supported flags are O_RDONLY, O_WRONLY and O_RDWR.
 *
 * Return 0 if o.k.
 *        -errno if not, in this case handle is trashed.
 */
static int ntfs_device_win32_simple_open_file(const char *filename,
		HANDLE *handle, int flags, BOOL locking)
{
	*handle = CreateFile(filename,
			ntfs_device_unix_status_flags_to_win32(flags),
			locking ? 0 : (FILE_SHARE_WRITE | FILE_SHARE_READ),
 			NULL, OPEN_EXISTING, 0, NULL);

	if (*handle == INVALID_HANDLE_VALUE) {
		Dprintf("CreateFile(%s) failed.\n", filename);
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
		Dputs("win32_getblksize(): FAILED!");
		errno = ntfs_w32error_to_errno(GetLastError());
		return -errno;
	}
	*argp=((s64)hiword << 32) + (s64)loword;
	return 0;
}

/**
 * ntfs_device_win32_init_imports - initialize the fnFind*Volume variables.
 *
 * The Find*Volume functions exist only on win2k+, as such we can't
 * just staticly import it.
 * This function initialize the imports if the function do exist.
 *
 * Note: The values are cached, do be afraid to run it more than once.
 */
static void ntfs_device_win32_init_imports(void)
{
	if (!fnFindFirstVolume)
		fnFindFirstVolume = (LPFN_FINDFIRSTVOLUME)
			GetProcAddress(GetModuleHandle("kernel32"),
			"FindFirstVolume"FUNCTIONPOSTFIX);
	if (!fnFindNextVolume)
		fnFindNextVolume = (LPFN_FINDNEXTVOLUME)
			GetProcAddress(GetModuleHandle("kernel32"),
			"FindNextVolume"FUNCTIONPOSTFIX);
	if (!fnFindVolumeClose)
		fnFindVolumeClose = (LPFN_FINDVOLUMECLOSE)
			GetProcAddress(GetModuleHandle("kernel32"), "FindVolumeClose");
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

	if ((err = ntfs_device_win32_simple_open_file(filename, &handle, flags,
			TRUE))) {
		/* open error */
 		return err;
	}

	if ((err = ntfs_win32_getsize(handle, &size))) {
		/* error while getting the information */
		Dputs("win32_open_file(): getsize failed.");
		size = -1;
	}
	
	/* fill fd */
	fd->handle = handle;
	fd->part_start = 0;
	fd->part_end = size;
	fd->current_pos.QuadPart = 0;
	fd->part_hidden_sectors = -1;
	return 0;
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

	if ((err = ntfs_device_win32_simple_open_file(filename, &handle, flags,
			TRUE))) {
		/* open error */
 		return err;
	}

	if ((err = ntfs_win32_getsize(handle, &size))) {
		/* error while getting the information */
		Dputs("win32_open_drive(): getsize failed.");
		size = -1;
	}

	/* fill fd */
	fd->handle = handle;
	fd->part_start = 0;
	fd->part_end = size;
	fd->current_pos.QuadPart = 0;
	fd->part_hidden_sectors = -1;
	return 0;
}

/**
 * ntfs_device_win32_open_volume_for_partition - find and open a volume.
 *
 * Windows NT/2k/XP handles volumes instead of partitions.
 * This function gets the partition details and return an open volume handle.
 * That volume is the one whose only physical location on disk is the described
 * partition.
 *
 * The function required Windows 2k/XP, otherwise it fails (gracefully).
 *
 * Return success: a valid open volume handle.
 *        fail   : INVALID_HANDLE_VALUE
 */
static HANDLE ntfs_device_win32_open_volume_for_partition(unsigned int drive_id,
		s64 part_offset, s64 part_length, int flags)
{
	HANDLE vol_find_handle;
	TCHAR vol_name[MAX_PATH];

	ntfs_device_win32_init_imports();
	/* make sure all the required imports exist */
	if (!fnFindFirstVolume || !fnFindNextVolume || !fnFindVolumeClose) {
		Dputs("win32_is_mounted: Imports not found.");
		return INVALID_HANDLE_VALUE;
	}

	/* start iterating through volumes. */
	Dprintf("win32_open_volume_for_partition: Start\n");
	vol_find_handle = fnFindFirstVolume(vol_name, MAX_PATH);

	/* if a valid handle could not be aquired, reply with "don't know" */
	if (vol_find_handle==INVALID_HANDLE_VALUE) {
		Dprintf("win32_open_volume_for_partition: "
				"FindFirstVolume failed.");
		return INVALID_HANDLE_VALUE;
	}

	do {
		int vol_name_length;
		HANDLE handle;

		/* remove trailing '/' from vol_name */
#ifdef UNICODE
		vol_name_length = wcslen(vol_name);
#else
		vol_name_length = strlen(vol_name);
#endif
		if (vol_name_length>0)
			vol_name[vol_name_length-1]=0;

		Dprintf("win32_open_volume_for_partition: Processing %s\n",
				vol_name);

		/* open the file */
		handle = CreateFile(vol_name,
			ntfs_device_unix_status_flags_to_win32(flags), FILE_SHARE_READ |
			FILE_SHARE_WRITE, NULL,	OPEN_EXISTING, 0, NULL);
		if (handle!=INVALID_HANDLE_VALUE) {
#define EXTENTS_SIZE sizeof(VOLUME_DISK_EXTENTS)+9*sizeof(DISK_EXTENT)
			char extents[EXTENTS_SIZE];
			DWORD bytesReturned;

			/* check physical locations */
			if (DeviceIoControl(handle,
					IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, extents,
					EXTENTS_SIZE, &bytesReturned, NULL)) {
				if (((VOLUME_DISK_EXTENTS *)extents)->NumberOfDiskExtents==1) {
					DISK_EXTENT *extent = &((VOLUME_DISK_EXTENTS *)extents)->
						Extents[0];
					if ((extent->DiskNumber==drive_id) &&
						(extent->StartingOffset.QuadPart==part_offset) &&
						(extent->ExtentLength.QuadPart==part_length)) {
						/* Eureka! (Archimedes, 287 BC, "I have found it!") */
						fnFindVolumeClose(vol_find_handle);
						return handle;
					}
				}
			}
		} else
			Dputs("win32_open_volume_for_partition: getExtents "
					"Failed!" );
	} while (fnFindNextVolume(vol_find_handle, vol_name, MAX_PATH));

	/* end of iteration through volumes */
	Dprintf("win32_open_volume_for_partition: Closing.\n");
	fnFindVolumeClose(vol_find_handle);

	return INVALID_HANDLE_VALUE;
}

/**
 * ntfs_device_win32_find_partition - locates partition details by id.
 * @handle			HANDLE to the PhysicalDrive
 * @partition_id	The partition number to locate.
 * @part_offset		Pointer to where to put the offset to the partition.
 * @part_length		Pointer to where to put the length of the partition.
 *
 * This function requires an open PhysicalDrive handle and a partition_id.
 * If a partition with the required id is found on the supplied device,
 * the partition attributes are returned back.
 *
 * Return TRUE  if found, and sets the output parameters.
 *        FALSE if not.
 */
static BOOL ntfs_device_win32_find_partition(HANDLE handle,DWORD partition_id,
		s64 *part_offset, s64 *part_length, int *hidden_sectors)
{
	char buf[sizeof(DRIVE_LAYOUT_INFORMATION)+9*sizeof(PARTITION_INFORMATION)];
	DRIVE_LAYOUT_INFORMATION *drive_layout;
	DWORD bytesReturned, i;

	if (!DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_LAYOUT, NULL, 0,
			&buf, sizeof (buf), &bytesReturned, NULL)) {
		Dputs("win32_find_partition(): GetDriveLayout failed.");
		errno = ntfs_w32error_to_errno(GetLastError());
		return FALSE;
	}

	drive_layout = (DRIVE_LAYOUT_INFORMATION *)buf;
	for (i = 0; i < drive_layout->PartitionCount; i++) {
		if (drive_layout->PartitionEntry[i].PartitionNumber == partition_id) {
			*part_offset =
				drive_layout->PartitionEntry[i].StartingOffset.QuadPart;
			*part_length =
				drive_layout->PartitionEntry[i].PartitionLength.QuadPart;
			*hidden_sectors = drive_layout->PartitionEntry[i].HiddenSectors;
			return TRUE;
		}
	}

	return FALSE;
}

/**
 * ntfs_device_win32_open_partition - Open a partition via win32 API
 * @dev:		NTFS_DEVICE to open
 * @fd:			Win32 file device to return
 * @flags:		Unix open status flags.
 *
 * Return  0 if o.k.
 *        -1 if not
 *
 * When fails, fd contents may have not been preserved.
 */
static __inline__ int ntfs_device_win32_open_partition(int drive_id,
		DWORD partition_id, win32_fd *fd, int flags)
{
	char drive_name[MAX_PATH];
	HANDLE handle;
	int err;
	s64 part_start, part_length;
	int hidden_sectors;

	sprintf(drive_name, "\\\\.\\PhysicalDrive%d", drive_id);

	/* Open the entire device without locking, ask questions later */
	if ((err = ntfs_device_win32_simple_open_file(drive_name, &handle, flags,
			FALSE))) {
	/* error */
		return err;
	}

	if (ntfs_device_win32_find_partition(handle, partition_id, &part_start,
			&part_length, &hidden_sectors)) {
		HANDLE vol_handle = ntfs_device_win32_open_volume_for_partition(
			drive_id, part_start, part_length, flags);
		if (vol_handle!=INVALID_HANDLE_VALUE) {
			BOOL retVal;
			DWORD bytesReturned;
			
			/* close the disk handle, we do not need it anymore */
			CloseHandle(handle);

			if ((flags & O_RDWR) == O_RDWR) {
				/* lock the volume */
				Dputs("win32_open_partition: Locking volume");
				retVal = DeviceIoControl(vol_handle, FSCTL_LOCK_VOLUME, NULL, 0,
						NULL, 0, &bytesReturned, NULL);
				if (!retVal) {
					Dputs("win32_open_partition: Couldn't lock volume");
					errno = ntfs_w32error_to_errno(GetLastError());
					return -1;
				} else
					Dputs("win32_open_partition: Lock O.k.");

				/* dismount volume */
				retVal = DeviceIoControl(vol_handle, FSCTL_DISMOUNT_VOLUME,
						NULL, 0, NULL, 0, &bytesReturned, NULL);
				if (!retVal) {
					Dputs("win32_open_partition: Couldn't Dismount");
					errno = ntfs_w32error_to_errno(GetLastError());
					return -1;
				} else
					Dputs("win32_open_partition: Dismount O.k.");
			}

			/* fill fd */
			fd->handle = vol_handle;
			fd->part_start = 0;
   			fd->part_end = part_length;
			fd->current_pos.QuadPart = 0;
			fd->part_hidden_sectors = hidden_sectors;
			return 0;
		} else {
			if ((flags & O_RDWR) == O_RDWR) {
				/* access if read-write, no volume found */
				Dputs("Partitions containing Spanned/Mirrored volumes are "
					  "not supported in R/W status yet");
				CloseHandle(handle);
				return -1;
			} else {
				/* fill fd */
				fd->handle = handle;
				fd->part_start = part_start;
				fd->part_end = part_start + part_length;
				fd->current_pos.QuadPart = 0;
				fd->part_hidden_sectors = hidden_sectors;
				return 0;
			}
		}
	} else {
		Dprintf("partition %u not found on drive %d\n",	partition_id, drive_id);
		CloseHandle(handle);
		errno = ENODEV;
 		return -1;
	}
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

	if (NDevOpen(dev)) {
		errno = EBUSY;
		return -1;
	}

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

	/* Setup our read-only flag. */
	if ((flags & O_RDWR) != O_RDWR)
		NDevSetReadOnly(dev);

	dev->d_private = malloc(sizeof (win32_fd));
	memcpy(dev->d_private, &fd, sizeof (win32_fd));

	NDevSetOpen(dev);
	NDevClearDirty(dev);

	return 0;
}

/**
 * ntfs_device_win32_seek - Change current file position.
 * @handle:		Pointer the file HADNLE obtained via open.
 * @offset:		Required offset from the whence anchor.
 * @whence:		May be one of the following:
 *		SEEK_SET	Offset is relative to file start.
 *		SEEK_CUR	Offset is relative to current position.
 *		SEEK_END	Offset is relative to end of file.
 *
 * Return 0 if o.k.
 *        -errno if not, in this case handle is trashed.
 */
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
			Dputs("win32_seek: position relative to end "
					"of disk not implemented.");
			errno = ENOTSUP;
			return -1;
		}
		abs_offset.QuadPart = fd->part_end + offset;
		break;
	default:
		Dprintf("win32_seek() wrong mode %d.\n", whence);
		errno = EINVAL;
		return -1;
	}

	rvl = SetFilePointerEx(fd->handle, abs_offset, &fd->current_pos, disp);
	if (!rvl) {
		Dputs("win32_seek(): SetFilePointer failed.");
		errno = ntfs_w32error_to_errno(GetLastError());
		return -1;
	}

	return offset;
}

/**
 * ntfs_device_win32_read - Read 'count' bytes from 'dev' into 'buf'.
 * @dev:		An NTFS_DEVICE obtained via the open command.
 * @buf:		A pointer to where to put the contents.
 * @count:		How many bytes should be read.
 *
 * On success returns the amount of bytes actually read.
 * On fail returns -errno.
 */
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
		Dputs("normal read.");

		rvl = ReadFile(fd->handle, (LPVOID)buf, count, &numread,
				(LPOVERLAPPED)NULL);
		if (!rvl) {
			Dputs("win32_read(): ReadFile failed.");
			errno = ntfs_w32error_to_errno(GetLastError());
			return -1;
		}
	} else {
		BYTE *alignedbuffer;

		Dputs("aligned read.");
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
			Dputs("win32_read(): SetFilePointerEx failed.");
			errno = ntfs_w32error_to_errno(GetLastError());
			VirtualFree(alignedbuffer, 0, MEM_RELEASE);
			return -1;
		}

		rvl = ReadFile(fd->handle, (LPVOID) alignedbuffer,
				numtoread.QuadPart, &numread,
				(LPOVERLAPPED)NULL);
		if (!rvl) {
			Dputs("win32_read(): ReadFile failed.");
			errno = ntfs_w32error_to_errno(GetLastError());
			VirtualFree(alignedbuffer, 0, MEM_RELEASE);
			return -1;
		}
		new_pos.QuadPart = fd->current_pos.QuadPart + count;
		Dprintf("reset SetFilePointerEx(%llx)\n", new_pos.QuadPart);
		rvl = SetFilePointerEx(fd->handle, new_pos, &fd->current_pos,
				FILE_BEGIN);
		if (!rvl) {
			Dputs("win32_read(): SetFilePointerEx failed.");
			errno = ntfs_w32error_to_errno(GetLastError());
			VirtualFree(alignedbuffer, 0, MEM_RELEASE);
			return -1;
		}

		memcpy((void *)buf, alignedbuffer + offset.QuadPart, count);
		VirtualFree(alignedbuffer, 0, MEM_RELEASE);
	}

	if (numread > count)
		return count;
	return numread;
}

/**
 * ntfs_device_win32_close - Close an open NTFS_DEVICE and
 *		free internal buffers.
 * @dev:		An NTFS_DEVICE obtained via the open command.
 *
 * Return 0 if o.k.
 *        -errno if not, in this case handle is trashed.
 */
static int ntfs_device_win32_close(struct ntfs_device *dev)
{
	struct win32_fd *fd = (win32_fd *)dev->d_private;
	BOOL rvl;

	Dprintf("win32_close(%p)\n", dev);

	if (!NDevOpen(dev)) {
		errno = EBADF;
		return -errno;
	}

	rvl = CloseHandle(fd->handle);
	fd->handle = 0;

	free(fd);

	if (!rvl) {
		Dputs("win32_close: CloseHandle failed.");
		errno = ntfs_w32error_to_errno(GetLastError());
		return -1;
	}

	return 0;
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
	if (!NDevReadOnly(dev) && NDevDirty(dev)) {
		if (FlushFileBuffers(((win32_fd *)dev->d_private)->handle)) {
			NDevClearDirty(dev);
	 		return 0;
		} else {
			errno = ntfs_w32error_to_errno(GetLastError());
			return -errno;
		}
	} else {
		/* no need/ability for a sync(), just exit gracefully */
		return 0;
	}
}

/**
 * ntfs_device_win32_write - Write 'count' bytes from 'buf' into 'dev'.
 * @dev:		An NTFS_DEVICE obtained via the open command.
 * @buf:		A pointer to the contents.
 * @count:		How many bytes should be written.
 *
 * On success returns the amount of bytes actually written.
 * On fail returns -1 and errno set.
 */
static s64 ntfs_device_win32_write(struct ntfs_device *dev, const void *buf,
		s64 count)
{
	s64 bytes_written = 0;
	HANDLE handle = ((win32_fd *)dev->d_private)->handle;

	Dprintf("win32_write: Writing %ll bytes\n",count);
	
	if (NDevReadOnly(dev)) {
		Dputs("win32_write: Device R/O, exiting.");
		errno = EROFS;
		return -1;
	}
	NDevSetDirty(dev);

	while (count>0) {
		DWORD cur_written;
		DWORD cur_count = (count>32768)?32768:count;

		if (WriteFile(handle, buf, cur_count, &cur_written, NULL) &&
		    (cur_written==cur_count)) {
			Dprintf("win32_write: Written %u bytes.",bytes_written);
			bytes_written += cur_written;
			count -= cur_written;
		} else {
			/* error */
			errno = ntfs_w32error_to_errno(GetLastError());
			return -1;
		}
	}
	if (count) {
		errno = EIO;
		return -1;
	} else {
		return bytes_written;
	}
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
		Dputs("win32_stat(): getsize failed.");

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
		Dputs("win32_hdio_getgeo(): Not a partition, unimplemented.");
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
		Dputs("win32_blksszget(): FAILED!");
		errno = ntfs_w32error_to_errno(GetLastError());
		return -errno;
	}
}

static int ntfs_device_win32_ioctl(struct ntfs_device *dev, int request,
		void *argp)
{
	win32_fd *fd = (win32_fd *)dev->d_private;

	Dprintf("win32_ioctl(%d) called.\n",request);

	switch (request) {
#if defined(BLKGETSIZE)
		case BLKGETSIZE:
			Dputs("win32_ioctl: BLKGETSIZE detected.");
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
			Dputs("win32_ioctl: BLKGETSIZE64 detected.");
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
			Dputs("win32_ioctl: HDIO_GETGEO detected.");
			return ntfs_win32_hdio_getgeo(dev,(struct hd_geometry *)argp);
#endif
#ifdef BLKSSZGET
		case BLKSSZGET:
			Dputs("win32_ioctl: BLKSSZGET detected.");
			return ntfs_win32_blksszget(dev,(int *)argp);
			break;
#endif
		default:
			Dprintf("win32_ioctl(): unimplemented ioctl %d.\n",
					request);
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
