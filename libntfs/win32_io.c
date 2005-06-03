/*
 * win32_io.c - A stdio-like disk I/O implementation for low-level disk access
 *		on Win32.  Can access an NTFS volume while it is mounted.
 *		Part of the Linux-NTFS project.
 *
 * Copyright (c) 2003-2004 Lode Leroy
 * Copyright (c) 2003-2005 Anton Altaparmakov
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
typedef long long s64;
typedef unsigned long u32;
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

/* Windows 2k+ imports. */
typedef HANDLE (WINAPI *LPFN_FINDFIRSTVOLUME)(LPTSTR, DWORD);
typedef BOOL (WINAPI *LPFN_FINDNEXTVOLUME)(HANDLE, LPTSTR, DWORD);
typedef BOOL (WINAPI *LPFN_FINDVOLUMECLOSE)(HANDLE);
typedef BOOL (WINAPI *LPFN_SETFILEPOINTEREX)(HANDLE, LARGE_INTEGER,
		PLARGE_INTEGER, DWORD);

static LPFN_FINDFIRSTVOLUME fnFindFirstVolume = NULL;
static LPFN_FINDNEXTVOLUME fnFindNextVolume = NULL;
static LPFN_FINDVOLUMECLOSE fnFindVolumeClose = NULL;
static LPFN_SETFILEPOINTEREX fnSetFilePointerEx = NULL;

#ifdef UNICODE
#define FNPOSTFIX "W"
#else
#define FNPOSTFIX "A"
#endif

typedef struct win32_fd {
	HANDLE handle;
	int part_hidden_sectors;
	s64 part_start;
	s64 part_length;
	s64 real_pos;
	int real_ofs;
	s64 geo_size, geo_cylinders;
	DWORD geo_sectors, geo_heads;
	HANDLE vol_handle;
} win32_fd;

/**
 * ntfs_w32error_to_errno - Convert a win32 error code to the unix one
 * @w32error	The win32 error code.
 *
 * Limited to a relatively small but useful number of codes.
 */
static int ntfs_w32error_to_errno(unsigned int w32error)
{
	Dprintf("win32_w32error_to_errno(%d).\n",w32error);
	switch (w32error) {
		case ERROR_INVALID_FUNCTION:
			return EBADRQC;
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
		case ERROR_SHARING_VIOLATION:
			return EBUSY;
		case ERROR_BAD_COMMAND:
			return EINVAL;
		case ERROR_SEEK:
		case ERROR_NEGATIVE_SEEK:
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
 * libntfs_SetFilePointerEx - emulation for SetFilePointerEx()
 *
 * We use this to emulate SetFilePointerEx() when it is not present.  This can
 * happen since SetFilePointerEx() only exists in Win2k+.
 */
static BOOL WINAPI libntfs_SetFilePointerEx(HANDLE hFile,
		LARGE_INTEGER liDistanceToMove,
		PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod)
{
	liDistanceToMove.LowPart = SetFilePointer(hFile,
			liDistanceToMove.LowPart, &liDistanceToMove.HighPart,
			dwMoveMethod);
	if (liDistanceToMove.LowPart == INVALID_SET_FILE_POINTER &&
			GetLastError() != NO_ERROR) {
		if (lpNewFilePointer)
			lpNewFilePointer->QuadPart = -1;
		return FALSE;
	}
	if (lpNewFilePointer)
		lpNewFilePointer->QuadPart = liDistanceToMove.QuadPart;
	return TRUE;
}

/**
 * ntfs_device_win32_init_imports - initialize the function pointers.
 *
 * The Find*Volume and SetFilePointerEx functions exist only on win2k+, as such
 * we cannot just staticly import them.
 * 
 * This function initializes the imports if the functions do exist and in the
 * SetFilePointerEx case, we emulate the function ourselves if it is not
 * present.
 *
 * Note: The values are cached, do be afraid to run it more than once.
 */
static void ntfs_device_win32_init_imports(void)
{
	HMODULE kernel32 = GetModuleHandle("kernel32");
	if (!kernel32) {
		errno = ntfs_w32error_to_errno(GetLastError());
		Dputs("Error: kernel32.dll not found in memory.");
	}
	if (!fnSetFilePointerEx) {
		if (kernel32)
			fnSetFilePointerEx = (LPFN_SETFILEPOINTEREX)
					GetProcAddress(kernel32,
					"SetFilePointerEx");
		/*
		 * If we did not get kernel32.dll or it is not Win2k+, emulate
		 * SetFilePointerEx().
		 */
		if (!fnSetFilePointerEx) {
			Dputs("SetFilePonterEx() not found in kernel32.dll: "
					"Enabling emulation.");
			fnSetFilePointerEx = libntfs_SetFilePointerEx;
		}
	}
	/* Cannot do lookups if we could not get kernel32.dll... */
	if (!kernel32)
		return;
	if (!fnFindFirstVolume)
		fnFindFirstVolume = (LPFN_FINDFIRSTVOLUME)
				GetProcAddress(kernel32, "FindFirstVolume"
				FNPOSTFIX);
	if (!fnFindNextVolume)
		fnFindNextVolume = (LPFN_FINDNEXTVOLUME)
				GetProcAddress(kernel32, "FindNextVolume"
				FNPOSTFIX);
	if (!fnFindVolumeClose)
		fnFindVolumeClose = (LPFN_FINDVOLUMECLOSE)
				GetProcAddress(kernel32, "FindVolumeClose");
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
 * @handle:		Pointer the a HANDLE in which to put the result.
 * @flags:		Unix open status flags.
 * @locking:	will the function gain an exclusive lock on the file?
 *
 * Supported flags are O_RDONLY, O_WRONLY and O_RDWR.
 *
 * Return 0 if o.k.
 *	 -1 if not, and errno set. in this case handle is trashed.
 */
static int ntfs_device_win32_simple_open_file(const char *filename,
		HANDLE *handle, int flags, BOOL locking)
{
	*handle = CreateFile(filename,
			ntfs_device_unix_status_flags_to_win32(flags),
			locking ? 0 : (FILE_SHARE_WRITE | FILE_SHARE_READ),
 			NULL, OPEN_EXISTING, 0, NULL);

	if (*handle == INVALID_HANDLE_VALUE) {
		errno = ntfs_w32error_to_errno(GetLastError());
		Dprintf("CreateFile(%s) failed.\n", filename);
 		return -1;
	}
	return 0;
}

/**
 * ntfs_device_win32_lock - Lock the volume
 * @handle:	A win32 HANDLE for a volume to lock.
 *
 * Locking a volume means no one can access its contents.
 * Exiting the process automatically unlocks the volume, except in old NT4s.
 *
 * Return 0 if o.k.
 *	 -1 if not, and errno set.
 */
static int ntfs_device_win32_lock(HANDLE handle)
{
	DWORD i;
	if (!DeviceIoControl(handle, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &i,
			NULL)) {
		errno = ntfs_w32error_to_errno(GetLastError());
		Dputs("Error: Couldn't lock volume.");
		return -1;
	}
	Dputs("Volume locked.");
	return 0;
}

/**
 * ntfs_device_win32_unlock - Unlock the volume
 * @handle:	The win32 HANDLE which the volume was locked with.
 *
 * Return 0 if o.k.
 *	 -1 if not, and errno set.
 */
static int ntfs_device_win32_unlock(HANDLE handle)
{
	DWORD i;
	if (!DeviceIoControl(handle, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &i,
			NULL)) {
		errno = ntfs_w32error_to_errno(GetLastError());
		Dputs("Error: Couldn't unlock volume.");
		return -1;
	}
	Dputs("Volume unlocked.");
	return 0;
}

/**
 * ntfs_device_win32_dismount - Dismount a volume
 * @handle:	A win32 HANDLE for a volume to dismount.
 *
 * Dismounting means the system will refresh the volume in the first change
 *	it gets. Usefull after altering the file structures.
 * The volume must be locked by the current process while dismounting.
 * A side effect is that the volume is also unlocked, but you mustn't rely
 *	On this.
 *
 * Return 0 if o.k.
 *	 -1 if not, and errno set.
 */
static int ntfs_device_win32_dismount(HANDLE handle)
{
	DWORD i;
	if (!DeviceIoControl(handle, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0,
			&i, NULL)) {
		errno = ntfs_w32error_to_errno(GetLastError());
		Dputs("Error: Couldn't dismount volume.");
		return -1;
	} else {
		Dputs("Volume dismounted.");
		return 0;
	}
}

/**
 * ntfs_device_win32_getsize - Get file size via win32 API
 * @handle:		Pointer the file HANDLE obtained via open.
 *
 * Only works on ordinary files.
 *
 * Return The file size if o.k.
 *	 -1 if not, and errno set.
 */
static s64 ntfs_device_win32_getsize(HANDLE handle)
{
	DWORD loword, hiword;

	loword = GetFileSize(handle, &hiword);
	if (loword == INVALID_FILE_SIZE) {
		errno = ntfs_w32error_to_errno(GetLastError());
		Dputs("Error: Couldn't get file size.");
		return -1;
	}
	return ((s64)hiword << 32) + (s64)loword;
}

/**
 * ntfs_device_win32_getdisklength - Get disk size via win32 API
 * @handle:		Pointer the file HANDLE obtained via open.
 * @argp:		Pointer to result buffer.
 *
 * Only works on PhysicalDriveX type handles.
 *
 * Return The disk size if o.k.
 *	 -1 if not, and errno set.
 */
static s64 ntfs_device_win32_getdisklength(HANDLE handle)
{
	GET_LENGTH_INFORMATION buf;
	DWORD i;

	if (!DeviceIoControl(handle, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &buf,
			sizeof(buf), &i, NULL)) {
		errno = ntfs_w32error_to_errno(GetLastError());
		Dputs("Error: Couldn't get disk length.");
		return -1;
	} else {
		Dprintf("Disk length: %lld\n", buf.Length.QuadPart);
		return buf.Length.QuadPart;
	}
}

/**
 * ntfs_device_win32_getntfssize - Get NTFS volume size via win32 API
 * @handle:		Pointer the file HANDLE obtained via open.
 * @argp:		Pointer to result buffer.
 *
 * Only works on NTFS volume handles.
 * An annoying bug in windows is that a NTFS volume does not occupy the
 *	Entire partition, namely not the last sector (Which holds the backup
 *	Boot sector, and normally not interesting).
 * Use this function to get the length of the accessible space through a
 *	given volume handle.
 *
 * Return The volume size if o.k.
 *	 -1 if not, and errno set.
 */
static s64 ntfs_device_win32_getntfssize(HANDLE handle)
{
#ifdef FSCTL_GET_NTFS_VOLUME_DATA
	NTFS_VOLUME_DATA_BUFFER buf;
	DWORD i;

	if (!DeviceIoControl(handle, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &buf,
			sizeof(buf), &i, NULL)) {
		errno = ntfs_w32error_to_errno(GetLastError());
		Dputs("Warnning: Couldn't get NTFS volume length.");
		return -1;
	} else {
		s64 rvl = buf.NumberSectors.QuadPart * buf.BytesPerSector;
		Dprintf("NTFS volume length: 0x%llx\n", (long long)rvl);
		return rvl;
	}
#else
	return -1;
#endif
}

/**
 * ntfs_device_win32_getgeo - Get CHS information of a drive.
 * @handle:		An open handle to the PhysicalDevice
 * @fd:		a win_fd structure that will be filled.
 *
 * Return 0 if o.k.
 *	 -1 if not
 *
 * In Windows NT+: fills the members: size, sectors, cylinders
 *			and set heads to -1.
 * In Windows XP+: fills the members: size, sectors, cylinders and heads.
 *
 * Note: in pre XP, this requires write permission, even though nothing is
 *	 actually written.
 *
 * if fails, set sectors, cylinders and heads to -1.
 */
static int ntfs_device_win32_getgeo(HANDLE handle, win32_fd *fd)
{
	BYTE buf[sizeof(DISK_GEOMETRY) + sizeof(DISK_PARTITION_INFO) +
		 sizeof(DISK_DETECTION_INFO) + 512];
	DWORD i;
	BOOL rvl;

	rvl = DeviceIoControl(handle,IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0,
			&buf, sizeof(buf), &i, NULL);
	if (rvl) {
		Dputs("GET_DRIVE_GEOMETRY_EX detected.");
		DISK_DETECTION_INFO *ddi = (PDISK_DETECTION_INFO)
			(((PBYTE)(&((PDISK_GEOMETRY_EX)buf)->Data)) +
			(((PDISK_PARTITION_INFO)(&((PDISK_GEOMETRY_EX)buf)
			->Data))->SizeOfPartitionInfo));

		fd->geo_cylinders = ((DISK_GEOMETRY*)&buf)->Cylinders.QuadPart;
		fd->geo_sectors = ((DISK_GEOMETRY*)&buf)->SectorsPerTrack;
		fd->geo_size = ((DISK_GEOMETRY_EX*)&buf)->DiskSize.QuadPart;
		switch (ddi->DetectionType) {
			case DetectInt13:
				fd->geo_cylinders = ddi->Int13.MaxCylinders;
				fd->geo_sectors = ddi->Int13.SectorsPerTrack;
				fd->geo_heads = ddi->Int13.MaxHeads;
				return 0;
			case DetectExInt13:
				fd->geo_cylinders = ddi->ExInt13.ExCylinders;
				fd->geo_sectors =
					ddi->ExInt13.ExSectorsPerTrack;
				fd->geo_heads = ddi->ExInt13.ExHeads;
				return 0;
			case DetectNone:
			default:
				break;
		}
	} else
		fd->geo_heads = -1;

	rvl = DeviceIoControl(handle,IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
			&buf, sizeof(buf), &i, NULL);
	if (rvl) {
		Dputs("GET_DRIVE_GEOMETRY detected.");
		fd->geo_cylinders = ((DISK_GEOMETRY*)&buf)->Cylinders.QuadPart;
		fd->geo_sectors = ((DISK_GEOMETRY*)&buf)->SectorsPerTrack;
		fd->geo_size = fd->geo_cylinders * fd->geo_sectors *
				((DISK_GEOMETRY*)&buf)->TracksPerCylinder *
				((DISK_GEOMETRY*)&buf)->BytesPerSector;
		return 0;
	}

	errno = ntfs_w32error_to_errno(GetLastError());
	Dputs("Error: Couldn't retrieve disk geometry.");

	fd->geo_cylinders = -1;
	fd->geo_sectors = -1;
	fd->geo_size = -1;

	return -1;
}

/**
 * ntfs_device_win32_open_file - Open a file via win32 API
 * @filename:	Name of the file to open.
 * @fd:			Pointer to win32 file device in which to put the result.
 * @flags:		Unix open status flags.
 *
 * Return 0 if o.k.
 *	 -1 if not, and errno set.
 */
static __inline__ int ntfs_device_win32_open_file(char *filename, win32_fd *fd,
		int flags)
{
	HANDLE handle;

	if (ntfs_device_win32_simple_open_file(filename, &handle, flags,
			FALSE)) {
		/* open error */
 		return -1;
	}

	/* fill fd */
	fd->handle = handle;
	fd->part_start = 0;
	fd->part_length = ntfs_device_win32_getsize(handle);
	fd->real_pos = 0;
	fd->real_ofs = 0;
	fd->part_hidden_sectors = -1;
	fd->geo_size = -1;	/* used as a marker that this is a file */
	fd->vol_handle = INVALID_HANDLE_VALUE;
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
	int err;

	sprintf(filename, "\\\\.\\PhysicalDrive%d", drive_id);

	if ((err = ntfs_device_win32_simple_open_file(filename, &handle, flags,
			TRUE))) {
		/* open error */
 		return err;
	}

	/* store the drive geometry */
	ntfs_device_win32_getgeo(handle, fd);

	/* Just to be sure */
	if (fd->geo_size == -1)
		fd->geo_size = ntfs_device_win32_getdisklength(handle);

	/* fill fd */
	fd->handle = handle;
	fd->part_start = 0;
	fd->part_length = fd->geo_size;
	fd->real_pos = 0;
	fd->real_ofs = 0;
	fd->part_hidden_sectors = -1;
	fd->vol_handle = INVALID_HANDLE_VALUE;

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

	/* Make sure all the required imports exist. */
	if (!fnFindFirstVolume || !fnFindNextVolume || !fnFindVolumeClose) {
		Dputs("win32_is_mounted: Required dll imports not found.");
		return INVALID_HANDLE_VALUE;
	}
	/* Start iterating through volumes. */
	Dprintf("win32_open_volume_for_partition: Start\n");
	vol_find_handle = fnFindFirstVolume(vol_name, MAX_PATH);
	/* If a valid handle could not be aquired, reply with "don't know". */
	if (vol_find_handle == INVALID_HANDLE_VALUE) {
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
	DWORD i;

	if (!DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_LAYOUT, NULL, 0,
			&buf, sizeof(buf), &i, NULL)) {
		errno = ntfs_w32error_to_errno(GetLastError());
		Dputs("Error: GetDriveLayout failed.");
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
static int ntfs_device_win32_open_partition(int drive_id,
		unsigned int partition_id, win32_fd *fd, int flags)
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
		s64 tmp;
		HANDLE vol_handle = ntfs_device_win32_open_volume_for_partition(
			drive_id, part_start, part_length, flags);

		/* store the drive geometry */
		ntfs_device_win32_getgeo(handle, fd);

		fd->handle = handle;
		fd->real_pos = 0;
		fd->real_ofs = 0;
		fd->part_start = part_start;
		fd->part_length = part_length;
		fd->part_hidden_sectors = hidden_sectors;

		tmp = ntfs_device_win32_getntfssize(vol_handle);
		if (tmp > 0)
			fd->geo_size = tmp;
		else
			fd->geo_size = fd->part_length;

		if (vol_handle != INVALID_HANDLE_VALUE) {
			if (((flags & O_RDWR) == O_RDWR) &&
					ntfs_device_win32_lock(vol_handle)) {
				CloseHandle(vol_handle);
				CloseHandle(handle);
				return -1;
			}
			fd->vol_handle = vol_handle;
		} else {
			if ((flags & O_RDWR) == O_RDWR) {
				/* access if read-write, no volume found */
				Dputs("Partitions containing Spanned/Mirrored volumes are "
					  "not supported in R/W status yet");
				CloseHandle(handle);
				errno = ENOTSUP;
				return -1;
			}
			fd->vol_handle = INVALID_HANDLE_VALUE;
		}
		return 0;
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
	ntfs_device_win32_init_imports();
	numparams = sscanf(dev->d_name, "/dev/hd%c%u", &drive_char, &part);
	drive_id = toupper(drive_char) - 'A';
	switch (numparams) {
	case 0:
		Dprintf("win32_open(%s) -> file\n", dev->d_name);
		err = ntfs_device_win32_open_file(dev->d_name, &fd, flags);
		break;
	case 1:
		Dprintf("win32_open(%s) -> drive %d\n", dev->d_name, drive_id);
		err = ntfs_device_win32_open_drive(drive_id, &fd, flags);
		break;
	case 2:
		Dprintf("win32_open(%s) -> drive %d, part %u\n", dev->d_name,
				drive_id, part);
		err = ntfs_device_win32_open_partition(drive_id, part, &fd,
				flags);
		break;
	default:
		Dprintf("win32_open(%s) -> unknwon file format\n", dev->d_name);
		err = -1;
	}
	if (err)
		return err;
	Dprintf("win32_open(%s) -> %p, offset 0x%llx\n", dev->d_name, dev,
			fd.part_start);
	/* Setup our read-only flag. */
	if ((flags & O_RDWR) != O_RDWR)
		NDevSetReadOnly(dev);
	dev->d_private = malloc(sizeof(win32_fd));
	memcpy(dev->d_private, &fd, sizeof(win32_fd));
	NDevSetOpen(dev);
	NDevClearDirty(dev);
	return 0;
}

/**
 * ntfs_device_win32_seek - Change current file position.
 * @handle:		Pointer the file HANDLE obtained via open.
 * @pos:		Offset in the file relative to file start.
 *
 * Return Succeed: The new position in the file
 *	  Fail: -1 and errno set.
 */
static s64 ntfs_device_win32_abs_seek(struct win32_fd *fd, s64 pos)
{
	LARGE_INTEGER li;
	HANDLE handle;

	if (pos < 0 || pos > fd->part_length) {
		Dputs("Error: Seeking outsize seekable area.");
		errno = EINVAL;
		return -1;
	}
	li.QuadPart = pos;
	if (fd->vol_handle != INVALID_HANDLE_VALUE && pos < fd->geo_size) {
		Dputs("Seeking via vol_handle");
		handle = fd->vol_handle;
	} else {
		Dputs("Seeking via handle");
		handle = fd->handle;
		li.QuadPart += fd->part_start;
	}
	/* If the address is not alligned, we round down to nearest sector. */
	li.QuadPart &= ~(s64)(NTFS_BLOCK_SIZE - 1);
	/* Only seek if we are not there already. */
	if (li.QuadPart != fd->real_pos) {
		if (!fnSetFilePointerEx(handle, li, NULL, FILE_BEGIN)) {
			errno = ntfs_w32error_to_errno(GetLastError());
			Dputs("Error: SetFilePointer failed.");
			return -1;
		}
		fd->real_pos = li.QuadPart;
	}
	fd->real_ofs = pos & (NTFS_BLOCK_SIZE - 1);
	return pos;
}

/**
 * ntfs_device_win32_seek - Change current file position.
 * @handle:		Pointer the file HANDLE obtained via open.
 * @offset:		Required offset from the whence anchor.
 * @whence:		May be one of the following:
 *	SEEK_SET	Offset is relative to file start.
 *	SEEK_CUR	Offset is relative to current position.
 *	SEEK_END	Offset is relative to end of file.
 *
 * Return 0 if o.k.
 *	 -1 if not and errno set.
 */
static s64 ntfs_device_win32_seek(struct ntfs_device *dev, s64 offset,
		int whence)
{
	s64 abs_ofs;
	struct win32_fd *fd = (win32_fd *)dev->d_private;

	Dprintf("win32_seek(%lld=0x%llx,%d)\n", offset, offset, whence);
	switch (whence) {
	case SEEK_SET:
		abs_ofs = offset;
		break;
	case SEEK_CUR:
		abs_ofs = fd->real_pos + fd->real_ofs + offset;
		break;
	case SEEK_END:
		/* end of partition != end of disk */
		if (fd->part_length == -1) {
			Dputs("win32_seek: position relative to end "
					"of disk not implemented.");
			errno = ENOTSUP;
			return -1;
		}
		abs_ofs = fd->part_length + offset;
		break;
	default:
		Dprintf("win32_seek() wrong mode %d.\n", whence);
		errno = EINVAL;
		return -1;
	}
	return ntfs_device_win32_abs_seek(fd, abs_ofs);
}

/**
 * ntfs_device_win32_read_simple - Positioned simple read.
 * @fd:			The private data of the NTFS_DEVICE.
 * @buf:		A pointer to where to put the contents.
 * @count:		How many bytes should be read.
 *
 * On success returns the number of bytes read (can be < @count) and on error
 * returns (DWORD)-1 and errno set.
 *
 * Notes:
 *	- Reads from fd->real_pos NOT considering fd->real_ofs.
 *	- Does NOT advance fd->real_pos and fd->real_ofs.
 *	- @buf must be aligned to page boundary.
 *	- @count must be a multiple of the sector size.
 *	- When dealing with volumes, a single call must not span both volume
 *	  and disk extents.
 */
static DWORD ntfs_device_win32_read_simple(win32_fd *fd, void *buf, DWORD count)
{
	HANDLE handle;
	DWORD br;

	if (fd->real_pos + fd->real_ofs < fd->geo_size &&
			fd->vol_handle != INVALID_HANDLE_VALUE) {
		Dputs("Reading via vol_handle.");
		handle = fd->vol_handle;
	} else {
		Dputs("Reading via handle.");
		handle = fd->handle;
	}
	if (!ReadFile(handle, buf, count, &br, NULL)) {
		errno = ntfs_w32error_to_errno(GetLastError());
		Dputs("Error: ReadFile() failed.");
		return (DWORD)-1;
	}
	/*
	 * NOTE: The caller *MUST* update fd->real_pos and fd->real_ofs!!!
	 * Alternatively, caller can call ntfs_device_win32_{,abs_}seek().
	 */
	return br;
}

/**
 * ntfs_device_win32_read - Read 'count' bytes from 'dev' into 'buf'.
 * @dev:		An NTFS_DEVICE obtained via the open command.
 * @buf:		A pointer to where to put the contents.
 * @count:		How many bytes should be read.
 *
 * On success returns the amount of bytes actually read.
 * On fail returns -1 and sets errno.
 */
static s64 ntfs_device_win32_read(struct ntfs_device *dev, void *buf, s64 count)
{
	s64 pos, to_read;
	struct win32_fd *fd = (win32_fd *)dev->d_private;
	BYTE *alignedbuffer;
	int old_ofs;
	DWORD i, br = 0;

	old_ofs = fd->real_ofs;
	pos = fd->real_pos + old_ofs;
	to_read = (old_ofs + count + NTFS_BLOCK_SIZE - 1) &
			~(s64)(NTFS_BLOCK_SIZE - 1);
	/* Impose maximum of 2GB to be on the safe side. */
	if (to_read > 0x80000000) {
		int delta = to_read - count;
		to_read = 0x80000000;
		count = to_read - delta;
	}
	Dprintf("win32_read(fd=%p,b=%p,count=0x%llx)->(%llx+%x:%llx)\n", fd,
			buf, count, (long long)fd->real_pos, old_ofs,
			(long long)to_read);
	if (!((unsigned long)buf & (NTFS_BLOCK_SIZE - 1)) && !old_ofs &&
			!(count & (NTFS_BLOCK_SIZE - 1)))
		alignedbuffer = buf;
	else {
		alignedbuffer = (BYTE *)VirtualAlloc(NULL, to_read, MEM_COMMIT,
				PAGE_READWRITE);
		if (!alignedbuffer) {
			errno = ntfs_w32error_to_errno(GetLastError());
			Dputs("Error: VirtualAlloc failed for read.");
			return -1;
		}
	}
	if (fd->vol_handle != INVALID_HANDLE_VALUE && pos < fd->geo_size) {
		s64 vol_to_read = fd->geo_size - pos;
		if (count > vol_to_read) {
			br = ntfs_device_win32_read_simple(fd,
					alignedbuffer, old_ofs + vol_to_read);
			if (br == (DWORD)-1)
				goto read_error;
			to_read -= br;
			if (br < old_ofs) {
				br = 0;
				goto read_partial;
			}
			br -= old_ofs;
			pos += br;
			fd->real_pos = pos & ~(s64)(NTFS_BLOCK_SIZE - 1);
			fd->real_ofs = pos & (NTFS_BLOCK_SIZE - 1);
			if (br != vol_to_read)
				goto read_partial;
		}
	}
	if ((i = ntfs_device_win32_read_simple(fd, alignedbuffer + br,
			to_read)) == (DWORD)-1) {
		if (br)
			goto read_partial;
		goto read_error;
	}
	if (i < fd->real_ofs)
		goto read_partial;
	i -= fd->real_ofs;
	br += i;
	if (br > count)
		br = count;
	pos += br;
	fd->real_pos = pos & ~(s64)(NTFS_BLOCK_SIZE - 1);
	fd->real_ofs = pos & (NTFS_BLOCK_SIZE - 1);
read_partial:
	if (alignedbuffer != buf) {
		memcpy((void*)buf, alignedbuffer + old_ofs, br);
		VirtualFree(alignedbuffer, 0, MEM_RELEASE);
	}
	return br;
read_error:
	if (alignedbuffer != buf)
		VirtualFree(alignedbuffer, 0, MEM_RELEASE);
	return -1;
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
	if (fd->vol_handle != INVALID_HANDLE_VALUE) {
		if (!NDevReadOnly(dev)) {
			ntfs_device_win32_dismount(fd->vol_handle);
			ntfs_device_win32_unlock(fd->vol_handle);
		}
		if (!CloseHandle(fd->vol_handle))
			Dputs("Error: CloseHandle failed for volume.");
	}
	rvl = CloseHandle(fd->handle);
	free(fd);
	if (!rvl) {
		errno = ntfs_w32error_to_errno(GetLastError());
		Dputs("Error: CloseHandle failed.");
		return -1;
	}
	return 0;
}

/**
 * ntfs_device_win32_sync - Flush write buffers to disk.
 * @dev:		An NTFS_DEVICE obtained via the open command.
 *
 * Return 0 if o.k.
 *	 -1 if not and errno set.
 *
 * Note: Volume syncing works differently in windows.
 *	Disk can't be synced in windows.
 */
static int ntfs_device_win32_sync(struct ntfs_device *dev)
{
	int err = 0;
	BOOL to_clear = TRUE;

	if (!NDevReadOnly(dev) && NDevDirty(dev)) {
		struct win32_fd *fd = (win32_fd *)dev->d_private;

		if ((fd->vol_handle != INVALID_HANDLE_VALUE) &&
				!FlushFileBuffers(fd->vol_handle)) {
			to_clear = FALSE;
			err = ntfs_w32error_to_errno(GetLastError());
		}
		if (!FlushFileBuffers(fd->handle)) {
			to_clear = FALSE;
			if (!err)
				err = ntfs_w32error_to_errno(GetLastError());
		}
		if (!to_clear) {
			errno = err;
			Dputs("Error: Could not sync.");
			return -1;
		}
		NDevClearDirty(dev);
	}
	return 0;
}

/**
 * ntfs_device_win32_write_simple - Write 'count' bytes from 'buf' into 'dev'.
 * @dev:		An NTFS_DEVICE obtained via the open command.
 * @buf:		A pointer to the contents.
 * @count:		How many bytes should be written.
 *
 * On success returns the amount of bytes actually written.
 * On success returns the number of bytes written and on error returns
 * (DWORD)-1 and errno set.
 *
 * Notes:
 *	- Writes to fd->real_pos NOT considering fd->real_ofs.
 *	- Does NOT advance fd->real_pos and fd->real_ofs.
 *	- @buf must be aligned to page boundary.
 *	- @count must be a multiple of the sector size.
 *	- When dealing with volumes, a single call must not span both volume
 *	  and disk extents.
 */
static DWORD ntfs_device_win32_write_simple(win32_fd *fd, const void *buf,
		DWORD count)
{
	HANDLE handle;
	DWORD bw;

	if (fd->real_pos + fd->real_ofs < fd->geo_size &&
			fd->vol_handle != INVALID_HANDLE_VALUE) {
		Dputs("Writing via vol_handle");
		handle = fd->vol_handle;
	} else {
		Dputs("Writing via handle");
		handle = fd->handle;
	}
	if (!WriteFile(handle, buf, count, &bw, NULL)) {
		errno = ntfs_w32error_to_errno(GetLastError());
		Dputs("Error: WriteFile failed.");
		return (DWORD)-1;
	}
	/*
	 * NOTE: The caller *MUST* update fd->real_pos and fd->real_ofs!!!
	 * Alternatively, caller can call ntfs_device_win32_{,abs_}seek().
	 */
	return bw;
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
	s64 pos, to_write;
	win32_fd *fd = (win32_fd *)dev->d_private;
	BYTE *alignedbuffer;
	int old_ofs;
	DWORD i, bw = 0;

	Dprintf("win32_write: Writing %lld bytes\n", (long long)count);
	if (NDevReadOnly(dev)) {
		Dputs("win32_write: Device R/O, exiting.");
		errno = EROFS;
		return -1;
	}
	if (!count)
		return 0;
	NDevSetDirty(dev);
	old_ofs = fd->real_ofs;
	pos = fd->real_pos + old_ofs;
	to_write = (old_ofs + count + NTFS_BLOCK_SIZE - 1) &
			~(s64)(NTFS_BLOCK_SIZE - 1);
	/* Impose maximum of 2GB to be on the safe side. */
	if (to_write > 0x80000000) {
		int delta = to_write - count;
		to_write = 0x80000000;
		count = to_write - delta;
	}
	if (!((unsigned long)buf & (NTFS_BLOCK_SIZE - 1)) && !old_ofs &&
			!(count & (NTFS_BLOCK_SIZE - 1)))
		alignedbuffer = buf;
	else {
		alignedbuffer = (BYTE *)VirtualAlloc(NULL, to_write,
				MEM_COMMIT, PAGE_READWRITE);
		if (!alignedbuffer) {
			errno = ntfs_w32error_to_errno(GetLastError());
			Dputs("Error: VirtualAlloc failed for write.");
			return -1;
		}
		/* Read first sector if start of write not sector aligned. */
		if (old_ofs) {
			i = ntfs_device_win32_read_simple(fd, alignedbuffer,
					NTFS_BLOCK_SIZE);
			if (i != NTFS_BLOCK_SIZE) {
				if (i >= 0)
					errno = EIO;
				goto write_error;
			}
		}
		/* Read last sector if end of write not sector aligned. */
		if ((pos + count) & (NTFS_BLOCK_SIZE - 1)) {
			if (ntfs_device_win32_abs_seek(fd, (pos + count) &
					~(NTFS_BLOCK_SIZE - 1)) == -1)
				goto write_error;
			i = ntfs_device_win32_read_simple(fd, alignedbuffer +
					to_write - NTFS_BLOCK_SIZE,
					NTFS_BLOCK_SIZE);
			if (i != NTFS_BLOCK_SIZE) {
				if (ntfs_device_win32_abs_seek(fd, pos) == -1) {
					fd->real_pos = pos & ~(s64)
							(NTFS_BLOCK_SIZE - 1);
					fd->real_ofs = old_ofs;
				}
				if (i >= 0)
					errno = EIO;
				goto write_error;
			}
		}
		/* Move the file position back so we can start writing. */
		if (ntfs_device_win32_abs_seek(fd, pos) == -1) {
			fd->real_pos = pos & ~(s64)(NTFS_BLOCK_SIZE - 1);
			fd->real_ofs = old_ofs;
			goto write_error;
		}
		/* Copy the data to be written into @alignedbuffer. */
 		memcpy(alignedbuffer + old_ofs, buf, count);
	}
	if (fd->vol_handle != INVALID_HANDLE_VALUE && pos < fd->geo_size) {
		s64 vol_to_write = fd->geo_size - pos;
		if (count > vol_to_read) {
			bw = ntfs_device_win32_write_simple(fd, alignedbuffer,
					old_ofs + vol_to_write);
			if (bw == (DWORD)-1)
				goto write_error;
			to_write -= bw;
			if (bw < old_ofs) {
				bw = 0;
				goto write_partial;
			}
			bw -= old_ofs;
			pos += bw;
			fd->real_pos = pos & ~(s64)(NTFS_BLOCK_SIZE - 1);
			fd->real_ofs = pos & (NTFS_BLOCK_SIZE - 1);
			if (bw != vol_to_write)
				goto write_partial;
		}
	}
	if ((i = ntfs_device_win32_write_simple(fd, alignedbuffer + bw,
			to_write)) == (DWORD)-1) {
		if (bw)
			goto write_partial;
		goto write_error;
	}
	if (i < fd->real_ofs)
		goto write_partial;
	i -= fd->real_ofs;
	bw += i;
	if (bw > count)
		bw = count;
	pos += bw;
	fd->real_pos = pos & ~(s64)(NTFS_BLOCK_SIZE - 1);
	fd->real_ofs = pos & (NTFS_BLOCK_SIZE - 1);
write_partial:
	if (alignedbuffer != buf)
		VirtualFree(alignedbuffer, 0, MEM_RELEASE);
	return bw;
write_error:
	bw = -1;
	goto write_partial;
}

/**
 * ntfs_device_win32_stat - Get a Unix-like stat structure for the file.
 * @dev:		An NTFS_DEVICE obtained via the open command.
 * @argp:		A pointer to where to put the output.
 *
 * Only st_mode & st_size are filled.
 *
 * Return 0 if o.k.
 *	 -1 if not and errno set. in this case handle is trashed.
 */
static int ntfs_device_win32_stat(struct ntfs_device *dev, struct stat *buf)
{
	mode_t st_mode;
	win32_fd *fd = (win32_fd *)dev->d_private;

	switch (GetFileType(fd->handle)) {
		case FILE_TYPE_CHAR:
			st_mode = S_IFCHR;
			break;
		case FILE_TYPE_DISK:
			st_mode = S_IFBLK;
			break;
		case FILE_TYPE_PIPE:
			st_mode = S_IFIFO;
			break;
		default:
			st_mode = 0;
	}

	memset(buf,0,sizeof (struct stat));
	buf->st_mode = st_mode;
	buf->st_size = fd->part_length;
	if (buf->st_size != -1)
		buf->st_blocks = buf->st_size >> 9;
	else
		buf->st_size = 0;

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

	argp->heads = fd->geo_heads;
	argp->sectors = fd->geo_sectors;
	argp->cylinders = fd->geo_cylinders;
	argp->start = fd->part_hidden_sectors;
	return 0;
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
		errno = ntfs_w32error_to_errno(GetLastError());
		Dputs("Error: GET_DRIVE_GEOMETRY failed.");
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
			if (fd->part_length>=0) {
				*(int *)argp = (int)(fd->part_length / 512);
				return 0;
			} else {
   				errno = ENOTSUP;
				return -ENOTSUP;
			}
#endif
#if defined(BLKGETSIZE64)
		case BLKGETSIZE64:
			Dputs("win32_ioctl: BLKGETSIZE64 detected.");
			if (fd->part_length>=0) {
				*(s64 *)argp = fd->part_length;
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
