/*
 * $Id$
 *
 * disk_io.h - Exports for disk io. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2000-2002 Anton Altaparmakov.
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

#ifndef _NTFS_DISK_IO_H
#define _NTFS_DISK_IO_H

#include "volume.h"

extern s64 ntfs_pread(const int fd, const s64 pos, s64 count, const void *b);
extern s64 ntfs_pwrite(const int fd, const s64 pos, s64 count, const void *b);

extern s64 ntfs_mst_pread(const int fd, const s64 pos, s64 count,
		const u32 bksize, const void *b);
extern s64 ntfs_mst_pwrite(const int fd, const s64 pos, s64 count,
		const u32 bksize, const void *b);

extern s64 ntfs_read_clusters(const ntfs_volume *vol, const s64 lcn,
		const s64 count, const void *b);
extern s64 ntfs_write_clusters(const ntfs_volume *vol, const s64 lcn,
		const s64 count, const void *b);

#endif /* defined _NTFS_DISK_IO_H */

