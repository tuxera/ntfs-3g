/*
 * utils.c - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002 Richard Russon <ntfs@flatcap.org>
 *
 * This utility will recover deleted files from an NTFS volume.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _NTFS_UTILS_H_
#define _NTFS_UTILS_H_

#include "types.h"
#include "layout.h"
#include "volume.h"

#define PATH_SEP	'/'

#define	GEN_PRINTF(NAME, STREAM, CONTROL, TRIGGER)				\
	__attribute__ ((format (printf, 1, 2)))					\
	int NAME (const char *format, ...)					\
	{									\
		int ret, olderr = errno, *control = (CONTROL);			\
		va_list args;							\
										\
		if (!(STREAM))							\
			return -1;						\
		if (control &&							\
		   ((*control && !(TRIGGER)) || (!*control && (TRIGGER))))	\
			return -1;						\
										\
		va_start (args, format);					\
		ret = vfprintf ((STREAM), format, args);			\
		va_end (args);							\
		errno = olderr;							\
		return ret;							\
	}

struct _IO_FILE;

int ntfs_printf (struct _IO_FILE *stream, int *control, BOOL trigger,
		const char *format, ...) __attribute__ ((format (printf, 4, 5)));

int utils_valid_device (const char *name, int force);
int utils_set_locale (void);
ntfs_volume * utils_mount_volume (const char *device, unsigned long flags, BOOL force);
int utils_parse_size (const char *value, s64 *size, BOOL scale);
int utils_parse_range (const char *string, s64 *start, s64 *finish, BOOL scale);
int utils_inode_get_name (ntfs_inode *inode, char *buffer, int bufsize);
int utils_attr_get_name (ntfs_volume *vol, ATTR_RECORD *attr, char *buffer, int bufsize);

time_t ntfs2utc (s64 time);
s64 utc2ntfs (time_t time);

ATTR_RECORD * find_attribute (const ATTR_TYPES type, ntfs_attr_search_ctx *ctx);
ATTR_RECORD * find_first_attribute (const ATTR_TYPES type, MFT_RECORD *mft);

#endif /* _NTFS_UTILS_H_ */
