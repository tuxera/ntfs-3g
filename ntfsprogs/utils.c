/**
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

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "config.h"
#include "types.h"
#include "volume.h"
#include "debug.h"

#define NTFS_TIME_OFFSET ((s64)(369 * 365 + 89) * 24 * 3600 * 10000000)

/**
 * ntfs2utc - Convert an NTFS time to Unix time
 * @time:  An NTFS time in 100ns units since 1601
 *
 * NTFS stores times as the number of 100ns intervals since January 1st 1601 at
 * 00:00 UTC.  This system will not suffer from Y2K problems until ~57000AD.
 *
 * Return:  n  A Unix time (number of seconds since 1970)
 */
time_t ntfs2utc (s64 time)
{
	return (time - (NTFS_TIME_OFFSET)) / 10000000;
}

/**
 * utc2ntfs - convert Linux time to NTFS time
 * @time:  Linux time to convert to NTFS
 *
 * Convert the Linux time @time to its corresponding NTFS time.
 *
 * Linux stores time in a long at present and measures it as the number of
 * 1-second intervals since 1st January 1970, 00:00:00 UTC.
 *
 * NTFS uses Microsoft's standard time format which is stored in a s64 and is
 * measured as the number of 100 nano-second intervals since 1st January 1601,
 * 00:00:00 UTC.
 *
 * Return:  n  An NTFS time (100ns units since Jan 1601)
 */
s64 utc2ntfs (time_t time)
{
	/* Convert to 100ns intervals and then add the NTFS time offset. */
	return (s64)time * 10000000 + NTFS_TIME_OFFSET;
}


/* valid_device requires the following */
extern int Eprintf (const char *format, ...) __attribute__ ((format (printf, 1, 2)));
extern int Vprintf (const char *format, ...) __attribute__ ((format (printf, 1, 2)));

/**
 * valid_device - Perform some safety checks on the device, before we start
 * @name:   Full pathname of the device/file to work with
 * @force:  Continue regardless of problems
 *
 * Check that the name refers to a device and that is isn't already mounted.
 * These checks can be overridden by using the force option.
 *
 * Return:  1  Success, we can continue
 *	    0  Error, we cannot use this device
 */
int valid_device (const char *name, int force)
{
	unsigned long mnt_flags = 0;
	struct stat st;

	if (stat (name, &st) == -1) {
		if (errno == ENOENT) {
			Eprintf ("The device %s doesn't exist\n", name);
		} else {
			Eprintf ("Error getting information about %s: %s\n", name, strerror (errno));
		}
		return 0;
	}

	if (!S_ISBLK (st.st_mode)) {
		Vprintf ("%s is not a block device.\n", name);
		if (!force) {
			Eprintf ("Use the force option to work with files.\n");
			return 0;
		}
		Vprintf ("Forced to continue.\n");
	}

	/* Make sure the file system is not mounted. */
	if (ntfs_check_if_mounted (name, &mnt_flags)) {
		Vprintf ("Failed to determine whether %s is mounted: %s\n", name, strerror (errno));
		if (!force) {
			Eprintf ("Use the force option to ignore this error.\n");
			return 0;
		}
		Vprintf ("Forced to continue.\n");
	} else if (mnt_flags & NTFS_MF_MOUNTED) {
		Vprintf ("The device %s, is mounted.\n", name);
		if (!force) {
			Eprintf ("Use the force option to work a mounted filesystem.\n");
			return 0;
		}
		Vprintf ("Forced to continue.\n");
	}

	return 1;
}

/**
 * find_attribute - Find an attribute of the given type
 * @type:  An attribute type, e.g. AT_FILE_NAME
 * @ctx:   A search context, created using ntfs_get_attr_search_ctx
 *
 * Using the search context to keep track, find the first/next occurrence of a
 * given attribute type.
 *
 * N.B.  This will return a pointer into @mft.  As long as the search context
 *       has been created without an inode, it won't overflow the buffer.
 *
 * Return:  Pointer  Success, an attribute was found
 *	    NULL     Error, no matching attributes were found
 */
ATTR_RECORD * find_attribute (const ATTR_TYPES type, ntfs_attr_search_ctx *ctx)
{
	if (!ctx)
		return NULL;

	if (ntfs_attr_lookup(type, NULL, 0, 0, 0, NULL, 0, ctx) != 0) {
		Dprintf ("find_attribute didn't find an attribute of type: 0x%02x.\n", type);
		return NULL;	/* None / no more of that type */
	}

	Dprintf ("find_attribute found an attribute of type: 0x%02x.\n", type);
	return ctx->attr;
}

/**
 * find_first_attribute - Find the first attribute of a given type
 * @type:  An attribute type, e.g. AT_FILE_NAME
 * @mft:   A buffer containing a raw MFT record
 *
 * Search through a raw MFT record for an attribute of a given type.
 * The return value is a pointer into the MFT record that was supplied.
 *
 * N.B.  This will return a pointer into @mft.  The pointer won't stray outside
 *       the buffer, since we created the search context without an inode.
 *
 * Return:  Pointer  Success, an attribute was found
 *	    NULL     Error, no matching attributes were found
 */
ATTR_RECORD * find_first_attribute (const ATTR_TYPES type, MFT_RECORD *mft)
{
	ntfs_attr_search_ctx *ctx;
	ATTR_RECORD *rec;

	if (!mft)
		return NULL;

	ctx = ntfs_attr_get_search_ctx(NULL, mft);
	if (!ctx) {
		Eprintf ("Couldn't create a search context.\n");
		return NULL;
	}

	rec = find_attribute (type, ctx);
	ntfs_attr_put_search_ctx(ctx);
	if (rec)
		Dprintf ("find_first_attribute: found attr of type 0x%02x.\n", type);
	else
		Dprintf ("find_first_attribute: didn't find attr of type 0x%02x.\n", type);
	return rec;
}


#if 0
hamming weight
inline unsigned int hweight32(unsigned int w)
{
	unsigned int res = (w & 0x55555555) + ((w >> 1) & 0x55555555);
	res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
	res = (res & 0x0F0F0F0F) + ((res >> 4) & 0x0F0F0F0F);
	res = (res & 0x00FF00FF) + ((res >> 8) & 0x00FF00FF);
	return (res & 0x0000FFFF) + ((res >> 16) & 0x0000FFFF);
}

inline unsigned int hweight16(unsigned int w)
{
	unsigned int res = (w & 0x5555) + ((w >> 1) & 0x5555);
	res = (res & 0x3333) + ((res >> 2) & 0x3333);
	res = (res & 0x0F0F) + ((res >> 4) & 0x0F0F);
	return (res & 0x00FF) + ((res >> 8) & 0x00FF);
}

inline unsigned int hweight8(unsigned int w)
{
	unsigned int res = (w & 0x55) + ((w >> 1) & 0x55);
	res = (res & 0x33) + ((res >> 2) & 0x33);
	return (res & 0x0F) + ((res >> 4) & 0x0F);
}

inline int set_bit(int nr,long * addr)
{
	int	mask, retval;

	addr += nr >> 5;
	mask = 1 << (nr & 0x1f);
	retval = (mask & *addr) != 0;
	*addr |= mask;
	return retval;
}

inline int clear_bit(int nr, long * addr)
{
	int	mask, retval;

	addr += nr >> 5;
	mask = 1 << (nr & 0x1f);
	retval = (mask & *addr) != 0;
	*addr &= ~mask;
	return retval;
}

inline int test_bit(int nr, long * addr)
{
	int	mask;

	addr += nr >> 5;
	mask = 1 << (nr & 0x1f);
	return ((mask & *addr) != 0);
}

#endif

