/**
 * efs.c - Limited processing of encrypted files
 *
 *	This module is part of ntfs-3g library
 *
 * Copyright (c)      2009 Martin Bene
 * Copyright (c)      2009 Jean-Pierre Andre
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

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#ifdef HAVE_SYS_SYSMACROS_H
#include <sys/sysmacros.h>
#endif

#include "types.h"
#include "debug.h"
#include "attrib.h"
#include "inode.h"
#include "dir.h"
#include "efs.h"
#include "index.h"
#include "logging.h"
#include "misc.h"
#include "efs.h"

static ntfschar logged_utility_stream_name[] = {
	const_cpu_to_le16('$'),
	const_cpu_to_le16('E'),
	const_cpu_to_le16('F'),
	const_cpu_to_le16('S'),
	const_cpu_to_le16(0)
} ;


/*
 *		Get the ntfs EFS info into an extended attribute
 */

int ntfs_get_efs_info(const char *path,
			char *value, size_t size, ntfs_inode *ni)
{
	EFS_ATTR_HEADER *efs_info;
	s64 attr_size = 0;

	if (ni) {
		if (ni->flags & FILE_ATTR_ENCRYPTED) {
			efs_info = (EFS_ATTR_HEADER*)ntfs_attr_readall(ni,
				AT_LOGGED_UTILITY_STREAM,(ntfschar*)NULL, 0,
				&attr_size);
			if (efs_info
			    && (le32_to_cpu(efs_info->length) == attr_size)) {
				if (attr_size <= (s64)size) {
					if (value)
						memcpy(value,efs_info,attr_size);
					else {
						errno = EFAULT;
						attr_size = 0;
					}
				} else
					if (size) {
						errno = ERANGE;
						attr_size = 0;
					}
				free (efs_info);
			} else {
				if (efs_info) {
					free(efs_info);
					ntfs_log_info("Bad efs_info for file %s\n",path);
				} else {
					ntfs_log_info("Could not get efsinfo"
						" for file %s\n", path);
				}
				errno = EIO;
				attr_size = 0;
			}
		} else {
			errno = ENODATA;
			ntfs_log_info("File %s is not encrypted",path); 
		}
	}
	return (attr_size ? (int)attr_size : -errno);
}

/*
 *		Set the efs data from an extended attribute
 *	Warning : the new data is not checked
 *	Returns 0, or -1 if there is a problem
 */

int ntfs_set_efs_info(const char *path	__attribute__((unused)),
			const char *value, size_t size, int flags,
			ntfs_inode *ni)
{
	int res;
	int written;
	ntfs_attr *na;
	const EFS_ATTR_HEADER *info_header;
	ntfs_attr_search_ctx *ctx;

	res = 0;
	if (ni && value && size) {
		if (ni->flags & (FILE_ATTR_ENCRYPTED | FILE_ATTR_COMPRESSED)) {
			if (ni->flags & FILE_ATTR_ENCRYPTED) {
				ntfs_log_info("File %s already encrypted",path);
				errno = EEXIST;
			} else {
				/*
				 * Possible problem : if encrypted file was
				 * restored in a compressed directory, it was
				 * restored as compressed.
				 * TODO : decompress first.
				 */
				ntfs_log_error("File %s cannot be encrypted and compressed\n",
					path);
				errno = EIO;
			}
			return -1;
		}
		info_header = (const EFS_ATTR_HEADER*)value;
			/* make sure we get a likely efsinfo */
		if (le32_to_cpu(info_header->length) != size) {
			errno = EINVAL;
			return (-1);
		}
		if (!ntfs_attr_exist(ni,AT_LOGGED_UTILITY_STREAM,
				(ntfschar*)NULL,0)) {
			if (!(flags & XATTR_REPLACE)) {
			/*
			 * no logged_utility_stream attribute : add one,
			 * apparently, this does not feed the new value in
			 */
				res = ntfs_attr_add(ni,AT_LOGGED_UTILITY_STREAM,
					logged_utility_stream_name,4,
					(u8*)NULL,(s64)size);
			} else {
				errno = ENODATA;
				res = -1;
			}
		} else {
			errno = EEXIST;
			res = -1;
		}
		if (!res) {
			/*
			 * open and update the existing efs data
			 */
			na = ntfs_attr_open(ni, AT_LOGGED_UTILITY_STREAM,
				logged_utility_stream_name, 4);
			if (na) {
				/* resize attribute */
				res = ntfs_attr_truncate(na, (s64)size);
				/* overwrite value if any */
				if (!res && value) {
					written = (int)ntfs_attr_pwrite(na,
						 (s64)0, (s64)size, value);
					if (written != (s64)size) {
						ntfs_log_error("Failed to "
							"update efs data\n");
						errno = EIO;
						res = -1;
					}
				}
				ntfs_attr_close(na);
			} else
				res = -1;
		}
		if (!res) {
			/* Don't handle AT_DATA Attribute(s) if inode is a directory */
			if (!(ni->mrec->flags & MFT_RECORD_IS_DIRECTORY)) {
				/* iterate over AT_DATA attributes */
                        	/* set encrypted flag, truncate attribute to match padding bytes */
			
				ctx = ntfs_attr_get_search_ctx(ni, NULL);
				if (!ctx) {
					ntfs_log_error("Failed to get ctx for efs\n");
					return (-1);
				}
				while (!ntfs_attr_lookup(AT_DATA, NULL, 0, 
					   CASE_SENSITIVE, 0, NULL, 0, ctx)) {
					if (ntfs_efs_fixup_attribute(ctx, NULL)) {
						ntfs_log_error("Error in efs fixup of AT_DATA Attribute");
						ntfs_attr_put_search_ctx(ctx);
						return(-1);
					}
				}
				ntfs_attr_put_search_ctx(ctx);
			}
			ni->flags |= FILE_ATTR_ENCRYPTED;
			NInoSetDirty(ni);
			NInoFileNameSetDirty(ni);
		}
	} else {
		errno = EINVAL;
		res = -1;
	}
	return (res ? -1 : 0);
}

/*
 *              Fixup raw encrypted AT_DATA Attribute
 *     read padding length from last two bytes
 *     truncate attribute, make non-resident,
 *     set data size to match padding length
 *     set ATTR_IS_ENCRYPTED flag on attribute 
 *
 *	Return 0 if successful
 *		-1 if failed (errno tells why)
 */

int ntfs_efs_fixup_attribute(ntfs_attr_search_ctx *ctx, ntfs_attr *na) 
{
	u64 newsize;
	le16 appended_bytes;
	u16 padding_length;
	ATTR_RECORD *a;
	ntfs_inode *ni;
	BOOL close_na = FALSE;
	BOOL close_ctx = FALSE;

	if (!ctx && !na) {
		ntfs_log_error("neither ctx nor na specified for efs_fixup_attribute\n");
		goto err_out;
	}
	if (!ctx) {
		ctx = ntfs_attr_get_search_ctx(na->ni, NULL);
		if (!ctx) {
			ntfs_log_error("Failed to get ctx for efs\n");
			goto err_out;
		}
		close_ctx=TRUE;
		if (ntfs_attr_lookup(AT_DATA, na->name, na->name_len, 
				CASE_SENSITIVE, 0, NULL, 0, ctx)) {
			ntfs_log_error("attr lookup for AT_DATA attribute failed in efs fixup\n");
			goto err_out;
		}
	}

	a = ctx->attr;
	if (!na) {
		na = ntfs_attr_open(ctx->ntfs_ino, AT_DATA,
			(ntfschar*)((u8*)a + le16_to_cpu(a->name_offset)),
			a->name_length);
		if (!na) {
			ntfs_log_error("can't open DATA Attribute\n");
			return (-1);
		}
		close_na = TRUE;
	}
		/* make sure size is valid for a raw encrypted stream */
	if ((na->data_size & 511) != 2) {
		ntfs_log_error("Bad raw encrypted stream");
		goto err_out;
	}
	/* read padding length from last two bytes of attribute */
	if (ntfs_attr_pread(na, na->data_size-2, 2, &appended_bytes) != 2) {
		ntfs_log_error("Error reading padding length\n");
		goto err_out;
	}
	padding_length = le16_to_cpu(appended_bytes);
	if (padding_length > 511 || padding_length > na->data_size-2) {
		errno = EINVAL;
		ntfs_log_error("invalid padding length %d for data_size %lld\n",
			 padding_length, (long long)na->data_size);
		goto err_out;
	}
	newsize = na->data_size - padding_length - 2;
	/* truncate attribute to possibly free clusters allocated 
	   for the last two bytes */
	if (ntfs_attr_truncate(na, na->data_size-2)) {
		 ntfs_log_error("Error truncating attribute\n");
		goto err_out;
	}

	/* Encrypted AT_DATA Attributes MUST be non-resident */
	if (!NAttrNonResident(na)
    		&& ntfs_attr_make_non_resident(na, ctx)) {
		ntfs_log_error("Error making DATA attribute non-resident\n");
		goto err_out;
	}
	ni = na->ni;
	if (!na->name_len) {
		ni->data_size = newsize;
		ni->allocated_size = na->allocated_size;
	}
	NInoSetDirty(ni);
	NInoFileNameSetDirty(ni);
	if (close_na)
		ntfs_attr_close(na);

	ctx->attr->data_size = cpu_to_le64(newsize);
	if (le64_to_cpu(ctx->attr->initialized_size) > newsize)
		ctx->attr->initialized_size = ctx->attr->data_size;
	ctx->attr->flags |= ATTR_IS_ENCRYPTED;
	if (close_ctx)
		ntfs_attr_put_search_ctx(ctx);
		
	return (0);
err_out:
	if (close_na && na)
		ntfs_attr_close(na);
	if (close_ctx && ctx)
		ntfs_attr_put_search_ctx(ctx);
	return (-1);
}
