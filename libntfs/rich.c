/**
 * rich.c - Temporary junk file.  Part of the Linux-NTFS project.
 *
 * Copyright (c) 2004-2005 Richard Russon
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

#ifdef NTFS_RICH

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "rich.h"
#include "layout.h"
#include "logging.h"

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
ATTR_RECORD * find_attribute(const ATTR_TYPES type, ntfs_attr_search_ctx *ctx)
{
	if (!ctx) {
		errno = EINVAL;
		return NULL;
	}

	if (ntfs_attr_lookup(type, NULL, 0, 0, 0, NULL, 0, ctx) != 0) {
		ntfs_log_debug("find_attribute didn't find an attribute of type: 0x%02x.\n", type);
		return NULL;	/* None / no more of that type */
	}

	ntfs_log_debug("find_attribute found an attribute of type: 0x%02x.\n", type);
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
ATTR_RECORD * find_first_attribute(const ATTR_TYPES type, MFT_RECORD *mft)
{
	ntfs_attr_search_ctx *ctx;
	ATTR_RECORD *rec;

	if (!mft) {
		errno = EINVAL;
		return NULL;
	}

	ctx = ntfs_attr_get_search_ctx(NULL, mft);
	if (!ctx) {
		//XXX ntfs_log_error("Couldn't create a search context.\n");
		return NULL;
	}

	rec = find_attribute(type, ctx);
	ntfs_attr_put_search_ctx(ctx);
	if (rec)
		ntfs_log_debug("find_first_attribute: found attr of type 0x%02x.\n", type);
	else
		ntfs_log_debug("find_first_attribute: didn't find attr of type 0x%02x.\n", type);
	return rec;
}

/**
 * ntfs_name_print
 */
void ntfs_name_print(ntfschar *name, int name_len)
{
	char *buffer = NULL;

	if (name_len) {
		ntfs_ucstombs(name, name_len, &buffer, 0);
		ntfs_log_info("%s", buffer);
		free(buffer);
	} else {
		ntfs_log_info("!");
	}
}

/**
 * utils_free_non_residents3
 */
int utils_free_non_residents3(struct ntfs_bmp *bmp, ntfs_inode *inode, ATTR_RECORD *attr)
{
	ntfs_attr *na;
	runlist_element *rl;
	LCN size;
	LCN count;

	if (!bmp)
		return 1;
	if (!inode)
		return 1;
	if (!attr)
		return 1;
	if (!attr->non_resident)
		return 0;

	na = ntfs_attr_open(inode, attr->type, NULL, 0);
	if (!na)
		return 1;

	ntfs_attr_map_whole_runlist(na);
	rl = na->rl;
	size = na->allocated_size >> inode->vol->cluster_size_bits;
	for (count = 0; count < size; count += rl->length, rl++) {
		if (ntfs_bmp_set_range(bmp, rl->lcn, rl->length, 0) < 0) {
			ntfs_log_info(RED "set range : %lld - %lld FAILED\n" END, rl->lcn, rl->lcn+rl->length-1);
		}
	}
	ntfs_attr_close(na);

	return 0;
}

/**
 * utils_free_non_residents2
 */
int utils_free_non_residents2(ntfs_inode *inode, struct ntfs_bmp *bmp)
{
	ntfs_attr_search_ctx *ctx;

	if (!inode)
		return -1;
	if (!bmp)
		return -1;

	ctx = ntfs_attr_get_search_ctx(NULL, inode->mrec);
	if (!ctx) {
		ntfs_log_info("can't create a search context\n");
		return -1;
	}

	while (ntfs_attr_lookup(AT_UNUSED, NULL, 0, 0, 0, NULL, 0, ctx) == 0) {
		utils_free_non_residents3(bmp, inode, ctx->attr);
	}

	ntfs_attr_put_search_ctx(ctx);
	return 0;
}


#endif /* NTFS_RICH */

