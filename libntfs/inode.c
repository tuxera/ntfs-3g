/*
 * $Id$
 *
 * inode.c - Inode handling code. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002 Anton Altaparmakov.
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "types.h"
#include "inode.h"
#include "debug.h"
#include "mft.h"
#include "attrib.h"
#include "runlist.h"

/**
 * Internal:
 *
 * __allocate_ntfs_inode - desc
 */
static __inline__ ntfs_inode *__allocate_ntfs_inode(ntfs_volume *vol)
{
	ntfs_inode *ni;

	ni = (ntfs_inode*)calloc(1, sizeof(ntfs_inode));
	if (ni)
		ni->vol = vol;
	return ni;
}

/**
 * Internal:
 *
 * allocate_ntfs_inode - desc
 */
ntfs_inode *allocate_ntfs_inode(ntfs_volume *vol)
{
	return __allocate_ntfs_inode(vol);
}

/**
 * Internal:
 *
 * __release_ntfs_inode - desc
 */
static __inline__ int __release_ntfs_inode(ntfs_inode *ni)
{
	if (NInoDirty(ni))
		Dputs("Eeek. Discarding dirty inode!");
	if (NInoAttrList(ni) && ni->attr_list)
		free(ni->attr_list);
	if (NInoAttrListNonResident(ni) && ni->attr_list_rl)
		free(ni->attr_list_rl);
	if (ni->mrec)
		free(ni->mrec);
	free(ni);
	return 0;
}

/**
 * ntfs_open_inode - open an inode ready for access
 * @vol:	volume to get the inode from
 * @mref:	inode number / mft record number to open
 *
 * Allocate an ntfs_inode structure and initialize it for the given inode
 * specified by @mref. @mref specifies the inode number / mft record to read,
 * including the sequence number, which can be 0 if no sequence number checking
 * is to be performed.
 *
 * Then, allocate a buffer for the mft record, read the mft record from the
 * volume @vol, and attach it to the ntfs_inode structure (->mrec). The
 * mft record is mst deprotected and sanity checked for validity and we abort
 * if deprotection or checks fail.
 *
 * Finally, search for an attribute list attribute in the mft record and if one
 * is found, load the attribute list attribute value and attach it to the
 * ntfs_inode structure (->attr_list). Also set the NI_AttrList bit to indicate
 * this as well as the NI_AttrListNonResident bit if the the attribute list is
 * non-resident. In that case, also attach the decompressed run list to the
 * ntfs_inode structure (->attr_list_rl).
 *
 * Return a pointer to the ntfs_inode structure on success or NULL on error,
 * with errno set to the error code.
 */
ntfs_inode *ntfs_open_inode(ntfs_volume *vol, const MFT_REF mref)
{
	s64 l;
	ntfs_inode *ni;
	ntfs_attr_search_ctx *ctx;
	int err = 0;

	Dprintf("%s(): Entering for inode 0x%Lx.\n", __FUNCTION__, MREF(mref));
	if (!vol) {
		errno = EINVAL;
		return NULL;
	}
	ni = __allocate_ntfs_inode(vol);
	if (!ni)
		return NULL;
	if (ntfs_read_file_record(vol, mref, &ni->mrec, NULL))
		goto err_out;
	if (!(ni->mrec->flags & MFT_RECORD_IN_USE))
		goto err_out;
	ni->mft_no = MREF(mref);
	ctx = ntfs_get_attr_search_ctx(ni, NULL);
	if (!ctx)
		goto err_out;
	if (ntfs_lookup_attr(AT_ATTRIBUTE_LIST, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx)) {
		if (errno != ENOENT)
			goto put_err_out;
		/* Attribute list attribute not present so we are done. */
		ntfs_put_attr_search_ctx(ctx);
		return ni;
	}
	NInoSetAttrList(ni);
	l = get_attribute_value_length(ctx->attr);
	if (!l)
		goto put_err_out;
	if (l > 0x40000) {
		err = EIO;
		goto put_err_out;
	}
	ni->attr_list_size = l;
	ni->attr_list = malloc(ni->attr_list_size);
	if (!ni->attr_list)
		goto put_err_out;
	l = get_attribute_value(vol, ni->mrec, ctx->attr, ni->attr_list);
	if (!l)
		goto put_err_out;
	if (l != ni->attr_list_size) {
		err = EIO;
		goto put_err_out;
	}
	if (!ctx->attr->non_resident) {
		/* Attribute list attribute is resident so we are done. */
		ntfs_put_attr_search_ctx(ctx);
		return ni;
	}
	NInoSetAttrListNonResident(ni);
	// FIXME: We are duplicating work here! (AIA)
	ni->attr_list_rl = ntfs_decompress_mapping_pairs(vol, ctx->attr, NULL);
	if (ni->attr_list_rl) {
		/* We got the run list, so we are done. */
		ntfs_put_attr_search_ctx(ctx);
		return ni;
	}
	err = EIO;
put_err_out:
	if (!err)
		err = errno;
	ntfs_put_attr_search_ctx(ctx);
err_out:
	if (!err)
		err = errno;
	__release_ntfs_inode(ni);
	errno = err;
	return NULL;
}

/**
 * ntfs_close_inode - close an ntfs inode and free all associated memory
 * @ni:		ntfs inode to close
 *
 * Make sure the ntfs inode @ni is clean.
 *
 * If the ntfs inode @ni is a base inode, close all associated extent inodes,
 * then deallocate all memory attached to it, and finally free the ntfs inode
 * structure itself.
 *
 * If it is an extent inode, we postpone to when the base inode is being closed
 * with ntfs_close_inode() to tear down all structures and free all allocated
 * memory. That way we keep the extent records cached in memory so we get an
 * efficient ntfs_lookup_attr().
 *
 * Return 0 on success or -1 on error with errno set to the error code. On
 * error, @ni has not been freed. The user should attempt to handle the error
 * and call ntfs_close_inode() again. The following error codes are defined:
 *
 *	EBUSY	@ni is dirty and/or the attribute list run list is dirty.
 */
int ntfs_close_inode(ntfs_inode *ni)
{
	// TODO: This needs to be replaced with a flush to disk attempt. (AIA)
	if (NInoDirty(ni) || NInoAttrListDirty(ni)) {
		errno = EBUSY;
		return -1;
	}
	/* Is this a base inode with mapped extent inodes? */
	if (ni->nr_extents > 0) {
		int i;

		// FIXME: Handle dirty case for each extent inode! (AIA)
		for (i = 0; i < ni->nr_extents; i++)
			__release_ntfs_inode(ni->extent_nis[i]);
		free(ni->extent_nis);
	}
	return __release_ntfs_inode(ni);
}

/**
 * ntfs_open_extent_inode - load an extent inode and attach it to its base
 * @base_ni:	base ntfs inode
 * @mref:	mft reference of the extent inode to load (in little endian)
 *
 * First check if the extent inode @mref is already attached to the base ntfs
 * inode @base_ni, and if so, return a pointer to the attached extent inode.
 *
 * If the extent inode is not already attached to the base inode, allocate an
 * ntfs_inode structure and initialize it for the given inode @mref. @mref
 * specifies the inode number / mft record to read, including the sequence
 * number, which can be 0 if no sequence number checking is to be performed.
 *
 * Then, allocate a buffer for the mft record, read the mft record from the
 * volume @base_ni->vol, and attach it to the ntfs_inode structure (->mrec).
 * The mft record is mst deprotected and sanity checked for validity and we
 * abort if deprotection or checks fail.
 *
 * Finally attach the ntfs inode to its base inode @base_ni and return a
 * pointer to the ntfs_inode structure on success or NULL on error, with errno
 * set to the error code.
 */
ntfs_inode *ntfs_open_extent_inode(ntfs_inode *base_ni, const MFT_REF mref)
{
	u64 mft_no = MREF_LE(mref);
	ntfs_inode *ni;
	ntfs_inode **extent_nis;
	int i;

	if (!base_ni) {
		errno = EINVAL;
		return NULL;
	}
	Dprintf("Opening extent inode %Lu (base mft record 0x%Lu).\n",
			(unsigned long long)mft_no,
			(unsigned long long)base_ni->mft_no);
	/* Is the extent inode already open and attached to the base inode? */
	if (base_ni->nr_extents > 0) {
		extent_nis = base_ni->extent_nis;
		for (i = 0; i < base_ni->nr_extents; i++) {
			u16 seq_no;

			ni = extent_nis[i];
			if (mft_no != ni->mft_no)
				continue;
			/* Verify the sequence number if given. */
			seq_no = MSEQNO_LE(mref);
			if (seq_no && seq_no != le16_to_cpu(
					ni->mrec->sequence_number)) {
				Dputs("Found stale extent mft reference! "
						"Corrupt file system. Run "
						"chkdsk.");
				errno = EIO;
				return NULL;
			}
			/* We are done, return the extent inode. */
			return ni;
		}
	}
	/* Wasn't there, we need to load the extent inode. */
	ni = __allocate_ntfs_inode(base_ni->vol);
	if (!ni)
		return NULL;
	if (ntfs_read_file_record(base_ni->vol, le64_to_cpu(mref), &ni->mrec,
			NULL))
		goto err_out;
	ni->mft_no = mft_no;
	ni->nr_extents = -1;
	ni->base_ni = base_ni;
	/* Attach extent inode to base inode, reallocating memory if needed. */
	if (!(base_ni->nr_extents & ~3)) {
		i = (base_ni->nr_extents + 4) * sizeof(ntfs_inode *);

		extent_nis = (ntfs_inode**)malloc(i);
		if (!extent_nis)
			goto err_out;
		if (base_ni->extent_nis) {
			memcpy(extent_nis, base_ni->extent_nis,
					i - 4 * sizeof(ntfs_inode *));
			free(base_ni->extent_nis);
		}
		base_ni->extent_nis = extent_nis;
	}
	base_ni->extent_nis[base_ni->nr_extents++] = ni;
	return ni;
err_out:
	i = errno;
	__release_ntfs_inode(ni);
	errno = i;
	Dperror("Failed to open extent inode");
	return NULL;
}

