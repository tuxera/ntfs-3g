/*
 * inode.c - Inode handling code. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002-2004 Anton Altaparmakov
 * Copyright (c) 2004 Yura Pakhuchiy
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "compat.h"

#include "types.h"
#include "inode.h"
#include "debug.h"
#include "mft.h"
#include "attrib.h"
#include "runlist.h"

/**
 * Internal:
 *
 * __ntfs_inode_allocate - desc
 */
static __inline__ ntfs_inode *__ntfs_inode_allocate(ntfs_volume *vol)
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
 * ntfs_inode_allocate - desc
 */
ntfs_inode *ntfs_inode_allocate(ntfs_volume *vol)
{
	return __ntfs_inode_allocate(vol);
}

/**
 * Internal:
 *
 * __ntfs_inode_release - desc
 */
static __inline__ int __ntfs_inode_release(ntfs_inode *ni)
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
 * ntfs_inode_open - open an inode ready for access
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
 * non-resident. In that case, also attach the decompressed runlist to the
 * ntfs_inode structure (->attr_list_rl).
 *
 * Return a pointer to the ntfs_inode structure on success or NULL on error,
 * with errno set to the error code.
 */
ntfs_inode *ntfs_inode_open(ntfs_volume *vol, const MFT_REF mref)
{
	s64 l;
	ntfs_inode *ni;
	ntfs_attr_search_ctx *ctx;
	int err = 0;

	Dprintf("%s(): Entering for inode 0x%llx.\n", __FUNCTION__, MREF(mref));
	if (!vol) {
		errno = EINVAL;
		return NULL;
	}
	ni = __ntfs_inode_allocate(vol);
	if (!ni)
		return NULL;
	if (ntfs_file_record_read(vol, mref, &ni->mrec, NULL))
		goto err_out;
	if (!(ni->mrec->flags & MFT_RECORD_IN_USE))
		goto err_out;
	ni->mft_no = MREF(mref);
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		goto err_out;
	if (ntfs_attr_lookup(AT_ATTRIBUTE_LIST, AT_UNNAMED, 0, 0, 0, NULL, 0,
			ctx)) {
		if (errno != ENOENT)
			goto put_err_out;
		/* Attribute list attribute not present so we are done. */
		ntfs_attr_put_search_ctx(ctx);
		return ni;
	}
	NInoSetAttrList(ni);
	l = ntfs_get_attribute_value_length(ctx->attr);
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
	l = ntfs_get_attribute_value(vol, ctx->attr, ni->attr_list);
	if (!l)
		goto put_err_out;
	if (l != ni->attr_list_size) {
		err = EIO;
		goto put_err_out;
	}
	if (!ctx->attr->non_resident) {
		/* Attribute list attribute is resident so we are done. */
		ntfs_attr_put_search_ctx(ctx);
		return ni;
	}
	NInoSetAttrListNonResident(ni);
	// FIXME: We are duplicating work here! (AIA)
	ni->attr_list_rl = ntfs_mapping_pairs_decompress(vol, ctx->attr, NULL);
	if (ni->attr_list_rl) {
		/* We got the runlist, so we are done. */
		ntfs_attr_put_search_ctx(ctx);
		return ni;
	}
	err = EIO;
put_err_out:
	if (!err)
		err = errno;
	ntfs_attr_put_search_ctx(ctx);
err_out:
	if (!err)
		err = errno;
	__ntfs_inode_release(ni);
	errno = err;
	return NULL;
}

/**
 * ntfs_inode_close - close an ntfs inode and free all associated memory
 * @ni:		ntfs inode to close
 *
 * Make sure the ntfs inode @ni is clean.
 *
 * If the ntfs inode @ni is a base inode, close all associated extent inodes,
 * then deallocate all memory attached to it, and finally free the ntfs inode
 * structure itself.
 *
 * If it is an extent inode, we disconnect it from its base inode before we
 * destroy it.
 *
 * Return 0 on success or -1 on error with errno set to the error code. On
 * error, @ni has not been freed. The user should attempt to handle the error
 * and call ntfs_inode_close() again. The following error codes are defined:
 *
 *	EBUSY	@ni and/or its attribute list runlist is/are dirty and the
 *		attempt to write it/them to disk failed.
 *	EINVAL	@ni is invalid (probably it is an extent inode).
 *	EIO	I/O error while trying to write inode to disk.
 */
int ntfs_inode_close(ntfs_inode *ni)
{
	if (!ni)
		return 0;

	/* If we have dirty metadata, write it out. */
	if (NInoDirty(ni) || NInoAttrListDirty(ni)) {
		if (ntfs_inode_sync(ni)) {
			if (errno != EIO)
				errno = EBUSY;
			return -1;
		}
	}
	/* Is this a base inode with mapped extent inodes? */
	if (ni->nr_extents > 0) {
		while (ni->nr_extents > 0) {
			if (ntfs_inode_close(ni->extent_nis[0])) {
				if (errno != EIO)
					errno = EBUSY;
				return -1;
			}
		}
	} else if (ni->nr_extents == -1) {
		ntfs_inode **tmp_nis;
		ntfs_inode *base_ni;
		s32 i;

		/*
		 * If the inode is an extent inode, disconnect it from the
		 * base inode before destroying it.
		 */
		base_ni = ni->base_ni;
		for (i = 0; i < base_ni->nr_extents; ++i) {
			tmp_nis = base_ni->extent_nis;
			if (tmp_nis[i] != ni)
				continue;
			/* Found it. Disconnect. */
			memmove(tmp_nis + i, tmp_nis + i + 1,
					(base_ni->nr_extents - i - 1) *
					sizeof(ntfs_inode *));
			base_ni->nr_extents--;
			/* Resize the memory buffer. */
			tmp_nis = realloc(tmp_nis, base_ni->nr_extents *
					sizeof(ntfs_inode *));
			/* Ignore realloc errors, they don't really matter. */
			if (tmp_nis)
				base_ni->extent_nis = tmp_nis;
			/* Allow for error checking. */
			i = -1;
			break;
		}
		if (i != -1)
			Dputs("Extent inode was not attached to base inode! "
					"Weird! Continuing regardless.");
	}
	return __ntfs_inode_release(ni);
}

/**
 * ntfs_extent_inode_open - load an extent inode and attach it to its base
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
 *
 * Note, extent inodes are never closed directly. They are automatically
 * disposed off by the closing of the base inode.
 */
ntfs_inode *ntfs_extent_inode_open(ntfs_inode *base_ni, const MFT_REF mref)
{
	u64 mft_no = MREF_LE(mref);
	ntfs_inode *ni;
	ntfs_inode **extent_nis;
	int i;

	if (!base_ni) {
		errno = EINVAL;
		return NULL;
	}
	Dprintf("%s(): Opening extent inode 0x%llx (base mft record 0x%llx).\n",
			__FUNCTION__, (unsigned long long)mft_no,
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
	ni = __ntfs_inode_allocate(base_ni->vol);
	if (!ni)
		return NULL;
	if (ntfs_file_record_read(base_ni->vol, le64_to_cpu(mref), &ni->mrec,
			NULL))
		goto err_out;
	ni->mft_no = mft_no;
	ni->nr_extents = -1;
	ni->base_ni = base_ni;
	/* Attach extent inode to base inode, reallocating memory if needed. */
	if (!(base_ni->nr_extents & 3)) {
		i = (base_ni->nr_extents + 4) * sizeof(ntfs_inode *);

		extent_nis = (ntfs_inode**)malloc(i);
		if (!extent_nis)
			goto err_out;
		if (base_ni->nr_extents) {
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
	__ntfs_inode_release(ni);
	errno = i;
	Dperror("Failed to open extent inode");
	return NULL;
}

/**
 * ntfs_inode_sync - write the inode (and its dirty extents) to disk
 * @ni:		ntfs inode to write
 *
 * Write the inode @ni to disk as well as its dirty extent inodes if such
 * exist and @ni is a base inode. If @ni is an extent inode, only @ni is
 * written completely disregarding its base inode and any other extent inodes.
 *
 * For a base inode with dirty extent inodes if any writes fail for whatever
 * reason, the failing inode is skipped and the sync process is continued. At
 * the end the error condition that brought about the failure is returned. Thus
 * the smallest amount of data loss possible occurs.
 *
 * Return 0 on success or -1 on error with errno set to the error code.
 * The following error codes are defined:
 *	EINVAL	- Invalid arguments were passed to the function.
 *	ENOTSUP	- Syncing requires code that has not been imlemented yet.
 *	EBUSY	- Inode and/or one of its extents is busy, try again later.
 *	EIO	- I/O error while writing the inode (or one of its extents).
 */
int ntfs_inode_sync(ntfs_inode *ni)
{
	int err = 0;

	if (!ni) {
		errno = EINVAL;
		return -1;
	}
	
	Dprintf("%s(): Entring for inode 0x%llx.\n", __FUNCTION__, ni->mft_no);

	/* Write out attribute list from cache to disk. */
	if (ni->nr_extents != -1 && NInoAttrListDirty(ni)) {
		ntfs_attr *na;

		na = ntfs_attr_open(ni, AT_ATTRIBUTE_LIST, 0, 0);
		if (!na) {
			if (!err || errno == EIO) {
				err = errno;
				if (err != EIO)
					err = EBUSY;
				Dprintf("%s(): Attribute list sync failed "
					"(open failed).\n", __FUNCTION__);
			}
		} else {
			if (na->data_size == ni->attr_list_size) {
				if (ntfs_attr_pwrite(na, 0, ni->attr_list_size,
							ni->attr_list) !=
							ni->attr_list_size) {
					if (!err || errno == EIO) {
						err = errno;
						if (err != EIO)
							err = EBUSY;
						Dprintf("%s(): Attribute list "
						"sync failed (write failed).\n",
						 __FUNCTION__);

					}
				} else
					NInoAttrListClearDirty(ni);
			} else {
				err = EIO;
				Dprintf("%s(): Attribute list sync failed "
					"(invalid size).\n", __FUNCTION__);
			}
			ntfs_attr_close(na);
		}
	}

	/* Write this inode out to the $MFT (and $MFTMirr if applicable). */
	if (NInoTestAndClearDirty(ni)) {
		if (ntfs_mft_record_write(ni->vol, ni->mft_no, ni->mrec)) {
			if (!err || errno == EIO) {
				err = errno;
				if (err != EIO)
					err = EBUSY;
			}
			NInoSetDirty(ni);
			Dprintf("%s(): Base MFT record sync failed.\n",
					__FUNCTION__);
		}
	}

	/* If this is a base inode with extents write all dirty extents, too. */
	if (ni->nr_extents > 0) {
		s32 i;

		for (i = 0; i < ni->nr_extents; ++i) {
			ntfs_inode *eni;
			
			eni = ni->extent_nis[i];
			if (NInoTestAndClearDirty(eni)) {
				if (ntfs_mft_record_write(eni->vol, eni->mft_no,
						eni->mrec)) {
					if (!err || errno == EIO) {
						err = errno;
						if (err != EIO)
							err = EBUSY;
					}
					NInoSetDirty(eni);
					Dprintf("%s(): Extent MFT record sync "
						"failed.\n", __FUNCTION__);
				}
			}
		}
	}

	if (!err)
		return err;
	errno = err;
	return -1;
}
