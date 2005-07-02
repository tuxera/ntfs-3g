/*
 * inode.c - Inode handling code. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002-2005 Anton Altaparmakov
 * Copyright (c) 2004-2005 Yura Pakhuchiy
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
#include "attrib.h"
#include "inode.h"
#include "debug.h"
#include "mft.h"
#include "attrlist.h"
#include "runlist.h"
#include "lcnalloc.h"
#include "index.h"
#include "dir.h"

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
 * this.
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
	STANDARD_INFORMATION *std_info;

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
	ni->data_size = -1;
	ni->allocated_size = -1;
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		goto err_out;
	/* Receive some basic information about inode. */
	if (ntfs_attr_lookup(AT_STANDARD_INFORMATION, AT_UNNAMED,
				0, CASE_SENSITIVE, 0, NULL, 0, ctx)) {
		err = errno;
		Dprintf("%s(): Failed to receive STANDARD_INFORMATION "
				"attribute.\n", __FUNCTION__);
		goto put_err_out;
	}
	std_info = (STANDARD_INFORMATION *)((u8 *)ctx->attr +
			le16_to_cpu(ctx->attr->value_offset));
	if (std_info->file_attributes & FILE_ATTR_COMPRESSED)
		NInoSetCompressed(ni);
	if (std_info->file_attributes & FILE_ATTR_ENCRYPTED)
		NInoSetEncrypted(ni);
	if (std_info->file_attributes & FILE_ATTR_SPARSE_FILE)
		NInoSetSparse(ni);
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
	ntfs_attr_put_search_ctx(ctx);
	return ni;
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
			/* 
			 * ElectricFence is unhappy with realloc(x,0) as free(x)
			 * thus we explicitely separate these two cases.
			 */
			if (--base_ni->nr_extents) {
				/* Resize the memory buffer. */
				tmp_nis = realloc(tmp_nis, ((base_ni->
						  nr_extents + 3) & ~3) *
						  sizeof(ntfs_inode *));
				/* Ignore errors, they don't really matter. */
				if (tmp_nis)
					base_ni->extent_nis = tmp_nis;
			} else if(tmp_nis)
				free(tmp_nis);
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
 * ntfs_inode_attach_all_extents - atach all extents for target inode
 * @ni:		opened ntfs inode for which perform atach
 *
 * Return 0 on success and -1 on error with errno set to the error code.
 */
int ntfs_inode_attach_all_extents(ntfs_inode *ni)
{
	ATTR_LIST_ENTRY *ale;
	u64 prev_attached = 0;

	if (!ni) {
		Dprintf("%s(): Invalid argumets.\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	if (ni->nr_extents == -1)
		ni = ni->base_ni;

	Dprintf("%s(): Entering for inode 0x%llx.\n",
			__FUNCTION__, (long long) ni->mft_no);

	/* Inode haven't got attribute list, thus nothing to attach. */
	if (!NInoAttrList(ni))
		return 0;

	if (!ni->attr_list) {
		Dprintf("%s(): Corrput in-memory struct.\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	/* Walk through attribute list and attach all extents. */
	errno = 0;
	ale = (ATTR_LIST_ENTRY *)ni->attr_list;
	while ((u8*)ale < ni->attr_list + ni->attr_list_size) {
		if (ni->mft_no != MREF_LE(ale->mft_reference) &&
				prev_attached != MREF_LE(ale->mft_reference)) {
			if (!ntfs_extent_inode_open(ni,
					MREF_LE(ale->mft_reference))) {
				Dprintf("%s(): Couldn't attach extent inode.\n",
						__FUNCTION__);
				return -1;
			}
			prev_attached = MREF_LE(ale->mft_reference);
		}
		ale = (ATTR_LIST_ENTRY *)((u8*)ale + le16_to_cpu(ale->length));
	}
	return 0;
}

/**
 * ntfs_inode_sync_standard_information - update standard informaiton attribute
 * @ni:		ntfs inode to update standard information
 *
 * Return 0 on success or -1 on error with errno set to the error code.
 */
static int ntfs_inode_sync_standard_information(ntfs_inode *ni)
{
	ntfs_attr_search_ctx *ctx;
	STANDARD_INFORMATION *std_info;
	int err;

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		return -1;
	if (ntfs_attr_lookup(AT_STANDARD_INFORMATION, AT_UNNAMED,
				0, CASE_SENSITIVE, 0, NULL, 0, ctx)) {
		err = errno;
		Dprintf("%s(): Failed to receive STANDARD_INFORMATION "
				"attribute.\n", __FUNCTION__);
		ntfs_attr_put_search_ctx(ctx);
		errno = err;
		return -1;
	}
	std_info = (STANDARD_INFORMATION *)((u8 *)ctx->attr +
			le16_to_cpu(ctx->attr->value_offset));
	if (NInoCompressed(ni))
		std_info->file_attributes |= FILE_ATTR_COMPRESSED;
	else
		std_info->file_attributes &= ~FILE_ATTR_COMPRESSED;
	if (NInoEncrypted(ni))
		std_info->file_attributes |= FILE_ATTR_ENCRYPTED;
	else
		std_info->file_attributes &= ~FILE_ATTR_ENCRYPTED;
	if (NInoSparse(ni))
		std_info->file_attributes |= FILE_ATTR_SPARSE_FILE;
	else
		std_info->file_attributes &= ~FILE_ATTR_SPARSE_FILE;
	ntfs_inode_mark_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	return 0;
}

/**
 * ntfs_inode_sync_file_name - update FILE_NAME attributes
 * @ni:		ntfs inode to update FILE_NAME attributes
 *
 * Update all FILE_NAME attributes for inode @ni in the index.
 *
 * Return 0 on success or -1 on error with errno set to the error code.
 */
static int ntfs_inode_sync_file_name(ntfs_inode *ni)
{
	ntfs_attr_search_ctx *ctx = NULL;
	ntfs_index_context *ictx;
	ntfs_inode *index_ni;
	FILE_NAME_ATTR *fn;
	int err = 0;

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		err = errno;
		Dprintf("%s(): Failed to get attribute search context.\n",
				__FUNCTION__);
		goto err_out;
	}
	/* Walk through all FILE_NAME attributes and update them. */
	while (!ntfs_attr_lookup(AT_FILE_NAME, NULL, 0, 0, 0, NULL, 0, ctx)) {
		fn = (FILE_NAME_ATTR *)((u8 *)ctx->attr +
				le16_to_cpu(ctx->attr->value_offset));
		if (MREF_LE(fn->parent_directory) == ni->mft_no) {
			/*
			 * WARNING: We cheater here and obtain 2 attribute
			 * search contextes for one inode (first we obtained
			 * above, second will be obtained inside
			 * ntfs_index_lookup), it's acceptable for library,
			 * but will lock kernel.
			 */
			index_ni = ni;
		} else
			index_ni = ntfs_inode_open(ni->vol,
				le64_to_cpu(fn->parent_directory));
		if (!index_ni) {
			if (!err)
				err = errno;
			Dprintf("%s(): Failed to open inode with index.\n",
					__FUNCTION__);
			continue;
		}
		ictx = ntfs_index_ctx_get(index_ni, I30, 4);
		if (!ictx) {
			if (!err)
				err = errno;
			Dprintf("%s(): Failed to get index context.\n",
					__FUNCTION__);
			ntfs_inode_close(index_ni);
			continue;
		}
		if (ntfs_index_lookup(fn, sizeof(FILE_NAME_ATTR), ictx)) {
			if (!err) {
				if (errno == ENOENT)
					err = EIO;
				else
					err = errno;
			}
			Dprintf("%s(): Index lookup failed.\n", __FUNCTION__);
			ntfs_index_ctx_put(ictx);
			ntfs_inode_close(index_ni);
			continue;
		}
		/* Update flags and file size. */
		fn = (FILE_NAME_ATTR *)ictx->data;
		if (NInoCompressed(ni))
			fn->file_attributes |= FILE_ATTR_COMPRESSED;
		else
			fn->file_attributes &= ~FILE_ATTR_COMPRESSED;
		if (NInoEncrypted(ni))
			fn->file_attributes |= FILE_ATTR_ENCRYPTED;
		else
			fn->file_attributes &= ~FILE_ATTR_ENCRYPTED;
		if (NInoSparse(ni))
			fn->file_attributes |= FILE_ATTR_SPARSE_FILE;
		else
			fn->file_attributes &= ~FILE_ATTR_SPARSE_FILE;
		if (ni->allocated_size != -1)
			fn->allocated_size = cpu_to_sle64(ni->allocated_size);
		if (ni->data_size != -1)
			fn->data_size = cpu_to_sle64(ni->data_size);
		ntfs_index_entry_mark_dirty(ictx);
		ntfs_index_ctx_put(ictx);
		ntfs_inode_close(index_ni);
	}
	/* Check for real error occured. */
	if (errno != ENOENT) {
		err = errno;
		Dprintf("%s(): Attribute lookup failed.\n", __FUNCTION__);
		goto err_out;
	}
	ntfs_attr_put_search_ctx(ctx);
	if (err) {
		errno = err;
		return -1;
	}
	return 0;
err_out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	errno = err;
	return -1;
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

	Dprintf("%s(): Entering for inode 0x%llx.\n",
			__FUNCTION__, (long long) ni->mft_no);

	/* Update STANDARD_INFORMATION. */
	if (ni->nr_extents != -1 && ntfs_inode_sync_standard_information(ni)) {
		if (!err || errno == EIO) {
			err = errno;
			if (err != EIO)
				err = EBUSY;
		}
		Dprintf("%s(): Failed to sync standard information.\n",
				__FUNCTION__);
	}

	/* Update FILE_NAME's in the index. */
	if (ni->nr_extents != -1 && NInoFileNameTestAndClearDirty(ni) &&
			ntfs_inode_sync_file_name(ni)) {
		if (!err || errno == EIO) {
			err = errno;
			if (err != EIO)
				err = EBUSY;
		}
		Dprintf("%s(): Failed to sync FILE_NAME attributes.\n",
				__FUNCTION__);
		NInoFileNameSetDirty(ni);
	}

	/* Write out attribute list from cache to disk. */
	if (ni->nr_extents != -1 && NInoAttrList(ni) &&
			NInoAttrListTestAndClearDirty(ni)) {
		ntfs_attr *na;

		na = ntfs_attr_open(ni, AT_ATTRIBUTE_LIST, AT_UNNAMED, 0);
		if (!na) {
			if (!err || errno == EIO) {
				err = errno;
				if (err != EIO)
					err = EBUSY;
				Dprintf("%s(): Attribute list sync failed "
					"(open failed).\n", __FUNCTION__);
			}
			NInoAttrListSetDirty(ni);
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
					NInoAttrListSetDirty(ni);
				}
			} else {
				err = EIO;
				Dprintf("%s(): Attribute list sync failed "
					"(invalid size).\n", __FUNCTION__);
				NInoAttrListSetDirty(ni);
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
		return 0;
	errno = err;
	return -1;
}

/**
 * ntfs_inode_add_attrlist - add attribute list to inode and fill it
 * @ni - opened ntfs inode to which add attribute list
 *
 * Return 0 on success or -1 on error with errno set to the error code.
 * The following error codes are defined:
 *	EINVAL	- Invalid arguments were passed to the function.
 *	EEXIST	- Attibute list already exist.
 *	EIO	- Input/Ouput error occured.
 *	ENOMEM	- Not enogh memory to perform add.
 */
int ntfs_inode_add_attrlist(ntfs_inode *ni)
{
	int err;
	ntfs_attr_search_ctx *ctx;
	u8 *al, *aln;
	int al_len, al_allocated;
	ATTR_LIST_ENTRY *ale;
	ntfs_attr *na;

	if (!ni) {
		Dprintf("%s(): Invalid argumets.\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	Dprintf("%s(): Entering for inode 0x%llx.\n",
			__FUNCTION__, (long long) ni->mft_no);

	if (NInoAttrList(ni) || ni->nr_extents) {
		Dprintf("%s(): Inode already has got attribute list.\n",
				__FUNCTION__);
		errno = EEXIST;
		return -1;
	}

	al_allocated = 0x40;
	al_len = 0;
	al = malloc(al_allocated);
	ale = (ATTR_LIST_ENTRY *) al;
	if (!al) {
		Dprintf("%s(): Not enough memory.\n", __FUNCTION__);
		errno = ENOMEM;
		return -1;
	}

	/* Form attribute list. */
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		err = errno;
		Dprintf("%s(): Coudn't get search context.\n", __FUNCTION__);
		goto err_out;
	}
	/* Walk through all attributes. */
	while (!ntfs_attr_lookup(AT_UNUSED, NULL, 0, 0, 0, NULL, 0, ctx)) {
		if (ctx->attr->type == AT_ATTRIBUTE_LIST) {
			err = EIO;
			Dprintf("%s(): Eeek! Attribute list already present.\n",
					__FUNCTION__);
			goto put_err_out;
		}
		/* Calculate new length of attribute list. */
		al_len += (sizeof(ATTR_LIST_ENTRY) + sizeof(ntfschar) *
					ctx->attr->name_length + 7) & ~7;
		/* Allocate more memory if needed. */
		while (al_len > al_allocated) {
			al_allocated += 0x40;
			aln = realloc(al, al_allocated);
			if (!aln) {
				Dprintf("%s(): Not enough memory.\n",
						__FUNCTION__);
				err = ENOMEM;
				goto put_err_out;
			}
			ale = (ATTR_LIST_ENTRY *)(aln + ((u8 *)ale - al));
			al = aln;
		}
		/* Add attribute to attribute list. */
		ale->type = ctx->attr->type;
		ale->length = cpu_to_le16((sizeof(ATTR_LIST_ENTRY) +
			sizeof(ntfschar) * ctx->attr->name_length + 7) & ~7);
		ale->name_length = ctx->attr->name_length;
		ale->name_offset = (u8 *)ale->name - (u8 *)ale;
		if (ctx->attr->non_resident)
			ale->lowest_vcn = ctx->attr->lowest_vcn;
		else
			ale->lowest_vcn = 0;
		ale->mft_reference = MK_LE_MREF(ni->mft_no,
			le16_to_cpu(ni->mrec->sequence_number));
		ale->instance = ctx->attr->instance;
		memcpy(ale->name, (u8 *)ctx->attr +
				le16_to_cpu(ctx->attr->name_offset),
				ctx->attr->name_length * sizeof(ntfschar));
		ale = (ATTR_LIST_ENTRY *)(al + al_len);
	}
	/* Check for real error occured. */
	if (errno != ENOENT) {
		err = errno;
		Dprintf("%s(): Attribute lookup failed.\n", __FUNCTION__);
		goto put_err_out;
	}
	/* Deallocate trailing memory. */
	aln = realloc(al, al_len);
	if (!aln) {
		err = errno;
		Dprintf("%s(): realloc() failed.\n", __FUNCTION__);
		goto put_err_out;
	}
	al = aln;

	/* Set in-memory attribute list. */
	ni->attr_list = al;
	ni->attr_list_size = al_len;
	NInoSetAttrList(ni);
	NInoAttrListSetDirty(ni);

	/* Free space if there is not enough it for $ATTRIBUTE_LIST. */
	if (le32_to_cpu(ni->mrec->bytes_allocated) -
			le32_to_cpu(ni->mrec->bytes_in_use) <
			offsetof(ATTR_RECORD, resident_end)) {
		if (ntfs_inode_free_space(ni,
				offsetof(ATTR_RECORD, resident_end))) {
			/* Failed to free space. */
			err = errno;
			Dprintf("%s(): Failed to free space for "
				"$ATTRIBUTE_LIST.\n", __FUNCTION__);
			goto rollback;
		}
	}

	/* Add $ATTRIBUTE_LIST to mft record. */
	if (ntfs_resident_attr_record_add(ni,
				AT_ATTRIBUTE_LIST, NULL, 0, 0) < 0) {
		err = errno;
		Dprintf("%s(): Couldn't add $ATTRIBUTE_LIST to MFT record.\n",
			__FUNCTION__);
		goto rollback;
	}

	/* Resize it. */
	na = ntfs_attr_open(ni, AT_ATTRIBUTE_LIST, AT_UNNAMED, 0);
	if (!na) {
		err = errno;
		Dprintf("%s(): Failed to open just added $ATTRIBUTE_LIST.\n",
				__FUNCTION__);
		goto remove_attrlist_record;
	}
	if (ntfs_attr_truncate(na, al_len)) {
		err = errno;
		Dprintf("%s(): Failed to resize just added $ATTRIBUTE_LIST.\n",
				__FUNCTION__);
		ntfs_attr_close(na);
		goto remove_attrlist_record;;
	}
	/* Done! */
	ntfs_attr_close(na);
	return 0;
remove_attrlist_record:
	/* Prevent ntfs_attr_recorm_rm from freeing attribute list. */
	ni->attr_list = NULL;
	NInoClearAttrList(ni);
	/* Remove $ATTRIBUTE_LIST record. */
	ntfs_attr_reinit_search_ctx(ctx);
	if (!ntfs_attr_lookup(AT_ATTRIBUTE_LIST, NULL, 0,
				CASE_SENSITIVE, 0, NULL, 0, ctx)) {
		if (ntfs_attr_record_rm(ctx))
			Dprintf("%s(): Rollback failed. Failed to remove "
				"attribute list record.\n", __FUNCTION__);
	} else
		Dprintf("%s(): Rollback failed. Coudn't find attribute list "
			"record.\n", __FUNCTION__);
	/* Setup back in-memory runlist. */
	ni->attr_list = al;
	ni->attr_list_size = al_len;
	NInoSetAttrList(ni);
rollback:
	/*
	 * Scan attribute list for attributes that placed not in the base MFT
	 * record and move them to it.
	 */
	ntfs_attr_reinit_search_ctx(ctx);
	ale = (ATTR_LIST_ENTRY*)al;
	while ((u8*)ale < al + al_len) {
		if (MREF_LE(ale->mft_reference) != ni->mft_no) {
			if (!ntfs_attr_lookup(ale->type, ale->name,
						ale->name_length,
						CASE_SENSITIVE,
						sle64_to_cpu(ale->lowest_vcn),
						NULL, 0, ctx)) {
				if (ntfs_attr_record_move_to(ctx, ni))
					Dprintf("%s(): Rollback failed. "
						"Couldn't back attribute to "
						"base MFT record.\n",
						__FUNCTION__);
			} else
				Dprintf("%s(): Rollback failed. "
					"ntfs_attr_lookup failed.\n",
					__FUNCTION__);
			ntfs_attr_reinit_search_ctx(ctx);
		}
		ale = (ATTR_LIST_ENTRY*)((u8*)ale + le16_to_cpu(ale->length));
	}
	/* Remove in-memory attribute list. */
	ni->attr_list = NULL;
	ni->attr_list_size = 0;
	NInoClearAttrList(ni);
	NInoAttrListClearDirty(ni);
put_err_out:
	ntfs_attr_put_search_ctx(ctx);
err_out:
	free(al);
	errno = err;
	return -1;
}

/**
 * ntfs_inode_free_space - free space in the MFT record of inode
 * @ni:		ntfs inode in which MFT record free space
 * @size:	amount of space needed to free
 *
 * Return 0 on success or -1 on error with errno set to the error code.
 */
int ntfs_inode_free_space(ntfs_inode *ni, int size)
{
	ntfs_attr_search_ctx *ctx;
	int freed, err;

	if (!ni || size < 0) {
		Dprintf("%s(): Invalid argumets.\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	Dprintf("%s(): Entering for inode 0x%llx, size %d.\n",
			__FUNCTION__, (long long) ni->mft_no, size);

	freed = (le32_to_cpu(ni->mrec->bytes_allocated) -
				le32_to_cpu(ni->mrec->bytes_in_use));

	if (size <= freed)
		return 0;

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		err = errno;
		Dprintf("%s(): Failed to get attribute search context.\n",
				__FUNCTION__);
		errno = err;
		return -1;
	}

	/*
	 * Chkdsk complain if $STANDART_INFORMATION is not in the base MFT
	 * record. FIXME: I'm not sure in this, need to recheck. For now simply
	 * do not move $STANDART_INFORMATION at all.
	 *
	 * Also we can't move $ATTRIBUTE_LIST from base MFT_RECORD, so position
	 * search context on first attribute after $STANDARD_INFORMATION and
	 * $ATTRIBUTE_LIST.
	 *
	 * Why we reposition instead of simply skip this attributes during
	 * enumeration? Because in case we have got only in-memory attribute
	 * list ntfs_attr_lookup will fail when it will try to find
	 * $ATTRIBUTE_LIST.
	 */
	if (ntfs_attr_lookup(AT_FILE_NAME, NULL, 0, CASE_SENSITIVE, 0, NULL,
				0, ctx)) {
		if (errno != ENOENT) {
			err = errno;
			Dprintf("%s(): Attribute lookup failed.\n",
				__FUNCTION__);
			goto put_err_out;
		}
		if (ctx->attr->type == AT_END) {
			err = ENOSPC;
			goto put_err_out;
		}
	}

	while (1) {
		int record_size;

		/*
		 * Check whether attribute is from different MFT record. If so,
		 * find next, because we don't need such.
		 */
		while (ctx->ntfs_ino->mft_no != ni->mft_no) {
			if (ntfs_attr_lookup(AT_UNUSED, NULL, 0, CASE_SENSITIVE,
						0, NULL, 0, ctx)) {
				err = errno;
				if (errno != ENOENT) {
					Dprintf("%s(): Attribute lookup failed."
						"\n", __FUNCTION__);
				} else
					err = ENOSPC;
				goto put_err_out;
			}
		}

		record_size = le32_to_cpu(ctx->attr->length);

		/* Move away attribute. */
		if (ntfs_attr_record_move_away(ctx, 0)) {
			err = errno;
			Dprintf("%s(): Failed to move out attribute.\n",
					__FUNCTION__);
			break;
		}
		freed += record_size;

		/* Check whether we done. */
		if (size <= freed) {
			ntfs_attr_put_search_ctx(ctx);
			return 0;
		}

		/*
		 * Repostion to first attribute after $STANDARD_INFORMATION and
		 * $ATTRIBUTE_LIST (see comments upwards).
		 */
		ntfs_attr_reinit_search_ctx(ctx);
		if (ntfs_attr_lookup(AT_FILE_NAME, NULL, 0, CASE_SENSITIVE, 0,
				NULL, 0, ctx)) {
			if (errno != ENOENT) {
				err = errno;
				Dprintf("%s(): Attribute lookup failed.\n",
					__FUNCTION__);
				break;
			}
			if (ctx->attr->type == AT_END) {
				err = ENOSPC;
				break;
			}
		}
	}
put_err_out:
	ntfs_attr_put_search_ctx(ctx);
	if (err == ENOSPC)
		Dprintf("%s(): No attributes left that can be moved out.\n",
			__FUNCTION__);
	errno = err;
	return -1;
}
