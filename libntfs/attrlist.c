/*
 * attrlist.c - Attribute list attribute handling code.  Part of the Linux-NTFS
 *		project.
 *
 * Copyright (c) 2004 Anton Altaparmakov
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
#include <errno.h>

#include "types.h"
#include "layout.h"
#include "attrib.h"
#include "attrlist.h"
#include "debug.h"
#include "unistr.h"

/**
 * ntfs_attrlist_need - check whether attribute need attribute list
 * @ni:		opened ntfs inode for which perform check
 *
 * Check whether all are atributes belong to one MFT record, in that case
 * attribute list is not needed.
 *
 * Return 1 if inode need attribute list, 0 if not, -1 on error with errno set
 * to the error code. If function succeed errno set to 0. The following error
 * codes are defined:
 *	EINVAL	- Invalid argumets passed to function or attribute haven't got
 *		  attribute list.
 */
int ntfs_attrlist_need(ntfs_inode *ni)
{
	ATTR_LIST_ENTRY *ale;

	if (!ni) {
		Dprintf("%s(): Invalid argumets.\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	Dprintf("%s(): Entering for inode 0x%llx.\n",
			__FUNCTION__, (long long) ni->mft_no);

	if (!NInoAttrList(ni)) {
		Dprintf("%s(): Inode haven't got attribute list.\n",
			__FUNCTION__);
		errno = EINVAL;
		return -1;
	}
	
	if (!ni->attr_list) {
		Dprintf("%s(): Corrput in-memory struct.\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	errno = 0;
	ale = (ATTR_LIST_ENTRY *)ni->attr_list;
	while ((u8*)ale < ni->attr_list + ni->attr_list_size) {
		if (MREF_LE(ale->mft_reference) != ni->mft_no)
			return 1;
		ale = (ATTR_LIST_ENTRY *)((u8*)ale + le16_to_cpu(ale->length));
	}
	return 0;
}

/**
 * ntfs_attrlist_set - set new attribute list for ntfs inode
 * @ni:		opened ntfs inode attribute list set for
 * @new_al:	new attribute list
 * @new_al_len:	length of new attribute list
 *
 * Return 0 on success and -1 on error with errno set to the error code. The
 * following error codes are defined:
 *	EINVAL	- Invalid argumets passed to function.
 *	ENOMEM	- Not enough memory to allocate necessary buffers.
 *	ENOTSUP	- Code that required for set is not implemented yet.
 *	EIO	- I/O error occured or damaged filesystem.
 */
int ntfs_attrlist_set(ntfs_inode *ni, u8 *new_al, int new_al_len)
{
	ntfs_attr *na = NULL;
	int err;

	if (!ni || !new_al || new_al_len < 1) {
		Dprintf("%s(): Invalid argumets.\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	Dprintf("%s(): Entering for inode 0x%llx, new_al_len %d.\n",
			__FUNCTION__, (long long) ni->mft_no, new_al_len);

	/* Make attribute list length 8 byte aligment. */
	new_al_len = (new_al_len + 7) & ~7;

	na = ntfs_attr_open(ni, AT_ATTRIBUTE_LIST, 0, 0);
	if (!na) {
		err = errno;
		Dprintf("%s(): Coudn't open $ATTRIBUTE_LIST.\n", __FUNCTION__);
		goto err_out;
	}
	/*
	 * Setup im-memory attribute list. We need this to perform attribute
	 * truncate (we need update attribute list in case other attributes
	 * will be moved away from their current MFT record).
	 */
	if (NInoAttrList(ni) && ni->attr_list)
		free(ni->attr_list);
	ni->attr_list = new_al;
	ni->attr_list_size = new_al_len;
	NInoSetAttrList(ni);
	NInoAttrListSetDirty(ni);
	/* Resize $ATTRIBUTE_LIST attribute. */
	if (ntfs_attr_truncate(na, new_al_len)) {
		/*
		 * FIXME: We leave new attribute list. But need to restore old
		 * and update in it records for moved attributes. Difficult to
		 * do if we haven't attribute list before truncate and records
		 * were moved.
		 */
		err = errno;
		Dprintf("%s(): Eeek! $ATTRIBUTE_LIST resize failed. Probably "
			"leaving inconsist metadata.\n", __FUNCTION__);
		goto err_out;
	}

	/* Done! */
	ntfs_attr_close(na);
	return 0;
err_out:
	if (na)
		ntfs_attr_close(na);
	errno = err;
	return -1;
}

/**
 * ntfs_attrlist_entry_add - add an attribute list attribute entry
 * @ni:		opened ntfs inode, which contains that attribute
 * @attr:	attribute record to add to attribute list
 *
 * Return 0 on success and -1 on error with errno set to the error code. The
 * following error codes are defined:
 *	EINVAL	- Invalid argumets passed to function.
 *	ENOMEM	- Not enough memory to allocate necessary buffers.
 *	ENOTSUP	- Code that required for set is not implemented yet.
 *	EIO	- I/O error occured or damaged filesystem.
 */
int ntfs_attrlist_entry_add(ntfs_inode *ni, ATTR_RECORD *attr)
{
	ATTR_LIST_ENTRY *ale;
	MFT_REF mref;
	u8 *new_al;
	int new_al_len;
	int err;

	Dprintf("%s(): Entering for inode 0x%llx, attr 0x%x.\n",
		 __FUNCTION__, (long long) ni->mft_no, (unsigned) attr->type);

	if (!ni || !attr) {
		Dprintf("%s(): Invalid argumets.\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	mref = MK_LE_MREF(ni->mft_no, le16_to_cpu(ni->mrec->sequence_number));

	if (ni->nr_extents == -1)
		ni = ni->base_ni;

	if (!NInoAttrList(ni)) {
		Dprintf("%s(): Attribute list isn't present.\n", __FUNCTION__);
		errno = ENOENT;
		return -1;
	}

	new_al_len = (ni->attr_list_size + sizeof(ATTR_LIST_ENTRY) +
			sizeof(ntfschar) * attr->name_length + 7) & ~7;
	new_al = malloc(new_al_len);
	if (!new_al) {
		Dprintf("%s(): Not enough memory.\n", __FUNCTION__);
		err = ENOMEM;
		return -1;
	}

	/* Find offset at which insert new entry. */
	ale = (ATTR_LIST_ENTRY *) ni->attr_list;
	for(; (u8 *)ale < ni->attr_list + ni->attr_list_size;
				ale = (ATTR_LIST_ENTRY *)((u8 *) ale +
				le16_to_cpu(ale->length))) {
		if (le32_to_cpu(ale->type) < le32_to_cpu(attr->type))
			continue;
		if (le32_to_cpu(ale->type) > le32_to_cpu(attr->type))
			break;
		err = ntfs_names_collate(ale->name, ale->name_length,
			(ntfschar *)((u8 *)attr + attr->name_length),
			attr->name_length, -2, CASE_SENSITIVE, 0, 0);
		if (err == -2) {
			err = EIO;
			Dprintf("%s(): Corrupt attribute name. Run chkdsk.\n",
						__FUNCTION__);
			goto err_out;
		}
		if (err < 0)
			continue;
		if (err > 0)
			break;
		if (sle64_to_cpu(ale->lowest_vcn) <
				sle64_to_cpu(attr->lowest_vcn))
			continue;
		if (sle64_to_cpu(ale->lowest_vcn) ==
				sle64_to_cpu(attr->lowest_vcn)) {
			err = EINVAL;
			Dprintf("%s(): Attribute with same type, name and "
				"lowest vcn already present in attribute "
				"list.\n", __FUNCTION__);
			goto err_out;
		}
		break;
	}

	/* Copy entries from old attribute list to new. */
	memcpy(new_al, ni->attr_list, (u8 *)ale - ni->attr_list);
	memcpy(new_al + new_al_len - ni->attr_list_size + ((u8 *)ale -
			ni->attr_list), ale, ni->attr_list_size -
			((u8 *)ale - ni->attr_list));

	/* Set pointer to new entry. */
	ale = (ATTR_LIST_ENTRY *)(new_al + ((u8 *)ale - ni->attr_list));

	/* Fill new entry with values. */
	ale->type = attr->type;
	ale->length = cpu_to_le16(new_al_len - ni->attr_list_size);
	ale->name_length = attr->name_length;
	ale->name_offset = (u8 *)ale->name - (u8 *)ale;
	if (attr->non_resident)
		ale->lowest_vcn = attr->lowest_vcn;
	else
		ale->lowest_vcn = 0;
	ale->mft_reference = mref;
	ale->instance = attr->instance;
	memcpy(ale->name, (u8 *)attr + attr->name_offset, attr->name_length);

	/* Set new runlist. */
	if (ntfs_attrlist_set(ni, new_al, new_al_len)) {
		err = errno;
		goto err_out;
	}

	return 0;
err_out:
	free(new_al);
	errno = err;
	return -1;
}

/**
 * ntfs_attrlist_entry_rm - remove an attribute list attribute entry
 * @ctx:	attribute search context describing the attrubute list entry
 *
 * Remove the attribute list entry @ctx->al_entry from the attribute list
 * attribute of the base mft record to which the attribute @ctx->attr belongs.
 *
 * Return 0 on success and -1 on error with errno set to the error code.
 */
int ntfs_attrlist_entry_rm(ntfs_attr_search_ctx *ctx)
{
	u8 *new_al;
	int new_al_len;
	ntfs_inode *base_ni;
	ATTR_LIST_ENTRY *ale;
	int err;

	if (!ctx || !ctx->ntfs_ino || !ctx->attr || !ctx->al_entry) {
		Dprintf("%s(): Invalid argumets.\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	if (ctx->base_ntfs_ino)
		base_ni = ctx->base_ntfs_ino;
	else
		base_ni = ctx->ntfs_ino;
	ale = ctx->al_entry;

	Dprintf("%s(): Entering for inode 0x%llx, attr 0x%x, lowest_vcn "
		"%lld.\n", __FUNCTION__, (long long) ctx->ntfs_ino->mft_no,
		(unsigned) le32_to_cpu(ctx->attr->type),
		(long long) le64_to_cpu(ctx->attr->lowest_vcn));
	
	if (!NInoAttrList(base_ni)) {
		Dprintf("%s(): Attribute list isn't present.\n", __FUNCTION__);
		errno = ENOENT;
		return -1;
	}

	/* Allocate memory for new attribute list. */
	new_al_len = base_ni->attr_list_size - le16_to_cpu(ale->length);
	new_al = malloc(new_al_len);
	if (!new_al) {
		Dprintf("%s(): Not enough memory.\n", __FUNCTION__);
		errno = ENOMEM;
		return -1;
	}

	/* Copy entries from old attribute list to new. */
	memcpy(new_al, base_ni->attr_list, (u8*)ale - base_ni->attr_list);
	memcpy(new_al + ((u8*)ale - base_ni->attr_list), (u8*)ale + le16_to_cpu(
		ale->length), new_al_len - ((u8*)ale - base_ni->attr_list));

	/* Set new runlist. */
	if (ntfs_attrlist_set(base_ni, new_al, new_al_len)) {
		err = errno;
		goto err_out;
	}
	return 0;
err_out:
	free(new_al);
	errno = err;
	return -1;
}
