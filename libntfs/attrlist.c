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
 * ntfs_attrlist_entry_add - add an attribute list attribute entry
 * @ni:		opened ntfs inode, which contains that attribute
 * @attr:	attribute record to add to attribute list
 *
 * Return 0 on success and -1 on error with errno set to the error code. The
 * following error codes are defined:
 *	EINVAL	- Invalid argumets passed to function.
 *	ENOMEM	- Not enough memory to allocate necessary buffers.
 *	EIO	- I/O error occured or damaged filesystem.
 */
int ntfs_attrlist_entry_add(ntfs_inode *ni, ATTR_RECORD *attr)
{
	ATTR_LIST_ENTRY *ale;
	MFT_REF mref;
	ntfs_attr *na = NULL;
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

	/* Determine size and allocate memory for new attribute list. */
	new_al_len = (ni->attr_list_size + sizeof(ATTR_LIST_ENTRY) +
			sizeof(ntfschar) * attr->name_length + 7) & ~7;
	new_al = malloc(new_al_len);
	if (!new_al) {
		Dprintf("%s(): Not enough memory.\n", __FUNCTION__);
		err = ENOMEM;
		return -1;
	}

	/* Reisze $ATTRIBUTE_LIST to new length. */
	na = ntfs_attr_open(ni, AT_ATTRIBUTE_LIST, NULL, 0);
	if (!na) {
		err = errno;
		Dprintf("%s(): Failed to open $ATTRIBUTE_LIST attribute.\n",
					__FUNCTION__);
		goto err_out;
	}
	if (ntfs_attr_truncate(na, new_al_len)) {
		err = errno;
		Dprintf("%s(): $ATTRIBUTE_LIST resize failed.\n", __FUNCTION__);
		goto err_out;
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
			(ntfschar*)((u8*)attr + le16_to_cpu(attr->name_offset)),
			attr->name_length, -2, CASE_SENSITIVE, NULL, 0);
		if (err == -2) {
			err = EIO;
			Dprintf("%s(): Corrupt attribute name. Run chkdsk.\n",
						__FUNCTION__);
			goto rollback;
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
			goto rollback;
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
	memcpy(ale->name, (u8 *)attr + attr->name_offset,
			attr->name_length * sizeof(ntfschar));

	/* Set new runlist. */
	if (ni->attr_list)
		free(ni->attr_list);
	ni->attr_list = new_al;
	ni->attr_list_size = new_al_len;
	NInoAttrListSetDirty(ni);
	/* Done! */
	ntfs_attr_close(na);
	return 0;
rollback:
	if (ntfs_attr_truncate(na, ni->attr_list_size)) {
		Dprintf("%s(): $ATTRIBUTE_LIST resize failed. Rollback failed. "
				"Leaving inconsist metadata.\n", __FUNCTION__);
	}
err_out:
	if (na)
		ntfs_attr_close(na);
	free(new_al);
	errno = err;
	return -1;
}

/**
 * ntfs_attrlist_entry_rm - remove an attribute list attribute entry
 * @ctx:	attribute search context describing the attrubute list entry
 *
 * Remove the attribute list entry @ctx->al_entry from the attribute list.
 *
 * Return 0 on success and -1 on error with errno set to the error code.
 */
int ntfs_attrlist_entry_rm(ntfs_attr_search_ctx *ctx)
{
	u8 *new_al;
	int new_al_len;
	ntfs_inode *base_ni;
	ntfs_attr *na;
	ATTR_LIST_ENTRY *ale;
	int err;

	if (!ctx || !ctx->ntfs_ino || !ctx->al_entry) {
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
		(unsigned) le32_to_cpu(ctx->al_entry->type),
		(long long) le64_to_cpu(ctx->al_entry->lowest_vcn));
	
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
	
	/* Reisze $ATTRIBUTE_LIST to new length. */
	na = ntfs_attr_open(base_ni, AT_ATTRIBUTE_LIST, NULL, 0);
	if (!na) {
		err = errno;
		Dprintf("%s(): Failed to open $ATTRIBUTE_LIST attribute.\n",
					__FUNCTION__);
		goto err_out;
	}
	if (ntfs_attr_truncate(na, new_al_len)) {
		err = errno;
		Dprintf("%s(): $ATTRIBUTE_LIST resize failed.\n", __FUNCTION__);
		goto err_out;
	}

	/* Copy entries from old attribute list to new. */
	memcpy(new_al, base_ni->attr_list, (u8*)ale - base_ni->attr_list);
	memcpy(new_al + ((u8*)ale - base_ni->attr_list), (u8*)ale + le16_to_cpu(
		ale->length), new_al_len - ((u8*)ale - base_ni->attr_list));

	/* Set new runlist. */
	if (base_ni->attr_list)
		free(base_ni->attr_list);
	base_ni->attr_list = new_al;
	base_ni->attr_list_size = new_al_len;
	NInoAttrListSetDirty(base_ni);
	/* Done! */
	ntfs_attr_close(na);
	return 0;
err_out:
	if (na)
		ntfs_attr_close(na);
	free(new_al);
	errno = err;
	return -1;
}
