/*
 * index.h - Defines for NTFS index handling.  Part of the Linux-NTFS project.
 *
 * Copyright (c) 2004 Anton Altaparmakov
 * Copyright (c) 2005 Yura Pakhuchiy
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

#ifndef _NTFS_INDEX_H
#define _NTFS_INDEX_H

#include "attrib.h"
#include "types.h"
#include "layout.h"
#include "inode.h"
#include "mft.h"

/**
 * struct ntfs_index_context -
 * @ni:		inode containing the @entry described by this context
 * @name:	name of the index described by this context
 * @name_len:	length of the index name
 * @entry:	index entry (points into @ir or @ia)
 * @data:	index entry data (points into @entry)
 * @data_len:	length in bytes of @data
 * @is_in_root:	TRUE if @entry is in @ir and FALSE if it is in @ia
 * @ir:		index root if @is_in_root and NULL otherwise
 * @actx:	attribute search context if @is_in_root and NULL otherwise
 * @ia:		index block if @is_in_root is FALSE and NULL otherwise
 * @ia_na:	opened INDEX_ALLOCATION attribute
 * @ia_vcn:	VCN from which @ia where read from
 * @ia_dirty:	TRUE if index block was changed
 * @block_size:	index block size
 *
 * @ni is the inode this context belongs to.
 *
 * @entry is the index entry described by this context.  @data and @data_len
 * are the index entry data and its length in bytes, respectively.  @data
 * simply points into @entry.  This is probably what the user is interested in.
 *
 * If @is_in_root is TRUE, @entry is in the index root attribute @ir described
 * by the attribute search context @actx and inode @ni.  @ia, @ia_vcn and
 * @ia_dirty are undefined in this case.
 *
 * If @is_in_root is FALSE, @entry is in the index allocation attribute and @ia
 * and @ia_vcn point to the index allocation block and VCN where it's placed,
 * respectively. @ir and @actx are NULL in this case. @ia_na is opened
 * INDEX_ALLOCATION attribute. @ia_dirty is TRUE if index block was changed and
 * FALSE otherwise.
 *
 * To obtain a context call ntfs_index_ctx_get().
 *
 * When finished with the @entry and its @data, call ntfs_index_ctx_put() to
 * free the context and other associated resources.
 *
 * If the index entry was modified, call ntfs_index_entry_mark_dirty() before
 * the call to ntfs_index_ctx_put() to ensure that the changes are written
 * to disk.
 */
typedef struct {
	ntfs_inode *ni;
	ntfschar *name;
	u32 name_len;
	INDEX_ENTRY *entry;
	void *data;
	u16 data_len;
	BOOL is_in_root;
	INDEX_ROOT *ir;
	ntfs_attr_search_ctx *actx;
	INDEX_ALLOCATION *ia;
	ntfs_attr *ia_na;
	VCN ia_vcn;
	BOOL ia_dirty;
	u32 block_size;
} ntfs_index_context;

extern ntfs_index_context *ntfs_index_ctx_get(ntfs_inode *ni,
						ntfschar *name, u32 name_len);
extern void ntfs_index_ctx_put(ntfs_index_context *ictx);
extern void ntfs_index_ctx_reinit(ntfs_index_context *ictx);

extern int ntfs_index_lookup(const void *key, const int key_len,
		ntfs_index_context *ictx);

extern int ntfs_index_add_filename(ntfs_inode *ni, FILE_NAME_ATTR *fn,
		MFT_REF mref);
extern int ntfs_index_rm(ntfs_index_context *ictx);

/**
 * ntfs_index_entry_mark_dirty - mark an index entry dirty
 * @ictx:	ntfs index context describing the index entry
 *
 * Mark the index entry described by the index entry context @ictx dirty.
 *
 * If the index entry is in the index root attribute, simply mark the inode
 * containing the index root attribute dirty.  This ensures the mftrecord, and
 * hence the index root attribute, will be written out to disk later.
 *
 * If the index entry is in an index block belonging to the index allocation
 * attribute, set ia_dirty to TRUE, thus index block will be updated during
 * ntfs_index_ctx_put.
 */
static inline void ntfs_index_entry_mark_dirty(ntfs_index_context *ictx)
{
	if (ictx->is_in_root)
		ntfs_inode_mark_dirty(ictx->actx->ntfs_ino);
	else
		ictx->ia_dirty = TRUE;
}


#ifdef NTFS_RICH

#include "layout.h"

void ntfs_ie_free(INDEX_ENTRY *ie);
INDEX_ENTRY * ntfs_ie_create(void);
VCN ntfs_ie_get_vcn(INDEX_ENTRY *ie);
INDEX_ENTRY * ntfs_ie_copy(INDEX_ENTRY *ie);
INDEX_ENTRY * ntfs_ie_set_vcn(INDEX_ENTRY *ie, VCN vcn);
INDEX_ENTRY * ntfs_ie_remove_vcn(INDEX_ENTRY *ie);
INDEX_ENTRY * ntfs_ie_set_name(INDEX_ENTRY *ie, ntfschar *name, int namelen, FILE_NAME_TYPE_FLAGS nametype);
INDEX_ENTRY * ntfs_ie_remove_name(INDEX_ENTRY *ie);

#endif /* NTFS_RICH */

#endif /* _NTFS_INDEX_H */

