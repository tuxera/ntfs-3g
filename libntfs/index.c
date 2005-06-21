/*
 * index.c - NTFS index handling.  Part of the Linux-NTFS project.
 *
 * Copyright (c) 2004-2005 Anton Altaparmakov
 * Copyright (c) 2005 Yura Pakhuchiy
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

#include "attrib.h"
#include "collate.h"
#include "debug.h"
#include "index.h"
#include "mst.h"

/**
 * ntfs_index_ctx_get - allocate and initialize a new index context
 * @ni:		ntfs inode with which to initialize the context
 * @name:	name of the which context describes
 * @name_len:	length of the index name
 *
 * Allocate a new index context, initialize it with @ni and return it.
 * Return NULL if allocation failed.
 */
ntfs_index_context *ntfs_index_ctx_get(ntfs_inode *ni,
					ntfschar *name, u32 name_len)
{
	ntfs_index_context *ictx;

	if (!ni) {
		errno = EINVAL;
		return NULL;
	}
	if (ni->nr_extents == -1)
		ni = ni->base_ni;
	ictx = malloc(sizeof(ntfs_index_context));
	if (ictx)
		*ictx = (ntfs_index_context) {
			.ni = ni,
			.name = name,
			.name_len = name_len
		};
	return ictx;
}

/**
 * ntfs_index_ctx_put - release an index context
 * @ictx:	index context to free
 *
 * Release the index context @ictx, releasing all associated resources.
 */
void ntfs_index_ctx_put(ntfs_index_context *ictx)
{
	if (ictx->entry) {
		if (ictx->is_in_root) {
			if (ictx->actx)
				ntfs_attr_put_search_ctx(ictx->actx);
		} else {
			/* Write out index block it it's dirty. */
			if (ictx->ia_dirty) {
				if (ntfs_attr_mst_pwrite(ictx->ia_na,
						ictx->ia_vcn <<
						ictx->ni->vol->
						cluster_size_bits,
						1, ictx->block_size,
						ictx->ia) != 1)
					ntfs_error(, "Failed to write out "
							"index block.");
			}
			/* Free resources. */
			free(ictx->ia);
			ntfs_attr_close(ictx->ia_na);
		}
	}
	free(ictx);
	return;
}

/**
 * ntfs_index_lookup - find a key in an index and return its index entry
 * @key:	[IN] key for which to search in the index
 * @key_len:	[IN] length of @key in bytes
 * @ictx:	[IN/OUT] context describing the index and the returned entry
 *
 * Before calling ntfs_index_lookup(), @ictx must have been obtained from a
 * call to ntfs_index_ctx_get().
 *
 * Look for the @key in the index specified by the index lookup context @ictx.
 * ntfs_index_lookup() walks the contents of the index looking for the @key.
 *
 * If the @key is found in the index, 0 is returned and @ictx is setup to
 * describe the index entry containing the matching @key.  @ictx->entry is the
 * index entry and @ictx->data and @ictx->data_len are the index entry data and
 * its length in bytes, respectively.
 *
 * If the @key is not found in the index, -1 is returned, errno = ENOENT and
 * @ictx is setup to describe the index entry whose key collates immediately
 * after the search @key, i.e. this is the position in the index at which
 * an index entry with a key of @key would need to be inserted.
 *
 * If an error occurs return -1, set errno to error code and @ictx is left
 * untouched.
 *
 * When finished with the entry and its data, call ntfs_index_ctx_put() to free
 * the context and other associated resources.
 *
 * If the index entry was modified, call ntfs_index_entry_mark_dirty() before
 * the call to ntfs_index_ctx_put() to ensure that the changes are written
 * to disk.
 */
int ntfs_index_lookup(const void *key, const int key_len,
		ntfs_index_context *ictx)
{
	COLLATION_RULES cr;
	VCN vcn;
	ntfs_inode *ni = ictx->ni;
	ntfs_volume *vol = ni->vol;
	INDEX_ROOT *ir;
	INDEX_ENTRY *ie;
	INDEX_ALLOCATION *ia = NULL;
	u8 *index_end;
	ntfs_attr_search_ctx *actx;
	ntfs_attr *na = NULL;
	int rc, err = 0;

	ntfs_debug("Entering.");
	if (!key || key_len <= 0) {
		errno = EINVAL;
		return -1;
	}

	actx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!actx) {
		err = ENOMEM;
		goto err_out;
	}

	/* Find the index root attribute in the mft record. */
	err = ntfs_attr_lookup(AT_INDEX_ROOT, ictx->name, ictx->name_len,
			CASE_SENSITIVE, 0, NULL, 0, actx);
	if (err) {
		if (errno == ENOENT) {
			ntfs_error(sb, "Index root attribute missing in inode "
					"0x%llx.", ni->mft_no);
			err = EIO;
		} else
			err = errno;
		goto err_out;
	}
	/* Get to the index root value (it has been verified in read_inode). */
	ir = (INDEX_ROOT*)((u8*)actx->attr +
			le16_to_cpu(actx->attr->value_offset));
	index_end = (u8*)&ir->index + le32_to_cpu(ir->index.index_length);
	/* Save index block size for future use. */
	ictx->block_size = ir->index_block_size;
	/* Get collation rule type and validate it. */
	cr = ir->collation_rule;
	if (!ntfs_is_collation_rule_supported(cr)) {
		ntfs_error(sb, "Index uses unsupported collation rule 0x%x.  "
				"Aborting lookup.", (unsigned)le32_to_cpu(cr));
		err = EOPNOTSUPP;
		goto err_out;
	}
	/* The first index entry. */
	ie = (INDEX_ENTRY*)((u8*)&ir->index +
			le32_to_cpu(ir->index.entries_offset));
	/*
	 * Loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */
	for (;; ie = (INDEX_ENTRY*)((u8*)ie + le16_to_cpu(ie->length))) {
		/* Bounds checks. */
		if ((u8*)ie < (u8*)actx->mrec || (u8*)ie +
				sizeof(INDEX_ENTRY_HEADER) > index_end ||
				(u8*)ie + le16_to_cpu(ie->length) > index_end)
			goto idx_err_out;
		/*
		 * The last entry cannot contain a key.  It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if (ie->flags & INDEX_ENTRY_END)
			break;
		/* If the keys match perfectly, we setup @ictx and return 0. */
		if ((key_len == le16_to_cpu(ie->key_length)) && !memcmp(key,
				&ie->key, key_len)) {
ir_done:
			ictx->is_in_root = TRUE;
			ictx->actx = actx;
			ictx->ia = NULL;
done:
			ictx->entry = ie;
			ictx->data = (u8*)ie + offsetof(INDEX_ENTRY, key);
			ictx->data_len = le16_to_cpu(ie->key_length);
			ntfs_debug("Done.");
			if (err) {
				errno = err;
				return -1;
			}
			return 0;
		}
		/*
		 * Not a perfect match, need to do full blown collation so we
		 * know which way in the B+tree we have to go.
		 */
		rc = ntfs_collate(vol, cr, key, key_len, &ie->key,
				le16_to_cpu(ie->key_length));
		/*
		 * If @key collates before the key of the current entry, there
		 * is definitely no such key in this index but we might need to
		 * descend into the B+tree so we just break out of the loop.
		 */
		if (rc == -1)
			break;
		/*
		 * A match should never happen as the memcmp() call should have
		 * cought it, but we still treat it correctly.
		 */
		if (!rc)
			goto ir_done;
		/* The keys are not equal, continue the search. */
	}
	/*
	 * We have finished with this index without success.  Check for the
	 * presence of a child node and if not present setup @ictx and return
	 * -1 with errno ENOENT.
	 */
	if (!(ie->flags & INDEX_ENTRY_NODE)) {
		ntfs_debug("Entry not found.");
		err = ENOENT;
		goto ir_done;
	} /* Child node present, descend into it. */
	/* Get the starting vcn of the index_block holding the child node. */
	vcn = sle64_to_cpup((sle64*)((u8*)ie + le16_to_cpu(ie->length) - 8));
	/* We are done with the index root. Release attribute search ctx. */
	ntfs_attr_put_search_ctx(actx);
	actx = NULL;
	/* Open INDEX_ALLOCATION. */
	na = ntfs_attr_open(ni, AT_INDEX_ALLOCATION,
				ictx->name, ictx->name_len);
	if (!na) {
		ntfs_error(sb, "No index allocation attribute but index entry "
				"requires one.  Inode 0x%llx is corrupt or "
				"library bug.", ni->mft_no);
		goto err_out;
	}
	/* Allocate memory to store index block. */
	ia = malloc(ictx->block_size);
	if (!ia) {
		ntfs_error(, "Not enough memory to allocate buffer for index"
				" allocation.");
		err = ENOMEM;
		goto err_out;
	}
descend_into_child_node:
	ntfs_debug("Descend into node with VCN %lld.", vcn);
	/* Read index allocation block. */
	if (ntfs_attr_mst_pread(na, vcn << vol->cluster_size_bits, 1,
				ictx->block_size, ia) != 1) {
		ntfs_error(, "Failed to read index allocation.");
		goto err_out;
	}
	/* Catch multi sector transfer fixup errors. */
	if (!ntfs_is_indx_record(ia->magic)) {
		ntfs_error(sb, "Index record with vcn 0x%llx is corrupt.  "
				"Corrupt inode 0x%llx.  Run chkdsk.",
				(long long)vcn, ni->mft_no);
		goto err_out;
	}
	if (sle64_to_cpu(ia->index_block_vcn) != vcn) {
		ntfs_error(sb, "Actual VCN (0x%llx) of index buffer is "
				"different from expected VCN (0x%llx).  Inode "
				"0x%llx is corrupt or driver bug.",
				(unsigned long long)
				sle64_to_cpu(ia->index_block_vcn),
				(unsigned long long)vcn, ni->mft_no);
		goto err_out;
	}
	if (le32_to_cpu(ia->index.allocated_size) + 0x18 != ictx->block_size) {
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of inode 0x%llx has "
				"a size (%u) differing from the index "
				"specified size (%u).  Inode is corrupt or "
				"driver bug.", (unsigned long long)vcn,
				ni->mft_no, (unsigned)
				le32_to_cpu(ia->index.allocated_size) + 0x18,
				(unsigned)ictx->block_size);
		goto err_out;
	}
	index_end = (u8*)&ia->index + le32_to_cpu(ia->index.index_length);
	if (index_end > (u8*)ia + ictx->block_size) {
		ntfs_error(sb, "Size of index buffer (VCN 0x%llx) of inode "
				"0x%llx exceeds maximum size.",
				(unsigned long long)vcn, ni->mft_no);
		goto err_out;
	}
	/* The first index entry. */
	ie = (INDEX_ENTRY*)((u8*)&ia->index +
			le32_to_cpu(ia->index.entries_offset));
	/*
	 * Iterate similar to above big loop but applied to index buffer, thus
	 * loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */
	for (;; ie = (INDEX_ENTRY*)((u8*)ie + le16_to_cpu(ie->length))) {
		/* Bounds checks. */
		if ((u8*)ie < (u8*)ia || (u8*)ie +
				sizeof(INDEX_ENTRY_HEADER) > index_end ||
				(u8*)ie + le16_to_cpu(ie->length) > index_end) {
			ntfs_error(sb, "Index entry out of bounds in inode "
					"0x%llx.", ni->mft_no);
			goto err_out;
		}
		/*
		 * The last entry cannot contain a key.  It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if (ie->flags & INDEX_ENTRY_END)
			break;
		/* If the keys match perfectly, we setup @ictx and return 0. */
		if ((key_len == le16_to_cpu(ie->key_length)) && !memcmp(key,
				&ie->key, key_len)) {
ia_done:
			ictx->is_in_root = FALSE;
			ictx->actx = NULL;
			ictx->ia = ia;
			ictx->ia_vcn = vcn;
			ictx->ia_na = na;
			goto done;
		}
		/*
		 * Not a perfect match, need to do full blown collation so we
		 * know which way in the B+tree we have to go.
		 */
		rc = ntfs_collate(vol, cr, key,	key_len, &ie->key,
				le16_to_cpu(ie->key_length));
		/*
		 * If @key collates before the key of the current entry, there
		 * is definitely no such key in this index but we might need to
		 * descend into the B+tree so we just break out of the loop.
		 */
		if (rc == -1)
			break;
		/*
		 * A match should never happen as the memcmp() call should have
		 * cought it, but we still treat it correctly.
		 */
		if (!rc)
			goto ia_done;
		/* The keys are not equal, continue the search. */
	}
	/*
	 * We have finished with this index buffer without success.  Check for
	 * the presence of a child node and if not present return ENOENT.
	 */
	if (!(ie->flags & INDEX_ENTRY_NODE)) {
		ntfs_debug("Entry not found.");
		err = ENOENT;
		goto ia_done;
	}
	if ((ia->index.flags & NODE_MASK) == LEAF_NODE) {
		ntfs_error(sb, "Index entry with child node found in a leaf "
				"node in inode 0x%llx.", ni->mft_no);
		goto err_out;
	}
	/* Child node present, descend into it. */
	vcn = sle64_to_cpup((sle64*)((u8*)ie + le16_to_cpu(ie->length) - 8));
	if (vcn >= 0)
		goto descend_into_child_node;
	ntfs_error(sb, "Negative child node vcn in inode 0x%llx.", ni->mft_no);
err_out:
	if (na)
		ntfs_attr_close(na);
	if (ia)
		free(ia);
	if (!err)
		err = EIO;
	if (actx)
		ntfs_attr_put_search_ctx(actx);
	errno = err;
	return -1;
idx_err_out:
	ntfs_error(sb, "Corrupt index.  Aborting lookup.");
	goto err_out;
}

