/**
 * index.c - NTFS index handling.  Part of the Linux-NTFS project.
 *
 * Copyright (c) 2004-2005 Anton Altaparmakov
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "attrib.h"
#include "collate.h"
#include "debug.h"
#include "index.h"
#include "mst.h"
#include "dir.h"
#include "logging.h"

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
			.name_len = name_len,
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
					ntfs_log_error("Failed to write out "
							"index block.");
			}
			/* Free resources. */
			free(ictx->ia);
			ntfs_attr_close(ictx->ia_na);
		}
	}
	free(ictx);
}

/**
 * ntfs_index_ctx_reinit - reinitialize an index context
 * @ictx:	index context to reinitialize
 *
 * Reintialize the index context @ictx so it can be used for ntfs_index_lookup.
 */
void ntfs_index_ctx_reinit(ntfs_index_context *ictx)
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
					ntfs_log_error("Failed to write out "
							"index block.");
			}
			/* Free resources. */
			free(ictx->ia);
			ntfs_attr_close(ictx->ia_na);
		}
	}
	*ictx = (ntfs_index_context) {
		.ni = ictx->ni,
		.name = ictx->name,
		.name_len = ictx->name_len,
	};
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

	ntfs_log_trace("Entering.\n");
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
			ntfs_log_error("Index root attribute missing in inode "
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
	ictx->block_size = le32_to_cpu(ir->index_block_size);
	/* Get collation rule type and validate it. */
	cr = ir->collation_rule;
	if (!ntfs_is_collation_rule_supported(cr)) {
		ntfs_log_error("Index uses unsupported collation rule 0x%x.  "
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
			ictx->ir = ir;
done:
			ictx->entry = ie;
			ictx->data = (u8*)ie + offsetof(INDEX_ENTRY, key);
			ictx->data_len = le16_to_cpu(ie->key_length);
			ntfs_log_trace("Done.\n");
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
		if (rc == NTFS_COLLATION_ERROR) {
			ntfs_log_error("Collation error. Probably filename "
					"contain invalid characters.");
			err = ERANGE;
			goto err_out;
		}
		/*
		 * If @key collates before the key of the current entry, there
		 * is definitely no such key in this index but we might need to
		 * descend into the B+tree so we just break out of the loop.
		 */
		if (rc == -1)
			break;
		/*
		 * A match should never happen as the memcmp() call should have
		 * caught it, but we still treat it correctly.
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
		ntfs_log_debug("Entry not found.\n");
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
		ntfs_log_error("No index allocation attribute but index entry "
				"requires one.  Inode 0x%llx is corrupt or "
				"library bug.", ni->mft_no);
		goto err_out;
	}
	/* Allocate memory to store index block. */
	ia = malloc(ictx->block_size);
	if (!ia) {
		ntfs_log_error("Not enough memory to allocate buffer for index"
				" allocation.");
		err = ENOMEM;
		goto err_out;
	}
descend_into_child_node:
	ntfs_log_debug("Descend into node with VCN %lld.\n", vcn);
	/* Read index allocation block. */
	if (ntfs_attr_mst_pread(na, vcn << vol->cluster_size_bits, 1,
				ictx->block_size, ia) != 1) {
		ntfs_log_error("Failed to read index allocation.");
		goto err_out;
	}
	/* Catch multi sector transfer fixup errors. */
	if (!ntfs_is_indx_record(ia->magic)) {
		ntfs_log_error("Index record with vcn 0x%llx is corrupt.  "
				"Corrupt inode 0x%llx.  Run chkdsk.",
				(long long)vcn, ni->mft_no);
		goto err_out;
	}
	if (sle64_to_cpu(ia->index_block_vcn) != vcn) {
		ntfs_log_error("Actual VCN (0x%llx) of index buffer is "
				"different from expected VCN (0x%llx).  Inode "
				"0x%llx is corrupt or driver bug.",
				(unsigned long long)
				sle64_to_cpu(ia->index_block_vcn),
				(unsigned long long)vcn, ni->mft_no);
		goto err_out;
	}
	if (le32_to_cpu(ia->index.allocated_size) + 0x18 != ictx->block_size) {
		ntfs_log_error("Index buffer (VCN 0x%llx) of inode 0x%llx has "
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
		ntfs_log_error("Size of index buffer (VCN 0x%llx) of inode "
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
			ntfs_log_error("Index entry out of bounds in inode "
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
		if (rc == NTFS_COLLATION_ERROR) {
			ntfs_log_error("Collation error. Probably filename "
					"contain invalid characters.");
			err = ERANGE;
			goto err_out;
		}
		/*
		 * If @key collates before the key of the current entry, there
		 * is definitely no such key in this index but we might need to
		 * descend into the B+tree so we just break out of the loop.
		 */
		if (rc == -1)
			break;
		/*
		 * A match should never happen as the memcmp() call should have
		 * caught it, but we still treat it correctly.
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
		ntfs_log_debug("Entry not found.\n");
		err = ENOENT;
		goto ia_done;
	}
	if ((ia->index.flags & NODE_MASK) == LEAF_NODE) {
		ntfs_log_error("Index entry with child node found in a leaf "
				"node in inode 0x%llx.", ni->mft_no);
		goto err_out;
	}
	/* Child node present, descend into it. */
	vcn = sle64_to_cpup((sle64*)((u8*)ie + le16_to_cpu(ie->length) - 8));
	if (vcn >= 0)
		goto descend_into_child_node;
	ntfs_log_error("Negative child node vcn in inode 0x%llx.", ni->mft_no);
err_out:
	if (na)
		ntfs_attr_close(na);
	free(ia);
	if (!err)
		err = EIO;
	if (actx)
		ntfs_attr_put_search_ctx(actx);
	errno = err;
	return -1;
idx_err_out:
	ntfs_log_error("Corrupt index.  Aborting lookup.");
	goto err_out;
}

/**
 * ntfs_index_add_filename - add filename to directory index
 * @ni:		ntfs inode describing directory to which index add filename
 * @fn:		FILE_NAME attribute to add
 * @mref:	reference of the inode which @fn describes
 *
 * NOTE: This function does not support all cases, so it can fail with
 * EOPNOTSUPP error code.
 *
 * Return 0 on success or -1 on error with errno set to the error code.
 */
int ntfs_index_add_filename(ntfs_inode *ni, FILE_NAME_ATTR *fn, MFT_REF mref)
{
	ntfs_index_context *ictx;
	INDEX_ENTRY *ie;
	INDEX_HEADER *ih;
	int err, fn_size, ie_size, allocated_size = 0;

	ntfs_log_trace("Entering.\n");
	if (!ni || !fn) {
		ntfs_log_error("Invalid arguments.");
		errno = EINVAL;
		return -1;
	}
	ictx = ntfs_index_ctx_get(ni, NTFS_INDEX_I30, 4);
	if (!ictx)
		return -1;
	fn_size = (fn->file_name_length * sizeof(ntfschar)) +
			sizeof(FILE_NAME_ATTR);
	ie_size = (sizeof(INDEX_ENTRY_HEADER) + fn_size + 7) & ~7;
retry:
	/* Find place where insert new entry. */
	if (!ntfs_index_lookup(fn, fn_size, ictx)) {
		err = EEXIST;
		ntfs_log_error("Index already have such entry.");
		goto err_out;
	}
	if (errno != ENOENT) {
		err = errno;
		ntfs_log_error("Failed to find place where to insert new entry.");
		goto err_out;
	}
	/* Some setup. */
	if (ictx->is_in_root)
		ih = &ictx->ir->index;
	else
		ih = &ictx->ia->index;
	if (!allocated_size)
		allocated_size = le16_to_cpu(ih->allocated_size);
	/* Check whether we have enough space in the index. */
	if (le16_to_cpu(ih->index_length) + ie_size > allocated_size) {
		/* If we in the index root try to resize it. */
		if (ictx->is_in_root) {
			ntfs_attr *na;

			allocated_size = le16_to_cpu(ih->index_length) +
					ie_size;
			na = ntfs_attr_open(ictx->ni, AT_INDEX_ROOT, ictx->name,
					ictx->name_len);
			if (!na) {
				err = errno;
				ntfs_log_error("Failed to open INDEX_ROOT.");
				goto err_out;
			}
			if (ntfs_attr_truncate(na, allocated_size + offsetof(
					INDEX_ROOT, index))) {
				err = EOPNOTSUPP;
				ntfs_attr_close(na);
				ntfs_log_error("Failed to truncate INDEX_ROOT.");
				goto err_out;
			}
			ntfs_attr_close(na);
			ntfs_index_ctx_reinit(ictx);
			goto retry;
		}
		ntfs_log_debug("Not implemented case.\n");
		err = EOPNOTSUPP;
		goto err_out;
	}
	/* Update allocated size if we in INDEX_ROOT. */
	if (ictx->is_in_root)
		ih->allocated_size = cpu_to_le16(allocated_size);
	/* Create entry. */
	ie = calloc(1, ie_size);
	if (!ie) {
		err = errno;
		goto err_out;
	}
	ie->indexed_file = cpu_to_le64(mref);
	ie->length = cpu_to_le16(ie_size);
	ie->key_length = cpu_to_le16(fn_size);
	memcpy(&ie->key, fn, fn_size);
	/* Update index length, move following entries forard and copy entry. */
	ih->index_length = cpu_to_le16(le16_to_cpu(ih->index_length) + ie_size);
	memmove((u8*)ictx->entry + ie_size, ictx->entry,
			le16_to_cpu(ih->index_length) -
			((u8*)ictx->entry - (u8*)ih) - ie_size);
	memcpy(ictx->entry, ie, ie_size);
	/* Done! */
	ntfs_index_entry_mark_dirty(ictx);
	ntfs_index_ctx_put(ictx);
	free(ie);
	ntfs_log_trace("Done.\n");
	return 0;
err_out:
	ntfs_log_trace("Failed.\n");
	ntfs_index_ctx_put(ictx);
	errno = err;
	return -1;
}

/**
 * ntfs_index_rm - remove entry from the index
 * @ictx:	index context describing entry to delete
 *
 * Delete entry described by @ictx from the index. NOTE: This function does not
 * support all cases, so it can fail with EOPNOTSUPP error code. In any case
 * index context is always reinitialized after use of this function, so it can
 * be used for index lookup once again.
 *
 * Return 0 on success or -1 on error with errno set to the error code.
 */
int ntfs_index_rm(ntfs_index_context *ictx)
{
	INDEX_HEADER *ih;
	u32 new_index_length;
	int err;

	ntfs_log_trace("Entering.\n");
	if (!ictx || (!ictx->ia && !ictx->ir) ||
			ictx->entry->flags & INDEX_ENTRY_END) {
		ntfs_log_error("Invalid arguments.");
		err = EINVAL;
		goto err_out;
	}
	if (ictx->is_in_root)
		ih = &ictx->ir->index;
	else
		ih = &ictx->ia->index;
	/* Don't support deletion of entries with subnodes yet. */
	if (ictx->entry->flags & INDEX_ENTRY_NODE) {
		err = EOPNOTSUPP;
		goto err_out;
	}
	/* Calculate new length of the index. */
	new_index_length = le32_to_cpu(ih->index_length) -
			le16_to_cpu(ictx->entry->length);
	/* Don't support deletion of the last entry in the allocation block. */
	if (!ictx->is_in_root && (new_index_length <=
			le32_to_cpu(ih->entries_offset) +
			sizeof(INDEX_ENTRY_HEADER) + sizeof(VCN))) {
		err = EOPNOTSUPP;
		goto err_out;
	}
	/* Update index length and remove index entry. */
	ih->index_length = cpu_to_le32(new_index_length);
	if (ictx->is_in_root)
		ih->allocated_size = ih->index_length;
	memmove(ictx->entry, (u8*)ictx->entry + le16_to_cpu(
			ictx->entry->length), new_index_length -
			((u8*)ictx->entry - (u8*)ih));
	ntfs_index_entry_mark_dirty(ictx);
	/* Resize INDEX_ROOT attribute. */
	if (ictx->is_in_root) {
		ntfs_attr *na;

		na = ntfs_attr_open(ictx->ni, AT_INDEX_ROOT, ictx->name,
				ictx->name_len);
		if (!na) {
			err = errno;
			ntfs_log_error("Failed to open INDEX_ROOT attribute.  "
					"Leaving inconsist metadata.");
			goto err_out;
		}
		if (ntfs_attr_truncate(na, new_index_length + offsetof(
				INDEX_ROOT, index))) {
			err = errno;
			ntfs_log_error("Failed to truncate INDEX_ROOT attribute. "
					" Leaving inconsist metadata.");
			goto err_out;
		}
		ntfs_attr_close(na);
	}
	ntfs_index_ctx_reinit(ictx);
	ntfs_log_trace("Done.\n");
	return 0;
err_out:
	ntfs_index_ctx_reinit(ictx);
	ntfs_log_trace("Failed.\n");
	errno = err;
	return -1;
}


#ifdef NTFS_RICH

#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "rich.h"

/**
 * ntfs_ie_free
 */
void ntfs_ie_free(INDEX_ENTRY *ie)
{
	free(ie);
}

/**
 * ntfs_ie_create
 */
INDEX_ENTRY * ntfs_ie_create(void)
{
	int length;
	INDEX_ENTRY *ie;

	length = 16;
	ie = calloc(1, length);
	if (!ie)
		return NULL;

	ie->indexed_file = 0;
	ie->length       = length;
	ie->key_length   = 0;
	ie->flags        = INDEX_ENTRY_END;
	ie->reserved     = 0;
	return ie;
}

/**
 * ntfs_ie_get_vcn
 */
VCN ntfs_ie_get_vcn(INDEX_ENTRY *ie)
{
	if (!ie)
		return -1;
	if (!(ie->flags & INDEX_ENTRY_NODE))
		return -1;

	return *((VCN*) ((u8*) ie + ie->length - 8));
}

/**
 * ntfs_ie_copy
 */
INDEX_ENTRY * ntfs_ie_copy(INDEX_ENTRY *ie)
{
	INDEX_ENTRY *copy = NULL;

	if (!ie)
		return NULL;

	copy = malloc(ie->length);
	if (!copy)
		return NULL;
	memcpy(copy, ie, ie->length);

	return copy;
}

/**
 * ntfs_ie_set_vcn
 */
INDEX_ENTRY * ntfs_ie_set_vcn(INDEX_ENTRY *ie, VCN vcn)
{
	if (!ie)
		return 0;

	if (!(ie->flags & INDEX_ENTRY_NODE)) {
		ie->length += 8;
		ie = realloc(ie, ie->length);
		if (!ie)
			return NULL;

		ie->flags |= INDEX_ENTRY_NODE;
	}

	*((VCN*) ((u8*) ie + ie->length - 8)) = vcn;
	return ie;
}

/**
 * ntfs_ie_remove_vcn
 */
INDEX_ENTRY * ntfs_ie_remove_vcn(INDEX_ENTRY *ie)
{
	if (!ie)
		return NULL;
	if (!(ie->flags & INDEX_ENTRY_NODE))
		return ie;

	ie->length -= 8;
	ie->flags &= ~INDEX_ENTRY_NODE;
	ie = realloc(ie, ie->length);
	return ie;
}

/**
 * ntfs_ie_set_name
 */
INDEX_ENTRY * ntfs_ie_set_name(INDEX_ENTRY *ie, ntfschar *name, int namelen, FILE_NAME_TYPE_FLAGS nametype)
{
	FILE_NAME_ATTR *file;
	int need;
	BOOL wipe = FALSE;
	VCN vcn = 0;

	if (!ie || !name)
		return NULL;

	/*
	 * INDEX_ENTRY
	 *	MFT_REF indexed_file;
	 *	u16 length;
	 *	u16 key_length;
	 *	INDEX_ENTRY_FLAGS flags;
	 *	u16 reserved;
	 *
	 *	FILENAME
	 *		MFT_REF parent_directory;
	 *		s64 creation_time;
	 *		s64 last_data_change_time;
	 *		s64 last_mft_change_time;
	 *		s64 last_access_time;
	 *		s64 allocated_size;
	 *		s64 data_size;
	 *		FILE_ATTR_FLAGS file_attributes;
	 *		u32 reserved;
	 *		u8 file_name_length;
	 *		FILE_NAME_TYPE_FLAGS file_name_type;
	 *		ntfschar file_name[l];
	 *		u8 reserved[n]
	 *
	 *	VCN vcn;
	 */

	//ntfs_log_debug("key length = 0x%02X\n", ie->key_length);
	//ntfs_log_debug("new name length = %d\n", namelen);
	if (ie->key_length > 0) {
		file = &ie->key.file_name;
		//ntfs_log_debug("filename, length %d\n", file->file_name_length);
		need =  ATTR_SIZE(namelen * sizeof(ntfschar) + 2) -
			ATTR_SIZE(file->file_name_length * sizeof(ntfschar) + 2);
	} else {
		//ntfs_log_debug("no filename\n");
		need = ATTR_SIZE(sizeof(FILE_NAME_ATTR) + (namelen * sizeof(ntfschar)));
		wipe = TRUE;
	}

	//ntfs_log_debug("need 0x%02X bytes\n", need);

	if (need != 0) {
		if (ie->flags & INDEX_ENTRY_NODE)
			vcn = ntfs_ie_get_vcn(ie);

		ie->length += need;
		ie->key_length += need;

		//ntfs_log_debug("realloc 0x%02X\n", ie->length);
		ie = realloc(ie, ie->length);
		if (!ie)
			return NULL;

		if (ie->flags & INDEX_ENTRY_NODE)
			ie = ntfs_ie_set_vcn(ie, vcn);

		if (wipe)
			memset(&ie->key.file_name, 0, sizeof(FILE_NAME_ATTR));
		if (need > 0)
			memset((u8*)ie + ie->length - need, 0, need);
	}

	memcpy(ie->key.file_name.file_name, name, namelen * sizeof(ntfschar));

	ie->key.file_name.file_name_length = namelen;
	ie->key.file_name.file_name_type = nametype;
	ie->flags &= ~INDEX_ENTRY_END;

	//ntfs_log_debug("ie->length     = 0x%02X\n", ie->length);
	//ntfs_log_debug("ie->key_length = 0x%02X\n", ie->key_length);

	return ie;
}

/**
 * ntfs_ie_remove_name
 */
INDEX_ENTRY * ntfs_ie_remove_name(INDEX_ENTRY *ie)
{
	VCN vcn = 0;

	if (!ie)
		return NULL;
	if (ie->key_length == 0)
		return ie;

	if (ie->flags & INDEX_ENTRY_NODE)
		vcn = ntfs_ie_get_vcn(ie);

	ie->length -= ATTR_SIZE(ie->key_length);
	ie->key_length = 0;
	ie->flags |= INDEX_ENTRY_END;

	ie = realloc(ie, ie->length);
	if (!ie)
		return NULL;

	if (ie->flags & INDEX_ENTRY_NODE)
		ie = ntfs_ie_set_vcn(ie, vcn);
	return ie;
}


#endif /* NTFS_RICH */

