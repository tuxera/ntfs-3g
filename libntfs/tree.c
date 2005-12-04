/**
 * tree.c - Directory tree handling code.  Part of the Linux-NTFS project.
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
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "volume.h"
#include "dir.h"
#include "tree.h"
#include "bitmap.h"
#include "index.h"
#include "inode.h"
#include "logging.h"
#include "rich.h"

/**
 * ntfs_dt_free - Destroy a directory-tree object
 * @dt:
 *
 * Description...
 *
 * Returns:
 */
void ntfs_dt_free(struct ntfs_dt *dt)
{
	int i;

	if (!dt)
		return;

	ntfs_log_trace ("dt %p, children %d, dir %lld\n", dt, dt->child_count, MREF(dt->dir->mft_num));

	for (i = 0; i < dt->child_count; i++) {
		ntfs_dt_free(dt->sub_nodes[i]);
		ntfs_inode_close2(dt->inodes[i]);
	}

	free(dt->sub_nodes);
	free(dt->children);
	free(dt->inodes);
	free(dt->data);	// XXX is this always ours?
	free(dt);
}

/**
 * ntfs_dt_rollback - Discard the in-memory directory-tree changes
 * @dt:
 *
 * Description...
 *
 * Returns:
 */
int ntfs_dt_rollback(struct ntfs_dt *dt)
{
	int i;

	if (!dt)
		return 0;
	if (dt->child_count == 0)	// No children or nothing mapped
		return 0;

	ntfs_log_trace ("dt %p, children %d, dir %lld\n", dt, dt->child_count, MREF(dt->dir->mft_num));

	if (dt->changed) {
		// We can't trust anything below us in the tree
		for (i = 0; i < dt->child_count; i++) {
			ntfs_dt_free(dt->sub_nodes[i]);
			ntfs_inode_close2(dt->inodes[i]);
		}

		dt->child_count = 0;

		free(dt->data);
		free(dt->children);
		free(dt->sub_nodes);
		free(dt->inodes);

		dt->data = NULL;
		dt->children = NULL;
		dt->sub_nodes = NULL;
		dt->inodes = NULL;
	} else {
		// This node is OK, check the su-nodes
		for (i = 0; i < dt->child_count; i++) {
			if (ntfs_dt_rollback(dt->sub_nodes[i])) {
				ntfs_inode_close2(dt->inodes[i]);
				// Child was changed so unmap it
				dt->sub_nodes[i] = NULL;
				dt->inodes[i] = NULL;
			}
		}
	}

	return (dt->child_count == 0);
}

/**
 * ntfs_dt_commit - Write to disk the in-memory directory-tree changes
 * @dt:
 *
 * Description...
 *
 * Returns:
 */
int ntfs_dt_commit(struct ntfs_dt *dt)
{
	ntfs_volume *vol;
	ntfs_attr *attr;
	struct ntfs_dir *dir;
	int i;
	int size;

	if (!dt)
		return 0;

	ntfs_log_trace ("dt %p, children %d, dir %lld\n", dt, dt->child_count, MREF(dt->dir->mft_num));

	dir = dt->dir;
	if (!dir)
		return -1;

	vol = dir->vol; // cluster size

	if (dt->changed) {
		if (dt->parent) {
			ntfs_log_debug("commit dt (alloc)\n");
			attr = dt->dir->ialloc;
			size = dt->dir->index_size;
			//utils_dump_mem(dt->data, 0, size, DM_DEFAULTS);
			ntfs_attr_mst_pwrite(attr, dt->vcn * vol->cluster_size, 1, size, dt->data); // XXX retval
		} else {
			ntfs_log_debug("commit dt (root)\n");
			attr = dt->dir->iroot;
			size = dt->data_len;
			//utils_dump_mem(dt->data, 0, size, DM_DEFAULTS);
			ntfs_attr_pwrite(attr, 0, size, dt->data); // XXX retval
		}

		ntfs_log_warning("\tntfs_attr_pwrite(vcn %lld)\n", dt->vcn);

		dt->changed = FALSE;
	} else {
		//ntfs_log_debug("\tdt is clean\n");
	}

	for (i = 0; i < dt->child_count; i++) {
		if ((dt->inodes[i]) && (NInoDirty(dt->inodes[i]))) {
			//utils_dump_mem(dt->inodes[i]->mrec, 0, vol->mft_record_size, DM_DEFAULTS);
			ntfs_inode_sync(dt->inodes[i]);
			ntfs_log_warning("\tntfs_inode_sync %llu\n", dt->inodes[i]->mft_no);
		}

		if (ntfs_dt_commit(dt->sub_nodes[i]) < 0)
			return -1;
	}

	return 0;
}

/**
 * ntfs_dt_create_children2 - Allocate space for the directory-tree's children
 * @dt:
 * @count:
 *
 * Description...
 *
 * Returns:
 */
BOOL ntfs_dt_create_children2(struct ntfs_dt *dt, int count)
{
	// XXX calculate for 2K and 4K indexes max and min filenames (inc/exc VCN)

	int old = (dt->child_count + 0x1e) & ~0x1f;
	int new = (count           + 0x1f) & ~0x1f;

	if (old == new)
		return TRUE;

	ntfs_log_trace ("\n");
	dt->children  = realloc(dt->children,  new * sizeof(*dt->children));
	dt->sub_nodes = realloc(dt->sub_nodes, new * sizeof(*dt->sub_nodes));
	dt->inodes    = realloc(dt->inodes,    new * sizeof(*dt->inodes));

	if (!dt->children || !dt->sub_nodes || !dt->inodes)
		return FALSE;		// dt->child_count = -1 ?

	memset((u8*)dt->children  + old, 0, (new - old) * sizeof(*dt->children));
	memset((u8*)dt->sub_nodes + old, 0, (new - old) * sizeof(*dt->sub_nodes));
	memset((u8*)dt->inodes    + old, 0, (new - old) * sizeof(*dt->inodes));

	return TRUE;
}

/**
 * ntfs_dt_resize_children3 - Resize a directory-tree's children arrays
 * @dt:
 * @new:
 *
 * Description...
 *
 * Returns:
 */
BOOL ntfs_dt_resize_children3(struct ntfs_dt *dt, int new)
{
	int old;

	// XXX calculate for 2K and 4K indexes max and min filenames (inc/exc VCN)
	// XXX assumption:  sizeof(*dt->children) == sizeof(*dt->sub_nodes) == sizeof(*dt->inodes)
	// XXX put back blocking factor

	if (!dt)
		return FALSE;

	old = dt->child_count;
	if (old == new)
		return TRUE;

	ntfs_log_trace ("dt %p, mft %lld, old %d, new %d\n", dt, MREF(dt->dir->mft_num), old, new);
	dt->child_count = new;

	old *= sizeof(*dt->children);
	new *= sizeof(*dt->children);

	dt->children  = realloc(dt->children,  new);
	dt->sub_nodes = realloc(dt->sub_nodes, new);
	dt->inodes    = realloc(dt->inodes,    new);

	if (!dt->children || !dt->sub_nodes || !dt->inodes)
		return FALSE;

	if (new > old) {
		memset((u8*)dt->children  + old, 0, (new - old));
		memset((u8*)dt->sub_nodes + old, 0, (new - old));
		memset((u8*)dt->inodes    + old, 0, (new - old));
	}

	return TRUE;
}

/**
 * ntfs_dt_root_count - Count the index entries in an index root
 * @dt:
 *
 * Description...
 *
 * Returns:
 */
int ntfs_dt_root_count(struct ntfs_dt *dt)
{
	u8 *buffer = NULL;
	u8 *ptr = NULL;
	VCN vcn;
	s64 size = 0;
	char *name = NULL;

	INDEX_ROOT *root;
	INDEX_HEADER *header;
	INDEX_ENTRY *entry;

	if (!dt)
		return -1;

	ntfs_log_trace ("\n");
	buffer = dt->data;
	size   = dt->data_len;

	//utils_dump_mem(buffer, 0, size, DM_DEFAULTS);

	root = (INDEX_ROOT*) buffer;
	if (root->type != AT_FILE_NAME)
		return -1;

	header = (INDEX_HEADER*) (buffer + 0x10);
	if (header->index_length > size)
		return -1;

	dt->child_count = 0;
	ptr = buffer + header->entries_offset + 0x10;

	while (ptr < (buffer + size)) {
		entry = (INDEX_ENTRY*) ptr;

		ntfs_dt_resize_children3(dt, dt->child_count + 1); // XXX retval

		if (entry->flags & INDEX_ENTRY_NODE) {
			vcn = ntfs_ie_get_vcn((INDEX_ENTRY*) ptr);
			//ntfs_log_debug("VCN %lld\n", vcn);
		}

		if (!(entry->flags & INDEX_ENTRY_END)) {
			ntfs_ucstombs(entry->key.file_name.file_name, entry->key.file_name.file_name_length, &name, 0);
			//ntfs_log_debug("\tinode %8lld %s\n", MREF(entry->indexed_file), name);
			free(name);
			name = NULL;
		}

		//ntfs_log_debug("CC[%d] = %p\n", dt->child_count-1, entry);
		dt->children[dt->child_count-1] = entry;

		ptr += entry->length;
	}

	//ntfs_log_debug("count = %d\n\n", dt->child_count);

	return dt->child_count;
}

/**
 * ntfs_dt_alloc_count - Count the index entries in an index allocation
 * @dt:
 *
 * Description...
 *
 * Returns:
 */
int ntfs_dt_alloc_count(struct ntfs_dt *dt)
{
	u8 *buffer = NULL;
	u8 *ptr = NULL;
	VCN vcn;
	s64 size = 0;
	char *name = NULL;

	INDEX_BLOCK *block;
	INDEX_ENTRY *entry;

	if (!dt)
		return -1;

	ntfs_log_trace ("\n");
	buffer = dt->data;
	size   = dt->data_len;

	//utils_dump_mem(buffer, 0, 128, DM_DEFAULTS);

	block = (INDEX_BLOCK*) buffer;
	//ntfs_log_debug("INDX %lld\n", block->index_block_vcn);

	ptr = buffer + 0x18 + block->index.entries_offset;

	//ntfs_log_debug("block size %d\n", block->index.index_length);
	dt->child_count = 0;
	//ntfs_log_debug("start = 0x%02X, end = 0x%02X\n", 0x18 + block->index.entries_offset, 0x18 + block->index.index_length);
	while (ptr < (buffer + 0x18 + block->index.index_length)) {
		entry = (INDEX_ENTRY*) ptr;

		ntfs_dt_resize_children3(dt, dt->child_count + 1); // XXX retval

		if (entry->flags & INDEX_ENTRY_NODE) {
			vcn = ntfs_ie_get_vcn((INDEX_ENTRY*) ptr);
			//ntfs_log_debug("\tVCN %lld\n", vcn);
		}

		dt->children[dt->child_count-1] = entry;

		if (entry->flags & INDEX_ENTRY_END) {
			break;
		} else {
			ntfs_ucstombs(entry->key.file_name.file_name, entry->key.file_name.file_name_length, &name, 0);
			//ntfs_log_debug("\tinode %8lld %s\n", MREF(entry->indexed_file), name);
			free(name);
			name = NULL;
		}

		ptr += entry->length;
	}
	//ntfs_log_debug("count = %d\n", dt->child_count);

	return dt->child_count;
}

/**
 * ntfs_dt_initialise2 - Setup a directory-tree object
 * @vol:
 * @dt:
 *
 * Description...
 *
 * Returns:
 */
int ntfs_dt_initialise2(ntfs_volume *vol, struct ntfs_dt *dt)
{
	INDEX_ALLOCATION *alloc;
	INDEX_ENTRY *entry;

	if (!vol)
		return 1;
	if (!dt)
		return 1;

	ntfs_log_trace ("\n");
	memset(dt->data, 0, dt->data_len);

	alloc = (INDEX_ALLOCATION*) dt->data;

	alloc->magic           = magic_INDX;
	alloc->usa_ofs         = 0x28;
	alloc->usa_count       = (dt->data_len >> vol->sector_size_bits) + 1;
	alloc->lsn             = 0;
	alloc->index_block_vcn = 0;

	alloc->index.entries_offset   = 0x28;
	alloc->index.index_length     = 0x10 + 0x28;
	alloc->index.allocated_size   = dt->data_len - 0x18;
	alloc->index.flags            = 0;

	entry = (INDEX_ENTRY*) (dt->data + 0x40);

	entry->indexed_file = 0;
	entry->length       = 0x10;
	entry->key_length   = 0;
	entry->flags        = INDEX_ENTRY_END;

	ntfs_dt_resize_children3(dt, 1);		// XXX retval

	dt->children[0] = entry;

	return 0;
}

/**
 * ntfs_dt_create - Create a representation of a directory index
 * @dir:
 * @parent:
 * @vcn:
 *
 * Description...
 *
 * Returns:
 */
struct ntfs_dt * ntfs_dt_create(struct ntfs_dir *dir, struct ntfs_dt *parent, VCN vcn)
{
	struct ntfs_dt *dt = NULL;
	//int i;

	if (!dir)
		return NULL;

	dt = calloc(1, sizeof(*dt));
	if (!dt)
		return NULL;

	ntfs_log_trace ("\n");
	dt->dir		= dir;
	dt->parent	= parent;
	dt->child_count	= 0;
	dt->children	= NULL;
	dt->sub_nodes	= NULL;
	dt->inodes	= NULL;
	dt->vcn		= vcn;
	dt->changed	= FALSE;

	if (parent) {
		//ntfs_log_debug("alloc a = %lld\n", dir->ialloc->allocated_size);
		//ntfs_log_debug("alloc d = %lld\n", dir->ialloc->data_size);
		//ntfs_log_debug("alloc i = %lld\n", dir->ialloc->initialized_size);
		//ntfs_log_debug("vcn = %lld\n", vcn);

		dt->data_len = dt->dir->index_size;
		//ntfs_log_debug("parent size = %d\n", dt->data_len);
		dt->data     = malloc(dt->data_len);

		if (vcn >= 0) {
			//ntfs_log_debug("%lld\n", ntfs_attr_mst_pread(dir->ialloc, vcn*512, 1, dt->data_len, dt->data));
			ntfs_attr_mst_pread(dir->ialloc, vcn*512, 1, dt->data_len, dt->data);
		} else {
			ntfs_dt_initialise2(dir->vol, dt);
		}

		//utils_dump_mem(dt->data, 0, dt->data_len, DM_DEFAULTS);
		//ntfs_log_debug("\n");

		ntfs_dt_alloc_count(dt);

		dt->header = &((INDEX_BLOCK*)dt->data)->index;
		//ntfs_log_debug("USA = %d\n", ((INDEX_BLOCK*)dt->data)->usa_count);

#if 0
		for (i = 0; i < dt->child_count; i++) {
			INDEX_ENTRY *ie = dt->children[i];

			ntfs_log_debug("%d\n", ((u8*)ie) - dt->data);
			if (ie->flags & INDEX_ENTRY_END)
				ntfs_log_debug("IE (%d)\n", ie->length);
			else
				ntfs_log_debug("IE %lld (%d)\n", MREF(ie->key.file_name.parent_directory), ie->length);
			utils_dump_mem(ie, 0, ie->length, DM_DEFAULTS);
			ntfs_log_debug("\n");
		}
#endif
	} else {
		//ntfs_log_debug("root a  = %lld\n", dir->iroot->allocated_size);
		//ntfs_log_debug("root d  = %lld\n", dir->iroot->data_size);
		//ntfs_log_debug("root i  = %lld\n", dir->iroot->initialized_size);

		dt->data_len = dir->iroot->allocated_size;
		dt->data     = malloc(dt->data_len);
		//ntfs_log_debug("%lld\n", ntfs_attr_pread(dir->iroot, 0, dt->data_len, dt->data));
		ntfs_attr_pread(dir->iroot, 0, dt->data_len, dt->data);
		//utils_dump_mem(dt->data, 0, dt->data_len, DM_DEFAULTS);
		//ntfs_log_debug("\n");

		ntfs_dt_root_count(dt);

		dt->header = &((INDEX_ROOT*)dt->data)->index;
		//dt->data_len = ((INDEX_ROOT*)dt->data)->index_block_size;
		//ntfs_log_debug("IBS = %d\n", ((INDEX_ROOT*)dt->data)->index_block_size);

#if 0
		for (i = 0; i < dt->child_count; i++) {
			INDEX_ENTRY *ie = dt->children[i];

			ntfs_log_debug("%d\n", ((u8*)ie) - dt->data);
			if (ie->flags & INDEX_ENTRY_END)
				ntfs_log_debug("IE (%d)\n", ie->length);
			else
				ntfs_log_debug("IE %lld (%d)\n", MREF(ie->key.file_name.parent_directory), ie->length);
			utils_dump_mem(ie, 0, ie->length, DM_DEFAULTS);
			ntfs_log_debug("\n");
		}
#endif
	}
	//ntfs_log_debug("index_header (%d,%d)\n", dt->header->index_length, dt->header->allocated_size);

	return dt;
}

/**
 * ntfs_dt_find - Find an index entry by name
 * @dt:
 * @name:
 * @name_len:
 *
 * find dt by name, return MFT_REF
 * maps dt's as necessary
 */
MFT_REF ntfs_dt_find(struct ntfs_dt *dt, ntfschar *name, int name_len)
{
	MFT_REF res = -1;
	INDEX_ENTRY *ie;
	struct ntfs_dt *sub;
	VCN vcn;
	int i;
	int r;

	if (!dt || !name)
		return -1;

	ntfs_log_trace ("\n");
	/*
	 * State            Children  Action
	 * -------------------------------------------
	 * collates after      -      keep searching
	 * match name          -      return MREF
	 * collates before     no     return -1
	 * collates before     yes    map & recurse
	 * end marker          no     return -1
	 * end marker          yes    map & recurse
	 */

	//ntfs_log_debug("child_count = %d\n", dt->child_count);
	for (i = 0; i < dt->child_count; i++) {
		ie = dt->children[i];

		if (ie->flags & INDEX_ENTRY_END) {
			r = -1;
		} else {
			//ntfs_log_debug("\t"); ntfs_name_print(ie->key.file_name.file_name, ie->key.file_name.file_name_length); ntfs_log_debug("\n");
			r = ntfs_names_collate(name, name_len,
						ie->key.file_name.file_name,
						ie->key.file_name.file_name_length,
						2, IGNORE_CASE,
						dt->dir->vol->upcase,
						dt->dir->vol->upcase_len);
		}

		//ntfs_log_debug("%d, %d\n", i, r);

		if (r == 1) {
			//ntfs_log_debug("keep searching\n");
			continue;
		} else if (r == 0) {
			res = MREF(ie->indexed_file);
			//ntfs_log_debug("match %lld\n", res);
		} else if (r == -1) {
			if (ie->flags & INDEX_ENTRY_NODE) {
				//ntfs_log_debug("map & recurse\n");
				//ntfs_log_debug("sub %p\n", dt->sub_nodes);
				if (!dt->sub_nodes[i]) {
					vcn = ntfs_ie_get_vcn(ie);
					//ntfs_log_debug("vcn = %lld\n", vcn);
					sub = ntfs_dt_create(dt->dir, dt, vcn);
					dt->sub_nodes[i] = sub;
				}
				res = ntfs_dt_find(dt->sub_nodes[i], name, name_len);
			} else {
				//ntfs_log_debug("ENOENT\n");
			}
		} else {
			ntfs_log_debug("error collating name\n");
		}
		break;
	}

	return res;
}

/**
 * ntfs_dt_find2 - Find an index entry by name
 * @dt:
 * @name:
 * @name_len:
 * @index_num:
 *
 * find dt by name, returns dt and index
 * maps dt's as necessary
 */
struct ntfs_dt * ntfs_dt_find2(struct ntfs_dt *dt, ntfschar *name, int name_len, int *index_num)
{
	struct ntfs_dt *res = NULL;
	INDEX_ENTRY *ie;
	VCN vcn;
	int i;
	int r;

	if (!dt || !name)
		return NULL;
	ntfs_log_trace ("dt %p, mft %llu, name %p%d\n", dt, MREF(dt->dir->mft_num), name, name_len);

	//ntfs_log_debug("searching for: "); ntfs_name_print(name, name_len); ntfs_log_debug("\n");

	//utils_dump_mem(dt->data, 0, 256, DM_DEFAULTS);

	// XXX default index_num to -1

	/*
	 * State            Children  Action
	 * -------------------------------------------
	 * collates after      -      keep searching
	 * match name          -      return MREF
	 * collates before     no     return -1
	 * collates before     yes    map & recurse
	 * end marker          no     return -1
	 * end marker          yes    map & recurse
	 */

	//ntfs_log_debug("child_count = %d\n", dt->child_count);
	for (i = 0; i < dt->child_count; i++) {
		ie = dt->children[i];

		if (ie->flags & INDEX_ENTRY_END) {
			r = -1;
		} else {
			//ntfs_log_debug("\t"); ntfs_name_print(ie->key.file_name.file_name, ie->key.file_name.file_name_length); ntfs_log_debug("\n");
			//utils_dump_mem(name, 0, name_len * 2, DM_DEFAULTS);
			//utils_dump_mem(ie->key.file_name.file_name, 0, ie->key.file_name.file_name_length * 2, DM_DEFAULTS);
			r = ntfs_names_collate(name, name_len,
						ie->key.file_name.file_name,
						ie->key.file_name.file_name_length,
						2, IGNORE_CASE,
						dt->dir->vol->upcase,
						dt->dir->vol->upcase_len);
		}

		//ntfs_log_debug("%d, %d\n", i, r);

		if (r == 1) {
			//ntfs_log_debug("keep searching\n");
			continue;
		} else if (r == 0) {
			res = dt;
			//ntfs_log_debug("match %p\n", res);
			if (index_num)
				*index_num = i;
		} else if ((r == -1) && (ie->flags & INDEX_ENTRY_NODE)) {
			//ntfs_log_debug("recurse\n");
			if (!dt->sub_nodes[i]) {
				vcn = ntfs_ie_get_vcn(ie);
				//ntfs_log_debug("vcn = %lld\n", vcn);
				dt->sub_nodes[i] = ntfs_dt_create(dt->dir, dt, vcn);
			}
			res = ntfs_dt_find2(dt->sub_nodes[i], name, name_len, index_num);
		} else {
			//ntfs_log_debug("error collating name\n");
		}
		break;
	}

	return res;
}

/**
 * ntfs_dt_find3 - Find an index entry by name
 * @dt:
 * @name:
 * @name_len:
 * @index_num:
 *
 * find dt by name, returns dt and index
 * does not map new dt's
 */
struct ntfs_dt * ntfs_dt_find3(struct ntfs_dt *dt, ntfschar *name, int name_len, int *index_num)
{
	struct ntfs_dt *res = NULL;
	INDEX_ENTRY *ie;
	int i;
	int r;

	if (!dt || !name)
		return NULL;
	ntfs_log_trace ("\n");

	//ntfs_log_debug("child_count = %d\n", dt->child_count);
	for (i = 0; i < dt->child_count; i++) {
		ie = dt->children[i];

		if (ie->flags & INDEX_ENTRY_END) {
			r = -1;
		} else {
			//ntfs_log_debug("\t"); ntfs_name_print(ie->key.file_name.file_name, ie->key.file_name.file_name_length); ntfs_log_debug("\n");
			r = ntfs_names_collate(name, name_len,
						ie->key.file_name.file_name,
						ie->key.file_name.file_name_length,
						2, IGNORE_CASE,
						dt->dir->vol->upcase,
						dt->dir->vol->upcase_len);
		}

		//ntfs_log_debug("%d, %d\n", i, r);

		if (r == 1) {
			//ntfs_log_debug("keep searching\n");
			continue;
		} else if (r == 0) {
			res = dt;
			//ntfs_log_debug("match %p\n", res);
			if (index_num)
				*index_num = i;
		} else if (r == -1) {
			if (ie->flags & INDEX_ENTRY_NODE) {
				//ntfs_log_debug("recurse\n");
				res = ntfs_dt_find3(dt->sub_nodes[i], name, name_len, index_num);
			} else {
				//ntfs_log_debug("no match\n");
				res = dt;
				if (index_num)
					*index_num = i;
			}
		} else {
			ntfs_log_debug("error collating name\n");
		}
		break;
	}

	return res;
}

/**
 * ntfs_dt_find4 - Find an index entry by name
 * @dt:
 * @name:
 * @name_len:
 * @index_num:
 *
 * find successor to specified name, returns dt and index
 * maps dt's as necessary
 */
struct ntfs_dt * ntfs_dt_find4(struct ntfs_dt *dt, ntfschar *name, int name_len, int *index_num)
{
	struct ntfs_dt *res = NULL;
	struct ntfs_dt *sub = NULL;
	INDEX_ENTRY *ie;
	VCN vcn;
	int i;
	int r;

	if (!dt || !name)
		return NULL;
	ntfs_log_trace ("\n");

	//ntfs_log_debug("child_count = %d\n", dt->child_count);
	for (i = 0; i < dt->child_count; i++) {
		ie = dt->children[i];

		//ntfs_log_debug("ie->flags = %d\n", ie->flags);
		if (ie->flags & INDEX_ENTRY_END) {
			r = -1;
		} else {
			//ntfs_log_debug("\t"); ntfs_name_print(ie->key.file_name.file_name, ie->key.file_name.file_name_length); ntfs_log_debug("\n");
			r = ntfs_names_collate(name, name_len,
						ie->key.file_name.file_name,
						ie->key.file_name.file_name_length,
						2, IGNORE_CASE,
						dt->dir->vol->upcase,
						dt->dir->vol->upcase_len);
		}

		//ntfs_log_debug("%d, %d\n", i, r);

		if (r == 1) {
			//ntfs_log_debug("keep searching\n");
		} else if (r == 0) {
			//res = dt;
			//ntfs_log_debug("match\n");
			// ignore
		} else if (r == -1) {
			if (ie->flags & INDEX_ENTRY_NODE) {
				//ntfs_log_debug("recurse\n");
				if (!dt->sub_nodes[i]) {
					vcn = ntfs_ie_get_vcn(ie);
					//ntfs_log_debug("vcn = %lld\n", vcn);
					sub = ntfs_dt_create(dt->dir, dt, vcn);
					dt->sub_nodes[i] = sub;
				}
				res = ntfs_dt_find4(dt->sub_nodes[i], name, name_len, index_num);
			} else {
				//ntfs_log_debug("no match\n");
				res = dt;
				if (index_num)
					*index_num = i;
			}
			break;
		} else {
			ntfs_log_debug("error collating name\n");
		}
		//break;
	}

	return res;
}

/**
 * ntfs_dt_find_all - Recurse the directory-tree, mapping all elements
 * @dt:
 *
 * maps all dt's into memory
 */
void ntfs_dt_find_all(struct ntfs_dt *dt)
{
	INDEX_ENTRY *ie;
	VCN vcn;
	int i;

	if (!dt)
		return;
	ntfs_log_trace ("\n");

	for (i = 0; i < dt->child_count; i++) {
		ie = dt->children[i];

		if (ie->flags & INDEX_ENTRY_NODE) {
			if (!dt->sub_nodes[i]) {
				vcn = ntfs_ie_get_vcn(ie);
				dt->sub_nodes[i] = ntfs_dt_create(dt->dir, dt, vcn);
			}
			ntfs_dt_find_all(dt->sub_nodes[i]);
		}
	}
}

/**
 * ntfs_dt_find_parent - Find the index of ourself in the parent's array
 * @dt:
 *
 * Description...
 *
 * Returns:
 */
int ntfs_dt_find_parent(struct ntfs_dt *dt)
{
	int i;
	struct ntfs_dt *parent;

	if (!dt)
		return -1;
	ntfs_log_trace ("\n");

	parent = dt->parent;
	if (!parent)
		return -1;

	for (i = 0; i < parent->child_count; i++)
		if (parent->sub_nodes[i] == dt)
			return i;

	return -1;
}

/**
 * ntfs_dt_isroot - Does this directory-tree represent an index root
 * @dt:
 *
 * Description...
 *
 * Returns:
 */
BOOL ntfs_dt_isroot(struct ntfs_dt *dt)
{
	if (!dt)
		return FALSE;
	ntfs_log_trace ("\n");
	return (dt->parent == NULL);
}

/**
 * ntfs_dt_root_freespace - Give the free space (bytes) in an index root
 * @dt:
 *
 * Description...
 *
 * Returns:
 */
int ntfs_dt_root_freespace(struct ntfs_dt *dt)
{
	int recsize;
	int inuse;
	MFT_RECORD *mrec;

	if (!dt)
		return -1;
	ntfs_log_trace ("\n");

	recsize = dt->dir->inode->vol->mft_record_size;

	mrec = (MFT_RECORD*) dt->dir->inode->mrec;
	inuse = mrec->bytes_in_use;

	return recsize - inuse;
}

/**
 * ntfs_dt_alloc_freespace - Give the free space (bytes) in an index allocation
 * @dt:
 *
 * Description...
 *
 * Returns:
 */
int ntfs_dt_alloc_freespace(struct ntfs_dt *dt)
{
	int recsize;
	int inuse;
	INDEX_BLOCK *block;

	if (!dt)
		return -1;
	ntfs_log_trace ("\n");

	recsize = dt->dir->index_size;

	block = (INDEX_BLOCK*) dt->data;
	inuse = block->index.index_length + 24;

	return recsize - inuse;
}

/**
 * ntfs_dt_transfer - Transfer several index entries between directory-trees
 * @old:
 * @new:
 * @start:
 * @count:
 *
 * Description...
 *
 * Returns:
 */
int ntfs_dt_transfer(struct ntfs_dt *old, struct ntfs_dt *new, int start, int count)
{
	int i;
	int need;
	int space;
	INDEX_ENTRY *mov_ie;
	u8 *src;
	u8 *dst;
	int len;
	int insert;
	//FILE_NAME_ATTR *file;
	ntfs_log_trace ("\n");

	//XXX check len > 0

	if (!old || !new)
		return -1;

	if ((start < 0) || ((start+count) >= old->child_count))
		return -1;

	//ntfs_log_debug("\n");
	ntfs_log_debug("Transferring children\n");

	need = 0;
	for (i = start; i < (start+count+1); i++) {
		mov_ie = old->children[i];
		need += mov_ie->length;
		//file = &mov_ie->key.file_name; ntfs_log_debug("\ttrn name: "); ntfs_name_print(file->file_name, file->file_name_length); ntfs_log_debug("\n");
	}

	if (ntfs_dt_isroot(new))
		space = ntfs_dt_root_freespace(new);
	else
		space = ntfs_dt_alloc_freespace(new);

	// XXX if this is an index root, it'll go badly wrong
	// restrict to allocs only?

	ntfs_log_debug("\tneed  = %d\n", need);
	ntfs_log_debug("\tspace = %d\n", space);

	if (space < need)
		return -1;

	if (new->child_count == 1) {
		i = -1;
	} else {
		ntfschar *n1, *n2;
		int l1, l2;

		n1 = new->children[0]->key.file_name.file_name;
		l1 = new->children[0]->key.file_name.file_name_length;

		n2 = old->children[start]->key.file_name.file_name;
		l2 = old->children[start]->key.file_name.file_name_length;

		i = ntfs_names_collate(n1, l1, n2, l2,
					2, IGNORE_CASE,
					old->dir->vol->upcase,
					old->dir->vol->upcase_len);
	}

	if ((i == 0) || (i == 2))
		return -1;

	// determine the insertion point
	if (i == 1)
		insert = 0;
	else
		insert = new->child_count-1;

	src = (u8*) new->children[insert];
	dst = src + need;
	len = (u8*) new->children[new->child_count-1] + new->children[new->child_count-1]->length - src;

	//ntfs_log_debug("src = %d, dst = %d, len = %d\n", src - new->data, dst - new->data, len);
	memmove(dst, src, len);

	dst = src;
	src = (u8*) old->children[start];
	len = need;

	memcpy(dst, src, len);

	src = (u8*) old->children[start+count-1];
	dst = (u8*) old->children[start];
	len = (u8*) old->children[old->child_count-1] + old->children[old->child_count-1]->length - src;

	//ntfs_log_debug("src = %d, dst = %d, len = %d\n", src - old->data, dst - old->data, len);
	memmove(dst, src, len);

	dst += len;
	len = old->data + old->dir->index_size - dst;

	//ntfs_log_debug("dst = %d, len = %d\n", dst - old->data, len);
	memset(dst, 0, len);

	if (!ntfs_dt_resize_children3(new, new->child_count + count))
		return -1;

	src = (u8*) &old->sub_nodes[start+count-1];
	dst = (u8*) &old->sub_nodes[start];
	len = (old->child_count - start - count + 1) * sizeof(struct ntfs_dt*);

	memmove(dst, src, len);

	src = (u8*) &new->sub_nodes[insert];
	dst = (u8*) &new->sub_nodes[insert+count-1];
	len = (new->child_count - insert - count + 1) * sizeof(struct ntfs_dt*);

	memmove(dst, src, len);

	if (!ntfs_dt_resize_children3(old, old->child_count - count))
		return -1;

	src = (u8*) new->children[0];
	for (i = 0; i < new->child_count; i++) {
		new->children[i] = (INDEX_ENTRY*) src;
		src += new->children[i]->length;
	}

	src = (u8*) old->children[0];
	for (i = 0; i < old->child_count; i++) {
		old->children[i] = (INDEX_ENTRY*) src;
		src += old->children[i]->length;
	}

	old->header->index_length -= need;
	new->header->index_length += need;

	// resize children and sub_nodes
	// memmove keys in new
	// memcpy old to new
	// memmove keys in old
	// rebuild old/new children/sub_nodes without destroying tree
	// update old/new headers

	old->changed = TRUE;
	new->changed = TRUE;

	ntfs_log_debug("Modified: inode %lld, $INDEX_ALLOCATION vcn %lld-%lld\n", old->dir->inode->mft_no, old->vcn, old->vcn + (old->dir->index_size>>9) - 1);
	ntfs_log_debug("Modified: inode %lld, $INDEX_ALLOCATION vcn %lld-%lld\n", new->dir->inode->mft_no, new->vcn, new->vcn + (new->dir->index_size>>9) - 1);

	return 0;
}

/**
 * ntfs_dt_alloc_insert - Insert an index entry into an index allocation
 * @dt:
 * @first:
 * @count:
 *
 * Description...
 *
 * Returns:
 */
int ntfs_dt_alloc_insert(struct ntfs_dt *dt, INDEX_ENTRY *first, int count)
{
	// XXX don't bother measuring, just subtract the children pointers

	int i;
	int need;
	INDEX_ENTRY *ie;
	INDEX_ALLOCATION *alloc;
	u8 *src;
	u8 *dst;
	int len;

	if (!dt)
		return 1;
	if (!first)
		return 1;
	ntfs_log_trace ("\n");

	need = 0;
	ie = first;
	for (i = 0; i < count; i++) {
		need += ie->length;
		ie = (INDEX_ENTRY*) ((u8*)ie + ie->length);
	}

	ntfs_log_debug("alloc insert %d bytes\n", need);

	alloc = (INDEX_ALLOCATION*) dt->data;
	ntfs_log_debug("entries_offset = %d\n", alloc->index.entries_offset);
	ntfs_log_debug("index_length   = %d\n", alloc->index.index_length);
	ntfs_log_debug("allocated_size = %d\n", alloc->index.allocated_size);

	ntfs_log_debug("insert has %d children\n", dt->child_count);
	ntfs_log_debug("children = %p\n", dt->children);
	//utils_dump_mem(dt->data, 0, 128, DM_DEFAULTS);

	ie = dt->children[dt->child_count-1];

	ntfs_log_debug("last child = %p (%ld)\n", ie, (long)ie - (long)dt->data);
	ntfs_log_debug("size = %d\n", ie->length);

	src = (u8*) ie;
	dst = src + need;
	len = ie->length;

	memmove(dst, src, len);

	src = (u8*) first;
	dst = (u8*) ie;
	len = need;

	memcpy(dst, src, len);

	// use create children
	// measure need and update children list
	// adjust headers

	//utils_dump_mem(dt->data, 0, 256, DM_DEFAULTS);
	return 0;
}

/**
 * ntfs_dt_alloc_insert2 - Insert an index entry into an index allocation
 * @dt:
 * @before:
 * @count:
 * @bytes:
 *
 * Description...
 *
 * Returns:
 */
INDEX_ENTRY * ntfs_dt_alloc_insert2(struct ntfs_dt *dt, int before, int count, int bytes)
{
	int space;
	u8 *src;
	u8 *dst;
	int len;

	// XXX don't bother measuring, just subtract the children pointers

	if (!dt)
		return NULL;
	if (before < 0)
		return NULL;
	if (count < 1)
		return NULL;
	if (bytes < 1)
		return NULL;
	ntfs_log_trace ("\n");

	// check alloc has enough space
	space = ntfs_dt_alloc_freespace(dt);
	if (bytes > space)
		return NULL;

	// move data
	src = (u8*) dt->children[before];
	dst = src + bytes;
	len = dt->header->index_length - ((int)dt->children[before] - (int)dt->data) + 24;

	//ntfs_log_debug("%d, %d, %d\n", (int)src - (int)dt->data, (int)dst - (int)dt->data, len);

	memmove(dst, src, len);
	memset(dst, 0, bytes);

	// resize arrays
	ntfs_dt_resize_children3(dt, dt->child_count + count);

	// move keys (children)
	src = (u8*) (dt->children + before);
	dst = src + (count * sizeof(u8*));
	len = (dt->child_count - count - before) * sizeof(u8*);

	memmove(dst, src, len);
	memset(src, 0, count * sizeof(u8*));

	// move keys (inodes)
	src = (u8*) (dt->inodes + before);
	dst = src + (count * sizeof(u8*));
	len = (dt->child_count - count - before) * sizeof(u8*);

	memmove(dst, src, len);
	memset(src, 0, count * sizeof(u8*));

	// move keys (sub_nodes)
	src = (u8*) (dt->sub_nodes + before);
	dst = src + (count * sizeof(u8*));
	len = (dt->child_count - count - before) * sizeof(u8*);

	memmove(dst, src, len);
	memset(src, 0, count * sizeof(u8*));

	return NULL;
}

/**
 * ntfs_dt_root_insert - Insert an index entry into an index root
 * @dt:
 * @first:
 * @count:
 *
 * Description...
 *
 * Returns:
 */
int ntfs_dt_root_insert(struct ntfs_dt *dt, INDEX_ENTRY *first, int count)
{
	if (!dt)
		return 1;
	if (!first)
		return 1;
	ntfs_log_trace ("\n");

	return count;
}

/**
 * ntfs_dt_alloc_remove2 - Remove an index entry from an index allocation
 * @dt:
 * @start:
 * @count:
 *
 * Description...
 *
 * Returns:
 */
int ntfs_dt_alloc_remove2(struct ntfs_dt *dt, int start, int count)
{
	int i;
	int size;

	if (!dt)
		return 1;
	ntfs_log_trace ("\n");

	size = 0;
	for (i = start; i < (start+count); i++) {
		size += dt->children[i]->length;
	}

	return start + count;
}

/**
 * ntfs_dt_root_remove2 - Remove an index entry from an index root
 * @dt:
 * @start:
 * @count:
 *
 * Description...
 *
 * Returns:
 */
int ntfs_dt_root_remove2(struct ntfs_dt *dt, int start, int count)
{
	int i;
	int size;

	if (!dt)
		return -1;
	if ((start < 0) || (start >= dt->child_count))
		return -1;
	if ((count < 1) || ((start + count - 1) >= dt->child_count))
		return -1;
	ntfs_log_trace ("\n");

	ntfs_log_debug("s c/t %d %d/%d\n", start, count, dt->child_count);

	size = 0;
	for (i = start; i < (start + count); i++)
		size += dt->children[i]->length;
	ntfs_log_debug("size1 = %d\n", size);

	size = (int) dt->children[start+count] - (int) dt->children[start];
	ntfs_log_debug("size2 = %d\n", size);

	size = (int) dt->children[start+count-1] - (int) dt->children[start] + dt->children[start+count-1]->length;
	ntfs_log_debug("size3 = %d\n", size);

	// XXX what shall we do with the inodes?
	// transfer them to the dir (commit them for now)
	// are they _our_ responsibility?  probably not

	// rearrange arrays
	// shrink attribute

	ntfs_dt_resize_children3(dt, dt->child_count - count);

	ntfs_log_debug("ntfs_dt_root_remove2\n");
	return dt->child_count;
}

/**
 * ntfs_dt_transfer2 - Transfer several index entries between directory-trees
 * @old:
 * @new:
 * @start:
 * @count:
 *
 * Description...
 *
 * Returns:
 */
int ntfs_dt_transfer2(struct ntfs_dt *old, struct ntfs_dt *new, int start, int count)
{
	int i;
	int need;
	int space;
	INDEX_ENTRY *mov_ie;
	u8 *src;
	u8 *dst;
	int len;
	int insert;
	//FILE_NAME_ATTR *file;

	if (!old || !new)
		return -1;

	if ((start < 0) || (count < 0))
		return -1;

	if ((start + count) >= old->child_count)
		return -1;
	ntfs_log_trace ("\n");

	//ntfs_log_debug("\n");
	ntfs_log_debug("Transferring children\n");

	need = 0;
	for (i = start; i < (start+count); i++) {
		mov_ie = old->children[i];
		need += mov_ie->length;
		//file = &mov_ie->key.file_name; ntfs_log_debug("\ttrn name: "); ntfs_name_print(file->file_name, file->file_name_length); ntfs_log_debug("\n");
	}

	if (ntfs_dt_isroot(new))
		space = ntfs_dt_root_freespace(new);
	else
		space = ntfs_dt_alloc_freespace(new);

	ntfs_log_debug("\tneed  = %d\n", need);
	ntfs_log_debug("\tspace = %d\n", space);

	if (need > space)
		return -1;

	if (ntfs_dt_isroot(new))
		ntfs_dt_root_insert(new, old->children[0], count);
	else
		ntfs_dt_alloc_insert2(new, 0, count, need);

	if (ntfs_dt_isroot(old))
		ntfs_dt_root_remove2(old, 0, count);
	else
		ntfs_dt_alloc_remove2(old, 0, count);

	if (1) return -1;
	if (0) ntfs_dt_alloc_insert(NULL, NULL, 0);

	if (new->child_count == 1) {
		i = -1;
	} else {
		ntfschar *n1, *n2;
		int l1, l2;

		n1 = new->children[0]->key.file_name.file_name;
		l1 = new->children[0]->key.file_name.file_name_length;

		n2 = old->children[start]->key.file_name.file_name;
		l2 = old->children[start]->key.file_name.file_name_length;

		i = ntfs_names_collate(n1, l1, n2, l2,
					2, IGNORE_CASE,
					old->dir->vol->upcase,
					old->dir->vol->upcase_len);
	}

	if ((i == 0) || (i == 2))
		return -1;

	// determine the insertion point
	if (i == 1)
		insert = 0;
	else
		insert = new->child_count-1;

	src = (u8*) new->children[insert];
	dst = src + need;
	len = (u8*) new->children[new->child_count-1] + new->children[new->child_count-1]->length - src;

	//ntfs_log_debug("src = %d, dst = %d, len = %d\n", src - new->data, dst - new->data, len);
	memmove(dst, src, len);

	dst = src;
	src = (u8*) old->children[start];
	len = need;

	memcpy(dst, src, len);

	src = (u8*) old->children[start+count-1];
	dst = (u8*) old->children[start];
	len = (u8*) old->children[old->child_count-1] + old->children[old->child_count-1]->length - src;

	//ntfs_log_debug("src = %d, dst = %d, len = %d\n", src - old->data, dst - old->data, len);
	memmove(dst, src, len);

	dst += len;
	len = old->data + old->dir->index_size - dst;

	//ntfs_log_debug("dst = %d, len = %d\n", dst - old->data, len);
	memset(dst, 0, len);

	if (!ntfs_dt_resize_children3(new, new->child_count + count))
		return -1;

	src = (u8*) &old->sub_nodes[start+count-1];
	dst = (u8*) &old->sub_nodes[start];
	len = (old->child_count - start - count + 1) * sizeof(struct ntfs_dt*);

	memmove(dst, src, len);

	src = (u8*) &new->sub_nodes[insert];
	dst = (u8*) &new->sub_nodes[insert+count-1];
	len = (new->child_count - insert - count + 1) * sizeof(struct ntfs_dt*);

	memmove(dst, src, len);

	if (!ntfs_dt_resize_children3(old, old->child_count - count))
		return -1;

	src = (u8*) new->children[0];
	for (i = 0; i < new->child_count; i++) {
		new->children[i] = (INDEX_ENTRY*) src;
		src += new->children[i]->length;
	}

	src = (u8*) old->children[0];
	for (i = 0; i < old->child_count; i++) {
		old->children[i] = (INDEX_ENTRY*) src;
		src += old->children[i]->length;
	}

	old->header->index_length -= need;
	new->header->index_length += need;

	// resize children and sub_nodes
	// memmove keys in new
	// memcpy old to new
	// memmove keys in old
	// rebuild old/new children/sub_nodes without destroying tree
	// update old/new headers

	old->changed = TRUE;
	new->changed = TRUE;

	ntfs_log_debug("Modified: inode %lld, $INDEX_ALLOCATION vcn %lld-%lld\n", old->dir->inode->mft_no, old->vcn, old->vcn + (old->dir->index_size>>9) - 1);
	ntfs_log_debug("Modified: inode %lld, $INDEX_ALLOCATION vcn %lld-%lld\n", new->dir->inode->mft_no, new->vcn, new->vcn + (new->dir->index_size>>9) - 1);

	return 0;
}

/**
 * ntfs_dt_root_replace - Replace an index entry in an index root
 * @del:
 * @del_num:
 * @del_ie:
 * @suc_ie:
 *
 * Description...
 *
 * Returns:
 */
int ntfs_dt_root_replace(struct ntfs_dt *del, int del_num, INDEX_ENTRY *del_ie, INDEX_ENTRY *suc_ie)
{
	u8 *src;
	u8 *dst;
	u8 *attr;
	int len;
	int i;

	if (!del || !del_ie || !suc_ie)
		return FALSE;
	ntfs_log_trace ("\n");

	//utils_dump_mem(del->data, 0, del->data_len, DM_DEFAULTS);
	//ntfs_log_debug("\n");

	attr = malloc(del->data_len + suc_ie->length - del_ie->length);

	dst = attr;
	src = del->data;
	len = (u8*) del_ie - del->data;

	memcpy(dst, src, len);

	dst += len;
	src = (u8*) suc_ie;
	len = suc_ie->length;

	memcpy(dst, src, len);

	dst += len;
	src = (u8*) del_ie + del_ie->length;
	len = del->data_len + (del->data - (u8*) del_ie) - del_ie->length;

	memcpy(dst, src, len);

	src = (u8*) del->data;
	dst = attr;

	len = suc_ie->length - del_ie->length;
	free(del->data);
	del->data = attr;
	del->data_len += len;
	del->header = (INDEX_HEADER*) (del->data + 0x10);
	del->header->index_length   += len;
	del->header->allocated_size += len;

	ntfs_mft_resize_resident(del->dir->inode, AT_INDEX_ROOT, NTFS_INDEX_I30, 4, del->data, del->data_len);

	//utils_dump_mem(attr, 0, del->data_len, DM_DEFAULTS);

	//ntfs_log_debug("\n");
	//ntfs_log_debug("Adjust children\n");
	//for (i = 0; i < del->child_count; i++)
	//	ntfs_log_debug("\tChild %d %p %d\n", i, del->children[i], del->children[i]->flags);
	//ntfs_log_debug("\n");

	//ntfs_log_debug("src = %p, dst = %p, len = %d\n", src, dst, len); fflush (stdout);

	for (i = 0; i < del->child_count; i++)
		del->children[i] = (INDEX_ENTRY*) (dst + ((u8*) del->children[i] - src));

	for (i = del_num+1; i < del->child_count; i++)
		del->children[i] = (INDEX_ENTRY*) ((u8*) del->children[i] + len);

	//for (i = 0; i < del->child_count; i++)
	//	ntfs_log_debug("\tChild %d %p %d\n", i, del->children[i], del->children[i]->flags);
	//ntfs_log_debug("\n");

	//utils_dump_mem(del->data, 0, del->data_len, DM_DEFAULTS);
	//ntfs_log_debug("\n");

	del->changed = TRUE;

	ntfs_log_debug("Modified: inode %lld, $INDEX_ROOT\n", del->dir->inode->mft_no);
	return TRUE;
}

/**
 * ntfs_dt_alloc_replace - Replace an index entry in an index allocation
 * @del:
 * @del_num:
 * @del_ie:
 * @suc_ie:
 *
 * Description...
 *
 * Returns:
 */
BOOL ntfs_dt_alloc_replace(struct ntfs_dt *del, int del_num, INDEX_ENTRY *del_ie, INDEX_ENTRY *suc_ie)
{
	u8 *src;
	u8 *dst;
	int len;
	int i;

	if (!del || !del_ie || !suc_ie)
		return FALSE;
	ntfs_log_trace ("\n");

	//utils_dump_mem(del->data, 0, del->data_len, DM_DEFAULTS);

	src = (u8*) del_ie + del_ie->length;
	dst = (u8*) del_ie + suc_ie->length;
	len = del->header->index_length + 24 + (del->data - src);
	//ntfs_log_debug("src = %d\n", src - del->data);
	//ntfs_log_debug("dst = %d\n", dst - del->data);
	//ntfs_log_debug("len = %d\n", len);

	if (src != dst)
		memmove(dst, src, len);

	src = (u8*) suc_ie;
	dst = (u8*) del_ie;
	len = suc_ie->length;

	memcpy(dst, src, len);

	//utils_dump_mem(del->data, 0, del->data_len, DM_DEFAULTS);

	del->header->index_length += suc_ie->length - del_ie->length;

	dst = del->data + del->header->index_length + 24;
	len = del->data_len - del->header->index_length - 24;

	memset(dst, 0, len);

	//for (i = 0; i < del->child_count; i++)
	//	ntfs_log_debug("Child %d %p\n", i, del->children[i]);
	//ntfs_log_debug("\n");

	len = suc_ie->length - del_ie->length;
	//ntfs_log_debug("len = %d\n", len);

	for (i = del_num+1; i < del->child_count; i++)
		del->children[i] = (INDEX_ENTRY*) ((u8*) del->children[i] + len);

	//for (i = 0; i < del->child_count; i++)
	//	ntfs_log_debug("Child %d %p\n", i, del->children[i]);
	//ntfs_log_debug("\n");

	//utils_dump_mem(del->data, 0, del->data_len, DM_DEFAULTS);

	del->changed = TRUE;

	ntfs_log_debug("Modified: inode %lld, $INDEX_ALLOCATION vcn %lld-%lld\n", del->dir->inode->mft_no, del->vcn, del->vcn + (del->dir->index_size>>9) - 1);
	return TRUE;
}

/**
 * ntfs_dt_root_remove - Remove an index entry from an index root
 * @del:
 * @del_num:
 *
 * Description...
 *
 * Returns:
 */
BOOL ntfs_dt_root_remove(struct ntfs_dt *del, int del_num)
{
	INDEX_ENTRY *del_ie = NULL;
	u8 *src;
	u8 *dst;
	u8 *old;
	int len;
	int del_len;
	int i;
	//int off;

	if (!del)
		return FALSE;
	ntfs_log_trace ("\n");

	//utils_dump_mem(del->data, 0, del->header->index_length+16, DM_RED);
	//ntfs_log_debug("\n");

#if 0
	off = (u8*) del->children[0] - del->data;
	for (i = 0; i < del->child_count; i++) {
		del_ie = del->children[i];

		ntfs_log_debug("%2d  %4d ", i+1, off);
		off += del_ie->length;

		if (del_ie->flags & INDEX_ENTRY_END) {
			ntfs_log_debug("END (%d)\n", del_ie->length);
			break;
		}

		ntfs_name_print(del_ie->key.file_name.file_name, del_ie->key.file_name.file_name_length);
		ntfs_log_debug(" (%d)\n", del_ie->length);
	}
	ntfs_log_debug("total = %d\n", off);
#endif

	del_ie  = del->children[del_num];
	del_len = del_ie->length;

	src = (u8*) del_ie + del_len;
	dst = (u8*) del_ie;
	len = del->header->index_length + 16 - (src - del->data);

	//ntfs_log_debug("src = %d\n", src - del->data);
	//ntfs_log_debug("dst = %d\n", dst - del->data);
	//ntfs_log_debug("len = %d\n", len);

	memmove(dst, src, len);

	del->data_len -= del_len;
	del->child_count--;

	del->header->index_length   = del->data_len - 16;
	del->header->allocated_size = del->data_len - 16;

	ntfs_mft_resize_resident(del->dir->inode, AT_INDEX_ROOT, NTFS_INDEX_I30, 4, del->data, del->data_len);
	old = del->data;
	del->data = realloc(del->data, del->data_len);
	del->header = (INDEX_HEADER*) (del->data + 0x10);

	//utils_dump_mem(del->data, 0, del->data_len, DM_GREEN | DM_RED);

	src = (u8*) (&del->children[del_num+1]);
	dst = (u8*) (&del->children[del_num]);
	len = (del->child_count - del_num) * sizeof(INDEX_ENTRY*);

	//ntfs_log_debug("src = %d\n", src - (u8*) del->children);
	//ntfs_log_debug("dst = %d\n", dst - (u8*) del->children);
	//ntfs_log_debug("len = %d\n", len);

	memmove(dst, src, len);

	src = (u8*) (&del->sub_nodes[del_num+1]);
	dst = (u8*) (&del->sub_nodes[del_num]);
	len = (del->child_count - del_num) * sizeof(struct ntfs_dt*);

	//ntfs_log_debug("src = %d\n", src - (u8*) del->children);
	//ntfs_log_debug("dst = %d\n", dst - (u8*) del->children);
	//ntfs_log_debug("len = %d\n", len);

	memmove(dst, src, len);

	//ntfs_log_debug("del_num = %d\n", del_num);
	for (i = 0; i < del->child_count; i++)
		del->children[i] = (INDEX_ENTRY*) ((u8*) del->children[i] - old + del->data);
	for (i = del_num; i < del->child_count; i++)
		del->children[i] = (INDEX_ENTRY*) ((u8*) del->children[i] - del_len);

	if (!ntfs_dt_create_children2(del, del->child_count))
		return FALSE;

#if 0
	off = (u8*) del->children[0] - del->data;
	for (i = 0; i < del->child_count; i++) {
		del_ie = del->children[i];

		ntfs_log_debug("%2d  %4d ", i+1, off);
		off += del_len;

		if (del_ie->flags & INDEX_ENTRY_END) {
			ntfs_log_debug("END (%d)\n", del_len);
			break;
		}

		ntfs_name_print(del_ie->key.file_name.file_name, del_ie->key.file_name.file_name_length);
		ntfs_log_debug(" (%d)\n", del_len);
	}
	ntfs_log_debug("total = %d\n", off);
#endif

	//utils_dump_mem(del->data, 0, del->header->index_length+16, DM_DEFAULTS);

	del->changed = TRUE;

	ntfs_log_debug("Modified: inode %lld, $INDEX_ROOT\n", del->dir->inode->mft_no);
	return TRUE;
}

/**
 * ntfs_dt_alloc_remove - Remove an index entry from an index allocation
 * @del:
 * @del_num:
 *
 * Description...
 *
 * Returns:
 */
BOOL ntfs_dt_alloc_remove(struct ntfs_dt *del, int del_num)
{
	INDEX_ENTRY *del_ie = NULL;
	u8 *dst;
	u8 *src;
	int len;
	int i;
	//int off;

	if (!del)
		return FALSE;
	ntfs_log_trace ("\n");

#if 0
	off = (u8*)del->children[0] - del->data;
	for (i = 0; i < del->child_count; i++) {
		del_ie = del->children[i];

		ntfs_log_debug("%2d  %4d ", i, off);
		off += del_ie->length;

		if (del_ie->flags & INDEX_ENTRY_END) {
			ntfs_log_debug("END (%d)\n", del_ie->length);
			break;
		}

		ntfs_name_print(del_ie->key.file_name.file_name, del_ie->key.file_name.file_name_length);
		ntfs_log_debug(" (%d)\n", del_ie->length);
	}
	ntfs_log_debug("total = %d\n", off);
	ntfs_log_debug("\n");
#endif

	//utils_dump_mem(del->data, 0, del->data_len, DM_DEFAULTS);
	//ntfs_log_debug("\n");

	del_ie = del->children[del_num];

	src = (u8*) del_ie + del_ie->length;
	dst = (u8*) del_ie;
	len = del->header->index_length + 24 - (src - del->data);

	//ntfs_log_debug("src = %d\n", src - del->data);
	//ntfs_log_debug("dst = %d\n", dst - del->data);
	//ntfs_log_debug("len = %d\n", len);

	memmove(dst, src, len);

	del->header->index_length -= src - dst;
	del->child_count--;

	dst += len;
	len = del->data_len - del->header->index_length - 24;

	//ntfs_log_debug("dst = %d\n", dst - del->data);
	//ntfs_log_debug("len = %d\n", len);

	memset(dst, 0, len);

	src = (u8*) (&del->children[del_num+1]);
	dst = (u8*) (&del->children[del_num]);
	len = (del->child_count - del_num) * sizeof(INDEX_ENTRY*);

	//ntfs_log_debug("src = %d\n", src - (u8*) del->children);
	//ntfs_log_debug("dst = %d\n", dst - (u8*) del->children);
	//ntfs_log_debug("len = %d\n", len);

	memmove(dst, src, len);

	src = (u8*) (&del->sub_nodes[del_num+1]);
	dst = (u8*) (&del->sub_nodes[del_num]);
	len = (del->child_count - del_num) * sizeof(struct ntfs_dt*);

	//ntfs_log_debug("src = %d\n", src - (u8*) del->children);
	//ntfs_log_debug("dst = %d\n", dst - (u8*) del->children);
	//ntfs_log_debug("len = %d\n", len);

	memmove(dst, src, len);

	//ntfs_log_debug("del_num = %d\n", del_num);
	for (i = del_num; i < del->child_count; i++)
		del->children[i] = (INDEX_ENTRY*) ((u8*) del->children[i] - del_ie->length);

	if (!ntfs_dt_create_children2(del, del->child_count))
		return FALSE;

	//utils_dump_mem(del->data, 0, del->data_len, DM_DEFAULTS);

#if 0
	off = (u8*)del->children[0] - del->data;
	for (i = 0; i < del->child_count; i++) {
		del_ie = del->children[i];

		ntfs_log_debug("%2d  %4d ", i, off);
		off += del_ie->length;

		if (del_ie->flags & INDEX_ENTRY_END) {
			ntfs_log_debug("END (%d)\n", del_ie->length);
			break;
		}

		ntfs_name_print(del_ie->key.file_name.file_name, del_ie->key.file_name.file_name_length);
		ntfs_log_debug(" (%d)\n", del_ie->length);
	}
	ntfs_log_debug("total = %d\n", off);
	ntfs_log_debug("\n");
#endif

	del->changed = TRUE;

	ntfs_log_debug("Modified: inode %lld, $INDEX_ALLOCATION vcn %lld-%lld\n", del->dir->inode->mft_no, del->vcn, del->vcn + (del->dir->index_size>>9) - 1);

	if (del->child_count < 2) {
		ntfs_log_debug("indx is empty\n");
		ntfs_bmp_set_range(del->dir->bitmap, del->vcn, 1, 0);
	}

	return TRUE;
}

/**
 * ntfs_dt_alloc_add - Add an index entry to an index allocation
 * @parent:
 * @index_num:
 * @ie:
 * @child:
 *
 * Description...
 *
 * Returns:
 */
int ntfs_dt_alloc_add(struct ntfs_dt *parent, int index_num, INDEX_ENTRY *ie, struct ntfs_dt *child)
{
	INDEX_BLOCK *block;
	INDEX_ENTRY *entry;
	int need;
	int space;
	u8 *src;
	u8 *dst;
	int len;

	if (!parent || !ie)
		return 0;
	ntfs_log_trace ("\n");

	block = (INDEX_BLOCK*) parent->data;

	need  = ie->length;
	space = parent->data_len - block->index.index_length - 24;

	ntfs_log_debug("need %d, have %d\n", need, space);
	if (need > space) {
		ntfs_log_debug("no room\n");
		return 0;
	}

	//utils_dump_mem(parent->data, 0, parent->data_len, DM_DEFAULTS);
	//ntfs_log_debug("\n");

	src = (u8*) parent->children[index_num];
	dst = src + need;
	len = parent->data + parent->data_len - src - space;
	//ntfs_log_debug("src = %d\n", src - parent->data);
	//ntfs_log_debug("dst = %d\n", dst - parent->data);
	//ntfs_log_debug("len = %d\n", len);

	memmove(dst, src, len);

	dst = src;
	src = (u8*) ie;
	len = need;

	memcpy(dst, src, len);

	block->index.index_length += len;

	dst = parent->data + block->index.index_length + 24;
	len = parent->data_len - block->index.index_length - 24;

	memset(dst, 0, len);

	//realloc children, sub_nodes
	ntfs_dt_create_children2(parent, parent->child_count + 1);

	// regen children pointers
	parent->child_count = 0;

	src = parent->data     + 0x18 + parent->header->entries_offset;
	len = parent->data_len - 0x18 - parent->header->entries_offset;

	while (src < (parent->data + parent->data_len)) {
		entry = (INDEX_ENTRY*) src;

		parent->children[parent->child_count] = entry;
		parent->child_count++;

		if (entry->flags & INDEX_ENTRY_END)
			break;

		src += entry->length;
	}
	ntfs_log_debug("count = %d\n", parent->child_count);

	src = (u8*) &parent->sub_nodes[index_num+parent->child_count-1];
	dst = (u8*) &parent->sub_nodes[index_num];
	len = (parent->child_count - index_num - 1) * sizeof(struct ntfs_dt*);

	memmove(dst, src, len);

	//insert sub_node pointer
	parent->sub_nodes[index_num] = child;

	//utils_dump_mem(parent->data, 0, parent->data_len, DM_DEFAULTS);
	//ntfs_log_debug("\n");
	return 0;
}

/**
 * ntfs_dt_root_add - Add an index entry to an index root
 * @parent:
 * @index_num:
 * @ie:
 * @child:
 *
 * Description...
 *
 * Returns:
 */
int ntfs_dt_root_add(struct ntfs_dt *parent, int index_num, INDEX_ENTRY *ie, struct ntfs_dt *child)
{
	INDEX_ROOT *root;
	INDEX_ENTRY *entry;
	int need;
	int space;
	u8 *attr;
	u8 *src;
	u8 *dst;
	int len;

	if (!parent || !ie)
		return -1;
	ntfs_log_trace ("\n");

	root = (INDEX_ROOT*) parent->data;

	//utils_dump_mem(parent->data, 0, parent->data_len, DM_DEFAULTS);
	//ntfs_log_debug("\n");

	need  = ie->length;
	space = ntfs_mft_free_space(parent->dir);

	ntfs_log_debug("need %d, have %d\n", need, space);
	if (need > space) {
		ntfs_log_debug("no room\n");
		return -1;
	}

	attr = malloc(parent->data_len + need);

	src = parent->data;
	dst = attr;
	len = root->index.entries_offset + 16;

	memcpy(dst, src, len);

	dst += len;
	src = (u8*) ie;
	len = ie->length;

	memcpy(dst, src, len);

	dst += len;
	src = (u8*) parent->children[index_num];
	len = parent->data + parent->data_len - src;

	memcpy(dst, src, len);

	free(parent->data);
	parent->data = attr;
	parent->data_len += need;

	ntfs_log_debug("parent data len = %d\n", parent->data_len);

	root = (INDEX_ROOT*) parent->data;
	root->index.index_length   = parent->data_len - 16;
	root->index.allocated_size = parent->data_len - 16;

	//utils_dump_mem(parent->data, 0, parent->data_len, DM_DEFAULTS);
	//ntfs_log_debug("\n");

	ntfs_mft_resize_resident(parent->dir->inode, AT_INDEX_ROOT, NTFS_INDEX_I30, 4, parent->data, parent->data_len);
	parent->changed = TRUE;

	//realloc children, sub_nodes
	ntfs_dt_create_children2(parent, parent->child_count + 1);

	// regen children pointers
	parent->child_count = 0;

	src = parent->data     + 0x18 + parent->header->entries_offset;
	len = parent->data_len - 0x18 - parent->header->entries_offset;

	// XXX can we rebase the children more simply? (in alloc_add too)
	while (src < (parent->data + parent->data_len)) {
		entry = (INDEX_ENTRY*) src;

		parent->children[parent->child_count] = entry;
		parent->child_count++;

		if (entry->flags & INDEX_ENTRY_END)
			break;

		src += entry->length;
	}
	ntfs_log_debug("count = %d\n", parent->child_count);

	src = (u8*) &parent->sub_nodes[index_num+parent->child_count-1];
	dst = (u8*) &parent->sub_nodes[index_num];
	len = (parent->child_count - index_num - 1) * sizeof(struct ntfs_dt*);

	memmove(dst, src, len);

	//insert sub_node pointer
	parent->sub_nodes[index_num] = child;

	return 0;
}

/**
 * ntfs_dt_add2 - Add an index entry to a directory-tree
 * @ie:
 * @suc:
 * @suc_num:
 * @ded:
 *
 * Description...
 *
 * Returns:
 */
int ntfs_dt_add2(INDEX_ENTRY *ie, struct ntfs_dt *suc, int suc_num, struct ntfs_dt *ded)
{
	int need;
	int space;
	int median;
	struct ntfs_dt *new = NULL;
	struct ntfs_dt *chl;
	INDEX_ENTRY *med_ie = NULL;
	//FILE_NAME_ATTR *file;
	VCN vcn = 0;
	//int i;

	if (!ie || !suc)
		return -1;
	ntfs_log_trace ("\n");

	ntfs_log_debug("Add key to leaf\n");

	//utils_dump_mem(suc->data, 0, suc->data_len, DM_DEFAULTS);

	chl = NULL;
ascend:
	//XXX replace with while/break?

#if 0
	for (; ded; ded = ded->sub_nodes[0]) {
		ntfs_log_debug("\tded vcn = %lld\n", ded->vcn);
	}
#endif

	/*
	 * ADD
	 * room in current node?
	 *   yes, add, done
	 *   no, split, ascend
	 */
	need = ie->length;

	if (ntfs_dt_isroot(suc))
		space = ntfs_dt_root_freespace(suc);
	else
		space = ntfs_dt_alloc_freespace(suc);

	ntfs_log_debug("\tneed %d\n", need);
	ntfs_log_debug("\tspace %d\n", space);

	if (space >= need) {
		//ntfs_log_critical("index = %d\n", suc_num);
		//ntfs_log_debug("prev inode = %p\n", suc->inodes[suc_num-1]);
		//ntfs_log_debug("curr inode = %p\n", suc->inodes[suc_num]);
		ntfs_log_debug("count = %d\n", suc->child_count);
		if (ntfs_dt_isroot(suc))
			ntfs_dt_root_add(suc, suc_num, ie, chl);
		else
			ntfs_dt_alloc_add(suc, suc_num, ie, chl);
		ntfs_log_debug("count = %d\n", suc->child_count);
		//goto done;
		return suc_num;	//XXX this is probably off-by-one
	}

	/*
	 * SPLIT
	 * any dead?
	 *   yes reuse
	 *   no alloc
	 */
	if (ded) {
		new = ded;
		vcn = ded->vcn;
		ded = ded->sub_nodes[0];
		ntfs_log_debug("\treusing vcn %lld\n", new->vcn);
	} else {
		ntfs_mft_add_index(suc->dir);
		/*
		 * ALLOC
		 * any unused records?
		 *   yes, enable first
		 *   no, extend
		 */
		/*
		 * ENABLE
		 * modify bitmap
		 * init indx record
		 */
		/*
		 * EXTEND
		 * room in bitmap
		 *   yes, do nothing
		 *   no, extend bitmap
		 * extend alloc
		 */
		/*
		 * EXTEND BITMAP
		 * extend bitmap
		 * init bitmap
		 */
	}

	//ntfs_log_debug("\tnode has %d children\n", suc->child_count);

	// initialise new node
	// XXX ntfs_dt_initialise(new, vcn);

	goto done;

	// find median key
	median = (suc->child_count+1) / 2;
	med_ie = ntfs_ie_copy(suc->children[median]);
	//file = &med_ie->key.file_name; ntfs_log_debug("\tmed name: "); ntfs_name_print(file->file_name, file->file_name_length); ntfs_log_debug("\n");

	ntfs_ie_free(med_ie);
	med_ie = NULL;

	//ntfs_log_debug("suc key count = %d\n", suc->child_count);
	//ntfs_log_debug("new key count = %d\n", new->child_count);

	//ntfs_log_debug("median's child = %p\n", suc->sub_nodes[median]);
	// need to pass the child when ascending
	chl = suc->sub_nodes[median];

	// transfer keys
	if (ntfs_dt_transfer(suc, new, 0, median-1) < 0)
		goto done;

	//ntfs_log_debug("suc key count = %d\n", suc->child_count);
	//ntfs_log_debug("new key count = %d\n", new->child_count);

	//file = &suc->children[0]->key.file_name; ntfs_log_debug("\tmed name: "); ntfs_name_print(file->file_name, file->file_name_length); ntfs_log_debug("\n");

	// can this be a root node?
	if (ntfs_dt_isroot(suc))
		ntfs_dt_root_remove(suc, 0);
	else
		ntfs_dt_alloc_remove(suc, 0);

	//file = &suc->children[0]->key.file_name; ntfs_log_debug("\tmed name: "); ntfs_name_print(file->file_name, file->file_name_length); ntfs_log_debug("\n");
	//ntfs_log_debug("suc key count = %d\n", suc->child_count);
	//ntfs_log_debug("new key count = %d\n", new->child_count);

	// remove the median key

	// split when median has children
	// median child given to new !
	// median child is new
	// ascend

	med_ie = ntfs_ie_set_vcn(med_ie, new->vcn);
	if (!med_ie)
		goto done;

	//ntfs_log_debug("median child = %lld\n", ntfs_ie_get_vcn(med_ie));
	//ntfs_log_debug("new's vcn    = %lld\n", new->vcn);

	// adjust parents
	//	attach new to median
	// escape clause for root node?
	// goto ascend

	// ie = insert
	// child = child
	// suc = successor
	// suc_num = insert point

	ie = med_ie;
	suc = suc->parent;
	suc_num = 0;

	//ntfs_log_debug("\n");
	ntfs_log_debug("Ascend\n");
	goto ascend;
done:
	return 0;
}


#endif /* NTFS_RICH */

