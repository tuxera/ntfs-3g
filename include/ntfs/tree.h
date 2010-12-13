/*
 * tree.h - Directory tree handling code.  Part of the Linux-NTFS project.
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

#ifndef _NTFS_TREE_H_
#define _NTFS_TREE_H_

#include "layout.h"
#include "volume.h"

struct ntfs_dir;

/**
 * struct ntfs_dt -
 */
struct ntfs_dt {
	struct ntfs_dir	 *dir;
	struct ntfs_dt	 *parent;
	u8		 *data;
	int		  data_len;
	int		  child_count;
	INDEX_ENTRY	**children;
	struct ntfs_dt	**sub_nodes;
	ntfs_inode	**inodes;
	VCN		  vcn;
	INDEX_HEADER	 *header;
	BOOL		  changed;
};


void ntfs_dt_free(struct ntfs_dt *dt);
int ntfs_dt_rollback(struct ntfs_dt *dt);
int ntfs_dt_commit(struct ntfs_dt *dt);
BOOL ntfs_dt_create_children2(struct ntfs_dt *dt, int count);
BOOL ntfs_dt_resize_children3(struct ntfs_dt *dt, int new);
int ntfs_dt_root_count(struct ntfs_dt *dt);
int ntfs_dt_alloc_count(struct ntfs_dt *dt);
int ntfs_dt_initialise2(ntfs_volume *vol, struct ntfs_dt *dt);
struct ntfs_dt * ntfs_dt_create(struct ntfs_dir *dir, struct ntfs_dt *parent, VCN vcn);
MFT_REF ntfs_dt_find(struct ntfs_dt *dt, ntfschar *name, int name_len);
struct ntfs_dt * ntfs_dt_find2(struct ntfs_dt *dt, ntfschar *name, int name_len, int *index_num);
struct ntfs_dt * ntfs_dt_find3(struct ntfs_dt *dt, ntfschar *name, int name_len, int *index_num);
struct ntfs_dt * ntfs_dt_find4(struct ntfs_dt *dt, ntfschar *name, int name_len, int *index_num);
void ntfs_dt_find_all(struct ntfs_dt *dt);
int ntfs_dt_find_parent(struct ntfs_dt *dt);
BOOL ntfs_dt_isroot(struct ntfs_dt *dt);
int ntfs_dt_root_freespace(struct ntfs_dt *dt);
int ntfs_dt_alloc_freespace(struct ntfs_dt *dt);
int ntfs_dt_transfer(struct ntfs_dt *old, struct ntfs_dt *new, int start, int count);
int ntfs_dt_alloc_insert(struct ntfs_dt *dt, INDEX_ENTRY *first, int count);
INDEX_ENTRY * ntfs_dt_alloc_insert2(struct ntfs_dt *dt, int before, int count, int bytes);
int ntfs_dt_root_insert(struct ntfs_dt *dt, INDEX_ENTRY *first, int count);
int ntfs_dt_alloc_remove2(struct ntfs_dt *dt, int start, int count);
int ntfs_dt_root_remove2(struct ntfs_dt *dt, int start, int count);
int ntfs_dt_transfer2(struct ntfs_dt *old, struct ntfs_dt *new, int start, int count);
int ntfs_dt_root_replace(struct ntfs_dt *del, int del_num, INDEX_ENTRY *del_ie, INDEX_ENTRY *suc_ie);
BOOL ntfs_dt_alloc_replace(struct ntfs_dt *del, int del_num, INDEX_ENTRY *del_ie, INDEX_ENTRY *suc_ie);
BOOL ntfs_dt_root_remove(struct ntfs_dt *del, int del_num);
BOOL ntfs_dt_alloc_remove(struct ntfs_dt *del, int del_num);
int ntfs_dt_alloc_add(struct ntfs_dt *parent, int index_num, INDEX_ENTRY *ie, struct ntfs_dt *child);
int ntfs_dt_root_add(struct ntfs_dt *parent, int index_num, INDEX_ENTRY *ie, struct ntfs_dt *child);
int ntfs_dt_add2(INDEX_ENTRY *ie, struct ntfs_dt *suc, int suc_num, struct ntfs_dt *ded);

#endif /* _NTFS_TREE_H_ */

