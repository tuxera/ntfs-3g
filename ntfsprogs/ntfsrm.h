/*
 * ntfsrm - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2004 Richard Russon
 *
 * This utility will delete files from an NTFS volume.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _NTFSRM_H_
#define _NTFSRM_H_

#include "types.h"
#include "layout.h"

#define ntfs_malloc	malloc
#define ntfs_realloc	realloc
#define ntfs_calloc	calloc
#define ntfs_free	free

/**
 * struct options
 */
struct options {
	char		*device;	/* Device/File to work with */
	char		*file;		/* File to delete */
	int		 force;		/* Override common sense */
	int		 interactive;	/* Ask before deleting files */
	int		 recursive;	/* Delete files in subdirectories */
	int		 quiet;		/* Less output */
	int		 verbose;	/* Extra output */
	int		 noaction;	/* Do not write to disk */
	int		 nodirty;	/* Do not mark volume dirty */
};

/**
 * struct ntfs_bmp
 * a cache for either dir/$BITMAP, $MFT/$BITMAP or $Bitmap/$DATA
 */
struct ntfs_bmp {
	ntfs_volume	 *vol;
	ntfs_attr	 *attr;
	int		  count;
	u8		**data;
	VCN		 *data_vcn;
	u8		 *cache;
	VCN		  cache_vcn;
};

/**
 * struct ntfs_dt
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

/**
 * struct ntfs_dir
 */
struct ntfs_dir {
	ntfs_volume	  *vol;
	struct ntfs_dir	  *parent;
	ntfschar	  *name;
	int		   name_len;
	MFT_REF		   mft_num;
	struct ntfs_dt	  *index;
	struct ntfs_dir	 **children;
	int		   child_count;
	struct ntfs_bmp	  *bitmap;
	ntfs_inode	  *inode;
	ntfs_attr	  *iroot;
	ntfs_attr	  *ialloc;
	int                index_size;
};

/**
 * struct ntfs_find
 */
struct ntfs_find {
	ntfs_inode	  *inode;
	struct ntfs_dir   *dir;
	struct ntfs_dt	  *dt;
	int		   dt_index;
	MFT_REF		   mref;
};


#define RED	"[31m"
#define GREEN	"[32m"
#define YELLOW	"[33m"
#define BLUE	"[34m"
#define MAGENTA	"[35m"
#define CYAN	"[36m"
#define BOLD	"[01m"
#define END	"[0m"

#define ROUND_UP(num,bound) (((num)+((bound)-1)) & ~((bound)-1))
#define ROUND_DOWN(num,bound) ((num) & ~((bound)-1))
#define ATTR_SIZE(s) ROUND_UP(s,8)

#endif /* _NTFSRM_H_ */

