/*
 * inode.h - Defines for NTFS inode handling. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2001,2002 Anton Altaparmakov
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

#ifndef _NTFS_INODE_H
#define _NTFS_INODE_H

/* Forward declaration */
typedef struct _ntfs_inode ntfs_inode;

#include "types.h"
#include "support.h"
#include "runlist.h"

/*
 * Defined bits for the state field in the ntfs_inode structure.
 * (f) = files only, (d) = directories only
 */
typedef enum {
	NI_Dirty,		/* 1: Mft record needs to be written to disk. */

	/* The NI_AttrList* tests only make sense for base inodes. */
	NI_AttrList,		/* 1: Mft record contains an attribute list. */
	NI_AttrListNonResident,	/* 1: Attribute list is non-resident. Implies
				      NI_AttrList is set. */
	NI_AttrListDirty,	/* 1: Attribute list needs to be written to the
				      mft record and then to disk. */
} ntfs_inode_state_bits;

#define  test_nino_flag(ni, flag)	   test_bit(NI_##flag, (ni)->state)
#define   set_nino_flag(ni, flag)	    set_bit(NI_##flag, (ni)->state)
#define clear_nino_flag(ni, flag)	  clear_bit(NI_##flag, (ni)->state)

#define test_and_set_nino_flag(ni, flag)	\
				   test_and_set_bit(NI_##flag, (ni)->state)
#define test_and_clear_nino_flag(ni, flag)	\
				 test_and_clear_bit(NI_##flag, (ni)->state)

#define NInoDirty(ni)				  test_nino_flag(ni, Dirty)
#define NInoSetDirty(ni)			   set_nino_flag(ni, Dirty)
#define NInoClearDirty(ni)			 clear_nino_flag(ni, Dirty)
#define NInoTestAndSetDirty(ni)		  test_and_set_nino_flag(ni, Dirty)
#define NInoTestAndClearDirty(ni)	test_and_clear_nino_flag(ni, Dirty)

#define NInoAttrList(ni)			  test_nino_flag(ni, AttrList)
#define NInoSetAttrList(ni)			   set_nino_flag(ni, AttrList)
#define NInoClearAttrList(ni)			 clear_nino_flag(ni, AttrList)


#define  test_nino_al_flag(ni, flag)	 test_nino_flag(ni, AttrList##flag)
#define   set_nino_al_flag(ni, flag)	  set_nino_flag(ni, AttrList##flag)
#define clear_nino_al_flag(ni, flag)	clear_nino_flag(ni, AttrList##flag)

#define NInoAttrListNonResident(ni)	   test_nino_al_flag(ni, NonResident)
#define NInoSetAttrListNonResident(ni)	    set_nino_al_flag(ni, NonResident)
#define NInoClearAttrListNonResident(ni)  clear_nino_al_flag(ni, NonResident)

#define NInoAttrListDirty(ni)		   test_nino_al_flag(ni, Dirty)
#define NInoAttrListSetDirty(ni)	    set_nino_al_flag(ni, Dirty)
#define NInoAttrListClearDirty(ni)	  clear_nino_al_flag(ni, Dirty)

/*
 * The NTFS in-memory inode structure. It is just used as an extension to the
 * fields already provided in the VFS inode.
 */
struct _ntfs_inode {
	u64 mft_no;		/* Inode / mft record number. */
	MFT_RECORD *mrec;	/* The actual mft record of the inode. */
	ntfs_volume *vol;	/* Pointer to the ntfs volume of this inode. */
	unsigned long state;	/* NTFS specific flags describing this inode.
				   See ntfs_inode_state_bits above. */
	/*
	 * Attribute list support (for use by the attribute lookup functions).
	 * Setup during ntfs_open_inode() for all inodes with attribute lists.
	 * Only valid if NI_AttrList is set in state, further attr_list_rl is
	 * only valid if NI_AttrListNonResident is set.
	 */
	u32 attr_list_size;	/* Length of attribute list value in bytes. */
	u8 *attr_list;		/* Attribute list value itself. */
	runlist *attr_list_rl;	/* Run list for the attribute list value. */
	/* Below fields are always valid. */
	s32 nr_extents;		/* For a base mft record, the number of
				   attached extent inodes (0 if none), for
				   extent records this is -1. */
	union {		/* This union is only used if nr_extents != 0. */
		ntfs_inode **extent_nis;/* For nr_extents > 0, array of the
					   ntfs inodes of the extent mft
					   records belonging to this base
					   inode which have been loaded. */
		ntfs_inode *base_ni;	/* For nr_extents == -1, the ntfs
					   inode of the base mft record. */
	};
};

extern ntfs_inode *ntfs_inode_open(ntfs_volume *vol, const MFT_REF mref);

extern int ntfs_inode_close(ntfs_inode *ni);

extern ntfs_inode *ntfs_extent_inode_open(ntfs_inode *base_ni,
		const MFT_REF mref);

/**
 * ntfs_inode_mark_dirty - set the inode (and its base inode if it exists) dirty
 * @ni:		ntfs inode to set dirty
 *
 * Set the inode @ni dirty so it is written out later (at the latest at
 * ntfs_inode_close() time). If @ni is an extent inode, set the base inode
 * dirty, too.
 *
 * This function cannot fail.
 */
static __inline__ void ntfs_inode_mark_dirty(ntfs_inode *ni) {
	NInoSetDirty(ni);
	if (ni->nr_extents == -1)
		NInoSetDirty(ni->base_ni);
}

extern int ntfs_inode_sync(ntfs_inode *ni);

#endif /* defined _NTFS_INODE_H */

