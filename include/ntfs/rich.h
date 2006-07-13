/*
 * rich.h - Temporary junk file.  Part of the Linux-NTFS project.
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

#ifndef _NTFS_RICH_H_
#define _NTFS_RICH_H_

#include "layout.h"
#include "attrib.h"
#include "bitmap.h"

#define ATTR_SIZE(s) ROUND_UP(s, 3)

ATTR_RECORD * find_attribute(const ATTR_TYPES type, ntfs_attr_search_ctx *ctx);
ATTR_RECORD * find_first_attribute(const ATTR_TYPES type, MFT_RECORD *mft);
int utils_free_non_residents3(struct ntfs_bmp *bmp, ntfs_inode *inode, ATTR_RECORD *attr);
int utils_free_non_residents2(ntfs_inode *inode, struct ntfs_bmp *bmp);
void ntfs_name_print(ntfschar *name, int name_len);

#endif /* _NTFS_RICH_H_ */

