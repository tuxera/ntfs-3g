/*
 * ntfs-3g_common.h - Common declarations for ntfs-3g and lowntfs-3g.
 *
 * Copyright (c) 2010-2011 Jean-Pierre Andre
 * Copyright (c) 2010      Erik Larsson
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
 * along with this program (in the main directory of the NTFS-3G
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _NTFS_3G_COMMON_H
#define _NTFS_3G_COMMON_H

#include "inode.h"

extern const char xattr_ntfs_3g[];

extern const char nf_ns_user_prefix[];
extern const int nf_ns_user_prefix_len;
extern const char nf_ns_system_prefix[];
extern const int nf_ns_system_prefix_len;
extern const char nf_ns_security_prefix[];
extern const int nf_ns_security_prefix_len;
extern const char nf_ns_trusted_prefix[];
extern const int nf_ns_trusted_prefix_len;

int ntfs_fuse_listxattr_common(ntfs_inode *ni, ntfs_attr_search_ctx *actx,
 			char *list, size_t size, BOOL prefixing);

#endif /* _NTFS_3G_COMMON_H */
