/**
 * ntfs-3g_common.c - Common definitions for ntfs-3g and lowntfs-3g.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "inode.h"
#include "security.h"
#include "xattrs.h"
#include "ntfs-3g_common.h"

const char xattr_ntfs_3g[] = "ntfs-3g.";

const char nf_ns_user_prefix[] = "user.";
const int nf_ns_user_prefix_len = sizeof(nf_ns_user_prefix) - 1;
const char nf_ns_system_prefix[] = "system.";
const int nf_ns_system_prefix_len = sizeof(nf_ns_system_prefix) - 1;
const char nf_ns_security_prefix[] = "security.";
const int nf_ns_security_prefix_len = sizeof(nf_ns_security_prefix) - 1;
const char nf_ns_trusted_prefix[] = "trusted.";
const int nf_ns_trusted_prefix_len = sizeof(nf_ns_trusted_prefix) - 1;

static const char nf_ns_alt_xattr_efsinfo[] = "user.ntfs.efsinfo";

#ifdef HAVE_SETXATTR

int ntfs_fuse_listxattr_common(ntfs_inode *ni, ntfs_attr_search_ctx *actx,
			char *list, size_t size, BOOL prefixing)
{
	int ret = 0;
	char *to = list;
#ifdef XATTR_MAPPINGS
	BOOL accepted;
	const struct XATTRMAPPING *item;
#endif /* XATTR_MAPPINGS */

		/* first list the regular user attributes (ADS) */
	while (!ntfs_attr_lookup(AT_DATA, NULL, 0, CASE_SENSITIVE,
				0, NULL, 0, actx)) {
		char *tmp_name = NULL;
		int tmp_name_len;

		if (!actx->attr->name_length)
			continue;
		tmp_name_len = ntfs_ucstombs(
			(ntfschar *)((u8*)actx->attr +
				le16_to_cpu(actx->attr->name_offset)),
			actx->attr->name_length, &tmp_name, 0);
		if (tmp_name_len < 0) {
			ret = -errno;
			goto exit;
		}
				/*
				 * When using name spaces, do not return
				 * security, trusted or system attributes
				 * (filtered elsewhere anyway)
				 * otherwise insert "user." prefix
				 */
		if (prefixing) {
			if ((strlen(tmp_name) > sizeof(xattr_ntfs_3g))
			  && !strncmp(tmp_name,xattr_ntfs_3g,
				sizeof(xattr_ntfs_3g)-1))
				tmp_name_len = 0;
			else
				ret += tmp_name_len
					 + nf_ns_user_prefix_len + 1;
		} else
			ret += tmp_name_len + 1;
		if (size && tmp_name_len) {
			if ((size_t)ret <= size) {
				if (prefixing) {
					strcpy(to, nf_ns_user_prefix);
					to += nf_ns_user_prefix_len;
				}
				strncpy(to, tmp_name, tmp_name_len);
				to += tmp_name_len;
				*to = 0;
				to++;
			} else {
				free(tmp_name);
				ret = -ERANGE;
				goto exit;
			}
		}
		free(tmp_name);
	}
#ifdef XATTR_MAPPINGS
		/* now append the system attributes mapped to user space */
	for (item=ni->vol->xattr_mapping; item; item=item->next) {
		switch (item->xattr) {
		case XATTR_NTFS_EFSINFO :
			accepted = ni->vol->efs_raw
				&& (ni->flags & FILE_ATTR_ENCRYPTED);
			break;
		case XATTR_NTFS_REPARSE_DATA :
			accepted = (ni->flags & FILE_ATTR_REPARSE_POINT)
					!= const_cpu_to_le32(0);
			break;
// TODO : we are supposed to only return xattrs which are set
// this is more complex for OBJECT_ID and DOS_NAME
		default : accepted = TRUE;
			break;
		}
		if (accepted) {
			ret += strlen(item->name) + 1;
			if (size) {
				if ((size_t)ret <= size) {
					strcpy(to, item->name);
					to += strlen(item->name);
					*to++ = 0;
				} else {
					ret = -ERANGE;
					goto exit;
				}
			}
#else /* XATTR_MAPPINGS */
		/* List efs info xattr for encrypted files */
	if (ni->vol->efs_raw && (ni->flags & FILE_ATTR_ENCRYPTED)) {
		ret += sizeof(nf_ns_alt_xattr_efsinfo);
		if ((size_t)ret <= size) {
			memcpy(to, nf_ns_alt_xattr_efsinfo,
				sizeof(nf_ns_alt_xattr_efsinfo));
			to += sizeof(nf_ns_alt_xattr_efsinfo);
#endif /* XATTR_MAPPINGS */
		}
	}
exit :
	return (ret);
}

#endif /* HAVE_SETXATTR */
