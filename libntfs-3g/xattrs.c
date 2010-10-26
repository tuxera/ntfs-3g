/**
 * xattrs.c : common functions to deal with system extended attributes
 *
 * Copyright (c) 2010 Jean-Pierre Andre
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

#ifdef HAVE_SETXATTR /* extended attributes support required */

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "types.h"
#include "param.h"
#include "layout.h"
#include "attrib.h"
#include "index.h"
#include "dir.h"
#include "security.h"
#include "acls.h"
#include "efs.h"
#include "reparse.h"
#include "object_id.h"
#include "misc.h"
#include "logging.h"
#include "xattrs.h"

static const char xattr_ntfs_3g[] = "ntfs-3g.";
static const char nf_ns_user_prefix[] = "user.";
static const int nf_ns_user_prefix_len = sizeof(nf_ns_user_prefix) - 1;

static const char nf_ns_xattr_ntfs_acl[] = "system.ntfs_acl";
static const char nf_ns_xattr_attrib[] = "system.ntfs_attrib";
static const char nf_ns_xattr_attrib_be[] = "system.ntfs_attrib_be";
static const char nf_ns_xattr_efsinfo[] = "user.ntfs.efsinfo";
static const char nf_ns_xattr_reparse[] = "system.ntfs_reparse_data";
static const char nf_ns_xattr_object_id[] = "system.ntfs_object_id";
static const char nf_ns_xattr_dos_name[] = "system.ntfs_dos_name";
static const char nf_ns_xattr_times[] = "system.ntfs_times";
static const char nf_ns_xattr_times_be[] = "system.ntfs_times_be";
static const char nf_ns_xattr_posix_access[] = "system.posix_acl_access";
static const char nf_ns_xattr_posix_default[] = "system.posix_acl_default";

static const char nf_ns_alt_xattr_efsinfo[] = "user.ntfs.efsinfo";

struct XATTRNAME {
	enum SYSTEMXATTRS xattr;
	const char *name;
} ;

static struct XATTRNAME nf_ns_xattr_names[] = {
	{ XATTR_NTFS_ACL, nf_ns_xattr_ntfs_acl },
	{ XATTR_NTFS_ATTRIB, nf_ns_xattr_attrib },
	{ XATTR_NTFS_ATTRIB_BE, nf_ns_xattr_attrib_be },
	{ XATTR_NTFS_EFSINFO, nf_ns_xattr_efsinfo },
	{ XATTR_NTFS_REPARSE_DATA, nf_ns_xattr_reparse },
	{ XATTR_NTFS_OBJECT_ID, nf_ns_xattr_object_id },
	{ XATTR_NTFS_DOS_NAME, nf_ns_xattr_dos_name },
	{ XATTR_NTFS_TIMES, nf_ns_xattr_times },
	{ XATTR_NTFS_TIMES_BE, nf_ns_xattr_times_be },
	{ XATTR_POSIX_ACC, nf_ns_xattr_posix_access },
	{ XATTR_POSIX_DEF, nf_ns_xattr_posix_default },
	{ XATTR_UNMAPPED, (char*)NULL } /* terminator */
};

/*
 *		Make an integer big-endian
 *
 *	Swap bytes on a small-endian computer and does nothing on a
 *	big-endian computer.
 */

static void fix_big_endian(char *p, int size)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	int i,j;
	int c;

	i = 0;
	j = size - 1;
	while (i < j) {
		c = p[i];
		p[i++] = p[j];
		p[j--] = c;
	}
#endif
}

/*
 *		Determine whether an extended attribute is mapped to
 *	internal data (original name in system namespace, or renamed)
 */

enum SYSTEMXATTRS ntfs_xattr_system_type(const char *name)
{
	struct XATTRNAME *p;

	p = nf_ns_xattr_names;
	while (p->name && strcmp(p->name,name))
		p++;
	return (p->xattr);
}

int ntfs_xattr_listxattr(ntfs_inode *ni, ntfs_attr_search_ctx *actx,
			char *list, size_t size, BOOL prefixing)
{
	int ret = 0;
	char *to = list;

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
		/* List efs info xattr for encrypted files */
	if (ni->vol->efs_raw && (ni->flags & FILE_ATTR_ENCRYPTED)) {
		ret += sizeof(nf_ns_xattr_efsinfo);
		if ((size_t)ret <= size) {
			memcpy(to, nf_ns_xattr_efsinfo,
				sizeof(nf_ns_xattr_efsinfo));
			to += sizeof(nf_ns_xattr_efsinfo);
		}
	}
exit :
	return (ret);
}


int ntfs_xattr_system_getxattr(struct SECURITY_CONTEXT *scx,
			enum SYSTEMXATTRS attr,
			ntfs_inode *ni, ntfs_inode *dir_ni,
			char *value, size_t size)
{
	int res;
	int i;

				/*
				 * the returned value is the needed
				 * size. If it is too small, no copy
				 * is done, and the caller has to
				 * issue a new call with correct size.
				 */
	switch (attr) {
	case XATTR_NTFS_ACL :
		res = ntfs_get_ntfs_acl(scx, ni, value, size);
		break;
#if POSIXACLS
	case XATTR_POSIX_ACC :
		res = ntfs_get_posix_acl(scx, ni, nf_ns_xattr_posix_access,
				value, size);
		break;
	case XATTR_POSIX_DEF :
		res = ntfs_get_posix_acl(scx, ni, nf_ns_xattr_posix_default,
				value, size);
		break;
#endif
	case XATTR_NTFS_ATTRIB :
		res = ntfs_get_ntfs_attrib(ni, value, size);
		break;
	case XATTR_NTFS_ATTRIB_BE :
		res = ntfs_get_ntfs_attrib(ni, value, size);
		if ((res == 4) && value) {
			if (size >= 4)
				fix_big_endian(value,4);
			else
				res = -EINVAL;
		}
		break;
	case XATTR_NTFS_EFSINFO :
		if (ni->vol->efs_raw)
			res = ntfs_get_efs_info(ni, value, size);
		else
			res = -EPERM;
		break;
	case XATTR_NTFS_REPARSE_DATA :
		res = ntfs_get_ntfs_reparse_data(ni, value, size);
		break;
	case XATTR_NTFS_OBJECT_ID :
		res = ntfs_get_ntfs_object_id(ni, value, size);
		break;
	case XATTR_NTFS_DOS_NAME:
		if (dir_ni)
			res = ntfs_get_ntfs_dos_name(ni, dir_ni, value, size);
		else
			res = -errno;
		break;
	case XATTR_NTFS_TIMES:
		res = ntfs_inode_get_times(ni, value, size);
		break;
	case XATTR_NTFS_TIMES_BE:
		res = ntfs_inode_get_times(ni, value, size);
		if ((res > 0) && value) {
			for (i=0; (i+1)*sizeof(u64)<=(unsigned int)res; i++)
				fix_big_endian(&value[i*sizeof(u64)],
						sizeof(u64));
		}
		break;
	default :
		errno = EOPNOTSUPP;
		res = -errno;
		break;
	}
	return (res);
}

int ntfs_xattr_system_setxattr(struct SECURITY_CONTEXT *scx,
			enum SYSTEMXATTRS attr,
			ntfs_inode *ni, ntfs_inode *dir_ni,
			const char *value, size_t size, int flags)
{
	int res;
	int i;
	char buf[4*sizeof(u64)];

	switch (attr) {
	case XATTR_NTFS_ACL :
		res = ntfs_set_ntfs_acl(scx, ni, value, size, flags);
		break;
#if POSIXACLS
	case XATTR_POSIX_ACC :
		res = ntfs_set_posix_acl(scx ,ni , nf_ns_xattr_posix_access,
					value, size, flags);
		break;
	case XATTR_POSIX_DEF :
		res = ntfs_set_posix_acl(scx, ni, nf_ns_xattr_posix_default,
					value, size, flags);
		break;
#endif
	case XATTR_NTFS_ATTRIB :
		res = ntfs_set_ntfs_attrib(ni, value, size, flags);
		break;
	case XATTR_NTFS_ATTRIB_BE :
		if (value && (size >= 4)) {
			memcpy(buf,value,4);
			fix_big_endian(buf,4);
			res = ntfs_set_ntfs_attrib(ni, buf, 4, flags);
		} else
			res = ntfs_set_ntfs_attrib(ni, value, size, flags);
		break;
	case XATTR_NTFS_EFSINFO :
		if (ni->vol->efs_raw)
			res = ntfs_set_efs_info(ni, value, size, flags);
		else
			res = -EPERM;
		break;
	case XATTR_NTFS_REPARSE_DATA :
		res = ntfs_set_ntfs_reparse_data(ni, value, size, flags);
		break;
	case XATTR_NTFS_OBJECT_ID :
		res = ntfs_set_ntfs_object_id(ni, value, size, flags);
		break;
	case XATTR_NTFS_DOS_NAME:
		if (dir_ni)
		/* warning : this closes both inodes */
			res = ntfs_set_ntfs_dos_name(ni, dir_ni, value,
						size, flags);
		else
			res = -errno;
		break;
	case XATTR_NTFS_TIMES:
		res = ntfs_inode_set_times(ni, value, size, flags);
		break;
	case XATTR_NTFS_TIMES_BE:
		if (value && (size > 0) && (size <= 4*sizeof(u64))) {
			memcpy(buf,value,size);
			for (i=0; (i+1)*sizeof(u64)<=size; i++)
				fix_big_endian(&buf[i*sizeof(u64)],
						sizeof(u64));
			res = ntfs_inode_set_times(ni, buf, size, flags);
		} else
			res = ntfs_inode_set_times(ni, value, size, flags);
		break;
	default :
		errno = EOPNOTSUPP;
		res = -errno;
		break;
	}
	return (res);
}

int ntfs_xattr_system_removexattr(struct SECURITY_CONTEXT *scx,
			enum SYSTEMXATTRS attr,
			ntfs_inode *ni, ntfs_inode *dir_ni)
{
	int res;

	res = 0;
	switch (attr) {
		/*
		 * Removal of NTFS ACL, ATTRIB, EFSINFO or TIMES
		 * is never allowed
		 */
	case XATTR_NTFS_ACL :
	case XATTR_NTFS_ATTRIB :
	case XATTR_NTFS_ATTRIB_BE :
	case XATTR_NTFS_EFSINFO :
	case XATTR_NTFS_TIMES :
	case XATTR_NTFS_TIMES_BE :
		res = -EPERM;
		break;
#if POSIXACLS
	case XATTR_POSIX_ACC :
	case XATTR_POSIX_DEF :
		if (ni) {
			if (!ntfs_allowed_as_owner(scx, ni)
			   || ntfs_remove_posix_acl(scx, ni,
					(attr == XATTR_POSIX_ACC ?
					nf_ns_xattr_posix_access :
					nf_ns_xattr_posix_default)))
				res = -errno;
		} else
			res = -errno;
		break;
#endif
	case XATTR_NTFS_REPARSE_DATA :
		if (ni) {
			if (!ntfs_allowed_as_owner(scx, ni)
			    || ntfs_remove_ntfs_reparse_data(ni))
				res = -errno;
		} else
			res = -errno;
		break;
	case XATTR_NTFS_OBJECT_ID :
		if (ni) {
			if (!ntfs_allowed_as_owner(scx, ni)
			    || ntfs_remove_ntfs_object_id(ni))
				res = -errno;
		} else
			res = -errno;
		break;
	case XATTR_NTFS_DOS_NAME:
		if (ni && dir_ni) {
			if (ntfs_remove_ntfs_dos_name(ni,dir_ni))
				res = -errno;
			/* ni and dir_ni have been closed */
		} else
			res = -errno;
		break;
	default :
		errno = EOPNOTSUPP;
		res = -errno;
		break;
	}
	return (res);
}

#endif  /* HAVE_SETXATTR */
