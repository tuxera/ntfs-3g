/**
 * reparse.c - Processing of reparse points
 *
 *	This module is part of ntfs-3g library, but may also be
 *	integrated in tools running over Linux or Windows
 *
 * Copyright (c) 2008 Jean-Pierre Andre
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
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_SYS_SYSMACROS_H
#include <sys/sysmacros.h>
#endif

#include "types.h"
#include "debug.h"
#include "attrib.h"
#include "inode.h"
#include "dir.h"
#include "volume.h"
#include "mft.h"
#include "index.h"
#include "lcnalloc.h"
#include "logging.h"
#include "misc.h"
#include "reparse.h"

/* the definition in layout.h is wrong.
   source : http://www.opensource.apple.com/darwinsource/WWDC2004/tcl-14/tcl/win/tclWinFile.c
*/
#undef IO_REPARSE_TAG_MOUNT_POINT
#define IO_REPARSE_TAG_MOUNT_POINT 0xA0000003


struct SYMLNK_REPARSE_DATA {
	u16	subst_name_offset;
	u16	subst_name_length;
	u16	print_name_offset;
	u16	print_name_length;
	char	path_buffer[0];      /* above data assume this is char array */
} ;

static const ntfschar dir_junction_head[] = {
	const_cpu_to_le16('\\'),
	const_cpu_to_le16('?'),
	const_cpu_to_le16('?'),
	const_cpu_to_le16('\\')
} ;

static const ntfschar vol_junction_head[] = {
	const_cpu_to_le16('\\'),
	const_cpu_to_le16('?'),
	const_cpu_to_le16('?'),
	const_cpu_to_le16('\\'),
	const_cpu_to_le16('V'),
	const_cpu_to_le16('o'),
	const_cpu_to_le16('l'),
	const_cpu_to_le16('u'),
	const_cpu_to_le16('m'),
	const_cpu_to_le16('e'),
	const_cpu_to_le16('{'),
} ;

static const char mappingdir[] = ".NTFS-3G/";

/*
 *		Fix a file name with doubtful case in some directory index
 *	and return the name with the casing used in directory.
 *
 *	Should only be used to translate paths stored with case insensitivity
 *	(such as directory junctions) when no case conflict is expected.
 *	If there some ambiguity, the name which collates first is returned.
 *
 *	The name is converted to upper case and searched the usual way.
 *	The collation rules for file names are such as we should get the
 *	first candidate if any.
 */

static u64 ntfs_fix_file_name(ntfs_inode *dir_ni, ntfschar *uname,
		int uname_len)
{
	ntfs_volume *vol = dir_ni->vol;
	ntfs_index_context *icx;
	u64 mref;
	le64 lemref;
	int lkup;
	int olderrno;
	int i;
	FILE_NAME_ATTR *found;
	struct {
		FILE_NAME_ATTR attr;
		ntfschar file_name[NTFS_MAX_NAME_LEN + 1];
	} find;

	mref = (u64)-1; /* default return */
	icx = ntfs_index_ctx_get(dir_ni, NTFS_INDEX_I30, 4);
	if (uname_len > NTFS_MAX_NAME_LEN)
		uname_len = NTFS_MAX_NAME_LEN;
	find.attr.file_name_length = uname_len;
	for (i=0; i<uname_len; i++)
		if (uname[i] < vol->upcase_len)
			find.attr.file_name[i] = vol->upcase[uname[i]];
		else
			find.attr.file_name[i] = uname[i];
	olderrno = errno;
	lkup = ntfs_index_lookup(&find, uname_len, icx);
	if (errno == ENOENT)
		errno = olderrno;
	found = (FILE_NAME_ATTR*)icx->data;
		/*
		 * We generally only get the first matching candidate,
		 * so we still have to check whether this is a real match
		 */
	if (icx && icx->data && icx->data_len) {
		if (lkup
		   && !ntfs_names_collate(find.attr.file_name, find.attr.file_name_length,
			found->file_name, found->file_name_length,
			1, TRUE /* IGNORE_CASE_BOOL */,
			vol->upcase, vol->upcase_len))
				lkup = 0;
		if (!lkup) {
				/*
				 * name found :
				 *    fix original name and return inode
				 */
			lemref = *(le64*)((char*)found->file_name - sizeof(INDEX_ENTRY_HEADER) - sizeof(FILE_NAME_ATTR));
			mref = le64_to_cpu(lemref);
			for (i=0; i<found->file_name_length; i++)
				uname[i] = found->file_name[i];
		}
	}
	ntfs_index_ctx_put(icx);

	return (mref);
}

/*
 *		Search a directory junction along the target path
 *
 *	Returns the path translated to a Linux path
 *		or NULL if the path does not designate a valid directory
 */

static char *search_junction(ntfs_volume *vol, ntfschar *path, int count)
{
	ntfs_inode *ni;
	u64 inum;
	char *target;
	int start;
	int len;

	target = (char*)NULL; /* default return */
	ni = ntfs_inode_open(vol, FILE_root);
	if (ni) {
		start = 0;
		do {
			len = 0;
			while (((start + len) < count)
			    && path[len + start] != const_cpu_to_le16('\\'))
				len++;
			inum = ntfs_fix_file_name(ni, &path[start], len);
			ntfs_inode_close(ni);
			ni = (ntfs_inode*)NULL;
			if (inum != (u64)-1) {
				inum = MREF(inum);
				ni = ntfs_inode_open(vol, inum);
				start += len;
				if (start < count)
					path[start++] = const_cpu_to_le16('/');
			}
		} while (ni
		    && (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY)
		    && (start < count));
	if (ni && (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY))
		if (ntfs_ucstombs(path, count, &target, 0) < 0) {
			if (target) {
				free(target);
				target = (char*)NULL;
			}
		}
	if (ni)
		ntfs_inode_close(ni);
	}
	return (target);
}

/*
 *		Check whether a drive letter has been defined in .NTFS-3G
 *
 *	Returns 1 if found,
 *		0 if not found,
 *		-1 if there was an error (described by errno)
 */

static int ntfs_drive_letter(ntfs_volume *vol, ntfschar letter)
{
	char defines[NTFS_MAX_NAME_LEN + 5];
	char *drive;
	int ret;
	int sz;
	int olderrno;
	ntfs_inode *ni;

	ret = -1;
	drive = (char*)NULL;
	sz = ntfs_ucstombs(&letter, 1, &drive, 0);
	if (sz > 0) {
		strcpy(defines,mappingdir);
		if ((*drive >= 'a') && (*drive <= 'z'))
			*drive += 'A' - 'a';
		strcat(defines,drive);
		strcat(defines,":");
		olderrno = errno;
		ni = ntfs_pathname_to_inode(vol, NULL, defines);
		if (ni && !ntfs_inode_close(ni))
			ret = 1;
		else
			if (errno == ENOENT) {
				ret = 0;
					/* avoid errno pollution */
				errno = olderrno;
			}
	}
	if (drive)
		free(drive);
	return (ret);
}

/*
 *		Check and translate the target of a junction point
 *	If the target is a directory junction or a volume junction, it
 *	redefined as a relative link,
 *		- either to the target if found on the same device.
 *		- or into the /.NTFS-3G directory for the user to define
 *
 *	returns the target converted to a relative symlink
 *		or NULL if there were some problem described by errno
 */


static char *ntfs_get_junction(ntfs_volume *vol, ntfschar *junction,
			int count, const char *path)
{
	char *target;
	char *fulltarget;
	int i;
	int sz;
	int level;
	const char *p;
	char *q;
	enum { DIR_JUNCTION, VOL_JUNCTION, NO_JUNCTION } kind;

	target = (char*)NULL;
	fulltarget = (char*)NULL;
			/*
			 * For a valid directory junction we want \??\x:\
			 * where \ is an individual char and x a non-null char
			 */
	if ((count >= 7)
	    && !memcmp(junction,dir_junction_head,8)
	    && junction[4]
	    && (junction[5] == const_cpu_to_le16(':'))
	    && (junction[6] == const_cpu_to_le16('\\')))
		kind = DIR_JUNCTION;
	else
			/*
			 * For a valid volume junction we want \\?\Volume{
			 * and a final \ (where \ is an individual char)
			 */
		if ((count >= 12)
		    && !memcmp(junction,vol_junction_head,22)
		    && (junction[count-1] == const_cpu_to_le16('\\')))
			kind = VOL_JUNCTION;
		else
			kind = NO_JUNCTION;
			/*
			 * Directory junction with an explicit path and
			 * no specific definition for the drive letter :
			 * try to interpret as a target on the same volume
			 */
	if ((kind == DIR_JUNCTION)
	    && (count >= 7)
	    && junction[7]
	    && !ntfs_drive_letter(vol, junction[4])) {
		target = search_junction(vol,&junction[7],count - 7);
		if (target) {
			level = 0;
			for (p=path; *p; p++)
				if (*p == '/')
					level++;
			fulltarget = ntfs_malloc(3*level + strlen(target) + 1);
			if (fulltarget) {
				fulltarget[0] = 0;
				if (level > 1) {
					for (i=1; i<level; i++)
						strcat(fulltarget,"../");
				} else
					strcpy(fulltarget,"./");
				strcat(fulltarget,target);
			}
			free(target);
		}
	}
			/*
			 * Volume junctions or directory junctions with
			 * target not found on current volume :
			 * link to /.NTFS-3G/target which the user can
			 * define as a symbolic link to the real target
			 */
	if (((kind == DIR_JUNCTION) && !fulltarget)
	    || (kind == VOL_JUNCTION)) {
		sz = ntfs_ucstombs(&junction[4],
			(kind == VOL_JUNCTION ? count - 5 : count - 4),
			&target, 0);
		if ((sz > 0) && target) {
				/* reverse slashes */
			for (q=target; *q; q++)
				if (*q == '\\')
					*q = '/';
				/* force uppercase drive letter */
			if ((target[1] == ':')
			    && (target[0] >= 'a')
			    && (target[0] <= 'z'))
				target[0] += 'A' - 'a';
			level = 0;
			for (p=path; *p; p++)
				if (*p == '/')
					level++;
			fulltarget = ntfs_malloc(3*level + sizeof(mappingdir) + count - 4);
			if (fulltarget) {
				fulltarget[0] = 0;
				if (level > 1) {
					for (i=1; i<level; i++)
						strcat(fulltarget,"../");
				} else
					strcpy(fulltarget,"./");
				strcat(fulltarget,mappingdir);
				strcat(fulltarget,target);
			}
		}
		if (target)
			free(target);
	}
	return (fulltarget);
}

/*
 *		Get the target for a directory or volume junction
 *	Should only be called for directories with reparse data
 *
 *	returns the target directory converted to a relative path
 *		or NULL if some error occurred, as described by errno
 *		errno is EOPNOTSUPP if the reparse point is not a valid
 *			directory junction
 */

char *ntfs_junction_point(ntfs_volume *vol, const char *org_path,
			ntfs_inode *ni,	int *pattr_size)
{
	s64 attr_size = 0;
	char *target;
	unsigned int offs;
	unsigned int lth;
	REPARSE_POINT *reparse_attr;
	struct SYMLNK_REPARSE_DATA *path_data;
	BOOL bad;

	target = (char*)NULL;
	bad = TRUE;
	reparse_attr = (REPARSE_POINT*)ntfs_attr_readall(ni,
			AT_REPARSE_POINT,(ntfschar*)NULL, 0, &attr_size);
	if (reparse_attr && attr_size) {
			/*
			 * reparse_tag 0xa000000c has been found for
			 * \Users\All Users
			 * (not supported until properly understood)
			 */
		if (reparse_attr->reparse_tag == IO_REPARSE_TAG_MOUNT_POINT) {
			path_data = (struct SYMLNK_REPARSE_DATA*)reparse_attr->reparse_data;
			offs = le16_to_cpu(path_data->subst_name_offset);
			lth = le16_to_cpu(path_data->subst_name_length);
				/* consistency checks */
			if (((le16_to_cpu(reparse_attr->reparse_data_length)
				 + 8) == attr_size)
			    && ((int)((sizeof(REPARSE_POINT)
				 + sizeof(struct SYMLNK_REPARSE_DATA)
				 + offs + lth)) <= attr_size)) {
				target = ntfs_get_junction(vol,
					(ntfschar*)&path_data->path_buffer[offs],
					lth/2, org_path);
				if (target)
					bad = FALSE;
			}
		}
		free(reparse_attr);
	}
	*pattr_size = attr_size;
	if (bad)
		errno = EOPNOTSUPP;
	return (target);
}
