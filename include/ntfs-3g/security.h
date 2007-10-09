/*
 * security.h - Exports for handling security/ACLs in NTFS.  
 *              Originated from the Linux-NTFS project.
 *
 * Copyright (c) 2004      Anton Altaparmakov
 * Copyright (c) 2005-2006 Szabolcs Szakacsits
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

#ifndef _NTFS_SECURITY_H
#define _NTFS_SECURITY_H

#include "types.h"
#include "layout.h"
#include "inode.h"

/*
 *          item in the mapping list
 */

struct MAPPING {
	struct MAPPING *next;
	int xid;		/* linux id : uid or gid */
	SID *sid;		/* Windows id : usid or gsid */
};

/*
 *	Entry in the permissions cache
 */

struct CACHED_PERMISSIONS {
	uid_t uid;
	gid_t gid;
	unsigned int mode:9;
	unsigned int valid:1;
} ;

/*
 *	Entry in the securid cache
 */

struct CACHED_SECURID {
	struct CACHED_SECURID *next;
	uid_t uid;
	gid_t gid;
	unsigned int mode;
	le32 securid;
} ;

/*
 *	Header of the security cache
 */

struct SECURITY_HEAD {
	unsigned int first;
	unsigned int last;
	struct CACHED_SECURID *first_securid;
	struct CACHED_SECURID *most_recent_securid;
			/* statistics for permissions */
	unsigned long p_writes;
	unsigned long p_reads;
	unsigned long p_hits;
			/* statistics for securids */
	unsigned long s_writes;
	unsigned long s_reads;
	unsigned long s_hits;
	unsigned long s_hops;
} ;

/*
 *	The whole security cache
 */

struct SECURITY_CACHE {
	struct SECURITY_HEAD head;
	struct CACHED_PERMISSIONS cachetable[1]; /* array of variable size */
} ;

/*
 *	Security context, needed by most security functions
 */

struct SECURITY_CONTEXT {
	ntfs_volume *vol;
	struct MAPPING *usermapping;
	struct MAPPING *groupmapping;
	struct SECURITY_CACHE **pseccache;
	uid_t uid; /* uid of user requesting (not the mounter) */
	gid_t gid; /* gid of user requesting (not the mounter) */
	} ;

extern const GUID *const zero_guid;

extern BOOL ntfs_guid_is_zero(const GUID *guid);
extern char *ntfs_guid_to_mbs(const GUID *guid, char *guid_str);

/**
 * ntfs_sid_is_valid - determine if a SID is valid
 * @sid:	SID for which to determine if it is valid
 *
 * Determine if the SID pointed to by @sid is valid.
 *
 * Return TRUE if it is valid and FALSE otherwise.
 */
static __inline__ BOOL ntfs_sid_is_valid(const SID *sid)
{
	if (!sid || sid->revision != SID_REVISION ||
			sid->sub_authority_count > SID_MAX_SUB_AUTHORITIES)
		return FALSE;
	return TRUE;
}

extern int ntfs_sid_to_mbs_size(const SID *sid);
extern char *ntfs_sid_to_mbs(const SID *sid, char *sid_str,
		size_t sid_str_size);
extern void ntfs_generate_guid(GUID *guid);
extern int ntfs_sd_add_everyone(ntfs_inode *ni);

extern le32 ntfs_security_hash(const SECURITY_DESCRIPTOR_RELATIVE *sd, 
			       const u32 len);
INDEX_ENTRY *ntfs_index_next(INDEX_ENTRY *ie, ntfs_index_context *xc,
			BOOL forsii);


int ntfs_build_mapping(struct SECURITY_CONTEXT *scx);
int ntfs_get_owner_mode(struct SECURITY_CONTEXT *scx,
		const char *path, ntfs_inode *ni, struct stat*);
int ntfs_set_mode(struct SECURITY_CONTEXT *scx,
		const char *path, ntfs_inode *ni, mode_t mode);
BOOL ntfs_allowed_access(struct SECURITY_CONTEXT *scx, const char *path,
		ntfs_inode *ni, int accesstype);
BOOL ntfs_allowed_dir_access(struct SECURITY_CONTEXT *scx,
		const char *path, int accesstype);

int ntfs_set_owner(struct SECURITY_CONTEXT *scx,
		const char *path, ntfs_inode *ni, uid_t uid, gid_t gid);
int ntfs_set_owner_mode(struct SECURITY_CONTEXT *scx,
		ntfs_inode *ni,
		uid_t uid, gid_t gid, mode_t mode);
int ntfs_open_secure(ntfs_volume *vol);
void ntfs_close_secure(struct SECURITY_CONTEXT *scx);


#endif /* defined _NTFS_SECURITY_H */
