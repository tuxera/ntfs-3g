/**
 * security.c - Handling security/ACLs in NTFS.  Originated from the Linux-NTFS project.
 *
 * Copyright (c) 2004 Anton Altaparmakov
 * Copyright (c) 2005-2006 Szabolcs Szakacsits
 * Copyright (c) 2006 Yura Pakhuchiy
 * Copyright (c) 2007-2008 Jean-Pierre Andre
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

/*
 *	JPA configuration modes for this module
 *	should be moved to some config file
 */

#define FORCE_FORMAT_v1x 0	/* Insert security data as in NTFS v1.x */
#define OWNERFROMACL 1		/* Get the owner from ACL (not Windows owner) */
#define BUFSZ 1024		/* buffer size to read mapping file */
#define MAPPINGFILE ".NTFS-3G/UserMapping" /* default mapping file */
#define LINESZ 120              /* maximum useful size of a mapping line */
#define CACHE_PERMISSIONS_BITS 6  /* log2 of unitary allocation of permissions */
#define CACHE_PERMISSIONS_SIZE 262144 /* max cacheable permissions */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
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
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include "types.h"
#include "layout.h"
#include "attrib.h"
#include "index.h"
#include "dir.h"
#include "misc.h"
#include "bitmap.h"
#include "security.h"

/*
 *	JPA NTFS constants or structs
 *	should be moved to layout.h
 */

#define ALIGN_SDS_BLOCK 0x40000 /* Alignment for a $SDS block */
#define ALIGN_SDS_ENTRY 16 /* Alignment for a $SDS entry */
#define STUFFSZ 0x4000 /* unitary stuffing size for $SDS */
#define FIRST_SECURITY_ID 0x100 /* Lowest security id */

/*
 *	JPA The following must be in some library...
 *	but did not found out where
 */

#define endian_rev16(x) (((x >> 8) & 255) | ((x & 255) << 8))
#define endian_rev32(x) (((x >> 24) & 255) | ((x >> 8) & 0xff00) \
		| ((x & 0xff00) << 8) | ((x & 255) << 24))

#define cpu_to_be16(x) endian_rev16(cpu_to_le16(x))
#define cpu_to_be32(x) endian_rev32(cpu_to_le32(x))

/*
 *		Struct to hold the input mapping file
 *	(private to this module)
 */

struct MAPLIST {
	struct MAPLIST *next;
	char *uidstr;		/* uid text from the same record */
	char *gidstr;		/* gid text from the same record */
	char *sidstr;		/* sid text from the same record */
	char maptext[LINESZ + 1];
};

/*
 *		Matching of ntfs permissions to Linux permissions
 *	these constants are adapted to endianness
 *	when setting, set them all
 *	when checking, check one is present
 */

          /* flags which are set to mean exec, write or read */

#define FILE_READ (FILE_READ_DATA | SYNCHRONIZE)
#define FILE_WRITE (FILE_WRITE_DATA | FILE_APPEND_DATA \
		| READ_CONTROL | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA)
#define FILE_EXEC (FILE_EXECUTE)
#define DIR_READ FILE_LIST_DIRECTORY
#define DIR_WRITE (FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD \
	 	| READ_CONTROL | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA)
#define DIR_EXEC (FILE_TRAVERSE)

          /* flags tested for meaning exec, write or read */
	  /* tests for write allow for interpretation of a sticky bit */

#define FILE_GREAD (FILE_READ_DATA | GENERIC_READ)
#define FILE_GWRITE (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE)
#define FILE_GEXEC (FILE_EXECUTE | GENERIC_EXECUTE)
#define DIR_GREAD (FILE_LIST_DIRECTORY | GENERIC_READ)
#define DIR_GWRITE (FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | GENERIC_WRITE)
#define DIR_GEXEC (FILE_TRAVERSE | GENERIC_EXECUTE)

	/* standard owner (and administrator) rights */

#define OWNER_RIGHTS (DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER \
			| SYNCHRONIZE \
			| FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES \
			| FILE_READ_EA | FILE_WRITE_EA)

	/* standard world rights */

#define WORLD_RIGHTS (READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_EA \
			| SYNCHRONIZE)

          /* inheritance flags for files and directories */

#define FILE_INHERITANCE NO_PROPAGATE_INHERIT_ACE
#define DIR_INHERITANCE (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)

struct SII {		/* this is an image of an $SII index entry */
	le16 offs;
	le16 size;
	le32 fill1;
	le16 indexsz;
	le16 indexksz;
	le16 flags;
	le16 fill2;
	le32 keysecurid;

	/* did not find official description for the following */
	le32 hash;
	le32 securid;
	le32 dataoffsl;	/* documented as badly aligned */
	le32 dataoffsh;
	le32 datasize;
} ;

struct SDH {		/* this is an image of an $SDH index entry */
	le16 offs;
	le16 size;
	le32 fill1;
	le16 indexsz;
	le16 indexksz;
	le16 flags;
	le16 fill2;
	le32 keyhash;
	le32 keysecurid;

	/* did not find official description for the following */
	le32 hash;
	le32 securid;
	le32 dataoffsl;
	le32 dataoffsh;
	le32 datasize;
	le32 fill3;
	} ;

/*
 *	A type large enough to hold any SID
 */

typedef char BIGSID[40];

/*
 *	A few useful constants
 */

static ntfschar sii_stream[] = { '$', 'S', 'I', 'I', 0 };
static ntfschar sdh_stream[] = { '$', 'S', 'D', 'H', 0 };

/*
 * The zero GUID.
 */
static const GUID __zero_guid = { const_cpu_to_le32(0), const_cpu_to_le16(0),
		const_cpu_to_le16(0), { 0, 0, 0, 0, 0, 0, 0, 0 } };
const GUID *const zero_guid = &__zero_guid;

/*
 *		null SID (S-1-0-0)
 */

static const char nullsidbytes[] = {
		1,		/* revision */
		1,		/* auth count */
		0, 0, 0, 0, 0, 0,	/* base */
		0, 0, 0, 0 	/* 1st level */
	};

static const SID *nullsid = (const SID*)nullsidbytes;

/*
 *		SID for world  (S-1-1-0)
 */

static const char worldsidbytes[] = {
		1,		/* revision */
		1,		/* auth count */
		0, 0, 0, 0, 0, 1,	/* base */
		0, 0, 0, 0	/* 1st level */
} ;

static const SID *worldsid = (const SID*)worldsidbytes;

/*
 *		SID for administrator
 */

static const char adminsidbytes[] = {
		1,		/* revision */
		2,		/* auth count */
		0, 0, 0, 0, 0, 5,	/* base */
		32, 0, 0, 0,	/* 1st level */
		32, 2, 0, 0	/* 2nd level */
};

static const SID *adminsid = (const SID*)adminsidbytes;

/*
 *		SID for system
 */

static const char systemsidbytes[] = {
		1,		/* revision */
		1,		/* auth count */
		0, 0, 0, 0, 0, 5,	/* base */
		18, 0, 0, 0 	/* 1st level */
	};

static const SID *systemsid = (const SID*)systemsidbytes;

/*
 *		SID for generic creator-owner
 *		S-1-3-0
 */

static const char ownersidbytes[] = {
		1,		/* revision */
		1,		/* auth count */
		0, 0, 0, 0, 0, 3,	/* base */
		0, 0, 0, 0	/* 1st level */
} ;

static const SID *ownersid = (const SID*)ownersidbytes;

/*
 *		SID for generic creator-group
 *		S-1-3-1
 */

static const char groupsidbytes[] = {
		1,		/* revision */
		1,		/* auth count */
		0, 0, 0, 0, 0, 3,	/* base */
		1, 0, 0, 0	/* 1st level */
} ;

static const SID *groupsid = (const SID*)groupsidbytes;

/*
 *		Determine the size of a SID
 */

static int sid_size(const SID * sid)
{
	return (sid->sub_authority_count * 4 + 8);
}

/*
 *		Test whether two SID are equal
 */

static BOOL same_sid(const SID *first, const SID *second)
{
	int size;

	size = sid_size(first);
	return ((sid_size(second) == size)
		&& !memcmp(first, second, size));
}

/*
 *		Test whether a SID means "world user"
 *	Local users group also recognized as world
 */

static int is_world_sid(const SID * usid)
{
	return (
	     /* check whether S-1-1-0 : world */
	       ((usid->sub_authority_count == 1)
	    && (usid->identifier_authority.high_part ==  cpu_to_be16(0))
	    && (usid->identifier_authority.low_part ==  cpu_to_be32(1))
	    && (usid->sub_authority[0] == 0))

	     /* check whether S-1-5-32-545 : local user */
	  ||   ((usid->sub_authority_count == 2)
	    && (usid->identifier_authority.high_part ==  cpu_to_be16(0))
	    && (usid->identifier_authority.low_part ==  cpu_to_be32(5))
	    && (usid->sub_authority[0] == cpu_to_le32(32))
	    && (usid->sub_authority[1] == cpu_to_le32(545)))
		);
}

/*
 *		Test whether a SID means "some user (or group)"
 *	Currently we only check for S-1-5-21... but we should
 *	probably test for other configurations
 */

static int is_user_sid(const SID *usid)
{
	return ((usid->sub_authority_count == 5)
	    && (usid->identifier_authority.high_part ==  cpu_to_be16(0))
	    && (usid->identifier_authority.low_part ==  cpu_to_be32(5))
	    && (usid->sub_authority[0] ==  cpu_to_le32(21)));
}

/*
 *		Determine the size of a security attribute
 *	whatever the order of fields
 */

static unsigned int attr_size(const char *attr)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const ACL *pdacl;
	const ACL *psacl;
	const SID *psid;
	unsigned int offdacl;
	unsigned int offsacl;
	unsigned int offowner;
	unsigned int offgroup;
	unsigned int endsid;
	unsigned int endsacl;
	unsigned int attrsz;

		/*
		 * First check DACL, which is the last field in all descriptors
		 * we build, and in most descriptors built by Windows
		 * however missing for "DR Watson"
		 */
	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)attr;
		/* find end of DACL */
	offdacl = le32_to_cpu(phead->dacl);
	if (offdacl) {
		pdacl = (const ACL*)&attr[offdacl];
		attrsz = offdacl + le16_to_cpu(pdacl->size);
	} else
		attrsz = 0;

	offowner = le32_to_cpu(phead->owner);
	if (offowner >= attrsz) {
			/* find end of USID */
		psid = (const SID*)&attr[offowner];
		endsid = offowner + sid_size(psid);
		attrsz = endsid;
	}
	offgroup = le32_to_cpu(phead->group);
	if (offgroup >= attrsz) {
			/* find end of GSID */
		psid = (const SID*)&attr[offgroup];
		endsid = offgroup + sid_size(psid);
		if (endsid > attrsz) attrsz = endsid;
	}
	offsacl = le32_to_cpu(phead->sacl);
	if (offsacl >= attrsz) {
			/* find end of SACL */
		offsacl = le32_to_cpu(phead->sacl);
		psacl = (const ACL*)&attr[offsacl];
		endsacl = offsacl + le16_to_cpu(psacl->size);
		if (endsacl > attrsz)
			attrsz = endsacl;
	}

	return (attrsz);
}

/*
 *		Do sanity checks on a SID read from storage
 *	(just check revision and number of authorities)
 */

static BOOL valid_sid(const SID *sid)
{
	return ((sid->revision == SID_REVISION)
		&& (sid->sub_authority_count >= 1)
		&& (sid->sub_authority_count <= 8));
}

/*
 *		Check whether a SID is acceptable for an implicit
 *	mapping pattern.
 *	It should have been already checked it is a valid user SID.
 *
 *	The last authority reference has to be >= 1000 (Windows usage)
 *	and <= 0x7fffffff, so that 30 bits from a uid and 30 more bits
 *      from a gid an be inserted with no overflow.
 */

static BOOL valid_pattern(const SID *sid)
{
	int cnt;
	u32 auth;

	cnt = sid->sub_authority_count;
	auth = le32_to_cpu(sid->sub_authority[cnt-1]);
	return ((auth >= 1000) && (auth <= 0x7fffffff));
}


/*
 *		Do sanity checks on security descriptors read from storage
 *	basically, we make sure that every field holds within
 *	allocated storage
 *	Should not be called with a NULL argument
 *	returns TRUE if considered safe
 *		if not, error should be logged by caller
 */

static BOOL valid_securattr(const char *securattr, unsigned int attrsz)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const ACL *pacl;
	const ACCESS_ALLOWED_ACE *pace;
	unsigned int offdacl;
	unsigned int offace;
	unsigned int acecnt;
	unsigned int acesz;
	unsigned int nace;
	BOOL ok;

	ok = TRUE;

	/*
	 * first check overall size if within allocation range
	 * and a DACL is present
	 * and owner and group SID are valid
	 */

	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)securattr;
	offdacl = le32_to_cpu(phead->dacl);
	pacl = (const ACL*)&securattr[offdacl];

		/*
		 * size check occurs before the above pointers are used
		 *
		 * "DR Watson" standard directory on WinXP has an
		 * old revision and no DACL though SE_DACL_PRESENT is set
		 */
	if ((attrsz >= sizeof(SECURITY_DESCRIPTOR_RELATIVE))
		&& (attr_size(securattr) <= attrsz)
		&& (phead->revision == SECURITY_DESCRIPTOR_REVISION)
		&& phead->owner
		&& phead->group
		&& !(phead->owner & cpu_to_le32(3))
		&& !(phead->group & cpu_to_le32(3))
		&& !(phead->dacl & cpu_to_le32(3))
		&& !(phead->sacl & cpu_to_le32(3))
		&& valid_sid((const SID*)&securattr[le32_to_cpu(phead->owner)])
		&& valid_sid((const SID*)&securattr[le32_to_cpu(phead->group)])
			/*
			 * if there is an ACL, as indicated by offdacl,
			 * require SE_DACL_PRESENT
			 * but "Dr Watson" has SE_DACL_PRESENT though no DACL
			 */
		&& (!offdacl
                    || ((pacl->revision == ACL_REVISION)
		       && (phead->control & SE_DACL_PRESENT)))) {

		/*
		 * For each ACE, check it is within limits
		 * and contains a valid SID
		 * "DR Watson" has no DACL
		 */

		if (offdacl) {
			acecnt = le16_to_cpu(pacl->ace_count);
			offace = offdacl + sizeof(ACL);
			for (nace = 0; (nace < acecnt) && ok; nace++) {
				/* be sure the beginning is within range */
				if ((offace + sizeof(ACCESS_ALLOWED_ACE)) > attrsz)
					ok = FALSE;
				else {
					pace = (const ACCESS_ALLOWED_ACE*)
						&securattr[offace];
					acesz = le16_to_cpu(pace->size);
					if (((offace + acesz) > attrsz)
					   || !valid_sid(&pace->sid))
						 ok = FALSE;
					offace += acesz;
				}
			}
		}
	} else
		ok = FALSE;
	return (ok);
}

#if POSIXACLS

/*
 *		Do sanity checks on a Posix descriptor
 *	Should not be called with a NULL argument
 *	returns TRUE if considered safe
 *		if not, error should be logged by caller
 */

static BOOL valid_posix(const struct POSIX_SECURITY *pxdesc)
{
	const struct POSIX_ACL *pacl;
	int i;
	BOOL ok;
	u16 tag;
	u32 id;
	int perms;
	struct {
		u16 previous;
		u32 previousid;
		u16 tagsset;
		mode_t mode;
		int owners;
		int groups;
		int others;
	} checks[2], *pchk;

	for (i=0; i<2; i++) {
		checks[i].mode = 0;
		checks[i].tagsset = 0;
		checks[i].owners = 0;
		checks[i].groups = 0;
		checks[i].others = 0;
		checks[i].previous = 0;
		checks[i].previousid = 0;
	}
	ok = TRUE;
	pacl = &pxdesc->acl;
			/*
			 * header (strict for now)
			 */
	if ((pacl->version != POSIX_VERSION)
	    || (pacl->flags != 0)
	    || (pacl->filler != 0))
		ok = FALSE;
			/*
			 * Reject multiple owner, group or other
			 * but do not require them to be present
			 * Also check the ACEs are in correct order
			 * which implies there is no duplicates
			 */
	for (i=0; i<pxdesc->acccnt + pxdesc->defcnt; i++) {
		if (i >= pxdesc->firstdef)
			pchk = &checks[1];
		else
			pchk = &checks[0];
		perms = pacl->ace[i].perms;
		tag = pacl->ace[i].tag;
		pchk->tagsset |= tag;
		id = pacl->ace[i].id;
		if (perms & ~7) ok = FALSE;
		if ((tag < pchk->previous)
			|| ((tag == pchk->previous)
			 && (id <= pchk->previousid)))
				ok = FALSE;
		pchk->previous = tag;
		pchk->previousid = id;
		switch (tag) {
		case POSIX_ACL_USER_OBJ :
			if (pchk->owners++)
				ok = FALSE;
			if (id != (u32)-1)
				ok = FALSE;
			pchk->mode |= perms << 6;
			break;
		case POSIX_ACL_GROUP_OBJ :
			if (pchk->groups++)
				ok = FALSE;
			if (id != (u32)-1)
				ok = FALSE;
			pchk->mode = (pchk->mode & 07707) | (perms << 3);
			break;
		case POSIX_ACL_OTHER :
			if (pchk->others++)
				ok = FALSE;
			if (id != (u32)-1)
				ok = FALSE;
			pchk->mode |= perms;
			break;
		case POSIX_ACL_USER :
		case POSIX_ACL_GROUP :
				/* cannot accept root as designated user/grp */
			if ((id == (u32)-1) || (id == (u32)0))
				ok = FALSE;
			break;
		case POSIX_ACL_MASK :
			if (id != (u32)-1)
				ok = FALSE;
			pchk->mode = (pchk->mode & 07707) | (perms << 3);
			break;
		default :
			ok = FALSE;
			break;
		}
	}
	if ((pxdesc->acccnt > 0)
	   && ((checks[0].owners != 1) || (checks[0].groups != 1) 
		|| (checks[0].others != 1)))
		ok = FALSE;
		/* do not check owner, group or other are present in */
		/* the default ACL, Windows does not necessarily set them */
			/* descriptor */
	if (pxdesc->defcnt && (pxdesc->acccnt > pxdesc->firstdef))
		ok = FALSE;
	if ((pxdesc->acccnt < 0) || (pxdesc->defcnt < 0))
		ok = FALSE;
			/* check mode, unless null or no tag set */
	if (pxdesc->mode
	    && checks[0].tagsset
	    && (checks[0].mode != (pxdesc->mode & 0777)))
		ok = FALSE;
			/* check tagsset */
	if (pxdesc->tagsset != checks[0].tagsset)
		ok = FALSE;
	return (ok);
}

static BOOL valid_posix_chk(const struct POSIX_SECURITY *pxdesc, const char *file, int line)
{
	BOOL ok;

	ok = valid_posix(pxdesc);
	if (!ok) {
		ntfs_log_error("Bad Posix ACL in %s line %d\n",file,line);
	}
	return (ok);
}

#define valid_posix(p) valid_posix_chk((p),__FILE__,__LINE__)

/*
 *		Set standard header data into a Posix ACL
 *	The mode argument should provide the 3 upper bits of target mode
 */

static mode_t posix_header(struct POSIX_SECURITY *pxdesc, mode_t basemode)
{
	mode_t mode;
	u16 tagsset;
	struct POSIX_ACE *pace;
	int i;

	mode = basemode & 07000;
	tagsset = 0;
	for (i=0; i<pxdesc->acccnt; i++) {
		pace = &pxdesc->acl.ace[i];
		tagsset |= pace->tag;
		switch(pace->tag) {
		case POSIX_ACL_USER_OBJ :
			mode |= (pace->perms & 7) << 6;
			break;
		case POSIX_ACL_GROUP_OBJ :
		case POSIX_ACL_MASK :
			mode = (mode & 07707) | ((pace->perms & 7) << 3);
			break;
		case POSIX_ACL_OTHER :
			mode |= pace->perms & 7;
			break;
		default :
			break;
		}
	}
	pxdesc->tagsset = tagsset;
	pxdesc->mode = mode;
	pxdesc->acl.version = POSIX_VERSION;
	pxdesc->acl.flags = 0;
	pxdesc->acl.filler = 0;
	return (mode);
}

/*
 *		Sort ACEs in a Posix ACL
 *	This is useful for always getting reusable converted ACLs,
 *	it also helps in merging ACEs.
 *	Repeated tag+id are allowed and not merged here.
 *
 *	Tags should be in ascending sequence and for a repeatable tag
 *	ids should be in ascending sequence.
 */

static void sort_posix(struct POSIX_SECURITY *pxdesc)
{
	struct POSIX_ACL *pacl;
	struct POSIX_ACE ace;
	int i;
	int offs;
	BOOL done;
	u16 tag;
	u16 previous;
	u32 id;
	u32 previousid;


			/*
			 * Check sequencing of tag+id in access ACE's
			 */
	pacl = &pxdesc->acl;
	do {
		done = TRUE;
		previous = pacl->ace[0].tag;
		previousid = pacl->ace[0].id;
		for (i=1; i<pxdesc->acccnt; i++) {
			tag = pacl->ace[i].tag;
			id = pacl->ace[i].id;

			if ((tag < previous)
			   || ((tag == previous) && (id < previousid))) {
				done = FALSE;
				memcpy(&ace,&pacl->ace[i-1],sizeof(struct POSIX_ACE));
				memcpy(&pacl->ace[i-1],&pacl->ace[i],sizeof(struct POSIX_ACE));
				memcpy(&pacl->ace[i],&ace,sizeof(struct POSIX_ACE));
			} else {
				previous = tag;
				previousid = id;
			}
		}
	} while (!done);
				/*
				 * Same for default ACEs
				 */
	do {
		done = TRUE;
		offs = pxdesc->firstdef;
		previous = pacl->ace[offs].tag;
		previousid = pacl->ace[offs].id;
		for (i=offs+1; i<offs+pxdesc->defcnt; i++) {
			tag = pacl->ace[i].tag;
			id = pacl->ace[i].id;

			if ((tag < previous)
			   || ((tag == previous) && (id < previousid))) {
				done = FALSE;
				memcpy(&ace,&pacl->ace[i-1],sizeof(struct POSIX_ACE));
				memcpy(&pacl->ace[i-1],&pacl->ace[i],sizeof(struct POSIX_ACE));
				memcpy(&pacl->ace[i],&ace,sizeof(struct POSIX_ACE));
			} else {
				previous = tag;
				previousid = id;
			}
		}
	} while (!done);
}

/*
 *		Merge a new mode into a Posix descriptor
 *	The Posix descriptor is not reallocated, its size is unchanged
 *
 *	returns 0 if ok
 */

static int merge_mode_posix(struct POSIX_SECURITY *pxdesc, mode_t mode)
{
	int i;
	BOOL maskfound;
	struct POSIX_ACE *pace;
	int todo;

	maskfound = FALSE;
	todo = POSIX_ACL_USER_OBJ | POSIX_ACL_GROUP_OBJ | POSIX_ACL_OTHER;
	for (i=pxdesc->acccnt-1; i>=0; i--) {
		pace = &pxdesc->acl.ace[i];
		switch(pace->tag) {
		case POSIX_ACL_USER_OBJ :
			pace->perms = (mode >> 6) & 7;
			todo &= ~POSIX_ACL_USER_OBJ;
			break;
		case POSIX_ACL_GROUP_OBJ :
			if (!maskfound)
				pace->perms = (mode >> 3) & 7;
			todo &= ~POSIX_ACL_GROUP_OBJ;
			break;
		case POSIX_ACL_MASK :
			pace->perms = (mode >> 3) & 7;
			maskfound = TRUE;
			break;
		case POSIX_ACL_OTHER :
			pace->perms = mode & 7;
			todo &= ~POSIX_ACL_OTHER;
			break;
		default :
			break;
		}
	}
	pxdesc->mode = mode;
	return (todo ? -1 : 0);
}

/*
 *		Merge new owner and group into a Posix descriptor
 *	The Posix descriptor is reallocated, it has to be freed
 *
 *	returns NULL if there is a problem
 */

static struct POSIX_SECURITY *merge_owner_posix(const struct POSIX_SECURITY *pxdesc,
		uid_t uid, gid_t gid, uid_t olduid, gid_t oldgid)
{
	struct POSIX_SECURITY *newpxdesc;
	const struct POSIX_ACE *oldace;
	struct POSIX_ACE *newace;
	BOOL uidpresent;
	BOOL gidpresent;
	BOOL maskpresent;
	mode_t ownerperms;
	mode_t groupperms;
	mode_t mode;
	BOOL ignore;
	u16 tagsset;
	int count;
	size_t size;
	int i;
	int k,l;

	/*
	 * Check whether the new owner and group were
	 * already designated in the ACL, and there is a mask
	 * Also get permissions of previous owner and group
	 */
	ownerperms = 0;
	groupperms = 0;
	uidpresent = FALSE;
	gidpresent = FALSE;
	maskpresent = FALSE;
	for (i=0; i<pxdesc->acccnt; i++) {
		oldace = &pxdesc->acl.ace[i];
		switch (oldace->tag) {
		case POSIX_ACL_USER_OBJ :
			ownerperms = oldace->perms;
			break;
		case POSIX_ACL_GROUP_OBJ :
			groupperms = oldace->perms;
			break;
		case POSIX_ACL_USER :
			if ((uid != (uid_t)-1)
			   && ((uid_t)oldace->id == uid))
				uidpresent = TRUE;
			break;
		case POSIX_ACL_GROUP :
			if ((gid != (gid_t)-1)
			   && ((gid_t)oldace->id == gid))
				gidpresent = TRUE;
			break;
		case POSIX_ACL_MASK :
			maskpresent = TRUE;
		default :
			break;
		}
	}
	count = pxdesc->acccnt + pxdesc->defcnt;
	if (!uidpresent)
		count++;
	if (!gidpresent)
		count++;
	if (!maskpresent)
		count++;
	size = sizeof(struct POSIX_SECURITY) + count*sizeof(struct POSIX_ACE);
	newpxdesc = (struct POSIX_SECURITY*)malloc(size);
	if (newpxdesc) {
		k = 0;
		mode = pxdesc->mode & 07000;
		tagsset = 0;
		if (!uidpresent) {
			newace = newpxdesc->acl.ace;
			newace->tag = POSIX_ACL_USER_OBJ;
			newace->id = -1;
			newace->perms = ownerperms;
			mode |= (ownerperms << 6);
			k++;
		}
		if (!gidpresent) {
			newace = &newpxdesc->acl.ace[k];
			newace->tag = POSIX_ACL_GROUP_OBJ;
			newace->id = -1;
			newace->perms = groupperms;
			mode |= (groupperms << 3);
			k++;
		}
		for (i=0; i<pxdesc->acccnt; i++) {
			oldace = &pxdesc->acl.ace[i];
			newace = &newpxdesc->acl.ace[k];
			ignore = FALSE;
			switch (oldace->tag) {
			case POSIX_ACL_USER_OBJ :
				if (olduid) {
					newace->tag = POSIX_ACL_USER;
					newace->id = olduid;
				} else
					ignore = TRUE;
				break;
			case POSIX_ACL_USER :
				if ((uid_t)oldace->id == uid) {
					newace->tag = POSIX_ACL_USER_OBJ;
					newace->id = -1;
					mode |= (oldace->perms << 6);
				} else {
					newace->tag = oldace->tag;
					newace->id = oldace->id;
				}
				break;
			case POSIX_ACL_GROUP_OBJ :
				if (oldgid) {
					newace->tag = POSIX_ACL_GROUP;
					newace->id = oldgid;
				} else
					ignore = TRUE;
				break;
			case POSIX_ACL_GROUP :
				if ((uid_t)oldace->id == gid) {
					newace->tag = POSIX_ACL_GROUP_OBJ;
					newace->id = -1;
					mode |= (oldace->perms << 3);
				} else {
					newace->tag = oldace->tag;
					newace->id = oldace->id;
				}
				break;
			case POSIX_ACL_OTHER :
				mode |= oldace->perms;
				/* fall through */
			default :
				newace->tag = oldace->tag;
				newace->id = oldace->id;
			}
			if (!ignore) {
				newace->perms = oldace->perms;
				tagsset |= newace->tag;
				k++;
			}
		}
			/*
			 * If there were no mask, and we have created
			 * a designated user or group, we need a mask
			 * similar to group, so that the group righs
			 * appear unchanged
			 */
		if (!maskpresent
		    && (olduid || oldgid)) {
			newace = &newpxdesc->acl.ace[k];
			newace->tag = POSIX_ACL_MASK;
			newace->perms = groupperms;
			newace->id = -1;
			tagsset |= POSIX_ACL_MASK;
			k++;
		}
/* default ACE left unchanged */
		l = 0;
		for (i=0; i<pxdesc->defcnt; i++) {
			oldace = &pxdesc->acl.ace[i + pxdesc->firstdef];
			newace = &newpxdesc->acl.ace[l + k];
			newace->tag = oldace->tag;
			newace->id = oldace->id;
			newace->perms = oldace->perms;
			l++;
		}
			/* now set headers */
		newpxdesc->acccnt = k;
		newpxdesc->firstdef = k;
		newpxdesc->defcnt = l;
		newpxdesc->mode = mode;
		newpxdesc->tagsset = tagsset;
		newpxdesc->acl.version = POSIX_VERSION;
		newpxdesc->acl.flags = 0;
		newpxdesc->acl.filler = 0;
			/* and finally sort */
		sort_posix(newpxdesc);
	} else
		errno = ENOMEM;
	return (newpxdesc);
}

#endif

#if POSIXACLS

/*
 *		Replace an access or default Posix ACL
 *	The resulting ACL is checked for validity
 *
 *	Returns a new ACL or NULL if there is a problem
 */

static struct POSIX_SECURITY *replace_acl(const struct POSIX_SECURITY *oldpxdesc,
		const struct POSIX_ACL *newacl, int count, BOOL deflt)
{
	struct POSIX_SECURITY *newpxdesc;
	size_t newsize;
	int offset;
	int oldoffset;
	int i;

	if (deflt)
		newsize = sizeof(struct POSIX_SECURITY)
			+ (oldpxdesc->acccnt + count)*sizeof(struct POSIX_ACE);
	else
		newsize = sizeof(struct POSIX_SECURITY)
			+ (oldpxdesc->defcnt + count)*sizeof(struct POSIX_ACE);
	newpxdesc = (struct POSIX_SECURITY*)malloc(newsize);
	if (newpxdesc) {
		if (deflt) {
			offset = oldpxdesc->acccnt;
			newpxdesc->acccnt = oldpxdesc->acccnt;
			newpxdesc->defcnt = count;
			newpxdesc->firstdef = offset;
					/* copy access ACEs */
			for (i=0; i<newpxdesc->acccnt; i++)
				newpxdesc->acl.ace[i] = oldpxdesc->acl.ace[i];
					/* copy default ACEs */
			for (i=0; i<count; i++)
				newpxdesc->acl.ace[i + offset] = newacl->ace[i];
		} else {
			offset = count;
			newpxdesc->acccnt = count;
			newpxdesc->defcnt = oldpxdesc->defcnt;
			newpxdesc->firstdef = count;
					/* copy access ACEs */
			for (i=0; i<count; i++)
				newpxdesc->acl.ace[i] = newacl->ace[i];
					/* copy default ACEs */
			oldoffset = oldpxdesc->firstdef;
			for (i=0; i<newpxdesc->defcnt; i++)
				newpxdesc->acl.ace[i + offset] = oldpxdesc->acl.ace[i + oldoffset];
		}
			/* assume special flags unchanged */
		posix_header(newpxdesc, oldpxdesc->mode);
		if (!valid_posix(newpxdesc)) {
			free(newpxdesc);
			newpxdesc = (struct POSIX_SECURITY*)NULL;
			errno = EINVAL;
		}
	} else
		errno = ENOMEM;
	return (newpxdesc);
}

/*
 *		Build an inherited Posix descriptor from parent
 *	descriptor (if any) restricted to creation mode
 *
 *	Returns the inherited descriptor or NULL if there is a problem
 */

static struct POSIX_SECURITY *build_inherited_posix(
		const struct POSIX_SECURITY *pxdesc, mode_t mode, BOOL isdir)
{
	struct POSIX_SECURITY *pydesc;
	struct POSIX_ACE *pyace;
	int count;
	int defcnt;
	int size;
	int i;
	s16 tagsset;

	if (pxdesc && pxdesc->defcnt) {
		if (isdir)
			count = 2*pxdesc->defcnt + 3;
		else
			count = pxdesc->defcnt + 3;
	} else
		count = 3;
	pydesc = (struct POSIX_SECURITY*)malloc(
		sizeof(struct POSIX_SECURITY) + count*sizeof(struct POSIX_ACE));
	if (pydesc) {
			/*
			 * Copy inherited tags and adapt perms
			 */
		tagsset = 0;
		defcnt = (pxdesc ? pxdesc->defcnt : 0);
		for (i=defcnt-1; i>=0; i--) {
			pyace = &pydesc->acl.ace[i];
			*pyace = pxdesc->acl.ace[pxdesc->firstdef + i];
			switch (pyace->tag) {
			case POSIX_ACL_USER_OBJ :
				pyace->perms &= (mode >> 6) & 7;
				break;
			case POSIX_ACL_GROUP_OBJ :
				if (!(tagsset & POSIX_ACL_MASK))
					pyace->perms &= (mode >> 3) & 7;
				break;
			case POSIX_ACL_OTHER :
				pyace->perms &= mode & 7;
				break;
			case POSIX_ACL_MASK :
				pyace->perms &= (mode >> 3) & 7;
				break;
			default :
				break;
			}
			tagsset |= pyace->tag;
		}
		pydesc->acccnt = defcnt;
		/*
		 * If some standard tags were missing, append them from mode
		 * and sort the list
		 */
		if (~tagsset & (POSIX_ACL_USER_OBJ
				 | POSIX_ACL_GROUP_OBJ | POSIX_ACL_OTHER)) {
			i = defcnt;
				/* owner was missing */
			if (!(tagsset & POSIX_ACL_USER_OBJ)) {
				pyace = &pydesc->acl.ace[i];
				pyace->tag = POSIX_ACL_USER_OBJ;
				pyace->id = -1;
				pyace->perms = (mode >> 6) & 7;
				tagsset |= POSIX_ACL_USER_OBJ;
				i++;
			}
				/* owning group was missing */
			if (!(tagsset & POSIX_ACL_GROUP_OBJ)) {
				pyace = &pydesc->acl.ace[i];
				pyace->tag = POSIX_ACL_GROUP_OBJ;
				pyace->id = -1;
				pyace->perms = (mode >> 3) & 7;
				tagsset |= POSIX_ACL_GROUP_OBJ;
				i++;
			}
				/* other was missing */
			if (!(tagsset & POSIX_ACL_OTHER)) {
				pyace = &pydesc->acl.ace[i];
				pyace->tag = POSIX_ACL_OTHER;
				pyace->id = -1;
				pyace->perms = mode & 7;
				tagsset |= POSIX_ACL_OTHER;
				i++;
			}
			pydesc->acccnt = i;
			pydesc->firstdef = i;
			pydesc->defcnt = 0;
			sort_posix(pydesc);
		}

		/*
		 * append as a default ACL if a directory
		 */
		pydesc->firstdef = pydesc->acccnt;
		if (defcnt && isdir) {
			size = sizeof(struct POSIX_ACE)*defcnt;
			memcpy(&pydesc->acl.ace[pydesc->firstdef],
				 &pxdesc->acl.ace[pxdesc->firstdef],size);
			pydesc->defcnt = defcnt;
		} else {
			pydesc->defcnt = 0;
		}
			/* assume special bits are not inherited */
		posix_header(pydesc, mode & 07000);
		if (!valid_posix(pydesc)) {
			ntfs_log_error("Error building an inherited Posix desc\n");
			errno = EIO;
			free(pydesc);
			pydesc = (struct POSIX_SECURITY*)NULL;
		}
	} else
		errno = ENOMEM;
	return (pydesc);
}

#endif

/**
 * ntfs_guid_is_zero - check if a GUID is zero
 * @guid:	[IN] guid to check
 *
 * Return TRUE if @guid is a valid pointer to a GUID and it is the zero GUID
 * and FALSE otherwise.
 */
BOOL ntfs_guid_is_zero(const GUID *guid)
{
	return (memcmp(guid, zero_guid, sizeof(*zero_guid)));
}

/**
 * ntfs_guid_to_mbs - convert a GUID to a multi byte string
 * @guid:	[IN]  guid to convert
 * @guid_str:	[OUT] string in which to return the GUID (optional)
 *
 * Convert the GUID pointed to by @guid to a multi byte string of the form
 * "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX".  Therefore, @guid_str (if not NULL)
 * needs to be able to store at least 37 bytes.
 *
 * If @guid_str is not NULL it will contain the converted GUID on return.  If
 * it is NULL a string will be allocated and this will be returned.  The caller
 * is responsible for free()ing the string in that case.
 *
 * On success return the converted string and on failure return NULL with errno
 * set to the error code.
 */
char *ntfs_guid_to_mbs(const GUID *guid, char *guid_str)
{
	char *_guid_str;
	int res;

	if (!guid) {
		errno = EINVAL;
		return NULL;
	}
	_guid_str = guid_str;
	if (!_guid_str) {
		_guid_str = ntfs_malloc(37);
		if (!_guid_str)
			return _guid_str;
	}
	res = snprintf(_guid_str, 37,
			"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			(unsigned int)le32_to_cpu(guid->data1),
			le16_to_cpu(guid->data2), le16_to_cpu(guid->data3),
			guid->data4[0], guid->data4[1],
			guid->data4[2], guid->data4[3], guid->data4[4],
			guid->data4[5], guid->data4[6], guid->data4[7]);
	if (res == 36)
		return _guid_str;
	if (!guid_str)
		free(_guid_str);
	errno = EINVAL;
	return NULL;
}

/**
 * ntfs_sid_to_mbs_size - determine maximum size for the string of a SID
 * @sid:	[IN]  SID for which to determine the maximum string size
 *
 * Determine the maximum multi byte string size in bytes which is needed to
 * store the standard textual representation of the SID pointed to by @sid.
 * See ntfs_sid_to_mbs(), below.
 *
 * On success return the maximum number of bytes needed to store the multi byte
 * string and on failure return -1 with errno set to the error code.
 */
int ntfs_sid_to_mbs_size(const SID *sid)
{
	int size, i;

	if (!ntfs_sid_is_valid(sid)) {
		errno = EINVAL;
		return -1;
	}
	/* Start with "S-". */
	size = 2;
	/*
	 * Add the SID_REVISION.  Hopefully the compiler will optimize this
	 * away as SID_REVISION is a constant.
	 */
	for (i = SID_REVISION; i > 0; i /= 10)
		size++;
	/* Add the "-". */
	size++;
	/*
	 * Add the identifier authority.  If it needs to be in decimal, the
	 * maximum is 2^32-1 = 4294967295 = 10 characters.  If it needs to be
	 * in hexadecimal, then maximum is 0x665544332211 = 14 characters.
	 */
	if (!sid->identifier_authority.high_part)
		size += 10;
	else
		size += 14;
	/*
	 * Finally, add the sub authorities.  For each we have a "-" followed
	 * by a decimal which can be up to 2^32-1 = 4294967295 = 10 characters.
	 */
	size += (1 + 10) * sid->sub_authority_count;
	/* We need the zero byte at the end, too. */
	size++;
	return size * sizeof(char);
}

/**
 * ntfs_sid_to_mbs - convert a SID to a multi byte string
 * @sid:		[IN]  SID to convert
 * @sid_str:		[OUT] string in which to return the SID (optional)
 * @sid_str_size:	[IN]  size in bytes of @sid_str
 *
 * Convert the SID pointed to by @sid to its standard textual representation.
 * @sid_str (if not NULL) needs to be able to store at least
 * ntfs_sid_to_mbs_size() bytes.  @sid_str_size is the size in bytes of
 * @sid_str if @sid_str is not NULL.
 *
 * The standard textual representation of the SID is of the form:
 *	S-R-I-S-S...
 * Where:
 *    - The first "S" is the literal character 'S' identifying the following
 *	digits as a SID.
 *    - R is the revision level of the SID expressed as a sequence of digits
 *	in decimal.
 *    - I is the 48-bit identifier_authority, expressed as digits in decimal,
 *	if I < 2^32, or hexadecimal prefixed by "0x", if I >= 2^32.
 *    - S... is one or more sub_authority values, expressed as digits in
 *	decimal.
 *
 * If @sid_str is not NULL it will contain the converted SUID on return.  If it
 * is NULL a string will be allocated and this will be returned.  The caller is
 * responsible for free()ing the string in that case.
 *
 * On success return the converted string and on failure return NULL with errno
 * set to the error code.
 */
char *ntfs_sid_to_mbs(const SID *sid, char *sid_str, size_t sid_str_size)
{
	u64 u;
	char *s;
	int i, j, cnt;

	/*
	 * No need to check @sid if !@sid_str since ntfs_sid_to_mbs_size() will
	 * check @sid, too.  8 is the minimum SID string size.
	 */
	if (sid_str && (sid_str_size < 8 || !ntfs_sid_is_valid(sid))) {
		errno = EINVAL;
		return NULL;
	}
	/* Allocate string if not provided. */
	if (!sid_str) {
		cnt = ntfs_sid_to_mbs_size(sid);
		if (cnt < 0)
			return NULL;
		s = ntfs_malloc(cnt);
		if (!s)
			return s;
		sid_str = s;
		/* So we know we allocated it. */
		sid_str_size = 0;
	} else {
		s = sid_str;
		cnt = sid_str_size;
	}
	/* Start with "S-R-". */
	i = snprintf(s, cnt, "S-%hhu-", (unsigned char)sid->revision);
	if (i < 0 || i >= cnt)
		goto err_out;
	s += i;
	cnt -= i;
	/* Add the identifier authority. */
	for (u = i = 0, j = 40; i < 6; i++, j -= 8)
		u += (u64)sid->identifier_authority.value[i] << j;
	if (!sid->identifier_authority.high_part)
		i = snprintf(s, cnt, "%lu", (unsigned long)u);
	else
		i = snprintf(s, cnt, "0x%llx", (unsigned long long)u);
	if (i < 0 || i >= cnt)
		goto err_out;
	s += i;
	cnt -= i;
	/* Finally, add the sub authorities. */
	for (j = 0; j < sid->sub_authority_count; j++) {
		i = snprintf(s, cnt, "-%u", (unsigned int)
				le32_to_cpu(sid->sub_authority[j]));
		if (i < 0 || i >= cnt)
			goto err_out;
		s += i;
		cnt -= i;
	}
	return sid_str;
err_out:
	if (i >= cnt)
		i = EMSGSIZE;
	else
		i = errno;
	if (!sid_str_size)
		free(sid_str);
	errno = i;
	return NULL;
}

/**
 * ntfs_generate_guid - generatates a random current guid.
 * @guid:	[OUT]   pointer to a GUID struct to hold the generated guid.
 *
 * perhaps not a very good random number generator though...
 */
void ntfs_generate_guid(GUID *guid)
{
	unsigned int i;
	u8 *p = (u8 *)guid;

	for (i = 0; i < sizeof(GUID); i++) {
		p[i] = (u8)(random() & 0xFF);
		if (i == 7)
			p[7] = (p[7] & 0x0F) | 0x40;
		if (i == 8)
			p[8] = (p[8] & 0x3F) | 0x80;
	}
}

/**
 * ntfs_security_hash - calculate the hash of a security descriptor
 * @sd:         self-relative security descriptor whose hash to calculate
 * @length:     size in bytes of the security descritor @sd
 *
 * Calculate the hash of the self-relative security descriptor @sd of length
 * @length bytes.
 *
 * This hash is used in the $Secure system file as the primary key for the $SDH
 * index and is also stored in the header of each security descriptor in the
 * $SDS data stream as well as in the index data of both the $SII and $SDH
 * indexes.  In all three cases it forms part of the SDS_ENTRY_HEADER
 * structure.
 *
 * Return the calculated security hash in little endian.
 */
le32 ntfs_security_hash(const SECURITY_DESCRIPTOR_RELATIVE *sd, const u32 len)
{
	const le32 *pos = (const le32*)sd;
	const le32 *end = pos + (len >> 2);
	u32 hash = 0;

	while (pos < end) {
		hash = le32_to_cpup(pos) + ntfs_rol32(hash, 3);
		pos++;
	}
	return cpu_to_le32(hash);
}


/*
 *		The following must be in some library...
 */

static unsigned long atoul(const char *p)
{				/* must be somewhere ! */
	unsigned long v;

	v = 0;
	while ((*p >= '0') && (*p <= '9'))
		v = v * 10 + (*p++) - '0';
	return (v);
}

/*
 *		Build an internal representation of a SID
 *	Returns a copy in allocated memory if it succeeds
 *	The SID is checked to be a valid user one.
 */

static SID *encodesid(const char *sidstr)
{
	SID *sid;
	int cnt;
	BIGSID bigsid;
	SID *bsid;
	long auth;
	const char *p;

	sid = (SID*) NULL;
	if (!strncmp(sidstr, "S-1-", 4)) {
		bsid = (SID*)&bigsid;
		bsid->revision = SID_REVISION;
		p = &sidstr[4];
		auth = atoul(p);
		bsid->identifier_authority.high_part = cpu_to_be16(0);
		bsid->identifier_authority.low_part = cpu_to_be32(auth);
		cnt = 0;
		p = strchr(p, '-');
		while (p && (cnt < 8)) {
			p++;
			bsid->sub_authority[cnt] = cpu_to_le32(atoul(p));
			p = strchr(p, '-');
			cnt++;
		}
		bsid->sub_authority_count = cnt;
		if ((cnt > 0) && valid_sid(bsid) && is_user_sid(bsid)) {
			sid = (SID*) ntfs_malloc(4 * cnt + 8);
			if (sid)
				memcpy(sid, bsid, 4 * cnt + 8);
		}
	}
	return (sid);
}

/*
 *		Internal read
 *	copied and pasted from ntfs_fuse_read() and made independent
 *	of fuse context
 */

static int ntfs_local_read(ntfs_inode *ni,
		ntfschar *stream_name, int stream_name_len,
		char *buf, size_t size, off_t offset)
{
	ntfs_attr *na = NULL;
	int res, total = 0;

	na = ntfs_attr_open(ni, AT_DATA, stream_name, stream_name_len);
	if (!na) {
		res = -errno;
		goto exit;
	}
	if ((size_t)offset < (size_t)na->data_size) {
		if (offset + size > (size_t)na->data_size)
			size = na->data_size - offset;
		while (size) {
			res = ntfs_attr_pread(na, offset, size, buf);
			if ((off_t)res < (off_t)size)
				ntfs_log_perror("ntfs_attr_pread partial read "
					"(%lld : %lld <> %d)",
					(long long)offset,
					(long long)size, res);
			if (res <= 0) {
				res = -errno;
				goto exit;
			}
			size -= res;
			offset += res;
			total += res;
		}
	}
	res = total;
exit:
	if (na)
		ntfs_attr_close(na);
	return res;
}


/*
 *		Internal write
 *	copied and pasted from ntfs_fuse_write() and made independent
 *	of fuse context
 */

static int ntfs_local_write(ntfs_inode *ni,
		ntfschar *stream_name, int stream_name_len,
		char *buf, size_t size, off_t offset)
{
	ntfs_attr *na = NULL;
	int res, total = 0;

	na = ntfs_attr_open(ni, AT_DATA, stream_name, stream_name_len);
	if (!na) {
		res = -errno;
		goto exit;
	}
	while (size) {
		res = ntfs_attr_pwrite(na, offset, size, buf);
		if (res < (s64)size)
			ntfs_log_perror("ntfs_attr_pwrite partial write (%lld: "
				"%lld <> %d)", (long long)offset,
				(long long)size, res);
		if (res <= 0) {
			res = -errno;
			goto exit;
		}
		size -= res;
		offset += res;
		total += res;
	}
	res = total;
exit:
	if (na)
		ntfs_attr_close(na);
	return res;
}


/*
 *	Get the first entry of current index block
 *	cut and pasted form ntfs_ie_get_first() in index.c
 */

static INDEX_ENTRY *ntfs_ie_get_first(INDEX_HEADER *ih)
{
	return (INDEX_ENTRY*)((u8*)ih + le32_to_cpu(ih->entries_offset));
}

/*
 *		Stuff a 256KB block into $SDS before writing descriptors
 *	into the block.
 *
 *	This prevents $SDS from being automatically declared as sparse
 *	when the second copy of the first security descriptor is written
 *	256KB further ahead.
 *
 *	Having $SDS declared as a sparse file is not wrong by itself
 *	and chkdsk leaves it as a sparse file. It does however complain
 *	and add a sparse flag (0x0200) into field file_attributes of
 *	STANDARD_INFORMATION of $Secure. This probably means that a
 *	sparse attribute (ATTR_IS_SPARSE) is only allowed in sparse
 *	files (FILE_ATTR_SPARSE_FILE).
 *
 *	Windows normally does not convert to sparse attribute or sparse
 *	file. Stuffing is just a way to get to the same result.
 */

static int entersecurity_stuff(ntfs_volume *vol, off_t offs)
{
	int res;
	int written;
	unsigned long total;
	char *stuff;

	res = 0;
	total = 0;
	stuff = ntfs_malloc(STUFFSZ);
	if (stuff) {
		memset(stuff, 0, STUFFSZ);
		do {
			written = ntfs_local_write(vol->secure_ni,
				STREAM_SDS, 4, stuff, STUFFSZ, offs);
			if (written == STUFFSZ) {
				total += STUFFSZ;
				offs += STUFFSZ;
			} else {
				errno = ENOSPC;
				res = -1;
			}
		} while (!res && (total < ALIGN_SDS_BLOCK));
		free(stuff);
	} else {
		errno = ENOMEM;
		res = -1;
	}
	return (res);
}

/*
 *		Enter a new security descriptor into $Secure (data only)
 *      it has to be written twice with an offset of 256KB
 *
 *	Should only be called by entersecurityattr() to ensure consistency
 *
 *	Returns zero if sucessful
 */

static int entersecurity_data(ntfs_volume *vol,
			const SECURITY_DESCRIPTOR_RELATIVE *attr, s64 attrsz,
			le32 hash, le32 keyid, off_t offs, int gap)
{
	int res;
	int written1;
	int written2;
	char *fullattr;
	int fullsz;
	SECURITY_DESCRIPTOR_HEADER *phsds;

	res = -1;
	fullsz = attrsz + gap + sizeof(SECURITY_DESCRIPTOR_HEADER);
	fullattr = ntfs_malloc(fullsz);
	if (fullattr) {
			/*
			 * Clear the gap from previous descriptor
			 * this could be useful for appending the second
			 * copy to the end of file. When creating a new
			 * 256K block, the gap is cleared while writing
			 * the first copy
			 */
		if (gap)
			memset(fullattr,0,gap);
		memcpy(&fullattr[gap + sizeof(SECURITY_DESCRIPTOR_HEADER)],
				attr,attrsz);
		phsds = (SECURITY_DESCRIPTOR_HEADER*)&fullattr[gap];
		phsds->hash = hash;
		phsds->security_id = keyid;
		phsds->offset = cpu_to_le64(offs);
		phsds->length = cpu_to_le32(fullsz - gap);
		written1 = ntfs_local_write(vol->secure_ni,
			STREAM_SDS, 4, fullattr, fullsz,
			offs - gap);
		written2 = ntfs_local_write(vol->secure_ni,
			STREAM_SDS, 4, fullattr, fullsz,
			offs - gap + ALIGN_SDS_BLOCK);
		if ((written1 == fullsz)
		     && (written2 == written1))
			res = 0;
		else
			errno = ENOSPC;
		free(fullattr);
	} else
		errno = ENOMEM;
	return (res);
}

/*
 *	Enter a new security descriptor in $Secure (indexes only)
 *
 *	Should only be called by entersecurityattr() to ensure consistency
 *
 *	Returns zero if sucessful
 */

static int entersecurity_indexes(ntfs_volume *vol, s64 attrsz,
			le32 hash, le32 keyid, off_t offs)
{
	union {
		struct {
			le32 dataoffsl;
			le32 dataoffsh;
		} parts;
		le64 all;
	} realign;
	int res;
	ntfs_index_context *xsii;
	ntfs_index_context *xsdh;
	struct SII newsii;
	struct SDH newsdh;

	res = -1;
				/* enter a new $SII record */

	xsii = vol->secure_xsii;
	ntfs_index_ctx_reinit(xsii);
	newsii.offs = cpu_to_le16(20);
	newsii.size = cpu_to_le16(sizeof(struct SII) - 20);
	newsii.fill1 = cpu_to_le32(0);
	newsii.indexsz = cpu_to_le16(sizeof(struct SII));
	newsii.indexksz = cpu_to_le16(sizeof(SII_INDEX_KEY));
	newsii.flags = cpu_to_le16(0);
	newsii.fill2 = cpu_to_le16(0);
	newsii.keysecurid = keyid;
	newsii.hash = hash;
	newsii.securid = keyid;
	realign.all = cpu_to_le64(offs);
	newsii.dataoffsh = realign.parts.dataoffsh;
	newsii.dataoffsl = realign.parts.dataoffsl;
	newsii.datasize = cpu_to_le32(attrsz
			 + sizeof(SECURITY_DESCRIPTOR_HEADER));
	if (!ntfs_ie_add(xsii,(INDEX_ENTRY*)&newsii)) {

		/* enter a new $SDH record */

		xsdh = vol->secure_xsdh;
		ntfs_index_ctx_reinit(xsdh);
		newsdh.offs = cpu_to_le16(24);
		newsdh.size = cpu_to_le16(
			sizeof(SECURITY_DESCRIPTOR_HEADER));
		newsdh.fill1 = cpu_to_le32(0);
		newsdh.indexsz = cpu_to_le16(
				sizeof(struct SDH));
		newsdh.indexksz = cpu_to_le16(
				sizeof(SDH_INDEX_KEY));
		newsdh.flags = cpu_to_le16(0);
		newsdh.fill2 = cpu_to_le16(0);
		newsdh.keyhash = hash;
		newsdh.keysecurid = keyid;
		newsdh.hash = hash;
		newsdh.securid = keyid;
		newsdh.dataoffsh = realign.parts.dataoffsh;
		newsdh.dataoffsl = realign.parts.dataoffsl;
		newsdh.datasize = cpu_to_le32(attrsz
			 + sizeof(SECURITY_DESCRIPTOR_HEADER));
                           /* special filler value, Windows generally */
                           /* fills with 0x00490049, sometimes with zero */
		newsdh.fill3 = cpu_to_le32(0x00490049);
		if (!ntfs_ie_add(xsdh,(INDEX_ENTRY*)&newsdh))
			res = 0;
	}
	return (res);
}

/*
 *	Enter a new security descriptor in $Secure (data and indexes)
 *	Returns id of entry, or zero if there is a problem.
 *	(should not be called for NTFS version < 3.0)
 *
 *	important : calls have to be serialized, however no locking is
 *	needed while fuse is not multithreaded
 */

static le32 entersecurityattr(ntfs_volume *vol,
			const SECURITY_DESCRIPTOR_RELATIVE *attr, s64 attrsz,
			le32 hash)
{
	union {
		struct {
			le32 dataoffsl;
			le32 dataoffsh;
		} parts;
		le64 all;
	} realign;
	le32 securid;
	le32 keyid;
	off_t offs;
	int gap;
	int size;
	BOOL found;
	struct SII *psii;
	INDEX_ENTRY *entry;
	INDEX_ENTRY *next;
	ntfs_index_context *xsii;
	ntfs_attr *na;

	/* find the first available securid beyond the last key */
	/* in $Secure:$SII. This also determines the first */
	/* available location in $Secure:$SDS, as this stream */
	/* is always appended to and the id's are allocated */
	/* in sequence */

	securid = cpu_to_le32(0);
	xsii = vol->secure_xsii;
	ntfs_index_ctx_reinit(xsii);
	offs = size = 0;
	keyid = cpu_to_le32(-1);
	found = !ntfs_index_lookup((char*)&keyid,
			       sizeof(SII_INDEX_KEY), xsii);
	if (!found && (errno != ENOENT)) {
		ntfs_log_perror("Inconsistency in index $SII");
		psii = (struct SII*)NULL;
	} else {
		entry = xsii->entry;
		psii = (struct SII*)xsii->entry;
	}
	if (psii) {
		/*
		 * Get last entry in block, but must get first one
		 * one first, as we should already be beyond the
		 * last one. For some reason the search for the last
		 * entry sometimes does not return the last block...
		 * we assume this can only happen in root block
		 */
		if (xsii->is_in_root)
			entry = ntfs_ie_get_first
				((INDEX_HEADER*)&xsii->ir->index);
		else
			entry = ntfs_ie_get_first
				((INDEX_HEADER*)&xsii->ib->index);
		/*
		 * All index blocks should be at least half full
		 * so there always is a last entry but one,
		 * except when creating the first entry in index root.
		 * A simplified version of next(), limited to
		 * current index node, could be used
		 */
		keyid = cpu_to_le32(0);
		while (entry) {
			next = ntfs_index_next(entry,xsii);
			if (next) { 
				psii = (struct SII*)next;
					/* save last key and */
					/* available position */
				keyid = psii->keysecurid;
				realign.parts.dataoffsh
						 = psii->dataoffsh;
				realign.parts.dataoffsl
						 = psii->dataoffsl;
				offs = le64_to_cpu(realign.all);
				size = le32_to_cpu(psii->datasize);
			}
			entry = next;
		}
	}
	if (!keyid) {
		/*
		 * could not find any entry, before creating the first
		 * entry, make a double check by making sure size of $SII
		 * is less than needed for one entry
		 */
		securid = cpu_to_le32(0);
		na = ntfs_attr_open(vol->secure_ni,AT_INDEX_ROOT,sii_stream,4);
		if (na) {
			if ((size_t)na->data_size < sizeof(struct SII)) {
				ntfs_log_error("Creating the first security_id\n");
				securid = cpu_to_le32(FIRST_SECURITY_ID);
			}
			ntfs_attr_close(na);
		}
		if (!securid) {
			ntfs_log_error("Error creating a security_id\n");
			errno = EIO;
		}
	} else
		securid = cpu_to_le32(le32_to_cpu(keyid) + 1);
	/*
	 * The security attr has to be written twice 256KB
	 * apart. This implies that offsets like
	 * 0x40000*odd_integer must be left available for
	 * the second copy. So align to next block when
	 * the last byte overflows on a wrong block.
	 */

	if (securid) {
		gap = (-size) & (ALIGN_SDS_ENTRY - 1);
		offs += gap + size;
		if ((offs + attrsz + sizeof(SECURITY_DESCRIPTOR_HEADER) - 1)
	 	   & ALIGN_SDS_BLOCK) {
			offs = ((offs + attrsz
				 + sizeof(SECURITY_DESCRIPTOR_HEADER) - 1)
			 	| (ALIGN_SDS_BLOCK - 1)) + 1;
		}
		if (!(offs & (ALIGN_SDS_BLOCK - 1)))
			entersecurity_stuff(vol, offs);
		/*
		 * now write the security attr to storage :
		 * first data, then SII, then SDH
		 * If failure occurs while writing SDS, data will never
		 *    be accessed through indexes, and will be overwritten
		 *    by the next allocated descriptor
		 * If failure occurs while writing SII, the id has not
		 *    recorded and will be reallocated later
		 * If failure occurs while writing SDH, the space allocated
		 *    in SDS or SII will not be reused, an inconsistency
		 *    will persist with no significant consequence
		 */
		if (entersecurity_data(vol, attr, attrsz, hash, securid, offs, gap)
		    || entersecurity_indexes(vol, attrsz, hash, securid, offs))
			securid = cpu_to_le32(0);
	}
		/* inode now is dirty, synchronize it all */
	ntfs_index_entry_mark_dirty(vol->secure_xsii);
	ntfs_index_ctx_reinit(vol->secure_xsii);
	ntfs_index_entry_mark_dirty(vol->secure_xsdh);
	ntfs_index_ctx_reinit(vol->secure_xsdh);
	NInoSetDirty(vol->secure_ni);
	if (ntfs_inode_sync(vol->secure_ni))
		ntfs_log_perror("Could not sync $Secure\n");
	return (securid);
}

/*
 *		Find a matching security descriptor in $Secure,
 *	if none, allocate a new id and write the descriptor to storage
 *	Returns id of entry, or zero if there is a problem.
 *
 *	important : calls have to be serialized, however no locking is
 *	needed while fuse is not multithreaded
 */

static le32 setsecurityattr(ntfs_volume *vol,
			const SECURITY_DESCRIPTOR_RELATIVE *attr, s64 attrsz)
{
	struct SDH *psdh;	/* this is an image of index (le) */
	union {
		struct {
			le32 dataoffsl;
			le32 dataoffsh;
		} parts;
		le64 all;
	} realign;
	BOOL found;
	BOOL collision;
	size_t size;
	size_t rdsize;
	s64 offs;
	int res;
	ntfs_index_context *xsdh;
	char *oldattr;
	SDH_INDEX_KEY key;
	INDEX_ENTRY *entry;
	le32 securid;
	le32 hash;

	hash = ntfs_security_hash(attr,attrsz);
	oldattr = (char*)NULL;
	securid = cpu_to_le32(0);
	res = 0;
	xsdh = vol->secure_xsdh;
	if (vol->secure_ni && xsdh && !vol->secure_reentry++) {
		ntfs_index_ctx_reinit(xsdh);
		/*
		 * find the nearest key as (hash,0)
		 * (do not search for partial key : in case of collision,
		 * it could return a key which is not the first one which
		 * collides)
		 */
		key.hash = hash;
		key.security_id = cpu_to_le32(0);
		found = !ntfs_index_lookup((char*)&key,
				 sizeof(SDH_INDEX_KEY), xsdh);
		if (!found && (errno != ENOENT))
			ntfs_log_perror("Inconsistency in index $SDH");
		else {
			entry = xsdh->entry;
			found = FALSE;
			/*
			 * lookup() may return a node with no data,
			 * if so get next
			 */
			if (entry->ie_flags & INDEX_ENTRY_END)
				entry = ntfs_index_next(entry,xsdh);
			do {
				collision = FALSE;
				psdh = (struct SDH*)entry;
				if (psdh)
					size = (size_t) le32_to_cpu(psdh->datasize)
						 - sizeof(SECURITY_DESCRIPTOR_HEADER);
				else size = 0;
			   /* if hash is not the same, the key is not present */
				if (psdh && (size > 0)
				   && (psdh->keyhash == hash)) {
					   /* if hash is the same */
					   /* check the whole record */
					realign.parts.dataoffsh = psdh->dataoffsh;
					realign.parts.dataoffsl = psdh->dataoffsl;
					offs = le64_to_cpu(realign.all)
						+ sizeof(SECURITY_DESCRIPTOR_HEADER);
					oldattr = (char*)ntfs_malloc(size);
					if (oldattr) {
						rdsize = ntfs_local_read(
							vol->secure_ni,
							STREAM_SDS, 4,
							oldattr, size, offs);
						found = (rdsize == size)
							&& !memcmp(oldattr,attr,size);
						free(oldattr);
					  /* if the records do not compare */
					  /* (hash collision), try next one */
						if (!found) {
							entry = ntfs_index_next(
								entry,xsdh);
							collision = TRUE;
						}
					} else
						res = ENOMEM;
				}
			} while (collision && entry);
			if (found)
				securid = psdh->keysecurid;
			else {
				if (res) {
					errno = res;
					securid = cpu_to_le32(0);
				} else {
					/*
					 * no matching key :
					 * have to build a new one
					 */
					securid = entersecurityattr(vol,
						attr, attrsz, hash);
				}
			}
		}
	}
	if (--vol->secure_reentry)
		ntfs_log_perror("Reentry error, check no multithreading\n");
	return (securid);
}


/*
 *		Update the security descriptor of a file
 *	Either as an attribute (complying with pre v3.x NTFS version)
 *	or, when possible, as an entry in $Secure (for NTFS v3.x)
 *
 *	returns 0 if success
 */

static int update_secur_descr(ntfs_volume *vol,
				char *newattr, ntfs_inode *ni)
{
	int newattrsz;
	int written;
	int res;
	ntfs_attr *na;

	newattrsz = attr_size(newattr);

#if !FORCE_FORMAT_v1x
	if ((vol->major_ver < 3) || !vol->secure_ni) {
#endif

		/* update for NTFS format v1.x */

		/* update the old security attribute */
		na = ntfs_attr_open(ni, AT_SECURITY_DESCRIPTOR, AT_UNNAMED, 0);
		if (na) {
			/* resize attribute */
			res = ntfs_attr_truncate(na, (s64) newattrsz);
			/* overwrite value */
			if (!res) {
				written = (int)ntfs_attr_pwrite(na, (s64) 0,
					 (s64) newattrsz, newattr);
				if (written != newattrsz) {
					ntfs_log_error("Failed to update "
						"a v1.x security descriptor\n");
					errno = EIO;
					res = -1;
				}
			}

			ntfs_attr_close(na);
			/* if old security attribute was found, also */
			/* truncate standard information attribute to v1.x */
			/* this is needed when security data is wanted */
			/* as v1.x though volume is formatted for v3.x */
			na = ntfs_attr_open(ni, AT_STANDARD_INFORMATION,
				AT_UNNAMED, 0);
			if (na) {
				clear_nino_flag(ni, v3_Extensions);
			/*
			 * Truncating the record does not sweep extensions
			 * from copy in memory. Clear security_id to be safe
			 */
				ni->security_id = cpu_to_le32(0);
				res = ntfs_attr_truncate(na, (s64)48);
				ntfs_attr_close(na);
				clear_nino_flag(ni, v3_Extensions);
			}
		} else {
			/*
			 * insert the new security attribute if there
			 * were none
			 */
			res = ntfs_attr_add(ni, AT_SECURITY_DESCRIPTOR,
					    AT_UNNAMED, 0, (u8*)newattr,
					    (s64) newattrsz);
		}
#if !FORCE_FORMAT_v1x
	} else {

		/* update for NTFS format v3.x */

		le32 securid;

		securid = setsecurityattr(vol,
			(const SECURITY_DESCRIPTOR_RELATIVE*)newattr,
			(s64)newattrsz);
		if (securid) {
			na = ntfs_attr_open(ni, AT_STANDARD_INFORMATION,
				AT_UNNAMED, 0);
			if (na) {
				res = 0;
				if (!test_nino_flag(ni, v3_Extensions)) {
			/* expand standard information attribute to v3.x */
					res = ntfs_attr_truncate(na,
					 (s64)sizeof(STANDARD_INFORMATION));
					ni->owner_id = cpu_to_le32(0);
					ni->quota_charged = cpu_to_le32(0);
					ni->usn = cpu_to_le32(0);
					ntfs_attr_remove(ni,
						AT_SECURITY_DESCRIPTOR,
						AT_UNNAMED, 0);
			}
				set_nino_flag(ni, v3_Extensions);
				ni->security_id = securid;
				ntfs_attr_close(na);
			} else {
				ntfs_log_error("Failed to update "
					"standard informations\n");
				errno = EIO;
				res = -1;
			}
		} else
			res = -1;
	}
#endif

	/* mark node as dirty */
	NInoSetDirty(ni);
	ntfs_inode_sync(ni); /* useful ? */
	return (res);
}

/*
 *		Upgrade the security descriptor of a file
 *	This is intended to allow graceful upgrades for files which
 *	were created in previous versions, with a security attributes
 *	and no security id.
 *	
 *      It will allocate a security id and replace the individual
 *	security attribute by a reference to the global one
 *
 *	Special files are not upgraded (currently / and files in
 *	directories /$*)
 *
 *	Though most code is similar to update_secur_desc() it has
 *	been kept apart to facilitate the further processing of
 *	special cases or even to remove it if found dangerous.
 *
 *	returns 0 if success,
 *		1 if not upgradable. This is not an error.
 *		-1 if there is a problem
 */

static int upgrade_secur_desc(ntfs_volume *vol, const char *path,
				const char *attr, ntfs_inode *ni)
{
	int attrsz;
	int res;
	le32 securid;
	ntfs_attr *na;

		/*
		 * upgrade requires NTFS format v3.x
		 * also refuse upgrading for special files
		 */

	if ((vol->major_ver >= 3)
		&& (path[0] == '/')
		&& (path[1] != '$') && (path[1] != '\0')) {
		attrsz = attr_size(attr);
		securid = setsecurityattr(vol,
			(const SECURITY_DESCRIPTOR_RELATIVE*)attr,
			(s64)attrsz);
		if (securid) {
			na = ntfs_attr_open(ni, AT_STANDARD_INFORMATION,
				AT_UNNAMED, 0);
			if (na) {
				res = 0;
			/* expand standard information attribute to v3.x */
				res = ntfs_attr_truncate(na,
					 (s64)sizeof(STANDARD_INFORMATION));
				ni->owner_id = cpu_to_le32(0);
				ni->quota_charged = cpu_to_le32(0);
				ni->usn = cpu_to_le32(0);
				ntfs_attr_remove(ni, AT_SECURITY_DESCRIPTOR,
						AT_UNNAMED, 0);
				set_nino_flag(ni, v3_Extensions);
				ni->security_id = securid;
				ntfs_attr_close(na);
			} else {
				ntfs_log_error("Failed to upgrade "
					"standard informations\n");
				errno = EIO;
				res = -1;
			}
		} else
			res = -1;
	/* mark node as dirty */
	NInoSetDirty(ni);
	ntfs_inode_sync(ni); /* useful ? */
	} else
		res = 1;

	return (res);
}

/*
 *		Compute the uid or gid associated to a SID
 *	through an implicit mapping
 *
 *	Returns 0 (root) if it does not match pattern
 */

static int findimplicit(const SID *xsid, const SID *pattern, int parity)
{
	BIGSID defsid;
	SID *psid;
	int xid; /* uid or gid */
	int cnt;
	int carry;
	u32 xlast;
	u32 rlast;

	memcpy(&defsid,pattern,sid_size(pattern));
	psid = (SID*)&defsid;
	cnt = psid->sub_authority_count;
	psid->sub_authority[cnt-1] = xsid->sub_authority[cnt-1];
	xlast = le32_to_cpu(xsid->sub_authority[cnt-1]);
	rlast = le32_to_cpu(pattern->sub_authority[cnt-1]);

	if ((xlast > rlast) && !((xlast ^ rlast ^ parity) & 1)) {
		/* direct check for basic situation */
		if (same_sid(psid,xsid))
			xid = ((xlast - rlast) >> 1) & 0x3fffffff;
		else {
			/*
			 * check whether part of mapping had to be recorded
			 * in a higher level authority
			 */
			carry = 1;
			do {
				psid->sub_authority[cnt-2]
					= cpu_to_le32(le32_to_cpu(
						psid->sub_authority[cnt-2]) + 1);
			} while (!same_sid(psid,xsid) && (++carry < 4));
			if (carry < 4)
				xid = (((xlast - rlast) >> 1) & 0x3fffffff)
					| (carry << 30);
			else
				xid = 0;
		}
	} else
		xid = 0;
	return (xid);
}


/*
 *		Find Linux owner mapped to a usid
 *	Returns 0 (root) if not found
 */

static int findowner(struct SECURITY_CONTEXT *scx, const SID *usid)
{
	struct MAPPING *p;
	uid_t uid;

	p = scx->usermapping;
	while (p && p->xid && !same_sid(usid, p->sid))
		p = p->next;
	if (p && !p->xid)
		/*
		 * No explicit mapping found, try implicit mapping
		 */
		uid = findimplicit(usid,p->sid,0);
	else
		uid = (p ? p->xid : 0);
	return (uid);
}

/*
 *		Find Linux group mapped to a gsid
 *	Returns 0 (root) if not found
 */

static gid_t findgroup(struct SECURITY_CONTEXT *scx, const SID * gsid)
{
	struct MAPPING *p;
	int gsidsz;
	gid_t gid;

	gsidsz = sid_size(gsid);
	p = scx->groupmapping;
	while (p && p->xid && !same_sid(gsid, p->sid))
		p = p->next;
	if (p && !p->xid)
		/*
		 * No explicit mapping found, try implicit mapping
		 */
		gid = findimplicit(gsid,p->sid,1);
	else
		gid = (p ? p->xid : 0);
	return (gid);
}

/*
 *		Find usid mapped to a Linux user
 *	Returns NULL if not found
 */

static const SID *find_usid(struct SECURITY_CONTEXT *scx,
		uid_t uid, SID *defusid)
{
	struct MAPPING *p;
	const SID *sid;
	int cnt;

	if (!uid)
		sid = adminsid;
	else {
		p = scx->usermapping;
		while (p && p->xid && ((uid_t)p->xid != uid))
			p = p->next;
		if (p && !p->xid) {
			/*
			 * default pattern has been reached :
			 * build an implicit SID according to pattern
			 * (the pattern format was checked while reading
			 * the mapping file)
			 */
			memcpy(defusid, p->sid, sid_size(p->sid));
			cnt = defusid->sub_authority_count;
			defusid->sub_authority[cnt-1]
				= cpu_to_le32(
					le32_to_cpu(defusid->sub_authority[cnt-1])
					+ 2*(uid & 0x3fffffff));
			if (uid & 0xc0000000)
				defusid->sub_authority[cnt-2]
					= cpu_to_le32(
						le32_to_cpu(defusid->sub_authority[cnt-2])
						+ ((uid >> 30) & 3));
			sid = defusid;
		} else
			sid = (p ? p->sid : (const SID*)NULL);
	}
	return (sid);
}

/*
 *		Find Linux group mapped to a gsid
 *	Returns 0 (root) if not found
 */

static const SID *find_gsid(struct SECURITY_CONTEXT *scx,
		gid_t gid, SID *defgsid)
{
	struct MAPPING *p;
	const SID *sid;
	int cnt;

	if (!gid)
		sid = adminsid;
	else {
		p = scx->groupmapping;
		while (p && p->xid && ((gid_t)p->xid != gid))
			p = p->next;
		if (p && !p->xid) {
			/*
			 * default pattern has been reached :
			 * build an implicit SID according to pattern
			 * (the pattern format was checked while reading
			 * the mapping file)
			 */
			memcpy(defgsid, p->sid, sid_size(p->sid));
			cnt = defgsid->sub_authority_count;
			defgsid->sub_authority[cnt-1]
				= cpu_to_le32(
					le32_to_cpu(defgsid->sub_authority[cnt-1])
					+ 2*(gid & 0x3fffffff) + 1);
			if (gid & 0xc0000000)
				defgsid->sub_authority[cnt-2]
					= cpu_to_le32(
						le32_to_cpu(defgsid->sub_authority[cnt-2])
						+ ((gid >> 30) & 3));
			sid = defgsid;
		} else
			sid = (p ? p->sid : (const SID*)NULL);
	}
	return (sid);
}

/*
 *		Optional simplified checking of group membership
 *
 *	This only takes into account the groups defined in
 *	/etc/group at initialization time.
 *	It does not take into account the groups dynamically set by
 *	setgroups() nor the changes in /etc/group since initialization
 *
 *	This optional method could be useful if standard checking
 *	leads to a performance concern.
 *
 *	Should not be called for user root, however the group may be root
 *
 */

static BOOL staticgroupmember(struct SECURITY_CONTEXT *scx, uid_t uid, gid_t gid)
{
	BOOL ingroup;
	int grcnt;
	gid_t *groups;
	struct MAPPING *user;

	ingroup = FALSE;
	if (uid) {
		user = scx->usermapping;
		while (user && ((uid_t)user->xid != uid))
			user = user->next;
		if (user) {
			groups = user->groups;
			grcnt = user->grcnt;
			while ((--grcnt >= 0) && (groups[grcnt] != gid)) { }
			ingroup = (grcnt >= 0);
		}
	}
	return (ingroup);
}


/*
 *		Check whether current thread owner is member of file group
 *
 *	Should not be called for user root, however the group may be root
 *
 * As indicated by Miklos Szeredi :
 *
 * The group list is available in
 *
 *   /proc/$PID/task/$TID/status
 *
 * and fuse supplies TID in get_fuse_context()->pid.  The only problem is
 * finding out PID, for which I have no good solution, except to iterate
 * through all processes.  This is rather slow, but may be speeded up
 * with caching and heuristics (for single threaded programs PID = TID).
 *
 * The following implementation gets the group list from
 *   /proc/$TID/task/$TID/status which apparently exists and
 * contains the same data.
 */

static BOOL groupmember(struct SECURITY_CONTEXT *scx, uid_t uid, gid_t gid)
{
	static char key[] = "\nGroups:";
	char buf[BUFSZ+1];
	char filename[64];
	enum { INKEY, INSEP, INNUM, INEND } state;
	int fd;
	char c;
	int matched;
	BOOL ismember;
	int got;
	char *p;
	gid_t grp;
	pid_t tid;

	if (scx->vol->secure_flags & (1 << SECURITY_STATICGRPS))
		ismember = staticgroupmember(scx, uid, gid);
	else {
		ismember = FALSE; /* default return */
		tid = scx->tid;
		sprintf(filename,"/proc/%u/task/%u/status",tid,tid);
		fd = open(filename,O_RDONLY);
		if (fd >= 0) {
			got = read(fd, buf, BUFSZ);
			buf[got] = 0;
			state = INKEY;
			matched = 0;
			p = buf;
			grp = 0;
				/*
				 *  A simple automaton to process lines like
				 *  Groups: 14 500 513
				 */
			do {
				c = *p++;
				if (!c) {
					/* refill buffer */
					got = read(fd, buf, BUFSZ);
					buf[got] = 0;
					p = buf;
					c = *p++; /* 0 at end of file */
				}
				switch (state) {
				case INKEY :
					if (key[matched] == c) {
						if (!key[++matched])
							state = INSEP;
					} else
						if (key[0] == c)
							matched = 1;
						else
							matched = 0;
					break;
				case INSEP :
					if ((c >= '0') && (c <= '9')) {
						grp = c - '0';
						state = INNUM;
					} else
						if ((c != ' ') && (c != '\t'))
							state = INEND;
					break;
				case INNUM :
					if ((c >= '0') && (c <= '9'))
						grp = grp*10 + c - '0';
					else {
						ismember = (grp == gid);
						if ((c != ' ') && (c != '\t'))
							state = INEND;
						else
							state = INSEP;
					}
				default :
					break;
				}
			} while (!ismember && c && (state != INEND));
		close(fd);
		if (!c)
			ntfs_log_error("No group record found in %s\n",filename);
		} else
			ntfs_log_error("Could not open %s\n",filename);
	}
	return (ismember);
}


/*
 *	Cacheing is done two-way :
 *	- from uid, gid and perm to securid (CACHED_SECURID)
 *	- from a securid to uid, gid and perm (CACHED_PERMISSIONS)
 *
 *	CACHED_SECURID data is kept in a most-recent-first list
 *	which should not be too long to be efficient. Its optimal
 *	size is depends on usage and is hard to determine.
 *
 *	CACHED_PERMISSIONS data is kept in a two-level indexed array. It
 *	is optimal at the expense of storage. Use of a most-recent-first
 *	list would save memory and provide similar performances for
 *	standard usage, but not for file servers with too many file
 *	owners
 *
 *	CACHED_PERMISSIONS_LEGACY is a special case for CACHED_PERMISSIONS
 *	for legacy directories which were not allocated a security_id
 *	it is organized in a most-recent-first list.
 *
 *	In main caches, data is never invalidated, as the meaning of
 *	a security_id only changes when user mapping is changed, which
 *	current implies remounting. However returned entries may be
 *	overwritten at next update, so data has to be copied elsewhere
 *	before another cache update is made.
 *	In legacy cache, data has to be invalidated when protection is
 *	changed.
 *
 *	Though the same data may be found in both list, they
 *	must be kept separately : the interpretation of ACL
 *	in both direction are approximations which could be non
 *	reciprocal for some configuration of the user mapping data
 *
 *	During the process of recompiling ntfs-3g from a tgz archive,
 *	security processing added 7.6% to the cpu time used by ntfs-3g
 *	and 30% if the cache is disabled.
 */

static struct PERMISSIONS_CACHE *create_caches(struct SECURITY_CONTEXT *scx,
			u32 securindex)
{
	struct PERMISSIONS_CACHE *cache;
	unsigned int index1;
	unsigned int i;

	cache = (struct PERMISSIONS_CACHE*)NULL;
		/* create the first permissions blocks */
	index1 = securindex >> CACHE_PERMISSIONS_BITS;
	cache = (struct PERMISSIONS_CACHE*)
		ntfs_malloc(sizeof(struct PERMISSIONS_CACHE)
		      + index1*sizeof(struct CACHED_PERMISSIONS*));
	if (cache) {
		cache->head.last = index1;
		cache->head.p_reads = 0;
		cache->head.p_hits = 0;
		cache->head.p_writes = 0;
		*scx->pseccache = cache;
		for (i=0; i<=index1; i++)
			cache->cachetable[i]
			   = (struct CACHED_PERMISSIONS*)NULL;
	}
	return (cache);
}

/*
 *		Free memory used by caches
 *	The only purpose is to facilitate the detection of memory leaks
 */

static void free_caches(struct SECURITY_CONTEXT *scx)
{
	unsigned int index1;
	struct PERMISSIONS_CACHE *pseccache;

	pseccache = *scx->pseccache;
	if (pseccache) {
		for (index1=0; index1<=pseccache->head.last; index1++)
			if (pseccache->cachetable[index1]) {
#if POSIXACLS
				unsigned int index2;

				for (index2=0; index2<(1<< CACHE_PERMISSIONS_BITS); index2++)
					if (pseccache->cachetable[index1][index2].pxdesc)
						free(pseccache->cachetable[index1][index2].pxdesc);
#endif
				free(pseccache->cachetable[index1]);
			}
		free(pseccache);
	}
}

static int compare(const struct CACHED_SECURID *cached,
			const struct CACHED_SECURID *item)
{
#if POSIXACLS
	size_t csize;
	size_t isize;

		/* only compare data and sizes */
	csize = (cached->variable ?
		sizeof(struct POSIX_ACL)
		+ (((struct POSIX_SECURITY*)cached->variable)->acccnt
		   + ((struct POSIX_SECURITY*)cached->variable)->defcnt)
			*sizeof(struct POSIX_ACE) :
		0);
	isize = (item->variable ?
		sizeof(struct POSIX_ACL)
		+ (((struct POSIX_SECURITY*)item->variable)->acccnt
		   + ((struct POSIX_SECURITY*)item->variable)->defcnt)
			*sizeof(struct POSIX_ACE) :
		0);
	return ((cached->uid != item->uid)
		 || (cached->gid != item->gid)
		 || (cached->dmode != item->dmode)
		 || (csize != isize)
		 || (csize
		    && isize
		    && memcmp(&((struct POSIX_SECURITY*)cached->variable)->acl,
		       &((struct POSIX_SECURITY*)item->variable)->acl, csize)));
#else
	return ((cached->uid != item->uid)
		 || (cached->gid != item->gid)
		 || (cached->dmode != item->dmode));
#endif
}

static int leg_compare(const struct CACHED_PERMISSIONS_LEGACY *cached,
			const struct CACHED_PERMISSIONS_LEGACY *item)
{
	return (cached->mft_no != item->mft_no);
}

/*
 *	Resize permission cache table
 *	do not call unless resizing is needed
 *	
 *	If allocation fails, the cache size is not updated
 *	Lack of memory is not considered as an error, the cache is left
 *	consistent and errno is not set.
 */

static void resize_cache(struct SECURITY_CONTEXT *scx,
			u32 securindex)
{
	struct PERMISSIONS_CACHE *oldcache;
	struct PERMISSIONS_CACHE *newcache;
	int newcnt;
	int oldcnt;
	unsigned int index1;
	unsigned int i;

	oldcache = *scx->pseccache;
	index1 = securindex >> CACHE_PERMISSIONS_BITS;
	newcnt = index1 + 1;
	if (newcnt <= ((CACHE_PERMISSIONS_SIZE
			+ (1 << CACHE_PERMISSIONS_BITS)
			- 1) >> CACHE_PERMISSIONS_BITS)) {
		/* expand cache beyond current end, do not use realloc() */
		/* to avoid losing data when there is no more memory */
		oldcnt = oldcache->head.last + 1;
		newcache = (struct PERMISSIONS_CACHE*)
			ntfs_malloc(
			    sizeof(struct PERMISSIONS_CACHE)
			      + (newcnt - 1)*sizeof(struct CACHED_PERMISSIONS*));
		if (newcache) {
			memcpy(newcache,oldcache,
			    sizeof(struct PERMISSIONS_CACHE)
			      + (oldcnt - 1)*sizeof(struct CACHED_PERMISSIONS*));
			free(oldcache);
			     /* mark new entries as not valid */
			for (i=newcache->head.last+1; i<=index1; i++)
				newcache->cachetable[i]
					 = (struct CACHED_PERMISSIONS*)NULL;
			newcache->head.last = index1;
			*scx->pseccache = newcache;
		}
	}
}

/*
 *	Enter uid, gid and mode into cache, if possible
 *
 *	returns the updated or created cache entry,
 *	or NULL if not possible (typically if there is no
 *		security id associated)
 */

#if POSIXACLS
static struct CACHED_PERMISSIONS *enter_cache(struct SECURITY_CONTEXT *scx,
		ntfs_inode *ni, uid_t uid, gid_t gid,
		struct POSIX_SECURITY *pxdesc)
#else
static struct CACHED_PERMISSIONS *enter_cache(struct SECURITY_CONTEXT *scx,
		ntfs_inode *ni, uid_t uid, gid_t gid, mode_t mode)
#endif
{
	struct CACHED_PERMISSIONS *cacheentry;
	struct CACHED_PERMISSIONS *cacheblock;
	struct PERMISSIONS_CACHE *pcache;
	u32 securindex;
#if POSIXACLS
	int pxsize;
	struct POSIX_SECURITY *pxcached;
#endif
	unsigned int index1;
	unsigned int index2;
	int i;

	/* cacheing is only possible if a security_id has been defined */
	if (test_nino_flag(ni, v3_Extensions)
	   && ni->security_id) {
		/*
		 *  Immediately test the most frequent situation
		 *  where the entry exists
		 */
		securindex = le32_to_cpu(ni->security_id);
		index1 = securindex >> CACHE_PERMISSIONS_BITS;
		index2 = securindex & ((1 << CACHE_PERMISSIONS_BITS) - 1);
		pcache = *scx->pseccache;
		if (pcache
		     && (pcache->head.last >= index1)
		     && pcache->cachetable[index1]) {
			cacheentry = &pcache->cachetable[index1][index2];
			cacheentry->uid = uid;
			cacheentry->gid = gid;
#if POSIXACLS
			if (cacheentry->pxdesc)
				free(cacheentry->pxdesc);
			if (pxdesc) {
				pxsize = sizeof(struct POSIX_SECURITY)
					+ (pxdesc->acccnt + pxdesc->defcnt)*sizeof(struct POSIX_ACE);
				pxcached = (struct POSIX_SECURITY*)malloc(pxsize);
				if (pxcached) {
					memcpy(pxcached, pxdesc, pxsize);
					cacheentry->pxdesc = pxcached;
				} else {
					cacheentry->valid = 0;
					cacheentry = (struct CACHED_PERMISSIONS*)NULL;
				}
				cacheentry->mode = pxdesc->mode & 07777;
			} else
				cacheentry->pxdesc = (struct POSIX_SECURITY*)NULL;
#else
			cacheentry->mode = mode & 07777;
#endif
			cacheentry->inh_fileid = cpu_to_le32(0);
			cacheentry->inh_dirid = cpu_to_le32(0);
			cacheentry->valid = 1;
			pcache->head.p_writes++;
		} else {
			if (!pcache) {
				/* create the first cache block */
				pcache = create_caches(scx, securindex);
			} else {
				if (index1 > pcache->head.last) {
					resize_cache(scx, securindex);
					pcache = *scx->pseccache;
				}
			}
			/* allocate block, if cache table was allocated */
			if (pcache && (index1 <= pcache->head.last)) {
				cacheblock = (struct CACHED_PERMISSIONS*)
					malloc(sizeof(struct CACHED_PERMISSIONS)
						<< CACHE_PERMISSIONS_BITS);
				pcache->cachetable[index1] = cacheblock;
				for (i=0; i<(1 << CACHE_PERMISSIONS_BITS); i++)
					cacheblock[i].valid = 0;
				cacheentry = &cacheblock[index2];
				if (cacheentry) {
					cacheentry->uid = uid;
					cacheentry->gid = gid;
#if POSIXACLS
					if (cacheentry->pxdesc)
						free(cacheentry->pxdesc);
					if (pxdesc) {
						pxsize = sizeof(struct POSIX_SECURITY)
							+ (pxdesc->acccnt + pxdesc->defcnt)*sizeof(struct POSIX_ACE);
						pxcached = (struct POSIX_SECURITY*)malloc(pxsize);
						if (pxcached) {
							memcpy(pxcached, pxdesc, pxsize);
							cacheentry->pxdesc = pxcached;
						} else {
							cacheentry->valid = 0;
							cacheentry = (struct CACHED_PERMISSIONS*)NULL;
						}
						cacheentry->mode = pxdesc->mode & 07777;
					} else
						cacheentry->pxdesc = (struct POSIX_SECURITY*)NULL;
#else
					cacheentry->mode = mode & 07777;
#endif
					cacheentry->inh_fileid = cpu_to_le32(0);
					cacheentry->inh_dirid = cpu_to_le32(0);
					cacheentry->valid = 1;
					pcache->head.p_writes++;
				}
			} else
				cacheentry = (struct CACHED_PERMISSIONS*)NULL;
		}
	} else {
		cacheentry = (struct CACHED_PERMISSIONS*)NULL;
#if CACHE_LEGACY_SIZE
		if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
			struct CACHED_PERMISSIONS_LEGACY wanted;
			struct CACHED_PERMISSIONS_LEGACY *legacy;

			wanted.perm.uid = uid;
			wanted.perm.gid = gid;
#if POSIXACLS
			wanted.perm.mode = pxdesc->mode & 07777;
			wanted.perm.inh_fileid = cpu_to_le32(0);
			wanted.perm.inh_dirid = cpu_to_le32(0);
			wanted.mft_no = ni->mft_no;
			wanted.variable = (void*)pxdesc;
			wanted.varsize = sizeof(struct POSIX_SECURITY)
					+ (pxdesc->acccnt + pxdesc->defcnt)*sizeof(struct POSIX_ACE);
#else
			wanted.perm.mode = mode & 07777;
			wanted.perm.inh_fileid = cpu_to_le32(0);
			wanted.perm.inh_dirid = cpu_to_le32(0);
			wanted.mft_no = ni->mft_no;
			wanted.variable = (void*)NULL;
			wanted.varsize = 0;
#endif
			legacy = (struct CACHED_PERMISSIONS_LEGACY*)ntfs_enter_cache(
				scx->vol->legacy_cache, GENERIC(&wanted),
				(cache_compare)leg_compare);
			if (legacy)
				cacheentry = &legacy->perm;
		}
#endif
	}
	return (cacheentry);
}

/*
 *	Fetch owner, group and permission of a file, if cached
 *
 *	Beware : do not use the returned entry after a cache update :
 *	the cache may be relocated making the returned entry meaningless
 *
 *	returns the cache entry, or NULL if not available
 */

static struct CACHED_PERMISSIONS *fetch_cache(struct SECURITY_CONTEXT *scx,
		ntfs_inode *ni)
{
	struct CACHED_PERMISSIONS *cacheentry;
	struct PERMISSIONS_CACHE *pcache;
	u32 securindex;
	unsigned int index1;
	unsigned int index2;

	/* cacheing is only possible if a security_id has been defined */
	cacheentry = (struct CACHED_PERMISSIONS*)NULL;
	if (test_nino_flag(ni, v3_Extensions)
	   && (ni->security_id)) {
		securindex = le32_to_cpu(ni->security_id);
		index1 = securindex >> CACHE_PERMISSIONS_BITS;
		index2 = securindex & ((1 << CACHE_PERMISSIONS_BITS) - 1);
		pcache = *scx->pseccache;
		if (pcache
		     && (pcache->head.last >= index1)
		     && pcache->cachetable[index1]) {
			cacheentry = &pcache->cachetable[index1][index2];
			/* reject if entry is not valid */
			if (!cacheentry->valid)
				cacheentry = (struct CACHED_PERMISSIONS*)NULL;
			else
				pcache->head.p_hits++;
		if (pcache)
			pcache->head.p_reads++;
		}
	}
#if CACHE_LEGACY_SIZE
	else {
		cacheentry = (struct CACHED_PERMISSIONS*)NULL;
		if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
			struct CACHED_PERMISSIONS_LEGACY wanted;
			struct CACHED_PERMISSIONS_LEGACY *legacy;

			wanted.mft_no = ni->mft_no;
			wanted.variable = (void*)NULL;
			wanted.varsize = 0;
			legacy = (struct CACHED_PERMISSIONS_LEGACY*)ntfs_fetch_cache(
				scx->vol->legacy_cache, GENERIC(&wanted),
				(cache_compare)leg_compare);
			if (legacy) cacheentry = &legacy->perm;
		}
	}
#endif
#if POSIXACLS
	if (cacheentry && !cacheentry->pxdesc) {
		ntfs_log_error("No Posix descriptor in cache\n");
		cacheentry = (struct CACHED_PERMISSIONS*)NULL;
	}
#endif
	return (cacheentry);
}

/*
 *	Retrieve a security attribute from $Secure
 */

static char *retrievesecurityattr(ntfs_volume *vol, SII_INDEX_KEY id)
{
	struct SII *psii;
	union {
		struct {
			le32 dataoffsl;
			le32 dataoffsh;
		} parts;
		le64 all;
	} realign;
	int found;
	size_t size;
	size_t rdsize;
	s64 offs;
	ntfs_inode *ni;
	ntfs_index_context *xsii;
	char *securattr;

	securattr = (char*)NULL;
	ni = vol->secure_ni;
	xsii = vol->secure_xsii;
	if (ni && xsii) {
		ntfs_index_ctx_reinit(xsii);
		found =
		    !ntfs_index_lookup((char*)&id,
				       sizeof(SII_INDEX_KEY), xsii);
		if (found) {
			psii = (struct SII*)xsii->entry;
			size =
			    (size_t) le32_to_cpu(psii->datasize)
				 - sizeof(SECURITY_DESCRIPTOR_HEADER);
			/* work around bad alignment problem */
			realign.parts.dataoffsh = psii->dataoffsh;
			realign.parts.dataoffsl = psii->dataoffsl;
			offs = le64_to_cpu(realign.all)
				+ sizeof(SECURITY_DESCRIPTOR_HEADER);

			securattr = (char*)ntfs_malloc(size);
			if (securattr) {
				rdsize = ntfs_local_read(
					ni, STREAM_SDS, 4,
					securattr, size, offs);
				if ((rdsize != size)
					|| !valid_securattr(securattr,
						rdsize)) {
					/* error to be logged by caller */
					free(securattr);
					securattr = (char*)NULL;
				}
			}
		} else
			if (errno != ENOENT)
				ntfs_log_perror("Inconsistency in index $SII");
	}
	if (!securattr) {
		ntfs_log_error("Failed to retrieve a security descriptor\n");
		errno = EIO;
	}
	return (securattr);
}

/*
 *		Build an ACL composed of several ACE's
 *	returns size of ACL or zero if failed
 *
 *	Three schemes are defined :
 *
 *	1) if root is neither owner nor group up to 7 ACE's are set up :
 *	- denials to owner (preventing grants to world or group to apply)
 *	- grants to owner (always present)
 *	- grants to group (unless group has no more than world rights)
 *	- denials to group (preventing grants to world to apply) 
 *	- grants to world (unless none)
 *	- full privileges to administrator, always present
 *	- full privileges to system, always present
 *
 *	The same scheme is applied for Posix ACLs, with the mask represented
 *	as denials prepended to grants for designated users and groups
 *
 *	This is inspired by an Internet Draft from Marius Aamodt Eriksen
 *	for mapping NFSv4 ACLs to Posix ACLs (draft-ietf-nfsv4-acl-mapping-00.txt)
 *
 *	Note that denials to group are located after grants to owner.
 *	This only occurs in the unfrequent situation where world
 *	has more rights than group and cannot be avoided if owner and other
 *	have some common right which is denied to group (eg for mode 745
 *	executing has to be denied to group, but not to owner or world).
 *	This rare situation is processed by Windows correctly, but
 *	Windows utilities may want to change the order, with a
 *	consequence of applying the group denials to the Windows owner.
 *	The interpretation on Linux is not affected by the order change.
 *
 *	2) if root is either owner or group, two problems arise :
 *	- granting full rights to administrator (as needed to transpose
 *	  to Windows rights bypassing granting to root) would imply
 *	  Linux permissions to always be seen as rwx, no matter the chmod
 *	- there is no different SID to separate an administrator owner
 *	  from an administrator group. Hence Linux permissions for owner
 *	  would always be similar to permissions to group.
 *
 *	as a work-around, up to 5 ACE's are set up if owner or group :
 *	- grants to owner, always present at first position
 *	- grants to group, always present
 *	- grants to world, unless none
 *	- full privileges to administrator, always present
 *	- full privileges to system, always present
 *
 *	On Windows, these ACE's are processed normally, though they
 *	are redundant (owner, group and administrator are the same,
 *	as a consequence any denials would damage administrator rights)
 *	but on Linux, privileges to administrator are ignored (they
 *	are not needed as root has always full privileges), and
 *	neither grants to group are applied to owner, nor grants to
 *	world are applied to owner or group.
 *
 *	3) finally a similar situation arises when group is owner (they
 *	 have the same SID), but is not root.
 *	 In this situation up to 6 ACE's are set up :
 *
 *	- denials to owner (preventing grants to world to apply)
 *	- grants to owner (always present)
 *	- grants to group (unless groups has same rights as world)
 *	- grants to world (unless none)
 *	- full privileges to administrator, always present
 *	- full privileges to system, always present
 *
 *	On Windows, these ACE's are processed normally, though they
 *	are redundant (as owner and group are the same), but this has
 *	no impact on administrator rights
 *
 *	Special flags (S_ISVTX, S_ISGID, S_ISUID) :
 *	an extra null ACE is inserted to hold these flags, using
 *	the same conventions as cygwin.
 *
 *	Limitations :
 *	- root cannot be a designated user or group. Full rights
 *	  are aways granted to root
 */

#if POSIXACLS

static int buildacls_posix(struct SECURITY_CONTEXT *scx,
		char *secattr, int offs, struct POSIX_SECURITY *pxdesc,
		int isdir, const SID *usid, const SID *gsid)
{
	struct {
		u16 grpperms;
		u16 othperms;
		u16 mask;
	} aceset[2], *pset;
	BOOL adminowns;
	BOOL groupowns;
	ACL *pacl;
	ACCESS_ALLOWED_ACE *pgace;
	ACCESS_ALLOWED_ACE *pdace;
	struct POSIX_ACE *pxace;
	BOOL cantmap;
	mode_t mode;
	u16 tag;
	u16 perms;
	u16 mixperms;
	ACE_FLAGS flags;
	int pos;
	int i;
	BIGSID defsid;
	const SID *sid;
	int sidsz;
	int acecnt;
	int usidsz;
	int gsidsz;
	int wsidsz;
	int asidsz;
	int ssidsz;
	int nsidsz;
	le32 grants;
	le32 denials;

	usidsz = sid_size(usid);
	gsidsz = sid_size(gsid);
	wsidsz = sid_size(worldsid);
	asidsz = sid_size(adminsid);
	ssidsz = sid_size(systemsid);
	mode = pxdesc->mode;
		/* adminowns and groupowns are used for both lists */
	adminowns = same_sid(usid, adminsid)
		 || same_sid(gsid, adminsid);
	groupowns = !adminowns && same_sid(usid, gsid);

	cantmap = FALSE;

	/* ACL header */
	pacl = (ACL*)&secattr[offs];
	pacl->revision = ACL_REVISION;
	pacl->alignment1 = 0;
	pacl->size = cpu_to_le16(sizeof(ACL) + usidsz + 8);
	pacl->ace_count = cpu_to_le16(1);
	pacl->alignment2 = cpu_to_le16(0);
	pos = sizeof(ACL);
	acecnt = 0;

		/*
		 * Determine what is allowed to some group or world
		 * to prevent designated users or other groups to get
		 * rights from groups or world
		 * Also get global mask
		 */
	aceset[0].grpperms = 0;
	aceset[0].othperms = 0;
	aceset[0].mask = (POSIX_PERM_R | POSIX_PERM_W | POSIX_PERM_X);
	aceset[1].grpperms = 0;
	aceset[1].othperms = 0;
	aceset[1].mask = (POSIX_PERM_R | POSIX_PERM_W | POSIX_PERM_X);

	for (i=pxdesc->acccnt+pxdesc->defcnt-1; i>=0; i--) {
		if (i >= pxdesc->acccnt) {
			pset = &aceset[1];
			pxace = &pxdesc->acl.ace[i + pxdesc->firstdef - pxdesc->acccnt];
		} else {
			pset = &aceset[0];
			pxace = &pxdesc->acl.ace[i];
		}
		switch (pxace->tag) {
		case POSIX_ACL_USER :
/* ! probably do no want root as designated user */
			if (!pxace->id)
				adminowns = TRUE;
			break;
		case POSIX_ACL_GROUP :
/* ! probably do no want root as designated group */
			if (!pxace->id)
				adminowns = TRUE;
			/* fall through */
		case POSIX_ACL_GROUP_OBJ :
			pset->grpperms |= pxace->perms;
			break;
		case POSIX_ACL_OTHER :
			pset->othperms = pxace->perms;
			break;
		case POSIX_ACL_MASK :
			pset->mask = pxace->perms;
		default :
			break;
		}
	}

if (pxdesc->defcnt && (pxdesc->firstdef != pxdesc->acccnt)) {
ntfs_log_error("** error : access and default not consecutive\n");
return (0);
}
	for (i=0; (i<(pxdesc->acccnt + pxdesc->defcnt)) && !cantmap; i++) {
		if (i >= pxdesc->acccnt) {
			flags = INHERIT_ONLY_ACE
				| OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
			pset = &aceset[1];
			pxace = &pxdesc->acl.ace[i + pxdesc->firstdef - pxdesc->acccnt];
		} else {
			flags = NO_PROPAGATE_INHERIT_ACE;
			pset = &aceset[0];
			pxace = &pxdesc->acl.ace[i];
		}
		tag = pxace->tag;
		perms = pxace->perms;
		switch (tag) {

			/* compute a grant ACE for each owner or allowed user */

		case POSIX_ACL_USER :
		case POSIX_ACL_USER_OBJ :
			if (tag == POSIX_ACL_USER_OBJ) {
				sid = usid;
				sidsz = usidsz;
				grants = OWNER_RIGHTS;
			} else {
				sid = find_usid(scx, pxace->id, (SID*)&defsid);
				if (sid) {
					sidsz = sid_size(sid);
					/*
					 * Insert denial of complement of mask for
					 * each designated user
					 * WRITE_OWNER is inserted so that
					 * the mask can be identified
					 */
					if (pset->mask != (POSIX_PERM_R | POSIX_PERM_W | POSIX_PERM_X)) {
						denials = WRITE_OWNER;
						pdace = (ACCESS_DENIED_ACE*) &secattr[offs + pos];
						if (isdir) {
							if (!(pset->mask & POSIX_PERM_X))
								denials |= DIR_EXEC;
							if (!(pset->mask & POSIX_PERM_W))
								denials |= DIR_WRITE;
							if (!(pset->mask & POSIX_PERM_R))
								denials |= DIR_READ;
						} else {
							if (!(pset->mask & POSIX_PERM_X))
								denials |= FILE_EXEC;
							if (!(pset->mask & POSIX_PERM_W))
								denials |= FILE_WRITE;
							if (!(pset->mask & POSIX_PERM_R))
								denials |= FILE_READ;
						}
						pdace->type = ACCESS_DENIED_ACE_TYPE;
						pdace->flags = flags;
						pdace->size = cpu_to_le16(sidsz + 8);
						pdace->mask = denials;
						memcpy((char*)&pdace->sid, sid, sidsz);
						pos += sidsz + 8;
						acecnt++;
					}
					grants = WORLD_RIGHTS;
				} else
					cantmap = TRUE;
			}
			if (!cantmap) {
				if (isdir) {
					if (perms & POSIX_PERM_X)
						grants |= DIR_EXEC;
					if (perms & POSIX_PERM_W)
						grants |= DIR_WRITE;
					if (perms & POSIX_PERM_R)
						grants |= DIR_READ;
				} else {
					if (perms & POSIX_PERM_X)
						grants |= FILE_EXEC;
					if (perms & POSIX_PERM_W)
						grants |= FILE_WRITE;
					if (perms & POSIX_PERM_R)
						grants |= FILE_READ;
				}

				/* a possible ACE to deny owner what he/she would */
				/* induely get from administrator, group or world */
				/* unless owner is administrator or group */

				denials = 0;
				pdace = (ACCESS_DENIED_ACE*) &secattr[offs + pos];
				if (!adminowns) {
					if (!groupowns) {
						mixperms = pset->grpperms | pset->othperms;
						if (isdir) {
							if (mixperms & POSIX_PERM_X)
								denials |= DIR_EXEC;
							if (mixperms & POSIX_PERM_W)
								denials |= DIR_WRITE;
							if (mixperms & POSIX_PERM_R)
								denials |= DIR_READ;
						} else {
							if (mixperms & POSIX_PERM_X)
								denials |= FILE_EXEC;
							if (mixperms & POSIX_PERM_W)
								denials |= FILE_WRITE;
							if (mixperms & POSIX_PERM_R)
								denials |= FILE_READ;
						}
					} else {
						mixperms = ~pset->grpperms & pset->othperms;
						if (isdir) {
							if (mixperms & POSIX_PERM_X)
								denials |= DIR_EXEC;
							if (mixperms & POSIX_PERM_W)
								denials |= DIR_WRITE;
							if (mixperms & POSIX_PERM_R)
								denials |= DIR_READ;
						} else {
							if (mixperms & POSIX_PERM_X)
								denials |= FILE_EXEC;
							if (mixperms & POSIX_PERM_W)
								denials |= FILE_WRITE;
							if (mixperms & POSIX_PERM_R)
								denials |= FILE_READ;
						}
					}
					denials &= ~grants;
					if (denials) {
						pdace->type = ACCESS_DENIED_ACE_TYPE;
						pdace->flags = flags;
						pdace->size = cpu_to_le16(sidsz + 8);
						pdace->mask = denials;
						memcpy((char*)&pdace->sid, sid, sidsz);
						pos += sidsz + 8;
						acecnt++;
					}
				}
			}
			break;
		default :
			break;
		}
	}

		/*
		 * for directories, a world execution denial
		 * inherited to plain files
		 */

	if (isdir) {
		pdace = (ACCESS_DENIED_ACE*) &secattr[offs + pos];
			pdace->type = ACCESS_DENIED_ACE_TYPE;
			pdace->flags = INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE;
			pdace->size = cpu_to_le16(wsidsz + 8);
			pdace->mask = FILE_EXEC;
			memcpy((char*)&pdace->sid, worldsid, wsidsz);
			pos += wsidsz + 8;
			acecnt++;
	}

	for (i=0; (i<(pxdesc->acccnt + pxdesc->defcnt)) && !cantmap; i++) {
		if (i >= pxdesc->acccnt) {
			flags = INHERIT_ONLY_ACE
				| OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
			pset = &aceset[1];
			pxace = &pxdesc->acl.ace[i + pxdesc->firstdef - pxdesc->acccnt];
		} else {
			flags = NO_PROPAGATE_INHERIT_ACE;
			pset = &aceset[0];
			pxace = &pxdesc->acl.ace[i];
		}
		tag = pxace->tag;
		perms = pxace->perms;
		switch (tag) {

			/* compute a grant ACE for each owner or allowed user */

		case POSIX_ACL_USER :
		case POSIX_ACL_USER_OBJ :
			if (tag == POSIX_ACL_USER_OBJ) {
				sid = usid;
				sidsz = usidsz;
				grants = OWNER_RIGHTS;
			} else {
				sid = find_usid(scx, pxace->id, (SID*)&defsid);
				if (sid)
					sidsz = sid_size(sid);
				else
					cantmap = TRUE;
				grants = WORLD_RIGHTS;
			}
			if (!cantmap) {
				if (isdir) {
					if (perms & POSIX_PERM_X)
						grants |= DIR_EXEC;
					if (perms & POSIX_PERM_W)
						grants |= DIR_WRITE;
					if (perms & POSIX_PERM_R)
						grants |= DIR_READ;
				} else {
					if (perms & POSIX_PERM_X)
						grants |= FILE_EXEC;
					if (perms & POSIX_PERM_W)
						grants |= FILE_WRITE;
					if (perms & POSIX_PERM_R)
						grants |= FILE_READ;
				}
				pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
				pgace->type = ACCESS_ALLOWED_ACE_TYPE;
				pgace->size = cpu_to_le16(sidsz + 8);
				pgace->flags = flags;
				pgace->mask = grants;
				memcpy((char*)&pgace->sid, sid, sidsz);
				pos += sidsz + 8;
				acecnt++;
			}
			break;

		case POSIX_ACL_GROUP :
		case POSIX_ACL_GROUP_OBJ :

			/* a grant ACE for group */
			/* unless group-obj has the same rights as world */
			/* but present if group is owner or owner is administrator */
			/* this ACE will be inserted after denials for group */

			if (tag == POSIX_ACL_GROUP_OBJ) {
				sid = gsid;
				sidsz = gsidsz;
			} else {
				sid = find_gsid(scx, pxace->id, (SID*)&defsid);
				if (sid) {
					sidsz = sid_size(sid);
					/*
					 * Insert denial of complement of mask for
					 * each designated user
					 * WRITE_OWNER is inserted so that
					 * the mask can be identified
					 */
					if (pset->mask != (POSIX_PERM_R | POSIX_PERM_W | POSIX_PERM_X)) {
						denials = WRITE_OWNER;
						pdace = (ACCESS_DENIED_ACE*) &secattr[offs + pos];
						if (isdir) {
							if (!(pset->mask & POSIX_PERM_X))
								denials |= DIR_EXEC;
							if (!(pset->mask & POSIX_PERM_W))
								denials |= DIR_WRITE;
							if (!(pset->mask & POSIX_PERM_R))
								denials |= DIR_READ;
						} else {
							if (!(pset->mask & POSIX_PERM_X))
								denials |= FILE_EXEC;
							if (!(pset->mask & POSIX_PERM_W))
								denials |= FILE_WRITE;
							if (!(pset->mask & POSIX_PERM_R))
								denials |= FILE_READ;
						}
						pdace->type = ACCESS_DENIED_ACE_TYPE;
						pdace->flags = flags;
						pdace->size = cpu_to_le16(sidsz + 8);
						pdace->mask = denials;
						memcpy((char*)&pdace->sid, sid, sidsz);
						pos += sidsz + 8;
						acecnt++;
					}
				} else
					cantmap = TRUE;
			}
			if (!cantmap
			    && (adminowns
				|| groupowns
				|| (perms != pset->othperms)
				|| (tag == POSIX_ACL_GROUP))) {
				grants = WORLD_RIGHTS;
				if (isdir) {
					if (perms & POSIX_PERM_X)
						grants |= DIR_EXEC;
					if (perms & POSIX_PERM_W)
						grants |= DIR_WRITE;
					if (perms & POSIX_PERM_R)
						grants |= DIR_READ;
				} else {
					if (perms & POSIX_PERM_X)
						grants |= FILE_EXEC;
					if (perms & POSIX_PERM_W)
						grants |= FILE_WRITE;
					if (perms & POSIX_PERM_R)
						grants |= FILE_READ;
				}

				/* a possible ACE to deny group what it would get from world */
				/* or administrator, unless owner is administrator or group */

				denials = 0;
				pdace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
				if (!adminowns && !groupowns) {
					mixperms = pset->othperms;
					if (isdir) {
						if (mixperms & POSIX_PERM_X)
							denials |= DIR_EXEC;
						if (mixperms & POSIX_PERM_W)
							denials |= DIR_WRITE;
						if (mixperms & POSIX_PERM_R)
							denials |= DIR_READ;
					} else {
						if (mixperms & POSIX_PERM_X)
							denials |= FILE_EXEC;
						if (mixperms & POSIX_PERM_W)
							denials |= FILE_WRITE;
						if (mixperms & POSIX_PERM_R)
							denials |= FILE_READ;
					}
					denials &= ~(grants | OWNER_RIGHTS);
					if (denials) {
						pdace->type = ACCESS_DENIED_ACE_TYPE;
						pdace->flags = flags;
						pdace->size = cpu_to_le16(sidsz + 8);
						pdace->mask = denials;
						memcpy((char*)&pdace->sid, sid, sidsz);
						pos += sidsz + 8;
						acecnt++;
					}
				}

					/* now insert grants to group if more than world */
				if (adminowns
					|| groupowns
					|| (perms & ~pset->othperms)
					|| (tag == POSIX_ACL_GROUP)) {
					pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
					pgace->type = ACCESS_ALLOWED_ACE_TYPE;
					pgace->flags = flags;
					pgace->size = cpu_to_le16(sidsz + 8);
					pgace->mask = grants;
					memcpy((char*)&pgace->sid, sid, sidsz);
					pos += sidsz + 8;
					acecnt++;
				}
			}
			break;

		case POSIX_ACL_OTHER :

			/* an ACE for world users */

			pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
			grants = WORLD_RIGHTS;
			if (isdir) {
				if (perms & POSIX_PERM_X)
					grants |= DIR_EXEC;
				if (perms & POSIX_PERM_W)
					grants |= DIR_WRITE;
				if (perms & POSIX_PERM_R)
					grants |= DIR_READ;
			} else {
				if (perms & POSIX_PERM_X)
					grants |= FILE_EXEC;
				if (perms & POSIX_PERM_W)
					grants |= FILE_WRITE;
				if (perms & POSIX_PERM_R)
					grants |= FILE_READ;
			}
			pgace->type = ACCESS_ALLOWED_ACE_TYPE;
			pgace->flags = flags;
			pgace->size = cpu_to_le16(wsidsz + 8);
			pgace->mask = grants;
			memcpy((char*)&pgace->sid, worldsid, wsidsz);
			pos += wsidsz + 8;
			acecnt++;
			break;
		}
	}

	if (cantmap)
		errno = EINVAL;
	else {
		/* an ACE for administrators */
		/* always full access */

		if (isdir)
			flags = OBJECT_INHERIT_ACE
				| CONTAINER_INHERIT_ACE;
		else
			flags = NO_PROPAGATE_INHERIT_ACE;
		pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
		pgace->type = ACCESS_ALLOWED_ACE_TYPE;
		pgace->flags = flags;
		pgace->size = cpu_to_le16(asidsz + 8);
		grants = OWNER_RIGHTS | FILE_READ | FILE_WRITE | FILE_EXEC;
		pgace->mask = grants;
		memcpy((char*)&pgace->sid, adminsid, asidsz);
		pos += asidsz + 8;
		acecnt++;

		/* an ACE for system (needed ?) */
		/* always full access */

		pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
		pgace->type = ACCESS_ALLOWED_ACE_TYPE;
		pgace->flags = flags;
		pgace->size = cpu_to_le16(ssidsz + 8);
		grants = OWNER_RIGHTS | FILE_READ | FILE_WRITE | FILE_EXEC;
		pgace->mask = grants;
		memcpy((char*)&pgace->sid, systemsid, ssidsz);
		pos += ssidsz + 8;
		acecnt++;

		/* a null ACE to hold special flags */
		/* using the same representation as cygwin */

		if (mode & (S_ISVTX | S_ISGID | S_ISUID)) {
			nsidsz = sid_size(nullsid);
			pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
			pgace->type = ACCESS_ALLOWED_ACE_TYPE;
			pgace->flags = NO_PROPAGATE_INHERIT_ACE;
			pgace->size = cpu_to_le16(nsidsz + 8);
			grants = 0;
			if (mode & S_ISUID)
				grants |= FILE_APPEND_DATA;
			if (mode & S_ISGID)
				grants |= FILE_WRITE_DATA;
			if (mode & S_ISVTX)
				grants |= FILE_READ_DATA;
			pgace->mask = grants;
			memcpy((char*)&pgace->sid, nullsid, nsidsz);
			pos += nsidsz + 8;
			acecnt++;
		}

		/* fix ACL header */
		pacl->size = cpu_to_le16(pos);
		pacl->ace_count = cpu_to_le16(acecnt);
	}
	return (cantmap ? 0 : pos);
}

#endif

static int buildacls(char *secattr, int offs, mode_t mode, int isdir,
	       const SID * usid, const SID * gsid)
{
	ACL *pacl;
	ACCESS_ALLOWED_ACE *pgace;
	ACCESS_ALLOWED_ACE *pdace;
	BOOL adminowns;
	BOOL groupowns;
	ACE_FLAGS gflags;
	int pos;
	int acecnt;
	int usidsz;
	int gsidsz;
	int wsidsz;
	int asidsz;
	int ssidsz;
	int nsidsz;
	le32 grants;
	le32 denials;

	usidsz = sid_size(usid);
	gsidsz = sid_size(gsid);
	wsidsz = sid_size(worldsid);
	asidsz = sid_size(adminsid);
	ssidsz = sid_size(systemsid);
	adminowns = same_sid(usid, adminsid)
	         || same_sid(gsid, adminsid);
	groupowns = !adminowns && same_sid(usid, gsid);

	/* ACL header */
	pacl = (ACL*)&secattr[offs];
	pacl->revision = ACL_REVISION;
	pacl->alignment1 = 0;
	pacl->size = cpu_to_le16(sizeof(ACL) + usidsz + 8);
	pacl->ace_count = cpu_to_le16(1);
	pacl->alignment2 = cpu_to_le16(0);
	pos = sizeof(ACL);
	acecnt = 0;

	/* compute a grant ACE for owner */
	/* this ACE will be inserted after denial for owner */

	grants = OWNER_RIGHTS;
	if (isdir) {
		gflags = DIR_INHERITANCE;
		if (mode & S_IXUSR)
			grants |= DIR_EXEC;
		if (mode & S_IWUSR)
			grants |= DIR_WRITE;
		if (mode & S_IRUSR)
			grants |= DIR_READ;
	} else {
		gflags = FILE_INHERITANCE;
		if (mode & S_IXUSR)
			grants |= FILE_EXEC;
		if (mode & S_IWUSR)
			grants |= FILE_WRITE;
		if (mode & S_IRUSR)
			grants |= FILE_READ;
	}

	/* a possible ACE to deny owner what he/she would */
	/* induely get from administrator, group or world */
        /* unless owner is administrator or group */

	denials = 0;
	pdace = (ACCESS_DENIED_ACE*) &secattr[offs + pos];
	if (!adminowns) {
		if (!groupowns) {
			if (isdir) {
				pdace->flags = DIR_INHERITANCE;
				if (mode & (S_IXGRP | S_IXOTH))
					denials |= DIR_EXEC;
				if (mode & (S_IWGRP | S_IWOTH))
					denials |= DIR_WRITE;
				if (mode & (S_IRGRP | S_IROTH))
					denials |= DIR_READ;
			} else {
				pdace->flags = FILE_INHERITANCE;
				if (mode & (S_IXGRP | S_IXOTH))
					denials |= FILE_EXEC;
				if (mode & (S_IWGRP | S_IWOTH))
					denials |= FILE_WRITE;
				if (mode & (S_IRGRP | S_IROTH))
					denials |= FILE_READ;
			}
		} else {
			if (isdir) {
				pdace->flags = DIR_INHERITANCE;
				if ((mode & S_IXOTH) && !(mode & S_IXGRP))
					denials |= DIR_EXEC;
				if ((mode & S_IWOTH) && !(mode & S_IWGRP))
					denials |= DIR_WRITE;
				if ((mode & S_IROTH) && !(mode & S_IRGRP))
					denials |= DIR_READ;
			} else {
				pdace->flags = FILE_INHERITANCE;
				if ((mode & S_IXOTH) && !(mode & S_IXGRP))
					denials |= FILE_EXEC;
				if ((mode & S_IWOTH) && !(mode & S_IWGRP))
					denials |= FILE_WRITE;
				if ((mode & S_IROTH) && !(mode & S_IRGRP))
					denials |= FILE_READ;
			}
		}
		denials &= ~grants;
		if (denials) {
			pdace->type = ACCESS_DENIED_ACE_TYPE;
			pdace->size = cpu_to_le16(usidsz + 8);
			pdace->mask = denials;
			memcpy((char*)&pdace->sid, usid, usidsz);
			pos += usidsz + 8;
			acecnt++;
		}
	}
		/*
		 * for directories, a world execution denial
		 * inherited to plain files
		 */

	if (isdir) {
		pdace = (ACCESS_DENIED_ACE*) &secattr[offs + pos];
			pdace->type = ACCESS_DENIED_ACE_TYPE;
			pdace->flags = INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE;
			pdace->size = cpu_to_le16(wsidsz + 8);
			pdace->mask = FILE_EXEC;
			memcpy((char*)&pdace->sid, worldsid, wsidsz);
			pos += wsidsz + 8;
			acecnt++;
	}


		/* now insert grants to owner */
	pgace = (ACCESS_ALLOWED_ACE*) &secattr[offs + pos];
	pgace->type = ACCESS_ALLOWED_ACE_TYPE;
	pgace->size = cpu_to_le16(usidsz + 8);
	pgace->flags = gflags;
	pgace->mask = grants;
	memcpy((char*)&pgace->sid, usid, usidsz);
	pos += usidsz + 8;
	acecnt++;

	/* a grant ACE for group */
	/* unless group has the same rights as world */
	/* but present if group is owner or owner is administrator */
	/* this ACE will be inserted after denials for group */

	if (adminowns
	    || groupowns
	    || (((mode >> 3) ^ mode) & 7)) {
		grants = WORLD_RIGHTS;
		if (isdir) {
			gflags = DIR_INHERITANCE;
			if (mode & S_IXGRP)
				grants |= DIR_EXEC;
			if (mode & S_IWGRP)
				grants |= DIR_WRITE;
			if (mode & S_IRGRP)
				grants |= DIR_READ;
		} else {
			gflags = FILE_INHERITANCE;
			if (mode & S_IXGRP)
				grants |= FILE_EXEC;
			if (mode & S_IWGRP)
				grants |= FILE_WRITE;
			if (mode & S_IRGRP)
				grants |= FILE_READ;
		}

		/* a possible ACE to deny group what it would get from world */
		/* or administrator, unless owner is administrator or group */

		denials = 0;
		pdace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
		if (!adminowns && !groupowns) {
			if (isdir) {
				pdace->flags = DIR_INHERITANCE;
				if (mode & S_IXOTH)
					denials |= DIR_EXEC;
				if (mode & S_IWOTH)
					denials |= DIR_WRITE;
				if (mode & S_IROTH)
					denials |= DIR_READ;
			} else {
				pdace->flags = FILE_INHERITANCE;
				if (mode & S_IXOTH)
					denials |= FILE_EXEC;
				if (mode & S_IWOTH)
					denials |= FILE_WRITE;
				if (mode & S_IROTH)
					denials |= FILE_READ;
			}
			denials &= ~(grants | OWNER_RIGHTS);
			if (denials) {
				pdace->type = ACCESS_DENIED_ACE_TYPE;
				pdace->size = cpu_to_le16(gsidsz + 8);
				pdace->mask = denials;
				memcpy((char*)&pdace->sid, gsid, gsidsz);
				pos += gsidsz + 8;
				acecnt++;
			}
		}

		if (adminowns
		   || groupowns
		   || ((mode >> 3) & ~mode & 7)) {
				/* now insert grants to group */
				/* if more rights than other */
			pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
			pgace->type = ACCESS_ALLOWED_ACE_TYPE;
			pgace->flags = gflags;
			pgace->size = cpu_to_le16(gsidsz + 8);
			pgace->mask = grants;
			memcpy((char*)&pgace->sid, gsid, gsidsz);
			pos += gsidsz + 8;
			acecnt++;
		}
	}

	/* an ACE for world users */

	pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
	pgace->type = ACCESS_ALLOWED_ACE_TYPE;
	grants = WORLD_RIGHTS;
	if (isdir) {
		pgace->flags = DIR_INHERITANCE;
		if (mode & S_IXOTH)
			grants |= DIR_EXEC;
		if (mode & S_IWOTH)
			grants |= DIR_WRITE;
		if (mode & S_IROTH)
			grants |= DIR_READ;
	} else {
		pgace->flags = FILE_INHERITANCE;
		if (mode & S_IXOTH)
			grants |= FILE_EXEC;
		if (mode & S_IWOTH)
			grants |= FILE_WRITE;
		if (mode & S_IROTH)
			grants |= FILE_READ;
	}
	pgace->size = cpu_to_le16(wsidsz + 8);
	pgace->mask = grants;
	memcpy((char*)&pgace->sid, worldsid, wsidsz);
	pos += wsidsz + 8;
	acecnt++;

	/* an ACE for administrators */
	/* always full access */

	pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
	pgace->type = ACCESS_ALLOWED_ACE_TYPE;
	if (isdir)
		pgace->flags = DIR_INHERITANCE;
	else
		pgace->flags = FILE_INHERITANCE;
	pgace->size = cpu_to_le16(asidsz + 8);
	grants = OWNER_RIGHTS | FILE_READ | FILE_WRITE | FILE_EXEC;
	pgace->mask = grants;
	memcpy((char*)&pgace->sid, adminsid, asidsz);
	pos += asidsz + 8;
	acecnt++;

	/* an ACE for system (needed ?) */
	/* always full access */

	pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
	pgace->type = ACCESS_ALLOWED_ACE_TYPE;
	if (isdir)
		pgace->flags = DIR_INHERITANCE;
	else
		pgace->flags = FILE_INHERITANCE;
	pgace->size = cpu_to_le16(ssidsz + 8);
	grants = OWNER_RIGHTS | FILE_READ | FILE_WRITE | FILE_EXEC;
	pgace->mask = grants;
	memcpy((char*)&pgace->sid, systemsid, ssidsz);
	pos += ssidsz + 8;
	acecnt++;

	/* a null ACE to hold special flags */
	/* using the same representation as cygwin */

	if (mode & (S_ISVTX | S_ISGID | S_ISUID)) {
		nsidsz = sid_size(nullsid);
		pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
		pgace->type = ACCESS_ALLOWED_ACE_TYPE;
		pgace->flags = NO_PROPAGATE_INHERIT_ACE;
		pgace->size = cpu_to_le16(nsidsz + 8);
		grants = 0;
		if (mode & S_ISUID)
			grants |= FILE_APPEND_DATA;
		if (mode & S_ISGID)
			grants |= FILE_WRITE_DATA;
		if (mode & S_ISVTX)
			grants |= FILE_READ_DATA;
		pgace->mask = grants;
		memcpy((char*)&pgace->sid, nullsid, nsidsz);
		pos += nsidsz + 8;
		acecnt++;
	}

	/* fix ACL header */
	pacl->size = cpu_to_le16(pos);
	pacl->ace_count = cpu_to_le16(acecnt);
	return (pos);
}

#if POSIXACLS

/*
 *		Build a full security descriptor from a Posix ACL
 *	returns descriptor in allocated memory, must free() after use
 */

static char *build_secur_descr_posix(struct SECURITY_CONTEXT *scx,
			struct POSIX_SECURITY *pxdesc,
			int isdir, const SID *usid, const SID *gsid)
{
	int newattrsz;
	SECURITY_DESCRIPTOR_RELATIVE *pnhead;
	char *newattr;
	int aclsz;
	int usidsz;
	int gsidsz;
	int wsidsz;
	int asidsz;
	int ssidsz;
	int k;

	usidsz = sid_size(usid);
	gsidsz = sid_size(gsid);
	wsidsz = sid_size(worldsid);
	asidsz = sid_size(adminsid);
	ssidsz = sid_size(systemsid);

	/* allocate enough space for the new security attribute */
	newattrsz = sizeof(SECURITY_DESCRIPTOR_RELATIVE)	/* header */
	    + usidsz + gsidsz	/* usid and gsid */
	    + sizeof(ACL)	/* acl header */
	    + 2*(8 + usidsz)	/* two possible ACE for user */
	    + 2*(8 + gsidsz)	/* two possible ACE for group */
	    + 8 + wsidsz	/* one ACE for world */
	    + 8 + asidsz	/* one ACE for admin */
	    + 8 + ssidsz;	/* one ACE for system */
	if (isdir)			/* a world denial for directories */
		newattrsz += 8 + wsidsz;
	if (pxdesc->mode & 07000)	/* a NULL ACE for special modes */
		newattrsz += 8 + sid_size(nullsid);
				/* account for non-owning users and groups */
	for (k=0; k<pxdesc->acccnt; k++) {
		if ((pxdesc->acl.ace[k].tag == POSIX_ACL_USER)
		    || (pxdesc->acl.ace[k].tag == POSIX_ACL_GROUP))
			newattrsz += 3*40; /* fixme : maximum size */
	}
				/* account for default ACE's */
	newattrsz += 2*40*pxdesc->defcnt;  /* fixme : maximum size */
	newattr = (char*)ntfs_malloc(newattrsz);
	if (newattr) {
		/* build the main header part */
		pnhead = (SECURITY_DESCRIPTOR_RELATIVE*)newattr;
		pnhead->revision = SECURITY_DESCRIPTOR_REVISION;
		pnhead->alignment = 0;
			/*
			 * The flag SE_DACL_PROTECTED prevents the ACL
			 * to be changed in an inheritance after creation
			 */
		pnhead->control = SE_DACL_PRESENT | SE_DACL_PROTECTED
				    | SE_SELF_RELATIVE;
			/*
			 * Windows prefers ACL first, do the same to
			 * get the same hash value and avoid duplication
			 */
		/* build permissions */
		aclsz = buildacls_posix(scx,newattr,
			  sizeof(SECURITY_DESCRIPTOR_RELATIVE),
			  pxdesc, isdir, usid, gsid);
		if (aclsz && ((aclsz + usidsz + gsidsz) <= newattrsz)) {
			/* append usid and gsid */
			memcpy(&newattr[sizeof(SECURITY_DESCRIPTOR_RELATIVE)
				 + aclsz], usid, usidsz);
			memcpy(&newattr[sizeof(SECURITY_DESCRIPTOR_RELATIVE)
				+ aclsz + usidsz], gsid, gsidsz);
			/* positions of ACL, USID and GSID into header */
			pnhead->owner =
			    cpu_to_le32(sizeof(SECURITY_DESCRIPTOR_RELATIVE)
				 + aclsz);
			pnhead->group =
			    cpu_to_le32(sizeof(SECURITY_DESCRIPTOR_RELATIVE)
				 + aclsz + usidsz);
			pnhead->sacl = cpu_to_le32(0);
			pnhead->dacl =
			    cpu_to_le32(sizeof(SECURITY_DESCRIPTOR_RELATIVE));
		} else {
			/* ACL failure (errno set) or overflow */
			free(newattr);
			newattr = (char*)NULL;
			if (aclsz) {
				/* hope error was detected before overflowing */
				ntfs_log_error("Security descriptor is longer than expected\n");
				errno = EIO;
			}
		}
	} else
		errno = ENOMEM;
	return (newattr);
}

#endif

/*
 *		Build a full security descriptor
 *	returns descriptor in allocated memory, must free() after use
 */

static char *build_secur_descr(mode_t mode,
			int isdir, const SID * usid, const SID * gsid)
{
	int newattrsz;
	SECURITY_DESCRIPTOR_RELATIVE *pnhead;
	char *newattr;
	int aclsz;
	int usidsz;
	int gsidsz;
	int wsidsz;
	int asidsz;
	int ssidsz;

	usidsz = sid_size(usid);
	gsidsz = sid_size(gsid);
	wsidsz = sid_size(worldsid);
	asidsz = sid_size(adminsid);
	ssidsz = sid_size(systemsid);

	/* allocate enough space for the new security attribute */
	newattrsz = sizeof(SECURITY_DESCRIPTOR_RELATIVE)	/* header */
	    + usidsz + gsidsz	/* usid and gsid */
	    + sizeof(ACL)	/* acl header */
	    + 2*(8 + usidsz)	/* two possible ACE for user */
	    + 2*(8 + gsidsz)	/* two possible ACE for group */
	    + 8 + wsidsz	/* one ACE for world */
	    + 8 + asidsz 	/* one ACE for admin */
	    + 8 + ssidsz;	/* one ACE for system */
	if (isdir)			/* a world denial for directories */
		newattrsz += 8 + wsidsz;
	if (mode & 07000)	/* a NULL ACE for special modes */
		newattrsz += 8 + sid_size(nullsid);
	newattr = (char*)ntfs_malloc(newattrsz);
	if (newattr) {
		/* build the main header part */
		pnhead = (SECURITY_DESCRIPTOR_RELATIVE*) newattr;
		pnhead->revision = SECURITY_DESCRIPTOR_REVISION;
		pnhead->alignment = 0;
			/*
			 * The flag SE_DACL_PROTECTED prevents the ACL
			 * to be changed in an inheritance after creation
			 */
		pnhead->control = SE_DACL_PRESENT | SE_DACL_PROTECTED
				    | SE_SELF_RELATIVE;
			/*
			 * Windows prefers ACL first, do the same to
			 * get the same hash value and avoid duplication
			 */
		/* build permissions */
		aclsz = buildacls(newattr,
			  sizeof(SECURITY_DESCRIPTOR_RELATIVE),
			  mode, isdir, usid, gsid);
		if ((aclsz + usidsz + gsidsz) <= newattrsz) {
			/* append usid and gsid */
			memcpy(&newattr[sizeof(SECURITY_DESCRIPTOR_RELATIVE)
				 + aclsz], usid, usidsz);
			memcpy(&newattr[sizeof(SECURITY_DESCRIPTOR_RELATIVE)
				+ aclsz + usidsz], gsid, gsidsz);
			/* positions of ACL, USID and GSID into header */
			pnhead->owner =
			    cpu_to_le32(sizeof(SECURITY_DESCRIPTOR_RELATIVE)
				 + aclsz);
			pnhead->group =
			    cpu_to_le32(sizeof(SECURITY_DESCRIPTOR_RELATIVE)
				 + aclsz + usidsz);
			pnhead->sacl = cpu_to_le32(0);
			pnhead->dacl =
			    cpu_to_le32(sizeof(SECURITY_DESCRIPTOR_RELATIVE));
		} else {
			/* hope error was detected before overflowing */
			free(newattr);
			newattr = (char*)NULL;
			ntfs_log_error("Security descriptor is longer than expected\n");
			errno = EIO;
		}
	} else
		errno = ENOMEM;
	return (newattr);
}

/*
 *		Create a mode_t permission set
 *	from owner, group and world grants as represented in ACEs
 */

static int merge_permissions(ntfs_inode *ni,
		le32 owner, le32 group, le32 world, le32 special)

{
	int perm;

	perm = 0;
	/* build owner permission */
	if (owner) {
		if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
			/* exec if any of list, traverse */
			if (owner & DIR_GEXEC)
				perm |= S_IXUSR;
			/* write if any of addfile, adddir, delchild */
			if (owner & DIR_GWRITE)
				perm |= S_IWUSR;
			/* read if any of list */
			if (owner & DIR_GREAD)
				perm |= S_IRUSR;
		} else {
			/* exec if execute or generic execute */
			if (owner & FILE_GEXEC)
				perm |= S_IXUSR;
			/* write if any of writedata or generic write */
			if (owner & FILE_GWRITE)
				perm |= S_IWUSR;
			/* read if any of readdata or generic read */
			if (owner & FILE_GREAD)
				perm |= S_IRUSR;
		}
	}
	/* build group permission */
	if (group) {
		if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
			/* exec if any of list, traverse */
			if (group & DIR_GEXEC)
				perm |= S_IXGRP;
			/* write if any of addfile, adddir, delchild */
			if (group & DIR_GWRITE)
				perm |= S_IWGRP;
			/* read if any of list */
			if (group & DIR_GREAD)
				perm |= S_IRGRP;
		} else {
			/* exec if execute */
			if (group & FILE_GEXEC)
				perm |= S_IXGRP;
			/* write if any of writedata, appenddata */
			if (group & FILE_GWRITE)
				perm |= S_IWGRP;
			/* read if any of readdata */
			if (group & FILE_GREAD)
				perm |= S_IRGRP;
		}
	}
	/* build world permission */
	if (world) {
		if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
			/* exec if any of list, traverse */
			if (world & DIR_GEXEC)
				perm |= S_IXOTH;
			/* write if any of addfile, adddir, delchild */
			if (world & DIR_GWRITE)
				perm |= S_IWOTH;
			/* read if any of list */
			if (world & DIR_GREAD)
				perm |= S_IROTH;
		} else {
			/* exec if execute */
			if (world & FILE_GEXEC)
				perm |= S_IXOTH;
			/* write if any of writedata, appenddata */
			if (world & FILE_GWRITE)
				perm |= S_IWOTH;
			/* read if any of readdata */
			if (world & FILE_GREAD)
				perm |= S_IROTH;
		}
	}
	/* build special permission flags */
	if (special) {
		if (special & FILE_APPEND_DATA)
			perm |= S_ISUID;
		if (special & FILE_WRITE_DATA)
			perm |= S_ISGID;
		if (special & FILE_READ_DATA)
			perm |= S_ISVTX;
	}
	return (perm);
}

#if POSIXACLS

/*
 *		Normalize a Posix ACL either from a sorted raw set of
 *		access ACEs or default ACEs
 *		(standard case : different owner, group and administrator)
 */

static int norm_std_permissions_posix(struct POSIX_SECURITY *posix_desc,
		BOOL groupowns, int start, int count, int target)
{
	int j,k;
	s32 id;
	u16 tag;
	u16 tagsset;
	struct POSIX_ACE *pxace;
	mode_t grantgrps;
	mode_t grantwrld;
	mode_t denywrld;
	mode_t allow;
	mode_t deny;
	mode_t perms;
	mode_t mode;

	mode = 0;
	tagsset = 0;
		/*
		 * Determine what is granted to some group or world
		 * Also get denials to world which are meant to prevent
		 * execution flags to be inherited by plain files
		 */
	pxace = posix_desc->acl.ace;
	grantgrps = 0;
	grantwrld = 0;
	denywrld = 0;
	for (j=start; j<(start + count); j++) {
		if (pxace[j].perms & POSIX_PERM_DENIAL) {
				/* deny world exec unless for default */
			if ((pxace[j].tag == POSIX_ACL_OTHER)
			&& !start)
				denywrld = pxace[j].perms;
		} else {
			switch (pxace[j].tag) {
			case POSIX_ACL_GROUP_OBJ :
			case POSIX_ACL_GROUP :
				grantgrps |= pxace[j].perms;
				break;
			case POSIX_ACL_OTHER :
				grantwrld = pxace[j].perms;
				break;
			default :
				break;
			}
		}
	}
		/*
		 * Collect groups of ACEs related to the same id
		 * and determine what is granted and what is denied.
		 * It is important the ACEs have been sorted
		 */
	j = start;
	k = target;
	while (j < (start + count)) {
		tag = pxace[j].tag;
		id = pxace[j].id;
		if (pxace[j].perms & POSIX_PERM_DENIAL) {
			deny = pxace[j].perms | denywrld;
			allow = 0;
		} else {
			deny = denywrld;
			allow = pxace[j].perms;
		}
		j++;
		while ((j < (start + count))
		    && (pxace[j].tag == tag)
		    && (pxace[j].id == id)) {
			if (pxace[j].perms & POSIX_PERM_DENIAL)
				deny |= pxace[j].perms;
			else
				allow |= pxace[j].perms;
			j++;
		}
			/*
			 * Build the permissions equivalent to grants and denials
			 */
		if (groupowns) {
			if (tag == POSIX_ACL_MASK)
				perms = ~deny;
			else
				perms = allow & ~deny;
		} else
			switch (tag) {
			case POSIX_ACL_USER_OBJ :
			case POSIX_ACL_USER :
				perms = (allow | grantgrps | grantwrld) & ~deny;
				break;
			case POSIX_ACL_GROUP_OBJ :
			case POSIX_ACL_GROUP :
				perms = (allow | grantwrld) & ~deny;
				break;
			case POSIX_ACL_MASK :
				perms = ~deny;
				break;
			default :
				perms = allow & ~deny;
				break;
			}
			/*
			 * Store into a Posix ACE
			 */
		if (tag != POSIX_ACL_SPECIAL) {
			pxace[k].tag = tag;
			pxace[k].id = id;
			pxace[k].perms = perms
				 & (POSIX_PERM_R | POSIX_PERM_W | POSIX_PERM_X);
			tagsset |= tag;
			k++;
		}
		switch (tag) {
		case POSIX_ACL_USER_OBJ :
			mode |= ((perms & 7) << 6);
			break;
		case POSIX_ACL_GROUP_OBJ :
		case POSIX_ACL_MASK :
			mode = (mode & 07707) | ((perms & 7) << 3);
			break;
		case POSIX_ACL_OTHER :
			mode |= perms & 7;
			break;
		case POSIX_ACL_SPECIAL :
			mode |= (perms & (S_ISVTX | S_ISUID | S_ISGID));
			break;
		default :
			break;
		}
	}
	if (!start) { /* not satisfactory */
		posix_desc->mode = mode;
		posix_desc->tagsset = tagsset;
	}
	return (k - target);
}

#endif

/*
 *		Interpret an ACL and extract meaningful grants
 *		(standard case : different owner, group and administrator)
 */

static int build_std_permissions(const char *securattr,
		const SID *usid, const SID *gsid, ntfs_inode *ni)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const ACL *pacl;
	const ACCESS_ALLOWED_ACE *pace;
	int offdacl;
	int offace;
	int acecnt;
	int nace;
	BOOL noown;
	le32 special;
	le32 allowown, allowgrp, allowall;
	le32 denyown, denygrp, denyall;

	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)securattr;
	offdacl = le32_to_cpu(phead->dacl);
	pacl = (const ACL*)&securattr[offdacl];
	special = cpu_to_le32(0);
	allowown = allowgrp = allowall = cpu_to_le32(0);
	denyown = denygrp = denyall = cpu_to_le32(0);
	noown = TRUE;
	if (offdacl) {
		acecnt = le16_to_cpu(pacl->ace_count);
		offace = offdacl + sizeof(ACL);
	} else
		acecnt = 0;
	for (nace = 0; nace < acecnt; nace++) {
		pace = (const ACCESS_ALLOWED_ACE*)&securattr[offace];
		if (!(pace->flags & INHERIT_ONLY_ACE)) {
			if (same_sid(usid, &pace->sid)
			  || same_sid(ownersid, &pace->sid)) {
				noown = FALSE;
				if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
					allowown |= pace->mask;
				else if (pace->type == ACCESS_DENIED_ACE_TYPE)
					denyown |= pace->mask;
				} else
				if (same_sid(gsid, &pace->sid)) {
					if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
						allowgrp |= pace->mask;
					else if (pace->type == ACCESS_DENIED_ACE_TYPE)
						denygrp |= pace->mask;
				} else
					if (is_world_sid((const SID*)&pace->sid)) {
						if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
							allowall |= pace->mask;
						else
							if (pace->type == ACCESS_DENIED_ACE_TYPE)
								denyall |= pace->mask;
					} else
					if ((same_sid((const SID*)&pace->sid,nullsid))
					   && (pace->type == ACCESS_ALLOWED_ACE_TYPE))
						special |= pace->mask;
			}
			offace += le16_to_cpu(pace->size);
		}
		/*
		 * No indication about owner's rights : grant basic rights
		 * This happens for files created by Windows in directories
		 * created by Linux and owned by root, because Windows
		 * merges the admin ACEs
		 */
	if (noown)
		allowown = (FILE_READ_DATA | FILE_WRITE_DATA | FILE_EXECUTE);
		/*
		 *  Add to owner rights granted to group or world
		 * unless denied personaly, and add to group rights
		 * granted to world unless denied specifically
		 */
	allowown |= (allowgrp | allowall);
	allowgrp |= allowall;
	return (merge_permissions(ni,
				allowown & ~(denyown | denyall),
				allowgrp & ~(denygrp | denyall),
				allowall & ~denyall,
				special));
}

/*
 *		Interpret an ACL and extract meaningful grants
 *		(special case : owner and group are the same,
 *		and not administrator)
 */

static int build_owngrp_permissions(const char *securattr,
			const SID *usid, ntfs_inode *ni)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const ACL *pacl;
	const ACCESS_ALLOWED_ACE *pace;
	int offdacl;
	int offace;
	int acecnt;
	int nace;
	le32 special;
	BOOL grppresent;
	le32 allowown, allowgrp, allowall;
	le32 denyown, denygrp, denyall;

	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)securattr;
	offdacl = le32_to_cpu(phead->dacl);
	pacl = (const ACL*)&securattr[offdacl];
	special = cpu_to_le32(0);
	allowown = allowgrp = allowall = cpu_to_le32(0);
	denyown = denygrp = denyall = cpu_to_le32(0);
	grppresent = FALSE;
	if (offdacl) {
		acecnt = le16_to_cpu(pacl->ace_count);
		offace = offdacl + sizeof(ACL);
	} else
		acecnt = 0;
	for (nace = 0; nace < acecnt; nace++) {
		pace = (const ACCESS_ALLOWED_ACE*)&securattr[offace];
		if (!(pace->flags & INHERIT_ONLY_ACE)) {
			if ((same_sid(usid, &pace->sid)
			   || same_sid(ownersid, &pace->sid))
			    && (pace->mask & WRITE_OWNER)) {
				if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
					allowown |= pace->mask;
				} else
				if (same_sid(usid, &pace->sid)
				   && (!(pace->mask & WRITE_OWNER))) {
					if (pace->type == ACCESS_ALLOWED_ACE_TYPE) {
						allowgrp |= pace->mask;
						grppresent = TRUE;
					}
				} else
					if (is_world_sid((const SID*)&pace->sid)) {
						if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
							allowall |= pace->mask;
						else
							if (pace->type == ACCESS_DENIED_ACE_TYPE)
								denyall |= pace->mask;
					} else
					if ((same_sid((const SID*)&pace->sid,nullsid))
					   && (pace->type == ACCESS_ALLOWED_ACE_TYPE))
						special |= pace->mask;
			}
			offace += le16_to_cpu(pace->size);
		}
	if (!grppresent)
		allowgrp = allowall;
	return (merge_permissions(ni,
				allowown & ~(denyown | denyall),
				allowgrp & ~(denygrp | denyall),
				allowall & ~denyall,
				special));
}

#if POSIXACLS

/*
 *		Normalize a Posix ACL either from a sorted raw set of
 *		access ACEs or default ACEs
 *		(special case : owner or/and group is administrator)
 */

static int norm_ownadmin_permissions_posix(struct POSIX_SECURITY *posix_desc,
		int start, int count, int target)
{
	int j,k;
	s32 id;
	u16 tag;
	u16 tagsset;
	struct POSIX_ACE *pxace;
	int acccnt;
	mode_t denywrld;
	mode_t allow;
	mode_t deny;
	mode_t perms;
	mode_t mode;

	mode = 0;
	pxace = posix_desc->acl.ace;
	acccnt = posix_desc->acccnt;
	tagsset = 0;
	denywrld = 0;
		/*
		 * Get denials to world which are meant to prevent
		 * execution flags to be inherited by plain files
		 */
	for (j=start; j<(start + count); j++) {
		if (pxace[j].perms & POSIX_PERM_DENIAL) {
				/* deny world exec not for default */
			if ((pxace[j].tag == POSIX_ACL_OTHER)
			&& !start)
				denywrld = pxace[j].perms;
		}
	}
		/*
		 * Collect groups of ACEs related to the same id
		 * and determine what is granted (denials are ignored)
		 * It is important the ACEs have been sorted
		 */
	j = start;
	k = target;
	deny = 0;
	while (j < (start + count)) {
		allow = 0;
		tag = pxace[j].tag;
		id = pxace[j].id;
		if (tag == POSIX_ACL_MASK) {
			deny = pxace[j].perms;
			j++;
			while ((j < (start + count))
			    && (pxace[j].tag == POSIX_ACL_MASK))
				j++;
		} else {
			if (!(pxace[j].perms & POSIX_PERM_DENIAL))
				allow = pxace[j].perms;
			j++;
			while ((j < (start + count))
			    && (pxace[j].tag == tag)
			    && (pxace[j].id == id)) {
				if (!(pxace[j].perms & POSIX_PERM_DENIAL))
					allow |= pxace[j].perms;
				j++;
			}
		}

			/*
			 * Store the grants into a Posix ACE
			 */
		if (tag == POSIX_ACL_MASK)
			perms = ~deny;
		else
			perms = allow & ~denywrld;
		if (tag != POSIX_ACL_SPECIAL) {
			pxace[k].tag = tag;
			pxace[k].id = id;
			pxace[k].perms = perms
				 & (POSIX_PERM_R | POSIX_PERM_W | POSIX_PERM_X);
			tagsset |= tag;
			k++;
		}
		switch (tag) {
		case POSIX_ACL_USER_OBJ :
			mode |= ((perms & 7) << 6);
			break;
		case POSIX_ACL_GROUP_OBJ :
		case POSIX_ACL_MASK :
			mode = (mode & 07707) | ((perms & 7) << 3);
			break;
		case POSIX_ACL_OTHER :
			mode |= perms & 7;
			break;
		case POSIX_ACL_SPECIAL :
			mode |= perms & (S_ISVTX | S_ISUID | S_ISGID);
			break;
		default :
			break;
		}
	}
	if (!start) { /* not satisfactory */
		posix_desc->mode = mode;
		posix_desc->tagsset = tagsset;
	}
	return (k - target);
}

#endif

/*
 *		Interpret an ACL and extract meaningful grants
 *		(special case : owner or/and group is administrator)
 */


static int build_ownadmin_permissions(const char *securattr,
			const SID *usid, const SID *gsid, ntfs_inode *ni)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const ACL *pacl;
	const ACCESS_ALLOWED_ACE *pace;
	int offdacl;
	int offace;
	int acecnt;
	int nace;
	BOOL firstapply;
	le32 special;
	le32 allowown, allowgrp, allowall;
	le32 denyown, denygrp, denyall;

	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)securattr;
	offdacl = le32_to_cpu(phead->dacl);
	pacl = (const ACL*)&securattr[offdacl];
	special = cpu_to_le32(0);
	allowown = allowgrp = allowall = cpu_to_le32(0);
	denyown = denygrp = denyall = cpu_to_le32(0);
	if (offdacl) {
		acecnt = le16_to_cpu(pacl->ace_count);
		offace = offdacl + sizeof(ACL);
	} else
		acecnt = 0;
	firstapply = TRUE;
	for (nace = 0; nace < acecnt; nace++) {
		pace = (const ACCESS_ALLOWED_ACE*)&securattr[offace];
		if (!(pace->flags & INHERIT_ONLY_ACE)) {
			if ((same_sid(usid, &pace->sid)
			   || same_sid(ownersid, &pace->sid))
			     && (((pace->mask & WRITE_OWNER) && firstapply))) {
				if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
					allowown |= pace->mask;
				else
					if (pace->type == ACCESS_DENIED_ACE_TYPE)
						denyown |= pace->mask;
				} else
				    if (same_sid(gsid, &pace->sid)
					&& (!(pace->mask & WRITE_OWNER))) {
						if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
							allowgrp |= pace->mask;
						else
							if (pace->type == ACCESS_DENIED_ACE_TYPE)
								denygrp |= pace->mask;
					} else if (is_world_sid((const SID*)&pace->sid)) {
						if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
							allowall |= pace->mask;
						else
							if (pace->type == ACCESS_DENIED_ACE_TYPE)
								denyall |= pace->mask;
					} else
					if ((same_sid((const SID*)&pace->sid,nullsid))
					   && (pace->type == ACCESS_ALLOWED_ACE_TYPE))
						special |= pace->mask;
			firstapply = FALSE;
			}
			offace += le16_to_cpu(pace->size);
		}
	return (merge_permissions(ni,
				allowown & ~(denyown | denyall),
				allowgrp & ~(denygrp | denyall),
				allowall & ~denyall,
				special));
}

#if OWNERFROMACL

/*
 *		Define the owner of a file as the first user allowed
 *	to change the owner, instead of the user defined as owner.
 *
 *	This produces better approximations for files written by a
 *	Windows user in an inheritable directory owned by another user,
 *	as the access rights are inheritable but the ownership is not.
 *
 *	An important case is the directories "Documents and Settings/user"
 *	which the users must have access to, though Windows considers them
 *	as owned by administrator.
 */

static const SID *acl_owner(const char *securattr)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const SID *usid;
	const ACL *pacl;
	const ACCESS_ALLOWED_ACE *pace;
	int offdacl;
	int offace;
	int acecnt;
	int nace;
	BOOL found;

	found = FALSE;
	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)securattr;
	offdacl = le32_to_cpu(phead->dacl);
	if (offdacl) {
		pacl = (const ACL*)&securattr[offdacl];
		acecnt = le16_to_cpu(pacl->ace_count);
		offace = offdacl + sizeof(ACL);
		nace = 0;
		do {
			pace = (const ACCESS_ALLOWED_ACE*)&securattr[offace];
			if ((pace->mask & WRITE_OWNER)
			   && (pace->type == ACCESS_ALLOWED_ACE_TYPE)
			   && is_user_sid(&pace->sid))
				found = TRUE;
		} while (!found && (++nace < acecnt));
	}
	if (found)
		usid = &pace->sid;
	else
		usid = (const SID*)&securattr[le32_to_cpu(phead->owner)];
	return (usid);
}

#else

/*
 *		Special case for files owned by administrator with full
 *	access granted to a mapped user : consider this user as the tenant
 *	of the file.
 *
 *	This situation cannot be represented with Linux concepts and can
 *	only be found for files or directories created by Windows.
 *	Typical situation : directory "Documents and Settings/user" which
 *	is on the path to user's files and must be given access to user
 *	only.
 *
 *	Check file is owned by administrator and no user has rights before
 *	calling.
 *	Returns the uid of tenant or zero if none
 */


static uid_t find_tenant(struct SECURITY_CONTEXT *scx,
			const char *securattr)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const ACL *pacl;
	const ACCESS_ALLOWED_ACE *pace;
	int offdacl;
	int offace;
	int acecnt;
	int nace;
	uid_t tid;
	uid_t xid;

	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)securattr;
	offdacl = le32_to_cpu(phead->dacl);
	pacl = (const ACL*)&securattr[offdacl];
	tid = 0;
	if (offdacl) {
		acecnt = le16_to_cpu(pacl->ace_count);
		offace = offdacl + sizeof(ACL);
	} else
		acecnt = 0;
	for (nace = 0; nace < acecnt; nace++) {
		pace = (const ACCESS_ALLOWED_ACE*)&securattr[offace];
		if ((pace->type == ACCESS_ALLOWED_ACE_TYPE)
		   && (pace->mask & DIR_WRITE)) {
			xid = findowner(scx, &pace->sid);
			if (xid) tid = xid;
		}
		offace += le16_to_cpu(pace->size);
	}
	return (tid);
}

#endif

#if POSIXACLS

/*
 *		Build Posix permissions from an ACL
 *	returns a pointer to the requested permissions
 *	or a null pointer (with errno set) if there is a problem
 */

static struct POSIX_SECURITY *build_permissions_posix(struct SECURITY_CONTEXT *scx,
			const char *securattr,
			const SID *usid, const SID *gsid, ntfs_inode *ni)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	struct POSIX_SECURITY *pxdesc;
	const ACL *pacl;
	const ACCESS_ALLOWED_ACE *pace;
	struct POSIX_ACE *pxace;
	struct {
		uid_t prevuid;
		gid_t prevgid;
		BOOL groupmask;
		s16 tagsset;
		mode_t permswrld;
	} ctx[2], *pctx;
	int offdacl;
	int offace;
	int alloccnt;
	int acecnt;
	uid_t uid;
	gid_t gid;
	int i,j;
	int k,l;
	BOOL ignore;
	BOOL adminowns;
	BOOL groupowns;
	BOOL firstinh;

	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)securattr;
	offdacl = le32_to_cpu(phead->dacl);
	if (offdacl) {
		pacl = (const ACL*)&securattr[offdacl];
		acecnt = le16_to_cpu(pacl->ace_count);
		offace = offdacl + sizeof(ACL);
	} else {
		acecnt = 0;
		offace = 0;
	}
	adminowns = FALSE;
	groupowns = same_sid(gsid,usid);
	firstinh = FALSE;
		/*
		 * Build a raw posix security descriptor
		 * by just translating permissions and ids
		 * Add 2 to the count of ACE to be able to insert
		 * a group ACE later in access and default ACLs
		 * and add 2 more to be able to insert ACEs for owner
		 * and 1 more for other
		 */
	alloccnt = acecnt + 5;
	pxdesc = (struct POSIX_SECURITY*)malloc(
				sizeof(struct POSIX_SECURITY)
				+ alloccnt*sizeof(struct POSIX_ACE));
	k = 0;
	l = alloccnt;
	for (i=0; i<2; i++) {
		ctx[i].permswrld = 0;
		ctx[i].prevuid = -1;
		ctx[i].prevgid = -1;
		ctx[i].groupmask = FALSE;
		ctx[i].tagsset = 0;
	}
	for (j=0; j<acecnt; j++) {
		pace = (const ACCESS_ALLOWED_ACE*)&securattr[offace];
		if (pace->flags & INHERIT_ONLY_ACE) {
			pxace = &pxdesc->acl.ace[l - 1];
			pctx = &ctx[1];
		} else {
			pxace = &pxdesc->acl.ace[k];
			pctx = &ctx[0];
		}
		ignore = FALSE;
		if (same_sid(usid, &pace->sid)) {
			pxace->id = -1;
				/*
				 * Owner has no write-owner right :
				 * a group was defined same as owner
				 * or admin was owner or group :
				 * denials are meant to owner
				 * and grants are meant to group
				 */
			if (!(pace->mask & WRITE_OWNER)
			    && (pace->type == ACCESS_ALLOWED_ACE_TYPE)) {
				if (same_sid(gsid,usid)) {
					pxace->tag = POSIX_ACL_GROUP_OBJ;
					pxace->id = -1;
				} else {
					if (same_sid(&pace->sid,usid))
						groupowns = TRUE;
					gid = findgroup(scx,&pace->sid);
					if (gid) {
						pxace->tag = POSIX_ACL_GROUP;
						pxace->id = gid;
						pctx->prevgid = gid;
					} else
						ignore = TRUE;
				}
			} else {
					/* system ignored, and admin */
					/* ignored at first position */
				pxace->tag = POSIX_ACL_USER_OBJ;
				if (pace->flags & INHERIT_ONLY_ACE) {
					if ((firstinh && same_sid(&pace->sid,adminsid))
					   || same_sid(&pace->sid,systemsid))
						ignore = TRUE;
					if (!firstinh) {
						firstinh = TRUE;
					}
				} else {
					if ((adminowns && same_sid(&pace->sid,adminsid))
					   || same_sid(&pace->sid,systemsid))
						ignore = TRUE;
					if (same_sid(usid,adminsid))
						adminowns = TRUE;
				}
			}
		} else if (same_sid(gsid, &pace->sid)) {
			pxace->id = -1;
			pxace->tag = POSIX_ACL_GROUP_OBJ;
			if (same_sid(gsid,adminsid)) {
				adminowns = TRUE;
				if (pace->mask & WRITE_OWNER)
					ignore = TRUE;
			}
		} else if (is_world_sid((const SID*)&pace->sid)) {
			pxace->id = -1;
			pxace->tag = POSIX_ACL_OTHER;
			if ((pace->type == ACCESS_DENIED_ACE_TYPE)
			   && (pace->flags & INHERIT_ONLY_ACE))
				ignore = TRUE;
		} else if (same_sid((const SID*)&pace->sid,nullsid)) {
			pxace->id = -1;
			pxace->tag = POSIX_ACL_SPECIAL;
		} else {
			uid = findowner(scx,&pace->sid);
			if (uid) {
				if ((pace->type == ACCESS_DENIED_ACE_TYPE)
				    && (pace->mask & WRITE_OWNER)
				    && (pctx->prevuid != uid)) {
					pxace->id = -1;
					pxace->tag = POSIX_ACL_MASK;
				} else {
					pxace->id = uid;
					pxace->tag = POSIX_ACL_USER;
				}
				pctx->prevuid = uid;
			} else {
				gid = findgroup(scx,&pace->sid);
				if (gid) {
					if ((pace->type == ACCESS_DENIED_ACE_TYPE)
					    && (pace->mask & WRITE_OWNER)
					    && (pctx->prevgid != gid)) {
						pxace->tag = POSIX_ACL_MASK;
						pctx->groupmask = TRUE;
					} else {
						pxace->tag = POSIX_ACL_GROUP;
					}
					pxace->id = gid;
					pctx->prevgid = gid;
				} else {
					/*
					 * do not grant rights to unknown
					 * people and do not define root as a
					 * designated user or group
					 */
					ignore = TRUE;
				}
			}
		}
		if (!ignore) {
			pxace->perms = 0;
				/* specific decoding for vtx/uid/gid */
			if (pxace->tag == POSIX_ACL_SPECIAL) {
				if (pace->mask & FILE_APPEND_DATA)
					pxace->perms |= S_ISUID;
				if (pace->mask & FILE_WRITE_DATA)
					pxace->perms |= S_ISGID;
				if (pace->mask & FILE_READ_DATA)
					pxace->perms |= S_ISVTX;
			} else
				if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
					if (pace->mask & DIR_GEXEC)
						pxace->perms |= POSIX_PERM_X;
					if (pace->mask & DIR_GWRITE)
						pxace->perms |= POSIX_PERM_W;
					if (pace->mask & DIR_GREAD)
						pxace->perms |= POSIX_PERM_R;
				} else {
					if (pace->mask & FILE_GEXEC)
						pxace->perms |= POSIX_PERM_X;
					if (pace->mask & FILE_GWRITE)
						pxace->perms |= POSIX_PERM_W;
					if (pace->mask & FILE_GREAD)
						pxace->perms |= POSIX_PERM_R;
				}

			if (pace->type != ACCESS_ALLOWED_ACE_TYPE)
				pxace->perms |= POSIX_PERM_DENIAL;
			else
				if (pxace->tag == POSIX_ACL_OTHER)
					pctx->permswrld = pxace->perms;
			pctx->tagsset |= pxace->tag;
			if (pace->flags & INHERIT_ONLY_ACE) {
				l--;
			} else {
				k++;
			}


		}
		offace += le16_to_cpu(pace->size);
	}
		/*
		 * Create world perms if none (access ACE only)
		 */
	if (!(ctx[0].tagsset & POSIX_ACL_OTHER)) {
		pxace = &pxdesc->acl.ace[k];
		pxace->tag = POSIX_ACL_OTHER;
		pxace->id = -1;
		pxace->perms = 0;
		ctx[0].tagsset |= POSIX_ACL_OTHER;
		ctx[0].permswrld = 0;
		k++;
	}
		/*
		 * Set basic owner perms if none (both lists)
		 * This happens for files created by Windows in directories
		 * created by Linux and owned by root, because Windows
		 * merges the admin ACEs
		 */
	for (i=0; i<2; i++)
//	for (i=0; i<1; i++)
		if (!(ctx[i].tagsset & POSIX_ACL_USER_OBJ)
		  && (ctx[i].tagsset & POSIX_ACL_OTHER)) {
			if (i)
				pxace = &pxdesc->acl.ace[--l];
			else
				pxace = &pxdesc->acl.ace[k++];
			pxace->tag = POSIX_ACL_USER_OBJ;
			pxace->id = -1;
			pxace->perms = POSIX_PERM_R | POSIX_PERM_W | POSIX_PERM_X;
			ctx[i].tagsset |= POSIX_ACL_USER_OBJ;
		}
		/*
		 * Duplicate world perms as group_obj perms if none
		 */
	for (i=0; i<2; i++)
		if ((ctx[i].tagsset & POSIX_ACL_OTHER)
		    && !(ctx[i].tagsset & POSIX_ACL_GROUP_OBJ)) {
			if (i)
				pxace = &pxdesc->acl.ace[--l];
			else
				pxace = &pxdesc->acl.ace[k++];
			pxace->tag = POSIX_ACL_GROUP_OBJ;
			pxace->id = -1;
			pxace->perms = ctx[i].permswrld;
			ctx[i].tagsset |= POSIX_ACL_GROUP_OBJ;
		}
		/*
		 * Also duplicate world perms as group perms if they
		 * were converted to mask and not followed by a group entry
		 */
	if (ctx[0].groupmask) {
		for (j=k-2; j>=0; j--) {
			if ((pxdesc->acl.ace[j].tag == POSIX_ACL_MASK)
			   && (pxdesc->acl.ace[j].id != -1)
			   && ((pxdesc->acl.ace[j+1].tag != POSIX_ACL_GROUP)
			     || (pxdesc->acl.ace[j+1].id
				!= pxdesc->acl.ace[j].id))) {
				pxace = &pxdesc->acl.ace[k];
				pxace->tag = POSIX_ACL_GROUP;
				pxace->id = pxdesc->acl.ace[j].id;
				pxace->perms = ctx[0].permswrld;
				ctx[0].tagsset |= POSIX_ACL_GROUP;
				k++;
			}
			if (pxdesc->acl.ace[j].tag == POSIX_ACL_MASK)
				pxdesc->acl.ace[j].id = -1;
		}
	}
	if (ctx[1].groupmask) {
		for (j=l; j<(alloccnt-1); j++) {
			if ((pxdesc->acl.ace[j].tag == POSIX_ACL_MASK)
			   && (pxdesc->acl.ace[j].id != -1)
			   && ((pxdesc->acl.ace[j+1].tag != POSIX_ACL_GROUP)
			     || (pxdesc->acl.ace[j+1].id
				!= pxdesc->acl.ace[j].id))) {
				pxace = &pxdesc->acl.ace[l - 1];
				pxace->tag = POSIX_ACL_GROUP;
				pxace->id = pxdesc->acl.ace[j].id;
				pxace->perms = ctx[1].permswrld;
				ctx[1].tagsset |= POSIX_ACL_GROUP;
				l--;
			}
			if (pxdesc->acl.ace[j].tag == POSIX_ACL_MASK)
				pxdesc->acl.ace[j].id = -1;
		}
	}

		/*
		 * Insert default mask if none present and
		 * there are designated users or groups
		 * (the space for it has not beed used)
		 */
	for (i=0; i<2; i++)
		if ((ctx[i].tagsset & (POSIX_ACL_USER | POSIX_ACL_GROUP))
		    && !(ctx[i].tagsset & POSIX_ACL_MASK)) {
			if (i)
				pxace = &pxdesc->acl.ace[--l];
			else
				pxace = &pxdesc->acl.ace[k++];
			pxace->tag = POSIX_ACL_MASK;
			pxace->id = -1;
			pxace->perms = POSIX_PERM_DENIAL;
			ctx[i].tagsset |= POSIX_ACL_MASK;
		}

	if (k > l) {
		ntfs_log_error("Posix descriptor is longer than expected\n");
		errno = EIO;
		free(pxdesc);
		pxdesc = (struct POSIX_SECURITY*)NULL;
	} else {
		pxdesc->acccnt = k;
		pxdesc->defcnt = alloccnt - l;
		pxdesc->firstdef = l;
		pxdesc->tagsset = ctx[0].tagsset;
		pxdesc->acl.version = POSIX_VERSION;
		pxdesc->acl.flags = 0;
		pxdesc->acl.filler = 0;
		sort_posix(pxdesc);
		if (adminowns) {
			k = norm_ownadmin_permissions_posix(pxdesc,
					0, pxdesc->acccnt, 0);
			pxdesc->acccnt = k;
			l = norm_ownadmin_permissions_posix(pxdesc,
					pxdesc->firstdef, pxdesc->defcnt, k);
			pxdesc->firstdef = k;
			pxdesc->defcnt = l;
		} else {
			k = norm_std_permissions_posix(pxdesc,groupowns,
					0, pxdesc->acccnt, 0);
			pxdesc->acccnt = k;
			l = norm_std_permissions_posix(pxdesc,groupowns,
					pxdesc->firstdef, pxdesc->defcnt, k);
			pxdesc->firstdef = k;
			pxdesc->defcnt = l;
		}
	}
	if (pxdesc && !valid_posix(pxdesc)) {
		ntfs_log_error("Invalid Posix descriptor built\n");
                errno = EIO;
                free(pxdesc);
                pxdesc = (struct POSIX_SECURITY*)NULL;
	}
	return (pxdesc);
}

#endif
/*
 *		Build unix-style (mode_t) permissions from an ACL
 *	returns the requested permissions
 *	or a negative result (with errno set) if there is a problem
 */

static int build_permissions(const char *securattr,
			const SID *usid, const SID *gsid, ntfs_inode *ni)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	int perm;
	BOOL adminowns;
	BOOL groupowns;

	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)securattr;
	adminowns = same_sid(usid,adminsid)
	         || same_sid(gsid,adminsid);
	groupowns = !adminowns && same_sid(gsid,usid);
	if (adminowns)
		perm = build_ownadmin_permissions(securattr, usid, gsid, ni);
	else
		if (groupowns)
			perm = build_owngrp_permissions(securattr, usid, ni);
		else
			perm = build_std_permissions(securattr, usid, gsid, ni);
	return (perm);
}

/*
 *		Get the security descriptor associated to a file
 *
 *	Either :
 *	   - read the security descriptor attribute (v1.x format)
 *	   - or find the descriptor in $Secure:$SDS (v3.x format)
 *
 *	in both case, sanity checks are done on the attribute and
 *	the descriptor can be assumed safe
 *
 *	The returned descriptor is dynamically allocated and has to be freed
 */

static char *getsecurityattr(ntfs_volume *vol,
		const char *path, ntfs_inode *ni)
{
	SII_INDEX_KEY securid;
	char *securattr;
	s64 readallsz;

		/*
		 * Warning : in some situations, after fixing by chkdsk,
		 * v3_Extensions are marked present (long standard informations)
		 * with a default security descriptor inserted in an
		 * attribute
		 */
	if (test_nino_flag(ni, v3_Extensions)
			&& vol->secure_ni && ni->security_id) {
			/* get v3.x descriptor in $Secure */
		securid.security_id = ni->security_id;
		securattr = retrievesecurityattr(vol,securid);
		if (!securattr)
			ntfs_log_error("Bad security descriptor for 0x%lx\n",
					(long)le32_to_cpu(ni->security_id));
	} else {
			/* get v1.x security attribute */
		readallsz = 0;
		securattr = ntfs_attr_readall(ni, AT_SECURITY_DESCRIPTOR,
				AT_UNNAMED, 0, &readallsz);
		if (securattr && !valid_securattr(securattr, readallsz)) {
			ntfs_log_error("Bad security descriptor for %s\n",
				path);
			free(securattr);
			securattr = (char*)NULL;
		}
	}
	if (!securattr) {
			/*
			 * in some situations, there is no security
			 * descriptor, and chkdsk does not detect or fix
			 * anything. This could be a normal situation.
			 * When this happens, simulate a descriptor with
			 * minimum rights, so that a real descriptor can
			 * be created by chown or chmod
			 */
		ntfs_log_error("No security descriptor found for %s\n",path);
		securattr = build_secur_descr(0, 0, adminsid, adminsid);
	}
	return (securattr);
}

#if POSIXACLS

static int access_check_posix(struct SECURITY_CONTEXT *scx,
			struct POSIX_SECURITY *pxdesc, mode_t request,
			uid_t uid, gid_t gid)
{
	struct POSIX_ACE *pxace;
	int userperms;
	int groupperms;
	int mask;
	BOOL somegroup;
	mode_t perms;
	int i;

	perms = pxdesc->mode;
					/* owner */
	if (uid == scx->uid)
		perms &= 07700;
	else {
					/* analyze designated users and get mask */
		userperms = -1;
		groupperms = -1;
		mask = 7;
		for (i=pxdesc->acccnt-1; i>=0 ; i--) {
			pxace = &pxdesc->acl.ace[i];
			switch (pxace->tag) {
			case POSIX_ACL_USER :
				if ((uid_t)pxace->id == scx->uid)
					userperms = pxace->perms;
				break;
			case POSIX_ACL_MASK :
				mask = pxace->perms & 7;
				break;
			default :
				break;
			}
		}
					/* designated users */
		if (userperms >= 0)
			perms = (perms & 07000) + (userperms & mask);
		else {
					/* owning group */
			if (!(~(perms >> 3) & request & mask)
			    && ((gid == scx->gid)
				|| groupmember(scx, scx->uid, gid)))
				perms &= 07070;
			else {
					/* other groups */
				groupperms = -1;
				somegroup = FALSE;
				for (i=pxdesc->acccnt-1; i>=0 ; i--) {
					pxace = &pxdesc->acl.ace[i];
					if ((pxace->tag == POSIX_ACL_GROUP)
					    && groupmember(scx, uid, pxace->id)) {
						if (!(~pxace->perms & request & mask))
							groupperms = pxace->perms;
						somegroup = TRUE;
					}
				}
				if (groupperms >= 0)
					perms = (perms & 07000) + (groupperms & mask);
				else
					if (somegroup)
						perms = 0;
					else
						perms &= 07007;
			}
		}
	}
	return (perms);
}

#endif

/*
 *		Get permissions to access a file
 *	Takes into account the relation of user to file (owner, group, ...)
 *	Do no use as mode of the file
 *
 *	returns -1 if there is a problem
 */

#if POSIXACLS
static int ntfs_get_perm(struct SECURITY_CONTEXT *scx,
		 const char *path, ntfs_inode * ni, mode_t request)
#else
static int ntfs_get_perm(struct SECURITY_CONTEXT *scx,
		 const char *path, ntfs_inode * ni)
#endif
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const struct CACHED_PERMISSIONS *cached;
	char *securattr;
	const SID *usid;	/* owner of file/directory */
	const SID *gsid;	/* group of file/directory */
	uid_t uid;
	gid_t gid;
	int perm;
#if POSIXACLS
	struct POSIX_SECURITY *pxdesc;
#endif

	if (!scx->usermapping || !scx->uid)
		perm = 07777;
	else {
		/* check whether available in cache */
		cached = fetch_cache(scx,ni);
		if (cached) {
#if POSIXACLS
			uid = cached->uid;
			gid = cached->gid;
			perm = access_check_posix(scx,cached->pxdesc,request,uid,gid);
#else
			perm = cached->mode;
			uid = cached->uid;
			gid = cached->gid;
#endif
		} else {
			perm = 0;	/* default to no permission */
			securattr = getsecurityattr(scx->vol, path, ni);
			if (securattr) {
				phead = (const SECURITY_DESCRIPTOR_RELATIVE*)
				    	securattr;
				gsid = (const SID*)&
					   securattr[le32_to_cpu(phead->group)];
				gid = findgroup(scx,gsid);
#if OWNERFROMACL
				usid = acl_owner(securattr);
#if POSIXACLS
				pxdesc = build_permissions_posix(scx,securattr,
						 usid, gsid, ni);
				if (pxdesc)
					perm = pxdesc->mode & 07777;
				else
					perm = -1;
#else
				perm = build_permissions(securattr,
						 usid, gsid, ni);
#endif
				uid = findowner(scx,usid);
#else
				usid = (const SID*)&
					    securattr[le32_to_cpu(phead->owner)];
#if POSIXACLS
				pxdesc = build_permissions_posix(scx,securattr,
						 usid, gsid, ni);
				if (pxdesc)
					perm = pxdesc->mode & 07777;
				else
					perm = -1;
#else
				perm = build_permissions(securattr,
						 usid, gsid, ni);
#endif
				if (!perm && same_sid(usid, adminsid)) {
					uid = find_tenant(scx, securattr);
					if (uid)
						perm = 0700;
				} else
					uid = findowner(scx,usid);
#endif
				/*
				 *  Create a security id if there were none
				 * and upgrade option is selected
				 */
				if (!test_nino_flag(ni, v3_Extensions)
				   && (perm >= 0)
				   && (scx->vol->secure_flags
				     & (1 << SECURITY_ADDSECURIDS))) {
					upgrade_secur_desc(scx->vol, path,
						securattr, ni);
					/*
					 * fetch owner and group for cacheing
					 * if there is a securid
					 */
				}
				if (test_nino_flag(ni, v3_Extensions)
				    && (perm >= 0)) {
#if POSIXACLS
					enter_cache(scx, ni, uid,
							gid, pxdesc);
#else
					enter_cache(scx, ni, uid,
							gid, perm);
#endif
				}
#if POSIXACLS
				if (pxdesc) {
					perm = access_check_posix(scx,pxdesc,request,uid,gid);
					free(pxdesc);
				}
#endif
				free(securattr);
			} else {
				perm = -1;
				uid = gid = 0;
			}
		}
#if POSIXACLS
#else
		if (perm >= 0) {
			if (uid == scx->uid)
				perm &= 07700;
			else
				if ((gid == scx->gid)
				   || groupmember(scx, scx->uid, gid))
					perm &= 07070;
				else
					perm &= 07007;
		}
#endif
	}
	return (perm);
}

#if POSIXACLS

/*
 *		Get a Posix ACL
 *	returns size or -errno if there is a problem
 */

int ntfs_get_posix_acl(struct SECURITY_CONTEXT *scx, const char *path,
			const char *name, char *value, size_t size,
			ntfs_inode *ni)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	struct POSIX_SECURITY *pxdesc;
	const struct CACHED_PERMISSIONS *cached;
	char *securattr;
	const SID *usid;	/* owner of file/directory */
	const SID *gsid;	/* group of file/directory */
	uid_t uid;
	gid_t gid;
	int perm;
	size_t outsize;

	outsize = 0;	/* default to error */
	if (!scx->usermapping)
		errno = ENOTSUP;
	else {
			/* check whether available in cache */
		cached = fetch_cache(scx,ni);
		if (cached)
			pxdesc = cached->pxdesc;
		else {
			securattr = getsecurityattr(scx->vol, path, ni);
			if (securattr) {
				phead =
				    (const SECURITY_DESCRIPTOR_RELATIVE*)
			    			securattr;
				gsid = (const SID*)&
					  securattr[le32_to_cpu(phead->group)];
#if OWNERFROMACL
				usid = acl_owner(securattr);
#else
				usid = (const SID*)&
					  securattr[le32_to_cpu(phead->owner)];
#endif
				pxdesc = build_permissions_posix(scx,securattr,
					  usid, gsid, ni);

					/*
					 * fetch owner and group for cacheing
					 */
				if (pxdesc) {
					perm = pxdesc->mode & 07777;
				/*
				 *  Create a security id if there were none
				 * and upgrade option is selected
				 */
					if (!test_nino_flag(ni, v3_Extensions)
					   && (scx->vol->secure_flags
					     & (1 << SECURITY_ADDSECURIDS))) {
						upgrade_secur_desc(scx->vol,
							 path, securattr, ni);
					}
#if OWNERFROMACL
					uid = findowner(scx,usid);
#else
					if (!perm && same_sid(usid, adminsid)) {
						uid = find_tenant(scx,
								securattr);
						if (uid)
							perm = 0700;
					} else
						uid = findowner(scx,usid);
#endif
					gid = findgroup(scx,gsid);
					if (pxdesc->tagsset & POSIX_ACL_EXTENSIONS)
					enter_cache(scx, ni, uid,
							gid, pxdesc);
				}
				free(securattr);
			} else
				pxdesc = (struct POSIX_SECURITY*)NULL;
		}

		if (pxdesc) {
			if (valid_posix(pxdesc)) {
				if (!strcmp(name,"system.posix_acl_default")) {
					outsize = sizeof(struct POSIX_ACL)
						+ pxdesc->defcnt*sizeof(struct POSIX_ACE);
					if (outsize <= size) {
						memcpy(value,&pxdesc->acl,sizeof(struct POSIX_ACL));
						memcpy(&value[sizeof(struct POSIX_ACL)],
							&pxdesc->acl.ace[pxdesc->firstdef],
							outsize-sizeof(struct POSIX_ACL));
					} else {
						outsize = 0;
						errno = ENOSPC;
					}
				} else {
					outsize = sizeof(struct POSIX_ACL)
						+ pxdesc->acccnt*sizeof(struct POSIX_ACE);
					if (outsize <= size)
						memcpy(value,&pxdesc->acl,outsize);
					else {
						outsize = 0;
						errno = ENOSPC;
					}
				}
			} else {
				outsize = 0;
				errno = EIO;
				ntfs_log_error("Invalid Posix ACL built\n");
			}
			if (!cached)
				free(pxdesc);
		} else
			outsize = 0;
	}
	return (outsize ? (int)outsize : -errno);
}

#endif

/*
 *		Get owner, group and permissions in an stat structure
 *	returns permissions, or -1 if there is a problem
 */

int ntfs_get_owner_mode(struct SECURITY_CONTEXT *scx,
		const char *path, ntfs_inode * ni,
		 struct stat *stbuf)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	char *securattr;
	const SID *usid;	/* owner of file/directory */
	const SID *gsid;	/* group of file/directory */
	const struct CACHED_PERMISSIONS *cached;
	int perm;
#if POSIXACLS
	struct POSIX_SECURITY *pxdesc;
#endif

	if (!scx->usermapping)
		perm = 07777;
	else {
			/* check whether available in cache */
		cached = fetch_cache(scx,ni);
		if (cached) {
			perm = cached->mode;
			stbuf->st_uid = cached->uid;
			stbuf->st_gid = cached->gid;
			stbuf->st_mode = (stbuf->st_mode & ~07777) + perm;
		} else {
			perm = -1;	/* default to error */
			securattr = getsecurityattr(scx->vol, path, ni);
			if (securattr) {
				phead =
				    (const SECURITY_DESCRIPTOR_RELATIVE*)
					    	securattr;
				gsid = (const SID*)&
					  securattr[le32_to_cpu(phead->group)];
#if OWNERFROMACL
				usid = acl_owner(securattr);
#else
				usid = (const SID*)&
					  securattr[le32_to_cpu(phead->owner)];
#endif
#if POSIXACLS
				pxdesc = build_permissions_posix(scx, securattr,
					  usid, gsid, ni);
				if (pxdesc)
					perm = pxdesc->mode & 07777;
				else
					perm = -1;
#else
				perm = build_permissions(securattr,
					  usid, gsid, ni);
#endif
					/*
					 * fetch owner and group for cacheing
					 */
				if (perm >= 0) {
				/*
				 *  Create a security id if there were none
				 * and upgrade option is selected
				 */
					if (!test_nino_flag(ni, v3_Extensions)
					   && (scx->vol->secure_flags
					     & (1 << SECURITY_ADDSECURIDS))) {
						upgrade_secur_desc(scx->vol,
							 path, securattr, ni);
					}
#if OWNERFROMACL
					stbuf->st_uid = findowner(scx,usid);
#else
					if (!perm && same_sid(usid, adminsid)) {
						stbuf->st_uid = 
							find_tenant(scx,
								securattr);
						if (stbuf->st_uid)
							perm = 0700;
					} else
						stbuf->st_uid = findowner(scx,usid);
#endif
					stbuf->st_gid = findgroup(scx,gsid);
					stbuf->st_mode =
					    (stbuf->st_mode & ~07777) + perm;
#if POSIXACLS
					enter_cache(scx, ni, stbuf->st_uid,
						stbuf->st_gid, pxdesc);
					free(pxdesc);
#else
					enter_cache(scx, ni, stbuf->st_uid,
						stbuf->st_gid, perm);
#endif
				}
				free(securattr);
			}
		}
	}
	return (perm);
}

#if POSIXACLS

/*
 *		Get the base for a Posix inheritance and
 *	build an inherited Posix descriptor
 */

static struct POSIX_SECURITY *inherit_posix(struct SECURITY_CONTEXT *scx,
			const char *dir_path, ntfs_inode *dir_ni,
			mode_t mode, BOOL isdir)
{
	const struct CACHED_PERMISSIONS *cached;
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	struct POSIX_SECURITY *pxdesc;
	struct POSIX_SECURITY *pydesc;
	char *securattr;
	const SID *usid;
	const SID *gsid;
	uid_t uid;
	gid_t gid;

	pydesc = (struct POSIX_SECURITY*)NULL;
		/* check whether parent directory is available in cache */
	cached = fetch_cache(scx,dir_ni);
	if (cached) {
		uid = cached->uid;
		gid = cached->gid;
		pxdesc = cached->pxdesc;
		if (pxdesc) {
			pydesc = build_inherited_posix(pxdesc,mode,isdir);
		}
	} else {
		securattr = getsecurityattr(scx->vol, dir_path, dir_ni);
		if (securattr) {
			phead = (const SECURITY_DESCRIPTOR_RELATIVE*)
			    	securattr;
			gsid = (const SID*)&
				   securattr[le32_to_cpu(phead->group)];
			gid = findgroup(scx,gsid);
#if OWNERFROMACL
			usid = acl_owner(securattr);
			pxdesc = build_permissions_posix(scx,securattr,
						 usid, gsid, dir_ni);
			uid = findowner(scx,usid);
#else
			usid = (const SID*)&
				    securattr[le32_to_cpu(phead->owner)];
			pxdesc = build_permissions_posix(scx,securattr,
						 usid, gsid, dir_ni);
			if (pxdesc && same_sid(usid, adminsid)) {
				uid = find_tenant(scx, securattr);
			} else
				uid = findowner(scx,usid);
#endif
			if (pxdesc) {
				/*
				 *  Create a security id if there were none
				 * and upgrade option is selected
				 */
				if (!test_nino_flag(dir_ni, v3_Extensions)
				   && (scx->vol->secure_flags
				     & (1 << SECURITY_ADDSECURIDS))) {
					upgrade_secur_desc(scx->vol, dir_path,
						securattr, dir_ni);
					/*
					 * fetch owner and group for cacheing
					 * if there is a securid
					 */
				}
				if (test_nino_flag(dir_ni, v3_Extensions)) {
					enter_cache(scx, dir_ni, uid,
							gid, pxdesc);
				}
				pydesc = build_inherited_posix(pxdesc, mode, isdir);
				free(pxdesc);
			}
		}
	}
	return (pydesc);
}

/*
 *		Allocate a security_id for a file being created
 *	
 *	Returns zero if not possible (NTFS v3.x required)
 */

le32 ntfs_alloc_securid(struct SECURITY_CONTEXT *scx,
		uid_t uid, gid_t gid, const char *dir_path,
		ntfs_inode *dir_ni, mode_t mode, BOOL isdir)
{
#if !FORCE_FORMAT_v1x
	const struct CACHED_SECURID *cached;
	struct CACHED_SECURID wanted;
	struct POSIX_SECURITY *pxdesc;
	char *newattr;
	int newattrsz;
	const SID *usid;
	const SID *gsid;
	BIGSID defusid;
	BIGSID defgsid;
	le32 securid;
#endif

	securid = cpu_to_le32(0);

#if !FORCE_FORMAT_v1x

	pxdesc = inherit_posix(scx, dir_path, dir_ni, mode, isdir);
	if (pxdesc) {
		/* check whether target securid is known in cache */

		wanted.uid = uid;
		wanted.gid = gid;
		wanted.dmode = pxdesc->mode & mode & 07777;
		if (isdir) wanted.dmode |= 0x10000;
		wanted.variable = (void*)pxdesc;
		wanted.varsize = sizeof(struct POSIX_SECURITY)
				+ (pxdesc->acccnt + pxdesc->defcnt)*sizeof(struct POSIX_ACE);
		cached = (const struct CACHED_SECURID*)ntfs_fetch_cache(
				scx->vol->securid_cache, GENERIC(&wanted),
				(cache_compare)compare);
			/* quite simple, if we are lucky */
		if (cached)
			securid = cached->securid;

			/* not in cache : make sure we can create ids */

		if (!cached && (scx->vol->major_ver >= 3)) {
			usid = find_usid(scx,uid,(SID*)&defusid);
			gsid = find_gsid(scx,gid,(SID*)&defgsid);
			if (!usid || !gsid) {
				ntfs_log_error("File created by an unmapped user/group %d/%d\n",
						(int)uid, (int)gid);
				usid = gsid = adminsid;
			}
			newattr = build_secur_descr_posix(scx, pxdesc,
					isdir, usid, gsid);
			if (newattr) {
				newattrsz = attr_size(newattr);
				securid = setsecurityattr(scx->vol,
					(const SECURITY_DESCRIPTOR_RELATIVE*)newattr,
					newattrsz);
				if (securid) {
					/* update cache, for subsequent use */
					wanted.securid = securid;
					ntfs_enter_cache(scx->vol->securid_cache,
							GENERIC(&wanted),
							(cache_compare)compare);
				}
				free(newattr);
			} else {
				/*
				 * could not build new security attribute
				 * errno set by build_secur_descr()
				 */
			}
		}
	free(pxdesc);
	}
#endif
	return (securid);
}

/*
 *		Apply Posix inheritance to a newly created file
 *	(for NTFS 1.x only : no securid)
 */

int ntfs_set_inherited_posix(struct SECURITY_CONTEXT *scx,
		ntfs_inode *ni, uid_t uid, gid_t gid,
		const char *dir_path, ntfs_inode *dir_ni, mode_t mode)
{
	struct POSIX_SECURITY *pxdesc;
	char *newattr;
	const SID *usid;
	const SID *gsid;
	BIGSID defusid;
	BIGSID defgsid;
	BOOL isdir;
	int res;

	res = -1;
	isdir = (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) != 0;
	pxdesc = inherit_posix(scx, dir_path, dir_ni, mode, isdir);
	if (pxdesc) {
		usid = find_usid(scx,uid,(SID*)&defusid);
		gsid = find_gsid(scx,gid,(SID*)&defgsid);
		if (!usid || !gsid) {
			ntfs_log_error("File created by an unmapped user/group %d/%d\n",
					(int)uid, (int)gid);
			usid = gsid = adminsid;
		}
		newattr = build_secur_descr_posix(scx, pxdesc,
					isdir, usid, gsid);
		if (newattr) {
			res = update_secur_descr(scx->vol, newattr, ni);
#if CACHE_LEGACY_SIZE
			/* also invalidate legacy cache */
			if (isdir && !ni->security_id) {
				struct CACHED_PERMISSIONS_LEGACY legacy;

				legacy.mft_no = ni->mft_no;
				legacy.variable = pxdesc;
				legacy.varsize = sizeof(struct POSIX_SECURITY)
					+ (pxdesc->acccnt + pxdesc->defcnt)*sizeof(struct POSIX_ACE);
				ntfs_invalidate_cache(scx->vol->legacy_cache,
						GENERIC(&legacy),
						(cache_compare)leg_compare);
			}
#endif
			free(newattr);

		} else {
			/*
			 * could not build new security attribute
			 * errno set by build_secur_descr()
			 */
		}
	}
	return (res);
}

#else

le32 ntfs_alloc_securid(struct SECURITY_CONTEXT *scx,
		uid_t uid, gid_t gid, mode_t mode, BOOL isdir)
{
#if !FORCE_FORMAT_v1x
	const struct CACHED_SECURID *cached;
	struct CACHED_SECURID wanted;
	char *newattr;
	int newattrsz;
	const SID *usid;
	const SID *gsid;
	BIGSID defusid;
	BIGSID defgsid;
	le32 securid;
#endif

	securid = cpu_to_le32(0);

#if !FORCE_FORMAT_v1x
		/* check whether target securid is known in cache */

	wanted.uid = uid;
	wanted.gid = gid;
	wanted.dmode = mode & 07777;
	if (isdir) wanted.dmode |= 0x10000;
	wanted.variable = (void*)NULL;
	wanted.varsize = 0;
	cached = (const struct CACHED_SECURID*)ntfs_fetch_cache(
			scx->vol->securid_cache, GENERIC(&wanted),
			(cache_compare)compare);
		/* quite simple, if we are lucky */
	if (cached)
		securid = cached->securid;

		/* not in cache : make sure we can create ids */

	if (!cached && (scx->vol->major_ver >= 3)) {
		usid = find_usid(scx,uid,(SID*)&defusid);
		gsid = find_gsid(scx,gid,(SID*)&defgsid);
		if (!usid || !gsid) {
			ntfs_log_error("File created by an unmapped user/group %d/%d\n",
					(int)uid, (int)gid);
			usid = gsid = adminsid;
		}
		newattr = build_secur_descr(mode, isdir, usid, gsid);
		if (newattr) {
			newattrsz = attr_size(newattr);
			securid = setsecurityattr(scx->vol,
				(const SECURITY_DESCRIPTOR_RELATIVE*)newattr,
				newattrsz);
			if (securid) {
				/* update cache, for subsequent use */
				wanted.securid = securid;
				ntfs_enter_cache(scx->vol->securid_cache,
						GENERIC(&wanted),
						(cache_compare)compare);
			}
			free(newattr);
		} else {
			/*
			 * could not build new security attribute
			 * errno set by build_secur_descr()
			 */
		}
	}
#endif
	return (securid);
}

#endif

/*
 *		Update ownership and mode of a file, reusing an existing
 *	security descriptor when possible
 *	
 *	Returns zero if successful
 */

#if POSIXACLS
int ntfs_set_owner_mode(struct SECURITY_CONTEXT *scx, ntfs_inode *ni,
		uid_t uid, gid_t gid, mode_t mode,
		struct POSIX_SECURITY *pxdesc)
#else
int ntfs_set_owner_mode(struct SECURITY_CONTEXT *scx, ntfs_inode *ni,
		uid_t uid, gid_t gid, mode_t mode)
#endif
{
	int res;
	const struct CACHED_SECURID *cached;
	struct CACHED_SECURID wanted;
	char *newattr;
	const SID *usid;
	const SID *gsid;
	BIGSID defusid;
	BIGSID defgsid;
	BOOL isdir;

	res = 0;

		/* check whether target securid is known in cache */

	isdir = (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) != 0;
	wanted.uid = uid;
	wanted.gid = gid;
	wanted.dmode = mode & 07777;
	if (isdir) wanted.dmode |= 0x10000;
#if POSIXACLS
	wanted.variable = (void*)pxdesc;
	if (pxdesc)
		wanted.varsize = sizeof(struct POSIX_SECURITY)
			+ (pxdesc->acccnt + pxdesc->defcnt)*sizeof(struct POSIX_ACE);
	else
		wanted.varsize = 0;
#else
	wanted.variable = (void*)NULL;
	wanted.varsize = 0;
#endif
	if (test_nino_flag(ni, v3_Extensions)) {
		cached = (const struct CACHED_SECURID*)ntfs_fetch_cache(
				scx->vol->securid_cache, GENERIC(&wanted),
				(cache_compare)compare);
			/* quite simple, if we are lucky */
		if (cached) {
			ni->security_id = cached->securid;
			NInoSetDirty(ni);
		}
	} else cached = (struct CACHED_SECURID*)NULL;

	if (!cached) {
			/*
			 * Do not use usid and gsid from former attributes,
			 * but recompute them to get repeatable results
			 * which can be kept in cache.
			 */
		usid = find_usid(scx,uid,(SID*)&defusid);
		gsid = find_gsid(scx,gid,(SID*)&defgsid);
		if (!usid || !gsid) {
			ntfs_log_error("File made owned by an unmapped user/group %d/%d\n",
				uid, gid);
			usid = gsid = adminsid;
		}
#if POSIXACLS
		if (pxdesc)
			newattr = build_secur_descr_posix(scx, pxdesc,
					 isdir, usid, gsid);
		else
			newattr = build_secur_descr(mode,
					 isdir, usid, gsid);
#else
		newattr = build_secur_descr(mode,
					 isdir, usid, gsid);
#endif
		if (newattr) {
			res = update_secur_descr(scx->vol, newattr, ni);
			if (!res) {
				/* update cache, for subsequent use */
				if (test_nino_flag(ni, v3_Extensions)) {
					wanted.securid = ni->security_id;
					ntfs_enter_cache(scx->vol->securid_cache,
							GENERIC(&wanted),
							(cache_compare)compare);
				}
#if CACHE_LEGACY_SIZE
				/* also invalidate legacy cache */
				if (isdir && !ni->security_id) {
					struct CACHED_PERMISSIONS_LEGACY legacy;

					legacy.mft_no = ni->mft_no;
#if POSIXACLS
					legacy.variable = wanted.variable;
					legacy.varsize = wanted.varsize;
#else
					legacy.variable = (void*)NULL;
					legacy.varsize = 0;
#endif
					ntfs_invalidate_cache(scx->vol->legacy_cache,
						GENERIC(&legacy),
						(cache_compare)leg_compare);
				}
#endif
			}
			free(newattr);
		} else {
			/*
			 * could not build new security attribute
			 * errno set by build_secur_descr()
			 */
			res = -1;
		}
	}
	return (res);
}

#if POSIXACLS

/*
 *		Set a new access or default Posix ACL to a file
 *		(or remove ACL if no input data)
 *	Validity of input data is checked after merging
 *
 *	Returns 0, or -1 if there is a problem
 */

int ntfs_set_posix_acl(struct SECURITY_CONTEXT *scx, const char *path,
			const char *name, const char *value, size_t size,
			ntfs_inode *ni)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const struct CACHED_PERMISSIONS *cached;
	char *oldattr;
	uid_t processuid;
	const SID *usid;
	const SID *gsid;
	uid_t uid;
	uid_t gid;
	int res;
	mode_t mode;
	BOOL isdir;
	BOOL deflt;
	int count;
	struct POSIX_SECURITY *oldpxdesc;
	struct POSIX_SECURITY *newpxdesc;

	/* get the current pxsec, either from cache or from old attribute  */
	res = -1;
	deflt = !strcmp(name,"system.posix_acl_default");
	if (size)
		count = (size - sizeof(struct POSIX_ACL)) / sizeof(struct POSIX_ACE);
	else
		count = 0;
	isdir = (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) != 0;
	newpxdesc = (struct POSIX_SECURITY*)NULL;
	if (!deflt || isdir) {
		cached = fetch_cache(scx, ni);
		if (cached) {
			uid = cached->uid;
			gid = cached->gid;
			oldpxdesc = cached->pxdesc;
			if (oldpxdesc) {
				mode = oldpxdesc->mode;
				newpxdesc = replace_acl(oldpxdesc,
						(const struct POSIX_ACL*)value,count,deflt);
				}
		} else {
			oldattr = getsecurityattr(scx->vol,path, ni);
			if (oldattr) {
				phead = (const SECURITY_DESCRIPTOR_RELATIVE*)oldattr;
#if OWNERFROMACL
				usid = acl_owner(oldattr);
#else
				usid = (const SID*)&oldattr[le32_to_cpu(phead->owner)];
#endif
				gsid = (const SID*)&oldattr[le32_to_cpu(phead->group)];
				uid = findowner(scx,usid);
				gid = findgroup(scx,gsid);
				oldpxdesc = build_permissions_posix(scx,
					oldattr, usid, gsid, ni);
				if (oldpxdesc) {
					mode = oldpxdesc->mode;
					newpxdesc = replace_acl(oldpxdesc,
							(const struct POSIX_ACL*)value,count,deflt);
					free(oldpxdesc);
				}
				free(oldattr);
			}
		}
	} else
		errno = EINVAL;

	if (newpxdesc) {
		processuid = scx->uid;
		if (!processuid || (uid == processuid)) {
				/*
				 * clear setgid if file group does
				 * not match process group
				 */
			if (processuid && (gid != scx->gid)
			    && !groupmember(scx, scx->uid, gid)) {
				newpxdesc->mode &= ~S_ISGID;
			}
			res = ntfs_set_owner_mode(scx, ni, uid, gid,
				newpxdesc->mode, newpxdesc);
		} else
			errno = EPERM;
		free(newpxdesc);
	}
	return (res ? -1 : 0);
}

/*
 *		Remove a default Posix ACL from a file
 */

int ntfs_remove_posix_acl(struct SECURITY_CONTEXT *scx, const char *path,
			const char *name, ntfs_inode *ni)
{
	return (ntfs_set_posix_acl(scx, path, name,
			(const char*)NULL, 0, ni));
}

#endif


/*
 *		Set new permissions to a file
 *	Checks user mapping has been defined before request for setting
 *
 *	rejected if request is not originated by owner or root
 *
 *	returns 0 on success
 *		-1 on failure, with errno = EIO
 */

int ntfs_set_mode(struct SECURITY_CONTEXT *scx,
		const char *path, ntfs_inode *ni, mode_t mode)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const struct CACHED_PERMISSIONS *cached;
	char *oldattr;
	const SID *usid;
	const SID *gsid;
	uid_t processuid;
	uid_t uid;
	uid_t gid;
	int res;
#if POSIXACLS
	BOOL isdir;
	int pxsize;
	const struct POSIX_SECURITY *oldpxdesc;
	struct POSIX_SECURITY *newpxdesc = (struct POSIX_SECURITY*)NULL;
#endif

	/* get the current owner, either from cache or from old attribute  */
	res = 0;
	cached = fetch_cache(scx, ni);
	if (cached) {
		uid = cached->uid;
		gid = cached->gid;
#if POSIXACLS
		oldpxdesc = cached->pxdesc;
		if (oldpxdesc) {
				/* must copy before merging */
			pxsize = sizeof(struct POSIX_SECURITY)
				+ (oldpxdesc->acccnt + oldpxdesc->defcnt)*sizeof(struct POSIX_ACE);
			newpxdesc = (struct POSIX_SECURITY*)malloc(pxsize);
			if (newpxdesc) {
				memcpy(newpxdesc, oldpxdesc, pxsize);
				if (merge_mode_posix(newpxdesc, mode))
					res = -1;
			} else
				res = -1;
		} else
			newpxdesc = (struct POSIX_SECURITY*)NULL;
#endif
	} else {
		oldattr = getsecurityattr(scx->vol,path, ni);
		if (oldattr) {
			phead = (const SECURITY_DESCRIPTOR_RELATIVE*)oldattr;
#if OWNERFROMACL
			usid = acl_owner(oldattr);
#else
			usid = (const SID*)&oldattr[le32_to_cpu(phead->owner)];
#endif
			gsid = (const SID*)&oldattr[le32_to_cpu(phead->group)];
			uid = findowner(scx,usid);
			gid = findgroup(scx,gsid);
#if POSIXACLS
			isdir = (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) != 0;
			newpxdesc = build_permissions_posix(scx,
				oldattr, usid, gsid, ni);
			if (!newpxdesc || merge_mode_posix(newpxdesc, mode))
				res = -1;
#endif
			free(oldattr);
		} else
			res = -1;
	}

	if (!res) {
		processuid = scx->uid;
		if (!processuid || (uid == processuid)) {
				/*
				 * clear setgid if file group does
				 * not match process group
				 */
			if (processuid && (gid != scx->gid)
			    && !groupmember(scx, scx->uid, gid))
				mode &= ~S_ISGID;
#if POSIXACLS
			if (newpxdesc) {
				newpxdesc->mode = mode;
				res = ntfs_set_owner_mode(scx, ni, uid, gid,
					mode, newpxdesc);
			} else
				res = ntfs_set_owner_mode(scx, ni, uid, gid,
					mode, newpxdesc);
#else
			res = ntfs_set_owner_mode(scx, ni, uid, gid, mode);
#endif
		} else {
			errno = EPERM;
			res = -1;	/* neither owner nor root */
		}
	} else {
		/*
		 * Should not happen : a default descriptor is generated
		 * by getsecurityattr() when there are none
		 */
		ntfs_log_error("File has no security descriptor\n");
		res = -1;
		errno = EIO;
	}
#if POSIXACLS
	if (newpxdesc) free(newpxdesc);
#endif
	return (res ? -1 : 0);
}

/*
 *	Create a default security descriptor for files whose descriptor
 *	cannot be inherited
 */

int ntfs_sd_add_everyone(ntfs_inode *ni)
{
	/* JPA SECURITY_DESCRIPTOR_ATTR *sd; */
	SECURITY_DESCRIPTOR_RELATIVE *sd;
	ACL *acl;
	ACCESS_ALLOWED_ACE *ace;
	SID *sid;
	int ret, sd_len;
	
	/* Create SECURITY_DESCRIPTOR attribute (everyone has full access). */
	/*
	 * Calculate security descriptor length. We have 2 sub-authorities in
	 * owner and group SIDs, but structure SID contain only one, so add
	 * 4 bytes to every SID.
	 */
	sd_len = sizeof(SECURITY_DESCRIPTOR_ATTR) + 2 * (sizeof(SID) + 4) +
		sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE); 
	sd = ntfs_calloc(sd_len);
	if (!sd)
		return -1;
	
	sd->revision = SECURITY_DESCRIPTOR_REVISION;
	sd->control = SE_DACL_PRESENT | SE_SELF_RELATIVE;
	
	sid = (SID*)((u8*)sd + sizeof(SECURITY_DESCRIPTOR_ATTR));
	sid->revision = SID_REVISION;
	sid->sub_authority_count = 2;
	sid->sub_authority[0] = cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	sid->sub_authority[1] = cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);
	sid->identifier_authority.value[5] = 5;
	sd->owner = cpu_to_le32((u8*)sid - (u8*)sd);
	
	sid = (SID*)((u8*)sid + sizeof(SID) + 4); 
	sid->revision = SID_REVISION;
	sid->sub_authority_count = 2;
	sid->sub_authority[0] = cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	sid->sub_authority[1] = cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);
	sid->identifier_authority.value[5] = 5;
	sd->group = cpu_to_le32((u8*)sid - (u8*)sd);
	
	acl = (ACL*)((u8*)sid + sizeof(SID) + 4);
	acl->revision = ACL_REVISION;
	acl->size = cpu_to_le16(sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE));
	acl->ace_count = cpu_to_le16(1);
	sd->dacl = cpu_to_le32((u8*)acl - (u8*)sd);
	
	ace = (ACCESS_ALLOWED_ACE*)((u8*)acl + sizeof(ACL));
	ace->type = ACCESS_ALLOWED_ACE_TYPE;
	ace->flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
	ace->size = cpu_to_le16(sizeof(ACCESS_ALLOWED_ACE));
	ace->mask = cpu_to_le32(0x1f01ff); /* FIXME */
	ace->sid.revision = SID_REVISION;
	ace->sid.sub_authority_count = 1;
	ace->sid.sub_authority[0] = cpu_to_le32(0);
	ace->sid.identifier_authority.value[5] = 1;

	ret = ntfs_attr_add(ni, AT_SECURITY_DESCRIPTOR, AT_UNNAMED, 0, (u8*)sd,
			    sd_len);
	if (ret)
		ntfs_log_perror("Failed to add initial SECURITY_DESCRIPTOR\n");
	
	free(sd);
	return ret;
}

/*
 *		Check whether user can access a file in a specific way
 *
 *	Returns 1 if access is allowed, including user is root or no
 *		  user mapping defined
 *		2 if sticky and accesstype is S_IWRITE + S_IEXEC + S_ISVTX
 *		0 and sets errno if there is a problem or if access
 *		  is not allowed
 */

int ntfs_allowed_access(struct SECURITY_CONTEXT *scx,
		const char *path, ntfs_inode *ni,
		int accesstype) /* access type required (S_Ixxx values) */
{
	int perm;
	int res;
	int allow;
	struct stat stbuf;

	/*
	 * Always allow for root. From the user's point of view,
	 * testing X_OK for a file with no x flag should return
	 * not allowed, but this is checked somewhere else (fuse ?)
	 * and we need not care about it.
	 * Also always allow if no mapping has been defined
	 */
	if (!scx->usermapping || !scx->uid)
		allow = 1;
	else {
#if POSIXACLS
			perm = ntfs_get_perm(scx, path, ni, accesstype);
#else
			perm = ntfs_get_perm(scx, path, ni);
#endif
		if (perm >= 0) {
			res = EACCES;
			switch (accesstype) {
			case S_IEXEC:
				allow = (perm & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
				break;
			case S_IWRITE:
				allow = (perm & (S_IWUSR | S_IWGRP | S_IWOTH)) != 0;
				break;
			case S_IWRITE + S_IEXEC:
				allow = ((perm & (S_IWUSR | S_IWGRP | S_IWOTH)) != 0)
				    && ((perm & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0);
				break;
			case S_IREAD:
				allow = (perm & (S_IRUSR | S_IRGRP | S_IROTH)) != 0;
				break;
			case S_IREAD + S_IEXEC:
				allow = ((perm & (S_IRUSR | S_IRGRP | S_IROTH)) != 0)
				    && ((perm & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0);
				break;
			case S_IREAD + S_IWRITE:
				allow = ((perm & (S_IRUSR | S_IRGRP | S_IROTH)) != 0)
				    && ((perm & (S_IWUSR | S_IWGRP | S_IWOTH)) != 0);
				break;
			case S_IWRITE + S_IEXEC + S_ISVTX:
				if (perm & S_ISVTX) {
					if ((ntfs_get_owner_mode(scx,path,ni,&stbuf) >= 0)
					    && (stbuf.st_uid == scx->uid))
						allow = 1;
					else
						allow = 2;
				} else
					allow = ((perm & (S_IWUSR | S_IWGRP | S_IWOTH)) != 0)
					    && ((perm & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0);
				break;
			default :
				res = EINVAL;
				allow = 0;
				break;
			}
			if (!allow)
				errno = res;
		} else
			allow = 0;
	}
	return (allow);
}

/*
 *		Check whether user can access the parent directory
 *	of a file in a specific way
 *
 *	Returns true if access is allowed, including user is root and
 *		no user mapping defined
 *	
 *	Sets errno if there is a problem or if not allowed
 */

BOOL ntfs_allowed_dir_access(struct SECURITY_CONTEXT *scx,
		const char *path, int accesstype)
{
	int allow;
	char *dirpath;
	char *name;
	ntfs_inode *ni;
	ntfs_inode *dir_ni;
	struct stat stbuf;

	allow = 0;
	dirpath = strdup(path);
	if (dirpath) {
		/* the root of file system is seen as a parent of itself */
		/* is that correct ? */
		name = strrchr(dirpath, '/');
		*name = 0;
		dir_ni = ntfs_pathname_to_inode(scx->vol, NULL, dirpath);
		if (dir_ni) {
			allow = ntfs_allowed_access(scx,dirpath,
				 dir_ni, accesstype);
			ntfs_inode_close(dir_ni);
				/*
				 * for an not-owned sticky directory, have to
				 * check whether file itself is owned
				 */
			if ((accesstype == (S_IWRITE + S_IEXEC + S_ISVTX))
			   && (allow == 2)) {
				ni = ntfs_pathname_to_inode(scx->vol, NULL,
					 path);
				allow = FALSE;
				if (ni) {
					allow = (ntfs_get_owner_mode(scx,path,ni,&stbuf) >= 0)
						&& (stbuf.st_uid == scx->uid);
				ntfs_inode_close(ni);
				}
			}
		}
		free(dirpath);
	}
	return (allow);		/* errno is set if not allowed */
}

/*
 *		Define a new owner/group to a file
 *
 *	returns zero if successful
 */

int ntfs_set_owner(struct SECURITY_CONTEXT *scx,
		const char *path, ntfs_inode *ni, uid_t uid, gid_t gid)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const struct CACHED_PERMISSIONS *cached;
	char *oldattr;
	const SID *usid;
	const SID *gsid;
	uid_t fileuid;
	uid_t filegid;
	mode_t mode;
	int perm;
	int res;
#if POSIXACLS
	struct POSIX_SECURITY *oldpxdesc;
	struct POSIX_SECURITY *newpxdesc;
#endif

	res = 0;
	/* get the current owner and mode from cache or security attributes */
	oldattr = (char*)NULL;
	cached = fetch_cache(scx,ni);
	if (cached) {
		fileuid = cached->uid;
		filegid = cached->gid;
		mode = cached->mode;
#if POSIXACLS
		oldpxdesc = cached->pxdesc;
		if (oldpxdesc) {
			newpxdesc = merge_owner_posix(oldpxdesc,
				uid, gid, fileuid, filegid);
			if (!newpxdesc)
				res = -1;
		} else
			newpxdesc = (struct POSIX_SECURITY*)NULL;
#endif
	} else {
		fileuid = 0;
		filegid = 0;
		mode = 0;
#if POSIXACLS
		newpxdesc = (struct POSIX_SECURITY*)NULL;
#endif
		oldattr = getsecurityattr(scx->vol, path, ni);
		if (oldattr) {
			phead = (const SECURITY_DESCRIPTOR_RELATIVE*)
				oldattr;
			gsid = (const SID*)
				&oldattr[le32_to_cpu(phead->group)];
#if OWNERFROMACL
			usid = acl_owner(oldattr);
#else
			usid = (const SID*)
				&oldattr[le32_to_cpu(phead->owner)];
#endif
#if POSIXACLS
			oldpxdesc = build_permissions_posix(scx, oldattr,
					usid, gsid, ni);
			if (oldpxdesc) {
				fileuid = findowner(scx,usid);
				filegid = findgroup(scx,gsid);
				mode = perm = oldpxdesc->mode;
				newpxdesc = merge_owner_posix(oldpxdesc,
					uid, gid, fileuid, filegid);
				free(oldpxdesc);
				if (!newpxdesc)
					res = -1;
			} else
				res = -1;
#else
			mode = perm = build_permissions(oldattr,
					 usid, gsid, ni);
			if (perm >= 0) {
				fileuid = findowner(scx,usid);
				filegid = findgroup(scx,gsid);
			} else
				res = -1;
#endif
			free(oldattr);
		} else
			res = -1;
	}
	if (!res) {
		/* check requested by root */
		/* or chgrp requested by owner to an owned group */
		if (!scx->uid
		   || ((((int)uid < 0) || (uid == fileuid))
		      && ((gid == scx->gid) || groupmember(scx, scx->uid, gid))
		      && (fileuid == scx->uid))) {
			/* replace by the new usid and gsid */
			/* or reuse old gid and sid for cacheing */
			if ((int)uid < 0)
				uid = fileuid;
			if ((int)gid < 0)
				gid = filegid;
			/* clear setuid and setgid if owner has changed */
                        /* unless request originated by root */
			if (uid && (fileuid != uid))
				mode &= 01777;
#if POSIXACLS
			res = ntfs_set_owner_mode(scx, ni, uid, gid, 
				mode, newpxdesc);
#else
			res = ntfs_set_owner_mode(scx, ni, uid, gid, mode);
#endif
		} else {
			res = -1;	/* neither owner nor root */
			errno = EPERM;
		}
#if POSIXACLS
		free(newpxdesc);
#endif
	} else {
		/*
		 * Should not happen : a default descriptor is generated
		 * by getsecurityattr() when there are none
		 */
		ntfs_log_error("File has no security descriptor\n");
		res = -1;
		errno = EIO;
	}
	return (res ? -1 : 0);
}

/*
 *		Copy the inheritable parts of an ACL
 *
 *	Returns the size of the new ACL
 *		or zero if nothing is inheritable
 */

static int inherit_acl(const ACL *oldacl, ACL *newacl,
			const SID *usid, const SID *gsid, BOOL fordir)
{
	unsigned int src;
	unsigned int dst;
	int oldcnt;
	int newcnt;
	unsigned int selection;
	int nace;
	int acesz;
	int usidsz;
	int gsidsz;
	const ACCESS_ALLOWED_ACE *poldace;
	ACCESS_ALLOWED_ACE *pnewace;

	usidsz = sid_size(usid);
	gsidsz = sid_size(gsid);

	/* ACL header */

	newacl->revision = ACL_REVISION;
	newacl->alignment1 = 0;
	newacl->alignment2 = cpu_to_le16(0);
	src = dst = sizeof(ACL);

	selection = (fordir ? CONTAINER_INHERIT_ACE : OBJECT_INHERIT_ACE);
	newcnt = 0;
	oldcnt = le16_to_cpu(oldacl->ace_count);
	for (nace = 0; nace < oldcnt; nace++) {
		poldace = (const ACCESS_ALLOWED_ACE*)((const char*)oldacl + src);
		acesz = le16_to_cpu(poldace->size);
		if (poldace->flags & selection) {
			pnewace = (ACCESS_ALLOWED_ACE*)
					((char*)newacl + dst);
			memcpy(pnewace,poldace,acesz);
				/*
				 * Replace generic creator-owner and
				 * creator-group by owner and group
				 */
			if (same_sid(&pnewace->sid, ownersid)) {
				memcpy(&pnewace->sid, usid, usidsz);
				acesz = usidsz + 8;
			}
			if (same_sid(&pnewace->sid, groupsid)) {
				memcpy(&pnewace->sid, gsid, gsidsz);
				acesz = gsidsz + 8;
			}
				/* remove inheritance flags if not a directory */
			if (!fordir)
				pnewace->flags &= ~(OBJECT_INHERIT_ACE
						| CONTAINER_INHERIT_ACE
						| INHERIT_ONLY_ACE);
			dst += acesz;
			newcnt++;
		}
		src += acesz;
	}
		/*
		 * Adjust header if something was inherited
		 */
	if (dst > sizeof(ACL)) {
		newacl->ace_count = cpu_to_le16(newcnt);
		newacl->size = cpu_to_le16(dst);
	} else
		dst = 0;
	return (dst);
}

/*
 *		Build a security id for a descriptor inherited from
 *	parent directory the Windows way
 */

static le32 build_inherited_id(struct SECURITY_CONTEXT *scx,
			const char *parentattr, BOOL fordir)
{
	const SECURITY_DESCRIPTOR_RELATIVE *pphead;
	const ACL *ppacl;
	const SID *usid;
	const SID *gsid;
	BIGSID defusid;
	BIGSID defgsid;
	int offpacl;
	int offowner;
	int offgroup;
	SECURITY_DESCRIPTOR_RELATIVE *pnhead;
	ACL *pnacl;
	int parentattrsz;
	char *newattr;
	int newattrsz;
	int aclsz;
	int usidsz;
	int gsidsz;
	int pos;
	le32 securid;

	parentattrsz = attr_size(parentattr);
	pphead = (const SECURITY_DESCRIPTOR_RELATIVE*)parentattr;
	if (scx->usermapping) {
		usid = find_usid(scx, scx->uid, (SID*)&defusid);
		gsid = find_gsid(scx, scx->gid, (SID*)&defgsid);
		if (!usid)
			usid = adminsid;
		if (!gsid)
			gsid = adminsid;
	} else {
		/*
		 * If there is no user mapping, we have to copy owner
		 * and group from parent directory.
		 * Windows never has to do that, because it can always
		 * rely on a user mapping
		 */
		offowner = le32_to_cpu(pphead->owner);
		usid = (const SID*)&parentattr[offowner];
		offgroup = le32_to_cpu(pphead->group);
		gsid = (const SID*)&parentattr[offgroup];
	}
		/*
		 * new attribute is smaller than parent's
		 * except for differences in SIDs which appear in
		 * owner, group and possible grants and denials in
		 * generic creator-owner and creator-group ACEs
		 */
	usidsz = sid_size(usid);
	gsidsz = sid_size(gsid);
	newattrsz = parentattrsz + 3*usidsz + 3*gsidsz;
	newattr = (char*)ntfs_malloc(parentattrsz);
	if (newattr) {
		pnhead = (SECURITY_DESCRIPTOR_RELATIVE*)newattr;
		pnhead->revision = SECURITY_DESCRIPTOR_REVISION;
		pnhead->alignment = 0;
		pnhead->control = SE_SELF_RELATIVE;
		pos = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
			/*
			 * locate and inherit DACL
			 * do not test SE_DACL_PRESENT (wrong for "DR Watson")
			 */
		pnhead->dacl = cpu_to_le32(0);
		if (pphead->dacl) {
			offpacl = le32_to_cpu(pphead->dacl);
			ppacl = (const ACL*)&parentattr[offpacl];
			pnacl = (ACL*)&newattr[pos];
			aclsz = inherit_acl(ppacl, pnacl, usid, gsid, fordir);
			if (aclsz) {
				pnhead->dacl = cpu_to_le32(pos);
				pos += aclsz;
				pnhead->control |= SE_DACL_PRESENT;
			}
		}
			/*
			 * locate and inherit SACL
			 */
		pnhead->sacl = cpu_to_le32(0);
		if (pphead->sacl) {
			offpacl = le32_to_cpu(pphead->sacl);
			ppacl = (const ACL*)&parentattr[offpacl];
			pnacl = (ACL*)&newattr[pos];
			aclsz = inherit_acl(ppacl, pnacl, usid, gsid, fordir);
			if (aclsz) {
				pnhead->sacl = cpu_to_le32(pos);
				pos += aclsz;
				pnhead->control |= SE_SACL_PRESENT;
			}
		}
			/*
			 * inherit or redefine owner
			 */
		memcpy(&newattr[pos],usid,usidsz);
		pnhead->owner = cpu_to_le32(pos);
		pos += usidsz;
			/*
			 * inherit or redefine group
			 */
		memcpy(&newattr[pos],gsid,gsidsz);
		pnhead->group = cpu_to_le32(pos);
		pos += usidsz;
		securid = setsecurityattr(scx->vol,
			(SECURITY_DESCRIPTOR_RELATIVE*)newattr, pos);
		free(newattr);
	} else
		securid = cpu_to_le32(0);
	return (securid);
}

/*
 *		Get an inherited security id
 *
 *	For Windows compatibility, the normal initial permission setting
 *	may be inherited from the parent directory instead of being
 *	defined by the creation arguments.
 *
 *	The following creates an inherited id for that purpose.
 *
 *	Note : the owner and group of parent directory are also
 *	inherited (which is not the case on Windows) if no user mapping
 *	is defined.
 *
 *	Returns the inherited id, or zero if not possible (eg on NTFS 1.x)
 */

le32 ntfs_inherited_id(struct SECURITY_CONTEXT *scx,
			const char *dir_path, ntfs_inode *dir_ni, BOOL fordir)
{
	struct CACHED_PERMISSIONS *cached;
	char *parentattr;
	le32 securid;

	securid = cpu_to_le32(0);
	cached = (struct CACHED_PERMISSIONS*)NULL;
		/*
		 * Try to get inherited id from cache
		 */
	if (test_nino_flag(dir_ni, v3_Extensions)
			&& dir_ni->security_id) {
		cached = fetch_cache(scx, dir_ni);
		if (cached)
			securid = (fordir ? cached->inh_dirid
					: cached->inh_fileid);
	}
		/*
		 * Not cached or not available in cache, compute it all
		 * Note : if parent directory has no id, it is not cacheable
		 */
	if (!securid) {
		parentattr = getsecurityattr(scx->vol, dir_path, dir_ni);
		if (parentattr) {
			securid = build_inherited_id(scx,
						parentattr, fordir);
			free(parentattr);
			/*
			 * Store the result into cache for further use
			 */
			if (securid) {
				cached = fetch_cache(scx, dir_ni);
				if (cached) {
					if (fordir)
						cached->inh_dirid = securid;
					else
						cached->inh_fileid = securid;
				}
			}
		}
	}
	return (securid);
}


/*
 *		Get a single mapping item from buffer
 *
 *	Always reads a full line, truncating long lines
 *	Refills buffer when exhausted
 *	Returns pointer to item, or NULL when there is no more
 */

static struct MAPLIST *getmappingitem(
		ntfs_inode *ni,	int fd, off_t *poffs, char *buf,
		int *psrc, s64 *psize)
{
	int src;
	int dst;
	char *p;
	char *q;
	int gotend;
	struct MAPLIST *item;

	src = *psrc;
	dst = 0;
			/* allocate and get a full line */
	item = (struct MAPLIST*)ntfs_malloc(sizeof(struct MAPLIST));
	if (item) {
		do {
			gotend = 0;
			while ((src < *psize)
			       && (buf[src] != '\n')) {
				if (dst < LINESZ)
					item->maptext[dst++] = buf[src];
				src++;
			}
			if (src >= *psize) {
				*poffs += *psize;
				if (ni)
					*psize = ntfs_local_read(ni,
						AT_UNNAMED, 0,
						buf, (size_t)BUFSZ, *poffs);
				else
					*psize = read(fd, buf, (size_t)BUFSZ);
				src = 0;
			} else {
				gotend = 1;
				src++;
				item->maptext[dst] = '\0';
				dst = 0;
			}
		} while (*psize && ((item->maptext[0] == '#') || !gotend));
		if (gotend) {
			/* decompose into uid, gid and sid */
			p = item->maptext;
			item->uidstr = item->maptext;
			item->gidstr = strchr(item->uidstr, ':');
			if (item->gidstr) {
				*item->gidstr++ = '\0';
				item->sidstr = strchr(item->gidstr, ':');
				if (item->sidstr) {
					*item->sidstr++ = 0;
					q = strchr(item->sidstr, ':');
					if (q) *q = 0;
				} else
					p = (char*)NULL;
			} else
				p = (char*)NULL;	/* bad line, stop */
			if (!p) {
				free(item);
				item = (struct MAPLIST*)NULL;
			}
		} else {
			free(item);	/* free unused item */
			item = (struct MAPLIST*)NULL;
		}
	}
	*psrc = src;
	return (item);
}

/*
 *		Read user mapping file and split into their attribute.
 *	Parameters are kept as text in a chained list until logins
 *	are converted to uid.
 *	Returns the head of list, if any
 *
 *	If an absolute path is provided, the mapping file is assumed
 *	to be located in another mounted file system, and plain read()
 *	are used to get its contents.
 *	If a relative path is provided, the mapping file is assumed
 *	to be located on the current file system, and internal IO
 *	have to be used since we are still mounting and we have not
 *	entered the fuse loop yet.
 */

static struct MAPLIST *readmapping(struct SECURITY_CONTEXT *scx,
			const char *usermap_path)
{
	char buf[BUFSZ];
	struct MAPLIST *item;
	struct MAPLIST *firstitem;
	struct MAPLIST *lastitem;
	ntfs_inode *ni;
	int fd;
	int src;
	off_t offs;
	s64 size;

	firstitem = (struct MAPLIST*)NULL;
	lastitem = (struct MAPLIST*)NULL;
	offs = 0;
	ni = (ntfs_inode*)NULL;
	fd = 0;
	if (!usermap_path) usermap_path = MAPPINGFILE;
	if (usermap_path[0] == '/')
		fd = open(usermap_path,O_RDONLY);
	else
		ni = ntfs_pathname_to_inode(scx->vol, NULL, usermap_path);
	if (ni || (fd > 0)) {
		if (ni)
			size = ntfs_local_read(ni, AT_UNNAMED, 0,
					buf, (size_t)BUFSZ, offs);
		else
			size = read(fd, buf, (size_t)BUFSZ);
		if (size > 0) {
			src = 0;
			do {
				item = getmappingitem(ni, fd, &offs,
					buf, &src, &size);
				if (item) {
					item->next = (struct MAPLIST*)NULL;
					if (lastitem)
						lastitem->next = item;
					else
						firstitem = item;
					lastitem = item;
				}
			} while (item);
		}
		if (ni) ntfs_inode_close(ni);
		else close(fd);
	}
	return (firstitem);
}

/*
 *		Free memory used to store the user mapping
 *	The only purpose is to facilitate the detection of memory leaks
 */

static void free_mapping(struct SECURITY_CONTEXT *scx)
{
	struct MAPPING *user;
	struct MAPPING *group;

		/* free user mappings */
	while (scx->usermapping) {
		user = scx->usermapping;
		/* do not free SIDs used for group mappings */
		group = scx->groupmapping;
		while (group && (group->sid != user->sid))
			group = group->next;
		if (!group)
			free(user->sid);
			/* free group list if any */
		if (user->grcnt)
			free(user->groups);
			/* unchain item and free */
		scx->usermapping = user->next;
		free(user);
	}
		/* free group mappings */
	while (scx->groupmapping) {
		group = scx->groupmapping;
		free(group->sid);
			/* unchain item and free */
		scx->groupmapping = group->next;
		free(group);
	}
}


/*
 *		Build the user mapping list
 *	user identification may be given in symbolic or numeric format
 *
 *	! Note ! : does getpwnam() read /etc/passwd or some other file ?
 *		if so there is a possible recursion into fuse if this
 *		file is on NTFS, and fuse is not recursion safe.
 */

static struct MAPPING *ntfs_do_user_mapping(struct MAPLIST *firstitem)
{
	struct MAPLIST *item;
	struct MAPPING *firstmapping;
	struct MAPPING *lastmapping;
	struct MAPPING *mapping;
	struct passwd *pwd;
	SID *sid;
	int uid;

	firstmapping = (struct MAPPING*)NULL;
	lastmapping = (struct MAPPING*)NULL;
	for (item = firstitem; item; item = item->next) {
		if ((item->uidstr[0] >= '0') && (item->uidstr[0] <= '9'))
			uid = atoi(item->uidstr);
		else {
			uid = 0;
			if (item->uidstr[0]) {
				pwd = getpwnam(item->uidstr);
				if (pwd) uid = pwd->pw_uid;
			}
		}
			/*
			 * Records with no uid and no gid are inserted
			 * to define the implicit mapping pattern
			 */
		if (uid
		   || (!item->uidstr[0] && !item->gidstr[0])) {
			sid = encodesid(item->sidstr);
			if (sid && !item->uidstr[0] && !item->gidstr[0]
			    && !valid_pattern(sid)) {
				ntfs_log_error("Bad implicit SID pattern %s\n",
					item->sidstr);
				sid = (SID*)NULL;
				}
			if (sid) {
				mapping =
				    (struct MAPPING*)
				    ntfs_malloc(sizeof(struct MAPPING));
				if (mapping) {
					mapping->sid = sid;
					mapping->xid = uid;
					mapping->next = (struct MAPPING*)NULL;
					if (lastmapping)
						lastmapping->next = mapping;
					else
						firstmapping = mapping;
					lastmapping = mapping;
				}
			}
		}
	}
	return (firstmapping);
}

/*
 *		Build the group mapping list
 *	group identification may be given in symbolic or numeric format
 *
 *	gid not associated to a uid are processed first in order
 *	to favour real groups
 *
 *	! Note ! : does getgrnam() read /etc/group or some other file ?
 *		if so there is a possible recursion into fuse if this
 *		file is on NTFS, and fuse is not recursion safe.
 */

static struct MAPPING *ntfs_do_group_mapping(struct MAPLIST *firstitem)
{
	struct MAPLIST *item;
	struct MAPPING *firstmapping;
	struct MAPPING *lastmapping;
	struct MAPPING *mapping;
	struct group *grp;
	BOOL secondstep;
	BOOL ok;
	int step;
	SID *sid;
	int gid;

	firstmapping = (struct MAPPING*)NULL;
	lastmapping = (struct MAPPING*)NULL;
	for (step=1; step<=2; step++) {
		for (item = firstitem; item; item = item->next) {
			secondstep = (item->uidstr[0] != '\0')
				|| !item->gidstr[0];
			ok = (step == 1 ? !secondstep : secondstep);
			if ((item->gidstr[0] >= '0')
			     && (item->gidstr[0] <= '9'))
				gid = atoi(item->gidstr);
			else {
				gid = 0;
				if (item->gidstr[0]) {
					grp = getgrnam(item->gidstr);
					if (grp) gid = grp->gr_gid;
				}
			}
			/*
			 * Records with no uid and no gid are inserted in the
			 * second step to define the implicit mapping pattern
			 */
			if (ok
			    && (gid
				 || (!item->uidstr[0] && !item->gidstr[0]))) {
				sid = encodesid(item->sidstr);
				if (sid && !item->uidstr[0] && !item->gidstr[0]
				    && !valid_pattern(sid)) {
					/* error already logged */
					sid = (SID*)NULL;
					}
				if (sid) {
					mapping = (struct MAPPING*)
					    ntfs_malloc(sizeof(struct MAPPING));
					if (mapping) {
						mapping->sid = sid;
						mapping->xid = gid;
						mapping->next = (struct MAPPING*)NULL;
						if (lastmapping)
							lastmapping->next = mapping;
						else
							firstmapping = mapping;
						lastmapping = mapping;
					}
				}
			}
		}
	}
	return (firstmapping);
}

/*
 *		Link a group to a member of group
 *
 *	Returns 0 if OK, -1 (and errno set) if error
 */

static int link_single_group(struct MAPPING *usermapping, struct passwd *user,
			gid_t gid)
{
	struct group *group;
	char **grmem;
	int grcnt;
	gid_t *groups;
	int res;

	res = 0;
	group = getgrgid(gid);
	if (group && group->gr_mem) {
		grcnt = usermapping->grcnt;
		groups = usermapping->groups;
		grmem = group->gr_mem;
		while (*grmem && strcmp(user->pw_name, *grmem))
			grmem++;
		if (*grmem) {
			if (!grcnt)
				groups = (gid_t*)malloc(sizeof(gid_t));
			else
				groups = (gid_t*)realloc(groups,
					(grcnt+1)*sizeof(gid_t));
			if (groups)
				groups[grcnt++]	= gid;
			else {
				res = -1;
				errno = ENOMEM;
			}
		}
		usermapping->grcnt = grcnt;
		usermapping->groups = groups;
	}
	return (res);
}


/*
 *		Statically link group to users
 *	This is based on groups defined in /etc/group and does not take
 *	the groups dynamically set by setgroups() nor any changes in
 *	/etc/group into account
 *
 *	Only mapped groups and root group are linked to mapped users
 *
 *	Returns 0 if OK, -1 (and errno set) if error
 *
 */

static int link_group_members(struct SECURITY_CONTEXT *scx)
{
	struct MAPPING *usermapping;
	struct MAPPING *groupmapping;
	struct passwd *user;
	int res;

	res = 0;
	for (usermapping=scx->usermapping; usermapping && !res;
			usermapping=usermapping->next) {
		usermapping->grcnt = 0;
		usermapping->groups = (gid_t*)NULL;
		user = getpwuid(usermapping->xid);
		if (user && user->pw_name) {
			for (groupmapping=scx->groupmapping;
					groupmapping && !res;
					groupmapping=groupmapping->next) {
				if (link_single_group(usermapping, user,
				    groupmapping->xid))
					res = -1;
				}
			if (!res && link_single_group(usermapping,
					 user, (gid_t)0))
				res = -1;
		}
	}
	return (res);
}


/*
 *		Apply default single user mapping
 *	returns zero if successful
 */

static int ntfs_do_default_mapping(struct SECURITY_CONTEXT *scx,
			 const SID *usid)
{
	struct MAPPING *usermapping;
	struct MAPPING *groupmapping;
	SID *sid;
	int sidsz;
	int res;

	res = -1;
	sidsz = sid_size(usid);
	sid = (SID*)ntfs_malloc(sidsz);
	if (sid) {
		memcpy(sid,usid,sidsz);
		usermapping = (struct MAPPING*)ntfs_malloc(sizeof(struct MAPPING));
		if (usermapping) {
			groupmapping = (struct MAPPING*)ntfs_malloc(sizeof(struct MAPPING));
			if (groupmapping) {
				usermapping->sid = sid;
				usermapping->xid = scx->uid;
				usermapping->next = (struct MAPPING*)NULL;
				groupmapping->sid = sid;
				groupmapping->xid = scx->uid;
				groupmapping->next = (struct MAPPING*)NULL;
				scx->usermapping = usermapping;
				scx->groupmapping = groupmapping;
				res = 0;
			}
		}
	}
	return (res);

}

/*
 *		Make sure there are no ambiguous mapping
 *	Ambiguous mapping may lead to undesired configurations and
 *	we had rather be safe until the consequences are understood
 */

#if 0 /* not activated for now */

static BOOL check_mapping(const struct MAPPING *usermapping,
		const struct MAPPING *groupmapping)
{
	const struct MAPPING *mapping1;
	const struct MAPPING *mapping2;
	BOOL ambiguous;

	ambiguous = FALSE;
	for (mapping1=usermapping; mapping1; mapping1=mapping1->next)
		for (mapping2=mapping1->next; mapping2; mapping1=mapping2->next)
			if (same_sid(mapping1->sid,mapping2->sid)) {
				if (mapping1->xid != mapping2->xid)
					ambiguous = TRUE;
			} else {
				if (mapping1->xid == mapping2->xid)
					ambiguous = TRUE;
			}
	for (mapping1=groupmapping; mapping1; mapping1=mapping1->next)
		for (mapping2=mapping1->next; mapping2; mapping1=mapping2->next)
			if (same_sid(mapping1->sid,mapping2->sid)) {
				if (mapping1->xid != mapping2->xid)
					ambiguous = TRUE;
			} else {
				if (mapping1->xid == mapping2->xid)
					ambiguous = TRUE;
			}
	return (ambiguous);
}

#endif

/*
 *		Try and apply default single user mapping
 *	returns zero if successful
 */

static int ntfs_default_mapping(struct SECURITY_CONTEXT *scx)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	ntfs_inode *ni;
	char *securattr;
	const SID *usid;
	int res;

	res = -1;
	ni = ntfs_pathname_to_inode(scx->vol, NULL, "/.");
	if (ni) {
		securattr = getsecurityattr(scx->vol,"/.",ni);
		if (securattr) {
			phead = (const SECURITY_DESCRIPTOR_RELATIVE*)securattr;
			usid = (SID*)&securattr[le32_to_cpu(phead->owner)];
			if (is_user_sid(usid))
				res = ntfs_do_default_mapping(scx,usid);
			free(securattr);
		}
		ntfs_inode_close(ni);
	}
	return (res);
}


/*
 *		Build the user mapping
 *	- according to a mapping file if defined (or default present),
 *	- or try default single user mapping if possible
 *
 *	The mapping is specific to a mounted device
 *	No locking done, mounting assumed non multithreaded
 *
 *	returns zero if mapping is successful
 *	(failure should not be interpreted as an error)
 */

int ntfs_build_mapping(struct SECURITY_CONTEXT *scx, const char *usermap_path)
{
	struct MAPLIST *item;
	struct MAPLIST *firstitem;
	struct MAPPING *usermapping;
	struct MAPPING *groupmapping;

	/* be sure not to map anything until done */
	scx->usermapping = (struct MAPPING*)NULL;
	scx->groupmapping = (struct MAPPING*)NULL;
	firstitem = readmapping(scx, usermap_path);
	if (firstitem) {
		usermapping = ntfs_do_user_mapping(firstitem);
		groupmapping = ntfs_do_group_mapping(firstitem);
		if (usermapping && groupmapping) {
			scx->usermapping = usermapping;
			scx->groupmapping = groupmapping;
		} else
			ntfs_log_error("There were no valid user or no valid group\n");
		/* now we can free the memory copy of input text */
		/* and rely on internal representation */
		while (firstitem) {
			item = firstitem->next;
			free(firstitem);
			firstitem = item;
		}
	} else {
			/* no mapping file, try default mapping */
		if (scx->uid && scx->gid) {
			if (!ntfs_default_mapping(scx))
				ntfs_log_info("Using default user mapping\n");
		}
	}
	return (!scx->usermapping || link_group_members(scx));
}

/*
 *	Open $Secure once for all
 *	returns zero if it succeeds
 *		non-zero if it fails. This is not an error (on NTFS v1.x)
 */


int ntfs_open_secure(ntfs_volume *vol)
{
	ntfs_inode *ni;
	int res;

	res = -1;
	vol->secure_ni = (ntfs_inode*)NULL;
	vol->secure_xsii = (ntfs_index_context*)NULL;
	vol->secure_xsdh = (ntfs_index_context*)NULL;
	if (vol->major_ver >= 3) {
			/* make sure this is a genuine $Secure inode 9 */
		ni = ntfs_pathname_to_inode(vol, NULL, "$Secure");
		if (ni && (ni->mft_no == 9)) {
			vol->secure_reentry = 0;
			vol->secure_xsii = ntfs_index_ctx_get(ni,
						sii_stream, 4);
			vol->secure_xsdh = ntfs_index_ctx_get(ni,
						sdh_stream, 4);
			if (ni && vol->secure_xsii && vol->secure_xsdh) {
				vol->secure_ni = ni;
				res = 0;
			}
		}
	}
	return (res);
}

/*
 *		Final cleaning
 *	Allocated memory is freed to facilitate the detection of memory leaks
 */

void ntfs_close_secure(struct SECURITY_CONTEXT *scx)
{
	ntfs_volume *vol;

	vol = scx->vol;
	if (vol->secure_ni) {
		ntfs_index_ctx_put(vol->secure_xsii);
		ntfs_index_ctx_put(vol->secure_xsdh);
		ntfs_inode_close(vol->secure_ni);
		
	}
	free_mapping(scx);
	free_caches(scx);
}

/*
 *		API for direct access to security descriptors
 *	based on Win32 API
 */


/*
 *		Selective feeding of a security descriptor into user buffer
 *
 *	Returns TRUE if successful
 */

static BOOL feedsecurityattr(const char *attr, u32 selection,
		char *buf, u32 buflen, u32 *psize)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	SECURITY_DESCRIPTOR_RELATIVE *pnhead;
	const ACL *pdacl;
	const ACL *psacl;
	const SID *pusid;
	const SID *pgsid;
	unsigned int offdacl;
	unsigned int offsacl;
	unsigned int offowner;
	unsigned int offgroup;
	unsigned int daclsz;
	unsigned int saclsz;
	unsigned int usidsz;
	unsigned int gsidsz;
	unsigned int size; /* size of requested attributes */
	BOOL ok;
	unsigned int pos;
	unsigned int avail;

		/*
		 * First check DACL, which is the last field in all descriptors
		 * we build, and in most descriptors built by Windows
		 */

	avail = 0;
	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)attr;
	size = sizeof(SECURITY_DESCRIPTOR_RELATIVE);

		/* locate DACL if requested and available */
	if (phead->dacl && (selection & DACL_SECURITY_INFORMATION)) {
		offdacl = le32_to_cpu(phead->dacl);
		pdacl = (const ACL*)&attr[offdacl];
		daclsz = le16_to_cpu(pdacl->size);
		size += daclsz;
		avail |= DACL_SECURITY_INFORMATION;
	} else
		offdacl = daclsz = 0;

		/* locate owner if requested and available */
	offowner = le32_to_cpu(phead->owner);
	if (offowner && (selection & OWNER_SECURITY_INFORMATION)) {
			/* find end of USID */
		pusid = (const SID*)&attr[offowner];
		usidsz = sid_size(pusid);
		size += usidsz;
		avail |= OWNER_SECURITY_INFORMATION;
	} else
		offowner = usidsz = 0;

		/* locate group if requested and available */
	offgroup = le32_to_cpu(phead->group);
	if (offgroup && (selection & GROUP_SECURITY_INFORMATION)) {
			/* find end of GSID */
		pgsid = (const SID*)&attr[offgroup];
		gsidsz = sid_size(pgsid);
		size += gsidsz;
		avail |= GROUP_SECURITY_INFORMATION;
	} else
		offgroup = gsidsz = 0;

		/* locate SACL if requested and available */
	if (phead->dacl && (selection & SACL_SECURITY_INFORMATION)) {
			/* find end of SACL */
		offsacl = le32_to_cpu(phead->sacl);
		psacl = (const ACL*)&attr[offsacl];
		saclsz = le16_to_cpu(psacl->size);
		size += saclsz;
		avail |= SACL_SECURITY_INFORMATION;
	} else
		offsacl = saclsz = 0;

		/*
		 * Check whether not requesting unavailable information
		 * and having enough size in destination buffer
		 * (required size is returned nevertheless so that
		 * the request can be reissued with adequate size)
		 */
	if ((selection & ~avail)
	   || (size > buflen)) {
		*psize = size;
		errno = EINVAL;
		ok = FALSE;
	} else {
		/* copy header and feed new flags */
		memcpy(buf,attr,sizeof(SECURITY_DESCRIPTOR_RELATIVE));
		pnhead = (SECURITY_DESCRIPTOR_RELATIVE*)buf;
		pnhead->control = cpu_to_le16(avail);
		pos = sizeof(SECURITY_DESCRIPTOR_RELATIVE);

		/* copy DACL if requested */
		if (selection & DACL_SECURITY_INFORMATION) {
			pnhead->dacl = cpu_to_le32(pos);
			memcpy(&buf[pos],&attr[offdacl],daclsz);
			pos += daclsz;
		} else
			pnhead->dacl = cpu_to_le32(0);

		/* copy SACL if requested */
		if (selection & SACL_SECURITY_INFORMATION) {
			pnhead->sacl = cpu_to_le32(pos);
			memcpy(&buf[pos],&attr[offsacl],saclsz);
			pos += saclsz;
		} else
			pnhead->sacl = cpu_to_le32(0);

		/* copy owner if requested */
		if (selection & OWNER_SECURITY_INFORMATION) {
			pnhead->owner = cpu_to_le32(pos);
			memcpy(&buf[pos],&attr[offowner],usidsz);
			pos += usidsz;
		} else
			pnhead->owner = cpu_to_le32(0);

		/* copy group if requested */
		if (selection & GROUP_SECURITY_INFORMATION) {
			pnhead->group = cpu_to_le32(pos);
			memcpy(&buf[pos],&attr[offgroup],gsidsz);
			pos += gsidsz;
		} else
			pnhead->group = cpu_to_le32(0);
		if (pos != size)
			ntfs_log_error("Error in security descriptor size\n");
		*psize = size;
		ok = TRUE;
	}

	return (ok);
}

/*
 *		Merge a new security descriptor into the old one
 *	and assign to designated file
 *
 *	Returns TRUE if successful
 */

static BOOL mergesecurityattr(ntfs_volume *vol, const char *oldattr,
		const char *newattr, u32 selection, ntfs_inode *ni)
{
	const SECURITY_DESCRIPTOR_RELATIVE *oldhead;
	const SECURITY_DESCRIPTOR_RELATIVE *newhead;
	SECURITY_DESCRIPTOR_RELATIVE *targhead;
	const ACL *pdacl;
	const ACL *psacl;
	const SID *powner;
	const SID *pgroup;
	int offdacl;
	int offsacl;
	int offowner;
	int offgroup;
	unsigned int present;
	unsigned int size;
	char *target;
	int pos;
	int oldattrsz;
	int newattrsz;
	BOOL ok;

	ok = FALSE; /* default return */
	oldhead = (const SECURITY_DESCRIPTOR_RELATIVE*)oldattr;
	newhead = (const SECURITY_DESCRIPTOR_RELATIVE*)newattr;
	oldattrsz = attr_size(oldattr);
	newattrsz = attr_size(newattr);
	target = (char*)ntfs_malloc(oldattrsz + newattrsz);
	if (target) {
		targhead = (SECURITY_DESCRIPTOR_RELATIVE*)target;
		pos = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
		present = 0;
		if (oldhead->sacl)
			present |= SACL_SECURITY_INFORMATION;
		if (oldhead->dacl)
			present |= DACL_SECURITY_INFORMATION;
		if (oldhead->owner)
			present |= OWNER_SECURITY_INFORMATION;
		if (oldhead->group)
			present |= GROUP_SECURITY_INFORMATION;
			/*
			 * copy new DACL if selected
			 * or keep old DACL if any
			 */
		if ((selection | present) & DACL_SECURITY_INFORMATION) {
			if (selection & DACL_SECURITY_INFORMATION) {
				offdacl = le32_to_cpu(newhead->dacl);
				pdacl = (const ACL*)&newattr[offdacl];
			} else {
				offdacl = le32_to_cpu(oldhead->dacl);
				pdacl = (const ACL*)&oldattr[offdacl];
			}
			size = le16_to_cpu(pdacl->size);
			memcpy(&target[pos], pdacl, size);
			targhead->dacl = cpu_to_le32(pos);
			pos += size;
		} else
			targhead->dacl = cpu_to_le32(0);
			/*
			 * copy new SACL if selected
			 * or keep old SACL if any
			 */
		if ((selection | present) & SACL_SECURITY_INFORMATION) {
			if (selection & SACL_SECURITY_INFORMATION) {
				offsacl = le32_to_cpu(newhead->sacl);
				psacl = (const ACL*)&newattr[offsacl];
			} else {
				offsacl = le32_to_cpu(oldhead->sacl);
				psacl = (const ACL*)&oldattr[offsacl];
			}
			size = le16_to_cpu(psacl->size);
			memcpy(&target[pos], psacl, size);
			targhead->sacl = cpu_to_le32(pos);
			pos += size;
		} else
			targhead->sacl = cpu_to_le32(0);
			/*
			 * copy new OWNER if selected
			 * or keep old OWNER if any
			 */
		if ((selection | present) & OWNER_SECURITY_INFORMATION) {
			if (selection & OWNER_SECURITY_INFORMATION) {
				offowner = le32_to_cpu(newhead->owner);
				powner = (const SID*)&newattr[offowner];
			} else {
				offowner = le32_to_cpu(oldhead->owner);
				powner = (const SID*)&oldattr[offowner];
			}
			size = sid_size(powner);
			memcpy(&target[pos], powner, size);
			targhead->owner = cpu_to_le32(pos);
			pos += size;
		} else
			targhead->owner = cpu_to_le32(0);
			/*
			 * copy new GROUP if selected
			 * or keep old GROUP if any
			 */
		if ((selection | present) & GROUP_SECURITY_INFORMATION) {
			if (selection & GROUP_SECURITY_INFORMATION) {
				offgroup = le32_to_cpu(newhead->group);
				pgroup = (const SID*)&newattr[offgroup];
			} else {
				offgroup = le32_to_cpu(oldhead->group);
				pgroup = (const SID*)&oldattr[offgroup];
			}
			size = sid_size(pgroup);
			memcpy(&target[pos], pgroup, size);
			targhead->group = cpu_to_le32(pos);
			pos += size;
		} else
			targhead->group = cpu_to_le32(0);
		targhead->revision = SECURITY_DESCRIPTOR_REVISION;
		targhead->alignment = 0;
		targhead->control = cpu_to_le16(SE_SELF_RELATIVE
			| ((present | selection)
			    & (SACL_SECURITY_INFORMATION
				 | DACL_SECURITY_INFORMATION)));
		ok = !update_secur_descr(vol, target, ni);
		free(target);
	}
	return (ok);
}

/*
 *		Return the security descriptor of a file
 *	This is intended to be similar to GetFileSecurity() from Win32
 *	in order to facilitate the development of portable tools
 *
 *	returns zero if unsuccessful (following Win32 conventions)
 *		-1 if no securid
 *		the securid if any
 *
 *  The Win32 API is :
 *
 *  BOOL WINAPI GetFileSecurity(
 *    __in          LPCTSTR lpFileName,
 *    __in          SECURITY_INFORMATION RequestedInformation,
 *    __out_opt     PSECURITY_DESCRIPTOR pSecurityDescriptor,
 *    __in          DWORD nLength,
 *    __out         LPDWORD lpnLengthNeeded
 *  );
 *
 */

int ntfs_get_file_security(struct SECURITY_API *scapi,
		const char *path, u32 selection,
		char *buf, u32 buflen, u32 *psize)
{
	ntfs_inode *ni;
	char *attr;
	int res;

	res = 0; /* default return */
	if (scapi && (scapi->magic == MAGIC_API)) {
		ni = ntfs_pathname_to_inode(scapi->security.vol, NULL, path);
		if (ni) {
			attr = getsecurityattr(scapi->security.vol, path, ni);
			if (attr) {
				if (feedsecurityattr(attr,selection,
						buf,buflen,psize)) {
					if (test_nino_flag(ni, v3_Extensions)
					    && ni->security_id)
						res = le32_to_cpu(
							ni->security_id);
					else
						res = -1;
				}
				free(attr);
			}
			ntfs_inode_close(ni);
		} else
			errno = ENOENT;
		if (!res) *psize = 0;
	} else
		errno = EINVAL; /* do not clear *psize */
	return (res);
}


/*
 *		Set the security descriptor of a file or directory
 *	This is intended to be similar to SetFileSecurity() from Win32
 *	in order to facilitate the development of portable tools
 *
 *	returns zero if unsuccessful (following Win32 conventions)
 *		-1 if no securid
 *		the securid if any
 *
 *  The Win32 API is :
 *
 *  BOOL WINAPI SetFileSecurity(
 *    __in          LPCTSTR lpFileName,
 *    __in          SECURITY_INFORMATION SecurityInformation,
 *    __in          PSECURITY_DESCRIPTOR pSecurityDescriptor
 *  );
 */

int ntfs_set_file_security(struct SECURITY_API *scapi,
		const char *path, u32 selection, const char *attr)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	ntfs_inode *ni;
	int attrsz;
	unsigned int provided;
	char *oldattr;
	int res;

	res = 0; /* default return */
	if (scapi && (scapi->magic == MAGIC_API) && attr) {
		phead = (const SECURITY_DESCRIPTOR_RELATIVE*)attr;
		attrsz = attr_size(attr);
		provided = 0;
		if (phead->sacl)
			provided |= SACL_SECURITY_INFORMATION;
		if (phead->dacl)
			provided |= DACL_SECURITY_INFORMATION;
		if (phead->owner)
			provided |= OWNER_SECURITY_INFORMATION;
		if (phead->group)
			provided |= GROUP_SECURITY_INFORMATION;
		if (valid_securattr(attr, attrsz)
			/* selected items must be provided */
		   && (!(selection & ~provided))) {
			ni = ntfs_pathname_to_inode(scapi->security.vol,
				NULL, path);
			if (ni) {
				oldattr = getsecurityattr(scapi->security.vol,
						path, ni);
				if (oldattr) {
					if (mergesecurityattr(
						scapi->security.vol,
						oldattr, attr,
						selection, ni)) {
						if (test_nino_flag(ni,
							    v3_Extensions))
							res = le32_to_cpu(
							    ni->security_id);
						else
							res = -1;
					}
					free(oldattr);
				}
				ntfs_inode_close(ni);
			}
		}
	}
	return (res);
}


/*
 *		Return the attributes of a file
 *	This is intended to be similar to GetFileAttributes() from Win32
 *	in order to facilitate the development of portable tools
 *
 *	returns -1 if unsuccessful (Win32 : INVALID_FILE_ATTRIBUTES)
 *
 *  The Win32 API is :
 *
 *  DWORD WINAPI GetFileAttributes(
 *   __in  LPCTSTR lpFileName
 *  );
 */

int ntfs_get_file_attributes(struct SECURITY_API *scapi, const char *path)
{
	ntfs_inode *ni;
	s32 attrib;

	attrib = -1; /* default return */
	if (scapi && (scapi->magic == MAGIC_API) && path) {
		ni = ntfs_pathname_to_inode(scapi->security.vol, NULL, path);
		if (ni) {
			attrib = ni->flags;
			ntfs_inode_close(ni);
		} else
			errno = ENOENT;
	} else
		errno = EINVAL; /* do not clear *psize */
	return (attrib);
}


/*
 *		Set attributes to a file or directory
 *	This is intended to be similar to SetFileAttributes() from Win32
 *	in order to facilitate the development of portable tools
 *
 *	Only a few flags can be set (same list as Win32)
 *
 *	returns zero if unsuccessful (following Win32 conventions)
 *		nonzero if successful
 *
 *  The Win32 API is :
 *
 *  BOOL WINAPI SetFileAttributes(
 *    __in  LPCTSTR lpFileName,
 *    __in  DWORD dwFileAttributes
 *  );
 */

BOOL ntfs_set_file_attributes(struct SECURITY_API *scapi,
		const char *path, s32 attrib)
{
	ntfs_inode *ni;
	int res;

	res = 0; /* default return */
	if (scapi && (scapi->magic == MAGIC_API) && path) {
		ni = ntfs_pathname_to_inode(scapi->security.vol, NULL, path);
		if (ni) {
			ni->flags = (ni->flags & ~0x31a7) | (attrib & 0x31a7);
			NInoSetDirty(ni);
			ntfs_inode_close(ni);
		} else
			errno = ENOENT;
	}
	return (res);
}


BOOL ntfs_read_directory(struct SECURITY_API *scapi,
		const char *path, ntfs_filldir_t callback, void *context)
{
	ntfs_inode *ni;
	BOOL ok;
	s64 pos;

	ok = FALSE; /* default return */
	if (scapi && (scapi->magic == MAGIC_API) && callback) {
		ni = ntfs_pathname_to_inode(scapi->security.vol, NULL, path);
		if (ni) {
			if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
				pos = 0;
				ntfs_readdir(ni,&pos,context,callback);
				ntfs_inode_close(ni);
ok = TRUE; /* clarification needed */
			} else
				errno = ENOTDIR;
		} else
			errno = ENOENT;
	} else
		errno = EINVAL; /* do not clear *psize */
	return (ok);
}

/*
 *		read $SDS (for auditing security data)
 *
 *	Returns the number or read bytes, or -1 if there is an error
 */

int ntfs_read_sds(struct SECURITY_API *scapi,
		char *buf, u32 size, u32 offset)
{
	int got;

	got = -1; /* default return */
	if (scapi && (scapi->magic == MAGIC_API)) {
		if (scapi->security.vol->secure_ni)
			got = ntfs_local_read(scapi->security.vol->secure_ni,
				STREAM_SDS, 4, buf, size, offset);
		else
			errno = EOPNOTSUPP;
	} else
		errno = EINVAL;
	return (got);
}

/*
 *		read $SII (for auditing security data)
 *
 *	Returns next entry, or NULL if there is an error
 */

INDEX_ENTRY *ntfs_read_sii(struct SECURITY_API *scapi,
		INDEX_ENTRY *entry)
{
	SII_INDEX_KEY key;
	INDEX_ENTRY *ret;
	BOOL found;
	ntfs_index_context *xsii;

	ret = (INDEX_ENTRY*)NULL; /* default return */
	if (scapi && (scapi->magic == MAGIC_API)) {
		xsii = scapi->security.vol->secure_xsii;
		if (xsii) {
			if (!entry) {
				key.security_id = cpu_to_le32(0);
				found = !ntfs_index_lookup((char*)&key,
						sizeof(SII_INDEX_KEY), xsii);
				/* not supposed to find */
				if (!found && (errno == ENOENT))
					ret = xsii->entry;
			} else
				ret = ntfs_index_next(entry,xsii);
			if (!ret)
				errno = ENODATA;
		} else
			errno = EOPNOTSUPP;
	} else
		errno = EINVAL;
	return (ret);
}

/*
 *		read $SDH (for auditing security data)
 *
 *	Returns next entry, or NULL if there is an error
 */

INDEX_ENTRY *ntfs_read_sdh(struct SECURITY_API *scapi,
		INDEX_ENTRY *entry)
{
	SDH_INDEX_KEY key;
	INDEX_ENTRY *ret;
	BOOL found;
	ntfs_index_context *xsdh;

	ret = (INDEX_ENTRY*)NULL; /* default return */
	if (scapi && (scapi->magic == MAGIC_API)) {
		xsdh = scapi->security.vol->secure_xsdh;
		if (xsdh) {
			if (!entry) {
				key.hash = cpu_to_le32(0);
				key.security_id = cpu_to_le32(0);
				found = !ntfs_index_lookup((char*)&key,
						sizeof(SDH_INDEX_KEY), xsdh);
				/* not supposed to find */
				if (!found && (errno == ENOENT))
					ret = xsdh->entry;
			} else
				ret = ntfs_index_next(entry,xsdh);
			if (!ret)
				errno = ENODATA;
		} else errno = ENOTSUP;
	} else
		errno = EINVAL;
	return (ret);
}

/*
 *		Get the mapped user SID
 *	A buffer of 40 bytes has to be supplied
 *
 *	returns the size of the SID, or zero and errno set if not found
 */

int ntfs_get_usid(struct SECURITY_API *scapi, uid_t uid, char *buf)
{
	const SID *usid;
	BIGSID defusid;
	int size;

	size = 0;
	if (scapi && (scapi->magic == MAGIC_API)) {
		usid = find_usid(&scapi->security, uid, (SID*)&defusid);
		if (usid) {
			size = sid_size(usid);
			memcpy(buf,usid,size);
		} else
			errno = ENODATA;
	} else
		errno = EINVAL;
	return (size);
}

/*
 *		Get the mapped group SID
 *	A buffer of 40 bytes has to be supplied
 *
 *	returns the size of the SID, or zero and errno set if not found
 */

int ntfs_get_gsid(struct SECURITY_API *scapi, gid_t gid, char *buf)
{
	const SID *gsid;
	BIGSID defgsid;
	int size;

	size = 0;
	if (scapi && (scapi->magic == MAGIC_API)) {
		gsid = find_gsid(&scapi->security, gid, (SID*)&defgsid);
		if (gsid) {
			size = sid_size(gsid);
			memcpy(buf,gsid,size);
		} else
			errno = ENODATA;
	} else
		errno = EINVAL;
	return (size);
}

/*
 *		Get the user mapped to a SID
 *
 *	returns the uid, or -1 if not found
 */

int ntfs_get_user(struct SECURITY_API *scapi, const SID *usid)
{
	int uid;

	uid = -1;
	if (scapi && (scapi->magic == MAGIC_API) && valid_sid(usid)) {
		if (same_sid(usid,adminsid))
			uid = 0;
		else {
			uid = findowner(&scapi->security, usid);
			if (!uid) {
				uid = -1;
				errno = ENODATA;
			}
		}
	} else
		errno = EINVAL;
	return (uid);
}

/*
 *		Get the group mapped to a SID
 *
 *	returns the uid, or -1 if not found
 */

int ntfs_get_group(struct SECURITY_API *scapi, const SID *gsid)
{
	int gid;

	gid = -1;
	if (scapi && (scapi->magic == MAGIC_API) && valid_sid(gsid)) {
		if (same_sid(gsid,adminsid))
			gid = 0;
		else {
			gid = findgroup(&scapi->security, gsid);
			if (!gid) {
				gid = -1;
				errno = ENODATA;
			}
		}
	} else
		errno = EINVAL;
	return (gid);
}

/*
 *		Initializations before calling ntfs_get_file_security()
 *	ntfs_set_file_security() and ntfs_read_directory()
 *
 *	Only allowed for root
 *
 *	Returns an (obscured) struct SECURITY_API* needed for further calls
 *		NULL if not root (EPERM) or device is mounted (EBUSY)
 */

struct SECURITY_API *ntfs_initialize_file_security(const char *device,
				int flags)
{
	ntfs_volume *vol;
	unsigned long mntflag;
	int mnt;
	struct SECURITY_API *scapi;
	struct SECURITY_CONTEXT *scx;

	scapi = (struct SECURITY_API*)NULL;
	mnt = ntfs_check_if_mounted(device, &mntflag);
	if (!mnt && !(mntflag & NTFS_MF_MOUNTED) && !getuid()) {
		vol = ntfs_mount(device, flags);
		if (vol) {
			scapi = (struct SECURITY_API*)
				ntfs_malloc(sizeof(struct SECURITY_API));
			if (scapi) {
				scapi->magic = MAGIC_API;
				scapi->seccache = (struct PERMISSIONS_CACHE*)NULL;
				scx = &scapi->security;
				scx->vol = vol;
				scx->uid = getuid();
				scx->gid = getgid();
				scx->pseccache = &scapi->seccache;
				scx->vol->secure_flags = 0;
					/* accept no mapping and no $Secure */
				ntfs_build_mapping(scx,(const char*)NULL);
				ntfs_open_secure(vol);
			} else
				errno = ENOMEM;
		}
	} else
		if (getuid())
			errno = EPERM;
		else
			errno = EBUSY;
	return (scapi);
}

/*
 *		Leaving after ntfs_initialize_file_security()
 *
 *	Returns FALSE if FAILED
 */

BOOL ntfs_leave_file_security(struct SECURITY_API *scapi)
{
	int ok;
	ntfs_volume *vol;

	ok = FALSE;
	if (scapi && (scapi->magic == MAGIC_API) && scapi->security.vol) {
		vol = scapi->security.vol;
		ntfs_close_secure(&scapi->security);
		free(scapi);
 		if (!ntfs_umount(vol, 0))
			ok = TRUE;
	}
	return (ok);
}

