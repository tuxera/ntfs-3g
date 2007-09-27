/**
 * security.c - Handling security/ACLs in NTFS.  Originated from the Linux-NTFS project.
 *
 * Copyright (c) 2004 Anton Altaparmakov
 * Copyright (c) 2005-2006 Szabolcs Szakacsits
 * Copyright (c) 2006 Yura Pakhuchiy
 * Copyright (c) 2007 Jean-Pierre Andre
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

#include "types.h"
#include "layout.h"
#include "attrib.h"
#include "index.h"
#include "dir.h"
#include "security.h"
#include "misc.h"
#include "bitmap.h"

/*
 *	JPA configuration modes for this module
 *	should move to some config file
 */

#define FORCE_FORMAT_v1x 0 /* Insert security data as in NTFS v1.x */
#define BUFSZ 1024		/* buffer size to read mapping file */
#define MAPPINGFILE "/$Mapping" /* name of mapping file */
#define LINESZ 120              /* maximum useful size of a mapping line */

/*
 *	JPA NTFS constants or structs
 *	should move to layout.h
 */

#define ALIGN_SDS_BLOCK 0x40000 /* Alignment for a $SDS block */
#define ALIGN_SDS_ENTRY 16 /* Alignment for a $SDS entry */
#define FIRST_SECURITY_ID 0x100 /* Lowest security id */

struct SII {		/* this is an image of index (le) */
	le16 offs;
	le16 size;
	le32 fill1;
	le16 indexsz;
	le16 indexksz;
	le16 flags;
	le16 fill2;
	le32 keysecurid;

	/* did not found official description for the following */
	le32 hash;
	le32 securid;
	le32 dataoffsl;	/* documented as badly aligned */
	le32 dataoffsh;
	le32 datasize;
} ;

struct SDH {		/* this is an image of index (le) */
	le16 offs;
	le16 size;
	le32 fill1;
	le16 indexsz;
	le16 indexksz;
	le16 flags;
	le16 fill2;
	le32 keyhash;
	le32 keysecurid;

	/* did not found official description for the following */
	le32 hash;
	le32 securid;
	le32 dataoffsl;
	le32 dataoffsh;
	le32 datasize;
	le32 fill3;
	} ;

static ntfschar sii_name[] = { '$', 'S', 'I', 'I', 0 };
static ntfschar sdh_name[] = { '$', 'S', 'D', 'H', 0 };
static ntfschar sds_name[] = { '$', 'S', 'D', 'S', 0 };

/*
 * The zero GUID.
 */
static const GUID __zero_guid = { const_cpu_to_le32(0), const_cpu_to_le16(0),
		const_cpu_to_le16(0), { 0, 0, 0, 0, 0, 0, 0, 0 } };
const GUID *const zero_guid = &__zero_guid;

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
        const le32 *pos = (le32*)sd;
        const le32 *end = pos + (len >> 2);
        u32 hash = 0;

        while (pos < end)
                hash = le32_to_cpup(pos++) + ntfs_rol32(hash, 3);
        return cpu_to_le32(hash);
}


/*
 *         Matching of ntfs permissions to Linux permissions
 *            these constants are adapted to endianness
 *            when setting, set them all
 *            when checking, check one is present
 *               (checks needed)
 */
          /* flags which are set to mean exec, write or read */
#define FILE_READ (FILE_READ_DATA | FILE_READ_EA)
#define FILE_WRITE (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA)
#define FILE_EXEC (FILE_EXECUTE)
#define DIR_READ (FILE_LIST_DIRECTORY | FILE_READ_EA)
#define DIR_WRITE (FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY \
                  | FILE_WRITE_EA | FILE_DELETE_CHILD)
#define DIR_EXEC (FILE_TRAVERSE)

          /* flags interpreted as meaning exec, write or read */
#define FILE_GREAD (FILE_READ | GENERIC_READ)
#define FILE_GWRITE (FILE_WRITE | GENERIC_WRITE)
#define FILE_GEXEC (FILE_EXEC | GENERIC_EXECUTE)
#define DIR_GREAD (DIR_READ | GENERIC_READ)
#define DIR_GWRITE (DIR_WRITE | GENERIC_WRITE)
#define DIR_GEXEC (DIR_EXEC | GENERIC_EXECUTE)

          /* standard owner (and administrator) rights */
#define OWNER_RIGHTS (DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE \
                        | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
          /* standard world rights */
#define WORLD_RIGHTS (READ_CONTROL | FILE_READ_ATTRIBUTES);
          /* inheritance flags for files and directories */
#define FILE_INHERITANCE 0
#define DIR_INHERITANCE (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)

struct MAPLIST {
	struct MAPLIST *next;
	char *uidstr;		/* uid text from the same record */
	char *gidstr;		/* gid text from the same record */
	char *sidstr;		/* sid text from the same record */
	char maptext[LINESZ + 1];
};

/*
 *        The following must be in some library...
 */

unsigned int cpu_to_be32(unsigned int x)
{
	return (((x >> 24) & 255)
		+ ((x >> 8) & 0xff00)
		+ ((x & 0xff00) << 8)
		+ ((x & 255) << 24));
}

/*
 *        The following must be in some library...
 */

unsigned long atoul(const char *p)
{				/* must be somewhere ! */
	unsigned long v;

	v = 0;
	while ((*p >= '0') && (*p <= '9'))
		v = v * 10 + (*p++) - '0';
	return (v);
}

static int sid_size(const SID * sid)
{
	return (sid->sub_authority_count * 4 + 8);
}

/*
 *	Determine the size of a security attribute
 *	whatever the order of fields
 *      we however assume USID, GSID and DACL are present
 */

static int attr_size(const char *attr)
{
	const SECURITY_DESCRIPTOR_RELATIVE *pnhead;
	const ACL *pdacl;
	const SID *psid;
	int offdacl;
	int offsid;
	int endsid;
	int attrsz;

	pnhead = (const SECURITY_DESCRIPTOR_RELATIVE*)attr;
		/* find end of DACL */
	offdacl = le32_to_cpu(pnhead->dacl);
	pdacl = (const ACL*)&attr[offdacl];
	attrsz = offdacl + le16_to_cpu(pdacl->size);
		/* find end of USID */
	offsid = le32_to_cpu(pnhead->owner);
	psid = (const SID*)&attr[offsid];
	endsid = offsid + sid_size(psid);
	if (endsid > attrsz) attrsz = endsid;
		/* find end of GSID */
	offsid = le32_to_cpu(pnhead->group);
	psid = (const SID*)&attr[offsid];
	endsid = offsid + sid_size(psid);
	if (endsid > attrsz) attrsz = endsid;

	return (attrsz);
}

/*
 *           Build an internal representation of a SID
 *         Returns a copy in allocated memory if it succeeds
 *         Currently it does only safety checks
 */

static SID *encodesid(const char *sidstr)
{
	SID *sid;
	int cnt;
	union {
		SID sid;
		char bytes[8 * 4 + 8];	/* maximum size for 8 authorities */
	} bigsid;
	SID *bsid;
	long auth;
	const char *p;

	sid = (SID*) NULL;
	if (!strncmp(sidstr, "S-1-", 4)) {
		bsid = &bigsid.sid;
		bsid->revision = 1;
		p = &sidstr[4];
		auth = atoul(p);
		bsid->identifier_authority.high_part = 0;
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
		if (cnt > 0) {
			sid = (SID*) malloc(4 * cnt + 8);
			if (sid)
				memcpy(sid, bsid, 4 * cnt + 8);
		}
	}
	return (sid);
}



/*
 *          Internal read
 *     copied and pasted from ntfs_fuse_read() and made independent
 *     of fuse context
 */

static int ntfs_local_read(ntfs_volume *vol, ntfs_inode *ni,
		const char *path, ntfschar *stream_name, int stream_name_len,
		char *buf, size_t size, off_t offset)
{
	ntfs_attr *na = NULL;
	int res, total = 0;

	na = ntfs_attr_open(ni, AT_DATA, stream_name, stream_name_len);
	if (!na) {
		res = -errno;
		goto exit;
	}
	if (offset + size > na->data_size)
		size = na->data_size - offset;
	while (size) {
		res = ntfs_attr_pread(na, offset, size, buf);
		if (res < (s64)size)
			ntfs_log_perror("ntfs_attr_pread partial write (%lld: "
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
 *          Internal write
 *     copied and pasted from ntfs_fuse_write() and made independent
 *     of fuse context
 */

static int ntfs_local_write(ntfs_volume *vol, ntfs_inode *ni,
		const char *path, ntfschar *stream_name, int stream_name_len,
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
// !	ntfs_fuse_mark_free_space_outdated();
	if (na)
		ntfs_attr_close(na);
	return res;
}

/*
 *                 Build a sid for world user
 *               (a constant in static data, do not free)
 */

static const SID *worldsid(void)
{
	static char wsid[] = {
		1,		/* revision */
		1,		/* auth count */
		0, 0, 0, 0, 0, 1,	/* base */
		0, 0, 0, 0	/* 1st level */
	};

	return ((SID*) wsid);
}

/*
 *                 Build a sid for administrator
 *               (a constant in static data, do not free)
 */

static const SID *adminsid(void)
{
	static char asid[] = {
		1,		/* revision */
		2,		/* auth count */
		0, 0, 0, 0, 0, 5,	/* base */
		32, 0, 0, 0,	/* 1st level */
		32, 2, 0, 0	/* 2nd level */
	};

	return ((const SID*)asid);
}

/*
 *                 Build a sid for system
 *               (a constant in static data, do not free)
 */

static const SID *systemsid(void)
{
	static char ssid[] = {
		1,		/* revision */
		1,		/* auth count */
		0, 0, 0, 0, 0, 5,	/* base */
		18, 0, 0, 0 	/* 1st level */
	};

	return ((const SID*)ssid);
}

/*
 *          Find Linux owner mapped to a usid
 *           Returns 0 (root) if not found
 */

static int findowner(struct SECURITY_CONTEXT *scx, const SID * usid)
{
	struct MAPPING *p;
	int usidsz;

	usidsz = sid_size(usid);
	p = scx->usermapping;
	while (p && memcmp(usid, p->sid, usidsz))
		p = p->next;
	return (p ? p->xid : 0);
}

/*
 *          Find Linux group mapped to a gsid
 *           Returns 0 (root) if not found
 */

static int findgroup(struct SECURITY_CONTEXT *scx, const SID * gsid)
{
	struct MAPPING *p;
	int gsidsz;

	gsidsz = sid_size(gsid);
	p = scx->groupmapping;
	while (p && memcmp(gsid, p->sid, gsidsz))
		p = p->next;
	return (p ? p->xid : 0);
}

/*
 *          Find usid mapped to a Linux user
 *           Returns NULL if not found
 */

static const SID *find_usid(struct SECURITY_CONTEXT *scx, uid_t uid)
{
	struct MAPPING *p;
	const SID *sid;

	if (!uid)
		sid = adminsid();
	else {
		p = scx->usermapping;
		while (p && (p->xid != uid))
			p = p->next;
		sid = (p ? p->sid : (const SID*)NULL);
	}
	return (sid);
}

/*
 *          Find Linux group mapped to a gsid
 *           Returns 0 (root) if not found
 */

static const SID *find_gsid(struct SECURITY_CONTEXT *scx, gid_t gid)
{
	struct MAPPING *p;
	const SID *sid;

	if (!gid)
		sid = adminsid();
	else {
		p = scx->groupmapping;
		while (p && (p->xid != gid))
			p = p->next;
		sid = (p ? p->sid : (const SID*)NULL);
	}
	return (sid);
}

/*
 *	Resize security cache in either direction
 *	do not call unless resizing is needed
 *	
 *	returns pointer to required entry or NULL if not possible
 */


static struct SECURITY_ENTRY *resize_cache(struct SECURITY_CONTEXT *scx,
			 le32 securid)
{
	struct SECURITY_ENTRY *cacheentry;
	struct SECURITY_CACHE *oldcache;
	struct SECURITY_CACHE *newcache;
	int oldcnt;
	int newcnt;
	int i;

	cacheentry = (struct SECURITY_ENTRY*)NULL;
	oldcache = *scx->pseccache;
	if (oldcache->head.last < securid) {
		/* expand cache beyond current end */
		newcnt = securid - oldcache->head.first + 1;
		newcache = (struct SECURITY_CACHE*)
			realloc(oldcache,
			    sizeof(struct SECURITY_HEAD)
			      +  newcnt*sizeof(struct SECURITY_ENTRY));
		if (newcache) {
				/* mark new entries as not valid */
			for (i=newcache->head.last+1; i<=securid; i++)
				newcache->cachetable[
					i - newcache->head.first].valid = 0;
			newcache->head.last = securid;
			*scx->pseccache = newcache;
			cacheentry = &newcache->
				cachetable[securid - newcache->head.first];
		}
	} else {
		/* expand cache before current beginning */
		newcnt = oldcache->head.last - securid + 1;
		newcache = (struct SECURITY_CACHE*)
			malloc(sizeof(struct SECURITY_HEAD)
			    +  newcnt*sizeof(struct SECURITY_ENTRY));
		if (newcache) {
				/* mark new entries as not valid */
			for (i=securid; i<oldcache->head.first; i++)
				newcache->cachetable[i - securid].valid = 0;
			newcache->head.first = securid;
			newcache->head.last = oldcache->head.last;
			newcache->head.attempts = oldcache->head.attempts;
			newcache->head.reads = oldcache->head.reads;
			newcache->head.writes = oldcache->head.writes;
			oldcnt = oldcache->head.last - oldcache->head.first + 1;
			memcpy(&newcache->cachetable[oldcache->head.first
						 - newcache->head.first],
				oldcache->cachetable,
				oldcnt*sizeof(struct SECURITY_ENTRY));
			*scx->pseccache = newcache;
			free(oldcache);
			cacheentry = &newcache->cachetable[0];
		}
	}
	return (cacheentry);
}


/*
 *	Enter uid, gid and mode into cache, if possible
 *
 *	returns the updated or created cache entry,
 *	or NULL if not possible (typically if there is no
 *		security id associated)
 */

static struct SECURITY_ENTRY *enter_cache(struct SECURITY_CONTEXT *scx,
		ntfs_inode *ni, uid_t uid, gid_t gid, mode_t mode)
{
	struct SECURITY_ENTRY *cacheentry;
	struct SECURITY_CACHE *pcache;

	/* cacheing is only possible if a security_id has been defined */
	if (test_nino_flag(ni, v3_Extensions)
	   && (ni->security_id)) {
		/*
		 *  Immediately test the most frequent situation
		 *  where the entry exists
		 */
		pcache = *scx->pseccache;
		if (pcache
		     && (pcache->head.first <= ni->security_id)
		     && (pcache->head.last >= ni->security_id)) {
			cacheentry = &pcache->cachetable[ni->security_id
					 - pcache->head.first];
			cacheentry->uid = uid;
			cacheentry->gid = gid;
			cacheentry->mode = mode;
			cacheentry->valid = 1;
			pcache->head.writes++;
		} else {
			if (!pcache) {
				/* create the first cache entry */
				pcache = (struct SECURITY_CACHE*)
					malloc(sizeof(struct SECURITY_HEAD)
					    +  sizeof(struct SECURITY_ENTRY));
				pcache->head.first = ni->security_id;
				pcache->head.last = ni->security_id;
				pcache->head.attempts = 0;
				pcache->head.reads = 0;
				pcache->head.writes = 0;
				*scx->pseccache = pcache;
				cacheentry = &pcache->cachetable[0];
			} else {
				cacheentry = resize_cache(scx, ni->security_id);
			}
			if (cacheentry) {
				cacheentry->uid = uid;
				cacheentry->gid = gid;
				cacheentry->mode = mode;
				cacheentry->valid = 1;
				pcache->head.writes++;
			}
		}
	} else
		cacheentry = (struct SECURITY_ENTRY*)NULL;
	return (cacheentry);
}

/*
 *	Fetch a cache entry, if available
 *
 *	Beware : do not use the returned entry after a cache update :
 *	the cache may be relocated making the returned entry meaningless
 *
 *	returns the cache entry, or NULL if not available
 */

static struct SECURITY_ENTRY *fetch_cache(struct SECURITY_CONTEXT *scx,
		ntfs_inode *ni)
{
	struct SECURITY_ENTRY *cacheentry;
	struct SECURITY_CACHE *pcache;

	/* cacheing is only possible if a security_id has been defined */
	cacheentry = (struct SECURITY_ENTRY*)NULL;
	if (test_nino_flag(ni, v3_Extensions)
	   && (ni->security_id)) {
		pcache = *scx->pseccache;
		if (pcache
		     && (pcache->head.first <= ni->security_id)
		     && (pcache->head.last >= ni->security_id)) {
			cacheentry = &pcache->cachetable[ni->security_id
					 - pcache->head.first];
			/* reject if entry is not valid */
			if (!cacheentry->valid)
				cacheentry = (struct SECURITY_ENTRY*)NULL;
			else
				pcache->head.reads++;
		if (pcache)
			pcache->head.attempts++;
		}
	}
	return (cacheentry);
}

static char *indexsearch(struct SECURITY_CONTEXT *scx, SII_INDEX_KEY id)
{
	struct SII *psii;	/* this is an image of index (le) */
	union {
		struct {
			u32 dataoffsl;
			u32 dataoffsh;
		} parts;
		u64 all;
	} realign;
	int found;
	size_t size;
	size_t rdsize;
	s64 offs;
	ntfs_inode *ni;
	ntfs_index_context *xc;
	char *securattr;

	securattr = (char*)NULL;
	ni = ntfs_pathname_to_inode(scx->vol, NULL, "$Secure");
	if (ni) {
		xc = ntfs_index_ctx_get(ni, sii_name, 4);
		if (xc) {
			found =
			    !ntfs_index_lookup((char*)&id,
					       sizeof(SII_INDEX_KEY), xc);
			if (found) {
				psii = (struct SII*)xc->entry;
				size =
				    (size_t) le32_to_cpu(psii->datasize) - 20;
				/* work around bad alignment problem */
				realign.parts.dataoffsh = psii->dataoffsh;
				realign.parts.dataoffsl = psii->dataoffsl;
				offs = le64_to_cpu(realign.all) + 20;

				securattr = (char*)malloc(size);
				if (securattr) {
					rdsize = ntfs_local_read(
						scx->vol,ni, "/$Secure",
						sds_name,4,
						securattr, size, offs);
					if (rdsize != size) {
						free(securattr);
						securattr = (char*)NULL;
					}
				}
			}
			ntfs_index_ctx_put(xc);
		}
		ntfs_inode_close(ni);
	}
	if (!securattr)
		errno = EIO;
	return (securattr);
}

/*
 *            Get the security descriptor associated to a file
 *
 *    Either :
 *         - read the security descriptor attribute (v1.x format)
 *         - or find the descriptor in $Secure:$SDS (v3.x format)
 *
 *   The returned descriptor is dynamically allocated and has to be freed
 */

static char *build_secur_descr(const char *path, mode_t mode,
			int isdir, const SID * usid, const SID * gsid);

static char *getsecurityattr(struct SECURITY_CONTEXT *scx,
		const char *path, ntfs_inode *ni)
{
	SII_INDEX_KEY securid;
	const SID *asid;
	char *securattr;
	ntfschar nullchar = 0;
	s64 readallsz;

		/*
		 * Warning : in some situations, after fixing by chkdsk,
		 * v3_Extensions are marked present (long standard informations)
		 * with a default security descriptor inserted in an
		 * attribute
		 */
	if (test_nino_flag(ni, v3_Extensions) && ni->security_id) {
			/* get v3.x descriptor in $Secure */
		securid.security_id = ni->security_id;
		securattr = indexsearch(scx,securid);
	} else {
			/* get v1.x security attribute */
		readallsz = 0;
		securattr = ntfs_attr_readall(ni, AT_SECURITY_DESCRIPTOR,
				&nullchar, 0,&readallsz);
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
		asid = adminsid();
		securattr = build_secur_descr(path, 0, 0, asid, asid);
	}
	return (securattr);
}

/*
 *               test whether a SID means "world user"
 */

static int is_world_sid(const SID * usid)
{
	int any;

             /* check whether S-1-1-0 */
        any = (usid->sub_authority_count == 1)
            && (usid->identifier_authority.high_part == cpu_to_be32(0))
            && (usid->identifier_authority.low_part == cpu_to_be32(1))
            && (usid->sub_authority[0] == cpu_to_le32(0));
	return (any);
}

/*
 *               test whether a SID means "some user"
 */

static int is_user_sid(const SID * usid)
{
	int user;

             /* check whether S-1-5-21... */
        user = (usid->sub_authority_count == 5)
            && (usid->identifier_authority.high_part == cpu_to_be32(0))
            && (usid->identifier_authority.low_part == cpu_to_be32(5))
            && (usid->sub_authority[0] == cpu_to_le32(21));
	return (user);
}

static int merge_permissions(ntfs_inode *ni,
		le32 owner, le32 group, le32 world)

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
//TRACE(fprintf(stderr,"owner allow 0x%x deny 0x%x perm 0%03o\n",owner,denyown,perm));
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
//TRACE(fprintf(stderr,"group allow 0x%x deny 0x%x perm 0%03o\n",group,denygrp,perm));
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
	return (perm);
}


static int build_std_permissions(struct SECURITY_CONTEXT *scx,
			const char *securattr, ntfs_inode *ni)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const ACL *pacl;
	const ACCESS_ALLOWED_ACE *pace;
	const SID *usid;	/* owner of file/directory */
	const SID *gsid;	/* group of file/directory */
	int usidsz;
	int gsidsz;
	int offdacl;
	int offace;
	int acecnt;
	int nace;
	le32 allowown, allowgrp, allowall;
	le32 denyown, denygrp, denyall;

	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)securattr;
	usid = (SID*)&securattr[le32_to_cpu(phead->owner)];
	usidsz = sid_size(usid);
	gsid = (SID*)&securattr[le32_to_cpu(phead->group)];
	gsidsz = sid_size(gsid);
	offdacl = le32_to_cpu(phead->dacl);
	pacl = (ACL*)&securattr[offdacl];
	allowown = allowgrp = allowall = cpu_to_le32(0);
	denyown = denygrp = denyall = cpu_to_le32(0);
	acecnt = le16_to_cpu(pacl->ace_count);
	offace = offdacl + sizeof(ACL);
	for (nace = 0; nace < acecnt; nace++) {
		pace = (const ACCESS_ALLOWED_ACE*)&securattr[offace];
		if (!memcmp(usid, &pace->sid, usidsz)) {
			if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
				allowown |= pace->mask;
			else if (pace->type == ACCESS_DENIED_ACE_TYPE)
				denyown |= pace->mask;
//TRACE(fprintf(stderr,"owner allow 0x%x deny 0x%x\n",allowown,denyown));
			} else
			if (!memcmp(gsid, &pace->sid, gsidsz)) {
				if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
					allowgrp |= pace->mask;
				else if (pace->type == ACCESS_DENIED_ACE_TYPE)
					denygrp |= pace->mask;
//TRACE(fprintf(stderr,"group allow 0x%x deny 0x%x\n",allowgrp,denygrp));
			} else
				if (is_world_sid((const SID*)&pace->sid)) {
					if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
						allowall |= pace->mask;
					else
						if (pace->type == ACCESS_DENIED_ACE_TYPE)
							denyall |= pace->mask;
//TRACE(fprintf(stderr,"world allow 0x%x deny 0x%x\n",allowall,denyall));
				}
			offace += le16_to_cpu(pace->size);
		}
		/*
		 *  Add to owner rights granted to group or world
		 * unless denied personaly, and add to group rights
		 * granted to world unless denied specifically
		 */
	allowown |= allowgrp | allowall;
	allowgrp |= allowall;
	return (merge_permissions(ni,
				allowown & ~denyown,
				allowgrp & ~denygrp,
				allowall & ~denyall));
}


static int build_owngrp_permissions(struct SECURITY_CONTEXT *scx,
			const char *securattr, ntfs_inode *ni)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const ACL *pacl;
	const ACCESS_ALLOWED_ACE *pace;
	const SID *usid;	/* owner and group of file/directory */
	int usidsz;
	int offdacl;
	int offace;
	int acecnt;
	int nace;
	le32 allowown, allowgrp, allowall;
	le32 denyown, denygrp, denyall;

	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)securattr;
	usid = (SID*)&securattr[le32_to_cpu(phead->owner)];
	usidsz = sid_size(usid);
	offdacl = le32_to_cpu(phead->dacl);
	pacl = (ACL*)&securattr[offdacl];
	allowown = allowgrp = allowall = cpu_to_le32(0);
	denyown = denygrp = denyall = cpu_to_le32(0);
	acecnt = le16_to_cpu(pacl->ace_count);
	offace = offdacl + sizeof(ACL);
	for (nace = 0; nace < acecnt; nace++) {
		pace = (const ACCESS_ALLOWED_ACE*)&securattr[offace];
		if (!memcmp(usid, &pace->sid, usidsz)
		   && (pace->mask & FILE_WRITE_ATTRIBUTES)) {
			if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
				allowown |= pace->mask;
//TRACE(fprintf(stderr,"owner allow 0x%x deny 0x%x\n",allowown,denyown));
			} else
			if (!memcmp(usid, &pace->sid, usidsz)
			   && (!(pace->mask & FILE_WRITE_ATTRIBUTES))) {
				if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
					allowgrp |= pace->mask;
//TRACE(fprintf(stderr,"group allow 0x%x deny 0x%x\n",allowgrp,denygrp));
			} else
				if (is_world_sid((const SID*)&pace->sid)) {
					if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
						allowall |= pace->mask;
					else
						if (pace->type == ACCESS_DENIED_ACE_TYPE)
							denyall |= pace->mask;
//TRACE(fprintf(stderr,"world allow 0x%x deny 0x%x\n",allowall,denyall));
				}
			offace += le16_to_cpu(pace->size);
		}
	return (merge_permissions(ni,
				allowown & ~denyown,
				allowgrp & ~denygrp,
				allowall & ~denyall));
}


static int build_ownadmin_permissions(struct SECURITY_CONTEXT *scx,
			const char *securattr, ntfs_inode *ni)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const ACL *pacl;
	const ACCESS_ALLOWED_ACE *pace;
	const SID *usid;	/* owner of file/directory */
	const SID *gsid;	/* group of file/directory */
	int usidsz;
	int gsidsz;
	int offdacl;
	int offace;
	int acecnt;
	int nace;
	le32 allowown, allowgrp, allowall;
	le32 denyown, denygrp, denyall;

	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)securattr;
	usid = (SID*)&securattr[le32_to_cpu(phead->owner)];
	usidsz = sid_size(usid);
	gsid = (SID*)&securattr[le32_to_cpu(phead->group)];
	gsidsz = sid_size(gsid);
	offdacl = le32_to_cpu(phead->dacl);
	pacl = (ACL*)&securattr[offdacl];
	allowown = allowgrp = allowall = cpu_to_le32(0);
	denyown = denygrp = denyall = cpu_to_le32(0);
	acecnt = le16_to_cpu(pacl->ace_count);
//TRACE(fprintf(ntfslog,"adminowns %d acecnt %d\n",adminowns,acecnt));
	offace = offdacl + sizeof(ACL);
	for (nace = 0; nace < acecnt; nace++) {
		pace = (const ACCESS_ALLOWED_ACE*)&securattr[offace];
		if (!memcmp(usid, &pace->sid, usidsz)
		   && (((pace->mask & FILE_WRITE_ATTRIBUTES) && !nace))) {
			if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
				allowown |= pace->mask;
			else
				if (pace->type == ACCESS_DENIED_ACE_TYPE)
					denyown |= pace->mask;
//TRACE(fprintf(stderr,"owner allow 0x%x deny 0x%x\n",allowown,denyown));
			} else
			    if (!memcmp(gsid, &pace->sid, gsidsz)
				&& (!(pace->mask & FILE_WRITE_ATTRIBUTES))) {
					if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
						allowgrp |= pace->mask;
					else
						if (pace->type == ACCESS_DENIED_ACE_TYPE)
							denygrp |= pace->mask;
//TRACE(fprintf(stderr,"group allow 0x%x deny 0x%x\n",allowgrp,denygrp));
				} else if (is_world_sid((const SID*)&pace->sid)) {
					if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
						allowall |= pace->mask;
					else
						if (pace->type == ACCESS_DENIED_ACE_TYPE)
							denyall |= pace->mask;
//TRACE(fprintf(stderr,"world allow 0x%x deny 0x%x\n",allowall,denyall));
				}
			offace += le16_to_cpu(pace->size);
		}
	return (merge_permissions(ni,
				allowown & ~denyown,
				allowgrp & ~denygrp,
				allowall & ~denyall));
}

/*
 *          Build unix-style (mode_t) permissions
 *     optionally filtered by the relation of user to file (owner, group or other)
 *     returns a negative result and sets errno if there is a problem
 */

static int build_permissions(struct SECURITY_CONTEXT *scx,
		const char *securattr, ntfs_inode *ni)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const SID *usid;	/* owner of file/directory */
	const SID *gsid;	/* group of file/directory */
	int usidsz;
	int gsidsz;
	int perm;
	BOOL adminowns;
	BOOL groupowns;

	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)securattr;
	if (phead->control & SE_DACL_PRESENT) {	/* no DACL, reject */
		usid = (SID*)&securattr[le32_to_cpu(phead->owner)];
		usidsz = sid_size(usid);
		gsid = (SID*)&securattr[le32_to_cpu(phead->group)];
		gsidsz = sid_size(gsid);
		adminowns = !memcmp(usid,adminsid(),usidsz)
		         || !memcmp(gsid,adminsid(),gsidsz);
		groupowns = !adminowns && !memcmp(gsid,usid,gsidsz);
		if (adminowns)
			perm = build_ownadmin_permissions(scx,securattr,
					ni);
		else
			if (groupowns)
				perm = build_owngrp_permissions(scx,securattr,
						ni);
			else
				perm = build_std_permissions(scx,securattr,
						ni);
	} else {
		perm = -1;
		errno = EIO;
	}
	return (perm);
}

/*
 *          Get permissions to access a file
 *        Takes into account the relation of user to file (owner, group, ...)
 *        Do no use as mode of the file
 *
 *	returns -1 if there is a problem
 */

static int ntfs_get_perm(struct SECURITY_CONTEXT *scx,
		 const char *path, ntfs_inode * ni)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const struct SECURITY_ENTRY *cached;
	const char *securattr;
	const SID *usid;	/* owner of file/directory */
	const SID *gsid;	/* group of file/directory */
	uid_t uid;
	gid_t gid;
	int perm;

	if (!scx->usermapping || !scx->uid)
		perm = 0777;
	else {
		/* check whether available in cache */
		cached = fetch_cache(scx,ni);
		if (cached) {
			perm = cached->mode;
			uid = cached->uid;
			gid = cached->gid;
		} else {
			perm = 0;	/* default to no permission */
			securattr = getsecurityattr(scx,path, ni);
			if (securattr) {
				perm = build_permissions(scx,securattr, ni);
					/* fetch owner and group for cacheing */
				if (perm >= 0) {
					phead =
					    (const SECURITY_DESCRIPTOR_RELATIVE*)
					    	securattr;
					usid = (SID*)&
					    securattr[le32_to_cpu(phead->owner)];
					gsid = (SID*)&
					    securattr[le32_to_cpu(phead->group)];
					uid = findowner(scx,usid);
					gid = findgroup(scx,gsid);
					enter_cache(scx, ni, uid,
							gid, perm);
				}
				free((void*)securattr);
			} else
				perm = -1;
				uid = gid = 0;
		}
	}
	if (perm >= 0) {
		if (uid == scx->uid)
			perm &= 0700;
		else
			if (gid == scx->gid)
				perm &= 070;
			else
				perm &= 007;
	}
	return (perm);
}

/*
 *          Get owner, group and permissions in an stat structure
 *              returns permissions, or -1 if there is a problem
 */

int ntfs_get_owner_mode(struct SECURITY_CONTEXT *scx,
		const char *path, ntfs_inode * ni,
		 struct stat *stbuf)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const char *securattr;
	const SID *usid;	/* owner of file/directory */
	const SID *gsid;	/* group of file/directory */
	const struct SECURITY_ENTRY *cached;
	int perm;

	if (!scx->usermapping)
		perm = 0777;
	else {
			/* check whether available in cache */
		cached = fetch_cache(scx,ni);
		if (cached) {
			perm = cached->mode;
			stbuf->st_uid = cached->uid;
			stbuf->st_gid = cached->gid;
			stbuf->st_mode = (stbuf->st_mode & ~0777) + perm;
		} else {
			perm = -1;	/* default to error */
			securattr = getsecurityattr(scx,path, ni);
			if (securattr) {
				perm = build_permissions(scx,securattr, ni);
				if (perm >= 0) {
					phead =
					    (const SECURITY_DESCRIPTOR_RELATIVE*)
					    	securattr;
					usid = (SID*)&
					    securattr[le32_to_cpu(phead->owner)];
					gsid = (SID*)&
					    securattr[le32_to_cpu(phead->group)];
					stbuf->st_uid = findowner(scx,usid);
					stbuf->st_gid = findgroup(scx,gsid);
					stbuf->st_mode =
					    (stbuf->st_mode & ~0777) + perm;
					enter_cache(scx, ni, stbuf->st_uid,
						stbuf->st_gid, perm);
				}
				free((void*)securattr);
			}
		}
	}
	return (perm);
}

/*
 *               Build an ACL composed of several ACE's
 *           (not expected to fail)
 *
 *	Three schemes are defined :
 *
 *	1) if root is neither owner nor group up to 7 ACE's are set up :
 *	- grants to owner (always present)
 *	- denials to owner (preventing grants to world or group to apply)
 *	- grants to group (unless groups has same rights as world)
 *	- denials to group (preventing grants to world to apply) 
 *	- grants to world (unless none)
 *	- full privileges to administrator, always present
 *	- full privileges to system, always present
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
 *	- grants to owner (always present)
 *	- denials to owner (preventing grants to world to apply)
 *	- grants to group (unless groups has same rights as world)
 *	- grants to world (unless none)
 *	- full privileges to administrator, always present
 *	- full privileges to system, always present
 *
 *	On Windows, these ACE's are processed normally, though they
 *	are redundant (as owner group are the same, but this has
 *	no impact on administrator rights)
 */

static int buildacls(char *secattr, int offs, mode_t mode, int isdir,
	       const SID * usid, const SID * gsid)
{
	ACL *pacl;
	ACCESS_ALLOWED_ACE *pgace;
	ACCESS_ALLOWED_ACE *pdace;
	const SID *wsid;
	const SID *asid;
	const SID *ssid;
	BOOL adminowns;
	BOOL groupowns;
	int pos;
	int acecnt;
	int usidsz;
	int gsidsz;
	int wsidsz;
	int asidsz;
	int ssidsz;
	long grants;
	long denials;

	usidsz = sid_size(usid);
	gsidsz = sid_size(gsid);
	asid = adminsid();
	asidsz = sid_size(asid);
	ssid = systemsid();
	ssidsz = sid_size(ssid);
	adminowns = !memcmp(usid, asid, usidsz)
	         || !memcmp(gsid, asid, gsidsz);
	groupowns = !adminowns && !memcmp(usid, gsid, usidsz);

	/* ACL header */
	pacl = (ACL*)&secattr[offs];
	pacl->revision = ACL_REVISION;
	pacl->alignment1 = 0;
	pacl->size = sizeof(ACL) + usidsz + 8;
	pacl->ace_count = cpu_to_le16(1);
	pacl->alignment2 = 0;
	pos = sizeof(ACL);
	acecnt = 0;

	/* a grant ACE for owner */

	pgace = (ACCESS_ALLOWED_ACE*) &secattr[offs + pos];
	pgace->type = ACCESS_ALLOWED_ACE_TYPE;
	pgace->size = usidsz + 8;
	grants = OWNER_RIGHTS;
	if (isdir) {
		pgace->flags = DIR_INHERITANCE;
		if (mode & S_IXUSR)
			grants |= DIR_EXEC;
		if (mode & S_IWUSR)
			grants |= DIR_WRITE;
		if (mode & S_IRUSR)
			grants |= DIR_READ;
	} else {
		pgace->flags = FILE_INHERITANCE;
		if (mode & S_IXUSR)
			grants |= FILE_EXEC;
		if (mode & S_IWUSR)
			grants |= FILE_WRITE;
		if (mode & S_IRUSR)
			grants |= FILE_READ;
	}
	pgace->mask = cpu_to_le32(grants);
	memcpy((char*)&pgace->sid, usid, usidsz);
	pos += pgace->size;
	acecnt++;

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
			pdace->size = usidsz + 8;
			pdace->mask = cpu_to_le32(denials);
			memcpy((char*)&pdace->sid, usid, usidsz);
			pos += pdace->size;
			acecnt++;
		}
	}

	/* a grant ACE for group */
	/* unless group has the same rights as world */
	/* but present if owner is administrator */

	if (adminowns
	    || (((mode >> 3) ^ mode) & 7)) {
		pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
		pgace->type = ACCESS_ALLOWED_ACE_TYPE;
		pgace->size = gsidsz + 8;
		grants = WORLD_RIGHTS;
		if (isdir) {
			pgace->flags = DIR_INHERITANCE;
			if (mode & S_IXGRP)
				grants |= DIR_EXEC;
			if (mode & S_IWGRP)
				grants |= DIR_WRITE;
			if (mode & S_IRGRP)
				grants |= DIR_READ;
		} else {
			pgace->flags = FILE_INHERITANCE;
			if (mode & S_IXGRP)
				grants |= FILE_EXEC;
			if (mode & S_IWGRP)
				grants |= FILE_WRITE;
			if (mode & S_IRGRP)
				grants |= FILE_READ;
		}
		pgace->mask = cpu_to_le32(grants);
		memcpy((char*)&pgace->sid, gsid, gsidsz);
		pos += pgace->size;
		acecnt++;

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
			denials &= ~grants;
			if (denials) {
				pdace->type = ACCESS_DENIED_ACE_TYPE;
				pdace->size = gsidsz + 8;
				pdace->mask = cpu_to_le32(denials);
				memcpy((char*)&pdace->sid, gsid, gsidsz);
				pos += pdace->size;
				acecnt++;
			}
		}
	}

	/* an ACE for world users */

	wsid = worldsid();
	wsidsz = sid_size(wsid);
	pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
	pgace->type = ACCESS_ALLOWED_ACE_TYPE;
	pgace->size = wsidsz + 8;
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
	pgace->mask = cpu_to_le32(grants);
	memcpy((char*)&pgace->sid, wsid, wsidsz);
	pos += pgace->size;
	acecnt++;

	/* an ACE for administrators */
	/* always full access */

	pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
	pgace->type = ACCESS_ALLOWED_ACE_TYPE;
	if (isdir)
		pgace->flags = DIR_INHERITANCE;
	else
		pgace->flags = FILE_INHERITANCE;
	pgace->size = asidsz + 8;
	grants = OWNER_RIGHTS | FILE_READ | FILE_WRITE | FILE_EXEC;
	pgace->mask = cpu_to_le32(grants);
	memcpy((char*)&pgace->sid, asid, asidsz);
	pos += pgace->size;
	acecnt++;

	/* an ACE for system (needed ?) */
	/* always full access */

	pgace = (ACCESS_ALLOWED_ACE*)&secattr[offs + pos];
	pgace->type = ACCESS_ALLOWED_ACE_TYPE;
	if (isdir)
		pgace->flags = DIR_INHERITANCE;
	else
		pgace->flags = FILE_INHERITANCE;
	pgace->size = ssidsz + 8;
	grants = OWNER_RIGHTS | FILE_READ | FILE_WRITE | FILE_EXEC;
	pgace->mask = cpu_to_le32(grants);
	memcpy((char*)&pgace->sid, ssid, ssidsz);
	pos += pgace->size;
	acecnt++;

	/* fix ACL header */
	pacl->size = cpu_to_le16(pos);
	pacl->ace_count = cpu_to_le16(acecnt);
	return (pos);
}

/*
 *                Build a full security descriptor
 *            (in allocated memory, must free() after use)
 */

static char *build_secur_descr(const char *path, mode_t mode,
			int isdir, const SID * usid, const SID * gsid)
{
	int newattrsz;
	SECURITY_DESCRIPTOR_RELATIVE *pnhead;
	const SID *wsid;
	char *newattr;
	int aclsz;
	int usidsz;
	int gsidsz;
	int wsidsz;
	int asidsz;
	int ssidsz;

	wsid = worldsid();
	usidsz = sid_size(usid);
	gsidsz = sid_size(gsid);
	wsidsz = sid_size(wsid);
	asidsz = sid_size(adminsid());
	ssidsz = sid_size(systemsid());

	/* allocate enough space for the new security attribute */
	newattrsz = sizeof(SECURITY_DESCRIPTOR_RELATIVE)	/* header */
	    + usidsz + gsidsz	/* usid and gsid */
	    + sizeof(ACL)	/* acl header */
	    + 2*(8 + usidsz)	/* two possible ACE for user */
	    + 2*(8 + gsidsz)	/* two possible ACE for group */
	    + 8 + wsidsz	/* one ACE for world */
	    + 8 + asidsz 	/* one ACE for admin */
	    + 8 + ssidsz;	/* one ACE for system */
	newattr = (char*)malloc(newattrsz);
	if (newattr) {
		/* build the main header part */
		pnhead = (SECURITY_DESCRIPTOR_RELATIVE*) newattr;
		pnhead->revision = 1;
		pnhead->alignment = 0;
		pnhead->control = SE_DACL_PRESENT | SE_SELF_RELATIVE;
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
 *	Get the first entry of current index block
 *	cut and pasted form ntfs_ie_get_first() in index.c
 */

static INDEX_ENTRY *ntfs_ie_get_first(INDEX_HEADER *ih)
{
	return (INDEX_ENTRY*)((u8*)ih + le32_to_cpu(ih->entries_offset));
}

/*
 *	get next index entry in current block or next block
 *	(limited to SII and SDH)
 *
 *	returns NULL at end of last block
 *
 * ! make sure getting next key value always returns an entry !
 * ! in the correct index level (a block with no child)       !
 *
 *	linking to next block should be improved and made generic
 *		(walk into tree instead of lookup)
 *	then function should then be made public in index.c
 */

static INDEX_ENTRY *ntfs_index_next(INDEX_ENTRY *ie, ntfs_index_context *xc,
			BOOL forsii)
{
	INDEX_ENTRY *next;
	struct SII *psii;
	struct SDH *psdh;
	SDH_INDEX_KEY sdhkey;
	le32 siikey;

	if (!(ie->ie_flags & INDEX_ENTRY_END))
		next = (INDEX_ENTRY*)((char*)ie + le16_to_cpu(ie->length));
	else {
		if (forsii) {
			psii = (struct SII*)ie;
			siikey = cpu_to_le32(le32_to_cpu(psii->keysecurid) + 1);
			ntfs_index_lookup((char*)&siikey,sizeof(SII_INDEX_KEY), xc);
		} else {
			psdh = (struct SDH*)ie;
			sdhkey.hash = cpu_to_le32(le32_to_cpu(psdh->keyhash) + 1);
			if (sdhkey.hash)
				sdhkey.security_id = psdh->keysecurid;
			else
				sdhkey.security_id =
				 cpu_to_le32(le32_to_cpu(psdh->keysecurid) + 1);
			ntfs_index_lookup((char*)&sdhkey,sizeof(SDH_INDEX_KEY), xc);
		}
		/*
		 *  ! lookup does not assume next key exists, but we !
		 *  ! do assume we get to the start of correct block anyway !
		 */
		next = xc->entry;
		/* for safety, return NULL at end of last block */
		if ((ie->ie_flags & INDEX_ENTRY_END)
		   && !(ie->ie_flags & INDEX_ENTRY_NODE))
			next = (INDEX_ENTRY*)NULL;
	}
	return (next);
}


/*
 *	Enter a new security descriptor to $Secure (data only)
 *      if has to be written twice with an offset of 256KB
 *	Returns zero if sucessful
 */

static int entersecurity_data(ntfs_volume *vol, ntfs_inode *ni,
			const SECURITY_DESCRIPTOR_RELATIVE *attr, s64 attrsz,
			le32 hash, le32 keyid, off_t offs)
{
	int res;
	int written1;
	int written2;
	char *fullattr;
	SECURITY_DESCRIPTOR_HEADER *phsds;

	res = -1;
	fullattr = malloc(attrsz + 20);
	if (fullattr) {
		memcpy(&fullattr[20],attr,attrsz);
		phsds = (SECURITY_DESCRIPTOR_HEADER*)fullattr;
		phsds->hash = hash;
		phsds->security_id = keyid;
		phsds->offset = cpu_to_le64(offs);
		phsds->length = cpu_to_le64(attrsz + 20);
		written1 = ntfs_local_write(vol, ni, "$Secure",
			sds_name, 4, fullattr, attrsz + 20,
			offs);
		written2 = ntfs_local_write(vol, ni, "$Secure",
			sds_name, 4, fullattr, attrsz + 20,
			offs + ALIGN_SDS_BLOCK);
		if ((written1 == (attrsz + 20))
		     && (written2 == written1))
			res = 0;
		else
			errno = ENOMEM;
		free(fullattr);
	}
	return (res);
}

/*
 *	Enter a new security descriptor in $Secure (indexes only)
 *	Returns zero if sucessful
 */

static int entersecurity_indexes(ntfs_inode *ni,
			const SECURITY_DESCRIPTOR_RELATIVE *attr, s64 attrsz,
			le32 hash, le32 keyid, off_t offs)
{
	union {
		struct {
			u32 dataoffsl;
			u32 dataoffsh;
		} parts;
		u64 all;
	} realign;
	int res;
	ntfs_index_context *xsii;
	ntfs_index_context *xsdh;
	struct SII newsii;
	struct SDH newsdh;

	res = -1;
				/* enter a new $SII record */
	xsii = ntfs_index_ctx_get(ni, sii_name, 4);
	if (xsii) {
		newsii.offs = 20;
		newsii.size = sizeof(struct SII) - 20;
		newsii.fill1 = 0;
		newsii.indexsz = sizeof(struct SII);
		newsii.indexksz = 4;
		newsii.flags = 0;
		newsii.fill2 = 0;
		newsii.keysecurid = keyid;
		newsii.hash = hash;
		newsii.securid = keyid;
		realign.all = cpu_to_le64(offs);
		newsii.dataoffsh = realign.parts.dataoffsh;
		newsii.dataoffsl = realign.parts.dataoffsl;
		newsii.datasize = attrsz + 20;
		if (!ntfs_ie_add(xsii,(INDEX_ENTRY*)&newsii)) {
			xsdh = ntfs_index_ctx_get(ni, sdh_name, 4);
			if (xsdh) {
				/* enter a new $SDH record */
				newsdh.offs = 24;
				newsdh.size = 20;
				newsdh.fill1 = 0;
				newsdh.indexsz = sizeof(struct SDH);
				newsdh.indexksz = 8;
				newsdh.flags = 0;
				newsdh.fill2 = 0;
				newsdh.keyhash = hash;
				newsdh.keysecurid = keyid;
				newsdh.hash = hash;
				newsdh.securid = keyid;
				newsdh.dataoffsh = realign.parts.dataoffsh;
				newsdh.dataoffsl = realign.parts.dataoffsl;
				newsdh.datasize = attrsz + 20;
				newsdh.fill3 = 0;
				if (!ntfs_ie_add(xsdh,(INDEX_ENTRY*)&newsdh))
					res = 0;
				ntfs_index_ctx_put(xsdh);
			}
		}
		ntfs_index_ctx_put(xsii);
	}
	return (res);
}

/*
 *	Enter a new security descriptor in $Secure (data and indexes)
 *	Returns id of entry, or zero if there is a problem.
 *
 *	important : calls have to be serialized, however no locking is
 *	needed while fuse is not multithreaded
 */

static u32 entersecurityattr(ntfs_volume *vol,
			ntfs_inode *ni,
			const SECURITY_DESCRIPTOR_RELATIVE *attr, s64 attrsz,
			le32 hash)
{
	union {
		struct {
			u32 dataoffsl;
			u32 dataoffsh;
		} parts;
		u64 all;
	} realign;
	u32 securid;
	le32 keyid;
	off_t offs;
	int size;
	struct SII *psii;
	INDEX_ENTRY *entry;
	INDEX_ENTRY *next;
	ntfs_index_context *xsii;

	/* find the first available securid beyond the last key */
	/* in $Secure:$SII. This also determines the first */
	/* available location in $Secure:$SDS, as this stream */
	/* is always appended to and the id's are allocated */
	/* in sequence */

	securid = 0;
	xsii = ntfs_index_ctx_get(ni, sii_name, 4);
	if (xsii) {
		offs = size = 0;
		keyid = cpu_to_le32(-1);
		ntfs_index_lookup((char*)&keyid,
				       sizeof(SII_INDEX_KEY), xsii);
		entry = xsii->entry;
		psii = (struct SII*)xsii->entry;
		if (psii) {
			/*
			 * Get last entry in block, but must get first one
			 * one first, as we should already be beyond the
			 * last one. For some reason the search for the last
			 * entry sometimes does not return the last block...
			 * we assume this can only happen in root block
			 */
			if (xsii->is_in_root)
				entry = ntfs_ie_get_first(&xsii->ir->index);
			else
				entry = ntfs_ie_get_first(&xsii->ib->index);
			/*
			 * All index blocks should be at least half full
			 * so there always is a last entry but one,
			 * except when creating the first entry in index root
			 */
			keyid = 0;
			while (!(entry->ie_flags & INDEX_ENTRY_END)) {
				next = ntfs_index_next(entry,xsii,TRUE);
				if (next->ie_flags & INDEX_ENTRY_END) {
					psii = (struct SII*)entry;
						/* save last key and */
						/* available position */
					keyid = psii->keysecurid;
					securid = le32_to_cpu(keyid) + 1;
					realign.parts.dataoffsh = psii->dataoffsh;
					realign.parts.dataoffsl = psii->dataoffsl;
					offs = le64_to_cpu(realign.all);
					size = le32_to_cpu(psii->datasize);
				}
				entry = next;
			}
		}
		if (!securid) {
			/* assume we could have to insert the first entry */
			/* (after upgrading from an old version ?) */
			ntfs_log_error("Creating the first security_id\n");
			securid = FIRST_SECURITY_ID;
		}
		if (securid) {
			/*
			 * The security attr has to be written twice 256KB
			 * apart. This implies that offsets like
			 * 0x40000*odd_integer must be left available for
			 * the second copy. So align to next block when
			 * the last byte overflows on a wrong block.
			 */
			offs += ((size - 1) | (ALIGN_SDS_ENTRY - 1)) + 1;
			if ((offs + attrsz - 1) & ALIGN_SDS_BLOCK)
				offs = ((offs + attrsz - 1)
					 | (ALIGN_SDS_BLOCK - 1)) + 1;
			/* now write the security attr to storage */
			keyid = cpu_to_le32(securid);
			if (entersecurity_data(vol,ni,attr,attrsz,
					hash,keyid,offs)
			    || entersecurity_indexes(ni,attr,attrsz,
					hash,keyid,offs))
				securid = 0;
		} else {
			ntfs_log_error("Could not find an available security_id\n");
			errno = EIO;
		}
		ntfs_index_ctx_put(xsii);
	}
	return (securid);
}

/*
 *	Find a matching security descriptor in $Secure,
 *	if none, allocate a new id and write the descriptor to storage
 *	Returns id of entry, or zero if there is a problem.
 *
 *	important : calls have to be serialized, however no locking is
 *	needed while fuse is not multithreaded
 */

static u32 setsecurityattr(ntfs_volume *vol,
			const SECURITY_DESCRIPTOR_RELATIVE *attr, s64 attrsz)
{
	struct SDH *psdh;	/* this is an image of index (le) */
	union {
		struct {
			u32 dataoffsl;
			u32 dataoffsh;
		} parts;
		u64 all;
	} realign;
	BOOL found;
	BOOL collision;
	size_t size;
	size_t rdsize;
	s64 offs;
	int res;
	ntfs_inode *ni;
	ntfs_index_context *xc;
	char *oldattr;
	SDH_INDEX_KEY key;
	INDEX_ENTRY *entry;
	u32 securid;
	le32 hash;

	hash = ntfs_security_hash(attr,attrsz);
	oldattr = (char*)NULL;
	securid = 0;
	res = 0;
	ni = ntfs_pathname_to_inode(vol, NULL, "$Secure");
	if (ni) {
		xc = ntfs_index_ctx_get(ni, sdh_name, 4);
		if (xc) {
			  /* find the nearest key */
			key.hash = hash;
			key.security_id = 0;
			ntfs_index_lookup((char*)&key,
					       sizeof(SDH_INDEX_KEY), xc);
			entry = xc->entry;
			found = FALSE;
			do {
				collision = FALSE;
				psdh = (struct SDH*)entry;
				size = (size_t) le32_to_cpu(psdh->datasize) - 20;
				   /* if hash is not the same, the key is not present */
				if (psdh && (size > 0)
				   && (psdh->keyhash == hash)) {
					   /* if hash is the same */
					   /* check the whole record */
					realign.parts.dataoffsh = psdh->dataoffsh;
					realign.parts.dataoffsl = psdh->dataoffsl;
					offs = le64_to_cpu(realign.all) + 20;
					oldattr = (char*)malloc(size);
					if (oldattr) {
						rdsize = ntfs_local_read(
							vol, ni, "/$Secure",
							sds_name, 4,
							oldattr, size, offs);
						found = (rdsize == size)
							&& !memcmp(oldattr,attr,size);
						free(oldattr);
						  /* if the records do not compare */
						  /* (hash collision), try next one */
						if (!found) {
							entry = ntfs_index_next(
								entry,xc,FALSE);
							collision = TRUE;
						}
					} else
						res = ENOMEM;
				}
			} while (collision && entry);
			if (found)
				securid = le32_to_cpu(psdh->keysecurid);
			else {
				if (res) {
					errno = res;
					securid = 0;
				} else {
                                 /* no matching key : have to build a new one */
					securid = entersecurityattr(vol,ni,
						attr,attrsz,hash);
				}
			}
			ntfs_index_ctx_put(xc);
		}
		ntfs_inode_close(ni);
	}
   return (securid);
}


/*
 *          Update a security descriptor
 *
 *    returns 0 if success
 */

static int update_secur_descr(ntfs_volume *vol,
				const char *newattr, ntfs_inode *ni)
{
	int newattrsz;
	int written;
	int res;
	ntfs_attr *na;
	ntfschar nullchar = 0;

	newattrsz = attr_size(newattr);

#if !FORCE_FORMAT_v1x
	if (vol->major_ver < 3) {
#endif

		/* update for NTFS format v1.x */

		/* update the old security attribute */
		na = ntfs_attr_open(ni, AT_SECURITY_DESCRIPTOR, &nullchar, 0);
		if (na) {
			/* resize attribute */
			res = ntfs_attr_truncate(na, (s64) newattrsz);
			/* overwrite value */
			if (!res) {
				written = (int)ntfs_attr_pwrite(na, (s64) 0,
					 (s64) newattrsz, newattr);
				if (written != newattrsz) {
					ntfs_log_error("File to update "
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
				&nullchar, 0);
			if (na) {
				clear_nino_flag(ni, v3_Extensions);
			/* Truncating the record does not sweep extensions */
			/* from copy in memory. Clear security_id for precaution */
				ni->security_id = 0;
				res = ntfs_attr_truncate(na, (s64)48);
				ntfs_attr_close(na);
				clear_nino_flag(ni, v3_Extensions);
			}
		} else {
			/* insert the new security attribute if there were none */
			res = ntfs_attr_add(ni, AT_SECURITY_DESCRIPTOR,
					    &nullchar, 0, (u8*)newattr,
					    (s64) newattrsz);
		}
#if !FORCE_FORMAT_v1x
	} else {

		/* update for NTFS format v3.x */

		u32 securid;

		securid = setsecurityattr(vol,
			(const SECURITY_DESCRIPTOR_RELATIVE*)newattr,
			(s64)newattrsz);
		if (securid) {
			na = ntfs_attr_open(ni, AT_STANDARD_INFORMATION,
				&nullchar, 0);
			if (na) {
				res = 0;
				if (!test_nino_flag(ni, v3_Extensions)) {
			/* expand standard information attribute to v3.x */
					res = ntfs_attr_truncate(na, (s64)72);
					ni->owner_id = 0;
					ni->quota_charged = 0;
					ni->usn = 0;
					ntfs_attr_remove(ni,
						AT_SECURITY_DESCRIPTOR,
						&nullchar, 0);
				}
				set_nino_flag(ni, v3_Extensions);
				ni->security_id = cpu_to_le32(securid);
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
	return (res);
}

/*
 *          Set new permissions to a file
 *  Checks user mapping has been defined before request for setting
 *
 *  rejected is request is not originated by owner or root
 *  returns 0 on success
 *         -1 on failure, with errno = EIO
 */

int ntfs_set_mode(struct SECURITY_CONTEXT *scx,
		const char *path, ntfs_inode * ni, mode_t mode)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const struct SECURITY_ENTRY *cached;
	const char *oldattr;
	const char *newattr;
	const SID *usid;
	const SID *gsid;
	uid_t uid;
	uid_t fileuid;
	uid_t filegid;
	int isdir;
	int res;

	/* get the current owner, either from cache or from old attribute  */
	res = 0;
	usid = (const SID*)NULL;
	oldattr = (char*)NULL;
	cached = fetch_cache(scx,ni);
	if (cached) {
		fileuid = cached->uid;
		filegid = cached->gid;
		usid = find_usid(scx,fileuid);
		gsid = find_usid(scx,filegid);
	} else {
		oldattr = getsecurityattr(scx,path, ni);
		if (oldattr) {
			phead = (const SECURITY_DESCRIPTOR_RELATIVE*)oldattr;
			usid = (SID*)&oldattr[le32_to_cpu(phead->owner)];
			gsid = (SID*)&oldattr[le32_to_cpu(phead->group)];
			fileuid = findowner(scx,usid);
			filegid = findowner(scx,gsid);
		 /* do not free oldattr until usid and gsid are not needed */
		}
	}
	if (usid) {
		isdir = (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) != 0;
		uid = scx->uid;
		if (!uid || (fileuid == uid)) {
			newattr = build_secur_descr(path, mode, isdir,
						     usid, gsid);
			if (newattr) {
				res = update_secur_descr(scx->vol, newattr, ni);
				if (!res) {
					enter_cache(scx, ni,
						 fileuid, filegid, mode);
					if (mode & S_IWUSR)
						ni->flags &= ~FILE_ATTR_READONLY;
					else
						ni->flags |= FILE_ATTR_READONLY;
				}
				free((void*)newattr);
			} else {
				 /* could not build new security attribute */
				errno = EIO;
				res = -1;
			}
		} else {
			errno = EPERM;
			res = -1;	/* neither owner nor root */
		}
		if (oldattr)
			free((void*)oldattr);
	} else {
		res = -1;	/* could not get old security attribute */
		errno = EIO;
	}
	return (res ? -1 : 0);
}

/*
 *	Create a default security descriptor for files whose descriptor
 *	cannot be inherited
 */

int ntfs_sd_add_everyone(ntfs_inode *ni)
{
	SECURITY_DESCRIPTOR_ATTR *sd;
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
	
	sd->revision = 1;
	sd->control = SE_DACL_PRESENT | SE_SELF_RELATIVE;
	
	sid = (SID*)((u8*)sd + sizeof(SECURITY_DESCRIPTOR_ATTR));
	sid->revision = 1;
	sid->sub_authority_count = 2;
	sid->sub_authority[0] = cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	sid->sub_authority[1] = cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);
	sid->identifier_authority.value[5] = 5;
	sd->owner = cpu_to_le32((u8*)sid - (u8*)sd);
	
	sid = (SID*)((u8*)sid + sizeof(SID) + 4); 
	sid->revision = 1;
	sid->sub_authority_count = 2;
	sid->sub_authority[0] = cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	sid->sub_authority[1] = cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);
	sid->identifier_authority.value[5] = 5;
	sd->group = cpu_to_le32((u8*)sid - (u8*)sd);
	
	acl = (ACL*)((u8*)sid + sizeof(SID) + 4);
	acl->revision = 2;
	acl->size = cpu_to_le16(sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE));
	acl->ace_count = cpu_to_le16(1);
	sd->dacl = cpu_to_le32((u8*)acl - (u8*)sd);
	
	ace = (ACCESS_ALLOWED_ACE*)((u8*)acl + sizeof(ACL));
	ace->type = ACCESS_ALLOWED_ACE_TYPE;
	ace->flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
	ace->size = cpu_to_le16(sizeof(ACCESS_ALLOWED_ACE));
	ace->mask = cpu_to_le32(0x1f01ff); /* FIXME */
	ace->sid.revision = 1;
	ace->sid.sub_authority_count = 1;
	ace->sid.sub_authority[0] = 0;
	ace->sid.identifier_authority.value[5] = 1;

	ret = ntfs_attr_add(ni, AT_SECURITY_DESCRIPTOR, AT_UNNAMED, 0, (u8*)sd,
			    sd_len);
	if (ret)
		ntfs_log_perror("Failed to add initial SECURITY_DESCRIPTOR\n");
	
	free(sd);
	return ret;
}

/*
 *            Check whether user can access a file in a specific way
 *
 *         Always returns true is user is root or if no user mapping
 *         has been defined
 *         Sets errno if there is a problem or if not allowed
 */

BOOL ntfs_allowed_access(struct SECURITY_CONTEXT *scx,
		const char *path, ntfs_inode *ni,
		int accesstype) /* access type required (1..6) */
{
	mode_t perm;
	int allow;

	/* always allow for root (also root group ?) */
	/* also always allow if no mapping has been defined */
	if (!scx->usermapping || !scx->uid)
		allow = 1;
	else {
		perm = ntfs_get_perm(scx, path, ni);
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
		default:	/* BUG ! */
			allow = 0;
			break;
		}
		if (!allow)
			errno = EPERM;
	}
	return (allow);
}

/*
 *            Check whether user can access the parent directory
 *         of a file in a specific way
 *
 *         Always returns true is user is root or if no user mapping
 *         has been defined
 *         Sets errno if there is a problem or if not allowed
 */

BOOL ntfs_allowed_dir_access(struct SECURITY_CONTEXT *scx,
		const char *path, int accesstype)
{
	BOOL allow;
	char *dirpath;
	char *name;
	ntfs_inode *dir_ni;

	allow = 0;
	dirpath = strdup(path);
	if (dirpath) {
		/* the root of file system is seen as a parent of itself */
		/* is that correct ? */
		name = strrchr(dirpath, '/');
		*++name = 0;
		dir_ni = ntfs_pathname_to_inode(scx->vol, NULL, dirpath);
		if (dir_ni)
			allow = ntfs_allowed_access(scx,path,
				 dir_ni, accesstype);
		free(dirpath);
	}
	return (allow);		/* errno is set if not allowed */
}

int ntfs_set_owner(struct SECURITY_CONTEXT *scx,
		const char *path, ntfs_inode *ni, uid_t uid, gid_t gid)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const struct SECURITY_ENTRY *cached;
	const char *oldattr;
	const char *newattr;
	const SID *usid;
	const SID *gsid;
	uid_t fileuid;
	uid_t filegid;
	mode_t mode;
	int isdir;
	int res;

	res = 0;
	/* get the current owner and mode from cache or security attributes */
	usid = (const SID*)NULL;
	oldattr = (char*)NULL;
	cached = fetch_cache(scx,ni);
	if (cached) {
		fileuid = cached->uid;
		filegid = cached->gid;
		mode = cached->mode;
		usid = find_usid(scx,fileuid);
		gsid = find_usid(scx,filegid);
	} else {
		oldattr = getsecurityattr(scx,path, ni);
		if (oldattr) {
			mode = build_permissions(scx, oldattr, ni);
			if (mode >= 0) {
				phead = (const SECURITY_DESCRIPTOR_RELATIVE*)oldattr;
				usid = (SID*)&oldattr[le32_to_cpu(phead->owner)];
				gsid = (SID*)&oldattr[le32_to_cpu(phead->group)];
				fileuid = findowner(scx,usid);
				filegid = findowner(scx,gsid);
			}
		 /* do not free oldattr until usid and gsid are not needed */
		}
	}
	if (usid) {
		isdir = (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) != 0;
		/* check requested by owner or root */
		/* for chgrp, group must match owner's */
		if (!scx->uid
		   || ((fileuid == scx->uid)
			&& (((int)gid < 0)
			   || (filegid == scx->gid)))) {
			/* replace by the new usid and gsid */
			/* or reuse old gid and sid for cacheing */
			if ((int)uid >= 0)
				usid = find_usid(scx,uid);
			else
				uid = fileuid;
			if ((int)gid >= 0)
				gsid = find_gsid(scx,gid);
			else
				gid = filegid;
			if (usid && gsid) {
				newattr = build_secur_descr(path, mode,
						 isdir, usid, gsid);
				if (newattr) {
					res =
					    update_secur_descr(scx->vol,
						 	newattr, ni);
					if (!res) {
						enter_cache(scx, ni,
						 uid, gid, mode);
					}
					free((void*)newattr);
				} else {
					errno = EIO;
					res = -1;	/* could not build new security attribute */
				}
			} else {
				res = -1;	/* user mapping not defined */
				errno = EOPNOTSUPP;
			}
		} else {
			res = -1;	/* neither owner nor root */
			errno = EPERM;
		}
		if (oldattr)
			free((void*)oldattr);
	} else {
		res = -1;	/* could not get old security attribute */
		errno = EIO;
	}
	return (res ? -1 : 0);
}


int ntfs_set_owner_mode(struct SECURITY_CONTEXT *scx,
	const char *path, ntfs_inode * ni,
	 uid_t uid, gid_t gid, mode_t mode)
{
	const char *newattr;
	const SID *usid;
	const SID *gsid;
	int isdir;
	int res;

	res = 0;
	isdir = (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) != 0;
	usid = find_usid(scx,uid);
	gsid = find_gsid(scx,gid);
	if (usid && gsid) {
		newattr = build_secur_descr(path, mode,
				 isdir, usid, gsid);
		if (newattr) {
			res = update_secur_descr(scx->vol, newattr, ni);
			if (!res) {
				enter_cache(scx, ni, uid, gid, mode);
				if (mode & S_IWUSR)
					ni->flags &= ~FILE_ATTR_READONLY;
				else
					ni->flags |= FILE_ATTR_READONLY;
			}
			free((void*)newattr);
		} else {
			errno = EIO;
			res = -1;	/* could not build new security attribute */
		}
	} else {
		res = -1;	/* user mapping not defined */
		errno = EOPNOTSUPP;
	}
	return (res ? -1 : 0);
}

/*
 *              Get a single mapping item from buffer
 *
 *              Always reads a full line, truncating long lines
 *               Refills buffer when exhausted
 *              Returns pointer to item, or NULL when no more
 */

static struct MAPLIST *getmappingitem(struct SECURITY_CONTEXT *scx,
		ntfs_inode *ni,	off_t *poffs, char *buf,
		int *psrc, s64 *psize)
{
	int src;
	int dst;
	char *p;
	char *q;
	int gotend;
	ntfschar nullchar = 0;
	struct MAPLIST *item;

	src = *psrc;
	dst = 0;
			/* allocate and get a full line */
	item = (struct MAPLIST*)malloc(sizeof(struct MAPLIST));
	if (item) {
		do {
			gotend = 0;
			while ((src < *psize)
			       && (buf[src] != '\n')) {
				if (dst < LINESZ)
					item->maptext[dst] = buf[src];
				dst++;
				src++;
			}
			if (buf[src] != '\n') {
				*poffs += *psize;
				*psize = ntfs_local_read(scx->vol,ni,
					MAPPINGFILE, &nullchar, 0,
					buf, (size_t)BUFSZ, *poffs);
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
 *            Read user mapping file and split into their attribute
 *            parameters are kept as text in a chained list until logins
 *            are converted to uid.
 *            Returns the head of list, if any
 *
 *        Basic IO routines are called since we are still mounting
 *        and we have not entered the fuse loop yet.
 */

static struct MAPLIST *readmapping(struct SECURITY_CONTEXT *scx)
{
	char buf[BUFSZ];
	struct MAPLIST *item;
	struct MAPLIST *firstitem;
	struct MAPLIST *lastitem;
	ntfs_inode *ni;
	int src;
	ntfschar nullchar = 0;
	off_t offs;
	s64 size;

	firstitem = (struct MAPLIST*)NULL;
	lastitem = (struct MAPLIST*)NULL;
	offs = 0;
	ni = ntfs_pathname_to_inode(scx->vol, NULL, MAPPINGFILE);
	if (ni) {
		size = ntfs_local_read(scx->vol,ni,MAPPINGFILE,
					&nullchar, 0,
					buf, (size_t)BUFSZ, offs);
		if (size > 0) {
			src = 0;
			do {
				item = getmappingitem(scx,ni,&offs,
					buf,&src,&size);
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
		ntfs_inode_close(ni);
	}
	return (firstitem);
}

/*
 *           Build the user mapping list
 *           decimal uid are currently expected
 */

static struct MAPPING *ntfs_do_user_mapping(struct MAPLIST *firstitem)
{
	struct MAPLIST *item;
	struct MAPPING *firstmapping;
	struct MAPPING *lastmapping;
	struct MAPPING *mapping;
	SID *sid;

	firstmapping = (struct MAPPING*)NULL;
	lastmapping = (struct MAPPING*)NULL;
	for (item = firstitem; item; item = item->next) {
		if (item->uidstr[0]) {
			sid = encodesid(item->sidstr);
			if (sid) {
				mapping =
				    (struct MAPPING*)
				    malloc(sizeof(struct MAPPING));
				if (mapping) {
					mapping->sid = sid;
					mapping->xid = atoi(item->uidstr);
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
 *           Build the group mapping list
 *           decimal gid are currently expected
 *	gid not associated to a uid are processed first in order
 *	to favour real groups
 */

static struct MAPPING *ntfs_do_group_mapping(struct MAPLIST *firstitem)
{
	struct MAPLIST *item;
	struct MAPPING *firstmapping;
	struct MAPPING *lastmapping;
	struct MAPPING *mapping;
	BOOL uidpresent;
	BOOL ok;
	int step;
	SID *sid;

	firstmapping = (struct MAPPING*)NULL;
	lastmapping = (struct MAPPING*)NULL;
	for (step=1; step<=2; step++) {
		for (item = firstitem; item; item = item->next) {
			uidpresent = (item->uidstr[0] >= '1')
                          && (item->uidstr[0] <= '9');
			ok = (step == 1 ? !uidpresent : uidpresent);
			if (item->gidstr[0] && ok) {
				sid = encodesid(item->sidstr);
				if (sid) {
					mapping = (struct MAPPING*)
					    malloc(sizeof(struct MAPPING));
					if (mapping) {
						mapping->sid = sid;
						mapping->xid = atoi(item->gidstr);
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
 *	Apply default mapping
 *	returns zero if successful
 */

int ntfs_do_default_mapping(struct SECURITY_CONTEXT *scx, const SID *usid)
{
	struct MAPPING *usermapping;
	struct MAPPING *groupmapping;
	SID *sid;
	int sidsz;
	int res;

	res = -1;
	sidsz = sid_size(usid);
	sid = (SID*)malloc(sidsz);
	if (sid) {
		memcpy(sid,usid,sidsz);
		usermapping = (struct MAPPING*)malloc(sizeof(struct MAPPING));
		if (usermapping) {
			groupmapping = (struct MAPPING*)malloc(sizeof(struct MAPPING));
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
 *	Try and apply default mapping
 *	returns zero if successful
 */

int ntfs_default_mapping(struct SECURITY_CONTEXT *scx)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	ntfs_inode *ni;
	char *securattr;
	const SID *usid;
	int res;

	res = -1;
	ni = ntfs_pathname_to_inode(scx->vol, NULL, "/.");
	if (ni) {
		securattr = getsecurityattr(scx,"/.",ni);
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
 *	Build the user mapping
 *	- according to $Mapping file if present,
 *	- or try default mapping if possible
 *
 *          The mapping is specific to a mounted device
 *       No locking done, mounting assumed non multithreaded
 *
 *	returns zero if mapping is successful
 *	(failure should not be interpreted as an error)
 */

int ntfs_build_mapping(struct SECURITY_CONTEXT *scx)
{
	struct MAPLIST *item;
	struct MAPLIST *firstitem;
	struct MAPPING *usermapping;
	struct MAPPING *groupmapping;

	/* be sure not to map anything until done */
	scx->usermapping = (struct MAPPING*)NULL;
	scx->groupmapping = (struct MAPPING*)NULL;
	firstitem = readmapping(scx);
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
	return (!scx->usermapping);
}


