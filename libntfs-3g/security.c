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

/*
 *	JPA configuration modes for this module
 *	should be moved to some config file
 */

#define FORCE_FORMAT_v1x 0	/* Insert security data as in NTFS v1.x */
#define BUFSZ 1024		/* buffer size to read mapping file */
#define MAPPINGFILE "/NTFS-3G/UserMapping" /* name of mapping file */
#define LINESZ 120              /* maximum useful size of a mapping line */
#define CACHE_SECURID_SIZE 8    /* securid cache size >= 3 and not too big */
#define CACHE_PERMISSIONS_SIZE 4000  /* think twice before increasing */

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
 *		Matching of ntfs permissions to Linux permissions
 *	these constants are adapted to endianness
 *	when setting, set them all
 *	when checking, check one is present
 *		(checks needed)
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

/*
 *	JPA The following must be in some library...
 *	but did not found out where
 */

#define endian_rev16(x) (((x >> 8) & 255) | ((x & 255) << 8))
#define endian_rev32(x) (((x >> 24) & 255) | ((x >> 8) & 0xff00) \
		| ((x & 0xff00) << 8) | ((x & 255) << 24))

#define cpu_to_be16(x) endian_rev16(cpu_to_le16(x))
#define cpu_to_be32(x) endian_rev32(cpu_to_le32(x))


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
 *	A few useful constants
 */

static ntfschar sii_stream[] = { '$', 'S', 'I', 'I', 0 };
static ntfschar sdh_stream[] = { '$', 'S', 'D', 'H', 0 };
static const char mapping_name[] = MAPPINGFILE;

/*
 * The zero GUID.
 */
static const GUID __zero_guid = { const_cpu_to_le32(0), const_cpu_to_le16(0),
		const_cpu_to_le16(0), { 0, 0, 0, 0, 0, 0, 0, 0 } };
const GUID *const zero_guid = &__zero_guid;

/*
 *		SID for world user
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

        while (pos < end)
                hash = le32_to_cpup(pos++) + ntfs_rol32(hash, 3);
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
		 */
	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)attr;
		/* find end of DACL */
	offdacl = le32_to_cpu(phead->dacl);
	pdacl = (const ACL*)&attr[offdacl];
	attrsz = offdacl + le16_to_cpu(pdacl->size);

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

		/* size check occurs before the above pointers are used */

	if ((attrsz >= sizeof(SECURITY_DESCRIPTOR_RELATIVE))
		&& (attr_size(securattr) <= attrsz)
      		&& (phead->control & SE_DACL_PRESENT)
		&& valid_sid((const SID*)&securattr[le32_to_cpu(phead->owner)])
		&& valid_sid((const SID*)&securattr[le32_to_cpu(phead->group)])
		&& (pacl->revision == ACL_REVISION)) {

		/*
		 * For each ACE, check it is within limits
		 * and contains a valid SID
		 */

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
	} else
		ok = FALSE;
	return (ok);
}

/*
 *		Build an internal representation of a SID
 *	Returns a copy in allocated memory if it succeeds
 *	Currently it does only safety checks on input
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
		if (cnt > 0) {
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
 *	Enter a new security descriptor into $Secure (data only)
 *      it has to be written twice with an offset of 256KB
 *
 *	Should only be called by entersecurityattr() to ensure consistency
 *
 *	Returns zero if sucessful
 */

static int entersecurity_data(ntfs_volume *vol,
			const SECURITY_DESCRIPTOR_RELATIVE *attr, s64 attrsz,
			le32 hash, le32 keyid, off_t offs)
{
	int res;
	int written1;
	int written2;
	char *fullattr;
	int fullsz;
	SECURITY_DESCRIPTOR_HEADER *phsds;

	res = -1;
	fullsz = attrsz + sizeof(SECURITY_DESCRIPTOR_HEADER);
	fullattr = ntfs_malloc(fullsz);
	if (fullattr) {
		memcpy(&fullattr[sizeof(SECURITY_DESCRIPTOR_HEADER)],
				attr,attrsz);
		phsds = (SECURITY_DESCRIPTOR_HEADER*)fullattr;
		phsds->hash = hash;
		phsds->security_id = keyid;
		phsds->offset = cpu_to_le64(offs);
		phsds->length = cpu_to_le32(fullsz);
		written1 = ntfs_local_write(vol->secure_ni,
			STREAM_SDS, 4, fullattr, fullsz,
			offs);
		written2 = ntfs_local_write(vol->secure_ni,
			STREAM_SDS, 4, fullattr, fullsz,
			offs + ALIGN_SDS_BLOCK);
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
                           /* special filler value... */
		newsdh.fill3 = cpu_to_le32(0x00490049);
		if (!ntfs_ie_add(xsdh,(INDEX_ENTRY*)&newsdh))
			res = 0;
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
	int size;
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
			if (na->data_size < sizeof(struct SII)) {
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
		offs += ((size - 1) | (ALIGN_SDS_ENTRY - 1)) + 1;
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
		if (entersecurity_data(vol, attr, attrsz, hash, securid, offs)
		    || entersecurity_indexes(vol, attrsz, hash, securid, offs))
			securid = cpu_to_le32(0);
	}
		/* inode now is dirty, synchronize it all */
	ntfs_index_ctx_reinit(vol->secure_xsii);
	ntfs_index_ctx_reinit(vol->secure_xsdh);
	NInoSetDirty(vol->secure_ni);
	ntfs_inode_sync(vol->secure_ni);
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
	ntfs_index_ctx_reinit(xsdh);
		/*
		 * find the nearest key as (hash,0)
		 * (do not search for partial key : in case of collision,
		 * it could return a key which is not the first one which
		 * collides)
		 */
	key.hash = hash;
	key.security_id = cpu_to_le32(0);
	ntfs_index_lookup((char*)&key, sizeof(SDH_INDEX_KEY), xsdh);
	entry = xsdh->entry;
	found = FALSE;
		/* lookup() may return a node with no data, if so get next */
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
			/* no matching key : have to build a new one */
			securid = entersecurityattr(vol,
				attr, attrsz, hash);
		}
	}
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
	if (vol->major_ver < 3) {
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
 *		Find Linux owner mapped to a usid
 *	Returns 0 (root) if not found
 */

static int findowner(struct SECURITY_CONTEXT *scx, const SID * usid)
{
	struct MAPPING *p;

	p = scx->usermapping;
	while (p && !same_sid(usid, p->sid))
		p = p->next;
	return (p ? p->xid : 0);
}

/*
 *		Find Linux group mapped to a gsid
 *	Returns 0 (root) if not found
 */

static int findgroup(struct SECURITY_CONTEXT *scx, const SID * gsid)
{
	struct MAPPING *p;
	int gsidsz;

	gsidsz = sid_size(gsid);
	p = scx->groupmapping;
	while (p && !same_sid(gsid, p->sid))
		p = p->next;
	return (p ? p->xid : 0);
}

/*
 *		Find usid mapped to a Linux user
 *	Returns NULL if not found
 */

static const SID *find_usid(struct SECURITY_CONTEXT *scx, uid_t uid)
{
	struct MAPPING *p;
	const SID *sid;

	if (!uid)
		sid = adminsid;
	else {
		p = scx->usermapping;
		while (p && ((uid_t)p->xid != uid))
			p = p->next;
		sid = (p ? p->sid : (const SID*)NULL);
	}
	return (sid);
}

/*
 *		Find Linux group mapped to a gsid
 *	Returns 0 (root) if not found
 */

static const SID *find_gsid(struct SECURITY_CONTEXT *scx, gid_t gid)
{
	struct MAPPING *p;
	const SID *sid;

	if (!gid)
		sid = adminsid;
	else {
		p = scx->groupmapping;
		while (p && ((gid_t)p->xid != gid))
			p = p->next;
		sid = (p ? p->sid : (const SID*)NULL);
	}
	return (sid);
}

/*
 *	Cacheing is done two-way :
 *	- from uid, gid and perm to securid (CACHED_SECURID)
 *	- from a securid to uid, gid and perm (CACHED_PERMISSIONS)
 *
 *	CACHED_SECURID data is kept in a most-recent-first lists
 *	which should not be too long to be efficient. Its optimal
 *	size is depends on usage and is hard to determine.
 *
 *	CACHED_PERMISSIONS data is kept in an indexed array. Is
 *	is optimal at the expense of storage. Use of a most-recent-first
 *	list would save memory and provide similar performances for
 *	standard usage, but not for file servers with too many file
 *	owners
 *
 *	In both caches, data is never invalidated, however returned
 *	entries may be overwritten at next update, so data has
 *	to be copied elsewhere before another cache update is made.
 *
 *	Though the same data may be found in both list, they
 *	must be kept separately : the interpretation of ACL
 *	in both direction are approximations which could be non
 *	reciprocal for some configuration of the user mapping data
 */

static struct SECURITY_CACHE *create_caches(struct SECURITY_CONTEXT *scx,
			u32 securindex)
{
	struct CACHED_SECURID *cachesecurid;
	struct SECURITY_CACHE *cache;
	int i;

		/* create the securid cache first */
	cachesecurid = (struct CACHED_SECURID*)
		ntfs_malloc(CACHE_SECURID_SIZE*sizeof(struct CACHED_SECURID));
	if (cachesecurid) {
			/* chain the entries, and mark an invalid mode */
		for (i=0; i<(CACHE_SECURID_SIZE - 1); i++) {
			cachesecurid[i].next = &cachesecurid[i+1];
			cachesecurid[i].mode = -1;
		}
			/* special for the last entry */
		cachesecurid[CACHE_SECURID_SIZE - 1].next =
			(struct CACHED_SECURID*)NULL;
		cachesecurid[CACHE_SECURID_SIZE - 1].mode = -1;

			/* create the first permissions cache entry */
		cache = (struct SECURITY_CACHE*)
			ntfs_malloc(sizeof(struct SECURITY_CACHE));
		if (cache) {
			cache->head.first = securindex;
			cache->head.last = securindex;
			cache->head.p_reads = 0;
			cache->head.p_hits = 0;
			cache->head.p_writes = 0;
			cache->head.s_reads = 0;
			cache->head.s_hits = 0;
			cache->head.s_writes = 0;
			cache->head.s_hops = 0;
			*scx->pseccache = cache;
			cache->head.first_securid = cachesecurid;
			cache->head.most_recent_securid = cachesecurid;
			cache->cachetable[0].valid = 0;
		}
	} else
		cache = (struct SECURITY_CACHE*)NULL;
	return (cache);
}

/*
 *		Free memory used by caches
 *	The only purpose is to facilitate the detection of memory leaks
 */

static void free_caches(struct SECURITY_CONTEXT *scx)
{
	if (*scx->pseccache) {
		free((*scx->pseccache)->head.first_securid);
		free(*scx->pseccache);
	}
}

/*
 *		Fetch a securid from cache
 *	returns the cache entry, or NULL if not available
 */

static const struct CACHED_SECURID *fetch_securid(struct SECURITY_CONTEXT *scx,
		uid_t uid, gid_t gid, mode_t mode)
{
	struct SECURITY_CACHE *cache;
	struct CACHED_SECURID *current;
	struct CACHED_SECURID *previous;

	cache = *scx->pseccache;
	if (cache) {
			/*
			 * Search sequentially in LRU list
			 */
		current = cache->head.most_recent_securid;
		previous = (struct CACHED_SECURID*)NULL;
		while (current
			&& ((current->uid != uid)
			  || (current->gid != gid)
			  || (current->mode != mode))) {
			cache->head.s_hops++;
			previous = current;
			current = current->next;
			}
		if (current)
			cache->head.s_hits++;
		if (current && previous) {
			/*
			 * found and not at head of list, unlink from current
			 * position and relink as head of list
			 */
			previous->next = current->next;
			current->next = cache->head.most_recent_securid;
			cache->head.most_recent_securid = current;
		}
	} else  /* cache not ready */
		current = (struct CACHED_SECURID*)NULL;
	cache->head.s_reads++;
	return (current);
}

/*
 *		Enter a securid into cache
 *	returns the cache entry
 */

static const struct CACHED_SECURID *enter_securid(struct SECURITY_CONTEXT *scx,
		uid_t uid, gid_t gid,
		mode_t mode, le32 securid)
{
	struct SECURITY_CACHE *cache;
	struct CACHED_SECURID *current;
	struct CACHED_SECURID *previous;
	struct CACHED_SECURID *before;

	mode &= 0777;
	cache = *scx->pseccache;
	if (cache || (cache = create_caches(scx, le32_to_cpu(securid)))) {

			/*
			 * Search sequentially in LRU list to locate the end,
			 * and find out whether the entry is already in list
			 * As we normally go to the end, no statitics is
			 * kept.
		 	 */
		current = cache->head.most_recent_securid;
		previous = (struct CACHED_SECURID*)NULL;
		before = (struct CACHED_SECURID*)NULL;
		while (current
			&& ((current->uid != uid)
			  || (current->gid != gid)
			  || (current->mode != mode))) {
			before = previous;
			previous = current;
			current = current->next;
			}

		if (!current) {
			/*
			 * Not in list, reuse the last entry,
			 * and relink as head of list
			 * Note : we assume at least three entries, so
			 * before, previous and first are always different
			 */
			before->next = (struct CACHED_SECURID*)NULL;
			previous->next = cache->head.most_recent_securid;
			cache->head.most_recent_securid = previous;
			current = previous;
			current->uid = uid;
			current->gid = gid;
			current->mode = mode;
			current->securid = securid;
		}
	} else		/* cache not available */
		current = (struct CACHED_SECURID*)NULL;
	cache->head.s_writes++;
	return (current);
}


/*
 *	Resize permission cache in either direction
 *	do not call unless resizing is needed
 *	
 *	returns pointer to required entry or NULL if not possible
 */

static struct CACHED_PERMISSIONS *resize_cache(
			struct SECURITY_CONTEXT *scx,
			u32 securindex)
{
	struct CACHED_PERMISSIONS *cacheentry;
	struct SECURITY_CACHE *oldcache;
	struct SECURITY_CACHE *newcache;
	int oldcnt;
	int newcnt;
	BOOL beyond;
	unsigned int i;

	cacheentry = (struct CACHED_PERMISSIONS*)NULL;
	oldcache = *scx->pseccache;
	beyond = oldcache->head.last < securindex;
	if (beyond)
		newcnt = securindex - oldcache->head.first + 1;
	else
		newcnt = oldcache->head.last - securindex + 1;
	if (beyond && (newcnt <= CACHE_PERMISSIONS_SIZE)) {
		/* expand cache beyond current end */
#if 1
		newcache = (struct SECURITY_CACHE*)
			realloc(oldcache,
			    sizeof(struct SECURITY_CACHE)
			      + (newcnt - 1)*sizeof(struct CACHED_PERMISSIONS));
#else
		oldcnt = oldcache->head.last - oldcache->head.first + 1;
		newcache = (struct SECURITY_CACHE*)
			ntfs_malloc(
			    sizeof(struct SECURITY_CACHE)
			      + (newcnt - 1)*sizeof(struct CACHED_PERMISSIONS));
		memcpy(newcache,oldcache,
			    sizeof(struct SECURITY_CACHE)
			      + (oldcnt - 1)*sizeof(struct CACHED_PERMISSIONS));
		free(oldcache);
#endif
		if (newcache) {
			     /* mark new entries as not valid */
			for (i=newcache->head.last+1; i<=securindex; i++)
				newcache->cachetable[
					i - newcache->head.first].valid = 0;
			newcache->head.last = securindex;
			*scx->pseccache = newcache;
			cacheentry = &newcache->
				cachetable[securindex - newcache->head.first];
		}
	}
	if (!beyond && (newcnt <= CACHE_PERMISSIONS_SIZE)) {
		/* expand cache before current beginning */
		newcache = (struct SECURITY_CACHE*)
			ntfs_malloc(sizeof(struct SECURITY_CACHE)
			    +  (newcnt - 1)*sizeof(struct CACHED_PERMISSIONS));
		if (newcache) {
			     /* mark new entries as not valid */
			for (i=securindex; i<oldcache->head.first; i++)
				newcache->cachetable[i - securindex].valid = 0;
			newcache->head = oldcache->head;
			newcache->head.first = securindex;
			oldcnt = oldcache->head.last - oldcache->head.first + 1;
			memcpy(&newcache->cachetable[oldcache->head.first
						 - newcache->head.first],
				oldcache->cachetable,
				oldcnt*sizeof(struct CACHED_PERMISSIONS));
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

static struct CACHED_PERMISSIONS *enter_cache(struct SECURITY_CONTEXT *scx,
		ntfs_inode *ni, uid_t uid, gid_t gid, mode_t mode)
{
	struct CACHED_PERMISSIONS *cacheentry;
	struct SECURITY_CACHE *pcache;
	u32 securindex;

	/* cacheing is only possible if a security_id has been defined */
	if (test_nino_flag(ni, v3_Extensions)
	   && (ni->security_id)) {
		/*
		 *  Immediately test the most frequent situation
		 *  where the entry exists
		 */
		securindex = le32_to_cpu(ni->security_id);
		pcache = *scx->pseccache;
		if (pcache
		     && (pcache->head.first <= securindex)
		     && (pcache->head.last >= securindex)) {
			cacheentry = &pcache->cachetable[securindex
					 - pcache->head.first];
			cacheentry->uid = uid;
			cacheentry->gid = gid;
			cacheentry->mode = mode & 0777;
			cacheentry->inh_fileid = cpu_to_le32(0);
			cacheentry->inh_dirid = cpu_to_le32(0);
			cacheentry->valid = 1;
			pcache->head.p_writes++;
		} else {
			if (!pcache) {
				/* create the first cache entry */
				pcache = create_caches(scx, securindex);
				cacheentry = &pcache->cachetable[0];
			} else {
				cacheentry = resize_cache(scx, securindex);
				pcache = *scx->pseccache;
			}
			if (cacheentry) {
				cacheentry->uid = uid;
				cacheentry->gid = gid;
				cacheentry->mode = mode & 0777;
				cacheentry->inh_fileid = cpu_to_le32(0);
				cacheentry->inh_dirid = cpu_to_le32(0);
				cacheentry->valid = 1;
				pcache->head.p_writes++;
			}
		}
	} else
		cacheentry = (struct CACHED_PERMISSIONS*)NULL;
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
	struct SECURITY_CACHE *pcache;
	u32 securindex;

	/* cacheing is only possible if a security_id has been defined */
	cacheentry = (struct CACHED_PERMISSIONS*)NULL;
	if (test_nino_flag(ni, v3_Extensions)
	   && (ni->security_id)) {
		securindex = le32_to_cpu(ni->security_id);
		pcache = *scx->pseccache;
		if (pcache
		     && (pcache->head.first <= securindex)
		     && (pcache->head.last >= securindex)) {
			cacheentry = &pcache->cachetable[securindex
					 - pcache->head.first];
			/* reject if entry is not valid */
			if (!cacheentry->valid)
				cacheentry = (struct CACHED_PERMISSIONS*)NULL;
			else
				pcache->head.p_hits++;
		if (pcache)
			pcache->head.p_reads++;
		}
	}
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
	ntfs_index_ctx_reinit(xsii);
	if (xsii) {
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
					/* error logged by caller */
					free(securattr);
					securattr = (char*)NULL;
				}
			}
		}
	}
	if (!securattr)
		errno = EIO;
	return (securattr);
}

/*
 *		Build an ACL composed of several ACE's
 *	(not expected to fail)
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
 *	are redundant (as owner and group are the same), but this has
 *	no impact on administrator rights
 */

static int buildacls(char *secattr, int offs, mode_t mode, int isdir,
	       const SID * usid, const SID * gsid)
{
	ACL *pacl;
	ACCESS_ALLOWED_ACE *pgace;
	ACCESS_ALLOWED_ACE *pdace;
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

	/* a grant ACE for owner */

	pgace = (ACCESS_ALLOWED_ACE*) &secattr[offs + pos];
	pgace->type = ACCESS_ALLOWED_ACE_TYPE;
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
	pgace->size = cpu_to_le16(usidsz + 8);
	pgace->mask = cpu_to_le32(grants);
	memcpy((char*)&pgace->sid, usid, usidsz);
	pos += usidsz + 8;
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
			pdace->size = cpu_to_le16(usidsz + 8);
			pdace->mask = cpu_to_le32(denials);
			memcpy((char*)&pdace->sid, usid, usidsz);
			pos += usidsz + 8;
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
		pgace->size = cpu_to_le16(gsidsz + 8);
		pgace->mask = cpu_to_le32(grants);
		memcpy((char*)&pgace->sid, gsid, gsidsz);
		pos += gsidsz + 8;
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
				pdace->size = cpu_to_le16(gsidsz + 8);
				pdace->mask = cpu_to_le32(denials);
				memcpy((char*)&pdace->sid, gsid, gsidsz);
				pos += gsidsz + 8;
				acecnt++;
			}
		}
	}

	/* an ACE for world users */

	wsidsz = sid_size(worldsid);
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
	pgace->mask = cpu_to_le32(grants);
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
	pgace->mask = cpu_to_le32(grants);
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
	pgace->mask = cpu_to_le32(grants);
	memcpy((char*)&pgace->sid, systemsid, ssidsz);
	pos += ssidsz + 8;
	acecnt++;

	/* fix ACL header */
	pacl->size = cpu_to_le16(pos);
	pacl->ace_count = cpu_to_le16(acecnt);
	return (pos);
}

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
	newattr = (char*)ntfs_malloc(newattrsz);
	if (newattr) {
		/* build the main header part */
		pnhead = (SECURITY_DESCRIPTOR_RELATIVE*) newattr;
		pnhead->revision = SECURITY_DESCRIPTOR_REVISION;
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
	if (test_nino_flag(ni, v3_Extensions) && ni->security_id) {
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

/*
 *		Test whether a SID means "world user"
 */

static int is_world_sid(const SID * usid)
{
             /* check whether S-1-1-0 */
        return ((usid->sub_authority_count == 1)
            && (usid->identifier_authority.high_part ==  cpu_to_be32(0))
            && (usid->identifier_authority.low_part ==  cpu_to_be32(1))
            && (usid->sub_authority[0] == 0));
}

/*
 *		Test whether a SID means "some user"
 *	Currently we only check for S-1-5-21... but we should
 *	probably test for other configurations
 */

static int is_user_sid(const SID * usid)
{
        return ((usid->sub_authority_count == 5)
            && (usid->identifier_authority.high_part ==  cpu_to_be32(0))
            && (usid->identifier_authority.low_part ==  cpu_to_be32(5))
            && (usid->sub_authority[0] ==  cpu_to_le32(21)));
}

/*
 *		Create a mode_t permission set
 *	from owner, group and world grants as represented in ACEs
 */

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
	return (perm);
}

/*
 *		Interpret an ACL and extract meaningful grants
 *		(standard case : different owner, group and administrator)
 */

static int build_std_permissions(const char *securattr, ntfs_inode *ni)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const ACL *pacl;
	const ACCESS_ALLOWED_ACE *pace;
	const SID *usid;	/* owner of file/directory */
	const SID *gsid;	/* group of file/directory */
	int offdacl;
	int offace;
	int acecnt;
	int nace;
	le32 allowown, allowgrp, allowall;
	le32 denyown, denygrp, denyall;

	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)securattr;
	usid = (const SID*)&securattr[le32_to_cpu(phead->owner)];
	gsid = (const SID*)&securattr[le32_to_cpu(phead->group)];
	offdacl = le32_to_cpu(phead->dacl);
	pacl = (const ACL*)&securattr[offdacl];
	allowown = allowgrp = allowall = cpu_to_le32(0);
	denyown = denygrp = denyall = cpu_to_le32(0);
	acecnt = le16_to_cpu(pacl->ace_count);
	offace = offdacl + sizeof(ACL);
	for (nace = 0; nace < acecnt; nace++) {
		pace = (const ACCESS_ALLOWED_ACE*)&securattr[offace];
		if (same_sid(usid, &pace->sid)) {
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
				}
			offace += le16_to_cpu(pace->size);
		}
		/*
		 *  Add to owner rights granted to group or world
		 * unless denied personaly, and add to group rights
		 * granted to world unless denied specifically
		 */
	allowown |= (allowgrp | allowall);
	allowgrp |= allowall;
	return (merge_permissions(ni,
				allowown & ~denyown,
				allowgrp & ~denygrp,
				allowall & ~denyall));
}

/*
 *		Interpret an ACL and extract meaningful grants
 *		(special case : owner and group are the same,
 *		and not administrator)
 */

static int build_owngrp_permissions(const char *securattr, ntfs_inode *ni)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const ACL *pacl;
	const ACCESS_ALLOWED_ACE *pace;
	const SID *usid;	/* owner and group of file/directory */
	int offdacl;
	int offace;
	int acecnt;
	int nace;
	le32 allowown, allowgrp, allowall;
	le32 denyown, denygrp, denyall;

	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)securattr;
	usid = (const SID*)&securattr[le32_to_cpu(phead->owner)];
	offdacl = le32_to_cpu(phead->dacl);
	pacl = (const ACL*)&securattr[offdacl];
	allowown = allowgrp = allowall = cpu_to_le32(0);
	denyown = denygrp = denyall = cpu_to_le32(0);
	acecnt = le16_to_cpu(pacl->ace_count);
	offace = offdacl + sizeof(ACL);
	for (nace = 0; nace < acecnt; nace++) {
		pace = (const ACCESS_ALLOWED_ACE*)&securattr[offace];
		if (same_sid(usid, &pace->sid)
		   && (pace->mask & FILE_WRITE_ATTRIBUTES)) {
			if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
				allowown |= pace->mask;
			} else
			if (same_sid(usid, &pace->sid)
			   && (!(pace->mask & FILE_WRITE_ATTRIBUTES))) {
				if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
					allowgrp |= pace->mask;
			} else
				if (is_world_sid((const SID*)&pace->sid)) {
					if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
						allowall |= pace->mask;
					else
						if (pace->type == ACCESS_DENIED_ACE_TYPE)
							denyall |= pace->mask;
				}
			offace += le16_to_cpu(pace->size);
		}
	return (merge_permissions(ni,
				allowown & ~denyown,
				allowgrp & ~denygrp,
				allowall & ~denyall));
}

/*
 *		Interpret an ACL and extract meaningful grants
 *		(special case : owner or/and group is administrator)
 */


static int build_ownadmin_permissions(const char *securattr, ntfs_inode *ni)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const ACL *pacl;
	const ACCESS_ALLOWED_ACE *pace;
	const SID *usid;	/* owner of file/directory */
	const SID *gsid;	/* group of file/directory */
	int offdacl;
	int offace;
	int acecnt;
	int nace;
	le32 allowown, allowgrp, allowall;
	le32 denyown, denygrp, denyall;

	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)securattr;
	usid = (const SID*)&securattr[le32_to_cpu(phead->owner)];
	gsid = (const SID*)&securattr[le32_to_cpu(phead->group)];
	offdacl = le32_to_cpu(phead->dacl);
	pacl = (const ACL*)&securattr[offdacl];
	allowown = allowgrp = allowall = cpu_to_le32(0);
	denyown = denygrp = denyall = cpu_to_le32(0);
	acecnt = le16_to_cpu(pacl->ace_count);
	offace = offdacl + sizeof(ACL);
	for (nace = 0; nace < acecnt; nace++) {
		pace = (const ACCESS_ALLOWED_ACE*)&securattr[offace];
		if (same_sid(usid, &pace->sid)
		   && (((pace->mask & FILE_WRITE_ATTRIBUTES) && !nace))) {
			if (pace->type == ACCESS_ALLOWED_ACE_TYPE)
				allowown |= pace->mask;
			else
				if (pace->type == ACCESS_DENIED_ACE_TYPE)
					denyown |= pace->mask;
			} else
			    if (same_sid(gsid, &pace->sid)
				&& (!(pace->mask & FILE_WRITE_ATTRIBUTES))) {
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
				}
			offace += le16_to_cpu(pace->size);
		}
	return (merge_permissions(ni,
				allowown & ~denyown,
				allowgrp & ~denygrp,
				allowall & ~denyall));
}

/*
 *		Build unix-style (mode_t) permissions from an ACL
 *	returns the requested permissions
 *	or a negative result (with errno set) if there is a problem
 */

static int build_permissions(const char *securattr, ntfs_inode *ni)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const SID *usid;	/* owner of file/directory */
	const SID *gsid;	/* group of file/directory */
	int perm;
	BOOL adminowns;
	BOOL groupowns;

	phead = (const SECURITY_DESCRIPTOR_RELATIVE*)securattr;
	if (phead->control & SE_DACL_PRESENT) {	/* no DACL, reject */
		usid = (const SID*)&securattr[le32_to_cpu(phead->owner)];
		gsid = (const SID*)&securattr[le32_to_cpu(phead->group)];
		adminowns = same_sid(usid,adminsid)
		         || same_sid(gsid,adminsid);
		groupowns = !adminowns && same_sid(gsid,usid);
		if (adminowns)
			perm = build_ownadmin_permissions(securattr, ni);
		else
			if (groupowns)
				perm = build_owngrp_permissions(securattr, ni);
			else
				perm = build_std_permissions(securattr, ni);
	} else {
		perm = -1;
		errno = EIO;
	}
	return (perm);
}

/*
 *		Get permissions to access a file
 *	Takes into account the relation of user to file (owner, group, ...)
 *	Do no use as mode of the file
 *
 *	returns -1 if there is a problem
 */

static int ntfs_get_perm(struct SECURITY_CONTEXT *scx,
		 const char *path, ntfs_inode * ni)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	const struct CACHED_PERMISSIONS *cached;
	char *securattr;
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
			securattr = getsecurityattr(scx->vol, path, ni);
			if (securattr) {
				perm = build_permissions(securattr, ni);
				/*
				 *  Create a security id if there were none
				 * and upgrade option is selected
				 */
				if (!test_nino_flag(ni, v3_Extensions)
				   && (perm >= 0)
				   && (scx->vol->flags
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
					phead =
					    (const SECURITY_DESCRIPTOR_RELATIVE*)
					    	securattr;
					usid = (const SID*)&
					    securattr[le32_to_cpu(phead->owner)];
					gsid = (const SID*)&
					    securattr[le32_to_cpu(phead->group)];
					uid = findowner(scx,usid);
					gid = findgroup(scx,gsid);
					enter_cache(scx, ni, uid,
							gid, perm);
				}
				free(securattr);
			} else
				perm = -1;
				uid = gid = 0;
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
	}
	return (perm);
}

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
			securattr = getsecurityattr(scx->vol, path, ni);
			if (securattr) {
				perm = build_permissions(securattr, ni);
					/*
					 * fetch owner and group for cacheing
					 */
				if (perm >= 0) {
				/*
				 *  Create a security id if there were none
				 * and upgrade option is selected
				 */
					if (!test_nino_flag(ni, v3_Extensions)
					   && (scx->vol->flags
					     & (1 << SECURITY_ADDSECURIDS))) {
						upgrade_secur_desc(scx->vol,
							 path, securattr, ni);
					}
					phead =
					    (const SECURITY_DESCRIPTOR_RELATIVE*)
					    	securattr;
					usid = (const SID*)&
					    securattr[le32_to_cpu(phead->owner)];
					gsid = (const SID*)&
					    securattr[le32_to_cpu(phead->group)];
					stbuf->st_uid = findowner(scx,usid);
					stbuf->st_gid = findgroup(scx,gsid);
					stbuf->st_mode =
					    (stbuf->st_mode & ~0777) + perm;
					enter_cache(scx, ni, stbuf->st_uid,
						stbuf->st_gid, perm);
				}
				free(securattr);
			}
		}
	}
	return (perm);
}

/*
 *		Update ownership and mode of a file, reusing an existing
 *	security descriptor when possible
 *	
 *	Returns zero if successful
 */

int ntfs_set_owner_mode(struct SECURITY_CONTEXT *scx, ntfs_inode *ni,
		uid_t uid, gid_t gid, mode_t mode)
{
	int res;
	const struct CACHED_SECURID *cached;
	char *newattr;
	const SID *usid;
	const SID *gsid;
	BOOL isdir;

	res = 0;

		/* check whether target securid is known in cache */

	if (test_nino_flag(ni, v3_Extensions)) {
		cached = fetch_securid(scx, uid, gid, mode & 0777);
			/* quite simple, if we are lucky */
		if (cached) {
			ni->security_id = cached->securid;
			if (mode & S_IWUSR)
				ni->flags &= ~FILE_ATTR_READONLY;
			else
				ni->flags |= FILE_ATTR_READONLY;
			NInoSetDirty(ni);
		}
	} else cached = (struct CACHED_SECURID*)NULL;

	if (!cached) {
		isdir = (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) != 0;
			/*
			 * Do not use usid and gsid from former attributes,
			 * but recompute them to get repeatable results
			 * which can be kept in cache.
			 */
		usid = find_usid(scx,uid);
		gsid = find_gsid(scx,gid);
		if (usid && gsid) {
			newattr = build_secur_descr(mode,
					 isdir, usid, gsid);
			if (newattr) {
				res = update_secur_descr(scx->vol, newattr, ni);
				if (!res) {
					/* update cache, for subsequent use */
					if (test_nino_flag(ni, v3_Extensions))
						enter_securid(scx, uid,
							gid, mode,
							ni->security_id);
				}
				free(newattr);
			} else {
				/* could not build new security attribute */
				errno = EIO;
				res = -1;
			}
		} else {
			/* could not map uid or gid */
			errno = EIO;
			res = -1;
		}
	}
	return (res);
}


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
	uid_t uid;
	uid_t fileuid;
	uid_t filegid;
	int res;

	/* get the current owner, either from cache or from old attribute  */
	res = 0;
	usid = (const SID*)NULL;
	cached = fetch_cache(scx, ni);
	if (cached) {
		fileuid = cached->uid;
		filegid = cached->gid;
	} else {
		oldattr = getsecurityattr(scx->vol,path, ni);
		if (oldattr) {
			phead = (const SECURITY_DESCRIPTOR_RELATIVE*)oldattr;
			usid = (const SID*)&oldattr[le32_to_cpu(phead->owner)];
			gsid = (const SID*)&oldattr[le32_to_cpu(phead->group)];
			fileuid = findowner(scx,usid);
			filegid = findowner(scx,gsid);
			free(oldattr);
		} else
			res = -1;
	}

	if (!res) {
		uid = scx->uid;
		if (!uid || (fileuid == uid)) {
			ntfs_set_owner_mode(scx, ni,
					fileuid, filegid, mode);
		} else {
			errno = EPERM;
			res = -1;	/* neither owner nor root */
		}
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
 *	Always returns true is user is root or if no user mapping
 *	has been defined
 *	Sets errno if there is a problem or if access is not allowed
 */

BOOL ntfs_allowed_access(struct SECURITY_CONTEXT *scx,
		const char *path, ntfs_inode *ni,
		int accesstype) /* access type required (S_Ixxx values) */
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
 *		Check whether user can access the parent directory
 *	of a file in a specific way
 *
 *	Always returns true is user is root or if no user mapping
 *	has been defined
 *	Sets errno if there is a problem or if not allowed
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
		if (dir_ni) {
			allow = ntfs_allowed_access(scx,path,
				 dir_ni, accesstype);
			ntfs_inode_close(dir_ni);
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

	res = 0;
	/* get the current owner and mode from cache or security attributes */
	oldattr = (char*)NULL;
	cached = fetch_cache(scx,ni);
	if (cached) {
		fileuid = cached->uid;
		filegid = cached->gid;
		mode = cached->mode;
	} else {
		fileuid = 0;
		filegid = 0;
		mode = 0;
		oldattr = getsecurityattr(scx->vol, path, ni);
		if (oldattr) {
			mode = perm = build_permissions(oldattr, ni);
			if (perm >= 0) {
				phead = (const SECURITY_DESCRIPTOR_RELATIVE*)
					oldattr;
				usid = (const SID*)
					&oldattr[le32_to_cpu(phead->owner)];
				gsid = (const SID*)
					&oldattr[le32_to_cpu(phead->group)];
				fileuid = findowner(scx,usid);
				filegid = findowner(scx,gsid);
			} else
				res = -1;
			free(oldattr);
		} else
			res = -1;
	}
	if (!res) {
		/* check requested by owner or root */
		/* for chgrp, group must match owner's */
		if (!scx->uid
		   || ((fileuid == scx->uid)
			&& (((int)gid < 0)
			   || (filegid == scx->gid)))) {
			/* replace by the new usid and gsid */
			/* or reuse old gid and sid for cacheing */
			if ((int)uid < 0)
				uid = fileuid;
			if ((int)gid < 0)
				gid = filegid;
			ntfs_set_owner_mode(scx, ni, uid, gid, mode);
		} else {
			res = -1;	/* neither owner nor root */
			errno = EPERM;
		}
	} else {
		res = -1;	/* could not get old security attribute */
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

static int inherit_acl(const ACL *oldacl, ACL *newacl, BOOL fordir)
{
	int src;
	int dst;
	int oldcnt;
	int newcnt;
	unsigned int selection;
	int nace;
	int acesz;
	const ACCESS_ALLOWED_ACE *poldace;
	ACCESS_ALLOWED_ACE *pnewace;

	/* ACL header */

	newacl->revision = ACL_REVISION;
	newacl->alignment1 = 0;
	newacl->alignment2 = cpu_to_le16(0);
	src = dst = sizeof(ACL);

	selection = (fordir ? CONTAINER_INHERIT_ACE : OBJECT_INHERIT_ACE);
	newcnt = 0;
	oldcnt = le16_to_cpu(oldacl->ace_count);
	for (nace = 0; nace < oldcnt; nace++) {
		poldace = (const ACCESS_ALLOWED_ACE*)((char*)oldacl + src);
		acesz = le16_to_cpu(poldace->size);
		if (poldace->flags & selection) {
			pnewace = (ACCESS_ALLOWED_ACE*)
					((char*)newacl + dst);
			memcpy(pnewace,poldace,acesz);
				/* remove inheritance flags if not a directory */
			if (!fordir)
				pnewace->flags &= ~(OBJECT_INHERIT_ACE
						| CONTAINER_INHERIT_ACE);
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
 *		Build a security id for descriptor inherited from
 *	parent directory
 */

static le32 build_inherited_id(struct SECURITY_CONTEXT *scx,
			const char *parentattr,
			ntfs_inode *dir_ni, BOOL fordir)
{
	const SECURITY_DESCRIPTOR_RELATIVE *pphead;
	const ACL *ppacl;
	const SID *usid;
	const SID *gsid;
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
	if (scx->usermapping) {
		usid = find_usid(scx, scx->uid);
		gsid = find_gsid(scx, scx->gid);
	} else
		usid = gsid = (const SID*)NULL;
		/*
		 * new attribute is smaller than parent's
		 * except for differences in SIDs
		 */
	newattrsz = parentattrsz;
	if (usid) newattrsz += sid_size(usid);
	if (gsid) newattrsz += sid_size(gsid);
	newattr = (char*)malloc(parentattrsz);
	if (newattr) {
		pphead = (const SECURITY_DESCRIPTOR_RELATIVE*)parentattr;
		pnhead = (SECURITY_DESCRIPTOR_RELATIVE*)newattr;
		pnhead->revision = SECURITY_DESCRIPTOR_REVISION;
		pnhead->alignment = 0;
		pnhead->control = SE_SELF_RELATIVE;
		pos = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
			/*
			 * locate and inherit DACL
			 */
		pnhead->dacl = cpu_to_le32(0);
		if (pphead->control & SE_DACL_PRESENT) {
			offpacl = le32_to_cpu(pphead->dacl);
			ppacl = (const ACL*)&parentattr[offpacl];
			pnacl = (ACL*)&newattr[pos];
			aclsz = inherit_acl(ppacl, pnacl, fordir);
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
		if (pphead->control & SE_SACL_PRESENT) {
			offpacl = le32_to_cpu(pphead->sacl);
			ppacl = (const ACL*)&parentattr[offpacl];
			pnacl = (ACL*)&newattr[pos];
			aclsz = inherit_acl(ppacl, pnacl, fordir);
			if (aclsz) {
				pnhead->sacl = cpu_to_le32(pos);
				pos += aclsz;
				pnhead->control |= SE_SACL_PRESENT;
			}
		}
			/*
			 * inherit or redefine owner
			 */
		if (!usid) {
			offowner = le32_to_cpu(pphead->owner);
			usid = (const SID*)&parentattr[offowner];
		}
		usidsz = sid_size(usid);
		memcpy(&newattr[pos],usid,usidsz);
		pnhead->owner = cpu_to_le32(pos);
		pos += usidsz;
			/*
			 * inherit or redefine group
			 */
		if (!gsid) {
			offgroup = le32_to_cpu(pphead->group);
			gsid = (const SID*)&parentattr[offgroup];
		}
		gsidsz = sid_size(gsid);
		memcpy(&newattr[pos],gsid,gsidsz);
		pnhead->group = cpu_to_le32(pos);
		pos += usidsz;
		securid = setsecurityattr(scx->vol,
			(SECURITY_DESCRIPTOR_RELATIVE*)newattr, pos);
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
						parentattr,
						dir_ni, fordir);
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
		ntfs_inode *ni,	off_t *poffs, char *buf,
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
					item->maptext[dst] = buf[src];
				dst++;
				src++;
			}
			if (buf[src] != '\n') {
				*poffs += *psize;
				*psize = ntfs_local_read(ni,
					AT_UNNAMED, 0,
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
 *		Read user mapping file and split into their attribute.
 *	Parameters are kept as text in a chained list until logins
 *	are converted to uid.
 *	Returns the head of list, if any
 *
 *	Basic IO routines are called since we are still mounting
 *	and we have not entered the fuse loop yet.
 */

static struct MAPLIST *readmapping(struct SECURITY_CONTEXT *scx)
{
	char buf[BUFSZ];
	struct MAPLIST *item;
	struct MAPLIST *firstitem;
	struct MAPLIST *lastitem;
	ntfs_inode *ni;
	int src;
	off_t offs;
	s64 size;

	firstitem = (struct MAPLIST*)NULL;
	lastitem = (struct MAPLIST*)NULL;
	offs = 0;
	ni = ntfs_pathname_to_inode(scx->vol, NULL, mapping_name);
	if (ni) {
		size = ntfs_local_read(ni, AT_UNNAMED, 0,
					buf, (size_t)BUFSZ, offs);
		if (size > 0) {
			src = 0;
			do {
				item = getmappingitem(ni,&offs,
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
 *	decimal uid are currently expected, however the input mapping
 *	data have been kept in memory to facilitate the conversion of
 *	logins while reading a file (such as /etc/passwd)
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
				    ntfs_malloc(sizeof(struct MAPPING));
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
 *		Build the group mapping list
 *	Decimal gid are currently expected, however the input mapping
 *	data have been kept in memory to facilitate the conversion of
 *	logins while reading a file (such as /etc/group)
 *
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
					    ntfs_malloc(sizeof(struct MAPPING));
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
 *	- according to $Mapping file if present,
 *	- or try default single user mapping if possible
 *
 *	The mapping is specific to a mounted device
 *	No locking done, mounting assumed non multithreaded
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

/*
 *	Open $Secure once for all
 *	returns zero if succeeds
 */


int ntfs_open_secure(ntfs_volume *vol)
{
	ntfs_inode *ni;
	int res;

	res = -1;
	vol->secure_ni = (ntfs_inode*)NULL;
	ni = ntfs_pathname_to_inode(vol, NULL, "$Secure");
	if (ni) {
		vol->secure_xsii = ntfs_index_ctx_get(ni, sii_stream, 4);
		vol->secure_xsdh = ntfs_index_ctx_get(ni, sdh_stream, 4);
		if (ni && vol->secure_xsii && vol->secure_xsdh) {
			vol->secure_ni = ni;
			res = 0;
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
	size = 0;

		/* locate DACL if requested and available */
	if (le16_to_cpu(phead->control)
			 & (selection & DACL_SECURITY_INFORMATION)) {
		offdacl = le32_to_cpu(phead->dacl);
		pdacl = (const ACL*)&attr[offdacl];
		daclsz = le16_to_cpu(pdacl->size);
		size = offdacl + daclsz;
		avail |= DACL_SECURITY_INFORMATION;
	} else
		offdacl = daclsz = 0;

		/* locate owner if requested and available */
	offowner = le32_to_cpu(phead->owner);
	if (offowner && (selection & OWNER_SECURITY_INFORMATION)) {
			/* find end of USID */
		pusid = (const SID*)&attr[offowner];
		usidsz = sid_size(pusid);
		if ((offowner + usidsz) > size)
			size = offowner + usidsz;
		avail |= OWNER_SECURITY_INFORMATION;
	} else
		offowner = usidsz = 0;

		/* locate group if requested and available */
	offgroup = le32_to_cpu(phead->group);
	if (offgroup && (selection & GROUP_SECURITY_INFORMATION)) {
			/* find end of GSID */
		pgsid = (const SID*)&attr[offgroup];
		gsidsz = sid_size(pgsid);
		if ((offgroup + gsidsz) > size)
			size = offgroup + gsidsz;
		avail |= GROUP_SECURITY_INFORMATION;
	} else
		offgroup = gsidsz = 0;

		/* locate SACL if requested and available */
	if (le16_to_cpu(phead->control)
		 & (selection & SACL_SECURITY_INFORMATION)) {
			/* find end of SACL */
		offsacl = le32_to_cpu(phead->sacl);
		psacl = (const ACL*)&attr[offsacl];
		saclsz = le16_to_cpu(psacl->size);
		if ((offsacl + saclsz) > size)
			size = offsacl + saclsz;
		avail |= SACL_SECURITY_INFORMATION;
	} else
		offsacl = saclsz = 0;

		/*
		 * Check whether not requesting unavailable information
		 * and having enough size in destination buffer
		 */
	if ((selection & ~avail)
	   || (size > buflen)) {
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
	target = (char*)malloc(oldattrsz + newattrsz);
	if (target) {
		targhead = (SECURITY_DESCRIPTOR_RELATIVE*)target;
		pos = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
		present = le16_to_cpu(oldhead->control);
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
		targhead->control = cpu_to_le16(present | selection);
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
 *	returns NON zero if successful (following Win32 conventions)
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

uid_t getuid(void);
gid_t getgid(void);

BOOL ntfs_get_file_security(struct SECURITY_API *scapi,
		const char *path, u32 selection,
		char *buf, u32 buflen, u32 *psize)
{
	ntfs_inode *ni;
	char *attr;
	BOOL ok;

	ok = FALSE; /* default return */
	if (scapi && (scapi->magic == MAGIC_API)) {
		ni = ntfs_pathname_to_inode(scapi->security.vol, NULL, path);
		if (ni) {
			attr = getsecurityattr(scapi->security.vol, path, ni);
			if (attr) {
				ok = feedsecurityattr(attr,selection,
						buf,buflen,psize);
				free(attr);
			}
			ntfs_inode_close(ni);
		} else
			errno = ENOENT;
		if (!ok) *psize = 0;
	} else
		errno = EINVAL; /* do not clear *psize */
	return (ok);
}


/*
 *		Set the security descriptor of a file or directory
 *	This is intended to be similar to SetFileSecurity() from Win32
 *	in order to facilitate the development of portable tools
 *
 *	returns NON zero if successful (following Win32 conventions)
 *
 *  BOOL WINAPI SetFileSecurity(
 *    __in          LPCTSTR lpFileName,
 *    __in          SECURITY_INFORMATION SecurityInformation,
 *    __in          PSECURITY_DESCRIPTOR pSecurityDescriptor
 *  );
 */

BOOL ntfs_set_file_security(struct SECURITY_API *scapi,
		const char *path, u32 selection, const char *attr)
{
	const SECURITY_DESCRIPTOR_RELATIVE *phead;
	ntfs_inode *ni;
	int attrsz;
	unsigned int provided;
	char *oldattr;
	BOOL ok;

	ok = FALSE; /* default return */
	if (scapi && (scapi->magic == MAGIC_API) && attr) {
		phead = (const SECURITY_DESCRIPTOR_RELATIVE*)attr;
		attrsz = attr_size(attr);
		provided = le16_to_cpu(phead->control);
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
					ok = mergesecurityattr(
						scapi->security.vol,
						oldattr, attr,
						selection, ni);
					free(oldattr);
				}
				ntfs_inode_close(ni);
			}
		}
	}
	return (ok);
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
 *		Initializations before calling ntfs_get_file_security()
 *	ntfs_set_file_security() and ntfs_read_directory()
 *
 *	Only allowed for root
 *
 *	Returns an (obscured) struct SECURITY_API* needed for further calls
 */

struct SECURITY_API *ntfs_initialize_file_security(const char *device,
				int flags)
{
	ntfs_volume *vol;
	struct SECURITY_API *scapi;
	struct SECURITY_CONTEXT *scx;

	scapi = (struct SECURITY_API*)NULL;
	if (!getuid()) {
		vol = ntfs_mount(device, flags);
		if (vol) {
			scapi = (struct SECURITY_API*)
				ntfs_malloc(sizeof(struct SECURITY_API));
			if (scapi) {
				scapi->magic = MAGIC_API;
				scx = &scapi->security;
				scx->vol = vol;
				scx->uid = getuid();
				scx->gid = getgid();
				scx->pseccache = &scapi->seccache;
				scx->vol->secure_flags = 0;
				if (ntfs_build_mapping(scx)
				    || ntfs_open_secure(vol)) {
					free(scapi);
					scapi = (struct SECURITY_API*)NULL;
				}
			} else
				errno = ENOMEM;
		}
	} else
		errno = EPERM;
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

