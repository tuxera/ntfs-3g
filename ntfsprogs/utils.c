/**
 * utils.c - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002-2003 Richard Russon
 * Copyright (c) 2003 Anton Altaparmakov
 * Copyright (c) 2003 Lode Leroy
 *
 * A set of shared functions for ntfs utilities
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <locale.h>
#include <libintl.h>
#include <stdlib.h>
#include <limits.h>

#include "config.h"
#include "utils.h"
#include "types.h"
#include "volume.h"
#include "debug.h"
#include "dir.h"

const char *ntfs_bugs = "Please report bugs to linux-ntfs-dev@lists.sourceforge.net\n";
const char *ntfs_home = "Linux NTFS homepage: http://linux-ntfs.sourceforge.net\n";
const char *ntfs_gpl = "This program is free software, released under the GNU "
	"General Public License\nand you are welcome to redistribute it under "
	"certain conditions.  It comes with\nABSOLUTELY NO WARRANTY; for "
	"details read the GNU General Public License to be\nfound in the file "
	"\"COPYING\" distributed with this program, or online at:\n"
	"http://www.gnu.org/copyleft/gpl.html\n";

#define NTFS_TIME_OFFSET ((s64)(369 * 365 + 89) * 24 * 3600 * 10000000)

/* These utilities require the following functions */
extern int Eprintf (const char *format, ...) __attribute__ ((format (printf, 1, 2)));
extern int Vprintf (const char *format, ...) __attribute__ ((format (printf, 1, 2)));
extern int Qprintf (const char *format, ...) __attribute__ ((format (printf, 1, 2)));

/**
 * utils_set_locale
 */
int utils_set_locale (void)
{
	const char *locale;

	locale = setlocale (LC_ALL, "");
	if (!locale) {
		locale = setlocale (LC_ALL, NULL);
		Eprintf ("Failed to set locale, using default '%s'.\n", locale);
		return 1;
	} else {
		Vprintf ("Using locale '%s'.\n", locale);
		return 0;
	}
}

/**
 * utils_valid_device - Perform some safety checks on the device, before we start
 * @name:   Full pathname of the device/file to work with
 * @force:  Continue regardless of problems
 *
 * Check that the name refers to a device and that is isn't already mounted.
 * These checks can be overridden by using the force option.
 *
 * Return:  1  Success, we can continue
 *	    0  Error, we cannot use this device
 */
int utils_valid_device (const char *name, int force)
{
	unsigned long mnt_flags = 0;
	struct stat st;

#ifdef __CYGWIN32__
	/* FIXME: This doesn't work for Cygwin, so just return success for now... */
	return 1;
#endif
	if (!name) {
		errno = EINVAL;
		return 0;
	}

	if (stat (name, &st) == -1) {
		if (errno == ENOENT) {
			Eprintf ("The device %s doesn't exist\n", name);
		} else {
			Eprintf ("Error getting information about %s: %s\n", name, strerror (errno));
		}
		return 0;
	}

	if (!S_ISBLK (st.st_mode)) {
		Vprintf ("%s is not a block device.\n", name);
		if (!force) {
			Eprintf ("Use the force option to work with files.\n");
			return 0;
		}
		Vprintf ("Forced to continue.\n");
	}

	/* Make sure the file system is not mounted. */
	if (ntfs_check_if_mounted (name, &mnt_flags)) {
		Vprintf ("Failed to determine whether %s is mounted: %s\n", name, strerror (errno));
		if (!force) {
			Eprintf ("Use the force option to ignore this error.\n");
			return 0;
		}
		Vprintf ("Forced to continue.\n");
	} else if (mnt_flags & NTFS_MF_MOUNTED) {
		Vprintf ("The device %s, is mounted.\n", name);
		if (!force) {
			Eprintf ("Use the force option to work a mounted filesystem.\n");
			return 0;
		}
		Vprintf ("Forced to continue.\n");
	}

	return 1;
}

/**
 * utils_mount_volume
 */
ntfs_volume * utils_mount_volume (const char *device, unsigned long flags, BOOL force)
{
	ntfs_volume *vol;

	if (!device) {
		errno = EINVAL;
		return NULL;
	}

	if (!utils_valid_device (device, force))
		return NULL;

	vol = ntfs_mount (device, flags);
	if (!vol) {
		Eprintf ("Couldn't mount device '%s': %s\n", device, strerror (errno));
		return NULL;
	}

	if (vol->flags & VOLUME_IS_DIRTY) {
		Qprintf ("Volume is dirty.\n");
		if (!force) {
			Eprintf ("Run chkdsk and try again, or use the --force option.\n");
			ntfs_umount (vol, FALSE);
			return NULL;
		}
		Qprintf ("Forced to continue.\n");
	}

	return vol;
}

/**
 * utils_parse_size - Convert a string representing a size
 * @value:  String to be parsed
 * @size:   Parsed size
 * @scale:  Whether or not to allow a suffix to scale the value
 *
 * Read a string and convert it to a number.  Strings may be suffixed to scale
 * them.  Any number without a suffix is assumed to be in bytes.
 *
 * Suffix  Description  Multiple
 *  [tT]    Terabytes     10^12
 *  [gG]    Gigabytes     10^9
 *  [mM]    Megabytes     10^6
 *  [kK]    Kilobytes     10^3
 *
 * Notes:
 *     Only the first character of the suffix is read.
 *     The multipliers are decimal thousands, not binary: 1000, not 1024.
 *     If parse_size fails, @size will not be changed
 *
 * Return:  1  Success
 *	    0  Error, the string was malformed
 */
int utils_parse_size (const char *value, s64 *size, BOOL scale)
{
	long long result;
	char *suffix = NULL;

	if (!value || !size) {
		errno = EINVAL;
		return 0;
	}

	Dprintf ("Parsing size '%s'.\n", value);

	result = strtoll (value, &suffix, 10);
	if (result < 0 || errno == ERANGE) {
		Eprintf ("Invalid size '%s'.\n", value);
		return 0;
	}

	if (!suffix) {
		Eprintf ("Internal error, strtoll didn't return a suffix.\n");
		return 0;
	}

	if (scale) {
		switch (suffix[0]) {
			case 't': case 'T': result *= 1000;
			case 'g': case 'G': result *= 1000;
			case 'm': case 'M': result *= 1000;
			case 'k': case 'K': result *= 1000;
			case '-': case 0:
				break;
			default:
				Eprintf ("Invalid size suffix '%s'.  Use T, G, M, or K.\n", suffix);
				return 0;
		}
	} else {
		if ((suffix[0] != '-') && (suffix[0] != 0)) {
			Eprintf ("Invalid number '%.*s'.\n", (suffix - value + 1), value);
			return 0;
		}
	}

	Dprintf ("Parsed size = %lld.\n", result);
	*size = result;
	return 1;
}

/**
 * utils_parse_range - Convert a string representing a range of numbers
 * @string:  The string to be parsed
 * @start:   The beginning of the range will be stored here
 * @finish:  The end of the range will be stored here
 *
 * Read a string of the form n-m.  If the lower end is missing, zero will be
 * substituted.  If the upper end is missing LONG_MAX will be used.  If the
 * string cannot be parsed correctly, @start and @finish will not be changed.
 *
 * Return:  1  Success, a valid string was found
 *	    0  Error, the string was not a valid range
 */
int utils_parse_range (const char *string, s64 *start, s64 *finish, BOOL scale)
{
	s64 a, b;
	char *middle;

	if (!string || !start || !finish) {
		errno = EINVAL;
		return 0;
	}

	middle = strchr (string, '-');
	if (string == middle) {
		Dprintf ("Range has no beginning, defaulting to 0.\n");
		a = 0;
	} else {
		if (!utils_parse_size (string, &a, scale))
			return 0;
	}

	if (middle) {
		if (middle[1] == 0) {
			b = LONG_MAX;		// XXX ULLONG_MAX
			Dprintf ("Range has no end, defaulting to %lld.\n", b);
		} else {
			if (!utils_parse_size (middle+1, &b, scale))
				return 0;
		}
	} else {
		b = a;
	}

	Dprintf ("Range '%s' = %lld - %lld\n", string, a, b);

	*start  = a;
	*finish = b;
	return 1;
}

/**
 * ntfs2utc - Convert an NTFS time to Unix time
 * @time:  An NTFS time in 100ns units since 1601
 *
 * NTFS stores times as the number of 100ns intervals since January 1st 1601 at
 * 00:00 UTC.  This system will not suffer from Y2K problems until ~57000AD.
 *
 * Return:  n  A Unix time (number of seconds since 1970)
 */
time_t ntfs2utc (s64 time)
{
	return (time - (NTFS_TIME_OFFSET)) / 10000000;
}

/**
 * utc2ntfs - Convert Linux time to NTFS time
 * @time:  Linux time to convert to NTFS
 *
 * Convert the Linux time @time to its corresponding NTFS time.
 *
 * Linux stores time in a long at present and measures it as the number of
 * 1-second intervals since 1st January 1970, 00:00:00 UTC.
 *
 * NTFS uses Microsoft's standard time format which is stored in a s64 and is
 * measured as the number of 100 nano-second intervals since 1st January 1601,
 * 00:00:00 UTC.
 *
 * Return:  n  An NTFS time (100ns units since Jan 1601)
 */
s64 utc2ntfs (time_t time)
{
	/* Convert to 100ns intervals and then add the NTFS time offset. */
	return (s64)time * 10000000 + NTFS_TIME_OFFSET;
}

/**
 * find_attribute - Find an attribute of the given type
 * @type:  An attribute type, e.g. AT_FILE_NAME
 * @ctx:   A search context, created using ntfs_get_attr_search_ctx
 *
 * Using the search context to keep track, find the first/next occurrence of a
 * given attribute type.
 *
 * N.B.  This will return a pointer into @mft.  As long as the search context
 *       has been created without an inode, it won't overflow the buffer.
 *
 * Return:  Pointer  Success, an attribute was found
 *	    NULL     Error, no matching attributes were found
 */
ATTR_RECORD * find_attribute (const ATTR_TYPES type, ntfs_attr_search_ctx *ctx)
{
	if (!ctx) {
		errno = EINVAL;
		return NULL;
	}

	if (ntfs_attr_lookup(type, NULL, 0, 0, 0, NULL, 0, ctx) != 0) {
		Dprintf ("find_attribute didn't find an attribute of type: 0x%02x.\n", type);
		return NULL;	/* None / no more of that type */
	}

	Dprintf ("find_attribute found an attribute of type: 0x%02x.\n", type);
	return ctx->attr;
}

/**
 * find_first_attribute - Find the first attribute of a given type
 * @type:  An attribute type, e.g. AT_FILE_NAME
 * @mft:   A buffer containing a raw MFT record
 *
 * Search through a raw MFT record for an attribute of a given type.
 * The return value is a pointer into the MFT record that was supplied.
 *
 * N.B.  This will return a pointer into @mft.  The pointer won't stray outside
 *       the buffer, since we created the search context without an inode.
 *
 * Return:  Pointer  Success, an attribute was found
 *	    NULL     Error, no matching attributes were found
 */
ATTR_RECORD * find_first_attribute (const ATTR_TYPES type, MFT_RECORD *mft)
{
	ntfs_attr_search_ctx *ctx;
	ATTR_RECORD *rec;

	if (!mft) {
		errno = EINVAL;
		return NULL;
	}

	ctx = ntfs_attr_get_search_ctx (NULL, mft);
	if (!ctx) {
		Eprintf ("Couldn't create a search context.\n");
		return NULL;
	}

	rec = find_attribute (type, ctx);
	ntfs_attr_put_search_ctx (ctx);
	if (rec)
		Dprintf ("find_first_attribute: found attr of type 0x%02x.\n", type);
	else
		Dprintf ("find_first_attribute: didn't find attr of type 0x%02x.\n", type);
	return rec;
}

/**
 * utils_inode_get_name
 *
 * using inode
 * get filename
 * add name to list
 * get parent
 * if parent is 5 (/) stop
 * get inode of parent
 */
int utils_inode_get_name (ntfs_inode *inode, char *buffer, int bufsize)
{
	// XXX option: names = posix/win32 or dos
	// flags: path, filename, or both
	const int max_path = 20;

	ntfs_volume *vol;
	ntfs_attr_search_ctx *ctx;
	ATTR_RECORD *rec;
	FILE_NAME_ATTR *attr;
	int name_space;
	MFT_REF parent = FILE_root;
	char *names[max_path + 1];// XXX malloc? and make max bigger?
	int i, len, offset = 0;

	if (!inode || !buffer) {
		errno = EINVAL;
		return 0;
	}

	vol = inode->vol;

	//printf ("sizeof (char*) = %d, sizeof (names) = %d\n", sizeof (char*), sizeof (names));
	memset (names, 0, sizeof (names));

	for (i = 0; i < max_path; i++) {

		ctx = ntfs_attr_get_search_ctx (inode, NULL);
		if (!ctx) {
			Eprintf ("Couldn't create a search context.\n");
			return 0;
		}

		//printf ("i = %d, inode = %p (%lld)\n", i, inode, inode->mft_no);

		name_space = 4;
		while ((rec = find_attribute (AT_FILE_NAME, ctx))) {
			/* We know this will always be resident. */
			attr = (FILE_NAME_ATTR *) ((char *) rec + le16_to_cpu (rec->value_offset));

			if (attr->file_name_type > name_space) { //XXX find the ...
				continue;
			}

			name_space = attr->file_name_type;
			parent     = le64_to_cpu (attr->parent_directory);

			if (names[i]) {
				free (names[i]);
				names[i] = NULL;
			}

			if (ntfs_ucstombs (attr->file_name, attr->file_name_length,
			    &names[i], attr->file_name_length) < 0) {
				char *temp;
				Eprintf ("Couldn't translate filename to current locale.\n");
				temp = malloc (30);
				if (!temp)
					return 0;
				snprintf (temp, 30, "<MFT%lld>", inode->mft_no);
				names[i] = temp;
			}

			//printf ("names[%d] %s\n", i, names[i]);
			//printf ("parent = %lld\n", MREF (parent));
		}

		ntfs_attr_put_search_ctx(ctx);

		if (i > 0)			/* Don't close the original inode */
			ntfs_inode_close (inode);

		if (MREF (parent) == FILE_root) {	/* The root directory, stop. */
			//printf ("inode 5\n");
			break;
		}

		inode = ntfs_inode_open (vol, parent);
		if (!inode) {
			Eprintf ("Couldn't open inode %lld.\n", MREF (parent));
			break;
		}
	}

	if (i >= max_path) {
		/* If we get into an infinite loop, we'll end up here. */
		Eprintf ("The directory structure is too deep (over %d) nested directories.\n", max_path);
		return 0;
	}

	/* Assemble the names in the correct order. */
	for (i = max_path; i >= 0; i--) {
		if (!names[i])
			continue;

		len = snprintf (buffer + offset, bufsize - offset, "%c%s", PATH_SEP, names[i]);
		if (len >= (bufsize - offset)) {
			Eprintf ("Pathname was truncated.\n");
			break;
		}

		offset += len;
	}

	/* Free all the allocated memory */
	for (i = 0; i < max_path; i++)
		free (names[i]);

	Dprintf ("Pathname: %s\n", buffer);

	return 0;
}

/**
 * utils_attr_get_name
 */
int utils_attr_get_name (ntfs_volume *vol, ATTR_RECORD *attr, char *buffer, int bufsize)
{
	int len, namelen;
	char *name;
	ATTR_DEF *attrdef;

	// flags: attr, name, or both
	if (!attr || !buffer) {
		errno = EINVAL;
		return 0;
	}

	attrdef = ntfs_attr_find_in_attrdef (vol, attr->type);
	if (attrdef) {
		name    = NULL;
		namelen = ntfs_ucsnlen (attrdef->name, sizeof (attrdef->name));
		if (ntfs_ucstombs (attrdef->name, namelen, &name, namelen) < 0) {
			Eprintf ("Couldn't translate attribute type to current locale.\n");
			// <UNKNOWN>?
			return 0;
		}
		len = snprintf (buffer, bufsize, "%s", name);
	} else {
		Eprintf ("Unknown attribute type 0x%02x\n", attr->type);
		len = snprintf (buffer, bufsize, "<UNKNOWN>");
	}

	if (len >= bufsize) {
		Eprintf ("Attribute type was truncated.\n");
		return 0;
	}

	if (!attr->name_length) {
		return 0;
	}

	buffer  += len;
	bufsize -= len;

	name    = NULL;
	namelen = attr->name_length;
	if (ntfs_ucstombs ((uchar_t *)((char *)attr + attr->name_offset),
	    namelen, &name, namelen) < 0) {
		Eprintf ("Couldn't translate attribute name to current locale.\n");
		// <UNKNOWN>?
		len = snprintf (buffer, bufsize, "<UNKNOWN>");
		return 0;
	}

	len = snprintf (buffer, bufsize, "(%s)", name);
	free (name);

	if (len >= bufsize) {
		Eprintf ("Attribute name was truncated.\n");
		return 0;
	}

	return 0;
}

/**
 * utils_cluster_in_use - Determine if a cluster is in use
 * @vol:  An ntfs volume obtained from ntfs_mount
 * @lcn:  The Logical Cluster Number to test
 *
 * The metadata file $Bitmap has one binary bit representing each cluster on
 * disk.  The bit will be set for each cluster that is in use.  The function
 * reads the relevant part of $Bitmap into a buffer and tests the bit.
 *
 * This function has a static buffer in which it caches a section of $Bitmap.
 * If the lcn, being tested, lies outside the range, the buffer will be
 * refreshed.
 *
 * Return:  1  Cluster is in use
 *	    0  Cluster is free space
 *	   -1  Error occurred
 */
int utils_cluster_in_use (ntfs_volume *vol, long long lcn)
{
	static unsigned char buffer[512];
	static long long bmplcn = -sizeof (buffer) - 1;	/* Which bit of $Bitmap is in the buffer */

	int byte, bit;
	ntfs_attr *attr;

	if (!vol) {
		errno = EINVAL;
		return -1;
	}

	/* Does lcn lie in the section of $Bitmap we already have cached? */
	if ((lcn < bmplcn) || (lcn >= (bmplcn + (sizeof (buffer) << 3)))) {
		Dprintf ("Bit lies outside cache.\n");
		attr = ntfs_attr_open (vol->lcnbmp_ni, AT_DATA, NULL, 0);
		if (!attr) {
			Eprintf ("Couldn't open $Bitmap: %s\n", strerror (errno));
			return -1;
		}

		/* Mark the buffer as in use, in case the read is shorter. */
		memset (buffer, 0xFF, sizeof (buffer));
		bmplcn = lcn & (~((sizeof (buffer) << 3) - 1));

		if (ntfs_attr_pread (attr, (bmplcn>>3), sizeof (buffer), buffer) < 0) {
			Eprintf ("Couldn't read $Bitmap: %s\n", strerror (errno));
			ntfs_attr_close (attr);
			return -1;
		}

		Dprintf ("Reloaded bitmap buffer.\n");
		ntfs_attr_close (attr);
	}

	bit  = 1 << (lcn & 7);
	byte = (lcn >> 3) & (sizeof (buffer) - 1);
	Dprintf ("cluster = %lld, bmplcn = %lld, byte = %d, bit = %d, in use %d\n",
		lcn, bmplcn, byte, bit, buffer[byte] & bit);

	return (buffer[byte] & bit);
}

/**
 * utils_mftrec_in_use - Determine if a MFT Record is in use
 * @vol:   An ntfs volume obtained from ntfs_mount
 * @mref:  MFT Reference (inode number)
 *
 * The metadata file $BITMAP has one binary bit representing each record in the
 * MFT.  The bit will be set for each record that is in use.  The function
 * reads the relevant part of $BITMAP into a buffer and tests the bit.
 *
 * This function has a static buffer in which it caches a section of $BITMAP.
 * If the mref, being tested, lies outside the range, the buffer will be
 * refreshed.
 *
 * Return:  1  MFT Record is in use
 *	    0  MFT Record is unused
 *	   -1  Error occurred
 */
int utils_mftrec_in_use (ntfs_volume *vol, MFT_REF mref)
{
	static u8 buffer[512];
	static s64 bmpmref = -sizeof (buffer) - 1; /* Which bit of $BITMAP is in the buffer */

	int byte, bit;

	if (!vol) {
		errno = EINVAL;
		return -1;
	}

	/* Does mref lie in the section of $Bitmap we already have cached? */
	if (((s64)MREF(mref) < bmpmref) || ((s64)MREF(mref) >= (bmpmref +
			(sizeof (buffer) << 3)))) {
		Dprintf ("Bit lies outside cache.\n");

		/* Mark the buffer as not in use, in case the read is shorter. */
		memset (buffer, 0, sizeof (buffer));
		bmpmref = mref & (~((sizeof (buffer) << 3) - 1));

		if (ntfs_attr_pread (vol->mftbmp_na, (bmpmref>>3), sizeof (buffer), buffer) < 0) {
			Eprintf ("Couldn't read $MFT/$BITMAP: %s\n", strerror (errno));
			return -1;
		}

		Dprintf ("Reloaded bitmap buffer.\n");
	}

	bit  = 1 << (mref & 7);
	byte = (mref >> 3) & (sizeof (buffer) - 1);
	Dprintf ("cluster = %lld, bmpmref = %lld, byte = %d, bit = %d, in use %d\n",
		mref, bmpmref, byte, bit, buffer[byte] & bit);

	return (buffer[byte] & bit);
}

/**
 * utils_pathname_to_inode - Find the inode which represents the given pathname
 * @vol:       An ntfs volume obtained from ntfs_mount
 * @parent:    A directory inode to begin the search (may be NULL)
 * @pathname:  Pathname to be located
 *
 * Take an ASCII pathname and find the inode that represents it.  The function
 * splits the path and then descends the directory tree.  If @parent is NULL,
 * then the root directory '.' will be used as the base for the search.
 *
 * Return:  inode  Success, the pathname was valid
 *	    NULL   Error, the pathname was invalid, or some other error occurred
 */
ntfs_inode * utils_pathname_to_inode (ntfs_volume *vol, ntfs_inode *parent, const char *pathname)
{
	u64 inum;
	int len;
	char *p, *q;
	ntfs_inode *ni;
	ntfs_inode *result  = NULL;
	uchar_t    *unicode = NULL;
	char       *ascii   = NULL;

	if (!vol || !pathname) {
		errno = EINVAL;
		return NULL;
	}

	if (parent) {
		ni = parent;
	} else {
		ni = ntfs_inode_open (vol, FILE_root);
		if (!ni) {
			Eprintf ("Couldn't open the inode of the root directory.\n");
			goto close;
		}
	}

	unicode = calloc (1, MAX_PATH);
	ascii   = strdup (pathname);		// Work with a r/w copy
	if (!unicode || !ascii) {
		Eprintf ("Out of memory.\n");
		goto close;
	}

	p = ascii;
	while (p && *p && *p == PATH_SEP)	// Remove leading /'s
		p++;
	while (p && *p) {
		q = strchr (p, PATH_SEP);	// Find the end of the first token
		if (q != NULL) {
			*q = '\0';
			q++;
		}

		len = ntfs_mbstoucs (p, &unicode, MAX_PATH);
		if (len < 0) {
			Eprintf ("Couldn't convert name to Unicode: %s.\n", p);
			goto close;
		}

		inum = ntfs_inode_lookup_by_name (ni, unicode, len);
		if (inum == (u64)-1) {
			Eprintf ("Couldn't find name '%s' in pathname '%s'.\n", p, pathname);
			goto close;
		}

		if (ni != parent)
			ntfs_inode_close (ni);

		ni = ntfs_inode_open (vol, inum);
		if (!ni) {
			Eprintf ("Cannot open inode %lld: %s.\n", inum, p);
			goto close;
		}

		p = q;
		while (p && *p && *p == PATH_SEP)
			p++;
	}

	result = ni;
	ni = NULL;
close:
	if (ni && (ni != parent))
		ntfs_inode_close (ni);
	free (ascii);
	free (unicode);
	return result;
}

/**
 * __metadata
 */
static int __metadata (ntfs_volume *vol, u64 num)
{
	if (num <= FILE_UpCase)
		return 1;
	if (!vol)
		return -1;
	if ((vol->major_ver == 3) && (num == FILE_Extend))
		return 1;

	return 0;
}

/**
 * utils_is_metadata - Determine if an inode represents a metadata file
 * @inode:  An ntfs inode to be tested
 *
 * A handful of files in the volume contain filesystem data - metadata.
 * They can be identified by their inode number (offset in MFT/$DATA) or by
 * their parent.
 *
 * Return:  1  inode is a metadata file
 *	    0  inode is not a metadata file
 *	   -1  Error occurred
 */
int utils_is_metadata (ntfs_inode *inode)
{
	ntfs_volume *vol;
	ATTR_RECORD *rec;
	FILE_NAME_ATTR *attr;
	MFT_RECORD *file;
	u64 num;

	if (!inode) {
		errno = EINVAL;
		return -1;
	}

	vol = inode->vol;
	if (!vol)
		return -1;

	num = inode->mft_no;
	if (__metadata (vol, num) == 1)
		return 1;

	file = inode->mrec;
	if (file && (file->base_mft_record != 0)) {
		num = MREF (file->base_mft_record);
		if (__metadata (vol, num) == 1)
			return 1;
	}
	file = inode->mrec;

	rec = find_first_attribute (AT_FILE_NAME, inode->mrec);
	if (!rec)
		return -1;

	/* We know this will always be resident. */
	attr = (FILE_NAME_ATTR *) ((char *) rec + le16_to_cpu (rec->value_offset));

	num = MREF (attr->parent_directory);
	if ((num != FILE_root) && (__metadata (vol, num) == 1))
		return 1;

	return 0;
}


/**
 * mft_get_search_ctx
 */
struct mft_search_ctx * mft_get_search_ctx (ntfs_volume *vol)
{
	struct mft_search_ctx *ctx;

	if (!vol) {
		errno = EINVAL;
		return NULL;
	}

	ctx = calloc (1, sizeof *ctx);

	ctx->mft_num = -1;
	ctx->vol = vol;

	return ctx;
}

/**
 * mft_put_search_ctx
 */
void mft_put_search_ctx (struct mft_search_ctx *ctx)
{
	if (!ctx)
		return;
	if (ctx->inode)
		ntfs_inode_close (ctx->inode);
	free (ctx);
}

/**
 * mft_next_record
 */
int mft_next_record (struct mft_search_ctx *ctx)
{
	ATTR_RECORD *attr10 = NULL;
	ATTR_RECORD *attr20 = NULL;
	ATTR_RECORD *attr80 = NULL;
	ntfs_attr_search_ctx *attr_ctx;

	if (!ctx) {
		errno = EINVAL;
		return -1;
	}

	if (ctx->inode) {
		ntfs_inode_close (ctx->inode);
		ctx->inode = NULL;
	}

	for (ctx->mft_num++; (s64)ctx->mft_num < ctx->vol->nr_mft_records; ctx->mft_num++) {
		ctx->flags_match = 0;
		int in_use = utils_mftrec_in_use (ctx->vol, (MFT_REF) ctx->mft_num);
		if (in_use == -1) {
			Eprintf ("Error reading inode %lld.  Aborting.", ctx->mft_num);
			return -1;
		}

		if (in_use) {
			ctx->flags_match |= FEMR_IN_USE;

			ctx->inode = ntfs_inode_open (ctx->vol, (MFT_REF) ctx->mft_num);
			if (ctx->inode == NULL) {
				Eprintf ("Error reading inode %lld.", ctx->mft_num);
				return -1;
			}

			attr10 = find_first_attribute (AT_STANDARD_INFORMATION, ctx->inode->mrec);
			attr20 = find_first_attribute (AT_ATTRIBUTE_LIST,       ctx->inode->mrec);
			attr80 = find_first_attribute (AT_DATA, ctx->inode->mrec);

			if (attr10)
				ctx->flags_match |= FEMR_BASE_RECORD;
			else
				ctx->flags_match |= FEMR_NOT_BASE_RECORD;

			if (attr20)
				ctx->flags_match |= FEMR_BASE_RECORD;

			if (attr80)
				ctx->flags_match |= FEMR_FILE;

			if (ctx->flags_search & FEMR_DIR) {
				attr_ctx = ntfs_attr_get_search_ctx (NULL, ctx->inode->mrec);
				if (attr_ctx) {
					if (ntfs_attr_lookup (AT_INDEX_ROOT, I30, 4, 0, 0, NULL, 0, attr_ctx) == 0)
						ctx->flags_match |= FEMR_DIR;

					ntfs_attr_put_search_ctx (attr_ctx);
				} else {
					Eprintf ("Couldn't create a search context.\n");
					return -1;
				}
			}

			switch (utils_is_metadata (ctx->inode)) {
				case 1: ctx->flags_match |= FEMR_METADATA;     break;
				case 0: ctx->flags_match |= FEMR_NOT_METADATA; break;
				default:
					ctx->flags_match |= FEMR_NOT_METADATA; break;
					//Eprintf ("Error reading inode %lld.", ctx->mft_num);
					//return -1;
			}

		} else {		// !in_use
			ntfs_attr *mft;

			ctx->flags_match |= FEMR_NOT_IN_USE;

			ctx->inode = calloc (1, sizeof (*ctx->inode));
			if (!ctx->inode) {
				Eprintf ("Out of memory.  Aborting.");
				return -1;
			}

			ctx->inode->mft_no = ctx->mft_num;
			ctx->inode->vol    = ctx->vol;
			ctx->inode->mrec   = malloc (ctx->vol->mft_record_size);
			if (!ctx->inode->mrec) {
				free (ctx->inode); // == ntfs_inode_close
				Eprintf ("Out of memory.  Aborting.");
				return -1;
			}

			mft = ntfs_attr_open (ctx->vol->mft_ni, AT_DATA, NULL, 0);
			if (!mft) {
				Eprintf ("Couldn't open $MFT/$DATA: %s\n", strerror (errno));
				// free / close
				return -1;
			}

			if (ntfs_attr_pread (mft, ctx->vol->mft_record_size * ctx->mft_num, ctx->vol->mft_record_size, ctx->inode->mrec) < ctx->vol->mft_record_size) {
				Eprintf ("Couldn't read MFT Record %lld: %s.\n", ctx->mft_num, strerror (errno));
				// free / close
				return -1;
			}
		}

		if (ctx->flags_match & ctx->flags_search) {
			break;
		}

		if (ntfs_inode_close (ctx->inode)) {
			Eprintf ("Error closing inode %lld.", ctx->mft_num);
			return -errno;
		}

		ctx->inode = NULL;
	}

	return (ctx->inode == NULL);
}


#if 0
hamming weight
inline unsigned int hweight32(unsigned int w)
{
	unsigned int res = (w & 0x55555555) + ((w >> 1) & 0x55555555);
	res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
	res = (res & 0x0F0F0F0F) + ((res >> 4) & 0x0F0F0F0F);
	res = (res & 0x00FF00FF) + ((res >> 8) & 0x00FF00FF);
	return (res & 0x0000FFFF) + ((res >> 16) & 0x0000FFFF);
}

inline unsigned int hweight16(unsigned int w)
{
	unsigned int res = (w & 0x5555) + ((w >> 1) & 0x5555);
	res = (res & 0x3333) + ((res >> 2) & 0x3333);
	res = (res & 0x0F0F) + ((res >> 4) & 0x0F0F);
	return (res & 0x00FF) + ((res >> 8) & 0x00FF);
}

inline unsigned int hweight8(unsigned int w)
{
	unsigned int res = (w & 0x55) + ((w >> 1) & 0x55);
	res = (res & 0x33) + ((res >> 2) & 0x33);
	return (res & 0x0F) + ((res >> 4) & 0x0F);
}

inline int set_bit(int nr,long * addr)
{
	int	mask, retval;

	addr += nr >> 5;
	mask = 1 << (nr & 0x1f);
	retval = (mask & *addr) != 0;
	*addr |= mask;
	return retval;
}

inline int clear_bit(int nr, long * addr)
{
	int	mask, retval;

	addr += nr >> 5;
	mask = 1 << (nr & 0x1f);
	retval = (mask & *addr) != 0;
	*addr &= ~mask;
	return retval;
}

inline int test_bit(int nr, long * addr)
{
	int	mask;

	addr += nr >> 5;
	mask = 1 << (nr & 0x1f);
	return ((mask & *addr) != 0);
}

#endif

