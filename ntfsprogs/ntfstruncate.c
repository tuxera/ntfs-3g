/*
 * ntfstruncate - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002-2003 Anton Altaparmakov
 *
 * This utility will truncate a specified attribute belonging to a
 * specified inode, i.e. file or directory, to a specified length.
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
 * along with this program (in the main directory of the Linux-NTFS source
 * in the file COPYING); if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "config.h"

#ifdef HAVE_UNISTD_H
#	include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#	include <stdlib.h>
#endif
#ifdef HAVE_STDIO_H
#	include <stdio.h>
#endif
#ifdef HAVE_STDARG_H
#	include <stdarg.h>
#endif
#ifdef HAVE_STRING_H
#	include <string.h>
#endif
#ifdef HAVE_ERRNO_H
#	include <errno.h>
#endif
#include <fcntl.h>
#include <time.h>
#ifdef HAVE_GETOPT_H
#	include <getopt.h>
#else
	extern char *optarg;
	extern int optind;
#endif
#include <limits.h>
#ifndef LLONG_MAX
#	define LLONG_MAX 9223372036854775807LL
#endif

#include "types.h"
#include "attrib.h"
#include "inode.h"
#include "layout.h"
#include "volume.h"
#include "utils.h"

extern const unsigned char attrdef_ntfs12_array[2400];

const char *EXEC_NAME = "ntfstruncate";

/* Need these global so ntfstruncate_exit can access them. */
BOOL success = FALSE;

char *dev_name;
s64 inode;
u32 attr_type;
uchar_t *attr_name = NULL;
u32 attr_name_len;
s64 new_len;

ntfs_volume *vol;
ntfs_inode *ni;
ntfs_attr *na = NULL;

struct flock flk;

ATTR_DEF *attr_defs;

struct {
				/* -h, print usage and exit. */
	int no_action;		/* -n, do not write to device, only display
				       what would be done. */
	int quiet;		/* -q, quiet execution. */
	int verbose;		/* -v, verbose execution, given twice, really
				       verbose execution (debug mode). */
	int force;		/* -f, force truncation. */
				/* -V, print version and exit. */
} opts;

GEN_PRINTF (Eprintf, stderr, NULL,          FALSE)
GEN_PRINTF (Vprintf, stdout, &opts.verbose, TRUE)
GEN_PRINTF (Qprintf, stdout, &opts.quiet,   FALSE)

void err_exit(const char *fmt, ...) __attribute__ ((noreturn));

/* Error output and terminate. Ignores quiet (-q). */
void err_exit(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "ERROR: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "Aborting...\n");
	exit(1);
}

/* Debugging output (-vv). Overriden by quiet (-q). */
void Dprintf(const char *fmt, ...)
{
	va_list ap;

	if (!opts.quiet && opts.verbose > 1) {
		printf("DEBUG: ");
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
	}
}

/**
 * ucstos - convert unicode-character string to ASCII
 * @dest:	points to buffer to receive the converted string
 * @src:	points to string to convert
 * @maxlen:	size of @dest buffer in bytes
 *
 * Return the number of characters written to @dest, not including the
 * terminating null byte. If a unicode character was encountered which could
 * not be converted -1 is returned.
 */
int ucstos(char *dest, const uchar_t *src, int maxlen)
{
	uchar_t u;
	int i;

	/* Need one byte for null terminator. */
	maxlen--;
	for (i = 0; i < maxlen; i++) {
		u = le16_to_cpu(src[i]);
		if (!u)
			break;
		if (u & 0xff00)
			return -1;
		dest[i] = u & 0xff;
	}
	dest[i] = 0;
	return i;
}

void dump_resident_attr_val(ATTR_TYPES type, char *val, u32 val_len)
{
	const char *don_t_know = "Don't know what to do with this attribute "
			"type yet.";
	const char *skip = "Skipping display of $%s attribute value.\n";
	const char *todo = "This is still work in progress.";
	char *buf;
	int i, j;

	switch (type) {
	case AT_STANDARD_INFORMATION:
		// TODO
		printf("%s\n", todo);
		return;
	case AT_ATTRIBUTE_LIST:
		// TODO
		printf("%s\n", todo);
		return;
	case AT_FILE_NAME:
		// TODO
		printf("%s\n", todo);
		return;
	case AT_OBJECT_ID:
		// TODO
		printf("%s\n", todo);
		return;
	case AT_SECURITY_DESCRIPTOR:
		// TODO
		printf("%s\n", todo);
		return;
	case AT_VOLUME_NAME:
		printf("Volume name length = %i\n", val_len);
		if (val_len) {
			buf = calloc(1, val_len);
			if (!buf)
				err_exit("Failed to allocate internal buffer: "
						"%s\n", strerror(errno));
			i = ucstos(buf, (uchar_t*)val, val_len);
			if (i == -1)
				printf("Volume name contains non-displayable "
						"Unicode characters.\n");
			printf("Volume name = %s\n", buf);
			free(buf);
		}
		return;
	case AT_VOLUME_INFORMATION:
#define VOL_INF(x) ((VOLUME_INFORMATION *)(x))
		printf("NTFS version %i.%i\n", VOL_INF(val)->major_ver,
				VOL_INF(val)->minor_ver);
		i = VOL_INF(val)->flags;
#undef VOL_INF
		printf("Volume flags = 0x%x: ", i);
		if (!i) {
			printf("NONE\n");
			return;
		}
		j = 0;
		if (i & VOLUME_MODIFIED_BY_CHKDSK) {
			j = 1;
			printf("VOLUME_MODIFIED_BY_CHKDSK");
		}
		if (i & VOLUME_REPAIR_OBJECT_ID) {
			if (j)
				printf(" | ");
			else
				j = 0;
			printf("VOLUME_REPAIR_OBJECT_ID");
		}
		if (i & VOLUME_DELETE_USN_UNDERWAY) {
			if (j)
				printf(" | ");
			else
				j = 0;
			printf("VOLUME_DELETE_USN_UNDERWAY");
		}
		if (i & VOLUME_MOUNTED_ON_NT4) {
			if (j)
				printf(" | ");
			else
				j = 0;
			printf("VOLUME_MOUNTED_ON_NT4");
		}
		if (i & VOLUME_UPGRADE_ON_MOUNT) {
			if (j)
				printf(" | ");
			else
				j = 0;
			printf("VOLUME_UPGRADE_ON_MOUNT");
		}
		if (i & VOLUME_RESIZE_LOG_FILE) {
			if (j)
				printf(" | ");
			else
				j = 0;
			printf("VOLUME_RESIZE_LOG_FILE");
		}
		if (i & VOLUME_IS_DIRTY) {
			if (j)
				printf(" | ");
			else
				j = 0;
			printf("VOLUME_IS_DIRTY");
		}
		printf("\n");
		return;
	case AT_DATA:
		printf(skip, "DATA");
		return;
	case AT_INDEX_ROOT:
		// TODO
		printf("%s\n", todo);
		return;
	case AT_INDEX_ALLOCATION:
		// TODO
		printf("%s\n", todo);
		return;
	case AT_BITMAP:
		printf(skip, "BITMAP");
		return;
	case AT_REPARSE_POINT:
		// TODO
		printf("%s\n", todo);
		return;
	case AT_EA_INFORMATION:
		// TODO
		printf("%s\n", don_t_know);
		return;
	case AT_EA:
		// TODO
		printf("%s\n", don_t_know);
		return;
	case AT_LOGGED_UTILITY_STREAM:
		// TODO
		printf("%s\n", don_t_know);
		return;
	default:
		i = le32_to_cpu(type);
		printf("Cannot display unknown %s defined attribute type 0x%x"
				".\n", i >=
				le32_to_cpu(AT_FIRST_USER_DEFINED_ATTRIBUTE) ?
				"user" : "system", i);
	}
}

void dump_resident_attr(ATTR_RECORD *a)
{
	int i;

	i = le32_to_cpu(a->value_length);
	printf("Attribute value length = %u (0x%x)\n", i, i);
	i = le16_to_cpu(a->value_offset);
	printf("Attribute value offset = %u (0x%x)\n", i, i);
	i = a->resident_flags;
	printf("Resident flags = 0x%x: ", i);
	if (!i)
		printf("NONE\n");
	else if (i & ~RESIDENT_ATTR_IS_INDEXED)
		printf("UNKNOWN FLAG(S)\n");
	else
		printf("RESIDENT_ATTR_IS_INDEXED\n");
	dump_resident_attr_val(a->type, (char*)a + le16_to_cpu(a->value_offset),
			le32_to_cpu(a->value_length));
}

void dump_mapping_pairs_array(char *b, unsigned int max_len)
{
	// TODO
	return;
}

void dump_non_resident_attr(ATTR_RECORD *a)
{
	s64 l;
	int i;

	l = sle64_to_cpu(a->lowest_vcn);
	printf("Lowest VCN = %Li (0x%Lx)\n", l, l);
	l = sle64_to_cpu(a->highest_vcn);
	printf("Highest VCN = %Li (0x%Lx)\n", l, l);
	printf("Mapping pairs array offset = 0x%x\n",
			le16_to_cpu(a->mapping_pairs_offset));
	printf("Compression unit = 0x%x: %sCOMPRESSED\n", a->compression_unit,
			a->compression_unit ? "" : "NOT ");
	if (sle64_to_cpu(a->lowest_vcn))
		printf("Attribute is not the first extent. The following "
				"sizes are meaningless:\n");
	l = sle64_to_cpu(a->allocated_size);
	printf("Allocated size = %Li (0x%Lx)\n", l, l);
	l = sle64_to_cpu(a->data_size);
	printf("Data size = %Li (0x%Lx)\n", l, l);
	l = sle64_to_cpu(a->initialized_size);
	printf("Initialized size = %Li (0x%Lx)\n", l, l);
	if (a->flags & ATTR_COMPRESSION_MASK) {
		l = sle64_to_cpu(a->compressed_size);
		printf("Compressed size = %Li (0x%Lx)\n", l, l);
	}
	i = le16_to_cpu(a->mapping_pairs_offset);
	dump_mapping_pairs_array((char*)a + i, le32_to_cpu(a->length) - i);
}

void dump_attr_record(MFT_RECORD *m, ATTR_RECORD *a)
{
	unsigned int u;
	char s[0x200];
	int i;

	printf("-- Beginning dump of attribute record at offset 0x%x. --\n",
			(u8*)a - (u8*)m);
	if (a->type == AT_END) {
		printf("Attribute type = 0x%x ($END)\n", le32_to_cpu(AT_END));
		u = le32_to_cpu(a->length);
		printf("Length of resident part = %u (0x%x)\n", u, u);
		return;
	}
	u = le32_to_cpu(a->type);
	for (i = 0; attr_defs[i].type; i++)
		if (le32_to_cpu(attr_defs[i].type) >= u)
			break;
	if (attr_defs[i].type) {
//		printf("type = 0x%x\n", le32_to_cpu(attr_defs[i].type));
//		{ char *p = (char*)attr_defs[i].name;
//		printf("name = %c%c%c%c%c\n", *p, p[1], p[2], p[3], p[4]);
//		}
		if (ucstos(s, attr_defs[i].name, sizeof(s)) == -1) {
			Eprintf("Could not convert Unicode string to single "
				"byte string in current locale.\n");
			strncpy(s, "Error converting Unicode string",
					sizeof(s));
		}
	} else
		strncpy(s, "UNKNOWN_TYPE", sizeof(s));
	printf("Attribute type = 0x%x (%s)\n", u, s);
	u = le32_to_cpu(a->length);
	printf("Length of resident part = %u (0x%x)\n", u, u);
	printf("Attribute is %sresident\n", a->non_resident ? "non-" : "");
	printf("Name length = %u unicode characters\n", a->name_length);
	printf("Name offset = %u (0x%x)\n", cpu_to_le16(a->name_offset),
			cpu_to_le16(a->name_offset));
	u = a->flags;
	if (a->name_length) {
		if (ucstos(s, (uchar_t*)((char*)a +
				cpu_to_le16(a->name_offset)),
				min(sizeof(s), a->name_length + 1)) == -1) {
			Eprintf("Could not convert Unicode string to single "
				"byte string in current locale.\n");
			strncpy(s, "Error converting Unicode string",
					sizeof(s));

		}
		printf("Name = %s\n", s);
	}
	printf("Attribute flags = 0x%x: ", le16_to_cpu(u));
	if (!u)
		printf("NONE");
	else {
		int first = TRUE;
		if (u & ATTR_COMPRESSION_MASK) {
			if (u & ATTR_IS_COMPRESSED) {
				printf("ATTR_IS_COMPRESSED");
				first = FALSE;
			}
			if ((u & ATTR_COMPRESSION_MASK) & ~ATTR_IS_COMPRESSED) {
				if (!first)
					printf(" | ");
				else
					first = FALSE;
				printf("ATTR_UNKNOWN_COMPRESSION");
			}
		}
		if (u & ATTR_IS_ENCRYPTED) {
			if (!first)
				printf(" | ");
			else
				first = FALSE;
			printf("ATTR_IS_ENCRYPTED");
		}
		if (u & ATTR_IS_SPARSE) {
			if (!first)
				printf(" | ");
			else
				first = FALSE;
			printf("ATTR_IS_SPARSE");
		}
	}
	printf("\n");
	printf("Attribute instance = %u\n", le16_to_cpu(a->instance));
	if (a->non_resident) {
		dump_non_resident_attr(a);
	} else {
		dump_resident_attr(a);
	}
}

void dump_mft_record(MFT_RECORD *m)
{
	ATTR_RECORD *a;
	unsigned int u;
	MFT_REF r;

	printf("-- Beginning dump of mft record. --\n");
	u = le32_to_cpu(m->magic);
	printf("Mft record signature (magic) = %c%c%c%c\n", u & 0xff,
			u >> 8 & 0xff, u >> 16 & 0xff, u >> 24 & 0xff);
	u = le16_to_cpu(m->usa_ofs);
	printf("Update sequence array offset = %u (0x%x)\n", u, u);
	printf("Update sequence array size = %u\n", le16_to_cpu(m->usa_count));
	printf("$LogFile sequence number (lsn) = %Lu\n", le64_to_cpu(m->lsn));
	printf("Sequence number = %u\n", le16_to_cpu(m->sequence_number));
	printf("Reference (hard link) count = %u\n",
						le16_to_cpu(m->link_count));
	u = le16_to_cpu(m->attrs_offset);
	printf("First attribute offset = %u (0x%x)\n", u, u);
	printf("Flags = %u: ", le16_to_cpu(m->flags));
	if (m->flags & MFT_RECORD_IN_USE)
		printf("MFT_RECORD_IN_USE");
	else
		printf("MFT_RECORD_NOT_IN_USE");
	if (m->flags & MFT_RECORD_IS_DIRECTORY)
		printf(" | MFT_RECORD_IS_DIRECTORY");
	printf("\n");
	u = le32_to_cpu(m->bytes_in_use);
	printf("Bytes in use = %u (0x%x)\n", u, u);
	u = le32_to_cpu(m->bytes_allocated);
	printf("Bytes allocated = %u (0x%x)\n", u, u);
	r = le64_to_cpu(m->base_mft_record);
	printf("Base mft record reference:\n\tMft record number = %Lu\n\t"
			"Sequence number = %u\n", MREF(r), MSEQNO(r));
	printf("Next attribute instance = %u\n",
			le16_to_cpu(m->next_attr_instance));
	a = (ATTR_RECORD*)((char*)m + le16_to_cpu(m->attrs_offset));
	printf("-- Beginning dump of attributes within mft record. --\n");
	while ((char*)a < (char*)m + le32_to_cpu(m->bytes_in_use)) {
		if (a->type == cpu_to_le32(attr_type))
			dump_attr_record(m, a);
		if (a->type == AT_END)
			break;
		a = (ATTR_RECORD*)((char*)a + le32_to_cpu(a->length));
	};
	printf("-- End of attributes. --\n");
}

void usage(void) __attribute__ ((noreturn));

void usage(void)
{
	fprintf(stderr, "This utility will truncate a specified attribute "
			"belonging to a specified\ninode, i.e. file or "
			"directory, to a specified length.\n\n"
			"Usage: %s [-fhnqvV] device inode [attr-type "
			"[attr-name]] new-length\n       If "
			"attr-type is not specified, 0x80 (i.e. $DATA) "
			"is assumed.\n       If attr-name is not "
			"specified, an unnamed attribute is assumed.\n",
			EXEC_NAME);
	exit(1);
}

void parse_options(int argc, char *argv[])
{
	long long ll;
	char *s, *s2;
	int c;

	if (argc && *argv)
		EXEC_NAME = *argv;
	fprintf(stderr, "%s v%s -- Copyright (c) 2002-2003 Anton "
			"Altaparmakov\n", EXEC_NAME, VERSION);
	while ((c = getopt(argc, argv, "fhnqvV")) != EOF)
		switch (c) {
		case 'f':
			opts.force = 1;
			break;
		case 'n':
			opts.no_action = 1;
			break;
		case 'q':
			opts.quiet = 1;
			break;
		case 'v':
			opts.verbose++;
			break;
		case 'V':
			/* Version number already printed, so just exit. */
			exit(0);
		case 'h':
		default:
			usage();
		}
	if (optind == argc)
		usage();

	/* Get the device. */
	dev_name = argv[optind++];
	Dprintf("device name = %s\n", dev_name);

	if (optind == argc)
		usage();

	/* Get the inode. */
	ll = strtoll(argv[optind++], &s, 0);
	if (*s || !ll || (ll >= LLONG_MAX && errno == ERANGE))
		err_exit("Invalid inode number: %s\n", argv[optind - 1]);
	inode = ll;
	Dprintf("inode = %Li\n", (long long)inode);

	if (optind == argc)
		usage();

	/* Get the attribute type, if specified. */
	s = argv[optind++];
	if (optind == argc) {
		attr_type = AT_DATA;
		attr_name = AT_UNNAMED;
		attr_name_len = 0;
	} else {
		unsigned long ul;

		ul = strtoul(s, &s2, 0);
		if (*s2 || !ul || (ul >= ULONG_MAX && errno == ERANGE))
			err_exit("Invalid attribute type %s: %s\n", s,
					strerror(errno));
		attr_type = ul;

		/* Get the attribute name, if specified. */
		s = argv[optind++];
		if (optind != argc) {
			/* Convert the string to little endian Unicode. */
			attr_name_len = ntfs_mbstoucs(s, &attr_name, 0);
			if (attr_name_len < 0)
				err_exit("Invalid attribute name \"%s\": %s\n",
						s, strerror(errno));

			/* Keep hold of the original string. */
			s2 = s;

			s = argv[optind++];
			if (optind != argc)
				usage();
		} else {
			attr_name = AT_UNNAMED;
			attr_name_len = 0;
		}
	}
	Dprintf("attribute type = 0x%x\n", attr_type);
	if (attr_name == AT_UNNAMED)
		Dprintf("attribute name = \"\" (UNNAMED)\n");
	else
		Dprintf("attribute name = \"%s\" (length %i Unicode "
				"characters)\n", s2, attr_name_len);

	/* Get the new length. */
	ll = strtoll(s, &s2, 0);
	if (*s2 || ll < 0 || (ll >= LLONG_MAX && errno == ERANGE))
		err_exit("Invalid new length: %s\n", s);
	new_len = ll;
	Dprintf("new length = %Li\n", new_len);
}

void ntfstruncate_exit(void)
{
	int err;

	if (success)
		return;
	/* Close the attribute. */
	if (na)
		ntfs_attr_close(na);
	/* Close the inode. */
	if (ni && ntfs_inode_close(ni)) {
		fprintf(stderr, "Warning: Failed to close inode %Li: %s\n",
				(long long)inode, strerror(errno));
	}
	/* Unlock the device. */
	flk.l_type = F_UNLCK;
	err = fcntl(vol->fd, F_SETLK, &flk);
	if (err == -1)
		fprintf(stderr, "Warning: Could not unlock %s: %s\n", dev_name,
				strerror(errno));
	/* Unmount the volume. */
	err = ntfs_umount(vol, 0);
	if (err == -1)
		fprintf(stderr, "Warning: Could not umount %s: %s\n", dev_name,
				strerror(errno));
	/* Free the attribute name if it exists. */
	if (attr_name && attr_name != AT_UNNAMED)
		free(attr_name);
}

int main(int argc, char **argv)
{
	unsigned long mnt_flags, ul;
	int err;

	/* Initialize opts to zero / required values. */
	memset(&opts, 0, sizeof(opts));

	/*
	 * Setup a default $AttrDef. FIXME: Should be reading this from the
	 * volume itself, at ntfs_mount() time.
	 */
	attr_defs = (ATTR_DEF*)&attrdef_ntfs12_array;

	/* Parse command line options. */
	parse_options(argc, argv);

	/* Make sure the file system is not mounted. */
	if (ntfs_check_if_mounted(dev_name, &mnt_flags))
		Eprintf("Failed to determine whether %s is mounted: %s\n",
				dev_name, strerror(errno));
	else if (mnt_flags & NTFS_MF_MOUNTED) {
		Eprintf("%s is mounted.\n", dev_name);
		if (!opts.force)
			err_exit("Refusing to run!\n");
		fprintf(stderr, "ntfstruncate forced anyway. Hope /etc/mtab "
				"is incorrect.\n");
	}

	/* Mount the device. */
	if (opts.no_action) {
		Qprintf("Running in READ-ONLY mode!\n");
		ul = MS_RDONLY;
	} else
		ul = 0;
	vol = ntfs_mount(dev_name, ul);
	if (!vol)
		err_exit("Failed to mount %s: %s\n", dev_name, strerror(errno));

	/* Acquire exlusive (mandatory) lock on the whole device. */
	memset(&flk, 0, sizeof(flk));
	if (opts.no_action)
		flk.l_type = F_RDLCK;
	else
		flk.l_type = F_WRLCK;
	flk.l_whence = SEEK_SET;
	flk.l_start = flk.l_len = 0LL;
	err = fcntl(vol->fd, F_SETLK, &flk);
	if (err == -1) {
		Eprintf("Could not lock %s for %s: %s\n", dev_name,
				opts.no_action ? "reading" : "writing",
				strerror(errno));
		err = ntfs_umount(vol, 0);
		if (err == -1)
			Eprintf("Warning: Could not umount %s: %s\n",
					dev_name, strerror(errno));
		exit(1);
	}

	/* Register our exit function which will unlock and close the device. */
	err = atexit(&ntfstruncate_exit);
	if (err == -1) {
		Eprintf("Could not set up exit() function because atexit() "
				"failed: %s Aborting...\n", strerror(errno));
		ntfstruncate_exit();
		exit(1);
	}

	/* Open the specified inode. */
	ni = ntfs_inode_open(vol, inode);
	if (!ni)
		err_exit("Failed to open inode %Li: %s\n", (long long)inode,
				strerror(errno));

	/* Open the specified attribute. */
	na = ntfs_attr_open(ni, attr_type, attr_name, attr_name_len);
	if (!na)
		err_exit("Failed to open attribute 0x%x: %s\n", attr_type,
				strerror(errno));

	if (!opts.quiet && opts.verbose > 1) {
		Dprintf("Dumping mft record before calling "
				"ntfs_attr_truncate():\n");
		dump_mft_record(ni->mrec);
	}

	/* Truncate the attribute. */
	err = ntfs_attr_truncate(na, new_len);
	if (err)
		err_exit("Failed to truncate attribute 0x%x: %s\n", attr_type,
				strerror(errno));

	if (!opts.quiet && opts.verbose > 1) {
		Dprintf("Dumping mft record after calling "
				"ntfs_attr_truncate():\n");
		dump_mft_record(ni->mrec);
	}

	/* Close the attribute. */
	ntfs_attr_close(na);
	na = NULL;

	/* Close the inode. */
	err = ntfs_inode_close(ni);
	if (err)
		err_exit("Failed to close inode %Li: %s\n", (long long)inode,
				strerror(errno));

	/* Unlock the device. */
	flk.l_type = F_UNLCK;
	err = fcntl(vol->fd, F_SETLK, &flk);
	if (err == -1)
		fprintf(stderr, "Warning: Failed to unlock %s: %s\n", dev_name,
				strerror(errno));

	/* Unmount the volume. */
	err = ntfs_umount(vol, 0);
	if (err == -1)
		fprintf(stderr, "Warning: Failed to umount %s: %s\n", dev_name,
				strerror(errno));

	/* Free the attribute name if it exists. */
	if (attr_name && attr_name != AT_UNNAMED)
		free(attr_name);

	/* Finally, disable our ntfstruncate_exit() handler. */
	success = TRUE;

	Qprintf("ntfstruncate completed successfully. Have a nice day.\n");
	return 0;
}

