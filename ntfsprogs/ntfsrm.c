/**
 * ntfsrm - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2004 Richard Russon
 *
 * This utility will delete files from an NTFS volume.
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

#include "config.h"

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "utils.h"
#include "ntfsrm.h"
#include "debug.h"
#include "dir.h"
#include "lcnalloc.h"
#include "mft.h"

static const char *EXEC_NAME = "ntfsrm";
static struct options opts;
static const char *space_line = "                                                                                ";

GEN_PRINTF (Eprintf, stderr, NULL,          FALSE)
GEN_PRINTF (Vprintf, stdout, &opts.verbose, TRUE)
GEN_PRINTF (Qprintf, stdout, &opts.quiet,   FALSE)

static int ntfs_inode_close2 (ntfs_inode *ni);

/**
 * version - Print version information about the program
 *
 * Print a copyright statement and a brief description of the program.
 *
 * Return:  none
 */
static void version (void)
{
	printf ("\n%s v%s - Delete files from an NTFS volume.\n\n",
		EXEC_NAME, VERSION);
	printf ("Copyright (c) 2004 Richard Russon\n");
	printf ("\n%s\n%s%s\n", ntfs_gpl, ntfs_bugs, ntfs_home);
}

/**
 * usage - Print a list of the parameters to the program
 *
 * Print a list of the parameters and options for the program.
 *
 * Return:  none
 */
static void usage (void)
{
	printf ("\nUsage: %s [options] device file\n"
		"\n"
		"    -r  --recursive    Delete files in subdirectories\n"
		"    -i  --interactive  Ask before deleting files\n"
		//"    -I num  --inode num  Delete the file with this inode number\n"
		//"    -U      --unlink     Unlink the file, deleting all references \n"
		"\n"
		"    -D  --no-dirty     Do not mark volume dirty (require chkdsk)\n"
		"    -n  --no-action    Do not write to disk\n"
		"    -f  --force        Use less caution\n"
		"    -h  --help         Print this help\n"
		"    -q  --quiet        Less output\n"
		"    -V  --version      Version information\n"
		"    -v  --verbose      More output\n\n",
		EXEC_NAME);
	printf ("%s%s\n", ntfs_bugs, ntfs_home);
}

/**
 * parse_options - Read and validate the programs command line
 *
 * Read the command line, verify the syntax and parse the options.
 * This function is very long, but quite simple.
 *
 * Return:  1 Success
 *	    0 Error, one or more problems
 */
static int parse_options (int argc, char **argv)
{
	static const char *sopt = "-Dfh?inqRrVv"; //"-Dfh?I:inqRrUVv";
	static const struct option lopt[] = {
		{ "force",		no_argument,		NULL, 'f' },
		{ "help",		no_argument,		NULL, 'h' },
		//{ "inode",		required_argument,	NULL, 'I' },
		{ "interactive",	no_argument,		NULL, 'i' },
		{ "no-action",		no_argument,		NULL, 'n' },
		{ "no-dirty",		no_argument,		NULL, 'D' },
		{ "quiet",		no_argument,		NULL, 'q' },
		{ "recursive",		no_argument,		NULL, 'r' },
		//{ "unlink",		no_argument,		NULL, 'U' },
		{ "verbose",		no_argument,		NULL, 'v' },
		{ "version",		no_argument,		NULL, 'V' },
		{ NULL,			0,			NULL, 0   }
	};

	char c = -1;
	int err  = 0;
	int ver  = 0;
	int help = 0;

	opterr = 0; /* We'll handle the errors, thank you. */

	while ((c = getopt_long (argc, argv, sopt, lopt, NULL)) != -1) {
		switch (c) {
		case 1:	/* A non-option argument */
			if (!opts.device) {
				opts.device = argv[optind-1];
			} else if (!opts.file) {
				opts.file = argv[optind-1];
			} else {
				opts.device = NULL;
				opts.file   = NULL;
				err++;
			}
			break;
		case 'D':
			opts.nodirty++;
			break;
		case 'f':
			opts.force++;
			break;
		case 'h':
		case '?':
			help++;
			break;
		case 'i':
			opts.interactive++;
			break;
		case 'n':
			opts.noaction++;
			break;
		case 'q':
			opts.quiet++;
			break;
		case 'R':
		case 'r':
			opts.recursive++;
			break;
		case 'V':
			ver++;
			break;
		case 'v':
			opts.verbose++;
			break;
		default:
			Eprintf ("Unknown option '%s'.\n", argv[optind-1]);
			err++;
			break;
		}
	}

	if (help || ver) {
		opts.quiet = 0;
	} else {
		if ((opts.device == NULL) ||
		    (opts.file   == NULL)) {
			if (argc > 1)
				Eprintf ("You must specify one device and one file.\n");
			err++;
		}

		if (opts.quiet && opts.verbose) {
			Eprintf("You may not use --quiet and --verbose at the "
					"same time.\n");
			err++;
		}
	}

	if (ver)
		version();
	if (help || err)
		usage();

	return (!err && !help && !ver);
}


/**
 * ntfs_name_print
 */
static void ntfs_name_print (ntfschar *name, int name_len)
{
	char *buffer = NULL;

	if (name_len) {
		ntfs_ucstombs (name, name_len, (char**) &buffer, 0);
		printf ("%s", buffer);
		free (buffer);
	} else {
		printf ("!");
	}
}

/**
 * ntfs_dir_print
 */
static void ntfs_dir_print (struct ntfs_dir *dir, int indent)
{
	int i;
	if (!dir)
		return;

	printf ("%.*s%p ", indent, space_line, dir);
	ntfs_name_print (dir->name, dir->name_len);
	printf ("\n");

	for (i = 0; i < dir->child_count; i++) {
		ntfs_dir_print (dir->children[i], indent + 4);
	}

}

/**
 * ntfs_dt_print
 */
static void ntfs_dt_print (struct ntfs_dt *dt, int indent)
{
	int i;

	if (!dt)
		return;

	printf ("%.*s%p (%d)\n", indent, space_line, dt, dt->child_count);

	for (i = 0; i < dt->child_count; i++) {
		ntfs_dt_print (dt->sub_nodes[i], indent + 4);
	}
}

/**
 * ntfsinfo_time_to_str
 */
static const char *ntfsinfo_time_to_str(const s64 sle_ntfs_clock)
{
	time_t unix_clock = ntfs2utc(sle64_to_cpu(sle_ntfs_clock));
	if (sle_ntfs_clock == 0)
		return "none\n";
	else
		return ctime(&unix_clock);
}


/**
 * ntfs_bmp_free
 */
static void ntfs_bmp_free (struct ntfs_bmp *bmp)
{
	int i;

	if (!bmp)
		return;

	for (i = 0; i < bmp->count; i++)
		free (bmp->data[i]);

	ntfs_attr_close (bmp->attr);

	free (bmp->data);
	free (bmp->data_vcn);
	free (bmp);
}

/**
 * ntfs_bmp_alloc
 */
static struct ntfs_bmp * ntfs_bmp_alloc (ntfs_inode *inode, ATTR_TYPES type, ntfschar *name, int name_len)
{
	struct ntfs_bmp *bmp;
	ntfs_attr *attr;

	if (!inode)
		return NULL;

	attr = ntfs_attr_open (inode, type, name, name_len);
	if (!attr)
		return NULL;

	bmp = calloc (1, sizeof (*bmp));
	if (!bmp)
		return NULL;

	bmp->attr      = attr;
	bmp->data      = calloc (16, sizeof (*bmp->data));
	bmp->data_vcn  = calloc (16, sizeof (*bmp->data_vcn));
	bmp->count     = 0;

	if (!bmp->data || !bmp->data_vcn) {
		ntfs_bmp_free (bmp);
		return NULL;
	}

	return bmp;
}

/**
 * ntfs_bmp_add_data
 */
static int ntfs_bmp_add_data (struct ntfs_bmp *bmp, VCN vcn, u8 *data)
{
	int i = 0;
	int old;
	int new;

	if (!bmp || !data)
		return -1;

	old = ((bmp->count + 15) & ~15);
	bmp->count++;
	new = ((bmp->count + 15) & ~15);

	if (old != new) {
		bmp->data     = realloc (bmp->data,      new * sizeof (*bmp->data));
		bmp->data_vcn = realloc (bmp->data_vcn , new * sizeof (*bmp->data_vcn));
	}

	for (i = 0; i < bmp->count-1; i++)
		if (bmp->data_vcn[i] > vcn)
			break;

	if ((bmp->count-i) > 0) {
		memmove (&bmp->data[i+1],     &bmp->data[i],     (bmp->count-i) * sizeof (*bmp->data));
		memmove (&bmp->data_vcn[i+1], &bmp->data_vcn[i], (bmp->count-i) * sizeof (*bmp->data_vcn));
	}

	bmp->data[i]     = data;
	bmp->data_vcn[i] = vcn;

	return bmp->count;
}

/**
 * ntfs_bmp_get_data
 */
static u8 * ntfs_bmp_get_data (struct ntfs_bmp *bmp, VCN vcn)
{
	u8 *buffer;
	int i;
	VCN begin;
	VCN end;

	if (!bmp)
		return NULL;

	for (i = 0; i < bmp->count; i++) {
		begin = (bmp->data_vcn[i] >> 3) & (~(512-1));
		end   = begin + (512 << 3);
		if ((vcn >= begin) && (vcn < end)) {
			//printf ("%lld, %lld, %lld\n", begin, vcn, end);
			return bmp->data[i];
		}
	}

	buffer = malloc (512);
	if (!buffer)
		return NULL;

	begin = (vcn>>3) & (~(512-1));
	//printf ("loading from offset %lld\n", begin);
	if (ntfs_attr_pread (bmp->attr, begin, 512, buffer) < 0) {
		free (buffer);
		return NULL;
	}

	ntfs_bmp_add_data (bmp, vcn, buffer);
	return buffer;
}

/**
 * ntfs_bmp_set_range
 */
static int ntfs_bmp_set_range (struct ntfs_bmp *bmp, VCN vcn, s64 length, int value)
{
	s64 i;
	u8 *buffer;
	VCN begin;
	VCN end;
	int start;
	int finish;
	u8 sta_part = 0;
	u8 fin_part = 0;

	if (!bmp)
		return -1;

	//printf ("\n");
	//printf ("set range: %lld - %lld\n", vcn, vcn+length-1);

	for (i = vcn; i < (vcn+length); i += 4096) {
		buffer = ntfs_bmp_get_data (bmp, i);
		if (!buffer)
			return -1;

#if 0
		memset (buffer, 0xFF, 512);
		value = 0;
		memset (buffer, 0x00, 512);
		value = 1;
#endif
		//utils_dump_mem (buffer, 0, 32, DM_DEFAULTS);
		//printf ("\n");

		begin = i & ~4095;
		end   = begin + 4095;
		//printf ("begin = %lld, vcn = %lld,%lld end = %lld\n", begin, vcn, vcn+length-1, end);

		if ((vcn > begin) && (vcn < end)) {
			//printf ("1\n");
			start = ((vcn+8) >> 3) & 511;
			sta_part = 0xff << (vcn&7);
		} else {
			//printf ("2\n");
			start = 0;
		}

		if (((vcn+length-1) >= begin) && ((vcn+length-1) <= end)) {
			//printf ("3\n");
			finish = ((vcn+length-1) >> 3) & 511;
			fin_part = 0xff >> (7-((vcn+length-1)&7));
		} else {
			//printf ("4\n");
			finish = 511;
		}

#if 0
		//printf ("\n");
		printf ("%lld) ", i>>12);
		if (start > 0) {
			printf ("(%02x) ", sta_part);
		} else {
			printf ("     ");
		}

		printf ("%d - %d", start, finish);

		if (finish < 511) {
			printf (" (%02x)\n", fin_part);
		} else {
			printf ("     \n");
		}
#endif
		if (value) {
			if (start != 0)
				buffer[start-1] |= sta_part;
			if ((finish - start) > 0)
				memset (buffer+start, 0xff, finish-start);
			buffer[finish] |= fin_part;
		} else {
			if (start != 0)
				buffer[start-1] &= ~sta_part;
			if ((finish - start) > 0)
				memset (buffer+start, 0x00, finish-start);
			buffer[finish] &= ~fin_part;
		}
		//utils_dump_mem (buffer, 0, 16, DM_DEFAULTS);
	}

	printf (GREEN "Modified: inode %lld, " END, bmp->attr->ni->mft_no);
	switch (bmp->attr->type) {
		case AT_BITMAP: printf ("$BITMAP"); break;
		case AT_DATA:   printf ("$DATA");   break;
	}
	printf (" vcn %lld-%lld\n", vcn>>12, (vcn+length)>>12);

	return 1;
}

/**
 * ntfs_bmp_commit
 */
static int ntfs_bmp_commit (struct ntfs_bmp *bmp)
{
	if (!bmp)
		return -1;
	return 0;
}

/**
 * ntfs_bmp_rollback
 */
static int ntfs_bmp_rollback (struct ntfs_bmp *bmp)
{
	if (!bmp)
		return -1;
	return 0;
}


/**
 * ntfs_ie_get_vcn
 */
static VCN ntfs_ie_get_vcn (INDEX_ENTRY *ie)
{
	if (!ie)
		return -1;
	if (!(ie->flags & INDEX_ENTRY_NODE))
		return -1;

	return *((VCN*) ((u8*) ie + ie->length - 8));
}

/**
 * ntfs_ie_dump
 */
static void ntfs_ie_dump (INDEX_ENTRY *ie)
{
	if (!ie)
		return;

	printf ("________________________________________________");
	printf ("\n");
	utils_dump_mem ((u8*)ie, 0, ie->length, DM_DEFAULTS);

	printf ("MFT Ref: 0x%llx\n", ie->indexed_file);
	printf ("length: %d\n", ie->length);
	printf ("keylen: %d\n", ie->key_length);
	printf ("flags: ");
		if (ie->flags & INDEX_ENTRY_NODE) printf ("NODE ");
		if (ie->flags & INDEX_ENTRY_END)  printf ("END");
		if (!(ie->flags & (INDEX_ENTRY_NODE | INDEX_ENTRY_END))) printf ("none");
	printf ("\n");
	printf ("reserved 0x%04x\n", ie->reserved);
	if (ie->key_length > 0) {
		printf ("mft parent: 0x%llx\n", ie->key.file_name.parent_directory);

		printf ("ctime: %s", ntfsinfo_time_to_str(ie->key.file_name.creation_time));
		printf ("dtime: %s", ntfsinfo_time_to_str(ie->key.file_name.last_data_change_time));
		printf ("mtime: %s", ntfsinfo_time_to_str(ie->key.file_name.last_mft_change_time));
		printf ("atime: %s", ntfsinfo_time_to_str(ie->key.file_name.last_access_time));
		printf ("alloc size: %lld\n", ie->key.file_name.allocated_size);
		printf ("data size: %lld\n", ie->key.file_name.data_size);
		printf ("file flags: 0x%04x\n", ie->key.file_name.file_attributes);
		printf ("reserved: 0x%04x\n", ie->key.file_name.reserved); printf ("name len: %d\n", ie->key.file_name.file_name_length);
		if (ie->key.file_name.file_name_length > 0) {
			int i, r;
			printf ("name type: %d\n", ie->key.file_name.file_name_type);
			printf ("name: ");
			ntfs_name_print (ie->key.file_name.file_name, ie->key.file_name.file_name_length);
			printf ("\n");
			r = ATTR_SIZE (2 * (ie->key.file_name.file_name_length+1)) - (2 * (ie->key.file_name.file_name_length+1));
			if (r > 0) {
				u8 *ptr;
				printf ("padding: ");
				ptr = (u8*) (ie->key.file_name.file_name +  ie->key.file_name.file_name_length);
				for (i = 0; i < r; i++, ptr++)
					printf ("0x%02x ", *ptr);
				printf ("\n");
			}
		}
	}
	if (ie->flags == INDEX_ENTRY_NODE) {
		printf ("child vcn = %lld\n", ntfs_ie_get_vcn (ie));
	}
}

/**
 * ntfs_ie_create
 */
static INDEX_ENTRY * ntfs_ie_create (void)
{
	int length;
	INDEX_ENTRY *ie;

	length = 16;
	ie = malloc (length);
	if (!ie)
		return NULL;

	ie->indexed_file = 0;
	ie->length       = length;
	ie->key_length   = 0;
	ie->flags        = INDEX_ENTRY_END;
	ie->reserved     = 0;
	return ie;
}

/**
 * ntfs_ie_copy
 */
static INDEX_ENTRY * ntfs_ie_copy (INDEX_ENTRY *ie)
{
	INDEX_ENTRY *copy = NULL;

	if (!ie)
		return NULL;

	copy = malloc (ie->length);
	if (!copy)
		return NULL;
	memcpy (copy, ie, ie->length);

	return copy;
}

/**
 * ntfs_ie_set_vcn
 */
static INDEX_ENTRY * ntfs_ie_set_vcn (INDEX_ENTRY *ie, VCN vcn)
{
	if (!ie)
		return 0;

	if (!(ie->flags & INDEX_ENTRY_NODE)) {
		ie->length += 8;
		ie = realloc (ie, ie->length);
		if (!ie)
			return NULL;

		ie->flags |= INDEX_ENTRY_NODE;
	}

	*((VCN*) ((u8*) ie + ie->length - 8)) = vcn;
	return ie;
}

/**
 * ntfs_ie_remove_vcn
 */
static INDEX_ENTRY * ntfs_ie_remove_vcn (INDEX_ENTRY *ie)
{
	if (!ie)
		return NULL;
	if (!(ie->flags & INDEX_ENTRY_NODE))
		return ie;

	ie->length -= 8;
	ie->flags &= ~INDEX_ENTRY_NODE;
	ie = realloc (ie, ie->length);
	return ie;
}

/**
 * ntfs_ie_set_name
 */
static INDEX_ENTRY * ntfs_ie_set_name (INDEX_ENTRY *ie, ntfschar *name, int namelen, FILE_NAME_TYPE_FLAGS nametype)
{
	FILE_NAME_ATTR *file;
	int klen;
	int need;
	VCN vcn = 0;

	if (!ie || !name)
		return NULL;

	/*
	 * INDEX_ENTRY
	 *	MFT_REF indexed_file;
	 *	u16 length;
	 *	u16 key_length;
	 *	INDEX_ENTRY_FLAGS flags;
	 *	u16 reserved;
	 *
	 *	FILENAME
	 *		MFT_REF parent_directory;
	 *		s64 creation_time;
	 *		s64 last_data_change_time;
	 *		s64 last_mft_change_time;
	 *		s64 last_access_time;
	 *		s64 allocated_size;
	 *		s64 data_size;
	 *		FILE_ATTR_FLAGS file_attributes;
	 *		u32 reserved;
	 *		u8 file_name_length;
	 *		FILE_NAME_TYPE_FLAGS file_name_type;
	 *		ntfschar file_name[l];
	 *		u8 reserved[n]
	 *
	 *	VCN vcn;
	 */

	file = &ie->key.file_name;

	klen = ATTR_SIZE (ie->key_length);
	need = ATTR_SIZE (sizeof (FILE_NAME_ATTR) + (namelen * sizeof (ntfschar)));

	//printf ("ilen = %d\n", ie->length);
	//printf ("klen = %d\n", klen);
	//printf ("need = %d\n", need);

	if (ie->flags & INDEX_ENTRY_NODE)
		vcn = ntfs_ie_get_vcn (ie);

	ie->length = 16 + need;
	ie->key_length = sizeof (FILE_NAME_ATTR) + (namelen * sizeof (ntfschar));
	ie = realloc (ie, ie->length + ie->key_length);
	if (!ie)
		return NULL;

	memcpy (ie->key.file_name.file_name, name, namelen * 2);

	if (ie->flags & INDEX_ENTRY_NODE)
		ie = ntfs_ie_set_vcn (ie, vcn);

	ie->key.file_name.file_name_length = namelen;
	ie->key.file_name.file_name_type = nametype;
	ie->flags &= ~INDEX_ENTRY_END;

	return ie;
}

/**
 * ntfs_ie_remove_name
 */
static INDEX_ENTRY * ntfs_ie_remove_name (INDEX_ENTRY *ie)
{
	VCN vcn = 0;

	if (!ie)
		return NULL;
	if (ie->key_length == 0)
		return ie;

	if (ie->flags & INDEX_ENTRY_NODE)
		vcn = ntfs_ie_get_vcn (ie);

	ie->length -= ATTR_SIZE (ie->key_length);
	ie->key_length = 0;
	ie->flags |= INDEX_ENTRY_END;

	ie = realloc (ie, ie->length);
	if (!ie)
		return NULL;

	if (ie->flags & INDEX_ENTRY_NODE)
		ie = ntfs_ie_set_vcn (ie, vcn);
	return ie;
}

/**
 * ntfs_ie_test
 */
static int ntfs_ie_test (void)
{
	INDEX_ENTRY *ie1 = NULL;
	INDEX_ENTRY *ie2 = NULL;
	int namelen = 0;
	ntfschar *name = NULL;

	if (1) {
		ie1 = ntfs_ie_create();
		//ntfs_ie_dump (ie1);
	}

	if (0) {
		ie2 = ntfs_ie_copy (ie1);
		ntfs_ie_dump (ie2);
	}

	if (1) {
		namelen = ntfs_mbstoucs("richard", &name, 0);
		ie1 = ntfs_ie_set_name (ie1, name, namelen, FILE_NAME_WIN32);
		free (name);
		name = NULL;
		ntfs_ie_dump (ie1);
	}

	if (1) {
		namelen = ntfs_mbstoucs("richard2", &name, 0);
		ie1 = ntfs_ie_set_name (ie1, name, namelen, FILE_NAME_WIN32);
		free (name);
		name = NULL;
		ntfs_ie_dump (ie1);
	}

	if (1) {
		ie1 = ntfs_ie_remove_name (ie1);
		ntfs_ie_dump (ie1);
	}

	if (1) {
		ie1 = ntfs_ie_set_vcn (ie1, 1234);
		ntfs_ie_dump (ie1);
	}

	if (1) {
		ie1 = ntfs_ie_remove_vcn (ie1);
		ntfs_ie_dump (ie1);
	}

	ie1->indexed_file = 1234;
	ie1->key.file_name.parent_directory = 5;
	ie1->key.file_name.creation_time = utc2ntfs (time(NULL));
	ie1->key.file_name.last_data_change_time = utc2ntfs (time(NULL));
	ie1->key.file_name.last_mft_change_time = utc2ntfs (time(NULL));
	ie1->key.file_name.last_access_time = utc2ntfs (time(NULL));
	ie1->key.file_name.allocated_size = 4096;
	ie1->key.file_name.data_size = 3973;

	//ntfs_ie_dump (ie1);
	free (name);
	free (ie1);
	free (ie2);
	return 0;
}


/**
 * ntfs_dt_alloc_children
 */
static INDEX_ENTRY ** ntfs_dt_alloc_children (INDEX_ENTRY **children, int count)
{
	// XXX calculate for 2K and 4K indexes max and min filenames (inc/exc VCN)
	int old = (count + 0x1e) & ~0x1f;
	int new = (count + 0x1f) & ~0x1f;

	if (old == new)
		return children;

	return realloc (children, new * sizeof (INDEX_ENTRY*));
}

/**
 * ntfs_dt_alloc_children2
 */
static BOOL ntfs_dt_alloc_children2 (struct ntfs_dt *dt, int count)
{
	// XXX calculate for 2K and 4K indexes max and min filenames (inc/exc VCN)

	int old = (dt->child_count + 0x1e) & ~0x1f;
	int new = (count           + 0x1f) & ~0x1f;

	if (old == new)
		return TRUE;

	dt->children  = realloc (dt->children,  new * sizeof (*dt->children));
	dt->sub_nodes = realloc (dt->sub_nodes, new * sizeof (*dt->sub_nodes));
	dt->inodes    = realloc (dt->sub_nodes, new * sizeof (*dt->inodes));

	// XXX wipe new space

	return (dt->children && dt->sub_nodes && dt->inodes);
}

/**
 * ntfs_dt_count_root
 */
static int ntfs_dt_count_root (struct ntfs_dt *dt)
{
	u8 *buffer = NULL;
	u8 *ptr = NULL;
	VCN vcn;
	s64 size = 0;
	char *name = NULL;

	INDEX_ROOT *root;
	INDEX_HEADER *header;
	INDEX_ENTRY *entry;

	if (!dt)
		return -1;

	buffer = dt->data;
	size   = dt->data_len;

	root = (INDEX_ROOT*) buffer;
	if (root->type != AT_FILE_NAME)
		return -1;

	header = (INDEX_HEADER*) (buffer + 0x10);
	if (header->index_length > size)
		return -1;

	dt->child_count = 0;
	ptr = buffer + header->entries_offset + 0x10;

	while (ptr < (buffer + size)) {
		entry = (INDEX_ENTRY*) ptr;
		dt->child_count++;

		dt->children  = ntfs_dt_alloc_children  (dt->children,  dt->child_count);

		if (entry->flags & INDEX_ENTRY_NODE) {
			vcn = ntfs_ie_get_vcn ((INDEX_ENTRY*) ptr);
			//printf ("VCN %lld\n", vcn);
		}

		if (!(entry->flags & INDEX_ENTRY_END)) {
			ntfs_ucstombs (entry->key.file_name.file_name, entry->key.file_name.file_name_length, &name, entry->key.file_name.file_name_length);
			//printf ("\tinode %8lld %s\n", MREF (entry->indexed_file), name);
			free (name);
			name = NULL;
		}

		//printf ("CC[%d] = %p\n", dt->child_count-1, entry);
		dt->children[dt->child_count-1] = entry;

		ptr += entry->length;
	}

	//printf ("count = %d\n\n", dt->child_count);

	if (dt->child_count > 0) {
		//printf ("%d subnodes\n", dt->child_count);
		dt->sub_nodes = calloc (dt->child_count, sizeof (struct ntfs_dt *));
		dt->inodes    = calloc (dt->child_count, sizeof (struct ntfs_inode *));
	}
	return dt->child_count;
}

/**
 * ntfs_dt_count_alloc
 */
static int ntfs_dt_count_alloc (struct ntfs_dt *dt)
{
	u8 *buffer = NULL;
	u8 *ptr = NULL;
	VCN vcn;
	s64 size = 0;
	char *name = NULL;

	INDEX_BLOCK *block;
	INDEX_ENTRY *entry;

	if (!dt)
		return -1;

	buffer = dt->data;
	size   = dt->data_len;

	//utils_dump_mem (buffer, 0, 128, DM_DEFAULTS);

	block = (INDEX_BLOCK*) buffer;
	//printf ("INDX %lld\n", block->index_block_vcn);

	ptr = buffer + 0x18 + block->index.entries_offset;

	//printf ("block size %d\n", block->index.index_length);
	dt->child_count = 0;
	while (ptr < (buffer + 0x18 + block->index.index_length)) {
		entry = (INDEX_ENTRY*) ptr;
		dt->child_count++;

		dt->children = ntfs_dt_alloc_children  (dt->children,  dt->child_count);

		if (entry->flags & INDEX_ENTRY_NODE) {
			vcn = ntfs_ie_get_vcn ((INDEX_ENTRY*) ptr);
			//printf ("\tVCN %lld\n", vcn);
		}

		dt->children[dt->child_count-1] = entry;

		if (entry->flags & INDEX_ENTRY_END) {
			break;
		} else {
			ntfs_ucstombs (entry->key.file_name.file_name, entry->key.file_name.file_name_length, &name, entry->key.file_name.file_name_length);
			//printf ("\tinode %8lld %s\n", MREF (entry->indexed_file), name);
			free (name);
			name = NULL;
		}

		ptr += entry->length;
	}
	//printf ("count = %d\n", dt->child_count);

	if (dt->child_count > 0) {
		//printf ("%d subnodes\n", dt->child_count);
		dt->sub_nodes = calloc (dt->child_count, sizeof (struct ntfs_dt *));
		dt->inodes    = calloc (dt->child_count, sizeof (struct ntfs_inode *));
	}

	return dt->child_count;
}

/**
 * ntfs_dt_alloc
 */
static struct ntfs_dt * ntfs_dt_alloc (struct ntfs_dir *dir, struct ntfs_dt *parent, VCN vcn)
{
	struct ntfs_dt *dt = NULL;
	//int i;

	if (!dir)
		return NULL;

	dt = calloc (1, sizeof (*dt));
	if (!dt)
		return NULL;

	dt->dir		= dir;
	dt->parent	= parent;
	dt->child_count	= 0;
	dt->children	= NULL;
	dt->sub_nodes	= NULL;
	dt->inodes	= NULL;
	dt->vcn		= vcn;
	dt->changed	= FALSE;

	if (parent) {
		//printf ("alloc a = %lld\n", dir->ialloc->allocated_size);
		//printf ("alloc d = %lld\n", dir->ialloc->data_size);
		//printf ("alloc i = %lld\n", dir->ialloc->initialized_size);
		//printf ("vcn = %lld\n", vcn);

		dt->data_len = dt->dir->index_size;
		//printf ("parent size = %d\n", dt->data_len);
		dt->data     = malloc (dt->data_len);
		//printf ("%lld\n", ntfs_attr_mst_pread (dir->ialloc, vcn*512, 1, dt->data_len, dt->data));
		ntfs_attr_mst_pread (dir->ialloc, vcn*512, 1, dt->data_len, dt->data);
		//utils_dump_mem (dt->data, 0, dt->data_len, DM_DEFAULTS);
		//printf ("\n");

		ntfs_dt_count_alloc (dt);

		dt->header = &((INDEX_BLOCK*)dt->data)->index;
		//printf ("USA = %d\n", ((INDEX_BLOCK*)dt->data)->usa_count);

#if 0
		for (i = 0; i < dt->child_count; i++) {
			INDEX_ENTRY *ie = dt->children[i];

			printf ("%d\n", ((u8*)ie) - dt->data);
			if (ie->flags & INDEX_ENTRY_END)
				printf ("IE (%d)\n", ie->length);
			else
				printf ("IE %lld (%d)\n", MREF (ie->key.file_name.parent_directory), ie->length);
			utils_dump_mem ((u8*)ie, 0, ie->length, DM_DEFAULTS);
			printf ("\n");
		}
#endif
	} else {
		//printf ("root a  = %lld\n", dir->iroot->allocated_size);
		//printf ("root d  = %lld\n", dir->iroot->data_size);
		//printf ("root i  = %lld\n", dir->iroot->initialized_size);

		dt->data_len = dir->iroot->allocated_size;
		dt->data     = malloc (dt->data_len);
		//printf ("%lld\n", ntfs_attr_pread (dir->iroot, 0, dt->data_len, dt->data));
		ntfs_attr_pread (dir->iroot, 0, dt->data_len, dt->data);
		//utils_dump_mem (dt->data, 0, dt->data_len, DM_DEFAULTS);

		ntfs_dt_count_root (dt);

		dt->header = &((INDEX_ROOT*)dt->data)->index;
		//dt->data_len = ((INDEX_ROOT*)dt->data)->index_block_size;
		//printf ("IBS = %d\n", ((INDEX_ROOT*)dt->data)->index_block_size);

#if 0
		for (i = 0; i < dt->child_count; i++) {
			INDEX_ENTRY *ie = dt->children[i];

			printf ("%d\n", ((u8*)ie) - dt->data);
			if (ie->flags & INDEX_ENTRY_END)
				printf ("IE (%d)\n", ie->length);
			else
				printf ("IE %lld (%d)\n", MREF (ie->key.file_name.parent_directory), ie->length);
			utils_dump_mem ((u8*)ie, 0, ie->length, DM_DEFAULTS);
			printf ("\n");
		}
#endif
	}
	//printf ("index_header (%d,%d)\n", dt->header.index_length, dt->header.allocated_size);

	return dt;
}

/**
 * ntfs_dt_free
 */
static void ntfs_dt_free (struct ntfs_dt *dt)
{
	int i;

	if (!dt)
		return;

	for (i = 0; i < dt->child_count; i++) {
		ntfs_dt_free      (dt->sub_nodes[i]);
		ntfs_inode_close2 (dt->inodes[i]);
	}

	free (dt->sub_nodes);
	free (dt->children);
	free (dt->inodes);
	free (dt->data);	// XXX is this always ours?
	free (dt);
}

/**
 * ntfs_dt_find
 * find dt by name, return MFT_REF
 * maps dt's as necessary
 */
static MFT_REF ntfs_dt_find (struct ntfs_dt *dt, ntfschar *name, int name_len)
{
	MFT_REF res = -1;
	INDEX_ENTRY *ie;
	struct ntfs_dt *sub;
	VCN vcn;
	int i;
	int r;

	if (!dt || !name)
		return -1;

	/*
	 * State            Children  Action
	 * -------------------------------------------
	 * collates after      -      keep searching
	 * match name          -      return MREF
	 * collates before     no     return -1
	 * collates before     yes    map & recurse
	 * end marker          no     return -1
	 * end marker          yes    map & recurse
	 */

	//printf ("child_count = %d\n", dt->child_count);
	for (i = 0; i < dt->child_count; i++) {
		ie = dt->children[i];

		if (ie->flags & INDEX_ENTRY_END) {
			r = -1;
		} else {
			//printf ("\t"); ntfs_name_print (ie->key.file_name.file_name, ie->key.file_name.file_name_length); printf ("\n");
			r = ntfs_names_collate (name, name_len,
						ie->key.file_name.file_name,
						ie->key.file_name.file_name_length,
						2, IGNORE_CASE,
						dt->dir->vol->upcase,
						dt->dir->vol->upcase_len);
		}

		//printf ("%d, %d\n", i, r);

		if (r == 1) {
			//printf ("keep searching\n");
			continue;
		} else if (r == 0) {
			res = MREF (ie->indexed_file);
			//printf ("match %lld\n", res);
		} else if (r == -1) {
			if (ie->flags & INDEX_ENTRY_NODE) {
				//printf ("map & recurse\n");
				//printf ("sub %p\n", dt->sub_nodes);
				if (!dt->sub_nodes[i]) {
					vcn = ntfs_ie_get_vcn (ie);
					//printf ("vcn = %lld\n", vcn);
					sub = ntfs_dt_alloc (dt->dir, dt, vcn);
					dt->sub_nodes[i] = sub;
				}
				res = ntfs_dt_find (dt->sub_nodes[i], name, name_len);
			} else {
				//printf ("ENOENT\n");
			}
		} else {
			printf ("error collating name\n");
		}
		break;
	}

	return res;
}

/**
 * ntfs_dt_find2
 * find dt by name, returns dt and index
 * maps dt's as necessary
 */
static struct ntfs_dt * ntfs_dt_find2 (struct ntfs_dt *dt, ntfschar *name, int name_len, int *index_num)
{
	struct ntfs_dt *res = NULL;
	INDEX_ENTRY *ie;
	VCN vcn;
	int i;
	int r;

	if (!dt || !name)
		return NULL;

	// XXX default index_num to -1
	
	/*
	 * State            Children  Action
	 * -------------------------------------------
	 * collates after      -      keep searching
	 * match name          -      return MREF
	 * collates before     no     return -1
	 * collates before     yes    map & recurse
	 * end marker          no     return -1
	 * end marker          yes    map & recurse
	 */

	//printf ("child_count = %d\n", dt->child_count);
	for (i = 0; i < dt->child_count; i++) {
		ie = dt->children[i];

		if (ie->flags & INDEX_ENTRY_END) {
			r = -1;
		} else {
			//printf ("\t"); ntfs_name_print (ie->key.file_name.file_name, ie->key.file_name.file_name_length); printf ("\n");
			r = ntfs_names_collate (name, name_len,
						ie->key.file_name.file_name,
						ie->key.file_name.file_name_length,
						2, IGNORE_CASE,
						dt->dir->vol->upcase,
						dt->dir->vol->upcase_len);
		}

		//printf ("%d, %d\n", i, r);

		if (r == 1) {
			//printf ("keep searching\n");
			continue;
		} else if (r == 0) {
			res = dt;
			//printf ("match %p\n", res);
			if (index_num)
				*index_num = i;
		} else if (r == -1) {
			//printf ("recurse\n");
			if (!dt->sub_nodes[i]) {
				vcn = ntfs_ie_get_vcn (ie);
				//printf ("vcn = %lld\n", vcn);
				dt->sub_nodes[i] = ntfs_dt_alloc (dt->dir, dt, vcn);
			}
			res = ntfs_dt_find2 (dt->sub_nodes[i], name, name_len, index_num);
		} else {
			printf ("error collating name\n");
		}
		break;
	}

	return res;
}

/**
 * ntfs_dt_find3
 * find dt by name, returns dt and index
 * does not map new dt's
 */
static struct ntfs_dt * ntfs_dt_find3 (struct ntfs_dt *dt, ntfschar *name, int name_len, int *index_num)
{
	struct ntfs_dt *res = NULL;
	INDEX_ENTRY *ie;
	int i;
	int r;

	if (!dt || !name)
		return NULL;

	//printf ("child_count = %d\n", dt->child_count);
	for (i = 0; i < dt->child_count; i++) {
		ie = dt->children[i];

		if (ie->flags & INDEX_ENTRY_END) {
			r = -1;
		} else {
			//printf ("\t"); ntfs_name_print (ie->key.file_name.file_name, ie->key.file_name.file_name_length); printf ("\n");
			r = ntfs_names_collate (name, name_len,
						ie->key.file_name.file_name,
						ie->key.file_name.file_name_length,
						2, IGNORE_CASE,
						dt->dir->vol->upcase,
						dt->dir->vol->upcase_len);
		}

		//printf ("%d, %d\n", i, r);

		if (r == 1) {
			//printf ("keep searching\n");
			continue;
		} else if (r == 0) {
			res = dt;
			//printf ("match %p\n", res);
			if (index_num)
				*index_num = i;
		} else if (r == -1) {
			if (ie->flags & INDEX_ENTRY_NODE) {
				//printf ("recurse\n");
				res = ntfs_dt_find3 (dt->sub_nodes[i], name, name_len, index_num);
			} else {
				//printf ("no match\n");
				res = dt;
				if (index_num)
					*index_num = i;
			}
		} else {
			printf ("error collating name\n");
		}
		break;
	}

	return res;
}

/**
 * ntfs_dt_find4
 * find successor to specified name, returns dt and index
 * maps dt's as necessary
 */
static struct ntfs_dt * ntfs_dt_find4 (struct ntfs_dt *dt, ntfschar *name, int name_len, int *index_num)
{
	struct ntfs_dt *res = NULL;
	struct ntfs_dt *sub = NULL;
	INDEX_ENTRY *ie;
	VCN vcn;
	int i;
	int r;

	if (!dt || !name)
		return NULL;

	//printf ("child_count = %d\n", dt->child_count);
	for (i = 0; i < dt->child_count; i++) {
		ie = dt->children[i];

		//printf ("ie->flags = %d\n", ie->flags);
		if (ie->flags & INDEX_ENTRY_END) {
			r = -1;
		} else {
			//printf ("\t"); ntfs_name_print (ie->key.file_name.file_name, ie->key.file_name.file_name_length); printf ("\n");
			r = ntfs_names_collate (name, name_len,
						ie->key.file_name.file_name,
						ie->key.file_name.file_name_length,
						2, IGNORE_CASE,
						dt->dir->vol->upcase,
						dt->dir->vol->upcase_len);
		}

		//printf ("%d, %d\n", i, r);

		if (r == 1) {
			//printf ("keep searching\n");
		} else if (r == 0) {
			//res = dt;
			//printf ("match\n");
			// ignore
		} else if (r == -1) {
			if (ie->flags & INDEX_ENTRY_NODE) {
				//printf ("recurse\n");
				if (!dt->sub_nodes[i]) {
					vcn = ntfs_ie_get_vcn (ie);
					//printf ("vcn = %lld\n", vcn);
					sub = ntfs_dt_alloc (dt->dir, dt, vcn);
					dt->sub_nodes[i] = sub;
				}
				res = ntfs_dt_find4 (dt->sub_nodes[i], name, name_len, index_num);
			} else {
				//printf ("no match\n");
				res = dt;
				if (index_num)
					*index_num = i;
			}
			break;
		} else {
			printf ("error collating name\n");
		}
		//break;
	}

	return res;
}

/**
 * ntfs_dt_find_all
 * maps all dt's into memory
 */
static void ntfs_dt_find_all (struct ntfs_dt *dt)
{
	INDEX_ENTRY *ie;
	VCN vcn;
	int i;

	if (!dt)
		return;

	for (i = 0; i < dt->child_count; i++) {
		ie = dt->children[i];

		if (ie->flags & INDEX_ENTRY_NODE) {
			if (!dt->sub_nodes[i]) {
				vcn = ntfs_ie_get_vcn (ie);
				dt->sub_nodes[i] = ntfs_dt_alloc (dt->dir, dt, vcn);
			}
			ntfs_dt_find_all (dt->sub_nodes[i]);
		}
	}
}

/**
 * ntfs_dt_commit
 */
static int ntfs_dt_commit (struct ntfs_dt *dt)
{
	if (!dt)
		return -1;
	return 0;
}

/**
 * ntfs_dt_rollback
 */
static int ntfs_dt_rollback (struct ntfs_dt *dt)
{
	if (!dt)
		return -1;
	return 0;
}

/**
 * ntfs_dt_find_parent
 */
static int ntfs_dt_find_parent (struct ntfs_dt *dt)
{
	int i;
	struct ntfs_dt *parent;

	if (!dt)
		return -1;

	parent = dt->parent;
	if (!parent)
		return -1;

	for (i = 0; i < parent->child_count; i++)
		if (parent->sub_nodes[i] == dt)
			return i;

	return -1;
}

/**
 * ntfs_dt_root
 */
static BOOL ntfs_dt_root (struct ntfs_dt *dt)
{
	if (!dt)
		return FALSE;
	return (dt->parent == NULL);
}

/**
 * ntfs_dt_freespace_root
 */
static int ntfs_dt_freespace_root (struct ntfs_dt *dt)
{
	int recsize;
	int inuse;
	MFT_RECORD *mrec;

	if (!dt)
		return -1;

	recsize = dt->dir->inode->vol->mft_record_size;

	mrec = (MFT_RECORD*) dt->dir->inode->mrec;
	inuse = mrec->bytes_in_use;

	return recsize - inuse;
}

/**
 * ntfs_dt_freespace_alloc
 */
static int ntfs_dt_freespace_alloc (struct ntfs_dt *dt)
{
	int recsize;
	int inuse;
	INDEX_BLOCK *block;

	if (!dt)
		return -1;

	recsize = dt->dir->index_size;

	block = (INDEX_BLOCK*) dt->data;
	inuse = block->index.index_length + 24;

	return recsize - inuse;
}

/**
 * ntfs_dt_initialise
 */
static int ntfs_dt_initialise (struct ntfs_dt *dt, VCN vcn)
{
	INDEX_BLOCK *block;
	INDEX_ENTRY *ie;

	if (!dt || !dt->data)
		return -1;

	memset (dt->data, 0, dt->data_len);

	// Ought to check these are empty
	free (dt->children);
	free (dt->sub_nodes);

	dt->children  = NULL;
	dt->sub_nodes = NULL;

	if (!ntfs_dt_alloc_children2 (dt, 1))
		return -1;

	block = (INDEX_BLOCK*) dt->data;

	block->magic                = magic_INDX;
	block->usa_ofs              = 0x28;
	block->usa_count            = (dt->data_len >> 9) + 1;
	block->index_block_vcn      = vcn;
	block->index.entries_offset = 0x28;
	block->index.index_length   = 0x38;
	block->index.allocated_size = dt->data_len - 0x18;

	ie = (INDEX_ENTRY*) (dt->data + block->index.entries_offset + 0x18);

	ie->length = 0x10;
	ie->flags  = INDEX_ENTRY_END;

	dt->children[0]  = ie;
	dt->sub_nodes[0] = NULL;

	//utils_dump_mem (dt->data, 0, block->index.index_length+0x18, DM_DEFAULTS);

	return 0;
}

/**
 * ntfs_dt_transfer
 */
static int ntfs_dt_transfer (struct ntfs_dt *old, struct ntfs_dt *new, int start, int count)
{
	int i;
	int need;
	int space;
	INDEX_ENTRY *mov_ie;
	u8 *src;
	u8 *dst;
	int len;
	int insert;
	//FILE_NAME_ATTR *file;

	//XXX check len > 0

	if (!old || !new)
		return -1;

	if ((start < 0) || ((start+count) >= old->child_count))
		return -1;

	printf ("\n");
	printf (BOLD YELLOW "Transferring children\n" END);

	need = 0;
	for (i = start; i < (start+count+1); i++) {
		mov_ie = old->children[i];
		need += mov_ie->length;
		//file = &mov_ie->key.file_name; printf ("\ttrn name: "); ntfs_name_print (file->file_name, file->file_name_length); printf ("\n");
	}

	if (ntfs_dt_root (new))
		space = ntfs_dt_freespace_root (new);
	else
		space = ntfs_dt_freespace_alloc (new);

	// XXX if this is an index root, it'll go badly wrong
	// restrict to allocs only?

	printf ("\tneed  = %d\n", need);
	printf ("\tspace = %d\n", space);

	if (space < need)
		return -1;

	if (new->child_count == 1) {
		i = -1;
	} else {
		ntfschar *n1, *n2;
		int l1, l2;

		n1 = new->children[0]->key.file_name.file_name;
		l1 = new->children[0]->key.file_name.file_name_length;

		n2 = old->children[start]->key.file_name.file_name;
		l2 = old->children[start]->key.file_name.file_name_length;

		i = ntfs_names_collate (n1, l1, n2, l2,
					2, IGNORE_CASE,
					old->dir->vol->upcase,
					old->dir->vol->upcase_len);
	}

	if ((i == 0) || (i == 2))
		return -1;

	// determine the insertion point
	if (i == 1)
		insert = 0;
	else
		insert = new->child_count-1;

	src = (u8*) new->children[insert];
	dst = src + need;
	len = (u8*) new->children[new->child_count-1] + new->children[new->child_count-1]->length - src;

	//printf ("src = %d, dst = %d, len = %d\n", src - new->data, dst - new->data, len);
	memmove (dst, src, len);

	dst = src;
	src = (u8*) old->children[start];
	len = need;

	memcpy (dst, src, len);

	src = (u8*) old->children[start+count-1];
	dst = (u8*) old->children[start];
	len = (u8*) old->children[old->child_count-1] + old->children[old->child_count-1]->length - src;

	//printf ("src = %d, dst = %d, len = %d\n", src - old->data, dst - old->data, len);
	memmove (dst, src, len);

	dst += len;
	len = old->data + old->dir->index_size - dst;

	//printf ("dst = %d, len = %d\n", dst - old->data, len);
	memset (dst, 0, len);

	new->child_count += count;
	if (!ntfs_dt_alloc_children2 (new, new->child_count))
		return -1;

	src = (u8*) &old->sub_nodes[start+count-1];
	dst = (u8*) &old->sub_nodes[start];
	len = (old->child_count - start - count + 1) * sizeof (struct ntfs_dt*);

	memmove (dst, src, len);

	src = (u8*) &new->sub_nodes[insert];
	dst = (u8*) &new->sub_nodes[insert+count-1];
	len = (new->child_count - insert - count + 1) * sizeof (struct ntfs_dt*);

	memmove (dst, src, len);

	old->child_count -= count;
	if (!ntfs_dt_alloc_children2 (old, old->child_count))
		return -1;

	src = (u8*) new->children[0];
	for (i = 0; i < new->child_count; i++) {
		new->children[i] = (INDEX_ENTRY*) src;
		src += new->children[i]->length;
	}

	src = (u8*) old->children[0];
	for (i = 0; i < old->child_count; i++) {
		old->children[i] = (INDEX_ENTRY*) src;
		src += old->children[i]->length;
	}

	old->header->index_length -= need;
	new->header->index_length += need;

	// resize children and sub_nodes
	// memmove keys in new
	// memcpy old to new
	// memmove keys in old
	// rebuild old/new children/sub_nodes without destroying tree
	// update old/new headers

	printf (GREEN "Modified: inode %lld, $INDEX_ALLOCATION vcn %lld-%lld\n" END, old->dir->inode->mft_no, old->vcn, old->vcn + (old->dir->index_size>>9) - 1);
	printf (GREEN "Modified: inode %lld, $INDEX_ALLOCATION vcn %lld-%lld\n" END, new->dir->inode->mft_no, new->vcn, new->vcn + (new->dir->index_size>>9) - 1);

	return 0;
}


/**
 * ntfs_inode_dir_map
 */
static void ntfs_inode_dir_map (ntfs_inode *ino)
{
	ATTR_RECORD *rec;
	FILE_NAME_ATTR *fn;
	ntfs_inode *parent;

	if (!ino)
		return;

	printf ("open inode %lld\n", ino->mft_no);

	if (ino->mft_no == FILE_root) {
		printf ("done\n");
		return;
	}

	rec = find_first_attribute (AT_FILE_NAME, ino->mrec);
	if (!rec)
		return;

	fn = (FILE_NAME_ATTR *) ((char *) rec + le16_to_cpu (rec->value_offset));

	parent = ntfs_inode_open (ino->vol, fn->parent_directory);
	if (parent) {
		ntfs_inode_dir_map (parent);
		ntfs_inode_close (parent);
	}
}

/**
 * ntfs_inode_open2
 */
static ntfs_inode *ntfs_inode_open2 (ntfs_volume *vol, const MFT_REF mref)
{
	ntfs_inode *ino = NULL;
	struct ntfs_dt *dt;

	if (!vol)
		return NULL;

	switch (mref) {
		case FILE_Bitmap:  ino = vol->lcnbmp_ni;  break;
		case FILE_MFT:     ino = vol->mft_ni;     break;
		case FILE_MFTMirr: ino = vol->mftmirr_ni; break;
		case FILE_root:
			if (vol->private_data) {
				dt = (struct ntfs_dt *) vol->private_data;
				if (dt->dir) {
					ino = dt->dir->inode;
				}
			}
			break;
	}

	if (ino) {
		//printf (BOLD YELLOW "inode reuse %lld\n" END, mref);
		ino->ref_count++;
		return ino;
	}

	ino = ntfs_inode_open (vol, mref);
	if (!ino)
		return NULL;

	/*
	if (mref != FILE_root)
		ntfs_inode_dir_map (ino);
	*/

	// link
	//   ino->private_data

	ino->private_data = NULL;
	ino->ref_count = 1;

	//printf (BOLD YELLOW "inode open %lld\n" END, mref);
	return ino;
}

/**
 * ntfs_inode_close2
 */
static int ntfs_inode_close2 (ntfs_inode *ni)
{
	if (!ni)
		return 0;
	
	//printf (BOLD YELLOW "inode close %lld (%d)\n" END, ni->mft_no, ni->ref_count);

	ni->ref_count--;
	if (ni->ref_count > 0)
		return 0;

	// unlink
	//   ino->private_data

	return ntfs_inode_close (ni);
}


/**
 * ntfs_dir_free
 */
static void ntfs_dir_free (struct ntfs_dir *dir)
{
	struct ntfs_dir *parent;
	int i;

	if (!dir)
		return;

	parent = dir->parent;
	if (parent) {
		for (i = 0; i < parent->child_count; i++) {
			if (parent->children[i] == dir) {
				parent->children[i] = NULL;
			}
		}
	}

	ntfs_attr_close (dir->iroot);
	ntfs_attr_close (dir->ialloc);
	ntfs_attr_close (dir->ibmp);
	ntfs_inode_close2 (dir->inode);

	ntfs_dt_free (dir->index);

	for (i = 0; i < dir->child_count; i++)
		ntfs_dir_free (dir->children[i]);

	free (dir->children);
	free (dir);
}

/**
 * ntfs_dir_alloc
 */
static struct ntfs_dir * ntfs_dir_alloc (ntfs_volume *vol, MFT_REF mft_num)
{
	struct ntfs_dir *dir   = NULL;
	ntfs_inode      *inode = NULL;
	ATTR_RECORD	*rec   = NULL;
	INDEX_ROOT	*ir    = NULL;

	if (!vol)
		return NULL;

	//printf ("ntfs_dir_alloc %lld\n", MREF (mft_num));
	inode = ntfs_inode_open2 (vol, mft_num);
	if (!inode)
		return NULL;

	dir = calloc (1, sizeof (*dir));
	if (!dir) {
		ntfs_inode_close2 (inode);
		return NULL;
	}

	dir->inode  = inode;
	dir->iroot  = ntfs_attr_open (inode, AT_INDEX_ROOT,       I30, 4);
	dir->ialloc = ntfs_attr_open (inode, AT_INDEX_ALLOCATION, I30, 4);
	dir->ibmp   = ntfs_attr_open (inode, AT_BITMAP,           I30, 4);

	dir->vol	  = vol;
	dir->parent	  = NULL;
	dir->name	  = NULL;
	dir->name_len	  = 0;
	dir->index	  = NULL;
	dir->children	  = NULL;
	dir->child_count  = 0;
	dir->mft_num	  = mft_num;
	dir->bitmap	  = NULL;

	if (dir->ialloc) {
		rec = find_first_attribute (AT_INDEX_ROOT, inode->mrec);
		ir  = (INDEX_ROOT*) ((u8*)rec + rec->value_offset);
		dir->index_size = ir->index_block_size;
	} else {
		dir->index_size = 0;
	}

	if (!dir->iroot) {
		ntfs_dir_free (dir);
		return NULL;
	}

	return dir;
}

/**
 * ntfs_dir_add
 */
static void ntfs_dir_add (struct ntfs_dir *parent, struct ntfs_dir *child)
{
	if (!parent || !child)
		return;

	parent->child_count++;
	//printf ("child count = %d\n", parent->child_count);
	parent->children = realloc (parent->children, parent->child_count * sizeof (struct ntfs_dir*));
	child->parent = parent;

	parent->children[parent->child_count-1] = child;
}

/**
 * ntfs_dir_find
 */
static MFT_REF ntfs_dir_find (struct ntfs_dir *dir, char *name)
{
	MFT_REF mft_num;
	ntfschar *uname = NULL;
	int len;

	if (!dir || !name)
		return -1;

	len = ntfs_mbstoucs (name, &uname, 0);
	if (len < 0)
		return -1;

	if (!dir->index)
		dir->index = ntfs_dt_alloc (dir, NULL, -1);

	//printf ("dir->index = %p\n", dir->index);
	//printf ("dir->child_count = %d\n", dir->child_count);
	//printf ("uname = %p\n", uname);
	mft_num = ntfs_dt_find (dir->index, uname, len);

	free (uname);
	return mft_num;
}

/**
 * ntfs_dir_find2
 */
static struct ntfs_dir * ntfs_dir_find2 (struct ntfs_dir *dir, ntfschar *name, int name_len)
{
	int i;
	struct ntfs_dir *child = NULL;
	struct ntfs_dt *dt = NULL;
	int dt_num = 0;
	INDEX_ENTRY *ie;
	MFT_REF mft_num;

	if (!dir || !name)
		return NULL;

	if (!dir->index) {	// XXX when will this happen?
		printf ("ntfs_dir_find2 - directory has no index\n");
		return NULL;
	}

	for (i = 0; i < dir->child_count; i++) {
		if (0 == ntfs_names_collate (name, name_len,
					dir->children[i]->name,
					dir->children[i]->name_len,
					2, IGNORE_CASE,
					dir->vol->upcase,
					dir->vol->upcase_len))
			return dir->children[i];
	}

	dt = ntfs_dt_find2 (dir->index, name, name_len, &dt_num);
	if (!dt) {
		printf ("can't find name in dir\n");
		return NULL;
	}

	ie = dt->children[dt_num];

	mft_num = ie->indexed_file;

	child = ntfs_dir_alloc (dir->vol, mft_num);
	child->index = ntfs_dt_alloc (child, NULL, -1);

	ntfs_dir_add (dir, child);

	return child;
}

/**
 * ntfs_dir_commit
 */
static int ntfs_dir_commit (struct ntfs_dir *dir)
{
	if (!dir)
		return -1;

	if (0) ntfs_dt_commit (NULL);
	if (0) ntfs_bmp_commit (NULL);

	return 0;
}

/**
 * ntfs_dir_rollback
 */
static int ntfs_dir_rollback (struct ntfs_dir *dir)
{
	if (!dir)
		return -1;

	if (0) ntfs_dt_rollback (NULL);
	if (0) ntfs_bmp_rollback (NULL);

	return 0;
}


/**
 * ntfs_umount2
 */
static int ntfs_umount2 (ntfs_volume *vol, const BOOL force)
{
	struct ntfs_dt *dt;

	if (!vol)
		return 0;

	dt = (struct ntfs_dt *) vol->private_data;
	if (dt) {
		vol->private_data = NULL;
		ntfs_dir_free (dt->dir);
	}

	return ntfs_umount (vol, force);
}

/**
 * utils_mount_volume2
 */
static ntfs_volume * utils_mount_volume2 (const char *device, unsigned long flags, BOOL force)
{
	static ntfschar bmp[8] = {
		const_cpu_to_le16('$'),
		const_cpu_to_le16('B'),
		const_cpu_to_le16('i'),
		const_cpu_to_le16('t'),
		const_cpu_to_le16('m'),
		const_cpu_to_le16('a'),
		const_cpu_to_le16('p'),
		const_cpu_to_le16(0)
	};

	static ntfschar mft[5] = {
		const_cpu_to_le16('$'),
		const_cpu_to_le16('M'),
		const_cpu_to_le16('F'),
		const_cpu_to_le16('T'),
		const_cpu_to_le16(0)
	};

	static ntfschar mftmirr[9] = {
		const_cpu_to_le16('$'),
		const_cpu_to_le16('M'),
		const_cpu_to_le16('F'),
		const_cpu_to_le16('T'),
		const_cpu_to_le16('M'),
		const_cpu_to_le16('i'),
		const_cpu_to_le16('r'),
		const_cpu_to_le16('r'),
		const_cpu_to_le16(0)
	};

	static ntfschar dot[2] = {
		const_cpu_to_le16('.'),
		const_cpu_to_le16(0)
	};

	ntfs_volume *vol;
	ntfs_inode *ni;
	struct ntfs_dir *dir;
	struct ntfs_dt *root;
	struct ntfs_dt *found;
	int num;

	vol = utils_mount_volume (device, flags, force);
	if (!vol)
		return NULL;

	vol->lcnbmp_ni ->ref_count = 1;
	vol->mft_ni    ->ref_count = 1;
	vol->mftmirr_ni->ref_count = 1;

	vol->lcnbmp_ni ->private_data = NULL;
	vol->mft_ni    ->private_data = NULL;
	vol->mftmirr_ni->private_data = NULL;

	dir = ntfs_dir_alloc (vol, FILE_root);
	if (!dir) {
		ntfs_umount2 (vol, FALSE);
		vol = NULL;
		goto done;
	}

	dir->index = ntfs_dt_alloc (dir, NULL, -1);

	root = dir->index;

	//$Bitmap
	num = -1;
	found = ntfs_dt_find2 (root, bmp, 7, &num);
	if ((!found) || (num < 0)) {
		printf ("can't find $Bitmap\n");
		ntfs_umount2 (vol, FALSE);
		vol = NULL;
		goto done;
	}
	vol->lcnbmp_ni->ref_count++;
	vol->lcnbmp_ni->private_data = found->dir;
	found->inodes[num] = vol->lcnbmp_ni;

	//$MFT
	num = -1;
	found = ntfs_dt_find2 (root, mft, 4, &num);
	if ((!found) || (num < 0)) {
		printf ("can't find $MFT\n");
		ntfs_umount2 (vol, FALSE);
		vol = NULL;
		goto done;
	}
	vol->mft_ni->ref_count++;
	vol->mft_ni->private_data = found->dir;
	found->inodes[num] = vol->mft_ni;

	//$MFTMirr
	num = -1;
	found = ntfs_dt_find2 (root, mftmirr, 8, &num);
	if ((!found) || (num < 0)) {
		printf ("can't find $MFTMirr\n");
		ntfs_umount2 (vol, FALSE);
		vol = NULL;
		goto done;
	}
	vol->mftmirr_ni->ref_count++;
	vol->mftmirr_ni->private_data = found->dir;
	found->inodes[num] = vol->mftmirr_ni;

	ni = ntfs_inode_open (vol, FILE_root);
	if (!ni) {
		printf ("can't find root dir\n");
		ntfs_umount2 (vol, FALSE);
		vol = NULL;
		goto done;
	}

	// root directory
	num = -1;
	found = ntfs_dt_find2 (root, dot, 1, &num);
	if ((!found) || (num < 0)) {
		printf ("can't find the root directory\n");
		ntfs_inode_close (ni);
		ntfs_umount2 (vol, FALSE);
		vol = NULL;
		goto done;
	}
	
	dir->inode = ni;
	vol->private_data = found;
	ni->private_data = found;
	found->inodes[num] = ni;
	ni->ref_count = 2;

done:
	return vol;
}


/**
 * utils_pathname_to_mftref
 */
static MFT_REF utils_pathname_to_mftref (ntfs_volume *vol, struct ntfs_dir *parent, const char *pathname, struct ntfs_dir **finddir)
{
	MFT_REF mft_num;
	MFT_REF result = -1;
	char *p, *q;
	char *ascii = NULL;
	struct ntfs_dir *dir = NULL;

	if (!vol || !parent || !pathname) {
		errno = EINVAL;
		return -1;
	}

	ascii = strdup (pathname);		// Work with a r/w copy
	if (!ascii) {
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

		//printf ("looking for %s in %p\n", p, parent);
		mft_num = ntfs_dir_find (parent, p);
		if (mft_num == (u64)-1) {
			Eprintf ("Couldn't find name '%s' in pathname '%s'.\n", p, pathname);
			goto close;
		}

		if (q) {
			dir = ntfs_dir_alloc (vol, mft_num);
			if (!dir) {
				Eprintf ("Couldn't allocate a new directory (%lld).\n", mft_num);
				goto close;
			}

			ntfs_dir_add (parent, dir);
			parent = dir;
		} else {
			//printf ("file %s\n", p);
			result = mft_num;
			if (finddir)
				*finddir = dir ? dir : parent;
			break;
		}

		p = q;
		while (p && *p && *p == PATH_SEP)
			p++;
	}

close:
	free (ascii);
	return result;
}

/**
 * utils_mftrec_mark_free
 */
static int utils_mftrec_mark_free (ntfs_volume *vol, MFT_REF mref)
{
	static u8 buffer[512];
	static s64 bmpmref = -sizeof (buffer) - 1; /* Which bit of $BITMAP is in the buffer */

	int byte, bit;

	if (!vol) {
		errno = EINVAL;
		return -1;
	}

	mref = MREF (mref);
	//printf ("mref = %lld\n", mref);
	/* Does mref lie in the section of $Bitmap we already have cached? */
	if (((s64)mref < bmpmref) || ((s64)mref >= (bmpmref +
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

	if ((buffer[byte] & bit) == 0) {
		Eprintf ("MFT record isn't in use (1).\n");
		return -1;
	}

	//utils_dump_mem (buffer, byte, 1, DM_NO_ASCII);
	buffer[byte] &= ~bit;
	//utils_dump_mem (buffer, byte, 1, DM_NO_ASCII);

	if (ntfs_attr_pwrite (vol->mftbmp_na, (bmpmref>>3), sizeof (buffer), buffer) < 0) {
		Eprintf ("Couldn't write $MFT/$BITMAP: %s\n", strerror (errno));
		return -1;
	}

	return (buffer[byte] & bit);
}

/**
 * utils_mftrec_mark_free2
 */
static int utils_mftrec_mark_free2 (ntfs_volume *vol, MFT_REF mref)
{
	u8 buffer[1024];
	s64 res;
	MFT_RECORD *rec;

	if (!vol)
		return -1;

	mref = MREF (mref);
	rec = (MFT_RECORD*) buffer;

	res = ntfs_mft_record_read (vol, mref, rec);
	printf ("res = %lld\n", res);

	if ((rec->flags & MFT_RECORD_IN_USE) == 0) {
		Eprintf ("MFT record isn't in use (2).\n");
		return -1;
	}

	rec->flags &= ~MFT_RECORD_IN_USE;

	//printf ("\n");
	//utils_dump_mem (buffer, 0, 1024, DM_DEFAULTS);

	res = ntfs_mft_record_write (vol, mref, rec);
	printf ("res = %lld\n", res);

	return 0;
}

/**
 * utils_mftrec_mark_free3
 */
static int utils_mftrec_mark_free3 (struct ntfs_bmp *bmp, MFT_REF mref)
{
	return ntfs_bmp_set_range (bmp, (VCN) MREF (mref), 1, 0);
}

/**
 * utils_mftrec_mark_free4
 */
static int utils_mftrec_mark_free4 (ntfs_inode *inode)
{
	MFT_RECORD *rec;

	if (!inode)
		return -1;

	rec = (MFT_RECORD*) inode->mrec;

	if ((rec->flags & MFT_RECORD_IN_USE) == 0) {
		Eprintf ("MFT record isn't in use (3).\n");
		return -1;
	}

	rec->flags &= ~MFT_RECORD_IN_USE;

	//printf ("\n");
	//utils_dump_mem (buffer, 0, 1024, DM_DEFAULTS);

	printf (GREEN "Modified: inode %lld MFT_RECORD header\n" END, inode->mft_no);
	return 0;
}

/**
 * utils_mftrec_mark_free5
 */
static int utils_mftrec_mark_free5 (ntfs_inode *inode, struct ntfs_bmp *bmp, MFT_REF mref)
{
	MFT_RECORD *rec;

	if (!inode)
		return -1;

	if (ntfs_bmp_set_range (bmp, (VCN) MREF (mref), 1, 0) < 0)
		return -1;

	rec = (MFT_RECORD*) inode->mrec;

	if ((rec->flags & MFT_RECORD_IN_USE) == 0) {
		Eprintf ("MFT record isn't in use (4).\n");
		return -1;
	}

	rec->flags &= ~MFT_RECORD_IN_USE;

	//printf ("\n");
	//utils_dump_mem (buffer, 0, 1024, DM_DEFAULTS);

	printf (GREEN "Modified: inode %lld MFT_RECORD header\n" END, inode->mft_no);
	return 0;
}

/**
 * utils_free_non_residents
 */
static int utils_free_non_residents (ntfs_inode *inode)
{
	// XXX need to do this in memory

	ntfs_attr_search_ctx *ctx;
	ntfs_attr *na;
	ATTR_RECORD *arec;

	if (!inode)
		return -1;

	ctx = ntfs_attr_get_search_ctx (NULL, inode->mrec);
	if (!ctx) {
		printf ("can't create a search context\n");
		return -1;
	}

	while (ntfs_attr_lookup(AT_UNUSED, NULL, 0, 0, 0, NULL, 0, ctx) == 0) {
		arec = ctx->attr;
		if (arec->non_resident) {
			na = ntfs_attr_open (inode, arec->type, NULL, 0);
			if (na) {
				runlist_element *rl;
				LCN size;
				LCN count;
				ntfs_attr_map_whole_runlist (na);
				rl = na->rl;
				size = na->allocated_size >> inode->vol->cluster_size_bits;
				for (count = 0; count < size; count += rl->length, rl++) {
					//printf ("rl(%llu,%llu,%lld)\n", rl->vcn, rl->lcn, rl->length);
					//printf ("freed %d\n", ntfs_cluster_free (inode->vol, na, rl->vcn, rl->length));
					ntfs_cluster_free (inode->vol, na, rl->vcn, rl->length);
				}
				ntfs_attr_close (na);
			}
		}
	}

	ntfs_attr_put_search_ctx (ctx);
	return 0;
}

/**
 * utils_free_non_residents2
 */
static int utils_free_non_residents2 (ntfs_inode *inode, struct ntfs_bmp *bmp)
{
	ntfs_attr_search_ctx *ctx;
	ntfs_attr *na;
	ATTR_RECORD *arec;

	if (!inode)
		return -1;

	ctx = ntfs_attr_get_search_ctx (NULL, inode->mrec);
	if (!ctx) {
		printf ("can't create a search context\n");
		return -1;
	}

	while (ntfs_attr_lookup(AT_UNUSED, NULL, 0, 0, 0, NULL, 0, ctx) == 0) {
		arec = ctx->attr;
		if (arec->non_resident) {
			na = ntfs_attr_open (inode, arec->type, NULL, 0);
			if (na) {
				runlist_element *rl;
				LCN size;
				LCN count;
				ntfs_attr_map_whole_runlist (na);
				rl = na->rl;
				size = na->allocated_size >> inode->vol->cluster_size_bits;
				for (count = 0; count < size; count += rl->length, rl++) {
					ntfs_bmp_set_range (bmp, rl->lcn, rl->length, 0);
				}
				ntfs_attr_close (na);
			}
		}
	}

	ntfs_attr_put_search_ctx (ctx);
	return 0;
}

/**
 * utils_pathname_to_inode2
 */
static BOOL utils_pathname_to_inode2 (ntfs_volume *vol, struct ntfs_dir *parent, const char *pathname, struct ntfs_find *found)
{
	int len;
	char *p, *q;
	ntfschar *unicode = NULL;
	char *ascii = NULL;
	struct ntfs_dir *dir = NULL;
	struct ntfs_dir *child = NULL;
	struct ntfs_dt *dt = NULL;
	BOOL result = FALSE;

	if (!vol || !pathname || !found) {
		errno = EINVAL;
		return FALSE;
	}

	memset (found, 0, sizeof (*found));

	if (parent) {
		dir = parent;
	} else {
		dt = (struct ntfs_dt *) vol->private_data;
		if (dt)
			dir = dt->dir;
		if (!dir) {
			Eprintf ("Couldn't open the inode of the root directory.\n");
			goto close;
		}
	}

	unicode = malloc (MAX_PATH * sizeof (ntfschar));
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

		//printf ("looking for %s\n", p);
		if (q) {
			child = ntfs_dir_find2 (dir, unicode, len);
			if (!child) {
				printf ("can't find %s in %s\n", p, pathname);
				break;
			}
		} else {
			printf ("file: %s\n", p);
			break;
		}

		dir   = child;
		child = NULL;
		p = q;
		while (p && *p && *p == PATH_SEP)
			p++;
	}

	found->dir = dir;
	result = TRUE;
close:
	free (ascii);
	free (unicode);
	return result;
}


/**
 * ntfs_mft_resize_resident
 */
static int ntfs_mft_resize_resident (ntfs_inode *inode, ATTR_TYPES type, ntfschar *name, int name_len, u8 *data, int data_len)
{
	int mft_size;
	int mft_usage;
	int mft_free;
	int attr_orig;
	int attr_new;
	u8 *src;
	u8 *dst;
	u8 *end;
	int len;
	ntfs_attr_search_ctx *ctx = NULL;
	ATTR_RECORD *arec = NULL;
	MFT_RECORD *mrec = NULL;
	int res = -1;

	if ((!inode) || (!inode->mrec))
		return -1;
	if ((!data) || (data_len < 0))
		return -1;

	mrec = inode->mrec;

	mft_size  = mrec->bytes_allocated;
	mft_usage = mrec->bytes_in_use;
	mft_free  = mft_size - mft_usage;

	//printf ("mft_size  = %d\n", mft_size);
	//printf ("mft_usage = %d\n", mft_usage);
	//printf ("mft_free  = %d\n", mft_free);
	//printf ("\n");

	ctx = ntfs_attr_get_search_ctx (NULL, mrec);
	if (!ctx)
		goto done;

	if (ntfs_attr_lookup(type, name, name_len, CASE_SENSITIVE, 0, NULL, 0, ctx) != 0)
		goto done;

	arec = ctx->attr;

	if (arec->non_resident) {
		printf ("attribute isn't resident\n");
		goto done;
	}

	attr_orig = arec->value_length;
	attr_new  = data_len;

	//printf ("attr orig = %d\n", attr_orig);
	//printf ("attr new  = %d\n", attr_new);
	//printf ("\n");

	if ((attr_new - attr_orig + mft_usage) > mft_size) {
		printf ("attribute won't fit into mft record\n");
		goto done;
	}

	//printf ("new free space = %d\n", mft_size - (attr_new - attr_orig + mft_usage));

	src = (u8*)arec + arec->length;
	dst = src + (attr_new - attr_orig);
	end = (u8*)mrec + mft_usage;
	len  = end - src;

	//printf ("src = %d\n", src - (u8*)mrec);
	//printf ("dst = %d\n", dst - (u8*)mrec);
	//printf ("end = %d\n", end - (u8*)mrec);
	//printf ("len = %d\n", len);

	if (src != dst)
		memmove (dst, src, len);

	memcpy ((u8*)arec + arec->value_offset, data, data_len);

	mrec->bytes_in_use += (attr_new - attr_orig);
	arec->length       += (attr_new - attr_orig);
	arec->value_length += (attr_new - attr_orig);

	memset ((u8*)mrec + mrec->bytes_in_use, 0, mft_size - mrec->bytes_in_use);

	mft_usage += (attr_new - attr_orig);
	//utils_dump_mem ((u8*) mrec, 0, mft_size, DM_DEFAULTS);
	res = 0;
done:
	ntfs_attr_put_search_ctx (ctx);
	return res;
}

/**
 * ntfs_mft_free_space
 */
static int ntfs_mft_free_space (struct ntfs_dir *dir)
{
	int res = 0;
	MFT_RECORD *mft;

	if ((!dir) || (!dir->inode))
		return -1;

	mft = (MFT_RECORD*) dir->inode->mrec;

	res = mft->bytes_allocated - mft->bytes_in_use;

	return res;
}


/**
 * ntfs_dt_root_replace
 */
static int ntfs_dt_root_replace (struct ntfs_dt *del, int del_num, INDEX_ENTRY *del_ie, INDEX_ENTRY *suc_ie)
{
	u8 *src;
	u8 *dst;
	u8 *attr;
	int len;
	int i;

	if (!del || !del_ie || !suc_ie)
		return FALSE;

	//utils_dump_mem (del->data, 0, del->data_len, DM_DEFAULTS);
	//printf ("\n");

	attr = malloc (del->data_len + suc_ie->length - del_ie->length);

	dst = attr;
	src = del->data;
	len = (u8*) del_ie - del->data;

	memcpy (dst, src, len);

	dst += len;
	src = (u8*) suc_ie;
	len = suc_ie->length;

	memcpy (dst, src, len);

	dst += len;
	src = (u8*) del_ie + del_ie->length;
	len = del->data_len + (del->data - (u8*) del_ie) - del_ie->length;

	memcpy (dst, src, len);

	src = (u8*) del->data;
	dst = attr;

	len = del->data_len + suc_ie->length - del_ie->length;
	free (del->data);
	del->data = attr;
	del->data_len = len;

	ntfs_mft_resize_resident (del->dir->inode, AT_INDEX_ROOT, I30, 4, del->data, del->data_len);

	//utils_dump_mem (attr, 0, del->data_len, DM_DEFAULTS);

	//printf ("\n");
	//printf (BOLD YELLOW "Adjust children\n" END);
	//for (i = 0; i < del->child_count; i++)
	//	printf ("\tChild %d %p %d\n", i, del->children[i], del->children[i]->flags);
	//printf ("\n");

	len = suc_ie->length - del_ie->length;
	//printf ("src = %p, dst = %p, len = %d\n", src, dst, len); fflush (stdout);

	for (i = 0; i < del->child_count; i++)
		del->children[i] = (INDEX_ENTRY*) (dst + ((u8*) del->children[i] - src));

	for (i = del_num+1; i < del->child_count; i++)
		del->children[i] = (INDEX_ENTRY*) ((u8*) del->children[i] + len);

	//for (i = 0; i < del->child_count; i++)
	//	printf ("\tChild %d %p %d\n", i, del->children[i], del->children[i]->flags);
	//printf ("\n");

	//utils_dump_mem (del->data, 0, del->data_len, DM_DEFAULTS);
	//printf ("\n");

	printf (GREEN "Modified: inode %lld, $INDEX_ROOT\n" END, del->dir->inode->mft_no);
	return TRUE;
}

/**
 * ntfs_dt_alloc_replace
 */
static BOOL ntfs_dt_alloc_replace (struct ntfs_dt *del, int del_num, INDEX_ENTRY *del_ie, INDEX_ENTRY *suc_ie)
{
	u8 *src;
	u8 *dst;
	int len;
	int i;

	if (!del || !del_ie || !suc_ie)
		return FALSE;

	//utils_dump_mem (del->data, 0, del->data_len, DM_DEFAULTS);

	src = (u8*) del_ie + del_ie->length;
	dst = (u8*) del_ie + suc_ie->length;
	len = del->header->index_length + 24 + (del->data - src);
	//printf ("src = %d\n", src - del->data);
	//printf ("dst = %d\n", dst - del->data);
	//printf ("len = %d\n", len);

	if (src != dst)
		memmove (dst, src, len);

	src = (u8*) suc_ie;
	dst = (u8*) del_ie;
	len = suc_ie->length;

	memcpy (dst, src, len);

	//utils_dump_mem (del->data, 0, del->data_len, DM_DEFAULTS);

	del->header->index_length += suc_ie->length - del_ie->length;

	dst = del->data + del->header->index_length + 24;
	len = del->data_len - del->header->index_length - 24;

	memset (dst, 0, len);

	//for (i = 0; i < del->child_count; i++)
	//	printf ("Child %d %p\n", i, del->children[i]);
	//printf ("\n");

	len = suc_ie->length - del_ie->length;
	//printf ("len = %d\n", len);

	for (i = del_num+1; i < del->child_count; i++)
		del->children[i] = (INDEX_ENTRY*) ((u8*) del->children[i] + len);

	//for (i = 0; i < del->child_count; i++)
	//	printf ("Child %d %p\n", i, del->children[i]);
	//printf ("\n");

	//utils_dump_mem (del->data, 0, del->data_len, DM_DEFAULTS);

	printf (GREEN "Modified: inode %lld, $INDEX_ALLOCATION vcn %lld-%lld\n" END, del->dir->inode->mft_no, del->vcn, del->vcn + (del->dir->index_size>>9) - 1);
	return TRUE;
}

/**
 * ntfs_dt_root_remove
 */
static BOOL ntfs_dt_root_remove (struct ntfs_dt *del, int del_num)
{
	INDEX_ENTRY *del_ie = NULL;
	u8 *src;
	u8 *dst;
	u8 *old;
	int len;
	int del_len;
	int i;
	//int off;

	if (!del)
		return FALSE;

	//utils_dump_mem (del->data, 0, del->header->index_length+16, DM_RED);
	//printf ("\n");

#if 0
	off = (u8*) del->children[0] - del->data;
	for (i = 0; i < del->child_count; i++) {
		del_ie = del->children[i];

		printf ("%2d  %4d ", i+1, off);
		off += del_ie->length;

		if (del_ie->flags & INDEX_ENTRY_END) {
			printf ("END (%d)\n", del_ie->length);
			break;
		}

		ntfs_name_print (del_ie->key.file_name.file_name, del_ie->key.file_name.file_name_length);
		printf (" (%d)\n", del_ie->length);
	}
	printf ("total = %d\n", off);
#endif

	del_ie  = del->children[del_num];
	del_len = del_ie->length;

	src = (u8*) del_ie + del_len;
	dst = (u8*) del_ie;
	len = del->header->index_length + 16 - (src - del->data);

	//printf ("src = %d\n", src - del->data);
	//printf ("dst = %d\n", dst - del->data);
	//printf ("len = %d\n", len);

	memmove (dst, src, len);

	del->data_len -= del_len;
	del->child_count--;

	del->header->index_length   = del->data_len - 16;
	del->header->allocated_size = del->data_len - 16;

	ntfs_mft_resize_resident (del->dir->inode, AT_INDEX_ROOT, I30, 4, del->data, del->data_len);
	old = del->data;
	del->data = realloc (del->data, del->data_len);
	del->header = (INDEX_HEADER*) (del->data + 0x10);

	del->header->index_length   -= del_len;
	del->header->allocated_size -= del_len;

	//utils_dump_mem (del->data, 0, del->data_len, DM_GREEN | DM_RED);

	src = (u8*) (&del->children[del_num+1]);
	dst = (u8*) (&del->children[del_num]);
	len = (del->child_count - del_num) * sizeof (INDEX_ENTRY*);

	//printf ("src = %d\n", src - (u8*) del->children);
	//printf ("dst = %d\n", dst - (u8*) del->children);
	//printf ("len = %d\n", len);

	memmove (dst, src, len);

	src = (u8*) (&del->sub_nodes[del_num+1]);
	dst = (u8*) (&del->sub_nodes[del_num]);
	len = (del->child_count - del_num) * sizeof (struct ntfs_dt*);

	//printf ("src = %d\n", src - (u8*) del->children);
	//printf ("dst = %d\n", dst - (u8*) del->children);
	//printf ("len = %d\n", len);

	memmove (dst, src, len);

	//printf ("del_num = %d\n", del_num);
	for (i = 0; i < del->child_count; i++)
		del->children[i] = (INDEX_ENTRY*) ((u8*) del->children[i] - old + del->data);
	for (i = del_num; i < del->child_count; i++)
		del->children[i] = (INDEX_ENTRY*) ((u8*) del->children[i] - del_len);

	if (!ntfs_dt_alloc_children2 (del, del->child_count))
		return FALSE;

#if 0
	off = (u8*) del->children[0] - del->data;
	for (i = 0; i < del->child_count; i++) {
		del_ie = del->children[i];

		printf ("%2d  %4d ", i+1, off);
		off += del_len;

		if (del_ie->flags & INDEX_ENTRY_END) {
			printf ("END (%d)\n", del_len);
			break;
		}

		ntfs_name_print (del_ie->key.file_name.file_name, del_ie->key.file_name.file_name_length);
		printf (" (%d)\n", del_len);
	}
	printf ("total = %d\n", off);
#endif

	//utils_dump_mem (del->data, 0, del->header->index_length+16, DM_DEFAULTS);

	del->changed = TRUE;
	printf (GREEN "Modified: inode %lld, $INDEX_ROOT\n" END, del->dir->inode->mft_no);
	return TRUE;
}

/**
 * ntfs_dt_alloc_remove
 */
static BOOL ntfs_dt_alloc_remove (struct ntfs_dt *del, int del_num)
{
	INDEX_ENTRY *del_ie = NULL;
	u8 *dst;
	u8 *src;
	int len;
	int i;
	//int off;

	if (!del)
		return FALSE;

#if 0
	off = (u8*)del->children[0] - del->data;
	for (i = 0; i < del->child_count; i++) {
		del_ie = del->children[i];

		printf ("%2d  %4d ", i, off);
		off += del_ie->length;

		if (del_ie->flags & INDEX_ENTRY_END) {
			printf ("END (%d)\n", del_ie->length);
			break;
		}

		ntfs_name_print (del_ie->key.file_name.file_name, del_ie->key.file_name.file_name_length);
		printf (" (%d)\n", del_ie->length);
	}
	printf ("total = %d\n", off);
	printf ("\n");
#endif

	//utils_dump_mem (del->data, 0, del->data_len, DM_DEFAULTS);
	//printf ("\n");

	del_ie = del->children[del_num];

	src = (u8*) del_ie + del_ie->length;
	dst = (u8*) del_ie;
	len = del->header->index_length + 24 - (src - del->data);

	//printf ("src = %d\n", src - del->data);
	//printf ("dst = %d\n", dst - del->data);
	//printf ("len = %d\n", len);

	memmove (dst, src, len);

	del->header->index_length -= src - dst;
	del->child_count--;

	dst += len;
	len = del->data_len - del->header->index_length - 24;

	//printf ("dst = %d\n", dst - del->data);
	//printf ("len = %d\n", len);

	memset (dst, 0, len);

	src = (u8*) (&del->children[del_num+1]);
	dst = (u8*) (&del->children[del_num]);
	len = (del->child_count - del_num) * sizeof (INDEX_ENTRY*);

	//printf ("src = %d\n", src - (u8*) del->children);
	//printf ("dst = %d\n", dst - (u8*) del->children);
	//printf ("len = %d\n", len);

	memmove (dst, src, len);

	src = (u8*) (&del->sub_nodes[del_num+1]);
	dst = (u8*) (&del->sub_nodes[del_num]);
	len = (del->child_count - del_num) * sizeof (struct ntfs_dt*);

	//printf ("src = %d\n", src - (u8*) del->children);
	//printf ("dst = %d\n", dst - (u8*) del->children);
	//printf ("len = %d\n", len);

	memmove (dst, src, len);

	//printf ("del_num = %d\n", del_num);
	for (i = del_num; i < del->child_count; i++)
		del->children[i] = (INDEX_ENTRY*) ((u8*) del->children[i] - del_ie->length);

	if (!ntfs_dt_alloc_children2 (del, del->child_count))
		return FALSE;

	//utils_dump_mem (del->data, 0, del->data_len, DM_DEFAULTS);

#if 0
	off = (u8*)del->children[0] - del->data;
	for (i = 0; i < del->child_count; i++) {
		del_ie = del->children[i];

		printf ("%2d  %4d ", i, off);
		off += del_ie->length;

		if (del_ie->flags & INDEX_ENTRY_END) {
			printf ("END (%d)\n", del_ie->length);
			break;
		}

		ntfs_name_print (del_ie->key.file_name.file_name, del_ie->key.file_name.file_name_length);
		printf (" (%d)\n", del_ie->length);
	}
	printf ("total = %d\n", off);
	printf ("\n");
#endif

	del->changed = TRUE;
	printf (GREEN "Modified: inode %lld, $INDEX_ALLOCATION vcn %lld-%lld\n" END, del->dir->inode->mft_no, del->vcn, del->vcn + (del->dir->index_size>>9) - 1);
	return TRUE;
}

/**
 * ntfs_dt_root_add
 */
static int ntfs_dt_root_add (struct ntfs_dt *add, INDEX_ENTRY *add_ie)
{
	FILE_NAME_ATTR *file;
	struct ntfs_dt *suc;
	int suc_num;
	int need;
	int space;
	u8 *attr;
	u8 *src;
	u8 *dst;
	int len;

	if (!add || !add_ie)
		return 0;

	//utils_dump_mem (add->data, 0, add->data_len, DM_DEFAULTS);
	//printf ("\n");

	need  = add_ie->length;
	space = ntfs_mft_free_space (add->dir);

	file = &add_ie->key.file_name;

	suc = ntfs_dt_find3 (add, file->file_name, file->file_name_length, &suc_num);
	if (!suc)
		return 0;

	// hmm, suc == add

	printf ("need %d, have %d\n", need, space);
	if (need > space) {
		printf ("no room");
		return 0;
	}

	attr = malloc (add->data_len + need);

	src = add->data;
	dst = attr;
	len = add->header->entries_offset + 16;

	memcpy (dst, src, len);

	dst += len;
	src = (u8*) add_ie;
	len = add_ie->length;

	memcpy (dst, src, len);

	dst += len;
	src = (u8*) suc->children[suc_num];
	len = add->data + add->data_len - src;

	memcpy (dst, src, len);

	free (add->data);
	add->data = attr;
	add->data_len += need;

	add->header->index_length   = add->data_len - 16;
	add->header->allocated_size = add->data_len - 16;

	ntfs_mft_resize_resident (add->dir->inode, AT_INDEX_ROOT, I30, 4, add->data, add->data_len);

	//utils_dump_mem (add->data, 0, add->data_len, DM_DEFAULTS);
	//printf ("\n");

	printf (GREEN "Modified: inode %lld, $INDEX_ROOT\n" END, add->dir->inode->mft_no);
	return 0;
}

/**
 * ntfs_dt_alloc_add
 */
static int ntfs_dt_alloc_add (struct ntfs_dt *add, INDEX_ENTRY *add_ie)
{
	FILE_NAME_ATTR *file;
	struct ntfs_dt *suc_dt;
	int suc_num;
	int need;
	int space;
	u8 *src;
	u8 *dst;
	int len;

	if (!add || !add_ie)
		return 0;

	need  = add_ie->length;
	space = add->data_len - add->header->index_length - 24;

	file = &add_ie->key.file_name;

	suc_dt = ntfs_dt_find3 (add, file->file_name, file->file_name_length, &suc_num);
	if (!suc_dt)
		return 0;

	// hmm, suc_dt == add

	printf ("need %d, have %d\n", need, space);
	if (need > space) {
		printf ("no room");
		return 0;
	}

	//utils_dump_mem (add->data, 0, add->data_len, DM_DEFAULTS);
	//printf ("\n");

	src = (u8*) suc_dt->children[suc_num];
	dst = src + need;
	len = add->data + add->data_len - src - space;
	//printf ("src = %d\n", src - add->data);
	//printf ("dst = %d\n", dst - add->data);
	//printf ("len = %d\n", len);

	memmove (dst, src, len);

	dst = src;
	src = (u8*) add_ie;
	len = need;

	memcpy (dst, src, len);

	add->header->index_length += len;

	dst = add->data     + add->header->index_length + 24;
	len = add->data_len - add->header->index_length - 24;

	memset (dst, 0, len);

	//utils_dump_mem (add->data, 0, add->data_len, DM_DEFAULTS);
	//printf ("\n");

	printf (GREEN "Modified: inode %lld, $INDEX_ALLOCATION vcn %lld-%lld\n" END, add->dir->inode->mft_no, add->vcn, add->vcn + (add->dir->index_size>>9) - 1);
	return 0;
}

/**
 * ntfs_dt_remove_alloc
 */
static int ntfs_dt_remove_alloc (struct ntfs_dt *dt, int index_num)
{
	INDEX_ENTRY *ie = NULL;
	int i;
	u8 *dst;
	u8 *src;
	u8 *end;
	int off;
	int len;
	s64 res;

	//printf ("removing entry %d of %d\n", index_num+1, dt->child_count);
	//printf ("index size = %d\n", dt->data_len);
	//printf ("index use  = %d\n", dt->header->index_length);

	//utils_dump_mem (dt->data, 0, dt->data_len, DM_DEFAULTS);

	off = (u8*)dt->children[0] - dt->data;
	for (i = 0; i < dt->child_count; i++) {
		ie = dt->children[i];

		//printf ("%2d  %4d ", i, off);
		off += ie->length;

		if (ie->flags & INDEX_ENTRY_END) {
			//printf ("END (%d)\n", ie->length);
			break;
		}

		//ntfs_name_print (ie->key.file_name.file_name, ie->key.file_name.file_name_length);
		//printf (" (%d)\n", ie->length);
	}
	//printf ("total = %d\n", off);

	ie = dt->children[index_num];
	dst = (u8*)ie;

	src  = dst + ie->length;

	ie = dt->children[dt->child_count-1];
	end = (u8*)ie + ie->length;

	len  = end - src;

	//printf ("move %d bytes\n", len);
	//printf ("%d, %d, %d\n", dst - dt->data, src - dt->data, len);
	memmove (dst, src, len);

	//printf ("clear %d bytes\n", dt->data_len - (dst - dt->data) - len);
	//printf ("%d, %d, %d\n", dst - dt->data + len, 0, dt->data_len - (dst - dt->data) - len);

	//ntfs_dt_print (dt->dir->index, 0);

	memset (dst + len, 0, dt->data_len - (dst - dt->data) - len);

	for (i = 0; i < dt->child_count; i++) {
		if (dt->sub_nodes[i]) {
			printf ("this shouldn't happen %p\n", dt->sub_nodes[i]);
			ntfs_dt_free (dt->sub_nodes[i]);	// shouldn't be any, yet
		}
	}

	free (dt->sub_nodes);
	dt->sub_nodes = NULL;
	free (dt->children);
	dt->children = NULL;
	dt->child_count = 0;

	//printf ("before = %d\n", dt->header->index_length + 24);
	dt->header->index_length -= src - dst;
	//printf ("after  = %d\n", dt->header->index_length + 24);

	ntfs_dt_count_alloc (dt);

	//utils_dump_mem (dt->data, 0, dt->data_len, DM_DEFAULTS);

#if 0
	//printf ("\n");
	//printf ("index size = %d\n", dt->data_len);
	//printf ("index use  = %d\n", dt->header.index_length);

	off = (u8*)dt->children[0] - dt->data;
	for (i = 0; i < dt->child_count; i++) {
		ie = dt->children[i];

		printf ("%2d  %4d ", i, off);
		off += ie->length;

		if (ie->flags & INDEX_ENTRY_END) {
			printf ("END (%d)\n", ie->length);
			break;
		}

		ntfs_name_print (ie->key.file_name.file_name,
				 ie->key.file_name.file_name_length);
		printf (" (%d)\n", ie->length);
	}
#endif
	//utils_dump_mem (dt->data, 0, dt->data_len, DM_DEFAULTS);
	res = ntfs_attr_mst_pwrite (dt->dir->ialloc, dt->vcn*512, 1, dt->data_len, dt->data);
	printf ("res = %lld\n", res);

	return 0;
}

/**
 * ntfs_dt_remove_root
 */
static int ntfs_dt_remove_root (struct ntfs_dt *dt, int index_num)
{
	INDEX_ENTRY *ie = NULL;
	INDEX_ROOT *ir = NULL;
	int i;
	u8 *dst;
	u8 *src;
	u8 *end;
	int off;
	int len;
	s64 res;

	//printf ("removing entry %d of %d\n", index_num+1, dt->child_count);
	//printf ("index size = %d\n", dt->data_len);
	//printf ("index use  = %d\n", dt->header->index_length);

	//utils_dump_mem (dt->data, 0, dt->data_len, DM_DEFAULTS);

	off = (u8*)dt->children[0] - dt->data;
	for (i = 0; i < dt->child_count; i++) {
		ie = dt->children[i];

		//printf ("%2d  %4d ", i+1, off);
		off += ie->length;

		if (ie->flags & INDEX_ENTRY_END) {
			//printf ("END (%d)\n", ie->length);
			break;
		}

		//ntfs_name_print (ie->key.file_name.file_name, ie->key.file_name.file_name_length);
		//printf (" (%d)\n", ie->length);
	}
	//printf ("total = %d\n", off);

	ie = dt->children[index_num];
	dst = (u8*)ie;

	src  = dst + ie->length;

	ie = dt->children[dt->child_count-1];
	end = (u8*)ie + ie->length;

	len  = end - src;

	//printf ("move %d bytes\n", len);
	//printf ("%d, %d, %d\n", dst - dt->data, src - dt->data, len);
	memmove (dst, src, len);

	dt->data_len -= (src - dt->data - sizeof (INDEX_ROOT));
	dt->child_count--;

	ir = (INDEX_ROOT*) dt->data;
	ir->index.index_length   = dt->data_len - 16;
	ir->index.allocated_size = dt->data_len - 16;

	ntfs_mft_resize_resident (dt->dir->inode, AT_INDEX_ROOT, I30, 4, dt->data, dt->data_len);
	dt->data = realloc (dt->data, dt->data_len);

	//printf ("ih->index_length   = %d\n", ir->index.index_length);
	//printf ("ih->allocated_size = %d\n", ir->index.allocated_size);
	//printf ("dt->data_len       = %d\n", dt->data_len);

	//utils_dump_mem (dt->data, 0, dt->data_len, DM_DEFAULTS);
	//ntfs_dt_print (dt->dir->index, 0);
#if 1
	for (i = 0; i < dt->child_count; i++) {
		if (dt->sub_nodes[i]) {
			printf ("this shouldn't happen %p\n", dt->sub_nodes[i]);
			ntfs_dt_free (dt->sub_nodes[i]);	// shouldn't be any, yet
		}
	}

	free (dt->sub_nodes);
	dt->sub_nodes = NULL;
	free (dt->children);
	dt->children = NULL;
	dt->child_count = 0;

	//printf ("before = %d\n", dt->header->index_length + 24);
	dt->header->index_length -= src - dst;
	//printf ("after  = %d\n", dt->header->index_length + 24);

	ntfs_dt_count_root (dt);
#endif
	//utils_dump_mem (dt->data, 0, dt->data_len, DM_DEFAULTS);

#if 0
	//printf ("\n");
	//printf ("index size = %d\n", dt->data_len);
	//printf ("index use  = %d\n", dt->header.index_length);

	off = (u8*)dt->children[0] - dt->data;
	for (i = 0; i < dt->child_count; i++) {
		ie = dt->children[i];

		printf ("%2d  %4d ", i, off);
		off += ie->length;

		if (ie->flags & INDEX_ENTRY_END) {
			printf ("END (%d)\n", ie->length);
			break;
		}

		ntfs_name_print (ie->key.file_name.file_name,
				 ie->key.file_name.file_name_length);
		printf (" (%d)\n", ie->length);
	}
#endif
	//utils_dump_mem (dt->data, 0, dt->data_len, DM_DEFAULTS);

	res = ntfs_mft_record_write (dt->dir->inode->vol, dt->dir->inode->mft_no, dt->dir->inode->mrec);
	printf ("res = %lld\n", res);

	return 0;
}

/**
 * ntfs_dt_remove
 */
static int ntfs_dt_remove (struct ntfs_dt *dt, int index_num)
{
	if (!dt)
		return 1;
	if ((index_num < 0) || (index_num >= dt->child_count))
		return 1;

	if (ntfs_dt_root (dt))
		return ntfs_dt_remove_root (dt, index_num);
	else
		return ntfs_dt_remove_alloc (dt, index_num);
}

/**
 * ntfs_dt_del_child
 */
static int ntfs_dt_del_child (struct ntfs_dt *dt, ntfschar *uname, int len)
{
	struct ntfs_dt *del;
	INDEX_ENTRY *ie;
	ntfs_inode *ichild = NULL;
	ntfs_inode *iparent = NULL;
	ntfs_attr *attr = NULL;
	ntfs_attr_search_ctx *ctx = NULL;
	int index_num = 0;
	int res = 1;
	ATTR_RECORD *arec = NULL;
	MFT_REF mft_num = -1;
	FILE_NAME_ATTR *file;
	int filenames = 0;

	// compressed & encrypted files?

	del = ntfs_dt_find2 (dt, uname, len, &index_num);
	if (!del) {
		printf ("can't find item to delete\n");
		goto close;
	}

	if ((index_num < 0) || (index_num >= del->child_count)) {
		printf ("error in dt_find\n");
		goto close;
	}

	if (del->header->flags & INDEX_NODE) {
		printf ("can only delete leaf nodes\n");
		goto close;
	}

	/*
	if (!del->parent) {
		printf ("has 0xA0, but isn't in use\n");
		goto close;
	}
	*/

	ie = del->children[index_num];
	if (ie->key.file_name.file_attributes & FILE_ATTR_DIRECTORY) {
		printf ("can't delete directories\n");
		goto close;
	}

	if (ie->key.file_name.file_attributes & FILE_ATTR_SYSTEM) {
		printf ("can't delete system files\n");
		goto close;
	}

	ichild = ntfs_inode_open2 (dt->dir->vol, MREF (ie->indexed_file));
	if (!ichild) {
		printf ("can't open inode\n");
		goto close;
	}

	ctx = ntfs_attr_get_search_ctx (NULL, ichild->mrec);
	if (!ctx) {
		printf ("can't create a search context\n");
		goto close;
	}

	while (ntfs_attr_lookup(AT_UNUSED, NULL, 0, 0, 0, NULL, 0, ctx) == 0) {
		arec = ctx->attr;
		if (arec->type == AT_ATTRIBUTE_LIST) {
			printf ("can't delete files with an attribute list\n");
			goto close;
		}
		if (arec->type == AT_INDEX_ROOT) {
			printf ("can't delete directories\n");
			goto close;
		}
		if (arec->type == AT_FILE_NAME) {
			filenames++;
			file = (FILE_NAME_ATTR*) ((u8*) arec + arec->value_offset);
			mft_num = MREF (file->parent_directory);
		}
	}

	if (filenames != 1) {
		printf ("file has more than one name\n");
		goto close;
	}

	iparent = ntfs_inode_open2 (dt->dir->vol, mft_num);
	if (!iparent) {
		printf ("can't open parent directory\n");
		goto close;
	}

	/*
	attr = ntfs_attr_open (iparent, AT_INDEX_ALLOCATION, I30, 4);
	if (!attr) {
		printf ("parent doesn't have 0xA0\n");
		goto close;
	}
	*/

	//printf ("deleting file\n");
	//ntfs_dt_print (del->dir->index, 0);

	if (1) res = utils_free_non_residents (ichild);
	if (1) res = utils_mftrec_mark_free (dt->dir->vol, del->children[index_num]->indexed_file);
	if (1) res = utils_mftrec_mark_free2 (dt->dir->vol, del->children[index_num]->indexed_file);
	if (1) res = ntfs_dt_remove (del, index_num);

close:
	ntfs_attr_put_search_ctx (ctx);
	ntfs_attr_close (attr);
	ntfs_inode_close2 (iparent);
	ntfs_inode_close2 (ichild);

	return res;
}

/**
 * ntfs_dt_add_alloc
 */
static int ntfs_dt_add_alloc (struct ntfs_dt *parent, int index_num, INDEX_ENTRY *ie, struct ntfs_dt *child)
{
	INDEX_BLOCK *block;
	INDEX_ENTRY *entry;
	int need;
	int space;
	u8 *src;
	u8 *dst;
	int len;

	if (!parent || !ie)
		return 0;

	block = (INDEX_BLOCK*) parent->data;

	need  = ie->length;
	space = parent->data_len - block->index.index_length - 24;

	printf ("need %d, have %d\n", need, space);
	if (need > space) {
		printf ("no room");
		return 0;
	}

	//utils_dump_mem (parent->data, 0, parent->data_len, DM_DEFAULTS);
	//printf ("\n");

	src = (u8*) parent->children[index_num];
	dst = src + need;
	len = parent->data + parent->data_len - src - space;
	//printf ("src = %d\n", src - parent->data);
	//printf ("dst = %d\n", dst - parent->data);
	//printf ("len = %d\n", len);

	memmove (dst, src, len);

	dst = src;
	src = (u8*) ie;
	len = need;

	memcpy (dst, src, len);

	block->index.index_length += len;

	dst = parent->data + block->index.index_length + 24;
	len = parent->data_len - block->index.index_length - 24;

	memset (dst, 0, len);

	//realloc children, sub_nodes
	ntfs_dt_alloc_children2 (parent, parent->child_count + 1);

	// regen children pointers
	parent->child_count = 0;

	src = parent->data     + 0x18 + parent->header->entries_offset;
	len = parent->data_len - 0x18 - parent->header->entries_offset;

	while (src < (parent->data + parent->data_len)) {
		entry = (INDEX_ENTRY*) src;

		parent->children[parent->child_count] = entry;
		parent->child_count++;

		if (entry->flags & INDEX_ENTRY_END)
			break;

		src += entry->length;
	}
	printf ("count = %d\n", parent->child_count);

	src = (u8*) &parent->sub_nodes[index_num+parent->child_count-1];
	dst = (u8*) &parent->sub_nodes[index_num];
	len = (parent->child_count - index_num - 1) * sizeof (struct ntfs_dt*);

	memmove (dst, src, len);

	//insert sub_node pointer
	parent->sub_nodes[index_num] = child;

	//utils_dump_mem (parent->data, 0, parent->data_len, DM_DEFAULTS);
	//printf ("\n");
	return 0;
}

/**
 * ntfs_dt_add_root
 */
static int ntfs_dt_add_root (struct ntfs_dt *parent, int index_num, INDEX_ENTRY *ie, struct ntfs_dt *child)
{
	INDEX_ROOT *root;
	INDEX_ENTRY *entry;
	int need;
	int space;
	u8 *attr;
	u8 *src;
	u8 *dst;
	int len;

	if (!parent || !ie)
		return 0;

	root = (INDEX_ROOT*) parent->data;

	utils_dump_mem (parent->data, 0, parent->data_len, DM_DEFAULTS);
	printf ("\n");

	need  = ie->length;
	space = ntfs_mft_free_space (parent->dir);

	printf ("need %d, have %d\n", need, space);
	if (need > space) {
		printf ("no room");
		return 0;
	}

	attr = malloc (parent->data_len + need);

	src = parent->data;
	dst = attr;
	len = root->index.entries_offset + 16;

	memcpy (dst, src, len);

	dst += len;
	src = (u8*) ie;
	len = ie->length;

	memcpy (dst, src, len);

	dst += len;
	src = (u8*) parent->children[index_num];
	len = parent->data + parent->data_len - src;

	memcpy (dst, src, len);

	free (parent->data);
	parent->data = attr;
	parent->data_len += need;

	root = (INDEX_ROOT*) parent->data;
	root->index.index_length   = parent->data_len - 16;
	root->index.allocated_size = parent->data_len - 16;

	utils_dump_mem (parent->data, 0, parent->data_len, DM_DEFAULTS);
	printf ("\n");

	ntfs_mft_resize_resident (parent->dir->inode, AT_INDEX_ROOT, I30, 4, parent->data, parent->data_len);

	//realloc children, sub_nodes
	ntfs_dt_alloc_children2 (parent, parent->child_count + 1);

	// regen children pointers
	parent->child_count = 0;

	src = parent->data     + 0x18 + parent->header->entries_offset;
	len = parent->data_len - 0x18 - parent->header->entries_offset;

	while (src < (parent->data + parent->data_len)) {
		entry = (INDEX_ENTRY*) src;

		parent->children[parent->child_count] = entry;
		parent->child_count++;

		if (entry->flags & INDEX_ENTRY_END)
			break;

		src += entry->length;
	}
	printf ("count = %d\n", parent->child_count);

	src = (u8*) &parent->sub_nodes[index_num+parent->child_count-1];
	dst = (u8*) &parent->sub_nodes[index_num];
	len = (parent->child_count - index_num - 1) * sizeof (struct ntfs_dt*);

	memmove (dst, src, len);

	//insert sub_node pointer
	parent->sub_nodes[index_num] = child;

	return 0;
}

/**
 * ntfs_dt_add
 */
static int ntfs_dt_add (struct ntfs_dt *parent, INDEX_ENTRY *ie)
{
	FILE_NAME_ATTR *file;
	struct ntfs_dt *dt;
	int index_num = -1;

	if (!ie)
		return 0;

	file = &ie->key.file_name;

	dt = ntfs_dt_find3 (parent, file->file_name, file->file_name_length, &index_num);
	if (!dt)
		return 0;

	//printf ("dt = %p, index = %d\n", dt, index_num);
	//ntfs_ie_dump (dt->children[index_num]);
	//utils_dump_mem ((u8*)dt->children[index_num], 0, dt->children[index_num]->length, DM_DEFAULTS);
	//printf ("\n");

	if (0) ntfs_dt_add_alloc (dt, index_num, ie, NULL);
	if (0) ntfs_dt_add_root (dt->dir->index, 0, ie, NULL);

	return 0;
}

/**
 * ntfs_dt_add2
 */
static int ntfs_dt_add2 (INDEX_ENTRY *ie, struct ntfs_dt *suc, int suc_num, struct ntfs_dt *ded)
{
	int need;
	int space;
	int median;
	struct ntfs_dt *new = NULL;
	struct ntfs_dt *chl;
	INDEX_ENTRY *med_ie;
	FILE_NAME_ATTR *file;
	VCN vcn = 0;
	//int i;

	if (!ie || !suc)
		return -1;

	printf ("\n");
	printf (BOLD YELLOW "Add key to leaf\n" END);

	//utils_dump_mem (suc->data, 0, suc->data_len, DM_DEFAULTS);

	chl = NULL;
ascend:
	//XXX replace with while/break?

#if 0
	for (; ded; ded = ded->sub_nodes[0]) {
		printf ("\tded vcn = %lld\n", ded->vcn);
	}
#endif

	/*
	 * ADD
	 * room in current node?
	 *   yes, add, done
	 *   no, split, ascend
	 */
	need = ie->length;

	if (ntfs_dt_root (suc))
		space = ntfs_dt_freespace_root (suc);
	else
		space = ntfs_dt_freespace_alloc (suc);

	printf ("\tneed %d\n", need);
	printf ("\tspace %d\n", space);

	if (space >= need) {
		if (ntfs_dt_root (suc))
			ntfs_dt_add_root (suc, suc_num, ie, chl);
		else
			ntfs_dt_add_alloc (suc, suc_num, ie, chl);
		goto done;
	}

	/*
	 * SPLIT
	 * any dead?
	 *   yes reuse
	 *   no alloc
	 */
	if (ded) {
		new = ded;
		vcn = ded->vcn;
		ded = ded->sub_nodes[0];
		printf ("\treusing vcn %lld\n", new->vcn);
	} else {
		/*
		 * ALLOC
		 * any unused records?
		 *   yes, enable first
		 *   no, extend
		 */
		/*
		 * ENABLE
		 * modify bitmap
		 * init indx record
		 */
		/*
		 * EXTEND
		 * room in bitmap
		 *   yes, do nothing
		 *   no, extend bitmap
		 * extend alloc
		 */
		/*
		 * EXTEND BITMAP
		 * extend bitmap
		 * init bitmap
		 */
	}

	printf ("\tnode has %d children\n", suc->child_count);

	// initialise new node
	ntfs_dt_initialise (new, vcn);

	// find median key
	median = (suc->child_count+1) / 2;
	med_ie = ntfs_ie_copy (suc->children[median]);
	file = &med_ie->key.file_name; printf ("\tmed name: "); ntfs_name_print (file->file_name, file->file_name_length); printf ("\n");

	//printf ("suc key count = %d\n", suc->child_count);
	//printf ("new key count = %d\n", new->child_count);

	//printf ("median's child = %p\n", suc->sub_nodes[median]);
	// need to pass the child when ascending
	chl = suc->sub_nodes[median];

	// transfer keys
	if (ntfs_dt_transfer (suc, new, 0, median-1) < 0)
		goto done;

	//printf ("suc key count = %d\n", suc->child_count);
	//printf ("new key count = %d\n", new->child_count);

	//file = &suc->children[0]->key.file_name; printf ("\tmed name: "); ntfs_name_print (file->file_name, file->file_name_length); printf ("\n");

	// can this be a root node?
	if (ntfs_dt_root (suc))
		ntfs_dt_root_remove (suc, 0);
	else
		ntfs_dt_alloc_remove (suc, 0);

	//file = &suc->children[0]->key.file_name; printf ("\tmed name: "); ntfs_name_print (file->file_name, file->file_name_length); printf ("\n");
	//printf ("suc key count = %d\n", suc->child_count);
	//printf ("new key count = %d\n", new->child_count);

	// remove the median key

	// split when median has children
	// median child given to new !
	// median child is new
	// ascend

	med_ie = ntfs_ie_set_vcn (med_ie, new->vcn);
	if (!med_ie)
		goto done;

	//printf ("median child = %lld\n", ntfs_ie_get_vcn (med_ie));
	//printf ("new's vcn    = %lld\n", new->vcn);

	// adjust parents
	// 	attach new to median
	// escape clause for root node?
	// goto ascend

	// ie = insert
	// child = child
	// suc = successor
	// suc_num = insert point

	ie = med_ie;
	suc = suc->parent;
	suc_num = 0;

	printf ("\n");
	printf (BOLD YELLOW "Ascend\n" END);
	goto ascend;
done:
	return 0;
}


/**
 * ntfsrm
 */
static int ntfsrm (ntfs_volume *vol, char *name)
{
	struct ntfs_dir *dir = NULL;
	struct ntfs_dir *finddir = NULL;
	MFT_REF mft_num;
	ntfschar *uname = NULL;
	int len;

	dir = ntfs_dir_alloc (vol, FILE_root);
	if (!dir)
		return 1;

	//mft_num = ntfs_dir_find (dir, name);
	//printf ("%s = %lld\n", name, mft_num);

	mft_num = utils_pathname_to_mftref (vol, dir, name, &finddir);
	//printf ("mft_num = %lld\n", mft_num);
	//ntfs_dir_print (finddir, 0);

	if (!finddir) {
		printf ("Couldn't find the index entry for %s\n", name);
		return 1;
	}

	if (rindex (name, PATH_SEP))
		name = rindex (name, PATH_SEP) + 1;

	len = ntfs_mbstoucs (name, &uname, 0);
	if (len < 0)
		return 1;

	ntfs_dt_del_child (finddir->index, uname, len);

	ntfs_dir_free (dir);
	free (uname);
	return 0;
}

/**
 * ntfs_index_dump_alloc
 */
static int ntfs_index_dump_alloc (ntfs_attr *attr, VCN vcn, int indent)
{
	u8 buffer[4096];
	INDEX_BLOCK *block;
	INDEX_ENTRY *entry;
	u8 *ptr;
	int size;
	VCN *newvcn = 0;

	ntfs_attr_mst_pread (attr, vcn*512, 1, sizeof (buffer), buffer);

	block = (INDEX_BLOCK*) buffer;
	size = block->index.allocated_size;

	for (ptr = buffer + 64; ptr < (buffer + size); ptr += entry->length) {
		entry = (INDEX_ENTRY*) ptr;

		if (entry->flags & INDEX_ENTRY_NODE) {
			newvcn = (VCN*) (ptr + ((entry->key_length + 0x17) & ~7));
			ntfs_index_dump_alloc (attr, *newvcn, indent+4);
		}

		printf ("%.*s", indent, space_line);

		if (entry->flags & INDEX_ENTRY_END) {
			printf ("[END]");
		} else {
			ntfs_name_print (entry->key.file_name.file_name, entry->key.file_name.file_name_length);
		}

		if (entry->flags & INDEX_ENTRY_NODE) {
			printf (" (%lld)\n", *newvcn);
		} else {
			printf ("\n");
		}

		if (entry->flags & INDEX_ENTRY_END)
			break;
	}
	printf ("%.*s", indent, space_line);
	printf ("fill = %u/%u\n", (unsigned int)block->index.index_length,
			(unsigned int)block->index.allocated_size);
	return 0;
}

/**
 * ntfs_index_dump
 */
static int ntfs_index_dump (ntfs_inode *inode)
{
	u8 buffer[1024];
	ntfs_attr *iroot;
	ntfs_attr *ialloc;
	INDEX_ROOT *root;
	INDEX_ENTRY *entry;
	u8 *ptr;
	int size;
	VCN *vcn = 0;

	if (!inode)
		return 0;

	iroot  = ntfs_attr_open (inode, AT_INDEX_ROOT, I30, 4);
	ialloc = ntfs_attr_open (inode, AT_INDEX_ALLOCATION, I30, 4);

	size = (int) ntfs_attr_pread (iroot, 0, sizeof (buffer), buffer);

	root = (INDEX_ROOT*) buffer;

	ptr = buffer + root->index.entries_offset + 0x10;

	while (ptr < (buffer + size)) {
		entry = (INDEX_ENTRY*) ptr;
		if (entry->flags & INDEX_ENTRY_NODE) {
			vcn = (VCN*) (ptr + ((entry->key_length + 0x17) & ~7));
			ntfs_index_dump_alloc (ialloc, *vcn, 4);
		}

		if (entry->flags & INDEX_ENTRY_END) {
			printf ("[END]");
		} else {
			ntfs_name_print (entry->key.file_name.file_name, entry->key.file_name.file_name_length);
		}

		if (entry->flags & INDEX_ENTRY_NODE) {
			printf (" (%lld)", *vcn);
		}
		printf ("\n");

		ptr += entry->length;
	}
	printf ("fill = %d\n", ptr - buffer);
	return 0;
}

/**
 * ntfs_file_add
 */
static int ntfs_file_add (ntfs_volume *vol, char *name)
{
	struct ntfs_dir *dir = NULL;
	struct ntfs_dir *finddir = NULL;
	struct ntfs_dt *del = NULL;
	INDEX_ENTRY *ie = NULL;
	MFT_REF mft_num;
	ntfschar *uname = NULL;
	int len;
	int index_num = 0;

	dir = ntfs_dir_alloc (vol, FILE_root);
	if (!dir)
		return 1;

	mft_num = utils_pathname_to_mftref (vol, dir, name, &finddir);
	//printf ("mft_num = %lld\n", mft_num);
	//ntfs_dir_print (finddir, 0);

	if (!finddir) {
		printf ("Couldn't find the index entry for %s\n", name);
		return 1;
	}

	if (rindex (name, PATH_SEP))
		name = rindex (name, PATH_SEP) + 1;

	len = ntfs_mbstoucs (name, &uname, 0);
	if (len < 0)
		return 1;

	del = ntfs_dt_find2 (finddir->index, uname, len, &index_num);
	if (!del) {
		printf ("can't find item to delete\n");
		goto done;
	}

	ie = ntfs_ie_copy (del->children[index_num]);
	if (!ie)
		goto done;

	free (uname);
	uname = NULL;

	len = ntfs_mbstoucs ("file26a", &uname, 0);
	if (len < 0)
		goto done;

	ie = ntfs_ie_set_name (ie, uname, len, FILE_NAME_WIN32);
	if (!ie)
		goto done;

	//utils_dump_mem ((u8*)ie, 0, ie->length, DM_DEFAULTS);
	//printf ("\n");
	//printf ("ie = %lld\n", MREF (ie->indexed_file));
	//ntfs_dt_del_child (finddir->index, uname, len);

	//ntfs_dt_print (finddir->index, 0);
	ntfs_dt_add (finddir->index, ie);

	// test
	if (0) ntfs_dt_alloc_add (del, ie);
	if (0) ntfs_dt_root_add (del, ie);
	// test

done:
	ntfs_dir_free (dir);
	free (uname);
	free (ie);
	return 0;
}

/**
 * ntfs_file_remove
 */
static int ntfs_file_remove (ntfs_volume *vol, char *name)
{
	// XXX work with inode - lookup name outside?
	// how do I do the inode -> dt lookup?

	struct ntfs_dir *root_dir = NULL;
	struct ntfs_dir *find_dir = NULL;
	struct ntfs_dt *top = NULL;
	struct ntfs_dt *del = NULL;
	struct ntfs_dt *suc = NULL;
	struct ntfs_dt *old = NULL;
	struct ntfs_dt *par = NULL;
	struct ntfs_dt *ded = NULL;
	MFT_REF mft_num;
	ntfschar *uname = NULL;
	int name_len;
	int del_num = 0;
	int suc_num = 0;
	int par_num = -1;
	INDEX_ENTRY *del_ie = NULL;
	INDEX_ENTRY *suc_ie = NULL;
	INDEX_ENTRY *par_ie = NULL;
	INDEX_ENTRY *add_ie = NULL;
	int res;
	VCN vcn;
	FILE_NAME_ATTR *file = NULL;
	//int i;

	root_dir = ntfs_dir_alloc (vol, FILE_root);
	if (!root_dir)
		return 1;

	mft_num = utils_pathname_to_mftref (vol, root_dir, name, &find_dir);
	// XXX mft_num not used

	if (!find_dir) {
		printf ("Couldn't find the index entry for %s\n", name);
		goto done;
	}

	//ntfs_dt_print (find_dir->index, 0);

	if (rindex (name, PATH_SEP))
		name = rindex (name, PATH_SEP) + 1;

	name_len = ntfs_mbstoucs (name, &uname, 0);
	if (name_len < 0)
		goto done;

	del = ntfs_dt_find2 (find_dir->index, uname, name_len, &del_num);
	if (!del) {
		printf ("can't find item to delete\n");
		goto done;
	}

	top = del->dir->index;
	ntfs_dt_find_all (top);
	//ntfs_dt_print (top, 0);

	del_ie = del->children[del_num];
	//utils_dump_mem ((u8*)del_ie, 0, del_ie->length, DM_DEFAULTS);
	//printf ("\n");

	/*
	 * If the key is not in a leaf node, then replace it with its successor.
	 * Continue the delete as if the successor had been deleted.
	 */

	/*
	for (i = 0; i < top->child_count; i++) {
		par_ie = top->children[i];
		file = &par_ie->key.file_name; printf ("\ttop node, key %d: ", i); ntfs_name_print (file->file_name, file->file_name_length); printf ("\n");
		printf ("\tvcn = %lld\n", ntfs_ie_get_vcn (par_ie));
	}
	*/

	if (del->header->flags & INDEX_NODE) {
		printf (BOLD YELLOW "Replace key with its successor:\n" END);

		vcn = ntfs_ie_get_vcn (del_ie);
		//printf ("vcn = %lld\n", vcn);

		suc = ntfs_dt_find4 (find_dir->index, uname, name_len, &suc_num);
		//printf ("succ = %p, index = %d\n", suc, suc_num);
		//printf ("\n");

		suc_ie = ntfs_ie_copy (suc->children[suc_num]);
		//utils_dump_mem ((u8*)suc_ie, 0, suc_ie->length, DM_BLUE|DM_GREEN|DM_INDENT);
		//printf ("\n");

		suc_ie = ntfs_ie_set_vcn (suc_ie, vcn);
		//utils_dump_mem ((u8*)suc_ie, 0, suc_ie->length, DM_BLUE|DM_GREEN|DM_INDENT);
		//printf ("\n");

		file = &del_ie->key.file_name; printf ("\trep name: "); ntfs_name_print (file->file_name, file->file_name_length); printf ("\n");
		file = &suc_ie->key.file_name; printf ("\tsuc name: "); ntfs_name_print (file->file_name, file->file_name_length); printf ("\n");

		//utils_dump_mem (del->data, 0, del->data_len, DM_BLUE|DM_GREEN|DM_INDENT);
		if (ntfs_dt_root (del))
			res = ntfs_dt_root_replace (del, del_num, del_ie, suc_ie);
		else
			res = ntfs_dt_alloc_replace (del, del_num, del_ie, suc_ie);
		//printf ("\n");
		//utils_dump_mem (del->data, 0, del->data_len, DM_BLUE|DM_GREEN|DM_INDENT);

		free (suc_ie);

		if (res == FALSE)
			goto done;

		del     = suc;		// Continue delete with the successor
		del_num = suc_num;
		del_ie  = suc->children[suc_num];
	}

	//ntfs_dt_print (top, 0);

	/*
	 * Now we have the simpler case of deleting from a leaf node.
	 * If this step creates an empty node, we have more to do.
	 */

	printf ("\n");
	printf (BOLD YELLOW "Delete key:\n" END);

	file = &del->children[del_num]->key.file_name; printf ("\tdel name: "); ntfs_name_print (file->file_name, file->file_name_length); printf ("\n");

	//utils_dump_mem (del->data, 0, del->header->index_length+24, DM_BLUE|DM_GREEN|DM_INDENT);
	// XXX if del->child_count == 2, we could skip this step
	// no, if we combine with another node, we'll have to remember
	if (ntfs_dt_root (del))
		ntfs_dt_root_remove (del, del_num);
	else
		ntfs_dt_alloc_remove (del, del_num);
	//printf ("\n");
	//utils_dump_mem (del->data, 0, del->header->index_length+24, DM_BLUE|DM_GREEN|DM_INDENT);

	if (del->child_count > 1)	// XXX ntfs_dt_empty (dt),  ntfs_dt_full (dt, new)
		goto commit;

	/*
	 * Ascend the tree until we find a node that is not empty.  Take the
	 * ancestor key and unhook it.  This will free up some space in the
	 * index allocation.  Finally add the ancestor to the node of its
	 * successor.
	 */

	// find the key nearest the root which has no descendents
	printf ("\n");
	printf (BOLD YELLOW "Find childless parent:\n" END);
	for (par = del->parent, old = par; par; old = par, par = par->parent) {
		if (par->child_count > 1)
			break;
		par_num = ntfs_dt_find_parent (par);
	}

	//utils_dump_mem (par->data, 0, par->data_len, DM_BLUE|DM_GREEN|DM_INDENT);

	file = &par->children[par_num]->key.file_name; printf ("\tpar name: "); ntfs_name_print (file->file_name, file->file_name_length); printf ("\n");

	if (par == NULL) {
		// unhook everything
		printf ("whole dir is empty\n");
		goto freedts;
	}

	//ntfs_dt_print (top, 0);
	printf ("\n");

	//utils_dump_mem (par->data, 0, par->data_len, DM_BLUE|DM_GREEN|DM_INDENT);
	//printf ("\n");

	/*
	for (i = 0; i < top->child_count; i++) {
		par_ie = top->children[i];
		file = &par_ie->key.file_name; printf ("\ttop node, key %d: ", i); ntfs_name_print (file->file_name, file->file_name_length); printf ("\n");
		printf ("\tvcn = %lld\n", ntfs_ie_get_vcn (par_ie));
	}
	*/

	// find if parent has left siblings
	if (par->children[par_num]->flags & INDEX_ENTRY_END) {
		printf (BOLD YELLOW "Swap the children of the parent and its left sibling\n" END);

		par_ie = par->children[par_num];
		vcn = ntfs_ie_get_vcn (par_ie);
		//printf ("\toffset = %d\n", (u8*)par_ie - par->data); printf ("\tflags = %d\n", par_ie->flags); printf ("\tvcn = %lld\n", vcn); printf ("\tlength = %d\n", par_ie->length);
		//utils_dump_mem ((u8*)par_ie, 0, par_ie->length, DM_DEFAULTS);
		//printf ("\n");

		//printf ("\toffset = %d\n", (u8*)par_ie - par->data); printf ("\tflags = %d\n", par_ie->flags); printf ("\tvcn = %lld\n", vcn); printf ("\tlength = %d\n", par_ie->length);
		//utils_dump_mem ((u8*)par_ie, 0, par_ie->length, DM_DEFAULTS);
		//printf ("\n");

		file = &par->children[par_num]  ->key.file_name; printf ("\tpar name: "); ntfs_name_print (file->file_name, file->file_name_length); printf ("\n");
		file = &par->children[par_num-1]->key.file_name; printf ("\tsib name: "); ntfs_name_print (file->file_name, file->file_name_length); printf ("\n");

		old                       = par->sub_nodes[par_num];
		par->sub_nodes[par_num]   = par->sub_nodes[par_num-1];
		par->sub_nodes[par_num-1] = old;

		par_ie = par->children[par_num-1];
		vcn = ntfs_ie_get_vcn (par_ie);

		par_ie = par->children[par_num];
		ntfs_ie_set_vcn (par_ie, vcn);

		par_num--;

		if (ntfs_dt_root (par))
			printf (GREEN "Modified: inode %lld, $INDEX_ROOT\n" END, par->dir->inode->mft_no);
		else
			printf (GREEN "Modified: inode %lld, $INDEX_ALLOCATION vcn %lld-%lld\n" END, par->dir->inode->mft_no, par->vcn, par->vcn + (par->dir->index_size>>9) - 1);
	}

	//ntfs_dt_print (top, 0);

	//printf ("\n");
	//utils_dump_mem (par->data, 0, par->data_len, DM_DEFAULTS);

	// unhook and hold onto the ded dt's
	printf ("\n");
	printf (BOLD YELLOW "Remove parent\n" END);

	file = &par->children[par_num]->key.file_name; printf ("\tpar name: "); ntfs_name_print (file->file_name, file->file_name_length); printf ("\n");

	add_ie = ntfs_ie_copy (par->children[par_num]);
	add_ie = ntfs_ie_remove_vcn (add_ie);
	if (!add_ie)
		goto done;

	//printf ("\n");
	//utils_dump_mem ((u8*)add_ie, 0, add_ie->length, DM_BLUE|DM_GREEN|DM_INDENT);

	ded = par->sub_nodes[par_num];
	par->sub_nodes[par_num] = NULL;
	//ntfs_dt_print (ded, 8);

#if 0
	for (i = 0; i < par->child_count; i++) {
		par_ie = par->children[i];
		file = &par_ie->key.file_name; printf ("\tdel node, key %d: ", i); ntfs_name_print (file->file_name, file->file_name_length); printf ("\n");
		printf ("\tvcn = %lld\n", ntfs_ie_get_vcn (par_ie));
	}
#endif

#if 1
	//printf ("PAR: %p,%d\n", par, par_num);
	if (ntfs_dt_root (par))
		ntfs_dt_root_remove (par, par_num);
	else
		ntfs_dt_alloc_remove (par, par_num);
#endif
	//printf ("count = %d\n", par->child_count);
	//utils_dump_mem (par->data, 0, par->data_len, DM_DEFAULTS);
	//printf ("0x%x\n", (u8*)par->children[0] - par->data);

#if 0
	for (i = 0; i < par->child_count; i++) {
		par_ie = par->children[i];
		file = &par_ie->key.file_name; printf ("\tadd node, key %d: ", i); ntfs_name_print (file->file_name, file->file_name_length); printf ("\n");
		printf ("\tvcn = %lld\n", ntfs_ie_get_vcn (par_ie));
	}
#endif

	//ntfs_dt_print (top, 0);
	printf ("\n");
	printf (BOLD YELLOW "Add childless parent\n" END);

	file = &add_ie->key.file_name; printf ("\tadd name: "); ntfs_name_print (file->file_name, file->file_name_length); printf ("\n");
	suc     = NULL;
	suc_num = -1;
	suc = ntfs_dt_find4 (top, file->file_name, file->file_name_length, &suc_num);
	//printf ("SUC: %p, %d\n", suc, suc_num);

	if (!suc)
		goto done;

	file = &suc->children[suc_num]->key.file_name; printf ("\tsuc name: "); ntfs_name_print (file->file_name, file->file_name_length); printf ("\n");

	// insert key into successor
	// if any new nodes are needed, reuse the preserved nodes
	if (!ntfs_dt_add2 (add_ie, suc, suc_num, ded))
		goto done;

	// remove any unused nodes

	// XXX mark dts, dirs and inodes dirty
	// XXX attach bmp to dir and volume
	// XXX attach root dir to volume
	// XXX add freed dts to a list for immediate reuse (attach to dir?)
	// XXX commit will free list of spare dts
	// XXX reduce size of alloc

	if (0) ntfs_dir_commit (find_dir);
	if (0) ntfs_dir_rollback (find_dir);

	printf ("empty\n");
	goto done;

freedts:

commit:
	printf ("commit\n");

done:
	ntfs_dir_free (root_dir);
	free (uname);
	return 0;
}

/**
 * ntfs_file_remove2
 */
static int ntfs_file_remove2 (ntfs_volume *vol, char *name)
{
	if (0) utils_mftrec_mark_free5 (NULL, NULL, 0);

	return ntfs_file_remove (vol, name);
}

/**
 * ntfs_test_bmp
 */
static int ntfs_test_bmp (ntfs_volume *vol, ntfs_inode *inode)
{
	ntfs_inode *volbmp;
	struct ntfs_bmp *bmp;
	struct ntfs_bmp *bmp2;
	//u8 *buffer;
	//int i;

	volbmp = ntfs_inode_open2 (vol, FILE_Bitmap);
	if (!volbmp)
		return 1;

	bmp = ntfs_bmp_alloc (volbmp, AT_DATA, NULL, 0);
	if (!bmp)
		return 1;

	bmp2 = ntfs_bmp_alloc (vol->mft_ni, AT_BITMAP, NULL, 0);
	if (!bmp2)
		return 1;

	if (0) ntfs_bmp_set_range (bmp, 0, 9, 1);
	if (0) utils_free_non_residents2 (inode, bmp);
	if (0) utils_mftrec_mark_free3 (bmp2, inode->mft_no);
	if (0) utils_mftrec_mark_free4 (inode);

	ntfs_bmp_free (bmp);
	return 0;
}


/**
 * main - Begin here
 *
 * Start from here.
 *
 * Return:  0  Success, the program worked
 *	    1  Error, something went wrong
 */
int main (int argc, char *argv[])
{
	ntfs_volume *vol = NULL;
	ntfs_inode *inode = NULL;
	int flags = 0;
	int result = 1;
	struct ntfs_find find;

	if (!parse_options (argc, argv))
		goto done;

	utils_set_locale();

#if 0
	printf ("sizeof (ntfs_bmp)   = %d\n", sizeof (struct ntfs_bmp));
	printf ("sizeof (ntfs_dt)    = %d\n", sizeof (struct ntfs_dt));
	printf ("sizeof (ntfs_dir)   = %d\n", sizeof (struct ntfs_dir));
	printf ("\n");
#endif

	if (opts.noaction)
		flags |= MS_RDONLY;

	vol = utils_mount_volume2 (opts.device, flags, opts.force);
	if (!vol) {
		printf ("!vol\n");
		goto done;
	}

	if (utils_pathname_to_inode2 (vol, NULL, opts.file, &find) == FALSE) {
		printf ("!inode\n");
		goto done;
	}

	inode = find.inode;

	//printf ("inode = %lld\n", inode->mft_no);

	if (0) result = ntfs_index_dump (inode);
	if (0) result = ntfsrm (vol, opts.file);
	if (0) result = ntfs_ie_test();
	if (0) result = ntfs_file_add (vol, opts.file);
	if (0) result = ntfs_file_remove2 (vol, opts.file);
	if (0) result = ntfs_test_bmp (vol, inode);

done:
	ntfs_inode_close2 (inode);
	ntfs_umount2 (vol, FALSE);

	return result;
}
