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
static const char *space = "                                                                                ";

GEN_PRINTF (Eprintf, stderr, NULL,          FALSE)
GEN_PRINTF (Vprintf, stdout, &opts.verbose, TRUE)
GEN_PRINTF (Qprintf, stdout, &opts.quiet,   FALSE)

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


struct ntfs_dir;
static void ntfs_ie_dump (INDEX_ENTRY *ie);
static VCN ntfs_ie_get_vcn (INDEX_ENTRY *ie);
static INDEX_ENTRY * ntfs_ie_set_name (INDEX_ENTRY *ie, ntfschar *name, int namelen, FILE_NAME_TYPE_FLAGS nametype);

/**
 * struct ntfs_bmp
 * a cache for either dir/$BITMAP, $MFT/$BITMAP or $Bitmap/$DATA
 */
struct ntfs_bmp {
	ntfs_attr	 *attr;
	u8		**data;
	VCN		 *data_vcn;
	int		  count;
	//int		  cluster_size;
};

/**
 * struct ntfs_dt
 */
struct ntfs_dt {
	struct ntfs_dir	 *dir;
	struct ntfs_dt	 *parent;
	u8		 *data;
	int		  data_len;
	struct ntfs_dt	**sub_nodes;
	int		  child_count;
	INDEX_ENTRY	**children;
	INDEX_HEADER	 *header;
	VCN		  vcn;
};

/**
 * struct ntfs_dir
 */
struct ntfs_dir {
	ntfs_volume	  *vol;
	struct ntfs_dir	  *parent;
	ntfschar	  *name;
	int		   name_len;
	struct ntfs_dt	  *index;
	struct ntfs_dir	 **children;
	int		   child_count;
	MFT_REF		   mft_num;
	struct mft_bitmap *bitmap;
	ntfs_inode	  *inode;
	ntfs_attr	  *iroot;
	ntfs_attr	  *ialloc;
	ntfs_attr	  *ibmp;
	int                index_size;
};


/**
 * ntfs_name_print
 */
static void ntfs_name_print (ntfschar *name, int name_len)
{
	char *buffer = NULL;

	ntfs_ucstombs (name, name_len, (char**) &buffer, 0);
	printf ("%s", buffer);
	free (buffer);
}

/**
 * ntfs_dir_print
 */
static void ntfs_dir_print (struct ntfs_dir *dir, int indent)
{
	int i;
	if (!dir)
		return;

	printf ("%.*s%p ", indent, space, dir);
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

	printf ("%.*s%p (%d)\n", indent, space, dt, dt->child_count);

	for (i = 0; i < dt->child_count; i++) {
		ntfs_dt_print (dt->sub_nodes[i], indent + 4);
	}
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
static int ntfs_bmp_set_range (struct ntfs_bmp *bmp, VCN vcn, u64 length, int value)
{
	u64 i;
	u8 *buffer;
	VCN begin;
	VCN end;
	int start;
	int finish;
	u8 sta_part;
	u8 fin_part;

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
#else
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

	printf ("Modified: inode %lld, ", bmp->attr->ni->mft_no);
	switch (bmp->attr->type) {
		case AT_BITMAP: printf ("$BITMAP"); break;
		case AT_DATA:   printf ("$DATA");   break;
	}
	printf (" vcn %lld-%lld\n", vcn>>12, (vcn+length)>>12);

	return 1;
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

	int old = (count + 0x1e) & ~0x1f;
	int new = (count + 0x1f) & ~0x1f;

	if (old == new)
		return TRUE;

	dt->children  = realloc (dt->children,  new * sizeof (*dt->children));
	dt->sub_nodes = realloc (dt->sub_nodes, new * sizeof (*dt->sub_nodes));

	return (dt->children && dt->sub_nodes);
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
	dt->children	= NULL;
	dt->child_count	= 0;
	dt->sub_nodes	= NULL;
	dt->vcn		= vcn;

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

	for (i = 0; i < dt->child_count; i++)
		ntfs_dt_free (dt->sub_nodes[i]);

	free (dt->sub_nodes);
	free (dt->children);
	free (dt->data);
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
	int i;
	int r;

	if (!dt || !name)
		return NULL;

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

	inode = ntfs_inode_open (vol, mft_num);
	if (!inode)
		return NULL;

	dir = calloc (1, sizeof (*dir));
	if (!dir) {
		ntfs_inode_close (inode);
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
		free (dir);
		return NULL;
	}

	return dir;
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

	ntfs_attr_close  (dir->iroot);
	ntfs_attr_close  (dir->ialloc);
	ntfs_attr_close  (dir->ibmp);
	ntfs_inode_close (dir->inode);

	for (i = 0; i < dir->child_count; i++)
		ntfs_dir_free (dir->children[i]);

	free (dir->children);

	ntfs_dt_free (dir->index);
	free (dir);
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
		Eprintf ("MFT record isn't in use (2).\n");
		return -1;
	}

	rec->flags &= ~MFT_RECORD_IN_USE;

	//printf ("\n");
	//utils_dump_mem (buffer, 0, 1024, DM_DEFAULTS);

	printf ("Modified: inode %lld MFT_RECORD header\n", inode->mft_no);
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
 * ntfs_dt_add_alloc
 */
static int ntfs_dt_add_alloc (struct ntfs_dt *parent, int index_num, INDEX_ENTRY *ie)
{
	INDEX_BLOCK *block;
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

	//utils_dump_mem (parent->data, 0, parent->data_len, DM_DEFAULTS);
	//printf ("\n");
	return 0;
}

/**
 * ntfs_dt_add_root
 */
static int ntfs_dt_add_root (struct ntfs_dt *parent, int index_num, INDEX_ENTRY *ie)
{
	INDEX_ROOT *root;
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

	if (0) ntfs_dt_add_alloc (dt, index_num, ie);
	if (0) ntfs_dt_add_root (dt->dir->index, 0, ie);

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

	if (dt->parent)
		return ntfs_dt_remove_alloc (dt, index_num);
	else
		return ntfs_dt_remove_root (dt, index_num);
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

	ichild = ntfs_inode_open (dt->dir->vol, MREF (ie->indexed_file));
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

	iparent = ntfs_inode_open (dt->dir->vol, mft_num);
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
	ntfs_inode_close (iparent);
	ntfs_inode_close (ichild);

	return res;
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


#define ATTR_SIZE(s) (((s)+7) & ~7)

/**
 * ntfsinfo_time_to_str() -
 * @sle_ntfs_clock:	on disk time format in 100ns units since 1st jan 1601
 *			in little-endian format
 *
 * Return char* in a format 'Thu Jan  1 00:00:00 1970'.
 * No need to free the returned memory.
 *
 * Example of usage:
 *	char *time_str = ntfsinfo_time_to_str(
 *			sle64_to_cpu(standard_attr->creation_time));
 *	printf("\tFile Creation Time:\t %s", time_str);
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
 * ntfs_ie_remove_child
 */
static INDEX_ENTRY * ntfs_ie_remove_child (INDEX_ENTRY *ie)
{
	if (!ie)
		return NULL;
	if (!(ie->flags & INDEX_ENTRY_NODE))
		return ie;

	ie->length -= 8;
	ie->flags &= ~INDEX_ENTRY_NODE;
	ie = realloc (ie, ie->length);
	return NULL;
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
	VCN vcn;

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
		ie1 = ntfs_ie_remove_child (ie1);
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
 * ntfs_ie_get_vcn
 */
static VCN ntfs_ie_get_vcn (INDEX_ENTRY *ie)
{
	if (!ie)
		return -1;

	return *((VCN*) ((u8*) ie + ie->length - 8));
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
	VCN *newvcn;

	ntfs_attr_mst_pread (attr, vcn*512, 1, sizeof (buffer), buffer);

	block = (INDEX_BLOCK*) buffer;
	size = block->index.allocated_size;

	for (ptr = buffer + 64; ptr < (buffer + size); ptr += entry->length) {
		entry = (INDEX_ENTRY*) ptr;

		if (entry->flags & INDEX_ENTRY_NODE) {
			newvcn = (VCN*) (ptr + ((entry->key_length + 0x17) & ~7));
			ntfs_index_dump_alloc (attr, *newvcn, indent+4);
		}

		printf ("%.*s", indent, space);

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
	printf ("%.*s", indent, space);
	printf ("fill = %d/%d\n", block->index.index_length, block->index.allocated_size);
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
	VCN *vcn;

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

	len = del->data_len + suc_ie->length - del_ie->length;
	free (del->data);
	del->data = attr;
	del->data_len = len;

	ntfs_mft_resize_resident (del->dir->inode, AT_INDEX_ROOT, I30, 4, del->data, del->data_len);

	//utils_dump_mem (attr, 0, del->data_len, DM_DEFAULTS);

	//for (i = 0; i < del->child_count; i++)
	//	printf ("Child %d %p\n", i, del->children[i]);
	//printf ("\n");

	len = suc_ie->length - del_ie->length + 8;
	//printf ("len = %d\n", len);

	for (i = del_num+1; i < del->child_count; i++)
		del->children[i] = (INDEX_ENTRY*) ((u8*) del->children[i] + len);

	//for (i = 0; i < del->child_count; i++)
	//	printf ("Child %d %p\n", i, del->children[i]);
	//printf ("\n");

	//utils_dump_mem (del->data, 0, del->data_len, DM_DEFAULTS);
	//printf ("\n");

	printf ("Modified: inode %lld MFT_RECORD, attribute 0x90\n", del->dir->inode->mft_no);
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

	printf ("Modified: inode %lld, $INDEX_ALLOCATION vcn %lld-%lld\n", del->dir->inode->mft_no, del->vcn, del->vcn + 4);
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
	int len;
	int i;
	//int off;

	if (!del)
		return FALSE;

	//utils_dump_mem (del->data, 0, del->data_len, DM_RED);
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

	del_ie = del->children[del_num];

	src = (u8*) del_ie + del_ie->length;
	dst = (u8*) del_ie;
	len = del->header->index_length + 16 - (src - del->data);

	//printf ("src = %d\n", src - del->data);
	//printf ("dst = %d\n", dst - del->data);
	//printf ("len = %d\n", len);

	memmove (dst, src, len);

	del->data_len -= del_ie->length;
	del->child_count--;

	del->header->index_length   = del->data_len - 16;
	del->header->allocated_size = del->data_len - 16;

	ntfs_mft_resize_resident (del->dir->inode, AT_INDEX_ROOT, I30, 4, del->data, del->data_len);
	del->data = realloc (del->data, del->data_len);

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
	for (i = del_num; i < del->child_count; i++)
		del->children[i] = (INDEX_ENTRY*) ((u8*) del->children[i] - del_ie->length);

	if (!ntfs_dt_alloc_children2 (del, del->child_count))
		return FALSE;

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

	//utils_dump_mem (del->data, 0, del->data_len, DM_DEFAULTS);

	printf ("Modified: inode %lld MFT_RECORD, attribute 0x90\n", del->dir->inode->mft_no);
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

	printf ("Modified: inode %lld, $INDEX_ALLOCATION vcn %lld-%lld\n", del->dir->inode->mft_no, del->vcn, del->vcn + 4);
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

	printf ("Modified: inode %lld MFT_RECORD, attribute 0x90\n", add->dir->inode->mft_no);
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

	printf ("Modified: inode %lld, $INDEX_ALLOCATION vcn %lld-%lld\n", add->dir->inode->mft_no, add->vcn, add->vcn + 4);
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
	struct ntfs_dt *del = NULL;
	struct ntfs_dt *suc = NULL;
	MFT_REF mft_num;
	ntfschar *uname = NULL;
	int name_len;
	int del_num = 0;
	int suc_num = 0;
	INDEX_ENTRY *del_ie = NULL;
	INDEX_ENTRY *suc_ie = NULL;
	int res;
	VCN vcn;

	root_dir = ntfs_dir_alloc (vol, FILE_root);
	if (!root_dir)
		return 1;

	mft_num = utils_pathname_to_mftref (vol, root_dir, name, &find_dir);

	if (!find_dir) {
		printf ("Couldn't find the index entry for %s\n", name);
		goto done;
	}

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

	del_ie = del->children[del_num];
	//utils_dump_mem ((u8*)del_ie, 0, del_ie->length, DM_DEFAULTS);
	//printf ("\n");

	/*
	 * If the key is not in a leaf node, then replace it with its successor.
	 * Continue the delete as if the successor had been deleted.
	 */

	if (del->header->flags & INDEX_NODE) {
		vcn = ntfs_ie_get_vcn (del_ie);
		//printf ("vcn = %lld\n", vcn);

		suc = ntfs_dt_find4 (find_dir->index, uname, name_len, &suc_num);
		//printf ("succ = %p, index = %d\n", suc, suc_num);
		//printf ("\n");

		suc_ie = ntfs_ie_copy (suc->children[suc_num]);
		//utils_dump_mem ((u8*)suc_ie, 0, suc_ie->length, DM_DEFAULTS);
		//printf ("\n");

		suc_ie = ntfs_ie_set_vcn (suc_ie, vcn);
		//utils_dump_mem ((u8*)suc_ie, 0, suc_ie->length, DM_DEFAULTS);
		//printf ("\n");

		if (del->parent)
			res = ntfs_dt_alloc_replace (del, del_num, del_ie, suc_ie);
		else
			res = ntfs_dt_root_replace (del, del_num, del_ie, suc_ie);

		free (suc_ie);

		if (res == FALSE)
			goto done;

		del     = suc;		// Continue delete with the successor
		del_num = suc_num;
		del_ie  = suc->children[suc_num];
	}

	/*
	 * Now we have the simple case of deleting from a leaf node.
	 * If this step creates an empty node, we have more to do.
	 */

	if (del->parent)
		ntfs_dt_alloc_remove (del, del_num);
	else
		ntfs_dt_root_remove (del, del_num);

	if (del->child_count > 1)	// XXX ntfs_dt_empty (dt),  ntfs_dt_full (dt, new)
		goto commit;

	/*
	 * Ascend the tree until we find a node that is not empty.  Take the
	 * ancestor key and unhook it.  This will free up some space in the
	 * index allocation.  Finally add the ancestor to the node of its
	 * successor.
	 */

	// find the key which has no descendents
	// unhook and hold onto the dt's
	// unhook the key
	// find successor
	// insert key into successor
	// if any new nodes are needed, reuse the preserved nodes
	// remove any unused nodes

	printf ("empty\n");
	goto done;

commit:
	printf ("commit\n");

done:
	ntfs_dir_free (root_dir);
	free (uname);
	return 0;
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

	volbmp = ntfs_inode_open (vol, FILE_Bitmap);
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

	vol = utils_mount_volume (opts.device, flags, opts.force);
	if (!vol) {
		printf ("!vol\n");
		goto done;
	}

	inode = utils_pathname_to_inode (vol, NULL, opts.file);
	if (!inode) {
		printf ("!inode\n");
		goto done;
	}

	if (0) result = ntfs_index_dump (inode);
	if (0) result = ntfsrm (vol, opts.file);
	if (0) result = ntfs_ie_test();
	if (0) result = ntfs_file_add (vol, opts.file);
	if (0) result = ntfs_file_remove (vol, opts.file);
	if (0) result = ntfs_test_bmp (vol, inode);

done:
	ntfs_inode_close (inode);
	ntfs_umount (vol, FALSE);

	return result;
}

