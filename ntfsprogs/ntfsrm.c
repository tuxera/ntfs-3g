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

/**
 * struct bmp_page
 */
struct bmp_page {
	u8		  *data;
	VCN		   vcn;
};

/**
 * struct mft_bitmap
 */
struct mft_bitmap {
	ntfs_attr	  *bmp;
	struct bmp_page	 **pages;
	int		   count;
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
	BOOL		  changed;
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
 * ntfs_dt_alloc_children
 */
static INDEX_ENTRY ** ntfs_dt_alloc_children (INDEX_ENTRY **children, int count)
{
	int old = (count + 0x1e) & ~0x1f;
	int new = (count + 0x1f) & ~0x1f;

	if (old == new)
		return children;

	return realloc (children, new * sizeof (INDEX_ENTRY*));
}

/**
 * ntfs_dt_count_root
 */
static int ntfs_dt_count_root (struct ntfs_dt *dt)
{
	u8 *buffer = NULL;
	u8 *ptr = NULL;
	VCN *vcn = NULL;
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
			vcn = (VCN *) (ptr + ((entry->key_length + 0x17) & ~7));
			//printf ("VCN %lld\n", *vcn);
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
	VCN *vcn = NULL;
	s64 size = 0;
	char *name = NULL;

	INDEX_BLOCK *block;
	INDEX_ENTRY *entry;

	if (!dt)
		return -1;

	buffer = dt->data;
	size   = dt->data_len;

	//utils_dump_mem (buffer, 0, 128, TRUE);

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
			vcn = (VCN *) (ptr + ((entry->key_length + 0x17) & ~7));
			//printf ("\tVCN %lld\n", *vcn);
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
	dt->changed	= FALSE;
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
		//utils_dump_mem (dt->data, 0, dt->data_len, 1);
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
			utils_dump_mem ((u8*)ie, 0, ie->length, 1);
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
		//utils_dump_mem (dt->data, 0, dt->data_len, 1);

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
			utils_dump_mem ((u8*)ie, 0, ie->length, 1);
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
					vcn = *(VCN*)(((u8*)ie) + ie->length - sizeof (VCN));
					//printf ("vcn = %lld\n", vcn);
					sub = ntfs_dt_alloc (dt->dir, dt, vcn);
					dt->sub_nodes[i] = sub;
				}
				res = ntfs_dt_find (dt->sub_nodes[i], name, name_len);
			} else {
				//printf ("ENOENT\n");
			}
		} else {
			//printf ("error collating name\n");
		}
		break;
	}

	return res;
}

/**
 * ntfs_dt_find2
 */
static struct ntfs_dt * ntfs_dt_find2 (struct ntfs_dt *dt, ntfschar *uname, int len, int *index_num)
{
	struct ntfs_dt *res = NULL;
	INDEX_ENTRY *ie;
	int i;
	int r;

	if (!dt || !uname)
		return NULL;
	
	//printf ("child_count = %d\n", dt->child_count);
	for (i = 0; i < dt->child_count; i++) {
		ie = dt->children[i];

		if (ie->flags & INDEX_ENTRY_END) {
			r = -1;
		} else {
			r = ntfs_names_collate (uname, len,
						ie->key.file_name.file_name,
						ie->key.file_name.file_name_length,
						2, IGNORE_CASE,
						dt->dir->vol->upcase,
						dt->dir->vol->upcase_len);
		}

		if (r == 1) {
			//printf ("keep searching\n");
			continue;
		} else if (r == 0) {
			//printf ("match\n");
			res = dt;
			if (index_num)
				*index_num = i;
		} else if (r == -1) {
			//printf ("recurse\n");
			res = ntfs_dt_find2 (dt->sub_nodes[i], uname, len, index_num);
		} else {
			//printf ("error\n");
		}
		break;
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

	if (dir->ialloc)
		dir->index_size = dir->ialloc->allocated_size;
	else
		dir->index_size = 0;

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

	//utils_dump_mem (buffer, byte, 1, 0);
	buffer[byte] &= ~bit;
	//utils_dump_mem (buffer, byte, 1, 0);

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

	rec = (MFT_RECORD*) buffer;

	res = ntfs_mft_record_read (vol, mref, rec);
	printf ("res = %lld\n", res);

	if ((rec->flags & MFT_RECORD_IN_USE) == 0) {
		Eprintf ("MFT record isn't in use (2).\n");
		return -1;
	}

	rec->flags &= ~MFT_RECORD_IN_USE;

	//printf ("\n");
	//utils_dump_mem (buffer, 0, 1024, 1);

	res = ntfs_mft_record_write (vol, mref, rec);
	printf ("res = %lld\n", res);

	return 0;
}

/**
 * utils_free_non_residents
 */
static int utils_free_non_residents (ntfs_inode *inode)
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
		printf ("attributes isn't resident\n");
		goto done;
	}

	attr_orig = arec->value_length;
	attr_new  = data_len;

	//printf ("attr orig = %d\n", attr_orig);
	//printf ("attr new  = %d\n", attr_new);
	//printf ("\n");

	if (attr_new == attr_orig) {
		printf ("nothing to do\n");
		res = 0;
		goto done;
	}

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

	memmove (dst, src, len);
	memcpy ((u8*)arec + arec->value_offset, data, data_len);

	mrec->bytes_in_use += (attr_new - attr_orig);
	arec->length       += (attr_new - attr_orig);
	arec->value_length += (attr_new - attr_orig);

	memset ((u8*)mrec + mrec->bytes_in_use, 'R', mft_size - mrec->bytes_in_use);

	mft_usage += (attr_new - attr_orig);
	//utils_dump_mem ((u8*) mrec, 0, mft_size, 1);
	res = 0;
done:
	ntfs_attr_put_search_ctx (ctx);
	return res;
}


/**
 * ntfs_dt_remove_alloc
 */
static int ntfs_dt_remove_alloc (struct ntfs_dt *dt, int index_num)
{
	INDEX_ENTRY *ie = NULL;
	int i;
	u8 *dest;
	u8 *src;
	u8 *end;
	int off;
	int len;
	s64 res;

	//printf ("removing entry %d of %d\n", index_num+1, dt->child_count);
	//printf ("index size = %d\n", dt->data_len);
	//printf ("index use  = %d\n", dt->header->index_length);

	//utils_dump_mem (dt->data, 0, dt->data_len, TRUE);
	//write (2, dt->data, dt->data_len);

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
	dest = (u8*)ie;

	src  = dest + ie->length;

	ie = dt->children[dt->child_count-1];
	end = (u8*)ie + ie->length;
	
	len  = end - src;

	//printf ("move %d bytes\n", len);
	//printf ("%d, %d, %d\n", dest - dt->data, src - dt->data, len);
	memmove (dest, src, len);

	//printf ("clear %d bytes\n", dt->data_len - (dest - dt->data) - len);
	//printf ("%d, %d, %d\n", dest - dt->data + len, 0, dt->data_len - (dest - dt->data) - len);

	//ntfs_dt_print (dt->dir->index, 0);
#if 1
	memset (dest + len, 0, dt->data_len - (dest - dt->data) - len);

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
	dt->header->index_length -= src - dest;
	//printf ("after  = %d\n", dt->header->index_length + 24);

	ntfs_dt_count_alloc (dt);
#endif
	//utils_dump_mem (dt->data, 0, dt->data_len, TRUE);
	//write (2, dt->data, dt->data_len);

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
	//utils_dump_mem (dt->data, 0, dt->data_len, TRUE);
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
	u8 *dest;
	u8 *src;
	u8 *end;
	int off;
	int len;
	s64 res;

	//printf ("removing entry %d of %d\n", index_num+1, dt->child_count);
	//printf ("index size = %d\n", dt->data_len);
	//printf ("index use  = %d\n", dt->header->index_length);

	//utils_dump_mem (dt->data, 0, dt->data_len, TRUE);
	//write (2, dt->data, dt->data_len);

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
	dest = (u8*)ie;

	src  = dest + ie->length;

	ie = dt->children[dt->child_count-1];
	end = (u8*)ie + ie->length;
	
	len  = end - src;

	//printf ("move %d bytes\n", len);
	//printf ("%d, %d, %d\n", dest - dt->data, src - dt->data, len);
	memmove (dest, src, len);

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

	//utils_dump_mem (dt->data, 0, dt->data_len, 1);
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
	dt->header->index_length -= src - dest;
	//printf ("after  = %d\n", dt->header->index_length + 24);

	ntfs_dt_count_root (dt);
#endif
	//utils_dump_mem (dt->data, 0, dt->data_len, TRUE);
	//write (2, dt->data, dt->data_len);

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
	//utils_dump_mem (dt->data, 0, dt->data_len, TRUE);

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
	//ntfs_dt_print (del->dir->index_num, 0);

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
	printf ("sizeof (bmp_page)   = %d\n", sizeof (struct bmp_page));
	printf ("sizeof (mft_bitmap) = %d\n", sizeof (struct mft_bitmap));
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

	result = ntfsrm (vol, opts.file);
	/*
	if (result)
		printf ("failed\n");
	else
		printf ("success\n");
	*/

done:
	ntfs_inode_close (inode);
	ntfs_umount (vol, FALSE);

	return result;
}

