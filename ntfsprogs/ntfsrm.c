/**
 * ntfsrm - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2004-2005 Richard Russon
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

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif

#include "ntfsrm.h"
#include "rich.h"
#include "utils.h"
#include "debug.h"
#include "dir.h"
#include "lcnalloc.h"
#include "mft.h"
#include "ntfstime.h"
#include "version.h"
#include "tree.h"
#include "index.h"
#include "inode.h"
#include "logging.h"

static const char *EXEC_NAME = "ntfsrm";
static struct options opts;
static const char *space_line = "                                                                                ";

/**
 * version - Print version information about the program
 *
 * Print a copyright statement and a brief description of the program.
 *
 * Return:  none
 */
static void version(void)
{
	ntfs_log_info("\n%s v%s (libntfs %s) - Delete files from an NTFS volume.\n\n",
			EXEC_NAME, VERSION, ntfs_libntfs_version());
	ntfs_log_info("Copyright (c) 2004 Richard Russon\n");
	ntfs_log_info("\n%s\n%s%s\n", ntfs_gpl, ntfs_bugs, ntfs_home);
}

/**
 * usage - Print a list of the parameters to the program
 *
 * Print a list of the parameters and options for the program.
 *
 * Return:  none
 */
static void usage(void)
{
	ntfs_log_info("\nUsage: %s [options] device file\n"
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
	ntfs_log_info("%s%s\n", ntfs_bugs, ntfs_home);
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
static int parse_options(int argc, char **argv)
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

	int c = -1;
	int err  = 0;
	int ver  = 0;
	int help = 0;
	int levels = 0;

	opterr = 0; /* We'll handle the errors, thank you. */

	while ((c = getopt_long(argc, argv, sopt, lopt, NULL)) != -1) {
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
			if (strncmp (argv[optind-1], "--log-", 6) == 0) {
				if (!ntfs_log_parse_option (argv[optind-1]))
					err++;
				break;
			}
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
			ntfs_log_clear_levels(NTFS_LOG_LEVEL_QUIET);
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
			ntfs_log_set_levels(NTFS_LOG_LEVEL_VERBOSE);
			break;
		default:
			ntfs_log_error("Unknown option '%s'.\n", argv[optind-1]);
			err++;
			break;
		}
	}

	/* Make sure we're in sync with the log levels */
	levels = ntfs_log_get_levels();
	if (levels & NTFS_LOG_LEVEL_VERBOSE)
		opts.verbose++;
	if (!(levels & NTFS_LOG_LEVEL_QUIET))
		opts.quiet++;

	if (help || ver) {
		opts.quiet = 0;
	} else {
		if ((opts.device == NULL) ||
		    (opts.file   == NULL)) {
			if (argc > 1)
				ntfs_log_error("You must specify one device and one file.\n");
			err++;
		}

		if (opts.quiet && opts.verbose) {
			ntfs_log_error("You may not use --quiet and --verbose at the "
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
 * ntfs_dir_print
 */
static void ntfs_dir_print(struct ntfs_dir *dir, int indent)
{
	int i;
	if (!dir)
		return;

	ntfs_log_info("%.*s%p ", indent, space_line, dir);
	ntfs_name_print(dir->name, dir->name_len);
	ntfs_log_info("\n");

	for (i = 0; i < dir->child_count; i++) {
		ntfs_dir_print(dir->children[i], indent + 4);
	}

}

/**
 * ntfs_dt_print
 */
static void ntfs_dt_print(struct ntfs_dt *dt, int indent)
{
	int i;

	if (!dt)
		return;

	ntfs_log_info("%.*s%p (%d)\n", indent, space_line, dt, dt->child_count);

	for (i = 0; i < dt->child_count; i++) {
		ntfs_dt_print(dt->sub_nodes[i], indent + 4);
	}
}


/**
 * utils_array_insert
 */
static int utils_array_insert(void *ptr, int asize, int before, int count)
{
	static int esize = sizeof(u8*);
	u8 *src;
	u8 *dst;
	int len;

	if (!ptr)
		return -1;

	ntfs_log_trace ("\n");
	src = (u8*) ptr + (before * esize);
	dst = src + (count * esize);
	len = (asize - before) * esize;

	// XXX what about realloc?
	memmove(dst, src, len);

	len = count * esize;

	memset(src, 0, len);

	return 0;
}

/**
 * utils_array_remove
 */
static int utils_array_remove(void *ptr, int asize, int first, int count)
{
	static int esize = sizeof(u8*);
	u8 *src;
	u8 *dst;
	int len;

	if (!ptr)
		return -1;

	ntfs_log_trace ("\n");
	dst = (u8*) ptr + (first * esize);
	src = dst + (count * esize);
	len = (asize - first) * esize;

	memmove(dst, src, len);

	src = (u8*) ptr + ((asize - count) * esize);
	len = count * esize;

	memset(src, 0, len);
	// XXX don't want to memset, want to realloc

	return 0;
}


/**
 * utils_pathname_to_inode2
 */
static BOOL utils_pathname_to_inode2(ntfs_volume *vol, struct ntfs_dir *parent, const char *pathname, struct ntfs_find *found)
{
	int len;
	char *p, *q;
	ntfschar *unicode = NULL;
	char *ascii = NULL;
	struct ntfs_dir *dir = NULL;
	struct ntfs_dir *child = NULL;
	struct ntfs_dt *dt = NULL;
	int dt_num;
	BOOL result = FALSE;

	if (!vol || !pathname || !found) {
		errno = EINVAL;
		return FALSE;
	}

	ntfs_log_trace("\n");
	memset(found, 0, sizeof(*found));

	if (parent) {
		dir = parent;
	} else {
		dir = (struct ntfs_dir *) vol->private_data;
		if (!dir) {
			ntfs_log_error("Couldn't open the inode of the root directory.\n");
			goto close;
		}
	}

	unicode = malloc(MAX_PATH * sizeof(ntfschar));
	ascii   = strdup(pathname);		// Work with a r/w copy
	if (!unicode || !ascii) {
		ntfs_log_error("Out of memory.\n");
		goto close;
	}

	p = ascii;
	while (p && *p && *p == PATH_SEP)	// Remove leading /'s
		p++;
	while (p && *p) {
		q = strchr(p, PATH_SEP);	// Find the end of the first token
		if (q != NULL) {
			*q = '\0';
			q++;
		}

		len = ntfs_mbstoucs(p, &unicode, MAX_PATH);
		if (len < 0) {
			ntfs_log_error("Couldn't convert name to Unicode: %s.\n", p);
			goto close;
		}

		//ntfs_log_info("looking for %s in dir %lld\n", p, MREF(dir->mft_num));
		//ntfs_log_info("dir: index = %p, children = %p, inode = %p, iroot = %p, ialloc = %p, count = %d\n", dir->index, dir->children, dir->inode, dir->iroot, dir->ialloc, dir->child_count);
		//if (dir->parent)
		if (q) {
			ntfs_log_trace("q\n");
			child = ntfs_dir_find2(dir, unicode, len);
			if (!child) {
				ntfs_log_info("can't find %s in %s\n", p, pathname);
				goto close;
			}
		} else {
			ntfs_log_trace("!q dir->index = %p, %d\n", dir->index, dir->index->data_len);
			//ntfs_log_info("file: %s\n", p);

			dt = ntfs_dt_find2(dir->index, unicode, len, &dt_num);
			if (!dt) {
				ntfs_log_info("can't find %s in %s (2)\n", p, pathname);
				goto close;
			}
			ntfs_log_debug("dt = %p, data_len = %d, parent = %p\n", dt, dt->data_len, dt->parent);

			//ntfs_log_info("dt's flags = 0x%08x\n", dt->children[dt_num]->key.file_name.file_attributes);
			if (dt->children[dt_num]->key.file_name.file_attributes == FILE_ATTR_I30_INDEX_PRESENT) {
				//ntfs_log_info("DIR\n");
				child = ntfs_dir_create(dir->vol, dt->children[dt_num]->indexed_file);
				//ntfs_log_info("child = %p (%lld)\n", child, MREF(dt->children[dt_num]->indexed_file));
				if (child) {
					child->index = ntfs_dt_create(child, NULL, -1);
					ntfs_dir_add(dir, child);
				}

			}

			if (dt->inodes[dt_num] == NULL) {
				dt->inodes[dt_num] = ntfs_inode_open(dir->vol, dt->children[dt_num]->indexed_file);
				if (!dt->inodes[dt_num]) {
					ntfs_log_info("Can't open inode %lld\n", MREF(dt->children[dt_num]->indexed_file));
					goto close;
				}
				dt->inodes[dt_num]->ref_count = 2;
				dt->inodes[dt_num]->private_data = dt;
			}

			//ntfs_log_info("dt = %p,%d\n", dt, dt_num);
			break;
		}

		dir   = child;
		child = NULL;
		p = q;
		while (p && *p && *p == PATH_SEP)
			p++;
	}

	found->dir      = dir;
	found->dt       = dt;
	found->dt_index = dt_num;
	found->inode    = dt->inodes[dt_num];
	found->mref     = found->inode->mft_no;
	result = TRUE;
	//ntfs_log_info("dir %p, dt %p, num %d, ino %p, %lld\n", dir, dt, dt_num, dt->inodes[dt_num], MREF(found->inode->mft_no));
close:
	free(ascii);	// from strdup
	free(unicode);
	return result;
}


/**
 * ntfs_mft_find_free_entry
 */
static s64 ntfs_mft_find_free_entry(ntfs_volume *vol)
{
	MFT_REF i;
	u64 recs;

	if (!vol)
		return -1;

	ntfs_log_trace ("\n");
	recs = vol->mft_na->initialized_size >> vol->mft_record_size_bits;
	//ntfs_log_info("mft contains %lld records\n", recs);
	for (i = 24; i < recs; i++) {
		if (utils_mftrec_in_use(vol, i) == 0)
			return i;
	}
	return -1;
}

/**
 * ntfs_mft_set_inuse6
 */
static int ntfs_mft_set_inuse6(ntfs_inode *inode, struct ntfs_bmp *bmp, BOOL inuse)
{
	MFT_RECORD *rec;

	if (!inode)
		return -1;

	ntfs_log_trace("\n");
	if (ntfs_bmp_set_range(bmp, (VCN) MREF(inode->mft_no), 1, inuse) < 0)
		return -1;

	rec = (MFT_RECORD*) inode->mrec;

	// XXX extent inodes?

	if (inuse)
		rec->flags |= MFT_RECORD_IN_USE;
	else
		rec->flags &= ~MFT_RECORD_IN_USE;

	// XXX inc sequence number

	NInoSetDirty(inode);

	ntfs_log_info("Modified: inode %lld MFT_RECORD header\n", inode->mft_no);
	return 0;
}


/**
 * ntfs_file_remove
 */
static int ntfs_file_remove(ntfs_volume *vol, struct ntfs_dt *del, int del_num)
{
	struct ntfs_dir *find_dir = NULL;
	struct ntfs_dt *top = NULL;
	struct ntfs_dt *suc = NULL;
	struct ntfs_dt *old = NULL;
	struct ntfs_dt *par = NULL;
	struct ntfs_dt *ded = NULL;
	ntfschar *uname;
	int name_len;
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

	if (!vol || !del) {
		return 1;
	}

	ntfs_log_trace ("\n");
	find_dir = del->dir;

	uname    = del->children[del_num]->key.file_name.file_name;
	name_len = del->children[del_num]->key.file_name.file_name_length;

	top = del->dir->index;
	//ntfs_dt_find_all(top);
	//ntfs_dt_print(top, 0);

	del_ie = del->children[del_num];
	//utils_dump_mem(del_ie, 0, del_ie->length, DM_DEFAULTS);
	//ntfs_log_info("\n");

	/*
	 * If the key is not in a leaf node, then replace it with its successor.
	 * Continue the delete as if the successor had been deleted.
	 */

	/*
	for (i = 0; i < top->child_count; i++) {
		par_ie = top->children[i];
		file = &par_ie->key.file_name; ntfs_log_info("\ttop node, key %d: ", i); ntfs_name_print(file->file_name, file->file_name_length); ntfs_log_info("\n");
		ntfs_log_info("\tvcn = %lld\n", ntfs_ie_get_vcn(par_ie));
	}
	*/

	if (del->header->flags & INDEX_NODE) {
		ntfs_log_info("Replace key with its successor:\n");

		vcn = ntfs_ie_get_vcn(del_ie);
		//ntfs_log_info("vcn = %lld\n", vcn);

		suc = ntfs_dt_find4(find_dir->index, uname, name_len, &suc_num);
		//ntfs_log_info("succ = %p, index = %d\n", suc, suc_num);
		//ntfs_log_info("\n");

		suc_ie = ntfs_ie_copy(suc->children[suc_num]);
		//utils_dump_mem(suc_ie, 0, suc_ie->length, DM_BLUE|DM_GREEN|DM_INDENT);
		//ntfs_log_info("\n");

		suc_ie = ntfs_ie_set_vcn(suc_ie, vcn);
		//utils_dump_mem(suc_ie, 0, suc_ie->length, DM_BLUE|DM_GREEN|DM_INDENT);
		//ntfs_log_info("\n");

		file = &del_ie->key.file_name; ntfs_log_info("\trep name: "); ntfs_name_print(file->file_name, file->file_name_length); ntfs_log_info("\n");
		file = &suc_ie->key.file_name; ntfs_log_info("\tsuc name: "); ntfs_name_print(file->file_name, file->file_name_length); ntfs_log_info("\n");

		//utils_dump_mem(del->data, 0, del->data_len, DM_BLUE|DM_GREEN|DM_INDENT);
		if (ntfs_dt_isroot(del))
			res = ntfs_dt_root_replace(del, del_num, del_ie, suc_ie);
		else
			res = ntfs_dt_alloc_replace(del, del_num, del_ie, suc_ie);
		//ntfs_log_info("\n");
		//utils_dump_mem(del->data, 0, del->data_len, DM_BLUE|DM_GREEN|DM_INDENT);

		ntfs_ie_free(suc_ie);

		if (res == FALSE)
			goto done;

		del     = suc;		// Continue delete with the successor
		del_num = suc_num;
		del_ie  = suc->children[suc_num];
	}

	//ntfs_dt_print(top, 0);

	/*
	 * Now we have the simpler case of deleting from a leaf node.
	 * If this step creates an empty node, we have more to do.
	 */

	ntfs_log_info("\n");
	ntfs_log_info("Delete key:\n");

	file = &del->children[del_num]->key.file_name; ntfs_log_info("\tdel name: "); ntfs_name_print(file->file_name, file->file_name_length); ntfs_log_info("\n");

	//utils_dump_mem(del->data, 0, del->header->index_length+24, DM_BLUE|DM_GREEN|DM_INDENT);
	// XXX if del->child_count == 2, we could skip this step
	// no, if we combine with another node, we'll have to remember
	if (ntfs_dt_isroot(del))
		ntfs_dt_root_remove(del, del_num);
	else
		ntfs_dt_alloc_remove(del, del_num);
	//ntfs_log_info("\n");
	//utils_dump_mem(del->data, 0, del->header->index_length+24, DM_BLUE|DM_GREEN|DM_INDENT);

	if (del->child_count > 1)	// XXX ntfs_dt_empty (dt),  ntfs_dt_full (dt, new)
		goto commit;

	/*
	 * Ascend the tree until we find a node that is not empty.  Take the
	 * ancestor key and unhook it.  This will free up some space in the
	 * index allocation.  Finally add the ancestor to the node of its
	 * successor.
	 */

	// find the key nearest the root which has no descendants
	ntfs_log_info("\n");
	ntfs_log_info("Find childless parent:\n");
#if 0
	for (par = del->parent, old = par; par; old = par, par = par->parent) {
		if (par->child_count > 1)
			break;
		par_num = ntfs_dt_find_parent(par);
	}
#endif

	ntfs_log_info("del = %p, parent = %p\n", del, del->parent);
	par = del->parent;
	par_num = ntfs_dt_find_parent(del);

	//utils_dump_mem(par->data, 0, par->data_len, DM_BLUE|DM_GREEN|DM_INDENT);

	ntfs_log_info("par = %p, par->parent = %p, num = %d\n", par, par->parent, par_num);
	par_num = 0; // TEMP

	if (par) {
		file = &par->children[par_num]->key.file_name;
		ntfs_log_info("\tpar name: ");
		ntfs_name_print(file->file_name, file->file_name_length);
		ntfs_log_info("\n");
	}

	if (par == NULL) {
		// unhook everything
		goto freedts;
	}

	//ntfs_dt_print(top, 0);
	ntfs_log_info("\n");

	//utils_dump_mem(par->data, 0, par->data_len, DM_BLUE|DM_GREEN|DM_INDENT);
	//ntfs_log_info("\n");

	/*
	for (i = 0; i < top->child_count; i++) {
		par_ie = top->children[i];
		file = &par_ie->key.file_name; ntfs_log_info("\ttop node, key %d: ", i); ntfs_name_print(file->file_name, file->file_name_length); ntfs_log_info("\n");
		ntfs_log_info("\tvcn = %lld\n", ntfs_ie_get_vcn(par_ie));
	}
	*/

	// find if parent has left siblings
	if (par->children[par_num]->flags & INDEX_ENTRY_END) {
		ntfs_log_info("Swap the children of the parent and its left sibling\n");

		par_ie = par->children[par_num];
		vcn = ntfs_ie_get_vcn(par_ie);
		//ntfs_log_info("\toffset = %d\n", (u8*)par_ie - par->data); ntfs_log_info("\tflags = %d\n", par_ie->flags); ntfs_log_info("\tvcn = %lld\n", vcn); ntfs_log_info("\tlength = %d\n", par_ie->length);
		//utils_dump_mem(par_ie, 0, par_ie->length, DM_DEFAULTS);
		//ntfs_log_info("\n");

		//ntfs_log_info("\toffset = %d\n", (u8*)par_ie - par->data); ntfs_log_info("\tflags = %d\n", par_ie->flags); ntfs_log_info("\tvcn = %lld\n", vcn); ntfs_log_info("\tlength = %d\n", par_ie->length);
		//utils_dump_mem(par_ie, 0, par_ie->length, DM_DEFAULTS);
		//ntfs_log_info("\n");

		file = &par->children[par_num]  ->key.file_name; ntfs_log_info("\tpar name: "); ntfs_name_print(file->file_name, file->file_name_length); ntfs_log_info("\n");
		file = &par->children[par_num-1]->key.file_name; ntfs_log_info("\tsib name: "); ntfs_name_print(file->file_name, file->file_name_length); ntfs_log_info("\n");

		old                       = par->sub_nodes[par_num];
		par->sub_nodes[par_num]   = par->sub_nodes[par_num-1];
		par->sub_nodes[par_num-1] = old;

		par_ie = par->children[par_num-1];
		vcn = ntfs_ie_get_vcn(par_ie);

		par_ie = par->children[par_num];
		ntfs_ie_set_vcn(par_ie, vcn);

		par_num--;

		if (ntfs_dt_isroot(par))
			ntfs_log_info("Modified: inode %lld, $INDEX_ROOT\n", par->dir->inode->mft_no);
		else
			ntfs_log_info("Modified: inode %lld, $INDEX_ALLOCATION vcn %lld-%lld\n", par->dir->inode->mft_no, par->vcn, par->vcn + (par->dir->index_size>>9) - 1);
	}

	//ntfs_dt_print(top, 0);

	//ntfs_log_info("\n");
	//utils_dump_mem(par->data, 0, par->data_len, DM_DEFAULTS);

	// unhook and hold onto the ded dt's
	ntfs_log_info("\n");
	ntfs_log_info("Remove parent\n");

	file = &par->children[par_num]->key.file_name; ntfs_log_info("\tpar name: "); ntfs_name_print(file->file_name, file->file_name_length); ntfs_log_info("\n");

	add_ie = ntfs_ie_copy(par->children[par_num]);
	add_ie = ntfs_ie_remove_vcn(add_ie);
	if (!add_ie)
		goto done;

	//ntfs_log_info("\n");
	//utils_dump_mem(add_ie, 0, add_ie->length, DM_BLUE|DM_GREEN|DM_INDENT);

	ded = par->sub_nodes[par_num];
	par->sub_nodes[par_num] = NULL;
	//ntfs_dt_print(ded, 8);

#if 0
	for (i = 0; i < par->child_count; i++) {
		par_ie = par->children[i];
		file = &par_ie->key.file_name; ntfs_log_info("\tdel node, key %d: ", i); ntfs_name_print(file->file_name, file->file_name_length); ntfs_log_info("\n");
		ntfs_log_info("\tvcn = %lld\n", ntfs_ie_get_vcn(par_ie));
	}
#endif

#if 1
	//ntfs_log_info("PAR: %p,%d\n", par, par_num);
	if (ntfs_dt_isroot(par))
		ntfs_dt_root_remove(par, par_num);
	else
		ntfs_dt_alloc_remove(par, par_num);
#endif
	//ntfs_log_info("count = %d\n", par->child_count);
	//utils_dump_mem(par->data, 0, par->data_len, DM_DEFAULTS);
	//ntfs_log_info("0x%x\n", (u8*)par->children[0] - par->data);

#if 0
	for (i = 0; i < par->child_count; i++) {
		par_ie = par->children[i];
		file = &par_ie->key.file_name; ntfs_log_info("\tadd node, key %d: ", i); ntfs_name_print(file->file_name, file->file_name_length); ntfs_log_info("\n");
		ntfs_log_info("\tvcn = %lld\n", ntfs_ie_get_vcn(par_ie));
	}
#endif

	//ntfs_dt_print(top, 0);
	ntfs_log_info("\n");
	ntfs_log_info("Add childless parent\n");

	file = &add_ie->key.file_name; ntfs_log_info("\tadd name: "); ntfs_name_print(file->file_name, file->file_name_length); ntfs_log_info("\n");
	suc     = NULL;
	suc_num = -1;
	suc = ntfs_dt_find4(top, file->file_name, file->file_name_length, &suc_num);
	//ntfs_log_info("SUC: %p, %d\n", suc, suc_num);

	if (!suc)
		goto done;

	file = &suc->children[suc_num]->key.file_name; ntfs_log_info("\tsuc name: "); ntfs_name_print(file->file_name, file->file_name_length); ntfs_log_info("\n");

	// insert key into successor
	// if any new nodes are needed, reuse the preserved nodes
	if (!ntfs_dt_add2(add_ie, suc, suc_num, ded))
		goto done;

	// remove any unused nodes

	// XXX mark dts, dirs and inodes dirty
	// XXX add freed dts to a list for immediate reuse (attach to dir?)
	// XXX any ded dts means we may need to adjust alloc
	// XXX commit will free list of spare dts
	// XXX reduce size of alloc
	// XXX if ded, don't write it back, just update bitmap

	ntfs_log_info("empty\n");
	goto done;

freedts:
	ntfs_log_info("\twhole dir is empty\n");

commit:
	//ntfs_log_info("commit\n");

done:
	return 0;
}

/**
 * ntfs_file_remove2
 */
static int ntfs_file_remove2(ntfs_volume *vol, struct ntfs_dt *dt, int dt_num)
{
	INDEX_ENTRY *ie;
	ntfs_inode *ino;
	struct ntfs_bmp *bmp_mft;
	struct ntfs_bmp *bmp_vol;
	struct ntfs_dir *dir;

	if (!vol || !dt)
		return -1;

	ntfs_log_trace ("\n");
	ie  = dt->children[dt_num];
	ino = dt->inodes[dt_num];
	dir = dt->dir;

	bmp_mft = vol->private_bmp1;
	bmp_vol = vol->private_bmp2;

	if (1) ntfs_mft_set_inuse6(ino, bmp_mft, FALSE);

	if (1) utils_free_non_residents2(ino, bmp_vol);

	if (1) ntfs_file_remove(vol, dt, dt_num); // remove name from index

	if (1) ntfs_dir_truncate(vol, dt->dir);

	if (1) ntfs_volume_commit(vol);

	if (0) ntfs_volume_rollback(vol);

	if (0) ntfs_log_info("last mft = %lld\n", ntfs_bmp_find_last_set(bmp_mft));
	if (0) ntfs_log_info("last vol = %lld\n", ntfs_bmp_find_last_set(bmp_vol));

	return 0;
}

/**
 * ntfs_file_add2
 */
static int ntfs_file_add2(ntfs_volume *vol, char *filename)
{
	MFT_REF new_num;
	char *ptr = NULL;
	char *dirname = NULL;
	struct ntfs_find find;
	INDEX_ENTRY *ie = NULL;
	ntfschar *uname = NULL;
	int uname_len = 0;
	ntfs_inode *ino = NULL;
	u8 *tmp = NULL;
	u8 *buffer = NULL;
	s64 now = 0;
	struct ntfs_dir *dir;
	struct ntfs_dt *dt;
	int dt_index = 0;
	int data_len = 0;
	ATTR_RECORD *attr;
	struct ntfs_dt *suc = NULL;
	int suc_num = 0;

	ntfs_log_trace("\n");
	new_num = ntfs_mft_find_free_entry(vol);
	if (new_num == (MFT_REF) -1)
		return 1;

	if (rindex(filename, PATH_SEP)) {
		ptr = rindex(filename, PATH_SEP);
		*ptr = 0;
		dirname = filename;
		filename = ptr + 1;
	}

	ntfs_log_info("looking for %s\n", dirname);
	if (utils_pathname_to_inode2(vol, NULL, dirname, &find) == FALSE) {
		ntfs_log_info("!inode\n");
		return 0;
	}

	dt  = find.dt;
	dir = find.dir;

	uname_len = ntfs_mbstoucs(filename, &uname, 0);
	if (uname_len < 0)
		goto close;

	ntfs_log_info("new inode %lld\n", new_num);
	ino = ntfs_inode_open3(vol, new_num);
	if (!ino) {
		ntfs_log_info("!ino\n");
		goto close;
	}

	tmp = (u8*) ino->mrec;
	now = utc2ntfs(time(NULL));

	// Wipe all the attributes
	memset(tmp + ino->mrec->attrs_offset, 0, vol->mft_record_size - ino->mrec->attrs_offset);

	// Add new end marker
	*(u32*) (tmp + ino->mrec->attrs_offset) = 0xFFFFFFFF;
	ino->mrec->bytes_in_use = ino->mrec->attrs_offset + 8;

	// Reset headers...
	ino->mrec->lsn = 0;
	ino->mrec->link_count = 1;
	ino->mrec->base_mft_record = 0;
	ino->mrec->next_attr_instance = 0;
	ino->mrec->flags = MFT_RECORD_IN_USE;

	ntfs_mft_set_inuse6(ino, vol->private_bmp1, TRUE);

	buffer = malloc(128);
	if (!buffer)
		goto close;

	// Standard information
	memset(buffer, 0, 128);
	*(u64*)(buffer + 0x00) = now;		// Time
	*(u64*)(buffer + 0x08) = now;		// Time
	*(u64*)(buffer + 0x10) = now;		// Time
	*(u64*)(buffer + 0x18) = now;		// Time
	ino->creation_time         = time(NULL);
	ino->last_data_change_time = time(NULL);
	ino->last_mft_change_time  = time(NULL);
	ino->last_access_time      = time(NULL);
	attr = ntfs_mft_add_attr(ino, AT_STANDARD_INFORMATION, buffer, 0x48);

	// Data
	memset(buffer, 0, 128);
	data_len = sprintf((char*)buffer, "Contents of file: %s\n", filename);
	attr = ntfs_mft_add_attr(ino, AT_DATA, buffer, data_len);

	// File name
	memset(buffer, 0, 128);
	*(u64*)(buffer + 0x00) = MK_MREF(find.mref, 2);	// MFT Ref of parent dir
	*(u64*)(buffer + 0x08) = now;				// Time
	*(u64*)(buffer + 0x10) = now;				// Time
	*(u64*)(buffer + 0x18) = now;				// Time
	*(u64*)(buffer + 0x20) = now;				// Time
	*(u64*)(buffer + 0x28) = ATTR_SIZE(data_len);		// Allocated size
	*(u64*)(buffer + 0x30) = data_len;			// Initialised size
	*(u32*)(buffer + 0x38) = 0;				// Flags
	*(u32*)(buffer + 0x3C) = 0;				// Not relevant
	*(u8* )(buffer + 0x40) = uname_len;			// Filename length
	*(u8* )(buffer + 0x41) = FILE_NAME_POSIX;		// Filename namespace
	memcpy(buffer + 0x42, uname, uname_len * sizeof(ntfschar));
	attr = ntfs_mft_add_attr(ino, AT_FILE_NAME, buffer, ATTR_SIZE(0x42 + (uname_len * sizeof(ntfschar))));
	attr->resident_flags = RESIDENT_ATTR_IS_INDEXED;
	attr->name_offset = 0x18;

	ie = ntfs_ie_create();
	ie = ntfs_ie_set_name(ie, uname, uname_len, FILE_NAME_POSIX);
	if (!ie) {
		ntfs_log_info("!ie\n");
		goto close;
	}

	// These two NEED the sequence number in the top 8 bits
	ie->key.file_name.parent_directory      = MK_MREF(find.mref, 2);// MFT Ref: parent dir
	ie->indexed_file = MK_MREF(new_num, ino->mrec->sequence_number);

	ie->key.file_name.creation_time         = now;
	ie->key.file_name.last_data_change_time = now;
	ie->key.file_name.last_mft_change_time  = now;
	ie->key.file_name.last_access_time      = now;
	ie->key.file_name.allocated_size        = ATTR_SIZE(data_len);
	ie->key.file_name.data_size             = data_len;

	dir = dt->dir->children[0];
	dt = dir->index;

	ntfs_log_debug("searching for "); ntfs_name_print(uname, uname_len); ntfs_log_debug("\n");
	// find3 doesn't map new dts.  don't I _want_ to map them?
	suc = ntfs_dt_find3(dt, uname, uname_len, &suc_num);

	ntfs_log_debug("dt = %p, data_len = %d, parent = %p\n", dt, dt->data_len, dt->parent);

	//dt_index = ntfs_dt_root_add(dt, ie);
	dt_index = ntfs_dt_add2(ie, suc, suc_num, NULL);
	if (dt_index >= 0) {
		dt->inodes[dt_index] = ino;
		ino->ref_count++;
	}

close:
	ntfs_log_debug("working inode refcount = %d\n", ino->ref_count);
	free(buffer);
	ntfs_inode_close2(ino);
	ntfs_ie_free(ie);
	free(uname);
	ntfs_inode_close2(find.inode);
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
int main(int argc, char *argv[])
{
	ntfs_volume *vol = NULL;
	ntfs_inode *inode = NULL;
	int flags = 0;
	int result = 1;
	struct ntfs_find find;

	ntfs_log_set_handler (ntfs_log_handler_stdout);
	ntfs_log_set_levels (NTFS_LOG_LEVEL_TRACE);
	ntfs_log_set_flags (NTFS_LOG_FLAG_COLOUR);

	ntfs_log_trace ("\n");
	if (!parse_options(argc, argv))
		goto done;

	utils_set_locale();

#if 0
	ntfs_log_info("sizeof(ntfs_bmp)   = %d\n", sizeof(struct ntfs_bmp));
	ntfs_log_info("sizeof(ntfs_dt)    = %d\n", sizeof(struct ntfs_dt));
	ntfs_log_info("sizeof(ntfs_dir)   = %d\n", sizeof(struct ntfs_dir));
	ntfs_log_info("\n");
#endif

	if (opts.noaction)
		flags |= MS_RDONLY;

	//ntfs_log_set_levels (NTFS_LOG_LEVEL_DEBUG | NTFS_LOG_LEVEL_TRACE);
	//ntfs_log_set_levels (NTFS_LOG_LEVEL_DEBUG);
	vol = ntfs_volume_mount2(opts.device, flags, opts.force);
	if (!vol) {
		ntfs_log_info("!vol\n");
		goto done;
	}

#if 0
	if (utils_pathname_to_inode2(vol, NULL, opts.file, &find) == FALSE) {
		ntfs_log_info("!inode\n");
		goto done;
	}

	inode = find.inode;
#endif

	//ntfs_log_info("inode = %lld\n", inode->mft_no);

	if (0) result = ntfs_file_remove2(vol, find.dt, find.dt_index);
	if (1) result = ntfs_file_add2(vol, opts.file);

done:
	if (1) ntfs_volume_commit(vol);
	if (0) ntfs_volume_rollback(vol);
	if (0) ntfs_inode_close2(inode);
	if (1) ntfs_volume_umount2(vol, FALSE);

	//ntfs_log_clear_levels(NTFS_LOG_LEVEL_DEBUG | NTFS_LOG_LEVEL_TRACE);
	if (0) utils_pathname_to_inode2(NULL, NULL, NULL, NULL);
	if (0) ntfs_ie_remove_name(NULL);
	if (0) ntfs_dt_transfer2(NULL, NULL, 0, 0);
	if (0) utils_array_remove(NULL, 0, 0, 0);
	if (0) utils_array_insert(NULL, 0, 0, 0);

	ntfs_log_trace("result = %d\n", result);
	return result;
}

