/**
 * ntfsls - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2003 Lode Leroy
 * Copyright (c) 2003 Anton Altaparmakov
 * Copyright (c) 2003 Richard Russon
 *
 * This utility will list a directory's files.
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
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>
#include <string.h>

#include "types.h"
#include "mft.h"
#include "attrib.h"
#include "layout.h"
#include "inode.h"
#include "utils.h"
#include "dir.h"

static const char *EXEC_NAME = "ntfsls";

static struct options {
	char *device;	/* Device/File to work with */
	int quiet;	/* Less output */
	int verbose;	/* Extra output */
	int force;	/* Override common sense */
	int all;
	int system;
	int dos;
	int lng;
	int inode;
	int classify;
	char *path;
} opts;

GEN_PRINTF(Eprintf, stderr, NULL,          FALSE)
GEN_PRINTF(Vprintf, stdout, &opts.verbose, TRUE)
GEN_PRINTF(Qprintf, stdout, &opts.quiet,   FALSE)

/**
 * version - Print version information about the program
 *
 * Print a copyright statement and a brief description of the program.
 *
 * Return:  none
 */
void version(void)
{
	printf("\n%s v%s - Display information about an NTFS Volume.\n\n",
			EXEC_NAME, VERSION);
	printf("Copyright (c) 2003 Lode Leroy\n");
	printf("Copyright (c) 2003 Anton Altaparmakov\n");
	printf("Copyright (c) 2003 Richard Russon\n");
	printf("\n%s\n%s%s\n", ntfs_gpl, ntfs_bugs, ntfs_home);
}

/**
 * usage - Print a list of the parameters to the program
 *
 * Print a list of the parameters and options for the program.
 *
 * Return:  none
 */
void usage(void)
{
	printf("\nUsage: %s [options] -d /dev/hda1\n"
		"\n"
		"    -a         --all            Display all files\n"
		"    -d DEVICE  --device DEVICE  NTFS volume\n"
		"    -F         --classify       Display classification\n"
		"    -f         --force          Use less caution\n"
		"    -h   -?    --help           Display this help\n"
		"    -i         --inode          Display inode numbers\n"
		"    -l         --long           Display long info\n"
		"    -p PATH    --path PATH      Directory whose contents to list\n"
		"    -q         --quiet          Less output\n"
		"    -s         --system         Display system files\n"
		"    -V         --version        Display version information\n"
		"    -v         --verbose        More output\n"
		"    -x         --dos            Use short (DOS 8.3) names\n"
		"\n",
		EXEC_NAME);
	printf("%s%s\n", ntfs_bugs, ntfs_home);
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
int parse_options(int argc, char *argv[])
{
	static const char *sopt = "-ad:Ffh?ilp:qsVvx";
	static const struct option lopt[] = {
		{ "all",	 no_argument,		NULL, 'a' },
		{ "device",      required_argument,	NULL, 'd' },
		{ "classify",	 no_argument,		NULL, 'F' },
		{ "force",	 no_argument,		NULL, 'f' },
		{ "help",	 no_argument,		NULL, 'h' },
		{ "inode",	 no_argument,		NULL, 'i' },
		{ "long",	 no_argument,		NULL, 'l' },
		{ "path",	 required_argument,     NULL, 'p' },
		{ "quiet",	 no_argument,		NULL, 'q' },
		{ "system",	 no_argument,		NULL, 's' },
		{ "version",	 no_argument,		NULL, 'V' },
		{ "verbose",	 no_argument,		NULL, 'v' },
		{ "dos",	 no_argument,		NULL, 'x' },
		{ NULL, 0, NULL, 0 },
	};

	char c = -1;
	int err  = 0;
	int ver  = 0;
	int help = 0;

	opterr = 0; /* We'll handle the errors, thank you. */

	memset(&opts, 0, sizeof(opts));
	opts.device = NULL;
	opts.path = "/";

	while ((c = getopt_long(argc, argv, sopt, lopt, NULL)) != (char)-1) {
		switch (c) {
		case 'd':
			opts.device = optarg;
			break;
		case 'p':
			opts.path = optarg;
			break;
		case 'f':
			opts.force++;
			break;
		case 'h':
		case '?':
			help++;
			break;
		case 'q':
			opts.quiet++;
			break;
		case 'v':
			opts.verbose++;
			break;
		case 'V':
			ver++;
			break;
		case 'x':
			opts.dos = 1;
			break;
		case 'l':
			opts.lng++;
			break;
		case 'i':
			opts.inode++;
			break;
		case 'F':
			opts.classify++;
			break;
		case 'a':
			opts.all++;
			break;
		case 's':
			opts.system++;
			break;
		default:
			Eprintf("Unknown option '%s'.\n", argv[optind - 1]);
			err++;
			break;
		}
	}

	if (help || ver)
		opts.quiet = 0;
	else {
		if (opts.device == NULL) {
			if (argc > 1)
				Eprintf("You must specify exactly one "
						"device.\n");
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

typedef struct {
	ntfs_volume *vol;
} ntfsls_dirent;

/**
 * list_entry
 * FIXME: Should we print errors as we go along? (AIA)
 */
int list_entry(ntfsls_dirent *dirent, const uchar_t *name, 
		const int name_len, const int name_type, const s64 pos,
		const MFT_REF mref, const unsigned dt_type)
{
	char *filename = NULL;
	int result = 0;

	filename = calloc (1, MAX_PATH);
	if (!filename)
		return -1;

	if (ntfs_ucstombs (name, name_len, &filename, MAX_PATH) < 0) {
		Eprintf ("Cannot represent filename in current locale.\n");
		goto free;
	}

	result = 0;					// These are successful
	if ((filename[0] == '$') && (!opts.system))
		goto free;
	if (name_type == FILE_NAME_POSIX && !opts.all)
		goto free;
	if (((name_type & FILE_NAME_WIN32_AND_DOS) == FILE_NAME_WIN32) &&
			opts.dos)
		goto free;
	if (((name_type & FILE_NAME_WIN32_AND_DOS) == FILE_NAME_DOS) &&
			!opts.dos)
		goto free;
	if (dt_type == NTFS_DT_DIR && opts.classify)
		sprintf(filename + strlen(filename), "/");

	if (!opts.lng) {
		if (!opts.inode)
			printf("%s\n", filename);
		else
			printf("%7llu %s\n", (unsigned long long)MREF(mref),
					filename);
		result = 0;
	} else {
		s64 filesize = 0;
		ntfs_inode *ni;
		ntfs_attr_search_ctx *ctx = NULL;
		FILE_NAME_ATTR *file_name_attr;
		ATTR_RECORD *attr;
		time_t ntfs_time;
		char t_buf[26];

		result = -1;				// Everything else is bad

		ni = ntfs_inode_open(dirent->vol, mref);
		if (!ni)
			goto release;

		ctx = ntfs_attr_get_search_ctx(ni, ni->mrec);
		if (!ctx)
			goto release;

		if (ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, 0, 0, NULL,
				0, ctx))
			goto release;
		attr = ctx->attr;

		file_name_attr = (FILE_NAME_ATTR *)((char *)attr +
				le16_to_cpu(attr->value_offset));
		if (!file_name_attr)
			goto release;

		ntfs_time = ntfs2utc(sle64_to_cpu(
				file_name_attr->last_data_change_time));
		strcpy(t_buf, ctime(&ntfs_time));
		t_buf[16] = '\0';

		if (dt_type != NTFS_DT_DIR) {
			if (!ntfs_attr_lookup(AT_DATA, AT_UNNAMED, 0, 0, 0,
					NULL, 0, ctx))
				filesize = ntfs_get_attribute_value_length(
						ctx->attr);
		}

		if (opts.inode)
			printf("%7llu    %8lld %s %s\n",
					(unsigned long long)MREF(mref),
					(long long)filesize, t_buf + 4,
					filename);
		else
			printf("%8lld %s %s\n", (long long)filesize, t_buf + 4,
					filename);

		result = 0;
release:
		/* Release atrtibute search context and close the inode. */
		if (ctx)
			ntfs_attr_put_search_ctx(ctx);
		if (ni)
			ntfs_inode_close(ni);
	}
free:
	free (filename);
	return result;
}

/**
 * main - Begin here
 *
 * Start from here.
 *
 * Return:  0  Success, the program worked
 *	    1  Error, parsing mount options failed
 *	    2  Error, mount attempt failed
 *	    3  Error, failed to open root directory
 *	    4  Error, failed to open directory in search path
 */
int main(int argc, char **argv)
{
	s64 pos;
	ntfs_volume *vol;
	ntfs_inode *ni;
	ntfsls_dirent dirent;

	if (!parse_options(argc, argv)) {
		// FIXME: Print error... (AIA)
		return 1;
	}

	utils_set_locale();

	vol = utils_mount_volume(opts.device, MS_RDONLY, opts.force);
	if (!vol) {
		// FIXME: Print error... (AIA)
		return 2;
	}

	ni = utils_pathname_to_inode (vol, NULL, opts.path);
	if (!ni) {
		// FIXME: Print error... (AIA)
		ntfs_umount(vol, FALSE);
		return 3;
	}

	/*
	 * We now are at the final path component.  If it is a file just
	 * list it.  If it is a directory, list its contents.
	 */
	pos = 0;
	memset(&dirent, 0, sizeof(dirent));
	dirent.vol = vol;
	if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
		ntfs_readdir(ni, &pos, &dirent, (ntfs_filldir_t)list_entry);
		// FIXME: error checking... (AIA)
	} else {
		ATTR_RECORD *rec;
		FILE_NAME_ATTR *attr;
		ntfs_attr_search_ctx *ctx;
		int space = 4;
		uchar_t *name = NULL;
		int name_len = 0;;

		ctx = ntfs_attr_get_search_ctx (NULL, ni->mrec);
		if (!ctx)
			return -1;

		while ((rec = find_attribute (AT_FILE_NAME, ctx))) {
			/* We know this will always be resident. */
			attr = (FILE_NAME_ATTR *) ((char *) rec + le16_to_cpu (rec->value_offset));

			if (attr->file_name_type < space) {
				name     = attr->file_name;
				name_len = attr->file_name_length;
				space    = attr->file_name_type;
			}
		}

		list_entry(&dirent, name, name_len, space, pos, ni->mft_no, NTFS_DT_REG);
		// FIXME: error checking... (AIA)

		ntfs_attr_put_search_ctx(ctx);
	}

	/* Finished with the inode; release it. */
	ntfs_inode_close(ni);

	ntfs_umount(vol, FALSE);
	return 0;
}

