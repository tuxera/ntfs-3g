/**
 * ntfscp - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2004 Yura Pakhuchiy
 *
 * This utility will overwrite files on ntfs volume
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
#include <sys/stat.h>

#include "types.h"
#include "attrib.h"
#include "utils.h"
#include "volume.h"
#include "debug.h"

struct options {
	char		*device;	/* Device/File to work with */
	char		*src_file;	/* Source file */
	char		*dest_file;	/* Destination file */
	int		 force;		/* Override common sense */
	int		 quiet;		/* Less output */
	int		 verbose;	/* Extra output */
	int		 noaction;	/* Do not write to disk */
};

static const char *EXEC_NAME = "ntfscp";
static struct options opts;

GEN_PRINTF (Eprintf, stderr, NULL,          FALSE)
GEN_PRINTF (Vprintf, stderr, &opts.verbose, TRUE)
GEN_PRINTF (Qprintf, stderr, &opts.quiet,   FALSE)
static GEN_PRINTF (Printf,  stderr, NULL,   FALSE)

/**
 * version - Print version information about the program
 *
 * Print a copyright statement and a brief description of the program.
 *
 * Return:  none
 */
static void version (void)
{
	Printf ("\n%s v%s - Overwrite files on NTFS volume.\n\n",
		EXEC_NAME, VERSION);
	Printf ("Copyright (c) 2004 Yura Pakhuchiy\n");
	Printf ("\n%s\n%s%s\n", ntfs_gpl, ntfs_bugs, ntfs_home);
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
	Printf ("\nUsage: %s [options] device src_file dest_file\n\n"
		"    -f  --force           Use less caution\n"
		"    -h  --help            Print this help\n"
		"    -n  --no-action       Do not write to disk\n"
		"    -q  --quiet           Less output\n"
		"    -V  --version         Version information\n"
		"    -v  --verbose         More output\n\n",
		EXEC_NAME);
	Printf ("%s%s\n", ntfs_bugs, ntfs_home);
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
	static const char *sopt = "-fh?nqVv";
	static const struct option lopt[] = {
		{ "force",	no_argument,		NULL, 'f' },
		{ "help",	no_argument,		NULL, 'h' },
		{ "no-action",	no_argument,		NULL, 'n' },
		{ "quiet",	no_argument,		NULL, 'q' },
		{ "version",	no_argument,		NULL, 'V' },
		{ "verbose",	no_argument,		NULL, 'v' },
		{ NULL,		0,			NULL, 0   }
	};

	char c = -1;
	int err  = 0;
	int ver  = 0;
	int help = 0;
	
	opts.device = 0;
	opts.src_file = 0;
	opts.dest_file = 0;

	opterr = 0; /* We'll handle the errors, thank you. */

	while ((c = getopt_long (argc, argv, sopt, lopt, NULL)) != (char)-1) {
		switch (c) {
		case 1:	/* A non-option argument */
			if (!opts.device) {
				opts.device = argv[optind-1];
			} else if (!opts.src_file) {
				opts.src_file = argv[optind-1];
			} else if (!opts.dest_file) {
				opts.dest_file = argv[optind-1];
			} else {
				Eprintf("You must specify exactly two files.\n");
				err++;
			}
			break;
		case 'f':
			opts.force++;
			break;
		case 'h':
		case '?':
			help++;
			break;
		case 'n':
			opts.noaction++;
			break;
		case 'q':
			opts.quiet++;
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
		if (!opts.device) {
		       	Eprintf ("You must specify a device.\n");
			err++;
		} else if (!opts.src_file) {
			Eprintf ("You must specify a source file.\n");
			err++;
		} else if (!opts.dest_file) {
			Eprintf ("You must specify a destination file.\n");
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
 * main - Begin here
 *
 * Start from here.
 *
 * Return:  0  Success, the program worked
 *	    1  Error, something went wrong
 */
int main (int argc, char *argv[])
{
	FILE *in;
	ntfs_volume *vol;
	ntfs_inode *out;
	ntfs_attr *na;
//	ntfs_attr_search_ctx *ctx;
//	FILE_NAME_ATTR *fna;
	int flags = 0;
	int result = 1;
	s64 new_size;
	int need_logfile_reset = 0;
	u64 offset;
	char *buf;
	s64 br, bw;

	if (!parse_options (argc, argv))
		return 1;

	utils_set_locale();
	
	if (opts.noaction)
		flags = MS_RDONLY;

	vol = utils_mount_volume (opts.device, flags, opts.force);
	if (!vol) {
 		perror("ERROR: couldn't mount volume");
		return 1;
	}
	
	if ((vol->flags & VOLUME_IS_DIRTY) && (!opts.force))
		goto umount;

	{
	struct stat fst;
	if (stat (opts.src_file, &fst) == -1) {
		perror ("ERROR: Couldn't stat source file\n");
		goto umount;
	}
	new_size = fst.st_size;
	}
	Vprintf ("New file size: %lld\n", new_size);

	in = fopen (opts.src_file, "r");
	if (!in) {
		perror ("ERROR: Couldn't open source file");
		goto umount;
	}

	out = utils_pathname_to_inode (vol, NULL, opts.dest_file);
	if (!out) {
 		perror ("ERROR: Couldn't open destination file");
		goto close_src;
	}
	
	na = ntfs_attr_open (out, AT_DATA, 0, 0);
	if (!na) {
		perror ("ERROR: Couldn't open $DATA attribute");
		goto close_dst;
	}
	
	Vprintf ("Old file size: %lld\n", na->data_size);
	if (na->data_size != new_size) {
		if (ntfs_attr_truncate (na, new_size)) {
			perror ("ERROR: Couldn't resize $DATA attribute");
			goto close_attr;
		}
		need_logfile_reset = 1;
		
		/*
		 * Update $FILE_NAME(0x30) attributes for new file size.
		 * This code now commented, because Windows does not update
		 * them unless a rename operation occur.
		 */
		/*
		ctx = ntfs_attr_get_search_ctx(out, NULL);
		if (!ctx) {
			perror("ERROR: Couldn't get search context");
			goto close_attr;
		}
		while (!ntfs_attr_lookup(AT_FILE_NAME, 0, 0, 0, 0, NULL, 0,
									ctx)) {
			fna = (FILE_NAME_ATTR *)((u8*)ctx->attr +
					le16_to_cpu(ctx->attr->value_offset));
			if (sle64_to_cpu(fna->allocated_size) ||
						sle64_to_cpu(fna->data_size)) {
				fna->allocated_size = cpu_to_sle64(
							na->allocated_size);
				fna->data_size = cpu_to_sle64(na->data_size);
				ntfs_inode_mark_dirty(ctx->ntfs_ino);
			}
		}
		if (errno != ENOENT)
			perror("ERROR: Attribute lookup failed");
		ntfs_attr_put_search_ctx(ctx);
		*/
	}

	buf = malloc (NTFS_BUF_SIZE);
	if (!buf) {
		perror ("ERROR: malloc failed");
		goto close_attr;
	}

	offset = 0;
	while (!feof (in)) {
		br = fread (buf, 1, NTFS_BUF_SIZE, in);
		if (!br) {
			if (!feof (in))	perror ("ERROR: fread failed");
			break;
		}
		
		bw = ntfs_attr_pwrite (na, offset, br, buf);
		if (bw != br) {
			perror ("ERROR: ntfs_attr_pwrite failed");
			break;
		}
		offset += bw;
	}
	need_logfile_reset = 1;

	free (buf);
close_attr:
	ntfs_attr_close (na);
close_dst:
	ntfs_inode_close (out);

	if (need_logfile_reset) {
		printf ("Resetting logfile.\n");
		ntfs_logfile_reset (vol);
	}

close_src:
	fclose (in);
umount:
	ntfs_umount (vol, FALSE);

	return result;
}
