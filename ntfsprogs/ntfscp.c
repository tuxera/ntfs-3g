/**
 * ntfscp - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2004-2005 Yura Pakhuchiy
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
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include "types.h"
#include "attrib.h"
#include "utils.h"
#include "volume.h"
#include "debug.h"

struct options {
	char		*device;	/* Device/File to work with */
	char		*src_file;	/* Source file */
	char		*dest_file;	/* Destination file */
	char		*attr_name;	/* Write to attribute with this name. */
	int		 force;		/* Override common sense */
	int		 quiet;		/* Less output */
	int		 verbose;	/* Extra output */
	int		 noaction;	/* Do not write to disk */
	ATTR_TYPES	 attribute;	/* Write to this attribute. */
	int		 inode;		/* Treat dest_file as inode number. */
};

static const char *EXEC_NAME = "ntfscp";
static struct options opts;
static int caught_sigint = 0;

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
		"    -a  --attribute num   Write to this attribute\n"
		"    -i  --inode           Treat dest_file as inode number\n"
		"    -f  --force           Use less caution\n"
		"    -h  --help            Print this help\n"
		"    -N  --attr-name name  Write to attribute with this name\n"
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
	static const char *sopt = "-a:ifh?N:nqVv";
	static const struct option lopt[] = {
		{ "attribute",	required_argument,	NULL, 'a' },
		{ "inode",	no_argument,		NULL, 'i' },
		{ "force",	no_argument,		NULL, 'f' },
		{ "help",	no_argument,		NULL, 'h' },
		{ "attr-name",	required_argument,	NULL, 'N' },		
		{ "no-action",	no_argument,		NULL, 'n' },
		{ "quiet",	no_argument,		NULL, 'q' },
		{ "version",	no_argument,		NULL, 'V' },
		{ "verbose",	no_argument,		NULL, 'v' },
		{ NULL,		0,			NULL, 0   }
	};

	char *s;
	char c = -1;
	int err  = 0;
	int ver  = 0;
	int help = 0;
	s64 attr;
	
	opts.device = NULL;
	opts.src_file = NULL;
	opts.dest_file = NULL;
	opts.attr_name = NULL;
	opts.inode = 0;
	opts.attribute = AT_DATA;

	opterr = 0; /* We'll handle the errors, thank you. */

	while ((c = getopt_long(argc, argv, sopt, lopt, NULL)) != (char) -1) {
		switch (c) {
		case 1:	/* A non-option argument */
			if (!opts.device) {
				opts.device = argv[optind - 1];
			} else if (!opts.src_file) {
				opts.src_file = argv[optind - 1];
			} else if (!opts.dest_file) {
				opts.dest_file = argv[optind - 1];
			} else {
				Eprintf("You must specify exactly 2 files.\n");
				err++;
			}
			break;
		case 'a':
			if (opts.attribute != AT_DATA) {
				Eprintf("You can specify only 1 attribute.\n");
				err++;
				break;
			}

			attr = strtol(optarg, &s, 0);
			if (*s) {
				Eprintf("Coudn't parse attribute.\n");
				err++;
			} else
				opts.attribute = (ATTR_TYPES)attr;
			break;
		case 'i':
			opts.inode++;
			break;
		case 'f':
			opts.force++;
			break;
		case 'h':
		case '?':
			help++;
			break;
		case 'N':
			if (opts.attr_name) {
				Eprintf("You can specify only one attribute "
						"name.\n");
				err++;
			} else 
				opts.attr_name = argv[optind - 1];
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
			Eprintf("Unknown option '%s'.\n", argv[optind - 1]);
			err++;
			break;
		}
	}

	if (help || ver) {
		opts.quiet = 0;
	} else {
		if (!opts.device) {
		       	Eprintf("You must specify a device.\n");
			err++;
		} else if (!opts.src_file) {
			Eprintf("You must specify a source file.\n");
			err++;
		} else if (!opts.dest_file) {
			Eprintf("You must specify a destination file.\n");
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
 * sigint_handler - Handle SIGINT: abort write, sync and exit.
 */
static void sigint_handler(int arg __attribute__((unused)))
{
	caught_sigint++;
	if (caught_sigint > 3) {
		Eprintf("SIGTERM received more than 3 times. "
				"Exit immediately.\n");
		exit(2);
	} else
		Eprintf("SIGTERM received. Aborting write.\n");
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
	int flags = 0;
	int result = 1;
	s64 new_size;
	u64 offset;
	char *buf;
	s64 br, bw;
	ntfschar *attr_name = NULL;
	int attr_name_len = 0;

	if (!parse_options(argc, argv))
		return 1;

	utils_set_locale();

	/* Set SIGINT handler. */
	if (signal(SIGINT, sigint_handler) == SIG_ERR) {
		perror("Failed to set SIGINT handler");
		return 1;
	}

	if (opts.noaction)
		flags = MS_RDONLY;

	vol = utils_mount_volume(opts.device, flags, opts.force);
	if (!vol) {
 		perror("ERROR: couldn't mount volume");
		return 1;
	}

	if ((vol->flags & VOLUME_IS_DIRTY) && (!opts.force))
		goto umount;

	{
		struct stat fst;
		if (stat (opts.src_file, &fst) == -1) {
			perror("ERROR: Couldn't stat source file");
			goto umount;
		}
		new_size = fst.st_size;
	}
	Vprintf("New file size: %lld\n", new_size);

	in = fopen(opts.src_file, "r");
	if (!in) {
		perror("ERROR: Couldn't open source file");
		goto umount;
	}

	if (opts.inode) {
		s64 inode_num;
		char *s;

		inode_num = strtoll(opts.dest_file, &s, 0);
		if (*s) {
			Eprintf("ERROR: Couldn't parse inode number.\n");
			goto close_src;
		}
		out = ntfs_inode_open(vol, inode_num);
	} else
		out = utils_pathname_to_inode(vol, NULL, opts.dest_file);
	if (!out) {
 		perror("ERROR: Couldn't open destination file");
		goto close_src;
	}
	if ((le16_to_cpu(out->mrec->flags) & MFT_RECORD_IS_DIRECTORY) &&
			!opts.inode){
		/*
		 * @out is directory and it was specified by pathname, add
		 * filename to path and reopen inode.
		 */
		char *filename, *new_dest_file;

		/*
		 * FIXME: There should exist more beautiful way to get filename.
		 * Not sure that it will work in windows, but I don't think that
		 * someone will use ntfscp under windows.
		 */
		filename = strrchr(opts.src_file, '/');
		if (filename)
			filename++;
		else
			filename = opts.src_file;
		/* Add 2 bytes for '/' and null-terminator. */
		new_dest_file = malloc(strlen(opts.dest_file) +
				strlen(filename) + 2);
		if (!new_dest_file) {
			perror("ERROR: malloc() failed");
			goto close_dst;
		}
		strcpy(new_dest_file, opts.dest_file);
		strcat(new_dest_file, "/");
		strcat(new_dest_file, filename);
		ntfs_inode_close(out);
		out = utils_pathname_to_inode(vol, NULL, new_dest_file);
		free(new_dest_file);
		if (!out) {
			perror("ERROR: Failed to open destination file");
			goto close_src;
		}
	}

	if (opts.attr_name) { 
		attr_name_len = ntfs_mbstoucs(opts.attr_name, &attr_name, 0);
		if (attr_name_len == -1) {
			perror("ERROR: Failed to parse attribute name");
			goto close_dst;
		}
	}
	na = ntfs_attr_open(out, opts.attribute, attr_name, attr_name_len);
	if (!na) {
		if (errno != ENOENT) {
			perror("ERROR: Couldn't open attribute");
			goto close_dst;
		}
		/* Requested attribute isn't present, add it. */
		na = ntfs_attr_add(out, opts.attribute, attr_name,
				attr_name_len, 0);
		if (!na) {
			perror("ERROR: Couldn't add attribute");
			goto close_dst;
		}
	}

	Vprintf("Old file size: %lld\n", na->data_size);
	if (na->data_size != new_size) {
		if (ntfs_attr_truncate(na, new_size)) {
			perror("ERROR: Couldn't resize attribute");
			goto close_attr;
		}
	}

	buf = malloc(NTFS_BUF_SIZE);
	if (!buf) {
		perror("ERROR: malloc failed");
		goto close_attr;
	}

	Vprintf("Starting write.\n");
	offset = 0;
	while (!feof(in) && !caught_sigint) {
		br = fread(buf, 1, NTFS_BUF_SIZE, in);
		if (!br) {
			if (!feof(in)) perror("ERROR: fread failed");
			break;
		}
		bw = ntfs_attr_pwrite(na, offset, br, buf);
		if (bw != br) {
			perror("ERROR: ntfs_attr_pwrite failed");
			break;
		}
		offset += bw;
	}
	Vprintf("Syncing.\n");
	result = 0;
	free(buf);
close_attr:
	ntfs_attr_close(na);
close_dst:
	while (ntfs_inode_close(out)) {
		if (errno != EBUSY) {
			Eprintf("Sync failed. Run chkdsk.\n");
			break;
		}
		Eprintf("Device busy. Will retry sync after 3 seconds.\n");
		sleep(3);
	}
close_src:
	fclose(in);
umount:
	ntfs_umount(vol, FALSE);
	Vprintf("Done.\n");
	return result;
}
