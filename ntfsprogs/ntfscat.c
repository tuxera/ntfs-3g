/**
 * ntfscat - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2003 Richard Russon
 *
 * This utility will concatenate files and print on the standard output.
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

#include "types.h"
#include "attrib.h"
#include "utils.h"
#include "volume.h"
#include "debug.h"
#include "dir.h"
#include "ntfscat.h"

static const char *EXEC_NAME = "ntfscat";
static struct options opts;
static int verbose = 0;
static int quiet   = 0;

GEN_PRINTF (Eprintf, stderr, NULL,     FALSE)
GEN_PRINTF (Vprintf, stdout, &verbose, TRUE)
GEN_PRINTF (Qprintf, stdout, &quiet,   FALSE)

/**
 * version - Print version information about the program
 *
 * Print a copyright statement and a brief description of the program.
 *
 * Return:  none
 */
void version (void)
{
	printf ("\n%s v%s - Concatenate files and print on the standard output.\n\n",
		EXEC_NAME, VERSION);
	printf ("Copyright (c) 2003 Richard Russon\n");
	printf ("\n%s\n%s%s\n", ntfs_gpl, ntfs_bugs, ntfs_home);
}

/**
 * usage - Print a list of the parameters to the program
 *
 * Print a list of the parameters and options for the program.
 *
 * Return:  none
 */
void usage (void)
{
	printf ("\nUsage: %s [options] device file\n"
		"    -f  --force      Use less caution\n"
		"    -V  --version    Version information\n"
		"    -h  --help       Print this help\n\n",
		//"    -A  --attribute  Display this attribute",
		//"    -I  --file       Display this file",
		//"    -F  --inode      Display this inode",
		//"    -N  --name       Display this attribute name",
		//"    -r  --raw        Display the compressed or encrypted file",
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
int parse_options (int argc, char **argv)
{
	static const char *sopt = "-fh?V"; // A:F:I:N:
	static const struct option lopt[] = {
		{ "force",	no_argument,		NULL, 'f' },
		{ "help",	no_argument,		NULL, 'h' },
		{ "version",	no_argument,		NULL, 'V' },
	//	{ "attribute",	required_argument,	NULL, 'A' },
	//	{ "file",	required_argument,	NULL, 'F' },
	//	{ "inode",	required_argument,	NULL, 'I' },
	//	{ "name",	required_argument,	NULL, 'N' },
		{ NULL,		0,			NULL, 0   }
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
		case 'f':
			opts.force++;
			break;
		case 'h':
		case '?':
			help++;
			break;
		case 'V':
			ver++;
			break;
		default:
			Eprintf ("Unknown option '%s'.\n", argv[optind-1]);
			err++;
			break;
		}
	}

	if (help || ver) {
	} else {
		if ((opts.device == NULL) ||
		    (opts.file   == NULL)) {
			if (argc > 1)
				Eprintf ("You must specify one device and one file.\n");
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
 * cat
 */
int cat (ntfs_volume *vol, ntfs_inode *inode)
{
	const int bufsize = 1024;
	char *buffer;
	ntfs_attr *attr;
	s64 read;
	s64 offset;

	buffer = malloc (bufsize);
	if (!buffer)
		return 1;

	attr = ntfs_attr_open (inode, AT_DATA, NULL, 0);
	if (!attr) {
		Eprintf ("Cannot cat a directory.\n");
		free (buffer);
		return 1;
	}

	offset = 0;
	do {
		read = ntfs_attr_pread (attr, offset, bufsize, buffer);
		fwrite (buffer, read, 1, stdout);
		offset += read;
	} while (read > 0);

	ntfs_attr_close (attr);
	free (buffer);
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
	ntfs_volume *vol;
	ntfs_inode *inode;
	int result = 1;

	if (!parse_options (argc, argv))
		return 1;

	utils_set_locale();

	vol = utils_mount_volume (opts.device, MS_RDONLY, opts.force);
	if (!vol) {
		printf ("!vol\n");
		return 1;
	}

	inode = utils_pathname_to_inode (vol, NULL, opts.file);
	if (!inode) {
		printf ("!inode\n");
		return 1;
	}

	result = cat (vol, inode);

	ntfs_inode_close (inode);
	ntfs_umount (vol, FALSE);
	if (result)
		;//printf ("failed\n");
	else
		;//printf ("success\n");
	return result;
}

