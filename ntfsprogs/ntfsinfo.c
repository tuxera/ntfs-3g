/**
 * ntfsinfo - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002 Matthew J. Fanto
 * Copyright (c) 2002 Anton Altaparmakov
 * Copyright (c) 2002-2003 Richard Russon
 *
 * This utility will dump a file's attributes.
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

#include "types.h"
#include "mft.h"
#include "attrib.h"
#include "layout.h"
#include "inode.h"
#include "utils.h"

static const char *EXEC_NAME = "ntfsinfo";

static struct options {
	char	*device;	/* Device/File to work with */
	s64	 inode;		/* Info for this inode */
	int	 quiet;		/* Less output */
	int	 verbose;	/* Extra output */
	int	 force;		/* Override common sense */
	int	 epochtime;	/* Report all timestamps as "Thu Jan  1 00:00:00 1970" */
	int	 notime;	/* Don't report timestamps at all */
} opts;

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
void version (void)
{
	printf ("\n%s v%s - Display information about an NTFS Volume.\n\n",
		EXEC_NAME, VERSION);
	printf ("Copyright (c)\n");
	printf ("    2002      Matthew J. Fanto\n");
	printf ("    2002      Anton Altaparmakov\n");
	printf ("    2002-2003 Richard Russon\n");
	printf ("    2003      Leonard Norrgard\n");
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
	printf ("\nUsage: %s [options] device\n"
		"    -i num  --inode num  Display information about this inode\n"
		"\n"
		"    -f      --force      Use less caution\n"
		"    -q      --quiet      Less output\n"
		"    -v      --verbose    More output\n"
		"    -V      --version    Display version information\n"
		"    -h      --help       Display this help\n\n"
		"    -t      --epochtime  Report all timestamps as \"Thu Jan  1 00:00:00 1970\"\n"
		"    -T      --notime     Don't report timestamps at all\n",
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
int parse_options (int argc, char *argv[])
{
	static const char *sopt = "-fh?i:qtTvV";
	static const struct option lopt[] = {
		{ "force",	 no_argument,		NULL, 'f' },
		{ "help",	 no_argument,		NULL, 'h' },
		{ "inode",	 required_argument,	NULL, 'i' },
		{ "quiet",	 no_argument,		NULL, 'q' },
		{ "verbose",	 no_argument,		NULL, 'v' },
		{ "version",	 no_argument,		NULL, 'V' },
		{ "epochtime",   no_argument,		NULL, 't' },
		{ "notime",	 no_argument,		NULL, 'T' },
		{ NULL, 0, NULL, 0 },
	};

	char c = -1;
	int err  = 0;
	int ver  = 0;
	int help = 0;

	opterr = 0; /* We'll handle the errors, thank you. */

	opts.inode = -1;

	while ((c = getopt_long (argc, argv, sopt, lopt, NULL)) != -1) {
		switch (c) {
		case 1:	/* A non-option argument */
			if (!opts.device) {
				opts.device = argv[optind-1];
			} else {
				opts.device = NULL;
				err++;
			}
			break;
		case 'i':
			if ((opts.inode != -1) ||
			    (!utils_parse_size (argv[optind-1], &opts.inode, FALSE))) {
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
		case 'q':
			opts.quiet++;
			break;
		case 't':
			opts.epochtime++;
			break;
		case 'T':
			opts.notime++;
			break;
		case 'v':
			opts.verbose++;
			break;
		case 'V':
			ver++;
			break;
		default:
			if ((optopt == 'i') && (!optarg)) {
				Eprintf ("Option '%s' requires an argument.\n", argv[optind-1]);
			} else {
				Eprintf ("Unknown option '%s'.\n", argv[optind-1]);
			}
			err++;
			break;
		}
	}

	if (help || ver) {
		opts.quiet = 0;
	} else {
		if (opts.device == NULL) {
			if (argc > 1)
				Eprintf ("You must specify exactly one device.\n");
			err++;
		}

		if (opts.inode == -1) {
			if (argc > 1)
				Eprintf ("You much specify an inode to learn about.\n");
			err++;
		}

		if (opts.quiet && opts.verbose) {
			Eprintf ("You may not use --quiet and --verbose at the same time.\n");
			err++;
		}

		if (opts.epochtime && opts.notime) {
			Eprintf ("You may not use --notime and --epochtime at the same time.\n");
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
 * ntfs_dump_file_name_attribute
 */
void ntfs_dump_file_name_attribute(ntfs_inode *inode, MFT_RECORD *mrec)
{
	FILE_NAME_ATTR *file_name_attr = NULL;
	ATTR_RECORD *attr = NULL;
	ntfs_attr_search_ctx *ctx = NULL;
	char *file_name = NULL;

	ctx = ntfs_attr_get_search_ctx(inode, mrec);

	if(ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx)) {
		fprintf(stderr, "ntfsinfo error: cannot lookup attribute AT_FILE_NAME!\n");
		return;
	}

	attr = ctx->attr;

	file_name_attr = (FILE_NAME_ATTR*)((char *)attr + le16_to_cpu(attr->value_offset));

	//need to convert the little endian unicode string to a multibyte string
	ntfs_ucstombs(file_name_attr->file_name, file_name_attr->file_name_length,
			&file_name, file_name_attr->file_name_length);

	printf("Dumping $FILE_NAME (0x30)\n");

	//basic stuff about the file
	printf("File Name: \t\t %s\n",file_name);
	printf("File Name Length: \t %d\n",file_name_attr->file_name_length);
	printf("Allocated File Size: \t %lld\n", sle64_to_cpu(file_name_attr->allocated_size));
	printf("Real File Size: \t %lld\n", sle64_to_cpu(file_name_attr->data_size));

	//time conversion stuff
	if (!opts.notime) {
	  time_t ntfs_time = { 0 };

	  if (!opts.epochtime) {
	    ntfs_time = ntfs2utc (sle64_to_cpu (file_name_attr->creation_time));
	    printf("File Creation Time: \t %s",ctime(&ntfs_time));
	    
	    ntfs_time = ntfs2utc (sle64_to_cpu (file_name_attr->last_data_change_time));
	    printf("File Altered Time: \t %s",ctime(&ntfs_time));
	    
	    ntfs_time = ntfs2utc (sle64_to_cpu (file_name_attr->last_mft_change_time));
	    printf("MFT Changed Time: \t %s",ctime(&ntfs_time));
	    
	    ntfs_time = ntfs2utc (sle64_to_cpu (file_name_attr->last_access_time));
	    printf("Last Accessed Time: \t %s",ctime(&ntfs_time));
	  } else {
	    char *t = asctime(gmtime(&ntfs_time));

	    printf("File Creation Time: \t %s",t);
	    printf("File Altered Time: \t %s",t);
	    printf("MFT Changed Time: \t %s",t);
	    printf("Last Accessed Time: \t %s",t);
	  }
	}
	free(file_name);

}

/**
 * ntfs_dump_standard_information
 */
void ntfs_dump_standard_information(ntfs_inode *inode, MFT_RECORD *mrec)
{

	STANDARD_INFORMATION *standard_attr = NULL;
	ATTR_RECORD *attr = NULL;
	ntfs_attr_search_ctx *ctx = NULL;

	ctx = ntfs_attr_get_search_ctx(inode, mrec);

	if(ntfs_attr_lookup(AT_STANDARD_INFORMATION, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx)) {
		fprintf(stderr, "ntfsinfo error: cannot look up attribute AT_STANDARD_INFORMATION!\n");
		return;
	}

	attr = ctx->attr;

	standard_attr = (STANDARD_INFORMATION*)((char *)attr + le16_to_cpu(attr->value_offset));

	printf("Dumping $STANDARD_INFORMATION (0x10)\n");

	printf("Maximum Number of Versions: \t %d \n", le32_to_cpu (standard_attr->maximum_versions));
	printf("Version Number: \t\t %d \n", le32_to_cpu (standard_attr->version_number));
	printf("Class ID: \t\t\t %d \n", le32_to_cpu (standard_attr->class_id));
	printf("User ID: \t\t\t %d \n",  le32_to_cpu (standard_attr->owner_id));
	printf("Security ID: \t\t\t %d \n",  le32_to_cpu (standard_attr->security_id));

}

/**
 * ntfs_get_file_attributes
 */
void ntfs_get_file_attributes(ntfs_volume *vol, s64 i)
{
	MFT_REF mref;
	MFT_RECORD *mrec = NULL;
	//ntfs_attr_search_ctx *ctx = NULL;
	ntfs_inode *inode = NULL;
	//int error;

	mref = (MFT_REF) i;
	inode = ntfs_inode_open(vol, mref);

	if (ntfs_file_record_read(vol, mref, &mrec, NULL)) {
		fprintf(stderr, "ntfsinfo error: error reading file record!\n");
		exit(1);
	}

	//see flatcap.org/ntfs/info for what formatting should look like
	//ntfs_dump_boot_sector_information(inode, mrec);
	ntfs_dump_file_name_attribute(inode, mrec);
	ntfs_dump_standard_information(inode, mrec);
}

/**
 * main - Begin here
 *
 * Start from here.
 *
 * Return:  0  Success, the program worked
 *	    1  Error, something went wrong
 */
int main(int argc, char **argv)
{
	ntfs_volume *vol;

	if (!parse_options (argc, argv))
		return 1;

	utils_set_locale();

	vol = utils_mount_volume (opts.device, MS_RDONLY, opts.force);
	if (!vol)
		return 1;

	ntfs_get_file_attributes (vol, opts.inode);

	ntfs_umount (vol, FALSE);
	return 0;
}

