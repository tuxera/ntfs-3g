/**
 * ntfsinfo - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002-2004 Matthew J. Fanto
 * Copyright (c) 2002-2005 Anton Altaparmakov
 * Copyright (c) 2002-2005 Richard Russon
 * Copyright (c) 2003-2006 Szabolcs Szakacsits
 * Copyright (c) 2004-2005 Yuval Fledel
 * Copyright (c) 2004-2005 Yura Pakhuchiy
 * Copyright (c)      2005 Cristian Klein
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
/*
 * TODO LIST:
 *	- Better error checking. (focus on ntfs_dump_volume)
 *	- Comment things better.
 *	- More things at verbose mode.
 *	- Dump ACLs when security_id exists (NTFS 3+ only).
 *	- Clean ups.
 *	- Internationalization.
 *	- Add more Indexed Attr Types.
 *	- Make formatting look more like www.flatcap.org/ntfs/info
 *
 *	Still not dumping certain attributes. Need to find the best
 *	way to output some of these attributes.
 *
 *	Still need to do:
 *	    $REPARSE_POINT/$SYMBOLIC_LINK
 *	    $PROPERTY_SET
 *	    $LOGGED_UTILITY_STREAM
 */

#include "config.h"

#ifdef HAVE_STDIO_H
#include <stdio.h>
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
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "types.h"
#include "mft.h"
#include "attrib.h"
#include "layout.h"
#include "inode.h"
#include "utils.h"
#include "security.h"
#include "mst.h"
#include "dir.h"
#include "ntfstime.h"
#include "version.h"

static const char *EXEC_NAME = "ntfsinfo";

static struct options {
	const char *device;	/* Device/File to work with */
	const char *filename;	/* Resolve this filename to mft number */
	s64	 inode;		/* Info for this inode */
	int	 quiet;		/* Less output */
	int	 verbose;	/* Extra output */
	int	 force;		/* Override common sense */
	int	 notime;	/* Don't report timestamps at all */
	int	 mft;		/* Dump information about the volume as well */
	u8	 padding[4];	/* Unused: padding to 64 bit. */
} opts;

/**
 * version - Print version information about the program
 *
 * Print a copyright statement and a brief description of the program.
 *
 * Return:  none
 */
static void version(void)
{
	printf("\n%s v%s (libntfs %s) - Display information about an NTFS "
			"Volume.\n\n", EXEC_NAME, VERSION,
			ntfs_libntfs_version());
	printf("Copyright (c)\n");
	printf("    2002-2004 Matthew J. Fanto\n");
	printf("    2002-2005 Anton Altaparmakov\n");
	printf("    2002-2005 Richard Russon\n");
	printf("    2003      Leonard Norrgård\n");
	printf("    2004-2005 Yura Pakhuchiy\n");
	printf("\n%s\n%s%s\n", ntfs_gpl, ntfs_bugs, ntfs_home);
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
	printf("\nUsage: %s [options] device\n"
		"    -i, --inode NUM  Display information about this inode\n"
		"    -F, --file FILE  Display information about this file (absolute path)\n"
		"    -m, --mft        Dump information about the volume\n"
		"    -t, --notime     Don't report timestamps\n"
		"\n"
		"    -f, --force      Use less caution\n"
		"    -q, --quiet      Less output\n"
		"    -v, --verbose    More output\n"
		"    -V, --version    Display version information\n"
		"    -h, --help       Display this help\n\n",
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
static int parse_options(int argc, char *argv[])
{
	static const char *sopt = "-:fhi:F:mqtTvV";
	static const struct option lopt[] = {
		{ "force",	 no_argument,		NULL, 'f' },
		{ "help",	 no_argument,		NULL, 'h' },
		{ "inode",	 required_argument,	NULL, 'i' },
		{ "file",	 required_argument,	NULL, 'F' },
		{ "quiet",	 no_argument,		NULL, 'q' },
		{ "verbose",	 no_argument,		NULL, 'v' },
		{ "version",	 no_argument,		NULL, 'V' },
		{ "notime",	 no_argument,		NULL, 'T' },
		{ "mft",	 no_argument,		NULL, 'm' },
		{ NULL,		 0,			NULL,  0  }
	};

	char c = -1;
	int err  = 0;
	int ver  = 0;
	int help = 0;
	int levels = 0;

	opterr = 0; /* We'll handle the errors, thank you. */

	opts.inode = -1;
	opts.filename = NULL;

	while ((c = getopt_long(argc, argv, sopt, lopt, NULL)) != (char)-1) {
		ntfs_log_trace("optind=%d; c='%c' optarg=\"%s\".\n", optind, c,
				optarg);
		switch (c) {
		case 1:
			if (!opts.device)
				opts.device = optarg;
			else
				err++;
			break;
		case 'i':
			if ((opts.inode != -1) ||
			    (!utils_parse_size(optarg, &opts.inode, FALSE))) {
				err++;
			}
			break;
		case 'F':
			if (opts.filename == NULL) {
				/* The inode can not be resolved here,
				   store the filename */
				opts.filename = argv[optind-1];
			} else {
				/* "-F" can't appear more than once */
				err++;
			}
			break;
		case 'f':
			opts.force++;
			break;
		case 'h':
			help++;
			break;
		case 'q':
			opts.quiet++;
			ntfs_log_clear_levels(NTFS_LOG_LEVEL_QUIET);
			break;
		case 't':
			opts.notime++;
			break;
		case 'T':
			/* 'T' is deprecated, notify */
			ntfs_log_error("Option 'T' is deprecated, it was "
				"replaced by 't'.\n");
			err++;
			break;
		case 'v':
			opts.verbose++;
			ntfs_log_set_levels(NTFS_LOG_LEVEL_VERBOSE);
			break;
		case 'V':
			ver++;
			break;
		case 'm':
			opts.mft++;
			break;
		case '?':
			if (optopt=='?') {
				help++;
				continue;
			}
			if (ntfs_log_parse_option(argv[optind-1]))
				continue;
			ntfs_log_error("Unknown option '%s'.\n",
					argv[optind-1]);
			err++;
			break;
		case ':':
			ntfs_log_error("Option '%s' requires an "
					"argument.\n", argv[optind-1]);
			err++;
			break;
		default:
			ntfs_log_error("Unhandled option case: %d.\n", c);
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
		if (opts.device == NULL) {
			if (argc > 1)
				ntfs_log_error("You must specify exactly one "
					"device.\n");
			err++;
		}

		if ((opts.inode == -1) && (opts.filename == NULL) && !opts.mft) {
			if (argc > 1)
				ntfs_log_error("You must specify an inode to "
					"learn about.\n");
			err++;
		}

		if (opts.quiet && opts.verbose) {
			ntfs_log_error("You may not use --quiet and --verbose "
				"at the same time.\n");
			err++;
		}

		if ((opts.inode != -1) && (opts.filename != NULL)) {
			if (argc > 1)
				ntfs_log_error("You may not specify --inode "
					"and --file together.\n");
			err++;
		}

	}

	if (ver)
		version();
	if (help || err)
		usage();

	return (!err && !help && !ver);
}


/* *************** utility functions ******************** */
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
static char *ntfsinfo_time_to_str(const s64 sle_ntfs_clock)
{
	time_t unix_clock = ntfs2utc(sle_ntfs_clock);
	return ctime(&unix_clock);
}

/**
 * ntfs_attr_get_name()
 * @attr:	a valid attribute record
 *
 * return multi-byte string containing the attribute name if exist. the user
 *             is then responsible of freeing that memory.
 *        null if no name exists (attr->name_length==0). no memory allocated.
 *        null if cannot convert to multi-byte string. errno would contain the
 *             error id. no memory allocated in that case
 */
static char *ntfs_attr_get_name(ATTR_RECORD *attr)
{
	ntfschar *ucs_attr_name;
	char *mbs_attr_name = NULL;
	int mbs_attr_name_size;

	/* calculate name position */
	ucs_attr_name = (ntfschar *)((char *)attr + le16_to_cpu(attr->name_offset));
	/* convert unicode to printable format */
	mbs_attr_name_size = ntfs_ucstombs(ucs_attr_name,attr->name_length,
		&mbs_attr_name,0);
	if (mbs_attr_name_size>0) {
		return mbs_attr_name;
	} else {
		return NULL;
	}
}


/* *************** functions for dumping global info ******************** */
/**
 * ntfs_dump_volume - dump information about the volume
 */
static void ntfs_dump_volume(ntfs_volume *vol)
{
	printf("Volume Information \n");
	printf("\tName of device: %s\n", vol->dev->d_name);
	printf("\tDevice state: %lu\n", vol->dev->d_state);
	printf("\tVolume Name: %s\n", vol->vol_name);
	printf("\tVolume State: %lu\n", vol->state);
	printf("\tVolume Version: %u.%u\n", vol->major_ver, vol->minor_ver);
	printf("\tSector Size: %hu\n", vol->sector_size);
	printf("\tCluster Size: %u\n", (unsigned int)vol->cluster_size);
	printf("\tVolume Size in Clusters: %lld\n",
			(long long)vol->nr_clusters);

	printf("MFT Information \n");
	printf("\tMFT Record Size: %u\n", (unsigned int)vol->mft_record_size);
	printf("\tMFT Zone Multiplier: %u\n", vol->mft_zone_multiplier);
	printf("\tMFT Data Position: %lld\n", (long long)vol->mft_data_pos);
	printf("\tMFT Zone Start: %lld\n", (long long)vol->mft_zone_start);
	printf("\tMFT Zone End: %lld\n", (long long)vol->mft_zone_end);
	printf("\tMFT Zone Position: %lld\n", (long long)vol->mft_zone_pos);
	printf("\tCurrent Position in First Data Zone: %lld\n",
			(long long)vol->data1_zone_pos);
	printf("\tCurrent Position in Second Data Zone: %lld\n",
			(long long)vol->data2_zone_pos);
	printf("\tLCN of Data Attribute for FILE_MFT: %lld\n",
			(long long)vol->mft_lcn);
	printf("\tFILE_MFTMirr Size: %d\n", vol->mftmirr_size);
	printf("\tLCN of Data Attribute for File_MFTMirr: %lld\n",
			(long long)vol->mftmirr_lcn);
	printf("\tSize of Attribute Definition Table: %d\n",
			(int)vol->attrdef_len);

	printf("FILE_Bitmap Information \n");
	printf("\tFILE_Bitmap MFT Record Number: %llu\n",
			(unsigned long long)vol->lcnbmp_ni->mft_no);
	printf("\tState of FILE_Bitmap Inode: %lu\n", vol->lcnbmp_ni->state);
	printf("\tLength of Attribute List: %u\n",
			(unsigned int)vol->lcnbmp_ni->attr_list_size);
	printf("\tAttribute List: %s\n", vol->lcnbmp_ni->attr_list);
	printf("\tNumber of Attached Extent Inodes: %d\n",
			(int)vol->lcnbmp_ni->nr_extents);
	/* FIXME: need to add code for the union if nr_extens != 0, but
	   i dont know if it will ever != 0 with FILE_Bitmap */

	printf("FILE_Bitmap Data Attribute Information\n");
	printf("\tDecompressed Runlist: not done yet\n");
	printf("\tBase Inode: %llu\n",
			(unsigned long long)vol->lcnbmp_na->ni->mft_no);
	printf("\tAttribute Types: not done yet\n");
	//printf("\tAttribute Name: %s\n", vol->lcnbmp_na->name);
	printf("\tAttribute Name Length: %u\n",
			(unsigned int)vol->lcnbmp_na->name_len);
	printf("\tAttribute State: %lu\n", vol->lcnbmp_na->state);
	printf("\tAttribute Allocated Size: %lld\n",
			(long long)vol->lcnbmp_na->allocated_size);
	printf("\tAttribute Data Size: %lld\n",
			(long long)vol->lcnbmp_na->data_size);
	printf("\tAttribute Initialized Size: %lld\n",
			(long long)vol->lcnbmp_na->initialized_size);
	printf("\tAttribute Compressed Size: %lld\n",
			(long long)vol->lcnbmp_na->compressed_size);
	printf("\tCompression Block Size: %u\n",
			(unsigned int)vol->lcnbmp_na->compression_block_size);
	printf("\tCompression Block Size Bits: %u\n",
			vol->lcnbmp_na->compression_block_size_bits);
	printf("\tCompression Block Clusters: %u\n",
			vol->lcnbmp_na->compression_block_clusters);

	//TODO: Still need to add a few more attributes
}

/**
 * ntfs_dump_flags - Dump flags for STANDARD_INFORMATION and FILE_NAME.
 * @type:	dump flags for this attribute type
 * @flags:	flags for dumping
 */
static void ntfs_dump_flags(ATTR_TYPES type, u32 flags)
{
	printf("\tFile attributes:\t");
	if (flags & FILE_ATTR_READONLY) {
		printf(" READONLY");
		flags &= ~FILE_ATTR_READONLY;
	}
	if (flags & FILE_ATTR_HIDDEN) {
		printf(" HIDDEN");
		flags &= ~FILE_ATTR_HIDDEN;
	}
	if (flags & FILE_ATTR_SYSTEM) {
		printf(" SYSTEM");
		flags &= ~FILE_ATTR_SYSTEM;
	}
	if (flags & FILE_ATTR_ARCHIVE) {
		printf(" ARCHIVE");
		flags &= ~FILE_ATTR_ARCHIVE;
	}
	if (flags & FILE_ATTR_DEVICE) {
		printf(" DEVICE");
		flags &= ~FILE_ATTR_DEVICE;
	}
	if (flags & FILE_ATTR_NORMAL) {
		printf(" NORMAL");
		flags &= ~FILE_ATTR_NORMAL;
	}
	if (flags & FILE_ATTR_TEMPORARY) {
		printf(" TEMPORARY");
		flags &= ~FILE_ATTR_TEMPORARY;
	}
	if (flags & FILE_ATTR_SPARSE_FILE) {
		printf(" SPARSE_FILE");
		flags &= ~FILE_ATTR_SPARSE_FILE;
	}
	if (flags & FILE_ATTR_REPARSE_POINT) {
		printf(" REPARSE_POINT");
		flags &= ~FILE_ATTR_REPARSE_POINT;
	}
	if (flags & FILE_ATTR_COMPRESSED) {
		printf(" COMPRESSED");
		flags &= ~FILE_ATTR_COMPRESSED;
	}
	if (flags & FILE_ATTR_OFFLINE) {
		printf(" OFFLINE");
		flags &= ~FILE_ATTR_OFFLINE;
	}
	if (flags & FILE_ATTR_NOT_CONTENT_INDEXED) {
		printf(" NOT_CONTENT_INDEXED");
		flags &= ~FILE_ATTR_NOT_CONTENT_INDEXED;
	}
	if (flags & FILE_ATTR_ENCRYPTED) {
		printf(" ENCRYPTED");
		flags &= ~FILE_ATTR_ENCRYPTED;
	}
	/* We know that FILE_ATTR_I30_INDEX_PRESENT only exists on $FILE_NAME,
	   and in case we are wrong, let it appear as UNKNOWN */
	if (type == AT_FILE_NAME) {
		if (flags & FILE_ATTR_I30_INDEX_PRESENT) {
			printf(" I30_INDEX");
			flags &= ~FILE_ATTR_I30_INDEX_PRESENT;
		}
	}
	if (flags & FILE_ATTR_VIEW_INDEX_PRESENT) {
		printf(" VIEW_INDEX");
		flags &= ~FILE_ATTR_VIEW_INDEX_PRESENT;
	}
	if (flags)
		printf(" UNKNOWN: 0x%08x", (unsigned int)le32_to_cpu(flags));
	printf("\n");
}

/**
 * ntfs_dump_namespace
 */
static void ntfs_dump_namespace(u8 file_name_type)
{
	const char *mbs_file_type;

	/* name space */
	switch (file_name_type) {
	case FILE_NAME_POSIX:
		mbs_file_type = "POSIX";
		break;
	case FILE_NAME_WIN32:
		mbs_file_type = "Win32";
		break;
	case FILE_NAME_DOS:
		mbs_file_type = "DOS";
		break;
	case FILE_NAME_WIN32_AND_DOS:
		mbs_file_type = "Win32 & DOS";
		break;
	default:
		mbs_file_type = "(unknown)";
	}
	printf("\tNamespace:\t\t %s\n", mbs_file_type);
}

/* *************** functions for dumping attributes ******************** */
/**
 * ntfs_dump_standard_information
 */
static void ntfs_dump_attr_standard_information(ATTR_RECORD *attr)
{
	STANDARD_INFORMATION *standard_attr = NULL;
	u32 value_length;

	standard_attr = (STANDARD_INFORMATION*)((char *)attr +
		le16_to_cpu(attr->value_offset));

	printf("Dumping attribute $STANDARD_INFORMATION (0x10)\n");

	printf("\tAttribute instance:\t %u\n", le16_to_cpu(attr->instance));

	/* let's start with mandatory? fields */

	/* time conversion stuff */
	if (!opts.notime) {
		char *ntfs_time_str = NULL;

		ntfs_time_str = ntfsinfo_time_to_str(standard_attr->creation_time);
		printf("\tFile Creation Time:\t %s",ntfs_time_str);

		ntfs_time_str = ntfsinfo_time_to_str(
			standard_attr->last_data_change_time);
		printf("\tFile Altered Time:\t %s",ntfs_time_str);

		ntfs_time_str = ntfsinfo_time_to_str(
			standard_attr->last_mft_change_time);
		printf("\tMFT Changed Time:\t %s",ntfs_time_str);

		ntfs_time_str = ntfsinfo_time_to_str(standard_attr->last_access_time);
		printf("\tLast Accessed Time:\t %s",ntfs_time_str);
	}
	ntfs_dump_flags(attr->type, standard_attr->file_attributes);

	printf("\tMax Number of Versions:\t %u \n",
		(unsigned int)le32_to_cpu(standard_attr->maximum_versions));
	printf("\tVersion Number:\t\t %u \n",
		(unsigned int)le32_to_cpu(standard_attr->version_number));
	printf("\tClass ID:\t\t %u \n",
		(unsigned int)le32_to_cpu(standard_attr->class_id));

	value_length = le32_to_cpu(attr->value_length);
	if (value_length == 48) {
/*		printf("\t$STANDARD_INFORMATION fields owner_id, security_id, quota \n"
			"\t & usn are missing. This volume has not been upgraded\n"); */
	} else if (value_length == 72) {
		printf("\tUser ID:\t\t %u \n",
			(unsigned int)le32_to_cpu(standard_attr->owner_id));
		printf("\tSecurity ID:\t\t %u \n",
			(unsigned int)le32_to_cpu(standard_attr->security_id));
	} else {
		printf("\tSize of STANDARD_INFORMATION is %u. It should be "
			"either 72 or 48, something is wrong...\n",
			(unsigned int)value_length);
	}
}

/**
 * ntfs_dump_attr_list()
 */
static void ntfs_dump_attr_list(ATTR_RECORD *attr, ntfs_volume *vol)
{
	ATTR_LIST_ENTRY *entry;
	u8 *value;
	s64 l;

	printf("Dumping attribute AT_ATTRIBUTE_LIST (0x20)\n");

	/* Dump list's name */
	if (attr->name_length) {
		char *stream_name = NULL;

		stream_name = ntfs_attr_get_name(attr);
		if (stream_name) {
			printf("\tList name:\t\t '%s'\n",stream_name);
			free(stream_name);
		} else {
			/* an error occurred, errno holds the reason - notify the user */
			ntfs_log_perror("ntfsinfo error: could not parse stream name");
		}
	} else {
		printf("\tList name:\t\t unnamed\n");
	}

	printf("\tAttribute instance:\t %u\n", le16_to_cpu(attr->instance));

	/* Dump list's size */
	if (attr->non_resident) {
		printf("\tAllocated size:\t\t %llu\n",
			(unsigned long long)le64_to_cpu(attr->allocated_size));
		printf("\tUsed size:\t\t %llu\n",
			(unsigned long long)le64_to_cpu(attr->data_size));
	} else {
		/* print only the payload's size */
		/* - "bytes" is mentioned here to avoid confusion with bits
		     this is not required (almost) anywhere else */
		printf("\tList's size:\t\t %u bytes\n",
			(unsigned int)le32_to_cpu(attr->value_length));
	}

	if (!opts.verbose)
		return;

	l = ntfs_get_attribute_value_length(attr);
	if (!l) {
		ntfs_log_perror("ntfs_get_attribute_value_length failed");
		return;
	}
	value = malloc(l);
	if (!value) {
		ntfs_log_perror("malloc failed");
		return;
	}
	l = ntfs_get_attribute_value(vol, attr, value);
	if (!l) {
		ntfs_log_perror("ntfs_get_attribute_value failed");
		free(value);
		return;
	}
	printf("\tDumping attribute list:");
	entry = (ATTR_LIST_ENTRY *) value;
	for (;(u8 *)entry < (u8 *) value + l; entry = (ATTR_LIST_ENTRY *)
				((u8 *) entry + le16_to_cpu(entry->length))) {
		printf("\n");
		printf("\t\tAttribute type:\t0x%x\n",
				(unsigned int)le32_to_cpu(entry->type));
		printf("\t\tRecord length:\t%u\n",
				le16_to_cpu(entry->length));
		printf("\t\tName length:\t%u\n", entry->name_length);
		printf("\t\tName offset:\t%u\n", entry->name_offset);
		printf("\t\tStarting VCN:\t%lld\n",
				sle64_to_cpu(entry->lowest_vcn));
		printf("\t\tMFT reference:\t%lld\n",
				MREF_LE(entry->mft_reference));
		printf("\t\tInstance:\t%u\n", le16_to_cpu(entry->instance));
		printf("\t\tName:\t\t");
		if (entry->name_length) {
			char *name = NULL;
			int name_size;

			name_size = ntfs_ucstombs(entry->name,
					entry->name_length, &name, 0);

			if (name_size > 0) {
				printf("%s\n", name);
				free(name);
			} else
				ntfs_log_perror("ntfs_ucstombs failed");
		} else
			printf("unnamed\n");
	}
	free(value);
	printf("\tEnd of attribute list reached.\n");
}

/**
 * ntfs_dump_attr_file_name()
 */
static void ntfs_dump_attr_file_name(ATTR_RECORD *attr)
{
	FILE_NAME_ATTR *file_name_attr = NULL;

	file_name_attr = (FILE_NAME_ATTR*)((char *)attr +
		le16_to_cpu(attr->value_offset));

	printf("Dumping attribute $FILE_NAME (0x30)\n");

	/* let's start with the obvious - file name */

	if (file_name_attr->file_name_length>0) {
		/* but first we need to convert the little endian unicode string
		   into a printable format */
		char *mbs_file_name = NULL;
		int mbs_file_name_size;

		mbs_file_name_size = ntfs_ucstombs(file_name_attr->file_name,
			file_name_attr->file_name_length,&mbs_file_name,0);

		if (mbs_file_name_size>0) {
			printf("\tFile Name:\t\t '%s'\n", mbs_file_name);
			free(mbs_file_name);
		} else {
			/* an error occurred, errno holds the reason - notify the user */
			ntfs_log_perror("ntfsinfo error: could not parse file name");
		}
		/* any way, error or not, print the length */
		printf("\tFile Name Length:\t %d\n", file_name_attr->file_name_length);
	} else {
		printf("\tFile Name:\t\t unnamed?!?\n");
	}

	ntfs_dump_namespace(file_name_attr->file_name_type);

	printf("\tAttribute instance:\t %u\n", le16_to_cpu(attr->instance));

	/* other basic stuff about the file */
	printf("\tAllocated File Size:\t %lld\n",
		(long long)sle64_to_cpu(file_name_attr->allocated_size));
	printf("\tReal File Size:\t\t %lld\n",
		(long long)sle64_to_cpu(file_name_attr->data_size));
	printf("\tParent directory:\t %lld\n",
		(long long)MREF_LE(file_name_attr->parent_directory));
	ntfs_dump_flags(attr->type, file_name_attr->file_attributes);

	/* time stuff stuff */
	if (!opts.notime) {
		char *ntfs_time_str;

		ntfs_time_str = ntfsinfo_time_to_str(file_name_attr->creation_time);
		printf("\tFile Creation Time:\t %s",ntfs_time_str);

		ntfs_time_str = ntfsinfo_time_to_str(
			file_name_attr->last_data_change_time);
		printf("\tFile Altered Time:\t %s",ntfs_time_str);

		ntfs_time_str = ntfsinfo_time_to_str(
			file_name_attr->last_mft_change_time);
		printf("\tMFT Changed Time:\t %s",ntfs_time_str);

		ntfs_time_str = ntfsinfo_time_to_str(file_name_attr->last_access_time);
		printf("\tLast Accessed Time:\t %s",ntfs_time_str);
	}
}

/**
 * ntfs_dump_object_id
 *
 * dump the $OBJECT_ID attribute - not present on all systems
 */
static void ntfs_dump_attr_object_id(ATTR_RECORD *attr,ntfs_volume *vol)
{
	OBJECT_ID_ATTR *obj_id_attr = NULL;

	obj_id_attr = (OBJECT_ID_ATTR *)((u8*)attr +
			le16_to_cpu(attr->value_offset));

	printf("Dumping attribute $OBJECT_ID (0x40)\n");

	printf("\tAttribute instance:\t %u\n", le16_to_cpu(attr->instance));

	if (vol->major_ver >= 3.0) {
		u32 value_length;
		char printable_GUID[37];

		value_length = le32_to_cpu(attr->value_length);

		/* Object ID is mandatory. */
		ntfs_guid_to_mbs(&obj_id_attr->object_id, printable_GUID);
		printf("\tObject ID:\t\t %s\n", printable_GUID);

		/* Dump Birth Volume ID. */
		if ((value_length > sizeof(GUID)) && !ntfs_guid_is_zero(
				&obj_id_attr->birth_volume_id)) {
			ntfs_guid_to_mbs(&obj_id_attr->birth_volume_id,
					printable_GUID);
			printf("\tBirth Volume ID:\t\t %s\n", printable_GUID);
		} else
			printf("\tBirth Volume ID:\t missing\n");

		/* Dumping Birth Object ID */
		if ((value_length > sizeof(GUID)) && !ntfs_guid_is_zero(
				&obj_id_attr->birth_object_id)) {
			ntfs_guid_to_mbs(&obj_id_attr->birth_object_id,
					printable_GUID);
			printf("\tBirth Object ID:\t\t %s\n", printable_GUID);
		} else
			printf("\tBirth Object ID:\t missing\n");

		/* Dumping Domain_id - reserved for now */
		if ((value_length > sizeof(GUID)) && !ntfs_guid_is_zero(
				&obj_id_attr->domain_id)) {
			ntfs_guid_to_mbs(&obj_id_attr->domain_id,
					printable_GUID);
			printf("\tDomain ID:\t\t\t %s\n", printable_GUID);
		} else
			printf("\tDomain ID:\t\t missing\n");
	} else
		printf("\t$OBJECT_ID not present. Only NTFS versions > 3.0\n"
			"\thave $OBJECT_ID. Your version of NTFS is %d.\n",
				vol->major_ver);
}

/**
 * ntfs_dump_acl
 *
 * given an acl, print it in a beautiful & lovely way.
 */
static void ntfs_dump_acl(const char *prefix, ACL *acl)
{
	unsigned int i;
	u16 ace_count;
	ACCESS_ALLOWED_ACE *ace;

	printf("%sRevision\t %u\n", prefix, acl->revision);

	/* don't recalc le16_to_cpu every iteration (minor speedup on big-endians */
	ace_count = le16_to_cpu(acl->ace_count);

	/* initialize 'ace' to the first ace (if any) */
	ace = (ACCESS_ALLOWED_ACE *)((char *)acl + 8);

	/* iterate through ACE's */
	for (i = 1; i <= ace_count; i++) {
		const char *ace_type;
		char *sid;

		/* set ace_type. */
		switch (ace->type) {
		case ACCESS_ALLOWED_ACE_TYPE:
			ace_type = "allow";
			break;
		case ACCESS_DENIED_ACE_TYPE:
			ace_type = "deny";
			break;
		case SYSTEM_AUDIT_ACE_TYPE:
			ace_type = "audit";
			break;
		default:
			ace_type = "unknown";
			break;
		}

		printf("%sACE:\t\t type:%s  flags:0x%x  access:0x%x\n", prefix,
			ace_type, (unsigned int)le16_to_cpu(ace->flags),
			(unsigned int)le32_to_cpu(ace->mask));
		/* get a SID string */
		sid = ntfs_sid_to_mbs(&ace->sid, NULL, 0);
		printf("%s\t\t SID: %s\n", prefix, sid);
		free(sid);

		/* proceed to next ACE */
		ace = (ACCESS_ALLOWED_ACE *)(((char *)ace) + le32_to_cpu(ace->size));
	}
}


static void ntfs_dump_security_descriptor(SECURITY_DESCRIPTOR_ATTR *sec_desc,
					  const char *indent)
{
	char *sid;
	
	printf("%s\tRevision:\t\t %u\n", indent, sec_desc->revision);

	/* TODO: parse the flags */
	printf("%s\tFlags:\t\t\t 0x%0x\n", indent, sec_desc->control);

	sid = ntfs_sid_to_mbs((SID *)((char *)sec_desc +
		le32_to_cpu(sec_desc->owner)), NULL, 0);
	printf("%s\tOwner SID:\t\t %s\n", indent, sid);
	free(sid);

	sid = ntfs_sid_to_mbs((SID *)((char *)sec_desc +
		le32_to_cpu(sec_desc->group)), NULL, 0);
	printf("%s\tGroup SID:\t\t %s\n", indent, sid);
	free(sid);

	printf("%s\tSystem ACL:\t\t ", indent);
	if (sec_desc->control & SE_SACL_PRESENT) {
		if (sec_desc->control & SE_SACL_DEFAULTED) {
			printf("defaulted");
		}
		printf("\n");
		ntfs_dump_acl(indent ? "\t\t\t" : "\t\t",
			      (ACL *)((char *)sec_desc +
				      le32_to_cpu(sec_desc->sacl)));
	} else {
		printf("missing\n");
	}

	printf("%s\tDiscretionary ACL:\t ", indent);
	if (sec_desc->control & SE_DACL_PRESENT) {
		if (sec_desc->control & SE_SACL_DEFAULTED) {
			printf("defaulted");
		}
		printf("\n");
		ntfs_dump_acl(indent ? "\t\t\t" : "\t\t",
			      (ACL *)((char *)sec_desc +
				      le32_to_cpu(sec_desc->dacl)));
	} else {
		printf("missing\n");
	}
}

/**
 * ntfs_dump_security_descriptor()
 *
 * dump the security information about the file
 */
static void ntfs_dump_attr_security_descriptor(ATTR_RECORD *attr, ntfs_volume *vol)
{
	SECURITY_DESCRIPTOR_ATTR *sec_desc_attr;

	printf("Dumping attribute $SECURITY_DESCRIPTOR (0x50)\n");

	printf("\tAttribute instance:\t %u\n", le16_to_cpu(attr->instance));

	if (attr->non_resident) {
		/* FIXME: We don't handle fragmented mapping pairs case. */
		runlist *rl = ntfs_mapping_pairs_decompress(vol, attr, 0);
		if (rl) {
			s64 data_size, bytes_read;

			data_size = sle64_to_cpu(attr->data_size);
			sec_desc_attr = malloc(data_size);
			if (!sec_desc_attr) {
				ntfs_log_perror("malloc failed");
				free(rl);
				return;
			}
			bytes_read = ntfs_rl_pread(vol, rl, 0,
						data_size, sec_desc_attr);
			if (bytes_read != data_size) {
				ntfs_log_error("ntfsinfo error: could not "
						"read security descriptor\n");
				free(rl);
				free(sec_desc_attr);
				return;
			}
			free(rl);
		} else {
			ntfs_log_error("ntfsinfo error: could not "
						"decompress runlist\n");
			return;
		}
	} else {
		sec_desc_attr = (SECURITY_DESCRIPTOR_ATTR *)((u8*)attr +
				le16_to_cpu(attr->value_offset));
	}

	ntfs_dump_security_descriptor(sec_desc_attr, "");
	
	if (attr->non_resident) 
		free(sec_desc_attr);
}

/**
 * ntfs_dump_volume_name()
 *
 * dump the name of the volume the inode belongs to
 */
static void ntfs_dump_attr_volume_name(ATTR_RECORD *attr)
{
	ntfschar *ucs_vol_name = NULL;

	printf("Dumping attribute $VOLUME_NAME (0x60)\n");

	printf("\tAttribute instance:\t %u\n", le16_to_cpu(attr->instance));

	if (attr->value_length>0) {
		char *mbs_vol_name = NULL;
		int mbs_vol_name_size;
		/* calculate volume name position */
		ucs_vol_name = (ntfschar*)((u8*)attr +
				le16_to_cpu(attr->value_offset));
		/* convert the name to current locale multibyte sequence */
		mbs_vol_name_size = ntfs_ucstombs(ucs_vol_name,
				le32_to_cpu(attr->value_length)/sizeof(ntfschar),
				&mbs_vol_name,0);

		if (mbs_vol_name_size>0) {
			/* output the converted name. */
			printf("\tVolume Name:\t\t '%s'\n",mbs_vol_name);
			free(mbs_vol_name);
		} else {
			/* an error occurred, errno holds the reason - notify the user */
			ntfs_log_perror("ntfsinfo error: could not parse volume name");
		}
	} else {
		printf("\tVolume Name:\t\t unnamed\n");
	}
}

/**
 * ntfs_dump_volume_information()
 *
 * dump the information for the volume the inode belongs to
 *
 */
static void ntfs_dump_attr_volume_information(ATTR_RECORD *attr)
{
	VOLUME_INFORMATION *vol_information = NULL;

	vol_information = (VOLUME_INFORMATION*)((char *)attr+
		le16_to_cpu(attr->value_offset));

	printf("Dumping attribute $VOLUME_INFORMATION (0x70)\n");

	printf("\tAttribute instance:\t %u\n", le16_to_cpu(attr->instance));

	printf("\tVolume Version:\t\t %d.%d\n", vol_information->major_ver,
		vol_information->minor_ver);
	printf("\tFlags:\t\t\t ");
	if (vol_information->flags & VOLUME_IS_DIRTY)
		printf("DIRTY ");
	if (vol_information->flags & VOLUME_RESIZE_LOG_FILE)
		printf("RESIZE_LOG ");
	if (vol_information->flags & VOLUME_UPGRADE_ON_MOUNT)
		printf("UPG_ON_MOUNT ");
	if (vol_information->flags & VOLUME_MOUNTED_ON_NT4)
		printf("MOUNTED_NT4 ");
	if (vol_information->flags & VOLUME_DELETE_USN_UNDERWAY)
		printf("DEL_USN ");
	if (vol_information->flags & VOLUME_REPAIR_OBJECT_ID)
		printf("REPAIR_OBJID ");
	if (vol_information->flags & VOLUME_CHKDSK_UNDERWAY)
		printf("CHKDSK_UNDERWAY ");
	if (vol_information->flags & VOLUME_MODIFIED_BY_CHKDSK)
		printf("MOD_BY_CHKDSK ");
	if (vol_information->flags & VOLUME_FLAGS_MASK) {
		printf("\n");
	} else {
		printf("none set\n");
	}
	if (vol_information->flags & (0xFFFF - VOLUME_FLAGS_MASK))
		printf("\t\t\t\t Unknown Flags: 0x%04x\n",
			vol_information->flags & (0xFFFF - VOLUME_FLAGS_MASK));
}

static ntfschar NTFS_DATA_SDS[5] = { const_cpu_to_le16('$'),
	const_cpu_to_le16('S'), const_cpu_to_le16('D'), 
	const_cpu_to_le16('S'), const_cpu_to_le16('\0') };

static void ntfs_dump_sds_entry(SECURITY_DESCRIPTOR_HEADER *sds)
{
	SECURITY_DESCRIPTOR_RELATIVE *sd;
	
	ntfs_log_verbose("\t\tHash:\t\t\t 0x%08x\n", le32_to_cpu(sds->hash));
	ntfs_log_verbose("\t\tSecurity id:\t\t %u\n",
			 le32_to_cpu(sds->security_id));
	ntfs_log_verbose("\t\tOffset:\t\t\t %llu\n", le64_to_cpu(sds->offset));
	ntfs_log_verbose("\t\tLength:\t\t\t %u\n", le32_to_cpu(sds->length));
	
	sd = (SECURITY_DESCRIPTOR_RELATIVE *)((char *)sds +
		sizeof(SECURITY_DESCRIPTOR_HEADER));
	
	ntfs_dump_security_descriptor(sd, "\t");
}
	
static void *ntfs_attr_readall(ntfs_inode *ni, const ATTR_TYPES type, 
			       ntfschar *name, u32 name_len, s64 *data_size)
{
	ntfs_attr *na;
	void *data, *ret = NULL;
	s64 size;
	
	na = ntfs_attr_open(ni, type, name, name_len);
	if (!na) {
		ntfs_log_perror("ntfs_attr_open failed");
		return NULL;
	}
	data = malloc(na->data_size);
	if (!data) {
		ntfs_log_perror("malloc failed");
		goto out;
	}
	size = ntfs_attr_pread(na, 0, na->data_size, data);
	if (size != na->data_size) {
		ntfs_log_perror("ntfs_attr_pread failed");
		free(data);
		goto out;
	}
	ret = data;
	if (data_size)
		*data_size = size;
out:
	ntfs_attr_close(na);
	return ret;
}

static void ntfs_dump_sds(ATTR_RECORD *attr, ntfs_inode *ni)
{
	SECURITY_DESCRIPTOR_HEADER *sds, *sd;
	ntfschar *name;
	int name_len;
	s64 data_size;
	u64 inode;
	
	inode = ni->mft_no;
	if (ni->nr_extents < 0)
		inode = ni->base_ni->mft_no;
	if (FILE_Secure != inode)
		return;
	
	name_len = attr->name_length;
	if (!name_len)
		return;
	
	name = (ntfschar *)((u8 *)attr + le16_to_cpu(attr->name_offset));
	if (!ntfs_names_are_equal(NTFS_DATA_SDS, sizeof(NTFS_DATA_SDS) / 2 - 1,
				  name, name_len, 0, NULL, 0))
		return;
	
	sd = sds = ntfs_attr_readall(ni, AT_DATA, name, name_len, &data_size);
	if (!sd)
		return;
	/*
	 * FIXME: The right way is based on the indexes, so we couldn't
	 * miss real entries. For now, dump until it makes sense.
	 */
	while (sd->length && sd->hash && 
	       le64_to_cpu(sd->offset) < (u64)data_size &&
	       le32_to_cpu(sd->length) < (u64)data_size &&
	       le64_to_cpu(sd->offset) + 
			le32_to_cpu(sd->length) < (u64)data_size) {
		ntfs_dump_sds_entry(sd);
		sd = (SECURITY_DESCRIPTOR_HEADER *)((char *)sd +
				(cpu_to_le32(sd->length + 0x0F) &
				 ~cpu_to_le32(0x0F)));
	}
	
	free(sds);
}
/**
 * ntfs_dump_data_attr()
 *
 * dump some info about the data attribute
 */
static void ntfs_dump_attr_data(ATTR_RECORD *attr, ntfs_inode *ni)
{
	ntfs_volume *vol = ni->vol;
	
	printf("Dumping attribute $DATA (0x80) related info\n");

	/* Dump stream name */
	if (attr->name_length) {
		char *stream_name = NULL;

		stream_name = ntfs_attr_get_name(attr);
		if (stream_name) {
			printf("\tStream name:\t\t '%s'\n",stream_name);
			free(stream_name);
		} else {
			/* an error occurred, errno holds the reason - notify the user */
			ntfs_log_perror("ntfsinfo error: could not parse stream name");
		}
	} else {
		printf("\tStream name:\t\t unnamed\n");
	}

	printf("\tAttribute instance:\t %u\n", le16_to_cpu(attr->instance));

	/* TODO: parse the flags */
	printf("\tFlags:\t\t\t 0x%04hx\n",le16_to_cpu(attr->flags));

	/* fork by residence */
	if (attr->non_resident) {
/*		VCN lowest_vcn;	  Lowest valid virtual cluster number
		VCN highest_vcn;  Highest valid vcn of this extent of
		u16 mapping_pairs_offset; Byte offset from the ... */
		printf("\tIs resident? \t\t No\n");
		printf("\tData size:\t\t %llu\n",
			(long long)le64_to_cpu(attr->data_size));
		printf("\tAllocated size:\t\t %llu\n",
			(long long)le64_to_cpu(attr->allocated_size));
		printf("\tInitialized size:\t %llu\n",
			(long long)le64_to_cpu(attr->initialized_size));
		if (attr->compression_unit) {
			printf("\tCompression unit:\t %u\n",attr->compression_unit);
			printf("\tCompressed size:\t %llu\n",
				(long long)le64_to_cpu(attr->compressed_size));
		} else {
			printf("\tNot Compressed\n");
		}

		if (opts.verbose) {
			runlist *rl = ntfs_mapping_pairs_decompress(vol, attr, 0);
			if (rl) {
				runlist *rlc = rl;
				printf("\tRunlist:\tVCN\t\tLCN\t\tLength\n");
				while (rlc->length) {
					printf("\t\t\t%lld\t\t%lld\t\t%lld\n",
						rlc->vcn, rlc->lcn, rlc->length);
					rlc++;
				}
				free(rl);
			} else {
				ntfs_log_error("ntfsinfo error: could not "
					"decompress runlist\n");
				return;
			}
		}
	} else {
		printf("\tIs resident? \t\t Yes\n");
		printf("\tData size:\t\t %u\n",
			(unsigned int)le32_to_cpu(attr->value_length));

		/* TODO: parse the flags */
		printf("\tResidence Flags:\t 0x%02hhx\n", attr->resident_flags);
	}
	
	if (opts.verbose)
		ntfs_dump_sds(attr, ni);
}

typedef enum {
	INDEX_ATTR_UNKNOWN,
	INDEX_ATTR_DIRECTORY_I30,
	INDEX_ATTR_SECURE_SII,
	INDEX_ATTR_SECURE_SDH,
	INDEX_ATTR_OBJID_O,
	INDEX_ATTR_REPARSE_R,
	INDEX_ATTR_QUOTA_O,
	INDEX_ATTR_QUOTA_Q,
} INDEX_ATTR_TYPE;

static void ntfs_dump_index_key(INDEX_ENTRY *entry, INDEX_ATTR_TYPE type)
{
	char *sid;
	char printable_GUID[37];
	
	switch (type) {
	case INDEX_ATTR_SECURE_SII:
		ntfs_log_verbose("\t\tKey security id:\t %u\n",
				 le32_to_cpu(entry->key.sii.security_id));
		break;
	case INDEX_ATTR_SECURE_SDH:
		ntfs_log_verbose("\t\tKey hash:\t\t 0x%08x\n",
				 le32_to_cpu(entry->key.sdh.hash));
		ntfs_log_verbose("\t\tKey security id:\t %u\n",
				 le32_to_cpu(entry->key.sdh.security_id));
		break;
	case INDEX_ATTR_OBJID_O:
		ntfs_guid_to_mbs(&entry->key.object_id, printable_GUID);
		ntfs_log_verbose("\t\tKey GUID:\t\t %s\n", printable_GUID);
		break;
	case INDEX_ATTR_REPARSE_R:
		ntfs_log_verbose("\t\tKey reparse tag:\t 0x%08x\n",
				 le32_to_cpu(entry->key.reparse.reparse_tag));
		ntfs_log_verbose("\t\tKey file id:\t\t %llu\n",
				 le64_to_cpu(entry->key.reparse.file_id));
		break;
	case INDEX_ATTR_QUOTA_O:
		sid = ntfs_sid_to_mbs(&entry->key.sid, NULL, 0);
		ntfs_log_verbose("\t\tKey SID:\t\t %s\n", sid);
		free(sid);
		break;
	case INDEX_ATTR_QUOTA_Q:
		ntfs_log_verbose("\t\tKey owner id:\t\t %u\n",
				 le32_to_cpu(entry->key.owner_id));
		break;
	default:
		ntfs_log_verbose("\t\tIndex attr type is UNKNOWN: \t 0x%08x\n",
				 le32_to_cpu(type));
		break;
	}
}

typedef union {
		SII_INDEX_DATA sii;		/* $SII index data in $Secure */
		SDH_INDEX_DATA sdh;		/* $SDH index data in $Secure */
		QUOTA_O_INDEX_DATA quota_o;	/* $O index data in $Quota    */
		QUOTA_CONTROL_ENTRY quota_q;	/* $Q index data in $Quota    */
} __attribute__((__packed__)) INDEX_ENTRY_DATA;

static void ntfs_dump_index_data(INDEX_ENTRY *entry, INDEX_ATTR_TYPE type)
{
	INDEX_ENTRY_DATA *data;
	
	data = (INDEX_ENTRY_DATA *)((u8 *)entry + entry->data_offset);
	
	switch (type) {
	case INDEX_ATTR_SECURE_SII:
		ntfs_log_verbose("\t\tHash:\t\t\t 0x%08x\n",
				 le32_to_cpu(data->sii.hash));
		ntfs_log_verbose("\t\tSecurity id:\t\t %u\n",
				 le32_to_cpu(data->sii.security_id));
		ntfs_log_verbose("\t\tOffset in $SDS:\t\t %llu\n",
				 le64_to_cpu(data->sii.offset));
		ntfs_log_verbose("\t\tLength in $SDS:\t\t %u\n",
				 le32_to_cpu(data->sii.length));
		break;
	case INDEX_ATTR_SECURE_SDH:
		ntfs_log_verbose("\t\tHash:\t\t\t 0x%08x\n",
				 le32_to_cpu(data->sdh.hash));
		ntfs_log_verbose("\t\tSecurity id:\t\t %u\n",
				 le32_to_cpu(data->sdh.security_id));
		ntfs_log_verbose("\t\tOffset in $SDS:\t\t %llu\n",
				 le64_to_cpu(data->sdh.offset));
		ntfs_log_verbose("\t\tLength in $SDS:\t\t %u\n",
				 le32_to_cpu(data->sdh.length));
		ntfs_log_verbose("\t\tUnknown (padding):\t 0x%08x\n",
				 le32_to_cpu(data->sdh.reserved_II));
		break;
	case INDEX_ATTR_OBJID_O:
		/* TODO */
		break;
	case INDEX_ATTR_REPARSE_R:
		/* TODO */
		break;
	case INDEX_ATTR_QUOTA_O:
		ntfs_log_verbose("\t\tOwner id:\t\t %u\n",
				 le32_to_cpu(data->quota_o.owner_id));
		ntfs_log_verbose("\t\tUnknown:\t\t %u\n",
				 le32_to_cpu(data->quota_o.unknown));
		break;
	case INDEX_ATTR_QUOTA_Q:
		ntfs_log_verbose("\t\tVersion:\t\t %u\n",
				 le32_to_cpu(data->quota_q.version));
		ntfs_log_verbose("\t\tQuota flags:\t\t 0x%08x\n",
				 le32_to_cpu(data->quota_q.flags));
		ntfs_log_verbose("\t\tBytes used:\t\t %llu\n",
				 le64_to_cpu(data->quota_q.bytes_used));
		ntfs_log_verbose("\t\tLast changed:\t\t %s",
				 ntfsinfo_time_to_str(
					 data->quota_q.change_time));
		ntfs_log_verbose("\t\tThreshold:\t\t %lld\n",
				 le64_to_cpu(data->quota_q.threshold));
		ntfs_log_verbose("\t\tLimit:\t\t\t %lld\n",
				 le64_to_cpu(data->quota_q.limit));
		ntfs_log_verbose("\t\tExceeded time:\t\t %lld\n",
				 le64_to_cpu(data->quota_q.exceeded_time));
		if (entry->data_length > 48) {
			char *sid;
			sid = ntfs_sid_to_mbs(&data->quota_q.sid, NULL, 0);
			ntfs_log_verbose("\t\tOwner SID:\t\t %s\n", sid);
			free(sid);
		}
		break;
	default:
		ntfs_log_verbose("\t\tIndex attr type is UNKNOWN: \t 0x%08x\n",
				 le32_to_cpu(type));
		break;
	}
}

/**
 * ntfs_dump_index_entries()
 *
 * dump sequence of index_entries and return number of entries dumped.
 */
static int ntfs_dump_index_entries(INDEX_ENTRY *entry, INDEX_ATTR_TYPE type)
{
	int numb_entries = 1;
	char *name = NULL;

	while (1) {
		if (!opts.verbose) {
			if (entry->flags & INDEX_ENTRY_END)
				break;
			entry = (INDEX_ENTRY *)((u8 *)entry +
						le16_to_cpu(entry->length));
			numb_entries++;
			continue;
		}
		ntfs_log_verbose("\n");
		ntfs_log_verbose("\t\tEntry length:\t\t %u\n",
				le16_to_cpu(entry->length));
		ntfs_log_verbose("\t\tKey length:\t\t %u\n",
				le16_to_cpu(entry->key_length));
		ntfs_log_verbose("\t\tFlags:\t\t\t 0x%02x\n",
			le16_to_cpu(entry->flags));

		if (entry->flags & INDEX_ENTRY_NODE)
			ntfs_log_verbose("\t\tSubnode VCN:\t\t %lld\n",
				le64_to_cpu(*((u8*)entry +
				le16_to_cpu(entry->length) - sizeof(VCN))));
		if (entry->flags & INDEX_ENTRY_END)
			break;

		switch (type) {
		case(INDEX_ATTR_DIRECTORY_I30):
			ntfs_log_verbose("\t\tFILE record number:\t %llu\n",
					MREF_LE(entry->indexed_file));
			printf("\t");
			ntfs_dump_flags(AT_FILE_NAME, entry->key.
				file_name.file_attributes);
			printf("\t");
			ntfs_dump_namespace(entry->key.
				file_name.file_name_type);
			ntfs_ucstombs(entry->key.file_name.file_name,
				entry->key.file_name.file_name_length,
				&name, 0);
			ntfs_log_verbose("\t\tName:\t\t\t %s\n", name);
			free(name);
			name = NULL;
			ntfs_log_verbose("\t\tParent directory:\t %lld\n",
				 MREF_LE(entry->
				 key.file_name.parent_directory));
			ntfs_log_verbose("\t\tCreation time:\t\t %s",
				ntfsinfo_time_to_str(
					entry->key.file_name.creation_time));
			ntfs_log_verbose("\t\tData change time:\t %s",
				ntfsinfo_time_to_str(
					entry->key.file_name.last_data_change_time));
			ntfs_log_verbose("\t\tMFT change time:\t %s",
				ntfsinfo_time_to_str(
					entry->key.file_name.last_mft_change_time));
			ntfs_log_verbose("\t\tAccess time:\t\t %s",
				ntfsinfo_time_to_str(
					entry->key.file_name.last_access_time));
			ntfs_log_verbose("\t\tData size:\t\t %lld\n",
				sle64_to_cpu(entry->key.file_name.data_size));
			ntfs_log_verbose("\t\tAllocated size:\t\t %lld\n",
				sle64_to_cpu(
				entry->key.file_name.allocated_size));
			break;
		default:
			ntfs_log_verbose("\t\tData offset:\t\t %u\n",
				le16_to_cpu(entry->data_offset));
			ntfs_log_verbose("\t\tData length:\t\t %u\n",
				le16_to_cpu(entry->data_length));
			ntfs_dump_index_key(entry, type);
			ntfs_dump_index_data(entry, type);
			break;
		}
		entry = (INDEX_ENTRY *)((u8 *)entry +
						le16_to_cpu(entry->length));
		numb_entries++;
	}
	ntfs_log_verbose("\tEnd of index block reached\n");
	return numb_entries;
}

#define	COMPARE_INDEX_NAMES(attr, name)					       \
	ntfs_names_are_equal((name), sizeof(name) / 2 - 1,		       \
		(ntfschar*)((char*)(attr) + le16_to_cpu((attr)->name_offset)), \
		(attr)->name_length, 0, NULL, 0)

static INDEX_ATTR_TYPE get_index_attr_type(ntfs_inode *ni, ATTR_RECORD *attr,
					   INDEX_ROOT *index_root)
{
	char file_name[64];

	if (!attr->name_length)
		return INDEX_ATTR_UNKNOWN;
	
	if (index_root->type) {
		if (index_root->type == AT_FILE_NAME)
			return INDEX_ATTR_DIRECTORY_I30;
		else
			/* weird, this should be illegal */
			ntfs_log_error("Unknown index attribute type: 0x%0X\n",
				       index_root->type);
		return INDEX_ATTR_UNKNOWN;
	}
	
	if (utils_is_metadata(ni) <= 0)
		return INDEX_ATTR_UNKNOWN;
	if (utils_inode_get_name(ni, file_name, sizeof(file_name)) <= 0)
		return INDEX_ATTR_UNKNOWN;
	
	if (COMPARE_INDEX_NAMES(attr, NTFS_INDEX_SDH))
		return INDEX_ATTR_SECURE_SDH;
	else if (COMPARE_INDEX_NAMES(attr, NTFS_INDEX_SII))
		return INDEX_ATTR_SECURE_SII;
	else if (COMPARE_INDEX_NAMES(attr, NTFS_INDEX_SII))
		return INDEX_ATTR_SECURE_SII;
	else if (COMPARE_INDEX_NAMES(attr, NTFS_INDEX_Q))
		return INDEX_ATTR_QUOTA_Q;
	else if (COMPARE_INDEX_NAMES(attr, NTFS_INDEX_R))
		return INDEX_ATTR_REPARSE_R;
	else if (COMPARE_INDEX_NAMES(attr, NTFS_INDEX_O)) {
		if (!strcmp(file_name, "/$Extend/$Quota"))
			return INDEX_ATTR_QUOTA_O;
		else if (!strcmp(file_name, "/$Extend/$ObjId"))
			return INDEX_ATTR_OBJID_O;
	}
	
	return INDEX_ATTR_UNKNOWN;
}

static void ntfs_dump_index_attr_type(INDEX_ATTR_TYPE type)
{
	if (type == INDEX_ATTR_DIRECTORY_I30)
		printf("DIRECTORY_I30");
	else if (type == INDEX_ATTR_SECURE_SDH)
		printf("SECURE_SDH");
	else if (type == INDEX_ATTR_SECURE_SII)
		printf("SECURE_SII");
	else if (type == INDEX_ATTR_OBJID_O)
		printf("OBJID_O");
	else if (type == INDEX_ATTR_QUOTA_O)
		printf("QUOTA_O");
	else if (type == INDEX_ATTR_QUOTA_Q)
		printf("QUOTA_Q");
	else if (type == INDEX_ATTR_REPARSE_R)
		printf("REPARSE_R");
	else
		printf("UNKNOWN");
	printf("\n");
}

/**
 * ntfs_dump_attr_index_root()
 *
 * dump the index_root attribute
 */
static void ntfs_dump_attr_index_root(ATTR_RECORD *attr, ntfs_inode *ni)
{
	INDEX_ATTR_TYPE type;
	INDEX_ROOT *index_root = NULL;
	INDEX_ENTRY *entry;

	index_root = (INDEX_ROOT*)((u8*)attr + le16_to_cpu(attr->value_offset));

	printf("Dumping attribute $INDEX_ROOT (0x90)\n");

	/* Dump index name */
	if (attr->name_length) {
		char *index_name = NULL;
		index_name = ntfs_attr_get_name(attr);

		if (index_name) {
			printf("\tIndex name:\t\t '%s'\n",index_name);
			free(index_name);
		} else {
			/* an error occurred, errno holds the reason - notify the user */
			ntfs_log_perror("ntfsinfo error: could not parse index name");
		}
	} else {
		printf("\tIndex name:\t\t unnamed\n");
	}

	printf("\tAttribute instance:\t %u\n", le16_to_cpu(attr->instance));

	/* attr_type dumping */
	type = get_index_attr_type(ni, attr, index_root);
	printf("\tIndexed Attr Type:\t ");
	ntfs_dump_index_attr_type(type);
	
	/* collation rule dumping */
	printf("\tCollation Rule:\t\t %u\n",
		(unsigned int)le32_to_cpu(index_root->collation_rule));
/*	COLLATION_BINARY, COLLATION_FILE_NAME, COLLATION_UNICODE_STRING,
	COLLATION_NTOFS_ULONG, COLLATION_NTOFS_SID,
	COLLATION_NTOFS_SECURITY_HASH, COLLATION_NTOFS_ULONGS */

	printf("\tIndex Block Size:\t %u\n",
		(unsigned int)le32_to_cpu(index_root->index_block_size));
	printf("\tClusters Per Block:\t %u\n",
		index_root->clusters_per_index_block);

	/* index header starts here */
	printf("\tAllocated Size:\t\t %u\n",
		(unsigned int)le32_to_cpu(index_root->index.allocated_size));
	printf("\tUsed Size:\t\t %u\n",
		(unsigned int)le32_to_cpu(index_root->index.index_length));

	/* the flags are 8bit long, no need for byte-order handling */
	printf("\tFlags:\t\t\t 0x%02x\n",index_root->index.flags);

	entry = (INDEX_ENTRY *)((u8 *)index_root +
			le32_to_cpu(index_root->index.entries_offset) + 0x10);
	ntfs_log_verbose("\tDumping index block:");
	printf("\tIndex entries total:\t %d\n",
			ntfs_dump_index_entries(entry, type));
}

/**
 * get_index_root()
 *
 * determine size, type and the collation rule of INDX record
 */
static int get_index_root(ntfs_inode *ni, ATTR_RECORD *attr, INDEX_ROOT *iroot)
{
	ntfs_attr_search_ctx *ctx;
	ntfschar *name = 0;
	INDEX_ROOT *root;

	if (attr->name_length) {
		name = malloc(attr->name_length * sizeof(ntfschar));
		if (!name) {
			ntfs_log_perror("malloc failed");
			return -1;
		}
		memcpy(name, (u8 *)attr + attr->name_offset,
				attr->name_length * sizeof(ntfschar));
	}
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		ntfs_log_perror("ntfs_get_search_ctx failed");
		free(name);
		return -1;
	}
	if (ntfs_attr_lookup(AT_INDEX_ROOT, name, attr->name_length, 0,
							0, NULL, 0, ctx)) {
		ntfs_log_perror("ntfs_attr_lookup failed");
		ntfs_attr_put_search_ctx(ctx);
		free(name);
		return -1;
	}

	root = (INDEX_ROOT*)((u8*)ctx->attr +
				le16_to_cpu(ctx->attr->value_offset));
	*iroot = *root;
	ntfs_attr_put_search_ctx(ctx);
	free(name);
	return 0;
}

/**
 * ntfs_dump_attr_index_allocation()
 *
 * dump context of the index_allocation attribute
 */
static void ntfs_dump_index_allocation(ATTR_RECORD *attr, ntfs_inode *ni)
{
	INDEX_ALLOCATION *allocation, *tmp_alloc;
	INDEX_ENTRY *entry;
	INDEX_ROOT index_root;
	INDEX_ATTR_TYPE type;
	int total_entries = 0;
	int total_indx_blocks = 0;
	u8 *bitmap, *byte;
	int bit;
	ntfschar *name;
	u32 name_len;
	s64 data_size;

	if (get_index_root(ni, attr, &index_root))
		return;
	
	type = get_index_attr_type(ni, attr, &index_root);
	
	name = (ntfschar *)((u8 *)attr + le16_to_cpu(attr->name_offset));
	name_len = attr->name_length;
	
	byte = bitmap = ntfs_attr_readall(ni, AT_BITMAP, name, name_len, NULL);
	if (!byte)
		return;

	tmp_alloc = allocation = ntfs_attr_readall(ni, AT_INDEX_ALLOCATION, 
						   name, name_len, &data_size);
	if (!tmp_alloc) {
		free(bitmap);
		return;
	}

	bit = 0;
	while ((u8 *)tmp_alloc < (u8 *)allocation + data_size) {
		if (*byte & (1 << bit)) {					   
			if (ntfs_mst_post_read_fixup((NTFS_RECORD *) tmp_alloc,
						index_root.index_block_size)) {
				ntfs_log_perror("Damaged INDX record");
				goto free;
			}
			entry = (INDEX_ENTRY *)((u8 *)tmp_alloc + le32_to_cpu(
				tmp_alloc->index.entries_offset) + 0x18);
			ntfs_log_verbose("\tDumping index block "
					"(VCN %lld, used %u/%u):", le64_to_cpu(
					tmp_alloc->index_block_vcn),
					(unsigned int)le32_to_cpu(tmp_alloc->
					index.index_length), (unsigned int)
					le32_to_cpu(tmp_alloc->index.
					allocated_size));
			total_entries += ntfs_dump_index_entries(entry, type);
			total_indx_blocks++;
		}
		tmp_alloc = (INDEX_ALLOCATION *)((u8 *)tmp_alloc + 
						 index_root.index_block_size);
		bit++;
		if (bit > 7) {
			bit = 0;
			byte++;
		}
	}
	printf("\tIndex entries total:\t %d\n", total_entries);
	printf("\tINDX blocks total:\t %d\n", total_indx_blocks);
free:
	free(allocation);
	free(bitmap);
}

/**
 * ntfs_dump_attr_index_allocation()
 *
 * dump the index_allocation attribute
 */
static void ntfs_dump_attr_index_allocation(ATTR_RECORD *attr, ntfs_inode *ni)
{
	printf("Dumping attribute $INDEX_ALLOCATION (0xA0)\n");

	/* Dump index name */
	if (attr->name_length) {
		char *index_name = NULL;
		index_name = ntfs_attr_get_name(attr);

		if (index_name) {
			printf("\tIndex name:\t\t '%s'\n",index_name);
			free(index_name);
		} else {
			/*
			 * An error occurred, errno holds the reason -
			 * notify the user
			 */
			ntfs_log_perror("ntfsinfo error: could not parse index name");
		}
	} else {
		printf("\tIndex name:\t\t unnamed\n");
	}

	printf("\tAttribute instance:\t %u\n", le16_to_cpu(attr->instance));

	/* dump index's size */
	if (attr->non_resident) {
		/* print only the non resident part's size */
		printf("\tAllocated data size:\t %llu\n",
			(unsigned long long)le64_to_cpu(attr->allocated_size));
		printf("\tUsed data size:\t\t %llu\n",
			(unsigned long long)le64_to_cpu(attr->data_size));
	} else {
		ntfs_log_error("Invalid $INDEX_ALLOCATION attribute. Should be"
						    " non-resident\n");
	}

	ntfs_dump_index_allocation(attr, ni);
}

/**
 * ntfs_dump_attr_bitmap()
 *
 * dump the bitmap attribute
 */
static void ntfs_dump_attr_bitmap(ATTR_RECORD *attr)
{
	printf("Dumping attribute $BITMAP (0xB0)\n");

	/* Dump bitmap name */
	if (attr->name_length) {
		char *bitmap_name = NULL;
		bitmap_name = ntfs_attr_get_name(attr);

		if (bitmap_name) {
			printf("\tBitmap name:\t\t '%s'\n",bitmap_name);
			free(bitmap_name);
		} else {
			/* an error occurred, errno holds the reason - notify the user */
			ntfs_log_perror("ntfsinfo error: could not parse bitmap name");
		}
	} else {
		printf("\tBitmap name:\t\t unnamed\n");
	}

	printf("\tAttribute instance:\t %u\n", le16_to_cpu(attr->instance));

	/* dump bitmap size */
	if (attr->non_resident) {
		/* print only the non resident part's size */
		printf("\tAllocated data size:\t %llu\n",
			(unsigned long long)le64_to_cpu(attr->allocated_size));
		printf("\tUsed data size:\t\t %llu\n",
			(unsigned long long)le64_to_cpu(attr->data_size));
	} else {
		/* print only the payload's size */
		/* - "bytes" is mentioned here to avoid confusion with bits
		     this is not required (almost) anywhere else */
		printf("\tBitmap's size:\t\t %u bytes\n",
			(unsigned int)le32_to_cpu(attr->value_length));
	}
}

/**
 * ntfs_dump_attr_reparse_point()
 *
 * of ntfs 3.x dumps the reparse_point attribute
 */
static void ntfs_dump_attr_reparse_point(ATTR_RECORD *attr __attribute__((unused)))
{
	printf("Dumping attribute $REPARSE_POINT/$SYMBOLIC_LINK (0xC0)\n");
	printf("\tTODO\n");
}

/**
 * ntfs_dump_attr_ea_information()
 *
 * dump the ea_information attribute
 */
static void ntfs_dump_attr_ea_information(ATTR_RECORD *attr)
{
	EA_INFORMATION *ea_info;

	ea_info = (EA_INFORMATION*)((u8*)attr +
			le16_to_cpu(attr->value_offset));
	printf("Dumping attribute $EA_INFORMATION (0xD0)\n");
	printf("\tPacked EA length:\t %u\n", le16_to_cpu(ea_info->ea_length));
	printf("\tNEED_EA count:\t\t %u\n",
			le16_to_cpu(ea_info->need_ea_count));
	printf("\tUnpacked EA length:\t %u\n",
			(unsigned)le32_to_cpu(ea_info->ea_query_length));
}

/**
 * ntfs_dump_attr_ea()
 *
 * dump the ea attribute
 */
static void ntfs_dump_attr_ea(ATTR_RECORD *attr, ntfs_volume *vol)
{
	EA_ATTR *ea;
	u8 *buf = NULL;
	s64 data_size;

	printf("Dumping attribute $EA (0xE0)\n");
	if (attr->non_resident) {
		runlist *rl;

		data_size = sle64_to_cpu(attr->data_size);
		printf("\tIs resident? \t\t No\n");
		printf("\tData size:\t\t %lld\n", data_size);
		if (!opts.verbose)
			return;
		/* FIXME: We don't handle fragmented mapping pairs case. */
		rl = ntfs_mapping_pairs_decompress(vol, attr, 0);
		if (rl) {
			s64 bytes_read;

			buf = malloc(data_size);
			if (!buf) {
				ntfs_log_perror("malloc failed");
				free(rl);
				return;
			}
			bytes_read = ntfs_rl_pread(vol, rl, 0, data_size, buf);
			if (bytes_read != data_size) {
				ntfs_log_perror("ntfs_rl_pread failed");
				free(buf);
				free(rl);
				return;
			}
			free(rl);
			ea = (EA_ATTR*)buf;
		} else {
			ntfs_log_perror("ntfs_mapping_pairs_decompress failed");
			return;
		}
	} else {
		data_size = le32_to_cpu(attr->value_length);
		printf("\tIs resident? \t\t Yes\n");
		printf("\tAttribute value length:\t %lld\n", data_size);
		if (!opts.verbose)
			return;
		ea = (EA_ATTR*)((u8*)attr + le16_to_cpu(attr->value_offset));
	}
	while (1) {
		printf("\n\tFlags:\t\t ");
		if (ea->flags) {
			if (ea->flags == NEED_EA)
				printf("NEED_EA\n");
			else
				printf("Unknown (0x%02x)\n", ea->flags);
		} else
			printf("\n");
		printf("\tName length:\t %d\n", ea->name_length);
		printf("\tValue length:\t %d\n",
				le16_to_cpu(ea->value_length));
		printf("\tName:\t\t '%s'\n", ea->name);
		printf("\tValue:\t\t '%s'\n", ea->value + ea->name_length + 1);
		if (ea->next_entry_offset)
			ea = (EA_ATTR*)((u8*)ea +
					le32_to_cpu(ea->next_entry_offset));
		else
			break;
		if ((u8*)ea - buf >= data_size)
			break;
	}
	free(buf);
}

/**
 * ntfs_dump_attr_property_set()
 *
 * dump the property_set attribute
 */
static void ntfs_dump_attr_property_set(ATTR_RECORD *attr __attribute__((unused)))
{
	printf("Dumping attribute $PROPERTY_SET (0xF0)\n");
	printf("\tTODO\n");
}

/**
 * ntfs_dump_attr_logged_utility_stream()
 *
 * dump the property_set attribute
 */
static void ntfs_dump_attr_logged_utility_stream(ATTR_RECORD *attr __attribute__((unused)))
{
	printf("Dumping attribute $LOGGED_UTILITY_STREAM (0x100)\n");
	printf("\tTODO\n");
}

/**
 * ntfs_hex_dump
 */
static void ntfs_hex_dump(void *buf,unsigned int length)
{
	unsigned int i=0;
	while (i<length) {
		unsigned int j;

		/* line start */
		printf("\t%04X  ",i);

		/* hex content */
		for (j=i;(j<length) && (j<i+16);j++) {
			unsigned char c = *((char *)buf + j);
			printf("%02hhX ",c);
		}

		/* realign */
		for (;j<i+16;j++) {
			printf("   ");
		}

		/* char content */
		for (j=i;(j<length) && (j<i+16);j++) {
			unsigned char c = *((char *)buf + j);
			/* display unprintable chars as '.' */
			if ((c<32) || (c>126)) {
				c = '.';
			}
			printf("%c",c);
		}

		/* end line */
		printf("\n");
		i=j;
	}
}

/**
 * ntfs_dump_attr_unknown
 */
static void ntfs_dump_attr_unknown(ATTR_RECORD *attr)
{
	printf("Dumping unknown attribute type 0x%X.\n"
		"--Please report this to %s--\n",
		(unsigned int)le32_to_cpu(attr->type), NTFS_DEV_LIST);

	printf("\tResident size:\t\t %u\n",(unsigned int)le32_to_cpu(attr->length));

	printf("\tIs resident? \t\t ");
	if (attr->non_resident) {
		printf("No\n");
	} else {
		printf("Yes\n");
	}

	/* Dump attribute name */
	if (attr->name_length) {
		char *attr_name = NULL;
		attr_name = ntfs_attr_get_name(attr);

		if (attr_name) {
			printf("\tAttribute name:\t '%s'\n",attr_name);
			free(attr_name);
		} else {
			/* an error occurred, errno holds the reason
			 * notify the user
			 */
			ntfs_log_perror("ntfsinfo error: could not parse "
				"attribute name");
		}
	} else {
		printf("\tAttribute name:\t unnamed\n");
	}

	/* we could parse the flags */
	/* however, it does not make sense with a new attribute type */
	printf("\tFlags:\t\t\t 0x%04hx\n",le16_to_cpu(attr->flags));

	/* fork by residence */
	printf("\tIs resident?\t\t ");
	if (attr->non_resident) {
		printf("No\n");
		printf("\tAllocated data size:\t %llu\n",
			(unsigned long long)le64_to_cpu(attr->allocated_size));
		printf("\tUsed data size:\t %llu\n",
			(unsigned long long)le64_to_cpu(attr->data_size));
		printf("\tInitialized data size:\t %llu\n",
			(unsigned long long)le64_to_cpu(attr->initialized_size));

		/* if the attribute resident part is large enough, it may
		 * contain the compressed size
		 */
		if ((le32_to_cpu(attr->length)>=72) &&
			((attr->name_offset==0) || (le16_to_cpu(attr->name_offset)>=72))) {
			printf("\tCompressed size:\t %llu\n",
				(unsigned long long)le64_to_cpu(attr->compressed_size));
		}
	} else {
		printf("Yes\n");
		printf("\tResident payload size:\t %u\n",
			(unsigned int)le32_to_cpu(attr->value_length));

		printf("\tResidence Flags:\t 0x%02hhx\n", attr->resident_flags);

		/* hex dump */
		printf("\tDumping some of the attribute data:\n");
		ntfs_hex_dump((u8*)attr + le16_to_cpu(attr->value_offset),
			(le16_to_cpu(attr->value_length)>128)?128
			:le16_to_cpu(attr->value_length));
	}
}

/**
 * ntfs_dump_inode_general_info
 */
static void ntfs_dump_inode_general_info(ntfs_inode *inode)
{
	u16 inode_flags = inode->mrec->flags;

	printf("Dumping Inode #%llu\n",(long long)inode->mft_no);

	printf("Update Sequence Offset:\t %hu\n",
		le16_to_cpu(inode->mrec->usa_ofs));
	printf("Update Sequence Array Count:\t %hu\n",
		le16_to_cpu(inode->mrec->usa_count));
	printf("Update Sequence Number:\t %hu\n",
		*(u16*)((u8*)inode->mrec + le16_to_cpu(inode->mrec->usa_ofs)));
	printf("$LogFile Sequence Number:\t 0x%llx\n",
		(signed long long int)sle64_to_cpu(inode->mrec->lsn));
	printf("MFT Record Sequence Number:\t %hu\n",
		(short unsigned int)le16_to_cpu(inode->mrec->sequence_number));
	printf("Number of hard links:\t\t %hu\n",
		le16_to_cpu(inode->mrec->link_count));
	printf("First attribute offset:\t %hu\n",
		le16_to_cpu(inode->mrec->attrs_offset));

	printf("MFT record Flags:\t\t ");
	if (inode_flags) {
		if (MFT_RECORD_IN_USE & inode_flags) {
			printf("IN_USE ");
			inode_flags &= ~MFT_RECORD_IN_USE;
		}
		if (MFT_RECORD_IS_DIRECTORY & inode_flags) {
			printf("DIRECTORY ");
			inode_flags &= ~MFT_RECORD_IS_DIRECTORY;
		}
		/* The meaning of IS_4 is illusive but not its existence. */
		if (MFT_RECORD_IS_4 & inode_flags) {
			printf("IS_4 ");
			inode_flags &= ~MFT_RECORD_IS_4;
		}
		if (MFT_RECORD_IS_VIEW_INDEX & inode_flags) {
			printf("VIEW_INDEX ");
			inode_flags &= ~MFT_RECORD_IS_VIEW_INDEX;
		}
		if (inode_flags)
			printf("UNKNOWN: 0x%04hx", inode_flags);
	} else {
		printf("none");
	}
	printf("\n");

	printf("Size - Used:\t\t\t %u bytes\n",
		(unsigned int)le32_to_cpu(inode->mrec->bytes_in_use));
	printf("Size - Allocated:\t\t %u bytes\n",
		(unsigned int)le32_to_cpu(inode->mrec->bytes_allocated));

	if (inode->mrec->base_mft_record) {
		printf("base MFT record:\t\t %llu\n",
			MREF_LE(inode->mrec->base_mft_record));
	}
	printf("Next Attribute Instance:\t %hu\n",
		le16_to_cpu(inode->mrec->next_attr_instance));
}

/**
 * ntfs_get_file_attributes
 */
static void ntfs_dump_file_attributes(ntfs_inode *inode)
{
	ntfs_attr_search_ctx *ctx = NULL;

	/* then start enumerating attributes
	   see ntfs_attr_lookup documentation for detailed explanation */
	ctx = ntfs_attr_get_search_ctx(inode, NULL);
	while (!ntfs_attr_lookup(AT_UNUSED, NULL, 0, 0, 0, NULL, 0, ctx)) {
		switch (ctx->attr->type) {
		case AT_UNUSED:
			/* That's an internal type, isn't it? */
			printf("Weird: AT_UNUSED type was returned, please "
				"report this.\n");
			break;
		case AT_STANDARD_INFORMATION:
			ntfs_dump_attr_standard_information(ctx->attr);
			break;
		case AT_ATTRIBUTE_LIST:
			ntfs_dump_attr_list(ctx->attr, inode->vol);
			break;
		case AT_FILE_NAME:
			ntfs_dump_attr_file_name(ctx->attr);
			break;
		case AT_OBJECT_ID:
			ntfs_dump_attr_object_id(ctx->attr, inode->vol);
			break;
		case AT_SECURITY_DESCRIPTOR:
			ntfs_dump_attr_security_descriptor(ctx->attr, inode->vol);
			break;
		case AT_VOLUME_NAME:
			ntfs_dump_attr_volume_name(ctx->attr);
			break;
		case AT_VOLUME_INFORMATION:
			ntfs_dump_attr_volume_information(ctx->attr);
			break;
		case AT_DATA:
			ntfs_dump_attr_data(ctx->attr, inode);
			break;
		case AT_INDEX_ROOT:
			ntfs_dump_attr_index_root(ctx->attr, inode);
			break;
		case AT_INDEX_ALLOCATION:
			ntfs_dump_attr_index_allocation(ctx->attr, inode);
			break;
		case AT_BITMAP:
			ntfs_dump_attr_bitmap(ctx->attr);
			break;
		case AT_REPARSE_POINT:
			ntfs_dump_attr_reparse_point(ctx->attr);
			break;
		case AT_EA_INFORMATION:
			ntfs_dump_attr_ea_information(ctx->attr);
			break;
		case AT_EA:
			ntfs_dump_attr_ea(ctx->attr, inode->vol);
			break;
		case AT_PROPERTY_SET:
			ntfs_dump_attr_property_set(ctx->attr);
			break;
		case AT_LOGGED_UTILITY_STREAM:
			ntfs_dump_attr_logged_utility_stream(ctx->attr);
			break;
		case AT_END:
			printf("Weird: AT_END type was returned, please report "
				"this.\n");
			break;
		default:
			ntfs_dump_attr_unknown(ctx->attr);
		}
	}

	/* if we exited the loop before we're done - notify the user */
	if (errno != ENOENT) {
		ntfs_log_perror("ntfsinfo error: stopped before finished "
			"enumerating attributes");
	} else {
		printf("End of inode reached\n");
	}

	/* close all data-structures we used */
	ntfs_attr_put_search_ctx(ctx);
	ntfs_inode_close(inode);

	/* happily exit */
}

/**
 * main() - Begin here
 *
 * Start from here.
 *
 * Return:  0  Success, the program worked
 *	    1  Error, something went wrong
 */
int main(int argc, char **argv)
{
	ntfs_volume *vol;

	ntfs_log_set_handler(ntfs_log_handler_outerr);

	if (!parse_options(argc, argv))
		return 1;

	utils_set_locale();

	vol = utils_mount_volume(opts.device, MS_RDONLY, opts.force);
	if (!vol)
		return 1;

	/*
	 * if opts.mft is not 0, then we will print out information about
	 * the volume, such as the sector size and whatnot.
	 */
	if (opts.mft)
		ntfs_dump_volume(vol);

	if ((opts.inode != -1) || opts.filename) {
		ntfs_inode *inode;
		/* obtain the inode */
		if (opts.filename) {
			inode = ntfs_pathname_to_inode(vol, NULL, opts.filename);
		} else {
			inode = ntfs_inode_open(vol, MK_MREF(opts.inode, 0));
		}

		/* dump the inode information */
		if (inode) {
			/* general info about the inode's mft record */
			ntfs_dump_inode_general_info(inode);
			/* dump attributes */
			ntfs_dump_file_attributes(inode);
		} else {
			/* can't open inode */
			/*
			 * note: when the specified inode does not exist, either
			 * EIO or or ESPIPE is returned, we should notify better
			 * in those cases
			 */
			ntfs_log_perror("Error loading node");
		}
	}

	ntfs_umount(vol, FALSE);
	return 0;
}

