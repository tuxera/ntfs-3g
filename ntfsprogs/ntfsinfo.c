/**
 * ntfsinfo - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002-2004 Matthew J. Fanto
 * Copyright (c) 2002-2004 Anton Altaparmakov
 * Copyright (c) 2002-2003 Richard Russon
 * Copyright (c) 2004 Yura Pakhuchiy
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
 *	    $EA_INFORMATION
 *	    $EA
 *	    $PROPERTY_SET
 *	    $LOGGED_UTILITY_STREAM
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>

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

static const char *EXEC_NAME = "ntfsinfo";

static struct options {
	char	*device;	/* Device/File to work with */
	s64	 inode;		/* Info for this inode */
	int	 quiet;		/* Less output */
	int	 verbose;	/* Extra output */
	int	 force;		/* Override common sense */
	int	 notime;	/* Don't report timestamps at all */
	int	 mft;		/* Dump information about the volume as well */
	const char *filename;
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
static void version (void)
{
	printf ("\n%s v%s - Display information about an NTFS Volume.\n\n",
		EXEC_NAME, VERSION);
	printf ("Copyright (c)\n");
	printf ("    2002-2004 Matthew J. Fanto\n");
	printf ("    2002-2004 Anton Altaparmakov\n");
	printf ("    2002-2003 Richard Russon\n");
	printf ("    2003      Leonard Norrgård\n");
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
	printf ("\nUsage: %s [options] -d dev\n"
		"    -d dev  --device dev The ntfs volume to display information about\n"
		"    -i num  --inode num  Display information about this inode\n"
		"    -F file --file file  Display information about this file (absolute path)\n"
		"    -m      --mft        Dump information about the volume\n"
		"    -t      --notime     Don't report timestamps\n"
		"\n"
		"    -f      --force      Use less caution\n"
		"    -q      --quiet      Less output\n"
		"    -v      --verbose    More output\n"
		"    -V      --version    Display version information\n"
		"    -h      --help       Display this help\n\n",
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
static int parse_options (int argc, char *argv[])
{
	static const char *sopt = "-fh?i:F:mqtTvVd:";
	static const struct option lopt[] = {
		{ "device",	 required_argument,	NULL, 'd' },
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

	opterr = 0; /* We'll handle the errors, thank you. */

	opts.inode = -1;
	opts.filename = NULL;

	while ((c = getopt_long (argc, argv, sopt, lopt, NULL)) != (char)-1) {
		switch (c) {
		case 'd':
			if (!opts.device)
				opts.device = argv[optind-1];
			else
				err++;
			break;
		case 'i':
			if ((opts.inode != -1) ||
			    (!utils_parse_size (optarg, &opts.inode, FALSE))) {
				err++;
			}
			break;
		case 'F':
			if (opts.filename == NULL) {
				/* The inode can not be resolved here, store the filename */
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
		case '?':
			help++;
			break;
		case 'q':
			opts.quiet++;
			break;
		case 't':
			opts.notime++;
			break;
		case 'T':
			/* 'T' is depreceted, notify */
			Eprintf ("Option 'T' is deprecated, it was replaced by 't'.\n");
			err++;
			break;
		case 'v':
			opts.verbose++;
			break;
		case 'V':
			ver++;
			break;
		case 'm':
			opts.mft++;
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

		if ((opts.inode == -1) && (opts.filename == NULL) && !opts.mft) {
			if (argc > 1)
				Eprintf ("You must specify an inode to learn about.\n");
			err++;
		}

		if (opts.quiet && opts.verbose) {
			Eprintf ("You may not use --quiet and --verbose at the same time.\n");
			err++;
		}

		if ((opts.inode != -1) && (opts.filename != NULL)) {
			if (argc > 1)
				Eprintf ("You may not specify --inode and --file together.\n");
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
	time_t unix_clock = ntfs2utc(sle64_to_cpu(sle_ntfs_clock));
	return ctime(&unix_clock);
}

/**
 * ntfs_attr_get_name()
 * @attr:	a vaild attribute record
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
	printf("\tNumber of Initialized Records in MFT: %lld\n",
			(long long)vol->nr_mft_records);
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
	
	/* TODO: file_attributes - Flags describing the file. */
	
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
static void ntfs_dump_attr_list(ATTR_RECORD *attr)
{
	printf("Dumping attribute AT_ATTRIBUTE_LIST (0x20)\n");

	/* Dump list's name */
	if (attr->name_length) {
		char *stream_name = NULL;

		stream_name = ntfs_attr_get_name(attr);
		if (stream_name) {
			printf("\tList name:\t\t '%s'\n",stream_name);
			free(stream_name);
		} else {
			/* an error occured, errno holds the reason - notify the user */
			fprintf(stderr, "ntfsinfo error: could not parse stream name: %s\n",
				strerror(errno));
		}
	} else {
		printf("\tList name:\t\t unnamed\n");
	}

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
			/* an error occured, errno holds the reason - notify the user */
			fprintf(stderr, "ntfsinfo error: could not parse file name: %s\n",
				strerror(errno));
		}
		/* any way, error or not, print the length */
		printf("\tFile Name Length:\t %d\n", file_name_attr->file_name_length);
	} else {
		printf("\tFile Name:\t\t unnamed?!?\n");
	}
	
	/* other basic stuff about the file */
	printf("\tAllocated File Size:\t %lld\n",
		(long long)sle64_to_cpu(file_name_attr->allocated_size));
	printf("\tReal File Size:\t\t %lld\n",
		(long long)sle64_to_cpu(file_name_attr->data_size));

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
 * given an acl, print it in a beautiful & lovley way.
 */
static void ntfs_dump_acl(const char *prefix,ACL *acl)
{
	unsigned int i;
	u16 ace_count;
	ACCESS_ALLOWED_ACE *ace;
	
	printf("%sRevision\t %u\n",prefix,acl->revision);

	/* don't recalc le16_to_cpu every iteration (minor speedup on big-endians */
	ace_count = le16_to_cpu(acl->ace_count);

	/* initialize 'ace' to the first ace (if any) */
	ace = (ACCESS_ALLOWED_ACE *)((char *)acl + 8);

	/* iterate through ACE's */
	for (i=0;i<acl->ace_count;i++) {
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
		
		printf("%sACE:\t\t type:%s  flags:0x%x  access:0x%x\n",prefix,ace_type,
			(unsigned int)le16_to_cpu(ace->flags),(unsigned int)le32_to_cpu(ace->mask));
		/* get a SID string */
		sid = ntfs_sid_to_mbs(&ace->sid, NULL, 0);
		printf("%s\t\t SID: %s\n",prefix,sid);
		if (sid)
			free(sid);
			
		/* proceed to next ACE */
		ace = (ACCESS_ALLOWED_ACE *)(((char *)ace) + le32_to_cpu(ace->size));
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
	char *sid;
	
	printf("Dumping attribute $SECURITY_DESCRIPTOR (0x50)\n");

	if (attr->non_resident) {
		runlist *rl = ntfs_mapping_pairs_decompress(vol, attr, 0);
		if (rl) {
			sec_desc_attr = malloc(attr->data_size);
			s64 bytes_read = ntfs_rl_pread(vol, rl, 0,
						attr->data_size, sec_desc_attr);
			if (bytes_read != attr->data_size) {
				Eprintf("ntfsinfo error: could not read secutiry descriptor\n");
				free(sec_desc_attr);
				return;
			}
			free (rl);
		} else {
			Eprintf("ntfsinfo error: could not decompress runlist\n");
			return;
		}
	} else {
		sec_desc_attr = (SECURITY_DESCRIPTOR_ATTR *)((u8*)attr +
				le16_to_cpu(attr->value_offset));
	}

	printf("\tRevision:\t\t %u\n",sec_desc_attr->revision);

	/* TODO: parse the flags */
	printf("\tFlags:\t\t\t 0x%0x\n",sec_desc_attr->control);

	sid = ntfs_sid_to_mbs((SID *)((char *)sec_desc_attr +
		sec_desc_attr->owner), NULL, 0);
	printf("\tOwner SID:\t\t %s\n",sid);
	free(sid);

	sid = ntfs_sid_to_mbs((SID *)((char *)sec_desc_attr +
		sec_desc_attr->group), NULL, 0);
	printf("\tGroup SID:\t\t %s\n",sid);
	free(sid);

	printf("\tSystem ACL:\t\t ");
	if (sec_desc_attr->control & SE_SACL_PRESENT) {
		if (sec_desc_attr->control & SE_SACL_DEFAULTED) {
			printf("defaulted");
		}
		printf("\n");
		ntfs_dump_acl("\t\t",(ACL *)((char *)sec_desc_attr +
			sec_desc_attr->sacl));
	} else {
		printf("missing\n");
	}
	
	printf("\tDiscretionary ACL:\t\t ");
	if (sec_desc_attr->control & SE_DACL_PRESENT) {
		if (sec_desc_attr->control & SE_SACL_DEFAULTED) {
			printf("Defaulted");
		}
		printf("\n");
		ntfs_dump_acl("\t\t",(ACL *)((char *)sec_desc_attr +
			sec_desc_attr->dacl));
	} else {
		printf("missing\n");
	}
	
	if (attr->non_resident) free(sec_desc_attr);
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
			/* an error occured, errno holds the reason - notify the user */
			fprintf(stderr,"ntfsinfo error: could not parse volume name: %s\n",
				strerror(errno));
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

	printf("\tVolume Version:\t %d.%d\n", vol_information->major_ver,
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

/**
 * ntfs_dump_data_attr()
 *
 * dump some info about the data attribute
 */
static void ntfs_dump_attr_data(ATTR_RECORD *attr)
{
	printf("Dumping attribute $DATA (0x80) related info\n");

	/* Dump stream name */
	if (attr->name_length) {
		char *stream_name = NULL;

		stream_name = ntfs_attr_get_name(attr);
		if (stream_name) {
			printf("\tStream name:\t\t '%s'\n",stream_name);
			free(stream_name);
		} else {
			/* an error occured, errno holds the reason - notify the user */
			fprintf(stderr, "ntfsinfo error: could not parse stream name: %s\n",
				strerror(errno));
		}
	} else {
		printf("\tStream name:\t\t unnamed\n");
	}

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
	} else {
		printf("\tIs resident? \t\t Yes\n");
		printf("\tData size:\t\t %u\n",
			(unsigned int)le32_to_cpu(attr->value_length));

		/* TODO: parse the flags */
		printf("\tResidence Flags:\t 0x%02hhx\n", attr->resident_flags);
	}
}

/**
 * ntfs_dump_attr_index_root()
 *
 * dump the index_root attribute
 */
static void ntfs_dump_attr_index_root(ATTR_RECORD *attr)
{
	unsigned int type;
	INDEX_ROOT *index_root = NULL;
	
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
			/* an error occured, errno holds the reason - notify the user */
			fprintf(stderr, "ntfsinfo error: could not parse index name: %s\n",
				strerror(errno));
		}
	} else {
		printf("\tIndex name:\t\t unnamed\n");
	}

	/* attr_type dumping */
	printf("\tIndexed Attr Type:\t ");
	type = le32_to_cpu(index_root->type);
	if (type) {
		if (index_root->type != AT_FILE_NAME) {
			/* wierd, this should be illgeal */
			printf("0x%0X\n", type);
			fprintf(stderr, "ntfsinfo error: Unknown Indexed Attr Type: 0x%0X\n",
				type);
		} else {
			printf("file names\n");
		}
	} else {
		/* fixme: add some more index types */
		printf("unknown\n");
	}

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
	/* printf("\tIndex Entries Following\t %u\n", ???? );*/
}

/**
 * ntfs_dump_attr_index_allocation()
 *
 * dump the index_allocation attribute
 */
static void ntfs_dump_attr_index_allocation(ATTR_RECORD *attr)
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
			/* an error occured, errno holds the reason - notify the user */
			fprintf(stderr, "ntfsinfo error: could not parse index name: %s\n",
				strerror(errno));
		}
	} else {
		printf("\tIndex name:\t\t unnamed\n");
	}

	/* dump index's size */
	if (attr->non_resident) {
		/* print only the non resident part's size */
		printf("\tAllocated data size:\t %llu\n",
			(unsigned long long)le64_to_cpu(attr->allocated_size));
		printf("\tUsed data size:\t\t %llu\n",
			(unsigned long long)le64_to_cpu(attr->data_size));
	} else {
		/* print only the payload's size */
		printf("\tValue's size:\t\t %u\n",
			(unsigned int)le32_to_cpu(attr->value_length));
	}
	
	/* TODO: parse how many records does this B-*+/Tree contains */
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
			/* an error occured, errno holds the reason - notify the user */
			fprintf(stderr, "ntfsinfo error: could not parse bitmap name: %s\n",
				strerror(errno));
		}
	} else {
		printf("\tBitmap name:\t\t unnamed\n");
	}

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
static void ntfs_dump_attr_ea_information(ATTR_RECORD *attr __attribute__((unused)))
{
	printf("Dumping attribute $EA_INFORMATION (0xD0)\n");
	printf("\tTODO\n");
}

/**
 * ntfs_dump_attr_ea()
 *
 * dump the ea attribute
 */
static void ntfs_dump_attr_ea(ATTR_RECORD *attr __attribute__((unused)))
{
	printf("Dumping attribute $EA (0xE0)\n");
	printf("\tTODO\n");
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
			"--Please report this to linux-ntfs-dev@lists.sourceforge.net--\n",
			(unsigned int)le32_to_cpu(attr->type));

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
			/* an error occured, errno holds the reason - notify the user */
			fprintf(stderr, "ntfsinfo error: could not parse attribute name: %s\n",
				strerror(errno));
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

		/* if the attribute resident part is large enough, it may contain
			the compressed size */
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
			(le16_to_cpu(attr->value_length)>128)?128:le16_to_cpu(attr->value_length));
	}
}

/**
 * ntfs_dump_inode_general_info
 */
static void ntfs_dump_inode_general_info(ntfs_inode *inode)
{
	u16 inode_flags = inode->mrec->flags;
	
	printf("Dumping Inode #%llu\n",(long long)inode->mft_no);
	
	printf("Update Sequence Array Count:\t %hu\n",
		le16_to_cpu(inode->mrec->usa_count));
	printf("$LogFile seqNum for this Inode:\t 0x%llx\n",
		(signed long long int)sle64_to_cpu(inode->mrec->lsn));
	printf("Number of times reused:\t\t %hu\n",
		(short unsigned int)le16_to_cpu(inode->mrec->sequence_number));
	printf("Number of hard links:\t\t %hu\n",
		le16_to_cpu(inode->mrec->link_count));

	printf("MFT record Flags:\t\t ");
	if (inode_flags) {
		if (!(MFT_RECORD_IN_USE & inode_flags)) {
			printf("DELETED ");
		}
		if (MFT_RECORD_IS_DIRECTORY & inode_flags) {
			printf("DIRECTORY ");
		}
		if (~(MFT_RECORD_IN_USE | MFT_RECORD_IS_DIRECTORY) & inode_flags) {
			printf("UNKNOWN:0x%04hx",inode_flags);
		}
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
	printf("Next Attribute Instance Num\t %hu\n",
		le16_to_cpu(inode->mrec->next_attr_instance));
}

/**
 * ntfs_get_file_attributes
 */
static void ntfs_dump_file_attributes(ntfs_inode *inode)
{
	ntfs_attr_search_ctx *ctx = NULL;

	/* then start enumerating attributes
	   see ntfs_attr_lookup documentation for detailed explenation */
	ctx = ntfs_attr_get_search_ctx(inode, NULL);
	while (!ntfs_attr_lookup(AT_UNUSED, NULL, 0, 0, 0, NULL, 0, ctx)) {
		switch (ctx->attr->type) {
		case AT_UNUSED:
			/* That's an internal type, isn't it? */
			printf("Weird: AT_UNUSED type was returned, please report this.\n");
			break;
		case AT_STANDARD_INFORMATION:
			ntfs_dump_attr_standard_information(ctx->attr);
			break;
		case AT_ATTRIBUTE_LIST:
			ntfs_dump_attr_list(ctx->attr);
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
			ntfs_dump_attr_data(ctx->attr);
			break;
		case AT_INDEX_ROOT:
			ntfs_dump_attr_index_root(ctx->attr);
			break;
		case AT_INDEX_ALLOCATION:
			ntfs_dump_attr_index_allocation(ctx->attr);
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
			ntfs_dump_attr_ea(ctx->attr);
			break;
		case AT_PROPERTY_SET:
			ntfs_dump_attr_property_set(ctx->attr);
			break;
		case AT_LOGGED_UTILITY_STREAM:
			ntfs_dump_attr_logged_utility_stream(ctx->attr);
			break;
		case AT_END:
			printf("Weird: AT_END type was returned, please report this.\n");
			break;
		default:
			ntfs_dump_attr_unknown(ctx->attr);
		}
	}
	
	/* if we exited the loop before we're done - notify the user */
	if (errno != ENOENT) {
		fprintf(stderr, "ntfsinfo error: stopped before finished "
			"enumerating attributes: %s\n", strerror(errno));
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

	if (!parse_options (argc, argv))
		return 1;

	utils_set_locale();

	vol = utils_mount_volume (opts.device, MS_RDONLY, opts.force);
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
			inode = utils_pathname_to_inode (vol, NULL, opts.filename);
		} else {
			inode = ntfs_inode_open(vol, MK_LE_MREF(opts.inode, 0));
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
			 * note: when the specified inode does not exist, either EIO or
			 *  or ESPIPE is returned, we should notify better in those cases
			 */
			fprintf(stderr, "Error loading node: %s\n", strerror(errno));
		}
	}

	ntfs_umount (vol, FALSE);
	return 0;
}

