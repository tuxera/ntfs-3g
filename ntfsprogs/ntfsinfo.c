/**
 * ntfsinfo - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002-2004 Matthew J. Fanto
 * Copyright (c) 2002-2004 Anton Altaparmakov
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
/* TODO LIST:
 *	1. Better error checking. In fact, my error checking sucks.
 *	2. Fix output issues.
 *	3. Check on the 72/48 issue
 *	4. Comment things better
 *
 *	Still not dumping certain attributes. Need to find the best
 *	way to output some of these attributes. 
 *
 *	Still need to do:
 *	    $OBJECT_ID - dump correctly
 *	    $SECURITY_DESCRIPTOR
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

static const char *EXEC_NAME = "ntfsinfo";

static struct options {
	char	*device;	/* Device/File to work with */
	s64	 inode;		/* Info for this inode */
	int	 quiet;		/* Less output */
	int	 verbose;	/* Extra output */
	int	 force;		/* Override common sense */
	int	 epochtime;	/* Report all timestamps as "Thu Jan  1 00:00:00 1970" */
	int	 notime;	/* Don't report timestamps at all */
	int	 mft;		/* Dump information about the volume as well */
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
void usage (void)
{
	printf ("\nUsage: %s [options] -d dev\n"
		"    -d dev  --device dev The ntfs volume to display information about\n"
		"    -i num  --inode num  Display information about this inode\n"
		"    -m      --mft        Dump information about the volume\n"
		"    -t      --epochtime  Report all timestamps as \"Thu Jan  1 00:00:00 1970\"\n"
		"    -T      --notime     Don't report timestamps at all\n"
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
int parse_options (int argc, char *argv[])
{
	static const char *sopt = "-fh?i:mqtTvVd:";
	static const struct option lopt[] = {
		{ "device",	 required_argument,	NULL, 'd' },
		{ "force",	 no_argument,		NULL, 'f' },
		{ "help",	 no_argument,		NULL, 'h' },
		{ "inode",	 required_argument,	NULL, 'i' },
		{ "quiet",	 no_argument,		NULL, 'q' },
		{ "verbose",	 no_argument,		NULL, 'v' },
		{ "version",	 no_argument,		NULL, 'V' },
		{ "epochtime",   no_argument,		NULL, 't' },
		{ "notime",	 no_argument,		NULL, 'T' },
	        { "mft",	 no_argument,		NULL, 'm' },
		{ NULL, 0, NULL, 0 },
	};

	char c = -1;
	int err  = 0;
	int ver  = 0;
	int help = 0;

	opterr = 0; /* We'll handle the errors, thank you. */

	opts.inode = -1;

	while ((c = getopt_long (argc, argv, sopt, lopt, NULL)) != (char)-1) {
		switch (c) {
		case 'd':	/* A non-option argument */
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

		if (opts.inode == -1 && !opts.mft) {
			if (argc > 1)
				Eprintf ("You must specify an inode to learn about.\n");
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
 * ntfs_dump_volume - dump information about the volume
 */
void ntfs_dump_volume(ntfs_volume *vol)
{
    
    printf("Volume Information \n");
    printf("\tName of device: %s\n", vol->dev->d_name);
    printf("\tDevice state: %lu\n", vol->dev->d_state);
    printf("\tVolume Name: %s\n", vol->vol_name);
    printf("\tVolume State: %lu\n", vol->state);
    printf("\tVolume Version: %u.%u\n", vol->major_ver, vol->minor_ver);
    printf("\tSector Size: %hu\n", vol->sector_size);
    printf("\tCluster Size: %u\n", vol->cluster_size);
    printf("\tVolume Size in Clusters: %lld\n", (long long)vol->nr_clusters);
    
    printf("MFT Information \n");
    printf("\tMFT Record Size: %u\n", vol->mft_record_size);
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
    printf("\tSize of Attribute Definition Table: %d\n", vol->attrdef_len);
   
    printf("FILE_Bitmap Information \n");
    printf("\tFILE_Bitmap MFT Record Number: %llu\n",
		    (unsigned long long)vol->lcnbmp_ni->mft_no);
    printf("\tState of FILE_Bitmap Inode: %lu\n", vol->lcnbmp_ni->state);
    printf("\tLength of Attribute List: %u\n", vol->lcnbmp_ni->attr_list_size);
    printf("\tAttribute List: %s\n", vol->lcnbmp_ni->attr_list);
    printf("\tNumber of Attached Extent Inodes: %d\n", vol->lcnbmp_ni->nr_extents);
	//FIXME: need to add code for the union if nr_extens != 0, but
	//i dont know if it will ever != 0 with FILE_Bitmap
    
    printf("FILE_Bitmap Data Attribute Information\n");
    printf("\tDecompressed Runlist: not done yet\n");
    printf("\tBase Inode: %llu\n",
		    (unsigned long long)vol->lcnbmp_na->ni->mft_no);
    printf("\tAttribute Types: not done yet\n");
    //printf("\tAttribute Name: %s\n", vol->lcnbmp_na->name);
    printf("\tAttribute Name Length: %u\n", vol->lcnbmp_na->name_len);
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
		    vol->lcnbmp_na->compression_block_size);
    printf("\tCompression Block Size Bits: %u\n",
		    vol->lcnbmp_na->compression_block_size_bits);
    printf("\tCompression Block Clusters: %u\n",
		    vol->lcnbmp_na->compression_block_clusters);
		
    //TODO: Still need to add a few more attributes
}

/**
 * ntfs_dump_standard_information
 */
void ntfs_dump_standard_information_attr(ntfs_inode *inode)
{

	STANDARD_INFORMATION *standard_attr = NULL;
	ATTR_RECORD *attr = NULL;
	ntfs_attr_search_ctx *ctx = NULL;

	ctx = ntfs_attr_get_search_ctx(inode, NULL);

	if(ntfs_attr_lookup(AT_STANDARD_INFORMATION, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx)) {
		if (errno != ENOENT)
			fprintf(stderr, "ntfsinfo error: cannot look up attribute AT_STANDARD_INFORMATION!\n");
		ntfs_attr_put_search_ctx(ctx); //free ctx
		return;
	}

	attr = ctx->attr;

	standard_attr = (STANDARD_INFORMATION*)((char *)attr + le16_to_cpu(attr->value_offset));

	printf("Dumping $STANDARD_INFORMATION (0x10)\n");
	
	//check with flatcap/anton and make sure this is correct
	if (sizeof(STANDARD_INFORMATION) == 48) {
	  printf("\t$STANDARD_INFORMATION fields maximum_versions, version_number, \
		      class_id, owner_id, security_id missing. This volume has \
		      not been upgraded\n");
	}
	if (sizeof(STANDARD_INFORMATION) == 72) {
	    printf("\tMaximum Number of Versions: \t %u \n",
			    le32_to_cpu(standard_attr->maximum_versions));
	    printf("\tVersion Number: \t\t %u \n",
			    le32_to_cpu(standard_attr->version_number));
	    printf("\tClass ID: \t\t\t %u \n",
			    le32_to_cpu(standard_attr->class_id));
	    printf("\tUser ID: \t\t\t %u \n",
			    le32_to_cpu (standard_attr->owner_id));
	    printf("\tSecurity ID: \t\t\t %u \n",
			    le32_to_cpu(standard_attr->security_id));
	} else {
		printf("\tSize of STANDARD_INFORMATION is %u. It should be "
				"either 72 or 48, something is wrong...\n",
				(unsigned)sizeof(STANDARD_INFORMATION));
	}

	ntfs_attr_put_search_ctx(ctx); //free ctx
	
}

/**
 * ntfs_dump_file_name_attribute
 */
void ntfs_dump_file_name_attr(ntfs_inode *inode)
{
	FILE_NAME_ATTR *file_name_attr = NULL;
	ATTR_RECORD *attr = NULL;
	ntfs_attr_search_ctx *ctx = NULL;
	char *file_name = NULL;

	ctx = ntfs_attr_get_search_ctx(inode, NULL);
do_next:
	if(ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx)) {
		if (errno != ENOENT)
			fprintf(stderr, "ntfsinfo error: cannot lookup attribute AT_FILE_NAME!\n");
		ntfs_attr_put_search_ctx(ctx); //free ctx	
		return;
	}

	attr = ctx->attr;

	file_name_attr = (FILE_NAME_ATTR*)((char *)attr + le16_to_cpu(attr->value_offset));

	//need to convert the little endian unicode string to a multibyte string
	ntfs_ucstombs(file_name_attr->file_name, file_name_attr->file_name_length,
			&file_name, file_name_attr->file_name_length);

	printf("Dumping $FILE_NAME (0x30)\n");

	//basic stuff about the file
	printf("\tFile Name: \t\t %s\n", file_name);
	printf("\tFile Name Length: \t %d\n", file_name_attr->file_name_length);
	printf("\tAllocated File Size: \t %lld\n",
			(long long)sle64_to_cpu(file_name_attr->allocated_size));
	printf("\tReal File Size: \t %lld\n",
			(long long)sle64_to_cpu(file_name_attr->data_size));

	//time conversion stuff
	if (!opts.notime) {
	  time_t ntfs_time = { 0 };
	
	  if (!opts.epochtime) {
	    ntfs_time = ntfs2utc (sle64_to_cpu (file_name_attr->creation_time));
	    printf("\tFile Creation Time: \t %s",ctime(&ntfs_time));
	    
	    ntfs_time = ntfs2utc (sle64_to_cpu (file_name_attr->last_data_change_time));
	    printf("\tFile Altered Time: \t %s",ctime(&ntfs_time));
	    
	    ntfs_time = ntfs2utc (sle64_to_cpu (file_name_attr->last_mft_change_time));
	    printf("\tMFT Changed Time: \t %s",ctime(&ntfs_time));
	    
	    ntfs_time = ntfs2utc (sle64_to_cpu (file_name_attr->last_access_time));
	    printf("\tLast Accessed Time: \t %s",ctime(&ntfs_time));
	  } else {
	    char *t = asctime(gmtime(&ntfs_time));
	    printf("\tFile Creation Time: \t %s",t);
	    printf("\tFile Altered Time: \t %s",t);
	    printf("\tMFT Changed Time: \t %s",t);
	    printf("\tLast Accessed Time: \t %s",t);
	  }
	}
	
	free(file_name);
	file_name = NULL;
	goto do_next;
}


/*
 * ntfs_dump_object_id
 *
 * dump the $OBJECT_ID attribute - not present on all systems
 *
 */
void ntfs_dump_object_id_attr(ntfs_inode *inode)
{
    
    OBJECT_ID_ATTR *obj_id_attr = NULL;
    ATTR_RECORD *attr = NULL;
    ntfs_attr_search_ctx *ctx = NULL;

    ctx = ntfs_attr_get_search_ctx(inode, NULL);

	if(ntfs_attr_lookup(AT_OBJECT_ID, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx)) {
		if (errno != ENOENT)
			fprintf(stderr, "ntfsinfo error: cannot look up "
					"attribute AT_OBJECT_ID: %s\n", 
					strerror(errno));
		ntfs_attr_put_search_ctx(ctx);
		return;
	}

    attr = ctx->attr;

    obj_id_attr = (OBJECT_ID_ATTR*)((char *)attr + le16_to_cpu(attr->value_offset)); //the attribute plus the offset

    printf("Dumping $OBJECT_ID (0x40)\n");

    //I believe these attributes are only present on volume versions > 3.0. It was introduced
    //in Win2k, which is 3.0

    //FIXME: Need to do a check to make sure these attributes are actually present
    //even if it is > 3.0. 
    if (inode->vol->major_ver >= 3.0) {
	printf("\tVolume Version > 3.0... Dumping Attributes\n");
	
	//printf("\tObject ID: \t\t\t %d\n", obj_id_attr->object_id);
	//printf("\tBirth Volume ID: \t\t\t %d\n", obj_id_attr->birth_volume_id);
	//printf("\tBirth Object ID: \t\t\t %d\n", obj_id_attr->birth_object_id);
    }

    else 
      printf("\t$OBJECT_ID not present. Only NTFS versions > 3.0 have $OBJECT_ID. \
		  Your version of NTFS is %d\n", inode->vol->major_ver);

    ntfs_attr_put_search_ctx(ctx);
}


/*
 * ntfs_dump_volume_name()
 *
 * dump the name of the volume the inode belongs to
 *
 */
void ntfs_dump_volume_name_attr(ntfs_inode *inode)
{
    VOLUME_NAME *vol_name = NULL;
    ATTR_RECORD *attr = NULL;
    ntfs_attr_search_ctx *ctx = NULL;

    ctx = ntfs_attr_get_search_ctx(inode, NULL);

    if(ntfs_attr_lookup(AT_VOLUME_NAME, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx)) {
	if (errno != ENOENT)
		fprintf(stderr, "ntfsinfo error: cannot look up attribute AT_VOLUME_NAME: %s\n", 
		    strerror(errno));
	ntfs_attr_put_search_ctx(ctx);
	return;
    }

    attr = ctx->attr;

    vol_name = (VOLUME_NAME*)((char *)attr + le16_to_cpu(attr->value_offset));

    printf("Dumping $VOLUME_NAME (0x60)\n");

    //printf("\tVolume Name: \t\t\t %s\n", vol_name->name);

    ntfs_attr_put_search_ctx(ctx);
}


/*
 * ntfs_dump_volume_information()
 *
 * dump the information for the volume the inode belongs to
 *
 */
void ntfs_dump_volume_information_attr(ntfs_inode *inode)
{
    VOLUME_INFORMATION *vol_information = NULL;
    ATTR_RECORD *attr = NULL;
    ntfs_attr_search_ctx *ctx = NULL;

    ctx = ntfs_attr_get_search_ctx(inode, NULL);

    if(ntfs_attr_lookup(AT_VOLUME_INFORMATION, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx)) {
	if (errno != ENOENT)
		fprintf(stderr, "ntfsinfo error: cannot look up attribute AT_VOLUME_INFORMATION: %s\n",
			strerror(errno));
	ntfs_attr_put_search_ctx(ctx);
	return;
    }

    attr = ctx->attr;
    
    vol_information = (VOLUME_INFORMATION*)((char *)attr + le16_to_cpu(attr->value_offset));

    printf("Dumping $VOLUME_INFORMATION (0x70)\n");

    printf("\tVolume Major Version: \t\t\t %d\n", vol_information->major_ver);
    printf("\tVolume Minor Version: \t\t\t %d\n", vol_information->minor_ver);
    printf("\tFlags: \t\t\t Not Finished Yet! \n");

    ntfs_attr_put_search_ctx(ctx);
}


	
/**
 * ntfs_get_file_attributes
 */
void ntfs_get_file_attributes(ntfs_volume *vol, s64 mft_no)
{
	ntfs_inode *inode = NULL;
	//int error;

	inode = ntfs_inode_open(vol, MK_MREF(mft_no, 0));

	//see flatcap.org/ntfs/info for what formatting should look likei
	//FIXME: both $FILE_NAME_ATTR and $STANDARD_INFORMATION has times, when do 
	//we want to output it?
	ntfs_dump_standard_information_attr(inode);
	ntfs_dump_file_name_attr(inode);
	ntfs_dump_object_id_attr(inode);
	ntfs_dump_volume_name_attr(inode);
	ntfs_dump_volume_information_attr(inode);

	ntfs_inode_close(inode);
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

	/* if opts.mft is not 0, then we will print out information about
	 * the volume, such as the sector size and whatnot. 
	 */
	if (opts.mft)
		ntfs_dump_volume(vol);

	if (opts.inode != -1)
		ntfs_get_file_attributes(vol, opts.inode);

	ntfs_umount (vol, FALSE);
	return 0;
}

