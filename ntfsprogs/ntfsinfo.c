/*
 * ntfsinfo - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002 Matthew J. Fanto
 * Copyright (c) 2002 Anton Altaparmakov
 * Copyright (c) 2002 Richard Russon
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
#include <string.h>
#include <errno.h>
#include <locale.h>
#include <time.h>
#include "types.h"
#include "mft.h"
#include "attrib.h"
#include "layout.h"
#include "inode.h"

void ntfs_get_file_attributes(const char *dev, long int i);
void ntfs_dump_file_name_attribute(ntfs_inode *inode, MFT_RECORD *mrec);
void ntfs_dump_standard_information(ntfs_inode *inode, MFT_RECORD *mrec);

/**
 * ntfs2utc - Convert an NTFS time to Unix time
 * @time:  An NTFS time in 100ns units since 1601
 *
 * NTFS stores times as the number of 100ns intervals since January 1st 1601 at
 * 00:00 UTC.  This system will not suffer from Y2K problems until ~57000AD.
 *
 * Return:  n  A Unix time (number of seconds since 1970)
 */
time_t ntfs2utc (long long time)
{
	return (time - ((long long) (369 * 365 + 89) * 24 * 3600 * 10000000)) / 10000000;
}

#define NTFS_TIME_OFFSET ((u64)(369*365 + 89) * 24 * 3600 * 10000000)

int main(int argc, char **argv)
{
	const char *AUTHOR = "Matthew J. Fanto";
	const char *EXEC_NAME = "ntfsinfo";
	const char *locale;
	long i;

	locale = setlocale(LC_ALL, "");
	if (!locale) {
		char *locale;

		locale = setlocale(LC_ALL, NULL);
		printf("Failed to set locale, using default (%s).\n", locale);
	}

	if (argc < 3 || argc > 4) {
		fprintf(stderr, "%s v%s - %s\n", EXEC_NAME, VERSION, AUTHOR);
		fprintf(stderr, "Usage: ntfsinfo device inode\n");
		exit(1);
	}

	else {
		i = atoll(argv[2]);
		ntfs_get_file_attributes(argv[1], i);
	}

	return 0;
}

void ntfs_get_file_attributes(const char *dev, long int i)
{

	MFT_REF mref;
	MFT_RECORD *mrec = NULL;
	//ntfs_attr_search_ctx *ctx = NULL;
	ntfs_volume *vol = NULL;
	ntfs_inode *inode = NULL;
	//int error;

	if(!(vol = ntfs_mount(dev, 0))) {
		fprintf(stderr, "ntfsinfo error: cannot mount device %s\n",dev);
		exit(1);
	}

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

void ntfs_dump_file_name_attribute(ntfs_inode *inode, MFT_RECORD *mrec)
{
	FILE_NAME_ATTR *file_name_attr = NULL;
	ATTR_RECORD *attr = NULL;
	ntfs_attr_search_ctx *ctx = NULL;
	char *file_name;
	time_t ntfs_time;

	ctx = ntfs_attr_get_search_ctx(inode, mrec);

	if(ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx)) {
		fprintf(stderr, "ntfsinfo error: cannot lookup attribute AT_FILE_NAME!\n");
		return;
	}

	attr = ctx->attr;

	file_name_attr = (FILE_NAME_ATTR*)((char *)attr + le16_to_cpu(attr->value_offset));

	file_name = malloc(file_name_attr->file_name_length * sizeof(char));

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
	ntfs_time = ntfs2utc(file_name_attr->creation_time);
	printf("File Creation Time: \t %s",ctime(&ntfs_time));

	ntfs_time = ntfs2utc(file_name_attr->last_data_change_time);
	printf("File Altered Time: \t %s",ctime(&ntfs_time));

	ntfs_time = ntfs2utc(file_name_attr->last_mft_change_time);
	printf("MFT Changed Time: \t %s",ctime(&ntfs_time));

	ntfs_time = ntfs2utc(file_name_attr->last_access_time);
	printf("Last Acced Time: \t %s",ctime(&ntfs_time));

	free(file_name);

}

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

	printf("Maximum Number of Versions: \t %d \n",standard_attr->maximum_versions);
	printf("Version Number: \t\t %d \n",standard_attr->version_number);
	printf("Class ID: \t\t\t %d \n",standard_attr->class_id);
	printf("User ID: \t\t\t %d \n", standard_attr->owner_id);
	printf("Security ID: \t\t\t %d \n", standard_attr->security_id);

}

