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
#include "types.h"
#include "mft.h"
#include "attrib.h"
#include "layout.h"
#include "inode.h"

void get_file_attribute_value(const char *dev, long int i);
void print_standard_information_attr(ntfs_attr_search_ctx * ctx);
void print_file_name_attr(ntfs_attr_search_ctx * ctx);


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
	} else
		printf("Using locale %s.\n", locale);

	if (argc < 3 || argc > 4) {
		fprintf(stderr, "%s v%s - %s\n", EXEC_NAME, VERSION, AUTHOR);
		fprintf(stderr, "Usage: ntfsinfo device inode\n");
		exit(1);
	}

	else {
		i = atoll(argv[2]);
		get_file_attribute_value(argv[1], i);
	}

	return 0;
}

void get_file_attribute_value(const char *dev, long int i)
{

	MFT_REF mref;
	MFT_RECORD *mrec = NULL;
	//ATTR_RECORD *attr = NULL;
	//FILE_NAME_ATTR *file_name_attr = NULL;
	//STANDARD_INFORMATION *standard_information = NULL;
	//SECURITY_DESCRIPTOR_RELATIVE *security_descriptor = NULL;
	ntfs_attr_search_ctx *ctx = NULL;
	ntfs_volume *vol = NULL;
	//char *file_name;
	ntfs_inode *inode = NULL;

	vol = ntfs_mount(dev, 0);

	mref = (MFT_REF) i;
	inode = ntfs_open_inode(vol, mref);

	if (ntfs_file_record_read(vol, mref, &mrec, NULL)) {
		perror("Error reading file record!\n");
		exit(1);
	}

	ctx = ntfs_get_attr_search_ctx(inode, mrec);

//	print_file_name_attr(ctx);

//	ctx = ntfs_get_attr_search_ctx(inode, mrec);	//need to fix this

	print_standard_information_attr(ctx);
}


s64 ntfs2time(s64 time)
{
	s64 t;
	printf("Original Time: %Li\n",time);
	t = time - NTFS_TIME_OFFSET;
	t = t / 10000000;
	return t;


}

void print_standard_information_attr(ntfs_attr_search_ctx *ctx)
{
	ATTR_RECORD *attr = NULL;
	STANDARD_INFORMATION *standard_information_attr = NULL;

	if (ntfs_lookup_attr
		(AT_STANDARD_INFORMATION, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx)) {
		perror("Error looking up $STANDARD_INFORMATION!\n");
		exit(1);
	}

	attr = ctx->attr;

	standard_information_attr =
	    (STANDARD_INFORMATION *) ((char *) attr +
				      le16_to_cpu(attr->value_offset));

	printf("Creation time: %Li\n",
		ntfs2time(standard_information_attr->creation_time));
/*	printf("Last Data Change Time: %Li\n",
	       ntfs2time(standard_information_attr->last_data_change_time));
	printf("Last MFT Change Time: %Li\n",
	       ntfs2time(standard_information_attr->last_mft_change_time));
	printf("Last Access Time: %Li\n",
	       ntfs2time(standard_information_attr->last_access_time));
	printf("Maxium Versions: %d\n",
		standard_information_attr->maximum_versions);
	printf("Version Number: %d\n",
		standard_information_attr->version_number);
	printf("Class ID: %d\n",
		standard_information_attr->class_id);
	printf("Owner ID: %d\n",
		standard_information_attr->owner_id);
	printf("Security ID: %d\n",
		standard_information_attr->security_id);

*/
}

void print_file_name_attr(ntfs_attr_search_ctx *ctx)
{
	ATTR_RECORD *attr = NULL;
	ntfs_attr_search_ctx *c = ctx;
	FILE_NAME_ATTR *file_name_attr = NULL;
	char *file_name;

	if (ntfs_lookup_attr(AT_FILE_NAME, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx)) {
		perror("Error looking up $FILE_NAME_ATTR!\n");
		exit(1);
	}

	attr = ctx->attr;
	ctx = c;

	file_name_attr =
	    (FILE_NAME_ATTR *) ((char *) attr +
				le16_to_cpu(attr->value_offset));

	file_name = malloc(file_name_attr->file_name_length * sizeof (char));

	ntfs_ucstombs(file_name_attr->file_name,
		      file_name_attr->file_name_length, &file_name,
		      file_name_attr->file_name_length);

	printf("File Name: %s\n", file_name);
	printf("File Name Length: %d\n", file_name_attr->file_name_length);
	printf("Allocated Size: %Li\n",sle64_to_cpu(file_name_attr->allocated_size));
	printf("Data Size: %Li\n",sle64_to_cpu(file_name_attr->data_size));
}

/*void print_security_descriptor_attr(SECURITY_DESCRIPTOR_RELATIVE *security_descriptor)
{

}*/
