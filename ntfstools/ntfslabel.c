/*
 * $Id$
 *
 * ntfslabel - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002 Matthew J. Fanto
 * Copyright (c) 2002 Anton Altaparmakov
 * Copyright (c) 2002 Richard Russon
 *
 * This utility will display/change the label on an NTFS partition.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <locale.h>

#include "debug.h"
#include "mft.h"

/*
 * print_label - display the current label of a mounted ntfs partition.
 * @dev:	device to read the label from
 * @mnt_flags:	mount flags of the device or 0 if not mounted
 * @mnt_point:	mount point of the device or NULL
 *
 * Print the label of the device @dev to stdout.
 */
void print_label(const char *dev, const unsigned long mnt_flags,
		const char *mnt_point)
{
	ntfs_volume *vol;

	if (mnt_point) {
		// Try ioctl and finish if present.
		// goto finished;
	}
	if ((mnt_flags & (NTFS_MF_MOUNTED | NTFS_MF_READONLY)) ==
			NTFS_MF_MOUNTED) {
		fprintf(stderr, "%s is mounted read-write, results may be "
				"unreliable.\n", dev);
	}
	vol = ntfs_mount(dev, MS_RDONLY);
	if (!vol) {
		fprintf(stderr, "ntfs_mount() on device %s failed: %s\n", dev,
				strerror(errno));
		exit(1);
	}
//finished:
	printf("%s\n", vol->vol_name);
	if (ntfs_umount(vol, 0))
		ntfs_umount(vol, 1);
}

/*
 * resize_resident_attribute_value - resize a resident attribute
 * @m:		mft record containing attribute to resize
 * @a:		attribute record (inside @m) which to resize
 * @new_vsize:	the new attribute value size to resize the attribute to
 *
 * Return 0 on success and -1 with errno = ENOSPC if not enough space in the
 * mft record.
 */
int resize_resident_attribute_value(MFT_RECORD *m, ATTR_RECORD *a,
		const u32 new_vsize)
{
	int new_alen, new_muse;

	/* New attribute length and mft record bytes used. */
	new_alen = (le16_to_cpu(a->value_offset) + new_vsize + 7) & ~7;
	new_muse = le32_to_cpu(m->bytes_in_use) - le32_to_cpu(a->length) +
			new_alen;
	/* Check for sufficient space. */
	if (new_muse > le32_to_cpu(m->bytes_allocated)) {
		errno = ENOSPC;
		return -1;
	}
	/* Move attributes behind @a to their new location. */
	memmove((char*)a + new_alen, (char*)a + le32_to_cpu(a->length),
			le32_to_cpu(m->bytes_in_use) - ((char*)a - (char*)m) -
			le32_to_cpu(a->length));
	/* Adjust @m to reflect change in used space. */
	m->bytes_in_use = cpu_to_le32(new_muse);
	/* Adjust @a to reflect new value size. */
	a->length = cpu_to_le32(new_alen);
	a->value_length = cpu_to_le32(new_vsize);
	return 0;
}

/*
 * change_label - change the current label on a device
 * @dev:	device to change the label on
 * @mnt_flags:	mount flags of the device or 0 if not mounted
 * @mnt_point:	mount point of the device or NULL
 * @label:	the new label
 *
 * Change the label on the device @dev to @label.
 */
void change_label(const char *dev, const unsigned long mnt_flags,
		const char *mnt_point, char *label, BOOL force)
{
	ntfs_attr_search_ctx *ctx = NULL;
	uchar_t *new_label = NULL;
	MFT_RECORD *mrec = NULL;
	ATTR_RECORD *a;
	ntfs_volume *vol;
	int label_len, err = 1;

	if (mnt_point) {
		// Try ioctl and return if present.
		// return;
	}
	if (mnt_flags & NTFS_MF_MOUNTED) {
		/* If not the root fs or mounted read/write, refuse change. */
		if (!(mnt_flags & NTFS_MF_ISROOT) ||
				!(mnt_flags & NTFS_MF_READONLY)) {
			if (!force) {
				fprintf(stderr, "Refusing to change label on "
						"read-%s mounted device %s.\n",
						mnt_flags & NTFS_MF_READONLY ?
						"only" : "write", dev);
				return;
			}
		}
	}
	vol = ntfs_mount(dev, 0);
	if (!vol) {
		fprintf(stderr, "ntfs_mount() on device %s failed: %s\n", dev,
				strerror(errno));
		exit(1);
	}
	if (ntfs_read_file_record(vol, (MFT_REF)FILE_Volume, &mrec, NULL)) {
		perror("Error reading file record");
		goto err_out;
	}
	if (!(mrec->flags & MFT_RECORD_IN_USE)) {
		fprintf(stderr, "Error: $Volume has been deleted. Run "
				"chkdsk to fix this.\n");
		goto err_out;
	}
	ctx = ntfs_get_attr_search_ctx(NULL, mrec);
	if (!ctx) {
		perror("Failed to get attribute search context");
		goto err_out;
	}
	if (ntfs_lookup_attr(AT_VOLUME_NAME, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx)) {
		perror("Lookup of $VOLUME_NAME attribute failed");
		goto err_out;
	}
	a = ctx->attr;
	if (a->non_resident) {
		fprintf(stderr, "Error: Attribute $VOLUME_NAME must be "
				"resident.\n");
		goto err_out;
	}
	label_len = ntfs_mbstoucs(label, &new_label, 0);
	if (label_len == -1) {
		perror("Unable to convert label string to Unicode");
		goto err_out;
	}
	label_len *= sizeof(uchar_t);
	if (label_len > 0x100) {
		fprintf(stderr, "New label is too long. Maximum %i characters "
				"allowed. Truncating excess characters.\n",
				0x100 / sizeof(uchar_t));
		label_len = 0x100;
		new_label[label_len / sizeof(uchar_t)] = cpu_to_le16(L'\0');
	}
	if (resize_resident_attribute_value(mrec, a, label_len)) {
		perror("Error resizing resident attribute");
		goto err_out;
	}
	memcpy((char*)a + le16_to_cpu(a->value_offset), new_label, label_len);
	if (ntfs_write_mft_record(vol, (MFT_REF)FILE_Volume, mrec)) {
		perror("Error writing MFT Record to disk");
		goto err_out;
	}
	err = 0;
err_out:
	if (new_label)
		free(new_label);
	if (mrec)
		free(mrec);
	if (ntfs_umount(vol, 0))
		ntfs_umount(vol, 1);
	if (err)
		exit(1);
}

int main(int argc, char **argv)
{
	const char *AUTHOR = "Matthew Fanto";
	char *EXEC_NAME = "ntfslabel";
	char *locale, *mnt_point = NULL;
	unsigned long mnt_flags;
	int err;
	// FIXME:Implement option -F meaning force the change.
	BOOL force = 0;

	locale = setlocale(LC_ALL, "");
	if (!locale) {
		char *locale;

		locale = setlocale(LC_ALL, NULL);
		Dprintf("Failed to set locale, using default (%s).\n", locale);
	} else
		Dprintf("Using locale %s.\n", locale);
	if (argc && *argv)
		EXEC_NAME = *argv;
	if (argc < 2 || argc > 3) {
		fprintf(stderr, "%s v%s - %s\n", EXEC_NAME, VERSION, AUTHOR);
		fprintf(stderr, "Usage: ntfslabel device [newlabel]\n");
		exit(1);
	}
	err = ntfs_check_if_mounted(argv[1], &mnt_flags);
	if (err)
		fprintf(stderr, "Failed to determine whether %s is mounted: "
				"%s\n", argv[1], strerror(errno));
	else if (mnt_flags & NTFS_MF_MOUNTED) {
	// Not implemented yet. Will be used for ioctl interface to driver.
	//	mnt_point = ntfs_get_mount_point(argv[1]);
	}
	if (argc == 2)
		print_label(argv[1], mnt_flags, mnt_point);
	else
		change_label(argv[1], mnt_flags, mnt_point, argv[2], force);
	return 0;
}

