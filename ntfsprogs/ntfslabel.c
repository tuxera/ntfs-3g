/**
 * ntfslabel - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002 Matthew J. Fanto
 * Copyright (c) 2002 Anton Altaparmakov
 * Copyright (c) 2002-2003 Richard Russon
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
#include <getopt.h>

#include "debug.h"
#include "mft.h"
#include "utils.h"

static const char *EXEC_NAME = "ntfslabel";

static struct options {
	char	*device;	/* Device/File to work with */
	char	*label;		/* Set the label to this */
	int	 quiet;		/* Less output */
	int	 verbose;	/* Extra output */
	int	 force;		/* Override common sense */
	int	 noaction;	/* Do not write to disk */
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
	printf ("\n%s v%s - Display, or set, the label for an NTFS Volume.\n\n",
		EXEC_NAME, VERSION);
	printf ("Copyright (c)\n");
	printf ("    2002      Matthew J. Fanto\n");
	printf ("    2002      Anton Altaparmakov\n");
	printf ("    2002-2003 Richard Russon\n");
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
	printf ("\nUsage: %s [options] device [label]\n"
	       "    -n    --no-action    Do not write to disk\n"
	       "    -f    --force        Use less caution\n"
	       "    -q    --quiet        Less output\n"
	       "    -v    --verbose      More output\n"
	       "    -V    --version      Display version information\n"
	       "    -h    --help         Display this help\n\n",
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
	static const char *sopt = "-fh?nqvV";
	static const struct option lopt[] = {
		{ "force",	 no_argument,		NULL, 'f' },
		{ "help",	 no_argument,		NULL, 'h' },
		{ "no-action",	 no_argument,		NULL, 'n' },
		{ "quiet",	 no_argument,		NULL, 'q' },
		{ "verbose",	 no_argument,		NULL, 'v' },
		{ "version",	 no_argument,		NULL, 'V' },
		{ NULL, 0, NULL, 0 },
	};

	char c = -1;
	int err  = 0;
	int ver  = 0;
	int help = 0;

	opterr = 0; /* We'll handle the errors, thank you. */

	while ((c = getopt_long (argc, argv, sopt, lopt, NULL)) != -1) {
		switch (c) {
		case 1:	/* A non-option argument */
			if (!err && !opts.device)
				opts.device = argv[optind-1];
			else if (!err && !opts.label)
				opts.label = argv[optind-1];
			else
				err++;
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
		case 'v':
			opts.verbose++;
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
		opts.quiet = 0;
	} else {
		if (opts.device == NULL) {
			if (argc > 1)
				Eprintf ("You must specify a device.\n");
			err++;
		}

		if (opts.quiet && opts.verbose) {
			Eprintf ("You may not use --quiet and --verbose at the same time.\n");
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
 * print_label - display the current label of a mounted ntfs partition.
 * @dev:	device to read the label from
 * @mnt_flags:	mount flags of the device or 0 if not mounted
 * @mnt_point:	mount point of the device or NULL
 *
 * Print the label of the device @dev to stdout.
 */
int print_label (ntfs_volume *vol, unsigned long mnt_flags)
{
	int result = 0;
	//XXX significant?
	if ((mnt_flags & (NTFS_MF_MOUNTED | NTFS_MF_READONLY)) ==
			NTFS_MF_MOUNTED) {
		Eprintf ("%s is mounted read-write, results may be "
			"unreliable.\n", opts.device);
		result = 1;
	}

	printf("%s\n", vol->vol_name);
	return result;
}

/**
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

/**
 * change_label - change the current label on a device
 * @dev:	device to change the label on
 * @mnt_flags:	mount flags of the device or 0 if not mounted
 * @mnt_point:	mount point of the device or NULL
 * @label:	the new label
 *
 * Change the label on the device @dev to @label.
 */
int change_label(ntfs_volume *vol, unsigned long mnt_flags, char *label, BOOL force)
{
	ntfs_attr_search_ctx *ctx = NULL;
	uchar_t *new_label = NULL;
	MFT_RECORD *mrec = NULL;
	ATTR_RECORD *a;
	int label_len;
	int result = 0;

	//XXX significant?
	if (mnt_flags & NTFS_MF_MOUNTED) {
		/* If not the root fs or mounted read/write, refuse change. */
		if (!(mnt_flags & NTFS_MF_ISROOT) ||
				!(mnt_flags & NTFS_MF_READONLY)) {
			if (!force) {
				fprintf(stderr, "Refusing to change label on "
						"read-%s mounted device %s.\n",
						mnt_flags & NTFS_MF_READONLY ?
						"only" : "write", opts.device);
				return 1;
			}
		}
	}

	if (ntfs_file_record_read(vol, (MFT_REF)FILE_Volume, &mrec, NULL)) {
		perror("Error reading file record");
		goto err_out;
	}
	if (!(mrec->flags & MFT_RECORD_IN_USE)) {
		fprintf(stderr, "Error: $Volume has been deleted. Run "
				"chkdsk to fix this.\n");
		goto err_out;
	}
	ctx = ntfs_attr_get_search_ctx(NULL, mrec);
	if (!ctx) {
		perror("Failed to get attribute search context");
		goto err_out;
	}
	if (ntfs_attr_lookup(AT_VOLUME_NAME, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx)) {
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
	if (ntfs_mft_record_write(vol, (MFT_REF)FILE_Volume, mrec)) {
		perror("Error writing MFT Record to disk");
		goto err_out;
	}
	result = 0;
err_out:
	if (new_label)
		free(new_label);
	if (mrec)
		free(mrec);
	return result;
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
	unsigned long mnt_flags = 0;
	int result = 0;
	ntfs_volume *vol;

	if (!parse_options (argc, argv))
		return 1;

	utils_set_locale();

	//XXX need to set and get mount flags
	vol = utils_mount_volume (opts.device, 0, opts.force);
	if (!vol)
		return 1;

	if (opts.label)
		result = change_label (vol, mnt_flags, opts.label, opts.force);
	else
		result = print_label (vol, mnt_flags);

	ntfs_umount (vol, FALSE);
	return result;
}

