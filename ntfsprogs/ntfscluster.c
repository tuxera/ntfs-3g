/**
 * ntfscluster - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002 Richard Russon <ntfs@flatcap.org>
 *
 * This utility will locate the owner of any given sector or cluster.
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
#include <errno.h>
#include <locale.h>
#include <libintl.h>
#include <stdarg.h>
#include <getopt.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include "ntfscluster.h"
#include "types.h"
#include "attrib.h"
#include "utils.h"
#include "volume.h"

static const char *AUTHOR    = "Richard Russon (FlatCap)";
static const char *EXEC_NAME = "ntfscluster";
static struct options opts;

GEN_PRINTF (Eprintf, stderr, NULL,          FALSE)
GEN_PRINTF (Vprintf, stdout, &opts.verbose, TRUE)
GEN_PRINTF (Iprintf, stdout, &opts.quiet,   FALSE)

/**
 * Dprintf - Print debug messages
 */
#ifndef DEBUG
#define Dprintf(...)
#else
void Dprintf (const char *format, ...)
{
	va_list va;
	va_start (va, format);
	vfprintf (stdout, format, va);
	va_end (va);
}
#endif
/**
 * version - Print version information about the program
 *
 * Print a copyright statement and a brief description of the program.
 *
 * Return:  none
 */
void version (void)
{
	Iprintf ("%s v%s Copyright (C) 2002 %s\n***XXX***on "
		"an NTFS Volume\n\n%s is free software, released under the GNU "
		"General Public License\nand you are welcome to redistribute "
		"it under certain conditions.\n%s comes with ABSOLUTELY NO "
		"WARRANTY; for details read the GNU\nGeneral Public License "
		"to be found in the file COPYING in the main\nLinux-NTFS "
		"distribution directory.\n\n",
		EXEC_NAME, VERSION, AUTHOR, EXEC_NAME, EXEC_NAME);
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
	Iprintf ("Usage: %s [options] device\n"
		"    -i        --info           Print information about the volume\n"
		"    -s range  --sector range   Look for objects in this range of sectors\n"
		"    -c range  --cluster range  Look for objects in this range of clusters\n"
		"\n"
		"    -f        --force          Use less caution\n"
		"    -q        --quiet          Less output\n"
		"    -v        --verbose        More output\n"
		"    -V        --version        Version information\n"
		"    -h        --help           Print this help\n\n",
		EXEC_NAME);
	Iprintf ("Please report bugs to: linux-ntfs-dev@lists.sf.net\n\n");
}

/**
 * parse_size - Convert a string representing a size
 * @value:  String to be parsed
 * @size:   Parsed size
 *
 * Read a string and convert it to a number.  Strings may be suffixed to scale
 * them.  Any number without a suffix is assumed to be in bytes.
 *
 * Suffix  Description  Multiple
 *  [tT]    Terabytes     10^12
 *  [gG]    Gigabytes     10^9
 *  [mM]    Megabytes     10^6
 *  [kK]    Kilobytes     10^3
 *
 * Notes:
 *     Only the first character of the suffix is read.
 *     The multipliers are decimal thousands, not binary: 1000, not 1024.
 *     If parse_size fails, @size will not be changed
 *
 * Return:  1  Success
 *	    0  Error, the string was malformed
 */
int parse_size (const char *value, s64 *size)
{
	long long result;
	char *suffix = NULL;

	if (!value || !size)
		return 0;

	Dprintf ("Parsing size '%s'.\n", value);

	result = strtoll (value, &suffix, 10);
	if (result < 0 || errno == ERANGE) {
		Eprintf ("Invalid size '%s'.\n", value);
		return 0;
	}

	if (!suffix) {
		Eprintf ("Internal error, strtoll didn't return a suffix.\n");
		return 0;
	}


	/*if (strlen (suffix) > 1) {
		Eprintf ("Invalid size suffix '%s'.  Use T, G, M, or K.\n", suffix);
		return 0;
	} Can't do this because of ranges*/

	switch (suffix[0]) {
		case 't': case 'T': result *= 1000;
		case 'g': case 'G': result *= 1000;
		case 'm': case 'M': result *= 1000;
		case 'k': case 'K': result *= 1000;
		case '-': case 0:
			break;
		default:
			Eprintf ("Invalid size suffix '%s'.  Use T, G, M, or K.\n", suffix);
			return 0;
	}

	Dprintf ("Parsed size = %lld.\n", result);
	*size = result;
	return 1;
}

/**
 * parse_range - Convert a string representing a range of numbers
 * @string:  The string to be parsed
 * @start:   The beginning of the range will be stored here
 * @finish:  The end of the range will be stored here
 *
 * Read a string of the form n-m.  If the lower end is missing, zero will be
 * substituted.  If the upper end is missing LONG_MAX will be used.  If the
 * string cannot be parsed correctly, @start and @finish will not be changed.
 *
 * Return:  1  Success, a valid string was found
 *	    0  Error, the string was not a valid range
 */
int parse_range (const char *string, s64 *start, s64 *finish)
{
	s64 a, b;
	char *middle;

	if (!string || !start || !finish)
		return 0;

	middle = strchr (string, '-');
	if (string == middle) {
		Dprintf ("Range has no beginning, defaulting to 0.\n");
		a = 0;
	} else {
		if (!parse_size (string, &a))
			return 0;
	}

	if (middle) {
		if (middle[1] == 0) {
			b = LONG_MAX;		// XXX ULLONG_MAX
			Dprintf ("Range has no end, defaulting to %lld.\n", b);
		} else {
			if (!parse_size (middle+1, &b))
				return 0;
		}
	} else {
		b = a;
	}

	Dprintf ("Range '%s' = %lld - %lld\n", string, a, b);

	*start  = a;
	*finish = b;
	return 1;
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
	static const char *sopt = "-c:fhiqs:vV";
	static const struct option lopt[] = {
		{ "cluster",	required_argument,	NULL, 'c' },
		{ "force",	no_argument,		NULL, 'f' },
		{ "help",	no_argument,		NULL, 'h' },
		{ "info",	no_argument,		NULL, 'i' },
		{ "quiet",	no_argument,		NULL, 'q' },
		{ "sector",	required_argument,	NULL, 's' },
		{ "verbose",	no_argument,		NULL, 'v' },
		{ "version",	no_argument,		NULL, 'V' },
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
			} else {
				opts.device = NULL;
				err++;
			}
			break;

		case 'c':
			if ((opts.cluster_begin > 0) || (opts.cluster_end > 0) ||
			    !parse_range (optarg, &opts.cluster_begin, &opts.cluster_end)) {
				err++;
			}
			break;
		case 'f':
			opts.force++;
			break;
		case 'h':
			help++;
			break;
		case 'i':
			opts.info++;
			break;
		case 'q':
			opts.quiet++;
			break;
		case 's':
			if ((opts.sector_begin > 0) || (opts.sector_end > 0) ||
			    !parse_range (optarg, &opts.sector_begin, &opts.sector_end)) {
				err++;
			}
			break;
		case 'v':
			opts.verbose++;
			break;
		case 'V':
			ver++;
			break;
		default:
			if ((optopt == 'c') || (optopt == 's')) {
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
			Eprintf ("You must specify exactly one device.\n");
			err++;
		}

		if (opts.quiet && opts.verbose) {
			Eprintf ("You may not use --quiet and --verbose at the same time.\n");
			err++;
		}

		if (opts.sector_end && opts.cluster_end) {
			Eprintf ("You must specify either a sector or a cluster.\n");
			err++;
		}
		if (opts.cluster_begin > opts.cluster_end) {
			Eprintf ("The cluster range must be in ascending order.\n");
			err++;
		}
		if (opts.sector_begin > opts.sector_end) {
			Eprintf ("The sector range must be in ascending order.\n");
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
 * mftrec_in_use - Determine if a MFT Record is in use
 * @vol:   An ntfs volume obtained from ntfs_mount
 * @mref:  MFT Reference (inode number)
 *
 * The metadata file $BITMAP has one binary bit representing each record in the
 * MFT.  The bit will be set for each record that is in use.  The function
 * reads the relevant part of $BITMAP into a buffer and tests the bit.
 *
 * This function has a static buffer in which it caches a section of $BITMAP.
 * If the mref, being tested, lies outside the range, the buffer will be
 * refreshed.
 *
 * Return:  1  MFT Record is in use
 *	    0  MFT Record is unused
 *	   -1  Error occurred
 */
int mftrec_in_use (ntfs_volume *vol, MFT_REF mref)
{
	static u8 buffer[512];
	static s64 bmpmref = -sizeof (buffer) - 1; /* Which bit of $BITMAP is in the buffer */

	int byte, bit;

	if (!vol)
		return -1;

	/* Does mref lie in the section of $Bitmap we already have cached? */
	if ((mref < bmpmref) || (mref >= (bmpmref + (sizeof (buffer) << 3)))) {
		Dprintf ("Bit lies outside cache.\n");

		/* Mark the buffer as not in use, in case the read is shorter. */
		memset (buffer, 0, sizeof (buffer));
		bmpmref = mref & (~((sizeof (buffer) << 3) - 1));

		if (ntfs_attr_pread (vol->mftbmp_na, (bmpmref>>3), sizeof (buffer), buffer) < 0) {
			Eprintf ("Couldn't read $MFT/$BITMAP: %s\n", strerror (errno));
			return -1;
		}

		Dprintf ("Reloaded bitmap buffer.\n");
	}

	bit  = 1 << (mref & 7);
	byte = (mref >> 3) & (sizeof (buffer) - 1);
	Dprintf ("cluster = %lld, bmpmref = %lld, byte = %d, bit = %d, in use %d\n",
		mref, bmpmref, byte, bit, buffer[byte] & bit);

	return (buffer[byte] & bit);
}

/**
 * cluster_find
 */
int cluster_find (ntfs_volume *vol, LCN s_begin, LCN s_end)
{
	int i;
	int result = 1;
	u8 *buffer;

	if (!vol)
		return 1;

	buffer = malloc (vol->mft_record_size);
	if (!buffer) {
		Eprintf ("Couldn't allocate memory.\n");
		return 1;
	}

	for (i = 0; i < vol->nr_mft_records; i++) {
	//for (i = 0; i < 30; i++) {
	//for (i = 162; i < 175; i++) {
		ntfs_inode *inode;
		ntfs_attr_search_ctx *ctx;

		if (!mftrec_in_use (vol, i)) {
			//printf ("%d skipped\n", i);
			continue;
		}

		inode = ntfs_inode_open (vol, i);
		if (!inode) {
			Eprintf ("Can't read inode %d\n", i);
			goto free;
		}

		if (inode->nr_extents == -1) {
			printf ("inode %d is an extent record\n", i);
			goto close;
		}

		Vprintf ("Inode: %d\n", i);
		ctx = ntfs_attr_get_search_ctx (inode, NULL);

		if (ntfs_attr_lookup (AT_STANDARD_INFORMATION, NULL, 0, IGNORE_CASE, 0, NULL, 0, ctx) < 0) {
			//printf ("extent inode\n");
			continue;
		}
		ntfs_attr_reinit_search_ctx (ctx);

		//printf ("Searching for cluster range %lld-%lld\n", s_begin, s_end);
		while (ntfs_attr_lookup (AT_UNUSED, NULL, 0, IGNORE_CASE, 0, NULL, 0, ctx) >= 0) {
			runlist_element *runs;
			int j;

			if (!ctx->attr->non_resident) {
				//printf ("0x%02X ", ctx->attr->type);
				continue;
			}

			runs = ntfs_mapping_pairs_decompress (vol, ctx->attr, NULL);
			if (!runs) {
				Eprintf ("Couldn't read the data runs.\n");
				ntfs_inode_close (inode);
				goto free;
			}

			Vprintf ("\t[0x%02X]\n", ctx->attr->type);

			Vprintf ("\t\tVCN\tLCN\tLength\n");
			for (j = 0; runs[j].length > 0; j++) {
				LCN a_begin = runs[j].lcn;
				LCN a_end   = a_begin + runs[j].length - 1;

				if (a_begin < 0)
					continue;	// sparse, discontiguous, etc

				Vprintf ("\t\t%lld\t%lld-%lld (%lld)\n", runs[j].vcn, runs[j].lcn, runs[j].lcn + runs[j].length - 1, runs[j].length);
				//Vprintf ("\t\t%lld\t%lld\t%lld\n", runs[j].vcn, runs[j].lcn, runs[j].length);
				//dprint list

				if (a_begin > s_end) {
					continue;	// after search range (5)
				}
				if (a_end < s_begin) {
					continue;	// before search range (1)
				}
				printf ("inode %d matches\n", i);
				break;
			}
		}

		ntfs_attr_put_search_ctx (ctx);
		ctx = NULL;
close:
		//printf ("\n");
		ntfs_inode_close (inode);
	}
free:
	free (buffer);
	result = 0;
	return result;
}

/**
 * my_locale
 */
int my_locale (void)
{
	const char *locale;

	locale = setlocale (LC_ALL, "");
	if (!locale) {
		locale = setlocale (LC_ALL, NULL);
		Vprintf ("Failed to set locale, using default '%s'.\n", locale);
		return 1;
	} else {
		Vprintf ("Using locale '%s'.\n", locale);
		return 0;
	}
}

/**
 * get_vol
 */
ntfs_volume * get_vol (const char *device, unsigned long flags, BOOL force)
{
	ntfs_volume *vol;

	if (!device)
		return NULL;

	if (!valid_device (device, force))
		return NULL;

	vol = ntfs_mount (device, MS_RDONLY);
	if (!vol) {
		Eprintf ("Couldn't mount device '%s': %s\n", device, strerror (errno));
		return NULL;
	}

	if (vol->flags & VOLUME_IS_DIRTY) {
		Iprintf ("Volume is dirty.\n");
		if (!force) {
			Eprintf ("Run chkdsk and try again, or use the --force option.\n");
			ntfs_umount (vol, FALSE);
			return NULL;
		}
		Iprintf ("Forced to continue.\n");
	}

	return vol;
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
	int result;

	if (!parse_options (argc, argv))
		return 1;

	my_locale();

	vol = get_vol (opts.device, MS_RDONLY, opts.force);
	if (!vol)
		return 1;

#if 0
	if (opts.info) {
		//result = get_info (vol);
	} else if (opts.cluster) {
		result = cluster_find (vol, opts.cluster);
	} else if (opts.sector) {
		//result = 
	} else {
		//result = 
	}
#endif
	//opts.cluster_end = LONG_MAX;
	printf ("Searching for cluster range %lld-%lld\n", opts.cluster_begin, opts.cluster_end);
	result = cluster_find (vol, opts.cluster_begin, opts.cluster_end);

	ntfs_umount (vol, FALSE);
	return result;
}

