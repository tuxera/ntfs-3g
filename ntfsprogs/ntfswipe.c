/**
 * ntfswipe - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002 Richard Russon <ntfs@flatcap.org>
 *
 * This utility will overwrite usused space on an NTFS volume.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <locale.h>
#include <libintl.h>
#include <stdarg.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>

#include "ntfswipe.h"
#include "types.h"
#include "volume.h"

static const char *AUTHOR    = "Richard Russon (FlatCap)";
static const char *EXEC_NAME = "ntfswipe";
static struct options opts;

/**
 * Eprintf - Print error messages
 */
void Eprintf (const char *format, ...)
{
	va_list va;
	va_start (va, format);
	vfprintf (stderr, format, va);
	va_end (va);
}

/**
 * Iprintf - Print informative messages
 */
void Iprintf (const char *format, ...)
{
	va_list va;
#ifndef DEBUG
	if (opts.quiet)
		return;
#endif
	va_start (va, format);
	vfprintf (stdout, format, va);
	va_end (va);
}

/**
 * Vprintf - Print verbose messages
 */
void Vprintf (const char *format, ...)
{
	va_list va;
#ifndef DEBUG
	if (!opts.verbose)
		return;
#endif
	va_start (va, format);
	vfprintf (stdout, format, va);
	va_end (va);
}

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
 * wipe_unused - Wipe unused clusters
 * @vol:   An ntfs volume obtained from ntfs_mount
 * @byte:  Overwrite with this value
 *
 * Read $Bitmap and wipe any clusters that are marked as not in use.
 *
 * Return:  1  Success, the clusters were wiped
 *          0  Error, something went wrong
 */
int wipe_unused (ntfs_volume *vol, int byte)
{
	if (!vol || (byte < 0))
		return 0;

	Iprintf ("wipe_unused 0x%02x\n", byte);
	return 1;
}

/**
 * wipe_tails - Wipe the file tails
 * @vol:   An ntfs volume obtained from ntfs_mount
 * @byte:  Overwrite with this value
 *
 * Disk space is allocated in clusters.  If a file isn't an exact multiple of
 * the cluster size, there is some slack space at the end.  Wipe this space.
 *
 * Return:  1  Success, the clusters were wiped
 *          0  Error, something went wrong
 */
int wipe_tails (ntfs_volume *vol, int byte)
{
	if (!vol || (byte < 0))
		return 0;

	Iprintf ("wipe_tails 0x%02x\n", byte);
	return 1;
}

/**
 * wipe_mft - Wipe the MFT slack space
 * @vol:   An ntfs volume obtained from ntfs_mount
 * @byte:  Overwrite with this value
 *
 * MFT Records are 1024 bytes long, but some of this space isn't used.  Wipe any
 * unused space at the end of the record and wipe any unused records.
 *
 * Return:  1  Success, the clusters were wiped
 *          0  Error, something went wrong
 */
int wipe_mft (ntfs_volume *vol, int byte)
{
	if (!vol || (byte < 0))
		return 0;

	Iprintf ("wipe_mft 0x%02x\n", byte);
	return 1;
}

/**
 * wipe_directory - Wipe the directiry indexes
 * @vol:   An ntfs volume obtained from ntfs_mount
 * @byte:  Overwrite with this value
 *
 * Directories are kept in sorted B+ Trees.  Index blocks may not be full.  Wipe
 * the unused space at the ends of these blocks.
 *
 * Return:  1  Success, the clusters were wiped
 *          0  Error, something went wrong
 */
int wipe_directory (ntfs_volume *vol, int byte)
{
	if (!vol || (byte < 0))
		return 0;

	Iprintf ("wipe_directory 0x%02x\n", byte);
	return 1;
}

/**
 * wipe_logfile - Wipe the logfile (journal)
 * @vol:   An ntfs volume obtained from ntfs_mount
 * @byte:  Overwrite with this value
 *
 * The logfile journals the metadata to give the volume fault-tolerance.  If the
 * volume is in a consistant state, then this information can be erased.
 *
 * Return:  1  Success, the clusters were wiped
 *          0  Error, something went wrong
 */
int wipe_logfile (ntfs_volume *vol, int byte)
{
	if (!vol || (byte < 0))
		return 0;

	Iprintf ("wipe_logfile 0x%02x\n", byte);
	return 1;
}

/**
 * wipe_pagefile - Wipe the pagefile (swap space)
 * @vol:   An ntfs volume obtained from ntfs_mount
 * @byte:  Overwrite with this value
 *
 * pagefile.sys is used by Windows as extra virtual memory (swap space).
 * Windows recreates the file at bootup, so it can be wiped without harm.
 *
 * Return:  1  Success, the clusters were wiped
 *          0  Error, something went wrong
 */
int wipe_pagefile (ntfs_volume *vol, int byte)
{
	if (!vol || (byte < 0))
		return 0;

	Iprintf ("wipe_pagefile 0x%02x\n", byte);
	return 1;
}

/**
 * ntfs_info - Display information about the NTFS Volume
 * @vol:  An ntfs volume obtained from ntfs_mount
 *
 * Tell the user how much could be cleaned up.  List the number of free
 * clusters, MFT records, etc.
 * 
 * Return:  1  Success, displayed some info
 *          0  Error, something went wrong
 */
int ntfs_info (ntfs_volume *vol)
{
	if (!vol)
		return 0;

	Iprintf ("ntfs_info\n");
	return 1;
}


/**
 * version - Print version information about the program
 *
 * Print a copyright statement and a brief description of the program.
 *
 * Return:  none
 */
void version (void)
{
	Iprintf ("%s v%s Copyright (C) 2002 %s\nOverwrite the unused space on "
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
		"    -i       --info        Show volume information (default)\n"
		"\n"
		"    -d       --directory   Wipe directory indexes\n"
		"    -l       --logfile     Wipe the logfile (journal)\n"
		"    -m       --mft         Wipe mft space\n"
		"    -p       --pagefile    Wipe pagefile (swap space)\n"
		"    -t       --tails       Wipe file tails\n"
		"    -u       --unused      Wipe unused clusters\n"
		"\n"
		"    -a       --all         Wipe all unused space\n"
		"\n"
		"    -c num   --count num   Number of times to write (default = 1)\n"
		"    -b list  --bytes list  List of values to write (default = 0)\n"
		"\n"
		"    -n       --no-action   Do not write to disk\n"
		"    -f       --force       Use less caution\n"
		"    -q       --quiet       Less output\n"
		"    -v       --verbose     More output\n"
		"    -V       --version     Version information\n"
		"    -h       --help        Print this help\n\n",
		EXEC_NAME);
	Iprintf ("Please report bugs to: linux-ntfs-dev@lists.sf.net\n\n");
}

/**
 * parse_list - Read a comma-separated list of numbers
 * @list:    The comma-separated list of numbers
 * @result:  Store the parsed list here (must be freed by caller)
 *
 * Read a comma-separated list of numbers and allocate an array of ints to store
 * them in.  The numbers can be in decimal, octal or hex.
 *
 * N.B.  The caller must free the memory returned in @result.
 * N.B.  If the function fails, @result is not changed.
 *
 * Return:  0  Error, invalid string
 *          n  Success, the count of numbers parsed
 */
int parse_list (const char *list, int **result)
{
	const char *ptr;
	char *end;
	int i;
	int count;
	int *mem = NULL;

	if (!list || !result)
		return 0;

	for (count = 0, ptr = list; ptr; ptr = strchr (ptr+1, ','))
		count++;

	mem = malloc ((count+1) * sizeof (int));
	if (!mem) {
		Eprintf ("Couldn't allocate memory in parse_list().\n");
		return 0;
	}

	memset (mem, 0xFF, (count+1) * sizeof (int));

	for (ptr = list, i = 0; i < count; i++) {

		end = NULL;
		mem[i] = strtol (ptr, &end, 0);

		if (!end || (end == ptr) || ((*end != ',') && (*end != 0))) {
			Eprintf ("Invalid list '%s'\n", list);
			free (mem);
			return 0;
		}

		if ((mem[i] < 0) || (mem[i] > 255)) {
			Eprintf ("Bytes must be in range 0-255.\n");
			free (mem);
			return 0;
		}

		ptr = end + 1;
	}

	Dprintf ("Parsing list '%s' - ", list);
	for (i = 0; i <= count; i++)
		Dprintf ("0x%02x ", mem[i]);
	Dprintf ("\n");

	*result = mem;
	return count;
}

/**
 * parse_options - Read and validate the programs command line
 *
 * Read the command line, verify the syntax and parse the options.
 * This function is very long, but quite simple.
 *
 * Return:  1 Success
 *          0 Error, one or more problems
 */
int parse_options (int argc, char *argv[])
{
	static const char *sopt = "-ab:c:dfhilmnpqtuvV";
	static const struct option lopt[] = {
		{ "all",	no_argument,		NULL, 'a' },
		{ "bytes",	required_argument,	NULL, 'b' },
		{ "count",	required_argument,	NULL, 'c' },
		{ "directory",	no_argument,		NULL, 'd' },
		{ "force",	no_argument,		NULL, 'f' },
		{ "help",	no_argument,		NULL, 'h' },
		{ "info",	no_argument,		NULL, 'i' },
		{ "logfile",	no_argument,		NULL, 'l' },
		{ "mft",	no_argument,		NULL, 'm' },
		{ "no-action",	no_argument,		NULL, 'n' },
		{ "pagefile",	no_argument,		NULL, 'p' },
		{ "quiet",	no_argument,		NULL, 'q' },
		{ "tails",	no_argument,		NULL, 't' },
		{ "unused",	no_argument,		NULL, 'u' },
		{ "verbose",	no_argument,		NULL, 'v' },
		{ "version",	no_argument,		NULL, 'V' },
		{ NULL,		0,			NULL, 0   }
	};

	char c = -1;
	char *end;
	int err  = 0;
	int ver  = 0;
	int help = 0;

	opterr = 0; /* We'll handle the errors, thank you. */

	opts.count = 1;

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

		case 'a':
			opts.directory++;
			opts.logfile++;
			opts.mft++;
			opts.pagefile++;
			opts.tails++;
			opts.unused++;
			break;
		case 'b':
			if (!opts.bytes) {
				if (!parse_list (argv[optind-1], &opts.bytes))
					err++;
			} else {
				err++;
			}
			break;
		case 'c':
			if (opts.count == 1) {
				end = NULL;
				opts.count = strtol (optarg, &end, 0);
				if (end && *end)
					err++;
			} else {
				err++;
			}
			break;
		case 'd':
			opts.directory++;
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
		case 'l':
			opts.logfile++;
			break;
		case 'm':
			opts.mft++;
			break;
		case 'n':
			opts.noaction++;
			break;
		case 'p':
			opts.pagefile++;
			break;
		case 'q':
			opts.quiet++;
			break;
		case 't':
			opts.tails++;
			break;
		case 'u':
			opts.unused++;
			break;
		case 'v':
			opts.verbose++;
			break;
		case 'V':
			ver++;
			break;
		default:
			if ((optopt == 'b') || (optopt == 'c')) {
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

		if ((opts.quiet) && (opts.verbose)) {
			Eprintf ("You may not use --quiet and --verbose at the same time.\n");
			err++;
		}

		if (opts.info && (opts.unused || opts.tails || opts.mft || opts.directory)) {
			Eprintf ("You may not use any other options with --info.\n");
			err++;
		}

		if ((opts.count < 1) || (opts.count > 100)) {
			Eprintf ("The iteration count must be between 1 and 100.\n");
			err++;
		}

		/*if (opts.bytes && (opts.count > 0)) {
			Eprintf ("You may not use both --bytes and --count.\n");
			err++;
		}*/

		/* Create a default list */
		if (!opts.bytes) {
			opts.bytes = malloc (2 * sizeof (int));
			if (opts.bytes) {
				opts.bytes[0] =  0;
				opts.bytes[1] = -1;
			}
		}

		if (!opts.directory && !opts.logfile && !opts.mft &&
		    !opts.pagefile && !opts.tails && !opts.unused) {
			opts.info = 1;
		}
	}

	if (ver)
		version();
	if (help || err)
		usage();

	return (!err && !help && !ver);
}

/**
 * valid_device - Perform some safety checks on the device, before we start
 * @name:   Full pathname of the device/file to work with
 * @force:  Continue regardless of problems
 *
 * Check that the name refers to a device and that is isn't already mounted.
 * These checks can be overridden by using the force option.
 *
 * Return:  1  Success, we can continue
 *          0  Error, we cannot use this device
 */
int valid_device (const char *name, int force)
{
	unsigned long mnt_flags = 0;
	struct stat st;

        if (stat (name, &st) == -1) {
		if (errno == ENOENT) {
			Eprintf ("The device %s doesn't exist\n", name);
		} else {
			Eprintf ("Error getting information about %s: %s\n", name, strerror (errno));
		}
		return 0;
	}

        if (!S_ISBLK (st.st_mode)) {
		Vprintf ("%s is not a block device.\n", name);
		if (!force) {
			Eprintf ("Use the force option to work with files.\n");
			return 0;
		}
		Vprintf ("Forced to continue.\n");
	}

	/* Make sure the file system is not mounted. */
	if (ntfs_check_if_mounted (name, &mnt_flags)) {
		Vprintf ("Failed to determine whether %s is mounted: %s\n", name, strerror (errno));
		if (!force) {
			Eprintf ("Use the force option to ignore this error.\n");
			return 0;
		}
		Vprintf ("Forced to continue.\n");
	} else if (mnt_flags & NTFS_MF_MOUNTED) {
		Vprintf ("The device %s, is mounted.\n", name);
		if (!force) {
			Eprintf ("Use the force option to work a mounted filesystem.\n");
			return 0;
		}
		Vprintf ("Forced to continue.\n");
	}

	Dprintf ("Device %s, will be used\n", name);
	return 1;
}


/**
 * print_summary - Tell the use what we are about to do
 *
 * List the operations about to be performed.  The output will be silenced by
 * the --quiet option.
 *
 * Return:  none
 */
void print_summary (void)
{
	int i;

	if (opts.noaction)
		Iprintf ("%s is in 'no-action' mode, it will NOT write to disk."
			 "\n\n", EXEC_NAME);

	Iprintf ("%s is about to wipe:\n", EXEC_NAME);
	if (opts.unused)
		Iprintf ("\tunused disk space\n");
	if (opts.tails)
		Iprintf ("\tfile tails\n");
	if (opts.mft)
		Iprintf ("\tunused mft areas\n");
	if (opts.directory)
		Iprintf ("\tunused directory index space\n");
	if (opts.logfile)
		Iprintf ("\tthe logfile (journal)\n");
	if (opts.pagefile)
		Iprintf ("\tthe pagefile (swap space)\n");

	Iprintf ("\n%s will overwrite these areas with: ", EXEC_NAME);
	if (opts.bytes) {
		for (i = 0; opts.bytes[i] >= 0; i++)
			Iprintf ("0x%02x ", opts.bytes[i]);
	}
	Iprintf ("\n");

	if (opts.count > 1)
		Iprintf ("%s will repeat these operations %d times.\n", EXEC_NAME, opts.count);
	Iprintf ("\n");
}

/**
 * main - Begin here
 *
 * Start from here.
 *
 * Return:  0  Success, the program worked
 *          1  Error, something went wrong
 */
int main (int argc, char *argv[])
{
	const char *locale;
	ntfs_volume *vol;
	int result = 1;
	int flags = 0;
	int i, j;

	locale = setlocale (LC_ALL, "");
	if (!locale) {
		locale = setlocale (LC_ALL, NULL);
		Vprintf ("Failed to set locale, using default '%s'.\n", locale);
	} else {
		Vprintf ("Using locale '%s'.\n", locale);
	}

	if (!parse_options (argc, argv))
		return 1;

	if (!valid_device (opts.device, opts.force)) {
		goto free;
	}

	if (!opts.info)
		print_summary();

	if (opts.info || opts.noaction)
		flags = MS_RDONLY;
	vol = ntfs_mount (opts.device, flags);
	if (!vol) {
		Eprintf ("Couldn't mount device '%s': %s\n", opts.device, strerror (errno));
		goto free;
	}

	if (vol->flags & VOLUME_IS_DIRTY) {
		Iprintf ("Volume is dirty.\n");
		if (!opts.force) {
			Eprintf ("Run chkdsk and try again, or use the --force option.\n");
			goto umount;
		}
		Iprintf ("Forced to continue.\n");
	}

	if (opts.info) {
		ntfs_info (vol);
		result = 0;
		goto umount;
	}

	/* Even if the output it quieted, you still get 5 seconds to abort. */
	if (!opts.force) {
		Iprintf ("\n%s will begin in 5 seconds, press CTRL-C to abort.\n", EXEC_NAME);
		sleep (5);
	}

	if (!opts.bytes) {
		Eprintf ("Internal error, byte list is empty\n");
		goto umount;
	}

	for (i = 0; i < opts.count; i++) {
		int byte;
		for (j = 0; byte = opts.bytes[j], byte >= 0; j++) {
			if (opts.unused && !wipe_unused (vol, byte))
				goto umount;
			if (opts.tails && !wipe_tails (vol, byte))
				goto umount;
			if (opts.mft && !wipe_mft (vol, byte))
				goto umount;
			if (opts.directory && !wipe_directory (vol, byte))
				goto umount;
			if (opts.logfile && !wipe_logfile (vol, byte))
				goto umount;
			if (opts.pagefile && !wipe_pagefile (vol, byte))
				goto umount;
		}
	}

	result = 0;
umount:
	ntfs_umount (vol, FALSE);
free:
	if (opts.bytes)
		free (opts.bytes);
	return result;
}


