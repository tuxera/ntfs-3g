/**
 * ntfsundelete - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002 Richard Russon <ntfs@flatcap.org>
 *
 * This utility will recover deleted files from an NTFS volume.
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

#include <features.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <time.h>
#include <limits.h>
#include <regex.h>
#include <libintl.h>
#include <time.h>
#include <stdarg.h>
#include <utime.h>

#include "ntfsundelete.h"
#include "bootsect.h"
#include "mft.h"
#include "attrib.h"
#include "layout.h"
#include "inode.h"
#include "disk_io.h"

static const char *AUTHOR    = "Richard Russon (FlatCap)";
static const char *EXEC_NAME = "ntfsundelete";
static const char *MFTFILE   = "mft";
static const char *UNNAMED   = "<unnamed>";
static       char *NONE      = "<none>";
static       char *UNKNOWN   = "unknown";
static struct options opts;

#define _(S)	gettext(S)

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
void Dprintf (const char *format, ...)
{
#ifdef DEBUG
	va_list va;
	va_start (va, format);
	vfprintf (stdout, format, va);
	va_end (va);
#endif
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
	Iprintf ("%s v%s Copyright (C) 2002 %s\nRecover deleted files from an "
		"NTFS Volume\n\n%s is free software, released under the GNU "
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
		"    -s          --scan             Scan for files (default)\n"
		"    -p num      --percentage num   Minimum percentage recoverable\n"
		"    -m pattern  --match pattern    Only work on files with matching names\n"
		"    -C          --case             Case sensitive matching\n"
		"    -S range    --size range       Match files of this size\n"
		"    -t since    --time since       Last referenced since this time\n"
		"\n"
		"    -u num      --undelete num     Undelete inode\n"
		"    -o file     --output file      Save with this filename\n"
		"    -d dir      --destination dir  Destination directory\n"
		"    -b num      --byte num         Fill missing parts with this byte\n"
		"\n"
		"    -c range    --copy range       Write a range of MFT records to a file\n"
		"\n"
		"    -f          --force            Use less caution\n"
		"    -q          --quiet            Less output\n"
		"    -v          --verbose          More output\n"
		"    -V          --version          Version information\n"
		"    -h          --help             Print this help\n\n",
		EXEC_NAME);
	Iprintf ("Please report bugs to: linux-ntfs-dev@lists.sf.net\n\n");
}

/**
 * transform - Convert a shell style pattern to a regex
 * @pattern:  String to be converted
 * @regex:    Resulting regular expression is put here
 *
 * This will transform patterns, such as "*.doc" to true regular expressions.
 * The function will also place '^' and '$' around the expression to make it
 * behave as the user would expect
 *
 * Before  After
 *   .       \.
 *   *       .*
 *   ?       .
 *
 * Notes:
 *     The returned string must be freed by the caller.
 *     If transform fails, @regex will not be changed.
 *
 * Return:  1, Success, the string was transformed
 *	    0, An error occurred
 */
int transform (const char *pattern, char **regex)
{
	char *result;
	int length, i, j;

	if (!pattern || !regex)
		return 0;

	length = strlen (pattern);
	if (length < 1) {
		Eprintf ("Pattern to transform is empty\n");
		return 0;
	}

	for (i = 0; pattern[i]; i++) {
		if ((pattern[i] == '*') || (pattern[i] == '.'))
			length++;
	}

	result = malloc (length + 3);
	if (!result) {
		Eprintf ("Couldn't allocate memory in transform()\n");
		return 0;
	}

	result[0] = '^';

	for (i = 0, j = 1; pattern[i]; i++, j++) {
		if (pattern[i] == '*') {
			result[j] = '.';
			j++;
			result[j] = '*';
		} else if (pattern[i] == '.') {
			result[j] = '\\';
			j++;
			result[j] = '.';
		} else if (pattern[i] == '?') {
			result[j] = '.';
		} else {
			result[j] = pattern[i];
		}
	}

	result[j]   = '$';
	result[j+1] = 0;
	Dprintf ("Pattern '%s' replaced with regex '%s'\n", pattern, result);

	*regex = result;
	return 1;
}

/**
 * parse_time - Convert a time abbreviation to seconds
 * @string:  The string to be converted
 * @since:   The absolute time referred to
 *
 * Strings representing times will be converted into a time_t.  The numbers will
 * be regarded as seconds unless suffixed.
 *
 * Suffix  Description
 *  [yY]      Year
 *  [mM]      Month
 *  [wW]      Week
 *  [dD]      Day
 *  [sS]      Second
 *
 * Therefore, passing "1W" will return the time_t representing 1 week ago.
 *
 * Notes:
 *     Only the first character of the suffix is read.
 *     If parse_time fails, @since will not be changed
 *
 * Return:  1  Success
 *	    0  Error, the string was malformed
 */
int parse_time (const char *value, time_t *since)
{
	time_t result, now;
	char *suffix = NULL;

	if (!value || !since)
		return -1;

	Dprintf ("parsing time '%s' ago\n", value);

	result = strtoll (value, &suffix, 10);
	if (result < 0 || errno == ERANGE) {
		Eprintf ("Invalid time '%s'.\n", value);
		return 0;
	}

	if (!suffix) {
		Eprintf ("Internal error, strtoll didn't return a suffix.\n");
		return 0;
	}

	if (strlen (suffix) > 1) {
		Eprintf ("Invalid time suffix '%s'.  Use Y, M, W, D or H.\n", suffix);
		return 0;
	}

	switch (suffix[0]) {
		case 'y': case 'Y': result *=   12;
		case 'm': case 'M': result *=    4;
		case 'w': case 'W': result *=    7;
		case 'd': case 'D': result *=   24;
		case 'h': case 'H': result *= 3600;
		case 0:
		    break;

		default:
			Eprintf ("Invalid time suffix '%s'.  Use Y, M, W, D or H.\n", suffix);
			return 0;
	}

	now = time (NULL);

	Dprintf ("Time now = %lld, Time then = %lld.\n", (long long) now, (long long) result);
	*since = now - result;
	return 1;
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
int parse_size (const char *value, long long *size)
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
int parse_range (const char *string, long long *start, long long *finish)
{
	long long a, b;
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
			b = LONG_MAX;
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
int parse_options (int argc, char *argv[])
{
	static const char *sopt = "-b:Cc:d:fhm:o:p:sS:t:u:qvV";
	static const struct option lopt[] = {
		{ "byte",	 required_argument,	NULL, 'b' },
		{ "case",	 no_argument,		NULL, 'C' },
		{ "copy",	 required_argument,	NULL, 'c' },
		{ "destination", required_argument,	NULL, 'd' },
		{ "force",	 no_argument,		NULL, 'f' },
		{ "help",	 no_argument,		NULL, 'h' },
		{ "match",	 required_argument,	NULL, 'm' },
		{ "output",	 required_argument,	NULL, 'o' },
		{ "percentage",  required_argument,	NULL, 'p' },
		{ "scan",	 no_argument,		NULL, 's' },
		{ "size",	 required_argument,	NULL, 'S' },
		{ "time",	 required_argument,	NULL, 't' },
		{ "undelete",	 required_argument,	NULL, 'u' },
		{ "quiet",	 no_argument,		NULL, 'q' },
		{ "verbose",	 no_argument,		NULL, 'v' },
		{ "version",	 no_argument,		NULL, 'V' },
		{ NULL, 0, NULL, 0 }
	};

	char c = -1;
	char *end = NULL;
	int err  = 0;
	int ver  = 0;
	int help = 0;

	opterr = 0; /* We'll handle the errors, thank you. */

	opts.mode     = MODE_NONE;
	opts.uinode   = -1;
	opts.percent  = -1;
	opts.fillbyte = -1;

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
		case 'b':
			if (opts.fillbyte == -1) {
				end = NULL;
				opts.fillbyte = strtol (optarg, &end, 0);
				if (end && *end)
					err++;
			} else {
				err++;
			}
			break;
		case 'C':
			opts.match_case++;
			break;
		case 'c':
			if (opts.mode == MODE_NONE) {
				if (!parse_range (argv[optind-1], &opts.mft_begin, &opts.mft_end))
					err++;
				opts.mode = MODE_COPY;
			} else {
				opts.mode = MODE_ERROR;
			}
			break;
		case 'd':
			if (!opts.dest)
				opts.dest = argv[optind-1];
			else
				err++;
			break;
		case 'f':
			opts.force++;
			break;
		case 'h':
			help++;
			break;
		case 'm':
			if (!opts.match) {
				if (!transform (argv[optind-1], &opts.match))
					err++;
			} else {
				err++;
			}
			break;
		case 'o':
			if (!opts.output) {
				opts.output = argv[optind-1];
			} else {
				err++;
			}
			break;
		case 'p':
			if (opts.percent == -1) {
				end = NULL;
				opts.percent = strtol (optarg, &end, 0);
				if (end && ((*end != '%') && (*end != 0)))
					err++;
			} else {
				err++;
			}
			break;
		case 'q':
			opts.quiet++;
			break;
		case 's':
			if (opts.mode == MODE_NONE)
				opts.mode = MODE_SCAN;
			else
				opts.mode = MODE_ERROR;
			break;
		case 'S':
			if ((opts.size_begin > 0) || (opts.size_end > 0) ||
			    !parse_range (argv[optind-1], &opts.size_begin,
			     &opts.size_end)) {
			    err++;
			}
			break;
		case 't':
			if (opts.since == 0) {
				if (!parse_time (argv[optind-1], &opts.since))
					err++;
			} else {
			    err++;
			}
			break;
		case 'u':
			if (opts.mode == MODE_NONE) {
				end = NULL;
				opts.mode = MODE_UNDELETE;
				opts.uinode = strtol (optarg, &end, 0);
				if (end && *end)
					err++;
			} else {
				opts.mode = MODE_ERROR;
			}
			break;
		case 'v':
			opts.verbose++;
			break;
		case 'V':
			ver++;
			break;
		default:
			if (((optopt == 'b') || (optopt == 'c') ||
			     (optopt == 'd') || (optopt == 'm') ||
			     (optopt == 'o') || (optopt == 'p') ||
			     (optopt == 'S') || (optopt == 't') ||
			     (optopt == 'u')) && (!optarg)) {
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

		if (opts.mode == MODE_NONE) {
			opts.mode = MODE_SCAN;
		}

		switch (opts.mode) {
		case MODE_SCAN:
			if (opts.output || opts.dest || (opts.fillbyte != -1)) {
				Eprintf ("Scan can only be used with --percent, "
					"--match, --ignore-case, --size and --time.\n");
				err++;
			}
			if (opts.match_case && !opts.match) {
				Eprintf ("The --case option doesn't make sense without the --match option\n");
				err++;
			}
			break;
		case MODE_UNDELETE:
			if ((opts.percent != -1) || opts.match || opts.match_case ||
			    (opts.size_begin > 0) || (opts.size_end > 0)) {
				Eprintf ("Undelete can only be used with "
					"--output, --destination and --byte.\n");
				err++;
			}
			break;
		case MODE_COPY:
			if ((opts.fillbyte != -1) || (opts.percent != -1) ||
			    opts.match || opts.match_case ||
			    (opts.size_begin > 0) || (opts.size_end > 0)) {
				Eprintf ("Copy can only be used with --output and --destination.\n");
				err++;
			}
			break;
		default:
			Eprintf ("You can only select one of Scan, Undelete or Copy.\n");
			err++;
		}

		if ((opts.percent < -1) || (opts.percent > 100)) {
			Eprintf ("Percentage value must be in the range 0 - 100.\n");
			err++;
		}

		if (opts.quiet) {
			if (opts.verbose) {
				Eprintf ("You may not use --quiet and --verbose at the same time.\n");
				err++;
			} else if (opts.mode == MODE_SCAN) {
				Eprintf ("You may not use --quiet when scanning a volume.\n");
				err++;
			}
		}
	}

	if (ver)
		version();
	if (help || err)
		usage();

	return (!err && !help && !ver);
}


/**
 * free_file - Release the resources used by a file object
 * @file:  The unwanted file object
 *
 * This will free up the memory used by a file object and iterate through the
 * object's children, freeing their resources too.
 *
 * Return:  none
 */
void free_file (struct ufile *file)
{
	struct list_head *item, *tmp;

	if (!file)
		return;

	list_for_each_safe (item, tmp, &file->name) { /* List of filenames */
		struct filename *f = list_entry (item, struct filename, list);
		Dprintf ("freeing filename '%s'\n", f->name ? f->name : NONE);
		if (f->name)
			free (f->name);
		free (f);
	}

	list_for_each_safe (item, tmp, &file->data) { /* List of data streams */
		struct data *d = list_entry (item, struct data, list);
		Dprintf ("freeing data stream '%s'\n", d->name ? d->name : UNNAMED);
		if (d->name)
			free (d->name);
		if (d->runlist)
			free (d->runlist);
		free (d);
	}

	free (file->mft);
	free (file);
}

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

/**
 * find_attribute - Find an attribute of the given type
 * @type:  An attribute type, e.g. AT_FILE_NAME
 * @ctx:   A search context, created using ntfs_get_attr_search_ctx
 *
 * Using the search context to keep track, find the first/next occurrence of a
 * given attribute type.
 *
 * N.B.  This will return a pointer into @mft.  As long as the search context
 *       has been created without an inode, it won't overflow the buffer.
 *
 * Return:  Pointer  Success, an attribute was found
 *	    NULL     Error, no matching attributes were found
 */
ATTR_RECORD * find_attribute (const ATTR_TYPES type, ntfs_attr_search_ctx *ctx)
{
	if (!ctx)
		return NULL;

	if (ntfs_attr_lookup(type, NULL, 0, 0, 0, NULL, 0, ctx) != 0) {
		Dprintf ("find_attribute didn't find an attribute of type: 0x%02x.\n", type);
		return NULL;	/* None / no more of that type */
	}

	Dprintf ("find_attribute found an attribute of type: 0x%02x.\n", type);
	return ctx->attr;
}

/**
 * find_first_attribute - Find the first attribute of a given type
 * @type:  An attribute type, e.g. AT_FILE_NAME
 * @mft:   A buffer containing a raw MFT record
 *
 * Search through a raw MFT record for an attribute of a given type.
 * The return value is a pointer into the MFT record that was supplied.
 *
 * N.B.  This will return a pointer into @mft.  The pointer won't stray outside
 *       the buffer, since we created the search context without an inode.
 *
 * Return:  Pointer  Success, an attribute was found
 *	    NULL     Error, no matching attributes were found
 */
ATTR_RECORD * find_first_attribute (const ATTR_TYPES type, MFT_RECORD *mft)
{
	ntfs_attr_search_ctx *ctx;
	ATTR_RECORD *rec;

	if (!mft)
		return NULL;

	ctx = ntfs_attr_get_search_ctx(NULL, mft);
	if (!ctx) {
		Eprintf ("Couldn't create a search context.\n");
		return NULL;
	}

	rec = find_attribute (type, ctx);
	ntfs_attr_put_search_ctx(ctx);
	if (rec)
		Dprintf ("find_first_attribute: found attr of type 0x%02x.\n", type);
	else
		Dprintf ("find_first_attribute: didn't find attr of type 0x%02x.\n", type);
	return rec;
}

/**
 * get_filenames - Read an MFT Record's $FILENAME attributes
 * @file:  The file object to work with
 *
 * A single file may have more than one filename.  This is quite common.
 * Windows creates a short DOS name for each long name, e.g. LONGFI~1.XYZ,
 * LongFiLeName.xyZ.
 *
 * The filenames that are found are put in filename objects and added to a
 * linked list of filenames in the file object.  For convenience, the unicode
 * filename is converted into the current locale and stored in the filename
 * object.
 *
 * One of the filenames is picked (the one with the lowest numbered namespace)
 * and its locale friendly name is put in pref_name.
 *
 * Return:  n  The number of $FILENAME attributes found
 *	   -1  Error
 */
int get_filenames (struct ufile *file)
{
	ATTR_RECORD *rec;
	FILE_NAME_ATTR *attr;
	ntfs_attr_search_ctx *ctx;
	struct filename *name;
	int count = 0;
	int space = 4;

	if (!file)
		return -1;

	ctx = ntfs_attr_get_search_ctx (NULL, file->mft);
	if (!ctx)
		return -1;

	while ((rec = find_attribute (AT_FILE_NAME, ctx))) {
		/* We know this will always be resident. */
		attr = (FILE_NAME_ATTR *) ((char *) rec + le16_to_cpu (rec->value_offset));

		name = calloc (1, sizeof (*name));
		if (!name) {
			Eprintf ("Couldn't allocate memory in get_filenames().\n");
			count = -1;
			break;
		}

		name->uname      = attr->file_name;
		name->uname_len  = attr->file_name_length;
		name->name_space = attr->file_name_type;
		name->size_alloc = sle64_to_cpu (attr->allocated_size);
		name->size_data  = sle64_to_cpu (attr->data_size);
		name->flags      = attr->file_attributes;

		name->date_c     = ntfs2utc (sle64_to_cpu (attr->creation_time));
		name->date_a     = ntfs2utc (sle64_to_cpu (attr->last_data_change_time));
		name->date_m     = ntfs2utc (sle64_to_cpu (attr->last_mft_change_time));
		name->date_r     = ntfs2utc (sle64_to_cpu (attr->last_access_time));

		if (ntfs_ucstombs (name->uname, name->uname_len, &name->name,
		    name->uname_len) < 0) {
			Dprintf ("Couldn't translate filename to current locale.\n");
		}

		if (name->name_space < space) {
			file->pref_name = name->name;
			space = name->name_space;
		}

		file->max_size = max (file->max_size, name->size_alloc);
		file->max_size = max (file->max_size, name->size_data);

		list_add_tail (&name->list, &file->name);
		count++;
	}

	ntfs_attr_put_search_ctx(ctx);
	Dprintf ("File has %d names.\n", count);
	return count;
}

/**
 * get_data - Read an MFT Record's $DATA attributes
 * @file:  The file object to work with
 * @vol:  An ntfs volume obtained from ntfs_mount
 *
 * A file may have more than one data stream.  All files will have an unnamed
 * data stream which contains the file's data.  Some Windows applications store
 * extra information in a separate stream.
 *
 * The streams that are found are put in data objects and added to a linked
 * list of data streams in the file object.
 *
 * Return:  n  The number of $FILENAME attributes found
 *	   -1  Error
 */
int get_data (struct ufile *file, ntfs_volume *vol)
{
	ATTR_RECORD *rec;
	ntfs_attr_search_ctx *ctx;
	int count = 0;
	struct data *data;

	if (!file)
		return -1;

	ctx = ntfs_attr_get_search_ctx (NULL, file->mft);
	if (!ctx)
		return -1;

	while ((rec = find_attribute (AT_DATA, ctx))) {
		data = calloc (1, sizeof (*data));
		if (!data) {
			Eprintf ("Couldn't allocate memory in get_data().\n");
			count = -1;
			break;
		}

		data->resident   = !rec->non_resident;
		data->compressed = rec->flags & ATTR_IS_COMPRESSED;
		data->encrypted  = rec->flags & ATTR_IS_ENCRYPTED;

		if (rec->name_length) {
			data->uname     = (uchar_t *) ((char *) rec + le16_to_cpu (rec->name_offset));
			data->uname_len = rec->name_length;

			if (ntfs_ucstombs (data->uname, data->uname_len, &data->name,
			    data->uname_len) < 0) {
				Eprintf ("Cannot translate name into current locale.\n");
			}
		}

		if (data->resident) {
			data->size_data  = le32_to_cpu (rec->value_length);
			data->data	 = ((char*) (rec)) + le16_to_cpu (rec->value_offset);
		} else {
			data->size_alloc = sle64_to_cpu (rec->allocated_size);
			data->size_data  = sle64_to_cpu (rec->data_size);
			data->size_init  = sle64_to_cpu (rec->initialized_size);
			data->size_vcn   = sle64_to_cpu (rec->highest_vcn) + 1;
		}

		data->runlist = ntfs_mapping_pairs_decompress(vol, rec, NULL);
		if (!data->runlist) {
			Dprintf ("Couldn't decompress the data runs\n");
		}

		file->max_size = max (file->max_size, data->size_data);
		file->max_size = max (file->max_size, data->size_init);

		list_add_tail (&data->list, &file->data);
		count++;
	}

	ntfs_attr_put_search_ctx(ctx);
	Dprintf ("File has %d data streams.\n", count);
	return count;
}

/**
 * read_record - Read an MFT record into memory
 * @vol:     An ntfs volume obtained from ntfs_mount
 * @record:  The record number to read
 *
 * Read the specified MFT record and gather as much information about it as
 * possible.
 *
 * Return:  Pointer  A ufile object containing the results
 *	    NULL     Error
 */
struct ufile * read_record (ntfs_volume *vol, long long record)
{
	ATTR_RECORD *attr10, *attr20, *attr90;
	struct ufile *file;
	ntfs_attr *mft;

	if (!vol)
		return NULL;

	file = calloc (1, sizeof (*file));
	if (!file) {
		Eprintf ("Couldn't allocate memory in read_record()\n");
		return NULL;
	}

	INIT_LIST_HEAD (&file->name);
	INIT_LIST_HEAD (&file->data);
	file->inode = record;

	file->mft = malloc (vol->mft_record_size);
	if (!file->mft) {
		Eprintf ("Couldn't allocate memory in read_record()\n");
		free_file (file);
		return NULL;
	}

	mft = ntfs_attr_open (vol->mft_ni, AT_DATA, NULL, 0);
	if (!mft) {
		Eprintf ("Couldn't open $MFT/$DATA: %s\n", strerror (errno));
		free_file (file);
		return NULL;
	}

	if (ntfs_attr_mst_pread (mft, vol->mft_record_size * record, 1, vol->mft_record_size, file->mft) < 1) {
		Eprintf ("Couldn't read MFT Record %lld.\n", record);
		ntfs_attr_close (mft);
		free_file (file);
		return NULL;
	}

	ntfs_attr_close (mft);
	mft = NULL;

	attr10 = find_first_attribute (AT_STANDARD_INFORMATION,	file->mft);
	attr20 = find_first_attribute (AT_ATTRIBUTE_LIST,	file->mft);
	attr90 = find_first_attribute (AT_INDEX_ROOT,		file->mft);

	Dprintf ("Attributes present: %s %s %s\n", attr10?"0x10":"", attr20?"0x20":"", attr90?"0x90":"");

	if (attr10)
	{
		STANDARD_INFORMATION *si;
		si = (STANDARD_INFORMATION *) ((char *) attr10 + le16_to_cpu (attr10->value_offset));
		file->date = ntfs2utc (sle64_to_cpu (si->last_data_change_time));
	}

	if (attr20 || !attr10)
		file->attr_list = 1;
	if (attr90)
		file->directory = 1;

	if (get_filenames (file) < 0) {
		Eprintf ("Couldn't get filenames.\n");
	}
	if (get_data (file, vol) < 0) {
		Eprintf ("Couldn't get data streams.\n");
	}

	return file;
}


/**
 * cluster_in_use - Determine if a cluster is in use
 * @vol:  An ntfs volume obtained from ntfs_mount
 * @lcn:  The Logical Cluster Number to test
 *
 * The metadata file $Bitmap has one binary bit representing each cluster on
 * disk.  The bit will be set of each cluster that is in use.  The function
 * reads the relevant part of $Bitmap into a buffer and tests the bit.
 *
 * This function has a static buffer in which it caches a section of $Bitmap.
 * If the lcn, being tested, lies outside the range, the buffer will be
 * refreshed.
 *
 * Return:  1  Cluster is in use
 *	    0  Cluster is free space
 *	   -1  Error occurred
 */
int cluster_in_use (ntfs_volume *vol, long long lcn)
{
	static unsigned char buffer[512];
	static long long bmplcn = -sizeof (buffer) - 1;	/* Which bit of $Bitmap is in the buffer */

	int byte, bit;
	ntfs_attr *attr;

	if (!vol)
		return -1;

	/* Does lcn lie in the section of $Bitmap we already have cached? */
	if ((lcn < bmplcn) || (lcn >= (bmplcn + (sizeof (buffer) << 3)))) {
		Dprintf ("Bit lies outside cache.\n");
		attr = ntfs_attr_open (vol->lcnbmp_ni, AT_DATA, NULL, 0);
		if (!attr) {
			Eprintf ("Couldn't open $MFT/$BITMAP: %s\n", strerror (errno));
			return -1;
		}

		/* Mark the buffer as in use, in case the read is shorter. */
		memset (buffer, 0xFF, sizeof (buffer));
		bmplcn = lcn & (~((sizeof (buffer) << 3) - 1));

		if (ntfs_attr_pread (attr, (bmplcn>>3), sizeof (buffer), buffer) < 0) {
			Eprintf ("Couldn't read $MFT/$BITMAP: %s\n", strerror (errno));
			ntfs_attr_close (attr);
			return -1;
		}

		Dprintf ("Reloaded bitmap buffer.\n");
		ntfs_attr_close (attr);
	}

	bit  = 1 << (lcn & 7);
	byte = (lcn >> 3) & (sizeof (buffer) - 1);
	Dprintf ("cluster = %lld, bmplcn = %lld, byte = %d, bit = %d, in use %d\n",
		lcn, bmplcn, byte, bit, buffer[byte] & bit);

	return (buffer[byte] & bit);
}

/**
 * calc_percentage - Calculate how much of the file is recoverable
 * @file:  The file object to work with
 * @vol:   An ntfs volume obtained from ntfs_mount
 *
 * Read through all the $DATA streams and determine if each cluster in each
 * stream is still free disk space.  This is just measuring the potential for
 * recovery.  The data may have still been overwritten by a another file which
 * was then deleted.
 *
 * Files with a resident $DATA stream will have a 100% potential.
 *
 * N.B.  If $DATA attribute spans more than one MFT record (i.e. badly
 *       fragmented) then only the data in this segment will be used for the
 *       calculation.
 *
 * N.B.  Currently, compressed and encrypted files cannot be recovered, so they
 *       will return 0%.
 *
 * Return:  n  The percentage of the file that _could_ be recovered
 *	   -1  Error
 */
int calc_percentage (struct ufile *file, ntfs_volume *vol)
{
	runlist_element *rl = NULL;
	struct list_head *pos;
	struct data *data;
	long long i, j;
	long long start, end;
	int inuse, free;
	int percent = 0;

	if (!file || !vol)
		return -1;

	if (file->directory) {
		Dprintf ("Found a directory: not recoverable.\n");
		return 0;
	}

	if (list_empty (&file->data)) {
		Vprintf ("File has no data streams.\n");
		return 0;
	}

	list_for_each (pos, &file->data) {
		data  = list_entry (pos, struct data, list);
		inuse = 0;
		free  = 0;

		if (data->encrypted) {
			Vprintf ("File is encrypted, recovery is impossible.\n");
			continue;
		}

		if (data->compressed) {
			Vprintf ("File is compressed, recovery not yet implemented.\n");
			continue;
		}

		if (data->resident) {
			Vprintf ("File is resident, therefore recoverable.\n");
			percent = 100;
			data->percent = 100;
			continue;
		}

		rl = data->runlist;
		if (!rl) {
			Vprintf ("File has no runlist, hence no data.\n");
			continue;
		}

		if (rl[0].length <= 0) {
			Vprintf ("File has an empty runlist, hence no data.\n");
			continue;
		}

		if (rl[0].lcn == LCN_RL_NOT_MAPPED) {	/* extended mft record */
			Vprintf ("Missing segment at beginning, %lld clusters\n", rl[0].length);
			inuse += rl[0].length;
			rl++;
		}

		for (i = 0; rl[i].length > 0; i++) {
			if (rl[i].lcn == LCN_RL_NOT_MAPPED) {
				Vprintf ("Missing segment at end, %lld clusters\n", rl[i].length);
				inuse += rl[i].length;
				continue;
			}

			if (rl[i].lcn == LCN_HOLE) {
				free += rl[i].length;
				continue;
			}

			start = rl[i].lcn;
			end   = rl[i].lcn + rl[i].length;

			for (j = start; j < end; j++) {
				if (cluster_in_use (vol, j))
					inuse++;
				else
					free++;
			}
		}

		if ((inuse + free) == 0) {
			Eprintf ("Unexpected error whilst calculating percentage for inode %lld\n", file->inode);
			continue;
		}

		data->percent = (free * 100) / (inuse + free);

		percent = max (percent, data->percent);
	}

	Vprintf ("File is %d%% recoverable\n", percent);
	return percent;
}

/**
 * dump_record - Print everything we know about an MFT record
 * @file:  The file to work with
 *
 * Output the contents of the file object.  This will print everything that has
 * been read from the MFT record, or implied by various means.
 *
 * Because of the redundant nature of NTFS, there will be some duplication of
 * information, though it will have been read from different sources.
 *
 * N.B.  If the filename is missing, or couldn't be converted to the current
 *       locale, "<none>" will be displayed.
 *
 * Return:  none
 */
void dump_record (struct ufile *file)
{
	char buffer[20];
	char *name;
	struct list_head *item;
	int i;

	if (!file)
		return;

	Iprintf ("MFT Record %lld\n", file->inode);
	Iprintf ("Type: %s\n", (file->directory) ? "Directory" : "File");
	strftime (buffer, sizeof (buffer), "%F %R", localtime (&file->date));
	Iprintf ("Date: %s\n", buffer);

	if (file->attr_list)
		Iprintf ("Metadata may span more than one MFT record\n");

	list_for_each (item, &file->name) {
		struct filename *f = list_entry (item, struct filename, list);

		if (f->name)
			name = f->name;
		else
			name = NONE;

		Iprintf ("Filename: (%d) %s\n", f->name_space, f->name);
		Iprintf ("File Flags: ");
		if (f->flags & FILE_ATTR_SYSTEM)	Iprintf ("System ");
		if (f->flags & FILE_ATTR_DIRECTORY)	Iprintf ("Directory ");
		if (f->flags & FILE_ATTR_SPARSE_FILE)	Iprintf ("Sparse ");
		if (f->flags & FILE_ATTR_REPARSE_POINT)	Iprintf ("Reparse ");
		if (f->flags & FILE_ATTR_COMPRESSED)	Iprintf ("Compressed ");
		if (f->flags & FILE_ATTR_ENCRYPTED)	Iprintf ("Encrypted ");
		if (!(f->flags & (FILE_ATTR_SYSTEM || FILE_ATTR_DIRECTORY ||
		    FILE_ATTR_SPARSE_FILE || FILE_ATTR_REPARSE_POINT ||
		    FILE_ATTR_COMPRESSED || FILE_ATTR_ENCRYPTED))) {
			Iprintf (NONE);
		}
		Iprintf ("\n");
		Iprintf ("Size alloc: %lld\n", f->size_alloc);
		Iprintf ("Size data: %lld\n", f->size_data);

		strftime (buffer, sizeof (buffer), "%F %R", localtime (&f->date_c));
		Iprintf ("Date C: %s\n", buffer);
		strftime (buffer, sizeof (buffer), "%F %R", localtime (&f->date_a));
		Iprintf ("Date A: %s\n", buffer);
		strftime (buffer, sizeof (buffer), "%F %R", localtime (&f->date_m));
		Iprintf ("Date M: %s\n", buffer);
		strftime (buffer, sizeof (buffer), "%F %R", localtime (&f->date_r));
		Iprintf ("Date R: %s\n", buffer);
	}

	Iprintf ("Data Streams:\n");
	list_for_each (item, &file->data) {
		struct data *d = list_entry (item, struct data, list);
		Iprintf ("Name: %s\n", (d->name) ? d->name : "<unnamed>");
		Iprintf ("Flags: ");
		if (d->resident)   Iprintf ("Resident\n");
		if (d->compressed) Iprintf ("Compressed\n");
		if (d->encrypted)  Iprintf ("Encrypted\n");
		if (!d->resident && !d->compressed && !d->encrypted)
			Iprintf ("None\n");
		else
			Iprintf ("\n");

		Iprintf ("Size alloc: %lld\n", d->size_alloc);
		Iprintf ("Size data: %lld\n", d->size_data);
		Iprintf ("Size init: %lld\n", d->size_init);
		Iprintf ("Size vcn: %lld\n", d->size_vcn);

		Iprintf ("Data runs:\n");
		if ((!d->runlist) || (d->runlist[0].length <= 0)) {
			Iprintf ("    None\n");
		} else {
			for (i = 0; d->runlist[i].length > 0; i++) {
				Iprintf ("    %lld @ %lld\n", d->runlist[i].length, d->runlist[i].lcn);
			}
		}

		Iprintf ("Amount potentially recoverable %d%%\n", d->percent);
	}

	Iprintf ("________________________________________\n\n");
}

/**
 * list_record - Print a one line summary of the file
 * @file:  The file to work with
 *
 * Print a one line description of a file.
 *
 *   Inode    Flags  %age  Date            Size  Filename
 *
 * The output will contain the file's inode number (MFT Record), some flags,
 * the percentage of the file that is recoverable, the last modification date,
 * the size and the filename.
 *
 * The flags are F/D = File/Directory, N/R = Data is (Non-)Resident,
 * C = Compressed, E = Encrypted, ! = Metadata may span multiple records.
 *
 * N.B.  The file size is stored in many forms in several attributes.   This
 *       display the largest it finds.
 *
 * N.B.  If the filename is missing, or couldn't be converted to the current
 *       locale, "<none>" will be displayed.
 *
 * Return:  none
 */
void list_record (struct ufile *file)
{
	char buffer[20];
	struct list_head *item;
	char *name = NULL;
	long long size = 0;
	int percent = 0;

	char flagd = '.', flagr = '.', flagc = '.', flagx = '.';

	strftime (buffer, sizeof (buffer), "%F", localtime (&file->date));

	if (file->attr_list)
		flagx = '!';

	if (file->directory)
		flagd = 'D';
	else
		flagd = 'F';

	list_for_each (item, &file->data) {
		struct data *d = list_entry (item, struct data, list);

		if (!d->name) {
			if (d->resident)   flagr = 'R';
			else		   flagr = 'N';
			if (d->compressed) flagc = 'C';	/* These two are mutually exclusive */
			if (d->encrypted)  flagc = 'E';

			percent = max (percent, d->percent);
		}

		size = max (size, d->size_data);
		size = max (size, d->size_init);
	}

	if (file->pref_name)
		name = file->pref_name;
	else
		name = NONE;

	Iprintf ("%-8lld %c%c%c%c   %3d%%  %s %9lld  %s\n",
		file->inode, flagd, flagr, flagc, flagx,
		percent, buffer, size, name);
}

/**
 * name_match - Does a file have a name matching a regex
 * @re:    The regular expression object
 * @file:  The file to be tested
 *
 * Iterate through the file's $FILENAME attributes and compare them against the
 * regular expression, created with regcomp.
 *
 * Return:  1  There is a matching filename.
 *	    0  There is no match.
 */
int name_match (regex_t *re, struct ufile *file)
{
	struct list_head *item;
	int result;

	if (!re || !file)
		return 0;

	list_for_each (item, &file->name) {
		struct filename *f = list_entry (item, struct filename, list);

		if (!f->name)
			continue;
		result = regexec (re, f->name, 0, NULL, 0);
		if (result < 0) {
			Eprintf ("Couldn't compare filename with regex: %s\n", strerror (errno));
			return 0;
		} else if (result == REG_NOERROR) {
			Dprintf ("Found a matching filename.\n");
			return 1;
		}
	}

	Dprintf ("Filename '%s' doesn't match regex.\n", file->pref_name);
	return 0;
}

/**
 * write_data - Write out a block of data
 * @fd:       File descriptor to write to
 * @buffer:   Data to write
 * @bufsize:  Amount of data to write
 *
 * Write a block of data to a file descriptor.
 *
 * Return:  -1  Error, something went wrong
 *	     0  Success, all the data was written
 */
unsigned int write_data (int fd, const char *buffer, unsigned int bufsize)
{
	ssize_t result1, result2;

	if (!buffer) {
		errno = EINVAL;
		return -1;
	}

	result1 = write (fd, buffer, bufsize);
	if ((result1 == (ssize_t) bufsize) || (result1 < 0))
		return result1;

	/* Try again with the rest of the buffer */
	buffer  += result1;
	bufsize -= result1;

	result2 = write (fd, buffer, bufsize);
	if (result2 < 0)
		return result1;

	return result1 + result2;
}

/**
 * create_pathname - Create a path/file from some components
 * @dir:      Directory in which to create the file (optional)
 * @name:     Filename to give the file (optional)
 * @stream:   Name of the stream (optional)
 * @buffer:   Store the result here
 * @bufsize:  Size of buffer
 *
 * Create a filename from various pieces.  The output will be of the form:
 *	dir/file
 *	dir/file:stream
 *	file
 *	file:stream
 *
 * All the components are optional.  If the name is missing, "unknown" will be
 * used.  If the directory is missing the file will be created in the current
 * directory.  If the stream name is present it will be appended to the
 * filename, delimited by a colon.
 *
 * N.B. If the buffer isn't large enough the name will be truncated.
 *
 * Return:  n  Length of the allocated name
 */
int create_pathname (const char *dir, const char *name, const char *stream,
		     char *buffer, int bufsize)
{
	if (!name)
		name = UNKNOWN;

	if (dir)
		if (stream)
			snprintf (buffer, bufsize, "%s/%s:%s", dir, name, stream);
		else
			snprintf (buffer, bufsize, "%s/%s", dir, name);
	else
		if (stream)
			snprintf (buffer, bufsize, "%s:%s", name, stream);
		else
			snprintf (buffer, bufsize, "%s", name);

	return strlen (buffer);
}

/**
 * open_file - Open a file to write to
 * @pathname:  Path, name and stream of the file to open
 *
 * Create a file and return the file descriptor.
 *
 * N.B.  If option force is given and existing file will be overwritten.
 *
 * Return:  -1  Error, failed to create the file
 *	     n  Success, this is the file descriptor
 */
int open_file (const char *pathname)
{
	int flags;

	Vprintf ("Creating file: %s\n", pathname);

	if (opts.force)
		flags = O_RDWR | O_CREAT | O_TRUNC;
	else
		flags = O_RDWR | O_CREAT | O_EXCL;

	return open (pathname, flags, S_IRUSR | S_IWUSR);
}

/**
 * set_date - Set the file's date and time
 * @pathname:  Path and name of the file to alter
 * @date:      Date and time to set
 *
 * Give a file a particular date and time.
 *
 * Return:  1  Success, set the file's date and time
 *	    0  Error, failed to change the file's date and time
 */
int set_date (const char *pathname, time_t date)
{
	struct utimbuf ut;

	if (!pathname)
		return 0;

	ut.actime  = date;
	ut.modtime = date;
	if (utime (pathname, &ut)) {
		Eprintf ("Couldn't set the file's date and time\n");
		return 0;
	}
	return 1;
}

/**
 * scan_disk - Search an NTFS volume for files that could be undeleted
 * @vol:  An ntfs volume obtained from ntfs_mount
 *
 * Read through all the MFT entries looking for deleted files.  For each one
 * determine how much of the data lies in unused disk space.
 *
 * The list can be filtered by name, size and date, using command line options.
 *
 * Return:  -1  Error, something went wrong
 *	     n  Success, the number of recoverable files
 */
int scan_disk (ntfs_volume *vol)
{
	const int BUFSIZE = 8192;
	char *buffer = NULL;
	int results = 0;
	ntfs_attr *attr;
	long long size;
	long long read;
	long long bmpsize;
	int i, j, k, b;
	int percent;
	struct ufile *file;
	regex_t re;

	if (!vol)
		return -1;

	attr = ntfs_attr_open (vol->mft_ni, AT_BITMAP, AT_UNNAMED, 0);
	if (!attr) {
		Eprintf ("Couldn't open $MFT/$BITMAP: %s\n", strerror (errno));
		return -1;
	}
	bmpsize = attr->initialized_size;

	buffer = malloc (BUFSIZE);
	if (!buffer) {
		Eprintf ("Couldn't allocate memory in scan_disk()\n");
		results = -1;
		goto out;
	}

	if (opts.match) {
		int flags = REG_NOSUB;

		if (!opts.match_case)
			flags |= REG_ICASE;
		if (regcomp (&re, opts.match, flags)) {
			Eprintf ("Couldn't create a regex.\n");
			goto out;
		}
	}

	Iprintf ("Inode    Flags  %%age  Date            Size  Filename\n");
	Iprintf ("---------------------------------------------------------------\n");
	for (i = 0; i < bmpsize; i += BUFSIZE) {
		read = min ((bmpsize - i), BUFSIZE);
		size = ntfs_attr_pread (attr, i, read, buffer);
		if (size < 0)
			break;

		for (j = 0; j < size; j++) {
			b = buffer[j];
			for (k = 0; k < 8; k++, b>>=1) {
				if (((i+j)*8+k) >= vol->nr_mft_records)
					goto done;
				if (b & 1)
					continue;
				file = read_record (vol, (i+j)*8+k);
				if (!file) {
					Eprintf ("Couldn't read MFT Record %d.\n", (i+j)*8+k);
					continue;
				}

				if ((opts.since > 0) && (file->date <= opts.since))
					goto skip;
				if (opts.match && !name_match (&re, file))
					goto skip;
				if (opts.size_begin && (opts.size_begin > file->max_size))
					goto skip;
				if (opts.size_end && (opts.size_end < file->max_size))
					goto skip;

				percent = calc_percentage (file, vol);

				if ((opts.percent == -1) || (percent >= opts.percent)) {
					if (opts.verbose)
						dump_record (file);
					else
						list_record (file);
				}

				if (((opts.percent == -1) && (percent > 0)) ||
				    ((opts.percent > 0)  && (percent >= opts.percent))) {
					results++;
				}
skip:
				free_file (file);
			}
		}
	}
done:
	Iprintf ("\nFiles with potentially recoverable content: %d\n", results);
out:
	if (opts.match)
		regfree (&re);
	free (buffer);
	if (attr)
		ntfs_attr_close (attr);
	return results;
}

/**
 * undelete_file - Recover a deleted file from an NTFS volume
 * @vol:    An ntfs volume obtained from ntfs_mount
 * @inode:  MFT Record number to be recovered
 *
 * Read an MFT Record and try an recover any data associated with it.  Some of
 * the clusters may be in use; these will be filled with zeros or the fill byte
 * supplied in the options.
 *
 * Each data stream will be recovered and saved to a file.  The file's name will
 * be the original filename and it will be written to the current directory.
 * Any named data stream will be saved as filename:streamname.
 *
 * The output file's name and location can be altered by using the command line
 * options.
 *
 * N.B.  We cannot tell if someone has overwritten some of the data since the
 *       file was deleted.
 *
 * Return:  0  Error, something went wrong
 *	    1  Success, the data was recovered
 */
int undelete_file (ntfs_volume *vol, long long inode)
{
	char pathname[256];
	char *buffer = NULL;
	unsigned int bufsize;
	struct ufile *file;
	int i, j;
	long long start, end;
	runlist_element *rl;
	struct list_head *item;
	int fd = -1;
	long long k;
	int result = 0;

	if (!vol)
		return 0;

	file = read_record (vol, inode);
	if (!file || !file->mft) {
		Eprintf ("Can't read info from mft record %lld.\n", inode);
		return 0;
	}

	bufsize = vol->cluster_size;
	buffer = malloc (bufsize);
	if (!buffer)
		goto free;

	if (opts.verbose) {
		dump_record (file);
	} else {
		Iprintf ("Inode    Flags  %%age  Date            Size  Filename\n");
		Iprintf ("---------------------------------------------------------------\n");
		list_record (file);
		Iprintf ("\n");
	}

	if (file->mft->flags & MFT_RECORD_IN_USE) {
		Eprintf ("Record is in use by the mft\n");
		if (!opts.force) {
			free_file (file);
			return 0;
		}
		Vprintf ("Forced to continue.\n");
	}

	if (calc_percentage (file, vol) == 0) {
		Iprintf ("File has no recoverable data.\n");
		goto free;
	}

	if (list_empty (&file->data)) {
		Iprintf ("File has no data.  There is nothing to recover.\n");
		goto free;
	}

	list_for_each (item, &file->data) {
		struct data *d = list_entry (item, struct data, list);

		create_pathname (opts.dest, file->pref_name, d->name, pathname, sizeof (pathname));
		if (d->resident) {
			fd = open_file (pathname);
			if (fd < 0) {
				Eprintf ("Couldn't create file: %s\n", strerror (errno));
				goto free;
			}

			Vprintf ("File has resident data.\n");
			if (write_data (fd, d->data, d->size_data) < d->size_data) {
				Eprintf ("Write failed: %s\n", strerror (errno));
				close (fd);
				goto free;
			}

			if (close (fd) < 0) {
				Eprintf ("Close failed: %s\n", strerror (errno));
			}
			fd = -1;
		} else {
			rl = d->runlist;
			if (!rl) {
				Vprintf ("File has no runlist, hence no data.\n");
				continue;
			}

			if (rl[0].length <= 0) {
				Vprintf ("File has an empty runlist, hence no data.\n");
				continue;
			}

			fd = open_file (pathname);
			if (fd < 0) {
				Eprintf ("Couldn't create output file: %s\n", strerror (errno));
				goto free;
			}

			if (rl[0].lcn == LCN_RL_NOT_MAPPED) {	/* extended mft record */
				Vprintf ("Missing segment at beginning, %lld clusters.\n", rl[0].length);
				memset (buffer, opts.fillbyte, bufsize);
				for (k = 0; k < rl[0].length * vol->cluster_size; k += bufsize) {
					if (write_data (fd, buffer, bufsize) < bufsize) {
						Eprintf ("Write failed: %s\n", strerror (errno));
						close (fd);
						goto free;
					}
				}
			}

			for (i = 0; rl[i].length > 0; i++) {

				if (rl[i].lcn == LCN_RL_NOT_MAPPED) {
					Vprintf ("Missing segment at end, %lld clusters.\n", rl[i].length);
					memset (buffer, opts.fillbyte, bufsize);
					for (k = 0; k < rl[k].length * vol->cluster_size; k += bufsize) {
						if (write_data (fd, buffer, bufsize) < bufsize) {
							Eprintf ("Write failed: %s\n", strerror (errno));
							close (fd);
							goto free;
						}
					}
					continue;
				}

				if (rl[i].lcn == LCN_HOLE) {
					Vprintf ("File has a sparse section.\n");
					memset (buffer, 0, bufsize);
					for (k = 0; k < rl[k].length * vol->cluster_size; k += bufsize) {
						if (write_data (fd, buffer, bufsize) < bufsize) {
							Eprintf ("Write failed: %s\n", strerror (errno));
							close (fd);
							goto free;
						}
					}
					continue;
				}

				start = rl[i].lcn;
				end   = rl[i].lcn + rl[i].length;

				for (j = start; j < end; j++) {
					if (cluster_in_use (vol, j)) {
						memset (buffer, opts.fillbyte, bufsize);
						if (write_data (fd, buffer, bufsize) < bufsize) {
							Eprintf ("Write failed: %s\n", strerror (errno));
							close (fd);
							goto free;
						}
					} else {
						if (ntfs_clusters_read(vol, j, 1, buffer) < 1) {
							Eprintf ("Read failed: %s\n", strerror (errno));
							close (fd);
							goto free;
						}
						if (write_data (fd, buffer, bufsize) < bufsize) {
							Eprintf ("Write failed: %s\n", strerror (errno));
							close (fd);
							goto free;
						}
					}
				}
			}
			Iprintf ("\n");
			if (close (fd) < 0) {
				Eprintf ("Close failed: %s\n", strerror (errno));
			}
			fd = -1;

		}
		set_date (pathname, file->date);
		if (d->name)
			Iprintf ("Undeleted '%s:%s' successfully.\n", file->pref_name, d->name);
		else
			Iprintf ("Undeleted '%s' successfully.\n", file->pref_name);
	}
	result = 1;
free:
	if (buffer)
		free (buffer);
	free_file (file);
	return result;
}

/**
 * copy_mft - Write a range of MFT Records to a file
 * @vol:	An ntfs volume obtained from ntfs_mount
 * @mft_begin:	First MFT Record to save
 * @mft_end:	Last MFT Record to save
 *
 * Read a number of MFT Records and write them to a file.
 *
 * Return:  0  Success, all the records were written
 *	    1  Error, something went wrong
 */
int copy_mft (ntfs_volume *vol, long long mft_begin, long long mft_end)
{
	char pathname[256];
	ntfs_attr *mft;
	char *buffer;
	const char *name;
	long long i;
	int result = 1;
	int fd;

	if (!vol)
		return 1;

	if (mft_end < mft_begin) {
		Eprintf ("Range to copy is backwards.\n");
		return 1;
	}

	buffer = malloc (vol->mft_record_size);
	if (!buffer) {
		Eprintf ("Couldn't allocate memory in copy_mft()\n");
		return 1;
	}

	mft = ntfs_attr_open (vol->mft_ni, AT_DATA, NULL, 0);
	if (!mft) {
		Eprintf ("Couldn't open $MFT/$DATA: %s\n", strerror (errno));
		goto free;
	}

	name = opts.output;
	if (!name) {
		name = MFTFILE;
		Dprintf ("No output filename, defaulting to '%s'.\n", name);
	}

	create_pathname (opts.dest, name, NULL, pathname, sizeof (pathname));
	fd = open_file (pathname);
	if (fd < 0) {
		Eprintf ("Couldn't open output file '%s': %s\n", name, strerror (errno));
		goto attr;
	}

	mft_end = min (mft_end, vol->nr_mft_records - 1);

	Dprintf ("MFT records\n");
	Dprintf ("    Total: %8lld\n", vol->nr_mft_records);
	Dprintf ("    Begin: %8lld\n", mft_begin);
	Dprintf ("    End:   %8lld\n", mft_end);

	for (i = mft_begin; i <= mft_end; i++) {
		if (ntfs_attr_pread (mft, vol->mft_record_size * i, vol->mft_record_size, buffer) < vol->mft_record_size) {
			Eprintf ("Couldn't read MFT Record %d: %s.\n", i, strerror (errno));
			goto close;
		}

		if (write_data (fd, buffer, vol->mft_record_size) < vol->mft_record_size) {
			Eprintf ("Write failed: %s\n", strerror (errno));
			goto close;
		}
	}

	Vprintf ("Read %d MFT Records\n", mft_end - mft_begin + 1);
	result = 0;
close:
	close (fd);
attr:
	ntfs_attr_close (mft);
free:
	free (buffer);
	return result;
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
 *	    0  Error, we cannot use this device
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
 * main - Begin here
 *
 * Start from here.
 *
 * Return:  0  Success, the program worked
 *	    1  Error, something went wrong
 */
int main (int argc, char *argv[])
{
	const char *locale;
	ntfs_volume *vol;
	int result = 1;

	locale = setlocale (LC_ALL, "");
	if (!locale) {
		locale = setlocale (LC_ALL, NULL);
		Vprintf ("Failed to set locale, using default '%s'.\n", locale);
	} else {
		Vprintf ("Using locale '%s'.\n", locale);
	}

	if (!parse_options (argc, argv))
		goto free;

	if (!valid_device (opts.device, opts.force))
		goto free;

	vol = ntfs_mount (opts.device, MS_RDONLY);
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

	switch (opts.mode) {
	case MODE_SCAN:
		result = !scan_disk (vol);
		if (result)
			Vprintf ("Failed to scan device '%s'.\n", opts.device);
		break;
	case MODE_UNDELETE:
		result = !undelete_file (vol, opts.uinode);
		if (result)
			Vprintf ("Failed to undelete inode %d.\n", opts.uinode);
		break;
	case MODE_COPY:
		result = !copy_mft (vol, opts.mft_begin, opts.mft_end);
		if (result)
			Vprintf ("Failed to read MFT blocks %lld-%lld.\n",
				opts.mft_begin, min (vol->nr_mft_records, opts.mft_end));
		break;
	default:
		; /* Cannot happen */
	}

umount:
	ntfs_umount (vol, FALSE);
free:
	if (opts.match)
		free (opts.match);

	return result;
}

