/**
 * ntfswipe - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002-2003 Richard Russon
 * Copyright (c) 2004 Yura Pakhuchiy
 *
 * This utility will overwrite unused space on an NTFS volume.
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
#include <stdarg.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "ntfswipe.h"
#include "types.h"
#include "volume.h"
#include "utils.h"
#include "debug.h"

static char *EXEC_NAME = "ntfswipe";
static struct options opts;

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
	printf ("\n%s v%s - Overwrite the unused space on an NTFS Volume.\n\n",
		EXEC_NAME, VERSION);
	printf ("Copyright (c) 2002-2003 Richard Russon\n");
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
	printf ("\nUsage: %s [options] device\n"
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
	printf ("%s%s\n", ntfs_bugs, ntfs_home);
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
 *	    n  Success, the count of numbers parsed
 */
static int parse_list (char *list, int **result)
{
	char *ptr;
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
 *	    0 Error, one or more problems
 */
static int parse_options (int argc, char *argv[])
{
	static char *sopt = "-ab:c:dfh?ilmnpqtuvV";
	static struct option lopt[] = {
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
		//{ "no-wait",	no_argument,		NULL, 0   },
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

		case 'i':
			opts.info++;		/* and fall through */
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
				if (!parse_list (optarg, &opts.bytes))
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
		case '?':
			help++;
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
			if (argc > 1)
				Eprintf ("You must specify exactly one device.\n");
			err++;
		}

		if (opts.quiet && opts.verbose) {
			Eprintf ("You may not use --quiet and --verbose at the same time.\n");
			err++;
		}

		/*
		if (opts.info && (opts.unused || opts.tails || opts.mft || opts.directory)) {
			Eprintf ("You may not use any other options with --info.\n");
			err++;
		}
		*/

		if ((opts.count < 1) || (opts.count > 100)) {
			Eprintf ("The iteration count must be between 1 and 100.\n");
			err++;
		}

		/* Create a default list */
		if (!opts.bytes) {
			opts.bytes = malloc (2 * sizeof (int));
			if (opts.bytes) {
				opts.bytes[0] =  0;
				opts.bytes[1] = -1;
			} else {
				Eprintf ("Couldn't allocate memory for byte list.\n");
				err++;
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
 * wipe_unused - Wipe unused clusters
 * @vol:   An ntfs volume obtained from ntfs_mount
 * @byte:  Overwrite with this value
 *
 * Read $Bitmap and wipe any clusters that are marked as not in use.
 *
 * Return:  1  Success, the clusters were wiped
 *	    0  Error, something went wrong
 */
static s64 wipe_unused (ntfs_volume *vol, int byte, enum action act)
{
	s64 i;
	s64 total = 0;
	s64 result = 0;
	u8 *buffer = NULL;

	if (!vol || (byte < 0))
		return -1;

	if (act != act_info) {
		buffer = malloc (vol->cluster_size);
		if (!buffer) {
			Eprintf ("malloc failed\n");
			return -1;
		}
		memset (buffer, byte, vol->cluster_size);
	}

	for (i = 0; i < vol->nr_clusters; i++) {
		if (utils_cluster_in_use (vol, i)) {
			//Vprintf ("cluster %lld is in use\n", i);
			continue;
		}

		if (act == act_wipe) {
			//Vprintf ("cluster %lld is not in use\n", i);
			result = ntfs_pwrite (vol->dev, vol->cluster_size * i, vol->cluster_size, buffer);
			if (result != vol->cluster_size) {
				Eprintf ("write failed\n");
				goto free;
			}
		}

		total += vol->cluster_size;
	}

	Qprintf ("wipe_unused 0x%02x, %lld bytes\n", byte, (long long)total);
free:
	free (buffer);
	return total;
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
 *	    0  Error, something went wrong
 */
static s64 wipe_tails (ntfs_volume *vol, int byte, enum action act)
{
	s64 total = 0;
	s64 size;
	s64 inode_num;
	ntfs_attr_search_ctx *ctx;
	ntfs_inode *ni;
	unsigned char *buf;
	ATTR_RECORD *attr;
	runlist *rl;
	
	if (!vol || (byte < 0))
		return -1;
	
	for (inode_num = 16; inode_num < vol->nr_mft_records; inode_num++) {
		Vprintf ("Inode %lli - ", inode_num);
		ni = ntfs_inode_open (vol, inode_num);
		if (!ni) {
			Vprintf ("Could not open inode\n");
			continue;
		}
		
		ctx = ntfs_attr_get_search_ctx(ni, 0);
		if (!ctx) {
			Vprintf ("Internal error\n");
			Eprintf ("Could not get search context\n");
			goto close_inode;
		}

		if (ntfs_attr_lookup(AT_DATA, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx)) {
			Vprintf ("Could not open $DATA attribute\n");
			goto put_search_ctx;
		}
		attr = ctx->attr;
		
		if (!attr->non_resident) {
			Vprintf ("Resident $DATA atrributes. Skipping.\n");
			goto put_search_ctx;
		}
		
		if (attr->flags &
			(ATTR_IS_SPARSE | ATTR_IS_ENCRYPTED | ATTR_IS_COMPRESSED)) {
			Vprintf ("Sparse, encrypted and compressed are not "
				"supported.\n");
			goto put_search_ctx;
		}
		
		size = attr->allocated_size - attr->data_size;
		if (!size) {
			Vprintf ("Nothing to wipe\n");
			goto put_search_ctx;
		}
		
		if (act == act_info) {
			total += size;
			Vprintf ("Can wipe %lld bytes\n", size);
			goto put_search_ctx;
		}
		
		buf = malloc (size);
		if (!buf) {
			Vprintf ("Not enough memory\n");
			Eprintf ("Not enough memory to allocate %lld bytes\n", size);
			goto put_search_ctx;
		}
		memset (buf, byte, size);
		
		rl = ntfs_mapping_pairs_decompress(vol, attr, 0);
		if (!rl) {
			Vprintf ("Internal error\n");
			Eprintf ("Could not decompress mapping pairs\n");
			goto free_buf;
		}

		s64 bw = ntfs_rl_pwrite (vol, rl, attr->data_size, size, buf);
		if (bw == -1) {
			Vprintf ("Internal error\n");
			Eprintf ("Couldn't wipe tail of inode %lld\n", inode_num);
		} else {
			Vprintf ("Wiped %lld bytes\n", bw);
			total += bw;
		}

		free (rl);
free_buf:
		free (buf);
put_search_ctx:
		ntfs_attr_put_search_ctx (ctx);
close_inode:
		ntfs_inode_close (ni);
	}
	Qprintf ("wipe_tails 0x%02x, %lld bytes\n", byte, (long long)total);
	return total;
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
 *	    0  Error, something went wrong
 */
static s64 wipe_mft (ntfs_volume *vol, int byte, enum action act)
{
	// by considering the individual attributes we might be able to
	// wipe a few more bytes at the attr's tail.
	s64 i;
	s64 total = 0;
	s64 result = 0;
	int size = 0;
	u8 *buffer = NULL;

	if (!vol || (byte < 0))
		return -1;

	buffer = malloc (vol->mft_record_size);
	if (!buffer) {
		Eprintf ("malloc failed\n");
		return -1;
	}

	for (i = 0; i < vol->nr_mft_records; i++) {
		if (utils_mftrec_in_use (vol, i)) {
			result = ntfs_attr_mst_pread (vol->mft_na, vol->mft_record_size * i,
				1, vol->mft_record_size, buffer);
			if (result != 1) {
				Eprintf ("error attr mst read %lld\n",
						(long long)i);
				total = -1;	// XXX just negate result?
				goto free;
			}

			// We know that the end marker will only take 4 bytes
			size = *((u32*) (buffer + 0x18)) - 4;

			if (act == act_info) {
				//printf ("mft %d\n", size);
				total += size;
				continue;
			}

			memset (buffer + size, byte, vol->mft_record_size - size);

			result = ntfs_attr_mst_pwrite (vol->mft_na, vol->mft_record_size * i,
				1, vol->mft_record_size, buffer);
			if (result != 1) {
				Eprintf ("error attr mst write %lld\n",
						(long long)i);
				total = -1;
				goto free;
			}

			if ((vol->mft_record_size * (i+1)) <= vol->mftmirr_na->allocated_size)
			{
				// We have to reduce the update sequence number, or else...
				u16 offset;
				u16 usa;
				offset = le16_to_cpu (*(buffer + 0x04));
				usa = le16_to_cpu (*(buffer + offset));
				*((u16*) (buffer + offset)) = cpu_to_le16 (usa - 1);

				result = ntfs_attr_mst_pwrite (vol->mftmirr_na, vol->mft_record_size * i,
					1, vol->mft_record_size, buffer);
				if (result != 1) {
					Eprintf ("error attr mst write %lld\n",
							(long long)i);
					total = -1;
					goto free;
				}
			}

			total += vol->mft_record_size;
		} else {
			if (act == act_info) {
				total += vol->mft_record_size;
				continue;
			}

			// Build the record from scratch
			memset (buffer, 0, vol->mft_record_size);

			// Common values
			*((u32*) (buffer + 0x00)) = magic_FILE;				// Magic
			*((u16*) (buffer + 0x06)) = cpu_to_le16 (0x0003);		// USA size
			*((u16*) (buffer + 0x10)) = cpu_to_le16 (0x0001);		// Seq num
			*((u32*) (buffer + 0x1C)) = cpu_to_le32 (vol->mft_record_size);	// FILE size
			*((u16*) (buffer + 0x28)) = cpu_to_le16 (0x0001);		// Attr ID

			if (vol->major_ver == 3) {
				// Only XP and 2K3
				*((u16*) (buffer + 0x04)) = cpu_to_le16 (0x0030);	// USA offset
				*((u16*) (buffer + 0x14)) = cpu_to_le16 (0x0038);	// Attr offset
				*((u32*) (buffer + 0x18)) = cpu_to_le32 (0x00000040);	// FILE usage
				*((u32*) (buffer + 0x38)) = cpu_to_le32 (0xFFFFFFFF);	// End marker
			} else {
				// Only NT and 2K
				*((u16*) (buffer + 0x04)) = cpu_to_le16 (0x002A);	// USA offset
				*((u16*) (buffer + 0x14)) = cpu_to_le16 (0x0030);	// Attr offset
				*((u32*) (buffer + 0x18)) = cpu_to_le32 (0x00000038);	// FILE usage
				*((u32*) (buffer + 0x30)) = cpu_to_le32 (0xFFFFFFFF);	// End marker
			}

			result = ntfs_attr_mst_pwrite (vol->mft_na, vol->mft_record_size * i,
				1, vol->mft_record_size, buffer);
			if (result != 1) {
				Eprintf ("error attr mst write %lld\n",
						(long long)i);
				total = -1;
				goto free;
			}

			total += vol->mft_record_size;
		}
	}

	Qprintf ("wipe_mft 0x%02x, %lld bytes\n", byte, (long long)total);
free:
	free (buffer);
	return total;
}

/**
 * wipe_directory - Wipe the directory indexes
 * @vol:   An ntfs volume obtained from ntfs_mount
 * @byte:  Overwrite with this value
 *
 * Directories are kept in sorted B+ Trees.  Index blocks may not be full.  Wipe
 * the unused space at the ends of these blocks.
 *
 * Return:  1  Success, the clusters were wiped
 *	    0  Error, something went wrong
 */
static s64 wipe_directory (ntfs_volume *vol, int byte, enum action act)
{
	if (!vol || (byte < 0))
		return -1;

	Qprintf ("wipe_directory (not implemented) 0x%02x\n", byte);
	return 0;
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
 *	    0  Error, something went wrong
 */
static s64 wipe_logfile (ntfs_volume *vol, int byte, enum action act)
{
	const int NTFS_BUF_SIZE2 = 8192;
	//FIXME(?): We might need to zero the LSN field of every single mft
	//record as well. (But, first try without doing that and see what
	//happens, since chkdsk might pickup the pieces and do it for us...)
	ntfs_inode *ni;
	ntfs_attr *na;
	s64 len, pos, count;
	char buf[NTFS_BUF_SIZE2];
	int eo;

	if (!vol || (byte < 0))
		return -1;

	//Qprintf ("wipe_logfile (not implemented) 0x%02x\n", byte);

	if ((ni = ntfs_inode_open(vol, FILE_LogFile)) == NULL) {
		Dprintf("Failed to open inode FILE_LogFile.\n");
		return -1;
	}

	if ((na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0)) == NULL) {
		Dprintf("Failed to open $FILE_LogFile/$DATA\n");
		goto error_exit;
	}

	/* The $DATA attribute of the $LogFile has to be non-resident. */
	if (!NAttrNonResident(na)) {
		Dprintf("$LogFile $DATA attribute is resident!?!\n");
		errno = EIO;
		goto io_error_exit;
	}

	/* Get length of $LogFile contents. */
	len = na->data_size;
	if (!len) {
		Dprintf("$LogFile has zero length, no disk write needed.\n");
		return 0;
	}

	/* Read $LogFile until its end. We do this as a check for correct
	   length thus making sure we are decompressing the mapping pairs
	   array correctly and hence writing below is safe as well. */
	pos = 0;
	while ((count = ntfs_attr_pread(na, pos, NTFS_BUF_SIZE2, buf)) > 0)
		pos += count;

	if (count == -1 || pos != len) {
		Dprintf("Amount of $LogFile data read does not "
			"correspond to expected length!");
		if (count != -1)
			errno = EIO;
		goto io_error_exit;
	}

	/* Fill the buffer with 0xff's. */
	memset(buf, -1, NTFS_BUF_SIZE2);

	/* Set the $DATA attribute. */
	pos = 0;
	while ((count = len - pos) > 0) {
		if (count > NTFS_BUF_SIZE2)
			count = NTFS_BUF_SIZE2;

		if ((count = ntfs_attr_pwrite(na, pos, count, buf)) <= 0) {
			Dprintf("Failed to set the $LogFile attribute value.");
			if (count != -1)
				errno = EIO;
			goto io_error_exit;
		}

		pos += count;
	}

	ntfs_attr_close(na);
	return ntfs_inode_close(ni);

io_error_exit:
	eo = errno;
	ntfs_attr_close(na);
	errno = eo;
error_exit:
	eo = errno;
	ntfs_inode_close(ni);
	errno = eo;
	return -1;
	return 0;
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
 *	    0  Error, something went wrong
 */
static s64 wipe_pagefile (ntfs_volume *vol, int byte, enum action act)
{
	// wipe completely, chkdsk doesn't do anything, booting writes header
	const int NTFS_BUF_SIZE2 = 4096;
	ntfs_inode *ni;
	ntfs_attr *na;
	s64 len, pos, count;
	char buf[NTFS_BUF_SIZE2];
	int eo;

	if (!vol || (byte < 0))
		return -1;

	//Qprintf ("wipe_pagefile (not implemented) 0x%02x\n", byte);
	
	ni = utils_pathname_to_inode (vol, NULL, "pagefile.sys");
	if (!ni) {
		Dprintf("Failed to open inode FILE_LogFile.\n");
		return -1;
	}

	if ((na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0)) == NULL) {
		Dprintf("Failed to open $FILE_LogFile/$DATA\n");
		goto error_exit;
	}

	/* The $DATA attribute of the $LogFile has to be non-resident. */
	if (!NAttrNonResident(na)) {
		Dprintf("$LogFile $DATA attribute is resident!?!\n");
		errno = EIO;
		goto io_error_exit;
	}

	/* Get length of $LogFile contents. */
	len = na->data_size;
	if (!len) {
		Dprintf("$LogFile has zero length, no disk write needed.\n");
		return 0;
	}

	memset(buf, byte, NTFS_BUF_SIZE2);

	/* Set the $DATA attribute. */
	pos = 0;
	while ((count = len - pos) > 0) {
		if (count > NTFS_BUF_SIZE2)
			count = NTFS_BUF_SIZE2;

		if ((count = ntfs_attr_pwrite(na, pos, count, buf)) <= 0) {
			Dprintf("Failed to set the $LogFile attribute value.");
			if (count != -1)
				errno = EIO;
			goto io_error_exit;
		}

		pos += count;
	}

	ntfs_attr_close(na);
	return ntfs_inode_close(ni);

io_error_exit:
	eo = errno;
	ntfs_attr_close(na);
	errno = eo;
error_exit:
	eo = errno;
	ntfs_inode_close(ni);
	errno = eo;
	return -1;
}

/**
 * ntfs_info - Display information about the NTFS Volume
 * @vol:  An ntfs volume obtained from ntfs_mount
 *
 * Tell the user how much could be cleaned up.  List the number of free
 * clusters, MFT records, etc.
 *
 * Return:  1  Success, displayed some info
 *	    0  Error, something went wrong
 */
static int ntfs_info (ntfs_volume *vol)
{
	u8 *buffer;

	if (!vol)
		return 0;

	Qprintf ("ntfs_info\n");

	Qprintf ("\n");

	Qprintf ("Cluster size = %u\n", (unsigned int)vol->cluster_size);
	Qprintf ("Volume size = %lld clusters\n", (long long)vol->nr_clusters);
	Qprintf ("Volume size = %lld bytes\n",
			(long long)vol->nr_clusters * vol->cluster_size);
	Qprintf ("Volume size = %lld MiB\n", (long long)vol->nr_clusters *
			vol->cluster_size / (1024*1024)); /* round up? */

	Qprintf ("\n");

	// move back bufsize
	buffer = malloc (vol->mft_record_size);
	if (!buffer)
		return 0;

	Qprintf ("cluster\n");
	//Qprintf ("allocated_size = %lld\n", vol->lcnbmp_na->allocated_size);
	Qprintf ("data_size = %lld\n", (long long)vol->lcnbmp_na->data_size);
	//Qprintf ("initialized_size = %lld\n", vol->lcnbmp_na->initialized_size);

	{
	s64 offset;
	s64 size = vol->lcnbmp_na->allocated_size;
	int bufsize = vol->mft_record_size;
	s64 use = 0;
	s64 not = 0;
	int i, j;

	for (offset = 0; offset < size; offset += bufsize) {

		if ((offset + bufsize) > size)
			bufsize = size - offset;

		if (ntfs_attr_pread (vol->lcnbmp_na, offset, bufsize, buffer) < bufsize) {
			Eprintf ("error\n");
			return 0;
		}

		for (i = 0; i < bufsize; i++) {
			for (j = 0; j < 8; j++) {
				if ((((offset+i)*8) + j) >= vol->nr_clusters)
					goto done;
				if (buffer[i] & (1 << j)) {
					//printf ("*");
					use++;
				} else {
					//printf (".");
					not++;
				}
			}
		}
	}
done:

	Qprintf ("cluster use %lld, not %lld, total %lld\n", (long long)use,
			(long long)not, (long long)(use + not));
	Qprintf ("\n");

	}

	{
	u8 *bitmap;
	s64 bmpoff;
	s64 bmpsize = vol->mftbmp_na->data_size;
	int bmpbufsize = 512;
	int i, j;
	s64 use = 0, not = 0;

	bitmap = malloc (bmpbufsize);
	if (!bitmap)
		return 0;

	printf ("mft has %lld records\n", (long long)vol->nr_mft_records);

	//Qprintf ("allocated_size = %lld\n", vol->mftbmp_na->allocated_size);
	Qprintf ("data_size = %lld\n", (long long)vol->mftbmp_na->data_size);
	//Qprintf ("initialized_size = %lld\n", vol->mftbmp_na->initialized_size);

	printf ("bmpsize = %lld\n", (long long)bmpsize);
	for (bmpoff = 0; bmpoff < bmpsize; bmpoff += bmpbufsize) {
		if ((bmpoff + bmpbufsize) > bmpsize)
			bmpbufsize = bmpsize - bmpoff;

		//printf ("bmpbufsize = %d\n", bmpbufsize);

		if (ntfs_attr_pread (vol->mftbmp_na, bmpoff, bmpbufsize, bitmap) < bmpbufsize) {
			Eprintf ("error\n");
			return 0;
		}

		for (i = 0; i < bmpbufsize; i++) {
			for (j = 0; j < 8; j++) {
				if ((((bmpoff+i)*8) + j) >= vol->nr_mft_records)
					goto bmpdone;
				if (bitmap[i] & (1 << j)) {
					//printf ("*");
					use++;
				} else {
					//printf (".");
					not++;
				}
			}
		}
	}

bmpdone:
	printf ("mft\n");
	printf ("use %lld, not %lld, total %lld\n", (long long)use,
			(long long)not, (long long)(use + not));

	free (bitmap);
	}

	/*
	 * wipe_unused - volume = n clusters, u unused (%age & MB)
	 *	$Bitmap
	 *	vol->lcnbmp_na
	 *
	 * wipe_tails - volume = n files, total tail slack space
	 *	$MFT, $DATA
	 *	vol->mft_na
	 *
	 * wipe_mft - volume = n mft records, u unused, s total slack space
	 *	$MFT, $BITMAP
	 *	vol->mftbmp_na
	 *
	 * wipe_directory - volume has d dirs, t total slack space
	 *	$MFT, $INDEX_ROOT, $INDEX_ALLOC, $BITMAP
	 *
	 * wipe_logfile - logfile is <size>
	 *	$MFT, $DATA
	 *
	 * wipe_pagefile - pagefile is <size>
	 *	$MFT, $DATA
	 */

	free (buffer);
#if 0
	ntfs_inode *inode;
	ntfs_attr *attr;

	inode = ntfs_inode_open (vol, 6);	/* $Bitmap */
	if (!inode)
		return 0;

	attr = ntfs_attr_open (inode, AT_DATA, NULL, 0);
	if (!attr)
		return 0;

	ntfs_attr_pread

	ntfs_attr_close (attr);
	ntfs_inode_close (inode);
#endif

	return 1;
}

/**
 * print_summary - Tell the user what we are about to do
 *
 * List the operations about to be performed.  The output will be silenced by
 * the --quiet option.
 *
 * Return:  none
 */
static void print_summary (void)
{
	int i;

	if (opts.noaction)
		Qprintf ("%s is in 'no-action' mode, it will NOT write to disk."
			 "\n\n", EXEC_NAME);

	Qprintf ("%s is about to wipe:\n", EXEC_NAME);
	if (opts.unused)
		Qprintf ("\tunused disk space\n");
	if (opts.tails)
		Qprintf ("\tfile tails\n");
	if (opts.mft)
		Qprintf ("\tunused mft areas\n");
	if (opts.directory)
		Qprintf ("\tunused directory index space\n");
	if (opts.logfile)
		Qprintf ("\tthe logfile (journal)\n");
	if (opts.pagefile)
		Qprintf ("\tthe pagefile (swap space)\n");

	Qprintf ("\n%s will overwrite these areas with: ", EXEC_NAME);
	if (opts.bytes) {
		for (i = 0; opts.bytes[i] >= 0; i++)
			Qprintf ("0x%02x ", opts.bytes[i]);
	}
	Qprintf ("\n");

	if (opts.count > 1)
		Qprintf ("%s will repeat these operations %d times.\n", EXEC_NAME, opts.count);
	Qprintf ("\n");
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
	int result = 1;
	int flags = 0;
	int i, j;
	enum action act = act_info;

	if (!parse_options (argc, argv))
		return 1;

	utils_set_locale();

	if (!opts.info)
		print_summary();

	if (opts.info || opts.noaction)
		flags = MS_RDONLY;

	vol = utils_mount_volume (opts.device, flags, opts.force);
	if (!vol)
		goto free;

	if ((vol->flags & VOLUME_IS_DIRTY) && (!opts.force))
		goto umount;

	if (opts.info) {
		act = act_info;
		opts.count = 1;
	} else if (opts.noaction) {
		act = act_test;
	} else {
		act = act_wipe;
	}

	/* Even if the output it quieted, you still get 5 seconds to abort. */
	if ((act == act_wipe) && !opts.force) {
		Qprintf ("\n%s will begin in 5 seconds, press CTRL-C to abort.\n", EXEC_NAME);
		sleep (5);
	}

	if (0)
	{
		int i = 0;
		runlist_element *rl = vol->mft_na->rl;
		printf ("________________________________________________________________________________\n\n");
		for (; rl->length > 0; rl++, i++) {
			printf ("%4d %lld,%lld,%lld\n", i, (long long)rl->vcn,
					(long long)rl->lcn,
					(long long)rl->length);
		}
		printf ("%4d %lld,%lld,%lld\n", i, (long long)rl->vcn,
				(long long)rl->lcn, (long long)rl->length);
		return 0;
	}

	printf ("\n");
	for (i = 0; i < opts.count; i++) {
		int byte;
		s64 total = 0;
		s64 wiped = 0;

		for (j = 0; byte = opts.bytes[j], byte >= 0; j++) {

			if (opts.directory) {
				wiped = wipe_directory (vol, byte, act);
				if (wiped < 0)
					goto umount;
				else
					total += wiped;
			}

			if (opts.tails) {
				wiped = wipe_tails (vol, byte, act);
				if (wiped < 0)
					goto umount;
				else
					total += wiped;
			}

			if (opts.logfile) {
				wiped = wipe_logfile (vol, byte, act);
				if (wiped < 0)
					goto umount;
				else
					total += wiped;
			}

			if (opts.mft) {
				wiped = wipe_mft (vol, byte, act);
				if (wiped < 0)
					goto umount;
				else
					total += wiped;
			}

			if (opts.pagefile) {
				wiped = wipe_pagefile (vol, byte, act);
				if (wiped < 0)
					goto umount;
				else
					total += wiped;
			}

			if (opts.unused) {
				wiped = wipe_unused (vol, byte, act);
				if (wiped < 0)
					goto umount;
				else
					total += wiped;
			}

			if (act == act_info)
				break;
		}

		printf ("%lld bytes were wiped\n", (long long)total);
	}

	if (ntfs_volume_set_flags (vol, VOLUME_IS_DIRTY) < 0) {
		Eprintf ("Couldn't mark volume dirty\n");
	}

	result = 0;
umount:
	ntfs_umount (vol, FALSE);
free:
	if (opts.bytes)
		free (opts.bytes);
	return result;
}

