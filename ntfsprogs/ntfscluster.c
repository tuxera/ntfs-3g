/**
 * ntfscluster - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002-2003 Richard Russon
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
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "ntfscluster.h"
#include "types.h"
#include "attrib.h"
#include "utils.h"
#include "volume.h"
#include "debug.h"
#include "dir.h"
#include "cluster.h"

static const char *EXEC_NAME = "ntfscluster";
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
void version (void)
{
	printf ("\n%s v%s - Find the owner of any given sector or cluster.\n\n",
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
void usage (void)
{
	printf ("\nUsage: %s [options] device\n"
		"    -i        --info           Print information about the volume (default)\n"
		"\n"
		"    -c range  --cluster range  Look for objects in this range of clusters\n"
		"    -s range  --sector range   Look for objects in this range of sectors\n"
		"    -I num    --inode num      Show information about this inode\n"
		"    -F name   --filename name  Show information about this file\n"
	/*	"    -l        --last           Find the last file on the volume\n" */
		"\n"
		"    -f        --force          Use less caution\n"
		"    -q        --quiet          Less output\n"
		"    -v        --verbose        More output\n"
		"    -V        --version        Version information\n"
		"    -h        --help           Print this help\n\n",
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
int parse_options (int argc, char **argv)
{
	static const char *sopt = "-c:F:fh?I:ilqs:vV";
	static const struct option lopt[] = {
		{ "cluster",	required_argument,	NULL, 'c' },
		{ "filename",	required_argument,	NULL, 'F' },
		{ "force",	no_argument,		NULL, 'f' },
		{ "help",	no_argument,		NULL, 'h' },
		{ "info",	no_argument,		NULL, 'i' },
		{ "inode",	required_argument,	NULL, 'I' },
		{ "last",	no_argument,		NULL, 'l' },
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
	char *end = NULL;

	opterr = 0; /* We'll handle the errors, thank you. */

	opts.action      = act_none;
	opts.range_begin = -1;
	opts.range_end   = -1;

	while ((c = getopt_long (argc, argv, sopt, lopt, NULL)) != (char)-1) {
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
			if ((opts.action == act_none) &&
			    (utils_parse_range (optarg, &opts.range_begin, &opts.range_end, FALSE)))
				opts.action = act_cluster;
			else
				opts.action = act_error;
			break;
		case 'F':
			if (opts.action == act_none) {
				opts.action = act_file;
				opts.filename = optarg;
			} else {
				opts.action = act_error;
			}
			break;
		case 'f':
			opts.force++;
			break;
		case 'h':
		case '?':
			help++;
			break;
		case 'I':
			if (opts.action == act_none) {
				opts.action = act_inode;
				opts.inode = strtol (optarg, &end, 0);
				if (end && *end)
					err++;
			} else {
				opts.action = act_error;
			}
			break;
		case 'i':
			if (opts.action == act_none)
				opts.action = act_info;
			else
				opts.action = act_error;
			break;
		case 'l':
			if (opts.action == act_none)
				opts.action = act_last;
			else
				opts.action = act_error;
			break;
		case 'q':
			opts.quiet++;
			break;
		case 's':
			if ((opts.action == act_none) &&
			    (utils_parse_range (optarg, &opts.range_begin, &opts.range_end, FALSE)))
				opts.action = act_sector;
			else
				opts.action = act_error;
			break;
		case 'v':
			opts.verbose++;
			break;
		case 'V':
			ver++;
			break;
		default:
			if ((optopt == 'c') || (optopt == 's'))
				Eprintf ("Option '%s' requires an argument.\n", argv[optind-1]);
			else
				Eprintf ("Unknown option '%s'.\n", argv[optind-1]);
			err++;
			break;
		}
	}

	if (help || ver) {
		opts.quiet = 0;
	} else {
		if (opts.action == act_none)
			opts.action = act_info;
		if (opts.action == act_info)
			opts.quiet = 0;

		if (opts.device == NULL) {
			if (argc > 1)
				Eprintf ("You must specify exactly one device.\n");
			err++;
		}

		if (opts.quiet && opts.verbose) {
			Eprintf ("You may not use --quiet and --verbose at the same time.\n");
			err++;
		}

		if (opts.action == act_error) {
			Eprintf ("You may only specify one action: --info, --cluster, --sector or --last.\n");
			err++;
		} else if (opts.range_begin > opts.range_end) {
			Eprintf ("The range must be in ascending order.\n");
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
 * info
 */
int info (ntfs_volume *vol)
{
	u64 a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u;
	int cb, sb, cps;
	u64 uc = 0, mc = 0, fc = 0;

	struct mft_search_ctx *m_ctx;
	ntfs_attr_search_ctx *a_ctx;
	runlist_element *rl;
	ATTR_RECORD *rec;
	int z;
	int inuse = 0;

	m_ctx = mft_get_search_ctx (vol);
	m_ctx->flags_search = FEMR_IN_USE | FEMR_METADATA | FEMR_BASE_RECORD | FEMR_NOT_BASE_RECORD;
	while (mft_next_record (m_ctx) == 0) {

		if (!(m_ctx->flags_match & FEMR_IN_USE))
			continue;

		inuse++;

		a_ctx = ntfs_attr_get_search_ctx (NULL, m_ctx->inode->mrec);

		while ((rec = find_attribute (AT_UNUSED, a_ctx))) {

			if (!rec->non_resident)
				continue;

			rl = ntfs_mapping_pairs_decompress (vol, rec, NULL);

			for (z = 0; rl[z].length > 0; z++)
			{
				if (rl[z].lcn >= 0) {
					if (m_ctx->flags_match & FEMR_METADATA)
						mc += rl[z].length;
					else
						uc += rl[z].length;
				}

			}

			free (rl);
		}

		ntfs_attr_put_search_ctx (a_ctx);
	}
	mft_put_search_ctx (m_ctx);

	cb  = vol->cluster_size_bits;
	sb  = vol->sector_size_bits;
	cps = cb - sb;

	fc  = vol->nr_clusters-mc-uc;
	fc  <<= cb;
	mc  <<= cb;
	uc  <<= cb;

	a = vol->sector_size;
	b = vol->cluster_size;
	c = 1 << cps;
	d = vol->nr_clusters << cb;
	e = vol->nr_clusters;
	f = vol->nr_clusters >> cps;
	g = vol->nr_mft_records;
	h = inuse;
	i = h * 100 / g;
	j = fc;
	k = fc >> sb;
	l = fc >> cb;
	m = fc * 100 / b / e;
	n = uc;
	o = uc >> sb;
	p = uc >> cb;
	q = uc * 100 / b / e;
	r = mc;
	s = mc >> sb;
	t = mc >> cb;
	u = mc * 100 / b / e;

	printf ("bytes per sector        : %llu\n", (unsigned long long)a);
	printf ("bytes per cluster       : %llu\n", (unsigned long long)b);
	printf ("sectors per cluster     : %llu\n", (unsigned long long)c);
	printf ("bytes per volume        : %llu\n", (unsigned long long)d);
	printf ("sectors per volume      : %llu\n", (unsigned long long)e);
	printf ("clusters per volume     : %llu\n", (unsigned long long)f);
	printf ("initialized mft records : %llu\n", (unsigned long long)g);
	printf ("mft records in use      : %llu\n", (unsigned long long)h);
	printf ("mft records percentage  : %llu\n", (unsigned long long)i);
	printf ("bytes of free space     : %llu\n", (unsigned long long)j);
	printf ("sectors of free space   : %llu\n", (unsigned long long)k);
	printf ("clusters of free space  : %llu\n", (unsigned long long)l);
	printf ("percentage free space   : %llu\n", (unsigned long long)m);
	printf ("bytes of user data      : %llu\n", (unsigned long long)n);
	printf ("sectors of user data    : %llu\n", (unsigned long long)o);
	printf ("clusters of user data   : %llu\n", (unsigned long long)p);
	printf ("percentage user data    : %llu\n", (unsigned long long)q);
	printf ("bytes of metadata       : %llu\n", (unsigned long long)r);
	printf ("sectors of metadata     : %llu\n", (unsigned long long)s);
	printf ("clusters of metadata    : %llu\n", (unsigned long long)t);
	printf ("percentage metadata     : %llu\n", (unsigned long long)u);

	return 0;
}

/**
 * dump_file
 */
int dump_file (ntfs_volume *vol, ntfs_inode *ino)
{
	u8 buffer[1024];
	ntfs_attr_search_ctx *ctx;
	ATTR_RECORD *rec;
	int i;
	runlist *runs;

	utils_inode_get_name (ino, buffer, sizeof (buffer));

	printf ("Dump: %s\n", buffer);

	ctx = ntfs_attr_get_search_ctx (ino, NULL);

	while ((rec = find_attribute (AT_UNUSED, ctx))) {
		printf ("    0x%02x - ", rec->type);
		if (rec->non_resident) {
			printf ("non-resident\n");
			runs = ntfs_mapping_pairs_decompress (vol, rec, NULL);
			if (runs) {
				printf ("             VCN     LCN     Length\n");
				for (i = 0; runs[i].length > 0; i++) {
					printf ("        %8lld %8lld %8lld\n",
							(long long)runs[i].vcn,
							(long long)runs[i].lcn,
							(long long)
							runs[i].length);
				}
				free (runs);
			}
		} else {
			printf ("resident\n");
		}
	}

	ntfs_attr_put_search_ctx (ctx);
	return 0;
}

/**
 * print_match
 */
int print_match (ntfs_inode *ino, ATTR_RECORD *attr, runlist_element *run, void *data)
{
	char *buffer;

	if (!ino || !attr || !run)
		return 1;

	buffer = malloc (MAX_PATH);
	if (!buffer) {
		Eprintf ("!buffer\n");
		return 1;
	}

	utils_inode_get_name (ino, buffer, MAX_PATH);
	printf ("Inode %llu %s", (unsigned long long)ino->mft_no, buffer);

	utils_attr_get_name (ino->vol, attr, buffer, MAX_PATH);
	printf ("/%s\n", buffer);

	free (buffer);
	return 0;
}

/**
 * find_last
 */
int find_last (ntfs_inode *ino, ATTR_RECORD *attr, runlist_element *run, void *data)
{
	struct match *m;

	if (!ino || !attr || !run || !data)
		return 1;

	m = data;

	if ((run->lcn + run->length) > m->lcn) {
		m->inum = ino->mft_no;
		m->lcn  = run->lcn + run->length;
	}

	return 0;
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
	ntfs_inode *ino = NULL;
	struct match m;
	int result = 1;

	if (!parse_options (argc, argv))
		return 1;

	utils_set_locale();

	vol = utils_mount_volume (opts.device, MS_RDONLY, opts.force);
	if (!vol)
		return 1;

	switch (opts.action) {
		case act_sector:
			if (opts.range_begin == opts.range_end)
				Qprintf ("Searching for sector %llu\n",
						(unsigned long long)opts.range_begin);
			else
				Qprintf ("Searching for sector range %llu-%llu\n", (unsigned long long)opts.range_begin, (unsigned long long)opts.range_end);
			/* Convert to clusters */
			opts.range_begin >>= (vol->cluster_size_bits - vol->sector_size_bits);
			opts.range_end   >>= (vol->cluster_size_bits - vol->sector_size_bits);
			result = cluster_find (vol, opts.range_begin, opts.range_end, (cluster_cb*)&print_match, NULL);
			break;
		case act_cluster:
			if (opts.range_begin == opts.range_end)
				Qprintf ("Searching for cluster %llu\n",
						(unsigned long long)opts.range_begin);
			else
				Qprintf ("Searching for cluster range %llu-%llu\n", (unsigned long long)opts.range_begin, (unsigned long long)opts.range_end);
			result = cluster_find (vol, opts.range_begin, opts.range_end, (cluster_cb*)&print_match, NULL);
			break;
		case act_file:
			ino = utils_pathname_to_inode (vol, NULL, opts.filename);
			if (ino)
				result = dump_file (vol, ino);
			break;
		case act_inode:
			ino = ntfs_inode_open (vol, opts.inode);
			if (ino) {
				result = dump_file (vol, ino);
				ntfs_inode_close (ino);
			} else {
				Eprintf ("Cannot open inode %llu\n",
						(unsigned long long)opts.inode);
			}
			break;
		case act_last:
			memset (&m, 0, sizeof (m));
			m.lcn = -1;
			result = cluster_find (vol, 0, LONG_MAX, (cluster_cb*)&find_last, &m);
			if (m.lcn >= 0) {
				ino = ntfs_inode_open (vol, m.inum);
				if (ino) {
					result = dump_file (vol, ino);
					ntfs_inode_close (ino);
				} else {
					Eprintf ("Cannot open inode %llu\n",
							(unsigned long long)
							opts.inode);
				}
				result = 0;
			} else {
				result = 1;
			}
			break;
		case act_info:
		default:
			result = info (vol);
			break;
	}

	ntfs_umount (vol, FALSE);
	return result;
}


