/**
 * ntfsresize - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002-2003 Szabolcs Szakacsits
 * Copyright (c) 2002-2003 Anton Altaparmakov
 * Copyright (c) 2002-2003 Richard Russon
 *
 * This utility will resize an NTFS volume.
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "debug.h"
#include "types.h"
#include "support.h"
#include "endians.h"
#include "bootsect.h"
#include "disk_io.h"
#include "attrib.h"
#include "volume.h"
#include "mft.h"
#include "bitmap.h"
#include "inode.h"
#include "runlist.h"
#include "utils.h"

static const char *EXEC_NAME = "ntfsresize";

static const char *resize_warning_msg =
"WARNING: Every sanity check passed and only the DANGEROUS operations left.\n"
"Please make sure all your important data had been backed up in case of an\n"
"unexpected failure!\n";

static const char *resize_important_msg =
"You can go on to shrink the device e.g. with 'fdisk'.\n"
"IMPORTANT: When recreating the partition, make sure you\n"
"  1)  create it with the same starting disk cylinder\n"
"  2)  create it with the same partition type (usually 7, HPFS/NTFS)\n"
"  3)  do not make it smaller than the new NTFS filesystem size\n"
"  4)  set the bootable flag for the partition if it existed before\n"
"Otherwise you may lose your data or can't boot your computer from the disk!\n";

static const char *fragmented_volume_msg =
"The volume end is fragmented, this case is not yet supported. Defragment it\n"
"(Windows 2000, XP and .NET have built in defragmentation tool) and try again.\n";

struct {
	int verbose;
	int quiet;
	int debug;
	int ro_flag;
	int force;
	int info;
	s64 bytes;
	char *volume;
} opt;

struct bitmap {
	u8 *bm;
	s64 size;
};

struct progress_bar {
	u64 start;
	u64 stop;
	int resolution;
	float unit;
};

struct __ntfs_resize_t {
	s64 new_volume_size;
	ntfs_inode *ni;			/* inode being processed */
	MFT_RECORD *mrec;		/* MFT buffer being processed */
	ntfs_attr_search_ctx *ctx;	/* inode attribute being processed */
	u64 relocations;		/* num of clusters to relocate */
	u64 inuse;			/* num of clusters in use */
	int multi_ref;			/* num of clusters ref'd many times */
};

typedef struct __ntfs_resize_t ntfs_resize_t;

ntfs_volume *vol = NULL;
struct bitmap lcn_bitmap;

#define NTFS_MBYTE (1000 * 1000)

#define ERR_PREFIX   "ERROR"
#define PERR_PREFIX  ERR_PREFIX "(%d): "
#define NERR_PREFIX  ERR_PREFIX ": "

#define rounded_up_division(a, b) (((a) + (b - 1)) / (b))

GEN_PRINTF (Eprintf, stderr, NULL,         FALSE)
GEN_PRINTF (Vprintf, stdout, &opt.verbose, TRUE)
GEN_PRINTF (Qprintf, stdout, &opt.quiet,   FALSE)

/**
 * perr_printf
 *
 * Print an error message.
 */
void perr_printf(const char *fmt, ...)
{
	va_list ap;
	int eo = errno;

	fprintf(stdout, PERR_PREFIX, eo);
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	printf(": %s\n", strerror(eo));
	fflush(stdout);
	fflush(stderr);
}

/**
 * err_exit
 *
 * Print and error message and exit the program.
 */
int err_exit(const char *fmt, ...)
{
	va_list ap;

	fprintf(stdout, NERR_PREFIX);
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fflush(stdout);
	fflush(stderr);
	exit(1);
}

/**
 * perr_exit
 *
 * Print and error message and exit the program
 */
int perr_exit(const char *fmt, ...)
{
	va_list ap;
	int eo = errno;

	fprintf(stdout, PERR_PREFIX, eo);
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	printf(": %s\n", strerror(eo));
	fflush(stdout);
	fflush(stderr);
	exit(1);
}

/**
 * usage - Print a list of the parameters to the program
 *
 * Print a list of the parameters and options for the program.
 *
 * Return:  none
 */
void usage()
{

	printf ("\nUsage: %s [options] device\n"
		"    Resize an NTFS volume non-destructively.\n"
		"\n"
		"    -i      --info       Calculate the smallest shrunken size supported\n"
		"    -s num  --size num   Resize volume to num[k|M|G] bytes\n"
		"\n"
		"    -n      --no-action  Do not write to disk\n"
		"    -f      --force      Force to progress (DANGEROUS)\n"
	/*	"    -q      --quiet      Less output\n"*/
	/*	"    -v      --verbose    More output\n"*/
		"    -V      --version    Display version information\n"
		"    -h      --help       Display this help\n"
#ifdef DEBUG
		"    -d      --debug      Show debug information\n"
#endif
		"\n"
		"    The options -i and -s are mutually exclusive. If both options are\n"
		"    omitted then the NTFS volume will be enlarged to the device size.\n"
		"\n", EXEC_NAME);
	printf ("%s%s\n", ntfs_bugs, ntfs_home);
	exit(1);
}

/**
 * proceed_question
 *
 * Force the user to confirm an action before performing it.
 * Copy-paste from e2fsprogs
 */
void proceed_question(void)
{
	char buf[256];
	const char *short_yes = "yY";

	fflush(stdout);
	fflush(stderr);
	printf("Are you sure you want to proceed (y/[n])? ");
	buf[0] = 0;
	fgets(buf, sizeof(buf), stdin);
	if (strchr(short_yes, buf[0]) == 0) {
		printf("OK quitting. NO CHANGES have been made to your "
				"NTFS volume.\n");
		exit(1);
	}
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
	printf ("\nResize an NTFS Volume, without data loss.\n\n");
	printf ("Copyright (c)\n");
	printf ("    2002-2003 Szabolcs Szakacsits\n");
	printf ("    2002-2003 Anton Altaparmakov\n");
	printf ("    2002-2003 Richard Russon\n");
	printf ("\n%s\n%s%s\n", ntfs_gpl, ntfs_bugs, ntfs_home);
}

/**
 * get_new_volume_size
 *
 * Convert a user-supplied string into a size.  Without any suffix the number
 * will be assumed to be in bytes.  If the number has a suffix of k, M or G it
 * will be scaled up by 1000, 1000000, or 1000000000.
 */
s64 get_new_volume_size(char *s)
{
	s64 size;
	char *suffix;
	int prefix_kind = 1000;

	size = strtoll(s, &suffix, 10);
	if (size <= 0 || errno == ERANGE)
		err_exit("Illegal new volume size\n");

	if (!*suffix)
		return size;

	if (strlen(suffix) == 2 && suffix[1] == 'i')
		prefix_kind = 1024;
	else if (strlen(suffix) > 1)
		usage();

	/* We follow the SI prefixes:
	   http://physics.nist.gov/cuu/Units/prefixes.html
	   http://physics.nist.gov/cuu/Units/binary.html
	   Disk partitioning tools use prefixes as,
	                       k        M          G
	   old fdisk         2^10     2^20      10^3*2^20
	   recent fdisk     10^3     10^6       10^9
	   cfdisk           10^3     10^6       10^9
	   sfdisk            2^10     2^20
	   parted            2^10     2^20  (may change)
	   fdisk (DOS)       2^10     2^20
	*/
	/* FIXME: check for overflow */
	switch (*suffix) {
	case 'G':
		size *= prefix_kind;
	case 'M':
		size *= prefix_kind;
	case 'k':
		size *= prefix_kind;
		break;
	default:
		usage();
	}

	return size;
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
int parse_options(int argc, char **argv)
{
	static const char *sopt = "-dfhins:vV";
	static const struct option lopt[] = {
#ifdef DEBUG
		{ "debug",	no_argument,		NULL, 'd' },
#endif
		{ "force",	no_argument,		NULL, 'f' },
		{ "help",	no_argument,		NULL, 'h' },
		{ "info",	no_argument,		NULL, 'i' },
		{ "no-action",	no_argument,		NULL, 'n' },
	/*	{ "quiet",	no_argument,		NULL, 'q' },*/
		{ "size",	required_argument,	NULL, 's' },
	/*	{ "verbose",	no_argument,		NULL, 'v' },*/
		{ "version",	no_argument,		NULL, 'V' },
		{ NULL, 0, NULL, 0 }
	};

	char c;
	int err  = 0;
	int ver  = 0;
	int help = 0;

	memset(&opt, 0, sizeof(opt));

	while ((c = getopt_long (argc, argv, sopt, lopt, NULL)) != -1) {
		switch (c) {
		case 1:	/* A non-option argument */
			if (!err && !opt.volume)
				opt.volume = argv[optind-1];
			else
				err++;
			break;
		case 'd':
			opt.debug++;
			break;
		case 'f':
			opt.force++;
			break;
		case 'h':
		case '?':
			help++;
			break;
		case 'i':
			opt.info++;
			break;
		case 'n':
			opt.ro_flag = MS_RDONLY;
			break;
		case 'q':
			opt.quiet++;
			break;
		case 's':
			if (!err && (opt.bytes == 0))
				opt.bytes = get_new_volume_size(optarg);
			else
				err++;
			break;
		case 'v':
			opt.verbose++;
			break;
		case 'V':
			ver++;
			break;
		default:
			if (optopt == 's') {
				Eprintf ("Option '%s' requires an argument.\n", argv[optind-1]);
			} else {
				Eprintf ("Unknown option '%s'.\n", argv[optind-1]);
			}
			err++;
			break;
		}
	}

	if (help || ver) {
		opt.quiet = 0;
	} else {
		if (opt.volume == NULL) {
			if (argc > 1)
				Eprintf ("You must specify exactly one device.\n");
			err++;
		}

		/*
		if (opt.quiet && opt.verbose) {
			Eprintf ("You may not use --quiet and --verbose at the same time.\n");
			err++;
		}
		*/

		if (opt.info) {
			opt.ro_flag = MS_RDONLY;
			if (opt.bytes > 0) {
				Eprintf (NERR_PREFIX "Options --info and --size"
					" can't be used together.\n");
				err++;
			}
		}
	}

	stderr = stdout;

#ifdef DEBUG
	if (!opt.debug)
		if (!(stderr = fopen("/dev/null", "rw")))
			perr_exit("Couldn't open /dev/null");
#endif

	if (ver)
		version();
	if (help || err)
		usage();

	return (!err && !help && !ver);
}

/**
 * runlist_extent_number
 *
 * Count the runs in a runlist.
 */
int runlist_extent_number(runlist *rl)
{
	int i;

	for (i = 0; rl[i].length; i++)
		;

	return i;
}

/**
 * nr_clusters_to_bitmap_byte_size
 *
 * Take the number of clusters in the volume and calculate the size of $Bitmap.
 * The size will always be a multiple of 8 bytes.
 */
s64 nr_clusters_to_bitmap_byte_size(s64 nr_clusters)
{
	s64 bm_bsize;

	bm_bsize = rounded_up_division(nr_clusters, 8);

	bm_bsize = (bm_bsize + 7) & ~7;
	Dprintf("Bitmap byte size  : %lld (%lld clusters)\n",
	       bm_bsize, rounded_up_division(bm_bsize, vol->cluster_size));

	return bm_bsize;
}

/**
 * build_lcn_usage_bitmap
 *
 * lcn_bitmap has one bit for each cluster on the disk.  Initially, lcn_bitmap
 * has no bits set.  As each attribute record is read the bits in lcn_bitmap are
 * checked to ensure that no other file already references that cluster.
 *
 * This serves as a rudimentary "chkdsk" operation.
 */
void build_lcn_usage_bitmap(ntfs_resize_t *resize)
{
	s64 new_volume_size, inode;
	ATTR_RECORD *a;
	runlist *rl;
	int i, j;//, runs;

	a = resize->ctx->attr;
	new_volume_size = resize->new_volume_size;
	inode = resize->ni->mft_no;

	if (!a->non_resident)
		return;

	if (!(rl = ntfs_mapping_pairs_decompress(vol, a, NULL)))
		perr_exit("ntfs_decompress_mapping_pairs");

	//runs = runlist_extent_number(rl);

	for (i = 0; rl[i].length; i++) {
		s64 lcn = rl[i].lcn;
		s64 lcn_length = rl[i].length;

		if (lcn == LCN_HOLE || lcn == LCN_RL_NOT_MAPPED)
			continue;

		/* FIXME: ntfs_mapping_pairs_decompress should return error */
		if (lcn < 0 || lcn_length <= 0)
			err_exit("Corrupt runlist in inode %lld attr %x LCN "
				 "%llx length %llx\n", inode,
				 le32_to_cpu (a->type), lcn, lcn_length);

		for (j = 0; j < lcn_length; j++) {
			u64 k = (u64)lcn + j;
			if (ntfs_bit_get_and_set(lcn_bitmap.bm, k, 1)) {
				
				if (++resize->multi_ref > 10)
					continue;
				
				printf("Cluster %Lu (0x%Lx) referenced "
				       "multiply times!\n", k, k);
			}
		}

		resize->inuse += lcn_length;

		if (opt.info)
			continue;

		if (lcn + (lcn_length - 1) > new_volume_size) {

			s64 start = lcn;
			s64 len = lcn_length;

			if (start <= new_volume_size) {
				start = new_volume_size + 1;
				len = lcn_length - (start - lcn);
			}

			resize->relocations += len;
		}
	}
	free(rl);
}

/**
 * walk_attributes
 *
 * For a given MFT Record, iterate through all its attributes.  Any non-resident
 * data runs will be marked in lcn_bitmap.
 */
void walk_attributes(ntfs_resize_t *resize)
{
	ntfs_attr_search_ctx *ctx;

	if (!(ctx = ntfs_attr_get_search_ctx(resize->ni, NULL)))
		perr_exit("ntfs_get_attr_search_ctx");

	while (!ntfs_attrs_walk(ctx)) {
		if (ctx->attr->type == AT_END)
			break;
		resize->ctx = ctx;
		build_lcn_usage_bitmap(resize);
	}

	ntfs_attr_put_search_ctx(ctx);
}

/**
 * compare_bitmaps
 *
 * Compare two bitmaps.  In this case, $Bitmap as read from the disk and
 * lcn_bitmap which we built from the MFT Records.
 */
void compare_bitmaps(struct bitmap *a)
{
	s64 i, count;
	int k, mismatch = 0;
	char bit;
	u8 bm[NTFS_BUF_SIZE];

	printf("Accounting clusters ...\n");

	i = 0;
	while (1) {
		count = ntfs_attr_pread(vol->lcnbmp_na, i, NTFS_BUF_SIZE, bm);
		if (count == -1)
			perr_exit("Couldn't get $Bitmap $DATA");

		if (count == 0) {
			if (a->size != i)
				err_exit("$Bitmap file size doesn't match "
					 "calculated size ((%Ld != %Ld)\n",
					 a->size, i);
			break;
		}

		for (k = 0; k < count; k++) {
			u64 j, start;

			if (a->bm[i + k] == bm[k])
				continue;

			start = (i + k) * 8;
			for (j = start; j < start + 8; j++) {

				bit = ntfs_bit_get(a->bm, j);
				if (bit == ntfs_bit_get(bm, k + j % 8))
					continue;

				if (++mismatch > 10)
					continue;

				printf("Cluster accounting failed at %llu "
				       "(0x%Lx): %s cluster in $Bitmap\n",
				       j, j, bit ? "missing" : "extra");
			}
		}

		i += count;
	}

	if (mismatch) {
		printf("Totally %d cluster accounting mismatches.\n", 
		       mismatch);
		err_exit("Filesystem check failed! Windows wasn't shutdown "
			 "properly or inconsistent\nfilesystem. Please run "
			 "chkdsk on Windows.\n");
	}
}

/**
 * progress_init
 *
 * Create and scale our progress bar.
 */
void progress_init(struct progress_bar *p, u64 start, u64 stop, int res)
{
	p->start = start;
	p->stop = stop;
	p->unit = 100.0 / (stop - start);
	p->resolution = res;
}

/**
 * progress_update
 *
 * Update the progress bar and tell the user.
 */
void progress_update(struct progress_bar *p, u64 current)
{
	float percent = p->unit * current;

	if (current != p->stop) {
		if ((current - p->start) % p->resolution)
			return;
		printf("%6.2f percent completed\r", percent);
	} else
		printf("100.00 percent completed\n");
	fflush(stdout);
}

/**
 * walk_inodes
 *
 * Read each record in the MFT, skipping the unused ones, and build up a bitmap
 * from all the non-resident attributes.
 */
void walk_inodes(ntfs_resize_t *resize)
{
	s64 inode = 0;
	s64 last_mft_rec;
	ntfs_inode *ni;
	struct progress_bar progress;

	printf("Checking filesystem consistency ...\n");

	last_mft_rec = vol->nr_mft_records - 1;
	progress_init(&progress, inode, last_mft_rec, 100);

	for (; inode <= last_mft_rec; inode++) {
		progress_update(&progress, inode);

		if ((ni = ntfs_inode_open(vol, (MFT_REF)inode)) == NULL) {
			/* FIXME: continue only if it make sense, e.g.
			   MFT record not in use based on $MFT bitmap */
			if (errno == EIO || errno == ENOENT)
				continue;
			perr_exit("Reading inode %lld failed", inode);
		}

		if (!(ni->mrec->flags & MFT_RECORD_IN_USE))
			continue;

		if ((ni->mrec->base_mft_record) != 0)
			continue;

		resize->ni = ni;
		resize->mrec = ni->mrec;
		walk_attributes(resize);

		if (ntfs_inode_close(ni))
			perr_exit("ntfs_inode_close for inode %lld", inode);
	}
}

/**
 * advise_on_resize
 *
 * The metadata file $Bitmap has one bit for each cluster on disk.  This has
 * already been read into lcn_bitmap.  By looking for the last used cluster on
 * the disk, we can work out by how much we can shrink the volume.
 */
void advise_on_resize()
{
	s64 i, old_b, new_b, g_b, old_mb, new_mb, g_mb;
	int fragmanted_end;

	printf("Calculating smallest shrunken size supported ...\n");

	for (i = vol->nr_clusters - 1; i > 0 && (i % 8); i--)
		if (ntfs_bit_get(lcn_bitmap.bm, i))
			goto found_used_cluster;

	if (i > 0) {
		if (ntfs_bit_get(lcn_bitmap.bm, i))
			goto found_used_cluster;
	} else
		goto found_used_cluster;

	for (i -=  8; i >= 0; i -= 8)
		if (lcn_bitmap.bm[i / 8])
			break;

	for (i += 7; i > 0; i--)
		if (ntfs_bit_get(lcn_bitmap.bm, i))
			break;

found_used_cluster:
	i += 2; /* first free + we reserve one for the backup boot sector */
	fragmanted_end = (i >= vol->nr_clusters) ? 1 : 0;

	if (fragmanted_end || !opt.info) {
		printf(fragmented_volume_msg);
		if (fragmanted_end)
			return;
		printf("Now ");
	}

	old_b = vol->nr_clusters * vol->cluster_size;
	old_mb = rounded_up_division(old_b, NTFS_MBYTE);
	new_b = i * vol->cluster_size;
	new_mb = rounded_up_division(new_b, NTFS_MBYTE);
	g_b = (vol->nr_clusters - i) * vol->cluster_size;
	g_mb = g_b / NTFS_MBYTE;

	printf("You could resize at %lld bytes ", new_b);

	if ((new_mb * NTFS_MBYTE) < old_b)
		printf("or %lld MB ", new_mb);

	printf("(freeing ");

	if (g_mb && (old_mb - new_mb))
	    printf("%lld MB", old_mb - new_mb);
	else
	    printf("%lld bytes", g_b);

	printf(").\n");
}

/**
 * look_for_bad_sector
 *
 * Read through the metadata file $BadClus looking for bad sectors on the disk.
 */
void look_for_bad_sector(ATTR_RECORD *a)
{
	runlist *rl;
	int i;

	rl = ntfs_mapping_pairs_decompress(vol, a, NULL);
	if (!rl)
		perr_exit("ntfs_mapping_pairs_decompress");

	for (i = 0; rl[i].length; i++)
		if (rl[i].lcn != LCN_HOLE)
			err_exit("Device has bad sectors, not supported\n");

	free(rl);
}

/**
 * rl_set
 *
 * Helper to set up a runlist object
 */
void rl_set(runlist *rl, VCN vcn, LCN lcn, s64 len)
{
	rl->vcn = vcn;
	rl->lcn = lcn;
	rl->length = len;
}

/**
 * bitmap_file_data_fixup
 *
 * $Bitmap can overlap the end of the volume. Any bits in this region
 * must be set. This region also encompasses the backup boot sector.
 */
void bitmap_file_data_fixup(s64 cluster, struct bitmap *bm)
{
	for (; cluster < bm->size << 3; cluster++)
		ntfs_bit_set(bm->bm, (u64)cluster, 1);
}

/**
 * truncate_badclust_bad_attr
 *
 * The metadata file $BadClus needs to be shrunk.
 *
 * FIXME: this function should go away and instead using a generalized
 * "truncate_bitmap_data_attr()"
 */
void truncate_badclust_bad_attr(ATTR_RECORD *a, s64 nr_clusters)
{
	runlist *rl_bad;
	int mp_size;
	char *mp;

	if (!a->non_resident)
		/* FIXME: handle resident attribute value */
		perr_exit("Resident attribute in $BadClust not supported!");

	if (!(rl_bad = (runlist *)malloc(2 * sizeof(runlist))))
		perr_exit("Couldn't get memory");

	rl_set(rl_bad, 0LL, (LCN)LCN_HOLE, nr_clusters);
	rl_set(rl_bad + 1, nr_clusters, -1LL, 0LL);

	if ((mp_size = ntfs_get_size_for_mapping_pairs(vol, rl_bad)) == -1)
		perr_exit("ntfs_get_size_for_mapping_pairs");

	if (mp_size > le32_to_cpu (a->length) -
			le16_to_cpu (a->mapping_pairs_offset))
		err_exit("Enlarging attribute header isn't supported yet.\n");

	if (!(mp = (char *)calloc(1, mp_size)))
		perr_exit("Couldn't get memory");

	if (ntfs_mapping_pairs_build(vol, mp, mp_size, rl_bad))
		perr_exit("ntfs_mapping_pairs_build");

	memcpy((char *)a + le16_to_cpu (a->mapping_pairs_offset), mp, mp_size);
	a->highest_vcn = cpu_to_le64(nr_clusters - 1LL);
	a->allocated_size = cpu_to_le64(nr_clusters * vol->cluster_size);
	a->data_size = cpu_to_le64(nr_clusters * vol->cluster_size);

	free(rl_bad);
	free(mp);
}

/**
 * shrink_bitmap_data_attr
 *
 * Shrink the metadata file $Bitmap.  It must be large enough for one bit per
 * cluster of the shrunken volume.  Also it must be a of 8 bytes in size.
 */
void shrink_bitmap_data_attr(runlist **rlist, s64 nr_bm_clusters, s64 new_size)
{
	runlist *rl = *rlist;
	int i, j;
	u64 k;
	int trunc_at = -1;	/* FIXME: -1 means unset */

	/* Unallocate truncated clusters in $Bitmap */
	for (i = 0; rl[i].length; i++) {
		if (rl[i].vcn + rl[i].length <= nr_bm_clusters)
			continue;
		if (trunc_at == -1)
			trunc_at = i;
		if (rl[i].lcn == LCN_HOLE || rl[i].lcn == LCN_RL_NOT_MAPPED)
			continue;
		for (j = 0; j < rl[i].length; j++) {
			if (rl[i].vcn + j < nr_bm_clusters)
				continue;

			k = (u64)rl[i].lcn + j;
			if (k < new_size) {
				ntfs_bit_set(lcn_bitmap.bm, k, 0);
				Dprintf("Unallocate cluster: "
				       "%llu (%llx)\n", k, k);
			}
		}
	}

	if (trunc_at != -1) {
		/* NOTE: 'i' always > 0 */
		i = nr_bm_clusters - rl[trunc_at].vcn;
		rl[trunc_at].length = i;
		rl_set(rl + trunc_at + 1, nr_bm_clusters, -1LL, 0LL);

		Dprintf("Runlist truncated at index %d, "
				"new cluster length %d\n", trunc_at, i);
	}
}

/**
 * enlarge_bitmap_data_attr
 *
 * Enlarge the metadata file $Bitmap.  It must be large enough for one bit per
 * cluster of the shrunken volume.  Also it must be a of 8 bytes in size.
 */
void enlarge_bitmap_data_attr(runlist **rlist, s64 nr_bm_clusters, s64 new_size)
{
	runlist *rl = *rlist;
	s64 i, j, free_zone = 0;

	for (i = 0; rl[i].length; i++)
		for (j = 0; j < rl[i].length; j++)
			ntfs_bit_set(lcn_bitmap.bm, rl[i].lcn + j, 0);
	free(rl);

	if (!(rl = *rlist = (runlist *)malloc(2 * sizeof(runlist))))
		perr_exit("Couldn't get memory");

	for (i = vol->nr_clusters; i < new_size; i++)
		ntfs_bit_set(lcn_bitmap.bm, i, 0);

	for (i = 0; i < new_size; i++) {
		if (!ntfs_bit_get(lcn_bitmap.bm, i)) {
			if (++free_zone == nr_bm_clusters)
				break;
		} else
			free_zone = 0;
	}

	if (free_zone != nr_bm_clusters)
		err_exit("Couldn't allocate $Bitmap clusters.\n");

	for (; free_zone; free_zone--, i--)
		ntfs_bit_set(lcn_bitmap.bm, i, 1);

	rl_set(rl, 0LL, i + 1, nr_bm_clusters);
	rl_set(rl + 1, nr_bm_clusters, -1LL, 0LL);
}

/**
 * truncate_bitmap_data_attr
 */
void truncate_bitmap_data_attr(ATTR_RECORD *a, s64 nr_clusters)
{
	runlist *rl;
	s64 bm_bsize, size;
	s64 nr_bm_clusters;
	int mp_size;
	char *mp;
	u8 *tmp;

	if (!a->non_resident)
		/* FIXME: handle resident attribute value */
		perr_exit("Resident data attribute in $Bitmap not supported!");

	bm_bsize = nr_clusters_to_bitmap_byte_size(nr_clusters);
	nr_bm_clusters = rounded_up_division(bm_bsize, vol->cluster_size);

	if (!(tmp = (u8 *)realloc(lcn_bitmap.bm, bm_bsize)))
		perr_exit("realloc");
	lcn_bitmap.bm = tmp;
	lcn_bitmap.size = bm_bsize;
	bitmap_file_data_fixup(nr_clusters, &lcn_bitmap);

	if (!(rl = ntfs_mapping_pairs_decompress(vol, a, NULL)))
		perr_exit("ntfs_mapping_pairs_decompress");

	if (nr_clusters < vol->nr_clusters)
		shrink_bitmap_data_attr(&rl, nr_bm_clusters, nr_clusters);
	else
		enlarge_bitmap_data_attr(&rl, nr_bm_clusters, nr_clusters);

	if ((mp_size = ntfs_get_size_for_mapping_pairs(vol, rl)) == -1)
		perr_exit("ntfs_get_size_for_mapping_pairs");

	if (mp_size > le32_to_cpu (a->length) -
			le16_to_cpu (a->mapping_pairs_offset))
		err_exit("Enlarging attribute header isn't supported yet.\n");

	if (!(mp = (char *)calloc(1, mp_size)))
		perr_exit("Couldn't get memory");

	if (ntfs_mapping_pairs_build(vol, mp, mp_size, rl))
		perr_exit("ntfs_mapping_pairs_build");

	memcpy((char *)a + le16_to_cpu (a->mapping_pairs_offset), mp, mp_size);
	a->highest_vcn = cpu_to_le64(nr_bm_clusters - 1LL);
	a->allocated_size = cpu_to_le64(nr_bm_clusters * vol->cluster_size);
	a->data_size = cpu_to_le64(bm_bsize);
	a->initialized_size = cpu_to_le64(bm_bsize);

	/*
	 * FIXME: update allocated/data sizes and timestamps in $FILE_NAME
	 * attribute too, for now chkdsk will do this for us.
	 */

	size = ntfs_rl_pwrite(vol, rl, 0, bm_bsize, lcn_bitmap.bm);
	if (bm_bsize != size) {
		if (size == -1)
			perr_exit("Couldn't write $Bitmap");
		printf("Couldn't write full $Bitmap file "
		       "(%lld from %lld)\n", size, bm_bsize);
		exit(1);
	}

	free(rl);
	free(mp);
}

/**
 * lookup_data_attr
 *
 * Find the $DATA attribute (with or without a name) for the given MFT reference
 * (inode number).
 */
void lookup_data_attr(MFT_REF mref, char *aname, ntfs_attr_search_ctx **ctx)
{
	ntfs_inode *ni;
	uchar_t *ustr = NULL;
	int len = 0;

	if (!(ni = ntfs_inode_open(vol, mref)))
		perr_exit("ntfs_open_inode");

	if (NInoAttrList(ni))
		perr_exit("Attribute list attribute not yet supported");

	if (!(*ctx = ntfs_attr_get_search_ctx(ni, NULL)))
		perr_exit("ntfs_get_attr_search_ctx");

	if (aname && ((len = ntfs_mbstoucs(aname, &ustr, 0)) == -1))
		perr_exit("Unable to convert string to Unicode");

	if (!ustr || !len) {
		ustr = AT_UNNAMED;
		len = 0;
	}

	if (ntfs_attr_lookup(AT_DATA, ustr, len, 0, 0, NULL, 0, *ctx))
		perr_exit("ntfs_lookup_attr");

	if (ustr != AT_UNNAMED)
		free(ustr);
}

/**
 * write_mft_record
 *
 * Write an MFT Record back to the disk.  If the read-only command line option
 * was given, this function will do nothing.
 */
int write_mft_record(ntfs_attr_search_ctx *ctx)
{
	if (ntfs_mft_record_write(vol, ctx->ntfs_ino->mft_no, ctx->mrec))
		perr_exit("ntfs_mft_record_write");

	if (fdatasync(vol->fd) == -1)
		perr_exit("Failed to sync device");

	return 0;
}

/**
 * truncate_badclust_file
 *
 * Shrink the $BadClus file to match the new volume size.
 */
void truncate_badclust_file(s64 nr_clusters)
{
	ntfs_attr_search_ctx *ctx = NULL;

	printf("Updating $BadClust file ...\n");

	lookup_data_attr((MFT_REF)FILE_BadClus, "$Bad", &ctx);
	look_for_bad_sector(ctx->attr);
	/* FIXME: sanity_check_attr(ctx->attr); */
	truncate_badclust_bad_attr(ctx->attr, nr_clusters);

	if (write_mft_record(ctx))
		perr_exit("Couldn't update $BadClust");

	ntfs_attr_put_search_ctx(ctx);
}

/**
 * truncate_bitmap_file
 *
 * Shrink the $Bitmap file to match the new volume size.
 */
void truncate_bitmap_file(s64 nr_clusters)
{
	ntfs_attr_search_ctx *ctx = NULL;

	printf("Updating $Bitmap file ...\n");

	lookup_data_attr((MFT_REF)FILE_Bitmap, NULL, &ctx);
	/* FIXME: sanity_check_attr(ctx->attr); */
	truncate_bitmap_data_attr(ctx->attr, nr_clusters);

	if (write_mft_record(ctx))
		perr_exit("Couldn't update $Bitmap");

	ntfs_attr_put_search_ctx(ctx);
}

/**
 * setup_lcn_bitmap
 *
 * Allocate a block of memory with one bit for each cluster of the disk.
 * All the bits are set to 0, except those representing the region beyond the
 * end of the disk.
 */
void setup_lcn_bitmap()
{
	/* Determine lcn bitmap byte size and allocate it. */
	lcn_bitmap.size = nr_clusters_to_bitmap_byte_size(vol->nr_clusters);

	if (!(lcn_bitmap.bm = (unsigned char *)calloc(1, lcn_bitmap.size)))
		perr_exit("Failed to allocate internal buffer");

	bitmap_file_data_fixup(vol->nr_clusters, &lcn_bitmap);
}

/**
 * update_bootsector
 *
 * FIXME: should be done using ntfs_* functions
 */
void update_bootsector(s64 nr_clusters)
{
	NTFS_BOOT_SECTOR bs;

	printf("Updating Boot record ...\n");

	if (lseek(vol->fd, 0, SEEK_SET) == (off_t)-1)
		perr_exit("lseek");

	if (read(vol->fd, &bs, sizeof(NTFS_BOOT_SECTOR)) == -1)
		perr_exit("read() error");

	bs.number_of_sectors = nr_clusters * bs.bpb.sectors_per_cluster;
	bs.number_of_sectors = cpu_to_le64(bs.number_of_sectors);

	if (lseek(vol->fd, 0, SEEK_SET) == (off_t)-1)
		perr_exit("lseek");

	if (!opt.ro_flag)
		if (write(vol->fd, &bs, sizeof(NTFS_BOOT_SECTOR)) == -1)
			perr_exit("write() error");
}

/**
 * volume_size
 */
s64 volume_size(ntfs_volume *vol, s64 nr_clusters)
{
	return nr_clusters * vol->cluster_size;
}

/**
 * print_volume_size
 *
 * Print the volume size in bytes and decimal megabytes.
 */
void print_volume_size(char *str, s64 bytes)
{
	printf("%s: %lld bytes (%lld MB)\n",
	       str, bytes, rounded_up_division(bytes, NTFS_MBYTE));
}

/**
 * print_disk_usage
 *
 * Display the amount of disk space in use.
 */
void print_disk_usage(ntfs_resize_t *resize)
{
	s64 total, used, free, relocations;

	total = vol->nr_clusters * vol->cluster_size;
	used = resize->inuse * vol->cluster_size;
	free = total - used;
	relocations = resize->relocations * vol->cluster_size;

	printf("Space in use       : %lld MB (%.1f%%)   ",
	       rounded_up_division(used, NTFS_MBYTE),
	       100.0 * ((float)used / total));

	printf("\n");
}

/**
 * mount_volume
 *
 * First perform some checks to determine if the volume is already mounted, or
 * is dirty (Windows wasn't shutdown properly).  If everything is OK, then mount
 * the volume (load the metadata into memory).
 */
void mount_volume()
{
	unsigned long mntflag;

	if (ntfs_check_if_mounted(opt.volume, &mntflag))
		perr_exit("Failed to check '%s' mount state", opt.volume);

	if (mntflag & NTFS_MF_MOUNTED) {
		if (!(mntflag & NTFS_MF_READONLY))
			err_exit("Device %s is mounted read-write. "
				 "You must 'umount' it first.\n", opt.volume);
		if (!opt.ro_flag)
			err_exit("Device %s is mounted. "
				 "You must 'umount' it first.\n", opt.volume);
	}

	if (!(vol = ntfs_mount(opt.volume, opt.ro_flag))) {

		int err = errno;

		perr_printf("ntfs_mount failed");
		if (err == EINVAL) {
			printf("Apparently device '%s' doesn't have a "
			       "valid NTFS. Maybe you selected\nthe whole "
			       "disk instead of a partition (e.g. /dev/hda, "
			       "not /dev/hda1)?\n", opt.volume);
		}
		exit(1);
	}

	if (vol->flags & VOLUME_IS_DIRTY)
		if (opt.force-- <= 0)
			err_exit("Volume is dirty. Run chkdsk and "
				 "please try again (or see -f option).\n");

	printf("NTFS volume version: %d.%d\n", vol->major_ver, vol->minor_ver);
	if (ntfs_version_is_supported(vol))
		perr_exit("Unknown NTFS version");

	printf("Cluster size       : %u bytes\n", vol->cluster_size);
	print_volume_size("Current volume size",
			  volume_size(vol, vol->nr_clusters));
}

/**
 * prepare_volume_fixup
 *
 * Set the volume's dirty flag and wipe the filesystem journal.  When Windows
 * boots it will automatically run chkdsk to check for any problems.  If the
 * read-only command line option was given, this function will do nothing.
 */
void prepare_volume_fixup()
{
	u16 flags;

	flags = vol->flags | VOLUME_IS_DIRTY;
	if (vol->major_ver >= 2)
		flags |= VOLUME_MOUNTED_ON_NT4;

	printf("Schedule chkdsk for NTFS consistency check at Windows "
		"boot time ...\n");

	if (ntfs_volume_set_flags(vol, flags))
		perr_exit("Failed to set $Volume dirty");

	if (fdatasync(vol->fd) == -1)
		perr_exit("Failed to sync device");

	printf("Resetting $LogFile ... (this might take a while)\n");

	if (ntfs_logfile_reset(vol))
		perr_exit("Failed to reset $LogFile");

	if (fdatasync(vol->fd) == -1)
		perr_exit("Failed to sync device");
}

/**
 * main
 *
 * Start here
 */
int main(int argc, char **argv)
{
	ntfs_resize_t resize;
	s64 new_size = 0;	/* in clusters */
	s64 device_size;        /* in bytes */
	int i;

	printf("%s v%s\n", EXEC_NAME, VERSION);

	if (!parse_options (argc, argv))
		return 1;

	utils_set_locale();

	mount_volume();

	device_size = ntfs_device_size_get(vol->fd, vol->sector_size);
	device_size *= vol->sector_size;
	if (device_size <= 0)
		err_exit("Couldn't get device size (%Ld)!\n", device_size);

	print_volume_size("Current device size", device_size);

	if (device_size < vol->nr_clusters * vol->cluster_size)
		err_exit("Current NTFS volume size is bigger than the device "
			 "size (%Ld)!\nCorrupt partition table or incorrect "
			 "device partitioning?\n", device_size);

	if (opt.bytes) {
		if (device_size < opt.bytes)
			err_exit("New size can't be bigger than the "
				 "device size (%Ld bytes).\n", device_size);
	} else
		opt.bytes = device_size;

	/*
	 * Take the integer part: we don't want to make the volume bigger
	 * than requested. Later on we will also decrease this value to save
	 * room for the backup boot sector.
	 */
	new_size = opt.bytes / vol->cluster_size;

	if (!opt.info)
		print_volume_size("New volume size    ",
				  volume_size(vol, new_size));

	/* Backup boot sector at the end of device isn't counted in NTFS
	   volume size thus we have to reserve space for. We don't trust
	   the user does this for us: better to be on the safe side ;) */
	if (new_size)
		--new_size;

	if (!opt.info && (new_size == vol->nr_clusters ||
			  (opt.bytes == device_size &&
			   new_size == vol->nr_clusters - 1))) {
		printf("Nothing to do: NTFS volume size is already OK.\n");
		exit(0);
	}

	setup_lcn_bitmap();

	memset(&resize, 0, sizeof(resize));
	resize.new_volume_size = new_size;

	walk_inodes(&resize);
	if (resize.multi_ref) {
		printf("Totally %d clusters referenced multiply times.\n", 
		       resize.multi_ref);
		err_exit("Filesystem check failed! Windows wasn't shutdown "
			 "properly or inconsistent\nfilesystem. Please run "
			 "chkdsk on Windows.\n");
	}
	compare_bitmaps(&lcn_bitmap);

	print_disk_usage(&resize);

	if (opt.info) {
		advise_on_resize();
		exit(0);
	}

	for (i = new_size; i < vol->nr_clusters; i++)
		if (ntfs_bit_get(lcn_bitmap.bm, (u64)i)) {
			/* FIXME: relocate cluster */
			advise_on_resize();
			exit(1);
		}

	if (opt.force-- <= 0 && !opt.ro_flag) {
		printf(resize_warning_msg);
		proceed_question();
	}

	prepare_volume_fixup();

	truncate_badclust_file(new_size);
	truncate_bitmap_file(new_size);
	update_bootsector(new_size);

	/* We don't create backup boot sector because we don't know where the
	   partition will be split. The scheduled chkdsk will fix it anyway */

	if (opt.ro_flag) {
		printf("The read-only test run ended successfully.\n");
		exit(0);
	}

	printf("Syncing device ...\n");
	if (fsync(vol->fd) == -1)
		perr_exit("fsync");

	printf("Successfully resized NTFS on device '%s'.\n", vol->dev_name);
	if (new_size < vol->nr_clusters)
		printf(resize_important_msg);

	return 0;
}

