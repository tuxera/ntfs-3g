/**
 * ntfsresize - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002-2004 Szabolcs Szakacsits
 * Copyright (c) 2002-2004 Anton Altaparmakov
 * Copyright (c) 2002-2003 Richard Russon
 *
 * This utility will resize an NTFS volume without data loss.
 *
 * WARNING FOR DEVELOPERS!!! Several external tools grep for text messages
 * to control execution thus if you would like to change any message
 * then PLEASE think twice before doing so then don't modify it. Thanks!
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
#include "device.h"
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

static const char *invalid_ntfs_msg =
"Apparently device '%s' doesn't have a valid NTFS.\n"
"Maybe you selected the wrong partition? Or the whole disk instead of a\n"
"partition (e.g. /dev/hda, not /dev/hda1)? This error might also occur\n"
"if the disk was incorrectly repartitioned (see the ntfsresize FAQ).\n";

static const char *corrupt_volume_msg =
"Apparently you have a corrupted NTFS. Please run the filesystem checker\n"
"on Windows by invoking chkdsk /f. Don't forget the /f (force) parameter,\n"
"it's important! You probably also need to reboot Windows to take effect.\n"
"Then you can try ntfsresize again. No modification was made to your NTFS.\n";

struct {
	int verbose;
	int debug;
	int ro_flag;
	int force;
	int info;
	int show_progress;
	s64 bytes;
	char *volume;
	u8 padding[4];		/* Unused: padding to 64 bit. */
} opt;

struct bitmap {
	s64 size;
	u8 *bm;
	u8 padding[4];		/* Unused: padding to 64 bit. */
};

#define NTFS_PROGBAR		0x0001
#define NTFS_PROGBAR_SUPPRESS	0x0002

struct progress_bar {
	u64 start;
	u64 stop;
	int resolution;
	int flags;
	float unit;
	u8 padding[4];		/* Unused: padding to 64 bit. */
};

struct llcn_t {
	s64 lcn;	/* last used LCN for a "special" file/attr type */
	s64 inode;	/* inode using it */
};	

#define NTFSCK_PROGBAR		0x0001

typedef struct {
	ntfs_inode *ni;		     /* inode being processed */
	ntfs_attr_search_ctx *ctx;   /* inode attribute being processed */
	s64 inuse;		     /* num of clusters in use */
	int multi_ref;		     /* num of clusters referenced many times */
	int flags;
	struct bitmap lcn_bitmap;
} ntfsck_t;

typedef struct {
	ntfs_volume *vol;
	ntfs_inode *ni;		     /* inode being processed */
	s64 new_volume_size;	     /* in clusters; 0 = --info w/o --size */
	MFT_REF mref;                /* mft reference */
	MFT_RECORD *mrec;            /* mft record */
	ntfs_attr_search_ctx *ctx;   /* inode attribute being processed */
	u64 relocations;	     /* num of clusters to relocate */
	s64 inuse;		     /* num of clusters in use */
	runlist mftmir_rl;	     /* $MFTMirr AT_DATA's new position */
	s64 mftmir_old;		     /* $MFTMirr AT_DATA's old LCN */
	int dirty_inode;	     /* some inode data got relocated */
	int shrink;		     /* shrink = 1, enlarge = 0 */
	struct progress_bar progress;
	struct bitmap lcn_bitmap;
	/* Temporary statistics until all case is supported */
	struct llcn_t last_mft;
	struct llcn_t last_mftmir;
	struct llcn_t last_multi_mft;
	struct llcn_t last_sparse;
	struct llcn_t last_compressed;
	struct llcn_t last_lcn;
	s64 last_unsupp;	     /* last unsupported cluster */
} ntfs_resize_t;

/* FIXME: This, lcn_bitmap and pos from find_free_cluster() will make a cluster
   allocation related structure, attached to ntfs_resize_t */
s64 max_free_cluster_range = 0;

#define NTFS_MBYTE (1000 * 1000)

/* WARNING: don't modify the text, external tools grep for it */
#define ERR_PREFIX   "ERROR"
#define PERR_PREFIX  ERR_PREFIX "(%d): "
#define NERR_PREFIX  ERR_PREFIX ": "

#define DIRTY_NONE		(0)
#define DIRTY_INODE		(1)
#define DIRTY_ATTRIB		(2)

#define NTFS_MAX_CLUSTER_SIZE 	(65536)

GEN_PRINTF(Eprintf, stderr, NULL,         FALSE)
GEN_PRINTF(Vprintf, stdout, &opt.verbose, TRUE)
GEN_PRINTF(Qprintf, stdout, NULL,         FALSE)

static s64 rounded_up_division(s64 numer, s64 denom)
{
	return (numer + (denom - 1)) / denom;
}

/**
 * perr_printf
 *
 * Print an error message.
 */
static void perr_printf(const char *fmt, ...)
		__attribute__((format(printf, 1, 2)));
static void perr_printf(const char *fmt, ...)
{
	va_list ap;
	int eo = errno;

	fprintf(stdout, PERR_PREFIX, eo);
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fprintf(stdout, ": %s\n", strerror(eo));
	fflush(stdout);
	fflush(stderr);
}

static void err_printf(const char *fmt, ...)
		__attribute__((format(printf, 1, 2)));
static void err_printf(const char *fmt, ...)
{
	va_list ap;

	fprintf(stdout, NERR_PREFIX);
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fflush(stdout);
	fflush(stderr);
}

/**
 * err_exit
 *
 * Print and error message and exit the program.
 */
static int err_exit(const char *fmt, ...)
		__attribute__((noreturn))
		__attribute__((format(printf, 1, 2)));
static int err_exit(const char *fmt, ...)
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
static int perr_exit(const char *fmt, ...)
		__attribute__((noreturn))
		__attribute__((format(printf, 1, 2)));
static int perr_exit(const char *fmt, ...)
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
static void usage(void) __attribute__((noreturn));
static void usage(void)
{

	printf ("\nUsage: %s [options] device\n"
		"    Resize an NTFS volume non-destructively.\n"
		"\n"
		"    -i, --info             Estimate the smallest shrunken size supported\n"
		"    -s, --size SIZE        Resize volume to SIZE[k|M|G] bytes\n"
		"\n"
		"    -n, --no-action        Do not write to disk\n"
		"    -f, --force            Force to progress (DANGEROUS)\n"
		"    -P, --no-progress-bar  Don't show progress bar\n"
		"    -v, --verbose          More output\n"
		"    -V, --version          Display version information\n"
		"    -h, --help             Display this help\n"
#ifdef DEBUG
		"    -d, --debug            Show debug information\n"
#endif
		"\n"
		"    The options -i and -s are mutually exclusive. If both options are\n"
		"    omitted then the NTFS volume will be enlarged to the device size.\n"
		"\n", EXEC_NAME);
	printf ("%s%s", ntfs_bugs, ntfs_home);
	printf ("Ntfsresize FAQ: http://linux-ntfs.sourceforge.net/info/ntfsresize.html\n");
	exit(1);
}

/**
 * proceed_question
 *
 * Force the user to confirm an action before performing it.
 * Copy-paste from e2fsprogs
 */
static void proceed_question(void)
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
static void version (void)
{
	printf ("\nResize an NTFS Volume, without data loss.\n\n");
	printf ("Copyright (c) 2002-2004  Szabolcs Szakacsits\n");
	printf ("Copyright (c) 2002-2004  Anton Altaparmakov\n");
	printf ("Copyright (c) 2002-2003  Richard Russon\n");
	printf ("\n%s\n%s%s", ntfs_gpl, ntfs_bugs, ntfs_home);
}

/**
 * get_new_volume_size
 *
 * Convert a user-supplied string into a size.  Without any suffix the number
 * will be assumed to be in bytes.  If the number has a suffix of k, M or G it
 * will be scaled up by 1000, 1000000, or 1000000000.
 */
static s64 get_new_volume_size(char *s)
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
	   fdisk 2.11x-      2^10     2^20      10^3*2^20
	   fdisk 2.11y+     10^3     10^6       10^9
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
static int parse_options(int argc, char **argv)
{
	static const char *sopt = "-dfhinPs:vV";
	static const struct option lopt[] = {
#ifdef DEBUG
		{ "debug",	no_argument,		NULL, 'd' },
#endif
		{ "force",	no_argument,		NULL, 'f' },
		{ "help",	no_argument,		NULL, 'h' },
		{ "info",	no_argument,		NULL, 'i' },
		{ "no-action",	no_argument,		NULL, 'n' },
		{ "no-progress-bar", no_argument,	NULL, 'P' },
		{ "size",	required_argument,	NULL, 's' },
		{ "verbose",	no_argument,		NULL, 'v' },
		{ "version",	no_argument,		NULL, 'V' },
		{ NULL, 0, NULL, 0 }
	};

	char c;
	int err  = 0;
	int ver  = 0;
	int help = 0;

	memset(&opt, 0, sizeof(opt));
	opt.show_progress = 1;

	while ((c = getopt_long (argc, argv, sopt, lopt, NULL)) != (char)-1) {
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
		case 'P':
			opt.show_progress = 0;
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
				Eprintf("Option '%s' requires an argument.\n", argv[optind-1]);
			} else {
				Eprintf("Unknown option '%s'.\n", argv[optind-1]);
			}
			err++;
			break;
		}
	}

	if (!help && !ver) {
		if (opt.volume == NULL) {
			if (argc > 1)
				Eprintf("You must specify exactly one device.\n");
			err++;
		}
		if (opt.info) {
			opt.ro_flag = MS_RDONLY;
			if (opt.bytes) {
				Eprintf(NERR_PREFIX "Options --info and --size "
					"can't be used together.\n");
				usage();
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

static void print_advise(ntfs_volume *vol, s64 supp_lcn)
{
	s64 old_b, new_b, freed_b, old_mb, new_mb, freed_mb;
	
	old_b = vol->nr_clusters * vol->cluster_size;
	old_mb = rounded_up_division(old_b, NTFS_MBYTE);

	/* Take the next supported cluster (free or relocatable)
	   plus reserve a cluster for the backup boot sector */
	supp_lcn += 2;

	if (supp_lcn > vol->nr_clusters) {
		err_printf("Very rare fragmentation type detected. "
			   "Sorry, it's not supported yet.\n"
			   "Try to defragment your NTFS, perhaps it helps.\n");
		exit(1);
	}

	new_b = supp_lcn * vol->cluster_size;
	new_mb = rounded_up_division(new_b, NTFS_MBYTE);
	freed_b = (vol->nr_clusters - supp_lcn + 1) * vol->cluster_size;
	freed_mb = freed_b / NTFS_MBYTE;

	/* WARNING: don't modify the text, external tools grep for it */
	printf("You might resize at %lld bytes ", (long long)new_b);
	if ((new_mb * NTFS_MBYTE) < old_b)
		printf("or %lld MB ", (long long)new_mb);

	printf("(freeing ");
	if (freed_mb && (old_mb - new_mb))
	    printf("%lld MB", (long long)(old_mb - new_mb));
	else
	    printf("%lld bytes", (long long)freed_b);
	printf(").\n");
	
	printf("Please make a test run using both the -n and -s options "
	       "before real resizing!\n");
}

static void rl_set(runlist *rl, VCN vcn, LCN lcn, s64 len)
{
	rl->vcn = vcn;
	rl->lcn = lcn;
	rl->length = len;
}

static int rl_items(runlist *rl)
{
	int i = 0;
	
	while (rl[i++].length)
		;
	
	return i;
}

static void dump_run(runlist_element *r)
{
	Vprintf(" %8lld  %8lld (0x%08llx)  %lld\n", (long long)r->vcn,
			(long long)r->lcn, (long long)r->lcn,
			(long long)r->length);
}

static void dump_runlist(runlist *rl)
{
	while (rl->length)
		dump_run(rl++);
}

/**
 * nr_clusters_to_bitmap_byte_size
 *
 * Take the number of clusters in the volume and calculate the size of $Bitmap.
 * The size will always be a multiple of 8 bytes.
 */
static s64 nr_clusters_to_bitmap_byte_size(s64 nr_clusters)
{
	s64 bm_bsize;

	bm_bsize = rounded_up_division(nr_clusters, 8);
	bm_bsize = (bm_bsize + 7) & ~7;

	return bm_bsize;
}

static int str2unicode(const char *aname, ntfschar **ustr, int *len)
{
	if (aname && ((*len = ntfs_mbstoucs(aname, ustr, 0)) == -1))
		return -1;

	if (!*ustr || !*len) {
		*ustr = AT_UNNAMED;
		*len = 0;
	}
	
	return 0;
}

static int has_bad_sectors(ntfs_resize_t *resize)
{
	int len, ret = 0;
	ntfschar *ustr = NULL;
	ATTR_RECORD *a = resize->ctx->attr;
	
	if (resize->ni->mft_no != FILE_BadClus)
		return 0;

	if (str2unicode("$Bad", &ustr, &len) == -1)
		return -1;

	if (ustr && ntfs_names_are_equal(ustr, len,
			(ntfschar*)((u8*)a + le16_to_cpu(a->name_offset)),
			a->name_length, 0, NULL, 0)) 
		ret = 1;
									
	if (ustr != AT_UNNAMED)
		free(ustr);

	return ret;	
}

static void collect_resize_constraints(ntfs_resize_t *resize, runlist *rl)
{
	s64 inode, last_lcn;
	ATTR_FLAGS flags;
	struct llcn_t *llcn = NULL;
	int ret, supported = 0;

	last_lcn = rl->lcn + (rl->length - 1);

	inode = resize->ni->mft_no;
	flags = resize->ctx->attr->flags;
	
	if ((ret = has_bad_sectors(resize)) != 0) {
		if (ret == -1)
			perr_exit("Couldn't convert string to Unicode");
		err_exit("Your disk has bad sectors (manufacturing faults or "
			 "dying disk).\nThis situation isn't supported yet.\n");
	} 

	if (NInoAttrList(resize->ni)) {
		llcn = &resize->last_multi_mft;

		if (inode != FILE_MFT && inode != FILE_MFTMirr)
			supported = 1;
	
	} else if (flags & ATTR_IS_SPARSE) {
		llcn = &resize->last_sparse;
		supported = 1;
	
	} else if (flags & ATTR_IS_COMPRESSED) {
		llcn = &resize->last_compressed;
		supported = 1;
	
	} else if (inode == FILE_MFT) {
		llcn = &resize->last_mft;

		/* First run of $MFT DATA attribute isn't supported yet */
		if (resize->ctx->attr->type != AT_DATA || rl->vcn)
			supported = 1;
	
	} else if (inode == FILE_MFTMirr) {
		llcn = &resize->last_mftmir;
		supported = 1;

		/* Fragmented $MFTMirr DATA attribute isn't supported yet */
		if (resize->ctx->attr->type == AT_DATA)
			if (rl[1].length != 0 || rl->vcn)
				supported = 0;
	} else {
		llcn = &resize->last_lcn;
		supported = 1;
	}
	
	if (llcn->lcn < last_lcn) {
		llcn->lcn = last_lcn;
		llcn->inode = inode;
	}	

	if (supported)
		return;

	if (resize->last_unsupp < last_lcn)
		resize->last_unsupp = last_lcn;
}


static void collect_relocation_info(ntfs_resize_t *resize, runlist *rl)
{
	s64 lcn, lcn_length, start, len, inode;
	s64 new_vol_size;	/* (last LCN on the volume) + 1 */
	
	lcn = rl->lcn;
	lcn_length = rl->length;
	inode = resize->ni->mft_no;
	new_vol_size = resize->new_volume_size;
	
	if (lcn + lcn_length <= new_vol_size)
		return;

	start = lcn;
	len = lcn_length;

	if (lcn < new_vol_size) {
		start = new_vol_size;
		len = lcn_length - (new_vol_size - lcn);

		if (!opt.info && (inode == FILE_MFT || inode == FILE_MFTMirr)) {
			s64 last_lcn;

			err_printf("$MFT%s can't be split up yet. Please try "
				   "a different size.\n", inode ? "Mirr" : "");
			last_lcn = lcn + lcn_length - 1;
			print_advise(resize->vol, last_lcn);
			exit(1);
		}
	}

	resize->relocations += len;

	if (!opt.info || !resize->new_volume_size)
		return;
	
	printf("Relocation needed for inode %8lld attr 0x%x LCN 0x%08llx "
			"length %6lld\n", (long long)inode,
			(unsigned int)le32_to_cpu(resize->ctx->attr->type),
			(unsigned long long)start, (long long)len);
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
static void build_lcn_usage_bitmap(ntfs_volume *vol, ntfsck_t *fsck)
{
	s64 inode;
	ATTR_RECORD *a;
	runlist *rl;
	int i, j;
	struct bitmap *lcn_bitmap = &fsck->lcn_bitmap;

	a = fsck->ctx->attr;
	inode = fsck->ni->mft_no;

	if (!a->non_resident)
		return;

	if (!(rl = ntfs_mapping_pairs_decompress(vol, a, NULL))) {
		int err = errno;
		perr_printf("ntfs_decompress_mapping_pairs");
		if (err == EIO)
			printf(corrupt_volume_msg);
		exit(1);
	}
		

	for (i = 0; rl[i].length; i++) {
		s64 lcn = rl[i].lcn;
		s64 lcn_length = rl[i].length;

		/* CHECKME: LCN_RL_NOT_MAPPED check isn't needed */
		if (lcn == LCN_HOLE || lcn == LCN_RL_NOT_MAPPED)
			continue;

		/* FIXME: ntfs_mapping_pairs_decompress should return error */
		if (lcn < 0 || lcn_length <= 0)
			err_exit("Corrupt runlist in inode %lld attr %x LCN "
				 "%llx length %llx\n", inode,
				 (unsigned int)le32_to_cpu(a->type), lcn,
				 lcn_length);

		for (j = 0; j < lcn_length; j++) {
			u64 k = (u64)lcn + j;
			if (ntfs_bit_get_and_set(lcn_bitmap->bm, k, 1)) {
				
				if (++fsck->multi_ref > 10)
					continue;

				printf("Cluster %llu (0x%llx) referenced "
						"multiply times!\n",
						(unsigned long long)k,
						(unsigned long long)k);
			}
		}
		fsck->inuse += lcn_length;
	}
	free(rl);
}


static ntfs_attr_search_ctx *attr_get_search_ctx(ntfs_inode *ni, MFT_RECORD *mrec)
{
	ntfs_attr_search_ctx *ret;

	if ((ret = ntfs_attr_get_search_ctx(ni, mrec)) == NULL)
		perr_printf("ntfs_attr_get_search_ctx");

	return ret;
}

/**
 * walk_attributes
 *
 * For a given MFT Record, iterate through all its attributes.  Any non-resident
 * data runs will be marked in lcn_bitmap.
 */
static int walk_attributes(ntfs_volume *vol, ntfsck_t *fsck)
{
	if (!(fsck->ctx = attr_get_search_ctx(fsck->ni, NULL)))
		return -1;

	while (!ntfs_attrs_walk(fsck->ctx)) {
		if (fsck->ctx->attr->type == AT_END)
			break;
		build_lcn_usage_bitmap(vol, fsck);
	}

	ntfs_attr_put_search_ctx(fsck->ctx);
	return 0;
}

/**
 * compare_bitmaps
 *
 * Compare two bitmaps.  In this case, $Bitmap as read from the disk and
 * lcn_bitmap which we built from the MFT Records.
 */
static void compare_bitmaps(ntfs_volume *vol, struct bitmap *a)
{
	s64 i, pos, count;
	int mismatch = 0;
	int backup_boot = 0;
	u8 bm[NTFS_BUF_SIZE];

	printf("Accounting clusters ...\n");

	pos = 0;
	while (1) {
		count = ntfs_attr_pread(vol->lcnbmp_na, pos, NTFS_BUF_SIZE, bm);
		if (count == -1)
			perr_exit("Couldn't get $Bitmap $DATA");

		if (count == 0) {
			if (a->size != pos)
				err_exit("$Bitmap file size doesn't match "
					 "calculated size (%lld != %lld)\n",
					 a->size, pos);
			break;
		}

		for (i = 0; i < count; i++, pos++) {
			s64 cl;  /* current cluster */	  

			if (a->bm[pos] == bm[i])
				continue;

			for (cl = pos * 8; cl < (pos + 1) * 8; cl++) {
				char bit;

				bit = ntfs_bit_get(a->bm, cl);
				if (bit == ntfs_bit_get(bm, i * 8 + cl % 8))
					continue;

				if (!mismatch && !bit && !backup_boot && 
						cl == vol->nr_clusters / 2) {
					/* FIXME: call also boot sector check */
					backup_boot = 1;
					printf("Found backup boot sector in "
					       "the middle of the volume.\n");
					continue;       
				}	

				if (++mismatch > 10)
					continue;

				printf("Cluster accounting failed at %lld "
						"(0x%llx): %s cluster in "
						"$Bitmap\n", (long long)cl,
						(unsigned long long)cl,
						bit ? "missing" : "extra");
			}
		}
	}

	if (mismatch) {
		err_printf("Filesystem check failed! Totally %d cluster "
			   "accounting mismatches.\n", mismatch);
		printf(corrupt_volume_msg);
		exit(1);
	}
}

/**
 * progress_init
 *
 * Create and scale our progress bar.
 */
static void progress_init(struct progress_bar *p, u64 start, u64 stop, int flags)
{
	p->start = start;
	p->stop = stop;
	p->unit = 100.0 / (stop - start);
	p->resolution = 100;
	p->flags = flags;
}

/**
 * progress_update
 *
 * Update the progress bar and tell the user.
 */
static void progress_update(struct progress_bar *p, u64 current)
{
	float percent;
	
	if (!(p->flags & NTFS_PROGBAR))
		return;
	if (p->flags & NTFS_PROGBAR_SUPPRESS)
		return;
	
	/* WARNING: don't modify the texts, external tools grep for them */
	percent = p->unit * current;
	if (current != p->stop) {
		if ((current - p->start) % p->resolution)
			return;
		printf("%6.2f percent completed\r", percent);
	} else
		printf("100.00 percent completed\n");
	fflush(stdout);
}

static int inode_close(ntfs_inode *ni)
{
	if (ntfs_inode_close(ni)) {
		perr_printf("ntfs_inode_close for inode %llu",
			    (unsigned long long)ni->mft_no);
		return -1;
	}
	return 0;
}

/**
 * walk_inodes
 *
 * Read each record in the MFT, skipping the unused ones, and build up a bitmap
 * from all the non-resident attributes.
 */
static int build_allocation_bitmap(ntfs_volume *vol, ntfsck_t *fsck)
{
	s64 inode = 0;
	ntfs_inode *ni;
	struct progress_bar progress;
	int pb_flags = 0;	/* progress bar flags */

	/* WARNING: don't modify the text, external tools grep for it */
	printf("Checking filesystem consistency ...\n");

	if (fsck->flags & NTFSCK_PROGBAR)
		pb_flags |= NTFS_PROGBAR;

	progress_init(&progress, inode, vol->nr_mft_records - 1, pb_flags);

	for (; inode < vol->nr_mft_records; inode++) {
		progress_update(&progress, inode);

		if ((ni = ntfs_inode_open(vol, (MFT_REF)inode)) == NULL) {
			/* FIXME: continue only if it make sense, e.g.
			   MFT record not in use based on $MFT bitmap */
			if (errno == EIO || errno == ENOENT)
				continue;
			perr_printf("Reading inode %lld failed", inode);
			return -1;
		}

		if (ni->mrec->base_mft_record)
			goto close_inode;

		fsck->ni = ni;
		if (walk_attributes(vol, fsck) != 0) {
			inode_close(ni);
			return -1;
		}
close_inode:
		if (inode_close(ni) != 0)
			return -1;
	}
	return 0;
}

static void build_resize_constrains(ntfs_resize_t *resize)
{
	s64 i;
	runlist *rl;

	if (!resize->ctx->attr->non_resident)
		return;

	if (!(rl = ntfs_mapping_pairs_decompress(resize->vol, 
						 resize->ctx->attr, NULL)))
		perr_exit("ntfs_decompress_mapping_pairs");

	for (i = 0; rl[i].length; i++) {
		/* CHECKME: LCN_RL_NOT_MAPPED check isn't needed */
		if (rl[i].lcn == LCN_HOLE || rl[i].lcn == LCN_RL_NOT_MAPPED)
			continue;
		
		collect_resize_constraints(resize, rl + i);
		if (resize->shrink)
			collect_relocation_info(resize, rl + i);
	}
	free(rl);
}

static void resize_constrains_by_attributes(ntfs_resize_t *resize)
{
	if (!(resize->ctx = attr_get_search_ctx(resize->ni, NULL)))
		exit(1);

	while (!ntfs_attrs_walk(resize->ctx)) {
		if (resize->ctx->attr->type == AT_END)
			break;
		build_resize_constrains(resize);
	}

	ntfs_attr_put_search_ctx(resize->ctx);
}

static void set_resize_constrains(ntfs_resize_t *resize)
{
	s64 inode;
	ntfs_inode *ni;

	printf("Collecting shrinkage constrains ...\n");

	for (inode = 0; inode < resize->vol->nr_mft_records; inode++) {

		ni = ntfs_inode_open(resize->vol, (MFT_REF)inode);
		if (ni == NULL) {
			if (errno == EIO || errno == ENOENT)
				continue;
			perr_exit("Reading inode %lld failed", inode);
		}

		if (ni->mrec->base_mft_record)
			goto close_inode;

		resize->ni = ni;
		resize_constrains_by_attributes(resize);
close_inode:
		if (inode_close(ni) != 0)
			exit(1);
	}
}

static void rl_fixup(runlist **rl)
{
	runlist *tmp = *rl;

	if (tmp->lcn == LCN_RL_NOT_MAPPED) {
		s64 unmapped_len = tmp->length;

		Vprintf("Skip unmapped run at the beginning ...\n");

		if (!tmp->length)
			err_exit("Empty unmapped runlist! Please report!\n");
		(*rl)++;
		for (tmp = *rl; tmp->length; tmp++)
			tmp->vcn -= unmapped_len;
	}

	for (tmp = *rl; tmp->length; tmp++) {
		if (tmp->lcn == LCN_RL_NOT_MAPPED) {
			Vprintf("Skip unmapped run at the end  ...\n");

			if (tmp[1].length)
				err_exit("Unmapped runlist in the middle! "
					 "Please report!\n");
			tmp->lcn = LCN_ENOENT;
			tmp->length = 0;
		}
	}
}

static void replace_attribute_runlist(ntfs_volume *vol, 
				      ntfs_attr_search_ctx *ctx, 
				      runlist *rl)
{
	int mp_size, l;
	void *mp;
	ATTR_RECORD *a = ctx->attr;
	
	rl_fixup(&rl);

	if ((mp_size = ntfs_get_size_for_mapping_pairs(vol, rl, 0)) == -1)
		perr_exit("ntfs_get_size_for_mapping_pairs");
	
	if (a->name_length) {
		u16 name_offs = le16_to_cpu(a->name_offset);
		u16 mp_offs = le16_to_cpu(a->mapping_pairs_offset);

		if (name_offs >= mp_offs)
			err_exit("Attribute name is after mapping pairs! "
				 "Please report!\n");
	}

	/* CHECKME: don't trust mapping_pairs is always the last item in the
	   attribute, instead check for the real size/space */
	l = (int)le32_to_cpu(a->length) - le16_to_cpu(a->mapping_pairs_offset);
	if (mp_size > l) {
		s64 remains_size;
		char *next_attr;

		Vprintf("Enlarging attribute header ...\n");
	
		mp_size = (mp_size + 7) & ~7;
		
		Vprintf("Old mp size      : %d\n", l);
		Vprintf("New mp size      : %d\n", mp_size);
		Vprintf("Bytes in use     : %u\n", (unsigned int)
				le32_to_cpu(ctx->mrec->bytes_in_use));
	
		next_attr = (char *)a + le16_to_cpu(a->length);
		l = mp_size - l;
		
		Vprintf("Bytes in use new : %u\n", l + (unsigned int)
				le32_to_cpu(ctx->mrec->bytes_in_use));
		Vprintf("Bytes allocated  : %u\n", (unsigned int)
				le32_to_cpu(ctx->mrec->bytes_allocated));

		remains_size = le32_to_cpu(ctx->mrec->bytes_in_use);
		remains_size -= (next_attr - (char *)ctx->mrec);

		Vprintf("increase         : %d\n", l);
		Vprintf("shift            : %lld\n", (long long)remains_size);
		
		if (le32_to_cpu(ctx->mrec->bytes_in_use) + l >
				le32_to_cpu(ctx->mrec->bytes_allocated))
			err_exit("Extended record needed (%u > %u), not yet "
				 "supported!\nPlease try to free less space.\n",
				 (unsigned int)le32_to_cpu(ctx->mrec->
					bytes_in_use) + l,
				 (unsigned int)le32_to_cpu(ctx->mrec->
					bytes_allocated));

		memmove(next_attr + l, next_attr, remains_size);
		ctx->mrec->bytes_in_use = cpu_to_le32(l +
				le32_to_cpu(ctx->mrec->bytes_in_use));
		a->length += l;
	}

	if (!(mp = calloc(1, mp_size)))
		perr_exit("Couldn't get memory");

	if (ntfs_mapping_pairs_build(vol, mp, mp_size, rl, 0, 0))
		perr_exit("ntfs_mapping_pairs_build");

	memmove((u8*)a + le16_to_cpu(a->mapping_pairs_offset), mp, mp_size);

	free(mp);
}

static void set_bitmap_range(struct bitmap *bm, s64 pos, s64 length, u8 bit)
{
	while (length--)
		ntfs_bit_set(bm->bm, pos++, bit);
}

static void set_bitmap_clusters(struct bitmap *bm, runlist *rl, u8 bit)
{
	for (; rl->length; rl++)
		set_bitmap_range(bm, rl->lcn, rl->length, bit);
}

static void release_bitmap_clusters(struct bitmap *bm, runlist *rl)
{
	max_free_cluster_range = 0;
	set_bitmap_clusters(bm, rl, 0);
}

static void set_max_free_zone(s64 length, s64 end, runlist_element *rle)
{
	if (length > rle->length) {
		rle->lcn = end - length;
		rle->length = length;
	}
}

static int find_free_cluster(struct bitmap *bm, 
			     runlist_element *rle,
			     s64 nr_vol_clusters, 
			     int hint)
{
	/* FIXME: get rid of this 'static' variable */
	static s64 pos = 0;
	s64 i, items = rle->length;
	s64 free_zone = 0;

	if (pos >= nr_vol_clusters)
		pos = 0;
	if (!max_free_cluster_range)
		max_free_cluster_range = nr_vol_clusters;
	rle->lcn = rle->length = 0;
	if (hint)
		pos = nr_vol_clusters / 2;
	i = pos;

	do {
		if (!ntfs_bit_get(bm->bm, i)) {
			if (++free_zone == items) {
				set_max_free_zone(free_zone, i + 1, rle);
				break;
			}
		} else {
			set_max_free_zone(free_zone, i, rle);
			free_zone = 0;
		}
		if (++i == nr_vol_clusters) {
			set_max_free_zone(free_zone, i, rle);
			i = free_zone = 0;
		}
		if (rle->length == max_free_cluster_range)
			break;
	} while (i != pos);

	if (i)
		set_max_free_zone(free_zone, i, rle);

	if (!rle->lcn) {
		errno = ENOSPC;
		return -1;
	}
	if (rle->length < items && rle->length < max_free_cluster_range) {
		max_free_cluster_range = rle->length;
		Vprintf("Max free range: %7lld     \n",
				(long long)max_free_cluster_range);
	}
	pos = rle->lcn + items;
	if (pos == nr_vol_clusters)
		pos = 0;

	set_bitmap_range(bm, rle->lcn, rle->length, 1);
	return 0;
}

static runlist *alloc_cluster(struct bitmap *bm, 
			      s64 items, 
			      s64 nr_vol_clusters, 
			      int hint)
{
	runlist_element rle;
	runlist *rl = NULL;
	int rl_size, runs = 0;
	s64 vcn = 0;

	if (items <= 0) {
		errno = EINVAL;
		return NULL;
	}

	while (items > 0) {

		if (runs)
			hint = 0;
		rle.length = items;
		if (find_free_cluster(bm, &rle, nr_vol_clusters, hint) == -1)
			return NULL;
		
		rl_size = (runs + 2) * sizeof(runlist_element);
		if (!(rl = (runlist *)realloc(rl, rl_size)))
			return NULL;

		rl_set(rl + runs, vcn, rle.lcn, rle.length);

		vcn += rle.length;
		items -= rle.length;
		runs++;
	}

	rl_set(rl + runs, vcn, -1LL, 0LL);
	
	if (runs > 1) {
		Vprintf("Multi-run allocation:    \n");
		dump_runlist(rl);
	}
	return rl;
}

static int read_all(struct ntfs_device *dev, void *buf, int count)
{
	int i;
	
	while (count > 0) {
		
		i = count;
		if (!NDevReadOnly(dev))
			i = dev->d_ops->read(dev, buf, count);

		if (i < 0) {
			if (errno != EAGAIN && errno != EINTR)
				return -1;
		} else if (i > 0) {
			count -= i;
			buf = i + (char *)buf;
		} else
			err_exit("Unexpected end of file!\n");
	}
	return 0;
}

static int write_all(struct ntfs_device *dev, void *buf, int count)
{
	int i;
	
	while (count > 0) {

		i = count;
		if (!NDevReadOnly(dev))
			i = dev->d_ops->write(dev, buf, count);

		if (i < 0) {
			if (errno != EAGAIN && errno != EINTR)
				return -1;
		} else {
			count -= i;
			buf = i + (char *)buf;
		}
	}
	return 0;
}

/**
 * write_mft_record
 *
 * Write an MFT Record back to the disk.  If the read-only command line option
 * was given, this function will do nothing.
 */
static int write_mft_record(ntfs_volume *v, const MFT_REF mref, MFT_RECORD *buf)
{
	if (ntfs_mft_record_write(v, mref, buf))
		perr_exit("ntfs_mft_record_write");

//	if (v->dev->d_ops->sync(v->dev) == -1)
//		perr_exit("Failed to sync device");

	return 0;
}

static void lseek_to_cluster(ntfs_volume *vol, s64 lcn)
{
	off_t pos;
	
	pos = (off_t)(lcn * vol->cluster_size);
	
	if (vol->dev->d_ops->seek(vol->dev, pos, SEEK_SET) == (off_t)-1)
		perr_exit("seek failed to position %lld", lcn);
}

static void copy_clusters(ntfs_resize_t *resize, s64 dest, s64 src, s64 len)
{
	s64 i;
	char buff[NTFS_MAX_CLUSTER_SIZE]; /* overflow checked at mount time */
	ntfs_volume *vol = resize->vol;

	for (i = 0; i < len; i++) {

		lseek_to_cluster(vol, src + i);
	
		if (read_all(vol->dev, buff, vol->cluster_size) == -1)
			perr_exit("read_all");
		
		lseek_to_cluster(vol, dest + i);
	
		if (write_all(vol->dev, buff, vol->cluster_size) == -1)
			perr_exit("write_all");
		
		resize->relocations++;
		progress_update(&resize->progress, resize->relocations);
	}
}

static void relocate_clusters(ntfs_resize_t *r, runlist *dest_rl, s64 src_lcn)
{
	/* collect_shrink_constraints() ensured $MFTMir DATA is one run */
	if (r->mref == FILE_MFTMirr && r->ctx->attr->type == AT_DATA) {
		if (!r->mftmir_old) {
			r->mftmir_rl.lcn = dest_rl->lcn;
			r->mftmir_rl.length = dest_rl->length;
			r->mftmir_old = src_lcn;
		} else
			err_exit("Multi-run $MFTMirr. Please report!\n");
	}

	for (; dest_rl->length; src_lcn += dest_rl->length, dest_rl++)
		copy_clusters(r, dest_rl->lcn, src_lcn, dest_rl->length);
}
	
static void rl_split_run(runlist **rl, int run, s64 pos)
{
	runlist *rl_new, *rle_new, *rle;
	int items, new_size, size_head, size_tail;
	s64 len_head, len_tail;
	
	items = rl_items(*rl);
	new_size = (items + 1) * sizeof(runlist_element);
	size_head = run * sizeof(runlist_element);
	size_tail = (items - run - 1) * sizeof(runlist_element);

	if (!(rl_new = (runlist *)malloc(new_size)))
		perr_exit("malloc");

	rle_new = rl_new + run;
	rle = *rl + run;

	memmove(rl_new, *rl, size_head);
	memmove(rle_new + 2, rle + 1, size_tail);

	len_tail = rle->length - (pos - rle->lcn);
	len_head = rle->length - len_tail;
	
	rl_set(rle_new, rle->vcn, rle->lcn, len_head);
	rl_set(rle_new + 1, rle->vcn + len_head, rle->lcn + len_head, len_tail);
	
	Vprintf("Splitting run at cluster %lld:\n", (long long)pos);
	dump_run(rle); dump_run(rle_new); dump_run(rle_new + 1);

	free(*rl);
	*rl = rl_new;
}

static void rl_insert_at_run(runlist **rl, int run, runlist *ins)
{
	int items, ins_items;
	int new_size, size_tail;
	runlist *rle;
	s64 vcn;

	items  = rl_items(*rl);
	ins_items = rl_items(ins) - 1;
	new_size = ((items - 1) + ins_items) * sizeof(runlist_element);
	size_tail = (items - run - 1) * sizeof(runlist_element);

	if (!(*rl = (runlist *)realloc(*rl, new_size)))
		perr_exit("realloc");

	rle = *rl + run;

	memmove(rle + ins_items, rle + 1, size_tail);

	for (vcn = rle->vcn; ins->length; rle++, vcn += ins->length, ins++) {
		rl_set(rle, vcn, ins->lcn, ins->length);
//		dump_run(rle);
	}

	return;

	/* FIXME: fastpath if ins_items = 1 */
//	(*rl + run)->lcn = ins->lcn;
}

static void relocate_run(ntfs_resize_t *resize, runlist **rl, int run)
{
	s64 lcn, lcn_length;
	s64 new_vol_size;	/* (last LCN on the volume) + 1 */
	runlist *relocate_rl;	/* relocate runlist to relocate_rl */
	int hint;

	lcn = (*rl + run)->lcn;
	lcn_length = (*rl + run)->length;
	new_vol_size = resize->new_volume_size;
	
	if (lcn + lcn_length <= new_vol_size)
		return;

	if (lcn < new_vol_size) {
		rl_split_run(rl, run, new_vol_size);
		return;
	}

	hint = (resize->mref == FILE_MFTMirr) ? 1 : 0;
	if (!(relocate_rl = alloc_cluster(&resize->lcn_bitmap, lcn_length, 
					  new_vol_size, hint)))
		perr_exit("Cluster allocation failed for %llu:%lld",
			  resize->mref, lcn_length);
	
	/* FIXME: check $MFTMirr DATA isn't multi-run (or support it) */
	Vprintf("Relocate inode %7llu:0x%x:%08lld:0x%08llx --> 0x%08llx\n",
			(unsigned long long)resize->mref,
			(unsigned int)le32_to_cpu(resize->ctx->attr->type),
			(long long)lcn_length, (unsigned long long)lcn,
			(unsigned long long)relocate_rl->lcn);

	relocate_clusters(resize, relocate_rl, lcn);
	rl_insert_at_run(rl, run, relocate_rl);

	/* We don't release old clusters in the bitmap, that area isn't
	   used by the allocator and will be truncated later on */
	free(relocate_rl);

	resize->dirty_inode = DIRTY_ATTRIB;
}

static void relocate_attribute(ntfs_resize_t *resize)
{
	ATTR_RECORD *a;
	runlist *rl;
	int i;

	a = resize->ctx->attr;

	if (!a->non_resident)
		return;

	if (!(rl = ntfs_mapping_pairs_decompress(resize->vol, a, NULL)))
		perr_exit("ntfs_decompress_mapping_pairs");

	for (i = 0; rl[i].length; i++) {
		s64 lcn = rl[i].lcn;
		s64 lcn_length = rl[i].length;

		if (lcn == LCN_HOLE || lcn == LCN_RL_NOT_MAPPED)
			continue;

		/* FIXME: ntfs_mapping_pairs_decompress should return error */
		if (lcn < 0 || lcn_length <= 0)
			err_exit("Corrupt runlist in MTF %llu attr %x LCN "
				 "%llx length %llx\n", resize->mref,
				 (unsigned int)le32_to_cpu(a->type),
				 lcn, lcn_length);

		relocate_run(resize, &rl, i);
	}

	if (resize->dirty_inode == DIRTY_ATTRIB) {
		replace_attribute_runlist(resize->vol, resize->ctx, rl);
		resize->dirty_inode = DIRTY_INODE;
	}

	free(rl);
}

static void relocate_attributes(ntfs_resize_t *resize)
{
	if (!(resize->ctx = attr_get_search_ctx(NULL, resize->mrec)))
		exit(1);

	while (!ntfs_attrs_walk(resize->ctx)) {
		if (resize->ctx->attr->type == AT_END)
			break;
		relocate_attribute(resize);
	}

	ntfs_attr_put_search_ctx(resize->ctx);
}

static void relocate_inode(ntfs_resize_t *resize, MFT_REF mref)
{
	if (ntfs_file_record_read(resize->vol, mref, &resize->mrec, NULL)) {
		/* FIXME: continue only if it make sense, e.g.
		   MFT record not in use based on $MFT bitmap */
		if (errno == EIO || errno == ENOENT)
			return;
		perr_exit("ntfs_file_record_record");
	}

	if (!(resize->mrec->flags & MFT_RECORD_IN_USE))
		return;

	resize->mref = mref;
	resize->dirty_inode = DIRTY_NONE;

	relocate_attributes(resize);

	if (resize->dirty_inode == DIRTY_INODE) {
//		if (vol->dev->d_ops->sync(vol->dev) == -1)
//			perr_exit("Failed to sync device");
		if (write_mft_record(resize->vol, mref, resize->mrec))
			perr_exit("Couldn't update inode %llu", mref);
	}
}

static void relocate_inodes(ntfs_resize_t *resize)
{
	MFT_REF mref;

	printf("Relocating needed data ...\n");
	
	progress_init(&resize->progress, 0, resize->relocations, resize->progress.flags);
	resize->relocations = 0;
	
	resize->mrec = (MFT_RECORD *)malloc(resize->vol->mft_record_size);
	if (!resize->mrec)
		perr_exit("malloc failed");

   	for (mref = 1; mref < (MFT_REF)resize->vol->nr_mft_records; mref++)
		relocate_inode(resize, mref);

	relocate_inode(resize, 0);

	if (resize->mrec)
		free(resize->mrec);
}

static void print_hint(ntfs_volume *vol, const char *s, struct llcn_t llcn)
{
	s64 runs_b, runs_mb;
	
	if (llcn.lcn == 0)
		return;
	
	runs_b = llcn.lcn * vol->cluster_size;
	runs_mb = rounded_up_division(runs_b, NTFS_MBYTE);
	printf("%-19s: %9lld MB      %8lld\n", s, (long long)runs_mb,
			(long long)llcn.inode);
}

/**
 * advise_on_resize
 *
 * The metadata file $Bitmap has one bit for each cluster on disk.  This has
 * already been read into lcn_bitmap.  By looking for the last used cluster on
 * the disk, we can work out by how much we can shrink the volume.
 */
static void advise_on_resize(ntfs_resize_t *resize)
{
	ntfs_volume *vol = resize->vol;

	printf("Estimating smallest shrunken size supported ...\n");

	printf("File feature         Last used at      By inode\n");
	print_hint(vol, "$MFT", resize->last_mft);
	print_hint(vol, "Multi-Record", resize->last_multi_mft);
	if (opt.verbose) {
		print_hint(vol, "$MFTMirr", resize->last_mftmir);
		print_hint(vol, "Compressed", resize->last_compressed);
		print_hint(vol, "Sparse", resize->last_sparse);
		print_hint(vol, "Ordinary", resize->last_lcn);
	}

	print_advise(vol, resize->last_unsupp);
}

/**
 * bitmap_file_data_fixup
 *
 * $Bitmap can overlap the end of the volume. Any bits in this region
 * must be set. This region also encompasses the backup boot sector.
 */
static void bitmap_file_data_fixup(s64 cluster, struct bitmap *bm)
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
static void truncate_badclust_bad_attr(ntfs_resize_t *resize)
{
	runlist *rl_bad;
	ATTR_RECORD *a = resize->ctx->attr;
	s64 nr_clusters = resize->new_volume_size;
	ntfs_volume *vol = resize->vol;

	if (!a->non_resident)
		/* FIXME: handle resident attribute value */
		err_exit("Resident attribute in $BadClust isn't supported!\n");

	if (!(rl_bad = (runlist *)malloc(2 * sizeof(runlist_element))))
		perr_exit("Couldn't get memory");

	a->highest_vcn = cpu_to_le64(nr_clusters - 1LL);
	a->allocated_size = cpu_to_le64(nr_clusters * vol->cluster_size);
	a->data_size = cpu_to_le64(nr_clusters * vol->cluster_size);

	rl_set(rl_bad, 0LL, (LCN)LCN_HOLE, nr_clusters);
	rl_set(rl_bad + 1, nr_clusters, -1LL, 0LL);

	replace_attribute_runlist(vol, resize->ctx, rl_bad);

	free(rl_bad);
}

/**
 * shrink_bitmap_data_attr
 *
 * Shrink the metadata file $Bitmap.  It must be large enough for one bit per
 * cluster of the shrunken volume.  Also it must be a of 8 bytes in size.
 */
static void shrink_bitmap_data_attr(struct bitmap *bm, 
				    runlist **rlist, 
				    s64 nr_bm_clusters, 
				    s64 new_size)
{
	runlist *rl = *rlist;
	int i, j;
	s64 k;
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

			k = rl[i].lcn + j;
			if (k < new_size) {
				ntfs_bit_set(bm->bm, k, 0);
				Dprintf("Unallocate cluster: "
				       "%lld (%llx)\n", k, k);
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
static void enlarge_bitmap_data_attr(ntfs_volume *vol,
				     struct bitmap *bm,
				     runlist **rl, 
				     s64 nr_bm_clusters, 
				     s64 new_size)
{
	s64 i;

	release_bitmap_clusters(bm, *rl);
	free(*rl);

	for (i = vol->nr_clusters; i < new_size; i++)
		ntfs_bit_set(bm->bm, i, 0);

	if (!(*rl = alloc_cluster(bm, nr_bm_clusters, new_size, 0)))
		perr_exit("Couldn't allocate $Bitmap clusters");
}

/**
 * truncate_bitmap_data_attr
 */
static void truncate_bitmap_data_attr(ntfs_resize_t *resize)
{
	ATTR_RECORD *a;
	runlist *rl;
	s64 bm_bsize, size;
	s64 nr_bm_clusters;
	s64 nr_clusters;
	u8 *tmp;
	ntfs_volume *vol = resize->vol;

	a = resize->ctx->attr;
	if (!a->non_resident)
		/* FIXME: handle resident attribute value */
		err_exit("Resident attribute in $Bitmap isn't supported!\n");

	nr_clusters = resize->new_volume_size;
	bm_bsize = nr_clusters_to_bitmap_byte_size(nr_clusters);
	nr_bm_clusters = rounded_up_division(bm_bsize, vol->cluster_size);

	if (!(tmp = (u8 *)realloc(resize->lcn_bitmap.bm, bm_bsize)))
		perr_exit("realloc");
	resize->lcn_bitmap.bm = tmp;
	resize->lcn_bitmap.size = bm_bsize;
	bitmap_file_data_fixup(nr_clusters, &resize->lcn_bitmap);

	if (!(rl = ntfs_mapping_pairs_decompress(vol, a, NULL)))
		perr_exit("ntfs_mapping_pairs_decompress");

	/* NOTE: shrink could use enlarge_bitmap_data_attr() also. Advantages:
	   less code, better code coverage. "Drawback": could be relocated */
	if (resize->shrink)
		shrink_bitmap_data_attr(&resize->lcn_bitmap, &rl, 
					nr_bm_clusters, nr_clusters);
	else
		enlarge_bitmap_data_attr(vol, &resize->lcn_bitmap, &rl, 
					 nr_bm_clusters, nr_clusters);

	a->highest_vcn = cpu_to_le64(nr_bm_clusters - 1LL);
	a->allocated_size = cpu_to_le64(nr_bm_clusters * vol->cluster_size);
	a->data_size = cpu_to_le64(bm_bsize);
	a->initialized_size = cpu_to_le64(bm_bsize);
	
	replace_attribute_runlist(vol, resize->ctx, rl);

	/*
	 * FIXME: update allocated/data sizes and timestamps in $FILE_NAME
	 * attribute too, for now chkdsk will do this for us.
	 */

	size = ntfs_rl_pwrite(vol, rl, 0, bm_bsize, resize->lcn_bitmap.bm);
	if (bm_bsize != size) {
		if (size == -1)
			perr_exit("Couldn't write $Bitmap");
		err_exit("Couldn't write full $Bitmap file (%lld from %lld)\n",
				(long long)size, (long long)bm_bsize);
	}

	free(rl);
}

/**
 * lookup_data_attr
 *
 * Find the $DATA attribute (with or without a name) for the given MFT reference
 * (inode number).
 */
static void lookup_data_attr(ntfs_volume *vol,
			     MFT_REF mref, 
			     const char *aname, 
			     ntfs_attr_search_ctx **ctx)
{
	ntfs_inode *ni;
	ntfschar *ustr = NULL;
	int len = 0;

	if (!(ni = ntfs_inode_open(vol, mref)))
		perr_exit("ntfs_open_inode");

	if (NInoAttrList(ni))
		perr_exit("Attribute list attribute not yet supported");

	if (!(*ctx = attr_get_search_ctx(ni, NULL)))
		exit(1);

	if (str2unicode(aname, &ustr, &len) == -1)
		perr_exit("Unable to convert string to Unicode");

	if (ntfs_attr_lookup(AT_DATA, ustr, len, 0, 0, NULL, 0, *ctx))
		perr_exit("ntfs_lookup_attr");

	if (ustr != AT_UNNAMED)
		free(ustr);
}

/**
 * truncate_badclust_file
 *
 * Shrink the $BadClus file to match the new volume size.
 */
static void truncate_badclust_file(ntfs_resize_t *resize)
{
	printf("Updating $BadClust file ...\n");

	lookup_data_attr(resize->vol, FILE_BadClus, "$Bad", &resize->ctx);
	/* FIXME: sanity_check_attr(ctx->attr); */
	truncate_badclust_bad_attr(resize);

	if (write_mft_record(resize->vol, resize->ctx->ntfs_ino->mft_no, 
			     resize->ctx->mrec))
		perr_exit("Couldn't update $BadClust");

	ntfs_attr_put_search_ctx(resize->ctx);
}

/**
 * truncate_bitmap_file
 *
 * Shrink the $Bitmap file to match the new volume size.
 */
static void truncate_bitmap_file(ntfs_resize_t *resize)
{
	printf("Updating $Bitmap file ...\n");

	lookup_data_attr(resize->vol, FILE_Bitmap, NULL, &resize->ctx);
	truncate_bitmap_data_attr(resize);

	if (write_mft_record(resize->vol, resize->ctx->ntfs_ino->mft_no, 
			     resize->ctx->mrec))
		perr_exit("Couldn't update $Bitmap");

	ntfs_attr_put_search_ctx(resize->ctx);
}

/**
 * setup_lcn_bitmap
 *
 * Allocate a block of memory with one bit for each cluster of the disk.
 * All the bits are set to 0, except those representing the region beyond the
 * end of the disk.
 */
static int setup_lcn_bitmap(struct bitmap *bm, s64 nr_clusters)
{
	/* Determine lcn bitmap byte size and allocate it. */
	bm->size = nr_clusters_to_bitmap_byte_size(nr_clusters);

	if (!(bm->bm = (unsigned char *)calloc(1, bm->size)))
		return -1;

	bitmap_file_data_fixup(nr_clusters, bm);
	return 0;
}

/**
 * update_bootsector
 *
 * FIXME: should be done using ntfs_* functions
 */
static void update_bootsector(ntfs_resize_t *r)
{
	NTFS_BOOT_SECTOR bs;
	s64  bs_size = sizeof(NTFS_BOOT_SECTOR);
	ntfs_volume *vol = r->vol;

	printf("Updating Boot record ...\n");

	if (vol->dev->d_ops->seek(vol->dev, 0, SEEK_SET) == (off_t)-1)
		perr_exit("lseek");

	if (vol->dev->d_ops->read(vol->dev, &bs, bs_size) == -1)
		perr_exit("read() error");

	bs.number_of_sectors = scpu_to_le64(r->new_volume_size *
			bs.bpb.sectors_per_cluster);

	if (r->mftmir_old) {
		r->progress.flags |= NTFS_PROGBAR_SUPPRESS;
		copy_clusters(r, r->mftmir_rl.lcn, r->mftmir_old, 
			      r->mftmir_rl.length);
		bs.mftmirr_lcn = cpu_to_le64(r->mftmir_rl.lcn);
		r->progress.flags &= ~NTFS_PROGBAR_SUPPRESS;
	}

	if (vol->dev->d_ops->seek(vol->dev, 0, SEEK_SET) == (off_t)-1)
		perr_exit("lseek");

	if (!opt.ro_flag)
		if (vol->dev->d_ops->write(vol->dev, &bs, bs_size) == -1)
			perr_exit("write() error");
}

/**
 * vol_size
 */
static s64 vol_size(ntfs_volume *v, s64 nr_clusters)
{
	/* add one sector_size for the backup boot sector */
	return nr_clusters * v->cluster_size + v->sector_size;
}

/**
 * print_vol_size
 *
 * Print the volume size in bytes and decimal megabytes.
 */
static void print_vol_size(const char *str, s64 bytes)
{
	printf("%s: %lld bytes (%lld MB)\n", str, (long long)bytes,
			(long long)rounded_up_division(bytes, NTFS_MBYTE));
}

/**
 * print_disk_usage
 *
 * Display the amount of disk space in use.
 */
static void print_disk_usage(ntfs_volume *vol, s64 nr_used_clusters)
{
	s64 total, used;

	total = vol->nr_clusters * vol->cluster_size;
	used = nr_used_clusters * vol->cluster_size;

	/* WARNING: don't modify the text, external tools grep for it */
	printf("Space in use       : %lld MB (%.1f%%)\n",
	       (long long)rounded_up_division(used, NTFS_MBYTE),
	       100.0 * ((float)used / total));
}

static void print_num_of_relocations(ntfs_resize_t *resize)
{
	s64 relocations = resize->relocations * resize->vol->cluster_size;
	
	printf("Needed relocations : %lld (%lld MB)\n",
			(long long)resize->relocations, (long long)
			rounded_up_division(relocations, NTFS_MBYTE));
}

/**
 * mount_volume
 *
 * First perform some checks to determine if the volume is already mounted, or
 * is dirty (Windows wasn't shutdown properly).  If everything is OK, then mount
 * the volume (load the metadata into memory).
 */
static ntfs_volume *mount_volume(void)
{
	unsigned long mntflag;
	ntfs_volume *vol = NULL;

	if (ntfs_check_if_mounted(opt.volume, &mntflag)) {
		perr_printf("Failed to check '%s' mount state", opt.volume);
		printf("Probably /etc/mtab is missing. It's too risky to "
		       "continue. You might try\nan another Linux distro.\n");
		exit(1);
	}
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
		if (err == EINVAL)
			printf(invalid_ntfs_msg, opt.volume);
		else if (err == EIO)
			printf(corrupt_volume_msg);
		exit(1);
	}

	if (vol->flags & VOLUME_IS_DIRTY)
		if (opt.force-- <= 0)
			err_exit("Volume is dirty. Run chkdsk /f and "
				 "please try again (or see -f option).\n");
	
	if (NTFS_MAX_CLUSTER_SIZE < vol->cluster_size)
		err_exit("Cluster size %u is too large!\n",
			(unsigned int)vol->cluster_size);

	printf("NTFS volume version: %d.%d\n", vol->major_ver, vol->minor_ver);
	if (ntfs_version_is_supported(vol))
		perr_exit("Unknown NTFS version");

	printf("Cluster size       : %u bytes\n",
			(unsigned int)vol->cluster_size);
	print_vol_size("Current volume size", vol_size(vol, vol->nr_clusters));

	return vol;
}

/**
 * prepare_volume_fixup
 *
 * Set the volume's dirty flag and wipe the filesystem journal.  When Windows
 * boots it will automatically run chkdsk to check for any problems.  If the
 * read-only command line option was given, this function will do nothing.
 */
static void prepare_volume_fixup(ntfs_volume *vol)
{
	u16 flags;

	flags = vol->flags | VOLUME_IS_DIRTY;
	if (vol->major_ver >= 2)
		flags |= VOLUME_MOUNTED_ON_NT4;

	printf("Schedule chkdsk for NTFS consistency check at Windows "
		"boot time ...\n");

	if (ntfs_volume_set_flags(vol, flags))
		perr_exit("Failed to set $Volume dirty");

	if (vol->dev->d_ops->sync(vol->dev) == -1)
		perr_exit("Failed to sync device");

	printf("Resetting $LogFile ... (this might take a while)\n");

	if (ntfs_logfile_reset(vol))
		perr_exit("Failed to reset $LogFile");

	if (vol->dev->d_ops->sync(vol->dev) == -1)
		perr_exit("Failed to sync device");
}


static void set_disk_usage_constraint(ntfs_resize_t *resize)
{
	/* last lcn for a filled up volume (no empty space) */
	s64 last = resize->inuse - 1;
	
	if (resize->last_unsupp < last)
		resize->last_unsupp = last;
}

static void check_shrink_constraints(ntfs_resize_t *resize)
{
	s64 new_size = resize->new_volume_size;

	/* FIXME: resize.shrink true also if only -i is used */
	if (!resize->shrink)
		return;

	if (resize->inuse == resize->vol->nr_clusters)
		err_exit("Volume is full. To shrink it, "
			 "delete unused files.\n");
	
	if (opt.info)
		return;

	/* FIXME: reserve some extra space so Windows can boot ... */
	if (new_size < resize->inuse)
		err_exit("New size can't be less than the space already"
			 " occupied by data.\nYou either need to delete unused"
			 " files or see the -i option.\n");

	if (new_size <= resize->last_unsupp)
		err_exit("The fragmentation type, you have, isn't "
			 "supported yet. Rerun ntfsresize\nwith "
			 "the -i option to estimate the smallest "
			 "shrunken volume size supported.\n");

	print_num_of_relocations(resize);
}


int main(int argc, char **argv)
{
	ntfsck_t fsck;
	ntfs_resize_t resize;
	s64 new_size = 0;	/* in clusters; 0 = --info w/o --size */
	s64 device_size;        /* in bytes */
	ntfs_volume *vol;

	printf("%s v%s\n", EXEC_NAME, VERSION);

	if (!parse_options(argc, argv))
		return 1;

	utils_set_locale();

	if ((vol = mount_volume()) == NULL)
		err_exit("Couldn't open volume '%s'!\n", opt.volume);

	device_size = ntfs_device_size_get(vol->dev, vol->sector_size);
	device_size *= vol->sector_size;
	if (device_size <= 0)
		err_exit("Couldn't get device size (%lld)!\n", device_size);

	print_vol_size("Current device size", device_size);

	if (device_size < vol->nr_clusters * vol->cluster_size)
		err_exit("Current NTFS volume size is bigger than the device "
			 "size!\nCorrupt partition table or incorrect device "
			 "partitioning?\n");

	if (!opt.bytes && !opt.info)
		opt.bytes = device_size;

	/* Take the integer part: don't make the volume bigger than requested */
	new_size = opt.bytes / vol->cluster_size;

	/* Backup boot sector at the end of device isn't counted in NTFS
	   volume size thus we have to reserve space for it. */
	if (new_size)
		--new_size;

	if (!opt.info) {
		print_vol_size("New volume size    ", vol_size(vol, new_size));
		if (device_size < opt.bytes)
			err_exit("New size can't be bigger than the device size"
				 ".\nIf you want to enlarge NTFS then first "
				 "enlarge the device size by e.g. fdisk.\n");
	}

	if (!opt.info && (new_size == vol->nr_clusters ||
			  (opt.bytes == device_size &&
			   new_size == vol->nr_clusters - 1))) {
		printf("Nothing to do: NTFS volume size is already OK.\n");
		exit(0);
	}

	memset(&fsck, 0, sizeof(fsck));
	if (opt.show_progress)
		fsck.flags |= NTFSCK_PROGBAR;

	if (setup_lcn_bitmap(&fsck.lcn_bitmap, vol->nr_clusters) != 0)
		perr_exit("Failed to setup allocation bitmap");
	if (build_allocation_bitmap(vol, &fsck) != 0)
		exit(1);
	if (fsck.multi_ref) {
		err_printf("Filesystem check failed! Totally %d clusters "
			   "referenced multiply times.\n", fsck.multi_ref);
		printf(corrupt_volume_msg);
		exit(1);
	}
	compare_bitmaps(vol, &fsck.lcn_bitmap);

	print_disk_usage(vol, fsck.inuse);
	
	memset(&resize, 0, sizeof(resize));
	resize.new_volume_size = new_size;
	resize.inuse = fsck.inuse;
	resize.lcn_bitmap = fsck.lcn_bitmap;
	resize.vol = vol;
	if (opt.show_progress)
		resize.progress.flags |= NTFS_PROGBAR;
	
	/* This is also true if --info was used w/o --size (new_size = 0) */
	if (new_size < vol->nr_clusters)
		resize.shrink = 1;

	set_resize_constrains(&resize);
	set_disk_usage_constraint(&resize);
	check_shrink_constraints(&resize);

	if (opt.info) {
	       	advise_on_resize(&resize);
		exit(0);
	}

	if (opt.force-- <= 0 && !opt.ro_flag) {
		printf(resize_warning_msg);
		proceed_question();
	}

	/* FIXME: performance - relocate logfile here if it's needed */
	prepare_volume_fixup(vol);

	if (resize.relocations)
		relocate_inodes(&resize);

	truncate_badclust_file(&resize);
	truncate_bitmap_file(&resize);
	update_bootsector(&resize);

	/* We don't create backup boot sector because we don't know where the
	   partition will be split. The scheduled chkdsk will fix it */

	if (opt.ro_flag) {
		printf("The read-only test run ended successfully.\n");
		exit(0);
	}

	/* WARNING: don't modify the texts, external tools grep for them */
	printf("Syncing device ...\n");
	if (vol->dev->d_ops->sync(vol->dev) == -1)
		perr_exit("fsync");

	printf("Successfully resized NTFS on device '%s'.\n", vol->dev->d_name);
	if (resize.shrink)
		printf(resize_important_msg);

	return 0;
}
