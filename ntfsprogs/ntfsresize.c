/**
 * ntfsresize - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002 Szabolcs Szakacsits
 * Copyright (c) 2002 Anton Altaparmakov
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

const char *EXEC_NAME = "ntfsresize";

static const char *ntfs_report_banner =
"\nReport bugs to linux-ntfs-dev@lists.sf.net. "
"Homepage: http://linux-ntfs.sf.net\n";

static const char *resize_warning_msg =
"WARNING: Every sanity check passed and only the DANGEROUS operations left.\n"
"Please make sure all your important data had been backed up in case of an\n"
"unexpected failure!\n";

static const char *resize_important_msg =
"NTFS had been successfully resized on device '%s'.\n"
"You can go on to resize the device e.g. with 'fdisk'.\n"
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

ntfs_volume *vol = NULL;
struct bitmap lcn_bitmap;

#define NTFS_MBYTE (1000 * 1000)

#define ERR_PREFIX   "ERROR"
#define PERR_PREFIX  ERR_PREFIX "(%d): "
#define NERR_PREFIX  ERR_PREFIX ": "

#define rounded_up_division(a, b) (((a) + (b - 1)) / (b))


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


void usage()
{
	printf("\n");
	printf ("Usage: %s [-fhin] [-s size[k|M|G]] device\n", EXEC_NAME);
	printf("Shrink a defragmented NTFS volume.\n");
	printf("\n");
	Dprintf("   -d              Show debug information\n");
	printf ("   -f              Force to progress (DANGEROUS)\n");
	printf ("   -h              This help text\n");
	printf ("   -i              Calculate the smallest shrunken size supported (read-only)\n");
	printf ("   -n              Make a test run without write operations (read-only)\n");
	printf ("   -s size[k|M|G]  Shrink volume to size[k|M|G] bytes (k=10^3, M=10^6, G=10^9)\n");
/*	printf ("   -v              Verbose operation\n"); */
	printf(ntfs_report_banner);
	exit(1);
}


/* Copy-paste from e2fsprogs */
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
		printf("OK quitting. NO CHANGES has been made to your NTFS volume.\n");
		exit(1);
	}
}


s64 get_new_volume_size(char *s)
{
	s64 size;
	char *suffix;

	size = strtoll(s, &suffix, 10);
	if (size <= 0 || errno == ERANGE)
		err_exit("Illegal new volume size\n");

	if (!*suffix)
		return size;

	if (strlen(suffix) > 1)
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
		size *= 1000;
	case 'M':
		size *= 1000;
	case 'k':
		size *= 1000;
		break;
	default:
		usage();
	}

	return size;
}


void parse_options(int argc, char **argv)
{
	int i;

	printf("%s v%s\n", EXEC_NAME, VERSION);

	memset(&opt, 0, sizeof(opt));

	while ((i = getopt(argc, argv, "dfhins:")) != EOF)
		switch (i) {
		case 'd':
			opt.debug = 1;
			break;
		case 'f':
			opt.force++;
			break;
		case 'h':
			usage();
		case 'i':
			opt.info = 1;
			break;
		case 'n':
			opt.ro_flag = MS_RDONLY;
			break;
		case 's':
			opt.bytes = get_new_volume_size(optarg);
			break;
		case 'v':
			opt.verbose++;
			break;
		default:
			usage();
		}
	if (optind == argc)
		usage();
	opt.volume = argv[optind++];
	if (optind < argc)
		usage();

	stderr = stdout;
	if (!opt.debug)
		if (!(stderr = fopen("/dev/null", "rw")))
			perr_exit("Couldn't open /dev/null");


	/* If no '-s size' then estimate smallest shrunken volume size */
	if (!opt.bytes)
		opt.info = 1;

	if (opt.info) {
		if (opt.bytes) {
			printf(NERR_PREFIX "It makes no sense to use -i and "
				"-s together.\n");
			usage();
		}
		opt.ro_flag = MS_RDONLY;
	}
}


s64 nr_clusters_to_bitmap_byte_size(s64 nr_clusters)
{
	s64 bm_bsize;

	bm_bsize = rounded_up_division(nr_clusters, 8);

	/* Needs to be multiple of 8 bytes */
	bm_bsize = (bm_bsize + 7) & ~7;
	Dprintf("Bitmap byte size  : %lld (%lld clusters)\n",
	       bm_bsize, rounded_up_division(bm_bsize, vol->cluster_size));

	return bm_bsize;
}


void build_lcn_usage_bitmap(ATTR_RECORD *a)
{
	runlist *rl;
	int i, j;

	if (!a->non_resident)
		return;

	if (!(rl = ntfs_decompress_mapping_pairs(vol, a, NULL)))
		perr_exit("ntfs_decompress_mapping_pairs");

	for (i = 0; rl[i].length; i++) {
		if (rl[i].lcn == LCN_HOLE || rl[i].lcn == LCN_RL_NOT_MAPPED)
			continue;
		for (j = 0; j < rl[i].length; j++) {
			u64 k = (u64)rl[i].lcn + j;
			if (ntfs_get_and_set_bit(lcn_bitmap.bm, k, 1))
				err_exit("Cluster %lu referenced twice!\n"
					 "You didn't shutdown your Windows"
					 "properly?", k);
		}
	}
	free(rl);
}


void walk_attributes(MFT_RECORD *mr)
{
	ntfs_attr_search_ctx *ctx;

	if (!(ctx = ntfs_get_attr_search_ctx(NULL, mr)))
		perr_exit("ntfs_get_attr_search_ctx");

	while (!ntfs_walk_attrs(ctx)) {
		if (ctx->attr->type == AT_END)
			break;
		build_lcn_usage_bitmap(ctx->attr);
	}

	ntfs_put_attr_search_ctx(ctx);
}


void get_bitmap_data(ntfs_volume *vol, struct bitmap *bm)
{
	ntfs_inode *ni;
	ntfs_attr_search_ctx *ctx;

	if (!(ni = ntfs_open_inode(vol, (MFT_REF)FILE_Bitmap)))
		perr_exit("ntfs_open_inode");

	if (!(ctx = ntfs_get_attr_search_ctx(ni, NULL)))
		perr_exit("ntfs_get_attr_search_ctx");

	if (ntfs_lookup_attr(AT_DATA, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx))
		perr_exit("ntfs_lookup_attr");

	/* FIXME: get_attribute_value_length() can't handle extents */
	bm->size = get_attribute_value_length(ctx->attr);

	if (!(bm->bm = (u8 *)malloc(bm->size)))
	    perr_exit("get_bitmap_data");

	if (get_attribute_value(vol, ni->mrec, ctx->attr, bm->bm) != bm->size)
		perr_exit("Couldn't get $Bitmap $DATA\n");

	ntfs_put_attr_search_ctx(ctx);
	ntfs_close_inode(ni);
}


void compare_bitmaps(struct bitmap *a, struct bitmap *b)
{
	int i;

	if (a->size != b->size)
		err_exit("$Bitmap file size doesn't match "
			 "calculated size ((%d != %d)\n", a->size, b->size);

	for (i = 0; i < a->size; i++)
		if (a->bm[i] != b->bm[i])
			err_exit("Cluster bitmaps differ at %d (%d != %d)\n"
				 "You didn't shutdown your Windows properly?",
				 i, a->bm[i], b->bm[i]);
}


void progress_init(struct progress_bar *p, u64 start, u64 stop, int res)
{
	p->start = start;
	p->stop = stop;
	p->unit = 100.0 / (stop - start);
	p->resolution = res;
}


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

void walk_inodes()
{
	s32 inode = 0;
	s64 last_mft_rec;
	MFT_REF mref;
	MFT_RECORD *mrec = NULL;
	struct progress_bar progress;

	printf("Scanning volume ...\n");

	last_mft_rec = vol->nr_mft_records - 1;
	progress_init(&progress, inode, last_mft_rec, 100);

	for (; inode <= last_mft_rec; inode++) {
		progress_update(&progress, inode);

		mref = (MFT_REF)inode;
		if (ntfs_file_record_read(vol, mref, &mrec, NULL)) {
			/* FIXME: continue only if it make sense, e.g.
			   MFT record not in use based on $MFT bitmap */
			if (errno == EIO)
				continue;
			perr_exit("Reading inode %ld failed", inode);
		}
		if (!(mrec->flags & MFT_RECORD_IN_USE))
			continue;

		walk_attributes(mrec);
	}
	if (mrec)
		free(mrec);
}


void advise_on_resize()
{
	u64 i, old_b, new_b, g_b, old_mb, new_mb, g_mb;
	int fragmanted_end;

	for (i = vol->nr_clusters - 1; i > 0; i--)
		if (ntfs_get_bit(lcn_bitmap.bm, i))
			break;

	i += 2; /* first free + we reserve one for the backup boot sector */
	fragmanted_end = (i >= vol->nr_clusters) ? 1 : 0;

	if (fragmanted_end || !opt.info) {
		printf(fragmented_volume_msg);
		if (fragmanted_end)
			exit(1);
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
	exit(1);
}


void look_for_bad_sector(ATTR_RECORD *a)
{
	runlist *rl;
	int i;

	rl = ntfs_decompress_mapping_pairs(vol, a, NULL);
	if (!rl)
		perr_exit("ntfs_decompress_mapping_pairs");

	for (i = 0; rl[i].length; i++)
		if (rl[i].lcn != LCN_HOLE)
			err_exit("Device has bad sectors, not supported\n");

	free(rl);
}


void rl_set(runlist *rl, VCN vcn, LCN lcn, s64 len)
{
	rl->vcn = vcn;
	rl->lcn = lcn;
	rl->length = len;
}


/*
 * $Bitmap can overlap the end of the volume. Any bits in this region
 * must be set. This region also encompasses the backup boot sector.
 */
void bitmap_file_data_fixup(s64 cluster, struct bitmap *bm)
{
	for (; cluster < bm->size << 3; cluster++)
		ntfs_set_bit(bm->bm, (u64)cluster, 1);
}


/*
 * FIXME: this function should go away and instead using a generalized
 * "truncate_bitmap_unnamed_attr()"
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

	mp_size = ntfs_get_size_for_mapping_pairs(vol, rl_bad);

	if (!(mp = (char *)calloc(1, mp_size)))
		perr_exit("Couldn't get memory");

	if (ntfs_build_mapping_pairs(vol, mp, mp_size, rl_bad))
		exit(1);

	memcpy((char *)a + a->mapping_pairs_offset, mp, mp_size);
	a->highest_vcn = cpu_to_le64(nr_clusters - 1LL);
	a->allocated_size = cpu_to_le64(nr_clusters * vol->cluster_size);
	a->data_size = cpu_to_le64(nr_clusters * vol->cluster_size);

	free(rl_bad);
	free(mp);
}


void truncate_bitmap_unnamed_attr(ATTR_RECORD *a, s64 nr_clusters)
{
	runlist *rl;
	s64 bm_bsize, size;
	s64 nr_bm_clusters;
	int i, j, mp_size;
	int trunc_at = -1;	/* FIXME: -1 means unset */
	char *mp;


	if (!a->non_resident)
		/* FIXME: handle resident attribute value */
		perr_exit("Resident data attribute in $Bitmap not supported!");

	bm_bsize = nr_clusters_to_bitmap_byte_size(nr_clusters);
	nr_bm_clusters = rounded_up_division(bm_bsize, vol->cluster_size);

	if (!(rl = ntfs_decompress_mapping_pairs(vol, a, NULL)))
		perr_exit("ntfs_decompress_mapping_pairs");

	/* Unallocate truncated clusters in $Bitmap */
	for (i = 0; rl[i].length; i++) {
		if (rl[i].vcn + rl[i].length <= nr_bm_clusters)
			continue;
		if (trunc_at == -1)
			trunc_at = i;
		if (rl[i].lcn == LCN_HOLE || rl[i].lcn == LCN_RL_NOT_MAPPED)
			continue;
		for (j = 0; j < rl[i].length; j++)
			if (rl[i].vcn + j >= nr_bm_clusters) {
				u64 k = (u64)rl[i].lcn + j;
				ntfs_set_bit(lcn_bitmap.bm, k, 0);
				Dprintf("Unallocate cluster: "
				       "%llu (%llx)\n", k, k);
			}
	}

	/* FIXME: realloc lcn_bitmap.bm (if it's worth the risk) */
	lcn_bitmap.size = bm_bsize;
	bitmap_file_data_fixup(nr_clusters, &lcn_bitmap);

	if (trunc_at != -1) {
		/* NOTE: 'i' always > 0 */
		i = nr_bm_clusters - rl[trunc_at].vcn;
		rl[trunc_at].length = i;
		rl_set(rl + trunc_at + 1, nr_bm_clusters, -1LL, 0LL);

		Dprintf("Runlist truncated at index %d, "
		       "new cluster length %d\n", trunc_at, i);
	}

	if (!opt.ro_flag) {
		size = ntfs_rl_pwrite(vol, rl, 0, bm_bsize, lcn_bitmap.bm);
		if (bm_bsize != size) {
			if (size == -1)
				perr_exit("Couldn't write $Bitmap");
			printf("Couldn't write full $Bitmap file "
			       "(%lld from %lld)\n", size, bm_bsize);
			exit(1);
		}
	}

	mp_size = ntfs_get_size_for_mapping_pairs(vol, rl);

	if (!(mp = (char *)calloc(1, mp_size)))
		perr_exit("Couldn't get memory");

	if (ntfs_build_mapping_pairs(vol, mp, mp_size, rl))
		exit(1);

	memcpy((char *)a + a->mapping_pairs_offset, mp, mp_size);
	a->highest_vcn = cpu_to_le64(nr_bm_clusters - 1LL);
	a->allocated_size = cpu_to_le64(nr_bm_clusters * vol->cluster_size);
	a->data_size = cpu_to_le64(bm_bsize);
	a->initialized_size = cpu_to_le64(bm_bsize);

	free(rl);
	free(mp);
}


void lookup_data_attr(MFT_REF mref, char *aname, ntfs_attr_search_ctx **ctx)
{
	ntfs_inode *ni;
	uchar_t *ustr = NULL;
	int len = 0;

	if (!(ni = ntfs_open_inode(vol, mref)))
		perr_exit("ntfs_open_inode");

	if (NInoAttrList(ni))
		perr_exit("Attribute list attribute not yet supported");

	if (!(*ctx = ntfs_get_attr_search_ctx(ni, NULL)))
		perr_exit("ntfs_get_attr_search_ctx");

	if (aname && ((len = ntfs_mbstoucs(aname, &ustr, 0)) == -1))
		perr_exit("Unable to convert string to Unicode");

	if (!ustr || !len) {
		ustr = AT_UNNAMED;
		len = 0;
	}

	if (ntfs_lookup_attr(AT_DATA, ustr, len, 0, 0, NULL, 0, *ctx))
		perr_exit("ntfs_lookup_attr");

	if (ustr != AT_UNNAMED)
		free(ustr);
}


int write_mft_record(ntfs_attr_search_ctx *ctx)
{
	if (opt.ro_flag)
		return 0;

	return ntfs_mft_record_write(vol, ctx->ntfs_ino->mft_no, ctx->mrec);
}


void truncate_badclust_file(s64 nr_clusters)
{
	ntfs_attr_search_ctx *ctx = NULL;

	printf("Updating $BadClust file ...\n");

	lookup_data_attr((MFT_REF)FILE_BadClus, "$Bad", &ctx);
	look_for_bad_sector(ctx->attr);
	/* FIXME: sanity_check_attr(ctx->attr); */
	/* FIXME: should use an "extended" truncate_bitmap_unnamed_attr() */
	truncate_badclust_bad_attr(ctx->attr, nr_clusters);

	if (write_mft_record(ctx))
		perr_exit("Couldn't update $BadClust");

	/* FIXME: clean up API => ntfs_put_attr_search_ctx() also closes ni */
	ntfs_put_attr_search_ctx(ctx);
}


void truncate_bitmap_file(s64 nr_clusters)
{
	ntfs_attr_search_ctx *ctx = NULL;

	printf("Updating $Bitmap file ...\n");

	lookup_data_attr((MFT_REF)FILE_Bitmap, NULL, &ctx);
	/* FIXME: sanity_check_attr(ctx->attr); */
	truncate_bitmap_unnamed_attr(ctx->attr, nr_clusters);

	if (write_mft_record(ctx))
		perr_exit("Couldn't update $Bitmap");

	ntfs_put_attr_search_ctx(ctx);
}


void setup_lcn_bitmap()
{
	/* Determine lcn bitmap byte size and allocate it. */
	lcn_bitmap.size = nr_clusters_to_bitmap_byte_size(vol->nr_clusters);

	if (!(lcn_bitmap.bm = (unsigned char *)calloc(1, lcn_bitmap.size)))
		perr_exit("Failed to allocate internal buffer");

	bitmap_file_data_fixup(vol->nr_clusters, &lcn_bitmap);
}


/* FIXME: should be done using ntfs_* functions */
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


void print_volume_size(char *str, ntfs_volume *v, s64 nr_clusters)
{
	s64 b; /* volume size in bytes */

	b = nr_clusters * v->cluster_size;
	printf("%s: %lld bytes (%lld MB)\n",
	       str, b, rounded_up_division(b, NTFS_MBYTE));
}


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
		perr_printf("ntfs_mount failed");
		if (errno == EINVAL) {
			printf("Apparently device '%s' doesn't have a "
			       "valid NTFS. Maybe you selected\nthe whole "
			       "disk instead of a partition (e.g. /dev/hda, "
			       "not /dev/hda8)?\n", opt.volume);
		}
		exit(1);
	}

	if (vol->flags & VOLUME_IS_DIRTY)
		if (opt.force-- <= 0)
			err_exit("Volume is dirty. Run chkdsk and "
				 "please try again (or see -f option).\n");

	printf("NTFS volume version: %d.%d\n", vol->major_ver, vol->minor_ver);
	if (ntfs_is_version_supported(vol))
		perr_exit("Unknown NTFS version");

	Dprintf("Cluster size       : %u\n", vol->cluster_size);
	print_volume_size("Current volume size", vol, vol->nr_clusters);
}


void prepare_volume_fixup()
{
	if (!opt.ro_flag) {
		u16 flags;

		flags = vol->flags | VOLUME_IS_DIRTY;
		if (vol->major_ver >= 2)
			flags |= VOLUME_MOUNTED_ON_NT4;

		printf("Schedule chkdsk NTFS consistency check at Windows boot time ...\n");
		if (ntfs_set_volume_flags(vol, flags))
			perr_exit("Failed to set $Volume dirty");

		printf("Resetting $LogFile ... "
		       "(this might take a while)\n");
		if (ntfs_reset_logfile(vol))
			perr_exit("Failed to reset $LogFile");
	}
}


int main(int argc, char **argv)
{
	struct bitmap on_disk_lcn_bitmap;
	s64 new_volume_size = 0;	/* in clusters */
	int i;

	parse_options(argc, argv);

	mount_volume();

	if (opt.bytes) {
		/* Take the integer part: when shrinking we don't want
		   to make the volume to be bigger than requested.
		   Later on we will also decrease this value to save
		   room for the backup boot sector */
		new_volume_size = opt.bytes / vol->cluster_size;
		print_volume_size("New volume size    ", vol, new_volume_size);
	}

	setup_lcn_bitmap();

	walk_inodes();

	get_bitmap_data(vol, &on_disk_lcn_bitmap);
	compare_bitmaps(&on_disk_lcn_bitmap, &lcn_bitmap);
	free(on_disk_lcn_bitmap.bm);

	if (opt.info)
		advise_on_resize();

	/* FIXME: check new_volume_size validity */

	/* Backup boot sector at the end of device isn't counted in NTFS
	   volume size thus we have to reserve space for. We don't trust
	   the user does this for us: better to be on the safe side ;) */
	if (new_volume_size)
		--new_volume_size;

	if (new_volume_size > vol->nr_clusters)
		err_exit("Volume enlargement not yet supported\n");
	else if (new_volume_size == vol->nr_clusters) {
		printf("Nothing to do: NTFS volume size is already OK.\n");
		exit(0);
	}

	for (i = new_volume_size; i < vol->nr_clusters; i++)
		if (ntfs_get_bit(lcn_bitmap.bm, (u64)i)) {
			/* FIXME: relocate cluster */
			advise_on_resize();
		}

	if (opt.force-- <= 0 && !opt.ro_flag) {
		printf(resize_warning_msg);
		proceed_question();
	}

	prepare_volume_fixup();

	truncate_badclust_file(new_volume_size);
	truncate_bitmap_file(new_volume_size);
	update_bootsector(new_volume_size);

	/* We don't create backup boot sector because we don't know where the
	   partition will be split. The scheduled chkdsk will fix it anyway */

	if (opt.ro_flag) {
		printf("The read-only test run ended successfully.\n");
		exit(0);
	}

	printf("Syncing device ...\n");
	if (fsync(vol->fd) == -1)
		perr_exit("fsync");

	printf(resize_important_msg, vol->dev_name);
	return 0;
}

