/**
 * ntfsresize - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002 Szabolcs Szakacsits
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

#define NTFS_REPORT_BANNER "\nReport bugs to linux-ntfs-dev@lists.sf.net. " \
                           "Homepage: http://linux-ntfs.sf.net\n"

struct {
	int verbose;
	int debug;
	int ro_flag;
	int force;
	int info;
	s64 size;
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


#define ERR_PREFIX   "==> ERROR"
#define PERR_PREFIX  ERR_PREFIX "(%d): "
#define NERR_PREFIX  ERR_PREFIX ": "

#define rounded_up_division(a, b) (((a) + (b - 1)) / (b))


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
	printf ("Usage: %s [-fhin] [-c clusters] [-s byte[K|M|G]] device\n", EXEC_NAME);
	printf("Shrink a defragmented NTFS volume.\n");
	printf("\n");
	printf ("   -c clusters     Shrink volume to size given in NTFS clusters\n");
	Dprintf("   -d              Show debug information\n");
	printf ("   -f              Force to progress (DANGEROUS)\n");
	printf ("   -h              This help text\n");
	printf ("   -i              Calculate the smallest shrinked volume size supported\n");
	printf ("   -n              No write operations (mount volume read-only)\n");
	printf ("   -s byte[K|M|G]  Shrink volume to size given in byte[K|M|G]\n");
/*	printf ("   -v              Verbose operation\n"); */
	printf("%s", NTFS_REPORT_BANNER);
	exit(1);
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

	/* FIXME: check for overflow */
	switch (*suffix) {
	case 'G':
	case 'g':
		size *= 1024;
	case 'M':
	case 'm':
		size *= 1024;
	case 'K':
	case 'k':
		size *= 1024;
		break;
	default:
		usage();
	}
	
	return size;
}


void parse_options(int argc, char **argv)
{
	char *s;
	int i;

	printf("%s v%s\n", EXEC_NAME, VERSION);

	memset(&opt, 0, sizeof(opt));

	while ((i = getopt(argc, argv, "c:dfhins:")) != EOF)
		switch (i) {
		case 'c':
			opt.size = strtoll(optarg, &s, 0);
			if (*s || opt.size <= 0 || errno == ERANGE)
				err_exit("Illegal number of clusters!\n");
			break;
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


	if (opt.size && opt.bytes) {
		printf(NERR_PREFIX "It makes no sense to use "
		       "-c and -s together.\n");
		usage();
	}

	/* If no '-c clusters' then estimate smallest shrinked volume size */
	if (!opt.size && !opt.bytes)
		opt.info = 1;

	if (opt.info) {
		if (opt.size || opt.bytes) {
			printf(NERR_PREFIX "It makes no sense to use -i and "
				"-%c together.\n", opt.size ? 'c' : 's');
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
	run_list *rl;
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
				err_exit("Cluster %lu "
					 "referenced multiply times!\n", k);
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
			err_exit("Cluster bitmaps differ at %d (%d != %d)\n",
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
		if (ntfs_read_file_record(vol, mref, &mrec, NULL)) {
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
	u64 i;

	for (i = vol->nr_clusters - 1; i > 0; i--)
		if (ntfs_get_bit(lcn_bitmap.bm, i))
			break;
	
	i += 2; /* first free + we reserve one for the backup boot sector */
	if (i >= vol->nr_clusters) {
		if (opt.info)
			printf("The volume end is fragmented. "
			       "This case is not yet supported.\n");
		exit(1);
	}
	
	if (!opt.info)
		printf(NERR_PREFIX "However, ");

	printf("You could resize at cluster %lld gaining %lld MB.\n",
	       i, ((vol->nr_clusters - i) * vol->cluster_size) >> 20);
	exit(1);
}


void look_for_bad_sector(ATTR_RECORD *a)
{
	run_list *rl;
	int i;

	rl = ntfs_decompress_mapping_pairs(vol, a, NULL);
	if (!rl)
		perr_exit("ntfs_decompress_mapping_pairs");

	for (i = 0; rl[i].length; i++)
		if (rl[i].lcn != LCN_HOLE)
			err_exit("Device has bad sectors, not supported\n");

	free(rl);
}


void rl_set(run_list *rl, VCN vcn, LCN lcn, s64 len)
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
	run_list *rl_bad;
	int mp_size;
	char *mp;

	if (!a->non_resident)
		/* FIXME: handle resident attribute value */
		perr_exit("Resident attribute in $BadClust not supported!");

	if (!(rl_bad = (run_list *)malloc(2 * sizeof(run_list))))
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
	run_list *rl;
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

	return ntfs_write_mft_record(vol, ctx->ntfs_ino->mft_no, ctx->mrec);
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
	printf("%s: %lld clusters (%lld MB)\n", 
	       str, nr_clusters, (nr_clusters * v->cluster_size) >> 20);
}


void mount_volume()
{
	unsigned long mntflag;

	if (ntfs_check_if_mounted(opt.volume, &mntflag))
		perr_exit("Failed to check '%s' mount state", opt.volume);

	if (mntflag & NTFS_MF_MOUNTED) {
		if (!(mntflag & NTFS_MF_READONLY))
			err_exit("Device %s is mounted read-write. "
				 "You must umount it first.\n", opt.volume);
		if (!opt.ro_flag)
			err_exit("Device %s is mounted. "
				 "You must umount it first.\n", opt.volume);
	}

	if (!(vol = ntfs_mount(opt.volume, opt.ro_flag)))
                perr_exit("ntfs_mount failed");

	if (vol->flags & VOLUME_IS_DIRTY)
		if (!opt.force--)
			err_exit("Volume is dirty. Run chkdsk and "
				 "please try again (or see -f option).\n");

	printf("NTFS volume version: %d.%d\n", vol->major_ver, vol->minor_ver);
	if (ntfs_is_version_supported(vol))
		perr_exit("Unknown NTFS version"); 

	printf("Cluster size       : %u\n", vol->cluster_size);
	print_volume_size("Current volume size", vol, vol->nr_clusters);
}


void prepare_volume_fixup()
{
	if (!opt.ro_flag) {
		u16 flags;
		
		flags = vol->flags | VOLUME_IS_DIRTY;
		if (vol->major_ver >= 2)
			flags |= VOLUME_MOUNTED_ON_NT4;
		
		printf("Setting NTFS $Volume flag dirty ...\n");
		if (ntfs_set_volume_flags(vol, flags))
			perr_exit("Failed to set $Volume dirty");

		printf("Resetting $LogFile ...\n");
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

	if (opt.size || opt.bytes) {
		new_volume_size = opt.bytes / vol->cluster_size;
		if (opt.size)
			new_volume_size = opt.size;
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
		printf("==> Nothing to do: NTFS volume size is already OK.\n");
		exit(0);
	}

	for (i = new_volume_size; i < vol->nr_clusters; i++)
		if (ntfs_get_bit(lcn_bitmap.bm, (u64)i)) {
			/* FIXME: relocate cluster */
			printf(NERR_PREFIX "Fragmented volume not yet "
			       "supported. Defragment it before resize.\n");
			advise_on_resize();
		}

	/* FIXME: first do all checks before any write attempt */

	prepare_volume_fixup();

	truncate_badclust_file(new_volume_size);
	truncate_bitmap_file(new_volume_size);
	update_bootsector(new_volume_size);

	/* We don't create backup boot sector because we don't know where the 
	   partition will be split. The scheduled chkdsk will fix it anyway */

	printf("==> NTFS had been successfully resized on device %s.\n"
	       "==> Now you can go on to resize/split the partition.\n", 
	       vol->dev_name);

	return 0;
}

