/**
 * ntfsclone - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2003-2004 Szabolcs Szakacsits
 *
 * Clone NTFS data and/or metadata to a sparse file, device or stdout.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "config.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_VFS_H
#	include <sys/vfs.h>
#endif
#include <fcntl.h>
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

#if defined(linux) && defined(_IO) && !defined(BLKGETSIZE)
#define BLKGETSIZE	_IO(0x12,96)  /* Get device size in 512-byte blocks. */
#endif
#if defined(linux) && defined(_IOR) && !defined(BLKGETSIZE64)
#define BLKGETSIZE64	_IOR(0x12,114,size_t)	/* Get device size in bytes. */
#endif

static const char *EXEC_NAME = "ntfsclone";

struct {
	int verbose;
	int quiet;
	int debug;
	int force;
	int overwrite;
	int std_out;
	int blkdev_out;		/* output file is block device */   
	int metadata_only;
	char *output;
	char *volume;
	struct statfs stfs;
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

typedef struct {
	ntfs_inode *ni;			/* inode being processed */
	ntfs_attr_search_ctx *ctx;	/* inode attribute being processed */
	s64 inuse;			/* number of clusters in use */
} ntfs_walk_clusters_ctx;

typedef int (ntfs_walk_op)(ntfs_inode *ni, void *data);

struct ntfs_walk_cluster {
	ntfs_walk_op *inode_op;		/* not implemented yet */
	ntfs_walk_clusters_ctx *image;
};


ntfs_volume *vol = NULL;
struct bitmap lcn_bitmap;

int fd_out;
FILE *msg_out = NULL;

int nr_used_mft_records = 0;
int wipe = 0;
int wiped_unused_mft_data = 0;
int wiped_unused_mft = 0;
int wiped_resident_data = 0;
int wiped_timestamp_data = 0;

#define NTFS_MBYTE (1000 * 1000)

#define ERR_PREFIX   "ERROR"
#define PERR_PREFIX  ERR_PREFIX "(%d): "
#define NERR_PREFIX  ERR_PREFIX ": "

#define LAST_METADATA_INODE  	11

#define NTFS_MAX_CLUSTER_SIZE 	65536

#define rounded_up_division(a, b) (((a) + (b - 1)) / (b))

#define read_all(f, p, n)  io_all((f), (p), (n), 0)
#define write_all(f, p, n) io_all((f), (p), (n), 1)

GEN_PRINTF(Eprintf, stderr,  NULL,         FALSE)
GEN_PRINTF(Vprintf, msg_out, &opt.verbose, TRUE)
GEN_PRINTF(Qprintf, msg_out, &opt.quiet,   FALSE)
static GEN_PRINTF(Printf,  msg_out, NULL,         FALSE)


static void perr_printf(const char *fmt, ...)
{
	va_list ap;
	int eo = errno;

	Printf(PERR_PREFIX, eo);
	va_start(ap, fmt);
	vfprintf(msg_out, fmt, ap);
	va_end(ap);
	Printf(": %s\n", strerror(eo));
	fflush(msg_out);
}

static void err_printf(const char *fmt, ...)
{
	va_list ap;

	Printf(NERR_PREFIX);
	va_start(ap, fmt);
	vfprintf(msg_out, fmt, ap);
	va_end(ap);
	fflush(msg_out);
}

static int err_exit(const char *fmt, ...)
{
	va_list ap;

	Printf(NERR_PREFIX);
	va_start(ap, fmt);
	vfprintf(msg_out, fmt, ap);
	va_end(ap);
	fflush(msg_out);
	exit(1);
}


static int perr_exit(const char *fmt, ...)
{
	va_list ap;
	int eo = errno;

	Printf(PERR_PREFIX, eo);
	va_start(ap, fmt);
	vfprintf(msg_out, fmt, ap);
	va_end(ap);
	Printf(": %s\n", strerror(eo));
	fflush(msg_out);
	exit(1);
}


static void usage(void)
{
	Eprintf("\nUsage: %s [options] device\n"
		"    Efficiently clone NTFS to a sparse file, device or standard output.\n"
		"\n"
		"    -o, --output FILE      Clone NTFS to the non-existent FILE\n"
		"    -O, --overwrite FILE   Clone NTFS to FILE, overwriting if exists\n"
		"    -m, --metadata         Clone *only* metadata (for NTFS experts)\n"
		"    -f, --force            Force to progress (DANGEROUS)\n"
		"    -h, --help             Display this help\n"
#ifdef DEBUG
		"    -d, --debug            Show debug information\n"
#endif
		"\n"
		"    If FILE is '-' then send NTFS data to stdout replacing non used\n"
		"    NTFS and partition space with zeros.\n"
		"\n", EXEC_NAME);
	Eprintf("%s%s\n", ntfs_bugs, ntfs_home);
	exit(1);
}


static void parse_options(int argc, char **argv)
{
	static const char *sopt = "-dfhmo:O:";
	static const struct option lopt[] = {
#ifdef DEBUG
		{ "debug",	no_argument,		NULL, 'd' },
#endif
		{ "force",	no_argument,		NULL, 'f' },
		{ "help",	no_argument,		NULL, 'h' },
		{ "metadata",	no_argument,		NULL, 'm' },
		{ "output",	required_argument,	NULL, 'o' },
		{ "overwrite",	required_argument,	NULL, 'O' },
		{ NULL, 0, NULL, 0 }
	};

	char c;

	memset(&opt, 0, sizeof(opt));

	while ((c = getopt_long(argc, argv, sopt, lopt, NULL)) != (char)-1) {
		switch (c) {
		case 1:	/* A non-option argument */
			if (opt.volume)
				usage();
			opt.volume = argv[optind-1];
			break;
		case 'd':
			opt.debug++;
			break;
		case 'f':
			opt.force++;
			break;
		case 'h':
		case '?':
			usage();
		case 'm':
			opt.metadata_only++;
			break;
		case 'O':
			opt.overwrite++;
		case 'o':
			if (opt.output)
				usage();
			opt.output = optarg;
			break;
		default:
			err_printf("Unknown option '%s'.\n", argv[optind-1]);
			usage();
		}
	}
	
	if (opt.output == NULL) {
		err_printf("You must specify an output file.\n");
		usage();
	}

	if (strcmp(opt.output, "-") == 0)
		opt.std_out++;

	if (opt.volume == NULL) {
		err_printf("You must specify a device file.\n");
		usage();
	}

	if (opt.metadata_only && opt.std_out)
		err_exit("Cloning only metadata to stdout isn't supported!\n");

	if (!opt.std_out) {
		struct stat st;
		
		if (stat(opt.output, &st) == -1) {
			if (errno != ENOENT)
				perr_exit("Couldn't access '%s'", opt.output); 
		} else {
			if (!opt.overwrite)
				err_exit("Output file '%s' already exists.\n"
					 "Use option --overwrite if you want to"
					 " replace its content.\n", opt.output);

			if (S_ISBLK(st.st_mode)) {
				opt.blkdev_out = 1;
				if (opt.metadata_only)
					err_exit("Cloning only metadata to a "
					     "block device isn't supported!\n");
			}
		}
	}	
		
	msg_out = stdout;
	
	/* FIXME: this is a workaround for loosing debug info if stdout != stderr
	   and for the uncontrollable verbose messages in libntfs. Ughhh. */
	if (opt.std_out)
		msg_out = stderr;
	else if (opt.debug)
		stderr = stdout; 
	else
		if (!(stderr = fopen("/dev/null", "rw")))
			perr_exit("Couldn't open /dev/null");
}

static void progress_init(struct progress_bar *p, u64 start, u64 stop, int res)
{
	p->start = start;
	p->stop = stop;
	p->unit = 100.0 / (stop - start);
	p->resolution = res;
}


static void progress_update(struct progress_bar *p, u64 current)
{
	float percent = p->unit * current;

	if (current != p->stop) {
		if ((current - p->start) % p->resolution)
			return;
		Printf("%6.2f percent completed\r", percent);
	} else
		Printf("100.00 percent completed\n");
	fflush(msg_out);
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
	Dprintf("Bitmap byte size  : %lld (%lld clusters)\n",
	       bm_bsize, rounded_up_division(bm_bsize, vol->cluster_size));

	return bm_bsize;
}

static s64 is_critical_metadata(ntfs_walk_clusters_ctx *image, runlist *rl)
{
	s64 inode = image->ni->mft_no;

	if (inode <= LAST_METADATA_INODE) {
		if (inode != FILE_LogFile)
			return rl->length;

		if (image->ctx->attr->type == AT_DATA) {
			/* Save at least the first 8 KiB of FILE_LogFile */
			s64 s = (s64)8192 - rl->vcn * vol->cluster_size;
			if (s > 0) {
				s = rounded_up_division(s, vol->cluster_size);
				if (rl->length < s)
					s = rl->length;
				return s;
			}
			return 0;
		}
	}
	
	if (image->ctx->attr->type != AT_DATA)
		return rl->length;

	return 0;
}


static int io_all(void *fd, void *buf, int count, int do_write)
{
	int i;
	struct ntfs_device *dev = (struct ntfs_device *)fd;
	
	while (count > 0) {
		if (do_write)
			i = write(*(int *)fd, buf, count);
		else
			i = dev->d_ops->read(dev, buf, count);
		if (i < 0) {
			if (errno != EAGAIN && errno != EINTR)
				return -1;
		} else {
			count -= i;
			buf = i + (char *) buf;
		}
	}
	return 0;
}


static void copy_cluster(void)
{
	char buff[NTFS_MAX_CLUSTER_SIZE]; /* overflow checked at mount time */

	if (read_all(vol->dev, buff, vol->cluster_size) == -1)
		perr_exit("read_all");

	if (write_all(&fd_out, buff, vol->cluster_size) == -1) {
		int err = errno;
		perr_printf("Write failed");
		if (err == EIO && opt.stfs.f_type == 0x517b)
			Printf("Apparently you tried to clone to a remote "
			       "Windows computer but they don't\nhave "
			       "efficient sparse file handling by default. "
			       "Please try a different method.\n");
		exit(1);
	}
}

static void lseek_to_cluster(s64 lcn)
{
	off_t pos;
	
	pos = (off_t)(lcn * vol->cluster_size);
	
	if (vol->dev->d_ops->seek(vol->dev, pos, SEEK_SET) == (off_t)-1)
		perr_exit("lseek input");

	if (opt.std_out)
		return;
	
	if (lseek(fd_out, pos, SEEK_SET) == (off_t)-1)
		perr_exit("lseek output");
}

static void dump_clusters(ntfs_walk_clusters_ctx *image, runlist *rl)
{
	s64 i, len; /* number of clusters to copy */
	
	if (opt.std_out || !opt.metadata_only)
		return;
	
	if (!(len = is_critical_metadata(image, rl)))
		return;
	
	lseek_to_cluster(rl->lcn);
	
	/* FIXME: this could give pretty suboptimal performance */
	for (i = 0; i < len; i++)
		copy_cluster();
}

static void clone_ntfs(u64 nr_clusters)
{
	s64 i, pos, count;
	u8 bm[NTFS_BUF_SIZE];
	void *buf;
	u32 csize = vol->cluster_size;
	u64 p_counter = 0;
	struct progress_bar progress;

	Printf("Cloning NTFS ...\n");
	
	if ((buf = calloc(1, csize)) == NULL)
		perr_exit("dump_to_stdout");
	
	progress_init(&progress, p_counter, nr_clusters, 100);
	
	pos = 0;
	while (1) {
		count = ntfs_attr_pread(vol->lcnbmp_na, pos, NTFS_BUF_SIZE, bm);
		if (count == -1)
			perr_exit("Couldn't read $Bitmap (pos = %lld)\n", pos);

		if (count == 0)
			return;

		for (i = 0; i < count; i++, pos++) {
			s64 cl;  /* current cluster */	  

			for (cl = pos * 8; cl < (pos + 1) * 8; cl++) {

				if (cl > vol->nr_clusters - 1)
					return;
				
				if (ntfs_bit_get(bm, i * 8 + cl % 8)) {
					progress_update(&progress, ++p_counter);
					lseek_to_cluster(cl);
					copy_cluster();
					continue;
				}
				
				if (opt.std_out) {
					progress_update(&progress, ++p_counter);
					if (write_all(&fd_out, buf, csize) == -1)
						perr_exit("write_all");
				}
			}
		}
	}
}

#define WIPE_TIMESTAMPS(atype, attr)				\
do {								\
	atype *ats;						\
	ats = (atype *)((char*)(attr) + (attr)->value_offset); 	\
								\
	ats->creation_time = 0;					\
	ats->last_data_change_time = 0;				\
	ats->last_mft_change_time= 0;				\
	ats->last_access_time = 0;				\
								\
	wiped_timestamp_data += 32;				\
								\
} while(0)

static void wipe_timestamps(ntfs_walk_clusters_ctx *image)
{
	ATTR_RECORD *a = image->ctx->attr;
	
	if (image->ni->mft_no <= LAST_METADATA_INODE)
		return;

	if (a->type == AT_FILE_NAME) 
		WIPE_TIMESTAMPS(FILE_NAME_ATTR, a);

	else if (a->type == AT_STANDARD_INFORMATION)	
		WIPE_TIMESTAMPS(STANDARD_INFORMATION, a);
}

static void wipe_resident_data(ntfs_walk_clusters_ctx *image)
{
	ATTR_RECORD *a;
	u32 i;
	int n = 0;
	char *p;

	a = image->ctx->attr;
	p = (char *)a + a->value_offset;
	
	if (image->ni->mft_no <= LAST_METADATA_INODE)
		return;
	
	if (a->type != AT_DATA)
		return;
	
	for (i = 0; i < a->value_length; i++) {
		if (p[i]) {
			p[i] = 0;
			n++;
		}	
	}		
			
	wiped_resident_data += n;
}

static void walk_runs(struct ntfs_walk_cluster *walk)
{
	int i, j;
	runlist *rl;
	ATTR_RECORD *a;
	ntfs_attr_search_ctx *ctx;

	ctx = walk->image->ctx;
	a = ctx->attr;

	if (!a->non_resident) {
		if (wipe) {
			wipe_resident_data(walk->image);
			wipe_timestamps(walk->image);
		}
		return;
	}

	if (!(rl = ntfs_mapping_pairs_decompress(vol, a, NULL)))
		perr_exit("ntfs_decompress_mapping_pairs");

	for (i = 0; rl[i].length; i++) {
		s64 lcn = rl[i].lcn;
		s64 lcn_length = rl[i].length;

		if (lcn == LCN_HOLE || lcn == LCN_RL_NOT_MAPPED)
			continue;

		/* FIXME: ntfs_mapping_pairs_decompress should return error */
		if (lcn < 0 || lcn_length < 0)
			err_exit("Corrupt runlist in inode %lld attr %x LCN "
				 "%llx length %llx\n", ctx->ntfs_ino->mft_no,
				 le32_to_cpu (a->type), lcn, lcn_length);
		
		if (!wipe)
			dump_clusters(walk->image, rl + i);
		
		for (j = 0; j < lcn_length; j++) {
			u64 k = (u64)lcn + j;
			if (ntfs_bit_get_and_set(lcn_bitmap.bm, k, 1))
				err_exit("Cluster %lu referenced twice!\n"
					 "You didn't shutdown your Windows"
					 "properly?\n", k);
		}

		walk->image->inuse += lcn_length;
	}
	
	free(rl);
}


static void walk_attributes(struct ntfs_walk_cluster *walk)
{
	ntfs_attr_search_ctx *ctx;

	if (!(ctx = ntfs_attr_get_search_ctx(walk->image->ni, NULL)))
		perr_exit("ntfs_get_attr_search_ctx");

	while (!ntfs_attrs_walk(ctx)) {
		if (ctx->attr->type == AT_END)
			break;

		walk->image->ctx = ctx;
		walk_runs(walk);
	}

	ntfs_attr_put_search_ctx(ctx);
}



static void compare_bitmaps(struct bitmap *a)
{
	s64 i, pos, count;
	int mismatch = 0;
	u8 bm[NTFS_BUF_SIZE];

	Printf("Accounting clusters ...\n");

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

				if (++mismatch > 10)
					continue;

				Printf("Cluster accounting failed at %lld "
						"(0x%llx): %s cluster in "
						"$Bitmap\n", (long long)cl,
						(unsigned long long)cl,
						bit ? "missing" : "extra");
			}
		}
	}

	if (mismatch) {
		Printf("Totally %d cluster accounting mismatches.\n", 
		       mismatch);
		err_exit("Filesystem check failed! Windows wasn't shutdown "
			 "properly or inconsistent\nfilesystem. Please run "
			 "chkdsk on Windows.\n");
	}
}


static int wipe_data(char *p, int pos, int len)
{
	int wiped = 0;
	
	p += pos;
	for (; len > 0; len--) {
		if (p[len]) {
			p[len] = 0;
			wiped++;
		}	
	}		

	return wiped;
}

static void wipe_unused_mft_data(ntfs_inode *ni)
{
	int unused;
	MFT_RECORD *m = ni->mrec;
	
	/* FIXME: broken MFTMirr update was fixed in libntfs, check if OK now */
	if (ni->mft_no <= LAST_METADATA_INODE)
		return;
	
	unused = m->bytes_allocated - m->bytes_in_use;
	wiped_unused_mft_data += wipe_data((char *)m, m->bytes_in_use, unused);
}

static void wipe_unused_mft(ntfs_inode *ni)
{
	int unused;
	MFT_RECORD *m = ni->mrec;
	
	/* FIXME: broken MFTMirr update was fixed in libntfs, check if OK now */
	if (ni->mft_no <= LAST_METADATA_INODE)
		return;
	
	unused = m->bytes_in_use - sizeof(MFT_RECORD);
	wiped_unused_mft += wipe_data((char *)m, sizeof(MFT_RECORD), unused);
}


static int walk_clusters(ntfs_volume *volume, struct ntfs_walk_cluster *walk)
{
	s64 inode = 0;
	s64 last_mft_rec;
	ntfs_inode *ni;
	struct progress_bar progress;

	Printf("Scanning volume ...\n");

	last_mft_rec = volume->nr_mft_records - 1;
	progress_init(&progress, inode, last_mft_rec, 100);

	for (; inode <= last_mft_rec; inode++) {
		
		int err, deleted_inode;
		MFT_REF mref = (MFT_REF)inode;

		progress_update(&progress, inode);

		/* FIXME: Terrible kludge for libntfs not being able to return
		   a deleted MFT record as inode */
		ni = (ntfs_inode*)calloc(1, sizeof(ntfs_inode));
		if (!ni)
			perr_exit("walk_clusters");
		
		ni->vol = volume;

		err = ntfs_file_record_read(volume, mref, &ni->mrec, NULL);
		if (err == -1) {
			free(ni);
			continue;
		}	

	        deleted_inode = !(ni->mrec->flags & MFT_RECORD_IN_USE);

	        if (deleted_inode) {

			ni->mft_no = MREF(mref);
			if (wipe) {
				wipe_unused_mft(ni);
				wipe_unused_mft_data(ni);
				if (ntfs_mft_record_write(volume, ni->mft_no, ni->mrec))
					perr_exit("ntfs_mft_record_write");
			}		
		}

	       	if (ni->mrec)
	        	free(ni->mrec);
		free(ni);

	        if (deleted_inode) 
			continue;
		
		if ((ni = ntfs_inode_open(volume, mref)) == NULL) {
			/* FIXME: continue only if it make sense, e.g.
			   MFT record not in use based on $MFT bitmap */
			if (errno == EIO || errno == ENOENT)
				continue;
			perr_exit("Reading inode %lld failed", inode);
		}

		if (wipe)
			nr_used_mft_records++;

		if ((ni->mrec->base_mft_record) != 0)
			goto out;

		walk->image->ni = ni;
		walk_attributes(walk);
out:		
		if (wipe) {
			wipe_unused_mft_data(ni);
			if (ntfs_mft_record_write(volume, ni->mft_no, ni->mrec))
				perr_exit("ntfs_mft_record_write");
		}		

		if (ntfs_inode_close(ni))
			perr_exit("ntfs_inode_close for inode %lld", inode);
	}
	
	return 0;
}


/*
 * $Bitmap can overlap the end of the volume. Any bits in this region
 * must be set. This region also encompasses the backup boot sector.
 */
static void bitmap_file_data_fixup(s64 cluster, struct bitmap *bm)
{
	for (; cluster < bm->size << 3; cluster++)
		ntfs_bit_set(bm->bm, (u64)cluster, 1);
}


/*
 * Allocate a block of memory with one bit for each cluster of the disk.
 * All the bits are set to 0, except those representing the region beyond the
 * end of the disk.
 */
static void setup_lcn_bitmap(void)
{
	/* Determine lcn bitmap byte size and allocate it. */
	lcn_bitmap.size = nr_clusters_to_bitmap_byte_size(vol->nr_clusters);

	if (!(lcn_bitmap.bm = (unsigned char *)calloc(1, lcn_bitmap.size)))
		perr_exit("Failed to allocate internal buffer");

	bitmap_file_data_fixup(vol->nr_clusters, &lcn_bitmap);
}


static s64 volume_size(ntfs_volume *volume, s64 nr_clusters)
{
	return nr_clusters * volume->cluster_size;
}


static void print_volume_size(const char *str, s64 bytes)
{
	Printf("%s: %lld bytes (%lld MB)\n", str, (long long)bytes,
			(long long)rounded_up_division(bytes, NTFS_MBYTE));
}


static void print_disk_usage(ntfs_walk_clusters_ctx *image)
{
	s64 total, used;

	total = vol->nr_clusters * vol->cluster_size;
	used = image->inuse * vol->cluster_size;

	Printf("Space in use       : %lld MB (%.1f%%)   ",
			(long long)rounded_up_division(used, NTFS_MBYTE),
			100.0 * ((float)used / total));

	Printf("\n");
}

static void check_if_mounted(const char *device, unsigned long new_mntflag)
{
	unsigned long mntflag;
	
	if (ntfs_check_if_mounted(device, &mntflag))
		perr_exit("Failed to check '%s' mount state", device);

	if (mntflag & NTFS_MF_MOUNTED) {
		if (!(mntflag & NTFS_MF_READONLY))
			err_exit("Device %s is mounted read-write. "
				 "You must 'umount' it first.\n", device);
		if (!new_mntflag)
			err_exit("Device %s is mounted. "
				 "You must 'umount' it first.\n", device);
	}
}

/**
 * First perform some checks to determine if the volume is already mounted, or
 * is dirty (Windows wasn't shutdown properly).  If everything is OK, then mount
 * the volume (load the metadata into memory).
 */
static void mount_volume(unsigned long new_mntflag)
{
	check_if_mounted(opt.volume, new_mntflag);
	
	if (!(vol = ntfs_mount(opt.volume, new_mntflag))) {

		int err = errno;

		perr_printf("ntfs_mount failed");
		if (err == EINVAL) {
			Printf("Apparently device '%s' doesn't have a "
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
	
	if (NTFS_MAX_CLUSTER_SIZE < vol->cluster_size)
		err_exit("Cluster size %u is too large!\n", vol->cluster_size);

	Printf("NTFS volume version: %d.%d\n", vol->major_ver, vol->minor_ver);
	if (ntfs_version_is_supported(vol))
		perr_exit("Unknown NTFS version");

	Printf("Cluster size       : %u bytes\n", vol->cluster_size);
	print_volume_size("Current volume size",
			  volume_size(vol, vol->nr_clusters));
}

struct ntfs_walk_cluster backup_clusters = { NULL, NULL }; 

static int device_offset_valid(int fd, s64 ofs)
{
	char ch;

	if (lseek(fd, ofs, SEEK_SET) >= 0 && read(fd, &ch, 1) == 1)
		return 0;
	return -1;
}

static s64 device_size_get(int fd)
{
	s64 high, low;
#ifdef BLKGETSIZE64
	{	u64 size;

		if (ioctl(fd, BLKGETSIZE64, &size) >= 0) {
			Dprintf("BLKGETSIZE64 nr bytes = %llu (0x%llx)\n",
					(unsigned long long)size,
					(unsigned long long)size);
			return (s64)size;
		}
	}
#endif
#ifdef BLKGETSIZE
	{	unsigned long size;

		if (ioctl(fd, BLKGETSIZE, &size) >= 0) {
			Dprintf("BLKGETSIZE nr 512 byte blocks = %lu "
					"(0x%lx)\n", size, size);
			return (s64)size * 512;
		}
	}
#endif
#ifdef FDGETPRM
	{       struct floppy_struct this_floppy;

		if (ioctl(fd, FDGETPRM, &this_floppy) >= 0) {
			Dprintf("FDGETPRM nr 512 byte blocks = %lu (0x%lx)\n",
					this_floppy.size, this_floppy.size);
			return (s64)this_floppy.size * 512;
		}
	}
#endif
	/*
	 * We couldn't figure it out by using a specialized ioctl,
	 * so do binary search to find the size of the device.
	 */
	low = 0LL;
	for (high = 1024LL; !device_offset_valid(fd, high); high <<= 1)
		low = high;
	while (low < high - 1LL) {
		const s64 mid = (low + high) / 2;

		if (!device_offset_valid(fd, mid))
			low = mid;
		else
			high = mid;
	}
	lseek(fd, 0LL, SEEK_SET);
	return (low + 1LL);
}

static void fsync_clone(int fd)
{
	Printf("Syncing ...\n");
	if (fsync(fd) && errno != EINVAL)
		perr_exit("fsync");
}

static void set_filesize(s64 filesize)
{
	if (fstatfs(fd_out, &opt.stfs) == -1)
		Printf("WARNING: Couldn't get filesystem type: "
		       "%s\n", strerror(errno));
	else if (opt.stfs.f_type == 0x52654973)
		Printf("WARNING: You're using ReiserFS, it has very poor "
		       "performance creating\nlarge sparse files. The next "
		       "operation might take a very long time!\n"
		       "Creating sparse output file ...\n");
	else if (opt.stfs.f_type == 0x517b)
		Printf("WARNING: You're using SMBFS and if the remote share "
		       "isn't Samba but a Windows\ncomputer then the clone "
		       "operation will be very inefficient and may fail!\n");

	if (ftruncate(fd_out, filesize) == -1) {
		int err = errno;
		perr_printf("ftruncate failed for file '%s'", opt.output);
		if (err == E2BIG) {
			Printf("Your system or the destination filesystem "
			       "doesn't support large files.\n");
			if (opt.stfs.f_type == 0x517b) {
				Printf("SMBFS needs minimum Linux kernel "
				       "version 2.4.25 and\n the 'lfs' option"
				       "\nfor mount or smbmount to have large "
				       "file support.\n");
			}
		}
		exit(1);
	}
}
	

int main(int argc, char **argv)
{
	ntfs_walk_clusters_ctx image;
	s64 device_size;        /* in bytes */
	int wiped_total = 0;

	/* print to stderr, stdout can be an NTFS image ... */
	Eprintf("%s v%s\n", EXEC_NAME, VERSION);
	msg_out = stderr;

	parse_options(argc, argv);
	
	utils_set_locale();

	mount_volume(MS_RDONLY);
	
	device_size = ntfs_device_size_get(vol->dev, 1);
	if (device_size <= 0)
		err_exit("Couldn't get device size (%lld)!\n", device_size);

	print_volume_size("Current device size", device_size);

	if (device_size < vol->nr_clusters * vol->cluster_size)
		err_exit("Current NTFS volume size is bigger than the device "
			 "size (%lld)!\nCorrupt partition table or incorrect "
			 "device partitioning?\n", device_size);

	if (opt.std_out) {
	       if ((fd_out = fileno(stdout)) == -1) 
		       perr_exit("fileno for stdout failed");
	} else {
	        /* device_size_get() might need to read() */
		int flags = O_RDWR;
		
		if (!opt.blkdev_out) {
			flags |= O_CREAT | O_TRUNC;
			if (!opt.overwrite)
				flags |= O_EXCL;
		}

		if ((fd_out = open(opt.output, flags, S_IRWXU)) == -1) 
			perr_exit("Opening file '%s' failed", opt.output);
	
		if (opt.blkdev_out) {
			s64 dest_size = device_size_get(fd_out);
			s64 ntfs_size = vol->nr_clusters * vol->cluster_size;
			ntfs_size += 512; /* add backup boot sector */
			if (dest_size < ntfs_size)
				err_exit("Output device size (%lld) is too small"
					 " to fit the NTFS image.\n", dest_size);
			
			check_if_mounted(opt.output, 0);
		} else
			set_filesize(device_size);
	}

	setup_lcn_bitmap();
	memset(&image, 0, sizeof(image));
	backup_clusters.image = &image; 

	walk_clusters(vol, &backup_clusters);
	compare_bitmaps(&lcn_bitmap);
	print_disk_usage(&image);
	
	free(lcn_bitmap.bm);
	
	/* FIXME: save backup boot sector */

	if (opt.std_out || !opt.metadata_only) {
		s64 nr_clusters = opt.std_out ? vol->nr_clusters : image.inuse;
		
		clone_ntfs(nr_clusters);
		fsync_clone(fd_out);
		exit(0);
	}
	
	wipe = 1;	
	opt.volume = opt.output;
	/* 'force' again mount for dirty volumes (e.g. after resize). 
	   FIXME: use mount flags to avoid potential side-effects in future */
	opt.force++;
	mount_volume(0);

	setup_lcn_bitmap();
	memset(&image, 0, sizeof(image));
	backup_clusters.image = &image; 

	walk_clusters(vol, &backup_clusters);
	
	Printf("Num of MFT records       = %8lld\n",
			(long long)vol->nr_mft_records); 
	Printf("Num of used MFT records  = %8d\n", nr_used_mft_records); 
	
	Printf("Wiped unused MFT data    = %8d\n", wiped_unused_mft_data); 
	Printf("Wiped deleted MFT data   = %8d\n", wiped_unused_mft); 
	Printf("Wiped resident user data = %8d\n", wiped_resident_data);
	Printf("Wiped timestamp data     = %8d\n", wiped_timestamp_data);
	
	wiped_total += wiped_unused_mft_data;
	wiped_total += wiped_unused_mft;
	wiped_total += wiped_resident_data;
	wiped_total += wiped_timestamp_data;
	Printf("Wiped totally            = %8d\n", wiped_total);
	
	fsync_clone(fd_out);
	exit(0);
}

