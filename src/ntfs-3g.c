/**
 * ntfs-3g - Third Generation NTFS Driver
 *
 * Copyright (c) 2005-2007 Yura Pakhuchiy
 * Copyright (c) 2005 Yuval Fledel
 * Copyright (c) 2006-2009 Szabolcs Szakacsits
 * Copyright (c) 2007-2009 Jean-Pierre Andre
 * Copyright (c) 2009 Erik Larsson
 *
 * This file is originated from the Linux-NTFS project.
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
 * along with this program (in the main directory of the NTFS-3G
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "config.h"

#include <fuse.h>

#if !defined(FUSE_VERSION) || (FUSE_VERSION < 26)
#error "***********************************************************"
#error "*                                                         *"
#error "*     Compilation requires at least FUSE version 2.6.0!   *"
#error "*                                                         *"
#error "***********************************************************"
#endif

#ifdef FUSE_INTERNAL
#define FUSE_TYPE	"integrated FUSE"
#else
#define FUSE_TYPE	"external FUSE"
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#include <signal.h>
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#include <getopt.h>
#include <syslog.h>
#include <sys/wait.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_MKDEV_H
#include <sys/mkdev.h>
#endif

#include "compat.h"
#include "attrib.h"
#include "inode.h"
#include "volume.h"
#include "dir.h"
#include "unistr.h"
#include "layout.h"
#include "index.h"
#include "ntfstime.h"
#include "misc.h"

typedef enum {
	FSTYPE_NONE,
	FSTYPE_UNKNOWN,
	FSTYPE_FUSE,
	FSTYPE_FUSEBLK
} fuse_fstype;

typedef enum {
	ATIME_ENABLED,
	ATIME_DISABLED,
	ATIME_RELATIVE
} ntfs_atime_t;

typedef struct {
	fuse_fill_dir_t filler;
	void *buf;
} ntfs_fuse_fill_context_t;

typedef enum {
	NF_STREAMS_INTERFACE_NONE,	/* No access to named data streams. */
	NF_STREAMS_INTERFACE_XATTR,	/* Map named data streams to xattrs. */
	NF_STREAMS_INTERFACE_WINDOWS,	/* "file:stream" interface. */
} ntfs_fuse_streams_interface;

typedef struct {
	ntfs_volume *vol;
	unsigned int uid;
	unsigned int gid;
	unsigned int fmask;
	unsigned int dmask;
	ntfs_fuse_streams_interface streams;
	ntfs_atime_t atime;
	BOOL ro;
	BOOL show_sys_files;
	BOOL silent;
	BOOL recover;
	BOOL hiberfile;
	BOOL debug;
	BOOL no_detach;
	BOOL blkdev;
	BOOL mounted;
	struct fuse_chan *fc;
} ntfs_fuse_context_t;

static struct options {
	char	*mnt_point;	/* Mount point */
	char	*options;	/* Mount options */
	char	*device;	/* Device to mount */
} opts;

static const char *EXEC_NAME = "ntfs-3g";
static char def_opts[] = "silent,allow_other,nonempty,";
static ntfs_fuse_context_t *ctx;
static u32 ntfs_sequence;

static const char *usage_msg = 
"\n"
"%s %s %s %d - Third Generation NTFS Driver\n"
"\n"
"Copyright (C) 2005-2007 Yura Pakhuchiy\n"
"Copyright (C) 2006-2009 Szabolcs Szakacsits\n"
"Copyright (C) 2007-2009 Jean-Pierre Andre\n"
"Copyright (C) 2009 Erik Larsson\n"
"\n"
"Usage:    %s [-o option[,...]] <device|image_file> <mount_point>\n"
"\n"
"Options:  ro (read-only mount), remove_hiberfile, uid=, gid=,\n" 
"          umask=, fmask=, dmask=, streams_interface=.\n"
"          Please see the details in the manual (type: man ntfs-3g).\n"
"\n"
"Example: ntfs-3g /dev/sda1 /mnt/windows\n"
"\n"
"%s";

#ifdef FUSE_INTERNAL
int drop_privs(void);
int restore_privs(void);
#else
/*
 * setuid and setgid root ntfs-3g denies to start with external FUSE, 
 * therefore the below functions are no-op in such case.
 */
static int drop_privs(void)    { return 0; }
static int restore_privs(void) { return 0; }

static const char *setuid_msg =
"Mount is denied because setuid and setgid root ntfs-3g is insecure with the\n"
"external FUSE library. Either remove the setuid/setgid bit from the binary\n"
"or rebuild NTFS-3G with integrated FUSE support and make it setuid root.\n"
"Please see more information at http://ntfs-3g.org/support.html#unprivileged\n";

static const char *unpriv_fuseblk_msg =
"Unprivileged user can not mount NTFS block devices using the external FUSE\n"
"library. Either mount the volume as root, or rebuild NTFS-3G with integrated\n"
"FUSE support and make it setuid root. Please see more information at\n"
"http://ntfs-3g.org/support.html#unprivileged\n";
#endif	


/**
 * ntfs_fuse_is_named_data_stream - check path to be to named data stream
 * @path:	path to check
 *
 * Returns 1 if path is to named data stream or 0 otherwise.
 */
static int ntfs_fuse_is_named_data_stream(const char *path)
{
	if (strchr(path, ':') && ctx->streams == NF_STREAMS_INTERFACE_WINDOWS)
		return 1;
	return 0;
}

static void ntfs_fuse_update_times(ntfs_inode *ni, ntfs_time_update_flags mask)
{
	if (ctx->atime == ATIME_DISABLED)
		mask &= ~NTFS_UPDATE_ATIME;
	else if (ctx->atime == ATIME_RELATIVE && mask == NTFS_UPDATE_ATIME &&
			ni->last_access_time >= ni->last_data_change_time &&
			ni->last_access_time >= ni->last_mft_change_time)
		return;
	ntfs_inode_update_times(ni, mask);
}

static s64 ntfs_get_nr_free_mft_records(ntfs_volume *vol)
{
	ntfs_attr *na = vol->mftbmp_na;
	s64 nr_free = ntfs_attr_get_free_bits(na);

	if (nr_free >= 0)
		nr_free += (na->allocated_size - na->data_size) << 3;
	return nr_free;
}

/**
 * ntfs_fuse_statfs - return information about mounted NTFS volume
 * @path:	ignored (but fuse requires it)
 * @sfs:	statfs structure in which to return the information
 *
 * Return information about the mounted NTFS volume @sb in the statfs structure
 * pointed to by @sfs (this is initialized with zeros before ntfs_statfs is
 * called). We interpret the values to be correct of the moment in time at
 * which we are called. Most values are variable otherwise and this isn't just
 * the free values but the totals as well. For example we can increase the
 * total number of file nodes if we run out and we can keep doing this until
 * there is no more space on the volume left at all.
 *
 * This code based on ntfs_statfs from ntfs kernel driver.
 *
 * Returns 0 on success or -errno on error.
 */
static int ntfs_fuse_statfs(const char *path __attribute__((unused)),
			    struct statvfs *sfs)
{
	s64 size;
	int delta_bits;
	ntfs_volume *vol;

	vol = ctx->vol;
	if (!vol)
		return -ENODEV;
	
	/* 
	 * File system block size. Used to calculate used/free space by df.
	 * Incorrectly documented as "optimal transfer block size". 
	 */
	sfs->f_bsize = vol->cluster_size;
	
	/* Fundamental file system block size, used as the unit. */
	sfs->f_frsize = vol->cluster_size;
	
	/*
	 * Total number of blocks on file system in units of f_frsize.
	 * Since inodes are also stored in blocks ($MFT is a file) hence
	 * this is the number of clusters on the volume.
	 */
	sfs->f_blocks = vol->nr_clusters;
	
	/* Free blocks available for all and for non-privileged processes. */
	size = vol->free_clusters;
	if (size < 0)
		size = 0;
	sfs->f_bavail = sfs->f_bfree = size;
	
	/* Free inodes on the free space */
	delta_bits = vol->cluster_size_bits - vol->mft_record_size_bits;
	if (delta_bits >= 0)
		size <<= delta_bits;
	else
		size >>= -delta_bits;
	
	/* Number of inodes at this point in time. */
	sfs->f_files = (vol->mftbmp_na->allocated_size << 3) + size;
	
	/* Free inodes available for all and for non-privileged processes. */
	size += vol->free_mft_records;
	if (size < 0)
		size = 0;
	sfs->f_ffree = sfs->f_favail = size;
	
	/* Maximum length of filenames. */
	sfs->f_namemax = NTFS_MAX_NAME_LEN;
	return 0;
}

/**
 * ntfs_fuse_parse_path - split path to path and stream name.
 * @org_path:		path to split
 * @path:		pointer to buffer in which parsed path saved
 * @stream_name:	pointer to buffer where stream name in unicode saved
 *
 * This function allocates buffers for @*path and @*stream, user must free them
 * after use.
 *
 * Return values:
 *	<0	Error occurred, return -errno;
 *	 0	No stream name, @*stream is not allocated and set to AT_UNNAMED.
 *	>0	Stream name length in unicode characters.
 */
static int ntfs_fuse_parse_path(const char *org_path, char **path,
		ntfschar **stream_name)
{
	char *stream_name_mbs;
	int res;

	stream_name_mbs = strdup(org_path);
	if (!stream_name_mbs)
		return -errno;
	if (ctx->streams == NF_STREAMS_INTERFACE_WINDOWS) {
		*path = strsep(&stream_name_mbs, ":");
		if (stream_name_mbs) {
			*stream_name = NULL;
			res = ntfs_mbstoucs(stream_name_mbs, stream_name);
			if (res < 0)
				return -errno;
			return res;
		}
	} else
		*path = stream_name_mbs;
	*stream_name = AT_UNNAMED;
	return 0;
}

static void set_fuse_error(int *err)
{
	if (!*err)
		*err = -errno;
}

#if defined(__APPLE__) || defined(__DARWIN__)
static void *ntfs_macfuse_init(struct fuse_conn_info *conn)
{
	FUSE_ENABLE_XTIMES(conn);
	return NULL;
}

static int ntfs_macfuse_getxtimes(const char *org_path,
		struct timespec *bkuptime, struct timespec *crtime)
{
	int res = 0;
	ntfs_inode *ni;
	char *path = NULL;
	ntfschar *stream_name;
	int stream_name_len;

	stream_name_len = ntfs_fuse_parse_path(org_path, &path, &stream_name);
	if (stream_name_len < 0)
		return stream_name_len;
	memset(bkuptime, 0, sizeof(struct timespec));
	memset(crtime, 0, sizeof(struct timespec));
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni) {
		res = -errno;
		goto exit;
	}
	
	/* We have no backup timestamp in NTFS. */
	crtime->tv_sec = ni->creation_time;
exit:
	if (ntfs_inode_close(ni))
		set_fuse_error(&res);
	free(path);
	if (stream_name_len)
		free(stream_name);
	return res;
}

int ntfs_macfuse_setcrtime(const char *path, const struct timespec *tv)
{
	ntfs_inode *ni;
	int res = 0;

	if (ntfs_fuse_is_named_data_stream(path))
		return -EINVAL; /* n/a for named data streams. */
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni)
		return -errno;
	
	if (tv) {
		ni->creation_time = tv->tv_sec;
		ntfs_fuse_update_times(ni, NTFS_UPDATE_CTIME);
	}

	if (ntfs_inode_close(ni))
		set_fuse_error(&res);
	return res;
}

int ntfs_macfuse_setbkuptime(const char *path, const struct timespec *tv)
{
	ntfs_inode *ni;
	int res = 0;
	
	if (ntfs_fuse_is_named_data_stream(path))
		return -EINVAL; /* n/a for named data streams. */
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni)
		return -errno;
	
	/* 
	 * Doing nothing while pretending to do something. NTFS has no backup
	 * time. If this function is not implemented then some apps break. 
	 */
	
	if (ntfs_inode_close(ni))
		set_fuse_error(&res);
	return res;
}
#endif /* defined(__APPLE__) || defined(__DARWIN__) */

static int ntfs_fuse_getattr(const char *org_path, struct stat *stbuf)
{
	int res = 0;
	ntfs_inode *ni;
	ntfs_attr *na;
	char *path = NULL;
	ntfschar *stream_name;
	int stream_name_len;

	stream_name_len = ntfs_fuse_parse_path(org_path, &path, &stream_name);
	if (stream_name_len < 0)
		return stream_name_len;
	memset(stbuf, 0, sizeof(struct stat));
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni) {
		res = -errno;
		goto exit;
	}
	if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY && !stream_name_len) {
		/* Directory. */
		stbuf->st_mode = S_IFDIR | (0777 & ~ctx->dmask);
		na = ntfs_attr_open(ni, AT_INDEX_ALLOCATION, NTFS_INDEX_I30, 4);
		if (na) {
			stbuf->st_size = na->data_size;
			stbuf->st_blocks = na->allocated_size >> 9;
			ntfs_attr_close(na);
		}
		stbuf->st_nlink = 1;	/* Make find(1) work */
	} else {
		/* Regular or Interix (INTX) file. */
		stbuf->st_mode = S_IFREG;
		stbuf->st_size = ni->data_size;
		/* 
		 * Temporary fix to make ActiveSync work via Samba 3.0.
		 * See more on the ntfs-3g-devel list.
		 */
		stbuf->st_blocks = (ni->allocated_size + 511) >> 9;
		stbuf->st_nlink = le16_to_cpu(ni->mrec->link_count);
		if (ni->flags & FILE_ATTR_SYSTEM || stream_name_len) {
			na = ntfs_attr_open(ni, AT_DATA, stream_name,
					stream_name_len);
			if (!na) {
				if (stream_name_len)
					res = -ENOENT;
				goto exit;
			}
			if (stream_name_len) {
				stbuf->st_size = na->data_size;
				stbuf->st_blocks = na->allocated_size >> 9;
			}
			/* Check whether it's Interix FIFO or socket. */
			if (!(ni->flags & FILE_ATTR_HIDDEN) &&
					!stream_name_len) {
				/* FIFO. */
				if (na->data_size == 0)
					stbuf->st_mode = S_IFIFO;
				/* Socket link. */
				if (na->data_size == 1)
					stbuf->st_mode = S_IFSOCK;
			}
			/*
			 * Check whether it's Interix symbolic link, block or
			 * character device.
			 */
			if (na->data_size <= sizeof(INTX_FILE_TYPES) + 
			    sizeof(ntfschar) * PATH_MAX && 
			    na->data_size > sizeof(INTX_FILE_TYPES) && 
			    !stream_name_len) {
				
				INTX_FILE *intx_file;

				intx_file = ntfs_malloc(na->data_size);
				if (!intx_file) {
					res = -errno;
					ntfs_attr_close(na);
					goto exit;
				}
				if (ntfs_attr_pread(na, 0, na->data_size,
						intx_file) != na->data_size) {
					res = -errno;
					free(intx_file);
					ntfs_attr_close(na);
					goto exit;
				}
				if (intx_file->magic == INTX_BLOCK_DEVICE &&
						na->data_size == offsetof(
						INTX_FILE, device_end)) {
					stbuf->st_mode = S_IFBLK;
					stbuf->st_rdev = makedev(le64_to_cpu(
							intx_file->major),
							le64_to_cpu(
							intx_file->minor));
				}
				if (intx_file->magic == INTX_CHARACTER_DEVICE &&
						na->data_size == offsetof(
						INTX_FILE, device_end)) {
					stbuf->st_mode = S_IFCHR;
					stbuf->st_rdev = makedev(le64_to_cpu(
							intx_file->major),
							le64_to_cpu(
							intx_file->minor));
				}
				if (intx_file->magic == INTX_SYMBOLIC_LINK)
					stbuf->st_mode = S_IFLNK;
				free(intx_file);
			}
			ntfs_attr_close(na);
		}
		stbuf->st_mode |= (0777 & ~ctx->fmask);
	}
	stbuf->st_uid = ctx->uid;
	stbuf->st_gid = ctx->gid;
	stbuf->st_ino = ni->mft_no;
	stbuf->st_atime = ni->last_access_time;
	stbuf->st_ctime = ni->last_mft_change_time;
	stbuf->st_mtime = ni->last_data_change_time;
exit:
	if (ntfs_inode_close(ni))
		set_fuse_error(&res);
	free(path);
	if (stream_name_len)
		free(stream_name);
	return res;
}

static int ntfs_fuse_readlink(const char *org_path, char *buf, size_t buf_size)
{
	char *path;
	ntfschar *stream_name;
	ntfs_inode *ni = NULL;
	ntfs_attr *na = NULL;
	INTX_FILE *intx_file = NULL;
	int stream_name_len, res = 0;

	/* Get inode. */
	stream_name_len = ntfs_fuse_parse_path(org_path, &path, &stream_name);
	if (stream_name_len < 0)
		return stream_name_len;
	if (stream_name_len > 0) {
		res = -EINVAL;
		goto exit;
	}
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni) {
		res = -errno;
		goto exit;
	}
	/* Sanity checks. */
	if (!(ni->flags & FILE_ATTR_SYSTEM)) {
		res = -EINVAL;
		goto exit;
	}
	na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
	if (!na) {
		res = -errno;
		goto exit;
	}
	if (na->data_size <= sizeof(INTX_FILE_TYPES)) {
		res = -EINVAL;
		goto exit;
	}
	if (na->data_size > sizeof(INTX_FILE_TYPES) +
			sizeof(ntfschar) * PATH_MAX) {
		res = -ENAMETOOLONG;
		goto exit;
	}
	/* Receive file content. */
	intx_file = ntfs_malloc(na->data_size);
	if (!intx_file) {
		res = -errno;
		goto exit;
	}
	if (ntfs_attr_pread(na, 0, na->data_size, intx_file) != na->data_size) {
		res = -errno;
		goto exit;
	}
	/* Sanity check. */
	if (intx_file->magic != INTX_SYMBOLIC_LINK) {
		res = -EINVAL;
		goto exit;
	}
	/* Convert link from unicode to local encoding. */
	if (ntfs_ucstombs(intx_file->target, (na->data_size -
			offsetof(INTX_FILE, target)) / sizeof(ntfschar),
			&buf, buf_size) < 0) {
		res = -errno;
		goto exit;
	}
exit:
	if (intx_file)
		free(intx_file);
	if (na)
		ntfs_attr_close(na);
	if (ntfs_inode_close(ni))
		set_fuse_error(&res);
	free(path);
	if (stream_name_len)
		free(stream_name);
	return res;
}

static int ntfs_fuse_filler(ntfs_fuse_fill_context_t *fill_ctx,
		const ntfschar *name, const int name_len, const int name_type,
		const s64 pos __attribute__((unused)), const MFT_REF mref,
		const unsigned dt_type __attribute__((unused)))
{
	char *filename = NULL;
	int ret = 0;

	if (name_type == FILE_NAME_DOS)
		return 0;
	
	if (ntfs_ucstombs(name, name_len, &filename, 0) < 0) {
		ntfs_log_perror("Filename decoding failed (inode %llu)",
				(unsigned long long)MREF(mref));
		return -1;
	}
	
	if (ntfs_fuse_is_named_data_stream(filename)) {
		ntfs_log_error("Unable to access '%s' (inode %llu) with "
				"current named streams access interface.\n",
				filename, (unsigned long long)MREF(mref));
		free(filename);
		return 0;
	}
	
	if (MREF(mref) == FILE_root || MREF(mref) >= FILE_first_user ||
			ctx->show_sys_files) {
		struct stat st = { .st_ino = MREF(mref) };
		 
		if (dt_type == NTFS_DT_REG)
			st.st_mode = S_IFREG | (0777 & ~ctx->fmask);
		else if (dt_type == NTFS_DT_DIR)
			st.st_mode = S_IFDIR | (0777 & ~ctx->dmask); 
		
		ret = fill_ctx->filler(fill_ctx->buf, filename, &st, 0);
	}
	
	free(filename);
	return ret;
}

static int ntfs_fuse_readdir(const char *path, void *buf,
		fuse_fill_dir_t filler, off_t offset __attribute__((unused)),
		struct fuse_file_info *fi __attribute__((unused)))
{
	ntfs_fuse_fill_context_t fill_ctx;
	ntfs_inode *ni;
	s64 pos = 0;
	int err = 0;

	fill_ctx.filler = filler;
	fill_ctx.buf = buf;
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni)
		return -errno;
	if (ntfs_readdir(ni, &pos, &fill_ctx,
			(ntfs_filldir_t)ntfs_fuse_filler))
		err = -errno;
	ntfs_fuse_update_times(ni, NTFS_UPDATE_ATIME);
	if (ntfs_inode_close(ni))
		set_fuse_error(&err);
	return err;
}

static int ntfs_fuse_open(const char *org_path,
		struct fuse_file_info *fi __attribute__((unused)))
{
	ntfs_inode *ni;
	ntfs_attr *na;
	int res = 0;
	char *path = NULL;
	ntfschar *stream_name;
	int stream_name_len;

	stream_name_len = ntfs_fuse_parse_path(org_path, &path, &stream_name);
	if (stream_name_len < 0)
		return stream_name_len;
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (ni) {
		na = ntfs_attr_open(ni, AT_DATA, stream_name, stream_name_len);
		if (na) {
			if (NAttrEncrypted(na))
				res = -EACCES;
			ntfs_attr_close(na);
		} else
			res = -errno;
		if (ntfs_inode_close(ni))
			set_fuse_error(&res);
	} else
		res = -errno;
	free(path);
	if (stream_name_len)
		free(stream_name);
	return res;
}

static int ntfs_fuse_read(const char *org_path, char *buf, size_t size,
		off_t offset, struct fuse_file_info *fi __attribute__((unused)))
{
	ntfs_inode *ni = NULL;
	ntfs_attr *na = NULL;
	char *path = NULL;
	ntfschar *stream_name;
	int stream_name_len, res;
	s64 total = 0;

	if (!size)
		return 0;

	stream_name_len = ntfs_fuse_parse_path(org_path, &path, &stream_name);
	if (stream_name_len < 0)
		return stream_name_len;
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni) {
		res = -errno;
		goto exit;
	}
	na = ntfs_attr_open(ni, AT_DATA, stream_name, stream_name_len);
	if (!na) {
		res = -errno;
		goto exit;
	}
	if (offset + size > na->data_size) {
		if (na->data_size < offset)
			goto ok;
		size = na->data_size - offset;
	}
	while (size > 0) {
		s64 ret = ntfs_attr_pread(na, offset, size, buf);
		if (ret != (s64)size)
			ntfs_log_perror("ntfs_attr_pread error reading '%s' at "
				"offset %lld: %lld <> %lld", org_path, 
				(long long)offset, (long long)size, (long long)ret);
		if (ret <= 0 || ret > (s64)size) {
			res = (ret < 0) ? -errno : -EIO;
			goto exit;
		}
		size -= ret;
		offset += ret;
		total += ret;
	}
ok:
	ntfs_fuse_update_times(na->ni, NTFS_UPDATE_ATIME);
	res = total;
exit:
	if (na)
		ntfs_attr_close(na);
	if (ntfs_inode_close(ni))
		set_fuse_error(&res);
	free(path);
	if (stream_name_len)
		free(stream_name);
	return res;
}

static int ntfs_fuse_write(const char *org_path, const char *buf, size_t size,
		off_t offset, struct fuse_file_info *fi __attribute__((unused)))
{
	ntfs_inode *ni = NULL;
	ntfs_attr *na = NULL;
	char *path = NULL;
	ntfschar *stream_name;
	int stream_name_len, res, total = 0;

	stream_name_len = ntfs_fuse_parse_path(org_path, &path, &stream_name);
	if (stream_name_len < 0) {
		res = stream_name_len;
		goto out;
	}
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni) {
		res = -errno;
		goto exit;
	}
	na = ntfs_attr_open(ni, AT_DATA, stream_name, stream_name_len);
	if (!na) {
		res = -errno;
		goto exit;
	}
	while (size) {
		s64 ret = ntfs_attr_pwrite(na, offset, size, buf);
		if (0 <= ret && ret < (s64)size)
			ntfs_log_perror("ntfs_attr_pwrite partial write to '%s'"
				" (%lld: %lld <> %lld)", path, (long long)offset,
				(long long)size, (long long)ret);
		if (ret <= 0) {
			res = -errno;
			goto exit;
		}
		size   -= ret;
		offset += ret;
		total  += ret;
	}
	res = total;
	if (res > 0)
		ntfs_fuse_update_times(na->ni, NTFS_UPDATE_MCTIME);
exit:
	if (na)
		ntfs_attr_close(na);
	if (ntfs_inode_close(ni))
		set_fuse_error(&res);
	free(path);
	if (stream_name_len)
		free(stream_name);
out:	
	return res;
}

static int ntfs_fuse_truncate(const char *org_path, off_t size)
{
	ntfs_inode *ni = NULL;
	ntfs_attr *na = NULL;
	int res;
	char *path = NULL;
	ntfschar *stream_name;
	int stream_name_len;

	stream_name_len = ntfs_fuse_parse_path(org_path, &path, &stream_name);
	if (stream_name_len < 0)
		return stream_name_len;
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni)
		goto exit;

	na = ntfs_attr_open(ni, AT_DATA, stream_name, stream_name_len);
	if (!na)
		goto exit;

	if (ntfs_attr_truncate(na, size))
		goto exit;
	
	ntfs_fuse_update_times(na->ni, NTFS_UPDATE_MCTIME);
	errno = 0;
exit:
	res = -errno;
	ntfs_attr_close(na);
	if (ntfs_inode_close(ni))
		set_fuse_error(&res);
	free(path);
	if (stream_name_len)
		free(stream_name);
	return res;
}

static int ntfs_fuse_chmod(const char *path,
		mode_t mode __attribute__((unused)))
{
	if (ntfs_fuse_is_named_data_stream(path))
		return -EINVAL; /* n/a for named data streams. */
	if (ctx->silent)
		return 0;
	return -EOPNOTSUPP;
}

static int ntfs_fuse_chown(const char *path, uid_t uid, gid_t gid)
{
	if (ntfs_fuse_is_named_data_stream(path))
		return -EINVAL; /* n/a for named data streams. */
	if (ctx->silent)
		return 0;
	if (uid == ctx->uid && gid == ctx->gid)
		return 0;
	return -EOPNOTSUPP;
}

static int ntfs_fuse_create(const char *org_path, dev_t type, dev_t dev,
		const char *target)
{
	char *name;
	ntfschar *uname = NULL, *utarget = NULL;
	ntfs_inode *dir_ni = NULL, *ni;
	char *path;
	int res = 0, uname_len, utarget_len;

	path = strdup(org_path);
	if (!path)
		return -errno;
	/* Generate unicode filename. */
	name = strrchr(path, '/');
	name++;
	uname_len = ntfs_mbstoucs(name, &uname);
	if (uname_len < 0) {
		res = -errno;
		goto exit;
	}
	/* Open parent directory. */
	*name = 0;
	dir_ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!dir_ni) {
		res = -errno;
		goto exit;
	}
	/* Create object specified in @type. */
	switch (type) {
		case S_IFCHR:
		case S_IFBLK:
			ni = ntfs_create_device(dir_ni, uname, uname_len, type,
					dev);
			break;
		case S_IFLNK:
			utarget_len = ntfs_mbstoucs(target, &utarget);
			if (utarget_len < 0) {
				res = -errno;
				goto exit;
			}
			ni = ntfs_create_symlink(dir_ni, uname, uname_len,
					utarget, utarget_len);
			break;
		default:
			ni = ntfs_create(dir_ni, uname, uname_len, type);
			break;
	}
	if (ni) {
		if (ntfs_inode_close(ni))
			set_fuse_error(&res);
		ntfs_fuse_update_times(dir_ni, NTFS_UPDATE_MCTIME);
	} else
		res = -errno;
exit:
	free(uname);
	if (ntfs_inode_close(dir_ni))
		set_fuse_error(&res);
	if (utarget)
		free(utarget);
	free(path);
	return res;
}

static int ntfs_fuse_create_stream(const char *path,
		ntfschar *stream_name, const int stream_name_len)
{
	ntfs_inode *ni;
	int res = 0;

	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni) {
		res = -errno;
		if (res == -ENOENT) {
			/*
			 * If such file does not exist, create it and try once
			 * again to add stream to it.
			 */
			res = ntfs_fuse_create(path, S_IFREG, 0, NULL);
			if (!res)
				return ntfs_fuse_create_stream(path,
						stream_name, stream_name_len);
			else
				res = -errno;
		}
		return res;
	}
	if (ntfs_attr_add(ni, AT_DATA, stream_name, stream_name_len, NULL, 0))
		res = -errno;
	if (ntfs_inode_close(ni))
		set_fuse_error(&res);
	return res;
}

static int ntfs_fuse_mknod_common(const char *org_path, mode_t mode, dev_t dev)
{
	char *path = NULL;
	ntfschar *stream_name;
	int stream_name_len;
	int res = 0;

	stream_name_len = ntfs_fuse_parse_path(org_path, &path, &stream_name);
	if (stream_name_len < 0)
		return stream_name_len;
	if (stream_name_len && !S_ISREG(mode)) {
		res = -EINVAL;
		goto exit;
	}
	if (!stream_name_len)
		res = ntfs_fuse_create(path, mode & S_IFMT, dev, NULL);
	else
		res = ntfs_fuse_create_stream(path, stream_name,
				stream_name_len);
exit:
	free(path);
	if (stream_name_len)
		free(stream_name);
	return res;
}

static int ntfs_fuse_mknod(const char *path, mode_t mode, dev_t dev)
{
	return ntfs_fuse_mknod_common(path, mode, dev);
}

static int ntfs_fuse_create_file(const char *path, mode_t mode,
			    struct fuse_file_info *fi __attribute__((unused)))
{
	return ntfs_fuse_mknod_common(path, mode, 0);
}

static int ntfs_fuse_symlink(const char *to, const char *from)
{
	if (ntfs_fuse_is_named_data_stream(from))
		return -EINVAL; /* n/a for named data streams. */
	return ntfs_fuse_create(from, S_IFLNK, 0, to);
}

static int ntfs_fuse_link(const char *old_path, const char *new_path)
{
	char *name;
	ntfschar *uname = NULL;
	ntfs_inode *dir_ni = NULL, *ni;
	char *path;
	int res = 0, uname_len;

	if (ntfs_fuse_is_named_data_stream(old_path))
		return -EINVAL; /* n/a for named data streams. */
	if (ntfs_fuse_is_named_data_stream(new_path))
		return -EINVAL; /* n/a for named data streams. */
	path = strdup(new_path);
	if (!path)
		return -errno;
	/* Open file for which create hard link. */
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, old_path);
	if (!ni) {
		res = -errno;
		goto exit;
	}
	
	/* Generate unicode filename. */
	name = strrchr(path, '/');
	name++;
	uname_len = ntfs_mbstoucs(name, &uname);
	if (uname_len < 0) {
		res = -errno;
		goto exit;
	}
	/* Open parent directory. */
	*name = 0;
	dir_ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!dir_ni) {
		res = -errno;
		goto exit;
	}

	if (ntfs_link(ni, dir_ni, uname, uname_len)) {
		res = -errno;
		goto exit;
	}

	ntfs_fuse_update_times(ni, NTFS_UPDATE_CTIME);
	ntfs_fuse_update_times(dir_ni, NTFS_UPDATE_MCTIME);
exit:
	/* 
	 * Must close dir_ni first otherwise ntfs_inode_sync_file_name(ni)
	 * may fail because ni may not be in parent's index on the disk yet.
	 */
	if (ntfs_inode_close(dir_ni))
		set_fuse_error(&res);
	if (ntfs_inode_close(ni))
		set_fuse_error(&res);
	free(uname);
	free(path);
	return res;
}

static int ntfs_fuse_rm(const char *org_path)
{
	char *name;
	ntfschar *uname = NULL;
	ntfs_inode *dir_ni = NULL, *ni;
	char *path;
	int res = 0, uname_len;

	path = strdup(org_path);
	if (!path)
		return -errno;
	/* Open object for delete. */
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni) {
		res = -errno;
		goto exit;
	}
	/* Generate unicode filename. */
	name = strrchr(path, '/');
	name++;
	uname_len = ntfs_mbstoucs(name, &uname);
	if (uname_len < 0) {
		res = -errno;
		goto exit;
	}
	/* Open parent directory. */
	*name = 0;
	dir_ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!dir_ni) {
		res = -errno;
		goto exit;
	}
	
	if (ntfs_delete(ni, dir_ni, uname, uname_len))
		res = -errno;
	/* ntfs_delete() always closes ni and dir_ni */
	ni = dir_ni = NULL;
exit:
	if (ntfs_inode_close(dir_ni))
		set_fuse_error(&res);
	if (ntfs_inode_close(ni))
		set_fuse_error(&res);
	free(uname);
	free(path);
	return res;
}

static int ntfs_fuse_rm_stream(const char *path, ntfschar *stream_name,
		const int stream_name_len)
{
	ntfs_inode *ni;
	int res = 0;

	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni)
		return -errno;
	
	if (ntfs_attr_remove(ni, AT_DATA, stream_name, stream_name_len))
		res = -errno;

	if (ntfs_inode_close(ni))
		set_fuse_error(&res);
	return res;
}

static int ntfs_fuse_unlink(const char *org_path)
{
	char *path = NULL;
	ntfschar *stream_name;
	int stream_name_len;
	int res = 0;

	stream_name_len = ntfs_fuse_parse_path(org_path, &path, &stream_name);
	if (stream_name_len < 0)
		return stream_name_len;
	if (!stream_name_len)
		res = ntfs_fuse_rm(path);
	else
		res = ntfs_fuse_rm_stream(path, stream_name, stream_name_len);
	free(path);
	if (stream_name_len)
		free(stream_name);
	return res;
}

static int ntfs_fuse_safe_rename(const char *old_path, 
				 const char *new_path, 
				 const char *tmp)
{
	int ret;

	ntfs_log_trace("Entering\n");
	
	ret = ntfs_fuse_link(new_path, tmp);
	if (ret)
		return ret;
	
	ret = ntfs_fuse_unlink(new_path);
	if (!ret) {
		
		ret = ntfs_fuse_link(old_path, new_path);
		if (ret)
			goto restore;
		
		ret = ntfs_fuse_unlink(old_path);
		if (ret) {
			if (ntfs_fuse_unlink(new_path))
				goto err;
			goto restore;
		}
	}
	
	goto cleanup;
restore:
	if (ntfs_fuse_link(tmp, new_path)) {
err:
		ntfs_log_perror("Rename failed. Existing file '%s' was renamed "
				"to '%s'", new_path, tmp);
	} else {
cleanup:
		ntfs_fuse_unlink(tmp);
	}
	return 	ret;
}

static int ntfs_fuse_rename_existing_dest(const char *old_path, const char *new_path)
{
	int ret, len;
	char *tmp;
	const char *ext = ".ntfs-3g-";

	ntfs_log_trace("Entering\n");
	
	len = strlen(new_path) + strlen(ext) + 10 + 1; /* wc(str(2^32)) + \0 */
	tmp = ntfs_malloc(len);
	if (!tmp)
		return -errno;
	
	ret = snprintf(tmp, len, "%s%s%010d", new_path, ext, ++ntfs_sequence);
	if (ret != len - 1) {
		ntfs_log_error("snprintf failed: %d != %d\n", ret, len - 1);
		ret = -EOVERFLOW;
	} else
		ret = ntfs_fuse_safe_rename(old_path, new_path, tmp);
	
	free(tmp);
	return 	ret;
}

static int ntfs_fuse_rename(const char *old_path, const char *new_path)
{
	int ret, stream_name_len;
	char *path = NULL;
	ntfschar *stream_name;
	ntfs_inode *ni;
	
	ntfs_log_debug("rename: old: '%s'  new: '%s'\n", old_path, new_path);
	
	/*
	 *  FIXME: Rename should be atomic.
	 */
	stream_name_len = ntfs_fuse_parse_path(new_path, &path, &stream_name);
	if (stream_name_len < 0)
		return stream_name_len;
	
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (ni) {
		ret = ntfs_check_empty_dir(ni);
		if (ret < 0) {
			ret = -errno;
			ntfs_inode_close(ni);
			goto out;
		}
		
		if (ntfs_inode_close(ni)) {
			set_fuse_error(&ret);
			goto out;
		}
		
		ret = ntfs_fuse_rename_existing_dest(old_path, new_path);
		goto out;
	}

	ret = ntfs_fuse_link(old_path, new_path);
	if (ret)
		goto out;
	
	ret = ntfs_fuse_unlink(old_path);
	if (ret)
		ntfs_fuse_unlink(new_path);
out:
	free(path);
	if (stream_name_len)
		free(stream_name);
	return ret;
}

static int ntfs_fuse_mkdir(const char *path,
		mode_t mode __attribute__((unused)))
{
	if (ntfs_fuse_is_named_data_stream(path))
		return -EINVAL; /* n/a for named data streams. */
	return ntfs_fuse_create(path, S_IFDIR, 0, NULL);
}

static int ntfs_fuse_rmdir(const char *path)
{
	if (ntfs_fuse_is_named_data_stream(path))
		return -EINVAL; /* n/a for named data streams. */
	return ntfs_fuse_rm(path);
}

static int ntfs_fuse_utime(const char *path, struct utimbuf *buf)
{
	ntfs_inode *ni;
	int res = 0;

	if (ntfs_fuse_is_named_data_stream(path))
		return -EINVAL; /* n/a for named data streams. */
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni)
		return -errno;
	
	if (buf) {
		ni->last_access_time = buf->actime;
		ni->last_data_change_time = buf->modtime;
		ntfs_fuse_update_times(ni, NTFS_UPDATE_CTIME);
	} else
		ntfs_inode_update_times(ni, NTFS_UPDATE_AMCTIME);

	if (ntfs_inode_close(ni))
		set_fuse_error(&res);
	return res;
}

static int ntfs_fuse_bmap(const char *path, size_t blocksize, uint64_t *idx)
{
	ntfs_inode *ni;
	ntfs_attr *na;
	LCN lcn;
	int ret = 0; 
	int cl_per_bl = ctx->vol->cluster_size / blocksize;

	if (blocksize > ctx->vol->cluster_size)
		return -EINVAL;
	
	if (ntfs_fuse_is_named_data_stream(path))
		return -EINVAL;
	
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni)
		return -errno;

	na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
	if (!na) {
		ret = -errno;
		goto close_inode;
	}
	
	if (NAttrCompressed(na) || NAttrEncrypted(na) || !NAttrNonResident(na)){
		ret = -EINVAL;
		goto close_attr;
	}
	
	if (ntfs_attr_map_whole_runlist(na)) {
		ret = -errno;
		goto close_attr;
	}
	
	lcn = ntfs_rl_vcn_to_lcn(na->rl, *idx / cl_per_bl);
	*idx = (lcn > 0) ? lcn * cl_per_bl + *idx % cl_per_bl : 0;
	
close_attr:
	ntfs_attr_close(na);
close_inode:
	if (ntfs_inode_close(ni))
		set_fuse_error(&ret);
	return ret;
}

#ifdef HAVE_SETXATTR

static const char nf_ns_xattr_preffix[] = "user.";
static const int nf_ns_xattr_preffix_len = 5;

static int ntfs_fuse_listxattr(const char *path, char *list, size_t size)
{
	ntfs_attr_search_ctx *actx = NULL;
	ntfs_inode *ni;
	char *to = list;
	int ret = 0;

	if (ctx->streams != NF_STREAMS_INTERFACE_XATTR)
		return -EOPNOTSUPP;
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni)
		return -errno;
	actx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!actx) {
		ret = -errno;
		ntfs_inode_close(ni);
		goto exit;
	}
	while (!ntfs_attr_lookup(AT_DATA, NULL, 0, CASE_SENSITIVE,
				0, NULL, 0, actx)) {
		char *tmp_name = NULL;
		int tmp_name_len;

		if (!actx->attr->name_length)
			continue;
		tmp_name_len = ntfs_ucstombs((ntfschar *)((u8*)actx->attr +
				le16_to_cpu(actx->attr->name_offset)),
				actx->attr->name_length, &tmp_name, 0);
		if (tmp_name_len < 0) {
			ret = -errno;
			goto exit;
		}
		ret += tmp_name_len + nf_ns_xattr_preffix_len + 1;
		if (size) {
			if ((size_t)ret <= size) {
				strcpy(to, nf_ns_xattr_preffix);
				to += nf_ns_xattr_preffix_len;
				strncpy(to, tmp_name, tmp_name_len);
				to += tmp_name_len;
				*to = 0;
				to++;
			} else {
				free(tmp_name);
				ret = -ERANGE;
				goto exit;
			}
		}
		free(tmp_name);
	}
	if (errno != ENOENT)
		ret = -errno;
exit:
	if (actx)
		ntfs_attr_put_search_ctx(actx);
	if (ntfs_inode_close(ni))
		set_fuse_error(&ret);
	return ret;
}

static int ntfs_fuse_getxattr_windows(const char *path, const char *name,
				char *value, size_t size)
{
	ntfs_attr_search_ctx *actx = NULL;
	ntfs_inode *ni;
	char *to = value;
	int ret = 0;

	if (strcmp(name, "ntfs.streams.list"))
		return -EOPNOTSUPP;
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni)
		return -errno;
	actx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!actx) {
		ret = -errno;
		ntfs_inode_close(ni);
		goto exit;
	}
	while (!ntfs_attr_lookup(AT_DATA, NULL, 0, CASE_SENSITIVE,
				0, NULL, 0, actx)) {
		char *tmp_name = NULL;
		int tmp_name_len;

		if (!actx->attr->name_length)
			continue;
		tmp_name_len = ntfs_ucstombs((ntfschar *)((u8*)actx->attr +
				le16_to_cpu(actx->attr->name_offset)),
				actx->attr->name_length, &tmp_name, 0);
		if (tmp_name_len < 0) {
			ret = -errno;
			goto exit;
		}
		if (ret)
			ret++; /* For space delimiter. */
		ret += tmp_name_len;
		if (size) {
			if ((size_t)ret <= size) {
				/* Don't add space to the beginning of line. */
				if (to != value) {
					*to = '\0';
					to++;
				}
				strncpy(to, tmp_name, tmp_name_len);
				to += tmp_name_len;
			} else {
				free(tmp_name);
				ret = -ERANGE;
				goto exit;
			}
		}
		free(tmp_name);
	}
	if (errno != ENOENT)
		ret = -errno;
exit:
	if (actx)
		ntfs_attr_put_search_ctx(actx);
	if (ntfs_inode_close(ni))
		set_fuse_error(&ret);
	return ret;
}

static int ntfs_fuse_getxattr(const char *path, const char *name,
				char *value, size_t size)
{
	ntfs_inode *ni;
	ntfs_attr *na = NULL;
	ntfschar *lename = NULL;
	int res, lename_len;

	if (ctx->streams == NF_STREAMS_INTERFACE_WINDOWS)
		return ntfs_fuse_getxattr_windows(path, name, value, size);
	if (ctx->streams != NF_STREAMS_INTERFACE_XATTR)
		return -EOPNOTSUPP;
	if (strncmp(name, nf_ns_xattr_preffix, nf_ns_xattr_preffix_len) ||
			strlen(name) == (size_t)nf_ns_xattr_preffix_len)
		return -ENODATA;
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni)
		return -errno;
	lename_len = ntfs_mbstoucs(name + nf_ns_xattr_preffix_len, &lename);
	if (lename_len == -1) {
		res = -errno;
		goto exit;
	}
	na = ntfs_attr_open(ni, AT_DATA, lename, lename_len);
	if (!na) {
		res = -ENODATA;
		goto exit;
	}
	if (size) {
		if (size >= na->data_size) {
			res = ntfs_attr_pread(na, 0, na->data_size, value);
			if (res != na->data_size)
				res = -errno;
		} else
			res = -ERANGE;
	} else
		res = na->data_size;
exit:
	if (na)
		ntfs_attr_close(na);
	free(lename);
	if (ntfs_inode_close(ni))
		set_fuse_error(&res);
	return res;
}

static int ntfs_fuse_setxattr(const char *path, const char *name,
				const char *value, size_t size, int flags)
{
	ntfs_inode *ni;
	ntfs_attr *na = NULL;
	ntfschar *lename = NULL;
	int res, lename_len;

	if (ctx->streams != NF_STREAMS_INTERFACE_XATTR)
		return -EOPNOTSUPP;
	if (strncmp(name, nf_ns_xattr_preffix, nf_ns_xattr_preffix_len) ||
			strlen(name) == (size_t)nf_ns_xattr_preffix_len)
		return -EOPNOTSUPP;
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni)
		return -errno;
	lename_len = ntfs_mbstoucs(name + nf_ns_xattr_preffix_len, &lename);
	if (lename_len == -1) {
		res = -errno;
		goto exit;
	}
	na = ntfs_attr_open(ni, AT_DATA, lename, lename_len);
	if (na && flags == XATTR_CREATE) {
		res = -EEXIST;
		goto exit;
	}
	if (!na) {
		if (flags == XATTR_REPLACE) {
			res = -ENODATA;
			goto exit;
		}
		if (ntfs_attr_add(ni, AT_DATA, lename, lename_len, NULL, 0)) {
			res = -errno;
			goto exit;
		}
		na = ntfs_attr_open(ni, AT_DATA, lename, lename_len);
		if (!na) {
			res = -errno;
			goto exit;
		}
	} else {
		if (ntfs_attr_truncate(na, (s64)size)) {
			res = -errno;
			goto exit;
		}
	}
	res = ntfs_attr_pwrite(na, 0, size, value);
	if (res != (s64) size)
		res = -errno;
	else
		res = 0;
exit:
	if (na)
		ntfs_attr_close(na);
	free(lename);
	if (ntfs_inode_close(ni))
		set_fuse_error(&res);
	return res;
}

static int ntfs_fuse_removexattr(const char *path, const char *name)
{
	ntfs_inode *ni;
	ntfschar *lename = NULL;
	int res = 0, lename_len;


	if (ctx->streams != NF_STREAMS_INTERFACE_XATTR)
		return -EOPNOTSUPP;
	if (strncmp(name, nf_ns_xattr_preffix, nf_ns_xattr_preffix_len) ||
			strlen(name) == (size_t)nf_ns_xattr_preffix_len)
		return -ENODATA;
	ni = ntfs_pathname_to_inode(ctx->vol, NULL, path);
	if (!ni)
		return -errno;
	lename_len = ntfs_mbstoucs(name + nf_ns_xattr_preffix_len, &lename);
	if (lename_len == -1) {
		res = -errno;
		goto exit;
	}
	if (ntfs_attr_remove(ni, AT_DATA, lename, lename_len)) {
		if (errno == ENOENT)
			errno = ENODATA;
		res = -errno;
	}
	
exit:
	free(lename);
	if (ntfs_inode_close(ni))
		set_fuse_error(&res);
	return res;
}

#endif /* HAVE_SETXATTR */

static void ntfs_close(void)
{
	if (!ctx)
		return;
	
	if (!ctx->vol)
		return;
	
	if (ctx->mounted)
		ntfs_log_info("Unmounting %s (%s)\n", opts.device, 
			      ctx->vol->vol_name);
	
	if (ntfs_umount(ctx->vol, FALSE))
		ntfs_log_perror("Failed to close volume %s", opts.device);
	
	ctx->vol = NULL;
}

static void ntfs_fuse_destroy2(void *unused __attribute__((unused)))
{
	ntfs_close();
}

static struct fuse_operations ntfs_3g_ops = {
	.getattr	= ntfs_fuse_getattr,
	.readlink	= ntfs_fuse_readlink,
	.readdir	= ntfs_fuse_readdir,
	.open		= ntfs_fuse_open,
	.read		= ntfs_fuse_read,
	.write		= ntfs_fuse_write,
	.truncate	= ntfs_fuse_truncate,
	.statfs		= ntfs_fuse_statfs,
	.chmod		= ntfs_fuse_chmod,
	.chown		= ntfs_fuse_chown,
	.create		= ntfs_fuse_create_file,
	.mknod		= ntfs_fuse_mknod,
	.symlink	= ntfs_fuse_symlink,
	.link		= ntfs_fuse_link,
	.unlink		= ntfs_fuse_unlink,
	.rename		= ntfs_fuse_rename,
	.mkdir		= ntfs_fuse_mkdir,
	.rmdir		= ntfs_fuse_rmdir,
	.utime		= ntfs_fuse_utime,
	.bmap		= ntfs_fuse_bmap,
	.destroy        = ntfs_fuse_destroy2,
#ifdef HAVE_SETXATTR
	.getxattr	= ntfs_fuse_getxattr,
	.setxattr	= ntfs_fuse_setxattr,
	.removexattr	= ntfs_fuse_removexattr,
	.listxattr	= ntfs_fuse_listxattr,
#endif /* HAVE_SETXATTR */
#if defined(__APPLE__) || defined(__DARWIN__)
	.init		= ntfs_macfuse_init,
	/* MacFUSE extensions. */
	.getxtimes	= ntfs_macfuse_getxtimes,
	.setcrtime	= ntfs_macfuse_setcrtime,
	.setbkuptime	= ntfs_macfuse_setbkuptime
#endif /* defined(__APPLE__) || defined(__DARWIN__) */
};

static int ntfs_fuse_init(void)
{
	ctx = ntfs_calloc(sizeof(ntfs_fuse_context_t));
	if (!ctx)
		return -1;
	
	*ctx = (ntfs_fuse_context_t) {
		.uid     = getuid(),
		.gid     = getgid(),
#if defined(linux)			
		.streams = NF_STREAMS_INTERFACE_XATTR,
#else			
		.streams = NF_STREAMS_INTERFACE_NONE,
#endif			
		.atime   = ATIME_RELATIVE,
		.silent  = TRUE,
		.recover = TRUE
	};
	return 0;
}

static int ntfs_open(const char *device)
{
	unsigned long flags = 0;
	
	if (!ctx->blkdev)
		flags |= MS_EXCLUSIVE;
	if (ctx->ro)
		flags |= MS_RDONLY;
	if (ctx->recover)
		flags |= MS_RECOVER;
	if (ctx->hiberfile)
		flags |= MS_IGNORE_HIBERFILE;

	ctx->vol = ntfs_mount(device, flags);
	if (!ctx->vol) {
		ntfs_log_perror("Failed to mount '%s'", device);
		goto err_out;
	}
	
	ctx->vol->free_clusters = ntfs_attr_get_free_bits(ctx->vol->lcnbmp_na);
	if (ctx->vol->free_clusters < 0) {
		ntfs_log_perror("Failed to read NTFS $Bitmap");
		goto err_out;
	}

	ctx->vol->free_mft_records = ntfs_get_nr_free_mft_records(ctx->vol);
	if (ctx->vol->free_mft_records < 0) {
		ntfs_log_perror("Failed to calculate free MFT records");
		goto err_out;
	}

	if (ctx->hiberfile && ntfs_volume_check_hiberfile(ctx->vol, 0)) {
		if (errno != EPERM)
			goto err_out;
		if (ntfs_fuse_rm("/hiberfil.sys"))
			goto err_out;
	}
	
	errno = 0;
err_out:
	return ntfs_volume_error(errno);
	
}

#define STRAPPEND_MAX_INSIZE   8192
#define strappend_is_large(x) ((x) > STRAPPEND_MAX_INSIZE)

static int strappend(char **dest, const char *append)
{
	char *p;
	size_t size_append, size_dest = 0;
	
	if (!dest)
		return -1;
	if (!append)
		return 0;

	size_append = strlen(append);
	if (*dest)
		size_dest = strlen(*dest);
	
	if (strappend_is_large(size_dest) || strappend_is_large(size_append)) {
		errno = EOVERFLOW;
		ntfs_log_perror("%s: Too large input buffer", EXEC_NAME);
		return -1;
	}
	
	p = realloc(*dest, size_dest + size_append + 1);
    	if (!p) {
		ntfs_log_perror("%s: Memory realloction failed", EXEC_NAME);
		return -1;
	}
	
	*dest = p;
	strcpy(*dest + size_dest, append);
	
	return 0;
}

static int bogus_option_value(char *val, const char *s)
{
	if (val) {
		ntfs_log_error("'%s' option shouldn't have value.\n", s);
		return -1;
	}
	return 0;
}

static int missing_option_value(char *val, const char *s)
{
	if (!val) {
		ntfs_log_error("'%s' option should have a value.\n", s);
		return -1;
	}
	return 0;
}

static char *parse_mount_options(const char *orig_opts)
{
	char *options, *s, *opt, *val, *ret = NULL;
	BOOL no_def_opts = FALSE;
	int default_permissions = 0;

	options = strdup(orig_opts ? orig_opts : "");
	if (!options) {
		ntfs_log_perror("%s: strdup failed", EXEC_NAME);
		return NULL;
	}
	
	s = options;
	while (s && *s && (val = strsep(&s, ","))) {
		opt = strsep(&val, "=");
		if (!strcmp(opt, "ro")) { /* Read-only mount. */
			if (bogus_option_value(val, "ro"))
				goto err_exit;
			ctx->ro = TRUE;
			if (strappend(&ret, "ro,"))
				goto err_exit;
		} else if (!strcmp(opt, "noatime")) {
			if (bogus_option_value(val, "noatime"))
				goto err_exit;
			ctx->atime = ATIME_DISABLED;
		} else if (!strcmp(opt, "atime")) {
			if (bogus_option_value(val, "atime"))
				goto err_exit;
			ctx->atime = ATIME_ENABLED;
		} else if (!strcmp(opt, "relatime")) {
			if (bogus_option_value(val, "relatime"))
				goto err_exit;
			ctx->atime = ATIME_RELATIVE;
		} else if (!strcmp(opt, "fake_rw")) {
			if (bogus_option_value(val, "fake_rw"))
				goto err_exit;
			ctx->ro = TRUE;
		} else if (!strcmp(opt, "fsname")) { /* Filesystem name. */
			/*
			 * We need this to be able to check whether filesystem
			 * mounted or not.
			 */
			ntfs_log_error("'fsname' is unsupported option.\n");
			goto err_exit;
		} else if (!strcmp(opt, "no_def_opts")) {
			if (bogus_option_value(val, "no_def_opts"))
				goto err_exit;
			no_def_opts = TRUE; /* Don't add default options. */
		} else if (!strcmp(opt, "default_permissions")) {
			default_permissions = 1;
		} else if (!strcmp(opt, "umask")) {
			if (missing_option_value(val, "umask"))
				goto err_exit;
			sscanf(val, "%o", &ctx->fmask);
			ctx->dmask = ctx->fmask;
			if (ctx->fmask)
				default_permissions = 1;
		} else if (!strcmp(opt, "fmask")) {
			if (missing_option_value(val, "fmask"))
				goto err_exit;
			sscanf(val, "%o", &ctx->fmask);
			if (ctx->fmask)
				default_permissions = 1;
		} else if (!strcmp(opt, "dmask")) {
			if (missing_option_value(val, "dmask"))
				goto err_exit;
			sscanf(val, "%o", &ctx->dmask);
			if (ctx->dmask)
				default_permissions = 1;
		} else if (!strcmp(opt, "uid")) {
			if (missing_option_value(val, "uid"))
				goto err_exit;
			sscanf(val, "%i", &ctx->uid);
		       	default_permissions = 1;
		} else if (!strcmp(opt, "gid")) {
			if (missing_option_value(val, "gid"))
				goto err_exit;
			sscanf(val, "%i", &ctx->gid);
		       	default_permissions = 1;
		} else if (!strcmp(opt, "show_sys_files")) {
			if (bogus_option_value(val, "show_sys_files"))
				goto err_exit;
			ctx->show_sys_files = TRUE;
		} else if (!strcmp(opt, "silent")) {
			if (bogus_option_value(val, "silent"))
				goto err_exit;
			ctx->silent = TRUE;
		} else if (!strcmp(opt, "recover")) {
			if (bogus_option_value(val, "recover"))
				goto err_exit;
			ctx->recover = TRUE;
		} else if (!strcmp(opt, "norecover")) {
			if (bogus_option_value(val, "norecover"))
				goto err_exit;
			ctx->recover = FALSE;
		} else if (!strcmp(opt, "remove_hiberfile")) {
			if (bogus_option_value(val, "remove_hiberfile"))
				goto err_exit;
			ctx->hiberfile = TRUE;
		} else if (!strcmp(opt, "locale")) {
			if (missing_option_value(val, "locale"))
				goto err_exit;
			setlocale(LC_ALL, val);
		} else if (!strcmp(opt, "streams_interface")) {
			if (missing_option_value(val, "streams_interface"))
				goto err_exit;
			if (!strcmp(val, "none"))
				ctx->streams = NF_STREAMS_INTERFACE_NONE;
			else if (!strcmp(val, "xattr"))
				ctx->streams = NF_STREAMS_INTERFACE_XATTR;
			else if (!strcmp(val, "windows"))
				ctx->streams = NF_STREAMS_INTERFACE_WINDOWS;
			else {
				ntfs_log_error("Invalid named data streams "
						"access interface.\n");
				goto err_exit;
			}
		} else if (!strcmp(opt, "noauto")) {
			/* Don't pass noauto option to fuse. */
		} else if (!strcmp(opt, "debug")) {
			if (bogus_option_value(val, "debug"))
				goto err_exit;
			ctx->debug = TRUE;
			ntfs_log_set_levels(NTFS_LOG_LEVEL_DEBUG);
			ntfs_log_set_levels(NTFS_LOG_LEVEL_TRACE);
		} else if (!strcmp(opt, "no_detach")) {
			if (bogus_option_value(val, "no_detach"))
				goto err_exit;
			ctx->no_detach = TRUE;
		} else if (!strcmp(opt, "remount")) {
			ntfs_log_error("Remounting is not supported at present."
					" You have to umount volume and then "
					"mount it once again.\n");
			goto err_exit;
		} else if (!strcmp(opt, "blksize")) {
			ntfs_log_info("WARNING: blksize option is ignored "
				      "because ntfs-3g must calculate it.\n");
		} else { /* Probably FUSE option. */
			if (strappend(&ret, opt))
				goto err_exit;
			if (val) {
				if (strappend(&ret, "="))
					goto err_exit;
				if (strappend(&ret, val))
					goto err_exit;
			}
			if (strappend(&ret, ","))
				goto err_exit;
		}
	}
	if (!no_def_opts && strappend(&ret, def_opts))
		goto err_exit;
	if (default_permissions && strappend(&ret, "default_permissions,"))
		goto err_exit;
	
	if (ctx->atime == ATIME_RELATIVE && strappend(&ret, "relatime,"))
		goto err_exit;
	else if (ctx->atime == ATIME_ENABLED && strappend(&ret, "atime,"))
		goto err_exit;
	else if (ctx->atime == ATIME_DISABLED && strappend(&ret, "noatime,"))
		goto err_exit;
	
	if (strappend(&ret, "fsname="))
		goto err_exit;
	if (strappend(&ret, opts.device))
		goto err_exit;
exit:
	free(options);
	return ret;
err_exit:
	free(ret);
	ret = NULL;
	goto exit;
}

static void usage(void)
{
	ntfs_log_info(usage_msg, EXEC_NAME, VERSION, FUSE_TYPE, fuse_version(),
		      EXEC_NAME, ntfs_home);
}

#ifndef HAVE_REALPATH
/* If there is no realpath() on the system, provide a dummy one. */
static char *realpath(const char *path, char *resolved_path)
{
	strncpy(resolved_path, path, PATH_MAX);
	resolved_path[PATH_MAX] = '\0';
	return resolved_path;
}
#endif

/**
 * parse_options - Read and validate the programs command line
 * Read the command line, verify the syntax and parse the options.
 *
 * Return:   0 success, -1 error.
 */
static int parse_options(int argc, char *argv[])
{
	int c;

	static const char *sopt = "-o:hvV";
	static const struct option lopt[] = {
		{ "options",	 required_argument,	NULL, 'o' },
		{ "help",	 no_argument,		NULL, 'h' },
		{ "verbose",	 no_argument,		NULL, 'v' },
		{ "version",	 no_argument,		NULL, 'V' },
		{ NULL,		 0,			NULL,  0  }
	};

	opterr = 0; /* We'll handle the errors, thank you. */

	while ((c = getopt_long(argc, argv, sopt, lopt, NULL)) != -1) {
		switch (c) {
		case 1:	/* A non-option argument */
			if (!opts.device) {
				opts.device = ntfs_malloc(PATH_MAX + 1);
				if (!opts.device)
					return -1;
				
				/* Canonicalize device name (mtab, etc) */
				if (!realpath(optarg, opts.device)) {
					ntfs_log_perror("%s: Failed to access "
					     "volume '%s'", EXEC_NAME, optarg);
					free(opts.device);
					opts.device = NULL;
					return -1;
				}
			} else if (!opts.mnt_point) {
				opts.mnt_point = optarg;
			} else {
				ntfs_log_error("%s: You must specify exactly one "
						"device and exactly one mount "
						"point.\n", EXEC_NAME);
				return -1;
			}
			break;
		case 'o':
			if (opts.options)
				if (strappend(&opts.options, ","))
					return -1;
			if (strappend(&opts.options, optarg))
				return -1;
			break;
		case 'h':
			usage();
			exit(9);
		case 'v':
			/*
			 * We must handle the 'verbose' option even if
			 * we don't use it because mount(8) passes it.
			 */
			break;
		case 'V':
			ntfs_log_info("%s %s %s %d\n", EXEC_NAME, VERSION, 
				      FUSE_TYPE, fuse_version());
			exit(0);
		default:
			ntfs_log_error("%s: Unknown option '%s'.\n", EXEC_NAME,
				       argv[optind - 1]);
			return -1;
		}
	}

	if (!opts.device) {
		ntfs_log_error("%s: No device is specified.\n", EXEC_NAME);
		return -1;
	}
	if (!opts.mnt_point) {
		ntfs_log_error("%s: No mountpoint is specified.\n", EXEC_NAME);
		return -1;
	}

	return 0;
}

#if defined(linux) || defined(__uClinux__)

static const char *dev_fuse_msg =
"HINT: You should be root, or make ntfs-3g setuid root, or load the FUSE\n"
"      kernel module as root ('modprobe fuse' or 'insmod <path_to>/fuse.ko'"
"      or insmod <path_to>/fuse.o'). Make also sure that the fuse device"
"      exists. It's usually either /dev/fuse or /dev/misc/fuse.";

static const char *fuse26_kmod_msg =
"WARNING: Deficient Linux kernel detected. Some driver features are\n"
"         not available (swap file on NTFS, boot from NTFS by LILO), and\n"
"         unmount is not safe unless it's made sure the ntfs-3g process\n"
"         naturally terminates after calling 'umount'. If you wish this\n"
"         message to disappear then you should upgrade to at least kernel\n"
"         version 2.6.20, or request help from your distribution to fix\n"
"         the kernel problem. The below web page has more information:\n"
"         http://ntfs-3g.org/support.html#fuse26\n"
"\n";

static void mknod_dev_fuse(const char *dev)
{
	struct stat st;
	
	if (stat(dev, &st) && (errno == ENOENT)) {
		mode_t mask = umask(0); 
		if (mknod(dev, S_IFCHR | 0666, makedev(10, 229))) {
			ntfs_log_perror("Failed to create '%s'", dev);
			if (errno == EPERM)
				ntfs_log_error("%s", dev_fuse_msg);
		}
		umask(mask);
	}
}

static void create_dev_fuse(void)
{
	mknod_dev_fuse("/dev/fuse");

#ifdef __UCLIBC__
	{
		struct stat st;
		/* The fuse device is under /dev/misc using devfs. */
		if (stat("/dev/misc", &st) && (errno == ENOENT)) {
			mode_t mask = umask(0); 
			mkdir("/dev/misc", 0775);
			umask(mask);
		}
		mknod_dev_fuse("/dev/misc/fuse");
	}
#endif
}

static fuse_fstype get_fuse_fstype(void)
{
	char buf[256];
	fuse_fstype fstype = FSTYPE_NONE;
	
	FILE *f = fopen("/proc/filesystems", "r");
	if (!f) {
		ntfs_log_perror("Failed to open /proc/filesystems");
		return FSTYPE_UNKNOWN;
	}
	
	while (fgets(buf, sizeof(buf), f)) {
		if (strstr(buf, "fuseblk\n")) {
			fstype = FSTYPE_FUSEBLK;
			break;
		}
		if (strstr(buf, "fuse\n"))
			fstype = FSTYPE_FUSE;
	}
	
	fclose(f);
	return fstype;
}

static fuse_fstype load_fuse_module(void)
{
	int i;
	struct stat st;
	pid_t pid;
	const char *cmd = "/sbin/modprobe";
	struct timespec req = { 0, 100000000 };   /* 100 msec */
	fuse_fstype fstype;
	
	if (!stat(cmd, &st) && !geteuid()) {
		pid = fork();
		if (!pid) {
			execl(cmd, cmd, "fuse", NULL);
			_exit(1);
		} else if (pid != -1)
			waitpid(pid, NULL, 0);
	}
	
	for (i = 0; i < 10; i++) {
		/* 
		 * We sleep first because despite the detection of the loaded
		 * FUSE kernel module, fuse_mount() can still fail if it's not 
		 * fully functional/initialized. Note, of course this is still
		 * unreliable but usually helps.
		 */  
		nanosleep(&req, NULL);
		fstype = get_fuse_fstype();
		if (fstype != FSTYPE_NONE)
			break;
	}
	return fstype;
}

#endif

static struct fuse_chan *try_fuse_mount(char *parsed_options)
{
	struct fuse_chan *fc = NULL;
	struct fuse_args margs = FUSE_ARGS_INIT(0, NULL);
	
	/* The fuse_mount() options get modified, so we always rebuild it */
	if ((fuse_opt_add_arg(&margs, EXEC_NAME) == -1 ||
	     fuse_opt_add_arg(&margs, "-o") == -1 ||
	     fuse_opt_add_arg(&margs, parsed_options) == -1)) {
		ntfs_log_error("Failed to set FUSE options.\n");
		goto free_args;
	}
	
	fc = fuse_mount(opts.mnt_point, &margs);
free_args:
	fuse_opt_free_args(&margs);
	return fc;
		
}
		
static int set_fuseblk_options(char **parsed_options)
{
	char options[64];
	long pagesize; 
	u32 blksize = ctx->vol->cluster_size;
	
	pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize < 1)
		pagesize = 4096;
	
	if (blksize > (u32)pagesize)
		blksize = pagesize;
	
	snprintf(options, sizeof(options), ",blkdev,blksize=%u", blksize);
	if (strappend(parsed_options, options))
		return -1;
	return 0;
}

static struct fuse *mount_fuse(char *parsed_options)
{
	struct fuse *fh = NULL;
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	
	ctx->fc = try_fuse_mount(parsed_options);
	if (!ctx->fc)
		return NULL;
	
	if (fuse_opt_add_arg(&args, "") == -1)
		goto err;
	if (fuse_opt_add_arg(&args, "-ouse_ino,kernel_cache,attr_timeout=0") == -1)
		goto err;
	if (ctx->debug)
		if (fuse_opt_add_arg(&args, "-odebug") == -1)
			goto err;
	
	fh = fuse_new(ctx->fc, &args , &ntfs_3g_ops, sizeof(ntfs_3g_ops), NULL);
	if (!fh)
		goto err;
	
	if (fuse_set_signal_handlers(fuse_get_session(fh)))
		goto err_destory;
out:
	fuse_opt_free_args(&args);
	return fh;
err_destory:
	fuse_destroy(fh);
	fh = NULL;
err:	
	fuse_unmount(opts.mnt_point, ctx->fc);
	goto out;
}

static void setup_logging(char *parsed_options)
{
	if (!ctx->no_detach) {
		if (daemon(0, ctx->debug))
			ntfs_log_error("Failed to daemonize.\n");
		else if (!ctx->debug) {
#ifndef DEBUG
			ntfs_log_set_handler(ntfs_log_handler_syslog);
			/* Override default libntfs identify. */
			openlog(EXEC_NAME, LOG_PID, LOG_DAEMON);
#endif
		}
	}

	ntfs_log_info("Version %s %s %d\n", VERSION, FUSE_TYPE, fuse_version());
	ntfs_log_info("Mounted %s (%s, label \"%s\", NTFS %d.%d)\n",
			opts.device, (ctx->ro) ? "Read-Only" : "Read-Write",
			ctx->vol->vol_name, ctx->vol->major_ver,
			ctx->vol->minor_ver);
	ntfs_log_info("Cmdline options: %s\n", opts.options ? opts.options : "");
	ntfs_log_info("Mount options: %s\n", parsed_options);
}

int main(int argc, char *argv[])
{
	char *parsed_options = NULL;
	struct fuse *fh;
	fuse_fstype fstype = FSTYPE_UNKNOWN;
	struct stat sbuf;
	int err, fd;

	/*
	 * Make sure file descriptors 0, 1 and 2 are open, 
	 * otherwise chaos would ensue.
	 */
	do {
		fd = open("/dev/null", O_RDWR);
		if (fd > 2)
			close(fd);
	} while (fd >= 0 && fd <= 2);

#ifndef FUSE_INTERNAL
	if ((getuid() != geteuid()) || (getgid() != getegid())) {
		fprintf(stderr, "%s", setuid_msg);
		return NTFS_VOLUME_INSECURE;
	}
#endif
	if (drop_privs())
		return NTFS_VOLUME_NO_PRIVILEGE;
	
	ntfs_set_locale();
	ntfs_log_set_handler(ntfs_log_handler_stderr);

	if (parse_options(argc, argv)) {
		usage();
		return NTFS_VOLUME_SYNTAX_ERROR;
	}

	if (ntfs_fuse_init()) {
		err = NTFS_VOLUME_OUT_OF_MEMORY;
		goto err2;
	}
	
	parsed_options = parse_mount_options(opts.options);
	if (!parsed_options) {
		err = NTFS_VOLUME_SYNTAX_ERROR;
		goto err_out;
	}
	
#if defined(linux) || defined(__uClinux__)
	fstype = get_fuse_fstype();

	err = NTFS_VOLUME_NO_PRIVILEGE;
	if (restore_privs())
		goto err_out;

	if (fstype == FSTYPE_NONE || fstype == FSTYPE_UNKNOWN)
		fstype = load_fuse_module();
	
	create_dev_fuse();

	if (drop_privs())
		goto err_out;
#endif	
	if (stat(opts.device, &sbuf)) {
		ntfs_log_perror("Failed to access '%s'", opts.device);
		err = NTFS_VOLUME_NO_PRIVILEGE;
		goto err_out;
	}

#if !(defined(__sun) && defined (__SVR4))
	/* Always use fuseblk for block devices unless it's surely missing. */
	if (S_ISBLK(sbuf.st_mode) && (fstype != FSTYPE_FUSE))
		ctx->blkdev = TRUE;
#endif

#ifndef FUSE_INTERNAL
	if (getuid() && ctx->blkdev) {
		ntfs_log_error("%s", unpriv_fuseblk_msg);
		goto err2;
	}
#endif
	err = ntfs_open(opts.device);
	if (err)
		goto err_out;
	
	/* We must do this after ntfs_open() to be able to set the blksize */
	if (ctx->blkdev && set_fuseblk_options(&parsed_options))
		goto err_out;
	
	fh = mount_fuse(parsed_options);
	if (!fh) {
		err = NTFS_VOLUME_FUSE_ERROR;
		goto err_out;
	}
	
	ctx->mounted = TRUE;

#if defined(linux) || defined(__uClinux__)
	if (S_ISBLK(sbuf.st_mode) && (fstype == FSTYPE_FUSE))
		ntfs_log_info("%s", fuse26_kmod_msg);
#endif	
	setup_logging(parsed_options);
	
	fuse_loop(fh);
	
	err = 0;

	fuse_unmount(opts.mnt_point, ctx->fc);
	fuse_destroy(fh);
err_out:
	ntfs_mount_error(opts.device, opts.mnt_point, err);
err2:
	ntfs_close();
	free(ctx);
	free(parsed_options);
	free(opts.options);
	free(opts.device);
	return err;
}
