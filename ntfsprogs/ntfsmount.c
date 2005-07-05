/**
 * ntfsfuse - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2005 Yura Pakhuchiy
 *
 * NTFS module for FUSE.
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

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <locale.h>
#include <signal.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "attrib.h"
#include "inode.h"
#include "volume.h"
#include "dir.h"
#include "unistr.h"
#include "layout.h"

typedef struct {
	fuse_fill_dir_t filler;
	void *buf;
} ntfs_fuse_fill_context_t;

typedef struct {
	ntfs_volume *vol;
	int state;
	long free_clusters;
	long free_mft;
	uid_t uid;
	gid_t gid;
	mode_t fmask;
	mode_t dmask;
	BOOL ro;
	BOOL show_sys_files;
} ntfs_fuse_context_t;

typedef enum {
	NF_FreeClustersOutdate	= (1 << 0),  /* Information about amount of
						free clusters is outdated. */
	NF_FreeMFTOutdate	= (1 << 1),  /* Information about amount of
						free MFT records is outdated. */
} ntfs_fuse_state_bits;

static const char *EXEC_NAME = "ntfsmount";
static char def_opts[] = "default_permissions,kernel_cache,allow_other,";
static ntfs_fuse_context_t *ctx;

#define Eprintf(arg...) fprintf(stderr, ##arg)

static long ntfs_fuse_get_nr_free_mft_records(ntfs_volume *vol)
{
	u8 *buf;
	long nr_free = 0;
	s64 br, total = 0;
	
	if (!(ctx->state & NF_FreeMFTOutdate))
		return ctx->free_mft;
	buf = malloc(NTFS_BUF_SIZE);
	if (!buf)
		return -ENOMEM;
	while (1) {
		int i, j;

		br = ntfs_attr_pread(vol->mftbmp_na, total,
				NTFS_BLOCK_SIZE, buf);
		if (!br)
			break;
		total += br;
		for (i = 0; i < NTFS_BLOCK_SIZE; i++)
			for (j = 0; j < 8; j++)
				if (!((buf[i] >> j) & 1))
					nr_free++;
	}
	free(buf);
	if (!total)
		return -errno;
	ctx->free_mft = nr_free;
	ctx->state &= ~(NF_FreeMFTOutdate);
	return nr_free;
}

static long ntfs_fuse_get_nr_free_clusters(ntfs_volume *vol)
{
	u8 *buf;
	long nr_free = 0;
	s64 br, total = 0;

	if (!(ctx->state & NF_FreeClustersOutdate))
		return ctx->free_clusters;
	buf = malloc(NTFS_BUF_SIZE);
	if (!buf)
		return -ENOMEM;
	while (1) {
		int i, j;

		br = ntfs_attr_pread(vol->lcnbmp_na, total,
				NTFS_BLOCK_SIZE, buf);
		if (!br)
			break;
		total += br;
		for (i = 0; i < NTFS_BLOCK_SIZE; i++)
			for (j = 0; j < 8; j++)
				if (!((buf[i] >> j) & 1))
					nr_free++;
	}
	free(buf);
	if (!total)
		return -errno;
	ctx->free_clusters = nr_free;
	ctx->state &= ~(NF_FreeClustersOutdate);
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
 * Return 0 on success or -errno on error.
 */
static int ntfs_fuse_statfs(const char *path __attribute__((unused)),
		struct statfs *sfs)
{
	long size;
	ntfs_volume *vol;

	vol = ctx->vol;
	if (!vol)
		return -ENODEV;
	/* Type of filesystem. */
	sfs->f_type = NTFS_SB_MAGIC;
	/* Optimal transfer block size. */
	sfs->f_bsize = NTFS_BLOCK_SIZE;
	/*
	 * Total data blocks in file system in units of f_bsize and since
	 * inodes are also stored in data blocs ($MFT is a file) this is just
	 * the total clusters.
	 */
	sfs->f_blocks = vol->nr_clusters;
	/* Free data blocks in file system in units of f_bsize. */
	size = ntfs_fuse_get_nr_free_clusters(vol);
	if (size < 0)
		size = 0;
	/* Free blocks avail to non-superuser, same as above on NTFS. */
	sfs->f_bavail = sfs->f_bfree = size;
	/* Number of inodes in file system (at this point in time). */
	sfs->f_files = vol->mft_na->data_size >> vol->mft_record_size_bits;
	/* Free inodes in fs (based on current total count). */
	size = ntfs_fuse_get_nr_free_mft_records(vol);
	if (size < 0)
		size = 0;
	sfs->f_ffree = size;
	/* Maximum length of filenames. */
	sfs->f_namelen = NTFS_MAX_NAME_LEN;
	return 0;
}

static int ntfs_fuse_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;
	ntfs_inode *ni;
	ntfs_attr *na;
	ntfs_volume *vol;

	vol = ctx->vol;
	memset(stbuf, 0, sizeof(struct stat));
	if ((ni = ntfs_pathname_to_inode(vol, NULL, path))) {
		if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
			stbuf->st_mode = S_IFDIR | (0777 & ~ctx->dmask);
			na = ntfs_attr_open(ni, AT_INDEX_ALLOCATION, I30, 0);
			if (na) {
				stbuf->st_size = na->data_size;
				stbuf->st_blocks = na->allocated_size >>
					vol->sector_size_bits;
				ntfs_attr_close(na);
			} else {
				stbuf->st_size = 0;
				stbuf->st_blocks = 0;
			}
		} else {
			stbuf->st_mode = S_IFREG | (0777 & ~ctx->fmask);
			na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
			if (na) {
				stbuf->st_size = na->data_size;
				stbuf->st_blocks = na->allocated_size >>
					vol->sector_size_bits;
				ntfs_attr_close(na);
			} else {
				stbuf->st_size = 0;
				stbuf->st_blocks = 0;
			}
		}
		stbuf->st_uid = ctx->uid;
		stbuf->st_gid = ctx->gid;
		stbuf->st_ino = ni->mft_no;
		stbuf->st_nlink = le16_to_cpu(ni->mrec->link_count);
		/*
		 * TODO: Need support in libntfs for this.
		 * stbuf->st_atime = 
		 * stbuf->st_ctime = 
		 * stbuf->st_mtime = 
		 */
		ntfs_inode_close(ni);
	} else
		res = -ENOENT;
	return res;
}

static int ntfs_fuse_filler(ntfs_fuse_fill_context_t *fill_ctx,
		const ntfschar *name, const int name_len, const int name_type,
		const s64 pos __attribute__((unused)), const MFT_REF mref,
		const unsigned dt_type __attribute__((unused)))
{
	char *filename;
	int err = 0;

	if (name_type == FILE_NAME_DOS)
		return 0;
	filename = malloc(name_len + 1);
	if (!filename)
		return -errno;
	if (ntfs_ucstombs(name, name_len, &filename, name_len + 1) < 0) {
		err = -errno;
		free(filename);
		return err;
	}
	if (MREF(mref) >= FILE_first_user || ctx->show_sys_files)
		fill_ctx->filler(fill_ctx->buf, filename, NULL, 0);
	free(filename);
	return err;
}

static int ntfs_fuse_readdir(const char *path, void *buf,
		fuse_fill_dir_t filler, off_t offset __attribute__((unused)),
		struct fuse_file_info *fi __attribute__((unused)))
{
	ntfs_fuse_fill_context_t fill_ctx;
	ntfs_volume *vol;
	ntfs_inode *ni;
	s64 pos = 0;

	vol = ctx->vol;
	if (!vol)
		return -ENODEV;
	fill_ctx.filler = filler;
	fill_ctx.buf = buf;
	ni = ntfs_pathname_to_inode(vol, NULL, path);
	if (!ni)
		return -errno;
	ntfs_readdir(ni, &pos, &fill_ctx, (ntfs_filldir_t)ntfs_fuse_filler);
	ntfs_inode_close(ni);
	return 0;
}

static int ntfs_fuse_open(const char *path,
		struct fuse_file_info *fi __attribute__((unused)))
{
	ntfs_volume *vol;
	ntfs_inode *ni;
	
	vol = ctx->vol;
	if (!vol)
		return -ENODEV;
	ni = ntfs_pathname_to_inode(vol, NULL, path);
	if (!ni)
		return -errno;
	ntfs_inode_close(ni);
	return 0;
}

static int ntfs_fuse_read(const char *path, char *buf, size_t size,
		off_t offset, struct fuse_file_info *fi __attribute__((unused)))
{
	ntfs_volume *vol;
	ntfs_inode *ni;
	ntfs_attr *na;
	int res;
	
	vol = ctx->vol;
	if (!vol)
		return -ENODEV;
	ni = ntfs_pathname_to_inode(vol, NULL, path);
	if (!ni)
		return -errno;
	na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
	if (!na)
		return -errno;
	res = ntfs_attr_pread(na, offset, size, buf);
	ntfs_attr_close(na);
	if (ntfs_inode_close(ni))
		perror("Failed to close inode");
	return res;
}

static int ntfs_fuse_write(const char *path, const char *buf, size_t size,
		off_t offset, struct fuse_file_info *fi __attribute__((unused)))
{
	ntfs_volume *vol;
	ntfs_inode *ni;
	ntfs_attr *na;
	int res;
	
	vol = ctx->vol;
	if (!vol)
		return -ENODEV;
	ni = ntfs_pathname_to_inode(vol, NULL, path);
	if (!ni)
		return -errno;
	na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
	if (!na)
		return -errno;
	res = ntfs_attr_pwrite(na, offset, size,  buf);
	ntfs_attr_close(na);
	if (ntfs_inode_close(ni))
		perror("Failed to close inode");
	ctx->state |= (NF_FreeClustersOutdate | NF_FreeMFTOutdate);
	return res;
}

static int ntfs_fuse_truncate(const char *path, off_t size)
{
	ntfs_volume *vol;
	ntfs_inode *ni;
	ntfs_attr *na;
	int res;
	
	vol = ctx->vol;
	if (!vol)
		return -ENODEV;
	ni = ntfs_pathname_to_inode(vol, NULL, path);
	if (!ni)
		return -errno;
	na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
	if (!na)
		return -errno;
	res = ntfs_attr_truncate(na, size);
	ntfs_attr_close(na);
	if (ntfs_inode_close(ni))
		perror("Failed to close inode");
	ctx->state |= (NF_FreeClustersOutdate | NF_FreeMFTOutdate);
	return res;
}

static int ntfs_fuse_chmod(const char *path __attribute__((unused)),
		mode_t mode __attribute__((unused)))
{
	return 0;
}

#ifdef HAVE_SETXATTR

static const char nf_ns_streams[] = "user.stream.";
static const int nf_ns_streams_len = 12;

static const char nf_ns_eas[] = "user.ea.";
static const int nf_ns_eas_len = 8;

static int ntfs_fuse_listxattr(const char *path, char *list, size_t size)
{
	ntfs_attr_search_ctx *actx = NULL;
	ntfs_volume *vol;
	ntfs_inode *ni;
	char *to = list;
	int ret = 0;

	vol = ctx->vol;
	if (!vol)
		return -ENODEV;
	ni = ntfs_pathname_to_inode(vol, NULL, path);
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
		if (!actx->attr->name_length)
			continue;
		ret += actx->attr->name_length + nf_ns_streams_len + 1;
		if (size && (size_t)ret <= size) {
			strcpy(to, nf_ns_streams);
			to += nf_ns_streams_len;
			if (ntfs_ucstombs((ntfschar *)((u8*)actx->attr +
					le16_to_cpu(actx->attr->name_offset)),
					actx->attr->name_length, &to,
					actx->attr->name_length + 1) < 0) {
				ret = -errno;
				goto exit;
			}
			to += actx->attr->name_length + 1;
		}
	}
	if (errno != ENOENT)
		ret = -errno;
exit:
	if (actx)
		ntfs_attr_put_search_ctx(actx);
	ntfs_inode_close(ni);
	fprintf(stderr, "return %d\n", ret);
	return ret;
}

static int ntfs_fuse_getxattr(const char *path, const char *name,
				char *value, size_t size)
{
	ntfs_volume *vol;
	ntfs_inode *ni;
	ntfs_attr *na = NULL;
	int res;
	ntfschar *lename = NULL;

	if (strncmp(name, nf_ns_streams, nf_ns_streams_len) ||
			strlen(name) == (size_t)nf_ns_streams_len)
		return -ENODATA;
	vol = ctx->vol;
	if (!vol)
		return -ENODEV;
	ni = ntfs_pathname_to_inode(vol, NULL, path);
	if (!ni)
		return -errno;
	if (ntfs_mbstoucs(name + nf_ns_streams_len, &lename, 0) == -1) {
		res = -errno;
		goto exit;
	}
	na = ntfs_attr_open(ni, AT_DATA, lename,
			strlen(name) - nf_ns_streams_len);
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
	if (lename)
		free(lename);
	if (ntfs_inode_close(ni))
		perror("Failed to close inode");
	return res;
}

static int ntfs_fuse_setxattr(const char *path, const char *name,
				const char *value, size_t size, int flags)
{
	ntfs_volume *vol;
	ntfs_inode *ni;
	ntfs_attr *na = NULL;
	int res;
	ntfschar *lename = NULL;

	if (strncmp(name, nf_ns_streams, nf_ns_streams_len) ||
			strlen(name) == (size_t)nf_ns_streams_len)
		return -EACCES;
	vol = ctx->vol;
	if (!vol)
		return -ENODEV;
	ni = ntfs_pathname_to_inode(vol, NULL, path);
	if (!ni)
		return -errno;
	if (ntfs_mbstoucs(name + nf_ns_streams_len, &lename, 0) == -1) {
		res = -errno;
		goto exit;
	}
	na = ntfs_attr_open(ni, AT_DATA, lename,
			strlen(name) - nf_ns_streams_len);
	if (na && flags == XATTR_CREATE) {
		res = -EEXIST;
		goto exit;
	}
	if (!na) {
		if (flags == XATTR_REPLACE) {
			res = -ENODATA;
			goto exit;
		}
		na = ntfs_attr_add(ni, AT_DATA, lename, strlen(name) -
				nf_ns_streams_len, 0);
		if (!na) {
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
	if (lename)
		free(lename);
	if (ntfs_inode_close(ni))
		perror("Failed to close inode");
	return res;
}

static int ntfs_fuse_removexattr(const char *path, const char *name)
{
	ntfs_volume *vol;
	ntfs_inode *ni;
	ntfs_attr *na = NULL;
	int res = 0;
	ntfschar *lename = NULL;

	if (strncmp(name, nf_ns_streams, nf_ns_streams_len) ||
			strlen(name) == (size_t)nf_ns_streams_len)
		return -ENODATA;
	vol = ctx->vol;
	if (!vol)
		return -ENODEV;
	ni = ntfs_pathname_to_inode(vol, NULL, path);
	if (!ni)
		return -errno;
	if (ntfs_mbstoucs(name + nf_ns_streams_len, &lename, 0) == -1) {
		res = -errno;
		goto exit;
	}
	na = ntfs_attr_open(ni, AT_DATA, lename,
			strlen(name) - nf_ns_streams_len);
	if (!na) {
		res = -ENODATA;
		goto exit;
	}
	if (ntfs_attr_rm(na))
		res = -errno;
	else
		na = NULL;
exit:
	if (na)
		ntfs_attr_close(na);
	if (lename)
		free(lename);
	if (ntfs_inode_close(ni))
		perror("Failed to close inode");
	return res;
}
#endif

static struct fuse_operations ntfs_fuse_oper = {
	.getattr	= ntfs_fuse_getattr,
	.readdir	= ntfs_fuse_readdir,
	.open		= ntfs_fuse_open,
	.read		= ntfs_fuse_read,
	.write		= ntfs_fuse_write,
	.truncate	= ntfs_fuse_truncate,
	.statfs		= ntfs_fuse_statfs,
	.chmod		= ntfs_fuse_chmod,
#ifdef HAVE_SETXATTR
	.listxattr	= ntfs_fuse_listxattr,
	.getxattr	= ntfs_fuse_getxattr,
	.setxattr	= ntfs_fuse_setxattr,
	.removexattr	= ntfs_fuse_removexattr,
#endif	
};

static int ntfs_fuse_init(void)
{
	ctx = malloc(sizeof(ntfs_fuse_context_t));
	if (!ctx) {
		perror("malloc failed");
		return -1;
	}
	*ctx = (ntfs_fuse_context_t) {
		.state = NF_FreeClustersOutdate | NF_FreeMFTOutdate,
		.uid = geteuid(),
		.gid = getegid(),
		.fmask = 0177,
		.dmask = 0077,
	};
	return 0;
}

static int ntfs_fuse_mount(const char *device)
{
	ntfs_volume *vol;

	vol = ntfs_mount(device, (ctx->ro) ? MS_RDONLY : 0);
	if (!vol) {
		perror("Mount failed");
		return -1;
	}
	ctx->vol = vol;
	return 0;
}

static void ntfs_fuse_destroy(void)
{
	if (ctx->vol) {
		printf("Unmounting: %s\n", ctx->vol->vol_name);
		if (ntfs_umount(ctx->vol, FALSE))
			perror("Failed to unmount volume");
	}
	free(ctx);
}

static void signal_handler(int arg __attribute__((unused)))
{
	fuse_exit((fuse_get_context())->fuse);
}

static char *parse_options(char *options, char **device)
{
	char *opts, *s, *opt, *val, *ret;
	BOOL no_def_opts = FALSE, no_fsname = FALSE;
	
	*device = NULL;
	/*
	 * +8 for different in length of "fsname=ntfs#..." and "dev=...".
	 * +1 for comma
	 * +1 for null-terminator.
	 * Total: +10
	 */
	ret = malloc(strlen(def_opts) + strlen(options) + 10);
	if (!ret) {
		perror("malloc failed");
		return NULL;
	}
	*ret = 0;
	opts = strdup(options);
	if (!opts) {
		perror("strdump failed");
		return NULL;
	}
	s = opts;
	while ((val = strsep(&s, ","))) {
		opt = strsep(&val, "=");
		if (!strcmp(opt, "dev")) { /* Device to mount. */
			if (!val) {
				Eprintf("dev option should have value.\n");
				goto err_exit;
			}
			*device = malloc(strlen(val) + 1);
			strcpy(*device, val);
		} else if (!strcmp(opt, "ro")) { /* Read-only mount. */
			if (val) {
				Eprintf("ro option should not have value.\n");
				goto err_exit;
			}
			ctx->ro =TRUE;
			strcat(ret, "ro,");
		} else if (!strcmp(opt, "fsname")) { /* Filesystem name. */
			if (!val) {
				Eprintf("fsname option should have value.\n");
				goto err_exit;
			}
			no_fsname = TRUE;
			strcat(ret, "fsname=");
			strcat(ret, val);
			strcat(ret, ",");
		} else if (!strcmp(opt, "no_def_opts")) {
			if (val) {
				Eprintf("no_def_opts option should not have "
						"value.\n");
				goto err_exit;
			}
			no_def_opts = TRUE; /* Don't add default options. */
		} else if (!strcmp(opt, "umask")) {
			if (!val) {
				Eprintf("umask option should have value.\n");
				goto err_exit;
			}
			sscanf(val, "%i", &ctx->fmask);
			ctx->dmask = ctx->fmask;
		} else if (!strcmp(opt, "fmask")) {
			if (!val) {
				Eprintf("fmask option should have value.\n");
				goto err_exit;
			}
			sscanf(val, "%i", &ctx->fmask);
		} else if (!strcmp(opt, "dmask")) {
			if (!val) {
				Eprintf("dmask option should have value.\n");
				goto err_exit;
			}
			sscanf(val, "%i", &ctx->dmask);
		} else if (!strcmp(opt, "uid")) {
			if (!val) {
				Eprintf("uid option should have value.\n");
				goto err_exit;
			}
			sscanf(val, "%i", &ctx->uid);
		} else if (!strcmp(opt, "gid")) {
			if (!val) {
				Eprintf("gid option should have value.\n");
				goto err_exit;
			}
			sscanf(val, "%i", &ctx->gid);
		} else if (!strcmp(opt, "show_sys_files")) {
			if (val) {
				Eprintf("show_sys_files option should not "
						"have value.\n");
				goto err_exit;
			}
			ctx->show_sys_files = TRUE;
		} else { /* Probably FUSE option. */
			strcat(ret, opt);
			if (val) {
				strcat(ret, "=");
				strcat(ret, val);
			}
			strcat(ret, ",");
		}
	}
	if (!*device)
		goto err_exit;
	if (!no_def_opts) {
		strcat(ret, def_opts);
		if (!no_fsname) {
			strcat(ret, "fsname=ntfs#");
			strcat(ret, *device);
		}
	}
exit:
	free(opts);
	return ret;
err_exit:
	free(ret);
	ret = NULL;
	goto exit;
}

static void usage(void)
{
	Eprintf("\n%s v%s - NTFS module for FUSE.\n\n",
			EXEC_NAME, VERSION);
	Eprintf("Copyright (c) 2005 Yura Pakhuchiy\n\n");
	Eprintf("usage:  %s mount_point -o dev=device[,other_options]\n\n",
			EXEC_NAME);
	Eprintf("Possible options are:\n\tdefault_permissions\n\tallow_other\n"
		"\tkernel_cache\n\tlarge_read\n\tdirect_io\n\tmax_read\n\t"
		"fsname\n\tro\n\tno_def_opts\n\tumask\n\tfmask\n\tdmask\n\t"
		"uid\n\tgid\n\tshow_sys_files\n\tdev\n\n");
	Eprintf("Default options are: \"%sfsname=ntfs#device\".\n", def_opts);
}

int main(int argc, char *argv[])
{
	char *options, *parsed_options, *mnt_point, *device;
	struct fuse *fh;
	int ffd;

	setlocale(LC_ALL, "");
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Simple arguments parse code. */
	if (argc != 4) {
		usage();
		return 1;
	}
	if (!strcmp(argv[1], "-o")) {
		options = argv[2];
		mnt_point = argv[3];
	} else if (!strcmp(argv[2], "-o")) {
		options = argv[3];
		mnt_point = argv[1];
	} else {
		usage();
		return 1;
	}
	ntfs_fuse_init();
	/* Parse options. */
	parsed_options = parse_options(options, &device);
	if (!device) {
		Eprintf("dev option is mandatory.\n");
		ntfs_fuse_destroy();
		return 5;
	}
	if (!parsed_options) {
		ntfs_fuse_destroy();
		return 6;
	}

	/* Create filesystem. */
	ffd = fuse_mount(mnt_point, parsed_options);
	if (ffd == -1) {
		Eprintf("fuse_mount failed.\n");
		return 2;
	}
	free(parsed_options);
#ifndef DEBUG
	fh = fuse_new(ffd, "use_ino", &ntfs_fuse_oper, sizeof(ntfs_fuse_oper));
#else
	fh = fuse_new(ffd, "debug,use_ino", &ntfs_fuse_oper,
			sizeof(ntfs_fuse_oper));
#endif
	if (!fh) {
		Eprintf("fuse_new failed.\n");
		close(ffd);
		fuse_unmount(mnt_point);
		return 3;
	}
	/* Mount volume. */
	if (ntfs_fuse_mount(device)) {
		fuse_destroy(fh);
		close(ffd);
		fuse_unmount(mnt_point);
		return 4;
	}
#ifndef DEBUG
	if (daemon(0, 0))
		Eprintf("Failed to daemonize.\n");
#endif
	printf("Mounted: %s\n", ctx->vol->vol_name);
	/* Main loop. */
	if (fuse_loop(fh))
		Eprintf("fuse_loop failed.\n");
	/* Destroy. */
	fuse_destroy(fh);
	close(ffd);
	fuse_unmount(mnt_point);
	ntfs_fuse_destroy();
	return 0;
}
