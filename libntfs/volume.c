/*
 * volume.c - NTFS volume handling code. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2000-2002 Anton Altaparmakov
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <limits.h>

#include "volume.h"
#include "attrib.h"
#include "mft.h"
#include "bootsect.h"
#include "disk_io.h"
#include "debug.h"
#include "inode.h"
#include "runlist.h"

/**
 * Internal:
 *
 * __ntfs_volume_allocate -
 *
 */
static ntfs_volume *__ntfs_volume_allocate(void)
{
	return (ntfs_volume*)calloc(1, sizeof(ntfs_volume));
}

/**
 * Internal:
 *
 * __ntfs_volume_release -
 *
 */
static void __ntfs_volume_release(ntfs_volume *v)
{
	if (v->fd)
		close(v->fd);
	if (v->dev_name)
		free(v->dev_name);
	if (v->vol_name)
		free(v->vol_name);
	if (v->lcnbmp_na)
		ntfs_attr_close(v->lcnbmp_na);
	if (v->lcnbmp_ni)
		ntfs_inode_close(v->lcnbmp_ni);
	if (v->mftbmp_na)
		ntfs_attr_close(v->mftbmp_na);
	if (v->mft_na)
		ntfs_attr_close(v->mft_na);
	if (v->mft_ni)
		ntfs_inode_close(v->mft_ni);
	if (v->mftmirr_na)
		ntfs_attr_close(v->mftmirr_na);
	if (v->mftmirr_ni)
		ntfs_inode_close(v->mftmirr_ni);
	if (v->upcase)
		free(v->upcase);
	free(v);
}

/* External declaration for internal function. */
extern ntfs_inode *ntfs_inode_allocate(ntfs_volume *);

/**
 * Internal:
 *
 * ntfs_mft_load - load the $MFT and setup the ntfs volume with it
 * @vol:	ntfs volume whose $MFT to load
 *
 * Load $MFT from @vol and setup @vol with it. After calling this function the
 * volume @vol is ready for use by all read access functions provided by the
 * ntfs library.
 *
 * Return 0 on success and -1 on error with errno set to the error code.
 */
static int ntfs_mft_load(ntfs_volume *vol)
{
	VCN next_vcn, last_vcn, highest_vcn;
	s64 l;
	MFT_RECORD *mb = NULL;
	ntfs_attr_search_ctx *ctx = NULL;
	ATTR_RECORD *a;
	int eo;

	/* Manually setup an ntfs_inode. */
	vol->mft_ni = ntfs_inode_allocate(vol);
	mb = (MFT_RECORD*)malloc(vol->mft_record_size);
	if (!vol->mft_ni || !mb) {
		Dperror("Error allocating memory for $MFT");
		goto error_exit;
	}
	vol->mft_ni->mft_no = 0;
	vol->mft_ni->mrec = mb;
	/* Can't use any of the higher level functions yet! */
	l = ntfs_mst_pread(vol->fd, vol->mft_lcn << vol->cluster_size_bits, 1,
			vol->mft_record_size, mb);
	if (l != 1) {
		if (l != -1)
			errno = EIO;
		Dperror("Error reading $MFT");
		goto error_exit;
	}
	if (ntfs_is_baad_record(mb->magic)) {
		Dputs("Error: Incomplete multi sector transfer detected in "
				"$MFT.");
		goto io_error_exit;
	}
	if (!ntfs_is_mft_record(mb->magic)) {
		Dputs("Error: $MFT has invalid magic.");
		goto io_error_exit;
	}
	ctx = ntfs_attr_get_search_ctx(vol->mft_ni, mb);
	if (!ctx) {
		Dperror("Failed to allocate attribute search context");
		goto error_exit;
	}
	if (p2n(ctx->attr) < p2n(mb) ||
			(char*)ctx->attr > (char*)mb + vol->mft_record_size) {
		Dputs("Error: $MFT is corrupt.");
		goto io_error_exit;
	}
	/* Find the $ATTRIBUTE_LIST attribute in $MFT if present. */
	if (ntfs_attr_lookup(AT_ATTRIBUTE_LIST, AT_UNNAMED, 0, 0, 0, NULL, 0,
			ctx)) {
		if (errno != ENOENT) {
			Dputs("Error: $MFT has corrupt attribute list.");
			goto io_error_exit;
		}
		goto mft_has_no_attr_list;
	}
	NInoSetAttrList(vol->mft_ni);
	l = ntfs_get_attribute_value_length(ctx->attr);
	if (l <= 0 || l > 0x40000) {
		Dputs("Error: $MFT/$ATTRIBUTE_LIST has invalid length.");
		goto io_error_exit;
	}
	vol->mft_ni->attr_list_size = l;
	vol->mft_ni->attr_list = malloc(l);
	if (!vol->mft_ni->attr_list) {
		Dputs("Error: failed to allocate buffer for attribute list.");
		goto error_exit;
	}
	l = ntfs_get_attribute_value(vol, vol->mft_ni->mrec, ctx->attr,
			vol->mft_ni->attr_list);
	if (!l) {
		Dputs("Error: failed to get value of $MFT/$ATTRIBUTE_LIST.");
		goto io_error_exit;
	}
	if (l != vol->mft_ni->attr_list_size) {
		Dputs("Error: got unexepected amount of data when reading "
				"$MFT/$ATTRIBUTE_LIST.");
		goto io_error_exit;
	}
	if (ctx->attr->non_resident) {
		NInoSetAttrListNonResident(vol->mft_ni);
		// FIXME: We are duplicating work here! (AIA)
		vol->mft_ni->attr_list_rl = ntfs_mapping_pairs_decompress(vol,
				ctx->attr, NULL);
		if (!vol->mft_ni->attr_list_rl) {
			Dperror("Error: failed to get runlist for "
					"$MFT/$ATTRIBUTE_LIST");
			goto error_exit;
		}
	}
mft_has_no_attr_list:
	/* We now have a fully setup ntfs inode for $MFT in vol->mft_ni. */

	/* Get an ntfs attribute for $MFT/$DATA and set it up, too. */
	vol->mft_na = ntfs_attr_open(vol->mft_ni, AT_DATA, AT_UNNAMED, 0);
	if (!vol->mft_na) {
		Dperror("Failed to open ntfs attribute");
		goto error_exit;
	}
	/* Set the number of mft records. */
	vol->nr_mft_records = vol->mft_na->data_size >>
			vol->mft_record_size_bits;
	/* Read all extents from the $DATA attribute in $MFT. */
	ntfs_attr_reinit_search_ctx(ctx);
	last_vcn = vol->mft_na->allocated_size >> vol->cluster_size_bits;
	highest_vcn = next_vcn = 0;
	a = NULL;
	while (!ntfs_attr_lookup(AT_DATA, AT_UNNAMED, 0, 0, next_vcn, NULL, 0,
			ctx)) {
		runlist_element *nrl;

		a = ctx->attr;
		/* $MFT must be non-resident. */
		if (!a->non_resident) {
			Dputs("$MFT must be non-resident but a resident "
					"extent was found. $MFT is corrupt. "
					"Run chkdsk.");
			goto io_error_exit;
		}
		/* $MFT must be uncompressed and unencrypted. */
		if (a->flags & ATTR_COMPRESSION_MASK ||
				a->flags & ATTR_IS_ENCRYPTED) {
			Dputs("$MFT must be uncompressed and unencrypted but "
					"a compressed/encrypted extent was "
					"found. $MFT is corrupt. Run chkdsk.");
			goto io_error_exit;
		}
		/*
		 * Decompress the mapping pairs array of this extent and merge
		 * the result into the existing runlist. No need for locking
		 * as we have exclusive access to the inode at this time and we
		 * are a mount in progress task, too.
		 */
		nrl = ntfs_mapping_pairs_decompress(vol, a, vol->mft_na->rl);
		if (!nrl) {
			Dperror("ntfs_mapping_pairs_decompress() failed");
			goto error_exit;
		}
		vol->mft_na->rl = nrl;

		/* Get the lowest vcn for the next extent. */
		highest_vcn = sle64_to_cpu(a->highest_vcn);
		next_vcn = highest_vcn + 1;

		/* Only one extent or error, which we catch below. */
		if (next_vcn <= 0)
			break;

		/* Avoid endless loops due to corruption. */
		if (next_vcn < sle64_to_cpu(a->lowest_vcn)) {
			Dputs("$MFT has corrupt attribute list attribute. "
					"Run chkdsk.");
			goto io_error_exit;
		}
	}
	if (!a) {
		Dputs("$MFT/$DATA attribute not found. $MFT is corrupt. "
				"Run chkdsk.");
		goto io_error_exit;
	}
	if (highest_vcn && highest_vcn != last_vcn - 1) {
		Dputs("Failed to load the complete runlist for $MFT/$DATA. "
				"Bug or corrupt $MFT. Run chkdsk.");
		Dprintf("highest_vcn = 0x%Lx, last_vcn - 1 = 0x%Lx\n",
				(long long)highest_vcn,
				(long long)last_vcn - 1);
		goto io_error_exit;
	}
	/* Done with the $Mft mft record. */
	ntfs_attr_put_search_ctx(ctx);
	ctx = NULL;
	/*
	 * The volume is now setup so we can use all read access functions.
	 */
	vol->mftbmp_na = ntfs_attr_open(vol->mft_ni, AT_BITMAP, AT_UNNAMED, 0);
	if (!vol->mftbmp_na) {
		Dperror("Failed to open $MFT/$BITMAP");
		goto error_exit;
	}
	return 0;
io_error_exit:
	errno = EIO;
error_exit:
	eo = errno;
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (vol->mft_na) {
		ntfs_attr_close(vol->mft_na);
		vol->mft_na = NULL;
	}
	if (vol->mft_ni) {
		ntfs_inode_close(vol->mft_ni);
		vol->mft_ni = NULL;
	}
	errno = eo;
	return -1;
}

/**
 * Internal:
 *
 * ntfs_mftmirr_load - load the $MFTMirr and setup the ntfs volume with it
 * @vol:	ntfs volume whose $MFTMirr to load
 *
 * Load $MFTMirr from @vol and setup @vol with it. After calling this function
 * the volume @vol is ready for use by all write access functions provided by
 * the ntfs library (assuming ntfs_mft_load() has been called successfully
 * beforehand).
 *
 * Return 0 on success and -1 on error with errno set to the error code.
 */
static int ntfs_mftmirr_load(ntfs_volume *vol)
{
	int i;
	runlist_element rl[2];

	vol->mftmirr_ni = ntfs_inode_open(vol, FILE_MFTMirr);
	if (!vol->mftmirr_ni) {
		Dperror("Failed to open inode $MFTMirr");
		return -1;
	}
	/* Get an ntfs attribute for $MFTMirr/$DATA, too. */
	vol->mftmirr_na = ntfs_attr_open(vol->mftmirr_ni, AT_DATA, AT_UNNAMED, 0);
	if (!vol->mftmirr_na) {
		Dperror("Failed to open $MFTMirr/$DATA");
		goto error_exit;
	}
	if (ntfs_attr_map_runlist(vol->mftmirr_na, 0) < 0) {
		Dperror("Failed to map runlist of $MFTMirr/$DATA");
		goto error_exit;
	}
	/* Construct the mft mirror runlist. */
	rl[0].vcn = 0;
	rl[0].lcn = vol->mftmirr_lcn;
	rl[0].length = (vol->mftmirr_size * vol->mft_record_size +
			vol->cluster_size - 1) / vol->cluster_size;
	rl[1].vcn = rl[0].length;
	rl[1].lcn = LCN_ENOENT;
	rl[1].length = 0;
	/* Compare the two runlists. They must be identical. */
	i = 0;
	do {
		if (rl[i].vcn != vol->mftmirr_na->rl[i].vcn ||
				rl[i].lcn != vol->mftmirr_na->rl[i].lcn ||
				rl[i].length != vol->mftmirr_na->rl[i].length) {
			Dputs("Error: $MFTMirr location mismatch! Run chkdsk.");
			errno = EIO;
			goto error_exit;
		}
	} while (rl[i++].length);
	return 0;
error_exit:
	i = errno;
	if (vol->mftmirr_na) {
		ntfs_attr_close(vol->mftmirr_na);
		vol->mftmirr_na = NULL;
	}
	ntfs_inode_close(vol->mftmirr_ni);
	vol->mftmirr_ni = NULL;
	errno = i;
	return -1;
}

/**
 * ntfs_volume_startup - allocate and setup an ntfs volume
 * @name:	name of device/file to open
 * @rwflag:	optional mount flags
 *
 * Load, verify, and parse bootsector; load and setup $MFT and $MFTMirr. After
 * calling this function, the volume is setup sufficiently to call all read
 * and write access functions provided by the library.
 *
 * Return the allocated volume structure on success and NULL on error with
 * errno set to the error code.
 */
ntfs_volume *ntfs_volume_startup(const char *name, unsigned long rwflag)
{
	LCN mft_zone_size, mft_lcn;
	s64 br;
	const char *OK = "OK";
	const char *FAILED = "FAILED";
	ntfs_volume *vol;
	NTFS_BOOT_SECTOR *bs = NULL;
	int eo;
#ifdef DEBUG
	BOOL debug = 1;
#else
	BOOL debug = 0;
#endif

	/* Allocate the volume structure. */
	vol = __ntfs_volume_allocate();
	if (!vol)
		return NULL;
	/* Make a copy of the partition name. */
	if (!(vol->dev_name = strdup(name)))
		goto error_exit;
	/* Allocate the boot sector structure. */
	if (!(bs = (NTFS_BOOT_SECTOR *)malloc(sizeof(NTFS_BOOT_SECTOR))))
		goto error_exit;
	if (rwflag & MS_RDONLY)
		NVolSetReadOnly(vol);
	Dprintf("Reading bootsector... ");
	if ((vol->fd = open(name, NVolReadOnly(vol) ? O_RDONLY: O_RDWR)) < 0) {
		Dputs(FAILED);
		Dperror("Error opening partition file");
		goto error_exit;
	}
	/* Now read the bootsector. */
	br = ntfs_pread(vol->fd, 0, sizeof(NTFS_BOOT_SECTOR), bs);
	if (br != sizeof(NTFS_BOOT_SECTOR)) {
		Dputs(FAILED);
		if (br != -1)
			errno = EINVAL;
		if (!br)
			Dputs("Error: partition is smaller than bootsector "
					"size. Weird!");
		else
			Dperror("Error reading bootsector");
		goto error_exit;
	}
	Dputs(OK);
	if (!ntfs_boot_sector_is_ntfs(bs, !debug)) {
		Dprintf("Error: %s is not a valid NTFS partition!\n", name);
		errno = EINVAL;
		goto error_exit;
	}
	if (ntfs_boot_sector_parse(vol, bs) < 0) {
		Dperror("Failed to parse ntfs bootsector");
		goto error_exit;
	}
	free(bs);
	bs = NULL;

	/*
	 * We now initialize the cluster allocator.
	 *
	 * FIXME: Move this to its own function? (AIA)
	 */

	// TODO: Make this tunable at mount time. (AIA)
	vol->mft_zone_multiplier = 1;

	/* Determine the size of the MFT zone. */
	mft_zone_size = vol->nr_clusters;
	switch (vol->mft_zone_multiplier) {  /* % of volume size in clusters */
	case 4:
		mft_zone_size >>= 1;			/* 50%   */
		break;
	case 3:
		mft_zone_size = mft_zone_size * 3 >> 3;	/* 37.5% */
		break;
	case 2:
		mft_zone_size >>= 2;			/* 25%   */
		break;
	/* case 1: */
	default:
		mft_zone_size >>= 3;			/* 12.5% */
		break;
	}

	/* Setup the mft zone. */
	vol->mft_zone_start = vol->mft_zone_pos = vol->mft_lcn;
	Dprintf("mft_zone_pos = 0x%Lx\n", (long long)vol->mft_zone_pos);

	/*
	 * Calculate the mft_lcn for an unmodified NTFS volume (see mkntfs
	 * source) and if the actual mft_lcn is in the expected place or even
	 * further to the front of the volume, extend the mft_zone to cover the
	 * beginning of the volume as well. This is in order to protect the
	 * area reserved for the mft bitmap as well within the mft_zone itself.
	 * On non-standard volumes we don't protect it as the overhead would be
	 * higher than the speed increase we would get by doing it.
	 */
	mft_lcn = (8192 + 2 * vol->cluster_size - 1) / vol->cluster_size;
	if (mft_lcn * vol->cluster_size < 16 * 1024)
		mft_lcn = (16 * 1024 + vol->cluster_size - 1) /
				vol->cluster_size;
	if (vol->mft_zone_start <= mft_lcn)
		vol->mft_zone_start = 0;
	Dprintf("mft_zone_start = 0x%Lx\n", (long long)vol->mft_zone_start);

	/*
	 * Need to cap the mft zone on non-standard volumes so that it does
	 * not point outside the boundaries of the volume. We do this by
	 * halving the zone size until we are inside the volume.
	 */
	vol->mft_zone_end = vol->mft_lcn + mft_zone_size;
	while (vol->mft_zone_end >= vol->nr_clusters) {
		mft_zone_size >>= 1;
		vol->mft_zone_end = vol->mft_lcn + mft_zone_size;
	}
	Dprintf("mft_zone_end = 0x%Lx\n", (long long)vol->mft_zone_end);

	/*
	 * Set the current position within each data zone to the start of the
	 * respective zone.
	 */
	vol->data1_zone_pos = vol->mft_zone_end;
	Dprintf("data1_zone_pos = 0x%Lx\n", vol->data1_zone_pos);
	vol->data2_zone_pos = 0;
	Dprintf("data2_zone_pos = 0x%Lx\n", vol->data2_zone_pos);

	/* Set the mft data allocation position to mft record 24. */
	vol->mft_data_pos = 24;

	/*
	 * The cluster allocator is now fully operational.
	 */

	/* Need to setup $MFT so we can use the library read functions. */
	Dprintf("Loading $MFT... ");
	if (ntfs_mft_load(vol) < 0) {
		Dputs(FAILED);
		Dperror("Failed to load $MFT");
		goto error_exit;
	}
	Dputs(OK);

	/* Need to setup $MFTMirr so we can use the write functions, too. */
	Dprintf("Loading $MFTMirr... ");
	if (ntfs_mftmirr_load(vol) < 0) {
		Dputs(FAILED);
		Dperror("Failed to load $MFTMirr");
		goto error_exit;
	}
	Dputs(OK);
	return vol;
error_exit:
	eo = errno;
	if (bs)
		free(bs);
	if (vol)
		__ntfs_volume_release(vol);
	errno = eo;
	return NULL;
}

/**
 * ntfs_mount - open ntfs volume
 * @name:	name of device/file to open
 * @rwflag:	optional mount flags
 *
 * This function mounts an ntfs volume. @name should contain the name of the
 * device/file to mount as the ntfs volume.
 *
 * @rwflags is an optional second parameter. The same flags are used as for
 * the mount system call (man 2 mount). Currently only the following flag
 * is implemented:
 *	MS_RDONLY	- mount volume read-only
 *
 * The function opens the device or file @name and verifies that it contains a
 * valid bootsector. Then, it allocates an ntfs_volume structure and initializes
 * some of the values inside the structure from the information stored in the
 * bootsector. It proceeds to load the necessary system files and completes
 * setting up the structure.
 *
 * Return the allocated volume structure on success and NULL on error with
 * errno set to the error code.
 *
 * Note, that a copy is made of @name, and hence it can be discarded as
 * soon as the function returns.
 */
ntfs_volume *ntfs_mount(const char *name, unsigned long rwflag)
{
	s64 l;
	const char *OK = "OK";
	const char *FAILED = "FAILED";
	ntfs_volume *vol;
	u8 *m = NULL, *m2 = NULL;
	ntfs_attr_search_ctx *ctx = NULL;
	ntfs_inode *ni;
	ntfs_attr *na;
	ATTR_RECORD *a;
	VOLUME_INFORMATION *vinf;
	uchar_t *vname;
	int i, j, eo;
	u32 u;

	if (!name) {
		errno = EINVAL;
		return NULL;
	}

	vol = ntfs_volume_startup(name, rwflag);
	if (!vol) {
		Dperror("Failed to startup volume");
		return NULL;
	}

	/* Load data from $MFT and $MFTMirr and compare the contents. */
	m = (u8*)malloc(vol->mftmirr_size << vol->mft_record_size_bits);
	m2 = (u8*)malloc(vol->mftmirr_size << vol->mft_record_size_bits);
	if (!m || !m2) {
		Dperror("Failed to allocate memory");
		goto error_exit;
	}

	l = ntfs_attr_mst_pread(vol->mft_na, 0, vol->mftmirr_size,
			vol->mft_record_size, m);
	if (l != vol->mftmirr_size) {
		if (l == -1)
			Dperror("Failed to read $MFT");
		else {
			Dputs("Length of data not equal expected length.");
			errno = EIO;
		}
		goto error_exit;
	}
	l = ntfs_attr_mst_pread(vol->mftmirr_na, 0, vol->mftmirr_size,
			vol->mft_record_size, m2);
	if (l != vol->mftmirr_size) {
		if (l == -1)
			Dperror("Failed to read $MFTMirr");
		else {
			Dputs("Length of data not equal expected length.");
			errno = EIO;
		}
		goto error_exit;
	}
	Dprintf("Comparing $MFTMirr to $MFT... ");
	for (i = 0; i < vol->mftmirr_size; ++i) {
		const char *ESTR[12] = { "$MFT", "$MFTMirr", "$LogFile",
			"$Volume", "$AttrDef", "root directory", "$Bitmap",
			"$Boot", "$BadClus", "$Secure", "$UpCase", "$Extend" };
		const char *s;

		if (i < 12)
			s = ESTR[i];
		else if (i < 16)
			s = "system file";
		else
			s = "mft record";

		if (ntfs_is_baad_recordp(m + i * vol->mft_record_size)) {
			Dputs("FAILED");
			Dprintf("$MFT error: Incomplete multi sector transfer "
					"detected in %s.\n", s);
			goto io_error_exit;
		}
		if (!ntfs_is_mft_recordp(m + i * vol->mft_record_size)) {
			Dputs("FAILED");
			Dprintf("$MFT error: Invalid mft record for %s.\n", s);
			goto io_error_exit;
		}
		if (ntfs_is_baad_recordp(m2 + i * vol->mft_record_size)) {
			Dputs("FAILED");
			Dprintf("$MFTMirr error: Incomplete multi sector "
					"transfer detected in %s.\n", s);
			goto io_error_exit;
		}
		if (!ntfs_is_mft_recordp(m2 + i * vol->mft_record_size)) {
			Dputs("FAILED");
			Dprintf("$MFTMirr error: Invalid mft record for %s.\n",
					s);
			goto io_error_exit;
		}
		if (memcmp((u8*)m + i * vol->mft_record_size, (u8*)m2 +
				i * vol->mft_record_size,
				ntfs_mft_record_get_data_size((MFT_RECORD*)(
				(u8*)m + i * vol->mft_record_size)))) {
			Dputs(FAILED);
			Dputs("$MFTMirr does not match $MFT. Run chkdsk.");
			goto io_error_exit;
		}
	}
	Dputs(OK);

	free(m2);
	free(m);
	m = m2 = NULL;

	/* Now load the bitmap from $Bitmap. */
	Dprintf("Loading $Bitmap... ");
	vol->lcnbmp_ni = ntfs_inode_open(vol, FILE_Bitmap);
	if (!vol->lcnbmp_ni) {
		Dputs(FAILED);
		Dperror("Failed to open inode");
		goto error_exit;
	}
	/* Get an ntfs attribute for $Bitmap/$DATA. */
	vol->lcnbmp_na = ntfs_attr_open(vol->lcnbmp_ni, AT_DATA, AT_UNNAMED, 0);
	if (!vol->lcnbmp_na) {
		Dputs(FAILED);
		Dperror("Failed to open ntfs attribute");
		goto error_exit;
	}
	/* Done with the $Bitmap mft record. */
	Dputs(OK);

	/* Now load the upcase table from $UpCase. */
	Dprintf("Loading $UpCase... ");
	ni = ntfs_inode_open(vol, FILE_UpCase);
	if (!ni) {
		Dputs(FAILED);
		Dperror("Failed to open inode");
		goto error_exit;
	}
	/* Get an ntfs attribute for $UpCase/$DATA. */
	na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
	if (!na) {
		Dputs(FAILED);
		Dperror("Failed to open ntfs attribute");
		goto error_exit;
	}
	/*
	 * Note: Normally, the upcase table has a length equal to 65536
	 * 2-byte Unicode characters but allow for different cases, so no
	 * checks done. Just check we don't overflow 32-bits worth of Unicode
	 * characters.
	 */
	if (na->data_size & ~0x1ffffffffULL) {
		Dputs(FAILED);
		Dputs("Error: Upcase table is too big (max 32-bit allowed).");
		errno = EINVAL;
		goto error_exit;
	}
	vol->upcase_len = na->data_size >> 1;
	vol->upcase = (uchar_t*)malloc(na->data_size);
	if (!vol->upcase) {
		Dputs(FAILED);
		Dputs("Not enough memory to load $UpCase.");
		goto error_exit;
	}
	/* Read in the $DATA attribute value into the buffer. */
	l = ntfs_attr_pread(na, 0, na->data_size, vol->upcase);
	if (l != na->data_size) {
		Dputs(FAILED);
		Dputs("Amount of data read does not correspond to expected "
				"length!");
		errno = EIO;
		goto error_exit;
	}
	/* Done with the $UpCase mft record. */
	Dputs(OK);
	ntfs_attr_close(na);
	if (ntfs_inode_close(ni))
		Dperror("Failed to close inode, leaking memory");

	/*
	 * Now load $Volume and set the version information and flags in the
	 * vol structure accordingly.
	 */
	Dprintf("Loading $Volume... ");
	ni = ntfs_inode_open(vol, FILE_Volume);
	if (!ni) {
		Dputs(FAILED);
		Dperror("Failed to open inode");
		goto error_exit;
	}
	/* Get an ntfs attribute for $UpCase/$DATA. */
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		Dputs(FAILED);
		Dperror("Failed to allocate attribute search context");
		goto error_exit;
	}
	/* Find the $VOLUME_INFORMATION attribute. */
	if (ntfs_attr_lookup(AT_VOLUME_INFORMATION, AT_UNNAMED, 0, 0, 0, NULL,
			0, ctx)) {
		Dputs(FAILED);
		Dputs("$VOLUME_INFORMATION attribute not found in "
				"$Volume?!?");
		goto error_exit;
	}
	a = ctx->attr;
	/* Has to be resident. */
	if (a->non_resident) {
		Dputs(FAILED);
		Dputs("Error: Attribute $VOLUME_INFORMATION must be resident "
				"(and it isn't)!");
		errno = EIO;
		goto error_exit;
	}
	/* Get a pointer to the value of the attribute. */
	vinf = (VOLUME_INFORMATION*)(le16_to_cpu(a->value_offset) + (char*)a);
	/* Sanity checks. */
	if ((char*)vinf + le32_to_cpu(a->value_length) > (char*)ctx->mrec +
			le16_to_cpu(ctx->mrec->bytes_in_use) ||
			le16_to_cpu(a->value_offset) + le32_to_cpu(
			a->value_length) > le32_to_cpu(a->length)) {
		Dputs(FAILED);
		Dputs("Error: Attribute $VOLUME_INFORMATION in $Volume is "
				"corrupt!");
		errno = EIO;
		goto error_exit;
	}
	/* Setup vol from the volume information attribute value. */
	vol->major_ver = vinf->major_ver;
	vol->minor_ver = vinf->minor_ver;
	/* Do not use le16_to_cpu() macro here as our VOLUME_FLAGS are
	   defined using cpu_to_le16() macro and hence are consistent. */
	vol->flags = vinf->flags;
	/* Find the $VOLUME_NAME attribute. */
	ntfs_attr_reinit_search_ctx(ctx);
	if (ntfs_attr_lookup(AT_VOLUME_NAME, AT_UNNAMED, 0, 0, 0, NULL, 0,
			ctx)) {
		Dputs(FAILED);
		Dputs("$VOLUME_NAME attribute not found in $Volume?!?");
		goto error_exit;
	}
	a = ctx->attr;
	/* Has to be resident. */
	if (a->non_resident) {
		Dputs(FAILED);
		Dputs("Error: Attribute $VOLUME_NAME must be resident!");
		errno = EIO;
		goto error_exit;
	}
	/* Get a pointer to the value of the attribute. */
	vname = (uchar_t*)(le16_to_cpu(a->value_offset) + (char*)a);
	u = le32_to_cpu(a->value_length) / 2;
	/* Convert Unicode volume name to current locale multibyte format. */
	vol->vol_name = NULL;
	if (ntfs_ucstombs(vname, u, &vol->vol_name, 0) == -1) {
		Dperror("Error: Volume name could not be converted to "
				"current locale");
		Dputs("Forcing name into ASCII by replacing non-ASCII "
				"characters with underscores.");
		vol->vol_name = malloc(u + 1);
		if (!vol->vol_name) {
			Dputs(FAILED);
			Dputs("Error: Unable to allocate memory for volume "
					"name!");
			goto error_exit;
		}
		for (j = 0; j < u; j++) {
			uchar_t uc = le16_to_cpu(vname[j]);
			if (uc > 0xff)
				uc = (uchar_t)'_';
			vol->vol_name[j] = (char)uc;
		}
		vol->vol_name[u] = '\0';
	}
	Dputs(OK);
	ntfs_attr_put_search_ctx(ctx);
	ctx = NULL;
	if (ntfs_inode_close(ni))
		Dperror("Failed to close inode, leaking memory");

	/* FIXME: Need to deal with FILE_AttrDef. (AIA) */

	return vol;
io_error_exit:
	errno = EIO;
error_exit:
	eo = errno;
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		free(m);
	if (m2)
		free(m2);
	if (vol)
		__ntfs_volume_release(vol);
	errno = eo;
	return NULL;
}

/**
 * ntfs_umount - close ntfs volume
 * @vol: address of ntfs_volume structure of volume to close
 * @force: if true force close the volume even if it is busy
 *
 * Deallocate all structures (including @vol itself) associated with the ntfs
 * volume @vol.
 *
 * Return 0 on success. On error return -1 with errno set appropriately
 * (most likely to one of EAGAIN, EBUSY or EINVAL). The EAGAIN error means that
 * an operation is in progress and if you try the close later the operation
 * might be completed and the close succeed.
 *
 * If @force is true (i.e. not zero) this function will close the volume even
 * if this means that data might be lost.
 *
 * @vol must have previously been returned by a call to ntfs_mount().
 *
 * @vol itself is deallocated and should no longer be dereferenced after this
 * function returns success. If it returns an error then nothing has been done
 * so it is safe to continue using @vol.
 */
int ntfs_umount(ntfs_volume *vol, const BOOL force)
{
	if (!vol) {
		errno = EINVAL;
		return -1;
	}
	__ntfs_volume_release(vol);
	return 0;
}

#ifdef HAVE_MNTENT_H
/**
 * Internal:
 *
 * ntfs_mntent_check - desc
 *
 * If you are wanting to use this, you actually wanted to use
 * ntfs_check_if_mounted(), you just didn't realize. (-:
 *
 * See description of ntfs_check_if_mounted(), below.
 */
static int ntfs_mntent_check(const char *file, unsigned long *mnt_flags)
{
	struct mntent *mnt;
	FILE *f;

	if (!(f = setmntent(MOUNTED, "r")))
		return -1;
	while ((mnt = getmntent(f)))
		if (!strcmp(file, mnt->mnt_fsname))
			break;
	endmntent(f);
	if (!mnt)
		return 0;
	*mnt_flags = NTFS_MF_MOUNTED;
	if (!strcmp(mnt->mnt_dir, "/"))
		*mnt_flags |= NTFS_MF_ISROOT;
	if (hasmntopt(mnt, "ro") && !hasmntopt(mnt, "rw"))
		*mnt_flags |= NTFS_MF_READONLY;
	return 0;
}

#endif

/**
 * ntfs_check_if_mounted - check if an ntfs volume is currently mounted
 * @file:	device file to check
 * @mnt_flags:	pointer into which to return the ntfs mount flags (see volume.h)
 *
 * If the running system does not support the {set,get,end}mntent() calls,
 * just return 0 and set *@mnt_flags to zero.
 *
 * When the system does support the calls, ntfs_check_if_mounted() first tries
 * to find the device @file in /etc/mtab (or wherever this is kept on the
 * running system). If it is not found, assume the device is not mounted and
 * return 0 and set *@mnt_flags to zero.
 *
 * If the device @file is found, set the NTFS_MF_MOUNTED flags in *@mnt_flags.
 *
 * Further if @file is mounted as the file system root ("/"), set the flag
 * NTFS_MF_ISROOT in *@mnt_flags.
 *
 * Finally, check if the file system is mounted read-only, and if so set the
 * NTFS_MF_READONLY flag in *@mnt_flags.
 *
 * On sucess return 0 with *@mnt_flags set to the ntfs mount flags.
 *
 * On error return -1 with errno set to the error code.
 */
int ntfs_check_if_mounted(const char *file, unsigned long *mnt_flags)
{
	*mnt_flags = 0;
#ifdef HAVE_MNTENT_H
	return ntfs_mntent_check(file, mnt_flags);
#else
	return 0;
#endif
}

/**
 * ntfs_version_is_supported - check if NTFS version is supported.
 * @vol:	ntfs volume whose version we're interested in.
 *
 * The function checks if the NTFS volume version is known or not.
 * Version 1.1 and 1.2 are used by Windows NT4.
 * Version 2.x is used by Windows 2000 Beta's
 * Version 3.0 is used by Windows 2000.
 * Version 3.1 is used by Windows XP and .NET.
 *
 * Return 0 if NTFS version is supported otherwise -1 with errno set.
 *
 * The following error codes are defined:
 *	ENOTSUP   Unknown NTFS versions
 *	EINVAL	  Invalid argument
 */
int ntfs_version_is_supported(ntfs_volume *vol)
{
	u8 major, minor;

	if (!vol) {
		errno = EINVAL;
		return -1;
	}

	major = vol->major_ver;
	minor = vol->minor_ver;

	if (NTFS_V1_1(major, minor) || NTFS_V1_2(major, minor))
		return 0;

	if (NTFS_V2_X(major, minor))
		return 0;

	if (NTFS_V3_0(major, minor) || NTFS_V3_1(major, minor))
		return 0;

	errno = ENOTSUP;
	return -1;
}

/**
 * ntfs_logfile_reset - "empty" $LogFile data attribute value
 * @vol:	ntfs volume whose $LogFile we intend to reset.
 *
 * Fill the value of the $LogFile data attribute, i.e. the contents of
 * the file, with 0xff's, thus marking the journal as empty.
 *
 * FIXME(?): We might need to zero the LSN field of every single mft
 * record as well. (But, first try without doing that and see what
 * happens, since chkdsk might pickup the pieces and do it for us...)
 *
 * On success return 0.
 *
 * On error return -1 with errno set to the error code.
 */
int ntfs_logfile_reset(ntfs_volume *vol)
{
	ntfs_inode *ni;
	ntfs_attr *na;
	s64 len, pos, count;
	char buf[NTFS_BUF_SIZE];
	int eo;

	if (!vol) {
		errno = EINVAL;
		return -1;
	}

	if ((ni = ntfs_inode_open(vol, FILE_LogFile)) == NULL) {
		Dperror("Failed to open inode FILE_LogFile.\n");
		return -1;
	}

	if ((na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0)) == NULL) {
		Dperror("Failed to open $FILE_LogFile/$DATA\n");
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
	while ((count = ntfs_attr_pread(na, pos, NTFS_BUF_SIZE, buf)) > 0)
		pos += count;

	if (count == -1 || pos != len) {
		Dprintf("Amount of $LogFile data read does not "
			"correspond to expected length!");
		if (count != -1)
			errno = EIO;
		goto io_error_exit;
	}

	/* Fill the buffer with 0xff's. */
	memset(buf, -1, NTFS_BUF_SIZE);

	/* Set the $DATA attribute. */
	pos = 0;
	while ((count = len - pos) > 0) {
		if (count > NTFS_BUF_SIZE)
			count = NTFS_BUF_SIZE;

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
 * ntfs_volume_set_flags - set the flags of an ntfs volume
 * @vol:	ntfs volume where we set the volume flags
 * @flags:	new flags
 *
 * Set the on-disk volume flags in the mft record of $Volume and
 * on volume @vol to @flags.
 *
 * Return 0 if successful and -1 if not with errno set to the error code.
 */
int ntfs_volume_set_flags(ntfs_volume *vol, const u16 flags)
{
	MFT_RECORD *m = NULL;
	ATTR_RECORD *r;
	VOLUME_INFORMATION *c;
	ntfs_attr_search_ctx *ctx;
	int ret = -1;	/* failure */

	if (!vol) {
		errno = EINVAL;
		return -1;
	}

	if (ntfs_file_record_read(vol, FILE_Volume, &m, NULL)) {
		Dperror("Failed to read $Volume");
		return -1;
	}

	/* Sanity check */
	if (!(m->flags & MFT_RECORD_IN_USE)) {
		Dprintf("Error: $Volume has been deleted. Cannot "
			"handle this yet. Run chkdsk to fix this.\n");
		errno = EIO;
		goto err_exit;
	}

	/* Get a pointer to the volume information attribute. */
	ctx = ntfs_attr_get_search_ctx(NULL, m);
	if (!ctx) {
		Dperror("Failed to allocate attribute search context");
		goto err_exit;
	}
	if (ntfs_attr_lookup(AT_VOLUME_INFORMATION, AT_UNNAMED, 0, 0, 0, NULL,
			0, ctx)) {
		Dputs("Error: Attribute $VOLUME_INFORMATION was not found in "
				"$Volume!");
		goto err_out;
	}
	r = ctx->attr;
	/* Sanity check. */
	if (r->non_resident) {
		Dputs("Error: Attribute $VOLUME_INFORMATION must be resident "
				"(and it isn't)!");
		errno = EIO;
		goto err_out;
	}
	/* Get a pointer to the value of the attribute. */
	c = (VOLUME_INFORMATION*)(le16_to_cpu(r->value_offset) + (char*)r);
	/* Sanity checks. */
	if ((char*)c + le32_to_cpu(r->value_length) >
			le16_to_cpu(m->bytes_in_use) + (char*)m ||
			le16_to_cpu(r->value_offset) +
			le32_to_cpu(r->value_length) > le32_to_cpu(r->length)) {
		Dputs("Error: Attribute $VOLUME_INFORMATION in $Volume is "
				"corrupt!");
		errno = EIO;
		goto err_out;
	}
	/* Set the volume flags. */
	vol->flags = c->flags = cpu_to_le16(flags);

	if (ntfs_mft_record_write(vol, FILE_Volume, m)) {
		Dperror("Error writing $Volume");
		goto err_out;
	}

	ret = 0; /* success */
err_out:
	ntfs_attr_put_search_ctx(ctx);
err_exit:
	if (m)
		free(m);
	return ret;
}

