/*
 * mft.c - Mft record handling code. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2000-2003 Anton Altaparmakov
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
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "compat.h"

#include "types.h"
#include "device.h"
#include "debug.h"
#include "bitmap.h"
#include "attrib.h"
#include "inode.h"
#include "volume.h"
#include "layout.h"
#include "mft.h"

/**
 * ntfs_mft_records_read - read records from the mft from disk
 * @vol:	volume to read from
 * @mref:	starting mft record number to read
 * @count:	number of mft records to read
 * @b:		output data buffer
 *
 * Read @count mft records starting at @mref from volume @vol into buffer
 * @b. Return 0 on success or -1 on error, with errno set to the error
 * code.
 *
 * The read mft records are mst deprotected and are hence ready to use. The
 * caller should check each record with is_baad_record() in case mst
 * deprotection failed.
 *
 * NOTE: @b has to be at least of size @count * vol->mft_record_size.
 */
int ntfs_mft_records_read(const ntfs_volume *vol, const MFT_REF mref,
		const s64 count, MFT_RECORD *b)
{
	s64 br;
	VCN m;

	Dprintf("%s(): Entering for inode 0x%Lx.\n", __FUNCTION__, MREF(mref));
	if (!vol || !vol->mft_na || !b || count < 0) {
		errno = EINVAL;
		return -1;
	}
	m = MREF(mref);
	if (m + count > vol->nr_mft_records) {
		errno = ESPIPE;
		return -1;
	}
	br = ntfs_attr_mst_pread(vol->mft_na, m << vol->mft_record_size_bits,
			count, vol->mft_record_size, b);
	if (br != count) {
		if (br != -1)
			errno = EIO;
		if (br >= 0)
			Dputs("Error: partition is smaller than it should be!");
		else
			Dperror("Error reading $Mft record(s)");
		return -1;
	}
	return 0;
}

/**
 * ntfs_mft_records_write - write mft records to disk
 * @vol:	volume to write to
 * @mref:	starting mft record number to write
 * @count:	number of mft records to write
 * @b:		data buffer containing the mft records to write
 *
 * Write @count mft records starting at @mref from data buffer @b to volume
 * @vol. Return 0 on success or -1 on error, with errno set to the error code.
 *
 * Before the mft records are written, they are mst protected. After the write,
 * they are deprotected again, thus resulting in an increase in the update
 * sequence number inside the data buffer @b.
 *
 * If any mft records are written which are also represented in the mft mirror
 * $MFTMirr, we make a copy of the relevant parts of the data buffer @b into a
 * temporary buffer before we do the actual write. Then if at least one mft
 * record was successfully written, we write the appropriate mft records from
 * the copied buffer to the mft mirror, too.
 */
int ntfs_mft_records_write(const ntfs_volume *vol, const MFT_REF mref,
		const s64 count, MFT_RECORD *b)
{
	s64 bw;
	VCN m;
	void *bmirr = NULL;
	int cnt = 0, res = 0;

	Dprintf("%s(): Entering for inode 0x%Lx.\n", __FUNCTION__, MREF(mref));
	if (!vol || !vol->mft_na || !b || count < 0) {
		errno = EINVAL;
		return -1;
	}
	m = MREF(mref);
	if (m < vol->mftmirr_size) {
		cnt = vol->mftmirr_size - m;
		if (cnt > count)
			cnt = count;
		bmirr = malloc(cnt * vol->mft_record_size);
		if (!bmirr)
			return -1;
		memcpy(bmirr, b, cnt * vol->mft_record_size);
	}
	if (m + count > vol->nr_mft_records) {
		// TODO: Need to extend $MFT. This is not just normal attribute
		// extension as many rules need to be observed. (AIA)
		if (bmirr);
			free(bmirr);
		errno = ENOTSUP;
		return -1;
	}
	bw = ntfs_attr_mst_pwrite(vol->mft_na, m << vol->mft_record_size_bits,
			count, vol->mft_record_size, b);
	if (bw != count) {
		if (bw != -1)
			errno = EIO;
		if (bw >= 0)
			Dputs("Error: partial write while writing $Mft "
					"record(s)!\n");
		else
			Dperror("Error writing $Mft record(s)");
		res = errno;
	}
	if (bmirr && bw > 0) {
		if (bw < cnt)
			cnt = bw;
		bw = ntfs_attr_mst_pwrite(vol->mftmirr_na,
				m << vol->mft_record_size_bits, cnt,
				vol->mft_record_size, bmirr);
		if (bw != cnt) {
			if (bw != -1)
				errno = EIO;
			Dputs("Error: failed to sync $MFTMirr! Run chkdsk.");
			res = errno;
		}
	}
	if (bmirr)
		free(bmirr);
	if (!res)
		return res;
	errno = res;
	return -1;
}

/**
 * ntfs_file_record_read - read a FILE record from the mft from disk
 * @vol:	volume to read from
 * @mref:	mft reference specifying mft record to read
 * @mrec:	address of pointer in which to return the mft record
 * @attr:	address of pointer in which to return the first attribute
 *
 * Read a FILE record from the mft of @vol from the storage medium. @mref
 * specifies the mft record to read, including the sequence number, which can
 * be 0 if no sequence number checking is to be performed.
 *
 * The function allocates a buffer large enough to hold the mft record and
 * reads the record into the buffer (mst deprotecting it in the process).
 * *@mrec is then set to point to the buffer.
 *
 * If @attr is not NULL, *@attr is set to point to the first attribute in the
 * mft record, i.e. *@attr is a pointer into *@mrec.
 *
 * Return 0 on success, or -1 on error, with errno set to the error code.
 *
 * The read mft record is checked for having the magic FILE,
 * and for having a matching sequence number (if MSEQNO(*@mref) != 0).
 * If either of these fails, -1 is returned and errno is set to EIO. If you get
 * this, but you still want to read the mft record (e.g. in order to correct
 * it), use ntfs_mft_record_read() directly.
 *
 * Note: Caller has to free *@mrec when finished.
 *
 * Note: We do not check if the mft record is flagged in use. The caller can
 *	 check if desired.
 */
int ntfs_file_record_read(const ntfs_volume *vol, const MFT_REF mref,
		MFT_RECORD **mrec, ATTR_RECORD **attr)
{
	MFT_RECORD *m;
	ATTR_RECORD *a;
	int err;

	if (!vol || !mrec) {
		errno = EINVAL;
		return -1;
	}
	m = *mrec;
	if (!m) {
		m = (MFT_RECORD*)malloc(vol->mft_record_size);
		if (!m)
			return -1;
	}
	if (ntfs_mft_record_read(vol, mref, m)) {
		err = errno;
		goto read_failed;
	}
	if (!ntfs_is_file_record(m->magic))
		goto file_corrupt;
	if (MSEQNO(mref) && MSEQNO(mref) != le16_to_cpu(m->sequence_number))
		goto file_corrupt;
	a = (ATTR_RECORD*)((char*)m + le16_to_cpu(m->attrs_offset));
	if (p2n(a) < p2n(m) || (char*)a > (char*)m + vol->mft_record_size)
		goto file_corrupt;
	*mrec = m;
	if (attr)
		*attr = a;
	return 0;
file_corrupt:
	Dputs("ntfs_file_record_read(): file is corrupt.");
	err = EIO;
read_failed:
	if (m != *mrec)
		free(m);
	errno = err;
	return -1;
}

/**
 * ntfs_mft_record_alloc - allocate an mft record on an ntfs volume
 * @vol:	mounted ntfs volume on which to allocate the mft record
 * @start:	starting mft record at which to allocate (or -1 if none)
 *
 * Allocate an mft record in $MFT/$DATA starting to search for a free record
 * at mft record number @start or at the current allocator position if
 * @start_mref is -1, on the mounted ntfs volume @vol.
 *
 * On success return the now opened ntfs inode of the mft record.
 *
 * On error return NULL with errno set to the error code.
 */
ntfs_inode *ntfs_mft_record_alloc(ntfs_volume *vol, u64 start)
{
	if (!vol || !vol->mftbmp_na) {
		errno = EINVAL;
		return NULL;
	}

	errno = ENOTSUP;
	return NULL;
}

/**
 * ntfs_mft_record_free - free an mft record on an ntfs volume
 * @vol:	mounted ntfs volume on which to free the mft record
 * @ni:		open ntfs inode of the mft record to free
 *
 * Free the mft record of the open inode @ni on the mounted ntfs volume @vol.
 * Note that this function calls ntfs_inode_close() internally and hence you
 * cannot use the pointer @ni any more after this function returns success.
 *
 * On success return 0 and on error return -1 with errno set to the error code.
 */
int ntfs_mft_record_free(ntfs_volume *vol, ntfs_inode *ni)
{
	u64 mft_no;
	u16 seq_no;

	if (!vol || !vol->mftbmp_na || !ni) {
		errno = EINVAL;
		return -1;
	}

	/* Cache the mft reference for later. */
	mft_no = ni->mft_no;

	/* Mark the mft record as not in use. */
	ni->mrec->flags &= ~MFT_RECORD_IN_USE;

	/* Increment the sequence number, skipping zero, if it is not zero. */
	seq_no = le16_to_cpu(ni->mrec->sequence_number);
	if (seq_no == 0xffff)
		seq_no = 1;
	else if (seq_no)
		seq_no++;
	ni->mrec->sequence_number = cpu_to_le16(seq_no);

	/* Set the inode dirty and close it so it is written out. */
	ntfs_inode_mark_dirty(ni);
	if (ntfs_inode_close(ni)) {
		int eo = errno;
		// FIXME: Eeek! We need rollback! (AIA)
		fprintf(stderr, "%s(): Eeek! Failed to close the inode."
				"Leaving inconsistent metadata!\n",
				__FUNCTION__);
		errno = eo;
		return -1;
	}

	/* Clear the bit in the $MFT/$BITMAP corresponding to this record. */
	if (ntfs_bitmap_clear_run(vol->mftbmp_na, mft_no, 1)) {
		// FIXME: Eeek! We need rollback! (AIA)
		fprintf(stderr, "%s(): Eeek! Failed to clear the allocation "
				"in the mft bitmap. Leaving deleted mft record "
				"marked as in use in the mft bitmap and "
				"pretending we succeeded. Error: %s\n",
				__FUNCTION__, strerror(errno));
	}
	return 0;
}

