/*
 * compress.c - Compressed attribute handling code. Part of the Linux-NTFS
 *		project.
 *
 * Copyright (c) 2004 Anton Altaparmakov
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "attrib.h"
#include "debug.h"
#include "volume.h"
#include "types.h"
#include "layout.h"
#include "runlist.h"

/**
 * ntfs_compressed_attr_pread - read from a compressed attribute
 * @na:		ntfs attribute to read from
 * @pos:	byte position in the attribute to begin reading from
 * @count:	number of bytes to read
 * @b:		output data buffer
 *
 * NOTE:  You probably want to be using attrib.c::ntfs_attr_pread() instead.
 *
 * This function will read @count bytes starting at offset @pos from the
 * compressed ntfs attribute @na into the data buffer @b.
 *
 * On success, return the number of successfully read bytes.  If this number
 * is lower than @count this means that the read reached end of file or that
 * an error was encountered during the read so that the read is partial.
 * 0 means end of file or nothing was read (also return 0 when @count is 0).
 *
 * On error and nothing has been read, return -1 with errno set appropriately
 * to the return code of ntfs_pread(), or to EINVAL in case of invalid
 * arguments.
 */
s64 ntfs_compressed_attr_pread(ntfs_attr *na, const s64 pos, s64 count,
		void *b)
{
	s64 br, to_read, ofs, total, total2;
	u64 cb_size_mask;
	VCN start_vcn, end_vcn;
	ntfs_volume *vol;
	runlist_element *rl;
	u8 *ntfs_compression_buffer, *ntfs_uncompressed_buffer;
	u8 *cb, *cb_pos, *cb_end;
	u32 cb_size;
	unsigned int nr_cbs, cb_clusters;

	Dprintf("%s(): Entering for inode 0x%Lx, attr 0x%x, pos 0x%Lx, "
			"count 0x%Lx.\n", __FUNCTION__,
			(unsigned long long)na->ni->mft_no, na->type,
			(long long)pos, (long long)count);
	if (!na || !NAttrCompressed(na) || !na->ni || !na->ni->vol || !b ||
			pos < 0 || count < 0) {
		errno = EINVAL;
		return -1;
	}
	/*
	 * Encrypted attributes are not supported.  We return access denied,
	 * which is what Windows NT4 does, too.
	 */
	if (NAttrEncrypted(na)) {
		errno = EACCES;
		return -1;
	}
	if (!count)
		return 0;
	/* Truncate reads beyond end of attribute. */
	if (pos + count > na->data_size) {
		if (pos >= na->data_size)
			return 0;
		count = na->data_size - pos;
	}
	/* If it is a resident attribute, simply use ntfs_attr_pread(). */
	if (!NAttrNonResident(na))
		return ntfs_attr_pread(na, pos, count, b);
	total = total2 = 0;
	/* Zero out reads beyond initialized size. */
	if (pos + count > na->initialized_size) {
		if (pos >= na->initialized_size) {
			memset(b, 0, count);
			return count;
		}
		total2 = pos + count - na->initialized_size;
		count -= total2;
		memset((u8*)b + count, 0, total2);
	}
	vol = na->ni->vol;
	cb_size = na->compression_block_size;
	cb_size_mask = cb_size - 1UL;
	cb_clusters = na->compression_block_clusters;
	/* Need a temporary buffer for each loaded compression block. */
	ntfs_compression_buffer = malloc(cb_size);
	if (!ntfs_compression_buffer)
		return -1;
	/* Need a temporary buffer for each uncompressed block. */
	ntfs_uncompressed_buffer = malloc(cb_size);
	if (!ntfs_uncompressed_buffer) {
		int eo = errno;
		free(ntfs_compression_buffer);
		errno = eo;
		return -1;
	}
	/*
	 * The first vcn in the first compression block (cb) which we need to
	 * decompress.
	 */
	start_vcn = (pos & ~cb_size_mask) >> vol->cluster_size_bits;
	/*
	 * The first vcn in the cb after the last cb which we need to
	 * decompress.
	 */
	end_vcn = ((pos + count + cb_size - 1) & ~cb_size_mask) >>
			vol->cluster_size_bits;
	/* Number of compression blocks (cbs) in the wanted vcn range. */
	nr_cbs = (end_vcn - start_vcn) << vol->cluster_size_bits >>
			na->compression_block_size_bits;
do_next_cb:
	nr_cbs--;
	cb_pos = cb = ntfs_compression_buffer;
	cb_end = cb + cb_size;

// FIXME: I am here... (AIA)

	free(ntfs_compression_buffer);
	free(ntfs_uncompressed_buffer);
	errno = ENOTSUP;
	return -1;

	/* Find the runlist element containing the vcn. */
	rl = ntfs_attr_find_vcn(na, pos >> vol->cluster_size_bits);
	if (!rl) {
		/*
		 * If the vcn is not present it is an out of bounds read.
		 * However, we already truncated the read to the data_size,
		 * so getting this here is an error.
		 */
		if (errno == ENOENT)
			errno = EIO;
		return -1;
	}
	/*
	 * Gather the requested data into the linear destination buffer. Note,
	 * a partial final vcn is taken care of by the @count capping of read
	 * length.
	 */
	ofs = pos - (rl->vcn << vol->cluster_size_bits);
	for (; count; rl++, ofs = 0) {
		if (!rl->length)
			goto rl_err_out;
		if (rl->lcn < (LCN)0) {
			if (rl->lcn != (LCN)LCN_HOLE)
				goto rl_err_out;
			/* It is a hole, just zero the matching @b range. */
			to_read = min(count, (rl->length <<
					vol->cluster_size_bits) - ofs);
			memset(b, 0, to_read);
			/* Update progress counters. */
			total += to_read;
			count -= to_read;
			(u8*)b += to_read;
			continue;
		}
		/* It is a real lcn, read it into @dst. */
		to_read = min(count, (rl->length << vol->cluster_size_bits) -
				ofs);
retry:
		Dprintf("%s(): Reading 0x%Lx bytes from vcn 0x%Lx, lcn 0x%Lx, "
				"ofs 0x%Lx.\n", __FUNCTION__, to_read,
				rl->vcn, rl->lcn, ofs);
		br = ntfs_pread(vol->dev, (rl->lcn << vol->cluster_size_bits) +
				ofs, to_read, b);
		/* If everything ok, update progress counters and continue. */
		if (br > 0) {
			total += br;
			count -= br;
			(u8*)b += br;
			continue;
		}
		/* If the syscall was interrupted, try again. */
		if (br == (s64)-1 && errno == EINTR)
			goto retry;
		if (total)
			return total;
		if (!br)
			errno = EIO;
		return -1;
	}
	/* Finally, return the number of bytes read. */
	return total + total2;
rl_err_out:
	if (total)
		return total;
	errno = EIO;
	return -1;
}

