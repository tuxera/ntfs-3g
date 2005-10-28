/**
 * bitmap.c - Bitmap handling code. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002-2004 Anton Altaparmakov
 * Copyright (c) 2004-2005 Richard Russon
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
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

#include "types.h"
#include "attrib.h"
#include "bitmap.h"
#include "debug.h"
#include "logging.h"

/**
 * ntfs_bitmap_set_bits_in_run - set a run of bits in a bitmap to a value
 * @na:		attribute containing the bitmap
 * @start_bit:	first bit to set
 * @count:	number of bits to set
 * @value:	value to set the bits to (i.e. 0 or 1)
 *
 * Set @count bits starting at bit @start_bit in the bitmap described by the
 * attribute @na to @value, where @value is either 0 or 1.
 *
 * On success return 0 and on error return -1 with errno set to the error code.
 */
static __inline__ int ntfs_bitmap_set_bits_in_run(ntfs_attr *na, s64 start_bit,
		s64 count, int value)
{
	s64 bufsize, br;
	u8 *buf, *lastbyte_buf;
	int bit, firstbyte, lastbyte, lastbyte_pos, tmp, err;

	if (!na || start_bit < 0 || count < 0) {
		errno = EINVAL;
		return -1;
	}

	bit = start_bit & 7;
	if (bit)
		firstbyte = 1;
	else
		firstbyte = 0;

	/* Calculate the required buffer size in bytes, capping it at 8kiB. */
	bufsize = ((count - (bit ? 8 - bit : 0) + 7) >> 3) + firstbyte;
	if (bufsize > 8192)
		bufsize = 8192;

	/* Allocate memory. */
	buf = (u8*)malloc(bufsize);
	if (!buf)
		return -1;
	/* Depending on @value, zero or set all bits in the allocated buffer. */
	memset(buf, value ? 0xff : 0, bufsize);

	/* If there is a first partial byte... */
	if (bit) {
		/* read it in... */
		br = ntfs_attr_pread(na, start_bit >> 3, 1, buf);
		if (br != 1) {
			free(buf);
			errno = EIO;
			return -1;
		}
		/* and set or clear the appropriate bits in it. */
		while ((bit & 7) && count--) {
			if (value)
				*buf |= 1 << bit++;
			else
				*buf &= ~(1 << bit++);
		}
		/* Update @start_bit to the new position. */
		start_bit = (start_bit + 7) & ~7;
	}

	/* Loop until @count reaches zero. */
	lastbyte = 0;
	lastbyte_buf = NULL;
	bit = count & 7;
	do {
		/* If there is a last partial byte... */
		if (count > 0 && bit) {
			lastbyte_pos = ((count + 7) >> 3) + firstbyte;
			if (!lastbyte_pos) {
				// FIXME: Eeek! BUG!
				ntfs_log_trace("Eeek! lastbyte is zero. Leaving "
						"inconsistent metadata.\n");
				err = EIO;
				goto free_err_out;
			}
			/* and it is in the currently loaded bitmap window... */
			if (lastbyte_pos <= bufsize) {
				lastbyte_buf = buf + lastbyte_pos - 1;

				/* read the byte in... */
				br = ntfs_attr_pread(na, (start_bit + count) >>
						3, 1, lastbyte_buf);
				if (br != 1) {
					// FIXME: Eeek! We need rollback! (AIA)
					ntfs_log_trace("Eeek! Read of last byte "
							"failed. Leaving "
							"inconsistent metadata.\n");
					err = EIO;
					goto free_err_out;
				}
				/* and set/clear the appropriate bits in it. */
				while (bit && count--) {
					if (value)
						*lastbyte_buf |= 1 << --bit;
					else
						*lastbyte_buf &= ~(1 << --bit);
				}
				/* We don't want to come back here... */
				bit = 0;
				/* We have a last byte that we have handled. */
				lastbyte = 1;
			}
		}

		/* Write the prepared buffer to disk. */
		tmp = (start_bit >> 3) - firstbyte;
		br = ntfs_attr_pwrite(na, tmp, bufsize, buf);
		if (br != bufsize) {
			// FIXME: Eeek! We need rollback! (AIA)
			ntfs_log_trace("Eeek! Failed to write buffer to bitmap. "
					"Leaving inconsistent metadata.\n");
			err = EIO;
			goto free_err_out;
		}

		/* Update counters. */
		tmp = (bufsize - firstbyte - lastbyte) << 3;
		firstbyte = 0;
		start_bit += tmp;
		count -= tmp;
		if (bufsize > (tmp = (count + 7) >> 3))
			bufsize = tmp;

		if (lastbyte && count != 0) {
			// FIXME: Eeek! BUG!
			ntfs_log_trace("Eeek! Last buffer but count is not zero (= "
					"%lli). Leaving inconsistent metadata.\n",
					(long long)count);
			err = EIO;
			goto free_err_out;
		}
	} while (count > 0);

	/* Done! */
	free(buf);
	return 0;

free_err_out:
	free(buf);
	errno = err;
	return -1;
}

/**
 * ntfs_bitmap_set_run - set a run of bits in a bitmap
 * @na:		attribute containing the bitmap
 * @start_bit:	first bit to set
 * @count:	number of bits to set
 *
 * Set @count bits starting at bit @start_bit in the bitmap described by the
 * attribute @na.
 *
 * On success return 0 and on error return -1 with errno set to the error code.
 */
int ntfs_bitmap_set_run(ntfs_attr *na, s64 start_bit, s64 count)
{
	return ntfs_bitmap_set_bits_in_run(na, start_bit, count, 1);
}

/**
 * ntfs_bitmap_clear_run - clear a run of bits in a bitmap
 * @na:		attribute containing the bitmap
 * @start_bit:	first bit to clear
 * @count:	number of bits to clear
 *
 * Clear @count bits starting at bit @start_bit in the bitmap described by the
 * attribute @na.
 *
 * On success return 0 and on error return -1 with errno set to the error code.
 */
int ntfs_bitmap_clear_run(ntfs_attr *na, s64 start_bit, s64 count)
{
	return ntfs_bitmap_set_bits_in_run(na, start_bit, count, 0);
}


#ifdef NTFS_RICH

#include "layout.h"
#include "volume.h"
#include "rich.h"

/**
 * ntfs_bmp_rollback
 */
int ntfs_bmp_rollback(struct ntfs_bmp *bmp)
{
	int i;

	if ((!bmp) || (bmp->count == 0))
		return 0;

	ntfs_log_trace ("bmp %p, records %d, attr %lld/%02X\n", bmp, bmp->count, MREF(bmp->attr->ni->mft_no), bmp->attr->type);

	for (i = 0; i < bmp->count; i++)
		free(bmp->data[i]);

	free(bmp->data);
	free(bmp->data_vcn);
	bmp->data = NULL;
	bmp->data_vcn = NULL;
	bmp->count = 0;

	return 0;
}

/**
 * ntfs_bmp_commit
 */
int ntfs_bmp_commit(struct ntfs_bmp *bmp)
{
	int i;
	u32 cs;
	u32 ws; // write size

	if (!bmp)
		return 0;
	if (bmp->count == 0)
		return 0;

	ntfs_log_trace ("bmp %p, records %d, attr %lld/%02X\n", bmp, bmp->count, MREF(bmp->attr->ni->mft_no), bmp->attr->type);
#if 0
	ntfs_log_debug("attr = 0x%02X\n", bmp->attr->type);
	ntfs_log_debug("resident = %d\n", !NAttrNonResident(bmp->attr));
	ntfs_log_debug("\ta size = %lld\n", bmp->attr->allocated_size);
	ntfs_log_debug("\td size = %lld\n", bmp->attr->data_size);
	ntfs_log_debug("\ti size = %lld\n", bmp->attr->initialized_size);
#endif

	ntfs_log_debug("commit bmp inode %lld, 0x%02X (%sresident)\n", bmp->attr->ni->mft_no, bmp->attr->type, NAttrNonResident(bmp->attr) ? "non-" : "");

	if (NAttrNonResident(bmp->attr)) {
		cs = bmp->vol->cluster_size;

		// non-resident
		for (i = 0; i < bmp->count; i++) {
			if (((bmp->data_vcn[i]+1) * cs) < bmp->attr->data_size)
				ws = cs;
			else
				ws = bmp->attr->data_size & (cs - 1);
			//ntfs_log_debug("writing %d bytes\n", ws);
			ntfs_attr_pwrite(bmp->attr, bmp->data_vcn[i] * cs, ws, bmp->data[i]); // XXX retval
			ntfs_log_warning("\tntfs_attr_pwrite(vcn %lld)\n", bmp->data_vcn[i]);
		}
	} else {
		// resident
		ntfs_attr_pwrite(bmp->attr, bmp->data_vcn[0], bmp->attr->data_size, bmp->data[0]); // XXX retval
		ntfs_log_warning("\tntfs_attr_pwrite resident (%lld)\n", bmp->attr->data_size);
	}

	ntfs_bmp_rollback(bmp);

	return 0;
}

/**
 * ntfs_bmp_free
 */
void ntfs_bmp_free(struct ntfs_bmp *bmp)
{
	if (!bmp)
		return;

	ntfs_log_trace ("bmp %p, records %d, attr %lld/%02X\n", bmp, bmp->count, MREF(bmp->attr->ni->mft_no), bmp->attr->type);

	ntfs_bmp_rollback(bmp);
	ntfs_attr_close(bmp->attr);

	free(bmp);
}

/**
 * ntfs_bmp_create
 */
struct ntfs_bmp * ntfs_bmp_create(ntfs_inode *inode, ATTR_TYPES type, ntfschar *name, int name_len)
{
	struct ntfs_bmp *bmp;
	ntfs_attr *attr;

	if (!inode)
		return NULL;

	ntfs_log_trace ("\n");
	attr = ntfs_attr_open(inode, type, name, name_len);
	if (!attr)
		return NULL;

	bmp = calloc(1, sizeof(*bmp));
	if (!bmp) {
		ntfs_attr_close(attr);
		return NULL;
	}

	ntfs_log_critical("bmp = %p, attr = %p, inode = %p, attr->ni->mft_no = %lld\n", bmp, attr, inode, MREF(attr->ni->mft_no));
	bmp->vol       = inode->vol;
	bmp->attr      = attr;
	bmp->data      = NULL;
	bmp->data_vcn  = NULL;
	bmp->count     = 0;

	return bmp;
}

/**
 * ntfs_bmp_add_data
 */
int ntfs_bmp_add_data(struct ntfs_bmp *bmp, VCN vcn, u8 *data)
{
	int i = 0;
	int old;
	int new;

	if (!bmp || !data)
		return -1;

	ntfs_log_trace ("\n");
	old = ROUND_UP(bmp->count, 16);
	bmp->count++;
	new = ROUND_UP(bmp->count, 16);

	if (old != new) {
		bmp->data     = realloc(bmp->data,      new * sizeof(*bmp->data));
		bmp->data_vcn = realloc(bmp->data_vcn , new * sizeof(*bmp->data_vcn));
	}

	for (i = 0; i < bmp->count-1; i++)
		if (bmp->data_vcn[i] > vcn)
			break;

	if ((bmp->count-i) > 0) {
		memmove(&bmp->data[i+1],     &bmp->data[i],     (bmp->count-i) * sizeof(*bmp->data));
		memmove(&bmp->data_vcn[i+1], &bmp->data_vcn[i], (bmp->count-i) * sizeof(*bmp->data_vcn));
	}

	bmp->data[i]     = data;
	bmp->data_vcn[i] = vcn;

	return bmp->count;
}

/**
 * ntfs_bmp_get_data
 */
u8 * ntfs_bmp_get_data(struct ntfs_bmp *bmp, VCN vcn)
{
	u8 *buffer;
	int i;
	int cs;
	int cb;

	if (!bmp)
		return NULL;

	ntfs_log_trace ("\n");
	cs = bmp->vol->cluster_size;
	cb = bmp->vol->cluster_size_bits;

	// XXX range check against vol,attr
	// never compressed, so data = init

	vcn >>= (cb + 3);	// convert to bitmap clusters

	for (i = 0; i < bmp->count; i++) {
		if (vcn == bmp->data_vcn[i]) {
			//ntfs_log_debug("reusing bitmap cluster %lld\n", vcn);
			return bmp->data[i];
		}
	}

	buffer = calloc(1, cs);	// XXX could be smaller if attr size < cluster size
	if (!buffer)
		return NULL;

	//ntfs_log_debug("loading from bitmap cluster %lld\n", vcn);
	//ntfs_log_debug("loading from bitmap byte    %lld\n", vcn<<cb);
	if (ntfs_attr_pread(bmp->attr, vcn<<cb, cs, buffer) < 0) {
		free(buffer);
		return NULL;
	}

	ntfs_bmp_add_data(bmp, vcn, buffer);	// XXX retval
	return buffer;
}

/**
 * ntfs_bmp_set_range
 */
int ntfs_bmp_set_range(struct ntfs_bmp *bmp, VCN vcn, s64 length, int value)
{
	// shouldn't all the vcns be lcns?
	s64 i;
	u8 *buffer;
	int csib;			// cluster size in bits

	int block_start, block_finish;	// rename to c[sf]  (rename to clust_)
	int vcn_start, vcn_finish;	// rename to v[sf]
	int byte_start, byte_finish;	// rename to b[sf]
	u8 mask_start, mask_finish;	// rename to m[sf]

	s64 a,b;

	if (!bmp)
		return -1;

	ntfs_log_trace ("vcn %lld, length %lld, value %d\n", vcn, length, value);
	if (value)
		value = 0xFF;

	csib = bmp->vol->cluster_size << 3;

	vcn_start  = vcn;
	vcn_finish = vcn + length - 1;

	//ntfs_log_debug("vcn_start = %d, vcn_finish = %d\n", vcn_start, vcn_finish);
	a = ROUND_DOWN(vcn_start,  csib);
	b = ROUND_DOWN(vcn_finish, csib) + 1;

	//ntfs_log_debug("a = %lld, b = %lld\n", a, b);

	for (i = a; i < b; i += csib) {
		//ntfs_log_debug("ntfs_bmp_get_data %lld\n", i);
		buffer = ntfs_bmp_get_data(bmp, i);
		if (!buffer)
			return -1;

		block_start  = i;
		block_finish = block_start + csib - 1;

		mask_start  = (0xFF << (vcn_start & 7));
		mask_finish = (0xFF >> (7 - (vcn_finish & 7)));

		if ((vcn_start >= block_start) && (vcn_start <= block_finish)) {
			byte_start = (vcn_start - block_start) >> 3;
		} else {
			byte_start = 0;
			mask_start = 0xFF;
		}

		if ((vcn_finish >= block_start) && (vcn_finish <= block_finish)) {
			byte_finish = (vcn_finish - block_start) >> 3;
		} else {
			byte_finish = bmp->vol->cluster_size - 1;
			mask_finish = 0xFF;
		}

		if ((byte_finish - byte_start) > 1) {
			memset(buffer+byte_start+1, value, byte_finish-byte_start-1);
		} else if (byte_finish == byte_start) {
			mask_start &= mask_finish;
			mask_finish = 0x00;
		}

		if (value) {
			buffer[byte_start]  |= mask_start;
			buffer[byte_finish] |= mask_finish;
		} else {
			buffer[byte_start]  &= (~mask_start);
			buffer[byte_finish] &= (~mask_finish);
		}
	}

#if 1
	ntfs_log_debug("Modified: inode %lld, ", bmp->attr->ni->mft_no);
	switch (bmp->attr->type) {
		case AT_BITMAP: ntfs_log_debug("$BITMAP");	break;
		case AT_DATA:   ntfs_log_debug("$DATA");	break;
		default:				break;
	}
	ntfs_log_debug(" vcn %lld-%lld\n", vcn>>12, (vcn+length-1)>>12);
#endif
	return 1;
}

/**
 * ntfs_bmp_find_last_set
 */
s64 ntfs_bmp_find_last_set(struct ntfs_bmp *bmp)
{
	s64 clust_count;
	s64 byte_count;
	s64 clust;
	int byte;
	int bit;
	int note;
	u8 *buffer;

	if (!bmp)
		return -2;

	ntfs_log_trace ("\n");
	// find byte size of bmp
	// find cluster size of bmp

	byte_count = bmp->attr->data_size;
	clust_count = ROUND_UP(byte_count, bmp->vol->cluster_size) >> bmp->vol->cluster_size_bits;

	//ntfs_log_debug("bitmap = %lld bytes\n", byte_count);
	//ntfs_log_debug("bitmap = %lld buffers\n", clust_count);

	// for each cluster backwards
	for (clust = clust_count-1; clust >= 0; clust--) {
		//ntfs_log_debug("cluster %lld\n", clust);
		//ntfs_log_debug("get vcn %lld\n", clust << (bmp->vol->cluster_size_bits + 3));
		buffer = ntfs_bmp_get_data(bmp, clust << (bmp->vol->cluster_size_bits + 3));
		//utils_dump_mem(buffer, 0, 8, DM_NO_ASCII);
		if (!buffer)
			return -2;
		if ((clust == (clust_count-1) && ((byte_count % bmp->vol->cluster_size) != 0))) {
			byte = byte_count % bmp->vol->cluster_size;
		} else {
			byte = bmp->vol->cluster_size;
		}
		//ntfs_log_debug("start byte = %d\n", byte);
		// for each byte backward
		for (byte--; byte >= 0; byte--) {
			//ntfs_log_debug("\tbyte %d (%d)\n", byte, buffer[byte]);
			// for each bit shift up
			note = -1;
			for (bit = 7; bit >= 0; bit--) {
				//ntfs_log_debug("\t\tbit %d (%d)\n", (1<<bit), buffer[byte] & (1<<bit));
				if (buffer[byte] & (1<<bit)) {
					// if set, keep note
					note = bit;
					break;
				}
			}
			if (note >= 0) {
				// if note, return value
				//ntfs_log_debug("match %lld (c=%lld,b=%d,n=%d)\n", (((clust << bmp->vol->cluster_size_bits) + byte) << 3) + note, clust, byte, note);
				return ((((clust << bmp->vol->cluster_size_bits) + byte) << 3) + note);
			}
		}
	}

	return -1;
}

/**
 * ntfs_bmp_find_space
 */
int ntfs_bmp_find_space(struct ntfs_bmp *bmp, LCN start, long size)
{
	if (!bmp)
		return 0;

	ntfs_log_trace ("\n");
	start = 0;
	size = 0;

	/*
	bmp find space - uncached bmp's
		$Bitmap/$DATA	free space on volume
		dir/$BITMAP	free index record
		$MFT/$BITMAP	free record in mft
	*/
	return 0;
}


#endif /* NTFS_RICH */

