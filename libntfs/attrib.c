/*
 * attrib.c - Attribute handling code. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2000-2002 Anton Altaparmakov
 * Copyright (c) 2002 Richard Russon
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
#include "disk_io.h"
#include "mft.h"
#include "debug.h"
#include "mst.h"
#include "volume.h"
#include "types.h"
#include "layout.h"
#include "inode.h"
#include "runlist.h"

uchar_t AT_UNNAMED[] = { const_cpu_to_le16('\0') };

/**
 * ntfs_get_attribute_value_length
 */
s64 ntfs_get_attribute_value_length(const ATTR_RECORD *a)
{
	if (!a) {
		errno = EINVAL;
		return 0;
	}
	errno = 0;
	if (a->non_resident)
		return sle64_to_cpu(a->data_size);
	else
		return (s64)le32_to_cpu(a->value_length);
	errno = EINVAL;
	return 0;
}

/**
 * ntfs_get_attribute_value
 */
s64 ntfs_get_attribute_value(const ntfs_volume *vol, const MFT_RECORD *m,
			  const ATTR_RECORD *a, u8 *b)
{
	/* Sanity checks. */
	if (!vol || !m || !a || !b) {
		errno = EINVAL;
		return 0;
	}
	/* Complex attribute? */
	if (a->flags) {
		puts("Enountered non-zero attribute flags. Cannot handle this "
		     "yet.");
		errno = ENOTSUP;
		return 0;
	}
	if (!a->non_resident) {		/* Attribute is resident. */
		/* Sanity check. */
		if (le32_to_cpu(a->value_length) +
		    le16_to_cpu(a->value_offset) > le32_to_cpu(a->length)) {
			return 0;
		}
		memcpy(b, (char*)a + le16_to_cpu(a->value_offset),
					le32_to_cpu(a->value_length));
		errno = 0;
		return (s64)le32_to_cpu(a->value_length);
	} else {			/* Attribute is not resident. */
		runlist *rl;
		s64 total, r;
		int i;

		/* If no data, return 0. */
		if (!(a->data_size)) {
			errno = 0;
			return 0;
		}
		/*
		 * FIXME: What about attribute lists?!? (AIA)
		 */
		/* Decompress the mapping pairs array into a runlist. */
		rl = ntfs_mapping_pairs_decompress(vol, a, NULL);
		if (!rl) {
			errno = EINVAL;
			return 0;
		}
		/*
		 * FIXED: We were overflowing here in a nasty fashion when we
		 * reach the last cluster in the runlist as the buffer will
		 * only be big enough to hold data_size bytes while we are
		 * reading in allocated_size bytes which is usually larger
		 * than data_size, since the actual data is unlikely to have a
		 * size equal to a multiple of the cluster size!
		 */
		/* Now load all clusters in the runlist into b. */
		for (i = 0, total = 0; rl[i].length; i++) {
			if (!rl[i+1].length) {
				unsigned char *intbuf = NULL;
				/*
				 * We have reached the last run so we were
				 * going to overflow when executing the
				 * ntfs_pread() which is BAAAAAAAD!
				 * Temporary fix:
				 *	Allocate a new buffer with size:
				 *	rl[i].length << vol->cluster_size_bits,
				 *	do the read into our buffer, then
				 *	memcpy the correct amount of data into
				 *	the caller supplied buffer, free our
				 *	buffer, and continue.
				 */
				intbuf = malloc(rl[i].length <<
							vol->cluster_size_bits);
				if (!intbuf) {
					int eo = errno;
					perror("Couldn't allocate memory for "
							"internal buffer.\n");
					free(rl);
					errno = eo;
					return 0;
				}
				/*
				 * FIXME: If compressed file: Only read if
				 * lcn != -1. Otherwise, we are dealing with a
				 * sparse run and we just memset the user buffer
				 * to 0 for the length of the run, which should
				 * be 16 (= compression unit size).
				 * FIXME: Really only when file is compressed,
				 * or can we have sparse runs in uncompressed
				 * files as well?
				 */
				r = ntfs_pread(vol->fd, rl[i].lcn <<
						vol->cluster_size_bits,
						rl[i].length <<
						vol->cluster_size_bits, intbuf);
				if (r != rl[i].length <<
						vol->cluster_size_bits) {
#define ESTR "Error reading attribute value"
					if (r == -1) {
						int eo = errno;
						perror(ESTR);
						errno = eo;
					} else if (r < rl[i].length <<
							vol->cluster_size_bits
							) {
						fprintf(stderr, ESTR ": Ran "
							"out of input data.\n");
						errno = EIO;
					} else {
						fprintf(stderr, ESTR ": "
							   "unknown error\n");
						errno = EIO;
					}
#undef ESTR
					free(rl);
					return 0;
				}
				memcpy(b + total, intbuf,
				       sle64_to_cpu(a->data_size) - total);
				free(intbuf);
				total = sle64_to_cpu(a->data_size);
			} else {
				/*
				 * FIXME: If compressed file: Only read if
				 * lcn != -1. Otherwise, we are dealing with a
				 * sparse run and we just memset the user buffer
				 * to 0 for the length of the run, which should
				 * be 16 (= compression unit size).
				 */
				r = ntfs_pread(vol->fd, rl[i].lcn <<
						vol->cluster_size_bits,
						rl[i].length <<
						vol->cluster_size_bits,
						b + total);
				if (r != rl[i].length <<
						vol->cluster_size_bits) {
#define ESTR "Error reading attribute value"
					if (r == -1) {
						int eo = errno;
						perror(ESTR);
						errno = eo;
					} else if (r < rl[i].length <<
							vol->cluster_size_bits
							) {
						fprintf(stderr, ESTR ": Ran "
							"out of input data.\n");
						errno = EIO;
					} else {
						fprintf(stderr, ESTR ": "
							   "unknown error\n");
						errno = EIO;
					}
#undef ESTR
					return 0;
				}
				total += r;
			}
		}
		free(rl);
		return total;
	}
	errno = EINVAL;
	return 0;
}

/* Already cleaned up code below, but still look for FIXME:... */

/**
 * Internal:
 *
 * __ntfs_attr_init - primary initialization of an ntfs attribute structure
 * @na:		ntfs attribute to initialize
 * @ni:		ntfs inode with which to initialize the ntfs attribute
 * @type:	attribute type
 * @name:	attribute name in little endian Unicode or NULL
 * @name_len:	length of attribute @name in Unicode characters (if @name given)
 *
 * Initialize the ntfs attribute @na with @ni, @type, @name, and @name_len.
 */
static __inline__ void __ntfs_attr_init(ntfs_attr *na, ntfs_inode *ni,
		const ATTR_TYPES type, uchar_t *name, const u32 name_len)
{
	na->rl = NULL;
	na->ni = ni;
	na->type = type;
	if (name) {
		na->name     = name;
		na->name_len = name_len;
	} else {
		na->name     = AT_UNNAMED;
		na->name_len = 0;
	}
}

/**
 * ntfs_attr_init - initialize an ntfs_attr with data sizes and status
 * @na:
 * @non_resident:
 * @compressed:
 * @ecnrypted:
 * @sparse:
 * @allocated_size:
 * @data_size:
 * @initialized_size:
 * @compressed_size:
 * @compression_unit:
 *
 * Final initialization for an ntfs attribute.
 */
void ntfs_attr_init(ntfs_attr *na, const BOOL non_resident,
		const BOOL compressed, const BOOL encrypted, const BOOL sparse,
		const s64 allocated_size, const s64 data_size,
		const s64 initialized_size, const s64 compressed_size,
		const u8 compression_unit)
{
	if (!NAttrInitialized(na)) {
		if (non_resident)
			NAttrSetNonResident(na);
		if (compressed)
			NAttrSetCompressed(na);
		if (encrypted)
			NAttrSetEncrypted(na);
		if (sparse)
			NAttrSetSparse(na);
		na->allocated_size = allocated_size;
		na->data_size = data_size;
		na->initialized_size = initialized_size;
		if (compressed || sparse) {
			ntfs_volume *vol = na->ni->vol;

			na->compressed_size = compressed_size;
			na->compression_block_clusters = 1 << compression_unit;
			na->compression_block_size = 1 << (compression_unit +
					vol->cluster_size_bits);
			na->compression_block_size_bits = ffs(
					na->compression_block_size) - 1;
		}
		NAttrSetInitialized(na);
	}
}

/**
 * ntfs_attr_open - open an ntfs attribute for access
 * @ni:		open ntfs inode in which the ntfs attribute resides
 * @type:	attribute type
 * @name:	attribute name in little endian Unicode or NULL
 * @name_len:	length of attribute @name in Unicode characters (if @name given)
 *
 * Allocate a new ntfs attribute structure, initialize it with @ni, @type,
 * @name, and @name_len, then return it. Return NULL on error with
 * errno set to the error code.
 *
 * If looking for an unnamed attribute set @name to NULL. @name_len is not used
 * at all in that case.
 */
ntfs_attr *ntfs_attr_open(ntfs_inode *ni, const ATTR_TYPES type,
		uchar_t *name, const u32 name_len)
{
	ntfs_attr_search_ctx *ctx;
	ntfs_attr *na;
	ATTR_RECORD *a;
	int err;

	Dprintf("%s(): Entering for inode 0x%Lx, attr 0x%x.\n", __FUNCTION__,
			(unsigned long long)ni->mft_no, type);
	if (!ni || !ni->vol || !ni->mrec) {
		errno = EINVAL;
		return NULL;
	}
	na = calloc(sizeof(ntfs_attr), 1);
	if (!na)
		return NULL;
	__ntfs_attr_init(na, ni, type, name, name_len);

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		err = errno;
		goto err_out;
	}

	if (ntfs_attr_lookup(type, name, name_len, 0, 0, NULL, 0, ctx)) {
		err = errno;
		goto put_err_out;
	}
	a = ctx->attr;
	if (a->non_resident) {
		BOOL cs = a->flags & (ATTR_IS_COMPRESSED | ATTR_IS_SPARSE);
		ntfs_attr_init(na, TRUE, a->flags & ATTR_IS_COMPRESSED,
				a->flags & ATTR_IS_ENCRYPTED,
				a->flags & ATTR_IS_SPARSE,
				sle64_to_cpu(a->allocated_size),
				sle64_to_cpu(a->data_size),
				sle64_to_cpu(a->initialized_size),
				cs ? sle64_to_cpu(a->compressed_size) : 0,
				cs ? a->compression_unit : 0);
	} else {
		s64 l = le32_to_cpu(a->value_length);
		if (a->flags & (ATTR_COMPRESSION_MASK | ATTR_IS_ENCRYPTED |
				ATTR_IS_SPARSE)) {
			err = EIO;
			goto put_err_out;
		}
		ntfs_attr_init(na, FALSE, FALSE, FALSE, FALSE, l, l, l, 0, 0);
	}
	ntfs_attr_put_search_ctx(ctx);
	return na;
put_err_out:
	ntfs_attr_put_search_ctx(ctx);
err_out:
	errno = err;
	return NULL;
}

/**
 * ntfs_attr_close - free an ntfs attribute structure
 * @na:		ntfs attribute structure to free
 *
 * Release all memory associated with the ntfs attribute @na and then release
 * @na itself.
 */
void ntfs_attr_close(ntfs_attr *na)
{
	if (NAttrNonResident(na) && na->rl)
		free(na->rl);
	if (na->name != AT_UNNAMED)
		free(na->name);
	free(na);
	return;
}

/**
 * ntfs_attr_map_runlist - map (a part of) a runlist of an ntfs attribute
 * @na:		ntfs attribute for which to map (part of) a runlist
 * @vcn:	map runlist part containing this vcn
 *
 * Map the part of a runlist containing the @vcn of an the ntfs attribute @na.
 *
 * Return 0 on success and -1 on error with errno set to the error code.
 */
int ntfs_attr_map_runlist(ntfs_attr *na, VCN vcn)
{
	ntfs_attr_search_ctx *ctx;
	int err;

	Dprintf("%s(): Entering for inode 0x%Lx, attr 0x%x, vcn 0x%Lx.\n",
			__FUNCTION__, (unsigned long long)na->ni->mft_no,
			na->type, (long long)vcn);

	ctx = ntfs_attr_get_search_ctx(na->ni, NULL);
	if (!ctx)
		return -1;

	/* Find the attribute in the mft record. */
	if (!ntfs_attr_lookup(na->type, na->name, na->name_len, CASE_SENSITIVE,
			vcn, NULL, 0, ctx)) {
		runlist_element *rl;

		/* Decode the runlist. */
		rl = ntfs_mapping_pairs_decompress(na->ni->vol, ctx->attr,
				na->rl);
		if (rl) {
			na->rl = rl;

			ntfs_attr_put_search_ctx(ctx);
			return 0;
		}
	}
	err = errno;
	ntfs_attr_put_search_ctx(ctx);
	errno = err;
	return -1;
}

/**
 * ntfs_attr_vcn_to_lcn - convert a vcn into a lcn given an ntfs attribute
 * @na:		ntfs attribute whose runlist to use for conversion
 * @vcn:	vcn to convert
 *
 * Convert the virtual cluster number @vcn of an attribute into a logical
 * cluster number (lcn) of a device using the runlist @na->rl to map vcns to
 * their corresponding lcns.
 *
 * If the @vcn is not mapped yet, attempt to map the attribute extent
 * containing the @vcn and retry the vcn to lcn conversion.
 *
 * Since lcns must be >= 0, we use negative return values with special meaning:
 *
 * Return value		Meaning / Description
 * ==========================================
 *  -1 = LCN_HOLE	Hole / not allocated on disk.
 *  -3 = LCN_ENOENT	There is no such vcn in the attribute.
 *  -4 = LCN_EINVAL	Input parameter error.
 *  -5 = LCN_EIO	Corrupt fs, disk i/o error, or not enough memory.
 */
LCN ntfs_attr_vcn_to_lcn(ntfs_attr *na, const VCN vcn)
{
	LCN lcn;
	BOOL is_retry = FALSE;

	if (!na || !NAttrNonResident(na) || vcn < 0)
		return (LCN)LCN_EINVAL;
retry:
	/* Convert vcn to lcn. If that fails map the runlist and retry once. */
	lcn = ntfs_rl_vcn_to_lcn(na->rl, vcn);
	if (lcn >= 0)
		return lcn;
	if (!is_retry && !ntfs_attr_map_runlist(na, vcn)) {
		is_retry = TRUE;
		goto retry;
	}
	/*
	 * If the attempt to map the runlist failed, or we are getting
	 * LCN_RL_NOT_MAPPED despite having mapped the attribute extent
	 * successfully, something is really badly wrong...
	 */
	if (!is_retry || lcn == (LCN)LCN_RL_NOT_MAPPED)
		return (LCN)LCN_EIO;
	/* lcn contains the appropriate error code. */
	return lcn;
}

/**
 * ntfs_attr_find_vcn - find a vcn in the runlist of an ntfs attribute
 * @na:		ntfs attribute whose runlist to search
 * @vcn:	vcn to find
 *
 * Find the virtual cluster number @vcn in the runlist of the ntfs attribute
 * @na and return the the address of the runlist element containing the @vcn.
 *
 * Note you need to distinguish between the lcn of the returned runlist
 * element being >= 0 and LCN_HOLE. In the later case you have to return zeroes
 * on read and allocate clusters on write. You need to update the runlist, the
 * attribute itself as well as write the modified mft record to disk.
 *
 * If there is an error return NULL with errno set to the error code. The
 * following error codes are defined:
 *	EINVAL		Input parameter error.
 *	ENOENT		There is no such vcn in the runlist.
 *	ENOMEM		Not enough memory.
 *	EIO		I/O error or corrupt metadata.
 */
runlist_element *ntfs_attr_find_vcn(ntfs_attr *na, const VCN vcn)
{
	runlist_element *rl;
	BOOL is_retry = FALSE;

	if (!na || !NAttrNonResident(na) || vcn < 0) {
		errno = EINVAL;
		return NULL;
	}
retry:
	rl = na->rl;
	if (!rl)
		goto map_rl;
	if (vcn < rl[0].vcn)
		goto map_rl;
	while (rl->length) {
		if (vcn < rl[1].vcn) {
			if (rl->lcn >= (LCN)LCN_HOLE)
				return rl;
			break;
		}
		rl++;
	}
	switch (rl->lcn) {
	case (LCN)LCN_RL_NOT_MAPPED:
		goto map_rl;
	case (LCN)LCN_ENOENT:
		errno = ENOENT;
		break;
	case (LCN)LCN_EINVAL:
		errno = EINVAL;
		break;
	default:
		errno = EIO;
		break;
	}
	return NULL;
map_rl:
	/* The @vcn is in an unmapped region, map the runlist and retry. */
	if (!is_retry && !ntfs_attr_map_runlist(na, vcn)) {
		is_retry = TRUE;
		goto retry;
	}
	/*
	 * If we already retried or the mapping attempt failed something has
	 * gone badly wrong. EINVAL and ENOENT coming from a failed mapping
	 * attempt are equivalent to errors for us as they should not happen
	 * in our code paths.
	 */
	if (is_retry || errno == EINVAL || errno == ENOENT)
		errno = EIO;
	return NULL;
}

/**
 * ntfs_attr_pread - read from an attribute specified by an ntfs_attr structure
 * @na:		ntfs attribute to read from
 * @pos:	byte position in the attribute to begin reading from
 * @count:	number of bytes to read
 * @b:		output data buffer
 *
 * This function will read @count bytes starting at offset @pos from the ntfs
 * attribute @na into the data buffer @b.
 *
 * On success, return the number of successfully read bytes. If this number is
 * lower than @count this means that the read reached end of file or thet an
 * error was encountered during the read so that the read is partial. 0 means
 * end of file or nothing was read (also return 0 when @count is 0).
 *
 * On error and nothing has been read, return -1 with errno set appropriately
 * to the return code of ntfs_pread(), or to EINVAL in case of invalid
 * arguments.
 */
s64 ntfs_attr_pread(ntfs_attr *na, const s64 pos, s64 count, void *b)
{
	s64 br, to_read, ofs, total, total2;
	ntfs_volume *vol;
	runlist_element *rl;
	int f;

	Dprintf("%s(): Entering for inode 0x%Lx, attr 0x%x, pos 0x%Lx, "
			"count 0x%Lx.\n", __FUNCTION__,
			(unsigned long long)na->ni->mft_no, na->type,
			(long long)pos, (long long)count);
	if (!na || !na->ni || !na->ni->vol || !b || pos < 0 || count < 0) {
		errno = EINVAL;
		return -1;
	}
	vol = na->ni->vol;
	f = vol->fd;
	if (!f) {
		errno = EBADF;
		return -1;
	}
	/*
	 * Encrypted attributes are not supported. We return access denied,
	 * which is what Windows NT4 does, too.
	 */
	if (NAttrEncrypted(na)) {
		errno = EACCES;
		return -1;
	}
	/* If this is a compressed attribute it needs special treatment. */
	if (NAttrCompressed(na)) {
		// TODO: Implement reading compressed attributes! (AIA)
		// return ntfs_attr_pread_compressed(ntfs_attr *na,
		//		const s64 pos, s64 count, void *b);
		errno = ENOTSUP;
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
	/* If it is a resident attribute, get the value from the mft record. */
	if (!NAttrNonResident(na)) {
		ntfs_attr_search_ctx *ctx;
		char *val;

		ctx = ntfs_attr_get_search_ctx(na->ni, NULL);
		if (!ctx)
			return -1;
		if (ntfs_attr_lookup(na->type, na->name, na->name_len, 0,
				0, NULL, 0, ctx)) {
			int eo;
res_err_out:
			eo = errno;
			ntfs_attr_put_search_ctx(ctx);
			errno = eo;
			return -1;
		}
		val = (char*)ctx->attr + le16_to_cpu(ctx->attr->value_offset);
		if (val < (char*)ctx->attr || val +
				le32_to_cpu(ctx->attr->value_length) >
				(char*)ctx->mrec + vol->mft_record_size) {
			errno = EIO;
			goto res_err_out;
		}
		memcpy(b, val + pos, count);
		ntfs_attr_put_search_ctx(ctx);
		return count;
	}
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
		br = ntfs_pread(f, (rl->lcn << vol->cluster_size_bits) + ofs,
				to_read, b);
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

/**
 * ntfs_attr_pwrite - positioned write to an ntfs attribute
 * @na:		ntfs attribute to write to
 * @pos:	position in the attribute to write to
 * @count:	number of bytes to write
 * @b:		data buffer to write to disk
 *
 * This function will write @count bytes from data buffer @b to ntfs attribute
 * @na at position @pos.
 *
 * On success, return the number of successfully written bytes. If this number
 * is lower than @count this means that an error was encountered during the
 * write so that the write is partial. 0 means nothing was written (also return
 * 0 when @count is 0).
 *
 * On error and nothing has been written, return -1 with errno set
 * appropriately to the return code of ntfs_pwrite(), or to EINVAL in case of
 * invalid arguments.
 *
 * NOTE: Currently changes in length of the attribute @na are not implemented.
 * Thus if such a change is requested we return -1 with errno set to ENOTSUP.
 */
s64 ntfs_attr_pwrite(ntfs_attr *na, const s64 pos, s64 count, void *b)
{
	s64 written, to_write, ofs, total, old_initialized_size;
	ntfs_volume *vol;
	ntfs_attr_search_ctx *ctx = NULL;
	runlist_element *rl;
	int f, eo;
	struct {
		unsigned int initialized_size	: 1;
	} need_to_undo = { 0 };

	Dprintf("%s(): Entering for inode 0x%Lx, attr 0x%x, pos 0x%Lx, "
			"count 0x%Lx.\n", __FUNCTION__, na->ni->mft_no,
			na->type, (long long)pos, (long long)count);
	if (!na || !na->ni || !na->ni->vol || !b || pos < 0 || count < 0) {
		errno = EINVAL;
		return -1;
	}
	vol = na->ni->vol;
	f = vol->fd;
	if (!f) {
		errno = EBADF;
		return -1;
	}
	/*
	 * Encrypted attributes are not supported. We return access denied,
	 * which is what Windows NT4 does, too.
	 */
	if (NAttrEncrypted(na)) {
		errno = EACCES;
		return -1;
	}
	/* If this is a compressed attribute it needs special treatment. */
	if (NAttrCompressed(na)) {
		// TODO: Implement writing compressed attributes! (AIA)
		// return ntfs_attr_pwrite_compressed(ntfs_attr *na,
		//		const s64 pos, s64 count, void *b);
		errno = ENOTSUP;
		return -1;
	}
	if (!count)
		return 0;
	/* If the write reaches beyond the end, extend the attribute. */
	if (pos + count > na->data_size) {
		// TODO: Need to extend the attribute. For now, just do a
		// partial write or abort if completely out of bounds. (AIA)
		if (pos >= na->data_size) {
			errno = ENOTSUP;
			return -1;
		}
		count = na->data_size - pos;
	}
	old_initialized_size = na->initialized_size;
	/* If it is a resident attribute, write the data to the mft record. */
	if (!NAttrNonResident(na)) {
		char *val;

		ctx = ntfs_attr_get_search_ctx(na->ni, NULL);
		if (!ctx)
			goto err_out;
		if (ntfs_attr_lookup(na->type, na->name, na->name_len, 0,
				0, NULL, 0, ctx))
			goto err_out;
		val = (char*)ctx->attr + le16_to_cpu(ctx->attr->value_offset);
		if (val < (char*)ctx->attr || val +
				le32_to_cpu(ctx->attr->value_length) >
				(char*)ctx->mrec + vol->mft_record_size) {
			errno = EIO;
			goto err_out;
		}
		memcpy(val + pos, b, count);
		if (ntfs_mft_record_write(vol, ctx->ntfs_ino->mft_no,
				ctx->mrec)) {
			/*
			 * NOTE: We are in a bad state at this moment. We have
			 * dirtied the mft record but we failed to commit it to
			 * disk. Since we have read the mft record ok before,
			 * it is unlikely to fail writing it, so is ok to just
			 * return error here... (AIA)
			 */
			goto err_out;
		}
		ntfs_attr_put_search_ctx(ctx);
		return count;
	}
	total = 0;
	/* Find the runlist element containing the vcn. */
	rl = ntfs_attr_find_vcn(na, pos >> vol->cluster_size_bits);
	if (!rl) {
		/*
		 * If the vcn is not present it is an out of bounds write.
		 * However, we already extended the size of the attribute,
		 * so getting this here must be an error of some kind.
		 */
		if (errno == ENOENT)
			errno = EIO;
		goto err_out;
	}
	/* Handle writes beyond initialized_size. */
	if (pos + count > na->initialized_size) {
		/* Set initialized_size to @pos + @count. */
		ctx = ntfs_attr_get_search_ctx(na->ni, NULL);
		if (!ctx)
			goto err_out;
		if (ntfs_attr_lookup(na->type, na->name, na->name_len, 0,
				0, NULL, 0, ctx))
			goto err_out;
		/* If write starts beyond initialized_size, zero the gap. */
		if (pos > na->initialized_size) {
			// TODO: Need to write zeroes in the region from
			// na->initialized_size to @pos, then update the
			// initialized size to equal @pos. If any sparse runs
			// are encountered while filling the gap, need to
			// honour them, i.e. do not instantiate them. Then can
			// continue as if pos <= na->initialized_size, i.e. can
			// just fall through and continue. (AIA)
			errno = ENOTSUP;
			goto err_out;
		}
		ctx->attr->initialized_size = scpu_to_le64(pos + count);
		if (ntfs_mft_record_write(vol, ctx->ntfs_ino->mft_no,
				ctx->mrec)) {
			/*
			 * Undo the change in the in-memory copy and send it
			 * back for writing.
			 */
			ctx->attr->initialized_size =
					scpu_to_le64(old_initialized_size);
			ntfs_mft_record_write(vol, ctx->ntfs_ino->mft_no,
					ctx->mrec);
			goto err_out;
		}
		na->initialized_size = pos + count;
		ntfs_attr_put_search_ctx(ctx);
		ctx = NULL;
		/*
		 * NOTE: At this point the initialized_size in the mft record
		 * has been updated BUT there is random data on disk thus if
		 * we decide to abort, we MUST change the initialized_size
		 * again.
		 */
		need_to_undo.initialized_size = 1;
	}
	/*
	 * Scatter the data from the linear data buffer to the volume. Note, a
	 * partial final vcn is taken care of by the @count capping of write
	 * length.
	 */
	ofs = pos - (rl->vcn << vol->cluster_size_bits);
	for (; count; rl++, ofs = 0) {
		if (!rl->length) {
			errno = EIO;
			goto rl_err_out;
		}
		if (rl->lcn < (LCN)0) {
			s64 t;
			int cnt;

			if (rl->lcn != (LCN)LCN_HOLE) {
				errno = EIO;
				goto rl_err_out;
			}
			/*
			 * It is a hole. Check if the data buffer is zero in
			 * this region and if not instantiate the hole.
			 */
			to_write = min(count, (rl->length <<
					vol->cluster_size_bits) - ofs);
			written = to_write / sizeof(unsigned long);
			eo = 0;
			for (t = 0; t < written; t++) {
				if (((unsigned long*)b)[t]) {
					eo = 1;
					break;
				}
			}
			cnt = to_write & (sizeof(unsigned long) - 1);
			if (cnt && !eo) {
				int i;
				u8 *b2;

				b2 = (u8*)b + (to_write &
						~(sizeof(unsigned long) - 1));
				for (i = 0; i < cnt; i++) {
					if (b2[i]) {
						eo = 1;
						break;
					}
				}
			}
			if (eo) {
				// TODO: Need to instantiate the hole. Then get
				// the runlist element again checking if it is
				// ok and fall through to do the writing. (AIA)
				errno = ENOTSUP;
				goto rl_err_out;
			}
			/*
			 * The buffer region is zero, update progress counters
			 * and proceed with next run.
			 */
			total += to_write;
			count -= to_write;
			(u8*)b += to_write;
			continue;
		}
		/* It is a real lcn, write it to the volume. */
		to_write = min(count, (rl->length << vol->cluster_size_bits) -
				ofs);
retry:
		Dprintf("%s(): Writing 0x%Lx bytes to vcn 0x%Lx, lcn 0x%Lx, "
				"ofs 0x%Lx.\n", __FUNCTION__, to_write,
				rl->vcn, rl->lcn, ofs);
		written = ntfs_pwrite(f, (rl->lcn << vol->cluster_size_bits) +
				ofs, to_write, b);
		/* If everything ok, update progress counters and continue. */
		if (written > 0) {
			total += written;
			count -= written;
			(u8*)b += written;
			continue;
		}
		/* If the syscall was interrupted, try again. */
		if (written == (s64)-1 && errno == EINTR)
			goto retry;
		if (!written)
			errno = EIO;
		goto rl_err_out;
	}
done:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	/* Finally, return the number of bytes written. */
	return total;
rl_err_out:
	eo = errno;
	if (total) {
		if (need_to_undo.initialized_size) {
			if (pos + total > na->initialized_size)
				goto done;
			// TODO: Need to try to change initialized_size. If it
			// succeeds goto done, otherwise goto err_out. (AIA)
			errno = ENOTSUP;
			goto err_out;
		}
		goto done;
	}
	errno = eo;
err_out:
	eo = errno;
	if (need_to_undo.initialized_size) {
		int err;

		err = 0;
		if (!ctx) {
			ctx = ntfs_attr_get_search_ctx(na->ni, NULL);
			if (!ctx)
				err = 1;
		} else
			ntfs_attr_reinit_search_ctx(ctx);
		if (!err) {
			err = ntfs_attr_lookup(na->type, na->name,
					na->name_len, 0, 0, NULL, 0, ctx);
			if (!err) {
				na->initialized_size = old_initialized_size;
				ctx->attr->initialized_size = scpu_to_le64(
						old_initialized_size);
				err = ntfs_mft_record_write(vol,
						ctx->ntfs_ino->mft_no,
						ctx->mrec);
			}
		}
		if (err) {
			Dputs("Eeek! Failed to recover from error. Leaving "
					"metadata in inconsistent state! Run "
					"chkdsk!");
			// FIXME: At this stage could try to recover by filling
			// old_initialized_size -> new_initialized_size with
			// data or at least zeroes. (AIA)
		}
	}
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	errno = eo;
	return -1;
}

/**
 * ntfs_attr_mst_pread - multi sector transfer protected ntfs attribute read
 * @na:		multi sector transfer protected ntfs attribute to read from
 * @pos:	byte position in the attribute to begin reading from
 * @bk_cnt:	number of mst protected blocks to read
 * @bk_size:	size of each mst protected block in bytes
 * @b:		output data buffer
 *
 * This function will read @bk_cnt blocks of size @bk_size bytes each starting
 * at offset @pos from the ntfs attribute @na into the data buffer @b.
 *
 * On success, the multi sector transfer fixups are applied and the number of
 * read blocks is returned. If this number is lower than @bk_cnt this means
 * that the read has either reached end of attribute or that an error was
 * encountered during the read so that the read is partial. 0 means end of
 * attribute or nothing to read (also return 0 when @bk_cnt or @bk_size are 0).
 *
 * On error and nothing has been read, return -1 with errno set appropriately
 * to the return code of ntfs_attr_pread() or to EINVAL in case of invalid
 * arguments.
 *
 * NOTE: If an incomplete multi sector transfer is detected the magic is
 * changed to BAAD but no error is returned, i.e. it is possible that any of
 * the returned blocks have multi sector transfer errors. This should be
 * detected by the caller by checking each block with is_baad_recordp(&block).
 * The reasoning is that we want to fixup as many blocks as possible and we
 * want to return even bad ones to the caller so, e.g. in case of ntfsck, the
 * errors can be repaired.
 */
s64 ntfs_attr_mst_pread(ntfs_attr *na, const s64 pos, const s64 bk_cnt,
		const u32 bk_size, void *b)
{
	s64 br;
	u8 *end;

	Dprintf("%s(): Entering for inode 0x%Lx, attr type 0x%x, pos 0x%Lx.\n",
			__FUNCTION__, (unsigned long long)na->ni->mft_no,
			na->type, (long long)pos);
	if (bk_cnt < 0 || bk_size % NTFS_SECTOR_SIZE) {
		errno = EINVAL;
		return -1;
	}
	br = ntfs_attr_pread(na, pos, bk_cnt * bk_size, b);
	if (br <= 0)
		return br;
	br /= bk_size;
	for (end = (u8*)b + br * bk_size; (u8*)b < end; (u8*)b += bk_size)
		ntfs_mst_post_read_fixup((NTFS_RECORD*)b, bk_size);
	/* Finally, return the number of blocks read. */
	return br;
}

/**
 * ntfs_attr_mst_pwrite - multi sector transfer protected ntfs attribute write
 * @na:		multi sector transfer protected ntfs attribute to write to
 * @pos:	position in the attribute to write to
 * @bk_cnt:	number of mst protected blocks to write
 * @bk_size:	size of each mst protected block in bytes
 * @b:		data buffer to write to disk
 *
 * This function will write @bk_cnt blocks of size @bk_size bytes each from
 * data buffer @b to multi sector transfer (mst) protected ntfs attribute @na
 * at position @pos.
 *
 * On success, return the number of successfully written blocks. If this number
 * is lower than @bk_cnt this means that an error was encountered during the
 * write so that the write is partial. 0 means nothing was written (also
 * return 0 when @bk_cnt or @bk_size are 0).
 *
 * On error and nothing has been written, return -1 with errno set
 * appropriately to the return code of ntfs_attr_pwrite(), or to EINVAL in case
 * of invalid arguments.
 *
 * NOTE: We mst protect the data, write it, then mst deprotect it using a quick
 * deprotect algorithm (no checking). This saves us from making a copy before
 * the write and at the same time causes the usn to be incremented in the
 * buffer. This conceptually fits in better with the idea that cached data is
 * always deprotected and protection is performed when the data is actually
 * going to hit the disk and the cache is immediately deprotected again
 * simulating an mst read on the written data. This way cache coherency is
 * achieved.
 */
s64 ntfs_attr_mst_pwrite(ntfs_attr *na, const s64 pos, s64 bk_cnt,
		const u32 bk_size, void *b)
{
	s64 written, i;

	Dprintf("%s(): Entering for inode 0x%Lx, attr type 0x%x, pos 0x%Lx.\n",
			__FUNCTION__, (unsigned long long)na->ni->mft_no,
			na->type, (long long)pos);
	if (bk_cnt < 0 || bk_size % NTFS_SECTOR_SIZE) {
		errno = EINVAL;
		return -1;
	}
	if (!bk_cnt)
		return 0;
	/* Prepare data for writing. */
	for (i = 0; i < bk_cnt; ++i) {
		int err;

		err = ntfs_mst_pre_write_fixup((NTFS_RECORD*)
				((u8*)b + i * bk_size), bk_size);
		if (err < 0) {
			/* Abort write at this position. */
			if (!i)
				return err;
			bk_cnt = i;
			break;
		}
	}
	/* Write the prepared data. */
	written = ntfs_attr_pwrite(na, pos, bk_cnt * bk_size, b);
	/* Quickly deprotect the data again. */
	for (i = 0; i < bk_cnt; ++i)
		ntfs_mst_post_write_fixup((NTFS_RECORD*)((u8*)b + i * bk_size));
	if (written <= 0)
		return written;
	/* Finally, return the number of complete blocks written. */
	return written / bk_size;
}

/**
 * Internal:
 *
 * ntfs_attr_find - find (next) attribute in mft record
 * @type:	attribute type to find
 * @name:	attribute name to find (optional, i.e. NULL means don't care)
 * @name_len:	attribute name length (only needed if @name present)
 * @ic:		IGNORE_CASE or CASE_SENSITIVE (ignored if @name not present)
 * @val:	attribute value to find (optional, resident attributes only)
 * @val_len:	attribute value length
 * @ctx:	search context with mft record and attribute to search from
 *
 * You shouldn't need to call this function directly. Use lookup_attr() instead.
 *
 * ntfs_attr_find() takes a search context @ctx as parameter and searches the
 * mft record specified by @ctx->mrec, beginning at @ctx->attr, for an
 * attribute of @type, optionally @name and @val. If found, ntfs_attr_find()
 * returns 0 and @ctx->attr will point to the found attribute. If not found,
 * ntfs_attr_find() returns -1, with errno set to the error code and @ctx->attr
 * is undefined (i.e. do not rely on it not changing).
 *
 * If @ctx->is_first is TRUE, the search begins with @ctx->attr itself. If it
 * is FALSE, the search begins after @ctx->attr.
 *
 * If @type is zero (i.e. AT_UNUSED), return the first found attribute, i.e.
 * one can enumerate all attributes by setting @type to zero and then calling
 * ntfs_attr_find() repeatedly until it returns -1 with errno set to ENOENT to
 * indicate that there are no more entries. During the enumeration, each
 * successful call of ntfs_attr_find() will return the next attribute in the
 * mft record @ctx->mrec.
 *
 * If @type is AT_END, seek to the end and return -1 with errno set to ENOENT.
 * AT_END is not a valid attribute, its length is zero for example, thus it is
 * safer to return error instead of success in this case. This also allows us
 * to interoperate cleanly with ntfs_external_attr_find().
 *
 * If @name is AT_UNNAMED search for an unnamed attribute. If @name is present
 * but not AT_UNNAMED search for a named attribute matching @name. Otherwise,
 * match both named and unnamed attributes.
 *
 * If @ic is IGNORE_CASE, the @name comparisson is not case sensitive and
 * @ctx->ntfs_ino must be set to the ntfs inode to which the mft record
 * @ctx->mrec belongs. This is so we can get at the ntfs volume and hence at
 * the upcase table. If @ic is CASE_SENSITIVE, the comparison is case
 * sensitive. When @name is present, @name_len is the @name length in Unicode
 * characters.
 *
 * If @name is not present (NULL), we assume that the unnamed attribute is
 * being searched for.
 *
 * Finally, the resident attribute value @val is looked for, if present.
 * If @val is not present (NULL), @val_len is ignored.
 *
 * ntfs_attr_find() only searches the specified mft record and it ignores the
 * presence of an attribute list attribute (unless it is the one being searched
 * for, obviously). If you need to take attribute lists into consideration, use
 * ntfs_attr_lookup() instead (see below). This also means that you cannot use
 * ntfs_attr_find() to search for extent records of non-resident attributes, as
 * extents with lowest_vcn != 0 are usually described by the attribute list
 * attribute only. - Note that it is possible that the first extent is only in
 * the attribute list while the last extent is in the base mft record, so don't
 * rely on being able to find the first extent in the base mft record.
 *
 * Warning: Never use @val when looking for attribute types which can be
 *	    non-resident as this most likely will result in a crash!
 */
static int ntfs_attr_find(const ATTR_TYPES type, const uchar_t *name,
		const u32 name_len, const IGNORE_CASE_BOOL ic,
		const u8 *val, const u32 val_len, ntfs_attr_search_ctx *ctx)
{
	ATTR_RECORD *a;
	ntfs_volume *vol;
	uchar_t *upcase;
	u32 upcase_len;

	if (!ctx || !ctx->mrec || !ctx->attr) {
		errno = EINVAL;
		return -1;
	}
	if (ic == IGNORE_CASE) {
		vol = ctx->ntfs_ino->vol;
		upcase = vol->upcase;
		upcase_len = vol->upcase_len;
	} else {
		vol = NULL;
		upcase = NULL;
		upcase_len = 0;
	}
	/*
	 * Iterate over attributes in mft record starting at @ctx->attr, or the
	 * attribute following that, if @ctx->is_first is TRUE.
	 */
	if (ctx->is_first) {
		a = ctx->attr;
		ctx->is_first = FALSE;
	} else
		a = (ATTR_RECORD*)((char*)ctx->attr +
				le32_to_cpu(ctx->attr->length));
	for (;;	a = (ATTR_RECORD*)((char*)a + le32_to_cpu(a->length))) {
		if (p2n(a) < p2n(ctx->mrec) || (char*)a > (char*)ctx->mrec +
				le32_to_cpu(ctx->mrec->bytes_allocated))
			break;
		ctx->attr = a;
		/* We catch $END with this more general check, too... */
		if ((type && (le32_to_cpu(a->type) > le32_to_cpu(type))) ||
				(a->type == AT_END)) {
			errno = ENOENT;
			return -1;
		}
		if (!a->length)
			break;
		/* If this is an enumeration return this attribute. */
		if (!type)
			return 0;
		if (a->type != type)
			continue;
		/*
		 * If @name is AT_UNNAMED we want an unnamed attribute.
		 * If @name is present, compare the two names.
		 * Otherwise, match any attribute.
		 */
		if (name == AT_UNNAMED) {
			/* The search failed if the found attribute is named. */
			if (a->name_length) {
				errno = ENOENT;
				return -1;
			}
		} else if (name && !ntfs_names_are_equal(name, name_len,
			    (uchar_t*)((char*)a + le16_to_cpu(a->name_offset)),
			    a->name_length, ic, upcase, upcase_len)) {
			register int rc;

			rc = ntfs_names_collate(name, name_len,
					(uchar_t*)((char*)a +
					le16_to_cpu(a->name_offset)),
					a->name_length, 1, IGNORE_CASE,
					upcase, upcase_len);
			/*
			 * If @name collates before a->name, there is no
			 * matching attribute.
			 */
			if (rc == -1) {
				errno = ENOENT;
				return -1;
			}
			/* If the strings are not equal, continue search. */
			if (rc)
				continue;
			rc = ntfs_names_collate(name, name_len,
					(uchar_t*)((char*)a +
					le16_to_cpu(a->name_offset)),
					a->name_length, 1, CASE_SENSITIVE,
					upcase, upcase_len);
			if (rc == -1) {
				errno = ENOENT;
				return -1;
			}
			if (rc)
				continue;
		}
		/*
		 * The names match or @name not present and attribute is
		 * unnamed. If no @val specified, we have found the attribute
		 * and are done.
		 */
		if (!val)
			return 0;
		/* @val is present; compare values. */
		else {
			register int rc;

			rc = memcmp(val, (char*)a +le16_to_cpu(a->value_offset),
					min(val_len,
					le32_to_cpu(a->value_length)));
			/*
			 * If @val collates before the current attribute's
			 * value, there is no matching attribute.
			 */
			if (!rc) {
				register u32 avl;
				avl = le32_to_cpu(a->value_length);
				if (val_len == avl)
					return 0;
				if (val_len < avl) {
					errno = ENOENT;
					return -1;
				}
			} else if (rc < 0) {
				errno = ENOENT;
				return -1;
			}
		}
	}
	Dputs("ntfs_attr_find(): File is corrupt. Run chkdsk.");
	errno = EIO;
	return -1;
}

/**
 * Internal:
 *
 * ntfs_external_attr_find - find an attribute in the attribute list of an inode
 * @type:	attribute type to find
 * @name:	attribute name to find (optional, i.e. NULL means don't care)
 * @name_len:	attribute name length (only needed if @name present)
 * @ic:		IGNORE_CASE or CASE_SENSITIVE (ignored if @name not present)
 * @lowest_vcn:	lowest vcn to find (optional, non-resident attributes only)
 * @val:	attribute value to find (optional, resident attributes only)
 * @val_len:	attribute value length
 * @ctx:	search context with mft record and attribute to search from
 *
 * You shouldn't need to call this function directly. Use ntfs_attr_lookup()
 * instead.
 *
 * Find an attribute by searching the attribute list for the corresponding
 * attribute list entry. Having found the entry, map the mft record for read
 * if the attribute is in a different mft record/inode, find the attribute in
 * there and return it.
 *
 * If @type is zero (i.e. AT_UNUSED), return the first found attribute, i.e.
 * one can enumerate all attributes by setting @type to zero and then calling
 * ntfs_external_attr_find() repeatedly until it returns -1 with errno set to
 * ENOENT to indicate that there are no more entries. During the enumeration,
 * each successful call of ntfs_external_attr_find() will return the next
 * attribute described by the attribute list of the base mft record described
 * by the search context @ctx.
 *
 * If @type is AT_END, seek to the end and return -1 with errno set to ENOENT.
 * AT_END is not a valid attribute, its length is zero for example, thus it is
 * safer to return error instead of success in this case.
 *
 * If @name is AT_UNNAMED search for an unnamed attribute. If @name is present
 * but not AT_UNNAMED search for a named attribute matching @name. Otherwise,
 * match both named and unnamed attributes.
 *
 * On first search @ctx->ntfs_ino must be the inode of the base mft record and
 * @ctx must have been obtained from a call to ntfs_attr_get_search_ctx().
 * On subsequent calls, @ctx->ntfs_ino can be any extent inode, too
 * (@ctx->base_ntfs_ino is then the base inode).
 *
 * After finishing with the attribute/mft record you need to call
 * ntfs_attr_put_search_ctx() to cleanup the search context (unmapping any
 * mapped extent inodes, etc).
 *
 * Return 0 if the search was successful and -1 if not, with errno set to the
 * error code.
 *
 * On success, @ctx->attr is the found attribute and it is in mft record
 * @ctx->mrec.
 *
 * On error, @ctx->attr is the attribute which collates just after the attribute
 * being searched for in the base ntfs inode, i.e. if one wants to add the
 * attribute to the mft record this is the correct place to insert it into,
 * and if there is not enough space, the attribute should be placed in an
 * extent mft record. @ctx->al_entry points to the position within
 * @ctx->base_ntfs_ino->attr_list at which the new attribute's attribute list
 * entry should be inserted.
 *
 * The following error codes are defined:
 *	ENOENT	Attribute not found, not an error as such.
 *	EINVAL	Invalid arguments.
 *	EIO	I/O error or corrupt data structures found.
 *	ENOMEM	Not enough memory to allocate necessary buffers.
 */
static int ntfs_external_attr_find(ATTR_TYPES type, const uchar_t *name,
		const u32 name_len, const IGNORE_CASE_BOOL ic,
		const VCN lowest_vcn, const u8 *val, const u32 val_len,
		ntfs_attr_search_ctx *ctx)
{
	ntfs_inode *base_ni, *ni;
	ntfs_volume *vol;
	ATTR_LIST_ENTRY *al_entry, *next_al_entry;
	char *al_start, *al_end;
	ATTR_RECORD *a;
	uchar_t *al_name;
	u32 al_name_len;
	BOOL is_first_search = FALSE;

	ni = ctx->ntfs_ino;
	base_ni = ctx->base_ntfs_ino;
	Dprintf("Entering for inode %Lu, attribute type 0x%x.\n",
			(unsigned long long)ni->mft_no, type);
	if (!base_ni) {
		/* First call happens with the base mft record. */
		base_ni = ctx->base_ntfs_ino = ctx->ntfs_ino;
		ctx->base_mrec = ctx->mrec;
	}
	if (type == AT_END)
		goto not_found;
	if (ni == base_ni)
		ctx->base_attr = ctx->attr;
	vol = base_ni->vol;
	al_start = base_ni->attr_list;
	al_end = al_start + base_ni->attr_list_size;
	if (!ctx->al_entry) {
		ctx->al_entry = (ATTR_LIST_ENTRY*)al_start;
		is_first_search = TRUE;
	}
	/*
	 * Iterate over entries in attribute list starting at @ctx->al_entry,
	 * or the entry following that, if @ctx->is_first is TRUE.
	 */
	if (ctx->is_first) {
		al_entry = ctx->al_entry;
		ctx->is_first = FALSE;
		/*
		 * If an enumeration and the first attribute is higher than
		 * the attribute list itself, need to return the attribute list
		 * attribute.
		 */
		if (!type && is_first_search && le16_to_cpu(al_entry->type) >
				le16_to_cpu(AT_ATTRIBUTE_LIST))
			goto find_attr_list_attr;
	} else {
		al_entry = (ATTR_LIST_ENTRY*)((char*)ctx->al_entry +
				le16_to_cpu(ctx->al_entry->length));
		/*
		 * If this is an enumeration and the attribute list attribute
		 * is the next one in the enumeration sequence, just return the
		 * attribute list attribute from the base mft record as it is
		 * not listed in the attribute list itself.
		 */
		if (!type && le16_to_cpu(ctx->al_entry->type) <
				le16_to_cpu(AT_ATTRIBUTE_LIST) &&
				le16_to_cpu(al_entry->type) >
				le16_to_cpu(AT_ATTRIBUTE_LIST)) {
			int rc;
find_attr_list_attr:

			/* Check for bogus calls. */
			if (name || name_len || val || val_len || lowest_vcn) {
				errno = EINVAL;
				return -1;
			}

			/* We want the base record. */
			ctx->ntfs_ino = base_ni;
			ctx->mrec = ctx->base_mrec;
			ctx->is_first = TRUE;
			/* Sanity checks are performed elsewhere. */
			ctx->attr = (ATTR_RECORD*)((u8*)ctx->mrec +
					le16_to_cpu(ctx->mrec->attrs_offset));

			/* Find the attribute list attribute. */
			rc = ntfs_attr_find(AT_ATTRIBUTE_LIST, NULL, 0,
					IGNORE_CASE, NULL, 0, ctx);

			/*
			 * Setup the search context so the correct
			 * attribute is returned next time round.
			 */
			ctx->al_entry = al_entry;
			ctx->is_first = TRUE;

			/* Got it. Done. */
			if (!rc)
			       return 0;

			/* Error! If other than not found return it. */
			if (errno != EINVAL)
				return rc;

			/* Not found?!? Absurd! Must be a bug... )-: */
			Dprintf("%s(): BUG! Attribute list attribute not found "
					"but it exists! Returning error "
					"(EINVAL).", __FUNCTION__);
			errno = EINVAL;
			return -1;
		}
	}
	for (;; al_entry = next_al_entry) {
		/* Out of bounds check. */
		if ((u8*)al_entry < base_ni->attr_list ||
				(char*)al_entry > al_end)
			break;	/* Inode is corrupt. */
		ctx->al_entry = al_entry;
		/* Catch the end of the attribute list. */
		if ((char*)al_entry == al_end)
			goto not_found;
		if (!al_entry->length)
			break;
		if ((char*)al_entry + 6 > al_end || (char*)al_entry +
				le16_to_cpu(al_entry->length) > al_end)
			break;
		next_al_entry = (ATTR_LIST_ENTRY*)((char*)al_entry +
				le16_to_cpu(al_entry->length));
		if (type) {
			if (le32_to_cpu(al_entry->type) > le32_to_cpu(type))
				goto not_found;
			if (type != al_entry->type)
				continue;
		}
		al_name_len = al_entry->name_length;
		al_name = (uchar_t*)((char*)al_entry + al_entry->name_offset);
		/*
		 * If !@type we want the attribute represented by this
		 * attribute list entry.
		 */
		if (!type)
			goto is_enumeration;
		/*
		 * If @name is AT_UNNAMED we want an unnamed attribute.
		 * If @name is present, compare the two names.
		 * Otherwise, match any attribute.
		 */
		if (name == AT_UNNAMED) {
			if (al_name_len)
				goto not_found;
		} else if (name && !ntfs_names_are_equal(al_name, al_name_len,
				name, name_len, ic, vol->upcase,
				vol->upcase_len)) {
			register int rc;

			rc = ntfs_names_collate(name, name_len, al_name,
					al_name_len, 1, IGNORE_CASE,
					vol->upcase, vol->upcase_len);
			/*
			 * If @name collates before al_name, there is no
			 * matching attribute.
			 */
			if (rc == -1)
				goto not_found;
			/* If the strings are not equal, continue search. */
			if (rc)
				continue;
			/*
			 * FIXME: Reverse engineering showed 0, IGNORE_CASE but
			 * that is inconsistent with ntfs_attr_find(). The
			 * subsequent rc checks were also different. Perhaps I
			 * made a mistake in one of the two. Need to recheck
			 * which is correct or at least see what is going
			 * on... (AIA)
			 */
			rc = ntfs_names_collate(name, name_len, al_name,
					al_name_len, 1, CASE_SENSITIVE,
					vol->upcase, vol->upcase_len);
			if (rc == -1)
				goto not_found;
			if (rc)
				continue;
		}
		/*
		 * The names match or @name not present and attribute is
		 * unnamed. Now check @lowest_vcn. Continue search if the
		 * next attribute list entry still fits @lowest_vcn. Otherwise
		 * we have reached the right one or the search has failed.
		 */
		if (lowest_vcn && (char*)next_al_entry >= al_start	    &&
				(char*)next_al_entry + 6 < al_end	    &&
				(char*)next_al_entry + le16_to_cpu(
					next_al_entry->length) <= al_end    &&
				sle64_to_cpu(next_al_entry->lowest_vcn) <=
					sle64_to_cpu(lowest_vcn)	    &&
				next_al_entry->type == al_entry->type	    &&
				next_al_entry->name_length == al_name_len   &&
				ntfs_names_are_equal((uchar_t*)((char*)
					next_al_entry +
					next_al_entry->name_offset),
					next_al_entry->name_length,
					al_name, al_name_len, CASE_SENSITIVE,
					vol->upcase, vol->upcase_len))
			continue;
is_enumeration:
		if (MREF_LE(al_entry->mft_reference) == ni->mft_no) {
			if (MSEQNO_LE(al_entry->mft_reference) !=
					le16_to_cpu(
					ni->mrec->sequence_number)) {
				Dputs("Found stale mft reference in attribute "
						"list!");
				break;
			}
		} else { /* Mft references do not match. */
			/* Do we want the base record back? */
			if (MREF_LE(al_entry->mft_reference) ==
					base_ni->mft_no) {
				ni = ctx->ntfs_ino = base_ni;
				ctx->mrec = ctx->base_mrec;
			} else {
				/* We want an extent record. */
				ni = ntfs_extent_inode_open(base_ni,
						al_entry->mft_reference);
				if (!ni) {
					Dperror("Failed to map extent inode");
					break;
				}
				ctx->ntfs_ino = ni;
				ctx->mrec = ni->mrec;
			}
			ctx->attr = (ATTR_RECORD*)((char*)ctx->mrec +
					le16_to_cpu(ctx->mrec->attrs_offset));
		}
		/*
		 * ctx->ntfs_ino, ctx->mrec, and ctx->attr now point to the
		 * mft record containing the attribute represented by the
		 * current al_entry.
		 */
		/*
		 * We could call into ntfs_attr_find() to find the right
		 * attribute in this mft record but this would be less
		 * efficient and not quite accurate as ntfs_attr_find() ignores
		 * the attribute instance numbers for example which become
		 * important when one plays with attribute lists. Also, because
		 * a proper match has been found in the attribute list entry
		 * above, the comparison can now be optimized. So it is worth
		 * re-implementing a simplified ntfs_attr_find() here.
		 */
		a = ctx->attr;
		/*
		 * Use a manual loop so we can still use break and continue
		 * with the same meanings as above.
		 */
do_next_attr_loop:
		if ((char*)a < (char*)ctx->mrec || (char*)a > (char*)ctx->mrec +
				le32_to_cpu(ctx->mrec->bytes_allocated))
			break;
		if (a->type == AT_END)
			continue;
		if (!a->length)
			break;
		if (al_entry->instance != a->instance)
			goto do_next_attr;
		/*
		 * If the type and/or the name are/is mismatched between the
		 * attribute list entry and the attribute record, there is
		 * corruption so we break and return error EIO.
		 */
		if (al_entry->type != a->type)
			break;
		if (!ntfs_names_are_equal((uchar_t*)((char*)a +
				le16_to_cpu(a->name_offset)),
				a->name_length, al_name,
				al_name_len, CASE_SENSITIVE,
				vol->upcase, vol->upcase_len))
			break;
		ctx->attr = a;
		/*
		 * If no @val specified or @val specified and it matches, we
		 * have found it! Also, if !@type, it is an enumeration, so we
		 * want the current attribute.
		 */
		if (!type || !val || (!a->non_resident &&
				le32_to_cpu(a->value_length) == val_len &&
				!memcmp((char*)a + le16_to_cpu(a->value_offset),
				val, val_len))) {
			return 0;
		}
do_next_attr:
		/* Proceed to the next attribute in the current mft record. */
		a = (ATTR_RECORD*)((char*)a + le32_to_cpu(a->length));
		goto do_next_attr_loop;
	}
	if (ni != base_ni) {
		ctx->ntfs_ino = base_ni;
		ctx->mrec = ctx->base_mrec;
		ctx->attr = ctx->base_attr;
	}
	Dputs("Inode is corrupt.");
	errno = EIO;
	return -1;
not_found:
	/*
	 * Seek to the end of the base mft record, i.e. when we return false,
	 * ctx->mrec and ctx->attr indicate where the attribute should be
	 * inserted into the attribute record.
	 * And of course ctx->al_entry points to the end of the attribute
	 * list inside ctx->base_ntfs_ino->attr_list.
	 *
	 * FIXME: Do we really want to do this here? Think about it... (AIA)
	 */
	ntfs_attr_reinit_search_ctx(ctx);
	/*
	 * If we were enumerating and reached the end, we can't just use !@type
	 * because that would return the first attribute instead of the last
	 * one. Thus we just change @type to AT_END which causes
	 * ntfs_attr_find() to seek to the end. We also do the same when an
	 * attribute extent was searched for (i.e. lowest_vcn != 0), as we
	 * otherwise rewind the search back to the first extent and we get
	 * that extent returned twice during a search for all extents.
	 */
	if (!type || lowest_vcn)
		type = AT_END;
	return ntfs_attr_find(type, name, name_len, ic, val, val_len, ctx);
}

/**
 * ntfs_attr_lookup - find an attribute in an ntfs inode
 * @type:	attribute type to find
 * @name:	attribute name to find (optional, i.e. NULL means don't care)
 * @name_len:	attribute name length (only needed if @name present)
 * @ic:		IGNORE_CASE or CASE_SENSITIVE (ignored if @name not present)
 * @lowest_vcn:	lowest vcn to find (optional, non-resident attributes only)
 * @val:	attribute value to find (optional, resident attributes only)
 * @val_len:	attribute value length
 * @ctx:	search context with mft record and attribute to search from
 *
 * Find an attribute in an ntfs inode. On first search @ctx->ntfs_ino must
 * be the base mft record and @ctx must have been obtained from a call to
 * ntfs_attr_get_search_ctx().
 *
 * This function transparently handles attribute lists and @ctx is used to
 * continue searches where they were left off at.
 *
 * If @type is zero (i.e. AT_UNUSED), return the first found attribute, i.e.
 * one can enumerate all attributes by setting @type to zero and then calling
 * ntfs_attr_lookup() repeatedly until it returns -1 with errno set to ENOENT
 * to indicate that there are no more entries. During the enumeration, each
 * successful call of ntfs_attr_lookup() will return the next attribute, with
 * the current attribute being described by the search context @ctx.
 *
 * If @type is AT_END, seek to the end of the attribute and return -1 with
 * errno set to ENOENT. AT_END is not a valid attribute, its length is zero for
 * example, thus it is safer to return error instead of success in this case.
 * It should never ne needed to do this, but we implement the functionality
 * because it allows for simpler code inside ntfs_external_attr_find().
 *
 * If @name is AT_UNNAMED search for an unnamed attribute. If @name is present
 * but not AT_UNNAMED search for a named attribute matching @name. Otherwise,
 * match both named and unnamed attributes.
 *
 * After finishing with the attribute/mft record you need to call
 * ntfs_attr_put_search_ctx() to cleanup the search context (unmapping any
 * mapped extent inodes, etc).
 *
 * Return 0 if the search was successful and -1 if not, with errno set to the
 * error code.
 *
 * On success, @ctx->attr is the found attribute and it is in mft record
 * @ctx->mrec.
 *
 * On error, @ctx->attr is the attribute which collates just after the attribute
 * being searched for, i.e. if one wants to add the attribute to the mft
 * record this is the correct place to insert it into. @ctx->al_entry points to
 * the position within @ctx->base_ntfs_ino->attr_list at which the new
 * attribute's attribute list entry should be inserted.
 *
 * The following error codes are defined:
 *	ENOENT	Attribute not found, not an error as such.
 *	EINVAL	Invalid arguments.
 *	EIO	I/O error or corrupt data structures found.
 *	ENOMEM	Not enough memory to allocate necessary buffers.
 */
int ntfs_attr_lookup(const ATTR_TYPES type, const uchar_t *name,
		const u32 name_len, const IGNORE_CASE_BOOL ic,
		const VCN lowest_vcn, const u8 *val, const u32 val_len,
		ntfs_attr_search_ctx *ctx)
{
	ntfs_inode *base_ni;

	if (!ctx || !ctx->mrec || !ctx->attr) {
		errno = EINVAL;
		return -1;
	}
	if (ctx->base_ntfs_ino)
		base_ni = ctx->base_ntfs_ino;
	else
		base_ni = ctx->ntfs_ino;
	if (!base_ni || !NInoAttrList(base_ni) || type == AT_ATTRIBUTE_LIST)
		return ntfs_attr_find(type, name, name_len, ic, val, val_len,
				ctx);
	return ntfs_external_attr_find(type, name, name_len, ic, lowest_vcn,
			val, val_len, ctx);
}

/**
 * Internal:
 *
 * ntfs_attr_init_search_ctx - initialize an attribute search context
 * @ctx:	attribute search context to initialize
 * @ni:		ntfs inode with which to initialize the search context
 * @mrec:	mft record with which to initialize the search context
 *
 * Initialize the attribute search context @ctx with @ni and @mrec.
 */
static __inline__ void ntfs_attr_init_search_ctx(ntfs_attr_search_ctx *ctx,
		ntfs_inode *ni, MFT_RECORD *mrec)
{
	if (ni && !mrec)
		mrec = ni->mrec;
	ctx->mrec = mrec;
	/* Sanity checks are performed elsewhere. */
	ctx->attr = (ATTR_RECORD*)((char*)mrec +
			le16_to_cpu(mrec->attrs_offset));
	ctx->is_first = TRUE;
	ctx->ntfs_ino = ni;
	ctx->al_entry = NULL;
	ctx->base_ntfs_ino = NULL;
	ctx->base_mrec = NULL;
	ctx->base_attr = NULL;
}

/**
 * ntfs_attr_reinit_search_ctx - reinitialize an attribute search context
 * @ctx:	attribute search context to reinitialize
 *
 * Reinitialize the attribute search context @ctx.
 *
 * This is used when a search for a new attribute is being started to reset
 * the search context to the beginning.
 */
void ntfs_attr_reinit_search_ctx(ntfs_attr_search_ctx *ctx)
{
	if (!ctx->base_ntfs_ino) {
		/* No attribute list. */
		ctx->is_first = TRUE;
		/* Sanity checks are performed elsewhere. */
		ctx->attr = (ATTR_RECORD*)((char*)ctx->mrec +
				le16_to_cpu(ctx->mrec->attrs_offset));
		return;
	} /* Attribute list. */
	ntfs_attr_init_search_ctx(ctx, ctx->base_ntfs_ino, ctx->base_mrec);
	return;
}

/**
 * ntfs_attr_get_search_ctx - allocate/initialize a new attribute search context
 * @ctx:	address of pointer in which to return the new search context
 * @ni:		ntfs inode with which to initialize the search context
 * @mrec:	mft record with which to initialize the search context
 *
 * Allocate a new attribute search context, initialize it with @ni and @mrec,
 * and return it. Return NULL on error with errno set to ENOMEM.
 *
 * @ni can be NULL if the search context is only going to be used for searching
 * for the attribute list attribute and for searches ignoring the contents of
 * the attribute list attribute.
 *
 * If @ni is specified, @mrec can be NULL, in which case the mft record is
 * taken from @ni.
 *
 * If both @ni and @mrec are specified, the mft record is taken from @mrec and
 * the value of @ni->mrec is ignored.
 */
ntfs_attr_search_ctx *ntfs_attr_get_search_ctx(ntfs_inode *ni, MFT_RECORD *mrec)
{
	ntfs_attr_search_ctx *ctx = malloc(sizeof(ntfs_attr_search_ctx));
	if (ctx)
		ntfs_attr_init_search_ctx(ctx, ni, mrec);
	return ctx;
}

/**
 * ntfs_attr_put_search_ctx - release an attribute search context
 * @ctx:	attribute search context to free
 *
 * Release the attribute search context @ctx.
 */
void ntfs_attr_put_search_ctx(ntfs_attr_search_ctx *ctx)
{
	free(ctx);
	return;
}

/**
 * ntfs_get_nr_significant_bytes - get number of bytes needed to store a number
 * @n:		number for which to get the number of bytes for
 *
 * Return the number of bytes required to store @n unambiguously as
 * a signed number.
 *
 * This is used in the context of the mapping pairs array to determine how
 * many bytes will be needed in the array to store a given logical cluster
 * number (lcn) or a specific run length.
 *
 * Return the number of bytes written. This function cannot fail.
 */
__inline__ int ntfs_get_nr_significant_bytes(const s64 n)
{
	s64 l = n;
	int i;
	s8 j;

	i = 0;
	do {
		l >>= 8;
		i++;
	} while (l != 0LL && l != -1LL);
	j = (n >> 8 * (i - 1)) & 0xff;
	/* If the sign bit is wrong, we need an extra byte. */
	if ((n < 0LL && j >= 0) || (n > 0LL && j < 0))
		i++;
	return i;
}

/**
 * ntfs_get_size_for_mapping_pairs - get bytes needed for mapping pairs array
 * @vol:	ntfs volume (needed for the ntfs version)
 * @rl:		runlist for which to determine the size of the mapping pairs
 *
 * Walk the runlist @rl and calculate the size in bytes of the mapping pairs
 * array corresponding to the runlist @rl. This for example allows us to
 * allocate a buffer of the right size when building the mapping pairs array.
 *
 * Return the calculated size in bytes on success. If @rl is NULL return 0.
 * On error, return -1 with errno set to the error code. The following error
 * codes are defined:
 *	EINVAL	- Run list contains unmapped elements. Make sure to only pass
 *		  fully mapped runlists to this function.
 *	EIO	- The runlist is corrupt.
 */
int ntfs_get_size_for_mapping_pairs(const ntfs_volume *vol,
		const runlist_element *rl)
{
	LCN prev_lcn;
	int i, rls;

	if (!rl)
		return 0;
	/* Always need the termining zero byte. */
	rls = 1;
	for (prev_lcn = i = 0; rl[i].length; prev_lcn = rl[++i].lcn) {
		if (rl[i].length < 0 || rl[i].lcn < LCN_HOLE)
			goto err_out;
		/* Header byte + length. */
		rls += 1 + ntfs_get_nr_significant_bytes(rl[i].length);
		/*
		 * If the logical cluster number (lcn) denotes a hole and we
		 * are on NTFS 3.0+, we don't store it at all, i.e. we need
		 * zero space. On earlier NTFS versions we just store the lcn.
		 */
		if (rl[i].lcn == LCN_HOLE && vol->major_ver >= 3)
			continue;
		/* Change in lcn. */
		rls += ntfs_get_nr_significant_bytes(rl[i].lcn - prev_lcn);
	}
	return rls;
err_out:
	if (rl[i].lcn == LCN_RL_NOT_MAPPED)
		errno = EINVAL;
	else
		errno = EIO;
	return -1;
}

/**
 * ntfs_write_significant_bytes - write the significant bytes of a number
 * @dst:	destination buffer to write to
 * @dst_max:	pointer to last byte of destination buffer for bounds checking
 * @n:		number whose significant bytes to write
 *
 * Store in @dst, the minimum bytes of the number @n which are required to
 * identify @n unambiguously as a signed number, taking care not to exceed
 * @dest_max, the maximum position within @dst to which we are allowed to
 * write.
 *
 * This is used when building the mapping pairs array of a runlist to compress
 * a given logical cluster number (lcn) or a specific run length to the minumum
 * size possible.
 *
 * Return the number of bytes written on success. On error, i.e. the
 * destination buffer @dst is too small, return -1 with errno set ENOSPC.
 */
__inline__ int ntfs_write_significant_bytes(s8 *dst, const s8 *dst_max,
		const s64 n)
{
	s64 l = n;
	int i;
	s8 j;

	i = 0;
	do {
		if (dst > dst_max)
			goto err_out;
		*dst++ = l & 0xffLL;
		l >>= 8;
		i++;
	} while (l != 0LL && l != -1LL);
	j = (n >> 8 * (i - 1)) & 0xff;
	/* If the sign bit is wrong, we need an extra byte. */
	if (n < 0LL && j >= 0) {
		if (dst > dst_max)
			goto err_out;
		i++;
		*dst = (s8)-1;
	} else if (n > 0LL && j < 0) {
		if (dst > dst_max)
			goto err_out;
		i++;
		*dst = (s8)0;
	}
	return i;
err_out:
	errno = ENOSPC;
	return -1;
}

/**
 * ntfs_non_resident_attr_shrink - shrink a non-resident, open ntfs attribute
 * @na:		non-resident ntfs attribute to shrink
 * @newsize:	new size (in bytes) to which to shrink the attribute
 *
 * Reduce the size of a non-resident, open ntfs attribute @na to @newsize bytes.
 *
 * On success return 0 and on error return -1 with errno set to the error code.
 * The following error codes are defined:
 *	ENOTSUP	- The desired resize is not implemented yet.
 */
static int ntfs_non_resident_attr_shrink(ntfs_attr *na, const s64 newsize) {
	errno = ENOTSUP;
	return -1;
}

/**
 * ntfs_resident_attr_value_resize - resize the value of a resident attribute
 * @m:		mft record containing attribute record
 * @a:		attribute record whose value to resize
 * @newsize:	new size in bytes to which to resize the attribute value of @a
 *
 * Resize the value of the attribute @a in the mft record @m to @newsize bytes.
 *
 * Return 0 on success and -1 on error with errno set to the error code.
 * The following error codes are defined:
 *	ENOSPC	- Not enough space in mft record to perform the resize.
 * Note that on error no modifications have been performed whatsoever.
 */
int ntfs_resident_attr_value_resize(MFT_RECORD *m, ATTR_RECORD *a,
		const u32 newsize)
{
	u32 new_alen, new_muse;

	/* Calculate the new attribute length and mft record bytes used. */
	new_alen = (le32_to_cpu(a->length) - le32_to_cpu(a->value_length) +
			newsize + 7) & ~7;
	new_muse = le32_to_cpu(m->bytes_in_use) - le32_to_cpu(a->length) +
			new_alen;
	/* Not enough space in this mft record. */
	if (new_muse > le32_to_cpu(m->bytes_allocated)) {
		errno = ENOSPC;
		return -1;
	}
	/* Move attributes following @a to their new location. */
	memmove((u8*)a + new_alen, (u8*)a + le32_to_cpu(a->length),
			le32_to_cpu(m->bytes_in_use) - ((u8*)a - (u8*)m) -
			le32_to_cpu(a->length));
	/* Adjust @a to reflect the new value size. */
	a->length = cpu_to_le32(new_alen);
	a->value_length = cpu_to_le32(newsize);
	/* Adjust @m to reflect the change in used space. */
	m->bytes_in_use = cpu_to_le32(new_muse);
	return 0;
}

/**
 * ntfs_resident_attr_shrink - shrink a resident, open ntfs attribute
 * @na:		resident ntfs attribute to shrink
 * @newsize:	new size (in bytes) to which to shrink the attribute
 *
 * Reduce the size of a resident, open ntfs attribute @na to @newsize bytes.
 *
 * On success return 0 and on error return -1 with errno set to the error code.
 * The following error codes are defined:
 *	ENOTSUP	- The desired resize is not implemented yet.
 */
static int ntfs_resident_attr_shrink(ntfs_attr *na, const u32 newsize) {
	ntfs_attr_search_ctx *ctx;
	int err;

	Dprintf("%s(): Entering for inode 0x%Lx, attr 0x%x.\n", __FUNCTION__,
			(unsigned long long)na->ni->mft_no, na->type);
	/* Get the attribute record that needs modification. */
	ctx = ntfs_attr_get_search_ctx(na->ni, NULL);
	if (!ctx)
		return -1;
	if (ntfs_attr_lookup(na->type, na->name, na->name_len, 0, 0, NULL, 0,
			ctx)) {
		err = errno;
		goto put_err_out;
	}

	// TODO: Check the attribute type and the corresponding minimum size
	// against @newsize and fail if @newsize is too small! (AIA)

	/* Perform the resize of the attribute record. */
	if (ntfs_resident_attr_value_resize(ctx->mrec, ctx->attr, newsize)) {
		err = errno;
		goto put_err_out;
	}
	/* Update the ntfs attribute structure, too. */
	na->allocated_size = na->data_size = na->initialized_size = newsize;
	if (NAttrCompressed(na) || NAttrSparse(na))
		na->compressed_size = newsize;

	/*
	 * Set the inode (and its base inode if it exists) dirty so it is
	 * written out later.
	 */
	ntfs_inode_mark_dirty(ctx->ntfs_ino);

	ntfs_attr_put_search_ctx(ctx);
	return 0;
put_err_out:
	ntfs_attr_put_search_ctx(ctx);
	errno = err;
	return -1;
}

/**
 * ntfs_attr_truncate - resize an ntfs attribute
 * @na:		open ntfs attribute to resize
 * @newsize:	new size (in bytes) to which to resize the attribute
 *
 * Change the size of an open ntfs attribute @na to @newsize bytes.
 *
 * On success return 0 and on error return -1 with errno set to the error code.
 * The following error codes are defined:
 *	EINVAL	- Invalid arguments were passed to the function.
 *	ENOTSUP	- The desired resize is not implemented yet.
 *
 * NOTE: At present attributes can only be made smaller using this function,
 *	 never bigger.
 */
int ntfs_attr_truncate(ntfs_attr *na, const s64 newsize)
{
	if (!na || newsize < 0) {
		errno = EINVAL;
		return -1;
	}
	/*
	 * Encrypted attributes are not supported. We return access denied,
	 * which is what Windows NT4 does, too.
	 */
	if (NAttrEncrypted(na)) {
		errno = EACCES;
		return -1;
	}
	/*
	 * TODO: Implement making attributes bigger/filling in of uninitialized
	 * holes as well as handling of compressed attributes. (AIA)
	 */
	if (newsize > na->initialized_size || NAttrCompressed(na)) {
		errno = ENOTSUP;
		return -1;
	}

	if (NAttrNonResident(na))
		return ntfs_non_resident_attr_shrink(na, newsize);
	return ntfs_resident_attr_shrink(na, newsize);
}

