/*
 * attrib.c - Attribute handling code. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2000-2004 Anton Altaparmakov
 * Copyright (c) 2002 Richard Russon
 * Copyright (c) 2004 Yura Pakhuchiy
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

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "compat.h"

#include "attrib.h"
#include "attrlist.h"
#include "device.h"
#include "mft.h"
#include "debug.h"
#include "mst.h"
#include "volume.h"
#include "types.h"
#include "layout.h"
#include "inode.h"
#include "runlist.h"
#include "lcnalloc.h"
#include "dir.h"
#include "compress.h"
#include "bitmap.h"

ntfschar AT_UNNAMED[] = { const_cpu_to_le16('\0') };

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
s64 ntfs_get_attribute_value(const ntfs_volume *vol,
		const ATTR_RECORD *a, u8 *b)
{
	runlist *rl;
	s64 total, r;
	int i;

	/* Sanity checks. */
	if (!vol || !a || !b) {
		errno = EINVAL;
		return 0;
	}
	/* Complex attribute? */
	if (a->flags) {
		Dputs("Enountered non-zero attribute flags.  Cannot handle "
				"this yet.");
		errno = ENOTSUP;
		return 0;
	}
	if (!a->non_resident) {
		/* Attribute is resident. */

		/* Sanity check. */
		if (le32_to_cpu(a->value_length) + le16_to_cpu(a->value_offset)
				> le32_to_cpu(a->length)) {
			return 0;
		}

		memcpy(b, (const char*)a + le16_to_cpu(a->value_offset),
				le32_to_cpu(a->value_length));
		errno = 0;
		return (s64)le32_to_cpu(a->value_length);
	}

	/* Attribute is not resident. */

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
	 * FIXED2:  We were also overflowing here in the same fashion
	 * when the data_size was more than one run smaller than the
	 * allocated size which happens with Windows XP sometimes.
	 */
	/* Now load all clusters in the runlist into b. */
	for (i = 0, total = 0; rl[i].length; i++) {
		if (total + (rl[i].length << vol->cluster_size_bits) >=
				sle64_to_cpu(a->data_size)) {
			unsigned char *intbuf = NULL;
			/*
			 * We have reached the last run so we were going to
			 * overflow when executing the ntfs_pread() which is
			 * BAAAAAAAD!
			 * Temporary fix:
			 *	Allocate a new buffer with size:
			 *	rl[i].length << vol->cluster_size_bits, do the
			 *	read into our buffer, then memcpy the correct
			 *	amount of data into the caller supplied buffer,
			 *	free our buffer, and continue.
			 * We have reached the end of data size so we were
			 * going to overflow in the same fashion.
			 * Temporary fix:  same as above.
			 */
			intbuf = malloc(rl[i].length << vol->cluster_size_bits);
			if (!intbuf) {
				int eo = errno;
				perror("Couldn't allocate memory for internal "
						"buffer.\n");
				free(rl);
				errno = eo;
				return 0;
			}
			/*
			 * FIXME: If compressed file: Only read if lcn != -1.
			 * Otherwise, we are dealing with a sparse run and we
			 * just memset the user buffer to 0 for the length of
			 * the run, which should be 16 (= compression unit
			 * size).
			 * FIXME: Really only when file is compressed, or can
			 * we have sparse runs in uncompressed files as well?
			 * - Yes we can, in sparse files! But not necessarily
			 * size of 16, just run length.
			 */
			r = ntfs_pread(vol->dev, rl[i].lcn <<
					vol->cluster_size_bits, rl[i].length <<
					vol->cluster_size_bits, intbuf);
			if (r != rl[i].length << vol->cluster_size_bits) {
#define ESTR "Error reading attribute value"
				if (r == -1) {
					int eo = errno;
					perror(ESTR);
					errno = eo;
				} else if (r < rl[i].length <<
						vol->cluster_size_bits) {
					Dputs(ESTR ": Ran out of input data.");
					errno = EIO;
				} else {
					Dputs(ESTR ": unknown error");
					errno = EIO;
				}
#undef ESTR
				free(rl);
				free(intbuf);
				return 0;
			}
			memcpy(b + total, intbuf, sle64_to_cpu(a->data_size) -
					total);
			free(intbuf);
			total = sle64_to_cpu(a->data_size);
			break;
		}
		/*
		 * FIXME: If compressed file: Only read if lcn != -1.
		 * Otherwise, we are dealing with a sparse run and we just
		 * memset the user buffer to 0 for the length of the run, which
		 * should be 16 (= compression unit size).
		 * FIXME: Really only when file is compressed, or can
		 * we have sparse runs in uncompressed files as well?
		 * - Yes we can, in sparse files! But not necessarily size of
		 * 16, just run length.
		 */
		r = ntfs_pread(vol->dev, rl[i].lcn << vol->cluster_size_bits,
				rl[i].length << vol->cluster_size_bits,
				b + total);
		if (r != rl[i].length << vol->cluster_size_bits) {
#define ESTR "Error reading attribute value"
			if (r == -1) {
				int eo = errno;
				perror(ESTR);
				errno = eo;
			} else if (r < rl[i].length << vol->cluster_size_bits) {
				Dputs(ESTR ": Ran out of input data.");
				errno = EIO;
			} else {
				Dputs(ESTR ": unknown error");
				errno = EIO;
			}
#undef ESTR
			return 0;
		}
		total += r;
	}
	free(rl);
	return total;
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
		const ATTR_TYPES type, ntfschar *name, const u32 name_len)
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
 * @name:	attribute name in little endian Unicode or AT_UNNAMED or NULL
 * @name_len:	length of attribute @name in Unicode characters (if @name given)
 *
 * Allocate a new ntfs attribute structure, initialize it with @ni, @type,
 * @name, and @name_len, then return it. Return NULL on error with
 * errno set to the error code.
 *
 * If @name is AT_UNNAMED look specifically for an unnamed attribute.  If you
 * do not care whether the attribute is named or not set @name to NULL.  In
 * both those cases @name_len is not used at all.
 */
ntfs_attr *ntfs_attr_open(ntfs_inode *ni, const ATTR_TYPES type,
		ntfschar *name, const u32 name_len)
{
	ntfs_attr_search_ctx *ctx;
	ntfs_attr *na;
	ATTR_RECORD *a;
	int err;
	BOOL cs;

	Dprintf("%s(): Entering for inode 0x%llx, attr 0x%x.\n", __FUNCTION__,
			(unsigned long long)ni->mft_no, type);
	if (!ni || !ni->vol || !ni->mrec) {
		errno = EINVAL;
		return NULL;
	}
	na = calloc(sizeof(ntfs_attr), 1);
	if (!na)
		return NULL;
	if (name && name != AT_UNNAMED && name != I30) {
		name = ntfs_ucsndup(name, name_len);
		if (!name) {
			err = errno;
			free(na);
			errno = err;
			return NULL;
		}
	}
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
	cs = a->flags & (ATTR_IS_COMPRESSED | ATTR_IS_SPARSE);
	if (a->non_resident) {
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
		ntfs_attr_init(na, FALSE, a->flags & ATTR_IS_COMPRESSED,
				a->flags & ATTR_IS_ENCRYPTED,
				a->flags & ATTR_IS_SPARSE, l, l, l,
				cs ? sle64_to_cpu(a->compressed_size) : 0,
				cs ? a->compression_unit : 0);
	}
	ntfs_attr_put_search_ctx(ctx);
	return na;
put_err_out:
	ntfs_attr_put_search_ctx(ctx);
err_out:
	free(na);
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
	if (!na)
		return;
	if (NAttrNonResident(na) && na->rl)
		free(na->rl);
	/* Don't release if using an internal constant. */
	if (na->name != AT_UNNAMED && na->name != I30)
		free(na->name);
	free(na);
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
	LCN lcn;
	ntfs_attr_search_ctx *ctx;
	int err;

	Dprintf("%s(): Entering for inode 0x%llx, attr 0x%x, vcn 0x%llx.\n",
			__FUNCTION__, (unsigned long long)na->ni->mft_no,
			na->type, (long long)vcn);
	
	lcn = ntfs_rl_vcn_to_lcn(na->rl, vcn);
	if (lcn >= 0 || lcn == LCN_HOLE || lcn == LCN_ENOENT)
		return 0;

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
 * ntfs_attr_map_whole_runlist - map the whole runlist of an ntfs attribute
 * @na:		ntfs attribute for which to map the runlist
 *
 * Map the whole runlist of an the ntfs attribute @na.  For an attribute made
 * up of only one attribute extent this is the same as calling
 * ntfs_attr_map_runlist(na, 0) but for an attribute with multiple extents this
 * will map the runlist fragments from each of the extents thus giving access
 * to the entirety of the disk allocation of an attribute.
 *
 * Return 0 on success and -1 on error with errno set to the error code.
 */
int ntfs_attr_map_whole_runlist(ntfs_attr *na)
{
	VCN next_vcn, last_vcn, highest_vcn;
	ntfs_attr_search_ctx *ctx;
	ntfs_volume *vol = na->ni->vol;
	ATTR_RECORD *a;
	int err;

	Dprintf("%s(): Entering for inode 0x%llx, attr 0x%x.\n", __FUNCTION__,
			(unsigned long long)na->ni->mft_no, na->type);

	ctx = ntfs_attr_get_search_ctx(na->ni, NULL);
	if (!ctx)
		return -1;

	/* Map all attribute extents one by one. */
	next_vcn = last_vcn = highest_vcn = 0;
	a = NULL;
	while (1) {
		runlist_element *rl;
		
		int not_mapped = 0;
		if (ntfs_rl_vcn_to_lcn(na->rl, next_vcn) == LCN_RL_NOT_MAPPED)
			not_mapped = 1;

		if (ntfs_attr_lookup(na->type, na->name, na->name_len,
				CASE_SENSITIVE, next_vcn, NULL, 0, ctx))
			break;

		a = ctx->attr;

		if (not_mapped) {
			/* Decode the runlist. */
			rl = ntfs_mapping_pairs_decompress(na->ni->vol,
								a, na->rl);
			if (!rl)
				goto err_out;
			na->rl = rl;
		}

		/* Are we in the first extent? */
		if (!next_vcn) {
			 if (a->lowest_vcn) {
				Dprintf("%s(): First extent of attribute "
						"has non zero lowest_vcn. "
						"Inode is corrupt.\n",
						__FUNCTION__);
				errno = EIO;
				goto err_out;
			}
			/* Get the last vcn in the attribute. */
			last_vcn = sle64_to_cpu(a->allocated_size) >>
					vol->cluster_size_bits;
		}

		/* Get the lowest vcn for the next extent. */
		highest_vcn = sle64_to_cpu(a->highest_vcn);
		next_vcn = highest_vcn + 1;

		/* Only one extent or error, which we catch below. */
		if (next_vcn <= 0) {
			errno = ENOENT;
			break;
		}

		/* Avoid endless loops due to corruption. */
		if (next_vcn < sle64_to_cpu(a->lowest_vcn)) {
			Dprintf("%s(): Inode has corrupt attribute list "
					"attribute.\n", __FUNCTION__);
			errno = EIO;
			goto err_out;
		}
	}
	if (!a) {
		err = errno;
		if (err == ENOENT)
			Dprintf("%s(): Attribute not found. Inode is "
					"corrupt.\n", __FUNCTION__);
		else
			Dprintf("%s(): Inode is corrupt.\n", __FUNCTION__);
		errno = err;
		goto err_out;
	}
	if (highest_vcn && highest_vcn != last_vcn - 1) {
		Dprintf("%s(): Failed to load the complete run list for the "
				"attribute. Bug or corrupt inode.\n",
				__FUNCTION__);
		Dprintf("%s(): highest_vcn = 0x%llx, last_vcn - 1 = 0x%llx\n",
				__FUNCTION__, (long long)highest_vcn,
				(long long)last_vcn - 1);
		errno = EIO;
		goto err_out;
	}
	err = errno;
	ntfs_attr_put_search_ctx(ctx);
	if (err == ENOENT)
		return 0;
out_now:
	errno = err;
	return -1;
err_out:
	err = errno;
	ntfs_attr_put_search_ctx(ctx);
	goto out_now;
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
 * lower than @count this means that the read reached end of file or that an
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

	Dprintf("%s(): Entering for inode 0x%llx, attr 0x%x, pos 0x%llx, "
			"count 0x%llx.\n", __FUNCTION__,
			(unsigned long long)na->ni->mft_no, na->type,
			(long long)pos, (long long)count);
	if (!na || !na->ni || !na->ni->vol || !b || pos < 0 || count < 0) {
		errno = EINVAL;
		return -1;
	}
	/*
	 * If this is a compressed attribute it needs special treatment, but
	 * only if it is non-resident.
	 */
	if (NAttrCompressed(na) && NAttrNonResident(na))
		return ntfs_compressed_attr_pread(na, pos, count, b);
	/*
	 * Encrypted non-resident attributes are not supported.  We return
	 * access denied, which is what Windows NT4 does, too.
	 */
	if (NAttrEncrypted(na) && NAttrNonResident(na)) {
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
	vol = na->ni->vol;
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
			b = (u8*)b + to_read;
			continue;
		}
		/* It is a real lcn, read it into @dst. */
		to_read = min(count, (rl->length << vol->cluster_size_bits) -
				ofs);
retry:
		Dprintf("%s(): Reading 0x%llx bytes from vcn 0x%llx, lcn 0x%llx, "
				"ofs 0x%llx.\n", __FUNCTION__, to_read,
				rl->vcn, rl->lcn, ofs);
		br = ntfs_pread(vol->dev, (rl->lcn << vol->cluster_size_bits) +
				ofs, to_read, b);
		/* If everything ok, update progress counters and continue. */
		if (br > 0) {
			total += br;
			count -= br;
			b = (u8*)b + br;
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
	int eo;
	struct {
		unsigned int initialized_size	: 1;
	} need_to_undo = { 0 };

	Dprintf("%s(): Entering for inode 0x%llx, attr 0x%x, pos 0x%llx, "
			"count 0x%llx.\n", __FUNCTION__, na->ni->mft_no,
			na->type, (long long)pos, (long long)count);
	if (!na || !na->ni || !na->ni->vol || !b || pos < 0 || count < 0) {
		errno = EINVAL;
		return -1;
	}
	vol = na->ni->vol;
	/*
	 * Encrypted non-resident attributes are not supported.  We return
	 * access denied, which is what Windows NT4 does, too.
	 */
	if (NAttrEncrypted(na) && NAttrNonResident(na)) {
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
			b = (u8*)b + to_write;
			continue;
		}
		/* It is a real lcn, write it to the volume. */
		to_write = min(count, (rl->length << vol->cluster_size_bits) -
				ofs);
retry:
		Dprintf("%s(): Writing 0x%llx bytes to vcn 0x%llx, lcn 0x%llx, "
				"ofs 0x%llx.\n", __FUNCTION__, to_write,
				rl->vcn, rl->lcn, ofs);
		if (!NVolReadOnly(vol))
			written = ntfs_pwrite(vol->dev, (rl->lcn <<
					vol->cluster_size_bits) + ofs,
					to_write, b);
		else
			written = to_write;
		/* If everything ok, update progress counters and continue. */
		if (written > 0) {
			total += written;
			count -= written;
			b = (u8*)b + written;
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

	Dprintf("%s(): Entering for inode 0x%llx, attr type 0x%x, pos 0x%llx.\n",
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
	for (end = (u8*)b + br * bk_size; (u8*)b < end; b = (u8*)b + bk_size)
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

	Dprintf("%s(): Entering for inode 0x%llx, attr type 0x%x, pos 0x%llx.\n",
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
 * returns 0 and @ctx->attr will point to the found attribute.
 *
 * If not found, ntfs_attr_find() returns -1, with errno set to ENOENT and
 * @ctx->attr will point to the attribute before which the attribute being
 * searched for would need to be inserted if such an action were to be desired.
 *
 * On actual error, ntfs_attr_find() returns -1 with errno set to the error
 * code but not to ENOENT.  In this case @ctx->attr is undefined and in
 * particular do not rely on it not changing.
 *
 * If @ctx->is_first is TRUE, the search begins with @ctx->attr itself. If it
 * is FALSE, the search begins after @ctx->attr.
 *
 * If @type is AT_UNUSED, return the first found attribute, i.e. one can
 * enumerate all attributes by setting @type to AT_UNUSED and then calling
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
static int ntfs_attr_find(const ATTR_TYPES type, const ntfschar *name,
		const u32 name_len, const IGNORE_CASE_BOOL ic,
		const u8 *val, const u32 val_len, ntfs_attr_search_ctx *ctx)
{
	ATTR_RECORD *a;
	ntfs_volume *vol;
	ntfschar *upcase;
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
		if (((type != AT_UNUSED) && (le32_to_cpu(a->type) >
				le32_to_cpu(type))) ||
				(a->type == AT_END)) {
			errno = ENOENT;
			return -1;
		}
		if (!a->length)
			break;
		/* If this is an enumeration return this attribute. */
		if (type == AT_UNUSED)
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
			    (ntfschar*)((char*)a + le16_to_cpu(a->name_offset)),
			    a->name_length, ic, upcase, upcase_len)) {
			register int rc;

			rc = ntfs_names_collate(name, name_len,
					(ntfschar*)((char*)a +
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
					(ntfschar*)((char*)a +
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
 * If @type is AT_UNUSED, return the first found attribute, i.e. one can
 * enumerate all attributes by setting @type to AT_UNUSED and then calling
 * ntfs_external_attr_find() repeatedly until it returns -1 with errno set to
 * ENOENT to indicate that there are no more entries. During the enumeration,
 * each successful call of ntfs_external_attr_find() will return the next
 * attribute described by the attribute list of the base mft record described
 * by the search context @ctx.
 *
 * If @type is AT_END, seek to the end of the base mft record ignoring the
 * attribute list completely and return -1 with errno set to ENOENT.  AT_END is
 * not a valid attribute, its length is zero for example, thus it is safer to
 * return error instead of success in this case.
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
 * On success, @ctx->attr is the found attribute, it is in mft record
 * @ctx->mrec, and @ctx->al_entry is the attribute list entry for this
 * attribute with @ctx->base_* being the base mft record to which @ctx->attr
 * belongs.
 *
 * On error ENOENT, i.e. attribute not found, @ctx->attr is set to the
 * attribute which collates just after the attribute being searched for in the
 * base ntfs inode, i.e. if one wants to add the attribute to the mft record
 * this is the correct place to insert it into, and if there is not enough
 * space, the attribute should be placed in an extent mft record.
 * @ctx->al_entry points to the position within @ctx->base_ntfs_ino->attr_list
 * at which the new attribute's attribute list entry should be inserted.  The
 * other @ctx fields, base_ntfs_ino, base_mrec, and base_attr are set to NULL.
 * The only exception to this is when @type is AT_END, in which case
 * @ctx->al_entry is set to NULL also (see above).
 *
 * The following error codes are defined:
 *	ENOENT	Attribute not found, not an error as such.
 *	EINVAL	Invalid arguments.
 *	EIO	I/O error or corrupt data structures found.
 *	ENOMEM	Not enough memory to allocate necessary buffers.
 */
static int ntfs_external_attr_find(ATTR_TYPES type, const ntfschar *name,
		const u32 name_len, const IGNORE_CASE_BOOL ic,
		const VCN lowest_vcn, const u8 *val, const u32 val_len,
		ntfs_attr_search_ctx *ctx)
{
	ntfs_inode *base_ni, *ni;
	ntfs_volume *vol;
	ATTR_LIST_ENTRY *al_entry, *next_al_entry;
	char *al_start, *al_end;
	ATTR_RECORD *a;
	ntfschar *al_name;
	u32 al_name_len;
	BOOL is_first_search = FALSE;

	ni = ctx->ntfs_ino;
	base_ni = ctx->base_ntfs_ino;
	Dprintf("%s(): Entering for inode 0x%llx, attribute type 0x%x.\n",
			__FUNCTION__, (unsigned long long)ni->mft_no, type);
	if (!base_ni) {
		/* First call happens with the base mft record. */
		base_ni = ctx->base_ntfs_ino = ctx->ntfs_ino;
		ctx->base_mrec = ctx->mrec;
	}
	if (ni == base_ni)
		ctx->base_attr = ctx->attr;
	if (type == AT_END)
		goto not_found;
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
		if ((type == AT_UNUSED) && is_first_search &&
				le16_to_cpu(al_entry->type) >
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
		if ((type == AT_UNUSED) && le16_to_cpu(ctx->al_entry->type) <
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
			if (errno != ENOENT)
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
		if (type != AT_UNUSED) {
			if (le32_to_cpu(al_entry->type) > le32_to_cpu(type))
				goto not_found;
			if (type != al_entry->type)
				continue;
		}
		al_name_len = al_entry->name_length;
		al_name = (ntfschar*)((char*)al_entry + al_entry->name_offset);
		/*
		 * If !@type we want the attribute represented by this
		 * attribute list entry.
		 */
		if (type == AT_UNUSED)
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
					lowest_vcn			    &&
				next_al_entry->type == al_entry->type	    &&
				next_al_entry->name_length == al_name_len   &&
				ntfs_names_are_equal((ntfschar*)((char*)
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
		if (!ntfs_names_are_equal((ntfschar*)((char*)a +
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
		if ((type == AT_UNUSED) || !val || (!a->non_resident &&
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
	 * If we were looking for AT_END or we were enumerating and reached the
	 * end, we reset the search context @ctx and use ntfs_attr_find() to
	 * seek to the end of the base mft record.
	 */
	if (type == AT_UNUSED || type == AT_END) {
		ntfs_attr_reinit_search_ctx(ctx);
		return ntfs_attr_find(AT_END, name, name_len, ic, val, val_len,
				ctx);
	}
	/*
	 * The attribute wasn't found.  Before we return, we want to ensure
	 * @ctx->mrec and @ctx->attr indicate the position at which the
	 * attribute should be inserted in the base mft record.  Since we also
	 * want to preserve @ctx->al_entry we cannot reinitialize the search
	 * context using ntfs_attr_reinit_search_ctx() as this would set
	 * @ctx->al_entry to NULL.  Thus we do the necessary bits manually (see
	 * ntfs_attr_init_search_ctx() below).  Note, we _only_ preserve
	 * @ctx->al_entry as the remaining fields (base_*) are identical to
	 * their non base_ counterparts and we cannot set @ctx->base_attr
	 * correctly yet as we do not know what @ctx->attr will be set to by
	 * the call to ntfs_attr_find() below.
	 */
	ctx->mrec = ctx->base_mrec;
	ctx->attr = (ATTR_RECORD*)((u8*)ctx->mrec +
			le16_to_cpu(ctx->mrec->attrs_offset));
	ctx->is_first = TRUE;
	ctx->ntfs_ino = ctx->base_ntfs_ino;
	ctx->base_ntfs_ino = NULL;
	ctx->base_mrec = NULL;
	ctx->base_attr = NULL;
	/*
	 * In case there are multiple matches in the base mft record, need to
	 * keep enumerating until we get an attribute not found response (or
	 * another error), otherwise we would keep returning the same attribute
	 * over and over again and all programs using us for enumeration would
	 * lock up in a tight loop.
	 */
	{
		int ret;

		do {
			ret = ntfs_attr_find(type, name, name_len, ic, val,
					val_len, ctx);
		} while (!ret);
		return ret;
	}
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
 * If @type is AT_UNUSED, return the first found attribute, i.e. one can
 * enumerate all attributes by setting @type to AT_UNUSED and then calling
 * ntfs_attr_lookup() repeatedly until it returns -1 with errno set to ENOENT
 * to indicate that there are no more entries. During the enumeration, each
 * successful call of ntfs_attr_lookup() will return the next attribute, with
 * the current attribute being described by the search context @ctx.
 *
 * If @type is AT_END, seek to the end of the base mft record ignoring the
 * attribute list completely and return -1 with errno set to ENOENT.  AT_END is
 * not a valid attribute, its length is zero for example, thus it is safer to
 * return error instead of success in this case.  It should never ne needed to
 * do this, but we implement the functionality because it allows for simpler
 * code inside ntfs_external_attr_find().
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
 * On success, @ctx->attr is the found attribute, it is in mft record
 * @ctx->mrec, and @ctx->al_entry is the attribute list entry for this
 * attribute with @ctx->base_* being the base mft record to which @ctx->attr
 * belongs.  If no attribute list attribute is present @ctx->al_entry and
 * @ctx->base_* are NULL.
 *
 * On error ENOENT, i.e. attribute not found, @ctx->attr is set to the
 * attribute which collates just after the attribute being searched for in the
 * base ntfs inode, i.e. if one wants to add the attribute to the mft record
 * this is the correct place to insert it into, and if there is not enough
 * space, the attribute should be placed in an extent mft record.
 * @ctx->al_entry points to the position within @ctx->base_ntfs_ino->attr_list
 * at which the new attribute's attribute list entry should be inserted.  The
 * other @ctx fields, base_ntfs_ino, base_mrec, and base_attr are set to NULL.
 * The only exception to this is when @type is AT_END, in which case
 * @ctx->al_entry is set to NULL also (see above).
 *
 *
 * The following error codes are defined:
 *	ENOENT	Attribute not found, not an error as such.
 *	EINVAL	Invalid arguments.
 *	EIO	I/O error or corrupt data structures found.
 *	ENOMEM	Not enough memory to allocate necessary buffers.
 */
int ntfs_attr_lookup(const ATTR_TYPES type, const ntfschar *name,
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
	ctx->attr = (ATTR_RECORD*)((u8*)mrec + le16_to_cpu(mrec->attrs_offset));
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
		ctx->attr = (ATTR_RECORD*)((u8*)ctx->mrec +
				le16_to_cpu(ctx->mrec->attrs_offset));
		return;
	} /* Attribute list. */
	ntfs_attr_init_search_ctx(ctx, ctx->base_ntfs_ino, ctx->base_mrec);
	return;
}

/**
 * ntfs_attr_get_search_ctx - allocate/initialize a new attribute search context
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
 * ntfs_attr_find_in_attrdef - find an attribute in the $AttrDef system file
 * @vol:	ntfs volume to which the attribute belongs
 * @type:	attribute type which to find
 *
 * Search for the attribute definition record corresponding to the attribute
 * @type in the $AttrDef system file.
 *
 * Return the attribute type definition record if found and NULL if not found
 * or an error occured. On error the error code is stored in errno. The
 * following error codes are defined:
 *	ENOENT	- The attribute @type is not specified in $AttrDef.
 *	EINVAL	- Invalid parameters (e.g. @vol is not valid).
 */
ATTR_DEF *ntfs_attr_find_in_attrdef(const ntfs_volume *vol,
		const ATTR_TYPES type)
{
	ATTR_DEF *ad;

	if (!vol || !vol->attrdef || !type) {
		errno = EINVAL;
		return NULL;
	}
	for (ad = vol->attrdef; (u8*)ad - (u8*)vol->attrdef <
			vol->attrdef_len && ad->type; ++ad) {
		/* We haven't found it yet, carry on searching. */
		if (le32_to_cpu(ad->type) < le32_to_cpu(type))
			continue;
		/* We found the attribute; return it. */
		if (ad->type == type)
			return ad;
		/* We have gone too far already. No point in continuing. */
		break;
	}
	/* Attribute not found?!? */
	errno = ENOENT;
	return NULL;
}

/**
 * ntfs_attr_size_bounds_check - check a size of an attribute type for validity
 * @vol:	ntfs volume to which the attribute belongs
 * @type:	attribute type which to check
 * @size:	size which to check
 *
 * Check whether the @size in bytes is valid for an attribute of @type on the
 * ntfs volume @vol. This information is obtained from $AttrDef system file.
 *
 * Return 0 if valid and -1 if not valid or an error occured. On error the
 * error code is stored in errno. The following error codes are defined:
 *	ERANGE	- @size is not valid for the attribute @type.
 *	ENOENT	- The attribute @type is not specified in $AttrDef.
 *	EINVAL	- Invalid parameters (e.g. @size is < 0 or @vol is not valid).
 */
int ntfs_attr_size_bounds_check(const ntfs_volume *vol, const ATTR_TYPES type,
		const s64 size)
{
	ATTR_DEF *ad;

	if (size < 0) {
		errno = EINVAL;
		return -1;
	}
	ad = ntfs_attr_find_in_attrdef(vol, type);
	if (!ad)
		return -1;
	/* We found the attribute. - Do the bounds check. */
	if ((sle64_to_cpu(ad->min_size) && size <
			sle64_to_cpu(ad->min_size)) ||
			((sle64_to_cpu(ad->max_size) > 0) && size >
			sle64_to_cpu(ad->max_size))) {
		/* @size is out of range! */
		errno = ERANGE;
		return -1;
	}
	return 0;
}

/**
 * ntfs_attr_can_be_non_resident - check if an attribute can be non-resident
 * @vol:	ntfs volume to which the attribute belongs
 * @type:	attribute type which to check
 *
 * Check whether the attribute of @type on the ntfs volume @vol is allowed to
 * be non-resident. This information is obtained from $AttrDef system file.
 *
 * Return 0 if the attribute is allowed to be non-resident and -1 if not or an
 * error occured. On error the error code is stored in errno. The following
 * error codes are defined:
 *	EPERM	- The attribute is not allowed to be non-resident.
 *	ENOENT	- The attribute @type is not specified in $AttrDef.
 *	EINVAL	- Invalid parameters (e.g. @vol is not valid).
 */
int ntfs_attr_can_be_non_resident(const ntfs_volume *vol, const ATTR_TYPES type)
{
	ATTR_DEF *ad;

	/*
	 * $DATA is always allowed to be non-resident even if $AttrDef does not
	 * specify this in the flags of the $DATA attribute definition record.
	 */
	if (type == AT_DATA)
		return 0;
	/* Find the attribute definition record in $AttrDef. */
	ad = ntfs_attr_find_in_attrdef(vol, type);
	if (!ad)
		return -1;
	/* Check the flags and return the result. */
	if (ad->flags & CAN_BE_NON_RESIDENT)
		return 0;
	errno = EPERM;
	return -1;
}

/**
 * ntfs_attr_can_be_resident - check if an attribute can be resident
 * @vol:	ntfs volume to which the attribute belongs
 * @type:	attribute type which to check
 *
 * Check whether the attribute of @type on the ntfs volume @vol is allowed to
 * be resident. This information is derived from our ntfs knowledge and may
 * not be completely accurate, especially when user defined attributes are
 * present. Basically we allow everything to be resident except for index
 * allocation and extended attribute attributes.
 *
 * Return 0 if the attribute is allowed to be resident and -1 if not or an
 * error occured. On error the error code is stored in errno. The following
 * error codes are defined:
 *	EPERM	- The attribute is not allowed to be resident.
 *	EINVAL	- Invalid parameters (e.g. @vol is not valid).
 *
 * Warning: In the system file $MFT the attribute $Bitmap must be non-resident
 *	    otherwise windows will not boot (blue screen of death)!  We cannot
 *	    check for this here as we don't know which inode's $Bitmap is being
 *	    asked about so the caller needs to special case this.
 */
int ntfs_attr_can_be_resident(const ntfs_volume *vol, const ATTR_TYPES type)
{
	if (!vol || !vol->attrdef || !type) {
		errno = EINVAL;
		return -1;
	}
	if (type != AT_INDEX_ALLOCATION && type != AT_EA)
		return 0;
	errno = EPERM;
	return -1;
}

/**
 * ntfs_make_room_for_attr - make room for an attribute inside an mft record
 * @m:		mft record
 * @pos:	position at which to make space
 * @size:	byte size to make available at this position
 *
 * @pos points to the attribute in front of which we want to make space.
 *
 * Return 0 on success or -1 on error. On error the error code is stored in
 * errno. Possible error codes are:
 *	ENOSPC	- There is not enough space available to complete operation. The
 *		  caller has to make space before calling this.
 *	EINVAL	- Input parameters were faulty.
 */
int ntfs_make_room_for_attr(MFT_RECORD *m, u8 *pos, u32 size)
{
	u32 biu;
	
	Dprintf("%s(): Entering for pos 0x%d, size %u.\n",
		 __FUNCTION__, (int)(pos - (u8*)m), (unsigned) size);

	/* Make size 8-byte aligment. */
	size = (size + 7) & ~7;

	/* Rigorous consistency checks. */
	if (!m || !pos || pos < (u8*)m || pos + size >
			(u8*)m + le32_to_cpu(m->bytes_allocated)) {
		errno = EINVAL;
		return -1;
	}
	/* The -8 is for the attribute terminator. */
	if (pos - (u8*)m > (int)le32_to_cpu(m->bytes_in_use) - 8) {
		errno = EINVAL;
		return -1;
	}
	/* Nothing to do. */
	if (!size)
		return 0;

	biu = le32_to_cpu(m->bytes_in_use);
	/* Do we have enough space? */
	if (biu + size > le32_to_cpu(m->bytes_allocated)) {
		errno = ENOSPC;
		return -1;
	}
	/* Move everything after pos to pos + size. */
	memmove(pos + size, pos, biu - (pos - (u8*)m));
	/* Update mft record. */
	m->bytes_in_use = cpu_to_le32(biu + size);
	return 0;
}

/**
 * ntfs_resident_attr_record_add - add resident attribute to inode
 * @ni:		opened ntfs inode to which MFT record add attribute
 * @type:	type of the new attribute
 * @name:	name of the new attribute
 * @name_len:	name length of the new attribute
 * @flags:	flags of the new attribute
 *
 * Return offset to attribute from the beginning of the mft record on success
 * and -1 on error. On error the error code is stored in errno.
 * Possible error codes are:
 *	EINVAL	- Invalid argumets passed to function.
 *	EEXIST	- Attribute of such type and with same name already exists.
 *	EIO	- I/O error occured or damaged filesystem.
 */
int ntfs_resident_attr_record_add(ntfs_inode *ni, ATTR_TYPES type,
			ntfschar *name, u8 name_len, ATTR_FLAGS flags)
{
	ntfs_attr_search_ctx *ctx;
	u32 length;
	ATTR_RECORD *a;
	MFT_RECORD *m;
	int err, offset;
	ntfs_inode *base_ni;
	
	Dprintf("%s(): Entering for inode 0x%llx, attr 0x%x, flags 0x%x.\n",
		 __FUNCTION__, (long long) ni->mft_no, (unsigned) type,
		(unsigned) flags);
	
	if (!ni || (!name && name_len)) {
		errno = EINVAL;
		return -1;
	}
	
	if (ntfs_attr_can_be_resident(ni->vol, type)) {
		err = errno;
		if (errno == EPERM)
			Dprintf("%s(): Attribute can't be resident.\n",
				__FUNCTION__);
		else
			Dprintf("%s(): ntfs_attr_can_be_resident failed.\n",
				__FUNCTION__);
		errno = err;
		return -1;
	}
	
	ctx = ntfs_attr_get_search_ctx(NULL, ni->mrec);
	if (!ctx)
		return -1;
	if (!ntfs_attr_lookup(type, name, name_len,
				CASE_SENSITIVE, 0, NULL, 0, ctx)) {
		err = EEXIST;
		Dprintf("%s(): Attribute already present.\n", __FUNCTION__);
		goto put_err_out;
	}
	if (errno != ENOENT) {
		err = EIO;
		goto put_err_out;
	}
	length = (0x18 + sizeof(ntfschar) * name_len + 7) & ~7;
	if (ntfs_make_room_for_attr(ctx->mrec, (u8*) ctx->attr, length)) {
		err = errno;
		Dprintf("%s(): Failed to make room for attribute.\n",
				__FUNCTION__);
		goto put_err_out;
	}
	a = ctx->attr;
	m = ctx->mrec;
	offset = ((u8*)a - (u8*)m);
	a->type = type;
	a->length = cpu_to_le32(length);
	a->non_resident = 0;
	a->name_length = name_len;
	a->name_offset = cpu_to_le16(0x18);
	a->flags = flags;
	a->instance = m->next_attr_instance;
	a->value_length = 0;
	a->value_offset = cpu_to_le16(length);
	a->resident_flags = 0;
	
	if (name_len)
		memcpy((u8*)a + le16_to_cpu(a->name_offset),
			name, sizeof(ntfschar) * name_len);
	m->next_attr_instance =
		cpu_to_le16((le16_to_cpu(m->next_attr_instance) + 1) & 0xffff);
	if (ni->nr_extents == -1)
		base_ni = ni->base_ni;
	else
		base_ni = ni;
	if (NInoAttrList(base_ni)) {
		if (ntfs_attrlist_entry_add(ni, a)) {
			err = errno;
			ntfs_attr_record_resize(m, a, 0);
			Dprintf("%s(): Failed add attribute entry to "
				"ATTRIBUTE_LIST.\n", __FUNCTION__);
			goto put_err_out;
		}
	}
	ntfs_inode_mark_dirty(ni);
	ntfs_attr_put_search_ctx(ctx);
	return offset;
put_err_out:
	ntfs_attr_put_search_ctx(ctx);
	errno = err;
	return -1;
}

/**
 * ntfs_non_resident_attr_record_add - add extent of non-resident attribute
 * @ni:			opened ntfs inode to which MFT record add attribute
 * @type:		type of the new attribute extent
 * @name:		name of the new attribute extent
 * @name_len:		name length of the new attribute extent
 * @lowest_vcn:		lowest vcn of the new attribute extent
 * @dataruns_size:	dataruns size of the new attribute extent
 * @flags:		flags of the new attribute extent
 *
 * Return offset to attribute from the beginning of the mft record on success
 * and -1 on error. On error the error code is stored in errno.
 * Possible error codes are:
 *	EINVAL	- Invalid argumets passed to function.
 *	EEXIST	- Attribute of such type, with same lowest vcn and with same
 *		  name already exists.
 *	EIO	- I/O error occured or damaged filesystem.
 */
int ntfs_non_resident_attr_record_add(ntfs_inode *ni, ATTR_TYPES type,
		ntfschar *name, u8 name_len, VCN lowest_vcn, int dataruns_size,
		ATTR_FLAGS flags)
{
	ntfs_attr_search_ctx *ctx;
	u32 length;
	ATTR_RECORD *a;
	MFT_RECORD *m;
	ntfs_inode *base_ni;
	int err, offset;
	
	Dprintf("%s(): Entering for inode 0x%llx, attr 0x%x, lowest_vcn %lld, "
		"dataruns_size %d, flags 0x%x.\n", __FUNCTION__,
		(long long) ni->mft_no, (unsigned) type, (long long) lowest_vcn,
		dataruns_size, (unsigned) flags);
	
	if (!ni || dataruns_size <= 0 || (!name && name_len)) {
		errno = EINVAL;
		return -1;
	}
	
	if (ntfs_attr_can_be_non_resident(ni->vol, type)) {
		err = errno;
		if (errno == EPERM)
			Dprintf("%s(): Attribute can't be non resident.\n",
				__FUNCTION__);
		else
			Dprintf("%s(): ntfs_attr_can_be_non_resident failed.\n",
				__FUNCTION__);
		errno = err;
		return -1;
	}
	
	dataruns_size = (dataruns_size + 7) & ~7;
	
	ctx = ntfs_attr_get_search_ctx(NULL, ni->mrec);
	if (!ctx)
		return -1;
	if (!ntfs_attr_lookup(type, name, name_len, CASE_SENSITIVE,
					lowest_vcn, NULL, 0, ctx)) {
		err = EEXIST;
		Dprintf("%s(): Attribute already present.\n", __FUNCTION__);
		goto put_err_out;
	}
	if (errno != ENOENT) {
		err = EIO;
		goto put_err_out;
	}
	length = 0x40 + sizeof(ntfschar) * name_len + dataruns_size;
	if (flags & ATTR_COMPRESSION_MASK)
		length += 8;
	if (ntfs_make_room_for_attr(ctx->mrec, (u8*) ctx->attr, length)) {
		err = errno;
		Dprintf("%s(): Failed to make room for attribute.\n",
				__FUNCTION__);
		goto put_err_out;
	}
	a = ctx->attr;
	m = ctx->mrec;
	offset = ((u8*)a - (u8*)m);
	a->type = type;
	a->length = cpu_to_le32((length + 7) & ~7);
	a->non_resident = 1;
	a->name_length = name_len;
	a->name_offset = cpu_to_le16(length - dataruns_size -
				sizeof(ntfschar) * name_len);
	a->flags = flags;
	a->instance = m->next_attr_instance;
	a->lowest_vcn = scpu_to_le64(lowest_vcn);
	a->mapping_pairs_offset = cpu_to_le16(length - dataruns_size);
	a->compression_unit = (flags & ATTR_COMPRESSION_MASK) ? 4 : 0;
	if (name_len)
		memcpy((u8*)a + le16_to_cpu(a->name_offset),
			name, sizeof(ntfschar) * name_len);
	m->next_attr_instance =
		cpu_to_le16((le16_to_cpu(m->next_attr_instance) + 1) & 0xffff);
	if (ni->nr_extents == -1)
		base_ni = ni->base_ni;
	else
		base_ni = ni;
	if (NInoAttrList(base_ni)) {
		if (ntfs_attrlist_entry_add(ni, a)) {
			err = errno;
			ntfs_attr_record_resize(m, a, 0);
			Dprintf("%s(): Failed add attribute entry to "
				"ATTRIBUTE_LIST.\n", __FUNCTION__);
			goto put_err_out;
		}
	}
	ntfs_inode_mark_dirty(ni);
	ntfs_attr_put_search_ctx(ctx);
	return offset;
put_err_out:
	ntfs_attr_put_search_ctx(ctx);
	errno = err;
	return -1;
}

/**
 * ntfs_attr_record_rm - remove attribute extent
 * @ctx:	search context describing the attrubute which should be removed
 *
 * User should reinit search context after use of this function if he/she wants
 * use it anymore.
 *
 * Return 0 on success and -1 on error. On error the error code is stored in
 * errno. Possible error codes are:
 *	EINVAL	- Invalid argumets passed to function.
 *	EIO	- I/O error occured or damaged filesystem.
 */
int ntfs_attr_record_rm(ntfs_attr_search_ctx *ctx) {
	ntfs_inode *base_ni, *ni;
	ATTR_TYPES type;
	int err;
	
	if (!ctx || !ctx->ntfs_ino || !ctx->mrec || !ctx->attr) {
		errno = EINVAL;
		return -1;
	}

	Dprintf("%s(): Entering for inode 0x%llx, attr 0x%x, lowest_vcn "
		"%lld.\n", __FUNCTION__, (long long) ctx->ntfs_ino->mft_no,
		(unsigned) le32_to_cpu(ctx->attr->type),
		(long long) sle64_to_cpu(ctx->attr->lowest_vcn));
	type = ctx->attr->type;
	ni = ctx->ntfs_ino;
	if (ctx->base_ntfs_ino)
		base_ni = ctx->base_ntfs_ino;
	else
		base_ni = ctx->ntfs_ino;
	/*
	 * Remove record from $ATTRIBUTE_LIST if present and we don't want
	 * delete $ATTRIBUTE_LIST itself.
	 */
	if (NInoAttrList(base_ni) && type != AT_ATTRIBUTE_LIST) {
		if (ntfs_attrlist_entry_rm(ctx)) {
			err = errno;
			Dprintf("%s(): Coudn't delete record from "
				"$ATTRIBUTE_LIST.\n",  __FUNCTION__);
			errno = err;
			return -1;
		}
	}
	if (ntfs_attr_record_resize(ctx->mrec, ctx->attr, 0)) {
		Dprintf("%s(): Coudn't remove attribute record. Bug or "
			"damaged MFT record.\n", __FUNCTION__);
		if (NInoAttrList(base_ni) && type != AT_ATTRIBUTE_LIST)
			if (ntfs_attrlist_entry_add(ni, ctx->attr))
				Dprintf("%s(): Rollback failed. Leaving "
					"inconsist metadata.\n", __FUNCTION__);
		err = EIO;
		return -1;
	}
	ntfs_inode_mark_dirty(ni);
	if (type == AT_ATTRIBUTE_LIST) {
		if (NInoAttrList(base_ni) && base_ni->attr_list)
			free(base_ni->attr_list);
		if (NInoAttrListNonResident(base_ni) && base_ni->attr_list_rl)
			free(base_ni->attr_list_rl);
		NInoClearAttrList(base_ni);
		NInoClearAttrListNonResident(base_ni);
		NInoAttrListClearDirty(base_ni);
	}
	if (le32_to_cpu(ctx->mrec->bytes_in_use) -
			le16_to_cpu(ctx->mrec->attrs_offset) == 8) {
		if (ntfs_mft_record_free(ni->vol, ni)) {
			// FIXME: We need rollback here.
			Dprintf("%s(): Coudn't free MFT record.\n",
					__FUNCTION__);
			errno = EIO;
			return -1;
		}
		/* Remove done if we freed base inode. */
		if (ni == base_ni)
			return 0;
	}
	if (type == AT_ATTRIBUTE_LIST || !NInoAttrList(base_ni))
		return 0;
	if (!ntfs_attrlist_need(base_ni)) {
		ntfs_attr_reinit_search_ctx(ctx);
		if (ntfs_attr_lookup(AT_ATTRIBUTE_LIST, NULL, 0, IGNORE_CASE,
				0, NULL, 0, ctx)) {
			/*
			 * FIXME: Should we succeed here? Definitely something
			 * goes wrong because NInoAttrList(base_ni) returned
			 * that we have got attribute list.
			 */
			Dprintf("%s(): Coudn't find attribute list. Succeed "
				"anyway.\n", __FUNCTION__);
			return 0;
		}
		if (ntfs_attr_record_rm(ctx)) {
			/*
			 * FIXME: Should we succeed here? BTW, chkdsk doesn't
			 * complain if it find MFT record with attribute list,
			 * but wothout extents.
			 */
			Dprintf("%s(): Coudn't remove attribute list. Succeed "
				"anyway.\n", __FUNCTION__);
			return 0;
		}
	}
	return 0;
}

/**
 * ntfs_attr_record_resize - resize an attribute record
 * @m:		mft record containing attribute record
 * @a:		attribute record to resize
 * @new_size:	new size in bytes to which to resize the attribute record @a
 *
 * Resize the attribute record @a, i.e. the resident part of the attribute, in
 * the mft record @m to @new_size bytes.
 *
 * Return 0 on success and -1 on error with errno set to the error code.
 * The following error codes are defined:
 *	ENOSPC	- Not enough space in the mft record @m to perform the resize.
 * Note that on error no modifications have been performed whatsoever.
 *
 * Warning: If you make a record smaller without having copied all the data you
 *	    are interested in the data may be overwritten!
 */
int ntfs_attr_record_resize(MFT_RECORD *m, ATTR_RECORD *a, u32 new_size)
{
	Dprintf("%s(): Entering for new_size %u.\n",
			__FUNCTION__, (unsigned) new_size);
	/* Align to 8 bytes, just in case the caller hasn't. */
	new_size = (new_size + 7) & ~7;
	/* If the actual attribute length has changed, move things around. */
	if (new_size != le32_to_cpu(a->length)) {
		u32 new_muse = le32_to_cpu(m->bytes_in_use) -
				le32_to_cpu(a->length) + new_size;
		/* Not enough space in this mft record. */
		if (new_muse > le32_to_cpu(m->bytes_allocated)) {
			errno = ENOSPC;
			return -1;
		}
		/* Move attributes following @a to their new location. */
		memmove((u8*)a + new_size, (u8*)a + le32_to_cpu(a->length),
				le32_to_cpu(m->bytes_in_use) - ((u8*)a -
				(u8*)m) - le32_to_cpu(a->length));
		/* Adjust @m to reflect the change in used space. */
		m->bytes_in_use = cpu_to_le32(new_muse);
		/* Adjust @a to reflect the new size. */
		if (new_size >= offsetof(ATTR_REC, length) + sizeof(a->length))
			a->length = cpu_to_le32(new_size);
	}
	return 0;
}

/**
 * ntfs_resident_attr_value_resize - resize the value of a resident attribute
 * @m:		mft record containing attribute record
 * @a:		attribute record whose value to resize
 * @new_size:	new size in bytes to which to resize the attribute value of @a
 *
 * Resize the value of the attribute @a in the mft record @m to @new_size bytes.
 * If the value is made bigger, the newly "allocated" space is cleared.
 *
 * Return 0 on success and -1 on error with errno set to the error code.
 * The following error codes are defined:
 *	ENOSPC	- Not enough space in the mft record @m to perform the resize.
 * Note that on error no modifications have been performed whatsoever.
 */
int ntfs_resident_attr_value_resize(MFT_RECORD *m, ATTR_RECORD *a,
		const u32 new_size)
{
	/*
	 * Check that the attribute name hasn't been placed after the
	 * attribute value/mapping pairs array. If it has we need to move it.
	 * TODO: Implement the move. For now just abort. (AIA)
	 */
	if (a->name_length) {
		BOOL move_name = FALSE;
		if (a->non_resident) {
			if (le16_to_cpu(a->name_offset) >=
					le16_to_cpu(a->mapping_pairs_offset))
				move_name = TRUE;
		} else {
			if (le16_to_cpu(a->name_offset) >=
					le16_to_cpu(a->value_offset))
				move_name = TRUE;
				
		}
		if (move_name) {
			// FIXME: Eeek!
			Dprintf("%s(): Eeek!  Name is placed after the %s.  "
					"Aborting...\n", __FUNCTION__,
					a->non_resident ? "mapping pairs array":
					"attribute value");
			errno = ENOTSUP;
			return -1;
		}
	}
	/* Resize the resident part of the attribute record. */
	if (ntfs_attr_record_resize(m, a, (le16_to_cpu(a->value_offset) +
			new_size + 7) & ~7) < 0) {
		if (errno != ENOSPC) {
			int eo = errno;
			// FIXME: Eeek!
			Dprintf("%s(): Eeek!  Attribute record resize failed.  "
					"Aborting...\n", __FUNCTION__);
			errno = eo;
		}
		return -1;
	}
	/*
	 * If we made the attribute value bigger, clear the area between the
	 * old size and @new_size.
	 */
	if (new_size > le32_to_cpu(a->value_length))
		memset((u8*)a + le16_to_cpu(a->value_offset) +
				le32_to_cpu(a->value_length), 0, new_size -
				le32_to_cpu(a->value_length));
	/* Finally update the length of the attribute value. */
	a->value_length = cpu_to_le32(new_size);
	return 0;
}

/**
 * ntfs_attr_make_non_resident - convert a resident to a non-resident attribute
 * @na:		open ntfs attribute to make non-resident
 * @ctx:	ntfs search context describing the attribute
 *
 * Convert a resident ntfs attribute to a non-resident one.
 *
 * Return 0 on success and -1 on error with errno set to the error code. The
 * following error codes are defined:
 *	EPERM	- The attribute is not allowed to be non-resident.
 *	TODO: others...
 *
 * NOTE to self: No changes in the attribute list are required to move from
 *		 a resident to a non-resident attribute.
 *
 * Warning: We do not set the inode dirty and we do not write out anything!
 *	    We expect the caller to do this as this is a fairly low level
 *	    function and it is likely there will be further changes made.
 */
static int ntfs_attr_make_non_resident(ntfs_attr *na,
		ntfs_attr_search_ctx *ctx)
{
	s64 new_allocated_size, bw;
	ntfs_volume *vol = na->ni->vol;
	ATTR_REC *a = ctx->attr;
	runlist *rl;
	int mp_size, mp_ofs, name_ofs, arec_size, err;

	/* Some preliminary sanity checking. */
	if (NAttrNonResident(na)) {
		// FIXME: Eeek!
		Dprintf("%s(): Eeek!  Trying to make non-resident attribute "
				"non-resident.  Aborting...\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	/* Check that the attribute is allowed to be non-resident. */
	if (ntfs_attr_can_be_non_resident(vol, na->type))
		return -1;

	/*
	 * Check that the attribute name hasn't been placed after the
	 * attribute value. If it has we need to move it.
	 * TODO: Implement the move. For now just abort. (AIA)
	 */
	if (a->name_length && le16_to_cpu(a->name_offset) >=
			le16_to_cpu(a->value_offset)) {
		// FIXME: Eeek!
		Dprintf("%s(): Eeek!  Name is placed after the attribute "
				"value.  Aborting...\n", __FUNCTION__);
		errno = ENOTSUP;
		return -1;
	}

	new_allocated_size = (le32_to_cpu(a->value_length) + vol->cluster_size
			- 1) & ~(vol->cluster_size - 1);

	if (new_allocated_size > 0) {
		/* Start by allocating clusters to hold the attribute value. */
		rl = ntfs_cluster_alloc(vol, new_allocated_size >>
				vol->cluster_size_bits, -1, DATA_ZONE, 0);
		if (!rl) {
			if (errno != ENOSPC) {
				int eo = errno;

				// FIXME: Eeek!
				Dprintf("%s(): Eeek!  Failed to allocate "
						"cluster(s).  Aborting...\n",
						__FUNCTION__);
				errno = eo;
			}
			return -1;
		}
	} else
		rl = NULL;
	/*
	 * Setup the in-memory attribute structure to be non-resident so that
	 * we can use ntfs_attr_pwrite().
	 */
	NAttrSetNonResident(na);
	na->rl = rl;
	na->allocated_size = new_allocated_size;
	na->data_size = na->initialized_size = le32_to_cpu(a->value_length);
	/*
	 * FIXME: For now just clear all of these as we don't support them when
	 * writing.
	 */
	NAttrClearCompressed(na);
	NAttrClearSparse(na);
	NAttrClearEncrypted(na);

	if (rl) {	
		/* Now copy the attribute value to the allocated cluster(s). */
		bw = ntfs_attr_pwrite(na, 0, le32_to_cpu(a->value_length),
				(u8*)a + le16_to_cpu(a->value_offset));
		if (bw != le32_to_cpu(a->value_length)) {
			err = errno;
			// FIXME: Eeek!
			Dprintf("Eeek!  Failed to write out attribute value "
					"(bw = %lli, errno = %i).  "
					"Aborting...\n", (long long)bw, err);
			if (bw >= 0)
				err = EIO;
			goto cluster_free_err_out;
		}
	}
	/* Determine the size of the mapping pairs array. */
	mp_size = ntfs_get_size_for_mapping_pairs(vol, rl, 0);
	if (mp_size < 0) {
		err = errno;
		// FIXME: Eeek!
		Dputs("Eeek!  Failed to get size for mapping pairs array.  "
				"Aborting...");
		goto cluster_free_err_out;
	}
	/* Calculate new offsets for the name and the mapping pairs array. */
	name_ofs = (sizeof(ATTR_REC) - sizeof(a->compressed_size) + 7) & ~7;
	mp_ofs = (name_ofs + a->name_length + 7) & ~7;
	/*
	 * Determine the size of the resident part of the non-resident
	 * attribute record. (Not compressed thus no compressed_size element
	 * present.)
	 */
	arec_size = (mp_ofs + mp_size + 7) & ~7;

	/* Sanity check. */
	if (a->name_length && (le16_to_cpu(a->name_offset) + a->name_length >
			arec_size)) {
		// FIXME: Eeek!
		Dprintf("%s(): Eeek!  Name exceeds new record size! "
				"Not supported.  Aborting...\n", __FUNCTION__);
		err = ENOTSUP;
		goto cluster_free_err_out;
	}

	/* Resize the resident part of the attribute record. */
	if (ntfs_attr_record_resize(ctx->mrec, a, arec_size) < 0) {
		err = errno;
		if (err != ENOSPC) {
			// FIXME: Eeek!
			Dprintf("%s(): Eeek!  Failed to resize attribute "
					"record.  Aborting...\n", __FUNCTION__);
		}
		goto cluster_free_err_out;
	}

	/*
	 * Convert the resident part of the attribute record to describe a
	 * non-resident attribute.
	 */
	a->non_resident = 1;

	/* Move the attribute name if it exists and update the offset. */
	if (a->name_length)
		memmove((u8*)a + name_ofs, (u8*)a + le16_to_cpu(a->name_offset),
				a->name_length * sizeof(ntfschar));
	a->name_offset = cpu_to_le16(name_ofs);

	/* Update the flags to match the in-memory ones. */
	a->flags &= ~(ATTR_IS_SPARSE | ATTR_IS_ENCRYPTED |
			ATTR_COMPRESSION_MASK);

	/* Setup the fields specific to non-resident attributes. */
	a->lowest_vcn = scpu_to_le64(0);
	a->highest_vcn = scpu_to_le64((new_allocated_size - 1) >>
						vol->cluster_size_bits);

	a->mapping_pairs_offset = cpu_to_le16(mp_ofs);

	a->compression_unit = 0;

	memset(&a->reserved1, 0, sizeof(a->reserved1));

	a->allocated_size = scpu_to_le64(new_allocated_size);
	a->data_size = a->initialized_size = scpu_to_le64(na->data_size);

	/* Generate the mapping pairs array in the attribute record. */
	if (ntfs_mapping_pairs_build(vol, (u8*)a + mp_ofs, arec_size - mp_ofs,
			rl, 0, NULL) < 0) {
		err = errno;
		// FIXME: Eeek! We need rollback! (AIA)
		Dprintf("%s(): Eeek!  Failed to build mapping pairs.  Leaving "
				"corrupt attribute record on disk.  "
				"In memory runlist is still intact!  Error "
				"code is %i.  FIXME:  Need to rollback "
				"instead!\n", __FUNCTION__, err);
		errno = err;
		return -1;
	}

	/* Done! */
	return 0;

cluster_free_err_out:
	if (rl && ntfs_cluster_free(vol, na, 0, -1) < 0)
		Dprintf("%s(): Eeek!  Failed to release allocated "
				"clusters in error code path.  Leaving "
				"inconsistent metadata...\n", __FUNCTION__);
	NAttrClearNonResident(na);
	na->allocated_size = na->data_size;
	na->rl = NULL;
	if (rl)
		free(rl);
	errno = err;
	return -1;
}

/**
 * ntfs_resident_attr_resize - resize a resident, open ntfs attribute
 * @na:		resident ntfs attribute to resize
 * @newsize:	new size (in bytes) to which to resize the attribute
 *
 * Change the size of a resident, open ntfs attribute @na to @newsize bytes.
 *
 * On success return 0 and on error return -1 with errno set to the error code.
 * The following error codes are defined:
 *	ENOTSUP	- The desired resize is not implemented yet.
 *	ENOMEM	- Not enough memory to complete operation.
 *	ERANGE	- @newsize is not valid for the attribute type of @na.
 *	ENOSPC  - There is no enogh space in base mft to resize $ATTRIBUTE_LIST.
 */
static int ntfs_resident_attr_resize(ntfs_attr *na, const s64 newsize)
{
	ntfs_attr_search_ctx *ctx;
	ntfs_volume *vol;
	int err;

	Dprintf("%s(): Entering for inode 0x%llx, attr 0x%x.\n", __FUNCTION__,
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
	vol = na->ni->vol;
	/*
	 * Check the attribute type and the corresponding minimum and maximum
	 * sizes against @newsize and fail if @newsize is out of bounds.
	 */
	if (ntfs_attr_size_bounds_check(vol, na->type, newsize) < 0) {
		err = errno;
		if (err == ERANGE) {
			// FIXME: Eeek!
			Dprintf("%s(): Eeek!  Size bounds check failed.  "
					"Aborting...\n", __FUNCTION__);
		} else if (err == ENOENT)
			err = EIO;
		goto put_err_out;
	}
	/*
	 * If @newsize is bigger than the mft record we need to make the
	 * attribute non-resident if the attribute type supports it. If it is
	 * smaller we can go ahead and attempt the resize.
	 */
	if (newsize < vol->mft_record_size) {
		/* Perform the resize of the attribute record. */
		if (!ntfs_resident_attr_value_resize(ctx->mrec, ctx->attr,
				newsize)) {
			/* Update the ntfs attribute structure, too. */
			na->allocated_size = na->data_size =
					na->initialized_size = newsize;
			if (NAttrCompressed(na) || NAttrSparse(na))
				na->compressed_size = newsize;
			goto resize_done;
		}
		/* Error! If not enough space, just continue. */
		if (errno != ENOSPC) {
			err = errno;
			// FIXME: Eeek!
			if (err != ENOTSUP)
				Dprintf("%s(): Eeek!  Failed to resize "
						"resident part of attribute.  "
						"Aborting...\n", __FUNCTION__);
			goto put_err_out;
		}
	}
	/* There is not enough space in the mft record to perform the resize. */

	/* Make the attribute non-resident if possible. */
	if (!ntfs_attr_make_non_resident(na, ctx)) {
		/* Resize non-resident attribute */
		if (ntfs_attr_truncate (na, newsize)) {
			/* 
			 * Resize failed, but mark inode dirty because we made
			 * it non-resident.
			 */
			err = errno;
			ntfs_inode_mark_dirty(ctx->ntfs_ino);
			goto put_err_out;
		}
		goto resize_done;
	} else if (errno != ENOSPC && errno != EPERM) {
		err = errno;
		// FIXME: Eeek!
		Dprintf("%s(): Eeek!  Failed to make attribute non-resident.  "
				"Aborting...\n", __FUNCTION__);
		goto put_err_out;
	}

	// TODO: Try to make other attributes non-resident and retry each time.

	if (na->type == AT_ATTRIBUTE_LIST && errno == ENOSPC) {
		err = errno;
		goto put_err_out;
	}

	// TODO: Move the attribute to a new mft record, creating an attribute
	// list attribute or modifying it if it is already present.

	// TODO: If that is still not enough, split the attribute into multiple
	// extents and save them to several mft records.

	err = ENOTSUP;
	goto put_err_out;

resize_done:
	/*
	 * Set the inode (and its base inode if it exists) dirty so it is
	 * written out later.
	 */
	ntfs_inode_mark_dirty(ctx->ntfs_ino);
	/* Done! */
	ntfs_attr_put_search_ctx(ctx);
	return 0;
put_err_out:
	ntfs_attr_put_search_ctx(ctx);
	errno = err;
	return -1;
}

/**
 * ntfs_attr_make_resident - convert a non-resident to a resident attribute
 * @na:		open ntfs attribute to make resident
 * @ctx:	ntfs search context describing the attribute
 *
 * Convert a non-resident ntfs attribute to a resident one.
 *
 * Return 0 on success and -1 on error with errno set to the error code. The
 * following error codes are defined:
 *	EPERM	- The attribute is not allowed to be resident.
 *	TODO: others...
 *
 * Warning: We do not set the inode dirty and we do not write out anything!
 *	    We expect the caller to do this as this is a fairly low level
 *	    function and it is likely there will be further changes made.
 */
static int ntfs_attr_make_resident(ntfs_attr *na, ntfs_attr_search_ctx *ctx)
{
	ntfs_volume *vol = na->ni->vol;
	ATTR_REC *a = ctx->attr;
	int name_ofs, val_ofs, err = EIO;
	s64 arec_size, bytes_read;

	/* Some preliminary sanity checking. */
	if (!NAttrNonResident(na)) {
		// FIXME: Eeek!
		Dprintf("%s(): Eeek!  Trying to make resident attribute "
				"resident.  Aborting...\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	/* Make sure this is not $MFT/$BITMAP or Windows will not boot! */
	if (na->type == AT_BITMAP && na->ni->mft_no == FILE_MFT) {
		errno = EPERM;
		return -1;
	}

	/* Check that the attribute is allowed to be resident. */
	if (ntfs_attr_can_be_resident(vol, na->type))
		return -1;

	/*
	 * Check that the attribute name hasn't been placed after the
	 * mapping pairs array. If it has we need to move it.
	 * TODO: Implement the move. For now just abort. (AIA)
	 */
	if (a->name_length && le16_to_cpu(a->name_offset) >=
			le16_to_cpu(a->mapping_pairs_offset)) {
		// FIXME: Eeek!
		Dprintf("%s(): Eeek!  Name is placed after the mapping "
				"pairs array.  Aborting...\n", __FUNCTION__);
		errno = ENOTSUP;
		return -1;
	}

	// FIXME: For now we cheat and assume there is no attribute list
	//	  attribute present. (AIA)
	if (NInoAttrList(na->ni)) {
		Dprintf("%s(): Working on files with attribute list "
				"attribute is not implemented yet.\n",
				__FUNCTION__);
		errno = ENOTSUP;
		return -1;
	}
	if (NAttrCompressed(na) || NAttrEncrypted(na)) {
		Dprintf("%s(): Making compressed or encrypted files "
				"resident is not implemented yet.\n",
				__FUNCTION__);
		errno = ENOTSUP;
		return -1;
	}

	/* Work out offsets into and size of the resident attribute. */
	name_ofs = 24; /* = sizeof(resident_ATTR_REC); */
	val_ofs = (name_ofs + a->name_length + 7) & ~7;
	arec_size = (val_ofs + na->data_size + 7) & ~7;

	/* Sanity check the size before we start modifying the attribute. */
	if (le32_to_cpu(ctx->mrec->bytes_in_use) - le32_to_cpu(a->length) +
			arec_size > le32_to_cpu(ctx->mrec->bytes_allocated)) {
		errno = ENOSPC;
		return -1;
	}

	/* Read and cache the whole runlist if not already done. */
	if (ntfs_attr_map_whole_runlist(na))
		return -1;

	/* Move the attribute name if it exists and update the offset. */
	if (a->name_length) {
		/* Sanity check. */
		if (le16_to_cpu(a->name_offset) + a->name_length > arec_size) {
			// FIXME: Eeek!
			Dprintf("%s(): Eeek! Name exceeds new record "
					"size! Not supported. Aborting...\n",
					__FUNCTION__);
			errno = ENOTSUP;
			return -1;
		}

		memmove((u8*)a + name_ofs, (u8*)a + le16_to_cpu(a->name_offset),
				a->name_length * sizeof(ntfschar));
	}
	a->name_offset = cpu_to_le16(name_ofs);

	/* Resize the resident part of the attribute record. */
	if (ntfs_attr_record_resize(ctx->mrec, a, arec_size) < 0) {
		if (errno != ENOSPC) {
			err = errno;
			// FIXME: Eeek!
			Dprintf("%s(): Eeek! Failed to resize "
					"attribute record. Aborting...\n",
					__FUNCTION__);
			errno = err;
		}
		return -1;
	}

	/* Convert the attribute record to describe a resident attribute. */
	a->non_resident = 0;
	a->flags = 0;
	a->value_length = cpu_to_le32(na->data_size);
	a->value_offset = cpu_to_le16(val_ofs);
	/*
	 * File names cannot be non-resident so we would never see this here
	 * but at least it serves as a reminder that there may be attributes
	 * for which we do need to set this flag. (AIA)
	 */
	if (a->type == AT_FILE_NAME)
		a->resident_flags = RESIDENT_ATTR_IS_INDEXED;
	else
		a->resident_flags = 0;
	a->reservedR = 0;

	/* Sanity fixup...  Shouldn't really happen. (AIA) */
	if (na->initialized_size > na->data_size)
		na->initialized_size = na->data_size;

	/* Copy data from run list to resident attribute value. */
	bytes_read = ntfs_rl_pread(vol, na->rl, 0, na->initialized_size,
			(u8*)a + val_ofs);
	if (bytes_read != na->initialized_size) {
		if (bytes_read < 0)
			err = errno;
		// FIXME: Eeek!
		Dprintf("%s(): Eeek! Failed to read attribute data. "
				"Aborting...\n", __FUNCTION__);
		errno = err;
		return -1;
	}

	/* Clear memory in gap between initialized_size and data_size. */
	if (na->initialized_size < na->data_size)
		memset((u8*)a + val_ofs + na->initialized_size, 0,
				na->data_size - na->initialized_size);

	/*
	 * Deallocate clusters from the runlist.
	 *
	 * NOTE: We can use ntfs_cluster_free() because we have already mapped
	 * the whole run list and thus it doesn't matter that the attribute
	 * record is in a transiently corrupted state at this moment in time.
	 */
	if (ntfs_cluster_free(vol, na, 0, -1) < 0) {
		err = errno;
		// FIXME: Eeek!
		Dprintf("%s(): Eeek! Failed to release allocated "
				"clusters (error: %s).  Ignoring error and "
				"leaving behind wasted clusters.\n",
				__FUNCTION__, strerror(err));
	}

	/* Throw away the now unused runlist. */
	free(na->rl);
	na->rl = NULL;

	/* Update in-memory struct ntfs_attr. */
	NAttrClearNonResident(na);
	NAttrClearCompressed(na);
	NAttrClearSparse(na);
	NAttrClearEncrypted(na);
	na->allocated_size = na->initialized_size = na->compressed_size =
			na->data_size;
	na->compression_block_size = 0;
	na->compression_block_size_bits = na->compression_block_clusters = 0;
	return 0;
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
 *	ENOMEM	- Not enough memory to complete operation.
 *	ERANGE	- @newsize is not valid for the attribute type of @na.
 */
static int ntfs_non_resident_attr_shrink(ntfs_attr *na, const s64 newsize)
{
	ntfs_volume *vol;
	ntfs_attr_search_ctx *ctx;
	ATTR_RECORD *a;
	MFT_RECORD *m;
	VCN first_free_vcn;
	s64 nr_freed_clusters;
	u32 new_alen, new_muse;
	int err, mp_size;

	Dprintf("%s(): Entering for inode 0x%llx, attr 0x%x.\n", __FUNCTION__,
			(unsigned long long)na->ni->mft_no, na->type);

	vol = na->ni->vol;

	/* Get the first attribute record that needs modification. */
	ctx = ntfs_attr_get_search_ctx(na->ni, NULL);
	if (!ctx)
		return -1;
	if (ntfs_attr_lookup(na->type, na->name, na->name_len, 0, newsize >>
			vol->cluster_size_bits, NULL, 0, ctx)) {
		err = errno;
		if (err == ENOENT)
			err = EIO;
		goto put_err_out;
	}
	a = ctx->attr;
	m = ctx->mrec;
	/*
	 * Check the attribute type and the corresponding minimum size
	 * against @newsize and fail if @newsize is too small.
	 */
	if (ntfs_attr_size_bounds_check(vol, na->type, newsize) < 0) {
		err = errno;
		if (err == ERANGE) {
			// FIXME: Eeek!
			Dprintf("%s(): Eeek! Size bounds check "
					"failed. Aborting...\n", __FUNCTION__);
		} else if (err == ENOENT)
			err = EIO;
		goto put_err_out;
	}

	// When extents/an attribute list is/are present it is very complicated:
	// TODO: For the current extent:
	//	TODO: free the required clusters
	//	FIXME: how do we deal with extents that haven't been loaded yet?
	//		do we just fault them in first so that the runlist is
	//		complete and we are done with deallocations in one go?
	//	TODO: update the run list in na->rl
	//	TODO: update the sizes, etc in the ntfs attribute structure na
	//	TODO: update the mapping pairs array
	//	TODO: mark the inode dirty
	// TODO: For all subsequent extents:
	//	TODO: free all clusters specified by the extent (FIXME: unless
	//		already done above!)
	//	TODO: completely delete each extent attribute record from its
	//		mft record
	//	TODO: free the mft record if there are no attributes left in it
	//		(to do so update the $MFT/$Bitmap as well as the mft
	//		 record header in use flag, etc)
	//	TODO: write the updated mft record to disk
	//	TODO: remove the extent inode from the list of loaded extent
	//		inodes in the base inode
	//	TODO: free all memory associated with the extent inode
	// TODO: update the attribute list attribute in ni->attr_list, removing
	//	 all entries corresponding to deleted attributes
	// TODO: if the attribute list attribute is resident:
	//		TODO: update the actual attribute in the base mft
	//			record from ni->attr_list
	//	 if the attribute list attribute is not resident:
	//		TODO: update the attribute list attribute run list in
	//			ni->attr_list_rl, freeing any no longer used
	//			clusters
	//		TODO: mark the inode attribute list as containing
	//			dirty data
	//		TODO: update the mapping pairs array from
	//			ni->attr_list_rl
	// TODO: mark the base inode dirty

	// TODO: Implement attribute list support as desribed above. (AIA)
	if (NInoAttrList(na->ni)) {
		err = ENOTSUP;
		goto put_err_out;
	}
	// FIXME: We now know that we don't have an attribute list. Thus we
	//	  are in the base inode only and hence it is all easier, even
	//	  if we are cheating for now... (AIA)

	/* The first cluster outside the new allocation. */
	first_free_vcn = (newsize + vol->cluster_size - 1) >>
			vol->cluster_size_bits;
	/*
	 * Compare the new allocation with the old one and only deallocate
	 * clusters if there is a change.
	 */
	if ((na->allocated_size >> vol->cluster_size_bits) != first_free_vcn) {
		/* Deallocate all clusters starting with the first free one. */
		nr_freed_clusters = ntfs_cluster_free(vol, na, first_free_vcn,
				-1);
		if (nr_freed_clusters < 0) {
			err = errno;
			// FIXME: Eeek!
			Dprintf("%s(): Eeek! Freeing of clusters "
					"failed. Aborting...\n", __FUNCTION__);
			goto put_err_out;
		}
		/* Truncate the runlist itself. */
		if (ntfs_rl_truncate(&na->rl, first_free_vcn)) {
			err = errno;
			// FIXME: Eeek! We need rollback! (AIA)
			Dprintf("%s(): Eeek! Run list truncation "
					"failed. Leaving inconsistent "
					"metadata!\n", __FUNCTION__);
			goto put_err_out;
		}
		/* Update the attribute record and the ntfs_attr structure. */
		na->allocated_size = first_free_vcn << vol->cluster_size_bits;
		a->allocated_size = scpu_to_le64(na->allocated_size);
		if (NAttrCompressed(na) || NAttrSparse(na)) {
			na->compressed_size -= nr_freed_clusters <<
					vol->cluster_size_bits;
			// FIXME: Bug catcher. Remove later... (AIA)
			if (!newsize && na->compressed_size) {
				Dprintf("%s(): Eeek! !newsize but "
						"na->compressed_size not zero "
						"(= %lli)! Fixing up by hand!\n",
						__FUNCTION__, (long long)
						na->compressed_size);
				na->compressed_size = 0;
			}
			a->compressed_size = scpu_to_le64(na->compressed_size);

			// FIXME: Bug catcher. Remove later... (AIA)
			if (na->compressed_size < 0) {
				// FIXME: Eeek! BUG!
				Dprintf("%s(): Eeek! Compressed size "
						"is negative. Leaving "
						"inconsistent metadata!\n",
						__FUNCTION__);
				err = EIO;
				goto put_err_out;
			}
		}
		a->highest_vcn = scpu_to_le64(first_free_vcn - 1);
		/* Get the size for the new mapping pairs array. */
		mp_size = ntfs_get_size_for_mapping_pairs(vol, na->rl, 0);
		if (mp_size <= 0) {
			err = errno;
			// FIXME: Eeek! We need rollback! (AIA)
			Dprintf("%s(): Eeek! Get size for mapping "
					"pairs failed. Leaving inconsistent "
					"metadata!\n", __FUNCTION__);
			goto put_err_out;
		}
		/*
		 * Generate the new mapping pairs array directly into the
		 * correct destination, i.e. the attribute record itself.
		 */
		if (ntfs_mapping_pairs_build(vol, (u8*)a + le16_to_cpu(
					a->mapping_pairs_offset), mp_size,
					na->rl, 0, NULL)) {
			err = errno;
			// FIXME: Eeek! We need rollback! (AIA)
			Dprintf("%s(): Eeek! Mapping pairs build "
					"failed. Leaving inconsistent "
					"metadata!\n", __FUNCTION__);
			goto put_err_out;
		}
		/*
		 * Check that the attribute name hasn't been placed after the
		 * attribute value/mapping pairs array. If it has we need to
		 * move it. TODO: Implement the move. For now just abort. (AIA)
		 */
		if (a->name_length) {
			BOOL move_name = FALSE;
			if (a->non_resident) {
				if (le16_to_cpu(a->name_offset) >= le16_to_cpu(
						a->mapping_pairs_offset))
					move_name = TRUE;
			} else {
				if (le16_to_cpu(a->name_offset) >=
						le16_to_cpu(a->value_offset))
					move_name = TRUE;
					
			}
			if (move_name) {
				// FIXME: Eeek!
				Dprintf("%s(): Eeek! Name is placed "
						"after the %s. Aborting...\n",
						__FUNCTION__, a->non_resident ?
						"mapping pairs array":
						"attribute value");
				err = ENOTSUP;
				goto put_err_out;
			}
		}
		/*
		 * Calculate the new attribute length and mft record bytes
		 * used.
		 */
		new_alen = (le16_to_cpu(a->mapping_pairs_offset) + mp_size +
				7) & ~7;
		new_muse = le32_to_cpu(m->bytes_in_use) -
				le32_to_cpu(a->length) + new_alen;
		if (new_muse > le32_to_cpu(m->bytes_allocated)) {
			// FIXME: Eeek! BUG()
			Dprintf("%s(): Eeek! Ran out of space in mft "
					"record. Leaving inconsistent "
					"metadata!\n", __FUNCTION__);
			err = EIO;
			goto put_err_out;
		}
		/* Move the following attributes forward. */
		memmove((u8*)a + new_alen, (u8*)a + le32_to_cpu(a->length),
				le32_to_cpu(m->bytes_in_use) - ((u8*)a -
				(u8*)m) - le32_to_cpu(a->length));
		/* Update the sizes of the attribute and mft records. */
		a->length = cpu_to_le32(new_alen);
		m->bytes_in_use = cpu_to_le32(new_muse);
	}
	/* Update the attribute record and the ntfs attribute structure. */
	na->data_size = newsize;
	a->data_size = scpu_to_le64(newsize);
	if (newsize < na->initialized_size) {
		na->initialized_size = newsize;
		a->initialized_size = scpu_to_le64(newsize);
	}
	/* If the attribute now has zero size, make it resident. */
	if (!newsize) {
		if (ntfs_attr_make_resident(na, ctx)) {
			/* If couldn't make resident, just continue. */
			if (errno != EPERM)
				Dprintf("%s(): Failed to make attribute "
						"resident. Leaving as is...\n",
						__FUNCTION__);
		}
	}

	/* Set the inode dirty so it is written out later. */
	ntfs_inode_mark_dirty(ctx->ntfs_ino);
	/* Done! */
	ntfs_attr_put_search_ctx(ctx);
	return 0;
put_err_out:
	ntfs_attr_put_search_ctx(ctx);
	errno = err;
	return -1;
}

/**
 * ntfs_non_resident_attr_expand - expand a non-resident, open ntfs attribute
 * @na:		non-resident ntfs attribute to expand
 * @newsize:	new size (in bytes) to which to expand the attribute
 *
 * Expand the size of a non-resident, open ntfs attribute @na to @newsize bytes,
 * by allocating new clusters.
 *
 * On success return 0 and on error return -1 with errno set to the error code.
 * The following error codes are defined:
 *	ENOTSUP	- The desired resize is not implemented yet.
 *	ENOMEM	- Not enough memory to complete operation.
 *	ERANGE	- @newsize is not valid for the attribute type of @na.
 *	ENOSPC  - There is no enogh space in base mft to resize $ATTRIBUTE_LIST.
 */
static int ntfs_non_resident_attr_expand(ntfs_attr *na, const s64 newsize)
{
	LCN lcn_seek_from;
	VCN first_free_vcn, stop_vcn;
	ntfs_volume *vol;
	ntfs_attr_search_ctx *ctx;
	ATTR_RECORD *a;
	MFT_RECORD *m;
	runlist *rl, *rln;
	ntfs_inode *ni;
	int err, mp_size, cur_max_mp_size, exp_max_mp_size;
	BOOL add_attr_list_and_retry = FALSE;
	BOOL mft_records_changed = FALSE;

	Dprintf("%s(): Entering for inode 0x%llx, attr 0x%x.\n", __FUNCTION__,
			(unsigned long long)na->ni->mft_no, na->type);

	vol = na->ni->vol;

	/*
	 * Check the attribute type and the corresponding maximum size
	 * against @newsize and fail if @newsize is too big.
	 */
	if (ntfs_attr_size_bounds_check(vol, na->type, newsize) < 0) {
		err = errno;
		if (err == ERANGE) {
			Dprintf("%s(): Eeek! Size bounds check "
					"failed. Aborting...\n", __FUNCTION__);
		} else if (err == ENOENT)
			err = EIO;
		errno = err;
		return -1;
	}

	ctx = ntfs_attr_get_search_ctx(na->ni, NULL);
	if (!ctx)
		return -1;

	/* The first cluster outside the new allocation. */
	first_free_vcn = (newsize + vol->cluster_size - 1) >>
			vol->cluster_size_bits;
	/*
	 * Compare the new allocation with the old one and only allocate
	 * clusters if there is a change.
	 */
	if ((na->allocated_size >> vol->cluster_size_bits) != first_free_vcn) {
		/* Get the last extent of the attribute. */
		if (ntfs_attr_lookup(na->type, na->name, na->name_len, 0,
				(na->allocated_size >>
				vol->cluster_size_bits) - 1, NULL, 0, ctx)) {
			err = errno;
			if (err == ENOENT)
				err = EIO;
			goto put_err_out;
		}
		a = ctx->attr;
		m = ctx->mrec;

		/*
		 * Check that the attribute name hasn't been placed after the
		 * mapping pairs array. If it has we need to move it.
		 * TODO: Implement the move, if someone will hit it.
		 */
		if (a->name_length) {
			if (le16_to_cpu(a->name_offset) >=
					le16_to_cpu(a->mapping_pairs_offset)) {
				Dprintf("%s(): Eeek! Name is placed after the "
					"mapping pairs array. Aborting...\n",
					__FUNCTION__);
				err = ENOTSUP;
				goto put_err_out;
			}
		}

		if (ntfs_attr_map_runlist(na, sle64_to_cpu(a->lowest_vcn))) {
			err = errno;
			Dprintf("%s(): Eeek! ntfs_attr_map_runlist failed.\n",
								 __FUNCTION__);
			goto put_err_out;
		}

		/*
		 * Determine first after last LCN of attribute.  We will start
		 * seek clusters from this LCN to avoid fragmentation.  If
		 * there are no valid LCNs in the attribute let the cluster
		 * allocator choose the starting LCN.
		 */
		lcn_seek_from = -1;
		if (na->rl->length) {
			/* Seek to the last run list element. */
			for (rl = na->rl; (rl + 1)->length; rl++)
				;
			/*
			 * If the last LCN is a hole or simillar seek back to
			 * last valid LCN.
			 */
			while (rl->lcn < 0 && rl != na->rl)
				rl--;
			/* Only set lcn_seek_from it the LCN is valid. */
			if (rl->lcn >= 0)
				lcn_seek_from = rl->lcn + rl->length;
		}

		rl = ntfs_cluster_alloc(vol, first_free_vcn - 
					(na->allocated_size >>
					vol->cluster_size_bits), lcn_seek_from,
					DATA_ZONE, na->allocated_size >>
					vol->cluster_size_bits);
		if (!rl) {
			err = errno;
			Dprintf("%s(): Eeek! Cluster allocation "
					"failed.\n", __FUNCTION__);
			goto put_err_out;
		}

		/* Append new clusters to attribute runlist. */
		rln = ntfs_runlists_merge(na->rl, rl);
		if (!rln) {
			/* Failed, free just allocated clusters. */
			err = errno;
			Dprintf("%s(): Eeek! Run list merge "
					"failed.\n", __FUNCTION__);
			ntfs_cluster_free_from_rl(vol, rl);
			free(rl);
			goto put_err_out;
		}
		na->rl = rln;

		/* Get the size for the new mapping pairs array. */
		mp_size = ntfs_get_size_for_mapping_pairs(vol, na->rl,
				sle64_to_cpu(a->lowest_vcn));
		if (mp_size <= 0) {
			err = errno;
			Dprintf("%s(): Eeek! Get size for mapping "
					"pairs failed.\n", __FUNCTION__);
			goto rollback;
		}
		/*
		 * Determine maximum possible length of mapping pairs,
		 * if we shall *not* expand space for mapping pairs.
		 */
		cur_max_mp_size = le32_to_cpu(a->length) - 
				le16_to_cpu(a->mapping_pairs_offset);
		/*
		 * Determine maximum possible length of mapping pairs in the
		 * current mft record, if we shall expand space for mapping
		 * pairs.
		 */
		exp_max_mp_size = le32_to_cpu(m->bytes_allocated) -
				le32_to_cpu(m->bytes_in_use) + cur_max_mp_size;

		/* Test mapping pairs for fitting in the current mft record. */
		if (mp_size > exp_max_mp_size) {
			/*
			 * Mapping pairs of $ATTRIBUTE_LIST attribute must fit
			 * in the base mft record.
			 */
			if (na->type == AT_ATTRIBUTE_LIST) {
				err = ENOSPC;
				goto rollback;
			}

			/* Add attribute list, if it isn't present and retry. */
			if (!NInoAttrList(na->ni)) {
			        err = ENOTSUP; /* to suppress gcc complain */
				add_attr_list_and_retry = TRUE;
				goto rollback;
			}

			/*
			 * Set mapping pairs size to maximum possible for this
			 * mft record. We shall allocate new mft records for
			 * rest of mapping pairs.
			 */
			mp_size = exp_max_mp_size;
		}

		/* Expand space for mapping pairs if we need this. */
		if (mp_size > cur_max_mp_size) {
			if (ntfs_attr_record_resize(m, a,
					le16_to_cpu(a->mapping_pairs_offset) +
					mp_size)) {
				Dprintf("%s(): BUG! Ran out of space in"
						" mft record. Please run chkdsk"
						" and if that doesn't find any "
						"errors please report you saw "
						"this message to "
						"linux-ntfs-dev@lists.sf.net."
						"\n", __FUNCTION__);
				err = EIO;
				goto rollback;
			}
			mft_records_changed = TRUE;
		}
		/*
		 * Generate the new mapping pairs array directly into the
		 * correct destination, i.e. the attribute record itself.
		 * If we ran out of space than allocate new MFT record, add
		 * attribute extent to it and continue generation.
		 */
		stop_vcn = sle64_to_cpu(a->lowest_vcn);
		ni = ctx->ntfs_ino;
		while(ntfs_mapping_pairs_build(vol, (u8*)a + le16_to_cpu(
				a->mapping_pairs_offset), mp_size, na->rl,
				stop_vcn, &stop_vcn)) {
			if (errno != ENOSPC) {
				err = errno;
				Dprintf("%s(): BUG!  Mapping pairs build "
					"failed.  Please run chkdsk and if "
					"that doesn't find any errors please "
					"report you saw this message to "
					"linux-ntfs-dev@lists.sf.net.\n",
					__FUNCTION__);
				goto rollback;
			}
			a->highest_vcn = scpu_to_le64(stop_vcn - 1);
			mft_records_changed = TRUE;
			ntfs_inode_mark_dirty(ni);
			
			/* Calculate size of rest mapping pairs. */
			mp_size = ntfs_get_size_for_mapping_pairs(vol,
					na->rl, stop_vcn);
	
			/* Allocate new mft record. */
			ni = ntfs_mft_record_alloc(vol, na->ni);
			if (!ni) {
				err = errno;
				Dprintf("%s(): Couldn't allocate new MFT "
					"record.\n", __FUNCTION__);
				goto rollback;
			}
			m = ni->mrec;
			/*
			 * If mapping size exceed avaible space, set them to
			 * possible maximum.
			 */
			cur_max_mp_size = le32_to_cpu(m->bytes_allocated) -
					le32_to_cpu(m->bytes_in_use) - 0x40 -
					sizeof(ntfschar) * na->name_len;
			if (mp_size > cur_max_mp_size)
				mp_size = cur_max_mp_size;
			/* Add atribute extent to new record. */
			err = ntfs_non_resident_attr_record_add(ni, na->type,
				 na->name, na->name_len, stop_vcn, mp_size, 0);
			if (err == -1) {
				err = errno;
				Dprintf("%s(): Couldn't add attribute extent "
					"into the MFT record.\n", __FUNCTION__);
				goto rollback;
			}
			a = (ATTR_RECORD*)((u8*)m + err);
		}
		a->highest_vcn = scpu_to_le64(first_free_vcn - 1);
		mft_records_changed = TRUE;
		ntfs_inode_mark_dirty(ni);
		ntfs_attr_reinit_search_ctx(ctx);
	}
	
	if (ntfs_attr_lookup(na->type, na->name, na->name_len, 0, 0, NULL, 0,
			ctx)) {
		Dprintf("%s(): Eeek! Lookup of first attribute extent "
				"failed.\n", __FUNCTION__);
		err = errno;
		if (err == ENOENT)
			err = EIO;
		if ((na->allocated_size >> vol->cluster_size_bits) !=
				first_free_vcn) {
			Dprintf("%s(): Trying perform rollback.\n",
					__FUNCTION__);
			goto rollback;
		} else
			goto put_err_out;
	}
	a = ctx->attr;
	
	if ((na->allocated_size >> vol->cluster_size_bits) != first_free_vcn) {
		/* Update the attribute record and the ntfs_attr structure. */
		na->allocated_size = first_free_vcn << vol->cluster_size_bits;
		a->allocated_size = scpu_to_le64(na->allocated_size);
	}
	/* Update the attribute record and the ntfs attribute structure. */
	na->data_size = newsize;
	a->data_size = scpu_to_le64(newsize);
	/* Set the inode dirty so it is written out later. */
	ntfs_inode_mark_dirty(ctx->ntfs_ino);
	/* Done! */
	ntfs_attr_put_search_ctx(ctx);
	return 0;
rollback:
	/* Free allocated clusters. */
	if (ntfs_cluster_free(vol, na, na->allocated_size >>
					vol->cluster_size_bits, -1) < 0) {
		Dprintf("%s(): Eeek!  Leaking clusters.  Run chkdsk!\n",
				__FUNCTION__);
		err = EIO;
	}
	/* Now, truncate the runlist itself. */
	if (ntfs_rl_truncate(&na->rl, na->allocated_size >>
					vol->cluster_size_bits)) {
		/*
		 * Failed to truncate the runlist, so just throw it away, it
		 * will be mapped afresh on next use.
		 */
		free(na->rl);
		na->rl = NULL;
	}
	/* Add attribute list and try again. */
	if (add_attr_list_and_retry) {
		ntfs_attr_put_search_ctx(ctx);
		if (ntfs_inode_add_attrlist(na->ni)) {
			err = errno;
			Dprintf("%s(): Eeek! Coudn't add attribute list.\n",
					__FUNCTION__);
			errno = err;
			return -1;
		}
		return ntfs_non_resident_attr_expand(na, newsize);
	}
	/* Do we need rollback changes inside MFT records.*/
	if (!mft_records_changed)
		goto put_err_out;
	/* Rollback changes inside MFT records. */
	ntfs_attr_reinit_search_ctx(ctx);
	if (ntfs_attr_lookup(na->type, na->name, na->name_len, 0,
			(na->allocated_size >> vol->cluster_size_bits) - 1,
			 NULL, 0, ctx)) {
		Dprintf("%s(): Eeek! Rollback failed. Run chkdsk.\n",
				__FUNCTION__);
		goto put_err_out;
	}
	a = ctx->attr;
	m = ctx->mrec;
	mp_size = ntfs_get_size_for_mapping_pairs(vol, na->rl, 
					sle64_to_cpu(a->lowest_vcn));
	if (mp_size <= 0) {
		Dprintf("%s(): Eeek! Get size for mapping pairs failed. "
			"Rollback failed. Run chkdsk.\n", __FUNCTION__);
		goto put_err_out;
	}
	if (ntfs_attr_record_resize(m, a,
			le16_to_cpu(a->mapping_pairs_offset) + mp_size)) {
		Dprintf("%s(): Eeek! Attribuite record resize failed. Rollback "
			"failed. Run chkdsk.\n", __FUNCTION__);
		goto put_err_out;
	}
	if (ntfs_mapping_pairs_build(vol, (u8*)a + le16_to_cpu(
				a->mapping_pairs_offset), mp_size, na->rl,
				sle64_to_cpu(a->lowest_vcn), 0)) {
		Dprintf("%s(): Eeek! Mapping pairs build failed. Rollback "
			"failed. Run chkdsk.\n", __FUNCTION__);
		goto put_err_out;
	}
	a->highest_vcn = scpu_to_le64((na->allocated_size >>
					vol->cluster_size_bits) - 1);
	stop_vcn = 0;
	while (!ntfs_attr_lookup(na->type, na->name,
			na->name_len, 0, 0, NULL, 0, ctx)) {
		if (stop_vcn > sle64_to_cpu(ctx->attr->highest_vcn))
			continue;
		stop_vcn = sle64_to_cpu(ctx->attr->highest_vcn) + 1;
		if (ntfs_attr_record_rm(ctx)) {
			Dprintf("%s(): Eeek! Removing attribute extent failed. "
				"Rollback failed. Run chkdsk.\n", __FUNCTION__);
			goto put_err_out;
		}
		ntfs_attr_reinit_search_ctx(ctx);
	}
	if (errno != ENOENT) {
		Dprintf("%s(): Eeek! Attribute extent lookup failed. Rollback "
			"failed. Run chkdsk.\n", __FUNCTION__);
	} else
		Dprintf("%s(): Rollback success.\n", __FUNCTION__);
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
 * Change the size of an open ntfs attribute @na to @newsize bytes. If the
 * attribute is made bigger and the attribute is resident the newly
 * "allocated" space is cleared and if the attribute is non-resident the
 * newly allocated space is marked as not initialised and no real allocation
 * on disk is performed. FIXME: Do we have to create sparse runs or can we just
 * leave the runlist to finish below data_size, i.e. can we have
 * allocated_size < data_size? I guess that what we can't and thus we will have
 * to set the sparse bit of the attribute and create sparse runs to ensure that
 * allocated_size is >= data_size. We don't need to clear the partial run at
 * the end of the real allocation because we leave initialized_size low enough.
 * FIXME: Do we want that? Alternatively, we leave initialized_size = data_size
 * and do clear the partial run. The latter approach would be more inline with
 * what windows would do, even though windows wouldn't even make the attribute
 * sparse, it would just allocate clusters instead. TODO: Check what happens on
 * WinXP and 2003. FIXME: Make sure to check what NT4 does with an NTFS1.2
 * volume that has sparse files. I suspect it will blow up so we will need to
 * perform allocations of clusters, like NT4 would do for NTFS1.2 while we can
 * use sparse attributes on NTFS3.x.
 *
 * On success return 0 and on error return -1 with errno set to the error code.
 * The following error codes are defined:
 *	EINVAL	- Invalid arguments were passed to the function.
 *	ENOTSUP	- The desired resize is not implemented yet.
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
	 * TODO: Implement making handling of compressed attributes.
	 */
	if (NAttrCompressed(na)) {
		errno = ENOTSUP;
		return -1;
	}
	if (NAttrNonResident(na)) {
		if (newsize > na->data_size)
			return ntfs_non_resident_attr_expand(na, newsize);
		else
			return ntfs_non_resident_attr_shrink(na, newsize);
	}
	return ntfs_resident_attr_resize(na, newsize);
}
