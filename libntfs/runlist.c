/*
 * runlist.c - Run list handling code. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002-2005 Anton Altaparmakov
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

#include "types.h"
#include "attrib.h"
#include "volume.h"
#include "layout.h"
#include "debug.h"
#include "device.h"

/**
 * Internal:
 *
 * ntfs_rl_mm - runlist memmove
 */
static __inline__ void ntfs_rl_mm(runlist_element *base, int dst, int src,
		int size)
{
	if ((dst != src) && (size > 0))
		memmove(base + dst, base + src, size * sizeof(*base));
}

/**
 * Internal:
 *
 * rl_mc - runlist memory copy
 */
static __inline__ void ntfs_rl_mc(runlist_element *dstbase, int dst,
		runlist_element *srcbase, int src, int size)
{
	if (size > 0)
		memcpy(dstbase + dst, srcbase + src, size * sizeof(*dstbase));
}

/**
 * Internal:
 *
 * ntfs_rl_realloc - Reallocate memory for runlists
 * @rl:		original runlist
 * @old_size:	number of runlist elements in the original runlist @rl
 * @new_size:	number of runlist elements we need space for
 *
 * As the runlists grow, more memory will be required. To prevent large
 * numbers of small reallocations of memory, this function returns a 4kiB block
 * of memory.
 *
 * N.B.	If the new allocation doesn't require a different number of 4kiB
 *	blocks in memory, the function will return the original pointer.
 *
 * On success, return a pointer to the newly allocated, or recycled, memory.
 * On error, return NULL with errno set to the error code.
 */
static __inline__ runlist_element *ntfs_rl_realloc(runlist_element *rl,
		int old_size, int new_size)
{
	old_size = (old_size * sizeof(runlist_element) + 0xfff) & ~0xfff;
	new_size = (new_size * sizeof(runlist_element) + 0xfff) & ~0xfff;
	if (old_size == new_size)
		return rl;
	return realloc(rl, new_size);
}

/**
 * Internal:
 *
 * ntfs_rl_are_mergeable - test if two runlists can be joined together
 * @dst:	original runlist
 * @src:	new runlist to test for mergeability with @dst
 *
 * Test if two runlists can be joined together. For this, their VCNs and LCNs
 * must be adjacent.
 *
 * Return: TRUE   Success, the runlists can be merged.
 *	   FALSE  Failure, the runlists cannot be merged.
 */
static __inline__ BOOL ntfs_rl_are_mergeable(runlist_element *dst,
		runlist_element *src)
{
	if (!dst || !src) {
		Dputs("Eeek. ntfs_rl_are_mergeable() invoked with NULL "
				"pointer!");
		return FALSE;
	}

	if ((dst->lcn < 0) || (src->lcn < 0)) {    /* Are we merging holes? */
		if (dst->lcn == LCN_HOLE && src->lcn == LCN_HOLE)
			return TRUE;
		return FALSE;
	}
	if ((dst->lcn + dst->length) != src->lcn) /* Are the runs contiguous? */
		return FALSE;
	if ((dst->vcn + dst->length) != src->vcn) /* Are the runs misaligned? */
		return FALSE;

	return TRUE;
}

/**
 * Internal:
 *
 * __ntfs_rl_merge - merge two runlists without testing if they can be merged
 * @dst:	original, destination runlist
 * @src:	new runlist to merge with @dst
 *
 * Merge the two runlists, writing into the destination runlist @dst. The
 * caller must make sure the runlists can be merged or this will corrupt the
 * destination runlist.
 */
static __inline__ void __ntfs_rl_merge(runlist_element *dst,
		runlist_element *src)
{
	dst->length += src->length;
}

/**
 * Internal:
 *
 * ntfs_rl_append - append a runlist after a given element
 * @dst:	original runlist to be worked on
 * @dsize:	number of elements in @dst (including end marker)
 * @src:	runlist to be inserted into @dst
 * @ssize:	number of elements in @src (excluding end marker)
 * @loc:	append the new runlist @src after this element in @dst
 *
 * Append the runlist @src after element @loc in @dst.  Merge the right end of
 * the new runlist, if necessary. Adjust the size of the hole before the
 * appended runlist.
 *
 * On success, return a pointer to the new, combined, runlist. Note, both
 * runlists @dst and @src are deallocated before returning so you cannot use
 * the pointers for anything any more. (Strictly speaking the returned runlist
 * may be the same as @dst but this is irrelevant.)
 *
 * On error, return NULL, with errno set to the error code. Both runlists are
 * left unmodified.
 */
static __inline__ runlist_element *ntfs_rl_append(runlist_element *dst,
		int dsize, runlist_element *src, int ssize, int loc)
{
	BOOL right;
	int magic;

	if (!dst || !src) {
		Dputs("Eeek. ntfs_rl_append() invoked with NULL pointer!");
		errno = EINVAL;
		return NULL;
	}

	/* First, check if the right hand end needs merging. */
	right = ntfs_rl_are_mergeable(src + ssize - 1, dst + loc + 1);

	/* Space required: @dst size + @src size, less one if we merged. */
	dst = ntfs_rl_realloc(dst, dsize, dsize + ssize - right);
	if (!dst)
		return dst;
	/*
	 * We are guaranteed to succeed from here so can start modifying the
	 * original runlists.
	 */

	/* First, merge the right hand end, if necessary. */
	if (right)
		__ntfs_rl_merge(src + ssize - 1, dst + loc + 1);

	/* FIXME: What does this mean? (AIA) */
	magic = loc + ssize;

	/* Move the tail of @dst out of the way, then copy in @src. */
	ntfs_rl_mm(dst, magic + 1, loc + 1 + right, dsize - loc - 1 - right);
	ntfs_rl_mc(dst, loc + 1, src, 0, ssize);

	/* Adjust the size of the preceding hole. */
	dst[loc].length = dst[loc + 1].vcn - dst[loc].vcn;

	/* We may have changed the length of the file, so fix the end marker */
	if (dst[magic + 1].lcn == LCN_ENOENT)
		dst[magic + 1].vcn = dst[magic].vcn + dst[magic].length;

	return dst;
}

/**
 * Internal:
 *
 * ntfs_rl_insert - insert a runlist into another
 * @dst:	original runlist to be worked on
 * @dsize:	number of elements in @dst (including end marker)
 * @src:	new runlist to be inserted
 * @ssize:	number of elements in @src (excluding end marker)
 * @loc:	insert the new runlist @src before this element in @dst
 *
 * Insert the runlist @src before element @loc in the runlist @dst. Merge the
 * left end of the new runlist, if necessary. Adjust the size of the hole
 * after the inserted runlist.
 *
 * On success, return a pointer to the new, combined, runlist. Note, both
 * runlists @dst and @src are deallocated before returning so you cannot use
 * the pointers for anything any more. (Strictly speaking the returned runlist
 * may be the same as @dst but this is irrelevant.)
 *
 * On error, return NULL, with errno set to the error code. Both runlists are
 * left unmodified.
 */
static __inline__ runlist_element *ntfs_rl_insert(runlist_element *dst,
		int dsize, runlist_element *src, int ssize, int loc)
{
	BOOL left = FALSE;
	BOOL disc = FALSE;	/* Discontinuity */
	BOOL hole = FALSE;	/* Following a hole */
	int magic;

	if (!dst || !src) {
		Dputs("Eeek. ntfs_rl_insert() invoked with NULL pointer!");
		errno = EINVAL;
		return NULL;
	}

	/* disc => Discontinuity between the end of @dst and the start of @src.
	 *	   This means we might need to insert a hole.
	 * hole => @dst ends with a hole or an unmapped region which we can
	 *	   extend to match the discontinuity.
	 */
	if (loc == 0)
		disc = (src[0].vcn > 0);
	else {
		s64 merged_length;

		left = ntfs_rl_are_mergeable(dst + loc - 1, src);

		merged_length = dst[loc - 1].length;
		if (left)
			merged_length += src->length;

		disc = (src[0].vcn > dst[loc - 1].vcn + merged_length);
		if (disc)
			hole = (dst[loc - 1].lcn == LCN_HOLE);
	}

	/* Space required: @dst size + @src size, less one if we merged, plus
	 * one if there was a discontinuity, less one for a trailing hole.
	 */
	dst = ntfs_rl_realloc(dst, dsize, dsize + ssize - left + disc - hole);
	if (!dst)
		return dst;
	/*
	 * We are guaranteed to succeed from here so can start modifying the
	 * original runlist.
	 */

	if (left)
		__ntfs_rl_merge(dst + loc - 1, src);

	/* FIXME: What does this mean? (AIA) */
	magic = loc + ssize - left + disc - hole;

	/* Move the tail of @dst out of the way, then copy in @src. */
	ntfs_rl_mm(dst, magic, loc, dsize - loc);
	ntfs_rl_mc(dst, loc + disc - hole, src, left, ssize - left);

	/* Adjust the VCN of the last run ... */
	if (dst[magic].lcn <= LCN_HOLE)
		dst[magic].vcn = dst[magic - 1].vcn + dst[magic - 1].length;
	/* ... and the length. */
	if (dst[magic].lcn == LCN_HOLE || dst[magic].lcn == LCN_RL_NOT_MAPPED)
		dst[magic].length = dst[magic + 1].vcn - dst[magic].vcn;

	/* Writing beyond the end of the file and there's a discontinuity. */
	if (disc) {
		if (hole)
			dst[loc - 1].length = dst[loc].vcn - dst[loc - 1].vcn;
		else {
			if (loc > 0) {
				dst[loc].vcn = dst[loc - 1].vcn +
						dst[loc - 1].length;
				dst[loc].length = dst[loc + 1].vcn -
						dst[loc].vcn;
			} else {
				dst[loc].vcn = 0;
				dst[loc].length = dst[loc + 1].vcn;
			}
			dst[loc].lcn = LCN_RL_NOT_MAPPED;
		}

		magic += hole;

		if (dst[magic].lcn == LCN_ENOENT)
			dst[magic].vcn = dst[magic - 1].vcn +
					dst[magic - 1].length;
	}
	return dst;
}

/**
 * Internal:
 *
 * ntfs_rl_replace - overwrite a runlist element with another runlist
 * @dst:	original runlist to be worked on
 * @dsize:	number of elements in @dst (including end marker)
 * @src:	new runlist to be inserted
 * @ssize:	number of elements in @src (excluding end marker)
 * @loc:	index in runlist @dst to overwrite with @src
 *
 * Replace the runlist element @dst at @loc with @src. Merge the left and
 * right ends of the inserted runlist, if necessary.
 *
 * On success, return a pointer to the new, combined, runlist. Note, both
 * runlists @dst and @src are deallocated before returning so you cannot use
 * the pointers for anything any more. (Strictly speaking the returned runlist
 * may be the same as @dst but this is irrelevant.)
 *
 * On error, return NULL, with errno set to the error code. Both runlists are
 * left unmodified.
 */
static __inline__ runlist_element *ntfs_rl_replace(runlist_element *dst,
		int dsize, runlist_element *src, int ssize, int loc)
{
	BOOL left = FALSE;
	BOOL right;
	int magic;

	if (!dst || !src) {
		Dputs("Eeek. ntfs_rl_replace() invoked with NULL pointer!");
		errno = EINVAL;
		return NULL;
	}

	/* First, merge the left and right ends, if necessary. */
	right = ntfs_rl_are_mergeable(src + ssize - 1, dst + loc + 1);
	if (loc > 0)
		left = ntfs_rl_are_mergeable(dst + loc - 1, src);

	/* Allocate some space. We'll need less if the left, right, or both
	 * ends were merged.
	 */
	dst = ntfs_rl_realloc(dst, dsize, dsize + ssize - left - right);
	if (!dst)
		return dst;
	/*
	 * We are guaranteed to succeed from here so can start modifying the
	 * original runlists.
	 */
	if (right)
		__ntfs_rl_merge(src + ssize - 1, dst + loc + 1);
	if (left)
		__ntfs_rl_merge(dst + loc - 1, src);

	/* FIXME: What does this mean? (AIA) */
	magic = loc + ssize - left;

	/* Move the tail of @dst out of the way, then copy in @src. */
	ntfs_rl_mm(dst, magic, loc + right + 1, dsize - loc - right - 1);
	ntfs_rl_mc(dst, loc, src, left, ssize - left);

	/* We may have changed the length of the file, so fix the end marker */
	if (dst[magic].lcn == LCN_ENOENT)
		dst[magic].vcn = dst[magic - 1].vcn + dst[magic - 1].length;
	return dst;
}

/**
 * Internal:
 *
 * ntfs_rl_split - insert a runlist into the centre of a hole
 * @dst:	original runlist to be worked on
 * @dsize:	number of elements in @dst (including end marker)
 * @src:	new runlist to be inserted
 * @ssize:	number of elements in @src (excluding end marker)
 * @loc:	index in runlist @dst at which to split and insert @src
 *
 * Split the runlist @dst at @loc into two and insert @new in between the two
 * fragments. No merging of runlists is necessary. Adjust the size of the
 * holes either side.
 *
 * On success, return a pointer to the new, combined, runlist. Note, both
 * runlists @dst and @src are deallocated before returning so you cannot use
 * the pointers for anything any more. (Strictly speaking the returned runlist
 * may be the same as @dst but this is irrelevant.)
 *
 * On error, return NULL, with errno set to the error code. Both runlists are
 * left unmodified.
 */
static __inline__ runlist_element *ntfs_rl_split(runlist_element *dst,
		int dsize, runlist_element *src, int ssize, int loc)
{
	if (!dst || !src) {
		Dputs("Eeek. ntfs_rl_split() invoked with NULL pointer!");
		errno = EINVAL;
		return NULL;
	}

	/* Space required: @dst size + @src size + one new hole. */
	dst = ntfs_rl_realloc(dst, dsize, dsize + ssize + 1);
	if (!dst)
		return dst;
	/*
	 * We are guaranteed to succeed from here so can start modifying the
	 * original runlists.
	 */

	/* Move the tail of @dst out of the way, then copy in @src. */
	ntfs_rl_mm(dst, loc + 1 + ssize, loc, dsize - loc);
	ntfs_rl_mc(dst, loc + 1, src, 0, ssize);

	/* Adjust the size of the holes either size of @src. */
	dst[loc].length		= dst[loc+1].vcn       - dst[loc].vcn;
	dst[loc+ssize+1].vcn	= dst[loc+ssize].vcn   + dst[loc+ssize].length;
	dst[loc+ssize+1].length	= dst[loc+ssize+2].vcn - dst[loc+ssize+1].vcn;

	return dst;
}


/**
 * ntfs_runlists_merge - merge two runlists into one
 * @drl:	original runlist to be worked on
 * @srl:	new runlist to be merged into @drl
 *
 * First we sanity check the two runlists @srl and @drl to make sure that they
 * are sensible and can be merged. The runlist @srl must be either after the
 * runlist @drl or completely within a hole (or unmapped region) in @drl.
 *
 * Merging of runlists is necessary in two cases:
 *   1. When attribute lists are used and a further extent is being mapped.
 *   2. When new clusters are allocated to fill a hole or extend a file.
 *
 * There are four possible ways @srl can be merged. It can:
 *	- be inserted at the beginning of a hole,
 *	- split the hole in two and be inserted between the two fragments,
 *	- be appended at the end of a hole, or it can
 *	- replace the whole hole.
 * It can also be appended to the end of the runlist, which is just a variant
 * of the insert case.
 *
 * On success, return a pointer to the new, combined, runlist. Note, both
 * runlists @drl and @srl are deallocated before returning so you cannot use
 * the pointers for anything any more. (Strictly speaking the returned runlist
 * may be the same as @dst but this is irrelevant.)
 *
 * On error, return NULL, with errno set to the error code. Both runlists are
 * left unmodified. The following error codes are defined:
 *	ENOMEM		Not enough memory to allocate runlist array.
 *	EINVAL		Invalid parameters were passed in.
 *	ERANGE		The runlists overlap and cannot be merged.
 */
runlist_element *ntfs_runlists_merge(runlist_element *drl,
		runlist_element *srl)
{
	int di, si;		/* Current index into @[ds]rl. */
	int sstart;		/* First index with lcn > LCN_RL_NOT_MAPPED. */
	int dins;		/* Index into @drl at which to insert @srl. */
	int dend, send;		/* Last index into @[ds]rl. */
	int dfinal, sfinal;	/* The last index into @[ds]rl with
				   lcn >= LCN_HOLE. */
	int marker = 0;
	VCN marker_vcn = 0;

	Dputs("dst:");
	ntfs_debug_runlist_dump(drl);
	Dputs("src:");
	ntfs_debug_runlist_dump(srl);

	/* Check for silly calling... */
	if (!srl)
		return drl;

	/* Check for the case where the first mapping is being done now. */
	if (!drl) {
		drl = srl;
		/* Complete the source runlist if necessary. */
		if (drl[0].vcn) {
			/* Scan to the end of the source runlist. */
			for (dend = 0; drl[dend].length; dend++)
				;
			drl = ntfs_rl_realloc(drl, dend, dend + 1);
			if (!drl)
				return drl;
			/* Insert start element at the front of the runlist. */
			ntfs_rl_mm(drl, 1, 0, dend);
			drl[0].vcn = 0;
			drl[0].lcn = LCN_RL_NOT_MAPPED;
			drl[0].length = drl[1].vcn;
		}
		goto finished;
	}

	si = di = 0;

	/* Skip any unmapped start element(s) in the source runlist. */
	while (srl[si].length && srl[si].lcn < (LCN)LCN_HOLE)
		si++;

	/* Can't have an entirely unmapped source runlist. */
	if (!srl[si].length) {
		Dputs("Eeek! ntfs_runlists_merge() received entirely "
				"unmapped source runlist.");
		errno = EINVAL;
		return NULL;
	}

	/* Record the starting points. */
	sstart = si;

	/*
	 * Skip forward in @drl until we reach the position where @srl needs to
	 * be inserted. If we reach the end of @drl, @srl just needs to be
	 * appended to @drl.
	 */
	for (; drl[di].length; di++) {
		if (drl[di].vcn + drl[di].length > srl[sstart].vcn)
			break;
	}
	dins = di;

	/* Sanity check for illegal overlaps. */
	if ((drl[di].vcn == srl[si].vcn) && (drl[di].lcn >= 0) &&
			(srl[si].lcn >= 0)) {
		Dputs("Run lists overlap. Cannot merge!");
		errno = ERANGE;
		return NULL;
	}

	/* Scan to the end of both runlists in order to know their sizes. */
	for (send = si; srl[send].length; send++)
		;
	for (dend = di; drl[dend].length; dend++)
		;

	if (srl[send].lcn == (LCN)LCN_ENOENT)
		marker_vcn = srl[marker = send].vcn;

	/* Scan to the last element with lcn >= LCN_HOLE. */
	for (sfinal = send; sfinal >= 0 && srl[sfinal].lcn < LCN_HOLE; sfinal--)
		;
	for (dfinal = dend; dfinal >= 0 && drl[dfinal].lcn < LCN_HOLE; dfinal--)
		;

	{
	BOOL start;
	BOOL finish;
	int ds = dend + 1;		/* Number of elements in drl & srl */
	int ss = sfinal - sstart + 1;

	start  = ((drl[dins].lcn <  LCN_RL_NOT_MAPPED) ||    /* End of file   */
		  (drl[dins].vcn == srl[sstart].vcn));	     /* Start of hole */
	finish = ((drl[dins].lcn >= LCN_RL_NOT_MAPPED) &&    /* End of file   */
		 ((drl[dins].vcn + drl[dins].length) <=      /* End of hole   */
		  (srl[send - 1].vcn + srl[send - 1].length)));

	/* Or we'll lose an end marker */
	if (start && finish && (drl[dins].length == 0))
		ss++;
	if (marker && (drl[dins].vcn + drl[dins].length > srl[send - 1].vcn))
		finish = FALSE;
#ifdef DEBUG
	Dprintf("dfinal = %i, dend = %i\n", dfinal, dend);
	Dprintf("sstart = %i, sfinal = %i, send = %i\n", sstart, sfinal, send);
	Dprintf("start = %i, finish = %i\n", start, finish);
	Dprintf("ds = %i, ss = %i, dins = %i\n", ds, ss, dins);
#endif
	if (start) {
		if (finish)
			drl = ntfs_rl_replace(drl, ds, srl + sstart, ss, dins);
		else
			drl = ntfs_rl_insert(drl, ds, srl + sstart, ss, dins);
	} else {
		if (finish)
			drl = ntfs_rl_append(drl, ds, srl + sstart, ss, dins);
		else
			drl = ntfs_rl_split(drl, ds, srl + sstart, ss, dins);
	}
	if (!drl) {
		Dprintf("%s(): Merge failed: %s\n", __FUNCTION__,
				strerror(errno));
		return drl;
	}
	free(srl);
	if (marker) {
		Dputs("Triggering marker code.");
		for (ds = dend; drl[ds].length; ds++)
			;
		/* We only need to care if @srl ended after @drl. */
		if (drl[ds].vcn <= marker_vcn) {
			int slots = 0;

			if (drl[ds].vcn == marker_vcn) {
				Dprintf("Old marker = %lli, replacing with "
						"LCN_ENOENT.\n",
						(long long)drl[ds].lcn);
				drl[ds].lcn = (LCN)LCN_ENOENT;
				goto finished;
			}
			/*
			 * We need to create an unmapped runlist element in
			 * @drl or extend an existing one before adding the
			 * ENOENT terminator.
			 */
			if (drl[ds].lcn == (LCN)LCN_ENOENT) {
				ds--;
				slots = 1;
			}
			if (drl[ds].lcn != (LCN)LCN_RL_NOT_MAPPED) {
				/* Add an unmapped runlist element. */
				if (!slots) {
					/* FIXME/TODO: We need to have the
					 * extra memory already! (AIA)
					 */
					drl = ntfs_rl_realloc(drl, ds, ds + 2);
					if (!drl)
						goto critical_error;
					slots = 2;
				}
				ds++;
				/* Need to set vcn if it isn't set already. */
				if (slots != 1)
					drl[ds].vcn = drl[ds - 1].vcn +
							drl[ds - 1].length;
				drl[ds].lcn = (LCN)LCN_RL_NOT_MAPPED;
				/* We now used up a slot. */
				slots--;
			}
			drl[ds].length = marker_vcn - drl[ds].vcn;
			/* Finally add the ENOENT terminator. */
			ds++;
			if (!slots) {
				/* FIXME/TODO: We need to have the extra
				 * memory already! (AIA)
				 */
				drl = ntfs_rl_realloc(drl, ds, ds + 1);
				if (!drl)
					goto critical_error;
			}
			drl[ds].vcn = marker_vcn;
			drl[ds].lcn = (LCN)LCN_ENOENT;
			drl[ds].length = (s64)0;
		}
	}
	}

finished:
	/* The merge was completed successfully. */
	Dputs("Merged runlist:");
	ntfs_debug_runlist_dump(drl);
	return drl;

critical_error:
	/* Critical error! We cannot afford to fail here. */
	Dperror("libntfs: Critical error");
	Dputs("Forcing segmentation fault!");
	marker_vcn = ((runlist*)NULL)->lcn;
	return drl;
}

/**
 * ntfs_mapping_pairs_decompress - convert mapping pairs array to runlist
 * @vol:	ntfs volume on which the attribute resides
 * @attr:	attribute record whose mapping pairs array to decompress
 * @old_rl:	optional runlist in which to insert @attr's runlist
 *
 * Decompress the attribute @attr's mapping pairs array into a runlist. On
 * success, return the decompressed runlist.
 *
 * If @old_rl is not NULL, decompressed runlist is inserted into the
 * appropriate place in @old_rl and the resultant, combined runlist is
 * returned. The original @old_rl is deallocated.
 *
 * On error, return NULL with errno set to the error code. @old_rl is left
 * unmodified in that case.
 *
 * The following error codes are defined:
 *	ENOMEM		Not enough memory to allocate runlist array.
 *	EIO		Corrupt runlist.
 *	EINVAL		Invalid parameters were passed in.
 *	ERANGE		The two runlists overlap.
 *
 * FIXME: For now we take the conceptionally simplest approach of creating the
 * new runlist disregarding the already existing one and then splicing the
 * two into one, if that is possible (we check for overlap and discard the new
 * runlist if overlap present before returning NULL, with errno = ERANGE).
 */
runlist_element *ntfs_mapping_pairs_decompress(const ntfs_volume *vol,
		const ATTR_RECORD *attr, runlist_element *old_rl)
{
	VCN vcn;		/* Current vcn. */
	LCN lcn;		/* Current lcn. */
	s64 deltaxcn;		/* Change in [vl]cn. */
	runlist_element *rl;	/* The output runlist. */
	const u8 *buf;		/* Current position in mapping pairs array. */
	const u8 *attr_end;	/* End of attribute. */
	int err, rlsize;	/* Size of runlist buffer. */
	u16 rlpos;		/* Current runlist position in units of
				   runlist_elements. */
	u8 b;			/* Current byte offset in buf. */

	Dprintf("%s(): Entering for attr 0x%x.\n", __FUNCTION__,
			(unsigned)le32_to_cpu(attr->type));
	/* Make sure attr exists and is non-resident. */
	if (!attr || !attr->non_resident ||
			sle64_to_cpu(attr->lowest_vcn) < (VCN)0) {
		errno = EINVAL;
		return NULL;
	}
	/* Start at vcn = lowest_vcn and lcn 0. */
	vcn = sle64_to_cpu(attr->lowest_vcn);
	lcn = 0;
	/* Get start of the mapping pairs array. */
	buf = (const u8*)attr + le16_to_cpu(attr->mapping_pairs_offset);
	attr_end = (const u8*)attr + le32_to_cpu(attr->length);
	if (buf < (const u8*)attr || buf > attr_end) {
		Dputs("Corrupt attribute.");
		errno = EIO;
		return NULL;
	}
	/* Current position in runlist array. */
	rlpos = 0;
	/* Allocate first 4kiB block and set current runlist size to 4kiB. */
	rl = malloc(rlsize = 0x1000);
	if (!rl)
		return NULL;
	/* Insert unmapped starting element if necessary. */
	if (vcn) {
		rl->vcn = (VCN)0;
		rl->lcn = (LCN)LCN_RL_NOT_MAPPED;
		rl->length = vcn;
		rlpos++;
	}
	while (buf < attr_end && *buf) {
		/*
		 * Allocate more memory if needed, including space for the
		 * not-mapped and terminator elements.
		 */
		if ((int)((rlpos + 3) * sizeof(*old_rl)) > rlsize) {
			runlist_element *rl2;

			rlsize += 0x1000;
			rl2 = realloc(rl, rlsize);
			if (!rl2) {
				int eo = errno;
				free(rl);
				errno = eo;
				return NULL;
			}
			rl = rl2;
		}
		/* Enter the current vcn into the current runlist element. */
		rl[rlpos].vcn = vcn;
		/*
		 * Get the change in vcn, i.e. the run length in clusters.
		 * Doing it this way ensures that we signextend negative values.
		 * A negative run length doesn't make any sense, but hey, I
		 * didn't make up the NTFS specs and Windows NT4 treats the run
		 * length as a signed value so that's how it is...
		 */
		b = *buf & 0xf;
		if (b) {
			if (buf + b > attr_end)
				goto io_error;
			for (deltaxcn = (s8)buf[b--]; b; b--)
				deltaxcn = (deltaxcn << 8) + buf[b];
		} else { /* The length entry is compulsory. */
			Dputs("Missing length entry in mapping pairs array.");
			deltaxcn = (s64)-1;
		}
		/*
		 * Assume a negative length to indicate data corruption and
		 * hence clean-up and return NULL.
		 */
		if (deltaxcn < 0) {
			Dputs("Invalid length in mapping pairs array.");
			goto err_out;
		}
		/*
		 * Enter the current run length into the current runlist
		 * element.
		 */
		rl[rlpos].length = deltaxcn;
		/* Increment the current vcn by the current run length. */
		vcn += deltaxcn;
		/*
		 * There might be no lcn change at all, as is the case for
		 * sparse clusters on NTFS 3.0+, in which case we set the lcn
		 * to LCN_HOLE.
		 */
		if (!(*buf & 0xf0))
			rl[rlpos].lcn = (LCN)LCN_HOLE;
		else {
			/* Get the lcn change which really can be negative. */
			u8 b2 = *buf & 0xf;
			b = b2 + ((*buf >> 4) & 0xf);
			if (buf + b > attr_end)
				goto io_error;
			for (deltaxcn = (s8)buf[b--]; b > b2; b--)
				deltaxcn = (deltaxcn << 8) + buf[b];
			/* Change the current lcn to it's new value. */
			lcn += deltaxcn;
#ifdef DEBUG
			/*
			 * On NTFS 1.2-, apparently can have lcn == -1 to
			 * indicate a hole. But we haven't verified ourselves
			 * whether it is really the lcn or the deltaxcn that is
			 * -1. So if either is found give us a message so we
			 * can investigate it further!
			 */
			if (vol->major_ver < 3) {
				if (deltaxcn == (LCN)-1)
					Dputs("lcn delta == -1");
				if (lcn == (LCN)-1)
					Dputs("lcn == -1");
			}
#endif
			/* Check lcn is not below -1. */
			if (lcn < (LCN)-1) {
				Dputs("Invalid LCN < -1 in mapping pairs "
						"array.");
				goto err_out;
			}
			/* Enter the current lcn into the runlist element. */
			rl[rlpos].lcn = lcn;
		}
		/* Get to the next runlist element. */
		rlpos++;
		/* Increment the buffer position to the next mapping pair. */
		buf += (*buf & 0xf) + ((*buf >> 4) & 0xf) + 1;
	}
	if (buf >= attr_end)
		goto io_error;
	/*
	 * If there is a highest_vcn specified, it must be equal to the final
	 * vcn in the runlist - 1, or something has gone badly wrong.
	 */
	deltaxcn = sle64_to_cpu(attr->highest_vcn);
	if (deltaxcn && vcn - 1 != deltaxcn) {
mpa_err:
		Dputs("Corrupt mapping pairs array in non-resident attribute.");
		goto err_out;
	}
	/* Setup not mapped runlist element if this is the base extent. */
	if (!attr->lowest_vcn) {
		VCN max_cluster;

		max_cluster = ((sle64_to_cpu(attr->allocated_size) +
				vol->cluster_size - 1) >>
				vol->cluster_size_bits) - 1;
		/*
		 * A highest_vcn of zero means this is a single extent
		 * attribute so simply terminate the runlist with LCN_ENOENT).
		 */
		if (deltaxcn) {
			/*
			 * If there is a difference between the highest_vcn and
			 * the highest cluster, the runlist is either corrupt
			 * or, more likely, there are more extents following
			 * this one.
			 */
			if (deltaxcn < max_cluster) {
				Dprintf("More extents to follow; deltaxcn = 0x%llx, "
						"max_cluster = 0x%llx\n",
						(long long)deltaxcn,
						(long long)max_cluster);
				rl[rlpos].vcn = vcn;
				vcn += rl[rlpos].length = max_cluster - deltaxcn;
				rl[rlpos].lcn = (LCN)LCN_RL_NOT_MAPPED;
				rlpos++;
			} else if (deltaxcn > max_cluster) {
				Dprintf("Corrupt attribute. deltaxcn = 0x%llx, "
						"max_cluster = 0x%llx",
						(long long)deltaxcn,
						(long long)max_cluster);
				goto mpa_err;
			}
		}
		rl[rlpos].lcn = (LCN)LCN_ENOENT;
	} else /* Not the base extent. There may be more extents to follow. */
		rl[rlpos].lcn = (LCN)LCN_RL_NOT_MAPPED;

	/* Setup terminating runlist element. */
	rl[rlpos].vcn = vcn;
	rl[rlpos].length = (s64)0;
	/* If no existing runlist was specified, we are done. */
	if (!old_rl) {
		Dputs("Mapping pairs array successfully decompressed:");
		ntfs_debug_runlist_dump(rl);
		return rl;
	}
	/* Now combine the new and old runlists checking for overlaps. */
	old_rl = ntfs_runlists_merge(old_rl, rl);
	if (old_rl)
		return old_rl;
	err = errno;
	free(rl);
	Dputs("Failed to merge runlists.");
	errno = err;
	return NULL;
io_error:
	Dputs("Corrupt attribute.");
err_out:
	free(rl);
	errno = EIO;
	return NULL;
}

/**
 * ntfs_rl_vcn_to_lcn - convert a vcn into a lcn given a runlist
 * @rl:		runlist to use for conversion
 * @vcn:	vcn to convert
 *
 * Convert the virtual cluster number @vcn of an attribute into a logical
 * cluster number (lcn) of a device using the runlist @rl to map vcns to their
 * corresponding lcns.
 *
 * Since lcns must be >= 0, we use negative return values with special meaning:
 *
 * Return value			Meaning / Description
 * ==================================================
 *  -1 = LCN_HOLE		Hole / not allocated on disk.
 *  -2 = LCN_RL_NOT_MAPPED	This is part of the runlist which has not been
 *				inserted into the runlist yet.
 *  -3 = LCN_ENOENT		There is no such vcn in the attribute.
 *  -4 = LCN_EINVAL		Input parameter error.
 */
LCN ntfs_rl_vcn_to_lcn(const runlist_element *rl, const VCN vcn)
{
	int i;

	if (vcn < (VCN)0)
		return (LCN)LCN_EINVAL;
	/*
	 * If rl is NULL, assume that we have found an unmapped runlist. The
	 * caller can then attempt to map it and fail appropriately if
	 * necessary.
	 */
	if (!rl)
		return (LCN)LCN_RL_NOT_MAPPED;

	/* Catch out of lower bounds vcn. */
	if (vcn < rl[0].vcn)
		return (LCN)LCN_ENOENT;

	for (i = 0; rl[i].length; i++) {
		if (vcn < rl[i+1].vcn) {
			if (rl[i].lcn >= (LCN)0)
				return rl[i].lcn + (vcn - rl[i].vcn);
			return rl[i].lcn;
		}
	}
	/*
	 * The terminator element is setup to the correct value, i.e. one of
	 * LCN_HOLE, LCN_RL_NOT_MAPPED, or LCN_ENOENT.
	 */
	if (rl[i].lcn < (LCN)0)
		return rl[i].lcn;
	/* Just in case... We could replace this with BUG() some day. */
	return (LCN)LCN_ENOENT;
}

/**
 * ntfs_rl_pread - gather read from disk
 * @vol:	ntfs volume to read from
 * @rl:		runlist specifying where to read the data from
 * @pos:	byte position within runlist @rl at which to begin the read
 * @count:	number of bytes to read
 * @b:		data buffer into which to read from disk
 *
 * This function will read @count bytes from the volume @vol to the data buffer
 * @b gathering the data as specified by the runlist @rl. The read begins at
 * offset @pos into the runlist @rl.
 *
 * On success, return the number of successfully read bytes. If this number is
 * lower than @count this means that the read reached end of file or that an
 * error was encountered during the read so that the read is partial. 0 means
 * nothing was read (also return 0 when @count is 0).
 *
 * On error and nothing has been read, return -1 with errno set appropriately
 * to the return code of ntfs_pread(), or to EINVAL in case of invalid
 * arguments.
 *
 * NOTE: If we encounter EOF while reading we return EIO because we assume that
 * the run list must point to valid locations within the ntfs volume.
 */
s64 ntfs_rl_pread(const ntfs_volume *vol, const runlist_element *rl,
		const s64 pos, s64 count, void *b)
{
	s64 bytes_read, to_read, ofs, total;
	int err = EIO;

	if (!vol || !rl || pos < 0 || count < 0) {
		errno = EINVAL;
		return -1;
	}
	if (!count)
		return count;
	/* Seek in @rl to the run containing @pos. */
	for (ofs = 0; rl->length && (ofs + (rl->length <<
			vol->cluster_size_bits) <= pos); rl++)
		ofs += (rl->length << vol->cluster_size_bits);
	/* Offset in the run at which to begin reading. */
	ofs = pos - ofs;
	for (total = 0LL; count; rl++, ofs = 0) {
		if (!rl->length)
			goto rl_err_out;
		if (rl->lcn < (LCN)0) {
			if (rl->lcn != (LCN)LCN_HOLE)
				goto rl_err_out;
			/* It is a hole. Just fill buffer @b with zeroes. */
			to_read = min(count, (rl->length <<
					vol->cluster_size_bits) - ofs);
			memset(b, 0, to_read);
			/* Update counters and proceed with next run. */
			total += to_read;
			count -= to_read;
			b = (u8*)b + to_read;
			continue;
		}
		/* It is a real lcn, read it from the volume. */
		to_read = min(count, (rl->length << vol->cluster_size_bits) -
				ofs);
retry:
		bytes_read = ntfs_pread(vol->dev, (rl->lcn <<
				vol->cluster_size_bits) + ofs, to_read, b);
		/* If everything ok, update progress counters and continue. */
		if (bytes_read > 0) {
			total += bytes_read;
			count -= bytes_read;
			b = (u8*)b + bytes_read;
			continue;
		}
		/* If the syscall was interrupted, try again. */
		if (bytes_read == (s64)-1 && errno == EINTR)
			goto retry;
		if (bytes_read == (s64)-1)
			err = errno;
		goto rl_err_out;
	}
	/* Finally, return the number of bytes read. */
	return total;
rl_err_out:
	if (total)
		return total;
	errno = err;
	return -1;
}

/**
 * ntfs_rl_pwrite - scatter write to disk
 * @vol:	ntfs volume to write to
 * @rl:		runlist specifying where to write the data to
 * @pos:	byte position within runlist @rl at which to begin the write
 * @count:	number of bytes to write
 * @b:		data buffer to write to disk
 *
 * This function will write @count bytes from data buffer @b to the volume @vol
 * scattering the data as specified by the runlist @rl. The write begins at
 * offset @pos into the runlist @rl.
 *
 * On success, return the number of successfully written bytes. If this number
 * is lower than @count this means that the write has been interrupted in
 * flight or that an error was encountered during the write so that the write
 * is partial. 0 means nothing was written (also return 0 when @count is 0).
 *
 * On error and nothing has been written, return -1 with errno set
 * appropriately to the return code of ntfs_pwrite(), or to to EINVAL in case
 * of invalid arguments.
 */
s64 ntfs_rl_pwrite(const ntfs_volume *vol, const runlist_element *rl,
		const s64 pos, s64 count, void *b)
{
	s64 written, to_write, ofs, total;
	int err = EIO;

	if (!vol || !rl || pos < 0 || count < 0) {
		errno = EINVAL;
		return -1;
	}
	if (!count)
		return count;
	/* Seek in @rl to the run containing @pos. */
	for (ofs = 0; rl->length && (ofs + (rl->length <<
			vol->cluster_size_bits) <= pos); rl++)
		ofs += (rl->length << vol->cluster_size_bits);
	/* Offset in the run at which to begin writing. */
	ofs = pos - ofs;
	for (total = 0LL; count; rl++, ofs = 0) {
		if (!rl->length)
			goto rl_err_out;
		if (rl->lcn < (LCN)0) {
			s64 t;
			int cnt;

			if (rl->lcn != (LCN)LCN_HOLE)
				goto rl_err_out;
			/*
			 * It is a hole. Check if the buffer is zero in this
			 * region and if not abort with error.
			 */
			to_write = min(count, (rl->length <<
					vol->cluster_size_bits) - ofs);
			written = to_write / sizeof(unsigned long);
			for (t = 0; t < written; t++) {
				if (((unsigned long*)b)[t])
					goto rl_err_out;
			}
			cnt = to_write & (sizeof(unsigned long) - 1);
			if (cnt) {
				int i;
				u8 *b2;

				b2 = (u8*)b + (to_write &
						~(sizeof(unsigned long) - 1));
				for (i = 0; i < cnt; i++) {
					if (b2[i])
						goto rl_err_out;
				}
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
		if (written == (s64)-1)
			err = errno;
		goto rl_err_out;
	}
	/* Finally, return the number of bytes written. */
	return total;
rl_err_out:
	if (total)
		return total;
	errno = err;
	return -1;
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
 * @start_vcn:	vcn at which to start the mapping pairs array
 *
 * Walk the runlist @rl and calculate the size in bytes of the mapping pairs
 * array corresponding to the runlist @rl, starting at vcn @start_vcn.  This
 * for example allows us to allocate a buffer of the right size when building
 * the mapping pairs array.
 *
 * If @rl is NULL, just return 1 (for the single terminator byte).
 *
 * Return the calculated size in bytes on success.  On error, return -1 with
 * errno set to the error code.  The following error codes are defined:
 *	EINVAL	- Run list contains unmapped elements. Make sure to only pass
 *		  fully mapped runlists to this function.
 *		- @start_vcn is invalid.
 *	EIO	- The runlist is corrupt.
 */
int ntfs_get_size_for_mapping_pairs(const ntfs_volume *vol,
		const runlist_element *rl, const VCN start_vcn)
{
	LCN prev_lcn;
	int rls;

	if (start_vcn < 0) {
		Dprintf("%s(): start_vcn %lld (should be >= 0)",
			__FUNCTION__, (long long) start_vcn);
		errno = EINVAL;
		return -1;
	}
	if (!rl) {
		if (start_vcn) {
			Dprintf("%s(): rl NULL, start_vcn %lld (should be > 0)",
				__FUNCTION__, (long long) start_vcn);
			errno = EINVAL;
			return -1;
		}
		return 1;
	}
	/* Skip to runlist element containing @start_vcn. */
	while (rl->length && start_vcn >= rl[1].vcn)
		rl++;
	if ((!rl->length && start_vcn > rl->vcn) || start_vcn < rl->vcn) {
		errno = EINVAL;
		return -1;
	}
	prev_lcn = 0;
	/* Always need the termining zero byte. */
	rls = 1;
	/* Do the first partial run if present. */
	if (start_vcn > rl->vcn) {
		s64 delta;

		/* We know rl->length != 0 already. */
		if (rl->length < 0 || rl->lcn < LCN_HOLE)
			goto err_out;
		delta = start_vcn - rl->vcn;
		/* Header byte + length. */
		rls += 1 + ntfs_get_nr_significant_bytes(rl->length - delta);
		/*
		 * If the logical cluster number (lcn) denotes a hole and we
		 * are on NTFS 3.0+, we don't store it at all, i.e. we need
		 * zero space. On earlier NTFS versions we just store the lcn.
		 * Note: this assumes that on NTFS 1.2-, holes are stored with
		 * an lcn of -1 and not a delta_lcn of -1 (unless both are -1).
		 */
		if (rl->lcn >= 0 || vol->major_ver < 3) {
			prev_lcn = rl->lcn;
			if (rl->lcn >= 0)
				prev_lcn += delta;
			/* Change in lcn. */
			rls += ntfs_get_nr_significant_bytes(prev_lcn);
		}
		/* Go to next runlist element. */
		rl++;
	}
	/* Do the full runs. */
	for (; rl->length; rl++) {
		if (rl->length < 0 || rl->lcn < LCN_HOLE)
			goto err_out;
		/* Header byte + length. */
		rls += 1 + ntfs_get_nr_significant_bytes(rl->length);
		/*
		 * If the logical cluster number (lcn) denotes a hole and we
		 * are on NTFS 3.0+, we don't store it at all, i.e. we need
		 * zero space. On earlier NTFS versions we just store the lcn.
		 * Note: this assumes that on NTFS 1.2-, holes are stored with
		 * an lcn of -1 and not a delta_lcn of -1 (unless both are -1).
		 */
		if (rl->lcn >= 0 || vol->major_ver < 3) {
			/* Change in lcn. */
			rls += ntfs_get_nr_significant_bytes(rl->lcn -
					prev_lcn);
			prev_lcn = rl->lcn;
		}
	}
	return rls;
err_out:
	if (rl->lcn == LCN_RL_NOT_MAPPED)
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
__inline__ int ntfs_write_significant_bytes(u8 *dst, const u8 *dst_max,
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
		*dst = (u8)-1;
	} else if (n > 0LL && j < 0) {
		if (dst > dst_max)
			goto err_out;
		i++;
		*dst = 0;
	}
	return i;
err_out:
	errno = ENOSPC;
	return -1;
}

/**
 * ntfs_mapping_pairs_build - build the mapping pairs array from a runlist
 * @vol:	ntfs volume (needed for the ntfs version)
 * @dst:	destination buffer to which to write the mapping pairs array
 * @dst_len:	size of destination buffer @dst in bytes
 * @rl:		runlist for which to build the mapping pairs array
 * @start_vcn:	vcn at which to start the mapping pairs array
 * @stop_vcn:	first vcn outside destination buffer on success or ENOSPC error
 *
 * Create the mapping pairs array from the runlist @rl, starting at vcn
 * @start_vcn and save the array in @dst.  @dst_len is the size of @dst in
 * bytes and it should be at least equal to the value obtained by calling
 * ntfs_get_size_for_mapping_pairs().
 *
 * If @rl is NULL, just write a single terminator byte to @dst.
 *
 * On success or ENOSPC error, if @stop_vcn is not NULL, *@stop_vcn is set to
 * the first vcn outside the destination buffer. Note that on error @dst has
 * been filled with all the mapping pairs that will fit, thus it can be treated
 * as partial success, in that a new attribute extent needs to be created or the
 * next extent has to be used and the mapping pairs build has to be continued
 * with @start_vcn set to *@stop_vcn.
 *
 * Return 0 on success.  On error, return -1 with errno set to the error code.
 * The following error codes are defined:
 *	EINVAL	- Run list contains unmapped elements. Make sure to only pass
 *		  fully mapped runlists to this function.
 *		- @start_vcn is invalid.
 *	EIO	- The runlist is corrupt.
 *	ENOSPC	- The destination buffer is too small.
 */
int ntfs_mapping_pairs_build(const ntfs_volume *vol, u8 *dst,
		const int dst_len, const runlist_element *rl,
		const VCN start_vcn, VCN *const stop_vcn)
{
	LCN prev_lcn;
	u8 *dst_max, *dst_next;
	s8 len_len, lcn_len;

	if (start_vcn < 0)
		goto val_err;
	if (!rl) {
		if (start_vcn)
			goto val_err;
		if (stop_vcn)
			*stop_vcn = 0;
		if (dst_len < 1) {
			errno = ENOSPC;
			return -1;
		}
		/* Terminator byte. */
		*dst = 0;
		return 0;
	}
	/* Skip to runlist element containing @start_vcn. */
	while (rl->length && start_vcn >= rl[1].vcn)
		rl++;
	if ((!rl->length && start_vcn > rl->vcn) || start_vcn < rl->vcn)
		goto val_err;
	/*
	 * @dst_max is used for bounds checking in
	 * ntfs_write_significant_bytes().
	 */
	dst_max = dst + dst_len - 1;
	prev_lcn = 0;
	/* Do the first partial run if present. */
	if (start_vcn > rl->vcn) {
		s64 delta;

		/* We know rl->length != 0 already. */
		if (rl->length < 0 || rl->lcn < LCN_HOLE)
			goto err_out;
		delta = start_vcn - rl->vcn;
		/* Write length. */
		len_len = ntfs_write_significant_bytes(dst + 1, dst_max,
				rl->length - delta);
		if (len_len < 0)
			goto size_err;
		/*
		 * If the logical cluster number (lcn) denotes a hole and we
		 * are on NTFS 3.0+, we don't store it at all, i.e. we need
		 * zero space. On earlier NTFS versions we just write the lcn
		 * change.  FIXME: Do we need to write the lcn change or just
		 * the lcn in that case?  Not sure as I have never seen this
		 * case on NT4. - We assume that we just need to write the lcn
		 * change until someone tells us otherwise... (AIA)
		 */
		if (rl->lcn >= 0 || vol->major_ver < 3) {
			prev_lcn = rl->lcn;
			if (rl->lcn >= 0)
				prev_lcn += delta;
			/* Write change in lcn. */
			lcn_len = ntfs_write_significant_bytes(dst + 1 +
					len_len, dst_max, prev_lcn);
			if (lcn_len < 0)
				goto size_err;
		} else
			lcn_len = 0;
		dst_next = dst + len_len + lcn_len + 1;
		if (dst_next > dst_max)
			goto size_err;
		/* Update header byte. */
		*dst = lcn_len << 4 | len_len;
		/* Position at next mapping pairs array element. */
		dst = dst_next;
		/* Go to next runlist element. */
		rl++;
	}
	/* Do the full runs. */
	for (; rl->length; rl++) {
		if (rl->length < 0 || rl->lcn < LCN_HOLE)
			goto err_out;
		/* Write length. */
		len_len = ntfs_write_significant_bytes(dst + 1, dst_max,
				rl->length);
		if (len_len < 0)
			goto size_err;
		/*
		 * If the logical cluster number (lcn) denotes a hole and we
		 * are on NTFS 3.0+, we don't store it at all, i.e. we need
		 * zero space. On earlier NTFS versions we just write the lcn
		 * change. FIXME: Do we need to write the lcn change or just
		 * the lcn in that case? Not sure as I have never seen this
		 * case on NT4. - We assume that we just need to write the lcn
		 * change until someone tells us otherwise... (AIA)
		 */
		if (rl->lcn >= 0 || vol->major_ver < 3) {
			/* Write change in lcn. */
			lcn_len = ntfs_write_significant_bytes(dst + 1 +
					len_len, dst_max, rl->lcn - prev_lcn);
			if (lcn_len < 0)
				goto size_err;
			prev_lcn = rl->lcn;
		} else
			lcn_len = 0;
		dst_next = dst + len_len + lcn_len + 1;
		if (dst_next > dst_max)
			goto size_err;
		/* Update header byte. */
		*dst = lcn_len << 4 | len_len;
		/* Position at next mapping pairs array element. */
		dst += 1 + len_len + lcn_len;
	}
	/* Set stop vcn. */
	if (stop_vcn)
		*stop_vcn = rl->vcn;
	/* Add terminator byte. */
	*dst = 0;
	return 0;
size_err:
	/* Set stop vcn. */
	if (stop_vcn)
		*stop_vcn = rl->vcn;
	/* Add terminator byte. */
	*dst = 0;
	errno = ENOSPC;
	return -1;
val_err:
	errno = EINVAL;
	return -1;
err_out:
	if (rl->lcn == LCN_RL_NOT_MAPPED)
		errno = EINVAL;
	else
		errno = EIO;
	return -1;
}

/**
 * ntfs_rl_truncate - truncate a runlist starting at a specified vcn
 * @arl:	address of runlist to truncate
 * @start_vcn:	first vcn which should be cut off
 *
 * Truncate the runlist *@arl starting at vcn @start_vcn as well as the memory
 * buffer holding the runlist.
 *
 * Return 0 on success and -1 on error with errno set to the error code.
 *
 * NOTE: @arl is the address of the runlist. We need the address so we can
 * modify the pointer to the runlist with the new, reallocated memory buffer.
 */
int ntfs_rl_truncate(runlist **arl, const VCN start_vcn)
{
	runlist *rl;
	BOOL is_end;

	if (!arl || !*arl) {
		errno = EINVAL;
		return -1;
	}
	rl = *arl;
	if (start_vcn < rl->vcn) {
		// FIXME: Eeek! BUG()
		Dprintf("%s(): Eeek! start_vcn lies outside front of "
				"runlist!  Aborting.\n", __FUNCTION__);
		errno = EIO;
		return -1;
	}
	/* Find the starting vcn in the run list. */
	while (rl->length) {
		if (start_vcn < rl[1].vcn)
			break;
		rl++;
	}
	if (!rl->length) {
		// FIXME: Weird, probably a BUG()!
		Dprintf("%s(): Weird!  Asking to truncate already truncated "
				"runlist?!?  Abort.\n", __FUNCTION__);
		errno = EIO;
		return -1;
	}
	if (start_vcn < rl->vcn) {
		// FIXME: Eeek! BUG()
		Dprintf("%s(): Eeek!  start_vcn < rl->vcn!  Aborting.\n",
				__FUNCTION__);
		errno = EIO;
		return -1;
	}
	if (rl->length) {
		is_end = FALSE;
		/* Truncate the run. */
		rl->length = start_vcn - rl->vcn;
		/*
		 * If a run was partially truncated, make the following runlist
		 * element a terminator instead of the truncated runlist
		 * element itself.
		 */
		if (rl->length) {
			++rl;
			if (!rl->length)
				is_end = TRUE;
			rl->vcn = start_vcn;
			rl->length = 0;
		}
	} else
		is_end = TRUE;
	rl->lcn = (LCN)LCN_ENOENT;
	/* Reallocate memory if necessary. */
	if (!is_end) {
		size_t new_size = (rl - *arl + 1) * sizeof(runlist_element);
		rl = realloc(*arl, new_size);
		if (rl)
			*arl = rl;
		else if (!new_size)
			*arl = NULL;
		else {
			// FIXME: Eeek!
			Dprintf("%s(): Eeek!  Failed to reallocate runlist "
					"buffer!  Continuing regardless and "
					"returning success.\n", __FUNCTION__);
		}
	}
	/* Done! */
	return 0;
}

/**
 * ntfs_rl_sparse - check whether runlist have sparse regions or not.
 * @rl:		runlist to check
 *
 * Return 1 if have, 0 if not, -1 on error with errno set to the error code.
 */
int ntfs_rl_sparse(runlist *rl)
{
	runlist *rlc;

	if (!rl) {
		Dprintf("%s(): Invalid argument passed.\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	for (rlc = rl; rlc->length; rlc++)
		if (rlc->lcn < 0) {
			if (rlc->lcn != LCN_HOLE) {
				Dprintf("%s(): Received unmapped runlist.\n",
					__FUNCTION__);
				errno = EINVAL;
				return -1;
			}
			return 1;
		}
	return 0;
}

/**
 * ntfs_rl_get_compressed_size - calculate length of non sparse regions
 * @vol:	ntfs volume (need for cluster size)
 * @rl:		runlist to calculate for
 *
 * Return compressed size or -1 on error with errno set to the error code.
 */
s64 ntfs_rl_get_compressed_size(ntfs_volume *vol, runlist *rl)
{
	runlist *rlc;
	s64 ret = 0;

	if (!rl) {
		Dprintf("%s(): Invalid argument passed.\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	for (rlc = rl; rlc->length; rlc++) {
		if (rlc->lcn < 0) {
			if (rlc->lcn != LCN_HOLE) {
				Dprintf("%s(): Received unmapped runlist.\n",
					__FUNCTION__);
				errno = EINVAL;
				return -1;
			}
		} else
			ret += rlc->length;
	}
	return ret << vol->cluster_size_bits;
}
