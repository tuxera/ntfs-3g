/*
 * $Id$
 *
 * runlist.c - Run list handling code. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002 Anton Altaparmakov.
 * Copyright (c) 2002 Richard Russon.
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

#include "types.h"
#include "attrib.h"
#include "volume.h"
#include "layout.h"
#include "debug.h"
#include "disk_io.h"

/**
 * Internal:
 *
 * ntfs_rl_mm - run_list memmove
 */
static __inline__ void ntfs_rl_mm(run_list_element *base, int dst, int src,
		int size)
{
	if ((dst != src) && (size > 0))
		memmove(base + dst, base + src, size * sizeof(*base));
}

/**
 * Internal:
 *
 * rl_mc - run_list memory copy
 */
static __inline__ void ntfs_rl_mc(run_list_element *dstbase, int dst,
		run_list_element *srcbase, int src, int size)
{
	if (size > 0)
		memcpy(dstbase + dst, srcbase + src, size * sizeof(*dstbase));
}

/**
 * Internal:
 *
 * ntfs_rl_realloc - Reallocate memory for run_lists*
 * @rl:		original run list
 * @old_size:	number of run list elements in the original run list @rl
 * @new_size:	number of run list elements we need space for
 *
 * As the run lists grow, more memory will be required. To prevent large
 * numbers of small reallocations of memory, this function returns a 4kiB block
 * of memory.
 *
 * N.B.	If the new allocation doesn't require a different number of 4kiB
 *	blocks in memory, the function will return the original pointer.
 *
 * On success, return a pointer to the newly allocated, or recycled, memory.
 * On error, return NULL with errno set to the error code.
 */
static __inline__ run_list_element *ntfs_rl_realloc(run_list_element *rl,
		int old_size, int new_size)
{
	old_size = (old_size * sizeof(run_list_element) + 0xfff) & ~0xfff;
	new_size = (new_size * sizeof(run_list_element) + 0xfff) & ~0xfff;
	if (old_size == new_size)
		return rl;
	return realloc(rl, new_size);
}

/**
 * Internal:
 *
 * ntfs_are_rl_mergeable - test if two run lists can be joined together
 * @dst:	original run list
 * @src:	new run list to test for mergeability with @dst
 *
 * Test if two run lists can be joined together. For this, their VCNs and LCNs
 * must be adjacent.
 *
 * Return: TRUE   Success, the run lists can be merged.
 *	   FALSE  Failure, the run lists cannot be merged.
 */
static __inline__ BOOL ntfs_are_rl_mergeable(run_list_element *dst,
		run_list_element *src)
{
	if (!dst || !src) {
		Dputs("Eeek. ntfs_are_rl_mergeable() invoked with NULL "
				"pointer!");
		return FALSE;
	}

	if ((dst->lcn < 0) || (src->lcn < 0))     /* Are we merging holes? */
		return FALSE;
	if ((dst->lcn + dst->length) != src->lcn) /* Are the runs contiguous? */
		return FALSE;
	if ((dst->vcn + dst->length) != src->vcn) /* Are the runs misaligned? */
		return FALSE;

	return TRUE;
}

/**
 * Internal:
 *
 * __ntfs_rl_merge - merge two run lists without testing if they can be merged
 * @dst:	original, destination run list
 * @src:	new run list to merge with @dst
 *
 * Merge the two run lists, writing into the destination run list @dst. The
 * caller must make sure the run lists can be merged or this will corrupt the
 * destination run list.
 */
static __inline__ void __ntfs_rl_merge(run_list_element *dst,
		run_list_element *src)
{
	dst->length += src->length;
}

/**
 * Internal:
 *
 * ntfs_rl_merge - test if two run lists can be joined together and merge them
 * @dst:	original, destination run list
 * @src:	new run list to merge with @dst
 *
 * Test if two run lists can be joined together. For this, their VCNs and LCNs
 * must be adjacent. If they can be merged, perform the merge, writing into
 * the destination run list @dst.
 *
 * Return: TRUE   Success, the run lists have been merged.
 *	   FALSE  Failure, the run lists cannot be merged and have not been
 *		  modified.
 */
static __inline__ BOOL ntfs_rl_merge(run_list_element *dst,
		run_list_element *src)
{
	BOOL merge = ntfs_are_rl_mergeable(dst, src);

	if (merge)
		__ntfs_rl_merge(dst, src);
	return merge;
}

/**
 * Internal:
 *
 * ntfs_rl_append - append a run list after a given element
 * @dst:	original run list to be worked on
 * @dsize:	number of elements in @dst (including end marker)
 * @src:	run list to be inserted into @dst
 * @ssize:	number of elements in @src (excluding end marker)
 * @loc:	append the new run list @src after this element in @dst
 *
 * Append the run list @src after element @loc in @dst.  Merge the right end of
 * the new run list, if necessary. Adjust the size of the hole before the
 * appended run list.
 *
 * On success, return a pointer to the new, combined, run list. Note, both
 * run lists @dst and @src are deallocated before returning so you cannot use
 * the pointers for anything any more. (Strictly speaking the returned run list
 * may be the same as @dst but this is irrelevant.)
 *
 * On error, return NULL, with errno set to the error code. Both run lists are
 * left unmodified.
 */
static __inline__ run_list_element *ntfs_rl_append(run_list_element *dst,
		int dsize, run_list_element *src, int ssize, int loc)
{
	BOOL right;
	int magic;

	if (!dst || !src) {
		Dputs("Eeek. ntfs_rl_append() invoked with NULL pointer!");
		errno = EINVAL;
		return NULL;
	}

	/* First, check if the right hand end needs merging. */
	right = ntfs_are_rl_mergeable(src + ssize - 1, dst + loc + 1);

	/* Space required: @dst size + @src size, less one if we merged. */
	dst = ntfs_rl_realloc(dst, dsize, dsize + ssize - right);
	if (!dst)
		return dst;
	/*
	 * We are guaranteed to succeed from here so can start modifying the
	 * original run lists.
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
 * ntfs_rl_insert - insert a run list into another
 * @dst:	original run list to be worked on
 * @dsize:	number of elements in @dst (including end marker)
 * @src:	new run list to be inserted
 * @ssize:	number of elements in @src (excluding end marker)
 * @loc:	insert the new run list @src before this element in @dst
 *
 * Insert the run list @src before element @loc in the run list @dst. Merge the
 * left end of the new run list, if necessary. Adjust the size of the hole
 * after the inserted run list.
 *
 * On success, return a pointer to the new, combined, run list. Note, both
 * run lists @dst and @src are deallocated before returning so you cannot use
 * the pointers for anything any more. (Strictly speaking the returned run list
 * may be the same as @dst but this is irrelevant.)
 *
 * On error, return NULL, with errno set to the error code. Both run lists are
 * left unmodified.
 */
static __inline__ run_list_element *ntfs_rl_insert(run_list_element *dst,
		int dsize, run_list_element *src, int ssize, int loc)
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
	 *	   extend to match the discontinuity. */
	if (loc == 0)
		disc = (src[0].vcn > 0);
	else {
		s64 merged_length;

		left = ntfs_are_rl_mergeable(dst + loc - 1, src);

		merged_length = dst[loc - 1].length;
		if (left)
			merged_length += src->length;

		disc = (src[0].vcn > dst[loc - 1].vcn + merged_length);
		if (disc)
			hole = (dst[loc - 1].lcn == LCN_HOLE);
	}

	/* Space required: @dst size + @src size, less one if we merged, plus
	 * one if there was a discontinuity, less one for a trailing hole. */
	dst = ntfs_rl_realloc(dst, dsize, dsize + ssize - left + disc - hole);
	if (!dst)
		return dst;
	/*
	 * We are guaranteed to succeed from here so can start modifying the
	 * original run list.
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
 * ntfs_rl_replace - overwrite a run_list element with another run list
 * @dst:	original run list to be worked on
 * @dsize:	number of elements in @dst (including end marker)
 * @src:	new run list to be inserted
 * @ssize:	number of elements in @src (excluding end marker)
 * @loc:	index in run list @dst to overwrite with @src
 *
 * Replace the run list element @dst at @loc with @src. Merge the left and
 * right ends of the inserted run list, if necessary.
 *
 * On success, return a pointer to the new, combined, run list. Note, both
 * run lists @dst and @src are deallocated before returning so you cannot use
 * the pointers for anything any more. (Strictly speaking the returned run list
 * may be the same as @dst but this is irrelevant.)
 *
 * On error, return NULL, with errno set to the error code. Both run lists are
 * left unmodified.
 */
static __inline__ run_list_element *ntfs_rl_replace(run_list_element *dst,
		int dsize, run_list_element *src, int ssize, int loc)
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
	right = ntfs_are_rl_mergeable(src + ssize - 1, dst + loc + 1);
	if (loc > 0)
		left = ntfs_are_rl_mergeable(dst + loc - 1, src);

	/* Allocate some space. We'll need less if the left, right, or both
	 * ends were merged. */
	dst = ntfs_rl_realloc(dst, dsize, dsize + ssize - left - right);
	if (!dst)
		return dst;
	/*
	 * We are guaranteed to succeed from here so can start modifying the
	 * original run lists.
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
 * ntfs_rl_split - insert a run list into the centre of a hole
 * @dst:	original run list to be worked on
 * @dsize:	number of elements in @dst (including end marker)
 * @src:	new run list to be inserted
 * @ssize:	number of elements in @src (excluding end marker)
 * @loc:	index in run list @dst at which to split and insert @src
 *
 * Split the run list @dst at @loc into two and insert @new in between the two
 * fragments. No merging of run lists is necessary. Adjust the size of the
 * holes either side.
 *
 * On success, return a pointer to the new, combined, run list. Note, both
 * run lists @dst and @src are deallocated before returning so you cannot use
 * the pointers for anything any more. (Strictly speaking the returned run list
 * may be the same as @dst but this is irrelevant.)
 *
 * On error, return NULL, with errno set to the error code. Both run lists are
 * left unmodified.
 */
static __inline__ run_list_element *ntfs_rl_split(run_list_element *dst,
		int dsize, run_list_element *src, int ssize, int loc)
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
	 * original run lists.
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
 * ntfs_merge_run_lists - merge two run lists into one
 * @drl:	original run list to be worked on
 * @srl:	new run list to be merged into @drl
 *
 * First we sanity check the two run lists @srl and @drl to make sure that they
 * are sensible and can be merged. The run list @srl must be either after the
 * run list @drl or completely within a hole (or unmapped region) in @drl.
 *
 * Merging of run lists is necessary in two cases:
 *   1. When attribute lists are used and a further extent is being mapped.
 *   2. When new clusters are allocated to fill a hole or extend a file.
 *
 * There are four possible ways @srl can be merged. It can:
 *	- be inserted at the beginning of a hole,
 *	- split the hole in two and be inserted between the two fragments,
 *	- be appended at the end of a hole, or it can
 *	- replace the whole hole.
 * It can also be appended to the end of the run list, which is just a variant
 * of the insert case.
 *
 * On success, return a pointer to the new, combined, run list. Note, both
 * run lists @drl and @srl are deallocated before returning so you cannot use
 * the pointers for anything any more. (Strictly speaking the returned run list
 * may be the same as @dst but this is irrelevant.)
 *
 * On error, return NULL, with errno set to the error code. Both run lists are
 * left unmodified. The following error codes are defined:
 *	ENOMEM		Not enough memory to allocate run list array.
 *	EINVAL		Invalid parameters were passed in.
 *	ERANGE		The run lists overlap and cannot be merged.
 */
run_list_element *ntfs_merge_run_lists(run_list_element *drl,
		run_list_element *srl)
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
	ntfs_debug_dump_run_list(drl);
	Dputs("src:");
	ntfs_debug_dump_run_list(srl);

	/* Check for silly calling... */
	if (!srl)
		return drl;

	/* Check for the case where the first mapping is being done now. */
	if (!drl) {
		drl = srl;
		/* Complete the source run list if necessary. */
		if (drl[0].vcn) {
			/* Scan to the end of the source run list. */
			for (dend = 0; drl[dend].length; dend++)
				;
			drl = ntfs_rl_realloc(drl, dend, dend + 1);
			if (!drl)
				return drl;
			/* Insert start element at the front of the run list. */
			ntfs_rl_mm(drl, 1, 0, dend);
			drl[0].vcn = 0;
			drl[0].lcn = LCN_RL_NOT_MAPPED;
			drl[0].length = drl[1].vcn;
		}
		goto finished;
	}

	si = di = 0;

	/* Skip any unmapped start element(s) in the source run list. */
	while (srl[si].length && srl[si].lcn < (LCN)LCN_HOLE)
		si++;

	/* Can't have an entirely unmapped source run list. */
	if (!srl[si].length) {
		Dputs("Eeek! ntfs_merge_run_lists() received entirely "
				"unmapped source run list.");
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

	/* Scan to the end of both run lists in order to know their sizes. */
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
				Dprintf("Old marker = %Li, replacing with "
						"LCN_ENOENT.\n",
						(long long)drl[ds].lcn);
				drl[ds].lcn = (LCN)LCN_ENOENT;
				goto finished;
			}
			/*
			 * We need to create an unmapped run list element in
			 * @drl or extend an existing one before adding the
			 * ENOENT terminator.
			 */
			if (drl[ds].lcn == (LCN)LCN_ENOENT) {
				ds--;
				slots = 1;
			}
			if (drl[ds].lcn != (LCN)LCN_RL_NOT_MAPPED) {
				/* Add an unmapped run list element. */
				if (!slots) {
					/* FIXME/TODO: We need to have the
					 * extra memory already! (AIA) */
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
				 * memory already! (AIA) */
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
	Dputs("Merged run list:");
	ntfs_debug_dump_run_list(drl);
	return drl;

critical_error:
	/* Critical error! We cannot afford to fail here. */
	Dperror("libntfs: Critical error");
	Dputs("Forcing segmentation fault!");
	marker_vcn = ((run_list*)NULL)->lcn;
	return drl;
}

/**
 * ntfs_decompress_mapping_pairs - convert mapping pairs array to run list
 * @vol:	ntfs volume on which the attribute resides
 * @attr:	attribute record whose mapping pairs array to decompress
 * @old_rl:	optional run list in which to insert @attr's run list
 *
 * Decompress the attribute @attr's mapping pairs array into a run list. On
 * success, return the decompressed run list.
 *
 * If @old_rl is not NULL, decompressed run list is inserted into the
 * appropriate place in @old_rl and the resultant, combined run list is
 * returned. The original @old_rl is deallocated.
 *
 * On error, return NULL with errno set to the error code. @old_rl is left
 * unmodified in that case.
 *
 * The following error codes are defined:
 *	ENOMEM		Not enough memory to allocate run list array.
 *	EIO		Corrupt run list.
 *	EINVAL		Invalid parameters were passed in.
 *	ERANGE		The two run lists overlap.
 *
 * FIXME: For now we take the conceptionally simplest approach of creating the
 * new run list disregarding the already existing one and then splicing the
 * two into one, if that is possible (we check for overlap and discard the new
 * run list if overlap present before returning NULL, with errno = ERANGE).
 */
run_list_element *ntfs_decompress_mapping_pairs(const ntfs_volume *vol,
		const ATTR_RECORD *attr, run_list_element *old_rl)
{
	VCN vcn;		/* Current vcn. */
	LCN lcn;		/* Current lcn. */
	s64 deltaxcn;		/* Change in [vl]cn. */
	run_list_element *rl;	/* The output run list. */
	u8 *buf;		/* Current position in mapping pairs array. */
	u8 *attr_end;		/* End of attribute. */
	int rlsize;		/* Size of run list buffer. */
	u16 rlpos;		/* Current run list position in units of
				   run_list_elements. */
	u8 b;			/* Current byte offset in buf. */

	Dprintf("%s(): Entering for attr 0x%x.\n", __FUNCTION__,
			le32_to_cpu(attr->type));
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
	buf = (u8*)attr + le16_to_cpu(attr->mapping_pairs_offset);
	attr_end = (u8*)attr + le32_to_cpu(attr->length);
	if (buf < (u8*)attr || buf > attr_end) {
		Dputs("Corrupt attribute.");
		errno = EIO;
		return NULL;
	}
	/* Current position in run list array. */
	rlpos = 0;
	/* Allocate first 4kiB block and set current run list size to 4kiB. */
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
		if (((rlpos + 3) * sizeof(*old_rl)) > rlsize) {
			run_list_element *rl2;

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
		/* Enter the current vcn into the current run_list element. */
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
		 * Enter the current run length into the current run list
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
			/* Enter the current lcn into the run list element. */
			rl[rlpos].lcn = lcn;
		}
		/* Get to the next run list element. */
		rlpos++;
		/* Increment the buffer position to the next mapping pair. */
		buf += (*buf & 0xf) + ((*buf >> 4) & 0xf) + 1;
	}
	if (buf >= attr_end)
		goto io_error;
	/*
	 * If there is a highest_vcn specified, it must be equal to the final
	 * vcn in the run list - 1, or something has gone badly wrong.
	 */
	deltaxcn = sle64_to_cpu(attr->highest_vcn);
	if (deltaxcn && vcn - 1 != deltaxcn) {
mpa_err:
		Dputs("Corrupt mapping pairs array in non-resident attribute.");
		goto err_out;
	}
	/* Setup not mapped run list element if this is the base extent. */
	if (!attr->lowest_vcn) {
		VCN max_cluster;

		max_cluster = (sle64_to_cpu(attr->allocated_size) +
				vol->cluster_size - 1) >>
				vol->cluster_size_bits;
		/*
		 * If there is a difference between the highest_vcn and the
		 * highest cluster, the run list is either corrupt or, more
		 * likely, there are more extents following this one.
		 */
		if (deltaxcn < --max_cluster) {
			Dprintf("More extents to follow; deltaxcn = 0x%Lx, "
					"max_cluster = 0x%Lx\n",
					(long long)deltaxcn,
					(long long)max_cluster);
			rl[rlpos].vcn = vcn;
			vcn += rl[rlpos].length = max_cluster - deltaxcn;
			rl[rlpos].lcn = (LCN)LCN_RL_NOT_MAPPED;
			rlpos++;
		} else if (deltaxcn > max_cluster) {
			Dprintf("Corrupt attribute. deltaxcn = 0x%Lx, "
					"max_cluster = 0x%Lx",
					(long long)deltaxcn,
					(long long)max_cluster);
			goto mpa_err;
		}
		rl[rlpos].lcn = (LCN)LCN_ENOENT;
	} else /* Not the base extent. There may be more extents to follow. */
		rl[rlpos].lcn = (LCN)LCN_RL_NOT_MAPPED;

	/* Setup terminating run_list element. */
	rl[rlpos].vcn = vcn;
	rl[rlpos].length = (s64)0;
	/* If no existing run list was specified, we are done. */
	if (!old_rl) {
		Dputs("Mapping pairs array successfully decompressed:");
		ntfs_debug_dump_run_list(rl);
		return rl;
	}
	/* Now combine the new and old run lists checking for overlaps. */
	old_rl = ntfs_merge_run_lists(old_rl, rl);
	if (old_rl)
		return old_rl;
	free(rl);
	Dputs("Failed to merge run lists.");
	return NULL;
io_error:
	Dputs("Corrupt attribute.");
err_out:
	free(rl);
	errno = EIO;
	return NULL;
}

/**
 * ntfs_rl_vcn_to_lcn - convert a vcn into a lcn given a run list
 * @rl:		run list to use for conversion
 * @vcn:	vcn to convert
 *
 * Convert the virtual cluster number @vcn of an attribute into a logical
 * cluster number (lcn) of a device using the run list @rl to map vcns to their
 * corresponding lcns.
 *
 * Since lcns must be >= 0, we use negative return values with special meaning:
 *
 * Return value			Meaning / Description
 * ==================================================
 *  -1 = LCN_HOLE		Hole / not allocated on disk.
 *  -2 = LCN_RL_NOT_MAPPED	This is part of the run list which has not been
 *				inserted into the run list yet.
 *  -3 = LCN_ENOENT		There is no such vcn in the attribute.
 *  -4 = LCN_EINVAL		Input parameter error.
 */
LCN ntfs_rl_vcn_to_lcn(const run_list_element *rl, const VCN vcn)
{
	int i;

	if (vcn < (VCN)0)
		return (LCN)LCN_EINVAL;
	/*
	 * If rl is NULL, assume that we have found an unmapped run list. The
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
 * ntfs_rl_pwrite - scatter write to disk
 * @vol:	ntfs volume to write to
 * @rl:		run list specifying where to write the data to
 * @pos:	byte position within run list @rl at which to begin the write
 * @count:	number of bytes to write
 * @b:		data buffer to write to disk
 *
 * This function will write @count bytes from data buffer @b to the volume @vol
 * scattering the data as specified by the run list @rl. The write begins at
 * offset @pos into the run list @rl.
 *
 * On success, return the number of successfully written bytes. If this number
 * is lower than @count this means that the write has been interrupted in
 * flight or that an error was encountered during the write so that the write
 * is partial. 0 means nothing was written (also return 0 when @count is 0).
 *
 * On error and nothing has been written, return -1 with errno set
 * appropriately to the return code of either lseek, write, fdatasync, or set
 * to EINVAL in case of invalid arguments.
 */
s64 ntfs_rl_pwrite(const ntfs_volume *vol, const run_list_element *rl,
		const s64 pos, s64 count, void *b)
{
	s64 written, to_write, ofs, total;
	int f, err = EIO;

	if (!vol || !rl || pos < 0 || count < 0) {
		errno = EINVAL;
		return -1;
	}
	f = vol->fd;
	if (!f) {
		errno = EBADF;
		return -1;
	}
	if (!count)
		return count;
	/* Seek in @rl to the run containing @pos. */
	for (ofs = 0; rl->length && (ofs + rl->length <= pos); rl++)
		ofs += rl->length;
	/* Offset in the run at which to begin writing. */
	ofs = pos - ofs;
	for (total = 0LL; count; rl++, ofs = 0) {
		if (!rl->length)
			goto rl_err_out;
		if (rl->lcn < (LCN) 0) {
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
			(u8*)b += to_write;
			continue;
		}
		/* It is a real lcn, write it to the volume. */
		to_write = min(count, (rl->length << vol->cluster_size_bits) -
				ofs);
retry:
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
		if (written == -1)
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
 * ntfs_build_mapping_pairs - build the mapping pairs array from a run list
 * @vol:	ntfs volume (needed for the ntfs version)
 * @dst:	destination buffer to which to write the mapping pairs array
 * @dst_len:	size of destination buffer @dst in bytes
 * @rl:		run list for which to build the mapping pairs array
 *
 * Create the mapping pairs array from the run list @rl and save the array in
 * @dst. @dst_len is the size of @dst in bytes and it should be at least equal
 * to the value obtained by calling ntfs_get_size_for_mapping_pairs(@rl).
 *
 * Return 0 on success or when @rl is NULL. On error, return -1 with errno set
 * to the error code. The following error codes are defined:
 *	EINVAL	- Run list contains unmapped elements. Make sure to only pass
 *		  fully mapped run lists to this function.
 *	EIO	- The run list is corrupt.
 *	ENOSPC	- The destination buffer is too small.
 */
int ntfs_build_mapping_pairs(const ntfs_volume *vol, s8 *dst,
		const int dst_len, const run_list_element *rl)
{
	LCN prev_lcn;
	s8 *dst_max;
	int i;
	s8 len_len, lcn_len;

	if (!rl)
		return 0;
	/*
	 * @dst_max is used for bounds checking in
	 * ntfs_write_significant_bytes().
	 */
	dst_max = dst + dst_len - 1;
	for (prev_lcn = i = 0; rl[i].length; prev_lcn = rl[++i].lcn) {
		if (rl[i].length < 0 || rl[i].lcn < LCN_HOLE)
			goto err_out;
		/* Write length. */
		len_len = ntfs_write_significant_bytes(dst + 1, dst_max,
				rl[i].length);
		if (len_len < 0)
			goto size_err;
		/*
		 * If the logical cluster number (lcn) denotes a hole and we
		 * are on NTFS 3.0+, we don't store it at all, i.e. we need
		 * zero space. On earlier NTFS versions we just write the lcn
		 * change. FIXME: Do we need to write the lcn change or just
		 * the lcn in that case? Not sure as I have never seen this
		 * case on NT4. (AIA)
		 */
		if (rl[i].lcn != LCN_HOLE || vol->major_ver < 3) {
			lcn_len = ntfs_write_significant_bytes(dst + 1 +
					len_len, dst_max, rl[i].lcn - prev_lcn);
			if (lcn_len < 0)
				goto size_err;
		} else
			lcn_len = 0;
		/* Update header byte. */
		*dst = lcn_len << 4 | len_len;
		/* Position ourselves at next mapping pairs array element. */
		dst += 1 + len_len + lcn_len;
	}
	if (dst <= dst_max) {
		/* Terminator byte. */
		*dst = 0;
		return 0;
	}
size_err:
	errno = ENOSPC;
	return -1;
err_out:
	if (rl[i].lcn == LCN_RL_NOT_MAPPED)
		errno = EINVAL;
	else
		errno = EIO;
	return -1;
}



