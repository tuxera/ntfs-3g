/*
 * lcnalloc.c - Cluster (de)allocation code. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002-2003 Anton Altaparmakov
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
#include <errno.h>

#include "types.h"
#include "attrib.h"
#include "bitmap.h"
#include "runlist.h"
#include "volume.h"
#include "lcnalloc.h"


/**
 * ntfs_cluster_alloc - allocate clusters on an ntfs volume
 * @vol:	mounted ntfs volume on which to allocate the clusters
 * @count:	number of clusters to allocate
 * @start_lcn:	starting lcn at which to allocate the clusters (or -1 if none)
 * @zone:	zone from which to allocate the clusters
 *
 * Allocate @count clusters preferably starting at cluster @start_lcn or at the
 * current allocator position if @start_lcn is -1, on the mounted ntfs volume
 * @vol. @zone is either DATA_ZONE for allocation of normal clusters and
 * MFT_ZONE for allocation of clusters for the master file table, i.e. the
 * $MFT/$DATA attribute.
 *
 * On success return a runlist describing the allocated cluster(s).
 *
 * On error return NULL with errno set to the error code.
 *
 * Notes on the allocation algorithm
 * =================================
 *
 * There are two data zones. First is the area between the end of the mft zone
 * and the end of the volume, and second is the area between the start of the
 * volume and the start of the mft zone. On unmodified/standard volumes, the
 * second mft zone doesn't exist due to the mft zone being expanded to cover
 * the start of the volume in order to reserve space for the mft bitmap
 * attribute.
 *
 * This is not the prettiest function but the complexity stems from the need of
 * implementing the mft vs data zoned approach and from the fact that we have
 * access to the lcn bitmap in portions of up to 8192 bytes at a time, so we
 * need to cope with crossing over boundaries of two buffers. Further, the fact
 * that the allocator allows for caller supplied hints as to the location of
 * where allocation should begin and the fact that the allocator keeps track of
 * where in the data zones the next natural allocation should occur, contribute
 * to the complexity of the function. But it should all be worthwhile, because
 * this allocator should: 1) be a full implementation of the MFT zone approach
 * used by Windows, 2) cause reduction in fragmentation as much as possible,
 * and 3) be speedy in allocations (the code is not optimized for speed, but
 * the algorithm is, so further speed improvements are probably possible).
 *
 * FIXME: We should be monitoring cluster allocation and increment the MFT zone
 * size dynamically but this is something for the future. We will just cause
 * heavier fragmentation by not doing it and I am not even sure Windows would
 * grow the MFT zone dynamically, so it might even be correct not to do this.
 * The overhead in doing dynamic MFT zone expansion would be very large and
 * unlikely worth the effort. (AIA)
 *
 * TODO: I have added in double the required zone position pointer wrap around
 * logic which can be optimized to having only one of the two logic sets.
 * However, having the double logic will work fine, but if we have only one of
 * the sets and we get it wrong somewhere, then we get into trouble, so
 * removing the duplicate logic requires _very_ careful consideration of _all_
 * possible code paths. So at least for now, I am leaving the double logic -
 * better safe than sorry... (AIA)
 */
runlist *ntfs_cluster_alloc(ntfs_volume *vol, s64 count, LCN start_lcn,
		const NTFS_CLUSTER_ALLOCATION_ZONES zone)
{
	if (!vol || count < 0 || start_lcn < 0 || !vol->lcnbmp_na ||
			zone < FIRST_ZONE || zone > LAST_ZONE) {
		errno = EINVAL;
		return NULL;
	}

	errno = ENOTSUP;
	return NULL;
}

/**
 * ntfs_cluster_free - free clusters on an ntfs volume
 * @vol:	mounted ntfs volume on which to free the clusters
 * @na:		attribute whose runlist describes the clusters to free
 * @start_vcn:	vcn in @rl at which to start freeing clusters
 * @count:	number of clusters to free or -1 for all clusters
 *
 * Free @count clusters starting at the cluster @start_vcn in the runlist
 * described by the attribute @na from the mounted ntfs volume @vol.
 *
 * If @count is -1, all clusters from @start_vcn to the end of the runlist
 * are deallocated.
 *
 * On success return the number of deallocated clusters (not counting sparse
 * clusters) and on error return -1 with errno set to the error code.
 */
int ntfs_cluster_free(ntfs_volume *vol, ntfs_attr *na, VCN start_vcn, s64 count)
{
	runlist *rl;
	s64 nr_freed, delta, to_free;

	if (!vol || !vol->lcnbmp_na || !na || start_vcn < 0 ||
			(count < 0 && count != -1)) {
		fprintf(stderr, "%s(): Invalid arguments!\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	rl = ntfs_attr_find_vcn(na, start_vcn);
	if (!rl)
		return -1;

	if (rl->lcn < 0 && rl->lcn != LCN_HOLE) {
		errno = EIO;
		return -1;
	}

	/* Find the starting cluster inside the run that needs freeing. */
	delta = start_vcn - rl->vcn;

	/* The number of clusters in this run that need freeing. */
	to_free = rl->length - delta;
	if (count >= 0 && to_free > count)
		to_free = count;

	if (rl->lcn != LCN_HOLE) {
		/* Do the actual freeing of the clusters in this run. */
		if (ntfs_bitmap_clear_run(vol->lcnbmp_na, rl->lcn + delta,
				to_free))
			return -1;
		/* We have freed @to_free real clusters. */
		nr_freed = to_free;
	} else {
		/* No real clusters were freed. */
		nr_freed = 0;
	}

	/* Go to the next run and adjust the number of clusters left to free. */
	++rl;
	if (count >= 0)
		count -= to_free;

	/*
	 * Loop over the remaining runs, using @count as a capping value, and
	 * free them.
	 */
	for (; rl->length && count != 0; ++rl) {
		// FIXME: Need to try ntfs_attr_map_runlist() for attribute
		//	  list support! (AIA)
		if (rl->lcn < 0 && rl->lcn != LCN_HOLE) {
			// FIXME: Eeek! We need rollback! (AIA)
			fprintf(stderr, "%s(): Eeek! invalid lcn (= %Li). "
					"Should attempt to map runlist! "
					"Leaving inconsistent metadata!\n",
					__FUNCTION__, (long long)rl->lcn);
			errno = EIO;
			return -1;
		}

		/* The number of clusters in this run that need freeing. */
		to_free = rl->length;
		if (count >= 0 && to_free > count)
			to_free = count;

		if (rl->lcn != LCN_HOLE) {
			/* Do the actual freeing of the clusters in the run. */
			if (ntfs_bitmap_clear_run(vol->lcnbmp_na, rl->lcn,
					to_free)) {
				int eo = errno;

				// FIXME: Eeek! We need rollback! (AIA)
				fprintf(stderr, "%s(): Eeek! bitmap clear run "
						"failed. Leaving inconsistent "
						"metadata!\n", __FUNCTION__);
				errno = eo;
				return -1;
			}
			/* We have freed @to_free real clusters. */
			nr_freed += to_free;
		}

		if (count >= 0)
			count -= to_free;
	}

	if (count != -1 && count != 0) {
		// FIXME: Eeek! BUG()
		fprintf(stderr, "%s(): Eeek! count still not zero (= %Li). "
				"Leaving inconsistent metadata!\n",
				__FUNCTION__, (long long)count);
		errno = EIO;
		return -1;
	}

	/* Done. Return the number of actual clusters that were freed. */
	return nr_freed;
}

