/*
 * lcnalloc.c - Cluster (de)allocation code. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002 Anton Altaparmakov
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
 *
 * Allocate @count clusters starting at cluster @start_lcn or at the current
 * allocator position if @start_lcn is -1, from the mounted ntfs volume @vol.
 *
 * On success return a runlist describing the allocated cluster(s).
 *
 * On error return NULL with errno set to the error code.
 */
runlist *ntfs_cluster_alloc(ntfs_volume *vol, s64 count, LCN start_lcn)
{
	if (!vol || count < 0 || start_lcn < 0 || !vol->lcnbmp_na) {
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

	if (!vol || !vol->lcnbmp_na || !na || !na->rl || start_vcn < 0 ||
			(count < 0 && count != -1)) {
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

