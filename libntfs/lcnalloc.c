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

//#include <stdio.h>
//#include <string.h>
//#include <stdlib.h>

#include <errno.h>

#include "types.h"
#include "attrib.h"
#include "runlist.h"
#include "volume.h"
#include "lcnalloc.h"

//#include "debug.h"

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
 * @rl:		runlist describing the clusters to free
 * @start_vcn:	starting relative vcn into @rl at which to free the clusters
 * @count:	number of clusters to free or -1 for all clusters
 *
 * Free @count clusters starting at the cluster @start_vcn in the runlist @rl
 * from the mounted ntfs volume @vol.
 *
 * If @count is -1, all clusters from @start_vcn to the end of the runlist
 * are deallocated.
 *
 * On success return the number of deallocated clusters (not counting sparse
 * clusters) and on error return -1 with errno set to the error code.
 */
int ntfs_cluster_free(ntfs_volume *vol, runlist *rl, VCN start_vcn, s64 count)
{
	if (!vol || !rl || start_vcn < 0 || count < 0 || !vol->lcnbmp_na) {
		errno = EINVAL;
		return -1;
	}

	errno = ENOTSUP;
	return -1;
}

