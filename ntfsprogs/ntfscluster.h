/*
 * ntfscluster - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002 Richard Russon <ntfs@flatcap.org>
 *
 * This utility will XXX
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _NTFSCLUSTER_H_
#define _NTFSCLUSTER_H_

#include "types.h"

struct options {
	char	*device;	/* Device/File to work with */
	int	 info;		/* Show volume info */
	int	 quiet;		/* Less output */
	int	 verbose;	/* Extra output */
	int	 force;		/* Override common sense */
	u64	 sector_begin;	/* Look for objects in this range of sectors */
	u64	 sector_end;
	u64	 cluster_begin;	/* Look for objects in this range of clusters */
	u64	 cluster_end;
};

#endif /* _NTFSCLUSTER_H_ */


