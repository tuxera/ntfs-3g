/*
 * utils.h - Originated from the Linux-NTFS project.
 *
 * Copyright (c) 2002-2005 Richard Russon
 * Copyright (c) 2004 Anton Altaparmakov
 * Copyright (c) 2005-2007 Szabolcs Szakacsits
 *
 * A set of shared functions for ntfs utilities
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
 * along with this program (in the main directory of the NTFS-3G
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _NTFS_UTILS_H_
#define _NTFS_UTILS_H_

#include "volume.h"

extern const char *ntfs_home;
extern const char *ntfs_gpl;

int utils_set_locale(void);

ntfs_volume *utils_mount_volume(const char *device, const char *mntpoint,
				unsigned long flags);

#endif /* _NTFS_UTILS_H_ */
