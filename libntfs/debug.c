/*
 * $Id$
 *
 * debug.c - Debugging output functions. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002 Anton Altaparmakov.
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

#include "debug.h"

#ifdef DEBUG
/**
 * ntfs_debug_dump_run_list - Dump a run list.
 */
void ntfs_debug_dump_run_list(const run_list_element *rl)
{
	int i = 0;
	const char *lcn_str[5] = { "LCN_HOLE         ", "LCN_RL_NOT_MAPPED",
				   "LCN_ENOENT       ", "LCN_EINVAL       ",
				   "LCN_unknown      " };

	Dputs("NTFS-fs DEBUG: Dumping run list (values in hex):");
	if (!rl) {
		Dputs("Run list not present.");
		return;
	}
	Dputs("VCN              LCN               Run length");
	do {
		LCN lcn = (rl + i)->lcn;

		if (lcn < (LCN)0) {
			int index = -lcn - 1;

			if (index > -LCN_EINVAL - 1)
				index = 4;
			Dprintf("%-16Lx %s %-16Lx%s\n", rl[i].vcn,
					lcn_str[index], rl[i].length,
					rl[i].length ? "" : " (run list end)");
		} else
			Dprintf("%-16Lx %-16Lx  %-16Lx%s\n", rl[i].vcn,
					rl[i].lcn, rl[i].length,
					rl[i].length ? "" : " (run list end)");
	} while (rl[i++].length);
}

#endif

