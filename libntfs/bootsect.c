/*
 * bootsect.c - Boot sector handling code. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2000-2002 Anton Altaparmakov
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "compat.h"

#include "bootsect.h"
#include "debug.h"

/**
 * ntfs_boot_sector_is_ntfs - check if buffer contains a valid ntfs boot sector
 * @b:		buffer containing putative boot sector to analyze
 * @silent:	if zero, output progress messages to stderr
 *
 * Check if the buffer @b contains a valid ntfs boot sector. The buffer @b
 * must be at least 512 bytes in size.
 *
 * If @silent is zero, output progress messages to stderr. Otherwise, do not
 * output any messages (except when configured with --enable-debug in which
 * case warning/debug messages may be displayed).
 *
 * Return TRUE if @b contains a valid ntfs boot sector and FALSE if not.
 */
BOOL ntfs_boot_sector_is_ntfs(NTFS_BOOT_SECTOR *b, const BOOL silent)
{
	u32 i;

	if (!silent)
		fprintf(stderr, "\nBeginning bootsector check...\n");

	/* Calculate the checksum. Note, this is just a simple addition of
	   all u32 values in the bootsector starting at the beginning and
	   finishing at the offset of the checksum itself (i.e. not including
	   the checksum...). */
	if ((void*)b < (void*)&b->checksum) {
		u32 *u = (u32 *)b;
		u32 *bi = (u32 *)(&b->checksum);

		if (!silent)
			fprintf(stderr, "Calculating bootsector checksum... ");

		for (i = 0; u < bi; ++u)
			i += le32_to_cpup(u);

		if (le32_to_cpu(b->checksum) && le32_to_cpu(b->checksum) != i)
			goto not_ntfs;
		if (!silent)
			fprintf(stderr, "OK\n");
	}

	/* Check OEMidentifier is "NTFS    " */
	if (!silent)
		fprintf(stderr, "Checking OEMid... ");
	if (b->oem_id != cpu_to_le64(0x202020205346544eULL)) /* "NTFS    " */
		goto not_ntfs;
	if (!silent)
		fprintf(stderr, "OK\n");

	/* Check bytes per sector value is between 256 and 4096. */
	if (!silent)
		fprintf(stderr, "Checking bytes per sector... ");
	if (le16_to_cpu(b->bpb.bytes_per_sector) <  0x100 ||
	    le16_to_cpu(b->bpb.bytes_per_sector) > 0x1000)
		goto not_ntfs;
	if (!silent)
		fprintf(stderr, "OK\n");

	/* Check sectors per cluster value is valid. */
	if (!silent)
		fprintf(stderr, "Checking sectors per cluster... ");
	switch (b->bpb.sectors_per_cluster) {
	case 1: case 2: case 4: case 8: case 16:
	case 32: case 64: case 128:
		break;
	default:
		goto not_ntfs;
	}
	if (!silent)
		fprintf(stderr, "OK\n");

	/* Check the cluster size is not above 65536 bytes. */
	if (!silent)
		fprintf(stderr, "Checking cluster size... ");
	if ((u32)le16_to_cpu(b->bpb.bytes_per_sector) *
	    b->bpb.sectors_per_cluster > 0x10000)
		goto not_ntfs;
	if (!silent)
		fprintf(stderr, "OK\n");

	/* Check reserved/unused fields are really zero. */
	if (!silent)
		fprintf(stderr, "Checking reserved fields are zero... ");
	if (le16_to_cpu(b->bpb.reserved_sectors) ||
	    le16_to_cpu(b->bpb.root_entries) ||
	    le16_to_cpu(b->bpb.sectors) ||
	    le16_to_cpu(b->bpb.sectors_per_fat) ||
	    le32_to_cpu(b->bpb.large_sectors) ||
	    b->bpb.fats)
		goto not_ntfs;
	if (!silent)
		fprintf(stderr, "OK\n");

	/* Check clusters per file mft record value is valid. */
	if (!silent)
		fprintf(stderr, "Checking clusters per mft record... ");
	if ((u8)b->clusters_per_mft_record < 0xe1 ||
	    (u8)b->clusters_per_mft_record > 0xf7) {
		switch (b->clusters_per_mft_record) {
		case 1: case 2: case 4: case 8: case 0x10: case 0x20: case 0x40:
			break;
		default:
			goto not_ntfs;
		}
	}
	if (!silent)
		fprintf(stderr, "OK\n");

	/* Check clusters per index block value is valid. */
	if (!silent)
		fprintf(stderr, "Checking clusters per index block... ");
	if ((u8)b->clusters_per_index_record < 0xe1 ||
	    (u8)b->clusters_per_index_record > 0xf7) {
		switch (b->clusters_per_index_record) {
		case 1: case 2: case 4: case 8: case 0x10: case 0x20: case 0x40:
			break;
		default:
			goto not_ntfs;
		}
	}
	if (!silent)
		fprintf(stderr, "OK\n");

	if (b->end_of_sector_marker != cpu_to_le16(0xaa55))
		Dputs("Warning: Bootsector has invalid end of sector marker.");

	if (!silent)
		fprintf(stderr, "Bootsector check completed successfully.\n");

	return TRUE;
not_ntfs:
	if (!silent) {
		fprintf(stderr, "FAILED\n");
		fprintf(stderr, "Bootsector check failed. Aborting...\n");
	}
	return FALSE;
}

/**
 * ntfs_boot_sector_parse - setup an ntfs volume from an ntfs boot sector
 * @vol:	ntfs_volume to setup
 * @bs:		buffer containing ntfs boot sector to parse
 *
 * Parse the ntfs bootsector @bs and setup the ntfs volume @vol with the
 * obtained values.
 *
 * Return 0 on success or -1 on error with errno set to the error code EINVAL.
 */
int ntfs_boot_sector_parse(ntfs_volume *vol, const NTFS_BOOT_SECTOR *bs)
{
	u8 sectors_per_cluster;
	s8 c;

	/* We return -1 with errno = EINVAL on error. */
	errno = EINVAL;

	vol->sector_size = le16_to_cpu(bs->bpb.bytes_per_sector);
	vol->sector_size_bits = ffs(vol->sector_size) - 1;
	Dprintf("SectorSize = 0x%x\n", vol->sector_size);
	Dprintf("SectorSizeBits = %u\n", vol->sector_size_bits);
	/*
	 * The bounds checks on mft_lcn and mft_mirr_lcn (i.e. them being
	 * below or equal the number_of_clusters) really belong in the
	 * ntfs_boot_sector_is_ntfs but in this way we can just do this once.
	 */
	sectors_per_cluster = bs->bpb.sectors_per_cluster;
	Dprintf("NumberOfSectors = %Li\n", sle64_to_cpu(bs->number_of_sectors));
	Dprintf("SectorsPerCluster = 0x%x\n", sectors_per_cluster);
	if (sectors_per_cluster & (sectors_per_cluster - 1)) {
		Dprintf("Error: %s is not a valid NTFS partition! "
				"sectors_per_cluster is not a power of 2.\n",
				vol->dev->d_name);
		return -1;
	}
	vol->nr_clusters = sle64_to_cpu(bs->number_of_sectors) >>
			(ffs(sectors_per_cluster) - 1);

	vol->mft_lcn = sle64_to_cpu(bs->mft_lcn);
	vol->mftmirr_lcn = sle64_to_cpu(bs->mftmirr_lcn);
	Dprintf("MFT LCN = 0x%Lx\n", vol->mft_lcn);
	Dprintf("MFTMirr LCN = 0x%Lx\n", vol->mftmirr_lcn);
	if (vol->mft_lcn > vol->nr_clusters ||
			vol->mftmirr_lcn > vol->nr_clusters) {
		Dprintf("Error: %s is not a valid NTFS partition! ($Mft LCN "
				"or\n$MftMirr LCN is greater than the number "
				"of clusters!\n", vol->dev->d_name);
		return -1;
	}
	vol->cluster_size = sectors_per_cluster * vol->sector_size;
	if (vol->cluster_size & (vol->cluster_size - 1)) {
		Dprintf("Error: %s is not a valid NTFS partition! "
				"cluster_size is not a power of 2.\n",
				vol->dev->d_name);
		return -1;
	}
	vol->cluster_size_bits = ffs(vol->cluster_size) - 1;
	/*
	 * Need to get the clusters per mft record and handle it if it is
	 * negative. Then calculate the mft_record_size. A value of 0x80 is
	 * illegal, thus signed char is actually ok!
	 */
	c = bs->clusters_per_mft_record;
	Dprintf("ClusterSize = 0x%x\n", vol->cluster_size);
	Dprintf("ClusterSizeBits = %u\n", vol->cluster_size_bits);
	Dprintf("ClustersPerMftRecord = 0x%x\n", c);
	/*
	 * When clusters_per_mft_record is negative, it means that it is to
	 * be taken to be the negative base 2 logarithm of the mft_record_size
	 * min bytes. Then:
	 *	 mft_record_size = 2^(-clusters_per_mft_record) bytes.
	 */
	if (c < 0)
		vol->mft_record_size = 1 << -c;
	else
		vol->mft_record_size = vol->cluster_size * c;
	if (vol->mft_record_size & (vol->mft_record_size - 1)) {
		Dprintf("Error: %s is not a valid NTFS partition! "
				"mft_record_size is not a power of 2.\n",
				vol->dev->d_name);
		return -1;
	}
	vol->mft_record_size_bits = ffs(vol->mft_record_size) - 1;
	Dprintf("MftRecordSize = 0x%x\n", vol->mft_record_size);
	Dprintf("MftRecordSizeBits = %u\n", vol->mft_record_size_bits);
	/*
	 * Work out the size of the MFT mirror in number of mft records. If the
	 * cluster size is less than or equal to the size taken by four mft
	 * records, the mft mirror stores the first four mft records. If the
	 * cluster size is bigger than the size taken by four mft records, the
	 * mft mirror contains as many mft records as will fit into one
	 * cluster.
	 */
	if (vol->cluster_size <= 4 * vol->mft_record_size)
		vol->mftmirr_size = 4;
	else
		vol->mftmirr_size = vol->cluster_size / vol->mft_record_size;
	return 0;
}

