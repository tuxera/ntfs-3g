/**
 * NtfsFix - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2000-2003 Anton Altaparmakov.
 *
 * This utility will attempt to fix a partition that has been damaged by the
 * current Linux-NTFS driver. It should be run after dismounting an NTFS
 * partition that has been mounted read-write under Linux and before rebooting
 * into Windows NT/2000. NtfsFix can be run even after Windows has had mounted
 * the partition, but it might be too late and irreversible damage to the data
 * might have been done already.
 *
 *	Anton Altaparmakov <aia21@cantab.net>
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
 * along with this program (in the main directory of the Linux-NTFS source
 * in the file COPYING); if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * WARNING: This program might not work on architectures which do not allow
 * unaligned access. For those, the program would need to start using
 * get/put_unaligned macros (#include <asm/unaligned.h>), but not doing it yet,
 * since NTFS really mostly applies to ia32 only, which does allow unaligned
 * accesses. We might not actually have a problem though, since the structs are
 * defined as being packed so that might be enough for gcc to insert the
 * correct code.
 *
 * If anyone using a non-little endian and/or an aligned access only CPU tries
 * this program please let me know whether it works or not!
 *
 *	Anton Altaparmakov <aia21@cantab.net>
 */

#include "config.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include "types.h"
#include "attrib.h"
#include "mft.h"
#include "device.h"
#include "logfile.h"
#include "utils.h"

#ifdef NO_NTFS_DEVICE_DEFAULT_IO_OPS
#	error "No default device io operations!  Cannot build ntfsfix.  \
You need to run ./configure without the --disable-default-device-io-ops \
switch if you want to be able to build the NTFS utilities."
#endif

GEN_PRINTF(Eprintf, stdout, NULL, FALSE)
GEN_PRINTF(Vprintf, stdout, NULL, FALSE)
GEN_PRINTF(Qprintf, stdout, NULL, FALSE)

static const char *EXEC_NAME = "ntfsfix";
static const char *OK        = "OK";
static const char *FAILED    = "FAILED";
static BOOL journal_is_empty = FALSE;

struct {
	char *volume;
} opt;

static int usage(void) __attribute__((noreturn));
static int usage(void)
{
	printf("%s v%s\n"
		   "\n"
		   "Usage: %s [options] device\n"
		   "    Attempt to fix an NTFS partition.\n"
		   "\n"
		   "    -h, --help             Display this help\n"
		   "    -V, --version          Display version information\n"
		   "\n"
		   "For example: %s /dev/hda6\n\n",
		   EXEC_NAME, VERSION, EXEC_NAME, EXEC_NAME);
	printf("%s%s", ntfs_bugs, ntfs_home);
	exit(1);
}

static void version (void)
{
	printf("%s v%s\n\n"
		   "Attempt to fix an NTFS partition.\n\n"
		   "Copyright (c) 2000-2003 Anton Altaparmakov.\n\n",
		   EXEC_NAME, VERSION);
	printf("%s\n%s%s", ntfs_gpl, ntfs_bugs, ntfs_home);
	exit(1);
}

static void parse_options(int argc, char **argv)
{
	char c;
	static const char *sopt = "-hV";
	static const struct option lopt[] = {
		{ "help",	    no_argument,		NULL, 'h' },
		{ "version",	no_argument,		NULL, 'V' },
		{ NULL, 0, NULL, 0 }
	};

	memset(&opt, 0, sizeof(opt));

	while ((c = getopt_long (argc, argv, sopt, lopt, NULL)) != (char)-1) {
		switch (c) {
		case 1:	/* A non-option argument */
			if (!opt.volume)
				opt.volume = argv[optind - 1];
			else {
				printf("ERROR: Too many arguments.\n");
				usage();
			}
			break;
		case 'h':
		case '?':
			usage();
		case 'V':
			version();
		default:
			printf("ERROR: Unknown option '%s'.\n", argv[optind - 1]);
			usage();
		}
	}

	if (opt.volume == NULL) {
		printf("ERROR: You must specify a device.\n");
		usage();
	}
}

static int empty_journal(ntfs_volume *vol)
{
	if (journal_is_empty == TRUE)
		return 0;

	printf("Going to empty the journal ($LogFile)... ");
	if (ntfs_logfile_reset(vol)) {
		puts(FAILED);
		perror("Failed to reset $LogFile");
		return -1;
	}
	puts(OK);
	journal_is_empty = TRUE;
	return 0;
}

/**
 * main
 */
int main(int argc, char **argv)
{
	s64 l, br;
	unsigned char *m = NULL, *m2 = NULL;
	ntfs_volume *vol;
	struct ntfs_device *dev;
	unsigned long mnt_flags;
	int i;
	BOOL done, force = FALSE;

	parse_options(argc, argv);

	if (!ntfs_check_if_mounted(opt.volume, &mnt_flags)) {
		if ((mnt_flags & NTFS_MF_MOUNTED) &&
				!(mnt_flags & NTFS_MF_READONLY) && !force) {
			fprintf(stderr, "Refusing to operate on read-write "
					"mounted device %s.\n", opt.volume);
			exit(1);
		}
	} else
		fprintf(stderr, "Failed to determine whether %s is mounted: "
				"%s\n", opt.volume, strerror(errno));
	/* Attempt a full mount first. */
	printf("Mounting volume... ");
	vol = ntfs_mount(opt.volume, 0);
	if (vol) {
		puts(OK);
		printf("Processing of $MFT and $MFTMirr completed "
				"successfully.\n");
		goto mount_ok;
	}
	puts(FAILED);

	printf("Attempting to correct errors... ");

	dev = ntfs_device_alloc(opt.volume, 0, &ntfs_device_default_io_ops, NULL);
	if (!dev) {
		puts(FAILED);
		perror("Failed to allocate device");
		goto error_exit;
	}

	vol = ntfs_volume_startup(dev, 0);
	if (!vol) {
		puts(FAILED);
		perror("Failed to startup volume");
		fprintf(stderr, "Volume is corrupt. You should run chkdsk.\n");
		ntfs_device_free(dev);
		goto error_exit;
	}

	puts("\nProcessing $MFT and $MFTMirr... ");

	/* Load data from $MFT and $MFTMirr and compare the contents. */
	m = (u8*)malloc(vol->mftmirr_size << vol->mft_record_size_bits);
	m2 = (u8*)malloc(vol->mftmirr_size << vol->mft_record_size_bits);
	if (!m || !m2) {
		perror("Failed to allocate memory");
		goto error_exit;
	}

	printf("Reading $MFT... ");
	l = ntfs_attr_mst_pread(vol->mft_na, 0, vol->mftmirr_size,
			vol->mft_record_size, m);
	if (l != vol->mftmirr_size) {
		puts(FAILED);
		if (l != -1)
			errno = EIO;
		perror("Failed to read $MFT");
		goto error_exit;
	}
	puts(OK);

	printf("Reading $MFTMirr... ");
	l = ntfs_attr_mst_pread(vol->mftmirr_na, 0, vol->mftmirr_size,
			vol->mft_record_size, m2);
	if (l != vol->mftmirr_size) {
		puts(FAILED);
		if (l != -1)
			errno = EIO;
		perror("Failed to read $MFTMirr");
		goto error_exit;
	}
	puts(OK);

	/*
	 * FIXME: Need to actually check the $MFTMirr for being real. Otherwise
	 * we might corrupt the partition if someone is experimenting with
	 * software RAID and the $MFTMirr is not actually in the position we
	 * expect it to be... )-:
	 * FIXME: We should emit a warning it $MFTMirr is damaged and ask
	 * user whether to recreate it from $MFT or whether to abort. - The
	 * warning needs to include the danger of software RAID arrays.
	 * Maybe we should go as far as to detect whether we are running on a
	 * MD disk and if yes then bomb out right at the start of the program?
	 */

	printf("Comparing $MFTMirr to $MFT... ");
	done = FALSE;
	for (i = 0; i < vol->mftmirr_size; ++i) {
		const char *ESTR[12] = { "$MFT", "$MFTMirr", "$LogFile",
			"$Volume", "$AttrDef", "root directory", "$Bitmap",
			"$Boot", "$BadClus", "$Secure", "$UpCase", "$Extend" };
		const char *s;

		if (i < 12)
			s = ESTR[i];
		else if (i < 16)
			s = "system file";
		else
			s = "mft record";

		if (ntfs_is_baad_recordp(m + i * vol->mft_record_size)) {
			puts("FAILED");
			fprintf(stderr, "$MFT error: Incomplete multi sector "
					"transfer detected in %s.\nCannot "
					"handle this yet. )-:\n", s);
			goto error_exit;
		}
		if (!ntfs_is_mft_recordp(m + i * vol->mft_record_size)) {
			puts("FAILED");
			fprintf(stderr, "$MFT error: Invalid mft record for "
					"%s.\nCannot handle this yet. )-:\n",
					s);
			goto error_exit;
		}
		if (ntfs_is_baad_recordp(m2 + i * vol->mft_record_size)) {
			puts("FAILED");
			fprintf(stderr, "$MFTMirr error: Incomplete multi "
					"sector transfer detected in %s.\n", s);
			goto error_exit;
		}
		if (memcmp((u8*)m + i * vol->mft_record_size, (u8*)m2 +
				i * vol->mft_record_size,
				ntfs_mft_record_get_data_size((MFT_RECORD*)(
				(u8*)m + i * vol->mft_record_size)))) {
			if (!done) {
				done = TRUE;
				puts(FAILED);
				printf("Correcting differences in $MFTMirr...");
			}
			br = ntfs_mft_record_write(vol, i, (MFT_RECORD*)(m +
					i * vol->mft_record_size));
			if (br) {
				puts(FAILED);
				perror("Error correcting $MFTMirr");
				goto error_exit;
			}
		}
	}
	puts(OK);

	free(m);
	free(m2);
	m = m2 = NULL;

	printf("Processing of $MFT and $MFTMirr completed successfully.\n");

	if (empty_journal(vol) < 0)
		goto error_exit;

	/* ntfs_umount() will invoke ntfs_device_free() for us. */
	if (ntfs_umount(vol, 0))
		ntfs_umount(vol, 1);
	vol = ntfs_mount(opt.volume, 0);
	if (!vol) {
		perror("Remount failed");
		goto error_exit;
	}
mount_ok:
	m = NULL;

	/* Check NTFS version is ok for us (in $Volume) */
	printf("NTFS volume version is %i.%i.\n", vol->major_ver,
			vol->minor_ver);
	if (ntfs_version_is_supported(vol)) {
		fprintf(stderr, "Error: Unknown NTFS version.\n");
		goto error_exit;
	}

	if (empty_journal(vol) < 0)
		goto error_exit;

	if (vol->major_ver >= 3) {
	/* FIXME: If on NTFS 3.0+, check for presence of the usn journal and
	   disable it (if present) as Win2k might be unhappy otherwise and Bad
	   Things(TM) could happen depending on what applications are actually
	   using it for. */
	}

	/* FIXME: Should we be marking the quota out of date, too? */

	/* That's all for now! */
	printf("NTFS partition %s was processed successfully.\n",
			vol->dev->d_name);
	/* Set return code to 0. */
	i = 0;
final_exit:
	if (m)
		free(m);
	if (m2)
		free(m2);
	if (vol && ntfs_umount(vol, 0))
		ntfs_umount(vol, 1);
	return i;
error_exit:
	i = 1;
	goto final_exit;
}

