/**
 * mkntfs - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2000-2004 Anton Altaparmakov
 * Copyright (c) 2001-2003 Richard Russon
 *
 * This utility will create an NTFS 1.2 (Windows NT 4.0) volume on a user
 * specified (block) device.
 *
 * Some things (option handling and determination of mount status) have been
 * adapted from e2fsprogs-1.19 and lib/ext2fs/ismounted.c and misc/mke2fs.c in
 * particular.
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
#	include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#	include <stdlib.h>
#endif
#ifdef HAVE_STDIO_H
#	include <stdio.h>
#endif
#ifdef HAVE_STDARG_H
#	include <stdarg.h>
#endif
#ifdef HAVE_STRING_H
#	include <string.h>
#endif
#ifdef HAVE_ERRNO_H
#	include <errno.h>
#endif
#include <time.h>
#ifdef HAVE_GETOPT_H
#	include <getopt.h>
#else
	extern char *optarg;
	extern int optind;
#endif
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#ifdef HAVE_LINUX_MAJOR_H
#	include <linux/major.h>
#	ifndef MAJOR
#		define MAJOR(dev)	((dev) >> 8)
#		define MINOR(dev)	((dev) & 0xff)
#	endif
#	ifndef IDE_DISK_MAJOR
#		ifndef IDE0_MAJOR
#			define IDE0_MAJOR	3
#			define IDE1_MAJOR	22
#			define IDE2_MAJOR	33
#			define IDE3_MAJOR	34
#			define IDE4_MAJOR	56
#			define IDE5_MAJOR	57
#			define IDE6_MAJOR	88
#			define IDE7_MAJOR	89
#			define IDE8_MAJOR	90
#			define IDE9_MAJOR	91
#		endif
#		define IDE_DISK_MAJOR(M) \
				((M) == IDE0_MAJOR || (M) == IDE1_MAJOR || \
				(M) == IDE2_MAJOR || (M) == IDE3_MAJOR || \
				(M) == IDE4_MAJOR || (M) == IDE5_MAJOR || \
				(M) == IDE6_MAJOR || (M) == IDE7_MAJOR || \
				(M) == IDE8_MAJOR || (M) == IDE9_MAJOR)
#	endif
#	ifndef SCSI_DISK_MAJOR
#		ifndef SCSI_DISK0_MAJOR
#			define SCSI_DISK0_MAJOR	8
#			define SCSI_DISK1_MAJOR	65
#			define SCSI_DISK7_MAJOR	71
#		endif
#		define SCSI_DISK_MAJOR(M) \
				((M) == SCSI_DISK0_MAJOR || \
				((M) >= SCSI_DISK1_MAJOR && \
				(M) <= SCSI_DISK7_MAJOR))
#	endif
#endif
#include <limits.h>

#if defined(linux) && defined(_IO) && !defined(BLKSSZGET)
#	define BLKSSZGET _IO(0x12,104) /* Get device sector size in bytse. */
#endif

#include "types.h"
#include "bootsect.h"
#include "device.h"
#include "attrib.h"
#include "bitmap.h"
#include "mst.h"
#include "dir.h"
#include "runlist.h"
#include "mft.h"
#include "utils.h"

#ifdef NO_NTFS_DEVICE_DEFAULT_IO_OPS
#	error "No default device io operations!  Cannot build mkntfs.  \
You need to run ./configure without the --disable-default-device-io-ops \
switch if you want to be able to build the NTFS utilities."
#endif

extern const unsigned char attrdef_ntfs12_array[2400];
extern const unsigned char boot_array[3429];
extern void init_system_file_sd(int sys_file_no, char **sd_val,
		int *sd_val_len);
extern void init_upcase_table(uchar_t *uc, u32 uc_len);

/* Page size on ia32. Can change to 8192 on Alpha. */
#define NTFS_PAGE_SIZE	4096

const char *EXEC_NAME = "mkntfs";

/* Need these global so mkntfs_exit can access them. */
char *buf = NULL;
char *buf2 = NULL;
int buf2_size = 0;
int mft_bitmap_size, mft_bitmap_byte_size;
unsigned char *mft_bitmap = NULL;
int lcn_bitmap_byte_size;
unsigned char *lcn_bitmap = NULL;
runlist *rl = NULL, *rl_mft = NULL, *rl_mft_bmp = NULL, *rl_mftmirr = NULL;
runlist *rl_logfile = NULL, *rl_boot = NULL, *rl_bad = NULL, *rl_index;
INDEX_ALLOCATION *index_block = NULL;
ntfs_volume *vol;
char *dev_name;

struct {
	int sector_size;		/* -s, in bytes, power of 2, default is
					   512 bytes. */
	int sectors_per_track;		/* number of sectors per track on
					   device */
	int heads;			/* number of heads on device */
	long long part_start_sect;	/* start sector of partition on parent
					   device */
	long long nr_sectors;		/* size of device in sectors */
	long long nr_clusters;		/* Note: Win2k treats clusters as
					   32-bit entities! */
	long long volume_size;		/* in bytes, or suffixed
					   with k for kB, m or M for MB, or
					   g or G for GB, or t or T for TB */
	int index_block_size;		/* in bytes. */
	int mft_size;			/* The bigger of 16kB & one cluster. */
	long long mft_lcn;		/* lcn of $MFT, $DATA attribute. */
	long long mftmirr_lcn;		/* lcn of $MFTMirr, $DATA. */
	long long logfile_lcn;		/* lcn of $LogFile, $DATA. */
	int logfile_size;		/* in bytes, determined from
					   volume_size. */
	char mft_zone_multiplier;	/* -z, value from 1 to 4. Default is
					   1. */
	long long mft_zone_end;		/* Determined from volume_size and
					   mft_zone_multiplier, in clusters. */
	char no_action;			/* -n, do not write to device, only
					   display what would be done. */
	char check_bad_blocks;		/* read-only test for bad
					   clusters. */
	long long *bad_blocks;		/* Array of bad clusters. */
	long long nr_bad_blocks;	/* Number of bad clusters. */
	char *bad_blocks_filename;	/* filename, file to read list of
					   bad clusters from. */
	ATTR_DEF *attr_defs;		/* filename, attribute defs. */
	int attr_defs_len;		/* in bytes */
	uchar_t *upcase;		/* filename, upcase table. */
	u32 upcase_len;			/* Determined automatically. */
	int quiet;			/* -q, quiet execution. */
	int verbose;			/* -v, verbose execution, given twice,
					 * really verbose execution (debug
					 * mode). */
	int force;			/* -F, force fs creation. */
	char quick_format;		/* -f or -Q, fast format, don't zero
					   the volume first. */
	char enable_compression;	/* -C, enables compression of all files
					   on the volume by default. */
	char disable_indexing;		/* -I, disables indexing of file
					   contents on the volume by default. */
					/* -V, print version and exit. */
} opts;

/**
 * Dprintf - debugging output (-vv); overriden by quiet (-q)
 */
static void Dprintf(const char *fmt, ...)
{
	va_list ap;

	if (!opts.quiet && opts.verbose > 1) {
		printf("DEBUG: ");
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
	}
}

/**
 * Eprintf - error output; ignores quiet (-q)
 */
void Eprintf(const char *fmt, ...);
void Eprintf(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "ERROR: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/* Generate code for Vprintf() function: Verbose output (-v). */
GEN_PRINTF(Vprintf, stdout, &opts.verbose, TRUE)

/* Generate code for Qprintf() function: Quietable output (if not -q). */
GEN_PRINTF(Qprintf, stdout, &opts.quiet,   FALSE)

/**
 * err_exit - error output and terminate; ignores quiet (-q)
 */
static void err_exit(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "ERROR: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "Aborting...\n");
	exit(1);

}

/**
 * copyright - print copyright statements
 */
static void copyright(void)
{
	fprintf(stderr, "Copyright (c) 2000-2004 Anton Altaparmakov\n"
			"Copyright (c) 2001-2003 Richard Russon\n"
			"Create an NTFS volume on a user specified (block) "
			"device.\n");
}

/**
 * license - print license statement
 */
static void license(void)
{
	fprintf(stderr, "%s", ntfs_gpl);
}

/**
 * usage - print a list of the parameters to the program
 */
static void usage(void) __attribute__ ((noreturn));
static void usage(void)
{
	copyright();
	fprintf(stderr,	"Usage: %s [options] device "
			"[number-of-sectors]\n"
			"    -s sector-size           Specify the sector size "
			"for the device\n"
			"    -p part-start-sect       Specify the partition "
			"start sector\n"
			"    -H heads                 Specify the number of "
			"heads\n"
			"    -S sectors-per-track     Specify the number of "
			"sectors per track\n"
			"    -c cluster-size          Specify the cluster "
			"size for the volume\n"
			"    -L volume-label          Set the volume label\n"
			"    -z mft-zone-multiplier   Set the MFT zone "
			"multiplier\n"
			"    -f                       Perform a quick format\n"
			"    -Q                       Perform a quick format\n"
			"    -C                       Enable compression on "
			"the volume\n"
			"    -I                       Disable indexing on the "
			"volume\n"
			"    -n                       Do not write to disk\n"
			"    -F                       Force execution despite "
			"errors\n"
			"    -q                       Quiet execution\n"
			"    -v                       Verbose execution\n"
			"    -vv                      Very verbose execution\n"
			"    -V                       Display version "
			"information\n"
			"    -l                       Display licensing "
			"information\n"
			"    -h                       Display this help\n",
			EXEC_NAME);
	fprintf(stderr, "%s%s", ntfs_bugs, ntfs_home);
	exit(1);
}

/**
 * parse_options
 */
static void parse_options(int argc, char *argv[])
{
	int c;
	long l;
	unsigned long u;
	char *s;

// Need to have: mft record size, index record size, ntfs version, mft size,
//		 logfile size, list of bad blocks, check for bad blocks, ...
	if (argc && *argv)
		EXEC_NAME = *argv;
	fprintf(stderr, "%s v%s\n", EXEC_NAME, VERSION);
	while ((c = getopt(argc, argv, "c:fh?np:qs:vz:CFIL:QVl")) != EOF)
		switch (c) {
		case 'n':
			opts.no_action = 1;
			break;
		case 'c':
			l = strtol(optarg, &s, 0);
			if (l <= 0 || l > INT_MAX || *s)
				err_exit("Invalid cluster size.\n");
			vol->cluster_size = l;
			break;
		case 'f':
		case 'Q':
			opts.quick_format = 1;
			break;
		case 'p':
			u = strtoul(optarg, &s, 0);
			if ((u >= ULONG_MAX && errno == ERANGE) || *s)
				err_exit("Invalid partition start sector.\n");
			opts.part_start_sect = u;
			break;
		case 'H':
			l = strtol(optarg, &s, 0);
			if (l <= 0 || l > INT_MAX || *s)
				err_exit("Invalid number of heads.\n");
			opts.heads = l;
			break;
		case 'S':
			l = strtol(optarg, &s, 0);
			if (l <= 0 || l > INT_MAX || *s)
				err_exit("Invalid number of sectors per "
						"track.\n");
			opts.sectors_per_track = l;
			break;
		case 'q':
			opts.quiet = 1;
			break;
		case 's':
			l = strtol(optarg, &s, 0);
			if (l <= 0 || l > INT_MAX || *s)
				err_exit("Invalid sector size.\n");
			opts.sector_size = l;
			break;
		case 'v':
			opts.verbose++;
			break;
		case 'z':
			l = strtol(optarg, &s, 0);
			if (l < 1 || l > 4 || *s)
				err_exit("Invalid MFT zone multiplier.\n");
			opts.mft_zone_multiplier = l;
			break;
		case 'C':
			opts.enable_compression = 1;
			break;
		case 'F':
			opts.force = 1;
			break;
		case 'I':
			opts.disable_indexing = 1;
			break;
		case 'L':
			vol->vol_name = optarg;
			break;
		case 'V':
			/* Version number already printed, so just exit. */
			exit(0);
		case 'l':
			copyright();
			license();
			exit(0);
		case 'h':
		case '?':
		default:
			usage();
		}
	if (optind == argc)
		usage();
	dev_name = argv[optind++];
	if (optind < argc) {
		u = strtoul(argv[optind++], &s, 0);
		if (*s || !u || (u >= ULONG_MAX && errno == ERANGE))
			err_exit("Invalid number of sectors: %s\n",
					argv[optind - 1]);
		opts.nr_sectors = u;
	}
	if (optind < argc)
		usage();
}

/**
 * append_to_bad_blocks
 */
static void append_to_bad_blocks(unsigned long block)
{
	long long *new_buf;

	if (!(opts.nr_bad_blocks & 15)) {
		new_buf = realloc(opts.bad_blocks, (opts.nr_bad_blocks + 16) *
							sizeof(long long));
		if (!new_buf)
			err_exit("Reallocating memory for bad blocks list "
				 "failed: %s\n", strerror(errno));
		opts.bad_blocks = new_buf;
	}
	opts.bad_blocks[opts.nr_bad_blocks++] = block;
}

/**
 * mkntfs_write
 */
static __inline__ long long mkntfs_write(struct ntfs_device *dev,
		const void *buf, long long count)
{
	long long bytes_written, total;
	int retry;

	if (opts.no_action)
		return count;
	total = 0LL;
	retry = 0;
	do {
		bytes_written = dev->d_ops->write(dev, buf, count);
		if (bytes_written == -1LL) {
			retry = errno;
			Eprintf("Error writing to %s: %s\n", vol->dev->d_name,
					strerror(errno));
			errno = retry;
			return bytes_written;
		} else if (!bytes_written)
			++retry;
		else {
			count -= bytes_written;
			total += bytes_written;
		}
	} while (count && retry < 3);
	if (count)
		Eprintf("Failed to complete writing to %s after three retries."
			"\n", vol->dev->d_name);
	return total;
}

/**
 * Write to disk the clusters contained in the runlist @rl taking the data
 * from @val. Take @val_len bytes from @val and pad the rest with zeroes.
 *
 * If the @rl specifies a completely sparse file, @val is allowed to be NULL.
 *
 * @inited_size if not NULL points to an output variable which will contain
 * the actual number of bytes written to disk. I.e. this will not include
 * sparse bytes for example.
 *
 * Return the number of bytes written (minus padding) or -1 on error. Errno
 * will be set to the error code.
 */
static s64 ntfs_rlwrite(struct ntfs_device *dev, const runlist *rl,
		const char *val, const s64 val_len, s64 *inited_size)
{
	s64 bytes_written, total, length, delta;
	int retry, i;

	if (inited_size)
		*inited_size = 0LL;
	if (opts.no_action)
		return val_len;
	total = delta = 0LL;
	for (i = 0; rl[i].length; i++) {
		length = rl[i].length * vol->cluster_size;
		/* Don't write sparse runs. */
		if (rl[i].lcn == -1) {
			total += length;
			if (!val)
				continue;
			// TODO: Check that *val is really zero at pos and len.
			continue;
		}
		if (dev->d_ops->seek(dev, rl[i].lcn * vol->cluster_size,
				SEEK_SET) == (off_t)-1)
			return -1LL;
		retry = 0;
		do {
			if (total + length > val_len) {
				delta = length;
				length = val_len - total;
				delta -= length;
			}
			bytes_written = dev->d_ops->write(dev, val + total,
					length);
			if (bytes_written == -1LL) {
				retry = errno;
				Eprintf("Error writing to %s: %s\n",
						vol->dev->d_name,
						strerror(errno));
				errno = retry;
				return bytes_written;
			}
			if (bytes_written) {
				length -= bytes_written;
				total += bytes_written;
				if (inited_size)
					*inited_size += bytes_written;
			} else
				++retry;
		} while (length && retry < 3);
		if (length) {
			Eprintf("Failed to complete writing to %s after three "
					"retries.\n", vol->dev->d_name);
			return total;
		}
	}
	if (delta) {
		char *buf = (char*)calloc(1, delta);
		if (!buf)
			err_exit("Error allocating internal buffer: "
					"%s\n", strerror(errno));
		bytes_written = mkntfs_write(dev, buf, delta);
		free(buf);
		if (bytes_written == -1LL)
			return bytes_written;
	}
	return total;
}

/**
 * ucstos - convert unicode-character string to ASCII
 * @dest:	points to buffer to receive the converted string
 * @src:	points to string to convert
 * @maxlen:	size of @dest buffer in bytes
 *
 * Return the number of characters written to @dest, not including the
 * terminating null byte. If a unicode character was encountered which could
 * not be converted -1 is returned.
 */
static int ucstos(char *dest, const uchar_t *src, int maxlen)
{
	uchar_t u;
	int i;

	/* Need one byte for null terminator. */
	maxlen--;
	for (i = 0; i < maxlen; i++) {
		u = le16_to_cpu(src[i]);
		if (!u)
			break;
		if (u & 0xff00)
			return -1;
		dest[i] = u & 0xff;
	}
	dest[i] = 0;
	return i;
}

/**
 * stoucs - convert ASCII string to unicode-character string
 * @dest:	points to buffer to receive the converted string
 * @src:	points to string to convert
 * @maxlen:	size of @dest buffer in bytes
 *
 * Return the number of characters written to @dest, not including the
 * terminating null unicode character.
 *
 * If @maxlen is less than the size of a single unicode character we cannot
 * write the terminating null unicode character and hence return -1 with errno
 * set to EINVAL.
 */
static int stoucs(uchar_t *dest, const char *src, int maxlen)
{
	char c;
	int i;

	if (maxlen < (int)sizeof(uchar_t)) {
		errno = EINVAL;
		return -1;
	}
	/* Convert maxlen from bytes to unicode characters. */
	maxlen /= sizeof(uchar_t);
	/* Need space for null terminator. */
	maxlen--;
	for (i = 0; i < maxlen; i++) {
		c = src[i];
		if (!c)
			break;
		dest[i] = cpu_to_le16(c);
	}
	dest[i] = cpu_to_le16('\0');
	return i;
}

/**
 * dump_resident_attr_val
 */
static void dump_resident_attr_val(ATTR_TYPES type, char *val, u32 val_len)
{
	const char *don_t_know = "Don't know what to do with this attribute "
			"type yet.";
	const char *skip = "Skipping display of $%s attribute value.\n";
	const char *todo = "This is still work in progress.";
	char *buf;
	int i, j;

	switch (type) {
	case AT_STANDARD_INFORMATION:
		// TODO
		printf("%s\n", todo);
		return;
	case AT_ATTRIBUTE_LIST:
		// TODO
		printf("%s\n", todo);
		return;
	case AT_FILE_NAME:
		// TODO
		printf("%s\n", todo);
		return;
	case AT_OBJECT_ID:
		// TODO
		printf("%s\n", todo);
		return;
	case AT_SECURITY_DESCRIPTOR:
		// TODO
		printf("%s\n", todo);
		return;
	case AT_VOLUME_NAME:
		printf("Volume name length = %i\n", (unsigned int)val_len);
		if (val_len) {
			buf = calloc(1, val_len);
			if (!buf)
				err_exit("Failed to allocate internal buffer: "
						"%s\n", strerror(errno));
			i = ucstos(buf, (uchar_t*)val, val_len);
			if (i == -1)
				printf("Volume name contains non-displayable "
						"Unicode characters.\n");
			printf("Volume name = %s\n", buf);
			free(buf);
		}
		return;
	case AT_VOLUME_INFORMATION:
#define VOL_INF(x) ((VOLUME_INFORMATION *)(x))
		printf("NTFS version %i.%i\n", VOL_INF(val)->major_ver,
				VOL_INF(val)->minor_ver);
		i = VOL_INF(val)->flags;
#undef VOL_INF
		printf("Volume flags = 0x%x: ", i);
		if (!i) {
			printf("NONE\n");
			return;
		}
		j = 0;
		if (i & VOLUME_MODIFIED_BY_CHKDSK) {
			printf("VOLUME_MODIFIED_BY_CHKDSK");
			j = 1;
		}
		if (i & VOLUME_REPAIR_OBJECT_ID) {
			if (j)
				printf(" | ");
			printf("VOLUME_REPAIR_OBJECT_ID");
			j = 1;
		}
		if (i & VOLUME_DELETE_USN_UNDERWAY) {
			if (j)
				printf(" | ");
			printf("VOLUME_DELETE_USN_UNDERWAY");
			j = 1;
		}
		if (i & VOLUME_MOUNTED_ON_NT4) {
			if (j)
				printf(" | ");
			printf("VOLUME_MOUNTED_ON_NT4");
			j = 1;
		}
		if (i & VOLUME_UPGRADE_ON_MOUNT) {
			if (j)
				printf(" | ");
			printf("VOLUME_UPGRADE_ON_MOUNT");
			j = 1;
		}
		if (i & VOLUME_RESIZE_LOG_FILE) {
			if (j)
				printf(" | ");
			printf("VOLUME_RESIZE_LOG_FILE");
			j = 1;
		}
		if (i & VOLUME_IS_DIRTY) {
			if (j)
				printf(" | ");
			printf("VOLUME_IS_DIRTY");
			j = 1;
		}
		printf("\n");
		return;
	case AT_DATA:
		printf(skip, "DATA");
		return;
	case AT_INDEX_ROOT:
		// TODO
		printf("%s\n", todo);
		return;
	case AT_INDEX_ALLOCATION:
		// TODO
		printf("%s\n", todo);
		return;
	case AT_BITMAP:
		printf(skip, "BITMAP");
		return;
	case AT_REPARSE_POINT:
		// TODO
		printf("%s\n", todo);
		return;
	case AT_EA_INFORMATION:
		// TODO
		printf("%s\n", don_t_know);
		return;
	case AT_EA:
		// TODO
		printf("%s\n", don_t_know);
		return;
	case AT_LOGGED_UTILITY_STREAM:
		// TODO
		printf("%s\n", don_t_know);
		return;
	default:
		i = le32_to_cpu(type);
		printf("Cannot display unknown %s defined attribute type 0x%x"
				".\n", (u32)i >=
				le32_to_cpu(AT_FIRST_USER_DEFINED_ATTRIBUTE) ?
				"user" : "system", i);
	}
}

/**
 * dump_resident_attr
 */
static void dump_resident_attr(ATTR_RECORD *a)
{
	int i;

	i = le32_to_cpu(a->value_length);
	printf("Attribute value length = %u (0x%x)\n", i, i);
	i = le16_to_cpu(a->value_offset);
	printf("Attribute value offset = %u (0x%x)\n", i, i);
	i = a->resident_flags;
	printf("Resident flags = 0x%x: ", i);
	if (!i)
		printf("NONE\n");
	else if (i & ~RESIDENT_ATTR_IS_INDEXED)
		printf("UNKNOWN FLAG(S)\n");
	else
		printf("RESIDENT_ATTR_IS_INDEXED\n");
	dump_resident_attr_val(a->type, (char*)a + le16_to_cpu(a->value_offset),
			le32_to_cpu(a->value_length));
}

/**
 * dump_mapping_pairs_array
 */
static void dump_mapping_pairs_array(char *b, unsigned int max_len)
{
	// TODO
	return;
}

/**
 * dump_non_resident_attr
 */
static void dump_non_resident_attr(ATTR_RECORD *a)
{
	s64 l;
	int i;

	l = sle64_to_cpu(a->lowest_vcn);
	printf("Lowest VCN = %lli (0x%llx)\n", (long long)l,
			(unsigned long long)l);
	l = sle64_to_cpu(a->highest_vcn);
	printf("Highest VCN = %lli (0x%llx)\n", (long long)l,
			(unsigned long long)l);
	printf("Mapping pairs array offset = 0x%x\n",
			le16_to_cpu(a->mapping_pairs_offset));
	printf("Compression unit = 0x%x: %sCOMPRESSED\n", a->compression_unit,
			a->compression_unit ? "" : "NOT ");
	if (sle64_to_cpu(a->lowest_vcn))
		printf("Attribute is not the first extent. The following "
				"sizes are meaningless:\n");
	l = sle64_to_cpu(a->allocated_size);
	printf("Allocated size = %lli (0x%llx)\n", (long long)l,
			(unsigned long long)l);
	l = sle64_to_cpu(a->data_size);
	printf("Data size = %lli (0x%llx)\n", (long long)l,
			(unsigned long long)l);
	l = sle64_to_cpu(a->initialized_size);
	printf("Initialized size = %lli (0x%llx)\n",
			(long long)l, (unsigned long long)l);
	if (a->flags & ATTR_COMPRESSION_MASK) {
		l = sle64_to_cpu(a->compressed_size);
		printf("Compressed size = %lli (0x%llx)\n",
				(long long)l, (unsigned long long)l);
	}
	i = le16_to_cpu(a->mapping_pairs_offset);
	dump_mapping_pairs_array((char*)a + i, le32_to_cpu(a->length) - i);
}

/**
 * dump_attr_record
 */
static void dump_attr_record(ATTR_RECORD *a)
{
	unsigned int u;
	char s[0x200];
	int i;

	printf("-- Beginning dump of attribute record. --\n");
	if (a->type == AT_END) {
		printf("Attribute type = 0x%x ($END)\n",
				(unsigned int)le32_to_cpu(AT_END));
		u = le32_to_cpu(a->length);
		printf("Length of resident part = %u (0x%x)\n", u, u);
		return;
	}
	u = le32_to_cpu(a->type);
	for (i = 0; opts.attr_defs[i].type; i++)
		if (le32_to_cpu(opts.attr_defs[i].type) >= u)
			break;
	if (opts.attr_defs[i].type) {
//		printf("type = 0x%x\n", le32_to_cpu(opts.attr_defs[i].type));
//		{ char *p = (char*)opts.attr_defs[i].name;
//		printf("name = %c%c%c%c%c\n", *p, p[1], p[2], p[3], p[4]);
//		}
		if (ucstos(s, opts.attr_defs[i].name, sizeof(s)) == -1) {
			Eprintf("Could not convert Unicode string to single "
				"byte string in current locale.\n");
			strncpy(s, "Error converting Unicode string",
					sizeof(s));
		}
	} else
		strncpy(s, "UNKNOWN_TYPE", sizeof(s));
	printf("Attribute type = 0x%x (%s)\n", u, s);
	u = le32_to_cpu(a->length);
	printf("Length of resident part = %u (0x%x)\n", u, u);
	printf("Attribute is %sresident\n", a->non_resident ? "non-" : "");
	printf("Name length = %u unicode characters\n", a->name_length);
	printf("Name offset = %u (0x%x)\n", cpu_to_le16(a->name_offset),
			cpu_to_le16(a->name_offset));
	u = a->flags;
	if (a->name_length) {
		if (ucstos(s, (uchar_t*)((char*)a +
				cpu_to_le16(a->name_offset)),
				min(sizeof(s), a->name_length + 1U)) == -1) {
			Eprintf("Could not convert Unicode string to single "
				"byte string in current locale.\n");
			strncpy(s, "Error converting Unicode string",
					sizeof(s));

		}
		printf("Name = %s\n", s);
	}
	printf("Attribute flags = 0x%x: ", le16_to_cpu(u));
	if (!u)
		printf("NONE");
	else {
		int first = TRUE;
		if (u & ATTR_COMPRESSION_MASK) {
			if (u & ATTR_IS_COMPRESSED) {
				printf("ATTR_IS_COMPRESSED");
				first = FALSE;
			}
			if ((u & ATTR_COMPRESSION_MASK) & ~ATTR_IS_COMPRESSED) {
				if (!first)
					printf(" | ");
				else
					first = FALSE;
				printf("ATTR_UNKNOWN_COMPRESSION");
			}
		}
		if (u & ATTR_IS_ENCRYPTED) {
			if (!first)
				printf(" | ");
			else
				first = FALSE;
			printf("ATTR_IS_ENCRYPTED");
		}
		if (u & ATTR_IS_SPARSE) {
			if (!first)
				printf(" | ");
			else
				first = FALSE;
			printf("ATTR_IS_SPARSE");
		}
	}
	printf("\n");
	printf("Attribute instance = %u\n", le16_to_cpu(a->instance));
	if (a->non_resident) {
		dump_non_resident_attr(a);
	} else {
		dump_resident_attr(a);
	}
}

/**
 * dump_mft_record
 */
static void dump_mft_record(MFT_RECORD *m) __attribute__((unused));
static void dump_mft_record(MFT_RECORD *m)
{
	ATTR_RECORD *a;
	unsigned int u;
	MFT_REF r;

	printf("-- Beginning dump of mft record. --\n");
	u = le32_to_cpu(m->magic);
	printf("Mft record signature (magic) = %c%c%c%c\n", u & 0xff,
			u >> 8 & 0xff, u >> 16 & 0xff, u >> 24 & 0xff);
	u = le16_to_cpu(m->usa_ofs);
	printf("Update sequence array offset = %u (0x%x)\n", u, u);
	printf("Update sequence array size = %u\n", le16_to_cpu(m->usa_count));
	printf("$LogFile sequence number (lsn) = %llu\n",
			(unsigned long long)le64_to_cpu(m->lsn));
	printf("Sequence number = %u\n", le16_to_cpu(m->sequence_number));
	printf("Reference (hard link) count = %u\n",
						le16_to_cpu(m->link_count));
	u = le16_to_cpu(m->attrs_offset);
	printf("First attribute offset = %u (0x%x)\n", u, u);
	printf("Flags = %u: ", le16_to_cpu(m->flags));
	if (m->flags & MFT_RECORD_IN_USE)
		printf("MFT_RECORD_IN_USE");
	else
		printf("MFT_RECORD_NOT_IN_USE");
	if (m->flags & MFT_RECORD_IS_DIRECTORY)
		printf(" | MFT_RECORD_IS_DIRECTORY");
	printf("\n");
	u = le32_to_cpu(m->bytes_in_use);
	printf("Bytes in use = %u (0x%x)\n", u, u);
	u = le32_to_cpu(m->bytes_allocated);
	printf("Bytes allocated = %u (0x%x)\n", u, u);
	r = le64_to_cpu(m->base_mft_record);
	printf("Base mft record reference:\n\tMft record number = %llu\n\t"
			"Sequence number = %u\n", (unsigned long long)MREF(r),
			MSEQNO(r));
	printf("Next attribute instance = %u\n",
			le16_to_cpu(m->next_attr_instance));
	a = (ATTR_RECORD*)((char*)m + le16_to_cpu(m->attrs_offset));
	printf("-- Beginning dump of attributes within mft record. --\n");
	while ((char*)a < (char*)m + le32_to_cpu(m->bytes_in_use)) {
		dump_attr_record(a);
		if (a->type == AT_END)
			break;
		a = (ATTR_RECORD*)((char*)a + le32_to_cpu(a->length));
	};
	printf("-- End of attributes. --\n");
}

/**
 * make_room_for_attribute - make room for an attribute inside an mft record
 * @m:		mft record
 * @pos:	position at which to make space
 * @size:	byte size to make available at this position
 *
 * @pos points to the attribute in front of which we want to make space.
 *
 * Return 0 on success or -errno on error. Possible error codes are:
 *
 *	-ENOSPC		There is not enough space available to complete
 *			operation. The caller has to make space before calling
 *			this.
 *	-EINVAL		Can only occur if mkntfs was compiled with -DEBUG. Means
 *			the input parameters were faulty.
 */
static int make_room_for_attribute(MFT_RECORD *m, char *pos, const u32 size)
{
	u32 biu;

	if (!size)
		return 0;
#ifdef DEBUG
	/*
	 * Rigorous consistency checks. Always return -EINVAL even if more
	 * appropriate codes exist for simplicity of parsing the return value.
	 */
	if (size != ((size + 7) & ~7)) {
		Eprintf("make_room_for_attribute() received non 8-byte aligned"
				"size.\n");
		return -EINVAL;
	}
	if (!m || !pos)
		return -EINVAL;
	if (pos < (char*)m || pos + size < (char*)m ||
			pos > (char*)m + le32_to_cpu(m->bytes_allocated) ||
			pos + size > (char*)m + le32_to_cpu(m->bytes_allocated))
		return -EINVAL;
	/* The -8 is for the attribute terminator. */
	if (pos - (char*)m > le32_to_cpu(m->bytes_in_use) - 8)
		return -EINVAL;
#endif
	biu = le32_to_cpu(m->bytes_in_use);
	/* Do we have enough space? */
	if (biu + size > le32_to_cpu(m->bytes_allocated))
		return -ENOSPC;
	/* Move everything after pos to pos + size. */
	memmove(pos + size, pos, biu - (pos - (char*)m));
	/* Update mft record. */
	m->bytes_in_use = cpu_to_le32(biu + size);
	return 0;
}

/**
 * deallocate_scattered_clusters
 */
static void deallocate_scattered_clusters(const runlist *rl)
{
	LCN j;
	int i;

	if (!rl)
		return;
	/* Iterate over all runs in the runlist @rl. */
	for (i = 0; rl[i].length; i++) {
		/* Skip sparse runs. */
		if (rl[i].lcn == -1LL)
			continue;
		/* Deallocate the current run. */
		for (j = rl[i].lcn; j < rl[i].lcn + rl[i].length; j++)
			ntfs_bit_set(lcn_bitmap, j, 0);
	}
}

/**
 * allocate_scattered_clusters
 * Allocate @clusters and create a runlist of the allocated clusters.
 *
 * Return the allocated runlist. Caller has to free the runlist when finished
 * with it.
 *
 * On error return NULL and errno is set to the error code.
 *
 * TODO: We should be returning the size as well, but for mkntfs this is not
 * necessary.
 */
static runlist *allocate_scattered_clusters(s64 clusters)
{
	runlist *rl = NULL, *rlt;
	VCN vcn = 0LL;
	LCN lcn, end, prev_lcn = 0LL;
	int rlpos = 0;
	int rlsize = 0;
	s64 prev_run_len = 0LL;
	char bit;

	end = opts.nr_clusters;
	/* Loop until all clusters are allocated. */
	while (clusters) {
		/* Loop in current zone until we run out of free clusters. */
		for (lcn = opts.mft_zone_end; lcn < end; lcn++) {
			bit = ntfs_bit_get_and_set(lcn_bitmap, lcn, 1);
			if (bit)
				continue;
			/*
			 * Reallocate memory if necessary. Make sure we have
			 * enough for the terminator entry as well.
			 */
			if ((rlpos + 2) * (int)sizeof(runlist) >= rlsize) {
				rlsize += 4096; /* PAGE_SIZE */
				rlt = realloc(rl, rlsize);
				if (!rlt)
					goto err_end;
				rl = rlt;
			}
			/* Coalesce with previous run if adjacent LCNs. */
			if (prev_lcn == lcn - prev_run_len) {
				rl[rlpos - 1].length = ++prev_run_len;
				vcn++;
			} else {
				rl[rlpos].vcn = vcn++;
				rl[rlpos].lcn = prev_lcn = lcn;
				rl[rlpos].length = prev_run_len = 1LL;
				rlpos++;
			}
			/* Done? */
			if (!--clusters) {
				/* Add terminator element and return. */
				rl[rlpos].vcn = vcn;
				rl[rlpos].lcn = rl[rlpos].length = 0LL;
				return rl;
			}

		}
		/* Switch to next zone, decreasing mft zone by factor 2. */
		end = opts.mft_zone_end;
		opts.mft_zone_end >>= 1;
		/* Have we run out of space on the volume? */
		if (opts.mft_zone_end <= 0)
			goto err_end;
	}
	return rl;
err_end:
	if (rl) {
		/* Add terminator element. */
		rl[rlpos].vcn = vcn;
		rl[rlpos].lcn = -1LL;
		rl[rlpos].length = 0LL;
		/* Deallocate all allocated clusters. */
		deallocate_scattered_clusters(rl);
		/* Free the runlist. */
		free(rl);
	}
	return NULL;
}

/**
 * insert_positioned_attr_in_mft_record
 * Create a non-resident attribute with a predefined on disk location
 * specified by the runlist @rl. The clusters specified by @rl are assumed to
 * be allocated already.
 *
 * Return 0 on success and -errno on error.
 */
static int insert_positioned_attr_in_mft_record(MFT_RECORD *m,
		const ATTR_TYPES type, const char *name, u32 name_len,
		const IGNORE_CASE_BOOL ic, const ATTR_FLAGS flags,
		const runlist *rl, const char *val, const s64 val_len)
{
	ntfs_attr_search_ctx *ctx;
	ATTR_RECORD *a;
	u16 hdr_size;
	int asize, mpa_size, err, i;
	s64 bw = 0, inited_size;
	VCN highest_vcn;
	uchar_t *uname;
/*
	if (base record)
		attr_lookup();
	else
*/
	if (name_len) {
		i = (name_len + 1) * sizeof(uchar_t);
		uname = (uchar_t*)calloc(1, i);
		if (!uname)
			return -errno;
		name_len = stoucs(uname, name, i);
		if (name_len > 0xff) {
			free(uname);
			return -ENAMETOOLONG;
		}
	} else
		uname = NULL;
	/* Check if the attribute is already there. */
	ctx = ntfs_attr_get_search_ctx(NULL, m);
	if (!ctx) {
		Eprintf("Failed to allocate attribute search context.\n");
		err = -ENOMEM;
		goto err_out;
	}
	if (ic == IGNORE_CASE) {
		Eprintf("FIXME: Hit unimplemented code path #1.\n");
		err = -ENOTSUP;
		goto err_out;
	}
	if (!ntfs_attr_lookup(type, uname, name_len, ic, 0, NULL, 0, ctx)) {
		err = -EEXIST;
		goto err_out;
	}
	if (errno != ENOENT) {
		Eprintf("Corrupt inode.\n");
		err = -errno;
		goto err_out;
	}
	a = ctx->attr;
	if (flags & ATTR_COMPRESSION_MASK) {
		Eprintf("Compressed attributes not supported yet.\n");
		// FIXME: Compress attribute into a temporary buffer, set
		// val accordingly and save the compressed size.
		err = -ENOTSUP;
		goto err_out;
	}
	if (flags & (ATTR_IS_ENCRYPTED || ATTR_IS_SPARSE)) {
		Eprintf("Encrypted/sparse attributes not supported yet.\n");
		err = -ENOTSUP;
		goto err_out;
	}
	if (flags & ATTR_COMPRESSION_MASK) {
		hdr_size = 72;
		// FIXME: This compression stuff is all wrong. Never mind for
		// now. (AIA)
		if (val_len)
			mpa_size = 0; //get_size_for_compressed_mapping_pairs(rl);
		else
			mpa_size = 0;
	} else {
		hdr_size = 64;
		if (val_len) {
			mpa_size = ntfs_get_size_for_mapping_pairs(vol, rl);
			if (mpa_size < 0) {
				err = -errno;
				Eprintf("Failed to get size for mapping "
						"pairs.\n");
				goto err_out;
			}
		} else
			mpa_size = 0;
	}
	/* Mapping pairs array and next attribute must be 8-byte aligned. */
	asize = (((int)hdr_size + ((name_len + 7) & ~7) + mpa_size) + 7) & ~7;
	/* Get the highest vcn. */
	for (i = 0, highest_vcn = 0LL; rl[i].length; i++)
		highest_vcn += rl[i].length;
	/* Does the value fit inside the allocated size? */
	if (highest_vcn * vol->cluster_size < val_len) {
		Eprintf("BUG: Allocated size is smaller than data size!\n");
		err = -EINVAL;
		goto err_out;
	}
	err = make_room_for_attribute(m, (char*)a, asize);
	if (err == -ENOSPC) {
		// FIXME: Make space! (AIA)
		// can we make it non-resident? if yes, do that.
		//	does it fit now? yes -> do it.
		// m's $DATA or $BITMAP+$INDEX_ALLOCATION resident?
		// yes -> make non-resident
		//	does it fit now? yes -> do it.
		// make all attributes non-resident
		//	does it fit now? yes -> do it.
		// m is a base record? yes -> allocate extension record
		//	does the new attribute fit in there? yes -> do it.
		// split up runlist into extents and place each in an extension
		// record.
		// FIXME: the check for needing extension records should be
		// earlier on as it is very quick: asize > m->bytes_allocated?
		err = -ENOTSUP;
		goto err_out;
	}
#ifdef DEBUG
	else if (err == -EINVAL) {
		fprintf(stderr, "BUG(): in insert_positioned_attribute_in_mft_"
				"record(): make_room_for_attribute() returned "
				"error: EINVAL!\n");
		goto err_out;
	}
#endif
	a->type = type;
	a->length = cpu_to_le32(asize);
	a->non_resident = 1;
	a->name_length = name_len;
	a->name_offset = cpu_to_le16(hdr_size);
	a->flags = flags;
	a->instance = m->next_attr_instance;
	m->next_attr_instance = cpu_to_le16((le16_to_cpu(m->next_attr_instance)
			+ 1) & 0xffff);
	a->lowest_vcn = cpu_to_le64(0);
	a->highest_vcn = cpu_to_le64(highest_vcn - 1LL);
	a->mapping_pairs_offset = cpu_to_le16(hdr_size + ((name_len + 7) & ~7));
	memset(a->reserved1, 0, sizeof(a->reserved1));
	// FIXME: Allocated size depends on compression.
	a->allocated_size = cpu_to_le64(highest_vcn * vol->cluster_size);
	a->data_size = cpu_to_le64(val_len);
	if (name_len)
		memcpy((char*)a + hdr_size, uname, name_len << 1);
	if (flags & ATTR_COMPRESSION_MASK) {
		if (flags & ATTR_COMPRESSION_MASK & ~ATTR_IS_COMPRESSED) {
			Eprintf("Unknown compression format. Reverting to "
					"standard compression.\n");
			a->flags &= ~ATTR_COMPRESSION_MASK;
			a->flags |= ATTR_IS_COMPRESSED;
		}
		a->compression_unit = 4;
		inited_size = val_len;
		// FIXME: Set the compressed size.
		a->compressed_size = cpu_to_le64(0);
		// FIXME: Write out the compressed data.
		// FIXME: err = build_mapping_pairs_compressed();
		err = -ENOTSUP;
	} else {
		a->compression_unit = 0;
		bw = ntfs_rlwrite(vol->dev, rl, val, val_len, &inited_size);
		if (bw != val_len)
			Eprintf("Error writing non-resident attribute value."
				"\n");
		err = ntfs_mapping_pairs_build(vol, (s8*)a + hdr_size +
				((name_len + 7) & ~7), mpa_size, rl);
	}
	a->initialized_size = cpu_to_le64(inited_size);
	if (err < 0 || bw != val_len) {
		// FIXME: Handle error.
		// deallocate clusters
		// remove attribute
		if (err >= 0)
			err = -EIO;
		Eprintf("insert_positioned_attr_in_mft_record failed with "
				"error %i.\n", err < 0 ? err : (int)bw);
	}
err_out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (uname)
		free(uname);
	return err;
}

/**
 * insert_non_resident_attr_in_mft_record
 * Return 0 on success and -errno on error.
 */
static int insert_non_resident_attr_in_mft_record(MFT_RECORD *m,
		const ATTR_TYPES type, const char *name, u32 name_len,
		const IGNORE_CASE_BOOL ic, const ATTR_FLAGS flags,
		const char *val, const s64 val_len)
{
	ntfs_attr_search_ctx *ctx;
	ATTR_RECORD *a;
	u16 hdr_size;
	int asize, mpa_size, err, i;
	runlist *rl = NULL;
	s64 bw = 0;
	uchar_t *uname;
/*
	if (base record)
		attr_lookup();
	else
*/
	if (name_len) {
		i = (name_len + 1) * sizeof(uchar_t);
		uname = (uchar_t*)calloc(1, i);
		if (!uname)
			return -errno;
		name_len = stoucs(uname, name, i);
		if (name_len > 0xff) {
			free(uname);
			return -ENAMETOOLONG;
		}
	} else
		uname = AT_UNNAMED;
	/* Check if the attribute is already there. */
	ctx = ntfs_attr_get_search_ctx(NULL, m);
	if (!ctx) {
		Eprintf("Failed to allocate attribute search context.\n");
		err = -ENOMEM;
		goto err_out;
	}
	if (ic == IGNORE_CASE) {
		Eprintf("FIXME: Hit unimplemented code path #2.\n");
		err = -ENOTSUP;
		goto err_out;
	}
	if (!ntfs_attr_lookup(type, uname, name_len, ic, 0, NULL, 0, ctx)) {
		err = -EEXIST;
		goto err_out;
	}
	if (errno != ENOENT) {
		Eprintf("Corrupt inode.\n");
		err = -errno;
		goto err_out;
	}
	a = ctx->attr;
	if (flags & ATTR_COMPRESSION_MASK) {
		Eprintf("Compressed attributes not supported yet.\n");
		// FIXME: Compress attribute into a temporary buffer, set
		// val accordingly and save the compressed size.
		err = -ENOTSUP;
		goto err_out;
	}
	if (flags & (ATTR_IS_ENCRYPTED || ATTR_IS_SPARSE)) {
		Eprintf("Encrypted/sparse attributes not supported yet.\n");
		err = -ENOTSUP;
		goto err_out;
	}
	if (val_len) {
		rl = allocate_scattered_clusters((val_len +
				vol->cluster_size - 1) / vol->cluster_size);
		if (!rl) {
			err = -errno;
			Eprintf("Failed to allocate scattered clusters: %s\n",
					strerror(-err));
			goto err_out;
		}
	} else
		rl = NULL;
	if (flags & ATTR_COMPRESSION_MASK) {
		hdr_size = 72;
		// FIXME: This compression stuff is all wrong. Never mind for
		// now. (AIA)
		if (val_len)
			mpa_size = 0; //get_size_for_compressed_mapping_pairs(rl);
		else
			mpa_size = 0;
	} else {
		hdr_size = 64;
		if (val_len) {
			mpa_size = ntfs_get_size_for_mapping_pairs(vol, rl);
			if (mpa_size < 0) {
				err = -errno;
				Eprintf("Failed to get size for mapping "
						"pairs.\n");
				goto err_out;
			}
		} else
			mpa_size = 0;
	}
	/* Mapping pairs array and next attribute must be 8-byte aligned. */
	asize = (((int)hdr_size + ((name_len + 7) & ~7) + mpa_size) + 7) & ~7;
	err = make_room_for_attribute(m, (char*)a, asize);
	if (err == -ENOSPC) {
		// FIXME: Make space! (AIA)
		// can we make it non-resident? if yes, do that.
		//	does it fit now? yes -> do it.
		// m's $DATA or $BITMAP+$INDEX_ALLOCATION resident?
		// yes -> make non-resident
		//	does it fit now? yes -> do it.
		// make all attributes non-resident
		//	does it fit now? yes -> do it.
		// m is a base record? yes -> allocate extension record
		//	does the new attribute fit in there? yes -> do it.
		// split up runlist into extents and place each in an extension
		// record.
		// FIXME: the check for needing extension records should be
		// earlier on as it is very quick: asize > m->bytes_allocated?
		err = -ENOTSUP;
		goto err_out;
	}
#ifdef DEBUG
	else if (err == -EINVAL) {
		fprintf(stderr, "BUG(): in insert_non_resident_attribute_in_"
				"mft_record(): make_room_for_attribute() "
				"returned error: EINVAL!\n");
		goto err_out;
	}
#endif
	a->type = type;
	a->length = cpu_to_le32(asize);
	a->non_resident = 1;
	a->name_length = name_len;
	a->name_offset = cpu_to_le16(hdr_size);
	a->flags = flags;
	a->instance = m->next_attr_instance;
	m->next_attr_instance = cpu_to_le16((le16_to_cpu(m->next_attr_instance)
			+ 1) & 0xffff);
	a->lowest_vcn = cpu_to_le64(0);
	for (i = 0; rl[i].length; i++)
		;
	a->highest_vcn = cpu_to_le64(rl[i].vcn - 1);
	a->mapping_pairs_offset = cpu_to_le16(hdr_size + ((name_len + 7) & ~7));
	memset(a->reserved1, 0, sizeof(a->reserved1));
	// FIXME: Allocated size depends on compression.
	a->allocated_size = cpu_to_le64((val_len + (vol->cluster_size - 1)) &
			~(vol->cluster_size - 1));
	a->data_size = cpu_to_le64(val_len);
	a->initialized_size = cpu_to_le64(val_len);
	if (name_len)
		memcpy((char*)a + hdr_size, uname, name_len << 1);
	if (flags & ATTR_COMPRESSION_MASK) {
		if (flags & ATTR_COMPRESSION_MASK & ~ATTR_IS_COMPRESSED) {
			Eprintf("Unknown compression format. Reverting to "
					"standard compression.\n");
			a->flags &= ~ATTR_COMPRESSION_MASK;
			a->flags |= ATTR_IS_COMPRESSED;
		}
		a->compression_unit = 4;
		// FIXME: Set the compressed size.
		a->compressed_size = cpu_to_le64(0);
		// FIXME: Write out the compressed data.
		// FIXME: err = build_mapping_pairs_compressed();
		err = -ENOTSUP;
	} else {
		a->compression_unit = 0;
		bw = ntfs_rlwrite(vol->dev, rl, val, val_len, NULL);
		if (bw != val_len)
			Eprintf("Error writing non-resident attribute value."
				"\n");
		err = ntfs_mapping_pairs_build(vol, (s8*)a + hdr_size +
				((name_len + 7) & ~7), mpa_size, rl);
	}
	if (err < 0 || bw != val_len) {
		// FIXME: Handle error.
		// deallocate clusters
		// remove attribute
		if (err >= 0)
			err = -EIO;
		Eprintf("insert_non_resident_attr_in_mft_record failed with "
			"error %lld.\n", (long long) (err < 0 ? err : bw));
	}
err_out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (uname && (uname != AT_UNNAMED))
		free(uname);
	if (rl)
		free(rl);
	return err;
}

/**
 * insert_resident_attr_in_mft_record
 * Return 0 on success and -errno on error.
 */
static int insert_resident_attr_in_mft_record(MFT_RECORD *m,
		const ATTR_TYPES type, const char *name, u32 name_len,
		const IGNORE_CASE_BOOL ic, const ATTR_FLAGS flags,
		const RESIDENT_ATTR_FLAGS res_flags,
		const char *val, const u32 val_len)
{
	ntfs_attr_search_ctx *ctx;
	ATTR_RECORD *a;
	int asize, err, i;
	uchar_t *uname;
/*
	if (base record)
		ntfs_attr_lookup();
	else
*/
	if (name_len) {
		i = (name_len + 1) * sizeof(uchar_t);
		uname = (uchar_t*)calloc(1, i);
		name_len = stoucs(uname, name, i);
		if (name_len > 0xff)
			return -ENAMETOOLONG;
	} else
		uname = AT_UNNAMED;
	/* Check if the attribute is already there. */
	ctx = ntfs_attr_get_search_ctx(NULL, m);
	if (!ctx) {
		Eprintf("Failed to allocate attribute search context.\n");
		err = -ENOMEM;
		goto err_out;
	}
	if (ic == IGNORE_CASE) {
		Eprintf("FIXME: Hit unimplemented code path #3.\n");
		err = -ENOTSUP;
		goto err_out;
	}
	if (!ntfs_attr_lookup(type, uname, name_len, ic, 0, val, val_len,
			ctx)) {
		err = -EEXIST;
		goto err_out;
	}
	if (errno != ENOENT) {
		Eprintf("Corrupt inode.\n");
		err = -errno;
		goto err_out;
	}
	a = ctx->attr;
	/* sizeof(resident attribute record header) == 24 */
	asize = ((24 + ((name_len + 7) & ~7) + val_len) + 7) & ~7;
	err = make_room_for_attribute(m, (char*)a, asize);
	if (err == -ENOSPC) {
		// FIXME: Make space! (AIA)
		// can we make it non-resident? if yes, do that.
		//	does it fit now? yes -> do it.
		// m's $DATA or $BITMAP+$INDEX_ALLOCATION resident?
		// yes -> make non-resident
		//	does it fit now? yes -> do it.
		// make all attributes non-resident
		//	does it fit now? yes -> do it.
		// m is a base record? yes -> allocate extension record
		//	does the new attribute fit in there? yes -> do it.
		// split up runlist into extents and place each in an extension
		// record.
		// FIXME: the check for needing extension records should be
		// earlier on as it is very quick: asize > m->bytes_allocated?
		err = -ENOTSUP;
		goto err_out;
	}
#ifdef DEBUG
	if (err == -EINVAL) {
		fprintf(stderr, "BUG(): in insert_resident_attribute_in_mft_"
				"record(): make_room_for_attribute() returned "
				"error: EINVAL!\n");
		goto err_out;
	}
#endif
	a->type = type;
	a->length = cpu_to_le32(asize);
	a->non_resident = 0;
	a->name_length = name_len;
	a->name_offset = cpu_to_le16(24);
	a->flags = cpu_to_le16(flags);
	a->instance = m->next_attr_instance;
	m->next_attr_instance = cpu_to_le16((le16_to_cpu(m->next_attr_instance)
			+ 1) & 0xffff);
	a->value_length = cpu_to_le32(val_len);
	a->value_offset = cpu_to_le16(24 + ((name_len + 7) & ~7));
	a->resident_flags = res_flags;
	a->reservedR = 0;
	if (name_len)
		memcpy((char*)a + 24, uname, name_len << 1);
	if (val_len)
		memcpy((char*)a + le16_to_cpu(a->value_offset), val, val_len);
err_out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (uname && (uname != AT_UNNAMED))
		free(uname);
	return err;
}

/**
 * add_attr_std_info
 * Return 0 on success or -errno on error.
 */
static int add_attr_std_info(MFT_RECORD *m, const FILE_ATTR_FLAGS flags)
{
	STANDARD_INFORMATION si;
	int err;

	si.creation_time = utc2ntfs(time(NULL));
	si.last_data_change_time = si.creation_time;
	si.last_mft_change_time = si.creation_time;
	si.last_access_time = si.creation_time;
	si.file_attributes = flags; /* already LE */
	if (vol->major_ver < 3)
		memset(&si.reserved12, 0, sizeof(si.reserved12));
	else {
		si.maximum_versions = cpu_to_le32(0);
		si.version_number = cpu_to_le32(0);
		si.class_id = cpu_to_le32(0);
		/* FIXME: $Secure support... */
		si.security_id = cpu_to_le32(0);
		/* FIXME: $Quota support... */
		si.owner_id = cpu_to_le32(0);
		si.quota_charged = cpu_to_le64(0ULL);
		/* FIXME: $UsnJrnl support... */
		si.usn = cpu_to_le64(0ULL);
	}
	/* NTFS 1.2: size of si = 48, NTFS 3.0: size of si = 72 */
	err = insert_resident_attr_in_mft_record(m, AT_STANDARD_INFORMATION,
			NULL, 0, 0, 0, 0, (char*)&si,
			vol->major_ver < 3 ? 48 : 72);
	if (err < 0)
		Eprintf("add_attr_std_info failed: %s\n", strerror(-err));
	return err;
}

/**
 * add_attr_file_name
 * Return 0 on success or -errno on error.
 */
static int add_attr_file_name(MFT_RECORD *m, const MFT_REF parent_dir,
		const s64 allocated_size, const s64 data_size,
		const FILE_ATTR_FLAGS flags, const u16 packed_ea_size,
		const u32 reparse_point_tag, const char *file_name,
		const FILE_NAME_TYPE_FLAGS file_name_type)
{
	ntfs_attr_search_ctx *ctx;
	STANDARD_INFORMATION *si;
	FILE_NAME_ATTR *fn;
	int i, fn_size;

	/* Check if the attribute is already there. */
	ctx = ntfs_attr_get_search_ctx(NULL, m);
	if (!ctx) {
		Eprintf("Failed to allocate attribute search context.\n");
		return -ENOMEM;
	}
	if (ntfs_attr_lookup(AT_STANDARD_INFORMATION, AT_UNNAMED, 0, 0, 0, NULL, 0,
			ctx)) {
		int eo = errno;
		Eprintf("BUG: Standard information attribute not present in "
				"file record\n");
		ntfs_attr_put_search_ctx(ctx);
		return -eo;
	}
	si = (STANDARD_INFORMATION*)((char*)ctx->attr +
			le16_to_cpu(ctx->attr->value_offset));
	i = (strlen(file_name) + 1) * sizeof(uchar_t);
	fn_size = sizeof(FILE_NAME_ATTR) + i;
	fn = (FILE_NAME_ATTR*)malloc(fn_size);
	if (!fn) {
		ntfs_attr_put_search_ctx(ctx);
		return -errno;
	}
	fn->parent_directory = parent_dir;

	fn->creation_time = si->creation_time;
	fn->last_data_change_time = si->last_data_change_time;
	fn->last_mft_change_time = si->last_mft_change_time;
	fn->last_access_time = si->last_access_time;
	ntfs_attr_put_search_ctx(ctx);

	fn->allocated_size = cpu_to_le64(allocated_size);
	fn->data_size = cpu_to_le64(data_size);
	fn->file_attributes = flags;
	/* These are in a union so can't have both. */
	if (packed_ea_size && reparse_point_tag) {
		free(fn);
		return -EINVAL;
	}
	if (packed_ea_size) {
		fn->packed_ea_size = cpu_to_le16(packed_ea_size);
		fn->reserved = cpu_to_le16(0);
	} else
		fn->reparse_point_tag = cpu_to_le32(reparse_point_tag);
	fn->file_name_type = file_name_type;
	i = stoucs(fn->file_name, file_name, i);
	if (i < 1) {
		free(fn);
		return -EINVAL;
	}
	if (i > 0xff) {
		free(fn);
		return -ENAMETOOLONG;
	}
	/* No terminating null in file names. */
	fn->file_name_length = i;
	fn_size = sizeof(FILE_NAME_ATTR) + i * sizeof(uchar_t);
	i = insert_resident_attr_in_mft_record(m, AT_FILE_NAME, NULL, 0, 0,
			0, RESIDENT_ATTR_IS_INDEXED, (char*)fn, fn_size);
	free(fn);
	if (i < 0)
		Eprintf("add_attr_file_name failed: %s\n", strerror(-i));
	return i;
}

/**
 * add_attr_sd
 * Create the security descriptor attribute adding the security descriptor @sd
 * of length @sd_len to the mft record @m.
 *
 * Return 0 on success or -errno on error.
 */
static int add_attr_sd(MFT_RECORD *m, const char *sd, const s64 sd_len)
{
	int err;

	/* Does it fit? NO: create non-resident. YES: create resident. */
	if (le32_to_cpu(m->bytes_in_use) + 24 + sd_len >
						le32_to_cpu(m->bytes_allocated))
		err = insert_non_resident_attr_in_mft_record(m,
				AT_SECURITY_DESCRIPTOR, NULL, 0, 0, 0, sd,
				sd_len);
	else
		err = insert_resident_attr_in_mft_record(m,
				AT_SECURITY_DESCRIPTOR, NULL, 0, 0, 0, 0, sd,
				sd_len);
	if (err < 0)
		Eprintf("add_attr_sd failed: %s\n", strerror(-err));
	return err;
}

/**
 * add_attr_data
 * Return 0 on success or -errno on error.
 */
static int add_attr_data(MFT_RECORD *m, const char *name, const u32 name_len,
		const IGNORE_CASE_BOOL ic, const ATTR_FLAGS flags,
		const char *val, const s64 val_len)
{
	int err;

	/*
	 * Does it fit? NO: create non-resident. YES: create resident.
	 *
	 * FIXME: Introduced arbitrary limit of mft record allocated size - 512.
	 * This is to get around the problem that if $Bitmap/$DATA becomes too
	 * big, but is just small enough to be resident, we would make it
	 * resident, and later run out of space when creating the other
	 * attributes and this would cause us to abort as making resident
	 * attributes non-resident is not supported yet.
	 * The proper fix is to support making resident attribute non-resident.
	 */
	if (le32_to_cpu(m->bytes_in_use) + 24 + val_len >
			min(le32_to_cpu(m->bytes_allocated),
			le32_to_cpu(m->bytes_allocated) - 512))
		err = insert_non_resident_attr_in_mft_record(m, AT_DATA, name,
				name_len, ic, flags, val, val_len);
	else
		err = insert_resident_attr_in_mft_record(m, AT_DATA, name,
				name_len, ic, flags, 0, val, val_len);

	if (err < 0)
		Eprintf("add_attr_data failed: %s\n", strerror(-err));
	return err;
}

/**
 * add_attr_data_positioned
 * Create a non-resident data attribute with a predefined on disk location
 * specified by the runlist @rl. The clusters specified by @rl are assumed to
 * be allocated already.
 *
 * Return 0 on success or -errno on error.
 */
static int add_attr_data_positioned(MFT_RECORD *m, const char *name,
		const u32 name_len, const IGNORE_CASE_BOOL ic,
		const ATTR_FLAGS flags, const runlist *rl,
		const char *val, const s64 val_len)
{
	int err;

	err = insert_positioned_attr_in_mft_record(m, AT_DATA, name, name_len,
			ic, flags, rl, val, val_len);
	if (err < 0)
		Eprintf("add_attr_data_positioned failed: %s\n",
				strerror(-err));
	return err;
}

/**
 * add_attr_vol_name
 * Create volume name attribute specifying the volume name @vol_name as a null
 * terminated char string of length @vol_name_len (number of characters not
 * including the terminating null), which is converted internally to a little
 * endian uchar_t string. The name is at least 1 character long and at most
 * 0xff characters long (not counting the terminating null).
 *
 * Return 0 on success or -errno on error.
 */
static int add_attr_vol_name(MFT_RECORD *m, const char *vol_name,
		const int vol_name_len)
{
	uchar_t *uname;
	int i, len;

	if (vol_name_len) {
		len = (vol_name_len + 1) * sizeof(uchar_t);
		uname = calloc(1, len);
		if (!uname)
			return -errno;
		i = (stoucs(uname, vol_name, len) + 1) * sizeof(uchar_t);
		if (!i) {
			free(uname);
			return -EINVAL;
		}
		if (i > 0xff) {
			free(uname);
			return -ENAMETOOLONG;
		}
	} else {
		uname = NULL;
		len = 0;
	}
	i = insert_resident_attr_in_mft_record(m, AT_VOLUME_NAME, NULL, 0, 0,
			0, 0, (char*)uname, len);
	if (uname)
		free(uname);
	if (i < 0)
		Eprintf("add_attr_vol_name failed: %s\n", strerror(-i));
	return i;
}

/**
 * add_attr_vol_info
 * Return 0 on success or -errno on error.
 */
static int add_attr_vol_info(MFT_RECORD *m, const VOLUME_FLAGS flags,
		const u8 major_ver, const u8 minor_ver)
{
	VOLUME_INFORMATION vi;
	int err;

	memset(&vi, 0, sizeof(vi));
	vi.major_ver = major_ver;
	vi.minor_ver = minor_ver;
	vi.flags = flags & VOLUME_FLAGS_MASK;
	err = insert_resident_attr_in_mft_record(m, AT_VOLUME_INFORMATION, NULL,
			0, 0, 0, 0, (char*)&vi, sizeof(vi));
	if (err < 0)
		Eprintf("add_attr_vol_info failed: %s\n", strerror(-err));
	return err;
}

/**
 * add_attr_index_root
 * Return 0 on success or -errno on error.
 */
static int add_attr_index_root(MFT_RECORD *m, const char *name,
		const u32 name_len, const IGNORE_CASE_BOOL ic,
		const ATTR_TYPES indexed_attr_type,
		const COLLATION_RULES collation_rule,
		const u32 index_block_size)
{
	INDEX_ROOT *r;
	INDEX_ENTRY_HEADER *e;
	int err, val_len;

	val_len = sizeof(INDEX_ROOT) + sizeof(INDEX_ENTRY_HEADER);
	r = (INDEX_ROOT*)malloc(val_len);
	if (!r)
		return -errno;
	r->type = indexed_attr_type == AT_FILE_NAME ? AT_FILE_NAME : 0;
	if (indexed_attr_type == AT_FILE_NAME &&
			collation_rule != COLLATION_FILE_NAME) {
		free(r);
		Eprintf("add_attr_index_root: indexed attribute is $FILE_NAME "
			"but collation rule is not COLLATION_FILE_NAME.\n");
		return -EINVAL;
	}
	r->collation_rule = collation_rule;
	r->index_block_size = cpu_to_le32(index_block_size);
	if (index_block_size >= vol->cluster_size) {
		if (index_block_size % vol->cluster_size) {
			Eprintf("add_attr_index_root: index block size is not "
					"a multiple of the cluster size.\n");
			free(r);
			return -EINVAL;
		}
		r->clusters_per_index_block = index_block_size /
				vol->cluster_size;
	} else /* if (vol->cluster_size > index_block_size) */ {
		if (index_block_size & (index_block_size - 1)) {
			Eprintf("add_attr_index_root: index block size is not "
					"a power of 2.\n");
			free(r);
			return -EINVAL;
		}
		if (index_block_size < (u32)opts.sector_size) {
			 Eprintf("add_attr_index_root: index block size is "
					 "smaller than the sector size.\n");
			 free(r);
			 return -EINVAL;
		}
		r->clusters_per_index_block = index_block_size /
				opts.sector_size;
	}
	memset(&r->reserved, 0, sizeof(r->reserved));
	r->index.entries_offset = cpu_to_le32(sizeof(INDEX_HEADER));
	r->index.index_length = cpu_to_le32(sizeof(INDEX_HEADER) +
			sizeof(INDEX_ENTRY_HEADER));
	r->index.allocated_size = r->index.index_length;
	r->index.flags = SMALL_INDEX;
	memset(&r->index.reserved, 0, sizeof(r->index.reserved));
	e = (INDEX_ENTRY_HEADER*)((char*)&r->index +
			le32_to_cpu(r->index.entries_offset));
	/*
	 * No matter whether this is a file index or a view as this is a
	 * termination entry, hence no key value / data is associated with it
	 * at all. Thus, we just need the union to be all zero.
	 */
	e->indexed_file = cpu_to_le64(0LL);
	e->length = cpu_to_le16(sizeof(INDEX_ENTRY_HEADER));
	e->key_length = cpu_to_le16(0);
	e->flags = INDEX_ENTRY_END;
	e->reserved = cpu_to_le16(0);
	err = insert_resident_attr_in_mft_record(m, AT_INDEX_ROOT, name,
				name_len, ic, 0, 0, (char*)r, val_len);
	free(r);
	if (err < 0)
		Eprintf("add_attr_index_root failed: %s\n", strerror(-err));
	return err;
}

/**
 * add_attr_index_alloc
 * Return 0 on success or -errno on error.
 */
static int add_attr_index_alloc(MFT_RECORD *m, const char *name,
		const u32 name_len, const IGNORE_CASE_BOOL ic,
		const char *index_alloc_val, const u32 index_alloc_val_len)
{
	int err;

	err = insert_non_resident_attr_in_mft_record(m, AT_INDEX_ALLOCATION,
			name, name_len, ic, 0, index_alloc_val,
			index_alloc_val_len);
	if (err < 0)
		Eprintf("add_attr_index_alloc failed: %s\n", strerror(-err));
	return err;
}

/**
 * add_attr_bitmap
 * Return 0 on success or -errno on error.
 */
static int add_attr_bitmap(MFT_RECORD *m, const char *name, const u32 name_len,
		const IGNORE_CASE_BOOL ic, const char *bitmap,
		const u32 bitmap_len)
{
	int err;

	/* Does it fit? NO: create non-resident. YES: create resident. */
	if (le32_to_cpu(m->bytes_in_use) + 24 + bitmap_len >
						le32_to_cpu(m->bytes_allocated))
		err = insert_non_resident_attr_in_mft_record(m, AT_BITMAP, name,
				name_len, ic, 0, bitmap, bitmap_len);
	else
		err = insert_resident_attr_in_mft_record(m, AT_BITMAP, name,
				name_len, ic, 0, 0, bitmap, bitmap_len);

	if (err < 0)
		Eprintf("add_attr_bitmap failed: %s\n", strerror(-err));
	return err;
}

/**
 * add_attr_bitmap_positioned
 * Create a non-resident bitmap attribute with a predefined on disk location
 * specified by the runlist @rl. The clusters specified by @rl are assumed to
 * be allocated already.
 *
 * Return 0 on success or -errno on error.
 */
static int add_attr_bitmap_positioned(MFT_RECORD *m, const char *name,
		const u32 name_len, const IGNORE_CASE_BOOL ic,
		const runlist *rl, const char *bitmap, const u32 bitmap_len)
{
	int err;

	err = insert_positioned_attr_in_mft_record(m, AT_BITMAP, name, name_len,
			ic, 0, rl, bitmap, bitmap_len);
	if (err < 0)
		Eprintf("add_attr_bitmap_positioned failed: %s\n",
				strerror(-err));
	return err;
}

/**
 * upgrade_to_large_index
 * Create bitmap and index allocation attributes, modify index root
 * attribute accordingly and move all of the index entries from the index root
 * into the index allocation.
 *
 * Return 0 on success or -errno on error.
 */
static int upgrade_to_large_index(MFT_RECORD *m, const char *name,
		u32 name_len, const IGNORE_CASE_BOOL ic,
		INDEX_ALLOCATION **index)
{
	ntfs_attr_search_ctx *ctx;
	ATTR_RECORD *a;
	INDEX_ROOT *r;
	INDEX_ENTRY *re;
	INDEX_ALLOCATION *ia_val = NULL;
	uchar_t *uname;
	char bmp[8];
	char *re_start, *re_end;
	int i, err, index_block_size;

	if (name_len) {
		i = (name_len + 1) * sizeof(uchar_t);
		uname = (uchar_t*)calloc(1, i);
		if (!uname)
			return -errno;
		name_len = stoucs(uname, name, i);
		if (name_len > 0xff) {
			free(uname);
			return -ENAMETOOLONG;
		}
	} else
		uname = NULL;
	/* Find the index root attribute. */
	ctx = ntfs_attr_get_search_ctx(NULL, m);
	if (!ctx) {
		Eprintf("Failed to allocate attribute search context.\n");
		return -ENOMEM;
	}
	if (ic == IGNORE_CASE) {
		Eprintf("FIXME: Hit unimplemented code path #4.\n");
		err = -ENOTSUP;
		goto err_out;
	}
	err = ntfs_attr_lookup(AT_INDEX_ROOT, uname, name_len, ic, 0, NULL, 0,
			ctx);
	if (uname)
		free(uname);
	if (err) {
		err = -ENOTDIR;
		goto err_out;
	}
	a = ctx->attr;
	if (a->non_resident || a->flags) {
		err = -EINVAL;
		goto err_out;
	}
	r = (INDEX_ROOT*)((char*)a + le16_to_cpu(a->value_offset));
	re_end = (char*)r + le32_to_cpu(a->value_length);
	re_start = (char*)&r->index + le32_to_cpu(r->index.entries_offset);
	re = (INDEX_ENTRY*)re_start;
	index_block_size = le32_to_cpu(r->index_block_size);
	memset(bmp, 0, sizeof(bmp));
	ntfs_bit_set(bmp, 0ULL, 1);
	/* Bitmap has to be at least 8 bytes in size. */
	err = add_attr_bitmap(m, name, name_len, ic, (char*)&bmp, sizeof(bmp));
	if (err)
		goto err_out;
	ia_val = calloc(1, index_block_size);
	if (!ia_val) {
		err = -errno;
		goto err_out;
	}
	/* Setup header. */
	ia_val->magic = magic_INDX;
	ia_val->usa_ofs = cpu_to_le16(sizeof(INDEX_ALLOCATION));
	if (index_block_size >= NTFS_SECTOR_SIZE)
		ia_val->usa_count = cpu_to_le16(index_block_size /
				NTFS_SECTOR_SIZE + 1);
	else {
		ia_val->usa_count = cpu_to_le16(1);
		Qprintf("Sector size is bigger than index block size. Setting "
			"usa_count to 1. If Windows\nchkdsk reports this as "
			"corruption, please email linux-ntfs-dev@lists.sf.net\n"
			"stating that you saw this message and that the file "
			"system created was corrupt.\nThank you.");
	}
	/* Set USN to 1. */
	*(u16*)((char*)ia_val + le16_to_cpu(ia_val->usa_ofs)) =
			cpu_to_le16(1);
	ia_val->lsn = cpu_to_le64(0);
	ia_val->index_block_vcn = cpu_to_le64(0);
	ia_val->index.flags = LEAF_NODE;
	/* Align to 8-byte boundary. */
	ia_val->index.entries_offset = cpu_to_le32((sizeof(INDEX_HEADER) +
			le16_to_cpu(ia_val->usa_count) * 2 + 7) & ~7);
	ia_val->index.allocated_size = cpu_to_le32(index_block_size -
			(sizeof(INDEX_ALLOCATION) - sizeof(INDEX_HEADER)));
	/* Find the last entry in the index root and save it in re. */
	while ((char*)re < re_end && !(re->flags & INDEX_ENTRY_END)) {
		/* Next entry in index root. */
		re = (INDEX_ENTRY*)((char*)re + le16_to_cpu(re->length));
	}
	/* Copy all the entries including the termination entry. */
	i = (char*)re - re_start + le16_to_cpu(re->length);
	memcpy((char*)&ia_val->index +
			le32_to_cpu(ia_val->index.entries_offset), re_start, i);
	/* Finish setting up index allocation. */
	ia_val->index.index_length = cpu_to_le32(i +
			le32_to_cpu(ia_val->index.entries_offset));
	/* Move the termination entry forward to the beginning if necessary. */
	if ((char*)re > re_start) {
		memmove(re_start, (char*)re, le16_to_cpu(re->length));
		re = (INDEX_ENTRY*)re_start;
	}
	/* Now fixup empty index root with pointer to index allocation VCN 0. */
	r->index.flags = LARGE_INDEX;
	re->flags |= INDEX_ENTRY_NODE;
	if (le16_to_cpu(re->length) < sizeof(INDEX_ENTRY_HEADER) + sizeof(VCN))
		re->length = cpu_to_le16(le16_to_cpu(re->length) + sizeof(VCN));
	r->index.index_length = cpu_to_le32(le32_to_cpu(r->index.entries_offset)
			+ le16_to_cpu(re->length));
	r->index.allocated_size = r->index.index_length;
	/* Resize index root attribute. */
	if (ntfs_resident_attr_value_resize(m, a, sizeof(INDEX_ROOT) -
			sizeof(INDEX_HEADER) +
			le32_to_cpu(r->index.allocated_size))) {
		// TODO: Remove the added bitmap!
		// Revert index root from index allocation.
		err = -errno;
		goto err_out;
	}
	/* Set VCN pointer to 0LL. */
	*(VCN*)((char*)re + cpu_to_le16(re->length) - sizeof(VCN)) =
			cpu_to_le64(0);
	err = ntfs_mst_pre_write_fixup((NTFS_RECORD*)ia_val, index_block_size);
	if (err) {
		err = -errno;
		Eprintf("ntfs_mst_pre_write_fixup() failed in "
				"upgrade_to_large_index.\n");
		goto err_out;
	}
	err = add_attr_index_alloc(m, name, name_len, ic, (char*)ia_val,
			index_block_size);
	ntfs_mst_post_write_fixup((NTFS_RECORD*)ia_val);
	if (err) {
		// TODO: Remove the added bitmap!
		// Revert index root from index allocation.
		goto err_out;
	}
	*index = ia_val;
	return 0;
err_out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (ia_val)
		free(ia_val);
	return err;
}

/**
 * make_room_for_index_entry_in_index_block
 * Create space of @size bytes at position @pos inside the index block @index.
 *
 * Return 0 on success or -errno on error.
 */
static int make_room_for_index_entry_in_index_block(INDEX_BLOCK *index,
		INDEX_ENTRY *pos, u32 size)
{
	u32 biu;

	if (!size)
		return 0;
#ifdef DEBUG
	/*
	 * Rigorous consistency checks. Always return -EINVAL even if more
	 * appropriate codes exist for simplicity of parsing the return value.
	 */
	if (size != ((size + 7) & ~7)) {
		Eprintf("make_room_for_index_entry_in_index_block() received "
				"non 8-byte aligned size.\n");
		return -EINVAL;
	}
	if (!index || !pos)
		return -EINVAL;
	if ((char*)pos < (char*)index || (char*)pos + size < (char*)index ||
			(char*)pos > (char*)index + sizeof(INDEX_BLOCK) -
				sizeof(INDEX_HEADER) +
				le32_to_cpu(index->index.allocated_size) ||
			(char*)pos + size > (char*)index + sizeof(INDEX_BLOCK) -
				sizeof(INDEX_HEADER) +
				le32_to_cpu(index->index.allocated_size))
		return -EINVAL;
	/* The - sizeof(INDEX_ENTRY_HEADER) is for the index terminator. */
	if ((char*)pos - (char*)&index->index >
			le32_to_cpu(index->index.index_length)
			- sizeof(INDEX_ENTRY_HEADER))
		return -EINVAL;
#endif
	biu = le32_to_cpu(index->index.index_length);
	/* Do we have enough space? */
	if (biu + size > le32_to_cpu(index->index.allocated_size))
		return -ENOSPC;
	/* Move everything after pos to pos + size. */
	memmove((char*)pos + size, (char*)pos, biu - ((char*)pos -
			(char*)&index->index));
	/* Update index block. */
	index->index.index_length = cpu_to_le32(biu + size);
	return 0;
}

/**
 * insert_file_link_in_dir_index
 * Insert the fully completed FILE_NAME_ATTR @file_name which is inside
 * the file with mft reference @file_ref into the index (allocation) block
 * @index (which belongs to @file_ref's parent directory).
 *
 * Return 0 on success or -errno on error.
 */
static int insert_file_link_in_dir_index(INDEX_BLOCK *index, MFT_REF file_ref,
		FILE_NAME_ATTR *file_name, u32 file_name_size)
{
	int err, i;
	INDEX_ENTRY *ie;
	char *index_end;

	/*
	 * Lookup dir entry @file_name in dir @index to determine correct
	 * insertion location. FIXME: Using a very oversimplified lookup
	 * method which is sufficient for mkntfs but no good whatsoever in
	 * real world scenario. (AIA)
	 */
	index_end = (char*)&index->index +
			le32_to_cpu(index->index.index_length);
	ie = (INDEX_ENTRY*)((char*)&index->index +
			le32_to_cpu(index->index.entries_offset));
	/*
	 * Loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */
	while ((char*)ie < index_end && !(ie->flags & INDEX_ENTRY_END)) {
/*
#ifdef DEBUG
		Dprintf("file_name_attr1->file_name_length = %i\n",
				file_name->file_name_length);
		if (file_name->file_name_length) {
			char *__buf;
			__buf = (char*)calloc(1, file_name->file_name_length +
					1);
			if (!__buf)
				err_exit("Failed to allocate internal buffer: "
						"%s\n", strerror(errno));
			i = ucstos(__buf, (uchar_t*)&file_name->file_name,
					file_name->file_name_length + 1);
			if (i == -1)
				Dprintf("Name contains non-displayable "
						"Unicode characters.\n");
			Dprintf("file_name_attr1->file_name = %s\n", __buf);
			free(__buf);
		}
		Dprintf("file_name_attr2->file_name_length = %i\n",
				ie->key.file_name.file_name_length);
		if (ie->key.file_name.file_name_length) {
			char *__buf;
			__buf = (char*)calloc(1,
					ie->key.file_name.file_name_length + 1);
			if (!__buf)
				err_exit("Failed to allocate internal buffer: "
						"%s\n", strerror(errno));
			i = ucstos(__buf, ie->key.file_name.file_name,
					ie->key.file_name.file_name_length + 1);
			if (i == -1)
				Dprintf("Name contains non-displayable "
						"Unicode characters.\n");
			Dprintf("file_name_attr2->file_name = %s\n", __buf);
			free(__buf);
		}
#endif
*/
		i = ntfs_file_values_compare(file_name,
				(FILE_NAME_ATTR*)&ie->key.file_name, 1,
				IGNORE_CASE, vol->upcase, vol->upcase_len);
		/*
		 * If @file_name collates before ie->key.file_name, there is no
		 * matching index entry.
		 */
		if (i == -1)
			break;
		/* If file names are not equal, continue search. */
		if (i)
			goto do_next;
		/* File names are equal when compared ignoring case. */
		/*
		 * If BOTH file names are in the POSIX namespace, do a case
		 * sensitive comparison as well. Otherwise the names match so
		 * we return -EEXIST. FIXME: There are problems with this in a
		 * real world scenario, when one is POSIX and one isn't, but
		 * fine for mkntfs where we don't use POSIX namespace at all
		 * and hence this following code is luxury. (AIA)
		 */
		if (file_name->file_name_type != FILE_NAME_POSIX ||
		    ie->key.file_name.file_name_type != FILE_NAME_POSIX)
			return -EEXIST;
		i = ntfs_file_values_compare(file_name,
				(FILE_NAME_ATTR*)&ie->key.file_name, 1,
				CASE_SENSITIVE, vol->upcase, vol->upcase_len);
		if (i == -1)
			break;
		/* Complete match. Bugger. Can't insert. */
		if (!i)
			return -EEXIST;
do_next:
#ifdef DEBUG
		/* Next entry. */
		if (!ie->length) {
			Dprintf("BUG: ie->length is zero, breaking out of "
					"loop.\n");
			break;
		}
#endif
		ie = (INDEX_ENTRY*)((char*)ie + le16_to_cpu(ie->length));
	};
	i = (sizeof(INDEX_ENTRY_HEADER) + file_name_size + 7) & ~7;
	err = make_room_for_index_entry_in_index_block(index, ie, i);
	if (err) {
		Eprintf("make_room_for_index_entry_in_index_block failed: "
				"%s\n", strerror(-err));
		return err;
	}
	/* Create entry in place and copy file name attribute value. */
	ie->indexed_file = file_ref;
	ie->length = cpu_to_le16(i);
	ie->key_length = cpu_to_le16(file_name_size);
	ie->flags = cpu_to_le16(0);
	ie->reserved = cpu_to_le16(0);
	memcpy((char*)&ie->key.file_name, (char*)file_name, file_name_size);
	return 0;
}

/**
 * create_hardlink
 * Create a file_name_attribute in the mft record @m_file which points to the
 * parent directory with mft reference @ref_parent.
 *
 * Then, insert an index entry with this file_name_attribute in the index
 * block @index of the index allocation attribute of the parent directory.
 *
 * @ref_file is the mft reference of @m_file.
 *
 * Return 0 on success or -errno on error.
 */
static int create_hardlink(INDEX_BLOCK *index, const MFT_REF ref_parent,
		MFT_RECORD *m_file, const MFT_REF ref_file,
		const s64 allocated_size, const s64 data_size,
		const FILE_ATTR_FLAGS flags, const u16 packed_ea_size,
		const u32 reparse_point_tag, const char *file_name,
		const FILE_NAME_TYPE_FLAGS file_name_type)
{
	FILE_NAME_ATTR *fn;
	int i, fn_size;

	/* Create the file_name attribute. */
	i = (strlen(file_name) + 1) * sizeof(uchar_t);
	fn_size = sizeof(FILE_NAME_ATTR) + i;
	fn = (FILE_NAME_ATTR*)malloc(fn_size);
	if (!fn)
		return -errno;
	fn->parent_directory = ref_parent;
	// FIXME: Is this correct? Or do we have to copy the creation_time
	// from the std info?
	fn->creation_time = utc2ntfs(time(NULL));
	fn->last_data_change_time = fn->creation_time;
	fn->last_mft_change_time = fn->creation_time;
	fn->last_access_time = fn->creation_time;
	fn->allocated_size = cpu_to_le64(allocated_size);
	fn->data_size = cpu_to_le64(data_size);
	fn->file_attributes = flags;
	/* These are in a union so can't have both. */
	if (packed_ea_size && reparse_point_tag) {
		free(fn);
		return -EINVAL;
	}
	if (packed_ea_size) {
		fn->packed_ea_size = cpu_to_le16(packed_ea_size);
		fn->reserved = cpu_to_le16(0);
	} else
		fn->reparse_point_tag = cpu_to_le32(reparse_point_tag);
	fn->file_name_type = file_name_type;
	i = stoucs(fn->file_name, file_name, i);
	if (i < 1) {
		free(fn);
		return -EINVAL;
	}
	if (i > 0xff) {
		free(fn);
		return -ENAMETOOLONG;
	}
	/* No terminating null in file names. */
	fn->file_name_length = i;
	fn_size = sizeof(FILE_NAME_ATTR) + i * sizeof(uchar_t);
	/* Increment the link count of @m_file. */
	i = le16_to_cpu(m_file->link_count);
	if (i == 0xffff) {
		Eprintf("Too many hardlinks present already.\n");
		free(fn);
		return -EINVAL;
	}
	m_file->link_count = cpu_to_le16(i + 1);
	/* Add the file_name to @m_file. */
	i = insert_resident_attr_in_mft_record(m_file, AT_FILE_NAME, NULL, 0, 0,
			0, RESIDENT_ATTR_IS_INDEXED, (char*)fn, fn_size);
	if (i < 0) {
		Eprintf("create_hardlink failed adding file name attribute: "
				"%s\n", strerror(-i));
		free(fn);
		/* Undo link count increment. */
		m_file->link_count = cpu_to_le16(
				le16_to_cpu(m_file->link_count) - 1);
		return i;
	}
	/* Insert the index entry for file_name in @index. */
	i = insert_file_link_in_dir_index(index, ref_file, fn, fn_size);
	if (i < 0) {
		Eprintf("create_hardlink failed inserting index entry: %s\n",
				strerror(-i));
		/* FIXME: Remove the file name attribute from @m_file. */
		free(fn);
		/* Undo link count increment. */
		m_file->link_count = cpu_to_le16(
				le16_to_cpu(m_file->link_count) - 1);
		return i;
	}
	free(fn);
	return 0;
}

/**
 * init_options
 */
static void init_options(void)
{
	memset(&opts, 0, sizeof(opts));
	opts.sectors_per_track = -1;
	opts.heads = -1;
	opts.part_start_sect = -1;
	opts.index_block_size = 4096;
	opts.attr_defs = (ATTR_DEF*)&attrdef_ntfs12_array;
	opts.attr_defs_len = sizeof(attrdef_ntfs12_array);
	//Dprintf("Attr_defs table length = %u\n", opts.attr_defs_len);
}

/**
 * mkntfs_exit
 */
static void mkntfs_exit(void)
{
	if (index_block)
		free(index_block);
	if (buf)
		free(buf);
	if (buf2)
		free(buf2);
	if (lcn_bitmap)
		free(lcn_bitmap);
	if (mft_bitmap)
		free(mft_bitmap);
	if (rl)
		free(rl);
	if (rl_mft)
		free(rl_mft);
	if (rl_mft_bmp)
		free(rl_mft_bmp);
	if (rl_mftmirr)
		free(rl_mftmirr);
	if (rl_logfile)
		free(rl_logfile);
	if (rl_boot)
		free(rl_boot);
	if (rl_bad)
		free(rl_bad);
	if (rl_index)
		free(rl_index);
	if (opts.bad_blocks)
		free(opts.bad_blocks);
	if (opts.attr_defs != (const ATTR_DEF*)attrdef_ntfs12_array)
		free(opts.attr_defs);
	if (!vol)
		return;
	if (vol->upcase)
		free(vol->upcase);
	if (vol->dev) {
		if (NDevOpen(vol->dev) && vol->dev->d_ops->close(vol->dev))
			Eprintf("Warning: Could not close %s: %s\n",
					vol->dev->d_name, strerror(errno));
		ntfs_device_free(vol->dev);
	}
	free(vol);
}

/**
 * mkntfs_open_partition -
 */
static void mkntfs_open_partition(void)
{
	int i;
	struct stat sbuf;
	unsigned long mnt_flags;

	/*
	 * Allocate and initialize an ntfs device structure and attach it to
	 * the volume.
	 */
	if (!(vol->dev = ntfs_device_alloc(dev_name, 0,
			&ntfs_device_default_io_ops, NULL)))
		err_exit("Could not allocate memory for internal buffer.\n");
	/* Open the device for reading or reading and writing. */
	if (opts.no_action) {
		Qprintf("Running in READ-ONLY mode!\n");
		i = O_RDONLY;
	} else
		i = O_RDWR;
	if (vol->dev->d_ops->open(vol->dev, i)) {
		if (errno == ENOENT)
			err_exit("The device doesn't exist; did you specify "
					"it correctly?\n");
		err_exit("Could not open %s: %s\n", vol->dev->d_name,
				strerror(errno));
	}
	/* Verify we are dealing with a block device. */
	if (vol->dev->d_ops->stat(vol->dev, &sbuf)) {
		err_exit("Error getting information about %s: %s\n",
				vol->dev->d_name, strerror(errno));
	}
	if (!S_ISBLK(sbuf.st_mode)) {
		Eprintf("%s is not a block device.\n", vol->dev->d_name);
		if (!opts.force)
			err_exit("Refusing to make a filesystem here!\n");
		if (!opts.nr_sectors) {
			if (!sbuf.st_size && !sbuf.st_blocks)
				err_exit("You must specify the number of "
						"sectors.\n");
			if (opts.sector_size) {
				if (sbuf.st_size)
					opts.nr_sectors = sbuf.st_size /
							opts.sector_size;
				else
					opts.nr_sectors = ((s64)sbuf.st_blocks
							<< 9) /	opts.sector_size;
			} else {
				if (sbuf.st_size)
					opts.nr_sectors = sbuf.st_size / 512;
				else
					opts.nr_sectors = sbuf.st_blocks;
				opts.sector_size = 512;
			}
		}
		fprintf(stderr, "mkntfs forced anyway.\n");
	}
#ifdef HAVE_LINUX_MAJOR_H
	else if ((IDE_DISK_MAJOR(MAJOR(sbuf.st_rdev)) &&
			MINOR(sbuf.st_rdev) % 64 == 0) ||
			(SCSI_DISK_MAJOR(MAJOR(sbuf.st_rdev)) &&
			MINOR(sbuf.st_rdev) % 16 == 0)) {
		Eprintf("%s is entire device, not just one partition.\n",
				vol->dev->d_name);
		if (!opts.force)
			err_exit("Refusing to make a filesystem here!\n");
		fprintf(stderr, "mkntfs forced anyway.\n");
	}
#endif
	/* Make sure the file system is not mounted. */
	if (ntfs_check_if_mounted(vol->dev->d_name, &mnt_flags))
		Eprintf("Failed to determine whether %s is mounted: %s\n",
				vol->dev->d_name, strerror(errno));
	else if (mnt_flags & NTFS_MF_MOUNTED) {
		Eprintf("%s is mounted.\n", vol->dev->d_name);
		if (!opts.force)
			err_exit("Refusing to make a filesystem here!\n");
		fprintf(stderr, "mkntfs forced anyway. Hope /etc/mtab is "
				"incorrect.\n");
	}
}

/**
 * mkntfs_override_phys_params -
 */
static void mkntfs_override_phys_params(void)
{
	/* If user didn't specify the sector size, determine it now. */
	if (!opts.sector_size) {
#ifdef BLKSSZGET
		int _sect_size = 0;

		if (vol->dev->d_ops->ioctl(vol->dev, BLKSSZGET, &_sect_size)
				>= 0)
			opts.sector_size = _sect_size;
		else
#endif
		{
			Eprintf("No sector size specified for %s and it could "
					"not be obtained automatically.\n"
					"Assuming sector size is 512 bytes.\n",
					vol->dev->d_name);
			opts.sector_size = 512;
		}
	}
	/* Validate sector size. */
	if ((opts.sector_size - 1) & opts.sector_size ||
			opts.sector_size < 256 || opts.sector_size > 4096)
		err_exit("sector_size is invalid. It must be a power "
			 "of two, and it must be\n greater or equal 256 and "
			 "less than or equal 4096 bytes.\n");
	Dprintf("sector size = %i bytes\n", opts.sector_size);
	/* If user didn't specify the number of sectors, determine it now. */
	if (!opts.nr_sectors) {
		opts.nr_sectors = ntfs_device_size_get(vol->dev,
				opts.sector_size);
		if (opts.nr_sectors <= 0)
			err_exit("ntfs_device_size_get(%s) failed. Please "
					"specify it manually.\n",
					vol->dev->d_name);
	}
	Dprintf("number of sectors = %lld (0x%llx)\n", opts.nr_sectors,
			opts.nr_sectors);
	/* Reserve the last sector for the backup boot sector. */
	opts.nr_sectors--;
	/* If user didn't specify the partition start sector, determine it. */
	if (opts.part_start_sect < 0) {
		opts.part_start_sect = ntfs_device_partition_start_sector_get(
				vol->dev);
		if (opts.part_start_sect < 0) {
			Eprintf("No partition start sector specified for %s "
					"and it could not\nbe obtained "
					"automatically.  Setting it to 0.\n"
					"This will cause Windows not to be "
					"able to boot from this volume.\n",
					vol->dev->d_name);
			opts.part_start_sect = 0;
		} else if (opts.part_start_sect >> 32) {
			Eprintf("No partition start sector specified for %s "
					"and the automatically\ndetermined "
					"value is too large.  Setting it to 0."
					"  This will cause Windows not\nto be "
					"able to boot from this volume.\n",
					vol->dev->d_name);
			opts.part_start_sect = 0;
		}
	} else if (opts.part_start_sect >> 32)
		err_exit("Invalid partition start sector specified: %lli  "
				"Maximum is 4294967295 (2^32-1).\n",
				opts.part_start_sect);
	/* If user didn't specify the sectors per track, determine it now. */
	if (opts.sectors_per_track < 0) {
		opts.sectors_per_track =
				ntfs_device_sectors_per_track_get(vol->dev);
		if (opts.sectors_per_track < 0) {
			Eprintf("No number of sectors per track specified for "
					"%s and\nit could not be obtained "
					"automatically.  Setting it to 0.  "
					"This will cause\nWindows not to be "
					"able to boot from this volume.\n",
					vol->dev->d_name);
			opts.sectors_per_track = 0;
		} else if (opts.sectors_per_track > 0xffff) {
			Eprintf("No number of sectors per track specified for "
					"%s and the automatically\ndetermined "
					"value is too large.  Setting it to 0."
					"  This will cause Windows not\nto be "
					"able to boot from this volume.\n",
					vol->dev->d_name);
			opts.sectors_per_track = 0;
		}
	} else if (opts.sectors_per_track > 0xffff)
		err_exit("Invalid number of sectors per track specified: %i  "
				"Maximum is 65535 (0xffff).\n",
				opts.sectors_per_track);
	/* If user didn't specify the number of heads, determine it now. */
	if (opts.heads < 0) {
		opts.heads = ntfs_device_heads_get(vol->dev);
		if (opts.heads < 0) {
			Eprintf("No number of heads specified for %s and it "
					"could not\nbe obtained automatically."
					"  Setting it to 0.  This will cause "
					"Windows not to\nbe able to boot from "
					"this volume.\n", vol->dev->d_name);
			opts.heads = 0;
		} else if (opts.heads > 0xffff) {
			Eprintf("No number of heads specified for %s and the "
					"automatically\ndetermined value is "
					"too large.  Setting it to 0.  This "
					"will cause Windows not\nto be able "
					"to boot from this volume.\n",
					vol->dev->d_name);
			opts.heads = 0;
		}
	} else if (opts.heads > 0xffff)
		err_exit("Invalid number of heads specified: %i  Maximum is "
				"65535 (0xffff).\n", opts.heads);
	/* If user didn't specify the volume size, determine it now. */
	if (!opts.volume_size)
		opts.volume_size = opts.nr_sectors * opts.sector_size;
	else if (opts.volume_size & (opts.sector_size - 1))
		err_exit("volume_size is not a multiple of sector_size.\n");
	/* Validate volume size. */
	if (opts.volume_size < 1 << 20 /* 1MiB */)
		err_exit("Device is too small (%ikiB). Minimum NTFS volume "
			 "size is 1MiB.\n", opts.volume_size / 1024);
	Dprintf("volume size = %llikiB\n", opts.volume_size / 1024);
	/* If user didn't specify the cluster size, determine it now. */
	if (!vol->cluster_size) {
		if (opts.volume_size <= 512LL << 20)	/* <= 512MB */
			vol->cluster_size = 512;
		else if (opts.volume_size <= 1LL << 30)	/* ]512MB-1GB] */
			vol->cluster_size = 1024;
		else if (opts.volume_size <= 2LL << 30)	/* ]1GB-2GB] */
			vol->cluster_size = 2048;
		else
			vol->cluster_size = 4096;
		/* For small volumes on devices with large sector sizes. */
		if (vol->cluster_size < (u32)opts.sector_size)
			vol->cluster_size = opts.sector_size;
		/*
		 * For huge volumes, grow the cluster size until the number of
		 * clusters fits into 32 bits or the cluster size exceeds the
		 * maximum limit of 64kiB.
		 */
		while (opts.volume_size >> (ffs(vol->cluster_size) - 1 + 32)) {
			vol->cluster_size <<= 1;
			if (vol->cluster_size > 65536)
				err_exit("Device is too large to hold an NTFS "
						"volume (maximum size is "
						"256TiB).\n");
		}
	}
	/* Validate cluster size. */
	if (vol->cluster_size & (vol->cluster_size - 1) ||
	    vol->cluster_size < (u32)opts.sector_size ||
	    vol->cluster_size > 128 * (u32)opts.sector_size ||
	    vol->cluster_size > 65536)
		err_exit("Cluster_size is invalid. It must be a power of two, "
			 "be at least\nthe same as sector_size, be maximum "
			 "64kiB, and the sectors per cluster value has\n"
			 "to fit inside eight bits. (We do not support larger "
			 "cluster sizes yet.)\n");
	vol->cluster_size_bits = ffs(vol->cluster_size) - 1;
	Dprintf("cluster size = %i bytes\n", vol->cluster_size);
	if (vol->cluster_size > 4096) {
		if (opts.enable_compression) {
			if (!opts.force)
				err_exit("Cluster_size is above 4096 bytes "
						"and compression is "
						"requested.\nThis is not "
						"possible due to limitations "
						"in the compression algorithm "
						"used by\nWindows.\n");
			opts.enable_compression = 0;
		}
		Qprintf("Warning: compression will be disabled on this volume "
				"because it is not\nsupported when the cluster "
				"size is above 4096 bytes. This is due to \n"
				"limitations in the compression algorithm used "
				"by Windows.\n");
	}
	/* If user didn't specify the number of clusters, determine it now. */
	if (!opts.nr_clusters)
		opts.nr_clusters = opts.volume_size / vol->cluster_size;
	/*
	 * Check the cluster_size and nr_sectors for consistency with
	 * sector_size and nr_sectors. And check both of these for consistency
	 * with volume_size.
	 */
	if (opts.nr_clusters != (opts.nr_sectors * opts.sector_size) /
			vol->cluster_size ||
	    opts.volume_size / opts.sector_size != opts.nr_sectors ||
	    opts.volume_size / vol->cluster_size != opts.nr_clusters)
		err_exit("Illegal combination of volume/cluster/sector size "
			 "and/or cluster/sector number.\n");
	Dprintf("number of clusters = %llu (0x%llx)\n", opts.nr_clusters,
			opts.nr_clusters);
	/* Number of clusters must fit within 32 bits (Win2k limitation). */
	if (opts.nr_clusters >> 32) {
		if (vol->cluster_size >= 65536)
			err_exit("Device is too large to hold an NTFS volume "
					"(maximum size is 256TiB).\n");
		err_exit("Number of clusters exceeds 32 bits. Please try "
				"again with a larger\ncluster size or leave "
				"the cluster size unspecified and the "
				"smallest possible\ncluster size for the size "
				"of the device will be used.\n");
	}
}

/**
 * mkntfs_initialize_bitmaps -
 */
static void mkntfs_initialize_bitmaps(void)
{
	int i, j;
	
	/* Determine lcn bitmap byte size and allocate it. */
	lcn_bitmap_byte_size = (opts.nr_clusters + 7) >> 3;
	/* Needs to be multiple of 8 bytes. */
	lcn_bitmap_byte_size = (lcn_bitmap_byte_size + 7) & ~7;
	i = (lcn_bitmap_byte_size + vol->cluster_size - 1) &
			~(vol->cluster_size - 1);
	Dprintf("lcn_bitmap_byte_size = %i, allocated = %i\n",
			lcn_bitmap_byte_size, i);
	lcn_bitmap = (unsigned char *)calloc(1, lcn_bitmap_byte_size);
	if (!lcn_bitmap)
		err_exit("Failed to allocate internal buffer: %s",
				strerror(errno));
	/*
	 * $Bitmap can overlap the end of the volume. Any bits in this region
	 * must be set. This region also encompasses the backup boot sector.
	 */
	for (i = opts.nr_clusters; i < lcn_bitmap_byte_size << 3; i++)
		ntfs_bit_set(lcn_bitmap, (u64)i, 1);
	/*
	 * Determine mft_size: 16 mft records or 1 cluster, which ever is
	 * bigger, rounded to multiples of cluster size.
	 */
	opts.mft_size = (16 * vol->mft_record_size + vol->cluster_size - 1)
			& ~(vol->cluster_size - 1);
	Dprintf("MFT size = %i (0x%x) bytes\n", opts.mft_size, opts.mft_size);
	/* Determine mft bitmap size and allocate it. */
	mft_bitmap_size = opts.mft_size / vol->mft_record_size;
	/* Convert to bytes, at least one. */
	mft_bitmap_byte_size = (mft_bitmap_size + 7) >> 3;
	/* Mft bitmap is allocated in multiples of 8 bytes. */
	mft_bitmap_byte_size = (mft_bitmap_byte_size + 7) & ~7;
	Dprintf("mft_bitmap_size = %i, mft_bitmap_byte_size = %i\n",
			mft_bitmap_size, mft_bitmap_byte_size);
	mft_bitmap = (unsigned char *)calloc(1, mft_bitmap_byte_size);
	if (!mft_bitmap)
		err_exit("Failed to allocate internal buffer: %s\n",
				strerror(errno));
	/* Create runlist for mft bitmap. */
	rl_mft_bmp = (runlist *)malloc(2 * sizeof(runlist));
	if (!rl_mft_bmp)
		err_exit("Failed to allocate internal buffer: %s\n",
				strerror(errno));
	rl_mft_bmp[0].vcn = 0LL;
	/* Mft bitmap is right after $Boot's data. */
	j = (8192 + vol->cluster_size - 1) / vol->cluster_size;
	rl_mft_bmp[0].lcn = j;
	/*
	 * Size is always one cluster, even though valid data size and
	 * initialized data size are only 8 bytes.
	 */
	rl_mft_bmp[1].vcn = rl_mft_bmp[0].length = 1LL;
	rl_mft_bmp[1].lcn = -1LL;
	rl_mft_bmp[1].length = 0LL;
	/* Allocate cluster for mft bitmap. */
	ntfs_bit_set(lcn_bitmap, (s64)j, 1);
}

/**
 * mkntfs_initialize_rl_mft -
 */
static void mkntfs_initialize_rl_mft(void)
{
	int i, j;
	
	/* If user didn't specify the mft lcn, determine it now. */
	if (!opts.mft_lcn) {
		/*
		 * We start at the higher value out of 16kiB and just after the
		 * mft bitmap.
		 */
		opts.mft_lcn = rl_mft_bmp[0].lcn + rl_mft_bmp[0].length;
		if (opts.mft_lcn * vol->cluster_size < 16 * 1024)
			opts.mft_lcn = (16 * 1024 + vol->cluster_size - 1) /
					vol->cluster_size;
	}
	Dprintf("$MFT logical cluster number = 0x%x\n", opts.mft_lcn);
	/* Determine MFT zone size. */
	opts.mft_zone_end = opts.nr_clusters;
	switch (opts.mft_zone_multiplier) {  /* % of volume size in clusters */
	case 4:
		opts.mft_zone_end = opts.mft_zone_end >> 1;	/* 50%   */
		break;
	case 3:
		opts.mft_zone_end = opts.mft_zone_end * 3 >> 3;	/* 37.5% */
		break;
	case 2:
		opts.mft_zone_end = opts.mft_zone_end >> 2;	/* 25%   */
		break;
	/* case 1: */
	default:
		opts.mft_zone_end = opts.mft_zone_end >> 3;	/* 12.5% */
		break;
	}
	Dprintf("MFT zone size = %lukiB\n", opts.mft_zone_end / 1024);
	/*
	 * The mft zone begins with the mft data attribute, not at the beginning
	 * of the device.
	 */
	opts.mft_zone_end += opts.mft_lcn;
	/* Create runlist for mft. */
	rl_mft = (runlist *)malloc(2 * sizeof(runlist));
	if (!rl_mft)
		err_exit("Failed to allocate internal buffer: %s\n",
				strerror(errno));
	rl_mft[0].vcn = 0LL;
	rl_mft[0].lcn = opts.mft_lcn;
	/* We already rounded mft size up to a cluster. */
	j = opts.mft_size / vol->cluster_size;
	rl_mft[1].vcn = rl_mft[0].length = j;
	rl_mft[1].lcn = -1LL;
	rl_mft[1].length = 0LL;
	/* Allocate clusters for mft. */
	for (i = 0; i < j; i++)
		ntfs_bit_set(lcn_bitmap, opts.mft_lcn + i, 1);
	/* Determine mftmirr_lcn (middle of volume). */
	opts.mftmirr_lcn = (opts.nr_sectors * opts.sector_size >> 1)
							/ vol->cluster_size;
	Dprintf("$MFTMirr logical cluster number = 0x%x\n", opts.mftmirr_lcn);
	/* Create runlist for mft mirror. */
	rl_mftmirr = (runlist *)malloc(2 * sizeof(runlist));
	if (!rl_mftmirr)
		err_exit("Failed to allocate internal buffer: %s\n",
				strerror(errno));
	rl_mftmirr[0].vcn = 0LL;
	rl_mftmirr[0].lcn = opts.mftmirr_lcn;
	/*
	 * The mft mirror is either 4kb (the first four records) or one cluster
	 * in size, which ever is bigger. In either case, it contains a
	 * byte-for-byte identical copy of the beginning of the mft (i.e. either
	 * ther first four records (4kb) or the first cluster worth of records,
	 * whichever is bigger).
	 */
	j = (4 * vol->mft_record_size + vol->cluster_size - 1) / vol->cluster_size;
	rl_mftmirr[1].vcn = rl_mftmirr[0].length = j;
	rl_mftmirr[1].lcn = -1LL;
	rl_mftmirr[1].length = 0LL;
	/* Allocate clusters for mft mirror. */
	for (i = 0; i < j; i++)
		ntfs_bit_set(lcn_bitmap, opts.mftmirr_lcn + i, 1);
	opts.logfile_lcn = opts.mftmirr_lcn + j;
	Dprintf("$LogFile logical cluster number = 0x%x\n", opts.logfile_lcn);
}

/**
 * mkntfs_initialize_rl_logfile -
 */
static void mkntfs_initialize_rl_logfile(void)
{
	int i, j;

	/* Create runlist for log file. */
	rl_logfile = (runlist *)malloc(2 * sizeof(runlist));
	if (!rl_logfile)
		err_exit("Failed to allocate internal buffer: %s\n",
				strerror(errno));
	rl_logfile[0].vcn = 0LL;
	rl_logfile[0].lcn = opts.logfile_lcn;
	/*
	 * Determine logfile_size from volume_size (rounded up to a cluster),
	 * making sure it does not overflow the end of the volume.
	 */
	if (opts.volume_size < 2048LL * 1024)		/* < 2MiB	*/
		opts.logfile_size = 256LL * 1024;	/*   -> 256kiB	*/
	else if (opts.volume_size < 4000000LL)		/* < 4MB	*/
		opts.logfile_size = 512LL * 1024;	/*   -> 512kiB	*/
	else if (opts.volume_size <= 200LL * 1024 * 1024)/* < 200MiB	*/
		opts.logfile_size = 2048LL * 1024;	/*   -> 2MiB	*/
	else if (opts.volume_size >= 400LL << 20)	/* > 400MiB	*/
		opts.logfile_size = 4 << 20;		/*   -> 4MiB	*/
	else
		opts.logfile_size = (opts.volume_size / 100) &
				~(vol->cluster_size - 1);
	j = opts.logfile_size / vol->cluster_size;
	while (rl_logfile[0].lcn + j >= opts.nr_clusters) {
		/*
		 * $Logfile would overflow volume. Need to make it smaller than
		 * the standard size. It's ok as we are creating a non-standard
		 * volume anyway if it is that small.
		 */
		opts.logfile_size >>= 1;
		j = opts.logfile_size / vol->cluster_size;
	}
	opts.logfile_size = (opts.logfile_size + vol->cluster_size - 1) &
			~(vol->cluster_size - 1);
	Dprintf("$LogFile (journal) size = %ikiB\n", opts.logfile_size / 1024);
	/*
	 * FIXME: The 256kiB limit is arbitrary. Should find out what the real
	 * minimum requirement for Windows is so it doesn't blue screen.
	 */
	if (opts.logfile_size < 256 << 10)
		err_exit("$LogFile would be created with invalid size. This "
				"is not allowed as it would cause Windows to "
				"blue screen and during boot.\n");
	rl_logfile[1].vcn = rl_logfile[0].length = j;
	rl_logfile[1].lcn = -1LL;
	rl_logfile[1].length = 0LL;
	/* Allocate clusters for log file. */
	for (i = 0; i < j; i++)
		ntfs_bit_set(lcn_bitmap, opts.logfile_lcn + i, 1);
}

/**
 * mkntfs_initialize_rl_boot -
 */
static void mkntfs_initialize_rl_boot(void)
{
	int i, j;
	/* Create runlist for $Boot. */
	rl_boot = (runlist *)malloc(2 * sizeof(runlist));
	if (!rl_boot)
		err_exit("Failed to allocate internal buffer: %s\n",
				strerror(errno));
	rl_boot[0].vcn = 0LL;
	rl_boot[0].lcn = 0LL;
	/*
	 * $Boot is always 8192 (0x2000) bytes or 1 cluster, whichever is
	 * bigger.
	 */
	j = (8192 + vol->cluster_size - 1) / vol->cluster_size;
	rl_boot[1].vcn = rl_boot[0].length = j;
	rl_boot[1].lcn = -1LL;
	rl_boot[1].length = 0LL;
	/* Allocate clusters for $Boot. */
	for (i = 0; i < j; i++)
		ntfs_bit_set(lcn_bitmap, 0LL + i, 1);
}

/**
 * mkntfs_initialize_rl_bad -
 */
static void mkntfs_initialize_rl_bad(void)
{
	/* Create runlist for $BadClus, $DATA named stream $Bad. */
	rl_bad = (runlist *)malloc(2 * sizeof(runlist));
	if (!rl_bad)
		err_exit("Failed to allocate internal buffer: %s\n",
				strerror(errno));
	rl_bad[0].vcn = 0LL;
	rl_bad[0].lcn = -1LL;
	/*
	 * $BadClus named stream $Bad contains the whole volume as a single
	 * sparse runlist entry.
	 */
	rl_bad[1].vcn = rl_bad[0].length = opts.nr_clusters;
	rl_bad[1].lcn = -1LL;
	rl_bad[1].length = 0LL;

	// TODO: Mark bad blocks as such.
}

/**
 * mkntfs_fill_device_with_zeroes -
 */
static void mkntfs_fill_device_with_zeroes(void)
{
	/*
	 * If not quick format, fill the device with 0s.
	 * FIXME: Except bad blocks! (AIA)
	 */
	int i;
	ssize_t bw;
	unsigned long position;
	unsigned long mid_clust;
	float progress_inc = (float)opts.nr_clusters / 100;

	Qprintf("Initialising device with zeroes:   0%%");
	fflush(stdout);
	mid_clust = (opts.volume_size >> 1) / vol->cluster_size;
	for (position = 0; position < opts.nr_clusters; position++) {
		if (!(position % (int)(progress_inc+1))) {
			Qprintf("\b\b\b\b%3.0f%%", position /
					progress_inc);
			fflush(stdout);
		}
		bw = mkntfs_write(vol->dev, buf, vol->cluster_size);
		if (bw != (ssize_t)vol->cluster_size) {
			if (bw != -1 || errno != EIO)
				err_exit("This should not happen.\n");
			if (!position)
				err_exit("Error: Cluster zero is bad. "
					"Cannot create NTFS file "
					"system.\n");
			if (position == mid_clust &&
					(vol->major_ver < 1 ||
					 (vol->major_ver == 1 &&
					  vol->minor_ver < 2)))
				err_exit("Error: Bad cluster found in "
					"location reserved for system "
					"file $Boot.\n");
			/* Add the baddie to our bad blocks list. */
			append_to_bad_blocks(position);
			Qprintf("\nFound bad cluster (%ld). Adding to "
				"list of bad blocks.\nInitialising "
				"device with zeroes: %3.0f%%", position,
				position / progress_inc);
			/* Seek to next cluster. */
			vol->dev->d_ops->seek(vol->dev,
					((off_t)position + 1) *
					vol->cluster_size, SEEK_SET);
		}
	}
	Qprintf("\b\b\b\b100%%");
	position = (opts.volume_size & (vol->cluster_size - 1)) /
			opts.sector_size;
	for (i = 0; (unsigned long)i < position; i++) {
		bw = mkntfs_write(vol->dev, buf, opts.sector_size);
		if (bw != opts.sector_size) {
			if (bw != -1 || errno != EIO)
				err_exit("This should not happen.\n");
			else if (i + 1UL == position &&
					(vol->major_ver >= 2 ||
					 (vol->major_ver == 1 &&
					  vol->minor_ver >= 2)))
				err_exit("Error: Bad cluster found in "
					"location reserved for system "
					"file $Boot.\n");
			/* Seek to next sector. */
			vol->dev->d_ops->seek(vol->dev,
					opts.sector_size, SEEK_CUR);
		}
	}
	Qprintf(" - Done.\n");
}

/**
 * mkntfs_create_root_structures -
 */
static void mkntfs_create_root_structures(void)
{
	NTFS_BOOT_SECTOR *bs;
	ATTR_RECORD *a;
	MFT_RECORD *m;
	MFT_REF root_ref;
	ssize_t bw;
	int i, j, err;
	char *sd;

	Qprintf("Creating NTFS volume structures.\n");
	/*
	 * Setup an empty mft record.  Note, we can just give 0 as the mft
	 * reference as we are creating an NTFS 1.2 volume for which the mft
	 * reference is ignored by ntfs_mft_record_layout().
	 */
	if (ntfs_mft_record_layout(vol, 0, (MFT_RECORD *)buf))
		err_exit("Error:  Failed to layout mft record.\n");
#if 0
	if (!opts.quiet && opts.verbose > 1)
		dump_mft_record((MFT_RECORD*)buf);
#endif
	/*
	 * Copy the mft record onto all 16 records in the buffer and setup the
	 * sequence numbers of each system file to equal the mft record number
	 * of that file (only for $MFT is the sequence number 1 rather than 0).
	 */
	for (i = 1; i < 16; i++) {
		m = (MFT_RECORD*)(buf + i * vol->mft_record_size);
		memcpy(m, buf, vol->mft_record_size);
		m->sequence_number = cpu_to_le16(i);
	}
	/*
	 * If a cluster contains more than the 16 system files, fill the rest
	 * with empty, formatted records.
	 */
	if (vol->cluster_size > 16 * vol->mft_record_size) {
		for (i = 16; i * vol->mft_record_size < vol->cluster_size; i++)
			memcpy(buf + i * vol->mft_record_size, buf,
					vol->mft_record_size);
	}
	/*
	 * Create the 16 system files, adding the system information attribute
	 * to each as well as marking them in use in the mft bitmap.
	 */
	for (i = 0; i < 16; i++) {
		u32 file_attrs;

		m = (MFT_RECORD*)(buf + i * vol->mft_record_size);
		m->flags |= MFT_RECORD_IN_USE;
		ntfs_bit_set(mft_bitmap, 0LL + i, 1);
		file_attrs = FILE_ATTR_HIDDEN | FILE_ATTR_SYSTEM;
		if (i == FILE_root) {
			if (opts.disable_indexing)
				file_attrs |= FILE_ATTR_NOT_CONTENT_INDEXED;
			if (opts.enable_compression)
				file_attrs |= FILE_ATTR_COMPRESSED;
		}
		add_attr_std_info(m, file_attrs);
		// dump_mft_record(m);
	}
	/* The root directory mft reference. */
	root_ref = MK_LE_MREF(FILE_root, FILE_root);
	Vprintf("Creating root directory (mft record 5)\n");
	m = (MFT_RECORD*)(buf + 5 * vol->mft_record_size);
	m->flags |= MFT_RECORD_IS_DIRECTORY;
	m->link_count = cpu_to_le16(le16_to_cpu(m->link_count) + 1);
	err = add_attr_file_name(m, root_ref, 0LL, 0LL,
			FILE_ATTR_HIDDEN | FILE_ATTR_SYSTEM |
			FILE_ATTR_DUP_FILE_NAME_INDEX_PRESENT, 0, 0,
			".", FILE_NAME_WIN32_AND_DOS);
	if (!err) {
		init_system_file_sd(FILE_root, &sd, &i);
		err = add_attr_sd(m, sd, i);
	}
	// FIXME: This should be IGNORE_CASE
	if (!err)
		err = add_attr_index_root(m, "$I30", 4, 0, AT_FILE_NAME,
				COLLATION_FILE_NAME, opts.index_block_size);
	// FIXME: This should be IGNORE_CASE
	if (!err)
		err = upgrade_to_large_index(m, "$I30", 4, 0, &index_block);
	if (!err) {
		ntfs_attr_search_ctx *ctx;
		ctx = ntfs_attr_get_search_ctx(NULL, m);
		if (!ctx)
			err_exit("Failed to allocate attribute search "
					"context: %s\n", strerror(errno));
		/* There is exactly one file name so this is ok. */
		if (ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, 0, 0, NULL, 0,
				ctx)) {
			ntfs_attr_put_search_ctx(ctx);
			err_exit("BUG: $FILE_NAME attribute not found.\n");
		}
		a = ctx->attr;
		err = insert_file_link_in_dir_index(index_block, root_ref,
				(FILE_NAME_ATTR*)((char*)a +
				le16_to_cpu(a->value_offset)),
				le32_to_cpu(a->value_length));
		ntfs_attr_put_search_ctx(ctx);
	}
	if (err)
		err_exit("Couldn't create root directory: %s\n",
				strerror(-err));
	// dump_mft_record(m);
	/* Add all other attributes, on a per-file basis for clarity. */
	Vprintf("Creating $MFT (mft record 0)\n");
	m = (MFT_RECORD*)buf;
	err = add_attr_data_positioned(m, NULL, 0, 0, 0, rl_mft, buf,
			opts.mft_size);
	if (!err)
		err = create_hardlink(index_block, root_ref, m,
				MK_LE_MREF(FILE_MFT, 1), opts.mft_size,
				opts.mft_size, FILE_ATTR_HIDDEN |
				FILE_ATTR_SYSTEM, 0, 0, "$MFT",
				FILE_NAME_WIN32_AND_DOS);
	if (!err) {
		init_system_file_sd(FILE_MFT, &sd, &i);
		err = add_attr_sd(m, sd, i);
	}
	/* mft_bitmap is not modified in mkntfs; no need to sync it later. */
	if (!err)
		err = add_attr_bitmap_positioned(m, NULL, 0, 0, rl_mft_bmp,
				mft_bitmap, mft_bitmap_byte_size);
	if (err < 0)
		err_exit("Couldn't create $MFT: %s\n", strerror(-err));
	//dump_mft_record(m);
	Vprintf("Creating $MFTMirr (mft record 1)\n");
	m = (MFT_RECORD*)(buf + 1 * vol->mft_record_size);
	err = add_attr_data_positioned(m, NULL, 0, 0, 0, rl_mftmirr, buf,
			rl_mftmirr[0].length * vol->cluster_size);
	if (!err)
		err = create_hardlink(index_block, root_ref, m,
				MK_LE_MREF(FILE_MFTMirr, FILE_MFTMirr),
				rl_mftmirr[0].length * vol->cluster_size,
				rl_mftmirr[0].length * vol->cluster_size,
				FILE_ATTR_HIDDEN | FILE_ATTR_SYSTEM, 0, 0,
				"$MFTMirr", FILE_NAME_WIN32_AND_DOS);
	if (!err) {
		init_system_file_sd(FILE_MFTMirr, &sd, &i);
		err = add_attr_sd(m, sd, i);
	}
	if (err < 0)
		err_exit("Couldn't create $MFTMirr: %s\n", strerror(-err));
	//dump_mft_record(m);
	Vprintf("Creating $LogFile (mft record 2)\n");
	m = (MFT_RECORD*)(buf + 2 * vol->mft_record_size);
	buf2 = malloc(opts.logfile_size);
	if (!buf2)
		err_exit("Failed to allocate internal buffer: %s\n",
				strerror(errno));
	memset(buf2, -1, opts.logfile_size);
	err = add_attr_data_positioned(m, NULL, 0, 0, 0, rl_logfile, buf2,
			opts.logfile_size);
	free(buf2);
	buf2 = NULL;
	if (!err)
		err = create_hardlink(index_block, root_ref, m,
				MK_LE_MREF(FILE_LogFile, FILE_LogFile),
				opts.logfile_size, opts.logfile_size,
				FILE_ATTR_HIDDEN | FILE_ATTR_SYSTEM, 0, 0,
				"$LogFile", FILE_NAME_WIN32_AND_DOS);
	if (!err) {
		init_system_file_sd(FILE_LogFile, &sd, &i);
		err = add_attr_sd(m, sd, i);
	}
	if (err < 0)
		err_exit("Couldn't create $LogFile: %s\n", strerror(-err));
	//dump_mft_record(m);
	Vprintf("Creating $Volume (mft record 3)\n");
	m = (MFT_RECORD*)(buf + 3 * vol->mft_record_size);
	err = create_hardlink(index_block, root_ref, m,
			MK_LE_MREF(FILE_Volume, FILE_Volume), 0LL, 0LL,
			FILE_ATTR_HIDDEN | FILE_ATTR_SYSTEM, 0, 0,
			"$Volume", FILE_NAME_WIN32_AND_DOS);
	if (!err) {
		init_system_file_sd(FILE_Volume, &sd, &i);
		err = add_attr_sd(m, sd, i);
	}
	if (!err)
		err = add_attr_data(m, NULL, 0, 0, 0, NULL, 0);
	if (!err)
		err = add_attr_vol_name(m, vol->vol_name, vol->vol_name ?
				strlen(vol->vol_name) : 0);
	if (!err) {
		Qprintf("Setting the volume dirty so check disk runs on next "
				"reboot into Windows.\n");
		err = add_attr_vol_info(m, VOLUME_IS_DIRTY, vol->major_ver,
				vol->minor_ver);
	}
	if (err < 0)
		err_exit("Couldn't create $Volume: %s\n", strerror(-err));
	//dump_mft_record(m);
	Vprintf("Creating $AttrDef (mft record 4)\n");
	m = (MFT_RECORD*)(buf + 4 * vol->mft_record_size);
	if (vol->major_ver < 3)
		buf2_size = 36000;
	else
		buf2_size = opts.attr_defs_len;
	buf2 = (char*)calloc(1, buf2_size);
	if (!buf2)
		err_exit("Failed to allocate internal buffer: %s\n",
				strerror(errno));
	memcpy(buf2, opts.attr_defs, opts.attr_defs_len);
	err = add_attr_data(m, NULL, 0, 0, 0, buf2, buf2_size);
	free(buf2);
	buf2 = NULL;
	if (!err)
		err = create_hardlink(index_block, root_ref, m,
				MK_LE_MREF(FILE_AttrDef, FILE_AttrDef),
				(buf2_size + vol->cluster_size - 1) &
				~(vol->cluster_size - 1), buf2_size,
				FILE_ATTR_HIDDEN | FILE_ATTR_SYSTEM, 0, 0,
				"$AttrDef", FILE_NAME_WIN32_AND_DOS);
	buf2_size = 0;
	if (!err) {
		init_system_file_sd(FILE_AttrDef, &sd, &i);
		err = add_attr_sd(m, sd, i);
	}
	if (err < 0)
		err_exit("Couldn't create $AttrDef: %s\n", strerror(-err));
	//dump_mft_record(m);
	Vprintf("Creating $Bitmap (mft record 6)\n");
	m = (MFT_RECORD*)(buf + 6 * vol->mft_record_size);
	err = add_attr_data(m, NULL, 0, 0, 0, lcn_bitmap, lcn_bitmap_byte_size);
	if (!err)
		err = create_hardlink(index_block, root_ref, m,
				MK_LE_MREF(FILE_Bitmap, FILE_Bitmap),
				(lcn_bitmap_byte_size + vol->cluster_size - 1) &
				~(vol->cluster_size - 1), lcn_bitmap_byte_size,
				FILE_ATTR_HIDDEN | FILE_ATTR_SYSTEM, 0, 0,
				"$Bitmap", FILE_NAME_WIN32_AND_DOS);
	if (!err) {
		init_system_file_sd(FILE_Bitmap, &sd, &i);
		err = add_attr_sd(m, sd, i);
	}
	if (err < 0)
		err_exit("Couldn't create $Bitmap: %s\n", strerror(-err));
	//dump_mft_record(m);
	Vprintf("Creating $Boot (mft record 7)\n");
	m = (MFT_RECORD*)(buf + 7 * vol->mft_record_size);
	buf2 = calloc(1, 8192);
	if (!buf2)
		err_exit("Failed to allocate internal buffer: %s\n",
				strerror(errno));
	memcpy(buf2, boot_array, sizeof(boot_array));
	/*
	 * Create the boot sector into buf2. Note, that buf2 already is zeroed
	 * in the boot sector section and that it has the NTFS OEM id/magic
	 * already inserted, so no need to worry about these things.
	 */
	bs = (NTFS_BOOT_SECTOR*)buf2;
	bs->bpb.bytes_per_sector = cpu_to_le16(opts.sector_size);
	bs->bpb.sectors_per_cluster = (u8)(vol->cluster_size /
			opts.sector_size);
	bs->bpb.media_type = 0xf8; /* hard disk */
	bs->bpb.sectors_per_track = cpu_to_le16(opts.sectors_per_track);
	Dprintf("sectors per track = %u (0x%x)\n", opts.sectors_per_track,
			opts.sectors_per_track);
	bs->bpb.heads = cpu_to_le16(opts.heads);
	Dprintf("heads = %u (0x%x)\n", opts.heads, opts.heads);
	bs->bpb.hidden_sectors = cpu_to_le32(opts.part_start_sect);
	Dprintf("hidden sectors = %llu (0x%llx)\n", opts.part_start_sect,
			opts.part_start_sect);
	/*
	 * If there are problems go back to bs->unused[0-3] and set them. See
	 * ../include/layout.h for details. Other fields to also consider
	 * setting are: bs->bpb.sectors_per_track and .heads.
	 */
	bs->number_of_sectors = scpu_to_le64(opts.nr_sectors);
	bs->mft_lcn = scpu_to_le64(opts.mft_lcn);
	bs->mftmirr_lcn = scpu_to_le64(opts.mftmirr_lcn);
	if (vol->mft_record_size >= vol->cluster_size)
		bs->clusters_per_mft_record = vol->mft_record_size /
			vol->cluster_size;
	else {
		bs->clusters_per_mft_record = -(ffs(vol->mft_record_size) - 1);
		if ((u32)(1 << -bs->clusters_per_mft_record) !=
				vol->mft_record_size)
			err_exit("BUG: calculated clusters_per_mft_record "
					"is wrong (= 0x%x)\n",
					bs->clusters_per_mft_record);
	}
	Dprintf("clusters per mft record = %i (0x%x)\n",
			bs->clusters_per_mft_record,
			bs->clusters_per_mft_record);
	if (opts.index_block_size >= (int)vol->cluster_size)
		bs->clusters_per_index_record = opts.index_block_size /
			vol->cluster_size;
	else {
		bs->clusters_per_index_record = -(ffs(opts.index_block_size) - 1);
		if ((1 << -bs->clusters_per_index_record) !=
				opts.index_block_size)
			err_exit("BUG: calculated clusters_per_index_record "
					"is wrong (= 0x%x)\n",
					bs->clusters_per_index_record);
	}
	Dprintf("clusters per index block = %i (0x%x)\n",
			bs->clusters_per_index_record,
			bs->clusters_per_index_record);
	/* Generate a 64-bit random number for the serial number. */
	bs->volume_serial_number = scpu_to_le64(((s64)random() << 32) |
			((s64)random() & 0xffffffff));
	/*
	 * Leave zero for now as NT4 leaves it zero, too. If want it later, see
	 * ../libntfs/bootsect.c for how to calculate it.
	 */
	bs->checksum = cpu_to_le32(0);
	/* Make sure the bootsector is ok. */
	if (!ntfs_boot_sector_is_ntfs(bs, opts.verbose > 0 ? 0 : 1))
		err_exit("FATAL: Generated boot sector is invalid!\n");
	err = add_attr_data_positioned(m, NULL, 0, 0, 0, rl_boot, buf2, 8192);
	if (!err)
		err = create_hardlink(index_block, root_ref, m,
				MK_LE_MREF(FILE_Boot, FILE_Boot),
				(8192 + vol->cluster_size - 1) &
				~(vol->cluster_size - 1), 8192,
				FILE_ATTR_HIDDEN | FILE_ATTR_SYSTEM, 0, 0,
				"$Boot", FILE_NAME_WIN32_AND_DOS);
	if (!err) {
		init_system_file_sd(FILE_Boot, &sd, &i);
		err = add_attr_sd(m, sd, i);
	}
	if (err < 0)
		err_exit("Couldn't create $Boot: %s\n", strerror(-err));
	Vprintf("Creating backup boot sector.\n");
	/*
	 * Write the first max(512, opts.sector_size) bytes from buf2 to the
	 * last sector.
	 */
	if (vol->dev->d_ops->seek(vol->dev, (opts.nr_sectors + 1) *
			opts.sector_size - i, SEEK_SET) == (off_t)-1)
		goto bb_err;
	bw = mkntfs_write(vol->dev, buf2, i);
	free(buf2);
	buf2 = NULL;
	if (bw != i) {
		int _e = errno;
		const char *_s;

		if (bw == -1LL)
			_s = strerror(_e);
		else
			_s = "unknown error";
		if (bw != -1LL || (bw == -1LL && _e != ENOSPC)) {
			err_exit("Couldn't write backup boot sector: %s\n", _s);
bb_err:
			Eprintf("Seek failed: %s\n", strerror(errno));
		}
		Eprintf("Couldn't write backup boot sector. This is due to a "
				"limitation in the\nLinux kernel. This is not "
				"a major problem as Windows check disk will "
				"create the\nbackup boot sector when it "
				"is run on your next boot into Windows.\n");
	}
	//dump_mft_record(m);
	Vprintf("Creating $BadClus (mft record 8)\n");
	m = (MFT_RECORD*)(buf + 8 * vol->mft_record_size);
	// FIXME: This should be IGNORE_CASE
	/* Create a sparse named stream of size equal to the volume size. */
	err = add_attr_data_positioned(m, "$Bad", 4, 0, 0, rl_bad, NULL,
			opts.nr_clusters * vol->cluster_size);
	if (!err) {
		err = add_attr_data(m, NULL, 0, 0, 0, NULL, 0);
	}
	if (!err) {
		err = create_hardlink(index_block, root_ref, m,
				MK_LE_MREF(FILE_BadClus, FILE_BadClus),
				0LL, 0LL, FILE_ATTR_HIDDEN | FILE_ATTR_SYSTEM,
				0, 0, "$BadClus", FILE_NAME_WIN32_AND_DOS);
	}
	if (!err) {
		init_system_file_sd(FILE_BadClus, &sd, &i);
		err = add_attr_sd(m, sd, i);
	}
	if (err < 0)
		err_exit("Couldn't create $BadClus: %s\n", strerror(-err));
	//dump_mft_record(m);
	Vprintf("Creating $Quota (mft record 9)\n");
	m = (MFT_RECORD*)(buf + 9 * vol->mft_record_size);
	err = add_attr_data(m, NULL, 0, 0, 0, NULL, 0);
	if (!err)
		err = create_hardlink(index_block, root_ref, m,
				MK_LE_MREF(9, 9), 0LL, 0LL, FILE_ATTR_HIDDEN
				| FILE_ATTR_SYSTEM, 0, 0, "$Quota",
				FILE_NAME_WIN32_AND_DOS);
	if (!err) {
		init_system_file_sd(FILE_Secure, &sd, &i);
		err = add_attr_sd(m, sd, i);
	}
	if (err < 0)
		err_exit("Couldn't create $Quota: %s\n", strerror(-err));
	//dump_mft_record(m);
	Vprintf("Creating $UpCase (mft record 0xa)\n");
	m = (MFT_RECORD*)(buf + 0xa * vol->mft_record_size);
	err = add_attr_data(m, NULL, 0, 0, 0, (char*)vol->upcase,
			vol->upcase_len << 1);
	if (!err)
		err = create_hardlink(index_block, root_ref, m,
				MK_LE_MREF(FILE_UpCase, FILE_UpCase),
				((vol->upcase_len << 1) + vol->cluster_size - 1) &
				~(vol->cluster_size - 1), vol->upcase_len << 1,
				FILE_ATTR_HIDDEN | FILE_ATTR_SYSTEM, 0, 0,
				"$UpCase", FILE_NAME_WIN32_AND_DOS);
	if (!err) {
		init_system_file_sd(FILE_UpCase, &sd, &i);
		err = add_attr_sd(m, sd, i);
	}
	if (err < 0)
		err_exit("Couldn't create $UpCase: %s\n", strerror(-err));
	//dump_mft_record(m);
	/* NTFS 1.2 reserved system files (mft records 0xb-0xf) */
	for (i = 0xb; i < 0x10; i++) {
		Vprintf("Creating system file (mft record 0x%x)\n", i);
		m = (MFT_RECORD*)(buf + i * vol->mft_record_size);
		err = add_attr_data(m, NULL, 0, 0, 0, NULL, 0);
		if (!err) {
			init_system_file_sd(i, &sd, &j);
			err = add_attr_sd(m, sd, j);
		}
		if (err < 0)
			err_exit("Couldn't create system file %i (0x%x): %s\n",
					i, i, strerror(-err));
		//dump_mft_record(m);
	}
}

/**
 * main
 */
int main(int argc, char **argv)
{
	ntfs_attr_search_ctx *ctx;
	long long lw, pos;
	ATTR_RECORD *a;
	MFT_RECORD *m;
	int i, err;

	/* Setup the correct locale for string output and conversion. */
	utils_set_locale();
	/* Initialize the random number generator with the current time. */
	srandom(time(NULL));
	/* Allocate and initialize ntfs_volume structure vol. */
	vol = ntfs_volume_alloc();
	if (!vol)
		err_exit("Could not allocate memory for internal buffer.\n");
	/* Register our exit function which will cleanup everything. */
	err = atexit(&mkntfs_exit);
	if (err == -1) {
		Eprintf("Could not set up exit() function because atexit() "
				"failed. Aborting...\n");
		mkntfs_exit();
		exit(1);
	}
	vol->major_ver = 1;
	vol->minor_ver = 2;
	vol->mft_record_size = 1024;
	vol->mft_record_size_bits = 10;
	/* Length is in unicode characters. */
	vol->upcase_len = 65536;
	vol->upcase = (uchar_t*)malloc(vol->upcase_len * sizeof(uchar_t));
	if (!vol->upcase)
		err_exit("Could not allocate memory for internal buffer.\n");
	init_upcase_table(vol->upcase, vol->upcase_len * sizeof(uchar_t));
	/* Initialize opts to zero / required values. */
	init_options();
	/* Parse command line options. */
	parse_options(argc, argv);
	/* Open the partition. */
	mkntfs_open_partition();
	/* Decide on the sectors/tracks/heads/size, etc. */
	mkntfs_override_phys_params();
	/* Initialize $Bitmap and $MFT/$BITMAP related stuff. */
	mkntfs_initialize_bitmaps();
	/* Initialize MFT & set opts.logfile_lcn. */
	mkntfs_initialize_rl_mft();
	/* Initlialize $LogFile. */
	mkntfs_initialize_rl_logfile();
	/* Initialize $Boot. */
	mkntfs_initialize_rl_boot();
	/* Allocate a buffer large enough to hold the mft. */
	buf = calloc(1, opts.mft_size);
	if (!buf)
		err_exit("Failed to allocate internal buffer: %s\n",
				strerror(errno));
	/* Create runlist for $BadClus, $DATA named stream $Bad. */
	mkntfs_initialize_rl_bad();
	/* If not quick format, fill the device with 0s. */
	if (!opts.quick_format)
		mkntfs_fill_device_with_zeroes();
	/* Create NTFS volume structures. */
	mkntfs_create_root_structures();
// - Do not step onto bad blocks!!!
// - If any bad blocks were specified or found, modify $BadClus, allocating the
//   bad clusters in $Bitmap.
// - C&w bootsector backup bootsector (backup in last sector of the
//   partition).
// - If NTFS 3.0+, c&w $Secure file and $Extend directory with the
//   corresponding special files in it, i.e. $ObjId, $Quota, $Reparse, and
//   $UsnJrnl. And others? Or not all necessary?
// - RE: Populate $root with the system files (and $Extend directory if
//   applicable). Possibly should move this as far to the top as possible and
//   update during each subsequent c&w of each system file.
	Vprintf("Syncing root directory index record.\n");
	m = (MFT_RECORD*)(buf + 5 * vol->mft_record_size);
	i = 5 * sizeof(uchar_t);
	ctx = ntfs_attr_get_search_ctx(NULL, m);
	if (!ctx)
		err_exit("Failed to allocate attribute search context: %s\n",
				strerror(errno));
	// FIXME: This should be IGNORE_CASE!
	if (ntfs_attr_lookup(AT_INDEX_ALLOCATION, I30, 4, 0, 0,
			NULL, 0, ctx)) {
		ntfs_attr_put_search_ctx(ctx);
		err_exit("BUG: $INDEX_ALLOCATION attribute not found.\n");
	}
	a = ctx->attr;
	rl_index = ntfs_mapping_pairs_decompress(vol, a, NULL);
	if (!rl_index) {
		ntfs_attr_put_search_ctx(ctx);
		err_exit("Failed to decompress runlist of $INDEX_ALLOCATION "
				"attribute.\n");
	}
	if (sle64_to_cpu(a->initialized_size) < i) {
		ntfs_attr_put_search_ctx(ctx);
		err_exit("BUG: $INDEX_ALLOCATION attribute too short.\n");
	}
	ntfs_attr_put_search_ctx(ctx);
	i = sizeof(INDEX_BLOCK) - sizeof(INDEX_HEADER) +
			le32_to_cpu(index_block->index.allocated_size);
	err = ntfs_mst_pre_write_fixup((NTFS_RECORD*)index_block, i);
	if (err)
		err_exit("ntfs_mst_pre_write_fixup() failed while syncing "
				"root directory index block.\n");
	lw = ntfs_rlwrite(vol->dev, rl_index, (char*)index_block, i, NULL);
	if (lw != i)
		err_exit("Error writing $INDEX_ALLOCATION.\n");
	/* No more changes to @index_block below here so no need for fixup: */
	// ntfs_mst_post_write_fixup((NTFS_RECORD*)index_block);
	Vprintf("Syncing $Bitmap.\n");
	m = (MFT_RECORD*)(buf + 6 * vol->mft_record_size);
	ctx = ntfs_attr_get_search_ctx(NULL, m);
	if (!ctx)
		err_exit("Failed to allocate attribute search context: %s\n",
				strerror(errno));
	if (ntfs_attr_lookup(AT_DATA, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx)) {
		ntfs_attr_put_search_ctx(ctx);
		err_exit("BUG: $DATA attribute not found.\n");
	}
	a = ctx->attr;
	if (a->non_resident) {
		rl = ntfs_mapping_pairs_decompress(vol, a, NULL);
		ntfs_attr_put_search_ctx(ctx);
		if (!rl)
			err_exit("ntfs_mapping_pairs_decompress() failed\n");
		lw = ntfs_rlwrite(vol->dev, rl, lcn_bitmap,
				lcn_bitmap_byte_size, NULL);
		if (lw != lcn_bitmap_byte_size)
			err_exit("%s\n", lw == -1 ? strerror(errno) :
					"unknown error");
	} else {
		memcpy((char*)a + le16_to_cpu(a->value_offset), lcn_bitmap,
				le32_to_cpu(a->value_length));
		ntfs_attr_put_search_ctx(ctx);
	}
	/*
	 * No need to sync $MFT/$BITMAP as that has never been modified since
	 * its creation.
	 */
	Vprintf("Syncing $MFT.\n");
	pos = opts.mft_lcn * vol->cluster_size;
	lw = 1;
	for (i = 0; i < opts.mft_size / (s32)vol->mft_record_size; i++) {
		if (!opts.no_action)
			lw = ntfs_mst_pwrite(vol->dev, pos, 1,
					vol->mft_record_size,
					buf + i * vol->mft_record_size);
		if (lw != 1)
			err_exit("%s\n", lw == -1 ? strerror(errno) :
						"unknown error");
		pos += vol->mft_record_size;
	}
	Vprintf("Updating $MFTMirr.\n");
	pos = opts.mftmirr_lcn * vol->cluster_size;
	lw = 1;
	for (i = 0; i < rl_mftmirr[0].length * vol->cluster_size /
			vol->mft_record_size; i++) {
		u16 usn, *usnp;
		m = (MFT_RECORD*)(buf + i * vol->mft_record_size);
		/*
		 * Decrement the usn by one, so it becomes the same as the one
		 * in $MFT once it is mst protected. - This is as we need the
		 * $MFTMirr to have the exact same byte by byte content as
		 * $MFT, rather than just equivalent meaning content.
		 */
		usnp = (u16*)((char*)m + le16_to_cpu(m->usa_ofs));
		usn = le16_to_cpup(usnp);
		if (usn-- <= 1)
			usn = 0xfffe;
		*usnp = cpu_to_le16(usn);
		if (!opts.no_action)
			lw = ntfs_mst_pwrite(vol->dev, pos, 1,
					vol->mft_record_size,
					buf + i * vol->mft_record_size);
		if (lw != 1)
			err_exit("%s\n", lw == -1 ? strerror(errno) :
					"unknown error");
		pos += vol->mft_record_size;
	}
	Vprintf("Syncing device.\n");
	if (vol->dev->d_ops->sync(vol->dev))
		err_exit("Syncing device. FAILED: %s", strerror(errno));
	Qprintf("mkntfs completed successfully. Have a nice day.\n");
	/*
	 * Device is unlocked and closed by the registered exit function
	 * mkntfs_exit().
	 */
	return 0;
}
