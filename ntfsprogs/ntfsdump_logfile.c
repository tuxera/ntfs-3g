/**
 * ntfsdump_logfile - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2000-2004 Anton Altaparmakov
 *
 * This utility will interpret the contents of the journal ($LogFile) of an
 * NTFS partition and display the results on stdout.  Errors will be output to
 * stderr.
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

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "types.h"
#include "endians.h"
#include "volume.h"
#include "inode.h"
#include "attrib.h"
#include "layout.h"
#include "logfile.h"
#include "mst.h"

/**
 * device_err_exit -
 */
void device_err_exit(char *dev_name, ntfs_volume *vol, ntfs_inode *ni,
		ntfs_attr *na, const char *fmt, ...) __attribute__ ((noreturn))
		__attribute__((format(printf, 5, 6)));
void device_err_exit(char *dev_name, ntfs_volume *vol, ntfs_inode *ni,
		ntfs_attr *na, const char *fmt, ...)
{
	va_list ap;

	if (na)
		ntfs_attr_close(na);
	if (ni && ntfs_inode_close(ni))
		fprintf(stderr, "Warning: Failed to close $LogFile (inode "
				"%i): %s\n", FILE_LogFile, strerror(errno));
	if (ntfs_umount(vol, 0))
		fprintf(stderr, "Warning: Failed to umount %s: %s\n",
				dev_name, strerror(errno));
	fprintf(stderr, "ERROR: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "Aborting...\n");
	exit(1);
}

/**
 * log_err_exit -
 */
void log_err_exit(u8 *buf, const char *fmt, ...) __attribute__ ((noreturn))
		__attribute__((format(printf, 2, 3)));
void log_err_exit(u8 *buf, const char *fmt, ...)
{
	va_list ap;

	if (buf)
		free(buf);
	fprintf(stderr, "ERROR: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "Aborting...\n");
	exit(1);
}

/**
 * usage -
 */
void usage(const char *exec_name) __attribute__ ((noreturn));
void usage(const char *exec_name)
{
	fprintf(stderr, "%s v%s - Interpret and display information about the "
			"journal\n($LogFile) of an NTFS volume.\n"
			"Copyright (c) 2000-2004 Anton Altaparmakov.\n"
			"%s is free software, released under the GNU General "
			"Public License\nand you are welcome to redistribute "
			"it under certain conditions.\n%s comes with "
			"ABSOLUTELY NO WARRANTY; for details read the GNU\n"
			"General Public License to be found in the file "
			"COPYING in the main Linux-NTFS\ndistribution "
			"directory.\nUsage: %s device\n    e.g. %s /dev/hda6\n"
			"Alternative usage: %s -f file\n    e.g. %s -f "
			"MyCopyOfTheLogFile\n", exec_name, VERSION, exec_name,
			exec_name, exec_name, exec_name, exec_name, exec_name);
	exit(1);
}

/**
 * main -
 */
int main(int argc, char **argv)
{
	u8 *buf;
	RESTART_PAGE_HEADER *rstr;
	RESTART_AREA *ra;
	LOG_CLIENT_RECORD *lcr;
	RECORD_PAGE_HEADER *rcrd;
	LOG_RECORD *lr;
	int buf_size, err, client, pass = 1;
	unsigned int page_size, usa_end_ofs, i;

	printf("\n");
	if (argc < 2 || argc > 3)
		usage(argv[0]);
	/*
	 * If one argument, it is a device containing an NTFS volume which we
	 * need to mount and read the $LogFile from so we can dump its contents.
	 *
	 * If two arguments the first one must be "-f" and the second one is
	 * the path and name of the $LogFile (or copy thereof) which we need to
	 * read and dump the contents of.
	 */
	if (argc == 2) {
		s64 br;
		ntfs_volume *vol;
		ntfs_inode *ni;
		ntfs_attr *na;

		vol = ntfs_mount(argv[1], MS_RDONLY);
		if (!vol)
			log_err_exit(NULL, "Failed to mount %s: %s\n", argv[1],
					strerror(errno));
		printf("\nMounted NTFS volume %s (NTFS v%i.%i) on device %s.\n",
				vol->vol_name ? vol->vol_name : "<NO_NAME>",
				vol->major_ver, vol->minor_ver, argv[1]);
		if (ntfs_version_is_supported(vol))
			device_err_exit(argv[1], vol, NULL, NULL,
					"Unsupported NTFS version.\n");
		ni = ntfs_inode_open(vol, FILE_LogFile);
		if (!ni)
			device_err_exit(argv[1], vol, NULL, NULL, "Failed to "
					"open $LogFile (inode %i): %s\n",
					FILE_LogFile, strerror(errno));
		na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
		if (!na)
			device_err_exit(argv[1], vol, ni, NULL, "Failed to "
					"open $LogFile/$DATA (attribute "
					"0x%x): %s\n",
					(unsigned int)le32_to_cpu(AT_DATA),
					strerror(errno));
		if (!na->data_size)
			device_err_exit(argv[1], vol, ni, na, "$LogFile has "
					"zero length.  Run chkdsk /f to "
					"correct this.\n");
		if (na->data_size <= 64 * 1024 * 1024)
			buf_size = na->data_size;
		else {
			fprintf(stderr, "Warning: $LogFile is too big.  Only "
					"analysing the first 64MiB.\n");
			buf_size = 64 * 1024 * 1024;
		}
		/* For simplicity we read all of $LogFile/$DATA into memory. */
		buf = malloc(buf_size);
		if (!buf)
			device_err_exit(argv[1], vol, ni, na, "Failed to "
					"allocate buffer for $LogFile/$DATA: "
					"%s", strerror(errno));
		br = ntfs_attr_pread(na, 0, buf_size, buf);
		if (br != buf_size) {
			free(buf);
			device_err_exit(argv[1], vol, ni, na, "Failed to read "
					"$LogFile/$DATA: %s", br < 0 ?
					strerror(errno) : "Partial read.");
		}
		ntfs_attr_close(na);
		if (ntfs_inode_close(ni))
			fprintf(stderr, "Warning: Failed to close $LogFile "
					"(inode %i): %s\n", FILE_LogFile,
					strerror(errno));
		if (ntfs_umount(vol, 0))
			fprintf(stderr, "Warning: Failed to umount %s: %s\n",
					argv[1], strerror(errno));
	} else /* if (argc == 3) */ {
		ssize_t br;
		int fd;
		struct stat sbuf;

		if (strncmp(argv[1], "-f", strlen("-f")))
			usage(argv[0]);
		if (stat(argv[2], &sbuf) == -1) {
			if (errno == ENOENT)
				log_err_exit(NULL, "The file %s does not "
						"exist.  Did you specify it "
						"correctly?\n", argv[2]);
			log_err_exit(NULL, "Error getting information about "
					"%s: %s\n", argv[2], strerror(errno));
		}
		if (sbuf.st_size <= 64 * 1024 * 1024)
			buf_size = sbuf.st_size;
		else {
			fprintf(stderr, "Warning: File %s is too big.  Only "
					"analysing the first 64MiB.\n",
					argv[2]);
			buf_size = 64 * 1024 * 1024;
		}
		/* For simplicity we read all of the file into memory. */
		buf = malloc(buf_size);
		if (!buf)
			log_err_exit(NULL, "Failed to allocate buffer for "
					"file data: %s", strerror(errno));
		fd = open(argv[2], O_RDONLY);
		if (fd == -1)
			log_err_exit(NULL, "Failed to open file %s: %s\n",
					argv[2], strerror(errno));
		/* Read in the file into the buffer. */
		br = read(fd, buf, buf_size);
		err = errno;
		if (close(fd))
			fprintf(stderr, "Warning: Failed to close file %s: "
					"%s\n", argv[2], strerror(errno));
		if (br != buf_size)
			log_err_exit(buf, "Failed to read data from %s: %s",
					argv[2], br < 0 ? strerror(err) :
					"Partial read.");
	}
	/*
	 * We now have the entirety of the journal ($LogFile/$DATA or argv[2])
	 * in the memory buffer buf and this has a size of buf_size.  Note we
	 * apply a size capping at 64MiB, so if the journal is any bigger we
	 * only have the first 64MiB.  This should not be a problem as I have
	 * never seen such a large $LogFile.  Usually it is only a few MiB in
	 * size.
	 */
	rstr = (RESTART_PAGE_HEADER*)buf;
	/* Check for presence of restart area signature. */
	if (!ntfs_is_rstr_record(rstr->magic) &&
			!ntfs_is_chkd_record(rstr->magic)) {
		s8 *pos = (s8*)buf;
		s8 *end = pos + buf_size;
		while (pos < end && *pos == -1)
			pos++;
		if (pos != end)
			log_err_exit(buf, "$LogFile contents are corrupt "
					"(magic RSTR is missing).  Cannot "
					"handle this yet.\n");
		/* All bytes are -1. */
		free(buf);
		puts("$LogFile is not initialized.");
		return 0;
	}
	/*
	 * First, verify the restart page header for consistency.
	 */
	/* Only CHKD records are allowed to have chkdsk_lsn set. */
	if (!ntfs_is_chkd_record(rstr->magic) && sle64_to_cpu(rstr->chkdsk_lsn))
		log_err_exit(buf, "$LogFile is corrupt:  Restart page header "
				"magic is not CHKD but a chkdsk LSN is "
				"specified.  Cannot handle this yet.\n");
	/* Both system and log page size must be >= 512 and a power of 2. */
	page_size = le32_to_cpu(rstr->log_page_size);
	if (page_size < 512 || page_size & (page_size - 1))
		log_err_exit(buf, "$LogFile is corrupt:  Restart page header "
				"specifies invalid log page size.  Cannot "
				"handle this yet.\n");
	if (page_size != le32_to_cpu(rstr->system_page_size)) {
		page_size = le32_to_cpu(rstr->system_page_size);
		if (page_size < 512 || page_size & (page_size - 1))
			log_err_exit(buf, "$LogFile is corrupt:  Restart page "
					"header specifies invalid system page "
					"size.  Cannot handle this yet.\n");
	}
	/* Abort if the version number is not 1.1. */
	if (sle16_to_cpu(rstr->major_ver != 1) ||
			sle16_to_cpu(rstr->minor_ver != 1))
		log_err_exit(buf, "Unknown $LogFile version %i.%i.  Only know "
				"how to handle version 1.1.\n",
				sle16_to_cpu(rstr->major_ver),
				sle16_to_cpu(rstr->minor_ver));
	/* Verify the location and size of the update sequence array. */
	usa_end_ofs = le16_to_cpu(rstr->usa_ofs) +
			le16_to_cpu(rstr->usa_count) * sizeof(u16);
	if (page_size / NTFS_SECTOR_SIZE + 1 != le16_to_cpu(rstr->usa_count))
		log_err_exit(buf, "Restart page header in $LogFile is "
				"corrupt:  Update sequence array size is "
				"wrong.  Cannot handle this yet.\n");
	if (le16_to_cpu(rstr->usa_ofs) < sizeof(RESTART_PAGE_HEADER))
		log_err_exit(buf, "Restart page header in $LogFile is "
				"corrupt:  Update sequence array overlaps "
				"restart page header.  Cannot handle this "
				"yet.\n");
	if (usa_end_ofs > NTFS_SECTOR_SIZE - sizeof(u16))
		log_err_exit(buf, "Restart page header in $LogFile is "
				"corrupt:  Update sequence array overlaps or "
				"is behind first protected sequence number.  "
				"Cannot handle this yet.\n");
	if (usa_end_ofs > le16_to_cpu(rstr->restart_offset))
		log_err_exit(buf, "Restart page header in $LogFile is "
				"corrupt:  Update sequence array overlaps or "
				"is behind restart area.  Cannot handle this "
				"yet.\n");
	/* Finally, verify the offset of the restart area. */
	if (le16_to_cpu(rstr->restart_offset) & 7)
		log_err_exit(buf, "Restart page header in $LogFile is "
				"corrupt:  Restart area offset is not aligned "
				"to 8-byte boundary.  Cannot handle this "
				"yet.\n");
	/*
	 * Second, verify the restart area itself.
	 */
	// TODO: Implement this.
	fprintf(stderr, "Warning:  Sanity checking of restart area not "
			"implemented yet.\n");
	/*
	 * Third and last, verify the array of log client records.
	 */
	// TODO: Implement this.
	fprintf(stderr, "Warning:  Sanity checking of array of log client "
			"records not implemented yet.\n");
rstr_pass_loc:
	if (ntfs_is_chkd_record(rstr->magic))
		log_err_exit(buf, "The %s restart page header in $LogFile has "
				"been modified by chkdsk.  Do not know how to "
				"handle this yet.  Reboot into Windows to fix "
				"this.\n", (u8*)rstr == buf ? "first" :
				"second");
	if (ntfs_mst_post_read_fixup((NTFS_RECORD*)rstr, page_size) ||
			ntfs_is_baad_record(rstr->magic))
		log_err_exit(buf, "$LogFile incomplete multi sector transfer "
				"detected in restart page header.  Cannot "
				"handle this yet.\n");
	if (pass == 1)
		printf("$LogFile version %i.%i.\n",
				sle16_to_cpu(rstr->major_ver),
				sle16_to_cpu(rstr->minor_ver));
	else /* if (pass == 2) */ {
		/*
		 * rstr is now the second restart page so we declare rstr1
		 * as the first restart page as this one has been verified in
		 * the first pass so we can use all its members safely.
		 */
		RESTART_PAGE_HEADER *rstr1 = (RESTART_PAGE_HEADER*)buf;

		/* Exclude the usa from the comparison. */
		ra = (RESTART_AREA*)((u8*)rstr1 +
				le16_to_cpu(rstr1->restart_offset));
		if (!memcmp(rstr1, rstr, le16_to_cpu(rstr1->usa_ofs)) &&
				!memcmp((u8*)rstr1 + le16_to_cpu(
				rstr1->restart_offset), (u8*)rstr +
				le16_to_cpu(rstr->restart_offset),
				le16_to_cpu(ra->restart_area_length))) {
			puts("\nSkipping analysis of second restart page "
					"because it fully matches the first "
					"one.");
			goto skip_rstr_pass;
		}
		/*
		 * The $LogFile versions specified in each of the two restart
		 * page headers must match.
		 */
		if (rstr1->major_ver != rstr->major_ver ||
				rstr1->minor_ver != rstr->minor_ver)
			log_err_exit(buf, "Second restart area specifies "
					"different $LogFile version to first "
					"restart area.  Cannot handle this "
					"yet.\n");
	}
	/* The restart page header is in rstr and it is mst deprotected. */
	printf("\n%s restart page:\n", pass == 1 ? "1st" : "2nd");
	printf("\nRestart page header:\n");
	printf("magic = %s\n", ntfs_is_rstr_record(rstr->magic) ? "RSTR" :
			"CHKD");
	printf("usa_ofs = %u (0x%x)\n", le16_to_cpu(rstr->usa_ofs),
			le16_to_cpu(rstr->usa_ofs));
	printf("usa_count = %u (0x%x)\n", le16_to_cpu(rstr->usa_count),
			le16_to_cpu(rstr->usa_count));
	printf("chkdsk_lsn = %lli (0x%llx)\n",
			(long long)sle64_to_cpu(rstr->chkdsk_lsn),
			(unsigned long long)sle64_to_cpu(rstr->chkdsk_lsn));
	printf("system_page_size = %u (0x%x)\n",
			(unsigned int)le32_to_cpu(rstr->system_page_size),
			(unsigned int)le32_to_cpu(rstr->system_page_size));
	printf("log_page_size = %u (0x%x)\n",
			(unsigned int)le32_to_cpu(rstr->log_page_size),
			(unsigned int)le32_to_cpu(rstr->log_page_size));
	printf("restart_offset = %u (0x%x)\n",
			le16_to_cpu(rstr->restart_offset),
			le16_to_cpu(rstr->restart_offset));
	printf("\nRestart area:\n");
	ra = (RESTART_AREA*)((u8*)rstr + le16_to_cpu(rstr->restart_offset));
	printf("current_lsn = %lli (0x%llx)\n",
			(long long)sle64_to_cpu(ra->current_lsn),
			(unsigned long long)sle64_to_cpu(ra->current_lsn));
	printf("log_clients = %u (0x%x)\n", le16_to_cpu(ra->log_clients),
			le16_to_cpu(ra->log_clients));
	printf("client_free_list = %i (0x%x)\n",
			(s16)le16_to_cpu(ra->client_free_list),
			le16_to_cpu(ra->client_free_list));
	printf("client_in_use_list = %i (0x%x)\n",
			(s16)le16_to_cpu(ra->client_in_use_list),
			le16_to_cpu(ra->client_in_use_list));
	printf("flags = 0x%.4x\n", le16_to_cpu(ra->flags));
	printf("seq_number_bits = %u (0x%x)\n",
			(unsigned int)le32_to_cpu(ra->seq_number_bits),
			(unsigned int)le32_to_cpu(ra->seq_number_bits));
	printf("restart_area_length = %u (0x%x)\n",
			le16_to_cpu(ra->restart_area_length),
			le16_to_cpu(ra->restart_area_length));
	printf("client_array_offset = %u (0x%x)\n",
			le16_to_cpu(ra->client_array_offset),
			le16_to_cpu(ra->client_array_offset));
	printf("file_size = %lli (0x%llx)\n",
			(long long)sle64_to_cpu(ra->file_size),
			(unsigned long long)sle64_to_cpu(ra->file_size));
	printf("last_lsn_data_length = %u (0x%x)\n",
			(unsigned int)le32_to_cpu(ra->last_lsn_data_length),
			(unsigned int)le32_to_cpu(ra->last_lsn_data_length));
	printf("record_length = %u (0x%x)\n", le16_to_cpu(ra->record_length),
			le16_to_cpu(ra->record_length));
	printf("log_page_data_offset = %u (0x%x)\n",
			le16_to_cpu(ra->log_page_data_offset),
			le16_to_cpu(ra->log_page_data_offset));
	printf("unknown = %u (0x%x)\n", le16_to_cpu(ra->unknown),
			le16_to_cpu(ra->unknown));
	lcr = (LOG_CLIENT_RECORD*)((u8*)ra +
			le16_to_cpu(ra->client_array_offset));
	for (client = 0; client < le16_to_cpu(ra->log_clients); client++) {
		char *client_name;

		printf("\nLog client record number %i:\n", client + 1);
		printf("oldest_lsn = %lli (0x%llx)\n",
				(long long)sle64_to_cpu(lcr->oldest_lsn),
				(unsigned long long)
				sle64_to_cpu(lcr->oldest_lsn));
		printf("client_restart_lsn = %lli (0x%llx)\n", (long long)
				sle64_to_cpu(lcr->client_restart_lsn),
				(unsigned long long)
				sle64_to_cpu(lcr->client_restart_lsn));
		printf("prev_client = %i (0x%x)\n",
				(s16)le16_to_cpu(lcr->prev_client),
				le16_to_cpu(lcr->prev_client));
		printf("next_client = %i (0x%x)\n",
				(s16)le16_to_cpu(lcr->next_client),
				le16_to_cpu(lcr->next_client));
		printf("seq_number = %u (0x%x)\n", le16_to_cpu(lcr->seq_number),
				le16_to_cpu(lcr->seq_number));
		printf("client_name_length = %u (0x%x)\n",
				(unsigned int)le32_to_cpu(lcr->client_name_length) / 2,
				(unsigned int)le32_to_cpu(lcr->client_name_length) / 2);
		if (le32_to_cpu(lcr->client_name_length)) {
			client_name = NULL;
			if (ntfs_ucstombs(lcr->client_name,
					le32_to_cpu(lcr->client_name_length) /
					2, &client_name, 0) < 0) {
				perror("Failed to convert log client name");
				client_name = strdup("<conversion error>");
			}
		} else
			client_name = strdup("<unnamed>");
		printf("client_name = %s\n", client_name);
		free(client_name);
		/*
		 * Log client records are fixed size so we can simply use the
		 * C increment operator to get to the next one.
		 */
		lcr++;
	}
skip_rstr_pass:
	if (pass == 1) {
		rstr = (RESTART_PAGE_HEADER*)((u8*)rstr + page_size);
		++pass;
		goto rstr_pass_loc;
	}
	printf("\n\nFinished with restart pages.  Beginning with log pages.\n");
	/* Reuse pass for log area. */
	pass = 0;
	rcrd = (RECORD_PAGE_HEADER*)rstr;
rcrd_pass_loc:
	rcrd = (RECORD_PAGE_HEADER*)((u8*)rcrd + page_size);
	if ((u8*)rcrd + page_size > buf + buf_size)
		goto end_of_rcrd_passes;
	printf("\nLog record page number %i", pass);
	if (!ntfs_is_rcrd_record(rcrd->magic) &&
			!ntfs_is_chkd_record(rcrd->magic)) {
		for (i = 0; i < page_size; i++)
			if (((u8*)rcrd)[i] != (u8)-1)
				break;
		if (i < page_size)
			puts(" is corrupt (magic is not RCRD or CHKD).");
		else
			puts(" is empty.");
		pass++;
		goto rcrd_pass_loc;
	} else
		puts(":");
	/* Dump log record page */
	printf("magic = %s\n", ntfs_is_rcrd_record(rcrd->magic) ? "RCRD" :
			"CHKD");
// TODO: I am here... (AIA)
	printf("copy.last_lsn/file_offset = 0x%llx\n", (unsigned long long)
			le64_to_cpu(rcrd->copy.last_lsn));
	printf("flags = 0x%x\n", (unsigned int)le32_to_cpu(rcrd->flags));
	printf("page count = %i\n", le16_to_cpu(rcrd->page_count));
	printf("page position = %i\n", le16_to_cpu(rcrd->page_position));
	printf("header.next_record_offset = 0x%llx\n", (unsigned long long)
			le64_to_cpu(rcrd->header.packed.next_record_offset));
	printf("header.last_end_lsn = 0x%llx\n", (unsigned long long)
			le64_to_cpu(rcrd->header.packed.last_end_lsn));
	/*
	 * Where does the 0x40 come from? Is it just usa_offset +
	 * usa_client * 2 + 7 & ~7 or is it derived from somewhere?
	 */
	lr = (LOG_RECORD*)((u8*)rcrd + 0x40);
	client = 0;
log_record_pass:
	printf("\nLog record %i:\n", client);
	printf("this lsn = 0x%llx\n",
			(unsigned long long)le64_to_cpu(lr->this_lsn));
	printf("client previous lsn = 0x%llx\n", (unsigned long long)
			le64_to_cpu(lr->client_previous_lsn));
	printf("client undo next lsn = 0x%llx\n", (unsigned long long)
			le64_to_cpu(lr->client_undo_next_lsn));
	printf("client data length = 0x%x\n",
			(unsigned int)le32_to_cpu(lr->client_data_length));
	printf("client_id.seq_number = 0x%x\n",
			le16_to_cpu(lr->client_id.seq_number));
	printf("client_id.client_index = 0x%x\n",
			le16_to_cpu(lr->client_id.client_index));
	printf("record type = 0x%x\n",
			(unsigned int)le32_to_cpu(lr->record_type));
	printf("transaction_id = 0x%x\n",
			(unsigned int)le32_to_cpu(lr->transaction_id));
	printf("flags = 0x%x:", lr->flags);
	if (!lr->flags)
		printf(" NONE\n");
	else {
		int _b = 0;

		if (lr->flags & LOG_RECORD_MULTI_PAGE) {
			printf(" LOG_RECORD_MULTI_PAGE");
			_b = 1;
		}
		if (lr->flags & ~LOG_RECORD_MULTI_PAGE) {
			if (_b)
				printf(" |");
			printf(" Unknown flags");
		}
		printf("\n");
	}
	printf("redo_operation = 0x%x\n", le16_to_cpu(lr->redo_operation));
	printf("undo_operation = 0x%x\n", le16_to_cpu(lr->undo_operation));
	printf("redo_offset = 0x%x\n", le16_to_cpu(lr->redo_offset));
	printf("redo_length = 0x%x\n", le16_to_cpu(lr->redo_length));
	printf("undo_offset = 0x%x\n", le16_to_cpu(lr->undo_offset));
	printf("undo_length = 0x%x\n", le16_to_cpu(lr->undo_length));
	printf("target_attribute = 0x%x\n", le16_to_cpu(lr->target_attribute));
	printf("lcns_to_follow = 0x%x\n", le16_to_cpu(lr->lcns_to_follow));
	printf("record_offset = 0x%x\n", le16_to_cpu(lr->record_offset));
	printf("attribute_offset = 0x%x\n", le16_to_cpu(lr->attribute_offset));
	printf("target_vcn = 0x%llx\n",
			(unsigned long long)sle64_to_cpu(lr->target_vcn));
	if (le16_to_cpu(lr->lcns_to_follow) > 0)
		printf("Array of lcns:\n");
	for (i = 0; i < le16_to_cpu(lr->lcns_to_follow); i++)
		printf("lcn_list[%i].lcn = 0x%llx\n", i, (unsigned long long)
				sle64_to_cpu(lr->lcn_list[i].lcn));
	client++;
	lr = (LOG_RECORD*)((u8*)lr + 0x70);
	if (((u8*)lr + 0x70 <= (u8*)rcrd +
			le64_to_cpu(rcrd->header.packed.next_record_offset)))
		goto log_record_pass;
	pass++;
	goto rcrd_pass_loc;
end_of_rcrd_passes:
	free(buf);
	return 0;
}

