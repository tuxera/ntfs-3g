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
#include <errno.h>
#include <string.h>

#include "types.h"
#include "endians.h"
#include "volume.h"
#include "inode.h"
#include "attrib.h"
#include "layout.h"
#include "logfile.h"
#include "mst.h"

/**
 * err_exit - error output and terminate
 */
void err_exit(const char *fmt, ...) __attribute__ ((noreturn));
void err_exit(const char *fmt, ...)
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
 * device_err_exit -
 */
void device_err_exit(char *dev_name, ntfs_volume *vol, ntfs_inode *ni,
		ntfs_attr *na, const char *fmt, ...) __attribute__ ((noreturn));
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
 * usage -
 */
void usage(void) __attribute__ ((noreturn));
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
	int buf_size, err, i, lps, client, pass = 1;

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
			err_exit("Failed to mount %s: %s\n", argv[1],
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
					"0x%x): %s\n", le32_to_cpu(AT_DATA),
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
				err_exit("The file %s does not exist.  Did "
						"you specify it correctly?\n",
						argv[2]);
			err_exit("Error getting information about %s: %s\n",
					argv[2], strerror(errno));
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
			err_exit("Failed to allocate buffer for file data: %s",
					strerror(errno));
		fd = open(argv[2], O_RDONLY);
		if (fd == -1) {
			free(buf);
			err_exit("Failed to open file %s: %s\n", argv[2],
					strerror(errno));
		}
		/* Read in the file into the buffer. */
		br = read(fd, buf, buf_size);
		err = errno;
		if (close(fd))
			fprintf(stderr, "Warning: Failed to close file %s: "
					"%s\n", strerror(errno));
		if (br != buf_size) {
			free(buf);
			err_exit("Failed to read data from %s: %s", argv[2],
					br < 0 ? strerror(err) :
					"Partial read.");
		}
	}
	/*
	 * We now have the entirety of the journal ($LogFile/$DATA or argv[2])
	 * in the memory buffer buf and this has a size of buf_size.  Note we
	 * apply a size capping at 64MiB, so if the journal is any bigger we
	 * only have the first 64MiB.  This should not be a problem as I have
	 * never seen such a large $LogFile.  Usually it is only a few MiB in
	 * size.
	 */
// TODO: I am here... (AIA)
	/* Check for presence of restart area signature. */
	if (!ntfs_is_rstr_recordp(buf)) {
		s8 *pos = (s8*)buf;
		s8 *end = pos + buf_size;
		while (pos < end && *pos == -1)
			pos++;
		free(buf);
		if (pos != end)
			err_exit("$LogFile contents are corrupt (magic RSTR "
					"missing)!");
		/* All bytes are -1. */
		puts("$LogFile is not initialized.");
		return 0;
	}
	/* Do the interpretation and display now. */
	rstr = (RESTART_PAGE_HEADER*)buf;
	lps = le32_to_cpu(rstr->log_page_size);
pass_loc:
	if (ntfs_mst_post_read_fixup((NTFS_RECORD*)rstr, lps) ||
	    ntfs_is_baad_record(rstr->magic)) {
		puts("$LogFile incomplete multi sector transfer detected! "
		     "Cannot handle this yet!");
		goto log_file_error;
	}
	if ((pass == 2) && !memcmp(buf, rstr, lps)) {
		printf("2nd restart area fully matches the 1st one. Skipping "
				"display.\n");
		goto skip_rstr_pass;
	}
	if (le16_to_cpu(rstr->major_ver != 1) ||
	    le16_to_cpu(rstr->minor_ver != 1)) {
		fprintf(stderr, "$LogFile version %i.%i! Error: Unknown "
				"$LogFile version!\n",
					le16_to_cpu(rstr->major_ver),
					le16_to_cpu(rstr->minor_ver));
		goto log_file_error;
	}
	ra = (RESTART_AREA*)((u8*)rstr + le16_to_cpu(rstr->restart_offset));
	lcr = (LOG_CLIENT_RECORD*)((u8*)ra +
			le16_to_cpu(ra->client_array_offset));
	/* Dump of the interpreted $LogFile restart area. */
	if (pass == 1)
		printf("\n$LogFile version %i.%i.\n",
				le16_to_cpu(rstr->major_ver),
				le16_to_cpu(rstr->minor_ver));
	printf("\n%s restart area:\n", pass == 1? "1st": "2nd");
	printf("magic = RSTR\n");
	printf("ChkDskLsn = 0x%llx\n",
			(unsigned long long)sle64_to_cpu(rstr->chkdsk_lsn));
	printf("SystemPageSize = %u\n", le32_to_cpu(rstr->system_page_size));
	printf("LogPageSize = %u\n", le32_to_cpu(rstr->log_page_size));
	printf("RestartOffset = 0x%x\n", le16_to_cpu(rstr->restart_offset));
	printf("\n(1st) restart record:\n");
	printf("CurrentLsn = %llx\n",
			(unsigned long long)sle64_to_cpu(ra->current_lsn));
	printf("LogClients = %u\n", le16_to_cpu(ra->log_clients));
	printf("ClientFreeList = %i\n", sle16_to_cpu(ra->client_free_list));
	printf("ClientInUseList = %i\n", sle16_to_cpu(ra->client_in_use_list));
	printf("Flags = 0x%x\n", le16_to_cpu(ra->flags));
	printf("SeqNumberBits = %u (0x%x)\n", le32_to_cpu(ra->seq_number_bits),
			le32_to_cpu(ra->seq_number_bits));
	printf("RestartAreaLength = 0x%x\n",
			le16_to_cpu(ra->restart_area_length));
	printf("ClientArrayOffset = 0x%x\n",
			le16_to_cpu(ra->client_array_offset));
	printf("FileSize = %lld (0x%llx)\n",
			(long long)sle64_to_cpu(ra->file_size),
			(unsigned long long)sle64_to_cpu(ra->file_size));
	if (sle64_to_cpu(ra->file_size) != buf_size)
		puts("$LogFile restart area indicates a log file size"
		     "different from the actual size!");
	printf("LastLsnDataLength = 0x%x\n",
			le32_to_cpu(ra->last_lsn_data_length));
	printf("RecordLength = 0x%x\n", le16_to_cpu(ra->record_length));
	printf("LogPageDataOffset = 0x%x\n",
			le16_to_cpu(ra->log_page_data_offset));
	for (client = 0; client < le16_to_cpu(ra->log_clients); client++) {
		printf("\nRestart client record number %i:\n", client);
		printf("OldestLsn = 0x%llx\n", (unsigned long long)
				sle64_to_cpu(lcr->oldest_lsn));
		printf("ClientRestartLsn = 0x%llx\n", (unsigned long long)
				sle64_to_cpu(lcr->client_restart_lsn));
		printf("PrevClient = %i\n", sle16_to_cpu(lcr->prev_client));
		printf("NextClient = %i\n", sle16_to_cpu(lcr->next_client));
		printf("SeqNumber = 0x%llx\n", (unsigned long long)
				le64_to_cpu(lcr->seq_number));
		printf("ClientNameLength = 0x%x\n",
				le32_to_cpu(lcr->client_name_length));
		if (le32_to_cpu(lcr->client_name_length)) {
			// convert to ascii and print out.
			// printf("ClientName = %u\n", le16_to_cpu(lcr->client_name));
		}
		/* Size of a restart client record is fixed at 0xa0 bytes. */
		lcr = (LOG_CLIENT_RECORD*)((u8*)lcr + 0xa0);
	}
skip_rstr_pass:
	if (pass == 1) {
		rstr = (RESTART_PAGE_HEADER*)((u8*)rstr + lps);
		++pass;
		goto pass_loc;
	}
	rcrd = (RECORD_PAGE_HEADER*)rstr;
	/* Reuse pass for log record clienter. */
	pass = 0;
	printf("\nFinished with restart area. Beginning with log area.\n");
rcrd_pass_loc:
	rcrd = (RECORD_PAGE_HEADER*)((u8*)rcrd + lps);
	if ((u8*)rcrd + lps > buf + buf_size)
		goto end_of_rcrd_passes;
	printf("\nLog record page number %i", pass);
	if (!ntfs_is_rcrd_record(rcrd->magic)) {
		for (i = 0; i < lps; i++)
			if (((u8*)rcrd)[i] != (u8)-1)
				break;
		if (i < lps)
			puts(" is corrupt (magic RCRD is missing).");
		else
			puts(" is empty.");
		pass++;
		goto rcrd_pass_loc;
	} else
		printf(":");
	/* Dump log record page */
	printf("\nmagic = RCRD\n");
	printf("copy.last_lsn/file_offset = 0x%llx\n", (unsigned long long)
			le64_to_cpu(rcrd->copy.last_lsn));
	printf("flags = 0x%x\n", le32_to_cpu(rcrd->flags));
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
			le32_to_cpu(lr->client_data_length));
	printf("client_id.seq_number = 0x%x\n",
			le16_to_cpu(lr->client_id.seq_number));
	printf("client_id.client_index = 0x%x\n",
			le16_to_cpu(lr->client_id.client_index));
	printf("record type = 0x%x\n", le32_to_cpu(lr->record_type));
	printf("transaction_id = 0x%x\n", le32_to_cpu(lr->transaction_id));
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
log_file_error:
	printf("\n");
	free(buf);
	return 0;
}

