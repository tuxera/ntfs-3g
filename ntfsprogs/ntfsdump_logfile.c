/**
 * NtfsDump_LogFile - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2000-2004 Anton Altaparmakov
 *
 * This utility will interpret the contents of the journal ($LogFile) of an
 * NTFS partition and display the results on stdout. Errors will be output to
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "types.h"
#include "attrib.h"
#include "mft.h"
#include "device.h"
#include "logfile.h"
#include "mst.h"

const char *EXEC_NAME = "NtfsDump_LogFile";
const char *EXEC_VERSION = "1.0";

/**
 * main
 */
int main(int argc, char **argv)
{
	MFT_RECORD *m = NULL;
	ATTR_RECORD *a;
	s64 l;
	unsigned char *lfd = NULL;
	ntfs_volume *vol = NULL;
	ntfs_attr_search_ctx *ctx = NULL;
	RESTART_PAGE_HEADER *rph;
	RESTART_AREA *rr;
	RESTART_CLIENT *cr;
	RECORD_PAGE_HEADER *rcrd_ph;
	LOG_RECORD *lr;
	int pass = 1;
	int i, lps, client;
	char zero[4096];

	memset(zero, 0, sizeof(zero));
	printf("\n");
	if (argc != 2) {
		printf("%s v%s - Interpret and display information about the "
		       "journal\n($LogFile) of an NTFS volume.\n\n"
		       /* Generic copyright / disclaimer. */
		       "Copyright (c) 2000, 2001 Anton Altaparmakov.\n\n"
		       "%s is free software, released under the GNU "
		       "General Public License\nand you are welcome to "
		       "redistribute it under certain conditions.\n"
		       "%s comes with ABSOLUTELY NO WARRANTY; for details "
		       "read the GNU\nGeneral Public License to be found "
		       "in the file COPYING in the main Linux-NTFS\n"
		       "distribution directory.\n\n"
		       /* Generic part ends here. */
		       "Syntax: ntfsdump_logfile partition_or_file_name\n"
		       "        e.g. ntfsdump_logfile /dev/hda6\n\n",
		       EXEC_NAME, EXEC_VERSION, EXEC_NAME, EXEC_NAME);
		fprintf(stderr, "Error: incorrect syntax\n");
		exit(1);
	}
	vol = ntfs_mount(argv[1], MS_RDONLY);
	if (!vol) {
		perror("ntfs_mount(MS_RDONLY) failed");
		exit(1);
	}
	/* Check NTFS version is ok for us. */
	printf("\nNTFS volume version is %i.%i.\n", vol->major_ver,
						  vol->minor_ver);
	switch (vol->major_ver) {
		case 1:
			if (vol->minor_ver == 1 || vol->minor_ver == 2)
				break;
			else
				goto version_error;
		case 2:	case 3:
			if (vol->minor_ver == 0)
				break;
			/* Fall through on error. */
		default:
version_error:
		fprintf(stderr, "Error: Unknown NTFS version.\n");
			goto error_exit;
	}
	/* Read in $LogFile. */
	if (ntfs_file_record_read(vol, FILE_LogFile, &m, NULL)) {
		fprintf(stderr, "Error reading mft record for $LogFile.\n");
		goto error_exit;
	}
	if (!(m->flags & MFT_RECORD_IN_USE)) {
		fprintf(stderr, "Error: $LogFile has been deleted. Run chkdsk "
				"to fix this.\n");
		goto error_exit;
	}
	ctx = ntfs_attr_get_search_ctx(NULL, m);
	if (!ctx) {
		perror("Failed to allocate attribute search context");
		goto error_exit;
	}
	/* Find the $DATA attribute of the $LogFile. */
	if (ntfs_attr_lookup(AT_DATA, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx)) {
		fprintf(stderr, "Error: Attribute $DATA was not found in" \
				"$LogFile!\n");
		goto log_file_error;
	}
	a = ctx->attr;
	/* Get length of $LogFile contents. */
	l = ntfs_get_attribute_value_length(a);
	if (!l) {
		puts("$LogFile has zero length, no need to write to disk.");
		goto log_file_error;
	}
	/* Allocate a buffer to hold all of the $LogFile contents. */
	lfd = (unsigned char*)malloc(l);
	if (!lfd) {
		puts("Not enough memory to load $LogFile.");
		goto log_file_error;
	}
	/* Read in the $LogFile into the buffer. */
	if (l != ntfs_get_attribute_value(vol, a, lfd)) {
		puts("Amount of data read does not correspond to expected "
		     "length!");
		free(lfd);
		goto log_file_error;
	}
	/* Check restart area. */
	if (!ntfs_is_rstr_recordp(lfd)) {
		s64 _l;

		for (_l = 0LL; _l < l; _l++)
			if (lfd[_l] != (unsigned char)-1)
				break;
		if (_l < l)
			puts("$LogFile contents are corrupt (magic RSTR "
					"missing)!");
		else
			puts("$LogFile is empty.");
		goto log_file_error;
	}
	/* Do the interpretation and display now. */
	rph = (RESTART_PAGE_HEADER*)lfd;
	lps = le32_to_cpu(rph->log_page_size);
pass_loc:
	if (ntfs_mst_post_read_fixup((NTFS_RECORD*)rph, lps) ||
	    ntfs_is_baad_record(rph->magic)) {
		puts("$LogFile incomplete multi sector transfer detected! "
		     "Cannot handle this yet!");
		goto log_file_error;
	}
	if ((pass == 2) && !memcmp(lfd, rph, lps)) {
		printf("2nd restart area fully matches the 1st one. Skipping "
				"display.\n");
		goto skip_rstr_pass;
	}
	if (le16_to_cpu(rph->major_ver != 1) ||
	    le16_to_cpu(rph->minor_ver != 1)) {
		fprintf(stderr, "$LogFile version %i.%i! Error: Unknown "
				"$LogFile version!\n",
					le16_to_cpu(rph->major_ver),
					le16_to_cpu(rph->minor_ver));
		goto log_file_error;
	}
	rr = (RESTART_AREA*)((char*)rph + le16_to_cpu(rph->restart_offset));
	cr = (RESTART_CLIENT*)((char*)rr +
			le16_to_cpu(rr->client_array_offset));
	/* Dump of the interpreted $LogFile restart area. */
	if (pass == 1)
		printf("\n$LogFile version %i.%i.\n",
				le16_to_cpu(rph->major_ver),
				le16_to_cpu(rph->minor_ver));
	printf("\n%s restart area:\n", pass == 1? "1st": "2nd");
	printf("magic = RSTR\n");
	printf("ChkDskLsn = 0x%llx\n",
			(unsigned long long)sle64_to_cpu(rph->chkdsk_lsn));
	printf("SystemPageSize = %u\n", le32_to_cpu(rph->system_page_size));
	printf("LogPageSize = %u\n", le32_to_cpu(rph->log_page_size));
	printf("RestartOffset = 0x%x\n", le16_to_cpu(rph->restart_offset));
	printf("\n(1st) restart record:\n");
	printf("CurrentLsn = %llx\n",
			(unsigned long long)sle64_to_cpu(rr->current_lsn));
	printf("LogClients = %u\n", le16_to_cpu(rr->log_clients));
	printf("ClientFreeList = %i\n", sle16_to_cpu(rr->client_free_list));
	printf("ClientInUseList = %i\n", sle16_to_cpu(rr->client_in_use_list));
	printf("Flags = 0x%x\n", le16_to_cpu(rr->flags));
	printf("SeqNumberBits = %u (0x%x)\n", le32_to_cpu(rr->seq_number_bits),
			le32_to_cpu(rr->seq_number_bits));
	printf("RestartAreaLength = 0x%x\n",
			le16_to_cpu(rr->restart_area_length));
	printf("ClientArrayOffset = 0x%x\n",
			le16_to_cpu(rr->client_array_offset));
	printf("FileSize = %lld (0x%llx)\n",
			(long long)sle64_to_cpu(rr->file_size),
			(unsigned long long)sle64_to_cpu(rr->file_size));
	if (sle64_to_cpu(rr->file_size) != l)
		puts("$LogFile restart area indicates a log file size"
		     "different from the actual size!");
	printf("LastLsnDataLength = 0x%x\n",
			le32_to_cpu(rr->last_lsn_data_length));
	printf("RecordLength = 0x%x\n", le16_to_cpu(rr->record_length));
	printf("LogPageDataOffset = 0x%x\n",
			le16_to_cpu(rr->log_page_data_offset));
	for (client = 0; client < le16_to_cpu(rr->log_clients); client++) {
		printf("\nRestart client record number %i:\n", client);
		printf("OldestLsn = 0x%llx\n", (unsigned long long)
				sle64_to_cpu(cr->oldest_lsn));
		printf("ClientRestartLsn = 0x%llx\n", (unsigned long long)
				sle64_to_cpu(cr->client_restart_lsn));
		printf("PrevClient = %i\n", sle16_to_cpu(cr->prev_client));
		printf("NextClient = %i\n", sle16_to_cpu(cr->next_client));
		printf("SeqNumber = 0x%llx\n", (unsigned long long)
				le64_to_cpu(cr->seq_number));
		printf("ClientNameLength = 0x%x\n",
				le32_to_cpu(cr->client_name_length));
		if (le32_to_cpu(cr->client_name_length)) {
			// convert to ascii and print out.
			// printf("ClientName = %u\n", le16_to_cpu(cr->client_name));
		}
		/* Size of a restart client record is fixed at 0xa0 bytes. */
		cr = (RESTART_CLIENT*)((char*)cr + 0xa0);
	}
skip_rstr_pass:
	if (pass == 1) {
		rph = (RESTART_PAGE_HEADER*)((char*)rph + lps);
		++pass;
		goto pass_loc;
	}
	rcrd_ph = (RECORD_PAGE_HEADER*)rph;
	/* Reuse pass for log record clienter. */
	pass = 0;
	printf("\nFinished with restart area. Beginning with log area.\n");
rcrd_pass_loc:
	rcrd_ph = (RECORD_PAGE_HEADER*)((char*)rcrd_ph + lps);
	if ((char*)rcrd_ph + lps > (char*)lfd + l)
		goto end_of_rcrd_passes;
	printf("\nLog record page number %i", pass);
	if (!ntfs_is_rcrd_record(rcrd_ph->magic)) {
		for (i = 0; i < lps; i++)
			if (((char*)rcrd_ph)[i] != (char)-1)
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
			le64_to_cpu(rcrd_ph->copy.last_lsn));
	printf("flags = 0x%x\n", le32_to_cpu(rcrd_ph->flags));
	printf("page count = %i\n", le16_to_cpu(rcrd_ph->page_count));
	printf("page position = %i\n", le16_to_cpu(rcrd_ph->page_position));
	printf("header.next_record_offset = 0x%llx\n", (unsigned long long)
			le64_to_cpu(rcrd_ph->header.packed.next_record_offset));
	printf("header.last_end_lsn = 0x%llx\n", (unsigned long long)
			le64_to_cpu(rcrd_ph->header.packed.last_end_lsn));
	/*
	 * Where does the 0x40 come from? Is it just usa_offset +
	 * usa_client * 2 + 7 & ~7 or is it derived from somewhere?
	 */
	lr = (LOG_RECORD*)((char*)rcrd_ph + 0x40);
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
	lr = (LOG_RECORD*)((char*)lr + 0x70);
	if (((char*)lr + 0x70 <= (char*)rcrd_ph +
			le64_to_cpu(rcrd_ph->header.packed.next_record_offset)))
		goto log_record_pass;
	pass++;
	goto rcrd_pass_loc;
end_of_rcrd_passes:
log_file_error:
	printf("\n");
	/* Set return code to 0. */
	i = 0;
final_exit:
	if (lfd)
		free(lfd);
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		free(m);
	if (vol && ntfs_umount(vol, 0))
		ntfs_umount(vol, 1);
	return i;
error_exit:
	i = 1;
	goto final_exit;
}

