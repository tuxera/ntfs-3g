/*
 * logfile.h - Exports for $LogFile handling. Part of the Linux-NTFS project.
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

#ifndef _NTFS_LOGFILE_H
#define _NTFS_LOGFILE_H

#include "types.h"

typedef enum {
	magic_RSTR = const_cpu_to_le32(0x52545352), /* "RSTR", restart area */
	magic_RCRD = const_cpu_to_le32(0x44524352), /* "RCRD", log record */
} LOG_FILE_RECORD_TYPES;

/*
 * Specialised magic comparison macros.
 */
#define ntfs_is_rstr_record(x)		( ntfs_is_magic (x, RSTR) )
#define ntfs_is_rstr_recordp(p)		( ntfs_is_magicp(p, RSTR) )
#define ntfs_is_rcrd_record(x)		( ntfs_is_magic (x, RCRD) )
#define ntfs_is_rcrd_recordp(p)		( ntfs_is_magicp(p, RCRD) )

/*
 * Log file organization:
 *	Two restart areas present in the first two pages (restart pages). When
 * the volume is unmounted they should be identical.
 *	These are followed by log records organized in pages headed by a record
 * header going up to log file size. Not all pages contain log records when a
 * volume is first formatted, but as the volume ages, all records will be used.
 * When the log file fills up, the records at the beginning are purged (by
 * modifying the oldest_lsn to a higher value presumably) and writing begins
 * at the beginning of the file. Effectively, the log file is viewed as a
 * circular entity.
 */

/*
 * Log file restart page header (begins the restart area).
 */
typedef struct {
/*  0	NTFS_RECORD; -- Unfolded here as gcc doesn't like unnamed structs. */
	NTFS_RECORD_TYPES magic;/* The magic is "RSTR". */
	u16 usa_ofs;		/* See NTFS_RECORD definition above. */
	u16 usa_count;		/* See NTFS_RECORD definition above. */

	u64 chkdsk_lsn;		/* The check disk log file sequence number for
				   this restart page. Only used when the
				   magic is changed to "CHKD". = 0 */
	u32 system_page_size;	/* Byte size of system pages, has to be >= 512
				   and a power of 2. Use this to calculate the
				   required size of the usa and add this to the
				   ntfs.usa_offset value. Then verify that the
				   result is less than the value of the
				   restart_offset. = 0x1000 */
	u32 log_page_size;	/* Byte size of log file records, has to be
				   >= 512 and a power of 2. = 0x1000 */
	u16 restart_offset;	/* Byte offset from the start of the record to
				   the restart record. Value has to be aligned
				   to 8-byte boundary. = 0x30 */
	s16 minor_ver;		/* Log file minor version. Only check if major
				   version is 1. (=1 but >=1 is treated the
				   same and <=0 is also ok) */
	u16 major_ver;		/* Log file major version (=1 but =0 is ok) */
} __attribute__ ((__packed__)) RESTART_PAGE_HEADER;

/*
 * Log file restart area record. The offset of this record is found by adding
 * the offset of the RESTART_PAGE_HEADER to the restart_offset value found in
 * it.
 */
typedef struct {
	u64 current_lsn;	/* Log file record. = 0x700000, 0x700808 */
	u16 log_clients;	/* Number of log client records following
				   the restart_area. = 1 */
	s16 client_free_list;	/* How many clients are free(?). If != 0xffff,
				   check that log_clients > client_free_list.
				   = 0xffff */
	s16 client_in_use_list;/* How many clients are in use(?). If != 0xffff
				   check that log_clients > client_in_use_list.
				   = 0 */
	u16 flags;		/* ??? = 0 */
	u32 seq_number_bits;	/* ??? = 0x2c or 0x2d */
	u16 restart_area_length;/* Length of the restart area. Following
				   checks required if version matches.
				   Otherwise, skip them. restart_offset +
				   restart_area_length has to be <=
				   system_page_size. Also, restart_area_length
				   has to be >= client_array_offset +
				   (log_clients * 0xa0). = 0xd0 */
	u16 client_array_offset;/* Offset from the start of this record to
				   the first client record if versions are
				   matched. The offset is otherwise assumed to
				   be (sizeof(RESTART_AREA) + 7) & ~7, i.e.
				   rounded up to first 8-byte boundary. Either
				   way, the offset to the client array has to be
				   aligned to an 8-byte boundary. Also,
				   restart_offset + offset to the client array
				   have to be <= 510. Also, the offset to the
				   client array + (log_clients * 0xa0) have to
				   be <= SystemPageSize. = 0x30 */
	s64 file_size;		/* Byte size of the log file. If the
				   restart_offset + the offset of the file_size
				   are > 510 then corruption has occured. This
				   is the very first check when starting with
				   the restart_area as if it fails it means
				   that some of the above values will be
				   corrupted by the multi sector transfer
				   protection! If the structure is deprotected
				   then these checks are futile of course.
				   Calculate the file_size bits and check that
				   seq_number_bits == 0x43 - file_size bits.
				   = 0x400000 */
	u32 last_lsn_data_length;/* ??? = 0, 0x40 */
	u16 record_length;	/* Byte size of this record. If the version
				   matches then check that the value of
				   record_length is a multiple of 8, i.e.
				   (record_length + 7) & ~7 == record_length.
				   = 0x30 */
	u16 log_page_data_offset;/* ??? = 0x40 */
	/*
	 * There are eight bytes here at offset 0x58, which contain a value,
	 * which we don't know what it means. It looks like it could be a
	 * 64-bit number or a 32-bit plus something else (the second 32-bits
	 * are zero so can't tell). Have to try to zero it and see if Windows
	 * copes with this.
	 */
} __attribute__ ((__packed__)) RESTART_AREA;

/*
 * Log file restart client. The offset of this record is found by adding
 * the offset of the RESTART_AREA to the client_array_offset value found in it.
 */
typedef struct {
	u64 oldest_lsn;		/* Oldest log file sequence number for this
				   client record. */
	u64 client_restart_lsn;	/* Log file sequence number at which to
				    restart the volume, i.e. the current
				    position within the logfile. */
	s16 prev_client;	/* ??? = 0xffff */
	s16 next_client;	/* ??? = 0xffff */
	u64 seq_number;		/* ??? = 1, size uncertain, Regis calls this
				   "volume clear flag" and gives a size of one
				   byte. */
	u32 client_name_length; /* ??? length of client name in bytes. = 8,
				     size uncertain, offset uncertain */
	uchar_t client_name[0];	/* ??? Name of the client in unicode. = NTFS */
	/*
	 * Or it could be the client name is fixed size like in attr def struct
	 * and the 8 means something else. Favouring this is that the
	 * RESTART_CLIENT struct is assumed to be fixed size of 0xa0 bytes,
	 * just like the attr def struct! There might be parallels to be drawn
	 * between the two.
	 */
} __attribute__ ((__packed__)) RESTART_CLIENT;

/*
 * Log page record page header. Each log page begins with this header and is
 * followed by several LOG_RECORD structures, starting at offset 0x40 (the
 * size of this structure and the following update sequence array and then
 * aligned to 8 byte boundary, but is this specified anywhere?).
 */
typedef struct {
/*  0	NTFS_RECORD; -- Unfolded here as gcc doesn't like unnamed structs. */
	NTFS_RECORD_TYPES magic;/* Usually the magic is "RCRD". */
	u16 usa_ofs;		/* See NTFS_RECORD definition above. */
	u16 usa_count;		/* See NTFS_RECORD definition above. */

	union {
		u64 last_lsn;
		u32 file_offset;
	} __attribute__ ((__packed__)) copy;
	u32 flags;
	u16 page_count;
	u16 page_position;
	union {
		struct {
			u64 next_record_offset;
			u64 last_end_lsn;
		} __attribute__ ((__packed__)) packed;
	} __attribute__ ((__packed__)) header;
} __attribute__ ((__packed__)) RECORD_PAGE_HEADER;

/*
 * Possible flags for log records.
 */
typedef enum {
	LOG_RECORD_MULTI_PAGE = const_cpu_to_le16(0x0001),	/* ??? */
	LOG_RECORD_SIZE_PLACE_HOLDER = 0xffff,
		/* This has nothing to do with the log record. It is only so
		   gcc knows to make the flags 16-bit. */
} __attribute__ ((__packed__)) LOG_RECORD_FLAGS;

/*
 * Log record header. Each log record seems to have a constant size of 0x70
 * bytes.
 */
typedef struct {
	u64 this_lsn;
	u64 client_previous_lsn;
	u64 client_undo_next_lsn;
	u32 client_data_length;
	struct {
		u16 seq_number;
		u16 client_index;
	} __attribute__ ((__packed__)) client_id;
	u32 record_type;
	u32 transaction_id;
	LOG_RECORD_FLAGS flags;
	u16 reserved_or_alignment[3];
/* Now are at ofs 0x30 into struct. */
	u16 redo_operation;
	u16 undo_operation;
	u16 redo_offset;
	u16 redo_length;
	u16 undo_offset;
	u16 undo_length;
	u16 target_attribute;
	u16 lcns_to_follow;		   /* Number of lcn_list entries
					      following this entry. */
/* Now at ofs 0x40. */
	u16 record_offset;
	u16 attribute_offset;
	u32 alignment_or_reserved;
	s64 target_vcn;
/* Now at ofs 0x50. */
	struct {			   /* Only present if lcns_to_follow
					      is not 0. */
		s64 lcn;
	} __attribute__((__packed__)) lcn_list[0];
} __attribute__ ((__packed__)) LOG_RECORD;

#endif /* defined _NTFS_LOGFILE_H */

