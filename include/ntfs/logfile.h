/*
 * logfile.h - Exports for $LogFile handling.  Part of the Linux-NTFS project.
 *
 * Copyright (c) 2000-2004 Anton Altaparmakov
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
#include "endians.h"
#include "layout.h"

/*
 * Log file organization:
 *
 * Two restart areas present in the first two pages (restart pages, one restart
 * area in each page).  When the volume is unmounted they should be identical.
 *
 *	These are followed by log records organized in pages headed by a record
 * header going up to log file size. Not all pages contain log records when a
 * volume is first formatted, but as the volume ages, all records will be used.
 * When the log file fills up, the records at the beginning are purged (by
 * modifying the oldest_lsn to a higher value presumably) and writing begins
 * at the beginning of the file. Effectively, the log file is viewed as a
 * circular entity.
 *
 * NOTE: Windows NT, 2000, and XP all use log file version 1.1 but they accept
 * versions <= 1.x, including 0.-1.  (Yes, that is a minus one in there!)  We
 * probably only want to support 1.1 as this seems to be the current version
 * and we don't know how that differs from the older versions.  The only
 * exception is if the journal is clean as marked by the two restart pages
 * then it doesn't matter whether we are on an earlier version.  We can just
 * reinitialize the logfile and start again with version 1.1.
 */

/*
 * Log file restart page header (begins the restart area).
 */
typedef struct {
/*Ofs*/
/*  0	NTFS_RECORD; -- Unfolded here as gcc doesn't like unnamed structs. */
/*  0*/	NTFS_RECORD_TYPES magic;/* The magic is "RSTR". */
/*  4*/	u16 usa_ofs;		/* See NTFS_RECORD definition in layout.h.
				   When creating, set this to be immediately
				   after this header structure (without any
				   alignment). */
/*  6*/	u16 usa_count;		/* See NTFS_RECORD definition in layout.h. */

/*  8*/	LSN chkdsk_lsn;		/* The last log file sequence number found by
				   chkdsk.  Only used when the magic is changed
				   to "CHKD".  Otherwise this is zero. */
/* 16*/	u32 system_page_size;	/* Byte size of system pages when the log file
				   was created, has to be >= 512 and a power of
				   2.  Use this to calculate the required size
				   of the usa (usa_count) and add it to usa_ofs.
				   Then verify that the result is less than the
				   value of the restart_offset. */
/* 20*/	u32 log_page_size;	/* Byte size of log file records, has to be >=
				   512 and a power of 2.  Usually is 4096 (or
				   is it just set to system_page_size?). */
/* 24*/	u16 restart_offset;	/* Byte offset from the start of this header to
				   the RESTART_AREA.  Value has to be aligned
				   to 8-byte boundary.  When creating, set this
				   to be after the usa. */
/* 26*/	s16 minor_ver;		/* Log file minor version.  Only check if major
				   version is 1. */
/* 28*/	s16 major_ver;		/* Log file major version.  We only support
				   version 1.1. */
/* sizeof() = 30 (0x1e) bytes */
} __attribute__ ((__packed__)) RESTART_PAGE_HEADER;

/*
 * Log file restart area record.  The offset of this record is found by adding
 * the offset of the RESTART_PAGE_HEADER to the restart_offset value found in
 * it.  See notes at restart_offset above.
 */
typedef struct {
/*Ofs*/
/*  0*/	LSN current_lsn;	/* The current LSN inside the log when the
				   restart area was last written.  This happens
				   often but what is the interval?  Is it just
				   fixed time or is it every time a check point
				   is written or somethine else? */
/*  8*/	u16 log_clients;	/* Number of log client records in the array of
				   log client records which follows this
				   restart area.  Must be 1.  */
/* 10*/	u16 client_free_list;	/* The index of the first free log client record
				   in the array of log client records.  0xffff
				   means that there are no free log client
				   records in the array.  If != 0xffff, check
				   that log_clients > client_free_list.  On a
				   clean volume this is != 0xffff, should at
				   present always be 0.  At present on dirty
				   volume this is 0xffff. */
/* 12*/	u16 client_in_use_list;	/* The index of the first in-use log client
				   record in the array of log client records.
				   0xffff means that there are no in-use log
				   client records in the array.  If != 0xffff
				   check that log_clients > client_in_use_list.
				   On a clean volume this is 0xffff.  On a
				   dirty volume this is != 0xffff.  At present
				   on dirty volume this is 0. */
/* 14*/	u16 flags;		/* Flags modifying LFS behaviour.  = 0 */
/* 16*/	u32 seq_number_bits;	/* How many bits to use for the sequence
				   number.  I have seen 0x2c and 0x2d. */
/* 20*/	u16 restart_area_length;/* Length of the restart area.  Following
				   checks required if version matches.
				   Otherwise, skip them.  restart_offset +
				   restart_area_length has to be <=
				   system_page_size.  Also, restart_area_length
				   has to be >= client_array_offset +
				   (log_clients * sizeof(log client record)). */
/* 22*/	u16 client_array_offset;/* Offset from the start of this record to
				   the first log client record if versions are
				   matched.  When creating, set this to be
				   after this restart area structure, aligned
				   to 8-bytes boundary.  If the versions do not
				   match, the offset is otherwise assumed to be
				   (sizeof(RESTART_AREA) + 7) & ~7, i.e.
				   rounded up to first 8-byte boundary.  Either
				   way, client_array_offset has to be aligned
				   to an 8-byte boundary.  Also, restart_offset
				   + client_array_offset has to be <= 510.
				   Finally, client_array_offset + (log_clients
				   * sizeof(log client record)) has to be <=
				   system_page_size. */
/* 24*/	s64 file_size;		/* Byte size of the log file.  If the
				   restart_offset + the offset of the file_size
				   are > 510 then corruption has occured.  This
				   is the very first check when starting with
				   the restart_area as if it fails it means
				   that some of the above values will be
				   corrupted by the multi sector transfer
				   protection!  If the structure is deprotected
				   then these checks are futile of course.
				   Calculate the file_size bits and check that
				   seq_number_bits == 0x43 - file_size bits.
				   = 0x400000 */
/* 32*/	u32 last_lsn_data_length;/* ??? = 0, 0x40 */
/* 36*/	u16 record_length;	/* Byte size of log records.  If the version
				   matches then check that the value of
				   record_length is a multiple of 8, i.e.
				   (record_length + 7) & ~7 == record_length.
				   = 0x30 */
/* 38*/	u16 log_page_data_offset;/* ??? = 0x40 */
/* 40*/	u32 unknown;		/* ??? It seems like it = 0 if clean and it != 0
				   if dirty.  */
/* 44*/	u32 reserved;		/* Reserved/alignment to 8-byte boundary. */
/* sizeof() = 48 (0x30) bytes */
} __attribute__ ((__packed__)) RESTART_AREA;

/*
 * Log client record.  The offset of this record is found by adding the offset
 * of the RESTART_AREA to the client_array_offset value found in it.
 */
typedef struct {
/*Ofs*/
/*  0*/	LSN oldest_lsn;		/* Oldest LSN needed by this client. */
/*  8*/	LSN client_restart_lsn;	/* LSN at which this client needs to restart
				   the volume, i.e. the current position within
				   the log file.  At present, if clean this
				   should = current_lsn in restart area but it
				   probably also = current_lsn when dirty most
				   of the time. */
/* 16*/	u16 prev_client;	/* The offset to the previous log client record
				   in the array of log client records.  0xffff
				   means there is no previous client record,
				   i.e. this is the first one. */
/* 18*/	u16 next_client;	/* The offset to the next log client record in
				   the array of log client records.  0xffff
				   means there are no next client records, i.e.
				   this is the last one. */
/* 20*/	u16 seq_number;		/* ???  It is 1 when clean and 0 when dirty,
				   but don't know if this is always the case. */
/* 22*/	u8 reserved[6];		/* Reserved/alignment. */
/* 28*/	u32 client_name_length; /* Length of client name in bytes.  = 8 */
/* 32*/	uchar_t client_name[64];/* Name of the client in Unicode.  = NTFS */
/* sizeof() = 160 (0xa0) bytes */
} __attribute__ ((__packed__)) LOG_CLIENT_RECORD;

/*
 * Log page record page header. Each log page begins with this header and is
 * followed by several LOG_RECORD structures, starting at offset 0x40 (the
 * size of this structure and the following update sequence array and then
 * aligned to 8 byte boundary, but is this specified anywhere?).
 */
typedef struct {
/*  0	NTFS_RECORD; -- Unfolded here as gcc doesn't like unnamed structs. */
	NTFS_RECORD_TYPES magic;/* Usually the magic is "RCRD". */
	u16 usa_ofs;		/* See NTFS_RECORD definition in layout.h.
				   When creating, set this to be immediately
				   after this header structure (without any
				   alignment). */
	u16 usa_count;		/* See NTFS_RECORD definition in layout.h. */

	union {
		LSN last_lsn;
		s64 file_offset;
	} __attribute__ ((__packed__)) copy;
	u32 flags;
	u16 page_count;
	u16 page_position;
	union {
		struct {
			u16 next_record_offset;
			u8 reserved[6];
			LSN last_end_lsn;
		} __attribute__ ((__packed__)) packed;
	} __attribute__ ((__packed__)) header;
} __attribute__ ((__packed__)) RECORD_PAGE_HEADER;

/*
 * Possible 16-bit flags for log records.  (Or is it log record pages?)
 */
typedef enum {
	LOG_RECORD_MULTI_PAGE = const_cpu_to_le16(0x0001),	/* ??? */
	LOG_RECORD_SIZE_PLACE_HOLDER = 0xffff,
		/* This has nothing to do with the log record. It is only so
		   gcc knows to make the flags 16-bit. */
} __attribute__ ((__packed__)) LOG_RECORD_FLAGS;

/*
 * The log client id structure identifying a log client.
 */
typedef struct {
	u16 seq_number;
	u16 client_index;
} __attribute__ ((__packed__)) LOG_CLIENT_ID;

/*
 * Log record header.  Each log record seems to have a constant size of 0x70
 * bytes.
 */
typedef struct {
	LSN this_lsn;
	LSN client_previous_lsn;
	LSN client_undo_next_lsn;
	u32 client_data_length;
	LOG_CLIENT_ID client_id;
	u32 record_type;
	u32 transaction_id;
	u16 flags;
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
	VCN target_vcn;
/* Now at ofs 0x50. */
	struct {			   /* Only present if lcns_to_follow
					      is not 0. */
		LCN lcn;
	} __attribute__((__packed__)) lcn_list[0];
} __attribute__ ((__packed__)) LOG_RECORD;

#endif /* defined _NTFS_LOGFILE_H */

