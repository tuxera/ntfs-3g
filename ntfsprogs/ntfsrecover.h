/*
 *		Declarations for processing log data
 *
 * Copyright (c) 2000-2005 Anton Altaparmakov
 * Copyright (c) 2014-2015 Jean-Pierre Andre
 */

/*
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

/*
 * TODO
 *	This file partially duplicates logfile.h (with modifications).
 *	The generic declarations are to be moved to logfile.h, thus
 *	implying adapting (at least) libntfs-3g/logfile.c and
 *	ntfsprogs/ntfsdump_logfile.c, and the declarations specific to
 *	ntfsrecover should be kept in this file.
 *	(removing ntfsdump_logfile.c might also be considered).
 */

#define getle16(p,x) le16_to_cpu(*(const le16*)((const char*)(p) + (x)))
#define getle32(p,x) le32_to_cpu(*(const le32*)((const char*)(p) + (x)))
#define getle64(p,x) le64_to_cpu(*(const le64*)((const char*)(p) + (x)))

#define feedle16(p,x) (*(const le16*)((const char*)(p) + (x)))
#define feedle32(p,x) (*(const le32*)((const char*)(p) + (x)))
#define feedle64(p,x) (*(const le64*)((const char*)(p) + (x)))

enum LOG_RECORD_TYPE {
	LOG_STANDARD = 1,
	LOG_CHECKPOINT = 2
} ;

	/* These flags were introduced in Vista in field attribute_flags */
enum ATTRIBUTE_FLAGS {
	ACTS_ON_MFT = 2,
	ACTS_ON_INDX = 8
} ;

enum ACTIONS {
	Noop,					/* 0 */
	CompensationlogRecord,			/* 1 */
	InitializeFileRecordSegment,		/* 2 */
	DeallocateFileRecordSegment,		/* 3 */
	WriteEndofFileRecordSegment,		/* 4 */
	CreateAttribute,			/* 5 */
	DeleteAttribute,			/* 6 */
	UpdateResidentValue,			/* 7 */
	UpdateNonResidentValue,			/* 8 */
	UpdateMappingPairs,			/* 9 */
	DeleteDirtyClusters,			/* 10 */
	SetNewAttributeSizes,			/* 11 */
	AddIndexEntryRoot,			/* 12 */
	DeleteIndexEntryRoot,			/* 13 */
	AddIndexEntryAllocation,		/* 14 */
	DeleteIndexEntryAllocation,		/* 15 */
	WriteEndOfIndexBuffer,			/* 16 */
	SetIndexEntryVcnRoot,			/* 17 */
	SetIndexEntryVcnAllocation,		/* 18 */
	UpdateFileNameRoot,			/* 19 */
	UpdateFileNameAllocation,		/* 20 */
	SetBitsInNonResidentBitMap,		/* 21 */
	ClearBitsInNonResidentBitMap,		/* 22 */
	HotFix,					/* 23 */
	EndTopLevelAction,			/* 24 */
	PrepareTransaction,			/* 25 */
	CommitTransaction,			/* 26 */
	ForgetTransaction,			/* 27 */
	OpenNonResidentAttribute,		/* 28 */
	OpenAttributeTableDump,			/* 29 */
	AttributeNamesDump,			/* 30 */
	DirtyPageTableDump,			/* 31 */
	TransactionTableDump,			/* 32 */
	UpdateRecordDataRoot,			/* 33 */
	UpdateRecordDataAllocation,		/* 34 */
	Win10Action35,				/* 35 */
	Win10Action36,				/* 36 */
	Win10Action37,				/* 37 */
	LastAction				/* 38 */
} ;

	/* Flags for field log_record_flags, their meaning is unclear */
enum RECORD_FLAGS {
	RECORD_UNKNOWN = 1,
	/* The flags below were introduced in Windows 10 */
	RECORD_DELETING = 2,
	RECORD_ADDING = 4
} ;
typedef le16 LOG_RECORD_FLAGS;

#define LOGFILE_NO_CLIENT const_cpu_to_le16(0xffff)
#define RESTART_VOLUME_IS_CLEAN const_cpu_to_le16(0x0002)

/* ntfsdoc p 39 (47), not in layout.h */

typedef struct RESTART_PAGE_HEADER { /* size 32 */
	NTFS_RECORD head;
	leLSN chkdsk_lsn;
	le32 system_page_size;
	le32 log_page_size;
	le16 restart_offset;
	le16 minor_ver;
	le16 major_ver;
	le16 usn;
} __attribute__((__packed__)) RESTART_PAGE_HEADER;

/* ntfsdoc p 40 (48), not in layout.h */

struct RESTART_AREA { /* size 44 */
	leLSN current_lsn;
	le16 log_clients;
	le16 client_free_list;
	le16 client_in_use_list;
	le16 flags;
	le32 seq_number_bits;
	le16 restart_area_length;
	le16 client_array_offset;
	le64 file_size;
	le32 last_lsn_data_length;
	le16 record_length;
	le16 log_page_data_offset;
	le32 restart_log_open_count;
} __attribute__((__packed__)) ;

typedef struct RESTART_CLIENT { /* size 160 */
/*Ofs*/
/*  0*/	leLSN oldest_lsn;	/* Oldest LSN needed by this client.  On create
				   set to 0. */
/*  8*/	leLSN client_restart_lsn;/* LSN at which this client needs to restart
				   the volume, i.e. the current position within
				   the log file.  At present, if clean this
				   should = current_lsn in restart area but it
				   probably also = current_lsn when dirty most
				   of the time.  At create set to 0. */
/* 16*/	le16 prev_client;	/* The offset to the previous log client record
				   in the array of log client records.
				   LOGFILE_NO_CLIENT means there is no previous
				   client record, i.e. this is the first one.
				   This is always LOGFILE_NO_CLIENT. */
/* 18*/	le16 next_client;	/* The offset to the next log client record in
				   the array of log client records.
				   LOGFILE_NO_CLIENT means there are no next
				   client records, i.e. this is the last one.
				   This is always LOGFILE_NO_CLIENT. */
/* 20*/	le16 seq_number;	/* On Win2k and presumably earlier, this is set
				   to zero every time the logfile is restarted
				   and it is incremented when the logfile is
				   closed at dismount time.  Thus it is 0 when
				   dirty and 1 when clean.  On WinXP and
				   presumably later, this is always 0. */
/* 22*/	u8 reserved[6];		/* Reserved/alignment. */
/* 28*/	le32 client_name_length;/* Length of client name in bytes.  Should
				   always be 8. */
/* 32*/	le16 client_name[64];   /* Name of the client in Unicode.  Should
				   always be "NTFS" with the remaining bytes
				   set to 0. */
/* sizeof() = 160 (0xa0) bytes */
} __attribute__((__packed__)) LOG_CLIENT_RECORD;

/* ntfsdoc p 41 (49), not in layout.h */

struct RECORD_PAGE_HEADER { /* size 40 */
	NTFS_RECORD head;       /* the magic is "RCRD" */
	union {
		leLSN last_lsn;
		le32 file_offset;
	} __attribute__((__packed__)) copy;
	le32 flags;
	le16 page_count;
	le16 page_position;
	le16 next_record_offset;
	le16 reserved4[3];
	leLSN last_end_lsn;
} __attribute__((__packed__)) ;

/* ntfsdoc p 42 (50), not in layout.h */

#define LOG_RECORD_HEAD_SZ 0x30 /* size of header of struct LOG_RECORD */

typedef struct LOG_RECORD { /* size 80 */
	leLSN this_lsn;
	leLSN client_previous_lsn;
	leLSN client_undo_next_lsn;
	le32 client_data_length;
	struct {
		le16 seq_number;
		le16 client_index;
	} __attribute__((__packed__)) client_id;
	le32 record_type;
	le32 transaction_id;
	LOG_RECORD_FLAGS log_record_flags;
	le16 reserved1[3];
	le16 redo_operation;
	le16 undo_operation;
	le16 redo_offset;
	le16 redo_length;
	union {
		struct {
			le16 undo_offset;
			le16 undo_length;
			le16 target_attribute;
			le16 lcns_to_follow;
			le16 record_offset;
			le16 attribute_offset;
			le16 cluster_index;
			le16 attribute_flags;
			le32 target_vcn;
			le32 reserved3;
			le64 lcn_list[0];
		} __attribute__((__packed__));
		struct {
			leLSN transaction_lsn;
			leLSN attributes_lsn;
			leLSN names_lsn;
			leLSN dirty_pages_lsn;
			le64 unknown_list[0];
		} __attribute__((__packed__));
	} __attribute__((__packed__));
} __attribute__((__packed__)) LOG_RECORD;

struct BUFFER {
	unsigned int num;
	unsigned int size;
	unsigned int headsz;
	BOOL safe;
	union {
		struct RESTART_PAGE_HEADER restart;
		struct RECORD_PAGE_HEADER record;
		char data[1];
	} block;  /* variable length, keep at the end */
} ;

struct ACTION_RECORD {
	struct ACTION_RECORD *next;
	struct ACTION_RECORD *prev;
	int num;
	unsigned int flags;
	struct LOG_RECORD record; /* variable length, keep at the end */
} ;

enum {		/* Flag values for ACTION_RECORD */
	ACTION_TO_REDO = 1	/* Committed, possibly not synced */
	} ;

struct ATTR {
	u64 inode;
	u64 lsn;
	le32 type;
	u16 key;
	u16 namelen;
	le16 name[1];
} ;

struct BITMAP_ACTION {
	le32 firstbit;
	le32 count;
} ;

/* Danger in arrays : contains le64's though size is not a multiple of 8 */
typedef struct ATTR_OLD {	/* Format up to Win10 (44 bytes) */
	le64 unknown1;
	le64 unknown2;
	le64 inode;
	leLSN lsn;
	le32 unknown3;
	le32 type;
	le32 unknown4;
} __attribute__((__packed__)) ATTR_OLD;

typedef struct ATTR_NEW {	/* Format since Win10 (40 bytes) */
	le64 unknown1;
	le64 unknown2;
	le32 type;
	le32 unknown3;
	le64 inode;
	leLSN lsn;
} __attribute__((__packed__)) ATTR_NEW;

extern u32 clustersz;
extern int clusterbits;
extern u32 blocksz;
extern int blockbits;
extern u16 bytespersect;
extern u64 mftlcn;
extern u32 mftrecsz;
extern int mftrecbits;
extern u32 mftcnt; /* number of entries */
extern BOOL optc;
extern BOOL optn;
extern int opts;
extern int optv;
extern unsigned int redocount;
extern unsigned int undocount;
extern ntfs_inode *log_ni;
extern ntfs_attr *log_na;
extern u64 logfilelcn;
extern u32 logfilesz; /* bytes */
extern u64 redos_met;
extern u64 committed_lsn;
extern u64 synced_lsn;
extern u64 latest_lsn;
extern u64 restart_lsn;

extern struct RESTART_AREA restart;
extern struct RESTART_CLIENT client;

const char *actionname(int op);
const char *mftattrname(ATTR_TYPES attr);
void showname(const char *prefix, const char *name, int cnt);
int fixnamelen(const char *name, int len);
BOOL within_lcn_range(const struct LOG_RECORD *logr);
struct ATTR *getattrentry(unsigned int key, unsigned int lth);
void copy_attribute(struct ATTR *pa, const char *buf, int length);
u32 get_undo_offset(const struct LOG_RECORD *logr);
u32 get_redo_offset(const struct LOG_RECORD *logr);
u32 get_extra_offset(const struct LOG_RECORD *logr);
BOOL exception(int num);

struct STORE;
BOOL ntfs_check_logfile(ntfs_attr *log_na, RESTART_PAGE_HEADER **rp);
extern int play_undos(ntfs_volume *vol, const struct ACTION_RECORD *firstundo);
extern int play_redos(ntfs_volume *vol, const struct ACTION_RECORD *firstredo);
extern void show_redos(void);
extern void freeclusterentry(struct STORE*);
void hexdump(const char *buf, unsigned int lth);
