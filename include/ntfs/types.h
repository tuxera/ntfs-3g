/*
 * types.h - Misc type definitions not related to on-disk structure. Part of
 *	     the Linux-NTFS project.
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

#ifndef _NTFS_TYPES_H
#define _NTFS_TYPES_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <sys/types.h>

typedef uint8_t  u8;			/* Unsigned types of an exact size */
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  s8;			/* Signed types of an exact size */
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef u16 uchar_t;			/* 2-byte Unicode character type. */
#define UCHAR_T_SIZE_BITS 1

/*
 * Clusters are signed 64-bit values on NTFS volumes. We define two types, LCN
 * and VCN, to allow for type checking and better code readability.
 */
typedef s64 VCN;
typedef s64 LCN;

/*
 * These are just to make the code more readable...
 */
typedef enum {
	FALSE = 0,
	NO = 0,
	ZERO = 0,
	TRUE = 1,
	YES = 1,
	ONE = 1,
} BOOL;

typedef enum {
	CASE_SENSITIVE = 0,
	IGNORE_CASE = 1,
} IGNORE_CASE_BOOL;

#endif /* defined _NTFS_TYPES_H */

