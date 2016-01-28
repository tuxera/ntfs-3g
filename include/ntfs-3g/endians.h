/*
 * endians.h - Definitions related to handling of byte ordering. 
 *             Originated from the Linux-NTFS project.
 *
 * Copyright (c) 2000-2005 Anton Altaparmakov
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
 * along with this program (in the main directory of the NTFS-3G
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _NTFS_ENDIANS_H
#define _NTFS_ENDIANS_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*
 * Notes:
 *	We define the conversion functions including typecasts since the
 * defaults don't necessarily perform appropriate typecasts.
 *	Also, using our own functions means that we can change them if it
 * turns out that we do need to use the unaligned access macros on
 * architectures requiring aligned memory accesses...
 */

#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#ifdef HAVE_MACHINE_ENDIAN_H
#include <machine/endian.h>
#endif
#ifdef HAVE_SYS_BYTEORDER_H
#include <sys/byteorder.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include "types.h"

#ifndef __BYTE_ORDER
#	if defined(_BYTE_ORDER)
#		define __BYTE_ORDER _BYTE_ORDER
#		define __LITTLE_ENDIAN _LITTLE_ENDIAN
#		define __BIG_ENDIAN _BIG_ENDIAN
#	elif defined(BYTE_ORDER)
#		define __BYTE_ORDER BYTE_ORDER
#		define __LITTLE_ENDIAN LITTLE_ENDIAN
#		define __BIG_ENDIAN BIG_ENDIAN
#	elif defined(__BYTE_ORDER__)
#		define __BYTE_ORDER __BYTE_ORDER__
#		define __LITTLE_ENDIAN __LITTLE_ENDIAN__
#		define __BIG_ENDIAN __BIG_ENDIAN__
#	elif (defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)) || \
			defined(WORDS_LITTLEENDIAN)
#		define __BYTE_ORDER 1
#		define __LITTLE_ENDIAN 1
#		define __BIG_ENDIAN 0
#	elif (!defined(_LITTLE_ENDIAN) && defined(_BIG_ENDIAN)) || \
			defined(WORDS_BIGENDIAN)
#		define __BYTE_ORDER 0
#		define __LITTLE_ENDIAN 1
#		define __BIG_ENDIAN 0
#	else
#		error "__BYTE_ORDER is not defined."
#	endif
#endif

#define __ntfs_bswap_constant_16(x)		\
	  (u16)((((u16)(x) & 0xff00) >> 8) |	\
		(((u16)(x) & 0x00ff) << 8))

#define __ntfs_bswap_constant_32(x)			\
	  (u32)((((u32)(x) & 0xff000000u) >> 24) |	\
		(((u32)(x) & 0x00ff0000u) >>  8) |	\
		(((u32)(x) & 0x0000ff00u) <<  8) |	\
		(((u32)(x) & 0x000000ffu) << 24))

#define __ntfs_bswap_constant_64(x)				\
	  (u64)((((u64)(x) & 0xff00000000000000ull) >> 56) |	\
		(((u64)(x) & 0x00ff000000000000ull) >> 40) |	\
		(((u64)(x) & 0x0000ff0000000000ull) >> 24) |	\
		(((u64)(x) & 0x000000ff00000000ull) >>  8) |	\
		(((u64)(x) & 0x00000000ff000000ull) <<  8) |	\
		(((u64)(x) & 0x0000000000ff0000ull) << 24) |	\
		(((u64)(x) & 0x000000000000ff00ull) << 40) |	\
		(((u64)(x) & 0x00000000000000ffull) << 56))

#ifdef HAVE_BYTESWAP_H
#	include <byteswap.h>
#else
#	define bswap_16(x) __ntfs_bswap_constant_16(x)
#	define bswap_32(x) __ntfs_bswap_constant_32(x)
#	define bswap_64(x) __ntfs_bswap_constant_64(x)
#endif

#if defined(__LITTLE_ENDIAN) && (__BYTE_ORDER == __LITTLE_ENDIAN)

#define __le16_to_cpu(x) (x)
#define __le32_to_cpu(x) (x)
#define __le64_to_cpu(x) (x)

#define __cpu_to_le16(x) (x)
#define __cpu_to_le32(x) (x)
#define __cpu_to_le64(x) (x)

#define __constant_le16_to_cpu(x) (x)
#define __constant_le32_to_cpu(x) (x)
#define __constant_le64_to_cpu(x) (x)

#define __constant_cpu_to_le16(x) (x)
#define __constant_cpu_to_le32(x) (x)
#define __constant_cpu_to_le64(x) (x)

#define __be16_to_cpu(x) bswap_16(x)
#define __be32_to_cpu(x) bswap_32(x)
#define __be64_to_cpu(x) bswap_64(x)

#define __cpu_to_be16(x) bswap_16(x)
#define __cpu_to_be32(x) bswap_32(x)
#define __cpu_to_be64(x) bswap_64(x)

#define __constant_be16_to_cpu(x) __ntfs_bswap_constant_16((u16)(x))
#define __constant_be32_to_cpu(x) __ntfs_bswap_constant_32((u32)(x))
#define __constant_be64_to_cpu(x) __ntfs_bswap_constant_64((u64)(x))

#define __constant_cpu_to_be16(x) __ntfs_bswap_constant_16((u16)(x))
#define __constant_cpu_to_be32(x) __ntfs_bswap_constant_32((u32)(x))
#define __constant_cpu_to_be64(x) __ntfs_bswap_constant_64((u64)(x))

#elif defined(__BIG_ENDIAN) && (__BYTE_ORDER == __BIG_ENDIAN)

#define __le16_to_cpu(x) bswap_16(x)
#define __le32_to_cpu(x) bswap_32(x)
#define __le64_to_cpu(x) bswap_64(x)

#define __cpu_to_le16(x) bswap_16(x)
#define __cpu_to_le32(x) bswap_32(x)
#define __cpu_to_le64(x) bswap_64(x)

#define __constant_le16_to_cpu(x) __ntfs_bswap_constant_16((u16)(x))
#define __constant_le32_to_cpu(x) __ntfs_bswap_constant_32((u32)(x))
#define __constant_le64_to_cpu(x) __ntfs_bswap_constant_64((u64)(x))

#define __constant_cpu_to_le16(x) __ntfs_bswap_constant_16((u16)(x))
#define __constant_cpu_to_le32(x) __ntfs_bswap_constant_32((u32)(x))
#define __constant_cpu_to_le64(x) __ntfs_bswap_constant_64((u64)(x))

#define __be16_to_cpu(x) (x)
#define __be32_to_cpu(x) (x)
#define __be64_to_cpu(x) (x)

#define __cpu_to_be16(x) (x)
#define __cpu_to_be32(x) (x)
#define __cpu_to_be64(x) (x)

#define __constant_be16_to_cpu(x) (x)
#define __constant_be32_to_cpu(x) (x)
#define __constant_be64_to_cpu(x) (x)

#define __constant_cpu_to_be16(x) (x)
#define __constant_cpu_to_be32(x) (x)
#define __constant_cpu_to_be64(x) (x)

#else

#error "You must define __BYTE_ORDER to be __LITTLE_ENDIAN or __BIG_ENDIAN."

#endif

#if !ENABLE_STRICT_ENDIANNESS_CHECKING

/* Unsigned from LE to CPU conversion. */

#define le16_to_cpu(x)		(u16)__le16_to_cpu((u16)(x))
#define le32_to_cpu(x)		(u32)__le32_to_cpu((u32)(x))
#define le64_to_cpu(x)		(u64)__le64_to_cpu((u64)(x))

#define le16_to_cpup(x)		(u16)__le16_to_cpu(*(const u16*)(x))
#define le32_to_cpup(x)		(u32)__le32_to_cpu(*(const u32*)(x))
#define le64_to_cpup(x)		(u64)__le64_to_cpu(*(const u64*)(x))

/* Signed from LE to CPU conversion. */

#define sle16_to_cpu(x)		(s16)__le16_to_cpu((s16)(x))
#define sle32_to_cpu(x)		(s32)__le32_to_cpu((s32)(x))
#define sle64_to_cpu(x)		(s64)__le64_to_cpu((s64)(x))

#define sle16_to_cpup(x)	(s16)__le16_to_cpu(*(s16*)(x))
#define sle32_to_cpup(x)	(s32)__le32_to_cpu(*(s32*)(x))
#define sle64_to_cpup(x)	(s64)__le64_to_cpu(*(s64*)(x))

/* Unsigned from CPU to LE conversion. */

#define cpu_to_le16(x)		(u16)__cpu_to_le16((u16)(x))
#define cpu_to_le32(x)		(u32)__cpu_to_le32((u32)(x))
#define cpu_to_le64(x)		(u64)__cpu_to_le64((u64)(x))

#define cpu_to_le16p(x)		(u16)__cpu_to_le16(*(u16*)(x))
#define cpu_to_le32p(x)		(u32)__cpu_to_le32(*(u32*)(x))
#define cpu_to_le64p(x)		(u64)__cpu_to_le64(*(u64*)(x))

/* Signed from CPU to LE conversion. */

#define cpu_to_sle16(x)		(s16)__cpu_to_le16((s16)(x))
#define cpu_to_sle32(x)		(s32)__cpu_to_le32((s32)(x))
#define cpu_to_sle64(x)		(s64)__cpu_to_le64((s64)(x))

#define cpu_to_sle16p(x)	(s16)__cpu_to_le16(*(s16*)(x))
#define cpu_to_sle32p(x)	(s32)__cpu_to_le32(*(s32*)(x))
#define cpu_to_sle64p(x)	(s64)__cpu_to_le64(*(s64*)(x))

/* Unsigned from BE to CPU conversion. */

#define be16_to_cpu(x)		(u16)__be16_to_cpu((u16)(x))
#define be32_to_cpu(x)		(u32)__be32_to_cpu((u32)(x))
#define be64_to_cpu(x)		(u64)__be64_to_cpu((u64)(x))

#define be16_to_cpup(x)		(u16)__be16_to_cpu(*(const u16*)(x))
#define be32_to_cpup(x)		(u32)__be32_to_cpu(*(const u32*)(x))
#define be64_to_cpup(x)		(u64)__be64_to_cpu(*(const u64*)(x))

/* Signed from BE to CPU conversion. */

#define sbe16_to_cpu(x)		(s16)__be16_to_cpu((s16)(x))
#define sbe32_to_cpu(x)		(s32)__be32_to_cpu((s32)(x))
#define sbe64_to_cpu(x)		(s64)__be64_to_cpu((s64)(x))

#define sbe16_to_cpup(x)	(s16)__be16_to_cpu(*(s16*)(x))
#define sbe32_to_cpup(x)	(s32)__be32_to_cpu(*(s32*)(x))
#define sbe64_to_cpup(x)	(s64)__be64_to_cpu(*(s64*)(x))

/* Unsigned from CPU to BE conversion. */

#define cpu_to_be16(x)		(u16)__cpu_to_be16((u16)(x))
#define cpu_to_be32(x)		(u32)__cpu_to_be32((u32)(x))
#define cpu_to_be64(x)		(u64)__cpu_to_be64((u64)(x))

#define cpu_to_be16p(x)		(u16)__cpu_to_be16(*(u16*)(x))
#define cpu_to_be32p(x)		(u32)__cpu_to_be32(*(u32*)(x))
#define cpu_to_be64p(x)		(u64)__cpu_to_be64(*(u64*)(x))

/* Signed from CPU to BE conversion. */

#define cpu_to_sbe16(x)		(s16)__cpu_to_be16((s16)(x))
#define cpu_to_sbe32(x)		(s32)__cpu_to_be32((s32)(x))
#define cpu_to_sbe64(x)		(s64)__cpu_to_be64((s64)(x))

#define cpu_to_sbe16p(x)	(s16)__cpu_to_be16(*(s16*)(x))
#define cpu_to_sbe32p(x)	(s32)__cpu_to_be32(*(s32*)(x))
#define cpu_to_sbe64p(x)	(s64)__cpu_to_be64(*(s64*)(x))

/* Constant endianness conversion defines. */

#define const_le16_to_cpu(x)	__constant_le16_to_cpu(x)
#define const_le32_to_cpu(x)	__constant_le32_to_cpu(x)
#define const_le64_to_cpu(x)	__constant_le64_to_cpu(x)

#define const_cpu_to_le16(x)	__constant_cpu_to_le16(x)
#define const_cpu_to_le32(x)	__constant_cpu_to_le32(x)
#define const_cpu_to_le64(x)	__constant_cpu_to_le64(x)

#define const_sle16_to_cpu(x)	__constant_le16_to_cpu((le16) x)
#define const_sle32_to_cpu(x)	__constant_le32_to_cpu((le32) x)
#define const_sle64_to_cpu(x)	__constant_le64_to_cpu((le64) x)

#define const_cpu_to_sle16(x)	__constant_cpu_to_le16((u16) x)
#define const_cpu_to_sle32(x)	__constant_cpu_to_le32((u32) x)
#define const_cpu_to_sle64(x)	__constant_cpu_to_le64((u64) x)

#define const_be16_to_cpu(x)	__constant_be16_to_cpu(x)
#define const_be32_to_cpu(x)	__constant_be32_to_cpu(x)
#define const_be64_to_cpu(x)	__constant_be64_to_cpu(x)

#define const_cpu_to_be16(x)	__constant_cpu_to_be16(x)
#define const_cpu_to_be32(x)	__constant_cpu_to_be32(x)
#define const_cpu_to_be64(x)	__constant_cpu_to_be64(x)

#define const_sbe16_to_cpu(x)	__constant_be16_to_cpu((be16) x)
#define const_sbe32_to_cpu(x)	__constant_be32_to_cpu((be32) x)
#define const_sbe64_to_cpu(x)	__constant_be64_to_cpu((be64) x)

#define const_cpu_to_sbe16(x)	__constant_cpu_to_be16((u16) x)
#define const_cpu_to_sbe32(x)	__constant_cpu_to_be32((u32) x)
#define const_cpu_to_sbe64(x)	__constant_cpu_to_be64((u64) x)

#define le16_eq(a, b) ((a) == (b))

#define le32_eq(a, b) ((a) == (b))

#define le64_eq(a, b) ((a) == (b))

#define sle16_eq(a, b) ((a) == (b))

#define sle64_eq(a, b) ((a) == (b))

#define be16_eq(a, b) ((a) == (b))

#define be32_eq(a, b) ((a) == (b))

#define le16_cmpz(a) (!(a))

#define le32_cmpz(a) (!(a))

#define le64_cmpz(a) (!(a))

#define sle64_cmpz(a) (!(a))

#define be16_cmpz(a) (!(a))

#define le16_andz(a, b) (!((a) & (b)))

#define le32_andz(a, b) (!((a) & (b)))

#define le16_and(a, b) ((a) & (b))

#define le32_and(a, b) ((a) & (b))

#define le64_and(a, b) ((a) & (b))

#define le16_or(a, b) ((a) | (b))

#define le32_or(a, b) ((a) | (b))

#define le64_or(a, b) ((a) | (b))

#define le16_xor(a, b) ((a) ^ (b))

#define le32_xor(a, b) ((a) ^ (b))

#define le64_xor(a, b) ((a) ^ (b))

#define le16_not(a) (~(a))

#define le32_not(a) (~(a))

#define le64_not(a) (~(a))

#else

/* Unsigned from LE to CPU conversion. */

static inline u16 le16_to_cpu(le16 x) { return (u16) __le16_to_cpu(x.value); }
static inline u32 le32_to_cpu(le32 x) { return (u32) __le32_to_cpu(x.value); }
static inline u64 le64_to_cpu(le64 x) { return (u64) __le64_to_cpu(x.value); }

static inline u16 le16_to_cpup(const le16 *x) {
	return (u16) __le16_to_cpu(x->value);
}
static inline u32 le32_to_cpup(const le32 *x) {
	return (u32) __le32_to_cpu(x->value);
}
static inline u64 le64_to_cpup(const le64 *x) {
	return (u64) __le64_to_cpu(x->value);
}

/* Signed from LE to CPU conversion. */

static inline s16 sle16_to_cpu(sle16 x) { return (s16) __le16_to_cpu(x.value); }
static inline s32 sle32_to_cpu(sle32 x) { return (s32) __le32_to_cpu(x.value); }
static inline s64 sle64_to_cpu(sle64 x) { return (s64) __le64_to_cpu(x.value); }

static inline s16 sle16_to_cpup(const sle16 *x) {
	return (s16) __le16_to_cpu(x->value);
}
static inline s32 sle32_to_cpup(const sle32 *x) {
	return (s32) __le32_to_cpu(x->value);
}
static inline s64 sle64_to_cpup(const sle64 *x) {
	return (s64) __le64_to_cpu(x->value);
}

/* Unsigned from CPU to LE conversion. */

static inline le16 cpu_to_le16(u16 x) {
	le16 leval; leval.value = __cpu_to_le16(x); return leval;
}
static inline le32 cpu_to_le32(u32 x) {
	le32 leval; leval.value = __cpu_to_le32(x); return leval;
}
static inline le64 cpu_to_le64(u64 x) {
	le64 leval; leval.value = __cpu_to_le64(x); return leval;
}

static inline le16 cpu_to_le16p(const u16 *x) {
	le16 leval; leval.value = __cpu_to_le16(*x); return leval;
}
static inline le32 cpu_to_le32p(const u32 *x) {
	le32 leval; leval.value = __cpu_to_le32(*x); return leval;
}
static inline le64 cpu_to_le64p(const u64 *x) {
	le64 leval; leval.value = __cpu_to_le64(*x); return leval;
}

/* Signed from CPU to LE conversion. */

static inline sle16 cpu_to_sle16(s16 x) {
	sle16 leval; leval.value = __cpu_to_le16(x); return leval;
}
static inline sle32 cpu_to_sle32(s32 x) {
	sle32 leval; leval.value = __cpu_to_le32(x); return leval;
}
static inline sle64 cpu_to_sle64(s64 x) {
	sle64 leval; leval.value = __cpu_to_le64(x); return leval;
}

static inline sle16 cpu_to_sle16p(const s16 *x) {
	sle16 leval; leval.value = __cpu_to_le16(*x); return leval;
}
static inline sle32 cpu_to_sle32p(const s32 *x) {
	sle32 leval; leval.value = __cpu_to_le32(*x); return leval;
}
static inline sle64 cpu_to_sle64p(const s64 *x) {
	sle64 leval; leval.value = __cpu_to_le64(*x); return leval;
}

/* Unsigned from BE to CPU conversion. */

static inline u16 be16_to_cpu(be16 x) { return (u16) __be16_to_cpu(x.value); }
static inline u32 be32_to_cpu(be32 x) { return (u32) __be32_to_cpu(x.value); }
static inline u64 be64_to_cpu(be64 x) { return (u64) __be64_to_cpu(x.value); }

static inline u16 be16_to_cpup(const be16 *x) {
	return (u16) __be16_to_cpu(x->value);
}
static inline u32 be32_to_cpup(const be32 *x) {
	return (u32) __be32_to_cpu(x->value);
}
static inline u64 be64_to_cpup(const be64 *x) {
	return (u64) __be64_to_cpu(x->value);
}

/* Signed from BE to CPU conversion. */

static inline s16 sbe16_to_cpu(sbe16 x) { return (s16) __be16_to_cpu(x.value); }
static inline s32 sbe32_to_cpu(sbe32 x) { return (s32) __be32_to_cpu(x.value); }
static inline s64 sbe64_to_cpu(sbe64 x) { return (s64) __be64_to_cpu(x.value); }

static inline s16 sbe16_to_cpup(const sbe16 *x) {
	return (s16) __be16_to_cpu(x->value);
}
static inline s32 sbe32_to_cpup(const sbe32 *x) {
	return (s32) __be32_to_cpu(x->value);
}
static inline s64 sbe64_to_cpup(const sbe64 *x) {
	return (s64) __be64_to_cpu(x->value);
}

/* Unsigned from CPU to BE conversion. */

static inline be16 cpu_to_be16(u16 x) {
	be16 beval; beval.value = __cpu_to_be16(x); return beval;
}
static inline be32 cpu_to_be32(u32 x) {
	be32 beval; beval.value = __cpu_to_be32(x); return beval;
}
static inline be64 cpu_to_be64(u64 x) {
	be64 beval; beval.value = __cpu_to_be64(x); return beval;
}

static inline be16 cpu_to_be16p(const u16 *x) {
	be16 beval; beval.value = __cpu_to_be16(*x); return beval;
}
static inline be32 cpu_to_be32p(const u32 *x) {
	be32 beval; beval.value = __cpu_to_be32(*x); return beval;
}
static inline be64 cpu_to_be64p(const u64 *x) {
	be64 beval; beval.value = __cpu_to_be64(*x); return beval;
}

/* Signed from CPU to BE conversion. */

static inline sbe16 cpu_to_sbe16(s16 x) {
	sbe16 beval; beval.value = __cpu_to_be16(x); return beval;
}
static inline sbe32 cpu_to_sbe32(s32 x) {
	sbe32 beval; beval.value = __cpu_to_be32(x); return beval;
}
static inline sbe64 cpu_to_sbe64(s64 x) {
	sbe64 beval; beval.value = __cpu_to_be64(x); return beval;
}

static inline sbe16 cpu_to_sbe16p(const s16 *x) {
	sbe16 beval; beval.value = __cpu_to_be16(*x); return beval;
}
static inline sbe32 cpu_to_sbe32p(const s32 *x) {
	sbe32 beval; beval.value = __cpu_to_be32(*x); return beval;
}
static inline sbe64 cpu_to_sbe64p(const s64 *x) {
	sbe64 beval; beval.value = __cpu_to_be64(*x); return beval;
}

/* Constant endianness conversion defines. */

#define const_le16_to_cpu(x)	__constant_le16_to_cpu((u16)(x.value))
#define const_le32_to_cpu(x)	__constant_le32_to_cpu((u32)(x.value))
#define const_le64_to_cpu(x)	__constant_le64_to_cpu((u64)(x.value))

#define const_cpu_to_le16(x)	((le16)(u16) __constant_cpu_to_le16((u16)(x)))
#define const_cpu_to_le32(x)	((le32) __constant_cpu_to_le32((u32)(x)))
#define const_cpu_to_le64(x)	((le64) __constant_cpu_to_le64((u64)(x)))

#define const_sle16_to_cpu(x)	__constant_le16_to_cpu((u16)(x.value))
#define const_sle32_to_cpu(x)	__constant_le32_to_cpu((u32)(x.value))
#define const_sle64_to_cpu(x)	__constant_le64_to_cpu((u64)(x.value))

#define const_cpu_to_sle16(x)	((sle16)(u16) __constant_cpu_to_le16((u16)(x)))
#define const_cpu_to_sle32(x)	((sle32) __constant_cpu_to_le32((u32)(x)))
#define const_cpu_to_sle64(x)	((sle64) __constant_cpu_to_le64((u64)(x)))

#define const_be16_to_cpu(x)	__constant_be16_to_cpu((u16)(x.value))
#define const_be32_to_cpu(x)	__constant_be32_to_cpu((u32)(x.value))
#define const_be64_to_cpu(x)	__constant_be64_to_cpu((u64)(x.value))

#define const_cpu_to_be16(x)	((be16)(u16) __constant_cpu_to_be16((u16)(x)))
#define const_cpu_to_be32(x)	((be32) __constant_cpu_to_be32((u32)(x)))
#define const_cpu_to_be64(x)	((be64) __constant_cpu_to_be64((u64)(x)))

#define const_sbe16_to_cpu(x)	__constant_be16_to_cpu((u16)(x.value))
#define const_sbe32_to_cpu(x)	__constant_be32_to_cpu((u32)(x.value))
#define const_sbe64_to_cpu(x)	__constant_be64_to_cpu((u64)(x.value))

#define const_cpu_to_sbe16(x)	((sbe16)(u16) __constant_cpu_to_be16((u16)(x)))
#define const_cpu_to_sbe32(x)	((sbe32) __constant_cpu_to_be32((u32)(x)))
#define const_cpu_to_sbe64(x)	((sbe64) __constant_cpu_to_be64((u64)(x)))

static inline int le16_eq(le16 a, le16 b) { return (a.value == b.value); }

static inline int le32_eq(le32 a, le32 b) { return (a.value == b.value); }

static inline int le64_eq(le64 a, le64 b) { return (a.value == b.value); }

static inline int sle16_eq(sle16 a, sle16 b) { return (a.value == b.value); }

static inline int sle64_eq(sle64 a, sle64 b) { return (a.value == b.value); }

static inline int be16_eq(be16 a, be16 b) { return (a.value == b.value); }

static inline int be32_eq(be32 a, be32 b) { return (a.value == b.value); }

static inline int le16_cmpz(le16 a) { return !a.value; }

static inline int le32_cmpz(le32 a) { return !a.value; }

static inline int le64_cmpz(le64 a) { return !a.value; }

static inline int sle64_cmpz(sle64 a) { return !a.value; }

static inline int be16_cmpz(be16 a) { return !a.value; }

static inline int le16_andz(le16 a, le16 b) { return !(a.value & b.value); }

static inline int le32_andz(le32 a, le32 b) { return !(a.value & b.value); }

static inline le16 le16_and(le16 a, le16 b)
{
	return (le16) ((u16) (a.value & b.value));
}

static inline le32 le32_and(le32 a, le32 b)
{
	return (le32) (a.value & b.value);
}

static inline le64 le64_and(le64 a, le64 b)
{
	return (le64) (a.value & b.value);
}

static inline le16 le16_or(le16 a, le16 b)
{
	return (le16) ((u16) (a.value | b.value));
}

static inline le32 le32_or(le32 a, le32 b)
{
	return (le32) (a.value | b.value);
}

static inline le64 le64_or(le64 a, le64 b)
{
	return (le64) (a.value | b.value);
}

static inline le16 le16_xor(le16 a, le16 b)
{
	return (le16) ((u16) (a.value ^ b.value));
}

static inline le32 le32_xor(le32 a, le32 b)
{
	return (le32) (a.value ^ b.value);
}

static inline le64 le64_xor(le64 a, le64 b)
{
	return (le64) (a.value ^ b.value);
}

static inline le16 le16_not(le16 a) { return (le16) ((u16) (~a.value)); }

static inline le32 le32_not(le32 a) { return (le32) (~a.value); }

static inline le64 le64_not(le64 a) { return (le64) (~a.value); }

#endif /* !ENABLE_STRICT_ENDIANNESS_CHECKING ... */

#endif /* defined _NTFS_ENDIANS_H */
