/*
 * debug.h - Debugging output functions. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002-2004 Anton Altaparmakov
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

#ifndef _NTFS_DEBUG_H
#define _NTFS_DEBUG_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

struct _runlist_element;

extern void __Sprintf(const int silent, const char *fmt, ...)
		__attribute__((format(printf, 2, 3)));
#define Sprintf(silent, f, a...)	__Sprintf(silent, f, ##a)

#ifdef DEBUG

/* Debug output to stderr.  To get it run ./configure --enable-debug. */

extern void __ntfs_debug(const char *file, int line, const char *function,
		const char *format, ...) __attribute__((format(printf, 4, 5)));
#define ntfs_debug(f, a...)						\
		__ntfs_debug(__FILE__, __LINE__, __FUNCTION__, f, ##a)

extern void __ntfs_error(const char *function,
		const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#define ntfs_error(sb, f, a...)		__ntfs_error(__FUNCTION__, f, ##a)

extern void __Dprintf(const char *fmt, ...)
		__attribute__((format(printf, 1, 2)));
#define Dprintf(f, a...)	__Dprintf(f, ##a)

extern void __Dputs(const char *s);
#define Dputs(s)		__Dputs(s)

extern void __Dperror(const char *s);
#define Dperror(s)		__Dperror(s)

#else /* if !DEBUG */

#define ntfs_debug(f, a...)		do {} while (0)
#define ntfs_error(f, a...)		do {} while (0)

#define Dprintf(f, a...)	do {} while (0)
#define Dputs(s)		do {} while (0)
#define Dperror(s)		do {} while (0)

#endif /* !DEBUG */

#ifdef NTFS_DISABLE_DEBUG_LOGGING
static __inline__ void ntfs_debug_runlist_dump(const struct _runlist_element *rl __attribute__((unused))) {}
#else
extern void ntfs_debug_runlist_dump(const struct _runlist_element *rl);
#endif

#define NTFS_BUG(msg)							  \
{									  \
	int ___i;							  \
	fprintf(stderr, "libntfs: Bug in %s(): %s\n", __FUNCTION__, msg); \
	Dputs("Forcing segmentation fault!");				  \
	___i = ((int*)NULL)[1];						  \
}

#endif /* defined _NTFS_DEBUG_H */
