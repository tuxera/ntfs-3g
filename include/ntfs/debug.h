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
#	include <stdio.h>
#endif
#ifdef HAVE_STDARG_H
#	include <stdarg.h>
#endif
#include <errno.h>

#include "types.h"

struct _runlist_element;

/**
 * Sprintf - silencable output to stderr
 * @silent:	if false string is output to stderr
 * @fmt:	printf style format string
 * @...:	optional arguments for the printf style format string
 *
 * If @silent is false, output the string @fmt to stderror.
 *
 * This is basically a replacelment for:
 *
 *	if (!silent)
 *		fprintf(stderr, fmt, ...);
 *
 * It is more convenient to use Sprintf instead of the above code and perhaps
 * more importantly, Sprintf makes it much easier to turn it into a "do
 * nothing" function with an #ifdef, thus removing the whole output completely.
 */
static __inline__ void Sprintf(const BOOL silent, const char *fmt, ...)
{
	int eo;
	va_list ap;

	if (silent)
		return;
	eo = errno;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	errno = eo;
}

#ifdef DEBUG

/* Debug output to stderr.  To get it run ./configure --enable-debug. */

static __inline__ void Dprintf(const char *fmt, ...)
{
	int eo = errno;
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	errno = eo;
}

static __inline__ void Dputs(const char *s)
{
	int eo = errno;
	fprintf(stderr, "%s\n", s);
	errno = eo;
}

static __inline__ void Dperror(const char *s)
{
	int eo = errno;
	perror(s);
	errno = eo;
}

extern void ntfs_debug_runlist_dump(const struct _runlist_element *rl);

#else /* if !DEBUG */

static __inline__ void Dprintf(const char *fmt __attribute__((unused)), ...) {}
static __inline__ void Dputs(const char *s __attribute__((unused))) {}
static __inline__ void Dperror(const char *s __attribute__((unused))) {}
static __inline__ void ntfs_debug_runlist_dump(const struct _runlist_element *rl __attribute__((unused))) {}

#endif /* !DEBUG */

#define NTFS_BUG(msg)							  \
{									  \
	int ___i;							  \
	fprintf(stderr, "libntfs: Bug in %s(): %s\n", __FUNCTION__, msg); \
	Dputs("Forcing segmentation fault!");				  \
	___i = ((int*)NULL)[1];						  \
}

#endif /* defined _NTFS_DEBUG_H */
