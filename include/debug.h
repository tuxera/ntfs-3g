/*
 * $Id$
 *
 * debug.h - Debugging output functions. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002 Anton Altaparmakov.
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

#include "attrib.h"

#ifdef DEBUG

#include "config.h"

#ifdef HAVE_STDIO_H
#	include <stdio.h>
#endif
#ifdef HAVE_STDARG_H
#	include <stdarg.h>
#endif
#include <errno.h>

/* Debug output to stderr. To get it run ./configure --enable-debug. */

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

extern void ntfs_debug_dump_runlist(const runlist_element *rl);

#else

static __inline__ void Dprintf(const char *fmt, ...) {}
static __inline__ void Dputs(const char *s) {}
static __inline__ void Dperror(const char *s) {}
static __inline__ void ntfs_debug_dump_runlist(const runlist_element *rl) {}

#endif

#endif /* defined _NTFS_DEBUG_H */

