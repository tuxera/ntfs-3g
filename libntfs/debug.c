/**
 * debug.c - Debugging output functions. Part of the Linux-NTFS project.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "types.h"
#include "runlist.h"
#include "debug.h"
#include "logging.h"

/**
 * Sprintf - silencable output to stderr
 * @silent:	if 0 string is output to stderr
 * @fmt:	printf style format string
 * @...:	optional arguments for the printf style format string
 *
 * If @silent is 0, output the string @fmt to stderr.
 *
 * This is basically a replacement for:
 *
 *	if (!silent)
 *		fprintf(stderr, fmt, ...);
 *
 * It is more convenient to use Sprintf instead of the above code and perhaps
 * more importantly, Sprintf makes it much easier to turn it into a "do
 * nothing" function, by defining it to "do {} while (0)" in debug.h instead of
 * to * __Sprintf, thus removing the whole output completely.
 */
void __Sprintf(const int silent, const char *fmt, ...)
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

/**
 * __ntfs_error
 */
void __ntfs_error(const char *function, const char *fmt, ...)
{
	int eo = errno;
	int flen = 0;
	va_list args;
	char err_buf[1024];

	if (function)
		flen = strlen(function);
	va_start(args, fmt);
	vsnprintf(err_buf, sizeof(err_buf), fmt, args);
	va_end(args);
	fprintf(stderr, "NTFS error: %s(): %s\n", flen ? function : "",
			err_buf);
	errno = eo;
}

/**
 * __ntfs_debug
 */
void __ntfs_debug(const char *file, int line, const char *function,
		const char *fmt, ...)
{
	int eo = errno;
	int flen = 0;
	va_list args;
	char err_buf[1024];

	if (function)
		flen = strlen(function);
	va_start(args, fmt);
	vsnprintf(err_buf, sizeof(err_buf), fmt, args);
	va_end(args);
	fprintf(stderr, "NTFS DEBUG (%s, %d): %s(): %s\n", file, line,
			flen ? function : "", err_buf);
	errno = eo;
}

/**
 * __Dprintf
 */
void __Dprintf(const char *fmt, ...)
{
	int eo = errno;
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	errno = eo;
}

/**
 * __Dputs
 */
void __Dputs(const char *s)
{
	int eo = errno;
	fprintf(stderr, "%s\n", s);
	errno = eo;
}

/**
 * __Dperror
 */
void __Dperror(const char *s)
{
	int eo = errno;
	perror(s);
	errno = eo;
}

#endif

#ifndef NTFS_DISABLE_DEBUG_LOGGING
/**
 * ntfs_debug_runlist_dump - Dump a runlist.
 */
void ntfs_debug_runlist_dump(const runlist_element *rl)
{
	int i = 0;
	const char *lcn_str[5] = { "LCN_HOLE         ", "LCN_RL_NOT_MAPPED",
				   "LCN_ENOENT       ", "LCN_EINVAL       ",
				   "LCN_unknown      " };

	ntfs_log_debug("NTFS-fs DEBUG: Dumping runlist (values in hex):\n");
	if (!rl) {
		ntfs_log_debug("Run list not present.\n");
		return;
	}
	ntfs_log_debug("VCN              LCN               Run length\n");
	do {
		LCN lcn = (rl + i)->lcn;

		if (lcn < (LCN)0) {
			int idx = -lcn - 1;

			if (idx > -LCN_EINVAL - 1)
				idx = 4;
			ntfs_log_debug("%-16llx %s %-16llx%s\n", rl[i].vcn, lcn_str[idx], rl[i].length, rl[i].length ? "" : " (runlist end)");
		} else
			ntfs_log_debug("%-16llx %-16llx  %-16llx%s\n", rl[i].vcn, rl[i].lcn, rl[i].length, rl[i].length ? "" : " (runlist end)");
	} while (rl[i++].length);
}

#endif

