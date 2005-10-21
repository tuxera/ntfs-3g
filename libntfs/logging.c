/**
 * logging.c - Centralised logging.  Part of the Linux-NTFS project.
 *
 * Copyright (c) 2005 Richard Russon
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

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "logging.h"

#ifndef PATH_SEP
#define PATH_SEP '/'
#endif

/**
 * struct ntfs_logging
 * This global struct controls all the logging within the library and tools.
 */
struct ntfs_logging ntfs_log =
{
#ifdef DEBUG
	NTFS_LOG_LEVEL_DEBUG | NTFS_LOG_LEVEL_TRACE |
#endif
	NTFS_LOG_LEVEL_INFO | NTFS_LOG_LEVEL_QUIET | NTFS_LOG_LEVEL_WARNING |
	NTFS_LOG_LEVEL_ERROR | NTFS_LOG_LEVEL_PERROR | NTFS_LOG_LEVEL_CRITICAL |
	NTFS_LOG_LEVEL_REASON,
	NTFS_LOG_FLAG_ONLYNAME,
	ntfs_logging_handler_printf
};

/**
 * ntfs_logging_get_levels - Get a list of the current logging levels
 *
 * Find out which logging levels are enabled.
 *
 * Returns:  Log levels in a 32-bit field
 */
u32 ntfs_logging_get_levels(void)
{
	return ntfs_log.levels;
}

/**
 * ntfs_logging_set_levels - Enable extra logging levels
 * @levels:	32-bit field of log levels to set
 *
 * Enable one or more logging levels.
 * The logging levels are named: NTFS_LOG_LEVEL_*.
 *
 * Returns:  Log levels that were enabled before the call
 */
u32 ntfs_logging_set_levels(u32 levels)
{
	u32 old;
	old = ntfs_log.levels;
	ntfs_log.levels |= levels;
	return old;
}

/**
 * ntfs_logging_clear_levels - Disable some logging levels
 * @levels:	32-bit field of log levels to clear
 *
 * Disable one or more logging levels.
 * The logging levels are named: NTFS_LOG_LEVEL_*.
 *
 * Returns:  Log levels that were enabled before the call
 */
u32 ntfs_logging_clear_levels(u32 levels)
{
	u32 old;
	old = ntfs_log.levels;
	ntfs_log.levels &= (~levels);
	return old;
}


/**
 * ntfs_logging_get_flags - Get a list of logging style flags
 *
 * Find out which logging flags are enabled.
 *
 * Returns:  Logging flags in a 32-bit field
 */
u32 ntfs_logging_get_flags(void)
{
	return ntfs_log.flags;
}

/**
 * ntfs_logging_set_flags - Enable extra logging style flags
 * @flags:	32-bit field of logging flags to set
 *
 * Enable one or more logging flags.
 * The log flags are named: NTFS_LOG_LEVEL_*.
 *
 * Returns:  Logging flags that were enabled before the call
 */
u32 ntfs_logging_set_flags(u32 flags)
{
	u32 old;
	old = ntfs_log.flags;
	ntfs_log.flags |= flags;
	return old;
}

/**
 * ntfs_logging_clear_flags - Disable some logging styles
 * @flags:	32-bit field of logging flags to clear
 *
 * Disable one or more logging flags.
 * The log flags are named: NTFS_LOG_LEVEL_*.
 *
 * Returns:  Logging flags that were enabled before the call
 */
u32 ntfs_logging_clear_flags(u32 flags)
{
	u32 old;
	old = ntfs_log.flags;
	ntfs_log.flags &= (~flags);
	return old;
}


/**
 * ntfs_logging_get_stream - Default output streams for logging levels
 * @level:	Log level
 *
 * By default, urgent messages are sent to "stderr".
 * Other messages are sent to "stdout".
 *
 * Returns:  "string"  Prefix to be used
 */
static FILE * ntfs_logging_get_stream(u32 level)
{
	FILE *stream;

	switch (level) {
		case NTFS_LOG_LEVEL_INFO:
		case NTFS_LOG_LEVEL_QUIET:
		case NTFS_LOG_LEVEL_PROGRESS:
		case NTFS_LOG_LEVEL_VERBOSE:
			stream = stdout;
			break;

		case NTFS_LOG_LEVEL_DEBUG:
		case NTFS_LOG_LEVEL_TRACE:
		case NTFS_LOG_LEVEL_WARNING:
		case NTFS_LOG_LEVEL_ERROR:
		case NTFS_LOG_LEVEL_CRITICAL:
		case NTFS_LOG_LEVEL_PERROR:
		default:
			stream = stderr;
			break;
	}

	return stream;
}

/**
 * ntfs_logging_get_prefix - Default prefixes for logging levels
 * @level:	Log level to be prefixed
 *
 * Prefixing the logging output can make it easier to parse.
 *
 * Returns:  "string"  Prefix to be used
 */
static const char * ntfs_logging_get_prefix(u32 level)
{
	const char *prefix;

	switch (level) {
		case NTFS_LOG_LEVEL_DEBUG:
			prefix = "DEBUG: ";
			break;
		case NTFS_LOG_LEVEL_TRACE:
			prefix = "TRACE: ";
			break;
		case NTFS_LOG_LEVEL_QUIET:
			prefix = "QUIET: ";
			break;
		case NTFS_LOG_LEVEL_INFO:
			prefix = "INFO: ";
			break;
		case NTFS_LOG_LEVEL_VERBOSE:
			prefix = "VERBOSE: ";
			break;
		case NTFS_LOG_LEVEL_PROGRESS:
			prefix = "PROGRESS: ";
			break;
		case NTFS_LOG_LEVEL_WARNING:
			prefix = "WARNING: ";
			break;
		case NTFS_LOG_LEVEL_ERROR:
			prefix = "ERROR: ";
			break;
		case NTFS_LOG_LEVEL_PERROR:
			prefix = "ERROR: ";
			break;
		case NTFS_LOG_LEVEL_CRITICAL:
			prefix = "CRITICAL: ";
			break;
		default:
			prefix = "";
			break;
	}

	return prefix;
}


/**
 * ntfs_logging_set_handler - Provide an alternate logging handler
 * @handler:	function to perform the logging
 *
 * This alternate handler will be called for all future logging requests.
 * If no @handler is specified, logging will revert to the default handler.
 *
 * Returns: void
 */
void ntfs_logging_set_handler(ntfs_logging_handler *handler)
{
	if (handler)
		ntfs_log.handler = handler;
	else
		ntfs_log.handler = ntfs_logging_handler_printf;
}

/**
 * ntfs_logging_redirect - Pass on the request to the real handler
 * @function:	Function in which the log line occurred
 * @file:	File in which the log line occurred
 * @line:	Line number on which the log line occurred
 * @level:	Level at which the line is logged
 * @data:	User specified data, possibly specific to a handler
 * @format:	printf-style formatting string
 * @...:	Arguments to be formatted
 *
 * This is just a redirector function.  The arguments are simply passed to the
 * main logging handler (as defined in the global logging struct @ntfs_log).
 *
 * Returns:  -1  Error occurred
 *            0  Message wasn't logged
 *          num  Number of output characters
 */
int ntfs_logging_redirect(const char *function, const char *file,
	int line, u32 level, void *data, const char *format, ...)
{
	int olderr = errno;
	int ret;
	va_list args;

	if (!(ntfs_log.levels & level))		/* Don't log this message */
		return 0;

	va_start(args, format);
	errno = olderr;
	ret = ntfs_log.handler(function, file, line, level, data, format, args);
	va_end(args);

	errno = olderr;
	return ret;
}

/**
 * ntfs_logging_handler_printf - Basic logging handler
 * @function:	Function in which the log line occurred
 * @file:	File in which the log line occurred
 * @line:	Line number on which the log line occurred
 * @level:	Level at which the line is logged
 * @data:	User specified data, possibly specific to a handler
 * @format:	printf-style formatting string
 * @args:	Arguments to be formatted
 *
 * A simple logging handler.  This is where the log line is finally displayed.
 *
 * Note: For this handler, @data is a pointer to a FILE output stream.
 *       If @data is NULL, the function ntfs_logging_get_stream will be called
 *
 * Returns:  -1  Error occurred
 *            0  Message wasn't logged
 *          num  Number of output characters
 */
int ntfs_logging_handler_printf(const char *function, const char *file,
	int line, u32 level, void *data, const char *format, va_list args)
{
	const int reason_size = 128;
	static char *reason = NULL;
	int ret = 0;
	int olderr = errno;
	FILE *stream;

	if (level == NTFS_LOG_LEVEL_REASON) {
		if (!reason)
			reason = malloc (reason_size);
		if (reason) {
			memset (reason, 0, reason_size);
			return vsnprintf (reason, reason_size, format, args);
		} else {
			/* Rather than call ourselves, just drop through */
			level = NTFS_LOG_LEVEL_PERROR;
			format = "Couldn't create reason";
			args = NULL;
			olderr = errno;
		}
	}

	if (data)
		stream = (FILE*) data;
	else
		stream = ntfs_logging_get_stream(level);

	if ((ntfs_log.flags & NTFS_LOG_FLAG_ONLYNAME) &&
	    (strchr(file, PATH_SEP)))		/* Abbreviate the filename */
		file = strrchr(file, PATH_SEP) + 1;

	if (ntfs_log.flags & NTFS_LOG_FLAG_PREFIX)	/* Prefix the output */
		ret += fprintf(stream, "%s", ntfs_logging_get_prefix(level));

	if (ntfs_log.flags & NTFS_LOG_FLAG_FILENAME)	/* Source filename */
		ret += fprintf(stream, "%s ", file);

	if (ntfs_log.flags & NTFS_LOG_FLAG_LINE)	/* Source line number */
		ret += fprintf(stream, "(%d) ", line);

	if ((ntfs_log.flags & NTFS_LOG_FLAG_FUNCTION) && /* Source function */
	    (level & NTFS_LOG_LEVEL_TRACE))
		ret += fprintf(stream, "%s(): ", function);

	ret += vfprintf(stream, format, args);

	if (level & NTFS_LOG_LEVEL_PERROR) {
		if (reason)
			ret += fprintf(stream, " : %s\n", reason);
		else
			ret += fprintf(stream, " : %s\n", strerror(olderr));
	}

	errno = olderr;
	return ret;
}

/**
 * ntfs_logging_handler_colour - Colour-highlighting logging handler
 * @function:	Function in which the log line occurred
 * @file:	File in which the log line occurred
 * @line:	Line number on which the log line occurred
 * @level:	Level at which the line is logged
 * @data:	User specified data, possibly specific to a handler
 * @format:	printf-style formatting string
 * @args:	Arguments to be formatted
 *
 * This is a simple logging filter that prefixes/suffixes some logs.
 *	Warnings:	 yellow
 *	Errors:		 red
 *	Critical errors: red (inverse video)
 *
 * Note: This function calls ntfs_logging_handler_printf to do the main work.
 *
 * Note: For this handler, @data is a pointer to a FILE output stream.
 *       If @data is NULL, the function ntfs_logging_get_stream will be called
 *
 * Returns:  -1  Error occurred
 *            0  Message wasn't logged
 *          num  Number of output characters
 */
int ntfs_logging_handler_colour(const char *function, const char *file,
	int line, u32 level, void *data, const char *format, va_list args)
{
	int ret = 0;
	int olderr = errno;
	const char *prefix = NULL;
	const char *suffix = NULL;
	const char *end = "\e[0m";
	FILE *stream = NULL;

	if (level != NTFS_LOG_LEVEL_REASON) {	/* Reasons get passed through */
		if (data)
			stream = (FILE*) data;
		else
			stream = ntfs_logging_get_stream(level);

		switch (level) {
			case NTFS_LOG_LEVEL_DEBUG:
				prefix = "\e[32m";	/* Green */
				suffix = end;
				break;
			case NTFS_LOG_LEVEL_TRACE:
				prefix = "\e[36m";	/* Cyan */
				suffix = end;
				break;
			case NTFS_LOG_LEVEL_WARNING:
				prefix = "\e[01;33m";	/* Yellow */
				suffix = end;
				break;
			case NTFS_LOG_LEVEL_ERROR:
			case NTFS_LOG_LEVEL_PERROR:
				prefix = "\e[01;31m";	/* Red */
				suffix = end;
				break;
			case NTFS_LOG_LEVEL_CRITICAL:
				prefix = "\e[01;07;31m"; /* Red, inverse */
				suffix = end;
				break;
		}
	}

	if (prefix)
		ret += fprintf(stream, prefix);

	errno = olderr;
	ret += ntfs_logging_handler_printf(function, file, line, level, stream, format, args);

	if (suffix)
		ret += fprintf(stream, suffix);

	errno = olderr;
	return ret;
}


/**
 * ntfs_logging_parse_option - Act upon command line options
 * @option:	Option flag
 *
 * Delegate some of the work of parsing the command line.  All the options begin
 * with "--log-".  Options cause log levels to be enabled in @ntfs_log (the
 * global logging structure).
 *
 * Note: The "colour" option changes the logging handler.
 *
 * Returns:  TRUE  Option understood
 *          FALSE  Invalid log option
 */
BOOL ntfs_logging_parse_option(const char *option)
{
	if (strcmp(option, "--log-debug") == 0) {
		ntfs_logging_set_levels(NTFS_LOG_LEVEL_DEBUG);
		return TRUE;
	} else if (strcmp(option, "--log-verbose") == 0) {
		ntfs_logging_set_levels(NTFS_LOG_LEVEL_VERBOSE);
		return TRUE;
	} else if (strcmp(option, "--log-quiet") == 0) {
		ntfs_logging_set_levels(NTFS_LOG_LEVEL_QUIET);
		return TRUE;
	} else if (strcmp(option, "--log-trace") == 0) {
		ntfs_logging_set_levels(NTFS_LOG_LEVEL_TRACE);
		return TRUE;
	} else if ((strcmp(option, "--log-colour") == 0) ||
		   (strcmp(option, "--log-color") == 0)) {
		ntfs_logging_set_handler(ntfs_logging_handler_colour);
		return TRUE;
	}

	ntfs_log_warning("Unknown logging option '%s'\n", option);
	return FALSE;
}

