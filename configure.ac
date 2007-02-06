#
# configure.ac - Source file to generate "./configure" to prepare package for
#		 compilation.
#
# Copyright (c) 2000-2006 Anton Altaparmakov
# Copyright (c) 2003 Jan Kratochvil
# Copyright (c) 2005-2006 Szabolcs Szakacsits
#
# This program/include file is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program/include file is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program (in the main directory of the NTFS-3G
# distribution in the file COPYING); if not, write to the Free Software
# Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

AC_PREREQ(2.59)
AC_INIT([ntfs-3g],[0.20070207-PREVIEW],[ntfs-3g-devel@lists.sf.net])

AC_CANONICAL_HOST([])
AC_CANONICAL_TARGET([])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AM_ENABLE_SHARED
AM_ENABLE_STATIC

AC_PREFIX_DEFAULT(/usr/local)
if test "x$prefix" = "xNONE"; then
	prefix=$ac_default_prefix
	ac_configure_args="$ac_configure_args --prefix $prefix"
fi

# Command-line options.
AC_ARG_ENABLE(debug,
	AS_HELP_STRING(--enable-debug,enable additional debugging code and
		       output), ,
	enable_debug=no
)

AC_ARG_ENABLE(really-static,
	AS_HELP_STRING(--enable-really-static,create static binaries
		       for the utilities), ,
	enable_really_static=no
)
AM_CONDITIONAL(REALLYSTATIC, test "$enable_really_static" = yes)

AC_ARG_ENABLE(warnings,
	AS_HELP_STRING(--enable-warnings,enable additional compiler warnings), ,
	enable_warnings=no
)

# Use GNU extensions if available.
AC_GNU_SOURCE

# Checks for programs.
AC_PROG_CC
AC_PROG_GCC_TRADITIONAL
AC_PROG_INSTALL
AC_PATH_PROG(RM, rm, rm)
AC_PATH_PROG(LDCONFIG, ldconfig, true, [/sbin /usr/sbin $PATH])
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

# Libraries often install their metadata .pc files in directories not searched
# by pkg-config. Let's workaround this. 
export PKG_CONFIG_PATH=${PKG_CONFIG_PATH}:/usr/lib/pkgconfig:/opt/gnome/lib/pkgconfig:/usr/share/pkgconfig:/usr/local/lib/pkgconfig:$prefix/lib/pkgconfig:/opt/gnome/share/pkgconfig:/usr/local/share/pkgconfig

# Enable large file support.
AC_SYS_LARGEFILE

case "$target_os" in
linux*)
	PKG_CHECK_MODULES(FUSE_MODULE, fuse >= 2.6.0, [ compile_fuse_module=true ],
	[
		AC_MSG_ERROR([ntfs-3g requires FUSE >= 2.6.0. Please see http://fuse.sf.net/ or install __all__ FUSE packages (e.g. fuse, fuse-utils, libfuse, libfuse2, libfuse-dev) or remove already installed __older__ FUSE.])
	]);;
freebsd*)
	AC_MSG_ERROR([Please see FreeBSD support at http://www.freshports.org/sysutils/fusefs-ntfs])
	;;
*)
		AC_MSG_ERROR([ntfs-3g can be built only under Linux.])
	;;
esac

# Static linking failed because FUSE 2.6.[01] forgot to include -lrt. 
# However FreeBSD doesn't have one. So, here we go with the code from FUSE. 
libfuse_libs=
LIBS=
AC_SEARCH_LIBS(clock_gettime, [rt])
libfuse_libs="$libfuse_libs $LIBS"
LIBS=
AC_SUBST(libfuse_libs)

# add --with-extra-includes and --with-extra-libs switch to ./configure
all_libraries="$all_libraries $USER_LDFLAGS"
all_includes="$all_includes $USER_INCLUDES"
AC_SUBST(all_includes)
AC_SUBST(all_libraries)

# Add our compiler switches not discarding 'CFLAGS' as they may have been
# passed to us by rpmbuild(8).
# We add -Wall to enable some compiler warnings.
CFLAGS="$CFLAGS -Wall"

# Add lots of extra warnings if --enable-warnings was specified.
if test "$enable_warnings" = "yes"; then
	CFLAGS="$CFLAGS -W -Wall -Waggregate-return -Wbad-function-cast -Wcast-align -Wcast-qual -Wdisabled-optimization -Wdiv-by-zero -Wfloat-equal -Winline -Wmissing-declarations -Wmissing-format-attribute -Wmissing-noreturn -Wmissing-prototypes -Wmultichar -Wnested-externs -Wpointer-arith -Wredundant-decls -Wshadow -Wsign-compare -Wstrict-prototypes -Wundef -Wwrite-strings"
fi

# Add debugging switches if --enable-debug was specified.
if test "$enable_debug" = "yes"; then
	CFLAGS="$CFLAGS -ggdb3 -DDEBUG"
fi

AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)
AC_SUBST(LIBS)

AC_SUBST(LIBNTFS_3G_CFLAGS)

AC_SUBST(AUTODIRS)

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([ctype.h fcntl.h libgen.h libintl.h limits.h locale.h \
	mntent.h stddef.h stdint.h stdlib.h stdio.h stdarg.h string.h \
	strings.h errno.h time.h unistd.h utime.h wchar.h getopt.h features.h \
	endian.h byteswap.h sys/byteorder.h sys/endian.h sys/param.h \
	sys/ioctl.h sys/mount.h sys/stat.h sys/types.h sys/vfs.h \
	sys/statvfs.h sys/sysmacros.h linux/major.h linux/fd.h linux/hdreg.h \
	machine/endian.h gcrypt.h windows.h gnutls/pkcs12.h syslog.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_BIGENDIAN(,
	[AC_DEFINE([WORDS_LITTLEENDIAN], 1,
	[Define to 1 if your processor stores words with the least significant
	byte first (like Intel and VAX, unlike Motorola and SPARC).])]
	,)
AC_C_CONST
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_STRUCT_ST_BLOCKS
AC_CHECK_MEMBERS([struct stat.st_rdev])

# Checks for library functions.
AC_FUNC_GETMNTENT
AC_FUNC_MBRTOWC
AC_FUNC_MEMCMP
AC_FUNC_STAT
AC_FUNC_STRFTIME
AC_FUNC_UTIME_NULL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([atexit basename dup2 fdatasync getopt_long hasmntopt mbsinit \
	memmove memset realpath regcomp setlocale setxattr strcasecmp strchr \
	strdup strerror strnlen strtol strtoul sysconf utime])

# Makefiles to be created by configure.
AC_CONFIG_FILES([
	Makefile
	include/Makefile
	include/ntfs-3g/Makefile
	libntfs-3g/Makefile
	src/Makefile
	src/ntfs-3g.8
])
AC_OUTPUT
