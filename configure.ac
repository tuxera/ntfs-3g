#
# configure.ac - Source file to generate "./configure" to prepare package for
#		 compilation.
#
# Copyright (c) 2000-2003 Anton Altaparmakov
# Copyright (c) 2003 Jan Kratochvil
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
# along with this program (in the main directory of the Linux-NTFS
# distribution in the file COPYING); if not, write to the Free Software
# Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

AC_PREREQ(2.57)
AC_INIT(ntfsprogs, 1.8.0betaBK, linux-ntfs-dev@lists.sourceforge.net)
AC_CANONICAL_TARGET([])
AC_CONFIG_SRCDIR([config.h.in])
AM_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AM_ENABLE_SHARED
AM_ENABLE_STATIC

# This is required to get past a stupid configure bug when making the rpm.
# Basically it is broken to specify the host as a command line argument to
# configure on its own, i.e. without giving --host=. It is supposed to work
# but doesn't. So this sets host and erases nonopt effectively moving the
# standalone command line option into the --host= form.
if test "x$nonopt" != "xNONE"; then
  host="$nonopt"
  nonopt="NONE"
fi

AC_PREFIX_DEFAULT(/usr/local)
if test "x$prefix" = "xNONE"; then
  prefix=$ac_default_prefix
  ac_configure_args="$ac_configure_args --prefix $prefix"
fi

# Command-line options.
AC_ARG_ENABLE(debug,
	[  --enable-debug          enable debugging], ,
	enable_debug=no
)

AC_ARG_ENABLE(really-static,
	[  --enable-really-static  completely static binaries], ,
	enable_really_static=no
)

AM_CONDITIONAL(DEBUG, test "$enable_debug" = yes)
AM_CONDITIONAL(REALLYSTATIC, test "$enable_really_static" = yes)

# Do not discard 'CFLAGS' as they may have been passed us by rpmbuild(8)
if test "$USE_MAINTAINER_MODE" = "yes";then
	CFLAGS="$CFLAGS -ggdb3 -Wall -Wstrict-prototypes -Wsign-compare" ## FIXME: fix all source: -Wsign-compare
fi

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

AM_PATH_GLIB_2_0(,,[AC_MSG_ERROR([Linux-NTFS Gnome VFS module requires glib-2.0 library.])],[gmodule gobject])
dnl Force glib-2.0 for the whole package
LIBNTFS_GNOMEVFS_CFLAGS="$CFLAGS $GLIB_CFLAGS"
LIBNTFS_GNOMEVFS_LIBS="$LIBS $GLIB_LIBS"

PKG_CHECK_MODULES(GNOME_VFS_MODULE,gnome-vfs-module-2.0)
dnl Force gnome-vfs-module-2.0 for the whole package
LIBNTFS_GNOMEVFS_CFLAGS="$LIBNTFS_GNOMEVFS_CFLAGS $CFLAGS $GNOME_VFS_MODULE_CFLAGS"
LIBNTFS_GNOMEVFS_LIBS="$LIBNTFS_GNOMEVFS_LIBS $LIBS $GNOME_VFS_MODULE_LIBS"

# create a working libtool-script
if test -z "$LIBTOOL"; then
  AC_LANG_PUSH(C)
  AM_PROG_LIBTOOL
  #LIBTOOL="$LIBTOOL --silent"
  AC_LANG_POP
  AC_SUBST(LIBTOOL_DEPS)
  LIBTOOL_SHELL='/bin/sh ./libtool'
else
  LIBTOOL_SHELL=$LIBTOOL
fi

# add --with-extra-includes and --with-extra-libs switch to ./configure
all_libraries="$all_libraries $USER_LDFLAGS"
all_includes="$all_includes $USER_INCLUDES"
AC_SUBST(all_includes)
AC_SUBST(all_libraries)

AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)
AC_SUBST(LIBS)

AC_SUBST(LIBNTFS_GNOMEVFS_CFLAGS)
AC_SUBST(LIBNTFS_GNOMEVFS_LIBS)

AC_SUBST(AUTODIRS)

# Get compiler name
if test ! -z "$CC"; then
	_cc="$CC"
else
	_cc="gcc"
fi

# Check for gcc version being >= 2.96.
AC_MSG_CHECKING(version of $_cc)
cc_version=`./getgccver $_cc`
cc_major=`echo $cc_version | cut -d'.' -f1`
cc_minor=`echo $cc_version | cut -d'.' -f2`
if test -z "$cc_version"; then
	cc_version="v. ?.??"
	cc_major=1
	cc_minor=1
fi
if test $cc_major -lt 2 -o \( $cc_major -eq 2 -a $cc_minor -lt 96 \) ; then
cc_version="$cc_version, bad"
AC_MSG_RESULT($cc_version)
AC_MSG_ERROR(Please upgrade your gcc compiler to gcc-2.96+ or gcc-3+ version!\
 Earlier compiler versions will NOT work as these do not support \
unnamed/annonymous structures and unions which are used heavily in linux-ntfs.)
fi
cc_version="$cc_version, ok"
AC_MSG_RESULT($cc_version)

# Add -fms-extensions for gcc-3.2+.
AM_CONDITIONAL(GCC_NEEDS_MS_EXTENSIONS, test $cc_major -gt 3 -o \( $cc_major -eq 3 -a $cc_minor -ge 2 \))

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h libintl.h limits.h locale.h mntent.h stddef.h \
	stdint.h stdlib.h stdio.h stdarg.h string.h strings.h errno.h time.h \
	sys/ioctl.h sys/mount.h unistd.h utime.h wchar.h getopt.h sys/stat.h \
	sys/types.h asm/byteorder.h linux/major.h linux/fd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_C_LONG_DOUBLE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_STRUCT_ST_BLOCKS
AC_CHECK_MEMBERS([struct stat.st_rdev])

# Checks for library functions.
AC_FUNC_GETMNTENT
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MBRTOWC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_FUNC_STRFTIME
AC_FUNC_UTIME_NULL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([atexit fdatasync hasmntopt memmove memset regcomp setlocale \
	strcasecmp strchr strdup strerror strtol strtoul utime])

# Makefiles to be created by configure.
AC_CONFIG_FILES([
	Makefile
	doc/Makefile
	include/Makefile
	libntfs/Makefile
	libntfs/libntfs.conf
	libntfs/libntfs-gnomevfs.8
	ntfsprogs/Makefile
	ntfsprogs/mkntfs.8
	ntfsprogs/ntfscat.8
	ntfsprogs/ntfsclone.8
	ntfsprogs/ntfscluster.8
	ntfsprogs/ntfsfix.8
	ntfsprogs/ntfsinfo.8
	ntfsprogs/ntfslabel.8
	ntfsprogs/ntfsls.8
	ntfsprogs/ntfsprogs.8
	ntfsprogs/ntfsresize.8
	ntfsprogs/ntfsundelete.8
	ntfsprogs.spec
])
AC_OUTPUT
