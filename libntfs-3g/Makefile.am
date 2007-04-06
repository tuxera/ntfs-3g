#
# Before making a release, the LTVERSION string should be modified.
# The string is of the form CURRENT:REVISION:AGE.
#
# CURRENT (C)
#	The most recent interface number that this library implements.
#
# REVISION (R)
#	The implementation number that this library implements.
#
# AGE (A)
#	The difference between the newest and oldest interfaces that this
#	library implements. In other works, the library implements all the
#	interface numbers in the range from number 'CURRENT - AGE' to
#	'CURRENT'.
#
# This means that:
#
#   - If interfaces have been changed or added, but binary compatibility has
#     been preserved, change to C+1:0:A+1
#
#   - If binary compatibility has been broken (eg removed or changed
#     interfaces) change to C+1:0:0
#
#   - If the interface is the same as the previous version, change to C:R+1:A
#

linux_ntfsincludedir = -I$(top_srcdir)/include/ntfs-3g

lib_LTLIBRARIES = libntfs-3g.la
libntfs_3g_la_LDFLAGS = -version-number $(LIBNTFS_3G_VERSION)
libntfs_3g_la_CFLAGS = $(LIBNTFS_3G_CFLAGS) 
libntfs_3g_la_SOURCES =	\
	attrib.c	\
	attrlist.c	\
	bitmap.c	\
	bootsect.c	\
	collate.c	\
	compat.c	\
	compress.c	\
	debug.c		\
	device.c	\
	device_io.c	\
	dir.c		\
	index.c		\
	inode.c		\
	lcnalloc.c	\
	logfile.c	\
	logging.c	\
	mft.c		\
	misc.c		\
	mst.c		\
	runlist.c	\
	security.c	\
	unistr.c	\
	version.c	\
	volume.c

AM_CPPFLAGS = $(linux_ntfsincludedir) $(all_includes)

EXTRA_DIST = unix_io.c

MAINTAINERCLEANFILES = Makefile.in

libs:	$(lib_LTLIBRARIES)
