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

LTVERSION = 4:0:0

# Need this to enable 64-bit (device) file access functions and parameters.
if DEBUG
AM_CFLAGS = -D_FILE_OFFSET_BITS=64 -Wall -g -DDEBUG
else
AM_CFLAGS = -D_FILE_OFFSET_BITS=64 -Wall
endif

linux_ntfsincludedir = -I$(top_srcdir)/include
lib_LTLIBRARIES = libntfs.la
libntfs_la_LDFLAGS = -version-info $(LTVERSION)
libntfs_la_SOURCES =	\
	attrib.c	\
	bitmap.c	\
	bootsect.c	\
	compat.c	\
	debug.c		\
	dir.c		\
	disk_io.c	\
	inode.c		\
	lcnalloc.c	\
	mft.c		\
	mst.c		\
	runlist.c	\
	unistr.c	\
	volume.c

INCLUDES = $(linux_ntfsincludedir) $(all_includes)

