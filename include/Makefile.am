
# Need this to enable 64-bit (device) file access functions and parameters.
if DEBUG
AM_CFLAGS = -D_FILE_OFFSET_BITS=64 -g -DDEBUG
else
AM_CFLAGS = -D_FILE_OFFSET_BITS=64
endif

linux_ntfsincludedir = $(includedir)/ntfs
linux_ntfsinclude_HEADERS = \
	attrib.h		\
	bitmap.h		\
	bootsect.h		\
	compat.h		\
	debug.h			\
	device.h		\
	device_io.h		\
	dir.h			\
	endians.h		\
	gnome-vfs-method.h	\
	gnome-vfs-module.h	\
	inode.h			\
	layout.h		\
	lcnalloc.h		\
	list.h			\
	logfile.h		\
	mft.h			\
	mst.h			\
	runlist.h		\
	support.h		\
	types.h			\
	unistr.h		\
	volume.h

