
MAINTAINERCLEANFILES = Makefile.in
 
if FUSE_INTERNAL
noinst_LTLIBRARIES = libfuse-lite.la
endif

libfuse_lite_la_CFLAGS=			  \
	$(AM_CFLAGS) 			  \
	-I$(top_srcdir)/include/fuse-lite \
	-DFUSERMOUNT_DIR=\"$(bindir)\"	  \
	-D_REENTRANT 			  \
	-D_FILE_OFFSET_BITS=64

libfuse_lite_la_LIBADD  = $(LIBFUSE_LITE_LIBS)

libfuse_lite_la_SOURCES =	\
	fuse.c 			\
	fuse_i.h 		\
	fuse_kern_chan.c 	\
	fuse_loop.c 		\
	fuse_loop_mt.c 		\
	fuse_lowlevel.c 	\
	fuse_misc.h 		\
	fuse_mt.c 		\
	fuse_opt.c 		\
	fuse_session.c 		\
	fuse_signals.c 		\
	fusermount.c		\
	helper.c 		\
	mount.c 		\
	mount_util.c 		\
	mount_util.h
