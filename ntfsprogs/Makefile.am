# Later gcc require -fms-extensions to work.
if GCC_NEEDS_MS_EXTENSIONS
GCCflag = -fms-extensions
else
GCCflag =
endif

# Need this to enable 64-bit (device) file access functions and parameters.
if DEBUG
AM_CFLAGS = -D_FILE_OFFSET_BITS=64 -Wall -g -DDEBUG $(GCCflag)
else
AM_CFLAGS = -D_FILE_OFFSET_BITS=64 -Wall $(GCCflag)
endif

if REALLYSTATIC
AM_LIBS		= $(top_srcdir)/libntfs/.libs/libntfs.a
AM_LFLAGS	= -static
STATIC_LINK     = $(CC) $(AM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@
else
AM_LIBS		= $(top_srcdir)/libntfs/libntfs.la
AM_LFLAGS	= $(all_libraries)
LIBTOOL_LINK    = $(LIBTOOL) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@
endif

# Workaround to make REALLYSTATIC work with automake 1.5.
LINK=$(STATIC_LINK) $(LIBTOOL_LINK)

bin_PROGRAMS		= ntfsfix ntfsinfo ntfscluster ntfsls
sbin_PROGRAMS		= mkntfs ntfslabel ntfsundelete ntfsresize ntfsclone
EXTRA_PROGRAMS		= ntfsdump_logfile dumplog ntfswipe ntfstruncate

man_MANS		= mkntfs.8 ntfsfix.8 ntfslabel.8 ntfsinfo.8 \
			  ntfsundelete.8 ntfsresize.8 ntfsprogs.8 ntfsls.8
EXTRA_MANS		=

CLEANFILES		= $(EXTRA_PROGRAMS)

linux_ntfsincludedir	= -I$(top_srcdir)/include

# Set the include path.
INCLUDES		= -I$(top_srcdir)/include $(all_includes)

ntfsfix_SOURCES		= ntfsfix.c
ntfsfix_LDADD		= $(AM_LIBS)
ntfsfix_LDFLAGS		= $(AM_LFLAGS)

mkntfs_SOURCES		= attrdef.c upcase.c boot.c sd.c mkntfs.c utils.c utils.h
mkntfs_LDADD		= $(AM_LIBS)
mkntfs_LDFLAGS		= $(AM_LFLAGS)

ntfslabel_SOURCES	= ntfslabel.c utils.c utils.h
ntfslabel_LDADD		= $(AM_LIBS)
ntfslabel_LDFLAGS	= $(AM_LFLAGS)

ntfsinfo_SOURCES	= ntfsinfo.c utils.c utils.h
ntfsinfo_LDADD		= $(AM_LIBS)
ntfsinfo_LDFLAGS	= $(AM_LFLAGS)

ntfsundelete_SOURCES	= ntfsundelete.c ntfsundelete.h utils.c utils.h
ntfsundelete_LDADD	= $(AM_LIBS)
ntfsundelete_LDFLAGS	= $(AM_LFLAGS)

ntfsresize_SOURCES	= ntfsresize.c utils.c utils.h
ntfsresize_LDADD	= $(AM_LIBS)
ntfsresize_LDFLAGS	= $(AM_LFLAGS)

ntfsclone_SOURCES	= ntfsclone.c utils.c utils.h
ntfsclone_LDADD		= $(AM_LIBS)
ntfsclone_LDFLAGS	= $(AM_LFLAGS)

ntfscluster_SOURCES	= ntfscluster.c ntfscluster.h utils.c utils.h
ntfscluster_LDADD	= $(AM_LIBS)
ntfscluster_LDFLAGS	= $(AM_LFLAGS)

ntfsls_SOURCES		= ntfsls.c utils.c utils.h
ntfsls_LDADD		= $(AM_LIBS)
ntfsls_LDFLAGS		= $(AM_LFLAGS)

# We don't distribute these

ntfstruncate_SOURCES	= attrdef.c ntfstruncate.c utils.c utils.h
ntfstruncate_LDADD	= $(AM_LIBS)
ntfstruncate_LDFLAGS	= $(AM_LFLAGS)

ntfswipe_SOURCES	= ntfswipe.c ntfswipe.h utils.c utils.h
ntfswipe_LDADD		= $(AM_LIBS)
ntfswipe_LDFLAGS	= $(AM_LFLAGS)

ntfsdump_logfile_SOURCES= ntfsdump_logfile.c
ntfsdump_logfile_LDADD	= $(AM_LIBS)
ntfsdump_logfile_LDFLAGS= $(AM_LFLAGS)

dumplog_SOURCES		= dumplog.c
dumplog_LDADD		= $(AM_LIBS)
dumplog_LDFLAGS		= $(AM_LFLAGS)

# Extra targets

strip:	$(bin_PROGRAMS) $(sbin_PROGRAMS)
	$(STRIP) $^

