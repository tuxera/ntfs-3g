# Need this to enable 64-bit (device) file access functions and parameters.
if DEBUG
AM_CFLAGS = -D_FILE_OFFSET_BITS=64 -g -DDEBUG -Wall
else
AM_CFLAGS = -D_FILE_OFFSET_BITS=64
endif

if REALLYSTATIC
AM_LIBS		= $(top_srcdir)/libntfs/.libs/libntfs.a
AM_LFLAGS	= -static
LINK		= $(CC) $(AM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@
else
AM_LIBS		= $(top_srcdir)/libntfs/libntfs.la
AM_LFLAGS	= $(all_libraries)
LINK		= $(LIBTOOL) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@
endif

bin_PROGRAMS		= ntfsfix ntfsinfo
sbin_PROGRAMS		= mkntfs ntfslabel ntfsundelete
EXTRA_PROGRAMS		= ntfsresize ntfsdump_logfile dumplog ntfswipe

man_MANS		= mkntfs.8 ntfsfix.8 ntfslabel.8 ntfsinfo.8 ntfsundelete.8
EXTRA_MANS		=

CLEANFILES		= $(EXTRA_PROGRAMS)

linux_ntfsincludedir	= -I$(top_srcdir)/include

# Set the include path.
INCLUDES		= -I$(top_srcdir)/include $(all_includes)

ntfsfix_SOURCES		= ntfsfix.c
ntfsfix_LDADD		= $(AM_LIBS)
ntfsfix_LDFLAGS		= $(AM_LFLAGS)

mkntfs_SOURCES		= attrdef.c upcase.c boot.c sd.c mkntfs.c
mkntfs_LDADD		= $(AM_LIBS)
mkntfs_LDFLAGS		= $(AM_LFLAGS)

ntfslabel_SOURCES	= ntfslabel.c
ntfslabel_LDADD		= $(AM_LIBS)
ntfslabel_LDFLAGS	= $(AM_LFLAGS)

ntfsinfo_SOURCES	= ntfsinfo.c
ntfsinfo_LDADD		= $(AM_LIBS)
ntfsinfo_LDFLAGS	= $(AM_LFLAGS)

ntfsundelete_SOURCES	= ntfsundelete.c ntfsundelete.h
ntfsundelete_LDADD	= $(AM_LIBS)
ntfsundelete_LDFLAGS	= $(AM_LFLAGS)

# We don't distribute these

ntfswipe_SOURCES	= ntfswipe.c ntfswipe.h
ntfswipe_LDADD		= $(AM_LIBS)
ntfswipe_LDFLAGS	= $(AM_LFLAGS)

ntfsresize_SOURCES	= ntfsresize.c
ntfsresize_LDADD	= $(AM_LIBS)
ntfsresize_LDFLAGS	= $(AM_LFLAGS)

ntfsdump_logfile_SOURCES= ntfsdump_logfile.c
ntfsdump_logfile_LDADD	= $(AM_LIBS)
ntfsdump_logfile_LDFLAGS= $(AM_LFLAGS)

dumplog_SOURCES		= dumplog.c
dumplog_LDADD		= $(AM_LIBS)
dumplog_LDFLAGS		= $(AM_LFLAGS)

# Extra targets

strip:	$(bin_PROGRAMS) $(sbin_PROGRAMS)
	$(STRIP) $^
