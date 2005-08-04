if REALLYSTATIC
AM_LIBS		= $(top_builddir)/libntfs/.libs/libntfs.a
AM_LFLAGS	= -static
STATIC_LINK     = $(CC) $(AM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@
else
AM_LIBS		= $(top_builddir)/libntfs/libntfs.la
AM_LFLAGS	= $(all_libraries)
LIBTOOL_LINK    = $(LIBTOOL) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@
endif

# Workaround to make REALLYSTATIC work with automake 1.5.
LINK=$(STATIC_LINK) $(LIBTOOL_LINK)

bin_PROGRAMS		= ntfsfix ntfsinfo ntfscluster ntfsls ntfscat
sbin_PROGRAMS		= mkntfs ntfslabel ntfsundelete ntfsresize ntfsclone \
			  ntfscp
EXTRA_PROGRAMS		= ntfsdump_logfile ntfswipe ntfstruncate ntfsmove \
			  ntfsrm ntfsmftalloc

man_MANS		= mkntfs.8 ntfsfix.8 ntfslabel.8 ntfsinfo.8 \
			  ntfsundelete.8 ntfsresize.8 ntfsprogs.8 ntfsls.8 \
			  ntfsclone.8 ntfscluster.8 ntfscat.8 ntfscp.8 \
			  ntfsmount.8
EXTRA_MANS		=

CLEANFILES		= $(EXTRA_PROGRAMS)

MAINTAINERCLEANFILES = Makefile.in

linux_ntfsincludedir	= -I$(top_srcdir)/include/ntfs

if ENABLE_FUSE_MODULE
bin_PROGRAMS		+= ntfsmount
endif

if ENABLE_CRYPTO
EXTRA_PROGRAMS		+= ntfsdecrypt
endif

# Set the include path.
AM_CPPFLAGS		= -I$(top_srcdir)/include/ntfs $(all_includes)

ntfsfix_SOURCES		= ntfsfix.c utils.c utils.h
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

ntfscluster_SOURCES	= ntfscluster.c ntfscluster.h cluster.c cluster.h utils.c utils.h
ntfscluster_LDADD	= $(AM_LIBS)
ntfscluster_LDFLAGS	= $(AM_LFLAGS)

ntfsls_SOURCES		= ntfsls.c utils.c utils.h
ntfsls_LDADD		= $(AM_LIBS)
ntfsls_LDFLAGS		= $(AM_LFLAGS)

ntfscat_SOURCES		= ntfscat.c ntfscat.h utils.c utils.h
ntfscat_LDADD		= $(AM_LIBS)
ntfscat_LDFLAGS		= $(AM_LFLAGS)

ntfscp_SOURCES		= ntfscp.c utils.c utils.h
ntfscp_LDADD		= $(AM_LIBS)
ntfscp_LDFLAGS		= $(AM_LFLAGS)

if ENABLE_FUSE_MODULE
ntfsmount_SOURCES	= ntfsmount.c utils.c utils.h
ntfsmount_LDADD		= $(AM_LIBS) $(FUSE_MODULE_LIBS)
ntfsmount_LDFLAGS	= $(AM_LFLAGS)
ntfsmount_CFLAGS	= $(FUSE_MODULE_CFLAGS) -DFUSE_USE_VERSION=22
endif

# We don't distribute these

ntfsrm_SOURCES		= ntfsrm.c ntfsrm.h utils.c utils.h
ntfsrm_LDADD		= $(AM_LIBS)
ntfsrm_LDFLAGS		= $(AM_LFLAGS)

ntfstruncate_SOURCES	= attrdef.c ntfstruncate.c utils.c utils.h
ntfstruncate_LDADD	= $(AM_LIBS)
ntfstruncate_LDFLAGS	= $(AM_LFLAGS)

ntfsmftalloc_SOURCES	= ntfsmftalloc.c utils.c utils.h
ntfsmftalloc_LDADD	= $(AM_LIBS)
ntfsmftalloc_LDFLAGS	= $(AM_LFLAGS)

ntfsmove_SOURCES	= ntfsmove.c ntfsmove.h utils.c utils.h
ntfsmove_LDADD		= $(AM_LIBS)
ntfsmove_LDFLAGS	= $(AM_LFLAGS)

ntfswipe_SOURCES	= ntfswipe.c ntfswipe.h utils.c utils.h
ntfswipe_LDADD		= $(AM_LIBS)
ntfswipe_LDFLAGS	= $(AM_LFLAGS)

ntfsdump_logfile_SOURCES= ntfsdump_logfile.c
ntfsdump_logfile_LDADD	= $(AM_LIBS)
ntfsdump_logfile_LDFLAGS= $(AM_LFLAGS)

if ENABLE_CRYPTO
ntfsdecrypt_SOURCES	= ntfsdecrypt.c decrypt.c decrypt.h utils.c utils.h
ntfsdecrypt_LDADD	= $(AM_LIBS)
ntfsdecrypt_LDFLAGS	= $(AM_LFLAGS) -lgcrypt
endif

# Extra targets

strip:	$(bin_PROGRAMS) $(sbin_PROGRAMS)
	$(STRIP) $^

libs:
	(cd ../libntfs && $(MAKE) libs) || exit 1;

extra:	extras

extras:	libs $(EXTRA_PROGRAMS)
