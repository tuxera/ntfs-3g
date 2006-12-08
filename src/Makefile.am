if REALLYSTATIC
AM_LIBS		= $(top_builddir)/libntfs-3g/.libs/libntfs-3g.a
AM_LFLAGS	= -static
STATIC_LINK     = $(CC) $(AM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@
else
AM_LIBS		= $(top_builddir)/libntfs-3g/libntfs-3g.la
AM_LFLAGS	= $(all_libraries)
LIBTOOL_LINK    = $(LIBTOOL) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@
endif

# Workaround to make REALLYSTATIC work with automake 1.5.
LINK=$(STATIC_LINK) $(LIBTOOL_LINK)

man_MANS		= ntfs-3g.8 

MAINTAINERCLEANFILES	= Makefile.in

linux_ntfsincludedir	= -I$(top_srcdir)/include/ntfs

bin_PROGRAMS		= ntfs-3g

# Set the include path.
AM_CPPFLAGS		= -I$(top_srcdir)/include/ntfs-3g $(all_includes)

ntfs_3g_SOURCES	= ntfs-3g.c utils.c utils.h
ntfs_3g_LDADD	= $(AM_LIBS) $(FUSE_MODULE_LIBS) $(libfuse_libs)
ntfs_3g_LDFLAGS	= $(AM_LFLAGS)
ntfs_3g_CFLAGS	= $(FUSE_MODULE_CFLAGS) -DFUSE_USE_VERSION=26

# Extra targets

strip:	$(bin_PROGRAMS)
	$(STRIP) $^

libs:
	(cd ../libntfs-3g && $(MAKE) libs) || exit 1;

install-exec-hook:
	$(INSTALL) -d $(DESTDIR)/sbin
	$(LN_S) -f $(bindir)/ntfs-3g $(DESTDIR)/sbin/mount.ntfs-3g
	$(LDCONFIG)

install-data-hook:
	$(INSTALL) -d $(DESTDIR)$(man8dir)
	$(LN_S) -f ntfs-3g.8 $(DESTDIR)$(man8dir)/mount.ntfs-3g.8

uninstall-local:
	$(RM) -f $(DESTDIR)/sbin/mount.ntfs-3g
	$(RM) -f $(DESTDIR)$(man8dir)/mount.ntfs-3g.8

