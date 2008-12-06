
MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

if FUSE_INTERNAL
FUSE_CFLAGS = -I$(top_srcdir)/include/fuse-lite
FUSE_LIBS   =
else
FUSE_CFLAGS = $(FUSE_MODULE_CFLAGS)
FUSE_LIBS   = $(FUSE_MODULE_LIBS)
endif

bin_PROGRAMS	 = ntfs-3g.probe
rootbin_PROGRAMS = ntfs-3g
rootsbin_DATA 	 = #Create directory
man_MANS	 = ntfs-3g.8 ntfs-3g.probe.8

ntfs_3g_LDADD    = $(FUSE_LIBS) $(top_builddir)/libntfs-3g/libntfs-3g.la
if REALLYSTATIC
ntfs_3g_LDFLAGS  = $(AM_LDFLAGS) -all-static
endif
ntfs_3g_CFLAGS   =			\
	$(AM_CFLAGS) 			\
	-DFUSE_USE_VERSION=26 		\
	$(FUSE_CFLAGS) 			\
	-I$(top_srcdir)/include/ntfs-3g
ntfs_3g_SOURCES  = ntfs-3g.c

ntfs_3g_probe_LDADD 	= $(top_builddir)/libntfs-3g/libntfs-3g.la
if REALLYSTATIC
ntfs_3g_probe_LDFLAGS	= $(AM_LDFLAGS) -all-static
endif
ntfs_3g_probe_CFLAGS  	= $(AM_CFLAGS) -I$(top_srcdir)/include/ntfs-3g
ntfs_3g_probe_SOURCES 	= ntfs-3g.probe.c

if RUN_LDCONFIG
install-exec-hook:
	$(LDCONFIG)
endif

if ENABLE_MOUNT_HELPER
install-exec-local:	install-rootbinPROGRAMS
	$(MKDIR_P) "$(DESTDIR)/sbin"
	$(LN_S) -f "$(rootbindir)/ntfs-3g" "$(DESTDIR)/sbin/mount.ntfs-3g"
endif

install-data-local:	install-man8
	$(LN_S) -f ntfs-3g.8 "$(DESTDIR)$(man8dir)/mount.ntfs-3g.8"

uninstall-local:
	$(RM) -f "$(DESTDIR)$(man8dir)/mount.ntfs-3g.8"
if ENABLE_MOUNT_HELPER
	$(RM) -f "$(DESTDIR)/sbin/mount.ntfs-3g"
endif
