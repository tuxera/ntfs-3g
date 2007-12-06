
MAINTAINERCLEANFILES=\
	Makefile.in

rootbin_PROGRAMS=\
	ntfs-3g
rootsbin_DATA=#Create directory
man_MANS=\
	ntfs-3g.8

ntfs_3g_LDADD =\
	$(top_builddir)/libntfs-3g/libntfs-3g.la
if REALLYSTATIC
ntfs_3g_LDFLAGS=\
	$(AM_LDFLAGS) \
        -all-static
endif
ntfs_3g_CFLAGS=\
	$(AM_CFLAGS) \
	-DFUSE_USE_VERSION=26 \
	-I$(top_srcdir)/include/ntfs-3g
ntfs_3g_SOURCES=\
	ntfs-3g.c \
	utils.c \
	utils.h
if FUSE_INTERNAL
ntfs_3g_CFLAGS+=\
	-I$(top_srcdir)/include/fuse-lite
else
ntfs_3g_CFLAGS+=\
	$(FUSE_MODULE_CFLAGS)
ntfs_3g_LDADD+=\
	$(FUSE_MODULE_LIBS)
endif

if RUN_LDCONFIG
install-exec-hook:
	$(LDCONFIG)
endif

install-exec-local:
	$(INSTALL) -d "$(DESTDIR)$(rootsbindir)"
	$(LN_S) -f "$(rootbindir)/ntfs-3g" "$(DESTDIR)$(rootsbindir)/mount.ntfs-3g"

install-data-local:
	$(INSTALL) -d "$(DESTDIR)$(man8dir)"
	$(LN_S) -f ntfs-3g.8 "$(DESTDIR)$(man8dir)/mount.ntfs-3g.8"

uninstall-local:
	$(RM) -f "$(DESTDIR)$(rootsbindir)/mount.ntfs-3g"
	$(RM) -f "$(DESTDIR)$(man8dir)/mount.ntfs-3g.8"
