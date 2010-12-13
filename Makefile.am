
AUTOMAKE_OPTIONS = gnu
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = AUTHORS CREDITS COPYING NEWS autogen.sh  

MAINTAINERCLEANFILES=\
	$(srcdir)/configure \
	$(srcdir)/Makefile.in \
	$(srcdir)/aclocal.m4 \
	$(srcdir)/compile \
	$(srcdir)/depcomp \
	$(srcdir)/install-sh \
	$(srcdir)/ltmain.sh \
	$(srcdir)/missing \
	$(srcdir)/config.guess \
	$(srcdir)/config.sub \
	$(srcdir)/config.h.in \
	$(srcdir)/config.h.in~ \
	$(srcdir)/INSTALL \
	$(srcdir)/m4/ltsugar.m4 \
	$(srcdir)/m4/libtool.m4 \
	$(srcdir)/m4/ltversion.m4 \
	$(srcdir)/m4/lt~obsolete.m4 \
	$(srcdir)/m4/ltoptions.m4

SUBDIRS = doc include libfuse-lite libntfs-3g ntfsprogs src

doc_DATA = README

dist-hook:
	$(MKDIR_P) "$(distdir)/m4"

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

strip:
	(cd ntfsprogs && $(MAKE) strip) || exit 1;

extra:	extras

extras: libs
	(cd ntfsprogs && $(MAKE) extras) || exit 1;
