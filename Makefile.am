
SUBDIRS = include libntfs-3g src

EXTRA_DIST = AUTHORS CREDITS COPYING INSTALL NEWS README autogen.sh  
AUTOMAKE_OPTIONS = gnu

MAINTAINERCLEANFILES = configure Makefile.in aclocal.m4 compile depcomp \
	install-sh ltmain.sh missing config.guess config.sub config.h.in INSTALL

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

strip:
	(cd src && $(MAKE) strip) || exit 1;

libs:
	(cd libntfs-3g && $(MAKE) libs) || exit 1;
