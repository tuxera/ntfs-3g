
SUBDIRS = doc include libntfs ntfsprogs

EXTRA_DIST = AUTHORS CREDITS COPYING TODO.include TODO.libntfs ChangeLog \
		INSTALL NEWS README autogen.sh ntfsprogs.spec.in \
		TODO.ntfsprogs getgccver

AUTOMAKE_OPTIONS = gnu

MAINTAINERCLEANFILES = aclocal.m4 config.guess config.h.in config.sub \
		configure Makefile.in

dist-hook: ntfsprogs.spec
	cp ntfsprogs.spec $(distdir)

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

strip:
	(cd ntfsprogs && $(MAKE) strip) || exit 1;

extra:	extras

extras:
	(cd ntfsprogs && $(MAKE) extras) || exit 1;

libs:
	(cd libntfs && $(MAKE) libs) || exit 1;

