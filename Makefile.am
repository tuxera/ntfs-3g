
SUBDIRS = doc include libntfs ntfsprogs

EXTRA_DIST = AUTHORS CREDITS COPYING TODO.include TODO.libntfs ChangeLog \
		INSTALL NEWS README autogen.sh ntfsprogs.spec.in \
		TODO.ntfsprogs getgccver

AUTOMAKE_OPTIONS = gnu

dist-hook: ntfsprogs.spec
	cp ntfsprogs.spec $(distdir)

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

strip:
	$(MAKE) -C ntfsprogs strip

extra:	extras

extras:
	$(MAKE) -C ntfsprogs extras

libs:
	$(MAKE) -C libntfs libs

