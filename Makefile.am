
# Need this to enable 64-bit (device) file access functions and parameters.
if DEBUG
AM_CFLAGS = -D_FILE_OFFSET_BITS=64 -g -DDEBUG -Wall
else
AM_CFLAGS = -D_FILE_OFFSET_BITS=64
endif

SUBDIRS = doc include libntfs ntfsprogs

EXTRA_DIST = AUTHORS CREDITS COPYING TODO.include TODO.libntfs ChangeLog \
		INSTALL NEWS README autogen.sh ntfsprogs.spec.in \
		TODO.ntfsprogs

AUTOMAKE_OPTIONS = gnu

dist-hook: ntfsprogs.spec
	cp ntfsprogs.spec $(distdir)

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

strip:
	$(MAKE) -C ntfsprogs strip

