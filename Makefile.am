
# Need this to enable 64-bit (device) file access functions and parameters.
if DEBUG
AM_CFLAGS = -D_FILE_OFFSET_BITS=64 -g -DDEBUG -Wall
else
AM_CFLAGS = -D_FILE_OFFSET_BITS=64
endif

SUBDIRS = doc include libntfs ntfstools

EXTRA_DIST = AUTHORS CREDITS COPYING TODO.include TODO.libntfs ChangeLog \
		INSTALL NEWS README autogen.sh linux-ntfs.spec.in \
		TODO.ntfstools

AUTOMAKE_OPTIONS = gnu

dist-hook: linux-ntfs.spec
	cp linux-ntfs.spec $(distdir)

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

strip:
	$(MAKE) -C ntfstools strip

