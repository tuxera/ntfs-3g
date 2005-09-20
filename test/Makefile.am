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

#TEST_VALGRIND		= valgrind
TEST_RUNLIST		= runlist

bin_PROGRAMS		= $(TEST_RUNLIST)

CLEANFILES		= attr[123].bin frag[123][123][123] pure-[cn][ms] zero
MAINTAINERCLEANFILES	= Makefile.in

linux_ntfsincludedir	= -I$(top_srcdir)/include/ntfs

# Set the include path.
AM_CPPFLAGS		= -I$(top_srcdir)/include/ntfs $(all_includes)

runlist_SOURCES		= runlist.c
runlist_LDADD		= $(AM_LIBS)
runlist_LDFLAGS		= $(AM_LFLAGS)

# Extra targets

libs:
	(cd ../libntfs && $(MAKE) libs) || exit 1;

test:	$(TEST_RUNLIST) testz testp testf

testz:	$(TEST_RUNLIST)
	@$(TEST_VALGRIND) $(TEST_RUNLIST) zero > zero
	@diff -qs {runlist-data/,}zero

testp:	$(TEST_RUNLIST)
	@for i in contig noncontig; do						\
		for j in single multi; do					\
			L1=`echo $$i | cut -b1`;				\
			L2=`echo $$j | cut -b1`;				\
			FILE=pure-$$L1$$L2;					\
			$(TEST_VALGRIND) $(TEST_RUNLIST) pure $$i $$j > $$FILE;	\
			diff -qs {runlist-data/,}$$FILE;			\
		done;								\
	done

testf:	$(TEST_RUNLIST)
	@for i in 123 132 213 231 312 321; do					\
		$(TEST_VALGRIND) $(TEST_RUNLIST) frag $$i > frag$$i;		\
		diff -qs {runlist-data/,}frag$$i;				\
	done

