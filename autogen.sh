#!/bin/sh
# Run this to generate all the initial makefiles, etc.

if test "$srcdir" == ""; then
	srcdir=.
elif test "$srcdir" != "."; then
	pushd $srcdir > /dev/null
fi

(autoreconf --version) < /dev/null > /dev/null 2>&1 || {
  (autoconf --version) < /dev/null > /dev/null 2>&1 || {
    echo
    echo "**Error**: You must have the GNU Build System (autoconf, automake, "
    echo "libtool, etc) to update the ntfsprogs build system.  Download the "
    echo "appropriate packages for your distribution, or get the source "
    echo "tar balls from ftp://ftp.gnu.org/pub/gnu/."
    exit 1
  }
  echo
  echo "**Error**: Your version of autoconf is too old (you need 2.57) to "
  echo "update the ntfsprogs build system.  Download the appropriate "
  echo "updated package for your distribution, or get the source tar ball "
  echo "from ftp://ftp.gnu.org/pub/gnu/."
  exit 1
}

echo Running autoreconf --verbose --install --warnings=all
autoreconf --verbose --install --warnings=all

if test -z "$*"; then
  echo "**Warning**: I am going to run \`configure' with no arguments."
  echo "If you wish to pass any to it, please specify them on the"
  echo \`$0\'" command line."
  echo
fi

conf_flags="--enable-maintainer-mode --enable-compile-warnings"

echo Running $srcdir/configure $conf_flags "$@" ...
$srcdir/configure $conf_flags "$@" \
	&& echo Now type \`make\' to compile ntfsprogs. || err=1

if test "$srcdir" != "."; then
	popd > /dev/null
fi

if test "$err" == "1"; then
	exit 1
fi

exit 0
