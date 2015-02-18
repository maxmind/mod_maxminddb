AC_INIT([mod_maxminddb], [1.0.0], [support@maxmind.com])
AC_ARG_WITH(apxs, AC_HELP_STRING([--with-apxs=NAME],
            [name of your apxs executable [[apxs]]]),
            [APXS="$with_apxs"])
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE
AC_PROG_CC_C99

# Copied from http://stackoverflow.com/a/10682813/9832 and tweaked for C (as
# opposed to C++)
#
# AX_CHECK_CFLAGS(ADDITIONAL-CFLAGS, ACTION-IF-FOUND, ACTION-IF-NOT-FOUND)
#
# checks whether the $(CC) compiler accepts the ADDITIONAL-CFLAGS
# if so, they are added to the CXXFLAGS
AC_DEFUN([AX_CHECK_CFLAGS],
[
  AC_MSG_CHECKING([whether compiler accepts "$1"])
  cat > conftest.c << EOF
  int main(){
    return 0;
  }
EOF
  if $CC $CFLAGS -o conftest.o conftest.c [$1] > /dev/null 2>&1
  then
    AC_MSG_RESULT([yes])
    CFLAGS="${CFLAGS} [$1]"
    [$2]
  else
    AC_MSG_RESULT([no])
   [$3]
  fi
])dnl AX_CHECK_CFLAGS

AX_CHECK_CFLAGS([-std=c99])

if test -z "${APXS}"; then
    AC_PATH_PROGS(APXS, apxs2 apxs, no, [$PATH:/usr/sbin:/usr/local/apache2/bin])
fi
if test "$APXS" = no; then
    AC_MSG_ERROR([apxs not found. set apxs with --with-apxs.])
fi
AC_SUBST(APXS)
AC_CHECK_HEADERS([maxminddb.h])
AC_CHECK_LIB(maxminddb, MMDB_lib_version, [
    AC_DEFINE([HAVE_LIBMAXMINDDB], [1], [Have found libmaxminddb])
    LIBMAXMINDDB_LDFLAGS='-lmaxminddb'
    AC_SUBST(LIBMAXMINDDB_LDFLAGS)
    ],
    [AC_MSG_ERROR([libmaxminddb was not found])])
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
