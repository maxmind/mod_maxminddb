AC_INIT([mod_maxminddb], [1.0.0], [support@maxmind.com])
AC_ARG_WITH(apxs, AC_HELP_STRING([--with-apxs=NAME],
            [name of your apxs executable [[apxs]]]),
            [APXS="$with_apxs"])
AC_PROG_CC_C99
AC_CONFIG_AUX_DIR([.])
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
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
