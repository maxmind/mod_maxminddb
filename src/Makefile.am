AUTOMAKE_OPTIONS = foreign
LIBEXECDIR = @LIBEXECDIR@
WC=-Wc,"$(CFLAGS)"
WL=-Wl,"$(LDFLAGS) $(LIBMAXMINDDB_LDFLAGS)"

#   the default target
all: module

#   compile the DSO file
module: mod_maxminddb.c $(TARGET)
	$(APXS) -c $(WL) $(LIBS) $(WC) $(APXS_LDFLAGS) mod_maxminddb.c

install-exec-local: module
	$(MKDIR_P) $(DESTDIR)$(LIBEXECDIR)
	$(APXS) -i -S LIBEXECDIR=$(DESTDIR)$(LIBEXECDIR) -a -n maxminddb .libs/mod_maxminddb.so

CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*

EXTRA_DIST= mod_maxminddb.c
