AUTOMAKE_OPTIONS = foreign
WC=-Wc,"-std=gnu99 $(CFLAGS)"

#   the default target
all: module

#   compile the DSO file
module: mod_maxminddb.c $(TARGET)
	$(APXS) -c $(LDFLAGS) $(LIBMAXMINDDB_LDFLAGS) $(LIBS) $(WC) $(APXS_LDFLAGS) mod_maxminddb.c

install-exec-local: module
	$(APXS) -i -a -n maxminddb .libs/mod_maxminddb.so

CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*

EXTRA_DIST= mod_maxminddb.c
