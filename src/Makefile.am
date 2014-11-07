AUTOMAKE_OPTIONS = foreign
WC=-Wc,"$(CFLAGS)"

#   the default target
all: mod_maxminddb.so
#   compile the DSO file
mod_maxminddb.so: $(TARGET)
	$(APXS) -c $(LDFLAGS) $(LIBMAXMINDDB_LDFLAGS) $(LIBS) $(WC) $(APXS_LDFLAGS) mod_maxminddb.c

install:
	$(APXS) -i -a -n maxminddb .libs/mod_maxminddb.so

clean:
	-rm -rf .libs *.o *.so *.lo *.la *.slo *.loT
