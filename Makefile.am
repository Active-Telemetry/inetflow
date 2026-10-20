lib_LTLIBRARIES = libinetflow.la

libinetflow_la_CFLAGS = \
	@CFLAGS@ \
	@GLIB_CFLAGS@

libinetflow_la_LDFLAGS = \
	-version-info 2:0:0

libinetflow_la_LIBADD = \
	@GLIB_LIBS@

libinetflow_la_SOURCES = \
	inetflow.c

include_HEADERS = inetflow.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = inetflow.pc

EXTRA_PROGRAMS = unittest demo inetmon

inetmon_SOURCES = inetmon.c ic.c
inetmon_CFLAGS = $(libinetflow_la_CFLAGS) @PCAP_CFLAGS@
inetmon_LDADD = @PCAP_LIBS@ $(libinetflow_la_LIBADD) $(lib_LTLIBRARIES) @NCURSES_LIBS@

demo_SOURCES = demo.c
demo_CFLAGS = $(libinetflow_la_CFLAGS) @PCAP_CFLAGS@ @NDPI_CFLAGS@
if USE_NDPI
demo_CFLAGS += -DLIBNDPI_NEWEST_API
endif
demo_LDADD = @PCAP_LIBS@ @NDPI_LIBS@ $(libinetflow_la_LIBADD) $(lib_LTLIBRARIES) @NCURSES_LIBS@

unittest_SOURCES = test.c
unittest_CFLAGS = $(libinetflow_la_CFLAGS) -g -fno-inline -fprofile-arcs -ftest-coverage
unittest_LDADD = $(libinetflow_la_LIBADD)

# The unit tests built with AddressSanitizer and UndefinedBehaviorSanitizer,
# which report unaligned and out of bounds reads that valgrind does not
CLEANFILES = unittest-asan

unittest-asan: test.c inetflow.c inetflow.h
	$(CC) -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all \
		$(GLIB_CFLAGS) -I$(srcdir) $(srcdir)/test.c -o $@ $(GLIB_LIBS)

test-asan: unittest-asan
	@echo "Running unit tests with sanitizers"
	$(Q)G_SLICE=always-malloc ASAN_OPTIONS=detect_leaks=1 ./unittest-asan

test: unittest test-asan
	@echo "Running unit tests"
	$(Q)mkdir -p gcov
	$(Q)G_SLICE=always-malloc VALGRIND_OPTS=--suppressions=valgrind.supp valgrind --leak-check=full --error-exitcode=1 ./unittest 2>&1
	$(Q)lcov -q --capture --directory . --output-file coverage.info
	$(Q)genhtml -q coverage.info --output-directory gcov

indent:
	indent -kr -ncs -nut -l140 inetflow.c inetflow.h test.c demo.c inetmon.c
	rm -f *.c~ *.h~
