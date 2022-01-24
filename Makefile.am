lib_LTLIBRARIES = libinetflow.la

libinetflow_la_CFLAGS = \
	@CFLAGS@ \
	@GLIB_CFLAGS@

libinetflow_la_LDFLAGS = \
	-version-info 1:0:0

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
unittest_CFLAGS = $(libinetflow_la_CFLAGS) -g -fprofile-arcs -fprofile-dir=gcov -ftest-coverage
unittest_LDADD = $(libinetflow_la_LIBADD)

test: unittest
	@echo "Running unit tests"
	$(Q)mkdir -p gcov
	$(Q)G_SLICE=always-malloc VALGRIND_OPTS=--suppressions=valgrind.supp valgrind --leak-check=full ./unittest 2>&1
	$(Q)mv *.gcno gcov/
	$(Q)lcov -q --capture --directory . --output-file gcov/coverage.info
	$(Q)genhtml -q gcov/coverage.info --output-directory gcov

indent:
	indent -kr -ncs -nut -l92 *.c *.h
	rm *.c~ *.h~
