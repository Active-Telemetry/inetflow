AC_INIT([inetflow], [1.0])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_PROG_CC_STDC
AM_PROG_AR

LT_INIT([disable-static pic-only])

AC_CONFIG_MACRO_DIRS([m4])

PKG_CHECK_MODULES([GLIB],[glib-2.0])
PKG_CHECK_MODULES([PCAP], [libpcap >= 1.9.1], [HAVE_PCAP=1], [HAVE_PCAP=0])
AM_CONDITIONAL([USE_PCAP], [test "$HAVE_PCAP" -eq 1])
PKG_CHECK_MODULES([NDPI], [libndpi >= 2.6.0], [HAVE_NDPI=1], [HAVE_NDPI=0])
AM_CONDITIONAL([USE_NDPI], [test "$HAVE_NDPI" -eq 1])
PKG_CHECK_MODULES([NCURSES],[ncurses])

AC_CONFIG_FILES([Makefile inetflow.pc])
AC_OUTPUT
