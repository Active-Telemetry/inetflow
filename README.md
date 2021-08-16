IP Flow Manager Library

## Build
```
./autogen.sh
./configure
make
make install
```

# Develop
```
make indent
make test
google-chrome gcov/index.html
```

# Demo - requires libpcap and libndpi
```
make demo

Usage:
  demo [OPTION...] - Demonstration of libinetflow

Help Options:
  -h, --help        Show help options

Application Options:
  -p, --pcap        Pcap file to use
  -d, --dpi         Analyse frames using DPI
  -v, --verbose     Be verbose
```

```
./demo -p test.pcap -d
```
