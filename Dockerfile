# docker build -t inetmon .
# docker run -it --net=host -e ARGS='-q -i eno1 -d 192.168.1.4' inetmon

# Build inside the image, so that the binaries match its C library
FROM ubuntu:24.04 AS build
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    autoconf automake libtool pkg-config make gcc libc6-dev \
    libglib2.0-dev libncurses-dev libpcap-dev
WORKDIR /src
COPY . .
RUN ./autogen.sh && ./configure --prefix=/usr/local && make && make inetmon && make install \
    && ./libtool --mode=install install -m 755 inetmon /usr/local/bin/inetmon

FROM ubuntu:24.04
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    libglib2.0-0t64 libncurses6 libpcap0.8t64 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/lib/libinetflow.so* /usr/local/lib/
COPY --from=build /usr/local/bin/inetmon /usr/local/bin/
RUN ldconfig
CMD inetmon ${ARGS}
