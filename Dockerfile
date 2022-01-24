# docker build -t inetmon .
# docker run -it --net=host -e ARGS='-i eno1 -d 192.168.1.4' inetmon
FROM ubuntu:20.04

RUN apt-get update -y
RUN apt-get install -y \
  libglib2.0-0 \
  libncurses6 \
  libpcap-dev

COPY .libs/libinetflow.so* ./
COPY .libs/inetmon .

ENV LD_LIBRARY_PATH=.
CMD ./inetmon ${ARGS}
