FROM ubuntu:xenial

RUN apt-get update && \
    apt-get install -y software-properties-common && \
    add-apt-repository ppa:lenski/openconnect-gp && \
    apt-get update && \
    apt-get install -y openconnect

COPY entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh"]
