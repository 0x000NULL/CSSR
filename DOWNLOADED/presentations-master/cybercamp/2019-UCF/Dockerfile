FROM alpine:3.10

MAINTAINER Rick Payne

# nmap build initial cache | install binary | remove cache
RUN apk update && apk add \
        nmap \
        && rm -rf /var/cache/apk/*

ENTRYPOINT ["nmap"]