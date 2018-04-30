# Subjack - Hostile Subdomain Takeover Tool
# docker run --name subjack \
#     --rm -v <path to wordlist or save dir>:/data \ 
#     c0dy/subjack <subjack options go here>
FROM golang:alpine
LABEL maintainer "Cody Zacharias <codyzacharias@pm.me>"

RUN apk add --no-cache --update \
      git \
      && go get github.com/haccer/subjack

VOLUME /data
ENV PATH="${PATH}:/go/bin"
WORKDIR /data

ENTRYPOINT [ "subjack" ]
