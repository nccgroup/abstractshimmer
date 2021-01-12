FROM golang:1.14.4-buster

RUN apt-get update && apt-get install -y jq

COPY . /build
RUN cd /build && go build && cp abstractshimmer /abstractshimmer

CMD /abstractshimmer
