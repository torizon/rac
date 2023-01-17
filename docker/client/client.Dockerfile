FROM alpine:latest

RUN apk --no-cache add bash

WORKDIR /opt/rac

COPY rac-arm /opt/rac/rac

COPY entrypoint.sh /opt/rac

COPY client-docker.toml /opt/rac

ENTRYPOINT /opt/rac/entrypoint.sh
