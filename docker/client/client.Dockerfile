# FROM --platform=linux/arm64 gcr.io/distroless/static-debian11
FROM --platform=linux/arm64 alpine:latest

WORKDIR /opt/rac

COPY rac-arm /opt/rac/rac

COPY entrypoint.sh /opt/rac

COPY client-docker.toml /opt/rac

ENTRYPOINT /opt/rac/entrypoint.sh
