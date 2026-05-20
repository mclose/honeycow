# Tiny dedicated tcpdump image for the wire-monitoring sidecar.
# Pinned to an Alpine point release so the build is reproducible.
FROM alpine:3.20
RUN apk add --no-cache tcpdump=~4.99
ENTRYPOINT ["tcpdump"]
