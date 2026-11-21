# Langstroth relay (langstroth-relay) — build from this repo root: docker build -t langstroth-relay .
FROM golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/langstroth-relay ./cmd/langstroth-relay

FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
# UID/GID 1000: the same ids the former "hive" user got, so files on an
# existing snapshot volume keep their owner.
RUN apk add --no-cache su-exec && addgroup -g 1000 langstroth && adduser -D -H -u 1000 -G langstroth langstroth
LABEL org.opencontainers.image.title="Langstroth Relay" \
      org.opencontainers.image.description="Content-blind, end-to-end-encrypted sync relay for Ligus" \
      org.opencontainers.image.source="https://github.com/langstroth-ai/langstroth-relay" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/langstroth-relay /usr/local/bin/langstroth-relay
COPY deploy/container/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
# Listens on 0.0.0.0:8443 unless $PORT or LANGSTROTH_RELAY_ADDR says
# otherwise. entrypoint.sh defaults the snapshot store to /data when
# LANGSTROTH_RELAY_DATA_DIR is unset. Set DATABASE_URL for a shared Postgres
# store (horizontal scaling / HA, no data migration) — it takes precedence.
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
