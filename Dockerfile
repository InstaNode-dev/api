FROM golang:1.25-alpine AS builder
WORKDIR /app
# Copy proto module (replace directive points to ../proto)
COPY proto/ /proto/
COPY common/ /common/
# Copy API source
COPY api/go.mod api/go.sum ./
RUN go mod download
COPY api/ .
# Build-time metadata injected via -ldflags into instant.dev/common/buildinfo.
# Defaults keep the build runnable without --build-arg; CI passes real values.
ARG GIT_SHA=dev
ARG BUILD_TIME=unknown
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X instant.dev/common/buildinfo.GitSHA=${GIT_SHA} -X instant.dev/common/buildinfo.BuildTime=${BUILD_TIME} -X instant.dev/common/buildinfo.Version=${VERSION}" \
    -o /instant .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata docker-cli
WORKDIR /app
COPY --from=builder /instant /app/instant
EXPOSE 8080
ENTRYPOINT ["/app/instant"]
