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
# docker-cli intentionally NOT installed: prod builds run via kaniko-in-k8s
# (COMPUTE_PROVIDER=k8s), so the api process never shells out to `docker`.
# Keeping it out trims the image and removes an unused tool from the surface.
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /instant /app/instant
# plans.yaml is the single source of truth for all plan limits and pricing.
# It MUST land in the final image — otherwise main.go's plans.Load() falls
# back to the embedded common/plans.Default() YAML and every edit to
# api/plans.yaml becomes a no-op at runtime. The builder stage above did
# `COPY api/ .` into /app, so plans.yaml is at /app/plans.yaml there.
# PLANS_PATH in the k8s configmap already points at /app/plans.yaml.
COPY --from=builder /app/plans.yaml /app/plans.yaml
EXPOSE 8080
ENTRYPOINT ["/app/instant"]
