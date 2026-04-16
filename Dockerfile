FROM golang:1.25-alpine AS builder
WORKDIR /app
# Copy proto module (replace directive points to ../proto)
COPY proto/ /proto/
COPY common/ /common/
# Copy API source
COPY api/go.mod api/go.sum ./
RUN go mod download
COPY api/ .
RUN CGO_ENABLED=0 GOOS=linux go build -o /instant .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata docker-cli
WORKDIR /app
COPY --from=builder /instant /app/instant
EXPOSE 8080
ENTRYPOINT ["/app/instant"]
