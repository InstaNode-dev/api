# Minimal hello-world image for deploy E2E test.
#
# We use busybox httpd for three reasons:
#   1. Smallest possible image (~1MB vs ~5MB alpine vs ~300MB Go) — fastest pull on local k3s
#   2. No build step (unlike a Go binary) — fastest build on slow buildkit / kaniko
#   3. Most reliable: busybox httpd has zero deps, runs as PID 1, handles SIGTERM cleanly
#
# Listens on 8080 so the deploy E2E can pass port=8080 and verify that the
# container port is correctly wired through to the public URL.
FROM busybox:1.36
COPY index.html /index.html
EXPOSE 8080
CMD ["httpd", "-f", "-p", "8080", "-h", "/"]
