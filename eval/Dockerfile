# Runs the whole analyzer inside a container whose `go` IS the target
# toolchain — no toolchain plumbing needed inside: every subprocess and
# packages.Load resolves stdlib under the release's GOROOT natively.
#
#   go build -o vuln-analyzer ./cmd/analyzer          # analyzer build Go is unrelated
#   docker build --build-arg GO_VERSION=1.21.13 \
#       -f eval/Dockerfile -t vuln-analyzer:go1.21.13 .
#   docker run --rm -v /path/to/repo:/repo:ro \
#       vuln-analyzer:go1.21.13 analyze --repo /repo --vuln GO-XXXX
#
# Mount the target repo read-only; case state/report are written under
# --case-dir (mount a rw dir if you need them on the host).
ARG GO_VERSION
FROM golang:${GO_VERSION}
COPY vuln-analyzer /usr/local/bin/vuln-analyzer
WORKDIR /repo
ENTRYPOINT ["vuln-analyzer"]
