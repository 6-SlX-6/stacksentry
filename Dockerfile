# Container image for running StackSentry Compose scans without installing Go.
#
#   docker build -t stacksentry:local .
#   docker run --rm -v "$PWD:/work:ro" stacksentry:local scan compose /work/compose.yaml
#
# For reproducible builds, pin the base images by digest.

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=0.1.0
ARG COMMIT=""
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/6-SlX-6/stacksentry/internal/version.Version=${VERSION} -X github.com/6-SlX-6/stacksentry/internal/version.Commit=${COMMIT}" \
      -o /out/stacksentry ./cmd/stacksentry

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/stacksentry /usr/local/bin/stacksentry
USER nonroot:nonroot
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/stacksentry"]
CMD ["--help"]
