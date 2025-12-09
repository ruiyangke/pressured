# Go pprof demo app with Fiber framework
#
# Build: docker build -t go-pprof-app .
# Run: docker run -p 8080:8080 go-pprof-app

FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go.mod first for layer caching
COPY go.mod ./
RUN go mod download 2>/dev/null || true

# Copy source and build
COPY main.go ./
RUN go mod tidy && CGO_ENABLED=0 go build -ldflags="-s -w" -o app .

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/app /app

EXPOSE 8080

# Default: start without memory leak mode
# Use --leak flag to enable continuous memory leak for testing
ENTRYPOINT ["/app"]
CMD ["--port", "8080"]
