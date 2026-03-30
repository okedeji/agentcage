FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /bin/orchestrator ./cmd/orchestrator/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /bin/payload-proxy ./cmd/payload-proxy/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /bin/findings-sidecar ./cmd/findings-sidecar/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /bin/cage-cli ./cmd/cage-cli/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /bin/orchestrator /usr/local/bin/
COPY --from=builder /bin/payload-proxy /usr/local/bin/
COPY --from=builder /bin/findings-sidecar /usr/local/bin/
COPY --from=builder /bin/cage-cli /usr/local/bin/
ENTRYPOINT ["orchestrator"]
