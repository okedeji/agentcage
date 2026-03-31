FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /bin/agentcage ./cmd/agentcage/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /bin/agentcage /usr/local/bin/
ENTRYPOINT ["agentcage"]
