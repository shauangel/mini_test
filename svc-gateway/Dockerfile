# build stage
FROM golang:1.25.6 AS builder

WORKDIR /src

COPY go.mod ./
RUN go mod download || true

COPY . .
WORKDIR /src/svc-gateway
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/app

# runtime stage（可以改成 alpine / distroless）
FROM gcr.io/distroless/base-debian12

COPY --from=builder /bin/app /app
EXPOSE 8003
ENTRYPOINT ["/app"]
