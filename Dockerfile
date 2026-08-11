FROM golang:1.25 AS build
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build

FROM debian:13-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/dummy-oidc /usr/local/bin/dummy-oidc
CMD ["/usr/local/bin/dummy-oidc", "server"]
EXPOSE 8000
