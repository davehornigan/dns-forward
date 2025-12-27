ARG GOLANG_VERSION=1.25

FROM golang:${GOLANG_VERSION}-alpine

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o /usr/local/bin/dns-forward main.go && chmod +x /usr/local/bin/dns-forward

ENTRYPOINT ["/usr/local/bin/dns-forward"]
CMD ["-config", "config.yaml"]