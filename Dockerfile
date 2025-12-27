ARG GOLANG_VERSION=1.25

FROM golang:${GOLANG_VERSION}-alpine

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod ./
RUN go mod download

RUN go install github.com/air-verse/air@latest

COPY . .

EXPOSE 53/udp 53/tcp

CMD ["air", "-c", ".air.toml"]
