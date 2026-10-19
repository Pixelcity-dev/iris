FROM golang:1.27-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /iris ./cmd/iris

FROM gcr.io/distroless/static-debian12:latest

COPY --from=builder /iris /usr/local/bin/iris

COPY rules /rules

ENTRYPOINT ["iris"]
