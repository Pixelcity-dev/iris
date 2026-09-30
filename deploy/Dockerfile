FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/iris-dashboard .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 app \
    && mkdir -p /data && chown app:app /data
USER app
COPY --from=build /out/iris-dashboard /usr/local/bin/iris-dashboard
EXPOSE 8080
ENTRYPOINT ["iris-dashboard"]
