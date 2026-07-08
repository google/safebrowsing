# 281284021051.dkr.ecr.us-east-1.amazonaws.com/wi-backend:google-safebrowsing
FROM golang:1.25-alpine AS build

WORKDIR /src
COPY . .
RUN go build -mod=mod -o /out/sbserver ./cmd/sbserver

FROM alpine:3.21

RUN addgroup -S safebrowsing \
	&& adduser -S -G safebrowsing safebrowsing \
	&& mkdir -p /var/lib/safebrowsing \
	&& chown -R safebrowsing:safebrowsing /var/lib/safebrowsing

COPY --from=build /out/sbserver /usr/local/bin/sbserver

USER safebrowsing
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
	CMD wget -q -O /dev/null http://127.0.0.1/health || exit 1
ENTRYPOINT ["sbserver", "-srvaddr", "0.0.0.0:80"]
