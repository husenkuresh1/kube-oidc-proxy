# Copyright Jetstack Ltd. See LICENSE for details.

FROM golang:1.23.4-alpine3.21 AS build
WORKDIR /api
COPY . .
RUN go mod download
RUN go build  -o=proxy ./cmd/.

FROM alpine
WORKDIR /api
COPY --from=build /api/proxy .
