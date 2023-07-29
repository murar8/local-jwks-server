FROM golang:1 AS base

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download


FROM base AS test-unit

COPY internal/ ./internal

RUN mkdir ./coverage

VOLUME ./coverage

CMD go test -v -race -covermode=atomic -coverprofile=./coverage/coverage.out ./...


FROM base AS test-e2e

COPY e2e ./e2e

CMD go test -v --tags e2e ./...


FROM base AS build

COPY cmd/ ./cmd
COPY internal/ ./internal

RUN CGO_ENABLED=0 GOOS=linux go build -o ./tmp/local-jwks-server cmd/server/server.go
RUN CGO_ENABLED=0 GOOS=linux go build -o ./tmp/health cmd/health/health.go


FROM gcr.io/distroless/base-debian11 AS app

COPY --from=build /app/tmp/local-jwks-server /usr/bin/local-jwks-server
COPY --from=build /app/tmp/health /usr/bin/health

USER nonroot:nonroot

HEALTHCHECK --interval=5s --timeout=30s --retries=10 CMD [ "/usr/bin/health" ]

ENTRYPOINT ["/usr/bin/local-jwks-server"]
