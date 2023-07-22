FROM golang:1 AS base

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd
COPY internal/ ./internal


FROM base AS test

COPY e2e ./e2e
CMD go test -v --tags e2e ./...


FROM base AS build

RUN CGO_ENABLED=0 GOOS=linux go build -o ./tmp/local-jwks-server cmd/server/server.go
RUN CGO_ENABLED=0 GOOS=linux go build -o ./tmp/health cmd/health/health.go


FROM gcr.io/distroless/base-debian11 AS app

COPY --from=build /app/tmp/local-jwks-server /usr/bin/local-jwks-server
COPY --from=build /app/tmp/health /usr/bin/health

USER nonroot:nonroot

HEALTHCHECK --interval=1s --timeout=10s --retries=10 CMD [ "/usr/bin/health" ]

ENTRYPOINT ["/usr/bin/local-jwks-server"]
