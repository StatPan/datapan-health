FROM golang:1.26.4-alpine3.22@sha256:727cfc3c40be55cd1bc9a4a059406b28a059857e3be752aa9d09531e12c20c56 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY schemas ./schemas
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /health-runner ./cmd/health-runner \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /health-scheduler ./cmd/health-scheduler

FROM scratch
COPY --from=build /health-runner /health-runner
COPY --from=build /health-scheduler /health-scheduler
ENTRYPOINT ["/health-runner"]
