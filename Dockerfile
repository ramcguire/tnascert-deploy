FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder
ARG TARGETOS TARGETARCH TARGETVARIANT
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} CGO_ENABLED=0 \
    go build -o tnascert-deploy -a -ldflags '-extldflags "-static"'

FROM gcr.io/distroless/static-debian13
COPY --from=builder /build/tnascert-deploy /tnascert-deploy
ENTRYPOINT ["/tnascert-deploy"]
