# maturad: static binary on a distroless base
FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /maturad ./cmd/maturad

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /maturad /maturad
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/maturad"]
