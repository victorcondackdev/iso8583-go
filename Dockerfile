# Test issuer simulator. Build: docker build -t iso8583-sim .
# Run:   docker run --rm -p 8583:8583 iso8583-sim -limit 50000
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/iso8583-sim ./cmd/iso8583-sim

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/iso8583-sim /iso8583-sim
EXPOSE 8583
ENTRYPOINT ["/iso8583-sim", "-addr", "0.0.0.0:8583"]
