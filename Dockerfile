FROM golang:1.21-alpine
COPY . /go/src/go.opentelemetry.io/otel/example/dice
WORKDIR /go/src/go.opentelemetry.io/otel/example/dice
RUN go install
CMD ["/go/bin/dice"]
