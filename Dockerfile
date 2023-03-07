FROM golang:buster AS build-env
ADD . /go-src
WORKDIR /go-src
RUN go build -o /go-app cmd/vulctl/main.go

FROM gcr.io/distroless/base
COPY --from=build-env /go-app /
ENTRYPOINT ["/go-app"]
