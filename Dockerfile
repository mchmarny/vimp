FROM golang:buster AS build-env
ADD . /go-src
WORKDIR /go-src
RUN make build

FROM gcr.io/distroless/base
COPY --from=build-env /go-src/bin/vulctl /
ENTRYPOINT ["/vulctl"]
