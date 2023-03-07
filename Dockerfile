FROM golang:buster AS build-env
WORKDIR /src/
COPY . /src/
ARG VERSION=v0.0.1-default
ARG COMMIT=12345notset
ARG CURRENT_DATE=2023-03-07T09:36:58Z
RUN CGO_ENABLED=0 go build -trimpath -ldflags="\
    -w -s -X main.version=$RELEASE_VERSION \
	-w -s -X main.commit=$COMMIT \
	-w -s -X main.date=$CURRENT_DATE \
	-extldflags '-static'" \
    -a -mod vendor -o vulctl cmd/vulctl/main.go

FROM gcr.io/distroless/base
COPY --from=build-env /src/vulctl /
ENTRYPOINT ["/vulctl"]
