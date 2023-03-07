FROM golang:buster AS build-env
WORKDIR /src/
COPY . /src/
ARG VERSION
ARG COMMIT
ARG DATE
ENV VERSION=$VERSION
ENV COMMIT=$COMMIT
ENV DATE=$DATE
RUN CGO_ENABLED=0 go build -trimpath -ldflags="\
    -w -s -X main.version=$VERSION \
	-w -s -X main.commit=$COMMIT \
	-w -s -X main.date=$DATE \
	-extldflags '-static'" \
    -a -mod vendor -o vulctl cmd/vulctl/main.go

FROM gcr.io/distroless/base
COPY --from=build-env /src/vulctl /
ENTRYPOINT ["/vulctl"]
