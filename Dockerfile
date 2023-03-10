FROM golang:buster AS build-env
WORKDIR /src/
COPY . /src/
ARG VERSION v0.2.0-dirty
ARG COMMIT c3536e5
ARG DATE 2023-03-09T18:52:01Z
ENV VERSION ${VERSION}
ENV COMMIT ${COMMIT}
ENV DATE ${DATE}
RUN CGO_ENABLED=0 go build -trimpath -ldflags="\
    -w -s -X main.version=$VERSION \
	-w -s -X main.commit=$COMMIT \
	-w -s -X main.date=$DATE \
	-extldflags '-static'" \
    -a -mod vendor -o vulctl cmd/vulctl/main.go

FROM gcr.io/distroless/base
COPY --from=build-env /src/vulctl /
ENTRYPOINT ["/vulctl"]
