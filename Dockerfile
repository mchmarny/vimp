FROM golang:buster AS build-env
WORKDIR /src/
COPY . /src/
ARG VERSION
ARG COMMIT
ARG DATE
ENV VERSION ${VERSION}
ENV COMMIT ${COMMIT}
ENV DATE ${DATE}
RUN CGO_ENABLED=0 go build -trimpath -ldflags="\
    -w -s -X main.version=$VERSION \
	-w -s -X main.commit=$COMMIT \
	-w -s -X main.date=$DATE \
	-extldflags '-static'" \
    -a -mod vendor -o vulctl cmd/vulctl/main.go

# chainguard's static seems to provide best balance of size and vulnerabilities
# gogole/distroless: 13.3 MB, 18 vulnerabilities (all low)
# chainguard/static:  4.7 MB, 0 vulnerabilities
FROM cgr.dev/chainguard/static:latest
COPY --from=build-env /src/vulctl /
ENTRYPOINT ["/vulctl"]
