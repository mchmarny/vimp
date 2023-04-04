FROM golang:buster AS builder
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
    -a -mod vendor -o vimp internal/cmd/main.go

FROM cgr.dev/chainguard/bash:latest
COPY --from=builder /src/vimp /bin/vimp
ENTRYPOINT ["/bin/vimp"]
