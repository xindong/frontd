FROM golang:latest
MAINTAINER Tomasen "https://github.com/tomasen"

# Copy the local package files to the container's workspace.
ADD . /go/src/github.com/xindong/frontd

# change workdir, build and install
WORKDIR /go/src/github.com/xindong/frontd
RUN go get .
RUN go install

RUN rm -rf /go/src/*
WORKDIR /go/bin

# Run the frontd command by default when the container starts.
ENTRYPOINT /go/bin/frontd

EXPOSE 4043
