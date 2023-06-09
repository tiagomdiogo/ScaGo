
FROM golang:latest

LABEL maintainer="Tiago Diogo <tiago.m.diogo@tecnico.ulisboa.pt>"

ENV GO111MODULE=on

COPY go.mod go.sum ./

RUN go mod download 

RUN go get -u github.com/tiagomdiogo/GoPpy


RUN apt-get update && apt-get install -y \
    git \
    nano
CMD ["/bin/bash"]
