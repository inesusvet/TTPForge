FROM mcr.microsoft.com/oss/go/microsoft/golang:1.22-cbl-mariner2.0

ADD . /src
WORKDIR /src
RUN go build -o /ttpforge main.go
WORKDIR /

ENTRYPOINT [ "/ttpforge" ]
