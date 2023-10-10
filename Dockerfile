FROM golang:1.19 AS bpf-tcp-proxy-sample

COPY bin/bpf-tcp-proxy-sample /usr/local/bin/bpf-tcp-proxy-sample
