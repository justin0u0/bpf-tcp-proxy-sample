all: bpf/*.o build

bpf/*.o: bpf/*.c
	go generate ./bpf/...

.PHONY: build
build:
	go build -o bin/bpf-tcp-proxy-sample ./main.go

.PHONY: clean
clean:
	rm -rf bin
