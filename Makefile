.PHONY: generate build run clean

export CGO_ENABLED=0

generate:
	go generate ./...

build: generate
	go build -o waf-sklookup-demo .

run: build
	sudo ./waf-sklookup-demo -listen 127.0.0.1:18080 -ports 18081,18082,65500

clean:
	rm -f waf-sklookup-demo dispatch_bpfel.go dispatch_bpfel.o dispatch_bpfeb.go dispatch_bpfeb.o
