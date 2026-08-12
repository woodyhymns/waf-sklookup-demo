.PHONY: generate build run run-toy run-openresty verify-openresty stop-openresty test clean certs

export CGO_ENABLED=0

generate:
	go generate ./...

build: generate
	go build -o waf-sklookup-demo .

test: generate
	go test ./...

certs:
	chmod +x openresty/certs/gen-demo-certs.sh
	./openresty/certs/gen-demo-certs.sh

run: build
	sudo ./waf-sklookup-demo -mode toy -listen 127.0.0.1:18080 -ports 18081,18082,65500

run-toy: run

run-openresty: build certs
	chmod +x run-openresty-demo.sh
	./run-openresty-demo.sh start

verify-openresty:
	./run-openresty-demo.sh verify

stop-openresty:
	./run-openresty-demo.sh stop

clean:
	rm -f waf-sklookup-demo dispatch_bpfel.go dispatch_bpfel.o dispatch_bpfeb.go dispatch_bpfeb.o
