.PHONY: generate build run run-toy run-openresty verify-openresty stop-openresty test clean certs \
	httpbench accept-prod-p0 accept-prod-p0-cps-tls accept-prod-p0-long-p99 \
	accept-prod-p0-loader-lifecycle accept-prod-p0-hot-ports \
	accept-prod-p1 accept-prod-p1-map-bytes accept-prod-p1-reuseport \
	accept-prod-p1-waf-port-path accept-prod-p1-rollback

export CGO_ENABLED=0

generate:
	go generate ./...

build: generate
	go build -o waf-sklookup-demo .

httpbench:
	mkdir -p bin
	go build -o bin/httpbench ./tools/httpbench

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

# Production Go/No-Go P0 (HAH). Defaults: OPENRESTY_PREFIX=/usr/local/openresty-hah
accept-prod-p0: httpbench build
	chmod +x scripts/accept-prod-p0.sh scripts/accept-prod-p0-*.sh scripts/lib-prod-gng.sh
	OPENRESTY_PREFIX="$(or $(OPENRESTY_PREFIX),/usr/local/openresty-hah)" \
	OPENRESTY_NGINX_CONF="$(or $(OPENRESTY_NGINX_CONF),openresty/nginx.tengine-https-allow-http.conf.example)" \
	LOADER_TLS_PORTS="" \
	./scripts/accept-prod-p0.sh

accept-prod-p0-cps-tls: httpbench build
	chmod +x scripts/accept-prod-p0-cps-tls.sh scripts/lib-prod-gng.sh
	OPENRESTY_PREFIX="$(or $(OPENRESTY_PREFIX),/usr/local/openresty-hah)" \
	OPENRESTY_NGINX_CONF="$(or $(OPENRESTY_NGINX_CONF),openresty/nginx.tengine-https-allow-http.conf.example)" \
	LOADER_TLS_PORTS="" \
	./scripts/accept-prod-p0-cps-tls.sh

accept-prod-p0-long-p99: httpbench build
	chmod +x scripts/accept-prod-p0-long-p99.sh scripts/lib-prod-gng.sh
	OPENRESTY_PREFIX="$(or $(OPENRESTY_PREFIX),/usr/local/openresty-hah)" \
	OPENRESTY_NGINX_CONF="$(or $(OPENRESTY_NGINX_CONF),openresty/nginx.tengine-https-allow-http.conf.example)" \
	LOADER_TLS_PORTS="" \
	./scripts/accept-prod-p0-long-p99.sh

accept-prod-p0-loader-lifecycle: build
	chmod +x scripts/accept-prod-p0-loader-lifecycle.sh scripts/lib-prod-gng.sh
	OPENRESTY_PREFIX="$(or $(OPENRESTY_PREFIX),/usr/local/openresty-hah)" \
	OPENRESTY_NGINX_CONF="$(or $(OPENRESTY_NGINX_CONF),openresty/nginx.tengine-https-allow-http.conf.example)" \
	LOADER_TLS_PORTS="" \
	./scripts/accept-prod-p0-loader-lifecycle.sh

accept-prod-p0-hot-ports: httpbench build
	chmod +x scripts/accept-prod-p0-hot-ports.sh scripts/lib-prod-gng.sh
	OPENRESTY_PREFIX="$(or $(OPENRESTY_PREFIX),/usr/local/openresty-hah)" \
	OPENRESTY_NGINX_CONF="$(or $(OPENRESTY_NGINX_CONF),openresty/nginx.tengine-https-allow-http.conf.example)" \
	LOADER_TLS_PORTS="" \
	./scripts/accept-prod-p0-hot-ports.sh

# Production Go/No-Go P1 (HAH). map bytes / reuseport / waf_port / rollback
accept-prod-p1: httpbench build
	chmod +x scripts/accept-prod-p1.sh scripts/accept-prod-p1-*.sh scripts/lib-prod-gng.sh
	OPENRESTY_PREFIX="$(or $(OPENRESTY_PREFIX),/usr/local/openresty-hah)" \
	OPENRESTY_NGINX_CONF="$(or $(OPENRESTY_NGINX_CONF),openresty/nginx.tengine-https-allow-http.conf.example)" \
	LOADER_TLS_PORTS="" \
	./scripts/accept-prod-p1.sh

accept-prod-p1-map-bytes: build
	chmod +x scripts/accept-prod-p1-map-bytes.sh scripts/lib-prod-gng.sh
	OPENRESTY_PREFIX="$(or $(OPENRESTY_PREFIX),/usr/local/openresty-hah)" \
	OPENRESTY_NGINX_CONF="$(or $(OPENRESTY_NGINX_CONF),openresty/nginx.tengine-https-allow-http.conf.example)" \
	LOADER_TLS_PORTS="" \
	./scripts/accept-prod-p1-map-bytes.sh

accept-prod-p1-reuseport: httpbench build
	chmod +x scripts/accept-prod-p1-reuseport.sh scripts/lib-prod-gng.sh
	OPENRESTY_PREFIX="$(or $(OPENRESTY_PREFIX),/usr/local/openresty-hah)" \
	OPENRESTY_NGINX_CONF="$(or $(OPENRESTY_NGINX_CONF),openresty/nginx.tengine-https-allow-http.conf.example)" \
	LOADER_TLS_PORTS="" \
	./scripts/accept-prod-p1-reuseport.sh

accept-prod-p1-waf-port-path: build
	chmod +x scripts/accept-prod-p1-waf-port-path.sh scripts/lib-prod-gng.sh
	OPENRESTY_PREFIX="$(or $(OPENRESTY_PREFIX),/usr/local/openresty-hah)" \
	OPENRESTY_NGINX_CONF="$(or $(OPENRESTY_NGINX_CONF),openresty/nginx.tengine-https-allow-http.conf.example)" \
	LOADER_TLS_PORTS="" \
	./scripts/accept-prod-p1-waf-port-path.sh

accept-prod-p1-rollback: build
	chmod +x scripts/accept-prod-p1-rollback.sh scripts/lib-prod-gng.sh
	OPENRESTY_PREFIX="$(or $(OPENRESTY_PREFIX),/usr/local/openresty-hah)" \
	OPENRESTY_NGINX_CONF="$(or $(OPENRESTY_NGINX_CONF),openresty/nginx.tengine-https-allow-http.conf.example)" \
	LOADER_TLS_PORTS="" \
	./scripts/accept-prod-p1-rollback.sh

clean:
	rm -f waf-sklookup-demo dispatch_bpfel.go dispatch_bpfel.o dispatch_bpfeb.go dispatch_bpfeb.o
	rm -f bin/httpbench
