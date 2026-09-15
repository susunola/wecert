GO ?= go
BIN := bin/wecert
# 辅助工具：只用于测试与排障，不随产品部署。
# 加 wecert- 前缀是为了安装到 /usr/local/bin 后不会和其它工具撞名。
PREFLIGHT := bin/wecert-preflight
CLBVERIFY := bin/wecert-clbverify
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.1.0)

# 交叉编译目标。腾讯云 CVM 绝大多数是 linux/amd64；
# ARM 实例用 linux/arm64；darwin/arm64 供本机调试。
PLATFORMS := linux/amd64 linux/arm64 darwin/arm64

.PHONY: build tools release test vet cover clean fmt

build: $(BIN)

$(BIN):
	$(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN) ./cmd/wecert

# 构建辅助工具（preflight 前置检查、clbverify 监听器绑定取证）。
tools: $(PREFLIGHT) $(CLBVERIFY)

$(PREFLIGHT):
	$(GO) build -trimpath -ldflags "-s -w" -o $(PREFLIGHT) ./cmd/preflight

$(CLBVERIFY):
	$(GO) build -trimpath -ldflags "-s -w" -o $(CLBVERIFY) ./cmd/clbverify

# 产出可直接扔到 CVM 上的静态二进制。
# CGO_ENABLED=0 是必须的：一是交叉编译，二是让产物不依赖 glibc，
# 这样 Alpine/musl 上也能直接跑。SQLite 用的是纯 Go 实现，所以可行。
release:
	@rm -rf dist && mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%%/*}; arch=$${p##*/}; \
		out=dist/wecert_$${os}_$${arch}; \
		printf 'building %-24s' "$$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath \
			-ldflags "-s -w -X main.version=$(VERSION)" -o $$out ./cmd/wecert || exit 1; \
		printf '%s\n' "ok"; \
	done
	@cd dist && (command -v sha256sum >/dev/null 2>&1 && sha256sum wecert_* || shasum -a 256 wecert_*) > SHA256SUMS
	@echo && echo "=== 产物 ===" && ls -lh dist/ && echo && cat dist/SHA256SUMS

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

cover:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

fmt:
	$(GO) fmt ./...

clean:
	rm -rf bin dist coverage.out
