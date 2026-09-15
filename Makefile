GO ?= go
BIN := bin/wecert
# 辅助工具：只用于测试与排障，不随产品部署。
# 加 wecert- 前缀是为了安装到 /usr/local/bin 后不会和其它工具撞名。
PREFLIGHT := bin/wecert-preflight
CLBVERIFY := bin/wecert-clbverify
TATRUN := bin/wecert-tatrun
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.1.0)

# 交叉编译目标。腾讯云 CVM 绝大多数是 linux/amd64；
# ARM 实例用 linux/arm64；darwin/arm64 供本机调试。
PLATFORMS := linux/amd64 linux/arm64 darwin/arm64

.PHONY: build tools release test vet cover clean fmt validate-cloudinit fmt-check check

build: $(BIN)

$(BIN):
	$(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN) ./cmd/wecert

# 构建辅助工具（preflight 前置检查、clbverify 监听器绑定取证）。
tools: $(PREFLIGHT) $(CLBVERIFY) $(TATRUN)

$(PREFLIGHT):
	$(GO) build -trimpath -ldflags "-s -w" -o $(PREFLIGHT) ./cmd/preflight

$(CLBVERIFY):
	$(GO) build -trimpath -ldflags "-s -w" -o $(CLBVERIFY) ./cmd/clbverify

$(TATRUN):
	$(GO) build -trimpath -ldflags "-s -w" -o $(TATRUN) ./cmd/tatrun

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

# apply 之前查 cloud-init user_data 里的脚本语法。
# 这类错误只有机器启动后才暴露，现象是 CLB 502，很容易误判成网络问题。
validate-cloudinit:
	python3 scripts/validate-cloudinit.py

test:
	$(GO) test ./...

# -race 是必要的：SAN 多的证书上，DNS 探测与授权轮询都是并发的，
# 数据竞争会表现成"偶尔某个域名的验证莫名其妙失败"，
# 那种 bug 靠人工 review 看不出来。
test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

cover:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

fmt:
	$(GO) fmt ./...

# 只检查不修改，用于 CI 门禁。
fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then \
		echo "以下文件未格式化，请运行 make fmt:"; echo "$$out"; exit 1; \
	fi

# 提交前的完整门禁。
check: fmt-check vet test-race

clean:
	rm -rf bin dist coverage.out
