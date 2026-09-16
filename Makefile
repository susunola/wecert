GO ?= go
BIN := bin/wecert
# The onboarding component. Like wecert it is part of the product (it runs in the
# scheduled job), but it is deliberately a separate binary: the inference logic
# must be replaceable wholesale without touching issuance.
ONBOARD := bin/wecert-onboard
# Auxiliary tools: used only for testing and troubleshooting, never shipped with
# the product. The wecert- prefix keeps them from colliding with other tools once
# installed into /usr/local/bin.
PREFLIGHT := bin/wecert-preflight
CLBVERIFY := bin/wecert-clbverify
TATRUN := bin/wecert-tatrun
PROBE := bin/wecert-probe
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.1.0)

# Diagrams: the Chinese version is the hand-written source, the English version is
# a build artifact.
SRCHTML := docs/certificate-lifecycle.html
ENHTML  := docs/certificate-lifecycle.en.html

# Cross-compilation targets. The vast majority of Tencent Cloud CVMs are
# linux/amd64; ARM instances use linux/arm64; darwin/arm64 is for local debugging.
PLATFORMS := linux/amd64 linux/arm64 darwin/arm64

# Commands shipped with the product. The webhook-triggered half is not in here
# yet; keep this list in sync when it lands.
CMDS := wecert wecert-onboard

.PHONY: build build-lego-dns fuzz sbom repro-check tools release test test-race vet cover clean fmt validate-cloudinit check-english check-scripts check-alerts fmt-check check diagrams diagrams-check

build:
	$(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN) ./cmd/wecert

# The same binary with lego's full DNS provider registry (~198 providers).
#
# Opt-in because the registry imports hundreds of third-party SDKs (Azure, AWS, Huawei, Yandex,
# Oracle, Akamai, ...), which is a large amount of code to add to the supply chain of a program
# that holds private keys -- and it would multiply the size of the default binary. The first
# build with this tag therefore has to fetch all of them:
#
#	go mod tidy   # once, with the tag in effect, to populate go.sum
#
# Without that the build fails with "missing go.sum entry" for whichever provider module is
# reached first, which is the honest outcome: a dependency cannot enter the binary without
# being recorded.
build-lego-dns:
	$(GO) build -tags lego_dns -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN) ./cmd/wecert

# Six PNGs per language, embedded in the readme.
#
# The Chinese version is the hand-written source of truth and the English version
# is generated from the translation table — so the English page is a build
# artifact that depends on the Chinese source and the translation table, and
# changing either of them regenerates it.
#
# Why there is a command for this instead of a one-off manual export: PNGs are
# binary, so they do not follow along when the code changes. Having a re-runnable
# path is what reduces "the diagram is stale" to a single `make diagrams`.
diagrams: diagrams-check
	python3 scripts/render-diagrams.py

# Measure in a real browser whether every foreignObject label overflows its box,
# in both languages.
#
# English is longer than Chinese, so the same sentence can fit in one language and
# overflow in the other — which is exactly why the English version has to be
# measured separately (the first run caught diagram 6 overflowing by 1px).
diagrams-check: $(ENHTML)
	python3 scripts/check-diagram-fit.py

$(ENHTML): $(SRCHTML) scripts/diagram_i18n.py scripts/build-diagram-langs.py
	python3 scripts/build-diagram-langs.py

# Build the auxiliary tools (preflight pre-flight checks, clbverify
# listener-binding evidence, probe network-side evidence).
tools:
	$(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(ONBOARD) ./cmd/wecert-onboard
	$(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(PROBE) ./cmd/wecert-probe
	$(GO) build -trimpath -ldflags "-s -w" -o $(PREFLIGHT) ./cmd/preflight
	$(GO) build -trimpath -ldflags "-s -w" -o $(CLBVERIFY) ./cmd/clbverify
	$(GO) build -trimpath -ldflags "-s -w" -o $(TATRUN) ./cmd/tatrun

# Produce static binaries that can be dropped straight onto a CVM.
# CGO_ENABLED=0 is required: first for cross-compilation, and second so the
# artifacts do not depend on glibc and therefore also run on Alpine/musl. This is
# feasible because SQLite is used through a pure-Go implementation.
release:
	@rm -rf dist && mkdir -p dist
	@for cmd in $(CMDS); do \
		for p in $(PLATFORMS); do \
			os=$${p%%/*}; arch=$${p##*/}; \
			out=dist/$${cmd}_$${os}_$${arch}; \
			printf 'building %-34s' "$$out"; \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath \
				-ldflags "-s -w -X main.version=$(VERSION)" -o $$out ./cmd/$$cmd || exit 1; \
			printf '%s\n' "ok"; \
		done; \
	done
	@cd dist && (command -v sha256sum >/dev/null 2>&1 && sha256sum wecert* || shasum -a 256 wecert*) > SHA256SUMS
	@echo && echo "=== artifacts ===" && ls -lh dist/ && echo && cat dist/SHA256SUMS

# A CycloneDX SBOM for the release, generated from the module graph.
#
# Why it ships: this program holds private keys and links two cloud SDKs plus a TLS stack, so "what
# exactly is in the binary" is a question operators and reviewers are entitled to answer without
# reading go.mod and resolving the transitive tree by hand.
#
# `-licenses` is deliberately NOT used: it needs every module present in the local cache, and when
# one is missing it logs a warning and produces an SBOM with that field silently absent. A
# completeness claim that quietly degrades is worse than not making it.
SBOM := dist/wecert-sbom.cdx.json
sbom: build
	@command -v cyclonedx-gomod >/dev/null 2>&1 || { \
		echo "cyclonedx-gomod not found; install with:"; \
		echo "  go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest"; \
		exit 1; }
	@mkdir -p dist
	cyclonedx-gomod mod -output $(SBOM) -json
	@echo "SBOM: $(SBOM) ($$(wc -c < $(SBOM) | tr -d ' ') bytes)"

# Verify that the release binaries can be rebuilt bit-for-bit from the same source.
#
# This is what makes "the artifact was built from this commit" checkable rather than asserted, and it
# is the precondition for anyone else reproducing a release to compare against ours. `-trimpath` is
# already in the build; the remaining variables are the Go toolchain and GOOS/GOARCH, which is why
# the comparison is per-platform and per-toolchain rather than universal.
repro-check:
	@rm -rf /tmp/wecert-repro && mkdir -p /tmp/wecert-repro
	@for p in $(PLATFORMS); do \
		os=$${p%%/*}; arch=$${p##*/}; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath \
			-ldflags "-s -w -X main.version=$(VERSION)" \
			-o /tmp/wecert-repro/a ./cmd/wecert || exit 1; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath \
			-ldflags "-s -w -X main.version=$(VERSION)" \
			-o /tmp/wecert-repro/b ./cmd/wecert || exit 1; \
		if cmp -s /tmp/wecert-repro/a /tmp/wecert-repro/b; then \
			printf 'reproducible  %s/%s\n' $$os $$arch; \
		else \
			printf 'NOT REPRODUCIBLE  %s/%s\n' $$os $$arch; exit 1; \
		fi; \
	done
	@rm -rf /tmp/wecert-repro

# Check the syntax of the scripts inside the cloud-init user_data before apply.
# This class of error only shows up after the machine boots, and what you see is a
# CLB 502, which is easily misdiagnosed as a network problem.
validate-cloudinit:
	python3 scripts/validate-cloudinit.py

# Fail if any comment or message is still in Chinese. Two files are deliberately
# excluded because their Chinese is data, not prose: docs/certificate-lifecycle.html
# (the hand-written source for the Chinese diagram set) and scripts/diagram_i18n.py
# (the zh->en translation table, whose Chinese keys are the lookup keys). Markdown
# is skipped too: the repository ships paired English/Chinese documents on purpose.
check-english:
	python3 scripts/check-english.py

test:
	$(GO) test ./...

# -race is necessary: on certificates with many SANs, DNS probing and
# authorization polling run concurrently, and a data race shows up as "some
# domain's validation fails intermittently for no apparent reason" — the kind of
# bug that human review does not catch.
test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

cover:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

fmt:
	$(GO) fmt ./...

# Check only, never modify; used as a CI gate.
fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then \
		echo "The following files are not formatted; run make fmt:"; echo "$$out"; exit 1; \
	fi

# The full pre-commit gate.
# The shell scripts are part of the delivery surface (install.sh, the systemd units, the
# e2e runners) and nothing else tests them. e2e-wildcard.sh in particular cannot be
# exercised without real DNS, so its assertions are driven by a canned resolver here.
check-scripts:
	@bash scripts/test-e2e-wildcard.sh

# The shipped Prometheus rules are the only thing watching several failures that are silent by
# construction, so a rule that cannot fire is worse than no rule: the operator believes they are
# covered. One of them could not fire, and this is what now catches that class.
check-alerts:
	python3 scripts/check-alerts.py

# A real ACME lifecycle against pebble (plus a real account, real order, real CSR finalize and
# real chain download). Behind a build tag because it needs a pebble binary, and it skips with
# instructions when the binary is absent rather than failing the build.
#
#	go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
test-pebble:
	$(GO) test -tags pebble -count=1 -timeout 5m ./internal/acme/ -run TestPebble -v

# Property and fuzz testing. Separate from `check` because each target runs for a bounded
# wall-clock budget rather than to completion, so it belongs in a scheduled job as well as a
# pre-merge run.
#
# FUZZTIME defaults to 30s per target: long enough to explore well past the seed corpus (the
# runs that found the divide-by-zero executed ~30 million inputs) and short enough to sit in CI.
FUZZTIME ?= 30s
fuzz:
	$(GO) test ./internal/ratelimit/ -run XXX -fuzz FuzzRemainingStaysWithinItsBucket -fuzztime $(FUZZTIME)
	$(GO) test ./internal/ratelimit/ -run XXX -fuzz FuzzSpendNeverCreatesTokens -fuzztime $(FUZZTIME)
	$(GO) test ./internal/ratelimit/ -run XXX -fuzz FuzzLimitWithDegenerateRefill -fuzztime $(FUZZTIME)
	$(GO) test ./internal/ratelimit/ -run XXX -fuzz FuzzParseRetryAfter -fuzztime $(FUZZTIME)

check: check-english fmt-check vet test-race check-scripts check-alerts

clean:
	rm -rf bin dist coverage.out
