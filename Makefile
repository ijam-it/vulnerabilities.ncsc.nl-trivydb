.PHONY: build test sync database full-build

BUILD_DIR ?= dist/ncsc

build:
	go build -trimpath -o bin/ncsc-trivy-db ./cmd/ncsc-trivy-db

test:
	go test ./...

sync: build
	./bin/ncsc-trivy-db sync

database: sync
	./bin/ncsc-trivy-db build

# Refresh twice to include changes made during the initial mirror download.
full-build: build
	@set -eu; \
	build_dir="$(BUILD_DIR)"; \
	./bin/ncsc-trivy-db sync; \
	./bin/ncsc-trivy-db sync; \
	./bin/ncsc-trivy-db build --output "$$build_dir"; \
	./bin/ncsc-trivy-db db audit --db "$$build_dir/db/trivy.db" --output "$$build_dir/audit.json"; \
	./bin/ncsc-trivy-db db verify --cache "$$build_dir"; \
	case "$$build_dir" in /*) scan_cache=$$build_dir;; *) scan_cache="$$PWD/$$build_dir";; esac; \
	printf 'Database ready. Scan with:\n./bin/ncsc-trivy-db scanning sbom --cache "%s" your-sbom.cdx.json\n' "$$scan_cache"
