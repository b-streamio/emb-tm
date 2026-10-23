# SPDX-License-Identifier: GPL-2.0-only
.DEFAULT_GOAL := help
.PHONY: help build bin serve app install uninstall tools test lint coverage security sbom package \
	commit-check release release-check

# Port of `make serve` and `make app`. An installed app loads from it, so
# pick one no other local server uses.
PORT := 8000

# What the app fetches besides the wasm, its JavaScript glue, index.html and
# data/. Keep in step with SHELL in sw.js (the offline cache).
FILES := sw.js style.css manifest.webmanifest icon.svg icon-192.png icon-512.png \
	library/components.json examples/index.json \
	examples/system/connected-vision-system.project.json \
	examples/yocto-scan/core-image-gateway.project.json

WASM := target/wasm32-unknown-unknown/release/emb3d-wb.wasm
# wasm-bindgen must be the version in Cargo.lock; both tools are installed
# into target/tools, one directory per version.
BINDGEN_VERSION := $(shell awk '/^name = "wasm-bindgen"$$/ { getline; gsub(/"/, "", $$3); print $$3 }' Cargo.lock)
WASM_OPT_VERSION := 0.116.1
BINDGEN := target/tools/wasm-bindgen-$(BINDGEN_VERSION)/bin/wasm-bindgen
WASM_OPT := target/tools/wasm-opt-$(WASM_OPT_VERSION)/bin/wasm-opt
# The wasm features rustc emits by default.
WASM_OPT_FLAGS := -Oz --enable-bulk-memory --enable-mutable-globals --enable-nontrapping-float-to-int \
	--enable-reference-types --enable-sign-ext --enable-multivalue

# Analysis and release tools, pinned and installed the same way.
AUDIT := target/tools/cargo-audit-0.22.2/bin/cargo-audit
DENY := target/tools/cargo-deny-0.20.2/bin/cargo-deny
CARGO_LLVM_COV := target/tools/cargo-llvm-cov-0.9.1/bin/cargo-llvm-cov
CYCLONEDX := target/tools/cargo-cyclonedx-0.5.9/bin/cargo-cyclonedx
ABOUT := target/tools/cargo-about-0.9.2/bin/cargo-about
# Conventional Commits → next version and CHANGELOG.md (cliff.toml).
CLIFF := target/tools/git-cliff-2.14.2/bin/git-cliff

# Minimum line coverage of the code that runs natively (`make coverage`).
# The browser-only code (Leptos views and the browser API wrappers in src/ui/)
# is left out of the figure; raise the minimum when coverage grows.
COVERAGE_MIN := 0
COVERAGE_SKIP := src/ui/|src/main\.rs|tests/

VERSION := $(shell awk -F'"' '/^version/ { print $$2; exit }' Cargo.toml)
# Release archives are reproducible: same sources, same bytes.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
TAR := tar --sort=name --mtime=@$(SOURCE_DATE_EPOCH) --owner=0 --group=0 --numeric-owner
REL := target/release-files
# Commit subjects (Conventional Commits) and the base `commit-check` compares with.
COMMIT_RE := ^(feat|fix|perf|refactor|revert|docs|test|build|ci|style|chore)(\([a-z0-9._-]+\))?!?: .+
BASE ?= origin/main

BIN := target/release/emb3d-wb
# `make install`: the program, its icon and its menu entry (emb3d-wb.desktop).
PREFIX ?= $(HOME)/.local

help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: $(BINDGEN) $(WASM_OPT) ## Release build of the PWA → dist/
	cargo build --release --locked --target wasm32-unknown-unknown
	rm -rf dist
	mkdir -p dist
	$(BINDGEN) --target web --no-typescript --out-dir dist $(WASM)
	$(WASM_OPT) $(WASM_OPT_FLAGS) -o dist/emb3d-wb_bg.wasm dist/emb3d-wb_bg.wasm
	tar cf - $(FILES) data | tar xf - -C dist
	sed "s|@STYLE_SRI@|sha384-$$(openssl dgst -sha384 -binary style.css | openssl base64 -A)|" index.html > dist/index.html
	gzip -9nf dist/emb3d-wb_bg.wasm dist/data/stix/emb3d-stix-*.json

bin: build ## Self-contained emb3d-wb with the app embedded → target/release/emb3d-wb
	cargo build --release --locked --features pwa

serve: bin ## Serve the app on 127.0.0.1:PORT (emb3d-wb app --no-open); install it from the browser
	$(BIN) app --no-open --port $(PORT)

app: bin ## Serve the app and open it in its own window (Chromium, Chrome or Edge; CHROME=…)
	$(BIN) app --port $(PORT)

install: bin ## Install emb3d-wb and its menu entry into PREFIX (default ~/.local)
	install -Dm755 $(BIN) $(PREFIX)/bin/emb3d-wb
	install -Dm644 icon.svg $(PREFIX)/share/icons/hicolor/scalable/apps/emb3d-wb.svg
	mkdir -p $(PREFIX)/share/applications
	sed -e "s|^Exec=emb3d-wb |Exec=$(PREFIX)/bin/emb3d-wb |" \
		-e "s|^Icon=emb3d-wb$$|Icon=$(PREFIX)/share/icons/hicolor/scalable/apps/emb3d-wb.svg|" \
		emb3d-wb.desktop > $(PREFIX)/share/applications/emb3d-wb.desktop

uninstall: ## Remove what make install put into PREFIX
	rm -f $(PREFIX)/bin/emb3d-wb $(PREFIX)/share/icons/hicolor/scalable/apps/emb3d-wb.svg \
		$(PREFIX)/share/applications/emb3d-wb.desktop

tools: $(BINDGEN) $(WASM_OPT) $(AUDIT) $(DENY) $(CARGO_LLVM_COV) $(CYCLONEDX) $(ABOUT) $(CLIFF) ## Pinned tools, into target/tools (not system-wide)

$(BINDGEN):
	cargo install --locked --root $(@D)/.. wasm-bindgen-cli@$(BINDGEN_VERSION)

$(WASM_OPT):
	cargo install --locked --root $(@D)/.. wasm-opt@$(WASM_OPT_VERSION)

# target/tools/<crate>-<version>/bin/<crate>
$(AUDIT) $(DENY) $(CARGO_LLVM_COV) $(CYCLONEDX) $(ABOUT) $(CLIFF):
	cargo install --locked --root $(@D)/.. $$(basename $(@D:/bin=)| sed 's/-\([0-9][^-]*\)$$/@\1/')

test: ## Unit tests (tests/unit) and command-line tests (tests/cli.rs)
	cargo test --locked

lint: ## rustfmt + clippy, warnings are errors
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo clippy --target wasm32-unknown-unknown -- -D warnings

coverage: $(CARGO_LLVM_COV) ## Tests with line coverage (needs the llvm-tools-preview component); fails under COVERAGE_MIN
	$(CARGO_LLVM_COV) llvm-cov --locked --ignore-filename-regex '$(COVERAGE_SKIP)' \
		--fail-under-lines $(COVERAGE_MIN) --summary-only

security: $(AUDIT) $(DENY) ## Known vulnerabilities (RustSec), licences and sources of every dependency
	$(AUDIT) audit
	$(DENY) deny check licenses bans sources

sbom: $(CYCLONEDX) ## CycloneDX SBOM of the program and the app → target/sbom/emb3d-wb.cdx.json
	$(CYCLONEDX) cyclonedx --format json --target all --override-filename emb3d-wb.cdx
	mkdir -p target/sbom
	mv emb3d-wb.cdx.json target/sbom/

package: bin sbom $(ABOUT) ## Release files of VERSION → target/release-files (archives, SBOM, notices, SHA256SUMS)
	rm -rf $(REL)
	mkdir -p $(REL)/emb3d-wb-$(VERSION)
	$(ABOUT) about generate --locked -o $(REL)/THIRD-PARTY-LICENSES.txt about.hbs
	cp $(BIN) LICENSE README.md CHANGELOG.md SECURITY.md emb3d-wb.desktop icon.svg \
		$(REL)/THIRD-PARTY-LICENSES.txt $(REL)/emb3d-wb-$(VERSION)/
	$(TAR) -C $(REL) -cf - emb3d-wb-$(VERSION) | gzip -9n > $(REL)/emb3d-wb-$(VERSION)-$$(uname -m)-linux.tar.gz
	cp LICENSE $(REL)/THIRD-PARTY-LICENSES.txt dist/
	$(TAR) -C dist --transform 's,^\.,emb3d-wb-pwa-$(VERSION),' -cf - . | gzip -9n > $(REL)/emb3d-wb-pwa-$(VERSION).tar.gz
	rm dist/LICENSE dist/THIRD-PARTY-LICENSES.txt
	rm -r $(REL)/emb3d-wb-$(VERSION)
	cp target/sbom/emb3d-wb.cdx.json $(REL)/emb3d-wb-$(VERSION).cdx.json
	awk '/^## \[/ { f = index($$0, "[$(VERSION)]") } f' CHANGELOG.md > $(REL)/NOTES.md
	cd $(REL) && sha256sum *.tar.gz *.cdx.json THIRD-PARTY-LICENSES.txt > SHA256SUMS

commit-check: ## Commits in BASE..HEAD are Conventional Commits and signed off (BASE=origin/main)
	@bad=0; for c in $$(git rev-list --no-merges $(BASE)..HEAD); do \
		subject=$$(git log -1 --format=%s $$c); \
		echo "$$subject" | grep -Eq '$(COMMIT_RE)' \
			|| { echo "$$c: not a Conventional Commit: $$subject"; bad=1; }; \
		git log -1 --format=%B $$c | grep -q '^Signed-off-by: ' \
			|| { echo "$$c: no Signed-off-by line (git commit -s): $$subject"; bad=1; }; \
	done; \
	[ $$bad = 0 ] && echo "Commits since $(BASE) are fine."; exit $$bad

release: $(CLIFF) ## From the commits since the last tag: version, CHANGELOG.md, release commit and tag
	@test -z "$$(git status --porcelain)" || { echo 'Commit or stash your changes first.'; exit 1; }
	@next=$$($(CLIFF) --bumped-version 2>/dev/null); \
	if [ "$$next" = "$$(git describe --tags --abbrev=0 2>/dev/null)" ]; then \
		echo "No feat or fix commits since $$next: nothing to release."; exit 1; fi; \
	sed -i "0,/^version *=/s/^version *= *\"[^\"]*\"/version      = \"$${next#v}\"/" Cargo.toml; \
	cargo update --workspace --offline --quiet; \
	$(CLIFF) --tag "$$next" --output CHANGELOG.md 2>/dev/null; \
	git commit -q -s -m "chore(release): $$next" Cargo.toml Cargo.lock CHANGELOG.md; \
	git tag -a "$$next" -m "emb3d-wb $${next#v}"; \
	echo "Released $$next locally. Publish it with: git push origin HEAD $$next, then run the release workflow."

release-check: ## Check that TAG (vX.Y.Z) is SemVer and matches Cargo.toml and CHANGELOG.md
	@echo '$(TAG)' | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$$' \
		|| { echo 'TAG=$(TAG) is not vMAJOR.MINOR.PATCH (SemVer)'; exit 1; }
	@test '$(TAG)' = 'v$(VERSION)' || { echo 'TAG=$(TAG) but Cargo.toml has $(VERSION)'; exit 1; }
	@grep -q '^## \[$(VERSION)\]' CHANGELOG.md || { echo 'CHANGELOG.md has no "## [$(VERSION)]" section'; exit 1; }
	@echo 'TAG=$(TAG): version $(VERSION) is ready to release'
