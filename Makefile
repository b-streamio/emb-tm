# SPDX-License-Identifier: GPL-2.0-only
.DEFAULT_GOAL := help
.PHONY: help build bin serve app install uninstall tools data test lint coverage security sbom package \
	commit-check release release-check

# Port of `make serve` and `make app`. An installed app loads from it, so
# pick one no other local server uses.
PORT := 8000

# MITRE's EMB3D releases listed in data/stix/index.json. Never shipped: the
# app and `emb-tm fetch` download them from emb3d.mitre.org; the tests need them.
STIX := $(addprefix data/stix/,$(shell sed -n 's/.*"file": "\(.*\)".*/\1/p' data/stix/index.json))

# What the app fetches besides the wasm and its JavaScript glue: the shell in
# web/ (copied to the top of dist/), data/ and these files. Keep in step with
# SHELL in web/sw.js (the offline cache).
WEB := sw.js style.css manifest.webmanifest icon.svg icon-192.png icon-512.png
FILES := library/components.json examples/index.json \
	examples/system/surveillance-alarm-system.project.json \
	examples/yocto-scan/alarm-hub-image.project.json

WASM := target/wasm32-unknown-unknown/release/emb-tm.wasm
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
# Conventional Commits → next version and CHANGELOG.md (.config/cliff.toml).
CLIFF := target/tools/git-cliff-2.14.2/bin/git-cliff
GIT_CLIFF := $(CLIFF) --config .config/cliff.toml

# Minimum line coverage of the code that runs natively (`make coverage`).
# The browser-only code (Leptos views and the browser API wrappers in src/ui/)
# is left out of the figure; raise the minimum when coverage grows.
COVERAGE_MIN := 90
COVERAGE_SKIP := src/ui/|src/main\.rs|tests/

VERSION := $(shell awk -F'"' '/^version/ { print $$2; exit }' Cargo.toml)
# Release archives are reproducible: same sources, same bytes.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
export SOURCE_DATE_EPOCH
TAR := tar --sort=name --mtime=@$(SOURCE_DATE_EPOCH) --owner=0 --group=0 --numeric-owner
REL := target/release-files
# Commit subjects (Conventional Commits) and the base `commit-check` compares with.
COMMIT_RE := ^(feat|fix|perf|refactor|revert|docs|test|build|ci|style|chore)(\([a-z0-9._-]+\))?!?: .+
BASE ?= origin/main

BIN := target/release/emb-tm
# `make install`: the program, its icon and its menu entry (web/emb-tm.desktop).
PREFIX ?= $(HOME)/.local

help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: $(BINDGEN) $(WASM_OPT) ## Release build of the PWA → dist/
	cargo build --release --locked --target wasm32-unknown-unknown
	rm -rf dist
	mkdir -p dist
	$(BINDGEN) --target web --no-typescript --out-dir dist $(WASM)
	$(WASM_OPT) $(WASM_OPT_FLAGS) -o dist/emb-tm_bg.wasm dist/emb-tm_bg.wasm
	cp $(addprefix web/,$(WEB)) dist/
	tar cf - $(FILES) data/stix/index.json data/stix/README.md | tar xf - -C dist
	sed "s|@STYLE_SRI@|sha384-$$(openssl dgst -sha384 -binary web/style.css | openssl base64 -A)|" web/index.html > dist/index.html
	gzip -9nf dist/emb-tm_bg.wasm

bin: build ## Self-contained emb-tm with the app embedded → target/release/emb-tm
	cargo build --release --locked --features pwa

serve: bin ## Serve the app on 127.0.0.1:PORT (emb-tm app --no-open); install it from the browser
	$(BIN) app --no-open --port $(PORT)

app: bin ## Serve the app and open it in its own window (Chromium, Chrome or Edge; CHROME=…)
	$(BIN) app --port $(PORT)

install: bin ## Install emb-tm and its menu entry into PREFIX (default ~/.local)
	@# A running app server keeps serving the old version; stop it so the next launch is new.
	@pkill -f '^$(PREFIX)/bin/emb-tm app' && echo 'Stopped the running emb-tm server.' || true
	install -Dm755 $(BIN) $(PREFIX)/bin/emb-tm
	install -Dm644 web/icon.svg $(PREFIX)/share/icons/hicolor/scalable/apps/emb-tm.svg
	mkdir -p $(PREFIX)/share/applications
	sed -e "s|^Exec=emb-tm |Exec=$(PREFIX)/bin/emb-tm |" \
		-e "s|^Icon=emb-tm$$|Icon=$(PREFIX)/share/icons/hicolor/scalable/apps/emb-tm.svg|" \
		web/emb-tm.desktop > $(PREFIX)/share/applications/emb-tm.desktop

uninstall: ## Remove what make install put into PREFIX
	rm -f $(PREFIX)/bin/emb-tm $(PREFIX)/share/icons/hicolor/scalable/apps/emb-tm.svg \
		$(PREFIX)/share/applications/emb-tm.desktop

tools: $(BINDGEN) $(WASM_OPT) $(AUDIT) $(DENY) $(CARGO_LLVM_COV) $(CYCLONEDX) $(ABOUT) $(CLIFF) ## Pinned tools, into target/tools (not system-wide)

$(BINDGEN):
	cargo install --locked --root $(@D)/.. wasm-bindgen-cli@$(BINDGEN_VERSION)

$(WASM_OPT):
	cargo install --locked --root $(@D)/.. wasm-opt@$(WASM_OPT_VERSION)

# target/tools/<crate>-<version>/bin/<crate>
$(AUDIT) $(DENY) $(CARGO_LLVM_COV) $(CYCLONEDX) $(CLIFF):
	cargo install --locked --root $(@D)/.. $$(basename $(@D:/bin=)| sed 's/-\([0-9][^-]*\)$$/@\1/')

# cargo-about builds its program only with the `cli` feature.
$(ABOUT):
	cargo install --locked --features cli --root $(@D)/.. cargo-about@0.9.2

data: $(STIX) ## Download the EMB3D releases from emb3d.mitre.org into data/stix (checksums verified)

$(STIX) &: data/stix/index.json
	cargo run --quiet --locked -- fetch

test: data ## Unit tests (tests/unit) and command-line tests (tests/cli.rs)
	cargo test --locked

lint: ## rustfmt + clippy, warnings are errors
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo clippy --target wasm32-unknown-unknown -- -D warnings

coverage: data $(CARGO_LLVM_COV) ## Tests with line coverage (needs the llvm-tools-preview component); fails under COVERAGE_MIN
	$(CARGO_LLVM_COV) llvm-cov --locked --ignore-filename-regex '$(COVERAGE_SKIP)' \
		--fail-under-lines $(COVERAGE_MIN) --summary-only

security: $(AUDIT) $(DENY) ## Known vulnerabilities (RustSec), licences and sources of every dependency
	$(AUDIT) audit
	$(DENY) deny --config .config/deny.toml check licenses bans sources

sbom: $(CYCLONEDX) ## CycloneDX SBOM of the program and the app → target/sbom/emb-tm.cdx.json
	$(CYCLONEDX) cyclonedx --format json --spec-version 1.5 --target all --override-filename emb-tm.cdx
	mkdir -p target/sbom
	mv emb-tm.cdx.json target/sbom/

package: bin sbom $(ABOUT) ## Release files of VERSION → target/release-files (archives, SBOM, notices, SHA256SUMS)
	rm -rf $(REL)
	mkdir -p $(REL)/emb-tm-$(VERSION)
	$(ABOUT) about generate --locked -c .config/about.toml -o $(REL)/THIRD-PARTY-LICENSES.txt .config/about.hbs
	cp $(BIN) LICENSE README.md CHANGELOG.md .github/SECURITY.md web/emb-tm.desktop web/icon.svg \
		$(REL)/THIRD-PARTY-LICENSES.txt $(REL)/emb-tm-$(VERSION)/
	$(TAR) -C $(REL) -cf - emb-tm-$(VERSION) | gzip -9n > $(REL)/emb-tm-$(VERSION)-$$(uname -m)-linux.tar.gz
	cp LICENSE $(REL)/THIRD-PARTY-LICENSES.txt dist/
	$(TAR) -C dist --transform 's,^\.,emb-tm-pwa-$(VERSION),' -cf - . | gzip -9n > $(REL)/emb-tm-pwa-$(VERSION).tar.gz
	rm dist/LICENSE dist/THIRD-PARTY-LICENSES.txt
	rm -r $(REL)/emb-tm-$(VERSION)
	cp target/sbom/emb-tm.cdx.json $(REL)/emb-tm-$(VERSION).cdx.json
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
	@next=$$($(GIT_CLIFF) --bumped-version 2>/dev/null); \
	if [ "$$next" = "$$(git describe --tags --abbrev=0 2>/dev/null)" ]; then \
		echo "No commit for the changelog since $$next: nothing to release."; exit 1; fi; \
	sed -i "0,/^version *=/s/^version *= *\"[^\"]*\"/version      = \"$${next#v}\"/" Cargo.toml; \
	cargo update --workspace --offline --quiet; \
	$(GIT_CLIFF) --tag "$$next" --output CHANGELOG.md 2>/dev/null; \
	git commit -q -s -m "chore(release): $$next" Cargo.toml Cargo.lock CHANGELOG.md; \
	git tag -a "$$next" -m "emb-tm $${next#v}"; \
	echo "Released $$next locally. Publish it with: git push origin HEAD $$next, then run the release workflow."

release-check: ## Check that TAG (vX.Y.Z) is SemVer and matches Cargo.toml and CHANGELOG.md
	@echo '$(TAG)' | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$$' \
		|| { echo 'TAG=$(TAG) is not vMAJOR.MINOR.PATCH (SemVer)'; exit 1; }
	@test '$(TAG)' = 'v$(VERSION)' || { echo 'TAG=$(TAG) but Cargo.toml has $(VERSION)'; exit 1; }
	@grep -q '^## \[$(VERSION)\]' CHANGELOG.md || { echo 'CHANGELOG.md has no "## [$(VERSION)]" section'; exit 1; }
	@echo 'TAG=$(TAG): version $(VERSION) is ready to release'
