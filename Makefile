# SPDX-License-Identifier: GPL-2.0-only
#
# The build: cargo → wasm-bindgen → wasm-opt → dist/, embedded into one
# static emb-tm. The pinned tools install themselves into target/tools on
# first use, never system-wide.
.DEFAULT_GOAL := help
.PHONY: help build app install uninstall check security package release publish image tools

# `make app`: an installed app loads from this port, so keep it.
PORT := 8000
PREFIX ?= $(HOME)/.local
VERSION = $(shell awk -F'"' '/^version/ { print $$2; exit }' Cargo.toml)
# The program is static (musl) where that target is installed, as in the
# build image: it then runs on any Linux of its architecture. Elsewhere it
# builds for the host, and `make package` runs in the build image.
MUSL := $(shell uname -m)-unknown-linux-musl
TARGET := $(if $(wildcard $(shell rustc --print target-libdir --target $(MUSL) 2>/dev/null)/libstd-*),$(MUSL),$(shell rustc -vV | sed -n 's/^host: //p'))
BIN := target/$(TARGET)/release/emb-tm

# What the app fetches besides the wasm: keep in step with SHELL in web/sw.js.
WEB := sw.js style.css manifest.webmanifest icon.svg icon-192.png icon-512.png
FILES := library/components.json data/stix/index.json data/stix/README.md examples/index.json \
	examples/system/surveillance-alarm-system.project.json \
	examples/yocto-scan/alarm-hub-image.project.json
# MITRE's EMB3D releases: never shipped, downloaded for the tests.
STIX := $(addprefix data/stix/,$(shell sed -n 's/.*"file": "\(.*\)".*/\1/p' data/stix/index.json))

# Pinned tools, $(T)/<crate>-<version>/bin/<program>; wasm-bindgen must be
# the version in Cargo.lock. The build image has them in /opt/emb-tm/tools.
T ?= target/tools
BINDGEN := $(T)/wasm-bindgen-cli-$(shell awk '/^name = "wasm-bindgen"$$/ { getline; gsub(/"/, "", $$3); print $$3 }' Cargo.lock)/bin/wasm-bindgen
WASM_OPT := $(T)/wasm-opt-0.116.1/bin/wasm-opt
LLVM_COV := $(T)/cargo-llvm-cov-0.9.1/bin/cargo-llvm-cov
AUDIT := $(T)/cargo-audit-0.22.2/bin/cargo-audit
DENY := $(T)/cargo-deny-0.20.2/bin/cargo-deny
CYCLONEDX := $(T)/cargo-cyclonedx-0.5.9/bin/cargo-cyclonedx
ABOUT := $(T)/cargo-about-0.9.2/bin/cargo-about
CLIFF := $(T)/git-cliff-2.14.2/bin/git-cliff
# The AppImage: appimagetool and the runtime it embeds (x86_64), checksummed.
APPIMAGETOOL := $(T)/appimagetool-1.9.1
# (a NixOS host runs the AppImage through appimage-run: .config/shell.nix)
APPIMAGE_RUN ?=
APPIMAGETOOL_URL := https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage
APPIMAGETOOL_SHA := ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0
RUNTIME := $(T)/appimage-runtime-20251108
RUNTIME_URL := https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64
RUNTIME_SHA := 2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d

# Line coverage of the native code (src/ui runs in a browser only).
COVERAGE_MIN := 90
COMMIT_RE := ^(feat|fix|perf|refactor|revert|docs|test|build|ci|style|chore)(\([a-z0-9._-]+\))?!?: .+
SEMVER_RE := ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$$
BASE ?= origin/main
# Release archives are reproducible: same sources, same bytes.
export SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
TAR := tar --sort=name --mtime=@$(SOURCE_DATE_EPOCH) --owner=0 --group=0 --numeric-owner
REL := target/release-files
ASSETS := *.AppImage *.tar.gz *.cdx.json THIRD-PARTY-LICENSES.txt SHA256SUMS
# The build environment (.config/Containerfile), named after what it holds.
IMAGE := emb-tm-build:$(shell cat .config/Containerfile Makefile | sha256sum | cut -c1-12)
ENGINE ?= $(shell command -v podman || command -v docker)

help: ## This list
	@awk -F':.*## ' '/^[a-z]+:.*## / { printf "  \033[36m%-9s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: $(BINDGEN) $(WASM_OPT) ## The PWA (dist/) and the static program with it inside
	cargo build --release --locked --target wasm32-unknown-unknown
	rm -rf dist
	$(BINDGEN) --target web --no-typescript --out-dir dist target/wasm32-unknown-unknown/release/emb-tm.wasm
	$(WASM_OPT) -Oz --enable-bulk-memory --enable-mutable-globals --enable-nontrapping-float-to-int \
		--enable-reference-types --enable-sign-ext --enable-multivalue -o dist/emb-tm_bg.wasm dist/emb-tm_bg.wasm
	gzip -9n dist/emb-tm_bg.wasm
	cp $(addprefix web/,$(WEB)) dist/
	tar cf - $(FILES) | tar xf - -C dist
	sed "s|@STYLE_SRI@|sha384-$$(openssl dgst -sha384 -binary web/style.css | openssl base64 -A)|" web/index.html > dist/index.html
	cargo build --release --locked --features pwa --target $(TARGET)

app: build ## Run the app on 127.0.0.1:PORT in its own window (ARGS=--no-open: serve it only)
	$(BIN) app --port $(PORT) $(ARGS)

install: build ## Install emb-tm and its menu entry into PREFIX (default ~/.local)
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

check: $(STIX) $(LLVM_COV) ## Commits since BASE, rustfmt, clippy, unit and CLI tests with line coverage
	@git rev-parse -q --verify $(BASE) > /dev/null || exit 0; bad=0; \
	for c in $$(git rev-list --no-merges $(BASE)..HEAD); do \
		s=$$(git log -1 --format=%s $$c); \
		echo "$$s" | grep -Eq '$(COMMIT_RE)' || { echo "$$c: not a Conventional Commit: $$s"; bad=1; }; \
		git log -1 --format=%B $$c | grep -q '^Signed-off-by: ' || { echo "$$c: not signed off: $$s"; bad=1; }; \
	done; exit $$bad
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo clippy --target wasm32-unknown-unknown -- -D warnings
	$(LLVM_COV) llvm-cov --locked --ignore-filename-regex 'src/ui/|src/main\.rs|tests/' \
		--fail-under-lines $(COVERAGE_MIN) --summary-only

$(STIX) &: data/stix/index.json
	EMB_TM_DATA=data/stix cargo run --quiet --locked -- fetch

security: $(AUDIT) $(DENY) $(CYCLONEDX) ## RustSec advisories, licences and sources of every dependency; SBOM
	$(AUDIT) audit
	$(DENY) deny --config .config/deny.toml check licenses bans sources
	$(CYCLONEDX) cyclonedx --format json --spec-version 1.5 --target all --override-filename emb-tm.cdx
	mkdir -p target/sbom
	mv emb-tm.cdx.json target/sbom/

ifneq ($(TARGET),$(MUSL))
package: image ## Release files: AppImage, static program, PWA, SBOM, licences, SHA256SUMS
	$(ENGINE) run --rm --security-opt label=disable -v $(CURDIR):/w -w /w $(IMAGE) make package
else
package: build security $(ABOUT) $(APPIMAGETOOL) $(RUNTIME)
	rm -rf $(REL)
	mkdir -p $(REL)/emb-tm-$(VERSION)
	$(ABOUT) about generate --locked -c .config/about.toml -o $(REL)/THIRD-PARTY-LICENSES.txt .config/about.hbs
	cp $(BIN) LICENSE README.md CHANGELOG.md .github/SECURITY.md web/emb-tm.desktop web/icon.svg \
		$(REL)/THIRD-PARTY-LICENSES.txt $(REL)/emb-tm-$(VERSION)/
	$(TAR) -C $(REL) -cf - emb-tm-$(VERSION) | gzip -9n > $(REL)/emb-tm-$(VERSION)-$(shell uname -m)-linux.tar.gz
	$(TAR) --transform 's,^\(\./\)\?,emb-tm-pwa-$(VERSION)/,' -cf - -C dist . -C $(CURDIR) LICENSE \
		-C $(REL) THIRD-PARTY-LICENSES.txt | gzip -9n > $(REL)/emb-tm-pwa-$(VERSION).tar.gz
	@# The AppImage: the same static program; a double click on it opens the app.
	mkdir -p $(REL)/AppDir/usr/bin
	cp $(BIN) $(REL)/AppDir/usr/bin/
	ln -s usr/bin/emb-tm $(REL)/AppDir/AppRun
	cp web/emb-tm.desktop $(REL)/AppDir/
	cp web/icon.svg $(REL)/AppDir/emb-tm.svg
	ARCH=$(shell uname -m) APPIMAGE_EXTRACT_AND_RUN=1 $(APPIMAGE_RUN) $(APPIMAGETOOL) --no-appstream --runtime-file $(RUNTIME) \
		$(REL)/AppDir $(REL)/emb-tm-$(VERSION)-$(shell uname -m).AppImage
	cp target/sbom/emb-tm.cdx.json $(REL)/emb-tm-$(VERSION).cdx.json
	awk '/^## \[/ { f = index($$0, "[$(VERSION)]") } f' CHANGELOG.md > $(REL)/NOTES.md
	cd $(REL) && sha256sum *.AppImage *.tar.gz *.cdx.json THIRD-PARTY-LICENSES.txt > SHA256SUMS
endif

release: $(CLIFF) ## When the commits since the last tag call for it: version, CHANGELOG.md, commit, tag
	@set -e; tag=$$(git tag --points-at HEAD 'v*' | head -n 1); \
	if [ -z "$$tag" ]; then \
		test -z "$$(git status --porcelain)" || { echo 'Commit or stash your changes first.'; exit 1; }; \
		tag=$$($(CLIFF) --config .config/cliff.toml --bumped-version 2>/dev/null); \
		[ "$$tag" != "$$(git describe --tags --abbrev=0 2>/dev/null)" ] || { echo 'Nothing to release.'; exit 0; }; \
		sed -i "0,/^version *=/s/^version *= *\"[^\"]*\"/version      = \"$${tag#v}\"/" Cargo.toml; \
		cargo update --workspace --offline --quiet; \
		$(CLIFF) --config .config/cliff.toml --tag "$$tag" --output CHANGELOG.md 2>/dev/null; \
		git commit -q -s -m "chore(release): $$tag" Cargo.toml Cargo.lock CHANGELOG.md; \
		git tag -a "$$tag" -m "emb-tm $${tag#v}"; \
	fi; \
	v=$$(awk -F'"' '/^version/ { print $$2; exit }' Cargo.toml); \
	echo "$$tag" | grep -Eq '$(SEMVER_RE)' && [ "$$tag" = "v$$v" ] && grep -q "^## \[$$v\]" CHANGELOG.md \
		|| { echo "$$tag does not match Cargo.toml and CHANGELOG.md"; exit 1; }; \
	echo "$$tag is ready: git push --atomic origin HEAD $$tag"

# The release files go to the generic package registry of the forge the CI
# runs on (Gitea API: GITHUB_SERVER_URL, GITHUB_REPOSITORY, TOKEN): a tagged
# HEAD into the package emb-tm, with a release of the tag; any other build
# into emb-tm-dev as <branch>-<commit>. Files already there are kept. TOKEN
# reaches curl on its standard input, never as an argument.
publish: ## (CI) Upload the release files to the forge's packages, and the release of a tagged HEAD
	@: "$${TOKEN:?the token that writes packages}" "$${GITHUB_SERVER_URL:?}" "$${GITHUB_REPOSITORY:?}"
	@set -e; auth() { printf 'header = "Authorization: token %s"\n' "$$TOKEN"; }; \
	tag=$$(git tag --points-at HEAD 'v*' | head -n 1); pkg=emb-tm; version=$$tag; \
	[ -n "$$tag" ] || { pkg=emb-tm-dev; version=$$(echo "$${GITHUB_REF_NAME:-local}" | tr / -)-$$(git rev-parse --short=12 HEAD); }; \
	url="$${GITHUB_SERVER_URL%/}/api/packages/$${GITHUB_REPOSITORY%%/*}/generic/$$pkg/$$version"; \
	cd $(REL); for f in $(ASSETS); do \
		code=$$(auth | curl -sS -K - -o ../publish.out -w '%{http_code}' -X PUT --upload-file "$$f" "$$url/$$f"); \
		case $$code in 201) echo "published $$pkg/$$version/$$f" ;; 409) echo "already there: $$f" ;; \
			*) echo "$$f: HTTP $$code: $$(head -c 500 ../publish.out)" >&2; exit 1 ;; esac; \
	done; \
	[ -n "$$tag" ] || exit 0; \
	api="$${GITHUB_SERVER_URL%/}/api/v1/repos/$$GITHUB_REPOSITORY/releases"; \
	if auth | curl -fsS -K - -o /dev/null "$$api/tags/$$tag" 2>/dev/null; then echo "release $$tag already there"; exit 0; fi; \
	python3 -c 'import json, sys; print(json.dumps({"tag_name": sys.argv[1], "name": "emb-tm " + sys.argv[1][1:], \
		"body": open("NOTES.md").read(), "prerelease": "-" in sys.argv[1]}))' "$$tag" > release.json; \
	id=$$(auth | curl -fsS -K - -H 'Content-Type: application/json' -X POST --data-binary @release.json "$$api" \
		| python3 -c 'import json, sys; print(json.load(sys.stdin)["id"])'); \
	for f in $(ASSETS); do \
		auth | curl -fsS -K - -o /dev/null -F "attachment=@$$f" "$$api/$$id/assets?name=$$f"; echo "attached $$f"; \
	done

image: ## The build environment with every tool (.config/Containerfile), as IMAGE
	mkdir -p target/image
	tar cf - Makefile Cargo.toml Cargo.lock data/stix/index.json | tar xf - -C target/image
	$(ENGINE) build -t $(IMAGE) -f .config/Containerfile target/image

tools: $(BINDGEN) $(WASM_OPT) $(LLVM_COV) $(AUDIT) $(DENY) $(CYCLONEDX) $(ABOUT) $(CLIFF) $(APPIMAGETOOL) $(RUNTIME)

$(APPIMAGETOOL):
	curl -fsSL --proto =https --create-dirs -o $@.part $(APPIMAGETOOL_URL)
	echo '$(APPIMAGETOOL_SHA)  $@.part' | sha256sum -c --quiet
	chmod +x $@.part && mv $@.part $@

$(RUNTIME):
	curl -fsSL --proto =https --create-dirs -o $@.part $(RUNTIME_URL)
	echo '$(RUNTIME_SHA)  $@.part' | sha256sum -c --quiet
	mv $@.part $@

# target/tools/<crate>-<version>/bin/<program>; cargo-about's program needs its `cli` feature.
$(T)/%:
	cargo install --locked $(if $(findstring cargo-about,$*),--features cli) --root $(T)/$(firstword $(subst /, ,$*)) \
		$$(echo $(firstword $(subst /, ,$*)) | sed 's/-\([0-9][^-]*\)$$/@\1/')
