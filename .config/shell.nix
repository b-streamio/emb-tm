# SPDX-License-Identifier: GPL-2.0-only
#
# The emb-tm build environment on a Nix host (the CI builder, as lp-boot):
# the tools of .config/Containerfile from a pinned nixpkgs (bstream-iac's
# pin), Rust from rustup at the version of the Containerfile, and the pinned
# tools of the Makefile in T, built once and kept between jobs.
#
#   nix-shell .config/shell.nix --run 'make check'
{ pkgs ? import (fetchTarball {
    url = "https://releases.nixos.org/nixpkgs/nixpkgs-26.11pre1088030.8edc0c72e3a3/nixexprs.tar.zst";
    sha256 = "sha256-6BIvCXtdLW4HQwsOGkgH444aB3vCbHypE9TA78ireh8=";
  }) {} }:
let
    # GCC 14, as Debian trixie (the Containerfile): binaryen 116 (wasm-opt)
    # does not link when built with a newer one.
    stdenv = pkgs.gcc14Stdenv;
    packages = with pkgs; [
        rustup gnumake gitMinimal curl cacert python3 openssl pkg-config zlib
        file gnutar gzip util-linux appimage-run trivy
    ];
    # What the programs in T and the toolchains of rustup link against: a
    # GC root keeps it while T exists.
    roots = pkgs.writeText "emb-tm-roots" (toString ([ stdenv.cc ] ++ packages));
in
(pkgs.mkShell.override { inherit stdenv; }) {
    inherit packages;
    shellHook = ''
        # (nix-shell points the CAs to nothing: the host's, with the site CA)
        for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt \
                 ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt; do
            [ -r "$f" ] && break
        done
        export SSL_CERT_FILE=$f NIX_SSL_CERT_FILE=$f CURL_CA_BUNDLE=$f GIT_SSL_CAINFO=$f
        export RUSTUP_TOOLCHAIN=$(sed -n 's/^FROM .*rust:\([0-9.]*\)-.*/\1/p' ${./Containerfile})
        export T=''${T:-''${XDG_CACHE_HOME:-$HOME/.cache}/emb-tm/tools}
        # The static program links with Rust's own lld, not Nix's gcc.
        arch=$(uname -m)
        export CARGO_TARGET_''${arch^^}_UNKNOWN_LINUX_MUSL_LINKER=rust-lld
        # appimagetool is an AppImage: a NixOS host runs it in an FHS.
        export APPIMAGE_RUN=appimage-run
        mkdir -p "$T"
        nix-store --realise --add-root "$T/.nix-roots" ${roots} > /dev/null
        # (one job at a time installs; the others wait, then find it there)
        flock "$T/.lock" sh -ec '
            rustup -q toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal \
                -c rustfmt,clippy,llvm-tools-preview -t wasm32-unknown-unknown,'"$arch"'-unknown-linux-musl
            make -s -C ${toString ./..} tools' >&2 || exit 1
    '';
}
