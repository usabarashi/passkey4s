{
  description = "passkey4s - WebAuthn/passkey sample on Cloudflare Workers with Scala.js + Durable Objects SQLite";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.mill
            pkgs.jdk21
            pkgs.nodejs_22
            pkgs.wrangler
            pkgs.coursier
          ];

          JAVA_HOME = pkgs.jdk21.home;
        };

        # Fixed-output derivation: network access during the build is only
        # permitted by Nix because outputHash pins what the result must be,
        # so a non-reproducible Coursier/Mill/Scala.js output fails the build
        # outright rather than silently succeeding. See .mill-jvm-version for
        # why Mill's own bootstrap doesn't need a separate JDK fetch here.
        #
        # outputHash below was computed and verified deterministic (via
        # `nix build --rebuild`) on aarch64-darwin only. It has not been
        # confirmed on other systems `eachDefaultSystem` covers (e.g. Linux
        # CI runners) — a mismatch there doesn't necessarily mean the build
        # is broken, just that this hash needs a per-system value. CI treats
        # this derivation as informational for exactly that reason.
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "passkey4s";
          version = "0.1.0";
          src = self;

          nativeBuildInputs = [
            pkgs.mill
            pkgs.nodejs_22
          ];

          outputHashMode = "recursive";
          outputHashAlgo = "sha256";
          outputHash = "sha256-sGAGS8AYiT6S7mx+lvT43ajcX7uSTa+EYtKMuzqLg5A=";

          buildPhase = ''
            export HOME=$TMPDIR
            export COURSIER_CACHE=$TMPDIR/coursier-cache
            export _JAVA_OPTIONS="-Duser.home=$TMPDIR"
            mill worker.assets
            mill worker.fullLinkJS
          '';

          installPhase = ''
            mkdir -p $out/assets
            cp out/worker/assets.dest/index.html $out/assets/
            cp out/worker/assets.dest/main.js $out/assets/
            cp out/worker/fullLinkJS.dest/main.js $out/worker.js
          '';
        };
      }
    );
}
