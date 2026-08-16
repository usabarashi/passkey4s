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
        # The build output isn't byte-identical across platforms (different
        # Coursier-resolved native bits, JVM, etc.), so outputHash is keyed
        # per system. Each entry was obtained by setting a dummy hash, running
        # `nix build`, and copying the "got:" hash from the mismatch error,
        # then independently confirmed deterministic via `nix build --rebuild`
        # (aarch64-darwin locally; x86_64-linux via this repo's own CI run).
        # Add a new system by doing the same and appending it here — the
        # throw below is deliberate so an unverified system fails loudly
        # instead of silently trusting an unrelated hash.
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
          outputHash =
            {
              "aarch64-darwin" = "sha256-sGAGS8AYiT6S7mx+lvT43ajcX7uSTa+EYtKMuzqLg5A=";
              "x86_64-linux" = "sha256-eiI+hJDxfXEY9MMCY9EZv2EE2UEewA+6XXjikCrhl2Y=";
            }
            .${system} or (throw ''
              packages.default has no verified-reproducible outputHash for system "${system}" yet.
              Set outputHash to a dummy value, run `nix build`, copy the "got:" hash from the
              mismatch error into flake.nix's outputHash attrset for this system, then confirm
              it's actually deterministic with `nix build --rebuild` before trusting it.
            '');

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
