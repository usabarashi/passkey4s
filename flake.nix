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
      }
    );
}
