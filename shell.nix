{ pkgs ? import (builtins.fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-24.05.tar.gz") {} }:
  pkgs.mkShell {
    nativeBuildInputs = [
      pkgs.openjdk8
      pkgs.ant
      pkgs.python3
    ];
    hardeningDisable = ["all"];
  }
