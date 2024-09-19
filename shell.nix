{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "shell-rust";
  nativeBuildInputs = with pkgs; [
    pkg-config
  ];
  buildInputs = with pkgs; [
    openssl
  ];
  LD_LIBRARY_PATH = "${pkgs.openssl.out}/lib";
}
