{
  description = "smartconsole";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.11";
  };

  outputs = { self, nixpkgs }:
  let
    pname = "smartconsole";
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      overlays = [ self.overlay ];
    };
    buildInputs = with pkgs; [
      binutils
      linux-pam
      zbar.dev
    ];
  in {
    packages.${system}.${pname} = pkgs.smartconsole;
    defaultPackage.${system} = pkgs.smartconsole;

    overlay = final: prev: {
      "${pname}" = (import ./Cargo.nix {
        pkgs = final;
      }).rootCrate.build;
    };

    devShell.${system} = with pkgs; mkShell {
      buildInputs = [
        cargo
        openssl.dev
        pkgconfig
        rustc
        rustfmt
      ] ++ buildInputs;
    };
  };
}
