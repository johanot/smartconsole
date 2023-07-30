{
  description = "smartconsole";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.05";
    crane.url = "github:ipetkov/crane";
    crane.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, crane }:
  let
    pname = "smartconsole";
    version = "0.1.0";
    system = "x86_64-linux";
    crane-overlay = final: prev: {
      # crane's lib is not exposed as an overlay in its flake (should be added
      # upstream ideally) so this interface might be brittle, but avoids
      # accidentally passing a detached nixpkgs from its flake (or its follows)
      # on to consumers.
      craneLib = crane.mkLib prev;
    };
    pkgs = import nixpkgs {
      inherit system;
      overlays = [ self.overlays.default crane-overlay ];
    };
    lib = nixpkgs.lib;
    buildInputs = with pkgs; [
      binutils
      linux-pam
      zbar.dev
    ];

    outputPackages = {
      "${pname}-cli" = {
        buildInputs = [
          "zbar"
        ];
        cargoExtraArgs = "-p smccli";
      };
      "${pname}-libpam" = {
        buildInputs = [
          "linux-pam"
        ];
        cargoExtraArgs = "-p smartconsole";
      };
    };
  in {
    packages.${system} = lib.mapAttrs (n: _: pkgs.${n}) outputPackages;
    defaultPackage.${system} = self.packages.${system}."${pname}-cli";

    overlays.default = final: prev:
    let
      cratePackage = name: opts:
        (final.craneLib.buildPackage {
          pname = name;
          inherit version;
          src = with final; lib.cleanSourceWith {
            src = ./.;
            filter = path: type: true;
          };
          #cargoVendorDir = final.craneLib.vendorCargoDeps { cargoLock = ./Cargo.lock; };
          nativeBuildInputs = with final; [
            pkg-config
          ];
          buildInputs = map (p: final.${p}) opts.buildInputs;
          inherit (opts) cargoExtraArgs;
        });
    in
      lib.mapAttrs cratePackage outputPackages;

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
