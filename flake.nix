{
  description = "Pressured - Memory pressure monitor for Kubernetes";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        devShells.default = pkgs.mkShell {
          # Disable fortify for debugging with gdb/valgrind
          hardeningDisable = [ "fortify" ];
          buildInputs = with pkgs; [
            # C toolchain
            gcc
            cmake
            gnumake
            pkg-config

            # C libraries
            curl
            openssl
            json_c
            lua5_4

            # Development tools
            gdb
            clang-tools  # clang-format, clang-tidy
            bear         # compile_commands.json generator
            cppcheck     # static analysis

            # Kubernetes tools
            kubernetes-helm
            kubectl

            # Misc
            python311
            jq
          ];
          shellHook = ''
            echo "Pressured Development Environment"
            echo ""
            echo "  Build:   make build"
            echo "  Test:    make test"
            echo "  Help:    make help"
          '';
        };
      });
}
