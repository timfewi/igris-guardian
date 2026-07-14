{
  description = "Igris Guardian — a prompt-injection firewall";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "igris-guardian";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo
            rustc
            clippy
            rust-analyzer
          ];
        };
      }
    ) // {
      nixosModules.default = { config, lib, pkgs, ... }:
        with lib;
        let
          cfg = config.services.igris-guardian;
          pkg = self.packages.${pkgs.system}.default;
        in
        {
          options.services.igris-guardian = {
            enable = mkEnableOption "Igris Guardian prompt-injection firewall";

            configFile = mkOption {
              type = types.path;
              description = "Path to igris config TOML file";
              example = "/etc/igris/config.toml";
            };

            environmentFile = mkOption {
              type = types.path;
              description = "Path to environment file with IGRIS_STAGE2_KEY and optionally IGRIS_LISTEN/IGRIS_UPSTREAM/IGRIS_AUTH_TOKEN";
              example = "/run/secrets/igris.env";
            };
          };

          config = mkIf cfg.enable {
            systemd.services.igris-guardian = {
              description = "Igris Guardian — prompt-injection firewall";
              wantedBy = [ "multi-user.target" ];
              after = [ "network-online.target" ];
              wants = [ "network-online.target" ];

              serviceConfig = {
                Type = "simple";
                ExecStart = "${pkg}/bin/igris serve --config ${cfg.configFile}";
                Restart = "always";
                RestartSec = 5;

                # Hardening
                DynamicUser = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                PrivateTmp = true;
                NoNewPrivileges = true;
                CapabilityBoundingSet = "";
                RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
                SystemCallFilter = [ "@system-service" ];
                SystemCallErrorNumber = "EPERM";

                # Logging
                LogsDirectory = "igris";
                StandardOutput = "journal";
                StandardError = "journal";
                SyslogIdentifier = "igris-guardian";

                # Environment
                EnvironmentFile = cfg.environmentFile;
              };
            };
          };
        };
    };
}
