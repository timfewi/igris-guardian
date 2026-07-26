{
  description = "Igris Guardian — a prompt-injection firewall";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        module = nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [
            self.nixosModules.default
            {
              services.igris-guardian = {
                enable = true;
                configFile = builtins.toFile "igris-config.toml" "";
                environmentFile = builtins.toFile "igris.env" "";
              };
            }
          ];
        };
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "igris-guardian";
          # Single source of truth: CI bumps the patch version in Cargo.toml on
          # every merge to main, and a literal here would silently drift.
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
        };

        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.cargo
            pkgs.rustc
            pkgs.rustfmt
            pkgs.clippy
            pkgs.rust-analyzer
            pkgs.just
            pkgs.direnv
          ];

          CARGO_TERM_COLOR = "always";
          RUST_BACKTRACE = "1";

          shellHook = ''
            if [ -t 2 ]; then
              printf '\033[38;5;160m%s\n\033[0m' \
                '   ⢰⡆' \
                ' ⣀⡤⠸⠇⢤⣀' \
                '⡞⠁⢀⢼⡧⡀⠈⢹' \
                '⡇ ⣟⢯⡵⢻ ⢸' \
                '⢇ ⠿⣏⢹⠿ ⡸' \
                ' ⠑⢄⠹⠟⡠⠊' \
                '   ⢹⡆' \
                '   ⠈⠁' >&2
              printf '\033[1m  I G R I S\033[0m  \033[2mguardian development shell\033[0m\n\n' >&2
            fi
          '';
        };

        checks.module = pkgs.runCommand "igris-module-${system}" {
          execStart = module.config.systemd.services.igris-guardian.serviceConfig.ExecStart;
        } "touch $out";
      }
    )
    // {
      nixosModules.default =
        {
          config,
          lib,
          pkgs,
          ...
        }:
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
              description = ''
                Path to an environment file holding the stage-2 API key, and
                optionally the endpoint overrides. The variable names are the ones
                config.rs actually reads:

                  IGRIS_STAGE2_KEY       (or whatever stage2.api_key_env names)
                  IGRIS_STAGE2_BASE_URL
                  IGRIS_STAGE2_MODEL
                  IGRIS_SERVE_LISTEN
                  IGRIS_SERVE_UPSTREAM
                  IGRIS_AUDIT_LOG

                Keep this out of the Nix store — it holds a credential. Use agenix
                or another runtime secret path such as /run/agenix/igris-env.
              '';
              example = "/run/agenix/igris.env";
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
                RestrictAddressFamilies = [
                  "AF_INET"
                  "AF_INET6"
                ];
                SystemCallFilter = [ "@system-service" ];
                SystemCallErrorNumber = "EPERM";

                # Audit log lives here. Required: DynamicUser + ProtectHome means
                # the default ~/.local/state path is unwritable, and audit writes
                # are best-effort, so without this the trail silently disappears.
                # Point audit_log at /var/lib/igris/audit.jsonl in the config file.
                StateDirectory = "igris";
                StateDirectoryMode = "0750";

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
