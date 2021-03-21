{ config, lib, ... }:

with lib;
let cfg = config.deployment.vultr;
in
{
  options = {

    deployment.vultr.apiKey = mkOption {
      default = "";
      example =
        "8b2f4e96af3997853bfd4cd8998958eab871d9614e35d63fab45a5ddf981c4da";
      type = types.str;
      description = ''
        The API key. We're checking the environment for
        <envar>VULTR_API_KEY</envar> first and if that is
        not set we try this api key.
      '';
    };

    deployment.vultr.region = mkOption {
      default = "";
      example = "nrt";
      type = types.str;
      description = ''
        The region. See https://status.digitalocean.com/ for a list
        of regions.
      '';
    };

    deployment.vultr.plan = mkOption {
      example = "vc2-1c-1gb";
      type = types.str;
      description = ''
        The plan identifier between <literal>512mb</literal> and <literal>64gb</literal>.
        The supported plan IDs for a region can be queried via API:
        https://developers.digitalocean.com/documentation/v2/#list-all-plans
      '';
    };

    deployment.instance.enableIpv6 = mkOption {
      default = false;
      type = types.bool;
      description = ''
        Whether to enable IPv6 support on the instance.
      '';
    };
  };

  config = mkIf (config.deployment.targetEnv == "vultr") {
    nixpkgs.system = mkOverride 900 "x86_64-linux";
    services.openssh.enable = true;
  };
}
