{
  config_exporters = { optionalAttrs, ... }:
    [
      (config: {
        instance = optionalAttrs (config.deployment.targetEnv == "instance")
          config.deployment.instance;
      })
    ];
  options = [ ./instance.nix ];
  resources = { evalResources, zipAttrs, resourcesByType, ... }: { };
}
