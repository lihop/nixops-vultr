{
  network.description = "NixOps Vultr Test";
  resources.sshKeyPairs.ssh-key = { };

  machine = {
    deployment.targetEnv = "vultr";
    deployment.vultr = {
      region = "nrt";
      plan = "vc2-1c-1gb";
    };
  };
}
