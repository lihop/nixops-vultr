# -*- coding: utf-8 -*-
"""
A backend for www.digitalocean.com (short as "DO").

This backend uses nixos-infect (which uses nixos LUSTRATE) to infect a
Ubuntu digital ocean instance. The setup requires two reboots, one for
the infect itself, another after we pushed the nixos image.

I hit a few subtle problems along the way:
* DO doesn't do dhcp so we have to hard-code the network configuration
* Ubuntu still uses eth0, 1 etc, not ens3 etc so we have a network
  link name change after the reboot.
* I had to modify nixos-infect to reflect the network link name changes,
  and to not reboot to avoid ssh-interruption and therefore errors.

Still to do:
* Floating IPs
* Network attached storage
"""
import os
import os.path
import time
import socket
from typing import Optional, List, Set, cast

from nixops.resources import ResourceEval, ResourceOptions, ssh_keypair
import nixops.known_hosts
from nixops.backends import MachineDefinition, MachineOptions, MachineState
from nixops.deployment import Deployment
from nixops.nix_expr import Function, RawValue
from nixops.util import attr_property
from nixops.state import RecordId
import codecs

import digitalocean  # type: ignore

infect_path: str = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "data", "nixos-infect")
)


class InstanceOptions(ResourceOptions):
    authToken: Optional[str]
    region: Optional[str]
    size: Optional[str]
    enableIpv6: Optional[bool]


class InstanceDeploymentOptions(MachineOptions):
    instance: InstanceOptions


class InstanceDefinition(MachineDefinition):
    @classmethod
    def get_type(cls) -> str:
        return "instance"

    config: InstanceDeploymentOptions

    auth_token: Optional[str]
    region: Optional[str]
    size: Optional[str]
    enable_ipv6: Optional[bool]

    def __init__(self, name: str, config: ResourceEval):
        super().__init__(name, config)

        if self.config.instance.authToken:
            self.auth_token = self.config.instance.authToken.strip()
        else:
            self.auth_token = None

        self.region = self.config.instance.region
        self.size = self.config.instance.size
        self.enable_ipv6 = self.config.instance.enableIpv6

    def show_type(self) -> str:
        return "{0} [{1}]".format(self.get_type(), self.region)


class InstanceState(MachineState[InstanceDefinition]):
    @classmethod
    def get_type(cls) -> str:
        return "instance"

    # generic options
    # state: int= attr_property("state", MachineState.MISSING, int)  # override
    public_ipv4: Optional[str] = attr_property("publicIpv4", None)
    public_ipv6: dict = attr_property("publicIpv6", {}, "json")
    default_gateway: Optional[str] = attr_property("defaultGateway", None)
    netmask: Optional[str] = attr_property("netmask", None)
    # instance options
    enable_ipv6: Optional[bool] = attr_property("instance.enableIpv6", False, bool)
    default_gateway6: Optional[str] = attr_property("defaultGateway6", None)
    region: Optional[str] = attr_property("instance.region", None)
    size: Optional[str] = attr_property("instance.size", None)
    auth_token: Optional[str] = attr_property("instance.authToken", None)
    instance_id: Optional[str] = attr_property("instance.instanceId", None)
    key_pair: Optional[str] = attr_property("instance.keyPair", None)

    def __init__(self, depl: Deployment, name: str, id: RecordId) -> None:
        MachineState.__init__(self, depl, name, id)
        self.name: str = name

    def _get_instance(self) -> digitalocean.Instance:
        return digitalocean.Instance(id=self.instance, token=self.get_auth_token())

    def get_ssh_name(self) -> Optional[str]:
        return self.public_ipv4

    def get_ssh_flags(self, *args, **kwargs) -> List[str]:
        super_flags = super(InstanceState, self).get_ssh_flags(*args, **kwargs)
        return super_flags + [
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-i",
            self.get_ssh_private_key_file(),
        ]

    def get_physical_spec(self) -> Function:
        def prefix_len(netmask):
            return bin(int(codecs.encode(socket.inet_aton(netmask), "hex"), 16)).count(
                "1"
            )

        networking = {
            "defaultGateway": self.default_gateway,
            "nameservers": ["67.207.67.2", "67.207.67.3"],  # default provided by DO
            ("interfaces", "ens3", "ipv4", "addresses"): [
                {"address": self.public_ipv4, "prefixLength": prefix_len(self.netmask)}
            ],
        }
        if self.public_ipv6:
            networking[("interfaces", "ens3", "ipv6", "addresses")] = [
                {
                    "address": self.public_ipv6["address"],
                    "prefixLength": self.public_ipv6["prefixLength"],
                }
            ]
        if self.default_gateway6:
            networking["defaultGateway6"] = self.default_gateway6

        return Function(
            "{ ... }",
            {
                "imports": [
                    RawValue("<nixpkgs/nixos/modules/profiles/qemu-guest.nix>")
                ],
                "networking": networking,
                (
                    "boot",
                    "loader",
                    "grub",
                    "device",
                ): "nodev",  # keep ubuntu bootloader?
                ("fileSystems", "/"): {"device": "/dev/vda1", "fsType": "ext4"},
                ("users", "extraUsers", "root", "openssh", "authorizedKeys", "keys"): [
                    self.get_ssh_key_resource().public_key
                ],
            },
        )

    def get_ssh_private_key_file(self) -> str:
        return self.write_ssh_private_key(self.get_ssh_key_resource().private_key)

    def get_ssh_key_resource(self) -> ssh_keypair.SSHKeyPairState:
        return cast(ssh_keypair.SSHKeyPairState, self.depl.active_resources["ssh-key"])

    def create_after(self, resources, defn) -> Set:
        # make sure the ssh key exists before we do anything else
        return {r for r in resources if isinstance(r, ssh_keypair.SSHKeyPairState)}

    def set_common_state(self, defn: InstanceDefinition) -> None:
        super().set_common_state(defn)
        self.auth_token = defn.auth_token

    def get_auth_token(self) -> Optional[str]:
        return os.environ.get("DIGITAL_OCEAN_AUTH_TOKEN", self.auth_token)

    def destroy(self, wipe: bool = False) -> bool:
        self.log("destroying instance {}".format(self.instance_id))
        try:
            instance = self._get_instance()
            instance.destroy()
        except digitalocean.baseapi.NotFoundError:
            self.log("instance not found - assuming it's been destroyed already")
        self.public_ipv4 = None
        self.instance_id = None

        return True

    def create(self, defn, check, allow_reboot: bool, allow_recreate: bool) -> None:
        try:
            ssh_key = self.get_ssh_key_resource()
        except KeyError:
            raise Exception(
                "Please specify a ssh-key resource (resources.sshKeyPairs.ssh-key = {})."
            )

        self.set_common_state(defn)

        if self.instance_id is not None:
            return

        self.manager = digitalocean.Manager(token=self.get_auth_token())
        instance = digitalocean.Instance(
            token=self.get_auth_token(),
            name=self.name,
            region=defn.region,
            ipv6=defn.enable_ipv6,
            ssh_keys=[ssh_key.public_key],
            image="ubuntu-16-04-x64",  # only for lustration
            size_slug=defn.size,
        )

        self.log_start("creating instance ...")
        instance.create()

        status = "in-progress"
        while status == "in-progress":
            actions = instance.get_actions()
            for action in actions:
                action.load()
                if action.status != "in-progress":
                    status = action.status
            time.sleep(1)
            self.log_continue("[{}] ".format(status))

        if status != "completed":
            raise Exception("unexpected status: {}".format(status))

        instance.load()
        self.instance = instance.id
        self.public_ipv4 = instance.ip_address
        self.log_end("{}".format(instance.ip_address))

        for n in instance.networks["v4"]:
            if n["ip_address"] == self.public_ipv4:
                self.default_gateway = n["gateway"]
        self.netmask = instance.networks["v4"][0]["netmask"]

        first_ipv6 = {}
        first_gw6 = None
        if "v6" in instance.networks:
            public_ipv6_networks = [
                n for n in instance.networks["v6"] if n["type"] == "public"
            ]
            if len(public_ipv6_networks) > 0:
                # The DigitalOcean API does not expose an explicit
                # default interface or gateway, so assume this is it.
                first_ipv6["address"] = public_ipv6_networks[0]["ip_address"]
                first_ipv6["prefixLength"] = public_ipv6_networks[0]["netmask"]
                first_gw6 = public_ipv6_networks[0]["gateway"]
        self.public_ipv6 = first_ipv6
        self.default_gateway6 = first_gw6

        # run modified nixos-infect
        # - no reboot
        # - predictable network interface naming (ens3 etc)
        self.wait_for_ssh()
        self.log_start("running nixos-infect")
        self.run_command("bash </dev/stdin 2>&1", stdin=open(infect_path))
        self.reboot_sync()

    def start(self) -> None:
        if self.state == self.UP:
            return

        self.log("starting instance... ")
        instance = self._get_instance()
        self.state = self.STARTING
        instance.reboot()

        if not nixops.util.check_wait(
            self.check_started, initial=3, max_tries=100, exception=False
        ):
            raise Exception(
                "Instance '{0}' failed to start. (state is '{1}')".format(
                    self.instance, instance.status
                )
            )

        self.wait_for_ssh(check=True)

    def check_started(self) -> bool:
        return self.check_status("active")

    def check_stopped(self) -> bool:
        return self.check_status("off")

    def check_status(self, status: str) -> bool:
        instance = self._get_instance()
        instance.load()
        self.log_continue("[{0}] ".format(instance.status))
        if instance.status == status:
            return True

        return False

    def stop(self) -> None:
        self.log_start("stopping instance...")
        instance = self._get_instance()
        instance.shutdown()
        self.state = self.STOPPING

        if not nixops.util.check_wait(
            self.check_stopped, initial=3, max_tries=100, exception=False
        ):
            self.log_end("(time out)")
            self.log_start("forcing power off... ")
            instance.power_off()
            if not nixops.util.check_wait(
                self.check_stopped, initial=3, max_tries=100, exception=False
            ):
                raise Exception(
                    "Instance '{0}' failed to stop (state is '{1}')".format(
                        self.instance_id, instance.status
                    )
                )

        self.log_end("")
        self.state = self.STOPPED

    def reboot(self, hard: bool = False) -> None:
        if hard:
            self.log("sending hard reset to instance...")
            instance = self._get_instance()
            instance.reboot()
            self.state = self.STARTING
            self.wait_for_ssh()
        else:
            MachineState.reboot(self, hard=hard)
