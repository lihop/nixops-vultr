import os.path
import nixops.plugins


class NixopsVultrPlugin(nixops.plugins.Plugin):
    @staticmethod
    def nixexprs():
        return [os.path.dirname(os.path.abspath(__file__)) + "/nix"]

    @staticmethod
    def load():
        return [
            "nixops_vultr.resources",
            "nixops_vultr.backends.vultr",
        ]


@nixops.plugins.hookimpl
def plugin():
    return NixopsVultrPlugin()
