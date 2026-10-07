"""Test doubles for the NIPS kill-switch: an in-memory iptables."""

import subprocess

from raspberry_pi import firewall as fw

LAN = "192.168.77.0/24"
GATEWAY = "192.168.77.1"
CHAIN = "EDGE_SENTINEL"


class FakeIptables:
    """Records every iptables call and keeps the NIPS chain's rules."""

    def __init__(self, rules=None, chain_exists=True, fail_inserts=0, comment_supported=True):
        self.calls = []
        self.rules = list(rules or [])
        self.chain_exists = chain_exists
        self.hooks = set()
        self.fail_inserts = fail_inserts
        self.comment_supported = comment_supported

    def __call__(self, cmd, timeout):
        self.calls.append(cmd)
        args = cmd[cmd.index("-w") + 2:]  # drop the binary and "-w 3"
        op, rc, out = args[0], 0, ""
        if op == "-S":
            if self.chain_exists:
                out = f"-N {CHAIN}\n" + "".join(rule + "\n" for rule in self.rules)
            else:
                rc = 1
        elif op == "-N":
            self.chain_exists = True
        elif op == "-C":
            rc = 0 if (args[1], args[-1]) in self.hooks else 1
        elif op == "-I" and args[1] in ("INPUT", "FORWARD"):
            self.hooks.add((args[1], args[-1]))
        elif op == "-I":
            if self.fail_inserts:
                self.fail_inserts -= 1
                rc = 1
            elif "--comment" in args and not self.comment_supported:
                rc = 1
            else:
                self.rules.append(f"-A {args[1]} -s {args[3]}/32 -j DROP")
        elif op == "-F":
            self.rules.clear()
        return subprocess.CompletedProcess(cmd, rc, out, "simulated failure" if rc else "")

    def drop_inserts(self):
        return [c for c in self.calls if "-I" in c and c[-1] == "DROP"]


def make_firewall(fake=None, **overrides):
    fake = fake if fake is not None else FakeIptables()
    params = dict(mode="enforce", chain=CHAIN, lan_interface="", lan_subnet=LAN,
                  gateway_ip=GATEWAY, block_scope="lan", whitelist=[],
                  runner=fake, use_sudo=False)
    params.update(overrides)
    return fw.FirewallManager(**params), fake
