import pytest

from raspberry_pi import firewall as fw
from nips_fakes import CHAIN, FakeIptables, make_firewall

ATTACKER = "192.168.77.23"


def test_chain_is_created_and_hooked_first_into_input_and_forward():
    _, fake = make_firewall(FakeIptables(chain_exists=False))
    tails = [c[c.index("-w") + 2:] for c in fake.calls]
    assert ["-N", CHAIN] in tails
    assert ["-I", "INPUT", "1", "-j", CHAIN] in tails
    assert ["-I", "FORWARD", "1", "-j", CHAIN] in tails


def test_block_inserts_one_drop_rule_and_dedupes_repeats():
    firewall, fake = make_firewall()

    assert firewall.block(ATTACKER, "PortScan") == fw.BLOCKED
    assert firewall.block(ATTACKER, "PortScan") == fw.ALREADY_BLOCKED

    inserts = fake.drop_inserts()
    assert len(inserts) == 1, "the in-memory set must prevent a second iptables call"
    assert inserts[0][-10:] == ["-I", CHAIN, "-s", ATTACKER, "-m", "comment",
                                "--comment", "edge-sentinel:PortScan", "-j", "DROP"]
    assert firewall.is_blocked(ATTACKER)
    assert firewall.last_latency_ms is not None


@pytest.mark.parametrize("ip, expected", [
    ("192.168.77.1", fw.WHITELISTED),     # the gateway itself
    ("192.168.77.50", fw.WHITELISTED),    # explicit whitelist entry
    ("192.168.77.70", fw.WHITELISTED),    # inside a whitelisted CIDR
    ("192.168.77.255", fw.WHITELISTED),   # subnet broadcast
    ("127.0.0.1", fw.INVALID),
    ("224.0.0.251", fw.INVALID),          # multicast (mDNS)
    ("fe80::1", fw.INVALID),              # IPv6 is out of iptables' reach
    ("not-an-ip", fw.INVALID),
    ("8.8.8.8", fw.OUT_OF_SCOPE),         # outside the LAN with scope=lan
])
def test_protected_and_unblockable_addresses(ip, expected):
    firewall, fake = make_firewall(whitelist=["192.168.77.50", "192.168.77.64/28"])
    assert firewall.block(ip, "DoS") == expected
    assert fake.drop_inserts() == []


def test_scope_any_allows_blocking_outside_addresses():
    firewall, _ = make_firewall(block_scope="any")
    assert firewall.block("8.8.8.8", "DDoS") == fw.BLOCKED


def test_failed_block_is_retried_on_the_next_alert():
    firewall, _ = make_firewall(FakeIptables(fail_inserts=2))
    assert firewall.block(ATTACKER, "DoS") == fw.FAILED
    assert not firewall.is_blocked(ATTACKER)
    assert firewall.block(ATTACKER, "DoS") == fw.BLOCKED


def test_falls_back_to_a_plain_rule_without_the_comment_match():
    firewall, fake = make_firewall(FakeIptables(comment_supported=False))
    assert firewall.block(ATTACKER, "DoS") == fw.BLOCKED
    assert f"-A {CHAIN} -s {ATTACKER}/32 -j DROP" in fake.rules


def test_existing_blocks_are_restored_after_an_engine_restart():
    fake = FakeIptables(rules=[f"-A {CHAIN} -s {ATTACKER}/32 -j DROP"])
    firewall, fake = make_firewall(fake)
    assert firewall.synced
    assert firewall.blocked_ips == {ATTACKER}
    assert firewall.block(ATTACKER, "DoS") == fw.ALREADY_BLOCKED
    assert fake.drop_inserts() == []


def test_dry_run_never_touches_iptables():
    firewall, fake = make_firewall(mode="dry-run")
    assert firewall.block(ATTACKER, "DoS") == fw.DRY_RUN
    assert firewall.block(ATTACKER, "DoS") == fw.DRY_RUN
    assert fake.calls == []
    assert not firewall.is_enforcing


def test_off_mode_disables_prevention():
    firewall, fake = make_firewall(mode="off")
    assert firewall.block(ATTACKER, "DoS") == fw.DISABLED
    assert fake.calls == []


def test_flush_clears_chain_and_memory():
    firewall, fake = make_firewall()
    firewall.block(ATTACKER, "DoS")
    assert firewall.flush()
    assert firewall.blocked_ips == set()
    assert fake.rules == []


def test_parse_chain_rules_reads_drop_counters():
    listing = "\n".join([
        f"-N {CHAIN}",
        f'-A {CHAIN} -s 192.168.77.23/32 -m comment --comment "edge-sentinel:PortScan" -c 120 7200 -j DROP',
        f"-A {CHAIN} -s 192.168.77.24/32 -c 5 300 -j DROP",
        f"-A {CHAIN} -s 10.0.0.0/8 -j DROP",          # not a single host: ignored
        f"-A {CHAIN} -s 192.168.77.25/32 -j ACCEPT",  # not a block: ignored
    ])
    assert fw.parse_chain_rules(listing) == {
        "192.168.77.23": {"packets": 120, "bytes": 7200},
        "192.168.77.24": {"packets": 5, "bytes": 300},
    }


def test_read_chain_state_requests_counters():
    fake = FakeIptables(rules=[f"-A {CHAIN} -s {ATTACKER}/32 -c 9 540 -j DROP"])
    cli = fw.IptablesCLI(runner=fake, use_sudo=False)
    assert fw.read_chain_state(CHAIN, "enforce", cli) == {ATTACKER: {"packets": 9, "bytes": 540}}
    assert fake.calls[-1][-3:] == ["-S", CHAIN, "-v"]
    assert fw.read_chain_state(CHAIN, "dry-run", cli) is None


def test_non_root_calls_go_through_non_interactive_sudo():
    fake = FakeIptables()
    fw.IptablesCLI(runner=fake, use_sudo=True, binary="/usr/sbin/iptables").run(["-S", CHAIN])
    assert fake.calls[0][:4] == ["sudo", "-n", "/usr/sbin/iptables", "-w"]
