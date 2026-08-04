from pathlib import Path

import pytest
from conftest import policy_with_base

import hozo
from hozo import seatbelt
from hozo.errors import ProfileError
from hozo.policy import SandboxRequest, resolve_policy
from hozo.profiles import Bind


def _macos_policy(tmp_path, **kw):
    # The Linux default base sets tmpfs:, which the renderer rejects.
    return policy_with_base("base-macos", tmp_path, **kw)


def _profile(tmp_path, **kw):
    return seatbelt.build_seatbelt_profile(_macos_policy(tmp_path, **kw))


def _bare(binds):
    # No base and no project bind, so only the given binds appear in the profile.
    policy = policy_with_base(None, Path("/proj"), command=["x"], bind_project=False, binds=binds)
    return seatbelt.build_seatbelt_profile(policy)


def test_profile_denies_by_default(tmp_path):
    assert _profile(tmp_path).startswith("(version 1)\n(deny default)")


def test_system_essentials_present(tmp_path):
    prof = _profile(tmp_path)
    assert "(allow process-exec*)" in prof
    # dylibs need file-read* AND the distinct file-map-executable op
    assert "file-map-executable" in prof
    # Apple's base profile owns the platform plumbing (dyld, the shared cache, mach services)
    assert '(import "system.sb")' in prof
    assert '(subpath "/usr")' in prof


def test_profile_grants_the_controlling_tty(tmp_path):
    # Without these, file-ioctl on the tty is denied and raw mode fails.
    prof = _profile(tmp_path)
    assert r'(regex #"^/dev/ttys[0-9]+$")' in prof
    assert '(literal "/dev/ptmx")' in prof


def test_ro_and_rw_binds_land_in_the_right_blocks():
    prof = _bare([Bind(source="/opt/ro", mode="ro"), Bind(source="/opt/rw", mode="rw")])
    ro_section = prof.split("(allow file-read* file-write*")[0]  # everything before the rw block
    assert '(subpath "/opt/ro")' in ro_section  # read-only path in the read block
    assert '(subpath "/opt/rw")' not in ro_section  # writable path is *not* in the read block
    assert '(subpath "/opt/rw")' in prof  # ...it's in the rw block


def test_tmpfs_is_rejected(tmp_path):
    # Granting it would expose the real host path.
    p = _macos_policy(tmp_path)
    p.tmpfs = ["/tmp"]
    with pytest.raises(ProfileError, match="tmpfs"):
        seatbelt.build_seatbelt_profile(p)


def test_rw_binds_are_writable(tmp_path):
    prof = _profile(tmp_path, binds=[Bind(source="/var/scratch", mode="rw")])
    rw_block = prof.split("(allow file-read* file-write*", 1)[1]
    assert '(subpath "/var/scratch")' in rw_block


def test_network_none_has_no_egress(tmp_path):
    prof = _profile(tmp_path, network="none")
    assert "network-outbound" not in prof
    assert "network-bind" not in prof  # not even a loopback listener
    assert "network: none" in prof


def test_network_host_allows_network_and_dns(tmp_path):
    prof = _profile(tmp_path, network="host")
    assert "(allow network-outbound)" in prof
    assert "com.apple.mDNSResponder" in prof  # DNS isn't covered by network*


def test_proxy_mode_pins_egress_to_loopback_port(tmp_path):
    p = _macos_policy(tmp_path, profiles=["proxy"])
    prof = seatbelt.build_seatbelt_profile(p, proxy_port=45678)
    assert '(allow network-outbound (remote tcp "localhost:45678"))' in prof


def test_proxy_mode_allows_a_loopback_listener(tmp_path):
    p = _macos_policy(tmp_path, profiles=["proxy"])
    for prof in (seatbelt.build_seatbelt_profile(p, proxy_port=45678), seatbelt.build_seatbelt_profile(p)):
        assert '(allow network-bind (local ip "localhost:*"))' in prof
        assert '(allow network-inbound (local ip "localhost:*"))' in prof


def test_proxy_mode_without_port_fails_closed(tmp_path):
    p = _macos_policy(tmp_path, profiles=["proxy"])
    assert "network-outbound" not in seatbelt.build_seatbelt_profile(p)  # no port -> no egress rule


def test_paths_are_sbpl_escaped():
    prof = _bare([Bind(source='/weird/"quote"', mode="ro")])
    assert r"/weird/\"quote\"" in prof  # embedded quotes escaped, not breaking the literal


def test_canonicalize_resolves_symlinks(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    p = resolve_policy(
        SandboxRequest(
            command=["x"],
            project=str(tmp_path),
            no_base=True,
            bind_project=False,
            binds=[Bind(source=str(link), mode="ro")],
        )
    )
    assert seatbelt._canonicalize(p).binds[0].source == str(real)


def test_describe_renders_the_profile(tmp_path):
    p = _macos_policy(tmp_path, command=["echo", "hi"])
    text = seatbelt.SeatbeltBackend().describe(p)
    assert text.startswith("seatbelt profile:") and "(deny default)" in text


def test_describe_reports_the_per_run_scratch(tmp_path):
    # run() grants this, so explain must not under-report it.
    text = seatbelt.SeatbeltBackend().describe(_macos_policy(tmp_path))
    rw_block = text.split("(allow file-read* file-write*", 1)[1]
    assert seatbelt._EXPLAIN_SCRATCH in rw_block


def test_check_available_returns_bool():
    assert isinstance(seatbelt.check_available(), bool)


def test_explain_with_seatbelt_renders_profile(tmp_path):
    p = _macos_policy(tmp_path)
    text = hozo.explain_policy(p, backend=seatbelt.SeatbeltBackend(), environ={})
    assert "seatbelt profile:" in text and "(deny default)" in text
