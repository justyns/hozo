import hozo
from hozo import seatbelt
from hozo.policy import SandboxRequest, resolve_policy
from hozo.profiles import Bind


def _profile(tmp_path, **req_kw):
    req_kw.setdefault("command", ["true"])
    req_kw.setdefault("project", str(tmp_path))
    return seatbelt.build_seatbelt_profile(resolve_policy(SandboxRequest(**req_kw)))


def _bare(binds, **req_kw):
    # A policy with no base and no project bind, so only the given binds appear.
    req_kw.setdefault("command", ["x"])
    req_kw.setdefault("project", "/proj")
    req = SandboxRequest(no_base=True, bind_project=False, binds=binds, **req_kw)
    return seatbelt.build_seatbelt_profile(resolve_policy(req))


def test_profile_denies_by_default(tmp_path):
    assert _profile(tmp_path).startswith("(version 1)\n(deny default)")


def test_system_essentials_present(tmp_path):
    prof = _profile(tmp_path)
    assert "(allow process-exec*)" in prof
    # dyld cache + dylibs need file-read* AND the distinct file-map-executable op
    assert "file-map-executable" in prof
    assert '(subpath "/System/Volumes/Preboot/Cryptexes/OS")' in prof


def test_ro_and_rw_binds_land_in_the_right_blocks():
    prof = _bare([Bind(source="/opt/ro", mode="ro"), Bind(source="/opt/rw", mode="rw")])
    ro_section = prof.split("(allow file-read* file-write*")[0]  # everything before the rw block
    assert '(subpath "/opt/ro")' in ro_section  # read-only path in the read block
    assert '(subpath "/opt/rw")' not in ro_section  # writable path is *not* in the read block
    assert '(subpath "/opt/rw")' in prof  # ...it's in the rw block


def test_tmpfs_and_scratch_are_writable(tmp_path):
    p = resolve_policy(SandboxRequest(command=["x"], project=str(tmp_path), no_base=True, bind_project=False))
    p.tmpfs = ["/tmp"]
    prof = seatbelt.build_seatbelt_profile(p, writable_scratch=("/var/scratch",))
    rw_block = prof.split("(allow file-read* file-write*", 1)[1]
    assert '(subpath "/tmp")' in rw_block and '(subpath "/var/scratch")' in rw_block


def test_network_none_has_no_egress(tmp_path):
    prof = _profile(tmp_path, network="none")
    assert "network-outbound" not in prof
    assert "network: none" in prof


def test_network_host_allows_network_and_dns(tmp_path):
    prof = _profile(tmp_path, network="host")
    assert "(allow network-outbound)" in prof
    assert "com.apple.mDNSResponder" in prof  # DNS isn't covered by network*


def test_proxy_mode_pins_egress_to_loopback_port(tmp_path):
    p = resolve_policy(SandboxRequest(command=["x"], project=str(tmp_path), profiles=["proxy"]))
    prof = seatbelt.build_seatbelt_profile(p, proxy_port=45678)
    assert '(allow network-outbound (remote tcp "localhost:45678"))' in prof


def test_proxy_mode_without_port_fails_closed(tmp_path):
    p = resolve_policy(SandboxRequest(command=["x"], project=str(tmp_path), profiles=["proxy"]))
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


def test_build_argv_uses_sandbox_exec(tmp_path):
    p = resolve_policy(SandboxRequest(command=["echo", "hi"], project=str(tmp_path)))
    argv = seatbelt.SeatbeltBackend().build_argv(p)
    assert argv[0] == "/usr/bin/sandbox-exec" and argv[-1] == "hi"


def test_check_available_returns_bool():
    assert isinstance(seatbelt.check_available(), bool)


def test_explain_with_seatbelt_renders_profile(tmp_path):
    p = resolve_policy(SandboxRequest(command=["true"], project=str(tmp_path)))
    text = hozo.explain_policy(p, backend=seatbelt.SeatbeltBackend(), environ={})
    assert "seatbelt profile:" in text and "(deny default)" in text
