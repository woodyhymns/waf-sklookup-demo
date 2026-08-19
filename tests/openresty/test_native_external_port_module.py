#!/usr/bin/env python3
"""SDD-004 source-contract tests.

These tests intentionally do not claim binary compatibility with an arbitrary
Nginx. Exact-image compilation and live traffic verification are separate
staging gates. They protect the repository against unsafe implementation
regressions before that environment is available.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "openresty/modules/ngx_http_waf_external_port_module.c"
LUA = ROOT / "openresty/lua/waf/external_port.lua"
PROD = ROOT / "openresty/nginx.native-external-port.conf.example"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_native_module_uses_connection_local_sockaddr() -> None:
    source = text(MODULE)
    assert "ngx_connection_local_sockaddr" in source
    assert "AF_INET" in source
    assert "AF_INET6" in source
    assert "ntohs" in source
    assert 'ngx_string("waf_external_port")' in source


def test_native_module_fails_closed_without_proc_or_lua_socket() -> None:
    source = text(MODULE).lower()
    assert "/proc" not in source
    assert "ngx.req.socket" not in source
    assert "server_port" not in source
    assert "not_found:" in source
    assert "v->not_found = 1" in source


def test_legacy_lua_cannot_become_a_hot_path_resolver_again() -> None:
    # Migration comments may mention the forbidden mechanisms; executable
    # statements may not reintroduce either one.
    source = "\n".join(
        line for line in text(LUA).lower().splitlines() if not line.lstrip().startswith("--")
    )
    assert "io.open" not in source
    assert "port_from_proc" not in source
    assert "ngx.req.socket" not in source
    assert "return \"\"" in source


def test_production_config_loads_native_module_and_never_overwrites_variable() -> None:
    source = text(PROD)
    executable = "\n".join(
        line
        for line in source.splitlines()
        if not line.lstrip().startswith(("#", "--"))
    )
    assert "load_module modules/ngx_http_waf_external_port_module.so;" in executable
    assert "set $waf_external_port" not in executable
    assert "waf.external_port.resolve" not in executable
    assert "ngx.HTTP_SERVICE_UNAVAILABLE" in executable


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("PASS: SDD-004 native external-port source contract")
