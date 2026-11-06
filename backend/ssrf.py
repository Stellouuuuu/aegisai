"""Target policy: stop the API from being used to probe internal networks (SSRF).

By default private, loopback, link-local and reserved addresses are refused.
Operators can allow specific hosts (AEGIS_ALLOWED_HOSTS=localhost,lab) or
everything (AEGIS_ALLOW_PRIVATE_TARGETS=1) for a local setup.

Known limit: DNS is resolved at check time and again when connecting
(DNS rebinding). The check is repeated just before each scan to narrow the window.
Redirects are not followed by the connector.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse


class TargetNotAllowedError(ValueError):
    pass


def _forbidden(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified
    )


@dataclass(frozen=True)
class TargetPolicy:
    allow_private: bool = False
    allowed_hosts: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_env(cls) -> TargetPolicy:
        hosts = {h.strip().lower() for h in os.environ.get("AEGIS_ALLOWED_HOSTS", "").split(",")}
        return cls(
            allow_private=os.environ.get("AEGIS_ALLOW_PRIVATE_TARGETS") == "1",
            allowed_hosts=frozenset(h for h in hosts if h),
        )

    def check(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise TargetNotAllowedError("target must be an http(s) URL with a host")
        host = parsed.hostname.lower()
        if host in self.allowed_hosts or self.allow_private:
            return
        try:
            infos = socket.getaddrinfo(host, parsed.port or 80, proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            raise TargetNotAllowedError(f"cannot resolve host {host!r}") from e
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if _forbidden(ip):
                raise TargetNotAllowedError(
                    f"host {host!r} resolves to a non-public address ({ip}); "
                    "ask the operator to allow it via AEGIS_ALLOWED_HOSTS"
                )
