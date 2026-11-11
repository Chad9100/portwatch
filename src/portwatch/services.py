"""Well-known service names for common ports.

A fixed table is used instead of ``socket.getservbyport`` so the output is the
same on every OS (Windows has no services database at the usual path).
"""

from __future__ import annotations

from typing import Optional

# (port, proto) -> name. A plain port entry applies to both protocols.
_BOTH = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5353: "mdns",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}

_UDP_ONLY = {67: "dhcp", 68: "dhcp", 69: "tftp", 1900: "ssdp", 5355: "llmnr"}


def service_name(port: int, proto: str = "tcp") -> Optional[str]:
    """Return the well-known service name for a port, or None."""
    if proto == "udp" and port in _UDP_ONLY:
        return _UDP_ONLY[port]
    return _BOTH.get(port)
