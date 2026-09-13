"""Pure network helpers: address classification, ports, TCP flags, domains.

Like :mod:`xniffer.util.text`, this module imports nothing from xniffer and is
safe to use from any layer. It holds the small pieces of network knowledge that
several layers need to agree on -- what counts as "private", which ports carry
cleartext protocols, how to split a domain name -- so that the decoders, the
analyzers, the rules and the renderers never disagree about them.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from xniffer.util.text import shannon_entropy

# --------------------------------------------------------------------------- #
# IP addresses
# --------------------------------------------------------------------------- #


def parse_ip(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse ``address``, returning ``None`` instead of raising on bad input."""
    try:
        return ipaddress.ip_address(address)
    except (ValueError, TypeError):
        return None


def ip_version(address: str) -> int | None:
    """Return 4, 6, or ``None`` if ``address`` is not an IP address."""
    parsed = parse_ip(address)
    return parsed.version if parsed else None


def is_private_ip(address: str) -> bool:
    """True for RFC1918 / RFC4193 and other non-globally-routable addresses."""
    parsed = parse_ip(address)
    return bool(parsed and parsed.is_private)


def is_global_ip(address: str) -> bool:
    """True for globally routable addresses -- i.e. "the internet"."""
    parsed = parse_ip(address)
    return bool(parsed and parsed.is_global)


def is_multicast_ip(address: str) -> bool:
    """True for IPv4/IPv6 multicast addresses."""
    parsed = parse_ip(address)
    return bool(parsed and parsed.is_multicast)


def is_loopback_ip(address: str) -> bool:
    """True for loopback addresses."""
    parsed = parse_ip(address)
    return bool(parsed and parsed.is_loopback)


def is_link_local_ip(address: str) -> bool:
    """True for link-local addresses (169.254.0.0/16, fe80::/10)."""
    parsed = parse_ip(address)
    return bool(parsed and parsed.is_link_local)


def classify_ip(address: str) -> str:
    """Return a one-word scope for ``address``.

    One of: ``invalid``, ``unspecified``, ``loopback``, ``link-local``,
    ``multicast``, ``broadcast``, ``private``, ``public``.

    Detection rules lean on this heavily: "many connections to *public*
    addresses" means something different from the same count against
    *private* ones.
    """
    parsed = parse_ip(address)
    if parsed is None:
        return "invalid"
    if parsed.is_unspecified:
        return "unspecified"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_link_local:
        return "link-local"
    if parsed.is_multicast:
        return "multicast"
    if parsed.version == 4 and parsed == ipaddress.IPv4Address("255.255.255.255"):
        return "broadcast"
    if parsed.is_private:
        return "private"
    return "public"


def same_network(a: str, b: str, prefix_v4: int = 24, prefix_v6: int = 64) -> bool:
    """True when ``a`` and ``b`` share a network at the given prefix length."""
    first, second = parse_ip(a), parse_ip(b)
    if first is None or second is None or first.version != second.version:
        return False
    prefix = prefix_v4 if first.version == 4 else prefix_v6
    net = ipaddress.ip_network(f"{first}/{prefix}", strict=False)
    return second in net


# --------------------------------------------------------------------------- #
# MAC addresses
# --------------------------------------------------------------------------- #

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def normalize_mac(mac: str) -> str:
    """Lower-case a MAC address and normalise separators to ``:``."""
    if not mac:
        return ""
    return mac.strip().lower().replace("-", ":")


def is_broadcast_mac(mac: str) -> bool:
    """True for the Ethernet broadcast address."""
    return normalize_mac(mac) == BROADCAST_MAC


def is_multicast_mac(mac: str) -> bool:
    """True when the multicast bit (least significant bit of octet 0) is set."""
    normalized = normalize_mac(mac)
    if len(normalized) < 2:
        return False
    try:
        return bool(int(normalized[:2], 16) & 0x01)
    except ValueError:
        return False


def is_locally_administered_mac(mac: str) -> bool:
    """True when the locally-administered bit is set -- often a spoofed MAC."""
    normalized = normalize_mac(mac)
    if len(normalized) < 2:
        return False
    try:
        return bool(int(normalized[:2], 16) & 0x02)
    except ValueError:
        return False


def mac_oui(mac: str) -> str:
    """Return the 3-octet OUI prefix (vendor portion) of a MAC address."""
    normalized = normalize_mac(mac)
    parts = normalized.split(":")
    return ":".join(parts[:3]) if len(parts) >= 3 else ""


# --------------------------------------------------------------------------- #
# Ports and services
# --------------------------------------------------------------------------- #

WELL_KNOWN_PORTS: dict[int, str] = {
    7: "echo",
    19: "chargen",
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    37: "time",
    43: "whois",
    53: "dns",
    67: "dhcp-server",
    68: "dhcp-client",
    69: "tftp",
    79: "finger",
    80: "http",
    88: "kerberos",
    102: "iso-tsap",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmp-trap",
    179: "bgp",
    389: "ldap",
    427: "slp",
    443: "https",
    445: "smb",
    465: "smtps",
    500: "isakmp",
    502: "modbus",
    512: "exec",
    513: "rlogin",
    514: "syslog",
    515: "printer",
    520: "rip",
    523: "db2",
    548: "afp",
    554: "rtsp",
    587: "smtp-submission",
    623: "ipmi",
    631: "ipp",
    636: "ldaps",
    873: "rsync",
    902: "vmware",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1099: "java-rmi",
    1194: "openvpn",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    1883: "mqtt",
    1900: "ssdp",
    2049: "nfs",
    2181: "zookeeper",
    2375: "docker",
    2376: "docker-tls",
    3128: "squid-proxy",
    3268: "globalcatalog",
    3306: "mysql",
    3389: "rdp",
    3690: "svn",
    4369: "epmd",
    4444: "metasploit-default",
    4786: "cisco-smi",
    5000: "upnp",
    5060: "sip",
    5061: "sip-tls",
    5222: "xmpp",
    5353: "mdns",
    5432: "postgresql",
    5555: "adb",
    5601: "kibana",
    5672: "amqp",
    5800: "vnc-http",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-tls",
    6000: "x11",
    6379: "redis",
    6443: "kubernetes-api",
    6667: "irc",
    7001: "weblogic",
    8000: "http-alt",
    8008: "http-alt",
    8009: "ajp13",
    8080: "http-proxy",
    8086: "influxdb",
    8088: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9000: "http-alt",
    9042: "cassandra",
    9092: "kafka",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    10000: "webmin",
    11211: "memcached",
    27017: "mongodb",
    31337: "elite-backdoor",
    50000: "sap",
}

#: Ports whose protocol transmits credentials or data without encryption.
#: The value explains *why* it matters, and rules quote that explanation
#: verbatim in their evidence so the operator never has to guess.
CLEARTEXT_SERVICE_PORTS: dict[int, tuple[str, str]] = {
    21: ("ftp", "FTP sends usernames and passwords in cleartext"),
    23: ("telnet", "Telnet sends the entire session, including credentials, in cleartext"),
    25: ("smtp", "SMTP without STARTTLS exposes message content and AUTH credentials"),
    69: ("tftp", "TFTP has no authentication or encryption at all"),
    79: ("finger", "Finger discloses user information without authentication"),
    80: ("http", "HTTP exposes URLs, headers, cookies and request bodies"),
    110: ("pop3", "POP3 without TLS exposes mailbox credentials and message content"),
    143: ("imap", "IMAP without TLS exposes mailbox credentials and message content"),
    161: ("snmp", "SNMP v1/v2c community strings cross the wire in cleartext"),
    389: ("ldap", "Unencrypted LDAP can expose simple-bind credentials"),
    512: ("exec", "Berkeley r-services transmit credentials in cleartext"),
    513: ("rlogin", "Berkeley r-services transmit credentials in cleartext"),
    514: ("syslog", "Plain syslog exposes log content, which often includes secrets"),
    873: ("rsync", "rsync daemon mode can transfer data and secrets unencrypted"),
    1433: ("mssql", "MSSQL without forced encryption can expose query data"),
    3306: ("mysql", "MySQL without TLS can expose query data and auth exchanges"),
    5432: ("postgresql", "PostgreSQL without TLS can expose query data"),
    5900: ("vnc", "VNC's native authentication is weak and the session is unencrypted"),
    6379: ("redis", "Redis is frequently exposed with no authentication"),
    11211: ("memcached", "Memcached has no authentication and is a known amplification vector"),
    27017: ("mongodb", "MongoDB is frequently exposed with no authentication"),
}

#: Ports commonly probed during reconnaissance. A scan that touches these is
#: more interesting than one that only touches ephemeral ports.
NOTABLE_SCAN_TARGET_PORTS: frozenset[int] = frozenset(
    {
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
        1433, 1521, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 9200, 27017,
    }
)

#: Ports with a strong association to remote-access tooling and default
#: implant listeners. Presence is suggestive, never conclusive -- these are
#: ordinary high ports that legitimate software also uses.
SUSPICIOUS_LISTENER_PORTS: dict[int, str] = {
    1337: "commonly used as a default listener port by offensive tooling",
    4444: "Metasploit's default handler port",
    4445: "commonly used as a secondary Metasploit handler port",
    5555: "Android Debug Bridge, and a common implant default",
    6666: "frequently used by IRC-based bots",
    6667: "IRC, historically used for botnet command and control",
    8081: "common alternate HTTP port used by tooling",
    9001: "common Tor ORPort and implant default",
    9050: "Tor SOCKS proxy default",
    9051: "Tor control port default",
    31337: "the classic 'elite' backdoor port",
}


def port_service(port: int | None) -> str | None:
    """Return the well-known service name for ``port``, if any."""
    if port is None:
        return None
    return WELL_KNOWN_PORTS.get(port)


def describe_port(port: int | None) -> str:
    """Render a port as ``443 (https)``, or just the number when unknown."""
    if port is None:
        return "-"
    service = port_service(port)
    return f"{port} ({service})" if service else str(port)


def is_ephemeral_port(port: int | None) -> bool:
    """True for ports in the IANA dynamic/ephemeral range."""
    return port is not None and port >= 49152


def cleartext_service(port: int | None) -> tuple[str, str] | None:
    """Return ``(service_name, risk_explanation)`` when ``port`` is cleartext."""
    if port is None:
        return None
    return CLEARTEXT_SERVICE_PORTS.get(port)


# --------------------------------------------------------------------------- #
# TCP flags
# --------------------------------------------------------------------------- #

#: Scapy renders TCP flags as a compact letter string such as ``"SA"``.
#: xniffer stores that string verbatim on the packet record and interprets it
#: through these helpers, so the letter convention is defined in exactly one
#: place.
TCP_FLAG_LETTERS: dict[str, str] = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
    "N": "NS",
}


def tcp_flag_names(flags: str | None) -> tuple[str, ...]:
    """Expand a flag string such as ``"SA"`` into ``("SYN", "ACK")``."""
    if not flags:
        return ()
    return tuple(TCP_FLAG_LETTERS[letter] for letter in flags if letter in TCP_FLAG_LETTERS)


def has_tcp_flag(flags: str | None, letter: str) -> bool:
    """True when ``flags`` contains the single-letter flag ``letter``."""
    return bool(flags) and letter in flags


def is_syn_only(flags: str | None) -> bool:
    """True for a bare SYN -- the opening packet of a connection attempt.

    This is the primitive behind scan detection: a host that emits many bare
    SYNs and receives few SYN/ACKs is probing rather than communicating.
    """
    return bool(flags) and "S" in flags and "A" not in flags and "R" not in flags


def is_syn_ack(flags: str | None) -> bool:
    """True for SYN/ACK -- a service accepting a connection."""
    return bool(flags) and "S" in flags and "A" in flags


def is_rst(flags: str | None) -> bool:
    """True when the RST flag is set -- a refused or torn-down connection."""
    return has_tcp_flag(flags, "R")


def is_fin(flags: str | None) -> bool:
    """True when the FIN flag is set."""
    return has_tcp_flag(flags, "F")


def is_null_scan_flags(flags: str | None) -> bool:
    """True for a TCP packet with no flags set at all -- a NULL scan probe."""
    return flags == ""


def is_xmas_scan_flags(flags: str | None) -> bool:
    """True for the FIN+PSH+URG combination used by an Xmas scan."""
    if not flags:
        return False
    return {"F", "P", "U"}.issubset(set(flags))


# --------------------------------------------------------------------------- #
# Domain names
# --------------------------------------------------------------------------- #

# A compact stand-in for the Public Suffix List. xniffer stays dependency-free
# and offline, so it approximates: these are the common two-part suffixes where
# naively taking the last two labels would give the wrong registrable domain.
# The approximation is documented rather than hidden -- it only affects how
# DNS names are split for entropy scoring, never whether traffic is captured.
_MULTIPART_SUFFIXES: frozenset[str] = frozenset(
    {
        "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk", "sch.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
        "co.za", "org.za", "net.za", "gov.za", "ac.za",
        "com.br", "net.br", "org.br", "gov.br", "edu.br",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "co.kr", "or.kr", "ne.kr", "go.kr",
        "co.in", "net.in", "org.in", "gov.in", "ac.in",
        "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw", "com.pl",
        "co.il", "org.il", "net.il", "ac.il", "gov.il",
        "com.ua", "com.ru", "com.es", "com.pe", "com.co", "com.ve", "com.uy",
    }
)


def domain_labels(name: str) -> tuple[str, ...]:
    """Split a domain name into its labels, dropping the root dot."""
    if not name:
        return ()
    return tuple(label for label in name.strip().rstrip(".").lower().split(".") if label)


def registrable_domain(name: str) -> str:
    """Return the registrable ("eTLD+1") portion of ``name``.

    ``a.b.example.co.uk`` -> ``example.co.uk``. See :data:`_MULTIPART_SUFFIXES`
    for the honest caveat about how suffixes are recognised.
    """
    labels = domain_labels(name)
    if len(labels) < 2:
        return ".".join(labels)
    last_two = ".".join(labels[-2:])
    if last_two in _MULTIPART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def subdomain_part(name: str) -> str:
    """Return everything to the left of the registrable domain.

    This is the portion an attacker controls when tunnelling data over DNS,
    so it -- not the whole name -- is what the tunneling heuristics score.
    """
    labels = domain_labels(name)
    registrable = registrable_domain(name)
    registrable_label_count = len(domain_labels(registrable))
    if len(labels) <= registrable_label_count:
        return ""
    return ".".join(labels[:-registrable_label_count])


def longest_label(name: str) -> str:
    """Return the longest single label in ``name``."""
    labels = domain_labels(name)
    return max(labels, key=len) if labels else ""


@dataclass(frozen=True, slots=True)
class DomainProfile:
    """Structural measurements of a domain name, used by DNS heuristics.

    Computing these once per name keeps every DNS rule reading the same
    numbers, and makes the numbers directly quotable as finding evidence.
    """

    name: str
    registrable: str
    subdomain: str
    label_count: int
    total_length: int
    longest_label_length: int
    subdomain_length: int
    subdomain_entropy: float
    digit_ratio: float
    hex_like: bool
    base32_like: bool

    @property
    def looks_encoded(self) -> bool:
        """True when the subdomain resembles encoded data rather than a name.

        Deliberately conservative: it wants a long subdomain *and* either high
        entropy or an obvious encoding alphabet. Plenty of legitimate CDN and
        cloud hostnames are long and random-looking, which is exactly why the
        rules that consume this also require volume before reporting anything.
        """
        if self.subdomain_length < 20:
            return False
        return self.subdomain_entropy >= 3.5 or self.hex_like or self.base32_like


_HEX_ALPHABET = frozenset("0123456789abcdef")
_BASE32_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz234567=")


def profile_domain(name: str) -> DomainProfile:
    """Measure the structure of ``name`` for use by DNS detection rules."""
    labels = domain_labels(name)
    registrable = registrable_domain(name)
    subdomain = subdomain_part(name)
    stripped = subdomain.replace(".", "")
    digits = sum(1 for char in stripped if char.isdigit())

    return DomainProfile(
        name=name,
        registrable=registrable,
        subdomain=subdomain,
        label_count=len(labels),
        total_length=len(".".join(labels)),
        longest_label_length=len(longest_label(name)),
        subdomain_length=len(subdomain),
        subdomain_entropy=shannon_entropy(subdomain) if subdomain else 0.0,
        digit_ratio=(digits / len(stripped)) if stripped else 0.0,
        hex_like=bool(stripped) and len(stripped) >= 16 and set(stripped) <= _HEX_ALPHABET,
        base32_like=bool(stripped) and len(stripped) >= 16 and set(stripped) <= _BASE32_ALPHABET,
    )


__all__ = [
    "BROADCAST_MAC",
    "CLEARTEXT_SERVICE_PORTS",
    "NOTABLE_SCAN_TARGET_PORTS",
    "SUSPICIOUS_LISTENER_PORTS",
    "TCP_FLAG_LETTERS",
    "WELL_KNOWN_PORTS",
    "DomainProfile",
    "classify_ip",
    "cleartext_service",
    "describe_port",
    "domain_labels",
    "has_tcp_flag",
    "ip_version",
    "is_broadcast_mac",
    "is_ephemeral_port",
    "is_fin",
    "is_global_ip",
    "is_link_local_ip",
    "is_locally_administered_mac",
    "is_loopback_ip",
    "is_multicast_ip",
    "is_multicast_mac",
    "is_null_scan_flags",
    "is_private_ip",
    "is_rst",
    "is_syn_ack",
    "is_syn_only",
    "is_xmas_scan_flags",
    "longest_label",
    "mac_oui",
    "normalize_mac",
    "parse_ip",
    "port_service",
    "profile_domain",
    "registrable_domain",
    "same_network",
    "subdomain_part",
    "tcp_flag_names",
]
