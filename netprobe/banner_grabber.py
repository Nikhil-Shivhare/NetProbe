# banner_grabber.py — Optional Phase 4: Service Banner Enumeration
#
# Connects to each confirmed-open port via raw socket / ssl and extracts:
#   • service name  (from the port number)
#   • version string  (parsed from the banner with lightweight regex)
#   • raw banner  (first 1 KB of data returned by the service)
#
# Only stdlib is used: socket, ssl, re, concurrent.futures, logging.

from __future__ import annotations

import re
import socket
import ssl
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, NamedTuple, Optional

log = logging.getLogger("netprobe")

# ─── Default Timeout (seconds per connection) ─────────────────────────────────

DEFAULT_TIMEOUT: float = 4.0

# ─── Result Container ─────────────────────────────────────────────────────────


class BannerResult(NamedTuple):
    """Holds the banner-grab outcome for a single (ip, port) pair.

    Attributes:
        port:       Integer port number.
        service:    Well-known service label (e.g. "SSH", "HTTP").
        version:    Parsed version string, empty string when not found.
        raw_banner: First 1 KB of the raw server response, stripped.
    """

    port: int
    service: str
    version: str
    raw_banner: str


# ─── Version Parser ───────────────────────────────────────────────────────────

# Ordered list of (compiled-pattern, group-index) to try against raw banners.
_VERSION_PATTERNS: list = [
    # OpenSSH 9.2p1, Dropbear etc.
    re.compile(r"SSH-[\d.]+-(\S+)", re.IGNORECASE),
    # Apache/2.4.57, nginx/1.24.0, lighttpd/1.4.71 …
    re.compile(r"Server:\s*([^\r\n]+)", re.IGNORECASE),
    # 220 ProFTPD 1.3.7 Server …  or  220 FileZilla Server 1.7.0
    re.compile(r"220[- ](\S+(?:\s+\S+)?)", re.IGNORECASE),
    # +OK Dovecot ready.  or  * OK Dovecot IMAP ready.
    re.compile(r"(?:\+OK|\* OK)\s+([^\r\n]+)", re.IGNORECASE),
    # Generic "version X.Y.Z" anywhere
    re.compile(r"version\s+([\d][\d.]+)", re.IGNORECASE),
    # Bare semver: 1.2.3 or 1.2.3p4
    re.compile(r"\b(\d+\.\d+[\w.]*)\b"),
]


def _parse_version(raw: str) -> str:
    """Extract the most informative version string from *raw* banner text.

    Returns an empty string when nothing recognisable is found.
    """
    for pattern in _VERSION_PATTERNS:
        m = pattern.search(raw)
        if m:
            return m.group(1).strip()[:80]
    return ""


# ─── Protocol-Specific Grabbers ───────────────────────────────────────────────


def _read(sock: socket.socket, bufsize: int = 1024) -> str:
    """Read up to *bufsize* bytes from *sock*, decode as UTF-8 (lossy)."""
    try:
        data = sock.recv(bufsize)
        return data.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _grab_ftp(ip: str, port: int, timeout: float) -> tuple[str, str]:
    """FTP — read the 220 greeting banner."""
    with socket.create_connection((ip, port), timeout=timeout) as s:
        raw = _read(s)
    log.debug(f"FTP banner {ip}:{port}: {raw!r}")
    return raw, _parse_version(raw)


def _grab_ssh(ip: str, port: int, timeout: float) -> tuple[str, str]:
    """SSH — read the SSH identification string (SSH-2.0-…)."""
    with socket.create_connection((ip, port), timeout=timeout) as s:
        raw = _read(s)
    log.debug(f"SSH banner {ip}:{port}: {raw!r}")
    return raw, _parse_version(raw)


def _grab_smtp(ip: str, port: int, timeout: float) -> tuple[str, str]:
    """SMTP — read the 220 greeting banner."""
    with socket.create_connection((ip, port), timeout=timeout) as s:
        raw = _read(s)
    log.debug(f"SMTP banner {ip}:{port}: {raw!r}")
    return raw, _parse_version(raw)


def _grab_http(ip: str, port: int, timeout: float) -> tuple[str, str]:
    """HTTP — issue a minimal GET request and parse the Server: header."""
    with socket.create_connection((ip, port), timeout=timeout) as s:
        s.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        raw = _read(s, 2048)
    log.debug(f"HTTP banner {ip}:{port}: {raw[:120]!r}")
    return raw, _parse_version(raw)


def _make_permissive_ssl_context() -> ssl.SSLContext:
    """Build the most permissive SSL context that Python allows.

    Many embedded devices (IP phones, APs, routers) still use TLS 1.0/1.1
    or weak cipher suites.  The default Python context rejects these,
    causing the connection to stall until timeout.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    # Allow TLS 1.0+ so old Fanvil phones, Aruba APs, etc. can respond
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    # Accept all cipher suites including legacy ones
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass  # older OpenSSL builds may not support SECLEVEL — ignore
    return ctx


def _grab_https(ip: str, port: int, timeout: float) -> tuple[str, str]:
    """HTTPS — TLS-wrapped HTTP GET to extract the Server: header.

    Falls back to a plain HTTP GET if the TLS handshake fails entirely,
    which covers devices that accept connections on 443 without TLS.
    Uses a maximally-permissive SSL context so old TLS 1.0/1.1 devices
    (IP phones, APs, embedded gear) are not rejected during the handshake.
    """
    ctx = _make_permissive_ssl_context()
    request = b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n"

    # ── Attempt 1: proper TLS ─────────────────────────────────────────────
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
            raw_sock.settimeout(timeout)          # ensure timeout on SSL ops too
            with ctx.wrap_socket(raw_sock, server_hostname=ip) as s:
                s.settimeout(timeout)
                s.sendall(request)
                raw = _read(s, 2048)
        log.debug(f"HTTPS banner {ip}:{port}: {raw[:120]!r}")
        return raw, _parse_version(raw)
    except ssl.SSLError as exc:
        log.debug(f"TLS handshake failed {ip}:{port} ({exc.reason}), trying plain HTTP")
    except (socket.timeout, TimeoutError):
        raise  # let the outer handler deal with timeouts
    except OSError:
        raise

    # ── Attempt 2: plain HTTP on the same port (some devices skip TLS) ───
    with socket.create_connection((ip, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(request)
        raw = _read(s, 2048)
    log.debug(f"HTTP-on-443 banner {ip}:{port}: {raw[:120]!r}")
    return raw, _parse_version(raw)


def _grab_pop3(ip: str, port: int, timeout: float) -> tuple[str, str]:
    """POP3 — read the +OK greeting."""
    with socket.create_connection((ip, port), timeout=timeout) as s:
        raw = _read(s)
    log.debug(f"POP3 banner {ip}:{port}: {raw!r}")
    return raw, _parse_version(raw)


def _grab_imap(ip: str, port: int, timeout: float) -> tuple[str, str]:
    """IMAP — read the * OK greeting."""
    with socket.create_connection((ip, port), timeout=timeout) as s:
        raw = _read(s)
    log.debug(f"IMAP banner {ip}:{port}: {raw!r}")
    return raw, _parse_version(raw)


def _grab_generic(ip: str, port: int, timeout: float) -> tuple[str, str]:
    """Generic — connect and read whatever the service sends first."""
    with socket.create_connection((ip, port), timeout=timeout) as s:
        raw = _read(s)
    log.debug(f"Generic banner {ip}:{port}: {raw[:80]!r}")
    return raw, _parse_version(raw)


# Map well-known port numbers → grabber function
_GRABBERS: Dict[int, object] = {
    21:  _grab_ftp,
    22:  _grab_ssh,
    25:  _grab_smtp,
    80:  _grab_http,
    110: _grab_pop3,
    143: _grab_imap,
    443: _grab_https,
    465: _grab_smtp,   # SMTPS — often shows SMTP greeting too
    587: _grab_smtp,   # SMTP submission
    993: _grab_imap,   # IMAPS
    995: _grab_pop3,   # POP3S
    8080: _grab_http,
    8443: _grab_https,
}


# ─── Public API ───────────────────────────────────────────────────────────────


def grab_banner(
    ip: str,
    port_str: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> BannerResult:
    """Grab the banner for a single (ip, port) pair.

    Args:
        ip:       Target IPv4 address string.
        port_str: Port/service token as produced by scan_ports, e.g. ``"22/SSH"``.
        timeout:  Per-connection timeout in seconds (default: 4.0).

    Returns:
        A :class:`BannerResult` with port, service, version, and raw_banner
        filled in.  On any failure the version and raw_banner fields describe
        the error so the caller never receives an exception.
    """
    try:
        port_num = int(port_str.split("/")[0])
        service  = port_str.split("/")[1] if "/" in port_str else "unknown"
    except (ValueError, IndexError):
        log.warning(f"grab_banner: cannot parse port token '{port_str}'")
        return BannerResult(0, "unknown", "", "[bad port token]")

    grabber = _GRABBERS.get(port_num, _grab_generic)
    log.debug(f"Grabbing banner from {ip}:{port_num} using {grabber.__name__}")

    try:
        raw, version = grabber(ip, port_num, timeout)  # type: ignore[call-arg]
        raw_trimmed  = raw[:256] if raw else "[no response]"
        return BannerResult(
            port       = port_num,
            service    = service,
            version    = version,
            raw_banner = raw_trimmed,
        )
    except (socket.timeout, TimeoutError):
        log.debug(f"Banner grab timeout: {ip}:{port_num}")
        return BannerResult(port_num, service, "", "[timeout]")
    except ssl.SSLError as exc:
        log.warning(f"SSL error grabbing {ip}:{port_num}: {exc}")
        return BannerResult(port_num, service, "", f"[SSL error: {exc.reason}]")
    except ConnectionRefusedError:
        log.debug(f"Connection refused: {ip}:{port_num}")
        return BannerResult(port_num, service, "", "[connection refused]")
    except OSError as exc:
        log.warning(f"OS error grabbing {ip}:{port_num}: {exc}")
        return BannerResult(port_num, service, "", f"[error: {exc}]")


def grab_banners_for_host(
    ip: str,
    open_ports: List[str],
    timeout: float = DEFAULT_TIMEOUT,
    threads: int = 10,
) -> Dict[str, BannerResult]:
    """Grab banners for all open ports on a single host concurrently.

    Args:
        ip:         Target IPv4 address.
        open_ports: List of port/service strings, e.g. ``["22/SSH", "80/HTTP"]``.
        timeout:    Per-connection timeout in seconds.
        threads:    Thread pool size for concurrent grabs.

    Returns:
        A dict mapping each port/service string to its :class:`BannerResult`.
        Ports that fail or time out are still included with descriptive
        raw_banner values rather than raising.
    """
    results: Dict[str, BannerResult] = {}

    if not open_ports:
        return results

    with ThreadPoolExecutor(max_workers=min(threads, len(open_ports))) as ex:
        future_map = {
            ex.submit(grab_banner, ip, port_str, timeout): port_str
            for port_str in open_ports
        }
        for future in as_completed(future_map):
            port_str = future_map[future]
            try:
                results[port_str] = future.result()
            except Exception as exc:
                log.warning(f"Unexpected error grabbing {ip}/{port_str}: {exc}")
                port_num = int(port_str.split("/")[0]) if "/" in port_str else 0
                service  = port_str.split("/")[1] if "/" in port_str else "unknown"
                results[port_str] = BannerResult(port_num, service, "", f"[unexpected: {exc}]")

    return results
