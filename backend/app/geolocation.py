"""
MailTracer-AI :: Hop Geolocation & Infrastructure Threat Intel
------------------------------------------------------------------
Resolves each relay hop IP to:
  - Physical geolocation (MaxMind GeoIP2 City/Country DB)
  - Infrastructure exposure & threat score (Shodan)
  - Ownership / ASN / registration info (WHOIS via ipwhois)

Falls back gracefully (returns None / low-confidence fields) if an
API key or local DB is not configured, so the platform still runs
in a degraded "offline" mode during demos.

Dependencies: geoip2, shodan, ipwhois
"""

from __future__ import annotations

import os
import functools
from dataclasses import dataclass, asdict
from typing import Optional

import geoip2.database
import geoip2.errors

try:
    import shodan
except ImportError:  # pragma: no cover
    shodan = None

try:
    from ipwhois import IPWhois
except ImportError:  # pragma: no cover
    IPWhois = None


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

MAXMIND_DB_PATH = os.getenv("MAXMIND_DB_PATH", "./data/GeoLite2-City.mmdb")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

_geoip_reader: Optional[geoip2.database.Reader] = None
_shodan_client = None


def _get_geoip_reader() -> Optional[geoip2.database.Reader]:
    global _geoip_reader
    if _geoip_reader is None and os.path.exists(MAXMIND_DB_PATH):
        _geoip_reader = geoip2.database.Reader(MAXMIND_DB_PATH)
    return _geoip_reader


def _get_shodan_client():
    global _shodan_client
    if _shodan_client is None and shodan and SHODAN_API_KEY:
        _shodan_client = shodan.Shodan(SHODAN_API_KEY)
    return _shodan_client


# --------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------

@dataclass
class GeoResult:
    ip: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    city: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    accuracy_radius_km: Optional[int] = None
    source: str = "maxmind"


@dataclass
class ShodanIntel:
    ip: str
    org: Optional[str] = None
    isp: Optional[str] = None
    open_ports: list[int] = None
    vulns: list[str] = None
    tags: list[str] = None
    infra_risk_score: float = 0.0  # 0-100, derived from exposure


@dataclass
class WhoisIntel:
    ip: str
    asn: Optional[str] = None
    asn_description: Optional[str] = None
    network_name: Optional[str] = None
    country: Optional[str] = None
    abuse_email: Optional[str] = None


@dataclass
class HopIntel:
    ip: str
    geo: GeoResult
    shodan: Optional[ShodanIntel]
    whois: Optional[WhoisIntel]
    combined_risk_score: float  # 0-100


# --------------------------------------------------------------------------
# Individual resolvers
# --------------------------------------------------------------------------

def geolocate_ip(ip: str) -> GeoResult:
    reader = _get_geoip_reader()
    if reader is None:
        return GeoResult(ip=ip, source="unavailable")
    try:
        resp = reader.city(ip)
        return GeoResult(
            ip=ip,
            latitude=resp.location.latitude,
            longitude=resp.location.longitude,
            city=resp.city.name,
            country=resp.country.name,
            country_code=resp.country.iso_code,
            accuracy_radius_km=resp.location.accuracy_radius,
        )
    except geoip2.errors.AddressNotFoundError:
        return GeoResult(ip=ip, source="not_found")
    except Exception:
        return GeoResult(ip=ip, source="error")


# High-risk service signatures commonly abused by spam/phishing infra
_RISKY_PORTS = {23, 25, 445, 3389, 6667, 8080}
_RISKY_TAGS = {"malware", "botnet", "proxy", "tor", "compromised", "self-signed"}


def shodan_lookup(ip: str) -> Optional[ShodanIntel]:
    client = _get_shodan_client()
    if client is None:
        return None
    try:
        host = client.host(ip)
    except Exception:
        return None

    open_ports = host.get("ports", [])
    tags = host.get("tags", []) or []
    vulns = list(host.get("vulns", []) or [])

    risk = 0.0
    risk += min(len(open_ports) * 4, 30)
    risk += 25 if any(p in _RISKY_PORTS for p in open_ports) else 0
    risk += 25 if any(t.lower() in _RISKY_TAGS for t in tags) else 0
    risk += min(len(vulns) * 10, 20)
    risk = min(risk, 100.0)

    return ShodanIntel(
        ip=ip,
        org=host.get("org"),
        isp=host.get("isp"),
        open_ports=open_ports,
        vulns=vulns,
        tags=tags,
        infra_risk_score=round(risk, 1),
    )


def whois_lookup(ip: str) -> Optional[WhoisIntel]:
    if IPWhois is None:
        return None
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
    except Exception:
        return None

    network = result.get("network", {}) or {}
    asn_desc = result.get("asn_description")
    abuse_email = None
    for entity in (result.get("objects") or {}).values():
        contact = entity.get("contact") or {}
        for email_entry in contact.get("email", []) or []:
            if "abuse" in (email_entry.get("value", "") or "").lower() or True:
                abuse_email = email_entry.get("value")
                break

    return WhoisIntel(
        ip=ip,
        asn=result.get("asn"),
        asn_description=asn_desc,
        network_name=network.get("name"),
        country=result.get("asn_country_code"),
        abuse_email=abuse_email,
    )


# --------------------------------------------------------------------------
# Combined hop trace
# --------------------------------------------------------------------------

@functools.lru_cache(maxsize=512)
def _cached_trace(ip: str) -> HopIntel:
    geo = geolocate_ip(ip)
    sh = shodan_lookup(ip)
    who = whois_lookup(ip)

    infra_risk = sh.infra_risk_score if sh else 0.0
    # Slight boost if WHOIS registration data is missing/opaque (harder to attribute)
    attribution_penalty = 10.0 if (who is None or not who.asn_description) else 0.0
    combined = min(infra_risk + attribution_penalty, 100.0)

    return HopIntel(
        ip=ip,
        geo=geo,
        shodan=sh,
        whois=who,
        combined_risk_score=round(combined, 1),
    )


def trace_hop(ip: str) -> dict:
    """Public entrypoint: returns a JSON-serializable dict for one hop IP."""
    intel = _cached_trace(ip)
    return {
        "ip": intel.ip,
        "geo": asdict(intel.geo),
        "shodan": asdict(intel.shodan) if intel.shodan else None,
        "whois": asdict(intel.whois) if intel.whois else None,
        "combined_risk_score": intel.combined_risk_score,
    }


def trace_hops(ips: list[str]) -> list[dict]:
    """Traces a full ordered relay chain, used to render the hop map."""
    return [trace_hop(ip) for ip in ips]
