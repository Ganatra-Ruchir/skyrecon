"""
Offline IP geolocation.

Reads a local MaxMind-format (.mmdb) database — DB-IP's free City Lite build
by default, downloaded once at image build time (see Dockerfile) — so a
lookup never leaves the process. If the database file is missing, every
lookup returns {}: enrichment degrades quietly, it does not fail or reach
out to the network to compensate.
"""

from __future__ import annotations

import os
import threading

import maxminddb

_CITY_DB_PATH = os.environ.get("SKYRECON_GEOIP_DB", "/srv/geoip/dbip-city-lite.mmdb")
_ASN_DB_PATH = os.environ.get("SKYRECON_ASN_DB", "/srv/geoip/dbip-asn-lite.mmdb")
_lock = threading.Lock()
_readers: dict[str, maxminddb.Reader | None] = {}
_load_attempted: set[str] = set()


def _open(path: str) -> maxminddb.Reader | None:
    if path in _readers or path in _load_attempted:
        return _readers.get(path)
    with _lock:
        if path in _load_attempted:
            return _readers.get(path)
        _load_attempted.add(path)
        if os.path.isfile(path):
            _readers[path] = maxminddb.open_database(path)
    return _readers.get(path)


def _get_reader() -> maxminddb.Reader | None:
    return _open(_CITY_DB_PATH)


def _get_asn_reader() -> maxminddb.Reader | None:
    return _open(_ASN_DB_PATH)


def geo_facts(ip: str) -> dict:
    """Country/region/city/coordinates for a public IP, or {} if unavailable."""
    reader = _get_reader()
    if reader is None:
        return {}
    try:
        record = reader.get(ip)
    except ValueError:
        return {}
    if not isinstance(record, dict):
        return {}

    country = record.get("country") or {}
    subdivisions = record.get("subdivisions") or []
    city = record.get("city") or {}
    location = record.get("location") or {}

    out = {
        "geo_country": (country.get("names") or {}).get("en"),
        "geo_country_code": country.get("iso_code"),
        "geo_region": (subdivisions[0].get("names") or {}).get("en") if subdivisions else None,
        "geo_city": (city.get("names") or {}).get("en"),
        "geo_lat": location.get("latitude"),
        "geo_lon": location.get("longitude"),
    }
    return {k: v for k, v in out.items() if v is not None}


def asn_facts(ip: str) -> dict:
    """Autonomous system number & org (hosting provider/ISP) for a public IP."""
    reader = _get_asn_reader()
    if reader is None:
        return {}
    try:
        record = reader.get(ip)
    except ValueError:
        return {}
    if not isinstance(record, dict):
        return {}

    number = record.get("autonomous_system_number")
    org = record.get("autonomous_system_organization")
    out = {
        "asn": f"AS{number}" if number is not None else None,
        "asn_org": org,
    }
    return {k: v for k, v in out.items() if v is not None}
