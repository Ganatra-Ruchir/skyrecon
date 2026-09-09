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

_DB_PATH = os.environ.get("SKYRECON_GEOIP_DB", "/srv/geoip/dbip-city-lite.mmdb")
_lock = threading.Lock()
_reader: maxminddb.Reader | None = None
_load_attempted = False


def _get_reader() -> maxminddb.Reader | None:
    global _reader, _load_attempted
    if _reader is not None or _load_attempted:
        return _reader
    with _lock:
        if _load_attempted:
            return _reader
        _load_attempted = True
        if os.path.isfile(_DB_PATH):
            _reader = maxminddb.open_database(_DB_PATH)
    return _reader


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
