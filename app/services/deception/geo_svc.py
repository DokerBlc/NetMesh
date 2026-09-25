"""NetPulse — Mapa global de ataques.

Agrega los eventos de deception por IP de origen, geolocaliza las IPs
públicas (GeoIP offline) y devuelve los puntos para el mapa, junto con la
ubicación del centro de datos (punto objetivo en verde).
"""

from app.core.settings import (
    DECEPTION_DATACENTER_LAT,
    DECEPTION_DATACENTER_LON,
    DECEPTION_DATACENTER_NAME,
)
from app.services.deception import geoip_svc, store_svc


def attack_map(limit: int = 3000) -> dict:
    """Puntos de ataque geolocalizados + objetivo (datacenter)."""
    events = store_svc.get_events(limit=limit)
    aggr: dict[str, dict] = {}

    for e in events:
        ip = e.get("src_ip")
        if not ip:
            continue
        if (e.get("detail") or {}).get("simulated"):
            continue
        a = aggr.setdefault(ip, {"count": 0, "devices": set(), "last": None})
        a["count"] += 1
        if e.get("device_id"):
            a["devices"].add(e["device_id"])
        ts = e.get("timestamp")
        if ts and (a["last"] is None or ts > a["last"]):
            a["last"] = ts

    points = []
    for ip, a in aggr.items():
        geo = geoip_svc.lookup(ip)
        if not geo or geo.get("lat") is None:
            continue
        points.append({
            "ip": ip,
            "count": a["count"],
            "devices": len(a["devices"]),
            "last_seen": a["last"],
            "country_code": geo.get("country_code"),
            "country": geo.get("country"),
            "city": geo.get("city"),
            "lat": geo["lat"],
            "lon": geo["lon"],
        })

    points.sort(key=lambda p: p["count"], reverse=True)
    return {
        "geoip": geoip_svc.available(),
        "target": {
            "lat": DECEPTION_DATACENTER_LAT,
            "lon": DECEPTION_DATACENTER_LON,
            "name": DECEPTION_DATACENTER_NAME,
        },
        "points": points,
        "total": sum(p["count"] for p in points),
    }
