"""NetPulse — IOCs (Indicators of Compromise) de la red señuelo.

Agrega los atacantes observados en un resumen exportable: IP, número de
eventos, dispositivos/protocolos tocados, comandos ejecutados, rango
temporal y estado de bloqueo. Útil para alimentar un SIEM/firewall.
"""

import csv
import io
from typing import Optional

from app.services.deception import blocklist_svc, store_svc

_SENSITIVE = ("passwd", "shadow", "id_rsa", "wget", "curl", "chmod", "rm -rf", "nc ")


def summarize(limit: int = 5000) -> list[dict]:
    """Resumen de atacantes (IOCs) ordenado por actividad."""
    events = store_svc.get_events(limit=limit)
    aggr: dict[str, dict] = {}

    for e in events:
        ip = e.get("src_ip")
        if not ip:
            continue
        a = aggr.setdefault(ip, {
            "ip": ip, "events": 0, "devices": set(), "protos": set(),
            "commands": [], "success": False, "first_seen": e.get("timestamp"),
            "last_seen": e.get("timestamp"),
        })
        a["events"] += 1
        if e.get("device_id"):
            a["devices"].add(e["device_id"])
        if e.get("proto"):
            a["protos"].add(e["proto"])
        if e.get("success"):
            a["success"] = True
        detail = e.get("detail") or {}
        if detail.get("command"):
            a["commands"].append(detail["command"])
        ts = e.get("timestamp")
        if ts:
            if not a["first_seen"] or ts < a["first_seen"]:
                a["first_seen"] = ts
            if not a["last_seen"] or ts > a["last_seen"]:
                a["last_seen"] = ts

    blocked = {b["ip"] for b in blocklist_svc.list_blocked()}
    result = []
    for ip, a in aggr.items():
        cmds = a["commands"]
        suspicious = [c for c in cmds if any(s in c.lower() for s in _SENSITIVE)]
        threat = "high" if (a["success"] or suspicious) else ("medium" if cmds else "low")
        result.append({
            "ip": ip,
            "events": a["events"],
            "devices": sorted(a["devices"]),
            "protos": sorted(a["protos"]),
            "commands": len(cmds),
            "suspicious_commands": suspicious[:5],
            "success": a["success"],
            "first_seen": a["first_seen"],
            "last_seen": a["last_seen"],
            "threat": threat,
            "blocked": ip in blocked,
        })

    result.sort(key=lambda r: (r["threat"] == "high", r["events"]), reverse=True)
    return result


def to_csv(limit: int = 5000) -> str:
    """Exporta los IOCs a CSV."""
    rows = summarize(limit=limit)
    buffer = io.StringIO()
    headers = ["ip", "threat", "events", "blocked", "success",
               "devices", "protos", "commands", "first_seen", "last_seen"]
    writer = csv.DictWriter(buffer, fieldnames=headers, lineterminator="\n")
    writer.writeheader()
    for r in rows:
        writer.writerow({
            "ip": r["ip"], "threat": r["threat"], "events": r["events"],
            "blocked": r["blocked"], "success": r["success"],
            "devices": "|".join(r["devices"]), "protos": "|".join(r["protos"]),
            "commands": r["commands"], "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
        })
    return buffer.getvalue()


def find(ip: str) -> Optional[dict]:
    """Devuelve el IOC de una IP concreta."""
    for row in summarize():
        if row["ip"] == ip:
            return row
    return None
