"""
analyzer.py — Motor de análisis forense de cabeceras de correo
"""

import re
import json
import urllib.request
from email import message_from_string
from email.utils import parsedate_to_datetime, parseaddr
from datetime import datetime


# ─────────────────────── UTILIDADES ────────────────────────────

def extract_public_ips(text: str) -> list:
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    candidates = re.findall(pattern, text)
    seen = set()
    public = []
    for ip in candidates:
        parts = list(map(int, ip.split('.')))
        if (parts[0] in (10, 127) or
                (parts[0] == 172 and 16 <= parts[1] <= 31) or
                (parts[0] == 192 and parts[1] == 168) or
                parts[0] == 0):
            continue
        if ip not in seen:
            seen.add(ip)
            public.append(ip)
    return public


def geolocate_ip(ip: str) -> dict:
    url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org,as"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "EmailForensics/2.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return {}


def parse_received_chain(raw: str) -> list:
    """
    Extrae todos los bloques Received y los devuelve en orden cronológico
    (el primero es el salto más antiguo).
    """
    blocks = re.findall(
        r'Received:\s*(.*?)(?=\nReceived:|\nMIME-Version:|\nContent-Type:'
        r'|\nFrom:|\nTo:|\nSubject:|\nReturn-Path:|\Z)',
        raw, re.DOTALL | re.IGNORECASE
    )
    hops = []
    for block in reversed(blocks):
        clean = re.sub(r'\s+', ' ', block).strip()
        ips = extract_public_ips(clean)

        date_match = re.search(
            r';\s*((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}\s+\w+\s+\d{4}'
            r'\s+[\d:]+\s+[+-]\d{4}(?:\s*\([^)]+\))?)',
            clean, re.IGNORECASE
        )
        ts = None
        if date_match:
            try:
                ts_str = re.sub(r'\s*\([^)]+\)', '', date_match.group(1)).strip()
                ts = parsedate_to_datetime(ts_str)
            except Exception:
                pass

        from_m = re.search(r'\bfrom\s+(\S+)', clean, re.IGNORECASE)
        by_m   = re.search(r'\bby\s+(\S+)',   clean, re.IGNORECASE)
        via_m  = re.search(r'\bvia\s+(\S+)',   clean, re.IGNORECASE)
        with_m = re.search(r'\bwith\s+(\S+)',  clean, re.IGNORECASE)

        hops.append({
            "raw":       clean,
            "ips":       ips,
            "from_host": from_m.group(1) if from_m else None,
            "by_host":   by_m.group(1)   if by_m   else None,
            "via":       via_m.group(1)  if via_m  else None,
            "with":      with_m.group(1) if with_m else None,
            "timestamp": ts,
            "timestamp_str": ts.strftime("%Y-%m-%d %H:%M:%S %Z") if ts else None,
        })
    return hops


# ──────────────────────── SPAM HEURISTICS ──────────────────────

def spam_analysis(msg, raw: str, hops: list) -> dict:
    flags = []
    score = 0

    from_raw    = msg.get("From", "")
    reply_to    = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    message_id  = msg.get("Message-ID", "")
    subject     = msg.get("Subject", "")

    _, from_addr    = parseaddr(from_raw)
    _, reply_addr   = parseaddr(reply_to)

    from_domain = from_addr.split("@")[-1].lower()   if "@" in from_addr    else ""
    reply_domain = reply_addr.split("@")[-1].lower() if "@" in reply_addr   else ""
    rp_domain = re.search(r'@([\w.\-]+)', return_path)
    rp_domain = rp_domain.group(1).lower() if rp_domain else ""
    mid_domain = re.search(r'@([\w.\-]+)>', message_id)
    mid_domain = mid_domain.group(1).lower() if mid_domain else ""

    # Inconsistencia de dominio From vs Return-Path
    if from_domain and rp_domain and from_domain != rp_domain:
        flags.append({
            "severity": "high",
            "label": "Inconsistencia From ↔ Return-Path",
            "detail": f"From: @{from_domain} / Return-Path: @{rp_domain}"
        })
        score += 30

    # Inconsistencia de dominio From vs Message-ID
    if from_domain and mid_domain and from_domain != mid_domain:
        flags.append({
            "severity": "high",
            "label": "Inconsistencia From ↔ Message-ID",
            "detail": f"From: @{from_domain} / Message-ID: @{mid_domain}"
        })
        score += 25

    # Reply-To distinto de From
    if reply_domain and from_domain and reply_domain != from_domain:
        flags.append({
            "severity": "medium",
            "label": "Reply-To distinto de From",
            "detail": f"From: @{from_domain} / Reply-To: @{reply_domain}"
        })
        score += 15

    # Palabras clave de phishing en asunto
    phishing_keywords = [
        "paquete", "package", "urgente", "urgent", "verify", "verifica",
        "cuenta", "account", "suspendida", "suspended", "ganaste", "won",
        "premio", "prize", "click", "confirma", "confirm", "notificaci"
    ]
    subject_lower = subject.lower()
    matched_kw = [kw for kw in phishing_keywords if kw in subject_lower]
    if matched_kw:
        flags.append({
            "severity": "medium",
            "label": "Palabras clave sospechosas en asunto",
            "detail": f"Detectadas: {', '.join(matched_kw)}"
        })
        score += 10

    # Dominio sospechoso en From
    suspicious_domains = ["onmicrosoft.com", "outlook.com", "hotmail.com"]
    if any(d in rp_domain for d in suspicious_domains) and from_domain not in suspicious_domains:
        flags.append({
            "severity": "medium",
            "label": "Return-Path usa dominio de infraestructura genérico",
            "detail": f"@{rp_domain} como Return-Path es inusual para el remitente declarado"
        })
        score += 10

    # Saltos MTA excesivos
    if len(hops) > 6:
        flags.append({
            "severity": "low",
            "label": "Cadena MTA muy larga",
            "detail": f"{len(hops)} saltos detectados (inusual)"
        })
        score += 5

    # Determinar veredicto
    if score >= 50:
        verdict = "ALTO RIESGO DE SPAM/PHISHING"
        verdict_level = "danger"
    elif score >= 25:
        verdict = "SOSPECHOSO"
        verdict_level = "warning"
    else:
        verdict = "APARENTEMENTE LEGÍTIMO"
        verdict_level = "ok"

    return {
        "score": min(score, 100),
        "verdict": verdict,
        "verdict_level": verdict_level,
        "flags": flags
    }


# ─────────────────────── ANALIZADOR PRINCIPAL ──────────────────

def analyze_header(raw: str) -> dict:
    msg = message_from_string(raw)

    # Campos básicos
    from_raw    = msg.get("From",       "")
    to_raw      = msg.get("To",         "")
    subject     = msg.get("Subject",    "")
    date_raw    = msg.get("Date",       "")
    message_id  = msg.get("Message-ID", "")
    return_path = msg.get("Return-Path","")
    reply_to    = msg.get("Reply-To",   "")
    x_mailer    = msg.get("X-Mailer",   "") or msg.get("User-Agent", "")
    x_orig_ip   = msg.get("X-Originating-IP", "") or msg.get("X-Original-IP", "")

    _, from_addr = parseaddr(from_raw)
    _, to_addr   = parseaddr(to_raw)

    try:
        date_dt  = parsedate_to_datetime(date_raw)
        date_str = date_dt.strftime("%A, %d %B %Y  %H:%M:%S %Z")
    except Exception:
        date_str = date_raw

    # Cadena Received
    hops = parse_received_chain(raw)

    # Tiempos de entrega
    delivery_times = []
    total_seconds  = None
    for i in range(1, len(hops)):
        t1 = hops[i-1]["timestamp"]
        t2 = hops[i]["timestamp"]
        if t1 and t2:
            delta = abs((t2 - t1).total_seconds())
            delivery_times.append({"hop": f"{i}→{i+1}", "seconds": delta,
                                   "human": _humanize(delta)})
        else:
            delivery_times.append({"hop": f"{i}→{i+1}", "seconds": None, "human": "N/A"})

    if hops:
        t_first = hops[0]["timestamp"]
        t_last  = hops[-1]["timestamp"]
        if t_first and t_last:
            total_seconds = abs((t_last - t_first).total_seconds())

    # IPs relevantes
    all_ips = extract_public_ips(raw)

    # Origen MTA global: primer Received con IP pública
    origin_ip = None
    for hop in hops:
        if hop["ips"]:
            origin_ip = hop["ips"][0]
            break

    # Destino MTA global: último Received con IP
    dest_ip = None
    for hop in reversed(hops):
        if hop["ips"]:
            dest_ip = hop["ips"][-1]
            break

    # IP del destinatario: último salto
    recipient_ip = dest_ip

    # Geolocalización MTA global
    origin_geo = geolocate_ip(origin_ip) if origin_ip else {}
    dest_geo   = geolocate_ip(dest_ip)   if dest_ip   else {}

    # Geolocalización de todos los saltos
    hops_geo = []
    for i, hop in enumerate(hops):
        hop_data = {
            "index":     i + 1,
            "from_host": hop["from_host"],
            "by_host":   hop["by_host"],
            "via":       hop["via"],
            "protocol":  hop["with"],
            "timestamp": hop["timestamp_str"],
            "ips":       [],
            "raw":       hop["raw"],
        }
        for ip in hop["ips"]:
            geo = geolocate_ip(ip)
            hop_data["ips"].append({
                "ip":      ip,
                "country": geo.get("country", "Desconocido"),
                "country_code": geo.get("countryCode", ""),
                "city":    geo.get("city", ""),
                "lat":     geo.get("lat"),
                "lon":     geo.get("lon"),
                "org":     geo.get("org") or geo.get("isp", ""),
                "as":      geo.get("as", ""),
            })
        # Distancia entre saltos
        if i > 0 and hops_geo:
            prev_ips = hops_geo[-1]["ips"]
            curr_ips = hop_data["ips"]
            if prev_ips and curr_ips and prev_ips[0].get("lat") and curr_ips[0].get("lat"):
                dist = _haversine(
                    prev_ips[0]["lat"], prev_ips[0]["lon"],
                    curr_ips[0]["lat"], curr_ips[0]["lon"]
                )
                hop_data["distance_km"] = round(dist)
            else:
                hop_data["distance_km"] = None
        else:
            hop_data["distance_km"] = None
        hops_geo.append(hop_data)

    # Análisis spam
    spam = spam_analysis(msg, raw, hops)

    return {
        "basic": {
            "from":        from_addr or from_raw,
            "to":          to_addr   or to_raw,
            "subject":     subject,
            "date":        date_str,
            "date_raw":    date_raw,
            "message_id":  message_id,
            "return_path": return_path,
            "reply_to":    reply_to,
            "x_mailer":    x_mailer,
            "x_orig_ip":   x_orig_ip,
        },
        "mta_global": {
            "origin_ip":   origin_ip,
            "origin_geo":  origin_geo,
            "dest_ip":     dest_ip,
            "dest_geo":    dest_geo,
        },
        "recipient_ip": recipient_ip,
        "delivery_times": delivery_times,
        "total_transit_seconds": total_seconds,
        "total_transit_human": _humanize(total_seconds) if total_seconds else "N/A",
        "hops": hops_geo,
        "all_ips": all_ips,
        "spam": spam,
    }


def _humanize(seconds) -> str:
    if seconds is None:
        return "N/A"
    seconds = abs(seconds)
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f} min"
    else:
        return f"{seconds/3600:.2f} h"


def _haversine(lat1, lon1, lat2, lon2) -> float:
    import math
    R = 6371
    φ1, φ2 = math.radians(lat1), math.radians(lat2)
    dφ = math.radians(lat2 - lat1)
    dλ = math.radians(lon2 - lon1)
    a = math.sin(dφ/2)**2 + math.cos(φ1)*math.cos(φ2)*math.sin(dλ/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
