"""
main.py — Servidor Flask para el analizador forense de cabeceras de correo
Uso: python3 main.py
Acceder en: http://localhost:5000
"""

from flask import Flask, render_template, request, jsonify
from analyzer import analyze_header, geolocate_ip, _haversine
import os

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB máximo


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    header_text = None

    # Puede venir como fichero .txt o como texto pegado directamente
    if "file" in request.files and request.files["file"].filename:
        f = request.files["file"]
        try:
            header_text = f.read().decode("utf-8", errors="replace")
        except Exception as e:
            return jsonify({"error": f"Error leyendo fichero: {str(e)}"}), 400

    elif "header_text" in request.form and request.form["header_text"].strip():
        header_text = request.form["header_text"].strip()

    if not header_text:
        return jsonify({"error": "No se proporcionó ninguna cabecera."}), 400

    try:
        result = analyze_header(header_text)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Error en el análisis: {str(e)}"}), 500


@app.route("/geoip", methods=["POST"])
def geoip():
    data = request.get_json(force=True, silent=True) or {}
    ips_raw = data.get("ips", [])

    if not ips_raw or not isinstance(ips_raw, list):
        return jsonify({"error": "Envía un JSON con campo 'ips': ['x.x.x.x', ...]"}), 400

    # Deduplicar y limitar a 10 IPs
    ips = list(dict.fromkeys(ip.strip() for ip in ips_raw if ip.strip()))[:10]

    results = []
    for ip in ips:
        geo = geolocate_ip(ip)
        if geo:
            results.append({
                "ip":           ip,
                "country":      geo.get("country", "Desconocido"),
                "country_code": geo.get("countryCode", ""),
                "city":         geo.get("city", ""),
                "lat":          geo.get("lat"),
                "lon":          geo.get("lon"),
                "isp":          geo.get("isp", ""),
                "org":          geo.get("org", ""),
                "as":           geo.get("as", ""),
                "ok":           True,
            })
        else:
            results.append({"ip": ip, "ok": False, "error": "No se pudo geolocalizar"})

    # Calcular distancias entre pares consecutivos (y todos los pares si son 2)
    distances = []
    geolocated = [r for r in results if r.get("ok") and r.get("lat")]
    for i in range(1, len(geolocated)):
        a, b = geolocated[i-1], geolocated[i]
        km = _haversine(a["lat"], a["lon"], b["lat"], b["lon"])
        distances.append({
            "from_ip": a["ip"],
            "to_ip":   b["ip"],
            "km":      round(km),
        })

    return jsonify({"results": results, "distances": distances})


if __name__ == "__main__":
    # Crear carpeta templates y static si no existen
    os.makedirs("templates", exist_ok=True)
    os.makedirs("static",    exist_ok=True)
    print("\n  ┌─────────────────────────────────────────┐")
    print("  │   Email Forensics Analyzer  v2.1        │")
    print("  │   http://localhost:5000                  │")
    print("  └─────────────────────────────────────────┘\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
